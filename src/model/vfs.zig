//! Virtual filesystem with a crash-consistency model (plan §6).
//!
//! Storage is a fixed pool of 4 KiB pages shared copy-on-write between each
//! inode's `cur` view (page cache, what reads observe) and `dur` view (media,
//! what survives power loss). Namespace operations are applied to the
//! `cur_dentries` table immediately and appended to an ordered metadata
//! journal; they reach `dur_dentries` when the journal commits.
//!
//! The VFS is independent of `std.Io`: it has its own error set and is unit
//! tested on its own. `Sim.zig` maps it onto the `std.Io` VTable.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const decide = @import("../sim/decide.zig");

pub const page_bytes = 4096;
pub const sector_bytes = 512;
const sectors_per_page = page_bytes / sector_bytes;
pub const name_bytes_max = 96;
pub const path_bytes_max = 1024;
/// Symlinks followed per path resolution before `error.SymLinkLoop` (Linux: 40).
pub const symlink_hops_max = 40;

pub const Persona = enum {
    linux_ext4,
    linux_xfs,
    windows_ntfs,
    posix_strict,
    /// Case-insensitive, case-preserving; no `auto_da_alloc`. Assumes `fsync`
    /// is durable (see plan section 6.4 on `F_FULLFSYNC`).
    macos_apfs,
    /// Copy-on-write: no torn sectors; a rename is ordered after the data
    /// written before it (transaction groups commit in order).
    freebsd_zfs,

    /// Names compare without case: ASCII and Latin-1 letters (`É` is `é`).
    pub fn caseInsensitive(p: Persona) bool {
        return p == .windows_ntfs or p == .macos_apfs;
    }
    /// Win32 name rules: a component's trailing dots and spaces, and a
    /// `::$DATA` suffix (the default stream), are dropped (`win32Name`), and
    /// a long name also answers to its 8.3 short name (`shortName`).
    pub fn win32Names(p: Persona) bool {
        return p == .windows_ntfs;
    }
    /// Composed and decomposed spellings name the same file (`é` as U+00E9
    /// or as `e` U+0301), for the Latin-1 letters (`NameIterator`).
    pub fn normalizationInsensitive(p: Persona) bool {
        return p == .macos_apfs;
    }
    pub fn backslashSeparator(p: Persona) bool {
        return p == .windows_ntfs;
    }
    pub fn sharingViolations(p: Persona) bool {
        return p == .windows_ntfs;
    }
    /// `fsync` of any file commits the whole metadata journal.
    pub fn fileSyncCommitsJournal(p: Persona) bool {
        return p != .posix_strict;
    }
    /// ext4 `auto_da_alloc`: rename over an existing file flushes the source's data.
    pub fn renameFlushesData(p: Persona) bool {
        return p == .linux_ext4 or p == .freebsd_zfs;
    }
    /// Unsynced data survives a power loss all-or-nothing per file.
    pub fn atomicWrites(p: Persona) bool {
        return p == .freebsd_zfs;
    }
    pub fn journalPrefixOnCrash(p: Persona) bool {
        return p != .posix_strict;
    }
};

pub const Limits = struct {
    pages_max: u32 = 2048,
    file_pages_max: u32 = 256,
    inodes_max: u32 = 256,
    dentries_max: u32 = 1024,
    journal_max: u32 = 256,
    handles_max: u32 = 128,
};

pub const Error = error{
    FileNotFound,
    PathAlreadyExists,
    NotDir,
    IsDir,
    DirNotEmpty,
    NoSpaceLeft,
    FileTooBig,
    NameTooLong,
    BadPathName,
    FileBusy,
    SystemResources,
    ProcessFdQuotaExceeded,
    InvalidHandle,
    NotOpenForReading,
    NotOpenForWriting,
    SymLinkLoop,
    NotLink,
    PermissionDenied,
};

pub const InodeId = u32;
pub const root_inode: InodeId = 0;
const none: u32 = std.math.maxInt(u32);

pub const Kind = enum(u8) { free, file, dir, symlink };

pub const Inode = struct {
    kind: Kind,
    cur_len_bytes: u64,
    dur_len_bytes: u64,
    /// For directories: parent in the `cur` namespace.
    parent: InodeId,
    cur_links: u32,
    dur_links: u32,
    journal_refs: u32,
    open_count: u32,
    mtime_ns: u64,
};

const Dentry = struct {
    used: bool,
    parent: InodeId,
    inode: InodeId,
    name_len: u8,
    name: [name_bytes_max]u8,
    /// The `~N` of its 8.3 short name (`win32Names` personas), 0 for none.
    short: u8 = 0,

    fn nameSlice(d: *const Dentry) []const u8 {
        return d.name[0..d.name_len];
    }
};

const OpKind = enum(u8) { link, unlink, rename };

const JournalOp = struct {
    kind: OpKind,
    inode: InodeId,
    replaced_existing: bool,
    parent: InodeId,
    name_len: u8,
    name: [name_bytes_max]u8,
    parent2: InodeId,
    name2_len: u8,
    name2: [name_bytes_max]u8,
};

pub const Handle = struct {
    used: bool,
    inode: InodeId,
    epoch: u16,
    pos: u64,
    readable: bool,
    writable: bool,
    lock: LockKind = .none,
};

pub const LockKind = enum(u8) { none, shared, exclusive };

pub const CrashMode = enum { power_loss, process_crash };

pub const CrashReport = struct {
    journal_ops_pending: u32 = 0,
    journal_ops_kept: u32 = 0,
    inodes_dirty: u32 = 0,
    inodes_torn: u32 = 0,
    inodes_orphaned: u32 = 0,
};

/// Special handle value for the root directory; valid across crashes.
pub const root_handle_value: u32 = 0x3FFF_FFFF;

pub const Vfs = struct {
    gpa: Allocator,
    limits: Limits,
    persona: Persona,
    now_ns: u64,
    epoch: u16,
    /// Pages written to media by fsync, rename flushes and crashes (cost ledger).
    flushed_pages: u64 = 0,

    pages: []align(page_bytes) u8,
    page_refs: []u16,
    free_pages: []u32,
    free_pages_len: u32,
    /// One past the highest page handed out since the last `reset`. Pages
    /// at or above it were never taken, so their entries at the bottom of
    /// the free list are as `reset` wrote them, and their references are
    /// zero: `reset` rewrites only what lies below.
    page_hwm: u32,

    inodes: []Inode,
    cur_slots: []u32,
    dur_slots: []u32,

    cur_dentries: []Dentry,
    dur_dentries: []Dentry,
    /// Slots at or beyond these are unused (bounds reset and lookups).
    cur_hwm: usize,
    dur_hwm: usize,
    /// Inodes at or beyond this were never allocated this run (bounds reset).
    inode_hwm: usize,

    journal: []JournalOp,
    journal_len: u32,

    handles: []Handle,

    scratch_page: [page_bytes]u8 align(16),
    /// Alternating buffers for paths rewritten by symlink expansion.
    path_bufs: [2][path_bytes_max]u8,

    pub fn init(gpa: Allocator, limits: Limits, persona: Persona) !Vfs {
        assert(limits.pages_max >= 2);
        assert(limits.inodes_max >= 1);
        var v: Vfs = undefined;
        v.gpa = gpa;
        v.limits = limits;
        v.persona = persona;
        v.now_ns = 0;
        v.epoch = 0;
        v.pages = try gpa.alignedAlloc(u8, .fromByteUnits(page_bytes), @as(usize, limits.pages_max) * page_bytes);
        errdefer gpa.free(v.pages);
        v.page_refs = try gpa.alloc(u16, limits.pages_max);
        errdefer gpa.free(v.page_refs);
        v.free_pages = try gpa.alloc(u32, limits.pages_max);
        errdefer gpa.free(v.free_pages);
        v.inodes = try gpa.alloc(Inode, limits.inodes_max);
        errdefer gpa.free(v.inodes);
        const slots = @as(usize, limits.inodes_max) * limits.file_pages_max;
        v.cur_slots = try gpa.alloc(u32, slots);
        errdefer gpa.free(v.cur_slots);
        v.dur_slots = try gpa.alloc(u32, slots);
        errdefer gpa.free(v.dur_slots);
        v.cur_dentries = try gpa.alloc(Dentry, limits.dentries_max);
        errdefer gpa.free(v.cur_dentries);
        v.dur_dentries = try gpa.alloc(Dentry, @as(usize, limits.dentries_max) + limits.journal_max);
        errdefer gpa.free(v.dur_dentries);
        // Make the first reset clear every slot.
        v.page_hwm = limits.pages_max;
        v.cur_hwm = v.cur_dentries.len;
        v.dur_hwm = v.dur_dentries.len;
        v.inode_hwm = limits.inodes_max;
        v.journal = try gpa.alloc(JournalOp, limits.journal_max);
        errdefer gpa.free(v.journal);
        v.handles = try gpa.alloc(Handle, limits.handles_max);
        errdefer gpa.free(v.handles);
        v.reset(persona);
        return v;
    }

    pub fn deinit(v: *Vfs) void {
        v.gpa.free(v.handles);
        v.gpa.free(v.journal);
        v.gpa.free(v.dur_dentries);
        v.gpa.free(v.cur_dentries);
        v.gpa.free(v.dur_slots);
        v.gpa.free(v.cur_slots);
        v.gpa.free(v.inodes);
        v.gpa.free(v.free_pages);
        v.gpa.free(v.page_refs);
        v.gpa.free(v.pages);
    }

    /// Formats a fresh, empty filesystem.
    pub fn reset(v: *Vfs, persona: Persona) void {
        v.persona = persona;
        v.now_ns = 0;
        v.epoch = 1; // handle values must be identical across runs of a seed
        v.flushed_pages = 0;
        @memset(v.page_refs[0..v.page_hwm], 0);
        @memset(v.pages[0..page_bytes], 0); // page 0: the shared zero page
        // The free list is pages `pages_max - 1` down to 1, so that pages
        // are handed out from 1 up. Only the top of it, the pages below
        // the high-water mark, can have changed.
        v.free_pages_len = v.limits.pages_max - v.page_hwm;
        var p: u32 = v.page_hwm;
        while (p > 1) {
            p -= 1;
            v.free_pages[v.free_pages_len] = p;
            v.free_pages_len += 1;
        }
        v.page_hwm = 1;
        // Only inodes below the high-water mark can have state or pages.
        const n_slots = v.inode_hwm * v.limits.file_pages_max;
        for (v.inodes[0..v.inode_hwm]) |*i| i.* = std.mem.zeroes(Inode);
        @memset(v.cur_slots[0..n_slots], 0);
        @memset(v.dur_slots[0..n_slots], 0);
        v.inode_hwm = 1; // the root
        for (v.cur_dentries[0..v.cur_hwm]) |*d| d.used = false;
        for (v.dur_dentries[0..v.dur_hwm]) |*d| d.used = false;
        v.cur_hwm = 0;
        v.dur_hwm = 0;
        v.journal_len = 0;
        for (v.handles) |*h| h.used = false;
        v.inodes[root_inode] = .{
            .kind = .dir,
            .cur_len_bytes = 0,
            .dur_len_bytes = 0,
            .parent = root_inode,
            .cur_links = 1,
            .dur_links = 1,
            .journal_refs = 0,
            .open_count = 0,
            .mtime_ns = 0,
        };
    }

    // ------------------------------------------------------------------
    // Pages

    fn pageAlloc(v: *Vfs) Error!u32 {
        if (v.free_pages_len == 0) return error.NoSpaceLeft;
        v.free_pages_len -= 1;
        const p = v.free_pages[v.free_pages_len];
        assert(v.page_refs[p] == 0);
        v.page_refs[p] = 1;
        v.page_hwm = @max(v.page_hwm, p + 1);
        return p;
    }

    fn pageRef(v: *Vfs, p: u32) void {
        if (p == 0) return;
        assert(v.page_refs[p] > 0);
        v.page_refs[p] += 1;
    }

    fn pageUnref(v: *Vfs, p: u32) void {
        if (p == 0) return;
        assert(v.page_refs[p] > 0);
        v.page_refs[p] -= 1;
        if (v.page_refs[p] == 0) {
            v.free_pages[v.free_pages_len] = p;
            v.free_pages_len += 1;
        }
    }

    fn pageData(v: *Vfs, p: u32) *[page_bytes]u8 {
        return v.pages[@as(usize, p) * page_bytes ..][0..page_bytes];
    }

    fn curSlots(v: *Vfs, ino: InodeId) []u32 {
        const n = v.limits.file_pages_max;
        return v.cur_slots[@as(usize, ino) * n ..][0..n];
    }

    fn durSlots(v: *Vfs, ino: InodeId) []u32 {
        const n = v.limits.file_pages_max;
        return v.dur_slots[@as(usize, ino) * n ..][0..n];
    }

    fn pagesFor(len_bytes: u64) usize {
        return @intCast((len_bytes + page_bytes - 1) / page_bytes);
    }

    /// Returns a page for slot `idx` of `ino`'s cur view that is safe to write.
    fn writableCurPage(v: *Vfs, ino: InodeId, idx: usize) Error!u32 {
        const slots = v.curSlots(ino);
        const p = slots[idx];
        if (p != 0 and v.page_refs[p] == 1) return p;
        const fresh = try v.pageAlloc();
        @memcpy(v.pageData(fresh), v.pageData(p));
        v.pageUnref(p);
        slots[idx] = fresh;
        return fresh;
    }

    /// Number of pages currently referenced (for conservation checks).
    pub fn livePageCount(v: *const Vfs) u32 {
        return v.limits.pages_max - 1 - v.free_pages_len;
    }

    /// A filesystem's state at one moment, sharing its pages: the tables
    /// are copied, and every page in use gets one more reference in the
    /// live filesystem, so later writes copy the page instead of changing
    /// it (pages are copy-on-write above one reference).
    pub const Snapshot = struct {
        persona: Persona,
        now_ns: u64,
        epoch: u16,
        flushed_pages: u64,
        free_pages_len: u32,
        page_hwm: u32,
        cur_hwm: usize,
        dur_hwm: usize,
        inode_hwm: usize,
        journal_len: u32,
        /// References of the pages below `page_hwm`, and the free list
        /// above its untouched bottom.
        page_refs: []u16,
        free_pages: []u32,
        inodes: []Inode,
        cur_slots: []u32,
        dur_slots: []u32,
        /// Per inode, how many of its page slots are in use (the rest are
        /// zero, as `reset` leaves them): `restore` copies only those.
        slot_counts: []u32,
        cur_dentries: []Dentry,
        dur_dentries: []Dentry,
        journal: []JournalOp,

        pub fn deinit(sn: *Snapshot, gpa: Allocator) void {
            gpa.free(sn.slot_counts);
            gpa.free(sn.journal);
            gpa.free(sn.dur_dentries);
            gpa.free(sn.cur_dentries);
            gpa.free(sn.dur_slots);
            gpa.free(sn.cur_slots);
            gpa.free(sn.inodes);
            gpa.free(sn.free_pages);
            gpa.free(sn.page_refs);
            sn.* = undefined;
        }
    };

    /// True if no file or directory handle is open.
    pub fn noHandles(v: *const Vfs) bool {
        for (v.handles) |h| if (h.used) return false;
        return true;
    }

    /// Gives every page in use one more reference (see `Snapshot`).
    fn pin(v: *Vfs) void {
        for (v.page_refs[1..v.page_hwm]) |*r| {
            if (r.* == 0) continue;
            assert(r.* < std.math.maxInt(u16));
            r.* += 1;
        }
    }

    /// Takes a snapshot and pins the pages it shares. No handle may be
    /// open (handles are not part of it).
    pub fn snapshot(v: *Vfs, gpa: Allocator) Allocator.Error!Snapshot {
        assert(v.noHandles());
        const n_slots = v.inode_hwm * v.limits.file_pages_max;
        const page_refs = try gpa.dupe(u16, v.page_refs[0..v.page_hwm]);
        errdefer gpa.free(page_refs);
        const free_pages = try gpa.dupe(u32, v.free_pages[v.limits.pages_max - v.page_hwm .. v.free_pages_len]);
        errdefer gpa.free(free_pages);
        const inodes = try gpa.dupe(Inode, v.inodes[0..v.inode_hwm]);
        errdefer gpa.free(inodes);
        const cur_slots = try gpa.dupe(u32, v.cur_slots[0..n_slots]);
        errdefer gpa.free(cur_slots);
        const dur_slots = try gpa.dupe(u32, v.dur_slots[0..n_slots]);
        errdefer gpa.free(dur_slots);
        const cur_dentries = try gpa.dupe(Dentry, v.cur_dentries[0..v.cur_hwm]);
        errdefer gpa.free(cur_dentries);
        const dur_dentries = try gpa.dupe(Dentry, v.dur_dentries[0..v.dur_hwm]);
        errdefer gpa.free(dur_dentries);
        const journal = try gpa.dupe(JournalOp, v.journal[0..v.journal_len]);
        errdefer gpa.free(journal);
        const slot_counts = try gpa.alloc(u32, v.inode_hwm);
        const per = v.limits.file_pages_max;
        for (slot_counts, 0..) |*count, ino| {
            var used: u32 = per;
            while (used > 0 and cur_slots[ino * per + used - 1] == 0 and dur_slots[ino * per + used - 1] == 0) used -= 1;
            count.* = used;
        }
        v.pin();
        return .{
            .persona = v.persona,
            .now_ns = v.now_ns,
            .epoch = v.epoch,
            .flushed_pages = v.flushed_pages,
            .free_pages_len = v.free_pages_len,
            .page_hwm = v.page_hwm,
            .cur_hwm = v.cur_hwm,
            .dur_hwm = v.dur_hwm,
            .inode_hwm = v.inode_hwm,
            .journal_len = v.journal_len,
            .page_refs = page_refs,
            .free_pages = free_pages,
            .inodes = inodes,
            .cur_slots = cur_slots,
            .dur_slots = dur_slots,
            .slot_counts = slot_counts,
            .cur_dentries = cur_dentries,
            .dur_dentries = dur_dentries,
            .journal = journal,
        };
    }

    /// True if the filesystem's tables are those of `sn` (before pinning):
    /// what a re-run of the same deterministic setup must give.
    pub fn matches(v: *const Vfs, sn: *const Snapshot) bool {
        return v.persona == sn.persona and v.now_ns == sn.now_ns and v.epoch == sn.epoch and
            v.flushed_pages == sn.flushed_pages and v.free_pages_len == sn.free_pages_len and
            v.cur_hwm == sn.cur_hwm and v.dur_hwm == sn.dur_hwm and v.inode_hwm == sn.inode_hwm and
            v.journal_len == sn.journal_len and
            v.page_hwm == sn.page_hwm and
            std.mem.eql(u16, v.page_refs[0..v.page_hwm], sn.page_refs) and
            std.mem.eql(u32, v.free_pages[v.limits.pages_max - v.page_hwm .. v.free_pages_len], sn.free_pages) and
            std.mem.eql(u32, v.cur_slots[0..sn.cur_slots.len], sn.cur_slots) and
            std.mem.eql(u32, v.dur_slots[0..sn.dur_slots.len], sn.dur_slots);
    }

    /// Makes a freshly `reset` filesystem the one `sn` was taken from. The
    /// pages `sn` shares still hold their contents, since they stayed
    /// pinned; they are pinned again.
    pub fn restore(v: *Vfs, sn: *const Snapshot) void {
        v.persona = sn.persona;
        v.now_ns = sn.now_ns;
        v.epoch = sn.epoch;
        v.flushed_pages = sn.flushed_pages;
        // A reset filesystem has taken no page, and one compared with the
        // snapshot has taken the same ones: nothing above the snapshot's
        // high-water mark needs writing.
        assert(v.page_hwm <= sn.page_hwm);
        v.page_hwm = sn.page_hwm;
        @memcpy(v.page_refs[0..sn.page_refs.len], sn.page_refs);
        v.free_pages_len = sn.free_pages_len;
        @memcpy(v.free_pages[v.limits.pages_max - sn.page_hwm ..][0..sn.free_pages.len], sn.free_pages);
        @memcpy(v.inodes[0..sn.inodes.len], sn.inodes);
        // The slots in use; the others are zero in a reset filesystem, and
        // equal to the snapshot's after a setup that was compared with it.
        const per = v.limits.file_pages_max;
        for (sn.slot_counts, 0..) |used, ino| {
            const at = ino * per;
            @memcpy(v.cur_slots[at..][0..used], sn.cur_slots[at..][0..used]);
            @memcpy(v.dur_slots[at..][0..used], sn.dur_slots[at..][0..used]);
        }
        @memcpy(v.cur_dentries[0..sn.cur_dentries.len], sn.cur_dentries);
        @memcpy(v.dur_dentries[0..sn.dur_dentries.len], sn.dur_dentries);
        @memcpy(v.journal[0..sn.journal.len], sn.journal);
        v.cur_hwm = sn.cur_hwm;
        v.dur_hwm = sn.dur_hwm;
        v.inode_hwm = sn.inode_hwm;
        v.journal_len = sn.journal_len;
        v.pin();
    }

    /// Verifies that page refcounts equal the number of slot references.
    pub fn checkPageConservation(v: *Vfs) !void {
        const counts = try v.gpa.alloc(u32, v.limits.pages_max);
        defer v.gpa.free(counts);
        @memset(counts, 0);
        for (v.cur_slots) |p| counts[p] += 1;
        for (v.dur_slots) |p| counts[p] += 1;
        var p: usize = 1;
        while (p < counts.len) : (p += 1) {
            if (counts[p] != v.page_refs[p]) return error.PageRefcountMismatch;
        }
    }

    // ------------------------------------------------------------------
    // Inodes

    fn inodeAlloc(v: *Vfs, kind: Kind) Error!InodeId {
        for (v.inodes, 0..) |*i, idx| {
            if (idx == root_inode) continue;
            if (i.kind != .free) continue;
            v.inode_hwm = @max(v.inode_hwm, idx + 1);
            i.* = .{
                .kind = kind,
                .cur_len_bytes = 0,
                .dur_len_bytes = 0,
                .parent = root_inode,
                .cur_links = 0,
                .dur_links = 0,
                .journal_refs = 0,
                .open_count = 0,
                .mtime_ns = v.now_ns,
            };
            return @intCast(idx);
        }
        return error.NoSpaceLeft;
    }

    fn inodeRelease(v: *Vfs, ino: InodeId) void {
        assert(ino != root_inode);
        for (v.curSlots(ino)) |*p| {
            v.pageUnref(p.*);
            p.* = 0;
        }
        for (v.durSlots(ino)) |*p| {
            v.pageUnref(p.*);
            p.* = 0;
        }
        v.inodes[ino] = std.mem.zeroes(Inode);
    }

    fn maybeFree(v: *Vfs, ino: InodeId) void {
        if (ino == root_inode) return;
        const i = &v.inodes[ino];
        if (i.kind == .free) return;
        if (i.cur_links != 0) return;
        if (i.dur_links != 0) return;
        if (i.journal_refs != 0) return;
        if (i.open_count != 0) return;
        v.inodeRelease(ino);
    }

    pub fn inode(v: *Vfs, ino: InodeId) *Inode {
        assert(v.inodes[ino].kind != .free);
        return &v.inodes[ino];
    }

    // ------------------------------------------------------------------
    // Names and paths

    fn isSeparator(v: *const Vfs, c: u8) bool {
        return c == '/' or (c == '\\' and v.persona.backslashSeparator());
    }

    fn nameEql(v: *const Vfs, a: []const u8, b: []const u8) bool {
        if (!v.persona.caseInsensitive()) return std.mem.eql(u8, a, b);
        return namesEqual(a, b, v.persona.normalizationInsensitive());
    }

    /// The name a lookup or create uses for component `name` (not `.` or
    /// `..`): the Win32 rules on `win32Names` personas, else `name`.
    fn canonicalName(v: *const Vfs, name: []const u8) []const u8 {
        return if (v.persona.win32Names()) win32Name(name) else name;
    }

    /// The short-name ordinal for `name` under `parent`, or 0 when it needs
    /// none or all of `~1`..`~4` are taken (Windows then derives a hashed
    /// name, which is not modelled). `slot` is the entry being named.
    fn shortOrdinal(v: *const Vfs, parent: InodeId, name: []const u8, slot: usize) u8 {
        if (!v.persona.win32Names()) return 0;
        var mine: [12]u8 = undefined;
        if (shortName(name, 1, &mine) == null) return 0;
        var n: u8 = 1;
        next: while (n <= short_ordinal_max) : (n += 1) {
            for (v.cur_dentries[0..v.cur_hwm], 0..) |*d, idx| {
                if (!d.used or d.parent != parent or idx == slot or d.short != n) continue;
                var theirs: [12]u8 = undefined;
                const a = shortName(name, n, &mine).?;
                const b = shortName(d.nameSlice(), n, &theirs) orelse continue;
                if (std.mem.eql(u8, a, b)) continue :next;
            }
            return n;
        }
        return 0;
    }

    /// The entry under `parent` whose 8.3 short name is `name`.
    fn findShort(v: *Vfs, parent: InodeId, name: []const u8) ?usize {
        if (!v.persona.win32Names() or std.mem.indexOfScalar(u8, name, '~') == null) return null;
        for (v.cur_dentries[0..v.cur_hwm], 0..) |*d, idx| {
            if (!d.used or d.parent != parent or d.short == 0) continue;
            var buf: [12]u8 = undefined;
            const short = shortName(d.nameSlice(), d.short, &buf) orelse continue;
            if (std.ascii.eqlIgnoreCase(short, name)) return idx;
        }
        return null;
    }

    fn validateName(v: *const Vfs, name: []const u8) Error!void {
        if (name.len == 0) return error.BadPathName;
        if (name.len > name_bytes_max) return error.NameTooLong;
        for (name) |c| {
            if (c == 0) return error.BadPathName;
        }
        if (v.persona != .windows_ntfs) return;
        for (name) |c| {
            if (c < 0x20) return error.BadPathName;
            switch (c) {
                '<', '>', ':', '"', '|', '?', '*' => return error.BadPathName,
                else => {},
            }
        }
        if (name[name.len - 1] == ' ' or name[name.len - 1] == '.') return error.BadPathName;
        const stem_end = std.mem.indexOfScalar(u8, name, '.') orelse name.len;
        const stem = name[0..stem_end];
        const reserved = [_][]const u8{ "CON", "PRN", "AUX", "NUL" };
        for (reserved) |r| {
            if (std.ascii.eqlIgnoreCase(stem, r)) return error.BadPathName;
        }
        if (stem.len == 4 and (std.ascii.startsWithIgnoreCase(stem, "COM") or std.ascii.startsWithIgnoreCase(stem, "LPT"))) {
            if (stem[3] >= '1' and stem[3] <= '9') return error.BadPathName;
        }
    }

    fn findCur(v: *Vfs, parent: InodeId, name: []const u8) ?usize {
        for (v.cur_dentries[0..v.cur_hwm], 0..) |*d, idx| {
            if (!d.used or d.parent != parent) continue;
            if (v.nameEql(d.nameSlice(), name)) return idx;
        }
        return v.findShort(parent, name);
    }

    fn findDur(v: *Vfs, parent: InodeId, name: []const u8) ?usize {
        for (v.dur_dentries[0..v.dur_hwm], 0..) |*d, idx| {
            if (!d.used or d.parent != parent) continue;
            if (v.nameEql(d.nameSlice(), name)) return idx;
        }
        return null;
    }

    fn hasChildren(v: *Vfs, dir: InodeId) bool {
        for (v.cur_dentries[0..v.cur_hwm]) |*d| {
            if (d.used and d.parent == dir) return true;
        }
        return false;
    }

    const Component = struct { name: []const u8, rest: []const u8 };

    fn nextComponent(v: *const Vfs, path: []const u8) ?Component {
        var i: usize = 0;
        while (i < path.len and v.isSeparator(path[i])) i += 1;
        if (i == path.len) return null;
        var j = i;
        while (j < path.len and !v.isSeparator(path[j])) j += 1;
        return .{ .name = path[i..j], .rest = path[j..] };
    }

    fn startDir(v: *const Vfs, dir: InodeId, path: []const u8) InodeId {
        if (path.len > 0 and v.isSeparator(path[0])) return root_inode;
        return dir;
    }

    /// A path that goes through something that is not a directory. NTFS
    /// reports the path as not found; POSIX systems say which component
    /// was wrong. Found by the differential test (`diff_fs_test.zig`).
    fn throughNonDir(v: *const Vfs) Error {
        return if (v.persona.win32Names()) error.FileNotFound else error.NotDir;
    }

    fn step(v: *Vfs, cur: InodeId, name: []const u8) Error!InodeId {
        if (v.inodes[cur].kind != .dir) return v.throughNonDir();
        if (std.mem.eql(u8, name, ".")) return cur;
        if (std.mem.eql(u8, name, "..")) return v.inodes[cur].parent;
        const canonical = v.canonicalName(name);
        try v.validateName(canonical);
        const idx = v.findCur(cur, canonical) orelse return error.FileNotFound;
        return v.cur_dentries[idx].inode;
    }

    /// Resolves a full path relative to `dir`, following symlinks.
    pub fn lookup(v: *Vfs, dir: InodeId, path: []const u8) Error!InodeId {
        return v.lookupEx(dir, path, true);
    }

    /// Resolves a full path relative to `dir`. Symlinks in intermediate
    /// components are always followed; the last one only if `follow_last`.
    pub fn lookupEx(v: *Vfs, dir: InodeId, path: []const u8, follow_last: bool) Error!InodeId {
        var cur = v.startDir(dir, path);
        var rest = path;
        var hops: u32 = 0;
        var which: usize = 0;
        while (v.nextComponent(rest)) |c| {
            const next = try v.step(cur, c.name);
            const is_last = v.nextComponent(c.rest) == null;
            if (v.inodes[next].kind != .symlink or (is_last and !follow_last)) {
                cur = next;
                rest = c.rest;
                continue;
            }
            hops += 1;
            if (hops > symlink_hops_max) return error.SymLinkLoop;
            // rest := target ++ "/" ++ c.rest, resolved from the link's directory
            // (or the root for an absolute target). `c.rest` may point into the
            // other buffer, never into this one.
            const buf = &v.path_bufs[which];
            which ^= 1;
            const target_len: usize = @intCast(v.inodes[next].cur_len_bytes);
            if (target_len + 1 + c.rest.len > buf.len) return error.NameTooLong;
            _ = v.read(next, 0, buf[0..target_len]);
            buf[target_len] = '/';
            @memcpy(buf[target_len + 1 ..][0..c.rest.len], c.rest);
            rest = buf[0 .. target_len + 1 + c.rest.len];
            if (target_len > 0 and v.isSeparator(buf[0])) cur = root_inode;
        }
        return cur;
    }

    const ParentAndName = struct { parent: InodeId, name: []const u8 };

    /// Resolves all but the last component (following symlinks). The last
    /// component must be a plain name.
    fn resolveParent(v: *Vfs, dir: InodeId, path: []const u8) Error!ParentAndName {
        var rest = path;
        var last: ?[]const u8 = null;
        while (v.nextComponent(rest)) |c| {
            last = c.name;
            rest = c.rest;
        }
        const last_name = last orelse return error.BadPathName;
        if (std.mem.eql(u8, last_name, ".") or std.mem.eql(u8, last_name, "..")) return error.BadPathName;
        const name = v.canonicalName(last_name);
        try v.validateName(name);
        const prefix = path[0 .. @intFromPtr(last_name.ptr) - @intFromPtr(path.ptr)];
        const parent = try v.lookupEx(dir, prefix, true);
        if (v.inodes[parent].kind != .dir) return v.throughNonDir();
        return .{ .parent = parent, .name = name };
    }

    // ------------------------------------------------------------------
    // Journal

    fn journalAppend(v: *Vfs, op: JournalOp) void {
        if (v.journal_len == v.journal.len) v.commitJournal(v.journal_len);
        v.journal[v.journal_len] = op;
        v.journal_len += 1;
        v.inodes[op.inode].journal_refs += 1;
    }

    fn makeOp(kind: OpKind, ino: InodeId, parent: InodeId, name: []const u8, parent2: InodeId, name2: []const u8, replaced: bool) JournalOp {
        var op: JournalOp = undefined;
        op.kind = kind;
        op.inode = ino;
        op.replaced_existing = replaced;
        op.parent = parent;
        op.name_len = @intCast(name.len);
        @memcpy(op.name[0..name.len], name);
        op.parent2 = parent2;
        op.name2_len = @intCast(name2.len);
        @memcpy(op.name2[0..name2.len], name2);
        return op;
    }

    fn durRemove(v: *Vfs, idx: usize) void {
        const d = &v.dur_dentries[idx];
        assert(d.used);
        v.inodes[d.inode].dur_links -= 1;
        d.used = false;
        v.maybeFree(d.inode);
    }

    fn durInsert(v: *Vfs, parent: InodeId, name: []const u8, ino: InodeId) void {
        for (v.dur_dentries, 0..) |*d, idx| {
            if (d.used) continue;
            v.dur_hwm = @max(v.dur_hwm, idx + 1);
            d.* = .{ .used = true, .parent = parent, .inode = ino, .name_len = @intCast(name.len), .name = undefined };
            @memcpy(d.name[0..name.len], name);
            v.inodes[ino].dur_links += 1;
            return;
        }
        unreachable; // dur table is sized dentries_max + journal_max
    }

    fn applyOp(v: *Vfs, op: *const JournalOp) void {
        const name = op.name[0..op.name_len];
        switch (op.kind) {
            .link => {
                if (v.findDur(op.parent, name)) |idx| v.durRemove(idx);
                v.durInsert(op.parent, name, op.inode);
            },
            .unlink => {
                if (v.findDur(op.parent, name)) |idx| v.durRemove(idx);
            },
            .rename => {
                const src = v.findDur(op.parent, name) orelse return;
                const name2 = op.name2[0..op.name2_len];
                if (op.replaced_existing and v.persona.renameFlushesData()) {
                    v.syncData(v.dur_dentries[src].inode);
                }
                if (v.findDur(op.parent2, name2)) |dst| {
                    if (dst != src) v.durRemove(dst);
                }
                const d = &v.dur_dentries[src];
                d.parent = op.parent2;
                d.name_len = op.name2_len;
                @memcpy(d.name[0..name2.len], name2);
            },
        }
    }

    fn dropOp(v: *Vfs, op: *const JournalOp) void {
        const i = &v.inodes[op.inode];
        assert(i.journal_refs > 0);
        i.journal_refs -= 1;
        v.maybeFree(op.inode);
    }

    /// Applies the first `n` journal ops to the durable namespace.
    fn commitJournal(v: *Vfs, n: u32) void {
        assert(n <= v.journal_len);
        var k: u32 = 0;
        while (k < n) : (k += 1) {
            v.applyOp(&v.journal[k]);
            v.dropOp(&v.journal[k]);
        }
        const remaining = v.journal_len - n;
        std.mem.copyForwards(JournalOp, v.journal[0..remaining], v.journal[n..v.journal_len]);
        v.journal_len = remaining;
    }

    pub fn journalPending(v: *const Vfs) u32 {
        return v.journal_len;
    }

    // ------------------------------------------------------------------
    // Namespace operations

    pub const CreateOptions = struct { exclusive: bool = false, truncate: bool = true };

    pub fn createFile(v: *Vfs, dir: InodeId, path: []const u8, options: CreateOptions) Error!InodeId {
        return v.createFileVia(dir, path, options, 0);
    }

    /// `links` counts the dangling symlinks followed to get here.
    fn createFileVia(v: *Vfs, dir: InodeId, path: []const u8, options: CreateOptions, links: u8) Error!InodeId {
        const pn = try v.resolveParent(dir, path);
        if (v.findCur(pn.parent, pn.name)) |idx| {
            // NTFS says what is in the way when it is a directory; POSIX
            // says only that something is. Found by the differential test.
            if (options.exclusive and v.persona.win32Names() and v.inodes[v.cur_dentries[idx].inode].kind == .dir) return error.IsDir;
            if (options.exclusive) return error.PathAlreadyExists;
            var ino = v.cur_dentries[idx].inode;
            if (v.inodes[ino].kind == .symlink) {
                ino = v.lookupEx(pn.parent, pn.name, true) catch |err| {
                    // A link to a file that is not there: POSIX creates
                    // the file the link names. Found by the differential
                    // test.
                    if (err != error.FileNotFound or v.persona.win32Names()) return err;
                    if (links == 8) return error.SymLinkLoop;
                    var target: [path_bytes_max]u8 = undefined;
                    const n: usize = @intCast(v.inodes[ino].cur_len_bytes);
                    _ = v.read(ino, 0, target[0..n]);
                    return v.createFileVia(pn.parent, target[0..n], options, links + 1);
                };
            }
            if (v.inodes[ino].kind == .dir) return error.IsDir;
            if (options.truncate) try v.setLength(ino, 0);
            return ino;
        }
        return v.link(pn.parent, pn.name, .file);
    }

    fn freeDentrySlot(v: *Vfs) Error!usize {
        for (v.cur_dentries[0..v.cur_hwm], 0..) |*d, idx| {
            if (!d.used) return idx;
        }
        if (v.cur_hwm == v.cur_dentries.len) return error.NoSpaceLeft;
        v.cur_hwm += 1;
        return v.cur_hwm - 1;
    }

    /// Adds the name `parent/name` for existing inode `ino` (journaled).
    fn addDentry(v: *Vfs, slot: usize, parent: InodeId, name: []const u8, ino: InodeId) void {
        const d = &v.cur_dentries[slot];
        d.* = .{ .used = true, .parent = parent, .inode = ino, .name_len = @intCast(name.len), .name = undefined };
        @memcpy(d.name[0..name.len], name);
        d.short = v.shortOrdinal(parent, name, slot);
        v.inodes[ino].cur_links += 1;
        v.inodes[parent].mtime_ns = v.now_ns;
        v.journalAppend(makeOp(.link, ino, parent, name, parent, "", false));
    }

    fn link(v: *Vfs, parent: InodeId, name: []const u8, kind: Kind) Error!InodeId {
        const slot = try v.freeDentrySlot();
        const ino = try v.inodeAlloc(kind);
        v.inodes[ino].parent = parent;
        v.addDentry(slot, parent, name, ino);
        return ino;
    }

    /// Creates a hard link `path` to file `ino`.
    pub fn hardLink(v: *Vfs, ino: InodeId, dir: InodeId, path: []const u8) Error!void {
        // The destination first: a kernel reports a missing parent or a
        // name already taken before it objects to linking a directory.
        // Found by the differential test (`diff_fs_test.zig`).
        const pn = try v.resolveParent(dir, path);
        if (v.findCur(pn.parent, pn.name) != null) return error.PathAlreadyExists;
        if (v.inodes[ino].kind == .dir) return error.PermissionDenied;
        v.addDentry(try v.freeDentrySlot(), pn.parent, pn.name, ino);
    }

    /// Creates symlink `path` pointing at `target`. The target is written with
    /// the inode, so it is durable whenever the link's name is.
    pub fn symLink(v: *Vfs, dir: InodeId, target: []const u8, path: []const u8) Error!void {
        if (target.len == 0) return error.FileNotFound;
        if (target.len > path_bytes_max) return error.NameTooLong;
        const pn = try v.resolveParent(dir, path);
        if (v.findCur(pn.parent, pn.name) != null) return error.PathAlreadyExists;
        if (v.free_pages_len == 0) return error.NoSpaceLeft;
        const ino = try v.link(pn.parent, pn.name, .symlink);
        const n = v.write(ino, 0, target) catch unreachable; // one page is free
        assert(n == target.len);
        v.syncData(ino);
    }

    /// Copies the target of symlink `path` into `buffer`; returns its length.
    pub fn readLink(v: *Vfs, dir: InodeId, path: []const u8, buffer: []u8) Error!usize {
        const ino = try v.lookupEx(dir, path, false);
        if (v.inodes[ino].kind != .symlink) return error.NotLink;
        return v.read(ino, 0, buffer);
    }

    pub fn makeDir(v: *Vfs, dir: InodeId, path: []const u8) Error!InodeId {
        const pn = try v.resolveParent(dir, path);
        if (v.findCur(pn.parent, pn.name) != null) return error.PathAlreadyExists;
        return v.link(pn.parent, pn.name, .dir);
    }

    pub const MakePathStatus = enum { existed, created };

    /// Creates every missing directory along `path`.
    pub fn makePath(v: *Vfs, dir: InodeId, path: []const u8) Error!struct { inode: InodeId, status: MakePathStatus } {
        var cur = v.startDir(dir, path);
        var rest = path;
        var status: MakePathStatus = .existed;
        while (v.nextComponent(rest)) |c| {
            rest = c.rest;
            if (std.mem.eql(u8, c.name, ".") or std.mem.eql(u8, c.name, "..")) {
                cur = try v.step(cur, c.name);
                continue;
            }
            const name = v.canonicalName(c.name);
            try v.validateName(name);
            if (v.inodes[cur].kind != .dir) return error.NotDir;
            if (v.findCur(cur, name)) |idx| {
                const found = v.cur_dentries[idx].inode;
                cur = if (v.inodes[found].kind == .symlink) try v.lookupEx(cur, name, true) else found;
                if (v.inodes[cur].kind != .dir) return error.NotDir;
                status = .existed;
            } else {
                cur = try v.link(cur, name, .dir);
                status = .created;
            }
        }
        return .{ .inode = cur, .status = status };
    }

    fn unlinkAt(v: *Vfs, parent: InodeId, idx: usize) void {
        const d = &v.cur_dentries[idx];
        const ino = d.inode;
        const name = d.nameSlice();
        v.journalAppend(makeOp(.unlink, ino, parent, name, parent, "", false));
        d.used = false;
        v.inodes[ino].cur_links -= 1;
        v.inodes[parent].mtime_ns = v.now_ns;
        v.maybeFree(ino);
    }

    pub fn deleteFile(v: *Vfs, dir: InodeId, path: []const u8) Error!void {
        const pn = try v.resolveParent(dir, path);
        const idx = v.findCur(pn.parent, pn.name) orelse return error.FileNotFound;
        const ino = v.cur_dentries[idx].inode;
        if (v.inodes[ino].kind == .dir) return error.IsDir;
        if (v.persona.sharingViolations() and v.inodes[ino].open_count > 0) return error.FileBusy;
        v.unlinkAt(pn.parent, idx);
    }

    pub fn deleteDir(v: *Vfs, dir: InodeId, path: []const u8) Error!void {
        const pn = try v.resolveParent(dir, path);
        const idx = v.findCur(pn.parent, pn.name) orelse return error.FileNotFound;
        const ino = v.cur_dentries[idx].inode;
        if (v.inodes[ino].kind != .dir) return error.NotDir;
        if (v.hasChildren(ino)) return error.DirNotEmpty;
        if (v.persona.sharingViolations() and v.inodes[ino].open_count > 0) return error.FileBusy;
        v.unlinkAt(pn.parent, idx);
    }

    fn isAncestor(v: *Vfs, ancestor: InodeId, of: InodeId) bool {
        var cur = of;
        var steps: u32 = 0;
        while (steps < v.limits.inodes_max) : (steps += 1) {
            if (cur == ancestor) return true;
            if (cur == root_inode) return false;
            cur = v.inodes[cur].parent;
        }
        return false;
    }

    pub fn rename(v: *Vfs, old_dir: InodeId, old_path: []const u8, new_dir: InodeId, new_path: []const u8) Error!void {
        const src = try v.resolveParent(old_dir, old_path);
        const dst = try v.resolveParent(new_dir, new_path);
        const src_idx = v.findCur(src.parent, src.name) orelse return error.FileNotFound;
        const ino = v.cur_dentries[src_idx].inode;
        const kind = v.inodes[ino].kind;
        if (v.persona.sharingViolations() and v.inodes[ino].open_count > 0) return error.FileBusy;
        if (kind == .dir and v.isAncestor(ino, dst.parent)) return error.BadPathName;

        var replaced = false;
        if (v.findCur(dst.parent, dst.name)) |dst_idx| {
            if (dst_idx == src_idx) return;
            const victim = v.cur_dentries[dst_idx].inode;
            // Two names of one file: POSIX `rename` does nothing and both
            // names stay. Found by the differential test.
            if (victim == ino and !v.persona.win32Names()) return;
            const vkind = v.inodes[victim].kind;
            // Onto a directory the source lives under: POSIX kernels find
            // that before they compare kinds, and call it not empty. Found
            // by the differential test (`diff_fs_test.zig`).
            if (!v.persona.win32Names() and vkind == .dir and v.isAncestor(victim, src.parent)) return error.DirNotEmpty;
            // Anything that is not a directory, a symbolic link included.
            if (kind != .dir and vkind == .dir) return error.IsDir;
            // A directory replaces only a directory: not a file, and on
            // POSIX not a symbolic link either (differential test).
            if (kind == .dir and (vkind == .file or (vkind == .symlink and !v.persona.win32Names()))) return error.NotDir;
            if (vkind == .dir and v.hasChildren(victim)) return error.DirNotEmpty;
            if (v.persona.sharingViolations() and v.inodes[victim].open_count > 0) return error.FileBusy;
            v.cur_dentries[dst_idx].used = false;
            v.inodes[victim].cur_links -= 1;
            replaced = true;
            // The victim may be freed only after the journal op is appended,
            // because the op does not reference it (it is still dur-linked).
            v.maybeFree(victim);
        }
        v.journalAppend(makeOp(.rename, ino, src.parent, src.name, dst.parent, dst.name, replaced));
        const d = &v.cur_dentries[src_idx];
        d.parent = dst.parent;
        d.name_len = @intCast(dst.name.len);
        @memcpy(d.name[0..dst.name.len], dst.name);
        d.short = 0;
        d.short = v.shortOrdinal(dst.parent, dst.name, src_idx);
        if (kind == .dir) v.inodes[ino].parent = dst.parent;
        v.inodes[src.parent].mtime_ns = v.now_ns;
        v.inodes[dst.parent].mtime_ns = v.now_ns;
    }

    // ------------------------------------------------------------------
    // Data

    pub fn read(v: *Vfs, ino: InodeId, offset: u64, buffer: []u8) usize {
        const i = &v.inodes[ino];
        if (offset >= i.cur_len_bytes) return 0;
        const n: usize = @intCast(@min(buffer.len, i.cur_len_bytes - offset));
        const slots = v.curSlots(ino);
        var done: usize = 0;
        while (done < n) {
            const pos = offset + done;
            const page_idx: usize = @intCast(pos / page_bytes);
            const in_page: usize = @intCast(pos % page_bytes);
            const chunk = @min(n - done, page_bytes - in_page);
            @memcpy(buffer[done..][0..chunk], v.pageData(slots[page_idx])[in_page..][0..chunk]);
            done += chunk;
        }
        return n;
    }

    pub fn write(v: *Vfs, ino: InodeId, offset: u64, data: []const u8) Error!usize {
        const cap: u64 = @as(u64, v.limits.file_pages_max) * page_bytes;
        if (offset >= cap and data.len > 0) return error.FileTooBig;
        const n: usize = @intCast(@min(data.len, cap - offset));
        var done: usize = 0;
        while (done < n) {
            const pos = offset + done;
            const page_idx: usize = @intCast(pos / page_bytes);
            const in_page: usize = @intCast(pos % page_bytes);
            const chunk = @min(n - done, page_bytes - in_page);
            const p = v.writableCurPage(ino, page_idx) catch |err| {
                if (done > 0) break;
                return err;
            };
            @memcpy(v.pageData(p)[in_page..][0..chunk], data[done..][0..chunk]);
            done += chunk;
        }
        const i = &v.inodes[ino];
        i.cur_len_bytes = @max(i.cur_len_bytes, offset + done);
        i.mtime_ns = v.now_ns;
        return done;
    }

    pub fn setLength(v: *Vfs, ino: InodeId, len_bytes: u64) Error!void {
        const cap: u64 = @as(u64, v.limits.file_pages_max) * page_bytes;
        if (len_bytes > cap) return error.FileTooBig;
        const i = &v.inodes[ino];
        if (len_bytes < i.cur_len_bytes) {
            // Keep the invariant: bytes at or beyond len in cur pages are zero.
            const keep = pagesFor(len_bytes);
            const slots = v.curSlots(ino);
            const in_page: usize = @intCast(len_bytes % page_bytes);
            if (in_page != 0 and slots[keep - 1] != 0) {
                const p = try v.writableCurPage(ino, keep - 1);
                @memset(v.pageData(p)[in_page..], 0);
            }
            for (slots[keep..pagesFor(i.cur_len_bytes)]) |*p| {
                v.pageUnref(p.*);
                p.* = 0;
            }
        }
        i.cur_len_bytes = len_bytes;
        i.mtime_ns = v.now_ns;
    }

    /// Makes `ino`'s data durable (no metadata).
    fn syncData(v: *Vfs, ino: InodeId) void {
        const i = &v.inodes[ino];
        const cur = v.curSlots(ino);
        const dur = v.durSlots(ino);
        const n = @max(pagesFor(i.cur_len_bytes), pagesFor(i.dur_len_bytes));
        for (cur[0..n], dur[0..n]) |c, *d| {
            if (c == d.*) continue;
            v.flushed_pages += 1;
            v.pageRef(c);
            v.pageUnref(d.*);
            d.* = c;
        }
        i.dur_len_bytes = i.cur_len_bytes;
    }

    /// `fsync`. Commits data, and metadata according to the persona.
    pub fn sync(v: *Vfs, ino: InodeId) void {
        const i = &v.inodes[ino];
        if (i.kind == .file) v.syncData(ino);
        if (v.persona.fileSyncCommitsJournal()) {
            v.commitJournal(v.journal_len);
            return;
        }
        if (i.kind != .dir) return;
        // posix_strict: commit through the last op that touches this directory.
        var last: u32 = 0;
        var k: u32 = 0;
        while (k < v.journal_len) : (k += 1) {
            const op = &v.journal[k];
            if (op.parent == ino or op.parent2 == ino) last = k + 1;
        }
        v.commitJournal(last);
    }

    pub fn isDirty(v: *Vfs, ino: InodeId) bool {
        const i = &v.inodes[ino];
        if (i.cur_len_bytes != i.dur_len_bytes) return true;
        const n = pagesFor(i.cur_len_bytes);
        return !std.mem.eql(u32, v.curSlots(ino)[0..n], v.durSlots(ino)[0..n]);
    }

    // ------------------------------------------------------------------
    // Handles

    pub fn encodeHandle(v: *const Vfs, slot: u32) u32 {
        return (@as(u32, v.epoch & 0x3FFF) << 16) | (slot + 1);
    }

    pub fn decodeHandle(v: *const Vfs, value: u32) Error!u32 {
        const slot_plus = value & 0xFFFF;
        if (slot_plus == 0 or slot_plus > v.handles.len) return error.InvalidHandle;
        const slot = slot_plus - 1;
        const h = &v.handles[slot];
        if (!h.used) return error.InvalidHandle;
        if (h.epoch != @as(u16, @intCast(value >> 16))) return error.InvalidHandle;
        return slot;
    }

    pub fn openHandle(v: *Vfs, ino: InodeId, readable: bool, writable: bool) Error!u32 {
        for (v.handles, 0..) |*h, idx| {
            if (h.used) continue;
            h.* = .{
                .used = true,
                .inode = ino,
                .epoch = v.epoch & 0x3FFF,
                .pos = 0,
                .readable = readable,
                .writable = writable,
            };
            v.inodes[ino].open_count += 1;
            return v.encodeHandle(@intCast(idx));
        }
        return error.ProcessFdQuotaExceeded;
    }

    pub fn handle(v: *Vfs, value: u32) Error!*Handle {
        const slot = try v.decodeHandle(value);
        return &v.handles[slot];
    }

    pub fn closeHandle(v: *Vfs, value: u32) void {
        const slot = v.decodeHandle(value) catch return;
        const h = &v.handles[slot];
        const ino = h.inode;
        h.used = false;
        v.inodes[ino].open_count -= 1;
        v.maybeFree(ino);
    }

    // ------------------------------------------------------------------
    // Directory listing and locks

    pub const Child = struct { name: []const u8, inode: InodeId, kind: Kind };

    /// The entry in dentry slot `slot` if it is a child of `dir`.
    pub fn childAt(v: *const Vfs, dir: InodeId, slot: usize) ?Child {
        const d = &v.cur_dentries[slot];
        if (!d.used or d.parent != dir) return null;
        return .{ .name = d.nameSlice(), .inode = d.inode, .kind = v.inodes[d.inode].kind };
    }

    pub fn dentrySlots(v: *const Vfs) usize {
        return v.cur_dentries.len;
    }

    /// True if a handle other than `value` holds a lock on the same inode
    /// that is incompatible with `want`.
    pub fn lockConflicts(v: *const Vfs, value: u32, want: LockKind) bool {
        const self = v.decodeHandle(value) catch return false;
        const ino = v.handles[self].inode;
        for (v.handles, 0..) |*h, i| {
            if (!h.used or i == self or h.inode != ino) continue;
            if (h.lock == .exclusive) return true;
            if (h.lock == .shared and want == .exclusive) return true;
        }
        return false;
    }

    /// True if a handle other than `value` holds an exclusive lock on its
    /// inode (Windows mandatory locking blocks I/O through other handles).
    pub fn lockedByOther(v: *const Vfs, value: u32) bool {
        const self = v.decodeHandle(value) catch return false;
        const ino = v.handles[self].inode;
        for (v.handles, 0..) |*h, i| {
            if (h.used and i != self and h.inode == ino and h.lock == .exclusive) return true;
        }
        return false;
    }
    pub fn openHandleCount(v: *const Vfs) u32 {
        var n: u32 = 0;
        for (v.handles) |h| {
            if (h.used) n += 1;
        }
        return n;
    }

    // ------------------------------------------------------------------
    // Crash

    pub fn crash(v: *Vfs, mode: CrashMode, d: *decide.Decider, torn_writes: bool, metadata_loss: bool) CrashReport {
        var report: CrashReport = .{ .journal_ops_pending = v.journal_len };

        // Close every handle: open counts drop to zero.
        for (v.handles) |*h| {
            if (!h.used) continue;
            h.used = false;
            v.inodes[h.inode].open_count -= 1;
        }

        switch (mode) {
            .process_crash => {
                report.journal_ops_kept = v.journal_len;
                v.commitJournal(v.journal_len);
                for (v.inodes, 0..) |*i, idx| {
                    if (i.kind == .file) v.syncData(@intCast(idx));
                }
            },
            .power_loss => {
                // 1. Metadata.
                if (!metadata_loss) {
                    report.journal_ops_kept = v.journal_len;
                    v.commitJournal(v.journal_len);
                } else if (v.persona.journalPrefixOnCrash()) {
                    // Decisions are phrased so that 0 means "survives" (M3 shrinking).
                    const keep: u32 = v.journal_len - @as(u32, @intCast(d.uniform(.crash, @as(u64, v.journal_len) + 1)));
                    report.journal_ops_kept = keep;
                    v.commitJournal(keep);
                } else {
                    var k: u32 = 0;
                    while (k < v.journal_len) : (k += 1) {
                        if (!d.boolean(.crash)) {
                            v.applyOp(&v.journal[k]);
                            report.journal_ops_kept += 1;
                        }
                    }
                }
                var k: u32 = 0;
                while (k < v.journal_len) : (k += 1) v.dropOp(&v.journal[k]);
                v.journal_len = 0;

                // 2. Data.
                for (v.inodes, 0..) |*i, idx| {
                    if (i.kind != .file) continue;
                    const ino: InodeId = @intCast(idx);
                    if (!v.isDirty(ino)) continue;
                    report.inodes_dirty += 1;
                    if (v.tearInode(ino, d, torn_writes and !v.persona.atomicWrites())) report.inodes_torn += 1;
                }
            },
        }

        // 3. Rebuild the volatile namespace from the durable one and collect orphans.
        report.inodes_orphaned = v.rebuildFromDurable();
        v.epoch +%= 1;
        return report;
    }

    /// Decides what survives of an unsynced file. Returns true if the result
    /// mixes old and new contents.
    fn tearInode(v: *Vfs, ino: InodeId, d: *decide.Decider, torn_writes: bool) bool {
        const i = &v.inodes[ino];
        if (!torn_writes) {
            if (!d.boolean(.crash)) v.syncData(ino);
            v.resetCurToDur(ino);
            return false;
        }
        const new_len = if (!d.boolean(.crash)) i.cur_len_bytes else i.dur_len_bytes;
        const old_len = i.dur_len_bytes;
        const cur = v.curSlots(ino);
        const dur = v.durSlots(ino);
        const n = @max(pagesFor(i.cur_len_bytes), pagesFor(i.dur_len_bytes));
        const keep_pages = pagesFor(new_len);
        var mixed = false;
        var p: usize = 0;
        while (p < n) : (p += 1) {
            const c = cur[p];
            const o = dur[p];
            var result: u32 = o;
            var fresh_page = false;
            if (p >= keep_pages) {
                result = 0;
            } else {
                const buf = &v.scratch_page;
                var any_new = false;
                var any_old = false;
                var s: usize = 0;
                while (s < sectors_per_page) : (s += 1) {
                    const off = s * sector_bytes;
                    const abs: u64 = @as(u64, p) * page_bytes + off;
                    const take_new = c == o or !d.boolean(.crash);
                    if (take_new) {
                        @memcpy(buf[off..][0..sector_bytes], v.pageData(c)[off..][0..sector_bytes]);
                        any_new = true;
                    } else if (abs < old_len) {
                        @memcpy(buf[off..][0..sector_bytes], v.pageData(o)[off..][0..sector_bytes]);
                        any_old = true;
                    } else {
                        @memset(buf[off..][0..sector_bytes], 0);
                        any_old = true;
                    }
                }
                if (any_new and any_old and c != o) mixed = true;
                // Zero everything at or beyond the surviving length.
                const page_start: u64 = @as(u64, p) * page_bytes;
                if (new_len < page_start + page_bytes) {
                    const tail: usize = @intCast(new_len - page_start);
                    @memset(buf[tail..], 0);
                }
                if (std.mem.eql(u8, buf, v.pageData(c))) {
                    result = c;
                } else if (std.mem.eql(u8, buf, v.pageData(o))) {
                    result = o;
                } else if (std.mem.allEqual(u8, buf, 0)) {
                    result = 0;
                } else if (v.pageAlloc()) |fresh| {
                    @memcpy(v.pageData(fresh), buf);
                    result = fresh;
                    fresh_page = true;
                } else |_| {
                    result = o; // pool exhausted: the new data is lost
                }
            }
            // Install `result` into both views. Take the new references before
            // dropping the old ones, since `result` may equal `c` or `o`.
            // A fresh page already carries one reference from `pageAlloc`.
            if (!fresh_page) v.pageRef(result);
            v.pageRef(result);
            v.pageUnref(c);
            v.pageUnref(o);
            cur[p] = result;
            dur[p] = result;
        }
        i.cur_len_bytes = new_len;
        i.dur_len_bytes = new_len;
        return mixed;
    }

    fn resetCurToDur(v: *Vfs, ino: InodeId) void {
        const i = &v.inodes[ino];
        const cur = v.curSlots(ino);
        const dur = v.durSlots(ino);
        const n = @max(pagesFor(i.cur_len_bytes), pagesFor(i.dur_len_bytes));
        for (cur[0..n], dur[0..n]) |*c, dp| {
            if (c.* == dp) continue;
            v.pageRef(dp);
            v.pageUnref(c.*);
            c.* = dp;
        }
        i.cur_len_bytes = i.dur_len_bytes;
    }

    /// cur namespace := dur namespace; frees inodes unreachable from root.
    fn rebuildFromDurable(v: *Vfs) u32 {
        // Reachability over durable dentries (iterative fixed point).
        const reach = v.gpa.alloc(bool, v.inodes.len) catch @panic("tardis: out of memory during crash");
        defer v.gpa.free(reach);
        @memset(reach, false);
        reach[root_inode] = true;
        var changed = true;
        while (changed) {
            changed = false;
            for (v.dur_dentries[0..v.dur_hwm]) |*dd| {
                if (!dd.used or !reach[dd.parent] or reach[dd.inode]) continue;
                reach[dd.inode] = true;
                changed = true;
            }
        }
        for (v.dur_dentries[0..v.dur_hwm], 0..) |*dd, idx| {
            if (dd.used and !reach[dd.parent]) v.durRemove(idx);
        }

        // Rebuild cur dentries.
        for (v.cur_dentries[0..v.cur_hwm]) |*cd| cd.used = false;
        for (v.inodes) |*i| i.cur_links = 0;
        var out: usize = 0;
        for (v.dur_dentries[0..v.dur_hwm]) |*dd| {
            if (!dd.used) continue;
            v.cur_dentries[out] = dd.*;
            out += 1;
            const i = &v.inodes[dd.inode];
            i.cur_links += 1;
            if (i.kind == .dir) i.parent = dd.parent;
        }
        v.cur_hwm = out;
        v.inodes[root_inode].cur_links = 1;
        // Short names are not journaled: they are given again, in entry
        // order (NTFS keeps them on disk, so an ordinal can differ after a
        // crash here where it would not on a real volume).
        for (v.cur_dentries[0..out], 0..) |*cd, idx| {
            cd.short = 0;
            cd.short = v.shortOrdinal(cd.parent, cd.nameSlice(), idx);
        }

        var orphans: u32 = 0;
        for (v.inodes, 0..) |*i, idx| {
            if (idx == root_inode or i.kind == .free) continue;
            if (!reach[idx]) {
                assert(i.dur_links == 0);
                i.cur_links = 0;
                i.journal_refs = 0;
                i.open_count = 0;
                v.inodeRelease(@intCast(idx));
                orphans += 1;
                continue;
            }
            // Live inode: cur view equals dur view after a crash.
            if (i.kind == .file) v.resetCurToDur(@intCast(idx));
        }
        return orphans;
    }
};

// ----------------------------------------------------------------------
// Tests

// ----------------------------------------------------------------------
// Name rules of the personas (shared with `tardis_sec`'s path confusions)

/// Win32's view of a name component: trailing dots and spaces dropped,
/// then a `::$DATA` suffix (the default data stream), so `secret.key.`,
/// `secret.key ` and `secret.key::$DATA` all name `secret.key`.
pub fn win32Name(name: []const u8) []const u8 {
    var n = std.mem.trimEnd(u8, name, ". ");
    const stream = "::$DATA";
    if (n.len > stream.len and std.ascii.endsWithIgnoreCase(n, stream)) n = n[0 .. n.len - stream.len];
    return n;
}

/// `~1`..`~4`: past that Windows derives a hashed short name.
pub const short_ordinal_max = 4;

fn shortChar(c: u8) ?u8 {
    return switch (c) {
        'a'...'z' => std.ascii.toUpper(c),
        'A'...'Z', '0'...'9', '!', '#', '$', '%', '&', '\'', '(', ')', '-', '@', '^', '_', '`', '{', '}', '~' => c,
        ' ', '.' => null,
        else => '_', // `+,;=[]` and non-ASCII bytes
    };
}

fn isShortValid(name: []const u8) bool {
    const dot = std.mem.lastIndexOfScalar(u8, name, '.');
    const base = if (dot) |d| name[0..d] else name;
    const ext = if (dot) |d| name[d + 1 ..] else "";
    if (base.len == 0 or base.len > 8 or ext.len > 3) return false;
    if (std.mem.indexOfScalar(u8, base, '.') != null) return false;
    for (name) |c| {
        if (c == '.') continue;
        const m = shortChar(c) orelse return false;
        if (m == '_' and c != '_') return false;
    }
    return true;
}

/// The 8.3 short name `ordinal` gives a long name (`PRIVAT~1.PEM` for
/// `private_key.pem`), in `out`; null for a name that is already 8.3 (it
/// needs none) or has no usable character before its extension. Windows'
/// generation: spaces and dots dropped, other characters not allowed in
/// 8.3 made `_`, upper case, the first six of the base and the first three
/// of the last extension.
pub fn shortName(name: []const u8, ordinal: u8, out: *[12]u8) ?[]const u8 {
    std.debug.assert(ordinal >= 1 and ordinal <= 9);
    if (isShortValid(name)) return null;
    const dot = std.mem.lastIndexOfScalar(u8, name, '.');
    const base = if (dot) |d| (if (d == 0) name else name[0..d]) else name;
    const ext = if (dot) |d| (if (d == 0) "" else name[d + 1 ..]) else "";
    var n: usize = 0;
    for (base) |c| {
        if (n == 6) break;
        out[n] = shortChar(c) orelse continue;
        n += 1;
    }
    if (n == 0) return null;
    out[n] = '~';
    out[n + 1] = '0' + ordinal;
    n += 2;
    var e: usize = 0;
    for (ext) |c| {
        if (e == 3) break;
        const m = shortChar(c) orelse continue;
        if (e == 0) {
            out[n] = '.';
            n += 1;
        }
        out[n] = m;
        n += 1;
        e += 1;
    }
    return out[0..n];
}

/// Canonical decompositions of the Latin-1 letters U+00E0..U+00FF (lower
/// case): base letter and combining mark, or 0 for none.
const latin1_nfd = blk: {
    const D = struct { base: u8, mark: u21 };
    var t: [32]D = @splat(.{ .base = 0, .mark = 0 });
    const rows = .{
        .{ 0xE0, 'a', 0x300 }, .{ 0xE1, 'a', 0x301 }, .{ 0xE2, 'a', 0x302 }, .{ 0xE3, 'a', 0x303 },
        .{ 0xE4, 'a', 0x308 }, .{ 0xE5, 'a', 0x30A }, .{ 0xE7, 'c', 0x327 }, .{ 0xE8, 'e', 0x300 },
        .{ 0xE9, 'e', 0x301 }, .{ 0xEA, 'e', 0x302 }, .{ 0xEB, 'e', 0x308 }, .{ 0xEC, 'i', 0x300 },
        .{ 0xED, 'i', 0x301 }, .{ 0xEE, 'i', 0x302 }, .{ 0xEF, 'i', 0x308 }, .{ 0xF1, 'n', 0x303 },
        .{ 0xF2, 'o', 0x300 }, .{ 0xF3, 'o', 0x301 }, .{ 0xF4, 'o', 0x302 }, .{ 0xF5, 'o', 0x303 },
        .{ 0xF6, 'o', 0x308 }, .{ 0xF9, 'u', 0x300 }, .{ 0xFA, 'u', 0x301 }, .{ 0xFB, 'u', 0x302 },
        .{ 0xFC, 'u', 0x308 }, .{ 0xFD, 'y', 0x301 }, .{ 0xFF, 'y', 0x308 },
    };
    for (rows) |r| t[r[0] - 0xE0] = .{ .base = r[1], .mark = r[2] };
    break :blk t;
};

fn foldLatin1(c: u21) u21 {
    return switch (c) {
        'A'...'Z' => c + 0x20,
        0xC0...0xD6, 0xD8...0xDE => c + 0x20,
        else => c,
    };
}

/// The code points of a name as a case-insensitive persona compares them:
/// case folded (ASCII and Latin-1), and with `decompose` the Latin-1
/// letters decomposed (NFD), so composed and decomposed spellings yield the
/// same sequence. A byte that is not valid UTF-8 yields itself above
/// U+10FFFF, so it equals only the same byte.
pub const NameIterator = struct {
    s: []const u8,
    decompose: bool,
    i: usize = 0,
    pending: u21 = 0,

    pub fn next(it: *NameIterator) ?u21 {
        if (it.pending != 0) {
            defer it.pending = 0;
            return it.pending;
        }
        if (it.i >= it.s.len) return null;
        const invalid = 0x110000 + @as(u21, it.s[it.i]);
        const len = std.unicode.utf8ByteSequenceLength(it.s[it.i]) catch 0;
        const cp: u21 = if (len > 0 and it.i + len <= it.s.len)
            std.unicode.utf8Decode(it.s[it.i..][0..len]) catch invalid
        else
            invalid;
        it.i += if (cp >= 0x110000) 1 else len;
        const folded = foldLatin1(cp);
        if (it.decompose and folded >= 0xE0 and folded <= 0xFF) {
            const d = latin1_nfd[folded - 0xE0];
            if (d.base != 0) {
                it.pending = d.mark;
                return d.base;
            }
        }
        return folded;
    }
};

/// `name` with its composed Latin-1 letters decomposed (NFD for them), in
/// `out`; null when it has none or `out` is too small.
pub fn decomposeLatin1(name: []const u8, out: []u8) ?[]const u8 {
    var n: usize = 0;
    var changed = false;
    var i: usize = 0;
    while (i < name.len) {
        const len = std.unicode.utf8ByteSequenceLength(name[i]) catch 0;
        const cp: ?u21 = if (len > 0 and i + len <= name.len) std.unicode.utf8Decode(name[i..][0..len]) catch null else null;
        const piece_len = if (cp != null) len else 1;
        defer i += piece_len;
        if (cp) |x| if (x >= 0xC0 and x <= 0xFF) {
            const lower = foldLatin1(x);
            if (lower >= 0xE0 and latin1_nfd[lower - 0xE0].base != 0) {
                const d = latin1_nfd[lower - 0xE0];
                if (n + 3 > out.len) return null;
                out[n] = if (lower != x) std.ascii.toUpper(d.base) else d.base;
                n += 1 + (std.unicode.utf8Encode(d.mark, out[n + 1 ..]) catch unreachable);
                changed = true;
                continue;
            }
        };
        if (n + piece_len > out.len) return null;
        @memcpy(out[n..][0..piece_len], name[i..][0..piece_len]);
        n += piece_len;
    }
    return if (changed) out[0..n] else null;
}

fn composed(base: u8, mark_bytes: []const u8) ?u21 {
    // `utf8Decode` asserts the lead byte matches the length.
    if ((std.unicode.utf8ByteSequenceLength(mark_bytes[0]) catch 0) != 2) return null;
    const mark = std.unicode.utf8Decode(mark_bytes) catch return null;
    const lower = std.ascii.toLower(base);
    for (latin1_nfd, 0..) |d, k| {
        if (d.base != lower or d.mark != mark) continue;
        const cp: u21 = 0xE0 + @as(u21, @intCast(k));
        if (base == lower) return cp;
        return if (cp == 0xFF) null else cp - 0x20; // `Ÿ` is not Latin-1
    }
    return null;
}

/// `name` with each Latin-1 letter written as base and combining mark
/// composed (NFC for them), in `out`; null when it has none or `out` is
/// too small.
pub fn composeLatin1(name: []const u8, out: []u8) ?[]const u8 {
    var n: usize = 0;
    var changed = false;
    var i: usize = 0;
    while (i < name.len) {
        const c = name[i];
        if (i + 3 <= name.len and std.ascii.isAlphabetic(c)) {
            if (composed(c, name[i + 1 ..][0..2])) |cp| {
                if (n + 2 > out.len) return null;
                n += std.unicode.utf8Encode(cp, out[n..]) catch unreachable;
                i += 3;
                changed = true;
                continue;
            }
        }
        if (n + 1 > out.len) return null;
        out[n] = c;
        n += 1;
        i += 1;
    }
    return if (changed) out[0..n] else null;
}

/// Whether two names are the same file on a case-insensitive persona.
pub fn namesEqual(a: []const u8, b: []const u8, decompose: bool) bool {
    if (std.ascii.eqlIgnoreCase(a, b)) return true;
    var ia: NameIterator = .{ .s = a, .decompose = decompose };
    var ib: NameIterator = .{ .s = b, .decompose = decompose };
    while (true) {
        const x = ia.next();
        const y = ib.next();
        if (x == null or y == null) return x == null and y == null;
        if (x.? != y.?) return false;
    }
}

const testing = std.testing;

fn testVfs(persona: Persona) !Vfs {
    return Vfs.init(testing.allocator, .{ .pages_max = 64, .file_pages_max = 8, .inodes_max = 16, .dentries_max = 32, .journal_max = 8, .handles_max = 8 }, persona);
}

fn readAll(v: *Vfs, ino: InodeId, buf: []u8) []u8 {
    return buf[0..v.read(ino, 0, buf)];
}

test "create, write, read, sync, crash keeps synced data" {
    var v = try testVfs(.linux_ext4);
    defer v.deinit();
    var d = decide.Decider.init(1);
    const f = try v.createFile(root_inode, "a.txt", .{});
    _ = try v.write(f, 0, "hello");
    v.sync(f);
    _ = v.crash(.power_loss, &d, true, true);
    const f2 = try v.lookup(root_inode, "a.txt");
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("hello", readAll(&v, f2, &buf));
    try v.checkPageConservation();
}

test "process crash keeps unsynced data, power loss may not" {
    var lost_any = false;
    var seed: u64 = 0;
    while (seed < 32) : (seed += 1) {
        var v = try testVfs(.linux_ext4);
        defer v.deinit();
        var d = decide.Decider.init(seed);
        const f = try v.createFile(root_inode, "a", .{});
        const xs: [1000]u8 = @splat('x');
        _ = try v.write(f, 0, &xs);
        v.sync(f);
        const ys: [1000]u8 = @splat('y');
        _ = try v.write(f, 0, &ys);
        _ = v.crash(.power_loss, &d, true, true);
        const f2 = try v.lookup(root_inode, "a");
        var buf: [1000]u8 = undefined;
        const got = readAll(&v, f2, &buf);
        try testing.expectEqual(@as(usize, 1000), got.len);
        // Every sector is entirely old or entirely new.
        var s: usize = 0;
        while (s < 1000) : (s += sector_bytes) {
            const end = @min(s + sector_bytes, 1000);
            const first = got[s];
            try testing.expect(first == 'x' or first == 'y');
            for (got[s..end]) |c| try testing.expectEqual(first, c);
            if (first == 'x') lost_any = true;
        }
        try v.checkPageConservation();
    }
    try testing.expect(lost_any);

    var v = try testVfs(.linux_ext4);
    defer v.deinit();
    var d = decide.Decider.init(9);
    const f = try v.createFile(root_inode, "a", .{});
    _ = try v.write(f, 0, "volatile");
    _ = v.crash(.process_crash, &d, true, true);
    const f2 = try v.lookup(root_inode, "a");
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("volatile", readAll(&v, f2, &buf));
}

test "unsynced create can vanish on power loss" {
    var vanished = false;
    var survived = false;
    var seed: u64 = 0;
    while (seed < 16) : (seed += 1) {
        var v = try testVfs(.linux_xfs);
        defer v.deinit();
        var d = decide.Decider.init(seed);
        _ = try v.createFile(root_inode, "new", .{});
        _ = v.crash(.power_loss, &d, true, true);
        if (v.lookup(root_inode, "new")) |_| survived = true else |_| vanished = true;
        try v.checkPageConservation();
    }
    try testing.expect(vanished and survived);
}

test "xfs rename over without fsync may lose data; ext4 auto_da_alloc keeps it" {
    var xfs_lost = false;
    var seed: u64 = 0;
    while (seed < 32) : (seed += 1) {
        inline for (.{ Persona.linux_xfs, Persona.linux_ext4 }) |persona| {
            var v = try testVfs(persona);
            defer v.deinit();
            var d = decide.Decider.init(seed);
            const old = try v.createFile(root_inode, "config", .{});
            _ = try v.write(old, 0, "old-config");
            v.sync(old);
            const tmp = try v.createFile(root_inode, "tmp", .{});
            _ = try v.write(tmp, 0, "new-config");
            try v.rename(root_inode, "tmp", root_inode, "config");
            v.sync(root_inode); // commits the rename (journaled persona)
            _ = v.crash(.power_loss, &d, true, true);
            const f = try v.lookup(root_inode, "config");
            var buf: [32]u8 = undefined;
            const got = readAll(&v, f, &buf);
            if (persona == .linux_ext4) {
                try testing.expectEqualStrings("new-config", got);
            } else if (!std.mem.eql(u8, got, "new-config")) {
                xfs_lost = true;
            }
            try v.checkPageConservation();
        }
    }
    try testing.expect(xfs_lost);
}

test "posix_strict: file fsync does not persist the directory entry" {
    var lost = false;
    var seed: u64 = 0;
    while (seed < 16) : (seed += 1) {
        var v = try testVfs(.posix_strict);
        defer v.deinit();
        var d = decide.Decider.init(seed);
        const f = try v.createFile(root_inode, "f", .{});
        _ = try v.write(f, 0, "data");
        v.sync(f);
        _ = v.crash(.power_loss, &d, true, true);
        if (v.lookup(root_inode, "f")) |_| {} else |_| lost = true;
    }
    try testing.expect(lost);

    // With a directory fsync the entry always survives.
    seed = 0;
    while (seed < 16) : (seed += 1) {
        var v = try testVfs(.posix_strict);
        defer v.deinit();
        var d = decide.Decider.init(seed);
        const f = try v.createFile(root_inode, "f", .{});
        _ = try v.write(f, 0, "data");
        v.sync(f);
        v.sync(root_inode);
        _ = v.crash(.power_loss, &d, true, true);
        _ = try v.lookup(root_inode, "f");
    }
}

test "ntfs: sharing violation, case-insensitive, reserved names" {
    var v = try testVfs(.windows_ntfs);
    defer v.deinit();
    const f = try v.createFile(root_inode, "Data.Log", .{});
    const h = try v.openHandle(f, true, true);
    try testing.expectError(error.FileBusy, v.deleteFile(root_inode, "data.log"));
    try testing.expectError(error.FileBusy, v.rename(root_inode, "DATA.LOG", root_inode, "x"));
    v.closeHandle(h);
    try v.deleteFile(root_inode, "DATA.log");
    try testing.expectError(error.BadPathName, v.createFile(root_inode, "nul.txt", .{}));
    try testing.expectError(error.BadPathName, v.createFile(root_inode, "a:b", .{}));
    _ = try v.makeDir(root_inode, "dir");
    _ = try v.createFile(root_inode, "dir\\inner", .{});
    _ = try v.lookup(root_inode, "DIR/INNER");
}

test "ntfs: trailing dots and spaces, the default stream and 8.3 short names name the same file" {
    var v = try testVfs(.windows_ntfs);
    defer v.deinit();
    const f = try v.createFile(root_inode, "secret.key", .{});
    for ([_][]const u8{ "secret.key.", "secret.key ", "secret.key. .", "SECRET.KEY::$DATA", "secret.key::$data" }) |p| {
        try testing.expectEqual(f, try v.lookup(root_inode, p));
    }
    // Creating a confusable name opens the same file.
    try testing.expectEqual(f, try v.createFile(root_inode, "secret.key.", .{}));
    try testing.expectError(error.BadPathName, v.createFile(root_inode, "secret.key:other", .{}));
    try testing.expectError(error.BadPathName, v.lookup(root_inode, " . "));

    // 8.3: ~1 and ~2 in creation order, per short base and extension; an
    // 8.3 name (`secret.key`) has none.
    const a = try v.createFile(root_inode, "private_key.pem", .{});
    const b = try v.createFile(root_inode, "private key 2.pem", .{});
    const c = try v.createFile(root_inode, "private_key.pem.bak", .{});
    try testing.expectEqual(a, try v.lookup(root_inode, "PRIVAT~1.PEM"));
    try testing.expectEqual(b, try v.lookup(root_inode, "privat~2.pem"));
    try testing.expectEqual(c, try v.lookup(root_inode, "PRIVAT~1.BAK"));
    try testing.expectError(error.FileNotFound, v.lookup(root_inode, "SECRET~1.KEY"));
    _ = try v.makeDir(root_inode, "Program Files");
    _ = try v.createFile(root_inode, "PROGRA~1/app.exe", .{});
    _ = try v.lookup(root_inode, "Program Files/APP.EXE");
    // A rename takes a fresh short name; the freed ordinal is reused.
    try v.rename(root_inode, "PRIVAT~1.PEM", root_inode, "public_key.pem");
    try testing.expectEqual(a, try v.lookup(root_inode, "PUBLIC~1.PEM"));
    try testing.expectError(error.FileNotFound, v.lookup(root_inode, "PRIVAT~1.PEM"));
    const d = try v.createFile(root_inode, "private-key.pem", .{});
    try testing.expectEqual(d, try v.lookup(root_inode, "PRIVAT~1.PEM"));
    // ext4 takes every one of these names literally.
    var e = try testVfs(.linux_ext4);
    defer e.deinit();
    _ = try e.createFile(root_inode, "secret.key", .{});
    try testing.expectError(error.FileNotFound, e.lookup(root_inode, "secret.key."));
}

test "names: short names, Latin-1 case folding and decomposition" {
    var buf: [12]u8 = undefined;
    try testing.expectEqualStrings("PRIVAT~1.PEM", shortName("private_key.pem", 1, &buf).?);
    try testing.expectEqualStrings("A_BC~3", shortName("a+b c", 3, &buf).?);
    try testing.expectEqualStrings("LONGFI~1.TXT", shortName("longfilename.txt", 1, &buf).?);
    try testing.expectEqualStrings("BASHRC~1", shortName(".bashrc", 1, &buf).?);
    try testing.expectEqual(@as(?[]const u8, null), shortName("README.md", 1, &buf));
    try testing.expectEqual(@as(?[]const u8, null), shortName("secret.key", 1, &buf));
    try testing.expectEqualStrings("secret.key", win32Name("secret.key. "));
    try testing.expectEqualStrings("a", win32Name("a::$Data"));
    try testing.expectEqualStrings("::$DATA", win32Name("::$DATA"));
    // Case: ASCII and Latin-1; normalization only with `decompose`.
    try testing.expect(namesEqual("CAF\u{C9}", "caf\u{E9}", false));
    try testing.expect(!namesEqual("cafe\u{301}", "caf\u{E9}", false));
    try testing.expect(namesEqual("CAFE\u{301}", "caf\u{E9}", true));
    try testing.expect(namesEqual("\u{C5}ngstr\u{F6}m", "a\u{30A}ngstro\u{308}m", true));
    try testing.expect(!namesEqual("caf\u{E9}", "cafe", true));
    try testing.expect(!namesEqual("\xFF", "\u{FF}", true));
}

test "names: Latin-1 decomposition and composition round-trip" {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    const nfd = decomposeLatin1("R\u{E9}sum\u{C9}.txt", &a).?;
    try testing.expectEqualStrings("Re\u{301}sumE\u{301}.txt", nfd);
    try testing.expectEqualStrings("R\u{E9}sum\u{C9}.txt", composeLatin1(nfd, &b).?);
    try testing.expectEqual(@as(?[]const u8, null), decomposeLatin1("plain.txt", &a));
    try testing.expectEqual(@as(?[]const u8, null), decomposeLatin1("\xE9", &a));
    try testing.expectEqual(@as(?[]const u8, null), composeLatin1("plain.txt", &a));
    try testing.expectEqualStrings("\u{FF}", composeLatin1("y\u{308}", &a).?);
    try testing.expectEqual(@as(?[]const u8, null), composeLatin1("Y\u{308}", &a));
}

test "apfs: composed and decomposed spellings name the same file" {
    var v = try testVfs(.macos_apfs);
    defer v.deinit();
    const f = try v.createFile(root_inode, "r\u{E9}sum\u{E9}.txt", .{});
    try testing.expectEqual(f, try v.lookup(root_inode, "re\u{301}sume\u{301}.txt"));
    try testing.expectEqual(f, try v.lookup(root_inode, "R\u{C9}SUM\u{C9}.TXT"));
    try testing.expectError(error.FileNotFound, v.lookup(root_inode, "resume.txt"));
    // NTFS folds the case but keeps the spellings apart.
    var n = try testVfs(.windows_ntfs);
    defer n.deinit();
    const g = try n.createFile(root_inode, "r\u{E9}sum\u{E9}.txt", .{});
    try testing.expectEqual(g, try n.lookup(root_inode, "R\u{C9}SUM\u{C9}.TXT"));
    try testing.expectError(error.FileNotFound, n.lookup(root_inode, "re\u{301}sume\u{301}.txt"));
}

test "posix: unlinked open file stays readable, freed on close" {
    var v = try testVfs(.linux_ext4);
    defer v.deinit();
    const f = try v.createFile(root_inode, "a", .{});
    _ = try v.write(f, 0, "abc");
    const h = try v.openHandle(f, true, false);
    try v.deleteFile(root_inode, "a");
    v.sync(root_inode);
    var buf: [8]u8 = undefined;
    try testing.expectEqualStrings("abc", readAll(&v, f, &buf));
    v.closeHandle(h);
    try testing.expectEqual(Kind.free, v.inodes[f].kind);
    try testing.expectEqual(@as(u32, 0), v.livePageCount());
}

test "paths, dirs, errors" {
    var v = try testVfs(.linux_ext4);
    defer v.deinit();
    const r = try v.makePath(root_inode, "a/b/c");
    try testing.expectEqual(Vfs.MakePathStatus.created, r.status);
    _ = try v.createFile(root_inode, "a/b/c/f", .{});
    try testing.expectError(error.DirNotEmpty, v.deleteDir(root_inode, "a/b/c"));
    try testing.expectError(error.NotDir, v.createFile(root_inode, "a/b/c/f/g", .{}));
    try testing.expectError(error.PathAlreadyExists, v.createFile(root_inode, "a/b/c/f", .{ .exclusive = true }));
    try testing.expectError(error.IsDir, v.createFile(root_inode, "a", .{}));
    const c = try v.lookup(root_inode, "a/b/c");
    try testing.expectEqual(c, try v.lookup(c, "../c/./"));
    try testing.expectError(error.BadPathName, v.rename(root_inode, "a", root_inode, "a/b/x"));
    try v.rename(root_inode, "a/b/c/f", root_inode, "top");
    try v.deleteDir(root_inode, "a/b/c");
    try testing.expectError(error.FileNotFound, v.lookup(root_inode, "a/b/c"));
}

test "setLength shrink then grow reads zeros" {
    var v = try testVfs(.linux_ext4);
    defer v.deinit();
    const f = try v.createFile(root_inode, "a", .{});
    _ = try v.write(f, 0, "abcdefgh");
    try v.setLength(f, 3);
    try v.setLength(f, 6);
    var buf: [8]u8 = undefined;
    try testing.expectEqualSlices(u8, "abc\x00\x00\x00", readAll(&v, f, &buf));
    try v.checkPageConservation();
}

test "disk full and file too big" {
    var v = try testVfs(.linux_ext4);
    defer v.deinit();
    const f = try v.createFile(root_inode, "big", .{});
    const chunk: [page_bytes]u8 = @splat(1);
    var i: u32 = 0;
    while (i < 8) : (i += 1) _ = try v.write(f, @as(u64, i) * page_bytes, &chunk);
    try testing.expectError(error.FileTooBig, v.write(f, 8 * page_bytes, "x"));
    // Fill the pool through other files until NoSpaceLeft.
    var name_buf: [8]u8 = undefined;
    var got_full = false;
    var k: u32 = 0;
    while (k < 12 and !got_full) : (k += 1) {
        const name = try std.fmt.bufPrint(&name_buf, "f{d}", .{k});
        const g = try v.createFile(root_inode, name, .{});
        var j: u32 = 0;
        while (j < 8) : (j += 1) {
            _ = v.write(g, @as(u64, j) * page_bytes, &chunk) catch |err| {
                try testing.expectEqual(error.NoSpaceLeft, err);
                got_full = true;
                break;
            };
        }
    }
    try testing.expect(got_full);
    try v.checkPageConservation();
}
