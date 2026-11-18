//! The parts of a git repository the evidence manifest reads (plan2.md
//! §7.5), without running `git`: the index, and the object store (loose
//! objects and packs, with their deltas).
//!
//! Two questions are answered against the checked-out commit:
//!
//! - `indexModified`: tracked files whose working copy differs from the
//!   index (what `git diff --quiet` checks);
//! - `stagedFiles`: paths whose index entry differs from the HEAD commit's
//!   tree (what `git diff --cached --quiet` checks): staged edits,
//!   additions, deletions, mode changes and unresolved merges.
//!
//! Only SHA-1 repositories with index versions 2 and 3 are read. Anything
//! this reader does not handle (SHA-256, index version 4, a sparse index,
//! an object it cannot find, such as one in an alternate store) gives null:
//! "unknown", never "clean".

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const Oid = [20]u8;

// ---------------------------------------------------------------------------
// The index

pub const IndexEntry = struct {
    path: []const u8,
    mode: u32,
    oid: *const Oid,
    size: u32,
    mtime_s: u32,
    mtime_ns: u32,
    /// 0 when merged; 1–3 for the sides of an unresolved conflict.
    stage: u2,
    skip_worktree: bool,
    intent_to_add: bool,
};

pub const IndexIterator = struct {
    bytes: []const u8,
    version: u32,
    left: u32,
    off: usize = 12,

    /// Null for a file that is not an index of version 2 or 3.
    pub fn init(bytes: []const u8) ?IndexIterator {
        if (bytes.len < 12 or !std.mem.eql(u8, bytes[0..4], "DIRC")) return null;
        const version = std.mem.readInt(u32, bytes[4..8], .big);
        if (version != 2 and version != 3) return null;
        return .{ .bytes = bytes, .version = version, .left = std.mem.readInt(u32, bytes[8..12], .big) };
    }

    pub fn next(it: *IndexIterator) error{MalformedIndex}!?IndexEntry {
        if (it.left == 0) return null;
        it.left -= 1;
        if (it.off + 62 > it.bytes.len) return error.MalformedIndex;
        const e = it.bytes[it.off..];
        const flags = std.mem.readInt(u16, e[60..62], .big);
        var head: usize = 62;
        var extended: u16 = 0;
        if (flags & 0x4000 != 0) {
            if (it.version < 3 or it.off + 64 > it.bytes.len) return error.MalformedIndex;
            extended = std.mem.readInt(u16, e[62..64], .big);
            head = 64;
        }
        const path_len = std.mem.indexOfScalar(u8, e[head..], 0) orelse return error.MalformedIndex;
        it.off += (head + path_len + 8) & ~@as(usize, 7);
        return .{
            .path = e[head..][0..path_len],
            .mtime_s = std.mem.readInt(u32, e[8..12], .big),
            .mtime_ns = std.mem.readInt(u32, e[12..16], .big),
            .mode = std.mem.readInt(u32, e[24..28], .big),
            .size = std.mem.readInt(u32, e[36..40], .big),
            .oid = e[40..60],
            .stage = @intCast((flags >> 12) & 3),
            .skip_worktree = extended & 0x4000 != 0,
            .intent_to_add = extended & 0x2000 != 0,
        };
    }
};

fn sha256Repository(io: Io, git: Io.Dir) bool {
    var cbuf: [4096]u8 = undefined;
    const config = git.readFile(io, "config", &cbuf) catch return false;
    return std.mem.indexOf(u8, config, "sha256") != null;
}

/// The index of `git`, or null when there is none or it is unreadable.
pub fn readIndex(gpa: Allocator, io: Io, git: Io.Dir) ?[]u8 {
    if (sha256Repository(io, git)) return null;
    return git.readFileAlloc(io, "index", gpa, .limited(256 << 20)) catch null;
}

/// Tracked files whose working copy differs from the index, the way
/// `git diff` decides: an entry whose size and modification time match its
/// file is unchanged; any other is hashed as a blob (`blob <len>\0<bytes>`)
/// and compared, first as it is, then with CRLF line endings turned into LF
/// (the conversion `core.autocrlf` applies on Windows). A missing file is
/// modified. Symlinks, submodules, skip-worktree, intent-to-add and
/// unmerged entries are not compared.
pub fn indexModified(gpa: Allocator, io: Io, repo: Io.Dir, index: []const u8) ?u32 {
    var it = IndexIterator.init(index) orelse return null;
    var modified: u32 = 0;
    while (it.next() catch return null) |e| {
        if (e.stage != 0 or e.skip_worktree or e.intent_to_add or e.mode & 0o170000 != 0o100000) continue;
        if (!sameBlob(gpa, io, repo, e)) modified += 1;
    }
    return modified;
}

fn sameBlob(gpa: Allocator, io: Io, repo: Io.Dir, e: IndexEntry) bool {
    const st = repo.statFile(io, e.path, .{}) catch return false;
    const ns = st.mtime.nanoseconds;
    if (@as(u32, @truncate(st.size)) == e.size and ns >= 0 and
        @as(u32, @truncate(@as(u96, @intCast(@divFloor(ns, std.time.ns_per_s))))) == e.mtime_s and
        @as(u32, @intCast(@mod(ns, std.time.ns_per_s))) == e.mtime_ns) return true;
    const data = repo.readFileAlloc(io, e.path, gpa, .limited(1 << 30)) catch return false;
    defer gpa.free(data);
    if (std.mem.eql(u8, &blobOid(data), e.oid)) return true;
    if (std.mem.indexOf(u8, data, "\r\n") == null) return false;
    const lf = gpa.alloc(u8, data.len) catch return false;
    defer gpa.free(lf);
    var n: usize = 0;
    for (data, 0..) |ch, i| {
        if (ch == '\r' and i + 1 < data.len and data[i + 1] == '\n') continue;
        lf[n] = ch;
        n += 1;
    }
    return std.mem.eql(u8, &blobOid(lf[0..n]), e.oid);
}

/// The object name of `data` as a blob.
pub fn blobOid(data: []const u8) Oid {
    return objectOid(.blob, data);
}

pub fn objectOid(kind: Kind, data: []const u8) Oid {
    var h = std.crypto.hash.Sha1.init(.{});
    var hdr: [32]u8 = undefined;
    h.update(std.fmt.bufPrint(&hdr, "{t} {d}\x00", .{ kind, data.len }) catch unreachable);
    h.update(data);
    var out: Oid = undefined;
    h.final(&out);
    return out;
}

// ---------------------------------------------------------------------------
// The object store

pub const Kind = enum { commit, tree, blob, tag };

pub const Object = struct {
    kind: Kind,
    data: []u8,
};

pub const ReadError = error{ ObjectNotFound, MalformedObject, DeltaTooDeep, OutOfMemory };

/// Deltas deeper than this are refused (git's default `pack.depth` is 50).
const delta_depth_max = 256;

pub const Store = struct {
    gpa: Allocator,
    io: Io,
    objects: Io.Dir,
    packs: std.ArrayList(Pack) = .empty,

    const Pack = struct { idx: []u8, file: Io.File };

    /// The object store of `git` (or of its `commondir`, in a worktree).
    pub fn open(gpa: Allocator, io: Io, git: Io.Dir) ?Store {
        const objects = git.openDir(io, "objects", .{ .iterate = true }) catch blk: {
            var cbuf: [512]u8 = undefined;
            const common = std.mem.trim(u8, git.readFile(io, "commondir", &cbuf) catch return null, " \t\r\n");
            var pbuf: [600]u8 = undefined;
            const path = std.fmt.bufPrint(&pbuf, "{s}/objects", .{common}) catch return null;
            break :blk git.openDir(io, path, .{ .iterate = true }) catch return null;
        };
        var s: Store = .{ .gpa = gpa, .io = io, .objects = objects };
        s.openPacks() catch {};
        return s;
    }

    fn openPacks(s: *Store) !void {
        var dir = s.objects.openDir(s.io, "pack", .{ .iterate = true }) catch return;
        defer dir.close(s.io);
        var it = dir.iterate();
        while (try it.next(s.io)) |entry| {
            if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".idx")) continue;
            var nbuf: [Io.Dir.max_name_bytes]u8 = undefined;
            const pack_name = std.fmt.bufPrint(&nbuf, "{s}.pack", .{entry.name[0 .. entry.name.len - 4]}) catch continue;
            const idx = dir.readFileAlloc(s.io, entry.name, s.gpa, .limited(1 << 30)) catch continue;
            const file = dir.openFile(s.io, pack_name, .{}) catch {
                s.gpa.free(idx);
                continue;
            };
            s.packs.append(s.gpa, .{ .idx = idx, .file = file }) catch {
                file.close(s.io);
                s.gpa.free(idx);
                return error.OutOfMemory;
            };
        }
    }

    pub fn close(s: *Store) void {
        for (s.packs.items) |p| {
            p.file.close(s.io);
            s.gpa.free(p.idx);
        }
        s.packs.deinit(s.gpa);
        s.objects.close(s.io);
    }

    /// Reads an object; the caller frees `data`.
    pub fn read(s: *Store, oid: *const Oid) ReadError!Object {
        return s.readDepth(oid, 0);
    }

    fn readDepth(s: *Store, oid: *const Oid, depth: u32) ReadError!Object {
        if (depth > delta_depth_max) return error.DeltaTooDeep;
        if (try s.readLoose(oid)) |o| return o;
        for (s.packs.items) |p| {
            const offset = findInIdx(p.idx, oid) orelse continue;
            return s.readPacked(p, offset, depth);
        }
        return error.ObjectNotFound;
    }

    fn readLoose(s: *Store, oid: *const Oid) ReadError!?Object {
        const hex = std.fmt.bytesToHex(oid.*, .lower);
        var pbuf: [41]u8 = undefined;
        const path = std.fmt.bufPrint(&pbuf, "{s}/{s}", .{ hex[0..2], hex[2..] }) catch unreachable;
        const compressed = s.objects.readFileAlloc(s.io, path, s.gpa, .limited(1 << 30)) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return null,
        };
        defer s.gpa.free(compressed);
        var in: Io.Reader = .fixed(compressed);
        const raw = try inflate(s.gpa, &in, null);
        errdefer s.gpa.free(raw);
        const nul = std.mem.indexOfScalar(u8, raw, 0) orelse return error.MalformedObject;
        const space = std.mem.indexOfScalar(u8, raw[0..nul], ' ') orelse return error.MalformedObject;
        const kind = std.meta.stringToEnum(Kind, raw[0..space]) orelse return error.MalformedObject;
        const len = std.fmt.parseUnsigned(usize, raw[space + 1 .. nul], 10) catch return error.MalformedObject;
        if (len != raw.len - nul - 1) return error.MalformedObject;
        @memmove(raw[0..len], raw[nul + 1 ..]);
        return .{ .kind = kind, .data = s.gpa.realloc(raw, len) catch raw[0..len] };
    }

    fn readPacked(s: *Store, p: Pack, offset: u64, depth: u32) ReadError!Object {
        var buf: [4096]u8 = undefined;
        var fr = p.file.reader(s.io, &buf);
        fr.seekTo(offset) catch return error.MalformedObject;
        const r = &fr.interface;
        var c = r.takeByte() catch return error.MalformedObject;
        const type_code: u3 = @intCast((c >> 4) & 7);
        var size: u64 = c & 15;
        var shift: u6 = 4;
        while (c & 0x80 != 0) {
            c = r.takeByte() catch return error.MalformedObject;
            if (shift > 57) return error.MalformedObject;
            size |= @as(u64, c & 0x7f) << shift;
            shift += 7;
        }
        switch (type_code) {
            1, 2, 3, 4 => {
                const data = try inflate(s.gpa, r, size);
                return .{ .kind = @fromBackingInt(@intCast(type_code - 1)), .data = data };
            },
            6, 7 => {
                // A delta against a base at a lower offset (6) or named by oid (7).
                var base: Object = undefined;
                if (type_code == 6) {
                    c = r.takeByte() catch return error.MalformedObject;
                    var back: u64 = c & 0x7f;
                    while (c & 0x80 != 0) {
                        c = r.takeByte() catch return error.MalformedObject;
                        if (back > std.math.maxInt(u64) >> 8) return error.MalformedObject;
                        back = ((back + 1) << 7) | (c & 0x7f);
                    }
                    if (back == 0 or back > offset) return error.MalformedObject;
                    const delta = try inflate(s.gpa, r, size);
                    defer s.gpa.free(delta);
                    base = try s.readPacked(p, offset - back, depth + 1);
                    defer s.gpa.free(base.data);
                    return .{ .kind = base.kind, .data = try applyDelta(s.gpa, base.data, delta) };
                } else {
                    const base_oid = (r.takeArray(20) catch return error.MalformedObject).*;
                    const delta = try inflate(s.gpa, r, size);
                    defer s.gpa.free(delta);
                    base = try s.readDepth(&base_oid, depth + 1);
                    defer s.gpa.free(base.data);
                    return .{ .kind = base.kind, .data = try applyDelta(s.gpa, base.data, delta) };
                }
            },
            else => return error.MalformedObject,
        }
    }
};

/// The pack offset of `oid` in a version-2 pack index.
fn findInIdx(idx: []const u8, oid: *const Oid) ?u64 {
    const header = 8 + 256 * 4;
    if (idx.len < header or !std.mem.eql(u8, idx[0..4], "\xfftOc") or std.mem.readInt(u32, idx[4..8], .big) != 2) return null;
    const fanout = idx[8..header];
    const n = std.mem.readInt(u32, fanout[255 * 4 ..][0..4], .big);
    if (idx.len < header + @as(usize, n) * 28) return null;
    const names = idx[header..][0 .. @as(usize, n) * 20];
    var lo: usize = if (oid[0] == 0) 0 else std.mem.readInt(u32, fanout[(@as(usize, oid[0]) - 1) * 4 ..][0..4], .big);
    var hi: usize = std.mem.readInt(u32, fanout[@as(usize, oid[0]) * 4 ..][0..4], .big);
    if (hi > n or lo > hi) return null;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (std.mem.order(u8, names[mid * 20 ..][0..20], oid)) {
            .eq => {
                const offsets = header + @as(usize, n) * 24;
                const off32 = std.mem.readInt(u32, idx[offsets + mid * 4 ..][0..4], .big);
                if (off32 & 0x8000_0000 == 0) return off32;
                const large = offsets + @as(usize, n) * 4 + @as(usize, off32 & 0x7fff_ffff) * 8;
                if (large + 8 > idx.len) return null;
                return std.mem.readInt(u64, idx[large..][0..8], .big);
            },
            .lt => lo = mid + 1,
            .gt => hi = mid,
        }
    }
    return null;
}

/// Inflates one zlib stream from `in`; with `expected`, the result must
/// have exactly that length.
fn inflate(gpa: Allocator, in: *Io.Reader, expected: ?u64) ReadError![]u8 {
    const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(window);
    var d: std.compress.flate.Decompress = .init(in, .zlib, window);
    const limit: Io.Limit = if (expected) |e| .limited64(e + 1) else .limited(1 << 30);
    const out = d.reader.allocRemaining(gpa, limit) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedObject,
    };
    if (expected) |e| if (out.len != e) {
        gpa.free(out);
        return error.MalformedObject;
    };
    return out;
}

fn deltaVarint(delta: []const u8, pos: *usize) ReadError!u64 {
    var v: u64 = 0;
    var shift: u6 = 0;
    while (true) {
        if (pos.* >= delta.len or shift > 63) return error.MalformedObject;
        const c = delta[pos.*];
        pos.* += 1;
        v |= @as(u64, c & 0x7f) << shift;
        if (c & 0x80 == 0) return v;
        shift +|= 7;
    }
}

/// Applies a git delta (copy and insert instructions) to `base`.
pub fn applyDelta(gpa: Allocator, base: []const u8, delta: []const u8) ReadError![]u8 {
    var pos: usize = 0;
    if (try deltaVarint(delta, &pos) != base.len) return error.MalformedObject;
    const len = try deltaVarint(delta, &pos);
    if (len > 1 << 30) return error.MalformedObject;
    const out = try gpa.alloc(u8, @intCast(len));
    errdefer gpa.free(out);
    var n: usize = 0;
    while (pos < delta.len) {
        const op = delta[pos];
        pos += 1;
        if (op & 0x80 != 0) {
            var off: u64 = 0;
            var size: u64 = 0;
            for (0..4) |i| if (op & (@as(u8, 1) << @intCast(i)) != 0) {
                if (pos >= delta.len) return error.MalformedObject;
                off |= @as(u64, delta[pos]) << @intCast(8 * i);
                pos += 1;
            };
            for (0..3) |i| if (op & (@as(u8, 0x10) << @intCast(i)) != 0) {
                if (pos >= delta.len) return error.MalformedObject;
                size |= @as(u64, delta[pos]) << @intCast(8 * i);
                pos += 1;
            };
            if (size == 0) size = 0x10000;
            if (off + size > base.len or n + size > out.len) return error.MalformedObject;
            @memcpy(out[n..][0..@intCast(size)], base[@intCast(off)..][0..@intCast(size)]);
            n += @intCast(size);
        } else if (op != 0) {
            if (pos + op > delta.len or n + op > out.len) return error.MalformedObject;
            @memcpy(out[n..][0..op], delta[pos..][0..op]);
            pos += op;
            n += op;
        } else return error.MalformedObject;
    }
    if (n != out.len) return error.MalformedObject;
    return out;
}

// ---------------------------------------------------------------------------
// Staged changes

const TreeEntry = struct { mode: u32, oid: Oid };

/// Adds every file under tree `oid` to `files`, keyed by its path.
fn collectTree(store: *Store, arena: Allocator, oid: *const Oid, prefix: []const u8, files: *std.StringHashMapUnmanaged(TreeEntry), depth: u32) !void {
    if (depth > 4096) return error.MalformedObject;
    const obj = try store.read(oid);
    defer store.gpa.free(obj.data);
    if (obj.kind != .tree) return error.MalformedObject;
    var pos: usize = 0;
    const data = obj.data;
    while (pos < data.len) {
        const space = std.mem.indexOfScalarPos(u8, data, pos, ' ') orelse return error.MalformedObject;
        const nul = std.mem.indexOfScalarPos(u8, data, space, 0) orelse return error.MalformedObject;
        if (nul + 21 > data.len) return error.MalformedObject;
        const mode = std.fmt.parseUnsigned(u32, data[pos..space], 8) catch return error.MalformedObject;
        const name = data[space + 1 .. nul];
        const child: Oid = data[nul + 1 ..][0..20].*;
        pos = nul + 21;
        const path = if (prefix.len == 0) try arena.dupe(u8, name) else try std.fmt.allocPrint(arena, "{s}/{s}", .{ prefix, name });
        if (mode == 0o40000) {
            try collectTree(store, arena, &child, path, files, depth + 1);
        } else {
            try files.put(arena, path, .{ .mode = mode, .oid = child });
        }
    }
}

/// Paths whose index entry differs from the tree of commit `head`: what
/// `git diff --cached --name-only` lists. An entry with another object or
/// mode, an entry the tree lacks (added), a tree file the index lacks
/// (deleted), and a path with an unresolved conflict each count once.
/// Intent-to-add entries do not count. Null when an object cannot be read
/// or the index is a kind this reader does not handle.
pub fn stagedFiles(gpa: Allocator, store: *Store, head: *const Oid, index: []const u8) ?u32 {
    var it = IndexIterator.init(index) orelse return null;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const commit = store.read(head) catch return null;
    defer gpa.free(commit.data);
    if (commit.kind != .commit or !std.mem.startsWith(u8, commit.data, "tree ") or commit.data.len < 45) return null;
    var tree: Oid = undefined;
    _ = std.fmt.hexToBytes(&tree, commit.data[5..45]) catch return null;
    var files: std.StringHashMapUnmanaged(TreeEntry) = .empty;
    collectTree(store, arena, &tree, "", &files, 0) catch return null;

    var staged: u32 = 0;
    var last_conflict: []const u8 = "";
    while (it.next() catch return null) |e| {
        if (e.stage != 0) {
            if (!std.mem.eql(u8, e.path, last_conflict)) staged += 1;
            last_conflict = e.path;
            _ = files.remove(e.path);
            continue;
        }
        if (e.mode == 0o40000) return null; // a sparse index's directory entry
        if (e.intent_to_add) continue;
        const t = files.fetchRemove(e.path) orelse {
            staged += 1;
            continue;
        };
        if (t.value.mode != e.mode or !std.mem.eql(u8, &t.value.oid, e.oid)) staged += 1;
    }
    return staged + files.count();
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

/// A zlib stream of stored (uncompressed) deflate blocks.
pub fn testZlib(gpa: Allocator, data: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, &.{ 0x78, 0x01 });
    var rest = data;
    while (true) {
        const n: u16 = @intCast(@min(rest.len, 0xffff));
        try out.append(gpa, if (n == rest.len) 1 else 0);
        var le: [2]u8 = undefined;
        std.mem.writeInt(u16, &le, n, .little);
        try out.appendSlice(gpa, &le);
        std.mem.writeInt(u16, &le, ~n, .little);
        try out.appendSlice(gpa, &le);
        try out.appendSlice(gpa, rest[0..n]);
        rest = rest[n..];
        if (rest.len == 0) break;
    }
    var be: [4]u8 = undefined;
    std.mem.writeInt(u32, &be, std.hash.Adler32.hash(data), .big);
    try out.appendSlice(gpa, &be);
    return out.toOwnedSlice(gpa);
}

/// Writes a loose object into `objects` and returns its name.
pub fn testLoose(gpa: Allocator, io: Io, objects: Io.Dir, kind: Kind, data: []const u8) !Oid {
    const oid = objectOid(kind, data);
    const raw = try std.fmt.allocPrint(gpa, "{t} {d}\x00{s}", .{ kind, data.len, data });
    defer gpa.free(raw);
    const z = try testZlib(gpa, raw);
    defer gpa.free(z);
    const hex = std.fmt.bytesToHex(oid, .lower);
    try objects.createDirPath(io, hex[0..2]);
    var pbuf: [41]u8 = undefined;
    try objects.writeFile(io, .{ .sub_path = try std.fmt.bufPrint(&pbuf, "{s}/{s}", .{ hex[0..2], hex[2..] }), .data = z });
    return oid;
}

/// A version-2 index. Each entry is (path, content, stage); with zero
/// times, so a working-copy comparison hashes every file.
pub fn testIndex(gpa: Allocator, entries: []const struct { []const u8, []const u8, u2 }) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, "DIRC");
    var w4: [4]u8 = undefined;
    std.mem.writeInt(u32, &w4, 2, .big);
    try out.appendSlice(gpa, &w4);
    std.mem.writeInt(u32, &w4, @intCast(entries.len), .big);
    try out.appendSlice(gpa, &w4);
    for (entries) |e| {
        const start = out.items.len;
        var fixed: [62]u8 = @splat(0);
        std.mem.writeInt(u32, fixed[24..28], 0o100644, .big);
        std.mem.writeInt(u32, fixed[36..40], @intCast(e[1].len), .big);
        fixed[40..60].* = blobOid(e[1]);
        std.mem.writeInt(u16, fixed[60..62], @as(u16, e[2]) << 12 | @as(u16, @intCast(e[0].len)), .big);
        try out.appendSlice(gpa, &fixed);
        try out.appendSlice(gpa, e[0]);
        const len = out.items.len - start;
        try out.appendNTimes(gpa, 0, ((len + 8) & ~@as(usize, 7)) - len);
    }
    return out.toOwnedSlice(gpa);
}

test "a delta copies from its base and inserts new bytes" {
    // "the quick brown fox" (19) -> "the quick red fox!!!" (20): copy 10
    // bytes at 0, insert "red ", copy 3 bytes at 16, insert "!!!".
    const delta = [_]u8{ 19, 20, 0x90, 10, 4, 'r', 'e', 'd', ' ', 0x91, 16, 3, 3, '!', '!', '!' };
    const out = try applyDelta(testing.allocator, "the quick brown fox", &delta);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings("the quick red fox!!!", out);
    // A copy past the end of the base is refused.
    try testing.expectError(error.MalformedObject, applyDelta(testing.allocator, "short", &[_]u8{ 5, 9, 0x91, 2, 9 }));
}

fn packHeader(list: *std.ArrayList(u8), gpa: Allocator, type_code: u8, size: usize) !void {
    var c: u8 = (type_code << 4) | @as(u8, @intCast(size & 15));
    var rest = size >> 4;
    while (rest != 0) {
        try list.append(gpa, c | 0x80);
        c = @intCast(rest & 0x7f);
        rest >>= 7;
    }
    try list.append(gpa, c);
}

test "packed objects are read, with offset and reference deltas" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "git/objects/pack");

    const base = "the quick brown fox";
    const delta = [_]u8{ 19, 20, 0x90, 10, 4, 'r', 'e', 'd', ' ', 0x91, 16, 3, 3, '!', '!', '!' };
    const delta2 = [_]u8{ 19, 9, 0x90, 9 };
    const oids = [3]Oid{ blobOid(base), blobOid("the quick red fox!!!"), blobOid("the quick") };

    var pack: std.ArrayList(u8) = .empty;
    defer pack.deinit(gpa);
    try pack.appendSlice(gpa, "PACK\x00\x00\x00\x02\x00\x00\x00\x03");
    var offsets: [3]u64 = undefined;
    // A blob.
    offsets[0] = pack.items.len;
    try packHeader(&pack, gpa, 3, base.len);
    const z0 = try testZlib(gpa, base);
    defer gpa.free(z0);
    try pack.appendSlice(gpa, z0);
    // An offset delta against it.
    offsets[1] = pack.items.len;
    try packHeader(&pack, gpa, 6, delta.len);
    try pack.append(gpa, @intCast(offsets[1] - offsets[0])); // < 128: one byte
    const z1 = try testZlib(gpa, &delta);
    defer gpa.free(z1);
    try pack.appendSlice(gpa, z1);
    // A reference delta against it.
    offsets[2] = pack.items.len;
    try packHeader(&pack, gpa, 7, delta2.len);
    try pack.appendSlice(gpa, &oids[0]);
    const z2 = try testZlib(gpa, &delta2);
    defer gpa.free(z2);
    try pack.appendSlice(gpa, z2);
    try tmp.dir.writeFile(io, .{ .sub_path = "git/objects/pack/pack-test.pack", .data = pack.items });

    // Its version-2 index: fanout, sorted names, CRCs (unchecked), offsets.
    var order = [3]usize{ 0, 1, 2 };
    std.mem.sort(usize, &order, &oids, struct {
        fn less(o: *const [3]Oid, a: usize, b: usize) bool {
            return std.mem.order(u8, &o[a], &o[b]) == .lt;
        }
    }.less);
    var idx: std.ArrayList(u8) = .empty;
    defer idx.deinit(gpa);
    try idx.appendSlice(gpa, "\xfftOc\x00\x00\x00\x02");
    for (0..256) |b| {
        var count: u32 = 0;
        for (oids) |o| count += @intFromBool(o[0] <= b);
        var be: [4]u8 = undefined;
        std.mem.writeInt(u32, &be, count, .big);
        try idx.appendSlice(gpa, &be);
    }
    for (order) |k| try idx.appendSlice(gpa, &oids[k]);
    try idx.appendNTimes(gpa, 0, 3 * 4);
    for (order) |k| {
        var be: [4]u8 = undefined;
        std.mem.writeInt(u32, &be, @intCast(offsets[k]), .big);
        try idx.appendSlice(gpa, &be);
    }
    try tmp.dir.writeFile(io, .{ .sub_path = "git/objects/pack/pack-test.idx", .data = idx.items });

    const git = try tmp.dir.openDir(io, "git", .{});
    defer git.close(io);
    var store = Store.open(gpa, io, git).?;
    defer store.close();
    const want = [3][]const u8{ base, "the quick red fox!!!", "the quick" };
    for (&oids, want) |*o, w| {
        const obj = try store.read(o);
        defer gpa.free(obj.data);
        try testing.expectEqual(Kind.blob, obj.kind);
        try testing.expectEqualStrings(w, obj.data);
    }
    try testing.expectError(error.ObjectNotFound, store.read(&blobOid("absent")));
}

test "staged files: edits, additions, deletions and conflicts against the HEAD tree" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "git/objects");
    const objects = try tmp.dir.openDir(io, "git/objects", .{});
    defer objects.close(io);

    // HEAD: README, old.txt, src/lib.zig, src/main.zig.
    var src_buf: [256]u8 = undefined;
    const src = try std.fmt.bufPrint(&src_buf, "100644 lib.zig\x00{s}100644 main.zig\x00{s}", .{ &blobOid("lib\n"), &blobOid("main\n") });
    const src_oid = try testLoose(gpa, io, objects, .tree, src);
    var tree_buf: [512]u8 = undefined;
    const root = try std.fmt.bufPrint(&tree_buf, "100644 README\x00{s}100644 old.txt\x00{s}40000 src\x00{s}", .{ &blobOid("hello\n"), &blobOid("old\n"), &src_oid });
    const root_oid = try testLoose(gpa, io, objects, .tree, root);
    var commit_buf: [256]u8 = undefined;
    const commit = try std.fmt.bufPrint(&commit_buf, "tree {s}\nauthor a <a> 0 +0000\ncommitter a <a> 0 +0000\n\nfixture\n", .{&std.fmt.bytesToHex(root_oid, .lower)});
    const head = try testLoose(gpa, io, objects, .commit, commit);

    const git = try tmp.dir.openDir(io, "git", .{});
    defer git.close(io);
    var store = Store.open(gpa, io, git).?;
    defer store.close();

    // The index as HEAD has it: nothing staged.
    const same = try testIndex(gpa, &.{ .{ "README", "hello\n", 0 }, .{ "old.txt", "old\n", 0 }, .{ "src/lib.zig", "lib\n", 0 }, .{ "src/main.zig", "main\n", 0 } });
    defer gpa.free(same);
    try testing.expectEqual(@as(?u32, 0), stagedFiles(gpa, &store, &head, same));

    // README edited, old.txt deleted, new.txt added, src/lib.zig in
    // conflict (two stages, one path): four paths.
    const changed = try testIndex(gpa, &.{
        .{ "README", "hello, world\n", 0 },
        .{ "new.txt", "new\n", 0 },
        .{ "src/lib.zig", "ours\n", 2 },
        .{ "src/lib.zig", "theirs\n", 3 },
        .{ "src/main.zig", "main\n", 0 },
    });
    defer gpa.free(changed);
    try testing.expectEqual(@as(?u32, 4), stagedFiles(gpa, &store, &head, changed));

    // A commit that is not in the store: unknown.
    try testing.expectEqual(@as(?u32, null), stagedFiles(gpa, &store, &blobOid("nothing"), same));
}
