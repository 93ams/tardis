//! System-call mode (plan §9.2, `plan3.md` D9): the code under test makes
//! system calls, and the simulator answers them.
//!
//! Linux on x86_64. `syscalls.zig` traps every system call of a run; the
//! ones that are not the harness's own come here. Each call on the list
//! below is translated into the matching operation on the simulator's own
//! `std.Io`, so a write made by system call draws the same faults, leaves
//! the same trace events and meets a crash exactly as one made through
//! `env.dir`. A call that is not on the list, or that names a descriptor
//! the simulator did not issue, is declined, and `syscalls.zig` counts it
//! as stray.
//!
//! A simulated descriptor is the VFS handle value with bit 30 set
//! (`0x4000_0000` to `0x7FFF_FFFF`). The kernel hands out the lowest free
//! number, so no real descriptor is up there. `AT_FDCWD` and absolute
//! paths are the root of the calling task's node.
//!
//! Emulated: `open`, `openat`, `creat`, `close`, `read`, `write`, `readv`,
//! `writev`, `pread64`, `pwrite64`, `preadv`, `pwritev`, `lseek`, `fsync`,
//! `fdatasync`, `ftruncate`, `truncate`, `rename`, `renameat`, `renameat2`,
//! `unlink`, `unlinkat`, `rmdir`, `mkdir`, `mkdirat`, `stat`, `lstat`,
//! `fstat`, `newfstatat`, `statx`, `access`, `faccessat`, `faccessat2`,
//! `link`, `linkat`,
//! `getdents64`, `getcwd`, `fcntl` (descriptor flags, record locks and
//! open-file-description locks), `flock`,
//! `ioctl` (only to say that a file is not a terminal),
//! `chmod`, `fchmod`, `fchown`, `getuid` and its three relatives, `clock_gettime`,
//! `clock_getres`, `gettimeofday`, `time`, `nanosleep`, `clock_nanosleep`,
//! `getrandom`, and `futex` (waits and wakes, below).
//!
//! Not modelled, and answered as a single-user, single-process system
//! would: owners and permission bits (every file is 0644 and every
//! directory 0755, owned by user 1000; `fchmod` and `fchown` succeed and
//! change nothing), record locks (`fcntl` grants every one: POSIX record
//! locks never conflict inside one process, and the simulation is one
//! process), `O_NOFOLLOW`, `O_PATH`, `O_DIRECT`, `O_SYNC`.
//!
//! Open-file-description locks (`F_OFD_SETLK`, `F_OFD_SETLKW`,
//! `F_OFD_GETLK`, revision 122) are modelled: they belong to the open
//! file, so two `open`s of one file in one process do conflict, and a
//! `dup` shares its original's. A byte range locked for writing
//! conflicts with any other lock over it, one locked for reading with a
//! write lock; `F_OFD_SETLKW` waits, in virtual time, until the range is
//! free; a lock goes with the last descriptor of its open file, and with
//! its node's crash. A run in which every task waits for a lock fails as
//! a deadlock, where Linux would wait forever (it does not detect one
//! among these locks either). Divergences: a POSIX record lock, which
//! this grants without recording it, never conflicts with an
//! open-file-description lock, where on Linux the two kinds do; and a
//! run has at most `ofd_max` locked ranges over all its nodes, and
//! `waiters_max` tasks waiting for one (`ENOLCK` past them).
//!
//! `flock` (revision 139, which `std.Io.File.lock` makes) is modelled the
//! same way: a lock of the whole file, shared or exclusive, held by the
//! open file, gone with its last descriptor or its node's crash; `LOCK_NB`
//! fails with `EWOULDBLOCK` where it would wait; a change between shared
//! and exclusive gives up the lock first, as Linux's does; `LOCK_MAND` is
//! ignored, as Linux ignores it. As on Linux, a `flock` lock and a
//! byte-range lock are never in each other's way. The limits above hold
//! for both together. `flock` of a socket, a pipe, the root or the random
//! device is stray, where Linux's succeeds.
//!
//! `O_TRUNC`
//! without `O_CREAT` is an open and then a truncation, two steps another
//! task can come between. A sleep that is canceled returns `EINTR` and the
//! cancellation is spent. `dup`, and `fcntl` with `F_DUPFD` or
//! `F_DUPFD_CLOEXEC`, give a file or a directory a second descriptor with
//! the same position and flags (`dups`, below), as they do a socket
//! (`sysnet.zig`) and a pipe, an eventfd or an epoll set (`sysfd.zig`).
//! `mmap` of a simulated file, shared or private, is emulated (below,
//! "file mappings"). `O_TMPFILE`, `dup2`, `dup3` and `select`
//! are not emulated: they are stray, as is `dup` of the root descriptor
//! or of the random device, any
//! path under `/proc`, `/sys` or `/dev` (but `/dev/urandom`, and five
//! files a runtime reads to learn about the machine, which are answered
//! as missing: `libcProbe`) and any call
//! relative to a directory descriptor the simulator did not issue. The
//! root descriptor (`root_fd`) serves as a directory to be relative to,
//! and can be stat-ed, synced and closed, not listed.

const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;
const Sim = @import("Sim.zig");
const vfs_mod = @import("../model/vfs.zig");
const sysnet = @import("sysnet.zig");
const sysfd = @import("sysfd.zig");
const syscalls = @import("syscalls.zig");
const systhread = @import("systhread.zig");

/// Set in every simulated descriptor.
pub const fd_bit: u32 = 0x4000_0000;

/// The root directory as a descriptor.
pub const root_fd: i32 = @bitCast(vfs_mod.root_handle_value | fd_bit);

/// `/dev/urandom` and `/dev/random`, opened for reading: one descriptor,
/// with no state, whose bytes are the decider's, as `getrandom`'s are.
/// A C library that seeds itself from the device follows the seed. No
/// other device exists.
pub const random_fd: i32 = root_fd - 1;

fn isRandomDevice(path: []const u8) bool {
    return std.mem.eql(u8, path, "/dev/urandom") or std.mem.eql(u8, path, "/dev/random");
}

const E = linux.E;

const at_fdcwd: i32 = -100;
const at_symlink_nofollow = 0x100;
const at_removedir = 0x200;
const at_empty_path = 0x1000;

const o_accmode = 0o3;
const o_wronly = 0o1;
const o_creat = 0o100;
const o_excl = 0o200;
const o_trunc = 0o1000;
const o_append = 0o2000;
const o_directory = 0o200000;
const o_tmpfile = 0o20000000;

/// The largest count one `read` or `write` transfers, as in the kernel.
const rw_bytes_max = 0x7fff_f000;
const iovecs_max = 16;

fn fail(e: E) u64 {
    return @bitCast(-@as(i64, @backingInt(e)));
}

/// The errno for an error a simulated operation returned, by name.
pub fn errnoOf(err: anyerror) E {
    return switch (err) {
        error.FileNotFound => .NOENT,
        error.PathAlreadyExists => .EXIST,
        error.NotDir => .NOTDIR,
        error.IsDir => .ISDIR,
        error.DirNotEmpty => .NOTEMPTY,
        error.NoSpaceLeft => .NOSPC,
        error.DiskQuota => .DQUOT,
        error.FileTooBig => .FBIG,
        error.NameTooLong => .NAMETOOLONG,
        error.BadPathName => .INVAL,
        error.FileBusy, error.DeviceBusy => .BUSY,
        error.SystemResources => .NOMEM,
        error.ProcessFdQuotaExceeded => .MFILE,
        error.SystemFdQuotaExceeded => .NFILE,
        error.NotOpenForReading, error.NotOpenForWriting => .BADF,
        // A handle the filesystem no longer knows: closed, or from before
        // a crash.
        error.Unexpected => .BADF,
        error.SymLinkLoop => .LOOP,
        error.NotLink => .INVAL,
        error.PermissionDenied => .PERM,
        error.AccessDenied => .ACCES,
        error.ReadOnlyFileSystem => .ROFS,
        error.CrossDevice => .XDEV,
        error.LinkQuotaExceeded => .MLINK,
        error.Unseekable => .SPIPE,
        error.LockViolation, error.WouldBlock => .AGAIN,
        error.Canceled => .INTR,
        error.InputOutput => .IO,
        else => .IO,
    };
}

fn fdOf(x: u64) i32 {
    return @bitCast(@as(u32, @truncate(x)));
}

fn simulated(fd: i32) bool {
    return fd > 0 and (@as(u32, @bitCast(fd)) & fd_bit) != 0;
}

fn valueOf(fd: i32) u32 {
    return @as(u32, @bitCast(fd)) & (fd_bit - 1);
}

fn fileOf(fd: i32) Io.File {
    return .{ .handle = @intCast(valueOf(fd)), .flags = .{ .nonblocking = false } };
}

fn fdFromHandle(h: Io.File.Handle) u64 {
    return @as(u32, @bitCast(@as(i32, h))) | fd_bit;
}

fn handleOf(s: *Sim, fd: i32) ?*vfs_mod.Handle {
    return s.vfs.handle(valueOf(fd)) catch null;
}

// --- duplicates ---------------------------------------------------------------

/// The first descriptor `dup` gives for a file: between the sockets'
/// numbers and the files'.
pub const dup_base: i32 = 0x3000_0000;
const dups_max = 64;

/// A handle of a node's file system.
const Held = struct {
    used: bool = false,
    node: u16 = 0,
    value: u32 = 0,

    /// False once the handle is closed, or its node has crashed.
    fn live(h: Held, s: *Sim) bool {
        if (!h.used) return false;
        _ = s.nodes[h.node].vfs.handle(h.value) catch return false;
        return true;
    }
};

/// `dups[i]` is the handle that descriptor `dup_base + i` is a second
/// number for. The position and the flags are the handle's, so the two
/// share them, as two descriptors of one open file description do.
threadlocal var dups: [dups_max]Held = @splat(.{});
/// The handles whose own descriptor was closed while a duplicate was
/// open: that number is no longer a descriptor, and the handle lives.
threadlocal var orphans: [dups_max]Held = @splat(.{});

/// A descriptor number that is in the simulated range and never open.
const dead_fd: i32 = @bitCast(fd_bit);

fn isDupFd(fd: i32) bool {
    return fd >= dup_base and fd < dup_base + dups_max;
}

fn holds(s: *Sim, table: *[dups_max]Held, node: u16, value: u32) ?*Held {
    for (table) |*h| if (h.node == node and h.value == value and h.live(s)) return h;
    return null;
}

/// The descriptor a call names, as the handle's own number: a duplicate
/// becomes the number it duplicates, and a number that was closed while
/// its duplicate lives becomes one that is not open.
fn resolve(s: *Sim, fd: i32) i32 {
    if (isDupFd(fd)) {
        const d = dups[@intCast(fd - dup_base)];
        return if (d.used and d.node == s.currentNode()) @bitCast(d.value | fd_bit) else dead_fd;
    }
    if (!simulated(fd) or fd == root_fd or fd == random_fd) return fd;
    return if (holds(s, &orphans, s.currentNode(), valueOf(fd)) != null) dead_fd else fd;
}

/// A node crashed (null: every node): its duplicates are gone with its
/// handles.
pub fn dropNode(node: ?u16) void {
    for ([_]*[dups_max]Held{ &dups, &orphans }) |table| {
        for (table) |*h| {
            if (node == null or h.node == node.?) h.* = .{};
        }
    }
    for (&ranges) |*r| {
        if (node == null or r.node == node.?) r.* = .{};
    }
    for (&waiters) |*w| {
        if (node == null or w.node == node.?) w.* = .{};
    }
    dropBackings(node);
}

/// `dup` of a file or a directory.
fn duplicate(s: *Sim, fd: i32) ?u64 {
    if (fd == root_fd or fd == random_fd) return null;
    if (handleOf(s, fd) == null) return fail(.BADF);
    for (&dups, 0..) |*d, i| {
        if (d.live(s)) continue;
        d.* = .{ .used = true, .node = s.currentNode(), .value = valueOf(fd) };
        return @intCast(dup_base + @as(i32, @intCast(i)));
    }
    return fail(.MFILE);
}

fn cstr(ptr: u64) ?[]const u8 {
    if (ptr == 0) return null;
    return std.mem.span(@as([*:0]const u8, @ptrFromInt(ptr)));
}

const DirOf = union(enum) {
    dir: Io.Dir,
    /// A simulated descriptor that is not open: `EBADF`.
    closed,
    /// Not the simulator's to answer: the call is stray.
    foreign,
};

/// The host's own trees. The simulated filesystem has none of them, and
/// what asks for them is the harness (a crash report reading
/// `/proc/self/exe`) or code that wants the real machine.
fn hostPath(path: []const u8) bool {
    return std.mem.startsWith(u8, path, "/proc/") or std.mem.startsWith(u8, path, "/sys/") or
        (std.mem.startsWith(u8, path, "/dev/") and !isRandomDevice(path));
}

/// The directory a path is relative to.
fn dirOf(s: *Sim, dirfd: i32, path: []const u8) DirOf {
    if (hostPath(path)) return .foreign;
    if (dirfd == at_fdcwd or (path.len > 0 and path[0] == '/')) return .{ .dir = Sim.rootDir() };
    if (!simulated(dirfd)) return .foreign;
    if (dirfd == root_fd) return .{ .dir = Sim.rootDir() };
    if (handleOf(s, dirfd) == null) return .closed;
    return .{ .dir = .{ .handle = @intCast(valueOf(dirfd)) } };
}

// --- poll ------------------------------------------------------------------------

const PollFd = extern struct { fd: i32, events: i16, revents: i16 };

fn pollDeadline(s: *Sim, timeout_ms: u64) ?u64 {
    const ms: i32 = @bitCast(@as(u32, @truncate(timeout_ms)));
    if (ms < 0) return null;
    return s.now_ns + @as(u64, @intCast(ms)) * std.time.ns_per_ms;
}

fn ppoll(s: *Sim, fds_ptr: u64, nfds: u64, ts_ptr: u64) ?u64 {
    if (ts_ptr == 0) return poll(s, fds_ptr, nfds, null);
    const ts: *align(1) const [2]i64 = @ptrFromInt(ts_ptr);
    if (ts[0] < 0 or ts[1] < 0 or ts[1] >= std.time.ns_per_s) return fail(.INVAL);
    const ns = @as(u64, @intCast(ts[0])) *| std.time.ns_per_s +| @as(u64, @intCast(ts[1]));
    return poll(s, fds_ptr, nfds, s.now_ns +| ns);
}

/// `poll` over simulated descriptors: sockets (`sysnet.pollMask`) and
/// simulated files (always ready, as regular files are). A real
/// descriptor among them makes the call a stray. Waits in virtual time,
/// for the network to change or the deadline to pass.
fn poll(s: *Sim, fds_ptr: u64, nfds: u64, deadline: ?u64) ?u64 {
    if (nfds > 4096) return fail(.INVAL);
    if (nfds > 0 and fds_ptr == 0) return fail(.FAULT);
    const fds: []align(1) PollFd = if (nfds == 0) &.{} else @as([*]align(1) PollFd, @ptrFromInt(fds_ptr))[0..nfds];
    // A real descriptor, or an epoll set (not emulated inside a `poll`).
    for (fds) |p| if (p.fd >= 0 and (descriptorKind(s, p.fd) == .real or sysfd.isEpoll(p.fd))) return null;
    s.yieldPoint();
    while (true) {
        var ready: u64 = 0;
        for (fds) |*p| {
            p.revents = 0;
            if (p.fd < 0) continue;
            const mask: u16 = descriptorMask(s, p.fd);
            const want: u16 = @as(u16, @bitCast(p.events)) | sysnet.pollerr | sysnet.pollhup | sysnet.pollnval;
            p.revents = @bitCast(mask & want);
            if (p.revents != 0) ready += 1;
        }
        if (ready > 0) return ready;
        if (deadline) |d| if (s.now_ns >= d) return 0;
        // Wake for the next network event too: a delivery due later.
        var until = deadline;
        if (s.net.nextEventAfter(s.now_ns)) |t| until = if (until) |d| @min(d, t) else t;
        s.waitNetwork(until) catch return fail(.INTR);
    }
}

/// What a descriptor number is, for the calls that take a set of them
/// (`poll`, `epoll_ctl`).
pub const DescriptorKind = enum {
    /// Not one the simulator issued.
    real,
    /// In a simulated range, and not open.
    closed,
    /// A simulated file or directory: always ready.
    file,
    /// A socket, a pipe, an eventfd or an epoll set.
    pollable,
};

pub fn descriptorKind(s: *Sim, raw: i32) DescriptorKind {
    const fd = resolve(s, raw);
    if (sysnet.isSocketFd(fd)) return if (sysnet.pollMask(s, fd) == sysnet.pollnval) .closed else .pollable;
    if (sysfd.isFd(fd)) return if (sysfd.pollMask(fd) == sysfd.poll_nval and !sysfd.isEpoll(fd)) .closed else .pollable;
    if (!simulated(fd)) return .real;
    return if (fd == root_fd or fd == random_fd or handleOf(s, fd) != null) .file else .closed;
}

/// The events a simulated descriptor has now, as `poll` names them.
pub fn descriptorMask(s: *Sim, raw: i32) u16 {
    const fd = resolve(s, raw);
    if (sysnet.isSocketFd(fd)) return sysnet.pollMask(s, fd);
    if (sysfd.isFd(fd)) return sysfd.pollMask(fd);
    if (fd == root_fd or fd == random_fd or (simulated(fd) and handleOf(s, fd) != null))
        return sysnet.pollin | sysnet.pollout | 0x40 | 0x100;
    return sysnet.pollnval;
}

/// A run begins: no socket, pipe, eventfd or epoll set is open.
pub fn resetRun() void {
    sysnet.reset();
    sysfd.reset();
    systhread.reset();
    dups = @splat(.{});
    orphans = @splat(.{});
    ranges = @splat(.{});
    waiters = @splat(.{});
    dropBackings(null);
}

/// Entry point for `syscalls.zig`: the value for `rax`, or null for a
/// call that is not emulated.
pub fn emulate(number: u64, a: *const [6]u64) ?u64 {
    const s = Sim.activeOrNull() orelse return null;
    if (!s.config.emulate_syscalls) return null;
    const raw = fdOf(a[0]);
    // A file's duplicate is the file's own number from here on.
    const fd = resolve(s, raw);
    // Sockets, and any call on a socket descriptor (`sysnet.zig`).
    if ((number >= 41 and number <= 55) or number == 288) {
        // A pair of sockets is two pipes (`sysfd.zig`).
        if (number == 53) return sysfd.emulate(s, number, a);
        if (number != 41 and sysfd.isFd(fd)) {
            sysfd.touched(fd);
            return sysfd.emulate(s, number, a);
        }
        if (number != 41) sysfd.touched(fd);
        return sysnet.emulate(s, number, a);
    }
    // Threads, and what a thread asks of the kernel (`systhread.zig`).
    switch (number) {
        56, 435, 334, 273, 24, 14, 60, 186, 218, 131, 11, 200, 234 => return systhread.emulate(s, number, a),
        else => {},
    }
    // Pipes, eventfds and epoll sets (`sysfd.zig`).
    switch (number) {
        22, 293, 284, 290, 213, 291, 232, 233, 281, 441 => return sysfd.emulate(s, number, a),
        else => {},
    }
    // Only a call whose first argument is a descriptor: in another, it is
    // a pointer or a number that may happen to fall in the range.
    const on_descriptor = switch (number) {
        0, 1, 3, 5, 8, 16, 17, 18, 19, 20, 32, 72, 74, 75, 77, 91, 93, 217, 295, 296 => true,
        else => false,
    };
    if (on_descriptor and sysnet.isSocketFd(fd)) {
        sysfd.touched(fd);
        return sysnet.emulate(s, number, a);
    }
    if (on_descriptor and sysfd.isFd(fd)) {
        sysfd.touched(fd);
        return sysfd.emulate(s, number, a);
    }
    return switch (number) {
        9 => mapFile(s, a),
        26 => msync(s, a[0], a[1], @truncate(a[2])),
        7 => poll(s, a[0], a[1], pollDeadline(s, a[2])),
        271 => ppoll(s, a[0], a[1], a[2]),
        2 => open(s, at_fdcwd, a[0], @truncate(a[1])),
        85 => open(s, at_fdcwd, a[0], o_creat | o_wronly | o_trunc), // creat
        257 => open(s, fd, a[1], @truncate(a[2])),
        86 => link(s, at_fdcwd, a[0], at_fdcwd, a[1], 0),
        265 => link(s, fd, a[1], resolve(s, fdOf(a[2])), a[3], @truncate(a[4])),
        89 => readlink(s, at_fdcwd, a[0], a[1], a[2]),
        267 => readlink(s, fd, a[1], a[2], a[3]),
        // Calls on a descriptor: only on one of ours.
        0, 1, 3, 5, 8, 16, 17, 18, 19, 20, 32, 72, 73, 74, 75, 77, 91, 93, 217, 295, 296 => {
            if (!simulated(fd)) return null;
            if (number == 16) return ioctl(s, fd, @truncate(a[1]));
            // A duplicate of the random device, or a lock of it, is not
            // emulated; nor is a lock of the root.
            const dups_it = number == 32 or number == 73 or (number == 72 and (@as(u32, @truncate(a[1])) == 0 or @as(u32, @truncate(a[1])) == 1030));
            if (fd == random_fd) return if (dups_it) null else randomDevice(s, number, a);
            if (number == 73 and fd == root_fd) return null;
            return switch (number) {
                0 => read(s, fd, a[1], a[2], null),
                1 => write(s, fd, a[1], a[2], null),
                3 => close(s, raw),
                32 => duplicate(s, fd),
                5 => fstat(s, fd, a[1]),
                8 => lseek(s, fd, @bitCast(a[1]), @truncate(a[2])),
                17 => read(s, fd, a[1], a[2], a[3]),
                18 => write(s, fd, a[1], a[2], a[3]),
                19 => vectors(s, fd, a[1], a[2], null, .read),
                20 => vectors(s, fd, a[1], a[2], null, .write),
                72 => fcntl(s, fd, @truncate(a[1]), a[2]),
                73 => flock(s, fd, a[1]),
                74 => fsync(s, fd, false),
                75 => fsync(s, fd, true),
                77 => ftruncate(s, fd, a[1]),
                91, 93 => if (fd == root_fd or handleOf(s, fd) != null) 0 else fail(.BADF), // fchmod, fchown
                217 => getdents(s, fd, a[1], a[2]),
                295 => vectors(s, fd, a[1], a[2], a[3], .read),
                296 => vectors(s, fd, a[1], a[2], a[3], .write),
                else => unreachable,
            };
        },
        76 => truncate(s, a[0], a[1]),
        82 => rename(s, at_fdcwd, a[0], at_fdcwd, a[1], 0),
        264 => rename(s, fd, a[1], resolve(s, fdOf(a[2])), a[3], 0),
        316 => rename(s, fd, a[1], resolve(s, fdOf(a[2])), a[3], @truncate(a[4])),
        87 => unlink(s, at_fdcwd, a[0], 0),
        84 => unlink(s, at_fdcwd, a[0], at_removedir),
        263 => unlink(s, fd, a[1], @truncate(a[2])),
        83 => mkdir(s, at_fdcwd, a[0]),
        258 => mkdir(s, fd, a[1]),
        4 => statPath(s, at_fdcwd, a[0], a[1], 0, .old),
        6 => statPath(s, at_fdcwd, a[0], a[1], at_symlink_nofollow, .old),
        262 => statPath(s, fd, a[1], a[2], @truncate(a[3]), .old),
        332 => statPath(s, fd, a[1], a[4], @truncate(a[2]), .x),
        21, 90 => access(s, at_fdcwd, a[0]), // access; chmod, which changes nothing
        269, 439 => access(s, fd, a[1]),
        79 => getcwd(a[0], a[1]),
        63 => uname(a[0]),
        102, 104, 107, 108 => owner_id, // getuid, getgid, geteuid, getegid
        228 => clockGettime(s, @truncate(a[0]), a[1]),
        229 => if (clockOf(@truncate(a[0])) == null) fail(.INVAL) else clockGetres(a[1]),
        96 => gettimeofday(s, a[0]),
        201 => time(s, a[0]),
        204 => schedGetaffinity(s, a[1], a[2]),
        202 => futex(s, a),
        35 => sleep(s, 1, 0, a[0], a[1]),
        230 => sleep(s, @truncate(a[0]), @truncate(a[1]), a[2], a[3]),
        318 => getrandom(s, a[0], a[1]),
        else => null,
    };
}

// --- files -------------------------------------------------------------------

/// `ioctl` on a file, a directory or the random device: the requests
/// that ask whether it is a terminal (`TCGETS` and `TCGETS2`, which are
/// `isatty`, and `TIOCGWINSZ`, which musl's `fopen` makes to choose its
/// buffering), and it is not. Any other is not emulated.
fn ioctl(s: *Sim, fd: i32, request: u32) ?u64 {
    if (fd != root_fd and fd != random_fd and handleOf(s, fd) == null) return fail(.BADF);
    return switch (request) {
        0x5401, 0x802C542A, 0x5413 => fail(.NOTTY),
        else => null,
    };
}

/// A file a language's runtime reads to learn about the machine, which
/// is answered as missing: at once, with no event and no decision, so
/// that the run in which the runtime happens to ask (often once in the
/// life of the process) is the same run as every other of its seed. Each
/// runtime takes the missing file as a default, and where the question is
/// the number of processors it goes on to `sched_getaffinity`, which says
/// one, or what `Options.processors` says.
///
/// - glibc's allocator asks whether the kernel overcommits memory, the
///   first time a thread's heap shrinks.
/// - glibc (2.41 was run; 2.36 and later by its source) counts
///   processors from `online` and `possible`, then from `/proc/stat`
///   (`sysconf`, `get_nprocs`, and through them C++'s
///   `hardware_concurrency`). musl asks `sched_getaffinity` only.
/// - Rust's `available_parallelism` reads the process's cgroup for a
///   limit on processor time. tokio sizes its runtime with it.
///
/// Only an `open` for reading of exactly these paths (one that writes or
/// creates is a stray, as before). A program that reads one of them
/// for its own purposes finds it missing too, and is not told that it
/// asked about the real machine; any other path under `/proc` or `/sys`
/// is still a stray.
fn libcProbe(path: []const u8) bool {
    const probes = [_][]const u8{
        "/proc/sys/vm/overcommit_memory",
        "/sys/devices/system/cpu/online",
        "/sys/devices/system/cpu/possible",
        "/proc/stat",
        "/proc/self/cgroup",
    };
    for (probes) |probe| {
        if (std.mem.eql(u8, path, probe)) return true;
    }
    return false;
}

fn open(s: *Sim, dirfd: i32, path_ptr: u64, flags: u32) ?u64 {
    const path = cstr(path_ptr) orelse return fail(.FAULT);
    if (flags & (o_accmode | o_creat) == 0 and libcProbe(path)) return fail(.NOENT);
    const dir = switch (dirOf(s, dirfd, path)) {
        .dir => |d| d,
        .closed => return fail(.BADF),
        .foreign => return null,
    };
    const io = s.io();
    const acc = flags & o_accmode;
    if (acc == o_accmode) return fail(.INVAL);
    if (acc == 0 and flags & o_creat == 0 and isRandomDevice(path)) return @as(u32, @bitCast(random_fd));
    if (flags & o_tmpfile != 0) return fail(.OPNOTSUPP);
    var handle: Io.File.Handle = undefined;
    if (flags & o_creat != 0) {
        if (flags & o_directory != 0) return fail(.INVAL);
        const f = dir.createFile(io, path, .{
            .read = acc != o_wronly,
            .truncate = flags & o_trunc != 0,
            .exclusive = flags & o_excl != 0,
        }) catch |err| return fail(errnoOf(err));
        handle = f.handle;
        if (acc == 0) if (s.vfs.handle(@bitCast(@as(i32, handle)))) |h| {
            h.writable = false;
        } else |_| {};
    } else if (flags & o_directory != 0) {
        const d = dir.openDir(io, path, .{}) catch |err| return fail(errnoOf(err));
        // Linux refuses a directory opened for writing.
        if (acc != 0) {
            d.close(io);
            return fail(.ISDIR);
        }
        handle = d.handle;
    } else {
        const f = dir.openFile(io, path, .{
            .mode = switch (acc) {
                0 => .read_only,
                o_wronly => .write_only,
                else => .read_write,
            },
            .allow_directory = true,
        }) catch |err| return fail(errnoOf(err));
        handle = f.handle;
        // A directory with O_TRUNC is EISDIR, whatever the access.
        if (flags & o_trunc != 0 and isDirHandle(s, f.handle)) {
            f.close(io);
            return fail(.ISDIR);
        }
        // Linux truncates a regular file even when it is opened read-only.
        if (flags & o_trunc != 0) truncateAny(s, f.handle) catch |err| {
            f.close(io);
            return fail(errnoOf(err));
        };
    }
    if (flags & o_append != 0) if (s.vfs.handle(@bitCast(@as(i32, handle)))) |h| {
        h.append = true;
    } else |_| {};
    if (flags & o_trunc != 0) resizeNode(s);
    return fdFromHandle(handle);
}

fn isDirHandle(s: *Sim, handle: Io.File.Handle) bool {
    const h = s.vfs.handle(@bitCast(@as(i32, handle))) catch return false;
    return s.vfs.inodes[h.inode].kind == .dir;
}

/// Sets a file's length to zero whatever access its handle has.
fn truncateAny(s: *Sim, handle: Io.File.Handle) !void {
    const h = try s.vfs.handle(@bitCast(@as(i32, handle)));
    const was = h.writable;
    h.writable = true;
    defer h.writable = was;
    const f: Io.File = .{ .handle = handle, .flags = .{ .nonblocking = false } };
    try f.setLength(s.io(), 0);
}

/// `sched_getaffinity`: the processors the test asked for
/// (`Options.processors`, one unless it says otherwise), the same on
/// every machine, so code that sizes itself by the processor count runs
/// the same everywhere. The first so many, as a mask of 64.
fn schedGetaffinity(s: *Sim, len: u64, mask_ptr: u64) u64 {
    if (len < 8) return fail(.INVAL);
    if (mask_ptr == 0) return fail(.FAULT);
    const count: u7 = @intCast(std.math.clamp(s.config.processors, 1, 64));
    const bits: u64 = if (count == 64) ~@as(u64, 0) else (@as(u64, 1) << @intCast(count)) - 1;
    @as(*align(1) u64, @ptrFromInt(mask_ptr)).* = std.mem.nativeToLittle(u64, bits);
    return 8;
}

/// The calls on the random device's descriptor.
fn randomDevice(s: *Sim, number: u64, a: *const [6]u64) u64 {
    switch (number) {
        0, 17 => return getrandom(s, a[1], a[2]),
        3 => return 0,
        5 => {
            if (a[1] == 0) return fail(.FAULT);
            @as(*align(1) KernelStat, @ptrFromInt(a[1])).* = .{
                .dev = 5,
                .ino = 9,
                .nlink = 1,
                .mode = 0o020666, // a character device
                .uid = 0,
                .gid = 0,
                .rdev = 0x109,
                .size = 0,
                .blksize = vfs_mod.page_bytes,
                .blocks = 0,
                .atime = .{ 0, 0 },
                .mtime = .{ 0, 0 },
                .ctime = .{ 0, 0 },
            };
            return 0;
        },
        72 => return switch (@as(u32, @truncate(a[1]))) {
            1 => 1, // F_GETFD
            2 => 0, // F_SETFD
            3 => 0o100000, // F_GETFL: O_RDONLY | O_LARGEFILE
            else => fail(.INVAL),
        },
        8 => return 0, // lseek
        19 => return vectorsRandom(s, a[1], a[2]),
        else => return fail(.BADF), // not open for writing
    }
}

fn vectorsRandom(s: *Sim, iov_ptr: u64, count: u64) u64 {
    if (count == 0) return 0;
    if (iov_ptr == 0) return fail(.FAULT);
    const first = @as(*align(1) const [2]u64, @ptrFromInt(iov_ptr)).*;
    return getrandom(s, first[0], first[1]);
}

fn close(s: *Sim, raw: i32) u64 {
    if (raw == root_fd) return 0; // always open
    const fd = resolve(s, raw);
    if (handleOf(s, fd) == null) return fail(.BADF);
    const node = s.currentNode();
    const value = valueOf(fd);
    if (isDupFd(raw)) {
        dups[@intCast(raw - dup_base)] = .{};
        // The handle is closed with its last number.
        if (holds(s, &dups, node, value) != null) return 0;
        (holds(s, &orphans, node, value) orelse return 0).* = .{};
    } else if (holds(s, &dups, node, value) != null) {
        // As many orphans as duplicates at most: there is room.
        for (&orphans) |*o| {
            if (o.live(s)) continue;
            o.* = .{ .used = true, .node = node, .value = value };
            return 0;
        }
        unreachable;
    }
    // Its locks go with it: whoever waits for one of them looks again.
    // Whoever waits to lock through it stops waiting.
    var wake = dropLocks(node, value);
    for (&waiters) |*w| if (w.used and w.node == node and w.value == value) {
        w.closed = true;
        wake = true;
    };
    if (wake) s.wakeNetwork();
    fileOf(fd).close(s.io());
    return 0;
}

fn userBytes(ptr: u64, len: u64) ?[]u8 {
    if (ptr == 0) return null;
    return @as([*]u8, @ptrFromInt(ptr))[0..@min(len, rw_bytes_max)];
}

const Direction = enum { read, write };

/// What the kernel checks before it looks at the count, so that a
/// transfer of no bytes fails as one of some bytes would.
fn refused(s: *Sim, fd: i32, direction: Direction) ?E {
    const h = handleOf(s, fd) orelse return .BADF;
    switch (direction) {
        .read => {
            if (!h.readable) return .BADF;
            if (s.vfs.inodes[h.inode].kind == .dir) return .ISDIR;
        },
        .write => if (!h.writable) return .BADF,
    }
    return null;
}

/// `read` (at the descriptor's position, which moves) or `pread64`.
fn read(s: *Sim, fd: i32, buf_ptr: u64, len: u64, offset: ?u64) u64 {
    if (refused(s, fd, .read)) |e| return fail(e);
    if (len == 0) return 0;
    var bufs: [1][]u8 = .{userBytes(buf_ptr, len) orelse return fail(.FAULT)};
    return readInto(s, fd, &bufs, offset);
}

fn readInto(s: *Sim, fd: i32, bufs: []const []u8, offset: ?u64) u64 {
    // What was stored into a mapping is what a read sees.
    if (backingFor(s, fd)) |b| _ = syncOut(s, b);
    const io = s.io();
    const f = fileOf(fd);
    if (offset) |at| {
        if (@as(i64, @bitCast(at)) < 0) return fail(.INVAL);
        return f.readPositional(io, bufs, at) catch |err| return fail(errnoOf(err));
    }
    return f.readStreaming(io, bufs) catch |err| switch (err) {
        error.EndOfStream => 0,
        else => fail(errnoOf(err)),
    };
}

/// `write` or `pwrite64`. A descriptor opened with `O_APPEND` writes at
/// the end either way, as on Linux (the simulator's handle carries the
/// flag, and finds the end after any yield).
fn write(s: *Sim, fd: i32, buf_ptr: u64, len: u64, offset: ?u64) u64 {
    if (refused(s, fd, .write)) |e| return fail(e);
    if (len == 0) return 0;
    const bufs: [1][]const u8 = .{userBytes(buf_ptr, len) orelse return fail(.FAULT)};
    return writeFrom(s, fd, &bufs, offset);
}

fn writeFrom(s: *Sim, fd: i32, bufs: []const []const u8, offset: ?u64) u64 {
    const io = s.io();
    const f = fileOf(fd);
    // A mapping of the file keeps what was stored into it elsewhere, and
    // sees the bytes written.
    if (backingFor(s, fd)) |m| _ = syncOut(s, m);
    if (offset) |at| {
        if (@as(i64, @bitCast(at)) < 0) return fail(.INVAL);
        const n = f.writePositional(io, bufs, at) catch |err| return fail(errnoOf(err));
        afterWrite(s, fd, at, n);
        return n;
    }
    const n = f.writeStreaming(io, &.{}, bufs, 1) catch |err| return fail(errnoOf(err));
    afterWrite(s, fd, null, n);
    return n;
}

/// `readv`, `writev`, `preadv`, `pwritev`: the first `iovecs_max` vectors
/// (a short transfer is always allowed).
fn vectors(s: *Sim, fd: i32, iov_ptr: u64, count: u64, offset: ?u64, comptime direction: Direction) u64 {
    if (refused(s, fd, direction)) |e| return fail(e);
    if (count == 0) return 0;
    if (iov_ptr == 0) return fail(.FAULT);
    if (count > 1024) return fail(.INVAL);
    const Vec = extern struct { base: u64, len: u64 };
    const iov = @as([*]align(1) const Vec, @ptrFromInt(iov_ptr))[0..@min(count, iovecs_max)];
    var bufs: [iovecs_max][]u8 = undefined;
    var n: usize = 0;
    for (iov) |v| {
        if (v.len == 0) continue;
        bufs[n] = userBytes(v.base, v.len) orelse return fail(.FAULT);
        n += 1;
    }
    if (n == 0) return 0;
    return switch (direction) {
        .read => readInto(s, fd, bufs[0..n], offset),
        .write => writeFrom(s, fd, @ptrCast(bufs[0..n]), offset),
    };
}

fn lseek(s: *Sim, fd: i32, offset: i64, whence: u32) u64 {
    const h = handleOf(s, fd) orelse return fail(.BADF);
    const node = &s.vfs.inodes[h.inode];
    const base: i64 = switch (whence) {
        0 => 0,
        1 => @intCast(h.pos),
        // A directory has no end to seek from (ext4 says the same).
        2 => if (node.kind == .dir) return fail(.INVAL) else @intCast(node.cur_len_bytes),
        else => return fail(.INVAL),
    };
    const pos = std.math.add(i64, base, offset) catch return fail(.OVERFLOW);
    if (pos < 0) return fail(.INVAL);
    h.pos = @intCast(pos);
    // A directory's position is the number of entries passed, which is
    // what `getdents64` gives as `d_off`. At 0 (`rewinddir`) the listing
    // starts again, in a newly drawn order.
    if (node.kind == .dir) {
        if (pos == 0) h.list = @splat(0) else h.list[0] = std.math.cast(u32, pos) orelse return fail(.INVAL);
    }
    return @intCast(pos);
}

/// `fsync`, or `fdatasync` with `data_only`.
fn fsync(s: *Sim, fd: i32, data_only: bool) u64 {
    if (fd == root_fd) {
        // The root has no handle of its own: one is opened for the sync.
        const io = s.io();
        const root = Sim.rootDir().openFile(io, ".", .{}) catch |err| return fail(errnoOf(err));
        defer root.close(io);
        root.sync(io) catch |err| return fail(errnoOf(err));
        return 0;
    }
    if (handleOf(s, fd) == null) return fail(.BADF);
    // Stored into a mapping is in the file, and the sync keeps it; a
    // store that could not be written (the disk full) fails the sync.
    if (backingFor(s, fd)) |b| if (syncOut(s, b)) |e| return fail(e);
    if (data_only) {
        s.fileDataSync(fileOf(fd)) catch |err| return fail(errnoOf(err));
    } else {
        fileOf(fd).sync(s.io()) catch |err| return fail(errnoOf(err));
    }
    return 0;
}

fn ftruncate(s: *Sim, fd: i32, len: u64) u64 {
    const h = handleOf(s, fd) orelse return fail(.BADF);
    if (@as(i64, @bitCast(len)) < 0) return fail(.INVAL);
    if (!h.writable or s.vfs.inodes[h.inode].kind != .file) return fail(.INVAL);
    if (backingFor(s, fd)) |m| _ = syncOut(s, m);
    fileOf(fd).setLength(s.io(), len) catch |err| return fail(errnoOf(err));
    // Looked up again: the call may have let another task map the file.
    resizeNode(s);
    return 0;
}

fn truncate(s: *Sim, path_ptr: u64, len: u64) ?u64 {
    const path = cstr(path_ptr) orelse return fail(.FAULT);
    if (@as(i64, @bitCast(len)) < 0) return fail(.INVAL);
    if (hostPath(path)) return null;
    const io = s.io();
    const f = Sim.rootDir().openFile(io, path, .{ .mode = .write_only, .allow_directory = false }) catch |err| return fail(errnoOf(err));
    defer f.close(io);
    if (backingFor(s, @bitCast(@as(u32, @bitCast(@as(i32, f.handle))) | fd_bit))) |m| _ = syncOut(s, m);
    f.setLength(io, len) catch |err| return fail(errnoOf(err));
    resizeNode(s);
    return 0;
}

// --- file mappings ------------------------------------------------------------------
//
// `mmap` of a simulated file, `MAP_SHARED` or `MAP_PRIVATE`. The kernel
// has no such file, so the harness makes one it has: a memory file
// (`memfd_create`) per mapped simulated file, holding its bytes, and maps
// that where the code asked, with the code's own address, protection,
// flags and offset. Every mapping of one file is of the one memory file,
// so a store through one is seen through another at once, and a private
// mapping sees the file until it writes to a page, as on Linux. The
// memory file is as long as the simulated file, to whole pages: a page
// wholly past the end raises `SIGBUS`, as on Linux. A mapped file is
// kept (`open_count`) while its memory file is, as a mapping keeps an
// inode on Linux: its number is not given to another file.
//
// The simulated file stays the one the simulator writes, syncs and
// crashes. What was stored into a shared mapping reaches it (`syncOut`)
// before a read, a write, a truncation or a sync of the file by system
// call, at `msync` of a range that maps it, and before a crash that only
// ends the process (`beforeCrash`: the page cache survives it). A power
// loss loses what no sync wrote, as a power loss loses dirty pages.
// Bytes written by system call reach the mappings (`syncIn`, wherever the
// write landed, an appending one at the end), and so does a change of
// length; bytes stored past the end of the file read as zeros once the
// file grows over them, as on Linux.
//
// Divergences: the test's own reads and writes through `env.dir` and
// `env.io` of a mapped file are not carried over either way (a write
// there is undone by the next carrying over: write a mapped file by
// system call); Linux writes dirty pages back on its own, and here only
// those calls do, so a power loss keeps no stored byte that no call
// carried over and synced; what is carried over is written to the model
// directly, with no trace event and no fault injected (the `fsync` after
// it is faulted as usual, and a write that fails there, the disk full,
// fails that `fsync` or `msync`); `munmap` carries nothing over (the
// memory file keeps the bytes, and the next of those calls carries
// them); a mapped file is kept until the run ends or its node crashes,
// though Linux lets it go at the last `munmap`; mappings the code never
// unmapped stay in the process when its run ends. At most
// `backings_max` mapped files at once and `mappings_max` mappings
// remembered for `msync`. `mremap`, `madvise` and `mprotect` of a mapping
// are the kernel's, on the memory file.

const page = vfs_mod.page_bytes;
const prot_write = 0x2;
const map_type_mask = 0x3;
const map_shared = 0x1;
const map_shared_validate = 0x3;

/// A simulated file that is mapped, and the memory file that holds it.
const Backing = struct {
    used: bool = false,
    node: u16 = 0,
    inode: vfs_mod.InodeId = 0,
    memfd: u64 = 0,
    /// The memory file's length.
    size: u64 = 0,
    /// The simulated file's length when the memory file last took it.
    len: u64 = 0,
};
const backings_max = 16;
threadlocal var backings: [backings_max]Backing = @splat(.{});

/// A shared mapping the code made, for `msync` to find its file by.
const Mapping = struct { used: bool = false, backing: u8 = 0, addr: u64 = 0, len: u64 = 0 };
const mappings_max = 64;
threadlocal var mappings: [mappings_max]Mapping = @splat(.{});

fn real(number: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) u64 {
    return syscalls.rawUntrapped(number, a, b, c, d, e, f);
}

fn failed(rc: u64) bool {
    return @as(i64, @bitCast(rc)) < 0;
}

/// The memory files of a node (null: of all), closed. The mappings of a
/// process that is gone, or of a run that is over, are left: the code
/// that made them has ended, and an address it may have unmapped and
/// the allocator reused is not the harness's to unmap.
fn dropBackings(node: ?u16) void {
    for (&backings, 0..) |*b, i| {
        if (!b.used or (node != null and b.node != node.?)) continue;
        _ = real(3, b.memfd, 0, 0, 0, 0, 0);
        b.* = .{};
        for (&mappings) |*m| {
            if (m.used and m.backing == i) m.* = .{};
        }
    }
}

/// The node's file system a backing's file is on.
fn vfsOf(s: *Sim, b: *const Backing) *vfs_mod.Vfs {
    return &s.nodes[b.node].vfs;
}

fn backingOf(node: u16, inode: vfs_mod.InodeId) ?*Backing {
    for (&backings) |*b| if (b.used and b.node == node and b.inode == inode) return b;
    return null;
}

/// The backing of the file a descriptor is open on, if it is mapped.
fn backingFor(s: *Sim, fd: i32) ?*Backing {
    const h = handleOf(s, fd) orelse return null;
    return backingOf(s.currentNode(), h.inode);
}

fn wholePages(n: u64) u64 {
    return std.mem.alignForward(u64, n, page);
}

/// What was stored into the mappings, written to the simulated file: the
/// pages that differ, up to the file's length (a store past it is lost,
/// as on Linux). The error of a write that failed (the disk full), for
/// `fsync` and `msync` to report.
fn syncOut(s: *Sim, b: *Backing) ?E {
    const v = vfsOf(s, b);
    const len = v.inodes[b.inode].cur_len_bytes;
    var mem: [page]u8 = undefined;
    var file: [page]u8 = undefined;
    var off: u64 = 0;
    while (off < len and off < b.size) : (off += page) {
        const n: usize = @intCast(@min(page, len - off, b.size - off));
        if (failed(real(17, b.memfd, @intFromPtr(&mem), n, off, 0, 0))) return .IO;
        _ = v.read(b.inode, off, file[0..n]);
        if (std.mem.eql(u8, mem[0..n], file[0..n])) continue;
        const wrote = v.write(b.inode, off, mem[0..n]) catch |err| return errnoOf(err);
        if (wrote < n) return .NOSPC;
    }
    return null;
}

/// The memory file made as long as the simulated file, to whole pages,
/// with zeros past its end: past the old end too, where a store past the
/// end may have left bytes that the file, grown over them, reads as zeros.
fn resize(s: *Sim, b: *Backing) void {
    const v = vfsOf(s, b);
    const len = v.inodes[b.inode].cur_len_bytes;
    const zeros: [page]u8 = @splat(0);
    if (len > b.len and b.len < b.size) {
        _ = real(18, b.memfd, @intFromPtr(&zeros), @min(b.size, len) - b.len, b.len, 0, 0);
    }
    const size = wholePages(len);
    if (size != b.size) {
        _ = real(77, b.memfd, size, 0, 0, 0, 0); // ftruncate
        b.size = size;
    }
    if (len < size) _ = real(18, b.memfd, @intFromPtr(&zeros), size - len, len, 0, 0);
    b.len = len;
}

/// Bytes `off`..`off + n` of the simulated file, copied into the memory
/// file, after its length is brought up to date.
fn syncIn(s: *Sim, b: *Backing, off: u64, n: u64) void {
    resize(s, b);
    const v = vfsOf(s, b);
    var buf: [page]u8 = undefined;
    var at = off;
    const end = @min(off +| n, v.inodes[b.inode].cur_len_bytes);
    while (at < end) {
        const k: usize = @intCast(@min(page, end - at));
        const got = v.read(b.inode, at, buf[0..k]);
        if (got == 0) break;
        _ = real(18, b.memfd, @intFromPtr(&buf), got, at, 0, 0); // pwrite64
        at += got;
    }
}

/// After a write of `n` bytes through descriptor `fd` (at `offset`, or at
/// its position): the mappings see them where they landed. The backing
/// is looked up now, after the write, which may have let another task
/// map the file meanwhile.
fn afterWrite(s: *Sim, fd: i32, offset: ?u64, n: u64) void {
    const h = handleOf(s, fd) orelse return;
    const b = backingOf(s.currentNode(), h.inode) orelse return;
    // An appending descriptor writes at the end whatever the offset, and
    // a streaming write leaves the position just past what it wrote.
    const end: u64 = if (h.append) vfsOf(s, b).inodes[b.inode].cur_len_bytes else if (offset) |at| at + n else h.pos;
    syncIn(s, b, end -| n, n);
}

/// After a truncation: every mapped file of the node takes its length
/// again (the truncated one among them).
fn resizeNode(s: *Sim) void {
    const node = s.currentNode();
    for (&backings) |*b| if (b.used and b.node == node) resize(s, b);
}

/// A crash is coming. One that only ends the process (`process_crash`)
/// leaves the page cache, and what was stored into a shared mapping with
/// it: it reaches the file first. A power loss loses it. Either way the
/// mappings' hold on their files goes with the process, before the crash
/// closes the file system's handles.
pub fn beforeCrash(s: *Sim, node: ?u16, mode: Sim.CrashMode) void {
    for (&backings) |*b| {
        if (!b.used or (node != null and b.node != node.?)) continue;
        if (mode == .process_crash) _ = syncOut(s, b);
        vfsOf(s, b).inodes[b.inode].open_count -= 1;
    }
    dropBackings(node);
}

/// `mmap` of a simulated file.
fn mapFile(s: *Sim, a: *const [6]u64) ?u64 {
    const fd = resolve(s, fdOf(a[4]));
    if (!simulated(fd) or fd == random_fd) return null;
    if (fd == root_fd) return fail(.NODEV);
    const h = handleOf(s, fd) orelse return fail(.BADF);
    if (s.vfs.inodes[h.inode].kind != .file) return fail(.NODEV);
    const prot = a[2];
    const flags = a[3];
    const shared = flags & map_type_mask == map_shared or flags & map_type_mask == map_shared_validate;
    // As Linux: the file must be open for reading, and for writing too if
    // a shared mapping may be written, and not for appending then.
    if (!h.readable) return fail(.ACCES);
    if (shared and prot & prot_write != 0 and (!h.writable or h.append)) return fail(.ACCES);
    const node = s.currentNode();
    var made = false;
    const b = backingOf(node, h.inode) orelse blk: {
        const slot = for (&backings) |*b| {
            if (!b.used) break b;
        } else return null;
        const memfd = real(319, @intFromPtr("tardis-map"), 1, 0, 0, 0, 0); // memfd_create, MFD_CLOEXEC
        if (failed(memfd)) return memfd;
        slot.* = .{ .used = true, .node = node, .inode = h.inode, .memfd = memfd };
        syncIn(s, slot, 0, s.vfs.inodes[h.inode].cur_len_bytes);
        made = true;
        break :blk slot;
    };
    const rc = real(9, a[0], a[1], prot, flags, b.memfd, a[5]);
    if (failed(rc)) {
        if (made) {
            _ = real(3, b.memfd, 0, 0, 0, 0, 0);
            b.* = .{};
        }
        return rc;
    }
    // The file is kept while it is mapped.
    if (made) s.vfs.inodes[h.inode].open_count += 1;
    const index: u8 = @intCast((@intFromPtr(b) - @intFromPtr(&backings)) / @sizeOf(Backing));
    // A new mapping replaces what an old one at its addresses was.
    for (&mappings) |*m| {
        if (m.used and m.addr < rc + a[1] and rc < m.addr + m.len) m.* = .{};
    }
    if (shared) for (&mappings) |*m| if (!m.used) {
        m.* = .{ .used = true, .backing = index, .addr = rc, .len = a[1] };
        break;
    };
    return rc;
}

/// `msync`: the kernel checks the range; what was stored into the files
/// mapped shared in it then reaches them, and `MS_SYNC` makes it durable.
fn msync(s: *Sim, addr: u64, len: u64, flags: u32) u64 {
    const rc = real(26, addr, len, flags, 0, 0, 0);
    if (failed(rc)) return rc;
    var done: [backings_max]bool = @splat(false);
    for (mappings) |m| {
        if (!m.used or done[m.backing] or !(m.addr < addr + len and addr < m.addr + m.len)) continue;
        done[m.backing] = true;
        const b = &backings[m.backing];
        if (syncOut(s, b)) |e| return fail(e);
        if (flags & 4 != 0) vfsOf(s, b).dataSync(b.inode); // MS_SYNC
    }
    return 0;
}

/// `F_GETFD`, `F_SETFD`, `F_GETFL`, `F_SETFL` (the append flag), and the
/// record locks, every one of which is granted: POSIX record locks belong
/// to the process, so within one process they never conflict.
fn fcntl(s: *Sim, fd: i32, cmd: u32, arg: u64) ?u64 {
    // F_DUPFD, F_DUPFD_CLOEXEC; of the root descriptor, a stray, as `dup`.
    if (cmd == 0 or cmd == 1030) return duplicate(s, fd);
    const h = handleOf(s, fd) orelse return fail(.BADF);
    switch (cmd) {
        1 => return 1, // F_GETFD: close-on-exec, which no simulated descriptor outlives
        2 => return 0, // F_SETFD
        3 => { // F_GETFL
            var flags: u64 = if (h.readable and h.writable) 2 else if (h.writable) 1 else 0;
            if (h.append) flags |= o_append;
            return flags | 0o100000; // O_LARGEFILE
        },
        4 => { // F_SETFL
            h.append = arg & o_append != 0;
            return 0;
        },
        36, 37, 38 => return ofdLock(s, fd, cmd, arg), // F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW
        5 => { // F_GETLK: nothing would block
            if (arg == 0) return fail(.FAULT);
            @as(*align(1) u16, @ptrFromInt(arg)).* = 2; // l_type = F_UNLCK
            return 0;
        },
        6, 7 => return if (arg == 0) fail(.FAULT) else 0, // F_SETLK, F_SETLKW: one process never conflicts with itself
        else => return fail(.INVAL),
    }
}

// --- open-file-description locks --------------------------------------------------

/// `struct flock`.
const Flock = extern struct {
    type: i16,
    whence: i16,
    start: i64,
    len: i64,
    pid: i32,
};

const f_rdlck = 0;
const f_wrlck = 1;
const f_unlck = 2;

/// Locked ranges, over all nodes.
const ofd_max = 128;
/// To the end of the file, however long it gets.
const to_end = std.math.maxInt(u64);

/// A range one open file description holds locked.
const Range = struct {
    used: bool = false,
    node: u16 = 0,
    /// The handle: its open file description. A `dup` shares it.
    value: u32 = 0,
    inode: vfs_mod.InodeId = 0,
    start: u64 = 0,
    /// Exclusive; `to_end` for a lock with no end.
    end: u64 = 0,
    write: bool = false,
    /// A `flock` lock, of the whole file: Linux keeps those apart from
    /// the byte-range locks, and neither kind is in the other's way.
    flock: bool = false,

    /// Its open file is still open (closing the last descriptor, or a
    /// crash, frees it: `dropLocks`, `dropNode`).
    fn live(r: Range) bool {
        return r.used;
    }

    fn overlaps(r: Range, start: u64, end: u64) bool {
        return r.start < end and start < r.end;
    }
};

threadlocal var ranges: [ofd_max]Range = @splat(.{});

/// A task in `F_OFD_SETLKW`: the open file it locks through. A handle
/// value is reused by the next open once its file is closed, so the
/// close is noted here, where the waiter finds it.
const Waiter = struct { used: bool = false, node: u16 = 0, value: u32 = 0, closed: bool = false };
const waiters_max = 64;
threadlocal var waiters: [waiters_max]Waiter = @splat(.{});

/// Frees the ranges an open file held; true if there were any.
fn dropLocks(node: u16, value: u32) bool {
    var any = false;
    for (&ranges) |*r| {
        if (r.live() and r.node == node and r.value == value) {
            r.* = .{};
            any = true;
        }
    }
    return any;
}

/// The first range another open file holds on `inode` that a lock of this
/// kind over `start`..`end` would conflict with: a `flock` lock only
/// with another, a byte-range lock only with another.
fn conflict(node: u16, value: u32, inode: vfs_mod.InodeId, start: u64, end: u64, exclusive: bool, whole_file: bool) ?*const Range {
    for (&ranges) |*r| {
        if (!r.live() or r.node != node or r.inode != inode or r.value == value or r.flock != whole_file) continue;
        if (!(exclusive or r.write)) continue;
        if (r.overlaps(start, end)) return r;
    }
    return null;
}

/// `F_OFD_GETLK`, `F_OFD_SETLK`, `F_OFD_SETLKW`.
fn ofdLock(s: *Sim, fd: i32, cmd: u32, arg: u64) u64 {
    if (arg == 0) return fail(.FAULT);
    const fl: *align(1) Flock = @ptrFromInt(arg);
    // Linux insists on 0: an open file has no process.
    if (fl.pid != 0) return fail(.INVAL);
    if (fl.type != f_rdlck and fl.type != f_wrlck and fl.type != f_unlck) return fail(.INVAL);
    if (cmd == 36 and fl.type == f_unlck) return fail(.INVAL);
    const h = handleOf(s, fd) orelse return fail(.BADF);
    const node = s.currentNode();
    const value = valueOf(fd);
    const inode = h.inode;
    // The range, from where `l_whence` says.
    const base: i64 = switch (fl.whence) {
        0 => 0, // SEEK_SET
        1 => @intCast(h.pos), // SEEK_CUR
        2 => @intCast(s.vfs.inodes[inode].cur_len_bytes), // SEEK_END
        else => return fail(.INVAL),
    };
    // As Linux's `flock_to_posix_lock`: a range that starts before the
    // file is `EINVAL`, and one whose last byte is past the largest offset
    // `EOVERFLOW`.
    const first = std.math.add(i64, base, fl.start) catch return fail(.OVERFLOW);
    if (first < 0) return fail(.INVAL);
    var lo: u64 = @intCast(first);
    var end: u64 = to_end;
    if (fl.len > 0) {
        const last = std.math.add(i64, first, fl.len - 1) catch return fail(.OVERFLOW);
        end = @as(u64, @intCast(last)) + 1;
    } else if (fl.len < 0) {
        const from = first + fl.len; // no overflow: `first` is not negative
        if (from < 0) return fail(.INVAL);
        lo = @intCast(from);
        end = @intCast(first);
    }
    if (cmd == 36) { // F_OFD_GETLK: what would be in the way, if anything
        const r = conflict(node, value, inode, lo, end, fl.type == f_wrlck, false) orelse {
            fl.type = f_unlck;
            return 0;
        };
        fl.type = if (r.write) f_wrlck else f_rdlck;
        fl.whence = 0;
        fl.start = @intCast(r.start);
        fl.len = if (r.end == to_end) 0 else @intCast(r.end - r.start);
        fl.pid = -1;
        return 0;
    }
    const exclusive = fl.type == f_wrlck;
    if (fl.type == f_rdlck and !h.readable) return fail(.BADF);
    if (exclusive and !h.writable) return fail(.BADF);
    if (fl.type != f_unlck and conflict(node, value, inode, lo, end, exclusive, false) != null) {
        if (cmd == 37) return fail(.AGAIN);
        const w = for (&waiters) |*w| {
            if (!w.used) break w;
        } else return fail(.NOLCK);
        w.* = .{ .used = true, .node = node, .value = value };
        defer w.* = .{};
        while (conflict(node, value, inode, lo, end, exclusive, false) != null) {
            s.waitNetwork(null) catch return fail(.INTR);
            // Its file was closed by another task meanwhile: Linux's call
            // holds the file it began with, takes the lock on it, and the
            // lock goes with that file at once. Nothing is held.
            if (w.closed) return 0;
        }
    }
    return if (setRange(node, value, inode, lo, end, fl.type)) |e| fail(e) else blk: {
        s.wakeNetwork();
        break :blk 0;
    };
}

/// This open file's locks over `start`..`end` become `kind` (`f_unlck`
/// removes them), splitting a range it held around them, and joining
/// the new one with a range of the same kind it touches, as Linux does.
/// Nothing changes when there is no room for the result (`ENOLCK`).
fn setRange(node: u16, value: u32, inode: vfs_mod.InodeId, start: u64, end: u64, kind: i16) ?E {
    var need: usize = if (kind == f_unlck) 0 else 1;
    var free: usize = 0;
    for (ranges) |r| {
        if (!r.live()) {
            free += 1;
            continue;
        }
        if (r.node != node or r.value != value or r.inode != inode or r.flock) continue;
        // One that goes past both ends is left in two pieces; one inside
        // the range is freed.
        if (r.start < start and r.end > end) need += 1;
        if (r.start >= start and r.end <= end) free += 1;
    }
    if (need > free) return .NOLCK;
    var tail: ?Range = null;
    for (&ranges) |*r| {
        if (!r.live() or r.node != node or r.value != value or r.inode != inode or r.flock or !r.overlaps(start, end)) continue;
        if (r.start < start and r.end > end) {
            tail = r.*;
            tail.?.start = end;
            r.end = start;
        } else if (r.start < start) {
            r.end = start;
        } else if (r.end > end) {
            r.start = end;
        } else {
            r.* = .{};
        }
    }
    if (tail) |t| put(t);
    if (kind == f_unlck) return null;
    // Neighbours of the same kind, which now end where it starts or start
    // where it ends, become part of it.
    var lo = start;
    var hi = end;
    for (&ranges) |*r| {
        if (!r.live() or r.node != node or r.value != value or r.inode != inode or r.flock or r.write != (kind == f_wrlck)) continue;
        if (r.end == start) {
            lo = r.start;
            r.* = .{};
        } else if (r.start == end) {
            hi = r.end;
            r.* = .{};
        }
    }
    put(.{ .used = true, .node = node, .value = value, .inode = inode, .start = lo, .end = hi, .write = kind == f_wrlck });
    return null;
}

const lock_sh = 1;
const lock_ex = 2;
const lock_nb = 4;
const lock_un = 8;
const lock_mand = 32;

/// `flock`: a lock of the whole file, shared or exclusive, held by the
/// open file, as Linux's. A change between shared and exclusive gives up
/// the lock held first, then takes the other, as Linux's does (so a
/// change that would wait, asked not to, leaves nothing held).
fn flock(s: *Sim, fd: i32, operation: u64) u64 {
    const op: u32 = @truncate(operation);
    // Linux ignores `LOCK_MAND` (it once meant mandatory locking), before
    // it looks at the descriptor.
    if (op & lock_mand != 0) return 0;
    const kind = op & ~@as(u32, lock_nb);
    if (kind != lock_sh and kind != lock_ex and kind != lock_un) return fail(.INVAL);
    const h = handleOf(s, fd) orelse return fail(.BADF);
    const node = s.currentNode();
    const value = valueOf(fd);
    const inode = h.inode;
    const exclusive = kind == lock_ex;
    // Set when the call has waited: the waiter it is.
    var waiter: ?*Waiter = null;
    defer if (waiter) |w| {
        w.* = .{};
    };
    // As Linux's, whose every try looks again at what the open file
    // holds: another task may have locked through it while this one
    // waited.
    while (true) {
        // What this open file holds now: one lock at most.
        for (&ranges) |*r| {
            if (!r.live() or !r.flock or r.node != node or r.value != value) continue;
            if (kind != lock_un and r.write == exclusive) return 0;
            r.* = .{};
            s.wakeNetwork();
            break;
        }
        if (kind == lock_un) return 0;
        if (conflict(node, value, inode, 0, to_end, exclusive, true) == null) break;
        if (op & lock_nb != 0) return fail(.AGAIN);
        const w = waiter orelse for (&waiters) |*w| {
            if (w.used) continue;
            w.* = .{ .used = true, .node = node, .value = value };
            waiter = w;
            break w;
        } else return fail(.NOLCK);
        // Closed by another task meanwhile: Linux's call holds the file
        // it began with, waits on, takes the lock once it is free, and
        // the lock goes with the file as the call ends. Nothing is held.
        if (w.closed) {
            while (conflict(node, value, inode, 0, to_end, exclusive, true) != null) {
                s.waitNetwork(null) catch return fail(.INTR);
            }
            return 0;
        }
        s.waitNetwork(null) catch return fail(.INTR);
    }
    for (&ranges) |*r| if (!r.live()) {
        r.* = .{ .used = true, .node = node, .value = value, .inode = inode, .start = 0, .end = to_end, .write = exclusive, .flock = true };
        return 0;
    };
    return fail(.NOLCK);
}

fn put(r: Range) void {
    for (&ranges) |*slot| if (!slot.live()) {
        slot.* = r;
        return;
    };
    unreachable; // counted by `setRange`
}

// --- names -------------------------------------------------------------------

/// `link` and `linkat`: a second name for a file, through the simulator's
/// hard link, which a crash treats as it treats any change of names.
/// `AT_SYMLINK_FOLLOW` links what a symbolic link points to;
/// `AT_EMPTY_PATH` links the file a descriptor is open on.
fn link(s: *Sim, old_fd: i32, old_ptr: u64, new_fd: i32, new_ptr: u64, flags: u32) ?u64 {
    const at_symlink_follow = 0x400;
    if (flags & ~@as(u32, at_symlink_follow | at_empty_path) != 0) return fail(.INVAL);
    const old = cstr(old_ptr) orelse return fail(.FAULT);
    const new = cstr(new_ptr) orelse return fail(.FAULT);
    const new_dir = switch (dirOf(s, new_fd, new)) {
        .dir => |d| d,
        .closed => return fail(.BADF),
        .foreign => return null,
    };
    const io = s.io();
    if (old.len == 0) {
        if (flags & at_empty_path == 0) return fail(.NOENT);
        if (old_fd == at_fdcwd or old_fd == root_fd) return fail(.PERM); // a directory
        if (!simulated(old_fd) or old_fd == random_fd) return null;
        const h = handleOf(s, old_fd) orelse return fail(.BADF);
        if (s.vfs.inodes[h.inode].kind == .dir) return fail(.PERM);
        // A file with no name left stays without one (Linux: unless it
        // was made with `O_TMPFILE`, which is not emulated).
        if (s.vfs.inodes[h.inode].cur_links == 0) return fail(.NOENT);
        fileOf(old_fd).hardLink(io, new_dir, new, .{}) catch |err| return fail(errnoOf(err));
        return 0;
    }
    const old_dir = switch (dirOf(s, old_fd, old)) {
        .dir => |d| d,
        .closed => return fail(.BADF),
        .foreign => return null,
    };
    old_dir.hardLink(old, new_dir, new, io, .{ .follow_symlinks = flags & at_symlink_follow != 0 }) catch |err| return fail(errnoOf(err));
    return 0;
}

fn rename(s: *Sim, old_fd: i32, old_ptr: u64, new_fd: i32, new_ptr: u64, flags: u32) ?u64 {
    const old = cstr(old_ptr) orelse return fail(.FAULT);
    const new = cstr(new_ptr) orelse return fail(.FAULT);
    const old_dir = switch (dirOf(s, old_fd, old)) {
        .dir => |d| d,
        .closed => return fail(.BADF),
        .foreign => return null,
    };
    const new_dir = switch (dirOf(s, new_fd, new)) {
        .dir => |d| d,
        .closed => return fail(.BADF),
        .foreign => return null,
    };
    const io = s.io();
    switch (flags) {
        0 => old_dir.rename(old, new_dir, new, io) catch |err| return fail(errnoOf(err)),
        1 => old_dir.renamePreserve(old, new_dir, new, io) catch |err| return fail(errnoOf(err)), // RENAME_NOREPLACE
        else => return fail(.INVAL),
    }
    return 0;
}

fn unlink(s: *Sim, dirfd: i32, path_ptr: u64, flags: u32) ?u64 {
    const path = cstr(path_ptr) orelse return fail(.FAULT);
    const dir = switch (dirOf(s, dirfd, path)) {
        .dir => |d| d,
        .closed => return fail(.BADF),
        .foreign => return null,
    };
    if (flags & ~@as(u32, at_removedir) != 0) return fail(.INVAL);
    if (flags & at_removedir != 0) {
        dir.deleteDir(s.io(), path) catch |err| return fail(errnoOf(err));
    } else {
        dir.deleteFile(s.io(), path) catch |err| return fail(errnoOf(err));
    }
    return 0;
}

fn mkdir(s: *Sim, dirfd: i32, path_ptr: u64) ?u64 {
    const path = cstr(path_ptr) orelse return fail(.FAULT);
    const dir = switch (dirOf(s, dirfd, path)) {
        .dir => |d| d,
        .closed => return fail(.BADF),
        .foreign => return null,
    };
    dir.createDir(s.io(), path, .default_dir) catch |err| return fail(errnoOf(err));
    return 0;
}

/// Whether the path names something. Permission bits are not modelled, so
/// the mode asked about is not looked at.
fn access(s: *Sim, dirfd: i32, path_ptr: u64) ?u64 {
    const path = cstr(path_ptr) orelse return fail(.FAULT);
    const dir = switch (dirOf(s, dirfd, path)) {
        .dir => |d| d,
        .closed => return fail(.BADF),
        .foreign => return null,
    };
    // Through a stat: `std.Io`'s `access` has no "not a directory", and
    // the kernel's has (found by the differential test).
    _ = dir.statFile(s.io(), path, .{}) catch |err| return fail(errnoOf(err));
    return 0;
}

// --- links read ----------------------------------------------------------------

/// `readlink` and `readlinkat`. Of `/proc/self/fd/N` (or
/// `/proc/thread-self/fd/N`) for a simulated descriptor: the path of what
/// it is open on, from the node's root, as Linux gives it; std's
/// `realPathFile` opens the file and reads this link. Of a simulated
/// path: the target of the symbolic link there (`EINVAL` for anything
/// else). As the kernel's: no terminating zero, and cut to the buffer.
/// Any other `/proc` link, `/proc/self/exe` among them, and the link of a
/// pipe, a socket or a descriptor of the host, is a stray.
fn readlink(s: *Sim, dirfd: i32, path_ptr: u64, buf_ptr: u64, len: u64) ?u64 {
    // The kernel's size is an `int`, checked before the path.
    const size: i32 = @bitCast(@as(u32, @truncate(len)));
    if (size <= 0) return fail(.INVAL);
    const path = cstr(path_ptr) orelse return fail(.FAULT);
    if (path.len == 0) return fail(.NOENT);
    var text: [path_bytes_max]u8 = undefined;
    const answer: []const u8 = if (procFd(path)) |raw| switch (if (raw < 0) DescriptorPath{ .err = .NOENT } else descriptorPath(s, resolve(s, raw), &text)) {
        .path => |p| p,
        .err => |e| return fail(e),
        .foreign => return null,
    } else blk: {
        const dir = switch (dirOf(s, dirfd, path)) {
            .dir => |d| d,
            .closed => return fail(.BADF),
            .foreign => return null,
        };
        const n = dir.readLink(s.io(), path, &text) catch |err| return fail(errnoOf(err));
        break :blk text[0..n];
    };
    if (buf_ptr == 0) return fail(.FAULT);
    const k = @min(answer.len, @as(usize, @intCast(size)));
    @memcpy(@as([*]u8, @ptrFromInt(buf_ptr))[0..k], answer[0..k]);
    return k;
}

const path_bytes_max = 4096;

/// The descriptor a `/proc/self/fd/N` path names: digits only, with no
/// sign and no leading zero, as procfs names them; -1 for another name
/// in that directory, which is not there (`ENOENT`).
fn procFd(path: []const u8) ?i32 {
    const rest = for ([_][]const u8{ "/proc/self/fd/", "/proc/thread-self/fd/" }) |prefix| {
        if (std.mem.startsWith(u8, path, prefix)) break path[prefix.len..];
    } else return null;
    if (rest.len == 0) return null; // the directory itself: not answered
    if (rest[0] == '0' and rest.len > 1) return -1;
    for (rest) |c| if (!std.ascii.isDigit(c)) return -1;
    return std.fmt.parseInt(i32, rest, 10) catch -1;
}

const DescriptorPath = union(enum) { path: []const u8, err: E, foreign };

/// The path a simulated descriptor is open on, from the node's root,
/// written from the end of `buf` back. A file with several names gets one
/// of them; one with none left (deleted while open) gets Linux's
/// " (deleted)" after the root, as its name is gone with the entry.
fn descriptorPath(s: *Sim, fd: i32, buf: *[path_bytes_max]u8) DescriptorPath {
    if (fd == root_fd) return .{ .path = "/" };
    if (fd == random_fd) return .{ .path = "/dev/urandom" };
    if (sysfd.isFd(fd) or sysnet.isSocketFd(fd) or !simulated(fd)) return .foreign;
    const h = handleOf(s, fd) orelse return .{ .err = .NOENT };
    const v = s.vfs;
    var at: usize = buf.len;
    var ino = h.inode;
    while (ino != vfs_mod.root_inode) {
        const d = for (v.cur_dentries[0..v.cur_hwm]) |*d| {
            if (d.used and d.inode == ino) break d;
        } else return .{ .path = "/ (deleted)" };
        // Each name with its slash; a longer path (or a cycle) is too long.
        if (d.name_len + 1 > at) return .{ .err = .NAMETOOLONG };
        at -= d.name_len;
        @memcpy(buf[at..][0..d.name_len], d.name[0..d.name_len]);
        at -= 1;
        buf[at] = '/';
        ino = d.parent;
    }
    if (at == buf.len) return .{ .path = "/" };
    return .{ .path = buf[at..] };
}

/// The working directory is the root of the node's filesystem.
fn getcwd(buf_ptr: u64, len: u64) u64 {
    if (buf_ptr == 0) return fail(.FAULT);
    if (len < 2) return fail(.RANGE);
    const buf: [*]u8 = @ptrFromInt(buf_ptr);
    buf[0] = '/';
    buf[1] = 0;
    return 2;
}

/// `uname`: the same machine everywhere, so that what a program prints
/// or decides from it does not depend on where the test runs. Six fields
/// of 65 bytes: system, node, release, version, machine, domain. glibc
/// asks for the domain when it looks a host name up.
fn uname(buf_ptr: u64) u64 {
    if (buf_ptr == 0) return fail(.FAULT);
    const buf: *[6 * 65]u8 = @ptrFromInt(buf_ptr);
    @memset(buf, 0);
    const texts = [6][]const u8{ "Linux", "tardis", "6.1.0", "#1 SMP", "x86_64", "(none)" };
    for (texts, 0..) |field, i| @memcpy(buf[i * 65 ..][0..field.len], field);
    return 0;
}

// --- stat ----------------------------------------------------------------------

/// Every file belongs to this user and group, who is also the caller.
const owner_id = 1000;

/// x86_64 `struct stat`, as the kernel fills it.
const KernelStat = extern struct {
    dev: u64,
    ino: u64,
    nlink: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    pad0: u32 = 0,
    rdev: u64 = 0,
    size: i64,
    blksize: i64,
    blocks: i64,
    atime: [2]i64,
    mtime: [2]i64,
    ctime: [2]i64,
    unused: [3]i64 = @splat(0),
};

const StatxTime = extern struct { sec: i64, nsec: u32, pad: i32 = 0 };

const KernelStatx = extern struct {
    mask: u32,
    blksize: u32,
    attributes: u64 = 0,
    nlink: u32,
    uid: u32,
    gid: u32,
    mode: u16,
    spare0: u16 = 0,
    ino: u64,
    size: u64,
    blocks: u64,
    attributes_mask: u64 = 0,
    atime: StatxTime,
    btime: StatxTime,
    ctime: StatxTime,
    mtime: StatxTime,
    rdev_major: u32 = 0,
    rdev_minor: u32 = 0,
    dev_major: u32 = 0,
    dev_minor: u32,
    spare: [14]u64 = @splat(0),
};

comptime {
    std.debug.assert(@sizeOf(KernelStat) == 144);
    std.debug.assert(@sizeOf(KernelStatx) == 256);
}

/// The device number of every simulated filesystem.
const device = 0x7a;

const Fields = struct { mode: u32, blocks: u64, sec: i64, nsec: u32 };

fn fields(st: *const Io.File.Stat) Fields {
    const ns: i128 = st.mtime.nanoseconds;
    return .{
        .mode = switch (st.kind) {
            .directory => 0o040755,
            .sym_link => 0o120777,
            else => 0o100644,
        },
        .blocks = std.mem.alignForward(u64, st.size, vfs_mod.page_bytes) / 512,
        .sec = @intCast(@divFloor(ns, std.time.ns_per_s)),
        .nsec = @intCast(@mod(ns, std.time.ns_per_s)),
    };
}

fn putStat(st: *const Io.File.Stat, out_ptr: u64, comptime shape: enum { old, x }) u64 {
    if (out_ptr == 0) return fail(.FAULT);
    const f = fields(st);
    switch (shape) {
        .old => {
            const t: [2]i64 = .{ f.sec, f.nsec };
            @as(*align(1) KernelStat, @ptrFromInt(out_ptr)).* = .{
                .dev = device,
                .ino = st.inode,
                .nlink = st.nlink,
                .mode = f.mode,
                .uid = owner_id,
                .gid = owner_id,
                .size = @intCast(st.size),
                .blksize = vfs_mod.page_bytes,
                .blocks = @intCast(f.blocks),
                .atime = t,
                .mtime = t,
                .ctime = t,
            };
        },
        .x => {
            const t: StatxTime = .{ .sec = f.sec, .nsec = f.nsec };
            @as(*align(1) KernelStatx, @ptrFromInt(out_ptr)).* = .{
                .mask = 0xfff, // STATX_BASIC_STATS | STATX_BTIME
                .blksize = vfs_mod.page_bytes,
                .nlink = @intCast(st.nlink),
                .uid = owner_id,
                .gid = owner_id,
                .mode = @intCast(f.mode),
                .ino = st.inode,
                .size = st.size,
                .blocks = f.blocks,
                .atime = t,
                .btime = t,
                .ctime = t,
                .mtime = t,
                .dev_minor = device,
            };
        },
    }
    return 0;
}

fn fstat(s: *Sim, fd: i32, out_ptr: u64) u64 {
    return statFd(s, fd, out_ptr, .old);
}

fn statFd(s: *Sim, fd: i32, out_ptr: u64, comptime shape: anytype) u64 {
    const io = s.io();
    const st = if (fd == root_fd)
        Sim.rootDir().stat(io) catch |err| return fail(errnoOf(err))
    else if (handleOf(s, fd) != null)
        fileOf(fd).stat(io) catch |err| return fail(errnoOf(err))
    else
        return fail(.BADF);
    return putStat(&st, out_ptr, shape);
}

fn statPath(s: *Sim, dirfd: i32, path_ptr: u64, out_ptr: u64, flags: u32, comptime shape: anytype) ?u64 {
    const path = cstr(path_ptr) orelse return fail(.FAULT);
    if (path.len == 0) {
        if (flags & at_empty_path == 0) return fail(.NOENT);
        if (dirfd == at_fdcwd) return statFd(s, root_fd, out_ptr, shape);
        if (!simulated(dirfd)) return null;
        return statFd(s, dirfd, out_ptr, shape);
    }
    const dir = switch (dirOf(s, dirfd, path)) {
        .dir => |d| d,
        .closed => return fail(.BADF),
        .foreign => return null,
    };
    const st = dir.statFile(s.io(), path, .{ .follow_symlinks = flags & at_symlink_nofollow == 0 }) catch |err| return fail(errnoOf(err));
    return putStat(&st, out_ptr, shape);
}

// --- directory listing -------------------------------------------------------

/// `getdents64`: "." and "..", then the children in an order drawn per
/// listing, as `Dir.Reader` lists them (a real directory promises none).
fn getdents(s: *Sim, fd: i32, buf_ptr: u64, len: u64) u64 {
    const h = handleOf(s, fd) orelse return fail(.BADF);
    const dir_ino = h.inode;
    if (s.vfs.inodes[dir_ino].kind != .dir) return fail(.NOTDIR);
    // A directory removed while open lists as gone (differential test).
    if (dir_ino != vfs_mod.root_inode and s.vfs.inodes[dir_ino].cur_links == 0) return fail(.NOENT);
    if (buf_ptr == 0) return fail(.FAULT);
    const buf = @as([*]u8, @ptrFromInt(buf_ptr))[0..@min(len, rw_bytes_max)];
    const slots: u32 = @intCast(s.vfs.dentrySlots());
    // list[0]: entries passed, list[1]: first slot, list[2]: stride (0: not drawn).
    if (h.list[2] == 0) {
        var stride: u32 = @intCast(s.decider.range(.fault, 1, slots));
        while (std.math.gcd(stride, slots) != 1) stride += 1;
        h.list = .{ 0, @intCast(s.decider.uniform(.fault, slots)), stride };
    }
    const header = @offsetOf(linux.dirent64, "name");
    var used: usize = 0;
    while (h.list[0] < slots + 2) {
        const index = h.list[0];
        var name: []const u8 = undefined;
        var ino: u64 = undefined;
        var kind: vfs_mod.Kind = .dir;
        if (index == 0) {
            name = ".";
            ino = dir_ino;
        } else if (index == 1) {
            name = "..";
            ino = s.vfs.inodes[dir_ino].parent;
        } else {
            const slot = (h.list[1] + @as(u64, index - 2) * h.list[2]) % slots;
            const c = s.vfs.childAt(dir_ino, slot) orelse {
                h.list[0] += 1;
                continue;
            };
            name = c.name;
            ino = c.inode;
            kind = c.kind;
        }
        const reclen = std.mem.alignForward(usize, header + name.len + 1, 8);
        if (used + reclen > buf.len) {
            if (used == 0) return fail(.INVAL);
            break;
        }
        const entry = buf[used..][0..reclen];
        @memset(entry, 0);
        std.mem.writeInt(u64, entry[0..8], ino + 1, .little);
        std.mem.writeInt(u64, entry[8..16], index + 1, .little);
        std.mem.writeInt(u16, entry[16..18], @intCast(reclen), .little);
        entry[18] = switch (kind) {
            .dir => 4,
            .symlink => 10,
            else => 8,
        };
        @memcpy(entry[header..][0..name.len], name);
        used += reclen;
        h.list[0] += 1;
    }
    h.pos = h.list[0];
    return used;
}

// --- futexes -------------------------------------------------------------------

/// `futex`: the waits and wakes of a C library's locks and condition
/// variables. Every fiber runs on one thread, so a real wait would stop
/// the whole simulation (the task holding the lock could never run to
/// release it). Here a wait blocks only the calling task, on the
/// simulator's futex for that address, and a wake wakes simulated
/// waiters. A deadlock between C locks is then the simulator's reported
/// deadlock, not a hang.
///
/// Emulated: `FUTEX_WAIT`, `FUTEX_WAKE`, `FUTEX_WAIT_BITSET`,
/// `FUTEX_WAKE_BITSET`, `FUTEX_REQUEUE`, `FUTEX_CMP_REQUEUE`, private or
/// not, with `FUTEX_CLOCK_REALTIME`. A bitset is not compared and a
/// requeue wakes instead of moving: both only add wakeups, which every
/// futex caller must tolerate. Other operations (priority inheritance,
/// `FUTEX_WAKE_OP`) are not emulated.
fn futex(s: *Sim, a: *const [6]u64) ?u64 {
    const futex_private = 128;
    const futex_clock_realtime = 256;
    const op: u32 = @truncate(a[1]);
    const cmd = op & ~@as(u32, futex_private | futex_clock_realtime);
    if (a[0] % 4 != 0) return fail(.INVAL);
    const val: u32 = @truncate(a[2]);
    if (a[0] == 0) return switch (cmd) {
        0, 9, 4 => fail(.FAULT), // the kernel reads the word: it faults
        1, 10, 3 => 0, // a private wake looks for waiters and finds none
        else => null,
    };
    const ptr: *const u32 = @ptrFromInt(a[0]);
    return switch (cmd) {
        0, 9 => { // FUTEX_WAIT, FUTEX_WAIT_BITSET
            if (cmd == 9 and @as(u32, @truncate(a[5])) == 0) return fail(.INVAL);
            // WAIT: a relative time on the monotonic clock. WAIT_BITSET:
            // an absolute one, on the real clock if asked.
            const clock: Io.Clock = if (cmd == 9 and op & futex_clock_realtime != 0) .real else .awake;
            var deadline: ?i128 = null;
            if (a[3] != 0) {
                const t = @as(*align(1) const Timespec, @ptrFromInt(a[3])).*;
                if (t.sec < 0 or t.nsec < 0 or t.nsec >= std.time.ns_per_s) return fail(.INVAL);
                const ns: i128 = @as(i128, t.sec) * std.time.ns_per_s + t.nsec;
                deadline = if (cmd == 9) ns else nowNs(s, clock) + ns;
            }
            return futexWait(s, ptr, val, clock, deadline);
        },
        1, 10 => futexWake(s, ptr, val), // FUTEX_WAKE, FUTEX_WAKE_BITSET
        3, 4 => { // FUTEX_REQUEUE, FUTEX_CMP_REQUEUE
            if (cmd == 4 and @atomicLoad(u32, ptr, .seq_cst) != @as(u32, @truncate(a[5]))) return fail(.AGAIN);
            // The waiters it would move to the second address are woken.
            const more: u32 = @truncate(@min(a[3], std.math.maxInt(u32)));
            return futexWake(s, ptr, val +| more);
        },
        else => null,
    };
}

fn futexWait(s: *Sim, ptr: *const u32, val: u32, clock: Io.Clock, deadline: ?i128) u64 {
    if (@atomicLoad(u32, ptr, .seq_cst) != val) return fail(.AGAIN);
    var timeout: Io.Timeout = .none;
    if (deadline) |d| {
        if (nowNs(s, clock) >= d) return fail(.TIMEDOUT);
        timeout = .{ .deadline = .{ .raw = .{ .nanoseconds = @intCast(d) }, .clock = clock } };
    }
    // Timed out only if the deadline ended the wait: a waiter a wake
    // picked returns 0, as in the kernel, or the wake would be lost (a
    // timed lock that reports a timeout does not pass the wake on).
    return switch (s.futexWaitSyscall(ptr, val, timeout)) {
        .woken => 0,
        .timed_out => fail(.TIMEDOUT),
    };
}

/// Wakes up to `max` simulated waiters on `ptr`: the number woken.
fn futexWake(s: *Sim, ptr: *const u32, max: u32) u64 {
    if (max == 0) return 0;
    var waiting: u32 = 0;
    for (s.tasks) |*t| {
        if (t.state == .blocked and t.block == .futex and t.block.futex == @intFromPtr(ptr)) waiting += 1;
    }
    const io = s.io();
    io.vtable.futexWake(io.userdata, ptr, max);
    return @min(waiting, max);
}

// --- time and randomness -------------------------------------------------------

fn clockOf(id: u32) ?Io.Clock {
    return switch (id) {
        0, 5, 11 => .real, // REALTIME, REALTIME_COARSE, TAI
        1, 4, 6 => .awake, // MONOTONIC, MONOTONIC_RAW, MONOTONIC_COARSE
        7 => .boot,
        2 => .cpu_process,
        3 => .cpu_thread,
        else => null,
    };
}

fn nowNs(s: *Sim, clock: Io.Clock) i128 {
    return Io.Timestamp.now(s.io(), clock).nanoseconds;
}

const Timespec = extern struct { sec: i64, nsec: i64 };

fn clockGettime(s: *Sim, id: u32, out_ptr: u64) u64 {
    const clock = clockOf(id) orelse return fail(.INVAL);
    if (out_ptr == 0) return fail(.FAULT);
    const ns = nowNs(s, clock);
    @as(*align(1) Timespec, @ptrFromInt(out_ptr)).* = .{
        .sec = @intCast(@divFloor(ns, std.time.ns_per_s)),
        .nsec = @intCast(@mod(ns, std.time.ns_per_s)),
    };
    return 0;
}

fn clockGetres(out_ptr: u64) u64 {
    if (out_ptr != 0) @as(*align(1) Timespec, @ptrFromInt(out_ptr)).* = .{ .sec = 0, .nsec = 1 };
    return 0;
}

fn gettimeofday(s: *Sim, out_ptr: u64) u64 {
    if (out_ptr == 0) return 0;
    const ns = nowNs(s, .real);
    @as(*align(1) Timespec, @ptrFromInt(out_ptr)).* = .{
        .sec = @intCast(@divFloor(ns, std.time.ns_per_s)),
        .nsec = @intCast(@divFloor(@mod(ns, std.time.ns_per_s), 1000)), // microseconds
    };
    return 0;
}

fn time(s: *Sim, out_ptr: u64) u64 {
    const sec: i64 = @intCast(@divFloor(nowNs(s, .real), std.time.ns_per_s));
    if (out_ptr != 0) @as(*align(1) i64, @ptrFromInt(out_ptr)).* = sec;
    return @bitCast(sec);
}

/// `nanosleep` and `clock_nanosleep`: the fiber sleeps in virtual time and
/// other tasks run.
fn sleep(s: *Sim, clock_id: u32, flags: u32, req_ptr: u64, rem_ptr: u64) u64 {
    const clock = clockOf(clock_id) orelse return fail(.INVAL);
    if (clock == .cpu_thread) return fail(.INVAL);
    if (req_ptr == 0) return fail(.FAULT);
    const req = @as(*align(1) const Timespec, @ptrFromInt(req_ptr)).*;
    if (req.sec < 0 or req.nsec < 0 or req.nsec >= std.time.ns_per_s) return fail(.INVAL);
    const ns: i96 = @as(i96, req.sec) * std.time.ns_per_s + req.nsec;
    const absolute = flags & 1 != 0; // TIMER_ABSTIME
    const timeout: Io.Timeout = if (absolute)
        .{ .deadline = .{ .raw = .{ .nanoseconds = ns }, .clock = clock } }
    else
        .{ .duration = .{ .raw = .{ .nanoseconds = ns }, .clock = clock } };
    timeout.sleep(s.io()) catch {
        if (!absolute and rem_ptr != 0) @as(*align(1) Timespec, @ptrFromInt(rem_ptr)).* = .{ .sec = 0, .nsec = 0 };
        return fail(.INTR);
    };
    return 0;
}

fn getrandom(s: *Sim, buf_ptr: u64, len: u64) u64 {
    if (len == 0) return 0;
    const buf = userBytes(buf_ptr, @min(len, 1 << 25)) orelse return fail(.FAULT);
    s.io().random(buf);
    return buf.len;
}
