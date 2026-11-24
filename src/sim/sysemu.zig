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
//! `getdents64`, `getcwd`, `fcntl` (descriptor flags and record locks),
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
//! process), `O_NOFOLLOW`, `O_PATH`, `O_DIRECT`, `O_SYNC`. `O_TRUNC`
//! without `O_CREAT` is an open and then a truncation, two steps another
//! task can come between. A sleep that is canceled returns `EINTR` and the
//! cancellation is spent. `dup`, and `fcntl` with `F_DUPFD` or
//! `F_DUPFD_CLOEXEC`, give a file or a directory a second descriptor with
//! the same position and flags (`dups`, below), as they do a socket
//! (`sysnet.zig`) and a pipe, an eventfd or an epoll set (`sysfd.zig`).
//! `O_TMPFILE`, `mmap` of a simulated file, `dup2`, `dup3` and `select`
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
        7 => poll(s, a[0], a[1], pollDeadline(s, a[2])),
        271 => ppoll(s, a[0], a[1], a[2]),
        2 => open(s, at_fdcwd, a[0], @truncate(a[1])),
        85 => open(s, at_fdcwd, a[0], o_creat | o_wronly | o_trunc), // creat
        257 => open(s, fd, a[1], @truncate(a[2])),
        // Calls on a descriptor: only on one of ours.
        0, 1, 3, 5, 8, 16, 17, 18, 19, 20, 32, 72, 74, 75, 77, 91, 93, 217, 295, 296 => {
            if (!simulated(fd)) return null;
            if (number == 16) return ioctl(s, fd, @truncate(a[1]));
            // A duplicate of the random device is not emulated.
            const dups_it = number == 32 or (number == 72 and (@as(u32, @truncate(a[1])) == 0 or @as(u32, @truncate(a[1])) == 1030));
            if (fd == random_fd) return if (dups_it) null else randomDevice(s, number, a);
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
    if (offset) |at| {
        if (@as(i64, @bitCast(at)) < 0) return fail(.INVAL);
        return f.writePositional(io, bufs, at) catch |err| return fail(errnoOf(err));
    }
    return f.writeStreaming(io, &.{}, bufs, 1) catch |err| return fail(errnoOf(err));
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
    fileOf(fd).setLength(s.io(), len) catch |err| return fail(errnoOf(err));
    return 0;
}

fn truncate(s: *Sim, path_ptr: u64, len: u64) ?u64 {
    const path = cstr(path_ptr) orelse return fail(.FAULT);
    if (@as(i64, @bitCast(len)) < 0) return fail(.INVAL);
    if (hostPath(path)) return null;
    const io = s.io();
    const f = Sim.rootDir().openFile(io, path, .{ .mode = .write_only, .allow_directory = false }) catch |err| return fail(errnoOf(err));
    defer f.close(io);
    f.setLength(io, len) catch |err| return fail(errnoOf(err));
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
        // Open-file-description locks conflict between two descriptions in
        // one process, which this does not model: not emulated (stray).
        36, 37, 38 => return null,
        5 => { // F_GETLK: nothing would block
            if (arg == 0) return fail(.FAULT);
            @as(*align(1) u16, @ptrFromInt(arg)).* = 2; // l_type = F_UNLCK
            return 0;
        },
        6, 7 => return if (arg == 0) fail(.FAULT) else 0, // F_SETLK, F_SETLKW: one process never conflicts with itself
        else => return fail(.INVAL),
    }
}

// --- names -------------------------------------------------------------------

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
