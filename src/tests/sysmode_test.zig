//! System-call mode (plan §9.2, `plan3.md` D9): `Options.mode = .syscalls`
//! answers the code's own system calls from the simulation.

const std = @import("std");
const builtin = @import("builtin");
const tardis = @import("../root.zig");
const Env = tardis.Env;
const Io = std.Io;
const testing = std.testing;
const gpa = testing.allocator;
const linux = std.os.linux;

const supported = tardis.syscall_mode_supported;

test "system-call mode: unsupported targets say so" {
    if (supported) return error.SkipZigTest;
    const S = struct {
        fn body(_: *Env) !void {}
    };
    try testing.expectError(error.SyscallModeUnsupported, tardis.check(gpa, S.body, .{ .iterations = 1, .mode = .syscalls }));
}

// --- raw calls ---------------------------------------------------------------

const cwd: usize = @bitCast(@as(isize, -100));

const o_rdonly = 0;
const o_wronly = 0o1;
const o_rdwr = 0o2;
const o_creat = 0o100;
const o_excl = 0o200;
const o_trunc = 0o1000;
const o_append = 0o2000;
const o_directory = 0o200000;

fn sys(number: linux.SYS, a: usize, b: usize, c: usize, d: usize) isize {
    return @bitCast(linux.syscall4(number, a, b, c, d));
}

fn errOf(e: linux.E) isize {
    return -@as(isize, @backingInt(e));
}

fn openAt(dir: usize, path: [*:0]const u8, flags: usize) isize {
    return sys(.openat, dir, @intFromPtr(path), flags, 0o644);
}

fn open(path: [*:0]const u8, flags: usize) !usize {
    const rc = openAt(cwd, path, flags);
    if (rc < 0) return error.OpenFailed;
    return @intCast(rc);
}

fn close(fd: usize) void {
    _ = sys(.close, fd, 0, 0, 0);
}

fn writeAll(fd: usize, bytes: []const u8) !void {
    var done: usize = 0;
    while (done < bytes.len) {
        const rc = sys(.write, fd, @intFromPtr(bytes.ptr) + done, bytes.len - done, 0);
        if (rc <= 0) return error.WriteFailed;
        done += @intCast(rc);
    }
}

fn readAll(fd: usize, buf: []u8) !void {
    var done: usize = 0;
    while (done < buf.len) {
        const rc = sys(.read, fd, @intFromPtr(buf.ptr) + done, buf.len - done, 0);
        if (rc <= 0) return error.ReadFailed;
        done += @intCast(rc);
    }
}

fn fsync(fd: usize) !void {
    if (sys(.fsync, fd, 0, 0, 0) != 0) return error.SyncFailed;
}

// --- a crash keeps and loses the same bytes either way -------------------------

const Way = enum { calls, io };

/// What the files held after the crash, for the test to compare.
const After = struct {
    kept: [16]u8 = @splat(0),
    kept_len: usize = 0,
    loose: [16]u8 = @splat(0),
    loose_len: usize = 0,
    loose_exists: bool = false,
};
threadlocal var after: After = .{};

/// "kept" is written and made durable, with its directory entry. "loose"
/// is written and never synced. Then the power goes.
fn durableAndLoose(env: *Env, comptime way: Way) !void {
    const io = env.io;
    switch (way) {
        .calls => {
            const fd = try open("kept", o_creat | o_wronly | o_trunc);
            try writeAll(fd, "durable!");
            try fsync(fd);
            close(fd);
            const dir = try open(".", o_rdonly);
            try fsync(dir);
            close(dir);
            const loose = try open("loose", o_creat | o_wronly | o_trunc);
            try writeAll(loose, "unsynced");
            close(loose);
        },
        .io => {
            const f = try env.dir.createFile(io, "kept", .{});
            try streamAll(io, f, "durable!");
            try f.sync(io);
            f.close(io);
            const dir = try env.dir.openFile(io, ".", .{});
            try dir.sync(io);
            dir.close(io);
            const loose = try env.dir.createFile(io, "loose", .{});
            try streamAll(io, loose, "unsynced");
            loose.close(io);
        },
    }
    try env.crashAndReboot(.power_loss);

    after = .{};
    const kept = try env.dir.readFile(io, "kept", &after.kept);
    after.kept_len = kept.len;
    try env.always("a file synced by system call survives a power loss", std.mem.eql(u8, kept, "durable!"));
    if (env.dir.readFile(io, "loose", &after.loose)) |loose| {
        after.loose_exists = true;
        after.loose_len = loose.len;
    } else |err| if (err != error.FileNotFound) return err;
    env.sometimes("an unsynced file written by system call is lost", !after.loose_exists);
    env.sometimes("an unsynced file written by system call survives whole", after.loose_exists and after.loose_len == 8);
}

fn streamAll(io: Io, f: Io.File, bytes: []const u8) !void {
    var done: usize = 0;
    while (done < bytes.len) {
        const one: [1][]const u8 = .{bytes[done..]};
        done += try f.writeStreaming(io, &.{}, &one, 1);
    }
}

fn byCalls(env: *Env) !void {
    return durableAndLoose(env, .calls);
}

fn byIo(env: *Env) !void {
    return durableAndLoose(env, .io);
}

test "system-call mode: raw file calls land in the simulated filesystem and meet a crash as env.dir writes do" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    const personas: []const tardis.Persona = &.{ .linux_ext4, .linux_xfs, .posix_strict };
    // In a campaign: the synced file always survives, the unsynced one is
    // sometimes lost and sometimes kept.
    try tardis.check(gpa, byCalls, .{ .iterations = 300, .mode = .syscalls, .personas = personas });
    // Seed by seed, the same program through `env.dir`: the same events
    // (one trace hash) and the same bytes after the crash.
    for (personas) |persona| {
        var seed: u64 = 1;
        while (seed <= 200) : (seed += 1) {
            const options: tardis.Options = .{ .mode = .syscalls };
            const calls_hash = try tardis.traceHash(gpa, byCalls, seed, persona, options);
            const calls_after = after;
            const io_hash = try tardis.traceHash(gpa, byIo, seed, persona, options);
            try testing.expectEqual(io_hash, calls_hash);
            try testing.expectEqualDeep(after, calls_after);
        }
    }
}

// --- the answers ---------------------------------------------------------------

fn answers(env: *Env) !void {
    _ = env;
    // Errors come back as the kernel's numbers.
    try testing.expectEqual(errOf(.NOENT), openAt(cwd, "missing", o_rdonly));
    try testing.expectEqual(errOf(.NOENT), openAt(cwd, "no/such/dir", o_creat | o_wronly));
    const fd = try open("f", o_creat | o_rdwr | o_excl);
    try testing.expect(fd >= 0x4000_0000);
    try testing.expectEqual(errOf(.EXIST), openAt(cwd, "f", o_creat | o_rdwr | o_excl));
    try testing.expectEqual(errOf(.NOTDIR), openAt(cwd, "f/x", o_rdonly));
    try testing.expectEqual(errOf(.NOTDIR), openAt(cwd, "f", o_rdonly | o_directory));

    // Positioned and streaming transfers, the position, the length.
    try writeAll(fd, "0123456789");
    try testing.expectEqual(@as(isize, 10), sys(.lseek, fd, 0, 1, 0));
    var buf: [32]u8 = undefined;
    try testing.expectEqual(@as(isize, 0), sys(.read, fd, @intFromPtr(&buf), buf.len, 0));
    try testing.expectEqual(@as(isize, 3), sys(.lseek, fd, 3, 0, 0));
    try readAll(fd, buf[0..7]);
    try testing.expectEqualStrings("3456789", buf[0..7]);
    try testing.expect(sys(.pwrite64, fd, @intFromPtr("AB"), 2, 20) > 0);
    try testing.expectEqual(@as(isize, 0), sys(.ftruncate, fd, 21, 0, 0));
    try testing.expectEqual(@as(isize, 21), sys(.lseek, fd, 0, 2, 0));
    try testing.expect(sys(.pread64, fd, @intFromPtr(&buf), 1, 20) == 1);
    try testing.expectEqual(@as(u8, 'A'), buf[0]);
    try testing.expect(sys(.pread64, fd, @intFromPtr(&buf), 1, 15) == 1);
    try testing.expectEqual(@as(u8, 0), buf[0]); // a hole reads as zeros

    // stat, by descriptor and by name.
    var st: [18]u64 = undefined;
    try testing.expectEqual(@as(isize, 0), sys(.fstat, fd, @intFromPtr(&st), 0, 0));
    try testing.expectEqual(@as(u64, 21), st[6]); // st_size
    try testing.expectEqual(@as(u64, 0o100644), st[3] & 0xffff_ffff); // st_mode
    try testing.expectEqual(@as(isize, 0), sys(.newfstatat, cwd, @intFromPtr("f"), @intFromPtr(&st), 0));
    try testing.expectEqual(@as(u64, 21), st[6]);
    try testing.expectEqual(errOf(.NOENT), sys(.newfstatat, cwd, @intFromPtr("g"), @intFromPtr(&st), 0));

    // A closed descriptor is closed.
    try testing.expectEqual(@as(isize, 0), sys(.close, fd, 0, 0, 0));
    try testing.expectEqual(errOf(.BADF), sys(.close, fd, 0, 0, 0));
    try testing.expectEqual(errOf(.BADF), sys(.write, fd, @intFromPtr("x"), 1, 0));

    // O_APPEND writes at the end wherever the position is.
    const a = try open("f", o_wronly | o_append);
    try testing.expectEqual(@as(isize, 0), sys(.lseek, a, 0, 0, 0));
    try writeAll(a, "Z");
    try testing.expectEqual(@as(isize, 0), sys(.fstat, a, @intFromPtr(&st), 0, 0));
    try testing.expectEqual(@as(u64, 22), st[6]);
    close(a);

    // Directories: make, list, rename into, remove.
    try testing.expectEqual(@as(isize, 0), sys(.mkdirat, cwd, @intFromPtr("d"), 0o755, 0));
    try testing.expectEqual(errOf(.EXIST), sys(.mkdirat, cwd, @intFromPtr("d"), 0o755, 0));
    try testing.expectEqual(@as(isize, 0), sys(.renameat, cwd, @intFromPtr("f"), cwd, @intFromPtr("d/g")));
    try testing.expectEqual(errOf(.NOTEMPTY), sys(.unlinkat, cwd, @intFromPtr("d"), 0x200, 0));
    try testing.expectEqual(errOf(.ISDIR), sys(.unlinkat, cwd, @intFromPtr("d"), 0, 0));
    const d = try open("d", o_rdonly | o_directory);
    try testing.expectEqual(errOf(.ISDIR), sys(.read, d, @intFromPtr(&buf), 1, 0));
    var names: [8][8]u8 = undefined;
    var name_lens: [8]usize = undefined;
    var names_len: usize = 0;
    var ents: [256]u8 align(8) = undefined;
    while (true) {
        const rc = sys(.getdents64, d, @intFromPtr(&ents), ents.len, 0);
        try testing.expect(rc >= 0);
        if (rc == 0) break;
        var at: usize = 0;
        while (at < rc) {
            const reclen = std.mem.readInt(u16, ents[at + 16 ..][0..2], .little);
            const name = std.mem.sliceTo(ents[at + 19 .. at + reclen], 0);
            @memcpy(names[names_len][0..name.len], name);
            name_lens[names_len] = name.len;
            names_len += 1;
            at += reclen;
        }
    }
    try testing.expectEqual(@as(usize, 3), names_len);
    try testing.expectEqualStrings(".", names[0][0..name_lens[0]]);
    try testing.expectEqualStrings("..", names[1][0..name_lens[1]]);
    try testing.expectEqualStrings("g", names[2][0..name_lens[2]]);
    // Relative to the directory's descriptor.
    try testing.expectEqual(@as(isize, 0), sys(.unlinkat, d, @intFromPtr("g"), 0, 0));
    close(d);
    try testing.expectEqual(@as(isize, 0), sys(.unlinkat, cwd, @intFromPtr("d"), 0x200, 0));
}

test "system-call mode: errors, positions, stat and directory listing answer as the kernel does" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    try tardis.check(gpa, answers, .{
        .iterations = 50,
        .mode = .syscalls,
        .personas = &.{.linux_ext4},
        .faults = .{ .short_io_ppm = 0 },
    });
}

// --- descriptors and env.dir are one filesystem ----------------------------------

fn oneWorld(env: *Env) !void {
    const io = env.io;
    try env.dir.writeFile(io, .{ .sub_path = "from_io", .data = "hello" });
    const fd = try open("from_io", o_rdonly);
    var buf: [8]u8 = undefined;
    try readAll(fd, buf[0..5]);
    try testing.expectEqualStrings("hello", buf[0..5]);
    // A crash closes every descriptor: this one is from before it.
    try env.crashAndReboot(.process_crash);
    try testing.expectEqual(errOf(.BADF), sys(.read, fd, @intFromPtr(&buf), 1, 0));
    try testing.expectEqual(errOf(.BADF), sys(.close, fd, 0, 0, 0));
}

test "system-call mode: a descriptor reads what env.dir wrote, and does not outlive a crash" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    try tardis.check(gpa, oneWorld, .{ .iterations = 50, .mode = .syscalls });
}

// --- time, sleeping, randomness ------------------------------------------------

const Timespec = extern struct { sec: i64, nsec: i64 };

fn monotonicNs() !u64 {
    var ts: Timespec = undefined;
    // The system call itself: `std.os.linux.clock_gettime` goes through
    // the vDSO, which is not trapped.
    if (sys(.clock_gettime, 1, @intFromPtr(&ts), 0, 0) != 0) return error.ClockFailed;
    return @intCast(ts.sec * std.time.ns_per_s + ts.nsec);
}

threadlocal var sleeper_woke_at: [2]u64 = @splat(0);

fn sleeper(index: usize, ms: i64) void {
    const req: Timespec = .{ .sec = 0, .nsec = ms * std.time.ns_per_ms };
    _ = sys(.nanosleep, @intFromPtr(&req), 0, 0, 0);
    sleeper_woke_at[index] = monotonicNs() catch 0;
}

fn clocks(env: *Env) !void {
    const io = env.io;
    const t0 = try monotonicNs();
    try testing.expectEqual(env.nowNs(), t0);

    // Two tasks asleep in the handler at once, and this one too: each
    // wakes at its own virtual time.
    sleeper_woke_at = @splat(0);
    var a = try io.concurrent(sleeper, .{ 0, 30 });
    var b = try io.concurrent(sleeper, .{ 1, 10 });
    const req: Timespec = .{ .sec = 0, .nsec = 20 * std.time.ns_per_ms };
    try testing.expectEqual(@as(isize, 0), sys(.nanosleep, @intFromPtr(&req), 0, 0, 0));
    const t1 = try monotonicNs();
    try testing.expect(t1 - t0 >= 20 * std.time.ns_per_ms);
    try testing.expect(t1 - t0 < 30 * std.time.ns_per_ms);
    a.await(io);
    b.await(io);
    try testing.expect(sleeper_woke_at[1] - t0 >= 10 * std.time.ns_per_ms);
    try testing.expect(sleeper_woke_at[1] < t1);
    try testing.expect(sleeper_woke_at[0] - t0 >= 30 * std.time.ns_per_ms);

    // An absolute deadline on the same clock.
    const t2 = try monotonicNs();
    const until = t2 + 5 * std.time.ns_per_ms;
    const abs: Timespec = .{ .sec = @intCast(until / std.time.ns_per_s), .nsec = @intCast(until % std.time.ns_per_s) };
    try testing.expectEqual(@as(isize, 0), sys(.clock_nanosleep, 1, 1, @intFromPtr(&abs), 0));
    try testing.expect(try monotonicNs() >= until);

    // The wall clock is the simulation's, not the host's.
    var real: Timespec = undefined;
    try testing.expectEqual(@as(isize, 0), sys(.clock_gettime, 0, @intFromPtr(&real), 0, 0));
    try testing.expect(real.sec >= 1_700_000_000 and real.sec < 1_700_000_100);
}

test "system-call mode: clock reads and sleeps are in virtual time, and a sleeping task lets others run" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    const t0 = std.Io.Clock.awake.now(testing.io).nanoseconds;
    try tardis.check(gpa, clocks, .{ .iterations = 100, .mode = .syscalls });
    // A hundred runs of 35 ms of sleep took no such time.
    const elapsed_ms = @divTrunc(std.Io.Clock.awake.now(testing.io).nanoseconds - t0, std.time.ns_per_ms);
    try testing.expect(elapsed_ms < 3000);
}

threadlocal var drawn: [16]u8 = @splat(0);

fn randomBytes(env: *Env) !void {
    _ = env;
    try testing.expectEqual(@as(usize, drawn.len), linux.getrandom(&drawn, drawn.len, 0));
}

test "system-call mode: getrandom follows the seed" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    const options: tardis.Options = .{ .mode = .syscalls };
    _ = try tardis.traceHash(gpa, randomBytes, 7, .linux_ext4, options);
    const first = drawn;
    _ = try tardis.traceHash(gpa, randomBytes, 7, .linux_ext4, options);
    try testing.expectEqualSlices(u8, &first, &drawn);
    _ = try tardis.traceHash(gpa, randomBytes, 8, .linux_ext4, options);
    try testing.expect(!std.mem.eql(u8, &first, &drawn));
}

// --- what is not emulated is still stray -----------------------------------------

fn opensSocket(env: *Env) !void {
    _ = env;
    const rc = sys(.socket, 2, 1, 0, 0); // AF_INET, SOCK_STREAM
    if (rc >= 0) _ = linux.close(@intCast(rc));
}

fn readsRealDescriptor(env: *Env) !void {
    _ = env;
    var byte: [1]u8 = undefined;
    // Not a descriptor the simulator issued: the call is not answered.
    _ = sys(.pread64, 1 << 20, @intFromPtr(&byte), 1, 0);
}

fn opensBesideRealDescriptor(env: *Env) !void {
    _ = env;
    // Relative to a directory the simulator did not issue.
    _ = openAt(2, "x", o_rdonly);
}

fn mapsSimulatedFile(env: *Env) !void {
    _ = env;
    const fd = try open("m", o_creat | o_rdwr);
    defer close(fd);
    // PROT_READ, MAP_PRIVATE: the kernel has no such file to map.
    const rc: isize = @bitCast(linux.syscall6(.mmap, 0, 4096, 1, 2, fd, 0));
    try testing.expect(rc < 0);
}

fn opensHostTree(env: *Env) !void {
    _ = env;
    const rc = openAt(cwd, "/proc/self/no-such-file", o_rdonly);
    try testing.expect(rc < 0);
}

/// A stray that would change the host: it must be refused, not made.
var host_path_buf: [64]u8 = undefined;
var host_path: [:0]const u8 = "";
var stray_rc: isize = 0;

fn renamesOnHost(env: *Env) !void {
    _ = env;
    // `/dev/shm` is a host tree: the call is not the simulator's to answer.
    stray_rc = sys(.rename, @intFromPtr(host_path.ptr), @intFromPtr("/dev/shm/tardis-stray-moved"), 0, 0);
}

fn failsAndStrays(env: *Env) !void {
    _ = env;
    _ = sys(.socket, 2, 1, 0, 0);
    return error.TestUnexpectedResult;
}

var cpus: usize = 0;

fn countsProcessors(env: *Env) !void {
    _ = env;
    var mask: [128]u8 = undefined;
    const rc = sys(.sched_getaffinity, 0, mask.len, @intFromPtr(&mask), 0);
    try testing.expect(rc > 0);
    var n: usize = 0;
    for (mask[0..@intCast(rc)]) |b| n += @popCount(b);
    cpus = n;
}

test "system-call mode: a stray is refused, not made, and fails the run even when the body fails too" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    // A real file in a host tree, which the stray would move.
    const text = try std.fmt.bufPrint(host_path_buf[0 .. host_path_buf.len - 1], "/dev/shm/tardis-stray-{d}", .{linux.getpid()});
    host_path_buf[text.len] = 0;
    host_path = host_path_buf[0..text.len :0];
    const made = sys(.open, @intFromPtr(host_path.ptr), o_creat | o_wronly, 0o600, 0);
    if (made < 0) return error.SkipZigTest; // no /dev/shm here
    _ = linux.close(@intCast(made));
    defer _ = sys(.unlink, @intFromPtr(host_path.ptr), 0, 0, 0);
    defer _ = sys(.unlink, @intFromPtr("/dev/shm/tardis-stray-moved"), 0, 0, 0);
    const options: tardis.Options = .{ .iterations = 2, .mode = .syscalls, .report = false, .shrink = false };
    try testing.expectError(error.StraySyscall, tardis.check(gpa, renamesOnHost, options));
    try testing.expectEqual(errOf(.NOSYS), stray_rc);
    // The file is where it was.
    try testing.expectEqual(@as(isize, 0), sys(.access, @intFromPtr(host_path.ptr), 0, 0, 0));
    try testing.expectError(error.StraySyscall, tardis.check(gpa, failsAndStrays, options));
}

test "system-call mode: the processor count is one, on every machine" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    try tardis.check(gpa, countsProcessors, .{ .iterations = 2, .mode = .syscalls });
    try testing.expectEqual(@as(usize, 1), cpus);
    // Without the mode, asking is a stray: it leaves the simulation.
    try testing.expectError(error.StraySyscall, tardis.check(gpa, countsProcessors, .{ .iterations = 1, .trap_syscalls = true, .report = false, .shrink = false }));
}

fn rootDescriptor(env: *Env) !void {
    const io = env.io;
    const root: usize = @intCast(tardis.syscall_root_fd);
    // A file made beside the root descriptor, made durable by syncing it.
    const fd: usize = @intCast(openAt(root, "r", o_creat | o_wronly));
    try writeAll(fd, "kept");
    try fsync(fd);
    close(fd);
    try fsync(root);
    try testing.expectEqual(@as(isize, 0), sys(.close, root, 0, 0, 0));
    var st: [18]u64 = undefined;
    try testing.expectEqual(@as(isize, 0), sys(.fstat, root, @intFromPtr(&st), 0, 0));
    try testing.expectEqual(@as(u64, 0o040755), st[3] & 0xffff_ffff);
    try testing.expectEqual(@as(isize, 0), sys(.chmod, @intFromPtr("r"), 0o600, 0, 0));
    try testing.expectEqual(errOf(.NOENT), sys(.chmod, @intFromPtr("none"), 0o600, 0, 0));
    try env.crashAndReboot(.power_loss);
    var buf: [8]u8 = undefined;
    try testing.expectEqualStrings("kept", try env.dir.readFile(io, "r", &buf));
}

test "system-call mode: the root descriptor is a directory to be relative to, and to sync" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    try tardis.check(gpa, rootDescriptor, .{ .iterations = 100, .mode = .syscalls, .personas = &.{ .linux_ext4, .posix_strict } });
}

test "system-call mode: a call that is not emulated, or on a real descriptor, fails the run" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    const options: tardis.Options = .{ .iterations = 3, .mode = .syscalls, .report = false, .shrink = false };
    try testing.expectError(error.StraySyscall, tardis.check(gpa, opensSocket, options));
    try testing.expectError(error.StraySyscall, tardis.check(gpa, readsRealDescriptor, options));
    try testing.expectError(error.StraySyscall, tardis.check(gpa, opensBesideRealDescriptor, options));
    try testing.expectError(error.StraySyscall, tardis.check(gpa, mapsSimulatedFile, options));
    try testing.expectError(error.StraySyscall, tardis.check(gpa, opensHostTree, options));
}

// --- differential: the same calls against the kernel -----------------------------

/// The paths a call may name: files, a directory, files in it, a path whose
/// parent does not exist, and one through a file.
const diff_names = [_][*:0]const u8{ "a", "b", "c", "d", "d/x", "d/y", "e/z", "a/q" };

const DiffKind = enum {
    open,
    close,
    write,
    pwrite,
    read,
    pread,
    lseek,
    ftruncate,
    fsync,
    fstat,
    stat,
    unlink,
    rmdir,
    mkdir,
    rename,
    access,
    getdents,
};

const DiffOp = struct {
    kind: DiffKind,
    name: u8,
    other: u8,
    slot: u8,
    len: u8,
    offset: u8,
    flags: u8,
    fill: u8,
};

/// What a call gave: its return value (a new descriptor counts as 0), and
/// a digest of what it wrote into the memory of the caller.
const DiffResult = struct {
    rc: isize = 0,
    digest: u64 = 0,
};

const diff_ops_max = 32;
const diff_slots = 4;

const diff_open_flags = [_]usize{
    o_rdonly,
    o_wronly,
    o_rdwr,
    o_rdwr | o_creat,
    o_wronly | o_creat | o_trunc,
    o_rdwr | o_creat | o_excl,
    o_wronly | o_append,
    o_rdwr | o_creat | o_append,
    o_rdonly | o_directory,
    o_wronly | o_trunc,
    // Found by review (revision 75): a directory opened for writing, and
    // a read-only open that truncates.
    o_rdwr | o_directory,
    o_rdonly | o_trunc,
};

fn diffGenerate(seed: u64, ops: []DiffOp) void {
    var prng: std.Random.DefaultPrng = .init(seed);
    const r = prng.random();
    for (ops) |*op| op.* = .{
        .kind = r.enumValue(DiffKind),
        .name = r.uintLessThan(u8, diff_names.len),
        .other = r.uintLessThan(u8, diff_names.len),
        .slot = r.uintLessThan(u8, diff_slots),
        .len = r.uintLessThan(u8, 48),
        .offset = r.uintLessThan(u8, 96),
        .flags = r.uintLessThan(u8, diff_open_flags.len),
        .fill = r.int(u8),
    };
}

/// Runs the calls relative to `dir` (a descriptor, or `AT_FDCWD`). The
/// same code for the kernel and for the simulator.
fn diffRun(dir: usize, ops: []const DiffOp, out: []DiffResult) void {
    var fds: [diff_slots]?usize = @splat(null);
    var buf: [512]u8 align(8) = undefined;
    for (ops, out) |op, *res| {
        res.* = .{};
        const name = @intFromPtr(diff_names[op.name]);
        const fd = fds[op.slot];
        switch (op.kind) {
            .open => {
                if (fd != null) continue;
                const rc = sys(.openat, dir, name, diff_open_flags[op.flags], 0o644);
                if (rc >= 0) fds[op.slot] = @intCast(rc);
                res.rc = @min(rc, 0);
            },
            .mkdir => res.rc = sys(.mkdirat, dir, name, 0o755, 0),
            .unlink => res.rc = sys(.unlinkat, dir, name, 0, 0),
            .rmdir => res.rc = sys(.unlinkat, dir, name, 0x200, 0),
            .rename => res.rc = sys(.renameat, dir, name, dir, @intFromPtr(diff_names[op.other])),
            .access => res.rc = sys(.faccessat, dir, name, 0, 0),
            .stat => {
                var st: [18]u64 = @splat(0);
                res.rc = sys(.newfstatat, dir, name, @intFromPtr(&st), 0);
                if (res.rc == 0) res.digest = statDigest(&st);
            },
            else => {
                // The calls on a descriptor.
                const f = fd orelse continue;
                switch (op.kind) {
                    .close => {
                        res.rc = sys(.close, f, 0, 0, 0);
                        fds[op.slot] = null;
                    },
                    .write, .pwrite => {
                        @memset(buf[0..op.len], op.fill);
                        res.rc = if (op.kind == .write)
                            sys(.write, f, @intFromPtr(&buf), op.len, 0)
                        else
                            sys(.pwrite64, f, @intFromPtr(&buf), op.len, op.offset);
                    },
                    .read, .pread => {
                        // A directory is read from its start: after a
                        // listing ext4 leaves a hash for a position, and
                        // refuses the read for that and not for what it is.
                        var st: [18]u64 = @splat(0);
                        if (sys(.fstat, f, @intFromPtr(&st), 0, 0) == 0 and st[3] & 0o170000 == 0o040000) _ = sys(.lseek, f, 0, 0, 0);
                        res.rc = if (op.kind == .read)
                            sys(.read, f, @intFromPtr(&buf), op.len, 0)
                        else
                            sys(.pread64, f, @intFromPtr(&buf), op.len, op.offset);
                        if (res.rc > 0) res.digest = std.hash.Wyhash.hash(0, buf[0..@intCast(res.rc)]);
                    },
                    .lseek => {
                        // Not on a directory: what its positions mean
                        // is the filesystem's own business.
                        var st: [18]u64 = @splat(0);
                        if (sys(.fstat, f, @intFromPtr(&st), 0, 0) != 0 or st[3] & 0o170000 == 0o040000) continue;
                        res.rc = sys(.lseek, f, op.offset, op.flags % 3, 0);
                    },
                    .ftruncate => res.rc = sys(.ftruncate, f, op.offset, 0, 0),
                    .fsync => res.rc = sys(if (op.flags & 1 == 0) .fsync else .fdatasync, f, 0, 0, 0),
                    .fstat => {
                        var st: [18]u64 = @splat(0);
                        res.rc = sys(.fstat, f, @intFromPtr(&st), 0, 0);
                        if (res.rc == 0) res.digest = statDigest(&st);
                    },
                    .getdents => {
                        // The names, whatever order they come in.
                        _ = sys(.lseek, f, 0, 0, 0);
                        var sum: u64 = 0;
                        while (true) {
                            const rc = sys(.getdents64, f, @intFromPtr(&buf), buf.len, 0);
                            if (rc <= 0) {
                                res.rc = rc;
                                break;
                            }
                            var at: usize = 0;
                            while (at < rc) {
                                const reclen = std.mem.readInt(u16, buf[at + 16 ..][0..2], .little);
                                const entry_name = std.mem.sliceTo(buf[at + 19 .. at + reclen], 0);
                                sum +%= std.hash.Wyhash.hash(buf[at + 18], entry_name);
                                at += reclen;
                            }
                        }
                        res.digest = sum;
                    },
                    else => unreachable,
                }
            },
        }
    }
    for (fds) |fd| if (fd) |f| close(f);
}

/// The kind of file, and the size of a regular file. Not compared: inode
/// numbers, times, owners, link counts, the size of a directory.
fn statDigest(st: *const [18]u64) u64 {
    const kind = (st[3] & 0xffff_ffff) & 0o170000;
    return (kind << 32) | (if (kind == 0o100000) st[6] else 0);
}

/// 20,000 agreed when this was written (revision 75); the suite runs fewer.
const diff_sequences = 5_000;

/// What the simulator answered, by iteration, with the seed the calls
/// were generated from.
const DiffRecord = struct {
    seed: u64 = 0,
    ran: bool = false,
    results: [diff_ops_max]DiffResult = undefined,
};
var diff_records: []DiffRecord = &.{};

fn diffBody(env: *Env) !void {
    if (env.iteration >= diff_records.len) return;
    const record = &diff_records[env.iteration];
    var ops: [diff_ops_max]DiffOp = undefined;
    diffGenerate(env.seed, &ops);
    diffRun(cwd, &ops, &record.results);
    record.seed = env.seed;
    record.ran = true;
}

test "system-call mode: random sequences of file calls answer as the Linux kernel answers them" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    diff_records = try gpa.alloc(DiffRecord, diff_sequences);
    defer gpa.free(diff_records);
    @memset(diff_records, .{});

    // The simulator: the model alone, no faults.
    try tardis.check(gpa, diffBody, .{
        .iterations = diff_sequences,
        .mode = .syscalls,
        .personas = &.{.linux_ext4},
        .swarm = false,
        .leak_check = false,
        .shrink = false,
        .faults = .{ .short_io_ppm = 0, .io_latency_min_ns = 0, .io_latency_max_ns = 0 },
    });

    // The kernel: each sequence in a directory of its own.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_fd: usize = @intCast(tmp.dir.handle);
    var ops: [diff_ops_max]DiffOp = undefined;
    var real: [diff_ops_max]DiffResult = undefined;
    var compared: usize = 0;
    for (diff_records, 0..) |*record, sequence| {
        if (!record.ran) continue;
        diffGenerate(record.seed, &ops);
        try testing.expectEqual(@as(isize, 0), sys(.mkdirat, tmp_fd, @intFromPtr("s"), 0o755, 0));
        const real_dir = sys(.openat, tmp_fd, @intFromPtr("s"), o_rdonly | o_directory, 0);
        try testing.expect(real_dir >= 0);
        diffRun(@intCast(real_dir), &ops, &real);
        close(@intCast(real_dir));
        try tmp.dir.deleteTree(testing.io, "s");

        for (real, record.results, 0..) |want, got, i| {
            if (want.rc == got.rc and want.digest == got.digest) continue;
            std.debug.print("sequence {d} (seed 0x{x}), call {d}: the kernel gave {d} (digest {x}), the simulator {d} (digest {x})\n", .{ sequence, record.seed, i, want.rc, want.digest, got.rc, got.digest });
            for (ops[0 .. i + 1], 0..) |o, k| std.debug.print("  {d}: {s} name={s} other={s} slot={d} len={d} offset={d} flags={d}\n", .{ k, @tagName(o.kind), diff_names[o.name], diff_names[o.other], o.slot, o.len, o.offset, o.flags });
            return error.SimulatorDisagreesWithKernel;
        }
        compared += 1;
    }
    try testing.expect(compared > 0);
}
