//! A C++ program under simulation (`plan3.md` D9, plan §9.2), and the
//! default suite's test of a program linked with libc.
//!
//! `test/cpp/probe.cpp` is C++ that knows nothing of TARDIS: the standard
//! library's threads, locks, condition variables, clocks, streams, random
//! device and exceptions, over libc++ and libc. Zig compiles it, so this
//! needs no other toolchain and is part of `zig build test` on Linux
//! x86_64 (and skipped elsewhere). System-call mode answers its system
//! calls from the simulation, and its threads are simulated tasks.
//!
//! The clock tests are the ones the rest of the default suite cannot
//! make: libc reads its clocks through the vDSO, with no system call, and
//! a test that links no libc never takes that path (revision 99 found it
//! broken for every program that does).

const std = @import("std");
const tardis = @import("tardis");
const Env = tardis.Env;
const testing = std.testing;

const supported = tardis.syscall_mode_supported;

extern fn cpp_threads() c_int;
extern fn cpp_time() i64;
extern fn cpp_wall_ms() i64;
extern fn cpp_exceptions() c_int;
extern fn cpp_files() c_int;
extern fn cpp_files_kept() c_int;
extern fn cpp_random() u32;

const options: tardis.Options = .{
    .iterations = 50,
    .mode = .syscalls,
    .limits = .{ .fiber_stack_bytes = 1024 * 1024 },
};

fn skip() bool {
    return !supported or !tardis.syscallModeAvailable();
}

fn skipThreads() bool {
    return skip() or !tardis.syscallThreadsAvailable();
}

/// libc's own clock call, before any C++: the virtual clock, to the
/// nanosecond, and a sleep moves it.
fn libcClock(env: *Env) !void {
    var ts: std.c.timespec = undefined;
    try testing.expectEqual(@as(c_int, 0), std.c.clock_gettime(.MONOTONIC, &ts));
    try testing.expectEqual(env.nowNs(), @as(u64, @intCast(ts.sec * std.time.ns_per_s + ts.nsec)));
    const req: std.c.timespec = .{ .sec = 0, .nsec = 250 * std.time.ns_per_ms };
    _ = std.c.nanosleep(&req, null);
    var later: std.c.timespec = undefined;
    try testing.expectEqual(@as(c_int, 0), std.c.clock_gettime(.MONOTONIC, &later));
    try testing.expectEqual(env.nowNs(), @as(u64, @intCast(later.sec * std.time.ns_per_s + later.nsec)));
    try testing.expect(later.sec * std.time.ns_per_s + later.nsec >= ts.sec * std.time.ns_per_s + ts.nsec + 250 * std.time.ns_per_ms);
}

test "libc: a clock read through the vDSO is in virtual time" {
    if (skip()) return error.SkipZigTest;
    try tardis.check(testing.allocator, libcClock, .{ .iterations = 20, .mode = .syscalls });
}

threadlocal var shared_lock: std.c.pthread_mutex_t = .{};
threadlocal var shared_count: u32 = 0;

fn countsUnderLock() void {
    for (0..5) |_| {
        _ = std.c.pthread_mutex_lock(&shared_lock);
        const before = shared_count;
        // A system call with the lock held: the other task runs, and
        // waits for the lock.
        const req: std.c.timespec = .{ .sec = 0, .nsec = 1000 };
        _ = std.c.nanosleep(&req, null);
        shared_count = before + 1;
        _ = std.c.pthread_mutex_unlock(&shared_lock);
    }
}

/// Two tasks, which are fibers on one real thread, and one libc mutex.
/// glibc's unlock wakes nobody while the process has only ever had one
/// thread, so the task that waited was never woken and the run was a
/// deadlock (found with SQLite on glibc, revision 110). A run in this
/// mode now starts one real thread first, and this test fails without it.
fn twoTasksOneLock(env: *Env) !void {
    // A run that failed may have left it held.
    shared_lock = .{};
    shared_count = 0;
    var other = try env.io.concurrent(countsUnderLock, .{});
    countsUnderLock();
    other.await(env.io);
    try testing.expectEqual(@as(u32, 10), shared_count);
}

test "libc: two tasks that meet at a pthread mutex both get it" {
    if (skip()) return error.SkipZigTest;
    try tardis.check(testing.allocator, twoTasksOneLock, options);
}

fn threads(env: *Env) !void {
    _ = env;
    try testing.expectEqual(@as(c_int, 0), cpp_threads());
}

test "c++: four threads, a mutex and a condition variable" {
    if (skipThreads()) return error.SkipZigTest;
    try tardis.check(testing.allocator, threads, options);
}

fn time(env: *Env) !void {
    const before = env.nowNs();
    const wall_before = cpp_wall_ms();
    const ms = cpp_time();
    // An hour's sleep and a wait of 250 ms that times out, on the steady
    // clock, and the simulation's clock moved as far.
    try testing.expect(ms >= 3600 * 1000 + 250);
    try testing.expect(ms < 3601 * 1000);
    const passed_ms: i64 = @intCast((env.nowNs() - before) / std.time.ns_per_ms);
    try testing.expect(passed_ms >= ms and passed_ms <= ms + 1);
    // The wall clock moved with it (a node's clock may drift a little).
    const wall = cpp_wall_ms() - wall_before;
    try testing.expect(wall >= 3590 * 1000 and wall <= 3611 * 1000);
}

test "c++: sleep_for and wait_for pass in virtual time, on both clocks" {
    if (skip()) return error.SkipZigTest;
    try tardis.check(testing.allocator, time, options);
}

fn exceptions(env: *Env) !void {
    _ = env;
    try testing.expectEqual(@as(c_int, 0), cpp_exceptions());
}

test "c++: exceptions unwind on a simulated thread's stack and on the body's" {
    if (skipThreads()) return error.SkipZigTest;
    try tardis.check(testing.allocator, exceptions, options);
}

fn files(env: *Env) !void {
    try testing.expectEqual(@as(c_int, 0), cpp_files());
    try env.crashAndReboot(.power_loss);
    // Written, synced, renamed, and the directory synced: it is kept.
    try testing.expectEqual(@as(c_int, 0), cpp_files_kept());
}

test "c++: streams land in the simulated filesystem, and a synced file meets a power loss" {
    if (skip()) return error.SkipZigTest;
    var o = options;
    o.personas = &.{ .linux_ext4, .linux_xfs, .posix_strict };
    try tardis.check(testing.allocator, files, o);
}

threadlocal var drawn: u32 = 0;

fn random(env: *Env) !void {
    _ = env;
    drawn = cpp_random();
}

extern fn cpp_processors() c_int;

fn processors(env: *Env) !void {
    _ = env;
    // One processor, asked three ways.
    try testing.expectEqual(@as(c_int, 10101), cpp_processors());
}

test "c++: the processor count is one, on every machine" {
    if (skip()) return error.SkipZigTest;
    try tardis.check(testing.allocator, processors, options);
}

test "c++: std::random_device follows the seed" {
    if (skip()) return error.SkipZigTest;
    try tardis.check(testing.allocator, random, .{ .iterations = 1, .seed = 1, .mode = .syscalls });
    const first = drawn;
    try tardis.check(testing.allocator, random, .{ .iterations = 1, .seed = 1, .mode = .syscalls });
    try testing.expectEqual(first, drawn);
    try tardis.check(testing.allocator, random, .{ .iterations = 1, .seed = 2, .mode = .syscalls });
    try testing.expect(first != drawn);
}
