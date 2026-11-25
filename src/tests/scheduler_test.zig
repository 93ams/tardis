//! Semantic tests for the scheduler and the concurrency half of the VTable
//! (plan §10, tier 2). These drive real `std.Io` code (Mutex, Condition,
//! Queue, Group, Future) through the simulator.

const std = @import("std");
const tardis = @import("../root.zig");
const Io = std.Io;
const testing = std.testing;

const quiet: tardis.Options = .{ .iterations = 30, .faults = .{ .io_error_ppm = 0 } };

test "sleep advances virtual time only" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            const t0 = Io.Timestamp.now(env.io, .awake);
            try env.io.sleep(.fromSeconds(30), .awake);
            const t1 = Io.Timestamp.now(env.io, .awake);
            try testing.expectEqual(@as(i96, 30 * std.time.ns_per_s), t0.durationTo(t1).nanoseconds);
            const real = Io.Timestamp.now(env.io, .real);
            try testing.expect(real.toSeconds() >= 1_700_000_000);
        }
    }.run, quiet);
}

fn worker(io: Io, counter: *u32, mutex: *Io.Mutex, rounds: u32) Io.Cancelable!void {
    var i: u32 = 0;
    while (i < rounds) : (i += 1) {
        try mutex.lock(io);
        defer mutex.unlock(io);
        const v = counter.*;
        try io.sleep(.fromMicroseconds(1), .awake); // force interleaving inside the critical section
        counter.* = v + 1;
    }
}

test "std.Io.Mutex protects a counter across concurrent tasks" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            var counter: u32 = 0;
            var mutex: Io.Mutex = .init;
            var group: Io.Group = .init;
            var i: u32 = 0;
            while (i < 4) : (i += 1) try group.concurrent(env.io, worker, .{ env.io, &counter, &mutex, 5 });
            try group.await(env.io);
            try testing.expectEqual(@as(u32, 20), counter);
        }
    }.run, quiet);
}

fn racyWorker(io: Io, counter: *u32) Io.Cancelable!void {
    const v = counter.*;
    try io.sleep(.fromMicroseconds(1), .awake);
    counter.* = v + 1;
}

test "an unprotected read-modify-write race is found" {
    const r = tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            var counter: u32 = 0;
            var group: Io.Group = .init;
            try group.concurrent(env.io, racyWorker, .{ env.io, &counter });
            try group.concurrent(env.io, racyWorker, .{ env.io, &counter });
            try group.await(env.io);
            try env.always("no lost update", counter == 2);
        }
    }.run, .{ .iterations = 30, .report = false });
    try testing.expectError(error.AssertionFailed, r);
}

fn producer(io: Io, q: *Io.Queue(u32), n: u32) !void {
    var i: u32 = 0;
    while (i < n) : (i += 1) try q.putOne(io, i);
}

test "std.Io.Queue delivers in order between tasks" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            var buf: [3]u32 = undefined;
            var q: Io.Queue(u32) = .init(&buf);
            var f = try env.io.concurrent(producer, .{ env.io, &q, 10 });
            var expected: u32 = 0;
            while (expected < 10) : (expected += 1) {
                try testing.expectEqual(expected, try q.getOne(env.io));
            }
            try f.await(env.io);
        }
    }.run, quiet);
}

fn add(a: u32, b: u32) u32 {
    return a + b;
}

test "async futures return results whether inline or spawned" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            var f1 = env.io.async(add, .{ 1, 2 });
            var f2 = env.io.async(add, .{ 3, 4 });
            try testing.expectEqual(@as(u32, 7), f2.await(env.io));
            try testing.expectEqual(@as(u32, 3), f1.await(env.io));
        }
    }.run, .{ .iterations = 40, .async_inline_ppm = 500_000 });
}

fn sleepForever(io: Io) Io.Cancelable!void {
    try io.sleep(.fromSeconds(1_000_000), .awake);
    unreachable;
}

test "cancel wakes a sleeping task with error.Canceled" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            var f = try env.io.concurrent(sleepForever, .{env.io});
            try env.advanceTimeNs(5 * std.time.ns_per_ms);
            try testing.expectError(error.Canceled, f.cancel(env.io));
            // Virtual time did not jump to the sleeper's deadline.
            try testing.expect(env.nowNs() < std.time.ns_per_s);
        }
    }.run, quiet);
}

fn protectedSleeper(io: Io, done: *bool) Io.Cancelable!void {
    const old = io.swapCancelProtection(.blocked);
    io.sleep(.fromMilliseconds(10), .awake) catch unreachable;
    _ = io.swapCancelProtection(old);
    done.* = true;
    try io.checkCancel(); // observes the deferred request
    unreachable;
}

test "cancel protection defers cancelation to the next unprotected point" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            var done = false;
            var f = try env.io.concurrent(protectedSleeper, .{ env.io, &done });
            try env.advanceTimeNs(std.time.ns_per_ms);
            try testing.expectError(error.Canceled, f.cancel(env.io));
            try testing.expect(done);
        }
    }.run, quiet);
}

test "group cancel stops all members" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            var group: Io.Group = .init;
            var i: u32 = 0;
            while (i < 3) : (i += 1) try group.concurrent(env.io, sleepForever, .{env.io});
            try env.advanceTimeNs(std.time.ns_per_ms);
            group.cancel(env.io);
        }
    }.run, quiet);
}

fn waitForFlag(io: Io, flag: *u32) void {
    while (@atomicLoad(u32, flag, .acquire) == 0) io.futexWaitUncancelable(u32, flag, 0);
}

test "deadlock is reported as an error, not a hang" {
    const r = tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            var flag: u32 = 0;
            var f = try env.io.concurrent(waitForFlag, .{ env.io, &flag });
            f.await(env.io); // nobody ever sets the flag
        }
    }.run, .{ .iterations = 3, .determinism_check_every = 0, .report = false });
    try testing.expectError(error.Deadlock, r);
}

fn setFlag(io: Io, flag: *u32) void {
    @atomicStore(u32, flag, 1, .release);
    io.futexWake(u32, flag, 1);
}

test "async-vs-concurrent misuse deadlocks when async runs inline" {
    // `waitForFlag` needs a concurrent partner, but `io.async` may run it
    // inline, so the flag is never set. TARDIS explores the inline choice.
    const r = tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            var flag: u32 = 0;
            var waiter = env.io.async(waitForFlag, .{ env.io, &flag });
            setFlag(env.io, &flag);
            waiter.await(env.io);
        }
    }.run, .{ .iterations = 50, .async_inline_ppm = 300_000, .determinism_check_every = 0, .report = false });
    try testing.expectError(error.Deadlock, r);
}

test "random bytes and schedules are deterministic per seed" {
    const Body = struct {
        fn run(env: *tardis.Env) !void {
            var buf: [16]u8 = undefined;
            env.io.random(&buf);
            var mutex: Io.Mutex = .init;
            var counter: u32 = 0;
            var group: Io.Group = .init;
            var i: u32 = 0;
            while (i < 3) : (i += 1) try group.concurrent(env.io, worker, .{ env.io, &counter, &mutex, 3 });
            try group.await(env.io);
        }
    };
    const a = try tardis.traceHash(testing.allocator, Body.run, 1234, .linux_ext4, .{});
    const b = try tardis.traceHash(testing.allocator, Body.run, 1234, .linux_ext4, .{});
    const c = try tardis.traceHash(testing.allocator, Body.run, 1235, .linux_ext4, .{});
    try testing.expectEqual(a, b);
    try testing.expect(a != c);
}

test "sometimes() fails a campaign that never reaches the condition" {
    const r = tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            env.sometimes("impossible", false);
        }
    }.run, .{ .iterations = 5, .report = false });
    try testing.expectError(error.SometimesNeverTrue, r);
}

test "leaked task is reported" {
    const r = tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            _ = try env.io.concurrent(sleepForever, .{env.io}); // never awaited
        }
    }.run, .{ .iterations = 1, .report = false });
    try testing.expectError(error.ResourceLeak, r);
}

test "crash drops in-flight tasks and their group no longer blocks" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            var group: Io.Group = .init;
            var i: u32 = 0;
            while (i < 3) : (i += 1) try group.concurrent(env.io, sleepForever, .{env.io});
            try env.advanceTimeNs(std.time.ns_per_ms);
            try env.crashAndReboot(.process_crash);
            try group.await(env.io);
            try testing.expectEqual(@as(u32, 1), env.crashCount());
        }
    }.run, quiet);
}

// --- a thousand tasks ---------------------------------------------------------

var thousand_ran: u32 = 0;
var thousand_order_sum: u64 = 0;

fn oneOfAThousand(io: Io, index: u32, total: *u32) Io.Cancelable!void {
    // Sleeps of different lengths, so the tasks finish in an order of
    // their own, and each is rescheduled several times.
    for (0..3) |round| try io.sleep(.fromNanoseconds(1 + (index * 7 + round) % 13), .awake);
    total.* += 1;
    thousand_order_sum +%= @as(u64, total.*) * (index + 1);
}

fn thousandTasks(env: *tardis.Env) !void {
    var total: u32 = 0;
    var group: Io.Group = .init;
    defer group.cancel(env.io);
    for (0..1000) |i| try group.concurrent(env.io, oneOfAThousand, .{ env.io, @as(u32, @intCast(i)), &total });
    try group.await(env.io);
    try testing.expectEqual(@as(u32, 1000), total);
    thousand_ran += 1;
}

test "a thousand tasks: every one runs to its end, and the same seed finishes them in the same order" {
    // Not when the environment chooses the runs or keeps some between
    // checks: the campaigns below are compared with each other.
    for ([_][]const u8{ "TARDIS_EXPLORE", "TARDIS_PRESET", "TARDIS_SEED", "TARDIS_REPLAY", "TARDIS_CORPUS_DIR", "TARDIS_CAMPAIGN_SALT", "TARDIS_ITERATIONS_SCALE" }) |name| {
        if (testing.environ.getAlloc(testing.allocator, name)) |value| {
            testing.allocator.free(value);
            return error.SkipZigTest;
        } else |_| {}
    }
    const options: tardis.Options = .{
        .iterations = 3,
        .determinism_check_every = 1,
        .limits = .{ .tasks_max = 1008, .fiber_stack_bytes = 64 * 1024 },
    };
    thousand_ran = 0;
    thousand_order_sum = 0;
    try tardis.check(testing.allocator, thousandTasks, options);
    // Each iteration and its determinism re-run.
    try testing.expectEqual(@as(u32, 6), thousand_ran);
    const first = thousand_order_sum;
    thousand_order_sum = 0;
    try tardis.check(testing.allocator, thousandTasks, options);
    try testing.expectEqual(first, thousand_order_sum);
    // The order is not the order of spawning every time.
    var other = options;
    other.campaign_seed = 99;
    thousand_order_sum = 0;
    try tardis.check(testing.allocator, thousandTasks, other);
    try testing.expect(first != thousand_order_sum);
}

fn noteThreadId(io: Io, out: *std.Thread.Id) Io.Cancelable!void {
    try io.sleep(.fromMicroseconds(1), .awake);
    out.* = tardis.threadId();
}

test "tardis.threadId: each task its own number, the same in every run" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            var ids: [4]std.Thread.Id = undefined;
            ids[0] = tardis.threadId();
            var group: Io.Group = .init;
            for (ids[1..]) |*id| try group.concurrent(env.io, noteThreadId, .{ env.io, id });
            try group.await(env.io);
            // The body's task is the second of the run (the first waits for
            // it); the three it spawns come next, in the order spawned.
            for (ids, 0..) |id, i| try testing.expectEqual(@as(std.Thread.Id, @intCast(0x2000_0001 + i)), id);
        }
    }.run, quiet);
    // Outside a simulation it is the real thread's.
    try testing.expectEqual(std.Thread.getCurrentId(), tardis.threadId());
}

fn yieldingWorker(io: Io, counter: *u32, yields: bool) Io.Cancelable!void {
    _ = io;
    const v = counter.*;
    if (yields) tardis.yield();
    counter.* = v + 1;
}

fn lostUpdate(comptime yields: bool) !void {
    return lostUpdateReporting(yields, null);
}

fn lostUpdateReporting(comptime yields: bool, report: ?*tardis.InterleaveReport) !void {
    return tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            var counter: u32 = 0;
            var group: Io.Group = .init;
            try group.concurrent(env.io, yieldingWorker, .{ env.io, &counter, yields });
            try group.concurrent(env.io, yieldingWorker, .{ env.io, &counter, yields });
            try group.await(env.io);
            try env.always("no lost update", counter == 2);
        }
    }.run, .{ .iterations = 30, .report = false, .interleave_report = report });
}

test "tardis.yield: a race with no switch point between its accesses is found only with one" {
    // Without a scheduling point each task runs its read and write at once,
    // and the test passes while testing nothing (docs/threads.md).
    try lostUpdate(false);
    try testing.expectError(error.AssertionFailed, lostUpdate(true));
    // Outside a simulation it does nothing.
    tardis.yield();
}

test "a check whose tasks never come between one another is told so" {
    // Two workers with no switch point: each runs to its end before the
    // other starts, in every run, and the check passes while testing
    // nothing. The report (and the warning a reporting check prints) says so.
    var none: tardis.InterleaveReport = .{};
    try lostUpdateReporting(false, &none);
    try testing.expectEqual(@as(u32, 30), none.several);
    try testing.expectEqual(@as(u32, 0), none.interleaved);
    // With a yield the second worker can start while the first waits at it.
    var some: tardis.InterleaveReport = .{};
    try testing.expectError(error.AssertionFailed, lostUpdateReporting(true, &some));
    try testing.expect(some.interleaved > 0);
    // One task besides the body is not several.
    var one: tardis.InterleaveReport = .{};
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            var f = try env.io.concurrent(struct {
                fn work(io: Io) void {
                    io.sleep(.fromMilliseconds(1), .awake) catch {};
                }
            }.work, .{env.io});
            f.await(env.io);
        }
    }.run, .{ .iterations = 5, .report = false, .interleave_report = &one });
    try testing.expectEqual(@as(u32, 0), one.several);
    // A daemon that sleeps (a server, chaos's healer) is not counted.
    var daemon: tardis.InterleaveReport = .{};
    try tardis.check(testing.allocator, struct {
        fn ticker(env: *tardis.Env) !void {
            while (true) try env.io.sleep(.fromMilliseconds(1), .awake);
        }
        fn run(env: *tardis.Env) !void {
            try env.spawnOn(0, ticker, .{env});
            var counter: u32 = 0;
            var group: Io.Group = .init;
            try group.concurrent(env.io, yieldingWorker, .{ env.io, &counter, false });
            try group.concurrent(env.io, yieldingWorker, .{ env.io, &counter, false });
            try group.await(env.io);
        }
    }.run, .{ .iterations = 10, .report = false, .interleave_report = &daemon });
    try testing.expectEqual(@as(u32, 10), daemon.several);
    try testing.expectEqual(@as(u32, 0), daemon.interleaved);
}
