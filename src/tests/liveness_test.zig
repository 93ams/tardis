//! F5 (plan3.md): a run that stays busy without making progress is a
//! finding (`Env.expectProgress`), not a hang.

const std = @import("std");
const tardis = @import("../root.zig");
const Env = tardis.Env;
const Io = std.Io;
const testing = std.testing;
const gpa = testing.allocator;

const quiet: tardis.Options = .{ .iterations = 10, .report = false, .shrink = false };

fn retriesForEver(env: *Env) !void {
    env.expectProgress("a request is answered", .{ .within_ns = 50 * std.time.ns_per_ms });
    // A client that retries a request nobody answers, with a pause between
    // attempts: virtual time passes, nothing is blocked for ever.
    // Bounded, as every loop here: without the watch the test fails, it
    // does not hang.
    for (0..spin_max) |_| try env.io.sleep(.fromMilliseconds(1), .awake);
}

/// Far more rounds than any bound in this file allows.
const spin_max = 200_000;

test "liveness: retries that sleep for ever are a livelock, by virtual time" {
    try testing.expectError(error.Livelock, tardis.check(gpa, retriesForEver, quiet));
}

fn spins(env: *Env, turn: *u32, mine: u32) void {
    // Each waits for its turn, and no one ever gives it: both stay
    // runnable, and virtual time stands still.
    for (0..spin_max) |_| {
        if (@atomicLoad(u32, turn, .acquire) == mine) break;
        env.dir.access(env.io, "turn", .{}) catch {};
    }
}

fn spinsForEver(env: *Env) !void {
    var turn: u32 = 0;
    env.expectProgress("a turn is taken", .{ .within_steps = 5_000 });
    var a = try env.io.concurrent(spins, .{ env, &turn, 1 });
    var b = try env.io.concurrent(spins, .{ env, &turn, 2 });
    a.await(env.io);
    b.await(env.io);
}

test "liveness: tasks that spin without sleeping are a livelock, by steps" {
    try testing.expectError(error.Livelock, tardis.check(gpa, spinsForEver, quiet));
}

test "liveness: a spinning task is found when no preemption is drawn, and while shrinking" {
    // Found by review (revision 85): steps were counted only where the
    // simulator switched tasks, so a task that span while another was
    // runnable and no preemption came was never stopped. Shrinking a
    // livelock runs exactly that (a dropped decision is no preemption).
    try testing.expectError(error.Livelock, tardis.check(gpa, spinsForEver, .{ .iterations = 3, .report = false, .shrink = false, .preempt_ppm = 0 }));
    var report: tardis.ShrinkReport = .{};
    try testing.expectError(error.Livelock, tardis.check(gpa, spinsForEver, .{ .iterations = 3, .report = false, .shrink_runs_max = 50, .shrink_report = &report }));
}

fn setupArms(env: *Env) !void {
    env.expectProgress("a request is answered", .{ .within_ns = 20 * std.time.ns_per_ms });
}

fn stopsAfterSetup(env: *Env) !void {
    for (0..spin_max) |_| try env.io.sleep(.fromMilliseconds(1), .awake);
}

test "liveness: a watch armed in setup is in force in every iteration" {
    // Found by review (revision 85): warm-started iterations began
    // without it.
    var log: tardis.FailureLog = .{};
    try testing.expectError(error.Livelock, tardis.check(gpa, stopsAfterSetup, .{ .iterations = 6, .report = false, .shrink = false, .setup = setupArms, .keep_going = &log }));
    try testing.expectEqual(@as(u32, 6), log.failures());
}

fn spinsAlone(env: *Env) !void {
    env.expectProgress("the loop ends", .{ .within_steps = 5_000 });
    // The only runnable task: it never reaches a scheduling point, and its
    // operations count as steps all the same.
    for (0..spin_max) |_| env.dir.access(env.io, "done", .{}) catch {};
}

test "liveness: a task that spins alone is a livelock" {
    try testing.expectError(error.Livelock, tardis.check(gpa, spinsAlone, quiet));
}

fn makesProgress(env: *Env) !void {
    // Unwatched: nothing to feed, nothing happens.
    env.progress("a request is answered");
    env.expectProgress("a request is answered", .{ .within_ns = 50 * std.time.ns_per_ms, .within_steps = 100_000 });
    for (0..100) |_| {
        try env.io.sleep(.fromMilliseconds(40), .awake);
        env.progress("a request is answered");
    }
    // A second watch does not disturb the first, and new bounds count as
    // progress.
    env.expectProgress("a batch is written", .{ .within_ns = std.time.ns_per_s });
    try env.io.sleep(.fromMilliseconds(45), .awake);
    env.expectProgress("a request is answered", .{ .within_ns = std.time.ns_per_s });
    try env.io.sleep(.fromMilliseconds(900), .awake);
    env.progressDone("a request is answered");
    env.progressDone("a batch is written");
    // Done: a long quiet time is no longer a finding.
    try env.io.sleep(.fromSeconds(3600), .awake);
}

test "liveness: a run that reports progress within its bounds passes, and a finished watch is not checked" {
    try tardis.check(gpa, makesProgress, .{ .iterations = 10 });
}

fn onlyOneStops(env: *Env) !void {
    env.expectProgress("reads", .{ .within_ns = 10 * std.time.ns_per_ms });
    env.expectProgress("writes", .{ .within_ns = 10 * std.time.ns_per_ms });
    // Reads go on; writes stop. Being busy elsewhere does not hide it.
    for (0..1000) |_| {
        try env.io.sleep(.fromMilliseconds(1), .awake);
        env.progress("reads");
    }
}

test "liveness: each watch is its own: progress on one does not feed another" {
    try testing.expectError(error.Livelock, tardis.check(gpa, onlyOneStops, quiet));
}

/// Livelocks only when the first byte drawn is a multiple of 8.
fn rareLivelock(env: *Env) !void {
    const x = try env.fuzz(u8);
    env.expectProgress("work is done", .{ .within_ns = 20 * std.time.ns_per_ms });
    if (x % 8 == 0) {
        for (0..spin_max) |_| try env.io.sleep(.fromMilliseconds(1), .awake);
    }
    env.progressDone("work is done");
}

test "liveness: a livelock is found by a campaign, shrinks, and its token replays to the same error" {
    var report: tardis.ShrinkReport = .{};
    try testing.expectError(error.Livelock, tardis.check(gpa, rareLivelock, .{ .iterations = 200, .report = false, .shrink_report = &report }));
    try testing.expect(report.token().len > 0);
    for (0..3) |_| {
        try testing.expectError(error.Livelock, tardis.check(gpa, rareLivelock, .{ .replay = report.token(), .report = false }));
    }
}

fn countsRuns(env: *Env) !void {
    _ = env;
    runs += 1;
}

var runs: u32 = 0;

test "presets: each is the defaults with a campaign of its size, and a preset fills in only what a check left alone" {
    const defaults: tardis.Options = .{};
    const quick: tardis.Options = .quick;
    const nightly: tardis.Options = .nightly;
    try testing.expectEqual(@as(u32, 20), quick.iterations);
    try testing.expectEqual(tardis.Explore.guided, nightly.explore);
    try testing.expectEqual(defaults.preempt_ppm, nightly.preempt_ppm);

    var o: tardis.Options = .{};
    tardis.Preset.nightly.apply(&o);
    try testing.expectEqual(@as(u32, 10_000), o.iterations);
    try testing.expectEqual(tardis.Explore.guided, o.explore);
    // A check that chose its own size keeps it.
    o = .{ .iterations = 5 };
    tardis.Preset.thorough.apply(&o);
    try testing.expectEqual(@as(u32, 5), o.iterations);
    try testing.expectEqual(tardis.Explore.random, o.explore);
    // Guided exploration would change what `keep_going` promises.
    var log: tardis.FailureLog = .{};
    o = .{ .keep_going = &log };
    tardis.Preset.nightly.apply(&o);
    try testing.expectEqual(tardis.Explore.random, o.explore);

    // A preset as the whole argument.
    runs = 0;
    try tardis.check(gpa, countsRuns, .quick);
    try testing.expect(runs >= 20);
}

fn noSetup(env: *Env) !void {
    _ = env;
}

test "liveness: a livelock or a deadlock in a forked iteration is a failed run, not a second test process" {
    // Found by review (revision 85): the child returned through the
    // driver it had inherited from the parent.
    try testing.expectError(error.Livelock, tardis.check(gpa, retriesForEver, .{ .iterations = 3, .report = false, .shrink = false, .fork = true, .setup = noSetup }));
    try testing.expectError(error.Deadlock, tardis.check(gpa, waitsForEver, .{ .iterations = 3, .report = false, .shrink = false, .fork = true, .setup = noSetup }));
}

fn neverSet(io: Io, flag: *u32) void {
    while (@atomicLoad(u32, flag, .acquire) == 0) io.futexWaitUncancelable(u32, flag, 0);
}

fn waitsForEver(env: *Env) !void {
    var flag: u32 = 0;
    var f = try env.io.concurrent(neverSet, .{ env.io, &flag });
    f.await(env.io);
}
