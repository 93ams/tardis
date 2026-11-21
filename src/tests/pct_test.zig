//! Priority scheduling (`Options.schedule = .pct`, plan3.md E5): the
//! runnable task with the highest priority runs, and a run changes a
//! priority at `pct_depth - 1` points.

const std = @import("std");
const tardis = @import("../root.zig");
const Io = std.Io;
const testing = std.testing;

/// No fault makes a file operation block: a task then stops only where
/// the scheduler stops it.
const still: tardis.FaultOptions = .{ .io_error_ppm = 0, .short_io_ppm = 0, .io_latency_min_ns = 0, .io_latency_max_ns = 0 };

fn read(io: Io, dir: Io.Dir) !u64 {
    var buf: [8]u8 = undefined;
    const bytes = try dir.readFile(io, "count", &buf);
    if (bytes.len != 8) return error.Corrupt;
    return std.mem.readInt(u64, bytes[0..8], .little);
}

fn write(io: Io, dir: Io.Dir, count: u64) !void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, count, .little);
    try dir.writeFile(io, .{ .sub_path = "count", .data = &buf });
}

/// Reads the count and writes it back plus one, with nothing held.
fn increment(io: Io, dir: Io.Dir, failed: *bool) Io.Cancelable!void {
    const count = read(io, dir) catch {
        failed.* = true;
        return;
    };
    write(io, dir, count + 1) catch {
        failed.* = true;
    };
}

fn lostUpdate(env: *tardis.Env) !void {
    const io = env.io;
    try write(io, env.dir, 0);
    var failed = false;
    var group: Io.Group = .init;
    defer group.cancel(io);
    for (0..3) |_| try group.concurrent(io, increment, .{ io, env.dir, &failed });
    try group.await(io);
    try env.always("no increment is lost", !failed and try read(io, env.dir) == 3);
}

test "pct: a lost update that needs a preemption is found, shrunk and replayed" {
    var shrunk: tardis.ShrinkReport = .{};
    const options: tardis.Options = .{ .iterations = 300, .schedule = .pct, .faults = still, .swarm = false, .report = false, .shrink_report = &shrunk };
    try testing.expectError(error.AssertionFailed, tardis.check(testing.allocator, lostUpdate, options));
    try testing.expect(shrunk.shrunk);
    try testing.expect(shrunk.after <= shrunk.before);
    // The token of the shrunk run fails the same way under the same options.
    var replay = options;
    replay.shrink_report = null;
    replay.replay = shrunk.token();
    try testing.expect(shrunk.token().len != 0);
    try testing.expectError(error.AssertionFailed, tardis.check(testing.allocator, lostUpdate, replay));
}

test "pct: at depth 1 no task is stopped between two operations" {
    // Each run is one order of the tasks: whichever has the highest
    // priority runs until it ends, so no increment is lost.
    try tardis.check(testing.allocator, lostUpdate, .{ .iterations = 300, .schedule = .pct, .pct_depth = 1, .faults = still, .swarm = false });
}

test "pct: the random schedule finds the same bug (the scenario is sound)" {
    try testing.expectError(error.AssertionFailed, tardis.check(testing.allocator, lostUpdate, .{ .iterations = 300, .faults = still, .swarm = false, .report = false, .shrink = false }));
}

fn setFlag(io: Io, dir: Io.Dir) Io.Cancelable!void {
    dir.writeFile(io, .{ .sub_path = "flag", .data = "x" }) catch {};
}

/// Polls for the flag without ever blocking.
fn poll(io: Io, dir: Io.Dir, polls: *u32) Io.Cancelable!void {
    var buf: [1]u8 = undefined;
    while (true) {
        polls.* += 1;
        if (dir.readFile(io, "flag", &buf)) |_| return else |_| {}
    }
}

var polls_max: u32 = 0;

fn polling(env: *tardis.Env) !void {
    const io = env.io;
    var polls: u32 = 0;
    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, poll, .{ io, env.dir, &polls });
    try group.concurrent(io, setFlag, .{ io, env.dir });
    try group.await(io);
    polls_max = @max(polls_max, polls);
}

test "pct: a task that polls without blocking does not starve the others" {
    polls_max = 0;
    // Depth 1 changes no priority: when the poller is above the task it
    // waits for, only the bound on one task's steps in a row ends the run.
    try tardis.check(testing.allocator, polling, .{ .iterations = 60, .schedule = .pct, .pct_depth = 1, .faults = still, .swarm = false });
    // Some run did have the poller on top, and it gave way at the bound.
    try testing.expect(polls_max > 1000);
    try testing.expect(polls_max <= 2 * tardis.Sim.pct_spin_max);
}

fn work(io: Io, dir: Io.Dir, done: *bool) Io.Cancelable!void {
    for (0..40) |_| dir.writeFile(io, .{ .sub_path = "a", .data = "x" }) catch {};
    done.* = true;
}

fn look(io: Io, dir: Io.Dir, other_done: *const bool, saw: *bool) Io.Cancelable!void {
    dir.writeFile(io, .{ .sub_path = "look", .data = "x" }) catch {};
    saw.* = other_done.*;
}

/// Fails when one task does its forty operations while the other does
/// one: an order the random schedule gives about once in a thousand runs
/// and priorities about every other run.
fn longStretch(env: *tardis.Env) !void {
    var done = false;
    var saw = false;
    var group: Io.Group = .init;
    defer group.cancel(env.io);
    try group.concurrent(env.io, work, .{ env.io, env.dir, &done });
    try group.concurrent(env.io, look, .{ env.io, env.dir, &done, &saw });
    try group.await(env.io);
    try env.always("the second task looks before the first has finished", !saw);
}

const stretch: tardis.Options = .{ .iterations = 50, .faults = still, .swarm = false, .report = false, .shrink = false };

test "pct: reaches an order the random schedule does not, in every way a campaign runs" {
    // The same campaign passes at random: what follows is the option's doing.
    try tardis.check(testing.allocator, longStretch, stretch);
    var o = stretch;
    o.schedule = .pct;
    try testing.expectError(error.AssertionFailed, tardis.check(testing.allocator, longStretch, o));
    var fixed = o;
    fixed.pct_depth = 2;
    fixed.pct_steps = 24;
    try testing.expectError(error.AssertionFailed, tardis.check(testing.allocator, longStretch, fixed));
    var guided = o;
    guided.explore = .guided;
    try testing.expectError(error.AssertionFailed, tardis.check(testing.allocator, longStretch, guided));
    var workers = o;
    workers.workers = 3;
    try testing.expectError(error.AssertionFailed, tardis.check(testing.allocator, longStretch, workers));
    // Shrunk, and the token fails again. (It may fail at random too: a
    // run shrunk to no decision at all is the same run under both.)
    var shrunk: tardis.ShrinkReport = .{};
    var shrinking = o;
    shrinking.shrink = true;
    shrinking.shrink_report = &shrunk;
    try testing.expectError(error.AssertionFailed, tardis.check(testing.allocator, longStretch, shrinking));
    try testing.expect(shrunk.shrunk and shrunk.token().len != 0);
    var replay = o;
    replay.replay = shrunk.token();
    try testing.expectError(error.AssertionFailed, tardis.check(testing.allocator, longStretch, replay));
}

fn ping(io: Io, q: *Io.Queue(u32), stop: *const bool) Io.Cancelable!void {
    while (!stop.*) q.putOne(io, 1) catch return;
}

fn pong(io: Io, q: *Io.Queue(u32), stop: *const bool, turns: *u32) Io.Cancelable!void {
    while (!stop.*) {
        _ = q.getOne(io) catch return;
        turns.* += 1;
    }
}

fn setStop(io: Io, dir: Io.Dir, stop: *bool) void {
    dir.writeFile(io, .{ .sub_path = "stop", .data = "x" }) catch {};
    stop.* = true;
}

var turns_max: u32 = 0;

/// Two tasks pass a value back and forth, each blocking in turn, until a
/// third says stop. One of the two can always run.
fn passing(env: *tardis.Env) !void {
    const io = env.io;
    var stop = false;
    var turns: u32 = 0;
    var buf: [1]u32 = undefined;
    var q: Io.Queue(u32) = .init(&buf);
    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, ping, .{ io, &q, &stop });
    try group.concurrent(io, pong, .{ io, &q, &stop, &turns });
    var stopper = try io.concurrent(setStop, .{ io, env.dir, &stop });
    stopper.await(io);
    turns_max = @max(turns_max, turns);
}

test "pct: two tasks that take turns by blocking do not starve a third" {
    turns_max = 0;
    try tardis.check(testing.allocator, passing, .{ .iterations = 60, .schedule = .pct, .pct_depth = 1, .faults = still, .swarm = false });
    // Some run had both above the third, which then had to wait its bound.
    try testing.expect(turns_max > 500);
}

var setup_ran: u32 = 0;

fn setup(env: *tardis.Env) !void {
    setup_ran += 1;
    try write(env.io, env.dir, 0);
}

fn afterSetup(env: *tardis.Env) !void {
    const io = env.io;
    var failed = false;
    var group: Io.Group = .init;
    defer group.cancel(io);
    for (0..3) |_| try group.concurrent(io, increment, .{ io, env.dir, &failed });
    try group.await(io);
    try env.always("no increment is lost", !failed and try read(io, env.dir) == 3);
}

test "pct: a run from a snapshot of its setup is the run that ran its setup" {
    // The same campaign with and without the snapshot fails at the same
    // iteration with the same reproduction. One change point among 400
    // steps makes the failure rare, so that it comes after runs that
    // did start from the snapshot.
    var tokens: [2][256]u8 = undefined;
    var lens: [2]usize = .{ 0, 0 };
    var setups: [2]u32 = .{ 0, 0 };
    for ([_]bool{ true, false }, 0..) |warm, i| {
        var shrunk: tardis.ShrinkReport = .{};
        var report: tardis.WarmReport = .{};
        setup_ran = 0;
        try testing.expectError(error.AssertionFailed, tardis.check(testing.allocator, afterSetup, .{ .iterations = 3000, .schedule = .pct, .pct_depth = 2, .pct_steps = 400, .setup = setup, .warm_restore = warm, .warm_report = &report, .faults = still, .swarm = false, .report = false, .shrink_report = &shrunk }));
        // The security layer on every check turns warm starts off.
        if (!tardis.security_by_default) try testing.expect((report.restores > 0) == warm);
        setups[i] = setup_ran;
        const t = shrunk.token();
        try testing.expect(t.len != 0 and t.len <= tokens[i].len);
        @memcpy(tokens[i][0..t.len], t);
        lens[i] = t.len;
    }
    try testing.expectEqualStrings(tokens[0][0..lens[0]], tokens[1][0..lens[1]]);
    if (!tardis.security_by_default) try testing.expect(setups[0] < setups[1]);
}
