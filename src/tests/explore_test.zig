//! M3: coverage-guided exploration.

const std = @import("std");
const tardis = @import("../root.zig");
const Io = std.Io;
const Env = tardis.Env;
const testing = std.testing;
const gpa = testing.allocator;

/// A bug behind five consecutive 1-in-16 choices: about one run in a
/// million reaches it at random. Each correct step is a coverage point.
fn combinationLock(env: *Env) !void {
    const code = [_]u8{ 7, 2, 13, 5, 11 };
    var depth: u64 = 0;
    for (code) |digit| {
        const d = (try env.fuzz(u8)) % 16;
        if (d != digit) break;
        depth += 1;
        env.cover("depth", depth);
    }
    try env.always("the lock stays shut", depth < code.len);
}

const lock_iterations = 6000;

test "explore: random exploration does not open a five-digit lock" {
    try tardis.check(gpa, combinationLock, .{ .iterations = lock_iterations, .determinism_check_every = 0 });
}

test "explore: guided exploration opens it, and the failure replays and shrinks" {
    var ex: tardis.ExploreReport = .{};
    var sh: tardis.ShrinkReport = .{};
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, combinationLock, .{
        .iterations = lock_iterations,
        .explore = .guided,
        .report = false,
        .explore_report = &ex,
        .shrink_report = &sh,
    }));
    try testing.expect(ex.failed_at != null);
    try testing.expect(ex.corpus >= 4); // one entry per depth reached before the last
    try testing.expect(ex.mutated_runs > 0);

    // The shrunk token (seed + forced decisions + kept decisions) replays.
    try testing.expect(sh.shrunk);
    try testing.expect(sh.after <= 5);
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, combinationLock, .{ .replay = sh.token(), .report = false, .shrink = false }));
}

// Coverage from the simulator itself: different I/O outcomes are different
// behaviour even without `env.cover`.
fn ioPaths(env: *Env) !void {
    const io = env.io;
    var f = env.dir.createFile(io, "data", .{}) catch return;
    defer f.close(io);
    f.writePositionalAll(io, "x", 0) catch |err| {
        env.sometimes("a write failed", true);
        return switch (err) {
            error.NoSpaceLeft, error.InputOutput => {},
            else => err,
        };
    };
    f.sync(io) catch {};
}

test "explore: guided campaigns grow a corpus from simulator coverage" {
    var ex: tardis.ExploreReport = .{};
    try tardis.check(gpa, ioPaths, .{
        .iterations = 200,
        .explore = .guided,
        .faults = .{ .io_error_ppm = 200_000 },
        .explore_report = &ex,
    });
    try testing.expect(ex.corpus >= 2);
    try testing.expect(ex.features >= 4);
}

fn guidedOn(workers: u32, ex: *tardis.ExploreReport, sh: *tardis.ShrinkReport) !void {
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, combinationLock, .{
        .iterations = lock_iterations,
        .explore = .guided,
        .workers = workers,
        .report = false,
        .explore_report = ex,
        .shrink_report = sh,
    }));
}

test "explore: guided exploration on several workers opens the lock, the same way for any worker count" {
    var ex2: tardis.ExploreReport = .{};
    var sh2: tardis.ShrinkReport = .{};
    var ex4: tardis.ExploreReport = .{};
    var sh4: tardis.ShrinkReport = .{};
    try guidedOn(2, &ex2, &sh2);
    try guidedOn(4, &ex4, &sh4);
    try testing.expect(ex2.failed_at != null);
    try testing.expectEqual(ex2.failed_at, ex4.failed_at);
    try testing.expectEqual(ex2.corpus, ex4.corpus);
    try testing.expectEqual(ex2.features, ex4.features);
    try testing.expectEqual(ex2.mutated_runs, ex4.mutated_runs);
    try testing.expectEqualStrings(sh2.token(), sh4.token());
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, combinationLock, .{ .replay = sh4.token(), .report = false, .shrink = false }));
}

test "explore: guided campaigns on several workers merge corpus and sometimes outcomes" {
    var ex: tardis.ExploreReport = .{};
    try tardis.check(gpa, ioPaths, .{
        .iterations = 200,
        .explore = .guided,
        .workers = 3,
        .epoch_iterations = 16,
        .faults = .{ .io_error_ppm = 200_000 },
        .explore_report = &ex,
    });
    try testing.expect(ex.corpus >= 2);
    try testing.expect(ex.features >= 4);
}
