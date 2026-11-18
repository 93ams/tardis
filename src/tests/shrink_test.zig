//! M3: shrinking failures to their essential decisions, and replay tokens.

const std = @import("std");
const tardis = @import("../root.zig");
const Io = std.Io;
const Env = tardis.Env;
const testing = std.testing;
const gpa = testing.allocator;

fn tornRename(env: *Env) !void {
    const io = env.io;
    {
        var f = try env.dir.createFile(io, "config", .{});
        defer f.close(io);
        try f.writePositionalAll(io, "old-config", 0);
        try f.sync(io);
    }
    {
        var t = try env.dir.createFile(io, "config.tmp", .{});
        defer t.close(io);
        try t.writePositionalAll(io, "new-config", 0);
    }
    try env.dir.rename("config.tmp", env.dir, "config", io);
    var d = try env.dir.openFile(io, ".", .{});
    try d.sync(io);
    d.close(io);
    try env.crashAndReboot(.power_loss);
    var buf: [32]u8 = undefined;
    const got = try env.dir.readFile(io, "config", &buf);
    try env.always("config is old or new", std.mem.eql(u8, got, "old-config") or std.mem.eql(u8, got, "new-config"));
}

test "shrink: a torn rename shrinks to one crash decision, and its token replays" {
    var report: tardis.ShrinkReport = .{};
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, tornRename, .{
        .iterations = 40,
        .personas = &.{.linux_xfs},
        .report = false,
        .shrink_report = &report,
    }));
    try testing.expect(report.shrunk);
    try testing.expect(report.before > 10);
    // A handful of crash decisions (which pages and entries are lost)
    // explain the tear; how many depends on the failing seed.
    try testing.expect(report.after >= 1 and report.after <= 3);

    // The token alone reproduces the failure.
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, tornRename, .{
        .replay = report.token(),
        .report = false,
        .shrink = false,
    }));
    // With every decision benign, the same seed passes.
    // (`persona:seed:` with an empty kept set and nothing forced.)
    const first = std.mem.indexOfScalar(u8, report.token(), ':').?;
    const colon = std.mem.indexOfScalarPos(u8, report.token(), first + 1, ':').?;
    try tardis.check(gpa, tornRename, .{ .replay = report.token()[0 .. colon + 1] });
}

/// A check that fails for some inputs; `extra` draws come before them, as
/// when code is edited after a token was recorded.
fn Edited(comptime extra: u8) type {
    return struct {
        fn body(env: *Env) !void {
            inline for (0..extra) |_| _ = try env.fuzz(u8);
            const a = try env.fuzz(u16);
            const b = try env.fuzz(u8);
            if (a % 7 == 3 and b > 200) return error.Planted;
        }
    };
}

test "fuzzy replay: a token still fails after an edit that adds or removes a draw before its decisions" {
    var shrunk: tardis.ShrinkReport = .{};
    try testing.expectError(error.Planted, tardis.check(gpa, Edited(1).body, .{ .iterations = 2000, .report = false, .shrink_report = &shrunk }));
    try testing.expect(shrunk.shrunk and shrunk.after == 2);
    try testing.expectError(error.Planted, tardis.check(gpa, Edited(1).body, .{ .replay = shrunk.token(), .report = false }));
    // An integer from `env.fuzz` is two draws, so each `extra` moves the
    // decisions by two.
    inline for (.{ .{ 2, 2 }, .{ 0, -2 } }) |edit| {
        // As written the token passes on the edited code: its keys name
        // other draws now.
        try tardis.check(gpa, Edited(edit[0]).body, .{ .replay = shrunk.token() });
        var report: tardis.ReplayReport = .{};
        try testing.expectError(error.Planted, tardis.check(gpa, Edited(edit[0]).body, .{
            .replay = shrunk.token(),
            .replay_fuzzy = 2,
            .replay_report = &report,
            .report = false,
        }));
        try testing.expect(report.fuzzy);
        try testing.expectEqual(@as(u32, 2), report.moved);
        try testing.expectEqual(@as(i16, edit[1]), report.shift);
        // The token it reports fits the edited code as written.
        try testing.expectError(error.Planted, tardis.check(gpa, Edited(edit[0]).body, .{ .replay = report.token(), .report = false }));
    }
    // A window too small finds nothing, and the replay passes.
    var none: tardis.ReplayReport = .{};
    try tardis.check(gpa, Edited(3).body, .{ .replay = shrunk.token(), .replay_fuzzy = 2, .replay_report = &none });
    try testing.expect(!none.fuzzy and none.runs > 1);
}

test "traceJson: a run, or a replay token, as a Chrome trace that parses" {
    var limits: tardis.Limits = .{};
    limits.trace_ring_len = 4096;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    // The torn rename fails under its token, and is traced all the same.
    var report: tardis.ShrinkReport = .{};
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, tornRename, .{ .iterations = 40, .personas = &.{.linux_xfs}, .report = false, .shrink_report = &report }));
    try testing.expectError(error.AssertionFailed, tardis.traceJson(gpa, tornRename, 0, .linux_ext4, .{ .replay = report.token(), .limits = limits }, &out.writer));
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, out.written(), .{});
    defer parsed.deinit();
    const events = parsed.value.array.items;
    try testing.expect(events.len > 10);
    var renames: usize = 0;
    var crashes: usize = 0;
    var last_ts: f64 = 0;
    for (events) |e| {
        const name = e.object.get("name").?.string;
        if (std.mem.eql(u8, name, "rename")) renames += 1;
        if (std.mem.eql(u8, name, "crash")) crashes += 1;
        const ts: f64 = switch (e.object.get("ts").?) {
            .float => |f| f,
            .integer => |n| @floatFromInt(n),
            else => return error.TestUnexpectedResult,
        };
        try testing.expect(ts >= last_ts); // oldest first
        last_ts = ts;
        try testing.expectEqualStrings("i", e.object.get("ph").?.string);
    }
    try testing.expect(renames >= 1 and crashes == 1);
}

fn racyWorker(io: Io, counter: *u32) Io.Cancelable!void {
    const v = counter.*;
    try io.sleep(.fromMicroseconds(1), .awake);
    counter.* = v + 1;
}

fn lostUpdate(env: *Env) !void {
    var counter: u32 = 0;
    var group: Io.Group = .init;
    for (0..4) |_| try group.concurrent(env.io, racyWorker, .{ env.io, &counter });
    try group.await(env.io);
    try env.always("no lost update", counter == 4);
}

test "shrink: a lost-update race shrinks to a handful of scheduling decisions" {
    var report: tardis.ShrinkReport = .{};
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, lostUpdate, .{
        .iterations = 30,
        .report = false,
        .shrink_report = &report,
    }));
    try testing.expect(report.shrunk);
    try testing.expect(report.after < report.before);
    try testing.expect(report.after <= 4);
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, lostUpdate, .{ .replay = report.token(), .report = false, .shrink = false }));
}

fn fuzzThreshold(env: *Env) !void {
    // Lots of irrelevant decisions around one that matters.
    for (0..20) |_| _ = try env.fuzz(u16);
    try env.io.sleep(.fromMilliseconds(1), .awake);
    const x = try env.fuzz(u32);
    for (0..20) |_| _ = try env.fuzz(u16);
    try env.always("x is small", x < 3_000_000_000);
}

test "shrink: irrelevant fuzz input is zeroed, the one relevant draw kept" {
    var report: tardis.ShrinkReport = .{};
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, fuzzThreshold, .{
        .iterations = 50,
        .report = false,
        .shrink_report = &report,
    }));
    try testing.expect(report.shrunk);
    try testing.expect(report.before >= 41);
    try testing.expectEqual(@as(usize, 1), report.after);
}

fn alwaysFails(env: *Env) !void {
    _ = env;
    return error.Broken;
}

test "shrink: a failure that needs no decisions shrinks to zero" {
    var report: tardis.ShrinkReport = .{};
    try testing.expectError(error.Broken, tardis.check(gpa, alwaysFails, .{ .iterations = 1, .report = false, .shrink_report = &report }));
    try testing.expect(report.shrunk);
    try testing.expectEqual(@as(usize, 0), report.after);
    // All benign (fails), then the run that records values for value shrinking.
    try testing.expectEqual(@as(u32, 2), report.runs);
}

test "shrink: a malformed replay token is rejected" {
    try testing.expectError(error.BadReplayToken, tardis.check(gpa, alwaysFails, .{ .replay = "not-a-token", .report = false }));
}

var last_pair: [2]u32 = .{ 0, 0 };

/// Fails when `a + b >= 5000`: the minimal failing input is on the boundary.
fn sumTooLarge(env: *Env) !void {
    const a = try env.fuzz(u32);
    const b = try env.fuzz(u32);
    last_pair = .{ a, b };
    try env.always("a + b < 5000", @as(u64, a) + b < 5000);
}

test "shrink: values are lowered to the boundary of the failure" {
    var report: tardis.ShrinkReport = .{};
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, sumTooLarge, .{ .iterations = 10, .report = false, .shrink_report = &report }));
    try testing.expect(report.shrunk);
    try testing.expect(report.values >= 1);
    // The final re-run is the shrunk case: exactly on the boundary.
    try testing.expectEqual(@as(u64, 5000), @as(u64, last_pair[0]) + last_pair[1]);
    // Its token replays to the same input.
    const shrunk = last_pair;
    last_pair = .{ 0, 0 };
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, sumTooLarge, .{ .replay = report.token(), .report = false, .shrink = false }));
    try testing.expectEqual(shrunk, last_pair);
}

test "shrink under sim: a failure reported with fail() shrinks like under check, and its token replays" {
    var report: tardis.ShrinkReport = .{};
    var s = try tardis.sim(gpa, .{ .iterations = 10, .report = false, .shrink_report = &report });
    defer s.deinit();
    var iterations: u32 = 0;
    while (s.step()) |env| {
        iterations += 1;
        sumTooLarge(env) catch |err| s.fail(err);
    }
    try testing.expectError(error.AssertionFailed, s.finish());
    try testing.expect(report.shrunk);
    try testing.expect(iterations > report.runs); // the shrink candidates ran through the loop
    // The last run through the loop was the shrunk one: on the boundary.
    try testing.expectEqual(@as(u64, 5000), @as(u64, last_pair[0]) + last_pair[1]);

    // `check` shrinks the same failure to the same token.
    var via_check: tardis.ShrinkReport = .{};
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, sumTooLarge, .{ .iterations = 10, .report = false, .shrink_report = &via_check }));
    try testing.expectEqualStrings(via_check.token(), report.token());

    // The token replays under `sim`: one iteration, same input.
    last_pair = .{ 0, 0 };
    var r = try tardis.sim(gpa, .{ .replay = report.token(), .report = false });
    defer r.deinit();
    var runs: u32 = 0;
    while (r.step()) |env| {
        runs += 1;
        sumTooLarge(env) catch |err| r.fail(err);
    }
    try testing.expectError(error.AssertionFailed, r.finish());
    try testing.expectEqual(@as(u32, 1), runs);
    try testing.expectEqual(@as(u64, 5000), @as(u64, last_pair[0]) + last_pair[1]);
}

test "shrink under sim: shrink = false stops at the failure" {
    var s = try tardis.sim(gpa, .{ .iterations = 10, .report = false, .shrink = false });
    defer s.deinit();
    var iterations: u32 = 0;
    while (s.step()) |env| {
        iterations += 1;
        sumTooLarge(env) catch |err| s.fail(err);
    }
    try testing.expectError(error.AssertionFailed, s.finish());
    try testing.expect(iterations <= 10);
}

fn oddInputFails(env: *Env) !void {
    const x = try env.fuzz(u8);
    try env.always("input is even", x & 1 == 0);
}

test "keep going: every failing iteration is shrunk and logged, and the first error is returned" {
    var log: tardis.FailureLog = .{};
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, oddInputFails, .{
        .iterations = 40,
        .report = false,
        .keep_going = &log,
    }));
    // About half of 40 inputs are odd; each is its own entry, in order.
    try testing.expect(log.len >= 10 and log.len <= 30);
    try testing.expectEqual(@as(u32, 0), log.dropped);
    var prev: ?u32 = null;
    for (log.slice()) |*e| {
        try testing.expect(e.shrunk);
        try testing.expectEqual(@as(anyerror, error.AssertionFailed), e.err);
        if (prev) |p| try testing.expect(e.iteration > p);
        prev = e.iteration;
        // The shrunk token still fails the same way.
        try testing.expectError(error.AssertionFailed, tardis.check(gpa, oddInputFails, .{ .replay = e.token(), .report = false }));
    }
    try testing.expectEqual(log.entries[0].seed, log.bySeed(log.entries[0].seed).?.seed);
}

fn expectSameLog(a: *const tardis.FailureLog, b: *const tardis.FailureLog) !void {
    try testing.expectEqual(a.len, b.len);
    try testing.expectEqual(a.dropped, b.dropped);
    for (a.slice(), b.slice()) |*x, *y| {
        try testing.expectEqual(x.iteration, y.iteration);
        try testing.expectEqual(x.persona, y.persona);
        try testing.expectEqual(x.seed, y.seed);
        try testing.expectEqual(x.err, y.err);
        try testing.expectEqual(x.shrunk, y.shrunk);
        try testing.expectEqualStrings(x.token(), y.token());
    }
}

test "keep going on 4 workers logs the same failures, tokens and overflow as one thread" {
    // 120 iterations on two personas: about 120 failures, more than the
    // log keeps, so the kept 32 and the dropped count are compared too.
    const base: tardis.Options = .{ .iterations = 120, .personas = &.{ .linux_ext4, .windows_ntfs }, .report = false };
    var one: tardis.FailureLog = .{};
    var many: tardis.FailureLog = .{};
    var o1 = base;
    o1.keep_going = &one;
    var o4 = base;
    o4.keep_going = &many;
    o4.workers = 4;
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, oddInputFails, o1));
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, oddInputFails, o4));
    try testing.expectEqual(@as(u32, tardis.FailureLog.entries_max), one.len);
    try testing.expect(one.dropped > 0);
    try expectSameLog(&one, &many);
}
