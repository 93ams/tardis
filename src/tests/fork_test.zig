//! M5: warm starts (`Options.setup`) and the fork server (`Options.fork`).
//! On Linux `fork = true` forks a child per iteration; elsewhere it runs
//! in-process. Both must give the same answers.

const std = @import("std");
const builtin = @import("builtin");
const tardis = @import("../root.zig");
const Env = tardis.Env;
const testing = std.testing;
const gpa = testing.allocator;

/// Expensive-looking, deterministic warm-up: 50 files and a random token.
fn warmUp(env: *Env) !void {
    const io = env.io;
    var token: [8]u8 = undefined;
    io.random(&token);
    try env.dir.writeFile(io, .{ .sub_path = "token", .data = &token });
    for (0..50) |i| {
        var name: [16]u8 = undefined;
        try env.dir.writeFile(io, .{ .sub_path = try std.fmt.bufPrint(&name, "f{d}", .{i}), .data = "warm" });
    }
}

var first_token: ?[8]u8 = null;

fn sameWarmState(env: *Env) !void {
    const io = env.io;
    var buf: [8]u8 = undefined;
    const token = try env.dir.readFile(io, "token", &buf);
    // The warm-up is identical in every iteration...
    if (first_token) |t| try testing.expectEqualSlices(u8, &t, token) else first_token = buf;
    _ = try env.dir.statFile(io, "f49", .{});
    // ...and the body still varies.
    var mine: [1]u8 = undefined;
    io.random(&mine);
    env.sometimes("body randomness differs from the warm-up", mine[0] != token[0]);
    env.sometimes("body randomness is odd", mine[0] % 2 == 1);
}

test "fork: every iteration starts from the same warm state, then diverges" {
    first_token = null;
    try tardis.check(gpa, sameWarmState, .{ .iterations = 40, .setup = warmUp, .fork = true });
    first_token = null;
    try tardis.check(gpa, sameWarmState, .{ .iterations = 40, .setup = warmUp });
}

fn bugAfterWarmUp(env: *Env) !void {
    const x = try env.fuzz(u16);
    try env.always("x is not a multiple of 61", x % 61 != 0 or x == 0);
}

test "fork: the same failure and shrunk token with and without forking" {
    var forked: tardis.ShrinkReport = .{};
    var in_process: tardis.ShrinkReport = .{};
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, bugAfterWarmUp, .{ .iterations = 1000, .setup = warmUp, .fork = true, .report = false, .shrink_report = &forked }));
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, bugAfterWarmUp, .{ .iterations = 1000, .setup = warmUp, .report = false, .shrink_report = &in_process }));
    try testing.expectEqualStrings(in_process.token(), forked.token());
    // The shrunk token replays (setup included).
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, bugAfterWarmUp, .{ .setup = warmUp, .replay = forked.token(), .report = false, .shrink = false }));
}

fn crashes(env: *Env) !void {
    const x = try env.fuzz(u8);
    if (x == 200) @panic("simulated crash in the code under test");
}

test "fork: a child that crashes is reported, and the parent survives" {
    if (!tardis.fork_supported) return error.SkipZigTest;
    try testing.expectError(error.ChildCrashed, tardis.check(gpa, crashes, .{ .iterations = 2000, .setup = warmUp, .fork = true, .report = false }));
}

test "fork: worker processes give the same failure and token as one process" {
    var one: tardis.ShrinkReport = .{};
    var many: tardis.ShrinkReport = .{};
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, bugAfterWarmUp, .{ .iterations = 1000, .setup = warmUp, .fork = true, .report = false, .shrink_report = &one }));
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, bugAfterWarmUp, .{ .iterations = 1000, .setup = warmUp, .fork = true, .workers = 4, .report = false, .shrink_report = &many }));
    try testing.expectEqualStrings(one.token(), many.token());
    first_token = null;
    try tardis.check(gpa, sameWarmState, .{ .iterations = 40, .setup = warmUp, .fork = true, .workers = 3 });
}

test "fork: keep going logs the same failures in one process, one fork server and 4 worker processes" {
    // About 16 of 1000 inputs are multiples of 61.
    const base: tardis.Options = .{ .iterations = 1000, .setup = warmUp, .report = false };
    var logs: [3]tardis.FailureLog = .{ .{}, .{}, .{} };
    for (&logs, 0..) |*log, k| {
        var o = base;
        o.keep_going = log;
        o.fork = k > 0;
        o.workers = if (k == 2) 4 else 1;
        try testing.expectError(error.AssertionFailed, tardis.check(gpa, bugAfterWarmUp, o));
    }
    try testing.expect(logs[0].len >= 5);
    for (logs[1..]) |*log| {
        try testing.expectEqual(logs[0].len, log.len);
        try testing.expectEqual(logs[0].dropped, log.dropped);
        for (logs[0].slice(), log.slice()) |*x, *y| {
            try testing.expectEqual(x.iteration, y.iteration);
            try testing.expect(y.shrunk);
            try testing.expectEqualStrings(x.token(), y.token());
        }
    }
}

/// Reads what setup wrote, then overwrites, deletes, adds and crashes: the
/// next iteration must find setup's files as setup left them.
fn scribble(env: *Env) !void {
    const io = env.io;
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("warm", try env.dir.readFile(io, "f7", &buf));
    try testing.expectEqualStrings("warm", try env.dir.readFile(io, "f8", &buf));
    try env.dir.writeFile(io, .{ .sub_path = "f7", .data = "cold and longer" });
    try env.dir.deleteFile(io, "f8");
    var big: [3 * 4096]u8 = undefined;
    io.random(&big);
    try env.dir.writeFile(io, .{ .sub_path = "extra", .data = &big });
    if ((try env.fuzz(u8)) % 2 == 0) try env.crashAndReboot(.power_loss);
}

/// A setup that leaves more than files: a bound socket.
fn warmUpWithSocket(env: *Env) !void {
    try warmUp(env);
    const any: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 77 } };
    _ = try any.bind(env.io, .{ .mode = .dgram });
}

test "warm restore: iterations start from a snapshot of what setup left, with the same results as running setup" {
    // With a security layer attached setup runs every time (`-Dsec`).
    const expect_restores = !tardis.security_by_default;
    var warm: tardis.WarmReport = .{};
    first_token = null;
    try tardis.check(gpa, sameWarmState, .{ .iterations = 200, .setup = warmUp, .warm_report = &warm });
    try testing.expectEqual(@as(u64, 0), warm.mismatches);
    if (expect_restores) {
        try testing.expect(warm.active);
        try testing.expect(warm.restores > 150);
        // Setup still runs now and then, and is compared with the snapshot.
        try testing.expect(warm.checks >= 2);
    }

    // The same failure, at the same iteration, with the same token.
    var with: tardis.ShrinkReport = .{};
    var without: tardis.ShrinkReport = .{};
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, bugAfterWarmUp, .{ .iterations = 1000, .setup = warmUp, .report = false, .shrink_report = &with }));
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, bugAfterWarmUp, .{ .iterations = 1000, .setup = warmUp, .report = false, .shrink_report = &without, .warm_restore = false }));
    try testing.expectEqualStrings(without.token(), with.token());

    // A body that changes, deletes and loses setup's files does not reach
    // the snapshot.
    try tardis.check(gpa, scribble, .{ .iterations = 300, .setup = warmUp, .warm_report = &warm });
    try testing.expectEqual(@as(u64, 0), warm.mismatches);
    if (expect_restores) try testing.expect(warm.restores > 200);

    // Setup left a socket: no snapshot, setup runs every time.
    try tardis.check(gpa, sameWarmStateQuiet, .{ .iterations = 40, .setup = warmUpWithSocket, .warm_report = &warm, .leak_check = false });
    try testing.expectEqual(@as(u64, 0), warm.restores);
    try testing.expect(!warm.active);
    // Turned off: the same.
    try tardis.check(gpa, sameWarmStateQuiet, .{ .iterations = 40, .setup = warmUp, .warm_restore = false, .warm_report = &warm });
    try testing.expectEqual(@as(u64, 0), warm.restores);
}

fn sameWarmStateQuiet(env: *Env) !void {
    var buf: [8]u8 = undefined;
    _ = try env.dir.readFile(env.io, "token", &buf);
    _ = try env.dir.statFile(env.io, "f49", .{});
}

/// Reads what setup left, changes it, and fails on about one input in
/// seven hundred. A snapshot that came back wrong fails every run.
fn readsWarmUpAndFails(env: *Env) !void {
    const io = env.io;
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("warm", try env.dir.readFile(io, "f49", &buf));
    try testing.expectEqualStrings("warm", try env.dir.readFile(io, "f7", &buf));
    _ = try env.dir.readFile(io, "token", &buf);
    try env.dir.writeFile(io, .{ .sub_path = "f7", .data = "changed" });
    try env.dir.deleteFile(io, "f49");
    const x = try env.fuzz(u16);
    try env.always("x is not a multiple of 701", x % 701 != 0 or x == 0);
}

test "warm restore: failing runs between warm starts, on three personas, are the failures of cold starts" {
    // A failed run is shrunk and replayed before the next one starts.
    // That drops the snapshots, and the next run takes them again; after
    // five such failures warm starts stay off, so this body fails less.
    for ([_][]const u8{ "TARDIS_EXPLORE", "TARDIS_PRESET", "TARDIS_SEED", "TARDIS_REPLAY", "TARDIS_CORPUS_DIR", "TARDIS_CAMPAIGN_SALT" }) |name| {
        if (testing.environ.getAlloc(gpa, name)) |value| {
            gpa.free(value);
            return error.SkipZigTest;
        } else |_| {}
    }
    const base: tardis.Options = .{
        .iterations = 600,
        .setup = warmUp,
        .report = false,
        .personas = &.{ .linux_ext4, .windows_ntfs, .posix_strict },
    };
    var report: tardis.WarmReport = .{};
    var logs: [2]tardis.FailureLog = .{ .{}, .{} };
    for (&logs, 0..) |*log, k| {
        var o = base;
        o.keep_going = log;
        o.warm_restore = k == 0;
        if (k == 0) o.warm_report = &report;
        try testing.expectError(error.AssertionFailed, tardis.check(gpa, readsWarmUpAndFails, o));
    }
    const warm = logs[0].slice();
    try testing.expect(warm.len >= 2 and warm.len <= 4);
    try testing.expectEqual(logs[1].len, logs[0].len);
    try testing.expectEqual(logs[1].dropped, logs[0].dropped);
    for (logs[1].slice(), warm) |*x, *y| {
        try testing.expectEqual(x.iteration, y.iteration);
        try testing.expectEqual(x.shrunk, y.shrunk);
        try testing.expectEqualStrings(x.token(), y.token());
    }
    try testing.expectEqual(@as(u64, 0), report.mismatches);
    // With a security layer on every check there are no warm starts.
    if (!tardis.security_by_default) {
        // Still on at the end, and more warm starts than there were runs
        // before the second failure: some came after a failure.
        try testing.expect(report.active);
        try testing.expect(report.restores > (@as(u64, warm[1].iteration) + 1) * base.personas.len);
    }
}

// --- warm starts with several nodes, and with allocations that fail ------------

/// What every run of a campaign saw, summed: the same for the same runs.
var nodes_sum: u64 = 0;

fn nodeContent(env: *const Env, node: u8, buf: *[32]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{s} on node {d}", .{ @tagName(env.persona), node }) catch unreachable;
}

/// A file on the first of three nodes, whose content names the persona.
/// A setup that starts a task on another node is never kept as a
/// snapshot (`Sim.warmOnlySnapshotState`), so the others start empty.
fn setupOnNodes(env: *Env) !void {
    var buf: [32]u8 = undefined;
    try env.dir.writeFile(env.io, .{ .sub_path = "mine", .data = nodeContent(env, 0, &buf) });
    // Seven pages in all: a size the copy of a snapshot's pages has to
    // itself (`pages_copy_bytes`).
    const pad: [5 * 4096 + 1]u8 = @splat('p');
    try env.dir.writeFile(env.io, .{ .sub_path = "pad", .data = &pad });
}

const pages_copy_bytes = 7 * 4096;

/// Fails the `fail_at`-th allocation of exactly `bytes` bytes, and counts
/// them.
const SizedFailing = struct {
    backing: std.mem.Allocator,
    bytes: usize,
    fail_at: usize,
    seen: usize = 0,

    fn allocator(f: *SizedFailing) std.mem.Allocator {
        return .{ .ptr = f, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const f: *SizedFailing = @ptrCast(@alignCast(ctx));
        if (len == f.bytes) {
            f.seen += 1;
            if (f.seen - 1 == f.fail_at) return null;
        }
        return f.backing.rawAlloc(len, alignment, ra);
    }
    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const f: *SizedFailing = @ptrCast(@alignCast(ctx));
        return f.backing.rawResize(memory, alignment, new_len, ra);
    }
    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const f: *SizedFailing = @ptrCast(@alignCast(ctx));
        return f.backing.rawRemap(memory, alignment, new_len, ra);
    }
    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const f: *SizedFailing = @ptrCast(@alignCast(ctx));
        f.backing.rawFree(memory, alignment, ra);
    }
};

/// Finds its node as setup left it, whatever the run before did there,
/// and changes it for the run after.
fn readOnNode(env: *Env, node: u8, done: *bool) !void {
    // Also when it fails: the body waits for this, and the failure is
    // reported when the body returns.
    defer done.* = true;
    const io = env.io;
    var want: [32]u8 = undefined;
    var got: [32]u8 = undefined;
    if (node == 0) {
        try testing.expectEqualStrings(nodeContent(env, node, &want), try env.dir.readFile(io, "mine", &got));
    } else {
        try testing.expectError(error.FileNotFound, env.dir.readFile(io, "mine", &got));
    }
    // Grown past a page.
    var big: [2 * 4096]u8 = undefined;
    io.random(&big);
    try env.dir.writeFile(io, .{ .sub_path = "mine", .data = &big });
}

fn bodyOnNodes(env: *Env) !void {
    var done: [3]bool = @splat(false);
    for (1..3) |n| try env.spawnOn(@intCast(n), readOnNode, .{ env, @as(u8, @intCast(n)), &done[n] });
    try readOnNode(env, 0, &done[0]);
    while (!done[1] or !done[2]) try env.io.sleep(.fromMilliseconds(1), .awake);
    var h = std.hash.Wyhash.init(0);
    h.update(std.mem.asBytes(&(try env.fuzz(u64))));
    h.update(std.mem.asBytes(&env.nowNs()));
    nodes_sum +%= h.final();
}

fn nodesCampaign(allocator: std.mem.Allocator, warm: bool, iterations: u32, report: ?*tardis.WarmReport) !u64 {
    nodes_sum = 0;
    try tardis.check(allocator, bodyOnNodes, .{
        .iterations = iterations,
        .nodes = 3,
        .setup = setupOnNodes,
        .personas = &.{ .linux_ext4, .windows_ntfs, .posix_strict },
        .warm_restore = warm,
        .warm_report = report,
        .determinism_check_every = 0,
        .report = false,
    });
    return nodes_sum;
}

test "warm restore: three nodes and three personas, the same runs as cold" {
    var report: tardis.WarmReport = .{};
    const cold = try nodesCampaign(gpa, false, 150, null);
    try testing.expect(cold != 0);
    try testing.expectEqual(cold, try nodesCampaign(gpa, true, 150, &report));
    try testing.expectEqual(@as(u64, 0), report.mismatches);
    if (!tardis.security_by_default) try testing.expect(report.active and report.restores > 400 and report.checks >= 6);
}

test "warm restore: an allocation that fails anywhere gives the cold result or OutOfMemory, and leaks nothing" {
    // The snapshots, and the copies of their pages when the personas take
    // turns, are the harness's own memory: one of those failing must cost
    // warm starts at most. Not when the environment sets what a check
    // runs: a failed allocation while it is read would lose the setting.
    for ([_][]const u8{ "TARDIS_EXPLORE", "TARDIS_PRESET", "TARDIS_SEED", "TARDIS_REPLAY", "TARDIS_CORPUS_DIR", "TARDIS_CAMPAIGN_SALT", "TARDIS_ITERATIONS_SCALE" }) |name| {
        if (testing.environ.getAlloc(gpa, name)) |value| {
            gpa.free(value);
            return error.SkipZigTest;
        } else |_| {}
    }
    const cold = try nodesCampaign(gpa, false, 4, null);
    var counting = std.testing.FailingAllocator.init(gpa, .{});
    try testing.expectEqual(cold, try nodesCampaign(counting.allocator(), true, 4, null));
    const total = counting.alloc_index;
    try testing.expect(total > 20);
    var failed: usize = 0;
    var passed: usize = 0;
    // Every allocation in turn where there are few, about 40 of them
    // evenly spread where there are many.
    const step = @max(1, total / 40);
    var n: usize = 0;
    while (n < total) : (n += step) {
        var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = n });
        if (nodesCampaign(failing.allocator(), true, 4, null)) |sum| {
            try testing.expectEqual(cold, sum);
            passed += 1;
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            failed += 1;
        }
    }
    // Both happen: a failure the campaign cannot do without, and one it can.
    try testing.expect(failed > 0);
    if (tardis.security_by_default) return;
    try testing.expect(passed > 0);

    // The copy of a snapshot's pages, one failure at a time: the
    // snapshot is given up, the run goes on cold, and nothing else shows.
    var whole: tardis.WarmReport = .{};
    var sized: SizedFailing = .{ .backing = gpa, .bytes = pages_copy_bytes, .fail_at = std.math.maxInt(usize) };
    try testing.expectEqual(cold, try nodesCampaign(sized.allocator(), true, 4, &whole));
    const copies = sized.seen;
    try testing.expect(copies >= 2 and copies <= 12);
    var k: usize = 0;
    while (k < copies) : (k += 1) {
        var report: tardis.WarmReport = .{};
        var one: SizedFailing = .{ .backing = gpa, .bytes = pages_copy_bytes, .fail_at = k };
        try testing.expectEqual(cold, try nodesCampaign(one.allocator(), true, 4, &report));
        try testing.expectEqual(@as(u64, 0), report.mismatches);
        try testing.expect(report.restores < whole.restores);
    }
}
