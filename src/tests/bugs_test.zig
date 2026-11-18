//! Bug-finding tests (plan §10, tier 4): deliberately buggy programs that
//! TARDIS must catch, next to their correct versions, which must pass.

const std = @import("std");
const tardis = @import("../root.zig");
const Io = std.Io;
const testing = std.testing;

fn expectBugFound(r: anyerror!void) !void {
    if (r) |_| {
        std.debug.print("expected TARDIS to find the bug, but every iteration passed\n", .{});
        return error.BugNotFound;
    } else |_| {}
}

// ---------------------------------------------------------------------------
// 1. Appending to a log without fsync.

fn appendRecord(env: *tardis.Env, sync: bool) !void {
    const io = env.io;
    var f = try env.dir.createFile(io, "log", .{});
    defer f.close(io);
    try f.writePositionalAll(io, "record-1", 0);
    if (sync) try f.sync(io);
}

fn readBack(env: *tardis.Env) !void {
    var buf: [16]u8 = undefined;
    const got = try env.dir.readFile(env.io, "log", &buf);
    try env.always("acknowledged record survives", std.mem.eql(u8, got, "record-1"));
}

test "bug: acknowledged write without fsync is lost on power loss" {
    try expectBugFound(tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            try appendRecord(env, false);
            try env.crashAndReboot(.power_loss);
            try readBack(env);
        }
    }.run, .{ .iterations = 40, .determinism_check_every = 0, .report = false }));
}

test "fixed: fsync before acknowledging" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            try appendRecord(env, true);
            try env.crashAndReboot(.power_loss);
            try readBack(env);
        }
    }.run, .{ .iterations = 40 });
}

// ---------------------------------------------------------------------------
// 2. "Atomic" replace via rename without fsyncing the temp file.

fn replaceConfig(env: *tardis.Env, sync_tmp: bool) !void {
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
        if (sync_tmp) try t.sync(io);
    }
    try env.dir.rename("config.tmp", env.dir, "config", io);
    var d = try env.dir.openFile(io, ".", .{});
    defer d.close(io);
    try d.sync(io);
}

fn configIsOldOrNew(env: *tardis.Env) !void {
    var buf: [32]u8 = undefined;
    const got = try env.dir.readFile(env.io, "config", &buf);
    const ok = std.mem.eql(u8, got, "old-config") or std.mem.eql(u8, got, "new-config");
    try env.always("config is old or new, never torn", ok);
}

test "bug: rename without fsync of the temp file tears on xfs" {
    try expectBugFound(tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            try replaceConfig(env, false);
            try env.crashAndReboot(.power_loss);
            try configIsOldOrNew(env);
        }
    }.run, .{ .iterations = 40, .personas = &.{.linux_xfs}, .determinism_check_every = 0, .report = false }));
}

test "same bug is hidden by ext4 auto_da_alloc" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            try replaceConfig(env, false);
            try env.crashAndReboot(.power_loss);
            try configIsOldOrNew(env);
        }
    }.run, .{ .iterations = 40, .personas = &.{.linux_ext4} });
}

test "fixed: fsync the temp file before rename (all personas)" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            try replaceConfig(env, true);
            try env.crashAndReboot(.power_loss);
            try configIsOldOrNew(env);
        }
    }.run, .{ .iterations = 40, .personas = &.{ .linux_ext4, .linux_xfs, .windows_ntfs, .posix_strict } });
}

// ---------------------------------------------------------------------------
// 3. Creating a file and fsyncing it, but not its directory.

test "bug: missing directory fsync loses a new file under posix_strict" {
    try expectBugFound(tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            try appendRecord(env, true);
            try env.crashAndReboot(.power_loss);
            try readBack(env);
        }
    }.run, .{ .iterations = 40, .personas = &.{.posix_strict}, .determinism_check_every = 0, .report = false }));
}

// ---------------------------------------------------------------------------
// 4. Ignoring a write error.

fn writeIgnoringErrors(env: *tardis.Env) !void {
    const io = env.io;
    var f = try env.dir.createFile(io, "data", .{ .read = true });
    defer f.close(io);
    f.writePositionalAll(io, "payload", 0) catch {}; // bug: error swallowed
    f.sync(io) catch {};
    var buf: [16]u8 = undefined;
    const n = try f.readPositionalAll(io, &buf, 0);
    try env.always("data was written", std.mem.eql(u8, buf[0..n], "payload"));
}

test "bug: swallowed I/O error is exposed by fault injection" {
    try expectBugFound(tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            try writeIgnoringErrors(env);
        }
    }.run, .{ .iterations = 60, .faults = .{ .io_error_ppm = 200_000 }, .determinism_check_every = 0, .report = false }));
}

// ---------------------------------------------------------------------------
// Replay: a failing run seed reproduces the failure on its own.

fn unsyncedBody(env: *tardis.Env) !void {
    try appendRecord(env, false);
    try env.crashAndReboot(.power_loss);
    try readBack(env);
}

test "replaying a failing seed reproduces the same failure" {
    var failing: ?u64 = null;
    var failure: anyerror = undefined;
    var i: u32 = 0;
    while (i < 40 and failing == null) : (i += 1) {
        const seed = tardis.runSeed(tardis.default_campaign_seed, i, 0);
        tardis.check(testing.allocator, unsyncedBody, .{ .seed = seed, .report = false }) catch |err| {
            failing = seed;
            failure = err;
        };
    }
    const seed = failing orelse return error.BugNotFound;
    var k: u32 = 0;
    while (k < 3) : (k += 1) {
        try testing.expectError(failure, tardis.check(testing.allocator, unsyncedBody, .{ .seed = seed, .report = false }));
    }
}
