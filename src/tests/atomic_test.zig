//! `Dir.createFileAtomic` (`File.Atomic.replace` / `link`), `renamePreserve`
//! and `Dir.copyFile`, which is built on them: what std's own atomic-write
//! helpers need, under crashes.

const std = @import("std");
const tardis = @import("../root.zig");
const Io = std.Io;
const Env = tardis.Env;
const testing = std.testing;
const gpa = testing.allocator;

fn writeAtomic(env: *Env, sub_path: []const u8, data: []const u8, sync_dir: bool) !void {
    const io = env.io;
    var atomic = try env.dir.createFileAtomic(io, sub_path, .{ .replace = true, .make_path = true });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, data);
    try atomic.file.sync(io);
    try atomic.replace(io);
    if (sync_dir) {
        const parent = std.fs.path.dirname(sub_path) orelse ".";
        var d = try env.dir.openFile(io, parent, .{});
        defer d.close(io);
        try d.sync(io);
    }
}

fn readOr(env: *Env, sub_path: []const u8, buf: []u8) []const u8 {
    return env.dir.readFile(env.io, sub_path, buf) catch "";
}

fn replaceBasics(env: *Env) !void {
    const io = env.io;
    try writeAtomic(env, "cfg/app.toml", "one", false);
    try writeAtomic(env, "cfg/app.toml", "two!", false);
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("two!", try env.dir.readFile(io, "cfg/app.toml", &buf));
    // Nothing but the target is left in the directory.
    var d = try env.dir.openDir(io, "cfg", .{ .iterate = true });
    defer d.close(io);
    var it = d.iterate();
    var n: usize = 0;
    while (try it.next(io)) |_| n += 1;
    try testing.expectEqual(@as(usize, 1), n);
}

test "createFileAtomic: replace writes the new contents and leaves no temporary file" {
    try tardis.check(gpa, replaceBasics, .{ .iterations = 20 });
}

fn linkRefusesExisting(env: *Env) !void {
    const io = env.io;
    try env.dir.writeFile(io, .{ .sub_path = "taken", .data = "x" });
    var atomic = try env.dir.createFileAtomic(io, "taken", .{});
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, "y");
    try testing.expectError(error.PathAlreadyExists, atomic.link(io));
    var fresh = try env.dir.createFileAtomic(io, "free", .{});
    defer fresh.deinit(io);
    try fresh.file.writeStreamingAll(io, "z");
    try fresh.link(io);
    var buf: [4]u8 = undefined;
    try testing.expectEqualStrings("z", try env.dir.readFile(io, "free", &buf));
    try testing.expectEqualStrings("x", try env.dir.readFile(io, "taken", &buf));
}

test "createFileAtomic: link refuses an existing destination (renamePreserve)" {
    try tardis.check(gpa, linkRefusesExisting, .{ .iterations = 10 });
}

fn copyWorks(env: *Env) !void {
    const io = env.io;
    try env.dir.writeFile(io, .{ .sub_path = "src.bin", .data = "payload" });
    try env.dir.copyFile("src.bin", env.dir, "dst.bin", io, .{});
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("payload", try env.dir.readFile(io, "dst.bin", &buf));
}

test "copyFile works in the simulation" {
    try tardis.check(gpa, copyWorks, .{ .iterations = 10 });
}

fn neverTorn(env: *Env) !void {
    try writeAtomic(env, "state", "old-state", true);
    try writeAtomic(env, "state", "new-state", false);
    try env.crashAndReboot(.power_loss);
    var buf: [16]u8 = undefined;
    const got = readOr(env, "state", &buf);
    try env.always("an atomic write is old or new, never torn", std.mem.eql(u8, got, "old-state") or std.mem.eql(u8, got, "new-state"));
    env.sometimes("the new state survived", std.mem.eql(u8, got, "new-state"));
}

test "createFileAtomic under power loss: old or new, never torn" {
    try tardis.check(gpa, neverTorn, .{ .iterations = 200, .personas = &.{ .linux_ext4, .linux_xfs, .posix_strict } });
}

fn durableAfterReturn(env: *Env) !void {
    try writeAtomic(env, "state", "old-state", true);
    try writeAtomic(env, "state", "new-state", false); // bug: directory not synced
    try env.crashAndReboot(.power_loss);
    var buf: [16]u8 = undefined;
    try env.always("a completed atomic write survives a crash", std.mem.eql(u8, readOr(env, "state", &buf), "new-state"));
}

test "createFileAtomic without a directory fsync is not durable (bug found)" {
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, durableAfterReturn, .{ .iterations = 200, .personas = &.{.posix_strict}, .report = false }));
}
