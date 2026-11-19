//! Example: saving a new file.
//!
//! The bug class: **a missing fsync of the directory.** The program writes
//! a new file and syncs it. The file's bytes are durable; its name is not,
//! because a name lives in the directory, and the directory was never
//! synced. After a power loss the file can be gone. Many filesystems hide
//! this most of the time; POSIX allows it, and the `posix_strict` persona
//! does what POSIX allows.
//!
//! The property: a file whose save returned exists after a power loss.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

pub const options: tardis.Options = .{ .iterations = 100, .personas = &.{.posix_strict} };

fn save(io: Io, dir: Io.Dir, name: []const u8, data: []const u8, variant: Variant) !void {
    var f = try dir.createFile(io, name, .{});
    defer f.close(io);
    try f.writePositionalAll(io, data, 0);
    try f.sync(io);
    // The whole difference: the name needs its directory synced too.
    if (variant == .fixed) {
        var d = try dir.openFile(io, ".", .{});
        defer d.close(io);
        try d.sync(io);
    }
}

fn scenario(env: *Env, variant: Variant) !void {
    try save(env.io, env.dir, "report.txt", "quarterly numbers", variant);
    try env.crashAndReboot(.power_loss);
    var buf: [32]u8 = undefined;
    const got: ?[]const u8 = env.dir.readFile(env.io, "report.txt", &buf) catch |err| switch (err) {
        error.FileNotFound => null,
        else => |e| return e,
    };
    try env.always("a saved file exists after a power loss", got != null);
    try env.always("a saved file has its content after a power loss", std.mem.eql(u8, got.?, "quarterly numbers"));
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "dir_sync: a new file whose directory was not synced can vanish in a power loss" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, o));
}

test "dir_sync: syncing the directory keeps the name" {
    try tardis.check(std.testing.allocator, fixed, options);
}
