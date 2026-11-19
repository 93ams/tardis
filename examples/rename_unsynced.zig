//! Example: replacing a settings file through a temporary file.
//!
//! The bug class: **renaming before the data is durable.** The program
//! writes the new settings to a temporary file and renames it over the old
//! one, so that a reader sees the old file or the new one, never half of
//! each. It syncs the directory, which makes the rename durable. It never
//! syncs the temporary file, so after a power loss the name can point at a
//! file whose bytes were never written. ext4 forgives this by default;
//! XFS does not.
//!
//! The fix syncs the temporary file before the rename.
//!
//! The property: after a power loss the settings are the old ones or the
//! new ones.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

pub const options: tardis.Options = .{ .iterations = 200, .personas = &.{ .linux_xfs, .posix_strict } };

fn syncPath(io: Io, dir: Io.Dir, name: []const u8) !void {
    var f = try dir.openFile(io, name, if (std.mem.eql(u8, name, ".")) .{} else .{ .mode = .read_write });
    defer f.close(io);
    try f.sync(io);
}

fn replace(io: Io, dir: Io.Dir, data: []const u8, variant: Variant) !void {
    try dir.writeFile(io, .{ .sub_path = "settings.tmp", .data = data });
    // The whole difference.
    if (variant == .fixed) try syncPath(io, dir, "settings.tmp");
    try dir.rename("settings.tmp", dir, "settings", io);
    try syncPath(io, dir, ".");
}

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    try env.dir.writeFile(io, .{ .sub_path = "settings", .data = "volume=3" });
    try syncPath(io, env.dir, "settings");
    try syncPath(io, env.dir, ".");

    try replace(io, env.dir, "volume=7", variant);
    try env.crashAndReboot(.power_loss);

    var buf: [32]u8 = undefined;
    const got = try env.dir.readFile(io, "settings", &buf);
    const ok = std.mem.eql(u8, got, "volume=3") or std.mem.eql(u8, got, "volume=7");
    try env.always("the settings are the old ones or the new ones", ok);
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "rename_unsynced: a rename can outlive the data it names" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, o));
}

test "rename_unsynced: syncing the temporary file first keeps old-or-new" {
    try tardis.check(std.testing.allocator, fixed, options);
}
