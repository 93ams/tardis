//! `zig build run`: a short demonstration of TARDIS finding a crash-
//! consistency bug that only some filesystems expose.

const std = @import("std");
const tardis = @import("tardis");

/// Replaces `config` "atomically" via a temp file and rename, but forgets to
/// fsync the temp file first. Correct on ext4 (auto_da_alloc), broken on xfs.
fn buggyReplace(env: *tardis.Env) !void {
    const io = env.io;
    try env.dir.writeFile(io, .{ .sub_path = "config", .data = "old-config" });
    {
        var f = try env.dir.openFile(io, "config", .{ .mode = .read_write });
        defer f.close(io);
        try f.sync(io);
    }
    try env.dir.writeFile(io, .{ .sub_path = "config.tmp", .data = "new-config" });
    try env.dir.rename("config.tmp", env.dir, "config", io);
    {
        var d = try env.dir.openFile(io, ".", .{});
        defer d.close(io);
        try d.sync(io);
    }

    try env.crashAndReboot(.power_loss);

    var buf: [32]u8 = undefined;
    const got = try env.dir.readFile(io, "config", &buf);
    const ok = std.mem.eql(u8, got, "old-config") or std.mem.eql(u8, got, "new-config");
    try env.always("config is either old or new", ok);
}

pub fn main(init: std.process.Init) !void {
    std.debug.print(
        \\TARDIS demo: write temp file, rename over config, power loss.
        \\Invariant: after reboot, config holds the old or the new contents.
        \\
        \\
    , .{});
    const personas = [_]tardis.Persona{ .linux_ext4, .linux_xfs, .windows_ntfs, .posix_strict, .macos_apfs, .freebsd_zfs };
    for (personas) |p| {
        const result = tardis.check(init.gpa, buggyReplace, .{
            .iterations = 100,
            .personas = &.{p},
            .determinism_check_every = 0,
        });
        if (result) |_| {
            std.debug.print("{s: <13} invariant held in 100 runs\n\n", .{@tagName(p)});
        } else |err| {
            std.debug.print("{s: <13} BUG FOUND ({s})\n\n", .{ @tagName(p), @errorName(err) });
        }
    }
}
