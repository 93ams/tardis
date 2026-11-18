//! M2: hard links, symlinks, and the macos_apfs / freebsd_zfs personas.

const std = @import("std");
const tardis = @import("../root.zig");
const Io = std.Io;
const Env = tardis.Env;
const testing = std.testing;
const gpa = testing.allocator;

fn writeFile(env: *Env, path: []const u8, data: []const u8, sync: bool) !void {
    var f = try env.dir.createFile(env.io, path, .{});
    defer f.close(env.io);
    try f.writePositionalAll(env.io, data, 0);
    if (sync) try f.sync(env.io);
}

fn syncRoot(env: *Env) !void {
    var d = try env.dir.openFile(env.io, ".", .{});
    defer d.close(env.io);
    try d.sync(env.io);
}

// ---------------------------------------------------------------------------
// Hard links

fn hardLinks(env: *Env) !void {
    const io = env.io;
    try writeFile(env, "a", "hello", false);
    try env.dir.hardLink("a", env.dir, "b", io, .{});
    try testing.expectEqual(@as(u64, 2), (try env.dir.statFile(io, "a", .{})).nlink);
    try testing.expectError(error.PathAlreadyExists, env.dir.hardLink("a", env.dir, "b", io, .{}));

    // One inode, two names.
    {
        var f = try env.dir.openFile(io, "b", .{ .mode = .read_write });
        defer f.close(io);
        try f.writePositionalAll(io, "J", 0);
        try f.hardLink(io, env.dir, "c", .{});
    }
    var buf: [8]u8 = undefined;
    try testing.expectEqualStrings("Jello", try env.dir.readFile(io, "a", &buf));
    try env.dir.deleteFile(io, "a");
    try testing.expectEqualStrings("Jello", try env.dir.readFile(io, "c", &buf));
    try testing.expectEqual(@as(u64, 2), (try env.dir.statFile(io, "b", .{})).nlink);

    try env.dir.createDir(io, "d", .default_dir);
    try testing.expectError(error.PermissionDenied, env.dir.hardLink("d", env.dir, "d2", io, .{}));
}

test "link: hard links share one inode" {
    try tardis.check(gpa, hardLinks, .{ .iterations = 10, .personas = &.{ .linux_ext4, .windows_ntfs } });
}

/// Publish with link(): write a temp file, fsync it, link it to the final
/// name, fsync the directory, remove the temp name.
fn linkPublish(env: *Env, sync_tmp: bool) !void {
    try writeFile(env, "tmp", "complete", sync_tmp);
    try env.dir.hardLink("tmp", env.dir, "final", env.io, .{});
    try syncRoot(env);
    try env.dir.deleteFile(env.io, "tmp");
    try env.crashAndReboot(.power_loss);
    var buf: [16]u8 = undefined;
    const got = env.dir.readFile(env.io, "final", &buf) catch |err| switch (err) {
        error.FileNotFound => return error.PublishedFileMissing,
        else => return err,
    };
    try env.always("a published file is complete", std.mem.eql(u8, got, "complete"));
}

fn linkPublishSynced(env: *Env) !void {
    return linkPublish(env, true);
}

fn linkPublishUnsynced(env: *Env) !void {
    return linkPublish(env, false);
}

const all_personas: []const tardis.Persona = &.{ .linux_ext4, .linux_xfs, .windows_ntfs, .posix_strict, .macos_apfs, .freebsd_zfs };

test "link: publish-by-link with fsync survives power loss on every persona" {
    try tardis.check(gpa, linkPublishSynced, .{ .iterations = 40, .personas = all_personas });
}

test "link: publish-by-link without fsync of the temp file loses data (bug found)" {
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, linkPublishUnsynced, .{
        .iterations = 60,
        .personas = &.{.linux_ext4},
        .report = false,
    }));
}

// ---------------------------------------------------------------------------
// Symlinks

fn symlinks(env: *Env) !void {
    const io = env.io;
    try env.dir.createDirPath(io, "releases/v1");
    try writeFile(env, "releases/v1/app.cfg", "one", false);
    try env.dir.symLink(io, "releases/v1", "current", .{ .is_directory = true });

    var buf: [64]u8 = undefined;
    // Followed in the middle of a path and at the end.
    try testing.expectEqualStrings("one", try env.dir.readFile(io, "current/app.cfg", &buf));
    try env.dir.symLink(io, "current/app.cfg", "cfg", .{});
    try testing.expectEqualStrings("one", try env.dir.readFile(io, "cfg", &buf));
    // A relative target resolves from the link's directory.
    try env.dir.symLink(io, "../v1/app.cfg", "releases/v1/self", .{});
    try testing.expectEqualStrings("one", try env.dir.readFile(io, "releases/v1/self", &buf));

    try testing.expectEqualStrings("releases/v1", buf[0..try env.dir.readLink(io, "current", &buf)]);
    try testing.expectError(error.NotLink, env.dir.readLink(io, "releases", &buf));
    try testing.expectEqual(Io.File.Kind.sym_link, (try env.dir.statFile(io, "cfg", .{ .follow_symlinks = false })).kind);
    try testing.expectEqual(Io.File.Kind.file, (try env.dir.statFile(io, "cfg", .{})).kind);

    // Listing reports the link itself.
    var it = env.dir.iterate();
    var saw = false;
    while (try it.next(io)) |e| {
        if (std.mem.eql(u8, e.name, "current")) {
            try testing.expectEqual(Io.File.Kind.sym_link, e.kind);
            saw = true;
        }
    }
    try testing.expect(saw);

    // Loops and dangling links.
    try env.dir.symLink(io, "loop-b", "loop-a", .{});
    try env.dir.symLink(io, "loop-a", "loop-b", .{});
    try testing.expectError(error.SymLinkLoop, env.dir.readFile(io, "loop-a", &buf));
    try env.dir.symLink(io, "nowhere", "dangling", .{});
    try testing.expectError(error.FileNotFound, env.dir.readFile(io, "dangling", &buf));

    // Deleting a link leaves the target.
    try env.dir.deleteFile(io, "cfg");
    try testing.expectEqualStrings("one", try env.dir.readFile(io, "releases/v1/app.cfg", &buf));
}

test "symlink: create, follow, readLink, stat, list, loop, dangling" {
    try tardis.check(gpa, symlinks, .{ .iterations = 10, .personas = &.{ .linux_ext4, .macos_apfs } });
}

/// Deploy by swapping a symlink: write the new release, point a temporary
/// link at it, rename the link over `current`.
fn deploy(env: *Env, sync_release: bool) !void {
    const io = env.io;
    try env.dir.createDirPath(io, "v1");
    try env.dir.createDirPath(io, "v2");
    try writeFile(env, "v1/app", "version-1", true);
    try env.dir.symLink(io, "v1", "current", .{ .is_directory = true });
    try syncRoot(env);

    try writeFile(env, "v2/app", "version-2", sync_release);
    try env.dir.symLink(io, "v2", "next", .{ .is_directory = true });
    try env.dir.rename("next", env.dir, "current", io);
    try syncRoot(env);
    try env.crashAndReboot(.power_loss);

    var buf: [16]u8 = undefined;
    const got = try env.dir.readFile(io, "current/app", &buf);
    try env.always("current is a complete release", std.mem.eql(u8, got, "version-1") or std.mem.eql(u8, got, "version-2"));
}

fn deploySynced(env: *Env) !void {
    return deploy(env, true);
}

fn deployUnsynced(env: *Env) !void {
    return deploy(env, false);
}

test "symlink: atomic deploy by renaming a link survives power loss" {
    try tardis.check(gpa, deploySynced, .{ .iterations = 40, .personas = &.{ .linux_ext4, .linux_xfs, .posix_strict, .freebsd_zfs } });
}

test "symlink: deploy without fsyncing the release is caught even on ext4 (bug found)" {
    // ext4's auto_da_alloc flushes the renamed inode, which here is the
    // link, not the release it points at.
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, deployUnsynced, .{
        .iterations = 60,
        .personas = &.{.linux_ext4},
        .report = false,
    }));
}

// ---------------------------------------------------------------------------
// Personas

fn apfsCase(env: *Env) !void {
    const io = env.io;
    try writeFile(env, "Readme", "x", false);
    var buf: [4]u8 = undefined;
    try testing.expectEqualStrings("x", try env.dir.readFile(io, "README", &buf));
    try testing.expectError(error.PathAlreadyExists, env.dir.createDir(io, "readme", .default_dir));
    // Case-preserving: the listing shows the name as created.
    var it = env.dir.iterate();
    try testing.expectEqualStrings("Readme", (try it.next(io)).?.name);
}

test "persona: macos_apfs is case-insensitive and case-preserving" {
    try tardis.check(gpa, apfsCase, .{ .iterations = 5, .personas = &.{.macos_apfs} });
}

fn overwriteUnsynced(env: *Env) !void {
    const old: [4096]u8 = @splat('o');
    const new: [4096]u8 = @splat('n');
    try writeFile(env, "f", &old, true);
    try syncRoot(env);
    {
        var f = try env.dir.openFile(env.io, "f", .{ .mode = .read_write });
        defer f.close(env.io);
        try f.writePositionalAll(env.io, &new, 0);
    }
    try env.crashAndReboot(.power_loss);
    var buf: [4096]u8 = undefined;
    const got = try env.dir.readFile(env.io, "f", &buf);
    const all_old = std.mem.allEqual(u8, got, 'o');
    const all_new = std.mem.allEqual(u8, got, 'n');
    env.sometimes("old survives", all_old);
    env.sometimes("new survives", all_new);
    if (env.persona == .freebsd_zfs) {
        try env.always("zfs never tears a write", got.len == 4096 and (all_old or all_new));
    } else {
        env.sometimes("ext4 tears an unsynced overwrite", !all_old and !all_new);
    }
}

test "persona: freebsd_zfs never tears; ext4 does" {
    try tardis.check(gpa, overwriteUnsynced, .{ .iterations = 60, .swarm = false, .personas = &.{ .freebsd_zfs, .linux_ext4 } });
}
