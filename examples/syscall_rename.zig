//! Example: replacing a settings file with system calls, no `std.Io`.
//!
//! This is `rename_unsynced.zig` written the way a C program or a
//! `std.posix` program would write it: `open`, `write`, `fsync`, `rename`
//! and `close` straight to the kernel. The program never sees an `Io`, so
//! the default mode cannot run it inside the simulation. System-call mode
//! (`Options.mode = .syscalls`, Linux on x86_64) answers its calls from
//! the simulated filesystem, and the same bug is found.
//!
//! The bug class: **renaming before the data is durable.** The new
//! settings go to a temporary file, which is renamed over the old one, and
//! the directory is synced. The temporary file never is, so after a power
//! loss the name can point at a file whose bytes were never written.
//!
//! The fix syncs the temporary file before the rename.
//!
//! The property: after a power loss the settings are the old ones or the
//! new ones.

const std = @import("std");
const tardis = @import("tardis");
const linux = std.os.linux;
const Env = tardis.Env;

/// System-call mode exists on this target.
pub const supported = tardis.syscall_mode_supported;

const Variant = enum { buggy, fixed };

pub const options: tardis.Options = .{
    .iterations = 200,
    .personas = &.{ .linux_xfs, .posix_strict },
    .mode = .syscalls,
};

fn ok(rc: usize) !usize {
    return if (linux.errno(rc) == .SUCCESS) rc else error.SystemCallFailed;
}

fn writeAll(fd: linux.fd_t, bytes: []const u8) !void {
    var done: usize = 0;
    while (done < bytes.len) done += try ok(linux.write(fd, bytes.ptr + done, bytes.len - done));
}

fn writeFile(path: [*:0]const u8, data: []const u8, sync: bool) !void {
    const fd: linux.fd_t = @intCast(try ok(linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644)));
    defer _ = linux.close(fd);
    try writeAll(fd, data);
    if (sync) _ = try ok(linux.fsync(fd));
}

fn syncDir(path: [*:0]const u8) !void {
    const fd: linux.fd_t = @intCast(try ok(linux.open(path, .{ .DIRECTORY = true }, 0)));
    defer _ = linux.close(fd);
    _ = try ok(linux.fsync(fd));
}

fn replace(data: []const u8, variant: Variant) !void {
    // The whole difference: whether the temporary file is synced.
    try writeFile("settings.tmp", data, variant == .fixed);
    _ = try ok(linux.rename("settings.tmp", "settings"));
    try syncDir(".");
}

fn readFile(path: [*:0]const u8, buf: []u8) ![]u8 {
    const fd: linux.fd_t = @intCast(try ok(linux.open(path, .{}, 0)));
    defer _ = linux.close(fd);
    var len: usize = 0;
    while (len < buf.len) {
        const n = try ok(linux.read(fd, buf.ptr + len, buf.len - len));
        if (n == 0) break;
        len += n;
    }
    return buf[0..len];
}

fn scenario(env: *Env, variant: Variant) !void {
    if (!supported) return error.SkipZigTest;
    try writeFile("settings", "volume=3", true);
    try syncDir(".");

    try replace("volume=7", variant);
    try env.crashAndReboot(.power_loss);

    var buf: [32]u8 = undefined;
    const got = try readFile("settings", &buf);
    const whole = std.mem.eql(u8, got, "volume=3") or std.mem.eql(u8, got, "volume=7");
    try env.always("the settings are the old ones or the new ones", whole);
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "syscall_rename: a rename made by system call can outlive the data it names" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    var o = options;
    o.report = false;
    var shrunk: tardis.ShrinkReport = .{};
    o.shrink_report = &shrunk;
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, o));
    // The failure shrinks, and its token replays to the same failure.
    try std.testing.expect(shrunk.shrunk);
    try std.testing.expect(shrunk.after < shrunk.before);
    var replay = options;
    replay.report = false;
    replay.replay = shrunk.token();
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, replay));
}

test "syscall_rename: syncing the temporary file first keeps old-or-new" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    try tardis.check(std.testing.allocator, fixed, options);
}

test "syscall_rename: where there is no system-call mode, check says so" {
    if (supported) return error.SkipZigTest;
    try std.testing.expectError(error.SyscallModeUnsupported, tardis.check(std.testing.allocator, fixed, options));
}
