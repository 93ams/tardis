//! termancy's crash-sensitive code under TARDIS: `sys.files` (atomic writes,
//! the private store) and `sys.update.install` (self-update with rollback).
//!
//! Each property is checked across filesystem personas with power loss at
//! random points. Four of them failed on termancy before its durability
//! fixes (each test says how); they now guard against regressions.

const std = @import("std");
const builtin = @import("builtin");
const tardis = @import("tardis");
const sys = @import("sys");
const Io = std.Io;
const Env = tardis.Env;
const testing = std.testing;
const gpa = testing.allocator;

/// `install` keeps two `max_path` buffers on the stack (~96 KiB each on
/// Windows); fibers get 256 KiB by default.
const big_stacks: tardis.Limits = .{ .fiber_stack_bytes = 1024 * 1024 };

const all_personas: []const tardis.Persona = &.{ .linux_ext4, .linux_xfs, .posix_strict, .windows_ntfs, .macos_apfs, .freebsd_zfs };

fn readOr(env: *Env, dir: Io.Dir, sub_path: []const u8, buf: []u8) []const u8 {
    return dir.readFile(env.io, sub_path, buf) catch "";
}

// ---------------------------------------------------------------------------
// sys.files.writeAtomic

/// Write `old`, make it durable, then replace it with `new` while a power
/// loss strikes at a random point (the writer runs as its own task, and the
/// test body crashes the machine after a fuzzed delay).
fn atomicWriteRace(env: *Env, comptime check_durable: bool) !void {
    const io = env.io;
    try sys.files.writeAtomic(io, env.dir, "settings.toml", "old = true\n", .{});
    {
        var d = try env.dir.openFile(io, ".", .{});
        defer d.close(io);
        try d.sync(io);
    }
    const Writer = struct {
        fn run(i: Io, dir: Io.Dir, done: *bool) void {
            sys.files.writeAtomic(i, dir, "settings.toml", "new = true\n", .{}) catch return;
            done.* = true;
        }
    };
    var done = false;
    var task = try io.concurrent(Writer.run, .{ io, env.dir, &done });
    const delay = try env.fuzz(u16);
    io.sleep(.fromMicroseconds(delay), .awake) catch {};
    if (check_durable) task.await(io) else _ = task.cancel(io);
    try env.crashAndReboot(.power_loss);
    var buf: [32]u8 = undefined;
    const got = readOr(env, env.dir, "settings.toml", &buf);
    const old = std.mem.eql(u8, got, "old = true\n");
    const new = std.mem.eql(u8, got, "new = true\n");
    try env.always("writeAtomic: the file is the old or the new contents, never torn or missing", old or new);
    if (check_durable and done) try env.always("writeAtomic: a write that returned survives power loss", new);
}

fn atomicNeverTorn(env: *Env) !void {
    return atomicWriteRace(env, false);
}

fn atomicDurable(env: *Env) !void {
    return atomicWriteRace(env, true);
}

test "termancy writeAtomic: old or new after power loss, on every persona" {
    try tardis.check(gpa, atomicNeverTorn, .{ .iterations = 150, .personas = all_personas });
}

test "termancy writeAtomic: a write that returned survives power loss" {
    // Failed before termancy synced the directory after the publishing
    // rename: the old contents came back though the call had returned.
    try tardis.check(gpa, atomicDurable, .{ .iterations = 150, .personas = all_personas });
}

// ---------------------------------------------------------------------------
// sys.files.Store

fn storeRoundTrip(env: *Env) !void {
    const io = env.io;
    const store = try sys.files.Store.open(io, env.dir, "state");
    try store.write(io, "token", "v1");
    {
        var d = try env.dir.openFile(io, "state", .{});
        defer d.close(io);
        try d.sync(io);
    }
    try store.write(io, "token", "v2-longer");
    store.close(io);
    try env.crashAndReboot(.power_loss);
    const again = try sys.files.Store.open(io, env.dir, "state");
    defer again.close(io);
    const got = try again.read(io, env.allocator, "token", .limited(64));
    defer if (got) |g| env.allocator.free(g);
    const ok = if (got) |g| std.mem.eql(u8, g, "v1") or std.mem.eql(u8, g, "v2-longer") else false;
    try env.always("Store: a blob is the old or the new value after power loss", ok);
    try testing.expect((try again.read(io, env.allocator, "missing", .limited(8))) == null);
}

test "termancy Store: blobs are old or new after power loss" {
    try tardis.check(gpa, storeRoundTrip, .{ .iterations = 100, .personas = all_personas });
}

// ---------------------------------------------------------------------------
// sys.update.install

fn repeat(comptime text: []const u8, comptime n: usize) *const [text.len * n]u8 {
    comptime {
        var out: [text.len * n]u8 = undefined;
        for (0..n) |i| @memcpy(out[i * text.len ..][0..text.len], text);
        const final = out;
        return &final;
    }
}

const old_exe = repeat("old-binary-v1", 64);
const new_exe = repeat("new-binary-v2", 80);

fn reject(context: ?*anyopaque, io: Io, dir: Io.Dir, exe_path: []const u8) error{Rejected}!void {
    _ = context;
    _ = io;
    _ = dir;
    _ = exe_path;
    return error.Rejected;
}

fn setUpOld(env: *Env) !void {
    const io = env.io;
    var f = try env.dir.createFile(io, "app", .{});
    defer f.close(io);
    try f.writeStreamingAll(io, old_exe);
    try f.sync(io);
    var d = try env.dir.openFile(io, ".", .{});
    defer d.close(io);
    try d.sync(io);
}

fn exeIsOldOrNew(env: *Env) !void {
    var buf: [new_exe.len + 16]u8 = undefined;
    const got = readOr(env, env.dir, "app", &buf);
    try env.always("install: the executable is the old or the new build after power loss", std.mem.eql(u8, got, old_exe) or std.mem.eql(u8, got, new_exe));
}

/// Power loss at a random point during an install.
fn installCrash(env: *Env, comptime strategy: sys.update.Strategy) !void {
    const io = env.io;
    try setUpOld(env);
    const Installer = struct {
        fn run(i: Io, dir: Io.Dir) void {
            sys.update.install(i, dir, "app", new_exe, .{ .strategy = strategy }) catch {};
        }
    };
    var task = try io.concurrent(Installer.run, .{ io, env.dir });
    const delay = try env.fuzz(u16);
    io.sleep(.fromMicroseconds(delay), .awake) catch {};
    _ = task.cancel(io);
    try env.crashAndReboot(.power_loss);
    // What termancy documents for start-up.
    try sys.update.removeLeftovers(io, env.dir, "app");
    try exeIsOldOrNew(env);
}

fn installCrashRenameOver(env: *Env) !void {
    return installCrash(env, .rename_over);
}

fn installCrashMoveAside(env: *Env) !void {
    return installCrash(env, .move_aside);
}

test "termancy install (rename_over): the executable survives power loss mid-install" {
    try tardis.check(gpa, installCrashRenameOver, .{ .limits = big_stacks, .iterations = 150, .personas = all_personas });
}

test "termancy install (move_aside): the executable survives power loss mid-install" {
    // `move_aside` renames the running image to `<exe>.old`, then `<exe>.new`
    // over the name; a crash between the two can leave only `<exe>.old`.
    // Failed before `removeLeftovers` put `.old` back: it deleted it.
    // On a Windows host `renameImage` calls `MoveFileExW` directly, outside
    // `std.Io`, so this only runs elsewhere.
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    try tardis.check(gpa, installCrashMoveAside, .{ .limits = big_stacks, .iterations = 300, .personas = all_personas });
}

/// The accept hook rejects the new build, `install` rolls back, and then
/// the power fails.
fn rejectedThenCrash(env: *Env, comptime property: enum { intact, rolled_back }) !void {
    const io = env.io;
    try setUpOld(env);
    try testing.expectError(error.Rejected, sys.update.install(io, env.dir, "app", new_exe, .{
        .strategy = .rename_over,
        .accept = .{ .run = reject },
    }));
    try env.crashAndReboot(.power_loss);
    var buf: [new_exe.len + 16]u8 = undefined;
    const got = readOr(env, env.dir, "app", &buf);
    switch (property) {
        .intact => try env.always("install: after a rollback and power loss the executable is intact", std.mem.eql(u8, got, old_exe) or std.mem.eql(u8, got, new_exe)),
        .rolled_back => try env.always("install: a rejected build stays rolled back after power loss", std.mem.eql(u8, got, old_exe)),
    }
}

fn rejectedIntact(env: *Env) !void {
    return rejectedThenCrash(env, .intact);
}

fn rejectedRolledBack(env: *Env) !void {
    return rejectedThenCrash(env, .rolled_back);
}

/// `rollBack` goes through `renameImage`, which on a Windows host calls
/// `MoveFileExW` directly (outside `std.Io`), so it cannot run simulated.
fn skipOnWindowsHost() !void {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
}

test "termancy install: the executable stays intact through a rollback and power loss" {
    // Failed on XFS (rename does not flush data) before the rollback copy
    // was synced: it came from `Dir.copyFile`, which never syncs, so a power
    // loss kept the rollback rename and lost the copy's data.
    try skipOnWindowsHost();
    try tardis.check(gpa, rejectedIntact, .{ .limits = big_stacks, .iterations = 100, .personas = all_personas });
}

test "termancy install: a rejected build stays rolled back after power loss" {
    // Failed on ext4 before the directory was synced after the rollback: a
    // crash kept the swap to the rejected build and lost the rename undoing it.
    try skipOnWindowsHost();
    try tardis.check(gpa, rejectedRolledBack, .{ .limits = big_stacks, .iterations = 100, .personas = all_personas });
}
