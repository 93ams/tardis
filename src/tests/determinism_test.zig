//! Determinism tests (plan §3, §10 tier 3).
//!
//! The golden hash pins the decision sequence and trace encoding: it must be
//! identical in Debug and Release builds and on every host. If it changes on
//! purpose (trace format or Decider change), bump the replay-token version in
//! plan §7.3 and update the constant.

const std = @import("std");
const tardis = @import("../root.zig");
const Io = std.Io;
const testing = std.testing;

fn work(io: Io, mutex: *Io.Mutex, dir: Io.Dir, id: u8) !void {
    const name: [6]u8 = .{ 'f', 'i', 'l', 'e', '-', '0' + id };
    try mutex.lock(io);
    defer mutex.unlock(io);
    var f = try dir.createFile(io, &name, .{});
    defer f.close(io);
    try f.writePositionalAll(io, &name, 0);
    try f.sync(io);
}

fn worker(io: Io, mutex: *Io.Mutex, dir: Io.Dir, id: u8, failed: *bool) Io.Cancelable!void {
    work(io, mutex, dir, id) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => failed.* = true,
    };
}

fn scenario(env: *tardis.Env) !void {
    var mutex: Io.Mutex = .init;
    var group: Io.Group = .init;
    var failed = false;
    var i: u8 = 0;
    while (i < 3) : (i += 1) try group.concurrent(env.io, worker, .{ env.io, &mutex, env.dir, i, &failed });
    try group.await(env.io);
    try testing.expect(!failed);
    var buf: [8]u8 = undefined;
    env.io.random(&buf);
    try env.crashAndReboot(.power_loss);
    _ = try env.dir.statFile(env.io, "file-0", .{});
}

/// Recorded on x86_64-windows Debug; must match every build mode and host.
/// Changed once, deliberately, in M3: decisions became key-addressed and
/// crash decisions were phrased so that 0 means "survives".
const golden_hash: u64 = 0xb990de4b5df96b20;

test "trace hash is reproducible" {
    const a = try tardis.traceHash(testing.allocator, scenario, 42, .linux_ext4, .{});
    const b = try tardis.traceHash(testing.allocator, scenario, 42, .linux_ext4, .{});
    try testing.expectEqual(a, b);
}

test "golden trace hash (cross-build, cross-host)" {
    const h = try tardis.traceHash(testing.allocator, scenario, 42, .linux_ext4, .{});
    if (h != golden_hash) {
        std.debug.print("golden trace hash changed: got 0x{x}, expected 0x{x}\n", .{ h, golden_hash });
        return error.GoldenHashMismatch;
    }
}

/// Set up once in the life of the process, as a C library's tables are.
var set_up_once = false;

fn onceOnly(env: *tardis.Env) !void {
    if (!set_up_once) {
        set_up_once = true;
        var f = try env.dir.createFile(env.io, "set-up-once", .{});
        f.close(env.io);
    }
    var buf: [4]u8 = undefined;
    env.io.random(&buf);
}

fn sometimesAtSeedZero(env: *tardis.Env) !void {
    env.sometimes("only the seed the prime run uses", env.seed == 0);
}

test "Options.prime: work done once in the life of the process does not make the first run differ" {
    const gpa = testing.allocator;
    // Without it, the first run of the process is not the second.
    set_up_once = false;
    const first = try tardis.traceHash(gpa, onceOnly, 7, .linux_ext4, .{});
    const second = try tardis.traceHash(gpa, onceOnly, 7, .linux_ext4, .{});
    try testing.expect(first != second);
    // With it, it is: the once-only work is done in a run thrown away.
    set_up_once = false;
    const primed = try tardis.traceHash(gpa, onceOnly, 7, .linux_ext4, .{ .prime = true });
    try testing.expectEqual(second, primed);
    try testing.expectEqual(primed, try tardis.traceHash(gpa, onceOnly, 7, .linux_ext4, .{ .prime = true }));
    // And `check` passes, which re-runs its first seed and compares.
    set_up_once = false;
    try tardis.check(gpa, onceOnly, .{ .iterations = 3, .prime = true });
    // The run thrown away counts for nothing: what only it reached with
    // `sometimes` is still never reached.
    try testing.expectError(error.SometimesNeverTrue, tardis.check(gpa, sometimesAtSeedZero, .{ .iterations = 3, .prime = true, .report = false }));
}
