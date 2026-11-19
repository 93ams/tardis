//! Example: a worker that applies jobs from a queue to a ledger.
//!
//! The bug class: **doing a job twice after a restart.** The worker
//! applies a job, then records that it did. A crash between the two
//! steps leaves the job applied and not recorded, so the restarted worker
//! applies it again. Every write here is synced; nothing is lost. The bug
//! is in the order of two durable steps, not in durability.
//!
//! The fix makes applying idempotent: a ledger entry carries its job's
//! number, and the worker skips a job the ledger already has.
//!
//! The property: after a crash at any point and a restart, the ledger has
//! each job exactly once.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };
const jobs = 4;

fn syncDir(io: Io, dir: Io.Dir) !void {
    var d = try dir.openFile(io, ".", .{});
    defer d.close(io);
    try d.sync(io);
}

/// Replaces `name` with `data`, durably.
fn store(io: Io, dir: Io.Dir, name: []const u8, data: []const u8) !void {
    try dir.writeFile(io, .{ .sub_path = name, .data = data });
    var f = try dir.openFile(io, name, .{ .mode = .read_write });
    defer f.close(io);
    try f.sync(io);
    try syncDir(io, dir);
}

fn load(io: Io, dir: Io.Dir, name: []const u8, buf: []u8) ![]const u8 {
    return dir.readFile(io, name, buf) catch |err| switch (err) {
        error.FileNotFound => buf[0..0],
        else => |e| return e,
    };
}

/// Runs the worker until the queue is done, or until `steps` durable
/// steps have been taken (a crash point chosen by the test).
fn work(io: Io, dir: Io.Dir, variant: Variant, steps: usize) !void {
    var left = steps;
    var done_buf: [1]u8 = undefined;
    const done_bytes = try load(io, dir, "done", &done_buf);
    var next: u8 = if (done_bytes.len == 1) done_bytes[0] else 0;
    while (next < jobs) : (next += 1) {
        var ledger_buf: [64]u8 = undefined;
        const ledger = try load(io, dir, "ledger", &ledger_buf);
        // The whole difference: the fixed worker looks before it applies.
        const applied = variant == .fixed and std.mem.indexOfScalar(u8, ledger, next) != null;
        if (!applied) {
            if (left == 0) return;
            left -= 1;
            var grown: [65]u8 = undefined;
            @memcpy(grown[0..ledger.len], ledger);
            grown[ledger.len] = next;
            try store(io, dir, "ledger", grown[0 .. ledger.len + 1]);
        }
        if (left == 0) return;
        left -= 1;
        try store(io, dir, "done", &.{next + 1});
    }
}

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    // The worker stops after a number of steps the seed chooses, the power
    // goes, and a new worker starts from what is on disk.
    const steps = (try env.fuzz(u8)) % (2 * jobs + 1);
    try work(io, env.dir, variant, steps);
    try env.crashAndReboot(.power_loss);
    try work(io, env.dir, variant, std.math.maxInt(usize));

    var buf: [64]u8 = undefined;
    const ledger = try load(io, env.dir, "ledger", &buf);
    var seen: [jobs]u8 = @splat(0);
    for (ledger) |job| {
        if (job < jobs) seen[job] += 1;
    }
    for (seen) |count| try env.always("each job is in the ledger exactly once", count == 1);
}

fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "jobs: apply-then-record applies a job twice after a crash between the two" {
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, .{
        .iterations = 200,
        .report = false,
    }));
}

test "jobs: an idempotent apply gives exactly once" {
    try tardis.check(std.testing.allocator, fixed, .{
        .iterations = 200,
        .personas = &.{ .linux_ext4, .linux_xfs, .posix_strict },
    });
}
