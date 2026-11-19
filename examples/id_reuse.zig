//! Example: a generator of unique numbers that survives restarts.
//!
//! The bug class: **an identifier handed out twice after a restart.** The
//! generator keeps the next number in memory and saves it to a file. The
//! buggy one hands a number out first and saves afterwards, without
//! syncing. A crash after the caller has the number and before the file
//! has it means the restarted generator hands the same number out again.
//!
//! The fix makes the new high-water mark durable before the number leaves.
//!
//! The property: no number is handed out twice, across a power loss.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

pub const options: tardis.Options = .{ .iterations = 200 };

fn load(io: Io, dir: Io.Dir) u8 {
    var buf: [1]u8 = undefined;
    const got = dir.readFile(io, "next-id", &buf) catch return 0;
    return if (got.len == 1) got[0] else 0;
}

fn store(io: Io, dir: Io.Dir, next: u8, durable: bool) !void {
    var f = try dir.createFile(io, "next-id", .{ .truncate = false });
    defer f.close(io);
    try f.writePositionalAll(io, &.{next}, 0);
    if (durable) {
        try f.sync(io);
        var d = try dir.openFile(io, ".", .{});
        defer d.close(io);
        try d.sync(io);
    }
}

fn take(io: Io, dir: Io.Dir, next: *u8, variant: Variant) !u8 {
    const id = next.*;
    next.* += 1;
    // The fixed generator does not return until the file says `id` is
    // taken; the buggy one writes it down on the way out and hopes.
    try store(io, dir, next.*, variant == .fixed);
    return id;
}

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    var handed: [64]bool = @splat(false);
    for (0..2) |_| {
        // One life of the process: start from the file, hand some out.
        var next = load(io, env.dir);
        const count = 1 + (try env.fuzz(u8)) % 5;
        for (0..count) |_| {
            const id = try take(io, env.dir, &next, variant);
            try env.always("no number is handed out twice", !handed[id]);
            handed[id] = true;
        }
        try env.crashAndReboot(.power_loss);
    }
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "id_reuse: a number handed out before it is recorded durably comes back after a crash" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, o));
}

test "id_reuse: recording durably first never repeats a number" {
    try tardis.check(std.testing.allocator, fixed, options);
}
