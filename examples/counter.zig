//! Example: a counter kept in a file, bumped by several tasks.
//!
//! The bug class: **a lost update.** Each task reads the count, adds one
//! and writes it back. Two tasks that read the same count both write
//! count + 1, and one increment is gone. It needs a particular
//! interleaving, so a plain test passes almost every time.
//!
//! The simulator chooses which task runs at every I/O call, from the
//! seed, so it reaches that interleaving within a few runs and replays
//! it exactly.
//!
//! The property: after three increments the count is three.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };
const tasks = 3;

fn read(io: Io, dir: Io.Dir) !u64 {
    var buf: [8]u8 = undefined;
    const bytes = try dir.readFile(io, "count", &buf);
    if (bytes.len != 8) return error.Corrupt;
    return std.mem.readInt(u64, bytes[0..8], .little);
}

fn write(io: Io, dir: Io.Dir, count: u64) !void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, count, .little);
    try dir.writeFile(io, .{ .sub_path = "count", .data = &buf });
}

fn increment(io: Io, dir: Io.Dir, lock: *Io.Mutex, variant: Variant, failed: *bool) Io.Cancelable!void {
    // The whole difference: the fixed version holds a lock from the read
    // to the write.
    if (variant == .fixed) try lock.lock(io);
    defer if (variant == .fixed) lock.unlock(io);
    const count = read(io, dir) catch {
        failed.* = true;
        return;
    };
    write(io, dir, count + 1) catch {
        failed.* = true;
    };
}

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    try write(io, env.dir, 0);
    var lock: Io.Mutex = .init;
    var failed = false;
    var group: Io.Group = .init;
    defer group.cancel(io);
    for (0..tasks) |_| try group.concurrent(io, increment, .{ io, env.dir, &lock, variant, &failed });
    try group.await(io);
    // A task that read the file while another was rewriting it saw a
    // short file: the same missing lock, seen from the reader's side.
    try env.always("no increment is lost", !failed and try read(io, env.dir) == tasks);
}

fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "counter: read-then-write without a lock loses an update" {
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, .{
        .iterations = 200,
        .report = false,
    }));
}

test "counter: holding a lock across the read and the write keeps every update" {
    try tardis.check(std.testing.allocator, fixed, .{ .iterations = 200 });
}
