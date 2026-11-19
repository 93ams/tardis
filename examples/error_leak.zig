//! Example: copying one file to another.
//!
//! The bug class: **a resource leaked on an error path.** The program
//! opens the source, opens the destination, copies, and closes both. When
//! a read or a write fails it returns the error, and the two handles stay
//! open. The happy path is clean, so a test that never sees an I/O error
//! never sees the leak; a long-running service sees it as a slow march to
//! "too many open files".
//!
//! The fix closes with `defer`, on every path.
//!
//! The property is the simulator's own: a run leaves no handle open.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

pub const options: tardis.Options = .{ .iterations = 300, .faults = .{ .io_error_ppm = 50_000 } };

fn copyLeaky(io: Io, dir: Io.Dir) !void {
    var src = try dir.openFile(io, "source", .{});
    var dst = try dir.createFile(io, "copy", .{});
    var buf: [64]u8 = undefined;
    const n = try src.readPositionalAll(io, &buf, 0);
    try dst.writePositionalAll(io, buf[0..n], 0);
    dst.close(io);
    src.close(io);
}

fn copyClean(io: Io, dir: Io.Dir) !void {
    var src = try dir.openFile(io, "source", .{});
    defer src.close(io);
    var dst = try dir.createFile(io, "copy", .{});
    defer dst.close(io);
    var buf: [64]u8 = undefined;
    const n = try src.readPositionalAll(io, &buf, 0);
    try dst.writePositionalAll(io, buf[0..n], 0);
}

fn scenario(env: *Env, variant: Variant) !void {
    env.dir.writeFile(env.io, .{ .sub_path = "source", .data = "some bytes worth copying" }) catch return;
    // A failed copy is an outcome the caller handles; what it must not do
    // is leave anything open.
    switch (variant) {
        .buggy => copyLeaky(env.io, env.dir) catch {},
        .fixed => copyClean(env.io, env.dir) catch {},
    }
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "error_leak: an I/O error on the way leaves both files open" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.ResourceLeak, tardis.check(std.testing.allocator, buggy, o));
}

test "error_leak: closing with defer leaves nothing open on any path" {
    try tardis.check(std.testing.allocator, fixed, options);
}
