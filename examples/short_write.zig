//! Example: writing a buffer to a file.
//!
//! The bug class: **a short write taken for a whole one.** A write may
//! transfer fewer bytes than it was given and say so in its return value.
//! The buggy program calls it once and ignores the count. On a quiet
//! machine the whole buffer goes out every time; under memory pressure, on
//! a network filesystem, or with a signal arriving, some of it does not.
//!
//! The fix writes until everything is out (`writePositionalAll`).
//!
//! The property: the file holds what was written.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

pub const options: tardis.Options = .{ .iterations = 200 };

const message = "a message long enough that a short write can cut it";

fn store(io: Io, dir: Io.Dir, variant: Variant) !void {
    var f = try dir.createFile(io, "message", .{});
    defer f.close(io);
    switch (variant) {
        // One call, its result thrown away.
        .buggy => _ = try f.writePositional(io, &.{message}, 0),
        .fixed => try f.writePositionalAll(io, message, 0),
    }
}

fn scenario(env: *Env, variant: Variant) !void {
    try store(env.io, env.dir, variant);
    var buf: [128]u8 = undefined;
    const got = try env.dir.readFile(env.io, "message", &buf);
    try env.always("the file holds the whole message", std.mem.eql(u8, got, message));
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "short_write: one write call can leave part of the buffer unwritten" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, o));
}

test "short_write: writing until done stores the whole message" {
    try tardis.check(std.testing.allocator, fixed, options);
}
