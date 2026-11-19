//! Example: reading a fixed-size header from a file.
//!
//! The bug class: **a short read taken for a whole one.** A read may return
//! fewer bytes than the buffer holds and say so in its result. The buggy
//! program calls it once, ignores the count, and parses the whole buffer,
//! part of which is whatever was there before.
//!
//! The fix reads until the header is complete (`readPositionalAll`).
//!
//! The property: the header parsed is the header stored.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

pub const options: tardis.Options = .{ .iterations = 200 };

const header = "MAGIC-v2:length=00042;crc=9f3a";

fn readHeader(io: Io, dir: Io.Dir, out: *[header.len]u8, variant: Variant) !void {
    var f = try dir.openFile(io, "blob", .{});
    defer f.close(io);
    // What a reused buffer holds before the read.
    @memset(out, '?');
    switch (variant) {
        // One call, its result thrown away.
        .buggy => _ = try f.readPositional(io, &.{out}, 0),
        .fixed => _ = try f.readPositionalAll(io, out, 0),
    }
}

fn scenario(env: *Env, variant: Variant) !void {
    try env.dir.writeFile(env.io, .{ .sub_path = "blob", .data = header ++ "payload" });
    var got: [header.len]u8 = undefined;
    try readHeader(env.io, env.dir, &got, variant);
    try env.always("the header parsed is the header stored", std.mem.eql(u8, &got, header));
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "short_read: one read call can return part of the header" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, o));
}

test "short_read: reading until complete parses the stored header" {
    try tardis.check(std.testing.allocator, fixed, options);
}
