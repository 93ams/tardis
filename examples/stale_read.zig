//! Example: a primary that replicates to a follower, and a client that
//! writes to one and reads from the other.
//!
//! The bug class: **a stale read.** The buggy primary acknowledges a write
//! and replicates it afterwards. A client that reads from the follower
//! right after its write was acknowledged can get the value from before.
//!
//! The fix replicates before it acknowledges.
//!
//! The property: a read after an acknowledged write returns that write,
//! whichever machine answers.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

pub const options: tardis.Options = .{ .nodes = 3, .iterations = 60, .shrink = false };

const primary_port = 7200;
const follower_port = 7300;

fn anyAddress(port: u16) IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } };
}

fn roundTrip(io: Io, addr: IpAddress, request: []const u8, out: []u8) ![]const u8 {
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var wbuf: [64]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeAll(request) catch return w.err.?;
    w.interface.flush() catch return w.err.?;
    var rbuf: [64]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    const line = r.interface.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.ReadFailed => return r.err.?,
        else => |e| return e,
    };
    @memcpy(out[0..line.len], line);
    return out[0..line.len];
}

/// `W <value>` sets the register, `R` reads it. A node with a `follower`
/// passes each write on.
fn node(io: Io, port: u16, follower: ?IpAddress, variant: Variant) !void {
    var value: u64 = 0;
    var server = try anyAddress(port).listen(io, .{});
    defer server.deinit(io);
    while (true) {
        const stream = try server.accept(io);
        var rbuf: [64]u8 = undefined;
        var r = stream.reader(io, &rbuf);
        const line = r.interface.takeDelimiterExclusive('\n') catch {
            stream.close(io);
            continue;
        };
        var wbuf: [64]u8 = undefined;
        var w = stream.writer(io, &wbuf);
        if (line.len > 2 and line[0] == 'W') {
            value = std.fmt.parseInt(u64, line[2..], 10) catch 0;
            var forward: [32]u8 = undefined;
            const text = std.fmt.bufPrint(&forward, "W {d}\n", .{value}) catch unreachable;
            var out: [16]u8 = undefined;
            // The whole difference: tell the follower before the client,
            // or after.
            if (variant == .fixed) {
                if (follower) |addr| _ = roundTrip(io, addr, text, &out) catch {};
            }
            w.interface.writeAll("OK\n") catch {};
            w.interface.flush() catch {};
            stream.close(io);
            if (variant == .buggy) {
                if (follower) |addr| _ = roundTrip(io, addr, text, &out) catch {};
            }
        } else {
            w.interface.print("V {d}\n", .{value}) catch {};
            w.interface.flush() catch {};
            stream.close(io);
        }
    }
}

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    try env.spawnOn(2, node, .{ io, follower_port, null, variant });
    try env.spawnOn(1, node, .{ io, primary_port, env.address(2, follower_port), variant });
    try io.sleep(.fromMilliseconds(1), .awake);

    var out: [32]u8 = undefined;
    for (1..4) |i| {
        var request: [32]u8 = undefined;
        const value: u64 = i * 11;
        const ack = try roundTrip(io, env.address(1, primary_port), try std.fmt.bufPrint(&request, "W {d}\n", .{value}), &out);
        try std.testing.expectEqualStrings("OK", ack);
        const reply = try roundTrip(io, env.address(2, follower_port), "R\n", &out);
        const read = try std.fmt.parseInt(u64, reply[2..], 10);
        try env.always("a read after an acknowledged write returns it", read == value);
    }
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "stale_read: acknowledging before replicating lets the follower answer with the old value" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, o));
}

test "stale_read: replicating first makes every read see the write" {
    try tardis.check(std.testing.allocator, fixed, options);
}
