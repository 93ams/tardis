//! Example: a setting pushed to a device over datagrams, latest wins.
//!
//! The bug class: **trusting the order of arrival.** The device applies
//! each update as it comes. Datagrams can be duplicated and delayed, so an
//! old update can arrive after a newer one and put the old value back.
//!
//! The fix numbers the updates, and the device ignores one older than what
//! it has.
//!
//! The property: once the network is quiet, the device has the last value
//! sent.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

pub const options: tardis.Options = .{
    .nodes = 2,
    .iterations = 200,
    .swarm = false,
    // Nothing is lost here: only duplicated, and late.
    .faults = .{ .datagram_loss_ppm = 0, .datagram_duplicate_ppm = 300_000 },
};

const port = 4100;

fn anyAddress(p: u16) IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = p } };
}

/// Updates are `sequence, value`. `shown` is the device's display, which
/// the test can see.
fn device(io: Io, variant: Variant, shown: *u8) !void {
    const sock = try anyAddress(port).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    var newest: ?u8 = null;
    var buf: [8]u8 = undefined;
    while (true) {
        const msg = try sock.receive(io, &buf);
        if (msg.data.len != 2) continue;
        // The whole difference: an update older than the newest is stale.
        if (variant == .fixed) {
            if (newest != null and msg.data[0] <= newest.?) continue;
            newest = msg.data[0];
        }
        shown.* = msg.data[1];
    }
}

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    var shown: u8 = 0;
    try env.spawnOn(1, device, .{ io, variant, &shown });
    const sock = try anyAddress(0).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    const target = env.address(1, port);

    var last: u8 = 0;
    for (0..5) |i| {
        last = 10 + @as(u8, @intCast(i));
        try sock.send(io, &target, &.{ @intCast(i), last });
        try io.sleep(.fromMicroseconds(200), .awake);
    }
    // Long enough for every copy, however late, to have arrived.
    try io.sleep(.fromSeconds(2), .awake);
    try env.always("the device shows the last value sent", shown == last);
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "udp_order: a late copy of an old update puts the old value back" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, o));
}

test "udp_order: numbered updates leave the newest in place" {
    try tardis.check(std.testing.allocator, fixed, options);
}
