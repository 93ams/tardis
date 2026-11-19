//! Example: deposits sent to a server over datagrams, retried until
//! acknowledged.
//!
//! The bug class: **a retry applied twice.** The client sends a deposit
//! and, hearing nothing, sends it again. When it was the acknowledgement
//! that got lost, not the request, the server has already applied the
//! deposit, and applies it again.
//!
//! The fix gives each request a number, and the server remembers the last
//! one it applied.
//!
//! The property: the balance is the sum of the deposits.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

pub const options: tardis.Options = .{
    .nodes = 2,
    .iterations = 150,
    .swarm = false,
    .faults = .{ .datagram_loss_ppm = 200_000, .datagram_duplicate_ppm = 0 },
};

const port = 4000;

fn anyAddress(p: u16) IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = p } };
}

/// Requests: `D id amount` deposits, `Q id 0` asks for the balance.
/// Replies echo the kind and the id; a `Q` reply carries the balance.
fn bank(io: Io, variant: Variant) !void {
    const sock = try anyAddress(port).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    var balance: u8 = 0;
    var last_applied: ?u8 = null;
    var buf: [8]u8 = undefined;
    while (true) {
        const msg = try sock.receive(io, &buf);
        if (msg.data.len != 3) continue;
        const kind = msg.data[0];
        const id = msg.data[1];
        if (kind == 'D') {
            // The whole difference: a request seen before is acknowledged
            // again, not applied again.
            const seen = variant == .fixed and last_applied != null and last_applied.? == id;
            if (!seen) balance +%= msg.data[2];
            last_applied = id;
        }
        try sock.send(io, &msg.from, &.{ kind, id, balance });
    }
}

/// Sends until the reply for this request arrives; returns its last byte.
fn request(io: Io, sock: anytype, server: *const IpAddress, kind: u8, id: u8, amount: u8) !u8 {
    var attempts: u32 = 0;
    while (attempts < 40) : (attempts += 1) {
        try sock.send(io, server, &.{ kind, id, amount });
        var buf: [8]u8 = undefined;
        const reply = sock.receiveTimeout(io, &buf, .{ .duration = .{ .raw = .fromMilliseconds(20), .clock = .awake } }) catch |err| switch (err) {
            error.Timeout => continue,
            else => return err,
        };
        if (reply.data.len == 3 and reply.data[0] == kind and reply.data[1] == id) return reply.data[2];
    }
    return error.ServerUnreachable;
}

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    try env.spawnOn(1, bank, .{ io, variant });
    const sock = try anyAddress(0).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    const server = env.address(1, port);

    var sum: u8 = 0;
    for (0..4) |i| {
        const amount = 1 + (try env.fuzz(u8)) % 9;
        _ = try request(io, sock, &server, 'D', @intCast(i), amount);
        sum += amount;
    }
    const balance = try request(io, sock, &server, 'Q', 100, 0);
    try env.always("the balance is the sum of the deposits", balance == sum);
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "udp_retry: a deposit retried after a lost acknowledgement is applied twice" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, o));
}

test "udp_retry: numbered requests are applied once however often they are sent" {
    try tardis.check(std.testing.allocator, fixed, options);
}
