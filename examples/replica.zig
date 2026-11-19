//! Example: a primary that forwards each write to a replica, on three
//! simulated machines (the client, the primary, the replica).
//!
//! The bug class: **a replica left behind by a partition.** The buggy
//! primary forwards a write once and, if the replica cannot be reached,
//! drops the forward and acknowledges anyway. While the network is whole
//! the two always agree. After one partition they disagree for ever.
//!
//! The fix retries the forward until the replica has it.
//!
//! The property: once the network has healed, the replica catches up with
//! the primary.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

const client_node = 0;
const primary_node = 1;
const replica_node = 2;
const primary_port = 7000;
const replica_port = 7100;

fn anyAddress(port: u16) IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } };
}

/// One request, one reply line.
fn roundTrip(io: Io, addr: IpAddress, request: []const u8, out: []u8, timeout: Io.Timeout) ![]const u8 {
    const stream = try addr.connect(io, .{ .mode = .stream, .timeout = timeout });
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

/// A register: `W <value>` sets it, `R` reads it. With a `replica`, a
/// write is forwarded there before it is acknowledged.
fn node(io: Io, port: u16, replica: ?IpAddress, variant: Variant) !void {
    var value: u64 = 0;
    var server = try anyAddress(port).listen(io, .{});
    defer server.deinit(io);
    while (true) {
        const stream = try server.accept(io);
        defer stream.close(io);
        var rbuf: [64]u8 = undefined;
        var r = stream.reader(io, &rbuf);
        const line = r.interface.takeDelimiterExclusive('\n') catch continue;
        var wbuf: [64]u8 = undefined;
        var w = stream.writer(io, &wbuf);
        if (line.len > 2 and line[0] == 'W') {
            value = std.fmt.parseInt(u64, line[2..], 10) catch continue;
            if (replica) |addr| {
                var forward: [32]u8 = undefined;
                const text = try std.fmt.bufPrint(&forward, "W {d}\n", .{value});
                var out: [16]u8 = undefined;
                while (true) {
                    // A short timeout keeps an unreachable replica from
                    // stalling the primary for ever.
                    _ = roundTrip(io, addr, text, &out, .{ .duration = .{ .raw = .fromMilliseconds(100), .clock = .awake } }) catch {
                        // The whole difference: give up, or try again.
                        if (variant == .buggy) break;
                        try io.sleep(.fromMilliseconds(50), .awake);
                        continue;
                    };
                    break;
                }
            }
            w.interface.writeAll("OK\n") catch continue;
        } else {
            w.interface.print("V {d}\n", .{value}) catch continue;
        }
        w.interface.flush() catch continue;
    }
}

fn readValue(io: Io, addr: IpAddress) !u64 {
    var out: [32]u8 = undefined;
    const reply = try roundTrip(io, addr, "R\n", &out, .none);
    return std.fmt.parseInt(u64, reply[2..], 10);
}

fn writeValue(io: Io, addr: IpAddress, value: u64) Io.Cancelable!void {
    var request: [32]u8 = undefined;
    var out: [16]u8 = undefined;
    const text = std.fmt.bufPrint(&request, "W {d}\n", .{value}) catch unreachable;
    _ = roundTrip(io, addr, text, &out, .none) catch {};
}

const Cluster = struct {
    io: Io,
    primary: IpAddress,
    replica: IpAddress,
};

fn agree(c: *Cluster) !bool {
    return try readValue(c.io, c.primary) == try readValue(c.io, c.replica);
}

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    try env.spawnOn(replica_node, node, .{ io, replica_port, null, variant });
    try env.spawnOn(primary_node, node, .{ io, primary_port, env.address(replica_node, replica_port), variant });
    try io.sleep(.fromMilliseconds(1), .awake);
    var cluster: Cluster = .{ .io = io, .primary = env.address(primary_node, primary_port), .replica = env.address(replica_node, replica_port) };

    // One write while the network is whole, one while the primary cannot
    // reach the replica.
    try writeValue(io, cluster.primary, 1);
    env.partition(primary_node, replica_node);
    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, writeValue, .{ io, cluster.primary, 2 + @as(u64, try env.fuzz(u8)) });
    try io.sleep(.fromMilliseconds(500), .awake);
    env.healAll();
    try group.await(io);

    try env.eventually("after the partition heals, the replica catches up", 30 * std.time.ns_per_s, &cluster, agree);
}

fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "replica: a forward dropped during a partition leaves the replica behind for ever" {
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, .{
        .nodes = 3,
        .iterations = 30,
        .report = false,
        .shrink = false,
    }));
}

test "replica: retrying the forward until it is acknowledged converges" {
    try tardis.check(std.testing.allocator, fixed, .{ .nodes = 3, .iterations = 30 });
}
