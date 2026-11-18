//! M2: datagrams, batch/timeout operations, partition-induced TCP timeouts,
//! per-node heaps.

const std = @import("std");
const tardis = @import("../root.zig");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const Env = tardis.Env;
const testing = std.testing;
const gpa = testing.allocator;

fn any(port: u16) IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } };
}

fn timeoutMs(ms: i64) Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
}

// ---------------------------------------------------------------------------
// Request/response over lossy UDP with retries

/// Echoes every datagram back to its sender.
fn udpEcho(io: Io) !void {
    const sock = try any(53).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    var buf: [64]u8 = undefined;
    while (true) {
        const msg = try sock.receive(io, &buf);
        try sock.send(io, &msg.from, msg.data);
    }
}

fn udpClient(env: *Env) !void {
    const io = env.io;
    try env.spawnOn(1, udpEcho, .{io});
    const sock = try any(0).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    const server = env.address(1, 53);

    var next_id: u8 = 0;
    for (0..5) |_| {
        const id = next_id;
        next_id += 1;
        var attempts: u32 = 0;
        // Retry until the reply for *this* id arrives; replies to earlier
        // attempts (late or duplicated) are skipped.
        while (true) {
            attempts += 1;
            if (attempts > 20) return error.ServerUnreachable;
            try sock.send(io, &server, &.{id});
            var buf: [8]u8 = undefined;
            const reply = sock.receiveTimeout(io, &buf, timeoutMs(20)) catch |err| switch (err) {
                error.Timeout => continue,
                else => return err,
            };
            env.sometimes("a stale or duplicate reply arrived", reply.data[0] != id);
            if (reply.data.len == 1 and reply.data[0] == id) break;
        }
        env.sometimes("a request needed a retry", attempts > 1);
    }
}

test "udp: request/response with retries survives loss, duplication and reordering" {
    try tardis.check(gpa, udpClient, .{
        .nodes = 2,
        .iterations = 120,
        .swarm = false,
        .faults = .{ .datagram_loss_ppm = 150_000, .datagram_duplicate_ppm = 100_000 },
    });
}

/// Bug: assumes datagrams arrive exactly once, in order.
fn udpSink(io: Io, out: *[4]u8, n: *usize) !void {
    const sock = try any(9).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    var buf: [8]u8 = undefined;
    while (n.* < out.len) {
        const msg = try sock.receive(io, &buf);
        out[n.*] = msg.data[0];
        n.* += 1;
    }
}

fn udpAssumesReliable(env: *Env) !void {
    const io = env.io;
    var got: [4]u8 = undefined;
    var n: usize = 0;
    try env.spawnOn(1, udpSink, .{ io, &got, &n });
    try io.sleep(.fromMilliseconds(1), .awake);
    const sock = try any(0).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    for (0..4) |i| try sock.send(io, &env.address(1, 9), &.{@intCast(i)});
    try io.sleep(.fromSeconds(1), .awake);
    try env.always("datagrams arrive once and in order", n == 4 and std.mem.eql(u8, &got, &.{ 0, 1, 2, 3 }));
}

test "udp: code that assumes reliable in-order datagrams is caught (bug found)" {
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, udpAssumesReliable, .{
        .nodes = 2,
        .iterations = 50,
        .report = false,
    }));
}

// ---------------------------------------------------------------------------
// Batch: operateTimeout on a stream read

fn silentServer(io: Io) !void {
    var server = try any(7).listen(io, .{});
    defer server.deinit(io);
    const stream = try server.accept(io);
    defer stream.close(io);
    try io.sleep(.fromSeconds(3600), .awake);
}

fn readTimeout(env: *Env) !void {
    const io = env.io;
    try env.spawnOn(1, silentServer, .{io});
    try io.sleep(.fromMilliseconds(1), .awake);
    const stream = try env.address(1, 7).connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var buf: [8]u8 = undefined;
    var vec = [_][]u8{&buf};
    const t0 = env.nowNs();
    try testing.expectError(error.Timeout, io.operateTimeout(.{ .net_read = .{
        .socket_handle = stream.socket.handle,
        .data = &vec,
    } }, timeoutMs(250)));
    try testing.expect(env.nowNs() - t0 >= 250 * std.time.ns_per_ms);
}

test "batch: operateTimeout times out a read nobody answers" {
    try tardis.check(gpa, readTimeout, .{ .nodes = 2, .iterations = 20 });
}

// ---------------------------------------------------------------------------
// A partition longer than the retransmit timeout

fn echoForever(io: Io) !void {
    var server = try any(8).listen(io, .{});
    defer server.deinit(io);
    while (true) {
        const stream = try server.accept(io);
        defer stream.close(io);
        var rb: [16]u8 = undefined;
        var r = stream.reader(io, &rb);
        var wb: [16]u8 = undefined;
        var w = stream.writer(io, &wb);
        while (true) {
            const b = r.interface.takeByte() catch break;
            w.interface.writeByte(b) catch break;
            w.interface.flush() catch break;
        }
    }
}

fn longPartition(env: *Env) !void {
    const io = env.io;
    try env.spawnOn(1, echoForever, .{io});
    try io.sleep(.fromMilliseconds(1), .awake);
    const stream = try env.address(1, 8).connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var wb: [8]u8 = undefined;
    var w = stream.writer(io, &wb);
    var rb: [8]u8 = undefined;
    var r = stream.reader(io, &rb);

    w.interface.writeByte('a') catch return w.err.?;
    w.interface.flush() catch return w.err.?;
    try testing.expectEqual(@as(u8, 'a'), r.interface.takeByte() catch return r.err.?);

    env.isolate(1);
    const t0 = env.nowNs();
    w.interface.writeByte('b') catch return w.err.?;
    w.interface.flush() catch return w.err.?;
    _ = r.interface.takeByte() catch {
        try testing.expectEqual(error.ConnectionTimedOut, r.err.?);
        try testing.expect(env.nowNs() - t0 >= 60 * std.time.ns_per_s);
        return;
    };
    return error.ExpectedTimeout;
}

test "tcp: a partition that outlasts the retransmit timeout fails the connection" {
    try tardis.check(gpa, longPartition, .{ .nodes = 2, .iterations = 20 });
}

// ---------------------------------------------------------------------------
// Per-node heaps

fn leakAndExit(a: std.mem.Allocator) !void {
    _ = try a.alloc(u8, 16);
}

fn holdForever(io: Io, a: std.mem.Allocator) !void {
    _ = try a.alloc(u8, 16);
    try io.sleep(.fromSeconds(3600), .awake);
}

fn finishedDaemonLeaks(env: *Env) !void {
    try env.spawnOn(1, leakAndExit, .{env.nodeAllocator(1)});
    try env.io.sleep(.fromMilliseconds(1), .awake);
}

fn liveDaemonOwnsMemory(env: *Env) !void {
    try env.spawnOn(1, holdForever, .{ env.io, env.nodeAllocator(1) });
    try env.io.sleep(.fromMilliseconds(1), .awake);
}

fn crashedDaemonMemoryIsWiped(env: *Env) !void {
    try env.spawnOn(1, holdForever, .{ env.io, env.nodeAllocator(1) });
    try env.io.sleep(.fromMilliseconds(1), .awake);
    env.crashNode(1, .process_crash);
}

test "heap: a daemon that exits without freeing leaks on its node" {
    try testing.expectError(error.ResourceLeak, tardis.check(gpa, finishedDaemonLeaks, .{
        .nodes = 2,
        .iterations = 1,
        .faults = .{ .oom_ppm = 0 },
        .report = false,
    }));
}

test "heap: a live daemon owns its node's memory; a crash wipes it" {
    try tardis.check(gpa, liveDaemonOwnsMemory, .{ .nodes = 2, .iterations = 5 });
    try tardis.check(gpa, crashedDaemonMemoryIsWiped, .{ .nodes = 2, .iterations = 5 });
}
