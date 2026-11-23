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

// ---------------------------------------------------------------------------
// A hundred nodes

/// Sends `id` to `node`'s echo until its reply comes; false if none did.
fn askNode(io: Io, sock: Io.net.Socket, server: IpAddress, id: u8) !bool {
    for (0..8) |_| {
        try sock.send(io, &server, &.{id});
        var buf: [8]u8 = undefined;
        // Replies to earlier questions are skipped.
        while (true) {
            const reply = sock.receiveTimeout(io, &buf, timeoutMs(20)) catch |err| switch (err) {
                error.Timeout => break,
                else => return err,
            };
            if (reply.data.len == 1 and reply.data[0] == id) return true;
        }
    }
    return false;
}

fn hundredNodes(env: *Env) !void {
    const io = env.io;
    for (1..100) |n| try env.spawnOn(@intCast(n), udpEcho, .{io});
    const sock = try any(0).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    for (1..100) |n| try testing.expect(try askNode(io, sock, env.address(@intCast(n), 53), @intCast(n)));
    // A cut is of two nodes and no others, on either side of the 32nd
    // and the 64th node.
    for ([_]u8{ 31, 32, 33, 63, 64, 65, 99 }) |far| {
        env.partition(0, far);
        try testing.expect(!try askNode(io, sock, env.address(far, 53), far));
        try testing.expect(try askNode(io, sock, env.address(far - 1, 53), far - 1));
        if (far != 99) try testing.expect(try askNode(io, sock, env.address(far + 1, 53), far + 1));
        env.healLink(0, far);
        env.healLink(far, 0);
        try testing.expect(try askNode(io, sock, env.address(far, 53), far));
        // The way out alone, which is this node's own bit in the first
        // node's row: the nodes 32 and 64 below it are not cut with it.
        env.cutLink(0, far);
        try testing.expect(!try askNode(io, sock, env.address(far, 53), far));
        if (far > 32) try testing.expect(try askNode(io, sock, env.address(far - 32, 53), far - 32));
        if (far > 64) try testing.expect(try askNode(io, sock, env.address(far - 64, 53), far - 64));
        env.healLink(0, far);
        try testing.expect(try askNode(io, sock, env.address(far, 53), far));
    }
    // One direction only: the question arrives, the answer does not.
    env.cutLink(99, 0);
    try testing.expect(!try askNode(io, sock, env.address(99, 53), 99));
    env.healAll();
    try testing.expect(try askNode(io, sock, env.address(99, 53), 99));
}

test "a hundred nodes: each answers, and a cut link cuts those two and no others" {
    // The security layer watches 32 nodes and refuses a check with more.
    if (tardis.security_by_default) return error.SkipZigTest;
    try testing.expect(tardis.nodes_max >= 100);
    try tardis.check(gpa, hundredNodes, .{
        .nodes = 100,
        .iterations = 3,
        .swarm = false,
        // No datagram is lost, and none comes twice: a second copy of an
        // answer, still on its way, would speak for a node just cut off.
        .faults = .{ .datagram_loss_ppm = 0, .datagram_duplicate_ppm = 0 },
        .limits = .{ .tasks_max = 128, .net = .{ .sockets_max = 128 } },
    });
}
