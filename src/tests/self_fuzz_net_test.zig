//! Fuzzing the simulator's network (plan3.md A6): random programs over
//! three nodes, drawn from the seed, with connection resets, datagram
//! loss and duplication, clock steps, and links cut and nodes crashed
//! both between exchanges and while streams are open. As in
//! `self_fuzz_test.zig`, what is asserted is the simulator's side of the
//! contract:
//!
//! - it does not panic and no run hangs, whatever the program does;
//! - every run is deterministic (in the one-worker test each is run
//!   twice and compared);
//! - nothing leaks, on any node, node crashes included;
//! - a stream never invents, loses or reorders bytes: what an echo sends
//!   back and the client reads to a clean end is exactly what was sent;
//! - a datagram is delivered whole or not at all, only if it was sent,
//!   and from where it was sent to.

const std = @import("std");
const tardis = @import("../root.zig");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const Stream = Io.net.Stream;
const Env = tardis.Env;
const testing = std.testing;

const stream_port: u16 = 9000;
const dgram_port: u16 = 9001;
const servers = [_]tardis.NodeId{ 1, 2 };

fn any(port: u16) IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } };
}

fn timeoutMs(ms: i64) Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
}

/// What a read to the end of a stream saw.
const Seen = struct {
    len: usize = 0,
    /// Byte `i` was `fill +% i`.
    uniform: bool = true,
    /// The stream ended with an end of file, not an error.
    clean: bool = false,
};

fn drain(io: Io, stream: Stream, fill: u8) Seen {
    var seen: Seen = .{};
    var rbuf: [32]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    var chunk: [48]u8 = undefined;
    while (true) {
        const n = r.interface.readSliceShort(&chunk) catch return seen;
        for (chunk[0..n], seen.len..) |b, i| {
            if (b != fill +% @as(u8, @truncate(i))) seen.uniform = false;
        }
        seen.len += n;
        if (n < chunk.len) {
            seen.clean = true;
            return seen;
        }
    }
}

fn send(io: Io, stream: Stream, bytes: []const u8) bool {
    var wbuf: [32]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeAll(bytes) catch return false;
    w.interface.flush() catch return false;
    return true;
}

/// Reads one request to its end and sends it back. A request that ended
/// in an error gets no reply.
fn echoOne(io: Io, stream: Stream) void {
    var request: [256]u8 = undefined;
    var len: usize = 0;
    var rbuf: [32]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    while (len < request.len) {
        const n = r.interface.readSliceShort(request[len..]) catch return;
        len += n;
        if (len < request.len) break;
    }
    switch (planted) {
        .flipped_byte => if (len != 0) {
            request[len / 2] ^= 1;
        },
        .lost_byte => if (len != 0) {
            len -= 1;
        },
        else => {},
    }
    _ = send(io, stream, request[0..len]);
}

/// A daemon: echoes one connection at a time, for ever.
fn streamEcho(io: Io) void {
    var server = any(stream_port).listen(io, .{}) catch return;
    defer server.deinit(io);
    while (true) {
        const stream = server.accept(io) catch |e| {
            if (e == error.Canceled) return;
            io.sleep(.fromMilliseconds(1), .awake) catch return;
            continue;
        };
        defer stream.close(io);
        echoOne(io, stream);
    }
}

/// A daemon: sends every datagram back to its sender.
fn dgramEcho(io: Io) void {
    const sock = any(dgram_port).bind(io, .{ .mode = .dgram }) catch return;
    defer sock.close(io);
    var buf: [128]u8 = undefined;
    while (true) {
        const msg = sock.receive(io, &buf) catch |e| {
            if (e == error.Canceled) return;
            io.sleep(.fromMilliseconds(1), .awake) catch return;
            continue;
        };
        const data = if (planted == .cut_datagram and msg.data.len > 1) msg.data[0 .. msg.data.len - 1] else msg.data;
        sock.send(io, &msg.from, data) catch {};
    }
}

const Exchange = struct {
    io: Io,
    to: IpAddress,
    len: usize,
    fill: u8,
    /// The reply was read to a clean end.
    clean: bool = false,
    /// The clean reply was wrong: other bytes, or a part of the request.
    wrong: bool = false,
    whole: bool = false,

    fn run(x: *Exchange) Io.Cancelable!void {
        const stream = x.to.connect(x.io, .{ .mode = .stream }) catch return;
        defer stream.close(x.io);
        var data: [200]u8 = undefined;
        for (data[0..x.len], 0..) |*b, i| b.* = x.fill +% @as(u8, @truncate(i));
        if (!send(x.io, stream, data[0..x.len])) return;
        stream.shutdown(x.io, .send) catch return;
        const seen = drain(x.io, stream, x.fill);
        if (!seen.clean) return;
        x.clean = true;
        x.whole = seen.len == x.len;
        // The echo answers nothing only to a request that ended in an
        // error, and the client of such a stream does not read a clean end.
        x.wrong = !seen.uniform or seen.len != x.len;
    }
};

/// While exchanges are under way: after a moment, cuts links to a server
/// and heals them, or crashes the server.
const Disturbance = struct {
    env: *Env,
    node: tardis.NodeId,
    what: u8,
    wait_us: i64,
    crashed: bool = false,

    fn run(d: *Disturbance) Io.Cancelable!void {
        const io = d.env.io;
        try io.sleep(.fromMicroseconds(d.wait_us), .awake);
        switch (d.what % 4) {
            0 => d.env.cutLink(0, d.node),
            1 => d.env.cutLink(d.node, 0),
            2 => d.env.partition(0, d.node),
            else => {
                d.env.crashNode(d.node, if (d.what & 4 == 0) .power_loss else .process_crash);
                d.crashed = true;
                return;
            },
        }
        // Healed again, so that nothing waits on a cut for ever.
        try io.sleep(.fromMicroseconds(d.wait_us * 3), .awake);
        d.env.healLink(0, d.node);
        d.env.healLink(d.node, 0);
    }
};

const Kind = enum {
    exchange,
    exchanges,
    /// Exchanges with a link cut or a server crashed under them.
    disturbed,
    datagram,
    cut,
    heal,
    partition,
    isolate,
    heal_all,
    crash_node,
    step_clock,
    sleep,
    file,
};

/// A bug planted in the echo daemons, for the tests of the oracles.
var planted: enum { none, flipped_byte, lost_byte, cut_datagram } = .none;

fn body(env: *Env) !void {
    const io = env.io;
    for (servers) |node| {
        try env.spawnOn(node, streamEcho, .{io});
        try env.spawnOn(node, dgramEcho, .{io});
    }
    // One datagram socket for the run, so that a late reply is one of
    // this run's own.
    const sock: ?Io.net.Socket = any(0).bind(io, .{ .mode = .dgram }) catch null;
    defer if (sock) |s| s.close(io);
    var sent_len: [256]u8 = @splat(0);
    var next_id: u8 = 1;

    const steps = 6 + (try env.fuzz(u8)) % 24;
    var crashes: u8 = 0;
    for (0..steps) |_| {
        const kinds = std.enums.values(Kind);
        const kind = kinds[(try env.fuzz(u8)) % kinds.len];
        const node: tardis.NodeId = servers[(try env.fuzz(u8)) % servers.len];
        const other: tardis.NodeId = @intCast((try env.fuzz(u8)) % 3);
        const len: usize = 1 + (try env.fuzz(u8)) % 200;
        const fill = try env.fuzz(u8);
        switch (kind) {
            .exchange, .exchanges, .disturbed => {
                var xs: [3]Exchange = undefined;
                const count: usize = if (kind == .exchange) 1 else 2 + fill % 2;
                var disturbance: Disturbance = .{ .env = env, .node = node, .what = fill >> 2, .wait_us = 20 + @as(i64, @intCast(len)) * 15 };
                for (xs[0..count], 0..) |*x, i| x.* = .{
                    .io = io,
                    .to = env.address(servers[(node + i) % servers.len], stream_port),
                    .len = len,
                    .fill = fill +% @as(u8, @intCast(i)),
                };
                {
                    var group: Io.Group = .init;
                    defer group.cancel(io);
                    for (xs[0..count]) |*x| group.concurrent(io, Exchange.run, .{x}) catch break;
                    if (kind == .disturbed) group.concurrent(io, Disturbance.run, .{&disturbance}) catch {};
                    try group.await(io);
                }
                if (disturbance.crashed) {
                    try env.spawnOn(node, streamEcho, .{io});
                    try env.spawnOn(node, dgramEcho, .{io});
                }
                for (xs[0..count]) |*x| {
                    if (x.clean and !x.wrong) env.sometimes("an echo came back whole", true);
                    if (kind == .disturbed and x.clean) env.sometimes("an echo came back whole through a disturbance", true);
                    if (kind == .disturbed and !x.clean) env.sometimes("a disturbance broke an exchange", true);
                    try env.always("an echo read to a clean end is the request", !x.wrong);
                }
            },
            .datagram => {
                const s = sock orelse continue;
                if (next_id == 255) continue;
                const id = next_id;
                next_id += 1;
                const n = 1 + len % 100;
                sent_len[id] = @intCast(n);
                var data: [100]u8 = undefined;
                @memset(data[0..n], id);
                const to = env.address(node, dgram_port);
                s.send(io, &to, data[0..n]) catch continue;
                // Replies, this one's or a late one: each must be a
                // datagram this run sent, whole.
                for (0..2) |_| {
                    var buf: [128]u8 = undefined;
                    const reply = s.receiveTimeout(io, &buf, timeoutMs(5)) catch break;
                    var ok = reply.data.len != 0;
                    if (ok) {
                        const got = reply.data[0];
                        for (reply.data) |b| ok = ok and b == got;
                        ok = ok and got != 0 and got < next_id and sent_len[got] == reply.data.len;
                        // From an echo daemon, whichever it was sent to.
                        ok = ok and reply.from.ip4.port == dgram_port and
                            (reply.from.eql(&env.address(1, dgram_port)) or reply.from.eql(&env.address(2, dgram_port)));
                    }
                    env.sometimes("a datagram came back", ok);
                    try env.always("a datagram arrives whole, and only one that was sent", ok);
                }
            },
            .cut => env.cutLink(node, other),
            .heal => env.healLink(other, node),
            .partition => if (node != other) env.partition(node, other),
            .isolate => env.isolate(other),
            .heal_all => env.healAll(),
            .crash_node => {
                if (crashes == 3) continue;
                crashes += 1;
                env.crashNode(node, if (fill & 1 == 0) .power_loss else .process_crash);
                env.sometimes("a node crashed and its daemons were started again", true);
                try env.spawnOn(node, streamEcho, .{io});
                try env.spawnOn(node, dgramEcho, .{io});
            },
            .step_clock => env.stepClock(other, @as(i64, fill) * 1_000_000 - 100_000_000),
            .sleep => try io.sleep(.fromMicroseconds(@as(i64, fill) * 40), .awake),
            .file => env.dir.writeFile(io, .{ .sub_path = "side", .data = &.{fill} }) catch {},
        }
    }
}

const options: tardis.Options = .{
    .nodes = 3,
    .iterations = 300,
    .determinism_check_every = 1,
    // (Injected I/O errors are for files; sockets have resets.)
    .faults = .{ .net_reset_ppm = 10_000, .datagram_loss_ppm = 100_000, .datagram_duplicate_ppm = 50_000 },
};

test "self-fuzz: random network programs are deterministic, leak nothing, and never invent bytes" {
    // With the security layer on every check a peer may be an attacker,
    // whose bytes are not the program's.
    if (tardis.security_by_default) return error.SkipZigTest;
    try tardis.check(testing.allocator, body, options);
}

test "self-fuzz: the same network programs on four workers" {
    if (tardis.security_by_default) return error.SkipZigTest;
    var o = options;
    o.iterations = 200;
    o.workers = 4;
    o.determinism_check_every = 16;
    try tardis.check(testing.allocator, body, o);
}

test "fuzz oracles (network): an echo that changes a byte, loses a byte or cuts a datagram is caught" {
    // Planted bugs, tied to this test's seeds: not for the nightly
    // campaign, which picks tests by "self-fuzz".
    if (tardis.security_by_default) return error.SkipZigTest;
    defer planted = .none;
    for ([_]@TypeOf(planted){ .flipped_byte, .lost_byte, .cut_datagram }) |bug| {
        planted = bug;
        var o = options;
        o.report = false;
        o.shrink = false;
        try testing.expectError(error.AssertionFailed, tardis.check(testing.allocator, body, o));
    }
}
