//! Differential test of the network model (plan3.md A4): the same small
//! stream and datagram scenarios run on the simulated network, with no
//! faults, and on the real loopback interface of the machine this test
//! runs on. What each side observes is compared: bytes received and their
//! order, where the stream ends, and the error a failed call gives.
//!
//! Each scenario is one function over an `Io`, so the same code is both
//! runs. A stream scenario has its server in a task of its own; a datagram
//! scenario runs in one task, the datagrams waiting in the socket.

const std = @import("std");
const builtin = @import("builtin");
const tardis = @import("../root.zig");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const Stream = Io.net.Stream;
const Env = tardis.Env;
const testing = std.testing;

/// What one side saw: how many bytes, their sum, and how it ended.
const Seen = struct {
    len: usize = 0,
    sum: u64 = 0,
    end: []const u8 = "none",

    fn eql(a: Seen, b: Seen) bool {
        return a.len == b.len and a.sum == b.sum and std.mem.eql(u8, a.end, b.end);
    }
};

const Outcome = struct {
    client: Seen = .{},
    server: Seen = .{},
    /// The error of the call the scenario is about, or "ok".
    call: []const u8 = "ok",

    fn eql(a: Outcome, b: Outcome) bool {
        return a.client.eql(b.client) and a.server.eql(b.server) and std.mem.eql(u8, a.call, b.call);
    }
};

/// A byte weighed by where it is, so that a sum also checks the order.
fn weigh(b: u8, at: usize) u64 {
    return @as(u64, b) * (at % 1021 + 1);
}

/// Reads until the stream ends, one way or the other.
fn drain(io: Io, stream: Stream) Seen {
    var seen: Seen = .{};
    var rbuf: [1024]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    var chunk: [1024]u8 = undefined;
    while (true) {
        const n = r.interface.readSliceShort(&chunk) catch {
            seen.end = if (r.err) |e| @errorName(e) else "ReadFailed";
            return seen;
        };
        for (chunk[0..n], seen.len..) |b, at| seen.sum += weigh(b, at);
        seen.len += n;
        if (n < chunk.len) {
            seen.end = "eof";
            return seen;
        }
    }
}

fn send(io: Io, stream: Stream, bytes: []const u8) []const u8 {
    var wbuf: [64]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeAll(bytes) catch return if (w.err) |e| @errorName(e) else "WriteFailed";
    w.interface.flush() catch return if (w.err) |e| @errorName(e) else "WriteFailed";
    return "ok";
}

const Scenario = enum {
    /// The client sends, closes its sending side and reads the reply; the
    /// server reads to the end and replies.
    half_close_echo,
    /// The server accepts and closes at once; the client reads.
    close_without_data,
    /// The server closes with bytes it never read; the client reads.
    close_with_unread,
    /// Nobody listens on the port.
    refused,
    /// A second listener on a port that has one.
    address_in_use,
    /// The client sends 256 KiB and closes its sending side; the server
    /// reads them all and sends 256 KiB back.
    large_transfer,
    /// Three connections made before any is written to; each is sent a
    /// different length, in the reverse order of connecting, and the
    /// server answers each with its place in the accept order.
    several_connections,
    /// Three datagrams of 5, 1,200 and 1 bytes, echoed back.
    dgram_boundaries,
    /// A datagram of 100 bytes received into a buffer of 10.
    dgram_truncated,
    /// A datagram of no bytes, then one of one byte.
    dgram_empty,

    fn datagram(s: Scenario) bool {
        return @backingInt(s) >= @backingInt(Scenario.dgram_boundaries);
    }
};

const large_len = 256 * 1024;

fn pattern(i: usize) u8 {
    return @truncate(i *% 7 +% 3);
}

/// Sends `len` bytes of `pattern`, in pieces.
fn sendLarge(io: Io, stream: Stream, len: usize) []const u8 {
    var wbuf: [4096]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    var piece: [1000]u8 = undefined;
    var i: usize = 0;
    while (i < len) {
        const n = @min(piece.len, len - i);
        for (piece[0..n], i..) |*b, k| b.* = pattern(k);
        w.interface.writeAll(piece[0..n]) catch return if (w.err) |e| @errorName(e) else "WriteFailed";
        i += n;
    }
    w.interface.flush() catch return if (w.err) |e| @errorName(e) else "WriteFailed";
    return "ok";
}

const connections = 3;

const Server = struct {
    io: Io,
    listener: *Io.net.Server,
    scenario: Scenario,
    seen: Seen = .{},

    fn run(s: *Server) Io.Cancelable!void {
        const stream = s.listener.accept(s.io) catch |e| {
            s.seen.end = @errorName(e);
            return;
        };
        defer stream.close(s.io);
        switch (s.scenario) {
            .half_close_echo => {
                s.seen = drain(s.io, stream);
                _ = send(s.io, stream, "reply");
            },
            .close_without_data => {},
            .close_with_unread => {
                // One byte, so the client's data has arrived; the rest is
                // left unread when the stream closes.
                var one: [1]u8 = undefined;
                var rbuf: [8]u8 = undefined;
                var r = stream.reader(s.io, &rbuf);
                r.interface.readSliceAll(&one) catch {};
                s.seen = .{ .len = 1, .sum = one[0], .end = "closed early" };
            },
            .large_transfer => {
                s.seen = drain(s.io, stream);
                _ = sendLarge(s.io, stream, large_len);
            },
            .several_connections => {
                // The first is accepted above and closed by the defer; the
                // others are accepted here, in turn.
                var k: u8 = 0;
                var current = stream;
                while (true) {
                    const got = drain(s.io, current);
                    s.seen.len += got.len;
                    s.seen.sum += got.sum * (k + 1);
                    s.seen.end = got.end;
                    _ = send(s.io, current, &.{ k, @truncate(got.len) });
                    if (k > 0) current.close(s.io);
                    k += 1;
                    if (k == connections) break;
                    current = s.listener.accept(s.io) catch |e| {
                        s.seen.end = @errorName(e);
                        return;
                    };
                }
            },
            .refused, .address_in_use => {},
            .dgram_boundaries, .dgram_truncated, .dgram_empty => unreachable,
        }
    }
};

/// The datagram scenarios. Each is played in sequence, without a second
/// task: the datagrams wait in the receiving socket. Receives have no
/// timeout, because the real run's `Io` refuses one
/// (`ConcurrencyUnavailable`); a datagram lost on the loopback interface
/// would hang the real run rather than fail it.
fn playDatagram(io: Io, scenario: Scenario, bind_at: IpAddress, reach: ?IpAddress) !Outcome {
    var out: Outcome = .{};
    const server = try bind_at.bind(io, .{ .mode = .dgram });
    defer server.close(io);
    const target = reach orelse server.address;
    var client_at = bind_at;
    client_at.setPort(0);
    const client = try client_at.bind(io, .{ .mode = .dgram });
    defer client.close(io);

    var buf: [2048]u8 = undefined;
    switch (scenario) {
        .dgram_boundaries => {
            const sizes = [_]usize{ 5, 1200, 1 };
            for (sizes, 0..) |n, k| {
                for (buf[0..n], 0..) |*b, i| b.* = pattern(i + k);
                client.send(io, &target, buf[0..n]) catch |e| {
                    out.call = @errorName(e);
                    return out;
                };
            }
            for (0..sizes.len) |k| {
                const msg = server.receive(io, &buf) catch |e| {
                    out.server.end = @errorName(e);
                    return out;
                };
                for (msg.data, out.server.len..) |b, at| out.server.sum += weigh(b, at) * (k + 1);
                out.server.len += msg.data.len;
                if (msg.flags.trunc) out.server.end = "trunc";
                client.send(io, &msg.from, msg.data) catch |e| {
                    out.call = @errorName(e);
                    return out;
                };
            }
            for (0..sizes.len) |k| {
                const msg = client.receive(io, &buf) catch |e| {
                    out.client.end = @errorName(e);
                    return out;
                };
                for (msg.data, out.client.len..) |b, at| out.client.sum += weigh(b, at) * (k + 1);
                out.client.len += msg.data.len;
                if (msg.flags.trunc) out.client.end = "trunc";
            }
        },
        .dgram_truncated => {
            for (buf[0..100], 0..) |*b, i| b.* = pattern(i);
            try client.send(io, &target, buf[0..100]);
            var small: [10]u8 = undefined;
            if (server.receive(io, &small)) |msg| {
                out.server.len = msg.data.len;
                for (msg.data, 0..) |b, at| out.server.sum += weigh(b, at);
                out.server.end = if (msg.flags.trunc) "trunc" else "whole";
            } else |e| out.call = @errorName(e);
        },
        .dgram_empty => {
            // A slice of a real buffer: the address of `&.{}` is not one
            // the kernel accepts, even for no bytes (Linux says EFAULT).
            try client.send(io, &target, buf[0..0]);
            try client.send(io, &target, "z");
            for (0..2) |k| {
                const msg = server.receive(io, &buf) catch |e| {
                    out.server.end = @errorName(e);
                    return out;
                };
                out.server.len += 1;
                out.server.sum += msg.data.len * (k + 1);
            }
        },
        else => unreachable,
    }
    return out;
}

/// `listen_at` is where to listen; `reach` says how the client names the
/// listener (the real run asked for any free port and reads it back).
fn play(io: Io, scenario: Scenario, listen_at: IpAddress, reach: ?IpAddress) !Outcome {
    if (scenario.datagram()) return playDatagram(io, scenario, listen_at, reach);
    var out: Outcome = .{};
    var listener = try listen_at.listen(io, .{});
    const target = reach orelse listener.socket.address;

    switch (scenario) {
        .refused => {
            listener.deinit(io);
            if (target.connect(io, .{ .mode = .stream })) |stream| stream.close(io) else |e| out.call = @errorName(e);
            return out;
        },
        .address_in_use => {
            defer listener.deinit(io);
            if (target.listen(io, .{})) |second| {
                var s = second;
                s.deinit(io);
            } else |e| out.call = @errorName(e);
            return out;
        },
        else => {},
    }
    defer listener.deinit(io);

    var server: Server = .{ .io = io, .listener = &listener, .scenario = scenario };
    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, Server.run, .{&server});

    const stream = target.connect(io, .{ .mode = .stream }) catch |e| {
        // The deferred cancel stops the server, waiting in `accept`.
        out.call = @errorName(e);
        return out;
    };
    defer stream.close(io);
    switch (scenario) {
        .half_close_echo => {
            out.call = send(io, stream, "hello, world");
            stream.shutdown(io, .send) catch |e| {
                out.call = @errorName(e);
            };
            out.client = drain(io, stream);
        },
        .close_without_data => out.client = drain(io, stream),
        .close_with_unread => {
            out.call = send(io, stream, "12345678");
            out.client = drain(io, stream);
        },
        .large_transfer => {
            out.call = sendLarge(io, stream, large_len);
            stream.shutdown(io, .send) catch |e| {
                out.call = @errorName(e);
            };
            out.client = drain(io, stream);
        },
        .several_connections => {
            // `stream` is the first; two more, all before any is used.
            var more: [connections - 1]Stream = undefined;
            var made: usize = 0;
            defer for (more[0..made]) |m| m.close(io);
            while (made < more.len) : (made += 1) {
                more[made] = target.connect(io, .{ .mode = .stream }) catch |e| {
                    // The server may be reading a stream never shut: the
                    // deferred cancel stops it, where awaiting would hang.
                    out.call = @errorName(e);
                    return out;
                };
            }
            {
                const all = [connections]Stream{ stream, more[0], more[1] };
                var j: usize = connections;
                while (j > 0) {
                    j -= 1;
                    var bytes: [connections]u8 = undefined;
                    @memset(bytes[0 .. j + 1], @intCast('a' + j));
                    const r = send(io, all[j], bytes[0 .. j + 1]);
                    if (!std.mem.eql(u8, r, "ok")) out.call = r;
                    all[j].shutdown(io, .send) catch |e| {
                        out.call = @errorName(e);
                    };
                }
                for (all, 0..) |c, k| {
                    const got = drain(io, c);
                    out.client.len += got.len;
                    out.client.sum += got.sum * (k + 1);
                    out.client.end = got.end;
                }
            }
        },
        .refused, .address_in_use => unreachable,
        .dgram_boundaries, .dgram_truncated, .dgram_empty => unreachable,
    }
    try group.await(io);
    out.server = server.seen;
    return out;
}

var real: [std.enums.values(Scenario).len]Outcome = undefined;
var mismatches: u32 = 0;

/// Which scenarios `body` plays: the stream ones, with the network's
/// default range of latencies, or the datagram ones, with one latency.
var datagrams = false;

fn body(env: *Env) !void {
    for (std.enums.values(Scenario), 0..) |scenario, i| {
        if (scenario.datagram() != datagrams) continue;
        const port: u16 = 7000 + @as(u16, @intCast(i));
        const listen_at: IpAddress = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } };
        const got = try play(env.io, scenario, listen_at, env.address(0, port));
        if (got.eql(real[i])) continue;
        // Known and accepted: on Windows a second listener on a port that
        // has one succeeds through Zig's std, where POSIX systems and
        // the model refuse it. The network model has no per-system
        // behaviour to hang this on.
        if (builtin.os.tag == .windows and scenario == .address_in_use and std.mem.eql(u8, real[i].call, "ok")) continue;
        // Known and accepted: on Windows a datagram larger than the
        // receive buffer is an error (WSAEMSGSIZE, `MessageOversize`)
        // where POSIX systems and the model give the first bytes and the
        // truncation flag. On Windows this scenario compares nothing.
        if (builtin.os.tag == .windows and scenario == .dgram_truncated and std.mem.eql(u8, real[i].call, "MessageOversize")) continue;
        mismatches += 1;
        if (mismatches <= 8) std.debug.print(
            "diff_net: {t}: simulated call {s}, client {d} bytes sum {d} end {s}, server {d} bytes end {s}; real call {s}, client {d} bytes sum {d} end {s}, server {d} bytes end {s}\n",
            .{ scenario, got.call, got.client.len, got.client.sum, got.client.end, got.server.len, got.server.end, real[i].call, real[i].client.len, real[i].client.sum, real[i].client.end, real[i].server.len, real[i].server.end },
        );
    }
}

test "diff_net: the simulated network agrees with the real loopback on stream and datagram scenarios" {
    // With the security layer on every check a peer may be an attacker.
    if (tardis.security_by_default) return error.SkipZigTest;
    const loopback: IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } };
    for (std.enums.values(Scenario), 0..) |scenario, i| real[i] = try play(testing.io, scenario, loopback, null);
    mismatches = 0;
    // The model alone: no faults, no added delay in calls, no loss.
    const faults: tardis.FaultOptions = .{ .short_io_ppm = 0, .spurious_wakeup_ppm = 0, .io_latency_min_ns = 0, .io_latency_max_ns = 0, .datagram_loss_ppm = 0, .datagram_duplicate_ppm = 0 };
    datagrams = false;
    try tardis.check(testing.allocator, body, .{
        .iterations = 20,
        .faults = faults,
        .determinism_check_every = 0,
    });
    // One latency for every datagram: a range would reorder them, which
    // UDP allows and the model may do, and the loopback interface does not.
    datagrams = true;
    try tardis.check(testing.allocator, body, .{
        .iterations = 20,
        .faults = faults,
        .net = .{ .latency_min_ns = 50_000, .latency_max_ns = 50_000 },
        .determinism_check_every = 0,
    });
    if (mismatches != 0) return error.ModelDisagreesWithHost;
}
