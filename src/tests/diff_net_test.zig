//! Differential test of the network model (plan3.md A4): the same small
//! stream scenarios run on the simulated network, with no faults, and on
//! the real loopback interface of the machine this test runs on. What each
//! side observes is compared: bytes received, where the stream ends, and
//! the error a failed call gives.
//!
//! Each scenario is one function over an `Io`, with the server in a task
//! of its own, so the same code is both runs.

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

/// Reads until the stream ends, one way or the other.
fn drain(io: Io, stream: Stream) Seen {
    var seen: Seen = .{};
    var rbuf: [64]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    var chunk: [64]u8 = undefined;
    while (true) {
        const n = r.interface.readSliceShort(&chunk) catch {
            seen.end = if (r.err) |e| @errorName(e) else "ReadFailed";
            return seen;
        };
        for (chunk[0..n]) |b| seen.sum += b;
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
};

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
            .refused, .address_in_use => {},
        }
    }
};

/// `listen_at` is where to listen; `reach` says how the client names the
/// listener (the real run asked for any free port and reads it back).
fn play(io: Io, scenario: Scenario, listen_at: IpAddress, reach: ?IpAddress) !Outcome {
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
        out.call = @errorName(e);
        try group.await(io);
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
        .refused, .address_in_use => unreachable,
    }
    try group.await(io);
    out.server = server.seen;
    return out;
}

var real: [std.enums.values(Scenario).len]Outcome = undefined;
var mismatches: u32 = 0;

fn body(env: *Env) !void {
    for (std.enums.values(Scenario), 0..) |scenario, i| {
        const port: u16 = 7000 + @as(u16, @intCast(i));
        const listen_at: IpAddress = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } };
        const got = try play(env.io, scenario, listen_at, env.address(0, port));
        if (got.eql(real[i])) continue;
        // Known and accepted: on Windows a second listener on a port that
        // has one succeeds through Zig's std, where POSIX systems and
        // the model refuse it. The network model has no per-system
        // behaviour to hang this on.
        if (builtin.os.tag == .windows and scenario == .address_in_use and std.mem.eql(u8, real[i].call, "ok")) continue;
        mismatches += 1;
        if (mismatches <= 8) std.debug.print(
            "diff_net: {t}: simulated call {s}, client {d} bytes sum {d} end {s}, server {d} bytes end {s}; real call {s}, client {d} bytes sum {d} end {s}, server {d} bytes end {s}\n",
            .{ scenario, got.call, got.client.len, got.client.sum, got.client.end, got.server.len, got.server.end, real[i].call, real[i].client.len, real[i].client.sum, real[i].client.end, real[i].server.len, real[i].server.end },
        );
    }
}

test "diff_net: the simulated network agrees with the real loopback on stream scenarios" {
    // With the security layer on every check a peer may be an attacker.
    if (tardis.security_by_default) return error.SkipZigTest;
    const loopback: IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } };
    for (std.enums.values(Scenario), 0..) |scenario, i| real[i] = try play(testing.io, scenario, loopback, null);
    mismatches = 0;
    try tardis.check(testing.allocator, body, .{
        .iterations = 20,
        // The model alone: no faults, no latency, no loss.
        .faults = .{ .short_io_ppm = 0, .spurious_wakeup_ppm = 0, .io_latency_min_ns = 0, .io_latency_max_ns = 0, .datagram_loss_ppm = 0, .datagram_duplicate_ppm = 0 },
        .determinism_check_every = 0,
    });
    if (mismatches != 0) return error.ModelDisagreesWithHost;
}
