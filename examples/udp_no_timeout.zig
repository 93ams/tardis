//! Example: asking a server a question over datagrams.
//!
//! The bug class: **waiting for ever for a message that was lost.** The
//! client sends its question and waits for the answer. Datagrams are not
//! promised to arrive. When the question or the answer is lost, the client
//! waits with nothing left that could wake it.
//!
//! The fix waits a bounded time and asks again.
//!
//! The property is the simulator's own: no run ends with every task
//! blocked.

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
    .faults = .{ .datagram_loss_ppm = 150_000, .datagram_duplicate_ppm = 0 },
};

const port = 4200;

fn anyAddress(p: u16) IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = p } };
}

/// Answers each question with its number plus one.
fn oracle(io: Io) !void {
    const sock = try anyAddress(port).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    var buf: [8]u8 = undefined;
    while (true) {
        const msg = try sock.receive(io, &buf);
        if (msg.data.len != 1) continue;
        try sock.send(io, &msg.from, &.{msg.data[0] +% 1});
    }
}

fn ask(io: Io, sock: anytype, server: *const IpAddress, question: u8, variant: Variant) !u8 {
    var buf: [8]u8 = undefined;
    switch (variant) {
        .buggy => {
            try sock.send(io, server, &.{question});
            const reply = try sock.receive(io, &buf);
            return reply.data[0];
        },
        .fixed => {
            var attempts: u32 = 0;
            while (attempts < 40) : (attempts += 1) {
                try sock.send(io, server, &.{question});
                const reply = sock.receiveTimeout(io, &buf, .{ .duration = .{ .raw = .fromMilliseconds(20), .clock = .awake } }) catch |err| switch (err) {
                    error.Timeout => continue,
                    else => return err,
                };
                // An answer to an earlier, repeated question is not this one's.
                if (reply.data.len == 1 and reply.data[0] == question +% 1) return reply.data[0];
            }
            return error.ServerUnreachable;
        },
    }
}

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    try env.spawnOn(1, oracle, .{io});
    // Let the server open its socket: a question sent before that is
    // lost on a perfect network too, which is not this example's point.
    try io.sleep(.fromMilliseconds(1), .awake);
    const sock = try anyAddress(0).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    const server = env.address(1, port);
    for (0..4) |i| {
        const question: u8 = @intCast(i * 10);
        const answer = try ask(io, sock, &server, question, variant);
        try env.always("the answer is the question plus one", answer == question + 1);
    }
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "udp_no_timeout: a lost datagram leaves the client waiting for ever" {
    // An open defect of the simulator (plan.md, Open items): on Windows in
    // ReleaseFast, a run that ends in a deadlock with tasks waiting for
    // datagrams is followed by a crash in a later run of the same process.
    if (@import("builtin").os.tag == .windows and @import("builtin").mode == .fast) return error.SkipZigTest;
    var o = options;
    o.report = false;
    try std.testing.expectError(error.Deadlock, tardis.check(std.testing.allocator, buggy, o));
}

test "udp_no_timeout: a bounded wait and a retry get the answer" {
    try tardis.check(std.testing.allocator, fixed, options);
}
