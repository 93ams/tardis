//! System-call mode's sockets against the Linux kernel's (plan3.md D9).
//!
//! Random sequences of socket calls on loopback run in the simulator (no
//! faults) and on the kernel, and are compared call by call: return value
//! or error, and what a call wrote back (bytes read, the shape of an
//! address). Port numbers are not compared, only whether a port is zero:
//! the kernel and the simulator choose ephemeral ports differently.
//!
//! The calls block, and a test that runs them on one thread must not ask
//! for a read with nothing to read, or an `accept` with nothing waiting.
//! The runner keeps a model of what is in flight (bytes per direction,
//! datagrams per socket, connections per listener) and skips a call that
//! would wait, in both runs alike. If the model is wrong the kernel run
//! does not hang: every kernel socket has two-second send and receive
//! timeouts, so the call fails with `EAGAIN` and the comparison shows it.

const std = @import("std");
const tardis = @import("../root.zig");
const Env = tardis.Env;
const testing = std.testing;
const gpa = testing.allocator;
const linux = std.os.linux;

const supported = tardis.syscall_mode_supported;

fn sys(number: linux.SYS, a: usize, b: usize, c: usize, d: usize) isize {
    return @bitCast(linux.syscall4(number, a, b, c, d));
}

fn sys6(number: linux.SYS, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) isize {
    return @bitCast(linux.syscall6(number, a, b, c, d, e, f));
}

const SockaddrIn = extern struct {
    family: u16 = 2,
    port_be: u16 = 0,
    addr: [4]u8 = .{ 0, 0, 0, 0 },
    zero: [8]u8 = @splat(0),
};

const msg_nosignal = 0x4000;
const pollin = 0x1;
const pollout = 0x4;
const pollerr = 0x8;
const pollrdhup = 0x2000;
const einprogress = -115;

/// `poll` of one descriptor; its events go to `revents`.
fn pollOne(fd: usize, events: u16, timeout_ms: i32, revents: *u64) isize {
    var p = extern struct { fd: i32, events: i16, revents: i16 }{ .fd = @intCast(fd), .events = @bitCast(events), .revents = 0 };
    const rc = sys(.poll, @intFromPtr(&p), 1, @as(u32, @bitCast(timeout_ms)), 0);
    revents.* = @as(u16, @bitCast(p.revents));
    return rc;
}
const slots = 4;
const ops_max = 40;

const Kind = enum {
    socket_stream,
    socket_dgram,
    bind_any,
    bind_loopback,
    /// Bind to the port another socket has.
    bind_taken,
    listen,
    connect,
    accept,
    send,
    sendto,
    recv,
    shutdown,
    close,
    getsockname,
    getpeername,
    so_error,
    so_type,
    /// `fcntl(F_SETFL, O_NONBLOCK)`: from then on a call that would wait
    /// fails with `EAGAIN`, and the runner makes it instead of skipping it.
    nonblock,
    /// `poll` of the socket for reading, writing and the peer's end, with
    /// no timeout: the events it has now.
    poll,
};

const Op = struct {
    kind: Kind,
    slot: u8,
    /// The socket a call aims at (its port), or none: a port with nothing.
    target: u8,
    len: u8,
    how: u8,
};

const Result = struct {
    rc: isize = 0,
    digest: u64 = 0,
    /// Skipped as it would wait.
    skipped: bool = false,
};

fn generate(seed: u64, ops: []Op) void {
    var prng: std.Random.DefaultPrng = .init(seed);
    const r = prng.random();
    for (ops) |*op| op.* = .{
        .kind = r.enumValue(Kind),
        .slot = r.uintLessThan(u8, slots),
        .target = r.uintLessThan(u8, slots + 1),
        .len = r.uintLessThan(u8, 49),
        .how = r.uintLessThan(u8, 3),
    };
}

/// A stream connection, from the client's slot `a` to the server's `b`
/// (null until accepted).
const Conn = struct {
    a: u8,
    b: ?u8 = null,
    listener: ?u8,
    /// Bytes sent and not yet read, a to b and b to a.
    ab: usize = 0,
    ba: usize = 0,
    a_wr: bool = false,
    b_wr: bool = false,
    a_rd: bool = false,
    b_rd: bool = false,
    a_closed: bool = false,
    b_closed: bool = false,
    reset: bool = false,
};

const Model = struct {
    fds: [slots]?usize = @splat(null),
    stream: [slots]bool = @splat(false),
    listening: [slots]bool = @splat(false),
    /// Connections waiting in each listener's queue.
    pending: [slots]u8 = @splat(0),
    /// The connection each stream slot is an end of.
    conn: [slots]?u8 = @splat(null),
    /// Not modelled: a stream reset by its peer is closed again on Linux,
    /// and may be bound or connected anew; the simulator keeps it
    /// connected. A slot that has been connected is not bound or
    /// connected again.
    was_connected: [slots]bool = @splat(false),
    nonblock: [slots]bool = @splat(false),
    /// The slot holds its port: bound, listening or connected, and no
    /// `connect` failed since (a failed one gives up a port the kernel
    /// chose; another socket's `bind` to it meets the kernel's own state
    /// for that port, which cannot be compared).
    holds_port: [slots]bool = @splat(false),
    conns: [16]Conn = undefined,
    conns_len: u8 = 0,
    /// Datagrams queued for each slot; the port a datagram socket is
    /// connected to (big-endian, as in the address); and whether an error
    /// waits for it (a datagram to its peer found no socket there: the
    /// kernel's ICMP port unreachable).
    queued: [slots]u8 = @splat(0),
    dgram_peer: [slots]?u16 = @splat(null),
    dgram_err: [slots]bool = @splat(false),
};

fn localAddress(fd: usize) SockaddrIn {
    var a: SockaddrIn = .{};
    var len: u32 = @sizeOf(SockaddrIn);
    if (sys(.getsockname, fd, @intFromPtr(&a), @intFromPtr(&len), 0) != 0) return .{};
    return a;
}

/// Where a call aimed at `target` goes: loopback, at that socket's port,
/// or at port 1 (nothing listens there) for no socket.
fn targetAddress(m: *const Model, target: u8) SockaddrIn {
    if (target < slots) if (m.fds[target]) |fd| {
        var a = localAddress(fd);
        a.addr = .{ 127, 0, 0, 1 };
        return a;
    };
    return .{ .port_be = std.mem.nativeToBig(u16, 1), .addr = .{ 127, 0, 0, 1 } };
}

fn addressDigest(a: *const SockaddrIn, len: u32) u64 {
    return (@as(u64, a.family) << 48) | (@as(u64, @intFromBool(a.port_be != 0)) << 40) |
        (@as(u64, std.mem.readInt(u32, &a.addr, .big)) << 8) | len;
}

/// A new socket on the kernel gets timeouts, so a wrong model fails a call
/// instead of hanging the test.
fn timeouts(real: bool, fd: usize) void {
    if (!real) return;
    const tv = [2]i64{ 2, 0 };
    _ = sys6(.setsockopt, fd, 1, 20, @intFromPtr(&tv), @sizeOf(@TypeOf(tv)), 0); // SO_RCVTIMEO
    _ = sys6(.setsockopt, fd, 1, 21, @intFromPtr(&tv), @sizeOf(@TypeOf(tv)), 0); // SO_SNDTIMEO
}

fn freeSlot(m: *const Model) ?u8 {
    for (m.fds, 0..) |fd, i| if (fd == null) return @intCast(i);
    return null;
}

/// The other end's slot of `slot`'s connection, if it is accepted and open.
fn connOf(m: *Model, slot: u8) ?*Conn {
    return &m.conns[m.conn[slot] orelse return null];
}

/// The same code for the kernel and the simulator.
fn run(real: bool, ops: []const Op, out: []Result) void {
    var m: Model = .{};
    var buf: [64]u8 align(8) = undefined;
    for (ops, out) |op, *res| {
        res.* = .{};
        const s = op.slot;
        const fd_opt = m.fds[s];
        switch (op.kind) {
            .socket_stream, .socket_dgram => {
                if (fd_opt != null) {
                    res.skipped = true;
                    continue;
                }
                const stream = op.kind == .socket_stream;
                const rc = sys(.socket, 2, if (stream) 1 else 2, 0, 0);
                res.rc = @min(rc, 0);
                if (rc < 0) continue;
                m.fds[s] = @intCast(rc);
                m.stream[s] = stream;
                m.listening[s] = false;
                m.pending[s] = 0;
                m.conn[s] = null;
                m.was_connected[s] = false;
                m.nonblock[s] = false;
                m.holds_port[s] = false;
                m.queued[s] = 0;
                m.dgram_peer[s] = null;
                m.dgram_err[s] = false;
                timeouts(real, @intCast(rc));
                continue;
            },
            else => {},
        }
        const fd = fd_opt orelse {
            res.skipped = true;
            continue;
        };
        switch (op.kind) {
            .socket_stream, .socket_dgram => unreachable,
            .bind_any, .bind_loopback, .bind_taken => {
                if (m.was_connected[s]) {
                    res.skipped = true;
                    continue;
                }
                var a: SockaddrIn = .{};
                if (op.kind == .bind_loopback) a.addr = .{ 127, 0, 0, 1 };
                if (op.kind == .bind_taken) {
                    // A port another open socket has (never a closed one's:
                    // the kernel keeps those in TIME_WAIT, the simulator not).
                    // Of the same protocol: TCP and UDP ports are apart,
                    // and a clash with a port the kernel chose for itself
                    // cannot be compared.
                    if (op.target >= slots or op.target == s or m.fds[op.target] == null or m.stream[op.target] != m.stream[s] or
                        (m.stream[op.target] and !m.holds_port[op.target]))
                    {
                        res.skipped = true;
                        continue;
                    }
                    a = localAddress(m.fds[op.target].?);
                }
                res.rc = sys(.bind, fd, @intFromPtr(&a), @sizeOf(SockaddrIn), 0);
                if (res.rc == 0) m.holds_port[s] = true;
            },
            .listen => {
                res.rc = sys(.listen, fd, 8, 0, 0);
                if (res.rc == 0 and m.stream[s]) {
                    m.listening[s] = true;
                    m.holds_port[s] = true;
                }
            },
            .connect => {
                const t = op.target;
                if (m.was_connected[s]) {
                    res.skipped = true;
                    continue;
                }
                // Not modelled: a stream socket connecting to its own port
                // (Linux's simultaneous open connects it to itself).
                if (m.stream[s]) {
                    const own = localAddress(fd).port_be;
                    if (t == s or (own != 0 and targetAddress(&m, t).port_be == own)) {
                        res.skipped = true;
                        continue;
                    }
                }
                const to_listener = t < slots and m.fds[t] != null and m.listening[t] and m.stream[s];
                // The kernel's queue is the backlog plus one; past it a
                // connect waits.
                if (to_listener and m.pending[t] >= 3) {
                    res.skipped = true;
                    continue;
                }
                const a = targetAddress(&m, t);
                res.rc = sys(.connect, fd, @intFromPtr(&a), @sizeOf(SockaddrIn), 0);
                if (m.nonblock[s] and m.stream[s] and res.rc == einprogress) {
                    // Wait for the outcome, as non-blocking code does: the
                    // kernel finishes the handshake after the call.
                    var revents: u64 = 0;
                    _ = pollOne(fd, pollout, 2000, &revents);
                    res.digest = revents;
                    if (revents & pollerr != 0) {
                        m.holds_port[s] = false;
                        continue;
                    }
                } else if (res.rc != 0) {
                    if (res.rc != -106) m.holds_port[s] = false; // EISCONN changes nothing
                    continue;
                }
                m.holds_port[s] = true;
                if (m.stream[s]) {
                    m.was_connected[s] = true;
                    if (to_listener and m.conns_len < m.conns.len) {
                        m.conns[m.conns_len] = .{ .a = s, .listener = t };
                        m.conn[s] = m.conns_len;
                        m.conns_len += 1;
                        m.pending[t] += 1;
                    }
                } else m.dgram_peer[s] = a.port_be;
            },
            .accept => {
                if (m.listening[s] and m.pending[s] == 0 and !m.nonblock[s]) {
                    res.skipped = true;
                    continue;
                }
                const into = freeSlot(&m);
                if (m.listening[s] and into == null) {
                    res.skipped = true;
                    continue;
                }
                var peer: SockaddrIn = .{};
                var peer_len: u32 = @sizeOf(SockaddrIn);
                const rc = sys(.accept, fd, @intFromPtr(&peer), @intFromPtr(&peer_len), 0);
                res.rc = @min(rc, 0);
                if (rc < 0) continue;
                res.digest = addressDigest(&peer, peer_len);
                const n = into.?;
                m.fds[n] = @intCast(rc);
                m.stream[n] = true;
                m.listening[n] = false;
                m.pending[n] = 0;
                m.queued[n] = 0;
                m.dgram_peer[n] = null;
                m.dgram_err[n] = false;
                m.was_connected[n] = true;
                m.nonblock[n] = false;
                m.holds_port[n] = true;
                m.pending[s] -|= 1;
                timeouts(real, @intCast(rc));
                // The oldest connection waiting on this listener.
                for (m.conns[0..m.conns_len], 0..) |*c, ci| {
                    if (c.listener == s and c.b == null and !c.reset) {
                        c.b = n;
                        m.conn[n] = @intCast(ci);
                        break;
                    }
                }
            },
            .send, .sendto => {
                @memset(buf[0..op.len], op.len);
                var dest_port: ?u16 = m.dgram_peer[s];
                if (op.kind == .send) {
                    res.rc = sys6(.sendto, fd, @intFromPtr(&buf), op.len, msg_nosignal, 0, 0);
                } else {
                    const a = targetAddress(&m, op.target);
                    dest_port = a.port_be;
                    res.rc = sys6(.sendto, fd, @intFromPtr(&buf), op.len, msg_nosignal, @intFromPtr(&a), @sizeOf(SockaddrIn));
                }
                if (!m.stream[s]) m.dgram_err[s] = false;
                if (res.rc < 0) continue;
                if (m.stream[s]) {
                    if (connOf(&m, s)) |c| {
                        const n: usize = @intCast(res.rc);
                        if (c.a == s) c.ab += n else c.ba += n;
                        // Data to a closed end is answered with a reset.
                        if ((c.a == s and c.b_closed) or (c.b == s and c.a_closed)) c.reset = true;
                    }
                } else {
                    // The datagram's receiver: the open datagram socket at
                    // that port, which takes it unless it is connected to
                    // another port than the sender's.
                    const from_port = localAddress(fd).port_be;
                    var to: ?u8 = null;
                    if (dest_port) |p| if (p != 0) for (0..slots) |t| {
                        if (m.fds[t] == null or m.stream[t]) continue;
                        if (localAddress(m.fds[t].?).port_be == p) to = @intCast(t);
                    };
                    if (to) |t| {
                        if ((m.dgram_peer[t] == null or m.dgram_peer[t] == from_port) and m.queued[t] < 32) m.queued[t] += 1;
                    } else if (m.dgram_peer[s] != null and dest_port == m.dgram_peer[s]) m.dgram_err[s] = true;
                }
            },
            .recv => {
                var want: usize = op.len;
                if (m.stream[s]) {
                    if (connOf(&m, s)) |c| {
                        const is_a = c.a == s;
                        if (!is_a and c.b != s) unreachable;
                        const incoming = if (is_a) c.ba else c.ab;
                        const done = if (is_a) (c.b_wr or c.b_closed) else (c.a_wr or c.a_closed);
                        const shut_rd = if (is_a) c.a_rd else c.b_rd;
                        if (incoming == 0 and !done and !c.reset and !shut_rd and !m.nonblock[s]) {
                            res.skipped = true;
                            continue;
                        }
                        if (c.reset or shut_rd) want = 0;
                        if (want > 0 and incoming > 0) {
                            // All of it, whatever the segments: the kernel
                            // and the simulator cut a stream differently.
                            want = @min(want, incoming);
                            var got: usize = 0;
                            while (got < want) {
                                const rc = sys6(.recvfrom, fd, @intFromPtr(&buf) + got, want - got, 0, 0, 0);
                                if (rc <= 0) {
                                    res.rc = rc;
                                    break;
                                }
                                got += @intCast(rc);
                            } else res.rc = @intCast(got);
                            res.digest = std.hash.Wyhash.hash(0, buf[0..got]);
                            if (is_a) c.ba -= got else c.ab -= got;
                            continue;
                        }
                        want = op.len;
                    } else if (!m.listening[s]) {
                        // Not connected: an error, at once. A socket that
                        // connected to nothing listening is not either.
                    }
                } else if (m.queued[s] == 0 and !m.dgram_err[s] and !m.nonblock[s]) {
                    res.skipped = true;
                    continue;
                }
                var from: SockaddrIn = .{};
                var from_len: u32 = @sizeOf(SockaddrIn);
                res.rc = sys6(.recvfrom, fd, @intFromPtr(&buf), want, 0, @intFromPtr(&from), @intFromPtr(&from_len));
                if (res.rc > 0) res.digest = std.hash.Wyhash.hash(0, buf[0..@intCast(res.rc)]);
                if (!m.stream[s]) {
                    m.dgram_err[s] = false;
                    if (res.rc >= 0) {
                        m.queued[s] -|= 1;
                        res.digest +%= addressDigest(&from, from_len);
                    }
                }
            },
            .shutdown => {
                res.rc = sys(.shutdown, fd, op.how, 0, 0);
                if (res.rc != 0) continue;
                if (m.listening[s]) continue;
                if (connOf(&m, s)) |c| {
                    const rd = op.how != 1;
                    const wr = op.how != 0;
                    if (c.a == s) {
                        c.a_rd = c.a_rd or rd;
                        c.a_wr = c.a_wr or wr;
                    } else {
                        c.b_rd = c.b_rd or rd;
                        c.b_wr = c.b_wr or wr;
                    }
                }
            },
            .close => {
                res.rc = sys(.close, fd, 0, 0, 0);
                m.fds[s] = null;
                if (m.listening[s]) {
                    // Connections still in its queue are reset.
                    for (m.conns[0..m.conns_len]) |*c| if (c.listener == s and c.b == null) {
                        c.reset = true;
                    };
                }
                if (connOf(&m, s)) |c| {
                    if (c.a == s) {
                        c.a_closed = true;
                        if (c.ba > 0) c.reset = true; // unread data: a reset, not an end
                    } else {
                        c.b_closed = true;
                        if (c.ab > 0) c.reset = true;
                    }
                }
                m.conn[s] = null;
                m.listening[s] = false;
                m.queued[s] = 0;
            },
            .getsockname, .getpeername => {
                var a: SockaddrIn = .{};
                var len: u32 = @sizeOf(SockaddrIn);
                res.rc = sys(if (op.kind == .getsockname) .getsockname else .getpeername, fd, @intFromPtr(&a), @intFromPtr(&len), 0);
                if (res.rc == 0) res.digest = addressDigest(&a, len);
            },
            .so_error, .so_type => {
                var v: u32 = 0;
                var len: u32 = 4;
                res.rc = sys6(.getsockopt, fd, 1, if (op.kind == .so_error) 4 else 3, @intFromPtr(&v), @intFromPtr(&len), 0);
                if (res.rc == 0) res.digest = (@as(u64, v) << 8) | len;
                if (op.kind == .so_error) m.dgram_err[s] = false;
            },
            .nonblock => {
                res.rc = sys(.fcntl, fd, 4, 0o4000, 0); // F_SETFL, O_NONBLOCK
                if (res.rc == 0) m.nonblock[s] = true;
            },
            .poll => res.rc = pollOne(fd, pollin | pollout | pollrdhup, 0, &res.digest),
        }
    }
    for (m.fds) |fd| if (fd) |f| {
        _ = sys(.close, f, 0, 0, 0);
    };
}

/// 20,000 agreed when this was written (revisions 81 and 82); the suite runs fewer.
const sequences = 5_000;

const Record = struct {
    seed: u64 = 0,
    started: bool = false,
    ran: bool = false,
    results: [ops_max]Result = undefined,
};
var records: []Record = &.{};

fn body(env: *Env) !void {
    if (env.iteration >= records.len) return;
    const record = &records[env.iteration];
    var ops: [ops_max]Op = undefined;
    generate(env.seed, &ops);
    record.seed = env.seed;
    record.started = true;
    run(false, &ops, &record.results);
    record.ran = true;
}

test "system-call mode: random sequences of socket calls answer as the Linux kernel answers them" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    records = try gpa.alloc(Record, sequences);
    defer gpa.free(records);
    @memset(records, .{});

    tardis.check(gpa, body, .{
        .iterations = sequences,
        .mode = .syscalls,
        .swarm = false,
        .leak_check = false,
        .shrink = false,
        .determinism_check_every = 0,
        // Loopback delivers at once, as the call returns.
        .net = .{ .latency_min_ns = 0, .latency_max_ns = 0 },
        // The model alone: no faults, no loss.
        .faults = .{ .short_io_ppm = 0, .spurious_wakeup_ppm = 0, .io_latency_min_ns = 0, .io_latency_max_ns = 0, .datagram_loss_ppm = 0, .datagram_duplicate_ppm = 0 },
    }) catch |err| {
        // The sequence the simulator could not finish, as the kernel ran it.
        for (records) |*record| if (record.started and !record.ran) {
            var ops: [ops_max]Op = undefined;
            var real: [ops_max]Result = undefined;
            generate(record.seed, &ops);
            run(true, &ops, &real);
            std.debug.print("the simulator did not finish seed 0x{x}; the kernel ran it so:\n", .{record.seed});
            for (ops, real, 0..) |o, r, k| std.debug.print("  {d}: {s} slot={d} target={d} len={d} how={d} -> {d}{s}\n", .{ k, @tagName(o.kind), o.slot, o.target, o.len, o.how, r.rc, if (r.skipped) " (skipped)" else "" });
            break;
        };
        return err;
    };

    var ops: [ops_max]Op = undefined;
    var real: [ops_max]Result = undefined;
    var compared: usize = 0;
    for (records, 0..) |*record, sequence| {
        if (!record.ran) continue;
        generate(record.seed, &ops);
        run(true, &ops, &real);
        for (real, record.results, 0..) |want, got, i| {
            if (want.rc == got.rc and want.digest == got.digest and want.skipped == got.skipped) continue;
            std.debug.print("sequence {d} (seed 0x{x}), call {d}: the kernel gave {d} (digest {x}{s}), the simulator {d} (digest {x}{s})\n", .{
                sequence, record.seed, i,                                    want.rc, want.digest, if (want.skipped) ", skipped" else "",
                got.rc,   got.digest,  if (got.skipped) ", skipped" else "",
            });
            for (ops[0 .. i + 1], real[0 .. i + 1], 0..) |o, r, k| std.debug.print("  {d}: {s} slot={d} target={d} len={d} how={d} -> {d}{s}\n", .{ k, @tagName(o.kind), o.slot, o.target, o.len, o.how, r.rc, if (r.skipped) " (skipped)" else "" });
            return error.SimulatorDisagreesWithKernel;
        }
        compared += 1;
    }
    try testing.expect(compared > 0);
}
