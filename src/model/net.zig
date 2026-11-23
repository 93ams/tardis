//! Virtual network (plan §9 M2): TCP-like byte streams between simulated
//! nodes.
//!
//! This file holds only data structures and non-blocking state transitions;
//! `Sim.zig` adds blocking, cancelation and fault injection on top.
//!
//! Model:
//! * Node `n` has address `10.0.0.(n+1)`; `127.0.0.1` is the caller's node.
//! * Every stream socket owns a receive ring. A writer copies into the
//!   peer's ring and appends a *segment* with a delivery time
//!   (`now + one-way latency`, never earlier than the previous segment, so
//!   bytes stay in order). Only delivered bytes are readable.
//! * A full receive ring blocks the writer (flow control).
//! * Reachability is a directed bitmask matrix. A segment sent across a cut
//!   link is *held* and delivered after the link heals, as TCP
//!   retransmission would.
//! * Closing a socket with unread received data resets the peer instead of
//!   sending FIN, as Linux and Windows do.
//! * A crashed node's peers see either a reset or, for a black-holed
//!   connection, `ConnectionTimedOut` after a timeout.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const decide = @import("../sim/decide.zig");

pub const NodeId = u8;
/// The most nodes a simulation can have. A node's address is
/// `10.0.0.(node+1)`, and a reachability row is one `Reach`.
pub const nodes_limit = 128;
/// A row of the reachability matrix: one bit per node.
const Reach = u128;

comptime {
    assert(@bitSizeOf(Reach) == nodes_limit);
}

pub const Limits = struct {
    sockets_max: u16 = 64,
    rx_buffer_bytes: u32 = 16 * 1024,
    /// In-flight segments per receive ring (one is reserved for FIN).
    segments_max: u16 = 64,
    backlog_max: u8 = 16,
};

pub const Options = struct {
    /// One-way latency per segment, drawn uniformly per segment.
    latency_min_ns: u64 = 50_000,
    latency_max_ns: u64 = 2_000_000,
    /// `connect` without an explicit timeout gives up after this long when
    /// the destination is unreachable.
    connect_timeout_ns: u64 = 10 * std.time.ns_per_s,
    /// When a node crashes, a peer connection is black-holed (instead of
    /// reset) with this probability; it then fails with
    /// `ConnectionTimedOut` after `blackhole_timeout_ns`.
    blackhole_ppm: decide.Ppm = 300_000,
    blackhole_timeout_ns: u64 = 30 * std.time.ns_per_s,
    /// A connection whose sent data is held by a partition this long fails
    /// with `ConnectionTimedOut` (TCP retransmission gives up).
    retransmit_timeout_ns: u64 = 60 * std.time.ns_per_s,
};

pub const ephemeral_port_first: u16 = 49152;
const backlog_cap = 32;

/// `bound`: a stream socket's port reserved by `bind`, before `listen` or
/// `connect` (system-call mode; `std.Io` has no such state).
pub const Kind = enum(u8) { free, listener, stream, dgram, bound };

pub const Fault = enum(u8) { none, reset, timed_out };

pub const Segment = struct {
    len: u32,
    deliver_at: u64,
    held: bool,
    fin: bool,
    /// Sender, for datagrams.
    src_node: NodeId = 0,
    src_port: u16 = 0,
    /// A datagram sent to a loopback address.
    loopback: bool = false,
};

const no_peer: u16 = std.math.maxInt(u16);

pub const Socket = struct {
    kind: Kind,
    generation: u16,
    node: NodeId,
    local_port: u16,

    // Listener state.
    backlog: [backlog_cap]u16,
    backlog_len: u8,
    backlog_limit: u8,

    // Stream state.
    peer: u16,
    peer_generation: u16,
    peer_node: NodeId,
    peer_port: u16,
    /// True while the socket waits in a listener's backlog (kernel-owned).
    in_backlog: bool,
    /// A connection made to a loopback address: both ends' addresses read
    /// as 127.0.0.1, as on a real host.
    loopback: bool = false,
    rx: []u8,
    rx_head: u32,
    /// Bytes buffered, delivered or not.
    rx_len: u32,
    /// Bytes delivered (readable).
    rx_ready: u32,
    segs: []Segment,
    seg_head: u16,
    seg_len: u16,
    last_deliver_at: u64,
    eof: bool,
    shut_send: bool,
    shut_recv: bool,
    fault: Fault,
    fault_at: u64,
    /// Non-zero while a sent segment is held by a cut link: the connection
    /// fails with `ConnectionTimedOut` at this time unless the link heals.
    rto_at: u64,
};

pub const RecvResult = union(enum) {
    data: usize,
    eof,
    fault: Fault,
    /// Nothing readable yet; the earliest virtual time at which that may
    /// change without another task acting, if any.
    would_block: ?u64,
};

pub const SendCheck = union(enum) {
    /// Bytes that may be written now.
    ready: u32,
    fault: Fault,
    shut_down,
    /// The peer closed; bytes are discarded and this socket is reset after
    /// a round trip.
    peer_gone,
    /// The peer's receive ring is full.
    would_block,
};

pub const Net = struct {
    gpa: Allocator,
    limits: Limits,
    sockets: []Socket,
    /// Every socket's receive buffer, `limits.rx_buffer_bytes` each. Empty
    /// until a run first opens a socket: a test without a network does not
    /// pay for it (1 MiB with the default limits).
    rx_pool: []u8,
    seg_pool: []Segment,
    node_count: u8,
    /// `reach[a] & (1 << b) != 0`: packets flow from node a to node b.
    reach: [nodes_limit]Reach,
    ephemeral_next: [nodes_limit]u16,

    pub fn init(gpa: Allocator, limits: Limits, node_count: u8) !Net {
        assert(node_count >= 1 and node_count <= nodes_limit);
        assert(limits.sockets_max >= 1 and limits.sockets_max < 0xFFFF);
        assert(limits.segments_max >= 2);
        assert(limits.backlog_max >= 1 and limits.backlog_max <= backlog_cap);
        const n: usize = limits.sockets_max;
        const sockets = try gpa.alloc(Socket, n);
        errdefer gpa.free(sockets);
        const seg_pool = try gpa.alloc(Segment, n * limits.segments_max);
        errdefer gpa.free(seg_pool);
        var net: Net = .{
            .gpa = gpa,
            .limits = limits,
            .sockets = sockets,
            .rx_pool = &.{},
            .seg_pool = seg_pool,
            .node_count = node_count,
            .reach = undefined,
            .ephemeral_next = undefined,
        };
        for (sockets, 0..) |*s, i| {
            s.kind = .free;
            s.generation = 0;
            s.rx = &.{};
            s.segs = seg_pool[i * limits.segments_max ..][0..limits.segments_max];
        }
        net.reset();
        return net;
    }

    pub fn deinit(net: *Net) void {
        net.gpa.free(net.seg_pool);
        net.gpa.free(net.rx_pool);
        net.gpa.free(net.sockets);
        net.* = undefined;
    }

    /// Frees every socket and heals every link. Generations restart so
    /// handle values are identical across runs of a seed.
    pub fn reset(net: *Net) void {
        for (net.sockets) |*s| {
            s.kind = .free;
            s.generation = 0;
        }
        net.reach = @splat(std.math.maxInt(Reach));
        net.ephemeral_next = @splat(ephemeral_port_first);
    }

    /// True if the network is as `reset` leaves it: no socket was ever
    /// opened, no link cut, no port handed out.
    pub fn pristine(net: *const Net) bool {
        for (net.sockets) |s| if (s.kind != .free or s.generation != 0) return false;
        for (net.reach) |r| if (r != std.math.maxInt(Reach)) return false;
        for (net.ephemeral_next) |p| if (p != ephemeral_port_first) return false;
        return true;
    }

    // ------------------------------------------------------------------
    // Addresses

    pub fn nodeAddress(node: NodeId) [4]u8 {
        return .{ 10, 0, 0, node + 1 };
    }

    /// Resolves an IPv4 destination seen from `from`. Null: no such host.
    pub fn nodeOf(net: *const Net, from: NodeId, bytes: [4]u8) ?NodeId {
        if (bytes[0] == 127) return from;
        if (bytes[0] == 10 and bytes[1] == 0 and bytes[2] == 0 and bytes[3] >= 1 and bytes[3] <= net.node_count) {
            return bytes[3] - 1;
        }
        return null;
    }

    /// True if `bytes` is an address `node` may listen on.
    pub fn isLocal(node: NodeId, bytes: [4]u8) bool {
        if (std.mem.eql(u8, &bytes, &.{ 0, 0, 0, 0 })) return true;
        if (bytes[0] == 127) return true;
        return std.mem.eql(u8, &bytes, &nodeAddress(node));
    }

    // ------------------------------------------------------------------
    // Handles

    pub fn encode(net: *const Net, slot: u16) u32 {
        const g: u32 = net.sockets[slot].generation & 0x3FFF;
        return 0x4000_0000 | (g << 16) | (@as(u32, slot) + 1);
    }

    pub fn isSocketValue(value: u32) bool {
        return value & 0xC000_0000 == 0x4000_0000;
    }

    pub fn decode(net: *const Net, value: u32) error{InvalidHandle}!u16 {
        if (!isSocketValue(value)) return error.InvalidHandle;
        const slot_plus = value & 0xFFFF;
        if (slot_plus == 0 or slot_plus > net.sockets.len) return error.InvalidHandle;
        const slot: u16 = @intCast(slot_plus - 1);
        const s = &net.sockets[slot];
        if (s.kind == .free or s.in_backlog) return error.InvalidHandle;
        if ((s.generation & 0x3FFF) != ((value >> 16) & 0x3FFF)) return error.InvalidHandle;
        return slot;
    }

    // ------------------------------------------------------------------
    // Allocation

    /// Allocates the receive buffers, at the first socket of the first run
    /// that opens one. They are kept from then on. Host memory running out
    /// here is not something to report to the program under test.
    fn rxAttach(net: *Net) void {
        const each: usize = net.limits.rx_buffer_bytes;
        net.rx_pool = net.gpa.alloc(u8, net.sockets.len * each) catch @panic("tardis: out of host memory for the simulated network's receive buffers");
        for (net.sockets, 0..) |*s, i| s.rx = net.rx_pool[i * each ..][0..each];
    }

    fn alloc(net: *Net, kind: Kind, node: NodeId, port: u16) ?u16 {
        if (net.rx_pool.len == 0) net.rxAttach();
        for (net.sockets, 0..) |*s, i| {
            if (s.kind != .free) continue;
            s.kind = kind;
            s.generation +%= 1;
            s.node = node;
            s.local_port = port;
            s.backlog_len = 0;
            s.backlog_limit = 0;
            s.peer = no_peer;
            s.peer_generation = 0;
            s.peer_node = 0;
            s.peer_port = 0;
            s.in_backlog = false;
            s.loopback = false;
            s.rx_head = 0;
            s.rx_len = 0;
            s.rx_ready = 0;
            s.seg_head = 0;
            s.seg_len = 0;
            s.last_deliver_at = 0;
            s.eof = false;
            s.shut_send = false;
            s.shut_recv = false;
            s.fault = .none;
            s.fault_at = 0;
            s.rto_at = 0;
            return @intCast(i);
        }
        return null;
    }

    fn release(net: *Net, slot: u16) void {
        net.sockets[slot].kind = .free;
    }

    /// Sockets owned by the application (excludes un-accepted connections).
    pub fn openCount(net: *const Net) u32 {
        var n: u32 = 0;
        for (net.sockets) |*s| {
            if (s.kind != .free and !s.in_backlog) n += 1;
        }
        return n;
    }

    pub fn openCountOn(net: *const Net, node: NodeId) u32 {
        var n: u32 = 0;
        for (net.sockets) |*s| {
            if (s.kind != .free and !s.in_backlog and s.node == node) n += 1;
        }
        return n;
    }

    /// TCP and UDP have separate port spaces.
    pub fn portInUse(net: *const Net, node: NodeId, port: u16, dgram: bool) bool {
        for (net.sockets) |*s| {
            if (s.kind == .free or s.node != node or s.local_port != port) continue;
            if ((s.kind == .dgram) == dgram) return true;
        }
        return false;
    }

    pub fn ephemeralPort(net: *Net, node: NodeId, dgram: bool) ?u16 {
        var tries: u32 = 0;
        while (tries < 0x4000) : (tries += 1) {
            const p = net.ephemeral_next[node];
            net.ephemeral_next[node] = if (p == 0xFFFF) ephemeral_port_first else p + 1;
            if (!net.portInUse(node, p, dgram)) return p;
        }
        return null;
    }

    pub fn listen(net: *Net, node: NodeId, port: u16, backlog: u31) error{ AddressInUse, SystemResources }!u16 {
        if (net.portInUse(node, port, false)) return error.AddressInUse;
        const slot = net.alloc(.listener, node, port) orelse return error.SystemResources;
        net.sockets[slot].backlog_limit = @intCast(@max(1, @min(backlog, net.limits.backlog_max)));
        return slot;
    }

    /// Reserves a stream port, as a kernel's `bind` does.
    pub fn bindStream(net: *Net, node: NodeId, port: u16) error{ AddressInUse, SystemResources }!u16 {
        if (net.portInUse(node, port, false)) return error.AddressInUse;
        return net.alloc(.bound, node, port) orelse error.SystemResources;
    }

    /// A bound stream socket starts listening on its port.
    pub fn listenBound(net: *Net, slot: u16, backlog: u31) void {
        const s = &net.sockets[slot];
        assert(s.kind == .bound);
        s.kind = .listener;
        s.backlog_len = 0;
        s.backlog_limit = @intCast(@max(1, @min(backlog, net.limits.backlog_max)));
    }

    /// A listener stops listening and keeps its port (as `bound`): the
    /// connections waiting in its queue are reset.
    pub fn unlisten(net: *Net, slot: u16, now_ns: u64, d: *decide.Decider, o: Options) void {
        const s = &net.sockets[slot];
        assert(s.kind == .listener);
        for (s.backlog[0..s.backlog_len]) |sv| {
            if (net.peerOf(sv)) |c| net.setFault(c, .reset, now_ns + drawLatency(d, o));
            net.release(sv);
        }
        s.backlog_len = 0;
        s.shut_recv = false;
        s.kind = .bound;
    }

    /// Frees a bound socket's reservation once its connection has the port.
    pub fn releaseBound(net: *Net, slot: u16) void {
        assert(net.sockets[slot].kind == .bound);
        net.release(slot);
    }

    pub fn findListener(net: *const Net, node: NodeId, port: u16) ?u16 {
        for (net.sockets, 0..) |*s, i| {
            if (s.kind == .listener and s.node == node and s.local_port == port) return @intCast(i);
        }
        return null;
    }

    pub fn reachable(net: *const Net, a: NodeId, b: NodeId) bool {
        return net.reach[a] & (@as(Reach, 1) << @intCast(b)) != 0;
    }

    pub const EstablishError = error{ ConnectionRefused, SystemResources };

    /// Creates a connected pair: the client socket (returned) and a server
    /// socket queued on `listener`'s backlog.
    pub fn establish(net: *Net, client_node: NodeId, client_port: u16, listener: u16) EstablishError!u16 {
        const l = &net.sockets[listener];
        assert(l.kind == .listener);
        if (l.backlog_len >= l.backlog_limit) return error.ConnectionRefused;
        const c = net.alloc(.stream, client_node, client_port) orelse return error.SystemResources;
        const sv = net.alloc(.stream, l.node, l.local_port) orelse {
            net.release(c);
            return error.SystemResources;
        };
        const cs = &net.sockets[c];
        const ss = &net.sockets[sv];
        cs.peer = sv;
        cs.peer_generation = ss.generation;
        cs.peer_node = ss.node;
        cs.peer_port = ss.local_port;
        ss.peer = c;
        ss.peer_generation = cs.generation;
        ss.peer_node = cs.node;
        ss.peer_port = cs.local_port;
        ss.in_backlog = true;
        l.backlog[l.backlog_len] = sv;
        l.backlog_len += 1;
        return c;
    }

    pub fn popBacklog(net: *Net, listener: u16) ?u16 {
        const l = &net.sockets[listener];
        if (l.backlog_len == 0) return null;
        const sv = l.backlog[0];
        std.mem.copyForwards(u16, l.backlog[0 .. l.backlog_len - 1], l.backlog[1..l.backlog_len]);
        l.backlog_len -= 1;
        net.sockets[sv].in_backlog = false;
        return sv;
    }

    /// The live peer of stream `slot`, or null if it closed.
    pub fn peerOf(net: *const Net, slot: u16) ?u16 {
        const s = &net.sockets[slot];
        if (s.peer == no_peer) return null;
        const p = &net.sockets[s.peer];
        if (p.kind != .stream or p.generation != s.peer_generation) return null;
        return s.peer;
    }

    // ------------------------------------------------------------------
    // Delivery

    fn drawLatency(d: *decide.Decider, o: Options) u64 {
        return d.range(.net, o.latency_min_ns, @max(o.latency_min_ns, o.latency_max_ns));
    }

    /// Moves delivered segments of `slot`'s receive ring into the readable
    /// region.
    pub fn settle(net: *Net, slot: u16, now_ns: u64) void {
        const s = &net.sockets[slot];
        while (s.seg_len > 0) {
            const seg = &s.segs[s.seg_head];
            if (seg.held or seg.deliver_at > now_ns) break;
            if (seg.fin) s.eof = true;
            s.rx_ready += seg.len;
            s.seg_head = @intCast((s.seg_head + 1) % s.segs.len);
            s.seg_len -= 1;
        }
    }

    /// Earliest future time at which `slot` may become readable on its own.
    fn nextEvent(net: *const Net, slot: u16) ?u64 {
        const s = &net.sockets[slot];
        var best: ?u64 = null;
        if (s.seg_len > 0) {
            const seg = s.segs[s.seg_head];
            if (!seg.held) best = seg.deliver_at;
        }
        if (s.fault != .none) best = if (best) |b| @min(b, s.fault_at) else s.fault_at;
        if (s.rto_at != 0) best = if (best) |b| @min(b, s.rto_at) else s.rto_at;
        return best;
    }

    /// A stream has something for a read by now: data, its end, a fault,
    /// or reading shut down.
    pub fn streamReadable(net: *Net, slot: u16, now_ns: u64) bool {
        net.settle(slot, now_ns);
        const s = &net.sockets[slot];
        return s.rx_ready > 0 or s.eof or s.shut_recv or activeFault(s, now_ns) != null;
    }

    /// A write on a stream would not wait (it may fail).
    pub fn streamWritable(net: *Net, slot: u16, now_ns: u64) bool {
        return net.checkSend(slot, now_ns) != .would_block;
    }

    /// The peer's FIN has arrived by now (read or not).
    pub fn finArrived(net: *Net, slot: u16, now_ns: u64) bool {
        net.settle(slot, now_ns);
        return net.sockets[slot].eof;
    }

    /// The stream was reset by now (its peer's RST arrived).
    pub fn isReset(net: *const Net, slot: u16, now_ns: u64) bool {
        return activeFault(&net.sockets[slot], now_ns) == .reset;
    }

    fn activeFault(s: *const Socket, now_ns: u64) ?Fault {
        if (s.fault != .none and s.fault_at <= now_ns) return s.fault;
        if (s.rto_at != 0 and s.rto_at <= now_ns) return .timed_out;
        return null;
    }

    pub fn recv(net: *Net, slot: u16, data: []const []u8, limit: usize, now_ns: u64) RecvResult {
        net.settle(slot, now_ns);
        const s = &net.sockets[slot];
        if (activeFault(s, now_ns)) |f| return .{ .fault = f };
        if (s.shut_recv) return .eof;
        if (s.rx_ready > 0) {
            var want: usize = @min(limit, s.rx_ready);
            var done: usize = 0;
            for (data) |d| {
                if (want == 0) break;
                const n = @min(d.len, want);
                net.ringRead(slot, d[0..n]);
                done += n;
                want -= n;
            }
            return .{ .data = done };
        }
        if (s.eof) return .eof;
        return .{ .would_block = net.nextEvent(slot) };
    }

    fn ringRead(net: *Net, slot: u16, out: []u8) void {
        const s = &net.sockets[slot];
        assert(out.len <= s.rx_ready);
        const cap: u32 = @intCast(s.rx.len);
        for (out) |*b| {
            b.* = s.rx[s.rx_head];
            s.rx_head = (s.rx_head + 1) % cap;
        }
        s.rx_len -= @intCast(out.len);
        s.rx_ready -= @intCast(out.len);
    }

    pub fn checkSend(net: *Net, slot: u16, now_ns: u64) SendCheck {
        const s = &net.sockets[slot];
        if (activeFault(s, now_ns)) |f| return .{ .fault = f };
        if (s.shut_send) return .shut_down;
        const p = net.peerOf(slot) orelse return .peer_gone;
        const ps = &net.sockets[p];
        // One segment slot stays free for FIN.
        if (ps.seg_len + 1 >= ps.segs.len) return .would_block;
        const free: u32 = @as(u32, @intCast(ps.rx.len)) - ps.rx_len;
        if (free == 0) return .would_block;
        return .{ .ready = free };
    }

    /// Appends `bytes` to the peer's ring. Call `commit` once afterwards.
    pub fn push(net: *Net, slot: u16, bytes: []const u8) void {
        const p = net.peerOf(slot).?;
        const ps = &net.sockets[p];
        const cap: u32 = @intCast(ps.rx.len);
        assert(bytes.len <= cap - ps.rx_len);
        var tail = (ps.rx_head + ps.rx_len) % cap;
        for (bytes) |b| {
            ps.rx[tail] = b;
            tail = (tail + 1) % cap;
        }
        ps.rx_len += @intCast(bytes.len);
    }

    /// Records a segment of `len` pushed bytes (or a FIN) from `slot` to its
    /// peer.
    pub fn commit(net: *Net, slot: u16, len: u32, fin: bool, now_ns: u64, d: *decide.Decider, o: Options) void {
        const s = &net.sockets[slot];
        const p = net.peerOf(slot).?;
        const ps = &net.sockets[p];
        assert(ps.seg_len < ps.segs.len);
        const held = !net.reachable(s.node, ps.node);
        if (held and s.rto_at == 0) s.rto_at = now_ns + o.retransmit_timeout_ns;
        var at: u64 = std.math.maxInt(u64);
        if (!held) {
            at = @max(now_ns + drawLatency(d, o), ps.last_deliver_at);
            ps.last_deliver_at = at;
        }
        const idx = (ps.seg_head + ps.seg_len) % ps.segs.len;
        ps.segs[idx] = .{ .len = len, .deliver_at = at, .held = held, .fin = fin };
        ps.seg_len += 1;
        // Data for a peer that shut down both ways (FIN sent, reading shut:
        // Linux's FIN_WAIT with RCV_SHUTDOWN) aborts the connection: the
        // peer resets itself and answers with RST (RFC 1122 4.2.2.13).
        if (len > 0 and !held and ps.shut_recv and ps.shut_send) {
            net.setFault(p, .reset, at);
            net.setFault(slot, .reset, at + drawLatency(d, o));
        }
    }

    /// Marks `slot` as failing with `fault` from `at` on.
    pub fn setFault(net: *Net, slot: u16, fault: Fault, at: u64) void {
        const s = &net.sockets[slot];
        if (s.fault != .none and s.fault_at <= at) return;
        s.fault = fault;
        s.fault_at = at;
    }

    /// Resets both ends of the connection (random RST injection).
    pub fn resetConnection(net: *Net, slot: u16, now_ns: u64, d: *decide.Decider, o: Options) void {
        net.setFault(slot, .reset, now_ns);
        if (net.peerOf(slot)) |p| net.setFault(p, .reset, now_ns + drawLatency(d, o));
    }

    pub fn shutdownSend(net: *Net, slot: u16, now_ns: u64, d: *decide.Decider, o: Options) void {
        const s = &net.sockets[slot];
        if (s.shut_send) return;
        s.shut_send = true;
        if (net.peerOf(slot) != null) net.commit(slot, 0, true, now_ns, d, o);
    }

    /// Closes `slot`. Returns true if other sockets changed state (waiters
    /// should be woken).
    pub fn close(net: *Net, slot: u16, now_ns: u64, d: *decide.Decider, o: Options) void {
        const s = &net.sockets[slot];
        switch (s.kind) {
            .free => return,
            .dgram, .bound => {},
            .listener => {
                // Un-accepted connections are reset.
                for (s.backlog[0..s.backlog_len]) |sv| {
                    if (net.peerOf(sv)) |c| net.setFault(c, .reset, now_ns + drawLatency(d, o));
                    net.release(sv);
                }
                s.backlog_len = 0;
            },
            .stream => if (net.peerOf(slot)) |p| {
                net.settle(slot, now_ns);
                const unread = s.rx_len > 0;
                if (unread or activeFault(s, now_ns) != null) {
                    // RST: the peer loses whatever is still in flight.
                    net.setFault(p, .reset, now_ns + drawLatency(d, o));
                } else if (!s.shut_send) {
                    net.commit(slot, 0, true, now_ns, d, o);
                }
            },
        }
        net.release(slot);
    }

    /// Crashes `node`: frees its sockets; each peer on another node is
    /// reset or black-holed. Returns the number of sockets freed.
    pub fn crashNode(net: *Net, node: NodeId, now_ns: u64, d: *decide.Decider, o: Options) u32 {
        var n: u32 = 0;
        for (net.sockets, 0..) |*s, i| {
            if (s.kind == .free or s.node != node) continue;
            const slot: u16 = @intCast(i);
            if (s.kind == .stream) {
                if (net.peerOf(slot)) |p| {
                    if (net.sockets[p].node != node) {
                        if (d.chance(.net, o.blackhole_ppm)) {
                            net.setFault(p, .timed_out, now_ns + o.blackhole_timeout_ns);
                        } else {
                            net.setFault(p, .reset, now_ns + drawLatency(d, o));
                        }
                    }
                }
            }
            n += 1;
        }
        for (net.sockets) |*s| {
            if (s.kind != .free and s.node == node) s.kind = .free;
        }
        return n;
    }

    /// Sets whether packets flow from `a` to `b`. Cutting a link holds
    /// undelivered segments; healing it schedules them.
    pub fn setLink(net: *Net, a: NodeId, b: NodeId, up: bool, now_ns: u64, d: *decide.Decider, o: Options) void {
        const bit = @as(Reach, 1) << @intCast(b);
        const was = net.reach[a] & bit != 0;
        if (was == up) return;
        if (up) net.reach[a] |= bit else net.reach[a] &= ~bit;
        for (net.sockets, 0..) |*s, i| {
            // `s` receives from a node-`a` socket. The sender may already be
            // closed: its last segments (often a FIN) must still be released.
            if (s.kind != .stream or s.node != b or s.peer_node != a) continue;
            net.settle(@intCast(i), now_ns);
            var k: u16 = 0;
            while (k < s.seg_len) : (k += 1) {
                const seg = &s.segs[(s.seg_head + k) % s.segs.len];
                if (up) {
                    if (!seg.held) continue;
                    seg.held = false;
                    seg.deliver_at = @max(now_ns + drawLatency(d, o), s.last_deliver_at);
                    s.last_deliver_at = seg.deliver_at;
                } else {
                    seg.held = true;
                    seg.deliver_at = std.math.maxInt(u64);
                }
            }
            if (!up) s.last_deliver_at = 0;
            // The sender's retransmissions succeed again, or start failing.
            const p = net.peerOf(@intCast(i)) orelse continue;
            if (up) {
                net.sockets[p].rto_at = 0;
            } else if (s.seg_len > 0 and net.sockets[p].rto_at == 0) {
                net.sockets[p].rto_at = now_ns + o.retransmit_timeout_ns;
            }
        }
    }

    /// Earliest network event strictly after `now_ns` (a segment or datagram
    /// becoming deliverable, a fault or retransmit timeout firing), if any.
    /// Tasks blocked on the network wake then and re-check.
    pub fn nextEventAfter(net: *const Net, now_ns: u64) ?u64 {
        var best: ?u64 = null;
        for (net.sockets) |*s| {
            switch (s.kind) {
                .free, .listener, .bound => continue,
                .stream => {
                    var k: u16 = 0;
                    while (k < s.seg_len) : (k += 1) {
                        const seg = s.segs[(s.seg_head + k) % s.segs.len];
                        if (seg.held) break; // later segments wait behind it
                        if (seg.deliver_at > now_ns) {
                            best = minOpt(best, seg.deliver_at);
                            break;
                        }
                    }
                    if (s.fault != .none and s.fault_at > now_ns) best = minOpt(best, s.fault_at);
                    if (s.rto_at > now_ns) best = minOpt(best, s.rto_at);
                },
                .dgram => for (s.segs[0..s.seg_len]) |seg| {
                    if (seg.deliver_at > now_ns) best = minOpt(best, seg.deliver_at);
                },
            }
        }
        return best;
    }

    fn minOpt(a: ?u64, b: u64) u64 {
        return if (a) |x| @min(x, b) else b;
    }

    // ------------------------------------------------------------------
    // Datagrams (UDP-like)
    //
    // A datagram socket's receive buffer is linear: messages are stored
    // back to back in arrival order, `segs[0..seg_len]` describing them.
    // Each message has its own delivery time, so jitter reorders delivery;
    // `recvDatagram` takes the earliest deliverable message and compacts.

    pub fn bind(net: *Net, node: NodeId, port: u16) error{ AddressInUse, SystemResources }!u16 {
        if (net.portInUse(node, port, true)) return error.AddressInUse;
        return net.alloc(.dgram, node, port) orelse error.SystemResources;
    }

    pub fn findDgram(net: *const Net, node: NodeId, port: u16) ?u16 {
        for (net.sockets, 0..) |*s, i| {
            if (s.kind == .dgram and s.node == node and s.local_port == port) return @intCast(i);
        }
        return null;
    }

    pub const SendOutcome = enum { queued, dropped_unreachable, dropped_no_socket, dropped_full, dropped_loss };

    /// Queues one datagram from socket `src` to `dst_node:dst_port`.
    /// `lose` and `duplicate` are the fault decisions for this datagram.
    /// `loopback`: sent to a 127.x address, so its source reads as
    /// 127.0.0.1, as on a real host.
    pub fn sendDatagram(net: *Net, src: u16, dst_node: NodeId, dst_port: u16, data: []const u8, lose: bool, duplicate: bool, now_ns: u64, d: *decide.Decider, o: Options, loopback: bool) SendOutcome {
        const ss = &net.sockets[src];
        if (!net.reachable(ss.node, dst_node)) return .dropped_unreachable;
        if (lose) return .dropped_loss;
        const dst = net.findDgram(dst_node, dst_port) orelse return .dropped_no_socket;
        const copies: u32 = if (duplicate) 2 else 1;
        var c: u32 = 0;
        while (c < copies) : (c += 1) {
            const ds = &net.sockets[dst];
            if (ds.seg_len == ds.segs.len or ds.rx.len - ds.rx_len < data.len) return if (c == 0) .dropped_full else .queued;
            @memcpy(ds.rx[ds.rx_len..][0..data.len], data);
            ds.rx_len += @intCast(data.len);
            ds.segs[ds.seg_len] = .{
                .len = @intCast(data.len),
                .deliver_at = now_ns + drawLatency(d, o),
                .held = false,
                .fin = false,
                .src_node = ss.node,
                .src_port = ss.local_port,
                .loopback = loopback,
            };
            ds.seg_len += 1;
        }
        return .queued;
    }

    pub const Datagram = struct { len: usize, truncated: bool, src_node: NodeId, src_port: u16, loopback: bool };

    /// Takes the earliest deliverable datagram, copying up to `out.len`
    /// bytes. Null if none is deliverable yet.
    pub fn recvDatagram(net: *Net, slot: u16, out: []u8, now_ns: u64) ?Datagram {
        const s = &net.sockets[slot];
        assert(s.kind == .dgram);
        var pick: ?usize = null;
        for (s.segs[0..s.seg_len], 0..) |seg, i| {
            if (seg.deliver_at > now_ns) continue;
            if (pick == null or seg.deliver_at < s.segs[pick.?].deliver_at) pick = i;
        }
        const i = pick orelse return null;
        var offset: u32 = 0;
        for (s.segs[0..i]) |seg| offset += seg.len;
        const seg = s.segs[i];
        const n = @min(out.len, seg.len);
        @memcpy(out[0..n], s.rx[offset..][0..n]);
        std.mem.copyForwards(u8, s.rx[offset .. s.rx_len - seg.len], s.rx[offset + seg.len .. s.rx_len]);
        s.rx_len -= seg.len;
        std.mem.copyForwards(Segment, s.segs[i .. s.seg_len - 1], s.segs[i + 1 .. s.seg_len]);
        s.seg_len -= 1;
        return .{ .len = n, .truncated = n < seg.len, .src_node = seg.src_node, .src_port = seg.src_port, .loopback = seg.loopback };
    }

    /// Removes the `i`th queued datagram of `slot`, unread.
    pub fn dropDatagram(net: *Net, slot: u16, i: usize) void {
        const s = &net.sockets[slot];
        var offset: u32 = 0;
        for (s.segs[0..i]) |seg| offset += seg.len;
        const len = s.segs[i].len;
        std.mem.copyForwards(u8, s.rx[offset .. s.rx_len - len], s.rx[offset + len .. s.rx_len]);
        s.rx_len -= len;
        std.mem.copyForwards(Segment, s.segs[i .. s.seg_len - 1], s.segs[i + 1 .. s.seg_len]);
        s.seg_len -= 1;
    }

    /// Datagrams that have arrived at `slot` by `now_ns` and are not read.
    pub fn datagramsArrived(net: *const Net, slot: u16, now_ns: u64) u32 {
        var n: u32 = 0;
        for (net.sockets[slot].segs[0..net.sockets[slot].seg_len]) |seg| {
            if (seg.deliver_at <= now_ns) n += 1;
        }
        return n;
    }

    pub fn datagramCapacity(net: *const Net) usize {
        return net.limits.rx_buffer_bytes;
    }
};

// ----------------------------------------------------------------------
// Tests

const testing = std.testing;

fn testNet(nodes: u8) !Net {
    return Net.init(testing.allocator, .{ .sockets_max = 8, .rx_buffer_bytes = 64, .segments_max = 8 }, nodes);
}

test "stream delivery honors latency and order" {
    var net = try testNet(2);
    defer net.deinit();
    var d = decide.Decider.init(1);
    const o: Options = .{ .latency_min_ns = 10, .latency_max_ns = 100 };
    const l = try net.listen(1, 80, 4);
    const c = try net.establish(0, 50000, l);
    const sv = net.popBacklog(l).?;

    try testing.expectEqual(SendCheck{ .ready = 64 }, net.checkSend(c, 0));
    net.push(c, "hello");
    net.commit(c, 5, false, 0, &d, o);
    net.push(c, " world");
    net.commit(c, 6, false, 0, &d, o);

    var buf: [32]u8 = undefined;
    var vec = [_][]u8{&buf};
    const r0 = net.recv(sv, &vec, 32, 0);
    try testing.expect(r0 == .would_block);
    const when = r0.would_block.?;
    try testing.expect(when >= 10 and when <= 100);

    const r1 = net.recv(sv, &vec, 32, 1000);
    try testing.expectEqualStrings("hello world", buf[0..r1.data]);

    net.close(c, 1000, &d, o);
    try testing.expect(net.recv(sv, &vec, 32, 1000) == .would_block);
    try testing.expect(net.recv(sv, &vec, 32, 2000) == .eof);
    net.close(sv, 2000, &d, o);
    net.close(l, 2000, &d, o);
    try testing.expectEqual(@as(u32, 0), net.openCount());
}

test "partition holds segments until heal" {
    var net = try testNet(2);
    defer net.deinit();
    var d = decide.Decider.init(2);
    const o: Options = .{ .latency_min_ns = 10, .latency_max_ns = 10 };
    const l = try net.listen(1, 80, 4);
    const c = try net.establish(0, 50000, l);
    const sv = net.popBacklog(l).?;
    net.setLink(0, 1, false, 0, &d, o);
    net.push(c, "x");
    net.commit(c, 1, false, 0, &d, o);
    var buf: [4]u8 = undefined;
    var vec = [_][]u8{&buf};
    try testing.expectEqual(RecvResult{ .would_block = null }, net.recv(sv, &vec, 4, 1_000_000));
    net.setLink(0, 1, true, 1_000_000, &d, o);
    try testing.expectEqual(RecvResult{ .data = 1 }, net.recv(sv, &vec, 4, 1_000_010));
}

test "close with unread data resets the peer" {
    var net = try testNet(2);
    defer net.deinit();
    var d = decide.Decider.init(3);
    const o: Options = .{ .latency_min_ns = 10, .latency_max_ns = 10 };
    const l = try net.listen(1, 80, 4);
    const c = try net.establish(0, 50000, l);
    const sv = net.popBacklog(l).?;
    net.push(c, "req");
    net.commit(c, 3, false, 0, &d, o);
    net.close(sv, 100, &d, o); // never read the request
    var buf: [4]u8 = undefined;
    var vec = [_][]u8{&buf};
    try testing.expectEqual(RecvResult{ .fault = .reset }, net.recv(c, &vec, 4, 200));
    try testing.expectEqual(SendCheck.peer_gone, net.checkSend(c, 50));
}

test "datagrams: loss, duplication, reordering, separate port space" {
    var net = try testNet(2);
    defer net.deinit();
    var d = decide.Decider.init(5);
    const o: Options = .{ .latency_min_ns = 10, .latency_max_ns = 1000 };
    const tcp = try net.listen(1, 53, 1);
    const a = try net.bind(0, 5000);
    const b = try net.bind(1, 53); // same number as the TCP listener: allowed
    try testing.expectError(error.AddressInUse, net.bind(1, 53));

    try testing.expectEqual(Net.SendOutcome.dropped_loss, net.sendDatagram(a, 1, 53, "lost", true, false, 0, &d, o, false));
    try testing.expectEqual(Net.SendOutcome.dropped_no_socket, net.sendDatagram(a, 1, 54, "x", false, false, 0, &d, o, false));
    try testing.expectEqual(Net.SendOutcome.queued, net.sendDatagram(a, 1, 53, "one", false, true, 0, &d, o, false));
    try testing.expectEqual(Net.SendOutcome.queued, net.sendDatagram(a, 1, 53, "two", false, false, 0, &d, o, false));

    var buf: [8]u8 = undefined;
    try testing.expect(net.recvDatagram(b, &buf, 0) == null);
    var got: [3][]const u8 = undefined;
    var storage: [3][8]u8 = undefined;
    for (0..3) |i| {
        const m = net.recvDatagram(b, &storage[i], 10_000).?;
        try testing.expectEqual(@as(NodeId, 0), m.src_node);
        try testing.expectEqual(@as(u16, 5000), m.src_port);
        got[i] = storage[i][0..m.len];
    }
    try testing.expect(net.recvDatagram(b, &buf, 10_000) == null);
    var ones: u32 = 0;
    for (got) |g| {
        if (std.mem.eql(u8, g, "one")) ones += 1 else try testing.expectEqualStrings("two", g);
    }
    try testing.expectEqual(@as(u32, 2), ones);

    net.setLink(0, 1, false, 0, &d, o);
    try testing.expectEqual(Net.SendOutcome.dropped_unreachable, net.sendDatagram(a, 1, 53, "cut", false, false, 0, &d, o, false));
    net.close(a, 0, &d, o);
    net.close(b, 0, &d, o);
    net.close(tcp, 0, &d, o);
}

test "a partition outlasting the retransmit timeout fails the sender" {
    var net = try testNet(2);
    defer net.deinit();
    var d = decide.Decider.init(6);
    const o: Options = .{ .latency_min_ns = 10, .latency_max_ns = 10, .retransmit_timeout_ns = 1000 };
    const l = try net.listen(1, 80, 4);
    const c = try net.establish(0, 50000, l);
    _ = net.popBacklog(l).?;
    net.setLink(0, 1, false, 0, &d, o);
    net.push(c, "x");
    net.commit(c, 1, false, 100, &d, o);
    try testing.expectEqual(@as(?u64, 1100), net.nextEventAfter(100));
    var buf: [4]u8 = undefined;
    var vec = [_][]u8{&buf};
    try testing.expect(net.recv(c, &vec, 4, 1099) == .would_block);
    try testing.expectEqual(RecvResult{ .fault = .timed_out }, net.recv(c, &vec, 4, 1100));
}

test "healing before the retransmit timeout keeps the connection" {
    var net = try testNet(2);
    defer net.deinit();
    var d = decide.Decider.init(7);
    const o: Options = .{ .latency_min_ns = 10, .latency_max_ns = 10, .retransmit_timeout_ns = 1000 };
    const l = try net.listen(1, 80, 4);
    const c = try net.establish(0, 50000, l);
    const sv = net.popBacklog(l).?;
    net.setLink(0, 1, false, 0, &d, o);
    net.push(c, "x");
    net.commit(c, 1, false, 0, &d, o);
    net.setLink(0, 1, true, 500, &d, o);
    var buf: [4]u8 = undefined;
    var vec = [_][]u8{&buf};
    try testing.expect(net.recv(c, &vec, 4, 5000) == .would_block);
    try testing.expectEqual(RecvResult{ .data = 1 }, net.recv(sv, &vec, 4, 5000));
}

test "handles are generation-checked" {
    var net = try testNet(1);
    defer net.deinit();
    var d = decide.Decider.init(4);
    const l = try net.listen(0, 80, 1);
    const v = net.encode(l);
    try testing.expectEqual(l, try net.decode(v));
    net.close(l, 0, &d, .{});
    try testing.expectError(error.InvalidHandle, net.decode(v));
    const l2 = try net.listen(0, 81, 1);
    try testing.expectEqual(l, l2);
    try testing.expectError(error.InvalidHandle, net.decode(v));
}

test "segments from a sender that closed during a partition are released on heal" {
    var net = try testNet(2);
    defer net.deinit();
    var d = decide.Decider.init(8);
    const o: Options = .{ .latency_min_ns = 10, .latency_max_ns = 10 };
    const l = try net.listen(1, 80, 4);
    const c = try net.establish(0, 50000, l);
    const sv = net.popBacklog(l).?;
    net.setLink(0, 1, false, 0, &d, o);
    net.push(c, "req");
    net.commit(c, 3, false, 0, &d, o);
    net.close(c, 0, &d, o); // FIN, also held
    var buf: [4]u8 = undefined;
    var vec = [_][]u8{&buf};
    try testing.expectEqual(RecvResult{ .would_block = null }, net.recv(sv, &vec, 4, 100));
    net.setLink(0, 1, true, 100, &d, o);
    try testing.expectEqual(RecvResult{ .data = 3 }, net.recv(sv, &vec, 4, 1000));
    try testing.expect(net.recv(sv, &vec, 4, 1000) == .eof);
}
