//! Sockets in system-call mode (plan §9.2, `plan3.md` D9): the socket
//! calls of the code under test, answered from the simulated network.
//!
//! As with files (`sysemu.zig`), each call is translated into the
//! simulator's own `std.Io` network operation, so a connection made by
//! system call meets the same latency, partitions, resets and crashes as
//! one made through `env.io`, and leaves the same trace events.
//!
//! A socket descriptor is `fd_base` plus a slot: above every real
//! descriptor, and below the simulated files' (bit 30). The `std.Io`
//! interface creates a socket only with its address (`listen`,
//! `connect`, `bind`), so `socket` only takes a slot; the simulated
//! socket appears at the call that names the address. A node's crash
//! frees its slots (`dropNode`), as a process's death closes its
//! descriptors.
//!
//! Emulated: `socket` (IPv4, stream or datagram, blocking), `bind`,
//! `listen`, `accept`, `accept4`, `connect`, `read`, `write`, `readv`,
//! `writev`, `recvfrom`, `sendto`, `shutdown`, `close`, `getsockname`,
//! `getpeername`, `setsockopt` (accepted, changes nothing), `getsockopt`
//! (`SO_ERROR` and `SO_TYPE`; any other reads as 0), and `fcntl` for the
//! descriptor flags. An IPv6 socket fails with `EAFNOSUPPORT`, which
//! code that tries IPv6 first takes as the cue to use IPv4.
//!
//! As Linux: a blocking stream `send` or `writev` sends everything; a
//! write after this end's `shutdown(SHUT_WR)`, or after a reset was
//! reported once, fails with `EPIPE` (and raises no `SIGPIPE`: signals
//! are not modelled); `shutdown` of a listening socket wakes its
//! `accept`; a connected datagram socket receives only from its peer.
//!
//! Not emulated (stray): non-blocking sockets (`SOCK_NONBLOCK`, `O_NONBLOCK`
//! set by `fcntl`, `MSG_DONTWAIT`) and so `poll`, `select` and `epoll`,
//! which only non-blocking code needs; `sendmsg`, `recvmsg`, `MSG_PEEK`,
//! `MSG_OOB`, `MSG_WAITALL`; a datagram `writev` of more than one vector;
//! Unix-domain and other families. Not modelled: a stream `bind` reserves
//! nothing until `listen` (an address in use is reported there, and
//! `bind` to port 0 reads back port 0 until then), and a `bind` before
//! `connect` does not choose the local port.

const std = @import("std");
const Io = std.Io;
const ionet = Io.net;
const linux = std.os.linux;
const Sim = @import("Sim.zig");
const net_mod = @import("../model/net.zig");

const E = linux.E;

/// The first socket descriptor.
pub const fd_base: i32 = 0x2000_0000;
const slots_max = 256;

const Kind = enum {
    free,
    /// From `socket`: no simulated socket yet.
    fresh,
    /// A stream socket `bind` gave an address, not yet listening.
    bound,
    listening,
    /// A connected stream.
    stream,
    /// A datagram socket with a simulated socket (bound).
    dgram,
};

const Mode = enum { stream, dgram };

const Slot = struct {
    kind: Kind = .free,
    mode: Mode = .stream,
    /// The node of the task that made it: its crash frees the slot.
    node: u16 = 0,
    /// Changes whenever the slot is taken: an operation that waited
    /// checks it to see whether its descriptor was closed meanwhile.
    gen: u32 = 0,
    /// The simulated socket, once there is one.
    handle: ionet.Socket.Handle = undefined,
    local: ionet.IpAddress = unspecified,
    /// A stream's peer; a datagram socket's default destination.
    peer: ?ionet.IpAddress = null,
    /// `shutdown(SHUT_WR)` was made: a write fails with `EPIPE`.
    shut_send: bool = false,
    /// A reset was reported once: later writes fail with `EPIPE`.
    reset_reported: bool = false,
};

const unspecified: ionet.IpAddress = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } };

/// The sockets of the run on this thread.
threadlocal var slots: [slots_max]Slot = @splat(.{});
threadlocal var next_gen: u32 = 0;

/// A run begins: no socket is open.
pub fn reset() void {
    slots = @splat(.{});
}

/// A node crashed (null: every node): its descriptors are gone. The
/// simulator has already removed its sockets.
pub fn dropNode(node: ?u16) void {
    for (&slots) |*slot| {
        if (slot.kind == .free) continue;
        if (node) |n| if (slot.node != n) continue;
        slot.* = .{};
    }
}

pub fn isSocketFd(fd: i32) bool {
    return fd >= fd_base and fd < fd_base + slots_max;
}

fn fail(e: E) u64 {
    return @bitCast(-@as(i64, @backingInt(e)));
}

fn slotOf(fd: i32) ?*Slot {
    if (!isSocketFd(fd)) return null;
    const s = &slots[@intCast(fd - fd_base)];
    return if (s.kind == .free) null else s;
}

/// Takes a free slot for the current node.
fn take(s: *Sim, kind: Kind, mode: Mode) ?usize {
    for (&slots, 0..) |*slot, i| {
        if (slot.kind != .free) continue;
        next_gen +%= 1;
        slot.* = .{ .kind = kind, .mode = mode, .node = s.currentNode(), .gen = next_gen };
        return i;
    }
    return null;
}

fn fdOf(index: usize) u64 {
    return @intCast(fd_base + @as(i32, @intCast(index)));
}

/// The errno for an error of a simulated network operation.
fn errnoOf(err: anyerror) E {
    return switch (err) {
        error.ConnectionRefused => .CONNREFUSED,
        error.ConnectionResetByPeer => .CONNRESET,
        error.ConnectionAborted => .CONNABORTED,
        error.AddressInUse => .ADDRINUSE,
        error.AddressUnavailable => .ADDRNOTAVAIL,
        error.AddressFamilyUnsupported => .AFNOSUPPORT,
        error.NetworkUnreachable => .NETUNREACH,
        error.HostUnreachable => .HOSTUNREACH,
        error.NetworkDown => .NETDOWN,
        error.Timeout, error.ConnectionTimedOut => .TIMEDOUT,
        error.SocketUnconnected, error.SocketNotConnected => .NOTCONN,
        error.SocketNotListening => .INVAL,
        error.BrokenPipe => .PIPE,
        error.MessageOversize => .MSGSIZE,
        error.WouldBlock => .AGAIN,
        error.AccessDenied => .ACCES,
        error.SystemResources => .NOBUFS,
        error.ProcessFdQuotaExceeded => .MFILE,
        error.SystemFdQuotaExceeded => .NFILE,
        error.Canceled => .INTR,
        error.SocketModeUnsupported, error.ProtocolUnsupportedByAddressFamily => .PROTONOSUPPORT,
        else => .IO,
    };
}

// --- addresses -------------------------------------------------------------------

const af_inet = 2;
const af_inet6 = 10;
const sockaddr_in_len = 16;

/// A `sockaddr_in`, read from the caller.
fn readAddress(ptr: u64, len: u64) union(enum) { ok: ionet.IpAddress, err: E } {
    if (ptr == 0) return .{ .err = .FAULT };
    if (len < 2) return .{ .err = .INVAL };
    const b: [*]const u8 = @ptrFromInt(ptr);
    const family = std.mem.readInt(u16, b[0..2], .little);
    if (family != af_inet) return .{ .err = .AFNOSUPPORT };
    if (len < sockaddr_in_len) return .{ .err = .INVAL };
    return .{ .ok = .{ .ip4 = .{
        .port = std.mem.readInt(u16, b[2..4], .big),
        .bytes = b[4..8].*,
    } } };
}

/// Writes `address` as a `sockaddr_in` where the caller asked for it:
/// as much as fits in `*len_ptr`, which is set to the full length.
fn writeAddress(ptr: u64, len_ptr: u64, address: ionet.IpAddress) ?E {
    if (ptr == 0) return null;
    if (len_ptr == 0) return .FAULT;
    const len: *align(1) u32 = @ptrFromInt(len_ptr);
    var raw: [sockaddr_in_len]u8 = @splat(0);
    std.mem.writeInt(u16, raw[0..2], af_inet, .little);
    switch (address) {
        .ip4 => |a| {
            std.mem.writeInt(u16, raw[2..4], a.port, .big);
            raw[4..8].* = a.bytes;
        },
        .ip6 => {},
    }
    const out: [*]u8 = @ptrFromInt(ptr);
    const n = @min(len.*, sockaddr_in_len);
    @memcpy(out[0..n], raw[0..n]);
    len.* = sockaddr_in_len;
    return null;
}

fn sameAddress(a: ionet.IpAddress, b: ionet.IpAddress) bool {
    return switch (a) {
        .ip4 => |x| switch (b) {
            .ip4 => |y| x.port == y.port and std.mem.eql(u8, &x.bytes, &y.bytes),
            .ip6 => false,
        },
        .ip6 => false,
    };
}

// --- the calls ------------------------------------------------------------------

const sock_stream = 1;
const sock_dgram = 2;
const sock_nonblock = 0o4000;
const sock_cloexec = 0o2000000;
const msg_nosignal = 0x4000;

/// Entry point from `sysemu.emulate`: the value for `rax`, or null for a
/// call that is not emulated (stray).
pub fn emulate(s: *Sim, number: u64, a: *const [6]u64) ?u64 {
    const fd: i32 = @bitCast(@as(u32, @truncate(a[0])));
    if (number == 41) return socket(s, @truncate(a[0]), @truncate(a[1]), @truncate(a[2]));
    const slot = slotOf(fd) orelse return if (isSocketFd(fd)) fail(.BADF) else null;
    return switch (number) {
        49 => bind(s, slot, a[1], a[2]),
        50 => listen(s, slot, a[1]),
        43 => accept(s, slot, a[1], a[2], 0),
        288 => accept(s, slot, a[1], a[2], @truncate(a[3])),
        42 => connect(s, slot, a[1], a[2]),
        0 => receive(s, slot, a[1], a[2], 0, 0, 0),
        45 => receive(s, slot, a[1], a[2], @truncate(a[3]), a[4], a[5]),
        1 => send(s, slot, a[1], a[2], 0, 0, 0),
        44 => send(s, slot, a[1], a[2], @truncate(a[3]), a[4], a[5]),
        19 => readVectors(s, slot, a[1], a[2]),
        20 => writeVectors(s, slot, a[1], a[2]),
        48 => shutdown(s, slot, a[1]),
        3 => close(s, fd),
        51 => if (writeAddress(a[1], a[2], slot.local)) |e| fail(e) else 0, // getsockname
        52 => if ((slot.kind == .stream or slot.kind == .dgram) and slot.peer != null) // getpeername
            (if (writeAddress(a[1], a[2], slot.peer.?)) |e| fail(e) else 0)
        else
            fail(.NOTCONN),
        54 => 0, // setsockopt: accepted, changes nothing
        55 => getsockopt(slot, a[1], a[2], a[3], a[4]),
        72 => fcntl(@truncate(a[1]), a[2]),
        else => null,
    };
}

fn socket(s: *Sim, domain: u32, type_and_flags: u32, protocol: u32) ?u64 {
    if (domain == af_inet6) return fail(.AFNOSUPPORT);
    if (domain != af_inet) return null;
    if (type_and_flags & sock_nonblock != 0) return null;
    const mode: Mode = switch (type_and_flags & ~@as(u32, sock_nonblock | sock_cloexec)) {
        sock_stream => if (protocol == 0 or protocol == 6) .stream else return fail(.PROTONOSUPPORT),
        sock_dgram => if (protocol == 0 or protocol == 17) .dgram else return fail(.PROTONOSUPPORT),
        else => return null,
    };
    const i = take(s, .fresh, mode) orelse return fail(.MFILE);
    return fdOf(i);
}

fn bind(s: *Sim, slot: *Slot, addr_ptr: u64, len: u64) u64 {
    const address = switch (readAddress(addr_ptr, len)) {
        .ok => |x| x,
        .err => |e| return fail(e),
    };
    if (slot.kind != .fresh) return fail(.INVAL);
    switch (slot.mode) {
        .stream => {
            slot.local = address;
            slot.kind = .bound;
        },
        .dgram => {
            const io = s.io();
            const sock = io.vtable.netBindIp(io.userdata, &address, .{ .mode = .dgram }) catch |err| return fail(errnoOf(err));
            slot.handle = sock.handle;
            slot.local = sock.address;
            slot.kind = .dgram;
        },
    }
    return 0;
}

fn listen(s: *Sim, slot: *Slot, backlog: u64) u64 {
    if (slot.mode != .stream) return fail(.OPNOTSUPP);
    switch (slot.kind) {
        .listening => return 0,
        .fresh, .bound => {},
        else => return fail(.INVAL),
    }
    const io = s.io();
    const sock = io.vtable.netListenIp(io.userdata, &slot.local, .{
        .kernel_backlog = @intCast(std.math.clamp(@as(i64, @bitCast(backlog)), 1, std.math.maxInt(u31))),
        .reuse_address = true,
        .mode = .stream,
        .protocol = .tcp,
    }) catch |err| return fail(errnoOf(err));
    slot.handle = sock.handle;
    slot.local = sock.address;
    slot.kind = .listening;
    return 0;
}

fn accept(s: *Sim, slot: *Slot, addr_ptr: u64, len_ptr: u64, flags: u32) ?u64 {
    if (flags & sock_nonblock != 0) return null;
    if (slot.kind != .listening) return fail(.INVAL);
    // Taken before the wait: another task's `socket` must not take it.
    const fresh = take(s, .fresh, .stream) orelse return fail(.MFILE);
    const fresh_gen = slots[fresh].gen;
    const local = slot.local;
    const io = s.io();
    const result = io.vtable.netAccept(io.userdata, slot.handle, {});
    // A crash of this node while it waited freed the slot.
    if (slots[fresh].gen != fresh_gen) {
        if (result) |sock| io.vtable.netClose(io.userdata, &.{sock}) else |_| {}
        return fail(.BADF);
    }
    const sock = result catch |err| {
        slots[fresh] = .{};
        return fail(errnoOf(err));
    };
    // The simulator's `accept` gives the peer's address; the local one is
    // the listener's, made concrete if it was the wildcard.
    var here = local;
    switch (here) {
        .ip4 => |*x| if (std.mem.eql(u8, &x.bytes, &.{ 0, 0, 0, 0 })) {
            x.bytes = net_mod.Net.nodeAddress(s.currentNode());
        },
        .ip6 => {},
    }
    slots[fresh].kind = .stream;
    slots[fresh].handle = sock.handle;
    slots[fresh].local = here;
    slots[fresh].peer = sock.address;
    if (writeAddress(addr_ptr, len_ptr, sock.address)) |e| return fail(e);
    return fdOf(fresh);
}

fn connect(s: *Sim, slot: *Slot, addr_ptr: u64, len: u64) u64 {
    const address = switch (readAddress(addr_ptr, len)) {
        .ok => |x| x,
        .err => |e| return fail(e),
    };
    const io = s.io();
    switch (slot.mode) {
        .stream => {
            switch (slot.kind) {
                .fresh, .bound => {},
                .stream => return fail(.ISCONN),
                else => return fail(.INVAL),
            }
            const gen = slot.gen;
            const result = io.vtable.netConnectIp(io.userdata, &address, .{ .mode = .stream });
            // Closed (by another task, or a crash) while it connected: the
            // connection belongs to no descriptor.
            if (slot.gen != gen) {
                if (result) |sock| io.vtable.netClose(io.userdata, &.{sock}) else |_| {}
                return fail(.BADF);
            }
            const sock = result catch |err| return fail(errnoOf(err));
            slot.handle = sock.handle;
            // The simulator's `connect` gives the local address.
            slot.local = sock.address;
            slot.peer = address;
            slot.kind = .stream;
        },
        .dgram => {
            if (ensureBound(s, slot)) |e| return fail(e);
            slot.peer = address;
        },
    }
    return 0;
}

/// A datagram socket sends from an address: the first send binds it to
/// an ephemeral port, as the kernel does.
fn ensureBound(s: *Sim, slot: *Slot) ?E {
    if (slot.kind == .dgram) return null;
    const gen = slot.gen;
    const io = s.io();
    const result = io.vtable.netBindIp(io.userdata, &unspecified, .{ .mode = .dgram });
    if (slot.gen != gen) {
        if (result) |sock| io.vtable.netClose(io.userdata, &.{sock}) else |_| {}
        return .BADF;
    }
    const sock = result catch |err| return errnoOf(err);
    slot.handle = sock.handle;
    slot.local = sock.address;
    slot.kind = .dgram;
    return null;
}

fn userBytes(ptr: u64, len: u64) ?[]u8 {
    if (len == 0) return &.{};
    if (ptr == 0) return null;
    return @as([*]u8, @ptrFromInt(ptr))[0..@min(len, 0x7fff_f000)];
}

fn receive(s: *Sim, slot: *Slot, buf_ptr: u64, len: u64, flags: u32, from_ptr: u64, from_len_ptr: u64) ?u64 {
    if (flags & ~@as(u32, msg_nosignal) != 0) return null; // peek, waitall, dontwait, oob
    const buf = userBytes(buf_ptr, len) orelse return fail(.FAULT);
    const io = s.io();
    switch (slot.kind) {
        .stream => {
            // Linux returns at once for an empty buffer on a stream.
            if (buf.len == 0) return 0;
            var data = [_][]u8{buf};
            const r = io.operate(.{ .net_read = .{ .socket_handle = slot.handle, .data = &data } }) catch return fail(.INTR);
            const got = r.net_read catch |err| return fail(errnoOf(err));
            if (from_ptr != 0) if (writeAddress(from_ptr, from_len_ptr, slot.peer.?)) |e| return fail(e);
            return got.data_len;
        },
        .dgram => while (true) {
            var message = [_]ionet.IncomingMessage{.init};
            const r = io.operate(.{ .net_receive = .{
                .socket_handle = slot.handle,
                .message_buffer = &message,
                .data_buffer = buf,
                .flags = .{},
            } }) catch return fail(.INTR);
            const err, const count = r.net_receive;
            if (err) |e| return fail(errnoOf(e));
            if (count == 0) return fail(.AGAIN);
            // A connected datagram socket receives only from its peer.
            if (slot.peer) |p| if (!sameAddress(p, message[0].from)) continue;
            if (writeAddress(from_ptr, from_len_ptr, message[0].from)) |e| return fail(e);
            return message[0].data.len;
        },
        .fresh => return if (slot.mode == .stream) fail(.NOTCONN) else null, // a receive on an unbound datagram socket waits forever
        .bound, .listening => return fail(.NOTCONN),
        .free => unreachable,
    }
}

fn send(s: *Sim, slot: *Slot, buf_ptr: u64, len: u64, flags: u32, to_ptr: u64, to_len: u64) ?u64 {
    if (flags & ~@as(u32, msg_nosignal) != 0) return null;
    const buf = userBytes(buf_ptr, len) orelse return fail(.FAULT);
    const io = s.io();
    switch (slot.mode) {
        .stream => {
            if (slot.kind != .stream) return fail(.NOTCONN);
            if (slot.shut_send or slot.reset_reported) return fail(.PIPE);
            // A blocking send on a stream returns when all of it is sent
            // (Linux: short only on a signal): the simulator's writes may
            // be short, so continue until done or failed.
            var sent: usize = 0;
            while (sent < buf.len) {
                const data = [_][]const u8{buf[sent..]};
                const r = io.operate(.{ .net_write = .{ .socket_handle = slot.handle, .data = &data } }) catch
                    return if (sent > 0) sent else fail(.INTR);
                const n = r.net_write catch |err| {
                    if (err == error.ConnectionResetByPeer) slot.reset_reported = true;
                    return if (sent > 0) sent else fail(errnoOf(err));
                };
                if (n == 0) break;
                sent += n;
            }
            return sent;
        },
        .dgram => {
            const to: ionet.IpAddress = if (to_ptr != 0) switch (readAddress(to_ptr, to_len)) {
                .ok => |x| x,
                .err => |e| return fail(e),
            } else slot.peer orelse return fail(.DESTADDRREQ);
            if (ensureBound(s, slot)) |e| return fail(e);
            var message = [_]ionet.OutgoingMessage{.{ .address = &to, .data_ptr = buf.ptr, .data_len = buf.len }};
            const r = io.operate(.{ .net_send = .{ .socket_handle = slot.handle, .messages = &message, .flags = .{} } }) catch return fail(.INTR);
            const err, const count = r.net_send;
            if (err) |e| return fail(errnoOf(e));
            if (count == 0) return fail(.AGAIN);
            return message[0].data_len;
        },
    }
}

const Iovec = extern struct { base: u64, len: u64 };

fn iovecs(iov_ptr: u64, count: u64) union(enum) { ok: []const Iovec, err: E } {
    if (count > 1024) return .{ .err = .INVAL };
    if (count == 0) return .{ .ok = &.{} };
    if (iov_ptr == 0) return .{ .err = .FAULT };
    return .{ .ok = @as([*]const Iovec, @ptrFromInt(iov_ptr))[0..count] };
}

/// `readv`: into the first vector with room. A stream read may return
/// fewer bytes than asked, and the caller loops.
fn readVectors(s: *Sim, slot: *Slot, iov_ptr: u64, count: u64) ?u64 {
    const iov = switch (iovecs(iov_ptr, count)) {
        .ok => |v| v,
        .err => |e| return fail(e),
    };
    for (iov) |v| {
        if (v.len == 0) continue;
        return receive(s, slot, v.base, v.len, 0, 0, 0);
    }
    return 0;
}

/// `writev`: on a stream, every vector in turn, all of it (a blocking
/// stream write is not short); a datagram is one message, emulated only
/// when it is one vector.
fn writeVectors(s: *Sim, slot: *Slot, iov_ptr: u64, count: u64) ?u64 {
    const iov = switch (iovecs(iov_ptr, count)) {
        .ok => |v| v,
        .err => |e| return fail(e),
    };
    if (slot.mode == .dgram) {
        var only: ?Iovec = null;
        for (iov) |v| {
            if (v.len == 0) continue;
            if (only != null) return null;
            only = v;
        }
        const v = only orelse return 0;
        return send(s, slot, v.base, v.len, 0, 0, 0);
    }
    var total: u64 = 0;
    for (iov) |v| {
        if (v.len == 0) continue;
        const r = send(s, slot, v.base, v.len, 0, 0, 0) orelse return null;
        if (@as(i64, @bitCast(r)) < 0) return if (total > 0) total else r;
        total += r;
        if (r < v.len) break;
    }
    return total;
}

fn shutdown(s: *Sim, slot: *Slot, how: u64) u64 {
    const h: ionet.ShutdownHow = switch (how) {
        0 => .recv,
        1 => .send,
        2 => .both,
        else => return fail(.INVAL),
    };
    const io = s.io();
    switch (slot.kind) {
        .stream => {
            io.vtable.netShutdown(io.userdata, slot.handle, h) catch |err| return fail(errnoOf(err));
            if (h != .recv) slot.shut_send = true;
        },
        // Linux: shutting down a listener's receiving side wakes its
        // `accept`, which then fails; servers stop their loops this way.
        .listening => if (h != .send) {
            io.vtable.netShutdown(io.userdata, slot.handle, .recv) catch |err| return fail(errnoOf(err));
        },
        else => return fail(.NOTCONN),
    }
    return 0;
}

fn close(s: *Sim, fd: i32) u64 {
    const slot = &slots[@intCast(fd - fd_base)];
    switch (slot.kind) {
        .listening, .stream, .dgram => {
            const io = s.io();
            const sock = [_]ionet.Socket{.{ .handle = slot.handle, .address = slot.local }};
            io.vtable.netClose(io.userdata, &sock);
        },
        else => {},
    }
    slot.* = .{};
    return 0;
}

fn getsockopt(slot: *const Slot, level: u64, name: u64, value_ptr: u64, len_ptr: u64) u64 {
    if (value_ptr == 0 or len_ptr == 0) return fail(.FAULT);
    const len: *align(1) u32 = @ptrFromInt(len_ptr);
    if (len.* < 4) return fail(.INVAL);
    const sol_socket = 1;
    const value: u32 = if (level == sol_socket and name == 3) // SO_TYPE
        (if (slot.mode == .stream) sock_stream else sock_dgram)
    else
        0; // SO_ERROR (no pending error) and every other option
    @as(*align(1) u32, @ptrFromInt(value_ptr)).* = value;
    len.* = 4;
    return 0;
}

fn fcntl(cmd: u32, arg: u64) ?u64 {
    return switch (cmd) {
        1 => 0, // F_GETFD
        2 => 0, // F_SETFD
        3 => 2, // F_GETFL: O_RDWR
        4 => if (arg & sock_nonblock != 0) null else 0, // F_SETFL: non-blocking is not emulated
        else => null,
    };
}
