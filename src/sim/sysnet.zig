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
//! `dup`, and `fcntl` with `F_DUPFD` or `F_DUPFD_CLOEXEC`, give a second
//! number for a slot (`aliases`): one socket, with one set of flags, that
//! is closed when its last number is. `dup2` and `dup3` are stray. As
//! for a pipe (`sysfd.zig`), a number leaves the epoll sets it is in
//! when it is closed, and a `poll` on it sees `POLLNVAL`, where Linux
//! keeps both while a duplicate lives. A run has `aliases_max`
//! duplicates over all its nodes.
//!
//! Emulated: `socket` (IPv4, stream or datagram, blocking), `bind`,
//! `listen`, `accept`, `accept4`, `connect`, `read`, `write`, `readv`,
//! `writev`, `recvfrom`, `sendto`, `recvmsg`, `sendmsg`, `shutdown`,
//! `close`, `getsockname`,
//! `getpeername`, `setsockopt` (accepted, changes nothing), `getsockopt`
//! (`SO_ERROR` and `SO_TYPE`; any other reads as 0), and `fcntl` for the
//! descriptor flags. An IPv6 socket fails with `EAFNOSUPPORT`, which
//! code that tries IPv6 first takes as the cue to use IPv4.
//!
//! As Linux: a blocking stream `send`, `writev` or `sendmsg` sends everything; a
//! write after this end's `shutdown(SHUT_WR)`, or after a reset was
//! reported once, fails with `EPIPE` (and raises no `SIGPIPE`: signals
//! are not modelled); `shutdown` of a listening socket wakes its
//! `accept`; a connected datagram socket receives only from its peer.
//!
//! Non-blocking sockets (`SOCK_NONBLOCK`, `accept4`'s flag, `O_NONBLOCK`
//! set by `fcntl`, `MSG_DONTWAIT`) fail a call that would wait with
//! `EAGAIN`; a non-blocking `connect` completes before it returns (in
//! virtual time, as long as the handshake takes) and says `EINPROGRESS`.
//! `poll` and `ppoll` are in `sysemu.zig`, with `pollMask` here. Many
//! details follow Linux as a differential test found them
//! (`src/tests/sysnet_diff_test.zig`).
//!
//! `sendmsg` and `recvmsg` (revision 120) are `sendto` and `recvfrom`
//! over several buffers, with the address in the message header (but a
//! stream's `recvmsg` names no sender: `msg_namelen` is 0). A
//! datagram goes out as one, whatever the number of buffers, and comes in
//! spread over them, with `MSG_TRUNC` in `msg_flags` when it did not
//! fit; `readv` and `writev` on a datagram socket do the same. A stream
//! `recvmsg` or `readv` fills the first buffer with room and no more,
//! a short read the caller must expect anyway. There is no ancillary
//! data: a `sendmsg` that carries any is stray, and a `recvmsg` is told
//! there was none (`msg_controllen` 0).
//!
//! `epoll` is in `sysfd.zig`. Not emulated (stray): `select` and
//! `pselect6`; `sendmmsg`, `recvmmsg`, `MSG_PEEK`,
//! `MSG_OOB`, `MSG_WAITALL`, `MSG_MORE` and every flag but
//! `MSG_DONTWAIT` and `MSG_NOSIGNAL` (and `MSG_CMSG_CLOEXEC` to
//! `recvmsg`); a datagram sent from several buffers that is longer than
//! `gather_max` bytes; a datagram read into several buffers with more
//! than 64 KiB of room when `limits.rx_buffer_bytes` is above that;
//! families other than IPv4, IPv6, Unix-domain and netlink (those three
//! are refused with `EAFNOSUPPORT`: the machine has none). A stream `bind` reserves its port, as
//! the kernel's does, and `listen` or `connect` after it use that port.

const std = @import("std");
const Io = std.Io;
const ionet = Io.net;
const linux = std.os.linux;
const Sim = @import("Sim.zig");
const net_mod = @import("../model/net.zig");
const sysfd = @import("sysfd.zig");

const E = linux.E;

/// The first socket descriptor.
pub const fd_base: i32 = 0x2000_0000;
const slots_max = 256;

const Kind = enum {
    free,
    /// From `socket`: no simulated socket yet.
    fresh,
    /// A stream socket `bind` gave an address and a reserved port
    /// (`Sim.bindStream`), not yet listening or connected.
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
    /// `SOCK_NONBLOCK` or `O_NONBLOCK`: a call that would wait fails
    /// with `EAGAIN` instead (`MSG_DONTWAIT` does so for one call).
    nonblock: bool = false,
    /// A non-blocking `connect` failed and has not been asked again:
    /// Linux's next `connect` then fails with `ECONNABORTED` if
    /// `SO_ERROR` already took the error.
    connect_failed: bool = false,
    /// `shutdown` after that failed attempt: Linux's socket is then
    /// "disconnecting", and every later `connect` fails with `EINVAL`.
    disconnecting: bool = false,
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
    /// A stream bound to port 0 (the kernel chose it): a failed `connect`
    /// gives the port up, as Linux does, though `getsockname` still shows
    /// it; `stale_port` then marks it given up.
    chose_port: bool = false,
    stale_port: bool = false,
    /// Once bound to a specific address (Linux's `SOCK_BINDADDR_LOCK`,
    /// never cleared): a failed `connect` keeps the source address it
    /// chose, where another socket goes back to the wildcard.
    addr_locked: bool = false,
    /// `shutdown(SHUT_RD)` of a connected datagram socket: a read with
    /// nothing queued returns 0 instead of waiting.
    shut_recv: bool = false,
    /// A reset was reported once: later writes fail with `EPIPE`.
    reset_reported: bool = false,
    /// A connected datagram socket's datagram to its peer found no socket
    /// there: the kernel's ICMP port unreachable, reported once by the
    /// next `recv`, `send` or `SO_ERROR`.
    pending: ?E = null,
    /// Datagrams that arrived before a datagram socket's `connect`: Linux
    /// keeps them whatever their source, and filters only later ones.
    unfiltered: u32 = 0,
    /// Its own number was closed, and a duplicate keeps the socket.
    primary_closed: bool = false,
};

const unspecified: ionet.IpAddress = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } };

/// The sockets of the run on this thread.
threadlocal var slots: [slots_max]Slot = @splat(.{});
threadlocal var next_gen: u32 = 0;

/// The descriptors `dup` made, after the slots' own numbers: the slot
/// each is a second number for.
const aliases_max = 64;
threadlocal var aliases: [aliases_max]?u16 = @splat(null);

/// A run begins: no socket is open.
pub fn reset() void {
    slots = @splat(.{});
    aliases = @splat(null);
}

/// A node crashed (null: every node): its descriptors are gone. The
/// simulator has already removed its sockets.
pub fn dropNode(node: ?u16) void {
    for (&slots) |*slot| {
        if (slot.kind == .free) continue;
        if (node) |n| if (slot.node != n) continue;
        slot.* = .{};
    }
    for (&aliases) |*alias| {
        if (alias.*) |index| if (slots[index].kind == .free) {
            alias.* = null;
        };
    }
}

pub fn isSocketFd(fd: i32) bool {
    return fd >= fd_base and fd < fd_base + slots_max + aliases_max;
}

/// The slot a descriptor is a number for, if it is open.
fn indexOf(fd: i32) ?usize {
    if (!isSocketFd(fd)) return null;
    const n: usize = @intCast(fd - fd_base);
    if (n >= slots_max) return if (aliases[n - slots_max]) |index| index else null;
    return if (slots[n].kind == .free or slots[n].primary_closed) null else n;
}

fn aliased(index: usize) bool {
    for (aliases) |alias| if (alias != null and alias.? == index) return true;
    return false;
}

/// `dup`: another number for the slot.
fn duplicate(index: usize) u64 {
    for (&aliases, 0..) |*alias, i| {
        if (alias.* != null) continue;
        alias.* = @intCast(index);
        return fdOf(slots_max + i);
    }
    return fail(.MFILE);
}

fn fail(e: E) u64 {
    return @bitCast(-@as(i64, @backingInt(e)));
}

fn slotOf(fd: i32) ?*Slot {
    return &slots[indexOf(fd) orelse return null];
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

const af_unix = 1;
const af_inet = 2;
const af_inet6 = 10;
const af_netlink = 16;
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
const msg_dontwait = 0x40;
const o_nonblock = 0o4000;

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
        0 => receive(s, slot, a[1], a[2], 0, 0, 0, null),
        45 => receive(s, slot, a[1], a[2], @truncate(a[3]), a[4], a[5], null),
        46 => sendMessage(s, slot, a[1], @truncate(a[2])),
        47 => receiveMessage(s, slot, a[1], @truncate(a[2])),
        1 => send(s, slot, a[1], a[2], 0, 0, 0),
        44 => send(s, slot, a[1], a[2], @truncate(a[3]), a[4], a[5]),
        19 => readVectors(s, slot, a[1], a[2]),
        20 => writeVectors(s, slot, a[1], a[2]),
        48 => shutdown(s, slot, a[1]),
        3 => close(s, fd),
        51 => if (writeAddress(a[1], a[2], slot.local)) |e| fail(e) else 0, // getsockname
        // getpeername; Linux reports no peer while its port is 0 (a
        // datagram socket connected to port 0 sends there all the same).
        // A stream whose reset was reported is closed: no peer either.
        52 => if ((slot.kind == .stream or slot.kind == .dgram) and slot.peer != null and slot.peer.?.ip4.port != 0 and !resetOf(s, slot))
            (if (writeAddress(a[1], a[2], slot.peer.?)) |e| fail(e) else 0)
        else
            fail(.NOTCONN),
        54 => 0, // setsockopt: accepted, changes nothing
        55 => getsockopt(s, slot, a[1], a[2], a[3], a[4]),
        32 => duplicate(indexOf(fd).?),
        72 => switch (@as(u32, @truncate(a[1]))) {
            0, 1030 => duplicate(indexOf(fd).?), // F_DUPFD, F_DUPFD_CLOEXEC
            else => |cmd| fcntl(slot, cmd, a[2]),
        },
        // ioctl: FIONBIO, as `fcntl`'s O_NONBLOCK (Rust's `set_nonblocking`).
        16 => if (@as(u32, @truncate(a[1])) != 0x5421) null else if (a[2] == 0) fail(.FAULT) else blk: {
            slot.nonblock = @as(*align(1) const i32, @ptrFromInt(a[2])).* != 0;
            break :blk 0;
        },
        else => null,
    };
}

fn socket(s: *Sim, domain: u32, type_and_flags: u32, protocol: u32) ?u64 {
    // The simulated machine has IPv4 and nothing else. A C library asks
    // for the other three in passing, when it looks a host name up (IPv6,
    // a name-service cache on a Unix-domain socket, the interfaces over
    // netlink), and goes on without them when told they are not there.
    if (domain == af_inet6 or domain == af_unix or domain == af_netlink) return fail(.AFNOSUPPORT);
    if (domain != af_inet) return null;
    const mode: Mode = switch (type_and_flags & ~@as(u32, sock_nonblock | sock_cloexec)) {
        sock_stream => if (protocol == 0 or protocol == 6) .stream else return fail(.PROTONOSUPPORT),
        sock_dgram => if (protocol == 0 or protocol == 17) .dgram else return fail(.PROTONOSUPPORT),
        else => return null,
    };
    const i = take(s, .fresh, mode) orelse return fail(.MFILE);
    slots[i].nonblock = type_and_flags & sock_nonblock != 0;
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
            const sock = s.bindStream(address) catch |err| return fail(errnoOf(err));
            slot.handle = sock.handle;
            slot.local = sock.address;
            slot.kind = .bound;
            slot.chose_port = address.ip4.port == 0;
            slot.stale_port = false;
            if (!std.mem.eql(u8, &address.ip4.bytes, &.{ 0, 0, 0, 0 })) slot.addr_locked = true;
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
    // Still "connecting" after a failed non-blocking attempt (Linux).
    if (slot.connect_failed) return fail(.INVAL);
    switch (slot.kind) {
        .listening => return 0,
        .fresh, .bound => {},
        else => return fail(.INVAL),
    }
    const queue: u31 = @intCast(std.math.clamp(@as(i64, @bitCast(backlog)), 1, std.math.maxInt(u31)));
    if (slot.kind == .bound) {
        // On the port `bind` reserved.
        s.listenBound(slot.handle, queue) catch |err| return fail(errnoOf(err));
        slot.kind = .listening;
        return 0;
    }
    const io = s.io();
    var here = slot.local;
    if (slot.stale_port) here.ip4.port = 0;
    const sock = io.vtable.netListenIp(io.userdata, &here, .{
        .kernel_backlog = queue,
        .reuse_address = true,
        .mode = .stream,
        .protocol = .tcp,
    }) catch |err| return fail(errnoOf(err));
    slot.handle = sock.handle;
    slot.local = sock.address;
    slot.kind = .listening;
    // Listening unbound, the kernel chose the port.
    slot.chose_port = true;
    return 0;
}

fn accept(s: *Sim, slot: *Slot, addr_ptr: u64, len_ptr: u64, flags: u32) ?u64 {
    if (slot.mode == .dgram) return fail(.OPNOTSUPP);
    if (slot.kind != .listening) return fail(.INVAL);
    if (slot.nonblock and !s.listenerReady(slot.handle)) return fail(.AGAIN);
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
            x.bytes = sourceFor(s, sock.address);
        },
        .ip6 => {},
    }
    if (writeAddress(addr_ptr, len_ptr, sock.address)) |e| {
        // No descriptor to give back: the connection is closed, not leaked.
        io.vtable.netClose(io.userdata, &.{sock});
        slots[fresh] = .{};
        return fail(e);
    }
    slots[fresh].kind = .stream;
    slots[fresh].nonblock = flags & sock_nonblock != 0;
    slots[fresh].handle = sock.handle;
    slots[fresh].local = here;
    slots[fresh].peer = sock.address;
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
                // Linux: a listening socket is not "closed", so connected.
                .stream, .listening => return fail(.ISCONN),
                else => return fail(.INVAL),
            }
            // A non-blocking attempt that failed: its error, or, taken
            // by `SO_ERROR` already, `ECONNABORTED` (Linux).
            if (slot.disconnecting) return fail(.INVAL);
            if (slot.connect_failed) {
                // This call disconnects it (`tcp_disconnect`).
                slot.connect_failed = false;
                slot.shut_send = false;
                slot.shut_recv = false;
                if (!slot.addr_locked) slot.local.ip4.bytes = .{ 0, 0, 0, 0 };
                const e = slot.pending orelse .CONNABORTED;
                slot.pending = null;
                return fail(e);
            }
            const gen = slot.gen;
            // A bound socket connects from the port it reserved.
            const result = if (slot.kind == .bound)
                s.connectFrom(slot.handle, address)
            else
                io.vtable.netConnectIp(io.userdata, &address, .{ .mode = .stream });
            // Closed (by another task, or a crash) while it connected: the
            // connection belongs to no descriptor.
            if (slot.gen != gen) {
                if (result) |sock| io.vtable.netClose(io.userdata, &.{sock}) else |_| {}
                return fail(.BADF);
            }
            const sock = result catch |err| {
                const after_port = err == error.ConnectionRefused or err == error.Timeout or err == error.ConnectionTimedOut;
                // A blocking attempt that fails disconnects the socket
                // (`tcp_disconnect`), which clears a recorded `shutdown`.
                if (!slot.nonblock) {
                    slot.shut_send = false;
                    slot.shut_recv = false;
                }
                if (after_port) slot.local.ip4.bytes = if (slot.addr_locked) sourceFor(s, address) else .{ 0, 0, 0, 0 };
                if (slot.kind == .fresh and after_port) {
                    // Linux chose a port for the attempt, and gives it up;
                    // `getsockname` still shows it, with any address
                    // `bind` named.
                    slot.local.ip4.port = s.last_connect_port;
                    slot.stale_port = true;
                }
                if (slot.kind == .bound and slot.chose_port) {
                    // Linux gives up a port it chose when the connection
                    // fails; the socket may be bound again.
                    io.vtable.netClose(io.userdata, &.{.{ .handle = slot.handle, .address = slot.local }});
                    slot.kind = .fresh;
                    slot.stale_port = true;
                }
                // Non-blocking, the attempt completed before the call
                // returns (POSIX allows it), but the call still says it is
                // in progress, as Linux does on loopback: the error is left
                // for `SO_ERROR`, `poll` and the next call.
                if (slot.nonblock and after_port) {
                    // Not disconnected yet: the source address stays until
                    // the next call does that (`tcp_disconnect`).
                    slot.local.ip4.bytes = sourceFor(s, address);
                    slot.pending = errnoOf(err);
                    slot.connect_failed = true;
                    return fail(.INPROGRESS);
                }
                return fail(errnoOf(err));
            };
            slot.handle = sock.handle;
            // The simulator's `connect` gives the local address; a bound
            // socket keeps its port, and its address unless the wildcard.
            if (slot.kind != .bound) {
                slot.local = sock.address;
            } else if (std.mem.eql(u8, &slot.local.ip4.bytes, &.{ 0, 0, 0, 0 })) {
                slot.local.ip4.bytes = sourceFor(s, address);
            }
            slot.peer = address;
            slot.kind = .stream;
            // A `shutdown` recorded before stays: `SHUT_WR` refuses sends
            // (no FIN goes), `SHUT_RD` ends reads.
            if (slot.shut_recv) io.vtable.netShutdown(io.userdata, slot.handle, .recv) catch {};
            if (slot.nonblock) return fail(.INPROGRESS);
        },
        .dgram => {
            if (ensureBound(s, slot)) |e| return fail(e);
            // Kept: what arrived and the old filter (if any) let through;
            // what it refused is gone, as on Linux, where it never queued.
            if (slot.peer) |old| if (slot.unfiltered == 0) s.dropDatagramsNotFrom(slot.handle, old);
            slot.unfiltered = readable(s, slot);
            slot.peer = address;
            // Connected, the socket's address is the route's source.
            if (std.mem.eql(u8, &slot.local.ip4.bytes, &.{ 0, 0, 0, 0 })) slot.local.ip4.bytes = sourceFor(s, address);
        },
    }
    return 0;
}

/// The source address a host uses toward `to`: loopback for loopback,
/// else the node's own.
fn sourceFor(s: *Sim, to: ionet.IpAddress) [4]u8 {
    return switch (to) {
        .ip4 => |a| if (a.bytes[0] == 127) .{ 127, 0, 0, 1 } else net_mod.Net.nodeAddress(s.currentNode()),
        .ip6 => net_mod.Net.nodeAddress(s.currentNode()),
    };
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

/// `truncated`, when asked for, is set for a datagram longer than the
/// buffer.
fn receive(s: *Sim, slot: *Slot, buf_ptr: u64, len: u64, flags: u32, from_ptr: u64, from_len_ptr: u64, truncated: ?*bool) ?u64 {
    if (flags & ~@as(u32, msg_nosignal | msg_dontwait) != 0) return null; // peek, waitall, oob
    const buf = userBytes(buf_ptr, len) orelse return fail(.FAULT);
    const nonblock = slot.nonblock or flags & msg_dontwait != 0;
    const io = s.io();
    switch (slot.kind) {
        .stream => {
            // Linux returns at once for an empty buffer on a stream. After
            // a reported reset the model gives what arrived before it, then
            // the end.
            if (buf.len == 0) return 0;
            if (nonblock and !s.streamReadable(slot.handle)) return fail(.AGAIN);
            var data = [_][]u8{buf};
            const r = io.operate(.{ .net_read = .{ .socket_handle = slot.handle, .data = &data } }) catch return fail(.INTR);
            const got = r.net_read catch |err| {
                if (err == error.ConnectionResetByPeer) slot.reset_reported = true;
                return fail(errnoOf(err));
            };
            if (from_ptr != 0) if (writeAddress(from_ptr, from_len_ptr, slot.peer.?)) |e| return fail(e);
            return got.data_len;
        },
        .dgram => while (true) {
            if (slot.pending) |e| {
                slot.pending = null;
                return fail(e);
            }
            // Linux looks at `SHUT_RD` only when the read would wait: a
            // non-blocking one says `EAGAIN` all the same.
            // It waits here rather than in the simulator, so a `shutdown`,
            // a close or an ICMP error (sysnet's own state) ends the wait.
            while (readable(s, slot) == 0) {
                if (nonblock) return fail(.AGAIN);
                if (slot.shut_recv) return 0;
                const gen = slot.gen;
                s.waitNetwork(s.net.nextEventAfter(s.now_ns)) catch return fail(.INTR);
                if (slot.gen != gen or slot.kind != .dgram) return fail(.BADF);
                if (slot.pending) |e| {
                    slot.pending = null;
                    return fail(e);
                }
            }
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
            // A connected datagram socket receives only from its peer,
            // once the datagrams that arrived before `connect` are read.
            if (slot.unfiltered > 0) {
                slot.unfiltered -= 1;
            } else if (slot.peer) |p| if (!icmpMatches(p, message[0].from)) continue;
            if (writeAddress(from_ptr, from_len_ptr, message[0].from)) |e| return fail(e);
            if (truncated) |t| t.* = message[0].flags.trunc;
            return message[0].data.len;
        },
        // Shut down for reading (see `shutdown`): 0 at once. Otherwise a
        // stream is not connected, and an unbound datagram socket would
        // wait forever.
        .fresh, .bound => {
            // A failed non-blocking `connect`'s error comes first (Linux).
            if (slot.mode == .stream) if (slot.pending) |e| {
                slot.pending = null;
                return fail(e);
            };
            if (slot.mode == .stream) {
                if (slot.shut_recv or slot.connect_failed) return 0;
                return fail(.NOTCONN);
            }
            if (nonblock) return fail(.AGAIN);
            return if (slot.shut_recv) 0 else null;
        },
        .listening => return fail(.NOTCONN),
        .free => unreachable,
    }
}

fn send(s: *Sim, slot: *Slot, buf_ptr: u64, len: u64, flags: u32, to_ptr: u64, to_len: u64) ?u64 {
    if (flags & ~@as(u32, msg_nosignal | msg_dontwait) != 0) return null;
    const buf = userBytes(buf_ptr, len) orelse return fail(.FAULT);
    const nonblock = slot.nonblock or flags & msg_dontwait != 0;
    const io = s.io();
    switch (slot.mode) {
        .stream => {
            // Linux: a stream that is not connected (fresh, bound or
            // listening) fails a send with `EPIPE`, not `ENOTCONN`.
            if (slot.kind != .stream) {
                if (slot.pending) |e| {
                    slot.pending = null;
                    return fail(e);
                }
                return fail(.PIPE);
            }
            // A reset not yet reported comes first (`sk_err`), once.
            if (!slot.reset_reported and s.streamReset(slot.handle)) {
                slot.reset_reported = true;
                s.streamFaultReported(slot.handle);
                return fail(resetErrno(s, slot));
            }
            if (slot.shut_send or slot.reset_reported) return fail(.PIPE);
            // A blocking send on a stream returns when all of it is sent
            // (Linux: short only on a signal): the simulator's writes may
            // be short, so continue until done or failed.
            var sent: usize = 0;
            while (sent < buf.len) {
                // Non-blocking: as much as fits now, or `EAGAIN`.
                if (nonblock and !s.streamWritable(slot.handle)) return if (sent > 0) sent else fail(.AGAIN);
                const data = [_][]const u8{buf[sent..]};
                const r = io.operate(.{ .net_write = .{ .socket_handle = slot.handle, .data = &data } }) catch
                    return if (sent > 0) sent else fail(.INTR);
                const n = r.net_write catch |err| {
                    // On a connected stream, an unconnected socket is the
                    // model's broken pipe: a reset after the peer's FIN, or
                    // a reset or timeout already reported. `EPIPE`.
                    if (err == error.SocketUnconnected) {
                        slot.reset_reported = true;
                        return if (sent > 0) sent else fail(.PIPE);
                    }
                    if (err == error.ConnectionResetByPeer) {
                        slot.reset_reported = true;
                        return if (sent > 0) sent else fail(resetErrno(s, slot));
                    }
                    return if (sent > 0) sent else fail(errnoOf(err));
                };
                if (n == 0) break;
                sent += n;
            }
            return sent;
        },
        .dgram => {
            // Linux binds the socket first, whatever the destination turns
            // out to be: a send that fails still leaves it bound.
            if (ensureBound(s, slot)) |e| return fail(e);
            const to: ionet.IpAddress = if (to_ptr != 0) switch (readAddress(to_ptr, to_len)) {
                .ok => |x| x,
                .err => |e| return fail(e),
            } else slot.peer orelse return fail(.DESTADDRREQ);
            // Port 0 named in the call is refused (a connected socket's
            // port 0 is sent to).
            if (to_ptr != 0 and to.ip4.port == 0) return fail(.INVAL);
            // A pending error, then `SHUT_WR`, refuse it only now, when
            // the buffer is allocated (`sock_alloc_send_pskb`).
            if (slot.pending) |e| {
                slot.pending = null;
                return fail(e);
            }
            if (slot.shut_send) return fail(.PIPE);
            var message = [_]ionet.OutgoingMessage{.{ .address = &to, .data_ptr = buf.ptr, .data_len = buf.len }};
            const r = io.operate(.{ .net_send = .{ .socket_handle = slot.handle, .messages = &message, .flags = .{} } }) catch return fail(.INTR);
            const err, const count = r.net_send;
            if (err) |e| return fail(errnoOf(e));
            if (count == 0) return fail(.AGAIN);
            // The ICMP answer reaches a connected socket whose peer it
            // matches: Linux matches a peer port of 0 to any port.
            if (slot.peer) |p| if (icmpMatches(p, to) and noDatagramSocket(s, to, slot.local.ip4.port)) {
                slot.pending = .CONNREFUSED;
            };
            return message[0].data_len;
        },
    }
}

fn icmpMatches(peer: ionet.IpAddress, to: ionet.IpAddress) bool {
    const p = switch (peer) {
        .ip4 => |x| x,
        .ip6 => return false,
    };
    const t = switch (to) {
        .ip4 => |x| x,
        .ip6 => return false,
    };
    return std.mem.eql(u8, &p.bytes, &t.bytes) and (p.port == 0 or p.port == t.port);
}

/// True when `to` names a host that is up and reachable and has no
/// datagram socket at that port that takes a datagram from `from_port`
/// (one connected to another peer does not): the host answers with ICMP
/// port unreachable, which a connected socket reports.
fn noDatagramSocket(s: *Sim, to: ionet.IpAddress, from_port: u16) bool {
    const a = switch (to) {
        .ip4 => |x| x,
        .ip6 => return false,
    };
    const here = s.currentNode();
    const node = s.net.nodeOf(here, a.bytes) orelse return false;
    if (!s.net.reachable(here, node)) return false;
    if (s.net.findDgram(node, a.port) == null) return true;
    const from: ionet.IpAddress = .{ .ip4 = .{ .bytes = sourceFor(s, to), .port = from_port } };
    for (&slots) |*other| {
        if (other.kind != .dgram or other.node != node or other.local.ip4.port != a.port) continue;
        const peer = other.peer orelse return false;
        return !icmpMatches(peer, from);
    }
    return false;
}

const Iovec = extern struct { base: u64, len: u64 };

/// More than 1024 vectors: `EINVAL` from `readv` and `writev`, `EMSGSIZE`
/// from `recvmsg` and `sendmsg`.
fn iovecs(iov_ptr: u64, count: u64, too_many: E) union(enum) { ok: []align(1) const Iovec, err: E } {
    if (count > 1024) return .{ .err = too_many };
    if (count == 0) return .{ .ok = &.{} };
    if (iov_ptr == 0) return .{ .err = .FAULT };
    return .{ .ok = @as([*]align(1) const Iovec, @ptrFromInt(iov_ptr))[0..count] };
}

/// `struct msghdr`, as the caller laid it out.
pub const Msghdr = extern struct {
    name: u64,
    namelen: u32,
    iov: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
    flags: u32,
};

pub const msg_trunc = 0x20;
/// Asked of `recvmsg` for the descriptors it might be passed: there are
/// none, so it changes nothing.
pub const msg_cmsg_cloexec = 0x4000_0000;

/// The longest datagram that is sent from more than one vector: it is
/// put together on the task's stack.
const gather_max = 4096;

/// Where a datagram read into more than one vector arrives. One for the
/// thread is enough: it is filled by the simulator's receive and emptied
/// into the caller's vectors with no scheduling point between.
threadlocal var whole: [65536]u8 = undefined;

/// `readv`. With no room at all it reads nothing (Linux).
fn readVectors(s: *Sim, slot: *Slot, iov_ptr: u64, count: u64) ?u64 {
    const iov = switch (iovecs(iov_ptr, count, .INVAL)) {
        .ok => |v| v,
        .err => |e| return fail(e),
    };
    for (iov) |v| {
        if (v.len != 0) return receiveVectors(s, slot, iov, 0, 0, 0, null);
    }
    return 0;
}

/// Into the vectors of a `readv` or a `recvmsg`. A stream read fills the
/// first vector with room and no more: it may return fewer bytes than
/// asked, and the caller loops. A datagram is spread over all of them.
fn receiveVectors(s: *Sim, slot: *Slot, iov: []align(1) const Iovec, flags: u32, from_ptr: u64, from_len_ptr: u64, truncated: ?*bool) ?u64 {
    var first: ?Iovec = null;
    var pieces: usize = 0;
    var room: u64 = 0;
    for (iov) |v| {
        if (v.len == 0) continue;
        if (first == null) first = v;
        pieces += 1;
        room +|= v.len;
    }
    const one = first orelse return receive(s, slot, 0, 0, flags, from_ptr, from_len_ptr, truncated);
    if (slot.mode == .stream or pieces == 1) return receive(s, slot, one.base, one.len, flags, from_ptr, from_len_ptr, truncated);
    // No datagram is longer than a socket's receive buffer.
    const most = @min(room, s.net.datagramCapacity());
    if (most > whole.len) return null;
    const rc = receive(s, slot, @intFromPtr(&whole), most, flags, from_ptr, from_len_ptr, truncated) orelse return null;
    if (@as(i64, @bitCast(rc)) < 0) return rc;
    var at: usize = 0;
    for (iov) |v| {
        if (at == rc) break;
        const n: usize = @intCast(@min(v.len, rc - at));
        if (n == 0) continue;
        // The datagram is taken and lost, as on Linux.
        if (v.base == 0) return fail(.FAULT);
        @memcpy(@as([*]u8, @ptrFromInt(v.base))[0..n], whole[at..][0..n]);
        at += n;
    }
    return rc;
}

/// `writev`. With nothing to write it sends nothing, not even an empty
/// datagram (Linux).
fn writeVectors(s: *Sim, slot: *Slot, iov_ptr: u64, count: u64) ?u64 {
    const iov = switch (iovecs(iov_ptr, count, .INVAL)) {
        .ok => |v| v,
        .err => |e| return fail(e),
    };
    for (iov) |v| {
        if (v.len != 0) return sendVectors(s, slot, iov, 0, 0, 0);
    }
    return 0;
}

/// From the vectors of a `writev` or a `sendmsg`. On a stream, every
/// vector in turn, all of it (a blocking stream write is not short). A
/// datagram is one message: put together first when it is in several
/// vectors, which is emulated up to `gather_max` bytes.
fn sendVectors(s: *Sim, slot: *Slot, iov: []align(1) const Iovec, flags: u32, to_ptr: u64, to_len: u64) ?u64 {
    if (slot.mode == .dgram) {
        var only: Iovec = .{ .base = 0, .len = 0 };
        var pieces: usize = 0;
        var all: u64 = 0;
        for (iov) |v| {
            if (v.len == 0) continue;
            only = v;
            pieces += 1;
            all +|= v.len;
        }
        if (pieces <= 1) return send(s, slot, only.base, only.len, flags, to_ptr, to_len);
        if (all > gather_max) return null;
        var joined: [gather_max]u8 = undefined;
        var at: usize = 0;
        for (iov) |v| {
            const part = userBytes(v.base, v.len) orelse return fail(.FAULT);
            @memcpy(joined[at..][0..part.len], part);
            at += part.len;
        }
        return send(s, slot, @intFromPtr(&joined), at, flags, to_ptr, to_len);
    }
    var total: u64 = 0;
    var any = false;
    for (iov) |v| any = any or v.len != 0;
    // A message of no bytes still hears that the stream is not open.
    if (!any) return send(s, slot, 0, 0, flags, 0, 0);
    for (iov) |v| {
        if (v.len == 0) continue;
        const r = send(s, slot, v.base, v.len, flags, 0, 0) orelse return null;
        if (@as(i64, @bitCast(r)) < 0) return if (total > 0) total else r;
        total += r;
        if (r < v.len) break;
    }
    return total;
}

/// `sendmsg`. A message with ancillary data (a descriptor to pass, a
/// packet's options) is stray. A stream ignores the address, as Linux's
/// TCP does.
fn sendMessage(s: *Sim, slot: *Slot, msg_ptr: u64, flags: u32) ?u64 {
    if (msg_ptr == 0) return fail(.FAULT);
    const msg: *align(1) const Msghdr = @ptrFromInt(msg_ptr);
    if (msg.name != 0 and @as(i32, @bitCast(msg.namelen)) < 0) return fail(.INVAL);
    if (msg.controllen != 0) return if (msg.control == 0) fail(.FAULT) else null;
    const iov = switch (iovecs(msg.iov, msg.iovlen, .MSGSIZE)) {
        .ok => |v| v,
        .err => |e| return fail(e),
    };
    // A null name, or a length of 0, is no address (Linux).
    const to_ptr: u64 = if (msg.namelen == 0) 0 else msg.name;
    return sendVectors(s, slot, iov, flags, to_ptr, if (to_ptr == 0) 0 else msg.namelen);
}

/// `recvmsg`. The sender of a datagram goes where `msg_name` says and
/// its length into `msg_namelen`; a stream names no one (length 0).
/// `msg_flags` is `MSG_TRUNC` for a datagram that did not fit, or 0, and
/// `msg_controllen` 0: nothing here produces ancillary data.
fn receiveMessage(s: *Sim, slot: *Slot, msg_ptr: u64, flags: u32) ?u64 {
    if (msg_ptr == 0) return fail(.FAULT);
    const msg: *align(1) Msghdr = @ptrFromInt(msg_ptr);
    if (msg.name != 0 and @as(i32, @bitCast(msg.namelen)) < 0) return fail(.INVAL);
    if (flags & ~@as(u32, msg_nosignal | msg_dontwait | msg_cmsg_cloexec) != 0) return null;
    const iov = switch (iovecs(msg.iov, msg.iovlen, .MSGSIZE)) {
        .ok => |v| v,
        .err => |e| return fail(e),
    };
    const mode = slot.mode;
    var truncated = false;
    const from_ptr: u64 = if (mode == .dgram) msg.name else 0;
    const rc = receiveVectors(s, slot, iov, flags & ~@as(u32, msg_cmsg_cloexec), from_ptr, msg_ptr + @offsetOf(Msghdr, "namelen"), &truncated) orelse return null;
    if (@as(i64, @bitCast(rc)) < 0) return rc;
    if (mode == .stream and msg.name != 0) msg.namelen = 0;
    msg.controllen = 0;
    msg.flags = if (truncated) msg_trunc else 0;
    return rc;
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
            // Reset, the socket is closed: as for an unconnected one.
            if (resetOf(s, slot)) {
                if (h != .recv) slot.shut_send = true;
                if (h != .send) slot.shut_recv = true;
                return fail(.NOTCONN);
            }
            io.vtable.netShutdown(io.userdata, slot.handle, h) catch |err| return fail(errnoOf(err));
            if (h != .recv) slot.shut_send = true;
            if (h != .send) slot.shut_recv = true;
        },
        // Linux disconnects a listener shut down for reading
        // (`tcp_disconnect`): its queue is reset, a waiting `accept` fails
        // (servers stop their loops this way), and the socket is closed
        // again, keeping its port only if `bind` named one.
        .listening => if (h != .send) {
            s.unlisten(slot.handle);
            slot.kind = .bound;
            slot.shut_send = false;
            slot.shut_recv = false;
            if (slot.chose_port) {
                io.vtable.netClose(io.userdata, &.{.{ .handle = slot.handle, .address = slot.local }});
                slot.kind = .fresh;
                slot.stale_port = true;
            }
        },
        // Linux records the shutdown on any other socket, and fails it
        // with `ENOTCONN` when the socket is not connected; a read then
        // returns 0 at once (`inet_shutdown` does so to wake pollers).
        .dgram, .fresh, .bound => {
            defer s.wakeNetwork();
            if (slot.connect_failed) slot.disconnecting = true;
            if (h != .recv) slot.shut_send = true;
            if (h != .send) slot.shut_recv = true;
            if (slot.peer == null) return fail(.NOTCONN);
        },
        .free => unreachable,
    }
    return 0;
}

fn close(s: *Sim, fd: i32) u64 {
    const index = indexOf(fd).?;
    const slot = &slots[index];
    const n: usize = @intCast(fd - fd_base);
    if (n >= slots_max) aliases[n - slots_max] = null else slot.primary_closed = true;
    if (!slot.primary_closed or aliased(index)) {
        // Another number keeps the socket. This one leaves the epoll sets.
        sysfd.forget(fd);
        s.wakeNetwork();
        return 0;
    }
    switch (slot.kind) {
        .bound, .listening, .stream, .dgram => {
            const io = s.io();
            const sock = [_]ionet.Socket{.{ .handle = slot.handle, .address = slot.local }};
            io.vtable.netClose(io.userdata, &sock);
        },
        else => {},
    }
    slot.* = .{};
    // It leaves every epoll set, and a waiter there looks again.
    sysfd.forget(fd);
    s.wakeNetwork();
    return 0;
}

/// Datagrams a read would take now: those that arrived before `connect`,
/// then only the peer's.
fn readable(s: *Sim, slot: *const Slot) u32 {
    const all = s.datagramsArrived(slot.handle);
    const peer = slot.peer orelse return all;
    if (slot.unfiltered > 0 and all > 0) return all;
    return s.datagramsArrivedFrom(slot.handle, peer);
}

/// What a reset reads as: `EPIPE` after the peer's FIN, else `ECONNRESET`.
fn resetErrno(s: *Sim, slot: *const Slot) E {
    return if (s.streamResetIsPipe(slot.handle)) .PIPE else .CONNRESET;
}

/// A stream reset by its peer, reported or not: Linux counts it closed.
fn resetOf(s: *Sim, slot: *const Slot) bool {
    return slot.kind == .stream and (slot.reset_reported or s.streamReset(slot.handle));
}

fn getsockopt(s: *Sim, slot: *Slot, level: u64, name: u64, value_ptr: u64, len_ptr: u64) u64 {
    if (value_ptr == 0 or len_ptr == 0) return fail(.FAULT);
    const len: *align(1) u32 = @ptrFromInt(len_ptr);
    if (len.* < 4) return fail(.INVAL);
    const sol_socket = 1;
    const value: u32 = if (level == sol_socket and name == 3) // SO_TYPE
        (if (slot.mode == .stream) sock_stream else sock_dgram)
    else if (level == sol_socket and name == 4) blk: { // SO_ERROR, cleared
        // A reset not yet reported is reported here, once.
        if (slot.kind == .stream and !slot.reset_reported and s.streamReset(slot.handle)) {
            slot.reset_reported = true;
            s.streamFaultReported(slot.handle);
            break :blk @backingInt(resetErrno(s, slot));
        }
        const e = slot.pending orelse break :blk 0;
        slot.pending = null;
        break :blk @backingInt(e);
    } else 0; // every other option
    @as(*align(1) u32, @ptrFromInt(value_ptr)).* = value;
    len.* = 4;
    return 0;
}

fn fcntl(slot: *Slot, cmd: u32, arg: u64) ?u64 {
    return switch (cmd) {
        1 => 0, // F_GETFD
        2 => 0, // F_SETFD
        3 => if (slot.nonblock) 2 | o_nonblock else 2, // F_GETFL: O_RDWR
        4 => blk: { // F_SETFL: only O_NONBLOCK changes anything
            slot.nonblock = arg & o_nonblock != 0;
            break :blk 0;
        },
        else => null,
    };
}

// --- poll ---------------------------------------------------------------------

pub const pollin = 0x1;
pub const pollout = 0x4;
pub const pollerr = 0x8;
pub const pollhup = 0x10;
pub const pollnval = 0x20;
const pollrdnorm = 0x40;
const pollwrnorm = 0x100;
const pollwrband = 0x200;
const pollrdhup = 0x2000;

/// The events a socket descriptor has, as Linux's `tcp_poll` and
/// `datagram_poll` compute them (before the caller's mask).
pub fn pollMask(s: *Sim, fd: i32) u16 {
    const slot = slotOf(fd) orelse return pollnval;
    const in: u16 = pollin | pollrdnorm;
    const out: u16 = pollout | pollwrnorm;
    var m: u16 = 0;
    switch (slot.kind) {
        .free => unreachable,
        .listening => if (s.listenerReady(slot.handle)) {
            m |= in;
        },
        .fresh, .bound => if (slot.mode == .stream) {
            // A closed TCP socket: hung up, and writable.
            m |= pollhup | out;
            // A failed non-blocking attempt left it shut down both ways.
            if (slot.shut_recv or slot.connect_failed) m |= in | pollrdhup;
            if (slot.pending != null) m |= pollerr;
        } else {
            m |= out | pollwrband;
            if (slot.shut_recv) m |= in | pollrdhup;
            if (slot.shut_recv and slot.shut_send) m |= pollhup;
        },
        .stream => if (resetOf(s, slot)) {
            // Reset: closed, shut down both ways; the error until taken.
            m |= pollhup | in | pollrdhup | out;
            if (!slot.reset_reported) m |= pollerr;
        } else {
            const rcv_shut = slot.shut_recv or s.streamResetIsPipe(slot.handle);
            if (rcv_shut) m |= in | pollrdhup;
            if (rcv_shut and slot.shut_send) m |= pollhup;
            if (s.streamReadable(slot.handle)) m |= in;
            if (slot.shut_send or s.streamWritable(slot.handle)) m |= out;
        },
        .dgram => {
            m |= out | pollwrband;
            if (readable(s, slot) > 0) m |= in;
            if (slot.pending != null) m |= pollerr;
            if (slot.shut_recv) m |= in | pollrdhup;
            if (slot.shut_recv and slot.shut_send) m |= pollhup;
        },
    }
    return m;
}
