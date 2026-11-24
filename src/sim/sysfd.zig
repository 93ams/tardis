//! Pipes, `eventfd` and `epoll` in system-call mode (plan §9.2,
//! `plan3.md` D9): what an event loop is made of, beside its sockets.
//!
//! These have no counterpart in `std.Io`, so unlike files (`sysemu.zig`)
//! and sockets (`sysnet.zig`) they are not translations: the objects live
//! here. They hold no durable state and never leave their node, so there
//! is nothing for a crash or the network model to say about them: a node's
//! crash frees its descriptors (`dropNode`) and that is all. A task that
//! waits on one waits as `poll` does, on the simulator's network wait,
//! which every change here ends (`Sim.wakeNetwork`).
//!
//! A descriptor is `fd_base` plus a slot: below the sockets', above every
//! real one.
//!
//! Emulated:
//! - `pipe`, `pipe2` (`O_NONBLOCK`, `O_CLOEXEC`): 64 KiB, as Linux's. A
//!   write of up to 4096 bytes is all or nothing; a larger one may be
//!   short when non-blocking. A read of an empty pipe with no writer
//!   returns 0; a write with no reader fails with `EPIPE` (no `SIGPIPE`:
//!   signals are not modelled).
//! - `eventfd`, `eventfd2` (`EFD_SEMAPHORE`, `EFD_NONBLOCK`,
//!   `EFD_CLOEXEC`).
//! - `socketpair` of the Unix domain, `SOCK_STREAM` (`SOCK_NONBLOCK`,
//!   `SOCK_CLOEXEC`): two descriptors, each of which reads what was
//!   written to the other. It is two pipes, one each way, of 64 KiB
//!   (Linux's holds about 208 KiB), with no all-or-nothing rule. On it,
//!   beside what is listed below: `recvfrom` (`MSG_DONTWAIT`, `MSG_PEEK`),
//!   `sendto` (`MSG_DONTWAIT`, `MSG_NOSIGNAL`), `shutdown`, `getsockname`
//!   and `getpeername` (unnamed), `setsockopt` (accepted, changes
//!   nothing) and `getsockopt` for `SO_ERROR`, `SO_TYPE`, `SO_DOMAIN`,
//!   `SO_SNDBUF`, `SO_RCVBUF`. Divergences: closing an end with unread
//!   bytes does not give the other end `ECONNRESET`; a timeout set with
//!   `SO_RCVTIMEO` or `SO_SNDTIMEO` never expires; no `SIGPIPE` is
//!   raised; and a task that writes more than 64 KiB before anyone reads
//!   waits here where on Linux it would wait only past about 208 KiB.
//! - `epoll_create`, `epoll_create1`, `epoll_ctl`, `epoll_wait`,
//!   `epoll_pwait`, `epoll_pwait2`, over sockets, pipes, pairs and eventfds,
//!   level-triggered, edge-triggered (`EPOLLET`) and `EPOLLONESHOT`.
//! - On these descriptors: `read`, `write`, `readv`, `writev`, `close`,
//!   `fstat` (the kind only), `fcntl` for the flags, `ioctl` `FIONBIO`
//!   and, for a pipe or a pair, `FIONREAD`. On a pipe, an eventfd or
//!   an epoll set the calls a pair has beside these fail with `ENOTSOCK`.
//! - `dup` and `fcntl` `F_DUPFD`, `F_DUPFD_CLOEXEC` of one of these (mio
//!   and so tokio duplicate their epoll descriptor): a second descriptor
//!   for the same pipe end, counter or epoll set, which lives until the
//!   last is closed. The new number is the lowest free one here, whatever
//!   minimum `F_DUPFD` asks for. Two divergences: a descriptor leaves
//!   the epoll sets it is in when it is closed, where Linux keeps it
//!   until its last duplicate is closed; and a task waiting in a call on
//!   a descriptor that another task closes gets `EBADF`, where Linux
//!   goes on waiting on the object.
//!
//! **Edge-triggered is an approximation.** Linux reports an edge when
//! something arrives. Here an event is reported once, and reported again
//! after it was seen to be gone, after the program made any call on that
//! descriptor, after a write to the other end of a pipe (or a read from
//! it), and, for a socket, after anything changed in the network or
//! virtual time passed, since either may be an arrival. The aim is that a
//! program misses no edge Linux would give it. It may get one Linux would
//! not (after a partial read, with nothing new arrived), which means a
//! program that fails to drain a descriptor is not caught by this.
//!
//! Every call here is a point where the scheduler may switch tasks, as
//! every simulated operation is.
//!
//! Not emulated (stray): a pair of datagram or `SOCK_SEQPACKET` sockets;
//! `sendmsg` and `recvmsg` on a pair, so no descriptor or credential is
//! passed through one, and `SO_PEERCRED`; an epoll descriptor inside an
//! epoll set or a
//! `poll`; a regular file in an epoll set fails with `EPERM`, as on Linux;
//! `O_DIRECT` pipes; `splice`, `tee`, `F_SETPIPE_SZ`; `dup2` and `dup3`
//! (the program chooses the number), and `dup` of a socket or a file.
//! `select` cannot be emulated at all: simulated descriptors are far
//! above `FD_SETSIZE`. For the same reason a library that keeps a table
//! indexed by descriptor number (libuv and libevent do) will try to
//! allocate a table of that size.

const std = @import("std");
const linux = std.os.linux;
const Sim = @import("Sim.zig");
const sysemu = @import("sysemu.zig");
const sysnet = @import("sysnet.zig");

const E = linux.E;

/// The first descriptor.
pub const fd_base: i32 = 0x1000_0000;
const slots_max = 128;
const pipes_max = 64;
const epolls_max = 8;
const interest_max = 64;

pub const pipe_bytes = 65536;
/// POSIX `PIPE_BUF`: a write of up to this many bytes is not split.
const pipe_atomic_bytes = 4096;

const Kind = enum { free, pipe_read, pipe_write, pair, eventfd, epoll };

const Slot = struct {
    kind: Kind = .free,
    /// The node of the task that made it: its crash frees the slot.
    node: u16 = 0,
    nonblock: bool = false,
    /// `EFD_SEMAPHORE`: a read takes 1.
    semaphore: bool = false,
    /// Index into `pipes`, `counters` or `epolls`. For one of a pair of
    /// sockets, the pipe it reads.
    object: u8 = 0,
    /// For one of a pair of sockets: the pipe it writes.
    out: u8 = 0,
    /// The open file description: shared by a descriptor and its
    /// duplicates, which share `O_NONBLOCK` too.
    description: u32 = 0,
    /// Changes whenever the slot is taken: an operation that waited
    /// checks it to see whether its descriptor was closed meanwhile.
    gen: u32 = 0,
};

const Pipe = struct {
    used: bool = false,
    head: u32 = 0,
    len: u32 = 0,
    readers: u8 = 0,
    writers: u8 = 0,
    /// `shutdown` on a pair of sockets, by either end: nothing more is
    /// written to it, and a read of it when empty returns 0.
    shut: bool = false,
};

/// An eventfd's counter, and how many descriptors it has.
const Counter = struct {
    holders: u8 = 0,
    value: u64 = 0,
};

const Entry = struct {
    fd: i32,
    events: u32,
    data: u64,
    /// Edge-triggered: the events that would be reported if ready.
    armed: u32 = ~@as(u32, 0),
    /// `EPOLLONESHOT` after its report: silent until `EPOLL_CTL_MOD`.
    disabled: bool = false,
};

const Epoll = struct {
    used: bool = false,
    /// Descriptors for it: the set lives until the last is closed.
    holders: u8 = 0,
    len: u8 = 0,
    /// Where the next scan begins: no ready entry starves another.
    rotor: u8 = 0,
    /// The virtual time and network change count of the last scan.
    seen_ns: u64 = 0,
    seen_changes: u64 = 0,
    entries: [interest_max]Entry = undefined,
};

/// The descriptors of the run on this thread.
threadlocal var slots: [slots_max]Slot = @splat(.{});
threadlocal var pipes: [pipes_max]Pipe = @splat(.{});
threadlocal var counters: [slots_max]Counter = @splat(.{});
threadlocal var epolls: [epolls_max]Epoll = @splat(.{});
/// The pipes' bytes, mapped on the first `pipe` of the thread and kept.
threadlocal var pipe_buffers: ?[]u8 = null;
/// Epoll sets in use: nothing to re-arm or forget while it is 0.
threadlocal var epoll_count: u32 = 0;
threadlocal var next_gen: u32 = 0;
/// Counts the simulator's network changes (`networkChanged`).
threadlocal var net_changes: u64 = 0;

/// The network changed (`Sim.netWakeAll`): something may have arrived on
/// a socket, which is an edge for an edge-triggered entry.
pub fn networkChanged() void {
    net_changes +%= 1;
}

/// A run begins: no descriptor is open.
pub fn reset() void {
    slots = @splat(.{});
    for (&pipes) |*p| p.* = .{};
    counters = @splat(.{});
    for (&epolls) |*e| e.* = .{};
    epoll_count = 0;
    net_changes = 0;
}

/// A node crashed (null: every node): its descriptors are gone.
pub fn dropNode(node: ?u16) void {
    for (&slots, 0..) |*slot, i| {
        if (slot.kind == .free) continue;
        if (node) |n| if (slot.node != n) continue;
        release(@intCast(i));
    }
}

pub fn isFd(fd: i32) bool {
    return fd >= fd_base and fd < fd_base + slots_max;
}

fn fail(e: E) u64 {
    return @bitCast(-@as(i64, @backingInt(e)));
}

fn slotOf(fd: i32) ?*Slot {
    if (!isFd(fd)) return null;
    const s = &slots[@intCast(fd - fd_base)];
    return if (s.kind == .free) null else s;
}

fn fdOf(index: usize) i32 {
    return fd_base + @as(i32, @intCast(index));
}

fn take(s: *Sim, kind: Kind) ?usize {
    for (&slots, 0..) |*slot, i| {
        if (slot.kind != .free) continue;
        next_gen +%= 1;
        slot.* = .{ .kind = kind, .node = s.currentNode(), .gen = next_gen, .description = next_gen };
        return i;
    }
    return null;
}

/// Frees a slot and what it was the last holder of. Does not wake.
fn release(index: usize) void {
    const slot = &slots[index];
    switch (slot.kind) {
        .free => return,
        .pipe_read => {
            const p = &pipes[slot.object];
            p.readers -= 1;
            if (p.readers == 0 and p.writers == 0) p.* = .{};
        },
        .pipe_write => {
            const p = &pipes[slot.object];
            p.writers -= 1;
            if (p.readers == 0 and p.writers == 0) p.* = .{};
        },
        .pair => {
            const in = &pipes[slot.object];
            in.readers -= 1;
            if (in.readers == 0 and in.writers == 0) in.* = .{};
            const out = &pipes[slot.out];
            out.writers -= 1;
            if (out.readers == 0 and out.writers == 0) out.* = .{};
        },
        .eventfd => {
            const c = &counters[slot.object];
            c.holders -= 1;
            if (c.holders == 0) c.* = .{};
        },
        .epoll => {
            const e = &epolls[slot.object];
            e.holders -= 1;
            if (e.holders == 0) {
                e.used = false;
                epoll_count -= 1;
            }
        },
    }
    slot.* = .{};
    forget(fdOf(index));
}

/// A simulated descriptor of any kind was closed: it leaves every epoll
/// set, as on Linux when its last descriptor closes.
pub fn forget(fd: i32) void {
    if (epoll_count == 0) return;
    for (&epolls) |*e| {
        if (!e.used) continue;
        var i: usize = 0;
        while (i < e.len) {
            if (e.entries[i].fd == fd) {
                e.len -= 1;
                e.entries[i] = e.entries[e.len];
            } else i += 1;
        }
    }
}

/// A pipe was written or read: an edge for whoever watches either end.
fn touchedPipe(index: usize) void {
    if (epoll_count == 0) return;
    for (&slots, 0..) |*slot, i| {
        const on_it = switch (slot.kind) {
            .pipe_read, .pipe_write => slot.object == index,
            .pair => slot.object == index or slot.out == index,
            else => false,
        };
        if (on_it) touched(fdOf(i));
    }
}

/// An eventfd's counter changed: an edge for whoever watches any of its
/// descriptors, not only the one the call was made on.
fn touchedCounter(index: usize) void {
    if (epoll_count == 0) return;
    for (&slots, 0..) |*slot, i| {
        if (slot.kind == .eventfd and slot.object == index) touched(fdOf(i));
    }
}

/// The program made a call on `fd`: an edge-triggered event on it is
/// reported again if it is still (or again) ready. See the file comment.
pub fn touched(fd: i32) void {
    if (epoll_count == 0) return;
    for (&epolls) |*e| {
        if (!e.used) continue;
        for (e.entries[0..e.len]) |*entry| {
            if (entry.fd == fd) entry.armed = ~@as(u32, 0);
        }
    }
}

fn userBytes(ptr: u64, len: u64) ?[]u8 {
    if (len == 0) return &.{};
    if (ptr == 0) return null;
    return @as([*]u8, @ptrFromInt(ptr))[0..len];
}

/// Waits for anything to change. False if the wait was canceled.
fn wait(s: *Sim) bool {
    s.waitNetwork(null) catch return false;
    return true;
}

// --- the calls ------------------------------------------------------------------

const o_nonblock = 0o4000;
const o_cloexec = 0o2000000;

/// Entry point from `sysemu.emulate`, for the calls that make one of these
/// descriptors and the calls on one: the value for `rax`, or null for a
/// call that is not emulated (stray).
pub fn emulate(s: *Sim, number: u64, a: *const [6]u64) ?u64 {
    switch (number) {
        22 => return pipe(s, a[0], 0),
        293 => return pipe(s, a[0], @truncate(a[1])),
        284 => return eventfd(s, a[0], 0),
        290 => return eventfd(s, a[0], @truncate(a[1])),
        213 => return if (@as(i32, @bitCast(@as(u32, @truncate(a[0])))) <= 0) fail(.INVAL) else epollCreate(s, 0),
        291 => return epollCreate(s, @truncate(a[0])),
        53 => return socketpair(s, @truncate(a[0]), @truncate(a[1]), @truncate(a[2]), a[3]),
        else => {},
    }
    const fd: i32 = @bitCast(@as(u32, @truncate(a[0])));
    if (!isFd(fd)) return null;
    // A scheduling point, before the descriptor is looked at.
    s.yieldPoint();
    const slot = slotOf(fd) orelse return fail(.BADF);
    return switch (number) {
        233 => epollCtl(s, slot, @truncate(a[1]), @bitCast(@as(u32, @truncate(a[2]))), a[3]),
        232, 281 => epollWait(s, slot, a[1], a[2], msDeadline(s, a[3])),
        441 => blk: {
            var deadline: ?u64 = null;
            if (a[3] != 0) {
                const ts: *align(1) const [2]i64 = @ptrFromInt(a[3]);
                if (ts[0] < 0 or ts[1] < 0 or ts[1] >= std.time.ns_per_s) break :blk fail(.INVAL);
                deadline = s.now_ns +| (@as(u64, @intCast(ts[0])) *| std.time.ns_per_s +| @as(u64, @intCast(ts[1])));
            }
            break :blk epollWait(s, slot, a[1], a[2], deadline);
        },
        0 => read(s, slot, userBytes(a[1], a[2]) orelse return fail(.FAULT)),
        1 => write(s, slot, userBytes(a[1], a[2]) orelse return fail(.FAULT)),
        44, 45, 48, 51, 52, 54, 55 => if (slot.kind == .pair) onSocket(s, slot, number, a) else fail(.NOTSOCK),
        19 => vectors(s, slot, a[1], a[2], .read),
        20 => vectors(s, slot, a[1], a[2], .write),
        3 => blk: {
            release(@intCast(fd - fd_base));
            s.wakeNetwork();
            break :blk 0;
        },
        5 => fstat(slot, a[1]),
        8, 17, 18 => fail(.SPIPE), // lseek, pread64, pwrite64
        16 => ioctl(slot, @truncate(a[1]), a[2]),
        32 => duplicate(s, slot),
        72 => fcntl(s, slot, @truncate(a[1]), a[2]),
        74, 75, 77 => fail(.INVAL), // fsync, fdatasync, ftruncate
        else => null,
    };
}

fn msDeadline(s: *Sim, timeout_ms: u64) ?u64 {
    const ms: i32 = @bitCast(@as(u32, @truncate(timeout_ms)));
    if (ms < 0) return null;
    return s.now_ns + @as(u64, @intCast(ms)) * std.time.ns_per_ms;
}

// --- pipes ---------------------------------------------------------------------

fn pipeBytes(index: usize) ?[]u8 {
    if (pipe_buffers == null) {
        pipe_buffers = std.heap.page_allocator.alloc(u8, pipes_max * pipe_bytes) catch return null;
    }
    return pipe_buffers.?[index * pipe_bytes ..][0..pipe_bytes];
}

/// The first pipe not in use, from `from` on.
fn freePipe(from: usize) ?usize {
    for (pipes[from..], from..) |*p, i| {
        if (!p.used) return i;
    }
    return null;
}

fn pipe(s: *Sim, out_ptr: u64, flags: u32) ?u64 {
    if (flags & ~@as(u32, o_nonblock | o_cloexec) != 0) return null; // `O_DIRECT`: packets
    if (out_ptr == 0) return fail(.FAULT);
    const index = freePipe(0) orelse return fail(.MFILE);
    _ = pipeBytes(index) orelse return fail(.NFILE);
    const r = take(s, .pipe_read) orelse return fail(.MFILE);
    const w = take(s, .pipe_write) orelse {
        slots[r] = .{};
        return fail(.MFILE);
    };
    pipes[index] = .{ .used = true, .readers = 1, .writers = 1 };
    for ([2]usize{ r, w }) |i| {
        slots[i].object = @intCast(index);
        slots[i].nonblock = flags & o_nonblock != 0;
    }
    const out: *align(1) [2]i32 = @ptrFromInt(out_ptr);
    out.* = .{ fdOf(r), fdOf(w) };
    return 0;
}

const ReadHow = struct {
    /// `MSG_DONTWAIT`: this call does not wait, whatever the descriptor's flag.
    dontwait: bool = false,
    /// `MSG_PEEK`: the bytes stay.
    peek: bool = false,
};

fn pipeRead(s: *Sim, slot: *Slot, buf: []u8, how: ReadHow) u64 {
    if (buf.len == 0) return 0;
    const index = slot.object;
    const gen = slot.gen;
    const p = &pipes[index];
    while (p.len == 0) {
        if (p.writers == 0 or p.shut) return 0;
        if (slot.nonblock or how.dontwait) return fail(.AGAIN);
        if (!wait(s)) return fail(.INTR);
        // Closed by another task while this one waited.
        if (slot.gen != gen) return fail(.BADF);
    }
    const bytes = pipeBytes(index).?;
    const n: u32 = @intCast(@min(buf.len, p.len));
    const first = @min(n, pipe_bytes - p.head);
    @memcpy(buf[0..first], bytes[p.head..][0..first]);
    @memcpy(buf[first..n], bytes[0 .. n - first]);
    if (how.peek) return n;
    p.head = (p.head + n) % pipe_bytes;
    p.len -= n;
    touchedPipe(index);
    s.wakeNetwork();
    return n;
}

/// Writes to the pipe `index`: the slot's own, or for one of a pair of
/// sockets the one it writes. `atomic`: a pipe's rule for a small write.
fn pipeWrite(s: *Sim, slot: *Slot, index: usize, buf: []const u8, atomic: bool, dontwait: bool) u64 {
    if (buf.len == 0) return 0;
    const gen = slot.gen;
    const p = &pipes[index];
    const bytes = pipeBytes(index).?;
    var done: usize = 0;
    while (done < buf.len) {
        if (p.readers == 0 or p.shut) return if (done > 0) done else fail(.PIPE);
        const room = pipe_bytes - p.len;
        // A small write is not split: it waits for room for all of it.
        const need: usize = if (atomic and buf.len <= pipe_atomic_bytes) buf.len else 1;
        if (room < need) {
            if (slot.nonblock or dontwait) return if (done > 0) done else fail(.AGAIN);
            if (!wait(s)) return if (done > 0) done else fail(.INTR);
            if (slot.gen != gen) return if (done > 0) done else fail(.BADF);
            continue;
        }
        const n: u32 = @intCast(@min(buf.len - done, room));
        const tail = (p.head + p.len) % pipe_bytes;
        const first = @min(n, pipe_bytes - tail);
        @memcpy(bytes[tail..][0..first], buf[done..][0..first]);
        @memcpy(bytes[0 .. n - first], buf[done + first ..][0 .. n - first]);
        p.len += n;
        done += n;
        touchedPipe(index);
        s.wakeNetwork();
    }
    return done;
}

// --- a pair of sockets ----------------------------------------------------------

const af_unix = 1;
const af_inet = 2;
const af_inet6 = 10;
const af_netlink = 16;
const sock_stream = 1;
const msg_peek = 0x2;
const msg_dontwait = 0x40;
const msg_nosignal = 0x4000;

fn socketpair(s: *Sim, domain: u32, type_and_flags: u32, protocol: u32, out_ptr: u64) ?u64 {
    switch (domain) {
        af_unix => {},
        // As Linux: these families have no pairs. (The last two are not
        // here at all: `sysnet.socket`.)
        af_inet => return fail(.OPNOTSUPP),
        af_inet6, af_netlink => return fail(.AFNOSUPPORT),
        else => return null,
    }
    if (type_and_flags & ~@as(u32, o_nonblock | o_cloexec) != sock_stream) return null; // datagrams, packets
    if (protocol != 0 and protocol != af_unix) return fail(.PROTONOSUPPORT);
    if (out_ptr == 0) return fail(.FAULT);
    const first = freePipe(0) orelse return fail(.MFILE);
    const second = freePipe(first + 1) orelse return fail(.MFILE);
    _ = pipeBytes(second) orelse return fail(.NFILE);
    const a = take(s, .pair) orelse return fail(.MFILE);
    const b = take(s, .pair) orelse {
        slots[a] = .{};
        return fail(.MFILE);
    };
    pipes[first] = .{ .used = true, .readers = 1, .writers = 1 };
    pipes[second] = .{ .used = true, .readers = 1, .writers = 1 };
    slots[a].object = @intCast(first);
    slots[a].out = @intCast(second);
    slots[b].object = @intCast(second);
    slots[b].out = @intCast(first);
    for ([2]usize{ a, b }) |i| slots[i].nonblock = type_and_flags & o_nonblock != 0;
    const out: *align(1) [2]i32 = @ptrFromInt(out_ptr);
    out.* = .{ fdOf(a), fdOf(b) };
    return 0;
}

/// The calls only a socket has, on one of a pair.
fn onSocket(s: *Sim, slot: *Slot, number: u64, a: *const [6]u64) ?u64 {
    switch (number) {
        44 => { // sendto
            const flags: u32 = @truncate(a[3]);
            if (flags & ~@as(u32, msg_dontwait | msg_nosignal) != 0) return null; // out-of-band, more
            if (a[4] != 0) return fail(.ISCONN);
            const buf = userBytes(a[1], a[2]) orelse return fail(.FAULT);
            return pipeWrite(s, slot, slot.out, buf, false, flags & msg_dontwait != 0);
        },
        45 => { // recvfrom
            const flags: u32 = @truncate(a[3]);
            if (flags & ~@as(u32, msg_dontwait | msg_peek | msg_nosignal) != 0) return null; // wait for all, truncate
            const buf = userBytes(a[1], a[2]) orelse return fail(.FAULT);
            const rc = pipeRead(s, slot, buf, .{ .dontwait = flags & msg_dontwait != 0, .peek = flags & msg_peek != 0 });
            // The sender has no name.
            if (@as(i64, @bitCast(rc)) >= 0 and a[4] != 0 and a[5] != 0) @as(*align(1) u32, @ptrFromInt(a[5])).* = 0;
            return rc;
        },
        48 => { // shutdown: 0 the reading, 1 the writing, 2 both
            if (a[1] > 2) return fail(.INVAL);
            if (a[1] != 1) pipes[slot.object].shut = true;
            if (a[1] != 0) pipes[slot.out].shut = true;
            touchedPipe(slot.object);
            touchedPipe(slot.out);
            s.wakeNetwork();
            return 0;
        },
        51, 52 => { // getsockname, getpeername: a family and no name
            if (a[1] == 0 or a[2] == 0) return fail(.FAULT);
            const len: *align(1) u32 = @ptrFromInt(a[2]);
            if (@as(i32, @bitCast(len.*)) < 0) return fail(.INVAL);
            const family = std.mem.toBytes(@as(u16, af_unix));
            const n = @min(len.*, family.len);
            @memcpy(@as([*]u8, @ptrFromInt(a[1]))[0..n], family[0..n]);
            len.* = family.len;
            return 0;
        },
        54 => return 0, // setsockopt: accepted, changes nothing
        55 => { // getsockopt
            if (a[1] != 1) return fail(.OPNOTSUPP); // not SOL_SOCKET
            const value: i32 = switch (a[2]) {
                4 => 0, // SO_ERROR
                3 => sock_stream, // SO_TYPE
                39 => af_unix, // SO_DOMAIN
                7, 8 => pipe_bytes, // SO_SNDBUF, SO_RCVBUF
                else => return null,
            };
            if (a[3] == 0 or a[4] == 0) return fail(.FAULT);
            const len: *align(1) u32 = @ptrFromInt(a[4]);
            if (@as(i32, @bitCast(len.*)) < 0) return fail(.INVAL);
            const bytes = std.mem.toBytes(value);
            const n = @min(len.*, bytes.len);
            @memcpy(@as([*]u8, @ptrFromInt(a[3]))[0..n], bytes[0..n]);
            len.* = n;
            return 0;
        },
        else => unreachable,
    }
}

// --- eventfd --------------------------------------------------------------------

const efd_semaphore = 1;
const counter_max = std.math.maxInt(u64) - 1;

fn eventfd(s: *Sim, initial: u64, flags: u32) ?u64 {
    if (flags & ~@as(u32, efd_semaphore | o_nonblock | o_cloexec) != 0) return fail(.INVAL);
    const index = for (&counters, 0..) |*c, n| {
        if (c.holders == 0) break n;
    } else return fail(.MFILE);
    const i = take(s, .eventfd) orelse return fail(.MFILE);
    slots[i].object = @intCast(index);
    counters[index] = .{ .holders = 1, .value = @as(u32, @truncate(initial)) };
    slots[i].semaphore = flags & efd_semaphore != 0;
    slots[i].nonblock = flags & o_nonblock != 0;
    return @intCast(fdOf(i));
}

fn eventRead(s: *Sim, slot: *Slot, buf: []u8) u64 {
    if (buf.len < 8) return fail(.INVAL);
    const gen = slot.gen;
    const counter = &counters[slot.object].value;
    while (counter.* == 0) {
        if (slot.nonblock) return fail(.AGAIN);
        if (!wait(s)) return fail(.INTR);
        if (slot.gen != gen) return fail(.BADF);
    }
    const value: u64 = if (slot.semaphore) 1 else counter.*;
    counter.* -= value;
    std.mem.writeInt(u64, buf[0..8], value, .little);
    touchedCounter(slot.object);
    s.wakeNetwork();
    return 8;
}

fn eventWrite(s: *Sim, slot: *Slot, buf: []const u8) u64 {
    if (buf.len < 8) return fail(.INVAL);
    const value = std.mem.readInt(u64, buf[0..8], .little);
    if (value == std.math.maxInt(u64)) return fail(.INVAL);
    const gen = slot.gen;
    const counter = &counters[slot.object].value;
    while (value > counter_max - counter.*) {
        if (slot.nonblock) return fail(.AGAIN);
        if (!wait(s)) return fail(.INTR);
        if (slot.gen != gen) return fail(.BADF);
    }
    counter.* += value;
    touchedCounter(slot.object);
    s.wakeNetwork();
    return 8;
}

// --- read, write and the rest -----------------------------------------------------

fn read(s: *Sim, slot: *Slot, buf: []u8) u64 {
    return switch (slot.kind) {
        .pipe_read => pipeRead(s, slot, buf, .{}),
        .pair => pipeRead(s, slot, buf, .{}),
        .eventfd => eventRead(s, slot, buf),
        .pipe_write => fail(.BADF),
        .epoll => fail(.INVAL),
        .free => unreachable,
    };
}

fn write(s: *Sim, slot: *Slot, buf: []const u8) u64 {
    return switch (slot.kind) {
        .pipe_write => pipeWrite(s, slot, slot.object, buf, true, false),
        .pair => pipeWrite(s, slot, slot.out, buf, false, false),
        .eventfd => eventWrite(s, slot, buf),
        .pipe_read => fail(.BADF),
        .epoll => fail(.INVAL),
        .free => unreachable,
    };
}

const Iovec = extern struct { base: u64, len: u64 };

/// `readv`: vector by vector, stopping at the first that is short, and
/// not waiting after the first. `writev`: as one write. Up to 4096 bytes
/// in all go in together or not at all; a longer one goes vector by
/// vector, each waiting for room unless the descriptor is non-blocking.
fn vectors(s: *Sim, slot: *Slot, iov_ptr: u64, count: u64, comptime direction: enum { read, write }) u64 {
    if (count > 1024) return fail(.INVAL);
    if (count > 0 and iov_ptr == 0) return fail(.FAULT);
    const iov: []align(1) const Iovec = if (count == 0) &.{} else @as([*]align(1) const Iovec, @ptrFromInt(iov_ptr))[0..count];
    const gen = slot.gen;
    if (direction == .write) {
        var all: u64 = 0;
        for (iov) |v| all +|= v.len;
        if (all <= pipe_atomic_bytes) {
            var joined: [pipe_atomic_bytes]u8 = undefined;
            var at: usize = 0;
            for (iov) |v| {
                const buf = userBytes(v.base, v.len) orelse return fail(.FAULT);
                @memcpy(joined[at..][0..buf.len], buf);
                at += buf.len;
            }
            return write(s, slot, joined[0..at]);
        }
    }
    var total: u64 = 0;
    for (iov) |v| {
        const buf = userBytes(v.base, v.len) orelse return if (total > 0) total else fail(.FAULT);
        if (buf.len == 0) continue;
        // After the first vector a read does not wait. Only then is the
        // flag put back: a call that waited may come back to a flag that
        // another task changed through a duplicate.
        const forced = direction == .read and total > 0 and !slot.nonblock;
        if (forced) slot.nonblock = true;
        const rc = if (direction == .read) read(s, slot, buf) else write(s, slot, buf);
        if (slot.gen != gen) return if (total > 0) total else rc;
        if (forced) slot.nonblock = false;
        if (@as(i64, @bitCast(rc)) < 0) return if (total > 0) total else rc;
        total += rc;
        if (rc < buf.len) break;
    }
    return total;
}

/// The kind, and nothing else: `st_mode` of a zeroed `struct stat`.
fn fstat(slot: *const Slot, out_ptr: u64) u64 {
    if (out_ptr == 0) return fail(.FAULT);
    const out: *[144]u8 = @ptrFromInt(out_ptr);
    out.* = @splat(0);
    const mode: u32 = switch (slot.kind) {
        .pipe_read, .pipe_write => 0o010600, // S_IFIFO
        .pair => 0o140777, // S_IFSOCK
        else => 0o600, // an anonymous inode
    };
    std.mem.writeInt(u32, out[24..28], mode, .little);
    std.mem.writeInt(u64, out[16..24], 1, .little); // st_nlink
    std.mem.writeInt(u64, out[56..64], 4096, .little); // st_blksize
    return 0;
}

/// `dup`: another descriptor for what `slot` is one for.
fn duplicate(s: *Sim, slot: *Slot) u64 {
    const from = slot.*;
    const i = take(s, from.kind) orelse return fail(.MFILE);
    slots[i].nonblock = from.nonblock;
    slots[i].semaphore = from.semaphore;
    slots[i].object = from.object;
    slots[i].out = from.out;
    slots[i].description = from.description;
    switch (from.kind) {
        .free => unreachable,
        .pipe_read => pipes[from.object].readers += 1,
        .pipe_write => pipes[from.object].writers += 1,
        .pair => {
            pipes[from.object].readers += 1;
            pipes[from.out].writers += 1;
        },
        .eventfd => counters[from.object].holders += 1,
        .epoll => epolls[from.object].holders += 1,
    }
    return @intCast(fdOf(i));
}

/// `O_NONBLOCK` is the open file description's: every duplicate has it.
fn setNonblock(slot: *Slot, on: bool) void {
    const description = slot.description;
    for (&slots) |*other| {
        if (other.kind != .free and other.description == description) other.nonblock = on;
    }
}

fn fcntl(s: *Sim, slot: *Slot, cmd: u32, arg: u64) ?u64 {
    return switch (cmd) {
        0, 1030 => duplicate(s, slot), // F_DUPFD, F_DUPFD_CLOEXEC
        1 => 0, // F_GETFD
        2 => 0, // F_SETFD
        3 => blk: { // F_GETFL
            const access: u64 = switch (slot.kind) {
                .pipe_read => 0,
                .pipe_write => 1,
                else => 2,
            };
            break :blk access | (if (slot.nonblock) @as(u64, o_nonblock) else 0);
        },
        4 => blk: { // F_SETFL: only O_NONBLOCK changes anything
            setNonblock(slot, arg & o_nonblock != 0);
            break :blk 0;
        },
        1032 => if (slot.kind == .pipe_read or slot.kind == .pipe_write) pipe_bytes else fail(.BADF), // F_GETPIPE_SZ
        else => null,
    };
}

fn ioctl(slot: *Slot, request: u32, arg: u64) ?u64 {
    switch (request) {
        0x5421 => { // FIONBIO
            if (arg == 0) return fail(.FAULT);
            setNonblock(slot, @as(*align(1) const i32, @ptrFromInt(arg)).* != 0);
            return 0;
        },
        0x541B => { // FIONREAD
            if (slot.kind != .pipe_read and slot.kind != .pipe_write and slot.kind != .pair) return fail(.NOTTY);
            if (arg == 0) return fail(.FAULT);
            @as(*align(1) i32, @ptrFromInt(arg)).* = @intCast(pipes[slot.object].len);
            return 0;
        },
        else => return null,
    }
}

// --- readiness -------------------------------------------------------------------

pub const poll_in = 0x1;
pub const poll_pri = 0x2;
pub const poll_out = 0x4;
pub const poll_err = 0x8;
pub const poll_hup = 0x10;
pub const poll_nval = 0x20;
const rdnorm = 0x40;
const wrnorm = 0x100;
const poll_rdhup = 0x2000;

/// The events one of these descriptors has, as `poll` names them.
pub fn pollMask(fd: i32) u16 {
    const slot = slotOf(fd) orelse return poll_nval;
    var m: u16 = 0;
    switch (slot.kind) {
        .free => unreachable,
        .pipe_read => {
            const p = &pipes[slot.object];
            if (p.len > 0) m |= poll_in | rdnorm;
            if (p.writers == 0) m |= poll_hup;
        },
        .pipe_write => {
            const p = &pipes[slot.object];
            // No reader: an error, and writable (the write fails at once).
            if (p.readers == 0) m |= poll_err | poll_out | wrnorm else if (pipe_bytes - p.len >= pipe_atomic_bytes) m |= poll_out | wrnorm;
        },
        .pair => {
            const in = &pipes[slot.object];
            const out = &pipes[slot.out];
            const in_over = in.writers == 0 or in.shut;
            const out_over = out.readers == 0 or out.shut;
            // The end of what there is to read is readable, as Linux's.
            if (in.len > 0 or in_over) m |= poll_in | rdnorm;
            if (in_over) m |= poll_rdhup;
            if (in_over and out_over) m |= poll_hup;
            // Writable while no more than a quarter is in use, as
            // Linux's, or when a write would fail at once.
            if (out_over or out.len * 4 <= pipe_bytes) m |= poll_out | wrnorm;
        },
        .eventfd => {
            const value = counters[slot.object].value;
            if (value > 0) m |= poll_in | rdnorm;
            if (value < counter_max) m |= poll_out | wrnorm;
        },
        // An epoll set inside a `poll` is not emulated: the caller makes
        // the call a stray before asking.
        .epoll => m |= poll_nval,
    }
    return m;
}

pub fn isEpoll(fd: i32) bool {
    const slot = slotOf(fd) orelse return false;
    return slot.kind == .epoll;
}

// --- epoll ----------------------------------------------------------------------

const epoll_et: u32 = 1 << 31;
const epoll_oneshot: u32 = 1 << 30;
/// `EPOLLWAKEUP`, `EPOLLEXCLUSIVE`: accepted, change nothing here.
const epoll_ignored: u32 = (1 << 29) | (1 << 28);
/// What is always reported, asked for or not.
const epoll_always: u32 = poll_err | poll_hup;

const EpollEvent = extern struct { events: u32 align(1), data: u64 align(1) };

fn epollCreate(s: *Sim, flags: u32) ?u64 {
    if (flags & ~@as(u32, o_cloexec) != 0) return fail(.INVAL);
    const index = for (&epolls, 0..) |*e, i| {
        if (!e.used) break i;
    } else return fail(.MFILE);
    const i = take(s, .epoll) orelse return fail(.MFILE);
    slots[i].object = @intCast(index);
    epolls[index] = .{ .used = true, .holders = 1 };
    epoll_count += 1;
    return @intCast(fdOf(i));
}

fn epollCtl(s: *Sim, slot: *Slot, op: u32, fd: i32, event_ptr: u64) ?u64 {
    if (slot.kind != .epoll) return fail(.INVAL);
    const e = &epolls[slot.object];
    // What may be in a set: a socket, a pipe, an eventfd.
    switch (sysemu.descriptorKind(s, fd)) {
        .real => return null,
        .closed => return fail(.BADF),
        .file => return fail(.PERM),
        .pollable => {},
    }
    // Itself: Linux says EINVAL. Another set: nesting is not emulated.
    if (slotOf(fd)) |other| if (other.kind == .epoll) return if (other.object == slot.object) fail(.INVAL) else null;
    const at: ?usize = for (e.entries[0..e.len], 0..) |entry, i| {
        if (entry.fd == fd) break i;
    } else null;
    switch (op) {
        1, 3 => { // EPOLL_CTL_ADD, EPOLL_CTL_MOD
            if (event_ptr == 0) return fail(.FAULT);
            const ev: *const EpollEvent = @ptrFromInt(event_ptr);
            const entry: Entry = .{ .fd = fd, .events = ev.events & ~epoll_ignored, .data = ev.data };
            if (op == 1) {
                if (at != null) return fail(.EXIST);
                if (e.len == interest_max) return fail(.NOSPC);
                e.entries[e.len] = entry;
                e.len += 1;
            } else {
                e.entries[at orelse return fail(.NOENT)] = entry;
            }
            // A waiter sees the new interest.
            s.wakeNetwork();
            return 0;
        },
        2 => { // EPOLL_CTL_DEL
            const i = at orelse return fail(.NOENT);
            e.len -= 1;
            e.entries[i] = e.entries[e.len];
            return 0;
        },
        else => return fail(.INVAL),
    }
}

fn epollWait(s: *Sim, slot: *Slot, events_ptr: u64, max_events: u64, deadline: ?u64) ?u64 {
    if (slot.kind != .epoll) return fail(.INVAL);
    const max: i32 = @bitCast(@as(u32, @truncate(max_events)));
    if (max <= 0) return fail(.INVAL);
    if (events_ptr == 0) return fail(.FAULT);
    const out_events = @as([*]EpollEvent, @ptrFromInt(events_ptr))[0..@intCast(max)];
    const gen = slot.gen;
    const e = &epolls[slot.object];
    while (true) {
        // Something may have arrived on a socket since the last scan: the
        // network changed, or time passed (a delivery is due at a time).
        const maybe_arrived = e.seen_ns != s.now_ns or e.seen_changes != net_changes;
        e.seen_ns = s.now_ns;
        e.seen_changes = net_changes;
        var n: usize = 0;
        const len: usize = e.len;
        const begin: usize = if (len == 0) 0 else e.rotor % len;
        for (0..len) |step| {
            const i = (begin + step) % len;
            const entry = &e.entries[i];
            const mask: u32 = sysemu.descriptorMask(s, entry.fd);
            // What is not ready now is an edge when it next is.
            entry.armed |= ~mask;
            if (maybe_arrived and sysnet.isSocketFd(entry.fd)) entry.armed = ~@as(u32, 0);
            if (entry.disabled or n == out_events.len) continue;
            var ready = mask & ((entry.events & 0xFFFF) | epoll_always);
            if (entry.events & epoll_et != 0) ready &= entry.armed;
            if (ready == 0) continue;
            entry.armed &= ~ready;
            if (entry.events & epoll_oneshot != 0) entry.disabled = true;
            out_events[n] = .{ .events = ready, .data = entry.data };
            n += 1;
            // The next scan begins after the last one reported.
            e.rotor = @intCast((i + 1) % len);
        }
        if (n > 0) return n;
        if (deadline) |d| if (s.now_ns >= d) return 0;
        // Wake for the next network event too: a delivery due later.
        var until = deadline;
        if (s.net.nextEventAfter(s.now_ns)) |t| until = if (until) |d| @min(d, t) else t;
        s.waitNetwork(until) catch return fail(.INTR);
        // Closed by another task while this one waited.
        if (slot.gen != gen) return fail(.BADF);
    }
}
