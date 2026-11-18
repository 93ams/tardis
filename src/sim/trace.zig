//! Rolling trace hash and bounded recent-event ring (plan §3, §7.2).
//!
//! Every simulator-visible event is folded into a Wyhash-based rolling hash.
//! The hash covers virtual time, task id, event kind and integer arguments,
//! never host pointers, so it is comparable across runs and hosts.

const std = @import("std");
const assert = std.debug.assert;

pub const Kind = enum(u8) {
    spawn,
    finish,
    switch_to,
    sleep,
    wake,
    futex_wait,
    futex_wake,
    cancel,
    clock_advance,
    random,
    open,
    create,
    close,
    read,
    write,
    sync,
    set_length,
    stat,
    delete,
    rename,
    mkdir,
    fault,
    crash,
    oom,
    assertion,
    deadlock,
    note,
    net_listen,
    net_connect,
    net_accept,
    net_read,
    net_write,
    net_close,
    net_shutdown,
    net_fault,
    link,
    node_crash,
    node_spawn,
    clock_step,
    lock,
    dir_read,
    net_bind,
    net_send,
    net_receive,
    fs_link,
    decision,
    chmod,
};

pub const Event = struct {
    time_ns: u64,
    task: u16,
    kind: Kind,
    a: u64,
    b: u64,
    c: u64,
    /// Short inline label (path or assertion name), truncated.
    label: [label_bytes_max]u8,
    label_len: u8,
};

pub const label_bytes_max = 40;

pub const Trace = struct {
    hash: u64,
    count: u64,
    ring: []Event,
    ring_next: usize,

    pub fn init(ring: []Event) Trace {
        return .{ .hash = 0, .count = 0, .ring = ring, .ring_next = 0 };
    }

    pub fn reset(t: *Trace) void {
        t.hash = 0;
        t.count = 0;
        t.ring_next = 0;
    }

    pub fn record(t: *Trace, time_ns: u64, task: u16, kind: Kind, a: u64, b: u64, c: u64, label: []const u8) void {
        var words = [_]u64{ time_ns, task, @backingInt(kind), a, b, c };
        var h = std.hash.Wyhash.init(t.hash);
        h.update(std.mem.sliceAsBytes(&words));
        h.update(label);
        t.hash = h.final();
        t.count += 1;

        if (t.ring.len == 0) return;
        const e = &t.ring[t.ring_next];
        const n: u8 = @intCast(@min(label.len, label_bytes_max));
        e.* = .{
            .time_ns = time_ns,
            .task = task,
            .kind = kind,
            .a = a,
            .b = b,
            .c = c,
            .label = undefined,
            .label_len = n,
        };
        @memcpy(e.label[0..n], label[0..n]);
        t.ring_next = (t.ring_next + 1) % t.ring.len;
    }

    /// Writes the events in the ring, oldest first, as a Chrome trace
    /// (the JSON array form, which Perfetto and `chrome://tracing` open):
    /// one instant event per simulator event, on a track per task, at its
    /// virtual time. The arguments are the event's three integers and its
    /// label.
    pub fn writeChromeTrace(t: *const Trace, w: *std.Io.Writer) !void {
        try w.writeAll("[");
        const stored: usize = @intCast(@min(t.count, t.ring.len));
        var i: usize = 0;
        while (i < stored) : (i += 1) {
            const e = &t.ring[(t.ring_next + t.ring.len - stored + i) % t.ring.len];
            if (i > 0) try w.writeAll(",");
            // `ts` is in microseconds.
            try w.print("\n{{\"name\":\"{t}\",\"ph\":\"i\",\"s\":\"t\",\"pid\":0,\"tid\":{d},\"ts\":{d}.{d:0>3},\"args\":{{\"a\":{d},\"b\":{d},\"c\":{d},\"label\":\"", .{
                e.kind, e.task, e.time_ns / 1000, e.time_ns % 1000, e.a, e.b, e.c,
            });
            for (e.label[0..e.label_len]) |ch| switch (ch) {
                '"', '\\' => try w.print("\\{c}", .{ch}),
                0...0x1f, 0x7f...0xff => try w.print("\\u{x:0>4}", .{ch}),
                else => try w.writeByte(ch),
            };
            try w.writeAll("\"}}");
        }
        try w.writeAll("\n]\n");
    }

    /// Prints the last `max` events in chronological order.
    pub fn dump(t: *const Trace, max: usize) void {
        if (t.ring.len == 0) return;
        const stored: usize = @intCast(@min(t.count, t.ring.len));
        const n = @min(stored, max);
        std.debug.print("tardis: last {d} events (virtual time, task, event):\n", .{n});
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const idx = (t.ring_next + t.ring.len - n + i) % t.ring.len;
            const e = &t.ring[idx];
            const s = e.time_ns / std.time.ns_per_s;
            const frac = e.time_ns % std.time.ns_per_s;
            std.debug.print("  {d}.{d:0>9}s  t{d: <3} {s: <13} {d} {d} {d}  {s}\n", .{
                s, frac, e.task, @tagName(e.kind), e.a, e.b, e.c, e.label[0..e.label_len],
            });
        }
    }
};

test "trace hash depends on order and content" {
    var ring_a: [4]Event = undefined;
    var ring_b: [4]Event = undefined;
    var a = Trace.init(&ring_a);
    var b = Trace.init(&ring_b);
    a.record(1, 0, .write, 1, 2, 3, "x");
    a.record(2, 0, .read, 1, 2, 3, "y");
    b.record(2, 0, .read, 1, 2, 3, "y");
    b.record(1, 0, .write, 1, 2, 3, "x");
    try std.testing.expect(a.hash != b.hash);

    var ring_c: [4]Event = undefined;
    var c = Trace.init(&ring_c);
    c.record(1, 0, .write, 1, 2, 3, "x");
    c.record(2, 0, .read, 1, 2, 3, "y");
    try std.testing.expectEqual(a.hash, c.hash);
}

test "chrome trace: one instant event per ring entry, oldest first, with escaped labels" {
    var ring: [2]Event = undefined;
    var t = Trace.init(&ring);
    t.record(1_500, 0, .note, 0, 0, 0, "dropped");
    t.record(2_000_250, 3, .write, 7, 8, 9, "a\"b\\c");
    t.record(3_000_000, 1, .sleep, 5, 0, 0, "");
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try t.writeChromeTrace(&w);
    try std.testing.expectEqualStrings(
        \\[
        \\{"name":"write","ph":"i","s":"t","pid":0,"tid":3,"ts":2000.250,"args":{"a":7,"b":8,"c":9,"label":"a\"b\\c"}},
        \\{"name":"sleep","ph":"i","s":"t","pid":0,"tid":1,"ts":3000.000,"args":{"a":5,"b":0,"c":0,"label":""}}
        \\]
        \\
    , w.buffered());
}

test "ring wraps" {
    var ring: [2]Event = undefined;
    var t = Trace.init(&ring);
    t.record(1, 0, .note, 0, 0, 0, "a");
    t.record(2, 0, .note, 0, 0, 0, "b");
    t.record(3, 0, .note, 0, 0, 0, "c");
    try std.testing.expectEqual(@as(u64, 3), t.count);
    try std.testing.expectEqual(@as(u64, 3), ring[0].time_ns);
}
