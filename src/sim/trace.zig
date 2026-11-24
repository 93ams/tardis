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

/// Labels up to this long are hashed in one call with the event's words;
/// longer ones (rare: long paths) through the streaming interface.
const inline_label_max = 256;

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
        // The hash of the event's six words followed by its label. One call
        // of `Wyhash.hash` over the bytes gives the value its streaming
        // interface gives (`init`, `update`, `final`), for about half the
        // work, which matters: this runs for every event (plan3.md E6).
        const words_bytes = 6 * @sizeOf(u64);
        var bytes: [words_bytes + inline_label_max]u8 align(@alignOf(u64)) = undefined;
        const words: *[6]u64 = @ptrCast(&bytes);
        words.* = .{ time_ns, task, @backingInt(kind), a, b, c };
        if (label.len <= inline_label_max) {
            @memcpy(bytes[words_bytes..][0..label.len], label);
            t.hash = std.hash.Wyhash.hash(t.hash, bytes[0 .. words_bytes + label.len]);
        } else {
            var h = std.hash.Wyhash.init(t.hash);
            h.update(bytes[0..words_bytes]);
            h.update(label);
            t.hash = h.final();
        }
        t.count += 1;

        if (t.ring.len == 0) return;
        const e = &t.ring[t.ring_next];
        const n: u8 = @intCast(@min(label.len, label_bytes_max));
        e.time_ns = time_ns;
        e.task = task;
        e.kind = kind;
        e.a = a;
        e.b = b;
        e.c = c;
        e.label_len = n;
        @memcpy(e.label[0..n], label[0..n]);
        t.ring_next += 1;
        if (t.ring_next == t.ring.len) t.ring_next = 0;
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

    /// The event with number `index` (the run's first is 0), if the ring
    /// still holds it.
    fn at(t: *const Trace, index: u64) ?*const Event {
        const stored: u64 = @min(t.count, t.ring.len);
        if (index >= t.count or index < t.count - stored) return null;
        const back: usize = @intCast(t.count - index);
        return &t.ring[(t.ring_next + t.ring.len - back) % t.ring.len];
    }

    fn same(x: *const Event, y: *const Event) bool {
        return x.time_ns == y.time_ns and x.task == y.task and x.kind == y.kind and x.a == y.a and x.b == y.b and x.c == y.c and
            std.mem.eql(u8, x.label[0..x.label_len], y.label[0..y.label_len]);
    }

    fn printEvent(prefix: []const u8, e: *const Event) void {
        std.debug.print("{s}{d}.{d:0>9}s  t{d: <3} {s: <13} {d} {d} {d}  {s}\n", .{
            prefix, e.time_ns / std.time.ns_per_s, e.time_ns % std.time.ns_per_s, e.task, @tagName(e.kind), e.a, e.b, e.c, e.label[0..e.label_len],
        });
    }

    /// Two runs of one seed gave two traces: prints the first event at
    /// which they part, with the few before it that they share. The two
    /// must not share a ring. When they part before what the rings still
    /// hold, says so.
    pub fn dumpDivergence(first: *const Trace, second: *const Trace) void {
        const from = @max(first.count - @min(first.count, first.ring.len), second.count - @min(second.count, second.ring.len));
        const to = @min(first.count, second.count);
        // What both rings still hold: nothing, when one run is longer
        // than the other by more than a ring.
        var i = from;
        while (i < to) : (i += 1) {
            if (!same(first.at(i).?, second.at(i).?)) break;
        }
        // The first event kept differs, or every one kept is the same,
        // and events before them were dropped: the runs parted there.
        if (from > 0 and (i == from or (i >= to and first.count == second.count))) {
            std.debug.print("tardis: the two runs ({d} and {d} events) part before the events that are kept: raise Options.limits.trace_ring_len ({d}) to see where\n", .{ first.count, second.count, first.ring.len });
            return;
        }
        if (i == to and first.count == second.count) {
            std.debug.print("tardis: the two runs have the same {d} events and end differently (another result, another leak, or a label that differs past its first {d} bytes)\n", .{ to, label_bytes_max });
            return;
        }
        std.debug.print("tardis: the two runs agree for {d} events (virtual time, task, event):\n", .{i});
        var k = i - @min(i - from, 4);
        while (k < i) : (k += 1) printEvent("    ", first.at(k).?);
        if (first.at(i)) |e| printEvent("  first run:   ", e) else std.debug.print("  first run:   ends here\n", .{});
        if (second.at(i)) |e| printEvent("  second run:  ", e) else std.debug.print("  second run:  ends here\n", .{});
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

test "the first event at which two traces part is found, in a ring that has wrapped too" {
    var ring_a: [4]Event = undefined;
    var ring_b: [4]Event = undefined;
    var a = Trace.init(&ring_a);
    var b = Trace.init(&ring_b);
    for (0..6) |i| {
        a.record(i, 0, .write, i, 0, 0, "x");
        b.record(i, 0, .write, if (i == 4) 99 else i, 0, 0, "x");
    }
    // Events 2 to 5 are kept; 4 is the first that differs.
    try std.testing.expect(a.at(1) == null and a.at(6) == null);
    try std.testing.expectEqual(@as(u64, 2), a.at(2).?.a);
    try std.testing.expectEqual(@as(u64, 5), a.at(5).?.a);
    try std.testing.expect(Trace.same(a.at(3).?, b.at(3).?));
    try std.testing.expect(!Trace.same(a.at(4).?, b.at(4).?));
    a.dumpDivergence(&b);
    // One run longer than the other by more than a ring (found by review:
    // the count of shared events underflowed), and two that differ only
    // in what the ring dropped.
    var c = Trace.init(&ring_b);
    c.record(0, 0, .write, 0, 0, 0, "x");
    a.dumpDivergence(&c);
    c.dumpDivergence(&a);
    var d = Trace.init(&ring_b);
    for (0..6) |i| d.record(i, 0, .write, if (i == 0) 99 else i, 0, 0, "x");
    a.dumpDivergence(&d);
}

test "trace hash: a long label is hashed as a short one is" {
    // The one call and the streaming fallback give the hash of the words
    // followed by the label, whatever its length.
    var label: [inline_label_max + 50]u8 = undefined;
    for (&label, 0..) |*x, i| x.* = @truncate(i *% 7 +% 3);
    for ([_]usize{ 0, 1, 16, 40, inline_label_max, inline_label_max + 1, label.len }) |n| {
        var t = Trace.init(&.{});
        t.hash = 0x1234;
        t.record(5, 2, .write, 7, 8, 9, label[0..n]);
        var h = std.hash.Wyhash.init(0x1234);
        const words = [_]u64{ 5, 2, @backingInt(Kind.write), 7, 8, 9 };
        h.update(std.mem.sliceAsBytes(&words));
        h.update(label[0..n]);
        try std.testing.expectEqual(h.final(), t.hash);
    }
}

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
