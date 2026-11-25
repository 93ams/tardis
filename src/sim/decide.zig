//! Deterministic decision source (plan §5.1).
//!
//! Every simulator choice draws from one of several independent streams so
//! that adding draws in one subsystem does not perturb another. The generator
//! is implemented here (SplitMix64) rather than taken from `std.Random`, so the
//! decision sequence for a seed never changes with Zig releases.

const std = @import("std");
const assert = std.debug.assert;

/// Parts per million, `0..1_000_000`.
pub const Ppm = u32;
pub const ppm_one: Ppm = 1_000_000;

pub const Stream = enum(u8) {
    schedule,
    fault,
    crash,
    latency,
    random,
    fuzz,
    alloc,
    swarm,
    net,
    clock,
};

const stream_count = @typeInfo(Stream).@"enum".field_names.len;

pub const golden_gamma: u64 = 0x9e3779b97f4a7c15;

pub fn splitmix64(x: u64) u64 {
    var z = x +% golden_gamma;
    z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
    return z ^ (z >> 31);
}

/// Mixes two words into one (used for deriving run seeds).
pub fn mix(a: u64, b: u64) u64 {
    return splitmix64(a ^ splitmix64(b));
}

/// Per-task decision addressing (plan §9 M3). A draw made while a context
/// is installed is keyed by `(stream, task spawn path, per-task per-stream
/// counter)` and its value derived from the key, so changing one decision
/// shifts only the later decisions of the same task and stream.
pub const KeyContext = struct {
    path: u64,
    counters: [stream_count]u32,
    /// `keyPrefix(stream, path)` for each stream, filled at the stream's
    /// first draw (0: not yet). It depends only on `path`, so it is not
    /// part of the context's identity (`eql`).
    prefixes: [stream_count]u64 = @splat(0),

    pub const root: KeyContext = .{ .path = 0, .counters = @splat(0) };

    /// Same task path and counters (the cached prefixes aside).
    pub fn eql(a: *const KeyContext, b: *const KeyContext) bool {
        return a.path == b.path and std.mem.eql(u32, &a.counters, &b.counters);
    }

    fn prefix(c: *KeyContext, stream: Stream) u64 {
        const p = &c.prefixes[@backingInt(stream)];
        if (p.* == 0) p.* = keyPrefix(stream, c.path);
        return p.*;
    }

    /// Context for the `index`-th task spawned by a task with this context.
    pub fn child(parent: *const KeyContext, index: u32) KeyContext {
        return .{ .path = mix(parent.path, @as(u64, index) +% 1), .counters = @splat(0) };
    }
};

pub const Forced = struct { key: u64, value: u64 };

/// What a run's keyed draws return instead of their natural value.
///
/// * `keep` (shrinking): when set, only these decisions keep their natural
///   value; every other keyed draw returns 0, the benign outcome (no fault,
///   no preemption, minimal latency, everything survives a crash, smallest
///   fuzz value). Sorted.
/// * `forced` (guided exploration): these decisions return the given raw
///   value instead (if kept). Sorted by key.
pub const Overlay = struct {
    keep: ?[]const u64 = null,
    forced: []const Forced = &.{},

    /// True if `key` may take a non-zero value.
    pub fn contains(o: *const Overlay, key: u64) bool {
        const keep = o.keep orelse return true;
        var lo: usize = 0;
        var hi: usize = keep.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (keep[mid] == key) return true;
            if (keep[mid] < key) lo = mid + 1 else hi = mid;
        }
        return false;
    }

    pub fn forcedValue(o: *const Overlay, key: u64) ?u64 {
        var lo: usize = 0;
        var hi: usize = o.forced.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (o.forced[mid].key == key) return o.forced[mid].value;
            if (o.forced[mid].key < key) lo = mid + 1 else hi = mid;
        }
        return null;
    }
};

/// Records the keys of keyed draws whose natural value was used.
pub const Recorder = struct {
    keys: []u64,
    /// When set (same length as `keys`), the value each draw returned.
    values: ?[]u64 = null,
    len: usize,
    overflowed: bool,

    pub fn init(buffer: []u64) Recorder {
        return .{ .keys = buffer, .len = 0, .overflowed = false };
    }

    pub fn initWithValues(keys: []u64, values: []u64) Recorder {
        assert(keys.len == values.len);
        return .{ .keys = keys, .values = values, .len = 0, .overflowed = false };
    }

    pub fn add(r: *Recorder, key: u64, value: u64) void {
        if (r.len == r.keys.len) {
            r.overflowed = true;
            return;
        }
        r.keys[r.len] = key;
        if (r.values) |v| v[r.len] = value;
        r.len += 1;
    }
};

/// The (stream, task) pairs a run drew from, each with how many draws it
/// made and the stream's state: what a decision key can be resolved
/// against when a replay token no longer fits the code (fuzzy replay).
pub const Anchors = struct {
    pub const Anchor = struct {
        stream: Stream,
        path: u64,
        /// Draws made: the counters 0 to `draws - 1` exist.
        draws: u32,
        /// The stream's state at the last draw (a key's natural value is
        /// `splitmix64(state ^ key)`).
        state: u64,
    };

    items: []Anchor,
    len: usize = 0,
    overflowed: bool = false,
    last: usize = 0,

    pub fn init(buffer: []Anchor) Anchors {
        return .{ .items = buffer };
    }

    pub fn slice(a: *const Anchors) []const Anchor {
        return a.items[0..a.len];
    }

    fn note(a: *Anchors, stream: Stream, path: u64, counter: u32, state: u64) void {
        if (a.len > 0) {
            const l = &a.items[a.last];
            if (l.stream != stream or l.path != path) {
                a.last = for (a.items[0..a.len], 0..) |x, i| {
                    if (x.stream == stream and x.path == path) break i;
                } else a.len;
            }
        }
        if (a.last == a.len) {
            if (a.len == a.items.len) {
                a.overflowed = true;
                a.last = 0;
                return;
            }
            a.items[a.len] = .{ .stream = stream, .path = path, .draws = 0, .state = state };
            a.len += 1;
        }
        const x = &a.items[a.last];
        x.draws = @max(x.draws, counter +% 1);
        x.state = state;
    }

    pub const Resolved = struct { anchor: u32, counter: u32 };

    /// The (anchor, counter) whose key is `key`, searching each anchor's
    /// counters up to `slack` past the draws it made.
    pub fn resolve(a: *const Anchors, key: u64, slack: u32) ?Resolved {
        for (a.slice(), 0..) |x, i| {
            var c: u32 = 0;
            while (c < x.draws + slack) : (c += 1) {
                if (decisionKey(x.stream, x.path, c) == key) return .{ .anchor = @intCast(i), .counter = c };
            }
        }
        return null;
    }
};

/// How a keyed draw was used, so bounded exhaustive exploration can force
/// each of its outcomes (`valueFor`).
pub const DomainKind = enum(u8) {
    /// `chance`: false or true.
    chance,
    /// `boolean`: false or true.
    boolean,
    /// `uniform(n)` (and `range`): `outcomes` values.
    uniform,
    /// `next`/`fill`: the raw 64-bit value; not enumerable.
    raw,
};

pub const Domain = struct {
    key: u64,
    kind: DomainKind,
    /// Number of outcomes (2 for chance and boolean; 0 for raw).
    outcomes: u64,
};

/// The raw value that makes a draw of `kind` produce outcome `k`.
pub fn valueFor(kind: DomainKind, outcomes: u64, k: u64) u64 {
    assert(k < outcomes);
    return switch (kind) {
        .chance => if (k == 0) 0 else std.math.maxInt(u64),
        .boolean => k,
        .uniform => @intCast(((@as(u128, k) << 64) + outcomes - 1) / outcomes),
        .raw => unreachable,
    };
}

/// Keyed draws of a run with their domains, in order.
pub const DomainLog = struct {
    entries: []Domain,
    len: usize = 0,
    overflowed: bool = false,

    pub fn init(buffer: []Domain) DomainLog {
        return .{ .entries = buffer };
    }

    fn add(l: *DomainLog, d: Domain) void {
        if (l.len == l.entries.len) {
            l.overflowed = true;
            return;
        }
        l.entries[l.len] = d;
        l.len += 1;
    }

    pub fn slice(l: *const DomainLog) []const Domain {
        return l.entries[0..l.len];
    }
};

pub const Hook = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, stream: Stream, key: u64, forced: bool) void,
};

/// Called for every keyed draw with the value it returned.
pub const DrawHook = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, stream: Stream, key: u64, value: u64) void,
};

pub fn decisionKey(stream: Stream, path: u64, counter: u32) u64 {
    return mix(keyPrefix(stream, path), counter);
}

/// The part of a decision key that depends only on the stream and the task.
fn keyPrefix(stream: Stream, path: u64) u64 {
    return mix(@as(u64, @backingInt(stream)) + 1, path);
}

test "a key context's cached prefix gives the key decisionKey gives" {
    var c = KeyContext.root.child(3);
    for (0..stream_count) |i| {
        const stream: Stream = @fromBackingInt(@intCast(i));
        for (0..3) |counter| {
            try std.testing.expectEqual(decisionKey(stream, c.path, @intCast(counter)), mix(c.prefix(stream), @intCast(counter)));
        }
    }
    var fresh = KeyContext.root.child(3);
    try std.testing.expect(fresh.eql(&c));
    fresh.counters[1] = 1;
    try std.testing.expect(!fresh.eql(&c));
}

pub const Decider = struct {
    state: [stream_count]u64,
    ctx: ?*KeyContext = null,
    overlay: ?*const Overlay = null,
    recorder: ?*Recorder = null,
    /// Called for each natural-valued draw while an overlay is installed
    /// (so shrunk and replayed runs can show their decisions in the trace).
    on_natural: ?Hook = null,
    /// Keyed draws made this run (for reports).
    keyed_draws: u64 = 0,
    /// Bounded exhaustive exploration: every keyed draw with its domain.
    domain_log: ?*DomainLog = null,
    /// Fuzzy replay: which (stream, task) pairs drew, and how often.
    anchors: ?*Anchors = null,
    /// Exhaustive exploration with state merging: every keyed draw.
    on_draw: ?DrawHook = null,
    /// Key of the last keyed draw.
    last_key: u64 = 0,

    pub fn init(seed: u64) Decider {
        var d: Decider = .{ .state = undefined };
        for (&d.state, 0..) |*s, i| {
            s.* = mix(seed, 0x7a7d_1500 + @as(u64, i));
        }
        return d;
    }

    /// Re-derives every stream from `seed`, keeping the key contexts, so the
    /// run continues with fresh values (end of a deterministic setup phase).
    pub fn reseed(d: *Decider, seed: u64) void {
        for (&d.state, 0..) |*s, i| s.* = mix(seed, 0x7a7d_1500 + @as(u64, i));
    }

    fn logDomain(d: *Decider, kind: DomainKind, outcomes: u64) void {
        if (d.ctx == null) return;
        const l = d.domain_log orelse return;
        l.add(.{ .key = d.last_key, .kind = kind, .outcomes = outcomes });
    }

    pub fn next(d: *Decider, stream: Stream) u64 {
        const v = d.nextRaw(stream);
        d.logDomain(.raw, 0);
        return v;
    }

    fn nextRaw(d: *Decider, stream: Stream) u64 {
        const s = &d.state[@backingInt(stream)];
        if (d.ctx) |c| {
            const counter = c.counters[@backingInt(stream)];
            c.counters[@backingInt(stream)] = counter +% 1;
            d.keyed_draws += 1;
            const key = mix(c.prefix(stream), counter);
            d.last_key = key;
            if (d.anchors) |a| a.note(stream, c.path, counter, s.*);
            if (d.overlay) |o| {
                if (!o.contains(key)) {
                    if (d.on_draw) |h| h.f(h.ctx, stream, key, 0);
                    return 0;
                }
                if (o.forcedValue(key)) |v| {
                    if (d.recorder) |r| r.add(key, v);
                    if (d.on_natural) |h| h.f(h.ctx, stream, key, true);
                    if (d.on_draw) |h| h.f(h.ctx, stream, key, v);
                    return v;
                }
                const v = splitmix64(s.* ^ key);
                if (d.recorder) |r| r.add(key, v);
                // Show natural decisions only when the run is restricted (shrunk).
                if (o.keep != null) if (d.on_natural) |h| h.f(h.ctx, stream, key, false);
                if (d.on_draw) |h| h.f(h.ctx, stream, key, v);
                return v;
            }
            const v = splitmix64(s.* ^ key);
            if (d.recorder) |r| r.add(key, v);
            if (d.on_draw) |h| h.f(h.ctx, stream, key, v);
            return v;
        }
        s.* +%= golden_gamma;
        var z = s.*;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }

    /// Uniform in `[0, n)`; `n` must be non-zero. Lemire multiply-shift.
    pub fn uniform(d: *Decider, stream: Stream, n: u64) u64 {
        const r = d.uniformRaw(stream, n);
        d.logDomain(.uniform, n);
        return r;
    }

    fn uniformRaw(d: *Decider, stream: Stream, n: u64) u64 {
        assert(n > 0);
        const wide: u128 = @as(u128, d.nextRaw(stream)) * @as(u128, n);
        const r: u64 = @intCast(wide >> 64);
        assert(r < n);
        return r;
    }

    /// Uniform in `[lo, hi]` inclusive.
    pub fn range(d: *Decider, stream: Stream, lo: u64, hi: u64) u64 {
        assert(lo <= hi);
        if (hi - lo == std.math.maxInt(u64)) return d.next(stream);
        return lo + d.uniform(stream, hi - lo + 1);
    }

    pub fn chance(d: *Decider, stream: Stream, p: Ppm) bool {
        assert(p <= ppm_one);
        if (p == 0) return false;
        if (p == ppm_one) return true;
        const r = d.uniformRaw(stream, ppm_one) >= ppm_one - p;
        d.logDomain(.chance, 2);
        return r;
    }

    pub fn boolean(d: *Decider, stream: Stream) bool {
        const r = d.nextRaw(stream) & 1 == 1;
        d.logDomain(.boolean, 2);
        return r;
    }

    pub fn fill(d: *Decider, stream: Stream, buffer: []u8) void {
        var i: usize = 0;
        while (i < buffer.len) {
            const word = d.next(stream);
            const n = @min(8, buffer.len - i);
            const bytes = std.mem.asBytes(&std.mem.nativeToLittle(u64, word));
            @memcpy(buffer[i..][0..n], bytes[0..n]);
            i += n;
        }
    }
};

test "anchors resolve a key to its stream, task and counter" {
    var buf: [4]Anchors.Anchor = undefined;
    var a = Anchors.init(&buf);
    var d = Decider.init(7);
    var root: KeyContext = .root;
    var child = root.child(0);
    d.anchors = &a;
    d.ctx = &root;
    _ = d.next(.fuzz);
    _ = d.next(.fuzz);
    d.ctx = &child;
    _ = d.next(.fault);
    d.ctx = &root;
    _ = d.next(.fuzz);
    try std.testing.expectEqual(@as(usize, 2), a.len);
    try std.testing.expectEqual(@as(u32, 3), a.slice()[0].draws);
    const r = a.resolve(decisionKey(.fuzz, root.path, 2), 0).?;
    try std.testing.expectEqual(@as(u32, 0), r.anchor);
    try std.testing.expectEqual(@as(u32, 2), r.counter);
    // A counter the run did not reach resolves only within the slack.
    try std.testing.expectEqual(@as(?Anchors.Resolved, null), a.resolve(decisionKey(.fault, child.path, 3), 2));
    try std.testing.expectEqual(@as(u32, 3), a.resolve(decisionKey(.fault, child.path, 3), 3).?.counter);
}

test "streams are independent" {
    var a = Decider.init(42);
    var b = Decider.init(42);
    // Draw extra values from one stream only in `b`.
    _ = b.next(.fuzz);
    _ = b.next(.fuzz);
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        try std.testing.expectEqual(a.next(.schedule), b.next(.schedule));
    }
}

test "same seed same sequence, different seed different sequence" {
    var a = Decider.init(1);
    var b = Decider.init(1);
    var c = Decider.init(2);
    var differ = false;
    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        const x = a.next(.fault);
        try std.testing.expectEqual(x, b.next(.fault));
        if (x != c.next(.fault)) differ = true;
    }
    try std.testing.expect(differ);
}

test "golden values are stable across releases" {
    // If this test fails, replay seeds from older TARDIS versions are invalid.
    var d = Decider.init(0x517cc1b727220a95);
    const first = d.next(.schedule);
    var e = Decider.init(0x517cc1b727220a95);
    try std.testing.expectEqual(first, e.next(.schedule));
    try std.testing.expectEqual(@as(u64, 0xe220a8397b1dcdaf), splitmix64(0));
}

test "uniform and chance bounds" {
    var d = Decider.init(7);
    var hits: u32 = 0;
    var i: u32 = 0;
    while (i < 10_000) : (i += 1) {
        try std.testing.expect(d.uniform(.schedule, 3) < 3);
        try std.testing.expect(d.range(.schedule, 5, 9) >= 5);
        if (d.chance(.fault, 500_000)) hits += 1;
    }
    try std.testing.expect(hits > 4_000 and hits < 6_000);
    try std.testing.expect(!d.chance(.fault, 0));
    try std.testing.expect(d.chance(.fault, ppm_one));
}

test "keyed draws: one task's decisions do not shift another's" {
    var a = Decider.init(9);
    var b = Decider.init(9);
    var t1a: KeyContext = KeyContext.root.child(0);
    var t2a: KeyContext = KeyContext.root.child(1);
    var t1b = t1a;
    var t2b = t2a;
    // In `b`, task 1 draws extra values first.
    b.ctx = &t1b;
    _ = b.next(.fault);
    _ = b.next(.fault);
    a.ctx = &t2a;
    b.ctx = &t2b;
    for (0..20) |_| try std.testing.expectEqual(a.next(.fault), b.next(.fault));
    a.ctx = &t1a;
    _ = a.next(.fault);
}

test "overlay: unlisted keyed draws are zero, listed ones natural" {
    var d = Decider.init(3);
    var ctx = KeyContext.root;
    d.ctx = &ctx;
    const natural0 = d.next(.fault);
    const natural1 = d.next(.fault);
    var keep = [_]u64{decisionKey(.fault, 0, 1)};
    const o: Overlay = .{ .keep = &keep };
    var ctx2 = KeyContext.root;
    var e = Decider.init(3);
    e.ctx = &ctx2;
    e.overlay = &o;
    try std.testing.expectEqual(@as(u64, 0), e.next(.fault));
    try std.testing.expectEqual(natural1, e.next(.fault));
    try std.testing.expect(natural0 != 0);
    // Zero is the benign outcome for every helper.
    try std.testing.expect(!e.chance(.fault, 999_999));
    try std.testing.expectEqual(@as(u64, 5), e.range(.latency, 5, 100));
    try std.testing.expect(!e.boolean(.crash));
}

test "valueFor forces every outcome" {
    var k: u64 = 0;
    while (k < 5) : (k += 1) {
        const v = valueFor(.uniform, 5, k);
        try std.testing.expectEqual(k, @as(u64, @intCast((@as(u128, v) * 5) >> 64)));
    }
    var root = KeyContext.root;
    var log_buf: [4]Domain = undefined;
    var log = DomainLog.init(&log_buf);
    var d = Decider.init(3);
    d.ctx = &root;
    d.domain_log = &log;
    _ = d.chance(.fault, 10);
    _ = d.boolean(.fault);
    _ = d.uniform(.schedule, 3);
    _ = d.next(.fuzz);
    _ = d.chance(.fault, 0); // no draw
    try std.testing.expectEqual(@as(usize, 4), log.len);
    try std.testing.expectEqual(DomainKind.chance, log_buf[0].kind);
    try std.testing.expectEqual(@as(u64, 3), log_buf[2].outcomes);
    try std.testing.expectEqual(DomainKind.raw, log_buf[3].kind);
}
