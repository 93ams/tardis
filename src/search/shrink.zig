//! Failure shrinking (plan §9 M3).
//!
//! A failing run is described by its seed plus the set of decisions that
//! keep their natural value; every other decision takes the benign value 0
//! (see `decide.Overlay`). `Shrinker` removes decisions by delta debugging
//! (ddmin), then lowers the values of the ones left, re-executing the test
//! each time and keeping a candidate only when it fails with the same error.
//!
//! A replay token encodes `persona:seed:KEEP[:FORCED]` (see `formatToken`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const decide = @import("../sim/decide.zig");

/// Sorts `keys` and removes duplicates; returns the new length.
pub fn sortUnique(keys: []u64) usize {
    std.mem.sort(u64, keys, {}, std.sort.asc(u64));
    var out: usize = 0;
    for (keys, 0..) |k, i| {
        if (i > 0 and k == keys[out - 1]) continue;
        keys[out] = k;
        out += 1;
    }
    return out;
}

/// One run the shrinker wants executed: only `keep` take their natural
/// value (or `forced`'s), every other decision is benign. The run must
/// record its decisions into `recorder` (install it as `Sim.recorder`).
pub const Candidate = struct {
    keep: []const u64,
    forced: []const decide.Forced,
    recorder: *decide.Recorder,
};

/// A resumable shrinker: `next()` hands out the next candidate run,
/// `result()` takes back whether it failed the same way. Being a state
/// machine rather than a loop over a callback lets the caller own the run:
/// `check` calls the body itself, while `tardis.sim` hands each candidate to
/// the user's loop as one more iteration.
///
/// Phases:
/// 1. **All benign:** every decision 0.
/// 2. **ddmin** over the decisions of the failing run, re-executing each
///    candidate and accepting it when the run fails the same way. After each
///    success the set is narrowed to the decisions the reduced run actually
///    drew (decisions that stopped existing are dropped for free). The
///    decisions are kept in the order the run drew them, so a chunk is a
///    stretch of the run (a time window) and not a random sample of it:
///    keys are hashes, and sorted by key a chunk would hold decisions from
///    all over the run, which a failure with one cause seldom lets go.
/// 3. **Record** the reduced run's decision values.
/// 4. **Value shrinking**, per kept decision, by forcing it: first the
///    fewest low bits that still fail (fuzz integers truncate the raw value,
///    so this keeps them exact, while `uniform` draws keep the high bits
///    they read), then a binary search for the smallest raw value that
///    still fails. Smaller raw values always mean more benign outcomes, so
///    this lands on the boundary of the failure: the smallest input, the
///    shortest latency. Both searches assume monotonicity and find a local
///    minimum otherwise; every accepted step was a failing run.
pub const Shrinker = struct {
    gpa: Allocator,
    runs_max: u32,
    runs: u32 = 0,
    /// Decisions in the failing run.
    before: usize,
    /// Kept decisions whose value was lowered.
    lowered: usize = 0,
    state: State = .all_benign,

    /// The kept decisions: in draw order during ddmin, sorted afterwards.
    keep_buf: []u64,
    sorted: bool = false,
    len: usize,
    cand_buf: []u64,
    rec_keys: []u64,
    rec_values: []u64,
    rec: decide.Recorder = undefined,

    forced: []decide.Forced,
    forced_len: usize,
    cand_forced: []decide.Forced,
    cand_forced_len: usize = 0,

    // ddmin
    n: usize = 2,
    start: usize = 0,
    chunk: usize = 0,
    // values
    drawn_keys: []u64,
    drawn_values: []u64,
    drawn_len: usize = 0,
    vi: usize = 0,
    bits_lo: u32 = 0,
    bits_hi: u32 = 64,
    v: u64 = 0,
    vlo: u64 = 0,
    pending: u64 = 0,

    const State = enum { all_benign, ddmin, record, mask, bisect, done };

    /// `initial`: the decisions the failing run drew (with `base` forced).
    /// `decisions_max` bounds every recorded run.
    pub fn init(gpa: Allocator, initial: []const u64, base: []const decide.Forced, runs_max: u32, decisions_max: usize) !Shrinker {
        const cap = @max(@max(initial.len, decisions_max), 1);
        const keep_buf = try gpa.alloc(u64, cap);
        errdefer gpa.free(keep_buf);
        const cand_buf = try gpa.alloc(u64, cap);
        errdefer gpa.free(cand_buf);
        const rec_keys = try gpa.alloc(u64, cap);
        errdefer gpa.free(rec_keys);
        const rec_values = try gpa.alloc(u64, cap);
        errdefer gpa.free(rec_values);
        const drawn_keys = try gpa.alloc(u64, cap);
        errdefer gpa.free(drawn_keys);
        const drawn_values = try gpa.alloc(u64, cap);
        errdefer gpa.free(drawn_values);
        const forced = try gpa.alloc(decide.Forced, base.len + cap);
        errdefer gpa.free(forced);
        const cand_forced = try gpa.alloc(decide.Forced, base.len + cap);
        @memcpy(forced[0..base.len], base);
        const len = drawOrder(keep_buf, cand_buf, initial);
        return .{
            .gpa = gpa,
            .runs_max = runs_max,
            .before = len,
            .keep_buf = keep_buf,
            .len = len,
            .cand_buf = cand_buf,
            .rec_keys = rec_keys,
            .rec_values = rec_values,
            .forced = forced,
            .forced_len = base.len,
            .cand_forced = cand_forced,
            .drawn_keys = drawn_keys,
            .drawn_values = drawn_values,
        };
    }

    pub fn deinit(sh: *Shrinker) void {
        const gpa = sh.gpa;
        gpa.free(sh.keep_buf);
        gpa.free(sh.cand_buf);
        gpa.free(sh.rec_keys);
        gpa.free(sh.rec_values);
        gpa.free(sh.drawn_keys);
        gpa.free(sh.drawn_values);
        gpa.free(sh.forced);
        gpa.free(sh.cand_forced);
        sh.* = undefined;
    }

    /// The kept decisions, sorted (valid once `next` returned null).
    pub fn keep(sh: *const Shrinker) []const u64 {
        assert(sh.sorted or sh.len == 0);
        return sh.keep_buf[0..sh.len];
    }

    /// The forced decisions of the result: lowered values plus the base,
    /// minus any outside the kept set (never consulted). Sorted.
    pub fn forcedResult(sh: *Shrinker) []const decide.Forced {
        const probe: decide.Overlay = .{ .keep = sh.keep() };
        var n: usize = 0;
        for (sh.forced[0..sh.forced_len]) |f| {
            if (!probe.contains(f.key)) continue;
            sh.forced[n] = f;
            n += 1;
        }
        sh.forced_len = n;
        return sh.forced[0..n];
    }

    pub fn next(sh: *Shrinker) ?Candidate {
        while (true) {
            if (sh.state != .done and sh.runs >= sh.runs_max) sh.state = .done;
            // Past ddmin the set is looked up by key.
            if (sh.state != .all_benign and sh.state != .ddmin and !sh.sorted) {
                std.mem.sort(u64, sh.keep_buf[0..sh.len], {}, std.sort.asc(u64));
                sh.sorted = true;
            }
            switch (sh.state) {
                .done => return null,
                .all_benign => return sh.emit(sh.cand_buf[0..0], sh.forced[0..sh.forced_len], false),
                .ddmin => {
                    if (sh.len == 0) {
                        sh.state = .record;
                        continue;
                    }
                    sh.n = @min(sh.n, sh.len);
                    sh.chunk = (sh.len + sh.n - 1) / sh.n;
                    if (sh.start >= sh.len) {
                        // No chunk could be removed at this granularity.
                        if (sh.chunk == 1) {
                            sh.state = .record;
                            continue;
                        }
                        sh.n = @min(sh.n * 2, sh.len);
                        sh.start = 0;
                        continue;
                    }
                    const end = @min(sh.start + sh.chunk, sh.len);
                    const cand_len = sh.len - (end - sh.start);
                    @memcpy(sh.cand_buf[0..sh.start], sh.keep_buf[0..sh.start]);
                    @memcpy(sh.cand_buf[sh.start..cand_len], sh.keep_buf[end..sh.len]);
                    std.mem.sort(u64, sh.cand_buf[0..cand_len], {}, std.sort.asc(u64));
                    return sh.emit(sh.cand_buf[0..cand_len], sh.forced[0..sh.forced_len], false);
                },
                .record => return sh.emit(sh.keep(), sh.forced[0..sh.forced_len], true),
                .mask => {
                    const natural = sh.drawn_values[sh.vi];
                    if (sh.bits_lo < sh.bits_hi) {
                        const mid = sh.bits_lo + (sh.bits_hi - sh.bits_lo) / 2;
                        const masked = natural & lowMask(mid);
                        if (masked == natural) {
                            sh.bits_hi = mid; // the value itself: fails, no run needed
                            continue;
                        }
                        sh.pending = mid;
                        return sh.emitValue(sh.drawn_keys[sh.vi], masked);
                    }
                    sh.v = natural & lowMask(sh.bits_hi);
                    sh.vlo = 0;
                    sh.state = .bisect;
                },
                .bisect => {
                    if (sh.vlo < sh.v) {
                        const mid = sh.vlo + (sh.v - sh.vlo) / 2;
                        sh.pending = mid;
                        return sh.emitValue(sh.drawn_keys[sh.vi], mid);
                    }
                    if (sh.v != sh.drawn_values[sh.vi]) sh.lowered += 1;
                    sh.vi += 1;
                    sh.startKey();
                },
            }
        }
    }

    /// The candidate last returned by `next` failed the same way (`true`)
    /// or not.
    pub fn result(sh: *Shrinker, failed: bool) void {
        switch (sh.state) {
            .done => {},
            .all_benign => if (failed) {
                sh.len = 0;
                sh.state = .record;
            } else {
                sh.state = .ddmin;
            },
            .ddmin => if (failed) {
                const end = @min(sh.start + sh.chunk, sh.len);
                const cand_len = sh.len - (end - sh.start);
                if (sh.rec.overflowed) {
                    // The chunk goes; the rest keeps its order.
                    std.mem.copyForwards(u64, sh.keep_buf[sh.start..cand_len], sh.keep_buf[end..sh.len]);
                    sh.len = cand_len;
                } else {
                    sh.len = drawOrder(sh.keep_buf, sh.cand_buf, sh.rec.keys[0..sh.rec.len]);
                }
                sh.n = @max(sh.n - 1, 2);
                sh.start = 0;
            } else {
                sh.start += sh.chunk;
            },
            .record => if (failed and !sh.rec.overflowed) {
                @memcpy(sh.drawn_keys[0..sh.rec.len], sh.rec.keys[0..sh.rec.len]);
                @memcpy(sh.drawn_values[0..sh.rec.len], sh.rec.values.?[0..sh.rec.len]);
                sh.drawn_len = sh.rec.len;
                sh.vi = 0;
                sh.startKey();
            } else {
                sh.state = .done;
            },
            .mask => if (failed) {
                sh.adopt();
                sh.bits_hi = @intCast(sh.pending);
            } else {
                sh.bits_lo = @as(u32, @intCast(sh.pending)) + 1;
            },
            .bisect => if (failed) {
                sh.adopt();
                sh.v = sh.pending;
            } else {
                sh.vlo = sh.pending + 1;
            },
        }
    }

    fn emit(sh: *Shrinker, keep_set: []const u64, forced: []const decide.Forced, with_values: bool) Candidate {
        sh.runs += 1;
        sh.rec = if (with_values) .initWithValues(sh.rec_keys, sh.rec_values) else .init(sh.rec_keys);
        return .{ .keep = keep_set, .forced = forced, .recorder = &sh.rec };
    }

    fn emitValue(sh: *Shrinker, key: u64, value: u64) Candidate {
        sh.cand_forced_len = setForced(sh.cand_forced, sh.forced[0..sh.forced_len], key, value);
        return sh.emit(sh.keep(), sh.cand_forced[0..sh.cand_forced_len], false);
    }

    fn adopt(sh: *Shrinker) void {
        @memcpy(sh.forced[0..sh.cand_forced_len], sh.cand_forced[0..sh.cand_forced_len]);
        sh.forced_len = sh.cand_forced_len;
    }

    /// Positions the value search on the next decision with a non-zero value.
    fn startKey(sh: *Shrinker) void {
        while (sh.vi < sh.drawn_len and sh.drawn_values[sh.vi] == 0) sh.vi += 1;
        if (sh.vi >= sh.drawn_len) {
            sh.state = .done;
            return;
        }
        sh.bits_lo = 0;
        sh.bits_hi = 64;
        sh.state = .mask;
    }
};

/// Copies `keys` into `out` in their order, each once. `scratch` is as
/// long as `out`. A key is drawn once in a run, so duplicates are not
/// expected: if there are any, the result is the sorted set instead.
fn drawOrder(out: []u64, scratch: []u64, keys: []const u64) usize {
    @memcpy(scratch[0..keys.len], keys);
    const unique = sortUnique(scratch[0..keys.len]);
    if (unique == keys.len) {
        @memcpy(out[0..keys.len], keys);
    } else {
        @memcpy(out[0..unique], scratch[0..unique]);
    }
    return unique;
}

fn lowMask(bits: u32) u64 {
    return if (bits >= 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(bits)) - 1;
}

/// `out` := `from` with `key` set to `value`, sorted by key. Returns its length.
fn setForced(out: []decide.Forced, from: []const decide.Forced, key: u64, value: u64) usize {
    var n: usize = 0;
    var placed = false;
    for (from) |f| {
        if (!placed and f.key >= key) {
            out[n] = .{ .key = key, .value = value };
            n += 1;
            placed = true;
            if (f.key == key) continue;
        }
        out[n] = f;
        n += 1;
    }
    if (!placed) {
        out[n] = .{ .key = key, .value = value };
        n += 1;
    }
    return n;
}

// ----------------------------------------------------------------------
// Replay tokens
//
// `persona:0xSEED:KEEP[:FORCED]`
// * KEEP: `*` (every decision natural) or `k1.k2...` (only these natural,
//   the rest benign; may be empty), keys in hex.
// * FORCED: `k=v.k=v...` decisions given a raw value by guided exploration.

pub const Token = struct {
    persona: []const u8,
    seed: u64,
    /// Null means every decision keeps its natural value.
    keep: ?[]u64,
    forced: []decide.Forced,

    pub fn deinit(t: *Token, gpa: Allocator) void {
        if (t.keep) |k| gpa.free(k);
        gpa.free(t.forced);
        t.* = undefined;
    }

    pub fn overlay(t: *const Token) decide.Overlay {
        return .{ .keep = t.keep, .forced = t.forced };
    }
};

/// Returns null if the token does not fit in `buf`.
pub fn formatToken(buf: []u8, persona: []const u8, seed: u64, keep: ?[]const u64, forced: []const decide.Forced) ?[]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.print("{s}:0x{x:0>16}:", .{ persona, seed }) catch return null;
    if (keep) |keys| {
        for (keys, 0..) |k, i| {
            if (i > 0) w.writeByte('.') catch return null;
            w.print("{x}", .{k}) catch return null;
        }
    } else {
        w.writeByte('*') catch return null;
    }
    if (forced.len > 0) {
        w.writeByte(':') catch return null;
        for (forced, 0..) |f, i| {
            if (i > 0) w.writeByte('.') catch return null;
            w.print("{x}={x}", .{ f.key, f.value }) catch return null;
        }
    }
    return w.buffered();
}

pub fn parseToken(gpa: Allocator, text: []const u8) !Token {
    var it = std.mem.splitScalar(u8, std.mem.trim(u8, text, " \t\r\n"), ':');
    const persona = it.next() orelse return error.BadReplayToken;
    const seed_text = it.next() orelse return error.BadReplayToken;
    const keep_text = it.next() orelse return error.BadReplayToken;
    const forced_text = it.next() orelse "";
    if (it.next() != null) return error.BadReplayToken;
    const seed = std.fmt.parseInt(u64, seed_text, 0) catch return error.BadReplayToken;

    var keep: ?[]u64 = null;
    errdefer if (keep) |k| gpa.free(k);
    if (!std.mem.eql(u8, keep_text, "*")) {
        const count: usize = if (keep_text.len == 0) 0 else std.mem.count(u8, keep_text, ".") + 1;
        const keys = try gpa.alloc(u64, count);
        keep = keys;
        if (count > 0) {
            var kit = std.mem.splitScalar(u8, keep_text, '.');
            var i: usize = 0;
            while (kit.next()) |k| : (i += 1) keys[i] = std.fmt.parseInt(u64, k, 16) catch return error.BadReplayToken;
        }
        keep = try gpa.realloc(keys, sortUnique(keys));
    }

    const fcount: usize = if (forced_text.len == 0) 0 else std.mem.count(u8, forced_text, ".") + 1;
    const forced = try gpa.alloc(decide.Forced, fcount);
    errdefer gpa.free(forced);
    if (fcount > 0) {
        var fit = std.mem.splitScalar(u8, forced_text, '.');
        var i: usize = 0;
        while (fit.next()) |pair| : (i += 1) {
            const eq = std.mem.indexOfScalar(u8, pair, '=') orelse return error.BadReplayToken;
            forced[i] = .{
                .key = std.fmt.parseInt(u64, pair[0..eq], 16) catch return error.BadReplayToken,
                .value = std.fmt.parseInt(u64, pair[eq + 1 ..], 16) catch return error.BadReplayToken,
            };
        }
        std.mem.sort(decide.Forced, forced, {}, forcedLess);
    }
    return .{ .persona = persona, .seed = seed, .keep = keep, .forced = forced };
}

pub fn forcedLess(_: void, a: decide.Forced, b: decide.Forced) bool {
    return a.key < b.key;
}

// ----------------------------------------------------------------------
// Tests

const testing = std.testing;

/// Emulates a run: each key of `universe` is drawn in order; a kept key
/// takes its forced or natural value (and is recorded), the rest 0.
const FakeRun = struct {
    universe: []const u64,
    natural: []const u64,
    /// Fails given each key's value in this run.
    predicate: *const fn (values: []const u64) bool,

    fn run(f: *const FakeRun, c: Candidate) bool {
        var values: [256]u64 = undefined;
        const o: decide.Overlay = .{ .keep = c.keep, .forced = c.forced };
        for (f.universe, f.natural, 0..) |k, nat, i| {
            if (!o.contains(k)) {
                values[i] = 0;
                continue;
            }
            const v = o.forcedValue(k) orelse nat;
            values[i] = v;
            c.recorder.add(k, v);
        }
        return f.predicate(values[0..f.universe.len]);
    }

    fn shrink(f: *const FakeRun, base: []const decide.Forced, runs_max: u32) !Shrinker {
        var sh = try Shrinker.init(testing.allocator, f.universe, base, runs_max, 256);
        while (sh.next()) |c| sh.result(f.run(c));
        return sh;
    }
};

fn needs17And99(values: []const u64) bool {
    return values[17] != 0 and values[99] != 0;
}

test "ddmin finds the two decisions that matter" {
    var universe: [200]u64 = undefined;
    var natural: [200]u64 = undefined;
    for (&universe, &natural, 0..) |*u, *n, i| {
        u.* = i;
        n.* = decide.splitmix64(i) | 1;
    }
    const f: FakeRun = .{ .universe = &universe, .natural = &natural, .predicate = needs17And99 };
    var sh = try f.shrink(&.{}, 1000);
    defer sh.deinit();
    try testing.expectEqualSlices(u64, &.{ 17, 99 }, sh.keep());
    try testing.expectEqual(@as(usize, 200), sh.before);
    // Both values are lowered to the smallest that still fails: 1.
    const o: decide.Overlay = .{ .forced = sh.forcedResult() };
    try testing.expectEqual(@as(u64, 1), o.forcedValue(17).?);
    try testing.expectEqual(@as(u64, 1), o.forcedValue(99).?);
    try testing.expectEqual(@as(usize, 2), sh.lowered);
    try testing.expect(sh.runs < 400);
}

/// Fails when eight draws in a row, late in the run, all happen.
fn needsAStretch(values: []const u64) bool {
    for (values[200..208]) |v| if (v == 0) return false;
    return true;
}

test "chunks are stretches of the run: a failure with one cause shrinks in few runs, whatever the keys" {
    // Keys are hashes, as in a real run: sorted by key, the eight draws
    // would be spread over the whole set.
    var universe: [256]u64 = undefined;
    var natural: [256]u64 = undefined;
    for (&universe, &natural, 0..) |*u, *n, i| {
        u.* = decide.splitmix64(i + 1000);
        n.* = 1;
    }
    const f: FakeRun = .{ .universe = &universe, .natural = &natural, .predicate = needsAStretch };
    var sh = try f.shrink(&.{}, 1000);
    defer sh.deinit();
    try testing.expectEqual(@as(usize, 8), sh.keep().len);
    for (universe[200..208]) |k| try testing.expect(std.mem.indexOfScalar(u64, sh.keep(), k) != null);
    try testing.expect(std.sort.isSorted(u64, sh.keep(), {}, std.sort.asc(u64)));
    // Measured: 39 runs for 256 decisions.
    try testing.expect(sh.runs <= 45);
}

/// Fails when decision 3, truncated to a u16 like a fuzz input, is at least
/// 1000, and decision 9 (a `uniform(100)` latency) is at least 40.
fn inputAndLatency(values: []const u64) bool {
    const input: u16 = @truncate(values[3]);
    const latency: u64 = @intCast((@as(u128, values[9]) * 100) >> 64);
    return input >= 1000 and latency >= 40;
}

test "value shrinking finds the boundary of the failure" {
    var universe: [12]u64 = undefined;
    var natural: [12]u64 = undefined;
    for (&universe, &natural, 0..) |*u, *n, i| {
        u.* = i;
        n.* = decide.splitmix64(i + 100);
    }
    natural[3] = 0x9abc_def0_1234_ffee;
    natural[9] = 0xf000_0000_0000_0000;
    const f: FakeRun = .{ .universe = &universe, .natural = &natural, .predicate = inputAndLatency };
    // A base forced decision outside the result is dropped.
    var sh = try f.shrink(&.{.{ .key = 1000, .value = 7 }}, 1000);
    defer sh.deinit();
    try testing.expectEqualSlices(u64, &.{ 3, 9 }, sh.keep());
    try testing.expectEqual(@as(usize, 2), sh.lowered);
    const forced = sh.forcedResult();
    const o: decide.Overlay = .{ .forced = forced };
    try testing.expectEqual(@as(u64, 1000), o.forcedValue(3).?);
    const v9 = o.forcedValue(9).?;
    try testing.expectEqual(@as(u64, 40), @as(u64, @intCast((@as(u128, v9) * 100) >> 64)));
    try testing.expectEqual(@as(u64, 39), @as(u64, @intCast((@as(u128, v9 - 1) * 100) >> 64)));
    try testing.expect(o.forcedValue(1000) == null);
    try testing.expectEqual(@as(usize, 2), forced.len);
}

fn alwaysFails(values: []const u64) bool {
    _ = values;
    return true;
}

test "a failure that needs no decisions shrinks in one run, and the budget is respected" {
    var universe = [_]u64{ 1, 2, 3 };
    var natural = [_]u64{ 5, 6, 7 };
    const f: FakeRun = .{ .universe = &universe, .natural = &natural, .predicate = alwaysFails };
    var sh = try f.shrink(&.{}, 1000);
    defer sh.deinit();
    try testing.expectEqual(@as(usize, 0), sh.keep().len);
    try testing.expectEqual(@as(u32, 2), sh.runs); // all benign, then the record run

    var universe2: [200]u64 = undefined;
    var natural2: [200]u64 = undefined;
    for (&universe2, &natural2, 0..) |*u, *n, i| {
        u.* = i;
        n.* = i + 1;
    }
    const g: FakeRun = .{ .universe = &universe2, .natural = &natural2, .predicate = needs17And99 };
    var capped = try g.shrink(&.{}, 5);
    defer capped.deinit();
    try testing.expectEqual(@as(u32, 5), capped.runs);
}

test "replay token round trip" {
    var buf: [256]u8 = undefined;
    const forced = [_]decide.Forced{.{ .key = 0x5, .value = 0xffffffffffffffff }};
    const text = formatToken(&buf, "linux_xfs", 0xabc, &.{ 0x10, 0xff00 }, &forced).?;
    try testing.expectEqualStrings("linux_xfs:0x0000000000000abc:10.ff00:5=ffffffffffffffff", text);
    var tok = try parseToken(testing.allocator, text);
    defer tok.deinit(testing.allocator);
    try testing.expectEqualStrings("linux_xfs", tok.persona);
    try testing.expectEqual(@as(u64, 0xabc), tok.seed);
    try testing.expectEqualSlices(u64, &.{ 0x10, 0xff00 }, tok.keep.?);
    try testing.expectEqual(@as(u64, 0xffffffffffffffff), tok.overlay().forcedValue(5).?);

    var empty = try parseToken(testing.allocator, "posix_strict:0x1:");
    defer empty.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), empty.keep.?.len);

    const all = formatToken(&buf, "linux_ext4", 1, null, &.{}).?;
    try testing.expectEqualStrings("linux_ext4:0x0000000000000001:*", all);
    var natural = try parseToken(testing.allocator, all);
    defer natural.deinit(testing.allocator);
    try testing.expect(natural.keep == null);
}
