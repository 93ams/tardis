//! Pillar V: MC/DC for Zig code (plan2.md §7.1, DO-178C DAL A).
//!
//! Zig has no MC/DC instrumentation, so a requirement-relevant decision is
//! written through `tardis_sec.mcdc.decision(id, .{ c0, c1, ... })`, which
//! returns the outcome and records the vector of condition values. A
//! decision has up to 8 conditions, so 256 vectors, kept as two 256-bit
//! sets: vectors seen, and the outcome of each. The outcome is computed by
//! the caller's expression (`eval`), so it is exactly the code's logic.
//!
//! A condition is shown (unique-cause MC/DC) when two seen vectors differ
//! only in it and have different outcomes. Conditions never shown are gaps:
//! either a missing test vector, which guided exploration is steered
//! towards (each new vector is a coverage feature), or a condition that can
//! never affect the outcome, which the project must justify or remove.
//!
//! The table outlives runs: coverage accumulates over the campaign, and
//! `Report.merge` ORs per-worker tables, so the result is the same for any
//! worker count.
//!
//! Conditions are passed as evaluated `bool`s, so Zig's short-circuit
//! evaluation is not observed: a condition the code would not evaluate is
//! recorded with its value anyway. That is the stricter, unique-cause form;
//! masking MC/DC (CAST-6) is not modelled.

const std = @import("std");
const assert = std.debug.assert;

pub const decisions_max = 256;
pub const conditions_max = 8;
const vector_words = (1 << conditions_max) / 64;

pub const Entry = struct {
    conditions: u8 = 0,
    seen: [vector_words]u64 = @splat(0),
    outcome: [vector_words]u64 = @splat(0),

    fn bit(set: [vector_words]u64, v: u8) bool {
        return set[v / 64] & (@as(u64, 1) << @as(u6, @truncate(v))) != 0;
    }

    fn setBit(set: *[vector_words]u64, v: u8) void {
        set[v / 64] |= @as(u64, 1) << @as(u6, @truncate(v));
    }

    pub fn reached(e: Entry) bool {
        for (e.seen) |w| if (w != 0) return true;
        return false;
    }

    pub fn vectorsSeen(e: Entry) u16 {
        var n: u16 = 0;
        for (e.seen) |w| n += @popCount(w);
        return n;
    }

    /// Records vector `v` with `outcome`. True if the vector is new.
    pub fn record(e: *Entry, conditions: u8, v: u8, out: bool) bool {
        assert(conditions <= conditions_max);
        if (e.conditions == 0) e.conditions = conditions;
        assert(e.conditions == conditions); // one decision id, one shape
        if (bit(e.seen, v)) return false;
        setBit(&e.seen, v);
        if (out) setBit(&e.outcome, v);
        return true;
    }

    /// The pair of vectors showing condition `c`, if one was seen.
    pub fn pair(e: Entry, c: u3) ?[2]u8 {
        if (c >= e.conditions) return null;
        const flip = @as(u8, 1) << c;
        const count: u16 = @as(u16, 1) << @as(u4, @intCast(e.conditions));
        var v: u16 = 0;
        while (v < count) : (v += 1) {
            const a: u8 = @intCast(v);
            if (a & flip != 0) continue;
            const b = a | flip;
            if (!bit(e.seen, a) or !bit(e.seen, b)) continue;
            if (bit(e.outcome, a) != bit(e.outcome, b)) return .{ a, b };
        }
        return null;
    }

    /// A vector not seen yet that would give condition `c` a candidate
    /// pair: one whose partner (the same vector with `c` flipped) was seen,
    /// or else any vector of an unseen pair. Null when `c` is shown, and
    /// when every pair was seen without a change of outcome: then no test
    /// can show `c`, which is redundant in the decision.
    pub fn wanted(e: Entry, c: u3) ?u8 {
        if (c >= e.conditions or e.pair(c) != null) return null;
        const flip = @as(u8, 1) << c;
        const count: u16 = @as(u16, 1) << @as(u4, @intCast(e.conditions));
        var unseen: ?u8 = null;
        var v: u16 = 0;
        while (v < count) : (v += 1) {
            const a: u8 = @intCast(v);
            if (a & flip != 0) continue;
            const b = a | flip;
            const seen_a = bit(e.seen, a);
            const seen_b = bit(e.seen, b);
            if (seen_a and !seen_b) return b;
            if (seen_b and !seen_a) return a;
            if (!seen_a and unseen == null) unseen = a;
        }
        return unseen;
    }

    /// Bit c set: condition c has an independence pair.
    pub fn shown(e: Entry) u8 {
        var m: u8 = 0;
        for (0..e.conditions) |c| {
            if (e.pair(@intCast(c)) != null) m |= @as(u8, 1) << @intCast(c);
        }
        return m;
    }

    pub fn complete(e: Entry) bool {
        if (e.conditions == 0) return false;
        const all: u8 = @truncate((@as(u16, 1) << @as(u4, @intCast(e.conditions))) - 1);
        return e.shown() == all;
    }
};

/// A decision the project instruments, as declared to `certify`
/// (`CertifyOptions.decisions`): the list of decision ids that turns
/// "never reached" into a dead-code finding, and the requirement each
/// decision implements, so MC/DC is reported per requirement.
pub const Decl = struct {
    id: u8,
    /// Where it is, for the report (`"auth.zig:88 armed and (sig or override)"`).
    name: []const u8,
    /// The Security Functional Requirement the decision implements.
    requirement: ?[]const u8 = null,
    /// Code deactivated by configuration (DO-178C §6.4.4.3): the reason it
    /// is not reached. A declared decision never reached without one is
    /// dead code, which the project must remove.
    deactivated: ?[]const u8 = null,
};

pub fn declOf(decls: []const Decl, id: usize) ?*const Decl {
    for (decls) |*d| if (d.id == id) return d;
    return null;
}

/// The conditions of `e` without an independence pair (bit c: condition c).
pub fn gaps(e: Entry) u8 {
    if (e.conditions == 0) return 0;
    const all: u8 = @truncate((@as(u16, 1) << @as(u4, @intCast(e.conditions))) - 1);
    return all & ~e.shown();
}

pub const Table = struct {
    entries: [decisions_max]Entry = @splat(.{}),

    pub fn merge(t: *Table, other: *const Table) void {
        for (&t.entries, other.entries) |*a, b| {
            if (b.conditions == 0) continue;
            if (a.conditions == 0) a.conditions = b.conditions;
            for (&a.seen, b.seen) |*w, x| w.* |= x;
            for (&a.outcome, b.outcome) |*w, x| w.* |= x;
        }
    }
};

/// `SecurityConfig.mcdc`: receives the campaign's MC/DC table when each
/// worker's simulator is destroyed (merged, so any worker count gives the
/// same report).
pub const Report = struct {
    table: Table = .{},
    /// Workers merge from their own threads, outside any `std.Io`.
    busy: std.atomic.Value(bool) = .init(false),

    pub fn merge(r: *Report, t: *const Table) void {
        while (r.busy.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
        defer r.busy.store(false, .release);
        r.table.merge(t);
    }

    pub fn entry(r: *const Report, id: u8) Entry {
        return r.table.entries[id];
    }

    /// One line per reached decision: conditions shown, and gaps.
    pub fn write(r: *const Report, w: *std.Io.Writer) !void {
        for (r.table.entries, 0..) |e, id| {
            if (!e.reached()) continue;
            try w.print("decision {d}: {d} conditions, {d} vectors, shown {b:0>8}", .{ id, e.conditions, e.vectorsSeen(), e.shown() });
            try w.writeAll(if (e.complete()) " complete\n" else " GAPS\n");
        }
    }
};

/// Packs condition values into a vector index (condition i is bit i).
pub fn vectorOf(conds: anytype) u8 {
    const n = @typeInfo(@TypeOf(conds)).@"struct".field_names.len;
    comptime assert(n >= 1 and n <= conditions_max);
    var v: u8 = 0;
    inline for (0..n) |i| {
        const c: bool = conds[i];
        if (c) v |= @as(u8, 1) << @intCast(i);
    }
    return v;
}

test "unique-cause pairs for a and (b or c)" {
    var e: Entry = .{};
    const eval = struct {
        fn f(v: u8) bool {
            const a = v & 1 != 0;
            const b = v & 2 != 0;
            const c = v & 4 != 0;
            return a and (b or c);
        }
    }.f;
    // The minimal MC/DC set for a and (b or c): n + 1 = 4 vectors.
    for ([_]u8{ 0b011, 0b010, 0b001, 0b101 }) |v| _ = e.record(3, v, eval(v));
    try std.testing.expect(e.complete());
    try std.testing.expectEqual([2]u8{ 0b010, 0b011 }, e.pair(0).?);
    try std.testing.expect(!e.record(3, 0b011, true)); // seen before
}

test "a redundant condition can never be shown" {
    // a or (a and b): b never changes the outcome.
    var e: Entry = .{};
    for (0..4) |i| {
        const v: u8 = @intCast(i);
        const a = v & 1 != 0;
        const b = v & 2 != 0;
        _ = e.record(2, v, a or (a and b));
    }
    try std.testing.expectEqual(@as(u8, 0b01), e.shown());
    try std.testing.expect(!e.complete());
}

test "wanted: the vector that would complete a pair, and none for a redundant condition" {
    var e: Entry = .{};
    // a and b, with only (a, not b) seen: flipping b gives 0b11.
    _ = e.record(2, 0b01, false);
    try std.testing.expectEqual(@as(?u8, 0b11), e.wanted(1));
    try std.testing.expectEqual(@as(?u8, 0b00), e.wanted(0));
    _ = e.record(2, 0b11, true);
    try std.testing.expectEqual(@as(?u8, null), e.wanted(1)); // shown
    // a or (a and b): every pair for b seen, the outcome never changes.
    var r: Entry = .{};
    for (0..4) |i| {
        const v: u8 = @intCast(i);
        _ = r.record(2, v, v & 1 != 0);
    }
    try std.testing.expectEqual(@as(?u8, null), r.wanted(1));
    try std.testing.expectEqual(@as(u8, 0b10), gaps(r));
}

test "merge is an OR, independent of order" {
    var x: Table = .{};
    var y: Table = .{};
    _ = x.entries[3].record(2, 0b00, false);
    _ = y.entries[3].record(2, 0b01, true);
    var xy = x;
    xy.merge(&y);
    var yx = y;
    yx.merge(&x);
    try std.testing.expectEqualDeep(xy.entries[3], yx.entries[3]);
    try std.testing.expectEqual(@as(u16, 2), xy.entries[3].vectorsSeen());
}
