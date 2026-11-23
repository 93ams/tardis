//! Pillars IV and V through the engine (plan2.md §6.1, §7.1, §7.2;
//! Milestone 5 (SEC) week 15): an amplification ratio steers guided
//! exploration to a hash-flooding input, MC/DC tables find a redundant
//! condition, and bounded exhaustive exploration enumerates every
//! execution of a 3-node protocol.

const std = @import("std");
const tardis = @import("tardis");
const sec = @import("tardis_sec");
const Io = std.Io;
const Env = tardis.Env;
const gpa = std.testing.allocator;

// ---------------------------------------------------------------------------
// HashDoS: a fixed-seed hash table fed untrusted keys

const bucket_count = 16;
const key_count = 16;

/// Separate chaining in a fixed array; the hash is fixed, so an attacker
/// who knows it can put every key in one bucket.
const Table = struct {
    heads: [bucket_count]u8 = @splat(none),
    next: [key_count]u8 = undefined,
    keys: [key_count]u16 = undefined,
    len: u8 = 0,

    const none = 0xFF;

    fn hash(k: u16, randomized: bool, seed: u16) u4 {
        const x: u32 = if (randomized) @as(u32, k ^ seed) *% 0x9E37_79B1 else @as(u32, k) *% 0x9E37;
        return @truncate(x >> 12);
    }

    /// Inserts `k` unless present. Each comparison is one work unit.
    fn insert(t: *Table, k: u16, randomized: bool, seed: u16) void {
        const b = hash(k, randomized, seed);
        var i = t.heads[b];
        while (i != none) : (i = t.next[i]) {
            sec.work(1);
            if (t.keys[i] == k) return;
        }
        sec.work(1);
        t.keys[t.len] = k;
        t.next[t.len] = t.heads[b];
        t.heads[b] = t.len;
        t.len += 1;
    }
};

fn loadKeys(env: *Env, randomized: bool) !void {
    var t: Table = .{};
    // A per-process secret seed: what a randomized hash would use.
    const seed: u16 = if (randomized) @as(u16, @truncate(env.seed)) | 1 else 0;
    for (0..key_count) |_| {
        const k = try env.fuzz(u16);
        sec.untrustedInput(2);
        t.insert(k, randomized, seed);
    }
}

pub fn fixedHash(env: *Env) !void {
    return loadKeys(env, false);
}

/// 16 keys, 32 input bytes; 16 distinct keys spread evenly cost about 24
/// comparisons. All in one bucket cost 1 + 2 + ... + 16 = 136. The limit
/// sits at 3 per byte (96 comparisons), which needs about 13 keys in one
/// bucket: about 1 run in 10^10 at random.
pub const hashdos_limits: sec.AmplificationLimits = .{ .work_per_input_byte_milli_max = 3_000 };

test "hashdos: guided exploration synthesizes a colliding key set (CWE-407)" {
    var report: sec.engine.Report = .{};
    var explored: tardis.ExploreReport = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, fixedHash, sec.withSecurity(.{
        .amplification = hashdos_limits,
        .report = &report,
        .base = .{
            .iterations = 100_000,
            .explore = .guided,
            .explore_report = &explored,
            .report = false,
            .shrink = false,
        },
    })));
    try std.testing.expectEqual(@as(u16, 407), report.findings[0].cwe);
    try std.testing.expectEqual(sec.engine.Kind.amplification, report.findings[0].kind);
    // Measured: iteration 13,974 with a corpus of 21 (the run is
    // deterministic, so this is the same on every machine and mode).
    try std.testing.expect(explored.failed_at.? < 100_000);
}

test "hashdos: random exploration does not find it" {
    try tardis.check(gpa, fixedHash, sec.withSecurity(.{
        .amplification = hashdos_limits,
        .base = .{ .iterations = 5_000 },
    }));
}

pub fn randomizedHash(env: *Env) !void {
    return loadKeys(env, true);
}

test "hashdos fixed: a hash seeded from the run is not flooded in this campaign" {
    // Weaker than it looks: a mutated input keeps its parent's run seed
    // (`Corpus.mutate` copies the entry), so the hash seed is the same for
    // a parent and its children, and the search can still converge on it.
    // `zig build secrates` measured it: 5 of 20 campaigns of 50,000
    // guided iterations flood the seeded table (11 of 20 flood the fixed
    // hash, whose multiplier differs, so the two are not a controlled
    // comparison). This campaign of 10,000, with the default campaign
    // seed, does not.
    try tardis.check(gpa, randomizedHash, sec.withSecurity(.{
        .amplification = hashdos_limits,
        .base = .{ .iterations = 10_000, .explore = .guided },
    }));
}

// ---------------------------------------------------------------------------
// MC/DC: an unlock decision, and a redundant condition

const unlock_decision = 1;
const audit_decision = 2;

fn unlock(env: *Env) !void {
    const armed = (try env.fuzz(u8)) & 1 == 1;
    const sig_ok = (try env.fuzz(u8)) & 1 == 1;
    const override = (try env.fuzz(u8)) & 1 == 1;
    // armed and (sig_ok or override)
    _ = sec.mcdc.decision(unlock_decision, .{ armed, sig_ok, override }, struct {
        fn f(c: anytype) bool {
            return c[0] and (c[1] or c[2]);
        }
    }.f);
    // The audit flag is written as `armed or (armed and sig_ok)`: sig_ok can
    // never change the outcome, which MC/DC exposes as a gap.
    _ = sec.mcdc.decision(audit_decision, .{ armed, sig_ok }, struct {
        fn f(c: anytype) bool {
            return c[0] or (c[0] and c[1]);
        }
    }.f);
}

test "mcdc: every condition of the unlock decision is shown; the redundant one is a gap" {
    var report: sec.mcdc.Report = .{};
    try tardis.check(gpa, unlock, sec.withSecurity(.{ .mcdc = &report, .base = .{ .iterations = 64 } }));
    const u = report.entry(unlock_decision);
    try std.testing.expect(u.complete());
    try std.testing.expectEqual(@as(u8, 0b111), u.shown());
    const a = report.entry(audit_decision);
    try std.testing.expectEqual(@as(u8, 2), a.conditions);
    try std.testing.expectEqual(@as(u16, 4), a.vectorsSeen()); // every vector tried
    try std.testing.expectEqual(@as(u8, 0b01), a.shown()); // sig_ok never shown
    try std.testing.expect(!a.complete());

    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try report.write(&w);
    try std.testing.expectEqualStrings(
        "decision 1: 3 conditions, 8 vectors, shown 00000111 complete\n" ++
            "decision 2: 2 conditions, 4 vectors, shown 00000001 GAPS\n",
        w.buffered(),
    );
}

const gate_decision = 3;
const gate_code: u32 = 0xC0DE600D;

/// A maintenance gate: open when armed and the 32-bit code matches. `fed`:
/// the code comparison goes through `mcdc.compare`.
fn gate(env: *Env, comptime fed: bool) !void {
    const code = try env.fuzz(u32);
    const armed = (try env.fuzz(u8)) & 1 == 1;
    const match = if (fed) sec.mcdc.compare(code, .eq, gate_code) else code == gate_code;
    _ = sec.mcdc.decision(gate_decision, .{ armed, match }, struct {
        fn f(c: anytype) bool {
            return c[0] and c[1];
        }
    }.f);
}

fn fedGate(env: *Env) !void {
    return gate(env, true);
}

fn plainGate(env: *Env) !void {
    return gate(env, false);
}

test "mcdc: a compared operand steers guided exploration to the vectors a 32-bit match needs" {
    var fed: sec.mcdc.Report = .{};
    try tardis.check(gpa, fedGate, sec.withSecurity(.{ .mcdc = &fed, .base = .{ .iterations = 2000, .explore = .guided } }));
    try std.testing.expect(fed.entry(gate_decision).complete());
    // The same on two workers.
    var parallel: sec.mcdc.Report = .{};
    try tardis.check(gpa, fedGate, sec.withSecurity(.{ .mcdc = &parallel, .base = .{ .iterations = 2000, .workers = 2, .explore = .guided } }));
    try std.testing.expect(parallel.entry(gate_decision).complete());
    // A plain `==` gives exploration nothing: one value in 2^32 is never
    // drawn, so neither condition is shown, and the report says which
    // vector to test next for the match (one with a match).
    var plain: sec.mcdc.Report = .{};
    try tardis.check(gpa, plainGate, sec.withSecurity(.{ .mcdc = &plain, .base = .{ .iterations = 2000, .explore = .guided } }));
    const p = plain.entry(gate_decision);
    try std.testing.expectEqual(@as(u8, 0), p.shown());
    try std.testing.expectEqual(@as(?u8, 0b10), p.wanted(1));
    // Signed and ordered operands, and enums.
    try std.testing.expect(sec.mcdc.compare(@as(i16, -3), .lt, 2));
    try std.testing.expect(sec.mcdc.compare(std.math.Order.lt, .neq, .gt));
}

// ---------------------------------------------------------------------------
// Bounded exhaustive exploration: three nodes vote over lossy UDP

const vote_port = 900;

fn anyAddr(port: u16) Io.net.IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } };
}

const Decisions = struct { value: [3]?u8 = @splat(null) };

/// Node `me` votes `me + 1`, sends its vote to the other two, and collects
/// votes until a timeout. `quorum_all`: decide only with all three votes
/// (else stay undecided); otherwise decide the largest vote seen (the bug).
fn voter(io: Io, env: *Env, me: u8, out: *Decisions, quorum_all: bool) !void {
    const sock = try anyAddr(vote_port).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    try io.sleep(.fromMilliseconds(1), .awake); // every node is bound
    const vote: [1]u8 = .{me + 1};
    for (0..3) |peer| {
        if (peer == me) continue;
        try sock.send(io, &env.address(@intCast(peer), vote_port), &vote);
    }
    var seen: [3]?u8 = @splat(null);
    seen[me] = me + 1;
    var buf: [8]u8 = undefined;
    for (0..2) |_| {
        const msg = sock.receiveTimeout(io, &buf, .{ .duration = .{ .raw = .fromMilliseconds(10), .clock = .awake } }) catch |err| switch (err) {
            error.Timeout => break,
            else => return err,
        };
        const v = msg.data[0];
        if (v >= 1 and v <= 3) seen[v - 1] = v;
    }
    var count: u8 = 0;
    var best: u8 = 0;
    for (seen) |s| if (s) |v| {
        count += 1;
        best = @max(best, v);
    };
    if (quorum_all and count < 3) return;
    out.value[me] = best;
}

/// Every final outcome the executions of a search reached (each node's
/// decision: none, or 1 to 3), to compare searches with.
var outcomes_seen: [64]bool = @splat(false);

fn outcomeCode(out: Decisions) u6 {
    var code: u6 = 0;
    for (out.value) |v| code = code * 4 + @as(u6, @intCast(v orelse 0));
    return code;
}

fn election(env: *Env, quorum_all: bool) !void {
    const io = env.io;
    var out: Decisions = .{};
    try env.spawnOn(1, voter, .{ io, env, 1, &out, quorum_all });
    try env.spawnOn(2, voter, .{ io, env, 2, &out, quorum_all });
    try voter(io, env, 0, &out, quorum_all);
    try io.sleep(.fromMilliseconds(50), .awake);
    outcomes_seen[outcomeCode(out)] = true;
    var decided: ?u8 = null;
    for (out.value) |v| if (v) |x| {
        if (decided) |d| try env.always("decided nodes agree", d == x);
        decided = x;
    };
}

fn maxSeen(env: *Env) !void {
    return election(env, false);
}

fn allThree(env: *Env) !void {
    return election(env, true);
}

/// Every draw narrow: losses are the model's only nondeterminism besides
/// the scheduler's choices among runnable tasks.
const model: tardis.Options = .{
    .nodes = 3,
    .swarm = false,
    .preempt_ppm = 0,
    .async_inline_ppm = 0,
    .faults = .{
        .short_io_ppm = 0,
        .spurious_wakeup_ppm = 0,
        .io_latency_min_ns = 1_000,
        .io_latency_max_ns = 1_000,
        .datagram_loss_ppm = 300_000,
        .datagram_duplicate_ppm = 0,
    },
    .net = .{ .latency_min_ns = 100_000, .latency_max_ns = 100_000 },
};

test "exhaustive: the max-of-seen vote disagrees under some loss pattern" {
    const r = try sec.verifyExhaustive(gpa, maxSeen, model, .{ .depth_max = 12 });
    try std.testing.expectEqual(@as(?anyerror, error.AssertionFailed), r.failure);
    // The counterexample replays from its token.
    var o = model;
    o.replay = r.token();
    o.report = false;
    try std.testing.expectError(error.AssertionFailed, tardis.check(gpa, maxSeen, o));
}

test "exhaustive: the all-three vote agrees in every execution to depth 12" {
    const r = try sec.verifyExhaustive(gpa, allThree, model, .{ .depth_max = 12 });
    try std.testing.expectEqual(@as(?anyerror, null), r.failure);
    try std.testing.expect(r.complete);
    try std.testing.expectEqual(@as(u32, 0), r.unenumerated);
    // Measured: 9,216 executions (6 binary losses and the scheduler's
    // choices). Executions make up to 15 branchable decisions, so the
    // bound is real: decisions after the 12th take their benign value.
    try std.testing.expectEqual(@as(u32, 9_216), r.executions);
    try std.testing.expect(r.depth_bounded and r.depth_seen >= 12);
}

/// The buggy election without its assertion, so a search runs to the end
/// and `outcomes_seen` holds every outcome.
fn maxSeenTally(env: *Env) !void {
    election(env, false) catch |err| switch (err) {
        error.AssertionFailed => {},
        else => return err,
    };
}

test "exhaustive with reduction: fewer executions, the same verdicts and the same outcomes" {
    const full = try sec.verifyExhaustive(gpa, allThree, model, .{ .depth_max = 12 });
    const reduced = try sec.verifyExhaustive(gpa, allThree, model, .{ .depth_max = 12, .reduce = true });
    try std.testing.expectEqual(@as(?anyerror, null), reduced.failure);
    try std.testing.expect(reduced.complete);
    try std.testing.expectEqual(@as(u32, 9_216), full.executions);
    // With a security layer attached nothing commutes (`-Dsec`).
    if (tardis.security_by_default) {
        try std.testing.expectEqual(full.executions, reduced.executions);
    } else {
        // Measured: a third of the executions, 1,549 alternatives pruned.
        try std.testing.expectEqual(@as(u32, 3_073), reduced.executions);
        try std.testing.expectEqual(@as(u32, 1_549), reduced.pruned);
    }
    // The bug is still found, and replays.
    const bug = try sec.verifyExhaustive(gpa, maxSeen, model, .{ .depth_max = 12, .reduce = true });
    try std.testing.expectEqual(@as(?anyerror, error.AssertionFailed), bug.failure);
    var o = model;
    o.replay = bug.token();
    o.report = false;
    try std.testing.expectError(error.AssertionFailed, tardis.check(gpa, maxSeen, o));
    // Every outcome the full search reaches, the reduced one reaches too.
    var sets: [2][64]bool = undefined;
    for ([_]bool{ false, true }, 0..) |reduce, k| {
        outcomes_seen = @splat(false);
        const t = try sec.verifyExhaustive(gpa, maxSeenTally, model, .{ .depth_max = 12, .reduce = reduce });
        try std.testing.expectEqual(@as(?anyerror, null), t.failure);
        sets[k] = outcomes_seen;
    }
    try std.testing.expectEqualSlices(bool, &sets[0], &sets[1]);
    var distinct: u32 = 0;
    for (sets[0]) |seen| distinct += @intFromBool(seen);
    try std.testing.expect(distinct > 4);
}

test "exhaustive with state merging: executions that did the same in another order are explored once" {
    const full = try sec.verifyExhaustive(gpa, allThree, model, .{ .depth_max = 12 });
    for ([_]bool{ false, true }) |reduce| {
        const merged = try sec.verifyExhaustive(gpa, allThree, model, .{ .depth_max = 12, .merge = true, .reduce = reduce });
        try std.testing.expectEqual(@as(?anyerror, null), merged.failure);
        try std.testing.expect(merged.complete);
        // With a security layer attached nothing merges (`-Dsec`).
        if (tardis.security_by_default) {
            try std.testing.expectEqual(full.executions, merged.executions);
        } else if (reduce) {
            // Measured: the adjacent-step rule leaves nothing to merge in
            // this model.
            try std.testing.expectEqual(@as(u32, 3_073), merged.executions);
        } else {
            // Measured: the same third of the executions as `reduce`.
            try std.testing.expectEqual(@as(u32, 3_073), merged.executions);
            try std.testing.expectEqual(@as(u32, 769), merged.merged);
        }
    }
    // The bug is still found, and replays.
    const bug = try sec.verifyExhaustive(gpa, maxSeen, model, .{ .depth_max = 12, .merge = true });
    try std.testing.expectEqual(@as(?anyerror, error.AssertionFailed), bug.failure);
    var o = model;
    o.replay = bug.token();
    o.report = false;
    try std.testing.expectError(error.AssertionFailed, tardis.check(gpa, maxSeen, o));
    // Every outcome the full search reaches, the merging ones reach too.
    var sets: [3][64]bool = undefined;
    const searches = [_]tardis.ExhaustiveOptions{
        .{ .depth_max = 12 },
        .{ .depth_max = 12, .merge = true },
        .{ .depth_max = 12, .merge = true, .reduce = true },
    };
    for (searches, 0..) |search, k| {
        outcomes_seen = @splat(false);
        const t = try sec.verifyExhaustive(gpa, maxSeenTally, model, search);
        try std.testing.expectEqual(@as(?anyerror, null), t.failure);
        sets[k] = outcomes_seen;
    }
    try std.testing.expectEqualSlices(bool, &sets[0], &sets[1]);
    try std.testing.expectEqualSlices(bool, &sets[0], &sets[2]);
}

const race_port = 901;

fn racer(io: Io, env: *Env, me: u8) !void {
    const sock = try anyAddr(race_port).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    try io.sleep(.fromMilliseconds(1), .awake);
    try sock.send(io, &env.address(0, race_port), &.{me});
}

/// Nodes 1 and 2 each send one datagram to node 0, with the same latency:
/// which one node 0 reads first depends on the order of the two sends.
fn firstArrival(env: *Env) !void {
    const io = env.io;
    const sock = try anyAddr(race_port).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    try env.spawnOn(1, racer, .{ io, env, 1 });
    try env.spawnOn(2, racer, .{ io, env, 2 });
    var buf: [8]u8 = undefined;
    const msg = sock.receiveTimeout(io, &buf, .{ .duration = .{ .raw = .fromMilliseconds(10), .clock = .awake } }) catch |err| switch (err) {
        error.Timeout => return,
        else => return err,
    };
    outcomes_seen[msg.data[0]] = true;
    try io.sleep(.fromMilliseconds(5), .awake);
}

test "exhaustive with reduction: two sends to one inbox do not commute, so both arrival orders are kept" {
    var lossless = model;
    lossless.faults.datagram_loss_ppm = 0;
    for ([_]tardis.ExhaustiveOptions{
        .{ .depth_max = 12 },
        .{ .depth_max = 12, .reduce = true },
        .{ .depth_max = 12, .merge = true },
        .{ .depth_max = 12, .reduce = true, .merge = true },
    }) |search| {
        outcomes_seen = @splat(false);
        const r = try sec.verifyExhaustive(gpa, firstArrival, lossless, search);
        try std.testing.expectEqual(@as(?anyerror, null), r.failure);
        try std.testing.expect(r.complete);
        try std.testing.expect(outcomes_seen[1] and outcomes_seen[2]);
    }
}
