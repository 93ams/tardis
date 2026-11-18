//! Coverage-guided exploration (plan §9 M3).
//!
//! A run's *coverage* is a 64 Ki-bit map of features:
//! * simulator event pairs `(previous kind, kind, label)`, where labels carry
//!   paths, error names and assertion names, so "this file was renamed after
//!   a fault" and "this error was returned" are distinct features;
//! * `sometimes` assertions that held;
//! * `env.cover(name, value)` points chosen by the code under test.
//!
//! A run that sets a bit no earlier run set joins the corpus as
//! `(persona, seed, forced decisions, sample of its decision keys)`. Later
//! iterations either start from a fresh seed or mutate a corpus entry by
//! forcing one to three of its decisions to new raw values
//! (`decide.Overlay.forced`), so exploration climbs from behaviour already
//! reached toward behaviour not yet reached.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const decide = @import("../sim/decide.zig");

pub const map_bits = 1 << 16;
pub const map_words = map_bits / 64;

pub const Map = struct {
    words: *[map_words]u64,

    pub fn clear(m: Map) void {
        @memset(m.words, 0);
    }

    pub fn set(m: Map, feature: u64) void {
        const bit: u32 = @truncate(decide.splitmix64(feature));
        const i = bit % map_bits;
        m.words[i / 64] |= @as(u64, 1) << @intCast(i % 64);
    }

    /// Merges `run` into `m`; returns how many bits were new.
    pub fn merge(m: Map, run: Map) u32 {
        var new: u32 = 0;
        for (m.words, run.words) |*seen, r| {
            new += @popCount(r & ~seen.*);
            seen.* |= r;
        }
        return new;
    }

    pub fn count(m: Map) u32 {
        var n: u32 = 0;
        for (m.words) |w| n += @popCount(w);
        return n;
    }
};

pub fn labelHash(label: []const u8) u64 {
    return std.hash.Wyhash.hash(0x7a2d, label);
}

pub const forced_max = 16;
/// Comparison constants kept by a corpus (first seen first).
pub const tokens_max = 256;
pub const sample_max = 64;

pub const Entry = struct {
    persona_index: u8,
    seed: u64,
    forced: [forced_max]decide.Forced,
    forced_len: u8,
    /// Decision keys the run drew (a deterministic sample): mutation targets.
    keys: [sample_max]u64,
    keys_len: u8,

    pub fn forcedSlice(e: *const Entry) []const decide.Forced {
        return e.forced[0..e.forced_len];
    }
};

pub const Corpus = struct {
    entries: []Entry,
    len: usize,
    /// Campaign-level choices (sequential, independent of any run).
    rng: decide.Decider,
    /// Constants the program compared against (a security layer's
    /// comparison feedback). A mutation forces one of them a fifth of the
    /// time once there are any; without them mutation is unchanged.
    tokens: [tokens_max]u64 = undefined,
    tokens_len: u16 = 0,

    pub fn init(gpa: Allocator, capacity: usize, campaign_seed: u64) !Corpus {
        assert(capacity > 0);
        return .{
            .entries = try gpa.alloc(Entry, capacity),
            .len = 0,
            .rng = .init(decide.mix(campaign_seed, 0xC0DE)),
        };
    }

    pub fn deinit(c: *Corpus, gpa: Allocator) void {
        gpa.free(c.entries);
        c.* = undefined;
    }

    /// Adds a run that found new coverage. When full, replaces a random entry.
    pub fn add(c: *Corpus, persona_index: u8, seed: u64, forced: []const decide.Forced, drawn: []const u64) void {
        const slot = if (c.len < c.entries.len) blk: {
            c.len += 1;
            break :blk c.len - 1;
        } else c.rng.uniform(.swarm, c.entries.len);
        const e = &c.entries[slot];
        e.persona_index = persona_index;
        e.seed = seed;
        e.forced_len = @intCast(forced.len);
        @memcpy(e.forced[0..forced.len], forced);
        // Evenly spaced sample, so early and late decisions are both targets.
        const n = @min(drawn.len, sample_max);
        e.keys_len = @intCast(n);
        for (0..n) |i| e.keys[i] = drawn[i * drawn.len / n];
    }

    /// Adds the constants a run compared against; duplicates and those
    /// beyond `tokens_max` are dropped.
    pub fn addTokens(c: *Corpus, tokens: []const u64) void {
        for (tokens) |t| {
            if (std.mem.indexOfScalar(u64, c.tokens[0..c.tokens_len], t) != null) continue;
            if (c.tokens_len == tokens_max) return;
            c.tokens[c.tokens_len] = t;
            c.tokens_len += 1;
        }
    }

    /// Picks a parent for `persona_index`, or null to start from a fresh
    /// seed (half the time, or when there is nothing to mutate).
    pub fn pickParent(c: *Corpus, persona_index: u8) ?*const Entry {
        if (c.len == 0 or c.rng.boolean(.swarm)) return null;
        var matching: usize = 0;
        for (c.entries[0..c.len]) |*e| {
            if (e.persona_index == persona_index and e.keys_len > 0) matching += 1;
        }
        if (matching == 0) return null;
        var pick = c.rng.uniform(.swarm, matching);
        for (c.entries[0..c.len]) |*e| {
            if (e.persona_index != persona_index or e.keys_len == 0) continue;
            if (pick == 0) return e;
            pick -= 1;
        }
        unreachable;
    }

    /// `out` := `parent` with one to three decisions forced to new values.
    pub fn mutate(c: *Corpus, parent: *const Entry, out: *Entry) void {
        out.* = parent.*;
        const n = 1 + c.rng.uniform(.swarm, 3);
        for (0..n) |_| {
            const key = parent.keys[c.rng.uniform(.swarm, parent.keys_len)];
            // Raw values: random, all-ones (every `chance` true, every
            // `uniform` at its maximum), zero (benign), or a compared
            // constant (an integer draw of its width then equals it).
            const kinds: u64 = if (c.tokens_len > 0) 5 else 4;
            const value = switch (c.rng.uniform(.swarm, kinds)) {
                0, 1 => c.rng.next(.swarm),
                2 => std.math.maxInt(u64),
                3 => 0,
                else => c.tokens[c.rng.uniform(.swarm, c.tokens_len)],
            };
            setForced(out, key, value, &c.rng);
        }
    }
};

fn setForced(e: *Entry, key: u64, value: u64, rng: *decide.Decider) void {
    for (e.forced[0..e.forced_len]) |*f| {
        if (f.key == key) {
            f.value = value;
            return;
        }
    }
    if (e.forced_len == forced_max) {
        e.forced[rng.uniform(.swarm, forced_max)] = .{ .key = key, .value = value };
    } else {
        e.forced[e.forced_len] = .{ .key = key, .value = value };
        e.forced_len += 1;
    }
    std.mem.sort(decide.Forced, e.forced[0..e.forced_len], {}, struct {
        fn less(_: void, a: decide.Forced, b: decide.Forced) bool {
            return a.key < b.key;
        }
    }.less);
}

test "map merge reports new bits once" {
    var a: [map_words]u64 = @splat(0);
    var b: [map_words]u64 = @splat(0);
    const seen: Map = .{ .words = &a };
    const run: Map = .{ .words = &b };
    run.set(1);
    run.set(2);
    try std.testing.expectEqual(@as(u32, 2), seen.merge(run));
    try std.testing.expectEqual(@as(u32, 0), seen.merge(run));
    try std.testing.expectEqual(@as(u32, 2), seen.count());
}

test "mutation forces sampled keys and keeps forced sorted" {
    var c = try Corpus.init(std.testing.allocator, 4, 1);
    defer c.deinit(std.testing.allocator);
    const drawn = [_]u64{ 50, 40, 30, 20, 10 };
    c.add(0, 7, &.{}, &drawn);
    var child: Entry = undefined;
    for (0..20) |_| {
        c.mutate(&c.entries[0], &child);
        try std.testing.expect(child.forced_len >= 1 and child.forced_len <= 3);
        for (child.forcedSlice(), 0..) |f, i| {
            try std.testing.expect(std.mem.indexOfScalar(u64, &drawn, f.key) != null);
            if (i > 0) try std.testing.expect(child.forced[i - 1].key < f.key);
        }
    }
}

test "tokens are kept once and some mutations force them" {
    var c = try Corpus.init(std.testing.allocator, 4, 7);
    defer c.deinit(std.testing.allocator);
    c.addTokens(&.{ 0x5EC0B1A5, 0x5EC0B1A5, 'G' });
    try std.testing.expectEqual(@as(u16, 2), c.tokens_len);
    c.add(0, 1, &.{}, &.{ 10, 20, 30 });
    var child: Entry = undefined;
    var forced_token = false;
    for (0..64) |_| {
        c.mutate(&c.entries[0], &child);
        for (child.forcedSlice()) |f| forced_token = forced_token or f.value == 0x5EC0B1A5 or f.value == 'G';
    }
    try std.testing.expect(forced_token);
}
