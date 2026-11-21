//! What a campaign keeps between runs (plan3.md E4): the guided explorer's
//! corpus, its comparison constants and the coverage it reached, and the
//! runs that failed, which the next campaign runs first.
//!
//! One file per `check`, written whole and renamed into place, so a
//! campaign killed while saving leaves the previous file. A file that does
//! not decode (another version, truncated, edited) is ignored: the campaign
//! starts empty, as without a file. Nothing in it changes what a run does
//! given its seed and forced decisions; it only changes which runs a
//! campaign chooses, so every failure still replays from its token alone.
//!
//! Layout, little-endian: the magic `TARDISK1`; the comparison constants
//! (`u32` count, `u64` each); the coverage map (`u8` present, then
//! `explore.map_words` words); the corpus entries (`u32` count; each: the
//! persona's name, the seed, the forced decisions, the sampled keys); the
//! failed runs (`u32` count; each: the persona's name, the seed, the forced
//! decisions); and a Wyhash of everything before it. A persona is kept by
//! name, so a file outlives a reordered `personas` list.

const std = @import("std");
const Allocator = std.mem.Allocator;
const decide = @import("../sim/decide.zig");
const explore = @import("explore.zig");
const Persona = @import("../model/vfs.zig").Persona;

const magic = "TARDISK1";
/// Failed runs kept; the oldest is dropped beyond this.
pub const failures_max = 16;
/// Corpus entries kept in a file, whatever `corpus_max` is.
pub const entries_max = 1 << 16;

pub const Failed = struct {
    persona: Persona,
    seed: u64,
    forced: [explore.forced_max]decide.Forced = undefined,
    forced_len: u8 = 0,

    pub fn forcedSlice(f: *const Failed) []const decide.Forced {
        return f.forced[0..f.forced_len];
    }

    fn same(a: *const Failed, b: *const Failed) bool {
        return a.persona == b.persona and a.seed == b.seed and
            std.mem.eql(u8, std.mem.sliceAsBytes(a.forcedSlice()), std.mem.sliceAsBytes(b.forcedSlice()));
    }
};

pub const Kept = struct {
    /// Corpus entries with their persona by name (`persona_index` unused).
    entries: std.ArrayList(Entry) = .empty,
    tokens: [explore.tokens_max]u64 = undefined,
    tokens_len: u16 = 0,
    seen: ?*[explore.map_words]u64 = null,
    failures: [failures_max]Failed = undefined,
    failures_len: u8 = 0,

    pub const Entry = struct { persona: Persona, entry: explore.Entry };

    pub fn deinit(k: *Kept, gpa: Allocator) void {
        k.entries.deinit(gpa);
        if (k.seen) |m| gpa.destroy(m);
        k.* = undefined;
    }

    pub fn failedSlice(k: *const Kept) []const Failed {
        return k.failures[0..k.failures_len];
    }

    /// Adds a failed run unless it is kept already; beyond `failures_max`
    /// the oldest goes.
    pub fn addFailure(k: *Kept, f: Failed) void {
        for (k.failedSlice()) |*old| if (old.same(&f)) return;
        if (k.failures_len == failures_max) {
            std.mem.copyForwards(Failed, k.failures[0 .. failures_max - 1], k.failures[1..failures_max]);
            k.failures_len -= 1;
        }
        k.failures[k.failures_len] = f;
        k.failures_len += 1;
    }

    pub fn removeFailure(k: *Kept, i: usize) void {
        std.mem.copyForwards(Failed, k.failures[i .. k.failures_len - 1], k.failures[i + 1 .. k.failures_len]);
        k.failures_len -= 1;
    }

    /// Loads the kept corpus into `corpus` and `seen`: entries whose persona
    /// is not in `personas` are left out.
    pub fn intoCorpus(k: *const Kept, corpus: *explore.Corpus, seen: *[explore.map_words]u64, personas: []const Persona) void {
        for (k.entries.items) |*e| {
            const pi = std.mem.indexOfScalar(Persona, personas, e.persona) orelse continue;
            if (corpus.len == corpus.entries.len) break;
            var entry = e.entry;
            entry.persona_index = @intCast(pi);
            corpus.entries[corpus.len] = entry;
            corpus.len += 1;
        }
        corpus.addTokens(k.tokens[0..k.tokens_len]);
        if (k.seen) |m| for (seen, m) |*w, x| {
            w.* |= x;
        };
    }

    /// Replaces the kept corpus with `corpus` and `seen`. Kept entries of
    /// personas this campaign did not run stay.
    /// On failure `k` is unchanged.
    pub fn fromCorpus(k: *Kept, gpa: Allocator, corpus: *const explore.Corpus, seen: *const [explore.map_words]u64, personas: []const Persona) Allocator.Error!void {
        var list: std.ArrayList(Entry) = .empty;
        errdefer list.deinit(gpa);
        for (k.entries.items) |e| {
            if (std.mem.indexOfScalar(Persona, personas, e.persona) == null) try list.append(gpa, e);
        }
        for (corpus.entries[0..corpus.len]) |*e| {
            if (list.items.len == entries_max) break;
            try list.append(gpa, .{ .persona = personas[e.persona_index], .entry = e.* });
        }
        const map = k.seen orelse try gpa.create([explore.map_words]u64);
        // Nothing fails from here.
        k.seen = map;
        map.* = seen.*;
        k.entries.deinit(gpa);
        k.entries = list;
        @memcpy(k.tokens[0..corpus.tokens_len], corpus.tokens[0..corpus.tokens_len]);
        k.tokens_len = corpus.tokens_len;
    }
};

pub fn encode(gpa: Allocator, k: *const Kept) Allocator.Error![]u8 {
    var w: std.Io.Writer.Allocating = .init(gpa);
    errdefer w.deinit();
    encodeTo(&w.writer, k) catch return error.OutOfMemory;
    const body = w.written();
    const sum = std.hash.Wyhash.hash(0, body);
    w.writer.writeInt(u64, sum, .little) catch return error.OutOfMemory;
    return w.toOwnedSlice();
}

fn encodeTo(w: *std.Io.Writer, k: *const Kept) std.Io.Writer.Error!void {
    try w.writeAll(magic);
    try w.writeInt(u32, k.tokens_len, .little);
    for (k.tokens[0..k.tokens_len]) |t| try w.writeInt(u64, t, .little);
    if (k.seen) |m| {
        try w.writeByte(1);
        for (m) |x| try w.writeInt(u64, x, .little);
    } else try w.writeByte(0);
    try w.writeInt(u32, @intCast(k.entries.items.len), .little);
    for (k.entries.items) |*e| {
        try writePersona(w, e.persona);
        try w.writeInt(u64, e.entry.seed, .little);
        try writeForced(w, e.entry.forcedSlice());
        try w.writeByte(e.entry.keys_len);
        for (e.entry.keys[0..e.entry.keys_len]) |key| try w.writeInt(u64, key, .little);
    }
    try w.writeInt(u32, k.failures_len, .little);
    for (k.failedSlice()) |*f| {
        try writePersona(w, f.persona);
        try w.writeInt(u64, f.seed, .little);
        try writeForced(w, f.forcedSlice());
    }
}

fn writePersona(w: *std.Io.Writer, p: Persona) !void {
    const name = @tagName(p);
    try w.writeByte(@intCast(name.len));
    try w.writeAll(name);
}

fn writeForced(w: *std.Io.Writer, forced: []const decide.Forced) !void {
    try w.writeByte(@intCast(forced.len));
    for (forced) |f| {
        try w.writeInt(u64, f.key, .little);
        try w.writeInt(u64, f.value, .little);
    }
}

pub const DecodeError = error{ Malformed, OutOfMemory };

/// Decodes a file `encode` wrote. Entries and failures of a persona this
/// build does not know are skipped.
pub fn decode(gpa: Allocator, bytes: []const u8) DecodeError!Kept {
    if (bytes.len < magic.len + 8) return error.Malformed;
    const body = bytes[0 .. bytes.len - 8];
    const sum = std.mem.readInt(u64, bytes[bytes.len - 8 ..][0..8], .little);
    if (sum != std.hash.Wyhash.hash(0, body) or !std.mem.eql(u8, body[0..magic.len], magic)) return error.Malformed;
    var r: Reader = .{ .bytes = body, .at = magic.len };
    var k: Kept = .{};
    errdefer k.deinit(gpa);

    const tokens = try r.int(u32);
    if (tokens > explore.tokens_max) return error.Malformed;
    k.tokens_len = @intCast(tokens);
    for (k.tokens[0..tokens]) |*t| t.* = try r.int(u64);
    switch (try r.int(u8)) {
        0 => {},
        1 => {
            const m = try gpa.create([explore.map_words]u64);
            k.seen = m;
            for (m) |*x| x.* = try r.int(u64);
        },
        else => return error.Malformed,
    }
    const entries = try r.int(u32);
    if (entries > entries_max) return error.Malformed;
    for (0..entries) |_| {
        const persona = try r.persona();
        var e: explore.Entry = undefined;
        e.persona_index = 0;
        e.seed = try r.int(u64);
        e.forced_len = try r.forced(&e.forced);
        const keys = try r.int(u8);
        if (keys > explore.sample_max) return error.Malformed;
        e.keys_len = keys;
        for (e.keys[0..keys]) |*key| key.* = try r.int(u64);
        if (persona) |p| try k.entries.append(gpa, .{ .persona = p, .entry = e });
    }
    const failures = try r.int(u32);
    if (failures > failures_max) return error.Malformed;
    for (0..failures) |_| {
        const persona = try r.persona();
        var f: Failed = .{ .persona = .linux_ext4, .seed = try r.int(u64) };
        f.forced_len = try r.forced(&f.forced);
        if (persona) |p| {
            f.persona = p;
            k.failures[k.failures_len] = f;
            k.failures_len += 1;
        }
    }
    if (r.at != body.len) return error.Malformed;
    return k;
}

const Reader = struct {
    bytes: []const u8,
    at: usize,

    fn int(r: *Reader, comptime T: type) !T {
        const n = @sizeOf(T);
        if (r.bytes.len - r.at < n) return error.Malformed;
        defer r.at += n;
        return std.mem.readInt(T, r.bytes[r.at..][0..n], .little);
    }

    /// Null for a name this build does not know.
    fn persona(r: *Reader) !?Persona {
        const n = try r.int(u8);
        if (r.bytes.len - r.at < n) return error.Malformed;
        defer r.at += n;
        return std.meta.stringToEnum(Persona, r.bytes[r.at..][0..n]);
    }

    fn forced(r: *Reader, out: *[explore.forced_max]decide.Forced) !u8 {
        const n = try r.int(u8);
        if (n > explore.forced_max) return error.Malformed;
        for (out[0..n]) |*f| f.* = .{ .key = try r.int(u64), .value = try r.int(u64) };
        return n;
    }
};

test "a kept corpus survives encoding, and a damaged file does not decode" {
    const gpa = std.testing.allocator;
    var c = try explore.Corpus.init(gpa, 8, 1);
    defer c.deinit(gpa);
    c.add(1, 0xAB, &.{.{ .key = 5, .value = 6 }}, &.{ 10, 20, 30 });
    c.add(0, 0xCD, &.{}, &.{40});
    c.addTokens(&.{ 0x5EC0, 7 });
    var seen: [explore.map_words]u64 = @splat(0);
    seen[3] = 0xF0;
    const personas = [_]Persona{ .linux_ext4, .windows_ntfs };

    var k: Kept = .{};
    defer k.deinit(gpa);
    try k.fromCorpus(gpa, &c, &seen, &personas);
    k.addFailure(.{ .persona = .windows_ntfs, .seed = 99 });
    k.addFailure(.{ .persona = .windows_ntfs, .seed = 99 });
    try std.testing.expectEqual(@as(u8, 1), k.failures_len);

    const bytes = try encode(gpa, &k);
    defer gpa.free(bytes);
    var back = try decode(gpa, bytes);
    defer back.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 2), back.entries.items.len);
    try std.testing.expectEqual(Persona.windows_ntfs, back.entries.items[0].persona);
    try std.testing.expectEqual(@as(u64, 0xAB), back.entries.items[0].entry.seed);
    try std.testing.expectEqual(@as(u64, 6), back.entries.items[0].entry.forced[0].value);
    try std.testing.expectEqual(@as(u8, 3), back.entries.items[0].entry.keys_len);
    try std.testing.expectEqual(@as(u16, 2), back.tokens_len);
    try std.testing.expectEqual(@as(u64, 0xF0), back.seen.?[3]);
    try std.testing.expectEqual(@as(u64, 99), back.failedSlice()[0].seed);

    // Into a campaign whose personas are ordered otherwise.
    var c2 = try explore.Corpus.init(gpa, 8, 2);
    defer c2.deinit(gpa);
    var seen2: [explore.map_words]u64 = @splat(0);
    back.intoCorpus(&c2, &seen2, &.{ .windows_ntfs, .macos_apfs });
    try std.testing.expectEqual(@as(usize, 1), c2.len);
    try std.testing.expectEqual(@as(u8, 0), c2.entries[0].persona_index);
    try std.testing.expectEqual(@as(u64, 0xF0), seen2[3]);

    for ([_]usize{ 0, 9, bytes.len / 2, bytes.len - 1 }) |at| {
        const bad = try gpa.dupe(u8, bytes);
        defer gpa.free(bad);
        bad[at] ^= 1;
        try std.testing.expectError(error.Malformed, decode(gpa, bad));
    }
    try std.testing.expectError(error.Malformed, decode(gpa, bytes[0 .. bytes.len - 3]));
}

test "the oldest failure goes when the list is full" {
    var k: Kept = .{};
    defer k.deinit(std.testing.allocator);
    for (0..failures_max + 2) |i| k.addFailure(.{ .persona = .linux_ext4, .seed = i });
    try std.testing.expectEqual(@as(u8, failures_max), k.failures_len);
    try std.testing.expectEqual(@as(u64, 2), k.failedSlice()[0].seed);
    k.removeFailure(0);
    try std.testing.expectEqual(@as(u64, 3), k.failedSlice()[0].seed);
}
