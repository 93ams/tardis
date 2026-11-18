//! The Requirement Traceability Registry (plan2.md §2.4, §7.5).
//!
//! One 128-byte row per requirement: its id, checks passed and failed, the
//! seed of the first failing run, and the set of tests (campaigns) bound to
//! it. A campaign accumulates its own table through the engine; `merge`
//! folds it into the project's persisted table (`.tardis_persist/
//! requirements.bin`), which is the rows back to back, little-endian.
//!
//! The tests bound to a row are a 256-bit Bloom filter over test names
//! (two bits per name), so merging is a bitwise OR and is the same in any
//! order; `tests_digest` is a hash of the filter. A requirement declared in
//! the project's requirement file but never checked is a gap.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Io = std.Io;

pub const requirements_max = 4096;
pub const id_bytes_max = 48;

/// One row of the registry (128 bytes).
pub const Record = extern struct {
    id: [id_bytes_max]u8 = @splat(0),
    id_len: u8 = 0,
    _pad0: [7]u8 = @splat(0),
    checks_passed: u64 = 0,
    checks_failed: u64 = 0,
    /// Wyhash of `tests_bloom` (bidirectional traceability).
    tests_digest: u64 = 0,
    /// Run seed of the first failing check (meaningful when `checks_failed > 0`).
    first_failure_seed: u64 = 0,
    mcdc_decisions_covered: u32 = 0,
    mcdc_decisions_total: u32 = 0,
    /// The tests bound to this requirement: a 256-bit Bloom filter.
    tests_bloom: [4]u64 = @splat(0),

    pub fn idSlice(r: *const Record) []const u8 {
        return r.id[0..r.id_len];
    }

    fn bloomBits(name: []const u8) [2]u8 {
        const h = std.hash.Wyhash.hash(0x5EC0_7E57, name);
        return .{ @truncate(h), @truncate(h >> 8) };
    }

    /// Binds the test `name` to this requirement.
    pub fn bindTest(r: *Record, name: []const u8) void {
        for (bloomBits(name)) |b| r.tests_bloom[b / 64] |= @as(u64, 1) << @as(u6, @truncate(b));
        r.tests_digest = std.hash.Wyhash.hash(0, std.mem.asBytes(&r.tests_bloom));
    }

    /// Whether `name` is bound (false positives at Bloom-filter rates).
    pub fn boundTo(r: *const Record, name: []const u8) bool {
        for (bloomBits(name)) |b| {
            if (r.tests_bloom[b / 64] & (@as(u64, 1) << @as(u6, @truncate(b))) == 0) return false;
        }
        return true;
    }

    pub fn checks(r: *const Record) u64 {
        return r.checks_passed + r.checks_failed;
    }

    pub const Status = enum { pass, fail, gap };

    pub fn status(r: *const Record) Status {
        if (r.checks_failed > 0) return .fail;
        if (r.checks_passed == 0) return .gap;
        return .pass;
    }

    /// Adds `other`'s results (same id).
    pub fn merge(r: *Record, other: *const Record) void {
        assert(std.mem.eql(u8, r.idSlice(), other.idSlice()));
        if (r.checks_failed == 0 and other.checks_failed > 0) r.first_failure_seed = other.first_failure_seed;
        r.checks_passed += other.checks_passed;
        r.checks_failed += other.checks_failed;
        r.mcdc_decisions_covered = @max(r.mcdc_decisions_covered, other.mcdc_decisions_covered);
        r.mcdc_decisions_total = @max(r.mcdc_decisions_total, other.mcdc_decisions_total);
        for (&r.tests_bloom, other.tests_bloom) |*a, b| a.* |= b;
        r.tests_digest = std.hash.Wyhash.hash(0, std.mem.asBytes(&r.tests_bloom));
    }
};

comptime {
    assert(@sizeOf(Record) == 128);
    assert(requirements_max * @sizeOf(Record) == 512 * 1024);
}

pub const Error = error{ RequirementsFull, RequirementIdTooLong, CorruptRequirements };

/// 512 KiB: keep it on the heap. Only `records[0..len]` is meaningful,
/// so setting `len = 0` initializes it.
pub const Table = struct {
    records: [requirements_max]Record = undefined,
    len: u16 = 0,

    pub fn slice(t: *const Table) []const Record {
        return t.records[0..t.len];
    }

    pub fn find(t: *const Table, id: []const u8) ?u16 {
        for (t.records[0..t.len], 0..) |*rec, i| {
            if (std.mem.eql(u8, rec.idSlice(), id)) return @intCast(i);
        }
        return null;
    }

    /// The row for `id`, created if new.
    pub fn index(t: *Table, id: []const u8) Error!u16 {
        if (id.len == 0 or id.len > id_bytes_max) return error.RequirementIdTooLong;
        if (t.find(id)) |i| return i;
        if (t.len == requirements_max) return error.RequirementsFull;
        const rec = &t.records[t.len];
        rec.* = .{};
        @memcpy(rec.id[0..id.len], id);
        rec.id_len = @intCast(id.len);
        t.len += 1;
        return t.len - 1;
    }

    /// Declares the requirements listed in a requirement file: one id per
    /// line; blank lines and `#` comments are skipped. Declared rows with
    /// no checks are gaps.
    pub fn declare(t: *Table, text: []const u8) Error!void {
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            const end = std.mem.indexOfAny(u8, line, " \t#") orelse line.len;
            _ = try t.index(line[0..end]);
        }
    }

    pub fn merge(t: *Table, other: *const Table) Error!void {
        for (other.slice()) |*rec| {
            const i = try t.index(rec.idSlice());
            t.records[i].merge(rec);
        }
    }

    /// The rows as stored on disk.
    pub fn bytes(t: *const Table) []const u8 {
        comptime assert(builtin.cpu.arch.endian() == .little);
        return std.mem.sliceAsBytes(t.records[0..t.len]);
    }

    /// Merges rows read from disk (validated: whole rows, ids in range).
    pub fn mergeBytes(t: *Table, data: []const u8) Error!void {
        comptime assert(builtin.cpu.arch.endian() == .little);
        if (data.len % @sizeOf(Record) != 0 or data.len / @sizeOf(Record) > requirements_max) return error.CorruptRequirements;
        var i: usize = 0;
        while (i < data.len) : (i += @sizeOf(Record)) {
            var rec: Record = undefined;
            @memcpy(std.mem.asBytes(&rec), data[i..][0..@sizeOf(Record)]);
            if (rec.id_len == 0 or rec.id_len > id_bytes_max) return error.CorruptRequirements;
            const at = try t.index(rec.idSlice());
            t.records[at].merge(&rec);
        }
    }

    /// Merges `path` under `dir` into `t`; a missing file is an empty table.
    pub fn load(t: *Table, io: Io, gpa: std.mem.Allocator, dir: Io.Dir, path: []const u8) !void {
        const data = dir.readFileAlloc(io, path, gpa, .limited(requirements_max * @sizeOf(Record) + 1)) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer gpa.free(data);
        try t.mergeBytes(data);
    }

    /// Writes the table to `path` under `dir`: to a temporary file first,
    /// then renamed over the old one, so a crash leaves the old table or
    /// the new one, never a torn one.
    pub fn save(t: *const Table, io: Io, dir: Io.Dir, path: []const u8) !void {
        if (std.fs.path.dirname(path)) |parent| try dir.createDirPath(io, parent);
        var tmp_buf: [Io.Dir.max_path_bytes]u8 = undefined;
        const tmp = try std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{path});
        {
            var file = try dir.createFile(io, tmp, .{});
            defer file.close(io);
            try file.writeStreamingAll(io, t.bytes());
            try file.sync(io);
        }
        try dir.rename(tmp, dir, path, io);
    }
};

/// Where a project keeps its registry between campaigns.
pub const persist_path = ".tardis_persist/requirements.bin";

const testing = std.testing;

test "records: binding, status, merge" {
    const t = try testing.allocator.create(Table);
    defer testing.allocator.destroy(t);
    t.len = 0;
    try t.declare(
        \\# security functional requirements
        \\SFR-FDP_ACC.1
        \\SFR-FIA_UAU.6   # re-authentication
        \\
    );
    try testing.expectEqual(@as(u16, 2), t.len);
    try testing.expectEqual(Record.Status.gap, t.records[1].status());
    const i = try t.index("SFR-FDP_ACC.1");
    try testing.expectEqual(@as(u16, 0), i);
    t.records[i].checks_passed = 3;
    t.records[i].bindTest("raft: safety");
    try testing.expect(t.records[i].boundTo("raft: safety"));
    try testing.expectEqual(Record.Status.pass, t.records[i].status());

    const u = try testing.allocator.create(Table);
    defer testing.allocator.destroy(u);
    u.len = 0;
    const j = try u.index("SFR-FDP_ACC.1");
    u.records[j].checks_failed = 1;
    u.records[j].first_failure_seed = 0xBAD;
    u.records[j].bindTest("tls: handshake");
    try t.merge(u);
    const r = &t.records[i];
    try testing.expectEqual(@as(u64, 4), r.checks());
    try testing.expectEqual(@as(u64, 0xBAD), r.first_failure_seed);
    try testing.expect(r.boundTo("raft: safety") and r.boundTo("tls: handshake"));
    try testing.expectEqual(Record.Status.fail, r.status());

    try testing.expectError(error.RequirementIdTooLong, t.index(&@as([49]u8, @splat('x'))));
}

test "persistence: save, load and merge round-trip; corrupt files are refused" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    const t = try testing.allocator.create(Table);
    defer testing.allocator.destroy(t);
    t.len = 0;
    const i = try t.index("SFR-FCS_CKM.4");
    t.records[i].checks_passed = 7;
    try t.save(io, tmp.dir, persist_path);
    try t.save(io, tmp.dir, persist_path); // overwrite in place

    const u = try testing.allocator.create(Table);
    defer testing.allocator.destroy(u);
    u.len = 0;
    try u.load(io, testing.allocator, tmp.dir, persist_path);
    try u.load(io, testing.allocator, tmp.dir, persist_path); // counts add up
    try testing.expectEqual(@as(u64, 14), u.records[0].checks_passed);
    try u.load(io, testing.allocator, tmp.dir, "missing.bin");
    try testing.expectError(error.CorruptRequirements, u.mergeBytes("short"));
}
