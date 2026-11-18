//! Antithesis-style reachability assertions (plan §7.1).
//!
//! The catalog persists across iterations and reboots of one campaign.

const std = @import("std");

pub const Entry = struct {
    name: []const u8,
    kind: Kind,
    reached_count: u64,
    true_count: u64,
};

pub const Kind = enum(u8) { sometimes, always };

pub const Catalog = struct {
    entries: []Entry,
    len: usize,

    pub fn init(storage: []Entry) Catalog {
        return .{ .entries = storage, .len = 0 };
    }

    fn find(c: *Catalog, name: []const u8, kind: Kind) *Entry {
        for (c.entries[0..c.len]) |*e| {
            if (e.kind == kind and std.mem.eql(u8, e.name, name)) return e;
        }
        if (c.len == c.entries.len) @panic("tardis: assertion catalog full (raise limits.assertions_max)");
        c.entries[c.len] = .{ .name = name, .kind = kind, .reached_count = 0, .true_count = 0 };
        c.len += 1;
        return &c.entries[c.len - 1];
    }

    /// `name` must outlive the catalog (use a comptime string).
    pub fn sometimes(c: *Catalog, name: []const u8, cond: bool) void {
        const e = c.find(name, .sometimes);
        e.reached_count += 1;
        if (cond) e.true_count += 1;
    }

    pub fn always(c: *Catalog, name: []const u8, cond: bool) bool {
        const e = c.find(name, .always);
        e.reached_count += 1;
        if (cond) e.true_count += 1;
        return cond;
    }

    /// Zeroes every count, keeping the entries (a forked child reports deltas).
    pub fn resetCounts(c: *Catalog) void {
        for (c.entries[0..c.len]) |*e| {
            e.reached_count = 0;
            e.true_count = 0;
        }
    }

    /// Adds another catalog's counts for the same assertion (parallel campaigns).
    pub fn merge(c: *Catalog, e: Entry) void {
        const mine = c.find(e.name, e.kind);
        mine.reached_count += e.reached_count;
        mine.true_count += e.true_count;
    }

    /// Reports every `sometimes` assertion that never held. Returns the count.
    pub fn reportUnsatisfied(c: *const Catalog, print: bool) usize {
        var n: usize = 0;
        for (c.entries[0..c.len]) |e| {
            if (e.kind != .sometimes or e.true_count > 0) continue;
            n += 1;
            if (!print) continue;
            if (e.reached_count == 0) {
                std.debug.print("tardis: sometimes(\"{s}\") was never reached\n", .{e.name});
            } else {
                std.debug.print("tardis: sometimes(\"{s}\") reached {d} times but never true\n", .{ e.name, e.reached_count });
            }
        }
        return n;
    }
};

test "catalog" {
    var storage: [4]Entry = undefined;
    var c = Catalog.init(&storage);
    c.sometimes("a", false);
    c.sometimes("a", true);
    c.sometimes("b", false);
    try std.testing.expect(c.always("c", true));
    try std.testing.expectEqual(@as(usize, 3), c.len);
    try std.testing.expectEqual(@as(u64, 1), c.entries[0].true_count);
}
