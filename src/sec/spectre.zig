//! The Spectre-v1 gadget shape (plan2.md §6.3, CWE-1037).
//!
//! The classic gadget is `if (x < len) y = probe[table[x] * 64]`: after a
//! bounds check on an index the attacker chooses, a load whose address is
//! computed from the value an earlier load returned. Run speculatively
//! with `x` out of bounds, the first load reads a secret and the second
//! leaves it in the cache.
//!
//! This is a heuristic over what the program does in bounds, not a model
//! of speculation. A bounds check the code marks (`boundsCheck`, or
//! `TARDIS_SEC_BOUNDS` in C) opens a window of the next `window_loads`
//! loads and `window_edges` edges. For every pair of loads in a window,
//! the detector keeps, per check site, up to three observations in which
//! the earlier load read different values from different addresses: (that
//! value, the later load's address). When three lie on one line with a
//! nonzero whole slope, the later address is `base + slope * value`: the
//! shape, and a finding. The earlier load must move too, because it is
//! the one the attacker's index addresses; an index that unoptimized code
//! reloads from its stack slot is a value at one address, and `table[x]`
//! after it is not a gadget.
//!
//! What it misses: a gadget whose loads the tracer does not see (Zig loads
//! not passed to `load`, C built without `trace-loads`), an address that
//! is not linear in the value, and a site seen with fewer than three
//! different values. What it gets wrong: a table whose values are linear
//! in the index makes any later load at `index + c` look value-dependent.
//! An index hardened with `indexNoSpec` is not marked, so it opens no
//! window: the detector trusts that marker.

const std = @import("std");

pub const window_loads = 8;
pub const window_edges = 16;
pub const sites_max = 16;

const Load = struct { value: u64, addr: u64 };

/// One run of a pair of loads: what the earlier one read and where, and
/// where the later one read.
const Obs = struct { value: u64, from: u64, addr: u64 };

const Pair = struct {
    obs: [3]Obs = undefined,
    len: u8 = 0,
    reported: bool = false,
};

const Site = struct {
    pc: usize,
    pairs: [window_loads * window_loads]Pair = @splat(.{}),
};

pub const Gadget = struct {
    /// Bytes the later load's address moves per unit of the earlier
    /// load's value.
    scale: i64,
    /// The two loads' places in the window (0: the first after the check).
    first: u8,
    second: u8,
};

pub const Detector = struct {
    sites: [sites_max]Site = undefined,
    sites_len: u8 = 0,
    /// The open window's site, or null.
    open: ?u8 = null,
    loads: [window_loads]Load = undefined,
    loads_len: u8 = 0,
    edges_left: u8 = 0,

    /// A run starts: no window is open. Observations stay: a site is seen
    /// with different values over the runs of a campaign.
    pub fn beginRun(d: *Detector) void {
        d.open = null;
    }

    /// A marked bounds check at `pc` passed: the window opens.
    pub fn check(d: *Detector, pc: usize) void {
        const at = for (d.sites[0..d.sites_len], 0..) |s, i| {
            if (s.pc == pc) break i;
        } else blk: {
            if (d.sites_len == sites_max) {
                d.open = null;
                return;
            }
            d.sites[d.sites_len] = .{ .pc = pc };
            d.sites_len += 1;
            break :blk d.sites_len - 1;
        };
        d.open = @intCast(at);
        d.loads_len = 0;
        d.edges_left = window_edges;
    }

    pub fn edge(d: *Detector) void {
        if (d.open == null) return;
        if (d.edges_left == 0) {
            d.open = null;
        } else d.edges_left -= 1;
    }

    /// A load of `value` from `addr`. Returns the gadget this load
    /// completes, once per pair of loads of a site.
    pub fn load(d: *Detector, addr: u64, value: u64) ?Gadget {
        const site = &d.sites[d.open orelse return null];
        if (d.loads_len == window_loads) {
            d.open = null;
            return null;
        }
        const m = d.loads_len;
        var found: ?Gadget = null;
        for (d.loads[0..m], 0..) |earlier, j| {
            const p = &site.pairs[j * window_loads + m];
            if (p.reported or p.len == p.obs.len) continue;
            const seen = for (p.obs[0..p.len]) |o| {
                if (o.value == earlier.value or o.from == earlier.addr) break true;
            } else false;
            if (seen) continue;
            p.obs[p.len] = .{ .value = earlier.value, .from = earlier.addr, .addr = addr };
            p.len += 1;
            if (p.len < p.obs.len) continue;
            if (slope(p.obs)) |k| {
                p.reported = true;
                if (found == null) found = .{ .scale = k, .first = @intCast(j), .second = m };
            }
        }
        d.loads[m] = .{ .value = value, .addr = addr };
        d.loads_len += 1;
        return found;
    }
};

/// The whole nonzero slope of the line through three observations with
/// different values, if they lie on one.
fn slope(obs: [3]Obs) ?i64 {
    const dv1 = @as(i128, obs[1].value) - obs[0].value;
    const dv2 = @as(i128, obs[2].value) - obs[0].value;
    const da1 = @as(i128, obs[1].addr) - obs[0].addr;
    const da2 = @as(i128, obs[2].addr) - obs[0].addr;
    if (da1 == 0 or @rem(da1, dv1) != 0) return null;
    if (da1 * dv2 != da2 * dv1) return null;
    const k = @divExact(da1, dv1);
    if (k < std.math.minInt(i64) or k > std.math.maxInt(i64)) return null;
    return @intCast(k);
}

test "three observations on a line are a gadget; a constant address and a bent line are not" {
    var d: Detector = .{};
    const table = [_]u64{ 7, 200, 13, 91 };
    var hit: ?Gadget = null;
    for (table, 0..) |v, x| {
        d.check(0x1000);
        try std.testing.expectEqual(@as(?Gadget, null), d.load(0x5000 + x, v));
        if (d.load(0x9000 + v * 64, 0)) |g| hit = g;
    }
    try std.testing.expectEqual(@as(i64, 64), hit.?.scale);
    try std.testing.expectEqual(@as(u8, 0), hit.?.first);
    try std.testing.expectEqual(@as(u8, 1), hit.?.second);

    // The second load's address does not move with the value.
    var c: Detector = .{};
    for (table, 0..) |v, x| {
        c.check(0x2000);
        _ = c.load(0x5000 + x, v);
        try std.testing.expectEqual(@as(?Gadget, null), c.load(0x9000, 0));
    }
    // It moves, but not on a line (a hash of the value).
    var h: Detector = .{};
    for (table) |v| {
        h.check(0x3000);
        _ = h.load(0x5000, v);
        try std.testing.expectEqual(@as(?Gadget, null), h.load(0x9000 + (v * v) % 251, 0));
    }
    // The earlier load is always at one address (an index reloaded from
    // the stack): not the load the index addresses.
    var r: Detector = .{};
    for (0..4) |x| {
        r.check(0x3800);
        _ = r.load(0x7000, x);
        try std.testing.expectEqual(@as(?Gadget, null), r.load(0x5000 + x, 0));
    }
    // No window: nothing is kept.
    var n: Detector = .{};
    try std.testing.expectEqual(@as(?Gadget, null), n.load(0x9000, 1));
    // The window closes after its edges.
    d.check(0x4000);
    for (0..window_edges + 1) |_| d.edge();
    try std.testing.expectEqual(@as(?u8, null), d.open);
}
