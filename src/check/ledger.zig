//! Deterministic cost ledger (plan §9 M4): integer latency histograms and
//! ratios, so performance properties can be asserted as exactly as
//! correctness ones ("p99 of a PUT stays under 20 ms of virtual time",
//! "write amplification stays under 50x").
//!
//! Virtual time and byte counts are deterministic, so these assertions
//! replay and shrink like any other.

const std = @import("std");
const assert = std.debug.assert;
const decide = @import("../sim/decide.zig");

/// Log-linear buckets: exact below 16, then 16 sub-buckets per power of two
/// (at most 6.25% relative error), covering all of `u64`.
pub const Histogram = struct {
    counts: [bucket_count]u64 = @splat(0),
    total: u64 = 0,
    min: u64 = std.math.maxInt(u64),
    max: u64 = 0,
    sum: u128 = 0,

    const sub_bits = 4;
    const sub = 1 << sub_bits;
    /// Number of buckets: 16 exact ones, then 16 for each power of two up to 2^63.
    pub const bucket_count = sub + (64 - sub_bits) * sub;

    fn bucketOf(v: u64) usize {
        if (v < sub) return @intCast(v);
        const e: u6 = @intCast(63 - @clz(v)); // >= sub_bits
        const mantissa: u64 = (v >> (e - sub_bits)) & (sub - 1);
        return sub + (@as(usize, e) - sub_bits) * sub + @as(usize, @intCast(mantissa));
    }

    /// Largest value that falls into bucket `b`.
    fn bucketMax(b: usize) u64 {
        if (b < sub) return b;
        const e: u6 = @intCast((b - sub) / sub + sub_bits);
        const mantissa: u64 = (b - sub) % sub;
        const lo = (@as(u64, 1) << e) | (mantissa << (e - sub_bits));
        const width = @as(u64, 1) << (e - sub_bits);
        return lo + (width - 1);
    }

    /// Adds one sample `v`, in whatever unit the caller measures (for example
    /// nanoseconds of virtual time, or bytes). Never fails or allocates.
    pub fn record(h: *Histogram, v: u64) void {
        h.counts[bucketOf(v)] += 1;
        h.total += 1;
        h.min = @min(h.min, v);
        h.max = @max(h.max, v);
        h.sum += v;
    }

    /// The value at quantile `q` (in ppm: 990_000 is p99), reported as the
    /// upper bound of its bucket, capped at the maximum seen. 0 if empty.
    pub fn quantile(h: *const Histogram, q: decide.Ppm) u64 {
        if (h.total == 0) return 0;
        assert(q <= decide.ppm_one);
        if (q == 0) return h.min;
        // Smallest rank r with r / total >= q.
        const rank = @max(1, (@as(u128, h.total) * q + decide.ppm_one - 1) / decide.ppm_one);
        var seen: u64 = 0;
        for (h.counts, 0..) |c, b| {
            seen += c;
            if (seen >= rank) return @min(bucketMax(b), h.max);
        }
        unreachable;
    }

    /// The exact arithmetic mean of the recorded samples, rounded down. 0 if empty.
    pub fn mean(h: *const Histogram) u64 {
        if (h.total == 0) return 0;
        return @intCast(h.sum / h.total);
    }
};

/// `numerator / denominator` in ppm (1_000_000 = 1x), saturating.
pub fn ratioPpm(numerator: u64, denominator: u64) u64 {
    if (denominator == 0) return if (numerator == 0) 0 else std.math.maxInt(u64);
    const r = @as(u128, numerator) * decide.ppm_one / denominator;
    return @intCast(@min(r, std.math.maxInt(u64)));
}

const testing = std.testing;

test "histogram buckets round-trip and bound relative error" {
    var v: u64 = 1;
    while (v < (1 << 60)) : (v = v * 3 + 7) {
        const b = Histogram.bucketOf(v);
        try testing.expect(Histogram.bucketMax(b) >= v);
        try testing.expect(b == 0 or Histogram.bucketMax(b - 1) < v);
        try testing.expect(Histogram.bucketMax(b) - v <= v / 16 + 1);
    }
    try testing.expectEqual(Histogram.bucket_count - 1, Histogram.bucketOf(std.math.maxInt(u64)));
}

test "histogram quantiles" {
    var h: Histogram = .{};
    for (1..101) |i| h.record(i * 1000);
    try testing.expectEqual(@as(u64, 1000), h.quantile(0));
    const p50 = h.quantile(500_000);
    try testing.expect(p50 >= 50_000 and p50 <= 53_000);
    const p99 = h.quantile(990_000);
    try testing.expect(p99 >= 99_000 and p99 <= 100_000);
    try testing.expectEqual(@as(u64, 100_000), h.quantile(decide.ppm_one));
    try testing.expectEqual(@as(u64, 50_500), h.mean());
    try testing.expectEqual(@as(u64, 2_500_000), ratioPpm(5, 2));
}
