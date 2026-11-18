//! Pillar IV: resource amplification (plan2.md §6.1, CWE-400 / CWE-407).
//!
//! Per run, untrusted input bytes are set against four costs. Ratios are
//! integers in thousandths. A ratio over its limit is a finding; the peak
//! ratios are also coverage features, so guided exploration keeps and
//! mutates the inputs that push them up. That is how a hash-flooding input
//! is synthesized instead of waited for.

const std = @import("std");

pub const Limits = struct {
    /// Work units (`tardis_sec.work`, e.g. hash probes or loop steps) per
    /// input byte. With an edge tracer this would count edges (§6.1).
    work_per_input_byte_milli_max: u32 = 64_000,
    alloc_bytes_per_input_byte_milli_max: u32 = 32_000,
    tx_bytes_per_rx_byte_milli_max: u32 = 10_000,
    /// 4 KiB pages written to files per input byte.
    file_pages_per_input_byte_milli_max: u32 = 2_000,
};

pub const Ratio = enum(u8) {
    work_per_input_byte,
    alloc_bytes_per_input_byte,
    tx_bytes_per_rx_byte,
    file_pages_per_input_byte,

    pub fn cwe(r: Ratio) u16 {
        return switch (r) {
            .work_per_input_byte => 407, // inefficient algorithmic complexity
            else => 400, // uncontrolled resource consumption
        };
    }
};

pub const Ledger = struct {
    /// Bytes from the network, plus bytes declared with `tardis_sec.input`.
    input_bytes: u64 = 0,
    work_units: u64 = 0,
    alloc_bytes: u64 = 0,
    rx_bytes: u64 = 0,
    tx_bytes: u64 = 0,
    file_bytes: u64 = 0,

    pub fn milli(num: u64, den: u64) u64 {
        return if (den == 0) 0 else num *| 1000 / den;
    }

    pub fn ratio(l: Ledger, r: Ratio) u64 {
        return switch (r) {
            .work_per_input_byte => milli(l.work_units, l.input_bytes),
            .alloc_bytes_per_input_byte => milli(l.alloc_bytes, l.input_bytes),
            .tx_bytes_per_rx_byte => milli(l.tx_bytes, l.rx_bytes),
            .file_pages_per_input_byte => milli((l.file_bytes + 4095) / 4096, l.input_bytes),
        };
    }

    fn limit(lim: Limits, r: Ratio) u64 {
        return switch (r) {
            .work_per_input_byte => lim.work_per_input_byte_milli_max,
            .alloc_bytes_per_input_byte => lim.alloc_bytes_per_input_byte_milli_max,
            .tx_bytes_per_rx_byte => lim.tx_bytes_per_rx_byte_milli_max,
            .file_pages_per_input_byte => lim.file_pages_per_input_byte_milli_max,
        };
    }

    /// The first ratio over its limit, or null.
    pub fn exceeded(l: Ledger, lim: Limits) ?Ratio {
        inline for (@typeInfo(Ratio).@"enum".field_names) |name| {
            const r = @field(Ratio, name);
            if (l.ratio(r) > limit(lim, r)) return r;
        }
        return null;
    }
};

/// Log-linear bucket: 8 buckets per power of two, so small ratio gains are
/// still new features while the feature count stays bounded (≤ 512).
pub fn bucket(x: u64) u16 {
    if (x < 8) return @intCast(x);
    const log: u6 = @intCast(63 - @clz(x));
    const frac: u64 = (x >> (log - 3)) & 7;
    return @intCast((@as(u64, log) << 3) | frac);
}

/// Packs limits into two seam parameter words.
pub fn pack(lim: Limits) [2]u64 {
    return .{
        (@as(u64, lim.work_per_input_byte_milli_max) << 32) | lim.alloc_bytes_per_input_byte_milli_max,
        (@as(u64, lim.tx_bytes_per_rx_byte_milli_max) << 32) | lim.file_pages_per_input_byte_milli_max,
    };
}

pub fn unpack(w: [2]u64) Limits {
    return .{
        .work_per_input_byte_milli_max = @truncate(w[0] >> 32),
        .alloc_bytes_per_input_byte_milli_max = @truncate(w[0]),
        .tx_bytes_per_rx_byte_milli_max = @truncate(w[1] >> 32),
        .file_pages_per_input_byte_milli_max = @truncate(w[1]),
    };
}

test "ratios, limits, buckets, packing" {
    var l: Ledger = .{ .input_bytes = 10, .work_units = 700 };
    try std.testing.expectEqual(@as(u64, 70_000), l.ratio(.work_per_input_byte));
    try std.testing.expectEqual(Ratio.work_per_input_byte, l.exceeded(.{}).?);
    l.work_units = 10;
    try std.testing.expectEqual(@as(?Ratio, null), l.exceeded(.{}));
    try std.testing.expectEqual(@as(u16, 5), bucket(5));
    try std.testing.expect(bucket(1000) < bucket(1200));
    try std.testing.expect(bucket(std.math.maxInt(u64)) < 512);
    const lim: Limits = .{ .work_per_input_byte_milli_max = 4_000 };
    try std.testing.expectEqual(lim, unpack(pack(lim)));
}
