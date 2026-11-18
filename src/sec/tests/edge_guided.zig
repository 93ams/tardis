//! Edge coverage as guidance (`plan.md` §9 M3, plan2.md §7.1): built with
//! Zig's edge counters (`zig build test-edges`, an ELF or Mach-O target),
//! guided exploration keeps a run that reaches new code, so it gets
//! through a check that compares its input one byte at a time. The body
//! does no I/O: without the counters every run looks the same.

const std = @import("std");
const tardis = @import("tardis");
const sec = @import("tardis_sec");
const Env = tardis.Env;
const gpa = std.testing.allocator;

const magic = "ZIG";

/// Each byte has its own code (`inline for`), so each match runs an edge
/// no shorter match ran. A loop would not do: its second pass runs the
/// edges of its first, and an edge counts once however often it runs.
fn header(env: *Env) !void {
    inline for (magic) |want| {
        if (try env.fuzz(u8) != want) return;
    }
    return error.HeaderAccepted;
}

test "edge coverage: guided exploration gets through a byte-by-byte check that random exploration does not" {
    try std.testing.expect(sec.edges.instrumented);
    var report: tardis.ExploreReport = .{};
    try std.testing.expectError(error.HeaderAccepted, tardis.check(gpa, header, sec.withSecurity(.{ .base = .{
        .iterations = 200_000,
        .explore = .guided,
        .explore_report = &report,
        .report = false,
        .shrink = false,
    } })));
    // Measured: iteration 15,388, with 6 corpus entries.
    try std.testing.expect(report.failed_at.? < 200_000);
    try std.testing.expect(report.corpus >= magic.len);
    // Three bytes at random: one run in 2^24.
    try tardis.check(gpa, header, sec.withSecurity(.{ .base = .{ .iterations = 200_000 } }));
}
