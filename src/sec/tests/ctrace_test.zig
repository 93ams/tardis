//! The tracer for instrumented C (plan2.md §6.3): C built with clang's
//! SanitizerCoverage (`tests/c/ct.c`) adds its edges and divisor widths to
//! the traces that `assertConstantTime` compares, and keeps the constants
//! it compares against.

const std = @import("std");
const tardis = @import("tardis");
const sec = @import("tardis_sec");
const Env = tardis.Env;
const gpa = std.testing.allocator;

comptime {
    sec.exportCoverage();
    sec.exportC();
}

extern fn tag_equal_early_exit(a: [*]const u8, b: [*]const u8, n: usize) c_int;
extern fn tag_equal_constant_time(a: [*]const u8, b: [*]const u8, n: usize) c_int;
extern fn bucket(x: c_uint, m: c_uint) c_uint;
extern fn command_code(s: [*:0]const u8, magic: c_uint) c_int;
extern fn lookup_indexed(secret: u8) c_uint;
extern fn lookup_scan(secret: u8) c_uint;
extern fn header_accepted(magic: c_uint) c_int;
extern fn spectre_victim(x: usize) c_uint;
extern fn spectre_hardened(x: usize) c_uint;
extern fn spectre_plain(x: usize) c_uint;

/// A forged tag the attacker sends; the secret is the expected tag.
const forged: [16]u8 = @splat(0);
/// Differs from the forgery in its last byte, and in its first.
const tag_late: [16]u8 = withByte(15, 1);
const tag_early: [16]u8 = @splat(1);

/// Sixteen zero bytes but one.
fn withByte(comptime at: usize, comptime value: u8) [16]u8 {
    var t: [16]u8 = @splat(0);
    t[at] = value;
    return t;
}

fn earlyExit(env: *Env, public: []const u8, secret: []const u8) anyerror!void {
    _ = env;
    _ = public;
    try std.testing.expectEqual(@as(c_int, 0), tag_equal_early_exit(&forged, secret.ptr, forged.len));
}

fn constantTime(env: *Env, public: []const u8, secret: []const u8) anyerror!void {
    _ = env;
    _ = public;
    try std.testing.expectEqual(@as(c_int, 0), tag_equal_constant_time(&forged, secret.ptr, forged.len));
}

test "C tracer: an early-exit tag compare is a timing leak with no I/O to show it; a constant-time one is not" {
    try std.testing.expectError(error.TimingLeak, sec.assertConstantTime(gpa, earlyExit, &tag_late, &tag_early, 4, .{}));
    try sec.assertConstantTime(gpa, constantTime, &tag_late, &tag_early, 4, .{});
    try sec.assertNonInterference(gpa, constantTime, "pub", &tag_late, &tag_early, 4, .{});
}

fn secretModulus(env: *Env, public: []const u8, secret: []const u8) anyerror!void {
    _ = env;
    _ = public;
    _ = bucket(1_000_003, @as(c_uint, secret[0]) | 1);
}

fn publicModulus(env: *Env, public: []const u8, secret: []const u8) anyerror!void {
    _ = env;
    _ = secret;
    _ = bucket(1_000_003, @as(c_uint, public[0]) | 1);
}

test "C tracer: dividing by a secret of another width is a timing leak; dividing by a public value is not" {
    const narrow = withByte(0, 3);
    const wide = withByte(0, 201);
    try std.testing.expectError(error.TimingLeak, sec.assertConstantTime(gpa, secretModulus, &narrow, &wide, 4, .{}));
    try sec.assertNonInterference(gpa, publicModulus, "q", &narrow, &wide, 4, .{});
}

fn parseCommands(env: *Env) !void {
    _ = env;
    _ = command_code("GET", 1);
    _ = command_code("PUT", 2);
}

test "C tracer: edges and comparisons are counted, and compared constants kept, only inside a simulation" {
    sec.c_trace.reset();
    _ = command_code("GET", 1);
    try std.testing.expectEqual(@as(u64, 0), sec.c_trace.current().edges);
    _ = try tardis.traceHash(gpa, parseCommands, 1, .linux_ext4, .{});
    const t = sec.c_trace.current();
    try std.testing.expect(t.edges > 0);
    try std.testing.expect(t.comparisons >= 4);
    for ([_]u64{ 0x7A3D51C9, 'G', 'P', 'D' }) |k| {
        if (std.mem.indexOfScalar(u64, t.constants(), k) == null) {
            std.debug.print("constant 0x{x} not kept: {any}\n", .{ k, t.constants() });
            return error.TestUnexpectedResult;
        }
    }
}

fn indexedLookup(env: *Env, public: []const u8, secret: []const u8) anyerror!void {
    _ = env;
    _ = public;
    _ = lookup_indexed(secret[0]);
}

fn scanLookup(env: *Env, public: []const u8, secret: []const u8) anyerror!void {
    _ = env;
    _ = public;
    _ = lookup_scan(secret[0]);
}

test "C tracer: a table lookup indexed by a secret is a timing leak through the cache; a full scan is not" {
    // Entries 0 and 200 are 12 cache lines apart.
    const first = withByte(0, 0);
    const far = withByte(0, 200);
    try std.testing.expectError(error.TimingLeak, sec.assertConstantTime(gpa, indexedLookup, &first, &far, 4, .{}));
    try sec.assertConstantTime(gpa, scanLookup, &first, &far, 4, .{});
    // Both read the same entry (outside a simulation, untraced).
    try std.testing.expectEqual(lookup_indexed(200), lookup_scan(200));
}

fn magicHeader(env: *Env) !void {
    const magic = try env.fuzz(u32);
    // The planted bug: the accepted header crashes the parser.
    if (header_accepted(magic) != 0) return error.MagicAccepted;
}

test "C tracer: comparison constants steer guided exploration past a magic-number check" {
    var steered: tardis.ExploreReport = .{};
    try std.testing.expectError(error.MagicAccepted, tardis.check(gpa, magicHeader, sec.withSecurity(.{ .base = .{
        .iterations = 2000,
        .explore = .guided,
        .explore_report = &steered,
        .report = false,
    } })));
    try std.testing.expect(steered.tokens >= 1);
    try std.testing.expect(steered.failed_at.? < 2000);
    // Two workers merge each run's constants in job order.
    var parallel: tardis.ExploreReport = .{};
    try std.testing.expectError(error.MagicAccepted, tardis.check(gpa, magicHeader, sec.withSecurity(.{ .base = .{
        .iterations = 2000,
        .workers = 2,
        .explore = .guided,
        .explore_report = &parallel,
        .report = false,
    } })));
    // Without the layer there is no feedback, and 2,000 random draws do not
    // find one value in 2^32. (Under `-Dsec` every check has the layer.)
    if (!tardis.security_by_default) try tardis.check(gpa, magicHeader, .{ .iterations = 2000, .explore = .guided });
}

const zig_table = [16]u8{ 7, 200, 13, 91, 164, 2, 255, 38, 119, 66, 181, 20, 233, 144, 5, 97 };
var zig_probe: [256 * 64]u8 = @splat(0);

const Lookup = enum { c_victim, c_hardened, c_plain, zig_victim, zig_hardened };

fn Indexed(comptime lookup: Lookup) type {
    return struct {
        fn body(env: *Env) !void {
            // The attacker's index, in bounds here: the shape shows there.
            const x: usize = (try env.fuzz(u8)) % 16;
            switch (lookup) {
                .c_victim => _ = spectre_victim(x),
                .c_hardened => _ = spectre_hardened(x),
                .c_plain => _ = spectre_plain(x),
                .zig_victim => if (sec.spectre.boundsCheck(x, zig_table.len)) {
                    const v = sec.spectre.load(&zig_table[x]);
                    _ = sec.spectre.load(&zig_probe[@as(usize, v) * 64]);
                },
                .zig_hardened => if (x < zig_table.len) {
                    const i = sec.spectre.indexNoSpec(x, zig_table.len);
                    _ = zig_probe[@as(usize, zig_table[i]) * 64];
                },
            }
        }
    };
}

test "Spectre-v1: a load addressed by a value loaded after a bounds check is CWE-1037, in C and in Zig; a hardened index and plain loads pass" {
    inline for (.{ Lookup.c_victim, Lookup.zig_victim }) |lookup| {
        var report: sec.engine.Report = .{};
        try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, Indexed(lookup).body, sec.withSecurity(.{
            .report = &report,
            .base = .{ .iterations = 200, .report = false, .shrink = false },
        })));
        const f = report.findings[0];
        try std.testing.expectEqual(@as(u16, 1037), f.cwe);
        try std.testing.expectEqual(sec.engine.Kind.spectre_v1, f.kind);
        // 64 bytes per unit of the table's value.
        try std.testing.expectEqual(@as(u16, 64), f.detail[0]);
    }
    inline for (.{ Lookup.c_hardened, Lookup.c_plain, Lookup.zig_hardened }) |lookup| {
        try tardis.check(gpa, Indexed(lookup).body, sec.withSecurity(.{ .base = .{ .iterations = 200 } }));
    }
    try std.testing.expectEqual(@as(usize, 0), sec.spectre.indexNoSpec(16, 16));
    try std.testing.expectEqual(@as(usize, 15), sec.spectre.indexNoSpec(15, 16));
}
