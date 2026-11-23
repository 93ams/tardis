//! `zig build secrates`: the detection table of the security layer's
//! oracles (plan3.md A5). Each row is a planted bug from the layer's own
//! tests (`src/sec/tests/pillar*_test.zig`), with the layer options its
//! test uses (the iterations, the campaign seed and shrinking are this
//! program's), and the count of 20 campaigns that found it at three
//! campaign sizes. The 20 campaign seeds are the same at every size, so
//! the columns are nested, not independent samples: with random
//! exploration a campaign of 10 iterations is the first 10 runs of the
//! campaign of 200. The fixed version of the same program, where its test
//! has one, runs in the same 20 campaigns of 200 iterations, and the count
//! of those that failed is its false alarms.
//!
//! The command fails if a campaign of 200 iterations misses a bug the row
//! expects found, if a fixed version fails, or if, at 50,000 iterations,
//! guided exploration never floods the hash table or random exploration
//! does.

const std = @import("std");
const tardis = @import("tardis");
const sec = @import("tardis_sec");
const p1 = @import("pillar1");
const p2 = @import("pillar2");
const p45 = @import("pillar45");
const Env = tardis.Env;

const campaigns = 20;
const sizes = [_]u32{ 10, 50, 200 };

const Body = *const fn (*Env) anyerror!void;

const Row = struct {
    name: []const u8,
    class: []const u8,
    buggy: Body,
    /// Null where the test has no fixed version.
    fixed: ?Body,
    config: sec.SecurityConfig,
    /// A row whose finding this build cannot see (see `secret_not_zeroed`).
    expected: bool = true,
};

fn Run(comptime body: Body) type {
    return struct {
        fn f(env: *Env) anyerror!void {
            return body(env);
        }
    };
}

/// Runs one campaign; returns what found the bug, or null.
fn campaign(gpa: std.mem.Allocator, comptime body: Body, r: Row, size: u32, c: usize, buf: []u8) ?[]const u8 {
    var report: sec.engine.Report = .{};
    var cfg = r.config;
    cfg.report = &report;
    cfg.base.iterations = size;
    cfg.base.report = false;
    cfg.base.shrink = false;
    cfg.base.campaign_seed = tardis.default_campaign_seed +% 0x9E37_79B9 *% (c + 1);
    if (tardis.check(gpa, Run(body).f, sec.withSecurity(cfg))) |_| return null else |err| return switch (err) {
        error.SecurityViolation => if (report.len > 0)
            std.fmt.bufPrint(buf, "CWE-{d}", .{report.findings[0].cwe}) catch "CWE"
        else
            "the layer, no finding kept",
        error.AssertionFailed => "the program's `always`",
        else => @errorName(err),
    };
}

fn row(gpa: std.mem.Allocator, comptime r: Row) bool {
    var found: [sizes.len]u32 = @splat(0);
    var by_buf: [32]u8 = undefined;
    var by: []const u8 = "";
    var by_store: [32]u8 = undefined;
    var mixed = false;
    for (sizes, &found) |size, *n| {
        for (0..campaigns) |c| {
            if (campaign(gpa, r.buggy, r, size, c, &by_buf)) |what| {
                n.* += 1;
                if (by.len != 0 and !std.mem.eql(u8, by, what)) mixed = true;
                const len = @min(what.len, by_store.len);
                @memcpy(by_store[0..len], what[0..len]);
                by = by_store[0..len];
            }
        }
    }
    var alarms: u32 = 0;
    var alarms_buf: [16]u8 = undefined;
    const alarms_text = if (r.fixed) |fixed| blk: {
        for (0..campaigns) |c| {
            if (campaign(gpa, fixed, r, sizes[sizes.len - 1], c, &by_buf)) |_| alarms += 1;
        }
        break :blk std.fmt.bufPrint(&alarms_buf, "{d}/{d}", .{ alarms, campaigns }) catch unreachable;
    } else "no fixed version";
    std.debug.print("| {s} | {s} | {s}{s} | {d}/{d} | {d}/{d} | {d}/{d} | {s} |\n", .{
        r.name,   r.class,   if (by.len == 0) "none" else by, if (mixed) " and others" else "",
        found[0], campaigns, found[1],                        campaigns,
        found[2], campaigns, alarms_text,
    });
    const caught = found[sizes.len - 1] == campaigns;
    return alarms == 0 and (if (r.expected) caught else found[sizes.len - 1] == 0);
}

const steer_toctou = 200_000;
const steer_byzantine = 500_000;

const rows = [_]Row{
    .{ .name = "uninitialized tail", .class = "uninitialized heap bytes written to a file", .buggy = p1.uninitTail, .fixed = p1.initOnly, .config = .{} },
    .{ .name = "use after free", .class = "freed bytes written to a file", .buggy = p1.useAfterFree, .fixed = null, .config = .{} },
    .{ .name = "write past the end", .class = "a copy longer than its buffer", .buggy = p1.overflowField, .fixed = p1.boundedField, .config = .{} },
    .{ .name = "over-read", .class = "a reply longer than its buffer", .buggy = p1.overRead, .fixed = p1.boundedRead, .config = .{} },
    .{ .name = "secret logged", .class = "part of a marked key in a log file", .buggy = p1.keyLogged, .fixed = p1.keyZeroized, .config = .{} },
    .{ .name = "secret not zeroed", .class = "a marked key freed without zeroing", .buggy = p1.keyNotZeroized, .fixed = p1.keyZeroized, .config = .{}, .expected = !sec.engine.safe_fill },
    .{ .name = "Heartbleed", .class = "one tenant's record echoed to another tenant", .buggy = p1.heartbleed, .fixed = p1.heartbeatFixed, .config = .{ .base = .{ .nodes = 2 } } },
    .{ .name = "lock order", .class = "two `sec.Mutex` classes taken in both orders", .buggy = p2.abba, .fixed = p2.ordered, .config = .{} },
    .{ .name = "file lock order", .class = "two file locks taken in both orders", .buggy = p2.fileAbba, .fixed = p2.fileOrdered, .config = .{} },
    .{ .name = "double fetch", .class = "a shared length checked, then read again", .buggy = p2.doubleFetch, .fixed = p2.singleFetch, .config = .{} },
    .{ .name = "check-then-use", .class = "stat a name, then open the name", .buggy = p2.toctou, .fixed = p2.byHandle, .config = .{ .vfs_toctou_race_ppm = steer_toctou } },
    .{ .name = "path from the network", .class = "a received name in a path", .buggy = p2.rawName, .fixed = p2.validatedName, .config = .{ .base = .{ .nodes = 2 } } },
    .{ .name = "command from the network", .class = "a received name in a process's arguments", .buggy = p2.rawCommand, .fixed = p2.queuedOnly, .config = .{ .base = .{ .nodes = 2 } } },
    .{ .name = "capability after start", .class = "a connect after `enterSandbox`", .buggy = p2.lateReconnect, .fixed = p2.keptConnection, .config = .{ .base = .{ .nodes = 3 } } },
    .{ .name = "equivocation", .class = "followers that trust one frame of a two-faced leader", .buggy = p2.trusting, .fixed = p2.echoing, .config = .{ .byzantine_ppm = steer_byzantine, .base = .{ .nodes = 3, .faults = p2.no_loss } } },
    .{ .name = "replay", .class = "a frame recorded before a reboot accepted after it", .buggy = p2.forgetful, .fixed = p2.durableSeq, .config = .{ .byzantine_ppm = steer_byzantine, .base = .{ .nodes = 2, .faults = p2.no_loss } } },
    .{ .name = "length desync", .class = "a frame shortened in flight smuggles another", .buggy = p2.batchParser, .fixed = p2.strictParser, .config = .{ .byzantine_ppm = steer_byzantine, .base = .{ .nodes = 2, .faults = p2.no_loss } } },
};

/// Hash flooding needs a set of colliding keys that random search does
/// not find; guided exploration builds it (CWE-407). Its own sizes.
const flood_sizes = [_]u32{ 5_000, 50_000 };

fn floodRow(gpa: std.mem.Allocator, explore: tardis.Explore, comptime body: Body, label: []const u8) [flood_sizes.len]u32 {
    var found: [flood_sizes.len]u32 = @splat(0);
    for (flood_sizes, &found) |size, *n| {
        for (0..campaigns) |c| {
            var report: sec.engine.Report = .{};
            var o = sec.withSecurity(.{
                .amplification = p45.hashdos_limits,
                .report = &report,
                .base = .{ .iterations = size, .explore = explore, .report = false, .shrink = false },
            });
            o.campaign_seed = tardis.default_campaign_seed +% 0x9E37_79B9 *% (c + 1);
            if (tardis.check(gpa, Run(body).f, o)) |_| {} else |err| {
                if (err == error.SecurityViolation and report.len > 0 and report.findings[0].cwe == 407) n.* += 1;
            }
        }
    }
    std.debug.print("| {s} | {t} | {d}/{d} | {d}/{d} |\n", .{ label, explore, found[0], campaigns, found[1], campaigns });
    return found;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    std.debug.print("| Program | Planted bug | Caught by | 10 iterations | 50 iterations | 200 iterations | Fixed version, 200 iterations |\n|---|---|---|---|---|---|---|\n", .{});
    var ok = true;
    inline for (rows) |r| ok = row(gpa, r) and ok;

    std.debug.print("\n| Program | Exploration | 5,000 iterations | 50,000 iterations |\n|---|---|---|---|\n", .{});
    const guided = floodRow(gpa, .guided, p45.fixedHash, "hash flooding");
    const random = floodRow(gpa, .random, p45.fixedHash, "hash flooding");
    // Not a pass or fail: the "fixed" program seeds its hash from the run's
    // seed, and a mutated input keeps its parent's seed
    // (`explore.zig`, `Corpus.mutate`), so the search can still converge.
    _ = floodRow(gpa, .guided, p45.randomizedHash, "hash flooding, hash seeded from the run");
    if (guided[flood_sizes.len - 1] == 0 or random[flood_sizes.len - 1] != 0) ok = false;

    if (!ok) {
        std.debug.print("\nsecrates: a planted bug was missed at the largest size, or a fixed version failed\n", .{});
        std.process.exit(1);
    }
}
