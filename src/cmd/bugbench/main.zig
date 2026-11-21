//! The bug benchmark (plan3.md F1, F2): small programs, each with one
//! class of bug planted and the same program fixed.
//!
//! For each program this prints:
//! - **plain run:** the buggy program run once with every decision benign
//!   (no fault, no preemption, nothing lost in a crash, the smallest
//!   input), which is what an ordinary test of it sees;
//! - **found:** whether a campaign finds the bug, in how long, and what the
//!   failure shrinks to;
//! - **fix:** whether the fixed program passes the same campaign.
//!
//! The process exits with 1 if a campaign misses a planted bug or a fixed
//! program fails, so CI can hold the table to its word.
//!
//! `zig build bugbench-rates` prints the detection table instead
//! (plan3.md A5): for each program, which oracle catches its bug, and in
//! how many of 20 campaigns with different seeds, at 10, 50 and 200
//! iterations. One campaign finding a bug says little about the next
//! one; the rate says how large a campaign has to be.

const std = @import("std");
const tardis = @import("tardis");

fn Run(comptime body: fn (*tardis.Env) anyerror!void) type {
    return struct {
        fn check(gpa: std.mem.Allocator, options: tardis.Options) anyerror!void {
            return tardis.check(gpa, body, options);
        }
    };
}

fn row(gpa: std.mem.Allocator, io: std.Io, comptime name: []const u8, comptime class: []const u8, comptime module: type) !bool {
    // A program that needs a mode this system does not have (system-call
    // mode is Linux on x86_64) is listed, not run.
    if (@hasDecl(module, "supported") and (!module.supported or !tardis.syscallModeAvailable())) {
        std.debug.print("| `{s}` | {s} | not run: no system-call mode on this system | | | | |\n", .{ name, class });
        return true;
    }
    // A program's own campaign options (personas, faults, nodes), if it
    // names any.
    var base: tardis.Options = if (@hasDecl(module, "options")) module.options else .{ .iterations = 200 };
    base.report = false;

    // An ordinary test: one run, every decision benign.
    var plain = base;
    plain.replay = "linux_ext4:0x1::";
    const plain_found = if (Run(module.buggy).check(gpa, plain)) |_| false else |_| true;

    var shrunk: tardis.ShrinkReport = .{};
    var campaign = base;
    campaign.shrink_report = &shrunk;
    const t0 = std.Io.Clock.awake.now(io).nanoseconds;
    const found = if (Run(module.buggy).check(gpa, campaign)) |_| false else |_| true;
    const elapsed_ms = @divTrunc(std.Io.Clock.awake.now(io).nanoseconds - t0, std.time.ns_per_ms);

    var fix = base;
    fix.shrink = false;
    const fix_holds = if (Run(module.fixed).check(gpa, fix)) |_| true else |_| false;

    var reduced: [48]u8 = undefined;
    const reduced_text = if (shrunk.shrunk)
        std.fmt.bufPrint(&reduced, "{d} -> {d} decisions", .{ shrunk.before, shrunk.after }) catch unreachable
    else
        "not shrunk";
    std.debug.print("| `{s}` | {s} | {s} | {s} | {d} ms | {s} | {s} |\n", .{
        name,
        class,
        if (plain_found) "fails" else "passes",
        if (found) "yes" else "NO",
        elapsed_ms,
        if (found) reduced_text else "",
        if (fix_holds) "passes" else "FAILS",
    });
    return found and fix_holds;
}

/// The oracle behind an error `check` returned.
fn oracleOf(err: anyerror) []const u8 {
    return switch (err) {
        error.AssertionFailed => "`always`",
        error.SometimesNeverTrue => "`sometimes`",
        error.Deadlock => "deadlock",
        error.Livelock => "`expectProgress`",
        error.ResourceLeak => "leak check",
        error.NonDeterministic => "determinism check",
        error.StraySyscall => "stray system call",
        error.SecurityViolation => "security layer",
        else => "the body's own error",
    };
}

const rate_campaigns = 20;
const rate_sizes = [_]u32{ 10, 50, 200 };

fn rateRow(gpa: std.mem.Allocator, io: std.Io, comptime name: []const u8, comptime class: []const u8, comptime module: type) !bool {
    _ = io;
    if (@hasDecl(module, "supported") and (!module.supported or !tardis.syscallModeAvailable())) {
        std.debug.print("| `{s}` | {s} | not run: no system-call mode on this system | | | |\n", .{ name, class });
        return true;
    }
    var base: tardis.Options = if (@hasDecl(module, "options")) module.options else .{};
    base.report = false;
    base.shrink = false;
    var found: [rate_sizes.len]u32 = @splat(0);
    var oracle: []const u8 = "";
    var mixed = false;
    for (rate_sizes, &found) |size, *n| {
        for (0..rate_campaigns) |c| {
            var o = base;
            o.iterations = size;
            o.campaign_seed = tardis.default_campaign_seed +% 0x9E37_79B9 *% (c + 1);
            if (Run(module.buggy).check(gpa, o)) |_| {} else |err| {
                n.* += 1;
                const by = oracleOf(err);
                if (oracle.len != 0 and !std.mem.eql(u8, oracle, by)) mixed = true;
                oracle = by;
            }
        }
    }
    std.debug.print("| `{s}` | {s} | {s}{s} | {d}/{d} | {d}/{d} | {d}/{d} |\n", .{
        name,     class,          if (oracle.len == 0) "none" else oracle, if (mixed) " and others" else "",
        found[0], rate_campaigns, found[1],                                rate_campaigns,
        found[2], rate_campaigns,
    });
    // The largest size must find it every time: the table is the claim.
    return found[rate_sizes.len - 1] == rate_campaigns;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args = try init.minimal.args.iterateAllocator(gpa);
    defer args.deinit();
    _ = args.skip();
    const rates = if (args.next()) |a| std.mem.eql(u8, a, "--rates") else false;
    if (rates) {
        std.debug.print("| Program | Bug class | Caught by | 10 iterations | 50 iterations | 200 iterations |\n|---|---|---|---|---|---|\n", .{});
        if (!try all(gpa, io, rateRow)) {
            std.debug.print("\nbugbench: a planted bug was missed by a campaign of 200 iterations\n", .{});
            std.process.exit(1);
        }
        return;
    }
    std.debug.print("| Program | Bug class | Plain run of the bug | Found by a campaign | Time | Reproduction | The fix |\n|---|---|---|---|---|---|---|\n", .{});
    if (!try all(gpa, io, row)) {
        std.debug.print("\nbugbench: a planted bug was missed, or a fix failed\n", .{});
        std.process.exit(1);
    }
}

fn all(gpa: std.mem.Allocator, io: std.Io, comptime each: anytype) !bool {
    var ok = true;
    ok = try each(gpa, io, "wal_kv", "acknowledged before durable", @import("wal_kv")) and ok;
    ok = try each(gpa, io, "dir_sync", "missing fsync of a directory", @import("dir_sync")) and ok;
    ok = try each(gpa, io, "rename_unsynced", "renamed before the data is durable", @import("rename_unsynced")) and ok;
    ok = try each(gpa, io, "syscall_rename", "renamed before the data is durable, by system call", @import("syscall_rename")) and ok;
    ok = try each(gpa, io, "in_place_rewrite", "a file rewritten in place", @import("in_place_rewrite")) and ok;
    ok = try each(gpa, io, "index_before_data", "two files made durable in the wrong order", @import("index_before_data")) and ok;
    ok = try each(gpa, io, "id_reuse", "identifier handed out twice after a restart", @import("id_reuse")) and ok;
    ok = try each(gpa, io, "jobs", "applied twice after a restart", @import("jobs")) and ok;
    ok = try each(gpa, io, "short_write", "short write taken for a whole one", @import("short_write")) and ok;
    ok = try each(gpa, io, "short_read", "short read taken for a whole one", @import("short_read")) and ok;
    ok = try each(gpa, io, "error_leak", "resource leaked on an error path", @import("error_leak")) and ok;
    ok = try each(gpa, io, "oom_partial", "half-finished update when memory runs out", @import("oom_partial")) and ok;
    ok = try each(gpa, io, "counter", "lost update between tasks", @import("counter")) and ok;
    ok = try each(gpa, io, "check_then_act", "check, then act", @import("check_then_act")) and ok;
    ok = try each(gpa, io, "deadlock", "deadlock from lock order", @import("deadlock")) and ok;
    ok = try each(gpa, io, "livelock", "livelock from retrying in step", @import("livelock")) and ok;
    ok = try each(gpa, io, "hidden_state", "state that survives a run", @import("hidden_state")) and ok;
    ok = try each(gpa, io, "never_retried", "code the test never reaches", @import("never_retried")) and ok;
    ok = try each(gpa, io, "lease", "a duration measured with the wall clock", @import("lease")) and ok;
    ok = try each(gpa, io, "udp_retry", "a retry applied twice", @import("udp_retry")) and ok;
    ok = try each(gpa, io, "udp_order", "trusting the order of arrival", @import("udp_order")) and ok;
    ok = try each(gpa, io, "udp_no_timeout", "waiting for ever for a lost message", @import("udp_no_timeout")) and ok;
    ok = try each(gpa, io, "stale_read", "a stale read from a follower", @import("stale_read")) and ok;
    ok = try each(gpa, io, "replica", "replica left behind by a partition", @import("replica")) and ok;
    return ok;
}
