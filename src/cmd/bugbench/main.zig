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

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    std.debug.print("| Program | Bug class | Plain run of the bug | Found by a campaign | Time | Reproduction | The fix |\n|---|---|---|---|---|---|---|\n", .{});
    var ok = true;
    ok = try row(gpa, io, "wal_kv", "acknowledged before durable", @import("wal_kv")) and ok;
    ok = try row(gpa, io, "dir_sync", "missing fsync of a directory", @import("dir_sync")) and ok;
    ok = try row(gpa, io, "rename_unsynced", "renamed before the data is durable", @import("rename_unsynced")) and ok;
    ok = try row(gpa, io, "in_place_rewrite", "a file rewritten in place", @import("in_place_rewrite")) and ok;
    ok = try row(gpa, io, "index_before_data", "two files made durable in the wrong order", @import("index_before_data")) and ok;
    ok = try row(gpa, io, "id_reuse", "identifier handed out twice after a restart", @import("id_reuse")) and ok;
    ok = try row(gpa, io, "jobs", "applied twice after a restart", @import("jobs")) and ok;
    ok = try row(gpa, io, "short_write", "short write taken for a whole one", @import("short_write")) and ok;
    ok = try row(gpa, io, "short_read", "short read taken for a whole one", @import("short_read")) and ok;
    ok = try row(gpa, io, "error_leak", "resource leaked on an error path", @import("error_leak")) and ok;
    ok = try row(gpa, io, "oom_partial", "half-finished update when memory runs out", @import("oom_partial")) and ok;
    ok = try row(gpa, io, "counter", "lost update between tasks", @import("counter")) and ok;
    ok = try row(gpa, io, "check_then_act", "check, then act", @import("check_then_act")) and ok;
    ok = try row(gpa, io, "deadlock", "deadlock from lock order", @import("deadlock")) and ok;
    ok = try row(gpa, io, "lease", "a duration measured with the wall clock", @import("lease")) and ok;
    ok = try row(gpa, io, "replica", "replica left behind by a partition", @import("replica")) and ok;
    if (!ok) {
        std.debug.print("\nbugbench: a planted bug was missed, or a fix failed\n", .{});
        std.process.exit(1);
    }
}
