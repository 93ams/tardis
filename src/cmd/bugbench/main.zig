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
//!
//! `zig build bugbench-baselines` prints the baseline table (plan3.md
//! F2): for each program, whether a campaign of its usual size still
//! finds the bug with no faults injected, with no preemption, with
//! neither, and as it is, and what the failing run shrinks to.
//!
//! `zig build bugbench-schedules` prints the schedule table (plan3.md
//! E5): for each program, in how many of 20 campaigns of 10 and of 50
//! iterations the bug is found when tasks are switched at random
//! (`Options.schedule = .random`, the default) and by priority (`.pct`)
//! at depths 1, 2 and 3, and whether the fixed program passes under
//! priorities. Two programs at its end are not examples: they are the
//! two shapes of ordering bug that tell the schedules apart.

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
        error.NotLinearizable => "`tardis.lin`",
        error.TransactionalAnomaly => "`tardis.elle`",
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

const Strategy = struct { schedule: tardis.Schedule, depth: u8 };
const strategies = [_]Strategy{
    .{ .schedule = .random, .depth = 0 },
    .{ .schedule = .pct, .depth = 1 },
    .{ .schedule = .pct, .depth = 2 },
    .{ .schedule = .pct, .depth = 3 },
};
const schedule_sizes = [_]u32{ 10, 50 };

fn scheduleRow(gpa: std.mem.Allocator, io: std.Io, comptime name: []const u8, comptime class: []const u8, comptime module: type) !bool {
    _ = io;
    _ = class;
    if (@hasDecl(module, "supported") and (!module.supported or !tardis.syscallModeAvailable())) {
        std.debug.print("| `{s}` | not run: no system-call mode on this system | | | | | | | | |\n", .{name});
        return true;
    }
    var base: tardis.Options = if (@hasDecl(module, "options")) module.options else .{};
    base.report = false;
    base.shrink = false;
    // The failure a campaign of the usual size finds: only that one is
    // counted below.
    var usual = base;
    usual.iterations = if (@hasDecl(module, "options")) module.options.iterations else 200;
    var want: ?anyerror = if (Run(module.buggy).check(gpa, usual)) |_| null else |err| err;
    if (want == null) {
        // A bug the random schedule does not reach at that size.
        usual.schedule = .pct;
        want = if (Run(module.buggy).check(gpa, usual)) |_| null else |err| err;
    }
    std.debug.print("| `{s}` |", .{name});
    for (strategies) |strategy| {
        for (schedule_sizes) |size| {
            var found: u32 = 0;
            for (0..rate_campaigns) |c| {
                var o = base;
                o.iterations = size;
                o.schedule = strategy.schedule;
                o.pct_depth = @max(1, strategy.depth);
                o.campaign_seed = tardis.default_campaign_seed +% 0x9E37_79B9 *% (c + 1);
                if (Run(module.buggy).check(gpa, o)) |_| {} else |err| {
                    if (want == null or want.? == err) found += 1;
                }
            }
            std.debug.print(" {d}/{d} |", .{ found, rate_campaigns });
        }
    }
    // A schedule must not fail a correct program: the fixed one, under
    // priorities, at the usual size.
    var fix_holds = true;
    if (@hasDecl(module, "fixed")) {
        var fix = usual;
        fix.schedule = .pct;
        fix_holds = if (Run(module.fixed).check(gpa, fix)) |_| true else |_| false;
        std.debug.print(" {s} |\n", .{if (fix_holds) "passes" else "FAILS"});
    } else std.debug.print(" |\n", .{});
    return want != null and fix_holds;
}

/// Two ordering bugs that are not examples, one for each way a schedule
/// can be hard to reach. Each has two tasks and one assertion.
const shapes = struct {
    const Io = std.Io;
    const steps = 40;

    fn work(io: Io, dir: Io.Dir, name: []const u8, n: u32, done: *bool) Io.Cancelable!void {
        for (0..n) |_| dir.writeFile(io, .{ .sub_path = name, .data = "x" }) catch {};
        done.* = true;
    }

    fn look(io: Io, dir: Io.Dir, other_done: *const bool, saw: *bool) Io.Cancelable!void {
        dir.writeFile(io, .{ .sub_path = "look", .data = "x" }) catch {};
        saw.* = other_done.*;
    }

    /// One long stretch: the bug shows when one task does all of its
    /// forty operations while the other does its one.
    const long_stretch = struct {
        pub const options: tardis.Options = .{ .iterations = 2000, .faults = quiet_faults, .swarm = false };

        pub fn buggy(env: *tardis.Env) !void {
            var done = false;
            var saw = false;
            var group: Io.Group = .init;
            defer group.cancel(env.io);
            try group.concurrent(env.io, work, .{ env.io, env.dir, "a", steps, &done });
            try group.concurrent(env.io, look, .{ env.io, env.dir, &done, &saw });
            try group.await(env.io);
            try env.always("the second task starts before the first has finished", !saw);
        }
    };

    fn bump(io: Io, dir: Io.Dir, name: []const u8, turn: *u32, me: u32, switches: *u32) Io.Cancelable!void {
        for (0..steps) |_| {
            dir.writeFile(io, .{ .sub_path = name, .data = "x" }) catch {};
            if (turn.* != me) switches.* += 1;
            turn.* = me;
        }
    }

    /// Many short stretches: the bug shows when the two tasks have
    /// taken turns twelve times.
    const many_switches = struct {
        pub const options: tardis.Options = .{ .iterations = 2000, .faults = quiet_faults, .swarm = false };

        pub fn buggy(env: *tardis.Env) !void {
            var turn: u32 = 0;
            var switches: u32 = 0;
            var group: Io.Group = .init;
            defer group.cancel(env.io);
            try group.concurrent(env.io, bump, .{ env.io, env.dir, "a", &turn, 1, &switches });
            try group.concurrent(env.io, bump, .{ env.io, env.dir, "b", &turn, 2, &switches });
            try group.await(env.io);
            try env.always("the two tasks take turns fewer than twelve times", switches < 12);
        }
    };

    /// Nothing but the schedule decides these runs.
    const quiet_faults: tardis.FaultOptions = .{ .io_error_ppm = 0, .short_io_ppm = 0, .io_latency_min_ns = 0, .io_latency_max_ns = 0 };
};

/// A campaign with a part of the exploration taken away, applied on top
/// of the program's own options.
const Baseline = enum {
    /// Schedules are explored; nothing is injected. Every rate in
    /// `Options.faults` is zero, file operations take no modeled time, a
    /// power loss neither tears a file nor loses metadata, and a crashed
    /// peer's connection is reset, never black-holed. What the body does
    /// itself (a power loss, a partition, a targeted I/O error) still
    /// happens, and a power loss still keeps or drops each unsynced
    /// file's data, whole, by a draw.
    no_faults,
    /// Faults are injected; no task is switched out at an `std.Io` call
    /// that does not block, and `io.async` never runs its task inline.
    /// When a task blocks (a lock, a sleep, a socket, the modeled time of
    /// a file operation) the next one is still drawn among those that can
    /// run.
    no_preemption,
    /// Both.
    neither,

    fn apply(b: Baseline, o: *tardis.Options) void {
        if (b != .no_preemption) {
            o.faults = .{
                .io_error_ppm = 0,
                .short_io_ppm = 0,
                .oom_ppm = 0,
                .spurious_wakeup_ppm = 0,
                .io_latency_min_ns = 0,
                .io_latency_max_ns = 0,
                .torn_writes = false,
                .metadata_loss = false,
                .net_reset_ppm = 0,
                .clock_drift_ppm_max = 0,
                .datagram_loss_ppm = 0,
                .datagram_duplicate_ppm = 0,
            };
            o.net.blackhole_ppm = 0;
        }
        if (b != .no_faults) {
            o.preempt_ppm = 0;
            o.async_inline_ppm = 0;
        }
    }
};

/// Whether the baseline campaign finds the bug. A campaign that fails
/// with the fixed program too has not found it: it fails for another
/// reason (a `sometimes` that needs a fault, say).
fn baselineCell(gpa: std.mem.Allocator, comptime module: type, base: tardis.Options, b: Baseline) []const u8 {
    // The failure the default campaign finds: a cell is "yes" only for
    // the same one.
    var plain = base;
    plain.shrink = false;
    const want: ?anyerror = if (Run(module.buggy).check(gpa, plain)) |_| null else |err| err;
    var o = base;
    b.apply(&o);
    o.shrink = false;
    if (Run(module.buggy).check(gpa, o)) |_| return "no" else |err| {
        if (want != null and want.? != err) return "no: it fails another way";
    }
    return if (Run(module.fixed).check(gpa, o)) |_| "yes" else |_| "no: the fix fails too";
}

/// Trouble the example's body makes itself, which no option takes away.
fn ownTrouble(comptime name: []const u8) []const u8 {
    const table = .{
        .{ "wal_kv", "power loss" },
        .{ "dir_sync", "power loss" },
        .{ "rename_unsynced", "power loss" },
        .{ "syscall_rename", "power loss" },
        .{ "in_place_rewrite", "an I/O error on a write it chooses, power loss" },
        .{ "index_before_data", "power loss" },
        .{ "id_reuse", "power loss" },
        .{ "jobs", "power loss" },
        .{ "deadlock", "a sleep while holding one lock" },
        .{ "livelock", "sleeps while holding one lock" },
        .{ "lease", "a step of the wall clock" },
        .{ "replica", "a partition" },
    };
    inline for (table) |entry| {
        if (comptime std.mem.eql(u8, name, entry[0])) return entry[1];
    }
    return "";
}

/// The example's trouble: what its body does, then the fault rates its
/// options set away from their defaults.
fn troubleText(buf: []u8, comptime name: []const u8, faults: tardis.FaultOptions) []const u8 {
    const defaults: tardis.FaultOptions = .{};
    var w: std.Io.Writer = .fixed(buf);
    w.writeAll(ownTrouble(name)) catch unreachable;
    inline for (.{ "io_error_ppm", "short_io_ppm", "oom_ppm", "spurious_wakeup_ppm", "net_reset_ppm", "clock_drift_ppm_max", "datagram_loss_ppm", "datagram_duplicate_ppm" }) |field| {
        if (@field(faults, field) != @field(defaults, field)) {
            if (w.end != 0) w.writeAll(", ") catch unreachable;
            w.print("`{s} = {d}`", .{ field, @field(faults, field) }) catch unreachable;
        }
    }
    return w.buffered();
}

fn baselineRow(gpa: std.mem.Allocator, io: std.Io, comptime name: []const u8, comptime class: []const u8, comptime module: type) !bool {
    _ = io;
    _ = class;
    if (@hasDecl(module, "supported") and (!module.supported or !tardis.syscallModeAvailable())) {
        std.debug.print("| `{s}` | not run: no system-call mode on this system | | | | | |\n", .{name});
        return true;
    }
    var base: tardis.Options = if (@hasDecl(module, "options")) module.options else .{ .iterations = 200 };
    base.report = false;

    const no_faults = baselineCell(gpa, module, base, .no_faults);
    const no_preemption = baselineCell(gpa, module, base, .no_preemption);
    const neither = baselineCell(gpa, module, base, .neither);

    var shrunk: tardis.ShrinkReport = .{};
    var campaign = base;
    campaign.shrink_report = &shrunk;
    const found = if (Run(module.buggy).check(gpa, campaign)) |_| false else |_| true;
    var fix = base;
    fix.shrink = false;
    const fix_holds = if (Run(module.fixed).check(gpa, fix)) |_| true else |_| false;

    var trouble: [160]u8 = undefined;
    var reduced: [48]u8 = undefined;
    const reduced_text = if (shrunk.shrunk)
        std.fmt.bufPrint(&reduced, "{d} -> {d} decisions", .{ shrunk.before, shrunk.after }) catch unreachable
    else
        "not shrunk";
    std.debug.print("| `{s}` | {s} | {s} | {s} | {s} | {s} | {s} |\n", .{
        name,
        troubleText(&trouble, name, base.faults),
        no_faults,
        no_preemption,
        neither,
        if (!found) "NO" else if (fix_holds) "yes" else "NO: THE FIX FAILS TOO",
        if (found) reduced_text else "",
    });
    return found and fix_holds;
}

/// `--without=<name>`: the example left out of the table, for a profiler
/// that cannot run it (docs/measurements.md §5: callgrind and
/// `syscall_rename`, which traps its own system calls).
var without: ?[]const u8 = null;
var without_found = false;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args = try init.minimal.args.iterateAllocator(gpa);
    defer args.deinit();
    _ = args.skip();
    var mode: []const u8 = "";
    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--without=")) without = arg["--without=".len..] else mode = arg;
    }
    if (std.mem.eql(u8, mode, "--baselines")) {
        std.debug.print("| Program | The example's own trouble | No faults | No preemption | Neither | Default | Failing run of the default |\n|---|---|---|---|---|---|---|\n", .{});
        if (!try all(gpa, io, baselineRow)) {
            std.debug.print("\nbugbench: the default campaign missed a planted bug, or a fix failed\n", .{});
            std.process.exit(1);
        }
        return;
    }
    if (std.mem.eql(u8, mode, "--schedules")) {
        std.debug.print("| Program | random, 10 | random, 50 | pct 1, 10 | pct 1, 50 | pct 2, 10 | pct 2, 50 | pct 3, 10 | pct 3, 50 | The fix under pct 3 |\n|---|---|---|---|---|---|---|---|---|---|\n", .{});
        var ok = try all(gpa, io, scheduleRow);
        ok = try scheduleRow(gpa, io, "(one long stretch)", "", shapes.long_stretch) and ok;
        ok = try scheduleRow(gpa, io, "(many short stretches)", "", shapes.many_switches) and ok;
        if (!ok) {
            std.debug.print("\nbugbench: a campaign of the usual size found no bug to count, or a fixed program failed under priorities\n", .{});
            std.process.exit(1);
        }
        return;
    }
    if (std.mem.eql(u8, mode, "--rates")) {
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
    const Each = struct {
        fn call(gpa_: std.mem.Allocator, io_: std.Io, comptime name: []const u8, comptime class: []const u8, comptime module: type) !bool {
            if (without) |w| if (std.mem.eql(u8, w, name)) {
                without_found = true;
                return true;
            };
            return each(gpa_, io_, name, class, module);
        }
    };
    var ok = true;
    ok = try Each.call(gpa, io, "wal_kv", "acknowledged before durable", @import("wal_kv")) and ok;
    ok = try Each.call(gpa, io, "dir_sync", "missing fsync of a directory", @import("dir_sync")) and ok;
    ok = try Each.call(gpa, io, "rename_unsynced", "renamed before the data is durable", @import("rename_unsynced")) and ok;
    ok = try Each.call(gpa, io, "syscall_rename", "renamed before the data is durable, by system call", @import("syscall_rename")) and ok;
    ok = try Each.call(gpa, io, "in_place_rewrite", "a file rewritten in place", @import("in_place_rewrite")) and ok;
    ok = try Each.call(gpa, io, "index_before_data", "two files made durable in the wrong order", @import("index_before_data")) and ok;
    ok = try Each.call(gpa, io, "id_reuse", "identifier handed out twice after a restart", @import("id_reuse")) and ok;
    ok = try Each.call(gpa, io, "jobs", "applied twice after a restart", @import("jobs")) and ok;
    ok = try Each.call(gpa, io, "short_write", "short write taken for a whole one", @import("short_write")) and ok;
    ok = try Each.call(gpa, io, "short_read", "short read taken for a whole one", @import("short_read")) and ok;
    ok = try Each.call(gpa, io, "error_leak", "resource leaked on an error path", @import("error_leak")) and ok;
    ok = try Each.call(gpa, io, "oom_partial", "half-finished update when memory runs out", @import("oom_partial")) and ok;
    ok = try Each.call(gpa, io, "counter", "lost update between tasks", @import("counter")) and ok;
    ok = try Each.call(gpa, io, "check_then_act", "check, then act", @import("check_then_act")) and ok;
    ok = try Each.call(gpa, io, "lin_register", "a compare-and-swap that is not atomic", @import("lin_register")) and ok;
    ok = try Each.call(gpa, io, "write_skew", "write skew between transactions", @import("write_skew")) and ok;
    ok = try Each.call(gpa, io, "deadlock", "deadlock from lock order", @import("deadlock")) and ok;
    ok = try Each.call(gpa, io, "livelock", "livelock from retrying in step", @import("livelock")) and ok;
    ok = try Each.call(gpa, io, "hidden_state", "state that survives a run", @import("hidden_state")) and ok;
    ok = try Each.call(gpa, io, "never_retried", "code the test never reaches", @import("never_retried")) and ok;
    ok = try Each.call(gpa, io, "lease", "a duration measured with the wall clock", @import("lease")) and ok;
    ok = try Each.call(gpa, io, "udp_retry", "a retry applied twice", @import("udp_retry")) and ok;
    ok = try Each.call(gpa, io, "udp_order", "trusting the order of arrival", @import("udp_order")) and ok;
    ok = try Each.call(gpa, io, "udp_no_timeout", "waiting for ever for a lost message", @import("udp_no_timeout")) and ok;
    ok = try Each.call(gpa, io, "stale_read", "a stale read from a follower", @import("stale_read")) and ok;
    ok = try Each.call(gpa, io, "replica", "replica left behind by a partition", @import("replica")) and ok;
    if (without) |w| if (!without_found) {
        std.debug.print("bugbench: no example is called `{s}`\n", .{w});
        return error.UnknownExample;
    };
    return ok;
}
