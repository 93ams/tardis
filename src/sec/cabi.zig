//! The C side of the security layer (plan2.md §5.2): the functions the
//! wrappers in `c/tardis_sec.h` call. They are exported only when a test
//! asks for them with `comptime { tardis_sec.exportC(); }`, so a build that
//! links no C carries no symbols.
//!
//! Each sink returns the CWE it found (0: none) and has already failed the
//! run; the wrapped call then goes on as it would have, like every hook.

const std = @import("std");
const engine = @import("engine.zig");

pub fn exportSymbols() void {
    @export(&checkFormat, .{ .name = "tardis_sec_check_format" });
    @export(&checkCommand, .{ .name = "tardis_sec_check_command" });
    @export(&checkExec, .{ .name = "tardis_sec_check_exec" });
    @export(&checkSql, .{ .name = "tardis_sec_check_sql" });
    @export(&criticalCheck, .{ .name = "tardis_sec_critical_check" });
    @export(&mcdcDecision, .{ .name = "tardis_sec_mcdc" });
    @export(&boundsCheck, .{ .name = "tardis_sec_bounds_check" });
    @export(&mutexAcquire, .{ .name = "tardis_sec_mutex_acquire" });
    @export(&mutexRelease, .{ .name = "tardis_sec_mutex_release" });
}

fn cString(s: ?[*:0]const u8) []const u8 {
    return std.mem.span(s orelse return "");
}

/// A `printf`-family format string (CWE-134).
fn checkFormat(format: ?[*:0]const u8) callconv(.c) c_int {
    return engine.cSink(.format, cString(format));
}

/// A command for the shell: `system`, `popen`. It is spawned as
/// `/bin/sh -c command`: a process (CWE-272 in a sandbox that forbids
/// one), whose command line is a sink (CWE-78).
fn checkCommand(command: ?[*:0]const u8) callconv(.c) c_int {
    return engine.cSpawn(&.{ "/bin/sh", "-c", cString(command) });
}

/// The longest argv checked; the rest of a longer one is not.
pub const exec_args_max = 32;

/// A program started by the `exec` family: the path, then `argv` up to its
/// NULL (or `exec_args_max` entries).
fn checkExec(path: ?[*:0]const u8, argv: ?[*:null]const ?[*:0]const u8) callconv(.c) c_int {
    var args: [exec_args_max][]const u8 = undefined;
    args[0] = cString(path);
    var n: usize = 1;
    if (argv) |list| {
        var i: usize = 0;
        while (list[i]) |arg| : (i += 1) {
            if (n == args.len) break;
            args[n] = std.mem.span(arg);
            n += 1;
        }
    }
    return engine.cSpawn(args[0..n]);
}

/// SQL text about to be prepared (CWE-89). `len` < 0: up to the NUL, as
/// `sqlite3_prepare_v2` reads it.
fn checkSql(sql: ?[*]const u8, len: c_int) callconv(.c) c_int {
    const p = sql orelse return 0;
    const bytes = if (len < 0) std.mem.span(@as([*:0]const u8, @ptrCast(p))) else p[0..@intCast(len)];
    return engine.cSink(.sql, bytes);
}

/// A security-critical condition in C (`TARDIS_SEC_CRITICAL(cond)`): its
/// truth value, which the simulator may invert as one skipped compare.
fn criticalCheck(cond: c_int) callconv(.c) c_int {
    return @intFromBool(engine.glitch(cond != 0));
}

/// A decision in C (§7.1): records the vector of its conditions' values
/// (condition i is bit i) with the outcome, in the same table as Zig's
/// `mcdc.decision`, and returns the outcome. A decision id of 256 or more,
/// or more than 8 conditions, is not recorded.
fn mcdcDecision(id: c_uint, conditions: c_uint, vector: c_uint, outcome: c_int) callconv(.c) c_int {
    if (id < engine.mcdc.decisions_max and conditions >= 1 and conditions <= engine.mcdc.conditions_max) {
        const mask = (@as(c_uint, 1) << @intCast(conditions)) - 1;
        engine.mcdcRecord(@intCast(id), @intCast(conditions), @intCast(vector & mask), outcome != 0);
    }
    return outcome;
}

/// A bounds check on an index the attacker chooses (`TARDIS_SEC_BOUNDS`):
/// `index < len`, and when it holds the next loads are watched for the
/// Spectre-v1 shape (§6.3, CWE-1037). The site is the caller.
fn boundsCheck(index: usize, len: usize) callconv(.c) c_int {
    if (index >= len) return 0;
    engine.spectreCheck(@returnAddress());
    return 1;
}

/// A C mutex is about to be taken (before it may wait): lock order across
/// C mutexes, by address (CWE-833, §4.2).
fn mutexAcquire(mutex: ?*const anyopaque) callconv(.c) void {
    engine.cLock(@intFromPtr(mutex), true);
}

fn mutexRelease(mutex: ?*const anyopaque) callconv(.c) void {
    engine.cLock(@intFromPtr(mutex), false);
}
