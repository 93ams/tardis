//! The C shims (plan2.md §5.2): C code compiled with `c/tardis_sec.h`
//! (`tests/c/legacy.c`) reports its format strings, SQL text, shell
//! commands and mutexes to the engine. Each planted bug is found, fails the
//! run, and shrinks to at most 5 decisions; each fixed form passes.

const std = @import("std");
const tardis = @import("tardis");
const sec = @import("tardis_sec");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const Env = tardis.Env;
const gpa = std.testing.allocator;

comptime {
    sec.exportC();
}

extern fn legacy_greet(out: [*]u8, cap: usize, name: [*:0]const u8, fixed: c_int) c_int;
extern fn legacy_lookup(name: [*:0]const u8, fixed: c_int) c_int;
extern fn legacy_notify(name: [*:0]const u8, fixed: c_int) c_int;
extern fn legacy_convert(name: [*:0]const u8, fixed: c_int) c_int;
extern fn legacy_archive(name: [*:0]const u8, fixed: c_int, spawn: c_int) c_int;
extern fn legacy_report(name: [*:0]const u8, fixed: c_int) c_int;
extern fn legacy_verify(tag: [*]const u8, expected: [*]const u8, n: usize, doubled: c_int) c_int;
extern fn legacy_unlock(armed: c_int, sig_ok: c_int, override: c_int) c_int;
extern fn legacy_transfer() void;
extern fn legacy_audit(fixed: c_int) void;

fn expectShrunkTo(r: tardis.ShrinkReport, decisions_max: usize) !void {
    try std.testing.expect(r.shrunk);
    if (r.after > decisions_max) {
        std.debug.print("shrunk to {d} decisions (from {d}), want <= {d}\n", .{ r.after, r.before, decisions_max });
        return error.TestUnexpectedResult;
    }
}

const users_port = 750;
/// No `%`: the buggy greeting really uses the name as a format, and the
/// test must not depend on what `vsnprintf` does with stray conversions.
const user_names = [_][]const u8{ "alice-from-sales", "mallory-the-admin" };

const Sink = enum {
    format,
    sql,
    command,
    exec,
    exec_list,
    spawn,
    pipe,
    /// The constant command, but from a server that has entered a sandbox.
    sandboxed_command,
};

/// Receives a user name and hands it to the C library.
fn userServer(io: Io, sink: Sink, fixed: bool) !void {
    const any: IpAddress = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = users_port } };
    var server = try any.listen(io, .{});
    defer server.deinit(io);
    const stream = try server.accept(io);
    defer stream.close(io);
    var rbuf: [64]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    const line = r.interface.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.ReadFailed => return r.err.?,
        else => |e| return e,
    };
    var name: [64:0]u8 = undefined;
    if (line.len >= name.len) return;
    @memcpy(name[0..line.len], line);
    name[line.len] = 0;
    const c_name: [*:0]const u8 = name[0..line.len :0];
    const f: c_int = @intFromBool(fixed);
    switch (sink) {
        .format => {
            var out: [128]u8 = undefined;
            _ = legacy_greet(&out, out.len, c_name, f);
        },
        .sql => _ = legacy_lookup(c_name, f),
        .command => _ = legacy_notify(c_name, f),
        .exec => try std.testing.expectEqual(@as(c_int, -1), legacy_convert(c_name, f)),
        .exec_list => try std.testing.expectEqual(@as(c_int, 1), legacy_archive(c_name, f, 0)),
        .spawn => try std.testing.expectEqual(@as(c_int, 1), legacy_archive(c_name, f, 1)),
        // The simulation runs no processes: no pipe either way.
        .pipe => try std.testing.expectEqual(@as(c_int, 0), legacy_report(c_name, f)),
        .sandboxed_command => {
            sec.enterSandbox(.{ .allow_process_spawn = fixed });
            _ = legacy_notify(c_name, 1);
        },
    }
}

fn usersRun(env: *Env, sink: Sink, fixed: bool) !void {
    const io = env.io;
    try env.spawnOn(1, userServer, .{ io, sink, fixed });
    try io.sleep(.fromMilliseconds(1), .awake);
    const name = user_names[(try env.fuzz(u8)) % user_names.len];
    const stream = try env.address(1, users_port).connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var wbuf: [64]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeAll(name) catch return w.err.?;
    w.interface.writeByte('\n') catch return w.err.?;
    w.interface.flush() catch return w.err.?;
    try io.sleep(.fromMilliseconds(10), .awake);
    if (env.daemonError()) |err| return err;
}

fn Run(comptime sink: Sink, comptime fixed: bool) type {
    return struct {
        fn body(env: *Env) !void {
            return usersRun(env, sink, fixed);
        }
    };
}

fn expectFinding(comptime body: fn (*Env) anyerror!void, cwe: u16, kind: sec.engine.Kind) !void {
    var report: sec.engine.Report = .{};
    var shrunk: tardis.ShrinkReport = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, body, sec.withSecurity(.{
        .report = &report,
        .base = .{ .nodes = 2, .iterations = 50, .report = false, .shrink_report = &shrunk },
    })));
    try std.testing.expectEqual(cwe, report.findings[0].cwe);
    try std.testing.expectEqual(kind, report.findings[0].kind);
    try std.testing.expectEqual(@as(u16, 1), report.findings[0].detail[1]);
    try expectShrunkTo(shrunk, 5);
}

const options: sec.SecurityConfig = .{ .base = .{ .nodes = 2, .iterations = 50 } };

test "C shims: a received name as a format string is CWE-134; as an argument it passes" {
    try expectFinding(Run(.format, false).body, 134, .tainted_format);
    try tardis.check(gpa, Run(.format, true).body, sec.withSecurity(options));
}

test "C shims: a received name pasted into SQL is CWE-89; as a bound parameter it passes" {
    try expectFinding(Run(.sql, false).body, 89, .tainted_sql);
    try tardis.check(gpa, Run(.sql, true).body, sec.withSecurity(options));
}

test "C shims: a received name on a shell command line is CWE-78; a constant command passes" {
    try expectFinding(Run(.command, false).body, 78, .tainted_command);
    try tardis.check(gpa, Run(.command, true).body, sec.withSecurity(options));
    // With taint off, nothing looks at the sinks.
    var off = options;
    off.taint_paths = false;
    try tardis.check(gpa, Run(.command, false).body, sec.withSecurity(off));
}

test "C shims: a received name in an exec argv or a popen command is CWE-78; constant ones pass" {
    try expectFinding(Run(.exec, false).body, 78, .tainted_command);
    try tardis.check(gpa, Run(.exec, true).body, sec.withSecurity(options));
    inline for (.{ Sink.exec_list, Sink.spawn }) |sink| {
        try expectFinding(Run(sink, false).body, 78, .tainted_command);
        try tardis.check(gpa, Run(sink, true).body, sec.withSecurity(options));
    }
    try expectFinding(Run(.pipe, false).body, 78, .tainted_command);
    try tardis.check(gpa, Run(.pipe, true).body, sec.withSecurity(options));
}

test "C shims: a shell command from a sandbox without process spawning is CWE-272" {
    try expectFinding(Run(.sandboxed_command, false).body, 272, .privilege);
    try tardis.check(gpa, Run(.sandboxed_command, true).body, sec.withSecurity(options));
}

const expected_tag: [16]u8 = @splat(0x5A);
const forged_tag: [16]u8 = @splat(0xA5);

fn Verify(comptime doubled: bool, comptime in_c: bool) type {
    return struct {
        fn body(env: *Env) !void {
            const accepted = if (in_c)
                legacy_verify(&forged_tag, &expected_tag, forged_tag.len, @intFromBool(doubled)) != 0
            else
                sec.criticalEql([16]u8, forged_tag, expected_tag) and (!doubled or sec.criticalEql([16]u8, forged_tag, expected_tag));
            try env.always("forged tag rejected", !accepted);
        }
    };
}

test "glitch sites: one skipped compare accepts a forged tag in C and in Zig; a doubled check fails closed" {
    inline for (.{ true, false }) |in_c| {
        // A single check, glitched one run in five: some run accepts.
        try std.testing.expectError(error.AssertionFailed, tardis.check(gpa, Verify(false, in_c).body, sec.withSecurity(.{
            .instruction_skip_glitch_ppm = 200_000,
            .base = .{ .iterations = 200, .report = false },
        })));
        // Doubled, at a realistic rate: both would have to be glitched.
        try tardis.check(gpa, Verify(true, in_c).body, sec.withSecurity(.{
            .instruction_skip_glitch_ppm = 1_000,
            .base = .{ .iterations = 200 },
        }));
        // Without glitches the single check rejects.
        try tardis.check(gpa, Verify(false, in_c).body, sec.withSecurity(.{ .base = .{ .iterations = 20 } }));
    }
    // Outside a simulation both are the plain comparison.
    try std.testing.expectEqual(@as(c_int, 0), legacy_verify(&forged_tag, &expected_tag, forged_tag.len, 0));
    try std.testing.expectEqual(@as(c_int, 1), legacy_verify(&expected_tag, &expected_tag, expected_tag.len, 1));
    try std.testing.expect(sec.criticalEql([16]u8, expected_tag, expected_tag));
}

fn unlockInC(env: *Env) !void {
    const armed = (try env.fuzz(u8)) & 1;
    const sig_ok = (try env.fuzz(u8)) & 1;
    const override = (try env.fuzz(u8)) & 1;
    const open = legacy_unlock(armed, sig_ok, override) != 0;
    try env.always("the C decision is the expression", open == (armed == 1 and (sig_ok == 1 or override == 1)));
}

test "C shims: a decision recorded from C reaches MC/DC in the same table as Zig's" {
    var report: sec.mcdc.Report = .{};
    try tardis.check(gpa, unlockInC, sec.withSecurity(.{ .mcdc = &report, .base = .{ .iterations = 64 } }));
    const e = report.entry(11);
    try std.testing.expectEqual(@as(u8, 3), e.conditions);
    try std.testing.expect(e.complete());
    // Outside a simulation the call is the expression.
    try std.testing.expectEqual(@as(c_int, 1), legacy_unlock(1, 0, 1));
    try std.testing.expectEqual(@as(c_int, 0), legacy_unlock(0, 1, 1));
}

fn bank(env: *Env, fixed: bool) !void {
    const io = env.io;
    legacy_transfer();
    try io.sleep(.fromMilliseconds((try env.fuzz(u8)) % 4), .awake);
    legacy_audit(@intFromBool(fixed));
}

fn invertedAudit(env: *Env) !void {
    return bank(env, false);
}

fn orderedAudit(env: *Env) !void {
    return bank(env, true);
}

test "C shims: pthread mutexes taken in both orders are CWE-833, by address" {
    var report: sec.engine.Report = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, invertedAudit, sec.withSecurity(.{
        .report = &report,
        .base = .{ .iterations = 20, .report = false },
    })));
    const f = report.findings[0];
    try std.testing.expectEqual(@as(u16, 833), f.cwe);
    const first = sec.engine.races.c_lock_class_first;
    // `accounts` was locked first in the run, so it has the first class.
    try std.testing.expectEqual([2]u16{ first + 1, first }, f.detail);
    try tardis.check(gpa, orderedAudit, sec.withSecurity(.{ .base = .{ .iterations = 20 } }));
    // Outside a simulation the shims do nothing.
    legacy_transfer();
    legacy_audit(0);
}
