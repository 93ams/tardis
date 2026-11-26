//! A run that crashes says which run it was (`sim/crash.zig`).

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const tardis = @import("../root.zig");
const Env = tardis.Env;
const crash = @import("../sim/crash.zig");
const decide = @import("../sim/decide.zig");

test "a crash's lines name the iteration, persona and seed, and how to replay it" {
    var buf: [2048]u8 = undefined;
    const plain = crash.format(&buf, .{ .iteration = 6, .persona = "strict", .seed = 0xabc, .overlay = null }, "crashed (a fatal signal)");
    try testing.expectEqualStrings(
        "\ntardis: crashed (a fatal signal) in iteration 7  persona=strict  seed=0x0000000000000abc\n" ++
            "tardis: replay with:  TARDIS_SEED=0x0000000000000abc TARDIS_PERSONA=strict zig build test\n",
        plain,
    );
    // Told decisions: a token, since the seed alone would run another run.
    const forced = [_]decide.Forced{.{ .key = 0x12, .value = 3 }};
    const overlay: decide.Overlay = .{ .forced = &forced };
    var buf2: [2048]u8 = undefined;
    const told = crash.format(&buf2, .{ .iteration = null, .persona = "strict", .seed = 0xabc, .overlay = &overlay }, "aborted (a panic, or abort)");
    try testing.expect(std.mem.indexOf(u8, told, "TARDIS_REPLAY=strict:0x0000000000000abc:") != null);
    try testing.expect(std.mem.indexOf(u8, told, "TARDIS_SEED") == null);
    // Not a campaign iteration: no iteration number.
    try testing.expect(std.mem.indexOf(u8, told, "not a campaign iteration") != null);
    // A token longer than a kilobyte, as an early shrink candidate's is.
    var keep: [400]u64 = undefined;
    for (&keep, 0..) |*k, i| k.* = 0x1000_0000_0000_0000 + i;
    const long: decide.Overlay = .{ .keep = &keep };
    const long_lines = crash.format(&big, .{ .iteration = null, .persona = "strict", .seed = 0xabc, .overlay = &long }, "crashed (a fatal signal)");
    try testing.expect(std.mem.indexOf(u8, long_lines, "TARDIS_REPLAY=strict:0x0000000000000abc:1000000000000000.") != null);
}

var big: [32 * 1024]u8 = undefined;

const Mode = enum { detect, panic, fault };
var mode: Mode = .detect;

/// Crashes on one seed in 64, in the way `mode` says; `detect` returns an
/// error there instead, which tells a replay that it reached the crash (a
/// wrong seed would too, one time in 64).
fn crashesSometimes(env: *Env) !void {
    try env.io.sleep(.fromMilliseconds(1), .awake);
    if (env.seed % 64 != 3) return;
    switch (mode) {
        .detect => return error.WouldCrash,
        .panic => @panic("tardis test: a planted panic"),
        .fault => {
            const p: *volatile u32 = @ptrFromInt(8);
            p.* = 1;
        },
    }
}

const Child = struct { out: []const u8, signaled: bool };

/// Runs a campaign of `crashesSometimes` in `m` in a forked child, its
/// standard error into a pipe, and returns what it wrote.
fn crashInChild(buf: []u8, m: Mode, workers: u32, options: tardis.Options) !Child {
    const linux = std.os.linux;
    // A raw `fork` behind libc's back would leave its state (thread ids,
    // atfork handlers) wrong in the child.
    if (builtin.link_libc) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    if (linux.pipe(&fds) != 0) return error.SkipZigTest;
    const pid: isize = @bitCast(linux.fork());
    if (pid < 0) return error.SkipZigTest;
    if (pid == 0) {
        _ = linux.close(fds[0]);
        _ = linux.dup2(fds[1], 2);
        mode = m;
        var o = options;
        o.iterations = 2000;
        o.workers = workers;
        o.report = false;
        tardis.check(std.heap.page_allocator, crashesSometimes, o) catch {};
        linux.exit_group(0); // not reached: some seed crashes
    }
    _ = linux.close(fds[1]);
    var len: usize = 0;
    while (len < buf.len) {
        const n: isize = @bitCast(linux.read(fds[0], buf[len..].ptr, buf.len - len));
        if (n <= 0) break;
        len += @intCast(n);
    }
    _ = linux.close(fds[0]);
    var status: i32 = 0;
    _ = linux.waitpid(@intCast(pid), &status, 0);
    const st: u32 = @bitCast(status);
    return .{ .out = buf[0..len], .signaled = st & 0x7f != 0 and st & 0x7f != 0x7f };
}

/// The seed and persona the replay line names, run once more: the run
/// reaches the crash again.
fn expectReplays(out: []const u8, options: tardis.Options) !void {
    const seed_at = (std.mem.indexOf(u8, out, "TARDIS_SEED=0x") orelse return error.NoReplayLine) + "TARDIS_SEED=0x".len;
    const seed = try std.fmt.parseInt(u64, out[seed_at..][0..16], 16);
    const persona_at = (std.mem.indexOf(u8, out, "TARDIS_PERSONA=") orelse return error.NoReplayLine) + "TARDIS_PERSONA=".len;
    const end = std.mem.indexOfScalarPos(u8, out, persona_at, ' ') orelse return error.NoReplayLine;
    const persona = std.meta.stringToEnum(tardis.Persona, out[persona_at..end]) orelse return error.NoReplayLine;
    mode = .detect;
    var o = options;
    o.seed = seed;
    o.personas = &.{persona};
    o.report = false;
    try testing.expectError(error.WouldCrash, tardis.check(testing.allocator, crashesSometimes, o));
}

test "a panic inside a run prints the run's iteration, persona, seed and replay line" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var buf: [64 * 1024]u8 = undefined;
    const child = try crashInChild(&buf, .panic, 1, .{});
    try testing.expect(child.signaled);
    try testing.expect(std.mem.indexOf(u8, child.out, "tardis test: a planted panic") != null);
    const at = std.mem.indexOf(u8, child.out, "tardis: aborted (a panic, or abort) in iteration ") orelse return error.NoCrashLine;
    // After the panic's own message.
    try testing.expect(at > std.mem.indexOf(u8, child.out, "a planted panic").?);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, child.out, "tardis: replay with:"));
    try expectReplays(child.out, .{});
}

test "a fault inside a run on a worker thread prints the run's line once" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var buf: [64 * 1024]u8 = undefined;
    const child = try crashInChild(&buf, .fault, 2, .{});
    try testing.expect(child.signaled);
    try testing.expect(std.mem.indexOf(u8, child.out, "tardis: crashed (a fatal signal) in iteration ") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, child.out, "tardis: replay with:"));
    try expectReplays(child.out, .{});
}

test "a fault inside a run in system-call mode prints the run's line" {
    if (builtin.os.tag != .linux or !tardis.syscall_mode_supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    var buf: [64 * 1024]u8 = undefined;
    const child = try crashInChild(&buf, .fault, 1, .{ .mode = .syscalls });
    try testing.expect(child.signaled);
    try testing.expect(std.mem.indexOf(u8, child.out, "tardis: crashed (a fatal signal) in iteration ") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, child.out, "tardis: replay with:"));
    try expectReplays(child.out, .{ .mode = .syscalls });
}
