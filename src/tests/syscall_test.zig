//! Stray system calls (plan §9 M6): `Options.trap_syscalls` fails a run
//! whose code asks the real kernel for something.

const std = @import("std");
const builtin = @import("builtin");
const tardis = @import("../root.zig");
const Env = tardis.Env;
const testing = std.testing;
const gpa = testing.allocator;

/// Asks the kernel for random bytes behind the simulator's back.
fn realRandom(env: *Env) !void {
    _ = env;
    if (!tardis.trap_syscalls_supported) return;
    var bytes: [16]u8 = @splat(0);
    const got = std.os.linux.getrandom(&bytes, bytes.len, 0);
    // The call was made for the thread: it got its bytes.
    try testing.expectEqual(@as(usize, bytes.len), got);
    try testing.expect(!std.mem.allEqual(u8, &bytes, 0));
}

fn threadBody() void {}

/// What the last spawn inside a run came to. A stray call replaces the
/// body's own result with `StraySyscall`, so the body cannot assert this.
var spawn_refusals: u32 = 0;
var spawn_other: u32 = 0;

/// Starts a real thread behind the simulator's back.
fn startsThread(env: *Env) !void {
    _ = env;
    if (std.Thread.spawn(.{}, threadBody, .{})) |t| {
        t.join();
        spawn_other += 1;
    } else |err| switch (err) {
        // The trap answers EAGAIN: this without libc, the other with it.
        error.ThreadQuotaExceeded, error.SystemResources => spawn_refusals += 1,
        else => spawn_other += 1,
    }
}

test "trap_syscalls: starting a thread is refused and fails the run" {
    if (!tardis.trap_syscalls_supported) return error.SkipZigTest;
    spawn_refusals = 0;
    spawn_other = 0;
    try testing.expectError(error.StraySyscall, tardis.check(gpa, startsThread, .{ .iterations = 3, .trap_syscalls = true, .report = false, .shrink = false }));
    // Every spawn was refused: no thread ran, and none failed otherwise.
    try testing.expect(spawn_refusals >= 1);
    try testing.expectEqual(@as(u32, 0), spawn_other);
    // Threads still start once the run is over.
    const t = try std.Thread.spawn(.{}, threadBody, .{});
    t.join();
}

/// Randomness and the clock from the simulation; files, sleeping and a
/// large allocation on the way.
fn simulated(env: *Env) !void {
    const io = env.io;
    var bytes: [16]u8 = undefined;
    io.random(&bytes);
    _ = std.Io.Timestamp.now(io, .real);
    try env.dir.writeFile(io, .{ .sub_path = "f", .data = "x" });
    const mem = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(mem);
    try io.sleep(.fromMilliseconds(1), .awake);
}

/// Makes one stray call, from a function a test can find in the report's
/// stack.
noinline fn strayFromHere() void {
    var bytes: [4]u8 = undefined;
    _ = std.os.linux.getrandom(&bytes, bytes.len, 0);
}

noinline fn strayCaller(env: *Env) !void {
    _ = env;
    strayFromHere();
}

/// A stray call made while `std.debug` holds its lock, as a panic's trace
/// does while it reads the program's file: no stack, and no hang.
fn strayWhileDebugLocked(env: *Env) !void {
    _ = env;
    const info = std.debug.getSelfDebugInfo() catch return;
    const io = std.Options.debug_io;
    info.rwlock.lockUncancelable(io);
    defer info.rwlock.unlock(io);
    strayFromHere();
}

fn within(address: usize, f: usize) bool {
    return address > f and address < f + 512;
}

test "trap_syscalls: the report names every call, and says where the first stray one was made" {
    if (!tardis.trap_syscalls_supported) return error.SkipZigTest;
    const syscalls = @import("../sim/syscalls.zig");
    try testing.expectEqualStrings("sched_getaffinity", syscalls.name(204));
    try testing.expectEqualStrings("io_uring_setup", syscalls.name(425));
    try testing.expectEqualStrings("a system call", syscalls.name(100_000));
    try testing.expectError(error.StraySyscall, tardis.check(gpa, strayCaller, .{ .iterations = 1, .trap_syscalls = true, .report = false, .shrink = false }));
    // The stack holds a return address inside the function that made the
    // call, and the next one out is inside its caller.
    const trace = syscalls.lastStrayTrace();
    if (!std.debug.sys_can_stack_trace or !std.options.allow_stack_tracing) return;
    var found = false;
    for (trace[0..trace.len -| 1], trace[1..]) |inner, outer| {
        if (within(inner, @intFromPtr(&strayFromHere)) and within(outer, @intFromPtr(&strayCaller))) found = true;
    }
    try testing.expect(found);
    if (@hasField(std.debug.SelfInfo, "rwlock")) {
        try testing.expectError(error.StraySyscall, tardis.check(gpa, strayWhileDebugLocked, .{ .iterations = 1, .trap_syscalls = true, .report = false, .shrink = false }));
        try testing.expectEqual(@as(usize, 0), syscalls.lastStrayTrace().len);
    }
}

test "trap_syscalls: asking the kernel for random bytes fails the run; simulated I/O does not" {
    if (!tardis.trap_syscalls_supported) return error.SkipZigTest;
    try testing.expectError(error.StraySyscall, tardis.check(gpa, realRandom, .{ .iterations = 3, .trap_syscalls = true, .report = false, .shrink = false }));
    try tardis.check(gpa, simulated, .{ .iterations = 50, .trap_syscalls = true });
    // And a system call made after the runs is not trapped.
    var bytes: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), std.os.linux.getrandom(&bytes, bytes.len, 0));
}
