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

test "trap_syscalls: asking the kernel for random bytes fails the run; simulated I/O does not" {
    if (!tardis.trap_syscalls_supported) return error.SkipZigTest;
    try testing.expectError(error.StraySyscall, tardis.check(gpa, realRandom, .{ .iterations = 3, .trap_syscalls = true, .report = false, .shrink = false }));
    try tardis.check(gpa, simulated, .{ .iterations = 50, .trap_syscalls = true });
    // And a system call made after the runs is not trapped.
    var bytes: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), std.os.linux.getrandom(&bytes, bytes.len, 0));
}
