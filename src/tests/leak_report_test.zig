//! A leak report names what leaked: the size of each live allocation and
//! the stack that made it (`reportLeakedAllocations` in `root.zig`).

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const tardis = @import("../root.zig");
const Env = tardis.Env;

/// Leaks one block of 24 bytes on one seed in four; frees the others.
noinline fn leakyHelper(env: *Env) !void {
    const kept = try env.allocator.alloc(u8, 24);
    const freed = try env.allocator.alloc(u8, 40);
    env.allocator.free(freed);
    try env.io.sleep(.fromMilliseconds(1), .awake);
    if (env.seed % 4 != 1) env.allocator.free(kept);
}

fn leaks(env: *Env) !void {
    try leakyHelper(env);
}

/// Runs `check` on `leaks` in a forked child with the report on, its
/// standard error into a pipe, and returns what it wrote.
fn reportOfChild(buf: []u8, options: tardis.Options) ![]const u8 {
    const linux = std.os.linux;
    // A raw `fork` behind libc's back would leave its state wrong in the
    // child.
    if (builtin.link_libc) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    if (linux.pipe(&fds) != 0) return error.SkipZigTest;
    const pid: isize = @bitCast(linux.fork());
    if (pid < 0) return error.SkipZigTest;
    if (pid == 0) {
        _ = linux.close(fds[0]);
        _ = linux.dup2(fds[1], 2);
        var o = options;
        o.iterations = 40;
        o.report = true;
        const failed = if (tardis.check(std.heap.page_allocator, leaks, o)) |_| false else |err| err == error.ResourceLeak;
        linux.exit_group(if (failed) 0 else 1);
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
    try testing.expectEqual(@as(i32, 0), status);
    return buf[0..len];
}

test "a leak report gives each live allocation's size and the stack that made it" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // A security layer keeps its own tables of the heap; the report is the
    // same, but the test's budget of output is not.
    if (tardis.security_by_default) return error.SkipZigTest;
    var buf: [256 * 1024]u8 = undefined;
    const out = try reportOfChild(&buf, .{});
    try testing.expect(std.mem.indexOf(u8, out, "tardis: the run again, recording each allocation:") != null);
    try testing.expect(std.mem.indexOf(u8, out, "tardis: node 0 has 1 live allocation(s) (24 bytes):\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "tardis: live allocation 1: 24 bytes, made at:") != null);
    try testing.expect(std.mem.indexOf(u8, out, "it did not leak again") == null);
    // The stack, with names where the build has them.
    if (builtin.mode == .debug) try testing.expect(std.mem.indexOf(u8, out, "leakyHelper") != null);
}

test "without shrinking, the leak report still gives the live allocations" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    if (tardis.security_by_default) return error.SkipZigTest;
    var buf: [256 * 1024]u8 = undefined;
    const out = try reportOfChild(&buf, .{ .shrink = false });
    try testing.expect(std.mem.indexOf(u8, out, "tardis: live allocation 1: 24 bytes, made at:") != null);
}
