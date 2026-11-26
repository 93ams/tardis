//! A freed block is filled, and a write to it after the free fails the run
//! (`Options.poison_freed`, `sim/alloc.zig`).

const std = @import("std");
const testing = std.testing;
const tardis = @import("../root.zig");
const Env = tardis.Env;

/// The value a read after the free saw, in the last run.
var read_after_free: u8 = 0;

fn readsAfterFree(env: *Env) !void {
    const block = try env.allocator.alloc(u8, 64);
    @memset(block, 7);
    // Not `free`, which in a build with runtime safety writes `undefined`
    // (0xAA) itself first: as a build without it frees.
    env.allocator.rawFree(block, .@"1", @returnAddress());
    try env.io.sleep(.fromMilliseconds(1), .awake);
    read_after_free = @as(*volatile u8, &block[10]).*;
}

test "a read after the free reads the fill, not the value left there" {
    // A security layer fills freed blocks itself, and this is not done.
    if (tardis.security_by_default) return error.SkipZigTest;
    try tardis.check(testing.allocator, readsAfterFree, .{ .iterations = 4 });
    try testing.expectEqual(@as(u8, 0xAA), read_after_free);
}

test "with poison_freed off, a read after the free reads the value left there" {
    // A security layer fills freed blocks itself, and this is not done.
    if (tardis.security_by_default) return error.SkipZigTest;
    try tardis.check(testing.allocator, readsAfterFree, .{ .iterations = 4, .poison_freed = false });
    try testing.expectEqual(@as(u8, 7), read_after_free);
}

fn writesAfterFree(env: *Env) !void {
    const block = try env.allocator.alloc(u8, 64);
    env.allocator.free(block);
    try env.io.sleep(.fromMilliseconds(1), .awake);
    @as(*volatile u8, &block[10]).* = 1;
}

test "a write after the free fails the run with WriteAfterFree" {
    // A security layer fills freed blocks itself, and this is not done.
    if (tardis.security_by_default) return error.SkipZigTest;
    try testing.expectError(error.WriteAfterFree, tardis.check(testing.allocator, writesAfterFree, .{ .iterations = 4, .report = false }));
    try tardis.check(testing.allocator, writesAfterFree, .{ .iterations = 4, .poison_freed = false });
}

fn writesAfterFreeThenCrashes(env: *Env) !void {
    const block = try env.allocator.alloc(u8, 64);
    env.allocator.free(block);
    @as(*volatile u8, &block[63]).* = 1;
    // The heap is wiped here: the block is checked first.
    try env.crashAndReboot(.power_loss);
}

test "a write after the free is found before a crash wipes the heap" {
    // A security layer fills freed blocks itself, and this is not done.
    if (tardis.security_by_default) return error.SkipZigTest;
    try testing.expectError(error.WriteAfterFree, tardis.check(testing.allocator, writesAfterFreeThenCrashes, .{ .iterations = 4, .report = false }));
}

fn writesAfterFreeThenFreesMore(env: *Env) !void {
    const block = try env.allocator.alloc(u8, 16);
    env.allocator.free(block);
    @as(*volatile u8, &block[0]).* = 1;
    // Enough frees to give the block back for reuse.
    for (0..4096) |_| env.allocator.free(try env.allocator.alloc(u8, 1));
    // Reused memory may now hold anything: the run ends without the block.
    try testing.expect(env.daemonError().? == error.WriteAfterFree);
}

test "a write after the free is found when the block is given back for reuse" {
    // A security layer fills freed blocks itself, and this is not done.
    if (tardis.security_by_default) return error.SkipZigTest;
    try testing.expectError(error.WriteAfterFree, tardis.check(testing.allocator, writesAfterFreeThenFreesMore, .{ .iterations = 2, .report = false }));
}
