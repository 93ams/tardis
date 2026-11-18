//! M5: multi-core campaigns give the same answers as one thread.

const std = @import("std");
const tardis = @import("../root.zig");
const Env = tardis.Env;
const testing = std.testing;
const gpa = testing.allocator;

fn rareBug(env: *Env) !void {
    const x = try env.fuzz(u16);
    env.sometimes("x is even", x % 2 == 0);
    try env.always("x is not a multiple of 97", x % 97 != 0 or x == 0);
}

test "parallel: the lowest failing iteration and its shrink match one thread" {
    var one: tardis.ShrinkReport = .{};
    var many: tardis.ShrinkReport = .{};
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, rareBug, .{ .iterations = 2000, .report = false, .shrink_report = &one }));
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, rareBug, .{ .iterations = 2000, .report = false, .shrink_report = &many, .workers = 6 }));
    try testing.expectEqualStrings(one.token(), many.token());
}

fn evenOnly(env: *Env) !void {
    const x = try env.fuzz(u16);
    env.sometimes("x is odd", x % 2 == 1);
    try env.io.sleep(.fromMilliseconds(1), .awake);
}

test "parallel: sometimes-assertions are merged across workers" {
    try tardis.check(gpa, evenOnly, .{ .iterations = 400, .workers = 4 });
}
