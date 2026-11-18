//! Atomics under simulation (plan §9 M6): scheduling between atomic
//! operations, and store buffers for orderings weaker than `.seq_cst`.

const std = @import("std");
const tardis = @import("../root.zig");
const Io = std.Io;
const testing = std.testing;
const gpa = testing.allocator;
const Value = tardis.atomic.Value;

/// The store-buffering litmus test: each task stores its flag and then
/// loads the other's. With `.seq_cst` stores at least one of them sees the
/// other's flag. With weaker stores both can read 0, each store still in
/// its task's buffer.
const Litmus = struct {
    x: Value(u32) = .init(0),
    y: Value(u32) = .init(0),
    r: [2]u32 = .{ 9, 9 },
};

fn Side(comptime order: std.builtin.AtomicOrder) type {
    return struct {
        fn run(l: *Litmus, me: u1) Io.Cancelable!void {
            const mine = if (me == 0) &l.x else &l.y;
            const other = if (me == 0) &l.y else &l.x;
            mine.store(1, order);
            l.r[me] = other.load(.seq_cst);
        }

        fn body(env: *tardis.Env) !void {
            var l: Litmus = .{};
            var group: Io.Group = .init;
            defer group.cancel(env.io);
            try group.concurrent(env.io, run, .{ &l, 0 });
            try group.concurrent(env.io, run, .{ &l, 1 });
            try group.await(env.io);
            try env.always("one of the two saw the other's store", l.r[0] == 1 or l.r[1] == 1);
            // Both stores are in memory once their tasks ended.
            try testing.expectEqual(@as(u32, 1), l.x.load(.seq_cst));
            try testing.expectEqual(@as(u32, 1), l.y.load(.seq_cst));
        }
    };
}

test "store buffers: two release stores can both be missed; seq_cst stores cannot" {
    var report: tardis.ShrinkReport = .{};
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, Side(.release).body, .{ .iterations = 500, .report = false, .shrink_report = &report }));
    try testing.expect(report.shrunk);
    // The token replays the reordering.
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, Side(.release).body, .{ .replay = report.token(), .report = false }));
    try tardis.check(gpa, Side(.seq_cst).body, .{ .iterations = 500 });
}

fn counter(env: *tardis.Env) !void {
    var n: Value(u32) = .init(0);
    const add = struct {
        fn f(v: *Value(u32)) Io.Cancelable!void {
            for (0..4) |_| _ = v.fetchAdd(1, .seq_cst);
        }
    }.f;
    var group: Io.Group = .init;
    defer group.cancel(env.io);
    try group.concurrent(env.io, add, .{&n});
    try group.concurrent(env.io, add, .{&n});
    try group.await(env.io);
    try env.always("no increment is lost", n.load(.seq_cst) == 8);
}

/// Load and store: another task can run in between.
fn lostUpdate(env: *tardis.Env) !void {
    var n: Value(u32) = .init(0);
    const add = struct {
        fn f(v: *Value(u32)) Io.Cancelable!void {
            for (0..4) |_| v.store(v.load(.seq_cst) + 1, .seq_cst);
        }
    }.f;
    var group: Io.Group = .init;
    defer group.cancel(env.io);
    try group.concurrent(env.io, add, .{&n});
    try group.concurrent(env.io, add, .{&n});
    try group.await(env.io);
    try env.always("no increment is lost", n.load(.seq_cst) == 8);
}

test "atomic operations are scheduling points: load-then-store loses updates, fetchAdd does not" {
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, lostUpdate, .{ .iterations = 200, .report = false }));
    try tardis.check(gpa, counter, .{ .iterations = 200 });
}
