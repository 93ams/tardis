//! Thread-local variables that each task has its own copy of
//! (`Options.task_locals`, `sim/tasktls.zig`).

const std = @import("std");
const testing = std.testing;
const tardis = @import("../root.zig");
const Env = tardis.Env;

/// Per-statement state, as code that keeps it in a `threadlocal` has it.
threadlocal var statement: u32 = 0;
threadlocal var depth: [4]u8 = .{ 1, 2, 3, 4 };

/// What a task saw at its start, for the last run.
var started_with: u32 = 0;

/// What the body must start with. (Not every function given to `async`:
/// one run inline, in its caller, has its caller's copy, as it would on a
/// real thread; `Options.async_inline_ppm`.)
var expected_start: ?u32 = null;

fn statementTask(io: std.Io, id: u32) error{ Canceled, Clobbered }!void {
    started_with = statement;
    statement = id;
    depth[0] = @intCast(id);
    // The other task runs here.
    io.sleep(.fromMilliseconds(1), .awake) catch return error.Canceled;
    if (statement != id or depth[0] != id) return error.Clobbered;
}

fn twoStatements(env: *Env) !void {
    if (expected_start) |e| if (statement != e) return error.WrongStart;
    var a = env.io.async(statementTask, .{ env.io, 10 });
    var b = env.io.async(statementTask, .{ env.io, 20 });
    try a.await(env.io);
    try b.await(env.io);
}

test "with task_locals, each task has its own copy of a threadlocal" {
    if (!tardis.task_locals_supported) return error.SkipZigTest;
    statement = 5;
    defer statement = 0;
    try tardis.check(testing.allocator, twoStatements, .{
        .iterations = 20,
        .task_locals = &.{ std.mem.asBytes(&statement), std.mem.asBytes(&depth) },
    });
    // Each task began with the thread's value at the run's start.
    try testing.expectEqual(@as(u32, 5), started_with);
    // And the thread has its own back.
    try testing.expectEqual(@as(u32, 5), statement);
    try testing.expectEqual(@as(u8, 1), depth[0]);
}

test "without task_locals, the tasks share it, and one clobbers the other's" {
    try testing.expectError(error.Clobbered, tardis.check(testing.allocator, twoStatements, .{ .iterations = 20, .report = false }));
    statement = 0;
    depth = .{ 1, 2, 3, 4 };
}

test "task_locals on worker threads" {
    if (!tardis.task_locals_supported) return error.SkipZigTest;
    try tardis.check(testing.allocator, twoStatements, .{
        .iterations = 40,
        .workers = 3,
        .task_locals = &.{ std.mem.asBytes(&statement), std.mem.asBytes(&depth) },
    });
    try testing.expectEqual(@as(u32, 0), statement);
    // Every task, on every worker, starts with the caller's values.
    statement = 5;
    defer statement = 0;
    expected_start = 5;
    defer expected_start = null;
    try tardis.check(testing.allocator, twoStatements, .{
        .iterations = 40,
        .workers = 3,
        .task_locals = &.{ std.mem.asBytes(&statement), std.mem.asBytes(&depth) },
    });
}

test "task_locals where the target cannot tell a threadlocal" {
    if (tardis.task_locals_supported) return error.SkipZigTest;
    try testing.expectError(error.TaskLocalsUnsupported, tardis.check(testing.allocator, twoStatements, .{
        .iterations = 1,
        .task_locals = &.{std.mem.asBytes(&statement)},
    }));
}

test "task_locals in system-call mode" {
    if (!tardis.task_locals_supported or !tardis.syscall_mode_supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    try tardis.check(testing.allocator, twoStatements, .{
        .iterations = 10,
        .mode = .syscalls,
        .task_locals = &.{ std.mem.asBytes(&statement), std.mem.asBytes(&depth) },
    });
    try testing.expectEqual(@as(u32, 0), statement);
}

fn setsStatement(_: *Env) !void {
    statement = 7;
}

fn seesSetup(env: *Env) !void {
    if (statement != 7) return error.SetupLost;
    try twoStatements(env);
}

test "what setup writes to a named threadlocal, the body sees (warm restore is off for it)" {
    if (!tardis.task_locals_supported) return error.SkipZigTest;
    try tardis.check(testing.allocator, seesSetup, .{
        .iterations = 20,
        .setup = setsStatement,
        .task_locals = &.{ std.mem.asBytes(&statement), std.mem.asBytes(&depth) },
    });
    try testing.expectEqual(@as(u32, 0), statement);
}

test "an empty entry in task_locals is left out" {
    if (!tardis.task_locals_supported) return error.SkipZigTest;
    try tardis.check(testing.allocator, twoStatements, .{
        .iterations = 2,
        .task_locals = &.{ std.mem.asBytes(&statement)[0..0], std.mem.asBytes(&statement), std.mem.asBytes(&depth), &.{} },
    });
}
