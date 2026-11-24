//! Child processes (plan3.md D4): programs a test registers, spawned
//! through `std.process`, with pipes that block as real ones do.

const std = @import("std");
const tardis = @import("../root.zig");
const Io = std.Io;
const testing = std.testing;

const quiet: tardis.Options = .{ .iterations = 40, .report = false, .faults = .{ .io_error_ppm = 0 } };

/// Writes its arguments after the first, space-separated, to stdout, and
/// "warn" to stderr; exits with the number of arguments.
fn echo(p: *tardis.Process) anyerror!u8 {
    var buf: [64]u8 = undefined;
    var w = p.stdout.writerStreaming(p.io, &buf);
    for (p.argv[1..], 0..) |a, i| {
        if (i > 0) try w.interface.writeByte(' ');
        try w.interface.writeAll(a);
    }
    try w.interface.flush();
    var ebuf: [16]u8 = undefined;
    var e = p.stderr.writerStreaming(p.io, &ebuf);
    try e.interface.writeAll("warn");
    try e.interface.flush();
    return @intCast(p.argv.len - 1);
}

/// Reads stdin to its end and writes it back upper-cased.
fn upper(p: *tardis.Process) anyerror!u8 {
    var rbuf: [16]u8 = undefined;
    var r = p.stdin.readerStreaming(p.io, &rbuf);
    var wbuf: [16]u8 = undefined;
    var w = p.stdout.writerStreaming(p.io, &wbuf);
    while (true) {
        const c = r.interface.takeByte() catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| return e,
        };
        try w.interface.writeByte(std.ascii.toUpper(c));
    }
    try w.interface.flush();
    return 0;
}

fn failing(p: *tardis.Process) anyerror!u8 {
    _ = p;
    return error.Unreadable;
}

test "std.process.run collects a registered program's output and exit code" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            try env.registerProgram("echo", echo);
            const r = try std.process.run(env.allocator, env.io, .{ .argv = &.{ "/usr/bin/echo", "hello", "world" } });
            defer env.allocator.free(r.stdout);
            defer env.allocator.free(r.stderr);
            try testing.expectEqualStrings("hello world", r.stdout);
            try testing.expectEqualStrings("warn", r.stderr);
            try testing.expectEqual(std.process.Child.Term{ .exited = 2 }, r.term);
        }
    }.run, quiet);
}

test "a pipe to the child's stdin: the child sees the end once the parent closes it" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            try env.registerProgram("upper", upper);
            var child = try std.process.spawn(env.io, .{ .argv = &.{"upper"}, .stdin = .pipe, .stdout = .pipe });
            defer child.kill(env.io);
            var wbuf: [8]u8 = undefined;
            var w = child.stdin.?.writerStreaming(env.io, &wbuf);
            try w.interface.writeAll("abc, def");
            try w.interface.flush();
            child.stdin.?.close(env.io);
            child.stdin = null;
            var out: [32]u8 = undefined;
            var rbuf: [8]u8 = undefined;
            var r = child.stdout.?.readerStreaming(env.io, &rbuf);
            const n = try r.interface.readSliceShort(&out);
            try testing.expectEqualStrings("ABC, DEF", out[0..n]);
            try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, try child.wait(env.io));
        }
    }.run, quiet);
}

test "a name nobody registered is FileNotFound; a program's error exits with 1" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            try testing.expectError(error.FileNotFound, std.process.spawn(env.io, .{ .argv = &.{"missing"} }));
            try env.registerProgram("failing", failing);
            var child = try std.process.spawn(env.io, .{ .argv = &.{"failing"} });
            try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, try child.wait(env.io));
        }
    }.run, quiet);
}

/// The planted bug: the parent waits for the child without closing the
/// child's stdin, and the child reads stdin to its end.
fn forgetsToClose(env: *tardis.Env) !void {
    try env.registerProgram("upper", upper);
    var child = try std.process.spawn(env.io, .{ .argv = &.{"upper"}, .stdin = .pipe });
    var wbuf: [8]u8 = undefined;
    var w = child.stdin.?.writerStreaming(env.io, &wbuf);
    try w.interface.writeAll("abc");
    try w.interface.flush();
    _ = try child.wait(env.io);
}

test "waiting for a child whose stdin was never closed is a deadlock" {
    try testing.expectError(error.Deadlock, tardis.check(testing.allocator, forgetsToClose, quiet));
}

/// Writes more than a pipe holds.
fn chatty(p: *tardis.Process) anyerror!u8 {
    var buf: [256]u8 = undefined;
    var w = p.stdout.writerStreaming(p.io, &buf);
    try w.interface.splatByteAll('x', 100 * 1024);
    try w.interface.flush();
    return 0;
}

/// The planted bug: the parent waits before it reads the child's output,
/// which is more than the pipe holds.
fn waitsFirst(env: *tardis.Env) !void {
    try env.registerProgram("chatty", chatty);
    var child = try std.process.spawn(env.io, .{ .argv = &.{"chatty"}, .stdout = .pipe });
    _ = try child.wait(env.io);
}

/// The fix: drain stdout, then wait.
fn drainsFirst(env: *tardis.Env) !void {
    try env.registerProgram("chatty", chatty);
    var child = try std.process.spawn(env.io, .{ .argv = &.{"chatty"}, .stdout = .pipe });
    var rbuf: [4096]u8 = undefined;
    var r = child.stdout.?.readerStreaming(env.io, &rbuf);
    // Not `discardRemaining`: on a streaming file it leaves uncounted the
    // bytes a read puts past its scratch buffer.
    var n: usize = 0;
    var chunk: [1000]u8 = undefined;
    while (true) {
        const k = try r.interface.readSliceShort(&chunk);
        if (k == 0) break;
        n += k;
    }
    try testing.expectEqual(@as(usize, 100 * 1024), n);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, try child.wait(env.io));
}

test "waiting before draining a full pipe is a deadlock; draining first is not" {
    try testing.expectError(error.Deadlock, tardis.check(testing.allocator, waitsFirst, quiet));
    try tardis.check(testing.allocator, drainsFirst, quiet);
}

fn sleeper(p: *tardis.Process) anyerror!u8 {
    try p.io.sleep(.fromSeconds(3600), .awake);
    return 0;
}

test "kill ends a child blocked in a sleep; a child never waited for is a leak" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            try env.registerProgram("sleeper", sleeper);
            var child = try std.process.spawn(env.io, .{ .argv = &.{"sleeper"}, .stdout = .pipe });
            child.kill(env.io);
            try testing.expect(child.id == null and child.stdout == null);
        }
    }.run, quiet);
    try testing.expectError(error.ResourceLeak, tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            try env.registerProgram("echo", echo);
            _ = try std.process.spawn(env.io, .{ .argv = &.{ "echo", "x" } });
        }
    }.run, quiet));
}

test "a crash drops the child; waiting for it then reports an unknown end" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            try env.registerProgram("sleeper", sleeper);
            var child = try std.process.spawn(env.io, .{ .argv = &.{"sleeper"}, .stdout = .pipe });
            try env.crashAndReboot(.process_crash);
            try testing.expectEqual(std.process.Child.Term{ .unknown = 0 }, try child.wait(env.io));
            try testing.expect(child.stdout == null);
        }
    }.run, quiet);
}

test "the same seed gives the same interleaving of parent and child" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            try env.registerProgram("echo", echo);
            const r = try std.process.run(env.allocator, env.io, .{ .argv = &.{ "echo", "a", "b", "c" } });
            env.allocator.free(r.stdout);
            env.allocator.free(r.stderr);
        }
    }.run, .{ .iterations = 20, .report = false, .determinism_check_every = 1 });
}

/// Writes its first argument with the default (positional) writer.
fn say(p: *tardis.Process) anyerror!u8 {
    var buf: [16]u8 = undefined;
    var w = p.stdout.writer(p.io, &buf);
    try w.interface.writeAll(p.argv[1]);
    try w.interface.flush();
    return 0;
}

/// Copies stdin to stdout with the default reader and writer.
fn cat(p: *tardis.Process) anyerror!u8 {
    var rbuf: [16]u8 = undefined;
    var r = p.stdin.reader(p.io, &rbuf);
    var wbuf: [16]u8 = undefined;
    var w = p.stdout.writer(p.io, &wbuf);
    _ = try r.interface.streamRemaining(&w.interface);
    try w.interface.flush();
    return 0;
}

test "a pipeline: the parent closes its copy of the pipe it passed on" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            try env.registerProgram("say", say);
            try env.registerProgram("cat", cat);
            var a = try std.process.spawn(env.io, .{ .argv = &.{ "say", "hello" }, .stdout = .pipe });
            var b = try std.process.spawn(env.io, .{ .argv = &.{"cat"}, .stdin = .{ .file = a.stdout.? }, .stdout = .pipe });
            a.stdout.?.close(env.io);
            a.stdout = null;
            // The default reader, which starts positional and falls back.
            var rbuf: [16]u8 = undefined;
            var r = b.stdout.?.reader(env.io, &rbuf);
            var out: [16]u8 = undefined;
            const n = try r.interface.readSliceShort(&out);
            try testing.expectEqualStrings("hello", out[0..n]);
            try testing.expectEqual(Io.File.Kind.named_pipe, (try b.stdout.?.stat(env.io)).kind);
            try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, try a.wait(env.io));
            try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, try b.wait(env.io));
        }
    }.run, quiet);
}

fn waitFor(io: Io, child: *std.process.Child) !std.process.Child.Term {
    return child.wait(io);
}

test "a wait blocked on a child can be canceled" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            try env.registerProgram("upper", upper);
            var child = try std.process.spawn(env.io, .{ .argv = &.{"upper"}, .stdin = .pipe });
            var f = try env.io.concurrent(waitFor, .{ env.io, &child });
            try testing.expectError(error.Canceled, f.cancel(env.io));
            // The canceled wait closed the parent's end, so the child sees
            // the end of its input and returns.
            try testing.expect(child.id == null and child.stdin == null);
            try env.io.sleep(.fromMilliseconds(1), .awake);
        }
    }.run, .{ .iterations = 40, .report = false, .faults = .{ .io_error_ppm = 0 }, .leak_check = false });
}
