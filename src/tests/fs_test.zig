//! Filesystem behavior through the real `std.Io.Dir` / `std.Io.File` APIs
//! (plan §6, §10 tier 2).

const std = @import("std");
const tardis = @import("../root.zig");
const Io = std.Io;
const testing = std.testing;

test "write, read back, stat, rename, delete through std.Io APIs" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            const io = env.io;
            try env.dir.createDirPath(io, "data/logs");
            {
                var f = try env.dir.createFile(io, "data/logs/a.txt", .{});
                defer f.close(io);
                var buf: [64]u8 = undefined;
                var w = f.writer(io, &buf);
                try w.interface.print("hello {s}!", .{"tardis"});
                try w.interface.flush();
                try f.sync(io);
            }
            const content = try env.dir.readFileAlloc(io, "data/logs/a.txt", env.allocator, .unlimited);
            defer env.allocator.free(content);
            try testing.expectEqualStrings("hello tardis!", content);

            const st = try env.dir.statFile(io, "data/logs/a.txt", .{});
            try testing.expectEqual(@as(u64, 13), st.size);
            try testing.expectEqual(Io.File.Kind.file, st.kind);

            try env.dir.rename("data/logs/a.txt", env.dir, "data/b.txt", io);
            try testing.expectError(error.FileNotFound, env.dir.statFile(io, "data/logs/a.txt", .{}));
            try env.dir.deleteFile(io, "data/b.txt");
            try env.dir.deleteDir(io, "data/logs");
        }
    }.run, .{ .iterations = 20 });
}

test "an operation the simulator does not model fails and is named" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            try testing.expectEqual(@as(usize, 0), env.refusedCalls().len);
            var buf: [64]u8 = undefined;
            try testing.expectError(error.FileNotFound, env.dir.realPath(env.io, &buf));
            try testing.expectError(error.FileNotFound, env.dir.realPath(env.io, &buf));
            // Asking whether a file is a terminal is answered, not refused.
            var f = try env.dir.createFile(env.io, "f", .{});
            defer f.close(env.io);
            try testing.expect(!try f.isTty(env.io));
            try testing.expect(!try f.supportsAnsiEscapeCodes(env.io));
            try testing.expectError(error.NotTerminalDevice, f.enableAnsiEscapeCodes(env.io));
            // Copying works (std falls back to reading and writing) and
            // is not a refused call either.
            try env.dir.copyFile("f", env.dir, "g", env.io, .{});
            const refused = env.refusedCalls();
            try testing.expectEqual(@as(usize, 1), refused.len);
            try testing.expectEqualStrings("dirRealPath", refused[0]);
        }
    }.run, .{ .iterations = 3 });
}

test "streaming reader and writer survive short reads and writes" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            const io = env.io;
            const payload = try env.fuzz([]const u8);
            {
                var f = try env.dir.createFile(io, "blob", .{});
                defer f.close(io);
                try f.writeStreamingAll(io, payload);
            }
            var f = try env.dir.openFile(io, "blob", .{});
            defer f.close(io);
            var rbuf: [7]u8 = undefined; // tiny buffer: many refills
            var r = f.readerStreaming(io, &rbuf);
            const got = try r.interface.allocRemaining(env.allocator, .unlimited);
            defer env.allocator.free(got);
            try testing.expectEqualSlices(u8, payload, got);
        }
    }.run, .{ .iterations = 50, .faults = .{ .short_io_ppm = 600_000 } });
}

test "synced data survives power loss on every persona" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            const io = env.io;
            const payload = try env.fuzz([]const u8);
            {
                var f = try env.dir.createFile(io, "state", .{});
                defer f.close(io);
                try f.writePositionalAll(io, payload, 0);
                try f.sync(io);
            }
            // Make the directory entry durable for posix_strict as well.
            {
                var d = try env.dir.openFile(io, ".", .{});
                defer d.close(io);
                try d.sync(io);
            }
            try env.crashAndReboot(.power_loss);
            const got = try env.dir.readFileAlloc(io, "state", env.allocator, .unlimited);
            defer env.allocator.free(got);
            try testing.expectEqualSlices(u8, payload, got);
        }
    }.run, .{ .iterations = 25, .personas = &.{ .linux_ext4, .linux_xfs, .windows_ntfs, .posix_strict } });
}

test "process crash keeps unsynced writes" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            const io = env.io;
            try env.dir.writeFile(io, .{ .sub_path = "x", .data = "not synced" });
            try env.crashAndReboot(.process_crash);
            var buf: [32]u8 = undefined;
            try testing.expectEqualStrings("not synced", try env.dir.readFile(io, "x", &buf));
        }
    }.run, .{ .iterations = 10 });
}

test "handles from before a crash are invalid afterwards" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            const io = env.io;
            var f = try env.dir.createFile(io, "x", .{});
            try env.crashAndReboot(.process_crash);
            try testing.expectError(error.Unexpected, f.writePositionalAll(io, "y", 0));
            f.close(io); // closing a stale handle is a no-op
        }
    }.run, .{ .iterations = 3 });
}

test "targeted fault injection: the Nth write fails" {
    var s = try tardis.sim(testing.allocator, .{ .iterations = 10, .personas = &.{.windows_ntfs} });
    defer s.deinit();
    while (s.step()) |env| {
        const io = env.io;
        var f = try env.dir.createFile(io, "wal.dat", .{});
        defer f.close(io);
        env.injectIoErrorAfter(.write, 1, error.NoSpaceLeft);
        try f.writePositionalAll(io, "a", 0);
        try testing.expectError(error.NoSpaceLeft, f.writePositionalAll(io, "b", 1));
        try f.writePositionalAll(io, "c", 1); // one-shot
    }
    try s.finish();
}

test "ntfs refuses to delete an open file; ext4 allows it" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            const io = env.io;
            var f = try env.dir.createFile(io, "locked", .{ .read = true });
            defer f.close(io);
            try f.writePositionalAll(io, "still here", 0);
            if (env.persona == .windows_ntfs) {
                try testing.expectError(error.FileBusy, env.dir.deleteFile(io, "locked"));
            } else {
                try env.dir.deleteFile(io, "locked");
                var buf: [16]u8 = undefined;
                const n = try f.readPositionalAll(io, &buf, 0); // a single readPositional may be short
                try testing.expectEqualStrings("still here", buf[0..n]);
            }
        }
    }.run, .{ .iterations = 5, .personas = &.{ .windows_ntfs, .linux_ext4 } });
}

test "ntfs paths are case-insensitive" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            const io = env.io;
            try env.dir.writeFile(io, .{ .sub_path = "Config.JSON", .data = "{}" });
            var buf: [8]u8 = undefined;
            try testing.expectEqualStrings("{}", try env.dir.readFile(io, "config.json", &buf));
            try testing.expectError(error.BadPathName, env.dir.writeFile(io, .{ .sub_path = "aux", .data = "" }));
        }
    }.run, .{ .iterations = 3, .personas = &.{.windows_ntfs} });
}

test "leaked file handle is reported" {
    const r = tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            _ = try env.dir.createFile(env.io, "leak", .{});
        }
    }.run, .{ .iterations = 1, .report = false });
    try testing.expectError(error.ResourceLeak, r);
}

test "OOM injection reaches env.allocator" {
    var saw_oom = false;
    var s = try tardis.sim(testing.allocator, .{ .iterations = 40, .swarm = false, .faults = .{ .oom_ppm = 300_000 } });
    defer s.deinit();
    while (s.step()) |env| {
        const buf = env.allocator.alloc(u8, 16) catch {
            saw_oom = true;
            continue;
        };
        env.allocator.free(buf);
    }
    try s.finish();
    try testing.expect(saw_oom);
}

test "Dir.cwd() resolves to the simulated root" {
    try tardis.check(testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            const io = env.io;
            try Io.Dir.cwd().writeFile(io, .{ .sub_path = "via-cwd", .data = "ok" });
            var buf: [4]u8 = undefined;
            try testing.expectEqualStrings("ok", try env.dir.readFile(io, "via-cwd", &buf));
        }
    }.run, .{ .iterations = 2 });
}
