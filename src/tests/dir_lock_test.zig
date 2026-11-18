//! M2: directory listing and file locks through the real `std.Io` APIs.

const std = @import("std");
const tardis = @import("../root.zig");
const Io = std.Io;
const testing = std.testing;
const Env = tardis.Env;
const gpa = testing.allocator;

const names = [_][]const u8{ "a", "b", "c", "d" };

fn listing(env: *Env) !void {
    const io = env.io;
    try env.dir.createDir(io, "sub", .default_dir);
    for (names) |n| {
        var f = try env.dir.createFile(io, n, .{});
        f.close(io);
    }
    var seen: [names.len]bool = @splat(false);
    var saw_sub = false;
    var first: u8 = 0;
    var it = env.dir.iterate();
    var count: usize = 0;
    while (try it.next(io)) |e| : (count += 1) {
        if (count == 0) first = e.name[0];
        if (std.mem.eql(u8, e.name, "sub")) {
            try testing.expectEqual(Io.File.Kind.directory, e.kind);
            saw_sub = true;
            continue;
        }
        try testing.expectEqual(Io.File.Kind.file, e.kind);
        for (names, 0..) |n, i| {
            if (std.mem.eql(u8, e.name, n)) seen[i] = true;
        }
    }
    try testing.expectEqual(names.len + 1, count);
    try testing.expect(saw_sub);
    for (seen) |s| try testing.expect(s);
    env.sometimes("listing does not start with the first file created", first != 'a');
}

test "dir: iterate lists every entry, in no particular order" {
    try tardis.check(gpa, listing, .{ .iterations = 30 });
}

/// Bug: treats the first directory entry as the oldest file.
fn oldestIsFirst(env: *Env) !void {
    const io = env.io;
    for (names) |n| {
        var f = try env.dir.createFile(io, n, .{});
        f.close(io);
    }
    var it = env.dir.iterate();
    const e = (try it.next(io)).?;
    try env.always("the first listed entry is the oldest", std.mem.eql(u8, e.name, "a"));
}

test "dir: code that relies on readdir order is caught (bug found)" {
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, oldestIsFirst, .{ .iterations = 20, .report = false }));
}

// --- locks -------------------------------------------------------------------

fn incrementLocked(io: Io, dir: Io.Dir) !void {
    var f = try dir.openFile(io, "counter", .{ .mode = .read_write });
    defer f.close(io);
    try f.lock(io, .exclusive);
    defer f.unlock(io);
    var buf: [1]u8 = undefined;
    _ = try f.readPositionalAll(io, &buf, 0);
    try io.sleep(.fromMicroseconds(10), .awake); // widen the critical section
    buf[0] += 1;
    try f.writePositionalAll(io, &buf, 0);
}

fn lockedCounter(env: *Env) !void {
    const io = env.io;
    {
        var f = try env.dir.createFile(io, "counter", .{});
        defer f.close(io);
        try f.writePositionalAll(io, &.{0}, 0);
    }
    var group: Io.Group = .init;
    defer group.cancel(io);
    for (0..3) |_| try group.concurrent(io, struct {
        fn run(i: Io, d: Io.Dir) Io.Cancelable!void {
            incrementLocked(i, d) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => @panic("increment failed"),
            };
        }
    }.run, .{ io, env.dir });
    try group.await(io);
    var buf: [1]u8 = undefined;
    _ = try env.dir.readFile(io, "counter", &buf);
    try env.always("every locked increment is kept", buf[0] == 3);
}

test "lock: an exclusive lock serializes read-modify-write across tasks" {
    try tardis.check(gpa, lockedCounter, .{ .iterations = 40, .personas = &.{ .linux_ext4, .windows_ntfs } });
}

fn tryLockAndMandatory(env: *Env) !void {
    const io = env.io;
    var a = try env.dir.createFile(io, "f", .{ .read = true });
    defer a.close(io);
    var b = try env.dir.openFile(io, "f", .{ .mode = .read_write });
    defer b.close(io);

    try a.lock(io, .shared);
    try testing.expect(try b.tryLock(io, .shared));
    try testing.expect(!(try b.tryLock(io, .exclusive)));
    b.unlock(io);
    a.unlock(io);

    try a.lock(io, .exclusive);
    try testing.expect(!(try b.tryLock(io, .shared)));
    const r = b.writePositionalAll(io, "x", 0);
    if (env.persona == .windows_ntfs) {
        // Windows locks are mandatory.
        try testing.expectError(error.LockViolation, r);
    } else {
        // POSIX locks are advisory.
        try r;
    }
    try a.downgradeLock(io);
    try testing.expect(try b.tryLock(io, .shared));
    b.unlock(io);
    a.unlock(io);
}

test "lock: tryLock, downgrade, and Windows mandatory locking" {
    try tardis.check(gpa, tryLockAndMandatory, .{ .iterations = 10, .personas = &.{ .linux_ext4, .windows_ntfs } });
}
