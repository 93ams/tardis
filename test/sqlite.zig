//! SQLite under simulation (`plan3.md` D9, plan §9.2).
//!
//! SQLite's amalgamation, built as it ships, with its own Unix VFS: it
//! opens, reads, writes, locks, syncs and deletes its files with system
//! calls through libc, and knows nothing of `std.Io`. System-call mode
//! (`Options.mode = .syscalls`, Linux on x86_64) answers those calls from
//! the simulated filesystem, so a power loss can be placed after a commit
//! and the database reopened to see what it kept.
//!
//! The program: create a table and a first row, then commit a second row,
//! and take the commit's return as the acknowledgement. Then the power
//! goes. The property: the database opens, passes `PRAGMA
//! integrity_check`, and holds the acknowledged row.
//!
//! The planted bug is `PRAGMA synchronous=OFF`, which commits without a
//! single `fsync`. The fix is `synchronous=EXTRA`.
//!
//! `FULL`, SQLite's default, fails the property too, and that is SQLite's
//! documented behaviour, not a planted bug: in its default journal mode a
//! commit ends by unlinking the rollback journal, `FULL` does not sync the
//! directory after that, and a power loss that undoes the unlink leaves a
//! journal which the next open takes for an unfinished transaction and
//! rolls back. SQLite's documentation gives exactly this as what `EXTRA`
//! adds. The third test pins it, and `docs/power-cut.md` records the same
//! result from real SQLite on a real ext4 with the power cut.
//!
//! SQLite keeps state for the life of the process (its random number
//! generator is seeded once, from `/dev/urandom`). A run must not inherit
//! it, or the same seed gives two different runs, which `check` reports as
//! `error.NonDeterministic`: so the program resets the generator first.
//!
//! The fourth test drives SQLite from two tasks at once, each with its own
//! database. SQLite holds process-wide mutexes across file calls (its
//! Unix VFS holds one across the `open` and `fstat` that find a file's
//! inode), and an emulated call can let the other task run: the other
//! task's wait for that mutex is a `futex` call, which system-call mode
//! answers in the simulation (revision 76). Before, it was a real wait on
//! the one thread every fiber shares, and the run hung.
//!
//! Run with `zig build test-sqlite -Dsqlite` on Linux x86_64.

const std = @import("std");
const tardis = @import("tardis");
const Env = tardis.Env;
const testing = std.testing;

const supported = tardis.syscall_mode_supported;

const Db = opaque {};
const Callback = *const fn (ctx: ?*anyopaque, columns: c_int, values: [*]?[*:0]const u8, names: [*]?[*:0]const u8) callconv(.c) c_int;

extern fn sqlite3_open(path: [*:0]const u8, db: *?*Db) c_int;
extern fn sqlite3_close(db: ?*Db) c_int;
extern fn sqlite3_exec(db: ?*Db, sql: [*:0]const u8, callback: ?Callback, ctx: ?*anyopaque, errmsg: ?*?[*:0]u8) c_int;
extern fn sqlite3_randomness(len: c_int, buf: ?*anyopaque) void;

fn open() !*Db {
    return openPath("app.db");
}

fn openPath(path: [*:0]const u8) !*Db {
    var db: ?*Db = null;
    if (sqlite3_open(path, &db) != 0) {
        _ = sqlite3_close(db);
        return error.SqliteOpenFailed;
    }
    return db.?;
}

fn exec(db: *Db, sql: [*:0]const u8) !void {
    if (sqlite3_exec(db, sql, null, null, null) != 0) return error.SqliteFailed;
}

/// The first column of the first row.
const First = struct {
    buf: [64]u8 = undefined,
    len: usize = 0,
    rows: usize = 0,

    fn row(ctx: ?*anyopaque, columns: c_int, values: [*]?[*:0]const u8, _: [*]?[*:0]const u8) callconv(.c) c_int {
        const self: *First = @ptrCast(@alignCast(ctx.?));
        if (self.rows == 0 and columns > 0) if (values[0]) |v| {
            const value = std.mem.span(v);
            self.len = @min(value.len, self.buf.len);
            @memcpy(self.buf[0..self.len], value[0..self.len]);
        };
        self.rows += 1;
        return 0;
    }

    fn text(self: *const First) []const u8 {
        return self.buf[0..self.len];
    }
};

fn query(db: *Db, sql: [*:0]const u8) !First {
    var first: First = .{};
    if (sqlite3_exec(db, sql, First.row, &first, null) != 0) return error.SqliteFailed;
    return first;
}

const Sync = enum { off, full, extra };

/// What the last failing run found, for a test that expects one finding
/// and not another.
const Broken = enum { nothing, cannot_open, cannot_read, integrity, row_lost };
threadlocal var broken: Broken = .nothing;

fn scenario(env: *Env, comptime sync: Sync) !void {
    return scenarioIn(env, sync, false);
}

/// In write-ahead-log mode (`wal`), SQLite keeps an index of the log in a
/// `-shm` file that every connection maps shared (`mmap`, `MAP_SHARED`).
fn scenarioIn(env: *Env, comptime sync: Sync, comptime wal: bool) !void {
    const pragma = "PRAGMA synchronous=" ++ switch (sync) {
        .off => "OFF",
        .full => "FULL",
        .extra => "EXTRA",
    };
    // The generator seeds itself again, from this run's `/dev/urandom`.
    sqlite3_randomness(0, null);
    {
        const db = try open();
        // After the crash the connection's descriptors are closed, as
        // the process's would be: closing it then only frees its memory.
        defer _ = sqlite3_close(db);
        if (wal) {
            const mode = try query(db, "PRAGMA journal_mode=WAL");
            if (!std.mem.eql(u8, mode.text(), "wal")) return error.NotWal;
        }
        try exec(db, pragma);
        try exec(db, "CREATE TABLE kv(k INTEGER PRIMARY KEY, v TEXT)");
        try exec(db, "INSERT INTO kv VALUES(1, 'one')");
        // The acknowledged commit.
        try exec(db, "INSERT INTO kv VALUES(2, 'two')");
        try env.crashAndReboot(.power_loss);
    }
    broken = .nothing;
    const db = open() catch {
        broken = .cannot_open;
        return env.always("the database opens after a power loss", false);
    };
    defer _ = sqlite3_close(db);
    const integrity = query(db, "PRAGMA integrity_check") catch {
        broken = .cannot_read;
        return env.always("the database can be read after a power loss", false);
    };
    if (!std.mem.eql(u8, integrity.text(), "ok")) broken = .integrity;
    try env.always("the database passes its integrity check after a power loss", broken == .nothing);
    const two = query(db, "SELECT v FROM kv WHERE k = 2") catch {
        broken = .cannot_read;
        return env.always("the table is there after a power loss", false);
    };
    if (!(two.rows == 1 and std.mem.eql(u8, two.text(), "two"))) broken = .row_lost;
    try env.always("the acknowledged row survives a power loss", broken == .nothing);
}

fn syncOff(env: *Env) !void {
    return scenario(env, .off);
}

fn syncFull(env: *Env) !void {
    return scenario(env, .full);
}

fn syncExtra(env: *Env) !void {
    return scenario(env, .extra);
}

const options: tardis.Options = .{
    .iterations = 100,
    .mode = .syscalls,
    .personas = &.{ .linux_ext4, .linux_xfs, .posix_strict },
    // SQLite's parser and its page cache want more than the default.
    .limits = .{ .fiber_stack_bytes = 1024 * 1024 },
};

test "sqlite: with synchronous=OFF an acknowledged commit does not survive a power loss" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    var o = options;
    o.report = false;
    var shrunk: tardis.ShrinkReport = .{};
    o.shrink_report = &shrunk;
    try testing.expectError(error.AssertionFailed, tardis.check(testing.allocator, syncOff, o));
    try testing.expect(shrunk.shrunk);
    try testing.expect(shrunk.after < shrunk.before);
    std.debug.print("sqlite, synchronous=OFF: found, shrunk from {d} to {d} decisions\n", .{ shrunk.before, shrunk.after });
    // The token replays to the same failure.
    var replay = options;
    replay.report = false;
    replay.replay = shrunk.token();
    try testing.expectError(error.AssertionFailed, tardis.check(testing.allocator, syncOff, replay));
}

fn walFull(env: *Env) !void {
    return scenarioIn(env, .full, true);
}

test "sqlite: in WAL mode, with its index mapped shared, synchronous=FULL keeps the acknowledged commit" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    try tardis.check(testing.allocator, walFull, options);
}

test "sqlite: with synchronous=EXTRA the acknowledged commit survives" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    try tardis.check(testing.allocator, syncExtra, options);
}

test "sqlite: with synchronous=FULL, the default, a lost unlink of the journal rolls the commit back" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    var o = options;
    o.report = false;
    var shrunk: tardis.ShrinkReport = .{};
    o.shrink_report = &shrunk;
    try testing.expectError(error.AssertionFailed, tardis.check(testing.allocator, syncFull, o));
    try testing.expect(shrunk.shrunk);
    // The database is whole and the commit is gone: a rollback, nothing else.
    var replay = options;
    replay.report = false;
    replay.replay = shrunk.token();
    try testing.expectError(error.AssertionFailed, tardis.check(testing.allocator, syncFull, replay));
    try testing.expectEqual(Broken.row_lost, broken);
    std.debug.print("sqlite, synchronous=FULL: found, shrunk from {d} to {d} decisions\n", .{ shrunk.before, shrunk.after });
    // Where a crash cannot lose a finished unlink, there is no such run.
    var kind = options;
    kind.faults.metadata_loss = false;
    try tardis.check(testing.allocator, syncFull, kind);
}

/// One task's database: created, written and read back while the other
/// task does the same to its own.
fn ownDatabase(path: [*:0]const u8) !void {
    const db = try openPath(path);
    defer _ = sqlite3_close(db);
    try exec(db, "CREATE TABLE kv(k INTEGER PRIMARY KEY, v TEXT)");
    try exec(db, "INSERT INTO kv VALUES(1, 'one')");
    try exec(db, "INSERT INTO kv VALUES(2, 'two')");
    const n = try query(db, "SELECT count(*) FROM kv");
    try testing.expectEqualStrings("2", n.text());
}

fn ownDatabaseTask(path: [*:0]const u8) void {
    ownDatabase(path) catch @panic("the second task's database failed");
}

fn twoTasks(env: *Env) !void {
    sqlite3_randomness(0, null);
    var other = try env.io.concurrent(ownDatabaseTask, .{"b.db"});
    try ownDatabase("a.db");
    other.await(env.io);
}

test "sqlite: two tasks, two databases, SQLite's own mutexes between them" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    try tardis.check(testing.allocator, twoTasks, options);
}

// --- real threads (revision 97) ----------------------------------------------------
//
// `pthread_create` is a `clone`, which system-call mode turns into a
// simulated task with its own stack and thread pointer
// (`src/sim/systhread.zig`). A thread may make system calls, as SQLite
// does; it may not use `env.io`.

const Pthread = ?*anyopaque;
extern fn pthread_create(thread: *Pthread, attr: ?*const anyopaque, start: *const fn (?*anyopaque) callconv(.c) ?*anyopaque, arg: ?*anyopaque) c_int;
extern fn pthread_join(thread: Pthread, result: ?*?*anyopaque) c_int;

fn databaseThread(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    const path: [*:0]const u8 = @ptrCast(arg.?);
    ownDatabase(path) catch return @ptrFromInt(1);
    return null;
}

fn twoThreads(env: *Env) !void {
    _ = env;
    sqlite3_randomness(0, null);
    var threads: [2]Pthread = undefined;
    const paths = [2][*:0]const u8{ "a.db", "b.db" };
    for (&threads, paths) |*t, path| try testing.expectEqual(@as(c_int, 0), pthread_create(t, null, databaseThread, @constCast(path)));
    for (threads) |t| {
        var result: ?*anyopaque = null;
        try testing.expectEqual(@as(c_int, 0), pthread_join(t, &result));
        try testing.expect(result == null);
    }
}

test "sqlite: two pthreads, a database each" {
    if (!supported or !tardis.syscallModeAvailable() or !tardis.syscallThreadsAvailable()) return error.SkipZigTest;
    try tardis.check(testing.allocator, twoThreads, options);
}

/// Ten rows through a connection another thread is using too. SQLite's
/// connection mutex is recursive, and its owner is the thread: with real
/// threads it keeps the second one out, which two tasks on one thread
/// could not have.
fn insertingThread(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    const db: *Db = @ptrCast(arg.?);
    for (0..10) |_| exec(db, "INSERT INTO log(v) VALUES('x')") catch return @ptrFromInt(1);
    return null;
}

fn sharedConnection(env: *Env) !void {
    _ = env;
    sqlite3_randomness(0, null);
    const db = try open();
    defer _ = sqlite3_close(db);
    try exec(db, "CREATE TABLE log(k INTEGER PRIMARY KEY, v TEXT)");
    var threads: [2]Pthread = undefined;
    for (&threads) |*t| try testing.expectEqual(@as(c_int, 0), pthread_create(t, null, insertingThread, db));
    for (threads) |t| {
        var result: ?*anyopaque = null;
        try testing.expectEqual(@as(c_int, 0), pthread_join(t, &result));
        try testing.expect(result == null);
    }
    const n = try query(db, "SELECT count(*) FROM log");
    try testing.expectEqualStrings("20", n.text());
    const integrity = try query(db, "PRAGMA integrity_check");
    try testing.expectEqualStrings("ok", integrity.text());
}

test "sqlite: two pthreads share one connection" {
    if (!supported or !tardis.syscallModeAvailable() or !tardis.syscallThreadsAvailable()) return error.SkipZigTest;
    try tardis.check(testing.allocator, sharedConnection, options);
}

/// libc reads its clocks through the vDSO, with no system call. The image
/// is found through the auxiliary vector, which in a program linked with
/// libc is libc's to give: found nowhere, it was never protected, and a C
/// library's clock was the machine's (until revision 99).
fn libcClock(env: *Env) !void {
    var ts: std.c.timespec = undefined;
    try testing.expectEqual(@as(c_int, 0), std.c.clock_gettime(.MONOTONIC, &ts));
    try testing.expectEqual(env.nowNs(), @as(u64, @intCast(ts.sec * std.time.ns_per_s + ts.nsec)));
    const req: std.c.timespec = .{ .sec = 0, .nsec = 250 * std.time.ns_per_ms };
    _ = std.c.nanosleep(&req, null);
    var later: std.c.timespec = undefined;
    try testing.expectEqual(@as(c_int, 0), std.c.clock_gettime(.MONOTONIC, &later));
    try testing.expectEqual(env.nowNs(), @as(u64, @intCast(later.sec * std.time.ns_per_s + later.nsec)));
    try testing.expect(later.sec * std.time.ns_per_s + later.nsec >= ts.sec * std.time.ns_per_s + ts.nsec + 250 * std.time.ns_per_ms);
}

test "libc: a clock read through the vDSO is in virtual time" {
    if (!supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    try tardis.check(testing.allocator, libcClock, .{ .iterations = 20, .mode = .syscalls });
}
