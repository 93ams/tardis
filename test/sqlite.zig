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
//! adds. The third test pins it.
//!
//! SQLite keeps state for the life of the process (its random number
//! generator is seeded once, from `/dev/urandom`). A run must not inherit
//! it, or the same seed gives two different runs, which `check` reports as
//! `error.NonDeterministic`: so the program resets the generator first.
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
    var db: ?*Db = null;
    if (sqlite3_open("app.db", &db) != 0) {
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
