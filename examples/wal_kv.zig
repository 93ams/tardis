//! Example: a key-value store with a write-ahead log.
//!
//! The bug class: **acknowledging a write before it is durable.** `put`
//! appends a record to the log and returns. The buggy store returns as
//! soon as the bytes are written; the fixed one returns after `sync`. On
//! a machine that never loses power the two behave the same, which is why
//! this bug survives ordinary tests.
//!
//! The property: every `put` that returned is still there after a power
//! loss.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

/// A record: key, value, and a check byte so a torn tail is recognised.
const record_bytes = 3;

fn checkByte(key: u8, value: u8) u8 {
    return key ^ value ^ 0x5a;
}

const Store = struct {
    io: Io,
    log: Io.File,
    end: u64 = 0,
    variant: Variant,

    fn put(s: *Store, key: u8, value: u8) !void {
        const record: [record_bytes]u8 = .{ key, value, checkByte(key, value) };
        try s.log.writePositionalAll(s.io, &record, s.end);
        s.end += record_bytes;
        // The whole difference between the two stores.
        if (s.variant == .fixed) try s.log.sync(s.io);
    }
};

/// Rebuilds the table from the log, stopping at the first record that does
/// not check out (a tail the crash cut short).
fn recover(io: Io, dir: Io.Dir, table: *[256]?u8) !void {
    var buf: [4096]u8 = undefined;
    const bytes = dir.readFile(io, "wal", &buf) catch |err| switch (err) {
        error.FileNotFound => return,
        else => |e| return e,
    };
    var at: usize = 0;
    while (at + record_bytes <= bytes.len) : (at += record_bytes) {
        const key = bytes[at];
        const value = bytes[at + 1];
        if (bytes[at + 2] != checkByte(key, value)) return;
        table[key] = value;
    }
}

fn syncDir(io: Io, dir: Io.Dir) !void {
    var d = try dir.openFile(io, ".", .{});
    defer d.close(io);
    try d.sync(io);
}

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    var acknowledged: [256]?u8 = @splat(null);
    {
        // Creating the log durably is not what this example is about: both
        // stores sync the file and its directory entry.
        const log = try env.dir.createFile(io, "wal", .{});
        defer log.close(io);
        try log.sync(io);
        try syncDir(io, env.dir);

        var store: Store = .{ .io = io, .log = log, .variant = variant };
        const puts = 1 + (try env.fuzz(u8)) % 8;
        for (0..puts) |_| {
            const key = try env.fuzz(u8);
            const value = try env.fuzz(u8);
            try store.put(key, value);
            acknowledged[key] = value;
        }
    }

    try env.crashAndReboot(.power_loss);

    var recovered: [256]?u8 = @splat(null);
    try recover(io, env.dir, &recovered);
    for (acknowledged, recovered) |want, got| {
        const value = want orelse continue;
        try env.always("an acknowledged put survives a power loss", got != null and got.? == value);
    }
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "wal_kv: acknowledging before sync loses a write in a power loss" {
    var shrunk: tardis.ShrinkReport = .{};
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, .{
        .iterations = 200,
        .report = false,
        .shrink_report = &shrunk,
    }));
    // The reproduction is a handful of decisions, not the whole run.
    try std.testing.expect(shrunk.shrunk and shrunk.after <= 6);
}

test "wal_kv: syncing before acknowledging holds on every filesystem persona" {
    try tardis.check(std.testing.allocator, fixed, .{
        .iterations = 200,
        .personas = &.{ .linux_ext4, .linux_xfs, .windows_ntfs, .posix_strict, .macos_apfs, .freebsd_zfs },
    });
}
