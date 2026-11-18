//! Shadow memory (plan2.md §3.8): code built with the sanitizer's
//! callbacks (`tests/shadow/sut.zig`, a Zig object), and C built with
//! clang's load and store tracing (`tests/c/shadow.c`), have every load
//! and store checked against the simulated heap's state, so a bad access
//! is found where it happens.

const std = @import("std");
const tardis = @import("tardis");
const sec = @import("tardis_sec");
const Env = tardis.Env;
const gpa = std.testing.allocator;

comptime {
    sec.exportSanitizer();
    sec.exportCoverage();
}

extern fn sut_fill(p: [*]u8, n: usize, value: u8) void;
extern fn sut_sum(p: [*]const u8, n: usize) u32;
extern fn sut_copy(dst: [*]u8, src: [*]const u8, n: usize) void;
extern fn sut_peek(p: *const u8) u8;
extern fn sut_count(p: *u32) u32;
extern fn sut_parse(a: *const std.mem.Allocator, input: [*]const u8, claimed: usize, size: usize) i64;
extern fn c_fill(p: [*]u8, n: usize, value: u8) void;
extern fn c_at(p: [*]const u8, i: usize) c_uint;

const size = 24;

fn expectFinding(comptime body: fn (*Env) anyerror!void, cwe: u16, kind: sec.engine.Kind) !sec.engine.Finding {
    var report: sec.engine.Report = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, body, sec.withSecurity(.{
        .shadow_memory = true,
        .report = &report,
        .base = .{ .iterations = 50, .report = false },
    })));
    try std.testing.expectEqual(cwe, report.findings[0].cwe);
    try std.testing.expectEqual(kind, report.findings[0].kind);
    return report.findings[0];
}

fn expectClean(comptime body: fn (*Env) anyerror!void) !void {
    try tardis.check(gpa, body, sec.withSecurity(.{ .shadow_memory = true, .base = .{ .iterations = 50 } }));
}

fn fill(env: *Env, bounded: bool) !void {
    const claimed = 1 + (try env.fuzz(u8)) % 40;
    const buf = try env.allocator.alloc(u8, size);
    defer env.allocator.free(buf);
    sut_fill(buf.ptr, if (bounded) @min(claimed, size) else claimed, 7);
}
fn fillPast(env: *Env) !void {
    return fill(env, false);
}
fn fillBounded(env: *Env) !void {
    return fill(env, true);
}

test "shadow: a store past the end of an allocation is CWE-787 at the store" {
    _ = try expectFinding(fillPast, 787, .write_past_end);
    try expectClean(fillBounded);
}

fn sum(env: *Env, bounded: bool) !void {
    const buf = try env.allocator.alloc(u8, size);
    defer env.allocator.free(buf);
    @memset(buf, 1);
    // Off by one: `<=` where `<` was meant.
    const total = sut_sum(buf.ptr, if (bounded) size else size + 1);
    if (bounded) try std.testing.expectEqual(@as(u32, size), total);
}
fn sumPast(env: *Env) !void {
    return sum(env, false);
}
fn sumBounded(env: *Env) !void {
    return sum(env, true);
}

test "shadow: a load past the end is CWE-125 without the bytes ever leaving" {
    _ = try expectFinding(sumPast, 125, .read_past_end);
    try expectClean(sumBounded);
}

fn peekFreed(env: *Env) !void {
    const buf = try env.allocator.alloc(u8, size);
    @memset(buf, 9);
    env.allocator.free(buf);
    _ = sut_peek(&buf.ptr[3]);
}

fn peekLive(env: *Env) !void {
    const buf = try env.allocator.alloc(u8, size);
    defer env.allocator.free(buf);
    @memset(buf, 9);
    try std.testing.expectEqual(@as(u8, 9), sut_peek(&buf[3]));
}

test "shadow: a load from a freed block is CWE-416 at the load" {
    const f = try expectFinding(peekFreed, 416, .use_after_free);
    try std.testing.expectEqual(@as(u32, 0), f.offset); // a read
    try std.testing.expectEqual(@as(u16, 1), f.detail[0]);
    try expectClean(peekLive);
}

fn copy(env: *Env, bounded: bool) !void {
    const src = try env.allocator.alloc(u8, 64);
    defer env.allocator.free(src);
    @memset(src, 3);
    const dst = try env.allocator.alloc(u8, size);
    defer env.allocator.free(dst);
    sut_copy(dst.ptr, src.ptr, if (bounded) size else size + 8);
}
fn copyPast(env: *Env) !void {
    return copy(env, false);
}
fn copyBounded(env: *Env) !void {
    return copy(env, true);
}

test "shadow: the compiler's memcpy is checked too" {
    _ = try expectFinding(copyPast, 787, .write_past_end);
    try expectClean(copyBounded);
}

fn parse(env: *Env, bounded: bool) !void {
    var input: [64]u8 = undefined;
    for (&input) |*b| b.* = try env.fuzz(u8);
    const claimed = input[0] % 40;
    const a = env.allocator;
    const got = sut_parse(&a, &input, if (bounded) @min(claimed, size) else claimed, size);
    // The simulated heap may refuse an allocation, as any other.
    if (got < 0) return error.OutOfMemory;
}
fn parsePast(env: *Env) !void {
    return parse(env, false);
}
fn parseBounded(env: *Env) !void {
    return parse(env, true);
}

test "shadow: code that allocates from the simulated heap is found, shrunk, and clean when bounded" {
    var report: sec.engine.Report = .{};
    var shrunk: tardis.ShrinkReport = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, parsePast, sec.withSecurity(.{
        .shadow_memory = true,
        .report = &report,
        .base = .{ .iterations = 200, .report = false, .shrink_report = &shrunk },
    })));
    try std.testing.expectEqual(sec.engine.Kind.write_past_end, report.findings[0].kind);
    try std.testing.expect(shrunk.shrunk and shrunk.after <= 4);
    try expectClean(parseBounded);
}

fn atomics(env: *Env) !void {
    const n = try env.allocator.create(u32);
    defer env.allocator.destroy(n);
    n.* = 40;
    try std.testing.expectEqual(@as(u32, 40), sut_count(n));
    try std.testing.expectEqual(@as(u32, 41), sut_count(n));
    try std.testing.expectEqual(@as(u32, 42), n.*);
}

fn atomicFreed(env: *Env) !void {
    const n = try env.allocator.create(u32);
    n.* = 0;
    env.allocator.destroy(n);
    _ = sut_count(n);
}

test "shadow: atomics go through the runtime, performed and checked" {
    try expectClean(atomics);
    const f = try expectFinding(atomicFreed, 416, .use_after_free);
    try std.testing.expectEqual(@as(u32, 1), f.offset); // a write
}

fn cFill(env: *Env, bounded: bool) !void {
    const buf = try env.allocator.alloc(u8, size);
    defer env.allocator.free(buf);
    c_fill(buf.ptr, if (bounded) size else size + 2, 1);
    _ = c_at(buf.ptr, size - 1);
}
fn cPast(env: *Env) !void {
    return cFill(env, false);
}
fn cBounded(env: *Env) !void {
    return cFill(env, true);
}

fn cReadPast(env: *Env) !void {
    const buf = try env.allocator.alloc(u8, size);
    defer env.allocator.free(buf);
    @memset(buf, 0);
    _ = c_at(buf.ptr, size + 5);
}

test "shadow: instrumented C is checked the same way" {
    _ = try expectFinding(cPast, 787, .write_past_end);
    const f = try expectFinding(cReadPast, 125, .read_past_end);
    // Five guard bytes lie between the end and the byte read.
    try std.testing.expectEqual(@as(u32, 5), f.offset);
    try expectClean(cBounded);
}

test "shadow: without shadow_memory the callbacks check nothing" {
    // The guard is still found changed at the free (CWE-787 there), and a
    // read past the end goes unseen: what the shadow adds.
    var report: sec.engine.Report = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, fillPast, sec.withSecurity(.{
        .report = &report,
        .base = .{ .iterations = 50, .report = false },
    })));
    try std.testing.expectEqual(sec.engine.Kind.overflow, report.findings[0].kind);
    try tardis.check(gpa, sumPast, sec.withSecurity(.{ .base = .{ .iterations = 20 } }));
}

test "shadow: outside a simulation the instrumented code just runs" {
    var buf: [size]u8 = undefined;
    sut_fill(&buf, size, 2);
    try std.testing.expectEqual(@as(u32, 2 * size), sut_sum(&buf, size));
}

// --- data races (plan2.md §4.5) ---------------------------------------------

const Io = std.Io;

extern fn sut_bump(p: *u64) void;
extern fn sut_read(p: *const u64) u64;
extern fn sut_bump_locked(io: *const Io, m: *Io.Mutex, p: *u64) void;
extern fn sut_bump_atomic(p: *u64) void;

const Bump = enum { plain, locked, atomic };

fn bumper(io: Io, how: Bump, m: *Io.Mutex, p: *u64) Io.Cancelable!void {
    switch (how) {
        .plain => sut_bump(p),
        .locked => sut_bump_locked(&io, m, p),
        .atomic => sut_bump_atomic(p),
    }
}

/// Two tasks bump one heap counter; the parent reads it after the group.
fn counter(env: *Env, how: Bump, together: bool) !void {
    const p = try env.allocator.create(u64);
    defer env.allocator.destroy(p);
    p.* = 0;
    var mutex: Io.Mutex = .init;
    var group: Io.Group = .init;
    try group.concurrent(env.io, bumper, .{ env.io, how, &mutex, p });
    // One after the other: the second task is spawned by a parent that
    // has the first one's result.
    if (!together) try group.await(env.io);
    try group.concurrent(env.io, bumper, .{ env.io, how, &mutex, p });
    try group.await(env.io);
    try std.testing.expectEqual(@as(u64, 2), sut_read(p));
}

fn counterPlain(env: *Env) !void {
    return counter(env, .plain, true);
}
fn counterInTurn(env: *Env) !void {
    return counter(env, .plain, false);
}
fn counterLocked(env: *Env) !void {
    return counter(env, .locked, true);
}
fn counterAtomic(env: *Env) !void {
    return counter(env, .atomic, true);
}

fn expectNoRace(comptime body: fn (*Env) anyerror!void) !void {
    try tardis.check(gpa, body, sec.withSecurity(.{ .data_races = true, .shadow_memory = true, .base = .{ .iterations = 50 } }));
}

test "race: two tasks bumping one counter with nothing between them are CWE-362" {
    var report: sec.engine.Report = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, counterPlain, sec.withSecurity(.{
        .data_races = true,
        .report = &report,
        .base = .{ .iterations = 50, .report = false },
    })));
    const f = report.findings[0];
    try std.testing.expectEqual(sec.engine.Kind.data_race, f.kind);
    try std.testing.expectEqual(@as(u16, 362), f.cwe);
    // The simulator ran the bumps one after the other, so the count is
    // right: without the detector this run passes.
    try tardis.check(gpa, counterPlain, sec.withSecurity(.{ .base = .{ .iterations = 50 } }));
}

test "race: a mutex, an atomic, or an await between them orders the two" {
    try expectNoRace(counterLocked);
    try expectNoRace(counterAtomic);
    try expectNoRace(counterInTurn);
}

// --- lock order (plan2.md §4.6) ---------------------------------------------

extern fn sut_lock_both(io: *const Io, first: *Io.Mutex, second: *Io.Mutex) void;

fn locker(io: Io, first: *Io.Mutex, second: *Io.Mutex) Io.Cancelable!void {
    sut_lock_both(&io, first, second);
}

/// Two tasks, one after the other, so no run deadlocks: the second takes
/// the two mutexes in the other order when `inverted`.
fn lockPair(env: *Env, inverted: bool) !void {
    var a: Io.Mutex = .init;
    var b: Io.Mutex = .init;
    var group: Io.Group = .init;
    try group.concurrent(env.io, locker, .{ env.io, &a, &b });
    try group.await(env.io);
    if (inverted) {
        try group.concurrent(env.io, locker, .{ env.io, &b, &a });
    } else {
        try group.concurrent(env.io, locker, .{ env.io, &a, &b });
    }
    try group.await(env.io);
}
fn lockInverted(env: *Env) !void {
    return lockPair(env, true);
}
fn lockSameOrder(env: *Env) !void {
    return lockPair(env, false);
}

test "lock order: two std.Io.Mutex taken in both orders are CWE-833, with no deadlock in the run" {
    var report: sec.engine.Report = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, lockInverted, sec.withSecurity(.{
        .atomic_lock_order = true,
        .report = &report,
        .base = .{ .iterations = 20, .report = false },
    })));
    try std.testing.expectEqual(sec.engine.Kind.lock_order, report.findings[0].kind);
    try std.testing.expectEqual(@as(u16, 833), report.findings[0].cwe);
    try tardis.check(gpa, lockSameOrder, sec.withSecurity(.{ .atomic_lock_order = true, .data_races = true, .base = .{ .iterations = 20 } }));
    // Off, the inverted order passes: no run deadlocks.
    try tardis.check(gpa, lockInverted, sec.withSecurity(.{ .base = .{ .iterations = 20 } }));
}
