//! Pillar I through core's seam (plan2.md §3, Milestone 5 (SEC) week 13):
//! planted leaks that reach a socket or a file are found by exploration,
//! fail the run with `error.SecurityViolation`, and name their CWE. The
//! fixed version of each program passes, and enabling the layer does not
//! change a run's trace.

const std = @import("std");
const tardis = @import("tardis");
const sec = @import("tardis_sec");
const Io = std.Io;
const Env = tardis.Env;
const gpa = std.testing.allocator;

const port = 4433;

// ---------------------------------------------------------------------------
// Heartbleed: an echo whose length comes from the request

/// Two tenants' records, adjacent in one heap block on the server.
const record_bytes = 32;
const tenant1_record = "t1: weather in Lisbon is sunny!!";
const tenant2_record = "t2: card 4111-1111-1111-1111 cvv";

fn heartbeatServer(io: Io, allocator: std.mem.Allocator, bounds_checked: bool) anyerror!void {
    const records = try allocator.alloc(u8, 2 * record_bytes);
    defer allocator.free(records);
    @memcpy(records[0..record_bytes], tenant1_record);
    @memcpy(records[record_bytes..], tenant2_record);
    sec.markTenant(records[0..record_bytes], 1);
    sec.markTenant(records[record_bytes..], 2);

    const addr: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } };
    var server = try addr.listen(io, .{});
    defer server.deinit(io);
    const stream = try server.accept(io);
    defer stream.close(io);

    var rbuf: [8]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    const claimed = r.interface.takeByte() catch return r.err orelse error.EndOfStream;
    // The bug: the reply length is the one the client claims.
    const n = if (bounds_checked) @min(claimed, record_bytes) else @min(claimed, records.len);
    var wbuf: [2 * record_bytes]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeAll(records[0..n]) catch return w.err.?;
    w.interface.flush() catch return w.err.?;
}

fn heartbeatClient(env: *Env, bounds_checked: bool) !void {
    const io = env.io;
    sec.bindNodeTenant(0, 1); // the test body is tenant 1's client
    try env.spawnOn(1, heartbeatServer, .{ io, env.nodeAllocator(1), bounds_checked });
    try io.sleep(.fromMilliseconds(1), .awake);
    const stream = try env.address(1, port).connect(io, .{ .mode = .stream });
    defer stream.close(io);
    const claimed: u8 = 1 + (try env.fuzz(u8)) % (2 * record_bytes);
    var wbuf: [4]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeByte(claimed) catch return w.err.?;
    w.interface.flush() catch return w.err.?;
    var rbuf: [2 * record_bytes]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    const cap: u8 = if (bounds_checked) record_bytes else 2 * record_bytes;
    _ = r.interface.take(@min(claimed, cap)) catch |err| switch (err) {
        error.ReadFailed => return r.err.?,
        else => |e| return e,
    };
    try io.sleep(.fromMilliseconds(5), .awake);
    if (env.daemonError()) |err| return err;
}

pub fn heartbleed(env: *Env) !void {
    return heartbeatClient(env, false);
}

pub fn heartbeatFixed(env: *Env) !void {
    return heartbeatClient(env, true);
}

test "heartbleed: tenant 2's record reaching tenant 1's client is CWE-668" {
    var report: sec.engine.Report = .{};
    var shrunk: tardis.ShrinkReport = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, heartbleed, sec.withSecurity(.{
        .report = &report,
        .base = .{ .nodes = 2, .iterations = 200, .report = false, .shrink_report = &shrunk },
    })));
    // The failure shrinks to a replay token with fewer natural decisions.
    try std.testing.expect(shrunk.shrunk);
    try std.testing.expect(shrunk.after < shrunk.before);
    try std.testing.expectEqual(@as(u8, 1), report.len);
    const f = report.findings[0];
    try std.testing.expectEqual(@as(u16, 668), f.cwe);
    try std.testing.expectEqual(@as(u8, 2), f.tenant);
    try std.testing.expectEqual(@as(u8, 1), f.dest_tenant);
    try std.testing.expectEqual(tardis.sec_seam.Sink.Kind.net_stream, f.sink.?.kind);
    try std.testing.expectEqual(@as(u8, 1), f.sink.?.node);
    try std.testing.expectEqual(@as(u8, 0), f.sink.?.peer_node);
}

test "heartbleed fixed: the bounds-checked echo passes" {
    try tardis.check(gpa, heartbeatFixed, sec.withSecurity(.{
        .base = .{ .nodes = 2, .iterations = 200 },
    }));
}

// ---------------------------------------------------------------------------
// Uninitialized heap bytes written to a file

fn sendRecord(env: *Env, whole_buffer: bool) !void {
    const buf = try env.allocator.alloc(u8, 64);
    defer env.allocator.free(buf);
    const header = "LEN=0012 record body";
    @memcpy(buf[0..header.len], header);
    const out = if (whole_buffer) buf else buf[0..header.len];
    try env.dir.writeFile(env.io, .{ .sub_path = "record.bin", .data = out });
}

pub fn uninitTail(env: *Env) !void {
    return sendRecord(env, true);
}

pub fn initOnly(env: *Env) !void {
    return sendRecord(env, false);
}

test "uninit: the unwritten tail of a heap buffer reaching a file is CWE-908" {
    var report: sec.engine.Report = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, uninitTail, sec.withSecurity(.{
        .report = &report,
        .base = .{ .iterations = 4, .report = false },
    })));
    try std.testing.expectEqual(@as(u16, 908), report.findings[0].cwe);
    try std.testing.expectEqual(tardis.sec_seam.Sink.Kind.file, report.findings[0].sink.?.kind);
    // The first window that is all pattern starts right after the header.
    try std.testing.expectEqual(@as(u32, 20), report.findings[0].offset);
    try tardis.check(gpa, initOnly, sec.withSecurity(.{ .base = .{ .iterations = 4 } }));
}

// ---------------------------------------------------------------------------
// Use after free reaching egress

pub fn useAfterFree(env: *Env) !void {
    const msg = try env.allocator.alloc(u8, 32);
    @memcpy(msg, "session=7f3a9c21; path=/; secure");
    env.allocator.free(msg);
    // `msg` dangles: the arena keeps the memory mapped, so this is a quiet
    // read of freed bytes that only shows when they leave.
    try env.dir.writeFile(env.io, .{ .sub_path = "cookie.txt", .data = msg });
}

test "use after free: freed bytes reaching a file are CWE-416" {
    var report: sec.engine.Report = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, useAfterFree, sec.withSecurity(.{
        .report = &report,
        .base = .{ .iterations = 4, .report = false },
    })));
    try std.testing.expectEqual(@as(u16, 416), report.findings[0].cwe);
}

fn useAfterReuse(env: *Env) !void {
    const msg = try env.allocator.alloc(u8, 32);
    @memcpy(msg, "session=7f3a9c21; path=/; secure");
    env.allocator.free(msg);
    // Same size, right after the free: a plain arena would hand back the
    // same block, and the dangling read would show this harmless text.
    // Core's reuse FIFO keeps the freed block out of reach instead.
    const other = try env.allocator.alloc(u8, 32);
    defer env.allocator.free(other);
    @memcpy(other, "harmless text, nothing to see!!!");
    try std.testing.expect(other.ptr != msg.ptr);
    try env.dir.writeFile(env.io, .{ .sub_path = "cookie.txt", .data = msg });
}

test "use after free: the reuse FIFO keeps freed bytes freed after the next allocation" {
    var report: sec.engine.Report = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, useAfterReuse, sec.withSecurity(.{
        .report = &report,
        .base = .{ .iterations = 4, .report = false },
    })));
    try std.testing.expectEqual(@as(u16, 416), report.findings[0].cwe);
}

// ---------------------------------------------------------------------------
// Past the end of a heap buffer: core's guard bytes

const field_bytes = 16;

/// Copies a client-sized field into a 16-byte buffer. `bounded` false (the
/// bug): the length is the one given, up to 24.
fn copyField(env: *Env, bounded: bool) !void {
    const input = "0123456789abcdefOVERFLOW";
    const claimed = 1 + (try env.fuzz(u8)) % input.len;
    const n = if (bounded) @min(claimed, field_bytes) else claimed;
    const buf = try env.allocator.alloc(u8, field_bytes);
    defer env.allocator.free(buf);
    @memcpy(buf.ptr[0..n], input[0..n]);
}

pub fn overflowField(env: *Env) !void {
    return copyField(env, false);
}

pub fn boundedField(env: *Env) !void {
    return copyField(env, true);
}

test "redzone: a write past the end of a heap buffer is CWE-787 at its free" {
    var report: sec.engine.Report = .{};
    var shrunk: tardis.ShrinkReport = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, overflowField, sec.withSecurity(.{
        .report = &report,
        .base = .{ .iterations = 50, .report = false, .shrink_report = &shrunk },
    })));
    try std.testing.expectEqual(@as(u16, 787), report.findings[0].cwe);
    // The first byte past the 16-byte buffer.
    try std.testing.expectEqual(@as(u32, field_bytes), report.findings[0].offset);
    try std.testing.expect(shrunk.shrunk and shrunk.after <= 5);
    try tardis.check(gpa, boundedField, sec.withSecurity(.{ .base = .{ .iterations = 50 } }));
}

/// Sends a 16-byte record with the length the caller claims. `bounded`
/// false (the bug): up to 32 bytes leave, the guard included.
fn sendClaimed(env: *Env, bounded: bool) !void {
    const claimed = 1 + (try env.fuzz(u8)) % 32;
    const n = if (bounded) @min(claimed, field_bytes) else claimed;
    const buf = try env.allocator.alloc(u8, field_bytes);
    defer env.allocator.free(buf);
    @memcpy(buf, "status: all good");
    try env.dir.writeFile(env.io, .{ .sub_path = "reply.bin", .data = buf.ptr[0..n] });
}

pub fn overRead(env: *Env) !void {
    return sendClaimed(env, false);
}

pub fn boundedRead(env: *Env) !void {
    return sendClaimed(env, true);
}

test "redzone: guard bytes leaving the program are an over-read, CWE-125" {
    var report: sec.engine.Report = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, overRead, sec.withSecurity(.{
        .report = &report,
        .base = .{ .iterations = 50, .report = false },
    })));
    try std.testing.expectEqual(@as(u16, 125), report.findings[0].cwe);
    try tardis.check(gpa, boundedRead, sec.withSecurity(.{ .base = .{ .iterations = 50 } }));
}

// ---------------------------------------------------------------------------
// Secrets: never leave, and are zeroized before free

fn keyLifecycle(env: *Env, zeroize: bool, leak: bool) !void {
    const key = try env.allocator.alloc(u8, 32);
    defer env.allocator.free(key);
    env.io.random(key);
    sec.markSecret(key);
    defer if (zeroize) std.crypto.secureZero(u8, key);
    if (leak) try env.dir.writeFile(env.io, .{ .sub_path = "debug.log", .data = key[4..20] });
}

pub fn keyZeroized(env: *Env) !void {
    return keyLifecycle(env, true, false);
}

pub fn keyNotZeroized(env: *Env) !void {
    return keyLifecycle(env, false, false);
}

pub fn keyLogged(env: *Env) !void {
    return keyLifecycle(env, true, true);
}

test "secrets: 16 bytes of a key in a log file are CWE-200" {
    var report: sec.engine.Report = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, keyLogged, sec.withSecurity(.{
        .report = &report,
        .base = .{ .iterations = 4, .report = false },
    })));
    try std.testing.expectEqual(@as(u16, 200), report.findings[0].cwe);
}

test "secrets: a zeroized key passes; an unzeroized one is CWE-226 where its bytes survive the free" {
    try tardis.check(gpa, keyZeroized, sec.withSecurity(.{ .base = .{ .iterations = 8 } }));
    if (sec.engine.safe_fill) {
        // `Allocator.free` already overwrote the key with 0xAA: no residue.
        try tardis.check(gpa, keyNotZeroized, sec.withSecurity(.{ .base = .{ .iterations = 8 } }));
    } else {
        var report: sec.engine.Report = .{};
        try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, keyNotZeroized, sec.withSecurity(.{
            .report = &report,
            .base = .{ .iterations = 8, .report = false },
        })));
        try std.testing.expectEqual(@as(u16, 226), report.findings[0].cwe);
    }
}

// ---------------------------------------------------------------------------
// Seam 4: the shrinker keeps the finding it was given

/// Every run leaks, but what leaks depends on the input: a small input logs
/// part of a key (CWE-200), any other leaks a buffer's uninitialized tail
/// (CWE-908). Lowering the input to 0 still fails with
/// `error.SecurityViolation`, but with the other finding.
fn leakByInput(env: *Env) !void {
    const v = try env.fuzz(u8);
    const buf = try env.allocator.alloc(u8, 64);
    defer env.allocator.free(buf);
    const header = "LEN=0012 record body";
    @memcpy(buf[0..header.len], header);
    if (v < 16) {
        // A fixed key: shrinking zeroes `io.random`, and zeros are not
        // distinctive enough to fingerprint.
        const key = buf[header.len..][0..32];
        @memcpy(key, "k3y:Zq9!pX27/vW5#mT0&hR4~bN8^cL$");
        sec.markSecret(key);
        defer std.crypto.secureZero(u8, key);
        try env.dir.writeFile(env.io, .{ .sub_path = "debug.log", .data = key[4..20] });
    } else {
        try env.dir.writeFile(env.io, .{ .sub_path = "record.bin", .data = buf });
    }
}

test "seam 4: shrinking keeps the original finding, not just the error" {
    const base: tardis.Options = .{ .seed = 0x5EC4_0001, .iterations = 1, .report = false };
    // The failing run as found (no shrinking): the uninitialized tail.
    var found: sec.engine.Report = .{};
    var unshrunk = base;
    unshrunk.shrink = false;
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, leakByInput, sec.withSecurity(.{ .report = &found, .base = unshrunk })));
    try std.testing.expectEqual(@as(u16, 908), found.findings[0].cwe);

    // Shrinking may only lower the input while CWE-908 on the file sink
    // still reproduces; the shrunk run (the last one) shows it.
    var shrunk_report: sec.engine.Report = .{};
    var shrunk: tardis.ShrinkReport = .{};
    var with_shrink = base;
    with_shrink.shrink_report = &shrunk;
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, leakByInput, sec.withSecurity(.{ .report = &shrunk_report, .base = with_shrink })));
    try std.testing.expect(shrunk.shrunk);
    try std.testing.expectEqual(@as(u8, 1), shrunk_report.len);
    try std.testing.expectEqual(@as(u16, 908), shrunk_report.findings[0].cwe);

    // The shrunk token replays to the same finding.
    var replayed: sec.engine.Report = .{};
    var replay = base;
    replay.replay = shrunk.token();
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, leakByInput, sec.withSecurity(.{ .report = &replayed, .base = replay })));
    try std.testing.expectEqual(@as(u16, 908), replayed.findings[0].cwe);
}

test "seam 4: TARDIS_SEC=1 attaches the engine to a check that names no layer" {
    // Plain core options: the uninitialized tail is invisible to core alone,
    // and found under `TARDIS_SEC=1 zig build test` (or `-Dsec`).
    const plain: tardis.Options = .{ .iterations = 4, .report = false };
    if (tardis.security_by_default) {
        try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, uninitTail, plain));
    } else {
        try tardis.check(gpa, uninitTail, plain);
    }
}

// ---------------------------------------------------------------------------
// Address and decision invariance: the layer observes, it does not steer

fn benign(env: *Env) !void {
    const io = env.io;
    try env.spawnOn(1, heartbeatServer, .{ io, env.nodeAllocator(1), true });
    try io.sleep(.fromMilliseconds(1), .awake);
    const stream = try env.address(1, port).connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var wbuf: [4]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeByte(16) catch return w.err.?;
    w.interface.flush() catch return w.err.?;
    var rbuf: [32]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    _ = r.interface.take(16) catch |err| switch (err) {
        error.ReadFailed => return r.err.?,
        else => |e| return e,
    };
    const log = try env.allocator.dupe(u8, "served one heartbeat\n");
    defer env.allocator.free(log);
    try env.dir.writeFile(io, .{ .sub_path = "log", .data = log });
    try io.sleep(.fromMilliseconds(5), .awake);
}

test "invariance: the same seeds give the same traces with and without tardis_sec" {
    const base: tardis.Options = .{ .nodes = 2 };
    for (0..16) |i| {
        const seed = tardis.runSeed(base.campaign_seed, @intCast(i), 0);
        const plain = try tardis.traceHash(gpa, benign, seed, .linux_ext4, base);
        const secured = try tardis.traceHash(gpa, benign, seed, .linux_ext4, sec.withSecurity(.{ .base = base }));
        try std.testing.expectEqual(plain, secured);
    }
}

test "seam 4: a failed check writes its SARIF, located at the test's call, with the replay token" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var shrunk: tardis.ShrinkReport = .{};
    const config: sec.SecurityConfig = .{ .check_sarif = &tmp.dir, .base = .{ .iterations = 4, .report = false, .shrink_report = &shrunk } };
    // A passing check writes nothing.
    try tardis.check(gpa, initOnly, sec.withSecurity(config));
    const call_line = @src().line + 1;
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, uninitTail, sec.withSecurity(config)));

    var it = tmp.dir.iterate();
    const entry = (try it.next(io)).?;
    try std.testing.expect(std.mem.endsWith(u8, entry.name, ".sarif"));
    try std.testing.expectEqual(@as(?std.Io.Dir.Entry, null), try it.next(io));
    const text = try tmp.dir.readFileAlloc(io, entry.name, gpa, .unlimited);
    defer gpa.free(text);
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
    defer parsed.deinit();
    const results = parsed.value.object.get("runs").?.array.items[0].object.get("results").?.array.items;
    try std.testing.expectEqual(@as(usize, 1), results.len);
    const r = results[0].object;
    try std.testing.expectEqualStrings("CWE-908", r.get("ruleId").?.string);
    const props = r.get("properties").?.object;
    try std.testing.expectEqualStrings(shrunk.token(), props.get("replayToken").?.string);
    // With debug info (not in stripped builds), the location is this test.
    if (r.get("locations")) |locs| {
        const loc = locs.array.items[0].object.get("physicalLocation").?.object;
        const uri = loc.get("artifactLocation").?.object.get("uri").?.string;
        try std.testing.expect(std.mem.endsWith(u8, uri, "src/sec/tests/pillar1_test.zig"));
        try std.testing.expectEqual(@as(i64, call_line), loc.get("region").?.object.get("startLine").?.integer);
    } else {
        try std.testing.expect(@import("builtin").mode == .small or @import("builtin").mode == .fast);
    }
}

/// Writes a record whose payload really is a run of 0xAA.
fn writesFillBytes(env: *Env) !void {
    var record: [32]u8 = @splat(0xAA);
    record[0] = 1;
    try env.dir.writeFile(env.io, .{ .sub_path = "record.bin", .data = &record });
}

test "undefined fill: a program that writes 0xAA itself is a false alarm unless it says so" {
    if (!sec.engine.safe_fill) return error.SkipZigTest;
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, writesFillBytes, sec.withSecurity(.{
        .base = .{ .iterations = 5, .report = false, .shrink = false },
    })));
    try tardis.check(gpa, writesFillBytes, sec.withSecurity(.{ .undefined_fill_is_data = true, .base = .{ .iterations = 5 } }));
}
