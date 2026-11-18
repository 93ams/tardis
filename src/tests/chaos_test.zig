//! M4: liveness after chaos (nemesis, heal, eventually) and the cost ledger.

const std = @import("std");
const tardis = @import("../root.zig");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const Stream = Io.net.Stream;
const Env = tardis.Env;
const testing = std.testing;
const gpa = testing.allocator;

const primary_port = 7000;
const replica_port = 7100;
const keys = 3;

fn any(port: u16) IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } };
}

fn roundTrip(io: Io, addr: IpAddress, request: []const u8, out: []u8) ![]const u8 {
    return roundTripTimeout(io, addr, request, out, .none);
}

fn roundTripTimeout(io: Io, addr: IpAddress, request: []const u8, out: []u8, timeout: Io.Timeout) ![]const u8 {
    const stream = try addr.connect(io, .{ .mode = .stream, .timeout = timeout });
    defer stream.close(io);
    var wbuf: [64]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeAll(request) catch return w.err.?;
    w.interface.flush() catch return w.err.?;
    var rbuf: [64]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    const line = r.interface.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.ReadFailed => return r.err.?,
        else => |e| return e,
    };
    @memcpy(out[0..line.len], line);
    return out[0..line.len];
}

const Forwarding = enum {
    /// Forward each write to the replica once; drop it if that fails.
    fire_and_forget,
    /// Retry the forward until the replica acknowledges it.
    retry_until_acked,
};

/// `W k v` / `R k`, one connection at a time. A primary forwards writes to
/// its replica before replying.
fn kvNode(io: Io, port: u16, replica: ?IpAddress, forwarding: Forwarding) !void {
    var values: [keys]u64 = @splat(0);
    var server = try any(port).listen(io, .{});
    defer server.deinit(io);
    while (true) {
        const stream = try server.accept(io);
        defer stream.close(io);
        var rbuf: [64]u8 = undefined;
        var r = stream.reader(io, &rbuf);
        const line = r.interface.takeDelimiterExclusive('\n') catch continue;
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const cmd = it.next() orelse continue;
        const key = std.fmt.parseInt(usize, it.next() orelse continue, 10) catch continue;
        var wbuf: [64]u8 = undefined;
        var w = stream.writer(io, &wbuf);
        if (cmd[0] == 'W') {
            const v = std.fmt.parseInt(u64, it.next() orelse continue, 10) catch continue;
            values[key] = v;
            if (replica) |addr| {
                var fwd: [32]u8 = undefined;
                const text = try std.fmt.bufPrint(&fwd, "W {d} {d}\n", .{ key, v });
                var out: [16]u8 = undefined;
                while (true) {
                    // A short connect timeout keeps a partitioned replica from
                    // stalling the primary.
                    _ = roundTripTimeout(io, addr, text, &out, .{ .duration = .{ .raw = .fromMilliseconds(100), .clock = .awake } }) catch {
                        if (forwarding == .fire_and_forget) break;
                        try io.sleep(.fromMilliseconds(50), .awake);
                        continue;
                    };
                    break;
                }
            }
            w.interface.writeAll("OK\n") catch continue;
        } else {
            w.interface.print("V {d}\n", .{values[key]}) catch continue;
        }
        w.interface.flush() catch continue;
    }
}

const Ctx = struct {
    io: Io,
    primary: IpAddress,
    replica: IpAddress,
    latency: *tardis.Histogram,
    now: *const fn (io: Io) u64,
};

fn nowNs(io: Io) u64 {
    return @intCast(Io.Clock.awake.now(io).nanoseconds);
}

fn writer(ctx: *Ctx, id: u64, plan: [5]u8) Io.Cancelable!void {
    for (plan, 0..) |c, i| {
        var req: [32]u8 = undefined;
        var out: [16]u8 = undefined;
        const text = std.fmt.bufPrint(&req, "W {d} {d}\n", .{ c % keys, id * 100 + i + 1 }) catch unreachable;
        const t0 = ctx.now(ctx.io);
        if (roundTrip(ctx.io, ctx.primary, text, &out)) |_| {
            ctx.latency.record(ctx.now(ctx.io) - t0);
        } else |_| {}
        try ctx.io.sleep(.fromMilliseconds(20), .awake);
    }
}

fn readValue(io: Io, addr: IpAddress, key: usize) !u64 {
    var req: [16]u8 = undefined;
    var out: [32]u8 = undefined;
    const reply = try roundTrip(io, addr, try std.fmt.bufPrint(&req, "R {d}\n", .{key}), &out);
    return std.fmt.parseInt(u64, reply[2..], 10);
}

fn replicasAgree(ctx: *Ctx) !bool {
    for (0..keys) |k| {
        if (try readValue(ctx.io, ctx.primary, k) != try readValue(ctx.io, ctx.replica, k)) return false;
    }
    return true;
}

fn scenario(env: *Env, forwarding: Forwarding, chaos: bool) !void {
    const io = env.io;
    try env.spawnOn(2, kvNode, .{ io, replica_port, null, forwarding });
    try env.spawnOn(1, kvNode, .{ io, primary_port, env.address(2, replica_port), forwarding });
    try io.sleep(.fromMilliseconds(1), .awake);

    var latency: tardis.Histogram = .{};
    var ctx: Ctx = .{ .io = io, .primary = env.address(1, primary_port), .replica = env.address(2, replica_port), .latency = &latency, .now = nowNs };
    if (chaos) try env.startChaos(.{});
    var group: Io.Group = .init;
    defer group.cancel(io);
    for (0..3) |i| try group.concurrent(io, writer, .{ &ctx, i, try env.fuzz([5]u8) });
    try io.sleep(.fromSeconds(2), .awake);
    env.heal();
    try group.await(io);

    try env.eventually("the replica converges to the primary", 30 * std.time.ns_per_s, &ctx, replicasAgree);
    if (!chaos) {
        // Healthy-cluster SLO: a write (two round trips) stays fast.
        try env.always("healthy p99 write latency is under 50 ms", latency.quantile(990_000) < 50 * std.time.ns_per_ms);
    }
}

fn retriesUnderChaos(env: *Env) !void {
    return scenario(env, .retry_until_acked, true);
}

fn fireAndForgetUnderChaos(env: *Env) !void {
    return scenario(env, .fire_and_forget, true);
}

fn healthy(env: *Env) !void {
    return scenario(env, .fire_and_forget, false);
}

test "chaos: replication that retries converges after chaos heals" {
    try tardis.check(gpa, retriesUnderChaos, .{ .nodes = 3, .iterations = 30, .shrink = false });
}

test "chaos: fire-and-forget replication never converges (bug found)" {
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, fireAndForgetUnderChaos, .{
        .nodes = 3,
        .iterations = 30,
        .report = false,
        .shrink = false,
    }));
}

test "chaos: without chaos, fire-and-forget converges and meets its latency SLO" {
    try tardis.check(gpa, healthy, .{ .nodes = 3, .iterations = 30, .shrink = false });
}

// ---------------------------------------------------------------------------
// Automatic chaos -> heal schedule (`Options.chaos`)

/// The same cluster, but chaos is started and healed by `check`.
fn scheduledScenario(env: *Env, forwarding: Forwarding) !void {
    const io = env.io;
    try env.spawnOn(2, kvNode, .{ io, replica_port, null, forwarding });
    try env.spawnOn(1, kvNode, .{ io, primary_port, env.address(2, replica_port), forwarding });
    var latency: tardis.Histogram = .{};
    var ctx: Ctx = .{ .io = io, .primary = env.address(1, primary_port), .replica = env.address(2, replica_port), .latency = &latency, .now = nowNs };
    var group: Io.Group = .init;
    defer group.cancel(io);
    for (0..3) |i| try group.concurrent(io, writer, .{ &ctx, i, try env.fuzz([5]u8) });
    try env.awaitHeal();
    try group.await(io);
    try env.eventually("the replica converges to the primary", 30 * std.time.ns_per_s, &ctx, replicasAgree);
}

fn scheduledRetries(env: *Env) !void {
    return scheduledScenario(env, .retry_until_acked);
}

fn scheduledFireAndForget(env: *Env) !void {
    return scheduledScenario(env, .fire_and_forget);
}

const schedule: tardis.Chaos = .{ .nemesis = .{ .interval_min_ns = 5 * std.time.ns_per_ms, .interval_max_ns = 50 * std.time.ns_per_ms }, .duration_min_ns = 200 * std.time.ns_per_ms, .duration_max_ns = 2 * std.time.ns_per_s };

test "chaos schedule: check runs chaos, heals it, and the retrying cluster converges" {
    try tardis.check(gpa, scheduledRetries, .{ .nodes = 3, .iterations = 30, .shrink = false, .chaos = schedule });
}

test "chaos schedule: fire-and-forget is caught, and the failure shrinks and replays" {
    var report: tardis.ShrinkReport = .{};
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, scheduledFireAndForget, .{ .nodes = 3, .iterations = 30, .report = false, .chaos = schedule, .shrink_report = &report }));
    try testing.expect(report.shrunk);
    try testing.expect(report.after < report.before);
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, scheduledFireAndForget, .{ .nodes = 3, .chaos = schedule, .replay = report.token(), .report = false, .shrink = false }));
}

var healed_at_ns: u64 = 0;

fn chaosDuration(env: *Env) !void {
    try env.always("chaos is running", env.sim.chaos_active);
    try env.awaitHeal();
    healed_at_ns = env.nowNs();
    try env.always("chaos healed", !env.sim.chaos_active);
    try env.always("chaos lasts under 2 s", healed_at_ns < 2 * std.time.ns_per_s);
}

test "chaos schedule: the chaos duration is a decision, shrunk to the boundary" {
    var report: tardis.ShrinkReport = .{};
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, chaosDuration, .{ .iterations = 50, .report = false, .chaos = .{}, .shrink_report = &report }));
    // The shrunk run (re-run last) heals exactly at the boundary.
    try testing.expectEqual(@as(u64, 2 * std.time.ns_per_s), healed_at_ns);
    try testing.expect(report.values >= 1);
}

// ---------------------------------------------------------------------------
// Write amplification

fn appendLog(env: *Env, records_per_sync: usize) !u64 {
    const io = env.io;
    var f = try env.dir.createFile(io, "log", .{});
    defer f.close(io);
    var off: u64 = 0;
    for (0..64) |i| {
        try f.writePositionalAll(io, "0123456789abcdef", off);
        off += 16;
        if ((i + 1) % records_per_sync == 0) try f.sync(io);
    }
    return tardis.ledger.ratioPpm(env.flushedBytes(), env.stats().disk_write_bytes);
}

fn syncEveryRecord(env: *Env) !void {
    const wa = try appendLog(env, 1);
    // 64 fsyncs, each flushing the log's one 4 KiB page, for 1 KiB of data.
    try testing.expectEqual(@as(u64, 256_000_000), wa);
    try env.always("write amplification is at most 32x", wa <= 32_000_000);
}

fn syncEvery16(env: *Env) !void {
    const wa = try appendLog(env, 16);
    try testing.expectEqual(@as(u64, 16_000_000), wa);
    try testing.expectEqual(@as(u64, 4), env.stats().disk_syncs);
    try env.always("write amplification is at most 32x", wa <= 32_000_000);
}

test "ledger: write amplification is exact and deterministic" {
    try tardis.check(gpa, syncEvery16, .{ .iterations = 10, .faults = .{ .short_io_ppm = 0 } });
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, syncEveryRecord, .{
        .iterations = 1,
        .faults = .{ .short_io_ppm = 0 },
        .report = false,
        .shrink = false,
    }));
}

fn warm(env: *Env) !void {
    try env.dir.writeFile(env.io, .{ .sub_path = "warm", .data = "x" });
}

fn healsInTime(env: *Env) !void {
    try env.always("chaos is running", env.sim.chaos_active);
    try env.awaitHeal();
    try env.always("healed within the schedule", !env.sim.chaos_active and env.nowNs() >= 500 * std.time.ns_per_ms and env.nowNs() <= 5 * std.time.ns_per_s);
}

test "chaos schedule: works with warm starts and the fork server" {
    try tardis.check(gpa, healsInTime, .{ .iterations = 20, .chaos = .{}, .setup = warm, .fork = true });
    try tardis.check(gpa, healsInTime, .{ .iterations = 20, .chaos = .{}, .setup = warm, .fork = true, .workers = 2 });
}
