//! `zig build bench`: throughput of the simulator itself (plan §10, M5).
//!
//! Each benchmark runs a `tardis.check` campaign and divides host
//! wall-clock time by the work done. Numbers vary by machine; the point is
//! to compare changes on one machine and to keep the §10 targets honest.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const Env = tardis.Env;

fn emptyBody(env: *Env) !void {
    _ = env;
}

fn fileBody(env: *Env) !void {
    const io = env.io;
    var data: [4096]u8 = undefined;
    @memset(&data, 'x');
    {
        var f = try env.dir.createFile(io, "f", .{ .read = true });
        defer f.close(io);
        try f.writePositionalAll(io, &data, 0);
        try f.sync(io);
        var back: [4096]u8 = undefined;
        _ = try f.readPositionalAll(io, &back, 0);
    }
    try env.crashAndReboot(.power_loss);
    _ = try env.dir.statFile(io, "f", .{});
}

fn sleeper(io: Io, n: u32) Io.Cancelable!void {
    for (0..n) |_| try io.sleep(.fromNanoseconds(1), .awake);
}

const sleeps_per_task = 1000;

fn schedulerBody(env: *Env) !void {
    var group: Io.Group = .init;
    defer group.cancel(env.io);
    try group.concurrent(env.io, sleeper, .{ env.io, sleeps_per_task });
    try group.concurrent(env.io, sleeper, .{ env.io, sleeps_per_task });
    try group.await(env.io);
}

fn echoServer(io: Io, server: *Io.net.Server) !void {
    const stream = try server.accept(io);
    defer stream.close(io);
    var buf: [64]u8 = undefined;
    var r = stream.reader(io, &buf);
    const line = r.interface.takeDelimiterInclusive('\n') catch return;
    var wbuf: [64]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeAll(line) catch return;
    w.interface.flush() catch return;
}

fn netBody(env: *Env) !void {
    const io = env.io;
    const addr: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try addr.listen(io, .{});
    defer server.deinit(io);
    var f = try io.concurrent(echoServer, .{ io, &server });
    const stream = try Io.net.IpAddress.connect(&.{ .ip4 = .loopback(server.socket.address.ip4.port) }, io, .{ .mode = .stream });
    defer stream.close(io);
    var wbuf: [64]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    try w.interface.writeAll("ping\n");
    try w.interface.flush();
    var rbuf: [64]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    _ = try r.interface.takeDelimiterExclusive('\n');
    try f.await(io);
}

fn tornRename(env: *Env) !void {
    const io = env.io;
    try env.dir.writeFile(io, .{ .sub_path = "config", .data = "old-config" });
    {
        var f = try env.dir.openFile(io, "config", .{ .mode = .read_write });
        defer f.close(io);
        try f.sync(io);
    }
    try env.dir.writeFile(io, .{ .sub_path = "config.tmp", .data = "new-config" });
    try env.dir.rename("config.tmp", env.dir, "config", io);
    var d = try env.dir.openFile(io, ".", .{});
    try d.sync(io);
    d.close(io);
    try env.crashAndReboot(.power_loss);
    var buf: [32]u8 = undefined;
    const got = try env.dir.readFile(io, "config", &buf);
    try env.always("old or new", std.mem.eql(u8, got, "old-config") or std.mem.eql(u8, got, "new-config"));
}

/// The scheduler at `tasks` tasks: the same number of sleeps in all, so
/// the time per sleep shows what a reschedule costs as tasks are added
/// (the timer scan and the rank selection are linear in the task limit).
fn Scaling(comptime tasks: u32) type {
    return struct {
        const sleeps_total = 51_200;

        fn body(env: *Env) !void {
            var group: Io.Group = .init;
            defer group.cancel(env.io);
            for (0..tasks) |_| try group.concurrent(env.io, sleeper, .{ env.io, sleeps_total / tasks });
            try group.await(env.io);
        }

        fn run(gpa: std.mem.Allocator, io: Io) !void {
            const iterations = 20;
            const t0 = nowNs(io);
            try tardis.check(gpa, body, .{
                .iterations = iterations,
                .determinism_check_every = 0,
                .limits = .{ .tasks_max = tasks + 8, .fiber_stack_bytes = 64 * 1024 },
            });
            const elapsed: u64 = @intCast(nowNs(io) - t0);
            std.debug.print("scheduler: {d: >4} tasks, {d} sleeps      {d: >7} ns/sleep\n", .{ tasks, sleeps_total, elapsed / (iterations * sleeps_total) });
        }
    };
}

fn nowNs(io: Io) i96 {
    return Io.Clock.awake.now(io).nanoseconds;
}

fn campaign(gpa: std.mem.Allocator, io: Io, comptime name: []const u8, comptime body: fn (*Env) anyerror!void, iterations: u32, workers: u32, unit_per_run: u64, comptime unit: []const u8) !void {
    const t0 = nowNs(io);
    try tardis.check(gpa, body, .{ .iterations = iterations, .determinism_check_every = 0, .workers = workers });
    const elapsed: u64 = @intCast(nowNs(io) - t0);
    const runs_per_s = @as(u64, iterations) * std.time.ns_per_s / @max(elapsed, 1);
    const per_unit = elapsed / @max(@as(u64, iterations) * unit_per_run, 1);
    std.debug.print("{s: <34} workers={d: <3} {d: >9} runs/s   {d: >7} ns/{s}\n", .{ name, workers, runs_per_s, per_unit, unit });
}

pub fn main(init: std.process.Init) !void {
    const gpa = std.heap.smp_allocator;
    const io = init.io;
    // TARDIS_BENCH_SOLO=1: only the one-worker file campaign. Several
    // such processes at once show what the machine gives independent
    // work, to compare the in-process workers against.
    if (init.environ_map.get("TARDIS_BENCH_SOLO") != null) {
        return campaign(gpa, io, "file: write+sync+read+power loss", fileBody, 60_000, 1, 1, "run");
    }
    std.debug.print("TARDIS benchmarks (host wall-clock time; compare on one machine)\n\n", .{});
    try campaign(gpa, io, "empty body", emptyBody, 20_000, 1, 1, "run");
    try campaign(gpa, io, "file: write+sync+read+power loss", fileBody, 5_000, 1, 1, "run");
    try campaign(gpa, io, "scheduler: 2 tasks x 1000 sleeps", schedulerBody, 200, 1, 2 * sleeps_per_task, "sleep");
    try campaign(gpa, io, "net: loopback echo", netBody, 5_000, 1, 1, "run");

    std.debug.print("\nscheduler scaling:\n", .{});
    inline for (.{ 2, 64, 512 }) |tasks| try Scaling(tasks).run(gpa, io);

    const cpus: u32 = @intCast(std.Thread.getCpuCount() catch 1);
    const workers = @min(cpus, 8);
    std.debug.print("\nmulti-core campaigns ({d} CPUs):\n", .{cpus});
    try campaign(gpa, io, "file: write+sync+read+power loss", fileBody, 20_000, 1, 1, "run");
    try campaign(gpa, io, "file: write+sync+read+power loss", fileBody, 20_000, workers, 1, "run");

    std.debug.print("\nshrinking:\n", .{});
    const t0 = nowNs(io);
    var report: tardis.ShrinkReport = .{};
    _ = tardis.check(gpa, tornRename, .{ .iterations = 100, .personas = &.{.linux_xfs}, .report = false, .shrink_report = &report }) catch {};
    const elapsed: u64 = @intCast(nowNs(io) - t0);
    std.debug.print("{s: <34} {d} -> {d} decisions, {d} runs, {d} us total\n", .{ "torn rename (find + shrink)", report.before, report.after, report.runs, elapsed / 1000 });
    try guidedLock(gpa, io);
    try exhaustiveVote(gpa, io);
    try warmStarts(gpa, io);
}

/// Three nodes each send a vote to the other two over lossy UDP and wait
/// for votes: the model of the exhaustive-search tests.
fn voter(io: Io, env: *Env, me: u8) !void {
    const any: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 900 } };
    const sock = try any.bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    try io.sleep(.fromMilliseconds(1), .awake);
    for (0..3) |peer| {
        if (peer != me) try sock.send(io, &env.address(@intCast(peer), 900), &.{me + 1});
    }
    var buf: [8]u8 = undefined;
    for (0..2) |_| {
        _ = sock.receiveTimeout(io, &buf, .{ .duration = .{ .raw = .fromMilliseconds(10), .clock = .awake } }) catch |err| switch (err) {
            error.Timeout => break,
            else => return err,
        };
    }
}

fn voteBody(env: *Env) !void {
    try env.spawnOn(1, voter, .{ env.io, env, 1 });
    try env.spawnOn(2, voter, .{ env.io, env, 2 });
    try voter(env.io, env, 0);
    try env.io.sleep(.fromMilliseconds(50), .awake);
}

/// What one execution of the exhaustive search costs: each is replayed
/// from the start, so this is what a snapshot would have to beat.
fn exhaustiveVote(gpa: std.mem.Allocator, io: Io) !void {
    std.debug.print("\nexhaustive search (3 nodes, votes over lossy UDP, depth 12):\n", .{});
    const model: tardis.Options = .{
        .nodes = 3,
        .swarm = false,
        .preempt_ppm = 0,
        .async_inline_ppm = 0,
        .faults = .{ .short_io_ppm = 0, .spurious_wakeup_ppm = 0, .io_latency_min_ns = 1_000, .io_latency_max_ns = 1_000, .datagram_loss_ppm = 300_000, .datagram_duplicate_ppm = 0 },
        .net = .{ .latency_min_ns = 100_000, .latency_max_ns = 100_000 },
    };
    inline for (.{ .{ "every order", false, false }, .{ "reduce", true, false }, .{ "reduce and merge", true, true } }) |mode| {
        const t0 = nowNs(io);
        const r = try tardis.exhaustive(gpa, voteBody, model, .{ .depth_max = 12, .reduce = mode[1], .merge = mode[2] });
        const elapsed: u64 = @intCast(nowNs(io) - t0);
        std.debug.print("{s: <34} {d: >6} executions, {d: >6} ms, {d: >6} ns/execution\n", .{ mode[0], r.executions, elapsed / std.time.ns_per_ms, elapsed / @max(r.executions, 1) });
    }
}

fn combinationLock(env: *Env) !void {
    const code = [_]u8{ 7, 2, 13, 5, 11, 3 };
    var depth: u64 = 0;
    for (code) |digit| {
        const d = (try env.fuzz(u8)) % 16;
        if (d != digit) break;
        depth += 1;
        env.cover("depth", depth);
    }
    try env.always("the lock stays shut", depth < code.len);
}

/// Guided exploration: time to open a six-digit lock (one run in 16M at random).
fn guidedLock(gpa: std.mem.Allocator, io: Io) !void {
    std.debug.print("\nguided exploration (six-digit lock):\n", .{});
    for ([_]u32{ 1, 2, 8 }) |workers| {
        var ex: tardis.ExploreReport = .{};
        const t0 = nowNs(io);
        _ = tardis.check(gpa, combinationLock, .{ .iterations = 200_000, .explore = .guided, .workers = workers, .report = false, .shrink = false, .determinism_check_every = 0, .explore_report = &ex }) catch {};
        const elapsed: u64 = @intCast(nowNs(io) - t0);
        std.debug.print("{s: <34} workers={d: <3} found at iteration {?d}, {d} ms\n", .{ "open the lock", workers, ex.failed_at, elapsed / std.time.ns_per_ms });
    }
}

// Warm starts: an expensive deterministic setup, a cheap body.
var setup_rounds: usize = 1;

fn heavySetup(env: *Env) !void {
    const io = env.io;
    var data: [8192]u8 = undefined;
    @memset(&data, 'w');
    for (0..100 * setup_rounds) |j| {
        const i = j % 100;
        var name: [16]u8 = undefined;
        var f = try env.dir.createFile(io, try std.fmt.bufPrint(&name, "seg{d}", .{i}), .{});
        defer f.close(io);
        try f.writePositionalAll(io, &data, 0);
        try f.sync(io);
    }
}

fn smallBody(env: *Env) !void {
    var f = try env.dir.openFile(env.io, "seg42", .{});
    defer f.close(env.io);
    var buf: [16]u8 = undefined;
    _ = try f.readPositionalAll(env.io, &buf, 0);
}

pub fn warmStarts(gpa: std.mem.Allocator, io: Io) !void {
    for ([_]usize{ 1, 10, 50 }) |rounds| {
        setup_rounds = rounds;
        std.debug.print("\nwarm starts (setup: {d} x 100 writes of 8 KiB + fsync; body: one read):\n", .{rounds});
        // Setup run every time; started from a snapshot of what setup left;
        // and (on Linux) from a forked copy.
        inline for (.{
            .{ "setup per iteration", false, false },
            .{ "snapshot per iteration", true, false },
            .{ "fork per iteration", true, true },
        }) |mode| {
            const iterations: u32 = 200;
            const t0 = nowNs(io);
            try tardis.check(gpa, smallBody, .{ .iterations = iterations, .determinism_check_every = 0, .setup = heavySetup, .warm_restore = mode[1], .fork = mode[2] });
            const elapsed: u64 = @intCast(nowNs(io) - t0);
            std.debug.print("{s: <34} {d: >9} runs/s   {d: >7} ns/run\n", .{ mode[0], @as(u64, iterations) * std.time.ns_per_s / @max(elapsed, 1), elapsed / iterations });
        }
        {
            const iterations: u32 = 800;
            const t0 = nowNs(io);
            try tardis.check(gpa, smallBody, .{ .iterations = iterations, .determinism_check_every = 0, .setup = heavySetup, .fork = true, .workers = 8 });
            const elapsed: u64 = @intCast(nowNs(io) - t0);
            std.debug.print("{s: <34} {d: >9} runs/s   {d: >7} ns/run\n", .{ "fork per iteration, 8 workers", @as(u64, iterations) * std.time.ns_per_s / @max(elapsed, 1), elapsed / iterations });
        }
    }
}
