//! M2: virtual network, multiple nodes, partitions, node crashes, DNS,
//! clocks.

const std = @import("std");
const tardis = @import("../root.zig");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const Stream = Io.net.Stream;
const Env = tardis.Env;
const gpa = std.testing.allocator;

const kv_port = 7000;

fn any(port: u16) IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } };
}

/// Connects, retrying while the server is not listening yet.
fn connectRetry(io: Io, addr: IpAddress) !Stream {
    var attempts: u32 = 0;
    while (true) : (attempts += 1) {
        return addr.connect(io, .{ .mode = .stream }) catch |err| switch (err) {
            error.ConnectionRefused => {
                if (attempts == 50) return err;
                try io.sleep(.fromMilliseconds(10), .awake);
                continue;
            },
            else => return err,
        };
    }
}

/// Sends `request` and reads one line of reply into `out`.
fn roundTrip(io: Io, addr: IpAddress, request: []const u8, out: []u8) ![]const u8 {
    const stream = try connectRetry(io, addr);
    defer stream.close(io);
    var wbuf: [128]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeAll(request) catch return w.err.?;
    w.interface.flush() catch return w.err.?;
    var rbuf: [128]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    const line = r.interface.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.ReadFailed => return r.err.?,
        else => |e| return e,
    };
    @memcpy(out[0..line.len], line);
    return out[0..line.len];
}

// ---------------------------------------------------------------------------
// Loopback echo on a single node

fn echoOnce(io: Io, server: *Io.net.Server) !void {
    const stream = try server.accept(io);
    defer stream.close(io);
    var buf: [64]u8 = undefined;
    var r = stream.reader(io, &buf);
    const line = r.interface.takeDelimiterInclusive('\n') catch return r.err orelse error.EndOfStream;
    var wbuf: [64]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeAll(line) catch return w.err.?;
    w.interface.flush() catch return w.err.?;
}

fn echoBody(env: *Env) !void {
    const io = env.io;
    const addr: IpAddress = .{ .ip4 = .loopback(0) };
    var server = try addr.listen(io, .{});
    defer server.deinit(io);
    const port = server.socket.address.ip4.port;
    try std.testing.expect(port >= tardis.net.ephemeral_port_first);

    var f = try io.concurrent(echoOnce, .{ io, &server });
    var out: [64]u8 = undefined;
    const reply = try roundTrip(io, .{ .ip4 = .loopback(port) }, "ping\n", &out);
    try f.await(io);
    try std.testing.expectEqualStrings("ping", reply);
}

test "net: loopback echo" {
    try tardis.check(gpa, echoBody, .{ .iterations = 40 });
}

// ---------------------------------------------------------------------------
// A KV server on node 1, a client on node 0, and node crashes

const Durability = enum {
    /// fsync the log and its directory before acknowledging: correct.
    fsync_file_and_dir,
    /// fsync only the log: the new file's directory entry is not durable
    /// under `posix_strict`.
    fsync_file_only,
    /// Acknowledge at once; a background task fsyncs every 20 ms.
    group_commit,
};

fn syncDir(io: Io, dir: Io.Dir) !void {
    var d = try dir.openFile(io, ".", .{});
    defer d.close(io);
    try d.sync(io);
}

fn kvHandle(io: Io, stream: Stream, mode: Durability) !void {
    var rbuf: [128]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    const line = r.interface.takeDelimiterExclusive('\n') catch return r.err orelse error.EndOfStream;
    var wbuf: [128]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    const dir = Io.Dir.cwd(); // the node's own filesystem
    if (std.mem.startsWith(u8, line, "PUT ")) {
        var f = try dir.createFile(io, "db.log", .{ .truncate = false });
        defer f.close(io);
        const end = try f.length(io);
        var rec: [64]u8 = undefined;
        const text = try std.fmt.bufPrint(&rec, "{s}\n", .{line[4..]});
        try f.writePositionalAll(io, text, end);
        switch (mode) {
            .fsync_file_and_dir => {
                try f.sync(io);
                try syncDir(io, dir);
            },
            .fsync_file_only => try f.sync(io),
            .group_commit => {},
        }
        w.interface.writeAll("OK\n") catch return w.err.?;
        w.interface.flush() catch return w.err.?;
    } else if (std.mem.startsWith(u8, line, "GET ")) {
        const key = line[4..];
        var buf: [4096]u8 = undefined;
        const data = dir.readFile(io, "db.log", &buf) catch |err| switch (err) {
            error.FileNotFound => "",
            else => return err,
        };
        var found = false;
        var it = std.mem.splitScalar(u8, data, '\n');
        while (it.next()) |rec| {
            if (std.mem.eql(u8, rec, key)) found = true;
        }
        w.interface.writeAll(if (found) "HIT\n" else "MISS\n") catch return w.err.?;
        w.interface.flush() catch return w.err.?;
    } else return error.BadRequest;
}

fn flusher(io: Io) Io.Cancelable!void {
    const dir = Io.Dir.cwd();
    while (true) {
        try io.sleep(.fromMilliseconds(20), .awake);
        var f = dir.openFile(io, "db.log", .{}) catch continue;
        defer f.close(io);
        f.sync(io) catch {};
        syncDir(io, dir) catch {};
    }
}

fn kvServer(io: Io, mode: Durability) !void {
    var server = try any(kv_port).listen(io, .{});
    defer server.deinit(io);
    var group: Io.Group = .init;
    defer group.cancel(io);
    if (mode == .group_commit) try group.concurrent(io, flusher, .{io});
    while (true) {
        const stream = try server.accept(io);
        defer stream.close(io);
        // A broken connection affects only that client.
        kvHandle(io, stream, mode) catch |err| switch (err) {
            error.ConnectionResetByPeer, error.ConnectionTimedOut, error.EndOfStream => {},
            else => return err,
        };
    }
}

fn kvScenario(env: *Env, mode: Durability) !void {
    const io = env.io;
    const server_addr = env.address(1, kv_port);
    try env.spawnOn(1, kvServer, .{ io, mode });

    const n = 1 + (try env.fuzz(u8)) % 3;
    var acked: [3]bool = @splat(false);
    var out: [16]u8 = undefined;
    for (0..n) |i| {
        var req: [16]u8 = undefined;
        const text = try std.fmt.bufPrint(&req, "PUT k{d}\n", .{i});
        const reply = roundTrip(io, server_addr, text, &out) catch continue;
        acked[i] = std.mem.eql(u8, reply, "OK");
    }

    // Power fails at an arbitrary moment up to 40 ms later.
    try io.sleep(.fromMicroseconds((try env.fuzz(u16)) % 40_000), .awake);
    env.crashNode(1, .power_loss);
    try env.spawnOn(1, kvServer, .{ io, mode });

    for (0..n) |i| {
        if (!acked[i]) continue;
        var req: [16]u8 = undefined;
        const text = try std.fmt.bufPrint(&req, "GET k{d}\n", .{i});
        const reply = try roundTrip(io, server_addr, text, &out);
        try env.always("an acknowledged PUT survives a server crash", std.mem.eql(u8, reply, "HIT"));
    }
}

fn kvCorrect(env: *Env) !void {
    return kvScenario(env, .fsync_file_and_dir);
}

fn kvNoDirSync(env: *Env) !void {
    return kvScenario(env, .fsync_file_only);
}

fn kvGroupCommit(env: *Env) !void {
    return kvScenario(env, .group_commit);
}

const all_personas: []const tardis.Persona = &.{ .linux_ext4, .linux_xfs, .windows_ntfs, .posix_strict };

test "net: KV server that fsyncs file and directory keeps acknowledged writes across node crashes" {
    try tardis.check(gpa, kvCorrect, .{ .nodes = 2, .iterations = 50, .personas = all_personas });
}

test "net: KV server without directory fsync is fine on ext4" {
    try tardis.check(gpa, kvNoDirSync, .{ .nodes = 2, .iterations = 50, .personas = &.{.linux_ext4} });
}

test "net: KV server without directory fsync loses writes under posix_strict (bug found)" {
    try std.testing.expectError(error.AssertionFailed, tardis.check(gpa, kvNoDirSync, .{
        .nodes = 2,
        .iterations = 100,
        .personas = &.{.posix_strict},
        .report = false,
    }));
}

test "net: group-commit KV server acknowledges writes it then loses (bug found)" {
    try std.testing.expectError(error.AssertionFailed, tardis.check(gpa, kvGroupCommit, .{
        .nodes = 2,
        .iterations = 100,
        .report = false,
    }));
}

// ---------------------------------------------------------------------------
// Partitions

fn acceptOne(io: Io) !void {
    var server = try any(9000).listen(io, .{});
    defer server.deinit(io);
    const stream = try server.accept(io);
    defer stream.close(io);
    var buf: [16]u8 = undefined;
    var r = stream.reader(io, &buf);
    const got = r.interface.takeDelimiterExclusive('\n') catch return r.err orelse error.EndOfStream;
    if (!std.mem.eql(u8, got, "late")) return error.WrongPayload;
}

fn partitionBody(env: *Env) !void {
    const io = env.io;
    try env.spawnOn(1, acceptOne, .{io});
    try io.sleep(.fromMilliseconds(1), .awake); // let the server listen

    // A partition makes connect time out.
    env.partition(0, 1);
    const t0 = env.nowNs();
    try std.testing.expectError(error.Timeout, env.address(1, 9000).connect(io, .{
        .mode = .stream,
        .timeout = .{ .duration = .{ .raw = .fromMilliseconds(500), .clock = .awake } },
    }));
    try std.testing.expect(env.nowNs() - t0 >= 500 * std.time.ns_per_ms);
    env.healAll();

    // Bytes sent across a link that is then cut arrive after it heals.
    const stream = try env.address(1, 9000).connect(io, .{ .mode = .stream });
    defer stream.close(io);
    env.cutLink(0, 1);
    var wbuf: [16]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeAll("late\n") catch return w.err.?;
    w.interface.flush() catch return w.err.?;
    try io.sleep(.fromSeconds(5), .awake);
    env.healLink(0, 1);
    try io.sleep(.fromSeconds(1), .awake);
    if (env.daemonError()) |err| return err;
}

test "net: partitions time out connects and delay delivery until healed" {
    try tardis.check(gpa, partitionBody, .{ .nodes = 2, .iterations = 30 });
}

// ---------------------------------------------------------------------------
// Node crash seen by a connected peer

fn holdOpen(io: Io) !void {
    var server = try any(9100).listen(io, .{});
    defer server.deinit(io);
    const stream = try server.accept(io);
    defer stream.close(io);
    try io.sleep(.fromSeconds(3600), .awake);
}

fn peerCrashBody(env: *Env) !void {
    const io = env.io;
    try env.spawnOn(1, holdOpen, .{io});
    const stream = try connectRetry(io, env.address(1, 9100));
    defer stream.close(io);
    env.crashNode(1, .power_loss);
    var buf: [8]u8 = undefined;
    var r = stream.reader(io, &buf);
    _ = r.interface.takeByte() catch |err| switch (err) {
        error.ReadFailed => {
            const e = r.err.?;
            env.sometimes("peer crash seen as reset", e == error.ConnectionResetByPeer);
            env.sometimes("peer crash seen as timeout", e == error.ConnectionTimedOut);
            return;
        },
        error.EndOfStream => return error.UnexpectedEof,
    };
    return error.UnexpectedData;
}

test "net: a crashed peer resets or black-holes connections" {
    try tardis.check(gpa, peerCrashBody, .{ .nodes = 2, .iterations = 40 });
}

// ---------------------------------------------------------------------------
// DNS, std.Io.net.HostName.connect

fn dnsBody(env: *Env) !void {
    const io = env.io;
    env.addHost("db.internal", 1);
    var server = try any(5432).listen(io, .{});
    defer server.deinit(io);
    // node0 is this node; db.internal points elsewhere and nobody listens.
    const s0 = try (try Io.net.HostName.init("node0")).connect(io, 5432, .{ .mode = .stream });
    s0.close(io);
    try std.testing.expectError(error.ConnectionRefused, (try Io.net.HostName.init("db.internal")).connect(io, 5432, .{ .mode = .stream }));
    try std.testing.expectError(error.UnknownHostName, (try Io.net.HostName.init("nope.example")).connect(io, 5432, .{ .mode = .stream }));
    // Accept and drop the connection from node0 so no socket leaks.
    const accepted = try server.accept(io);
    accepted.close(io);
}

test "net: virtual DNS" {
    try tardis.check(gpa, dnsBody, .{ .nodes = 2, .iterations = 10 });
}

// ---------------------------------------------------------------------------
// Leak detection, daemon failure

fn leakySocket(env: *Env) !void {
    _ = try any(1234).listen(env.io, .{});
}

test "net: an unclosed socket is a leak" {
    try std.testing.expectError(error.ResourceLeak, tardis.check(gpa, leakySocket, .{ .iterations = 1, .report = false }));
}

fn failingDaemon(io: Io) !void {
    try io.sleep(.fromMilliseconds(1), .awake);
    return error.ServiceBroke;
}

fn daemonFailBody(env: *Env) !void {
    try env.spawnOn(1, failingDaemon, .{env.io});
    try env.io.sleep(.fromMilliseconds(5), .awake);
}

test "net: a failing daemon fails the iteration" {
    try std.testing.expectError(error.ServiceBroke, tardis.check(gpa, daemonFailBody, .{ .nodes = 2, .iterations = 1, .report = false }));
}

// ---------------------------------------------------------------------------
// Clocks

fn measure(io: Io, out: *i96) !void {
    const t0 = Io.Clock.awake.now(io);
    try io.sleep(.fromSeconds(1), .awake);
    out.* = Io.Clock.awake.now(io).nanoseconds - t0.nanoseconds;
}

fn driftBody(env: *Env) !void {
    var local: i96 = 0;
    const g0 = env.nowNs();
    try env.spawnOn(1, measure, .{ env.io, &local });
    try env.io.sleep(.fromSeconds(2), .awake);
    // The node slept one second by its own clock.
    try std.testing.expect(local >= std.time.ns_per_s);
    try std.testing.expect(local < std.time.ns_per_s + 1000);
    _ = g0;

    // NTP step: the real clock jumps, the monotonic clock does not.
    const real0 = Io.Clock.real.now(env.io).nanoseconds;
    const mono0 = Io.Clock.awake.now(env.io).nanoseconds;
    env.stepClock(0, -5 * std.time.ns_per_s);
    try std.testing.expect(Io.Clock.real.now(env.io).nanoseconds < real0);
    try std.testing.expect(Io.Clock.awake.now(env.io).nanoseconds >= mono0);
}

test "net: per-node clock drift and NTP steps" {
    try tardis.check(gpa, driftBody, .{
        .nodes = 2,
        .iterations = 20,
        .faults = .{ .clock_drift_ppm_max = 500 },
    });
}

fn clockSkew(env: *Env) !void {
    try env.io.sleep(.fromSeconds(100), .awake);
    const skew = Io.Clock.awake.now(env.io).nanoseconds - @as(i96, env.nowNs());
    env.sometimes("node clock ahead of true time", skew > 0);
    env.sometimes("node clock behind true time", skew < 0);
    // 500 ppm over 100 s is at most 50 ms.
    try std.testing.expect(@abs(skew) <= 50 * std.time.ns_per_ms);
}

test "net: drift moves node clocks both ways within the bound" {
    try tardis.check(gpa, clockSkew, .{
        .iterations = 40,
        .swarm = false,
        .faults = .{ .clock_drift_ppm_max = 500 },
    });
}
