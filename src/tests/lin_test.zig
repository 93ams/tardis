//! M4: linearizability of a replicated KV store over the virtual network.

const std = @import("std");
const tardis = @import("../root.zig");
const lin = tardis.lin;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const Stream = Io.net.Stream;
const Env = tardis.Env;
const testing = std.testing;
const gpa = testing.allocator;

const primary_port = 7000;
const replica_port = 7100;
const keys = 2;

fn any(port: u16) IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } };
}

fn connectRetry(io: Io, addr: IpAddress) !Stream {
    var attempts: u32 = 0;
    while (true) : (attempts += 1) {
        return addr.connect(io, .{ .mode = .stream }) catch |err| switch (err) {
            error.ConnectionRefused => {
                if (attempts == 50) return err;
                try io.sleep(.fromMilliseconds(5), .awake);
                continue;
            },
            else => return err,
        };
    }
}

fn roundTrip(io: Io, addr: IpAddress, request: []const u8, out: []u8) ![]const u8 {
    const stream = try connectRetry(io, addr);
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

const Mode = enum {
    /// Reads go to the primary: linearizable.
    primary_reads,
    /// Reads go to a replica that the primary updates after acknowledging.
    async_replica_reads,
};

/// Serves `W k v` and `R k` one connection at a time. A primary forwards
/// writes to the replica after replying.
fn kvNode(io: Io, port: u16, replica: ?IpAddress) !void {
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
            w.interface.writeAll("OK\n") catch continue;
            w.interface.flush() catch continue;
            if (replica) |addr| {
                var fwd: [32]u8 = undefined;
                var out: [16]u8 = undefined;
                _ = roundTrip(io, addr, try std.fmt.bufPrint(&fwd, "W {d} {d}\n", .{ key, v }), &out) catch {};
            }
        } else {
            w.interface.print("V {d}\n", .{values[key]}) catch continue;
            w.interface.flush() catch continue;
        }
    }
}

const Ctx = struct {
    env: *Env,
    history: *lin.History(lin.Kv),
    reads_from: IpAddress,
    writes_to: IpAddress,
};

fn client(ctx: *Ctx, id: u32, choices: [4]u8) Io.Cancelable!void {
    const io = ctx.env.io;
    for (choices, 0..) |c, i| {
        const key: u64 = c % keys;
        var req: [32]u8 = undefined;
        var out: [32]u8 = undefined;
        if (c & 0x80 != 0) {
            const v: u64 = @as(u64, id) * 100 + i + 1;
            const op = ctx.history.invoke(id, .{ .key = key, .op = .{ .write = v } }) catch return;
            const text = std.fmt.bufPrint(&req, "W {d} {d}\n", .{ key, v }) catch unreachable;
            _ = roundTrip(io, ctx.writes_to, text, &out) catch continue; // outcome unknown
            ctx.history.ok(op, .ok);
        } else {
            const op = ctx.history.invoke(id, .{ .key = key, .op = .read }) catch return;
            const text = std.fmt.bufPrint(&req, "R {d}\n", .{key}) catch unreachable;
            const reply = roundTrip(io, ctx.reads_from, text, &out) catch continue;
            const v = std.fmt.parseInt(u64, reply[2..], 10) catch continue;
            ctx.history.ok(op, .{ .value = v });
        }
    }
}

fn scenario(env: *Env, mode: Mode) !void {
    const io = env.io;
    try env.spawnOn(2, kvNode, .{ io, replica_port, null });
    try env.spawnOn(1, kvNode, .{ io, primary_port, env.address(2, replica_port) });

    var history = lin.History(lin.Kv).init(env.allocator);
    defer history.deinit();
    var ctx: Ctx = .{
        .env = env,
        .history = &history,
        .writes_to = env.address(1, primary_port),
        .reads_from = switch (mode) {
            .primary_reads => env.address(1, primary_port),
            .async_replica_reads => env.address(2, replica_port),
        },
    };
    var group: Io.Group = .init;
    defer group.cancel(io);
    for (0..3) |i| try group.concurrent(io, client, .{ &ctx, @as(u32, @intCast(i)), try env.fuzz([4]u8) });
    try group.await(io);

    lin.expectLinearizable(gpa, lin.Kv, &history, env.sim.config.report) catch |err| {
        try env.always("the KV store is linearizable", false);
        return err;
    };
}

fn primaryReads(env: *Env) !void {
    return scenario(env, .primary_reads);
}

fn replicaReads(env: *Env) !void {
    return scenario(env, .async_replica_reads);
}

test "lin: a KV store that reads from its primary is linearizable" {
    try tardis.check(gpa, primaryReads, .{ .nodes = 3, .iterations = 60, .shrink = false });
}

test "lin: reading from an asynchronously updated replica is caught (stale read)" {
    var sh: tardis.ShrinkReport = .{};
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, replicaReads, .{
        .nodes = 3,
        .iterations = 200,
        .report = false,
        .shrink_report = &sh,
    }));
    try testing.expect(sh.shrunk);
    try testing.expect(sh.after < sh.before);
}
