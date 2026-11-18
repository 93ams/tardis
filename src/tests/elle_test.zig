//! M4: Elle-style anomaly detection on a simulated transactional store.

const std = @import("std");
const tardis = @import("../root.zig");
const elle = tardis.elle;
const Io = std.Io;
const Env = tardis.Env;
const testing = std.testing;
const gpa = testing.allocator;

const keys = 3;
const list_max = 64;

const Isolation = enum {
    /// One lock held for the whole transaction: serializable.
    serializable,
    /// A lock per operation: each read and append is atomic, transactions
    /// are not (read committed at best).
    per_operation,
};

const Store = struct {
    lists: [keys][list_max]u64 = undefined,
    lens: [keys]usize = @splat(0),
    mutex: Io.Mutex = .init,
    next_value: u64 = 1,
};

const Ctx = struct {
    io: Io,
    store: *Store,
    history: *elle.History,
    isolation: Isolation,
};

fn worker(ctx: *Ctx, plan: [6]u8) Io.Cancelable!void {
    const io = ctx.io;
    const s = ctx.store;
    var t: usize = 0;
    while (t < plan.len) : (t += 2) {
        var ops: [3]elle.Op = undefined;
        var reads: [3][list_max]u64 = undefined;
        const start = ctx.history.begin();
        if (ctx.isolation == .serializable) try s.mutex.lock(io);
        // Two micro-ops per transaction, drawn from the plan.
        for (0..2) |i| {
            const c = plan[t + i];
            const key: usize = c % keys;
            if (ctx.isolation == .per_operation) try s.mutex.lock(io);
            if (c & 0x80 != 0 and s.lens[key] < list_max) {
                const v = s.next_value;
                s.next_value += 1;
                s.lists[key][s.lens[key]] = v;
                s.lens[key] += 1;
                ops[i] = .{ .append = .{ .key = key, .value = v } };
            } else {
                const n = s.lens[key];
                @memcpy(reads[i][0..n], s.lists[key][0..n]);
                ops[i] = .{ .read = .{ .key = key, .values = reads[i][0..n] } };
            }
            if (ctx.isolation == .per_operation) s.mutex.unlock(io);
            try io.sleep(.fromMicroseconds(5), .awake); // other transactions may run here
        }
        if (ctx.isolation == .serializable) s.mutex.unlock(io);
        ctx.history.finish(start, .committed, ops[0..2]) catch return;
    }
}

fn scenario(env: *Env, isolation: Isolation) !void {
    var store: Store = .{};
    var history = elle.History.init(env.allocator);
    defer history.deinit();
    var ctx: Ctx = .{ .io = env.io, .store = &store, .history = &history, .isolation = isolation };
    var group: Io.Group = .init;
    defer group.cancel(env.io);
    for (0..3) |_| try group.concurrent(env.io, worker, .{ &ctx, try env.fuzz([6]u8) });
    try group.await(env.io);
    // Reads of every key at the end pin down the version orders.
    var final: [keys][list_max]u64 = undefined;
    var ops: [keys]elle.Op = undefined;
    for (0..keys) |k| {
        @memcpy(final[k][0..store.lens[k]], store.lists[k][0..store.lens[k]]);
        ops[k] = .{ .read = .{ .key = k, .values = final[k][0..store.lens[k]] } };
    }
    try history.finish(history.begin(), .committed, &ops);

    elle.expectSerializable(gpa, &history, .{ .realtime = true }, env.sim.config.report) catch |err| {
        try env.always("transactions are strictly serializable", false);
        return err;
    };
}

fn serializable(env: *Env) !void {
    return scenario(env, .serializable);
}

fn perOperation(env: *Env) !void {
    return scenario(env, .per_operation);
}

test "elle: whole-transaction locking is strictly serializable" {
    try tardis.check(gpa, serializable, .{ .iterations = 100, .shrink = false });
}

test "elle: per-operation locking produces transactional anomalies (bug found)" {
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, perOperation, .{
        .iterations = 100,
        .report = false,
    }));
}

// ---------------------------------------------------------------------------
// Read-write registers: read-modify-write transactions on a register store.

const RegStore = struct {
    values: [keys]?u64 = @splat(null),
    mutex: Io.Mutex = .init,
    next_value: u64 = 1,
};

const RegCtx = struct {
    io: Io,
    store: *RegStore,
    history: *elle.History,
    isolation: Isolation,
};

/// Each transaction reads two keys and writes a fresh value to the first.
fn regWorker(ctx: *RegCtx, plan: [6]u8) Io.Cancelable!void {
    const io = ctx.io;
    const s = ctx.store;
    var t: usize = 0;
    while (t < plan.len) : (t += 2) {
        const a: usize = plan[t] % keys;
        const b: usize = plan[t + 1] % keys;
        var ops: [3]elle.Op = undefined;
        const start = ctx.history.begin();
        if (ctx.isolation == .serializable) try s.mutex.lock(io);
        for ([_]usize{ a, b }, 0..) |key, i| {
            if (ctx.isolation == .per_operation) try s.mutex.lock(io);
            ops[i] = .{ .read_reg = .{ .key = key, .value = s.values[key] } };
            if (ctx.isolation == .per_operation) s.mutex.unlock(io);
            try io.sleep(.fromMicroseconds(5), .awake);
        }
        if (ctx.isolation == .per_operation) try s.mutex.lock(io);
        const v = s.next_value;
        s.next_value += 1;
        s.values[a] = v;
        ops[2] = .{ .write = .{ .key = a, .value = v } };
        if (ctx.isolation == .per_operation) s.mutex.unlock(io);
        if (ctx.isolation == .serializable) s.mutex.unlock(io);
        ctx.history.finish(start, .committed, &ops) catch return;
    }
}

var saw_lost_update = false;

fn regScenario(env: *Env, isolation: Isolation) !void {
    var store: RegStore = .{};
    var history = elle.History.init(env.allocator);
    defer history.deinit();
    var ctx: RegCtx = .{ .io = env.io, .store = &store, .history = &history, .isolation = isolation };
    var group: Io.Group = .init;
    defer group.cancel(env.io);
    for (0..3) |_| try group.concurrent(env.io, regWorker, .{ &ctx, try env.fuzz([6]u8) });
    try group.await(env.io);
    const report = try elle.check(gpa, &history, .{ .realtime = true });
    if (report.found.contains(.lost_update)) saw_lost_update = true;
    if (!report.ok()) {
        if (env.sim.config.report) report.print(&history);
        try env.always("register transactions are strictly serializable", false);
    }
}

fn regSerializable(env: *Env) !void {
    return regScenario(env, .serializable);
}

fn regPerOperation(env: *Env) !void {
    return regScenario(env, .per_operation);
}

test "elle: registers under whole-transaction locking are strictly serializable" {
    try tardis.check(gpa, regSerializable, .{ .iterations = 100, .shrink = false });
}

test "elle: per-operation locking loses register updates (bug found)" {
    saw_lost_update = false;
    try testing.expectError(error.AssertionFailed, tardis.check(gpa, regPerOperation, .{ .iterations = 100, .report = false, .shrink = false }));
    try testing.expect(saw_lost_update);
}
