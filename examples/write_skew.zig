//! Example: an on-call rota kept in a small transactional store.
//!
//! The bug class: **write skew.** A doctor may go off call only if the
//! other one stays. Each transaction reads both rows, and if both doctors
//! are on call it takes its own off. The buggy store checks at commit
//! only the rows the transaction wrote. Two transactions that run
//! together each read the row the other is about to write, write
//! different rows, and both commit: nobody is on call.
//!
//! The fix checks the rows the transaction read as well, and the second
//! one to commit is turned away.
//!
//! The property: the transactions are serializable. Every transaction is
//! recorded with what it read and wrote, and `tardis.elle` looks for a
//! cycle of dependencies between them. Here each of the two read what the
//! other overwrote (anomaly G2).

const std = @import("std");
const tardis = @import("tardis");
const elle = tardis.elle;
const Io = std.Io;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };
const doctors = 2;

pub const options: tardis.Options = .{ .iterations = 200 };

/// One row per doctor. A row never written (null) means on call. Every
/// write to a row bumps its version.
const Store = struct {
    values: [doctors]?u64 = @splat(null),
    versions: [doctors]u32 = @splat(0),
};

const Ctx = struct {
    io: Io,
    dir: Io.Dir,
    store: *Store,
    history: *elle.History,
    variant: Variant,
};

/// One transaction: doctor `me` asks to go off call.
fn goOffCall(ctx: *Ctx, me: usize) Io.Cancelable!void {
    const s = ctx.store;
    const start = ctx.history.begin();

    // Read every row, remembering the version of each.
    var ops: [doctors + 1]elle.Op = undefined;
    var seen: [doctors]u32 = undefined;
    var on_call: u32 = 0;
    for (0..doctors) |k| {
        seen[k] = s.versions[k];
        ops[k] = .{ .read_reg = .{ .key = k, .value = s.values[k] } };
        if (s.values[k] == null) on_call += 1;
    }
    if (on_call < 2) {
        // Somebody has to stay: a transaction that only read.
        ctx.history.finish(start, .committed, ops[0..doctors]) catch {};
        return;
    }
    ops[doctors] = .{ .write = .{ .key = me, .value = me + 1 } };

    // The handover note is written before the commit, and other
    // transactions may run meanwhile.
    var name_buf: [16]u8 = undefined;
    const name = std.fmt.bufPrint(&name_buf, "handover-{d}", .{me}) catch unreachable;
    var committed = if (ctx.dir.writeFile(ctx.io, .{ .sub_path = name, .data = "off call" })) |_| true else |_| false;

    // Commit. No I/O from here on, so nothing runs in between.
    // The whole difference: the buggy store checks only the row it
    // writes, the fixed one every row it read.
    for (0..doctors) |k| {
        if (ctx.variant == .buggy and k != me) continue;
        if (s.versions[k] != seen[k]) committed = false;
    }
    if (committed) {
        s.values[me] = me + 1;
        s.versions[me] += 1;
    }
    ctx.history.finish(start, if (committed) .committed else .aborted, &ops) catch {};
}

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    var store: Store = .{};
    var history = elle.History.init(env.allocator);
    defer history.deinit();
    var ctx: Ctx = .{ .io = io, .dir = env.dir, .store = &store, .history = &history, .variant = variant };
    var group: Io.Group = .init;
    defer group.cancel(io);
    for (0..doctors) |me| try group.concurrent(io, goOffCall, .{ &ctx, me });
    try group.await(io);
    try elle.expectSerializable(env.allocator, &history, .{}, env.sim.config.report);
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "write_skew: checking only the written rows lets both doctors go off call" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.TransactionalAnomaly, tardis.check(std.testing.allocator, buggy, o));
}

test "write_skew: checking the rows that were read turns the second one away" {
    try tardis.check(std.testing.allocator, fixed, options);
}
