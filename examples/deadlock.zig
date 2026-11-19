//! Example: moving money between two accounts, each with its own lock.
//!
//! The bug class: **a deadlock from lock order.** A transfer locks the
//! account it takes from, then the one it gives to. Two transfers in
//! opposite directions can each take their first lock and wait for ever
//! for the second. It needs one task to be interrupted between its two
//! locks, which a plain test almost never arranges.
//!
//! The fix takes the locks in one order whatever the direction.
//!
//! The property is the simulator's own: no run ends with every task
//! blocked.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

pub const options: tardis.Options = .{ .iterations = 200 };

const Account = struct {
    lock: Io.Mutex = .init,
    balance: i64,
};

fn transfer(io: Io, accounts: *[2]Account, from: usize, amount: i64, variant: Variant) Io.Cancelable!void {
    const to = 1 - from;
    // The whole difference: lock in the direction of the money, or always
    // the lower account first.
    const first = if (variant == .fixed) @min(from, to) else from;
    const second = 1 - first;
    try accounts[first].lock.lock(io);
    defer accounts[first].lock.unlock(io);
    // Work done while holding one lock: looking up a rate, writing an
    // audit line. Any I/O is a point where another task may run.
    try io.sleep(.fromMicroseconds(1), .awake);
    try accounts[second].lock.lock(io);
    defer accounts[second].lock.unlock(io);
    accounts[from].balance -= amount;
    accounts[to].balance += amount;
}

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    var accounts: [2]Account = .{ .{ .balance = 100 }, .{ .balance = 100 } };
    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, transfer, .{ io, &accounts, 0, 30, variant });
    try group.concurrent(io, transfer, .{ io, &accounts, 1, 20, variant });
    try group.await(io);
    try env.always("no money is made or lost", accounts[0].balance + accounts[1].balance == 200);
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "deadlock: two transfers in opposite directions can wait on each other for ever" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.Deadlock, tardis.check(std.testing.allocator, buggy, o));
}

test "deadlock: one lock order for both directions never blocks" {
    try tardis.check(std.testing.allocator, fixed, options);
}
