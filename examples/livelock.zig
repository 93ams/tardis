//! Example: moving money between two accounts, each with its own lock,
//! by a program that knows about deadlocks.
//!
//! The bug class: **a livelock.** To never wait while holding a lock, a
//! transfer takes its first account's lock, does its work, and only
//! *tries* the second: if that one is taken it lets go of the first, waits
//! a moment and starts again. Two transfers in opposite directions that
//! start at the same moment each hold one lock, each fail on the other,
//! each let go, each wait the same time, and start again at the same
//! moment. Nothing is blocked and nobody waits for ever, so it is not a
//! deadlock: both tasks stay busy and no money ever moves. It needs the
//! two transfers to start within the same instant, which a plain test
//! does not arrange.
//!
//! The fix makes the two wait different times, so one of them goes first.
//!
//! The property is a liveness one: a transfer completes within a
//! millisecond of virtual time (`env.expectProgress`). Without it the buggy
//! run would not fail: it would never end.

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

fn transfer(env: *Env, accounts: *[2]Account, from: usize, amount: i64, start_us: u64, variant: Variant) Io.Cancelable!void {
    const io = env.io;
    const to = 1 - from;
    try io.sleep(.fromMicroseconds(@intCast(start_us)), .awake);
    while (true) {
        try accounts[from].lock.lock(io);
        // Work done while holding one lock: looking up a rate, writing an
        // audit line.
        try io.sleep(.fromMicroseconds(1), .awake);
        if (accounts[to].lock.tryLock()) break;
        // Taken: undo the work (strike the audit line), let go, start again.
        try io.sleep(.fromMicroseconds(1), .awake);
        accounts[from].lock.unlock(io);
        // The whole difference: both directions wait the same time, or each
        // a time of its own.
        const wait_us: i64 = if (variant == .fixed) 10 * (@as(i64, @intCast(from)) + 1) else 10;
        try io.sleep(.fromMicroseconds(wait_us), .awake);
    }
    accounts[from].balance -= amount;
    accounts[to].balance += amount;
    accounts[to].lock.unlock(io);
    accounts[from].lock.unlock(io);
    env.progress("a transfer completes");
}

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    var accounts: [2]Account = .{ .{ .balance = 100 }, .{ .balance = 100 } };
    // The settlement job runs at a fixed time; a customer's transfer
    // arrives whenever it does.
    const arrives_us: u64 = (try env.fuzz(u8)) % 4;
    env.expectProgress("a transfer completes", .{ .within_ns = std.time.ns_per_ms });
    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, transfer, .{ env, &accounts, 0, 30, 2, variant });
    try group.concurrent(io, transfer, .{ env, &accounts, 1, 20, arrives_us, variant });
    try group.await(io);
    env.progressDone("a transfer completes");
    try env.always("no money is made or lost", accounts[0].balance + accounts[1].balance == 200);
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "livelock: two transfers that back off in step never finish" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.Livelock, tardis.check(std.testing.allocator, buggy, o));
}

test "livelock: backing off for different times lets one go first" {
    try tardis.check(std.testing.allocator, fixed, options);
}
