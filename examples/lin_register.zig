//! Example: a register kept in a file, with a compare-and-swap.
//!
//! The bug class: **a compare-and-swap that is not atomic.** The buggy
//! register reads the value, compares it and writes the new one: three
//! steps, and another task can run between them. Two tasks that both swap
//! 0 for their own number can both be told they won.
//!
//! The fix holds a lock for the whole operation, reads included.
//!
//! The property: the history is linearizable. Every task records what it
//! asked and what it was told, and `tardis.lin` looks for one order of
//! the operations that a register used by one task at a time could have
//! produced. Two swaps from 0 that both succeed have no such order.

const std = @import("std");
const tardis = @import("tardis");
const lin = tardis.lin;
const Io = std.Io;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };
const clients = 3;

pub const options: tardis.Options = .{ .iterations = 200 };

const Register = struct {
    io: Io,
    dir: Io.Dir,
    lock: Io.Mutex = .init,
    variant: Variant,

    fn load(r: *Register) !u64 {
        var buf: [8]u8 = undefined;
        const bytes = try r.dir.readFile(r.io, "register", &buf);
        if (bytes.len != 8) return error.Corrupt;
        return std.mem.readInt(u64, bytes[0..8], .little);
    }

    fn store(r: *Register, value: u64) !void {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, value, .little);
        try r.dir.writeFile(r.io, .{ .sub_path = "register", .data = &buf });
    }

    fn read(r: *Register) !u64 {
        if (r.variant == .fixed) try r.lock.lock(r.io);
        defer if (r.variant == .fixed) r.lock.unlock(r.io);
        return r.load();
    }

    /// Writes `to` if the register holds `from`; says whether it did.
    fn cas(r: *Register, from: u64, to: u64) !bool {
        // The whole difference: the fixed version holds a lock from the
        // read to the write.
        if (r.variant == .fixed) try r.lock.lock(r.io);
        defer if (r.variant == .fixed) r.lock.unlock(r.io);
        if (try r.load() != from) return false;
        try r.store(to);
        return true;
    }
};

const History = lin.History(lin.Register);

/// Tries to take the register (swap 0 for its own number), then reads it.
fn client(reg: *Register, history: *History, id: u32) Io.Cancelable!void {
    const mine: u64 = id + 1;
    const swap = history.invoke(id, .{ .cas = .{ .from = 0, .to = mine } }) catch return;
    // An operation that failed is left without an answer: it may or may
    // not have taken effect, and the checker allows for both.
    if (reg.cas(0, mine)) |won| history.ok(swap, .{ .cas = won }) else |_| {}

    const look = history.invoke(id, .read) catch return;
    if (reg.read()) |value| history.ok(look, .{ .value = value }) else |_| history.failed(look);
}

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    var reg: Register = .{ .io = io, .dir = env.dir, .variant = variant };
    try reg.store(0);
    var history = History.init(env.allocator);
    defer history.deinit();
    var group: Io.Group = .init;
    defer group.cancel(io);
    for (0..clients) |i| try group.concurrent(io, client, .{ &reg, &history, @as(u32, @intCast(i)) });
    try group.await(io);
    try lin.expectLinearizable(env.allocator, lin.Register, &history, env.sim.config.report);
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "lin_register: a swap done as a read and then a write lets two tasks win" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.NotLinearizable, tardis.check(std.testing.allocator, buggy, o));
}

test "lin_register: a lock around the swap keeps the history linearizable" {
    try tardis.check(std.testing.allocator, fixed, options);
}
