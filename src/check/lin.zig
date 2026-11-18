//! Linearizability checking (plan §9 M4), in the style of Porcupine.
//!
//! Record a history of operations as the test runs (`History.invoke`, then
//! `ok`, `failed`, or nothing for an operation whose outcome is unknown),
//! then ask whether some total order of the operations both respects
//! real time (an operation that returned before another was invoked comes
//! first) and is a legal sequential execution of a model.
//!
//! The search is Wing & Gong's algorithm with Lowe's memoization: an
//! iterative depth-first search over a doubly linked list of call/return
//! entries, with an explicit stack and a cache of
//! `(set of linearized operations, model state)` already explored. Models
//! with a `partition` function are checked one partition (key) at a time
//! (P-compositionality), which is what keeps realistic KV histories cheap.
//!
//! A model is a type with:
//!   `State`, `Input`, `Output` types,
//!   `fn init() State`,
//!   `fn step(state: State, input: Input, output: ?Output) ?State`
//!       (null: this output is impossible here; `output == null` means the
//!       operation's outcome is unknown, so accept any result),
//!   `fn hash(state: State) u64`,
//!   optionally `fn partition(input: Input) u64`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const decide = @import("../sim/decide.zig");

pub const Options = struct {
    /// Search steps per partition before giving up with `.unknown`.
    steps_max: u64 = 10_000_000,
};

pub fn History(comptime M: type) type {
    return struct {
        const Self = @This();

        pub const Status = enum(u8) { pending, ok, failed };

        pub const Op = struct {
            client: u32,
            input: M.Input,
            output: ?M.Output,
            call: u64,
            ret: u64,
            status: Status,
        };

        gpa: Allocator,
        ops: std.ArrayList(Op),
        clock: u64,

        pub fn init(gpa: Allocator) Self {
            return .{ .gpa = gpa, .ops = .empty, .clock = 0 };
        }

        pub fn deinit(h: *Self) void {
            h.ops.deinit(h.gpa);
            h.* = undefined;
        }

        /// Records that `client` invoked `input`; returns the operation id.
        pub fn invoke(h: *Self, client: u32, input: M.Input) !usize {
            h.clock += 1;
            try h.ops.append(h.gpa, .{ .client = client, .input = input, .output = null, .call = h.clock, .ret = std.math.maxInt(u64), .status = .pending });
            return h.ops.items.len - 1;
        }

        /// Records that operation `id` completed with `output`.
        pub fn ok(h: *Self, id: usize, output: M.Output) void {
            const op = &h.ops.items[id];
            assert(op.status == .pending);
            h.clock += 1;
            op.output = output;
            op.ret = h.clock;
            op.status = .ok;
        }

        /// Records that operation `id` definitely did not take effect (for
        /// example, the request was refused before being sent). Operations
        /// left pending are treated as "may or may not have happened".
        pub fn failed(h: *Self, id: usize) void {
            const op = &h.ops.items[id];
            assert(op.status == .pending);
            op.status = .failed;
        }

        /// Prints the operations of one partition, ordered by invocation.
        pub fn dump(h: *const Self, v: Violation) void {
            std.debug.print("tardis: linearizability violation in partition 0x{x}: no order of its {d} operations is legal (deepest partial order: {d} ops)\n", .{ v.partition, v.ops, v.deepest });
            for (h.ops.items, 0..) |op, i| {
                if (op.status == .failed or partitionOf(M, op.input) != v.partition) continue;
                const mark: []const u8 = if (i == v.stuck) "  <-- cannot be placed" else "";
                if (op.status == .pending) {
                    std.debug.print("  #{d:<4} client {d:<3} [{d}, ...)  {any} -> (unknown){s}\n", .{ i, op.client, op.call, op.input, mark });
                } else {
                    std.debug.print("  #{d:<4} client {d:<3} [{d}, {d}]  {any} -> {any}{s}\n", .{ i, op.client, op.call, op.ret, op.input, op.output.?, mark });
                }
            }
        }
    };
}

pub const Violation = struct {
    partition: u64,
    /// Operations in that partition.
    ops: usize,
    /// Most operations any partial linearization reached.
    deepest: usize,
    /// History index of an operation that could not be linearized before
    /// its return at the deepest point of the search.
    stuck: usize,
};

pub const Result = union(enum) {
    linearizable,
    not_linearizable: Violation,
    /// The search budget ran out.
    unknown: struct { partition: u64 },
};

fn partitionOf(comptime M: type, input: M.Input) u64 {
    if (@hasDecl(M, "partition")) return M.partition(input);
    return 0;
}

/// Checks `h`. Allocates scratch memory from `gpa` only.
pub fn check(gpa: Allocator, comptime M: type, h: *const History(M), options: Options) !Result {
    const ops = h.ops.items;
    // Distinct partitions, in first-seen order (deterministic).
    var parts: std.ArrayList(u64) = .empty;
    defer parts.deinit(gpa);
    for (ops) |op| {
        if (op.status == .failed) continue;
        const p = partitionOf(M, op.input);
        if (std.mem.indexOfScalar(u64, parts.items, p) == null) try parts.append(gpa, p);
    }
    var members: std.ArrayList(usize) = .empty;
    defer members.deinit(gpa);
    for (parts.items) |p| {
        members.clearRetainingCapacity();
        for (ops, 0..) |op, i| {
            if (op.status != .failed and partitionOf(M, op.input) == p) try members.append(gpa, i);
        }
        const r = try checkPartition(gpa, M, ops, members.items, options);
        switch (r) {
            .linearizable => {},
            .not_linearizable => |v| return .{ .not_linearizable = .{ .partition = p, .ops = members.items.len, .deepest = v.deepest, .stuck = v.stuck } },
            .unknown => return .{ .unknown = .{ .partition = p } },
        }
    }
    return .linearizable;
}

const none = std.math.maxInt(u32);

const Entry = struct {
    time: u64,
    /// Index into the partition's member list.
    op: u32,
    is_call: bool,
    /// For a call: index of its return entry.
    match: u32,
    prev: u32,
    next: u32,
};

fn checkPartition(gpa: Allocator, comptime M: type, ops: []const History(M).Op, members: []const usize, options: Options) !Result {
    const n = members.len;
    if (n == 0) return .linearizable;

    // Entries sorted by time; index `2n` is the list head sentinel.
    const entries = try gpa.alloc(Entry, 2 * n + 1);
    defer gpa.free(entries);
    for (members, 0..) |hi, k| {
        const op = ops[hi];
        // Pending returns sort after everything, in member order.
        const ret_time = if (op.status == .pending) std.math.maxInt(u64) - (n - k) else op.ret;
        entries[2 * k] = .{ .time = op.call, .op = @intCast(k), .is_call = true, .match = 0, .prev = 0, .next = 0 };
        entries[2 * k + 1] = .{ .time = ret_time, .op = @intCast(k), .is_call = false, .match = 0, .prev = 0, .next = 0 };
    }
    std.mem.sort(Entry, entries[0 .. 2 * n], {}, struct {
        fn less(_: void, a: Entry, b: Entry) bool {
            return a.time < b.time;
        }
    }.less);
    const ret_of = try gpa.alloc(u32, n);
    defer gpa.free(ret_of);
    for (entries[0 .. 2 * n], 0..) |e, i| {
        if (!e.is_call) ret_of[e.op] = @intCast(i);
    }
    for (entries[0 .. 2 * n]) |*e| {
        if (e.is_call) e.match = ret_of[e.op];
    }
    const head: u32 = @intCast(2 * n);
    entries[head] = .{ .time = 0, .op = none, .is_call = false, .match = 0, .prev = none, .next = 0 };
    for (0..2 * n) |i| {
        entries[i].prev = if (i == 0) head else @intCast(i - 1);
        entries[i].next = if (i + 1 == 2 * n) none else @intCast(i + 1);
    }

    const linearized = try gpa.alloc(bool, n);
    defer gpa.free(linearized);
    @memset(linearized, false);

    var completed_left: usize = 0;
    for (members) |hi| {
        if (ops[hi].status == .ok) completed_left += 1;
    }

    var cache: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer cache.deinit(gpa);

    const Frame = struct { call: u32, state: M.State, zobrist: u64 };
    var stack: std.ArrayList(Frame) = .empty;
    defer stack.deinit(gpa);

    var state = M.init();
    var zobrist: u64 = 0;
    var deepest: usize = 0;
    var stuck: usize = members[0];
    var steps: u64 = 0;
    var cur = entries[head].next;

    while (true) {
        if (completed_left == 0) return .linearizable;
        steps += 1;
        if (steps > options.steps_max) return .{ .unknown = .{ .partition = 0 } };
        if (cur == none) {
            // Only pending operations remain unplaced beyond this point but
            // a completed one is still unlinearized: backtrack.
            if (stack.items.len == 0) return .{ .not_linearizable = .{ .partition = 0, .ops = n, .deepest = deepest, .stuck = stuck } };
            cur = backtrack(M, entries, &stack, &state, &zobrist, linearized, ops, members, &completed_left);
            continue;
        }
        const e = entries[cur];
        if (e.is_call) {
            const op = ops[members[e.op]];
            if (M.step(state, op.input, op.output)) |next_state| {
                const z = zobrist ^ decide.splitmix64(@as(u64, e.op) +% 0x51ed);
                const key = decide.mix(z, M.hash(next_state));
                const gop = try cache.getOrPut(gpa, key);
                if (!gop.found_existing) {
                    try stack.append(gpa, .{ .call = cur, .state = state, .zobrist = zobrist });
                    state = next_state;
                    zobrist = z;
                    linearized[e.op] = true;
                    if (op.status == .ok) completed_left -= 1;
                    lift(entries, cur);
                    if (stack.items.len > deepest) deepest = stack.items.len;
                    cur = entries[head].next;
                    continue;
                }
            }
            cur = e.next;
        } else {
            // A return: its operation must be linearized before anything
            // after this point. It is not, so backtrack.
            if (stack.items.len >= deepest) stuck = members[e.op];
            if (stack.items.len == 0) return .{ .not_linearizable = .{ .partition = 0, .ops = n, .deepest = deepest, .stuck = stuck } };
            cur = backtrack(M, entries, &stack, &state, &zobrist, linearized, ops, members, &completed_left);
        }
    }
}

fn lift(entries: []Entry, call: u32) void {
    const c = entries[call];
    entries[c.prev].next = c.next;
    if (c.next != none) entries[c.next].prev = c.prev;
    const r = entries[c.match];
    entries[r.prev].next = r.next;
    if (r.next != none) entries[r.next].prev = r.prev;
}

fn unlift(entries: []Entry, call: u32) void {
    // Reverse order of `lift` (dancing links).
    const r_idx = entries[call].match;
    const r = entries[r_idx];
    entries[r.prev].next = r_idx;
    if (r.next != none) entries[r.next].prev = r_idx;
    const c = entries[call];
    entries[c.prev].next = call;
    if (c.next != none) entries[c.next].prev = call;
}

fn backtrack(
    comptime M: type,
    entries: []Entry,
    stack: anytype,
    state: *M.State,
    zobrist: *u64,
    linearized: []bool,
    ops: []const History(M).Op,
    members: []const usize,
    completed_left: *usize,
) u32 {
    const f = stack.pop().?;
    state.* = f.state;
    zobrist.* = f.zobrist;
    const e = entries[f.call];
    linearized[e.op] = false;
    if (ops[members[e.op]].status == .ok) completed_left.* += 1;
    unlift(entries, f.call);
    return e.next;
}

/// Checks `h` and, on a violation, prints the partition (if `report`) and
/// returns `error.NotLinearizable`. `error.LinearizabilityUnknown` if the
/// search budget ran out.
pub fn expectLinearizable(gpa: Allocator, comptime M: type, h: *const History(M), report: bool) !void {
    switch (try check(gpa, M, h, .{})) {
        .linearizable => {},
        .not_linearizable => |v| {
            if (report) h.dump(v);
            return error.NotLinearizable;
        },
        .unknown => return error.LinearizabilityUnknown,
    }
}

// ----------------------------------------------------------------------
// Ready-made models

/// A single read/write/compare-and-set register, initially 0.
pub const Register = struct {
    pub const State = u64;
    pub const Input = union(enum) {
        read,
        write: u64,
        cas: struct { from: u64, to: u64 },
    };
    pub const Output = union(enum) {
        value: u64,
        ok,
        cas: bool,
    };

    pub fn init() State {
        return 0;
    }

    pub fn hash(s: State) u64 {
        return s;
    }

    pub fn step(s: State, input: Input, output: ?Output) ?State {
        switch (input) {
            .read => {
                const out = output orelse return s;
                return if (out == .value and out.value == s) s else null;
            },
            .write => |v| return v,
            .cas => |c| {
                const succeeded = s == c.from;
                if (output) |out| {
                    if (out != .cas or out.cas != succeeded) return null;
                }
                return if (succeeded) c.to else s;
            },
        }
    }
};

/// A map of independent registers (checked one key at a time).
pub const Kv = struct {
    pub const State = u64;
    pub const Input = struct { key: u64, op: Register.Input };
    pub const Output = Register.Output;

    pub fn init() State {
        return 0;
    }

    pub fn hash(s: State) u64 {
        return s;
    }

    pub fn partition(input: Input) u64 {
        return input.key;
    }

    pub fn step(s: State, input: Input, output: ?Output) ?State {
        return Register.step(s, input.op, output);
    }
};

// ----------------------------------------------------------------------
// Tests

const testing = std.testing;

test "sequential register history is linearizable" {
    var h = History(Register).init(testing.allocator);
    defer h.deinit();
    const a = try h.invoke(0, .{ .write = 5 });
    h.ok(a, .ok);
    const b = try h.invoke(0, .read);
    h.ok(b, .{ .value = 5 });
    try testing.expectEqual(Result.linearizable, try check(testing.allocator, Register, &h, .{}));
}

test "a stale read after a completed write is not linearizable" {
    var h = History(Register).init(testing.allocator);
    defer h.deinit();
    const w = try h.invoke(0, .{ .write = 1 });
    h.ok(w, .ok);
    const r = try h.invoke(1, .read);
    h.ok(r, .{ .value = 0 });
    const res = try check(testing.allocator, Register, &h, .{});
    try testing.expect(res == .not_linearizable);
    try testing.expectEqual(@as(usize, 1), res.not_linearizable.stuck);
}

test "concurrent operations may be ordered either way" {
    var h = History(Register).init(testing.allocator);
    defer h.deinit();
    const w = try h.invoke(0, .{ .write = 1 });
    const r = try h.invoke(1, .read); // overlaps the write
    h.ok(r, .{ .value = 1 });
    h.ok(w, .ok);
    const r2 = try h.invoke(1, .read);
    h.ok(r2, .{ .value = 1 });
    try testing.expectEqual(Result.linearizable, try check(testing.allocator, Register, &h, .{}));
}

test "a pending write may or may not have happened" {
    var h = History(Register).init(testing.allocator);
    defer h.deinit();
    _ = try h.invoke(0, .{ .write = 9 }); // never answered
    const r1 = try h.invoke(1, .read);
    h.ok(r1, .{ .value = 0 });
    const r2 = try h.invoke(1, .read);
    h.ok(r2, .{ .value = 9 });
    try testing.expectEqual(Result.linearizable, try check(testing.allocator, Register, &h, .{}));
    // ...but it cannot un-happen.
    const r3 = try h.invoke(1, .read);
    h.ok(r3, .{ .value = 0 });
    try testing.expect((try check(testing.allocator, Register, &h, .{})) == .not_linearizable);
}

test "failed operations are ignored; cas outcomes are checked" {
    var h = History(Register).init(testing.allocator);
    defer h.deinit();
    const f = try h.invoke(0, .{ .write = 3 });
    h.failed(f);
    const c = try h.invoke(0, .{ .cas = .{ .from = 0, .to = 4 } });
    h.ok(c, .{ .cas = true });
    const c2 = try h.invoke(0, .{ .cas = .{ .from = 0, .to = 5 } });
    h.ok(c2, .{ .cas = true }); // impossible: the value is 4
    try testing.expect((try check(testing.allocator, Register, &h, .{})) == .not_linearizable);
}

test "kv partitions are checked independently" {
    var h = History(Kv).init(testing.allocator);
    defer h.deinit();
    // Many concurrent writers across keys: a single partition would blow up.
    var ids: [40]usize = undefined;
    for (&ids, 0..) |*id, i| id.* = try h.invoke(@intCast(i), .{ .key = i % 4, .op = .{ .write = i } });
    for (ids, 0..) |id, i| {
        _ = i;
        h.ok(id, .ok);
    }
    const r = try h.invoke(99, .{ .key = 2, .op = .read });
    h.ok(r, .{ .value = 38 });
    try testing.expectEqual(Result.linearizable, try check(testing.allocator, Kv, &h, .{}));
    const bad = try h.invoke(99, .{ .key = 3, .op = .read });
    h.ok(bad, .{ .value = 2 }); // key 3 was last written... any of 3,7,..,39 concurrently; 2 never
    const res = try check(testing.allocator, Kv, &h, .{});
    try testing.expect(res == .not_linearizable);
    try testing.expectEqual(@as(u64, 3), res.not_linearizable.partition);
}
