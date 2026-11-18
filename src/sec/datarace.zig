//! A happens-before data-race detector for instrumented code (plan2.md
//! §4.5): vector clocks per task, fed by the loads, stores and atomic
//! operations the sanitizer's callbacks report (`shadow.zig`) and by what
//! core says orders tasks (`seam.TaskSync`).
//!
//! The simulator runs one task at a time, so two tasks never touch a word
//! at the same instant. A race here is the pair real threads could
//! interleave: two accesses to one address from two tasks of one node, at
//! least one a store, with nothing ordering the first before the second.
//!
//! What orders them:
//! - a spawn (the child comes after the parent's steps so far);
//! - a wake (the woken task continues after the waker's steps);
//! - an await of a future or a group (the waiter comes after the tasks
//!   awaited);
//! - an atomic operation: a store or read-modify-write publishes the
//!   task's clock at that address, a load or read-modify-write takes it.
//!   `std.Io.Mutex` and what `std.Io` builds on it are atomics and wakes,
//!   so data guarded by a mutex locked in instrumented code is ordered.
//!
//! Each address remembers its last store and its last load (one of each,
//! not every reader), so a race may be missed and none is invented by the
//! shadow itself. Fixed capacities, no allocation after `init`.

const std = @import("std");

pub const tasks_max = 128;
const cells_len = 1 << 16;
pub const syncs_max = 512;
const sync_slots = syncs_max * 2;
const none: u16 = std.math.maxInt(u16);

pub const Clock = [tasks_max]u32;

const Cell = struct {
    addr: usize,
    /// The run it belongs to (`Detector.run`): older cells are empty.
    run: u32,
    write_clock: u32,
    read_clock: u32,
    write_task: u16,
    read_task: u16,
};

pub const Race = struct {
    /// The earlier access's task, and whether it was a store.
    other: u16,
    other_write: bool,
};

pub const Detector = struct {
    clocks: []Clock,
    cells: []Cell,
    /// Open addressing: key + 1, or 0 for an empty slot.
    sync_keys: []usize,
    sync_index: []u16,
    sync_clocks: []Clock,
    syncs_len: u16 = 0,
    run: u32 = 1,
    /// Each slot's next own clock value: never reused within a run, so a
    /// new task in an old slot is not mistaken for the old one.
    next_own: [tasks_max]u32 = @splat(1),
    node_of: [tasks_max]u8 = @splat(0),
    /// Highest task slot seen this run (what `reset` must clear).
    tasks_high: u16 = 0,
    /// The run outgrew a table: ordering was lost, so nothing more is
    /// reported in it.
    blind: bool = false,
    /// Accesses checked this run.
    checked: u64 = 0,

    pub fn init(gpa: std.mem.Allocator) error{OutOfMemory}!Detector {
        const clocks = try gpa.alloc(Clock, tasks_max);
        errdefer gpa.free(clocks);
        const cells = try gpa.alloc(Cell, cells_len);
        errdefer gpa.free(cells);
        const sync_keys = try gpa.alloc(usize, sync_slots);
        errdefer gpa.free(sync_keys);
        const sync_index = try gpa.alloc(u16, sync_slots);
        errdefer gpa.free(sync_index);
        const sync_clocks = try gpa.alloc(Clock, syncs_max);
        for (clocks) |*c| c.* = @splat(0);
        for (cells) |*c| c.run = 0;
        @memset(sync_keys, 0);
        var d: Detector = .{ .clocks = clocks, .cells = cells, .sync_keys = sync_keys, .sync_index = sync_index, .sync_clocks = sync_clocks };
        d.tasks_high = tasks_max - 1;
        d.reset();
        return d;
    }

    pub fn deinit(d: *Detector, gpa: std.mem.Allocator) void {
        gpa.free(d.clocks);
        gpa.free(d.cells);
        gpa.free(d.sync_keys);
        gpa.free(d.sync_index);
        gpa.free(d.sync_clocks);
    }

    /// A new run: every cell is empty, every clock starts over.
    pub fn reset(d: *Detector) void {
        d.run +%= 1;
        if (d.run == 0) {
            for (d.cells) |*c| c.run = 0;
            d.run = 1;
        }
        for (d.clocks[0 .. @as(usize, d.tasks_high) + 1], 0..) |*c, i| {
            c.* = @splat(0);
            c[i] = 1;
        }
        d.next_own = @splat(2);
        d.tasks_high = 0;
        if (d.syncs_len != 0) @memset(d.sync_keys, 0);
        d.syncs_len = 0;
        d.blind = false;
        d.checked = 0;
    }

    fn known(d: *Detector, task: usize) bool {
        if (task >= tasks_max) {
            d.blind = true;
            return false;
        }
        d.tasks_high = @max(d.tasks_high, @as(u16, @intCast(task)));
        return true;
    }

    fn join(into: *Clock, from: *const Clock) void {
        for (into, from) |*a, b| a.* = @max(a.*, b);
    }

    fn tick(d: *Detector, task: usize) void {
        d.clocks[task][task] = d.next_own[task];
        d.next_own[task] += 1;
    }

    pub fn spawn(d: *Detector, parent: usize, child: usize) void {
        if (!d.known(parent) or !d.known(child)) return;
        d.clocks[child] = d.clocks[parent];
        d.tick(child);
        d.tick(parent);
        // A future this slot left unawaited is not this task's.
        if (d.sync(child * 2 + 1, false)) |s| s.* = @splat(0);
    }

    pub fn wake(d: *Detector, from: usize, to: usize) void {
        if (from == to or !d.known(from) or !d.known(to)) return;
        join(&d.clocks[to], &d.clocks[from]);
        d.tick(from);
    }

    fn sync(d: *Detector, key: usize, create: bool) ?*Clock {
        var slot: usize = (key *% 0x9E37_79B9_7F4A_7C15) >> (@bitSizeOf(usize) - std.math.log2(sync_slots));
        while (true) : (slot = (slot + 1) % sync_slots) {
            const k = d.sync_keys[slot];
            if (k == key +% 1) return &d.sync_clocks[d.sync_index[slot]];
            if (k != 0) continue;
            if (!create) return null;
            if (d.syncs_len == syncs_max) {
                d.blind = true;
                return null;
            }
            d.sync_keys[slot] = key +% 1;
            d.sync_index[slot] = d.syncs_len;
            const c = &d.sync_clocks[d.syncs_len];
            d.syncs_len += 1;
            c.* = @splat(0);
            return c;
        }
    }

    /// `task` publishes its steps so far at `key`.
    pub fn release(d: *Detector, task: usize, key: usize) void {
        if (!d.known(task)) return;
        const s = d.sync(key, true) orelse return;
        join(s, &d.clocks[task]);
        d.tick(task);
    }

    /// `task` comes after everything published at `key`.
    pub fn acquire(d: *Detector, task: usize, key: usize) void {
        if (!d.known(task)) return;
        const s = d.sync(key, false) orelse return;
        join(&d.clocks[task], s);
    }

    fn cell(d: *Detector, addr: usize) *Cell {
        const c = &d.cells[(addr *% 0x9E37_79B9_7F4A_7C15) >> (@bitSizeOf(usize) - std.math.log2(cells_len))];
        if (c.run != d.run or c.addr != addr) c.* = .{ .addr = addr, .run = d.run, .write_clock = 0, .read_clock = 0, .write_task = none, .read_task = none };
        return c;
    }

    /// `task` (on `node`) is about to load from or store to `addr`.
    pub fn access(d: *Detector, task: usize, node: u8, addr: usize, write: bool) ?Race {
        if (d.blind or !d.known(task)) return null;
        d.checked += 1;
        d.node_of[task] = node;
        const me = &d.clocks[task];
        const c = d.cell(addr);
        var found: ?Race = null;
        if (c.write_task != none and c.write_task != task and d.node_of[c.write_task] == node and c.write_clock > me[c.write_task]) {
            found = .{ .other = c.write_task, .other_write = true };
        } else if (write and c.read_task != none and c.read_task != task and d.node_of[c.read_task] == node and c.read_clock > me[c.read_task]) {
            found = .{ .other = c.read_task, .other_write = false };
        }
        if (write) {
            c.write_task = @intCast(task);
            c.write_clock = me[task];
        } else {
            c.read_task = @intCast(task);
            c.read_clock = me[task];
        }
        return found;
    }

    /// The heap handed out `[addr, addr + len)`: what earlier owners did
    /// there is not this block's history.
    pub fn forget(d: *Detector, addr: usize, len: usize) void {
        if (len >= cells_len) {
            for (d.cells) |*c| {
                if (c.run == d.run and c.addr >= addr and c.addr - addr < len) c.run = 0;
            }
            return;
        }
        for (addr..addr + len) |a| {
            const c = &d.cells[(a *% 0x9E37_79B9_7F4A_7C15) >> (@bitSizeOf(usize) - std.math.log2(cells_len))];
            if (c.run == d.run and c.addr == a) c.run = 0;
        }
    }
};

test "unordered accesses race, ordered ones do not" {
    var d = try Detector.init(std.testing.allocator);
    defer d.deinit(std.testing.allocator);
    const x: usize = 0x1000;
    // Task 0 spawns 1 and 2; both store to x.
    d.spawn(0, 1);
    d.spawn(0, 2);
    try std.testing.expectEqual(null, d.access(1, 0, x, true));
    const r = d.access(2, 0, x, true).?;
    try std.testing.expectEqual(@as(u16, 1), r.other);
    try std.testing.expect(r.other_write);

    d.reset();
    d.spawn(0, 1);
    d.spawn(0, 2);
    // Two loads never race; a store after an unordered load does.
    try std.testing.expectEqual(null, d.access(1, 0, x, false));
    try std.testing.expectEqual(null, d.access(2, 0, x, false));
    try std.testing.expect(!d.access(1, 0, x, true).?.other_write);

    d.reset();
    // The parent stores before the spawn: the child comes after.
    try std.testing.expectEqual(null, d.access(0, 0, x, true));
    d.spawn(0, 1);
    try std.testing.expectEqual(null, d.access(1, 0, x, true));
    // The parent awaits the child: its store comes after the child's.
    d.release(1, 3);
    d.acquire(0, 3);
    try std.testing.expectEqual(null, d.access(0, 0, x, true));
    // Without the await it races.
    d.spawn(0, 2);
    try std.testing.expectEqual(null, d.access(2, 0, x, true));
    try std.testing.expect(d.access(0, 0, x, true) != null);
}

test "an atomic orders what it guards, nodes are apart, and blocks start clean" {
    var d = try Detector.init(std.testing.allocator);
    defer d.deinit(std.testing.allocator);
    const x: usize = 0x2000;
    const lock: usize = 0x3000;
    d.spawn(0, 1);
    d.spawn(0, 2);
    // lock (read-modify-write), store, unlock (store), on each task.
    for ([_]usize{ 1, 2, 1 }) |t| {
        d.acquire(t, lock);
        d.release(t, lock);
        try std.testing.expectEqual(null, d.access(t, 0, x, true));
        d.release(t, lock);
    }
    // Another node's task is another process.
    try std.testing.expectEqual(null, d.access(2, 1, x + 8, true));
    try std.testing.expectEqual(null, d.access(1, 0, x + 8, true));
    // A block handed out again has no history.
    try std.testing.expectEqual(null, d.access(1, 0, x + 16, true));
    d.forget(x + 16, 8);
    try std.testing.expectEqual(null, d.access(2, 0, x + 16, true));
}
