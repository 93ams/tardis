//! Atomics under simulation (plan §9 M6): `tardis.atomic.Value(T)` has
//! `std.atomic.Value`'s operations. Outside a simulation it is the real
//! atomic. Inside one:
//!
//! - every operation is a scheduling point, so the simulator can switch
//!   tasks between two of them, as a second core would run between them;
//! - a store with an ordering weaker than `.seq_cst` goes to the storing
//!   task's store buffer first. The task reads its own buffered value;
//!   other tasks still read the old one until the buffer drains. Whether a
//!   store is held back is a keyed decision (benign: it is not), so a
//!   failure that needs one replays and shrinks.
//!
//! That is the total-store-order model of x86: a store can be overtaken
//! by the storing core's later loads. It finds the classic bug of that
//! model, two threads that each store their flag and load the other's
//! without a `.seq_cst` store or a fence. It is not the C11 or ARM model:
//! reorderings only those allow (a later store before an earlier one,
//! loads of one address out of order) are not produced. `.seq_cst` stores
//! and every read-modify-write drain the buffer first, as a locked
//! instruction does. The buffer also drains when the task blocks, makes
//! any `std.Io` call, or ends.
//!
//! Data races on plain memory (vector clocks) are not checked.

const std = @import("std");
const Sim = @import("Sim.zig");
const AtomicOrder = std.builtin.AtomicOrder;

/// Chance that a task's buffered stores stay buffered at its next atomic
/// operation.
pub const hold_ppm = 500_000;

/// An atomic of type `T` (at most 8 bytes) with `std.atomic.Value`'s
/// operations: the real atomic outside a simulation, and inside one a
/// scheduling point with a store buffer for weak orderings (see above).
pub fn Value(comptime T: type) type {
    comptime std.debug.assert(@sizeOf(T) >= 1 and @sizeOf(T) <= @sizeOf(u64));
    return struct {
        raw: T,

        const Self = @This();

        /// An atomic holding `value`.
        pub fn init(value: T) Self {
            return .{ .raw = value };
        }

        fn addr(self: *const Self) usize {
            return @intFromPtr(&self.raw);
        }

        fn bitsOf(value: T) u64 {
            var bits: u64 = 0;
            @memcpy(std.mem.asBytes(&bits)[0..@sizeOf(T)], std.mem.asBytes(&value));
            return bits;
        }

        fn ofBits(bits: u64) T {
            var value: T = undefined;
            @memcpy(std.mem.asBytes(&value), std.mem.asBytes(&bits)[0..@sizeOf(T)]);
            return value;
        }

        /// Reads the value: the task's own latest buffered store if it has one,
        /// else what is in memory. Another task may run before and after.
        pub fn load(self: *const Self, comptime order: AtomicOrder) T {
            const s = Sim.activeOrNull() orelse return @atomicLoad(T, &self.raw, order);
            s.atomicPoint(hold_ppm);
            const value = if (s.atomicBuffered(self.addr())) |bits| ofBits(bits) else self.raw;
            // The task may be descheduled with what it read, and with its
            // own stores still buffered.
            s.atomicPoint(hold_ppm);
            return value;
        }

        /// Writes `value`. With `.seq_cst` it reaches memory at once, after the
        /// task's earlier buffered stores; with a weaker ordering it may wait in
        /// the task's store buffer, where other tasks do not see it yet.
        pub fn store(self: *Self, value: T, comptime order: AtomicOrder) void {
            const s = Sim.activeOrNull() orelse return @atomicStore(T, &self.raw, value, order);
            s.atomicPoint(hold_ppm);
            if (order == .seq_cst) {
                s.atomicFlush();
                self.raw = value;
            } else {
                s.atomicBuffer(self.addr(), bitsOf(value), @sizeOf(T));
            }
        }

        /// Stores `value` and returns what was there, as one step. Drains the
        /// task's store buffer first, like every read-modify-write here.
        pub fn swap(self: *Self, value: T, comptime order: AtomicOrder) T {
            const s = Sim.activeOrNull() orelse return @atomicRmw(T, &self.raw, .Xchg, value, order);
            s.atomicPoint(hold_ppm);
            s.atomicFlush();
            const old = self.raw;
            self.raw = value;
            return old;
        }

        /// Null when `expected` was there and `new` was stored; else what
        /// was there.
        pub fn cmpxchgStrong(self: *Self, expected: T, new: T, comptime success: AtomicOrder, comptime failure: AtomicOrder) ?T {
            const s = Sim.activeOrNull() orelse return @cmpxchgStrong(T, &self.raw, expected, new, success, failure);
            s.atomicPoint(hold_ppm);
            s.atomicFlush();
            const old = self.raw;
            if (!std.meta.eql(old, expected)) return old;
            self.raw = new;
            return null;
        }

        /// As `cmpxchgStrong`: the simulation does not fail spuriously.
        pub fn cmpxchgWeak(self: *Self, expected: T, new: T, comptime success: AtomicOrder, comptime failure: AtomicOrder) ?T {
            if (Sim.activeOrNull() == null) return @cmpxchgWeak(T, &self.raw, expected, new, success, failure);
            return self.cmpxchgStrong(expected, new, success, failure);
        }

        /// Adds `operand` (wrapping) as one step and returns the value before.
        pub fn fetchAdd(self: *Self, operand: T, comptime order: AtomicOrder) T {
            const s = Sim.activeOrNull() orelse return @atomicRmw(T, &self.raw, .Add, operand, order);
            s.atomicPoint(hold_ppm);
            s.atomicFlush();
            const old = self.raw;
            self.raw = old +% operand;
            return old;
        }

        /// Subtracts `operand` (wrapping) as one step and returns the value before.
        pub fn fetchSub(self: *Self, operand: T, comptime order: AtomicOrder) T {
            const s = Sim.activeOrNull() orelse return @atomicRmw(T, &self.raw, .Sub, operand, order);
            s.atomicPoint(hold_ppm);
            s.atomicFlush();
            const old = self.raw;
            self.raw = old -% operand;
            return old;
        }
    };
}

test "outside a simulation the value is a plain atomic" {
    var v = Value(u32).init(5);
    try std.testing.expectEqual(@as(u32, 5), v.load(.acquire));
    v.store(7, .release);
    try std.testing.expectEqual(@as(u32, 7), v.fetchAdd(1, .monotonic));
    try std.testing.expectEqual(@as(u32, 8), v.swap(2, .seq_cst));
    try std.testing.expectEqual(@as(?u32, 2), v.cmpxchgStrong(9, 1, .seq_cst, .seq_cst));
    try std.testing.expectEqual(@as(?u32, null), v.cmpxchgStrong(2, 1, .seq_cst, .seq_cst));
    try std.testing.expectEqual(@as(u32, 1), v.fetchSub(1, .monotonic));
    var flag = Value(bool).init(false);
    flag.store(true, .seq_cst);
    try std.testing.expect(flag.load(.seq_cst));
}
