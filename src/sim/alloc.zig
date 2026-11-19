//! The SUT-visible heap (`env.allocator`, plan §2.3, §5.2).
//!
//! An arena that is reset on every crash and iteration (the "volatile heap"),
//! with deterministic OOM injection, a byte budget, and live-allocation
//! counting for leak checks. Arena capacity is retained across resets, so a
//! warm campaign stops calling the backing allocator.
//!
//! Every allocation is followed by `seam.redzone_bytes` guard bytes, and a
//! freed block goes through a FIFO of `quarantine_slots` before the arena
//! may reclaim it (plan2.md §3.5). Both hold with or without a security
//! layer, so attaching one never changes an address.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;
const decide = @import("decide.zig");
const seam = @import("sec_seam.zig");

pub const redzone_bytes = seam.redzone_bytes;
/// Freed blocks held back from reuse, per node.
pub const quarantine_slots = 4096;

const Quarantined = struct { ptr: [*]u8, len: usize, alignment: Alignment };

pub const SutAllocator = struct {
    arena: std.heap.ArenaAllocator,
    decider: *decide.Decider,
    oom_ppm: decide.Ppm,
    budget_bytes: u64,
    live_bytes: u64,
    live_count: u64,
    oom_count: u64,
    /// Freed blocks (guard included), oldest at `quarantine_next` once the
    /// FIFO is full. Allocated by `init`, so a free never allocates.
    quarantine: []Quarantined,
    quarantine_len: usize = 0,
    quarantine_next: usize = 0,
    /// The security layer, when one is attached (plan2.md §2.2).
    sec: ?seam.Attached = null,
    sec_node: seam.NodeId = 0,
    sec_violation: ?seam.ViolationSink = null,

    pub fn init(backing: Allocator, decider: *decide.Decider, budget_bytes: u64) error{OutOfMemory}!SutAllocator {
        return .{
            .quarantine = try backing.alloc(Quarantined, quarantine_slots),
            .arena = .init(backing),
            .decider = decider,
            .oom_ppm = 0,
            .budget_bytes = budget_bytes,
            .live_bytes = 0,
            .live_count = 0,
            .oom_count = 0,
        };
    }

    pub fn deinit(s: *SutAllocator) void {
        s.arena.child_allocator.free(s.quarantine);
        s.arena.deinit();
    }

    /// Wipes the heap (crash or new iteration).
    /// True if nothing was allocated since `reset`.
    pub fn pristine(s: *const SutAllocator) bool {
        return s.live_bytes == 0 and s.live_count == 0 and s.oom_count == 0 and s.quarantine_len == 0;
    }

    pub fn reset(s: *SutAllocator) void {
        _ = s.arena.reset(.retain_capacity);
        s.live_bytes = 0;
        s.live_count = 0;
        s.quarantine_len = 0;
        s.quarantine_next = 0;
        if (s.sec) |a| a.provider.heap_reset(a.ctx, s.sec_node);
    }

    fn secAlloc(s: *SutAllocator, mem: []u8) void {
        if (s.sec) |a| a.provider.alloc(a.ctx, s.sec_node, mem);
    }

    fn secFree(s: *SutAllocator, mem: []u8) void {
        const a = s.sec orelse return;
        const cwe = a.provider.free(a.ctx, s.sec_node, mem);
        if (cwe != 0) if (s.sec_violation) |v| v.f(v.ctx, cwe);
    }

    fn writeGuard(p: [*]u8, len: usize) void {
        @memcpy(p[len..][0..redzone_bytes], &seam.redzone_pattern);
    }

    /// Holds a freed block back from reuse; the oldest one goes back to the
    /// arena when the FIFO is full (which reclaims it only if it is still
    /// the arena's last block).
    fn quarantinePush(s: *SutAllocator, block: []u8, alignment: Alignment, ret_addr: usize) void {
        const q: Quarantined = .{ .ptr = block.ptr, .len = block.len, .alignment = alignment };
        if (s.quarantine_len < s.quarantine.len) {
            s.quarantine[s.quarantine_len] = q;
            s.quarantine_len += 1;
            return;
        }
        const old = s.quarantine[s.quarantine_next];
        s.arena.allocator().rawFree(old.ptr[0..old.len], old.alignment, ret_addr);
        s.quarantine[s.quarantine_next] = q;
        s.quarantine_next = (s.quarantine_next + 1) % s.quarantine.len;
    }

    pub fn allocator(s: *SutAllocator) Allocator {
        return .{ .ptr = s, .vtable = &vtable };
    }

    const vtable: Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn shouldFail(s: *SutAllocator, len: usize) bool {
        if (s.live_bytes + len > s.budget_bytes) return true;
        if (s.oom_ppm != 0 and s.decider.chance(.alloc, s.oom_ppm)) {
            s.oom_count += 1;
            return true;
        }
        return false;
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
        const s: *SutAllocator = @ptrCast(@alignCast(ctx));
        if (s.shouldFail(len)) return null;
        const p = s.arena.allocator().rawAlloc(len + redzone_bytes, alignment, ret_addr) orelse return null;
        writeGuard(p, len);
        s.live_bytes += len;
        s.live_count += 1;
        s.secAlloc(p[0..len]);
        return p;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) bool {
        const s: *SutAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > memory.len and s.live_bytes + (new_len - memory.len) > s.budget_bytes) return false;
        const block = memory.ptr[0 .. memory.len + redzone_bytes];
        if (!s.arena.allocator().rawResize(block, alignment, new_len + redzone_bytes, ret_addr)) return false;
        s.resized(memory, new_len);
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const s: *SutAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > memory.len and s.live_bytes + (new_len - memory.len) > s.budget_bytes) return null;
        const block = memory.ptr[0 .. memory.len + redzone_bytes];
        const p = s.arena.allocator().rawRemap(block, alignment, new_len + redzone_bytes, ret_addr) orelse return null;
        std.debug.assert(p == memory.ptr); // the arena remaps in place only
        s.resized(memory, new_len);
        return p;
    }

    /// After an in-place resize: the arena leaves the bytes in place, so a
    /// dropped tail is checked (against the old guard, still after it) and
    /// poisoned, then the guard moves to the new end.
    fn resized(s: *SutAllocator, memory: []u8, new_len: usize) void {
        s.live_bytes = s.live_bytes - memory.len + new_len;
        if (new_len < memory.len) s.secFree(memory[new_len..]);
        if (new_len > memory.len) s.secAlloc(memory.ptr[memory.len..new_len]);
        writeGuard(memory.ptr, new_len);
        // The guard now stands inside what was just dropped: an empty
        // allocation at the new end says where.
        if (new_len < memory.len) s.secAlloc(memory.ptr[new_len..new_len]);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: Alignment, ret_addr: usize) void {
        const s: *SutAllocator = @ptrCast(@alignCast(ctx));
        std.debug.assert(s.live_count > 0);
        s.secFree(memory);
        s.quarantinePush(memory.ptr[0 .. memory.len + redzone_bytes], alignment, ret_addr);
        s.live_bytes -= memory.len;
        s.live_count -= 1;
    }
};

test "live counting, budget, and oom" {
    var d = decide.Decider.init(1);
    var s = try SutAllocator.init(std.testing.allocator, &d, 1024);
    defer s.deinit();
    const a = s.allocator();
    const x = try a.alloc(u8, 100);
    try std.testing.expectEqual(@as(u64, 1), s.live_count);
    try std.testing.expectError(error.OutOfMemory, a.alloc(u8, 2000));
    a.free(x);
    try std.testing.expectEqual(@as(u64, 0), s.live_count);
    s.oom_ppm = decide.ppm_one;
    try std.testing.expectError(error.OutOfMemory, a.alloc(u8, 1));
    s.reset();
}

test "a guard follows every allocation and moves with a resize; a freed block is not reused at once" {
    var d = decide.Decider.init(1);
    var s = try SutAllocator.init(std.testing.allocator, &d, 1 << 20);
    defer s.deinit();
    const a = s.allocator();
    var x = try a.alloc(u8, 24);
    try std.testing.expectEqualSlices(u8, &seam.redzone_pattern, x.ptr[24..][0..redzone_bytes]);
    try std.testing.expect(a.resize(x, 10));
    x = x[0..10];
    try std.testing.expectEqualSlices(u8, &seam.redzone_pattern, x.ptr[10..][0..redzone_bytes]);
    const x_addr = @intFromPtr(x.ptr);
    a.free(x);
    // The arena would hand its last block straight back; the FIFO holds it.
    const y = try a.alloc(u8, 10);
    try std.testing.expect(@intFromPtr(y.ptr) != x_addr);
    a.free(y);
    try std.testing.expectEqual(@as(usize, 2), s.quarantine_len);
    s.reset();
    try std.testing.expectEqual(@as(usize, 0), s.quarantine_len);
}
