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
//!
//! Without a security layer a freed block is filled with `freed_fill`
//! (`Options.poison_freed`): code that reads it after the free reads the
//! fill, the same on every replay, instead of the value it left there. The
//! fill is checked when the block leaves the quarantine and when the run
//! ends or the node crashes, which finds a write after the free. With a
//! layer the layer fills freed blocks with its own pattern, which it
//! recognizes where it looks (`tardis_sec`), and this check is not made.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;
const decide = @import("decide.zig");
const seam = @import("sec_seam.zig");

pub const redzone_bytes = seam.redzone_bytes;
/// Freed blocks held back from reuse, per node.
pub const quarantine_slots = 4096;
/// What a freed block is filled with: what Zig writes for `undefined` in
/// a build with runtime safety, so a read of it looks like one; as a
/// pointer it is not canonical on x86_64 and faults on aarch64.
pub const freed_fill: u8 = 0xAA;

/// Told of a freed block found changed: its length, and the first changed
/// byte's offset and value.
pub const FreedWritten = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, node: u8, len: usize, offset: usize, byte: u8) void,
};

/// Frames kept of the stack that made a live allocation.
pub const stack_frames_max = 12;

/// A live allocation, while `track` is on: what a leak report prints.
pub const Live = struct {
    len: usize,
    /// The order it was made in, among this heap's allocations of the run.
    order: u64,
    /// Return addresses, innermost first: the code that called the
    /// allocator, then its callers.
    stack: [stack_frames_max]usize,
    depth: u8,

    pub fn frames(l: *const Live) []const usize {
        return l.stack[0..l.depth];
    }
};

/// Whether a live allocation's whole stack is captured here: where std
/// can unwind a task's stack. Elsewhere only the allocator's caller.
const unwind_stacks = builtin.os.tag == .linux and std.debug.sys_can_stack_trace;

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
    /// Fill freed blocks and check the fill (`Options.poison_freed`);
    /// not with a security layer, which fills them itself.
    poison: bool = true,
    /// This heap's node, for the report of a write after free.
    node: u8 = 0,
    freed_written: ?FreedWritten = null,
    /// The live allocations and their stacks (`track`): on for the run a
    /// leak report makes again, off otherwise.
    live: std.AutoHashMapUnmanaged(usize, Live) = .empty,
    tracking: bool = false,
    /// An allocation the table could not hold: the report says so.
    track_lost: u64 = 0,
    track_order: u64 = 0,

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
        s.live.deinit(s.arena.child_allocator);
        s.arena.child_allocator.free(s.quarantine);
        s.arena.deinit();
    }

    /// Wipes the heap (crash or new iteration).
    /// True if nothing was allocated since `reset`.
    pub fn pristine(s: *const SutAllocator) bool {
        return s.live_bytes == 0 and s.live_count == 0 and s.oom_count == 0 and s.quarantine_len == 0;
    }

    /// Whether freed blocks are filled and checked here.
    fn filling(s: *const SutAllocator) bool {
        return s.poison and s.sec == null;
    }

    /// Checks every quarantined block's fill (`freed_written` hears of the
    /// first changed one); before the heap is wiped.
    pub fn checkQuarantine(s: *SutAllocator) void {
        if (!s.filling()) return;
        for (s.quarantine[0..s.quarantine_len]) |q| {
            if (s.checkFill(q)) return;
        }
    }

    /// True if `q` was written after its free (and says so).
    fn checkFill(s: *SutAllocator, q: Quarantined) bool {
        const bytes = q.ptr[0 .. q.len - redzone_bytes];
        const at = firstChanged(bytes) orelse return false;
        if (s.freed_written) |sink| sink.f(sink.ctx, s.node, bytes.len, at, bytes[at]);
        return true;
    }

    pub fn reset(s: *SutAllocator) void {
        _ = s.arena.reset(.retain_capacity);
        s.live.clearRetainingCapacity();
        s.track_lost = 0;
        s.track_order = 0;
        s.live_bytes = 0;
        s.live_count = 0;
        s.quarantine_len = 0;
        s.quarantine_next = 0;
        if (s.sec) |a| a.provider.heap_reset(a.ctx, s.sec_node);
    }

    /// Records each allocation's size and stack from the next run on
    /// (`on`), or stops.
    pub fn track(s: *SutAllocator, on: bool) void {
        s.tracking = on;
        if (!on) s.live.clearRetainingCapacity();
    }

    fn trackAlloc(s: *SutAllocator, p: [*]u8, len: usize, ret_addr: usize) void {
        var l: Live = .{ .len = len, .order = s.track_order, .stack = undefined, .depth = 0 };
        s.track_order += 1;
        if (unwind_stacks and std.options.allow_stack_tracing) {
            const t = std.debug.captureCurrentStackTrace(.{ .first_address = ret_addr }, &l.stack);
            l.depth = @intCast(t.return_addresses.len);
        }
        if (l.depth == 0) {
            l.stack[0] = ret_addr;
            l.depth = 1;
        }
        s.live.put(s.arena.child_allocator, @intFromPtr(p), l) catch {
            s.track_lost += 1;
        };
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
        if (s.filling()) _ = s.checkFill(old);
        s.arena.allocator().rawFree(old.ptr[0..old.len], old.alignment, ret_addr);
        s.quarantine[s.quarantine_next] = q;
        s.quarantine_next = (s.quarantine_next + 1) % s.quarantine.len;
    }

    /// The first byte of `bytes` that is not `freed_fill`: sixteen at a
    /// time (every freed byte is looked at once, even in a debug build).
    fn firstChanged(bytes: []const u8) ?usize {
        const V = @Vector(16, u8);
        const fill: V = @splat(freed_fill);
        var i: usize = 0;
        while (i + 16 <= bytes.len) : (i += 16) {
            const v: V = bytes[i..][0..16].*;
            if (@reduce(.Or, v != fill)) break;
        }
        while (i < bytes.len) : (i += 1) {
            if (bytes[i] != freed_fill) return i;
        }
        return null;
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
        if (s.tracking) s.trackAlloc(p, len, ret_addr);
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
        if (s.tracking) if (s.live.getPtr(@intFromPtr(memory.ptr))) |l| {
            l.len = new_len;
        };
        if (new_len < memory.len) s.secFree(memory[new_len..]);
        // The dropped tail past the new guard: filled, not checked (the
        // arena may give it to the next allocation).
        if (new_len + redzone_bytes < memory.len and s.filling()) @memset(memory[new_len + redzone_bytes ..], freed_fill);
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
        if (s.filling()) @memset(memory, freed_fill);
        s.quarantinePush(memory.ptr[0 .. memory.len + redzone_bytes], alignment, ret_addr);
        s.live_bytes -= memory.len;
        s.live_count -= 1;
        if (s.tracking) _ = s.live.remove(@intFromPtr(memory.ptr));
    }

    /// The live allocations recorded, at most `out.len` of them, the
    /// earliest made first; the count of all of them.
    pub fn liveAllocations(s: *const SutAllocator, out: []Live) struct { []Live, usize } {
        var n: usize = 0;
        var it = s.live.valueIterator();
        while (it.next()) |l| {
            // Insertion into the `out.len` earliest, by order.
            var i = @min(n, out.len);
            if (i == out.len) {
                if (out.len == 0 or out[out.len - 1].order < l.order) {
                    n += 1;
                    continue;
                }
                i -= 1;
            }
            while (i > 0 and out[i - 1].order > l.order) : (i -= 1) {
                if (i < out.len) out[i] = out[i - 1];
            }
            out[i] = l.*;
            n += 1;
        }
        return .{ out[0..@min(n, out.len)], n };
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

test "a freed block is filled, and a write to it is found when it leaves the quarantine or is checked" {
    var d = decide.Decider.init(1);
    var s = try SutAllocator.init(std.testing.allocator, &d, 1 << 30);
    defer s.deinit();
    const Seen = struct {
        count: usize = 0,
        len: usize = 0,
        offset: usize = 0,
        byte: u8 = 0,
        fn f(ctx: *anyopaque, _: u8, len: usize, offset: usize, byte: u8) void {
            const seen: *@This() = @ptrCast(@alignCast(ctx));
            seen.count += 1;
            seen.len = len;
            seen.offset = offset;
            seen.byte = byte;
        }
    };
    var seen: Seen = .{};
    s.freed_written = .{ .ctx = &seen, .f = Seen.f };
    const a = s.allocator();
    const x = try a.alloc(u8, 40);
    @memset(x, 7);
    a.rawFree(x, .@"1", @returnAddress());
    for (x) |b| try std.testing.expectEqual(freed_fill, b);
    s.checkQuarantine();
    try std.testing.expectEqual(@as(usize, 0), seen.count);
    // A write after the free.
    x[13] = 1;
    s.checkQuarantine();
    try std.testing.expectEqual(@as(usize, 1), seen.count);
    try std.testing.expectEqual(@as(usize, 40), seen.len);
    try std.testing.expectEqual(@as(usize, 13), seen.offset);
    try std.testing.expectEqual(@as(u8, 1), seen.byte);
    // And when it leaves the quarantine.
    for (0..quarantine_slots) |_| a.free(try a.alloc(u8, 1));
    try std.testing.expectEqual(@as(usize, 2), seen.count);
    s.reset();

    // Off: the bytes stay as the program left them.
    s.poison = false;
    const y = try a.alloc(u8, 8);
    @memset(y, 7);
    // Past `free`, which writes `undefined` first in a build with runtime
    // safety.
    a.rawFree(y, .@"1", @returnAddress());
    for (y) |b| try std.testing.expectEqual(@as(u8, 7), b);
    s.reset();
}

test "with tracking on, the live allocations are listed with their sizes, earliest first" {
    var d = decide.Decider.init(1);
    var s = try SutAllocator.init(std.testing.allocator, &d, 1 << 20);
    defer s.deinit();
    const a = s.allocator();
    s.track(true);
    defer s.track(false);
    var blocks: [6][]u8 = undefined;
    for (&blocks, 0..) |*b, i| b.* = try a.alloc(u8, 10 + i);
    a.free(blocks[1]);
    try std.testing.expect(a.resize(blocks[4], 3));
    var out: [3]Live = undefined;
    const listed, const all = s.liveAllocations(&out);
    try std.testing.expectEqual(@as(usize, 5), all);
    try std.testing.expectEqual(@as(usize, 3), listed.len);
    try std.testing.expectEqual(@as(usize, 10), listed[0].len);
    try std.testing.expectEqual(@as(usize, 12), listed[1].len);
    try std.testing.expectEqual(@as(usize, 13), listed[2].len);
    for (listed) |l| try std.testing.expect(l.depth >= 1);
    var more: [8]Live = undefined;
    const every, _ = s.liveAllocations(&more);
    try std.testing.expectEqual(@as(usize, 5), every.len);
    try std.testing.expectEqual(@as(usize, 3), every[3].len);
    s.reset();
    try std.testing.expectEqual(@as(usize, 0), s.liveAllocations(&out)[1]);
}
