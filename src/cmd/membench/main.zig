//! `zig build membench`: memory one simulator takes, by option (plan3.md
//! E3). Each row runs a campaign of one iteration (one per worker) of a small body through an
//! allocator that counts, and prints the most that was live at once.
//!
//! Fiber stacks are not in the count: they are reserved address space
//! (`limits.tasks_max` times `limits.fiber_stack_bytes`), and only the
//! pages a task touches become memory. The row shows the reservation.

const std = @import("std");
const tardis = @import("tardis");
const sec = @import("tardis_sec");
const Allocator = std.mem.Allocator;
const Env = tardis.Env;

/// Counts what is live and the most that ever was, and remembers the
/// largest single allocations.
const Counting = struct {
    child: Allocator,
    live: usize = 0,
    peak: usize = 0,
    largest: [largest_max]usize = @splat(0),
    /// `workers` allocate from their own threads.
    busy: std.atomic.Value(bool) = .init(false),

    const largest_max = 6;

    fn lock(c: *Counting) void {
        while (c.busy.swap(true, .acquire)) std.atomic.spinLoopHint();
    }

    fn unlock(c: *Counting) void {
        c.busy.store(false, .release);
    }

    fn allocator(c: *Counting) Allocator {
        return .{ .ptr = c, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn grew(c: *Counting, n: usize) void {
        c.live += n;
        c.peak = @max(c.peak, c.live);
    }

    fn note(c: *Counting, n: usize) void {
        var v = n;
        for (&c.largest) |*slot| if (v > slot.*) std.mem.swap(usize, slot, &v);
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        const p = c.child.rawAlloc(len, alignment, ra) orelse return null;
        c.lock();
        defer c.unlock();
        c.grew(len);
        c.note(len);
        return p;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        if (!c.child.rawResize(memory, alignment, new_len, ra)) return false;
        c.lock();
        defer c.unlock();
        c.live -= memory.len;
        c.grew(new_len);
        c.note(new_len);
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        const p = c.child.rawRemap(memory, alignment, new_len, ra) orelse return null;
        c.lock();
        defer c.unlock();
        c.live -= memory.len;
        c.grew(new_len);
        c.note(new_len);
        return p;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        c.lock();
        c.live -= memory.len;
        c.unlock();
        c.child.rawFree(memory, alignment, ra);
    }
};

/// A little of everything: a file, a task, some of the test's heap.
fn body(env: *Env) !void {
    const io = env.io;
    var f = try env.dir.createFile(io, "f", .{});
    defer f.close(io);
    try f.writePositionalAll(io, "hello", 0);
    const m = try env.allocator.alloc(u8, 4096);
    defer env.allocator.free(m);
    env.cover("ran", 1);
}

fn kib(n: usize) usize {
    return (n + 512) / 1024;
}

fn row(comptime name: []const u8, options: tardis.Options) !void {
    var c: Counting = .{ .child = std.heap.page_allocator };
    var o = options;
    o.iterations = @max(o.workers, 1);
    o.report = false;
    o.faults = .{ .io_error_ppm = 0, .oom_ppm = 0 };
    try tardis.check(c.allocator(), body, o);
    if (c.live != 0) return error.Leaked;
    const stacks = @as(usize, o.limits.tasks_max) * o.limits.fiber_stack_bytes;
    std.debug.print("| {s} | {d} KiB | {d} KiB | ", .{ name, kib(c.peak), kib(stacks) });
    for (c.largest, 0..) |n, i| {
        if (n < 16 * 1024) break;
        std.debug.print("{s}{d}", .{ if (i == 0) "" else ", ", kib(n) });
    }
    std.debug.print(" |\n", .{});
}

pub fn main() !void {
    std.debug.print("| Options | Most memory live at once | Fiber stacks (reserved, not memory until touched) | Largest allocations (KiB) |\n|---|---|---|---|\n", .{});
    try row("defaults (`.{}`)", .{});
    try row("`nodes = 3`", .{ .nodes = 3 });
    try row("`nodes = 8`", .{ .nodes = 8 });
    try row("`nodes = 32` (the most there can be)", .{ .nodes = 32 });
    try row("`limits.tasks_max = 1024`", .{ .limits = .{ .tasks_max = 1024 } });
    try row("`explore = .guided`", .{ .explore = .guided });
    try row("`workers = 4` (four simulators and the caller's)", .{ .workers = 4 });
    try row("`limits.trace_ring_len = 4096`", .{ .limits = .{ .trace_ring_len = 4096 } });
    try row("security layer (`tardis_sec`, its defaults)", sec.withSecurity(sec.default_config));
    try row("security layer with `shadow_memory`", sec.withSecurity(.{ .shadow_memory = true }));
    try row("security layer with `data_races`", sec.withSecurity(.{ .data_races = true }));
}
