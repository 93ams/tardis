//! Shadow memory for instrumented code (plan2.md §3.6, §3.8): one state
//! byte per byte of the simulated heap, kept by the allocator hooks and
//! checked at every load and store the compiler reports.
//!
//! The reports are LLVM's ThreadSanitizer callbacks (`__tsan_read8`,
//! `__tsan_write4`, `__tsan_memcpy`, `__tsan_atomic32_load`, ...), which
//! Zig emits for Zig code built with `sanitize_thread` and clang for C
//! built with `-fsanitize=thread`. A test that links such code exports
//! this runtime in place of the sanitizer's own with
//! `comptime { tardis_sec.exportSanitizer(); }`.
//!
//! Zig links its own sanitizer runtime into any executable that has a
//! module built with `sanitize_thread`, and the two cannot share a
//! program. So the code under test is built as an object
//! (`b.addObject`, `sanitize_thread = true`) and linked into a test that
//! is not.
//!
//! With `SecurityConfig.shadow_memory`, an access to a guard after an
//! allocation, or to a freed block still in quarantine, is a finding at
//! the access itself: CWE-787 (write past the end), CWE-125 (read past
//! the end) or CWE-416 (use after free).

const std = @import("std");
const engine = @import("engine.zig");

pub const State = enum(u8) {
    /// Not heap, or heap the program may use.
    valid = 0,
    /// The guard after an allocation.
    redzone = 1,
    /// Freed, and held back from reuse.
    freed = 2,
};

pub const page_bits = 12;
pub const page_bytes = 1 << page_bits;
/// Heap pages one run can shadow (8 MiB of heap); more are counted in
/// `dropped` and not checked.
pub const pages_max = 2048;
const slots = pages_max * 2;

pub const Hit = struct {
    state: State,
    /// Address of the first byte of the access that is not valid.
    addr: usize,
};

pub const Shadow = struct {
    /// Open addressing: page number + 1, or 0 for an empty slot.
    keys: []usize,
    /// The slot's page in `bytes`.
    index: []u16,
    /// Slot of each page in use, to empty it at `reset`.
    slot_of: []u16,
    bytes: []u8,
    used: u16 = 0,
    /// Bounds of every marked address: an access outside is valid.
    lo: usize = std.math.maxInt(usize),
    hi: usize = 0,
    /// Marks that found no free page.
    dropped: u32 = 0,
    /// Accesses reported by instrumented code this run.
    accesses: u64 = 0,

    pub fn init(gpa: std.mem.Allocator) error{OutOfMemory}!Shadow {
        const keys = try gpa.alloc(usize, slots);
        errdefer gpa.free(keys);
        const index = try gpa.alloc(u16, slots);
        errdefer gpa.free(index);
        const slot_of = try gpa.alloc(u16, pages_max);
        errdefer gpa.free(slot_of);
        const bytes = try gpa.alloc(u8, pages_max * page_bytes);
        @memset(keys, 0);
        return .{ .keys = keys, .index = index, .slot_of = slot_of, .bytes = bytes };
    }

    pub fn deinit(s: *Shadow, gpa: std.mem.Allocator) void {
        gpa.free(s.keys);
        gpa.free(s.index);
        gpa.free(s.slot_of);
        gpa.free(s.bytes);
    }

    /// Forgets every mark (a new run). Costs only the pages the last run
    /// used.
    pub fn reset(s: *Shadow) void {
        for (s.slot_of[0..s.used]) |slot| s.keys[slot] = 0;
        s.used = 0;
        s.lo = std.math.maxInt(usize);
        s.hi = 0;
        s.dropped = 0;
        s.accesses = 0;
    }

    fn page(s: *Shadow, number: usize, create: bool) ?[]u8 {
        var slot: usize = (number *% 0x9E37_79B9_7F4A_7C15) >> (@bitSizeOf(usize) - std.math.log2(slots));
        while (true) : (slot = (slot + 1) % slots) {
            const k = s.keys[slot];
            if (k == number + 1) return s.bytes[@as(usize, s.index[slot]) * page_bytes ..][0..page_bytes];
            if (k != 0) continue;
            if (!create) return null;
            if (s.used == pages_max) {
                s.dropped += 1;
                return null;
            }
            s.keys[slot] = number + 1;
            s.index[slot] = s.used;
            s.slot_of[s.used] = @intCast(slot);
            const p = s.bytes[@as(usize, s.used) * page_bytes ..][0..page_bytes];
            s.used += 1;
            @memset(p, @backingInt(State.valid));
            return p;
        }
    }

    /// Sets the state of `len` bytes at `addr`.
    pub fn mark(s: *Shadow, addr: usize, len: usize, state: State) void {
        if (len == 0) return;
        if (state != .valid) {
            s.lo = @min(s.lo, addr);
            s.hi = @max(s.hi, addr + len);
        }
        var a = addr;
        const end = addr + len;
        while (a < end) {
            const in_page = a & (page_bytes - 1);
            const n = @min(end - a, page_bytes - in_page);
            // A page with no marks is all valid already.
            if (s.page(a >> page_bits, state != .valid)) |p| @memset(p[in_page..][0..n], @backingInt(state));
            a += n;
        }
    }

    /// The first byte of `[addr, addr + len)` that is not valid.
    pub fn check(s: *Shadow, addr: usize, len: usize) ?Hit {
        if (addr >= s.hi or addr + len <= s.lo) return null;
        var a = addr;
        const end = addr + len;
        while (a < end) {
            const in_page = a & (page_bytes - 1);
            const n = @min(end - a, page_bytes - in_page);
            if (s.page(a >> page_bits, false)) |p| {
                for (p[in_page..][0..n], 0..) |b, i| {
                    if (b != @backingInt(State.valid)) return .{ .state = @fromBackingInt(b), .addr = a + i };
                }
            }
            a += n;
        }
        return null;
    }

    /// Bytes from `addr` back to the first valid byte below it (at most
    /// `limit`): how far past the end an access into a guard landed.
    pub fn depth(s: *Shadow, addr: usize, limit: usize) usize {
        var d: usize = 0;
        while (d < limit and addr > d) : (d += 1) {
            const a = addr - d - 1;
            const p = s.page(a >> page_bits, false) orelse break;
            if (p[a & (page_bytes - 1)] == @backingInt(State.valid)) break;
        }
        return d;
    }
};

fn read(addr: usize, len: usize) void {
    engine.shadowAccess(addr, len, false);
}

fn write(addr: usize, len: usize) void {
    engine.shadowAccess(addr, len, true);
}

fn Access(comptime bytes: usize, comptime store: bool) type {
    return struct {
        fn f(addr: usize) callconv(.c) void {
            engine.shadowAccess(addr, bytes, store);
        }
        fn both(addr: usize) callconv(.c) void {
            engine.shadowAccess(addr, bytes, true);
        }
    };
}

fn rangeRead(addr: usize, len: usize) callconv(.c) void {
    read(addr, len);
}

fn rangeWrite(addr: usize, len: usize) callconv(.c) void {
    write(addr, len);
}

fn nothing() callconv(.c) void {}
fn nothing1(_: usize) callconv(.c) void {}
fn nothing2(_: usize, _: usize) callconv(.c) void {}

// The sanitizer replaces the memory intrinsics with these, so they do the
// work too. Byte loops, so they cannot call themselves through `@memcpy`.
fn tsanMemcpy(dst: [*]u8, src: [*]const u8, n: usize) callconv(.c) [*]u8 {
    @setRuntimeSafety(false);
    read(@intFromPtr(src), n);
    write(@intFromPtr(dst), n);
    var i: usize = 0;
    while (i < n) : (i += 1) (dst + i)[0] = (src + i)[0];
    return dst;
}

fn tsanMemmove(dst: [*]u8, src: [*]const u8, n: usize) callconv(.c) [*]u8 {
    @setRuntimeSafety(false);
    read(@intFromPtr(src), n);
    write(@intFromPtr(dst), n);
    if (@intFromPtr(dst) <= @intFromPtr(src)) {
        var i: usize = 0;
        while (i < n) : (i += 1) (dst + i)[0] = (src + i)[0];
    } else {
        var i: usize = n;
        while (i > 0) {
            i -= 1;
            (dst + i)[0] = (src + i)[0];
        }
    }
    return dst;
}

fn tsanMemset(dst: [*]u8, value: c_int, n: usize) callconv(.c) [*]u8 {
    @setRuntimeSafety(false);
    write(@intFromPtr(dst), n);
    const b: u8 = @truncate(@as(c_uint, @bitCast(value)));
    var i: usize = 0;
    while (i < n) : (i += 1) (dst + i)[0] = b;
    return dst;
}

/// The atomic operations of one width. The sanitizer routes every atomic
/// through its runtime, so these perform them (sequentially consistent:
/// at least as strong as any order asked for) after checking the address.
/// An atomic is never a data race; it orders the tasks that use it
/// (`datarace.zig`).
fn Atomic(comptime T: type) type {
    return struct {
        /// `std.Io.Mutex` keeps its state in 32 bits: zero is unlocked.
        const lock_shaped = T == u32;

        fn load(p: *const T, _: c_int) callconv(.c) T {
            engine.atomicAccess(@intFromPtr(p), @sizeOf(T), .load);
            return @atomicLoad(T, p, .seq_cst);
        }
        fn store(p: *T, v: T, _: c_int) callconv(.c) void {
            engine.atomicAccess(@intFromPtr(p), @sizeOf(T), .store);
            @atomicStore(T, p, v, .seq_cst);
            if (lock_shaped and v == 0) engine.atomicLock(@intFromPtr(p), false);
        }
        fn Rmw(comptime op: std.builtin.AtomicRmwOp) type {
            return struct {
                fn f(p: *T, v: T, _: c_int) callconv(.c) T {
                    engine.atomicAccess(@intFromPtr(p), @sizeOf(T), .read_modify_write);
                    const old = @atomicRmw(T, p, op, v, .seq_cst);
                    if (lock_shaped and op == .Xchg) {
                        if (v == 0) engine.atomicLock(@intFromPtr(p), false) else if (old == 0) engine.atomicLock(@intFromPtr(p), true);
                    }
                    return old;
                }
            };
        }
        fn casVal(p: *T, expected: T, v: T, _: c_int, _: c_int) callconv(.c) T {
            engine.atomicAccess(@intFromPtr(p), @sizeOf(T), .read_modify_write);
            const old = @cmpxchgStrong(T, p, expected, v, .seq_cst, .seq_cst) orelse {
                if (lock_shaped and expected == 0 and v != 0) engine.atomicLock(@intFromPtr(p), true);
                return expected;
            };
            return old;
        }
        fn casStrong(p: *T, expected: *T, v: T, _: c_int, _: c_int) callconv(.c) c_int {
            engine.atomicAccess(@intFromPtr(p), @sizeOf(T), .read_modify_write);
            const want = expected.*;
            if (@cmpxchgStrong(T, p, want, v, .seq_cst, .seq_cst)) |old| {
                expected.* = old;
                return 0;
            }
            if (lock_shaped and want == 0 and v != 0) engine.atomicLock(@intFromPtr(p), true);
            return 1;
        }
    };
}

pub fn exportSymbols() void {
    @export(&nothing, .{ .name = "__tsan_init" });
    @export(&nothing1, .{ .name = "__tsan_func_entry" });
    @export(&nothing, .{ .name = "__tsan_func_exit" });
    @export(&nothing, .{ .name = "__tsan_ignore_thread_begin" });
    @export(&nothing, .{ .name = "__tsan_ignore_thread_end" });
    @export(&nothing2, .{ .name = "__tsan_vptr_update" });
    @export(&nothing1, .{ .name = "__tsan_vptr_read" });
    inline for (.{ 1, 2, 4, 8, 16 }) |n| {
        const r = &Access(n, false).f;
        const w = &Access(n, true).f;
        const rw = &Access(n, true).both;
        inline for (.{ "", "unaligned_", "volatile_", "unaligned_volatile_" }) |prefix| {
            @export(r, .{ .name = std.fmt.comptimePrint("__tsan_{s}read{d}", .{ prefix, n }) });
            @export(w, .{ .name = std.fmt.comptimePrint("__tsan_{s}write{d}", .{ prefix, n }) });
        }
        @export(rw, .{ .name = std.fmt.comptimePrint("__tsan_read_write{d}", .{n}) });
        @export(rw, .{ .name = std.fmt.comptimePrint("__tsan_unaligned_read_write{d}", .{n}) });
    }
    @export(&rangeRead, .{ .name = "__tsan_read_range" });
    @export(&rangeWrite, .{ .name = "__tsan_write_range" });
    @export(&tsanMemcpy, .{ .name = "__tsan_memcpy" });
    @export(&tsanMemmove, .{ .name = "__tsan_memmove" });
    @export(&tsanMemset, .{ .name = "__tsan_memset" });
    @export(&nothing1, .{ .name = "__tsan_atomic_thread_fence" });
    @export(&nothing1, .{ .name = "__tsan_atomic_signal_fence" });
    inline for (.{ u8, u16, u32, u64 }) |T| {
        const A = Atomic(T);
        const bits = @bitSizeOf(T);
        @export(&A.load, .{ .name = std.fmt.comptimePrint("__tsan_atomic{d}_load", .{bits}) });
        @export(&A.store, .{ .name = std.fmt.comptimePrint("__tsan_atomic{d}_store", .{bits}) });
        @export(&A.casVal, .{ .name = std.fmt.comptimePrint("__tsan_atomic{d}_compare_exchange_val", .{bits}) });
        @export(&A.casStrong, .{ .name = std.fmt.comptimePrint("__tsan_atomic{d}_compare_exchange_strong", .{bits}) });
        @export(&A.casStrong, .{ .name = std.fmt.comptimePrint("__tsan_atomic{d}_compare_exchange_weak", .{bits}) });
        inline for (.{
            .{ "exchange", .Xchg },
            .{ "fetch_add", .Add },
            .{ "fetch_sub", .Sub },
            .{ "fetch_and", .And },
            .{ "fetch_or", .Or },
            .{ "fetch_xor", .Xor },
            .{ "fetch_nand", .Nand },
        }) |op| {
            @export(&A.Rmw(op[1]).f, .{ .name = std.fmt.comptimePrint("__tsan_atomic{d}_{s}", .{ bits, op[0] }) });
        }
    }
}

test "marks, checks and reset" {
    var s = try Shadow.init(std.testing.allocator);
    defer s.deinit(std.testing.allocator);
    const base: usize = 0x10_0000;
    try std.testing.expectEqual(null, s.check(base, 64));
    // A 24-byte block, its 16-byte guard, across a page boundary.
    const block = base + page_bytes - 30;
    s.mark(block, 24, .valid);
    s.mark(block + 24, 16, .redzone);
    try std.testing.expectEqual(null, s.check(block, 24));
    const hit = s.check(block + 20, 8).?;
    try std.testing.expectEqual(State.redzone, hit.state);
    try std.testing.expectEqual(block + 24, hit.addr);
    try std.testing.expectEqual(@as(usize, 3), s.depth(block + 27, 64));
    try std.testing.expectEqual(@as(u16, 2), s.used);
    s.mark(block, 40, .freed);
    try std.testing.expectEqual(State.freed, s.check(block, 1).?.state);
    s.mark(block, 24, .valid);
    try std.testing.expectEqual(null, s.check(block, 24));
    s.reset();
    try std.testing.expectEqual(null, s.check(block, 40));
    try std.testing.expectEqual(@as(u16, 0), s.used);
}
