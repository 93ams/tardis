//! Code under test for `shadow_test.zig`: built as an object with
//! `sanitize_thread`, so every load and store here is reported to the
//! shadow (plan2.md §3.8). It knows nothing of the simulator.

const std = @import("std");

/// Stores `n` bytes of `value` at `p`.
export fn sut_fill(p: [*]u8, n: usize, value: u8) void {
    for (p[0..n]) |*b| b.* = value;
}

/// The sum of `n` bytes at `p`.
export fn sut_sum(p: [*]const u8, n: usize) u32 {
    var total: u32 = 0;
    for (p[0..n]) |b| total +%= b;
    return total;
}

/// Copies `n` bytes (the compiler's `memcpy`).
export fn sut_copy(dst: [*]u8, src: [*]const u8, n: usize) void {
    @memcpy(dst[0..n], src[0..n]);
}

/// One byte, read through a pointer the caller may have freed.
export fn sut_peek(p: *const u8) u8 {
    return p.*;
}

/// An atomic counter: the sanitizer routes atomics through its runtime.
export fn sut_count(p: *u32) u32 {
    return @atomicRmw(u32, p, .Add, 1, .seq_cst);
}

/// A record parser with its own allocation: copies a `claimed`-byte field
/// into a `size`-byte buffer. Returns the field's checksum, or -1 when out
/// of memory.
export fn sut_parse(a: *const std.mem.Allocator, input: [*]const u8, claimed: usize, size: usize) i64 {
    const buf = a.alloc(u8, size) catch return -1;
    defer a.free(buf);
    var i: usize = 0;
    while (i < claimed) : (i += 1) buf.ptr[i] = input[i];
    return sut_sum(buf.ptr, @min(claimed, size));
}

// --- data races (plan2.md §4.5) ---------------------------------------------

/// A counter bumped with a plain load and store.
export fn sut_bump(p: *u64) void {
    p.* += 1;
}

export fn sut_read(p: *const u64) u64 {
    return p.*;
}

/// The same bump under a mutex locked here, where its atomics are seen.
export fn sut_bump_locked(io: *const std.Io, m: *std.Io.Mutex, p: *u64) void {
    m.lockUncancelable(io.*);
    defer m.unlock(io.*);
    p.* += 1;
}

/// The same bump as one atomic operation.
export fn sut_bump_atomic(p: *u64) void {
    _ = @atomicRmw(u64, p, .Add, 1, .monotonic);
}

// --- lock order (plan2.md §4.6) ---------------------------------------------

/// Takes `first`, then `second`, and drops both.
export fn sut_lock_both(io: *const std.Io, first: *std.Io.Mutex, second: *std.Io.Mutex) void {
    first.lockUncancelable(io.*);
    defer first.unlock(io.*);
    second.lockUncancelable(io.*);
    defer second.unlock(io.*);
}
