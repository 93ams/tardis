//! The edge, comparison and division tracer for instrumented C (plan2.md
//! §6.3): clang's SanitizerCoverage callbacks, for C built by `zig cc` with
//! `-fsanitize-coverage=trace-pc,trace-cmp,trace-div,trace-loads,trace-stores`
//! (any subset; `trace-pc-guard`
//! in place of `trace-pc` on ELF targets; on Windows the guard sections
//! link only with the MSVC ABI). Exported only
//! when a test asks for them with `comptime { tardis_sec.exportCoverage(); }`
//! (Zig's own `-ffuzz` runtime exports other `__sanitizer_cov_*` symbols,
//! none of these).
//!
//! While a simulation runs on the thread, the tracer folds into one hash:
//! - every edge in the order taken: control flow. A `trace-pc` edge is
//!   named by its address, which is stable within one process (the two
//!   runs a dual execution compares); a guard by its number;
//! - the cache set of every traced load and store: address bits 6–11, the
//!   64 sets of a typical 32 KiB L1 data cache with 64-byte lines. Where a
//!   table lookup lands in the cache follows its index, so a lookup indexed
//!   by a secret shows; bits above 11 are left out, since the two runs'
//!   heaps and stacks sit at different (page-aligned) addresses;
//! - the significant bits of the divisor of every traced division (clang
//!   passes the divisor only): a variable-time instruction's latency
//!   follows its operands' widths.
//!
//! Each edge is also a coverage feature for guided exploration
//! (`Options.explore = .guided`), and the constants are offered to its
//! mutator through seam 3's `tokens` hook (comparison feedback, §7.1).
//!
//! Comparison operands are data, not timing (constant-time code compares
//! secrets and selects without branching), so they are not folded. They are
//! counted, and the constants compared against are kept as tokens.
//!
//! `assertConstantTime` and `assertNonInterference` mix the hash of each run
//! into the trace they compare, so C that branches on a secret, or divides
//! by one, leaks even when its I/O does not.

const std = @import("std");
const tardis = @import("tardis");
const engine = @import("engine.zig");

/// Constants compared against (`trace_const_cmp`), kept per thread.
pub const tokens_max = 64;

pub const Trace = struct {
    hash: u64 = 0,
    edges: u64 = 0,
    comparisons: u64 = 0,
    divisions: u64 = 0,
    accesses: u64 = 0,
    tokens: [tokens_max]u64 = undefined,
    tokens_len: u8 = 0,

    fn fold(t: *Trace, x: u64) void {
        t.hash = tardis.decide.mix(t.hash ^ x, 0x5EC0_C7AC_E000_0208);
    }

    fn token(t: *Trace, x: u64) void {
        for (t.tokens[0..t.tokens_len]) |k| if (k == x) return;
        if (t.tokens_len == tokens_max) return;
        t.tokens[t.tokens_len] = x;
        t.tokens_len += 1;
    }

    /// The distinct constants C code compared against, first seen first.
    pub fn constants(t: *const Trace) []const u64 {
        return t.tokens[0..t.tokens_len];
    }
};

threadlocal var trace: Trace = .{};
/// Guards numbered so far (all modules).
var guards_given: u32 = 0;

/// Forgets the thread's trace (before a run).
pub fn reset() void {
    trace = .{};
}

/// The thread's trace since `reset`.
pub fn current() *const Trace {
    return &trace;
}

/// Offers `x` to guided exploration as a value worth forcing (§7.1), as a
/// constant instrumented C compared against is. Outside a simulation it
/// does nothing.
pub fn offer(x: u64) void {
    if (simulating()) trace.token(x);
}

fn simulating() bool {
    return tardis.Sim.activeOrNull() != null;
}

pub fn exportSymbols() void {
    @export(&guardInit, .{ .name = "__sanitizer_cov_trace_pc_guard_init" });
    @export(&guard, .{ .name = "__sanitizer_cov_trace_pc_guard" });
    @export(&pc, .{ .name = "__sanitizer_cov_trace_pc" });
    @export(&cmp1, .{ .name = "__sanitizer_cov_trace_cmp1" });
    @export(&cmp2, .{ .name = "__sanitizer_cov_trace_cmp2" });
    @export(&cmp4, .{ .name = "__sanitizer_cov_trace_cmp4" });
    @export(&cmp8, .{ .name = "__sanitizer_cov_trace_cmp8" });
    @export(&constCmp1, .{ .name = "__sanitizer_cov_trace_const_cmp1" });
    @export(&constCmp2, .{ .name = "__sanitizer_cov_trace_const_cmp2" });
    @export(&constCmp4, .{ .name = "__sanitizer_cov_trace_const_cmp4" });
    @export(&constCmp8, .{ .name = "__sanitizer_cov_trace_const_cmp8" });
    @export(&switchCmp, .{ .name = "__sanitizer_cov_trace_switch" });
    @export(&div4, .{ .name = "__sanitizer_cov_trace_div4" });
    @export(&div8, .{ .name = "__sanitizer_cov_trace_div8" });
    inline for (.{ 1, 2, 4, 8, 16 }) |n| {
        @export(&Access(n, false).f, .{ .name = std.fmt.comptimePrint("__sanitizer_cov_load{d}", .{n}) });
        @export(&Access(n, true).f, .{ .name = std.fmt.comptimePrint("__sanitizer_cov_store{d}", .{n}) });
    }
}

/// Bits 6–11 of an address: its set in a 64-set L1 data cache.
pub fn cacheSet(addr: usize) u64 {
    return (addr >> 6) & 63;
}

fn Access(comptime bytes: u8, comptime store: bool) type {
    return struct {
        fn f(addr: ?*const anyopaque) callconv(.c) void {
            if (!simulating()) return;
            trace.accesses += 1;
            // With a shadowed heap, the access is checked against it (§3.8).
            engine.shadowAccess(@intFromPtr(addr), bytes, store);
            const kind: u64 = if (store) 0x5700 else 0x1D00;
            trace.fold(kind | (@as(u64, bytes) << 6) | cacheSet(@intFromPtr(addr)));
            // After a marked bounds check, the value this load is about
            // to return goes to the Spectre-v1 detector (§6.3).
            if (store or !engine.spectreWatching()) return;
            const p: [*]const u8 = @ptrCast(addr orelse return);
            var value: u64 = 0;
            const n = @min(bytes, @sizeOf(u64));
            @memcpy(std.mem.asBytes(&value)[0..n], p[0..n]);
            engine.spectreLoad(@intFromPtr(p), value);
        }
    };
}

/// Numbers each module's guards once, from 1 (a guard of 0 is not traced).
fn guardInit(start: [*]u32, stop: [*]u32) callconv(.c) void {
    if (start == stop or start[0] != 0) return;
    const n = (@intFromPtr(stop) - @intFromPtr(start)) / @sizeOf(u32);
    for (start[0..n]) |*g| {
        guards_given += 1;
        g.* = guards_given;
    }
}

fn guard(g: *u32) callconv(.c) void {
    if (g.* != 0) edge(g.*);
}

/// An edge: folded into the trace, and a coverage feature for guided
/// exploration (so C that does no I/O still grows the corpus).
fn edge(id: u64) void {
    const s = tardis.Sim.activeOrNull() orelse return;
    trace.edges += 1;
    trace.fold(id);
    engine.spectreEdge();
    s.cover(tardis.decide.mix(id, 0x5EC0_ED6E_0000_0001));
}

fn pc() callconv(.c) void {
    edge(@returnAddress());
}

fn compared() void {
    if (simulating()) trace.comparisons += 1;
}

fn cmp1(_: u8, _: u8) callconv(.c) void {
    compared();
}
fn cmp2(_: u16, _: u16) callconv(.c) void {
    compared();
}
fn cmp4(_: u32, _: u32) callconv(.c) void {
    compared();
}
fn cmp8(_: u64, _: u64) callconv(.c) void {
    compared();
}

/// The first operand is the compile-time constant.
fn constCompared(k: u64) void {
    if (!simulating()) return;
    trace.comparisons += 1;
    trace.token(k);
}

fn constCmp1(k: u8, _: u8) callconv(.c) void {
    constCompared(k);
}
fn constCmp2(k: u16, _: u16) callconv(.c) void {
    constCompared(k);
}
fn constCmp4(k: u32, _: u32) callconv(.c) void {
    constCompared(k);
}
fn constCmp8(k: u64, _: u64) callconv(.c) void {
    constCompared(k);
}

/// `cases[0]` is the case count, `cases[1]` the width in bits, then the
/// case values.
fn switchCmp(_: u64, cases: [*]const u64) callconv(.c) void {
    if (!simulating()) return;
    trace.comparisons += 1;
    for (cases[2..][0..@intCast(cases[0])]) |k| trace.token(k);
}

fn divided(divisor: u64) void {
    if (!simulating()) return;
    trace.divisions += 1;
    trace.fold(0xD1F0_0000 | @as(u64, 64 - @clz(divisor)));
}

fn div4(divisor: u32) callconv(.c) void {
    divided(divisor);
}
fn div8(divisor: u64) callconv(.c) void {
    divided(divisor);
}
