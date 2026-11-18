//! A virtual time-stamp counter (plan §9 M6): `rdtsc` and `rdtscp` are
//! instructions, not system calls, so code that times itself with them
//! reads the real machine and its run no longer depends on the seed alone.
//!
//! Linux on x86_64 only. While a run is on, `prctl(PR_SET_TSC,
//! PR_TSC_SIGSEGV)` makes the two instructions fault on this thread. The
//! SIGSEGV handler recognises them at the faulting address, answers with
//! the run's virtual time in nanoseconds plus the number of reads so far
//! (so two reads never return the same value, and the answer follows the
//! seed), and steps over the instruction. Any other fault goes to the
//! handler that was installed before this one (Zig's crash report in a
//! debug build), or to the default action.
//!
//! The kernel's vDSO reads the counter too: a real `clock_gettime` made
//! during such a run computes its answer from the virtual counter, and is
//! wrong. Code under test should not be calling it (`trap_syscalls` does
//! not see it either); the simulator does not.
//!
//! Elsewhere `supported` is false and nothing is trapped.

const std = @import("std");
const builtin = @import("builtin");
const syscalls = @import("syscalls.zig");

pub const supported = builtin.os.tag == .linux and builtin.cpu.arch == .x86_64;

const pr_set_tsc = 26;
const pr_tsc_enable = 1;
const pr_tsc_sigsegv = 2;
const sigsegv = 11;

/// The run's virtual clock, while the thread traps.
threadlocal var clock: ?*const u64 = null;
threadlocal var reads: u64 = 0;

var installed: std.atomic.Value(bool) = .init(false);
/// The SIGSEGV action in place before ours.
var previous: syscalls.KernelSigaction = undefined;

const gregs_offset = 8 + 8 + 24;
const reg_rdx = 12;
const reg_rax = 13;
const reg_rcx = 14;
const reg_rip = 16;

fn onSegv(sig: i32, info: ?*anyopaque, context: ?*anyopaque) callconv(.c) void {
    const gregs: [*]u64 = @ptrFromInt(@intFromPtr(context.?) + gregs_offset);
    if (clock) |now| {
        const ip: [*]const u8 = @ptrFromInt(gregs[reg_rip]);
        // `rdtsc` is 0F 31, `rdtscp` 0F 01 F9.
        const len: u64 = if (ip[0] == 0x0f and ip[1] == 0x31) 2 else if (ip[0] == 0x0f and ip[1] == 0x01 and ip[2] == 0xf9) 3 else 0;
        if (len != 0) {
            reads += 1;
            const value = now.* +% reads;
            gregs[reg_rax] = value & 0xffff_ffff;
            gregs[reg_rdx] = value >> 32;
            if (len == 3) gregs[reg_rcx] = 0; // `rdtscp`: processor 0
            gregs[reg_rip] += len;
            return;
        }
    }
    // Not ours: the earlier handler, or the default action on the retry.
    if (previous.handler > 1) {
        const f: *const fn (i32, ?*anyopaque, ?*anyopaque) callconv(.c) void = @ptrFromInt(previous.handler);
        return f(sig, info, context);
    }
    _ = syscalls.raw6(13, sigsegv, @intFromPtr(&previous), 0, @sizeOf(u64), 0, 0);
}

fn install() bool {
    if (installed.load(.acquire)) return true;
    const act: syscalls.KernelSigaction = .{
        .handler = @intFromPtr(&onSegv),
        .flags = 4 | 0x04000000 | 0x40000000, // SA_SIGINFO | SA_RESTORER | SA_NODEFER
        .restorer = @intFromPtr(&syscalls.restorer),
        .mask = 0,
    };
    if (@as(i64, @bitCast(syscalls.raw6(13, sigsegv, @intFromPtr(&act), @intFromPtr(&previous), @sizeOf(u64), 0, 0))) < 0) return false;
    installed.store(true, .release);
    return true;
}

/// A run starts: from here on the thread's counter reads return `now`'s
/// value. False where they cannot be trapped.
pub fn begin(now: *const u64) bool {
    if (!supported) return false;
    if (!install()) return false;
    if (@as(i64, @bitCast(syscalls.raw6(157, pr_set_tsc, pr_tsc_sigsegv, 0, 0, 0, 0))) < 0) return false;
    reads = 0;
    clock = now;
    return true;
}

/// The run ended: the counter is the machine's again. Returns how many
/// reads the run made.
pub fn end() u64 {
    if (!supported or clock == null) return 0;
    clock = null;
    _ = syscalls.raw6(157, pr_set_tsc, pr_tsc_enable, 0, 0, 0, 0);
    return reads;
}
