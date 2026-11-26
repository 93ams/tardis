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
//! not see it either, but system-call mode answers it, `vdso.zig`); the
//! simulator does not.
//!
//! The same handler answers calls into the vDSO while system-call mode
//! has it protected (`vdso.zig`): it offers every fault there first.
//!
//! The handler runs on the stack of the task that faulted, like Zig's own
//! crash handler: a fault caused by a stack overflow is not reported by
//! either. `tardis.sim`'s loop form does not arm it (`check` does).
//!
//! Elsewhere `supported` is false and nothing is trapped.

const std = @import("std");
const builtin = @import("builtin");
const syscalls = @import("syscalls.zig");
const vdso = @import("vdso.zig");
const crash = @import("crash.zig");

pub const supported = builtin.os.tag == .linux and builtin.cpu.arch == .x86_64;

const pr_set_tsc = 26;
const pr_tsc_enable = 1;
const pr_tsc_sigsegv = 2;
const sigsegv = 11;

/// The run's virtual clock, while the thread traps.
threadlocal var clock: ?*const u64 = null;
threadlocal var reads: u64 = 0;

/// 0: not installed, 1: a thread is installing, 2: installed.
var installed: std.atomic.Value(u8) = .init(0);
/// Set while the handler reads the faulting instruction: a fault there
/// is not ours either.
threadlocal var reading = false;
/// `si_code` of a fault the kernel raised for a privileged instruction
/// (a general protection fault), which is what a trapped `rdtsc` is. A
/// jump to unmapped memory has another code, and its instruction pointer
/// cannot be read.
const si_kernel = 0x80;
/// The SIGSEGV action in place before ours.
var previous: syscalls.KernelSigaction = undefined;

const gregs_offset = 8 + 8 + 24;
const reg_rdx = 12;
const reg_rax = 13;
const reg_rcx = 14;
const reg_rip = 16;

fn onSegv(sig: i32, info: ?*anyopaque, context: ?*anyopaque) callconv(.c) void {
    const gregs: [*]u64 = @ptrFromInt(@intFromPtr(context.?) + gregs_offset);
    // `siginfo_t` starts with `si_signo`, `si_errno`, `si_code`.
    const code = @as(*const [3]i32, @ptrCast(@alignCast(info.?)))[2];
    // A call into the protected vDSO (system-call mode, `vdso.zig`).
    const fault_address = @as(*const usize, @ptrFromInt(@intFromPtr(info.?) + 16)).*; // si_addr
    if (!reading and vdso.onFault(fault_address, gregs)) return;
    if (clock != null and code == si_kernel and !reading) {
        const now = clock.?;
        // A general protection fault can also come from a jump to a
        // non-canonical address: reading it faults again, and `reading`
        // sends that second fault on.
        reading = true;
        const ip: [*]const u8 = @ptrFromInt(gregs[reg_rip]);
        // `rdtsc` is 0F 31, `rdtscp` 0F 01 F9.
        const len: u64 = if (ip[0] == 0x0f and ip[1] == 0x31) 2 else if (ip[0] == 0x0f and ip[1] == 0x01 and ip[2] == 0xf9) 3 else 0;
        reading = false;
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
    reading = false;
    // Not ours: the earlier handler, or the default action on the retry.
    if (previous.handler > 1) {
        const f: *const fn (i32, ?*anyopaque, ?*anyopaque) callconv(.c) void = @ptrFromInt(previous.handler);
        return f(sig, info, context);
    }
    _ = syscalls.raw6(13, sigsegv, @intFromPtr(&previous), 0, @sizeOf(u64), 0, 0);
}

/// Installs the SIGSEGV handler (shared with `vdso.zig`).
pub fn install() bool {
    // One thread installs; the others wait for it, so `previous` is
    // written once and is never this handler.
    while (true) {
        switch (installed.cmpxchgStrong(0, 1, .acquire, .acquire) orelse break) {
            2 => return true,
            else => std.atomic.spinLoopHint(),
        }
    }
    // The crash report's handler goes in before this one, so this one
    // answers its own faults first and passes it only the others.
    crash.install();
    // The handler before this one, first: if it runs on an alternate
    // signal stack (to report a stack overflow), so does this one, and a
    // fault that is not ours reaches it on that stack.
    if (@as(i64, @bitCast(syscalls.raw6(13, sigsegv, 0, @intFromPtr(&previous), @sizeOf(u64), 0, 0))) < 0) {
        installed.store(0, .release);
        return false;
    }
    const sa_onstack = 0x08000000;
    const act: syscalls.KernelSigaction = .{
        .handler = syscalls.handlerAddress(&onSegv),
        .flags = (4 | 0x04000000 | 0x40000000) | (previous.flags & sa_onstack), // SA_SIGINFO | SA_RESTORER | SA_NODEFER
        .restorer = @intFromPtr(&syscalls.restorer),
        .mask = 0,
    };
    if (@as(i64, @bitCast(syscalls.raw6(13, sigsegv, @intFromPtr(&act), @intFromPtr(&previous), @sizeOf(u64), 0, 0))) < 0) {
        installed.store(0, .release);
        return false;
    }
    installed.store(2, .release);
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
