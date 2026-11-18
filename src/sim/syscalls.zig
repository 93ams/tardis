//! Stray system calls (plan §9 M6): code under test that asks the real
//! kernel for something (the time, random bytes, a file, a socket) has
//! left the simulation, and its run no longer depends on the seed alone.
//!
//! Linux on x86_64 only, through syscall user dispatch (Linux 5.11): while
//! a run is on, every system call the thread makes raises SIGSYS instead of
//! entering the kernel. The handler notes the call if it is not one the
//! simulator and the test harness make themselves (memory, writes to the
//! terminal, futexes, signals, exiting), then makes the call for the
//! thread, so the program goes on as it would have. `end` says which call
//! was the first stray one.
//!
//! The handler returns through its own two-instruction restorer, which the
//! kernel is told to let through, so the thread is back to "blocked" before
//! it runs another instruction of the program.
//!
//! What it does not see: calls the kernel answers in user space through the
//! vDSO (`clock_gettime`, `gettimeofday`, `getcpu`) are not system calls,
//! and `rdtsc` is an instruction (`tsc.zig` answers that one). Other
//! threads are not trapped.
//!
//! Elsewhere `supported` is false and nothing is trapped.

const std = @import("std");
const builtin = @import("builtin");

pub const supported = builtin.os.tag == .linux and builtin.cpu.arch == .x86_64;

const linux = std.os.linux;

const allow: u8 = 0;
const block: u8 = 1;

threadlocal var selector: u8 = allow;
threadlocal var armed = false;
threadlocal var stray_count: u32 = 0;
threadlocal var stray_first: u64 = 0;
var handler_installed: std.atomic.Value(bool) = .init(false);

/// The calls a run makes without leaving the simulation, by x86_64 number.
fn expected(number: u64, arg0: u64) bool {
    return switch (number) {
        // Memory: allocators, fiber stacks, guard pages.
        9, 10, 11, 12, 25, 28 => true, // mmap, mprotect, munmap, brk, mremap, madvise
        // Reports and test output, to the terminal only.
        1, 20 => arg0 == 1 or arg0 == 2, // write, writev
        // Locks inside the harness.
        202 => true, // futex
        // Signals, and the ways out of the process.
        13, 14, 15, 131 => true, // rt_sigaction, rt_sigprocmask, rt_sigreturn, sigaltstack
        60, 231, 62, 234, 186, 39 => true, // exit, exit_group, kill, tgkill, gettid, getpid
        157 => true, // prctl (turning the trap off)
        else => false,
    };
}

pub fn raw6(number: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) u64 {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> u64),
        : [number] "{rax}" (number),
          [a] "{rdi}" (a),
          [b] "{rsi}" (b),
          [c] "{rdx}" (c),
          [d] "{r10}" (d),
          [e] "{r8}" (e),
          [f] "{r9}" (f),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

/// `rt_sigreturn`, from an address the kernel lets through.
pub fn restorer() callconv(.naked) noreturn {
    asm volatile (
        \\movl $15, %%eax
        \\syscall
    );
}
/// Its seven bytes and one more: the kernel compares the address after
/// the `syscall` instruction, which is the restorer's end.
const restorer_bytes = 8;

/// The general registers in the signal frame (x86_64 `ucontext_t`:
/// `uc_flags`, `uc_link`, `uc_stack`, then `gregs`).
const gregs_offset = 8 + 8 + 24;
const Reg = enum(usize) { r8 = 0, r9 = 1, r10 = 2, rdi = 8, rsi = 9, rdx = 12, rax = 13 };

fn onSigsys(_: i32, _: ?*anyopaque, context: ?*anyopaque) callconv(.c) void {
    selector = allow;
    const gregs: [*]u64 = @ptrFromInt(@intFromPtr(context.?) + gregs_offset);
    const number = gregs[@backingInt(Reg.rax)];
    const a = gregs[@backingInt(Reg.rdi)];
    if (!expected(number, a)) {
        if (stray_count == 0) stray_first = number;
        stray_count +|= 1;
    }
    // Make the call for the thread: it sees what it would have seen.
    gregs[@backingInt(Reg.rax)] = raw6(
        number,
        a,
        gregs[@backingInt(Reg.rsi)],
        gregs[@backingInt(Reg.rdx)],
        gregs[@backingInt(Reg.r10)],
        gregs[@backingInt(Reg.r8)],
        gregs[@backingInt(Reg.r9)],
    );
    selector = block;
}

pub const KernelSigaction = extern struct {
    handler: usize,
    flags: u64,
    restorer: usize,
    mask: u64,
};

const pr_set_syscall_user_dispatch = 59;

/// Makes the thread ready to trap. False if the kernel cannot.
fn arm() bool {
    if (armed) return true;
    if (!handler_installed.load(.acquire)) {
        const act: KernelSigaction = .{
            .handler = @intFromPtr(&onSigsys),
            .flags = 4 | 0x04000000, // SA_SIGINFO | SA_RESTORER
            .restorer = @intFromPtr(&restorer),
            .mask = 0,
        };
        if (@as(i64, @bitCast(raw6(13, 31, @intFromPtr(&act), 0, @sizeOf(u64), 0, 0))) < 0) return false; // rt_sigaction(SIGSYS)
        handler_installed.store(true, .release);
    }
    const rc = raw6(157, pr_set_syscall_user_dispatch, 1, @intFromPtr(&restorer), restorer_bytes, @intFromPtr(&selector), 0);
    if (@as(i64, @bitCast(rc)) < 0) return false;
    armed = true;
    return true;
}

/// A run starts: from here on the thread's system calls are trapped.
/// False where they cannot be.
pub fn begin() bool {
    if (!supported) return false;
    if (!arm()) return false;
    stray_count = 0;
    stray_first = 0;
    @atomicStore(u8, &selector, block, .seq_cst);
    return true;
}

pub const Stray = struct { number: u64, count: u32 };

/// The run ended: the first system call that left the simulation, if any.
pub fn end() ?Stray {
    if (!supported or !armed) return null;
    @atomicStore(u8, &selector, allow, .seq_cst);
    if (stray_count == 0) return null;
    return .{ .number = stray_first, .count = stray_count };
}

/// The call's name on x86_64 Linux, for the ones a test is likely to hit.
pub fn name(number: u64) []const u8 {
    return switch (number) {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        8 => "lseek",
        17 => "pread64",
        18 => "pwrite64",
        35 => "nanosleep",
        41 => "socket",
        42 => "connect",
        56 => "clone",
        57 => "fork",
        59 => "execve",
        96 => "gettimeofday",
        201 => "time",
        228 => "clock_gettime",
        230 => "clock_nanosleep",
        257 => "openat",
        262 => "newfstatat",
        318 => "getrandom",
        332 => "statx",
        else => "a system call",
    };
}
