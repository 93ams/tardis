//! Stray system calls (plan §9 M6): code under test that asks the real
//! kernel for something (the time, random bytes, a file, a socket) has
//! left the simulation, and its run no longer depends on the seed alone.
//!
//! Linux on x86_64 only, through syscall user dispatch (Linux 5.11): while
//! a run is on, every system call the thread makes raises SIGSYS instead of
//! entering the kernel. The handler notes the call if it is not one the
//! simulator and the test harness make themselves (memory, writes to the
//! terminal, futexes, signals, exiting), then makes the call for the
//! thread, so the program goes on as it would have. Four calls it does not
//! make: one that starts a thread or a process (clone, clone3, fork,
//! vfork) is refused with EAGAIN, because the child would begin inside
//! the handler. `end` says which call was the first stray one and how
//! many were refused.
//!
//! The handler returns through its own two-instruction restorer, which the
//! kernel is told to let through, so the thread is back to "blocked" before
//! it runs another instruction of the program.
//!
//! In system-call mode (`Options.mode = .syscalls`, plan §9.2) the handler
//! first offers a call that is not the harness's own to an emulator
//! (`sysemu.zig`), which answers it from the simulator; only what the
//! emulator declines is stray. The emulator may switch fibers, so SIGSYS is
//! not blocked inside its handler (`SA_NODEFER`), and the selector byte
//! belongs to the fiber: `Sim.switchToTask` saves and restores it.
//!
//! What it does not see: calls the kernel answers in user space through the
//! vDSO (`clock_gettime`, `gettimeofday`, `getcpu`) are not system calls
//! (in system-call mode `vdso.zig` makes them fault and answers them,
//! through `answerFromVdso`), and `rdtsc` is an instruction (`tsc.zig`
//! answers that one). Other threads are not trapped.
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
/// Stray calls that were refused, not made (`startsThreadOrProcess`).
threadlocal var stray_refused: u32 = 0;
/// True between `begin` and `end`.
threadlocal var active = false;
threadlocal var emulator: ?Emulator = null;
/// The registers of the call being emulated (`frame`).
threadlocal var frame_regs: ?[*]u64 = null;
/// Threads made by `clone` exist (`systhread.zig`): some of the harness's
/// own calls are then offered to the emulator first.
threadlocal var thread_calls = false;
/// This thread's `fs` base. 0 until `arm`, and where the processor has no
/// FSGSBASE.
threadlocal var fs_home: usize = 0;

/// Answers a system call from the simulation: the value for `rax`, or
/// null for a call it does not emulate.
pub const Emulator = *const fn (number: u64, args: *const [6]u64) ?u64;
var handler_installed: std.atomic.Value(bool) = .init(false);

/// The calls a run makes without leaving the simulation, by x86_64 number.
fn expected(number: u64, arg0: u64) bool {
    return switch (number) {
        // Memory: allocators, fiber stacks, guard pages.
        9, 10, 11, 12, 25, 28 => true, // mmap, mprotect, munmap, brk, mremap, madvise
        // Reports and test output, to the terminal only.
        1, 20 => arg0 == 1 or arg0 == 2, // write, writev
        // What libc asks about the terminal before its first output
        // (glibc `fstat(1)`, musl `ioctl(1, TIOCGWINSZ)`): it reads, and
        // only about the standard descriptors.
        5, 16 => arg0 <= 2, // fstat, ioctl
        262 => arg0 <= 2, // newfstatat with AT_EMPTY_PATH on one of them
        // Locks inside the harness.
        202 => true, // futex
        // Signals, and the ways out of the process.
        13, 14, 15, 131 => true, // rt_sigaction, rt_sigprocmask, rt_sigreturn, sigaltstack
        60, 231, 62, 234, 186, 39 => true, // exit, exit_group, kill, tgkill, gettid, getpid
        157 => true, // prctl (turning the trap off)
        else => false,
    };
}

/// clone, fork, vfork, clone3: calls the trap refuses instead of making.
pub fn startsThreadOrProcess(number: u64) bool {
    return switch (number) {
        56, 57, 58, 435 => true,
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

/// The harness's own calls that system-call mode offers to the emulator
/// first. A futex is the code under test's lock, and a real wait would
/// stop every fiber (`sysemu.futex`). A signal mask is a task's, and one
/// given to the kernel could block the trap itself. With threads
/// (`systhread.zig`): a thread's exit, its number, its alternate stack and
/// the unmapping of its own stack, and a signal it sends itself.
fn emulatorFirst(number: u64) bool {
    return switch (number) {
        202, 14 => true,
        60, 186, 131, 11, 200, 234 => thread_calls,
        else => false,
    };
}

fn onSigsys(_: i32, _: ?*anyopaque, context: ?*anyopaque) callconv(.c) void {
    selector = allow;
    const gregs: [*]u64 = @ptrFromInt(@intFromPtr(context.?) + gregs_offset);
    const number = gregs[@backingInt(Reg.rax)];
    const a = gregs[@backingInt(Reg.rdi)];
    // A file mapping of a simulated descriptor (bit 30, `sysemu.zig`) is
    // not the allocator's `mmap`: the kernel has no such file.
    const maps_simulated = number == 9 and gregs[@backingInt(Reg.r10)] & 0x20 == 0 and // MAP_ANONYMOUS
        gregs[@backingInt(Reg.r8)] & 0xC000_0000 == 0x4000_0000;
    const first = emulator != null and emulatorFirst(number);
    stray: {
        if (!(maps_simulated or first or !expected(number, a))) break :stray;
        if (emulator) |emulate| {
            frame_regs = gregs;
            const args: [6]u64 = .{
                a,
                gregs[@backingInt(Reg.rsi)],
                gregs[@backingInt(Reg.rdx)],
                gregs[@backingInt(Reg.r10)],
                gregs[@backingInt(Reg.r8)],
                gregs[@backingInt(Reg.r9)],
            };
            // May switch fibers and come back much later, on this stack.
            if (emulate(number, &args)) |answer| {
                gregs[@backingInt(Reg.rax)] = answer;
                @atomicStore(u8, &selector, block, .seq_cst);
                return;
            }
            // One of the harness's own, which the emulator left alone (a
            // futex operation it does not know is a stray).
            if (first and number != 202 and !maps_simulated and expected(number, a)) break :stray;
        }
        if (stray_count == 0) stray_first = number;
        stray_count +|= 1;
        // With the emulator on, the code under test believes it has no
        // other world: a call it was not answered must not reach the real
        // one (a rename or a truncation of a host file). It fails as an
        // unimplemented call, and the run fails with `StraySyscall`.
        if (emulator != null) {
            gregs[@backingInt(Reg.rax)] = @bitCast(@as(i64, -@as(i64, @backingInt(linux.E.NOSYS))));
            @atomicStore(u8, &selector, block, .seq_cst);
            return;
        }
        // A new thread or process would begin its life inside this
        // handler, and nothing it did would be seen. The call is not made:
        // the caller is told to try again later, and the run fails.
        if (startsThreadOrProcess(number)) {
            stray_refused +|= 1;
            gregs[@backingInt(Reg.rax)] = @bitCast(@as(i64, -@as(i64, @backingInt(linux.E.AGAIN))));
            @atomicStore(u8, &selector, block, .seq_cst);
            return;
        }
    }
    // Make the call for the thread: it sees what it would have seen. (The
    // calls refused above never get here.)
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

/// A call the emulator answers with an error and counts as a stray: the
/// run fails with `StraySyscall`. For one that returning null would hand
/// to the kernel (`emulatorFirst`).
pub fn noteStray(number: u64) void {
    if (!supported) return;
    if (stray_count == 0) stray_first = number;
    stray_count +|= 1;
}

/// The registers of the system call being emulated, as the signal frame
/// holds them (x86_64 `gregs`). Valid until the emulator lets another
/// task run.
pub fn frame() ?[*]u64 {
    return frame_regs;
}

pub fn setThreadCalls(on: bool) void {
    thread_calls = on;
}

/// Whether threads can be emulated on this machine (FSGSBASE).
pub fn threadsAvailable() bool {
    return available() and baseCode() != 0;
}

/// Whether this thread's handlers find their way home from another thread
/// pointer: threads can be emulated.
pub fn homing() bool {
    return supported and fs_home != 0;
}

const Handler = fn (i32, ?*anyopaque, ?*anyopaque) callconv(.c) void;

/// Reading and writing the `fs` base: two routines of one instruction and
/// a `ret` each. The assembler of Zig's own backend has no
/// encoding for them, so they are bytes, copied to a page of their own at
/// first use.
const base_code_bytes = [_]u8{
    0xf3, 0x48, 0x0f, 0xae, 0xc0, 0xc3, 0x90, 0x90, // 0: rdfsbase %rax
    0xf3, 0x48, 0x0f, 0xae, 0xd7, 0xc3, 0x90, 0x90, // 8: wrfsbase %rdi
};
const read_fs = 0;
const write_fs = 8;

/// The thread pointers of the simulated threads alive in the process
/// (`systhread.zig`), each with the `fs` base of the real thread it runs
/// on. How a signal handler entered under a simulated thread's pointer
/// finds the simulator's thread-local state (`Homed`). The process's, and
/// not thread-local, for that reason. A base is 0 for a free place and 1
/// while one is being filled.
const thread_bases_max = 256;
var thread_bases: [thread_bases_max]std.atomic.Value(usize) = @splat(.init(0));
var thread_homes: [thread_bases_max]std.atomic.Value(usize) = @splat(.init(0));
var thread_bases_used: std.atomic.Value(u32) = .init(0);

/// A simulated thread with this `fs` base begins, on this real thread.
/// False when there is no room.
pub fn registerThreadBase(base: usize) bool {
    if (base <= 1 or fs_home == 0) return false;
    for (&thread_bases, &thread_homes) |*b, *h| {
        if (b.cmpxchgStrong(0, 1, .acq_rel, .acquire) != null) continue;
        h.store(fs_home, .release);
        b.store(base, .release);
        _ = thread_bases_used.fetchAdd(1, .acq_rel);
        return true;
    }
    return false;
}

/// It ended, or was dropped: it never runs again.
pub fn unregisterThreadBase(base: usize) void {
    if (base <= 1) return;
    for (&thread_bases) |*b| {
        if (b.cmpxchgStrong(base, 0, .acq_rel, .acquire) == null) {
            _ = thread_bases_used.fetchSub(1, .acq_rel);
            return;
        }
    }
}
/// 0: not tried. 1: this machine cannot. Else the page's address. The
/// process's, and read by handlers that cannot use thread-local state.
var base_code: std.atomic.Value(usize) = .init(0);

/// The page of `base_code_bytes`, or 0 where user code may not set the
/// bases (`HWCAP2_FSGSBASE`: a processor with FSGSBASE, Linux 5.9).
fn baseCode() usize {
    if (!supported) return 0;
    const known = base_code.load(.acquire);
    if (known != 0) return if (known == 1) 0 else known;
    var found: usize = 1;
    // AT_HWCAP2, from libc where there is one: without Zig's own startup
    // code, `std.os.linux.getauxval` has no vector to read.
    const hwcap2: usize = if (builtin.link_libc) std.c.getauxval(26) else linux.getauxval(26);
    if (hwcap2 & 2 != 0) {
        const page = raw6(9, 0, 4096, 3, 0x22, ~@as(u64, 0), 0); // mmap, read and write, private and anonymous
        if (@as(i64, @bitCast(page)) > 0) {
            @memcpy(@as([*]u8, @ptrFromInt(page))[0..base_code_bytes.len], &base_code_bytes);
            if (raw6(10, page, 4096, 5, 0, 0, 0) == 0) found = page else _ = raw6(11, page, 4096, 0, 0, 0, 0); // mprotect: read and execute
        }
    }
    if (base_code.cmpxchgStrong(0, found, .acq_rel, .acquire)) |other| {
        if (found != 1) _ = raw6(11, found, 4096, 0, 0, 0, 0);
        return if (other == 1) 0 else other;
    }
    return if (found == 1) 0 else found;
}

inline fn readBase(code: usize, comptime which: usize) usize {
    return @as(*const fn () callconv(.c) usize, @ptrFromInt(code + which))();
}

inline fn writeBase(code: usize, comptime which: usize, value: usize) void {
    @as(*const fn (usize) callconv(.c) void, @ptrFromInt(code + which))(value);
}

/// `handler`, entered with the simulator's thread pointer whatever the
/// interrupted code's was, which is put back on return. The handler may
/// switch fibers: the saved base is on the fiber's own stack. Nothing
/// here may touch thread-local state, and `handler` is not inlined into
/// it, so that none of its thread-local reads moves before the switch.
fn Homed(comptime handler: *const Handler) type {
    return struct {
        fn entry(sig: i32, info: ?*anyopaque, context: ?*anyopaque) callconv(.c) void {
            // No simulated thread anywhere: every thread pointer is its
            // real thread's own.
            if (thread_bases_used.load(.acquire) == 0) return @call(.never_inline, handler, .{ sig, info, context });
            const code = base_code.load(.acquire);
            const saved = readBase(code, read_fs);
            const home: usize = for (&thread_bases, &thread_homes) |*b, *h| {
                if (b.load(.acquire) == saved) break h.load(.acquire);
            } else 0;
            if (home == 0) return @call(.never_inline, handler, .{ sig, info, context });
            writeBase(code, write_fs, home);
            @call(.never_inline, handler, .{ sig, info, context });
            writeBase(code, write_fs, saved);
        }
    };
}

/// The address to install for `handler`: through `Homed` where the bases
/// can be set.
pub fn handlerAddress(comptime handler: *const Handler) usize {
    return if (baseCode() != 0) @intFromPtr(&Homed(handler).entry) else @intFromPtr(handler);
}

/// Becomes a thread: loads the registers of `entry` and its `fs` base, and
/// goes on at its instruction pointer with `rax` 0, as the child of a
/// `clone` does. `entry` is `systhread.Entry`. Only where `homing()`.
pub fn enterUser(entry: *const anyopaque) noreturn {
    if (!supported) unreachable;
    // From here on the thread pointer is the thread's: no thread-local
    // state is touched again.
    writeBase(base_code.load(.acquire), write_fs, @as(*align(1) const [19]u64, @ptrCast(entry))[18]);
    asm volatile (
        \\ movq 120(%%rdi), %%rsp
        \\ pushq 128(%%rdi)
        \\ movq 0(%%rdi), %%r8
        \\ movq 8(%%rdi), %%r9
        \\ movq 16(%%rdi), %%r10
        \\ movq 32(%%rdi), %%r12
        \\ movq 40(%%rdi), %%r13
        \\ movq 48(%%rdi), %%r14
        \\ movq 56(%%rdi), %%r15
        \\ movq 72(%%rdi), %%rsi
        \\ movq 80(%%rdi), %%rbp
        \\ movq 88(%%rdi), %%rbx
        \\ movq 96(%%rdi), %%rdx
        \\ movq 64(%%rdi), %%rdi
        \\ xorl %%eax, %%eax
        \\ retq
        :
        : [entry] "{rdi}" (entry),
    );
    unreachable;
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
            .handler = handlerAddress(&onSigsys),
            // SA_NODEFER: a fiber may be switched out inside the handler,
            // and the next fiber's calls must still trap.
            .flags = 4 | 0x04000000 | 0x40000000, // SA_SIGINFO | SA_RESTORER | SA_NODEFER
            .restorer = @intFromPtr(&restorer),
            .mask = 0,
        };
        if (@as(i64, @bitCast(raw6(13, 31, @intFromPtr(&act), 0, @sizeOf(u64), 0, 0))) < 0) return false; // rt_sigaction(SIGSYS)
        handler_installed.store(true, .release);
    }
    const rc = raw6(157, pr_set_syscall_user_dispatch, 1, @intFromPtr(&restorer), restorer_bytes, @intFromPtr(&selector), 0);
    if (@as(i64, @bitCast(rc)) < 0) return false;
    const code = baseCode();
    if (code != 0) fs_home = readBase(code, read_fs);
    armed = true;
    return true;
}

/// A run starts: from here on the thread's system calls are trapped.
/// False where they cannot be.
pub fn begin(emulate: ?Emulator) bool {
    if (!supported) return false;
    if (!arm()) return false;
    stray_count = 0;
    stray_first = 0;
    stray_refused = 0;
    emulator = emulate;
    active = true;
    @atomicStore(u8, &selector, block, .seq_cst);
    return true;
}

/// `count` stray calls, the first of them `number`; `refused` of them
/// would have started a thread or a process and were not made.
pub const Stray = struct { number: u64, count: u32, refused: u32 };

/// The run ended: the first system call that left the simulation, if any.
pub fn end() ?Stray {
    if (!supported or !armed) return null;
    @atomicStore(u8, &selector, allow, .seq_cst);
    active = false;
    emulator = null;
    if (stray_count == 0) return null;
    return .{ .number = stray_first, .count = stray_count, .refused = stray_refused };
}

/// A vDSO function the code under test called (`vdso.zig`): answered as
/// the system call it stands for would be. From the simulator when the
/// caller is the code under test of a system-call-mode run; otherwise
/// (the harness, another thread) from the kernel.
pub fn answerFromVdso(number: u64, args: *const [6]u64) u64 {
    const saved = selector;
    @atomicStore(u8, &selector, allow, .seq_cst);
    defer @atomicStore(u8, &selector, saved, .seq_cst);
    if (saved == block and active) if (emulator) |emulate| {
        if (number == 309) { // getcpu: processor 0, node 0, on every machine
            if (args[0] != 0) @as(*align(1) u32, @ptrFromInt(args[0])).* = 0;
            if (args[1] != 0) @as(*align(1) u32, @ptrFromInt(args[1])).* = 0;
            return 0;
        }
        if (emulate(number, args)) |answer| return answer;
        // Declined: stray, refused as one by system call would be.
        if (stray_count == 0) stray_first = number;
        stray_count +|= 1;
        return @bitCast(-@as(i64, @backingInt(linux.E.NOSYS)));
    };
    return raw6(number, args[0], args[1], args[2], 0, 0, 0);
}

/// Whether this thread can trap its system calls (the kernel has syscall
/// user dispatch).
pub fn available() bool {
    return supported and arm();
}

/// The selector is the running fiber's: one inside the handler runs the
/// simulator untrapped, one in the code under test is trapped. The
/// scheduler saves it before a switch and restores it after.
pub inline fn selectorSave() u8 {
    return if (supported) selector else allow;
}

pub inline fn selectorRestore(value: u8) void {
    if (supported) @atomicStore(u8, &selector, value, .seq_cst);
}

/// Whether a fiber parked with this selector is inside an emulated
/// system call (system-call mode): in the middle of whatever library made
/// it, which may hold that library's locks.
pub inline fn parkedInCall(saved: u8) bool {
    return supported and emulator != null and saved == allow;
}

/// The seed of a run that dropped a task inside an emulated system call,
/// if one has. The process's, as a C library's state is: it outlives runs.
pub var dropped_in_call_seed: ?u64 = null;

/// A new fiber starts in the code under test.
pub inline fn fiberEntry() void {
    if (supported and active) @atomicStore(u8, &selector, block, .seq_cst);
}

/// The call's name on x86_64 Linux, for the ones a test is likely to hit.
pub fn name(number: u64) []const u8 {
    return switch (number) {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        4 => "stat",
        5 => "fstat",
        7 => "poll",
        8 => "lseek",
        9 => "mmap",
        16 => "ioctl",
        19 => "readv",
        20 => "writev",
        21 => "access",
        22 => "pipe",
        23 => "select",
        213 => "epoll_create",
        232 => "epoll_wait",
        233 => "epoll_ctl",
        270 => "pselect6",
        281 => "epoll_pwait",
        284 => "eventfd",
        290 => "eventfd2",
        291 => "epoll_create1",
        425 => "io_uring_setup",
        441 => "epoll_pwait2",
        32 => "dup",
        72 => "fcntl",
        73 => "flock",
        79 => "getcwd",
        82 => "rename",
        87 => "unlink",
        217 => "getdents64",
        293 => "pipe2",
        17 => "pread64",
        18 => "pwrite64",
        35 => "nanosleep",
        41 => "socket",
        42 => "connect",
        24 => "sched_yield",
        56 => "clone",
        218 => "set_tid_address",
        273 => "set_robust_list",
        334 => "rseq",
        57 => "fork",
        58 => "vfork",
        435 => "clone3",
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
