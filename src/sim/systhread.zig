//! Threads in system-call mode (plan §9.2, `plan3.md` D9): a `clone` that
//! starts a thread starts a simulated task instead.
//!
//! The simulation has one real thread and switches fibers on it. A thread
//! the code under test starts (`pthread_create`, `std.Thread.spawn`) is a
//! `clone` with a stack and a thread pointer of its own. Here that call
//! makes a task whose fiber begins where the child would have: at the
//! instruction after the `syscall`, with the parent's registers, `rax` 0,
//! the stack the caller gave, and the caller's thread pointer in `fs`. From
//! then on it is a task like any other. It runs until it makes a system
//! call (every emulated call is a point where the scheduler may switch),
//! its waits are the simulator's, and the scheduler's decisions are the
//! seed's.
//!
//! **The thread pointer.** Every task has run on one `fs` base until now.
//! A thread has its own (its `errno`, its `pthread_self`), and the
//! simulator's own thread-local state must still be found from inside a
//! signal handler that a thread's system call raised. So the handlers are
//! entered through a wrapper (`syscalls.Homed`) that looks the caller's
//! `fs` base up among the simulated threads' (a table of the process, not
//! of a thread), loads the simulator's if it is one of them, and puts the
//! caller's back on return. That needs the FSGSBASE instructions (a
//! processor from 2012 on, Linux 5.9); without them `clone` stays a stray
//! call.
//!
//! **The stack.** A thread's system calls are answered on the thread's own
//! stack: the signal frame, the emulator and the simulator's file and
//! network code all run there. A small thread stack (musl's default is
//! 128 KiB) leaves less room for that than a task's fiber stack does.
//!
//! **What a thread may do.** Make system calls. It may not call `env.io`
//! or anything else of the simulator directly: under its own thread
//! pointer the simulator's thread-local state is not there.
//!
//! **Threads switch only at system calls.** A thread that waits for another
//! by spinning on memory, with no system call in the loop, never lets the
//! other run: the run hangs, and nothing reports it. `sched_yield` in the
//! loop is enough. Data races between threads are not explored either: no
//! switch falls between two instructions.
//!
//! Emulated, beside `clone`: `exit` of a thread (with the wake of whoever
//! joins it, `CLONE_CHILD_CLEARTID`), `gettid`, `set_tid_address`,
//! `sched_yield`, `rt_sigprocmask` (a mask per task, kept and never
//! applied: a thread that blocks every signal on its way out would block
//! the trap's own), `sigaltstack` in a thread (accepted, changes nothing),
//! `set_robust_list` (accepted), `clone3` (`ENOSYS`, which libc takes as
//! an old kernel and falls back from), `rseq` (accepted, on processor 0:
//! see `rseq`), and a thread's `munmap` of
//! the stack it is running on, which is put off until it has left it, and
//! a signal a thread sends itself (`abort`), which is raised on the real
//! thread.
//!
//! Not emulated: `fork`, `vfork` and a `clone` that is not a thread
//! (stray); a signal sent to another thread (stray); thread-directed
//! anything else (affinity, priorities, names).

const std = @import("std");
const linux = std.os.linux;
const Sim = @import("Sim.zig");
const syscalls = @import("syscalls.zig");
const sysemu = @import("sysemu.zig");

const E = linux.E;

const threads_max = 64;
/// Thread numbers start here: above any the kernel gives (`pid_max` is at
/// most 2^22).
const tid_base: i32 = 0x3000_0000;

/// What `syscalls.enterUser` loads: the general registers as the signal
/// frame holds them (`gregs` 0 to 17), then the `fs` base.
pub const Entry = extern struct {
    gregs: [18]u64,
    fs: u64,
};

const reg_rax = 13;
const reg_rsp = 15;

const Thread = struct {
    used: bool = false,
    task: Sim.TaskId = 0,
    /// Its number: never given twice in a run.
    tid: i32 = 0,
    node: u16 = 0,
    /// Where to write 0, and wake, when the thread exits.
    clear_tid: u64 = 0,
    entry: Entry = undefined,
};

const Unmap = struct { address: u64, len: u64, task: Sim.TaskId, node: u16 };

threadlocal var threads: [threads_max]Thread = @splat(.{});
threadlocal var live: u32 = 0;
threadlocal var next_tid: i32 = tid_base;
/// Signal masks, by task: what `rt_sigprocmask` reads back.
threadlocal var masks: [256]u64 = @splat(0);
/// Stacks whose thread asked to unmap them while standing on them.
threadlocal var unmaps: [threads_max]Unmap = undefined;
threadlocal var unmaps_len: usize = 0;

/// A run begins: no thread, and every mask empty.
pub fn reset() void {
    flushUnmaps(null);
    for (&threads) |*t| if (t.used) syscalls.unregisterThreadBase(t.entry.fs);
    threads = @splat(.{});
    live = 0;
    next_tid = tid_base;
    masks = @splat(0);
    syscalls.setThreadCalls(false);
}

/// A node crashed (null: every node): its threads are gone with their
/// tasks. Their stacks stay mapped: they are the library's, which is gone
/// too.
pub fn dropNode(node: ?u16) void {
    for (&threads) |*t| {
        if (!t.used) continue;
        if (node) |n| if (t.node != n) continue;
        syscalls.unregisterThreadBase(t.entry.fs);
        t.used = false;
        live -= 1;
    }
    // A dropped thread's request to unmap its stack is dropped with it.
    var i: usize = 0;
    while (i < unmaps_len) {
        if (node == null or unmaps[i].node == node.?) {
            unmaps_len -= 1;
            unmaps[i] = unmaps[unmaps_len];
        } else i += 1;
    }
    if (live == 0) syscalls.setThreadCalls(false);
}

fn fail(e: E) u64 {
    return @bitCast(-@as(i64, @backingInt(e)));
}

fn threadOf(task: Sim.TaskId) ?*Thread {
    if (live == 0) return null;
    for (&threads) |*t| {
        if (t.used and t.task == task) return t;
    }
    return null;
}

fn tidOf(t: *const Thread) i32 {
    return t.tid;
}

/// Unmaps the stacks put off, but not one whose thread (`running`) is
/// still on it.
fn flushUnmaps(running: ?Sim.TaskId) void {
    var i: usize = 0;
    while (i < unmaps_len) {
        const u = unmaps[i];
        if (running != null and u.task == running.?) {
            i += 1;
            continue;
        }
        _ = syscalls.raw6(11, u.address, u.len, 0, 0, 0, 0);
        unmaps_len -= 1;
        unmaps[i] = unmaps[unmaps_len];
    }
}

/// Entry point from `sysemu.emulate`: the value for `rax`, or null for a
/// call that is not emulated here (which, for a call the harness makes
/// too, means it is made for real).
pub fn emulate(s: *Sim, number: u64, a: *const [6]u64) ?u64 {
    return switch (number) {
        56 => clone(s, a),
        435 => fail(.NOSYS), // clone3: libc falls back to clone
        // Only a simulated thread's: on the thread the run began on,
        // libc registered with the kernel before the run, and a program
        // that registers by itself is told there is no such call.
        334 => if (threadOf(s.current) == null) fail(.NOSYS) else rseq(a[0], a[1], a[2]),
        273 => 0, // set_robust_list
        24 => blk: { // sched_yield
            s.yieldNow();
            break :blk 0;
        },
        14 => sigprocmask(s, @truncate(a[0]), a[1], a[2], a[3]),
        60 => exit(s),
        186 => if (threadOf(s.current)) |t| @intCast(tidOf(t)) else null,
        218 => if (threadOf(s.current)) |t| blk: {
            t.clear_tid = a[0];
            break :blk @intCast(tidOf(t));
        } else null,
        131 => if (threadOf(s.current) != null) blk: {
            // The old one: none.
            if (a[1] != 0) @as(*align(1) [3]u64, @ptrFromInt(a[1])).* = .{ 0, 2, 0 }; // SS_DISABLE
            break :blk 0;
        } else null,
        11 => munmap(s, a[0], a[1]),
        200 => kill(s, number, @bitCast(@as(u32, @truncate(a[0]))), a[1]), // tkill
        234 => kill(s, number, @bitCast(@as(u32, @truncate(a[1]))), a[2]), // tgkill
        else => null,
    };
}

const clone_vm = 0x100;
const clone_thread = 0x10000;
const clone_settls = 0x80000;
const clone_parent_settid = 0x100000;
const clone_child_cleartid = 0x200000;
const clone_child_settid = 0x1000000;

fn clone(s: *Sim, a: *const [6]u64) ?u64 {
    const flags = a[0];
    const stack = a[1];
    // A thread, with a stack and a thread pointer of its own. Anything
    // else (`fork`, `vfork`, a new process) is not emulated.
    const needed = clone_vm | clone_thread | clone_settls;
    if (flags & needed != needed or stack == 0) return null;
    if (!syscalls.homing()) return null;
    const frame = syscalls.frame() orelse return null;
    flushUnmaps(s.current);
    const t = for (&threads) |*t| {
        if (!t.used) break t;
    } else return fail(.AGAIN);
    t.* = .{ .used = true, .node = s.currentNode(), .tid = next_tid };
    next_tid += 1;
    @memcpy(&t.entry.gregs, frame[0..18]);
    t.entry.gregs[reg_rax] = 0;
    t.entry.gregs[reg_rsp] = stack;
    t.entry.fs = a[4];
    if (!syscalls.registerThreadBase(t.entry.fs)) {
        t.used = false;
        return fail(.AGAIN);
    }
    const index: u32 = @intCast((@intFromPtr(t) - @intFromPtr(&threads)) / @sizeOf(Thread));
    const task = s.spawnThread(start, std.mem.asBytes(&index)) orelse {
        syscalls.unregisterThreadBase(t.entry.fs);
        t.used = false;
        return fail(.AGAIN);
    };
    t.task = task;
    if (task < masks.len and s.current < masks.len) masks[task] = masks[s.current];
    live += 1;
    syscalls.setThreadCalls(true);
    const tid = tidOf(t);
    if (flags & clone_parent_settid != 0 and a[2] != 0) @as(*align(1) i32, @ptrFromInt(a[2])).* = tid;
    if (flags & clone_child_settid != 0 and a[3] != 0) @as(*align(1) i32, @ptrFromInt(a[3])).* = tid;
    if (flags & clone_child_cleartid != 0) t.clear_tid = a[3];
    // The child may run first, as on a real machine.
    s.yieldPoint();
    return @intCast(tid);
}

/// The new task's first and only function: it becomes the thread.
fn start(context: *const anyopaque) void {
    const index = @as(*align(1) const u32, @ptrCast(context)).*;
    syscalls.enterUser(&threads[index].entry);
}

/// `exit` of a thread: its task ends. Of anything else: not ours.
fn exit(s: *Sim) ?u64 {
    const t = threadOf(s.current) orelse return null;
    const clear = t.clear_tid;
    syscalls.unregisterThreadBase(t.entry.fs);
    // The task's number is given to a later task: not the mask with it.
    if (s.current < masks.len) masks[s.current] = 0;
    t.used = false;
    live -= 1;
    if (live == 0) syscalls.setThreadCalls(false);
    s.exitThread(if (clear != 0) @ptrFromInt(clear) else null);
}

/// `rseq`, which glibc makes in every thread it starts and takes no
/// refusal of: when the thread the program began on was registered, a
/// thread whose registration fails aborts the process ("rseq registration
/// failed"). So the registration is accepted and never given to the
/// kernel, whose one registration for the real thread stands. The area is
/// filled as the kernel fills it, with processor 0, which is where
/// `sched_getcpu` then says every simulated thread runs. The kernel
/// restarts a registered critical section when its thread is preempted or
/// moved; here no other simulated thread runs until this one makes a
/// system call, which no critical section contains, so none needs
/// restarting. Laxer than the kernel, which also checks the area's
/// alignment, its length (32 bytes or more) and the signature. On the
/// thread a run began on, glibc's `sched_getcpu` reads the area the kernel
/// keeps, and says the machine's processor: that one answer is not the
/// simulation's.
fn rseq(area: u64, len: u64, flags: u64) u64 {
    if (flags & 1 != 0) return 0; // RSEQ_FLAG_UNREGISTER
    if (area == 0) return fail(.FAULT);
    if (len < 20) return fail(.INVAL);
    const words: [*]align(1) u32 = @ptrFromInt(area);
    words[0] = 0; // cpu_id_start
    words[1] = 0; // cpu_id
    if (len >= 28) {
        words[5] = 0; // node_id
        words[6] = 0; // mm_cid
    }
    return 0;
}

/// A signal to a simulated thread. To itself (`abort`, `raise`): raised
/// on the real thread it runs on, where the default action takes it, or
/// nothing does if the program ignores it. A handler the program
/// installed for it would run inside this call, with the simulator's
/// thread pointer and its system calls not trapped: a caught signal a
/// thread sends itself is not emulated, and fails the run. To another:
/// not emulated either. To a number that is not a simulated thread's: not
/// ours.
fn kill(s: *Sim, number: u64, tid: i32, signal: u64) ?u64 {
    // Not a simulated thread's number (the thread the run began on has
    // its real one): the kernel's to answer.
    if (tid < tid_base) return null;
    const target = for (&threads) |*t| {
        if (t.used and t.tid == tid) break t;
    } else return fail(.SRCH);
    if (target.task != s.current) {
        // Not emulated, and not to be dropped in silence (`pthread_kill`,
        // `pthread_cancel`): the run fails.
        syscalls.noteStray(number);
        return fail(.NOSYS);
    }
    if (signal != 0) {
        // The kernel's `struct sigaction`: the handler first. 0 is the
        // default action and 1 is to ignore.
        var action: [4]u64 = @splat(0);
        const rc: i64 = @bitCast(syscalls.raw6(13, signal, 0, @intFromPtr(&action), @sizeOf(u64), 0, 0)); // rt_sigaction
        if (rc == 0 and action[0] > 1) {
            syscalls.noteStray(number);
            return fail(.NOSYS);
        }
    }
    const pid = syscalls.raw6(39, 0, 0, 0, 0, 0, 0); // getpid
    const real = syscalls.raw6(186, 0, 0, 0, 0, 0, 0); // gettid
    return syscalls.raw6(234, pid, real, signal, 0, 0, 0);
}

/// A thread's `munmap` of the stack it stands on (a detached thread frees
/// its own stack, then exits, in two system calls with nothing between
/// them): put off until the thread has gone.
fn munmap(s: *Sim, address: u64, len: u64) ?u64 {
    _ = threadOf(s.current) orelse return null;
    const frame = syscalls.frame() orelse return null;
    const sp = frame[reg_rsp];
    if (sp < address or sp >= address +| len) return null;
    if (unmaps_len == unmaps.len) return null;
    unmaps[unmaps_len] = .{ .address = address, .len = len, .task = s.current, .node = s.currentNode() };
    unmaps_len += 1;
    return 0;
}

/// `rt_sigprocmask`: the task's own mask, read and written, never given
/// to the kernel.
fn sigprocmask(s: *Sim, how: u32, set_ptr: u64, old_ptr: u64, size: u64) u64 {
    if (size != 8) return fail(.INVAL);
    const none: u64 = 0;
    const mask: *u64 = if (s.current < masks.len) &masks[s.current] else @constCast(&none);
    const old = mask.*;
    if (set_ptr != 0 and s.current < masks.len) {
        const set = @as(*align(1) const u64, @ptrFromInt(set_ptr)).*;
        switch (how) {
            0 => mask.* |= set, // SIG_BLOCK
            1 => mask.* &= ~set, // SIG_UNBLOCK
            2 => mask.* = set, // SIG_SETMASK
            else => return fail(.INVAL),
        }
    }
    if (old_ptr != 0) @as(*align(1) u64, @ptrFromInt(old_ptr)).* = old;
    return 0;
}

comptime {
    _ = sysemu;
}
