//! Clock reads through the vDSO, in system-call mode (plan §9.2).
//!
//! `clock_gettime`, `gettimeofday`, `time`, `clock_getres` and `getcpu`
//! are answered by the kernel in user space: libc calls code the kernel
//! maps into every process (the vDSO), with no system call, so the trap
//! in `syscalls.zig` never sees them and a C library's timestamps were
//! the host's.
//!
//! While a system-call-mode run is on, the vDSO's code is made
//! inaccessible (`mprotect`, `PROT_NONE`). A call into it faults at the
//! function's first instruction; the SIGSEGV handler (`tsc.zig`'s, which
//! offers every fault here first) finds which function it was by its
//! address, answers it as the matching system call would be answered
//! (from the simulator for the code under test, from the kernel for the
//! harness and for other threads), and returns to the caller as the
//! function's `ret` would. When the run ends the code is readable and
//! executable again.
//!
//! The protection is the process's, so another thread calling the vDSO
//! during a run faults too, and is answered by the real system call: it
//! sees the right time, only more slowly. A thread that was inside the
//! vDSO when the protection began faults in the middle of a function;
//! then the protection is lifted for the rest of the run (`lifted`), and
//! the run's later vDSO reads are the host's again, which `end` reports
//! (the run fails with `StraySyscall`). The same for a read of the image
//! itself: the symbol lookups of Zig and of libc are made before the
//! protection begins, so that does not come from them.
//!
//! Linux on x86_64 only.

const std = @import("std");
const builtin = @import("builtin");
const syscalls = @import("syscalls.zig");

pub const supported = builtin.os.tag == .linux and builtin.cpu.arch == .x86_64;

const linux = std.os.linux;

const Entry = struct { address: usize, number: u64 };

/// The functions, by the system call each stands for.
const names = [_]struct { []const u8, u64 }{
    .{ "__vdso_clock_gettime", 228 },
    .{ "__vdso_gettimeofday", 96 },
    .{ "__vdso_time", 201 },
    .{ "__vdso_clock_getres", 229 },
    .{ "__vdso_getcpu", 309 },
    // glibc 2.41 and later, on Linux 6.11 and later.
    .{ "__vdso_getrandom", 318 },
};

var entries: [names.len]Entry = undefined;
var entries_len: usize = 0;
/// The vDSO's code: page-aligned start and length. Zero: none found.
var text_start: usize = 0;
var text_len: usize = 0;
/// 0: not looked up, 1: being looked up, 2: done.
var looked_up: std.atomic.Value(u8) = .init(0);
/// Runs that want the protection on. The first protects, the last lifts.
var users: std.atomic.Value(u32) = .init(0);
var protect_lock: std.atomic.Value(bool) = .init(false);
/// The process has a vDSO, whether or not its functions were found.
var image_present = false;
/// The protection was lifted early during a run (see the file comment).
var lifted: std.atomic.Value(bool) = .init(false);
/// The image is protected right now.
var protected_now: std.atomic.Value(bool) = .init(false);

const prot_none = 0;
const prot_read_exec = 1 | 4;
const page = 4096;

fn lookUp() void {
    while (true) {
        switch (looked_up.cmpxchgStrong(0, 1, .acquire, .acquire) orelse break) {
            2 => return,
            else => std.atomic.spinLoopHint(),
        }
    }
    defer looked_up.store(2, .release);
    // From libc where there is one: without Zig's startup code,
    // `std.os.linux.getauxval` has no vector to read, and finds nothing.
    const image: usize = if (builtin.link_libc) std.c.getauxval(std.elf.AT.SYSINFO_EHDR) else linux.getauxval(std.elf.AT.SYSINFO_EHDR);
    if (image == 0) return;
    image_present = true;
    const elf = std.elf;
    const eh: *const elf.Ehdr = @ptrFromInt(image);
    // The image's extent, and the address its symbols are relative to
    // (`std.os.linux.vdso.lookup` does the same; its `lookup` is not
    // public, and the functions are found by name alone here: the
    // `__vdso_` names are unique).
    var base: usize = std.math.maxInt(usize);
    var low: usize = std.math.maxInt(usize);
    var high: usize = 0;
    var maybe_dynv: ?[*]const usize = null;
    var ph_addr = image + eh.e_phoff;
    for (0..eh.e_phnum) |_| {
        const ph: *const elf.ElfN.Phdr = @ptrFromInt(ph_addr);
        switch (ph.type) {
            .LOAD => {
                base = image +% ph.offset -% ph.vaddr;
                low = @min(low, ph.vaddr);
                high = @max(high, ph.vaddr +% ph.memsz);
            },
            .DYNAMIC => maybe_dynv = @ptrFromInt(image + ph.offset),
            else => {},
        }
        ph_addr += eh.e_phentsize;
    }
    const dynv = maybe_dynv orelse return;
    if (base == std.math.maxInt(usize) or high <= low) return;
    var maybe_strings: ?[*:0]const u8 = null;
    var maybe_syms: ?[*]const elf.Sym = null;
    var maybe_hash: ?[*]const linux.Elf_Symndx = null;
    var i: usize = 0;
    while (dynv[i] != 0) : (i += 2) {
        const p = base +% dynv[i + 1];
        switch (dynv[i]) {
            elf.DT_STRTAB => maybe_strings = @ptrFromInt(p),
            elf.DT_SYMTAB => maybe_syms = @ptrFromInt(p),
            elf.DT_HASH => maybe_hash = @ptrFromInt(p),
            else => {},
        }
    }
    const strings = maybe_strings orelse return;
    const syms = maybe_syms orelse return;
    const hash = maybe_hash orelse return;
    for (names) |n| {
        for (0..hash[1]) |k| {
            if (syms[k].st_shndx == 0 or syms[k].st_info & 0xf != elf.STT_FUNC) continue;
            if (!std.mem.eql(u8, n[0], std.mem.sliceTo(strings + syms[k].st_name, 0))) continue;
            entries[entries_len] = .{ .address = base +% syms[k].st_value, .number = n[1] };
            entries_len += 1;
            break;
        }
    }
    text_start = image;
    text_len = std.mem.alignForward(usize, high - low, page);
}

fn lock() void {
    while (protect_lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
}

fn unlock() void {
    protect_lock.store(false, .release);
}

fn mprotect(prot: u64) bool {
    return @as(i64, @bitCast(syscalls.raw6(10, text_start, text_len, prot, 0, 0, 0))) == 0;
}

/// The process has a vDSO: if a run could not protect it, clock reads
/// through it are the host's.
pub fn present() bool {
    if (!supported) return false;
    lookUp();
    return image_present;
}

/// A system-call-mode run starts. False if there is no vDSO to protect
/// (its calls then were never the host's to begin with), or it could not
/// be protected (`present` tells the two apart).
pub fn begin() bool {
    if (!supported) return false;
    lookUp();
    if (text_len == 0) return false;
    // Zig's and libc's own lookups read the vDSO's headers the first time
    // a clock is read, which faults once the image is protected: make
    // them now.
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    if (builtin.link_libc) _ = std.c.clock_gettime(.MONOTONIC, &ts);
    lock();
    defer unlock();
    if (users.load(.monotonic) == 0) {
        lifted.store(false, .monotonic);
        if (!mprotect(prot_none)) return false;
        protected_now.store(true, .release);
    }
    _ = users.fetchAdd(1, .monotonic);
    return true;
}

/// The run ended. True if the protection had to be lifted during it, so
/// some of its vDSO reads may have been the host's.
pub fn end() bool {
    if (!supported or text_len == 0) return false;
    lock();
    defer unlock();
    const was_lifted = lifted.load(.monotonic);
    if (users.fetchSub(1, .monotonic) == 1 and !was_lifted) {
        protected_now.store(false, .release);
        _ = mprotect(prot_read_exec);
    }
    return was_lifted;
}

/// The image is readable and executable again until the last run using
/// it ends, which reports it.
fn liftNow() void {
    lock();
    defer unlock();
    lifted.store(true, .monotonic);
    protected_now.store(false, .release);
    _ = mprotect(prot_read_exec);
}

const reg_r8 = 0;
const reg_rcx = 14;
const reg_err = 19;
const reg_rdi = 8;
const reg_rsi = 9;
const reg_rdx = 12;
const reg_rax = 13;
const reg_rsp = 15;
const reg_rip = 16;

/// Offered every SIGSEGV first (`tsc.zig`). True if it was a call into
/// the protected vDSO, answered.
pub fn onFault(fault_address: usize, gregs: [*]u64) bool {
    if (!supported or text_len == 0) return false;
    // Only a fault on the image itself is ours: a bad pointer passed to a
    // vDSO function faults elsewhere, and is the program's own crash.
    if (fault_address < text_start or fault_address >= text_start + text_len) return false;
    // A write to the image: never allowed, protected or not.
    if (gregs[reg_err] & 2 != 0) return false;
    // The protection ended while this fault was on its way: run the
    // instruction again, on a readable and executable image.
    if (!protected_now.load(.acquire)) return true;
    const ip = gregs[reg_rip];
    if (ip != fault_address) {
        // A read of the image (a symbol lookup `begin` did not make in
        // advance): lift the protection, as for a call caught midway.
        liftNow();
        return true;
    }
    const number = for (entries[0..entries_len]) |e| {
        if (e.address == ip) break e.number;
    } else {
        // In the middle of a function (a thread was inside when the
        // protection began), or a function this does not answer. Lift
        // it, and let the instruction run again.
        liftNow();
        return true;
    };
    const args: [6]u64 = .{ gregs[reg_rdi], gregs[reg_rsi], gregs[reg_rdx], gregs[reg_rcx], gregs[reg_r8], 0 };
    gregs[reg_rax] = if (number == 318 and args[4] == std.math.maxInt(u64))
        // glibc asking how to keep `getrandom` state in user space: no
        // such state here, and it falls back to the system call.
        @bitCast(-@as(i64, @backingInt(linux.E.NOSYS)))
    else
        syscalls.answerFromVdso(number, &args);
    // Return to the caller, as the function's `ret` would.
    const sp = gregs[reg_rsp];
    gregs[reg_rip] = @as(*const u64, @ptrFromInt(sp)).*;
    gregs[reg_rsp] = sp + 8;
    return true;
}
