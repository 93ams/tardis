//! The line a run that crashes leaves behind: which iteration, persona and
//! seed it was, and how to run it again.
//!
//! A panic or a fault in the code under test ends the process, and with it
//! the campaign, before the report of a failed run can be printed. So
//! `check` marks each run on the thread that runs it (`enter`, `leave`),
//! and a handler for the ways a process ends prints the marked run's lines
//! to standard error, then lets the process end as it would have:
//!
//! * Linux and macOS: the signals of a fault (`SIGSEGV`, `SIGBUS`,
//!   `SIGILL`, `SIGFPE`) and of an abort (`SIGABRT`, which a Zig panic
//!   raises once it has printed its message and stack). The handler that
//!   was there before is put back and runs next, so a fault's lines come
//!   before the stack the standard handler prints, and a panic's after it.
//! * Windows: a vectored exception handler for the faults (it runs first
//!   and passes each one on), and a TLS callback at process exit for a
//!   panic, which on Windows ends the process without an exception.
//!
//! The handlers are installed once per process, the first time a `check`
//! runs, and are never taken away: they print only while a run is marked
//! on the faulting thread, and otherwise pass the signal on at once.
//! Nothing here allocates or takes a lock: the lines are formatted on the
//! stack and written with one system call.

const std = @import("std");
const builtin = @import("builtin");
const decide = @import("decide.zig");
const syscalls = @import("syscalls.zig");
const shrink = @import("../search/shrink.zig");

const native_os = builtin.os.tag;
const posix_signals = native_os == .linux or native_os.isDarwin();

/// Whether a crash inside a run is reported on this platform.
pub const supported = posix_signals or native_os == .windows;

/// The run this thread is in, while it is in one.
pub const Run = struct {
    /// The campaign's iteration; null for a run that is not one (a shrink
    /// candidate, a replay, a run of the kept corpus, setup's priming).
    iteration: ?u32,
    persona: []const u8,
    seed: u64,
    /// The decisions it was told (a shrink candidate, guided exploration,
    /// a replay token): the seed alone does not bring it back.
    overlay: ?*const decide.Overlay,
};

threadlocal var current: ?Run = null;
/// One report per process: a fault whose handler ends in an abort is one
/// crash, not two.
var reported: std.atomic.Value(bool) = .init(false);

/// The command a replay line names (`TARDIS_REPLAY_COMMAND`); set before
/// the first run, read only by the handlers.
pub var replay_command: []const u8 = "zig build test";

/// This thread begins `run`.
pub fn enter(run: Run) void {
    current = run;
}

/// This thread's run is over.
pub fn leave() void {
    current = null;
}

/// The lines a crash of `run` prints, formatted into `buf`.
pub fn format(buf: []u8, run: Run, what: []const u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    write(&w, run, what) catch return w.buffered();
    return w.buffered();
}

fn write(w: *std.Io.Writer, run: Run, what: []const u8) std.Io.Writer.Error!void {
    if (run.iteration) |it| {
        try w.print("\ntardis: {s} in iteration {d}  persona={s}  seed=0x{x:0>16}\n", .{ what, it + 1, run.persona, run.seed });
    } else {
        try w.print("\ntardis: {s} in a run that is not a campaign iteration (shrinking, a replay, the kept corpus, setup)  persona={s}  seed=0x{x:0>16}\n", .{ what, run.persona, run.seed });
    }
    if (run.overlay) |o| {
        // One writer at a time (`reported`): a buffer of the process's own.
        if (shrink.formatToken(&token_buf, run.persona, run.seed, o.keep, o.forced)) |t| {
            try w.print("tardis: it ran with decisions the seed alone does not give (shrinking, guided exploration or a replay token); replay with:  TARDIS_REPLAY={s} {s}\n", .{ t, replay_command });
        } else {
            try w.print("tardis: it ran with decisions told (shrinking, guided exploration or a replay token), too many to print here; the seed alone may not bring it back\n", .{});
        }
        return;
    }
    try w.print("tardis: replay with:  TARDIS_SEED=0x{x:0>16} TARDIS_PERSONA={s} {s}\n", .{ run.seed, run.persona, replay_command });
}

/// As long as the longest token a shrink report holds.
const token_bytes_max = 16 * 1024;
var token_buf: [token_bytes_max]u8 = undefined;
var line_buf: [token_bytes_max + 1024]u8 = undefined;

/// Prints the marked run's lines, once per process.
fn report(what: []const u8) void {
    const run = current orelse return;
    if (reported.swap(true, .acq_rel)) return;
    writeStderr(format(&line_buf, run, what));
}

/// `report`, for a Windows exception: named by its code.
fn reportException(code: u32) void {
    var buf: [96]u8 = undefined;
    report(std.fmt.bufPrint(&buf, "crashed (exception 0x{x:0>8})", .{code}) catch "crashed (an exception)");
}

fn writeStderr(bytes: []const u8) void {
    if (native_os == .windows) {
        const windows = std.os.windows;
        const handle = windows.peb().ProcessParameters.hStdError;
        var iosb: windows.IO_STATUS_BLOCK = undefined;
        _ = windows.ntdll.NtWriteFile(handle, null, null, null, &iosb, bytes.ptr, @intCast(bytes.len), null, null);
        return;
    }
    var rest = bytes;
    while (rest.len > 0) {
        const n = std.posix.system.write(2, rest.ptr, rest.len);
        const signed: isize = if (@TypeOf(n) == usize) @bitCast(n) else n;
        if (signed <= 0) return;
        rest = rest[@intCast(signed)..];
    }
}

var install_state: std.atomic.Value(u8) = .init(0); // 0 not yet, 1 being installed, 2 done

/// Installs the handlers, once per process.
pub fn install() void {
    if (!supported) return;
    while (true) switch (install_state.load(.acquire)) {
        2 => return,
        1 => std.atomic.spinLoopHint(),
        else => if (install_state.cmpxchgStrong(0, 1, .acquire, .monotonic) == null) {
            if (posix_signals) installPosix() else installWindows();
            install_state.store(2, .release);
            return;
        },
    };
}

// ---------------------------------------------------------------------------
// Linux and macOS

const Sig = std.posix.SIG;
const fatal = [_]Sig{ .SEGV, .BUS, .ILL, .FPE, .ABRT };
var previous: [fatal.len]std.posix.Sigaction = undefined;

fn slot(sig: Sig) ?usize {
    for (fatal, 0..) |f, i| if (f == sig) return i;
    return null;
}

const SigactionFn = @FieldType(@FieldType(std.posix.Sigaction, "handler"), "sigaction");

fn installPosix() void {
    // Through `syscalls.handlerAddress` where system-call-mode threads may
    // have their own thread pointer: the run is found in this thread's
    // state whichever task faulted.
    const entry: SigactionFn = if (syscalls.supported) @ptrFromInt(syscalls.handlerAddress(&onSignalC)) else &onSignal;
    const act: std.posix.Sigaction = .{
        .handler = .{ .sigaction = entry },
        .mask = std.posix.sigemptyset(),
        // On the alternate stack where one is set up (a stack overflow);
        // not deferred: the simulator's own SIGSEGV handler, which this
        // one may pass a fault to, can switch fibers.
        .flags = std.posix.SA.SIGINFO | std.posix.SA.ONSTACK | std.posix.SA.NODEFER,
    };
    // The earlier actions first, so a fault on another thread meanwhile
    // finds them.
    for (fatal, 0..) |sig, i| std.posix.sigaction(sig, null, &previous[i]);
    for (fatal) |sig| std.posix.sigaction(sig, &act, null);
}

fn onSignalC(sig: i32, info: ?*anyopaque, context: ?*anyopaque) callconv(.c) void {
    onSignal(@fromBackingInt(@intCast(sig)), @ptrCast(@alignCast(info.?)), context);
}

fn onSignal(sig: Sig, info: *const std.posix.siginfo_t, context: ?*anyopaque) callconv(.c) void {
    const i = slot(sig) orelse return;
    // A fault the simulator answers itself (a trapped `rdtsc`, a call into
    // the protected vDSO) never comes here: its handler is installed after
    // this one (`tsc.install` installs this first), runs first, and passes
    // on only what is not its own.
    if (current != null) {
        // Under the system-call trap the thread's calls are blocked: the
        // report's, and the standard handler's after it, go to the kernel
        // (on every thread that crashes, not only the one that reports).
        if (syscalls.supported) syscalls.allowForCrash();
        report(if (sig == .ABRT) "aborted (a panic, or abort)" else "crashed (a fatal signal)");
    }
    passOn(sig, &previous[i], info, context);
}

fn passOn(sig: Sig, prev: *const std.posix.Sigaction, info: *const std.posix.siginfo_t, context: ?*anyopaque) void {
    const h = @intFromPtr(prev.handler.handler);
    if (h > 1) {
        // The handler before this one: it reports and ends the process,
        // or answers the fault and returns.
        if (prev.flags & std.posix.SA.SIGINFO != 0) {
            prev.handler.sigaction.?(sig, info, context);
        } else {
            prev.handler.handler.?(sig);
        }
        return;
    }
    if (h == 1) {
        // Ignored before: so again. A fault an instruction raised comes
        // again on return, and the kernel ends the process for it.
        std.posix.sigaction(sig, prev, null);
        return;
    }
    // The default action: put it back and raise the signal again, which
    // ends the process with it (whether an instruction raised it or it
    // was sent, which would not come again on its own).
    const dfl: std.posix.Sigaction = .{ .handler = .{ .handler = Sig.DFL }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(sig, &dfl, null);
    std.posix.raise(sig) catch {};
}

// ---------------------------------------------------------------------------
// Windows

fn installWindows() void {
    _ = std.os.windows.ntdll.RtlAddVectoredExceptionHandler(1, onException);
}

fn onException(info: *std.os.windows.EXCEPTION_POINTERS) callconv(.winapi) c_long {
    const windows = std.os.windows;
    switch (info.ExceptionRecord.ExceptionCode) {
        windows.EXCEPTION_ACCESS_VIOLATION,
        windows.EXCEPTION_ILLEGAL_INSTRUCTION,
        windows.EXCEPTION_STACK_OVERFLOW,
        windows.EXCEPTION_DATATYPE_MISALIGNMENT,
        0xc0000094, // EXCEPTION_INT_DIVIDE_BY_ZERO
        0xc0000096, // EXCEPTION_PRIV_INSTRUCTION
        0xc000008c, // EXCEPTION_ARRAY_BOUNDS_EXCEEDED
        0xc0000006, // EXCEPTION_IN_PAGE_ERROR
        0xc0000409, // STATUS_STACK_BUFFER_OVERRUN (__fastfail)
        => |code| reportException(code),
        else => {},
    }
    return windows.EXCEPTION_CONTINUE_SEARCH;
}

/// Called by the loader for each thread's start and end and the process's:
/// a panic on Windows ends the process (`RtlExitUserProcess`) on the
/// panicking thread, which still has its run marked here.
fn onTls(_: std.os.windows.PVOID, reason: std.os.windows.DWORD, _: std.os.windows.PVOID) callconv(.winapi) void {
    if (reason != 0) return; // DLL_PROCESS_DETACH
    report("ended the process (a panic, or an exit)");
}

comptime {
    if (native_os == .windows) _ = WindowsTls;
}
const WindowsTls = struct {
    // Between std's `__xl_a` and `__xl_z` (`std/os/windows/tls.zig`): the
    // linker orders the `.CRT$XL?` sections by their suffix.
    export var tardis_crash_tls_callback: std.os.windows.PIMAGE_TLS_CALLBACK linksection(".CRT$XLT") = &onTls;
};
