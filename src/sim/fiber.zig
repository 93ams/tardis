//! Fiber stacks, entry trampolines and context switching (plan §4.1).
//!
//! Builds on `std.Io.fiber.contextSwitch`, which saves sp/fp/pc and declares
//! every other register clobbered so the compiler spills live values around
//! the switch. TARDIS adds its own naked entry trampoline per ABI, a guard
//! page and a canary below each stack, and (on Windows) NT_TIB stack-bounds
//! bookkeeping.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const sf = std.Io.fiber;

pub const supported = sf.supported;
pub const Context = sf.Context;

const is_windows = builtin.os.tag == .windows;

pub const canary_bytes = 64;
const canary_byte: u8 = 0xC5;

/// Stack bounds as the OS sees them (base is the high end).
pub const Bounds = struct {
    base: usize,
    limit: usize,
};

/// Returns the current thread's stack bounds as recorded by the OS. On
/// non-Windows hosts the bounds are not tracked and this returns zeros.
pub fn currentBounds() Bounds {
    if (is_windows) {
        const tib = &std.os.windows.teb().NtTib;
        return .{ .base = @intFromPtr(tib.StackBase), .limit = @intFromPtr(tib.StackLimit) };
    }
    return .{ .base = 0, .limit = 0 };
}

fn setBounds(b: Bounds) void {
    if (is_windows) {
        if (b.base == 0) return;
        const tib = &std.os.windows.teb().NtTib;
        tib.StackBase = @ptrFromInt(b.base);
        tib.StackLimit = @ptrFromInt(b.limit);
    }
}

/// The stacks of a simulator's fibers: one mapping, each stack with an
/// inaccessible guard page below it. A stack that overflows faults at the
/// overflowing instruction, where the host's crash report shows the frame,
/// instead of writing into the stack below it.
pub const Stacks = struct {
    mem: []align(std.heap.page_size_min) u8,
    count: usize,
    stack_bytes: usize,
    /// A stack's bytes rounded up to whole pages, plus its guard page.
    slot_bytes: usize,
    page_bytes: usize,
    /// False where the host could not protect the guard pages: the canary
    /// still reports an overflow, at the task's next switch.
    guarded: bool,

    pub fn init(count: usize, stack_bytes: usize) !Stacks {
        assert(stack_bytes % 16 == 0);
        const page = std.heap.pageSize();
        const slot = std.mem.alignForward(usize, stack_bytes, page) + page;
        const mem = try std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(std.heap.page_size_min), count * slot);
        var st: Stacks = .{
            .mem = mem,
            .count = count,
            .stack_bytes = stack_bytes,
            .slot_bytes = slot,
            .page_bytes = page,
            .guarded = true,
        };
        for (0..count) |i| {
            std.process.protectMemory(st.guard(i), .{}) catch {
                st.guarded = false;
            };
        }
        return st;
    }

    pub fn deinit(st: *Stacks) void {
        // The mapping goes back writable, as the allocator handed it out.
        for (0..st.count) |i| std.process.protectMemory(st.guard(i), .{ .read = true, .write = true }) catch {};
        std.heap.page_allocator.free(st.mem);
        st.* = undefined;
    }

    /// The page below stack `i`.
    pub fn guard(st: *const Stacks, i: usize) []align(std.heap.page_size_min) u8 {
        return @alignCast(st.mem[i * st.slot_bytes ..][0..st.page_bytes]);
    }

    /// Stack `i`: the top `stack_bytes` of its slot.
    pub fn stack(st: *const Stacks, i: usize) []align(16) u8 {
        const end = (i + 1) * st.slot_bytes;
        return @alignCast(st.mem[end - st.stack_bytes .. end]);
    }
};

/// Fills the low end of a stack with the canary pattern.
pub fn paintCanary(stack: []u8) void {
    @memset(stack[0..canary_bytes], canary_byte);
}

pub fn canaryIntact(stack: []const u8) bool {
    for (stack[0..canary_bytes]) |b| {
        if (b != canary_byte) return false;
    }
    return true;
}

/// Produces a naked entry function that jumps to `target` with a call-like
/// stack layout. `target` takes no arguments and reads its task from
/// simulator state.
pub fn Trampoline(comptime target: *const fn () callconv(.c) noreturn) type {
    return struct {
        pub fn entry() callconv(.naked) noreturn {
            switch (builtin.cpu.arch) {
                .x86_64 => asm volatile ("jmp %[f:P]"
                    :
                    : [f] "X" (target),
                ),
                .aarch64 => asm volatile ("b %[f]"
                    :
                    : [f] "X" (target),
                ),
                .riscv64 => asm volatile ("tail %[f]"
                    :
                    : [f] "X" (target),
                ),
                else => @compileError("tardis: fibers unsupported on this architecture"),
            }
        }
    };
}

/// Builds the initial context for a fiber whose stack is `stack`.
pub fn initContext(stack: []align(16) u8, entry: *const fn () callconv(.naked) noreturn) Context {
    const top = @intFromPtr(stack.ptr) + stack.len;
    assert(top % 16 == 0);
    switch (builtin.cpu.arch) {
        .x86_64 => {
            // At function entry rsp % 16 == 8 (as after a `call`). On Windows the
            // callee may use 32 bytes of shadow space above the return address,
            // so reserve 64 bytes (keeps alignment, covers both ABIs).
            const sp = top - 64 - 8;
            @as(*usize, @ptrFromInt(sp)).* = 0; // fake return address
            return .{ .rsp = sp, .rbp = 0, .rip = @intFromPtr(entry) };
        },
        .aarch64 => return .{ .sp = top - 16, .fp = 0, .pc = @intFromPtr(entry) },
        .riscv64 => return .{ .sp = top - 16, .fp = 0, .pc = @intFromPtr(entry) },
        else => @compileError("tardis: fibers unsupported on this architecture"),
    }
}

/// Saves the current context into `old` and resumes `new`, installing
/// `new_bounds` as the OS-visible stack bounds first.
pub fn switchTo(old: *Context, new: *Context, new_bounds: Bounds) void {
    setBounds(new_bounds);
    var s: sf.Switch = .{ .old = old, .new = new };
    if (!win64_vector_registers) {
        _ = sf.contextSwitch(&s);
        return;
    }
    // On 64-bit Windows a callee must preserve xmm6 to xmm15. The switch
    // names them as clobbered, which keeps this function from relying on
    // them, but the compiler does not save them for the caller: an
    // optimized caller that kept a value there across a call that
    // switches fibers got back what another fiber left (found as a crash
    // in ReleaseFast, plan.md "Open items", revision 72). So they are
    // saved here, on this fiber's stack, and put back when it resumes.
    var saved: [10][16]u8 align(16) = undefined;
    asm volatile (
        \\ movups %%xmm6, 0(%[p])
        \\ movups %%xmm7, 16(%[p])
        \\ movups %%xmm8, 32(%[p])
        \\ movups %%xmm9, 48(%[p])
        \\ movups %%xmm10, 64(%[p])
        \\ movups %%xmm11, 80(%[p])
        \\ movups %%xmm12, 96(%[p])
        \\ movups %%xmm13, 112(%[p])
        \\ movups %%xmm14, 128(%[p])
        \\ movups %%xmm15, 144(%[p])
        :
        : [p] "r" (&saved),
        : .{ .memory = true });
    _ = sf.contextSwitch(&s);
    asm volatile (
        \\ movups 0(%[p]), %%xmm6
        \\ movups 16(%[p]), %%xmm7
        \\ movups 32(%[p]), %%xmm8
        \\ movups 48(%[p]), %%xmm9
        \\ movups 64(%[p]), %%xmm10
        \\ movups 80(%[p]), %%xmm11
        \\ movups 96(%[p]), %%xmm12
        \\ movups 112(%[p]), %%xmm13
        \\ movups 128(%[p]), %%xmm14
        \\ movups 144(%[p]), %%xmm15
        :
        : [p] "r" (&saved),
        : .{ .memory = true });
}

/// Whether `switchTo` must carry the vector registers a callee preserves.
const win64_vector_registers = is_windows and builtin.cpu.arch == .x86_64;

pub fn boundsOf(stack: []u8) Bounds {
    return .{ .base = @intFromPtr(stack.ptr) + stack.len, .limit = @intFromPtr(stack.ptr) };
}

// ---------------------------------------------------------------------------

var test_main: Context = undefined;
var test_fiber: Context = undefined;
var test_main_bounds: Bounds = undefined;
var test_stack: []align(16) u8 = undefined;
var test_counter: u32 = 0;

fn testDeep(n: u32) u32 {
    var buf: [4096]u8 = undefined;
    buf[n % buf.len] = @truncate(n);
    if (n == 0) return buf[0];
    return testDeep(n - 1) +% buf[n % buf.len];
}

fn testFiberMain() callconv(.c) noreturn {
    while (true) {
        test_counter += 1;
        _ = testDeep(8);
        switchTo(&test_fiber, &test_main, test_main_bounds);
    }
}

test "each fiber stack has an inaccessible guard page below it" {
    var st = try Stacks.init(3, 64 * 1024 + 16);
    defer st.deinit();
    const page = std.heap.pageSize();
    for (0..3) |i| {
        const s = st.stack(i);
        try std.testing.expectEqual(@as(usize, 64 * 1024 + 16), s.len);
        // The guard is below the stack, and nothing else of this stack is.
        const guard_end = @intFromPtr(st.guard(i).ptr) + page;
        try std.testing.expect(guard_end <= @intFromPtr(s.ptr));
        try std.testing.expect(@intFromPtr(s.ptr) - guard_end < page);
        s[0] = 1; // the stack itself is writable to its lowest byte
        s[s.len - 1] = 1;
    }
    switch (builtin.os.tag) {
        .windows => {
            try std.testing.expect(st.guarded);
            const Info = extern struct {
                base: ?*anyopaque,
                allocation_base: ?*anyopaque,
                allocation_protect: u32,
                partition: u16,
                region_size: usize,
                state: u32,
                protect: u32,
                kind: u32,
            };
            const k32 = struct {
                extern "kernel32" fn VirtualQuery(address: ?*const anyopaque, info: *Info, len: usize) callconv(.winapi) usize;
            };
            for (0..3) |i| {
                var info: Info = undefined;
                try std.testing.expect(k32.VirtualQuery(st.guard(i).ptr, &info, @sizeOf(Info)) != 0);
                try std.testing.expectEqual(@as(u32, 0x01), info.protect); // PAGE_NOACCESS
                try std.testing.expect(k32.VirtualQuery(st.stack(i).ptr, &info, @sizeOf(Info)) != 0);
                try std.testing.expectEqual(@as(u32, 0x04), info.protect); // PAGE_READWRITE
            }
        },
        .linux => {
            try std.testing.expect(st.guarded);
            // A child that writes below its stack dies of the fault.
            const linux = std.os.linux;
            const rc = linux.fork();
            try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
            if (rc == 0) {
                _ = linux.close(2); // the crash report is expected: keep it quiet
                st.guard(1)[page - 1] = 1;
                linux.exit_group(0); // not reached
            }
            var status: i32 = 0;
            _ = linux.waitpid(@intCast(rc), &status, 0);
            try std.testing.expect(status & 0x7f != 0); // ended by a signal
        },
        else => {},
    }
}

/// A fiber that leaves all ones in the vector registers a Win64 callee
/// must preserve, then switches back.
fn testClobberMain() callconv(.c) noreturn {
    while (true) {
        if (win64_vector_registers) asm volatile (
            \\ pcmpeqd %%xmm6, %%xmm6
            \\ pcmpeqd %%xmm7, %%xmm7
            \\ pcmpeqd %%xmm8, %%xmm8
            \\ pcmpeqd %%xmm9, %%xmm9
            \\ pcmpeqd %%xmm10, %%xmm10
            \\ pcmpeqd %%xmm11, %%xmm11
            \\ pcmpeqd %%xmm12, %%xmm12
            \\ pcmpeqd %%xmm13, %%xmm13
            \\ pcmpeqd %%xmm14, %%xmm14
            \\ pcmpeqd %%xmm15, %%xmm15
            ::: .{ .xmm6 = true, .xmm7 = true, .xmm8 = true, .xmm9 = true, .xmm10 = true, .xmm11 = true, .xmm12 = true, .xmm13 = true, .xmm14 = true, .xmm15 = true });
        switchTo(&test_fiber, &test_main, test_main_bounds);
    }
}

test "a switch keeps the vector registers a Win64 callee must preserve" {
    if (!win64_vector_registers) return error.SkipZigTest;
    test_stack = try std.testing.allocator.alignedAlloc(u8, .@"16", 128 * 1024);
    defer std.testing.allocator.free(test_stack);
    test_main_bounds = currentBounds();
    test_fiber = initContext(test_stack, Trampoline(&testClobberMain).entry);
    // Zero in xmm6 and xmm15, another fiber that fills them with ones, and
    // what they hold when this one resumes. One piece of assembly, so the
    // compiler keeps nothing of its own in them meanwhile.
    var before: [2]u64 = undefined;
    var after: [2]u64 = undefined;
    const Call = struct {
        fn go() callconv(.c) void {
            switchTo(&test_main, &test_fiber, boundsOf(test_stack));
        }
    };
    asm volatile (
        \\ pxor %%xmm6, %%xmm6
        \\ pxor %%xmm15, %%xmm15
        \\ movq %%xmm6, 0(%[b])
        \\ movq %%xmm15, 8(%[b])
        \\ subq $32, %%rsp
        \\ callq *%[f]
        \\ addq $32, %%rsp
        \\ movq %%xmm6, 0(%[a])
        \\ movq %%xmm15, 8(%[a])
        :
        : [b] "{rbx}" (&before),
          [a] "{rsi}" (&after),
          [f] "{rdi}" (&Call.go),
        : .{ .rax = true, .rcx = true, .rdx = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true, .xmm0 = true, .xmm1 = true, .xmm2 = true, .xmm3 = true, .xmm4 = true, .xmm5 = true, .xmm6 = true, .xmm15 = true, .memory = true });
    try std.testing.expectEqual([2]u64{ 0, 0 }, before);
    try std.testing.expectEqual([2]u64{ 0, 0 }, after);
}

test "fiber round trips" {
    if (!supported) return error.SkipZigTest;
    test_stack = try std.testing.allocator.alignedAlloc(u8, .@"16", 128 * 1024);
    defer std.testing.allocator.free(test_stack);
    paintCanary(test_stack);
    test_main_bounds = currentBounds();
    test_fiber = initContext(test_stack, Trampoline(&testFiberMain).entry);
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        switchTo(&test_main, &test_fiber, boundsOf(test_stack));
    }
    try std.testing.expectEqual(@as(u32, 5), test_counter);
    try std.testing.expect(canaryIntact(test_stack));
    try std.testing.expectEqual(test_main_bounds.base, currentBounds().base);
}
