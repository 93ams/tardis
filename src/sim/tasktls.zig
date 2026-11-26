//! Thread-local variables that each task has its own copy of
//! (`Options.task_locals`).
//!
//! Every task of a run is a fiber on one thread, so a `threadlocal`
//! variable has one copy for all of them. For the variables a check names,
//! the simulator keeps a copy per task and swaps it in when the task runs:
//! at each switch the outgoing task's bytes are saved and the incoming
//! one's put in their place (`Sim.switchToTask`). Nothing else of the
//! thread's thread-local storage is touched, the simulator's own included.
//!
//! A variable is named by its bytes on the thread that calls `check`. It is
//! kept as an offset into the program's thread-local block, which is the
//! same on every thread (workers run on other threads), and each run finds
//! its own thread's block again (`block`).

const std = @import("std");
const builtin = @import("builtin");

/// Where a variable can be told to be thread-local: Linux (ELF) and
/// Windows. In a single-threaded build a `threadlocal` is a plain
/// variable, and any variable may be named.
pub const supported = builtin.single_threaded or switch (builtin.os.tag) {
    .linux => builtin.object_format == .elf,
    .windows => true,
    else => false,
};

/// Variables a check may name.
pub const ranges_max = 64;

/// A named variable: its place in the thread-local block.
pub const Range = struct { offset: usize, len: usize };

/// The named variables as found on the thread that named them: their
/// places, and their values there (what each task starts with, on any
/// thread).
pub const Resolved = struct { ranges: []const Range, home: []const u8 };

/// A value no other thread-local's initial bytes are likely to hold: found
/// in the template of the thread-local block, it says where the block
/// begins (Linux).
const probe_value: u64 = 0x7a2d_51c3_9e04_b6f1;
threadlocal var probe: u64 = probe_value;

/// This thread's thread-local block of the program; null where it cannot
/// be found.
pub fn block() ?[]u8 {
    if (builtin.single_threaded) return null;
    return switch (builtin.os.tag) {
        .linux => if (builtin.object_format == .elf) linuxBlock() else null,
        .windows => windowsBlock(),
        else => null,
    };
}

fn linuxBlock() ?[]u8 {
    const Found = struct {
        template: []const u8 = &.{},
        memsz: usize = 0,
        at: usize = 0,
    };
    var found: Found = .{};
    const Cb = struct {
        fn f(info: *std.posix.dl_phdr_info, _: usize, out: *Found) error{Done}!void {
            for (info.phdr[0..info.phnum]) |ph| {
                if (ph.type != .TLS) continue;
                const template = @as([*]const u8, @ptrFromInt(info.addr + ph.vaddr))[0..ph.filesz];
                // The object whose template holds the probe, once.
                const at = findProbe(template) orelse continue;
                out.* = .{ .template = template, .memsz = ph.memsz, .at = at };
                return error.Done;
            }
        }
    };
    std.posix.dl_iterate_phdr(&found, error{Done}, Cb.f) catch {};
    if (found.memsz == 0) return null;
    const lo = @intFromPtr(&probe) - found.at;
    return @as([*]u8, @ptrFromInt(lo))[0..found.memsz];
}

/// The probe's offset in `template`, if its value is there once and
/// aligned.
fn findProbe(template: []const u8) ?usize {
    const needle = std.mem.asBytes(&probe_value);
    var at: ?usize = null;
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, template, i, needle)) |k| : (i = k + 1) {
        if ((@intFromPtr(template.ptr) + k) % @alignOf(u64) != 0) continue;
        if (at != null) return null;
        at = k;
    }
    return at;
}

fn windowsBlock() ?[]u8 {
    const windows = std.os.windows;
    // Exported by std (`std/os/windows/tls.zig`) where the program has
    // thread-locals: the template's bounds and the program's slot.
    const index = @extern(*const u32, .{ .name = "_tls_index" });
    const start = @extern(*const ?*anyopaque, .{ .name = "_tls_start" });
    const end = @extern(*const ?*anyopaque, .{ .name = "_tls_end" });
    const slots: [*]const usize = @ptrCast(@alignCast(windows.teb().ThreadLocalStoragePointer));
    const lo = slots[index.*];
    if (lo == 0) return null;
    const len = @intFromPtr(end) + @sizeOf(?*anyopaque) - @intFromPtr(start);
    const b = @as([*]u8, @ptrFromInt(lo))[0..len];
    // The probe is in it, or this is not the block.
    const p = @intFromPtr(&probe);
    if (p < lo or p + @sizeOf(u64) > lo + len) return null;
    return b;
}

pub const Error = error{
    /// The platform cannot tell a thread-local variable (`supported`).
    TaskLocalsUnsupported,
};

/// The places of `vars`, given as their bytes on the calling thread, into
/// `out` (an empty one is left out). Panics on one that is not a
/// thread-local variable of the program (a plain variable would be swapped
/// on one thread and missed on the others).
pub fn ranges(vars: []const []u8, out: *[ranges_max]Range) Error![]const Range {
    if (vars.len == 0) return out[0..0];
    if (!supported) return error.TaskLocalsUnsupported;
    if (vars.len > ranges_max) std.debug.panic("tardis: Options.task_locals names {d} variables, at most {d}", .{ vars.len, ranges_max });
    var n: usize = 0;
    if (builtin.single_threaded) {
        for (vars) |v| {
            if (v.len == 0) continue;
            out[n] = .{ .offset = @intFromPtr(v.ptr), .len = v.len };
            n += 1;
        }
        return out[0..n];
    }
    const b = block() orelse return error.TaskLocalsUnsupported;
    const lo = @intFromPtr(b.ptr);
    for (vars, 0..) |v, i| {
        if (v.len == 0) continue;
        const p = @intFromPtr(v.ptr);
        if (p < lo or p + v.len > lo + b.len) std.debug.panic("tardis: Options.task_locals[{d}] is not a threadlocal variable of the program (its bytes are not in the thread-local block)", .{i});
        out[n] = .{ .offset = p - lo, .len = v.len };
        n += 1;
    }
    return out[0..n];
}

/// The sum of the lengths of `rs`.
pub fn length(rs: []const Range) usize {
    var len: usize = 0;
    for (rs) |r| len += r.len;
    return len;
}

/// The variables' values on this thread, into `out` (`length` bytes).
pub fn snapshot(rs: []const Range, out: []u8) void {
    const c: Copies = .{ .ranges = rs, .len = length(rs), .base = thisBase() };
    c.save(out);
}

fn thisBase() usize {
    if (builtin.single_threaded) return 0;
    const b = block() orelse @panic("tardis: the thread-local block of the program was found on the thread that called check, and is not found on this one");
    return @intFromPtr(b.ptr);
}

/// The swapping, for one simulator: a copy of the named variables per task,
/// and the thread's own from the run's start.
pub const Copies = struct {
    ranges: []const Range = &.{},
    /// The sum of the lengths.
    len: usize = 0,
    /// `len` bytes per task, then the thread's own.
    bytes: []u8 = &.{},
    /// This thread's block (or 0 in a single-threaded build), for the run.
    base: usize = 0,

    /// `start`: what each task starts with, as found on the thread that
    /// named the variables; null to take it from this thread now.
    pub fn init(gpa: std.mem.Allocator, rs: []const Range, start: ?[]const u8, tasks: usize) error{OutOfMemory}!Copies {
        const len = length(rs);
        if (len == 0) return .{};
        const owned = try gpa.dupe(Range, rs);
        errdefer gpa.free(owned);
        var c: Copies = .{ .ranges = owned, .len = len, .bytes = try gpa.alloc(u8, len * (tasks + 1)) };
        if (start) |h| @memcpy(c.home(), h) else {
            c.base = thisBase();
            c.save(c.home());
        }
        return c;
    }

    pub fn deinit(c: *Copies, gpa: std.mem.Allocator) void {
        if (c.ranges.len == 0) return;
        gpa.free(c.ranges);
        gpa.free(c.bytes);
        c.* = .{};
    }

    pub fn on(c: *const Copies) bool {
        return c.ranges.len > 0;
    }

    fn slot(c: *const Copies, i: usize) []u8 {
        return c.bytes[i * c.len ..][0..c.len];
    }

    fn home(c: *const Copies) []u8 {
        return c.slot(c.bytes.len / c.len - 1);
    }

    /// A run begins on this thread: the variables are this thread's.
    pub fn beginRun(c: *Copies) void {
        if (!c.on()) return;
        c.base = thisBase();
    }

    /// Task `id` begins: the values found where they were named.
    pub fn fresh(c: *const Copies, id: usize) void {
        if (!c.on()) return;
        @memcpy(c.slot(id), c.home());
    }

    /// The running task changes from `prev` to `next`.
    pub fn swap(c: *const Copies, prev: usize, next: usize) void {
        if (!c.on()) return;
        c.save(c.slot(prev));
        c.load(c.slot(next));
    }

    fn save(c: *const Copies, into: []u8) void {
        var k: usize = 0;
        for (c.ranges) |r| {
            @memcpy(into[k..][0..r.len], @as([*]const u8, @ptrFromInt(c.base + r.offset))[0..r.len]);
            k += r.len;
        }
    }

    fn load(c: *const Copies, from: []const u8) void {
        var k: usize = 0;
        for (c.ranges) |r| {
            @memcpy(@as([*]u8, @ptrFromInt(c.base + r.offset))[0..r.len], from[k..][0..r.len]);
            k += r.len;
        }
    }
};

threadlocal var test_counter: u32 = 7;
var test_plain: u32 = 0;

test "a thread-local variable is found in the block, a plain one is not" {
    if (!supported or builtin.single_threaded) return error.SkipZigTest;
    const b = block() orelse return error.TestUnexpectedResult;
    const p = @intFromPtr(&test_counter);
    try std.testing.expect(p >= @intFromPtr(b.ptr) and p + 4 <= @intFromPtr(b.ptr) + b.len);
    const q = @intFromPtr(&test_plain);
    try std.testing.expect(!(q >= @intFromPtr(b.ptr) and q < @intFromPtr(b.ptr) + b.len));
    // The same offset on another thread is that thread's copy.
    var out: [ranges_max]Range = undefined;
    const rs = try ranges(&.{std.mem.asBytes(&test_counter)}, &out);
    const T = struct {
        fn run(r: Range, seen: *u32) void {
            test_counter = 99;
            const ob = block().?;
            seen.* = @as(*const u32, @ptrFromInt(@intFromPtr(ob.ptr) + r.offset)).*;
        }
    };
    var seen: u32 = 0;
    const t = try std.Thread.spawn(.{}, T.run, .{ rs[0], &seen });
    t.join();
    try std.testing.expectEqual(@as(u32, 99), seen);
    try std.testing.expectEqual(@as(u32, 7), test_counter);
}
