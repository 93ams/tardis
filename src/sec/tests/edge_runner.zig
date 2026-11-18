//! Test runner for edge-instrumented builds (`zig build evidence -Dedges`,
//! plan2.md §7.1).
//!
//! A module built with `fuzz = true` carries Zig's edge counters, which
//! `tardis_sec.certify` reads to list dead edges. Zig's default test runner
//! refuses such a build outside `zig build`'s fuzzing server ("fuzz test
//! requires server"), because it expects to drive the fuzzer. This runner
//! runs the tests as plain tests and never starts the fuzzer: the counters
//! are read by `certify`, not by Zig's fuzzer.
const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

pub fn main(init: std.process.Init.Minimal) void {
    @disableInstrumentation();
    var ok: usize = 0;
    var skipped: usize = 0;
    var failed: usize = 0;
    var leaks: usize = 0;
    for (builtin.test_functions) |t| {
        testing.allocator_instance = .init(std.heap.page_allocator, .{});
        testing.io_instance = .init(testing.allocator, .{
            .argv0 = .init(init.args),
            .environ = init.environ,
        });
        testing.environ = init.environ;
        testing.log_level = .warn;
        std.debug.print("{s}...", .{t.name});
        if (t.func()) |_| {
            ok += 1;
            std.debug.print("OK\n", .{});
        } else |err| switch (err) {
            error.SkipZigTest => {
                skipped += 1;
                std.debug.print("SKIP\n", .{});
            },
            else => {
                failed += 1;
                std.debug.print("FAIL ({t})\n", .{err});
                if (@errorReturnTrace()) |trace| std.debug.dumpErrorReturnTrace(trace);
            },
        }
        testing.io_instance.deinit();
        if (testing.allocator_instance.deinit() != 0) leaks += 1;
    }
    std.debug.print("{d} passed; {d} skipped; {d} failed; {d} leaked.\n", .{ ok, skipped, failed, leaks });
    if (failed != 0 or leaks != 0) std.process.exit(1);
}

// Zig's fuzzer runtime, linked into every `fuzz` build, refers to these
// runner entry points. This runner never starts the fuzzer, so none of
// them is reached.
const abi = std.Build.abi.fuzz;
export fn runner_test_run(i: u32) void {
    _ = i;
    unreachable;
}
export fn runner_test_name(i: u32) abi.Slice {
    _ = i;
    unreachable;
}
export fn runner_broadcast_input(i: u32, bytes: abi.Slice) void {
    _ = i;
    _ = bytes;
    unreachable;
}
export fn runner_start_input_poller() void {
    unreachable;
}
export fn runner_stop_input_poller() void {
    unreachable;
}
export fn runner_futex_wait(ptr: *const u32, expected: u32) bool {
    _ = ptr;
    _ = expected;
    unreachable;
}
export fn runner_futex_wake(ptr: *const u32, waiters: u32) void {
    _ = ptr;
    _ = waiters;
    unreachable;
}
