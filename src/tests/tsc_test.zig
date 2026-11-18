//! The virtual time-stamp counter (plan §9 M6): with `Options.virtual_tsc`
//! a run's `rdtsc` reads follow its virtual clock, not the machine.

const std = @import("std");
const builtin = @import("builtin");
const tardis = @import("../root.zig");
const Env = tardis.Env;
const testing = std.testing;
const gpa = testing.allocator;

fn rdtsc() u64 {
    if (builtin.cpu.arch != .x86_64) return 0;
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return (@as(u64, hi) << 32) | lo;
}

fn rdtscp() u64 {
    if (builtin.cpu.arch != .x86_64) return 0;
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtscp"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
        :
        : .{ .rcx = true });
    return (@as(u64, hi) << 32) | lo;
}

/// Times a sleep with the counter, as code that bypasses `std.Io` would.
fn timed(env: *Env) !void {
    const a = rdtsc();
    const b = rdtsc();
    try env.io.sleep(.fromMilliseconds(5), .awake);
    const c = rdtscp();
    // Two reads at one instant differ by one; the sleep is 5 ms of
    // virtual time, to the nanosecond.
    try testing.expectEqual(a + 1, b);
    try testing.expectEqual(b + 5 * std.time.ns_per_ms + 1, c);
}

test "virtual_tsc: rdtsc and rdtscp follow the run's virtual clock" {
    if (!tardis.virtual_tsc_supported) return error.SkipZigTest;
    const real_before = rdtsc();
    try tardis.check(gpa, timed, .{ .iterations = 20, .virtual_tsc = true });
    // With stray system calls trapped as well: reading the counter is not one.
    try tardis.check(gpa, timed, .{ .iterations = 20, .virtual_tsc = true, .trap_syscalls = true });
    // After the runs the counter is the machine's again.
    const real_after = rdtsc();
    try testing.expect(real_after > real_before);
}

test "virtual_tsc: off, the same body fails its own arithmetic" {
    if (!tardis.virtual_tsc_supported) return error.SkipZigTest;
    try testing.expectError(error.TestExpectedEqual, tardis.check(gpa, timed, .{ .iterations = 1, .report = false, .shrink = false }));
}
