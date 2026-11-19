//! Example: a lease that is good for one second.
//!
//! The bug class: **measuring a duration with the wall clock.** The holder
//! notes the time of day when it got the lease and, before each use, checks
//! that less than a second has passed. The time of day can be set back (an
//! NTP correction, an operator, a virtual machine resumed), and then the
//! check says the lease is fresh long after it ran out. Two holders at once
//! is the usual result.
//!
//! The fix measures with a clock that only runs forward.
//!
//! The property: the lease is not used once a second of real time has
//! passed since it was granted.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

pub const options: tardis.Options = .{ .iterations = 200 };

const lease_ns = std.time.ns_per_s;

fn now(io: Io, variant: Variant) i128 {
    // The whole difference: the time of day, or a clock that cannot be set.
    return switch (variant) {
        .buggy => Io.Clock.real.now(io).nanoseconds,
        .fixed => Io.Clock.awake.now(io).nanoseconds,
    };
}

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    const granted = now(io, variant);
    const truly_granted = env.nowNs();

    // Some work, and somewhere in it the time of day is corrected by an
    // amount the seed chooses: up to two seconds back.
    try io.sleep(.fromMilliseconds(600), .awake);
    const back_ms: i64 = (try env.fuzz(u8)) % 9;
    env.stepClock(0, -back_ms * 250 * std.time.ns_per_ms);
    try io.sleep(.fromMilliseconds(600), .awake);

    const believes_valid = now(io, variant) - granted < lease_ns;
    const truly_valid = env.nowNs() - truly_granted < lease_ns;
    try env.always("the holder does not use a lease that has run out", !believes_valid or truly_valid);
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "lease: a wall clock set back makes an expired lease look fresh" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, o));
}

test "lease: a monotonic clock is not fooled" {
    try tardis.check(std.testing.allocator, fixed, options);
}
