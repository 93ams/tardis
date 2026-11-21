//! Example: saving a note, with one more try when the disk reports an error.
//!
//! The bug class: **code that never runs.** The retry is written against
//! the wrong error: it tries again on `error.WouldBlock`, which this write
//! never returns, and gives up on the I/O error it does get. Giving up is
//! allowed (the caller is told), so nothing the program promises is
//! broken, and every assertion about its results passes. The retry is
//! simply dead, and the test that was written to exercise it exercises
//! nothing.
//!
//! The fix retries on any error.
//!
//! The property is a `sometimes`: across the campaign, at least one save
//! must have succeeded on its second try. An assertion that can never fail
//! says nothing; a `sometimes` that never holds says the test does not
//! reach what it claims to.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

pub const options: tardis.Options = .{ .iterations = 200, .faults = .{ .io_error_ppm = 100_000 } };

const Saved = enum { first_try, second_try };

fn save(io: Io, dir: Io.Dir, variant: Variant, note: []const u8) !Saved {
    dir.writeFile(io, .{ .sub_path = "note", .data = note }) catch |err| {
        // The whole difference: which errors are worth one more try.
        const again = switch (variant) {
            .buggy => err == error.WouldBlock,
            .fixed => true,
        };
        if (!again) return err;
        try dir.writeFile(io, .{ .sub_path = "note", .data = note });
        return .second_try;
    };
    return .first_try;
}

fn scenario(env: *Env, variant: Variant) !void {
    // A save that fails is an outcome the caller handles.
    const saved = save(env.io, env.dir, variant, "remember the milk") catch null;
    env.sometimes("a save succeeds on its second try", saved == .second_try);
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "never_retried: a retry written against the wrong error never runs" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.SometimesNeverTrue, tardis.check(std.testing.allocator, buggy, o));
}

test "never_retried: retrying on any error is reached" {
    try tardis.check(std.testing.allocator, fixed, options);
}
