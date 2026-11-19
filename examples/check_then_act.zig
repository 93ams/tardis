//! Example: claiming a job by creating its lock file.
//!
//! The bug class: **check, then act.** A worker looks whether the lock
//! file exists and, if not, creates it. Two workers can both look before
//! either creates, and both believe the job is theirs.
//!
//! The fix asks the filesystem to do both at once: create the file only if
//! it does not exist (`exclusive`), and let the loser see the error.
//!
//! The property: exactly one worker claims the job.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

pub const options: tardis.Options = .{ .iterations = 200 };

fn claim(io: Io, dir: Io.Dir, variant: Variant, claims: *u32) Io.Cancelable!void {
    switch (variant) {
        .buggy => {
            // Look, then create: two steps, with room between them.
            if (dir.access(io, "job.lock", .{})) |_| return else |_| {}
            var f = dir.createFile(io, "job.lock", .{}) catch return;
            f.close(io);
        },
        .fixed => {
            var f = dir.createFile(io, "job.lock", .{ .exclusive = true }) catch return;
            f.close(io);
        },
    }
    claims.* += 1;
}

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    var claims: u32 = 0;
    var group: Io.Group = .init;
    defer group.cancel(io);
    for (0..3) |_| try group.concurrent(io, claim, .{ io, env.dir, variant, &claims });
    try group.await(io);
    try env.always("exactly one worker claims the job", claims == 1);
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "check_then_act: looking and then creating lets two workers claim one job" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, o));
}

test "check_then_act: an exclusive create gives the job to one worker" {
    try tardis.check(std.testing.allocator, fixed, options);
}
