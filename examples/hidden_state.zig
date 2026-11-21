//! Example: a job queue that names each job's file after its number.
//!
//! The bug class: **state that survives a run.** The next job number lives
//! in a global variable. Nothing resets it between two runs of the test,
//! so what a run does depends on how many runs came before it: the same
//! seed writes other files the second time. Every property of a single
//! run still holds, so no assertion can see it; what breaks is the promise
//! that a failure found with a seed comes back with that seed.
//!
//! The fix keeps the number in the queue, which each run makes anew.
//!
//! The property is the simulator's own: it runs some seeds twice and
//! compares what happened (`Options.determinism_check_every`).

const std = @import("std");
const tardis = @import("tardis");
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

pub const options: tardis.Options = .{ .iterations = 200 };

/// The bug: a number that outlives the queue it belongs to.
var next_job_global: u32 = 0;

const Queue = struct {
    next_job: u32 = 0,

    fn submit(q: *Queue, env: *Env, variant: Variant, payload: []const u8) !void {
        const counter = if (variant == .fixed) &q.next_job else &next_job_global;
        const job = counter.*;
        counter.* += 1;
        var name_buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "job-{d}", .{job % 8});
        try env.dir.writeFile(env.io, .{ .sub_path = name, .data = payload[0 .. 1 + job % payload.len] });
    }
};

fn scenario(env: *Env, variant: Variant) !void {
    var q: Queue = .{};
    for (0..3) |_| try q.submit(env, variant, "payload");
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "hidden_state: a number kept in a global makes the same seed run differently" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.NonDeterministic, tardis.check(std.testing.allocator, buggy, o));
}

test "hidden_state: the number kept in the queue repeats" {
    try tardis.check(std.testing.allocator, fixed, options);
}
