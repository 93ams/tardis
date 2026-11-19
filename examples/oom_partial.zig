//! Example: an index that keeps names in one list and their sizes in
//! another, entry for entry.
//!
//! The bug class: **a half-finished update when memory runs out.** Adding
//! an entry appends to the first list, then to the second. If the second
//! append cannot allocate, the function returns the error with the first
//! list one entry longer. The caller handles the error and carries on with
//! an index whose two halves no longer match.
//!
//! The fix reserves room in both lists before it changes either.
//!
//! The property: the two lists are always the same length.

const std = @import("std");
const tardis = @import("tardis");
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

pub const options: tardis.Options = .{ .iterations = 300, .faults = .{ .oom_ppm = 100_000 } };

const Index = struct {
    names: std.ArrayList(u8) = .empty,
    sizes: std.ArrayList(u32) = .empty,

    fn add(ix: *Index, gpa: std.mem.Allocator, name: u8, size: u32, variant: Variant) !void {
        switch (variant) {
            .buggy => {
                try ix.names.append(gpa, name);
                try ix.sizes.append(gpa, size);
            },
            .fixed => {
                try ix.names.ensureUnusedCapacity(gpa, 1);
                try ix.sizes.ensureUnusedCapacity(gpa, 1);
                ix.names.appendAssumeCapacity(name);
                ix.sizes.appendAssumeCapacity(size);
            },
        }
    }

    fn deinit(ix: *Index, gpa: std.mem.Allocator) void {
        ix.names.deinit(gpa);
        ix.sizes.deinit(gpa);
    }
};

fn scenario(env: *Env, variant: Variant) !void {
    const gpa = env.allocator;
    var index: Index = .{};
    defer index.deinit(gpa);
    for (0..24) |i| {
        // Out of memory is an answer the caller lives with.
        index.add(gpa, @intCast(i), @intCast(i * 10), variant) catch {};
        try env.always("the index's two lists are the same length", index.names.items.len == index.sizes.items.len);
    }
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "oom_partial: an allocation failure between two appends leaves the index lopsided" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, o));
}

test "oom_partial: reserving both before changing either keeps them in step" {
    try tardis.check(std.testing.allocator, fixed, options);
}
