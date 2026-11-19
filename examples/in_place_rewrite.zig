//! Example: saving a document by writing over the old one.
//!
//! The bug class: **rewriting a file in place.** Opening a file for
//! writing empties it, and the new content follows. A power loss between
//! the two leaves an empty file, or half of the new one: the old document
//! is gone and the new one is not there yet.
//!
//! The fix writes the new content beside the old, makes it durable, and
//! swaps the names.
//!
//! The property: after a power loss the document is the old version or
//! the new one.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

pub const options: tardis.Options = .{ .iterations = 200 };

const old_text = "chapter one, first draft";
const new_text = "chapter one, second draft, rather longer than the first";

fn syncPath(io: Io, dir: Io.Dir, name: []const u8) !void {
    var f = try dir.openFile(io, name, if (std.mem.eql(u8, name, ".")) .{} else .{ .mode = .read_write });
    defer f.close(io);
    try f.sync(io);
}

fn save(io: Io, dir: Io.Dir, variant: Variant) !void {
    switch (variant) {
        .buggy => {
            try dir.writeFile(io, .{ .sub_path = "document", .data = new_text });
            try syncPath(io, dir, "document");
        },
        .fixed => {
            try dir.writeFile(io, .{ .sub_path = "document.new", .data = new_text });
            try syncPath(io, dir, "document.new");
            try dir.rename("document.new", dir, "document", io);
            try syncPath(io, dir, ".");
        },
    }
}

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    try env.dir.writeFile(io, .{ .sub_path = "document", .data = old_text });
    try syncPath(io, env.dir, "document");
    try syncPath(io, env.dir, ".");

    // The power may go at any point of the save: the seed picks how many
    // of its I/O calls complete.
    env.injectIoErrorAfter(.write, (try env.fuzz(u8)) % 3, error.InputOutput);
    save(io, env.dir, variant) catch {};
    try env.crashAndReboot(.power_loss);

    var buf: [128]u8 = undefined;
    const got = try env.dir.readFile(io, "document", &buf);
    const ok = std.mem.eql(u8, got, old_text) or std.mem.eql(u8, got, new_text);
    try env.always("the document is the old version or the new one", ok);
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "in_place_rewrite: a save interrupted after the truncate loses both versions" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, o));
}

test "in_place_rewrite: writing beside and renaming keeps one whole version" {
    try tardis.check(std.testing.allocator, fixed, options);
}
