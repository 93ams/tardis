//! Example: a data file and an index that says how much of it is valid.
//!
//! The bug class: **two files made durable in the wrong order.** An append
//! writes the record to the data file and then the new length to the
//! index. The buggy store syncs only the index. After a power loss the
//! index can promise bytes the data file never got.
//!
//! The fix syncs the data before it writes the index: nothing may point at
//! bytes that are not durable yet.
//!
//! The property: every byte the index promises is there, with the content
//! that was written.

const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const Env = tardis.Env;

const Variant = enum { buggy, fixed };

pub const options: tardis.Options = .{ .iterations = 200 };

const record_bytes = 16;

fn syncPath(io: Io, dir: Io.Dir, name: []const u8) !void {
    var f = try dir.openFile(io, name, if (std.mem.eql(u8, name, ".")) .{} else .{ .mode = .read_write });
    defer f.close(io);
    try f.sync(io);
}

fn append(io: Io, dir: Io.Dir, count: u8, variant: Variant) !void {
    const record: [record_bytes]u8 = @splat('A' + count);
    {
        var data = try dir.openFile(io, "data", .{ .mode = .read_write });
        defer data.close(io);
        try data.writePositionalAll(io, &record, @as(u64, count) * record_bytes);
        // The whole difference.
        if (variant == .fixed) try data.sync(io);
    }
    var index = try dir.openFile(io, "index", .{ .mode = .read_write });
    defer index.close(io);
    try index.writePositionalAll(io, &.{count + 1}, 0);
    try index.sync(io);
}

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    try env.dir.writeFile(io, .{ .sub_path = "data", .data = "" });
    try env.dir.writeFile(io, .{ .sub_path = "index", .data = &.{0} });
    try syncPath(io, env.dir, "data");
    try syncPath(io, env.dir, "index");
    try syncPath(io, env.dir, ".");

    const appends = 1 + (try env.fuzz(u8)) % 6;
    for (0..appends) |i| try append(io, env.dir, @intCast(i), variant);
    try env.crashAndReboot(.power_loss);

    var index_buf: [1]u8 = undefined;
    const promised = (try env.dir.readFile(io, "index", &index_buf))[0];
    var data_buf: [8 * record_bytes]u8 = undefined;
    const data = try env.dir.readFile(io, "data", &data_buf);
    try env.always("the data file is as long as the index says", data.len >= @as(usize, promised) * record_bytes);
    for (0..promised) |i| {
        const want: [record_bytes]u8 = @splat('A' + @as(u8, @intCast(i)));
        try env.always("every indexed record has its content", std.mem.eql(u8, data[i * record_bytes ..][0..record_bytes], &want));
    }
}

pub fn buggy(env: *Env) !void {
    return scenario(env, .buggy);
}

pub fn fixed(env: *Env) !void {
    return scenario(env, .fixed);
}

test "index_before_data: an index synced before its data points at nothing after a power loss" {
    var o = options;
    o.report = false;
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, o));
}

test "index_before_data: data made durable first keeps the index honest" {
    try tardis.check(std.testing.allocator, fixed, options);
}
