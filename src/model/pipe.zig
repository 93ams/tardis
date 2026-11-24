//! Pipes between a simulated program and the processes it spawns
//! (`plan3.md` D4). A pipe is a bounded byte queue with a read end and a
//! write end, each a handle of its own:
//!
//! - a read of an empty pipe blocks while the write end is open, and is the
//!   end of the stream once it is closed;
//! - a write blocks while the pipe is full (`capacity` bytes, as Linux's
//!   default), may be short, and fails with `error.BrokenPipe` once the
//!   read end is closed;
//! - no faults: real pipes do not lose or reorder bytes.
//!
//! Handle values share the filesystem's range (`vfs.encodeHandle`) with
//! bit 15 set, which a filesystem handle never has (`Vfs` handles are
//! limited to fewer than 0x8000), so the network's range stays as it was.
//! The buffers are allocated on the first pipe a run makes.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

pub const pipes_max = 16;
/// Bytes a pipe holds before a write blocks (Linux's default).
pub const capacity = 64 * 1024;

const tag: u32 = 0x8000;
/// Reads as an empty stream at its end; writes vanish (`StdIo.ignore`, and
/// `inherit`, which has no terminal behind it in a simulation).
pub const null_value: u32 = tag | 0x7FFF;
/// Names nothing (`StdIo.close`): every use fails as on a closed handle.
pub const closed_value: u32 = tag | 0x7FFE;

pub const End = enum(u1) { read, write };

pub const Pipe = struct {
    generation: u16 = 0,
    used: bool = false,
    read_open: bool = false,
    write_open: bool = false,
    /// Holders of each end: a pipe end given to a child as its
    /// `StdIo.file` is a duplicate, and the end closes with its last holder.
    read_refs: u8 = 0,
    write_refs: u8 = 0,
    head: u32 = 0,
    len: u32 = 0,
    /// The node of the process holding each end, for a node crash.
    read_node: u8 = 0,
    write_node: u8 = 0,
};

pub const Pipes = struct {
    gpa: Allocator,
    pipes: [pipes_max]Pipe = @splat(.{}),
    /// `pipes_max * capacity` bytes, once a pipe has been made.
    pool: []u8 = &.{},

    pub fn init(gpa: Allocator) Pipes {
        return .{ .gpa = gpa };
    }

    pub fn deinit(p: *Pipes) void {
        if (p.pool.len != 0) p.gpa.free(p.pool);
        p.pool = &.{};
    }

    /// Closes every pipe. Generations keep counting, so a handle from an
    /// earlier run never names a later pipe.
    pub fn reset(p: *Pipes) void {
        for (&p.pipes) |*q| {
            q.used = false;
            q.read_open = false;
            q.write_open = false;
            q.head = 0;
            q.len = 0;
        }
    }

    pub fn pristine(p: *const Pipes) bool {
        for (p.pipes) |q| if (q.used) return false;
        return true;
    }

    /// A value in the pipes' part of the range: an end, the null stream, or
    /// the closed one. (The filesystem's root, `0x3FFF_FFFF`, has bit 15
    /// set too, and is not one.)
    pub fn isPipeValue(value: u32) bool {
        if (value & 0xC000_8000 != tag) return false;
        const low = value & 0x7FFF;
        return (low >= 1 and low <= pipes_max * 2) or value == null_value or value == closed_value;
    }

    pub fn encode(p: *const Pipes, slot: u8, end: End) u32 {
        const g: u32 = p.pipes[slot].generation & 0x3FFF;
        return (g << 16) | tag | (@as(u32, slot) * 2 + @backingInt(end) + 1);
    }

    pub const Ref = struct { slot: u8, end: End };

    /// The open end `value` names, or null (closed, stale, or not a pipe).
    pub fn decode(p: *const Pipes, value: u32) ?Ref {
        if (!isPipeValue(value) or value == null_value) return null;
        const low = value & 0x7FFF;
        if (low == 0 or low > pipes_max * 2) return null;
        const slot: u8 = @intCast((low - 1) / 2);
        const end: End = @fromBackingInt(@intCast((low - 1) % 2));
        const q = &p.pipes[slot];
        if (!q.used or (q.generation & 0x3FFF) != ((value >> 16) & 0x3FFF)) return null;
        const open = switch (end) {
            .read => q.read_open,
            .write => q.write_open,
        };
        return if (open) .{ .slot = slot, .end = end } else null;
    }

    /// A new pipe with both ends open, or null when all are in use.
    pub fn create(p: *Pipes, read_node: u8, write_node: u8) error{OutOfMemory}!?u8 {
        if (p.pool.len == 0) p.pool = try p.gpa.alloc(u8, pipes_max * capacity);
        for (&p.pipes, 0..) |*q, i| {
            if (q.used) continue;
            q.* = .{
                .generation = q.generation +% 1,
                .used = true,
                .read_open = true,
                .write_open = true,
                .read_refs = 1,
                .write_refs = 1,
                .read_node = read_node,
                .write_node = write_node,
            };
            return @intCast(i);
        }
        return null;
    }

    /// One more holder of an open end (a child given it as a stream).
    pub fn dup(p: *Pipes, r: Ref) error{SystemResources}!void {
        const q = &p.pipes[r.slot];
        const refs = switch (r.end) {
            .read => &q.read_refs,
            .write => &q.write_refs,
        };
        if (refs.* == std.math.maxInt(u8)) return error.SystemResources;
        refs.* += 1;
    }

    /// One holder lets go of an end; the end closes with the last.
    pub fn close(p: *Pipes, r: Ref) void {
        const q = &p.pipes[r.slot];
        switch (r.end) {
            .read => {
                q.read_refs -|= 1;
                if (q.read_refs == 0) q.read_open = false;
            },
            .write => {
                q.write_refs -|= 1;
                if (q.write_refs == 0) q.write_open = false;
            },
        }
        if (!q.read_open and !q.write_open) {
            q.used = false;
            q.head = 0;
            q.len = 0;
        }
    }

    /// Closes every end held on `node` (a node crash).
    pub fn closeNode(p: *Pipes, node: u8) void {
        for (&p.pipes, 0..) |*q, i| {
            if (!q.used) continue;
            if (q.read_open and q.read_node == node) {
                q.read_refs = 1;
                p.close(.{ .slot = @intCast(i), .end = .read });
            }
            if (q.used and q.write_open and q.write_node == node) {
                q.write_refs = 1;
                p.close(.{ .slot = @intCast(i), .end = .write });
            }
        }
    }

    /// Open ends held on `node` (the leak check).
    pub fn openEndsOn(p: *const Pipes, node: u8) u32 {
        var n: u32 = 0;
        for (p.pipes) |q| {
            if (!q.used) continue;
            n += @intFromBool(q.read_open and q.read_node == node);
            n += @intFromBool(q.write_open and q.write_node == node);
        }
        return n;
    }

    fn buf(p: *Pipes, slot: u8) []u8 {
        return p.pool[@as(usize, slot) * capacity ..][0..capacity];
    }

    pub const ReadResult = union(enum) { data: usize, end, would_block };

    /// Copies queued bytes into `data`.
    pub fn read(p: *Pipes, slot: u8, data: []const []u8) ReadResult {
        const q = &p.pipes[slot];
        var want: usize = 0;
        for (data) |d| want += d.len;
        if (want == 0) return .{ .data = 0 };
        if (q.len == 0) return if (q.write_open) .would_block else .end;
        const b = p.buf(slot);
        var n: usize = 0;
        for (data) |d| {
            var i: usize = 0;
            while (i < d.len and q.len > 0) : (i += 1) {
                d[i] = b[q.head];
                q.head = (q.head + 1) % capacity;
                q.len -= 1;
                n += 1;
            }
            if (q.len == 0) break;
        }
        return .{ .data = n };
    }

    pub const WriteResult = union(enum) { written: usize, broken, would_block };

    /// Queues as many of `bytes` as fit.
    pub fn write(p: *Pipes, slot: u8, bytes: []const u8) WriteResult {
        const q = &p.pipes[slot];
        if (!q.read_open) return .broken;
        if (bytes.len == 0) return .{ .written = 0 };
        const room = capacity - q.len;
        if (room == 0) return .would_block;
        const n = @min(room, bytes.len);
        const b = p.buf(slot);
        for (bytes[0..n]) |c| {
            b[(q.head + q.len) % capacity] = c;
            q.len += 1;
        }
        return .{ .written = n };
    }
};

const testing = std.testing;

test "pipe: bytes in order, a full pipe blocks, a closed reader breaks it" {
    var p: Pipes = .init(testing.allocator);
    defer p.deinit();
    const slot = (try p.create(0, 0)).?;
    const r = p.encode(slot, .read);
    const w = p.encode(slot, .write);
    try testing.expect(r != w and Pipes.isPipeValue(r) and Pipes.isPipeValue(w));
    try testing.expect(!Pipes.isPipeValue(0x3FFF_FFFF) and !Pipes.isPipeValue(0x4000_8001));
    try testing.expectEqual(Pipes.Ref{ .slot = slot, .end = .write }, p.decode(w).?);

    var out: [4]u8 = undefined;
    try testing.expectEqual(Pipes.ReadResult.would_block, p.read(slot, &.{&out}));
    try testing.expectEqual(Pipes.WriteResult{ .written = 3 }, p.write(slot, "abc"));
    try testing.expectEqual(Pipes.ReadResult{ .data = 3 }, p.read(slot, &.{&out}));
    try testing.expectEqualStrings("abc", out[0..3]);

    var big: [capacity + 10]u8 = @splat(7);
    try testing.expectEqual(Pipes.WriteResult{ .written = capacity }, p.write(slot, &big));
    try testing.expectEqual(Pipes.WriteResult.would_block, p.write(slot, "x"));

    p.close(p.decode(r).?);
    try testing.expect(p.decode(r) == null);
    try testing.expectEqual(Pipes.WriteResult.broken, p.write(slot, "x"));
    p.close(p.decode(w).?);
    try testing.expect(p.pristine());
    // A handle of the closed pipe does not name the next one in its slot.
    const again = (try p.create(0, 0)).?;
    try testing.expectEqual(slot, again);
    try testing.expect(p.decode(w) == null);
}

test "pipe: a duplicated end closes with its last holder" {
    var p: Pipes = .init(testing.allocator);
    defer p.deinit();
    const slot = (try p.create(0, 0)).?;
    const w: Pipes.Ref = .{ .slot = slot, .end = .write };
    try p.dup(w);
    p.close(w);
    try testing.expect(p.decode(p.encode(slot, .write)) != null);
    _ = p.write(slot, "x");
    p.close(w);
    var out: [2]u8 = undefined;
    try testing.expectEqual(Pipes.ReadResult{ .data = 1 }, p.read(slot, &.{&out}));
    try testing.expectEqual(Pipes.ReadResult.end, p.read(slot, &.{&out}));
}

test "pipe: end of stream once the writer is closed and the bytes are read" {
    var p: Pipes = .init(testing.allocator);
    defer p.deinit();
    const slot = (try p.create(0, 0)).?;
    _ = p.write(slot, "hi");
    p.close(.{ .slot = slot, .end = .write });
    var out: [8]u8 = undefined;
    try testing.expectEqual(Pipes.ReadResult{ .data = 2 }, p.read(slot, &.{&out}));
    try testing.expectEqual(Pipes.ReadResult.end, p.read(slot, &.{&out}));
}
