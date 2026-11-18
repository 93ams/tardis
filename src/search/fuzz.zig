//! Comptime structure-aware input generation (plan §5.3).

const std = @import("std");
const decide = @import("../sim/decide.zig");

pub const depth_max = 8;

pub const Generator = struct {
    decider: *decide.Decider,
    allocator: std.mem.Allocator,
    slice_len_max: u32,

    pub fn int(g: *Generator, comptime T: type) T {
        return generateInt(g, T);
    }

    pub fn uniform(g: *Generator, n: u64) u64 {
        return g.decider.uniform(.fuzz, n);
    }

    pub fn boolean(g: *Generator) bool {
        return g.decider.boolean(.fuzz);
    }

    pub fn bytes(g: *Generator, buffer: []u8) void {
        g.decider.fill(.fuzz, buffer);
    }

    pub fn value(g: *Generator, comptime T: type) error{OutOfMemory}!T {
        return generate(g, T, 0);
    }

    fn sliceLen(g: *Generator) usize {
        const max: u64 = g.slice_len_max;
        if (max == 0) return 0;
        // Half the time short (<= 16), otherwise up to the cap.
        if (g.decider.boolean(.fuzz)) return @intCast(g.decider.uniform(.fuzz, @min(max, 16) + 1));
        return @intCast(g.decider.uniform(.fuzz, max + 1));
    }
};

fn generateInt(g: *Generator, comptime T: type) T {
    const info = @typeInfo(T).int;
    if (info.bits == 0) return 0;
    const U = @Int(.unsigned, info.bits);
    // ~12% boundary values.
    // ~12% boundary values. A draw of 0 (benign, for shrinking) takes the
    // ordinary path, whose own 0 then yields the value 0.
    if (g.decider.uniform(.fuzz, 8) == 7) {
        return switch (g.decider.uniform(.fuzz, 5)) {
            0 => 0,
            1 => if (info.bits == 1 and info.signedness == .signed) 0 else 1,
            2 => std.math.maxInt(T),
            3 => std.math.minInt(T),
            else => if (info.signedness == .signed) -1 else std.math.maxInt(T) - 1,
        };
    }
    var raw: U = 0;
    if (info.bits <= 64) {
        raw = @truncate(g.decider.next(.fuzz));
    } else {
        var buf: [@sizeOf(U)]u8 = undefined;
        g.decider.fill(.fuzz, &buf);
        raw = @truncate(std.mem.readInt(@Int(.unsigned, @sizeOf(U) * 8), &buf, .little));
    }
    return @bitCast(raw);
}

fn generate(g: *Generator, comptime T: type, comptime depth: u32) error{OutOfMemory}!T {
    if (comptime hasGenerateHook(T)) return T.tardisGenerate(g);
    switch (@typeInfo(T)) {
        .void => return {},
        .bool => return g.decider.boolean(.fuzz),
        .int => return generateInt(g, T),
        .float => |f| {
            const Bits = @Int(.unsigned, f.bits);
            // ~12% boundary values. A draw of 0 (benign, for shrinking) takes the
            // ordinary path, whose own 0 then yields the value 0.
            if (g.decider.uniform(.fuzz, 8) == 7) {
                return switch (g.decider.uniform(.fuzz, 5)) {
                    0 => 0,
                    1 => -0.0,
                    2 => std.math.inf(T),
                    3 => -std.math.inf(T),
                    else => std.math.nan(T),
                };
            }
            const raw: Bits = @truncate(g.decider.next(.fuzz));
            return @bitCast(raw);
        },
        .@"enum" => |e| {
            if (e.mode != .exhaustive) return @fromBackingInt(@intCast(generateInt(g, e.tag_type)));
            const fields = e.field_names;
            const pick = g.decider.uniform(.fuzz, fields.len);
            inline for (fields, 0..) |name, i| {
                if (i == pick) return @field(T, name);
            }
            unreachable;
        },
        .optional => |o| {
            if (depth >= depth_max) return null;
            if (g.decider.uniform(.fuzz, 4) == 0) return null;
            return try generate(g, o.child, depth + 1);
        },
        .array => |a| {
            var out: T = undefined;
            for (&out) |*elem| elem.* = try generate(g, a.child, depth + 1);
            return out;
        },
        .@"struct" => |s| {
            var out: T = undefined;
            inline for (s.field_names, s.field_types) |name, FT| {
                @field(out, name) = try generate(g, FT, depth + 1);
            }
            return out;
        },
        .@"union" => |u| {
            if (u.tag_type == null) @compileError("tardis.fuzz: untagged unions are not supported: " ++ @typeName(T));
            const pick = g.decider.uniform(.fuzz, u.field_names.len);
            inline for (u.field_names, u.field_types, 0..) |name, FT, i| {
                if (i == pick) return @unionInit(T, name, try generate(g, FT, depth + 1));
            }
            unreachable;
        },
        .pointer => |p| switch (p.size) {
            .slice => {
                const len = if (depth >= depth_max) 0 else g.sliceLen();
                const buf = try g.allocator.alloc(p.child, len);
                if (p.child == u8) {
                    g.decider.fill(.fuzz, buf);
                } else {
                    for (buf) |*elem| elem.* = try generate(g, p.child, depth + 1);
                }
                return buf;
            },
            .one => {
                if (depth >= depth_max) @compileError("tardis.fuzz: depth limit reached at non-optional pointer " ++ @typeName(T));
                const ptr = try g.allocator.create(p.child);
                ptr.* = try generate(g, p.child, depth + 1);
                return ptr;
            },
            else => @compileError("tardis.fuzz: unsupported pointer type " ++ @typeName(T)),
        },
        else => @compileError("tardis.fuzz: unsupported type " ++ @typeName(T)),
    }
}

fn hasGenerateHook(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum" => @hasDecl(T, "tardisGenerate"),
        else => false,
    };
}

test "generate composite types deterministically" {
    const Msg = union(enum) {
        put: struct { key: u3, val: u64 },
        get: struct { key: u3 },
        blob: []const u8,
        none,
    };
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    var d1 = decide.Decider.init(5);
    var d2 = decide.Decider.init(5);
    var g1: Generator = .{ .decider = &d1, .allocator = arena.allocator(), .slice_len_max = 64 };
    var g2: Generator = .{ .decider = &d2, .allocator = arena.allocator(), .slice_len_max = 64 };
    var seen_tags: [4]bool = @splat(false);
    var i: u32 = 0;
    while (i < 200) : (i += 1) {
        const a = try g1.value(Msg);
        const b = try g2.value(Msg);
        try std.testing.expectEqual(std.meta.activeTag(a), std.meta.activeTag(b));
        seen_tags[@backingInt(std.meta.activeTag(a))] = true;
        switch (a) {
            .blob => |s| {
                try std.testing.expect(s.len <= 64);
                try std.testing.expectEqualSlices(u8, s, b.blob);
            },
            .put => |p| try std.testing.expectEqual(p.val, b.put.val),
            else => {},
        }
    }
    for (seen_tags) |t| try std.testing.expect(t);
}

test "custom generation hook" {
    const Even = struct {
        n: u32,
        pub fn tardisGenerate(g: *Generator) error{OutOfMemory}!@This() {
            return .{ .n = g.int(u32) & ~@as(u32, 1) };
        }
    };
    var d = decide.Decider.init(1);
    var g: Generator = .{ .decider = &d, .allocator = std.testing.allocator, .slice_len_max = 8 };
    var i: u32 = 0;
    while (i < 50) : (i += 1) {
        const e = try g.value(Even);
        try std.testing.expectEqual(@as(u32, 0), e.n % 2);
    }
}
