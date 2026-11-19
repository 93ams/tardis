//! Differential test of the filesystem model (plan3.md A2): the same
//! random sequences of operations run against the simulated filesystem,
//! with no faults, and against the real one this test runs on, and every
//! result is compared: the bytes read, the kind and size a stat gives,
//! and the error an operation fails with.
//!
//! The persona is the host's: NTFS on Windows, ext4 on Linux, APFS on
//! macOS. What the two are known to disagree on is listed in `deliberate`,
//! with the reason; anything else is a failure.

const std = @import("std");
const builtin = @import("builtin");
const tardis = @import("../root.zig");
const Io = std.Io;
const Env = tardis.Env;
const testing = std.testing;

const host_persona: tardis.Persona = switch (builtin.os.tag) {
    .windows => .windows_ntfs,
    .macos => .macos_apfs,
    else => .linux_ext4,
};

/// The paths an operation may name: files, a directory, files in it, and
/// a path whose parent does not exist.
const names = [_][]const u8{ "a", "b", "c", "d", "d/x", "d/y", "e/z" };

const Kind = enum {
    write,
    read,
    delete,
    make_dir,
    delete_dir,
    rename,
    stat,
    /// Through an open handle: write or read at an offset, set the length.
    write_at,
    read_at,
    set_length,
    /// Create a file that must not exist yet.
    create_new,
    access,
    hard_link,
    /// POSIX hosts only: making a symbolic link needs a privilege on
    /// Windows.
    sym_link,
    read_link,
};

const Op = struct {
    kind: Kind,
    name: u8,
    other: u8,
    len: u8,
    fill: u8,
};

/// What an operation gave: an error's name, or what it returned.
const Result = struct {
    err: ?[]const u8 = null,
    len: u64 = 0,
    sum: u64 = 0,
    is_dir: bool = false,

    fn eql(a: Result, b: Result) bool {
        if (a.err != null or b.err != null) {
            if (a.err == null or b.err == null) return false;
            return std.mem.eql(u8, a.err.?, b.err.?);
        }
        return a.len == b.len and a.sum == b.sum and a.is_dir == b.is_dir;
    }
};

fn apply(io: Io, dir: Io.Dir, op: Op) Result {
    const name = names[op.name];
    switch (op.kind) {
        .write => {
            var data: [64]u8 = undefined;
            @memset(data[0..op.len], op.fill);
            dir.writeFile(io, .{ .sub_path = name, .data = data[0..op.len] }) catch |e| return .{ .err = @errorName(e) };
            return .{};
        },
        .read => {
            var buf: [128]u8 = undefined;
            const got = dir.readFile(io, name, &buf) catch |e| return .{ .err = @errorName(e) };
            var sum: u64 = 0;
            for (got) |b| sum += b;
            return .{ .len = got.len, .sum = sum };
        },
        .delete => {
            dir.deleteFile(io, name) catch |e| return .{ .err = @errorName(e) };
            return .{};
        },
        .make_dir => {
            dir.createDir(io, name, .default_dir) catch |e| return .{ .err = @errorName(e) };
            return .{};
        },
        .delete_dir => {
            dir.deleteDir(io, name) catch |e| return .{ .err = @errorName(e) };
            return .{};
        },
        .rename => {
            dir.rename(name, dir, names[op.other], io) catch |e| return .{ .err = @errorName(e) };
            return .{};
        },
        .write_at => {
            var f = dir.openFile(io, name, .{ .mode = .read_write }) catch |e| return .{ .err = @errorName(e) };
            defer f.close(io);
            var data: [64]u8 = undefined;
            @memset(data[0..op.len], op.fill);
            f.writePositionalAll(io, data[0..op.len], op.other * 7) catch |e| return .{ .err = @errorName(e) };
            return .{ .len = f.length(io) catch |e| return .{ .err = @errorName(e) } };
        },
        .read_at => {
            var f = dir.openFile(io, name, .{}) catch |e| return .{ .err = @errorName(e) };
            defer f.close(io);
            var buf: [48]u8 = undefined;
            const n = f.readPositionalAll(io, &buf, op.other * 7) catch |e| return .{ .err = @errorName(e) };
            var sum: u64 = 0;
            for (buf[0..n]) |b| sum += b;
            return .{ .len = n, .sum = sum };
        },
        .set_length => {
            var f = dir.openFile(io, name, .{ .mode = .read_write }) catch |e| return .{ .err = @errorName(e) };
            defer f.close(io);
            f.setLength(io, op.len) catch |e| return .{ .err = @errorName(e) };
            return .{ .len = f.length(io) catch |e| return .{ .err = @errorName(e) } };
        },
        .create_new => {
            var f = dir.createFile(io, name, .{ .exclusive = true }) catch |e| return .{ .err = @errorName(e) };
            f.close(io);
            return .{};
        },
        .access => {
            dir.access(io, name, .{}) catch |e| return .{ .err = @errorName(e) };
            return .{};
        },
        .hard_link => {
            dir.hardLink(name, dir, names[op.other], io, .{}) catch |e| return .{ .err = @errorName(e) };
            return .{};
        },
        .sym_link => {
            // The target is relative to the link's directory; plain names
            // only, so the same text means the same file on both sides.
            dir.symLink(io, names[op.other % 3], name, .{}) catch |e| return .{ .err = @errorName(e) };
            return .{};
        },
        .read_link => {
            var buf: [64]u8 = undefined;
            const n = dir.readLink(io, name, &buf) catch |e| return .{ .err = @errorName(e) };
            var sum: u64 = 0;
            for (buf[0..n]) |b| sum += b;
            return .{ .len = n, .sum = sum };
        },
        .stat => {
            const st = dir.statFile(io, name, .{}) catch |e| return .{ .err = @errorName(e) };
            const is_dir = st.kind == .directory;
            // A directory's size is the filesystem's business.
            return .{ .len = if (is_dir) 0 else st.size, .is_dir = is_dir };
        },
    }
}

/// A disagreement that is known and accepted, with why.
const Deliberate = struct {
    kind: Kind,
    simulated: ?[]const u8,
    real: ?[]const u8,
    why: []const u8,
};

const deliberate = [_]Deliberate{};

fn accepted(kind: Kind, sim: Result, real: Result) bool {
    for (deliberate) |d| {
        if (d.kind != kind) continue;
        const sim_ok = if (d.simulated) |e| sim.err != null and std.mem.eql(u8, sim.err.?, e) else sim.err == null;
        const real_ok = if (d.real) |e| real.err != null and std.mem.eql(u8, real.err.?, e) else real.err == null;
        if (sim_ok and real_ok) return true;
    }
    return false;
}

var real_root: Io.Dir = undefined;
var sequences: u32 = 0;
var operations: u32 = 0;
var mismatches: u32 = 0;
const ops_per_sequence = 32;

fn body(env: *Env) !void {
    var prng: std.Random.DefaultPrng = .init(env.seed);
    const random = prng.random();
    var sub: [24]u8 = undefined;
    const sub_name = try std.fmt.bufPrint(&sub, "s{d}", .{sequences});
    sequences += 1;
    const real_io = testing.io;
    try real_root.createDir(real_io, sub_name, .default_dir);
    var real = try real_root.openDir(real_io, sub_name, .{});
    defer real.close(real_io);

    for (0..ops_per_sequence) |step| {
        const op: Op = .{
            .kind = random.enumValue(Kind),
            .name = random.uintLessThan(u8, names.len),
            .other = random.uintLessThan(u8, names.len),
            .len = random.uintLessThan(u8, 64),
            .fill = random.int(u8),
        };
        // Moving a directory into itself: on Windows the kernel answers
        // INVALID_PARAMETER, which Zig's std treats as a bug in the
        // caller and panics on. Not generated.
        if (op.kind == .rename and std.mem.startsWith(u8, names[op.other], names[op.name]) and names[op.other].len > names[op.name].len) continue;
        // Zig's std does not make hard links on Windows (it answers
        // OperationUnsupported); the model's NTFS does, as NTFS does.
        // On POSIX a symbolic link can make the destination's directory an
        // alias of the source, which is the same move into itself.
        if (builtin.os.tag != .windows and op.kind == .rename and std.mem.indexOfScalar(u8, names[op.other], '/') != null and std.mem.indexOfScalar(u8, names[op.name], '/') == null) continue;
        if (builtin.os.tag == .windows and (op.kind == .sym_link or op.kind == .read_link or op.kind == .hard_link)) continue;
        const sim_result = apply(env.io, env.dir, op);
        const real_result = apply(real_io, real, op);
        operations += 1;
        if (sim_result.eql(real_result) or accepted(op.kind, sim_result, real_result)) continue;
        mismatches += 1;
        if (mismatches <= 12) std.debug.print(
            "diff_fs: seed 0x{x} step {d}: {t} {s} (other {s}, {d} bytes): simulated {s} len {d} dir {}, real {s} len {d} dir {}\n",
            .{ env.seed, step, op.kind, names[op.name], names[op.other], op.len, sim_result.err orelse "ok", sim_result.len, sim_result.is_dir, real_result.err orelse "ok", real_result.len, real_result.is_dir },
        );
        // Later steps of this sequence start from different states.
        return;
    }
}

test "diff_fs: the simulated filesystem agrees with the real one on random operation sequences" {
    // With the security layer on every check (`-Dsec`) an attacker swaps
    // paths between a check and a use: not the model alone.
    if (tardis.security_by_default) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    real_root = tmp.dir;
    sequences = 0;
    operations = 0;
    mismatches = 0;
    try tardis.check(testing.allocator, body, .{
        .iterations = 2000,
        .personas = &.{host_persona},
        // The model alone: no faults, no latency.
        .faults = .{ .short_io_ppm = 0, .spurious_wakeup_ppm = 0, .io_latency_min_ns = 0, .io_latency_max_ns = 0, .datagram_loss_ppm = 0, .datagram_duplicate_ppm = 0 },
        // The real calls run on the task's stack, and Windows' path
        // conversion alone wants more than the default 256 KiB.
        .limits = .{ .fiber_stack_bytes = 4 << 20, .tasks_max = 4 },
        .determinism_check_every = 0,
        .warm_restore = false,
    });
    if (mismatches != 0) {
        std.debug.print("diff_fs: {d} of {d} sequences disagreed ({d} operations compared)\n", .{ mismatches, sequences, operations });
        return error.ModelDisagreesWithHost;
    }
}
