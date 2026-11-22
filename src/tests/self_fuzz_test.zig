//! Fuzzing the simulator itself (plan3.md A6): random programs against
//! `std.Io`, drawn from the seed, on every persona, with every fault kind
//! on. The program's own results do not matter; what is asserted is the
//! simulator's side of the contract:
//!
//! - it does not panic, whatever the program does;
//! - every run is deterministic: each one is run twice and its trace
//!   compared (`determinism_check_every = 1`);
//! - nothing leaks: a program that closes what it opens leaves no handle,
//!   task or allocation behind, crashes included;
//! - a file synced, in a directory synced, survives a power loss with its
//!   content.

const std = @import("std");
const tardis = @import("../root.zig");
const Io = std.Io;
const Env = tardis.Env;
const testing = std.testing;

const names = [_][]const u8{ "a", "b", "c", "d", "d/x", "d/y", "e/z" };

const Kind = enum {
    write,
    read,
    delete,
    make_dir,
    delete_dir,
    rename,
    stat,
    write_at,
    set_length,
    hard_link,
    sym_link,
    sleep,
    crash,
    tasks,
    durable,
};

fn syncDir(io: Io, dir: Io.Dir) !void {
    var d = try dir.openFile(io, ".", .{});
    defer d.close(io);
    try d.sync(io);
}

/// A side task: a few writes and reads of its own, errors ignored.
fn sideTask(io: Io, dir: Io.Dir, which: u8, fill: u8) Io.Cancelable!void {
    const name = names[which % 3];
    var data: [24]u8 = undefined;
    @memset(&data, fill);
    dir.writeFile(io, .{ .sub_path = name, .data = &data }) catch {};
    var buf: [64]u8 = undefined;
    _ = dir.readFile(io, name, &buf) catch {};
    try io.sleep(.fromMicroseconds(fill), .awake);
    dir.deleteFile(io, name) catch {};
}

/// For the test of the oracle itself: the durable step leaves out the
/// sync of the directory.
var planted_no_dir_sync = false;

fn body(env: *Env) !void {
    const io = env.io;
    const dir = env.dir;
    const steps = 8 + (try env.fuzz(u8)) % 40;
    var crashes: u8 = 0;
    for (0..steps) |_| {
        const kinds = std.enums.values(Kind);
        const kind = kinds[(try env.fuzz(u8)) % kinds.len];
        const name = names[(try env.fuzz(u8)) % names.len];
        const other = names[(try env.fuzz(u8)) % names.len];
        const len = (try env.fuzz(u8)) % 64;
        var fill = try env.fuzz(u8);
        // With the security layer on every check (`-Dsec`), eight bytes of
        // 0xAA leaving the program are taken for undefined memory, which a
        // safe build fills with that byte (plan2.md §3.7): a false alarm
        // for a program that really writes them, as this one would.
        if (tardis.security_by_default and fill == 0xAA) fill = 0xAB;
        var data: [64]u8 = undefined;
        @memset(data[0..len], fill);
        switch (kind) {
            .write => dir.writeFile(io, .{ .sub_path = name, .data = data[0..len] }) catch {},
            .read => {
                var buf: [128]u8 = undefined;
                _ = dir.readFile(io, name, &buf) catch {};
            },
            .delete => dir.deleteFile(io, name) catch {},
            .make_dir => dir.createDir(io, name, .default_dir) catch {},
            .delete_dir => dir.deleteDir(io, name) catch {},
            .rename => dir.rename(name, dir, other, io) catch {},
            .stat => _ = dir.statFile(io, name, .{}) catch {},
            .write_at => {
                var f = dir.openFile(io, name, .{ .mode = .read_write }) catch continue;
                defer f.close(io);
                f.writePositionalAll(io, data[0..len], fill) catch {};
                if (fill & 1 == 0) f.sync(io) catch {};
            },
            .set_length => {
                var f = dir.openFile(io, name, .{ .mode = .read_write }) catch continue;
                defer f.close(io);
                f.setLength(io, len) catch {};
            },
            .hard_link => dir.hardLink(name, dir, other, io, .{}) catch {},
            .sym_link => dir.symLink(io, other, name, .{}) catch {},
            .sleep => try io.sleep(.fromMicroseconds(fill), .awake),
            .crash => {
                if (crashes == 3) continue;
                crashes += 1;
                try env.crashAndReboot(if (fill & 1 == 0) .power_loss else .process_crash);
            },
            .tasks => {
                var group: Io.Group = .init;
                defer group.cancel(io);
                for (0..1 + fill % 3) |i| group.concurrent(io, sideTask, .{ io, dir, @as(u8, @intCast(i)), fill }) catch break;
                try group.await(io);
            },
            .durable => {
                // The one promise checked on content: written, synced, its
                // directory entry synced, then the power goes.
                if (crashes == 3) continue;
                var keep: [16]u8 = undefined;
                @memset(&keep, fill);
                dir.deleteFile(io, "keep") catch {};
                dir.deleteDir(io, "keep") catch {};
                {
                    var f = dir.createFile(io, "keep", .{}) catch continue;
                    defer f.close(io);
                    f.writePositionalAll(io, &keep, 0) catch continue;
                    f.sync(io) catch continue;
                }
                if (!planted_no_dir_sync) syncDir(io, dir) catch continue;
                crashes += 1;
                try env.crashAndReboot(.power_loss);
                // The campaign fails if no run ever gets this far.
                env.sometimes("a synced file went through a power loss", true);
                var buf: [32]u8 = undefined;
                const got = dir.readFile(io, "keep", &buf) catch |err| {
                    try env.always("a synced file in a synced directory is there after a power loss", err != error.FileNotFound);
                    continue;
                };
                try env.always("a synced file keeps its content through a power loss", std.mem.eql(u8, got, &keep));
            },
        }
    }
}

test "self-fuzz: random programs on every persona are deterministic, leak nothing, and keep what they synced" {
    try tardis.check(testing.allocator, body, .{
        .iterations = 300,
        .personas = &.{ .linux_ext4, .linux_xfs, .windows_ntfs, .posix_strict, .macos_apfs, .freebsd_zfs },
        .determinism_check_every = 1,
        .faults = .{ .io_error_ppm = 20_000, .oom_ppm = 5_000 },
    });
}

test "self-fuzz: the same programs on four workers" {
    try tardis.check(testing.allocator, body, .{
        .iterations = 200,
        .personas = &.{ .linux_ext4, .windows_ntfs, .posix_strict },
        .workers = 4,
        .faults = .{ .io_error_ppm = 20_000 },
    });
}

test "fuzz oracles (files): without the directory's sync the durable step fails on strict POSIX" {
    // The planted bug: the same programs, with the one line that makes
    // the file's name durable left out.
    planted_no_dir_sync = true;
    defer planted_no_dir_sync = false;
    try testing.expectError(error.AssertionFailed, tardis.check(testing.allocator, body, .{
        .iterations = 300,
        .personas = &.{.posix_strict},
        .faults = .{ .io_error_ppm = 20_000, .oom_ppm = 5_000 },
        .report = false,
        .shrink = false,
    }));
}

/// The sum, over the runs of a campaign, of a hash of what each run
/// observed: the same for the same runs in any order.
var observed_sum: std.atomic.Value(u64) = .init(0);

fn setup(env: *Env) !void {
    // Another content on each persona: a warm start that brought back
    // another persona's pages would be seen.
    try env.dir.writeFile(env.io, .{ .sub_path = "a", .data = @tagName(env.persona) });
    try env.dir.createDir(env.io, "d", .default_dir);
    try env.dir.writeFile(env.io, .{ .sub_path = "d/x", .data = "nested" });
    try syncDir(env.io, env.dir);
}

/// The random program, then everything the run can see afterwards: each
/// name's content or error, and the clock.
fn observing(env: *Env) !void {
    try body(env);
    var h = std.hash.Wyhash.init(0);
    for (names) |name| {
        var buf: [128]u8 = undefined;
        if (env.dir.readFile(env.io, name, &buf)) |bytes| {
            h.update(bytes);
        } else |err| {
            if (err == error.Canceled) return error.Canceled;
            h.update(@errorName(err));
        }
        h.update(&.{0xFF});
    }
    h.update(std.mem.asBytes(&env.nowNs()));
    h.update(std.mem.asBytes(&env.crashCount()));
    _ = observed_sum.fetchAdd(h.final(), .monotonic);
}

fn observe(o: tardis.Options) !u64 {
    observed_sum.store(0, .monotonic);
    try tardis.check(testing.allocator, observing, o);
    return observed_sum.load(.monotonic);
}

test "simulator agreement: the same runs cold and warm, on one worker and on four" {
    // Each configuration runs the same seeds; a run that saw anything
    // else in any of them changes the sum. Not when the environment
    // changes which runs a check makes, or keeps runs between checks.
    for ([_][]const u8{ "TARDIS_EXPLORE", "TARDIS_PRESET", "TARDIS_SEED", "TARDIS_REPLAY", "TARDIS_CORPUS_DIR", "TARDIS_CAMPAIGN_SALT" }) |name| {
        if (testing.environ.getAlloc(testing.allocator, name)) |value| {
            testing.allocator.free(value);
            return error.SkipZigTest;
        } else |_| {}
    }
    const base: tardis.Options = .{
        .iterations = 200,
        .personas = &.{ .linux_ext4, .windows_ntfs, .posix_strict },
        .setup = setup,
        .warm_restore = false,
        .determinism_check_every = 0,
        .explore = .random,
        .faults = .{ .io_error_ppm = 20_000 },
    };
    const want = try observe(base);
    try testing.expect(want != 0);
    var four = base;
    four.workers = 4;
    try testing.expectEqual(want, try observe(four));
    // The sum does tell runs apart: other seeds give another.
    var other = base;
    other.campaign_seed = 12345;
    try testing.expect(want != try observe(other));

    // Warm starts keep a snapshot of setup per persona, and bring its
    // pages back when the personas take turns. Every 64th use of a
    // snapshot is a check: 7 per persona in 400 runs.
    var cold = base;
    cold.iterations = 400;
    var report: tardis.WarmReport = .{};
    var warm = cold;
    warm.warm_restore = true;
    warm.warm_report = &report;
    const cold_sum = try observe(cold);
    try testing.expectEqual(cold_sum, try observe(warm));
    // The security layer on every check turns warm starts off.
    if (!tardis.security_by_default) {
        try testing.expectEqual(@as(u64, 0), report.mismatches);
        try testing.expect(report.restores > 1100 and report.checks >= 21 and report.active);
    }
    // One persona, where the snapshot's pages never leave the filesystem.
    var one = warm;
    one.personas = &.{.posix_strict};
    var cold_one = one;
    cold_one.warm_restore = false;
    cold_one.warm_report = null;
    try testing.expectEqual(try observe(cold_one), try observe(one));
    if (!tardis.security_by_default) try testing.expect(report.restores > 300 and report.mismatches == 0);
    // On four workers the report says nothing (it is the calling
    // thread's): the same sum, whether or not the workers started warm.
    var warm_four = warm;
    warm_four.workers = 4;
    try testing.expectEqual(cold_sum, try observe(warm_four));
}
