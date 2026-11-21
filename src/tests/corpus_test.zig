//! E4 (plan3.md): what a campaign keeps for the next one.

const std = @import("std");
const tardis = @import("../root.zig");
const Env = tardis.Env;
const testing = std.testing;
const gpa = testing.allocator;

/// The lock of `explore_test.zig`: five consecutive 1-in-16 choices.
fn combinationLock(env: *Env) !void {
    const code = [_]u8{ 7, 2, 13, 5, 11 };
    var depth: u64 = 0;
    for (code) |digit| {
        const d = (try env.fuzz(u8)) % 16;
        if (d != digit) break;
        depth += 1;
        env.cover("depth", depth);
    }
    try env.always("the lock stays shut", depth < code.len);
}

fn tmpPath(tmp: *const testing.TmpDir, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, ".zig-cache/tmp/{s}", .{&tmp.sub_path}) catch unreachable;
}

fn corpusFiles(tmp: *testing.TmpDir) !usize {
    var n: usize = 0;
    var it = tmp.dir.iterate();
    while (try it.next(testing.io)) |e| {
        if (std.mem.endsWith(u8, e.name, ".corpus")) n += 1;
        // A save leaves no temporary file behind.
        try testing.expect(!std.mem.endsWith(u8, e.name, ".tmp"));
    }
    return n;
}

/// Opens the lock across campaigns of `iterations` each, every one with a
/// new campaign seed (as the nightly salt gives); returns the campaign that
/// opened it, or null after `campaigns`.
fn campaignsToOpen(dir: ?[]const u8, iterations: u32, campaigns: u32) !?u32 {
    for (0..campaigns) |c| {
        tardis.check(gpa, combinationLock, .{
            .iterations = iterations,
            .campaign_seed = 0xC0FFEE + c,
            .explore = .guided,
            .determinism_check_every = 0,
            .report = false,
            .shrink = false,
            .corpus_dir = dir,
            .corpus_name = "lock.corpus",
        }) catch |err| {
            try testing.expectEqual(error.AssertionFailed, err);
            return @intCast(c);
        };
    }
    return null;
}

test "corpus: guided campaigns that keep their corpus open a lock that the same campaigns without it do not" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var buf: [128]u8 = undefined;
    const dir = tmpPath(&tmp, &buf);
    // A campaign of 300 iterations starting empty never gets past the
    // first digits. Keeping the corpus, the campaigns reach the fourth
    // digit by the third, and then go on mutating from it (measured: the
    // 24th campaign opens the lock, about 7000 runs in all; one campaign
    // needs about as many, `explore_test.zig`).
    try testing.expectEqual(@as(?u32, null), try campaignsToOpen(null, 300, 30));
    const opened = try campaignsToOpen(dir, 300, 30);
    try testing.expect(opened != null);
    try testing.expect(opened.? > 2);
    try testing.expectEqual(@as(usize, 1), try corpusFiles(&tmp));
}

var fixed = false;

/// Fails for one input in 64 until `fixed`.
fn rareBug(env: *Env) !void {
    const x = try env.fuzz(u8);
    if (!fixed) try env.always("x is not a multiple of 64", x % 64 != 0);
}

fn runRare(dir: []const u8, iterations: u32, seed: u64) !void {
    return tardis.check(gpa, rareBug, .{
        .iterations = iterations,
        .campaign_seed = seed,
        .personas = &.{ .linux_ext4, .windows_ntfs },
        .report = false,
        .shrink = false,
        .corpus_dir = dir,
    });
}

test "corpus: a failed run is run first by the next campaign until it passes" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var buf: [128]u8 = undefined;
    const dir = tmpPath(&tmp, &buf);
    fixed = false;
    defer fixed = false;

    try testing.expectError(error.AssertionFailed, runRare(dir, 2000, 1));
    try testing.expectEqual(@as(usize, 1), try corpusFiles(&tmp));
    // No iterations of its own: only the kept run, which fails again.
    try testing.expectError(error.AssertionFailed, runRare(dir, 0, 2));
    try testing.expectError(error.AssertionFailed, runRare(dir, 0, 3));
    // Fixed: the kept run passes and is dropped.
    fixed = true;
    try runRare(dir, 0, 4);
    fixed = false;
    try runRare(dir, 0, 5);
    try testing.expectEqual(@as(usize, 1), try corpusFiles(&tmp));
}

test "corpus: a damaged file is replaced, and a seed replay does not touch the file" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var buf: [128]u8 = undefined;
    const dir = tmpPath(&tmp, &buf);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "lock.corpus", .data = "not a corpus" });
    try testing.expectEqual(@as(?u32, null), try campaignsToOpen(dir, 50, 1));
    const bytes = try tmp.dir.readFileAlloc(testing.io, "lock.corpus", gpa, .limited(1 << 20));
    defer gpa.free(bytes);
    try testing.expect(std.mem.startsWith(u8, bytes, "TARDISK1"));

    // Replaying a seed keeps nothing.
    fixed = true;
    defer fixed = false;
    try tardis.check(gpa, rareBug, .{ .seed = 0, .report = false, .corpus_dir = dir });
    try testing.expectEqual(@as(usize, 1), try corpusFiles(&tmp));
}

test "corpus: the default file name follows the test, and two checks in one test keep two files" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var buf: [128]u8 = undefined;
    const dir = tmpPath(&tmp, &buf);
    fixed = true;
    defer fixed = false;
    try tardis.check(gpa, rareBug, .{ .iterations = 5, .report = false, .corpus_dir = dir });
    try tardis.check(gpa, rareBug, .{ .iterations = 5, .report = false, .corpus_dir = dir });
    try testing.expectEqual(@as(usize, 1), try corpusFiles(&tmp));
    {
        // The test's name from the debug info, or the body's without it.
        var it = tmp.dir.iterate();
        const e = (try it.next(testing.io)).?;
        try testing.expect(std.mem.indexOf(u8, e.name, "default_file_name") != null or std.mem.startsWith(u8, e.name, "rareBug-"));
    }
    try tardis.check(gpa, rareBug, .{ .iterations = 5, .report = false, .corpus_dir = dir, .personas = &.{.windows_ntfs} });
    try testing.expectEqual(@as(usize, 2), try corpusFiles(&tmp));
}
