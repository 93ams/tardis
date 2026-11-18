//! Pillars II and III through the engine (plan2.md §4, §5.1; Milestone 5
//! (SEC) week 14). Each planted bug is found, fails the run, and shrinks to
//! at most 5 natural decisions; each fixed version passes.

const std = @import("std");
const tardis = @import("tardis");
const sec = @import("tardis_sec");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const Env = tardis.Env;
const gpa = std.testing.allocator;

fn expectShrunkTo(r: tardis.ShrinkReport, decisions_max: usize) !void {
    try std.testing.expect(r.shrunk);
    if (r.after > decisions_max) {
        std.debug.print("shrunk to {d} decisions (from {d}), want <= {d}\n", .{ r.after, r.before, decisions_max });
        return error.TestUnexpectedResult;
    }
}

// ---------------------------------------------------------------------------
// AB-BA: two lock classes taken in both orders

const accounts_class = 1;
const audit_class = 2;

const Bank = struct {
    accounts: sec.Mutex = .{ .class = accounts_class },
    audit: sec.Mutex = .{ .class = audit_class },
    balance: u64 = 100,
    log_len: u64 = 0,
};

fn transfer(io: Io, bank: *Bank) Io.Cancelable!void {
    try bank.accounts.lock(io);
    defer bank.accounts.unlock(io);
    try io.sleep(.fromMicroseconds(10), .awake);
    try bank.audit.lock(io);
    defer bank.audit.unlock(io);
    bank.balance -= 1;
    bank.log_len += 1;
}

/// The bug: the audit job takes the locks in the other order.
fn auditJob(io: Io, bank: *Bank, inverted: bool) Io.Cancelable!void {
    if (inverted) {
        try bank.audit.lock(io);
        defer bank.audit.unlock(io);
        try bank.accounts.lock(io);
        defer bank.accounts.unlock(io);
        std.debug.assert(bank.balance + bank.log_len == 100);
    } else {
        try bank.accounts.lock(io);
        defer bank.accounts.unlock(io);
        try bank.audit.lock(io);
        defer bank.audit.unlock(io);
        std.debug.assert(bank.balance + bank.log_len == 100);
    }
}

fn bankRun(env: *Env, inverted: bool) !void {
    const io = env.io;
    var bank: Bank = .{};
    // The audit runs after the transfer in virtual time: no schedule
    // deadlocks, so only the lock order shows the bug.
    try transfer(io, &bank);
    try io.sleep(.fromMilliseconds(1), .awake);
    try auditJob(io, &bank, inverted);
}

fn abba(env: *Env) !void {
    return bankRun(env, true);
}

fn ordered(env: *Env) !void {
    return bankRun(env, false);
}

test "lockdep: AB-BA is CWE-833 on a schedule that never deadlocks" {
    var report: sec.engine.Report = .{};
    var shrunk: tardis.ShrinkReport = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, abba, sec.withSecurity(.{
        .report = &report,
        .base = .{ .iterations = 20, .report = false, .shrink_report = &shrunk },
    })));
    try std.testing.expectEqual(@as(u16, 833), report.findings[0].cwe);
    // Held `audit`, took `accounts`, after `accounts -> audit` was seen.
    try std.testing.expectEqual([2]u16{ audit_class, accounts_class }, report.findings[0].detail);
    try expectShrunkTo(shrunk, 5);
    try tardis.check(gpa, ordered, sec.withSecurity(.{ .base = .{ .iterations = 20 } }));
}

// ---------------------------------------------------------------------------
// AB-BA with plain file locks: core reports them, no `tardis_sec.Mutex`

/// Locks `first`, then `second` (lock files), with a yield between, and
/// unlocks by closing.
fn lockBoth(io: Io, dir: Io.Dir, first: []const u8, second: []const u8) !void {
    const a = try dir.createFile(io, first, .{ .truncate = false });
    defer a.close(io);
    try a.lock(io, .exclusive);
    try io.sleep(.fromMicroseconds(10), .awake);
    const b = try dir.createFile(io, second, .{ .truncate = false });
    defer b.close(io);
    try b.lock(io, .exclusive);
    b.unlock(io);
}

fn spoolRun(env: *Env, inverted: bool) !void {
    const io = env.io;
    // The writer job takes queue.lock then index.lock; a cleanup job runs
    // 1 ms of virtual time later, so no schedule deadlocks.
    try lockBoth(io, env.dir, "queue.lock", "index.lock");
    try io.sleep(.fromMilliseconds(1), .awake);
    if (inverted)
        try lockBoth(io, env.dir, "index.lock", "queue.lock")
    else
        try lockBoth(io, env.dir, "queue.lock", "index.lock");
}

fn fileAbba(env: *Env) !void {
    return spoolRun(env, true);
}

fn fileOrdered(env: *Env) !void {
    return spoolRun(env, false);
}

test "lockdep: file locks taken in both orders are CWE-833, reported by core's lock calls" {
    var report: sec.engine.Report = .{};
    var shrunk: tardis.ShrinkReport = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, fileAbba, sec.withSecurity(.{
        .report = &report,
        .base = .{ .iterations = 10, .report = false, .shrink_report = &shrunk },
    })));
    try std.testing.expectEqual(@as(u16, 833), report.findings[0].cwe);
    // Classes from the reserved file range, in first-locked order:
    // index.lock (2nd) held while taking queue.lock (1st).
    const first = sec.engine.races.file_lock_class_first;
    try std.testing.expectEqual([2]u16{ first + 1, first }, report.findings[0].detail);
    try expectShrunkTo(shrunk, 5);
    try tardis.check(gpa, fileOrdered, sec.withSecurity(.{ .base = .{ .iterations = 10 } }));
}

// ---------------------------------------------------------------------------
// Double fetch: a length checked, then read again

const Message = struct {
    len: sec.Shared(u32) = .init(8),
    data: [64]u8 = @splat('m'),
};

/// The peer rewrites the length (it owns the shared memory).
fn peer(msg: *Message) void {
    msg.len.store(200);
}

fn parseMessage(env: *Env, refetch: bool) !void {
    const io = env.io;
    var msg: Message = .{};
    var f = try io.concurrent(peer, .{&msg});
    defer f.await(io);
    const n = msg.len.load();
    if (n > msg.data.len) return; // rejected: fine
    // The bug: the length is read again for the copy.
    const m = if (refetch) msg.len.load() else n;
    try env.always("the copy stays inside the message", m <= msg.data.len);
}

fn doubleFetch(env: *Env) !void {
    return parseMessage(env, true);
}

fn singleFetch(env: *Env) !void {
    return parseMessage(env, false);
}

test "double fetch: the forced switch between two reads exposes it; core alone never does" {
    // No `std.Io` call between the two reads, so core has no point to switch.
    try tardis.check(gpa, doubleFetch, .{ .iterations = 200 });

    var shrunk: tardis.ShrinkReport = .{};
    try std.testing.expectError(error.AssertionFailed, tardis.check(gpa, doubleFetch, sec.withSecurity(.{
        .base = .{ .iterations = 200, .report = false, .shrink_report = &shrunk },
    })));
    try expectShrunkTo(shrunk, 5);
    try tardis.check(gpa, singleFetch, sec.withSecurity(.{ .base = .{ .iterations = 200 } }));
}

// ---------------------------------------------------------------------------
// TOCTOU: stat a path, then open it by name

fn publish(env: *Env, by_handle: bool) !void {
    const io = env.io;
    var key: [32]u8 = undefined;
    io.random(&key);
    try env.dir.writeFile(io, .{ .sub_path = "secret.key", .data = &key });
    sec.markSecret(&key);
    try env.dir.writeFile(io, .{ .sub_path = "report.txt", .data = "quarterly report: all is well." });
    sec.setToctouTarget("secret.key");

    var buf: [64]u8 = undefined;
    var n: usize = 0;
    if (by_handle) {
        // Open once, then check what was opened.
        const file = try env.dir.openFile(io, "report.txt", .{});
        defer file.close(io);
        const st = try file.stat(io);
        if (st.kind != .file) return;
        n = try file.readPositionalAll(io, &buf, 0);
    } else {
        // The bug: check the name, then open the name.
        const st = try env.dir.statFile(io, "report.txt", .{ .follow_symlinks = false });
        if (st.kind != .file) return;
        n = (try env.dir.readFile(io, "report.txt", &buf)).len;
    }
    try env.dir.writeFile(io, .{ .sub_path = "published.txt", .data = buf[0..n] });
}

fn toctou(env: *Env) !void {
    return publish(env, false);
}

fn byHandle(env: *Env) !void {
    return publish(env, true);
}

test "toctou: a symlink swapped in between stat and open leaks the key (CWE-200)" {
    var report: sec.engine.Report = .{};
    var shrunk: tardis.ShrinkReport = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, toctou, sec.withSecurity(.{
        .vfs_toctou_race_ppm = 200_000,
        .report = &report,
        .base = .{ .iterations = 200, .report = false, .shrink_report = &shrunk },
    })));
    try std.testing.expectEqual(@as(u16, 200), report.findings[0].cwe);
    try expectShrunkTo(shrunk, 5);
    try tardis.check(gpa, byHandle, sec.withSecurity(.{ .vfs_toctou_race_ppm = 200_000, .base = .{ .iterations = 200 } }));
}

// ---------------------------------------------------------------------------
// TOCTOU beyond symlinks: a hard link, or a swapped parent directory

/// Publishes `public/report.txt` after checking it. `by_identity` false:
/// `lstat`, open, `lstat` again, which catches a symlink swapped in but not
/// a hard link (still a regular file) or a parent directory swapped for a
/// symlink (no-follow applies to the last component only). `by_identity`
/// true: the opened handle must be the inode the check saw.
fn publishChecked(env: *Env, by_identity: bool) !void {
    const io = env.io;
    var key: [32]u8 = undefined;
    io.random(&key);
    try env.dir.createDirPath(io, "private");
    try env.dir.createDirPath(io, "public");
    try env.dir.writeFile(io, .{ .sub_path = "private/report.txt", .data = &key });
    sec.markSecret(&key);
    try env.dir.writeFile(io, .{ .sub_path = "public/report.txt", .data = "quarterly report: all is well." });
    sec.setToctouTarget("/private/report.txt");
    sec.setToctouDirTarget("/private");

    const path = "public/report.txt";
    const checked = try env.dir.statFile(io, path, .{ .follow_symlinks = false });
    if (checked.kind != .file) return;
    const file = try env.dir.openFile(io, path, .{});
    defer file.close(io);
    if (by_identity) {
        const opened = try file.stat(io);
        if (opened.inode != checked.inode) return;
    } else {
        const again = try env.dir.statFile(io, path, .{ .follow_symlinks = false });
        if (again.kind != .file) return;
    }
    var buf: [64]u8 = undefined;
    const n = try file.readPositionalAll(io, &buf, 0);
    try env.dir.writeFile(io, .{ .sub_path = "published.txt", .data = buf[0..n] });
}

fn checkedTwice(env: *Env) !void {
    return publishChecked(env, false);
}

/// Swaps made in the runs of `checkedIdentity` (one worker).
var identity_swaps: u32 = 0;

fn checkedIdentity(env: *Env) !void {
    defer identity_swaps += sec.raceCounters().toctou_swaps;
    return publishChecked(env, true);
}

test "toctou: a hard link and a swapped parent directory get past a second lstat (CWE-200); an inode check holds" {
    const leaking = [_]sec.engine.ToctouSwaps{ .{ .symlink = false, .parent_symlink = false }, .{ .symlink = false, .hard_link = false } };
    for (leaking) |swaps| {
        var report: sec.engine.Report = .{};
        var shrunk: tardis.ShrinkReport = .{};
        try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, checkedTwice, sec.withSecurity(.{
            .vfs_toctou_race_ppm = 200_000,
            .vfs_toctou_swaps = swaps,
            .report = &report,
            .base = .{ .iterations = 200, .report = false, .shrink_report = &shrunk },
        })));
        try std.testing.expectEqual(@as(u16, 200), report.findings[0].cwe);
        try expectShrunkTo(shrunk, 5);
    }
    // A symlink swap is what the second `lstat` sees.
    try tardis.check(gpa, checkedTwice, sec.withSecurity(.{
        .vfs_toctou_race_ppm = 200_000,
        .vfs_toctou_swaps = .{ .hard_link = false, .parent_symlink = false },
        .base = .{ .iterations = 200 },
    }));
    // Comparing the inode holds against all three, and swaps did happen.
    identity_swaps = 0;
    try tardis.check(gpa, checkedIdentity, sec.withSecurity(.{ .vfs_toctou_race_ppm = 500_000, .base = .{ .iterations = 200 } }));
    try std.testing.expect(identity_swaps > 20);
}

// ---------------------------------------------------------------------------
// TOCTOU into an error path: the checked file becomes a directory

/// Exports `private/report.txt` unless `export.deny` names it. The deny-list
/// is checked to be a regular file, then opened. `fail_open` true (the bug):
/// an open that fails after the check passed is taken to mean "no
/// restrictions". false: it refuses the export.
fn exportGated(env: *Env, fail_open: bool) !void {
    const io = env.io;
    var key: [32]u8 = undefined;
    io.random(&key);
    try env.dir.createDirPath(io, "private");
    try env.dir.writeFile(io, .{ .sub_path = "private/report.txt", .data = &key });
    sec.markSecret(&key);
    try env.dir.writeFile(io, .{ .sub_path = "export.deny", .data = "private/report.txt\n" });

    const checked = try env.dir.statFile(io, "export.deny", .{ .follow_symlinks = false });
    if (checked.kind != .file) return;
    const denied = blk: {
        var buf: [128]u8 = undefined;
        const list = env.dir.readFile(io, "export.deny", &buf) catch {
            if (fail_open) break :blk false;
            return;
        };
        break :blk std.mem.indexOf(u8, list, "private/report.txt") != null;
    };
    if (denied) return;
    var buf: [64]u8 = undefined;
    const data = try env.dir.readFile(io, "private/report.txt", &buf);
    try env.dir.writeFile(io, .{ .sub_path = "published.txt", .data = data });
}

fn failOpen(env: *Env) !void {
    return exportGated(env, true);
}

/// Swaps made in the runs of `failClosed` (one worker).
var closed_swaps: u32 = 0;

fn failClosed(env: *Env) !void {
    defer closed_swaps += sec.raceCounters().toctou_swaps;
    return exportGated(env, false);
}

test "toctou: a deny-list swapped for a directory fails open and leaks the key (CWE-200); failing closed holds" {
    const dir_only: sec.engine.ToctouSwaps = .{ .symlink = false, .hard_link = false, .parent_symlink = false, .directory = true };
    var report: sec.engine.Report = .{};
    var shrunk: tardis.ShrinkReport = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, failOpen, sec.withSecurity(.{
        .vfs_toctou_race_ppm = 200_000,
        .vfs_toctou_swaps = dir_only,
        .report = &report,
        .base = .{ .iterations = 200, .report = false, .shrink_report = &shrunk },
    })));
    try std.testing.expectEqual(@as(u16, 200), report.findings[0].cwe);
    try expectShrunkTo(shrunk, 5);
    // Off by default: with the default swaps (and no targets set) the same
    // program passes.
    try tardis.check(gpa, failOpen, sec.withSecurity(.{ .vfs_toctou_race_ppm = 200_000, .base = .{ .iterations = 200 } }));
    // Failing closed holds, with swaps made in the runs.
    closed_swaps = 0;
    try tardis.check(gpa, failClosed, sec.withSecurity(.{
        .vfs_toctou_race_ppm = 500_000,
        .vfs_toctou_swaps = dir_only,
        .base = .{ .iterations = 200 },
    }));
    try std.testing.expect(closed_swaps > 20);
}

// ---------------------------------------------------------------------------
// Ingress taint: a file name from the network reaching a path (CWE-22)

const files_port = 730;
const requested_names = [_][]const u8{ "report.txt", "../secret.key" };

/// A plain name: 1 to 32 of `[A-Za-z0-9._-]`, not starting with a dot.
fn safeName(name: []const u8) bool {
    if (name.len == 0 or name.len > 32 or name[0] == '.') return false;
    for (name) |c| switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-' => {},
        else => return false,
    };
    return true;
}

/// Serves `files/<name>` for the name a client sends. `validated` false
/// (the bug): the received name goes into the path as is. true: it must be
/// a plain name, and is marked sanitized once checked.
fn fileServer(io: Io, validated: bool) !void {
    const dir = Io.Dir.cwd();
    try dir.createDirPath(io, "files");
    try dir.writeFile(io, .{ .sub_path = "files/report.txt", .data = "quarterly report" });
    try dir.writeFile(io, .{ .sub_path = "secret.key", .data = "not for clients" });
    var server = try any(files_port).listen(io, .{});
    defer server.deinit(io);
    const stream = try server.accept(io);
    defer stream.close(io);
    var rbuf: [64]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    const name = r.interface.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.ReadFailed => return r.err.?,
        else => |e| return e,
    };
    if (validated) {
        if (!safeName(name)) return;
        sec.markSanitized(name);
    }
    var path_buf: [96]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "files/{s}", .{name});
    var buf: [64]u8 = undefined;
    const data = dir.readFile(io, path, &buf) catch return;
    var wbuf: [64]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeAll(data) catch return w.err.?;
    w.interface.flush() catch return w.err.?;
}

fn fetchRun(env: *Env, validated: bool) !void {
    const io = env.io;
    try env.spawnOn(1, fileServer, .{ io, validated });
    try io.sleep(.fromMilliseconds(1), .awake);
    const name = requested_names[(try env.fuzz(u8)) % requested_names.len];
    const stream = try env.address(1, files_port).connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var wbuf: [64]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeAll(name) catch return w.err.?;
    w.interface.writeByte('\n') catch return w.err.?;
    w.interface.flush() catch return w.err.?;
    try io.sleep(.fromMilliseconds(10), .awake);
    if (env.daemonError()) |err| return err;
}

fn rawName(env: *Env) !void {
    return fetchRun(env, false);
}

fn validatedName(env: *Env) !void {
    return fetchRun(env, true);
}

test "ingress taint: a received file name in a path is CWE-22 until validated and marked sanitized" {
    var report: sec.engine.Report = .{};
    var shrunk: tardis.ShrinkReport = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, rawName, sec.withSecurity(.{
        .report = &report,
        .base = .{ .nodes = 2, .iterations = 50, .report = false, .shrink_report = &shrunk },
    })));
    try std.testing.expectEqual(@as(u16, 22), report.findings[0].cwe);
    try std.testing.expectEqual(sec.engine.Kind.tainted_path, report.findings[0].kind);
    try expectShrunkTo(shrunk, 5);
    try tardis.check(gpa, validatedName, sec.withSecurity(.{ .base = .{ .nodes = 2, .iterations = 50 } }));
    // With taint off, nothing looks at the path.
    try tardis.check(gpa, rawName, sec.withSecurity(.{ .taint_paths = false, .base = .{ .nodes = 2, .iterations = 50 } }));
}

test "sink audit: a certification campaign counts every path check and lists each distinct hit" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const config: sec.SecurityConfig = .{ .mode = .certification_eal7, .base = .{ .nodes = 2, .iterations = 20, .report = false } };
    const raw = try sec.certify(gpa, io, rawName, config, .{ .name = "sink audit: raw", .out = tmp.dir });
    defer raw.deinit(gpa);
    try std.testing.expectEqual(@as(?anyerror, error.SecurityViolation), raw.err);
    const path = @backingInt(sec.engine.SinkKind.path);
    // The server checks at least its own two writes and the request each run.
    try std.testing.expect(raw.campaign.sink_checks[path] >= 3 * raw.campaign.runs);
    var buf: [8192]u8 = undefined;
    const text = try raw.bundle.?.readFile(io, "sinks.json", &buf);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"sink\": \"path\", \"cwe\": 22") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"replay\": ") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"hits\": 0, \"distinct\": []") != null); // the other sinks

    var clean_dir = std.testing.tmpDir(.{ .iterate = true });
    defer clean_dir.cleanup();
    const clean = try sec.certify(gpa, io, validatedName, config, .{ .name = "sink audit: validated", .out = clean_dir.dir });
    defer clean.deinit(gpa);
    try std.testing.expectEqual(@as(?anyerror, null), clean.err);
    // A rejected name returns before the read: two checks for those runs.
    try std.testing.expect(clean.campaign.sink_checks[path] >= 2 * clean.campaign.runs);
    const clean_text = try clean.bundle.?.readFile(io, "sinks.json", &buf);
    try std.testing.expect(std.mem.indexOf(u8, clean_text, "\"sink\": \"path\", \"cwe\": 22, \"checks\": ") != null);
    try std.testing.expect(std.mem.indexOf(u8, clean_text, "\"replay\"") == null);
}

/// A warm start: the fork server needs one (`Options.setup`).
fn filesWarmUp(env: *Env) !void {
    try env.dir.createDirPath(env.io, "files");
}

test "sink audit: the same sums and the same sinks.json in one process, through the fork server, and on four workers" {
    // On Linux each iteration runs in a forked child, which sends its sink
    // counts back in the fork header; elsewhere `fork` runs in-process.
    const io = std.testing.io;
    const runs = [_]struct { fork: bool, workers: u32 }{ .{ .fork = false, .workers = 1 }, .{ .fork = true, .workers = 1 }, .{ .fork = true, .workers = 4 } };
    var sums: [runs.len][sec.engine.sink_kinds]u64 = undefined;
    var texts: [runs.len][2048]u8 = undefined;
    var lens: [runs.len]usize = undefined;
    for (runs, 0..) |run, k| {
        var tmp = std.testing.tmpDir(.{ .iterate = true });
        defer tmp.cleanup();
        const config: sec.SecurityConfig = .{ .mode = .certification_eal7, .base = .{
            .nodes = 2,
            .iterations = 20,
            .report = false,
            .setup = filesWarmUp,
            .fork = run.fork,
            .workers = run.workers,
        } };
        const cert = try sec.certify(gpa, io, rawName, config, .{ .name = "sink audit: raw (fork)", .out = tmp.dir });
        defer cert.deinit(gpa);
        try std.testing.expectEqual(@as(?anyerror, error.SecurityViolation), cert.err);
        try std.testing.expectEqual(@as(u64, 20), cert.campaign.runs);
        sums[k] = cert.campaign.sink_checks;
        lens[k] = (try cert.bundle.?.readFile(io, "sinks.json", &texts[k])).len;
    }
    const path = @backingInt(sec.engine.SinkKind.path);
    try std.testing.expect(sums[0][path] >= 3 * 20);
    for (1..runs.len) |k| {
        try std.testing.expectEqualSlices(u64, &sums[0], &sums[k]);
        try std.testing.expectEqualStrings(texts[0][0..lens[0]], texts[k][0..lens[k]]);
    }
}

// ---------------------------------------------------------------------------
// Path confusion: a file server that refuses one name, by comparing names

/// Serves the file a client names. `deny_list` refuses `secret` by name
/// (without a leading `./`, case-insensitively: the careful version for
/// Windows); otherwise only
/// `report.txt` is served, byte for byte (an allow-list). The client asks
/// for the report or for a confusable spelling of the secret, chosen by a
/// keyed fuzz byte.
fn serveFile(env: *Env, secret: []const u8, deny_list: bool) !void {
    const io = env.io;
    var key: [32]u8 = undefined;
    io.random(&key);
    try env.dir.writeFile(io, .{ .sub_path = secret, .data = &key });
    sec.markSecret(&key);
    try env.dir.writeFile(io, .{ .sub_path = "report.txt", .data = "quarterly report: all is well." });

    const spellings = sec.pathConfusions(env.persona, secret);
    const pick = try env.fuzz(u8);
    const request = if (pick % (spellings.len + 1) == 0) "report.txt" else spellings.get(pick % (spellings.len + 1) - 1);

    const bare = if (std.mem.startsWith(u8, request, "./")) request[2..] else request;
    const refused = if (deny_list) std.ascii.eqlIgnoreCase(bare, secret) else !std.mem.eql(u8, request, "report.txt");
    if (refused) return;
    var buf: [64]u8 = undefined;
    const data = env.dir.readFile(io, request, &buf) catch |err| switch (err) {
        error.FileNotFound, error.BadPathName => return,
        else => return err,
    };
    try env.dir.writeFile(io, .{ .sub_path = "published.txt", .data = data });
}

fn denyNtfs(env: *Env) !void {
    return serveFile(env, "secret.key", true);
}
fn denyApfs(env: *Env) !void {
    return serveFile(env, "cl\u{E9}.key", true);
}
fn allowNtfs(env: *Env) !void {
    return serveFile(env, "secret.key", false);
}
fn allowApfs(env: *Env) !void {
    return serveFile(env, "cl\u{E9}.key", false);
}

const confusable_names = [_][]const u8{ "secret.key", "private_key.pem", "cl\u{E9}.key", "Re\u{301}sume\u{301}.txt" };

test "path confusion: every generated spelling opens the same file in core's VFS" {
    const names = confusable_names;
    for ([_]tardis.Persona{ .linux_ext4, .windows_ntfs, .macos_apfs }) |persona| {
        var v = try tardis.vfs.Vfs.init(gpa, .{}, persona);
        defer v.deinit();
        for (names) |name| {
            const want = try v.createFile(tardis.vfs.root_inode, name, .{});
            const spellings = sec.pathConfusions(persona, name);
            try std.testing.expect(spellings.len >= 1);
            for (0..spellings.len) |i| {
                const s = spellings.get(i);
                try std.testing.expect(!std.mem.eql(u8, s, name));
                try std.testing.expectEqual(want, try v.lookup(tardis.vfs.root_inode, s));
            }
        }
    }
    // And through the simulator's `std.Io`, as a program opens them.
    try tardis.check(gpa, struct {
        fn f(env: *Env) !void {
            for (confusable_names) |name| {
                try env.dir.writeFile(env.io, .{ .sub_path = name, .data = name });
                const spellings = sec.pathConfusions(env.persona, name);
                for (0..spellings.len) |i| {
                    var buf: [64]u8 = undefined;
                    try std.testing.expectEqualStrings(name, try env.dir.readFile(env.io, spellings.get(i), &buf));
                }
            }
        }
    }.f, .{ .iterations = 1, .personas = &.{ .linux_ext4, .windows_ntfs, .macos_apfs } });
    try std.testing.expectEqual(@as(usize, 6), sec.pathConfusions(.windows_ntfs, "private_key.pem").len);
    try std.testing.expectEqual(@as(usize, 3), sec.pathConfusions(.macos_apfs, "cl\u{E9}.key").len);
    try std.testing.expectEqual(@as(usize, 1), sec.pathConfusions(.linux_ext4, "secret.key").len);
}

test "path confusion: a deny-list of names leaks the key on NTFS and APFS (CWE-200); an allow-list does not" {
    inline for (.{ .{ denyNtfs, allowNtfs, tardis.Persona.windows_ntfs }, .{ denyApfs, allowApfs, tardis.Persona.macos_apfs } }) |case| {
        var report: sec.engine.Report = .{};
        var shrunk: tardis.ShrinkReport = .{};
        try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, case[0], sec.withSecurity(.{
            .report = &report,
            .base = .{ .iterations = 200, .personas = &.{case[2]}, .report = false, .shrink_report = &shrunk },
        })));
        try std.testing.expectEqual(@as(u16, 200), report.findings[0].cwe);
        try expectShrunkTo(shrunk, 5);
        try tardis.check(gpa, case[1], sec.withSecurity(.{ .base = .{ .iterations = 200, .personas = &.{case[2]} } }));
    }
    // On ext4 the same deny-list holds: the only other spelling there is
    // `./secret.key`, which it strips.
    try tardis.check(gpa, struct {
        fn f(env: *Env) !void {
            return serveFile(env, "secret.key", true);
        }
    }.f, sec.withSecurity(.{ .base = .{ .iterations = 200, .personas = &.{.linux_ext4} } }));
}

// ---------------------------------------------------------------------------
// Equivocation: a two-faced leader against followers that trust it

const Frame = extern struct { index: u32, len: u32, crc: u32 };
const Spec = sec.ByzantineFrameSpec(Frame, .{ .length_field = "len", .checksum_field = "crc" });
const proposal_port = 700;
const echo_port = 701;

fn any(port: u16) IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } };
}

const Committed = struct { value: [3]?u64 = @splat(null) };

fn follower(io: Io, env: *Env, me: tardis.NodeId, committed: *Committed, echo: bool) !void {
    const sock = try any(proposal_port).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    var buf: [64]u8 = undefined;
    const msg = try sock.receive(io, &buf);
    const d = Spec.decode(msg.data) orelse return;
    if (!Spec.isValid(d.header, d.payload) or d.payload.len != 8) return;
    const value = std.mem.readInt(u64, d.payload[0..8], .little);
    if (!echo) {
        committed.value[me] = value; // the bug: trusts the leader alone
        return;
    }
    // Fixed: commit only if the other follower saw the same value.
    const other: tardis.NodeId = if (me == 1) 2 else 1;
    const echo_sock = try any(echo_port).bind(io, .{ .mode = .dgram });
    defer echo_sock.close(io);
    try sock.send(io, &env.address(other, echo_port), d.payload);
    const peer_msg = try echo_sock.receive(io, &buf);
    if (peer_msg.data.len == 8 and std.mem.readInt(u64, peer_msg.data[0..8], .little) == value)
        committed.value[me] = value;
}

fn leaderRun(env: *Env, echo: bool) !void {
    const io = env.io;
    var committed: Committed = .{};
    // Node 0 is two-faced towards node 2: same proposal, one byte flipped,
    // checksum recomputed, so it verifies.
    sec.twoFaced(0, &.{2}, Spec.equivocateFrame(0, 0x01));
    try env.spawnOn(1, follower, .{ io, env, 1, &committed, echo });
    try env.spawnOn(2, follower, .{ io, env, 2, &committed, echo });
    try io.sleep(.fromMilliseconds(1), .awake);

    const sock = try any(0).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    var value: [8]u8 = undefined;
    std.mem.writeInt(u64, &value, 0x1111_2222_3333_4444, .little);
    var frame: [64]u8 = undefined;
    const n = Spec.encode(.{ .index = 1, .len = 8, .crc = Spec.checksumOf(&value) }, &value, &frame);
    try sock.send(io, &env.address(1, proposal_port), frame[0..n]);
    try sock.send(io, &env.address(2, proposal_port), frame[0..n]);
    try io.sleep(.fromMilliseconds(50), .awake);

    const a = committed.value[1];
    const b = committed.value[2];
    try env.always("followers never commit different values for one index", a == null or b == null or a.? == b.?);
}

fn trusting(env: *Env) !void {
    return leaderRun(env, false);
}

fn echoing(env: *Env) !void {
    return leaderRun(env, true);
}

const no_loss: tardis.FaultOptions = .{ .datagram_loss_ppm = 0, .datagram_duplicate_ppm = 0 };

test "equivocation: followers that trust one frame commit different values" {
    var shrunk: tardis.ShrinkReport = .{};
    try std.testing.expectError(error.AssertionFailed, tardis.check(gpa, trusting, sec.withSecurity(.{
        .byzantine_ppm = 500_000,
        .base = .{ .nodes = 3, .iterations = 100, .faults = no_loss, .report = false, .shrink_report = &shrunk },
    })));
    try expectShrunkTo(shrunk, 5);
    try tardis.check(gpa, echoing, sec.withSecurity(.{
        .byzantine_ppm = 500_000,
        .base = .{ .nodes = 3, .iterations = 100, .faults = no_loss },
    }));
}

// The same leader over TCP: one connection per follower, the proposal
// written as one frame. The rewrite applies to the stream's bytes in flight.

const stream_port = 702;

fn streamFollower(io: Io, env: *Env, me: tardis.NodeId, committed: *Committed, echo: bool) !void {
    var server = try any(stream_port).listen(io, .{});
    defer server.deinit(io);
    const stream = try server.accept(io);
    defer stream.close(io);
    var rbuf: [64]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    const frame = r.interface.take(@sizeOf(Frame) + 8) catch |err| switch (err) {
        error.ReadFailed => return r.err.?,
        else => |e| return e,
    };
    const d = Spec.decode(frame) orelse return;
    if (!Spec.isValid(d.header, d.payload) or d.payload.len != 8) return;
    const value = std.mem.readInt(u64, d.payload[0..8], .little);
    if (!echo) {
        committed.value[me] = value; // the bug: trusts the leader alone
        return;
    }
    const other: tardis.NodeId = if (me == 1) 2 else 1;
    const echo_sock = try any(echo_port).bind(io, .{ .mode = .dgram });
    defer echo_sock.close(io);
    try echo_sock.send(io, &env.address(other, echo_port), d.payload);
    var buf: [64]u8 = undefined;
    const peer_msg = try echo_sock.receive(io, &buf);
    if (peer_msg.data.len == 8 and std.mem.readInt(u64, peer_msg.data[0..8], .little) == value)
        committed.value[me] = value;
}

fn streamLeaderRun(env: *Env, echo: bool) !void {
    const io = env.io;
    var committed: Committed = .{};
    sec.twoFaced(0, &.{2}, Spec.equivocateFrame(0, 0x01));
    try env.spawnOn(1, streamFollower, .{ io, env, 1, &committed, echo });
    try env.spawnOn(2, streamFollower, .{ io, env, 2, &committed, echo });
    try io.sleep(.fromMilliseconds(1), .awake);

    var value: [8]u8 = undefined;
    std.mem.writeInt(u64, &value, 0x1111_2222_3333_4444, .little);
    var frame: [64]u8 = undefined;
    const n = Spec.encode(.{ .index = 1, .len = 8, .crc = Spec.checksumOf(&value) }, &value, &frame);
    for ([_]tardis.NodeId{ 1, 2 }) |follower_node| {
        const stream = try env.address(follower_node, stream_port).connect(io, .{ .mode = .stream });
        defer stream.close(io);
        var wbuf: [64]u8 = undefined;
        var w = stream.writer(io, &wbuf);
        w.interface.writeAll(frame[0..n]) catch return w.err.?;
        w.interface.flush() catch return w.err.?;
    }
    try io.sleep(.fromMilliseconds(50), .awake);
    if (env.daemonError()) |err| return err;

    const a = committed.value[1];
    const b = committed.value[2];
    try env.always("followers never commit different values for one index", a == null or b == null or a.? == b.?);
}

fn streamTrusting(env: *Env) !void {
    return streamLeaderRun(env, false);
}

/// Rewrites made in the runs of `streamEchoing` (one worker).
var stream_mutations: u32 = 0;

fn streamEchoing(env: *Env) !void {
    defer stream_mutations += sec.raceCounters().mutations;
    return streamLeaderRun(env, true);
}

test "equivocation over TCP: the rewrite applies to stream bytes in flight" {
    var shrunk: tardis.ShrinkReport = .{};
    try std.testing.expectError(error.AssertionFailed, tardis.check(gpa, streamTrusting, sec.withSecurity(.{
        .byzantine_ppm = 500_000,
        .base = .{ .nodes = 3, .iterations = 100, .faults = no_loss, .report = false, .shrink_report = &shrunk },
    })));
    try expectShrunkTo(shrunk, 5);
    stream_mutations = 0;
    try tardis.check(gpa, streamEchoing, sec.withSecurity(.{
        .byzantine_ppm = 500_000,
        .base = .{ .nodes = 3, .iterations = 100, .faults = no_loss },
    }));
    try std.testing.expect(stream_mutations > 10);
}

// ---------------------------------------------------------------------------
// Replay across a reboot: an actuator that remembers the last command

const Command = extern struct { seq: u32, open: u32 };
const command_port = 710;

/// What the actuator did, in order (owned by the test body: the valve is
/// the physical world and outlives the actuator's reboot).
const Valve = struct {
    applied: [16]u32 = undefined,
    n: usize = 0,

    fn inOrder(v: *const Valve) bool {
        for (1..v.n) |i| if (v.applied[i] <= v.applied[i - 1]) return false;
        return true;
    }
};

/// Applies each command whose sequence number is above the last one
/// applied. `durable` false (the bug): the last number lives in memory and
/// a reboot forgets it. true: it is written to `last_seq` and synced
/// before the command takes effect, and read back at start.
fn actuator(io: Io, valve: *Valve, durable: bool) !void {
    const dir = Io.Dir.cwd();
    var last: u32 = 0;
    var seq_bytes: [4]u8 = undefined;
    if (durable) {
        if (dir.readFile(io, "last_seq", &seq_bytes)) |got| {
            if (got.len == 4) last = std.mem.readInt(u32, got[0..4], .little);
        } else |_| {}
    }
    const sock = try any(command_port).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    var buf: [64]u8 = undefined;
    while (true) {
        const msg = try sock.receive(io, &buf);
        if (msg.data.len != @sizeOf(Command)) continue;
        const cmd = std.mem.bytesToValue(Command, msg.data[0..@sizeOf(Command)]);
        if (cmd.seq <= last) continue;
        last = cmd.seq;
        if (durable) {
            std.mem.writeInt(u32, &seq_bytes, last, .little);
            const f = try dir.createFile(io, "last_seq", .{});
            defer f.close(io);
            try f.writePositionalAll(io, &seq_bytes, 0);
            try f.sync(io);
        }
        if (valve.n < valve.applied.len) {
            valve.applied[valve.n] = cmd.seq;
            valve.n += 1;
        }
    }
}

fn sendCommand(io: Io, env: *Env, sock: Io.net.Socket, seq: u32, open: bool) !void {
    const cmd: Command = .{ .seq = seq, .open = @intFromBool(open) };
    try sock.send(io, &env.address(1, command_port), std.mem.asBytes(&cmd));
    try io.sleep(.fromMilliseconds(5), .awake);
}

fn controlRun(env: *Env, durable: bool) !void {
    const io = env.io;
    var valve: Valve = .{};
    sec.replayer(0, &.{1});
    try env.spawnOn(1, actuator, .{ io, &valve, durable });
    try io.sleep(.fromMilliseconds(1), .awake);
    const sock = try any(0).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    try sendCommand(io, env, sock, 1, true);
    try sendCommand(io, env, sock, 2, false);
    env.crashNode(1, .process_crash);
    try env.spawnOn(1, actuator, .{ io, &valve, durable });
    try io.sleep(.fromMilliseconds(1), .awake);
    try sendCommand(io, env, sock, 3, true);
    try sendCommand(io, env, sock, 4, false);
    try io.sleep(.fromMilliseconds(20), .awake);
    if (env.daemonError()) |err| return err;
    try env.always("each command takes effect once, in order", valve.inOrder());
}

fn forgetful(env: *Env) !void {
    return controlRun(env, false);
}

/// Replays made in the runs of `durableSeq` (one worker).
var durable_replays: u32 = 0;

fn durableSeq(env: *Env) !void {
    defer durable_replays += sec.raceCounters().replays;
    return controlRun(env, true);
}

test "replay: a frame recorded before a reboot is accepted after it unless the sequence number is durable" {
    var shrunk: tardis.ShrinkReport = .{};
    try std.testing.expectError(error.AssertionFailed, tardis.check(gpa, forgetful, sec.withSecurity(.{
        .byzantine_ppm = 500_000,
        .base = .{ .nodes = 2, .iterations = 100, .faults = no_loss, .report = false, .shrink_report = &shrunk },
    })));
    try expectShrunkTo(shrunk, 5);
    durable_replays = 0;
    try tardis.check(gpa, durableSeq, sec.withSecurity(.{
        .byzantine_ppm = 500_000,
        .base = .{ .nodes = 2, .iterations = 100, .faults = no_loss },
    }));
    try std.testing.expect(durable_replays > 20);
    // Without the replayer, the forgetful actuator passes: it is the replay
    // that finds it.
    try tardis.check(gpa, forgetful, sec.withSecurity(.{
        .byzantine_ppm = 0,
        .base = .{ .nodes = 2, .iterations = 100, .faults = no_loss },
    }));
}

// ---------------------------------------------------------------------------
// Length desync in flight: a shortened frame smuggles its tail

const data_kind = 0;
const admin_kind = 7;
const gateway_port = 720;
/// The client's text: ordinary words, then bytes that happen to encode an
/// admin frame. Sent as the payload of one data frame, they are just data.
const smuggled_bytes = @sizeOf(Frame) + 4;

fn clientText(out: []u8) []const u8 {
    const words = "hello ";
    @memcpy(out[0..words.len], words);
    const inner = "halt";
    const n = Spec.encode(.{ .index = admin_kind, .len = inner.len, .crc = Spec.checksumOf(inner) }, inner, out[words.len..]);
    return out[0 .. words.len + n];
}

/// `strict` false (the bug): parses frames back to back until the datagram
/// is used up. true: one frame per datagram, which must use it exactly.
fn gateway(io: Io, executed: *bool, strict: bool) !void {
    const sock = try any(gateway_port).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    var buf: [128]u8 = undefined;
    const msg = try sock.receive(io, &buf);
    var rest = msg.data;
    while (rest.len >= @sizeOf(Frame)) {
        const d = Spec.decode(rest) orelse return;
        if (!Spec.isValid(d.header, d.payload)) return;
        const used = @sizeOf(Frame) + d.payload.len;
        if (strict and used != rest.len) return;
        if (d.header.index == admin_kind) executed.* = true;
        rest = rest[used..];
    }
}

fn smuggleRun(env: *Env, strict: bool) !void {
    const io = env.io;
    var executed = false;
    // On the wire from the proxy (node 0), the data frame's length is cut
    // short by the smuggled frame's size, with the checksum fixed.
    sec.twoFaced(0, &.{1}, Spec.desyncFrame(-@as(i64, smuggled_bytes), true));
    try env.spawnOn(1, gateway, .{ io, &executed, strict });
    try io.sleep(.fromMilliseconds(1), .awake);

    var text_buf: [64]u8 = undefined;
    const text = clientText(&text_buf);
    var frame: [128]u8 = undefined;
    const n = Spec.encode(.{ .index = data_kind, .len = @intCast(text.len), .crc = Spec.checksumOf(text) }, text, &frame);
    const sock = try any(0).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    try sock.send(io, &env.address(1, gateway_port), frame[0..n]);
    try io.sleep(.fromMilliseconds(10), .awake);
    if (env.daemonError()) |err| return err;
    try env.always("a client's text never runs as an admin frame", !executed);
}

fn batchParser(env: *Env) !void {
    return smuggleRun(env, false);
}

/// Rewrites made in the runs of `strictParser` (one worker).
var strict_mutations: u32 = 0;

fn strictParser(env: *Env) !void {
    defer strict_mutations += sec.raceCounters().mutations;
    return smuggleRun(env, true);
}

test "length desync: a frame shortened in flight smuggles an admin frame past a batch parser" {
    var shrunk: tardis.ShrinkReport = .{};
    try std.testing.expectError(error.AssertionFailed, tardis.check(gpa, batchParser, sec.withSecurity(.{
        .byzantine_ppm = 500_000,
        .base = .{ .nodes = 2, .iterations = 100, .faults = no_loss, .report = false, .shrink_report = &shrunk },
    })));
    try expectShrunkTo(shrunk, 5);
    strict_mutations = 0;
    try tardis.check(gpa, strictParser, sec.withSecurity(.{
        .byzantine_ppm = 500_000,
        .base = .{ .nodes = 2, .iterations = 100, .faults = no_loss },
    }));
    try std.testing.expect(strict_mutations > 20);
}

test "frames: desyncFrame shortens the claim, keeps the bytes and fixes the checksum" {
    var text_buf: [64]u8 = undefined;
    const text = clientText(&text_buf);
    var frame: [128]u8 = undefined;
    const n = Spec.encode(.{ .index = data_kind, .len = @intCast(text.len), .crc = Spec.checksumOf(text) }, text, &frame);
    var out: [128]u8 = undefined;
    const m = Spec.desyncFrame(-@as(i64, smuggled_bytes), true)(frame[0..n], &out).?;
    try std.testing.expectEqual(n, m);
    try std.testing.expectEqualSlices(u8, frame[@sizeOf(Frame)..n], out[@sizeOf(Frame)..m]);
    const a = Spec.decode(out[0..m]).?;
    try std.testing.expect(Spec.isValid(a.header, a.payload));
    try std.testing.expectEqual(text.len - smuggled_bytes, a.payload.len);
    const b = Spec.decode(out[@sizeOf(Frame) + a.payload.len .. m]).?;
    try std.testing.expect(Spec.isValid(b.header, b.payload));
    try std.testing.expectEqual(@as(u32, admin_kind), b.header.index);
    // A longer claim cannot have its checksum fixed: left alone.
    try std.testing.expect(Spec.desyncFrame(4, true)(frame[0..n], &out) == null);
    // Without the fix, it goes out and no longer parses.
    const k = Spec.desyncFrame(4, false)(frame[0..n], &out).?;
    try std.testing.expect(Spec.decode(out[0..k]) == null);
}

test "frames: encode, decode, and an equivocated frame that still verifies" {
    var value: [8]u8 = @splat(7);
    var frame: [64]u8 = undefined;
    const n = Spec.encode(.{ .index = 1, .len = 8, .crc = Spec.checksumOf(&value) }, &value, &frame);
    var out: [64]u8 = undefined;
    const m = Spec.equivocateFrame(0, 0x01)(frame[0..n], &out).?;
    const a = Spec.decode(frame[0..n]).?;
    const b = Spec.decode(out[0..m]).?;
    try std.testing.expect(Spec.isValid(a.header, a.payload));
    try std.testing.expect(Spec.isValid(b.header, b.payload));
    try std.testing.expect(!std.mem.eql(u8, a.payload, b.payload));
}

// ---------------------------------------------------------------------------
// Sandbox: capabilities used after the program said its initialization was
// done (§5.2)

const front_port = 740;
const backend_port = 741;

fn backend(io: Io) !void {
    var server = try any(backend_port).listen(io, .{});
    defer server.deinit(io);
    while (true) {
        const stream = try server.accept(io);
        stream.close(io);
    }
}

/// Connects to its backend and listens for clients, then drops both
/// capabilities. `reconnect_late` (the bug): a refresh request (`r`)
/// reconnects, which a production sandbox would refuse. Otherwise it keeps
/// the connection it opened during initialization.
fn frontend(io: Io, upstream_address: IpAddress, reconnect_late: bool) !void {
    var server = try any(front_port).listen(io, .{});
    defer server.deinit(io);
    var upstream = try upstream_address.connect(io, .{ .mode = .stream });
    defer upstream.close(io);
    sec.enterSandbox(.{ .allow_net_connect = false, .allow_net_listen = false });
    const client = try server.accept(io);
    defer client.close(io);
    var rbuf: [16]u8 = undefined;
    var r = client.reader(io, &rbuf);
    const request = r.interface.takeByte() catch |err| switch (err) {
        error.ReadFailed => return r.err.?,
        else => |e| return e,
    };
    if (request == 'r' and reconnect_late) {
        upstream.close(io);
        upstream = try upstream_address.connect(io, .{ .mode = .stream });
    }
}

fn frontendRun(env: *Env, reconnect_late: bool) !void {
    const io = env.io;
    try env.spawnOn(2, backend, .{io});
    try io.sleep(.fromMilliseconds(1), .awake);
    try env.spawnOn(1, frontend, .{ io, env.address(2, backend_port), reconnect_late });
    try io.sleep(.fromMilliseconds(1), .awake);
    const request: u8 = if ((try env.fuzz(u8)) % 4 == 0) 'r' else 's';
    const stream = try env.address(1, front_port).connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var wbuf: [16]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeByte(request) catch return w.err.?;
    w.interface.flush() catch return w.err.?;
    try io.sleep(.fromMilliseconds(10), .awake);
    // A restart runs the initialization again, with its connect and listen
    // before the sandbox: the policy died with the process.
    env.crashNode(1, .process_crash);
    try env.spawnOn(1, frontend, .{ io, env.address(2, backend_port), reconnect_late });
    try io.sleep(.fromMilliseconds(10), .awake);
    if (env.daemonError()) |err| return err;
}

fn lateReconnect(env: *Env) !void {
    return frontendRun(env, true);
}

fn keptConnection(env: *Env) !void {
    return frontendRun(env, false);
}

test "sandbox: a connect after enterSandbox is CWE-272; one made during initialization, before or after a restart, is not" {
    var report: sec.engine.Report = .{};
    var shrunk: tardis.ShrinkReport = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, lateReconnect, sec.withSecurity(.{
        .report = &report,
        .base = .{ .nodes = 3, .iterations = 50, .report = false, .shrink_report = &shrunk },
    })));
    const f = report.findings[0];
    try std.testing.expectEqual(@as(u16, 272), f.cwe);
    try std.testing.expectEqual(sec.engine.Kind.privilege, f.kind);
    try std.testing.expectEqual(@backingInt(sec.engine.Privilege.net_connect), f.detail[0]);
    try std.testing.expectEqual(@as(u16, 1), f.detail[1]);
    try expectShrunkTo(shrunk, 5);
    try tardis.check(gpa, keptConnection, sec.withSecurity(.{ .base = .{ .nodes = 3, .iterations = 50 } }));
}

const jobs_port = 742;
const job_names = [_][]const u8{ "thumbnail", "transcode" };

const Job = struct {
    /// The received name is checked against `job_names` and marked
    /// sanitized before use.
    validated: bool,
    /// After lockdown, also writes `jobs.log`, outside `spool/`.
    log_outside: bool = false,
    /// The policy keeps process spawns.
    may_spawn: bool = true,
};

/// Receives a job name, runs `convert <name>`, and queues it under
/// `spool/`. Only `spool/` stays writable after lockdown.
fn jobRunner(io: Io, job: Job) !void {
    const dir = Io.Dir.cwd();
    try dir.createDirPath(io, "spool");
    var server = try any(jobs_port).listen(io, .{});
    defer server.deinit(io);
    var policy: sec.SandboxPolicy = .{ .allow_process_spawn = job.may_spawn };
    policy.vfs_prefixes[0] = "spool/";
    policy.vfs_prefixes_len = 1;
    sec.enterSandbox(policy);
    const client = try server.accept(io);
    defer client.close(io);
    var rbuf: [64]u8 = undefined;
    var r = client.reader(io, &rbuf);
    const name = r.interface.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.ReadFailed => return r.err.?,
        else => |e| return e,
    };
    if (job.validated) {
        for (job_names) |known| {
            if (std.mem.eql(u8, name, known)) break;
        } else return;
        sec.markSanitized(name);
    }
    // Core runs no processes: the spawn fails, after the layer saw it.
    _ = std.process.spawn(io, .{ .argv = &.{ "convert", name } }) catch {};
    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "spool/{s}", .{name});
    try dir.writeFile(io, .{ .sub_path = path, .data = "queued" });
    if (job.log_outside) try dir.writeFile(io, .{ .sub_path = "jobs.log", .data = "queued" });
}

fn jobRun(env: *Env, job: Job) !void {
    const io = env.io;
    try env.spawnOn(1, jobRunner, .{ io, job });
    try io.sleep(.fromMilliseconds(1), .awake);
    const name = job_names[(try env.fuzz(u8)) % job_names.len];
    const stream = try env.address(1, jobs_port).connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var wbuf: [64]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeAll(name) catch return w.err.?;
    w.interface.writeByte('\n') catch return w.err.?;
    w.interface.flush() catch return w.err.?;
    try io.sleep(.fromMilliseconds(10), .awake);
    if (env.daemonError()) |err| return err;
}

fn rawCommand(env: *Env) !void {
    return jobRun(env, .{ .validated = false });
}

fn logOutside(env: *Env) !void {
    return jobRun(env, .{ .validated = true, .log_outside = true });
}

fn noSpawn(env: *Env) !void {
    return jobRun(env, .{ .validated = true, .may_spawn = false });
}

fn queuedOnly(env: *Env) !void {
    return jobRun(env, .{ .validated = true });
}

fn expectFinding(comptime body: fn (*Env) anyerror!void, cwe: u16, kind: sec.engine.Kind, detail0: u16) !void {
    var report: sec.engine.Report = .{};
    var shrunk: tardis.ShrinkReport = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, body, sec.withSecurity(.{
        .report = &report,
        .base = .{ .nodes = 2, .iterations = 50, .report = false, .shrink_report = &shrunk },
    })));
    try std.testing.expectEqual(cwe, report.findings[0].cwe);
    try std.testing.expectEqual(kind, report.findings[0].kind);
    try std.testing.expectEqual(detail0, report.findings[0].detail[0]);
    try expectShrunkTo(shrunk, 5);
}

test "sandbox and the spawn sink: a received name in argv is CWE-78; a write outside the prefix or a dropped spawn is CWE-272" {
    // argv[1] is the name as received.
    try expectFinding(rawCommand, 78, .tainted_command, 1);
    try expectFinding(logOutside, 272, .privilege, @backingInt(sec.engine.Privilege.vfs_write));
    try expectFinding(noSpawn, 272, .privilege, @backingInt(sec.engine.Privilege.process_spawn));
    try tardis.check(gpa, queuedOnly, sec.withSecurity(.{ .base = .{ .nodes = 2, .iterations = 50 } }));
    // Without taint, the raw name passes: nothing else is wrong with it.
    try tardis.check(gpa, rawCommand, sec.withSecurity(.{ .taint_paths = false, .base = .{ .nodes = 2, .iterations = 50 } }));
}
