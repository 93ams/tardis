//! `tardis`: the command-line companion to the TARDIS test library, built on
//! termancy's `cli`, `term` and `sys`.
//!
//!     tardis explain <token>          what a replay token pins down
//!     tardis replay <token|seed>      re-run one failing run (zig build test)
//!     tardis scan <file|->            failures and replay tokens in test output
//!     tardis replay-evidence <dir>    verify a tardis_sec evidence bundle
//!     tardis personas                 the simulated filesystems
//!
//! Every command takes `-o json` for scripts.

const std = @import("std");
const cli = @import("cli");
const term = @import("term");
const sys = @import("sys");
const tardis = @import("tardis");
const tardis_sec = @import("tardis_sec");
const Persona = tardis.Persona;

// ---------------------------------------------------------------------------
// personas

const PersonaRow = struct {
    name: []const u8,
    case_insensitive: bool,
    rename_flushes_data: bool,
    file_sync_commits_journal: bool,
    atomic_unsynced_writes: bool,
    models: []const u8,

    pub const text_columns = .{
        .name = "PERSONA",
        .case_insensitive = "CASE-INSENSITIVE",
        .rename_flushes_data = "RENAME FLUSHES DATA",
        .file_sync_commits_journal = "FSYNC COMMITS JOURNAL",
        .models = "MODELS",
    };
};

fn describe(p: Persona) []const u8 {
    return switch (p) {
        .linux_ext4 => "ext4, data=ordered, auto_da_alloc",
        .linux_xfs => "XFS: metadata journaled, data not ordered",
        .windows_ntfs => "NTFS: case-insensitive, Win32 names (trailing dots, ::$DATA, 8.3), sharing violations, mandatory locks",
        .posix_strict => "only what POSIX promises: sync the file and its directory",
        .macos_apfs => "APFS: case- and normalization-insensitive (Latin-1), assuming fsync is durable (no F_FULLFSYNC)",
        .freebsd_zfs => "ZFS: copy-on-write, rename ordered after earlier data",
    };
}

fn row(p: Persona) PersonaRow {
    return .{
        .name = @tagName(p),
        .case_insensitive = p.caseInsensitive(),
        .rename_flushes_data = p.renameFlushesData(),
        .file_sync_commits_journal = p.fileSyncCommitsJournal(),
        .atomic_unsynced_writes = p.atomicWrites(),
        .models = describe(p),
    };
}

fn personas(ctx: *cli.Context) !void {
    var rows: [std.enums.values(Persona).len]PersonaRow = undefined;
    for (std.enums.values(Persona), &rows) |p, *r| r.* = row(p);
    try ctx.render(@as([]const PersonaRow, &rows));
}

// ---------------------------------------------------------------------------
// explain

const Explained = struct {
    persona: []const u8,
    seed: []const u8,
    /// Null: every decision keeps its natural value (an unshrunk run).
    kept: ?usize,
    kept_keys: []const []const u8,
    forced: []const Forced,
    models: []const u8,
    replay_sh: []const u8,
    replay_powershell: []const u8,

    const Forced = struct { key: []const u8, value: []const u8 };
};

const TokenArgs = struct { token: []const u8 };

fn explain(ctx: *cli.Context, args: TokenArgs) !void {
    const tok = tardis.shrink.parseToken(ctx.arena, args.token) catch
        return ctx.fail("not a replay token: {s}", .{args.token});
    const p = std.meta.stringToEnum(Persona, tok.persona) orelse
        return ctx.fail("unknown persona '{s}' in the token", .{tok.persona});
    const a = ctx.arena;
    var keys: std.ArrayList([]const u8) = .empty;
    if (tok.keep) |k| for (k) |key| try keys.append(a, try std.fmt.allocPrint(a, "{x:0>16}", .{key}));
    var forced: std.ArrayList(Explained.Forced) = .empty;
    for (tok.forced) |f| try forced.append(a, .{
        .key = try std.fmt.allocPrint(a, "{x:0>16}", .{f.key}),
        .value = try std.fmt.allocPrint(a, "0x{x}", .{f.value}),
    });
    const e: Explained = .{
        .persona = tok.persona,
        .seed = try std.fmt.allocPrint(a, "0x{x:0>16}", .{tok.seed}),
        .kept = if (tok.keep) |k| k.len else null,
        .kept_keys = keys.items,
        .forced = forced.items,
        .models = describe(p),
        .replay_sh = try std.fmt.allocPrint(a, "TARDIS_REPLAY={s} zig build test", .{args.token}),
        .replay_powershell = try std.fmt.allocPrint(a, "$env:TARDIS_REPLAY='{s}'; zig build test", .{args.token}),
    };
    if (ctx.output != .text) return ctx.render(e);

    const out = ctx.out;
    const heading: term.Style = .{ .bold = true };
    try ctx.paint(heading, "persona  ");
    try out.print("{s} ({s})\n", .{ e.persona, e.models });
    try ctx.paint(heading, "seed     ");
    try out.print("{s}\n", .{e.seed});
    try ctx.paint(heading, "decisions");
    if (e.kept) |n| {
        try out.print(" {d} keep their natural value; every other decision is benign\n", .{n});
        try out.print("          (no fault, no preemption, nothing lost in a crash, minimal input)\n", .{});
    } else {
        try out.print(" all natural (an unshrunk run)\n", .{});
    }
    if (e.forced.len > 0) {
        try ctx.paint(heading, "forced   ");
        try out.print(" {d} decision(s) set to an explicit value:\n", .{e.forced.len});
        for (e.forced) |f| try out.print("            {s} = {s}\n", .{ f.key, f.value });
    }
    try ctx.paint(heading, "replay\n");
    try out.print("  sh:          {s}\n  PowerShell:  {s}\n  or:          tardis replay '{s}'\n", .{ e.replay_sh, e.replay_powershell, args.token });
}

// ---------------------------------------------------------------------------
// replay

const ReplayFlags = struct {
    persona: ?Persona = null,
    filter: ?[]const u8 = null,
    step: []const u8 = "test",
    zig: []const u8 = "zig",
};

const replay_flags = cli.flags(ReplayFlags, @import("field").Set(.{}), .{ .fields = .{
    .persona = .{ .short = 'p' },
    .filter = .{ .short = 'f' },
} });

/// What `replay` runs: `zig build <step> [-Dtest-filter=...]` with one of
/// `TARDIS_REPLAY` or `TARDIS_SEED` (+ `TARDIS_PERSONA`) set.
const Plan = struct {
    argv: []const []const u8,
    env_name: []const u8,
    env_value: []const u8,
    persona: ?[]const u8,
};

fn plan(a: std.mem.Allocator, flags: ReplayFlags, what: []const u8) !?Plan {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(a, &.{ flags.zig, "build", flags.step });
    if (flags.filter) |f| try argv.append(a, try std.fmt.allocPrint(a, "-Dtest-filter={s}", .{f}));
    if (std.fmt.parseInt(u64, what, 0)) |seed| {
        return .{
            .argv = argv.items,
            .env_name = "TARDIS_SEED",
            .env_value = try std.fmt.allocPrint(a, "0x{x:0>16}", .{seed}),
            .persona = if (flags.persona) |p| @tagName(p) else null,
        };
    } else |_| {}
    var tok = tardis.shrink.parseToken(a, what) catch return null;
    _ = &tok;
    return .{ .argv = argv.items, .env_name = "TARDIS_REPLAY", .env_value = what, .persona = null };
}

fn replay(ctx: *cli.Context, flags: ReplayFlags, args: TokenArgs) !void {
    const p = (try plan(ctx.arena, flags, args.token)) orelse
        return ctx.usageError("not a seed or a replay token: {s}", .{args.token});
    if (ctx.dry_run) {
        try ctx.out.print("{s}={s}", .{ p.env_name, p.env_value });
        if (p.persona) |name| try ctx.out.print(" TARDIS_PERSONA={s}", .{name});
        for (p.argv) |arg| try ctx.out.print(" {s}", .{arg});
        try ctx.out.print("\n", .{});
        return;
    }
    var env = try ctx.environ.clone(ctx.arena);
    try env.put(p.env_name, p.env_value);
    if (p.persona) |name| try env.put("TARDIS_PERSONA", name);
    try ctx.out.flush();
    const status = sys.process.stream(ctx.io, p.argv, .{ .environ = &env }) catch |err|
        return ctx.fail("could not run {s}: {t}", .{ p.argv[0], err });
    const code = sys.process.exitStatus(status);
    if (code != 0) return ctx.exit(code);
}

// ---------------------------------------------------------------------------
// scan

/// One failure found in test output.
pub const Failure = struct {
    /// The test that failed, when the runner named it after the report.
    test_name: []const u8 = "",
    iteration: []const u8 = "",
    persona: []const u8 = "",
    seed: []const u8 = "",
    err: []const u8 = "",
    /// The shrunk replay token, else `persona:seed:*` (the unshrunk run).
    replay: []const u8 = "",
    shrunk: bool = false,

    pub const text_columns = .{ .test_name = "TEST", .err = "ERROR", .persona = "PERSONA", .replay = "REPLAY" };
};

fn after(line: []const u8, prefix: []const u8) ?[]const u8 {
    const i = std.mem.indexOf(u8, line, prefix) orelse return null;
    const rest = line[i + prefix.len ..];
    const end = std.mem.indexOfAny(u8, rest, " \t\r") orelse rest.len;
    return rest[0..end];
}

/// Finds TARDIS failure reports in `text` (the output of `zig build test`).
pub fn scanText(a: std.mem.Allocator, text: []const u8) ![]Failure {
    var found: std.ArrayList(Failure) = .empty;
    var open = false; // a failure waiting for its test name
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (std.mem.indexOf(u8, line, "tardis: FAILED") != null) {
            try found.append(a, .{
                .iteration = after(line, "iteration ") orelse "",
                .persona = after(line, "persona=") orelse "",
                .seed = after(line, "seed=") orelse "",
            });
            open = true;
            continue;
        }
        if (found.items.len == 0) continue;
        const cur = &found.items[found.items.len - 1];
        if (std.mem.indexOf(u8, line, "tardis: error.")) |i| {
            if (cur.err.len == 0) cur.err = line[i + "tardis: ".len ..];
        } else if (after(line, "TARDIS_REPLAY=")) |tok| {
            cur.replay = tok;
            cur.shrunk = true;
        } else if (after(line, "TARDIS_SEED=")) |seed| {
            // `persona:seed:*` (every decision natural) replays the same run.
            if (!cur.shrunk) cur.replay = try std.fmt.allocPrint(a, "{s}:{s}:*", .{ cur.persona, seed });
        } else if (open and std.mem.startsWith(u8, std.mem.trimStart(u8, line, " "), "error: '")) {
            const start = std.mem.indexOfScalar(u8, line, '\'').? + 1;
            const end = std.mem.indexOfScalarPos(u8, line, start, '\'') orelse line.len;
            const name = line[start..end];
            const short = if (std.mem.indexOf(u8, name, ".test.")) |t| name[t + ".test.".len ..] else name;
            // Every failure since the last named test belongs to this one.
            var k = found.items.len;
            while (k > 0 and found.items[k - 1].test_name.len == 0) : (k -= 1) found.items[k - 1].test_name = short;
            open = false;
        }
    }
    return found.items;
}

const ScanArgs = struct { file: []const u8 };

fn scan(ctx: *cli.Context, args: ScanArgs) !void {
    const limit: std.Io.Limit = .limited(256 * 1024 * 1024);
    const text = if (std.mem.eql(u8, args.file, "-")) blk: {
        var buf: [4096]u8 = undefined;
        var r = std.Io.File.stdin().reader(ctx.io, &buf);
        break :blk r.interface.allocRemaining(ctx.arena, limit) catch |err|
            return ctx.fail("reading standard input: {t}", .{err});
    } else std.Io.Dir.cwd().readFileAlloc(ctx.io, args.file, ctx.arena, limit) catch |err|
        return ctx.fail("{s}: {t}", .{ args.file, err });
    const failures = try scanText(ctx.arena, text);
    if (ctx.output != .text) return ctx.render(@as([]const Failure, failures));
    if (failures.len == 0) {
        try ctx.out.print("no TARDIS failures found\n", .{});
        return;
    }
    try ctx.render(@as([]const Failure, failures));
    try ctx.out.print("\nreplay one with: tardis replay '<REPLAY>'   (explain one: tardis explain '<REPLAY>')\n", .{});
}

// ---------------------------------------------------------------------------
// replay-evidence

const EvidenceFlags = struct {
    /// The project's Ed25519 public key (64 hex digits): the bundle must be
    /// signed by it. Without it, only integrity is checked.
    key: ?[]const u8 = null,
};

const evidence_flags = cli.flags(EvidenceFlags, @import("field").Set(.{}), .{ .fields = .{
    .key = .{ .short = 'k' },
} });

const EvidenceArgs = struct { dir: []const u8 };

const CapsuleRow = struct {
    file: []const u8,
    err: []const u8,
    token: []const u8,

    pub const text_columns = .{ .file = "CAPSULE", .err = "EXPECTED ERROR", .token = "TOKEN" };
};

const EvidenceReport = struct {
    root: []const u8,
    files: u32,
    signed: bool,
    /// Checked against `--key` (else only consistent with the signature).
    authenticated: bool,
    public_key: []const u8,
    capsules: []const CapsuleRow,
};

fn replayEvidence(ctx: *cli.Context, flags: EvidenceFlags, args: EvidenceArgs) !void {
    const a = ctx.arena;
    var expected: ?tardis_sec.Ed25519.PublicKey = null;
    if (flags.key) |hex| {
        var bytes: [32]u8 = undefined;
        const got = std.fmt.hexToBytes(&bytes, hex) catch return ctx.usageError("--key: not hex: {s}", .{hex});
        if (got.len != 32) return ctx.usageError("--key: expected 64 hex digits", .{});
        expected = tardis_sec.Ed25519.PublicKey.fromBytes(bytes) catch return ctx.usageError("--key: not an Ed25519 public key", .{});
    }
    var dir = std.Io.Dir.cwd().openDir(ctx.io, args.dir, .{ .iterate = true }) catch |err|
        return ctx.fail("{s}: {t}", .{ args.dir, err });
    defer dir.close(ctx.io);
    const v = tardis_sec.verifyEvidence(a, ctx.io, dir, expected) catch |err|
        return ctx.fail("{s}: the evidence does NOT verify: {t}", .{ args.dir, err });

    var rows: std.ArrayList(CapsuleRow) = .empty;
    var caps = dir.openDir(ctx.io, "capsules", .{ .iterate = true }) catch null;
    if (caps) |*cd| {
        defer cd.close(ctx.io);
        var it = cd.iterate();
        while (try it.next(ctx.io)) |entry| {
            const text = try cd.readFileAlloc(ctx.io, entry.name, a, .limited(64 * 1024));
            const c = tardis_sec.evidence.parseCapsule(text) catch return ctx.fail("capsules/{s}: malformed", .{entry.name});
            try rows.append(a, .{ .file = try a.dupe(u8, entry.name), .err = c.err, .token = c.token });
        }
    }
    std.mem.sort(CapsuleRow, rows.items, {}, struct {
        fn lt(_: void, x: CapsuleRow, y: CapsuleRow) bool {
            return std.mem.lessThan(u8, x.file, y.file);
        }
    }.lt);
    const report: EvidenceReport = .{
        .root = try std.fmt.allocPrint(a, "{x}", .{&v.root}),
        .files = v.files,
        .signed = v.signed,
        .authenticated = v.signed and expected != null,
        .public_key = if (v.signed) try std.fmt.allocPrint(a, "{x}", .{&v.public_key}) else "",
        .capsules = rows.items,
    };
    if (ctx.output != .text) return ctx.render(report);

    const out = ctx.out;
    try ctx.paint(.{ .bold = true }, "evidence verifies");
    try out.print(": {d} files, Merkle root {s}\n", .{ report.files, report.root });
    if (!report.signed) {
        try out.print("  unsigned: integrity only\n", .{});
    } else if (report.authenticated) {
        try out.print("  signed by the expected key {s}\n", .{report.public_key});
    } else {
        try out.print("  signed by {s} (pass --key to require the project's key)\n", .{report.public_key});
    }
    if (rows.items.len == 0) {
        try out.print("  no capsules: the campaign had no failures\n", .{});
        return;
    }
    try out.print("\n", .{});
    try ctx.render(@as([]const CapsuleRow, rows.items));
    try out.print("\neach capsule must fail with its error when replayed:  tardis replay '<TOKEN>'\n", .{});
    try out.print("(tardis_sec.replayEvidence does all of them, and the determinism hashes, from a test)\n", .{});
}

// ---------------------------------------------------------------------------

pub const root = cli.command(.{
    .name = "tardis",
    .summary = "Explain, replay and collect TARDIS failures",
    .description = "Companion to the TARDIS deterministic simulation testing library: " ++
        "replay tokens and seeds from failing runs, and the simulated filesystems.",
    .subcommands = .{
        cli.command(.{
            .name = "explain",
            .summary = "Explain what a replay token pins down",
            .args = TokenArgs,
            .output = true,
            .run = explain,
        }),
        cli.command(.{
            .name = "replay",
            .summary = "Re-run one failing run: zig build test with TARDIS_REPLAY or TARDIS_SEED",
            .flags = replay_flags,
            .args = TokenArgs,
            .dry_run = true,
            .run = replay,
        }),
        cli.command(.{
            .name = "scan",
            .summary = "List the failures and replay tokens in test output (a file, or - for stdin)",
            .args = ScanArgs,
            .output = true,
            .run = scan,
        }),
        cli.command(.{
            .name = "replay-evidence",
            .summary = "Verify a tardis_sec evidence bundle: hashes, Merkle root, signature; list its capsules",
            .flags = evidence_flags,
            .args = EvidenceArgs,
            .output = true,
            .run = replayEvidence,
        }),
        cli.command(.{
            .name = "personas",
            .summary = "List the simulated filesystems and what they guarantee",
            .output = true,
            .run = personas,
        }),
    },
});

pub fn main(init: std.process.Init) u8 {
    const app: cli.App = .{ .root = &root, .version = "0.1.0" };
    return app.run(init);
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;
const test_app: cli.App = .{ .root = &root };

test "explain decodes a shrunk token" {
    const result = try cli.testing.run(test_app, &.{ "explain", "linux_xfs:0x0000000000000abc:10.ff00:10=1388" }, .{});
    defer result.deinit();
    try testing.expectEqual(0, result.status);
    try testing.expect(std.mem.indexOf(u8, result.out, "linux_xfs") != null);
    try testing.expect(std.mem.indexOf(u8, result.out, "0x0000000000000abc") != null);
    try testing.expect(std.mem.indexOf(u8, result.out, "2 keep their natural value") != null);
    try testing.expect(std.mem.indexOf(u8, result.out, "0000000000000010 = 0x1388") != null);
}

test "explain -o json, and a bad token is an error" {
    const json = try cli.testing.run(test_app, &.{ "explain", "-o", "json", "posix_strict:0x1:*" }, .{});
    defer json.deinit();
    try testing.expectEqual(0, json.status);
    try testing.expect(std.mem.indexOf(u8, json.out, "\"persona\"") != null);
    try testing.expect(std.mem.indexOf(u8, json.out, "\"kept\": null") != null or std.mem.indexOf(u8, json.out, "\"kept\":null") != null);
    const bad = try cli.testing.run(test_app, &.{ "explain", "nonsense" }, .{});
    defer bad.deinit();
    try testing.expectEqual(1, bad.status);
}

test "replay --dry-run shows the command for a token and for a seed" {
    const tok = try cli.testing.run(test_app, &.{ "replay", "--dry-run", "-f", "torn", "linux_ext4:0x1:" }, .{});
    defer tok.deinit();
    try testing.expectEqual(0, tok.status);
    try testing.expectEqualStrings("TARDIS_REPLAY=linux_ext4:0x1: zig build test -Dtest-filter=torn\n", tok.out);
    const seed = try cli.testing.run(test_app, &.{ "replay", "--dry-run", "-p", "linux_xfs", "0x2a" }, .{});
    defer seed.deinit();
    try testing.expectEqualStrings("TARDIS_SEED=0x000000000000002a TARDIS_PERSONA=linux_xfs zig build test\n", seed.out);
    const bad = try cli.testing.run(test_app, &.{ "replay", "--dry-run", "what" }, .{});
    defer bad.deinit();
    try testing.expectEqual(2, bad.status);
}

test "replay-evidence verifies a bundle, lists its capsules, and rejects a tampered one" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const gpa = testing.allocator;
    const c = try gpa.create(tardis_sec.Campaign);
    defer gpa.destroy(c);
    c.init("");
    var log: tardis.FailureLog = undefined;
    const kp = tardis_sec.Ed25519.KeyPair.generateDeterministic(@splat(7)) catch unreachable;
    _ = try tardis_sec.evidence.write(gpa, io, tmp.dir, tardis_sec.evidence.testBundle(c, &log), kp);

    var key_buf: [64]u8 = undefined;
    const key = try std.fmt.bufPrint(&key_buf, "{x}", .{&kp.public_key.toBytes()});

    const ok = try cli.testing.run(test_app, &.{ "replay-evidence", "--key", key, "." }, .{ .cwd = tmp.dir });
    defer ok.deinit();
    try testing.expectEqual(0, ok.status);
    try testing.expect(std.mem.indexOf(u8, ok.out, "evidence verifies: 8 files") != null);
    try testing.expect(std.mem.indexOf(u8, ok.out, "signed by the expected key") != null);
    try testing.expect(std.mem.indexOf(u8, ok.out, "SecurityViolation") != null);
    try testing.expect(std.mem.indexOf(u8, ok.out, "linux_ext4:0x0000000000000051:*") != null);

    try tmp.dir.writeFile(io, .{ .sub_path = "findings.sarif", .data = "{}" });
    const bad = try cli.testing.run(test_app, &.{ "replay-evidence", "." }, .{ .cwd = tmp.dir });
    defer bad.deinit();
    try testing.expectEqual(1, bad.status);
    try testing.expect(std.mem.indexOf(u8, bad.err, "HashMismatch") != null);
}

test "personas lists every persona" {
    const result = try cli.testing.run(test_app, &.{"personas"}, .{});
    defer result.deinit();
    try testing.expectEqual(0, result.status);
    for (std.enums.values(Persona)) |p| try testing.expect(std.mem.indexOf(u8, result.out, @tagName(p)) != null);
}

test "scan finds failures, their errors, tokens and test names" {
    const output =
        \\tardis: FAILED  iteration 3/40  persona=linux_xfs  seed=0x00000000000000aa
        \\tardis: error.AssertionFailed
        \\tardis: replay with:  TARDIS_SEED=0x00000000000000aa TARDIS_PERSONA=linux_xfs zig build test
        \\tardis: shrunk 27 -> 1 decisions and lowered 1 values in 9 runs
        \\tardis: replay the shrunk run with:  TARDIS_REPLAY=linux_xfs:0x00000000000000aa:5:5=1 zig build test
        \\error: 'tests.shrink_test.test.shrink: torn rename' failed:
        \\tardis: FAILED  iteration 1/10  persona=posix_strict  seed=0x00000000000000bb
        \\tardis: error.Broken
        \\tardis: replay with:  TARDIS_SEED=0x00000000000000bb TARDIS_PERSONA=posix_strict zig build test
        \\error: 'tests.bugs_test.test.broken' failed:
    ;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const found = try scanText(arena.allocator(), output);
    try testing.expectEqual(@as(usize, 2), found.len);
    try testing.expectEqualStrings("shrink: torn rename", found[0].test_name);
    try testing.expectEqualStrings("error.AssertionFailed", found[0].err);
    try testing.expectEqualStrings("linux_xfs:0x00000000000000aa:5:5=1", found[0].replay);
    try testing.expect(found[0].shrunk);
    try testing.expectEqualStrings("broken", found[1].test_name);
    try testing.expectEqualStrings("posix_strict:0x00000000000000bb:*", found[1].replay);
    try testing.expect(!found[1].shrunk);
}
