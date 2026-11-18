//! Example 2 (plan2.md §8.5; Milestone 5 (SEC) week 16): a 3-node
//! replication round under an equivocating leader, certified.
//!
//! Node 0 proposes a value to nodes 1 and 2 and is two-faced towards
//! node 2: half the time node 2 receives the same frame with one byte
//! flipped and the checksum recomputed, so it verifies. The fixed
//! followers commit only when the other follower echoes the same value;
//! the broken ones trust the leader alone.
//!
//! `certify` binds the checks to Security Functional Requirements, runs the
//! campaign without stopping early, and writes a signed evidence bundle;
//! `replayEvidence` then verifies it the way an evaluation lab would:
//! hashes, Merkle root and signature, every capsule replayed to its
//! recorded error, and the golden trace hashes recomputed.

const std = @import("std");
const tardis = @import("tardis");
const sec = @import("tardis_sec");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const Env = tardis.Env;
const gpa = std.testing.allocator;

const Frame = extern struct { index: u32, len: u32, crc: u32 };
const Spec = sec.ByzantineFrameSpec(Frame, .{ .length_field = "len", .checksum_field = "crc" });
const proposal_port = 700;
const echo_port = 701;
const proposal: u64 = 0x1111_2222_3333_4444;

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
    const other: tardis.NodeId = if (me == 1) 2 else 1;
    // tardis-deactivated: a fresh node binds its own echo port, which nothing else holds
    const echo_sock = try any(echo_port).bind(io, .{ .mode = .dgram });
    defer echo_sock.close(io);
    try sock.send(io, &env.address(other, echo_port), d.payload);
    const peer_msg = try echo_sock.receive(io, &buf);
    // The commit decision, instrumented for MC/DC (declared as decision 1).
    const well_formed = peer_msg.data.len == 8;
    const same = well_formed and std.mem.readInt(u64, peer_msg.data[0..8], .little) == value;
    if (sec.mcdc.decision(1, .{ well_formed, same }, struct {
        fn f(c: anytype) bool {
            return c[0] and c[1];
        }
    }.f)) committed.value[me] = value;
}

fn round(env: *Env, echo: bool) !void {
    const io = env.io;
    var committed: Committed = .{};
    sec.twoFaced(0, &.{2}, Spec.equivocateFrame(0, 0x01));
    try env.spawnOn(1, follower, .{ io, env, 1, &committed, echo });
    try env.spawnOn(2, follower, .{ io, env, 2, &committed, echo });
    try io.sleep(.fromMilliseconds(1), .awake);

    const sock = try any(0).bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    var value: [8]u8 = undefined;
    std.mem.writeInt(u64, &value, proposal, .little);
    var frame: [64]u8 = undefined;
    const n = Spec.encode(.{ .index = 1, .len = 8, .crc = Spec.checksumOf(&value) }, &value, &frame);
    try sock.send(io, &env.address(1, proposal_port), frame[0..n]);
    try sock.send(io, &env.address(2, proposal_port), frame[0..n]);
    try io.sleep(.fromMilliseconds(50), .awake);

    const a = committed.value[1];
    const b = committed.value[2];
    // FDP_ITC.2: imported data keeps its integrity across the replicas.
    const agree = sec.requirement("SFR-FDP_ITC.2");
    try env.always("no two followers commit different values", agree.check(a == null or b == null or a.? == b.?));
    // FDP_UIT.1: what is committed is what the leader proposed to everyone.
    const integrity = sec.requirement("SFR-FDP_UIT.1");
    for ([_]?u64{ a, b }) |v| {
        try env.always("a committed value is the proposal", integrity.check(v == null or v.? == proposal));
    }
}

fn echoing(env: *Env) !void {
    return round(env, true);
}

fn trusting(env: *Env) !void {
    return round(env, false);
}

const requirement_file =
    \\# Security Functional Requirements of the replication round
    \\SFR-FDP_ITC.2   # import of user data with security attributes
    \\SFR-FDP_UIT.1   # data exchange integrity
    \\SFR-FPT_RCV.1   # manual recovery: no test yet, so a gap
;

const config: sec.SecurityConfig = .{
    .mode = .certification_eal7,
    .byzantine_ppm = 500_000,
    .base = .{
        .nodes = 3,
        .iterations = 120,
        .faults = .{ .datagram_loss_ppm = 0, .datagram_duplicate_ppm = 0 },
    },
};

/// The project's instrumented decisions. Decision 1 is the commit above.
/// Decision 2 stands for a recovery path no test reaches (dead code until
/// a test covers it); decision 3 for one compiled out of this
/// configuration, with its justification.
const decisions = [_]sec.mcdc.Decl{
    .{ .id = 1, .name = "example2.zig follower: well_formed and same", .requirement = "SFR-FDP_ITC.2" },
    .{ .id = 2, .name = "recovery: resync from the leader's log", .requirement = "SFR-FPT_RCV.1" },
    .{ .id = 3, .name = "legacy v1 frame format", .deactivated = "v1 frames are disabled in this configuration (no v1 peers)" },
};

/// The 1-based line of this file holding `text` (for the dead-edge checks).
fn lineOf(comptime text: []const u8) u32 {
    const source = @embedFile("example2.zig");
    const at = std.mem.indexOf(u8, source, text) orelse unreachable;
    return @intCast(std.mem.count(u8, source[0..at], "\n") + 1);
}

/// The project key that signs the bundles (a fixed test key here).
fn projectKey() sec.Ed25519.KeyPair {
    return sec.Ed25519.KeyPair.generateDeterministic(@splat(0x5E)) catch unreachable;
}

fn rowOf(rtm: []const u8, id: []const u8) []const u8 {
    var lines = std.mem.splitScalar(u8, rtm, '\n');
    while (lines.next()) |line| if (std.mem.startsWith(u8, line, id)) return line;
    return "";
}

test "example 2: the echo quorum is certified; the bundle verifies and replays" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const key = projectKey();
    // A checkout the manifest names (a fixture: a branch in packed-refs).
    const fixture_commit = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
    try tmp.dir.createDirPath(io, "fixture/.git");
    try tmp.dir.writeFile(io, .{ .sub_path = "fixture/.git/HEAD", .data = "ref: refs/heads/release\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "fixture/.git/packed-refs", .data = fixture_commit ++ " refs/heads/release\n" });
    const fixture = try tmp.dir.openDir(io, "fixture", .{});
    defer fixture.close(io);

    const cert = try sec.certify(gpa, io, echoing, config, .{
        .name = "example 2: echo quorum",
        .requirements = requirement_file,
        .persist = tmp.dir,
        .out = tmp.dir,
        .key = key,
        .source = @src(),
        .source_prefix = "src/sec/tests/",
        .decisions = &decisions,
        // Dead edges (an instrumented build: `zig build evidence -Dedges`):
        // the service, not the tests around it.
        .edge_scope = &.{.{ .file = "src/sec/tests/example2.zig", .functions = &.{ "follower", "round" } }},
        // This repository (null outside a git checkout) and the fixture.
        .repositories = &.{ .{ .name = "tardis", .dir = std.Io.Dir.cwd() }, .{ .name = "fixture", .dir = fixture } },
    });
    defer cert.deinit(gpa);
    try std.testing.expectEqual(@as(?anyerror, null), cert.err);
    try std.testing.expectEqual(@as(u32, 0), cert.failures.failures());
    // Every iteration counted once: the determinism re-run (every run in
    // certification mode) and the golden-hash runs are not counted.
    try std.testing.expectEqual(@as(u64, 120), cert.campaign.runs);
    const recs = cert.campaign.requirements.slice();
    try std.testing.expectEqual(@as(u64, 120), recs[0].checks_passed);
    try std.testing.expectEqual(@as(u64, 240), recs[1].checks_passed);
    try std.testing.expectEqual(sec.RequirementRecord.Status.gap, recs[2].status());

    const bundle = cert.bundle.?;
    const rtm = try bundle.readFileAlloc(io, "rtm.csv", gpa, .unlimited);
    defer gpa.free(rtm);
    try std.testing.expect(std.mem.startsWith(u8, rowOf(rtm, "SFR-FDP_ITC.2"), "SFR-FDP_ITC.2,PASS,example 2: echo quorum,120,0,"));
    try std.testing.expect(std.mem.startsWith(u8, rowOf(rtm, "SFR-FPT_RCV.1"), "SFR-FPT_RCV.1,GAP,,0,0,"));
    {
        const text = try bundle.readFileAlloc(io, "manifest.json", gpa, .unlimited);
        defer gpa.free(text);
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const revs = parsed.value.object.get("revisions").?.array.items;
        try std.testing.expectEqual(@as(usize, 2), revs.len);
        try std.testing.expectEqualStrings("tardis", revs[0].object.get("name").?.string);
        try std.testing.expectEqualStrings(fixture_commit, revs[1].object.get("commit").?.string);
        try std.testing.expectEqualStrings("refs/heads/release", revs[1].object.get("ref").?.string);
        // The fixture has no index: whether it has local changes is unknown, not "none".
        try std.testing.expect(revs[1].object.get("modified_files").? == .null);
        try std.testing.expect(revs[1].object.get("staged_files").? == .null);
    }
    // MC/DC per requirement: neither requirement's decision is complete.
    // The commit only ever sees well-formed echoes, so `well_formed` is
    // never shown to matter; the recovery decision is never reached.
    try std.testing.expect(std.mem.endsWith(u8, rowOf(rtm, "SFR-FDP_ITC.2"), ",0,1"));
    try std.testing.expect(std.mem.endsWith(u8, rowOf(rtm, "SFR-FDP_UIT.1"), ",0,0"));
    try std.testing.expect(std.mem.endsWith(u8, rowOf(rtm, "SFR-FPT_RCV.1"), ",0,1"));
    {
        const text = try bundle.readFileAlloc(io, "mcdc.json", gpa, .unlimited);
        defer gpa.free(text);
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const root = parsed.value.object;
        const commit = root.get("decisions").?.array.items[0].object;
        try std.testing.expectEqual(@as(i64, 1), commit.get("id").?.integer);
        try std.testing.expectEqualStrings("SFR-FDP_ITC.2", commit.get("requirement").?.string);
        // Both vectors with a well-formed echo: `same` is shown, `well_formed` is the gap.
        try std.testing.expectEqual(@as(i64, 2), commit.get("vectors").?.integer);
        try std.testing.expectEqual(@as(usize, 1), commit.get("gaps").?.array.items.len);
        try std.testing.expectEqual(@as(i64, 0), commit.get("gaps").?.array.items[0].integer);
        const unreached = root.get("unreached").?.array.items;
        try std.testing.expectEqual(@as(usize, 2), unreached.len);
        try std.testing.expectEqualStrings("dead", unreached[0].object.get("status").?.string);
        try std.testing.expectEqualStrings("deactivated", unreached[1].object.get("status").?.string);
        try std.testing.expectEqual(@as(i64, 1), root.get("dead").?.integer);
        try std.testing.expectEqual(@as(usize, 0), root.get("undeclared").?.array.items.len);
    }
    {
        const sarif = try bundle.readFileAlloc(io, "findings.sarif", gpa, .unlimited);
        defer gpa.free(sarif);
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, sarif, .{});
        defer parsed.deinit();
        const results = parsed.value.object.get("runs").?.array.items[0].object.get("results").?.array.items;
        // No failure: the decisions' results, in declaration order, then
        // one per line with an edge that never ran (instrumented builds):
        // a note when the line is justified, a warning otherwise.
        try std.testing.expectEqual(3 + cert.edges.lines.len + cert.edges.stale.len, results.len);
        const expect = [_][2][]const u8{ .{ "tardis/mcdc-gap", "warning" }, .{ "tardis/dead-decision", "warning" }, .{ "tardis/dead-decision", "note" } };
        for (results[0..3], expect) |res, e| {
            try std.testing.expectEqualStrings(e[0], res.object.get("ruleId").?.string);
            try std.testing.expectEqualStrings(e[1], res.object.get("level").?.string);
        }
        for (results[3..], cert.edges.lines) |res, l| {
            try std.testing.expectEqualStrings("tardis/dead-edge", res.object.get("ruleId").?.string);
            try std.testing.expectEqualStrings(if (l.justification != null) "note" else "warning", res.object.get("level").?.string);
        }
    }
    {
        const text = try bundle.readFileAlloc(io, "edges.json", gpa, .unlimited);
        defer gpa.free(text);
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const root = parsed.value.object;
        try std.testing.expectEqual(sec.edges.instrumented, root.get("instrumented").?.bool);
        try std.testing.expectEqual(sec.edges.instrumented, root.get("measured").?.bool);
        try std.testing.expectEqual(cert.edges.lines.len, root.get("lines").?.array.items.len);
        try std.testing.expectEqual(@as(i64, cert.edges.justified()), root.get("justified").?.integer);
        try std.testing.expectEqual(@as(usize, 0), root.get("stale").?.array.items.len);
    }
    if (sec.edges.instrumented) {
        // Only the service is in scope, and some of it never ran: the
        // followers' error paths (a bind or receive that fails), which no
        // run takes. Measured in Debug: 37 edges, 18 run.
        const r = &cert.edges;
        try std.testing.expect(r.measured and r.hit > 0 and r.hit < r.edges);
        const service = .{ lineOf("fn follower("), lineOf("fn echoing(") };
        var in_follower = false;
        for (r.lines) |l| {
            try std.testing.expectEqualStrings("src/sec/tests/example2.zig", l.file);
            try std.testing.expect(l.line > service[0] and l.line < service[1]);
            try std.testing.expect(l.hit < l.edges);
            if (l.line < lineOf("fn round(")) in_follower = true;
        }
        try std.testing.expect(in_follower);
        // The echo socket's bind cannot fail, and its line says so: its
        // error path is listed with the justification, and nothing else
        // is justified or stale.
        const bind_line = lineOf("const echo_sock = try");
        var justified = false;
        for (r.lines) |l| if (l.justification) |j| {
            try std.testing.expectEqual(bind_line, l.line);
            try std.testing.expectEqualStrings("a fresh node binds its own echo port, which nothing else holds", j);
            justified = true;
        };
        try std.testing.expect(justified);
        try std.testing.expectEqual(@as(usize, 0), r.stale.len);
    }

    // The independent check: integrity, signature, determinism hashes.
    const r = try sec.replayEvidence(gpa, io, bundle, key.public_key, echoing, sec.withSecurity(config));
    try std.testing.expect(r.verified.signed);
    try std.testing.expectEqual(cert.written.?.root, r.verified.root);
    try std.testing.expectEqual(@as(u32, 0), r.capsules_replayed);
    try std.testing.expectEqual(@as(u32, 8), r.determinism_checked);

    // The registry persisted across campaigns: a second campaign adds up.
    const again = try sec.certify(gpa, io, echoing, .{ .mode = .audit, .byzantine_ppm = 500_000, .base = config.base }, .{
        .name = "example 2: echo quorum (audit)",
        .persist = tmp.dir,
    });
    defer again.deinit(gpa);
    // Audit mode writes no bundle (`TARDIS_CERT_EAL7` promotes it, as `zig build evidence` does).
    if (again.mode == .audit) try std.testing.expectEqual(@as(?std.Io.Dir, null), again.bundle);
    const table = try gpa.create(sec.Registry);
    defer gpa.destroy(table);
    table.len = 0;
    try table.load(io, gpa, tmp.dir, sec.traceability.persist_path);
    const row = &table.records[table.find("SFR-FDP_ITC.2").?];
    try std.testing.expectEqual(@as(u64, 240), row.checks_passed);
    // The audit campaign declared no decisions: the merge keeps the MC/DC counts.
    try std.testing.expectEqual(@as(u32, 1), row.mcdc_decisions_total);
    try std.testing.expect(row.boundTo("example 2: echo quorum") and row.boundTo("example 2: echo quorum (audit)"));
}

test "example 2: trusting followers fail; the campaign keeps going and every capsule replays" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const key = projectKey();
    var c = config;
    c.base.iterations = 24;
    c.base.report = false;

    const cert = try sec.certify(gpa, io, trusting, c, .{
        .name = "example 2: trusting followers",
        .requirements = requirement_file,
        .out = tmp.dir,
        .key = key,
        .source = @src(),
        .source_prefix = "src/sec/tests/",
    });
    defer cert.deinit(gpa);
    try std.testing.expectEqual(@as(?anyerror, error.AssertionFailed), cert.err);
    // Not stopped at the first failure: every iteration ran.
    try std.testing.expectEqual(@as(u64, 24), cert.campaign.runs);
    const n = cert.failures.len;
    try std.testing.expect(n >= 2);
    for (cert.failures.slice()) |*e| {
        try std.testing.expect(e.shrunk);
        try std.testing.expectEqual(@as(anyerror, error.AssertionFailed), e.err);
    }
    const itc = cert.campaign.requirements.slice()[0];
    try std.testing.expectEqual(sec.RequirementRecord.Status.fail, itc.status());
    try std.testing.expectEqual(@as(u64, n), itc.checks_failed);
    try std.testing.expectEqual(cert.failures.entries[0].seed, itc.first_failure_seed);

    const bundle = cert.bundle.?;
    const sarif = try bundle.readFileAlloc(io, "findings.sarif", gpa, .unlimited);
    defer gpa.free(sarif);
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, sarif, .{});
    defer parsed.deinit();
    const results = parsed.value.object.get("runs").?.array.items[0].object.get("results").?.array.items;
    // One failed requirement and one result per failure (no security finding explains them).
    try std.testing.expectEqual(1 + n, results.len);
    try std.testing.expectEqualStrings("tardis/requirement", results[0].object.get("ruleId").?.string);
    const token = results[0].object.get("properties").?.object.get("replayToken").?.string;
    try std.testing.expectEqualStrings(cert.failures.entries[0].token(), token);

    const r = try sec.replayEvidence(gpa, io, bundle, key.public_key, trusting, sec.withSecurity(c));
    try std.testing.expectEqual(n, r.capsules_replayed);
    try std.testing.expectEqual(n, r.verified.capsules);
    // Measured: 10 of the 24 iterations fail, each shrunk to one decision
    // (the rewrite towards node 2); the bundle has 17 files.
    try std.testing.expectEqual(@as(u32, 10), n);
    try std.testing.expectEqual(@as(u32, 17), r.verified.files);
}

test "example 2: four workers give the same signed bundle as one" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const key = projectKey();
    var roots: [2][32]u8 = undefined;
    for ([_]u32{ 1, 4 }, 0..) |workers, k| {
        var c = config;
        c.base.iterations = 24;
        c.base.report = false;
        c.base.workers = workers;
        const cert = try sec.certify(gpa, io, trusting, c, .{
            .name = "example 2: trusting followers",
            .requirements = requirement_file,
            .out = tmp.dir,
            .key = key,
            .source = @src(),
            .source_prefix = "src/sec/tests/",
        });
        defer cert.deinit(gpa);
        try std.testing.expectEqual(@as(?anyerror, error.AssertionFailed), cert.err);
        try std.testing.expectEqual(@as(u64, 24), cert.campaign.runs);
        try std.testing.expectEqual(@as(u32, 10), cert.failures.len);
        roots[k] = cert.written.?.root;
        // The same directory: the second campaign overwrites the first.
        const r = try sec.replayEvidence(gpa, io, cert.bundle.?, key.public_key, trusting, sec.withSecurity(c));
        try std.testing.expectEqual(@as(u32, 10), r.capsules_replayed);
    }
    // Same counts, same first failures, same capsules and tokens, in the
    // same order: byte-identical evidence, so the same Merkle root.
    try std.testing.expectEqualSlices(u8, &roots[0], &roots[1]);
}

/// A warm start: the fork server needs one (`Options.setup`).
fn warmUp(env: *Env) !void {
    try env.dir.writeFile(env.io, .{ .sub_path = "config", .data = "quorum=2" });
}

test "example 2: through the fork server and its worker processes, the same signed bundle as in one process" {
    // On Linux each iteration runs in a forked child, which sends its
    // requirement checks, findings and MC/DC vectors back (seam 4);
    // elsewhere `fork` runs in-process and the two campaigns coincide.
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const key = projectKey();
    var roots: [3][32]u8 = undefined;
    // In one process, through one fork server, and through 4 worker
    // processes (each forwarding its children's tallies).
    const runs = [_]struct { fork: bool, workers: u32 }{ .{ .fork = false, .workers = 1 }, .{ .fork = true, .workers = 1 }, .{ .fork = true, .workers = 4 } };
    for (runs, 0..) |run, k| {
        var c = config;
        c.base.iterations = 24;
        c.base.report = false;
        c.base.setup = warmUp;
        c.base.fork = run.fork;
        c.base.workers = run.workers;
        const cert = try sec.certify(gpa, io, trusting, c, .{
            .name = "example 2: trusting followers (warm)",
            .requirements = requirement_file,
            .out = tmp.dir,
            .key = key,
            .source = @src(),
            .source_prefix = "src/sec/tests/",
        });
        defer cert.deinit(gpa);
        try std.testing.expectEqual(@as(?anyerror, error.AssertionFailed), cert.err);
        // Every iteration counted once, the determinism re-runs not at all.
        try std.testing.expectEqual(@as(u64, 24), cert.campaign.runs);
        const itc = cert.campaign.requirements.slice()[0];
        try std.testing.expectEqual(@as(u64, 24), itc.checks());
        try std.testing.expect(cert.failures.len >= 2);
        try std.testing.expectEqual(@as(u64, cert.failures.len), itc.checks_failed);
        roots[k] = cert.written.?.root;
        const r = try sec.replayEvidence(gpa, io, cert.bundle.?, key.public_key, trusting, sec.withSecurity(c));
        try std.testing.expectEqual(cert.failures.len, r.capsules_replayed);
    }
    try std.testing.expectEqualSlices(u8, &roots[0], &roots[1]);
    try std.testing.expectEqualSlices(u8, &roots[0], &roots[2]);
}

test "example 2: every execution of the echo round is safe, and the reply does not depend on the token" {
    const model: tardis.Options = sec.withSecurity(.{
        .byzantine_ppm = 500_000,
        .base = .{
            .nodes = 3,
            .swarm = false,
            .preempt_ppm = 0,
            .async_inline_ppm = 0,
            .faults = .{
                .short_io_ppm = 0,
                .spurious_wakeup_ppm = 0,
                .io_latency_min_ns = 1_000,
                .io_latency_max_ns = 1_000,
                .datagram_loss_ppm = 0,
                .datagram_duplicate_ppm = 0,
            },
            .net = .{ .latency_min_ns = 100_000, .latency_max_ns = 100_000 },
        },
    });
    const ok = try sec.verifyExhaustive(gpa, echoing, model, .{ .depth_max = 10 });
    try std.testing.expectEqual(@as(?anyerror, null), ok.failure);
    try std.testing.expect(ok.complete);
    // Measured: 64 executions of at most 6 branchable decisions, so the
    // bound is never reached: every execution of the model was run.
    try std.testing.expectEqual(@as(u32, 64), ok.executions);
    try std.testing.expect(!ok.depth_bounded);
    const bad = try sec.verifyExhaustive(gpa, trusting, model, .{ .depth_max = 10 });
    try std.testing.expectEqual(@as(?anyerror, error.AssertionFailed), bad.failure);

    try sec.assertNonInterference(gpa, handleClient, "GET k", "token-A", "token-B", 32, .{});
}

/// Answers a read; the session token is checked with a constant-time
/// compare and must not change what is observable.
fn handleClient(env: *Env, request: []const u8, token: []const u8) anyerror!void {
    var expected: [7]u8 = "token-A".*;
    var diff: u8 = 0;
    for (token, 0..) |c, i| diff |= c ^ expected[i % expected.len];
    std.mem.doNotOptimizeAway(&diff);
    expected = @splat(0);
    const f = try env.dir.createFile(env.io, "reply", .{});
    defer f.close(env.io);
    try f.writeStreamingAll(env.io, request);
}
