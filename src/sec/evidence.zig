//! Signed evidence bundles (plan2.md §7.5): written at the end of a
//! certification campaign, verified by anyone holding the bundle.
//!
//!     <bundle>/
//!       manifest.json             tool, Zig and campaign identity, outcome counts
//!       rtm.csv                   requirement ⇄ test traceability, with results
//!       mcdc.json                 per-decision MC/DC pairs and gaps
//!       findings.sarif            SARIF v2.1.0: findings, failed requirements, failures
//!       sinks.json                taint sink audit: checks and hits per sink
//!       determinism.txt           golden trace hashes (build mode, host, seed)
//!       capsules/NNNN.tardis-replay  one per logged failure: token and expected error
//!       merkle.txt                SHA-256 of every file above, and the Merkle root
//!       signature.ed25519         the root signed with the project key
//!
//! A leaf binds a file's path to its content: SHA-256 of a domain tag, the
//! path, and the content's SHA-256. The root is `merkleRoot` over the
//! leaves in the order `merkle.txt` lists them. `verify` re-hashes every
//! file, rejects a file the list does not cover, recomputes the root and
//! checks the signature; `replay` also re-runs every capsule and the
//! determinism hashes against the test body.

const std = @import("std");
const builtin = @import("builtin");
const tardis = @import("tardis");
const engine = @import("engine.zig");
const campaign_mod = @import("campaign.zig");
const registry = @import("registry.zig");
const mcdc = @import("mcdc.zig");
const edges = @import("edges.zig");
const git_mod = @import("git.zig");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
pub const Ed25519 = std.crypto.sign.Ed25519;
const Campaign = campaign_mod.Campaign;

pub const sarif_schema = "https://json.schemastore.org/sarif-2.1.0.json";

pub const DeterminismRow = struct {
    persona: tardis.Persona,
    seed: u64,
    trace_hash: u64,
};

pub const Manifest = struct {
    tool_version: []const u8,
    campaign: []const u8,
    campaign_id: []const u8,
    campaign_seed: u64,
    iterations: u32,
    personas: []const tardis.Persona,
    nodes: u8,
    mode: []const u8,
    /// The revisions of the code under evidence (`readRevision`).
    revisions: []const Revision = &.{},
};

// ---------------------------------------------------------------------------
// Revisions, read from `.git` without running `git`

/// A repository's checked-out revision: the commit HEAD resolves to and
/// the branch it names (null when detached). Both null when the directory
/// is not a git checkout or its HEAD cannot be resolved; the manifest then
/// says so rather than guessing.
///
/// `modified` counts tracked files whose content differs from the index
/// (`git diff --quiet`), and `staged` paths whose index entry differs from
/// the commit's tree (`git diff --cached --quiet`), read from the object
/// store (`git.zig`). Untracked files are not counted.
pub const Revision = struct {
    name: []const u8,
    /// Null when unknown: no index, an index version or object format this
    /// reader does not handle.
    modified: ?u32 = null,
    /// Null when unknown, as `modified`, or when an object of the commit's
    /// tree cannot be read (an alternate object store, say).
    staged: ?u32 = null,
    commit_buf: [64]u8 = undefined,
    commit_len: u8 = 0,
    ref_buf: [200]u8 = undefined,
    ref_len: u8 = 0,

    pub fn commit(r: *const Revision) ?[]const u8 {
        return if (r.commit_len == 0) null else r.commit_buf[0..r.commit_len];
    }

    pub fn ref(r: *const Revision) ?[]const u8 {
        return if (r.ref_len == 0) null else r.ref_buf[0..r.ref_len];
    }

    fn setCommit(r: *Revision, text: []const u8) bool {
        const t = std.mem.trim(u8, text, " \t\r\n");
        if (t.len != 40 and t.len != 64) return false; // SHA-1 or SHA-256 object names
        for (t) |c| if (!std.ascii.isHex(c)) return false;
        @memcpy(r.commit_buf[0..t.len], t);
        r.commit_len = @intCast(t.len);
        return true;
    }
};

/// Reads the revision checked out in `repo`, the way `git rev-parse HEAD`
/// would for the common layouts: `.git` as a directory or as a
/// `gitdir:` file (worktrees, submodules), HEAD naming a branch (a loose
/// ref, or a line of `packed-refs`, in the git directory or its
/// `commondir`) or a detached commit.
pub fn readRevision(gpa: Allocator, io: Io, repo: Io.Dir, name: []const u8) Revision {
    var r: Revision = .{ .name = name };
    const git = openGitDir(io, repo) orelse return r;
    defer git.close(io);
    readHead(gpa, io, git, &r);
    const index = git_mod.readIndex(gpa, io, git) orelse return r;
    defer gpa.free(index);
    r.modified = git_mod.indexModified(gpa, io, repo, index);
    const commit = r.commit() orelse return r;
    var head: git_mod.Oid = undefined;
    if (commit.len != 40) return r;
    _ = std.fmt.hexToBytes(&head, commit) catch return r;
    var store = git_mod.Store.open(gpa, io, git) orelse return r;
    defer store.close();
    r.staged = git_mod.stagedFiles(gpa, &store, &head, index);
    return r;
}

fn readHead(gpa: Allocator, io: Io, git: Io.Dir, r: *Revision) void {
    var buf: [512]u8 = undefined;
    const head = std.mem.trim(u8, git.readFile(io, "HEAD", &buf) catch return, " \t\r\n");
    if (!std.mem.startsWith(u8, head, "ref: ")) {
        _ = r.setCommit(head);
        return;
    }
    const ref = std.mem.trim(u8, head["ref: ".len..], " \t");
    if (ref.len == 0 or ref.len > r.ref_buf.len or std.mem.indexOf(u8, ref, "..") != null) return;
    @memcpy(r.ref_buf[0..ref.len], ref);
    r.ref_len = @intCast(ref.len);
    if (lookupRef(gpa, io, git, r.ref().?, r)) return;
    // A worktree's refs live in the main repository's git directory.
    var cbuf: [512]u8 = undefined;
    const common_path = std.mem.trim(u8, git.readFile(io, "commondir", &cbuf) catch return, " \t\r\n");
    const common = git.openDir(io, common_path, .{}) catch return;
    defer common.close(io);
    _ = lookupRef(gpa, io, common, r.ref().?, r);
}

/// Tracked files whose working copy differs from the index (`git.zig`).
pub const indexModified = git_mod.indexModified;

fn openGitDir(io: Io, repo: Io.Dir) ?Io.Dir {
    if (repo.openDir(io, ".git", .{})) |d| return d else |_| {}
    var buf: [1024]u8 = undefined;
    const text = std.mem.trim(u8, repo.readFile(io, ".git", &buf) catch return null, " \t\r\n");
    if (!std.mem.startsWith(u8, text, "gitdir:")) return null;
    return repo.openDir(io, std.mem.trim(u8, text["gitdir:".len..], " \t"), .{}) catch null;
}

fn lookupRef(gpa: Allocator, io: Io, git: Io.Dir, ref: []const u8, r: *Revision) bool {
    var buf: [256]u8 = undefined;
    if (git.readFile(io, ref, &buf)) |text| {
        if (r.setCommit(text)) return true;
    } else |_| {}
    const packed_refs = git.readFileAlloc(io, "packed-refs", gpa, .limited(64 << 20)) catch return false;
    defer gpa.free(packed_refs);
    var lines = std.mem.splitScalar(u8, packed_refs, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#' or line[0] == '^') continue;
        const space = std.mem.indexOfScalar(u8, line, ' ') orelse continue;
        if (!std.mem.eql(u8, std.mem.trim(u8, line[space + 1 ..], " \t"), ref)) continue;
        return r.setCommit(line[0..space]);
    }
    return false;
}

pub const Bundle = struct {
    manifest: Manifest,
    campaign: *const Campaign,
    failures: *const tardis.FailureLog,
    mcdc: ?*const mcdc.Report = null,
    /// The project's declared decisions (dead code, MC/DC per requirement).
    decisions: []const mcdc.Decl = &.{},
    /// Edges never run (§7.1); null or not `measured` writes an
    /// `edges.json` that says the counters were not read.
    edges: ?*const edges.Report = null,
    determinism: []const DeterminismRow = &.{},
    /// The test that ran the campaign, for SARIF locations.
    source: ?std.builtin.SourceLocation = null,
    /// Prepended to `source.file` (the path of its module root in the repository).
    source_prefix: []const u8 = "",
};

pub const build_mode = @tagName(builtin.mode);
pub const host = @tagName(builtin.cpu.arch) ++ "-" ++ @tagName(builtin.os.tag);

// ---------------------------------------------------------------------------
// Writing

fn jsonString(w: *Io.Writer, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        0...8, 11, 12, 14...0x1F => try w.print("\\u{x:0>4}", .{c}),
        else => try w.writeByte(c),
    };
    try w.writeByte('"');
}

fn csvField(w: *Io.Writer, s: []const u8) !void {
    if (std.mem.indexOfAny(u8, s, ",\"\r\n") == null) return w.writeAll(s);
    try w.writeByte('"');
    for (s) |c| {
        if (c == '"') try w.writeByte('"');
        try w.writeByte(c);
    }
    try w.writeByte('"');
}

fn writeManifest(w: *Io.Writer, b: Bundle) !void {
    const m = b.manifest;
    try w.writeAll("{\n  \"tool\": \"tardis_sec\",\n  \"tool_version\": ");
    try jsonString(w, m.tool_version);
    try w.print(",\n  \"zig_version\": \"{s}\",\n  \"build_mode\": \"{s}\",\n  \"host\": \"{s}\",\n  \"campaign\": ", .{ builtin.zig_version_string, build_mode, host });
    try jsonString(w, m.campaign);
    try w.writeAll(",\n  \"campaign_id\": ");
    try jsonString(w, m.campaign_id);
    try w.print(",\n  \"campaign_seed\": \"0x{x:0>16}\",\n  \"iterations\": {d},\n  \"personas\": [", .{ m.campaign_seed, m.iterations });
    for (m.personas, 0..) |p, i| {
        if (i > 0) try w.writeAll(", ");
        try w.print("\"{s}\"", .{@tagName(p)});
    }
    try w.print("],\n  \"nodes\": {d},\n  \"mode\": ", .{m.nodes});
    try jsonString(w, m.mode);
    try w.writeAll(",\n  \"revisions\": [");
    for (m.revisions, 0..) |*r, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("\n    {\"name\": ");
        try jsonString(w, r.name);
        try w.writeAll(", \"commit\": ");
        if (r.commit()) |c| try jsonString(w, c) else try w.writeAll("null");
        try w.writeAll(", \"ref\": ");
        if (r.ref()) |x| try jsonString(w, x) else try w.writeAll("null");
        try w.writeAll(", \"modified_files\": ");
        if (r.modified) |count| try w.print("{d}", .{count}) else try w.writeAll("null");
        try w.writeAll(", \"staged_files\": ");
        if (r.staged) |count| try w.print("{d}", .{count}) else try w.writeAll("null");
        try w.writeAll("}");
    }
    try w.writeAll(if (m.revisions.len > 0) "\n  ]" else "]");
    try w.print(
        ",\n  \"runs\": {d},\n  \"failures\": {d},\n  \"failures_logged\": {d},\n  \"findings\": {d},\n  \"findings_dropped\": {d},\n  \"requirements\": {d}\n}}\n",
        .{ b.campaign.runs, b.failures.failures(), b.failures.len, b.campaign.findings_len, b.campaign.findings_dropped, b.campaign.requirements.len },
    );
}

fn tokenFor(b: Bundle, seed: u64) []const u8 {
    const e = b.failures.bySeed(seed) orelse return "";
    return e.token();
}

/// requirement ⇄ test, with the results and the replay of the first failure.
fn writeRtm(w: *Io.Writer, b: Bundle) !void {
    try w.writeAll("requirement,status,test,checks_passed,checks_failed,tests_digest,first_failure_seed,replay,mcdc_decisions_covered,mcdc_decisions_total\n");
    for (b.campaign.requirements.slice()) |*r| {
        try csvField(w, r.idSlice());
        try w.print(",{s},", .{switch (r.status()) {
            .pass => "PASS",
            .fail => "FAIL",
            .gap => "GAP",
        }});
        if (r.boundTo(b.campaign.name)) try csvField(w, b.campaign.name);
        try w.print(",{d},{d},{x:0>16},", .{ r.checks_passed, r.checks_failed, r.tests_digest });
        if (r.checks_failed > 0) {
            try w.print("0x{x:0>16},", .{r.first_failure_seed});
            try csvField(w, tokenFor(b, r.first_failure_seed));
        } else try w.writeAll(",");
        try w.print(",{d},{d}\n", .{ r.mcdc_decisions_covered, r.mcdc_decisions_total });
    }
}

fn writeMcdc(w: *Io.Writer, b: Bundle) !void {
    try w.writeAll("{\"decisions\": [");
    var reached: u32 = 0;
    var complete: u32 = 0;
    if (b.mcdc) |rep| for (rep.table.entries, 0..) |e, id| {
        if (!e.reached()) continue;
        if (reached > 0) try w.writeAll(",");
        reached += 1;
        if (e.complete()) complete += 1;
        try w.print("\n  {{\"id\": {d}, ", .{id});
        if (mcdc.declOf(b.decisions, id)) |d| try writeDeclFields(w, d);
        try w.print("\"conditions\": {d}, \"vectors\": {d}, \"complete\": {}, \"pairs\": [", .{ e.conditions, e.vectorsSeen(), e.complete() });
        for (0..e.conditions) |c| {
            if (c > 0) try w.writeAll(", ");
            if (e.pair(@intCast(c))) |p| try w.print("[{d}, {d}]", .{ p[0], p[1] }) else try w.writeAll("null");
        }
        try w.writeAll("], \"gaps\": [");
        var first = true;
        for (0..e.conditions) |c| {
            if (e.pair(@intCast(c)) != null) continue;
            if (!first) try w.writeAll(", ");
            first = false;
            try w.print("{d}", .{c});
        }
        // Per gap, a vector to test next; null: no test can show it.
        try w.writeAll("], \"wanted\": [");
        first = true;
        for (0..e.conditions) |c| {
            if (e.pair(@intCast(c)) != null) continue;
            if (!first) try w.writeAll(", ");
            first = false;
            if (e.wanted(@intCast(c))) |v| try w.print("{d}", .{v}) else try w.writeAll("null");
        }
        try w.writeAll("]}");
    };
    // Declared decisions never reached: dead, or deactivated by design.
    try w.writeAll("\n], \"unreached\": [");
    var dead: u32 = 0;
    var deactivated: u32 = 0;
    for (b.decisions) |*d| {
        if (reachedDecision(b, d.id)) continue;
        if (dead + deactivated > 0) try w.writeAll(",");
        if (d.deactivated != null) deactivated += 1 else dead += 1;
        try w.print("\n  {{\"id\": {d}, ", .{d.id});
        try writeDeclFields(w, d);
        try w.writeAll(if (d.deactivated != null) "\"status\": \"deactivated\"}" else "\"status\": \"dead\"}");
    }
    // Reached but never declared: the declaration list is incomplete.
    try w.writeAll("\n], \"undeclared\": [");
    var undeclared: u32 = 0;
    if (b.decisions.len > 0) if (b.mcdc) |rep| for (rep.table.entries, 0..) |e, id| {
        if (!e.reached() or mcdc.declOf(b.decisions, id) != null) continue;
        if (undeclared > 0) try w.writeAll(", ");
        undeclared += 1;
        try w.print("{d}", .{id});
    };
    try w.print("], \"reached\": {d}, \"complete\": {d}, \"dead\": {d}, \"deactivated\": {d}}}\n", .{ reached, complete, dead, deactivated });
}

fn reachedDecision(b: Bundle, id: u8) bool {
    const rep = b.mcdc orelse return false;
    return rep.table.entries[id].reached();
}

fn writeDeclFields(w: *Io.Writer, d: *const mcdc.Decl) !void {
    try w.writeAll("\"name\": ");
    try jsonString(w, d.name);
    if (d.requirement) |r| {
        try w.writeAll(", \"requirement\": ");
        try jsonString(w, r);
    }
    if (d.deactivated) |j| {
        try w.writeAll(", \"justification\": ");
        try jsonString(w, j);
    }
    try w.writeAll(", ");
}

pub fn cweName(cwe: u16) []const u8 {
    return switch (cwe) {
        200 => "Exposure of Sensitive Information to an Unauthorized Actor",
        226 => "Sensitive Information in Resource Not Removed Before Reuse",
        367 => "Time-of-check Time-of-use (TOCTOU) Race Condition",
        22 => "Improper Limitation of a Pathname to a Restricted Directory",
        125 => "Out-of-bounds Read",
        787 => "Out-of-bounds Write",
        272 => "Least Privilege Violation",
        134 => "Use of Externally-Controlled Format String",
        89 => "Improper Neutralization of Special Elements used in an SQL Command",
        78 => "Improper Neutralization of Special Elements used in an OS Command",
        400 => "Uncontrolled Resource Consumption",
        1037 => "Processor Optimization Removal or Modification of Security-critical Code",
        407 => "Inefficient Algorithmic Complexity",
        416 => "Use After Free",
        668 => "Exposure of Resource to Wrong Sphere",
        833 => "Deadlock",
        908 => "Use of Uninitialized Resource",
        else => "",
    };
}

fn writeLockClass(w: *Io.Writer, class: u16) !void {
    const first = engine.races.file_lock_class_first;
    if (class >= first) return w.print("file lock {d}", .{class - first + 1});
    const c_first = engine.races.c_lock_class_first;
    if (class >= c_first) return w.print("mutex {d} (by address)", .{class - c_first + 1});
    return w.print("class {d}", .{class});
}

fn describe(w: *Io.Writer, f: engine.Finding) !void {
    switch (f.kind) {
        .lock_order => {
            try w.writeAll("locks taken in inverted order: ");
            try writeLockClass(w, f.detail[0]);
            try w.writeAll(" held while taking ");
            return writeLockClass(w, f.detail[1]);
        },
        .amplification => {
            const r: engine.amplify.Ratio = @fromBackingInt(@as(u8, @intCast(f.detail[0])));
            return w.print("{t} reached {d}.{d:0>3}, over its limit", .{ r, f.offset / 1000, f.offset % 1000 });
        },
        .overflow => return w.print("a write past the end of a {d}-byte allocation changed its guard (first at offset {d}), found at its free", .{ f.offset - f.detail[0], f.offset }),
        .tainted_path => {
            const node = if (f.sink) |s| s.node else 0;
            return w.print("received bytes, not sanitized, in a path used on node {d} (path offset {d})", .{ node, f.offset });
        },
        .privilege => {
            const what: engine.Privilege = @fromBackingInt(@intCast(f.detail[0]));
            return w.print("node {d} used {t} after its sandbox dropped it", .{ f.detail[1], what });
        },
        .tainted_format => return w.print("received bytes, not sanitized, in a C format string on node {d} (offset {d})", .{ f.detail[1], f.offset }),
        .write_past_end => return w.print("a {d}-byte write on node {d} landed {d} bytes past the end of an allocation", .{ f.detail[0], f.detail[1], f.offset }),
        .read_past_end => return w.print("a {d}-byte read on node {d} landed {d} bytes past the end of an allocation", .{ f.detail[0], f.detail[1], f.offset }),
        .use_after_free => return w.print("a {d}-byte {s} of freed memory on node {d}", .{ f.detail[0], if (f.offset != 0) "write" else "read", f.detail[1] }),
        .data_race => return w.print("task {d} {s} an address on node {d} that task {d} {s}, and nothing orders the two", .{ f.offset & 0xffff, if (f.offset & 0x10000 != 0) "stored to" else "loaded from", f.detail[1], f.detail[0], if (f.offset & 0x20000 != 0) "stored to" else "loaded from" }),
        .tainted_sql => return w.print("received bytes, not sanitized, in SQL text on node {d} (offset {d})", .{ f.detail[1], f.offset }),
        .spectre_v1 => return w.print("after a bounds check on node {d}, load {d} reads an address that moves {d} bytes per unit of the value load {d} returned (the Spectre-v1 shape)", .{ f.detail[1], f.offset % 16, f.detail[0], f.offset / 16 }),
        .tainted_command => return w.print("received bytes, not sanitized, in argument {d} of a process spawned on node {d} (offset {d})", .{ f.detail[0], f.detail[1], f.offset }),
        else => {},
    }
    const what = switch (f.kind) {
        .uninit => "uninitialized bytes",
        .freed => "freed bytes",
        .secret => "secret bytes",
        .tenant_data => "another tenant's bytes",
        .redzone => "guard bytes past the end of an allocation",
        else => unreachable,
    };
    const s = f.sink orelse return w.print("{s} survived their free (not zeroed)", .{what});
    try w.print("{s} reached a {t} sink (node {d} -> node {d}) at payload offset {d}", .{ what, s.kind, s.node, s.peer_node, f.offset });
    if (f.kind == .tenant_data) try w.print(" (tenant {d} -> tenant {d})", .{ f.tenant, f.dest_tenant });
}

fn writeLocation(w: *Io.Writer, b: Bundle) !void {
    const src = b.source orelse return;
    try w.writeAll(",\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":");
    var buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const uri = std.fmt.bufPrint(&buf, "{s}{s}", .{ b.source_prefix, src.file }) catch src.file;
    try jsonString(w, uri);
    try w.print("}},\"region\":{{\"startLine\":{d}}}}}}}]", .{src.line});
}

fn writeReplay(w: *Io.Writer, b: Bundle, seed: u64) !void {
    try w.print(",\"properties\":{{\"seed\":\"0x{x:0>16}\"", .{seed});
    const token = tokenFor(b, seed);
    if (token.len > 0) {
        try w.writeAll(",\"replayToken\":");
        try jsonString(w, token);
    }
    try w.writeAll("}");
}

// ---------------------------------------------------------------------------
// Per-check SARIF (seam 4's emitter, without `certify`)

/// A source position for SARIF: a repository-relative path when the file
/// is under the current directory, else the path as the debug info has it.
pub const Location = struct {
    uri_buf: [512]u8 = undefined,
    uri_len: u16 = 0,
    line: u64 = 0,

    pub fn uri(l: *const Location) []const u8 {
        return l.uri_buf[0..l.uri_len];
    }
};

/// Resolves a return address to the file and line of its call through the
/// program's own debug info (DWARF, or PDB on Windows). Null without debug
/// info (stripped builds) or on targets `std.debug` cannot symbolize.
pub fn locate(gpa: Allocator, io: Io, address: usize) ?Location {
    if (std.debug.SelfInfo == void or address == 0) return null else {
        const si = std.debug.getSelfDebugInfo() catch return null;
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        // The symbol list must use the debug-info allocator: with another
        // one, `getSymbols` hangs on Linux (Zig 0.17; checked in WSL).
        const symbol_allocator = std.debug.getDebugInfoAllocator();
        var symbols: std.ArrayList(std.debug.Symbol) = .empty;
        defer symbols.deinit(symbol_allocator);
        // The return address is the instruction after the call.
        si.getSymbols(io, symbol_allocator, arena.allocator(), address - 1, false, &symbols) catch return null;
        for (symbols.items) |sym| {
            const sl = sym.source_location orelse continue;
            if (sl.file_name.len == 0 or sl.line == 0) continue;
            var l: Location = .{ .line = sl.line };
            var path = sl.file_name;
            const cwd: ?[]u8 = std.process.currentPathAlloc(io, arena.allocator()) catch null;
            if (cwd) |c| if (path.len > c.len + 1 and std.mem.eql(u8, path[0..c.len], c) and (path[c.len] == '/' or path[c.len] == '\\')) {
                path = path[c.len + 1 ..];
            };
            const n = @min(path.len, l.uri_buf.len);
            for (path[0..n], l.uri_buf[0..n]) |ch, *out| out.* = if (ch == '\\') '/' else ch;
            l.uri_len = @intCast(n);
            return l;
        }
        return null;
    }
}

/// What `writeCheckSarif` reports: one failed `check`.
pub const CheckReport = struct {
    tool_version: []const u8,
    err: anyerror,
    /// The failing (shrunk) run's findings; empty for failures that are not
    /// security findings.
    findings: []const engine.Finding,
    token: []const u8,
    location: ?Location,
};

/// SARIF v2.1.0 for one failed `check`: a result per distinct finding
/// (`CWE-n`), or one `tardis/failure` when no finding explains it, located
/// at the test's call to `check` and carrying the replay token.
pub fn writeCheckSarif(w: *Io.Writer, r: CheckReport) !void {
    try w.print("{{\"$schema\":\"{s}\",\"version\":\"2.1.0\",\"runs\":[{{\"tool\":{{\"driver\":{{\"name\":\"tardis_sec\",\"version\":", .{sarif_schema});
    try jsonString(w, r.tool_version);
    try w.writeAll(",\"rules\":[");
    var keys: [engine.findings_max]u64 = undefined;
    var keys_len: usize = 0;
    var cwes: [engine.findings_max]u16 = undefined;
    var cwes_len: usize = 0;
    for (r.findings) |f| {
        if (std.mem.indexOfScalar(u16, cwes[0..cwes_len], f.cwe) != null) continue;
        cwes[cwes_len] = f.cwe;
        cwes_len += 1;
        try w.print("{{\"id\":\"CWE-{d}\",\"name\":", .{f.cwe});
        try jsonString(w, cweName(f.cwe));
        try w.print(",\"helpUri\":\"https://cwe.mitre.org/data/definitions/{d}.html\"}},", .{f.cwe});
    }
    try w.writeAll("{\"id\":\"tardis/failure\",\"name\":\"A simulated run failed\"}]}},\"results\":[");
    var first = true;
    for (r.findings) |f| {
        const k = campaign_mod.Logged.key(f);
        if (std.mem.indexOfScalar(u64, keys[0..keys_len], k) != null) continue;
        keys[keys_len] = k;
        keys_len += 1;
        if (!first) try w.writeAll(",");
        first = false;
        try w.print("\n{{\"ruleId\":\"CWE-{d}\",\"level\":\"error\",\"message\":{{\"text\":", .{f.cwe});
        var text_buf: [256]u8 = undefined;
        var tw: Io.Writer = .fixed(&text_buf);
        describe(&tw, f) catch {};
        try jsonString(w, tw.buffered());
        try w.print("}},\"partialFingerprints\":{{\"tardisFinding/v1\":\"{x:0>16}\"}}", .{k});
        try writeCheckTail(w, r);
    }
    if (first) {
        try w.print("\n{{\"ruleId\":\"tardis/failure\",\"level\":\"error\",\"message\":{{\"text\":\"error.{s}\"}}", .{@errorName(r.err)});
        try writeCheckTail(w, r);
    }
    try w.writeAll("\n]}]}\n");
}

fn writeCheckTail(w: *Io.Writer, r: CheckReport) !void {
    if (r.location) |*l| {
        try w.writeAll(",\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":");
        try jsonString(w, l.uri());
        try w.print("}},\"region\":{{\"startLine\":{d}}}}}}}]", .{l.line});
    }
    try w.writeAll(",\"properties\":{\"error\":");
    try jsonString(w, @errorName(r.err));
    if (r.token.len > 0) {
        try w.writeAll(",\"replayToken\":");
        try jsonString(w, r.token);
    }
    try w.writeAll("}}");
}

/// SARIF v2.1.0: one result per distinct finding (rule `CWE-n`), per failed
/// requirement (`tardis/requirement`) and per logged failure no finding
/// explains (`tardis/failure`), each with its seed and replay token.
pub fn writeSarif(w: *Io.Writer, b: Bundle) !void {
    try w.print("{{\"$schema\":\"{s}\",\"version\":\"2.1.0\",\"runs\":[{{\"tool\":{{\"driver\":{{\"name\":\"tardis_sec\",\"version\":", .{sarif_schema});
    try jsonString(w, b.manifest.tool_version);
    try w.writeAll(",\"rules\":[");
    // Rules: each CWE once, then the two tardis rules.
    var seen: [campaign_mod.findings_max]u16 = undefined;
    var seen_len: usize = 0;
    for (b.campaign.findingsSlice()) |l| {
        if (std.mem.indexOfScalar(u16, seen[0..seen_len], l.finding.cwe) != null) continue;
        seen[seen_len] = l.finding.cwe;
        seen_len += 1;
        try w.print("{{\"id\":\"CWE-{d}\",\"name\":", .{l.finding.cwe});
        try jsonString(w, cweName(l.finding.cwe));
        try w.print(",\"helpUri\":\"https://cwe.mitre.org/data/definitions/{d}.html\"}},", .{l.finding.cwe});
    }
    try w.writeAll(
        \\{"id":"tardis/requirement","name":"A security functional requirement failed a check"},
        \\{"id":"tardis/failure","name":"A simulated run failed"},
        \\{"id":"tardis/mcdc-gap","name":"A declared decision has conditions without an MC/DC independence pair"},
        \\{"id":"tardis/dead-decision","name":"A declared decision was never reached"},
        \\{"id":"tardis/dead-edge","name":"Code in the certified scope never ran in the campaign"},
        \\{"id":"tardis/stale-justification","name":"Code justified as deactivated ran in the campaign"}]}},"results":[
    );
    var first = true;
    for (b.campaign.findingsSlice()) |l| {
        if (!first) try w.writeAll(",");
        first = false;
        try w.print("\n{{\"ruleId\":\"CWE-{d}\",\"level\":\"error\",\"message\":{{\"text\":", .{l.finding.cwe});
        var text_buf: [256]u8 = undefined;
        var tw: Io.Writer = .fixed(&text_buf);
        describe(&tw, l.finding) catch {};
        tw.print(" ({d} occurrence{s})", .{ l.occurrences, if (l.occurrences == 1) "" else "s" }) catch {};
        try jsonString(w, tw.buffered());
        try w.print("}},\"partialFingerprints\":{{\"tardisFinding/v1\":\"{x:0>16}\"}}", .{campaign_mod.Logged.key(l.finding)});
        try writeLocation(w, b);
        try writeReplay(w, b, l.seed);
        try w.writeAll("}");
    }
    for (b.campaign.requirements.slice()) |*r| {
        if (r.checks_failed == 0) continue;
        if (!first) try w.writeAll(",");
        first = false;
        try w.writeAll("\n{\"ruleId\":\"tardis/requirement\",\"level\":\"error\",\"message\":{\"text\":");
        var text_buf: [256]u8 = undefined;
        const text = std.fmt.bufPrint(&text_buf, "{s} failed {d} of {d} checks", .{ r.idSlice(), r.checks_failed, r.checks() }) catch r.idSlice();
        try jsonString(w, text);
        try w.writeAll("},\"partialFingerprints\":{\"tardisRequirement/v1\":");
        try jsonString(w, r.idSlice());
        try w.writeAll("}");
        try writeLocation(w, b);
        try writeReplay(w, b, r.first_failure_seed);
        try w.writeAll("}");
    }
    for (b.failures.slice()) |*e| {
        const explained = for (b.campaign.findingsSlice()) |l| {
            if (l.seed == e.seed) break true;
        } else false;
        if (explained) continue;
        if (!first) try w.writeAll(",");
        first = false;
        try w.print("\n{{\"ruleId\":\"tardis/failure\",\"level\":\"error\",\"message\":{{\"text\":\"error.{s} in iteration {d} (persona {s})\"}}", .{ @errorName(e.err), e.iteration + 1, @tagName(e.persona) });
        try writeLocation(w, b);
        try writeReplay(w, b, e.seed);
        try w.writeAll("}");
    }
    // Declared decisions: conditions never shown (a warning: a missing test
    // vector or redundant logic), and decisions never reached (dead code is
    // a warning; deactivated code with its justification is a note).
    for (b.decisions) |*d| {
        const e: mcdc.Entry = if (b.mcdc) |rep| rep.table.entries[d.id] else .{};
        var text_buf: [512]u8 = undefined;
        var tw: Io.Writer = .fixed(&text_buf);
        const rule, const level = if (!e.reached()) blk: {
            if (d.deactivated) |j| {
                tw.print("decision {d} ({s}) is deactivated: {s}", .{ d.id, d.name, j }) catch {};
                break :blk .{ "tardis/dead-decision", "note" };
            }
            tw.print("decision {d} ({s}) was never reached: dead code", .{ d.id, d.name }) catch {};
            break :blk .{ "tardis/dead-decision", "warning" };
        } else blk: {
            const missing = mcdc.gaps(e);
            if (missing == 0) continue;
            tw.print("decision {d} ({s}): conditions", .{ d.id, d.name }) catch {};
            for (0..e.conditions) |c| if (missing & (@as(u8, 1) << @intCast(c)) != 0) tw.print(" {d}", .{c}) catch {};
            tw.print(" of {d} have no independence pair", .{e.conditions}) catch {};
            break :blk .{ "tardis/mcdc-gap", "warning" };
        };
        if (d.requirement) |r| tw.print(" (requirement {s})", .{r}) catch {};
        if (!first) try w.writeAll(",");
        first = false;
        try w.print("\n{{\"ruleId\":\"{s}\",\"level\":\"{s}\",\"message\":{{\"text\":", .{ rule, level });
        try jsonString(w, tw.buffered());
        try w.print("}},\"partialFingerprints\":{{\"tardisDecision/v1\":\"{d}\"}}", .{d.id});
        try writeLocation(w, b);
        try w.writeAll("}");
    }
    // Lines with edges that never ran (an untaken branch, an error never
    // returned, or unreached code): each is for the project to justify
    // (deactivated code, a note with its reason) or remove (a warning).
    // A justified line whose edges all ran is a warning: the code it calls
    // deactivated ran.
    if (b.edges) |r| {
        for (r.lines) |l| {
            if (!first) try w.writeAll(",");
            first = false;
            var text_buf: [512]u8 = undefined;
            var tw: Io.Writer = .fixed(&text_buf);
            tw.print("{d} of the {d} edge{s} counted at this line never ran in the campaign", .{ l.edges - l.hit, l.edges, if (l.edges == 1) "" else "s" }) catch {};
            if (l.justification) |j| {
                tw.print(": deactivated: {s}", .{j}) catch {};
            } else {
                tw.writeAll(" (an untaken branch, an error never returned, or unreached code)") catch {};
            }
            try writeLineResult(w, "tardis/dead-edge", if (l.justification != null) "note" else "warning", tw.buffered(), l);
        }
        for (r.stale) |l| {
            if (!first) try w.writeAll(",");
            first = false;
            var text_buf: [512]u8 = undefined;
            var tw: Io.Writer = .fixed(&text_buf);
            tw.print("justified as deactivated ({s}), but all {d} edge{s} counted at this line ran in the campaign", .{ l.justification.?, l.edges, if (l.edges == 1) "" else "s" }) catch {};
            try writeLineResult(w, "tardis/stale-justification", "warning", tw.buffered(), l);
        }
    }
    try w.writeAll("\n]}]}\n");
}

/// A SARIF result at a source line, fingerprinted by file and line.
fn writeLineResult(w: *Io.Writer, rule: []const u8, level: []const u8, text: []const u8, l: edges.Line) !void {
    try w.print("\n{{\"ruleId\":\"{s}\",\"level\":\"{s}\",\"message\":{{\"text\":", .{ rule, level });
    try jsonString(w, text);
    try w.writeAll("},\"partialFingerprints\":{\"tardisEdge/v1\":");
    var fp_buf: [Io.Dir.max_path_bytes + 16]u8 = undefined;
    try jsonString(w, std.fmt.bufPrint(&fp_buf, "{s}:{d}", .{ l.file, l.line }) catch l.file);
    try w.writeAll("},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":");
    try jsonString(w, l.file);
    try w.print("}},\"region\":{{\"startLine\":{d}}}}}}}]}}", .{l.line});
}

/// `sinks.json`: the taint sink audit log (§5.2). For each sink, the
/// checks counted runs made and the hits among them, with every distinct
/// hit (the finding, its first run and how often it recurred), so the
/// bundle shows that a sink was exercised and not only whether it failed.
fn writeSinks(w: *Io.Writer, b: Bundle) !void {
    try w.writeAll("{\"runs\": ");
    try w.print("{d}, \"sinks\": [", .{b.campaign.runs});
    for (0..engine.sink_kinds) |i| {
        const sink: engine.SinkKind = @fromBackingInt(@intCast(i));
        const kind = sink.findingKind();
        var hits: u64 = 0;
        for (b.campaign.findingsSlice()) |l| {
            if (l.finding.kind == kind) hits += l.occurrences;
        }
        if (i > 0) try w.writeAll(",");
        try w.print("\n  {{\"sink\": \"{t}\", \"cwe\": {d}, \"checks\": {d}, \"hits\": {d}, \"distinct\": [", .{ sink, sink.cwe(), b.campaign.sink_checks[i], hits });
        var first = true;
        for (b.campaign.findingsSlice()) |l| {
            if (l.finding.kind != kind) continue;
            if (!first) try w.writeAll(", ");
            first = false;
            const node: u16 = if (l.finding.sink) |s| s.node else l.finding.detail[1];
            try w.print("{{\"node\": {d}, \"offset\": {d}, \"seed\": \"0x{x:0>16}\", \"occurrences\": {d}", .{ node, l.finding.offset, l.seed, l.occurrences });
            const token = tokenFor(b, l.seed);
            if (token.len > 0) {
                try w.writeAll(", \"replay\": ");
                try jsonString(w, token);
            }
            try w.writeAll("}");
        }
        try w.writeAll("]}");
    }
    try w.writeAll("\n]}\n");
}

/// `edges.json`: whether the campaign's edge counters were read, the scope,
/// the edges in it and those that ran, each line where an edge never ran,
/// with how many of its edges did and its justification if deactivated,
/// and the justified lines that ran (`edges.zig` says what that means).
fn writeEdges(w: *Io.Writer, b: Bundle) !void {
    const empty: edges.Report = .{};
    const r = b.edges orelse &empty;
    try w.print("{{\"instrumented\": {}, \"measured\": {}, \"scope\": [", .{ edges.instrumented, r.measured });
    for (r.scope, 0..) |sc, i| {
        if (i > 0) try w.writeAll(", ");
        try w.writeAll("{\"file\": ");
        try jsonString(w, sc.file);
        try w.writeAll(", \"functions\": [");
        for (sc.functions, 0..) |f, k| {
            if (k > 0) try w.writeAll(", ");
            try jsonString(w, f);
        }
        try w.writeAll("]}");
    }
    try w.print("],\n \"edges\": {d}, \"hit\": {d}, \"unplaced\": {d}, \"justified\": {d}, \"lines\": [", .{ r.edges, r.hit, r.unplaced, r.justified() });
    try writeEdgeLines(w, r.lines);
    try w.writeAll("],\n \"stale\": [");
    try writeEdgeLines(w, r.stale);
    try w.writeAll("]}\n");
}

fn writeEdgeLines(w: *Io.Writer, lines: []const edges.Line) !void {
    for (lines, 0..) |l, i| {
        if (i > 0) try w.writeAll(",");
        try w.writeAll("\n  {\"file\": ");
        try jsonString(w, l.file);
        try w.print(", \"line\": {d}, \"edges\": {d}, \"hit\": {d}, \"justification\": ", .{ l.line, l.edges, l.hit });
        if (l.justification) |j| try jsonString(w, j) else try w.writeAll("null");
        try w.writeAll("}");
    }
}

fn writeDeterminism(w: *Io.Writer, b: Bundle) !void {
    try w.writeAll("# build_mode host persona seed trace_hash\n");
    for (b.determinism) |r| try w.print("{s} {s} {s} 0x{x:0>16} 0x{x:0>16}\n", .{ build_mode, host, @tagName(r.persona), r.seed, r.trace_hash });
}

fn writeCapsule(w: *Io.Writer, e: *const tardis.FailureLog.Entry) !void {
    try w.print("token {s}\nerror {s}\niteration {d}\npersona {s}\nseed 0x{x:0>16}\nshrunk {}\n", .{ e.token(), @errorName(e.err), e.iteration + 1, @tagName(e.persona), e.seed, e.shrunk });
}

/// The leaf of `path` with content digest `digest`.
pub fn leafOf(path: []const u8, digest: [32]u8) [32]u8 {
    var h = Sha256.init(.{});
    h.update("tardis-evidence-leaf\x00");
    h.update(path);
    h.update("\x00");
    h.update(&digest);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// Merkle root over leaves (pairs hashed, an odd leaf promoted); `leaves`
/// is overwritten.
pub fn merkleRoot(leaves: [][32]u8) [32]u8 {
    std.debug.assert(leaves.len > 0);
    var n = leaves.len;
    while (n > 1) {
        var out: usize = 0;
        var i: usize = 0;
        while (i < n) : (i += 2) {
            if (i + 1 == n) {
                leaves[out] = leaves[i];
            } else {
                var h = Sha256.init(.{});
                h.update(&leaves[i]);
                h.update(&leaves[i + 1]);
                h.final(&leaves[out]);
            }
            out += 1;
        }
        n = out;
    }
    return leaves[0];
}

const Listing = struct {
    paths: std.ArrayList([]u8) = .empty,
    digests: std.ArrayList([32]u8) = .empty,

    fn deinit(l: *Listing, gpa: Allocator) void {
        for (l.paths.items) |p| gpa.free(p);
        l.paths.deinit(gpa);
        l.digests.deinit(gpa);
    }

    fn root(l: *const Listing, gpa: Allocator) ![32]u8 {
        const leaves = try gpa.alloc([32]u8, l.paths.items.len);
        defer gpa.free(leaves);
        for (leaves, l.paths.items, l.digests.items) |*leaf, p, d| leaf.* = leafOf(p, d);
        return merkleRoot(leaves);
    }
};

const Out = struct {
    gpa: Allocator,
    io: Io,
    dir: Io.Dir,
    listing: Listing = .{},
    buf: Io.Writer.Allocating,

    fn put(o: *Out, path: []const u8) !void {
        const data = o.buf.written();
        try o.dir.writeFile(o.io, .{ .sub_path = path, .data = data });
        var d: [32]u8 = undefined;
        Sha256.hash(data, &d, .{});
        try o.listing.paths.append(o.gpa, try o.gpa.dupe(u8, path));
        try o.listing.digests.append(o.gpa, d);
        o.buf.clearRetainingCapacity();
    }
};

pub const Written = struct { root: [32]u8, files: u32, signed: bool };

/// Writes the bundle into `dir` (which should be empty or hold an older
/// bundle of the same campaign: its capsules are removed first).
pub fn write(gpa: Allocator, io: Io, dir: Io.Dir, b: Bundle, key: ?Ed25519.KeyPair) !Written {
    var o: Out = .{ .gpa = gpa, .io = io, .dir = dir, .buf = .init(gpa) };
    defer o.buf.deinit();
    defer o.listing.deinit(gpa);
    const w = &o.buf.writer;

    try writeManifest(w, b);
    try o.put("manifest.json");
    try writeRtm(w, b);
    try o.put("rtm.csv");
    try writeMcdc(w, b);
    try o.put("mcdc.json");
    try writeEdges(w, b);
    try o.put("edges.json");
    try writeSarif(w, b);
    try o.put("findings.sarif");
    try writeSinks(w, b);
    try o.put("sinks.json");
    try writeDeterminism(w, b);
    try o.put("determinism.txt");
    dir.deleteTree(io, "capsules") catch {};
    dir.deleteFile(io, "signature.ed25519") catch {};
    if (b.failures.len > 0) try dir.createDirPath(io, "capsules");
    for (b.failures.slice(), 0..) |*e, i| {
        try writeCapsule(w, e);
        var name: [64]u8 = undefined;
        try o.put(try std.fmt.bufPrint(&name, "capsules/{d:0>4}.tardis-replay", .{i}));
    }

    const root = try o.listing.root(gpa);
    for (o.listing.paths.items, o.listing.digests.items) |p, d| try w.print("{x}  {s}\n", .{ &d, p });
    try w.print("root {x}\n", .{&root});
    try dir.writeFile(io, .{ .sub_path = "merkle.txt", .data = o.buf.written() });
    o.buf.clearRetainingCapacity();
    if (key) |kp| {
        const sig = try kp.sign(&root, null);
        try w.print("public-key {x}\nsignature {x}\n", .{ &kp.public_key.toBytes(), &sig.toBytes() });
        try dir.writeFile(io, .{ .sub_path = "signature.ed25519", .data = o.buf.written() });
    }
    return .{ .root = root, .files = @intCast(o.listing.paths.items.len), .signed = key != null };
}

// ---------------------------------------------------------------------------
// Verifying

pub const VerifyError = error{
    MalformedBundle,
    HashMismatch,
    RootMismatch,
    UnlistedFile,
    Unsigned,
    KeyMismatch,
    BadSignature,
};

pub const Verified = struct {
    root: [32]u8,
    files: u32,
    signed: bool,
    public_key: [32]u8 = @splat(0),
    capsules: u32,
};

const file_bytes_max = 64 * 1024 * 1024;

fn safePath(p: []const u8) bool {
    if (p.len == 0 or p[0] == '/' or std.mem.indexOf(u8, p, "..") != null) return false;
    for (p) |c| switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', '_', '-', '/' => {},
        else => return false,
    };
    return true;
}

fn hex32(text: []const u8) VerifyError![32]u8 {
    var out: [32]u8 = undefined;
    const got = std.fmt.hexToBytes(&out, text) catch return error.MalformedBundle;
    if (got.len != 32) return error.MalformedBundle;
    return out;
}

fn listed(l: *const Listing, path: []const u8) bool {
    for (l.paths.items) |p| if (std.mem.eql(u8, p, path)) return true;
    return false;
}

fn readListing(gpa: Allocator, io: Io, dir: Io.Dir, l: *Listing) ![32]u8 {
    const text = dir.readFileAlloc(io, "merkle.txt", gpa, .limited(file_bytes_max)) catch return error.MalformedBundle;
    defer gpa.free(text);
    var claimed: ?[32]u8 = null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "root ")) {
            claimed = try hex32(line["root ".len..]);
            continue;
        }
        const sep = std.mem.indexOf(u8, line, "  ") orelse return error.MalformedBundle;
        const path = line[sep + 2 ..];
        if (!safePath(path) or listed(l, path)) return error.MalformedBundle;
        try l.digests.append(gpa, try hex32(line[0..sep]));
        try l.paths.append(gpa, try gpa.dupe(u8, path));
    }
    if (l.paths.items.len == 0) return error.MalformedBundle;
    return claimed orelse error.MalformedBundle;
}

/// Every file in the bundle (top level and `capsules/`) must be listed.
fn checkComplete(io: Io, dir: Io.Dir, l: *const Listing) !void {
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind == .directory and std.mem.eql(u8, entry.name, "capsules")) continue;
        if (std.mem.eql(u8, entry.name, "merkle.txt") or std.mem.eql(u8, entry.name, "signature.ed25519")) continue;
        if (!listed(l, entry.name)) return error.UnlistedFile;
    }
    var caps = dir.openDir(io, "capsules", .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer caps.close(io);
    var cit = caps.iterate();
    while (try cit.next(io)) |entry| {
        var buf: [Io.Dir.max_path_bytes]u8 = undefined;
        const p = std.fmt.bufPrint(&buf, "capsules/{s}", .{entry.name}) catch return error.UnlistedFile;
        if (!listed(l, p)) return error.UnlistedFile;
    }
}

/// Checks the bundle in `dir` (opened with `.iterate = true`): every listed
/// file hashes to its digest, no file is unlisted, the root matches, and
/// the signature verifies. With `expected_key`, the bundle must be signed
/// by that key; without it the embedded key is only checked for
/// consistency (integrity, not authenticity).
pub fn verify(gpa: Allocator, io: Io, dir: Io.Dir, expected_key: ?Ed25519.PublicKey) !Verified {
    var l: Listing = .{};
    defer l.deinit(gpa);
    const claimed = try readListing(gpa, io, dir, &l);
    var capsules: u32 = 0;
    for (l.paths.items, l.digests.items) |p, want| {
        const data = dir.readFileAlloc(io, p, gpa, .limited(file_bytes_max)) catch return error.HashMismatch;
        defer gpa.free(data);
        var got: [32]u8 = undefined;
        Sha256.hash(data, &got, .{});
        if (!std.mem.eql(u8, &got, &want)) return error.HashMismatch;
        if (std.mem.startsWith(u8, p, "capsules/")) capsules += 1;
    }
    try checkComplete(io, dir, &l);
    const root = try l.root(gpa);
    if (!std.mem.eql(u8, &root, &claimed)) return error.RootMismatch;

    var out: Verified = .{ .root = root, .files = @intCast(l.paths.items.len), .signed = false, .capsules = capsules };
    const sig_text = dir.readFileAlloc(io, "signature.ed25519", gpa, .limited(4096)) catch |err| switch (err) {
        error.FileNotFound => {
            if (expected_key != null) return error.Unsigned;
            return out;
        },
        else => return err,
    };
    defer gpa.free(sig_text);
    var pk_bytes: ?[32]u8 = null;
    var sig_bytes: ?[64]u8 = null;
    var lines = std.mem.splitScalar(u8, sig_text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (std.mem.startsWith(u8, line, "public-key ")) {
            pk_bytes = try hex32(line["public-key ".len..]);
        } else if (std.mem.startsWith(u8, line, "signature ")) {
            var s: [64]u8 = undefined;
            const got = std.fmt.hexToBytes(&s, line["signature ".len..]) catch return error.MalformedBundle;
            if (got.len != 64) return error.MalformedBundle;
            sig_bytes = s;
        }
    }
    const pkb = pk_bytes orelse return error.MalformedBundle;
    const sb = sig_bytes orelse return error.MalformedBundle;
    if (expected_key) |k| if (!std.mem.eql(u8, &k.toBytes(), &pkb)) return error.KeyMismatch;
    const pk = Ed25519.PublicKey.fromBytes(pkb) catch return error.BadSignature;
    Ed25519.Signature.fromBytes(sb).verify(&root, pk) catch return error.BadSignature;
    out.signed = true;
    out.public_key = pkb;
    return out;
}

pub const Capsule = struct {
    token: []const u8,
    err: []const u8,
};

/// Parses a capsule (slices point into `text`).
pub fn parseCapsule(text: []const u8) VerifyError!Capsule {
    var c: Capsule = .{ .token = "", .err = "" };
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (std.mem.startsWith(u8, line, "token ")) c.token = line["token ".len..];
        if (std.mem.startsWith(u8, line, "error ")) c.err = line["error ".len..];
    }
    if (c.token.len == 0 or c.err.len == 0) return error.MalformedBundle;
    return c;
}

pub const ReplayError = error{ CapsuleMismatch, DeterminismMismatch };

pub const Replayed = struct {
    verified: Verified,
    capsules_replayed: u32 = 0,
    /// Determinism rows from this build mode and host (others are listed
    /// but cannot be checked here).
    determinism_checked: u32 = 0,
    determinism_other: u32 = 0,
};

/// The options a replay uses: the caller's, with campaign sinks removed
/// (they may point at memory of the campaign that wrote the bundle).
fn replayOptions(options: tardis.Options) tardis.Options {
    var o = options;
    o.report = false;
    o.keep_going = null;
    o.shrink_report = null;
    o.explore_report = null;
    if (o.security) |*sec| {
        sec.params[@backingInt(engine.Param.campaign)] = 0;
        sec.params[@backingInt(engine.Param.mcdc_report)] = 0;
        sec.params[@backingInt(engine.Param.report)] = 0;
    }
    return o;
}

/// `verify`, then re-runs every capsule (it must fail with its recorded
/// error) and recomputes the determinism hashes of this build mode and
/// host. `body` and `options` are the campaign's.
pub fn replay(gpa: Allocator, io: Io, dir: Io.Dir, expected_key: ?Ed25519.PublicKey, comptime body: fn (*tardis.Env) anyerror!void, options: tardis.Options) !Replayed {
    var out: Replayed = .{ .verified = try verify(gpa, io, dir, expected_key) };
    const o = replayOptions(options);
    var l: Listing = .{};
    defer l.deinit(gpa);
    _ = try readListing(gpa, io, dir, &l);
    for (l.paths.items) |p| {
        if (!std.mem.startsWith(u8, p, "capsules/")) continue;
        const text = try dir.readFileAlloc(io, p, gpa, .limited(file_bytes_max));
        defer gpa.free(text);
        const c = try parseCapsule(text);
        var run = o;
        run.replay = c.token;
        tardis.check(gpa, body, run) catch |err| {
            if (!std.mem.eql(u8, @errorName(err), c.err)) return error.CapsuleMismatch;
            out.capsules_replayed += 1;
            continue;
        };
        return error.CapsuleMismatch; // it passed
    }
    const det = try dir.readFileAlloc(io, "determinism.txt", gpa, .limited(file_bytes_max));
    defer gpa.free(det);
    var lines = std.mem.splitScalar(u8, det, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0 or line[0] == '#') continue;
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        const mode = f.next() orelse return error.MalformedBundle;
        const h = f.next() orelse return error.MalformedBundle;
        const persona_name = f.next() orelse return error.MalformedBundle;
        const seed = std.fmt.parseInt(u64, f.next() orelse return error.MalformedBundle, 0) catch return error.MalformedBundle;
        const want = std.fmt.parseInt(u64, f.next() orelse return error.MalformedBundle, 0) catch return error.MalformedBundle;
        if (!std.mem.eql(u8, mode, build_mode) or !std.mem.eql(u8, h, host)) {
            out.determinism_other += 1;
            continue;
        }
        const persona = std.meta.stringToEnum(tardis.Persona, persona_name) orelse return error.MalformedBundle;
        const got = try tardis.traceHash(gpa, body, seed, persona, o);
        if (got != want) return error.DeterminismMismatch;
        out.determinism_checked += 1;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

/// A small bundle without a simulation: one finding, one failed and one
/// passing requirement, a gap, one logged failure.
pub fn testBundle(c: *Campaign, log: *tardis.FailureLog) Bundle {
    c.name = "unit: evidence";
    c.requirements.declare("SFR-FDP_ACC.1\nSFR-FIA_UAU.6\nSFR-FPT_TST.1\n") catch unreachable;
    c.commit(0x51, 0, &.{ .{ .index = 0, .passed = 3, .failed = 0 }, .{ .index = 1, .passed = 1, .failed = 1 } }, &.{.{
        .cwe = 200,
        .kind = .secret,
        .tenant = 0,
        .dest_tenant = 0,
        .sink = .{ .kind = .datagram, .node = 0, .peer_node = 2, .id = 1 },
        .offset = 12,
        .at_ns = 0,
    }}, .{ 5, 0, 0, 0 });
    log.* = .{};
    log.entries[0] = .{ .iteration = 4, .persona = .linux_ext4, .seed = 0x51, .err = error.SecurityViolation, .shrunk = true, .token_buf = undefined, .token_len = 0 };
    const t = "linux_ext4:0x0000000000000051:*";
    @memcpy(log.entries[0].token_buf[0..t.len], t);
    log.entries[0].token_len = t.len;
    log.len = 1;
    return .{
        .manifest = .{
            .tool_version = "0.1.0",
            .campaign = c.name,
            .campaign_id = "00000000000000aa",
            .campaign_seed = 1,
            .iterations = 8,
            .personas = &.{.linux_ext4},
            .nodes = 3,
            .mode = "certification_eal7",
        },
        .campaign = c,
        .failures = log,
        .source = @src(),
        .source_prefix = "src/sec/",
    };
}

test "revisions: branches (loose and packed), detached HEADs and worktrees, without git" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const d = tmp.dir;
    const a = "0123456789abcdef0123456789abcdef01234567";
    const b2 = "89abcdef0123456789abcdef0123456789abcdef";
    const c3 = "fedcba9876543210fedcba9876543210fedcba98";
    // A branch with a loose ref, and a worktree on another branch.
    try d.createDirPath(io, "loose/.git/refs/heads");
    try d.writeFile(io, .{ .sub_path = "loose/.git/HEAD", .data = "ref: refs/heads/main\n" });
    try d.writeFile(io, .{ .sub_path = "loose/.git/refs/heads/main", .data = a ++ "\n" });
    try d.writeFile(io, .{ .sub_path = "loose/.git/refs/heads/feature", .data = c3 ++ "\n" });
    try d.createDirPath(io, "loose/.git/worktrees/wt");
    try d.writeFile(io, .{ .sub_path = "loose/.git/worktrees/wt/HEAD", .data = "ref: refs/heads/feature\n" });
    try d.writeFile(io, .{ .sub_path = "loose/.git/worktrees/wt/commondir", .data = "../..\n" });
    try d.createDirPath(io, "wt");
    try d.writeFile(io, .{ .sub_path = "wt/.git", .data = "gitdir: ../loose/.git/worktrees/wt\n" });
    // A branch only in packed-refs (after `git gc`).
    try d.createDirPath(io, "packed/.git");
    try d.writeFile(io, .{ .sub_path = "packed/.git/HEAD", .data = "ref: refs/heads/dev\n" });
    try d.writeFile(io, .{ .sub_path = "packed/.git/packed-refs", .data = "# pack-refs with: peeled fully-peeled sorted\n" ++ a ++ " refs/heads/main\n" ++ b2 ++ " refs/heads/dev\n^" ++ c3 ++ "\n" });
    // A detached HEAD (CI checkouts of pull requests).
    try d.createDirPath(io, "detached/.git");
    try d.writeFile(io, .{ .sub_path = "detached/.git/HEAD", .data = c3 ++ "\n" });
    try d.createDirPath(io, "plain");

    const cases = [_]struct { path: []const u8, commit: ?[]const u8, ref: ?[]const u8 }{
        .{ .path = "loose", .commit = a, .ref = "refs/heads/main" },
        .{ .path = "wt", .commit = c3, .ref = "refs/heads/feature" },
        .{ .path = "packed", .commit = b2, .ref = "refs/heads/dev" },
        .{ .path = "detached", .commit = c3, .ref = null },
        .{ .path = "plain", .commit = null, .ref = null },
    };
    for (cases) |case| {
        const repo = try d.openDir(io, case.path, .{});
        defer repo.close(io);
        const r = readRevision(testing.allocator, io, repo, case.path);
        if (case.commit) |c| try testing.expectEqualStrings(c, r.commit().?) else try testing.expectEqual(@as(?[]const u8, null), r.commit());
        if (case.ref) |x| try testing.expectEqualStrings(x, r.ref().?) else try testing.expectEqual(@as(?[]const u8, null), r.ref());
    }
}

test "revisions: modified tracked files are counted from the index, CRLF checkouts included" {
    const io = testing.io;
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const d = tmp.dir;
    try d.createDirPath(io, "repo/.git");
    try d.createDirPath(io, "repo/src");
    try d.writeFile(io, .{ .sub_path = "repo/.git/HEAD", .data = "0123456789abcdef0123456789abcdef01234567\n" });
    const repo = try d.openDir(io, "repo", .{});
    defer repo.close(io);
    // No index yet: unknown.
    try testing.expectEqual(@as(?u32, null), readRevision(gpa, io, repo, "repo").modified);

    const index = try git_mod.testIndex(gpa, &.{
        .{ "README", "hello\n", 0 },
        .{ "src/main.zig", "pub fn main() void {}\n", 0 },
        .{ "src/crlf.txt", "one\ntwo\n", 0 },
    });
    defer gpa.free(index);
    try d.writeFile(io, .{ .sub_path = "repo/.git/index", .data = index });
    try d.writeFile(io, .{ .sub_path = "repo/README", .data = "hello\n" });
    try d.writeFile(io, .{ .sub_path = "repo/src/main.zig", .data = "pub fn main() void {}\n" });
    // Checked out with CRLF line endings (core.autocrlf): unchanged.
    try d.writeFile(io, .{ .sub_path = "repo/src/crlf.txt", .data = "one\r\ntwo\r\n" });
    // Untracked files do not count.
    try d.writeFile(io, .{ .sub_path = "repo/notes.txt", .data = "scratch" });
    try testing.expectEqual(@as(?u32, 0), readRevision(gpa, io, repo, "repo").modified);

    try d.writeFile(io, .{ .sub_path = "repo/README", .data = "hello, world\n" });
    try testing.expectEqual(@as(?u32, 1), readRevision(gpa, io, repo, "repo").modified);
    try d.deleteFile(io, "repo/src/main.zig");
    try testing.expectEqual(@as(?u32, 2), readRevision(gpa, io, repo, "repo").modified);
}

test "evidence: write, verify, and every kind of tampering is caught" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const c = try gpa.create(Campaign);
    defer gpa.destroy(c);
    c.init("");
    var log: tardis.FailureLog = undefined;
    const b = testBundle(c, &log);
    const kp = Ed25519.KeyPair.generateDeterministic(@splat(7)) catch unreachable;
    const w = try write(gpa, io, tmp.dir, b, kp);
    try testing.expectEqual(@as(u32, 8), w.files);
    var sinks_buf: [1024]u8 = undefined;
    const sinks = try tmp.dir.readFile(io, "sinks.json", &sinks_buf);
    try testing.expect(std.mem.indexOf(u8, sinks, "{\"sink\": \"path\", \"cwe\": 22, \"checks\": 5, \"hits\": 0, \"distinct\": []}") != null);

    const v = try verify(gpa, io, tmp.dir, kp.public_key);
    try testing.expect(v.signed);
    try testing.expectEqual(w.root, v.root);
    try testing.expectEqual(@as(u32, 1), v.capsules);

    const rtm = try tmp.dir.readFileAlloc(io, "rtm.csv", gpa, .unlimited);
    defer gpa.free(rtm);
    try testing.expect(std.mem.indexOf(u8, rtm, "SFR-FDP_ACC.1,PASS,unit: evidence,3,0,") != null);
    try testing.expect(std.mem.indexOf(u8, rtm, "SFR-FIA_UAU.6,FAIL,unit: evidence,1,1,") != null);
    try testing.expect(std.mem.indexOf(u8, rtm, "0x0000000000000051,linux_ext4:0x0000000000000051:*") != null);
    try testing.expect(std.mem.indexOf(u8, rtm, "SFR-FPT_TST.1,GAP,,0,0,") != null);

    const sarif = try tmp.dir.readFileAlloc(io, "findings.sarif", gpa, .unlimited);
    defer gpa.free(sarif);
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, sarif, .{});
    defer parsed.deinit();
    const run = parsed.value.object.get("runs").?.array.items[0];
    const results = run.object.get("results").?.array.items;
    try testing.expectEqual(@as(usize, 2), results.len); // the finding and the failed requirement
    try testing.expectEqualStrings("CWE-200", results[0].object.get("ruleId").?.string);
    try testing.expectEqualStrings("tardis/requirement", results[1].object.get("ruleId").?.string);
    const loc = results[0].object.get("locations").?.array.items[0].object.get("physicalLocation").?.object;
    try testing.expectEqualStrings("src/sec/evidence.zig", loc.get("artifactLocation").?.object.get("uri").?.string);

    // Tampering: a changed file, an extra file, a wrong key, a missing signature.
    try tmp.dir.writeFile(io, .{ .sub_path = "rtm.csv", .data = "requirement\n" });
    try testing.expectError(error.HashMismatch, verify(gpa, io, tmp.dir, kp.public_key));
    _ = try write(gpa, io, tmp.dir, b, kp);
    try tmp.dir.writeFile(io, .{ .sub_path = "capsules/0001.tardis-replay", .data = "token x\nerror y\n" });
    try testing.expectError(error.UnlistedFile, verify(gpa, io, tmp.dir, kp.public_key));
    _ = try write(gpa, io, tmp.dir, b, kp);
    const other = Ed25519.KeyPair.generateDeterministic(@splat(8)) catch unreachable;
    try testing.expectError(error.KeyMismatch, verify(gpa, io, tmp.dir, other.public_key));
    _ = try write(gpa, io, tmp.dir, b, null);
    try testing.expectError(error.Unsigned, verify(gpa, io, tmp.dir, kp.public_key));
    try testing.expect(!(try verify(gpa, io, tmp.dir, null)).signed);
}
