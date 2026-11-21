//! The live security engine behind core's seam (plan2.md §3, week 13).
//!
//! An ordinary Zig build has no load/store instrumentation, so a per-word
//! shadow cannot follow `@memcpy`: a secret copied into a response buffer
//! reaches the socket from an address the shadow never saw. This engine
//! tracks *content* instead, which survives any copy (for code built with
//! the sanitizer's callbacks, `shadow.zig` adds a shadow of the heap):
//!
//! * **Uninitialized and freed heap bytes.** Every allocation is filled
//!   with a per-run 8-byte pattern laid out by address (byte at address `a`
//!   is `uninit[a % 8]`), and every free overwrites the bytes with a second
//!   pattern. Both patterns derive from the run seed, so a run replays
//!   bit for bit. A copy at any alignment contains a rotation of the
//!   pattern, so all 8 rotations of each are fingerprints.
//! * **Secrets and tenant data.** `markSecret` / `markTenant` fingerprint
//!   every 8-byte window of the bytes at the time they are marked.
//!
//! Every byte written to a socket or file is scanned with a sliding 8-byte
//! window against the fingerprint set: one hash lookup per byte. A match is
//! a finding: uninitialized bytes leaving (CWE-908), freed bytes leaving
//! (CWE-416), a secret leaving (CWE-200), or one tenant's data reaching a
//! peer bound to another tenant (CWE-668). A free of a marked secret whose
//! bytes are not all zero is CWE-226 (missing zeroization).
//!
//! Safe build modes (Debug, ReleaseSafe): `Allocator.alloc` and `free`
//! overwrite the bytes with `undefined` (0xAA) around the allocator call, so
//! there 8 bytes of 0xAA are also an uninitialized fingerprint (this also
//! catches stack buffers declared `undefined`), and a secret's bytes are
//! already 0xAA when the free hook sees them: CWE-226 at free is reported
//! only where the secret's bytes actually survive the free (ReleaseFast,
//! ReleaseSmall, or a direct `rawFree`).
//!
//! Limits, by construction: leaks shorter than 8 bytes are not seen;
//! windows with fewer than 3 distinct byte values are not fingerprinted
//! (they would match ordinary data); a secret on the stack is checked at
//! egress but not at the end of its lifetime. A false positive needs an
//! unrelated 8-byte window to equal a fingerprint: about
//! `fingerprints / 2^64` per byte scanned.
//!
//! Capacities are fixed at `create`; the engine allocates nothing per run.

const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");
const tardis = @import("tardis");
const seam = tardis.sec_seam;
pub const races = @import("races.zig");
const ctrace = @import("ctrace.zig");
pub const amplify = @import("amplify.zig");
pub const mcdc = @import("mcdc.zig");
pub const spectre = @import("spectre.zig");
pub const campaign = @import("campaign.zig");
pub const edges = @import("edges.zig");
pub const shadow = @import("shadow.zig");
pub const datarace = @import("datarace.zig");

/// The build fills `undefined` memory with 0xAA (Debug, ReleaseSafe).
pub const safe_fill = std.debug.runtime_safety;
const undefined_byte: u8 = 0xAA;

pub const TenantId = u8;
pub const tenant_system: TenantId = 0;

pub const fingerprints_max = 16 * 1024;
/// Tainted windows of received bytes per run (§5.2).
pub const untrusted_max = 16 * 1024;
pub const regions_max = 256;
pub const findings_max = 64;
pub const nodes_max = 32;
pub const window_bytes = 8;

pub const Kind = enum(u8) {
    /// Allocated but never written (CWE-908 at egress).
    uninit,
    /// Freed (CWE-416 at egress).
    freed,
    /// `markSecret` (CWE-200 at egress, CWE-226 when freed unzeroed).
    secret,
    /// `markTenant` (CWE-668 at egress to another tenant's peer).
    tenant_data,
    /// Lock-order inversion (CWE-833), from `Mutex`.
    lock_order,
    /// A resource ratio over its limit (CWE-400 / 407); `detail[0]` is the
    /// `amplify.Ratio`, `offset` the ratio in thousandths (saturated).
    amplification,
    /// Received bytes, not sanitized, in a path that is opened, created,
    /// deleted or renamed (CWE-22, §5.2).
    tainted_path,
    /// Core's guard bytes after an allocation (CWE-125 at egress: an
    /// over-read past the end).
    redzone,
    /// A guard found changed when its allocation was freed (CWE-787: a
    /// write past the end).
    overflow,
    /// A capability used after `enterSandbox` dropped it (CWE-272, §5.2);
    /// `detail[0]` is the `Privilege`, `detail[1]` the node.
    privilege,
    /// Received bytes, not sanitized, in the command of a process spawn
    /// (CWE-78, §5.2); `detail[0]` is the argument's index.
    tainted_command,
    /// Received bytes, not sanitized, in a C format string (CWE-134,
    /// through the C shims).
    tainted_format,
    /// Received bytes, not sanitized, in SQL text (CWE-89, through the C
    /// shims).
    tainted_sql,
    /// After a marked bounds check, a load whose address follows the
    /// value of an earlier load (CWE-1037, §6.3); `detail[0]` is the
    /// address's bytes per unit of the value (capped), `detail[1]` the
    /// node, `offset` the two loads' places in the window (first * 16 +
    /// second).
    spectre_v1,
    /// Instrumented code wrote to the guard after an allocation (CWE-787,
    /// §3.8), found at the store; `offset` is how far past the end,
    /// `detail[0]` the bytes written, `detail[1]` the node.
    write_past_end,
    /// Instrumented code read the guard after an allocation (CWE-125);
    /// fields as for `write_past_end`.
    read_past_end,
    /// Instrumented code read or wrote a freed block (CWE-416);
    /// `offset` is 1 for a write, `detail` as for `write_past_end`.
    use_after_free,
    /// Two tasks of one node touched one address, at least one with a
    /// store, and nothing orders them (CWE-362, §4.5). `detail[0]` is
    /// the earlier task, `detail[1]` the node; `offset` is the later
    /// task, plus 0x10000 if it stored and 0x20000 if the earlier did.
    data_race,

    pub fn cwe(k: Kind) u16 {
        return switch (k) {
            .uninit => 908,
            .freed => 416,
            .secret => 200,
            .tenant_data => 668,
            .lock_order => 833,
            .amplification => 400,
            .tainted_path => 22,
            .redzone => 125,
            .overflow => 787,
            .privilege => 272,
            .tainted_command => 78,
            .tainted_format => 134,
            .tainted_sql => 89,
            .spectre_v1 => 1037,
            .write_past_end => 787,
            .read_past_end => 125,
            .use_after_free => 416,
            .data_race => 362,
        };
    }
};

pub const Origin = struct {
    kind: Kind,
    tenant: TenantId,
};

/// A finding: what left, where to, and at which payload offset; or, for
/// `lock_order`, the two lock classes (`detail`).
pub const Finding = struct {
    cwe: u16,
    kind: Kind,
    /// The owner of the leaked bytes (secrets and tenant data).
    tenant: TenantId,
    /// Tenant bound to the destination (0: none).
    dest_tenant: TenantId,
    /// Null for findings not tied to I/O (CWE-226 at free, CWE-833).
    sink: ?seam.Sink,
    /// Offset of the first matching byte in the written payload.
    offset: u32,
    /// `lock_order`: the class held and the class taken.
    detail: [2]u16 = .{ 0, 0 },
    /// The run's virtual time, for the report.
    at_ns: u64,
};

const Region = struct {
    addr: usize,
    len: usize,
    node: seam.NodeId,
    kind: Kind,
};

/// Words in `seam.Params` (`withSecurity` fills them).
pub const Param = enum(u5) {
    glitch_ppm = 0,
    mode = 1,
    report = 2,
    /// Probability that a checked path is swapped for a symlink before use.
    toctou_ppm = 3,
    /// Probability of a forced task switch at the second read of a shared word.
    double_fetch_ppm = 4,
    /// Probability that an equivocating node's datagram is rewritten.
    byzantine_ppm = 5,
    /// Non-zero: amplification limits are checked (`amplify.pack` in 7, 8).
    amplification = 6,
    amplification_limits_a = 7,
    amplification_limits_b = 8,
    /// `*mcdc.Report` that receives the MC/DC table at the end, or 0.
    mcdc_report = 9,
    /// `*campaign.Campaign` that receives requirement checks and findings
    /// at the end of every counted run, or 0.
    campaign = 10,
    /// `*const std.Io.Dir` where a failed `check` writes its SARIF, or 0
    /// (then `TARDIS_SARIF_DIR`, in tests).
    check_sarif = 11,
    /// The swaps a won check-to-use race may make (`ToctouSwaps` bits).
    toctou_swaps = 12,
    /// Non-zero: received network bytes are tainted, and a path that holds
    /// them is a finding (§5.2).
    taint_paths = 13,
    /// Non-zero: the heap is shadowed, and accesses reported by
    /// instrumented code are checked against it (§3.8).
    shadow = 14,
    /// Non-zero: accesses reported by instrumented code are checked for
    /// data races (§4.5, bit 0), and its lock-shaped atomics for lock
    /// order (§4.6, bit 1).
    data_races = 15,
    /// Non-zero: eight bytes of 0xAA leaving the program are not taken
    /// for undefined memory (`SecurityConfig.undefined_fill_is_data`).
    undefined_fill_is_data = 16,
};

pub const paths_max = 8;

/// The taint sinks (§5.2), counted per run for the audit log.
pub const SinkKind = enum(u8) {
    /// A VFS path opened, created, deleted or renamed (CWE-22).
    path,
    /// A spawn's argv or a C `system` command (CWE-78).
    command,
    /// A C format string (CWE-134).
    format,
    /// C SQL text (CWE-89).
    sql,

    pub fn cwe(k: SinkKind) u16 {
        return switch (k) {
            .path => 22,
            .command => 78,
            .format => 134,
            .sql => 89,
        };
    }

    /// The finding kind a hit in this sink is reported as.
    pub fn findingKind(k: SinkKind) Kind {
        return switch (k) {
            .path => .tainted_path,
            .command => .tainted_command,
            .format => .tainted_format,
            .sql => .tainted_sql,
        };
    }
};
pub const sink_kinds = std.enums.values(SinkKind).len;

/// Post-init capability lockdown (`tardis_sec.enterSandbox`, §5.2).
pub const SandboxPolicy = struct {
    allow_net_connect: bool = false,
    allow_net_listen: bool = true,
    allow_process_spawn: bool = false,
    /// Creating, deleting and renaming files (under `vfs_prefixes`).
    allow_vfs_write: bool = true,
    /// Path prefixes the program may still open, create, delete or rename
    /// after lockdown, compared byte for byte with the path as the program
    /// passes it (relative to its directory handle).
    vfs_prefixes: [paths_max][]const u8 = @splat(""),
    vfs_prefixes_len: u8 = 0,

    pub fn allowsPath(p: *const SandboxPolicy, path: []const u8) bool {
        for (p.vfs_prefixes[0..p.vfs_prefixes_len]) |prefix| {
            if (std.mem.startsWith(u8, path, prefix)) return true;
        }
        return false;
    }
};

/// What a `privilege` finding used (`Finding.detail[0]`).
pub const Privilege = enum(u16) {
    net_connect,
    net_listen,
    process_spawn,
    /// Opened a path outside `vfs_prefixes`.
    vfs_open,
    /// Created, deleted or renamed a file outside `vfs_prefixes`, or at all
    /// without `allow_vfs_write`.
    vfs_write,
};

/// Which swaps a won check-to-use race may make (§4.3); the engine picks
/// one of those that apply by a keyed decision.
pub const ToctouSwaps = packed struct(u8) {
    symlink: bool = true,
    hard_link: bool = true,
    parent_symlink: bool = true,
    /// Off by default: its effect is an `IsDir` error at the open, which a
    /// program that returns its errors simply fails with. Turn it on to
    /// test how a failed use after a passed check is handled (fail-open).
    directory: bool = false,
    _: u4 = 0,
};

/// Distinct requirements checked in one run.
pub const deltas_max = 64;

/// `SecurityConfig.report`: the findings of the last run (the failing one
/// when `check` fails, since a failure ends the campaign with its replay).
/// With `workers > 1` several threads would share it: use one worker.
pub const Report = struct {
    pub const len_max = 16;
    findings: [len_max]Finding = undefined,
    len: u8 = 0,

    pub fn slice(r: *const Report) []const Finding {
        return r.findings[0..r.len];
    }
};

pub const Engine = struct {
    params: seam.Params,
    seed: u64,
    uninit: [window_bytes]u8,
    freed: [window_bytes]u8,
    fingerprints: std.AutoHashMapUnmanaged(u64, Origin),
    /// Ingress taint: the distinctive 8-byte windows of bytes received from
    /// the network this run, until `markSanitized` (§5.2).
    untrusted: std.AutoHashMapUnmanaged(u64, void),
    /// Windows that did not fit in `untrusted` (not tainted).
    untrusted_dropped: u32,
    regions: [regions_max]Region,
    regions_len: u16,
    tenant_of_node: [nodes_max]TenantId,
    /// Each node's policy since its `enterSandbox`, until its program
    /// restarts (a crash, or the next run).
    sandboxes: [nodes_max]?SandboxPolicy,
    current_tenant: TenantId,
    findings: [findings_max]Finding,
    findings_len: u16,
    /// Findings beyond `findings_max`, and marks that did not fit.
    findings_dropped: u32,
    fingerprints_dropped: u32,
    rx_bytes: u64,
    tx_bytes: u64,
    races: races.State,
    ledger: amplify.Ledger,
    /// MC/DC coverage: kept across runs for the whole campaign.
    mcdc_table: mcdc.Table,
    /// Requirement checks of this run (committed at its end).
    deltas: [deltas_max]campaign.Delta,
    deltas_len: u16,
    /// Requirements beyond `deltas_max` in one run (not counted).
    deltas_dropped: u32,
    /// Spectre-v1 gadget shapes (§6.3): kept over the campaign's runs.
    spectre_detector: spectre.Detector,
    /// Taint checks made this run, by sink (whether they hit or not).
    sink_checks: [sink_kinds]u32,
    /// The last run's seed and `campaign.runOrder` (for `forkExport`).
    run_seed: u64,
    run_order: u64,
    /// The heap's shadow (§3.8), with `Param.shadow`.
    shadow_memory: ?shadow.Shadow,
    /// The data-race detector (§4.5), with `Param.data_races`.
    race_detector: ?datarace.Detector,

    pub fn param(e: *const Engine, p: Param) u64 {
        return e.params[@backingInt(p)];
    }

    pub fn campaignSink(e: *const Engine) ?*campaign.Campaign {
        const p = e.param(.campaign);
        if (p == 0) return null;
        return @ptrFromInt(p);
    }

    fn reportSink(e: *const Engine) ?*Report {
        const p = e.param(.report);
        if (p == 0) return null;
        return @ptrFromInt(p);
    }

    pub fn findingsSlice(e: *const Engine) []const Finding {
        return e.findings[0..e.findings_len];
    }

    fn reset(e: *Engine, seed: u64) void {
        e.seed = seed;
        e.fingerprints.clearRetainingCapacity();
        e.untrusted.clearRetainingCapacity();
        e.untrusted_dropped = 0;
        e.regions_len = 0;
        e.tenant_of_node = @splat(tenant_system);
        e.sandboxes = @splat(null);
        e.current_tenant = tenant_system;
        e.findings_len = 0;
        e.findings_dropped = 0;
        e.fingerprints_dropped = 0;
        e.rx_bytes = 0;
        e.tx_bytes = 0;
        if (e.reportSink()) |r| r.len = 0;
        e.races.reset();
        e.ledger = .{};
        e.deltas_len = 0;
        e.deltas_dropped = 0;
        e.sink_checks = @splat(0);
        if (e.shadow_memory) |*m| m.reset();
        if (e.race_detector) |*d| d.reset();
        e.uninit = patternFor(seed, 0x5EC0_0000_0000_0908);
        e.freed = patternFor(seed, 0x5EC0_0000_0000_0416);
        e.addRotations(e.uninit, .{ .kind = .uninit, .tenant = tenant_system });
        e.addRotations(e.freed, .{ .kind = .freed, .tenant = tenant_system });
        e.addRotations(seam.redzone_period, .{ .kind = .redzone, .tenant = tenant_system });
        if (safe_fill and e.param(.undefined_fill_is_data) == 0) e.addFingerprint(0xAAAA_AAAA_AAAA_AAAA, .{ .kind = .uninit, .tenant = tenant_system });
    }

    /// Eight bytes, all distinct and non-zero, from the run seed.
    fn patternFor(seed: u64, salt: u64) [window_bytes]u8 {
        var x = seed ^ salt;
        var out: [window_bytes]u8 = undefined;
        var n: usize = 0;
        while (n < window_bytes) {
            x = tardis.decide.mix(x, salt);
            var w = x;
            var k: usize = 0;
            while (k < 8 and n < window_bytes) : (k += 1) {
                const b: u8 = @truncate(w);
                w >>= 8;
                if (b == 0 or std.mem.indexOfScalar(u8, out[0..n], b) != null) continue;
                out[n] = b;
                n += 1;
            }
        }
        return out;
    }

    fn addRotations(e: *Engine, p: [window_bytes]u8, o: Origin) void {
        for (0..window_bytes) |r| {
            var w: [window_bytes]u8 = undefined;
            for (&w, 0..) |*b, i| b.* = p[(i + r) % window_bytes];
            e.addFingerprint(std.mem.readInt(u64, &w, .little), o);
        }
    }

    fn addFingerprint(e: *Engine, key: u64, o: Origin) void {
        if (e.fingerprints.get(key) != null) return;
        if (e.fingerprints.count() >= fingerprints_max) {
            e.fingerprints_dropped += 1;
            return;
        }
        e.fingerprints.putAssumeCapacity(key, o);
    }

    /// Fingerprints every distinctive 8-byte window of `bytes`.
    pub fn mark(e: *Engine, bytes: []const u8, kind: Kind, tenant: TenantId, node: seam.NodeId) void {
        assert(kind == .secret or kind == .tenant_data);
        if (bytes.len >= window_bytes) {
            var i: usize = 0;
            while (i + window_bytes <= bytes.len) : (i += 1) {
                const win = bytes[i..][0..window_bytes];
                if (!distinctive(win)) continue;
                e.addFingerprint(std.mem.readInt(u64, win, .little), .{ .kind = kind, .tenant = tenant });
            }
        }
        if (e.regions_len < regions_max) {
            e.regions[e.regions_len] = .{ .addr = @intFromPtr(bytes.ptr), .len = bytes.len, .node = node, .kind = kind };
            e.regions_len += 1;
        } else {
            e.fingerprints_dropped += 1;
        }
    }

    /// Taints the distinctive windows of received bytes.
    fn taint(e: *Engine, bytes: []const u8) void {
        if (bytes.len < window_bytes) return;
        var i: usize = 0;
        while (i + window_bytes <= bytes.len) : (i += 1) {
            const win = bytes[i..][0..window_bytes];
            if (!distinctive(win)) continue;
            const key = std.mem.readInt(u64, win, .little);
            if (e.untrusted.contains(key)) continue;
            if (e.untrusted.count() >= untrusted_max) {
                e.untrusted_dropped += 1;
                continue;
            }
            e.untrusted.putAssumeCapacity(key, {});
        }
    }

    /// `markSanitized`: these bytes were validated. Taint is by content,
    /// so equal bytes elsewhere are cleared too, until received again.
    pub fn sanitize(e: *Engine, bytes: []const u8) void {
        if (bytes.len < window_bytes) return;
        var i: usize = 0;
        while (i + window_bytes <= bytes.len) : (i += 1) {
            _ = e.untrusted.remove(std.mem.readInt(u64, bytes[i..][0..window_bytes], .little));
        }
    }

    /// The path sink: the first tainted window in `path`, or null.
    fn taintedAt(e: *const Engine, path: []const u8) ?usize {
        if (path.len < window_bytes or e.untrusted.count() == 0) return null;
        var i: usize = 0;
        while (i + window_bytes <= path.len) : (i += 1) {
            if (e.untrusted.contains(std.mem.readInt(u64, path[i..][0..window_bytes], .little))) return i;
        }
        return null;
    }

    pub fn enterSandbox(e: *Engine, node: seam.NodeId, policy: SandboxPolicy) void {
        if (node < nodes_max) e.sandboxes[node] = policy;
    }

    pub fn sandboxOf(e: *const Engine, node: seam.NodeId) ?*const SandboxPolicy {
        if (node >= nodes_max) return null;
        return if (e.sandboxes[node]) |*p| p else null;
    }

    /// A capability used after lockdown: CWE-272.
    fn privilegeUsed(e: *Engine, node: seam.NodeId, what: Privilege, sink: ?seam.Sink) u16 {
        e.report(.{
            .cwe = 272,
            .kind = .privilege,
            .tenant = tenant_system,
            .dest_tenant = tenant_system,
            .sink = sink,
            .offset = 0,
            .detail = .{ @backingInt(what), node },
            .at_ns = e.now(),
        });
        return 272;
    }

    fn distinctive(win: *const [window_bytes]u8) bool {
        var seen: [3]u8 = undefined;
        var n: usize = 0;
        for (win) |b| {
            if (std.mem.indexOfScalar(u8, seen[0..n], b) != null) continue;
            seen[n] = b;
            n += 1;
            if (n == seen.len) return true;
        }
        return false;
    }

    fn fill(mem: []u8, p: [window_bytes]u8) void {
        const base = @intFromPtr(mem.ptr);
        for (mem, 0..) |*b, i| b.* = p[(base + i) % window_bytes];
    }

    fn report(e: *Engine, f: Finding) void {
        if (e.reportSink()) |r| if (r.len < Report.len_max) {
            r.findings[r.len] = f;
            r.len += 1;
        };
        if (e.findings_len == findings_max) {
            e.findings_dropped += 1;
            return;
        }
        e.findings[e.findings_len] = f;
        e.findings_len += 1;
    }

    fn now(e: *const Engine) u64 {
        _ = e;
        const s = tardis.Sim.activeOrNull() orelse return 0;
        return s.now_ns;
    }

    fn onFree(e: *Engine, node: seam.NodeId, mem: []u8) u16 {
        var violation: u16 = 0;
        // Core's guard after the block, as the program left it.
        const guard = mem.ptr[mem.len..][0..seam.redzone_bytes];
        if (std.mem.indexOfDiff(u8, guard, &seam.redzone_pattern)) |at| {
            e.report(.{
                .cwe = 787,
                .kind = .overflow,
                .tenant = tenant_system,
                .dest_tenant = tenant_system,
                .sink = null,
                .offset = @intCast(mem.len + at),
                // `offset - detail[0]` is the allocation's length.
                .detail = .{ @intCast(at), 0 },
                .at_ns = e.now(),
            });
            violation = 787;
        }
        const lo = @intFromPtr(mem.ptr);
        const hi = lo + mem.len;
        var i: usize = 0;
        while (i < e.regions_len) {
            const r = e.regions[i];
            const r_hi = r.addr + r.len;
            if (r.node != node or r_hi <= lo or r.addr >= hi) {
                i += 1;
                continue;
            }
            if (r.kind == .secret) {
                const a = @max(lo, r.addr);
                const b = @min(hi, r_hi);
                for (mem[a - lo .. b - lo], 0..) |byte, k| {
                    if (byte == 0) continue;
                    if (safe_fill and byte == undefined_byte) continue; // scrubbed by `Allocator.free`
                    e.report(.{
                        .cwe = 226,
                        .kind = .secret,
                        .tenant = tenant_system,
                        .dest_tenant = tenant_system,
                        .sink = null,
                        .offset = @intCast(a - lo + k),
                        .at_ns = e.now(),
                    });
                    violation = 226;
                    break;
                }
            }
            e.regions[i] = e.regions[e.regions_len - 1];
            e.regions_len -= 1;
        }
        fill(mem, e.freed);
        // The block and its guard: any access from here on is a use
        // after free, until the heap hands the bytes out again.
        if (e.shadow_memory) |*m| m.mark(lo, mem.len + seam.redzone_bytes, .freed);
        return violation;
    }

    fn destTenant(e: *const Engine, sink: seam.Sink) TenantId {
        return switch (sink.kind) {
            .net_stream, .datagram => if (sink.peer_node < nodes_max) e.tenant_of_node[sink.peer_node] else tenant_system,
            .file => tenant_system,
        };
    }

    /// The scan: one finding per payload (the first match decides).
    pub fn scan(e: *Engine, sink: seam.Sink, bytes: []const u8) u16 {
        e.tx_bytes += bytes.len;
        if (bytes.len < window_bytes) return 0;
        const dest = e.destTenant(sink);
        var i: usize = 0;
        while (i + window_bytes <= bytes.len) : (i += 1) {
            const key = std.mem.readInt(u64, bytes[i..][0..window_bytes], .little);
            const o = e.fingerprints.get(key) orelse continue;
            if (o.kind == .tenant_data and (dest == tenant_system or dest == o.tenant)) continue;
            e.report(.{
                .cwe = o.kind.cwe(),
                .kind = o.kind,
                .tenant = o.tenant,
                .dest_tenant = dest,
                .sink = sink,
                .offset = @intCast(i),
                .at_ns = e.now(),
            });
            return o.kind.cwe();
        }
        return 0;
    }
};

// --- the provider core calls -------------------------------------------------

fn engineOf(ctx: *anyopaque) *Engine {
    return @ptrCast(@alignCast(ctx));
}

fn create(gpa: std.mem.Allocator, params: seam.Params) error{OutOfMemory}!*anyopaque {
    const e = try gpa.create(Engine);
    errdefer gpa.destroy(e);
    edges.engineCreated();
    errdefer edges.engineDestroyed();
    e.* = .{
        .params = params,
        .seed = 0,
        .uninit = undefined,
        .freed = undefined,
        .fingerprints = .empty,
        .untrusted = .empty,
        .untrusted_dropped = 0,
        .regions = undefined,
        .regions_len = 0,
        .tenant_of_node = @splat(tenant_system),
        .sandboxes = @splat(null),
        .current_tenant = tenant_system,
        .findings = undefined,
        .findings_len = 0,
        .findings_dropped = 0,
        .fingerprints_dropped = 0,
        .rx_bytes = 0,
        .tx_bytes = 0,
        .races = undefined,
        .ledger = .{},
        .mcdc_table = .{},
        .deltas = undefined,
        .deltas_len = 0,
        .deltas_dropped = 0,
        .spectre_detector = .{},
        .sink_checks = @splat(0),
        .run_seed = 0,
        .run_order = 0,
        .shadow_memory = null,
        .race_detector = null,
    };
    try e.fingerprints.ensureTotalCapacity(gpa, fingerprints_max);
    errdefer e.fingerprints.deinit(gpa);
    try e.untrusted.ensureTotalCapacity(gpa, untrusted_max);
    errdefer e.untrusted.deinit(gpa);
    if (e.param(.shadow) != 0) e.shadow_memory = try shadow.Shadow.init(gpa);
    errdefer if (e.shadow_memory) |*m| m.deinit(gpa);
    if (e.param(.data_races) & 1 != 0) e.race_detector = try datarace.Detector.init(gpa);
    e.reset(0);
    return e;
}

fn destroy(gpa: std.mem.Allocator, ctx: *anyopaque) void {
    const e = engineOf(ctx);
    const p = e.param(.mcdc_report);
    if (p != 0) {
        const r: *mcdc.Report = @ptrFromInt(p);
        r.merge(&e.mcdc_table);
    }
    e.fingerprints.deinit(gpa);
    e.untrusted.deinit(gpa);
    if (checking == e) checking = null;
    if (e.shadow_memory) |*m| m.deinit(gpa);
    if (e.race_detector) |*d| d.deinit(gpa);
    gpa.destroy(e);
    edges.engineDestroyed();
}

/// The engine that checks this thread's instrumented accesses, while one
/// of its runs is on: one thread-local load on the path of every load and
/// store, in place of the walk `active` makes.
threadlocal var checking: ?*Engine = null;

fn beginRun(ctx: *anyopaque, seed: u64) void {
    engineOf(ctx).reset(seed);
    const e = engineOf(ctx);
    checking = if (e.shadow_memory != null or e.race_detector != null) e else null;
    engineOf(ctx).spectre_detector.beginRun();
    ctrace.reset();
    edges.clear();
}

/// Comparison feedback (§7.1): the constants instrumented C compared
/// against in the run.
fn runTokens(ctx: *anyopaque) []const u64 {
    _ = ctx;
    return ctrace.current().constants();
}

fn onAlloc(ctx: *anyopaque, node: seam.NodeId, mem: []u8) void {
    _ = node;
    const e = engineOf(ctx);
    e.ledger.alloc_bytes += mem.len;
    Engine.fill(mem, e.uninit);
    if (e.shadow_memory) |*m| {
        m.mark(@intFromPtr(mem.ptr), mem.len, .valid);
        m.mark(@intFromPtr(mem.ptr) + mem.len, seam.redzone_bytes, .redzone);
    }
    if (e.race_detector) |*d| d.forget(@intFromPtr(mem.ptr), mem.len);
}

fn onFree(ctx: *anyopaque, node: seam.NodeId, mem: []u8) u16 {
    return engineOf(ctx).onFree(node, mem);
}

fn onHeapReset(ctx: *anyopaque, node: seam.NodeId) void {
    const e = engineOf(ctx);
    // The program restarts with every capability it had at startup.
    if (node < nodes_max) e.sandboxes[node] = null;
    var i: usize = 0;
    while (i < e.regions_len) {
        if (e.regions[i].node == node) {
            e.regions[i] = e.regions[e.regions_len - 1];
            e.regions_len -= 1;
        } else i += 1;
    }
}

/// The race detector's key for what one node's tasks pass each other
/// through its files or its sockets (§4.5): a task that reads comes
/// after every task of the node that wrote before it. Never an address.
fn messageKey(sink: seam.Sink) usize {
    const kind: usize = if (sink.kind == .file) 1 else 2;
    return (@as(usize, 1) << 62) | (kind << 40) | (@as(usize, sink.node) << 1) | 1;
}

fn onIngress(ctx: *anyopaque, sink: seam.Sink, bytes: []u8) void {
    const e = engineOf(ctx);
    if (e.race_detector) |*d| if (tardis.Sim.activeOrNull()) |s| d.acquire(s.current, messageKey(sink));
    e.rx_bytes += bytes.len;
    if (sink.kind != .file) {
        e.ledger.rx_bytes += bytes.len;
        e.ledger.input_bytes += bytes.len;
        if (e.param(.taint_paths) != 0) e.taint(bytes);
    }
}

fn onPath(ctx: *anyopaque, node: seam.NodeId, op: seam.VfsOp, path: []const u8) u16 {
    const e = engineOf(ctx);
    const sink: seam.Sink = .{ .kind = .file, .node = node, .peer_node = node, .id = 0 };
    var cwe: u16 = 0;
    if (e.sandboxOf(node)) |p| {
        const write = op != .open;
        if ((write and !p.allow_vfs_write) or !p.allowsPath(path))
            cwe = e.privilegeUsed(node, if (write) .vfs_write else .vfs_open, sink);
    }
    if (e.param(.taint_paths) == 0) return cwe;
    e.sink_checks[@backingInt(SinkKind.path)] += 1;
    const at = e.taintedAt(path) orelse return cwe;
    e.report(.{
        .cwe = 22,
        .kind = .tainted_path,
        .tenant = tenant_system,
        .dest_tenant = tenant_system,
        .sink = sink,
        .offset = @intCast(at),
        .at_ns = e.now(),
    });
    return if (cwe != 0) cwe else 22;
}

fn onCapability(ctx: *anyopaque, node: seam.NodeId, cap: seam.Capability, argv: []const []const u8) u16 {
    const e = engineOf(ctx);
    var cwe: u16 = 0;
    if (e.sandboxOf(node)) |p| {
        const allowed = switch (cap) {
            .net_connect => p.allow_net_connect,
            .net_listen => p.allow_net_listen,
            .process_spawn => p.allow_process_spawn,
        };
        if (!allowed) cwe = e.privilegeUsed(node, switch (cap) {
            .net_connect => .net_connect,
            .net_listen => .net_listen,
            .process_spawn => .process_spawn,
        }, null);
    }
    if (e.param(.taint_paths) == 0) return cwe;
    if (argv.len > 0) e.sink_checks[@backingInt(SinkKind.command)] += 1;
    for (argv, 0..) |arg, i| {
        const at = e.taintedAt(arg) orelse continue;
        e.report(.{
            .cwe = 78,
            .kind = .tainted_command,
            .tenant = tenant_system,
            .dest_tenant = tenant_system,
            .sink = null,
            .offset = @intCast(at),
            .detail = .{ @intCast(@min(i, std.math.maxInt(u16))), node },
            .at_ns = e.now(),
        });
        return if (cwe != 0) cwe else 78;
    }
    return cwe;
}

fn onEgress(ctx: *anyopaque, sink: seam.Sink, bytes: []const u8) u16 {
    const e = engineOf(ctx);
    if (e.race_detector) |*d| if (tardis.Sim.activeOrNull()) |s| d.release(s.current, messageKey(sink));
    if (sink.kind == .file) e.ledger.file_bytes += bytes.len else e.ledger.tx_bytes += bytes.len;
    return e.scan(sink, bytes);
}

const work_label: u64 = 0x5EC0_A3B1_0000_0407;
const alloc_label: u64 = 0x5EC0_A3B1_0000_0400;
const mcdc_label: u64 = 0x5EC0_3CDC_0000_0178;

/// The run ended: whole-run checks, then the counted run's requirement
/// checks and findings go to the campaign.
fn onEndRun(ctx: *anyopaque) u16 {
    const e = engineOf(ctx);
    checking = null;
    const cwe = amplificationCheck(e);
    // Edge counters into the campaign's seen set (instrumented builds
    // under `certify` only; plan2.md §7.1).
    edges.sweep(tardis.Sim.activeOrNull());
    if (e.campaignSink()) |c| {
        const s = tardis.Sim.activeOrNull();
        const counted = if (s) |sim| !sim.rerun else true;
        // The iteration's seed (`Sim.seed`), not the warm-up's, and the
        // run's place in the campaign, which no worker schedule changes.
        const order: u64 = if (s) |sim| campaign.runOrder(sim.iteration, @backingInt(sim.persona)) else 0;
        e.run_seed = if (s) |sim| sim.seed else e.seed;
        e.run_order = order;
        if (counted) c.commit(e.run_seed, order, e.deltas[0..e.deltas_len], e.findingsSlice(), e.sink_checks);
    }
    return cwe;
}

/// Seam 4: the run's first finding as the shrinker's predicate. The key is
/// the campaign's deduplication key (CWE, kind, detail, kind of sink), so a
/// shrunk run may move the leak's offset or time but not change the bug.
fn findingKey(ctx: *anyopaque) u64 {
    const e = engineOf(ctx);
    if (e.findings_len == 0) return 0;
    return campaign.Logged.key(e.findings[0]) | 1;
}

/// `RequirementScope.check` inside a run with a campaign: tallied for
/// the run. False when there is no campaign to receive it.
pub fn requirementCheck(id: []const u8, ok: bool) bool {
    const e = active() orelse return false;
    const c = e.campaignSink() orelse return false;
    const index = c.requirementIndex(id) catch @panic("tardis_sec: requirement id too long, or requirements_max reached");
    for (e.deltas[0..e.deltas_len]) |*d| {
        if (d.index != index) continue;
        if (ok) d.passed += 1 else d.failed += 1;
        return true;
    }
    if (e.deltas_len == deltas_max) {
        e.deltas_dropped += 1;
        return true;
    }
    e.deltas[e.deltas_len] = .{ .index = index, .passed = @intFromBool(ok), .failed = @intFromBool(!ok) };
    e.deltas_len += 1;
    return true;
}

/// The amplification ratios become coverage features (so exploration
/// climbs them) and a ratio over its limit is a finding.
fn amplificationCheck(e: *Engine) u16 {
    if (e.param(.amplification) == 0) return 0;
    const l = e.ledger;
    if (l.input_bytes == 0) return 0;
    if (tardis.Sim.activeOrNull()) |s| {
        s.cover(tardis.decide.mix(work_label, amplify.bucket(l.ratio(.work_per_input_byte))));
        s.cover(tardis.decide.mix(alloc_label, amplify.bucket(l.ratio(.alloc_bytes_per_input_byte))));
    }
    const lim = amplify.unpack(.{ e.param(.amplification_limits_a), e.param(.amplification_limits_b) });
    const r = l.exceeded(lim) orelse return 0;
    e.report(.{
        .cwe = r.cwe(),
        .kind = .amplification,
        .tenant = tenant_system,
        .dest_tenant = tenant_system,
        .sink = null,
        .offset = @intCast(@min(l.ratio(r), std.math.maxInt(u32))),
        .detail = .{ @backingInt(r), 0 },
        .at_ns = e.now(),
    });
    return r.cwe();
}

/// `tardis_sec.work`: work units for the amplification ledger.
pub fn addWork(n: u64) void {
    const e = active() orelse return;
    e.ledger.work_units += n;
}

/// `tardis_sec.untrustedInput`: untrusted input that did not come from the network.
pub fn addInput(n: u64) void {
    const e = active() orelse return;
    e.ledger.input_bytes += n;
}

/// `mcdc.decision`: a new vector is a coverage feature.
pub fn mcdcRecord(id: u8, conditions: u8, vector: u8, outcome: bool) void {
    const e = active() orelse return;
    if (!e.mcdc_table.entries[id].record(conditions, vector, outcome)) return;
    const s = tardis.Sim.activeOrNull() orelse return;
    s.cover(tardis.decide.mix(mcdc_label, (@as(u64, id) << 8) | vector));
}

/// The value a condition compares its input against (`mcdc.compare`):
/// offered to guided exploration, so a draw can be forced to the value
/// that flips the condition. For an ordering, its neighbours too. The
/// input itself is not offered: it differs in every run, and would crowd
/// the values worth forcing out of the corpus.
pub fn mcdcOperand(b: u64, ordered: bool) void {
    if (active() == null) return;
    ctrace.offer(b);
    if (ordered) {
        ctrace.offer(b +% 1);
        ctrace.offer(b -% 1);
    }
}

fn taskOf(s: *tardis.Sim) u16 {
    return @intCast(s.current);
}

/// `Mutex.lock`: lockdep before the lock is taken (an inversion is
/// reported even on schedules that do not deadlock).
pub fn lockAcquire(class: u16) void {
    const e = active() orelse return;
    const s = tardis.Sim.activeOrNull().?;
    const held = e.races.acquire(taskOf(s), class) orelse return;
    e.report(.{
        .cwe = 833,
        .kind = .lock_order,
        .tenant = tenant_system,
        .dest_tenant = tenant_system,
        .sink = null,
        .offset = 0,
        .detail = .{ held, class },
        .at_ns = s.now_ns,
    });
    s.securityFailed(833, "lock_order");
}

fn onFileLock(ctx: *anyopaque, node: seam.NodeId, inode: u32, held: bool) void {
    const e = engineOf(ctx);
    const class = e.races.fileClass(node, inode) orelse return;
    if (held) lockAcquire(class) else lockRelease(class);
}

/// A C sink (the C shims, §5.2): received bytes in `bytes` are a finding
/// of `kind` and fail the run. Returns the CWE, or 0.
pub fn cSink(sink: SinkKind, bytes: []const u8) u16 {
    const e = active() orelse return 0;
    if (e.param(.taint_paths) == 0) return 0;
    e.sink_checks[@backingInt(sink)] += 1;
    const kind = sink.findingKind();
    const at = e.taintedAt(bytes) orelse return 0;
    const s = tardis.Sim.activeOrNull().?;
    const cwe = kind.cwe();
    e.report(.{
        .cwe = cwe,
        .kind = kind,
        .tenant = tenant_system,
        .dest_tenant = tenant_system,
        .sink = null,
        .offset = @intCast(at),
        .detail = .{ 0, s.currentNode() },
        .at_ns = s.now_ns,
    });
    s.securityFailed(cwe, @tagName(kind));
    return cwe;
}

/// A marked bounds check at `site` passed (§6.3): the next loads are
/// watched for the Spectre-v1 shape.
pub fn spectreCheck(site: usize) void {
    const e = active() orelse return;
    e.spectre_detector.check(site);
}

/// An edge of traced code: the window after a bounds check is that long.
pub fn spectreEdge() void {
    const e = active() orelse return;
    e.spectre_detector.edge();
}

/// True while a bounds-check window is open (loads are worth reading).
pub fn spectreWatching() bool {
    const e = active() orelse return false;
    return e.spectre_detector.open != null;
}

/// A traced load of `value` from `addr`.
pub fn spectreLoad(addr: usize, value: u64) void {
    const e = active() orelse return;
    const g = e.spectre_detector.load(addr, value) orelse return;
    const s = tardis.Sim.activeOrNull().?;
    const scale: u64 = @abs(g.scale);
    e.report(.{
        .cwe = 1037,
        .kind = .spectre_v1,
        .tenant = tenant_system,
        .dest_tenant = tenant_system,
        .sink = null,
        .offset = @as(u32, g.first) * 16 + g.second,
        .detail = .{ @intCast(@min(scale, std.math.maxInt(u16))), s.currentNode() },
        .at_ns = s.now_ns,
    });
    s.securityFailed(1037, "spectre_v1");
}

/// Instrumented code is about to read or write `len` bytes at `addr`
/// (`shadow.zig`): checked against the heap's shadow and for a data
/// race, whichever the run has.
pub fn shadowAccess(addr: usize, len: usize, write: bool) void {
    const e = checking orelse return;
    // A copy or a fill of no bytes touches nothing.
    if (len == 0) return;
    heapAccess(e, addr, len, write);
    raceAccess(e, addr, len, write);
}

/// What an atomic operation does to the ordering of tasks (§4.5).
pub const AtomicOp = enum { load, store, read_modify_write };

/// Instrumented code is about to perform an atomic operation on `len`
/// bytes at `addr`. Checked against the heap's shadow; never a data
/// race, and a point that orders the tasks using it.
pub fn atomicAccess(addr: usize, len: usize, op: AtomicOp) void {
    const e = checking orelse return;
    heapAccess(e, addr, len, op != .load);
    const d = &(e.race_detector orelse return);
    const task = tardis.Sim.activeOrNull().?.current;
    if (op != .store) d.acquire(task, addr);
    if (op != .load) d.release(task, addr);
}

/// Instrumented code took (`held`) or dropped a lock-shaped atomic at
/// `addr` (§4.6): a 32-bit word that went from zero to non-zero by a
/// compare-and-swap or an exchange, as `std.Io.Mutex` does, and back to
/// zero. Lock order across such words is checked like any mutex's.
pub fn atomicLock(addr: usize, held: bool) void {
    const e = active() orelse return;
    if (e.param(.data_races) & 2 == 0) return;
    const s = tardis.Sim.activeOrNull().?;
    if (held) {
        lockAcquire(e.races.cLockClass(s.currentNode(), addr) orelse return);
    } else {
        // A zero stored to a word never taken is not an unlock.
        lockRelease(e.races.cLockClassKnown(s.currentNode(), addr) orelse return);
    }
}

fn onTaskSync(ctx: *anyopaque, op: seam.TaskSync, a: usize, b: usize) void {
    const d = &(engineOf(ctx).race_detector orelse return);
    switch (op) {
        .spawn => d.spawn(a, b),
        .wake => d.wake(a, b),
        .release => d.release(a, b),
        .acquire => d.acquire(a, b),
    }
}

/// An access of up to this many bytes is checked for races at its first
/// byte (accesses are matched by start address, `datarace.zig`); a longer
/// one, a copy or a fill, also at every eighth byte after it, up to
/// `race_range_max`.
const race_range_bytes = 16;
const race_range_max = 4096;

fn raceAccess(e: *Engine, addr: usize, len: usize, write: bool) void {
    const d = &(e.race_detector orelse return);
    const s = tardis.Sim.activeOrNull().?;
    const node: u8 = @intCast(s.currentNode());
    var found: ?datarace.Race = d.access(s.current, node, addr, write);
    if (len > race_range_bytes) {
        var at: usize = 8;
        while (at < @min(len, race_range_max)) : (at += 8) {
            if (d.access(s.current, node, addr + at, write)) |r| found = found orelse r;
        }
    }
    const r = found orelse return;
    for (e.findingsSlice()) |f| if (f.kind == .data_race) return;
    e.report(.{
        .cwe = 362,
        .kind = .data_race,
        .tenant = tenant_system,
        .dest_tenant = tenant_system,
        .sink = null,
        .offset = @as(u32, @intCast(s.current)) | (@as(u32, @intFromBool(write)) << 16) | (@as(u32, @intFromBool(r.other_write)) << 17),
        .detail = .{ r.other, node },
        .at_ns = s.now_ns,
    });
    s.securityFailed(362, "data_race");
}

/// The first bad access of a run is its finding, and fails it.
fn heapAccess(e: *Engine, addr: usize, len: usize, write: bool) void {
    const m = &(e.shadow_memory orelse return);
    m.accesses += 1;
    const hit = m.check(addr, len) orelse return;
    const s = tardis.Sim.activeOrNull().?;
    const kind: Kind = switch (hit.state) {
        .valid => unreachable,
        .redzone => if (write) .write_past_end else .read_past_end,
        .freed => .use_after_free,
    };
    for (e.findingsSlice()) |f| if (f.kind == kind) return;
    e.report(.{
        .cwe = kind.cwe(),
        .kind = kind,
        .tenant = tenant_system,
        .dest_tenant = tenant_system,
        .sink = null,
        .offset = if (hit.state == .redzone) @intCast(m.depth(hit.addr, seam.redzone_bytes)) else @intFromBool(write),
        .detail = .{ @intCast(@min(len, std.math.maxInt(u16))), s.currentNode() },
        .at_ns = s.now_ns,
    });
    s.securityFailed(kind.cwe(), @tagName(kind));
}

/// A security-critical comparison's result, possibly inverted: one
/// skipped instruction (§7.4). The inversion is a keyed decision on the
/// fault stream, so it replays and shrinks. Without the engine, or with
/// `instruction_skip_glitch_ppm` 0, the result is returned as it is.
pub fn glitch(cond: bool) bool {
    const e = active() orelse return cond;
    const ppm: tardis.Ppm = @intCast(e.param(.glitch_ppm));
    if (ppm == 0) return cond;
    const s = tardis.Sim.activeOrNull().?;
    return if (s.decider.chance(.fault, ppm)) !cond else cond;
}

/// C code starts a process (`system`, `popen`, the `exec` family): the same
/// check as a simulated spawn, so a sandbox without `allow_process_spawn`
/// is CWE-272 and a received argument is CWE-78 (detail: argument index).
pub fn cSpawn(argv: []const []const u8) u16 {
    const e = active() orelse return 0;
    const s = tardis.Sim.activeOrNull().?;
    const cwe = onCapability(e, s.currentNode(), .process_spawn, argv);
    if (cwe != 0) s.securityFailed(cwe, "a process started from C");
    return cwe;
}

/// A C mutex at `addr` taken (before it may wait) or released.
pub fn cLock(addr: usize, held: bool) void {
    const e = active() orelse return;
    const s = tardis.Sim.activeOrNull().?;
    const class = e.races.cLockClass(s.currentNode(), addr) orelse return;
    if (held) lockAcquire(class) else lockRelease(class);
}

pub fn lockRelease(class: u16) void {
    const e = active() orelse return;
    e.races.release(taskOf(tardis.Sim.activeOrNull().?), class);
}

/// `Shared(T).load`: the second read of a word by one task gets a keyed
/// chance to let another task run first (plan2.md §4.1).
pub fn sharedRead(addr: usize) void {
    const e = active() orelse return;
    const s = tardis.Sim.activeOrNull().?;
    if (!e.races.fetch(addr, taskOf(s))) return;
    const ppm = e.param(.double_fetch_ppm);
    if (ppm != 0) s.preemptionPoint(@intCast(ppm));
}

fn onVfsOp(ctx: *anyopaque, node: seam.NodeId, op: seam.VfsOp, dir: u32, path: []const u8) ?seam.Swap {
    _ = node;
    const e = engineOf(ctx);
    const s = tardis.Sim.activeOrNull() orelse return null;
    const key = races.State.pathKey(dir, path);
    switch (op) {
        .stat, .access => {
            e.races.noteCheck(taskOf(s), key);
            return null;
        },
        .create, .delete, .rename => return null,
        .open => {
            if (!e.races.takeCheck(taskOf(s), key)) return null;
            const allowed: ToctouSwaps = @bitCast(@as(u8, @truncate(e.param(.toctou_swaps))));
            var kinds: [4]seam.Swap = undefined;
            var n: usize = 0;
            if (e.races.targetSlice()) |t| {
                if (allowed.symlink) kinds[n] = .{ .kind = .symlink, .target = t };
                n += @intFromBool(allowed.symlink);
                if (allowed.hard_link) kinds[n] = .{ .kind = .hard_link, .target = t };
                n += @intFromBool(allowed.hard_link);
            }
            if (e.races.dirTargetSlice()) |t| if (allowed.parent_symlink and hasParent(path)) {
                kinds[n] = .{ .kind = .parent_symlink, .target = t };
                n += 1;
            };
            if (allowed.directory) {
                kinds[n] = .{ .kind = .directory, .target = "" };
                n += 1;
            }
            if (n == 0) return null;
            const ppm = e.param(.toctou_ppm);
            if (ppm == 0 or !s.decider.chance(.fault, @intCast(ppm))) return null;
            const pick = if (n == 1) 0 else s.decider.uniform(.fault, n);
            e.races.toctou_swaps += 1;
            return kinds[pick];
        },
    }
}

/// Whether `path` has a directory component before its last one.
fn hasParent(path: []const u8) bool {
    const i = std.mem.indexOfAny(u8, path, "/\\") orelse return false;
    return i > 0 and i + 1 < path.len;
}

fn onDatagram(ctx: *anyopaque, sink: seam.Sink, payload: []const u8, out: []u8) ?usize {
    const e = engineOf(ctx);
    const q = e.races.equivocator orelse return null;
    if (sink.node != q.node or sink.peer_node >= 32) return null;
    if (q.peers & (@as(u32, 1) << @as(u5, @intCast(sink.peer_node))) == 0) return null;
    const s = tardis.Sim.activeOrNull() orelse return null;
    const ppm = e.param(.byzantine_ppm);
    if (ppm == 0 or !s.decider.chance(.fault, @intCast(ppm))) return null;
    const n = q.mutate(payload, out) orelse return null;
    e.races.mutations += 1;
    return n;
}

/// Stream segments from the two-faced node: the same rewrite as datagrams,
/// applied to each segment the writer pushes, kept only when it keeps the
/// length. A mutation that needs a whole frame applies when the frame goes
/// out in one segment (no short write split it).
fn onStream(ctx: *anyopaque, sink: seam.Sink, bytes: []const u8, out: []u8) bool {
    const e = engineOf(ctx);
    const q = e.races.equivocator orelse return false;
    if (sink.node != q.node or sink.peer_node >= 32) return false;
    if (q.peers & (@as(u32, 1) << @as(u5, @intCast(sink.peer_node))) == 0) return false;
    const s = tardis.Sim.activeOrNull() orelse return false;
    const ppm = e.param(.byzantine_ppm);
    if (ppm == 0 or !s.decider.chance(.fault, @intCast(ppm))) return false;
    const n = q.mutate(bytes, out) orelse return false;
    if (n != bytes.len) return false;
    e.races.mutations += 1;
    return true;
}

/// The replayer: with `byzantine_ppm` per datagram from its node to one of
/// its peers, and some frame already recorded for that peer, delivers one
/// of them again first (picked by a keyed decision). The datagram itself is
/// recorded after the decision, so a frame is never replayed ahead of
/// itself.
fn onReplay(ctx: *anyopaque, sink: seam.Sink, payload: []const u8, out: []u8) ?usize {
    const e = engineOf(ctx);
    const r = e.races.replayer orelse return null;
    if (sink.node != r.node or sink.peer_node >= 32) return null;
    if (r.peers & (@as(u32, 1) << @as(u5, @intCast(sink.peer_node))) == 0) return null;
    const s = tardis.Sim.activeOrNull() orelse return null;
    defer e.races.recordFrame(sink.peer_node, payload);
    const n = e.races.framesFor(sink.peer_node);
    if (n == 0) return null;
    const ppm = e.param(.byzantine_ppm);
    if (ppm == 0 or !s.decider.chance(.fault, @intCast(ppm))) return null;
    const pick = if (n == 1) 0 else s.decider.uniform(.fault, n);
    const frame = e.races.frameFor(sink.peer_node, pick);
    if (frame.len > out.len) return null;
    @memcpy(out[0..frame.len], frame);
    e.races.replays += 1;
    return frame.len;
}

// ---------------------------------------------------------------------------
// Fork server (seam 4): a forked child's run tallies, sent to the parent

const ForkHeader = extern struct {
    seed: u64,
    order: u64,
    sinks: [sink_kinds]u32,
    deltas: u16,
    findings: u16,
    mcdc: u16,
};

/// In the child: the run's requirement checks (by id: the parent's row
/// numbers may differ), its findings, and the MC/DC entries reached so far
/// (an OR-merge, so resending what the parent has is harmless).
fn forkExport(ctx: *anyopaque, out: []u8) usize {
    const e = engineOf(ctx);
    const c = e.campaignSink();
    var h: ForkHeader = .{ .seed = e.run_seed, .order = e.run_order, .sinks = e.sink_checks, .deltas = 0, .findings = 0, .mcdc = 0 };
    var n: usize = @sizeOf(ForkHeader);
    if (c) |camp| {
        for (e.deltas[0..e.deltas_len]) |d| {
            const id = camp.requirements.records[d.index].idSlice();
            if (n + 1 + id.len + 8 > out.len) break;
            out[n] = @intCast(id.len);
            @memcpy(out[n + 1 ..][0..id.len], id);
            n += 1 + id.len;
            std.mem.writeInt(u32, out[n..][0..4], d.passed, .little);
            std.mem.writeInt(u32, out[n + 4 ..][0..4], d.failed, .little);
            n += 8;
            h.deltas += 1;
        }
        for (e.findingsSlice()) |*f| {
            if (n + @sizeOf(Finding) > out.len) break;
            @memcpy(out[n..][0..@sizeOf(Finding)], std.mem.asBytes(f));
            n += @sizeOf(Finding);
            h.findings += 1;
        }
    }
    if (e.param(.mcdc_report) != 0) {
        for (&e.mcdc_table.entries, 0..) |*m, id| {
            if (!m.reached()) continue;
            if (n + 1 + @sizeOf(mcdc.Entry) > out.len) break;
            out[n] = @intCast(id);
            @memcpy(out[n + 1 ..][0..@sizeOf(mcdc.Entry)], std.mem.asBytes(m));
            n += 1 + @sizeOf(mcdc.Entry);
            h.mcdc += 1;
        }
    }
    if (n == @sizeOf(ForkHeader)) return 0;
    @memcpy(out[0..@sizeOf(ForkHeader)], std.mem.asBytes(&h));
    return n;
}

/// In the parent: commits the child's run as if it had run here.
fn forkImport(ctx: *anyopaque, bytes: []const u8) void {
    const e = engineOf(ctx);
    if (bytes.len < @sizeOf(ForkHeader)) return;
    const h = std.mem.bytesToValue(ForkHeader, bytes[0..@sizeOf(ForkHeader)]);
    var n: usize = @sizeOf(ForkHeader);
    var deltas: [deltas_max]campaign.Delta = undefined;
    var findings: [findings_max]Finding = undefined;
    var deltas_len: usize = 0;
    const c = e.campaignSink();
    for (0..h.deltas) |_| {
        if (n >= bytes.len) return;
        const len = bytes[n];
        if (n + 1 + len + 8 > bytes.len) return;
        const id = bytes[n + 1 ..][0..len];
        n += 1 + len;
        const passed = std.mem.readInt(u32, bytes[n..][0..4], .little);
        const failed = std.mem.readInt(u32, bytes[n + 4 ..][0..4], .little);
        n += 8;
        const camp = c orelse continue;
        if (deltas_len == deltas_max) continue;
        const index = camp.requirementIndex(id) catch continue;
        deltas[deltas_len] = .{ .index = index, .passed = passed, .failed = failed };
        deltas_len += 1;
    }
    const findings_len = @min(h.findings, findings_max);
    for (0..h.findings) |k| {
        if (n + @sizeOf(Finding) > bytes.len) return;
        if (k < findings_max) findings[k] = std.mem.bytesToValue(Finding, bytes[n..][0..@sizeOf(Finding)]);
        n += @sizeOf(Finding);
    }
    if (c) |camp| camp.commit(h.seed, h.order, deltas[0..deltas_len], findings[0..findings_len], h.sinks);
    for (0..h.mcdc) |_| {
        if (n + 1 + @sizeOf(mcdc.Entry) > bytes.len) return;
        const m = std.mem.bytesToValue(mcdc.Entry, bytes[n + 1 ..][0..@sizeOf(mcdc.Entry)]);
        var one: mcdc.Table = .{};
        one.entries[bytes[n]] = m;
        e.mcdc_table.merge(&one);
        n += 1 + @sizeOf(mcdc.Entry);
    }
}

// ---------------------------------------------------------------------------
// Emitter (seam 4): a failed `check` writes its SARIF

/// Where per-check SARIF goes: `SecurityConfig.check_sarif`, else
/// `TARDIS_SARIF_DIR` (relative to the current directory) in tests.
fn onCampaignEnd(ctx: *anyopaque, end: *const seam.CampaignEnd) void {
    if (!builtin.is_test) return; // needs a real `std.Io`: tests have one
    const e = engineOf(ctx);
    const err = end.err orelse return;
    // `certify` writes its own SARIF, with the whole campaign.
    if (e.campaignSink() != null) return;
    const io = std.testing.io;
    const gpa = std.heap.page_allocator;
    var owned: ?std.Io.Dir = null;
    defer if (owned) |d| d.close(io);
    const dir: std.Io.Dir = if (e.param(.check_sarif) != 0) @as(*const std.Io.Dir, @ptrFromInt(e.param(.check_sarif))).* else blk: {
        const path = std.testing.environ.getAlloc(gpa, "TARDIS_SARIF_DIR") catch return;
        defer gpa.free(path);
        owned = std.Io.Dir.cwd().createDirPathOpen(io, path, .{}) catch return;
        break :blk owned.?;
    };
    const evidence = @import("evidence.zig");
    const location = evidence.locate(gpa, io, end.caller);
    var h = std.hash.Wyhash.init(0x5EC0_5A21);
    if (location) |*l| {
        h.update(l.uri());
        h.update(std.mem.asBytes(&l.line));
    }
    h.update(@errorName(err));
    h.update(end.token);
    var name_buf: [32]u8 = undefined;
    const name = std.fmt.bufPrint(&name_buf, "{x:0>16}.sarif", .{h.final()}) catch return;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    evidence.writeCheckSarif(&out.writer, .{
        .tool_version = @import("root.zig").version,
        .err = err,
        .findings = if (err == error.SecurityViolation) e.findingsSlice() else &.{},
        .token = end.token,
        .location = location,
    }) catch return;
    dir.writeFile(io, .{ .sub_path = name, .data = out.written() }) catch {};
}

pub const provider: seam.Provider = .{
    .create = create,
    .destroy = destroy,
    .begin_run = beginRun,
    .alloc = onAlloc,
    .free = onFree,
    .heap_reset = onHeapReset,
    .ingress = onIngress,
    .egress = onEgress,
    .vfs_op = onVfsOp,
    .path = onPath,
    .file_lock = onFileLock,
    .capability = onCapability,
    .datagram = onDatagram,
    .stream = onStream,
    .replay = onReplay,
    .end_run = onEndRun,
    .finding_key = findingKey,
    .tokens = runTokens,
    .fork_export = forkExport,
    .fork_import = forkImport,
    .campaign_end = onCampaignEnd,
    .task_sync = onTaskSync,
};

/// The engine of the simulator running on this thread, if it has one.
pub fn active() ?*Engine {
    const s = tardis.Sim.activeOrNull() orelse return null;
    const a = s.sec orelse return null;
    if (a.provider != &provider) return null;
    return engineOf(a.ctx);
}

test {
    _ = races;
    _ = amplify;
    _ = mcdc;
    _ = spectre;
    _ = campaign;
    _ = shadow;
    _ = datarace;
}

test "patterns are distinct, non-zero, and seed-dependent" {
    const a = Engine.patternFor(1, 7);
    const b = Engine.patternFor(2, 7);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
    for (a, 0..) |x, i| {
        try std.testing.expect(x != 0);
        for (a[i + 1 ..]) |y| try std.testing.expect(x != y);
    }
}

test "scan: rotations of the uninit pattern, secrets, tenant data" {
    const gpa = std.testing.allocator;
    const e = engineOf(try create(gpa, @splat(0)));
    defer destroy(gpa, e);
    e.reset(42);
    const sink: seam.Sink = .{ .kind = .net_stream, .node = 0, .peer_node = 1, .id = 3 };

    // A heap buffer copied at an odd offset still matches.
    var heap: [32]u8 = undefined;
    Engine.fill(&heap, e.uninit);
    var out: [40]u8 = @splat('x');
    @memcpy(out[3..35], &heap);
    try std.testing.expect(0 != e.scan(sink, &out));
    try std.testing.expectEqual(@as(u16, 908), e.findings[0].cwe);
    try std.testing.expectEqual(@as(u32, 3), e.findings[0].offset);

    // Ordinary text does not.
    try std.testing.expect(0 == e.scan(sink, "GET /index.html HTTP/1.1\r\nHost: a\r\n\r\n"));

    // Tenant 2's data may go to tenant 2's peer, not to tenant 1's.
    const t2 = "tenant-2 balance: 1,000,000 EUR";
    e.mark(t2, .tenant_data, 2, 0);
    e.tenant_of_node[1] = 2;
    try std.testing.expect(0 == e.scan(sink, t2));
    e.tenant_of_node[1] = 1;
    try std.testing.expect(0 != e.scan(sink, "..." ++ t2[4..20]));
    try std.testing.expectEqual(@as(u16, 668), e.findings[1].cwe);

    // Low-entropy windows are not fingerprinted.
    const zeros: [32]u8 = @splat(0);
    e.mark(&zeros, .secret, 0, 0);
    try std.testing.expect(0 == e.scan(sink, &zeros));
}

test "free: an unzeroed secret is CWE-226, a zeroed one is not, and bytes are poisoned" {
    const gpa = std.testing.allocator;
    const e = engineOf(try create(gpa, @splat(0)));
    defer destroy(gpa, e);
    e.reset(9);
    // As core's heap lays it out: the block, then its guard.
    var block: [32 + seam.redzone_bytes]u8 = undefined;
    @memcpy(block[32..], &seam.redzone_pattern);
    const key = block[0..32];
    for (key, 0..) |*b, i| b.* = @intCast(i * 7 + 1);
    e.mark(key, .secret, 0, 0);
    std.crypto.secureZero(u8, key);
    try std.testing.expectEqual(@as(u16, 0), e.onFree(0, key));
    try std.testing.expectEqual(e.freed[@intFromPtr(&key[5]) % 8], key[5]);

    for (key, 0..) |*b, i| b.* = @intCast(i * 5 + 3);
    e.mark(key, .secret, 0, 0);
    try std.testing.expectEqual(@as(u16, 226), e.onFree(0, key));
    try std.testing.expectEqual(@as(u16, 226), e.findings[0].cwe);
    try std.testing.expectEqual(@as(u16, 0), e.regions_len);
}

test "free: a changed guard is CWE-787 at the first changed byte" {
    const gpa = std.testing.allocator;
    const e = engineOf(try create(gpa, @splat(0)));
    defer destroy(gpa, e);
    e.reset(9);
    var block: [16 + seam.redzone_bytes]u8 = undefined;
    @memcpy(block[16..], &seam.redzone_pattern);
    try std.testing.expectEqual(@as(u16, 0), e.onFree(0, block[0..16]));
    block[16 + 3] ^= 0xFF;
    try std.testing.expectEqual(@as(u16, 787), e.onFree(0, block[0..16]));
    try std.testing.expectEqual(Kind.overflow, e.findings[0].kind);
    try std.testing.expectEqual(@as(u32, 19), e.findings[0].offset);
    try std.testing.expectEqual(@as(u16, 3), e.findings[0].detail[0]);
}
