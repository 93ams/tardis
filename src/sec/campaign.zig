//! A certification campaign's evidence as it accumulates (plan2.md §7.5):
//! the requirement table bound to this campaign, and its distinct findings
//! with the seed of the first run that produced each.
//!
//! The engine tallies requirement checks per run and commits them, with
//! the run's findings, when the run ends, but only for runs the campaign
//! counts: shrinking and the determinism re-run repeat a run already
//! counted (`Sim.rerun`) and are skipped. Commits take a spinlock, since
//! workers on several threads share one campaign.
//!
//! Nothing kept depends on the order commits arrive in: counts are sums,
//! a requirement's first failure and a finding's first run are the
//! lowest (iteration, persona) seen, and `canonicalize` sorts what was
//! appended in arrival order. So the evidence of a campaign is the same on
//! one worker or many.

const std = @import("std");
const registry = @import("registry.zig");
const engine = @import("engine.zig");

pub const findings_max = 64;

/// One distinct finding: what, where to, and the first run that showed it.
pub const Logged = struct {
    finding: engine.Finding,
    /// Run seed of the first run with this finding.
    seed: u64,
    /// That run's `runOrder` (the lowest of the runs that showed it).
    order: u64,
    /// Times it was reported in counted runs.
    occurrences: u32,

    /// Findings that differ only in payload offset, time or node are one.
    pub fn key(f: engine.Finding) u64 {
        var h = std.hash.Wyhash.init(0x5EC0_F1D);
        h.update(std.mem.asBytes(&f.cwe));
        h.update(std.mem.asBytes(&@backingInt(f.kind)));
        h.update(std.mem.asBytes(&f.detail));
        const sink: u8 = if (f.sink) |s| @as(u8, @backingInt(s.kind)) + 1 else 0;
        h.update(std.mem.asBytes(&sink));
        return h.final();
    }
};

/// A run's place in its campaign: iteration, then persona.
pub fn runOrder(iteration: u32, persona: u8) u64 {
    return @as(u64, iteration) << 8 | persona;
}

/// Requirement checks of one run, committed at its end.
pub const Delta = struct { index: u16, passed: u32, failed: u32 };

pub const Campaign = struct {
    /// The test (campaign) bound to the requirements it checks.
    name: []const u8 = "",
    requirements: registry.Table = .{},
    findings: [findings_max]Logged = undefined,
    findings_len: u16 = 0,
    /// Distinct findings beyond `findings_max`.
    findings_dropped: u32 = 0,
    /// Runs committed (counted runs that reached their end).
    runs: u64 = 0,
    /// Taint checks made by counted runs, by `engine.SinkKind`.
    sink_checks: [engine.sink_kinds]u64 = @splat(0),
    busy: std.atomic.Value(bool) = .init(false),
    /// `runOrder` of each requirement's first failure (valid while its
    /// `checks_failed` is non-zero).
    failure_order: [registry.requirements_max]u64 = undefined,

    /// Initializes in place (the requirement table is 512 KiB: allocate
    /// the campaign, do not build it on the stack).
    pub fn init(c: *Campaign, name: []const u8) void {
        c.name = name;
        c.requirements.len = 0;
        c.findings_len = 0;
        c.findings_dropped = 0;
        c.runs = 0;
        c.sink_checks = @splat(0);
        c.busy = .init(false);
    }

    fn lock(c: *Campaign) void {
        while (c.busy.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }

    fn unlock(c: *Campaign) void {
        c.busy.store(false, .release);
    }

    /// The row for requirement `id` (created on first use).
    pub fn requirementIndex(c: *Campaign, id: []const u8) registry.Error!u16 {
        c.lock();
        defer c.unlock();
        return c.requirements.index(id);
    }

    /// Commits one counted run.
    pub fn commit(c: *Campaign, seed: u64, order: u64, deltas: []const Delta, findings: []const engine.Finding, sinks: [engine.sink_kinds]u32) void {
        c.lock();
        defer c.unlock();
        c.runs += 1;
        for (&c.sink_checks, sinks) |*total, n| total.* += n;
        for (deltas) |d| {
            const rec = &c.requirements.records[d.index];
            if (d.failed > 0 and (rec.checks_failed == 0 or order < c.failure_order[d.index])) {
                rec.first_failure_seed = seed;
                c.failure_order[d.index] = order;
            }
            rec.checks_passed += d.passed;
            rec.checks_failed += d.failed;
            rec.bindTest(c.name);
        }
        next: for (findings) |f| {
            const k = Logged.key(f);
            for (c.findings[0..c.findings_len]) |*l| {
                if (Logged.key(l.finding) == k) {
                    l.occurrences += 1;
                    if (order < l.order) {
                        l.finding = f;
                        l.seed = seed;
                        l.order = order;
                    }
                    continue :next;
                }
            }
            if (c.findings_len == findings_max) {
                c.findings_dropped += 1;
                continue;
            }
            c.findings[c.findings_len] = .{ .finding = f, .seed = seed, .order = order, .occurrences = 1 };
            c.findings_len += 1;
        }
    }

    /// After the campaign: findings in order of their first run, and the
    /// requirement rows created during the campaign (after the first
    /// `declared`, which keep the requirement file's order) by id.
    pub fn canonicalize(c: *Campaign, declared: usize) void {
        std.mem.sort(Logged, c.findings[0..c.findings_len], {}, struct {
            fn lt(_: void, a: Logged, b: Logged) bool {
                return a.order < b.order or (a.order == b.order and Logged.key(a.finding) < Logged.key(b.finding));
            }
        }.lt);
        const rows = c.requirements.records[declared..c.requirements.len];
        std.mem.sort(registry.Record, rows, {}, struct {
            fn lt(_: void, a: registry.Record, b: registry.Record) bool {
                return std.mem.lessThan(u8, a.idSlice(), b.idSlice());
            }
        }.lt);
    }

    pub fn findingsSlice(c: *const Campaign) []const Logged {
        return c.findings[0..c.findings_len];
    }
};
