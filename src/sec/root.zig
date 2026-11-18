//! tardis_sec: Layer 7 of TARDIS. Security auditing, Byzantine fuzzing,
//! side-channel oracles and assurance evidence, as a separate package that
//! plugs into core `tardis` through four seams (plan2.md §2).
//!
//! Two layers live here. `engine.zig` is the live engine behind core's
//! run-time seam (`tardis.sec_seam`): it sees every allocation, free and
//! byte crossing an `std.Io` boundary, and tracks secrets, tenants and
//! uninitialized or freed heap bytes by content (`withSecurity` attaches
//! it). The `ShadowCell`/`WorkerSec`/`SecurityHooks` types below are the
//! per-word shadow model for paths that see individual loads and stores
//! (instrumented C, `load`/`store` wrappers); they are verified as types and
//! state machines, and wait for those paths.
//!
//! TigerStyle: no allocation after `WorkerSec.init`, an explicit bound on
//! every table, no recursion, units in names, comptime layout proofs.

const std = @import("std");
const tardis = @import("tardis");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

pub const engine = @import("engine.zig");
pub const Engine = engine.Engine;
pub const ContentFinding = engine.Finding;
pub const traceability = @import("registry.zig");
pub const Campaign = engine.campaign.Campaign;
pub const evidence = @import("evidence.zig");
/// Dead edges from `-ffuzz` counters (§7.1).
pub const edges = engine.edges;

// ===========================================================================
// §3 ByteState and the 16-byte ShadowCell

/// What one application byte is, 4 bits per byte. 0xC..0xF are reserved.
pub const ByteState = enum(u4) {
    valid_clean = 0x0,
    uninit_heap = 0x1,
    uninit_stack = 0x2,
    redzone_left = 0x3,
    redzone_right = 0x4,
    freed_quarantine = 0x5,
    stack_guard = 0x6,
    secret_key = 0x7,
    tenant_isolated = 0x8,
    untrusted_input = 0x9,
    double_fetch_armed = 0xA,
    secret_zeroed = 0xB,
    _,

    pub fn bit(s: ByteState) u16 {
        return @as(u16, 1) << @backingInt(s);
    }

    /// States that make a load or store invalid (CWE id per state).
    pub const access_fault: u16 = bit(.redzone_left) | bit(.redzone_right) |
        bit(.freed_quarantine) | bit(.stack_guard);
    /// States that must never leave the process (egress scan).
    pub const egress_fault: u16 = bit(.uninit_heap) | bit(.uninit_stack) |
        bit(.freed_quarantine) | bit(.secret_key) | bit(.redzone_left) |
        bit(.redzone_right) | bit(.stack_guard);

    pub fn cwe(s: ByteState) u16 {
        return switch (s) {
            .uninit_heap, .uninit_stack => 908,
            .redzone_left => 124,
            .redzone_right => 125,
            .freed_quarantine => 416,
            .stack_guard => 121,
            .secret_key => 200,
            .tenant_isolated => 125,
            .untrusted_input => 20,
            .double_fetch_armed => 367,
            else => 0,
        };
    }
};

/// Tenant ids: 0 is the system, 255 marks bytes mixed from two tenants.
pub const TenantId = u8;
pub const tenant_system: TenantId = 0;
pub const tenant_poison: TenantId = 255;

/// Low word: one comparison against the fiber's epoch proves "same fiber,
/// every byte clean" (`per_byte_nibble == 0`).
pub const FastWord = packed struct(u64) {
    /// `(fiber_id << 16) | local_epoch`.
    last_scalar: u32,
    /// Byte i of the 8-byte word is nibble i (bits 4i..4i+3).
    per_byte_nibble: u32,
};

/// High word: concurrency and provenance; orthogonal to the nibbles.
pub const MetaWord = packed struct(u64) {
    vclock_epoch: u47,
    has_concurrent_writer: u1,
    alloc_gen: u8,
    taint_tenant_id: TenantId,
};

/// Shadow of one aligned 8-byte application word.
pub const ShadowCell = extern struct {
    fast_word: u64 = 0,
    meta_word: u64 = 0,

    pub inline fn fast(c: ShadowCell) FastWord {
        return @bitCast(c.fast_word);
    }

    pub inline fn meta(c: ShadowCell) MetaWord {
        return @bitCast(c.meta_word);
    }

    pub inline fn setMeta(c: *ShadowCell, m: MetaWord) void {
        c.meta_word = @bitCast(m);
    }

    pub inline fn nibble(c: ShadowCell, byte_index: u3) ByteState {
        return @fromBackingInt(@intCast(@as(u4, @truncate(c.fast().per_byte_nibble >> (@as(u5, byte_index) * 4)))));
    }

    pub inline fn setNibble(c: *ShadowCell, byte_index: u3, s: ByteState) void {
        var f = c.fast();
        const shift: u5 = @as(u5, byte_index) * 4;
        f.per_byte_nibble = (f.per_byte_nibble & ~(@as(u32, 0xF) << shift)) | (@as(u32, @backingInt(s)) << shift);
        c.fast_word = @bitCast(f);
    }

    /// The hot path: same fiber epoch and every byte clean, in one compare.
    pub inline fn isFastClean(c: ShadowCell, epoch_scalar: u32) bool {
        return c.fast_word == @as(u64, epoch_scalar);
    }
};

comptime {
    assert(@sizeOf(ShadowCell) == 16);
    assert(@offsetOf(ShadowCell, "fast_word") == 0);
    assert(@offsetOf(ShadowCell, "meta_word") == 8);
    assert(@bitSizeOf(FastWord) == 64 and @bitSizeOf(MetaWord) == 64);
    assert(@bitOffsetOf(MetaWord, "taint_tenant_id") == 120 - 64);
    assert(@bitOffsetOf(MetaWord, "alloc_gen") == 112 - 64);
    assert(@typeInfo(ByteState).@"enum".tag_type == u4);
}

// --- Address mapping (Chrono-Slab: 64 workers x 1 GiB, strided) ----------

pub const workers_max = 64;
pub const worker_arena_bytes: u64 = 1 << 30;
pub const arena_window_base: u64 = 0x4000_0000_0000; // 2^46, aligned to 2^38
pub const shadow_base: u64 = 0x7100_0000_0000;
pub const arena_mask: u64 = 0x3F_FFFF_FFF8;

pub inline fn workerBase(w: u6) u64 {
    return arena_window_base + (@as(u64, w) << 30);
}

pub inline fn workerShadowBase(w: u6) u64 {
    return shadow_base + (@as(u64, w) << 31);
}

/// One instruction after the mask: application address to its ShadowCell.
pub inline fn shadowAddress(virt: u64) u64 {
    return ((virt & arena_mask) << 1) + shadow_base;
}

comptime {
    assert(arena_window_base % (1 << 38) == 0);
    for (0..workers_max) |w| {
        assert(shadowAddress(workerBase(w)) == workerShadowBase(w));
        assert(shadowAddress(workerBase(w) + worker_arena_bytes - 8) ==
            workerShadowBase(w) + 2 * worker_arena_bytes - 16);
    }
}

/// The nibbles of an access of `len_bytes` (1..8) at byte `offset` of a
/// word, possibly straddling into the next word's cell. Branch-free.
pub inline fn spanNibbles(c0: ShadowCell, c1: ShadowCell, offset: u3, len_bytes: u4) u64 {
    assert(len_bytes >= 1 and len_bytes <= 8);
    const both = (@as(u64, c1.fast().per_byte_nibble) << 32) | c0.fast().per_byte_nibble;
    const shifted = both >> (@as(u6, offset) * 4);
    const mask = (@as(u64, 1) << (@as(u6, len_bytes) * 4)) - 1;
    return shifted & mask;
}

/// Bit set of the ByteStates present in up to 16 nibbles.
pub inline fn statesIn(nibbles: u64) u16 {
    var set: u16 = 0;
    inline for (0..16) |k| set |= @as(u16, 1) << @as(u4, @truncate(nibbles >> (k * 4)));
    return set;
}

pub const EgressVerdict = struct {
    /// ByteStates seen in the 64 bytes (bit per state).
    states: u16,
    /// The first offending state, or null.
    fault: ?ByteState,
    /// True if a byte belongs to a tenant other than the destination's.
    cross_tenant: bool,
};

/// Scans 64 payload bytes (8 cells) at once: uninit/UAF bleed (CWE-908),
/// secret exfiltration (CWE-200), cross-tenant bleed (CWE-125).
pub fn egressScan(nibbles: @Vector(8, u32), tenants: @Vector(8, u8), dest_tenant: TenantId) EgressVerdict {
    var seen: @Vector(8, u16) = @splat(0);
    inline for (0..8) |k| {
        const n: @Vector(8, u32) = (nibbles >> @splat(@as(u5, k * 4))) & @as(@Vector(8, u32), @splat(0xF));
        seen |= @as(@Vector(8, u16), @splat(1)) << @as(@Vector(8, u4), @truncate(n));
    }
    const states = @reduce(.Or, seen);
    const bad = states & ByteState.egress_fault;
    const foreign = (tenants != @as(@Vector(8, u8), @splat(dest_tenant))) &
        (tenants != @as(@Vector(8, u8), @splat(tenant_system)));
    return .{
        .states = states,
        .fault = if (bad == 0) null else @fromBackingInt(@intCast(@as(u4, @intCast(@ctz(bad))))),
        .cross_tenant = @reduce(.Or, foreign),
    };
}

/// Free-time poison: deterministic per run, so reports replay.
pub inline fn poisonWord(causal_seed: u64) u64 {
    return 0xDEADBEEF_CAFEBABE ^ causal_seed;
}

// ===========================================================================
// §2 Region C budget (per worker, exact, comptime-checked)

pub const nodes_max = 32;
pub const region_c_bytes_max: u64 = 512 * 1024 * 1024;
pub const core_region_c_bytes: u64 = 352 * 1024 * 1024;
pub const SEC_REGION_C_BYTES: u64 = 64 * 1024 * 1024;
pub const region_c_spare_bytes: u64 = 96 * 1024 * 1024;

pub const Budget = struct {
    pub const quarantine_ring: u64 = nodes_max * 4096 * 16;
    pub const lockdep_graph: u64 = nodes_max * (512 * 64 + 512 * 32);
    pub const local_cmp_token_ring: u64 = 65_536 * 32;
    pub const local_mcdc_table: u64 = 16_384 * 64;
    pub const byzantine_replay_pool: u64 = 2048 * 16 * 1024;
    pub const cost_amplification_ledger: u64 = nodes_max * 2048 * 64;
    pub const taint_sink_audit_log: u64 = 65_536 * 64;
    pub const dpor_state_table: u64 = 65_536 * 64;
    pub const sec_reserved_headroom: u64 = 13 * 1024 * 1024 + 512 * 1024;

    pub const total: u64 = quarantine_ring + lockdep_graph + local_cmp_token_ring +
        local_mcdc_table + byzantine_replay_pool + cost_amplification_ledger +
        taint_sink_audit_log + dpor_state_table + sec_reserved_headroom;
};

comptime {
    const MiB = 1024 * 1024;
    assert(Budget.quarantine_ring == 2 * MiB);
    assert(Budget.lockdep_graph == 3 * MiB / 2);
    assert(Budget.local_cmp_token_ring == 2 * MiB);
    assert(Budget.local_mcdc_table == 1 * MiB);
    assert(Budget.byzantine_replay_pool == 32 * MiB);
    assert(Budget.cost_amplification_ledger == 4 * MiB);
    assert(Budget.taint_sink_audit_log == 4 * MiB);
    assert(Budget.dpor_state_table == 4 * MiB);
    assert(Budget.total == SEC_REGION_C_BYTES);
    assert(core_region_c_bytes + SEC_REGION_C_BYTES + region_c_spare_bytes == region_c_bytes_max);
}

pub const requirements_max = traceability.requirements_max;

/// One row of the Requirement Traceability Registry (128 bytes, §2.4).
pub const RequirementRecord = traceability.Record;

comptime {
    assert(@sizeOf(RequirementRecord) == 128);
    assert(requirements_max * @sizeOf(RequirementRecord) == 512 * 1024);
}

// ===========================================================================
// §2 Seam 3: the SecurityHooks contract

/// Every hook core `tardis` calls. Core uses `NoopSecurityHooks` unless
/// `tardis_sec` is imported, and every call then compiles to nothing.
pub const hook_names = [_][]const u8{
    "onAlloc", "onFree",        "onNetRead",   "onNetWrite",
    "onVfsOp", "onLockAcquire", "onBranchCmp", "onCausalStep",
    "onWrite", "onLockRelease",
};

pub const VfsOp = enum(u8) { stat, access, open, create, rename, delete, link, symlink, write, read };
pub const CmpSite = struct { pc: u64, lhs: u64, rhs: u64, width_bytes: u8, critical: bool };

pub const NoopSecurityHooks = struct {
    pub const enabled = false;
    pub inline fn onAlloc(_: *anyopaque, _: u64, _: u32) void {}
    pub inline fn onFree(_: *anyopaque, _: u64, _: u32) void {}
    pub inline fn onWrite(_: *anyopaque, _: u64, _: []const u8) void {}
    pub inline fn onNetRead(_: *anyopaque, _: u64, _: []const u8) void {}
    pub inline fn onNetWrite(_: *anyopaque, _: u64, _: []const u8, _: TenantId) bool {
        return true;
    }
    pub inline fn onVfsOp(_: *anyopaque, _: VfsOp, _: []const u8) void {}
    pub inline fn onLockAcquire(_: *anyopaque, _: u16) void {}
    pub inline fn onLockRelease(_: *anyopaque, _: u16) void {}
    pub inline fn onBranchCmp(_: *anyopaque, _: CmpSite) bool {
        return true;
    }
    pub inline fn onCausalStep(_: *anyopaque, _: u64) void {}
};

/// Comptime proof that `H` implements the whole contract.
pub fn assertHooks(comptime H: type) void {
    comptime {
        if (!@hasDecl(H, "enabled")) @compileError(@typeName(H) ++ " lacks `enabled`");
        for (hook_names) |name| {
            if (!@hasDecl(H, name)) @compileError(@typeName(H) ++ " lacks hook " ++ name);
        }
    }
}

comptime {
    assertHooks(NoopSecurityHooks);
    assertHooks(SecurityHooks);
}

// ===========================================================================
// Per-worker state (lives in the Region C carve-out)

pub const Finding = struct {
    cwe: u16,
    state: ByteState,
    addr: u64,
    tenant: TenantId,
    requirement: u16, // index into the registry, 0xFFFF: none
};

pub const findings_max = 256;
pub const lock_classes_max = 512;

/// Lock-order bitmatrix: `order[a]` bit b means "a held while taking b"
/// (transitively closed on insert). O(1) inversion test per held lock.
pub const LockdepGraph = struct {
    order: [lock_classes_max][lock_classes_max / 64]u64 = @splat(@splat(0)),
    held: [16]u16 = undefined,
    held_len: u8 = 0,

    pub fn acquire(g: *LockdepGraph, class: u16) ?u16 {
        assert(class < lock_classes_max);
        var inversion: ?u16 = null;
        for (g.held[0..g.held_len]) |a| {
            if (a == class) continue;
            // Taking `class` while holding `a`: inverted if class -> a was seen.
            if (bitSet(g.order[class], a)) inversion = a;
            g.addEdge(a, class);
        }
        assert(g.held_len < g.held.len);
        g.held[g.held_len] = class;
        g.held_len += 1;
        return inversion;
    }

    pub fn release(g: *LockdepGraph, class: u16) void {
        for (g.held[0..g.held_len], 0..) |h, i| {
            if (h != class) continue;
            g.held[i] = g.held[g.held_len - 1];
            g.held_len -= 1;
            return;
        }
    }

    /// Hold-across-yield: any lock held at an `std.Io` yield point.
    pub fn heldAtYield(g: *const LockdepGraph) bool {
        return g.held_len != 0;
    }

    fn addEdge(g: *LockdepGraph, a: u16, b: u16) void {
        if (bitSet(g.order[a], b)) return;
        // a -> b and everything b precedes; and so for every x preceding a.
        var row_b = g.order[b];
        setBit(&row_b, b);
        for (&g.order, 0..) |*row, x| {
            if (x == a or bitSet(row.*, a)) {
                for (row, row_b) |*w, rb| w.* |= rb;
            }
        }
    }

    fn bitSet(row: [lock_classes_max / 64]u64, i: u16) bool {
        return row[i / 64] & (@as(u64, 1) << @as(u6, @truncate(i))) != 0;
    }

    fn setBit(row: *[lock_classes_max / 64]u64, i: u16) void {
        row[i / 64] |= @as(u64, 1) << @as(u6, @truncate(i));
    }
};

/// Shadow and tables for one worker. In the full system `shadow` is the
/// worker's mapped shadow window; here it covers `[base, base + len)`.
pub const WorkerSec = struct {
    base: u64,
    shadow: []ShadowCell,
    epoch_scalar: u32 = 0,
    tenant: TenantId = tenant_system,
    lockdep: LockdepGraph = .{},
    findings: [findings_max]Finding = undefined,
    findings_len: u16 = 0,
    rx_bytes: u64 = 0,
    tx_bytes: u64 = 0,

    pub fn init(base: u64, shadow: []ShadowCell) WorkerSec {
        @memset(shadow, .{});
        return .{ .base = base, .shadow = shadow };
    }

    fn cell(ws: *WorkerSec, addr: u64) *ShadowCell {
        assert(addr >= ws.base);
        const i = (addr - ws.base) / 8;
        assert(i < ws.shadow.len);
        return &ws.shadow[i];
    }

    pub fn setRange(ws: *WorkerSec, addr: u64, len: u64, s: ByteState) void {
        var a = addr;
        while (a < addr + len) : (a += 1) ws.cell(a & ~@as(u64, 7)).setNibble(@truncate(a), s);
    }

    pub fn stateAt(ws: *WorkerSec, addr: u64) ByteState {
        return ws.cell(addr & ~@as(u64, 7)).nibble(@truncate(addr));
    }

    pub fn setTenant(ws: *WorkerSec, addr: u64, len: u64, tenant: TenantId) void {
        var a = addr & ~@as(u64, 7);
        while (a < addr + len) : (a += 8) {
            const c = ws.cell(a);
            var m = c.meta();
            m.taint_tenant_id = tenant;
            c.setMeta(m);
        }
    }

    pub fn report(ws: *WorkerSec, state: ByteState, addr: u64) void {
        if (ws.findings_len == findings_max) return;
        ws.findings[ws.findings_len] = .{
            .cwe = state.cwe(),
            .state = state,
            .addr = addr,
            .tenant = ws.cell(addr & ~@as(u64, 7)).meta().taint_tenant_id,
            .requirement = 0xFFFF,
        };
        ws.findings_len += 1;
    }

    pub fn findingsSlice(ws: *const WorkerSec) []const Finding {
        return ws.findings[0..ws.findings_len];
    }
};

/// The `tardis_sec` implementation of the hook contract. `ctx` is the
/// worker's `WorkerSec`.
pub const SecurityHooks = struct {
    pub const enabled = true;

    inline fn ws(ctx: *anyopaque) *WorkerSec {
        return @ptrCast(@alignCast(ctx));
    }

    pub fn onAlloc(ctx: *anyopaque, addr: u64, len: u32) void {
        const w = ws(ctx);
        w.setRange(addr, len, .uninit_heap);
        w.setTenant(addr, len, w.tenant);
        var a = addr & ~@as(u64, 7);
        while (a < addr + len) : (a += 8) {
            const c = w.cell(a);
            var m = c.meta();
            m.alloc_gen +%= 1;
            c.setMeta(m);
        }
    }

    pub fn onFree(ctx: *anyopaque, addr: u64, len: u32) void {
        const w = ws(ctx);
        var a = addr;
        while (a < addr + len) : (a += 1) {
            if (w.stateAt(a) == .secret_key) {
                w.report(.secret_key, a); // CWE-226 at free: not zeroized
                break;
            }
        }
        w.setRange(addr, len, .freed_quarantine);
    }

    /// Stores: zero bytes scrub secrets (`secureZero`), other bytes become
    /// valid; secrets and taint are kept by `copy`, not by stores.
    pub fn onWrite(ctx: *anyopaque, addr: u64, bytes: []const u8) void {
        const w = ws(ctx);
        for (bytes, 0..) |b, i| {
            const a = addr + i;
            const s = w.stateAt(a);
            if (ByteState.access_fault & s.bit() != 0) {
                w.report(s, a);
                continue;
            }
            const next: ByteState = switch (s) {
                .secret_key => if (b == 0) .secret_zeroed else .secret_key,
                .untrusted_input => .untrusted_input,
                else => .valid_clean,
            };
            w.setRange(a, 1, next);
        }
    }

    /// Ingress: received bytes are untrusted until `markSanitized`.
    pub fn onNetRead(ctx: *anyopaque, addr: u64, bytes: []const u8) void {
        const w = ws(ctx);
        w.rx_bytes += bytes.len;
        w.setRange(addr, bytes.len, .untrusted_input);
    }

    /// Egress: false (and a finding) if the payload must not leave.
    pub fn onNetWrite(ctx: *anyopaque, addr: u64, bytes: []const u8, dest_tenant: TenantId) bool {
        const w = ws(ctx);
        w.tx_bytes += bytes.len;
        var off: u64 = 0;
        while (off < bytes.len) : (off += 64) {
            var nib: @Vector(8, u32) = @splat(0);
            var ten: @Vector(8, u8) = @splat(dest_tenant);
            inline for (0..8) |k| {
                const a = addr + off + k * 8;
                if (a < addr + bytes.len) {
                    const c = w.cell(a & ~@as(u64, 7)).*;
                    nib[k] = c.fast().per_byte_nibble;
                    ten[k] = c.meta().taint_tenant_id;
                }
            }
            const v = egressScan(nib, ten, dest_tenant);
            if (v.fault) |f| {
                w.report(f, addr + off);
                return false;
            }
            if (v.cross_tenant) {
                w.report(.tenant_isolated, addr + off);
                return false;
            }
        }
        return true;
    }

    pub fn onVfsOp(_: *anyopaque, _: VfsOp, _: []const u8) void {}

    pub fn onLockAcquire(ctx: *anyopaque, class: u16) void {
        const w = ws(ctx);
        if (w.lockdep.acquire(class)) |_| {
            if (w.findings_len < findings_max) {
                w.findings[w.findings_len] = .{ .cwe = 833, .state = .valid_clean, .addr = class, .tenant = w.tenant, .requirement = 0xFFFF };
                w.findings_len += 1;
            }
        }
    }

    pub fn onLockRelease(ctx: *anyopaque, class: u16) void {
        ws(ctx).lockdep.release(class);
    }

    /// Returns the branch outcome to take: `cmp` result, or inverted by a
    /// glitch (decided by core's fault stream, so it replays and shrinks).
    pub fn onBranchCmp(_: *anyopaque, site: CmpSite) bool {
        return site.lhs == site.rhs;
    }

    pub fn onCausalStep(ctx: *anyopaque, _: u64) void {
        ws(ctx).epoch_scalar +%= 1;
    }
};

// ===========================================================================
// §5 Byzantine wire mutation with comptime checksum fixup

pub const ChecksumKind = enum { crc32, xxhash64 };

pub const FrameOptions = struct {
    length_field: []const u8,
    checksum_field: []const u8,
    epoch_field: ?[]const u8 = null,
    checksum: ChecksumKind = .crc32,
};

/// Reflects over `HeaderT` once, at comptime: which fields carry the
/// payload length, checksum and epoch, and how to recompute the checksum.
pub fn ByzantineFrameSpec(comptime HeaderT: type, comptime opts: FrameOptions) type {
    comptime {
        if (!@hasField(HeaderT, opts.length_field)) @compileError("no length field " ++ opts.length_field);
        if (!@hasField(HeaderT, opts.checksum_field)) @compileError("no checksum field " ++ opts.checksum_field);
        if (opts.epoch_field) |e| if (!@hasField(HeaderT, e)) @compileError("no epoch field " ++ e);
    }
    const LenT = @FieldType(HeaderT, opts.length_field);
    const SumT = @FieldType(HeaderT, opts.checksum_field);
    comptime {
        if (@bitSizeOf(SumT) < (if (opts.checksum == .crc32) 32 else 64)) @compileError("checksum field too narrow");
    }
    return struct {
        pub const Header = HeaderT;

        pub fn checksumOf(payload: []const u8) SumT {
            return switch (opts.checksum) {
                .crc32 => @intCast(std.hash.Crc32.hash(payload)),
                .xxhash64 => @intCast(std.hash.XxHash64.hash(0, payload)),
            };
        }

        /// Makes `header` valid for `payload` again after a mutation.
        pub fn fixup(header: *HeaderT, payload: []const u8) void {
            @field(header, opts.checksum_field) = checksumOf(payload);
        }

        pub fn isValid(header: HeaderT, payload: []const u8) bool {
            return @field(header, opts.checksum_field) == checksumOf(payload) and
                @field(header, opts.length_field) == payload.len;
        }

        /// Attack 1: the length prefix disagrees with the payload (wraps).
        pub fn desyncLength(header: *HeaderT, delta: i64) void {
            const old: i64 = @intCast(@field(header, opts.length_field));
            @field(header, opts.length_field) = @truncate(@as(u64, @bitCast(old +% delta)));
        }

        /// Attack 2: two-faced equivocation. Writes a second payload that
        /// differs at `index` and fixes both headers, so each half of the
        /// cluster receives a frame that verifies.
        pub fn equivocate(header: HeaderT, payload: []const u8, index: usize, flip: u8, out_header: *HeaderT, out_payload: []u8) void {
            assert(out_payload.len == payload.len and index < payload.len and flip != 0);
            @memcpy(out_payload, payload);
            out_payload[index] ^= flip;
            out_header.* = header;
            @field(out_header, opts.length_field) = @intCast(out_payload.len);
            fixup(out_header, out_payload);
        }

        /// Wire form: the header's bytes, then the payload (`HeaderT`
        /// must be an `extern struct`). Returns the frame length.
        pub fn encode(header: HeaderT, payload: []const u8, out: []u8) usize {
            comptime assert(@typeInfo(HeaderT).@"struct".layout == .@"extern");
            const hb = std.mem.asBytes(&header);
            @memcpy(out[0..hb.len], hb);
            @memcpy(out[hb.len..][0..payload.len], payload);
            return hb.len + payload.len;
        }

        pub const Decoded = struct { header: HeaderT, payload: []const u8 };

        /// Parses a wire frame; null if it is too short for its length field.
        pub fn decode(frame: []const u8) ?Decoded {
            comptime assert(@typeInfo(HeaderT).@"struct".layout == .@"extern");
            if (frame.len < @sizeOf(HeaderT)) return null;
            const h = std.mem.bytesToValue(HeaderT, frame[0..@sizeOf(HeaderT)]);
            const len: usize = @intCast(@field(h, opts.length_field));
            if (frame.len - @sizeOf(HeaderT) < len) return null;
            return .{ .header = h, .payload = frame[@sizeOf(HeaderT)..][0..len] };
        }

        /// `equivocate` on wire frames, for `tardis_sec.twoFaced`: the
        /// payload byte at `index` is flipped by `flip` and the checksum
        /// recomputed. Null (send the original) if the frame does not parse
        /// or is shorter than `index`.
        pub fn equivocateFrame(comptime index: usize, comptime flip: u8) fn ([]const u8, []u8) ?usize {
            return struct {
                fn f(in: []const u8, out: []u8) ?usize {
                    const d = decode(in) orelse return null;
                    if (index >= d.payload.len or in.len > out.len) return null;
                    var h2: HeaderT = undefined;
                    equivocate(d.header, d.payload, index, flip, &h2, out[@sizeOf(HeaderT)..][0..d.payload.len]);
                    @memcpy(out[0..@sizeOf(HeaderT)], std.mem.asBytes(&h2));
                    return @sizeOf(HeaderT) + d.payload.len;
                }
            }.f;
        }

        /// `desyncLength` on wire frames, for `twoFaced` (in flight): the
        /// length field becomes `len + delta` (wrapping) and the bytes stay
        /// as sent. With `fix_checksum`, the checksum is recomputed over the
        /// span the frame now claims, so a shorter claim passes integrity
        /// and the bytes after it reach the parser as whatever comes next
        /// (smuggling); a claim longer than the bytes there is then left
        /// alone (null), since its checksum cannot be computed. Without it,
        /// the receiver over- or under-reads unless it checks. Null too if
        /// the frame does not parse.
        pub fn desyncFrame(comptime delta: i64, comptime fix_checksum: bool) fn ([]const u8, []u8) ?usize {
            return struct {
                fn f(in: []const u8, out: []u8) ?usize {
                    const d = decode(in) orelse return null;
                    if (in.len > out.len) return null;
                    var h = d.header;
                    desyncLength(&h, delta);
                    if (fix_checksum) {
                        const claimed: u64 = @intCast(@field(h, opts.length_field));
                        if (claimed > in.len - @sizeOf(HeaderT)) return null;
                        fixup(&h, in[@sizeOf(HeaderT)..][0..@intCast(claimed)]);
                    }
                    @memcpy(out[0..in.len], in);
                    @memcpy(out[0..@sizeOf(HeaderT)], std.mem.asBytes(&h));
                    return in.len;
                }
            }.f;
        }

        pub fn epochOf(header: HeaderT) u64 {
            const e = opts.epoch_field orelse return 0;
            return @intCast(@field(header, e));
        }

        comptime {
            _ = LenT;
        }
    };
}

// ===========================================================================
// §6 Amplification limits and the ledger

/// Ratios are in thousandths (milli) so they stay integers. The ledger
/// lives in `amplify.zig`; `SecurityConfig.amplification` turns the checks on.
pub const AmplificationLimits = engine.amplify.Limits;
pub const Amplification = engine.amplify.Ledger;
pub const AmplificationRatio = engine.amplify.Ratio;

/// Counts `n` work units (hash probes, loop steps, comparisons) for the
/// amplification ledger: the numerator of `work_per_input_byte`.
pub fn work(n: u64) void {
    engine.addWork(n);
}

/// Declares `n` bytes of untrusted input that did not arrive over the
/// network (network bytes are counted automatically).
pub fn untrustedInput(n: u64) void {
    engine.addInput(n);
}

// ===========================================================================
// §7.1 MC/DC for Zig code

pub const mcdc = struct {
    pub const Report = engine.mcdc.Report;
    pub const Entry = engine.mcdc.Entry;
    pub const Decl = engine.mcdc.Decl;
    pub const decisions_max = engine.mcdc.decisions_max;

    /// A decision with up to 8 conditions: records the vector and returns
    /// `eval(conds)`, the code's own expression over the conditions.
    ///
    ///     if (mcdc.decision(7, .{ armed, sig_ok, override }, struct {
    ///         fn f(c: anytype) bool { return c[0] and (c[1] or c[2]); }
    ///     }.f)) { ... }
    pub fn decision(comptime id: u8, conds: anytype, comptime eval: anytype) bool {
        const out: bool = eval(conds);
        const n = @typeInfo(@TypeOf(conds)).@"struct".field_names.len;
        engine.mcdcRecord(id, n, engine.mcdc.vectorOf(conds), out);
        return out;
    }

    /// `a op b`, for a comparison that is a condition of a decision: `a`
    /// is the input, `b` the value it is compared against. `b` is offered
    /// to guided exploration (`Options.explore = .guided`) as a value worth
    /// forcing, so an input drawn with `env.fuzz` can be made equal to the
    /// value that flips the condition: what `trace-cmp` gives instrumented
    /// C. Integers and enums up to 64 bits.
    ///
    ///     const ok = mcdc.compare(header.magic, .eq, 0x7A3D51C9);
    pub fn compare(a: anytype, comptime op: std.math.CompareOperator, b: anytype) bool {
        const T = @TypeOf(a, b);
        const x: T = a;
        const y: T = b;
        engine.mcdcOperand(operandBits(y), op != .eq and op != .neq);
        return switch (@typeInfo(T)) {
            .@"enum" => std.math.compare(@backingInt(x), op, @backingInt(y)),
            else => std.math.compare(x, op, y),
        };
    }

    fn operandBits(x: anytype) u64 {
        return switch (@typeInfo(@TypeOf(x))) {
            .@"enum" => operandBits(@backingInt(x)),
            .comptime_int => if (x < 0) @bitCast(@as(i64, x)) else @as(u64, x),
            .int => |int| if (int.signedness == .signed) @bitCast(@as(i64, x)) else @as(u64, x),
            else => @compileError("mcdc.compare: integers and enums only, not " ++ @typeName(@TypeOf(x))),
        };
    }
};

// ===========================================================================
// Configuration and the comptime entry point

pub const SecurityMode = enum {
    /// Shadow memory, taint, Byzantine and DoS oracles; stop at the first failure.
    audit,
    /// Everything in `audit`, plus MC/DC, DPOR and evidence; never stops early.
    certification_eal7,
};

pub const paths_max = engine.paths_max;
pub const SandboxPolicy = engine.SandboxPolicy;

pub const SecurityConfig = struct {
    mode: SecurityMode = .audit,
    tenants_max: u8 = 8,
    vfs_toctou_race_ppm: tardis.Ppm = 20_000,
    /// The swaps a won check-to-use race may make: a symlink or a hard link
    /// at the path (to `setToctouTarget`), or a symlink in place of its
    /// parent directory (to `setToctouDirTarget`); and, when turned on, an
    /// empty directory at the path, which needs no target.
    vfs_toctou_swaps: engine.ToctouSwaps = .{},
    /// Chance of a forced task switch at the second read of a `Shared`
    /// word by one task (the window a double fetch needs).
    double_fetch_preempt_ppm: tardis.Ppm = 500_000,
    entropy_starvation_ppm: tardis.Ppm = 0,
    instruction_skip_glitch_ppm: tardis.Ppm = 0,
    byzantine_ppm: tardis.Ppm = 50_000,
    /// Ingress taint (§5.2): received network bytes are untrusted until
    /// `markSanitized`, and a path that holds 8 or more of them in a row
    /// when it is opened, created, deleted or renamed is CWE-22.
    taint_paths: bool = true,
    /// Shadow memory (§3.8): every load and store of code built with
    /// the sanitizer's callbacks (`exportSanitizer`) is checked against
    /// the heap's state, so a write or read past an allocation's end,
    /// or a use after free, is a finding at the access. Costs 8 MiB
    /// per simulator.
    shadow_memory: bool = false,
    /// Data races (§4.5): two tasks of one node that touch one address
    /// from code built with the sanitizer's callbacks, at least one
    /// with a store, with no spawn, wake, await or atomic (a mutex is
    /// one) ordering them, are CWE-362. Costs about 2 MiB per simulator.
    data_races: bool = false,
    /// Lock order for lock-shaped atomics (§4.6): a 32-bit atomic that
    /// code built with the sanitizer's callbacks takes from zero to
    /// non-zero and back, as `std.Io.Mutex` does, is a lock, and taking
    /// two of them in both orders is CWE-833.
    atomic_lock_order: bool = false,
    /// Amplification checks and steering (§6.1); off unless set, since any
    /// program allocates more than its input in absolute terms.
    amplification: ?AmplificationLimits = null,
    /// Receives the campaign's MC/DC table (§7.1).
    mcdc: ?*mcdc.Report = null,
    /// Receives every counted run's requirement checks and findings
    /// (§7.5); `certify` sets it.
    campaign: ?*Campaign = null,
    /// Forced to false by `.certification_eal7`, so coverage and
    /// traceability evidence is complete even when defects are found.
    stop_on_first_failure: bool = true,
    evidence_dir: []const u8 = "zig-out/tardis-evidence",
    /// Receives the content findings of the last run (see `engine.Report`).
    report: ?*engine.Report = null,
    /// A failed `check` writes `<hash>.sarif` here: its findings, located
    /// at the test's call to `check`, with the replay token (seam 4). Under
    /// `TARDIS_SEC=1`, `TARDIS_SARIF_DIR` does the same for every check.
    check_sarif: ?*const std.Io.Dir = null,
    /// Base campaign options (iterations, personas, nodes, ...).
    base: tardis.Options = .{},

    pub fn effective(c: SecurityConfig) SecurityConfig {
        var out = c;
        if (c.mode == .certification_eal7) out.stop_on_first_failure = false;
        return out;
    }
};

/// The run's security configuration, readable from hooks and helpers.
threadlocal var active_config: SecurityConfig = .{};
threadlocal var active_worker: ?*WorkerSec = null;

/// `tardis.check(gpa, body, tardis_sec.withSecurity(.{ ... }))`: core
/// options with the security layer configured: the content engine
/// (`engine.zig`) is attached through core's run-time seam, one instance
/// per simulator, so every allocation and every byte crossing `std.Io` is
/// checked.
pub fn withSecurity(config: SecurityConfig) tardis.Options {
    const c = config.effective();
    active_config = c;
    var o = c.base;
    if (c.mode == .certification_eal7) o.determinism_check_every = 1;
    o.security = .{ .provider = &engine.provider, .params = paramsOf(c) };
    return o;
}

/// What `TARDIS_SEC=1` attaches to every `check` whose options name no
/// security layer (seam 4, plan2.md §8.2): the content engine in `.audit`
/// mode, observing only. Nothing that steers a run is on (no symlink swaps,
/// no forced switches inside `Shared` reads, no Byzantine rewrites, no
/// amplification limits), so a passing test's trace stays the same and
/// only real findings fail it.
pub const default_config: SecurityConfig = .{
    .vfs_toctou_race_ppm = 0,
    .double_fetch_preempt_ppm = 0,
    .byzantine_ppm = 0,
};
pub const default_security: ?tardis.sec_seam.Security = .{ .provider = &engine.provider, .params = paramsOf(default_config) };

/// The engine's configuration words for `c` (see `engine.Param`).
fn paramsOf(c: SecurityConfig) tardis.sec_seam.Params {
    var params: tardis.sec_seam.Params = @splat(0);
    params[@backingInt(engine.Param.glitch_ppm)] = c.instruction_skip_glitch_ppm;
    params[@backingInt(engine.Param.mode)] = @backingInt(c.mode);
    params[@backingInt(engine.Param.report)] = if (c.report) |r| @intFromPtr(r) else 0;
    params[@backingInt(engine.Param.toctou_ppm)] = c.vfs_toctou_race_ppm;
    params[@backingInt(engine.Param.toctou_swaps)] = @as(u8, @bitCast(c.vfs_toctou_swaps));
    params[@backingInt(engine.Param.taint_paths)] = @intFromBool(c.taint_paths);
    params[@backingInt(engine.Param.shadow)] = @intFromBool(c.shadow_memory);
    params[@backingInt(engine.Param.data_races)] = @as(u64, @intFromBool(c.data_races)) | (@as(u64, @intFromBool(c.atomic_lock_order)) << 1);
    params[@backingInt(engine.Param.double_fetch_ppm)] = c.double_fetch_preempt_ppm;
    params[@backingInt(engine.Param.byzantine_ppm)] = c.byzantine_ppm;
    if (c.amplification) |lim| {
        const w = engine.amplify.pack(lim);
        params[@backingInt(engine.Param.amplification)] = 1;
        params[@backingInt(engine.Param.amplification_limits_a)] = w[0];
        params[@backingInt(engine.Param.amplification_limits_b)] = w[1];
    }
    params[@backingInt(engine.Param.mcdc_report)] = if (c.mcdc) |r| @intFromPtr(r) else 0;
    params[@backingInt(engine.Param.campaign)] = if (c.campaign) |r| @intFromPtr(r) else 0;
    params[@backingInt(engine.Param.check_sarif)] = if (c.check_sarif) |d| @intFromPtr(d) else 0;
    return params;
}

/// Content findings of the current run so far (empty without the engine).
/// Call from the test body, or read `lastFindings` after `check` returns.
pub fn runFindings() []const ContentFinding {
    const e = engine.active() orelse return &.{};
    return e.findingsSlice();
}

/// The client on simulated node `node` belongs to `tenant` for the rest of
/// the run: bytes another tenant marked (`markTenant`, `withTenant`
/// secrets) must not reach it.
pub fn bindNodeTenant(node: tardis.NodeId, tenant: TenantId) void {
    assert(tenant != tenant_poison);
    const e = engine.active() orelse return;
    if (node < engine.nodes_max) e.tenant_of_node[node] = tenant;
}

/// Declares bytes as belonging to `tenant`: they may reach that tenant's
/// peers (and local files), not another tenant's (CWE-668).
pub fn markTenant(bytes: []const u8, tenant: TenantId) void {
    assert(tenant != tenant_poison);
    const e = engine.active() orelse return;
    e.mark(bytes, .tenant_data, tenant, currentNode());
}

fn currentNode() tardis.NodeId {
    const s = tardis.Sim.activeOrNull() orelse return 0;
    return s.currentNode();
}

pub fn attachWorker(w: ?*WorkerSec) void {
    active_worker = w;
}

fn spanOf(bytes: []const u8) u64 {
    return @intFromPtr(bytes.ptr);
}

fn inShadow(w: *WorkerSec, bytes: []const u8) bool {
    const a = spanOf(bytes);
    return a >= w.base and a + bytes.len <= w.base + w.shadow.len * 8;
}

/// Declares key material: a free before `secureZero` reports CWE-226, and
/// egress reports CWE-200.
/// Call it once the bytes hold their final value: the engine fingerprints
/// the content at this moment (8-byte windows, so secrets of at least 8
/// bytes).
pub fn markSecret(bytes: []const u8) void {
    if (engine.active()) |e| e.mark(bytes, .secret, e.current_tenant, currentNode());
    const w = active_worker orelse return;
    if (inShadow(w, bytes)) w.setRange(spanOf(bytes), bytes.len, .secret_key);
}

/// Declares validated input: clears its taint (plan2.md §5.2). The content
/// engine taints by content, so equal bytes elsewhere are cleared too until
/// they are received again; the shadow model clears these addresses.
pub fn markSanitized(bytes: []const u8) void {
    if (engine.active()) |e| e.sanitize(bytes);
    const w = active_worker orelse return;
    if (inShadow(w, bytes)) w.setRange(spanOf(bytes), bytes.len, .valid_clean);
}

/// Runs `f(args...)` with allocations and received bytes tagged `tenant`.
pub fn withTenant(tenant: TenantId, comptime f: anytype, args: anytype) @typeInfo(@TypeOf(f)).@"fn".return_type.? {
    assert(tenant != tenant_poison);
    if (engine.active()) |e| {
        const saved = e.current_tenant;
        e.current_tenant = tenant;
        defer e.current_tenant = saved;
        return withTenantShadow(tenant, f, args);
    }
    return withTenantShadow(tenant, f, args);
}

fn withTenantShadow(tenant: TenantId, comptime f: anytype, args: anytype) @typeInfo(@TypeOf(f)).@"fn".return_type.? {
    const w = active_worker orelse return @call(.auto, f, args);
    const saved = w.tenant;
    w.tenant = tenant;
    defer w.tenant = saved;
    return @call(.auto, f, args);
}

/// A security-critical decision. Under `instruction_skip_glitch_ppm` the
/// simulator may invert it (one skipped compare), deterministically.
pub fn criticalCheck(env: *tardis.Env, cond: bool) bool {
    const ppm: tardis.Ppm = if (engine.active()) |e|
        @intCast(e.param(.glitch_ppm))
    else
        active_config.instruction_skip_glitch_ppm;
    if (ppm != 0 and env.sim.decider.chance(.fault, ppm)) return !cond;
    return cond;
}

/// `std.crypto.timing_safe.eql` as a glitch site: the comparison of a
/// MAC, a signature or a password hash is what a fault attack inverts.
/// Needs no `env`; outside a simulation it is the plain comparison.
pub fn criticalEql(comptime T: type, a: T, b: T) bool {
    return engine.glitch(std.crypto.timing_safe.eql(T, a, b));
}

// --- Pillars II and III through the engine (plan2.md §4, §5.1) ------------

/// `std.Io.Mutex` with a lock class. Taking it checks the lock order of
/// every task so far (lockdep, §4.2): an inversion is CWE-833 and fails the
/// run even on a schedule that does not deadlock. Without the engine it is
/// a plain mutex.
pub const Mutex = struct {
    inner: std.Io.Mutex = .init,
    /// Lock class, below `engine.races.c_lock_class_first` (the classes
    /// above are given to C mutexes and file locks): one per kind of lock
    /// (all locks of one table share a class).
    class: u16,

    pub fn lock(m: *Mutex, io: std.Io) std.Io.Cancelable!void {
        assert(m.class < engine.races.c_lock_class_first);
        engine.lockAcquire(m.class);
        m.inner.lock(io) catch |err| {
            engine.lockRelease(m.class);
            return err;
        };
    }

    pub fn unlock(m: *Mutex, io: std.Io) void {
        m.inner.unlock(io);
        engine.lockRelease(m.class);
    }
};

/// A value another party can change under the reader: memory shared with a
/// peer process, a DMA buffer, a ring written by another task. Zig has no
/// load instrumentation, so code that reads such memory opts in by reading
/// through `load`. The second read of the same word by one task is a
/// keyed preemption point (`double_fetch_preempt_ppm`): the writer gets to
/// run between the check and the use, and the program's own oracle shows
/// whether it re-validates (CWE-367, §4.1).
pub fn Shared(comptime T: type) type {
    return struct {
        const Self = @This();
        value: T,

        pub fn init(v: T) Self {
            return .{ .value = v };
        }

        pub fn load(s: *const Self) T {
            engine.sharedRead(@intFromPtr(s));
            return @as(*const volatile T, &s.value).*;
        }

        pub fn store(s: *Self, v: T) void {
            @as(*volatile T, &s.value).* = v;
        }
    };
}

/// For the rest of the run, a path this task checks (`statFile`, `access`)
/// and then opens may, with `vfs_toctou_race_ppm` per pair, be replaced
/// between the two by a symlink to `target` or a hard link to the file at
/// `target` (`vfs_toctou_swaps`, §4.3). A hard link's target resolves from
/// the directory the path is relative to, a symlink's from the link's own
/// directory: an absolute `target` means the same to both. Paths up to 256
/// bytes.
pub fn setToctouTarget(target: []const u8) void {
    const e = engine.active() orelse return;
    assert(target.len > 0 and target.len <= engine.races.target_bytes_max);
    @memcpy(e.races.target[0..target.len], target);
    e.races.target_len = @intCast(target.len);
}

/// For the rest of the run, a checked path with a directory component
/// (`uploads/report.txt`) may also have that first directory moved aside
/// and replaced by a symlink to the directory `dir` before the use, so the
/// rest of the path resolves inside `dir` (§4.3).
pub fn setToctouDirTarget(dir: []const u8) void {
    const e = engine.active() orelse return;
    assert(dir.len > 0 and dir.len <= engine.races.target_bytes_max);
    @memcpy(e.races.dir_target[0..dir.len], dir);
    e.races.dir_target_len = @intCast(dir.len);
}

/// Spellings of a file name that a persona resolves to the same file while
/// a byte comparison (even a case-insensitive ASCII one) tells them apart:
/// the inputs that get past a deny-list of names (CWE-41, path
/// equivalence; plan2.md §4.3). The rules are core's (`tardis.vfs`):
///
/// - every persona: `./name`;
/// - case-insensitive personas: the name with its ASCII case swapped;
/// - `windows_ntfs`: a trailing dot, a trailing space, the `::$DATA`
///   default stream, and the 8.3 short name `~1` when the name is long
///   (the first file of its short base and extension in a directory);
/// - `macos_apfs`: the decomposed (or composed) spelling of the Latin-1
///   letters in it (`é` as `e` U+0301).
pub const PathConfusions = struct {
    pub const max = 8;
    bufs: [max][tardis.vfs.name_bytes_max * 2 + 8]u8 = undefined,
    lens: [max]u16 = undefined,
    len: usize = 0,

    pub fn get(c: *const PathConfusions, i: usize) []const u8 {
        return c.bufs[i][0..c.lens[i]];
    }

    fn add(c: *PathConfusions, parts: []const []const u8) void {
        if (c.len == max) return;
        var n: usize = 0;
        for (parts) |part| {
            if (n + part.len > c.bufs[c.len].len) return;
            @memcpy(c.bufs[c.len][n..][0..part.len], part);
            n += part.len;
        }
        c.lens[c.len] = @intCast(n);
        c.len += 1;
    }
};

/// The confusable spellings of `name` (one path component) on `persona`.
pub fn pathConfusions(persona: tardis.Persona, name: []const u8) PathConfusions {
    const vfs = tardis.vfs;
    var c: PathConfusions = .{};
    c.add(&.{ "./", name });
    if (persona.caseInsensitive()) {
        var swapped: [vfs.name_bytes_max]u8 = undefined;
        const n = @min(name.len, swapped.len);
        var differs = false;
        for (name[0..n], swapped[0..n]) |ch, *o| {
            o.* = if (std.ascii.isUpper(ch)) std.ascii.toLower(ch) else std.ascii.toUpper(ch);
            differs = differs or o.* != ch;
        }
        if (differs) c.add(&.{swapped[0..n]});
    }
    if (persona.win32Names()) {
        c.add(&.{ name, "." });
        c.add(&.{ name, " " });
        c.add(&.{ name, "::$DATA" });
        var short: [12]u8 = undefined;
        if (vfs.shortName(name, 1, &short)) |s| c.add(&.{s});
    }
    if (persona.normalizationInsensitive()) {
        var buf: [vfs.name_bytes_max * 2]u8 = undefined;
        if (vfs.decomposeLatin1(name, &buf)) |d| c.add(&.{d});
        if (vfs.composeLatin1(name, &buf)) |d| c.add(&.{d});
    }
    return c;
}

/// For the rest of the run, datagrams from `node` to the nodes in `peers`
/// are rewritten by `mutate` with `byzantine_ppm` per datagram, while the
/// other peers get the original: a two-faced node (§5.1). Stream writes
/// from `node` to those peers go through `mutate` too, one pushed segment
/// at a time, and a rewrite is kept only when it keeps the length. Use
/// `ByzantineFrameSpec(...).equivocateFrame(i, flip)` for a mutation that
/// keeps the checksum valid.
pub fn twoFaced(node: tardis.NodeId, peers: []const tardis.NodeId, mutate: engine.races.MutateFn) void {
    const e = engine.active() orelse return;
    var set: u32 = 0;
    for (peers) |p| {
        assert(p < 32);
        set |= @as(u32, 1) << @as(u5, @intCast(p));
    }
    e.races.equivocator = .{ .node = node, .peers = set, .mutate = mutate };
}

/// For the rest of the run, an attacker on the wire records the datagrams
/// `node` sends to the nodes in `peers` (up to 16 frames of up to 256
/// bytes), and with `byzantine_ppm` per later datagram on those links
/// delivers one of the recorded frames again just before it (§5.1). The
/// recording belongs to the run, not to a node: a frame recorded before a
/// peer's reboot can be replayed after it.
pub fn replayer(node: tardis.NodeId, peers: []const tardis.NodeId) void {
    const e = engine.active() orelse return;
    var set: u32 = 0;
    for (peers) |p| {
        assert(p < 32);
        set |= @as(u32, 1) << @as(u5, @intCast(p));
    }
    e.races.replayer = .{ .node = node, .peers = set };
}

pub const RaceCounters = struct { double_fetches: u32, toctou_swaps: u32, mutations: u32, replays: u32 };

/// Counters of the current run (zero without the engine).
pub fn raceCounters() RaceCounters {
    const e = engine.active() orelse return .{ .double_fetches = 0, .toctou_swaps = 0, .mutations = 0, .replays = 0 };
    return .{ .double_fetches = e.races.double_fetches, .toctou_swaps = e.races.toctou_swaps, .mutations = e.races.mutations, .replays = e.races.replays };
}

/// The C shims' functions (`src/sec/c/tardis_sec.h`, §5.2).
pub const c_shims = @import("cabi.zig");

/// Exports the functions `c/tardis_sec.h` calls; for a test that links C:
/// `comptime { tardis_sec.exportC(); }`.
pub fn exportC() void {
    c_shims.exportSymbols();
}

/// The edge, comparison and division tracer for instrumented C (§6.3).
pub const c_trace = @import("ctrace.zig");

/// Exports clang's SanitizerCoverage callbacks, for a test that links C
/// built with `-fsanitize-coverage=trace-pc,trace-cmp,trace-div`:
/// `comptime { tardis_sec.exportCoverage(); }`. The dual-execution
/// assertions then compare that C's control flow and division widths too.
pub fn exportCoverage() void {
    c_trace.exportSymbols();
}

/// Exports the sanitizer callbacks (`shadow.zig`), for a test that links
/// an object built with `sanitize_thread` (Zig) or `-fsanitize=thread`
/// (C): `comptime { tardis_sec.exportSanitizer(); }`. With
/// `SecurityConfig.shadow_memory`, that code's loads and stores are
/// checked against the heap's shadow. The test itself must not be built
/// with `sanitize_thread`: Zig would link its own runtime.
pub fn exportSanitizer() void {
    engine.shadow.exportSymbols();
}

/// The Spectre-v1 gadget shape for Zig code (§6.3, CWE-1037). Zig has no
/// load tracing, so the code names the bounds check and the loads after
/// it: a load whose address follows the value an earlier one returned is
/// a finding once the site was seen with three different values.
///
///     if (spectre.boundsCheck(x, table.len)) {
///         const v = spectre.load(&table[x]);
///         return spectre.load(&probe[@as(usize, v) * 64]);
///     }
pub const spectre = struct {
    pub const Gadget = engine.spectre.Gadget;

    /// `index < len`, for an index the attacker chooses.
    pub noinline fn boundsCheck(index: usize, len: usize) bool {
        if (index >= len) return false;
        engine.spectreCheck(@returnAddress());
        return true;
    }

    /// `ptr.*`, reported to the detector (integers up to 64 bits).
    pub fn load(ptr: anytype) @TypeOf(ptr.*) {
        const value = ptr.*;
        var bits: u64 = 0;
        const n = @min(@sizeOf(@TypeOf(value)), @sizeOf(u64));
        @memcpy(std.mem.asBytes(&bits)[0..n], std.mem.asBytes(&value)[0..n]);
        engine.spectreLoad(@intFromPtr(ptr), bits);
        return value;
    }

    /// `index` when it is below `len`, else 0, by a mask: an index the
    /// processor cannot speculate out of bounds. Opens no window.
    pub fn indexNoSpec(index: usize, len: usize) usize {
        const mask = @as(usize, 0) -% @intFromBool(index < len);
        return index & mask;
    }
};

pub const Sandbox = struct {
    policy: SandboxPolicy,

    pub fn allowsPath(s: Sandbox, path: []const u8) bool {
        return s.policy.allowsPath(path);
    }
};

/// The policy outside any engine (a plain test, or a build without the
/// layer), for `activeSandbox`; nothing enforces it.
threadlocal var unenforced_sandbox: ?Sandbox = null;

/// Declares the end of the calling node's initialization (§5.2): from now
/// until its program restarts (a crash, or the next run), using a
/// capability the policy does not allow is CWE-272 and fails the run.
/// Enforced at core's calls: `connect`; `listen` and `bind`;
/// `std.process.spawn` and `replace`; and open, create, delete and rename
/// of paths outside `vfs_prefixes`. Calling it again replaces the policy.
pub fn enterSandbox(policy: SandboxPolicy) void {
    if (engine.active()) |e| return e.enterSandbox(currentNode(), policy);
    unenforced_sandbox = .{ .policy = policy };
}

/// The calling node's policy, if it entered one.
pub fn activeSandbox() ?Sandbox {
    if (engine.active()) |e| {
        const p = e.sandboxOf(currentNode()) orelse return null;
        return .{ .policy = p.* };
    }
    return unenforced_sandbox;
}

// --- Requirement Traceability Registry ------------------------------------

pub const Registry = traceability.Table;

/// Checks made outside any campaign (no engine, or no `certify`).
threadlocal var registry: Registry = .{};

pub const RequirementScope = struct {
    id: []const u8,

    /// Records one check of the requirement and returns `ok`. Inside a
    /// `certify` campaign the check counts for that campaign (once per
    /// counted run, not during shrinking); elsewhere it goes to this
    /// thread's `requirementRecords`.
    pub fn check(s: RequirementScope, ok: bool) bool {
        if (engine.requirementCheck(s.id, ok)) return ok;
        const i = registry.index(s.id) catch @panic("tardis_sec: requirement id too long, or requirements_max reached");
        const rec = &registry.records[i];
        if (ok) rec.checks_passed += 1 else rec.checks_failed += 1;
        return ok;
    }
};

/// Binds the following checks to a Security Functional Requirement, e.g.
/// `tardis_sec.requirement("SFR-FDP_ACC.1")` (ids up to 48 bytes).
pub fn requirement(id: []const u8) RequirementScope {
    assert(id.len > 0 and id.len <= traceability.id_bytes_max);
    return .{ .id = id };
}

/// Checks made outside a campaign on this thread.
pub fn requirementRecords() []const RequirementRecord {
    return registry.slice();
}

// ===========================================================================
// §6/§7 Dual-execution oracles

pub const Error = error{
    TimingLeak,
    Interference,
    DifferentialDivergence,
};

threadlocal var dual_secret: []const u8 = "";
threadlocal var dual_public: []const u8 = "";
/// Both runs of a dual execution read their inputs from these, so the
/// inputs' addresses (and cache sets, §6.3) do not differ between runs;
/// longer inputs are passed where they are.
threadlocal var dual_secret_buf: [4096]u8 = undefined;
threadlocal var dual_public_buf: [4096]u8 = undefined;

fn pinned(buf: *[4096]u8, bytes: []const u8) []const u8 {
    if (bytes.len > buf.len) return bytes;
    @memcpy(buf[0..bytes.len], bytes);
    return buf[0..bytes.len];
}

fn traceWith(
    gpa: Allocator,
    comptime body: fn (*tardis.Env, []const u8, []const u8) anyerror!void,
    public: []const u8,
    secret: []const u8,
    seed: u64,
    persona: tardis.Persona,
    options: tardis.Options,
) !u64 {
    const Thunk = struct {
        fn run(env: *tardis.Env) anyerror!void {
            return body(env, dual_public, dual_secret);
        }
    };
    dual_public = pinned(&dual_public_buf, public);
    dual_secret = pinned(&dual_secret_buf, secret);
    c_trace.reset();
    const h = try tardis.traceHash(gpa, Thunk.run, seed, persona, options);
    // Instrumented C's edges and divisions, when there were any.
    const c = c_trace.current().hash;
    return if (c == 0) h else tardis.decide.mix(h, c);
}

/// Runs `body` with `secret_a` and with `secret_b` on the same seeds and
/// requires identical observable traces (every I/O operation, its size and
/// its virtual time). With C built for the tracer (`exportCoverage`), the
/// trace also covers that C's edges and the widths of its divisors.
pub fn assertConstantTime(
    gpa: Allocator,
    comptime body: fn (*tardis.Env, []const u8, []const u8) anyerror!void,
    secret_a: []const u8,
    secret_b: []const u8,
    seeds: u32,
    options: tardis.Options,
) !void {
    var i: u32 = 0;
    while (i < seeds) : (i += 1) {
        const seed = tardis.runSeed(options.campaign_seed, i, 0);
        const persona = options.personas[0];
        const a = try traceWith(gpa, body, "", secret_a, seed, persona, options);
        const b = try traceWith(gpa, body, "", secret_b, seed, persona, options);
        if (a != b) return error.TimingLeak;
    }
}

/// Goguen-Meseguer non-interference: for one public input and two HIGH
/// secrets, LOW observations (the trace) must be identical.
pub fn assertNonInterference(
    gpa: Allocator,
    comptime body: fn (*tardis.Env, []const u8, []const u8) anyerror!void,
    public: []const u8,
    high_a: []const u8,
    high_b: []const u8,
    seeds: u32,
    options: tardis.Options,
) !void {
    var i: u32 = 0;
    while (i < seeds) : (i += 1) {
        const seed = tardis.runSeed(options.campaign_seed, i, 0);
        const persona = options.personas[0];
        const a = try traceWith(gpa, body, public, high_a, seed, persona, options);
        const b = try traceWith(gpa, body, public, high_b, seed, persona, options);
        if (a != b) return error.Interference;
    }
}

/// Two implementations of one parser or protocol must agree on `input`:
/// same accept/reject, and the same result when both accept (CWE-444).
pub fn assertDifferential(
    comptime T: type,
    input: []const u8,
    scratch_a: []u8,
    scratch_b: []u8,
    comptime parse_a: fn ([]const u8, []u8) anyerror!T,
    comptime parse_b: fn ([]const u8, []u8) anyerror!T,
) !void {
    const a = parse_a(input, scratch_a);
    const b = parse_b(input, scratch_b);
    if (a) |va| {
        const vb = b catch return error.DifferentialDivergence;
        if (!std.meta.eql(va, vb)) return error.DifferentialDivergence;
    } else |_| {
        _ = b catch return;
        return error.DifferentialDivergence;
    }
}

pub const ExhaustiveOptions = tardis.ExhaustiveOptions;
pub const ExhaustiveResult = tardis.ExhaustiveResult;

/// Bounded exhaustive exploration (§7.2): every combination of outcomes of
/// the first `depth_max` branchable decisions of `body`, by stateless
/// replay in core (`tardis.exhaustive`). Partial-order reduction and
/// snapshot restore are not applied yet, so the cost is the full product
/// of outcomes; `ExhaustiveResult.complete` says whether the bound was
/// covered without gaps. Evidence within the model and the bound, never a
/// proof beyond them.
pub fn verifyExhaustive(
    gpa: Allocator,
    comptime body: fn (*tardis.Env) anyerror!void,
    options: tardis.Options,
    x: ExhaustiveOptions,
) !ExhaustiveResult {
    return tardis.exhaustive(gpa, body, options, x);
}

// ===========================================================================
// §7 Evidence: SARIF v2.1.0 and the signed bundle

pub fn writeSarif(w: *std.Io.Writer, tool_version: []const u8, findings: []const Finding) !void {
    try w.print(
        \\{{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{{"tool":{{"driver":{{"name":"tardis_sec","version":"{s}"}}}},"results":[
    , .{tool_version});
    for (findings, 0..) |f, i| {
        if (i > 0) try w.writeAll(",");
        try w.print(
            \\{{"ruleId":"CWE-{d}","level":"error","message":{{"text":"{t} at 0x{x} (tenant {d})"}}}}
        , .{ f.cwe, f.state, f.addr, f.tenant });
    }
    try w.writeAll("]}]}\n");
}

/// Merkle root over SHA-256 leaves (pairs hashed; an odd leaf is promoted).
/// `leaves` is overwritten. Iterative, bounded by `leaves.len`.
pub const merkleRoot = evidence.merkleRoot;

pub const Ed25519 = std.crypto.sign.Ed25519;

/// Signs a bundle's Merkle root.
pub fn signEvidence(root: [32]u8, key: Ed25519.KeyPair) !Ed25519.Signature {
    return key.sign(&root, null);
}

// --- certification campaigns ----------------------------------------------

pub const version = "0.1.0";

/// `CertifyOptions.repositories`: a checkout and the name it goes by.
pub const Repository = struct { name: []const u8, dir: std.Io.Dir };
pub const repositories_max = 8;

pub const CertifyOptions = struct {
    /// The test (campaign) name, bound to every requirement it checks.
    name: []const u8,
    /// The project's requirement file (its contents): requirements listed
    /// there and never checked are gaps in the matrix.
    requirements: ?[]const u8 = null,
    /// The project directory holding `.tardis_persist/requirements.bin`:
    /// the campaign's results are merged into it.
    persist: ?std.Io.Dir = null,
    /// Where `SecurityConfig.evidence_dir` is created (default: the
    /// current directory). `TARDIS_EVIDENCE_DIR`, in tests, overrides both.
    out: ?std.Io.Dir = null,
    /// Signs the Merkle root; without it the bundle is integrity-checked only.
    key: ?Ed25519.KeyPair = null,
    /// `@src()` of the test, for SARIF locations.
    source: ?std.builtin.SourceLocation = null,
    /// Repository path of the test module's root, prepended to `source.file`.
    source_prefix: []const u8 = "",
    /// Golden trace hashes recorded (the first iterations' seeds).
    determinism_seeds: u32 = 8,
    /// The repositories whose checked-out revisions the manifest records
    /// (read from `.git`, no `git` process; §7.5).
    repositories: []const Repository = &.{},
    /// The project's instrumented decisions (§7.1): each one's MC/DC counts
    /// towards its requirement's row, and declared decisions never reached
    /// are listed as dead (or, with a justification, deactivated) code.
    decisions: []const mcdc.Decl = &.{},
    /// The code whose never-run edges `edges.json` lists (§7.1). Read only
    /// in an instrumented build (`zig build evidence -Dedges`), where the
    /// campaign then runs on one thread, in-process.
    edge_scope: []const edges.Scope = &.{},
    tool_version: []const u8 = version,
};

/// The outcome of `certify`. Heap-allocated (the requirement table is
/// 512 KiB); `deinit` frees it.
pub const Certified = struct {
    campaign: Campaign,
    failures: tardis.FailureLog,
    mcdc: mcdc.Report,
    /// Edges in `CertifyOptions.edge_scope` that never ran (§7.1).
    edges: edges.Report,
    mode: SecurityMode,
    /// The campaign's first failure (`check`'s error), if any.
    err: ?anyerror,
    /// `<16 hex digits>`: a hash of the name, seed, iterations and mode.
    id_buf: [16]u8,
    /// The bundle directory, open (certification mode only).
    bundle: ?std.Io.Dir,
    written: ?evidence.Written,
    determinism: [64]evidence.DeterminismRow,
    revisions: [repositories_max]evidence.Revision,
    revisions_len: u8,
    determinism_len: u32,
    io: std.Io,

    pub fn id(c: *const Certified) []const u8 {
        return &c.id_buf;
    }

    pub fn deinit(c: *Certified, gpa: Allocator) void {
        if (c.bundle) |d| d.close(c.io);
        c.edges.deinit(gpa);
        gpa.destroy(c);
    }
};

fn testEnvSet(gpa: Allocator, name: []const u8) bool {
    if (!@import("builtin").is_test) return false;
    return std.testing.environ.containsUnempty(gpa, name) catch false;
}

/// Runs a certification campaign: `check` with every counted run's
/// requirement checks and findings collected, merged into the persisted
/// registry when `persist` is set. In `.certification_eal7` mode (or with
/// `TARDIS_CERT_EAL7` set in tests) the campaign never stops early (one
/// thread, `keep_going`: every failure is shrunk and kept as a capsule),
/// and the signed evidence bundle is written to
/// `<out>/<evidence_dir>/<id>/`. The campaign's error, if any, is in
/// `Certified.err`; `certify` itself fails only on I/O and allocation.
pub fn certify(
    gpa: Allocator,
    io: std.Io,
    comptime body: fn (*tardis.Env) anyerror!void,
    config: SecurityConfig,
    c: CertifyOptions,
) !*Certified {
    const r = try gpa.create(Certified);
    errdefer gpa.destroy(r);
    r.campaign.init(c.name);
    r.failures = .{};
    r.mcdc = .{};
    r.edges = .{ .scope = c.edge_scope };
    r.mode = if (config.mode == .certification_eal7 or testEnvSet(gpa, "TARDIS_CERT_EAL7")) .certification_eal7 else config.mode;
    r.err = null;
    r.bundle = null;
    r.written = null;
    r.determinism_len = 0;
    r.revisions_len = 0;
    r.io = io;
    if (c.repositories.len > repositories_max) return error.TooManyRepositories;
    for (c.repositories) |repo| {
        r.revisions[r.revisions_len] = evidence.readRevision(gpa, io, repo.dir, repo.name);
        r.revisions_len += 1;
    }
    if (c.requirements) |text| try r.campaign.requirements.declare(text);
    const declared = r.campaign.requirements.len;

    var cfg = config;
    cfg.mode = r.mode;
    cfg.campaign = &r.campaign;
    if (cfg.mcdc == null) cfg.mcdc = &r.mcdc;
    const eal7 = r.mode == .certification_eal7;
    if (eal7) cfg.base.keep_going = &r.failures;
    // Counted runs commit into this process's campaign: a forked child
    // sends its run's tallies back through the seam (`fork_export`), and
    // worker processes forward their children's to this one.
    for (c.decisions, 0..) |d, k| {
        for (c.decisions[0..k]) |e| if (e.id == d.id) return error.DuplicateDecision;
    }
    // Edge counters are per process and unsynchronized: an instrumented
    // campaign runs on this thread, without forking.
    const count_edges = edges.instrumented and eal7 and c.edge_scope.len > 0;
    if (count_edges) {
        cfg.base.workers = 1;
        cfg.base.fork = false;
        try edges.begin(gpa);
    }
    tardis.check(gpa, body, withSecurity(cfg)) catch |err| {
        r.err = err;
    };
    if (count_edges) r.edges = try edges.finish(gpa, io, c.edge_scope);
    // MC/DC per requirement: decisions declared for it, and those complete.
    const report = cfg.mcdc.?;
    for (c.decisions) |d| {
        const req = d.requirement orelse continue;
        const rec = &r.campaign.requirements.records[try r.campaign.requirements.index(req)];
        rec.mcdc_decisions_total += 1;
        if (report.entry(d.id).complete()) rec.mcdc_decisions_covered += 1;
    }
    r.campaign.canonicalize(declared);

    {
        var h = std.hash.Wyhash.init(0x5EC0_CE27);
        h.update(c.name);
        h.update(std.mem.asBytes(&cfg.base.campaign_seed));
        h.update(std.mem.asBytes(&cfg.base.iterations));
        h.update(@tagName(r.mode));
        const v = h.final();
        _ = std.fmt.bufPrint(&r.id_buf, "{x:0>16}", .{v}) catch unreachable;
    }

    if (c.persist) |dir| {
        const table = try gpa.create(Registry);
        defer gpa.destroy(table);
        table.len = 0;
        try table.load(io, gpa, dir, traceability.persist_path);
        try table.merge(&r.campaign.requirements);
        try table.save(io, dir, traceability.persist_path);
    }
    if (!eal7) return r;

    // Golden trace hashes, from runs outside the campaign's counts.
    var plain = cfg;
    plain.campaign = null;
    plain.mcdc = null;
    plain.report = null;
    plain.base.keep_going = null;
    const plain_options = withSecurity(plain);
    var i: u32 = 0;
    while (i < c.determinism_seeds and r.determinism_len < r.determinism.len) : (i += 1) {
        const persona = cfg.base.personas[0];
        const seed = tardis.runSeed(cfg.base.campaign_seed, i, 0);
        const hash = tardis.traceHash(gpa, body, seed, persona, plain_options) catch continue;
        r.determinism[r.determinism_len] = .{ .persona = persona, .seed = seed, .trace_hash = hash };
        r.determinism_len += 1;
    }

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const env_dir: ?[]u8 = if (@import("builtin").is_test) std.testing.environ.getAlloc(gpa, "TARDIS_EVIDENCE_DIR") catch null else null;
    defer if (env_dir) |d| gpa.free(d);
    // `TARDIS_EVIDENCE_DIR` is relative to the current directory and wins.
    const base_dir = if (env_dir != null) std.Io.Dir.cwd() else c.out orelse std.Io.Dir.cwd();
    const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ env_dir orelse config.evidence_dir, r.id() });
    const dir = try base_dir.createDirPathOpen(io, path, .{ .open_options = .{ .iterate = true } });
    r.bundle = dir;
    r.written = try evidence.write(gpa, io, dir, .{
        .manifest = .{
            .tool_version = c.tool_version,
            .campaign = c.name,
            .campaign_id = r.id(),
            .campaign_seed = cfg.base.campaign_seed,
            .iterations = cfg.base.iterations,
            .personas = cfg.base.personas,
            .nodes = cfg.base.nodes,
            .mode = @tagName(r.mode),
            .revisions = r.revisions[0..r.revisions_len],
        },
        .campaign = &r.campaign,
        .failures = &r.failures,
        .mcdc = report,
        .decisions = c.decisions,
        .edges = &r.edges,
        .determinism = r.determinism[0..r.determinism_len],
        .source = c.source,
        .source_prefix = c.source_prefix,
    }, c.key);
    return r;
}

/// Verifies a bundle (§7.5): hashes, completeness, root and signature.
pub const verifyEvidence = evidence.verify;

/// Verifies a bundle and re-runs its capsules and determinism hashes
/// against the campaign's body and options.
pub const replayEvidence = evidence.replay;

// ===========================================================================
// Tests

const testing = std.testing;

test "shadow cell: nibbles, the one-compare fast path, and meta orthogonality" {
    var c: ShadowCell = .{};
    try testing.expect(c.isFastClean(0));
    c.fast_word = 0x0001_0007; // fiber 1, epoch 7, all bytes clean
    try testing.expect(c.isFastClean(0x0001_0007));
    c.setNibble(3, .secret_key);
    try testing.expect(!c.isFastClean(0x0001_0007));
    try testing.expectEqual(ByteState.secret_key, c.nibble(3));
    c.setMeta(.{ .vclock_epoch = 9, .has_concurrent_writer = 1, .alloc_gen = 4, .taint_tenant_id = 2 });
    try testing.expectEqual(ByteState.secret_key, c.nibble(3));
    try testing.expectEqual(@as(TenantId, 2), c.meta().taint_tenant_id);
    try testing.expectEqual(@as(u64, 2), c.meta_word >> 56);
}

test "unaligned span straddling two cells" {
    var c0: ShadowCell = .{};
    var c1: ShadowCell = .{};
    c1.setNibble(1, .redzone_right);
    // Bytes 6..7 of c0 and 0..1 of c1: clean, clean, clean, redzone.
    const n = spanNibbles(c0, c1, 6, 4);
    try testing.expect(statesIn(n) & ByteState.access_fault != 0);
    try testing.expectEqual(@as(u64, 0), spanNibbles(c0, c1, 6, 3));
    c0.setNibble(0, .uninit_heap);
    try testing.expect(statesIn(spanNibbles(c0, c1, 0, 1)) & ByteState.bit(.uninit_heap) != 0);
}

test "egress scan: secret, uninit, and cross-tenant bytes are caught" {
    const clean: @Vector(8, u32) = @splat(0);
    const sys_tenants: @Vector(8, u8) = @splat(0);
    try testing.expectEqual(@as(?ByteState, null), egressScan(clean, sys_tenants, 1).fault);
    var secret = clean;
    secret[5] = 0x7 << 8;
    try testing.expectEqual(@as(?ByteState, .secret_key), egressScan(secret, sys_tenants, 1).fault);
    var zeroed = clean;
    zeroed[5] = 0xB << 8;
    try testing.expectEqual(@as(?ByteState, null), egressScan(zeroed, sys_tenants, 1).fault);
    var mixed: @Vector(8, u8) = @splat(1);
    mixed[2] = 2;
    try testing.expect(egressScan(clean, mixed, 1).cross_tenant);
}

test "hooks: secureZero turns secrets into secret_zeroed; leaks are reported" {
    var cells: [64]ShadowCell = undefined;
    const base: u64 = 0x1000;
    var w = WorkerSec.init(base, &cells);
    const H = SecurityHooks;
    H.onAlloc(&w, base, 32);
    try testing.expectEqual(ByteState.uninit_heap, w.stateAt(base));
    w.setRange(base, 32, .secret_key);
    H.onWrite(&w, base, &@as([32]u8, @splat(0))); // secureZero
    try testing.expectEqual(ByteState.secret_zeroed, w.stateAt(base + 31));
    H.onFree(&w, base, 32);
    try testing.expectEqual(@as(u16, 0), w.findings_len);

    H.onAlloc(&w, base + 64, 16);
    w.setRange(base + 64, 16, .secret_key);
    H.onFree(&w, base + 64, 16); // not zeroized
    try testing.expectEqual(@as(u16, 1), w.findings_len);

    H.onAlloc(&w, base + 128, 64);
    H.onWrite(&w, base + 128, &@as([60]u8, @splat(1)));
    try testing.expect(!H.onNetWrite(&w, base + 128, &@as([64]u8, @splat(1)), 0)); // 4 uninit bytes
    try testing.expectEqual(@as(u16, 908), w.findings[1].cwe);
}

test "lockdep: AB-BA and transitive inversions" {
    var g: LockdepGraph = .{};
    try testing.expectEqual(@as(?u16, null), g.acquire(1));
    try testing.expectEqual(@as(?u16, null), g.acquire(2)); // 1 -> 2
    g.release(2);
    g.release(1);
    try testing.expectEqual(@as(?u16, null), g.acquire(2));
    try testing.expectEqual(@as(?u16, null), g.acquire(3)); // 2 -> 3, so 1 -> 3
    g.release(3);
    g.release(2);
    _ = g.acquire(3);
    try testing.expectEqual(@as(?u16, 3), g.acquire(1)); // 3 held, then 1: inverts 1 -> 3
    try testing.expect(g.heldAtYield());
}

const RaftHeader = extern struct { term: u64, len: u32, crc: u32 };

test "byzantine: equivocation produces two frames that both verify" {
    const Spec = ByzantineFrameSpec(RaftHeader, .{ .length_field = "len", .checksum_field = "crc", .epoch_field = "term" });
    const payload = "vote:node2";
    var h: RaftHeader = .{ .term = 7, .len = payload.len, .crc = 0 };
    Spec.fixup(&h, payload);
    try testing.expect(Spec.isValid(h, payload));
    var h2: RaftHeader = undefined;
    var p2: [payload.len]u8 = undefined;
    Spec.equivocate(h, payload, 9, 0x01, &h2, &p2);
    try testing.expect(Spec.isValid(h2, &p2));
    try testing.expect(!std.mem.eql(u8, payload, &p2));
    try testing.expectEqual(@as(u64, 7), Spec.epochOf(h2));
    Spec.desyncLength(&h2, -20);
    try testing.expect(!Spec.isValid(h2, &p2));
}

test "amplification ratios" {
    const a: Amplification = .{ .input_bytes = 100, .alloc_bytes = 4_000, .rx_bytes = 10, .tx_bytes = 500 };
    try testing.expectEqual(AmplificationRatio.alloc_bytes_per_input_byte, a.exceeded(.{}).?);
}

test {
    _ = traceability;
    _ = evidence;
    _ = @import("git.zig");
}

test "registry and certification mode" {
    const scope = requirement("SFR-FDP_ACC.1");
    try testing.expect(scope.check(true));
    _ = scope.check(false);
    try testing.expectEqual(@as(u64, 1), requirementRecords()[0].checks_failed);
    const c = (SecurityConfig{ .mode = .certification_eal7 }).effective();
    try testing.expect(!c.stop_on_first_failure);
}

test "evidence: SARIF and a signed Merkle root" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeSarif(&w, "0.1.0", &.{.{ .cwe = 200, .state = .secret_key, .addr = 0x40, .tenant = 2, .requirement = 0xFFFF }});
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\"ruleId\":\"CWE-200\"") != null);
    var leaves: [3][32]u8 = .{ @splat(1), @splat(2), @splat(3) };
    const root = merkleRoot(&leaves);
    const kp = Ed25519.KeyPair.generateDeterministic(@splat(7)) catch unreachable;
    const sig = try signEvidence(root, kp);
    try sig.verify(&root, kp.public_key);
}

fn ctMacCheck(env: *tardis.Env, public: []const u8, secret: []const u8) anyerror!void {
    _ = public;
    var tag: [16]u8 = undefined;
    std.crypto.auth.siphash.SipHash128(1, 3).create(&tag, "message", secret[0..16]);
    // Writes the same number of bytes whatever the key: constant observable time.
    try env.dir.writeFile(env.io, .{ .sub_path = "tag", .data = &tag });
}

fn leakyCheck(env: *tardis.Env, public: []const u8, secret: []const u8) anyerror!void {
    _ = public;
    // Early exit on the first secret byte: the trace depends on the secret.
    if (secret[0] == 0) return;
    try env.dir.writeFile(env.io, .{ .sub_path = "x", .data = "y" });
}

test "constant time and non-interference by dual execution" {
    const k1: [16]u8 = @splat(1);
    const k2: [16]u8 = @splat(2);
    const k0: [16]u8 = @splat(0);
    try assertConstantTime(testing.allocator, ctMacCheck, &k1, &k2, 4, .{});
    try testing.expectError(error.TimingLeak, assertConstantTime(testing.allocator, leakyCheck, &k0, &k1, 4, .{}));
    try assertNonInterference(testing.allocator, ctMacCheck, "pub", &k1, &k2, 4, .{});
}

fn parseLenA(input: []const u8, _: []u8) !u32 {
    return std.fmt.parseInt(u32, input, 10);
}

fn parseLenB(input: []const u8, _: []u8) !u32 {
    // Lenient: ignores trailing whitespace, which the other parser rejects.
    return std.fmt.parseInt(u32, std.mem.trimEnd(u8, input, " "), 10);
}

test "differential oracle finds the framing disagreement" {
    var sa: [8]u8 = undefined;
    var sb: [8]u8 = undefined;
    try assertDifferential(u32, "42", &sa, &sb, parseLenA, parseLenB);
    try testing.expectError(error.DifferentialDivergence, assertDifferential(u32, "42 ", &sa, &sb, parseLenA, parseLenB));
}
