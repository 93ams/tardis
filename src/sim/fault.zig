//! Fault plans (plan §5.2): targeted one-shot faults, probabilistic faults,
//! swarm masks, and conversion of an injected error into an operation's
//! error set.

const std = @import("std");
const decide = @import("decide.zig");
const Ppm = decide.Ppm;

pub const OpKind = enum(u8) { open, read, write, sync, metadata, any, connect, accept, net_read, net_write };

pub const FaultClass = enum(u8) {
    io_error,
    short_io,
    latency,
    spurious_wakeup,
    oom,
    torn_write,
    metadata_loss,
    net_reset,
    clock_drift,
    datagram_loss,
};

pub const class_count = @typeInfo(FaultClass).@"enum".field_names.len;

pub const FaultOptions = struct {
    /// Probability that an eligible file operation fails with an I/O error.
    io_error_ppm: Ppm = 0,
    /// Probability that a read or write transfers fewer bytes than asked.
    short_io_ppm: Ppm = 200_000,
    /// Probability that `env.allocator` returns `error.OutOfMemory`.
    oom_ppm: Ppm = 0,
    /// Probability that a futex wait returns without a wake.
    spurious_wakeup_ppm: Ppm = 50_000,
    /// Modeled latency per file operation; both zero disables latency.
    io_latency_min_ns: u64 = 1_000,
    io_latency_max_ns: u64 = 100_000,
    /// On power loss, allow unsynced sectors to tear (otherwise all-or-nothing per file).
    torn_writes: bool = true,
    /// On power loss, allow uncommitted metadata operations to be lost.
    metadata_loss: bool = true,
    /// Probability that a stream read or write finds its connection reset.
    net_reset_ppm: Ppm = 0,
    /// Per-node monotonic clock drift is drawn from `[-max, +max]` ppm.
    clock_drift_ppm_max: u32 = 0,
    /// Probability that a datagram is lost, and that it is delivered twice.
    datagram_loss_ppm: Ppm = 20_000,
    datagram_duplicate_ppm: Ppm = 5_000,
};

pub const Targeted = struct {
    op: OpKind,
    remaining_successes: u32,
    err: anyerror,
};

pub const targeted_max = 16;

pub const Plan = struct {
    options: FaultOptions,
    /// Classes enabled for this iteration (swarm testing).
    enabled: [class_count]bool,
    targeted: [targeted_max]?Targeted,

    pub fn init(options: FaultOptions) Plan {
        return .{
            .options = options,
            .enabled = @splat(true),
            .targeted = @splat(null),
        };
    }

    /// Draws a swarm mask: each class is disabled independently with p = 1/2.
    pub fn drawSwarm(p: *Plan, d: *decide.Decider) void {
        for (&p.enabled) |*e| e.* = d.boolean(.swarm);
    }

    pub fn isEnabled(p: *const Plan, class: FaultClass) bool {
        return p.enabled[@backingInt(class)];
    }

    pub fn addTargeted(p: *Plan, t: Targeted) void {
        for (&p.targeted) |*slot| {
            if (slot.* == null) {
                slot.* = t;
                return;
            }
        }
        @panic("tardis: too many pending targeted faults (max 16)");
    }

    pub fn hasTargeted(p: *const Plan) bool {
        for (p.targeted) |slot| if (slot != null) return true;
        return false;
    }

    pub fn clearTargeted(p: *Plan) void {
        p.targeted = @splat(null);
    }

    /// Called once per eligible operation. Returns an error to inject, if any.
    pub fn takeTargeted(p: *Plan, op: OpKind) ?anyerror {
        for (&p.targeted) |*slot| {
            const t = &(slot.* orelse continue);
            if (t.op != op and t.op != .any) continue;
            if (t.remaining_successes == 0) {
                const err = t.err;
                slot.* = null;
                return err;
            }
            t.remaining_successes -= 1;
        }
        return null;
    }
};

/// Converts `err` into a member of error set `E`. Falls back to `InputOutput`,
/// then `Unexpected`, then the first member of `E`.
pub fn castError(comptime E: type, err: anyerror) E {
    const names = comptime @typeInfo(E).error_set.error_names orelse @compileError("castError needs a concrete error set");
    inline for (names) |name| {
        if (err == @field(anyerror, name)) return @field(E, name);
    }
    if (comptime hasError(E, "InputOutput")) return @field(E, "InputOutput");
    if (comptime hasError(E, "Unexpected")) return @field(E, "Unexpected");
    return @field(E, names[0]);
}

pub fn hasError(comptime E: type, comptime name: []const u8) bool {
    const names = @typeInfo(E).error_set.error_names orelse return false;
    for (names) |n| {
        if (std.mem.eql(u8, n, name)) return true;
    }
    return false;
}

test "targeted fault fires after N successes" {
    var p = Plan.init(.{});
    p.addTargeted(.{ .op = .write, .remaining_successes = 2, .err = error.NoSpaceLeft });
    try std.testing.expect(p.takeTargeted(.read) == null);
    try std.testing.expect(p.takeTargeted(.write) == null);
    try std.testing.expect(p.takeTargeted(.write) == null);
    try std.testing.expect(p.takeTargeted(.write).? == error.NoSpaceLeft);
    try std.testing.expect(p.takeTargeted(.write) == null);
}

test "castError" {
    const E = error{ NoSpaceLeft, InputOutput };
    try std.testing.expectEqual(E.NoSpaceLeft, castError(E, error.NoSpaceLeft));
    try std.testing.expectEqual(E.InputOutput, castError(E, error.AccessDenied));
    const F = error{ Foo, Unexpected };
    try std.testing.expectEqual(F.Unexpected, castError(F, error.AccessDenied));
}
