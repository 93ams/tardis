//! TARDIS: deterministic simulation testing for Zig `std.Io` programs.
//!
//! See `plan.md` for the design. Entry points:
//!
//! * `check(gpa, body, options)`: run `body(*Env)` across many seeds and
//!   personas; report a replayable failure.
//! * `sim(gpa, options)`: the same, as a plain `while (s.step()) |env|` loop.
//! * `Env`: the simulated world handed to the test body (`env.io`, `env.dir`,
//!   `env.allocator`, fault injection, crashes, fuzz input, assertions).

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

pub const Sim = @import("sim/Sim.zig");
/// The seam an optional security layer plugs into (plan2.md §2.2).
pub const sec_seam = @import("sim/sec_seam.zig");
/// `src/sim/sec_default.zig`, or `tardis_sec` under `TARDIS_SEC=1` (seam 4).
const sec_default = @import("tardis_sec_default");
/// True when this build attaches a security layer to every simulator whose
/// options name none (`TARDIS_SEC=1 zig build test`, seam 4).
pub const security_by_default = @TypeOf(sec_default.default_security) != @TypeOf(null);
pub const decide = @import("sim/decide.zig");
pub const fault = @import("sim/fault.zig");
pub const vfs = @import("model/vfs.zig");
pub const fuzz = @import("search/fuzz.zig");
pub const trace = @import("sim/trace.zig");
pub const shrink = @import("search/shrink.zig");
pub const explore = @import("search/explore.zig");
pub const lin = @import("check/lin.zig");
pub const elle = @import("check/elle.zig");
pub const ledger = @import("check/ledger.zig");
const oracle = @import("check/oracle.zig");
const forkserver = @import("sim/forkserver.zig");
const syscalls = @import("sim/syscalls.zig");
const tsc = @import("sim/tsc.zig");

/// Whether `Options.virtual_tsc` answers `rdtsc` on this target (Linux
/// x86_64).
pub const virtual_tsc_supported = tsc.supported;

/// Whether `Options.trap_syscalls` traps on this target (Linux x86_64).
pub const trap_syscalls_supported = syscalls.supported;

/// Whether `Options.fork` forks on this target (Linux; macOS and the BSDs
/// with libc). Elsewhere the same iterations run in-process.
pub const fork_supported = forkserver.supported;
pub const Histogram = ledger.Histogram;
pub const net = @import("model/net.zig");
/// Atomics that the simulator schedules around, with store buffers for
/// weak orderings (`sim/atomic.zig`).
pub const atomic = @import("sim/atomic.zig");
const assert = std.debug.assert;

pub const Persona = vfs.Persona;
pub const CrashMode = vfs.CrashMode;
pub const OpKind = fault.OpKind;
pub const FaultOptions = fault.FaultOptions;
pub const Limits = Sim.Limits;
pub const Ppm = decide.Ppm;
pub const Generator = fuzz.Generator;
pub const NodeId = net.NodeId;
pub const NetOptions = net.Options;

pub const default_campaign_seed: u64 = 0x7A2D_1500_0000_0001;

pub const Options = struct {
    /// Replay exactly this run seed (one iteration per persona). When null,
    /// the `TARDIS_SEED` environment variable is consulted (in tests).
    seed: ?u64 = null,
    /// Seed from which per-iteration run seeds are derived.
    campaign_seed: u64 = default_campaign_seed,
    iterations: u32 = 100,
    personas: []const Persona = &.{.linux_ext4},
    /// Probability of switching tasks at each `std.Io` call.
    preempt_ppm: Ppm = 250_000,
    /// Probability that `io.async` runs the task inline.
    async_inline_ppm: Ppm = 200_000,
    /// Draw a random subset of fault classes per iteration.
    swarm: bool = true,
    faults: FaultOptions = .{},
    limits: Limits = .{},
    /// After a successful body, fail on open handles, live tasks, or live allocations.
    leak_check: bool = true,
    /// Re-run every Nth iteration and compare trace hashes (0 disables).
    determinism_check_every: u32 = 16,
    epoch_offset_ns: u64 = 1_700_000_000 * std.time.ns_per_s,
    /// Simulated nodes, each with its own filesystem, address
    /// (`10.0.0.(n+1)`) and clock. The test body runs on node 0.
    nodes: u8 = 1,
    net: NetOptions = .{},
    /// Print failure reports (seed, recent events, replay command) to stderr.
    /// Disable for tests that expect a failure.
    report: bool = true,
    /// On failure, shrink to the fewest natural decisions that still fail
    /// the same way, and print a replay token (M3).
    shrink: bool = true,
    shrink_runs_max: u32 = 2000,
    /// Decisions recorded per run while shrinking; larger runs are not shrunk.
    shrink_decisions_max: u32 = 1 << 18,
    shrink_report: ?*ShrinkReport = null,
    /// Run this replay token once instead of a campaign (`TARDIS_REPLAY`
    /// does the same from the environment).
    replay: ?[]const u8 = null,
    /// Fuzzy replay: when the token passes as written, try it with its
    /// decisions moved by up to this many draws within their task and
    /// stream (`TARDIS_REPLAY_FUZZY` does the same from the environment).
    /// Code that has changed since the token was made may draw once more
    /// or once less before the decisions that mattered, which moves their
    /// keys; a decision that is moved keeps the value it had. 0: off. The
    /// first failure found is returned, whatever its error: the token does
    /// not say which error it stood for.
    replay_fuzzy: u8 = 0,
    replay_report: ?*ReplayReport = null,
    /// How iterations choose their decisions (M3).
    explore: Explore = .random,
    /// Corpus entries kept by guided exploration.
    corpus_max: u32 = 256,
    explore_report: ?*ExploreReport = null,
    /// Threads for the campaign (M5), each with its own simulator. Results
    /// (which failure is reported, `sometimes` outcomes) do not depend on
    /// thread timing. Guided exploration with several workers runs in
    /// epochs (`epoch_iterations`) and gives the same results for any
    /// number of workers above one.
    workers: u32 = 1,
    /// Guided exploration on several workers: each epoch's iterations are
    /// planned from one corpus snapshot. Smaller epochs feed new coverage
    /// back sooner; larger ones keep more threads busy.
    epoch_iterations: u32 = 64,
    /// A deterministic warm-up run before every iteration's body with a fixed
    /// setup seed (the same state every time); the body then continues with
    /// the iteration's own seed. Lets `fork` reuse one warm-up (M5).
    setup: ?SetupFn = null,
    /// Automatic chaos -> heal schedule (M4): every iteration starts this
    /// nemesis before its body and heals (`Env.heal`) after a drawn duration
    /// of virtual time. The body runs its workload, calls `env.awaitHeal()`,
    /// then checks recovery (for example with `env.eventually`).
    chaos: ?Chaos = null,
    /// Run `setup` once per persona and `fork()` a child per iteration
    /// (Linux; elsewhere the same iterations run in-process with identical
    /// results). Applies to `explore = .random` with `workers = 1`.
    fork: bool = false,
    /// With `setup`, in-process: keep a snapshot of what setup left and
    /// start later iterations from it instead of running setup again, when
    /// setup left only files, clock steps, host names and time passed
    /// (`Sim.Warm`). The iterations are the same either way; false runs
    /// setup every time.
    warm_restore: bool = true,
    warm_report: ?*WarmReport = null,
    /// Fail a run with `error.StraySyscall` when its code makes a real
    /// system call: it asked the kernel for the time, random bytes, a file
    /// or a socket instead of going through `env.io`, so the run no longer
    /// depends on its seed alone. Linux on x86_64 (syscall user dispatch,
    /// Linux 5.11); ignored elsewhere, in forked iterations, in `sim`'s
    /// loop form and on worker threads' setup. `TARDIS_TRAP_SYSCALLS=1` turns it on for every
    /// check of a test run.
    trap_syscalls: bool = false,
    /// Answer `rdtsc` and `rdtscp` with the run's virtual time in
    /// nanoseconds (plus the number of reads so far), so code that times
    /// itself with the processor's counter follows the seed. Linux on
    /// x86_64 (`PR_SET_TSC`); ignored elsewhere, in forked iterations and
    /// in `sim`'s loop form.
    virtual_tsc: bool = false,
    /// An optional security layer such as `tardis_sec` (plan2.md §2.2).
    /// A violation it reports fails the run with `error.SecurityViolation`.
    security: ?sec_seam.Security = null,
    /// Certification campaigns: do not stop at the first failure. Every
    /// failing run is reported, shrunk and logged here (up to
    /// `FailureLog.entries_max`; later ones are counted), the campaign runs
    /// to its last iteration, and `check` then returns the first failure's
    /// error. With `workers > 1` (random exploration) or `fork`, workers and
    /// forked children only note which runs failed; this thread then re-runs,
    /// reports, shrinks and logs the lowest `FailureLog.entries_max` of them
    /// in iteration order, so the log is the same for any number of workers.
    /// Guided exploration on several workers still stops at the first
    /// failure.
    keep_going: ?*FailureLog = null,
};

/// `Options.keep_going`: the failures of a campaign that ran to the end.
pub const FailureLog = struct {
    pub const entries_max = 32;
    pub const token_bytes_max = 1024;

    pub const Entry = struct {
        iteration: u32,
        persona: Persona,
        seed: u64,
        err: anyerror,
        /// The token pins the shrunk run (else the run as found).
        shrunk: bool,
        token_buf: [token_bytes_max]u8,
        token_len: u16,

        pub fn token(e: *const Entry) []const u8 {
            return e.token_buf[0..e.token_len];
        }
    };

    entries: [entries_max]Entry = undefined,
    len: u32 = 0,
    /// Failing runs beyond `entries_max`: counted, not shrunk or logged.
    dropped: u32 = 0,

    pub fn slice(l: *const FailureLog) []const Entry {
        return l.entries[0..l.len];
    }

    pub fn failures(l: *const FailureLog) u32 {
        return l.len + l.dropped;
    }

    /// The logged failure of the run with this seed.
    pub fn bySeed(l: *const FailureLog, seed: u64) ?*const Entry {
        for (l.slice()) |*e| if (e.seed == seed) return e;
        return null;
    }
};

var trap_env: std.atomic.Value(u8) = .init(0); // 0 unknown, 1 off, 2 on

fn trapSyscallsFromEnv() bool {
    if (!builtin.is_test or !syscalls.supported) return false;
    switch (trap_env.load(.monotonic)) {
        1 => return false,
        2 => return true,
        else => {},
    }
    const a = std.heap.page_allocator;
    const on = if (std.testing.environ.getAlloc(a, "TARDIS_TRAP_SYSCALLS")) |text| blk: {
        defer a.free(text);
        break :blk std.mem.eql(u8, text, "1");
    } else |_| false;
    trap_env.store(if (on) 2 else 1, .monotonic);
    return on;
}

fn simConfig(o: Options) Sim.Config {
    return .{
        .preempt_ppm = o.preempt_ppm,
        .async_inline_ppm = o.async_inline_ppm,
        .swarm = o.swarm,
        .trap_syscalls = o.trap_syscalls or trapSyscallsFromEnv(),
        .virtual_tsc = o.virtual_tsc,
        .faults = o.faults,
        .limits = o.limits,
        .epoch_offset_ns = o.epoch_offset_ns,
        .nodes = o.nodes,
        .net = o.net,
        .report = o.report,
        .security = o.security orelse sec_default.default_security,
    };
}

/// Run seed for iteration `i`, persona index `p`.
pub fn runSeed(campaign_seed: u64, iteration: u32, persona_index: usize) u64 {
    return decide.mix(campaign_seed +% @as(u64, iteration) *% decide.golden_gamma, persona_index);
}

pub const Error = error{
    Deadlock,
    ResourceLeak,
    NonDeterministic,
    SometimesNeverTrue,
    AssertionFailed,
    FibersUnsupported,
};

/// The simulated world handed to a test body.
pub const Env = struct {
    sim: *Sim,
    io: std.Io,
    /// Root of the virtual filesystem. Valid across crashes.
    dir: std.Io.Dir,
    /// Volatile SUT heap: wiped on every crash and iteration; may inject OOM.
    allocator: Allocator,
    seed: u64,
    persona: Persona,
    iteration: u32,

    fn init(s: *Sim, iteration: u32) Env {
        return .{
            .sim = s,
            .io = s.io(),
            .dir = Sim.rootDir(),
            .allocator = s.nodes[0].heap.allocator(),
            .seed = s.seed,
            .persona = s.persona,
            .iteration = iteration,
        };
    }

    /// Generates a value of type `T` (structure-aware; see `fuzz.zig`).
    /// Slices are freed automatically at the end of the iteration.
    pub fn fuzz(env: *Env, comptime T: type) !T {
        var g = env.sim.generator();
        return g.value(T);
    }

    /// Simulates a crash and restart. Every task except the caller is dropped,
    /// open handles are invalidated, `env.allocator` is wiped, and the
    /// filesystem keeps only what `mode` lets survive.
    pub fn crashAndReboot(env: *Env, mode: CrashMode) !void {
        env.sim.crashAndReboot(mode);
    }

    /// The next `successes` operations of kind `op` succeed; the one after
    /// fails with `err` (converted into that operation's error set).
    pub fn injectIoErrorAfter(env: *Env, op: OpKind, successes: u32, err: anyerror) void {
        env.sim.plan.addTargeted(.{ .op = op, .remaining_successes = successes, .err = err });
    }

    /// Sleeps the caller for `delta_ns` of virtual time (other tasks run).
    pub fn advanceTimeNs(env: *Env, delta_ns: u64) !void {
        env.sim.advanceTime(delta_ns);
    }

    pub fn nowNs(env: *const Env) u64 {
        return env.sim.now_ns;
    }

    pub fn crashCount(env: *const Env) u32 {
        return env.sim.crash_count;
    }

    /// Fails if any handle (other than `env.dir`), task (other than the
    /// caller), or `env.allocator` allocation is still live.
    pub fn expectNoLeaks(env: *Env) !void {
        return expectNoLeaksExcluding(env.sim, 0);
    }

    /// Records that `cond` held at least once across the campaign is required.
    pub fn sometimes(env: *Env, comptime name: []const u8, cond: bool) void {
        env.sim.catalog.sometimes(name, cond);
        if (cond) env.sim.cover(explore.labelHash(name));
    }

    // --- chaos, liveness, cost ledger (M4) ----------------------------------

    /// Starts a nemesis: a background task that, every
    /// `[interval_min_ns, interval_max_ns]` of virtual time, partitions or
    /// isolates nodes, crashes nodes other than 0 (calling `restart`), steps
    /// clocks, or heals everything. Its choices are ordinary decisions, so
    /// failures under chaos replay and shrink. Stop it with `heal`.
    pub fn startChaos(env: *Env, nemesis: Nemesis) !void {
        const s = env.sim;
        s.chaos_active = true;
        s.chaos_generation +%= 1;
        try env.spawnOn(0, nemesisLoop, .{ env, nemesis, s.chaos_generation });
    }

    /// Ends chaos: stops the nemesis, heals every link, and turns off every
    /// probabilistic fault class, so the system can be checked for recovery
    /// with `eventually`.
    pub fn heal(env: *Env) void {
        const s = env.sim;
        s.chaos_active = false;
        env.healAll();
        s.plan.enabled = @splat(false);
        s.trace.record(s.now_ns, s.current, .note, 0, 0, 0, "heal");
    }

    /// Returns once chaos has healed: immediately if no chaos is active, at
    /// the drawn heal time under `Options.chaos`, or (after a manual
    /// `startChaos`) when the test calls `heal` from another task.
    pub fn awaitHeal(env: *Env) !void {
        const s = env.sim;
        while (s.chaos_active) {
            const wait = if (s.heal_at_ns > s.now_ns) s.heal_at_ns - s.now_ns else std.time.ns_per_ms;
            try env.io.sleep(.fromNanoseconds(wait), .awake);
        }
    }

    /// Polls `predicate(ctx)` every 10 ms of virtual time until it returns
    /// true. If it has not within `timeout_ns`, fails like `always(name, false)`.
    /// The predicate may do I/O; an error counts as "not yet".
    pub fn eventually(env: *Env, comptime name: []const u8, timeout_ns: u64, ctx: anytype, comptime predicate: fn (@TypeOf(ctx)) anyerror!bool) !void {
        const deadline = env.nowNs() + timeout_ns;
        while (true) {
            if (predicate(ctx) catch false) {
                env.sim.catalog.sometimes(name, true);
                return;
            }
            if (env.nowNs() >= deadline) return env.always(name, false);
            try env.io.sleep(.fromMilliseconds(10), .awake);
        }
    }

    /// Cost counters for this run so far.
    pub fn stats(env: *const Env) Sim.Stats {
        return env.sim.stats;
    }

    /// Bytes written to media so far (whole pages flushed by fsync, rename
    /// flushes and crashes), on every node. Compare with
    /// `stats().disk_write_bytes` for write amplification.
    pub fn flushedBytes(env: *const Env) u64 {
        var pages: u64 = 0;
        for (env.sim.nodes) |*n| pages += n.vfs.flushed_pages;
        return pages * vfs.page_bytes;
    }

    /// A coverage point for guided exploration (`Options.explore = .guided`):
    /// each distinct `(name, value)` reached counts as new behaviour, so a
    /// run reaching it is kept and mutated further. Use small, meaningful
    /// values (a protocol state, a depth, a phase), not raw data. No effect
    /// under random exploration.
    pub fn cover(env: *Env, comptime name: []const u8, value: u64) void {
        env.sim.cover(decide.mix(explore.labelHash(name), value));
    }

    /// Fails the iteration with `error.AssertionFailed` if `cond` is false.
    pub fn always(env: *Env, comptime name: []const u8, cond: bool) !void {
        if (env.sim.catalog.always(name, cond)) return;
        env.sim.trace.record(env.sim.now_ns, env.sim.current, .assertion, 0, 0, 0, name);
        if (env.sim.config.report) std.debug.print("tardis: always(\"{s}\") failed\n", .{name});
        return error.AssertionFailed;
    }

    // --- nodes and network (M2) ---------------------------------------------

    /// Node `node`'s volatile heap (node 0's is `env.allocator`). Give each
    /// daemon its own node's allocator: it is wiped when that node crashes,
    /// and leak-checked when no daemon is left on the node.
    pub fn nodeAllocator(env: *Env, node: NodeId) Allocator {
        return env.sim.nodes[node].heap.allocator();
    }

    pub fn nodeCount(env: *const Env) u8 {
        return @intCast(env.sim.nodes.len);
    }

    /// The address of `node` (`10.0.0.(node+1)`) at `port`.
    pub fn address(env: *const Env, node: NodeId, port: u16) std.Io.net.IpAddress {
        assert(node < env.sim.nodes.len);
        return .{ .ip4 = .{ .bytes = net.Net.nodeAddress(node), .port = port } };
    }

    /// Runs `function(args...)` as a daemon task on `node`: its `std.Io`
    /// calls use that node's filesystem, address and clock. Daemons are not
    /// awaited; they end when they return, when their node crashes, or at
    /// the end of the iteration. A daemon that returns an error (other than
    /// `error.Canceled`) fails the iteration under `check`.
    pub fn spawnOn(env: *Env, node: NodeId, comptime function: anytype, args: std.meta.ArgsTuple(@TypeOf(function))) !void {
        const Args = @TypeOf(args);
        const Wrapper = struct {
            fn start(context: *const anyopaque) void {
                const a: *const Args = @ptrCast(@alignCast(context));
                const R = @typeInfo(@TypeOf(function)).@"fn".return_type.?;
                switch (@typeInfo(R)) {
                    .error_union => @call(.auto, function, a.*) catch |err| {
                        if (@as(anyerror, err) != error.Canceled) Sim.active().daemonFailed(err);
                    },
                    else => _ = @call(.auto, function, a.*),
                }
            }
        };
        try env.sim.spawnDaemon(node, Wrapper.start, std.mem.asBytes(&args), .of(Args));
    }

    /// Crashes and reboots one node (see `Sim.crashNode`). Other nodes keep
    /// running; their connections to `node` reset or time out.
    pub fn crashNode(env: *Env, node: NodeId, mode: CrashMode) void {
        env.sim.crashNode(node, mode);
    }

    pub fn nodeCrashCount(env: *const Env, node: NodeId) u32 {
        return env.sim.nodes[node].crash_count;
    }

    /// Cuts the directed link `from -> to` (an asymmetric partition).
    pub fn cutLink(env: *Env, from: NodeId, to: NodeId) void {
        env.sim.setLink(from, to, false);
    }

    pub fn healLink(env: *Env, from: NodeId, to: NodeId) void {
        env.sim.setLink(from, to, true);
    }

    /// Cuts both directions between `a` and `b`.
    pub fn partition(env: *Env, a: NodeId, b: NodeId) void {
        env.sim.setLink(a, b, false);
        env.sim.setLink(b, a, false);
    }

    /// Cuts `node` off from every other node, both directions.
    pub fn isolate(env: *Env, node: NodeId) void {
        for (0..env.sim.nodes.len) |i| {
            const other: NodeId = @intCast(i);
            if (other == node) continue;
            env.partition(node, other);
        }
    }

    /// Heals every link.
    pub fn healAll(env: *Env) void {
        for (0..env.sim.nodes.len) |a| {
            for (0..env.sim.nodes.len) |b| env.sim.setLink(@intCast(a), @intCast(b), true);
        }
    }

    /// Steps `node`'s real-time clock (an NTP step; monotonic clocks are
    /// unaffected).
    pub fn stepClock(env: *Env, node: NodeId, delta_ns: i64) void {
        env.sim.stepClock(node, delta_ns);
    }

    /// Registers `name` in virtual DNS. `node<N>` and `localhost` always resolve.
    pub fn addHost(env: *Env, name: []const u8, node: NodeId) void {
        env.sim.addHost(name, node);
    }

    /// First error returned by a daemon this iteration, if any. `check`
    /// fails the iteration with it; `sim` users should check it themselves.
    pub fn daemonError(env: *const Env) ?anyerror {
        env.sim.touchGlobal(); // any task's failure sets it
        return env.sim.daemon_error;
    }
};

pub const Chaos = struct {
    nemesis: Nemesis = .{},
    /// Chaos lasts a duration drawn from this range, then heals. The draw is
    /// an ordinary decision: shrinking pulls it to `duration_min_ns`.
    duration_min_ns: u64 = 500 * std.time.ns_per_ms,
    duration_max_ns: u64 = 5 * std.time.ns_per_s,
};

/// Starts `Options.chaos`, if set, and the task that heals it.
fn startAutoChaos(env: *Env) !void {
    const s = env.sim;
    const c = s.auto_chaos orelse return;
    const d = s.decider.range(.fault, c.duration_min_ns, @max(c.duration_min_ns, c.duration_max_ns));
    try env.startChaos(c.nemesis);
    s.heal_at_ns = s.now_ns + d;
    try env.spawnOn(0, healer, .{ env, s.chaos_generation, d });
}

fn healer(env: *Env, generation: u32, duration_ns: u64) !void {
    try env.io.sleep(.fromNanoseconds(duration_ns), .awake);
    const s = env.sim;
    if (s.chaos_active and s.chaos_generation == generation) env.heal();
}

pub const Nemesis = struct {
    interval_min_ns: u64 = 10 * std.time.ns_per_ms,
    interval_max_ns: u64 = 200 * std.time.ns_per_ms,
    partitions: bool = true,
    crashes: bool = false,
    clock_steps: bool = false,
    /// Called on the nemesis task right after it crashes `node`, to restart
    /// that node's services (for example with `env.spawnOn`).
    restart: ?*const fn (env: *Env, node: NodeId) anyerror!void = null,
};

fn nemesisLoop(env: *Env, n: Nemesis, generation: u32) !void {
    const s = env.sim;
    const nodes: u64 = s.nodes.len;
    while (true) {
        const d = s.decider.range(.fault, n.interval_min_ns, @max(n.interval_min_ns, n.interval_max_ns));
        try env.io.sleep(.fromNanoseconds(d), .awake);
        if (!s.chaos_active or s.chaos_generation != generation) return;
        // Action 0 (the benign decision) heals.
        switch (s.decider.uniform(.fault, 5)) {
            0 => env.healAll(),
            1 => if (n.partitions and nodes >= 2) {
                const a: NodeId = @intCast(s.decider.uniform(.fault, nodes));
                const b: NodeId = @intCast((a + 1 + s.decider.uniform(.fault, nodes - 1)) % nodes);
                env.partition(a, b);
            },
            2 => if (n.partitions and nodes >= 2) env.isolate(@intCast(s.decider.uniform(.fault, nodes))),
            3 => if (n.crashes and nodes >= 2) {
                const node: NodeId = @intCast(1 + s.decider.uniform(.fault, nodes - 1));
                env.crashNode(node, if (s.decider.boolean(.fault)) .power_loss else .process_crash);
                if (n.restart) |r| try r(env, node);
            },
            4 => if (n.clock_steps) {
                const node: NodeId = @intCast(s.decider.uniform(.fault, nodes));
                const step: i64 = @as(i64, @intCast(s.decider.range(.fault, 0, 2 * std.time.ns_per_s))) - std.time.ns_per_s;
                env.stepClock(node, step);
            },
            else => unreachable,
        }
    }
}

fn expectNoLeaksExcluding(s: *Sim, exclude: Sim.TaskId) !void {
    const r = s.leaks(exclude);
    if (!r.any()) return;
    if (s.config.report) {
        std.debug.print("tardis: leak check failed: {d} live task(s), {d} open handle(s), {d} live allocation(s)\n", .{
            r.tasks, r.handles, r.allocations,
        });
    }
    return error.ResourceLeak;
}

/// Generates fuzz input from a TARDIS `io`. Panics if `io` is not simulated.
pub fn fuzzInput(comptime T: type, io: std.Io) !T {
    const s = Sim.fromIo(io) orelse @panic("tardis.fuzzInput: io is not a TARDIS io");
    var g = s.generator();
    return g.value(T);
}

/// Campaign-wide reachability assertion; see `Env.sometimes`.
pub fn assertSometimes(io: std.Io, comptime name: []const u8, cond: bool) void {
    const s = Sim.fromIo(io) orelse return;
    s.catalog.sometimes(name, cond);
}

/// Returns true if `io` is a TARDIS simulated io.
pub fn isSimulated(io: std.Io) bool {
    return Sim.fromIo(io) != null;
}

// ===========================================================================
// check

const Replay = struct { seed: ?u64, persona: ?Persona };

/// Long campaigns without editing tests (plan3.md I1), in tests only:
/// `TARDIS_CAMPAIGN_SALT=<number>` gives every `check` other seeds than
/// its usual ones (a nightly job passes a new number each night), and
/// `TARDIS_ITERATIONS_SCALE=<n>` multiplies its iterations. A failure's
/// replay lines name the seed itself, so they work without either.
fn campaignFromEnv(gpa: Allocator, o: *Options) void {
    if (!builtin.is_test) return;
    if (std.testing.environ.getAlloc(gpa, "TARDIS_CAMPAIGN_SALT")) |text| {
        defer gpa.free(text);
        if (std.fmt.parseInt(u64, std.mem.trim(u8, text, " \t\r\n"), 0)) |salt| {
            o.campaign_seed = decide.mix(o.campaign_seed, salt);
        } else |_| std.debug.print("tardis: ignoring unparsable TARDIS_CAMPAIGN_SALT=\"{s}\"\n", .{text});
    } else |_| {}
    if (std.testing.environ.getAlloc(gpa, "TARDIS_ITERATIONS_SCALE")) |text| {
        defer gpa.free(text);
        if (std.fmt.parseInt(u32, std.mem.trim(u8, text, " \t\r\n"), 0)) |scale| {
            o.iterations *|= @max(scale, 1);
        } else |_| std.debug.print("tardis: ignoring unparsable TARDIS_ITERATIONS_SCALE=\"{s}\"\n", .{text});
    } else |_| {}
}

fn replayFromEnv(gpa: Allocator) Replay {
    var r: Replay = .{ .seed = null, .persona = null };
    if (!builtin.is_test) return r;
    if (std.testing.environ.getAlloc(gpa, "TARDIS_SEED")) |text| {
        defer gpa.free(text);
        r.seed = std.fmt.parseInt(u64, std.mem.trim(u8, text, " \t\r\n"), 0) catch blk: {
            std.debug.print("tardis: ignoring unparsable TARDIS_SEED=\"{s}\"\n", .{text});
            break :blk null;
        };
    } else |_| {}
    if (std.testing.environ.getAlloc(gpa, "TARDIS_PERSONA")) |text| {
        defer gpa.free(text);
        r.persona = std.meta.stringToEnum(Persona, std.mem.trim(u8, text, " \t\r\n"));
    } else |_| {}
    return r;
}

const RunOutcome = struct {
    result: anyerror!void,
    trace_hash: u64,
    /// For `error.SecurityViolation`: the security layer's key for the
    /// run's first finding (seam 4), 0 otherwise.
    finding: u64 = 0,
};

pub const SetupFn = *const fn (env: *Env) anyerror!void;

/// Runs `Options.setup` (if any) and switches to the iteration's seed.
fn applySetup(s: *Sim, options: Options) void {
    s.auto_chaos = options.chaos;
    const f = options.setup orelse return;
    s.setup_fn = f;
    s.setup_seed = decide.mix(options.campaign_seed, 0x5E70_5E70_5E70_5E70);
    s.warm.enabled = options.warm_restore;
}

fn runSetup(env: *Env) !void {
    const p = env.sim.setup_fn orelse return;
    const setup: SetupFn = @ptrCast(@alignCast(p));
    // Later iterations start from a snapshot of what setup left, when
    // that is all it left (`Sim.Warm`).
    if (!env.sim.warmRestore()) {
        try setup(env);
        env.sim.warmCapture();
    }
    env.sim.reseed(env.seed);
}

fn BodyThunk(comptime body: fn (*Env) anyerror!void) type {
    return struct {
        fn call(ctx: *anyopaque) anyerror!void {
            const env: *Env = @ptrCast(@alignCast(ctx));
            try runSetup(env);
            try startAutoChaos(env);
            return body(env);
        }
    };
}

fn runOnce(s: *Sim, comptime body: fn (*Env) anyerror!void, seed: u64, persona: Persona, iteration: u32, leak_check: bool) RunOutcome {
    s.beginRun(s.setup_seed orelse seed, persona);
    s.iteration = iteration;
    var env = Env.init(s, iteration);
    env.seed = seed;
    // The counter first and last: arming it is a system call.
    const virtual_counter = s.config.virtual_tsc and tsc.begin(&s.now_ns);
    const trapping = s.config.trap_syscalls and syscalls.begin();
    const r = s.drive(BodyThunk(body).call, &env);
    const stray = if (trapping) syscalls.end() else null;
    if (virtual_counter) _ = tsc.end();
    s.secEndRun();
    var result = r.outcome;
    if (stray) |call| {
        if (s.config.report) std.debug.print("tardis: the code under test made {d} real system call(s), the first one {s} (number {d}): it left the simulation, so the run does not depend on its seed alone\n", .{ call.count, syscalls.name(call.number), call.number });
        if (result) |_| result = error.StraySyscall else |_| {}
    }
    if (result) |_| {
        if (s.daemon_error) |err| {
            if (s.config.report and err != error.SecurityViolation) std.debug.print("tardis: a daemon task failed with error.{s}\n", .{@errorName(err)});
            result = err;
        }
    } else |_| {}
    if (result) |_| {
        if (leak_check) result = expectNoLeaksExcluding(s, r.control);
    } else |_| {}
    const hash = s.trace.hash;
    // Fold the outcome in so a different error is a different trace.
    const outcome_word: u64 = if (result) |_| 0 else |err| @intFromError(err);
    const finding: u64 = if (result) |_| 0 else |err| if (err == error.SecurityViolation) s.secFindingKey() else 0;
    s.endRun();
    return .{ .result = result, .trace_hash = decide.mix(hash, outcome_word), .finding = finding };
}

fn reportFailure(s: *Sim, err: anyerror, iteration: u32, iterations: u32, seed: u64, persona: Persona, forced: []const decide.Forced) void {
    if (!s.config.report) return;
    std.debug.print(
        \\
        \\tardis: FAILED  iteration {d}/{d}  persona={s}  seed=0x{x:0>16}
        \\tardis: error.{s}
        \\
    , .{ iteration + 1, iterations, @tagName(persona), seed, @errorName(err) });
    s.trace.dump(16);
    if (forced.len == 0) {
        std.debug.print("tardis: replay with:  TARDIS_SEED=0x{x:0>16} TARDIS_PERSONA={s} zig build test\n\n", .{ seed, @tagName(persona) });
        return;
    }
    var buf: [ShrinkReport.token_bytes_max]u8 = undefined;
    if (shrink.formatToken(&buf, @tagName(persona), seed, null, forced)) |t| {
        std.debug.print("tardis: replay with:  TARDIS_REPLAY={s} zig build test\n\n", .{t});
    }
}

// ===========================================================================
// Shrinking and replay tokens (M3)

/// Filled by `check` when it shrinks a failure (for tests and tooling).
pub const ShrinkReport = struct {
    /// Decisions with their natural (or forced) value in the failing run.
    before: usize = 0,
    /// ... and after shrinking.
    after: usize = 0,
    runs: u32 = 0,
    /// Kept decisions whose value was lowered (`shrink.minimizeValues`).
    values: usize = 0,
    /// False if shrinking was skipped (failure did not reproduce, too many
    /// decisions, or shrinking disabled).
    shrunk: bool = false,
    token_buf: [token_bytes_max]u8 = undefined,
    token_len: usize = 0,

    pub const token_bytes_max = 16 * 1024;

    pub fn token(r: *const ShrinkReport) []const u8 {
        return r.token_buf[0..r.token_len];
    }
};

/// Runs `body` once with a shrink candidate's overlay and recorder installed.
/// Returns true if it failed with `target` and, for a security violation,
/// with the same finding (`finding`, seam 4): a candidate that trades one
/// CWE for another is a different bug, not a smaller one.
fn runCandidate(s: *Sim, comptime body: fn (*Env) anyerror!void, seed: u64, persona: Persona, c: shrink.Candidate, target: anyerror, finding: u64, leak_check: bool) bool {
    const overlay: decide.Overlay = .{ .keep = c.keep, .forced = c.forced };
    s.overlay = &overlay;
    s.recorder = c.recorder;
    defer {
        s.overlay = null;
        s.recorder = null;
    }
    const out = runOnce(s, body, seed, persona, 0, leak_check);
    if (out.result) |_| return false else |err| return err == target and out.finding == finding;
}

/// Fills `report` from a finished shrinker and prints it (the shrunk run
/// must have just been re-run, so the trace ring shows it).
fn reportShrunk(s: *Sim, sh: *shrink.Shrinker, persona: Persona, seed: u64, report: *ShrinkReport, print: bool) void {
    report.before = sh.before;
    report.after = sh.keep().len;
    report.values = sh.lowered;
    report.runs = sh.runs;
    report.shrunk = true;
    if (shrink.formatToken(&report.token_buf, @tagName(persona), seed, sh.keep(), sh.forcedResult())) |t| report.token_len = t.len;
    if (!print) return;
    std.debug.print("tardis: shrunk {d} -> {d} decisions and lowered {d} values in {d} runs (every other decision is benign: no fault, no preemption, nothing lost in a crash, minimal input)\n", .{ report.before, report.after, report.values, report.runs });
    s.trace.dump(16);
    if (report.token_len > 0) {
        std.debug.print("tardis: replay the shrunk run with:  TARDIS_REPLAY={s} zig build test\n\n", .{report.token()});
    } else {
        std.debug.print("tardis: the shrunk replay token is too long to print\n\n", .{});
    }
}

/// Shrinks the failure `target` of `(seed, persona, forced)` and prints it.
fn shrinkAndReport(gpa: Allocator, s: *Sim, comptime body: fn (*Env) anyerror!void, seed: u64, persona: Persona, forced: []const decide.Forced, target: anyerror, options: Options) void {
    var report: ShrinkReport = .{};
    defer if (options.shrink_report) |r| {
        r.* = report;
    };
    if (!options.shrink) return;
    const was_rerun = s.rerun;
    s.rerun = true;
    defer s.rerun = was_rerun;
    const print = s.config.report;
    s.config.report = false;
    defer s.config.report = print;

    // Record every decision of the failing run.
    const rec_buf = gpa.alloc(u64, options.shrink_decisions_max) catch return;
    defer gpa.free(rec_buf);
    var rec = decide.Recorder.init(rec_buf);
    const as_found: decide.Overlay = .{ .forced = forced };
    s.overlay = if (forced.len > 0) &as_found else null;
    s.recorder = &rec;
    const natural = runOnce(s, body, seed, persona, 0, options.leak_check);
    s.overlay = null;
    s.recorder = null;
    const ok = if (natural.result) |_| false else |err| err == target;
    if (!ok or rec.overflowed) {
        if (print) std.debug.print("tardis: not shrinking ({s})\n\n", .{if (rec.overflowed) "too many decisions; raise shrink_decisions_max" else "the failure did not reproduce"});
        return;
    }

    var sh = shrink.Shrinker.init(gpa, rec.keys[0..rec.len], forced, options.shrink_runs_max, options.shrink_decisions_max) catch return;
    defer sh.deinit();
    // The finding of the run as found: candidates must reproduce it.
    const finding = natural.finding;
    while (sh.next()) |c| sh.result(runCandidate(s, body, seed, persona, c, target, finding, options.leak_check));

    // Re-run the shrunk case so the trace ring shows it.
    rec = decide.Recorder.init(rec_buf);
    _ = runCandidate(s, body, seed, persona, .{ .keep = sh.keep(), .forced = sh.forcedResult(), .recorder = &rec }, target, finding, options.leak_check);
    reportShrunk(s, &sh, persona, seed, &report, print);
}

/// What warm starts did on the calling thread's simulator
/// (`Options.warm_report`).
pub const WarmReport = struct {
    /// Iterations started from the snapshot instead of running setup.
    restores: u64 = 0,
    /// Setups re-run to compare their result with the snapshot.
    checks: u64 = 0,
    /// Comparisons that differed (warm starts then stop).
    mismatches: u64 = 0,
    /// A snapshot was in use when the campaign ended.
    active: bool = false,
};

/// What a token replay did (`Options.replay_report`).
pub const ReplayReport = struct {
    /// The token failed only with decisions moved (fuzzy replay).
    fuzzy: bool = false,
    /// Decisions moved, and by how many draws.
    moved: u32 = 0,
    shift: i16 = 0,
    /// Runs made, the first one included.
    runs: u32 = 0,
    /// The token that fails on the current code, when one was found.
    token_buf: [ShrinkReport.token_bytes_max]u8 = undefined,
    token_len: usize = 0,

    pub fn token(r: *const ReplayReport) []const u8 {
        return r.token_buf[0..r.token_len];
    }
};

const fuzzy_runs_max = 256;

/// The token passed as written. Resolves each kept key to its task, stream
/// and counter, and re-runs with keys moved by `-delta..delta` draws: all
/// of them, then those of one (stream, task), then that pair's keys from
/// one counter on (an edit in the middle of a task). Returns the error of
/// the first run that fails.
fn fuzzyReplay(gpa: Allocator, s: *Sim, comptime body: fn (*Env) anyerror!void, tok: *const shrink.Token, persona: Persona, anchors: *const decide.Anchors, options: Options, delta: u8, report: *ReplayReport) !void {
    const keys = tok.keep orelse return;
    if (keys.len == 0) return;
    const resolved = try gpa.alloc(?decide.Anchors.Resolved, keys.len);
    defer gpa.free(resolved);
    var any = false;
    for (keys, resolved) |k, *r| {
        r.* = anchors.resolve(k, @as(u32, delta) + 64);
        any = any or r.* != null;
    }
    if (!any) return;
    const keep = try gpa.alloc(u64, keys.len);
    defer gpa.free(keep);
    const forced = try gpa.alloc(decide.Forced, tok.forced.len + keys.len);
    defer gpa.free(forced);
    const base: decide.Overlay = .{ .forced = tok.forced };

    // scope: 0 all keys; 1 one anchor; 2 one anchor from a counter on.
    var scope: u2 = 0;
    while (scope < 3) : (scope += 1) {
        var target: usize = 0;
        const targets = if (scope == 0) 1 else keys.len;
        while (target < targets) : (target += 1) {
            const at = resolved[target] orelse continue;
            if (scope == 1) {
                // Once per anchor: at its first key.
                const first = for (resolved[0..target]) |r| {
                    if (r != null and r.?.anchor == at.anchor) break false;
                } else true;
                if (!first) continue;
            }
            var step: i16 = 1;
            while (step <= delta) : (step += 1) {
                for ([_]i16{ step, -step }) |d| {
                    var forced_len: usize = 0;
                    var moved: u32 = 0;
                    var ok = true;
                    for (keys, resolved, 0..) |k, r, i| {
                        keep[i] = k;
                        const value = base.forcedValue(k);
                        const selected = if (r) |x| switch (scope) {
                            0 => true,
                            1 => x.anchor == at.anchor,
                            else => x.anchor == at.anchor and x.counter >= at.counter,
                        } else false;
                        if (selected) {
                            const x = r.?;
                            const counter = @as(i64, x.counter) + d;
                            if (counter < 0) {
                                ok = false;
                                break;
                            }
                            const a = anchors.slice()[x.anchor];
                            keep[i] = decide.decisionKey(a.stream, a.path, @intCast(counter));
                            // The decision keeps the value it had.
                            forced[forced_len] = .{ .key = keep[i], .value = value orelse decide.splitmix64(a.state ^ k) };
                            forced_len += 1;
                            moved += 1;
                        } else if (value) |v| {
                            forced[forced_len] = .{ .key = k, .value = v };
                            forced_len += 1;
                        }
                    }
                    if (!ok or moved == 0) continue;
                    if (shrink.sortUnique(keep) != keys.len) continue; // a moved key met another
                    std.mem.sort(decide.Forced, forced[0..forced_len], {}, shrink.forcedLess);
                    if (report.runs >= fuzzy_runs_max) return;
                    report.runs += 1;
                    const overlay: decide.Overlay = .{ .keep = keep, .forced = forced[0..forced_len] };
                    s.overlay = &overlay;
                    const out = runOnce(s, body, tok.seed, persona, 0, options.leak_check);
                    s.overlay = null;
                    out.result catch |err| {
                        report.fuzzy = true;
                        report.moved = moved;
                        report.shift = d;
                        if (shrink.formatToken(&report.token_buf, tok.persona, tok.seed, keep, forced[0..forced_len])) |t| report.token_len = t.len;
                        if (s.config.report) {
                            std.debug.print("\ntardis: FAILED  replay token, with {d} of its {d} decisions moved by {d} draws (the code draws differently than when the token was made)\ntardis: error.{s}\n", .{ moved, keys.len, d, @errorName(err) });
                            s.trace.dump(32);
                            if (report.token_len > 0) std.debug.print("tardis: the token for this code:  TARDIS_REPLAY={s} zig build test\n\n", .{report.token()});
                        }
                        return err;
                    };
                }
            }
        }
    }
}

fn replayFuzzyFromEnv(gpa: Allocator) u8 {
    if (!builtin.is_test) return 0;
    const text = std.testing.environ.getAlloc(gpa, "TARDIS_REPLAY_FUZZY") catch return 0;
    defer gpa.free(text);
    return std.fmt.parseInt(u8, std.mem.trim(u8, text, " \t\r\n"), 10) catch 0;
}

/// Runs a replay token (`TARDIS_REPLAY` or `Options.replay`) once.
fn runToken(gpa: Allocator, s: *Sim, comptime body: fn (*Env) anyerror!void, text: []const u8, options: Options) !void {
    var tok = shrink.parseToken(gpa, text) catch {
        if (s.config.report) std.debug.print("tardis: unparsable replay token \"{s}\"\n", .{text});
        return error.BadReplayToken;
    };
    defer tok.deinit(gpa);
    const persona = std.meta.stringToEnum(Persona, tok.persona) orelse return error.BadReplayToken;
    var local_report: ReplayReport = .{};
    const report = options.replay_report orelse &local_report;
    report.* = .{ .runs = 1 };
    const delta = if (options.replay_fuzzy != 0) options.replay_fuzzy else replayFuzzyFromEnv(gpa);
    var anchor_buf: [512]decide.Anchors.Anchor = undefined;
    var anchors = decide.Anchors.init(&anchor_buf);
    const overlay = tok.overlay();
    s.overlay = &overlay;
    s.anchors = if (delta != 0) &anchors else null;
    const out = runOnce(s, body, tok.seed, persona, 0, options.leak_check);
    s.overlay = null;
    s.anchors = null;
    out.result catch |err| {
        if (s.config.report) {
            std.debug.print("\ntardis: FAILED  replay token  persona={s}  seed=0x{x:0>16}\ntardis: error.{s}\n", .{ tok.persona, tok.seed, @errorName(err) });
            s.trace.dump(32);
        }
        return err;
    };
    if (delta != 0) try fuzzyReplay(gpa, s, body, &tok, persona, &anchors, options, delta, report);
}

fn replayTokenFromEnv(gpa: Allocator) ?[]u8 {
    if (!builtin.is_test) return null;
    return std.testing.environ.getAlloc(gpa, "TARDIS_REPLAY") catch null;
}

// ===========================================================================
// Guided exploration (M3)

pub const Explore = enum {
    /// Every iteration uses a fresh seed.
    random,
    /// Runs that reach new coverage join a corpus; half the iterations
    /// mutate a corpus entry instead of using a fresh seed (see explore.zig).
    guided,
};

/// Filled by `check` when `explore == .guided` (for tests and tooling).
pub const ExploreReport = struct {
    corpus: usize = 0,
    /// Coverage bits set by the whole campaign.
    features: u32 = 0,
    mutated_runs: u32 = 0,
    /// Comparison constants the security layer reported (§7.1 of plan2.md).
    tokens: u32 = 0,
    /// Iteration (0-based) at which the campaign failed, if it did.
    failed_at: ?u32 = null,
};

const Guided = struct {
    corpus: explore.Corpus,
    seen: *[explore.map_words]u64,
    run: *[explore.map_words]u64,
    rec_buf: []u64,
    mutated: u32,

    fn init(gpa: Allocator, options: Options) !Guided {
        var corpus = try explore.Corpus.init(gpa, options.corpus_max, options.campaign_seed);
        errdefer corpus.deinit(gpa);
        const seen = try gpa.create([explore.map_words]u64);
        errdefer gpa.destroy(seen);
        const run = try gpa.create([explore.map_words]u64);
        errdefer gpa.destroy(run);
        @memset(seen, 0);
        return .{ .corpus = corpus, .seen = seen, .run = run, .rec_buf = try gpa.alloc(u64, 4096), .mutated = 0 };
    }

    fn deinit(g: *Guided, gpa: Allocator) void {
        gpa.free(g.rec_buf);
        gpa.destroy(g.run);
        gpa.destroy(g.seen);
        g.corpus.deinit(gpa);
    }

    fn report(g: *const Guided, options: Options, failed_at: ?u32) void {
        const r = options.explore_report orelse return;
        r.* = .{
            .corpus = g.corpus.len,
            .features = (explore.Map{ .words = g.seen }).count(),
            .mutated_runs = g.mutated,
            .tokens = g.corpus.tokens_len,
            .failed_at = failed_at,
        };
    }
};

/// Runs `body` across `options.iterations` seeds for each persona.
pub fn check(gpa: Allocator, comptime body: fn (*Env) anyerror!void, options: Options) !void {
    const caller = @returnAddress();
    var o = options;
    campaignFromEnv(gpa, &o);
    const s = try Sim.create(gpa, simConfig(o));
    defer s.destroy();
    applySetup(s, o);
    // The shrunk token, for a security layer's emitter (seam 4).
    var shrunk: ShrinkReport = .{};
    if (o.shrink_report == null) o.shrink_report = &shrunk;
    const result = checkOn(gpa, s, body, o);
    if (options.warm_report) |r| r.* = .{
        .restores = s.warm.restores,
        .checks = s.warm.checks,
        .mismatches = s.warm.mismatches,
        .active = s.warm.state == .ready,
    };
    if (s.sec != null) {
        const failed = if (result) |_| false else |_| true;
        const token: []const u8 = if (!failed) "" else if (options.keep_going) |log|
            (if (log.len > 0) log.entries[0].token() else "")
        else if (o.shrink_report.?.shrunk) o.shrink_report.?.token() else "";
        s.secCampaignEnd(&.{
            .err = if (result) |_| null else |err| err,
            .caller = caller,
            .token = token,
            .iterations = options.iterations,
        });
    }
    return result;
}

fn checkOn(gpa: Allocator, s: *Sim, comptime body: fn (*Env) anyerror!void, options: Options) anyerror!void {
    if (options.replay) |text| return runToken(gpa, s, body, text, options);
    if (replayTokenFromEnv(gpa)) |text| {
        defer gpa.free(text);
        return runToken(gpa, s, body, text, options);
    }

    const env_replay = replayFromEnv(gpa);
    const replay_seed = options.seed orelse env_replay.seed;
    if (options.keep_going) |log| log.* = .{};

    if (replay_seed) |seed| {
        for (options.personas) |persona| {
            if (env_replay.persona) |p| if (p != persona) continue;
            const out = runOnce(s, body, seed, persona, 0, options.leak_check);
            out.result catch |err| {
                reportFailure(s, err, 0, 1, seed, persona, &.{});
                shrinkAndReport(gpa, s, body, seed, persona, &.{}, err, options);
                return err;
            };
        }
        return;
    }

    const fork_server = options.fork and forkserver.supported and options.setup != null;
    if (options.workers > 1 and options.explore == .random and !fork_server) {
        if (try runParallel(gpa, s, body, options)) |failed_at| {
            // Re-run the lowest failing iteration on this thread to report
            // and shrink it exactly as a one-thread campaign would.
            try campaignRange(gpa, s, body, options, null, failed_at, failed_at + 1);
            return error.NonDeterministic; // it passed here: not reproducible
        }
        if (options.keep_going) |log| if (log.len > 0) return log.entries[0].err;
    } else if (options.workers > 1 and options.explore == .guided) {
        try runGuidedParallel(gpa, s, body, options);
    } else {
        var guided: ?Guided = if (options.explore == .guided) try Guided.init(gpa, options) else null;
        defer if (guided) |*g| g.deinit(gpa);
        try campaignRange(gpa, s, body, options, if (guided) |*g| g else null, 0, options.iterations);
        if (guided) |*g| g.report(options, null);
    }
    if (s.catalog.reportUnsatisfied(s.config.report) > 0) return error.SometimesNeverTrue;
}

/// Runs iterations `[first, end)` on `s`, reporting and shrinking the first failure.
fn campaignRange(gpa: Allocator, s: *Sim, comptime body: fn (*Env) anyerror!void, options: Options, guided: ?*Guided, first: u32, end: u32) anyerror!void {
    if (options.fork and forkserver.supported and guided == null and s.setup_fn != null) {
        var in_process = options;
        in_process.fork = false;
        var runs: FoundRuns = .{};
        const keep: ?*FoundRuns = if (options.keep_going != null) &runs else null;
        const found = if (options.workers > 1)
            try forkWorkers(gpa, s, body, options, first, end, keep)
        else
            try forkRange(gpa, s, body, options, first, end, 1, keep, null);
        if (options.keep_going) |log| {
            // A worker that could not run: the whole range here instead.
            if (found != null) return campaignRange(gpa, s, body, in_process, null, first, end);
            logFound(gpa, s, body, log, &runs, in_process);
            if (log.len > 0) return log.entries[0].err;
            return;
        }
        if (found) |failed_at| {
            try campaignRange(gpa, s, body, in_process, null, failed_at, failed_at + 1);
            return error.NonDeterministic; // failed in a child, passed here
        }
        return;
    }
    var iteration: u32 = first;
    while (iteration < end) : (iteration += 1) {
        for (options.personas, 0..) |persona, pi| {
            var seed = runSeed(options.campaign_seed, iteration, pi);
            var child: explore.Entry = undefined;
            var forced: []const decide.Forced = &.{};
            var rec = decide.Recorder.init(&.{});
            if (guided) |g| {
                if (g.corpus.pickParent(@intCast(pi))) |parent| {
                    g.corpus.mutate(parent, &child);
                    seed = child.seed;
                    forced = child.forcedSlice();
                    g.mutated += 1;
                }
                rec = decide.Recorder.init(g.rec_buf);
                s.coverage = .{ .words = g.run };
                s.recorder = &rec;
            }
            const overlay: decide.Overlay = .{ .forced = forced };
            s.overlay = if (forced.len > 0) &overlay else null;
            const out = runOnce(s, body, seed, persona, iteration, options.leak_check);
            s.coverage = null;
            s.recorder = null;
            out.result catch |err| {
                s.overlay = null;
                if (options.keep_going) |log| {
                    logFailure(gpa, s, body, log, iteration, seed, persona, forced, err, options);
                    continue;
                }
                reportFailure(s, err, iteration, options.iterations, seed, persona, forced);
                shrinkAndReport(gpa, s, body, seed, persona, forced, err, options);
                if (guided) |g| g.report(options, iteration);
                return err;
            };
            if (guided) |g| {
                const seen: explore.Map = .{ .words = g.seen };
                if (seen.merge(.{ .words = g.run }) > 0) g.corpus.add(@intCast(pi), seed, forced, rec.keys[0..rec.len]);
                g.corpus.addTokens(s.secTokens());
            }
            const every = options.determinism_check_every;
            if (every != 0 and iteration % every == 0) {
                s.rerun = true;
                const again = runOnce(s, body, seed, persona, iteration, options.leak_check);
                s.rerun = false;
                if (again.trace_hash != out.trace_hash) {
                    std.debug.print(
                        "tardis: NON-DETERMINISM: seed=0x{x:0>16} persona={s} produced trace 0x{x} then 0x{x}\n" ++
                            "tardis: the code under test reads state that does not come from env.io/env.allocator\n",
                        .{ seed, @tagName(persona), out.trace_hash, again.trace_hash },
                    );
                    s.overlay = null;
                    return error.NonDeterministic;
                }
            }
            s.overlay = null;
        }
    }
    if (options.keep_going) |log| if (log.len > 0) return log.entries[0].err;
}

/// `Options.keep_going`: reports, shrinks and logs one failure; the
/// campaign continues.
fn logFailure(gpa: Allocator, s: *Sim, comptime body: fn (*Env) anyerror!void, log: *FailureLog, iteration: u32, seed: u64, persona: Persona, forced: []const decide.Forced, err: anyerror, options: Options) void {
    if (log.len == FailureLog.entries_max) {
        log.dropped += 1;
        return;
    }
    reportFailure(s, err, iteration, options.iterations, seed, persona, forced);
    var shrunk: ShrinkReport = .{};
    var o = options;
    o.shrink_report = &shrunk;
    shrinkAndReport(gpa, s, body, seed, persona, forced, err, o);
    const e = &log.entries[log.len];
    e.* = .{ .iteration = iteration, .persona = persona, .seed = seed, .err = err, .shrunk = false, .token_buf = undefined, .token_len = 0 };
    if (shrunk.shrunk and shrunk.token_len > 0 and shrunk.token_len <= FailureLog.token_bytes_max) {
        @memcpy(e.token_buf[0..shrunk.token_len], shrunk.token());
        e.token_len = @intCast(shrunk.token_len);
        e.shrunk = true;
    } else if (shrink.formatToken(&e.token_buf, @tagName(persona), seed, null, forced)) |t| {
        e.token_len = @intCast(t.len);
    }
    log.len += 1;
}

/// `Options.keep_going` on several workers or in forked children: the
/// failing runs a phase found. The lowest `FailureLog.entries_max` are kept
/// in (iteration, persona) order whatever order they arrive in, so the
/// result does not depend on which worker ran what.
const FoundRuns = struct {
    const Run = extern struct { iteration: u32, persona_index: u32 };

    runs: [FailureLog.entries_max]Run = undefined,
    len: u32 = 0,
    /// Every failing run, kept or not.
    total: u32 = 0,

    fn lessThan(a: Run, b: Run) bool {
        return a.iteration < b.iteration or (a.iteration == b.iteration and a.persona_index < b.persona_index);
    }

    fn add(f: *FoundRuns, r: Run) void {
        f.total += 1;
        var i: u32 = f.len;
        while (i > 0 and lessThan(r, f.runs[i - 1])) i -= 1;
        if (i == FailureLog.entries_max) return;
        const n = @min(f.len + 1, FailureLog.entries_max);
        var j = n - 1;
        while (j > i) : (j -= 1) f.runs[j] = f.runs[j - 1];
        f.runs[i] = r;
        f.len = n;
    }

    fn merge(f: *FoundRuns, other: *const FoundRuns) void {
        for (other.runs[0..other.len]) |r| f.add(r);
        f.total += other.total - other.len;
    }
};

/// Logs the runs another thread or process found failing, lowest first:
/// each is re-run here (as a rerun: layers that tally runs counted it where
/// it ran) for its error, then reported, shrunk and logged as a one-thread
/// campaign would. A run that passes here is logged as non-deterministic.
fn logFound(gpa: Allocator, s: *Sim, comptime body: fn (*Env) anyerror!void, log: *FailureLog, found: *const FoundRuns, options: Options) void {
    for (found.runs[0..found.len]) |r| {
        const persona = options.personas[r.persona_index];
        const seed = runSeed(options.campaign_seed, r.iteration, r.persona_index);
        s.rerun = true;
        const out = runOnce(s, body, seed, persona, r.iteration, options.leak_check);
        s.rerun = false;
        const err = if (out.result) |_| error.NonDeterministic else |e| e;
        logFailure(gpa, s, body, log, r.iteration, seed, persona, &.{}, err, options);
    }
    log.dropped += found.total - found.len;
}

test "FoundRuns keeps the lowest runs in order, whatever the arrival order" {
    var a: FoundRuns = .{};
    var b: FoundRuns = .{};
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        a.add(.{ .iteration = i, .persona_index = i % 2 });
        b.add(.{ .iteration = 99 - i, .persona_index = (99 - i) % 2 });
    }
    try std.testing.expectEqual(@as(u32, FailureLog.entries_max), a.len);
    try std.testing.expectEqual(@as(u32, 100), b.total);
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(a.runs[0..a.len]), std.mem.sliceAsBytes(b.runs[0..b.len]));
    for (a.runs[0..a.len], 0..) |r, k| try std.testing.expectEqual(@as(u32, @intCast(k)), r.iteration);
    var m: FoundRuns = .{};
    var odd: FoundRuns = .{};
    var even: FoundRuns = .{};
    for (0..100) |k| (if (k % 2 == 0) &even else &odd).add(.{ .iteration = @intCast(k), .persona_index = 0 });
    m.merge(&odd);
    m.merge(&even);
    try std.testing.expectEqual(@as(u32, 100), m.total);
    for (m.runs[0..m.len], 0..) |r, k| try std.testing.expectEqual(@as(u32, @intCast(k)), r.iteration);
}

// ===========================================================================
// Multi-core campaigns (M5)

const ParallelShared = struct {
    /// Lowest failing iteration so far (maxInt: none).
    best: std.atomic.Value(u32) = .init(std.math.maxInt(u32)),
    setup_failed: std.atomic.Value(bool) = .init(false),

    fn offer(p: *ParallelShared, iteration: u32) void {
        var cur = p.best.load(.acquire);
        while (iteration < cur) {
            cur = p.best.cmpxchgWeak(cur, iteration, .acq_rel, .acquire) orelse return;
        }
    }
};

fn ParallelWorker(comptime body: fn (*Env) anyerror!void) type {
    return struct {
        /// Worker `w` runs iterations w, w + workers, ... on its own `Sim`,
        /// stopping once it passes the lowest failure any worker has seen.
        /// Every iteration below that failure is still run by someone, so
        /// the lowest failing iteration is the same whatever the timing.
        fn run(gpa: Allocator, options: Options, w: u32, shared: *ParallelShared, out: []oracle.Entry, out_len: *usize, found: *FoundRuns) void {
            var config = simConfig(options);
            config.report = false;
            const ws = Sim.create(gpa, config) catch {
                shared.setup_failed.store(true, .release);
                return;
            };
            defer ws.destroy();
            applySetup(ws, options);
            var it: u32 = w;
            outer: while (it < options.iterations) : (it += options.workers) {
                if (it > shared.best.load(.acquire)) break;
                for (options.personas, 0..) |persona, pi| {
                    const seed = runSeed(options.campaign_seed, it, pi);
                    const first = runOnce(ws, body, seed, persona, it, options.leak_check);
                    var failed = if (first.result) |_| false else |_| true;
                    const every = options.determinism_check_every;
                    if (!failed and every != 0 and it % every == 0) {
                        ws.rerun = true;
                        failed = runOnce(ws, body, seed, persona, it, options.leak_check).trace_hash != first.trace_hash;
                        ws.rerun = false;
                    }
                    if (failed) {
                        if (options.keep_going != null) {
                            found.add(.{ .iteration = it, .persona_index = @intCast(pi) });
                            continue;
                        }
                        shared.offer(it);
                        break :outer;
                    }
                }
            }
            const n = ws.catalog.len;
            @memcpy(out[0..n], ws.catalog.entries[0..n]);
            out_len.* = n;
        }
    };
}

/// Runs the campaign on `options.workers` threads. Returns the lowest
/// failing iteration, or null after merging the workers' assertion catalogs
/// into `s`.
fn runParallel(gpa: Allocator, s: *Sim, comptime body: fn (*Env) anyerror!void, options: Options) !?u32 {
    const workers = options.workers;
    var shared: ParallelShared = .{};
    const catalogs = try gpa.alloc(oracle.Entry, @as(usize, workers) * options.limits.assertions_max);
    defer gpa.free(catalogs);
    const lens = try gpa.alloc(usize, workers);
    defer gpa.free(lens);
    @memset(lens, 0);
    const founds = try gpa.alloc(FoundRuns, workers);
    defer gpa.free(founds);
    @memset(founds, .{});
    const threads = try gpa.alloc(std.Thread, workers);
    defer gpa.free(threads);
    var spawned: usize = 0;
    defer for (threads[0..spawned]) |t| t.join();
    for (0..workers) |w| {
        const out = catalogs[w * options.limits.assertions_max ..][0..options.limits.assertions_max];
        threads[w] = try std.Thread.spawn(.{}, ParallelWorker(body).run, .{ gpa, options, @as(u32, @intCast(w)), &shared, out, &lens[w], &founds[w] });
        spawned += 1;
    }
    for (threads[0..spawned]) |t| t.join();
    spawned = 0;
    if (shared.setup_failed.load(.acquire)) return error.OutOfMemory;
    const best = shared.best.load(.acquire);
    if (best != std.math.maxInt(u32)) return best;
    for (0..workers) |w| {
        const entries = catalogs[w * options.limits.assertions_max ..][0..lens[w]];
        for (entries) |e| s.catalog.merge(e);
    }
    if (options.keep_going) |log| {
        var all: FoundRuns = .{};
        for (founds) |*f| all.merge(f);
        logFound(gpa, s, body, log, &all, options);
    }
    return null;
}

// ===========================================================================
// Guided exploration on several threads (M5)
//
// Epochs of `Options.epoch_iterations` iterations. Before an epoch, the
// main thread plans every run of it (fresh seed or a mutation of a corpus
// entry) from the corpus as it stood at the end of the previous epoch.
// Workers run the planned jobs on their own simulators, each writing its
// coverage map and decision-key sample into the job's slot. The main thread
// then merges the slots in job order, adding runs with new coverage to the
// corpus. Planning and merging never look at which thread ran what, so the
// campaign (corpus, failure, shrunk token) is the same for any number of
// workers; only one-thread guided exploration, which updates the corpus
// after every run, differs.

const GuidedJob = struct {
    iteration: u32,
    persona_index: u8,
    seed: u64,
    /// In: the forced decisions. Out: the run's sampled decision keys.
    entry: explore.Entry,
    /// Out: the constants the run compared against (the first
    /// `job_tokens_max`).
    tokens: [job_tokens_max]u64,
    tokens_len: u8,
};

const job_tokens_max = 16;

const guided_rec_len = 4096;

/// State shared by the threads of a parallel guided campaign. Threads are
/// started once; each epoch is released by bumping `generation` and ends
/// when every helper has bumped `done` (spin-and-yield barriers: `check` has
/// no host `Io` to block on, and the waits are short).
const EpochCtx = struct {
    options: Options,
    sims: []*Sim,
    jobs: []GuidedJob,
    /// Jobs in the current epoch.
    len: u32 = 0,
    maps: []u64,
    rec_bufs: []u64,
    /// Next job to claim.
    next: std.atomic.Value(u32) = .init(0),
    /// Lowest failing job of the epoch.
    shared: ParallelShared = .{},
    generation: std.atomic.Value(u32) = .init(0),
    done: std.atomic.Value(u32) = .init(0),
    stop: std.atomic.Value(bool) = .init(false),
};

fn waitYield() void {
    std.Thread.yield() catch {};
}

fn GuidedWorker(comptime body: fn (*Env) anyerror!void) type {
    return struct {
        /// Helper thread `w` (1..workers-1): one epoch per generation.
        fn helper(ctx: *EpochCtx, w: u32) void {
            var seen: u32 = 0;
            while (true) {
                var g = ctx.generation.load(.acquire);
                while (g == seen) : (g = ctx.generation.load(.acquire)) waitYield();
                seen = g;
                if (ctx.stop.load(.acquire)) return;
                runJobs(ctx, w);
                _ = ctx.done.fetchAdd(1, .acq_rel);
            }
        }

        /// Claims and runs jobs until none are left. Which thread runs which
        /// job does not matter: results go into the job's own slot.
        fn runJobs(ctx: *EpochCtx, w: u32) void {
            const options = ctx.options;
            const ws = ctx.sims[w];
            const rec_buf = ctx.rec_bufs[w * guided_rec_len ..][0..guided_rec_len];
            while (true) {
                const j = ctx.next.fetchAdd(1, .acq_rel);
                if (j >= ctx.len) return;
                // Jobs after the lowest failure are never merged.
                if (j > ctx.shared.best.load(.acquire)) continue;
                const job = &ctx.jobs[j];
                const map: *[explore.map_words]u64 = ctx.maps[@as(usize, j) * explore.map_words ..][0..explore.map_words];
                var rec = decide.Recorder.init(rec_buf);
                const overlay: decide.Overlay = .{ .forced = job.entry.forcedSlice() };
                ws.overlay = if (job.entry.forced_len > 0) &overlay else null;
                ws.coverage = .{ .words = map };
                ws.recorder = &rec;
                const persona = options.personas[job.persona_index];
                const out = runOnce(ws, body, job.seed, persona, job.iteration, options.leak_check);
                ws.coverage = null;
                ws.recorder = null;
                const tokens = ws.secTokens();
                job.tokens_len = @intCast(@min(tokens.len, job_tokens_max));
                @memcpy(job.tokens[0..job.tokens_len], tokens[0..job.tokens_len]);
                var failed = if (out.result) |_| false else |_| true;
                const every = options.determinism_check_every;
                if (!failed and every != 0 and job.iteration % every == 0) {
                    failed = runOnce(ws, body, job.seed, persona, job.iteration, options.leak_check).trace_hash != out.trace_hash;
                }
                ws.overlay = null;
                if (failed) {
                    ctx.shared.offer(j);
                    continue;
                }
                // The same evenly spaced sample `Corpus.add` takes.
                const drawn = rec.keys[0..rec.len];
                const n = @min(drawn.len, explore.sample_max);
                job.entry.keys_len = @intCast(n);
                for (0..n) |i| job.entry.keys[i] = drawn[i * drawn.len / n];
            }
        }
    };
}

fn runGuidedParallel(gpa: Allocator, s: *Sim, comptime body: fn (*Env) anyerror!void, options: Options) !void {
    const workers = options.workers;
    const epoch: u32 = @max(options.epoch_iterations, 1);
    var g = try Guided.init(gpa, options);
    defer g.deinit(gpa);
    const jobs_max = @as(usize, epoch) * options.personas.len;
    const jobs = try gpa.alloc(GuidedJob, jobs_max);
    defer gpa.free(jobs);
    const maps = try gpa.alloc(u64, jobs_max * explore.map_words);
    defer gpa.free(maps);
    const rec_bufs = try gpa.alloc(u64, @as(usize, workers) * guided_rec_len);
    defer gpa.free(rec_bufs);

    const sims = try gpa.alloc(*Sim, workers);
    defer gpa.free(sims);
    var created: usize = 0;
    defer for (sims[0..created]) |ws| ws.destroy();
    var config = simConfig(options);
    config.report = false;
    for (sims) |*ws| {
        ws.* = try Sim.create(gpa, config);
        created += 1;
        applySetup(ws.*, options);
    }

    var ctx: EpochCtx = .{ .options = options, .sims = sims, .jobs = jobs, .maps = maps, .rec_bufs = rec_bufs };
    const Worker = GuidedWorker(body);
    // This thread is worker 0; helpers are 1..workers-1.
    const threads = try gpa.alloc(std.Thread, workers - 1);
    defer gpa.free(threads);
    var spawned: usize = 0;
    defer {
        ctx.stop.store(true, .release);
        _ = ctx.generation.fetchAdd(1, .acq_rel);
        for (threads[0..spawned]) |t| t.join();
    }
    for (threads, 1..) |*t, w| {
        t.* = try std.Thread.spawn(.{}, Worker.helper, .{ &ctx, @as(u32, @intCast(w)) });
        spawned += 1;
    }

    var first: u32 = 0;
    while (first < options.iterations) {
        const end = @min(first + epoch, options.iterations);
        // Plan, from the corpus as of the end of the last epoch.
        var n: u32 = 0;
        var it = first;
        while (it < end) : (it += 1) {
            for (0..options.personas.len) |pi| {
                const job = &jobs[n];
                n += 1;
                job.* = .{ .iteration = it, .persona_index = @intCast(pi), .seed = runSeed(options.campaign_seed, it, pi), .entry = undefined, .tokens = undefined, .tokens_len = 0 };
                job.entry.forced_len = 0;
                job.entry.keys_len = 0;
                if (g.corpus.pickParent(@intCast(pi))) |parent| {
                    g.corpus.mutate(parent, &job.entry);
                    job.seed = job.entry.seed;
                    g.mutated += 1;
                }
            }
        }
        // Run: release the helpers, work alongside them, wait for them.
        ctx.len = n;
        ctx.next.store(0, .release);
        ctx.shared = .{};
        ctx.done.store(0, .release);
        _ = ctx.generation.fetchAdd(1, .acq_rel);
        Worker.runJobs(&ctx, 0);
        while (ctx.done.load(.acquire) < spawned) waitYield();
        // Merge, in job order.
        const best = ctx.shared.best.load(.acquire);
        const seen: explore.Map = .{ .words = g.seen };
        for (jobs[0..n], 0..) |*job, j| {
            if (j == best) {
                // Re-run the failure here to report and shrink it.
                const persona = options.personas[job.persona_index];
                const forced = job.entry.forcedSlice();
                const overlay: decide.Overlay = .{ .forced = forced };
                s.overlay = if (forced.len > 0) &overlay else null;
                const out = runOnce(s, body, job.seed, persona, job.iteration, options.leak_check);
                s.overlay = null;
                g.report(options, job.iteration);
                out.result catch |err| {
                    reportFailure(s, err, job.iteration, options.iterations, job.seed, persona, forced);
                    shrinkAndReport(gpa, s, body, job.seed, persona, forced, err, options);
                    return err;
                };
                return error.NonDeterministic; // failed on a worker, passed here
            }
            const map: *[explore.map_words]u64 = maps[j * explore.map_words ..][0..explore.map_words];
            if (seen.merge(.{ .words = map }) > 0) {
                g.corpus.add(job.persona_index, job.seed, job.entry.forcedSlice(), job.entry.keys[0..job.entry.keys_len]);
            }
            g.corpus.addTokens(job.tokens[0..job.tokens_len]);
        }
        first = end;
    }
    for (sims) |ws| {
        for (ws.catalog.entries[0..ws.catalog.len]) |e| s.catalog.merge(e);
    }
    g.report(options, null);
}

// ===========================================================================
// Fork server campaigns (M5)

const ForkMessage = extern struct {
    failed: u8,
    catalog_len: u32,
    trace_hash: u64,
    /// Bytes from the security layer (`fork_export`), after the catalog.
    sec_len: u32 = 0,
};

const WireEntry = extern struct {
    name_ptr: usize,
    name_len: usize,
    kind: u8,
    reached: u64,
    true_count: u64,
};

/// A worker process's children's security tallies (`fork_export` bytes),
/// kept to forward to the main process: importing them in the worker would
/// commit them to the worker's copy of the layer's state, which dies with
/// it. Records are a little-endian u32 length and the bytes.
const SecRelay = struct {
    gpa: Allocator,
    bytes: std.ArrayList(u8) = .empty,

    fn add(r: *SecRelay, payload: []const u8) !void {
        var len: [4]u8 = undefined;
        std.mem.writeInt(u32, &len, @intCast(payload.len), .little);
        try r.bytes.appendSlice(r.gpa, &len);
        try r.bytes.appendSlice(r.gpa, payload);
    }

    fn deinit(r: *SecRelay) void {
        r.bytes.deinit(r.gpa);
    }

    /// Imports every record of `bytes` into `s`'s layer.
    fn importAll(s: *Sim, bytes: []const u8) void {
        var off: usize = 0;
        while (off + 4 <= bytes.len) {
            const len = std.mem.readInt(u32, bytes[off..][0..4], .little);
            off += 4;
            if (off + len > bytes.len) return;
            s.secForkImport(bytes[off..][0..len]);
            off += len;
        }
    }
};

fn ForkServer(comptime body: fn (*Env) anyerror!void) type {
    return struct {
        const Ctx = struct {
            env: *Env,
            options: Options,
            persona_index: usize,
            first: u32,
            step: u32,
            /// Exclusive; lowered as failures are found in other personas.
            end: u32,
            failed_at: ?u32 = null,
            crashed: bool = false,
            buf: []u8,
            /// `keep_going`: failing iterations are noted here and the
            /// range continues (a crashed child still ends it).
            found: ?*FoundRuns = null,
            /// In a worker process: children's security tallies are kept
            /// here for the main process instead of imported.
            relay: ?*SecRelay = null,

            /// Iteration `it` failed. True: note it and go on.
            fn failed(c: *Ctx, it: u32) bool {
                if (!c.crashed) if (c.found) |f| {
                    f.add(.{ .iteration = it, .persona_index = @intCast(c.persona_index) });
                    return true;
                };
                c.failed_at = it;
                return false;
            }
        };

        /// Runs on the control fiber: setup once, then one child per iteration.
        fn call(ctx_ptr: *anyopaque) anyerror!void {
            const c: *Ctx = @ptrCast(@alignCast(ctx_ptr));
            const setup: SetupFn = @ptrCast(@alignCast(c.env.sim.setup_fn.?));
            try setup(c.env);
            var it = c.first;
            while (it < c.end) : (it += c.step) {
                const seed = runSeed(c.options.campaign_seed, it, c.persona_index);
                const h1 = (try child(c, seed, it, true)) orelse {
                    if (c.failed(it)) continue;
                    return;
                };
                const every = c.options.determinism_check_every;
                if (every != 0 and it % every == 0) {
                    const h2 = (try child(c, seed, it, false)) orelse {
                        if (c.failed(it)) continue;
                        return;
                    };
                    if (h1 != h2) {
                        if (c.failed(it)) continue;
                        return;
                    }
                }
            }
        }

        /// Forks one iteration. Returns its trace hash, or null if it failed
        /// or crashed.
        /// `counted`: the iteration's own run (its security tallies are
        /// imported), not the determinism re-run.
        fn child(c: *Ctx, seed: u64, it: u32, counted: bool) !?u64 {
            const s = c.env.sim;
            switch (try forkserver.fork()) {
                .child => |fd| {
                    s.config.report = false;
                    // Report only this child's counts: the parent already has its own.
                    s.catalog.resetCounts();
                    s.reseed(seed);
                    c.env.seed = seed;
                    c.env.iteration = it;
                    s.iteration = it;
                    var result: anyerror!void = if (startAutoChaos(c.env)) body(c.env) else |err| err;
                    s.secEndRun();
                    if (result) |_| {
                        if (s.daemon_error) |e| result = e;
                    } else |_| {}
                    if (result) |_| {
                        if (c.options.leak_check) result = expectNoLeaksExcluding(s, s.current);
                    } else |_| {}
                    const outcome_word: u64 = if (result) |_| 0 else |err| @intFromError(err);
                    // The child's copy of the receive buffer is free scratch.
                    const sec_bytes = c.buf[c.buf.len - sec_seam.fork_bytes_max ..];
                    const sec_len = s.secForkExport(sec_bytes);
                    const msg: ForkMessage = .{
                        .failed = if (result) |_| 0 else |_| 1,
                        .catalog_len = @intCast(s.catalog.len),
                        .trace_hash = decide.mix(s.trace.hash, outcome_word),
                        .sec_len = @intCast(sec_len),
                    };
                    forkserver.writeAll(fd, std.mem.asBytes(&msg));
                    for (s.catalog.entries[0..s.catalog.len]) |e| {
                        const w: WireEntry = .{ .name_ptr = @intFromPtr(e.name.ptr), .name_len = e.name.len, .kind = @backingInt(e.kind), .reached = e.reached_count, .true_count = e.true_count };
                        forkserver.writeAll(fd, std.mem.asBytes(&w));
                    }
                    forkserver.writeAll(fd, sec_bytes[0..sec_len]);
                    forkserver.exitNow(0);
                },
                .parent => |p| {
                    const n = forkserver.readAll(p.fd, c.buf);
                    forkserver.close(p.fd);
                    _ = forkserver.wait(p.pid);
                    if (n < @sizeOf(ForkMessage)) {
                        c.crashed = true;
                        return null;
                    }
                    const msg = std.mem.bytesToValue(ForkMessage, c.buf[0..@sizeOf(ForkMessage)]);
                    // Assertion names are string literals: same address in
                    // the child and here.
                    var off: usize = @sizeOf(ForkMessage);
                    for (0..msg.catalog_len) |_| {
                        if (off + @sizeOf(WireEntry) > n) break;
                        const w = std.mem.bytesToValue(WireEntry, c.buf[off..][0..@sizeOf(WireEntry)]);
                        off += @sizeOf(WireEntry);
                        const name: [*]const u8 = @ptrFromInt(w.name_ptr);
                        s.catalog.merge(.{ .name = name[0..w.name_len], .kind = @fromBackingInt(@intCast(w.kind)), .reached_count = w.reached, .true_count = w.true_count });
                    }
                    // The run's security tallies (failing runs count too).
                    if (counted and msg.sec_len > 0 and off + msg.sec_len <= n) {
                        const tallies = c.buf[off..][0..msg.sec_len];
                        if (c.relay) |r| try r.add(tallies) else s.secForkImport(tallies);
                    }
                    if (msg.failed != 0) return null;
                    return msg.trace_hash;
                },
            }
        }
    };
}

/// Runs iterations `[first, end)` with one warm-up per persona and a forked
/// child per iteration. Returns the lowest failing iteration, if any.
fn forkRange(gpa: Allocator, s: *Sim, comptime body: fn (*Env) anyerror!void, options: Options, first: u32, end: u32, step: u32, found: ?*FoundRuns, relay: ?*SecRelay) !?u32 {
    const Server = ForkServer(body);
    const buf = try gpa.alloc(u8, @sizeOf(ForkMessage) + @as(usize, options.limits.assertions_max) * @sizeOf(WireEntry) + sec_seam.fork_bytes_max);
    defer gpa.free(buf);
    var best: ?u32 = null;
    for (options.personas, 0..) |persona, pi| {
        s.beginRun(s.setup_seed.?, persona);
        var env = Env.init(s, first);
        var ctx: Server.Ctx = .{ .env = &env, .options = options, .persona_index = pi, .first = first, .step = step, .end = if (best) |b| b else end, .buf = buf, .found = found, .relay = relay };
        const r = s.drive(Server.call, &ctx);
        s.endRun();
        try r.outcome; // the setup itself failed
        if (ctx.crashed) {
            const it = ctx.failed_at.?;
            if (s.config.report) std.debug.print("tardis: iteration {d} crashed its forked child (persona={s}); replay with:  TARDIS_SEED=0x{x:0>16} TARDIS_PERSONA={s} zig build test\n", .{ it + 1, @tagName(persona), runSeed(options.campaign_seed, it, pi), @tagName(persona) });
            return error.ChildCrashed;
        }
        if (ctx.failed_at) |f| best = if (best) |b| @min(b, f) else f;
    }
    return best;
}

const WorkerMessage = extern struct {
    /// 0: passed, 1: failed at `failed_at`, 2: a child crashed, 3: error.
    status: u8,
    failed_at: u32,
    catalog_len: u32,
    /// `keep_going`: the worker's failing runs, sent after the catalog.
    found_len: u32 = 0,
    found_total: u32 = 0,
    /// Bytes of forwarded security tallies (`SecRelay`), sent last.
    sec_len: u32 = 0,
};

/// Multi-core fork server: forks `options.workers` single-threaded worker
/// processes (never threads: a child forked from a multi-threaded process
/// could inherit a held allocator lock). Worker `w` runs iterations
/// `first + w, first + w + W, ...` with its own per-iteration fork server
/// and reports its first failure. Each worker's first failure is the lowest
/// in its stride, so the minimum over workers is the campaign's lowest
/// failing iteration, independent of timing.
fn forkWorkers(gpa: Allocator, s: *Sim, comptime body: fn (*Env) anyerror!void, options: Options, first: u32, end: u32, found: ?*FoundRuns) !?u32 {
    const workers = options.workers;
    const pids = try gpa.alloc(i32, workers);
    defer gpa.free(pids);
    const fds = try gpa.alloc(forkserver.Fd, workers);
    defer gpa.free(fds);
    var started: usize = 0;
    for (0..workers) |w| {
        switch (try forkserver.fork()) {
            .child => |fd| {
                s.catalog.resetCounts(); // report only this worker's counts
                var msg: WorkerMessage = .{ .status = 0, .failed_at = 0, .catalog_len = 0 };
                var mine: FoundRuns = .{};
                var relay: SecRelay = .{ .gpa = gpa };
                defer relay.deinit();
                if (forkRange(gpa, s, body, options, first + @as(u32, @intCast(w)), end, workers, if (found != null) &mine else null, &relay)) |lowest| {
                    if (lowest) |f| {
                        msg.status = 1;
                        msg.failed_at = f;
                    }
                } else |err| {
                    msg.status = if (err == error.ChildCrashed) 2 else 3;
                }
                msg.catalog_len = @intCast(s.catalog.len);
                msg.found_len = mine.len;
                msg.found_total = mine.total;
                msg.sec_len = @intCast(relay.bytes.items.len);
                forkserver.writeAll(fd, std.mem.asBytes(&msg));
                for (s.catalog.entries[0..s.catalog.len]) |e| {
                    const wire: WireEntry = .{ .name_ptr = @intFromPtr(e.name.ptr), .name_len = e.name.len, .kind = @backingInt(e.kind), .reached = e.reached_count, .true_count = e.true_count };
                    forkserver.writeAll(fd, std.mem.asBytes(&wire));
                }
                forkserver.writeAll(fd, std.mem.sliceAsBytes(mine.runs[0..mine.len]));
                forkserver.writeAll(fd, relay.bytes.items);
                forkserver.exitNow(0);
            },
            .parent => |p| {
                pids[w] = p.pid;
                fds[w] = p.fd;
                started += 1;
            },
        }
    }
    const buf = try gpa.alloc(u8, @sizeOf(WorkerMessage) + @as(usize, options.limits.assertions_max) * @sizeOf(WireEntry) + FailureLog.entries_max * @sizeOf(FoundRuns.Run));
    defer gpa.free(buf);
    var best: ?u32 = null;
    var crashed = false;
    var errored = false;
    for (0..started) |w| {
        const n = forkserver.readAll(fds[w], buf);
        defer {
            forkserver.close(fds[w]);
            _ = forkserver.wait(pids[w]);
        }
        if (n < @sizeOf(WorkerMessage)) {
            errored = true;
            continue;
        }
        const msg = std.mem.bytesToValue(WorkerMessage, buf[0..@sizeOf(WorkerMessage)]);
        switch (msg.status) {
            1 => best = if (best) |b| @min(b, msg.failed_at) else msg.failed_at,
            2 => crashed = true,
            3 => errored = true,
            else => {},
        }
        var off: usize = @sizeOf(WorkerMessage);
        for (0..msg.catalog_len) |_| {
            if (off + @sizeOf(WireEntry) > n) break;
            const wire = std.mem.bytesToValue(WireEntry, buf[off..][0..@sizeOf(WireEntry)]);
            off += @sizeOf(WireEntry);
            const name: [*]const u8 = @ptrFromInt(wire.name_ptr);
            s.catalog.merge(.{ .name = name[0..wire.name_len], .kind = @fromBackingInt(@intCast(wire.kind)), .reached_count = wire.reached, .true_count = wire.true_count });
        }
        if (found) |all| {
            var theirs: FoundRuns = .{};
            for (0..@min(msg.found_len, FailureLog.entries_max)) |_| {
                if (off + @sizeOf(FoundRuns.Run) > n) break;
                theirs.add(std.mem.bytesToValue(FoundRuns.Run, buf[off..][0..@sizeOf(FoundRuns.Run)]));
                off += @sizeOf(FoundRuns.Run);
            }
            theirs.total = @max(theirs.total, msg.found_total);
            all.merge(&theirs);
        } else off += @as(usize, msg.found_len) * @sizeOf(FoundRuns.Run);
        // The worker's children's security tallies: what did not fit in
        // `buf` is still in the pipe.
        if (msg.sec_len > 0 and off <= n) {
            const tallies = try gpa.alloc(u8, msg.sec_len);
            defer gpa.free(tallies);
            const have = @min(n - off, tallies.len);
            @memcpy(tallies[0..have], buf[off..][0..have]);
            const got = have + forkserver.readAll(fds[w], tallies[have..]);
            SecRelay.importAll(s, tallies[0..got]);
        }
    }
    if (crashed) return error.ChildCrashed;
    // A worker that could not run (setup failed, out of resources):
    // reproduce on this process, where the error surfaces normally.
    if (errored) return first;
    return best;
}

/// Runs `body` once with `seed` and returns its trace hash (for tests and
/// cross-host determinism checks).
pub fn traceHash(gpa: Allocator, comptime body: fn (*Env) anyerror!void, seed: u64, persona: Persona, options: Options) !u64 {
    const s = try Sim.create(gpa, simConfig(options));
    defer s.destroy();
    applySetup(s, options);
    const out = runOnce(s, body, seed, persona, 0, options.leak_check);
    try out.result;
    return out.trace_hash;
}

/// Runs `body` once and writes the run's events to `w` as a Chrome trace
/// (JSON; open it in Perfetto or `chrome://tracing`): one track per task,
/// virtual time. The run is `Options.replay`'s token if there is one, else
/// `seed` and `persona`. The trace holds the last
/// `options.limits.trace_ring_len` events (64 by default: raise it for a
/// whole run). Returns the run's error after writing, so a failing run is
/// traced too.
pub fn traceJson(gpa: Allocator, comptime body: fn (*Env) anyerror!void, seed: u64, persona: Persona, options: Options, w: *std.Io.Writer) !void {
    const s = try Sim.create(gpa, simConfig(options));
    defer s.destroy();
    applySetup(s, options);
    s.config.report = false;
    var tok: ?shrink.Token = if (options.replay) |text| shrink.parseToken(gpa, text) catch return error.BadReplayToken else null;
    defer if (tok) |*t| t.deinit(gpa);
    const run_seed = if (tok) |t| t.seed else seed;
    const run_persona = if (tok) |t| std.meta.stringToEnum(Persona, t.persona) orelse return error.BadReplayToken else persona;
    const overlay: decide.Overlay = if (tok) |t| t.overlay() else .{};
    if (tok != null) s.overlay = &overlay;
    const out = runOnce(s, body, run_seed, run_persona, 0, options.leak_check);
    s.overlay = null;
    try s.trace.writeChromeTrace(w);
    try out.result;
}

// ===========================================================================
// Bounded exhaustive exploration (plan2.md §7.2)

pub const ExhaustiveOptions = struct {
    /// Branchable decisions per execution that are enumerated; later ones
    /// take their benign value (0: no fault, no preemption, first choice).
    depth_max: u16 = 12,
    /// Draws with more outcomes than this are not enumerated (they take
    /// their benign value and make the result incomplete).
    outcomes_max: u32 = 4,
    /// Executions before giving up (the result is then incomplete).
    executions_max: u32 = 1 << 16,
    /// Keyed draws recorded per execution.
    draws_max: u32 = 4096,
    /// Partial-order reduction: an execution that runs two steps in an
    /// order whose result the other order gives too is not extended, since
    /// the search also runs that other order. Two steps are taken to
    /// commute when they run on different nodes, neither wakes the other's
    /// task, they touch no common datagram inbox, and neither does anything
    /// else that reaches beyond its node (streams, spawns, crashes, links,
    /// futexes, clock steps count as reaching every node). This assumes
    /// that tasks on different nodes share no memory except through the
    /// simulator. With a security layer attached no step commutes, so
    /// nothing is pruned.
    reduce: bool = false,
    /// State merging: an execution that reaches, before a scheduling
    /// choice, a state another execution reached with as many decisions
    /// left or more, is not extended from there, since the search runs
    /// everything after that state from the other one. States are compared
    /// by what each node and each datagram inbox has seen (`Sim.History`),
    /// so two executions merge when they did the same things in another
    /// order. Same assumption as `reduce`, which it goes beyond (not only
    /// adjacent steps); with a security layer attached nothing merges.
    merge: bool = false,
    persona: Persona = .linux_ext4,
    seed: u64 = 0,
};

pub const ExhaustiveResult = struct {
    executions: u32 = 0,
    /// The most branchable decisions any execution made.
    depth_seen: u32 = 0,
    /// Draws inside the depth window that could not be enumerated: raw
    /// values (`fuzz`, `random`) and draws wider than `outcomes_max`.
    unenumerated: u32 = 0,
    /// Some execution made more than `depth_max` branchable decisions.
    depth_bounded: bool = false,
    /// With `reduce`: alternatives not run because an execution that
    /// orders two commuting steps the other way covers them.
    pruned: u32 = 0,
    /// With `merge`: executions not extended past a state already reached.
    merged: u32 = 0,
    /// True when every combination of outcomes of the first `depth_max`
    /// branchable decisions was run and passed, no draw in that window was
    /// unenumerated, and `executions_max` was not reached. "Complete" is
    /// relative to the simulated model and to the depth bound. With
    /// `reduce`, "was run" includes "or differs from one that was run only
    /// in the order of commuting steps"; when `depth_bounded` is also
    /// true, the two orders may put different decisions past the bound.
    complete: bool = false,
    /// The first failing execution, if any (exploration stops there).
    failure: ?anyerror = null,
    /// Its replay token (`TARDIS_REPLAY`), when it fits.
    token_buf: [ShrinkReport.token_bytes_max]u8 = undefined,
    token_len: usize = 0,

    pub fn token(r: *const ExhaustiveResult) []const u8 {
        return r.token_buf[0..r.token_len];
    }
};

/// Runs every execution of `body` that differs in the outcomes of its
/// first `depth_max` branchable decisions (scheduling choices, `chance`
/// faults, booleans, small `uniform`s), depth first. Unforced decisions
/// take their benign value, so each execution is determined by the
/// outcomes forced on its prefix; children only vary decisions after the
/// parent's last forced one, so each execution runs once. This is
/// stateless model checking (no snapshots): each execution replays from
/// the start, and no partial-order reduction is applied yet.
pub fn exhaustive(gpa: Allocator, comptime body: fn (*Env) anyerror!void, options: Options, x: ExhaustiveOptions) !ExhaustiveResult {
    var result: ExhaustiveResult = .{};
    const s = try Sim.create(gpa, simConfig(options));
    defer s.destroy();
    applySetup(s, options);
    s.config.report = false;

    const log_buf = try gpa.alloc(decide.Domain, x.draws_max);
    defer gpa.free(log_buf);
    const step_buf = try gpa.alloc(Sim.Step, if (x.reduce) x.draws_max else 0);
    defer gpa.free(step_buf);
    const point_buf = try gpa.alloc(Sim.History.Point, if (x.merge) x.draws_max else 0);
    defer gpa.free(point_buf);
    const node_hashes = try gpa.alloc(u64, if (x.merge) options.nodes else 0);
    defer gpa.free(node_hashes);
    // A state's hash, and the fewest decisions made on a way to it.
    var states: std.AutoHashMapUnmanaged(u64, u32) = .empty;
    defer states.deinit(gpa);

    const Node = struct { forced: []decide.Forced };
    var stack: std.ArrayList(Node) = .empty;
    defer {
        for (stack.items) |n| gpa.free(n.forced);
        stack.deinit(gpa);
    }
    try stack.append(gpa, .{ .forced = try gpa.alloc(decide.Forced, 0) });
    // Only forced decisions keep a value; every other draw is benign (0).
    const keep = try gpa.alloc(u64, x.depth_max);
    defer gpa.free(keep);
    var truncated = false;

    while (stack.pop()) |node| {
        defer gpa.free(node.forced);
        if (result.executions == x.executions_max) {
            truncated = true;
            break;
        }
        var log = decide.DomainLog.init(log_buf);
        for (node.forced, 0..) |f, i| keep[i] = f.key;
        const keys = keep[0..node.forced.len];
        const overlay: decide.Overlay = .{ .keep = keys, .forced = node.forced };
        var steps = Sim.StepLog.init(step_buf);
        s.overlay = &overlay;
        s.domain_log = &log;
        var history = Sim.History.init(node_hashes, point_buf);
        s.step_log = if (x.reduce) &steps else null;
        s.history = if (x.merge) &history else null;
        const out = runOnce(s, body, x.seed, x.persona, result.executions, options.leak_check);
        s.overlay = null;
        s.domain_log = null;
        s.step_log = null;
        s.history = null;
        result.executions += 1;
        if (out.result) |_| {} else |err| {
            result.failure = err;
            if (shrink.formatToken(&result.token_buf, @tagName(x.persona), x.seed, keys, node.forced)) |t| result.token_len = t.len;
            return result;
        }
        if (log.overflowed) result.unenumerated += 1;

        // Children vary only decisions after the last forced one.
        const draws = log.slice();
        var from: usize = 0;
        for (draws, 0..) |d, i| {
            if (overlay.forcedValue(d.key) != null) from = i + 1;
        }
        // Reduction: the first step that could have run before its
        // predecessor with the same result. Every execution that shares
        // the draws up to that step's end shares the two steps, and is
        // covered by the one that runs them in the other order.
        var cut: usize = std.math.maxInt(usize);
        const logged = steps.slice();
        for (logged, 0..) |*b, k| {
            if (k == 0 or !b.redundantAfter(&logged[k - 1])) continue;
            cut = b.end_draws;
            break;
        }
        // Merging: the first state, after the forced decisions, that
        // another execution reached with at least as much of the window
        // left. Earlier states of this execution are recorded as its own.
        {
            var made: u32 = 0; // branchable decisions before the point
            var at: usize = 0;
            for (history.slice()) |p| {
                if (p.draws >= cut) break;
                while (at < p.draws and at < draws.len) : (at += 1) {
                    const d = draws[at];
                    if (d.kind != .raw and d.outcomes >= 2 and d.outcomes <= x.outcomes_max) made += 1;
                }
                if (p.draws < from) continue;
                if (made >= x.depth_max) break;
                const entry = try states.getOrPut(gpa, p.state);
                if (entry.found_existing and entry.value_ptr.* <= made) {
                    cut = p.draws;
                    result.merged += 1;
                    break;
                }
                entry.value_ptr.* = made;
            }
        }
        var depth: u32 = 0;
        for (draws, 0..) |d, i| {
            const branchable = d.kind != .raw and d.outcomes >= 2 and d.outcomes <= x.outcomes_max;
            const inside = depth < x.depth_max;
            if (d.kind == .raw or d.outcomes > x.outcomes_max) {
                if (inside and i >= from) result.unenumerated += 1;
                continue;
            }
            if (!branchable) continue;
            depth += 1;
            if (!inside or i < from) continue;
            if (i >= cut) {
                result.pruned += @intCast(d.outcomes - 1);
                continue;
            }
            var k: u64 = 1;
            while (k < d.outcomes) : (k += 1) {
                const child = try gpa.alloc(decide.Forced, node.forced.len + 1);
                @memcpy(child[0..node.forced.len], node.forced);
                child[node.forced.len] = .{ .key = d.key, .value = decide.valueFor(d.kind, d.outcomes, k) };
                std.mem.sort(decide.Forced, child, {}, struct {
                    fn lt(_: void, a: decide.Forced, b: decide.Forced) bool {
                        return a.key < b.key;
                    }
                }.lt);
                try stack.append(gpa, .{ .forced = child });
            }
        }
        result.depth_seen = @max(result.depth_seen, depth);
        if (depth > x.depth_max) result.depth_bounded = true;
    }
    result.complete = !truncated and result.unenumerated == 0;
    return result;
}

// ===========================================================================
// sim: the while-loop form

pub const Simulation = struct {
    s: *Sim,
    gpa: Allocator,
    options: Options,
    iteration: u32,
    persona_index: usize,
    in_progress: bool,
    finished: bool,
    replay: ?u64,
    env: Env,
    /// A replay token being run (`Options.replay` or `TARDIS_REPLAY`).
    token: ?shrink.Token = null,
    token_text: ?[]u8 = null,
    token_overlay: decide.Overlay = .{},

    mode: Mode = .campaign,
    /// Set by `fail` during the current iteration.
    failure: ?anyerror = null,
    /// The campaign failure (being shrunk, or returned by `finish`).
    target: ?anyerror = null,
    seed: u64 = 0,
    failed_seed: u64 = 0,
    print: bool = true,
    rec_buf: []u64 = &.{},
    rec: decide.Recorder = undefined,
    shrinker: ?shrink.Shrinker = null,
    overlay: decide.Overlay = .{},
    report: ShrinkReport = .{},

    const Mode = enum {
        campaign,
        /// Re-running the failure with a recorder: the decisions to shrink.
        recording,
        shrinking,
        /// The shrunk run, re-run so the trace ring shows it.
        final,
        stopped,
    };

    /// Starts the next iteration and returns its environment, or null when
    /// all iterations have run. The body runs on the caller's stack as the
    /// root task; a deadlock there panics with the replay seed.
    ///
    /// After an iteration reports a failure with `fail`, the next calls
    /// return *shrink candidates* of that iteration instead: the same seed
    /// with fewer and smaller decisions. Run the body on them exactly as on
    /// any iteration (reporting failures with `fail` again); when shrinking
    /// is done `step` returns null and `finish` returns the error.
    pub fn step(self: *Simulation) ?*Env {
        if (self.in_progress) {
            const failed_now = self.failure;
            self.failure = null;
            self.s.secEndRun();
            self.s.endRun();
            self.s.overlay = null;
            self.s.recorder = null;
            self.in_progress = false;
            self.afterRun(failed_now);
        }
        return self.beginNext();
    }

    /// Reports that the current iteration failed with `err` (call it in the
    /// loop body instead of returning the error, so the failure can be
    /// shrunk). The first failure of an iteration counts.
    pub fn fail(self: *Simulation, err: anyerror) void {
        if (!self.in_progress or self.failure != null) return;
        self.failure = err;
        self.s.trace.record(self.s.now_ns, self.s.current, .note, 0, 0, 0, @errorName(err));
    }

    fn persona(self: *const Simulation) Persona {
        return self.options.personas[self.persona_index];
    }

    fn afterRun(self: *Simulation, failed_now: ?anyerror) void {
        switch (self.mode) {
            .campaign => {
                const err = failed_now orelse {
                    self.persona_index += 1;
                    if (self.persona_index == self.options.personas.len) {
                        self.persona_index = 0;
                        self.iteration += 1;
                    }
                    return;
                };
                self.target = err;
                self.failed_seed = self.seed;
                reportFailure(self.s, err, self.iteration, self.options.iterations, self.seed, self.persona(), self.token_overlay.forced);
                if (!self.options.shrink or self.token != null) {
                    self.mode = .stopped;
                    return;
                }
                self.rec_buf = self.gpa.alloc(u64, self.options.shrink_decisions_max) catch {
                    self.mode = .stopped;
                    return;
                };
                self.print = self.s.config.report;
                self.s.config.report = false;
                self.mode = .recording;
            },
            .recording => {
                const ok = failed_now != null and failed_now.? == self.target.?;
                if (!ok or self.rec.overflowed) {
                    if (self.print) std.debug.print("tardis: not shrinking ({s})\n\n", .{if (self.rec.overflowed) "too many decisions; raise shrink_decisions_max" else "the failure did not reproduce"});
                    self.stop();
                    return;
                }
                self.shrinker = shrink.Shrinker.init(self.gpa, self.rec.keys[0..self.rec.len], &.{}, self.options.shrink_runs_max, self.options.shrink_decisions_max) catch {
                    self.stop();
                    return;
                };
                self.mode = .shrinking;
            },
            .shrinking => self.shrinker.?.result(failed_now != null and failed_now.? == self.target.?),
            .final => {
                reportShrunk(self.s, &self.shrinker.?, self.persona(), self.failed_seed, &self.report, self.print);
                if (self.options.shrink_report) |r| r.* = self.report;
                self.stop();
            },
            .stopped => {},
        }
    }

    fn stop(self: *Simulation) void {
        if (self.mode == .recording or self.mode == .shrinking or self.mode == .final) self.s.config.report = self.print;
        self.mode = .stopped;
    }

    fn beginNext(self: *Simulation) ?*Env {
        switch (self.mode) {
            .campaign => {
                const total: u32 = if (self.replay != null or self.token != null) 1 else self.options.iterations;
                if (self.iteration >= total or self.options.personas.len == 0) {
                    self.finished = true;
                    return null;
                }
                if (self.token) |*t| {
                    self.seed = t.seed;
                    self.s.overlay = &self.token_overlay;
                } else {
                    self.seed = self.replay orelse runSeed(self.options.campaign_seed, self.iteration, self.persona_index);
                }
            },
            .recording => {
                self.rec = decide.Recorder.init(self.rec_buf);
                self.s.recorder = &self.rec;
                self.seed = self.failed_seed;
            },
            .shrinking => {
                const sh = &self.shrinker.?;
                if (sh.next()) |c| {
                    self.overlay = .{ .keep = c.keep, .forced = c.forced };
                    self.s.recorder = c.recorder;
                } else {
                    self.rec = decide.Recorder.init(self.rec_buf);
                    self.overlay = .{ .keep = sh.keep(), .forced = sh.forcedResult() };
                    self.s.recorder = &self.rec;
                    self.mode = .final;
                }
                self.s.overlay = &self.overlay;
                self.seed = self.failed_seed;
            },
            .final => unreachable,
            .stopped => {
                self.finished = true;
                return null;
            },
        }
        self.s.beginRun(self.seed, self.persona());
        self.env = Env.init(self.s, self.iteration);
        self.env.seed = self.seed;
        self.in_progress = true;
        return &self.env;
    }

    /// Verifies campaign-wide assertions. Call after the loop. Returns the
    /// error an iteration reported with `fail`, if any (after shrinking it).
    pub fn finish(self: *Simulation) !void {
        if (self.in_progress) {
            self.s.secEndRun();
            self.s.endRun();
            self.s.overlay = null;
            self.s.recorder = null;
            self.in_progress = false;
        }
        self.stop();
        self.finished = true;
        if (self.target) |err| return err;
        if (self.s.catalog.reportUnsatisfied(self.s.config.report) > 0) return error.SometimesNeverTrue;
    }

    /// Frees the simulator. If an iteration was interrupted (the loop body
    /// returned an error instead of calling `fail`), prints the replay seed.
    pub fn deinit(self: *Simulation) void {
        if (self.in_progress) {
            std.debug.print(
                \\
                \\tardis: iteration {d}/{d} did not complete  persona={s}  seed=0x{x:0>16}
                \\
            , .{ self.iteration + 1, self.options.iterations, @tagName(self.persona()), self.s.seed });
            self.s.trace.dump(16);
            std.debug.print("tardis: replay with:  TARDIS_SEED=0x{x:0>16} TARDIS_PERSONA={s} zig build test\n\n", .{ self.s.seed, @tagName(self.persona()) });
            self.s.endRun();
            self.s.overlay = null;
            self.s.recorder = null;
        }
        if (self.shrinker) |*sh| sh.deinit();
        if (self.rec_buf.len > 0) self.gpa.free(self.rec_buf);
        if (self.token) |*t| t.deinit(self.gpa);
        if (self.token_text) |t| self.gpa.free(t);
        self.s.destroy();
    }
};

/// The imperative form: `while (s.step()) |env| { ... }`. Replays
/// `Options.seed`/`TARDIS_SEED` or a replay token (`Options.replay`,
/// `TARDIS_REPLAY`) when given.
pub fn sim(gpa: Allocator, options: Options) !Simulation {
    const s = try Sim.create(gpa, simConfig(options));
    errdefer s.destroy();
    const env_replay = replayFromEnv(gpa);
    var o = options;
    if (env_replay.persona) |p| {
        for (options.personas, 0..) |q, i| {
            if (q == p) o.personas = options.personas[i..][0..1];
        }
    }
    var result: Simulation = .{
        .s = s,
        .gpa = gpa,
        .options = o,
        .iteration = 0,
        .persona_index = 0,
        .in_progress = false,
        .finished = false,
        .replay = options.seed orelse env_replay.seed,
        .env = undefined,
    };
    const env_token = if (options.replay == null) replayTokenFromEnv(gpa) else null;
    errdefer if (env_token) |t| gpa.free(t);
    if (options.replay orelse env_token) |text| {
        var tok = shrink.parseToken(gpa, text) catch {
            if (s.config.report) std.debug.print("tardis: unparsable replay token \"{s}\"\n", .{text});
            return error.BadReplayToken;
        };
        errdefer tok.deinit(gpa);
        const p = std.meta.stringToEnum(Persona, tok.persona) orelse return error.BadReplayToken;
        // A static one-element slice (the result is returned by value).
        const all = comptime std.enums.values(Persona);
        result.options.personas = all[@backingInt(p)..][0..1];
        result.token_overlay = tok.overlay();
        result.token = tok;
        result.token_text = env_token;
    }
    return result;
}

test {
    _ = @import("sim/decide.zig");
    _ = @import("sim/trace.zig");
    _ = @import("sim/fault.zig");
    _ = @import("check/oracle.zig");
    _ = @import("sim/alloc.zig");
    _ = @import("sim/fiber.zig");
    _ = @import("sim/sched.zig");
    _ = @import("search/fuzz.zig");
    _ = @import("model/vfs.zig");
    _ = @import("model/net.zig");
    _ = @import("search/shrink.zig");
    _ = @import("search/explore.zig");
    _ = @import("check/lin.zig");
    _ = @import("check/elle.zig");
    _ = @import("check/ledger.zig");
    _ = @import("sim/forkserver.zig");
    _ = @import("tests/scheduler_test.zig");
    _ = @import("tests/weak_test.zig");
    _ = @import("tests/syscall_test.zig");
    _ = @import("tests/tsc_test.zig");
    _ = @import("tests/diff_fs_test.zig");
    _ = @import("tests/self_fuzz_test.zig");
    _ = @import("tests/diff_net_test.zig");
    _ = syscalls;
    _ = atomic;
    _ = @import("tests/fs_test.zig");
    _ = @import("tests/bugs_test.zig");
    _ = @import("tests/determinism_test.zig");
    _ = @import("tests/net_test.zig");
    _ = @import("tests/dir_lock_test.zig");
    _ = @import("tests/udp_test.zig");
    _ = @import("tests/link_test.zig");
    _ = @import("tests/atomic_test.zig");
    _ = @import("tests/shrink_test.zig");
    _ = @import("tests/explore_test.zig");
    _ = @import("tests/lin_test.zig");
    _ = @import("tests/elle_test.zig");
    _ = @import("tests/chaos_test.zig");
    _ = @import("tests/parallel_test.zig");
    _ = @import("tests/fork_test.zig");
}
