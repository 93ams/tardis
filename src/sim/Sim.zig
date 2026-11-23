//! The simulator: deterministic scheduler (plan §4) and `std.Io` VTable
//! implementation (plan §4.5, §6.2) over the virtual filesystem.
//!
//! One `Sim` runs one execution at a time. `beginRun` formats fresh state for
//! a seed; `endRun` abandons anything left over. All memory is allocated in
//! `create` except the SUT heap and fuzz arena (see `alloc.zig`).

const Sim = @This();

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const File = Io.File;
const Dir = Io.Dir;

const decide = @import("decide.zig");
const trace_mod = @import("trace.zig");
const fault = @import("fault.zig");
const oracle = @import("../check/oracle.zig");
const alloc_mod = @import("alloc.zig");
const fiber = @import("fiber.zig");
const sched = @import("sched.zig");
const vfs_mod = @import("../model/vfs.zig");
const fuzz = @import("../search/fuzz.zig");
const net_mod = @import("../model/net.zig");
const explore = @import("../search/explore.zig");
const persist = @import("../search/persist.zig");
const seam = @import("sec_seam.zig");
const syscalls = @import("syscalls.zig");
const sysemu = @import("sysemu.zig");
const sysnet = @import("sysnet.zig");
const sysfd = @import("sysfd.zig");
const systhread = @import("systhread.zig");
const ionet = Io.net;

pub const TaskId = sched.TaskId;
pub const Persona = vfs_mod.Persona;
pub const CrashMode = vfs_mod.CrashMode;
pub const Ppm = decide.Ppm;
pub const NodeId = net_mod.NodeId;

const is_windows = builtin.os.tag == .windows;

pub const Limits = struct {
    /// Fiber tasks per run (the root task is extra).
    tasks_max: u16 = 64,
    fiber_stack_bytes: u32 = 256 * 1024,
    /// Budget for `env.allocator` per boot.
    heap_bytes_max: u64 = 64 * 1024 * 1024,
    fuzz_slice_len_max: u32 = 1024,
    trace_ring_len: u32 = 64,
    assertions_max: u32 = 64,
    vfs: vfs_mod.Limits = .{},
    net: net_mod.Limits = .{},
    /// Names registered with `addHost` for virtual DNS.
    hosts_max: u8 = 16,
};

/// How the next task to run is chosen.
pub const Schedule = enum {
    /// At each simulated operation, with probability `preempt_ppm`, the
    /// next task is drawn again, uniformly among those that can run (the
    /// current one included).
    random,
    /// Priorities (PCT: Burckhardt, Kothari, Musuvathi and Nagarakatte,
    /// "A randomized scheduler with probabilistic guarantees of finding
    /// bugs", ASPLOS 2010). Every task gets a random priority when it
    /// starts, and the runnable task with the highest one always runs. At
    /// `pct_depth - 1` points of the run, drawn at its start, the task
    /// that is running drops below every task that has not been dropped.
    /// A run is then a few long stretches, not many short ones. The
    /// paper's bound: a bug of depth `d` (one that `d` ordering
    /// constraints are enough to reach) is found by one run with
    /// probability at least `1 / (n * k^(d-1))`, for `n` tasks and `k`
    /// steps, when the change points are drawn among the run's `k` steps.
    /// Here `k` is `pct_steps`, or a drawn length when that is 0, and
    /// steps are counted only while more than one task can run; a run
    /// longer than `k` has no change point past it.
    ///
    /// Two departures from the paper. A runnable task that has not run
    /// for `pct_spin_max` steps makes the running task drop below every
    /// other, or a task that polls without blocking would keep the task
    /// it waits for out for ever. And `preempt_ppm` is not used, nor the
    /// probability the security layer gives its own preemption points:
    /// a task stops only where it blocks, at a change point, or when a
    /// task above it becomes runnable.
    pct,
};

/// Most change points of a `.pct` run (`pct_depth - 1`).
pub const pct_points_max = 7;
/// Priorities: a task that starts gets one at or above `pct_base`; a
/// change point gives one in `pct_changed..pct_base`; a task that kept
/// another waiting for `pct_spin_max` steps gets the next one below
/// `pct_changed`, counting down.
const pct_base: u32 = 1 << 30;
const pct_changed: u32 = 1 << 29;
/// Steps a runnable task may wait. PCT as published starves every task
/// below one that never blocks; a task that polls without blocking would
/// then run for ever.
pub const pct_spin_max = 4096;

pub const Config = struct {
    preempt_ppm: Ppm = 250_000,
    schedule: Schedule = .random,
    /// `.pct`: the bug depth aimed at, 1 to `pct_points_max + 1`. 1 never
    /// changes a priority: each run is one order of the tasks.
    pct_depth: u8 = 3,
    /// `.pct`: the steps among which the change points are drawn. 0: each
    /// run draws a length from 16 to 16,384, a power of two, since the
    /// length of a run is not known before it ends.
    pct_steps: u32 = 0,
    async_inline_ppm: Ppm = 200_000,
    swarm: bool = true,
    faults: fault.FaultOptions = .{},
    limits: Limits = .{},
    epoch_offset_ns: u64 = 1_700_000_000 * std.time.ns_per_s,
    /// Number of simulated nodes, each with its own filesystem and address.
    nodes: u8 = 1,
    net: net_mod.Options = .{},
    /// Print failure reports and diagnostics to stderr.
    report: bool = true,
    /// Where a reported failure's trace is written, and through which
    /// `std.Io` (`Options.trace_dir`); `trace_caller` names the file.
    trace_dir: ?[]const u8 = null,
    /// The directory came from the options, not the environment: a
    /// failure that is not reported leaves its trace too.
    trace_always: bool = false,
    trace_io: ?Io = null,
    trace_caller: usize = 0,
    /// Fail a run whose code makes a real system call (`syscalls.zig`).
    trap_syscalls: bool = false,
    /// Answer the code's own system calls from the simulation
    /// (`sysemu.zig`, plan §9.2).
    emulate_syscalls: bool = false,
    /// Answer `rdtsc` with virtual time (`tsc.zig`).
    virtual_tsc: bool = false,
    /// An optional security layer (plan2.md §2.2), one instance per `Sim`.
    security: ?seam.Security = null,
};

/// Bytes available for an `async`/`concurrent` context and result.
pub const task_buffer_bytes = 1024;
const task_buffer_align = 64;

const State = enum(u8) { free, runnable, blocked, finished };

const Block = union(enum) {
    none,
    sleep,
    futex: usize,
    await_task: TaskId,
    group: *Io.Group,
    driver,
    net,
    lock,
};

const Start = union(enum) {
    none,
    future: *const fn (context: *const anyopaque, result: *anyopaque) void,
    group: *const fn (context: *const anyopaque) void,
    daemon: *const fn (context: *const anyopaque) void,
};

const Task = struct {
    state: State,
    node: NodeId,
    /// Spawned by `spawnOn` (or by such a task): exempt from task leak checks.
    daemon: bool,
    /// `Schedule.pct`: the highest among the runnable tasks runs.
    prio: u32 = 0,
    /// `Schedule.pct`: when (`pct_clock`) the task last ran, or became
    /// runnable.
    last_ran: u64 = 0,
    /// Decision addressing (M3): spawn path and per-stream draw counters.
    keys: decide.KeyContext,
    /// Tasks spawned by this task so far (gives children stable paths).
    children: u32,
    ctx: fiber.Context,
    stack: []align(16) u8,
    block: Block,
    cancelable_block: bool,
    deadline_ns: ?u64,
    woke_by_timeout: bool,
    cancel_requested: bool,
    cancel_protection: Io.CancelProtection,
    /// Parked inside an emulated system call (system-call mode): dropping
    /// it may leave a C library's lock held (`noteDropped`).
    in_call: bool = false,
    awaiter: ?TaskId,
    group: ?*Io.Group,
    start: Start,
    result_len: usize,
    /// Stores the task made with a weak ordering and other tasks do not
    /// see yet (`atomic.zig`), oldest first.
    stores: [stores_max]PendingStore,
    stores_len: u8,
    context_buf: [task_buffer_bytes]u8 align(task_buffer_align),
    result_buf: [task_buffer_bytes]u8 align(task_buffer_align),
};

/// Per-run cost counters (M4 cost ledger). All integers, so they are
/// as deterministic as the trace.
pub const Stats = struct {
    /// Bytes the program wrote to files (logical).
    disk_write_bytes: u64 = 0,
    disk_read_bytes: u64 = 0,
    disk_syncs: u64 = 0,
    /// Stream bytes and writes, datagrams sent.
    net_bytes: u64 = 0,
    net_writes: u64 = 0,
    datagrams: u64 = 0,
};

pub const Node = struct {
    vfs: vfs_mod.Vfs,
    /// Monotonic clock rate error in ppm (local = global * (1 + drift/1e6)).
    drift_ppm: i32,
    /// Offset of the `.real` clock (NTP steps).
    real_offset_ns: i64,
    crash_count: u32,
    /// The node's volatile heap: wiped when the node crashes.
    heap: alloc_mod.SutAllocator,
};

pub const host_name_bytes_max = 64;

const Host = struct {
    name: [host_name_bytes_max]u8,
    name_len: u8,
    node: NodeId,
};

const stores_max = 8;
const PendingStore = struct { addr: usize, bits: u64, size: u8 };

threadlocal var tls_sim: ?*Sim = null;

gpa: Allocator,
config: Config,

decider: decide.Decider,
trace: trace_mod.Trace,
trace_ring: []trace_mod.Event,
catalog: oracle.Catalog,
catalog_storage: []oracle.Entry,
plan: fault.Plan,
/// The filesystem of the running task's node (updated on every switch).
vfs: *vfs_mod.Vfs,
nodes: []Node,
net: net_mod.Net,
hosts: []Host,
hosts_len: u8,
/// Guided exploration (M3): this run's coverage map, when collecting.
coverage: ?explore.Map,
prev_kind: u64,
/// Shrinking (M3): when set, only these decisions keep their natural value.
overlay: ?*const decide.Overlay,
/// Shrinking (M3): records the keys of natural-valued draws.
recorder: ?*decide.Recorder,
/// Bounded exhaustive exploration: logs every keyed draw's domain.
domain_log: ?*decide.DomainLog,
/// Warm starts without re-running setup (plan §9 M5).
warm: Warm,
/// Fuzzy replay: the (stream, task) pairs the run drew from.
anchors: ?*decide.Anchors,
/// Bounded exhaustive exploration with state merging: what each node and
/// each datagram inbox has seen so far (plan2.md §7.2).
history: ?*History,
/// Bounded exhaustive exploration with reduction: what each scheduling
/// step touched (plan2.md §7.2).
step_log: ?*StepLog,
/// True while `fireTimers` wakes tasks: those wakes are caused by the
/// clock, not by the running step.
in_timers: bool,
/// True while a run repeats one already counted (shrinking, the
/// determinism re-run): layers that tally per run (requirement checks,
/// campaign findings) skip it.
rerun: bool,
/// The campaign iteration being run (0 outside campaigns). With the
/// persona, it orders runs the same way whichever worker ran them.
iteration: u32,
/// Warm starts (M5): when set, `Options.setup` runs first with `setup_seed`,
/// then `reseed` switches to the iteration's seed.
setup_seed: ?u64,
/// The `Options.setup` function (a `*const fn (*Env) anyerror!void`).
setup_fn: ?*const anyopaque,
/// Cost ledger (M4): counters for the current run.
stats: Stats,
/// Chaos (M4): a nemesis runs while active; `generation` retires old ones.
chaos_active: bool,
chaos_generation: u32,
/// `Options.chaos`: started before every body, healed after a drawn duration.
auto_chaos: ?@import("../root.zig").Chaos,
/// Virtual time at which automatic chaos heals (0: no automatic heal).
heal_at_ns: u64,
/// First error returned by a `spawnOn` task this run.
daemon_error: ?anyerror,
daemons_spawned: u32,
/// The security layer's instance, when `Config.security` is set.
sec: ?seam.Attached,
/// Replacement datagram payloads from the security layer (first half) and
/// replayed ones (second half), each one datagram long.
sec_scratch: []u8,
fuzz_arena: std.heap.ArenaAllocator,

now_ns: u64,
tasks: []Task,
stacks: fiber.Stacks,
/// Deadline of each blocked task (`no_timer` if none): a compact copy of
/// `Task.deadline_ns` so timer scans stay in a few cache lines.
timers: []u64,
/// The pending deadlines as a binary min-heap, so the earliest is found
/// without scanning every task. `timers[id]` stays the truth: an entry
/// whose deadline is no longer its task's is stale, and is dropped when it
/// reaches the top.
timer_heap: []TimerEntry,
timer_heap_len: usize,
runq: sched.RunQueue,
runq_words: []u64,
current: TaskId,
root_bounds: fiber.Bounds,
free_ids: []TaskId,
free_len: u32,
deadlocked: bool,
/// Progress watches (`Env.expectProgress`): a run that goes on without
/// feeding one for longer than its bound is a livelock.
watches: [watches_max]Watch = @splat(.{}),
watches_armed: u8 = 0,
/// In a forked iteration's child: reports the run's failure to the parent
/// and exits. The driver the child inherited belongs to the parent's
/// campaign; a deadlock or a livelock must not return through it.
child_abort: ?*const fn (s: *Sim, err: anyerror) noreturn = null,
/// The watch that ran out, once: `drive` then ends the run.
stalled: ?u8 = null,
/// The `std.Io` calls this run made that the simulator does not model
/// (the first `refused.len` distinct names) and how many such calls.
refused: [4][]const u8 = undefined,
refused_len: u8 = 0,
refused_calls: u32 = 0,
/// Scheduling points and simulated operations so far in this run (what a
/// watch's steps count).
sched_points: u64 = 0,
/// `Schedule.pct` (`pctBegin`): steps counted, the steps at which the
/// running task is dropped, and the last priority given to a task that
/// kept another waiting.
pct_step: u64 = 0,
/// Counts those steps and every choice of a next task: what `last_ran`
/// is measured in.
pct_clock: u64 = 0,
pct_points: [pct_points_max]u64 = @splat(0),
pct_points_len: u8 = 0,
pct_floor: u32 = pct_changed,
/// Task running the test body under `check` (0 when none).
control: TaskId,

persona: Persona,
seed: u64,
/// The first runs of a `check` that root.zig's `reportFailure` reported
/// (several with `keep_going`): what a campaign's corpus keeps
/// (`Options.corpus_dir`).
reported: [4]persist.Failed = undefined,
reported_len: u8 = 0,
/// The port the last stream `connect` used, failed or not (system-call
/// mode's `getsockname` after a failed attempt).
last_connect_port: u16 = 0,
boot_count: u32,
crash_count: u32,

pub fn create(gpa: Allocator, config: Config) !*Sim {
    if (!fiber.supported) return error.FibersUnsupported;
    const limits = config.limits;
    assert(limits.tasks_max >= 1);
    assert(limits.fiber_stack_bytes >= 16 * 1024);
    assert(limits.fiber_stack_bytes % 16 == 0);

    const s = try gpa.create(Sim);
    errdefer gpa.destroy(s);
    s.gpa = gpa;
    s.config = config;
    s.decider = .init(0);

    s.trace_ring = try gpa.alloc(trace_mod.Event, limits.trace_ring_len);
    errdefer gpa.free(s.trace_ring);
    s.trace = .init(s.trace_ring);

    s.catalog_storage = try gpa.alloc(oracle.Entry, limits.assertions_max);
    errdefer gpa.free(s.catalog_storage);
    s.catalog = .init(s.catalog_storage);

    s.plan = .init(config.faults);
    assert(config.nodes >= 1 and config.nodes <= net_mod.nodes_limit);
    s.nodes = try gpa.alloc(Node, config.nodes);
    errdefer gpa.free(s.nodes);
    var nodes_ready: usize = 0;
    errdefer for (s.nodes[0..nodes_ready]) |*n| {
        n.vfs.deinit();
        n.heap.deinit();
    };
    for (s.nodes) |*n| {
        // A fresh heap holds no pointers into itself, so it can be moved in.
        var heap: alloc_mod.SutAllocator = try .init(gpa, &s.decider, limits.heap_bytes_max);
        errdefer heap.deinit();
        n.* = .{
            .vfs = try .init(gpa, limits.vfs, .linux_ext4),
            .drift_ppm = 0,
            .real_offset_ns = 0,
            .crash_count = 0,
            .heap = heap,
        };
        nodes_ready += 1;
    }
    s.vfs = &s.nodes[0].vfs;
    s.net = try .init(gpa, limits.net, config.nodes);
    errdefer s.net.deinit();
    s.hosts = try gpa.alloc(Host, limits.hosts_max);
    errdefer gpa.free(s.hosts);
    s.hosts_len = 0;
    s.daemon_error = null;
    s.daemons_spawned = 0;
    s.stats = .{};
    s.chaos_active = false;
    s.chaos_generation = 0;
    s.auto_chaos = null;
    s.heal_at_ns = 0;
    s.setup_seed = null;
    s.setup_fn = null;
    s.overlay = null;
    s.recorder = null;
    s.domain_log = null;
    s.step_log = null;
    s.anchors = null;
    s.warm = .{};
    s.history = null;
    s.in_timers = false;
    s.rerun = false;
    s.iteration = 0;
    s.coverage = null;
    s.prev_kind = 0;
    s.fuzz_arena = .init(gpa);
    errdefer s.fuzz_arena.deinit();
    s.sec = null;
    s.sec_scratch = &.{};
    if (config.security) |sec| {
        // Its tables are per node (a tenant, a sandbox): a node beyond
        // them would go unwatched without a word.
        if (config.nodes > sec.provider.nodes_max) std.debug.panic("tardis: {d} nodes, and the security layer attached to this check watches {d} at most", .{ config.nodes, sec.provider.nodes_max });
        s.sec_scratch = try gpa.alloc(u8, 2 * s.net.datagramCapacity());
        const a: seam.Attached = .{ .provider = sec.provider, .ctx = try sec.provider.create(gpa, sec.params) };
        s.sec = a;
        for (s.nodes, 0..) |*n, i| {
            n.heap.sec = a;
            n.heap.sec_node = @intCast(i);
            n.heap.sec_violation = .{ .ctx = s, .f = secViolationThunk };
        }
    }
    errdefer if (s.sec) |a| {
        a.provider.destroy(gpa, a.ctx);
        gpa.free(s.sec_scratch);
    };

    const task_count = @as(usize, limits.tasks_max) + 1;
    s.tasks = try gpa.alloc(Task, task_count);
    errdefer gpa.free(s.tasks);
    s.stacks = try fiber.Stacks.init(limits.tasks_max, limits.fiber_stack_bytes);
    errdefer s.stacks.deinit();
    s.timers = try gpa.alloc(u64, task_count);
    errdefer gpa.free(s.timers);
    @memset(s.timers, std.math.maxInt(u64));
    s.timer_heap = try gpa.alloc(TimerEntry, 4 * task_count);
    errdefer gpa.free(s.timer_heap);
    s.timer_heap_len = 0;
    s.runq_words = try gpa.alloc(u64, (task_count + 63) / 64);
    errdefer gpa.free(s.runq_words);
    s.runq = .init(s.runq_words);
    s.free_ids = try gpa.alloc(TaskId, task_count);
    errdefer gpa.free(s.free_ids);

    for (s.tasks, 0..) |*t, i| {
        t.state = .free;
        t.stores_len = 0;
        if (i == 0) {
            t.stack = &.{};
        } else {
            t.stack = s.stacks.stack(i - 1);
            fiber.paintCanary(t.stack);
        }
    }
    s.now_ns = 0;
    s.current = 0;
    s.root_bounds = .{ .base = 0, .limit = 0 };
    s.free_len = 0;
    s.deadlocked = false;
    s.watchReset();
    s.child_abort = null;
    s.control = 0;
    s.persona = .linux_ext4;
    s.seed = 0;
    s.boot_count = 0;
    s.crash_count = 0;
    return s;
}

pub fn destroy(s: *Sim) void {
    const gpa = s.gpa;
    if (tls_sim == s) tls_sim = null;
    gpa.free(s.free_ids);
    gpa.free(s.runq_words);
    gpa.free(s.timers);
    gpa.free(s.timer_heap);
    s.stacks.deinit();
    gpa.free(s.tasks);
    s.fuzz_arena.deinit();
    if (s.sec) |a| {
        a.provider.destroy(gpa, a.ctx);
        gpa.free(s.sec_scratch);
    }
    s.warm.drop(gpa);
    gpa.free(s.hosts);
    s.net.deinit();
    for (s.nodes) |*n| {
        n.vfs.deinit();
        n.heap.deinit();
    }
    gpa.free(s.nodes);
    gpa.free(s.catalog_storage);
    gpa.free(s.trace_ring);
    gpa.destroy(s);
}

pub fn io(s: *Sim) Io {
    return .{ .userdata = s, .vtable = &vtable };
}

/// Returns the simulator behind `io`, or null if `io` is not a TARDIS io.
pub fn fromIo(i: Io) ?*Sim {
    if (i.vtable != &vtable) return null;
    return @ptrCast(@alignCast(i.userdata.?));
}

fn fromUserdata(userdata: ?*anyopaque) *Sim {
    return @ptrCast(@alignCast(userdata.?));
}

// ===========================================================================
// Run lifecycle

pub fn beginRun(s: *Sim, seed: u64, persona: Persona) void {
    tls_sim = s;
    s.seed = seed;
    s.persona = persona;
    s.decider = .init(seed);
    // Every draw of the run, from here on, is keyed (M3).
    s.tasks[0].keys = .root;
    s.tasks[0].children = 0;
    s.decider.ctx = &s.tasks[0].keys;
    s.decider.overlay = s.overlay;
    s.decider.recorder = s.recorder;
    s.decider.domain_log = s.domain_log;
    s.decider.anchors = s.anchors;
    s.decider.on_draw = if (s.history != null) .{ .ctx = s, .f = historyDraw } else null;
    s.decider.on_natural = .{ .ctx = s, .f = recordDecision };
    if (s.sec) |a| a.provider.begin_run(a.ctx, seed);
    if (s.coverage) |m| m.clear();
    s.prev_kind = 0;
    s.plan = .init(s.config.faults);
    if (s.config.swarm) s.plan.drawSwarm(&s.decider);
    s.trace.reset();
    s.now_ns = 0;
    const drift_max = s.config.faults.clock_drift_ppm_max;
    const drift_on = drift_max > 0 and s.plan.isEnabled(.clock_drift);
    for (s.nodes) |*n| {
        n.vfs.reset(persona);
        n.real_offset_ns = 0;
        n.crash_count = 0;
        n.drift_ppm = 0;
        n.heap.reset();
        n.heap.oom_ppm = if (s.plan.isEnabled(.oom)) s.config.faults.oom_ppm else 0;
        if (drift_on) {
            const span: u64 = 2 * @as(u64, drift_max);
            n.drift_ppm = @as(i32, @intCast(s.decider.range(.clock, 0, span))) - @as(i32, @intCast(drift_max));
        }
    }
    s.vfs = &s.nodes[0].vfs;
    s.net.reset();
    s.hosts_len = 0;
    s.daemon_error = null;
    s.daemons_spawned = 0;
    s.stats = .{};
    s.chaos_active = false;
    s.heal_at_ns = 0;
    _ = s.fuzz_arena.reset(.retain_capacity);
    s.boot_count = 1;
    s.crash_count = 0;
    s.deadlocked = false;
    s.watchReset();
    s.control = 0;
    s.root_bounds = fiber.currentBounds();

    for (s.tasks) |*t| t.state = .free;
    s.runq.clear();
    @memset(s.timers, no_timer);
    s.timer_heap_len = 0;
    s.current = 0;
    s.resetTask(0);
    s.tasks[0].state = .runnable;
    s.runq.insert(0);
    s.rebuildFreeList();
    s.pctBegin();
}

/// The keys of a `.pct` run's own draws. The task that runs the body
/// starts its counters at 0 (`drive`), so draws made here on a task's
/// keys would be the body's first draws over again.
const pct_key_path: u64 = 0x5043_5400_0000_0001;

/// Draws what a `.pct` run needs: where its change points are, and a
/// priority for each task that exists. At the start of a run and again
/// at `reseed`, so that a run started from a snapshot of its setup and
/// one that ran its setup continue alike.
fn pctBegin(s: *Sim) void {
    s.pct_step = 0;
    s.pct_clock = 0;
    s.pct_floor = pct_changed;
    s.pct_points_len = 0;
    if (s.config.schedule != .pct) return;
    var keys: decide.KeyContext = .{ .path = pct_key_path, .counters = @splat(0) };
    const ctx = s.decider.ctx;
    s.decider.ctx = &keys;
    defer s.decider.ctx = ctx;
    const depth: usize = @max(1, @min(s.config.pct_depth, pct_points_max + 1));
    const steps: u64 = if (s.config.pct_steps != 0) s.config.pct_steps else @as(u64, 16) << @intCast(s.decider.uniform(.schedule, 11));
    // A point is a step number from 1; 0, the benign draw, is no point.
    for (s.pct_points[0 .. depth - 1]) |*p| p.* = s.decider.uniform(.schedule, steps + 1);
    s.pct_points_len = @intCast(depth - 1);
    for (s.tasks) |*t| {
        if (t.state == .free) continue;
        t.prio = pct_base + @as(u32, @intCast(s.decider.uniform(.schedule, 1 << 20)));
        t.last_ran = 0;
    }
}

/// The priority of a task that starts: the first scheduling decision on
/// the task's own keys, which no other draw has.
fn pctSpawned(s: *Sim, t: *Task) void {
    const ctx = s.decider.ctx;
    s.decider.ctx = &t.keys;
    defer s.decider.ctx = ctx;
    t.prio = pct_base + @as(u32, @intCast(s.decider.uniform(.schedule, 1 << 20)));
}

/// The runnable task with the highest priority. Among equals the current
/// task stays, or else the lowest id runs: with every draw benign (a
/// shrink candidate) that is the order the random schedule has too,
/// until a task has waited `pct_spin_max` steps.
fn pctBest(s: *Sim) TaskId {
    assert(s.runq.count > 0);
    var best: TaskId = 0;
    var best_prio: u32 = 0;
    var found = false;
    for (s.runq.words, 0..) |word, w| {
        var rest = word;
        while (rest != 0) : (rest &= rest - 1) {
            const id: TaskId = @intCast(w * 64 + @ctz(rest));
            const p = s.tasks[id].prio;
            if (!found or p > best_prio or (p == best_prio and id == s.current)) {
                best = id;
                best_prio = p;
                found = true;
            }
        }
    }
    return best;
}

/// A simulated operation under `.pct`, with more than one task runnable:
/// counts the step, drops the current task at a change point or when
/// another has waited too long, and says whether another task must run
/// now.
fn pctStep(s: *Sim) bool {
    const t = &s.tasks[s.current];
    s.pct_step += 1;
    s.pct_clock += 1;
    t.last_ran = s.pct_clock;
    for (s.pct_points[0..s.pct_points_len], 0..) |p, i| {
        if (p == s.pct_step) t.prio = pct_base - 1 - @as(u32, @intCast(i));
    }
    s.pctFair();
    return s.pctBest() != s.current;
}

/// A task that could run and has not for `pct_spin_max` steps: the task
/// about to run, which is above it, goes below every other. Tasks above
/// it that take turns by blocking go one at a time, `pct_spin_max` steps
/// apart.
fn pctFair(s: *Sim) void {
    var starved = false;
    for (s.runq.words, 0..) |word, w| {
        var rest = word;
        while (rest != 0) : (rest &= rest - 1) {
            starved = starved or s.pct_clock - s.tasks[w * 64 + @ctz(rest)].last_ran > pct_spin_max;
        }
    }
    if (!starved) return;
    const best = &s.tasks[s.pctBest()];
    // The one that waited is the one about to run.
    if (s.pct_clock - best.last_ran > pct_spin_max) return;
    s.pct_floor -= 1;
    best.prio = s.pct_floor;
    for (s.runq.words, 0..) |word, w| {
        var rest = word;
        while (rest != 0) : (rest &= rest - 1) {
            const other = &s.tasks[w * 64 + @ctz(rest)];
            if (s.pct_clock - other.last_ran > pct_spin_max) other.last_ran = s.pct_clock;
        }
    }
}

pub fn endRun(s: *Sim) void {
    assert(s.current == 0);
    // A daemon parked in `accept` or `read` when a run ends is normal for
    // a server, so these drops are not noted (`noteDropped`): only a
    // crash's are. What such a daemon's C library holds is still the
    // process's.
    for (s.tasks) |*t| t.in_call = false;
    s.abandonAllExcept(0, 0);
    s.plan.clearTargeted();
}

fn resetTask(s: *Sim, id: TaskId) void {
    const t = &s.tasks[id];
    t.node = 0;
    t.daemon = false;
    t.block = .none;
    t.cancelable_block = false;
    t.deadline_ns = null;
    t.woke_by_timeout = false;
    t.cancel_requested = false;
    t.in_call = false;
    t.cancel_protection = .unblocked;
    t.awaiter = null;
    t.group = null;
    t.start = .none;
    t.result_len = 0;
    t.stores_len = 0;
}

/// Rebuilds the free list so that ids are handed out lowest first.
fn rebuildFreeList(s: *Sim) void {
    s.free_len = 0;
    var i: usize = s.tasks.len;
    while (i > 1) {
        i -= 1;
        if (s.tasks[i].state != .free) continue;
        s.free_ids[s.free_len] = @intCast(i);
        s.free_len += 1;
    }
}

/// Drops every task except `keep_a` and `keep_b` without running them
/// further (a crash, or the end of a run).
fn abandonAllExcept(s: *Sim, keep_a: TaskId, keep_b: TaskId) void {
    for (s.tasks, 0..) |*t, i| {
        if (i == keep_a or i == keep_b) continue;
        if (t.state == .free) continue;
        s.noteDropped(t);
        t.state = .free;
        s.runq.remove(@intCast(i));
    }
    s.rebuildFreeList();
}

/// A task is dropped without running further. If it was inside an
/// emulated system call, the C library that made the call may hold a
/// lock or be half way through changing its own state, and that state is
/// the process's: later runs inherit it (plan §9.2).
fn noteDropped(s: *Sim, t: *const Task) void {
    if (t.state == .finished or !t.in_call) return;
    if (syscalls.dropped_in_call_seed == null) {
        syscalls.dropped_in_call_seed = s.seed;
        if (s.config.report) std.debug.print("tardis: a task was dropped inside a system call (seed=0x{x}): a C library it was in may keep a lock or half-changed state into later runs\n", .{s.seed});
    }
}

fn recordDecision(ctx: *anyopaque, stream: decide.Stream, key: u64, forced: bool) void {
    const s: *Sim = @ptrCast(@alignCast(ctx));
    s.record(.decision, @backingInt(stream), key, @intFromBool(forced), @tagName(stream));
}

/// One scheduling step of a run: a task running from the point it was
/// chosen until it next yields or blocks, with what it touched outside its
/// own node. Two steps that are `independent` leave the same state in
/// either order.
pub const Step = struct {
    task: TaskId,
    node: NodeId,
    /// Keyed draws logged when the step ended (`open_end` while it runs).
    end_draws: usize = open_end,
    /// The tasks runnable when it was chosen (bit per task id).
    runnable: u64,
    /// The tasks it woke.
    woke: u64 = 0,
    /// The datagram inboxes (node, port) it read or wrote.
    inboxes: [inboxes_max]u32 = undefined,
    inboxes_len: u8 = 0,
    /// It did something whose effect on other nodes is not tracked, so it
    /// is dependent with every step.
    global: bool,

    pub const inboxes_max = 6;
    pub const open_end = std.math.maxInt(usize);

    fn bit(id: TaskId) u64 {
        return @as(u64, 1) << @as(u6, @intCast(id));
    }

    pub fn independent(a: *const Step, b: *const Step) bool {
        if (a.global or b.global) return false;
        // Tasks of one node share its memory, files and sockets.
        if (a.node == b.node) return false;
        if (a.woke & bit(b.task) != 0 or b.woke & bit(a.task) != 0) return false;
        for (a.inboxes[0..a.inboxes_len]) |x| {
            for (b.inboxes[0..b.inboxes_len]) |y| if (x == y) return false;
        }
        return true;
    }

    /// True when `b`, run right after `a`, could have run before it with
    /// the same result, and that order comes first in the search (the
    /// lower task id first): this order need not be explored.
    pub fn redundantAfter(b: *const Step, a: *const Step) bool {
        if (b.task >= a.task) return false;
        if (a.runnable & bit(b.task) == 0) return false;
        return a.independent(b);
    }
};

pub const StepLog = struct {
    steps: []Step,
    len: usize = 0,
    /// More steps than fit: the later ones are not logged.
    overflowed: bool = false,

    pub fn init(buffer: []Step) StepLog {
        return .{ .steps = buffer };
    }

    pub fn slice(l: *const StepLog) []const Step {
        return l.steps[0..l.len];
    }
};

/// The state `Options.setup` leaves, kept so that later iterations start
/// from a copy of it instead of running setup again.
///
/// Setup is deterministic (it runs with the campaign's setup seed), so
/// every iteration's setup on one persona leaves the same state. There is
/// one snapshot per persona (`Shot`). A snapshot holds what
/// setup can change in a simulator that is otherwise as `beginRun` leaves
/// it: each node's filesystem (sharing its pages, `Vfs.Snapshot`) and
/// clock offset, the virtual time, the body task's decision counters, the
/// trace so far, the coverage bits, the cost counters and the host names.
/// It is only taken when setup changed nothing else: no task, socket,
/// heap block or open handle is left, no link was cut, nothing crashed, no
/// assertion was counted, and no security layer or decision overlay is
/// attached. Otherwise setup runs every iteration, as before.
///
/// A filesystem's snapshot shares its pages with the running filesystem,
/// and a filesystem holds the pages of one state: when a run on another
/// persona begins, the snapshot whose pages are there (`resident`) copies
/// them out, and a warm start on its persona later copies them back. A
/// campaign on one persona never copies.
///
/// Every `check_every`-th use of a snapshot runs setup for real and
/// compares the result with it. A difference turns warm starts off for
/// the rest of the simulator's life.
pub const Warm = struct {
    /// Warm starts are given up for the rest of the simulator's life.
    off: bool = false,
    /// False: setup runs every iteration (`Options.warm_restore`).
    enabled: bool = true,
    /// This run re-runs setup to compare it with the snapshot of
    /// `verified`. Still set at the next run: setup did not finish.
    verifying: bool = false,
    verified: Persona = undefined,
    /// Assertion catalog totals before setup: setup must not count any.
    catalog_len: usize = 0,
    catalog_reached: u64 = 0,
    /// Warm starts made from a snapshot, and setups re-run to check one.
    restores: u64 = 0,
    checks: u64 = 0,
    mismatches: u64 = 0,
    interruptions: u8 = 0,
    /// One snapshot per persona: a campaign takes its personas in turn.
    shots: [personas_len]Shot = @splat(.{}),
    /// The persona whose snapshot's pages are in the filesystems now,
    /// pinned. Any other snapshot holds a copy of its pages.
    resident: ?Persona = null,

    pub const personas_len = std.enums.values(Persona).len;
    pub const check_every = 64;
    /// Runs that could not use the snapshots before warm starts give up.
    pub const interruptions_max = 4;

    const Clock = struct { drift_ppm: i32, real_offset_ns: i64 };

    /// What setup left on one persona.
    pub const Shot = struct {
        ready: bool = false,
        /// The filesystems' pages are copied into `files` (`Vfs.savePages`).
        saved: bool = false,
        /// Warm starts from this snapshot and checks of it.
        uses: u64 = 0,
        setup_seed: u64 = 0,
        now_ns: u64 = 0,
        stats: Stats = .{},
        keys: decide.KeyContext = .root,
        keyed_draws: u64 = 0,
        last_key: u64 = 0,
        prev_kind: u64 = 0,
        trace_hash: u64 = 0,
        trace_count: u64 = 0,
        ring_next: usize = 0,
        ring: []trace_mod.Event = &.{},
        coverage: []u64 = &.{},
        hosts: []Host = &.{},
        clocks: []Clock = &.{},
        files: []vfs_mod.Vfs.Snapshot = &.{},

        fn drop(t: *Shot, gpa: Allocator) void {
            for (t.files) |*f| f.deinit(gpa);
            gpa.free(t.files);
            gpa.free(t.clocks);
            gpa.free(t.hosts);
            gpa.free(t.coverage);
            gpa.free(t.ring);
            t.* = .{};
        }
    };

    /// True if a snapshot is held.
    pub fn active(w: *const Warm) bool {
        for (w.shots) |t| if (t.ready) return true;
        return false;
    }

    fn drop(w: *Warm, gpa: Allocator) void {
        for (&w.shots) |*t| t.drop(gpa);
        w.resident = null;
    }
};

fn catalogReached(s: *const Sim) u64 {
    var n: u64 = 0;
    for (s.catalog.entries[0..s.catalog.len]) |e| n += e.reached_count;
    return n;
}

/// True if this run may start from a snapshot, or have one taken: a plain
/// campaign run, with nothing that changes or watches setup's decisions.
fn warmPlainRun(s: *const Sim) bool {
    return s.warm.enabled and !s.warm.off and s.sec == null and s.overlay == null and
        s.recorder == null and s.domain_log == null and s.anchors == null and
        s.step_log == null and s.history == null and s.auto_chaos == null;
}

/// True if the simulator differs from a fresh run only in what the
/// snapshot holds.
fn warmOnlySnapshotState(s: *const Sim) bool {
    // Setup and the body run on one task (`control`); the root task
    // waits for it.
    const me = s.current;
    if (me != s.control or s.runq.count != 1 or s.timer_heap_len != 0) return false;
    // A progress watch armed by setup is not in a snapshot, and neither
    // are the unmodelled calls setup made.
    if (s.watches_armed != 0 or s.refused_len != 0) return false;
    for (s.tasks, 0..) |t, i| {
        if (i != 0 and i != me and t.state != .free) return false;
    }
    if (s.tasks[me].children != 0 or s.tasks[me].stores_len != 0 or s.daemons_spawned != 0) return false;
    if (s.daemon_error != null or s.deadlocked or s.chaos_active or s.heal_at_ns != 0) return false;
    if (s.boot_count != 1 or s.crash_count != 0) return false;
    if (s.plan.hasTargeted() or !s.net.pristine()) return false;
    if (s.catalog.len != s.warm.catalog_len or s.catalogReached() != s.warm.catalog_reached) return false;
    for (s.nodes) |*n| {
        if (n.crash_count != 0 or !n.heap.pristine() or !n.vfs.noHandles()) return false;
    }
    return true;
}

/// Another persona's run is about to write the filesystems, whose pages
/// the resident snapshot shares: the snapshot gets its own copy of them.
/// Called on freshly reset filesystems, before anything is written.
fn warmEvict(s: *Sim) void {
    const w = &s.warm;
    const r = w.resident orelse return;
    w.resident = null;
    const t = &w.shots[@backingInt(r)];
    if (!t.ready or t.saved) return;
    for (s.nodes, t.files) |*n, *f| {
        n.vfs.savePages(f, s.gpa) catch {
            t.drop(s.gpa);
            return;
        };
    }
    t.saved = true;
}

/// Before setup: starts the run from the snapshot if there is one. True
/// if it did, and setup must not run.
pub fn warmRestore(s: *Sim) bool {
    const w = &s.warm;
    if (w.verifying) {
        // The last check's setup never reached `warmCapture`: the pages
        // it was rewriting may not be the snapshot's any more.
        w.shots[@backingInt(w.verified)].drop(s.gpa);
        if (w.resident == w.verified) w.resident = null;
    }
    w.verifying = false;
    if (!s.warmPlainRun()) {
        // This run's setup may decide differently (a shrink candidate, a
        // replay) and write other bytes into the pages a snapshot
        // shares, which `reset` has just freed: the snapshots go.
        if (w.active()) {
            w.drop(s.gpa);
            w.interruptions += 1;
            w.off = w.interruptions > Warm.interruptions_max;
        }
        w.resident = null;
        return false;
    }
    w.catalog_len = s.catalog.len;
    w.catalog_reached = s.catalogReached();
    if (w.resident != s.persona) s.warmEvict();
    const t = &w.shots[@backingInt(s.persona)];
    if (!t.ready) return false;
    if (t.setup_seed != s.seed) {
        // Another setup seed: its setup leaves another state.
        t.drop(s.gpa);
        w.resident = null;
        return false;
    }
    if (t.uses % Warm.check_every == 0) {
        // Setup runs and writes the pages itself; `warmCapture` compares.
        w.verifying = true;
        w.verified = s.persona;
        return false;
    }
    t.uses += 1;
    w.restores += 1;
    for (s.nodes, t.files, t.clocks) |*n, *f, c| {
        if (w.resident == null) n.vfs.loadPages(f);
        n.vfs.restore(f);
        n.drift_ppm = c.drift_ppm;
        n.real_offset_ns = c.real_offset_ns;
    }
    w.resident = s.persona;
    s.now_ns = t.now_ns;
    s.stats = t.stats;
    s.tasks[s.current].keys = t.keys;
    s.decider.keyed_draws = t.keyed_draws;
    s.decider.last_key = t.last_key;
    s.prev_kind = t.prev_kind;
    s.trace.hash = t.trace_hash;
    s.trace.count = t.trace_count;
    s.trace.ring_next = t.ring_next;
    @memcpy(s.trace.ring, t.ring);
    if (s.coverage) |m| @memcpy(m.words, t.coverage);
    @memcpy(s.hosts[0..t.hosts.len], t.hosts);
    s.hosts_len = @intCast(t.hosts.len);
    return true;
}

/// After setup ran: takes the snapshot, or compares this setup's result
/// with it.
pub fn warmCapture(s: *Sim) void {
    const w = &s.warm;
    if (!s.warmPlainRun()) return;
    if (!s.warmOnlySnapshotState()) {
        w.drop(s.gpa);
        w.off = true;
        return;
    }
    const t = &w.shots[@backingInt(s.persona)];
    if (t.ready) {
        if (!w.verifying) return;
        w.verifying = false;
        t.uses += 1;
        w.checks += 1;
        var same = s.now_ns == t.now_ns and s.trace.hash == t.trace_hash and s.trace.count == t.trace_count and
            std.meta.eql(s.tasks[s.current].keys, t.keys) and s.hosts_len == t.hosts.len;
        for (s.nodes, t.files, t.clocks) |*n, *f, c| {
            same = same and n.vfs.matches(f) and n.drift_ppm == c.drift_ppm and n.real_offset_ns == c.real_offset_ns;
            if (same and t.saved) same = n.vfs.pagesMatch(f);
        }
        if (!same) {
            w.mismatches += 1;
            w.drop(s.gpa);
            w.off = true;
            return;
        }
        // The pages this setup wrote are the snapshot's: pin them again.
        for (s.nodes, t.files) |*n, *f| n.vfs.restore(f);
        w.resident = s.persona;
        return;
    }
    s.warmTake(t) catch {
        w.drop(s.gpa);
        w.off = true;
    };
}

fn warmTake(s: *Sim, t: *Warm.Shot) !void {
    const gpa = s.gpa;
    t.ring = try gpa.dupe(trace_mod.Event, s.trace.ring);
    t.coverage = if (s.coverage) |m| try gpa.dupe(u64, m.words[0..]) else &.{};
    t.hosts = try gpa.dupe(Host, s.hosts[0..s.hosts_len]);
    t.clocks = try gpa.alloc(Warm.Clock, s.nodes.len);
    for (s.nodes, t.clocks) |n, *c| c.* = .{ .drift_ppm = n.drift_ppm, .real_offset_ns = n.real_offset_ns };
    const files = try gpa.alloc(vfs_mod.Vfs.Snapshot, s.nodes.len);
    var taken: usize = 0;
    errdefer {
        // The nodes whose snapshot was taken keep no reference for it.
        for (s.nodes[0..taken], files[0..taken]) |*n, *f| {
            n.vfs.unpin();
            f.deinit(gpa);
        }
        gpa.free(files);
    }
    for (s.nodes, files) |*n, *f| {
        f.* = try n.vfs.snapshot(gpa);
        taken += 1;
    }
    t.files = files;
    t.setup_seed = s.seed;
    t.now_ns = s.now_ns;
    t.stats = s.stats;
    t.keys = s.tasks[s.current].keys;
    t.keyed_draws = s.decider.keyed_draws;
    t.last_key = s.decider.last_key;
    t.prev_kind = s.prev_kind;
    t.trace_hash = s.trace.hash;
    t.trace_count = s.trace.count;
    t.ring_next = s.trace.ring_next;
    t.ready = true;
    s.warm.resident = s.persona;
}

/// What a run has done so far, kept so that two runs that did the same
/// things in a different order get the same value (`state`), and are known
/// to be in the same state.
///
/// Each node has a hash of its own events in their order: what its tasks
/// did, which of them ran, and every keyed draw they made with its value.
/// Each datagram inbox has a hash of its sends, receives, binds and closes
/// in their order. Everything else (streams, spawns, crashes, link
/// changes, futexes, clock steps, time advancing) is folded together with
/// all of the above at the moment it happens, so nothing is reordered
/// across it.
///
/// A task's behaviour is a function of what it observes: its draws, its
/// node's files and memory, what it receives, and the clock. So equal
/// histories mean equal states, as long as tasks on different nodes share
/// no memory except through the simulator (the assumption of
/// `ExhaustiveOptions.reduce`).
pub const History = struct {
    nodes: []u64,
    global: u64 = 0,
    inbox_keys: [inboxes_max]u32 = undefined,
    inbox_hashes: [inboxes_max]u64 = undefined,
    inboxes_len: u8 = 0,
    points: []Point,
    len: usize = 0,
    /// Something the histories do not capture: no more points are logged.
    blind: bool = false,

    pub const inboxes_max = 32;

    /// The state before a scheduling choice: the keyed draws logged so
    /// far, and the state's hash.
    pub const Point = struct { draws: usize, state: u64 };

    pub fn init(nodes: []u64, points: []Point) History {
        @memset(nodes, 0);
        return .{ .nodes = nodes, .points = points };
    }

    pub fn slice(h: *const History) []const Point {
        return h.points[0..h.len];
    }

    fn combined(h: *const History) u64 {
        var x = h.global;
        for (h.nodes, 0..) |n, i| x = decide.mix(x, decide.mix(i, n));
        // Inboxes in no order: they are found in the order they are used.
        var inboxes: u64 = 0;
        for (h.inbox_keys[0..h.inboxes_len], h.inbox_hashes[0..h.inboxes_len]) |k, v| inboxes +%= decide.mix(k, v);
        return decide.mix(x, inboxes);
    }
};

/// An event that stays inside the current task's node.
fn historyNode(s: *Sim, kind: trace_mod.Kind, a: u64, b: u64, c: u64, label: []const u8) void {
    const h = s.history orelse return;
    const n = &h.nodes[s.tasks[s.current].node];
    const lh: u64 = if (label.len == 0) 0 else explore.labelHash(label);
    n.* = decide.mix(decide.mix(n.*, (@as(u64, @backingInt(kind)) << 16) | s.current), decide.mix(decide.mix(a, b), decide.mix(c, lh)));
}

/// An event that may matter to any node: nothing commutes with it.
fn historyGlobal(s: *Sim, x: u64) void {
    const h = s.history orelse return;
    h.global = decide.mix(h.combined(), x);
}

/// The current task used the datagram inbox at (node, port).
fn historyInbox(s: *Sim, node: NodeId, port: u16) void {
    const h = s.history orelse return;
    const key = (@as(u32, node) << 16) | port;
    const at = for (h.inbox_keys[0..h.inboxes_len], 0..) |k, i| {
        if (k == key) break i;
    } else blk: {
        if (h.inboxes_len == History.inboxes_max) {
            h.blind = true;
            return;
        }
        h.inbox_keys[h.inboxes_len] = key;
        h.inbox_hashes[h.inboxes_len] = 0;
        h.inboxes_len += 1;
        break :blk h.inboxes_len - 1;
    };
    // Who used it, and what that node had done until then.
    const me = s.tasks[s.current].node;
    h.inbox_hashes[at] = decide.mix(h.inbox_hashes[at], decide.mix(me, h.nodes[me]));
}

/// A keyed draw and its value. The scheduler's own draws are left out:
/// what they chose shows as the tasks that ran.
fn historyDraw(ctx: *anyopaque, stream: decide.Stream, key: u64, value: u64) void {
    const s: *Sim = @ptrCast(@alignCast(ctx));
    const h = s.history orelse return;
    if (stream == .schedule) return;
    const n = &h.nodes[s.tasks[s.current].node];
    n.* = decide.mix(n.*, decide.mix(key, value));
}

/// The state before a scheduling choice.
fn historyPoint(s: *Sim) void {
    const h = s.history orelse return;
    // A security layer keeps state across nodes, and a pending targeted
    // fault counts operations on every node: the histories miss both.
    if (s.sec != null or s.plan.hasTargeted()) h.blind = true;
    if (h.blind or h.len == h.points.len) {
        h.blind = true;
        return;
    }
    var x = decide.mix(h.combined(), s.now_ns);
    for (s.runq.words) |w| x = decide.mix(x, w);
    h.points[h.len] = .{ .draws = if (s.domain_log) |l| l.len else 0, .state = x };
    h.len += 1;
}

/// The step being run, if steps are logged.
fn stepNow(s: *Sim) ?*Step {
    const l = s.step_log orelse return null;
    if (l.len == 0 or l.overflowed) return null;
    const st = &l.steps[l.len - 1];
    return if (st.end_draws == Step.open_end) st else null;
}

/// The running step did something that may matter to any other step.
pub fn touchGlobal(s: *Sim) void {
    if (s.stepNow()) |st| st.global = true;
    s.historyGlobal(0x6C0BA1);
}

/// The running step read or wrote the datagram inbox at (node, port).
fn touchInbox(s: *Sim, node: NodeId, port: u16) void {
    s.historyInbox(node, port);
    const st = s.stepNow() orelse return;
    const key = (@as(u32, node) << 16) | port;
    for (st.inboxes[0..st.inboxes_len]) |k| if (k == key) return;
    if (st.inboxes_len == Step.inboxes_max) {
        st.global = true;
        return;
    }
    st.inboxes[st.inboxes_len] = key;
    st.inboxes_len += 1;
}

/// The running step ends: the current task yields or blocks.
fn endStep(s: *Sim) void {
    const st = s.stepNow() orelse return;
    // A pending targeted fault counts operations on every node.
    if (s.plan.hasTargeted()) st.global = true;
    st.end_draws = if (s.domain_log) |l| l.len else 0;
}

/// `next` was chosen to run.
fn beginStep(s: *Sim, next: TaskId) void {
    const l = s.step_log orelse return;
    if (l.len == l.steps.len) {
        l.overflowed = true;
        return;
    }
    // A security layer keeps state across nodes (taint by content), and
    // tasks beyond the mask cannot be tracked: no reduction then.
    var global = s.sec != null or next >= 64 or s.plan.hasTargeted();
    for (s.runq.words[1..]) |w| global = global or w != 0;
    l.steps[l.len] = .{
        .task = next,
        .node = s.tasks[next].node,
        .runnable = s.runq.words[0],
        .global = global,
    };
    l.len += 1;
}

fn record(s: *Sim, kind: trace_mod.Kind, a: u64, b: u64, c: u64, label: []const u8) void {
    s.trace.record(s.now_ns, s.current, kind, a, b, c, label);
    if (s.step_log != null or s.history != null) switch (kind) {
        // The task's own keyed draws: folded as they are made.
        .decision => {},
        // Which task runs on its node (not which one ran before it, on
        // whatever node).
        .switch_to => s.historyNode(kind, 0, b, 0, ""),
        // Time moves when nothing can run: the same in every order, and
        // after it nothing is as before.
        .clock_advance => s.historyGlobal(decide.mix(@backingInt(kind), a)),
        // Scheduling, and the node's files.
        .sleep, .finish, .random => s.historyNode(kind, a, b, c, label),
        .open, .create, .close, .read, .write, .sync, .set_length, .stat => s.historyNode(kind, a, b, c, label),
        .delete, .rename, .mkdir, .dir_read, .fs_link, .chmod => s.historyNode(kind, a, b, c, label),
        // Datagram operations name their inboxes at the call (`touchInbox`).
        // Their socket slots and handles depend on which node bound
        // first, so they are left out: the inbox says which socket.
        .net_send, .net_receive => s.historyNode(kind, 0, b, c, label),
        .net_bind => s.historyNode(kind, a, b, 0, label),
        .net_close => s.historyNode(kind, 0, 0, 0, label),
        else => {
            s.touchGlobal();
            s.historyGlobal(decide.mix(decide.mix(@backingInt(kind), a), decide.mix(b, c)));
        },
    };
    if (s.coverage) |m| {
        switch (kind) {
            // Scheduling noise and decision markers are not behaviour.
            .switch_to, .clock_advance, .sleep, .decision, .spawn, .finish => {},
            else => {
                const lh: u64 = if (label.len == 0) 0 else explore.labelHash(label);
                m.set(decide.mix(decide.mix(s.prev_kind, @backingInt(kind)), lh));
                s.prev_kind = @backingInt(kind);
            },
        }
    }
}

// ===========================================================================
// Scheduler

fn boundsOf(s: *Sim, id: TaskId) fiber.Bounds {
    if (id == 0) return s.root_bounds;
    return fiber.boundsOf(s.tasks[id].stack);
}

fn checkCanary(s: *Sim, id: TaskId) void {
    if (id == 0) return;
    if (!fiber.canaryIntact(s.tasks[id].stack)) {
        std.debug.print("tardis: stack overflow in task {d} (seed=0x{x}); raise limits.fiber_stack_bytes\n", .{ id, s.seed });
        @panic("tardis: fiber stack overflow");
    }
}

fn switchToTask(s: *Sim, next: TaskId) void {
    const prev = s.current;
    if (prev == next) return;
    s.checkCanary(prev);
    s.current = next;
    s.vfs = &s.nodes[s.tasks[next].node].vfs;
    s.decider.ctx = &s.tasks[next].keys;
    s.record(.switch_to, prev, next, 0, "");
    // The system-call trap's selector is this fiber's (`syscalls.zig`).
    const selector = syscalls.selectorSave();
    s.tasks[prev].in_call = syscalls.parkedInCall(selector);
    fiber.switchTo(&s.tasks[prev].ctx, &s.tasks[next].ctx, s.boundsOf(next));
    syscalls.selectorRestore(selector);
    // Resumed: whoever switched back to us set `current`.
    assert(s.current == prev);
}

fn wake(s: *Sim, id: TaskId) void {
    const t = &s.tasks[id];
    if (t.state != .blocked) return;
    t.state = .runnable;
    t.block = .none;
    t.cancelable_block = false;
    t.deadline_ns = null;
    s.timers[id] = no_timer;
    s.runq.insert(id);
    t.last_ran = s.pct_clock;
    if (!s.in_timers) s.secSync(.wake, s.current, id);
    if (!s.in_timers) if (s.stepNow()) |st| {
        if (id < 64) st.woke |= @as(u64, 1) << @as(u6, @intCast(id)) else st.global = true;
    };
}

const no_timer = std.math.maxInt(u64);

const TimerEntry = struct {
    deadline: u64,
    id: TaskId,

    fn before(a: TimerEntry, b: TimerEntry) bool {
        return if (a.deadline != b.deadline) a.deadline < b.deadline else a.id < b.id;
    }
};

/// A task blocked with a deadline. When the heap is full of stale entries
/// it is rebuilt from `timers`, which holds at most one per task.
fn timerPush(s: *Sim, deadline: u64, id: TaskId) void {
    if (s.timer_heap_len == s.timer_heap.len) {
        s.timer_heap_len = 0;
        for (s.timers, 0..) |d, i| {
            if (d != no_timer and i != id) s.timerInsert(.{ .deadline = d, .id = @intCast(i) });
        }
    }
    s.timerInsert(.{ .deadline = deadline, .id = id });
}

fn timerInsert(s: *Sim, e: TimerEntry) void {
    const h = s.timer_heap;
    var i = s.timer_heap_len;
    s.timer_heap_len += 1;
    while (i > 0) {
        const parent = (i - 1) / 2;
        if (!e.before(h[parent])) break;
        h[i] = h[parent];
        i = parent;
    }
    h[i] = e;
}

fn timerPop(s: *Sim) void {
    const h = s.timer_heap;
    s.timer_heap_len -= 1;
    const n = s.timer_heap_len;
    if (n == 0) return;
    const e = h[n];
    var i: usize = 0;
    while (true) {
        var child = 2 * i + 1;
        if (child >= n) break;
        if (child + 1 < n and h[child + 1].before(h[child])) child += 1;
        if (!h[child].before(e)) break;
        h[i] = h[child];
        i = child;
    }
    h[i] = e;
}

/// The earliest live entry, after dropping the stale ones above it: those
/// whose task was woken, re-blocked with another deadline, or is no longer
/// blocked (freed, dropped), whose `timers` slot is cleared here.
fn timerTop(s: *Sim) ?TimerEntry {
    while (s.timer_heap_len > 0) {
        const e = s.timer_heap[0];
        if (s.timers[e.id] == e.deadline) {
            const t = &s.tasks[e.id];
            if (t.state == .blocked and t.deadline_ns != null) return e;
            s.timers[e.id] = no_timer;
        }
        s.timerPop();
    }
    return null;
}

/// Wakes every blocked task whose deadline has passed.
fn fireTimers(s: *Sim) void {
    s.in_timers = true;
    defer s.in_timers = false;
    while (s.timerTop()) |e| {
        if (e.deadline > s.now_ns) return;
        s.timerPop();
        s.tasks[e.id].woke_by_timeout = true;
        s.wake(e.id);
    }
}

fn earliestDeadline(s: *Sim) ?u64 {
    const e = s.timerTop() orelse return null;
    return e.deadline;
}

/// Picks the next task and switches to it. Returns when the current task is
/// next resumed. The current task may or may not be runnable.
fn reschedule(s: *Sim) void {
    s.endStep();
    while (true) {
        s.fireTimers();
        if (s.runq.count > 0) {
            s.sched_points += 1;
            if (s.watches_armed > 0 and s.watchStalls()) {
                // As a deadlock: the driver ends the run. It runs next, not
                // by a draw, so the run ends here whatever else is runnable.
                s.beginStep(0);
                s.switchToTask(0);
                return;
            }
            s.historyPoint();
            const next = if (s.config.schedule == .pct) next: {
                s.pct_clock += 1;
                s.pctFair();
                const best = s.pctBest();
                s.tasks[best].last_ran = s.pct_clock;
                break :next best;
            } else s.runq.pickNth(s.decider.uniform(.schedule, s.runq.count));
            s.beginStep(next);
            s.switchToTask(next);
            return;
        }
        if (s.earliestDeadline()) |d| {
            assert(d > s.now_ns);
            s.record(.clock_advance, d - s.now_ns, 0, 0, "");
            s.now_ns = d;
            continue;
        }
        // Nothing runnable and no timers: deadlock.
        s.record(.deadlock, 0, 0, 0, "");
        const root = &s.tasks[0];
        if (root.state == .blocked and root.block == .driver and !s.deadlocked) {
            s.deadlocked = true;
            s.wake(0);
            continue;
        }
        s.dumpTasks();
        std.debug.print("tardis: deadlock: no runnable task and no pending timer (seed=0x{x} persona={s})\n", .{ s.seed, @tagName(s.persona) });
        s.trace.dump(16);
        @panic("tardis: deadlock");
    }
}

pub const watches_max = 8;

/// One progress watch. A bound of 0 is not checked.
pub const Watch = struct {
    armed: bool = false,
    label: u64 = 0,
    name: []const u8 = "",
    within_ns: u64 = 0,
    within_steps: u64 = 0,
    last_ns: u64 = 0,
    last_step: u64 = 0,
};

fn watchReset(s: *Sim) void {
    s.refused_len = 0;
    s.refused_calls = 0;
    s.watches = @splat(.{});
    s.watches_armed = 0;
    s.stalled = null;
    s.sched_points = 0;
}

fn watchSlot(s: *Sim, label: u64) ?*Watch {
    for (&s.watches) |*w| if (w.armed and w.label == label) return w;
    return null;
}

/// Arms (or re-arms with new bounds) the watch `label`, fed now.
pub fn watchArm(s: *Sim, label: u64, name: []const u8, within_ns: u64, within_steps: u64) void {
    const w = s.watchSlot(label) orelse blk: {
        for (&s.watches) |*free| if (!free.armed) {
            s.watches_armed += 1;
            break :blk free;
        };
        @panic("tardis: too many progress watches in one run (8)");
    };
    w.* = .{ .armed = true, .label = label, .name = name, .within_ns = within_ns, .within_steps = within_steps, .last_ns = s.now_ns, .last_step = s.sched_points };
}

/// Progress was made on `label`. False when no such watch is armed.
pub fn watchFeed(s: *Sim, label: u64) bool {
    const w = s.watchSlot(label) orelse return false;
    w.last_ns = s.now_ns;
    w.last_step = s.sched_points;
    return true;
}

pub fn watchDisarm(s: *Sim, label: u64) void {
    const w = s.watchSlot(label) orelse return;
    w.armed = false;
    s.watches_armed -= 1;
}

/// Whether a watch has just run out: the driver is then runnable and must
/// run next. Once per run, and only under `check` (a driver to end it).
fn watchStalls(s: *Sim) bool {
    if (s.stalled != null) return false;
    const w = s.watchExpired() orelse return false;
    const root = &s.tasks[0];
    if (root.state != .blocked or root.block != .driver) return false;
    s.stalled = w;
    s.record(.note, 0, 0, 0, "livelock");
    s.wake(0);
    return true;
}

/// A simulated operation is a step for the watches whether or not the
/// simulator switches tasks at it: a task that spins is found when it runs
/// alone, and when no preemption is drawn (a shrink candidate, a replay,
/// `preempt_ppm = 0`), where it would otherwise spin for ever.
fn watchStep(s: *Sim) void {
    s.sched_points += 1;
    if (!s.watchStalls()) return;
    s.endStep();
    s.beginStep(0);
    s.switchToTask(0);
}

fn watchExpired(s: *Sim) ?u8 {
    for (&s.watches, 0..) |*w, i| {
        if (!w.armed) continue;
        if (w.within_ns != 0 and s.now_ns - w.last_ns > w.within_ns) return @intCast(i);
        if (w.within_steps != 0 and s.sched_points - w.last_step > w.within_steps) return @intCast(i);
    }
    return null;
}

fn block(s: *Sim, reason: Block, deadline_ns: ?u64, cancelable: bool) void {
    s.atomicFlush();
    const id = s.current;
    const t = &s.tasks[id];
    assert(t.state == .runnable);
    t.state = .blocked;
    t.block = reason;
    t.cancelable_block = cancelable;
    t.deadline_ns = deadline_ns;
    s.timers[id] = deadline_ns orelse no_timer;
    if (deadline_ns) |d| s.timerPush(d, id);
    t.woke_by_timeout = false;
    s.runq.remove(id);
    s.reschedule();
    assert(s.tasks[id].state == .runnable);
}

/// Writes the current task's buffered stores to memory, oldest first.
pub fn atomicFlush(s: *Sim) void {
    const t = &s.tasks[s.current];
    for (t.stores[0..t.stores_len]) |p| {
        const dst: [*]u8 = @ptrFromInt(p.addr);
        @memcpy(dst[0..p.size], std.mem.asBytes(&p.bits)[0..p.size]);
    }
    t.stores_len = 0;
}

/// The current task stores `bits` to `addr` with a weak ordering: other
/// tasks see it when the buffer drains.
pub fn atomicBuffer(s: *Sim, addr: usize, bits: u64, size: u8) void {
    const t = &s.tasks[s.current];
    if (t.stores_len == stores_max) s.atomicFlush();
    t.stores[t.stores_len] = .{ .addr = addr, .bits = bits, .size = size };
    t.stores_len += 1;
}

/// The current task's latest buffered store to `addr`, if any.
pub fn atomicBuffered(s: *Sim, addr: usize) ?u64 {
    const t = &s.tasks[s.current];
    var i: usize = t.stores_len;
    while (i > 0) {
        i -= 1;
        if (t.stores[i].addr == addr) return t.stores[i].bits;
    }
    return null;
}

/// An atomic operation: memory other tasks (on any node) may share, and
/// a point where another task may run. The task's buffered stores drain
/// here unless a keyed decision holds them (benign: they drain).
pub fn atomicPoint(s: *Sim, hold_ppm: decide.Ppm) void {
    s.touchGlobal();
    if (s.tasks[s.current].stores_len > 0 and !s.decider.chance(.schedule, hold_ppm)) s.atomicFlush();
    if (s.watches_armed > 0) s.watchStep();
    if (s.runq.count <= 1) return;
    if (s.config.schedule == .pct) {
        if (s.pctStep()) s.reschedule();
        return;
    }
    if (!s.decider.chance(.schedule, s.config.preempt_ppm)) return;
    s.reschedule();
}

/// A scheduling point: possibly yield to another runnable task.
fn maybeYield(s: *Sim) void {
    s.atomicFlush(); // a simulated operation: the store buffer has drained
    if (s.watches_armed > 0) s.watchStep();
    if (s.runq.count <= 1) return;
    if (s.config.schedule == .pct) {
        if (s.pctStep()) s.reschedule();
        return;
    }
    if (!s.decider.chance(.schedule, s.config.preempt_ppm)) return;
    s.reschedule();
}

fn sleepUntil(s: *Sim, deadline_ns: u64, cancelable: bool) void {
    s.record(.sleep, deadline_ns -| s.now_ns, 0, 0, "");
    s.block(.sleep, deadline_ns, cancelable);
}

/// Consumes a pending cancel request if the task observes cancelation.
fn cancelPoint(s: *Sim) Io.Cancelable!void {
    const t = &s.tasks[s.current];
    if (!t.cancel_requested) return;
    if (t.cancel_protection == .blocked) return;
    t.cancel_requested = false;
    s.record(.cancel, 1, 0, 0, "");
    return error.Canceled;
}

fn requestCancel(s: *Sim, id: TaskId) void {
    const t = &s.tasks[id];
    if (t.state == .free or t.state == .finished) return;
    t.cancel_requested = true;
    s.record(.cancel, 0, id, 0, "");
    if (t.state == .blocked and t.cancelable_block and t.cancel_protection == .unblocked) s.wake(id);
}

fn dumpTasks(s: *Sim) void {
    std.debug.print("tardis: tasks at virtual time {d} ns:\n", .{s.now_ns});
    for (s.tasks, 0..) |*t, i| {
        if (t.state == .free) continue;
        std.debug.print("  task {d}: {s}", .{ i, @tagName(t.state) });
        if (t.state == .blocked) {
            std.debug.print(" on {s}", .{@tagName(t.block)});
            if (t.deadline_ns) |d| std.debug.print(" until {d} ns", .{d});
        }
        std.debug.print("\n", .{});
    }
}

// ===========================================================================
// Task spawning and completion

fn allocTask(s: *Sim) ?TaskId {
    if (s.free_len == 0) return null;
    s.free_len -= 1;
    const id = s.free_ids[s.free_len];
    assert(s.tasks[id].state == .free);
    return id;
}

fn freeTask(s: *Sim, id: TaskId) void {
    assert(id != 0);
    const t = &s.tasks[id];
    t.state = .free;
    s.runq.remove(id);
    s.free_ids[s.free_len] = id;
    s.free_len += 1;
}

fn fitsBuffer(len: usize, alignment: std.mem.Alignment) bool {
    return len <= task_buffer_bytes and alignment.toByteUnits() <= task_buffer_align;
}

const Trampoline = fiber.Trampoline(&fiberMain);

fn spawn(s: *Sim, start: Start, context: []const u8, group: ?*Io.Group, result_len: usize) ?TaskId {
    const id = s.allocTask() orelse return null;
    s.resetTask(id);
    const t = &s.tasks[id];
    t.node = s.tasks[s.current].node;
    t.daemon = s.tasks[s.current].daemon;
    const parent = &s.tasks[s.current];
    t.keys = parent.keys.child(parent.children);
    t.children = 0;
    parent.children += 1;
    t.last_ran = s.pct_clock;
    if (s.config.schedule == .pct) s.pctSpawned(t);
    t.start = start;
    t.group = group;
    t.result_len = result_len;
    @memcpy(t.context_buf[0..context.len], context);
    t.ctx = fiber.initContext(t.stack, Trampoline.entry);
    t.state = .runnable;
    s.runq.insert(id);
    s.record(.spawn, id, @intFromBool(group != null), 0, "");
    s.secSync(.spawn, s.current, id);
    return id;
}

fn fiberMain() callconv(.c) noreturn {
    syscalls.fiberEntry();
    const s = tls_sim.?;
    const id = s.current;
    const t = &s.tasks[id];
    switch (t.start) {
        .future => |f| f(&t.context_buf, &t.result_buf),
        .group, .daemon => |f| f(&t.context_buf),
        .none => unreachable,
    }
    s.finishCurrent();
}

fn finishCurrent(s: *Sim) noreturn {
    s.atomicFlush();
    const id = s.current;
    const t = &s.tasks[id];
    s.record(.finish, id, 0, 0, "");
    s.runq.remove(id);
    if (t.group) |g| s.secSync(.release, id, @intFromPtr(g)) else if (t.start != .daemon) s.secSync(.release, id, seam.futureKey(id));
    if (t.group) |g| {
        t.group = null;
        assert(g.state > 0);
        g.state -= 1;
        if (g.state == 0) s.wakeGroupWaiters(g);
        // The slot is reused only by a later spawn, which runs on another
        // stack after we have switched away.
        s.freeTask(id);
    } else if (t.start == .daemon) {
        s.freeTask(id);
    } else {
        t.state = .finished;
        if (t.awaiter) |a| s.wake(a);
    }
    s.reschedule();
    unreachable; // a finished task is never resumed
}

fn wakeGroupWaiters(s: *Sim, g: *Io.Group) void {
    for (s.tasks, 0..) |*t, i| {
        if (t.state != .blocked) continue;
        switch (t.block) {
            .group => |bg| if (bg == g) s.wake(@intCast(i)),
            else => {},
        }
    }
}

// ===========================================================================
// Driver (used by `tardis.check`)

pub const Body = *const fn (ctx: *anyopaque) anyerror!void;

const ControlContext = struct {
    body: Body,
    ctx: *anyopaque,
};

fn controlStart(context: *const anyopaque, result: *anyopaque) void {
    const c: *const ControlContext = @ptrCast(@alignCast(context));
    const r: *anyerror!void = @ptrCast(@alignCast(result));
    r.* = c.body(c.ctx);
}

pub const DriveResult = struct {
    outcome: anyerror!void,
    control: TaskId,
};

/// Runs `body` on a control fiber until it finishes or the run deadlocks.
/// Must be called from the root task.
/// Key path of the driver task (task 0) under `check`.
const driver_key_path: u64 = 0xD71E_5EED_0000_0001;

pub fn drive(s: *Sim, body: Body, ctx: *anyopaque) DriveResult {
    assert(s.current == 0);
    const cc: ControlContext = .{ .body = body, .ctx = ctx };
    const id = s.spawn(.{ .future = controlStart }, std.mem.asBytes(&cc), null, @sizeOf(anyerror!void)) orelse
        @panic("tardis: no task slot for the control fiber");
    const t = &s.tasks[id];
    // The body draws the decisions the root task would under `tardis.sim`,
    // so replay tokens work under either entry point. The driver (task 0)
    // gets its own path so its draws never share a key with the body's.
    t.keys = .root;
    s.tasks[0].keys = .{ .path = driver_key_path, .counters = @splat(0) };
    s.control = id;
    defer s.control = 0;
    while (t.state != .finished) {
        if (s.deadlocked) {
            if (s.child_abort) |abort| abort(s, error.Deadlock);
            if (s.config.report) s.dumpTasks();
            return .{ .outcome = error.Deadlock, .control = id };
        }
        if (s.stalled) |i| {
            if (s.child_abort) |abort| abort(s, error.Livelock);
            const w = &s.watches[i];
            if (s.config.report) {
                std.debug.print("tardis: livelock: no progress on \"{s}\" for {d} ms of virtual time and {d} scheduling points (bounds: {d} ms, {d} points; 0 is unchecked)\n", .{
                    w.name,
                    (s.now_ns - w.last_ns) / std.time.ns_per_ms,
                    s.sched_points - w.last_step,
                    w.within_ns / std.time.ns_per_ms,
                    w.within_steps,
                });
                s.dumpTasks();
            }
            return .{ .outcome = error.Livelock, .control = id };
        }
        t.awaiter = 0;
        s.block(.driver, null, false);
    }
    const r: *const (anyerror!void) = @ptrCast(@alignCast(&t.result_buf));
    return .{ .outcome = r.*, .control = id };
}

// ===========================================================================
// Services used by `Env`

/// Must be called from the test body (the root task under `sim`, the
/// control task under `check`), which survives the crash; every other task
/// is dropped.
pub fn crashAndReboot(s: *Sim, mode: CrashMode) void {
    if (s.current != 0 and s.current != s.control) {
        @panic("tardis: crashAndReboot must be called from the test body, not from a spawned task");
    }
    for (s.nodes, 0..) |*n, i| s.crashVfs(&n.vfs, @intCast(i), mode);
    s.dropTasks(null);
    s.net.reset();
    sysemu.dropNode(null);
    sysnet.dropNode(null);
    sysfd.dropNode(null);
    systhread.dropNode(null);
    for (s.nodes) |*n| n.heap.reset();
    s.plan.clearTargeted();
    s.boot_count += 1;
    s.crash_count += 1;
}

fn crashVfs(s: *Sim, v: *vfs_mod.Vfs, node: NodeId, mode: CrashMode) void {
    const f = s.config.faults;
    const report = v.crash(
        mode,
        &s.decider,
        f.torn_writes and s.plan.isEnabled(.torn_write),
        f.metadata_loss and s.plan.isEnabled(.metadata_loss),
    );
    s.nodes[node].crash_count += 1;
    if (node == 0) {
        s.record(.crash, @backingInt(mode), report.journal_ops_kept, report.inodes_torn, @tagName(mode));
    } else {
        s.record(.node_crash, node, report.journal_ops_kept, report.inodes_torn, @tagName(mode));
    }
}

/// Drops every task (on `node`, or on every node when null) except the root
/// and the caller, without running them further.
fn dropTasks(s: *Sim, node: ?NodeId) void {
    // Dropped group members no longer count as pending, so a surviving
    // `group.await` returns instead of hanging. Writing to a group that lived
    // on a dropped stack is harmless: stacks stay mapped for the Sim's lifetime.
    for (s.tasks, 0..) |*t, i| {
        if (i == 0 or i == s.current) continue;
        if (t.state == .free or t.state == .finished) continue;
        if (node) |n| if (t.node != n) continue;
        const g = t.group orelse continue;
        t.group = null;
        g.state -|= 1;
        if (g.state == 0) {
            g.token.store(null, .release);
            s.wakeGroupWaiters(g);
        }
    }
    // Under `check`, the root is the driver; it stays blocked on the control fiber.
    for (s.tasks, 0..) |*t, i| {
        if (i == 0 or i == s.current) continue;
        if (t.state == .free) continue;
        if (node) |n| if (t.node != n) continue;
        s.noteDropped(t);
        t.state = .free;
        s.runq.remove(@intCast(i));
    }
    s.rebuildFreeList();
}

/// Crashes and immediately reboots one node: its tasks are dropped (except
/// the caller, if it is the test body), its filesystem keeps only what
/// `mode` lets survive, and its sockets disappear; peers on other nodes see
/// a reset or, for black-holed connections, a timeout.
pub fn crashNode(s: *Sim, node: NodeId, mode: CrashMode) void {
    assert(node < s.nodes.len);
    const body = s.current == 0 or s.current == s.control;
    if (!body and s.tasks[s.current].node == node) {
        @panic("tardis: crashNode called from a task on the node being crashed");
    }
    s.crashVfs(&s.nodes[node].vfs, node, mode);
    s.dropTasks(node);
    sysemu.dropNode(node);
    sysnet.dropNode(node);
    sysfd.dropNode(node);
    systhread.dropNode(node);
    s.nodes[node].heap.reset();
    const freed = s.net.crashNode(node, s.now_ns, &s.decider, s.config.net);
    s.record(.net_fault, node, freed, 0, "node crash");
    s.netWakeAll();
}

/// Cuts (`up == false`) or heals the directed link `from -> to`.
pub fn setLink(s: *Sim, from: NodeId, to: NodeId, up: bool) void {
    assert(from < s.nodes.len and to < s.nodes.len);
    s.net.setLink(from, to, up, s.now_ns, &s.decider, s.config.net);
    s.record(.link, from, to, @intFromBool(up), if (up) "heal" else "cut");
    s.netWakeAll();
}

/// Steps node `node`'s real-time clock by `delta_ns` (an NTP step).
pub fn stepClock(s: *Sim, node: NodeId, delta_ns: i64) void {
    s.nodes[node].real_offset_ns += delta_ns;
    s.record(.clock_step, node, @bitCast(delta_ns), 0, "");
}

/// Starts `start(context)` as a daemon task on `node`. Daemons are not
/// awaited; they end when they return, when their node crashes, or when the
/// run ends.
pub fn spawnDaemon(s: *Sim, node: NodeId, start: *const fn (context: *const anyopaque) void, context: []const u8, context_alignment: std.mem.Alignment) error{ ConcurrencyUnavailable, NoSuchNode }!void {
    if (node >= s.nodes.len) return error.NoSuchNode;
    if (!fitsBuffer(context.len, context_alignment)) return error.ConcurrencyUnavailable;
    const id = s.spawn(.{ .daemon = start }, context, null, 0) orelse return error.ConcurrencyUnavailable;
    s.tasks[id].node = node;
    s.tasks[id].daemon = true;
    s.daemons_spawned += 1;
    s.record(.node_spawn, node, id, 0, "");
}

/// Called by a daemon wrapper when the daemon returned an error.
pub fn daemonFailed(s: *Sim, err: anyerror) void {
    s.record(.note, s.tasks[s.current].node, @intFromError(err), 0, @errorName(err));
    if (s.daemon_error == null) s.daemon_error = err;
}

/// The security layer found a violation: the run fails with
/// `error.SecurityViolation` (the layer keeps the details).
/// `what` goes into the trace: the kind of finding where the caller knows
/// it, otherwise where it was seen.
pub fn securityFailed(s: *Sim, cwe: u16, what: []const u8) void {
    // In the trace: a = node, b = CWE (docs/trace.md).
    var label: [trace_mod.label_bytes_max]u8 = undefined;
    const text = std.fmt.bufPrint(&label, "security: {s}", .{what[0..@min(what.len, label.len - 10)]}) catch unreachable;
    s.record(.note, s.tasks[s.current].node, cwe, 0, text);
    if (s.daemon_error == null) s.daemon_error = error.SecurityViolation;
}

/// The constants the run compared against, from the security layer
/// (comparison feedback for guided exploration).
pub fn secTokens(s: *Sim) []const u64 {
    const a = s.sec orelse return &.{};
    const f = a.provider.tokens orelse return &.{};
    return f(a.ctx);
}

/// The body returned: the security layer checks the run as a whole.
pub fn secEndRun(s: *Sim) void {
    const a = s.sec orelse return;
    const cwe = a.provider.end_run(a.ctx);
    if (cwe != 0) s.securityFailed(cwe, "found at the end of the run");
}

/// The security layer's key for this run's first finding (seam 4): 0
/// without a layer, without findings, or if the layer gives no keys.
pub fn secFindingKey(s: *Sim) u64 {
    const a = s.sec orelse return 0;
    const f = a.provider.finding_key orelse return 0;
    return f(a.ctx);
}

/// Fork server: the layer's per-run tallies, packed in the child (0 bytes
/// without a layer or without the hook).
pub fn secForkExport(s: *Sim, out: []u8) usize {
    const a = s.sec orelse return 0;
    const f = a.provider.fork_export orelse return 0;
    return @min(f(a.ctx, out), out.len);
}

/// ... and unpacked in the parent.
pub fn secForkImport(s: *Sim, bytes: []const u8) void {
    const a = s.sec orelse return;
    const f = a.provider.fork_import orelse return;
    f(a.ctx, bytes);
}

/// Seam 4: the campaign is over (`check` returning).
pub fn secCampaignEnd(s: *Sim, end: *const seam.CampaignEnd) void {
    const a = s.sec orelse return;
    const f = a.provider.campaign_end orelse return;
    f(a.ctx, end);
}

fn secViolationThunk(ctx: *anyopaque, cwe: u16) void {
    const s: *Sim = @ptrCast(@alignCast(ctx));
    s.securityFailed(cwe, "reported by the layer");
}

fn secEgress(s: *Sim, sink: seam.Sink, bytes: []const u8) void {
    const a = s.sec orelse return;
    if (bytes.len == 0) return;
    const cwe = a.provider.egress(a.ctx, sink, bytes);
    if (cwe != 0) s.securityFailed(cwe, "in bytes leaving the node");
}

/// The first `n` bytes of `data` were just filled from `sink`.
fn secIngress(s: *Sim, sink: seam.Sink, data: []const []u8, n: usize) void {
    const a = s.sec orelse return;
    var left = n;
    for (data) |d| {
        if (left == 0) break;
        const k = @min(d.len, left);
        a.provider.ingress(a.ctx, sink, d[0..k]);
        left -= k;
    }
}

/// Tells the security layer what orders tasks (`seam.TaskSync`).
fn secSync(s: *Sim, op: seam.TaskSync, a: usize, b: usize) void {
    const at = s.sec orelse return;
    const f = at.provider.task_sync orelse return;
    f(at.ctx, op, a, b);
}

/// A path about to be used: the security layer's sink check (untrusted
/// bytes in a path, plan2.md §5.2). A violation fails the run at its end.
fn secPath(s: *Sim, op: seam.VfsOp, path: []const u8) void {
    const a = s.sec orelse return;
    const cwe = a.provider.path(a.ctx, s.currentNode(), op, path);
    if (cwe != 0) s.securityFailed(cwe, "in a path");
}

/// A capability about to be used (plan2.md §5.2). A violation fails the
/// run at its end; the call itself goes on unchanged.
fn secCapability(s: *Sim, cap: seam.Capability, argv: []const []const u8) void {
    const a = s.sec orelse return;
    const cwe = a.provider.capability(a.ctx, s.currentNode(), cap, argv);
    if (cwe != 0) s.securityFailed(cwe, "a capability the sandbox lacks");
}

/// Where a parent swap moves the original directory.
const toctou_aside = ".tardis-toctou-aside";

/// A filesystem operation the layer may answer with a swap: the attacker's
/// move, between the check and this use. A swap whose target is missing
/// leaves the entry as it was.
fn secVfs(s: *Sim, op: seam.VfsOp, parent: vfs_mod.InodeId, path: []const u8) void {
    const a = s.sec orelse return;
    const swap = a.provider.vfs_op(a.ctx, s.currentNode(), op, parent, path) orelse return;
    s.syncClock();
    switch (swap.kind) {
        .symlink => {
            s.vfs.deleteFile(parent, path) catch return;
            s.vfs.symLink(parent, swap.target, path) catch return;
            s.record(.fs_link, parent, 3, 0, "toctou swap");
        },
        .hard_link => {
            const ino = s.vfs.lookup(parent, swap.target) catch return;
            if (s.vfs.inodes[ino].kind != .file) return;
            s.vfs.deleteFile(parent, path) catch return;
            s.vfs.hardLink(ino, parent, path) catch return;
            s.record(.fs_link, parent, 4, 0, "toctou hard link");
        },
        .parent_symlink => {
            const end = for (path, 0..) |c, i| {
                if (c == '/' or (c == '\\' and s.vfs.persona.backslashSeparator())) break i;
            } else return;
            const first = path[0..end];
            if (first.len == 0 or std.mem.eql(u8, first, ".") or std.mem.eql(u8, first, "..")) return;
            s.vfs.rename(parent, first, parent, toctou_aside) catch return;
            s.vfs.symLink(parent, swap.target, first) catch return;
            s.record(.fs_link, parent, 5, 0, "toctou parent swap");
        },
        .directory => {
            s.vfs.deleteFile(parent, path) catch return;
            _ = s.vfs.makeDir(parent, path) catch return;
            s.record(.fs_link, parent, 6, 0, "toctou directory");
        },
    }
}

/// A preemption point the security layer adds where core has none (a
/// second read of shared memory, plan2.md §4.1): with probability `ppm`,
/// as a keyed scheduling decision, another task runs first.
pub fn preemptionPoint(s: *Sim, ppm: Ppm) void {
    if (s.runq.count <= 1) return;
    if (s.config.schedule == .pct) {
        if (s.pctStep()) s.reschedule();
        return;
    }
    if (!s.decider.chance(.schedule, ppm)) return;
    s.reschedule();
}

fn fileSink(s: *Sim, ino: vfs_mod.InodeId) seam.Sink {
    const node = s.currentNode();
    return .{ .kind = .file, .node = node, .peer_node = node, .id = ino };
}

fn socketSink(s: *Sim, kind: seam.Sink.Kind, slot: u16, peer_node: NodeId) seam.Sink {
    return .{ .kind = kind, .node = s.net.sockets[slot].node, .peer_node = peer_node, .id = slot };
}

pub fn active() *Sim {
    return tls_sim.?;
}

/// The simulator running on this thread, if any.
pub fn activeOrNull() ?*Sim {
    return tls_sim;
}

pub fn currentNode(s: *const Sim) NodeId {
    return s.tasks[s.current].node;
}

/// Registers `name` in virtual DNS as node `node`'s address.
pub fn addHost(s: *Sim, name: []const u8, node: NodeId) void {
    assert(node < s.nodes.len);
    if (name.len > host_name_bytes_max) @panic("tardis: host name too long");
    if (s.hosts_len == s.hosts.len) @panic("tardis: too many hosts (raise limits.hosts_max)");
    const h = &s.hosts[s.hosts_len];
    @memcpy(h.name[0..name.len], name);
    h.name_len = @intCast(name.len);
    h.node = node;
    s.hosts_len += 1;
}

pub fn advanceTime(s: *Sim, delta_ns: u64) void {
    s.sleepUntil(s.now_ns + delta_ns, false);
}

pub const LeakReport = struct {
    tasks: u32,
    handles: u32,
    allocations: u64,
    sockets: u32 = 0,

    pub fn any(r: LeakReport) bool {
        return r.tasks != 0 or r.handles != 0 or r.allocations != 0 or r.sockets != 0;
    }
};

/// Live resources at the end of the test body. Daemon tasks are never
/// counted. A node with a live daemon is skipped entirely, since its
/// daemons own that node's handles, sockets and heap legitimately; every
/// other node (and node 0's heap, which backs `env.allocator`) must be clean.
/// A crashed node's heap is wiped, so a crash does not strand allocations.
pub fn leaks(s: *Sim, exclude: TaskId) LeakReport {
    var r: LeakReport = .{ .tasks = 0, .handles = 0, .allocations = 0 };
    var daemon_nodes: u128 = 0;
    for (s.tasks, 0..) |*t, i| {
        if (i == 0 or i == s.current or i == exclude) continue;
        if (t.state == .free) continue;
        if (t.daemon) {
            daemon_nodes |= @as(u128, 1) << @intCast(t.node);
        } else {
            r.tasks += 1;
        }
    }
    for (s.nodes, 0..) |*node, i| {
        if (daemon_nodes & (@as(u128, 1) << @intCast(i)) != 0) continue;
        r.handles += node.vfs.openHandleCount();
        r.allocations += node.heap.live_count;
        r.sockets += s.net.openCountOn(@intCast(i));
    }
    return r;
}

pub fn generator(s: *Sim) fuzz.Generator {
    return .{
        .decider = &s.decider,
        .allocator = s.fuzz_arena.allocator(),
        .slice_len_max = s.config.limits.fuzz_slice_len_max,
    };
}

// ===========================================================================
// Fault helpers

fn injected(s: *Sim, comptime E: type, op: fault.OpKind) ?E {
    if (s.plan.takeTargeted(op)) |err| {
        s.record(.fault, @backingInt(op), 1, 0, @errorName(err));
        return fault.castError(E, err);
    }
    const probabilistic = switch (op) {
        .read, .write, .sync => true,
        else => false,
    };
    if (probabilistic and s.plan.isEnabled(.io_error) and s.decider.chance(.fault, s.config.faults.io_error_ppm)) {
        s.record(.fault, @backingInt(op), 0, 0, "InputOutput");
        return fault.castError(E, error.InputOutput);
    }
    return null;
}

/// Common prologue for operations that may be canceled.
fn enter(s: *Sim, comptime E: type) E!void {
    if (comptime fault.hasError(E, "Canceled")) {
        s.cancelPoint() catch return @field(E, "Canceled");
    }
    s.maybeYield();
}

fn ioLatency(s: *Sim) void {
    const f = s.config.faults;
    if (f.io_latency_max_ns == 0) return;
    if (!s.plan.isEnabled(.latency)) return;
    const d = s.decider.range(.latency, f.io_latency_min_ns, f.io_latency_max_ns);
    if (d == 0) return;
    s.sleepUntil(s.now_ns + d, false);
}

/// Possibly shortens a transfer of `n` bytes.
fn shortLen(s: *Sim, n: usize) usize {
    if (n <= 1) return n;
    if (!s.plan.isEnabled(.short_io)) return n;
    if (!s.decider.chance(.fault, s.config.faults.short_io_ppm)) return n;
    return @intCast(s.decider.range(.fault, 1, n - 1));
}

fn vfsError(comptime E: type, err: vfs_mod.Error) E {
    return switch (err) {
        error.InvalidHandle => fault.castError(E, error.Unexpected),
        else => fault.castError(E, err),
    };
}

// ===========================================================================
// Handles

fn handleValue(h: File.Handle) u32 {
    if (is_windows) return @truncate(@intFromPtr(h));
    return @bitCast(@as(i32, @intCast(h)));
}

fn toHandle(v: u32) File.Handle {
    if (is_windows) return @ptrFromInt(@as(usize, v));
    return @intCast(v);
}

/// Resolves a directory handle. Handles TARDIS did not issue (for example
/// `Dir.cwd()`) refer to the root.
fn dirInode(s: *Sim, dir: Dir) vfs_mod.Error!vfs_mod.InodeId {
    const v = handleValue(dir.handle);
    if (v == vfs_mod.root_handle_value) return vfs_mod.root_inode;
    const h = s.vfs.handle(v) catch |err| {
        const slot_plus = v & 0xFFFF;
        const epoch = v >> 16;
        const ours = slot_plus >= 1 and slot_plus <= s.vfs.handles.len and epoch >= 1 and epoch <= 0x3FFF;
        if (ours) return err;
        return vfs_mod.root_inode;
    };
    if (s.vfs.inodes[h.inode].kind != .dir) return error.NotDir;
    return h.inode;
}

fn fileHandle(s: *Sim, file: File) vfs_mod.Error!*vfs_mod.Handle {
    return s.vfs.handle(handleValue(file.handle));
}

pub fn rootDir() Dir {
    return .{ .handle = toHandle(vfs_mod.root_handle_value) };
}

fn makeFile(v: u32) File {
    return .{ .handle = toHandle(v), .flags = .{ .nonblocking = false } };
}

fn intOrVoid(comptime T: type, v: u64) T {
    return switch (@typeInfo(T)) {
        .void => {},
        .int => @intCast(@min(v, std.math.maxInt(T))),
        else => @compileError("unexpected stat field type"),
    };
}

fn makeStat(s: *Sim, ino: vfs_mod.InodeId) File.Stat {
    const i = &s.vfs.inodes[ino];
    const t: Io.Timestamp = .{ .nanoseconds = @as(i96, s.config.epoch_offset_ns) + i.mtime_ns };
    const is_dir = i.kind == .dir;
    return .{
        .inode = intOrVoid(File.INode, @as(u64, ino) + 1),
        .nlink = intOrVoid(File.NLink, i.cur_links),
        .size = if (is_dir) 0 else i.cur_len_bytes,
        .permissions = if (is_dir) .default_dir else .default_file,
        .kind = fileKind(i.kind),
        .atime = null,
        .mtime = t,
        .ctime = t,
        .block_size = vfs_mod.page_bytes,
    };
}

fn syncClock(s: *Sim) void {
    s.vfs.now_ns = s.now_ns;
}

// ===========================================================================
// VTable

const vtable: Io.VTable = blk: {
    var v = Io.failing.vtable.*;
    v.async = async;
    v.concurrent = concurrent;
    v.await = await;
    v.cancel = cancel;
    v.groupAsync = groupAsync;
    v.groupConcurrent = groupConcurrent;
    v.groupAwait = groupAwait;
    v.groupCancel = groupCancel;
    v.recancel = recancel;
    v.swapCancelProtection = swapCancelProtection;
    v.checkCancel = checkCancel;
    v.futexWait = futexWait;
    v.futexWaitUncancelable = futexWaitUncancelable;
    v.futexWake = futexWake;
    v.operate = operate;
    v.dirCreateDir = dirCreateDir;
    v.dirCreateDirPath = dirCreateDirPath;
    v.dirCreateDirPathOpen = dirCreateDirPathOpen;
    v.dirOpenDir = dirOpenDir;
    v.dirStat = dirStat;
    v.dirStatFile = dirStatFile;
    v.dirAccess = dirAccess;
    v.dirCreateFile = dirCreateFile;
    v.dirOpenFile = dirOpenFile;
    v.dirClose = dirClose;
    v.dirDeleteFile = dirDeleteFile;
    v.dirDeleteDir = dirDeleteDir;
    v.dirRename = dirRename;
    v.dirRenamePreserve = dirRenamePreserve;
    v.dirCreateFileAtomic = dirCreateFileAtomic;
    v.dirSetPermissions = dirSetPermissions;
    v.dirSetFilePermissions = dirSetFilePermissions;
    v.fileSetPermissions = fileSetPermissions;
    v.fileStat = fileStat;
    v.fileLength = fileLength;
    v.fileClose = fileClose;
    v.fileWritePositional = fileWritePositional;
    v.fileReadPositional = fileReadPositional;
    v.fileSeekBy = fileSeekBy;
    v.fileSeekTo = fileSeekTo;
    v.fileSync = fileSync;
    v.fileSetLength = fileSetLength;
    v.now = now;
    v.clockResolution = clockResolution;
    v.sleep = sleep;
    v.random = random;
    v.randomSecure = randomSecure;
    v.dirRead = dirRead;
    v.fileLock = fileLock;
    v.fileTryLock = fileTryLock;
    v.fileUnlock = fileUnlock;
    v.fileDowngradeLock = fileDowngradeLock;
    v.netListenIp = netListenIp;
    v.netAccept = netAccept;
    v.netConnectIp = netConnectIp;
    v.netClose = netClose;
    v.netShutdown = netShutdown;
    v.netWriteFile = netWriteFile;
    v.netLookup = netLookup;
    v.netBindIp = netBindIp;
    v.batchAwaitAsync = batchAwaitAsync;
    v.batchAwaitConcurrent = batchAwaitConcurrent;
    v.batchCancel = batchCancel;
    v.dirHardLink = dirHardLink;
    v.fileHardLink = fileHardLink;
    v.dirSymLink = dirSymLink;
    v.dirReadLink = dirReadLink;
    v.processSpawn = processSpawn;
    v.processReplace = processReplace;
    v.fileIsTty = fileIsTty;
    v.fileSupportsAnsiEscapeCodes = fileSupportsAnsiEscapeCodes;
    v.fileEnableAnsiEscapeCodes = fileEnableAnsiEscapeCodes;
    // Every entry that is still std's own refuses the call. Each is wrapped
    // so that the run remembers which one it was (plan3.md D1).
    @setEvalBranchQuota(100_000);
    const table = @typeInfo(Io.VTable).@"struct";
    for (table.field_names, table.field_types) |name, T| {
        if (refusalIsQuiet(name)) continue;
        const theirs = @field(Io.failing.vtable.*, name);
        if (@field(v, name) == theirs) @field(v, name) = refusing(name, T, theirs);
    }
    break :blk v;
};

/// No simulated file is a terminal. (`std.Io.failing` has `unreachable`
/// for these three, which a program that asks would run into.)
fn fileIsTty(userdata: ?*anyopaque, file: File) Io.Cancelable!bool {
    _ = userdata;
    _ = file;
    return false;
}

fn fileSupportsAnsiEscapeCodes(userdata: ?*anyopaque, file: File) Io.Cancelable!bool {
    _ = userdata;
    _ = file;
    return false;
}

fn fileEnableAnsiEscapeCodes(userdata: ?*anyopaque, file: File) File.EnableAnsiEscapeCodesError!void {
    _ = userdata;
    _ = file;
    return error.NotTerminalDevice;
}

/// Entries left to `std.Io.failing` that are not wrapped. For three the
/// answer there is a fine answer for a simulated program ("stderr is
/// busy", "no progress pipe"). The two `fileWriteFile` entries answer
/// "unimplemented" and std then copies by reading and writing, which is
/// simulated: `Dir.copyFile` works, and the program never called them.
fn refusalIsQuiet(comptime name: []const u8) bool {
    for ([_][]const u8{ "crashHandler", "tryLockStderr", "progressParentFile", "fileWriteFileStreaming", "fileWriteFilePositional" }) |quiet| {
        if (std.mem.eql(u8, name, quiet)) return true;
    }
    return false;
}

/// Entries that are `unreachable` in `std.Io.failing`. Most cannot be
/// called without an earlier call having succeeded (a memory map that was
/// never created, a child that was never spawned); `lockStderr` and
/// `netInterfaceName` can. Under the simulator each panics by name where
/// std would be undefined behaviour in a release build. The list is kept
/// by hand: an entry that a later Zig makes `unreachable` is not on it
/// until someone adds it.
fn refusalPanics(comptime name: []const u8) bool {
    for ([_][]const u8{
        "lockStderr",           "unlockStderr",
        "childWait",            "childKill",
        "fileMemoryMapDestroy", "fileMemoryMapSetLength",
        "fileMemoryMapRead",    "fileMemoryMapWrite",
        "netInterfaceName",
    }) |name_panics| {
        if (std.mem.eql(u8, name, name_panics)) return true;
    }
    return false;
}

/// `orig` (an entry of `std.Io.failing`) behind a function that first notes
/// `name` in the simulator.
fn refusing(comptime name: []const u8, comptime P: type, comptime orig: anytype) P {
    const info = @typeInfo(@typeInfo(P).pointer.child).@"fn";
    const R = info.return_type.?;
    const p = info.param_types;
    if (p.len == 0 or p[0].? != ?*anyopaque) return orig;
    return switch (p.len) {
        1 => &struct {
            fn f(u: ?*anyopaque) R {
                noteRefused(u, name);
                return orig(u);
            }
        }.f,
        2 => &struct {
            fn f(u: ?*anyopaque, a: p[1].?) R {
                noteRefused(u, name);
                return orig(u, a);
            }
        }.f,
        3 => &struct {
            fn f(u: ?*anyopaque, a: p[1].?, b: p[2].?) R {
                noteRefused(u, name);
                return orig(u, a, b);
            }
        }.f,
        4 => &struct {
            fn f(u: ?*anyopaque, a: p[1].?, b: p[2].?, c: p[3].?) R {
                noteRefused(u, name);
                return orig(u, a, b, c);
            }
        }.f,
        5 => &struct {
            fn f(u: ?*anyopaque, a: p[1].?, b: p[2].?, c: p[3].?, d: p[4].?) R {
                noteRefused(u, name);
                return orig(u, a, b, c, d);
            }
        }.f,
        6 => &struct {
            fn f(u: ?*anyopaque, a: p[1].?, b: p[2].?, c: p[3].?, d: p[4].?, e: p[5].?) R {
                noteRefused(u, name);
                return orig(u, a, b, c, d, e);
            }
        }.f,
        7 => &struct {
            fn f(u: ?*anyopaque, a: p[1].?, b: p[2].?, c: p[3].?, d: p[4].?, e: p[5].?, g: p[6].?) R {
                noteRefused(u, name);
                return orig(u, a, b, c, d, e, g);
            }
        }.f,
        else => @compileError("std.Io." ++ name ++ " takes more arguments than `refusing` wraps"),
    };
}

fn noteRefused(userdata: ?*anyopaque, comptime name: []const u8) void {
    if (comptime refusalPanics(name)) @panic("tardis: the program called std.Io." ++ name ++ ", which the simulator does not model");
    const s: *Sim = @ptrCast(@alignCast(userdata.?));
    s.refused_calls +|= 1;
    for (s.refused[0..s.refused_len]) |have| {
        if (have.ptr == name.ptr) return;
    }
    if (s.refused_len == s.refused.len) return;
    s.refused[s.refused_len] = name;
    s.refused_len += 1;
}

/// The names of the unmodelled `std.Io` calls this run has made so far (at
/// most the first four distinct ones).
pub fn refusedCalls(s: *const Sim) []const []const u8 {
    return s.refused[0..s.refused_len];
}

/// One line for a failure report, when the run made such a call.
pub fn printRefused(s: *const Sim) void {
    if (s.refused_len == 0) return;
    std.debug.print("tardis: this run called std.Io operations the simulator does not model ({d} call{s}):", .{ s.refused_calls, if (s.refused_calls == 1) "" else "s" });
    for (s.refusedCalls()) |name| std.debug.print(" {s}", .{name});
    std.debug.print("{s}. Each got the answer std.Io.failing gives it (an error; setting timestamps does nothing and succeeds) and reached nothing real.\n", .{if (s.refused_len == s.refused.len) " (and maybe others)" else ""});
}

// --- tasks -----------------------------------------------------------------

fn async(
    userdata: ?*anyopaque,
    result: []u8,
    result_alignment: std.mem.Alignment,
    context: []const u8,
    context_alignment: std.mem.Alignment,
    start: *const fn (context: *const anyopaque, result: *anyopaque) void,
) ?*Io.AnyFuture {
    const s = fromUserdata(userdata);
    const fits = fitsBuffer(context.len, context_alignment) and fitsBuffer(result.len, result_alignment);
    const inline_run = !fits or s.decider.chance(.schedule, s.config.async_inline_ppm);
    if (!inline_run) {
        if (s.spawn(.{ .future = start }, context, null, result.len)) |id| {
            s.maybeYield();
            return @ptrCast(&s.tasks[id]);
        }
    }
    s.record(.spawn, 0, 2, 0, "inline");
    start(context.ptr, result.ptr);
    return null;
}

fn concurrent(
    userdata: ?*anyopaque,
    result_len: usize,
    result_alignment: std.mem.Alignment,
    context: []const u8,
    context_alignment: std.mem.Alignment,
    start: *const fn (context: *const anyopaque, result: *anyopaque) void,
) Io.ConcurrentError!*Io.AnyFuture {
    const s = fromUserdata(userdata);
    if (!fitsBuffer(context.len, context_alignment) or !fitsBuffer(result_len, result_alignment))
        return error.ConcurrencyUnavailable;
    const id = s.spawn(.{ .future = start }, context, null, result_len) orelse return error.ConcurrencyUnavailable;
    s.maybeYield();
    return @ptrCast(&s.tasks[id]);
}

fn taskIdOf(s: *Sim, any_future: *Io.AnyFuture) TaskId {
    const t: *Task = @ptrCast(@alignCast(any_future));
    const id: TaskId = @intCast((@intFromPtr(t) - @intFromPtr(s.tasks.ptr)) / @sizeOf(Task));
    assert(&s.tasks[id] == t);
    return id;
}

fn awaitTask(s: *Sim, id: TaskId, result: []u8) void {
    const t = &s.tasks[id];
    while (t.state != .finished) {
        assert(t.state != .free); // awaiting an abandoned task
        t.awaiter = s.current;
        s.block(.{ .await_task = id }, null, false);
    }
    @memcpy(result, t.result_buf[0..result.len]);
    s.secSync(.acquire, s.current, seam.futureKey(id));
    s.freeTask(id);
}

fn await(userdata: ?*anyopaque, any_future: *Io.AnyFuture, result: []u8, result_alignment: std.mem.Alignment) void {
    _ = result_alignment;
    const s = fromUserdata(userdata);
    s.awaitTask(s.taskIdOf(any_future), result);
}

fn cancel(userdata: ?*anyopaque, any_future: *Io.AnyFuture, result: []u8, result_alignment: std.mem.Alignment) void {
    _ = result_alignment;
    const s = fromUserdata(userdata);
    const id = s.taskIdOf(any_future);
    s.requestCancel(id);
    s.awaitTask(id, result);
}

fn groupAdd(s: *Sim, g: *Io.Group) void {
    g.state += 1;
    g.token.store(@ptrCast(s), .release);
}

fn groupAsync(
    userdata: ?*anyopaque,
    group: *Io.Group,
    context: []const u8,
    context_alignment: std.mem.Alignment,
    start: *const fn (context: *const anyopaque) void,
) void {
    const s = fromUserdata(userdata);
    const fits = fitsBuffer(context.len, context_alignment);
    if (fits and !s.decider.chance(.schedule, s.config.async_inline_ppm)) {
        if (s.spawn(.{ .group = start }, context, group, 0)) |_| {
            s.groupAdd(group);
            s.maybeYield();
            return;
        }
    }
    s.record(.spawn, 0, 3, 0, "inline");
    start(context.ptr);
}

fn groupConcurrent(
    userdata: ?*anyopaque,
    group: *Io.Group,
    context: []const u8,
    context_alignment: std.mem.Alignment,
    start: *const fn (context: *const anyopaque) void,
) Io.ConcurrentError!void {
    const s = fromUserdata(userdata);
    if (!fitsBuffer(context.len, context_alignment)) return error.ConcurrencyUnavailable;
    _ = s.spawn(.{ .group = start }, context, group, 0) orelse return error.ConcurrencyUnavailable;
    s.groupAdd(group);
    s.maybeYield();
}

fn cancelGroupMembers(s: *Sim, g: *Io.Group) void {
    for (s.tasks, 0..) |*t, i| {
        if (t.state == .free or t.state == .finished) continue;
        if (t.group != g) continue;
        s.requestCancel(@intCast(i));
    }
}

fn groupAwait(userdata: ?*anyopaque, group: *Io.Group, token: *anyopaque) Io.Cancelable!void {
    _ = token;
    const s = fromUserdata(userdata);
    var canceled = false;
    while (group.state > 0) {
        if (!canceled) {
            s.cancelPoint() catch {
                canceled = true;
                s.cancelGroupMembers(group);
            };
        }
        if (group.state == 0) break;
        s.block(.{ .group = group }, null, !canceled);
    }
    s.secSync(.acquire, s.current, @intFromPtr(group));
    group.token.store(null, .release);
    if (canceled) return error.Canceled;
}

fn groupCancel(userdata: ?*anyopaque, group: *Io.Group, token: *anyopaque) void {
    _ = token;
    const s = fromUserdata(userdata);
    s.cancelGroupMembers(group);
    while (group.state > 0) s.block(.{ .group = group }, null, false);
    s.secSync(.acquire, s.current, @intFromPtr(group));
    group.token.store(null, .release);
}

fn recancel(userdata: ?*anyopaque) void {
    const s = fromUserdata(userdata);
    s.tasks[s.current].cancel_requested = true;
}

fn swapCancelProtection(userdata: ?*anyopaque, new: Io.CancelProtection) Io.CancelProtection {
    const s = fromUserdata(userdata);
    const t = &s.tasks[s.current];
    const old = t.cancel_protection;
    t.cancel_protection = new;
    return old;
}

fn checkCancel(userdata: ?*anyopaque) Io.Cancelable!void {
    const s = fromUserdata(userdata);
    try s.cancelPoint();
    s.maybeYield();
}

// --- futex -----------------------------------------------------------------

/// The current node's clock reading for global virtual time `g`.
fn localTime(s: *const Sim, g: u64) i128 {
    const drift = s.nodes[s.currentNode()].drift_ppm;
    return @as(i128, g) + @divTrunc(@as(i128, g) * drift, decide.ppm_one);
}

/// Global virtual nanoseconds that elapse while the current node's clock
/// advances by `local_delta`.
fn globalDelta(s: *const Sim, local_delta: i128) u64 {
    if (local_delta <= 0) return 0;
    const drift = s.nodes[s.currentNode()].drift_ppm;
    const den: i128 = @as(i128, decide.ppm_one) + drift;
    const g = @divFloor(local_delta * decide.ppm_one + den - 1, den);
    return @intCast(@min(g, std.math.maxInt(u64) - s.now_ns));
}

fn deadlineFrom(s: *Sim, timeout: Io.Timeout) ?u64 {
    switch (timeout) {
        .none => return null,
        .duration => |d| return s.now_ns + s.globalDelta(d.raw.nanoseconds),
        .deadline => |d| {
            var ns: i128 = d.raw.nanoseconds;
            if (d.clock == .real) ns -= @as(i128, s.config.epoch_offset_ns) + s.nodes[s.currentNode()].real_offset_ns;
            return s.now_ns + s.globalDelta(ns - s.localTime(s.now_ns));
        },
    }
}

fn futexWaitImpl(s: *Sim, ptr: *const u32, expected: u32, deadline_ns: ?u64, cancelable: bool) void {
    if (@atomicLoad(u32, ptr, .acquire) != expected) {
        s.maybeYield();
        return;
    }
    if (s.plan.isEnabled(.spurious_wakeup) and s.decider.chance(.fault, s.config.faults.spurious_wakeup_ppm)) {
        s.record(.futex_wait, 0, 1, 0, "spurious");
        s.maybeYield();
        return;
    }
    s.record(.futex_wait, 0, 0, 0, "");
    s.block(.{ .futex = @intFromPtr(ptr) }, deadline_ns, cancelable);
}

/// A `futex` wait made by system call (`sysemu.zig`): never a cancelation
/// point (the kernel's is not one, and a cancel spent on a libc that loops
/// on `EINTR` would be lost), and it says whether its deadline ended it,
/// as the kernel does: a task a wake picked returns woken even if its
/// deadline has also passed.
pub fn futexWaitSyscall(s: *Sim, ptr: *const u32, expected: u32, timeout: Io.Timeout) enum { woken, timed_out } {
    const deadline_ns = s.deadlineFrom(timeout);
    s.tasks[s.current].woke_by_timeout = false;
    s.futexWaitImpl(ptr, expected, deadline_ns, false);
    return if (s.tasks[s.current].woke_by_timeout) .timed_out else .woken;
}

fn futexWait(userdata: ?*anyopaque, ptr: *const u32, expected: u32, timeout: Io.Timeout) Io.Cancelable!void {
    const s = fromUserdata(userdata);
    try s.cancelPoint();
    s.futexWaitImpl(ptr, expected, s.deadlineFrom(timeout), true);
    try s.cancelPoint();
}

fn futexWaitUncancelable(userdata: ?*anyopaque, ptr: *const u32, expected: u32) void {
    const s = fromUserdata(userdata);
    s.futexWaitImpl(ptr, expected, null, false);
}

fn futexWake(userdata: ?*anyopaque, ptr: *const u32, max_waiters: u32) void {
    const s = fromUserdata(userdata);
    const addr = @intFromPtr(ptr);
    var woken: u32 = 0;
    while (woken < max_waiters) {
        var count: u64 = 0;
        for (s.tasks) |*t| {
            if (t.state == .blocked and t.block == .futex and t.block.futex == addr) count += 1;
        }
        if (count == 0) break;
        var pick = s.decider.uniform(.schedule, count);
        for (s.tasks, 0..) |*t, i| {
            if (t.state != .blocked or t.block != .futex or t.block.futex != addr) continue;
            if (pick == 0) {
                s.wake(@intCast(i));
                break;
            }
            pick -= 1;
        }
        woken += 1;
    }
    s.record(.futex_wake, woken, max_waiters, 0, "");
    s.maybeYield();
}

// --- time and randomness ---------------------------------------------------

fn now(userdata: ?*anyopaque, clock: Io.Clock) Io.Timestamp {
    const s = fromUserdata(userdata);
    var t: i128 = s.localTime(s.now_ns);
    if (clock == .real) t += @as(i128, s.config.epoch_offset_ns) + s.nodes[s.currentNode()].real_offset_ns;
    return .{ .nanoseconds = @intCast(t) };
}

fn clockResolution(userdata: ?*anyopaque, clock: Io.Clock) Io.Clock.ResolutionError!Io.Duration {
    _ = userdata;
    _ = clock;
    return .{ .nanoseconds = 1 };
}

fn sleep(userdata: ?*anyopaque, timeout: Io.Timeout) Io.Cancelable!void {
    const s = fromUserdata(userdata);
    try s.cancelPoint();
    const deadline = s.deadlineFrom(timeout);
    s.record(.sleep, if (deadline) |d| d -| s.now_ns else std.math.maxInt(u64), 0, 0, "");
    s.block(.sleep, deadline, true);
    try s.cancelPoint();
}

fn random(userdata: ?*anyopaque, buffer: []u8) void {
    const s = fromUserdata(userdata);
    s.decider.fill(.random, buffer);
    s.record(.random, buffer.len, 0, 0, "");
}

fn randomSecure(userdata: ?*anyopaque, buffer: []u8) Io.RandomSecureError!void {
    random(userdata, buffer);
}

// --- directories -----------------------------------------------------------

fn dirCreateDir(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, permissions: Dir.Permissions) Dir.CreateDirError!void {
    _ = permissions;
    const s = fromUserdata(userdata);
    const E = Dir.CreateDirError;
    try s.enter(E);
    s.syncClock();
    if (s.injected(E, .metadata)) |e| return e;
    const parent = s.dirInode(dir) catch |err| return vfsError(E, err);
    _ = s.vfs.makeDir(parent, sub_path) catch |err| return vfsError(E, err);
    s.record(.mkdir, 0, 0, 0, sub_path);
}

fn dirCreateDirPath(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, permissions: Dir.Permissions) Dir.CreateDirPathError!Dir.CreatePathStatus {
    _ = permissions;
    const s = fromUserdata(userdata);
    const E = Dir.CreateDirPathError;
    try s.enter(E);
    s.syncClock();
    if (s.injected(E, .metadata)) |e| return e;
    const parent = s.dirInode(dir) catch |err| return vfsError(E, err);
    const r = s.vfs.makePath(parent, sub_path) catch |err| return vfsError(E, err);
    s.record(.mkdir, 1, 0, 0, sub_path);
    return switch (r.status) {
        .existed => .existed,
        .created => .created,
    };
}

fn dirCreateDirPathOpen(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, permissions: Dir.Permissions, options: Dir.OpenOptions) Dir.CreateDirPathOpenError!Dir {
    _ = permissions;
    _ = options;
    const s = fromUserdata(userdata);
    const E = Dir.CreateDirPathOpenError;
    try s.enter(E);
    s.syncClock();
    if (s.injected(E, .metadata)) |e| return e;
    const parent = s.dirInode(dir) catch |err| return vfsError(E, err);
    const r = s.vfs.makePath(parent, sub_path) catch |err| return vfsError(E, err);
    const h = s.vfs.openHandle(r.inode, true, false) catch |err| return vfsError(E, err);
    s.record(.mkdir, 2, h, 0, sub_path);
    return .{ .handle = toHandle(h) };
}

fn dirOpenDir(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, options: Dir.OpenOptions) Dir.OpenError!Dir {
    _ = options;
    const s = fromUserdata(userdata);
    const E = Dir.OpenError;
    try s.enter(E);
    if (s.injected(E, .open)) |e| return e;
    const parent = s.dirInode(dir) catch |err| return vfsError(E, err);
    const ino = s.vfs.lookup(parent, sub_path) catch |err| return vfsError(E, err);
    if (s.vfs.inodes[ino].kind != .dir) return vfsError(E, error.NotDir);
    const h = s.vfs.openHandle(ino, true, false) catch |err| return vfsError(E, err);
    s.record(.open, h, 1, 0, sub_path);
    return .{ .handle = toHandle(h) };
}

fn dirStat(userdata: ?*anyopaque, dir: Dir) Dir.StatError!Dir.Stat {
    const s = fromUserdata(userdata);
    const E = Dir.StatError;
    try s.enter(E);
    const ino = s.dirInode(dir) catch |err| return vfsError(E, err);
    return s.makeStat(ino);
}

fn dirStatFile(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, options: Dir.StatFileOptions) Dir.StatFileError!File.Stat {
    const s = fromUserdata(userdata);
    const E = Dir.StatFileError;
    try s.enter(E);
    const parent = s.dirInode(dir) catch |err| return vfsError(E, err);
    s.secVfs(.stat, parent, sub_path);
    const ino = s.vfs.lookupEx(parent, sub_path, options.follow_symlinks) catch |err| switch (err) {
        // On macOS std reports a stat through a regular file as not
        // found (differential test, first run on real APFS).
        error.NotDir => return if (s.vfs.persona == .macos_apfs) error.FileNotFound else vfsError(E, err),
        else => return vfsError(E, err),
    };
    s.record(.stat, ino, 0, 0, sub_path);
    return s.makeStat(ino);
}

fn dirAccess(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, options: Dir.AccessOptions) Dir.AccessError!void {
    _ = options;
    const s = fromUserdata(userdata);
    const E = Dir.AccessError;
    try s.enter(E);
    const parent = s.dirInode(dir) catch |err| return vfsError(E, err);
    s.secVfs(.access, parent, sub_path);
    _ = s.vfs.lookup(parent, sub_path) catch |err| switch (err) {
        // `access` has no "not a directory": std reports a path through
        // a file as not found (differential test, `diff_fs_test.zig`).
        error.NotDir => return error.FileNotFound,
        else => return vfsError(E, err),
    };
}

fn dirCreateFile(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, options: Dir.CreateFileOptions) File.OpenError!File {
    const s = fromUserdata(userdata);
    const E = File.OpenError;
    try s.enter(E);
    s.syncClock();
    if (s.injected(E, .open)) |e| return e;
    const parent = s.dirInode(dir) catch |err| return vfsError(E, err);
    s.secPath(.create, sub_path);
    const ino = s.vfs.createFile(parent, sub_path, .{ .exclusive = options.exclusive, .truncate = options.truncate }) catch |err|
        return vfsError(E, err);
    const h = s.vfs.openHandle(ino, options.read, true) catch |err| return vfsError(E, err);
    s.record(.create, h, ino, 0, sub_path);
    return makeFile(h);
}

fn dirOpenFile(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, options: Dir.OpenFileOptions) File.OpenError!File {
    const s = fromUserdata(userdata);
    const E = File.OpenError;
    try s.enter(E);
    if (s.injected(E, .open)) |e| return e;
    const parent = s.dirInode(dir) catch |err| return vfsError(E, err);
    s.secPath(.open, sub_path);
    s.secVfs(.open, parent, sub_path);
    const ino = s.vfs.lookup(parent, sub_path) catch |err| return vfsError(E, err);
    const is_dir = s.vfs.inodes[ino].kind == .dir;
    if (is_dir and (!options.allow_directory or options.mode != .read_only)) return vfsError(E, error.IsDir);
    const h = s.vfs.openHandle(ino, options.mode != .write_only, options.mode != .read_only) catch |err|
        return vfsError(E, err);
    s.record(.open, h, ino, 0, sub_path);
    return makeFile(h);
}

fn dirClose(userdata: ?*anyopaque, dirs: []const Dir) void {
    const s = fromUserdata(userdata);
    for (dirs) |d| {
        const v = handleValue(d.handle);
        if (v == vfs_mod.root_handle_value) continue;
        s.record(.close, v, 1, 0, "");
        s.vfs.closeHandle(v);
    }
}

fn dirDeleteFile(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8) Dir.DeleteFileError!void {
    const s = fromUserdata(userdata);
    const E = Dir.DeleteFileError;
    try s.enter(E);
    s.syncClock();
    if (s.injected(E, .metadata)) |e| return e;
    const parent = s.dirInode(dir) catch |err| return vfsError(E, err);
    s.secPath(.delete, sub_path);
    s.vfs.deleteFile(parent, sub_path) catch |err| return vfsError(E, err);
    s.record(.delete, 0, 0, 0, sub_path);
}

fn dirDeleteDir(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8) Dir.DeleteDirError!void {
    const s = fromUserdata(userdata);
    const E = Dir.DeleteDirError;
    try s.enter(E);
    s.syncClock();
    if (s.injected(E, .metadata)) |e| return e;
    const parent = s.dirInode(dir) catch |err| return vfsError(E, err);
    s.vfs.deleteDir(parent, sub_path) catch |err| return vfsError(E, err);
    s.record(.delete, 1, 0, 0, sub_path);
}

fn dirRename(userdata: ?*anyopaque, old_dir: Dir, old_sub_path: []const u8, new_dir: Dir, new_sub_path: []const u8) Dir.RenameError!void {
    const s = fromUserdata(userdata);
    const E = Dir.RenameError;
    try s.enter(E);
    s.syncClock();
    if (s.injected(E, .metadata)) |e| return e;
    const old_parent = s.dirInode(old_dir) catch |err| return vfsError(E, err);
    const new_parent = s.dirInode(new_dir) catch |err| return vfsError(E, err);
    s.secPath(.rename, old_sub_path);
    s.secPath(.rename, new_sub_path);
    s.vfs.rename(old_parent, old_sub_path, new_parent, new_sub_path) catch |err| return vfsError(E, err);
    s.record(.rename, 0, 0, 0, old_sub_path);
}

// Permissions are accepted but not modelled: the target must exist, and the
// call is traced, so code that sets modes (private files, `+x`) runs.

fn dirSetPermissions(userdata: ?*anyopaque, dir: Dir, permissions: Dir.Permissions) Dir.SetPermissionsError!void {
    _ = permissions;
    const s = fromUserdata(userdata);
    const E = Dir.SetPermissionsError;
    try s.enter(E);
    const ino = s.dirInode(dir) catch |err| return vfsError(E, err);
    s.record(.chmod, ino, 0, 0, "");
}

fn dirSetFilePermissions(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, permissions: File.Permissions, options: Dir.SetFilePermissionsOptions) Dir.SetFilePermissionsError!void {
    _ = permissions;
    _ = options;
    const s = fromUserdata(userdata);
    const E = Dir.SetFilePermissionsError;
    try s.enter(E);
    if (s.injected(E, .metadata)) |e| return e;
    const parent = s.dirInode(dir) catch |err| return vfsError(E, err);
    const ino = s.vfs.lookup(parent, sub_path) catch |err| return vfsError(E, err);
    s.record(.chmod, ino, 0, 0, sub_path);
}

fn fileSetPermissions(userdata: ?*anyopaque, file: File, permissions: File.Permissions) File.SetPermissionsError!void {
    _ = permissions;
    const s = fromUserdata(userdata);
    const E = File.SetPermissionsError;
    try s.enter(E);
    const h = s.fileHandle(file) catch |err| return vfsError(E, err);
    s.record(.chmod, h.inode, 0, 0, "");
}

/// Like `dirRename`, but fails with `error.PathAlreadyExists` instead of
/// replacing an existing destination.
fn dirRenamePreserve(userdata: ?*anyopaque, old_dir: Dir, old_sub_path: []const u8, new_dir: Dir, new_sub_path: []const u8) Dir.RenamePreserveError!void {
    const s = fromUserdata(userdata);
    const E = Dir.RenamePreserveError;
    try s.enter(E);
    s.syncClock();
    if (s.injected(E, .metadata)) |e| return e;
    const old_parent = s.dirInode(old_dir) catch |err| return vfsError(E, err);
    const new_parent = s.dirInode(new_dir) catch |err| return vfsError(E, err);
    if (s.vfs.lookupEx(new_parent, new_sub_path, false)) |_| {
        return error.PathAlreadyExists;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return vfsError(E, err),
    }
    s.vfs.rename(old_parent, old_sub_path, new_parent, new_sub_path) catch |err| return vfsError(E, err);
    s.record(.rename, 1, 0, 0, old_sub_path);
}

/// `Dir.createFileAtomic`: a named temporary file (16 hex digits) in the
/// destination's directory, materialized later by `File.Atomic.replace`
/// (a rename) or `File.Atomic.link` (`dirRenamePreserve`). There are no
/// unnamed files (`O_TMPFILE`) in the simulation, so a crash before the
/// rename leaves the temporary file behind, as on systems without them.
fn dirCreateFileAtomic(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, options: Dir.CreateFileAtomicOptions) Dir.CreateFileAtomicError!File.Atomic {
    const s = fromUserdata(userdata);
    const E = Dir.CreateFileAtomicError;
    try s.enter(E);
    s.syncClock();
    if (s.injected(E, .open)) |e| return e;
    const base = std.fs.path.basename(sub_path);
    const parent_path = sub_path[0 .. sub_path.len - base.len];
    var parent = s.dirInode(dir) catch |err| return vfsError(E, err);
    var target_dir = dir;
    var close_dir = false;
    if (parent_path.len > 0) {
        const trimmed = std.mem.trimEnd(u8, parent_path, "/\\");
        parent = if (options.make_path)
            (s.vfs.makePath(parent, trimmed) catch |err| return vfsError(E, err)).inode
        else
            s.vfs.lookup(parent, trimmed) catch |err| return vfsError(E, err);
        if (s.vfs.inodes[parent].kind != .dir) return vfsError(E, error.NotDir);
        const dh = s.vfs.openHandle(parent, true, false) catch |err| return vfsError(E, err);
        target_dir = .{ .handle = toHandle(dh) };
        close_dir = true;
    }
    errdefer if (close_dir) s.vfs.closeHandle(handleValue(target_dir.handle));
    var name_value = s.decider.next(.random);
    while (true) : (name_value +%= 1) {
        const name = std.fmt.hex(name_value);
        const ino = s.vfs.createFile(parent, &name, .{ .exclusive = true, .truncate = false }) catch |err| switch (err) {
            error.PathAlreadyExists => continue,
            else => return vfsError(E, err),
        };
        const h = s.vfs.openHandle(ino, true, true) catch |err| return vfsError(E, err);
        s.record(.create, h, ino, 0, &name);
        return .{
            .file = makeFile(h),
            .file_basename_hex = name_value,
            .file_open = true,
            .file_exists = true,
            .dir = target_dir,
            .close_dir_on_deinit = close_dir,
            .dest_sub_path = base,
        };
    }
}

// --- files -----------------------------------------------------------------

fn fileStat(userdata: ?*anyopaque, file: File) File.StatError!File.Stat {
    const s = fromUserdata(userdata);
    const E = File.StatError;
    try s.enter(E);
    const h = s.fileHandle(file) catch |err| return vfsError(E, err);
    return s.makeStat(h.inode);
}

fn fileLength(userdata: ?*anyopaque, file: File) File.LengthError!u64 {
    const s = fromUserdata(userdata);
    const E = File.LengthError;
    try s.enter(E);
    const h = s.fileHandle(file) catch |err| return vfsError(E, err);
    return s.vfs.inodes[h.inode].cur_len_bytes;
}

fn fileClose(userdata: ?*anyopaque, files: []const File) void {
    const s = fromUserdata(userdata);
    for (files) |f| {
        const v = handleValue(f.handle);
        if (s.fileHandle(f)) |h| {
            if (h.lock != .none) s.secFileLock(h.inode, false);
        } else |_| {}
        s.record(.close, v, 0, 0, "");
        s.vfs.closeHandle(v);
    }
    s.wakeBlocked(.lock);
}

/// Writes `header`, then `data[0..n-1]`, then `data[n-1]` repeated `splat`
/// times, at `offset`. Returns bytes written (possibly short).
fn writeVectors(s: *Sim, comptime E: type, ino: vfs_mod.InodeId, header: []const u8, data: []const []const u8, splat: usize, offset: u64) E!usize {
    var total: usize = header.len;
    if (data.len > 0) {
        for (data[0 .. data.len - 1]) |d| total += d.len;
        total += data[data.len - 1].len * splat;
    }
    const limit = s.shortLen(total);
    // Segment k: 0 = header, 1..data.len-1 = data[k-1], then `splat` copies of the last element.
    const segment_count: usize = if (data.len == 0) 1 else data.len + splat;
    var written: usize = 0;
    var k: usize = 0;
    while (k < segment_count and written < limit) : (k += 1) {
        const seg: []const u8 = if (k == 0) header else data[@min(k - 1, data.len - 1)];
        if (seg.len == 0) continue;
        const want = @min(seg.len, limit - written);
        s.secEgress(s.fileSink(ino), seg[0..want]);
        const n = s.vfs.write(ino, offset + written, seg[0..want]) catch |err| {
            if (written > 0) break;
            return vfsError(E, err);
        };
        written += n;
        if (n < want) break;
    }
    s.stats.disk_write_bytes += written;
    return written;
}

fn fileWritePositional(userdata: ?*anyopaque, file: File, header: []const u8, data: []const []const u8, splat: usize, offset: u64) File.WritePositionalError!usize {
    const s = fromUserdata(userdata);
    const E = File.WritePositionalError;
    try s.enter(E);
    s.ioLatency();
    const h = s.fileHandle(file) catch |err| return vfsError(E, err);
    if (!h.writable) return vfsError(E, error.NotOpenForWriting);
    if (s.lockViolation(file)) return fault.castError(E, error.LockViolation);
    const ino = h.inode;
    if (s.injected(E, .write)) |e| return e;
    s.syncClock();
    // An appending descriptor (system-call mode) writes at the end
    // whatever offset it is given, as `pwrite` does on Linux.
    const at = if (h.append) s.vfs.inodes[ino].cur_len_bytes else offset;
    const n = try s.writeVectors(E, ino, header, data, splat, at);
    s.record(.write, ino, at, n, "");
    return n;
}

fn readVectors(s: *Sim, ino: vfs_mod.InodeId, data: []const []u8, offset: u64) usize {
    var total: usize = 0;
    for (data) |d| total += d.len;
    const limit = s.shortLen(total);
    var done: usize = 0;
    for (data) |d| {
        if (done >= limit) break;
        const want = @min(d.len, limit - done);
        const n = s.vfs.read(ino, offset + done, d[0..want]);
        done += n;
        if (n < want) break;
    }
    s.secIngress(s.fileSink(ino), data, done);
    s.stats.disk_read_bytes += done;
    return done;
}

fn fileReadPositional(userdata: ?*anyopaque, file: File, data: []const []u8, offset: u64) File.ReadPositionalError!usize {
    const s = fromUserdata(userdata);
    const E = File.ReadPositionalError;
    try s.enter(E);
    s.ioLatency();
    const h = s.fileHandle(file) catch |err| return vfsError(E, err);
    if (!h.readable) return vfsError(E, error.NotOpenForReading);
    if (s.lockViolation(file)) return fault.castError(E, error.LockViolation);
    const ino = h.inode;
    if (s.vfs.inodes[ino].kind == .dir) return vfsError(E, error.IsDir);
    if (s.injected(E, .read)) |e| return e;
    const n = s.readVectors(ino, data, offset);
    s.record(.read, ino, offset, n, "");
    return n;
}

fn fileSeekBy(userdata: ?*anyopaque, file: File, relative_offset: i64) File.SeekError!void {
    const s = fromUserdata(userdata);
    const E = File.SeekError;
    try s.enter(E);
    const h = s.fileHandle(file) catch |err| return vfsError(E, err);
    const pos: i64 = @as(i64, @intCast(h.pos)) + relative_offset;
    if (pos < 0) return fault.castError(E, error.Unseekable);
    h.pos = @intCast(pos);
}

fn fileSeekTo(userdata: ?*anyopaque, file: File, absolute_offset: u64) File.SeekError!void {
    const s = fromUserdata(userdata);
    const E = File.SeekError;
    try s.enter(E);
    const h = s.fileHandle(file) catch |err| return vfsError(E, err);
    h.pos = absolute_offset;
}

fn fileSync(userdata: ?*anyopaque, file: File) File.SyncError!void {
    return fromUserdata(userdata).syncFile(file, false);
}

/// `fdatasync`, which `std.Io` does not have: system-call mode calls it.
/// As a file's `sync` in every way but what it commits (`Vfs.dataSync`).
pub fn fileDataSync(s: *Sim, file: File) File.SyncError!void {
    return s.syncFile(file, true);
}

fn syncFile(s: *Sim, file: File, data_only: bool) File.SyncError!void {
    const E = File.SyncError;
    try s.enter(E);
    s.ioLatency();
    const h = s.fileHandle(file) catch |err| return vfsError(E, err);
    const ino = h.inode;
    if (s.injected(E, .sync)) |e| return e;
    s.syncClock();
    if (data_only) s.vfs.dataSync(ino) else s.vfs.sync(ino);
    s.stats.disk_syncs += 1;
    s.record(.sync, ino, s.vfs.journalPending(), 0, "");
}

fn fileSetLength(userdata: ?*anyopaque, file: File, length: u64) File.SetLengthError!void {
    const s = fromUserdata(userdata);
    const E = File.SetLengthError;
    try s.enter(E);
    const h = s.fileHandle(file) catch |err| return vfsError(E, err);
    if (!h.writable) return vfsError(E, error.NotOpenForWriting);
    if (s.lockViolation(file)) return fault.castError(E, error.LockViolation);
    const ino = h.inode;
    if (s.injected(E, .write)) |e| return e;
    s.syncClock();
    s.vfs.setLength(ino, length) catch |err| return vfsError(E, err);
    s.record(.set_length, ino, length, 0, "");
}

fn readStreaming(s: *Sim, op: Io.Operation.FileReadStreaming) Io.Operation.FileReadStreaming.Result {
    const E = Io.Operation.FileReadStreaming.Error;
    s.maybeYield();
    s.ioLatency();
    const h = s.fileHandle(op.file) catch |err| return vfsError(E, err);
    if (!h.readable) return vfsError(E, error.NotOpenForReading);
    if (s.lockViolation(op.file)) return fault.castError(E, error.LockViolation);
    const ino = h.inode;
    if (s.vfs.inodes[ino].kind == .dir) return vfsError(E, error.IsDir);
    if (s.injected(E, .read)) |e| return e;
    var total: usize = 0;
    for (op.data) |d| total += d.len;
    const pos = h.pos;
    const n = s.readVectors(ino, op.data, pos);
    s.record(.read, ino, pos, n, "stream");
    if (n == 0 and total > 0) return error.EndOfStream;
    h.pos = pos + n;
    return n;
}

fn writeStreaming(s: *Sim, op: Io.Operation.FileWriteStreaming) Io.Operation.FileWriteStreaming.Result {
    const E = Io.Operation.FileWriteStreaming.Error;
    s.maybeYield();
    s.ioLatency();
    const h = s.fileHandle(op.file) catch |err| return vfsError(E, err);
    if (!h.writable) return vfsError(E, error.NotOpenForWriting);
    if (s.lockViolation(op.file)) return fault.castError(E, error.LockViolation);
    const ino = h.inode;
    if (s.injected(E, .write)) |e| return e;
    s.syncClock();
    const pos = if (h.append) s.vfs.inodes[ino].cur_len_bytes else h.pos;
    const n = try s.writeVectors(E, ino, op.header, op.data, op.splat, pos);
    h.pos = pos + n;
    s.record(.write, ino, pos, n, "stream");
    return n;
}

// --- wake helpers ------------------------------------------------------------

fn wakeBlocked(s: *Sim, tag: std.meta.Tag(Block)) void {
    for (s.tasks, 0..) |*t, i| {
        if (t.state == .blocked and std.meta.activeTag(t.block) == tag) s.wake(@intCast(i));
    }
}

/// Network state changed: every task waiting on the network re-checks.
fn netWakeAll(s: *Sim) void {
    sysfd.networkChanged();
    s.wakeBlocked(.net);
}

// --- directory listing -----------------------------------------------------

/// Bytes at the start of `Dir.Reader.buffer` holding the listing order.
const dir_reader_state_bytes = 2 * @sizeOf(u32);

/// Lists entries in an order drawn per listing (real directories promise no
/// order), so code that depends on readdir order is caught.
fn dirRead(userdata: ?*anyopaque, r: *Dir.Reader, entries: []Dir.Entry) Dir.Reader.Error!usize {
    const s = fromUserdata(userdata);
    const E = Dir.Reader.Error;
    try s.enter(E);
    const dir_ino = s.dirInode(r.dir) catch |err| return vfsError(E, err);
    const slots: u32 = @intCast(s.vfs.dentrySlots());
    assert(r.buffer.len > dir_reader_state_bytes);
    const state: *[2]u32 = @ptrCast(r.buffer[0..dir_reader_state_bytes]);
    switch (r.state) {
        .finished => return 0,
        .reset => {
            // Visit slot (offset + k * stride) mod slots for k = 0..slots-1.
            var stride: u32 = @intCast(s.decider.range(.fault, 1, slots));
            while (std.math.gcd(stride, slots) != 1) stride += 1;
            state[0] = @intCast(s.decider.uniform(.fault, slots));
            state[1] = stride;
            r.index = 0;
            r.state = .reading;
        },
        .reading => {},
    }
    var name_pos: usize = dir_reader_state_bytes;
    var n: usize = 0;
    while (r.index < slots and n < entries.len) {
        const pos = (state[0] + @as(u64, r.index) * state[1]) % slots;
        if (s.vfs.childAt(dir_ino, pos)) |c| {
            if (name_pos + c.name.len > r.buffer.len) break;
            const name = r.buffer[name_pos..][0..c.name.len];
            @memcpy(name, c.name);
            name_pos += c.name.len;
            entries[n] = .{
                .name = name,
                .kind = fileKind(c.kind),
                .inode = intOrVoid(File.INode, @as(u64, c.inode) + 1),
            };
            n += 1;
        }
        r.index += 1;
    }
    if (r.index >= slots) r.state = .finished;
    s.record(.dir_read, dir_ino, n, 0, "");
    return n;
}

// --- file locks ------------------------------------------------------------

fn toLockKind(l: File.Lock) vfs_mod.LockKind {
    return switch (l) {
        .none => .none,
        .shared => .shared,
        .exclusive => .exclusive,
    };
}

fn setLock(s: *Sim, file: File, kind: vfs_mod.LockKind) void {
    const h = s.fileHandle(file) catch return;
    const was = h.lock;
    h.lock = kind;
    s.record(.lock, handleValue(file.handle), @backingInt(kind), 0, "");
    if (@backingInt(kind) < @backingInt(was)) s.wakeBlocked(.lock);
}

fn fileLock(userdata: ?*anyopaque, file: File, lock: File.Lock) File.LockError!void {
    const s = fromUserdata(userdata);
    const E = File.LockError;
    try s.enter(E);
    const v = handleValue(file.handle);
    _ = s.fileHandle(file) catch |err| return vfsError(E, err);
    const want = toLockKind(lock);
    const first = s.fileHandle(file) catch |err| return vfsError(E, err);
    const taking = want != .none and first.lock == .none;
    const ino = first.inode;
    if (taking) s.secFileLock(ino, true);
    errdefer if (taking) s.secFileLock(ino, false);
    while (want != .none and s.vfs.lockConflicts(v, want)) {
        s.record(.lock, v, @backingInt(want), 1, "wait");
        s.block(.lock, null, true);
        try s.cancelPoint();
        _ = s.fileHandle(file) catch |err| return vfsError(E, err);
    }
    s.setLock(file, want);
}

fn fileTryLock(userdata: ?*anyopaque, file: File, lock: File.Lock) File.LockError!bool {
    const s = fromUserdata(userdata);
    const E = File.LockError;
    try s.enter(E);
    _ = s.fileHandle(file) catch |err| return vfsError(E, err);
    const want = toLockKind(lock);
    if (want != .none and s.vfs.lockConflicts(handleValue(file.handle), want)) return false;
    s.setLock(file, want);
    return true;
}

fn fileUnlock(userdata: ?*anyopaque, file: File) void {
    const s = fromUserdata(userdata);
    if (s.fileHandle(file)) |h| {
        if (h.lock != .none) s.secFileLock(h.inode, false);
    } else |_| {}
    s.setLock(file, .none);
}

/// A file lock taken or dropped by the current task, for the security
/// layer's lock order (plan2.md §4.2).
fn secFileLock(s: *Sim, ino: vfs_mod.InodeId, held: bool) void {
    const a = s.sec orelse return;
    a.provider.file_lock(a.ctx, s.currentNode(), ino, held);
}

fn fileDowngradeLock(userdata: ?*anyopaque, file: File) File.DowngradeLockError!void {
    const s = fromUserdata(userdata);
    const E = File.DowngradeLockError;
    try s.enter(E);
    const h = s.fileHandle(file) catch |err| return vfsError(E, err);
    if (h.lock == .exclusive) s.setLock(file, .shared);
}

/// Windows locks are mandatory: I/O through another handle fails while a
/// handle holds an exclusive lock.
fn lockViolation(s: *Sim, file: File) bool {
    return s.persona.sharingViolations() and s.vfs.lockedByOther(handleValue(file.handle));
}

// --- network ---------------------------------------------------------------

fn ip4(bytes: [4]u8, port: u16) ionet.IpAddress {
    return .{ .ip4 = .{ .bytes = bytes, .port = port } };
}

/// Sleeps for one modeled one-way network latency (not cancelable).
fn netDelay(s: *Sim) void {
    const o = s.config.net;
    const d = s.decider.range(.net, o.latency_min_ns, @max(o.latency_min_ns, o.latency_max_ns));
    if (d > 0) s.sleepUntil(s.now_ns + d, false);
}

fn netFaultError(comptime E: type, f: net_mod.Fault) E {
    return switch (f) {
        .none => unreachable,
        .reset => fault.castError(E, error.ConnectionResetByPeer),
        .timed_out => fault.castError(E, error.ConnectionTimedOut),
    };
}

fn maybeInjectReset(s: *Sim, slot: u16) void {
    if (!s.plan.isEnabled(.net_reset)) return;
    if (!s.decider.chance(.fault, s.config.faults.net_reset_ppm)) return;
    s.net.resetConnection(slot, s.now_ns, &s.decider, s.config.net);
    s.record(.net_fault, slot, 0, 0, "reset");
    s.netWakeAll();
}

fn streamSlot(s: *Sim, handle: ionet.Socket.Handle) ?u16 {
    const slot = s.net.decode(handleValue(handle)) catch return null;
    if (s.net.sockets[slot].kind != .stream) return null;
    return slot;
}

fn netListenIp(userdata: ?*anyopaque, address: *const ionet.IpAddress, options: ionet.IpAddress.ListenOptions) ionet.IpAddress.ListenError!ionet.Socket {
    const s = fromUserdata(userdata);
    const E = ionet.IpAddress.ListenError;
    try s.enter(E);
    s.secCapability(.net_listen, &.{});
    if (options.mode != .stream) return error.SocketModeUnsupported;
    if (options.protocol != .tcp) return error.ProtocolUnsupportedByAddressFamily;
    const a = switch (address.*) {
        .ip4 => |a| a,
        .ip6 => return error.AddressFamilyUnsupported,
    };
    const node = s.currentNode();
    if (!net_mod.Net.isLocal(node, a.bytes)) return error.AddressUnavailable;
    const port = if (a.port == 0) s.net.ephemeralPort(node, false) orelse return error.AddressInUse else a.port;
    const slot = try s.net.listen(node, port, options.kernel_backlog);
    const v = s.net.encode(slot);
    s.record(.net_listen, node, port, v, "");
    return .{ .handle = toHandle(v), .address = ip4(a.bytes, port) };
}

fn netAccept(userdata: ?*anyopaque, server: ionet.Socket.Handle, options: ionet.Server.AcceptOptions) ionet.Server.AcceptError!ionet.Socket {
    _ = options;
    const s = fromUserdata(userdata);
    const E = ionet.Server.AcceptError;
    try s.enter(E);
    if (s.injected(E, .accept)) |e| return e;
    while (true) {
        const l = s.net.decode(handleValue(server)) catch return error.SocketNotListening;
        const ls = &s.net.sockets[l];
        if (ls.kind != .listener or ls.shut_recv) return error.SocketNotListening;
        if (s.net.popBacklog(l)) |sv| {
            const ss = &s.net.sockets[sv];
            const v = s.net.encode(sv);
            s.record(.net_accept, ss.node, ss.peer_node, v, "");
            const from: [4]u8 = if (ss.loopback) .{ 127, 0, 0, 1 } else net_mod.Net.nodeAddress(ss.peer_node);
            return .{ .handle = toHandle(v), .address = ip4(from, ss.peer_port) };
        }
        s.block(.net, null, true);
        try s.cancelPoint();
    }
}

fn netConnectIp(userdata: ?*anyopaque, address: *const ionet.IpAddress, options: ionet.IpAddress.ConnectOptions) ionet.IpAddress.ConnectError!ionet.Socket {
    const s = fromUserdata(userdata);
    const E = ionet.IpAddress.ConnectError;
    try s.enter(E);
    return s.connectStream(address, options, null);
}

// --- stream sockets of system-call mode (`sysnet.zig`) ---------------------
//
// A kernel's stream socket has a state `std.Io` does not: bound to a port
// before `listen` or `connect`. These give it to system-call mode.

/// Stops a listener in place, keeping its port reserved (system-call mode:
/// Linux's `shutdown(SHUT_RD)` of a listener). Waiting connections are
/// reset and a waiting `accept` fails.
pub fn unlisten(s: *Sim, handle: ionet.Socket.Handle) void {
    const slot = s.net.decode(handleValue(handle)) catch return;
    if (s.net.sockets[slot].kind != .listener) return;
    s.net.unlisten(slot, s.now_ns, &s.decider, s.config.net);
    s.touchGlobal();
    s.netWakeAll();
}

// --- threads of system-call mode (`systhread.zig`) ----------------------------

/// A task for a thread the code under test started with `clone`. It is on
/// the parent's node and ends by `exitThread`.
pub fn spawnThread(s: *Sim, start: *const fn (context: *const anyopaque) void, context: []const u8) ?TaskId {
    return s.spawn(.{ .daemon = start }, context, null, 0);
}

/// The current task, a thread, has exited: it never runs again. `clear`
/// is the word the kernel zeroes and wakes for whoever joins the thread
/// (`CLONE_CHILD_CLEARTID`). The wake and the end are one step: a joiner
/// that ran between them would find the thread's task still there.
pub fn exitThread(s: *Sim, clear: ?*u32) noreturn {
    if (clear) |word| {
        @atomicStore(u32, word, 0, .seq_cst);
        var woken: u32 = 0;
        for (s.tasks, 0..) |*t, i| {
            if (t.state == .blocked and t.block == .futex and t.block.futex == @intFromPtr(word)) {
                s.wake(@intCast(i));
                woken += 1;
            }
        }
        s.record(.futex_wake, woken, woken, 0, "");
    }
    s.finishCurrent();
}

/// `sched_yield`: another runnable task runs, if there is one.
pub fn yieldNow(s: *Sim) void {
    s.atomicFlush();
    if (s.watches_armed > 0) s.watchStep();
    if (s.runq.count > 1) s.reschedule();
}

/// A scheduling point, as any simulated operation is.
pub fn yieldPoint(s: *Sim) void {
    s.maybeYield();
}

/// Wakes the tasks waiting on the network (system-call mode: a `shutdown`
/// that only sysnet records still ends a `poll` or a read).
pub fn wakeNetwork(s: *Sim) void {
    s.touchGlobal();
    s.netWakeAll();
}

/// System-call mode's `poll`: a connected stream's readiness.
pub fn streamReadable(s: *Sim, handle: ionet.Socket.Handle) bool {
    const slot = s.streamSlot(handle) orelse return true;
    return s.net.streamReadable(slot, s.now_ns);
}

pub fn streamWritable(s: *Sim, handle: ionet.Socket.Handle) bool {
    const slot = s.streamSlot(handle) orelse return true;
    return s.net.streamWritable(slot, s.now_ns);
}

/// A listener has a connection waiting, or was shut down.
pub fn listenerReady(s: *Sim, handle: ionet.Socket.Handle) bool {
    const slot = s.net.decode(handleValue(handle)) catch return true;
    const l = &s.net.sockets[slot];
    return l.kind != .listener or l.shut_recv or l.backlog_len > 0;
}

/// Waits until the network changes or `deadline_ns` passes (system-call
/// mode's `poll`). A wait that cannot end is a deadlock, as for any
/// blocked task.
pub fn waitNetwork(s: *Sim, deadline_ns: ?u64) Io.Cancelable!void {
    s.block(.net, deadline_ns, true);
    try s.cancelPoint();
}

/// The connected stream was reset by its peer (system-call mode: Linux
/// then counts the socket closed).
pub fn streamReset(s: *Sim, handle: ionet.Socket.Handle) bool {
    const slot = s.streamSlot(handle) orelse return false;
    return s.net.isReset(slot, s.now_ns);
}

/// The error Linux reports for a reset stream: `EPIPE` when the peer's FIN
/// came first (the socket was in CLOSE_WAIT), else `ECONNRESET`.
pub fn streamResetIsPipe(s: *Sim, handle: ionet.Socket.Handle) bool {
    const slot = s.streamSlot(handle) orelse return false;
    return s.net.finArrived(slot, s.now_ns);
}

/// `bind` of a stream socket: reserves the port (an ephemeral one for 0).
pub fn bindStream(s: *Sim, address: ionet.IpAddress) ionet.IpAddress.BindError!ionet.Socket {
    const E = ionet.IpAddress.BindError;
    try s.enter(E);
    s.secCapability(.net_listen, &.{});
    const a = switch (address) {
        .ip4 => |a| a,
        .ip6 => return error.AddressFamilyUnsupported,
    };
    const node = s.currentNode();
    if (!net_mod.Net.isLocal(node, a.bytes)) return error.AddressUnavailable;
    const port = if (a.port == 0) s.net.ephemeralPort(node, false) orelse return error.AddressInUse else a.port;
    const slot = try s.net.bindStream(node, port);
    const v = s.net.encode(slot);
    s.record(.net_bind, node, port, v, "stream");
    return .{ .handle = toHandle(v), .address = ip4(a.bytes, port) };
}

/// `listen` of a bound stream socket, on its port.
pub fn listenBound(s: *Sim, handle: ionet.Socket.Handle, backlog: u31) ionet.IpAddress.ListenError!void {
    const E = ionet.IpAddress.ListenError;
    try s.enter(E);
    const slot = s.net.decode(handleValue(handle)) catch return error.Unexpected;
    if (s.net.sockets[slot].kind != .bound) return error.Unexpected;
    s.net.listenBound(slot, backlog);
    s.record(.net_listen, s.net.sockets[slot].node, s.net.sockets[slot].local_port, handleValue(handle), "bound");
}

/// `connect` of a bound stream socket: the connection takes its port.
pub fn connectFrom(s: *Sim, handle: ionet.Socket.Handle, address: ionet.IpAddress) ionet.IpAddress.ConnectError!ionet.Socket {
    const E = ionet.IpAddress.ConnectError;
    try s.enter(E);
    const slot = s.net.decode(handleValue(handle)) catch return error.Unexpected;
    if (s.net.sockets[slot].kind != .bound) return error.Unexpected;
    return s.connectStream(&address, .{ .mode = .stream }, slot);
}

/// `from`: a bound socket whose port the connection takes, and whose
/// reservation it then replaces.
fn connectStream(s: *Sim, address: *const ionet.IpAddress, options: ionet.IpAddress.ConnectOptions, from: ?u16) ionet.IpAddress.ConnectError!ionet.Socket {
    const E = ionet.IpAddress.ConnectError;
    // The bound socket by its handle, generation and all: it may be closed
    // and its slot reused while the SYN is out.
    const bound_value: ?u32 = if (from) |b| s.net.encode(b) else null;
    s.secCapability(.net_connect, &.{});
    if (options.mode != .stream) return error.SocketModeUnsupported;
    if (options.protocol) |p| if (p != .tcp) return error.ProtocolUnsupportedByAddressFamily;
    const a = switch (address.*) {
        .ip4 => |a| a,
        .ip6 => return error.AddressFamilyUnsupported,
    };
    const src = s.currentNode();
    const dst = s.net.nodeOf(src, a.bytes) orelse return error.NetworkUnreachable;
    if (s.injected(E, .connect)) |e| return e;
    const deadline = s.deadlineFrom(options.timeout) orelse s.now_ns + s.config.net.connect_timeout_ns;
    s.record(.net_connect, src, dst, a.port, "syn");
    // The SYN and SYN-ACK need both directions; retransmits continue until
    // the link heals or the deadline passes.
    while (!s.net.reachable(src, dst) or !s.net.reachable(dst, src)) {
        if (s.now_ns >= deadline) {
            s.record(.net_connect, src, dst, a.port, "timeout");
            return error.Timeout;
        }
        s.block(.net, deadline, true);
        try s.cancelPoint();
    }
    s.netDelay(); // SYN
    // A bound socket closed while the SYN was out: its port is no longer its.
    if (bound_value) |v| {
        const b = s.net.decode(v) catch return error.Canceled;
        if (b != from.? or s.net.sockets[b].kind != .bound) return error.Canceled;
    }
    const port = if (from) |b| s.net.sockets[b].local_port else s.net.ephemeralPort(src, false) orelse return error.AddressUnavailable;
    s.last_connect_port = port;
    const listener = s.net.findListener(dst, a.port) orelse {
        s.netDelay(); // RST
        s.record(.net_connect, src, dst, a.port, "refused");
        return error.ConnectionRefused;
    };
    const c = s.net.establish(src, port, listener) catch |err| switch (err) {
        error.ConnectionRefused => {
            s.netDelay();
            s.record(.net_connect, src, dst, a.port, "backlog full");
            return error.ConnectionRefused;
        },
        error.SystemResources => return error.SystemResources,
    };
    if (from) |b| s.net.releaseBound(b);
    const loopback = a.bytes[0] == 127;
    s.net.sockets[c].loopback = loopback;
    s.net.sockets[s.net.sockets[c].peer].loopback = loopback;
    s.netWakeAll(); // acceptors
    s.netDelay(); // SYN-ACK
    const v = s.net.encode(c);
    s.record(.net_connect, src, dst, v, "established");
    return .{ .handle = toHandle(v), .address = ip4(if (loopback) .{ 127, 0, 0, 1 } else net_mod.Net.nodeAddress(src), port) };
}

fn netClose(userdata: ?*anyopaque, sockets: []const ionet.Socket) void {
    const s = fromUserdata(userdata);
    for (sockets) |sock| {
        const v = handleValue(sock.handle);
        const slot = s.net.decode(v) catch continue;
        const closing = &s.net.sockets[slot];
        if (closing.kind == .dgram) s.touchInbox(closing.node, closing.local_port) else s.touchGlobal();
        s.record(.net_close, v, 0, 0, "");
        s.net.close(slot, s.now_ns, &s.decider, s.config.net);
    }
    s.netWakeAll();
}

fn netShutdown(userdata: ?*anyopaque, handle: ionet.Socket.Handle, how: ionet.ShutdownHow) ionet.ShutdownError!void {
    const s = fromUserdata(userdata);
    const E = ionet.ShutdownError;
    try s.enter(E);
    const v = handleValue(handle);
    const slot = s.net.decode(v) catch return error.SocketUnconnected;
    const sock = &s.net.sockets[slot];
    if (how != .send) sock.shut_recv = true;
    if (how != .recv and sock.kind == .stream) s.net.shutdownSend(slot, s.now_ns, &s.decider, s.config.net);
    s.record(.net_shutdown, v, @backingInt(how), 0, "");
    s.netWakeAll();
}

fn netWriteFile(userdata: ?*anyopaque, handle: ionet.Socket.Handle, header: []const u8, file_reader: *Io.File.Reader, limit: Io.Limit) ionet.Stream.Writer.WriteFileError!usize {
    _ = userdata;
    _ = handle;
    _ = header;
    _ = file_reader;
    _ = limit;
    return error.Unimplemented; // the writer falls back to read + write
}

/// Virtual DNS: `localhost`, `node<N>`, and names added with `addHost`.
fn netLookup(userdata: ?*anyopaque, host: ionet.HostName, resolved: *Io.Queue(ionet.HostName.LookupResult), options: ionet.HostName.LookupOptions) ionet.HostName.LookupError!void {
    const s = fromUserdata(userdata);
    const sio = s.io();
    defer resolved.close(sio);
    try s.cancelPoint();
    s.maybeYield();
    const name = host.bytes;
    const found: ?[4]u8 = blk: {
        if (std.ascii.eqlIgnoreCase(name, "localhost")) break :blk .{ 127, 0, 0, 1 };
        for (s.hosts[0..s.hosts_len]) |*h| {
            if (std.ascii.eqlIgnoreCase(name, h.name[0..h.name_len])) break :blk net_mod.Net.nodeAddress(h.node);
        }
        if (name.len > 4 and std.ascii.eqlIgnoreCase(name[0..4], "node")) {
            const n = std.fmt.parseInt(u8, name[4..], 10) catch break :blk null;
            if (n < s.nodes.len) break :blk net_mod.Net.nodeAddress(n);
        }
        break :blk null;
    };
    const bytes = found orelse {
        s.record(.note, 0, 0, 0, "dns: unknown host");
        return error.UnknownHostName;
    };
    if (options.family == .ip6) return error.NoAddressReturned;
    s.netDelay(); // query
    s.netDelay(); // answer
    resolved.putOne(sio, .{ .address = ip4(bytes, options.port) }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Closed => unreachable,
    };
    var canonical = host;
    if (options.canonical_name_buffer) |buf| {
        @memcpy(buf[0..name.len], name);
        canonical = .{ .bytes = buf[0..name.len] };
    }
    resolved.putOne(sio, .{ .canonical_name = canonical }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Closed => unreachable,
    };
}

// --- operations: one non-blocking step each -----------------------------------
//
// `stepOperate` tries an operation once and returns null if it would block.
// `operate` repeats the step, waiting for network events in between; the
// batch entries try every submitted operation and wait until one completes
// or the timeout passes. Only network operations ever block.

/// Waits until a network event (any socket) or `deadline`, whichever comes
/// first. Spurious wakeups are fine: callers re-check.
fn netWait(s: *Sim, deadline: ?u64) Io.Cancelable!void {
    var wake_at = s.net.nextEventAfter(s.now_ns);
    if (deadline) |d| wake_at = if (wake_at) |w| @min(w, d) else d;
    s.block(.net, wake_at, true);
    try s.cancelPoint();
}

/// Once-per-operation entry work: a scheduling point and targeted faults.
fn preOperate(s: *Sim, operation: Io.Operation) ?Io.Operation.Result {
    switch (operation) {
        .net_read => {
            s.maybeYield();
            if (s.injected(Io.Operation.NetRead.Error, .net_read)) |e| return .{ .net_read = e };
        },
        .net_write => {
            s.maybeYield();
            if (s.injected(Io.Operation.NetWrite.Error, .net_write)) |e| return .{ .net_write = e };
        },
        .net_receive => {
            s.maybeYield();
            if (s.injected(Io.Operation.NetReceive.Error, .net_read)) |e| return .{ .net_receive = .{ e, 0 } };
        },
        .net_send => {
            s.maybeYield();
            if (s.injected(Io.Operation.NetSend.Error, .net_write)) |e| return .{ .net_send = .{ e, 0 } };
        },
        else => {},
    }
    return null;
}

fn stepOperate(s: *Sim, operation: Io.Operation) ?Io.Operation.Result {
    return switch (operation) {
        .file_read_streaming => |op| .{ .file_read_streaming = s.readStreaming(op) },
        .file_write_streaming => |op| .{ .file_write_streaming = s.writeStreaming(op) },
        .net_read => |op| if (s.netReadStep(op)) |r| .{ .net_read = r } else null,
        .net_write => |op| if (s.netWriteStep(op)) |r| .{ .net_write = r } else null,
        .net_send => |op| .{ .net_send = s.netSendStep(op) },
        .net_receive => |op| if (s.netReceiveStep(op)) |r| .{ .net_receive = r } else null,
        .device_io_control => Io.failingOperate(s, operation) catch unreachable,
    };
}

fn operate(userdata: ?*anyopaque, operation: Io.Operation) Io.Cancelable!Io.Operation.Result {
    const s = fromUserdata(userdata);
    try s.cancelPoint();
    if (s.preOperate(operation)) |r| return r;
    while (true) {
        if (s.stepOperate(operation)) |r| return r;
        try s.netWait(null);
    }
}

fn batchRun(s: *Sim, b: *Io.Batch, deadline: ?u64) (Io.Cancelable || Io.Timeout.Error)!void {
    const none: Io.Operation.OptionalIndex = .none;
    var first = true;
    while (true) {
        var progressed = false;
        var prev = none;
        var idx = b.submitted.head;
        while (idx != .none) {
            const i = idx.toIndex();
            const next = b.storage[i].submission.node.next;
            const op = b.storage[i].submission.operation;
            const pre = if (first) s.preOperate(op) else null;
            if (pre orelse s.stepOperate(op)) |result| {
                // Unlink from `submitted`, append to `completed`.
                if (prev == .none) b.submitted.head = next else b.storage[prev.toIndex()].submission.node.next = next;
                if (b.submitted.tail == idx) b.submitted.tail = prev;
                b.storage[i] = .{ .completion = .{ .node = .{ .next = .none }, .result = result } };
                if (b.completed.tail == .none) {
                    b.completed.head = idx;
                } else {
                    b.storage[b.completed.tail.toIndex()].completion.node.next = idx;
                }
                b.completed.tail = idx;
                progressed = true;
            } else {
                prev = idx;
            }
            idx = next;
        }
        first = false;
        if (progressed or b.completed.head != .none or b.submitted.head == .none) return;
        if (deadline) |d| if (s.now_ns >= d) return error.Timeout;
        try s.netWait(deadline);
    }
}

fn batchAwaitAsync(userdata: ?*anyopaque, b: *Io.Batch) Io.Cancelable!void {
    const s = fromUserdata(userdata);
    try s.cancelPoint();
    s.batchRun(b, null) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Timeout => unreachable,
    };
}

fn batchAwaitConcurrent(userdata: ?*anyopaque, b: *Io.Batch, timeout: Io.Timeout) Io.Batch.AwaitConcurrentError!void {
    const s = fromUserdata(userdata);
    try s.cancelPoint();
    return s.batchRun(b, s.deadlineFrom(timeout));
}

/// Operations not yet complete stay on the `submitted` list (they have no
/// side effects until they complete), so there is nothing to interrupt.
fn batchCancel(userdata: ?*anyopaque, b: *Io.Batch) void {
    _ = userdata;
    _ = b;
}

fn netReadStep(s: *Sim, op: Io.Operation.NetRead) ?Io.Operation.NetRead.Result {
    const E = Io.Operation.NetRead.Error;
    var total: usize = 0;
    for (op.data) |d| total += d.len;
    const slot = s.streamSlot(op.socket_handle) orelse return error.SocketUnconnected;
    if (total > 0) s.maybeInjectReset(slot);
    switch (s.net.recv(slot, op.data, s.shortLen(total), s.now_ns)) {
        .data => |n| {
            s.secIngress(s.socketSink(.net_stream, slot, s.net.sockets[slot].peer_node), op.data, n);
            s.record(.net_read, slot, n, 0, "");
            s.netWakeAll(); // writers waiting for space
            return .{ .data_len = n };
        },
        .eof => {
            s.record(.net_read, slot, 0, 1, "eof");
            return .{ .data_len = 0 };
        },
        .fault => |f| {
            s.record(.net_fault, slot, @backingInt(f), 1, @tagName(f));
            return netFaultError(E, f);
        },
        .would_block => return null,
    }
}

fn netWriteStep(s: *Sim, op: Io.Operation.NetWrite) ?Io.Operation.NetWrite.Result {
    const E = Io.Operation.NetWrite.Error;
    var total: usize = op.header.len;
    if (op.data.len > 0) {
        for (op.data[0 .. op.data.len - 1]) |d| total += d.len;
        total += op.data[op.data.len - 1].len * op.splat;
    }
    if (total == 0) return 0;
    const slot = s.streamSlot(op.socket_handle) orelse return error.SocketUnconnected;
    s.maybeInjectReset(slot);
    switch (s.net.checkSend(slot, s.now_ns)) {
        .fault => |f| {
            s.record(.net_fault, slot, @backingInt(f), 2, @tagName(f));
            return netFaultError(E, f);
        },
        .shut_down => return error.SocketUnconnected,
        .peer_gone => {
            // The bytes vanish; the peer answers with RST a round trip later.
            s.net.setFault(slot, .reset, s.now_ns + 2 * s.config.net.latency_min_ns);
            s.record(.net_write, slot, total, 1, "peer closed");
            return total;
        },
        .would_block => return null,
        .ready => |free| {
            const limit = @min(free, s.shortLen(total));
            const segment_count: usize = if (op.data.len == 0) 1 else op.data.len + op.splat;
            var done: usize = 0;
            var k: usize = 0;
            while (k < segment_count and done < limit) : (k += 1) {
                const seg: []const u8 = if (k == 0) op.header else op.data[@min(k - 1, op.data.len - 1)];
                const n = @min(seg.len, limit - done);
                if (n == 0) continue;
                var bytes: []const u8 = seg[0..n];
                if (s.sec) |sa| {
                    const sink = s.socketSink(.net_stream, slot, s.net.sockets[slot].peer_node);
                    if (n <= s.sec_scratch.len and sa.provider.stream(sa.ctx, sink, bytes, s.sec_scratch)) {
                        bytes = s.sec_scratch[0..n];
                        s.record(.net_write, slot, n, 2, "byzantine");
                    }
                    s.secEgress(sink, bytes);
                }
                s.net.push(slot, bytes);
                done += n;
            }
            s.net.commit(slot, @intCast(done), false, s.now_ns, &s.decider, s.config.net);
            s.stats.net_bytes += done;
            s.stats.net_writes += 1;
            s.record(.net_write, slot, done, 0, "");
            s.netWakeAll(); // readers
            return done;
        },
    }
}

// --- datagrams ---------------------------------------------------------------

/// Datagrams that have arrived at a datagram socket and are not read
/// (system-call mode's `connect`, `sysnet.zig`).
pub fn datagramsArrived(s: *Sim, handle: ionet.Socket.Handle) u32 {
    const slot = s.dgramSlot(handle) orelse return 0;
    return s.net.datagramsArrived(slot, s.now_ns);
}

/// Drops the arrived datagrams not from `from` (port 0: any port): a
/// connected socket's filter, which Linux applies on arrival.
pub fn dropDatagramsNotFrom(s: *Sim, handle: ionet.Socket.Handle, from: ionet.IpAddress) void {
    const slot = s.dgramSlot(handle) orelse return;
    const f = switch (from) {
        .ip4 => |x| x,
        .ip6 => return,
    };
    const sock = &s.net.sockets[slot];
    var i: usize = 0;
    while (i < sock.seg_len) {
        const seg = sock.segs[i];
        const bytes: [4]u8 = if (seg.loopback) .{ 127, 0, 0, 1 } else net_mod.Net.nodeAddress(seg.src_node);
        const match = (f.port == 0 or seg.src_port == f.port) and std.mem.eql(u8, &bytes, &f.bytes);
        if (seg.deliver_at <= s.now_ns and !match) s.net.dropDatagram(slot, i) else i += 1;
    }
}

/// Of those, the ones from `from` (a connected datagram socket's peer).
pub fn datagramsArrivedFrom(s: *Sim, handle: ionet.Socket.Handle, from: ionet.IpAddress) u32 {
    const slot = s.dgramSlot(handle) orelse return 0;
    const f = switch (from) {
        .ip4 => |x| x,
        .ip6 => return 0,
    };
    const sock = &s.net.sockets[slot];
    var n: u32 = 0;
    for (sock.segs[0..sock.seg_len]) |seg| {
        // A peer port of 0 matches any port (Linux).
        if (seg.deliver_at > s.now_ns or (f.port != 0 and seg.src_port != f.port)) continue;
        const bytes: [4]u8 = if (seg.loopback) .{ 127, 0, 0, 1 } else net_mod.Net.nodeAddress(seg.src_node);
        if (std.mem.eql(u8, &bytes, &f.bytes)) n += 1;
    }
    return n;
}

fn dgramSlot(s: *Sim, handle: ionet.Socket.Handle) ?u16 {
    const slot = s.net.decode(handleValue(handle)) catch return null;
    if (s.net.sockets[slot].kind != .dgram) return null;
    return slot;
}

fn netBindIp(userdata: ?*anyopaque, address: *const ionet.IpAddress, options: ionet.IpAddress.BindOptions) ionet.IpAddress.BindError!ionet.Socket {
    const s = fromUserdata(userdata);
    const E = ionet.IpAddress.BindError;
    try s.enter(E);
    s.secCapability(.net_listen, &.{});
    if (options.mode != .dgram) return error.SocketModeUnsupported;
    if (options.protocol) |p| if (p != .udp) return error.ProtocolUnsupportedByAddressFamily;
    const a = switch (address.*) {
        .ip4 => |a| a,
        .ip6 => return error.AddressFamilyUnsupported,
    };
    const node = s.currentNode();
    if (!net_mod.Net.isLocal(node, a.bytes)) return error.AddressUnavailable;
    const port = if (a.port == 0) s.net.ephemeralPort(node, true) orelse return error.AddressInUse else a.port;
    const slot = try s.net.bind(node, port);
    const v = s.net.encode(slot);
    s.touchInbox(node, port);
    s.record(.net_bind, node, port, v, "");
    return .{ .handle = toHandle(v), .address = ip4(a.bytes, port) };
}

/// Core runs no processes: a spawn or an exec fails as on a system without
/// them, after the security layer has seen the command.
fn processSpawn(userdata: ?*anyopaque, options: std.process.SpawnOptions) std.process.SpawnError!std.process.Child {
    const s = fromUserdata(userdata);
    s.secCapability(.process_spawn, options.argv);
    return error.OperationUnsupported;
}

fn processReplace(userdata: ?*anyopaque, options: std.process.ReplaceOptions) std.process.ReplaceError {
    const s = fromUserdata(userdata);
    s.secCapability(.process_spawn, options.argv);
    return error.OperationUnsupported;
}

/// Datagrams never block on send. Each may be lost or duplicated (swarm
/// class `datagram_loss`), and is dropped across a cut link, when nothing
/// is bound to the destination port, or when the receive buffer is full.
fn netSendStep(s: *Sim, op: Io.Operation.NetSend) Io.Operation.NetSend.Result {
    const slot = s.dgramSlot(op.socket_handle) orelse return .{ error.SocketUnconnected, 0 };
    const src = s.net.sockets[slot].node;
    const f = s.config.faults;
    const loss_on = s.plan.isEnabled(.datagram_loss);
    for (op.messages, 0..) |*m, i| {
        const a = switch (m.address.*) {
            .ip4 => |a| a,
            .ip6 => return .{ error.AddressFamilyUnsupported, i },
        };
        const dst = s.net.nodeOf(src, a.bytes) orelse return .{ error.NetworkUnreachable, i };
        s.touchInbox(dst, a.port);
        if (m.data_len > s.net.datagramCapacity()) return .{ error.MessageOversize, i };
        var payload: []const u8 = m.data_ptr[0..m.data_len];
        if (s.sec) |sa| {
            const sink = s.socketSink(.datagram, slot, dst);
            const cap = s.sec_scratch.len / 2;
            if (sa.provider.datagram(sa.ctx, sink, payload, s.sec_scratch[0..cap])) |n| {
                payload = s.sec_scratch[0..n];
                s.record(.net_send, slot, n, 0, "byzantine");
            }
            s.secEgress(sink, payload);
            if (sa.provider.replay(sa.ctx, sink, payload, s.sec_scratch[cap..])) |n| {
                // The attacker's copy: no loss decisions, so a replay that
                // was chosen is one that arrives.
                const replayed = s.sec_scratch[cap..][0..n];
                const outcome = s.net.sendDatagram(slot, dst, a.port, replayed, false, false, s.now_ns, &s.decider, s.config.net, a.bytes[0] == 127);
                s.record(.net_send, slot, n, @backingInt(outcome), "replay");
            }
        }
        const lose = loss_on and s.decider.chance(.fault, f.datagram_loss_ppm);
        const dup = loss_on and s.decider.chance(.fault, f.datagram_duplicate_ppm);
        const outcome = s.net.sendDatagram(slot, dst, a.port, payload, lose, dup, s.now_ns, &s.decider, s.config.net, a.bytes[0] == 127);
        s.stats.datagrams += 1;
        s.stats.net_bytes += m.data_len;
        s.record(.net_send, slot, m.data_len, @backingInt(outcome), @tagName(outcome));
    }
    s.netWakeAll();
    return .{ null, op.messages.len };
}

fn netReceiveStep(s: *Sim, op: Io.Operation.NetReceive) ?Io.Operation.NetReceive.Result {
    const slot = s.dgramSlot(op.socket_handle) orelse return .{ error.SocketUnconnected, 0 };
    // Also when nothing is there: an empty read depends on the senders.
    s.touchInbox(s.net.sockets[slot].node, s.net.sockets[slot].local_port);
    if (op.message_buffer.len == 0) return .{ null, 0 };
    var count: usize = 0;
    var used: usize = 0;
    while (count < op.message_buffer.len) {
        const out = op.data_buffer[used..];
        if (count > 0 and out.len == 0) break;
        const dg = s.net.recvDatagram(slot, out, s.now_ns) orelse break;
        const m = &op.message_buffer[count];
        m.from = ip4(if (dg.loopback) .{ 127, 0, 0, 1 } else net_mod.Net.nodeAddress(dg.src_node), dg.src_port);
        m.data = out[0..dg.len];
        if (s.sec) |a| a.provider.ingress(a.ctx, s.socketSink(.datagram, slot, dg.src_node), m.data);
        m.control = m.control[0..0];
        m.flags = .{ .eor = false, .trunc = dg.truncated, .ctrunc = false, .oob = false, .errqueue = false };
        s.record(.net_receive, slot, dg.len, dg.src_node, "");
        used += dg.len;
        count += 1;
    }
    if (count == 0) return null;
    return .{ null, count };
}

// --- links -------------------------------------------------------------------

fn fileKind(k: vfs_mod.Kind) File.Kind {
    return switch (k) {
        .dir => .directory,
        .symlink => .sym_link,
        .file, .free => .file,
    };
}

fn dirHardLink(userdata: ?*anyopaque, old_dir: Dir, old_sub_path: []const u8, new_dir: Dir, new_sub_path: []const u8, options: Dir.HardLinkOptions) Dir.HardLinkError!void {
    const s = fromUserdata(userdata);
    const E = Dir.HardLinkError;
    try s.enter(E);
    s.syncClock();
    if (s.injected(E, .metadata)) |e| return e;
    const old_parent = s.dirInode(old_dir) catch |err| return vfsError(E, err);
    const new_parent = s.dirInode(new_dir) catch |err| return vfsError(E, err);
    const ino = s.vfs.lookupEx(old_parent, old_sub_path, options.follow_symlinks) catch |err| return vfsError(E, err);
    s.vfs.hardLink(ino, new_parent, new_sub_path) catch |err| return vfsError(E, err);
    s.record(.fs_link, ino, 0, 0, new_sub_path);
}

fn fileHardLink(userdata: ?*anyopaque, file: File, new_dir: Dir, new_sub_path: []const u8, options: File.HardLinkOptions) File.HardLinkError!void {
    _ = options;
    const s = fromUserdata(userdata);
    const E = File.HardLinkError;
    try s.enter(E);
    s.syncClock();
    if (s.injected(E, .metadata)) |e| return e;
    const h = s.fileHandle(file) catch |err| return vfsError(E, err);
    const ino = h.inode;
    const new_parent = s.dirInode(new_dir) catch |err| return vfsError(E, err);
    s.vfs.hardLink(ino, new_parent, new_sub_path) catch |err| return vfsError(E, err);
    s.record(.fs_link, ino, 1, 0, new_sub_path);
}

fn dirSymLink(userdata: ?*anyopaque, dir: Dir, target_path: []const u8, sym_link_path: []const u8, flags: Dir.SymLinkFlags) Dir.SymLinkError!void {
    _ = flags;
    const s = fromUserdata(userdata);
    const E = Dir.SymLinkError;
    try s.enter(E);
    s.syncClock();
    if (s.injected(E, .metadata)) |e| return e;
    const parent = s.dirInode(dir) catch |err| return vfsError(E, err);
    s.vfs.symLink(parent, target_path, sym_link_path) catch |err| return vfsError(E, err);
    s.record(.fs_link, 0, 2, 0, sym_link_path);
}

fn dirReadLink(userdata: ?*anyopaque, dir: Dir, sub_path: []const u8, buffer: []u8) Dir.ReadLinkError!usize {
    const s = fromUserdata(userdata);
    const E = Dir.ReadLinkError;
    try s.enter(E);
    const parent = s.dirInode(dir) catch |err| return vfsError(E, err);
    return s.vfs.readLink(parent, sub_path, buffer) catch |err| return vfsError(E, err);
}

/// Adds a coverage feature (guided exploration); no-op otherwise.
pub fn cover(s: *Sim, feature: u64) void {
    if (s.coverage) |m| m.set(feature);
}

/// Ends a deterministic setup phase: from here on the run draws from
/// `seed`, with a fresh swarm mask. Called by `check` between
/// `Options.setup` and the body, in the fork server child and in-process
/// alike, so both produce the same trace.
pub fn reseed(s: *Sim, seed: u64) void {
    s.seed = seed;
    s.decider.reseed(seed);
    s.plan = .init(s.config.faults);
    if (s.config.swarm) s.plan.drawSwarm(&s.decider);
    for (s.nodes) |*n| n.heap.oom_ppm = if (s.plan.isEnabled(.oom)) s.config.faults.oom_ppm else 0;
    s.pctBegin();
    s.record(.note, 0, 0, 0, "reseed");
}
