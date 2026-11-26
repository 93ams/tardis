# User guide

This guide covers the core of TARDIS: writing a test, stating what must be
true, choosing faults, and sizing a campaign. Read the
[tutorial](tutorial.md) first if you have not written a test yet.

The code blocks are excerpts. Each names the file it comes from, and that
file is compiled and run by `zig build test` or `zig build test-examples`.
The excerpts leave out imports and helpers; open the file for the whole
program. They assume:

```zig
const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;
const Env = tardis.Env;
```

Defaults and names in this guide are those of `src/root.zig`. `zig build
docs` writes the full API reference to `zig-out/docs`.

## 1. Writing a check

A test body is a function that takes an `*Env` and returns an error union.
`check` runs it many times, each run with its own seed.

```zig
pub fn check(gpa: Allocator, comptime body: fn (*Env) anyerror!void, options: Options) !void
```

From [`examples/counter.zig`](../examples/counter.zig): three tasks bump a
counter in a file, and the body states that no increment is lost.

```zig
fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    try write(io, env.dir, 0);
    var lock: Io.Mutex = .init;
    var failed = false;
    var group: Io.Group = .init;
    defer group.cancel(io);
    for (0..tasks) |_| try group.concurrent(io, increment, .{ io, env.dir, &lock, variant, &failed });
    try group.await(io);
    try env.always("no increment is lost", !failed and try read(io, env.dir) == tasks);
}

test "counter: holding a lock across the read and the write keeps every update" {
    try tardis.check(std.testing.allocator, fixed, .{ .iterations = 200 });
}
```

The code under test (`increment`, `read`, `write`) takes an `Io` and a
`Dir` and knows nothing about TARDIS.

Every field of `Options` has a default, so `.{}` is a valid campaign: 100
iterations on the `linux_ext4` persona, one node, random exploration,
shrinking on.

A run fails when the body returns an error, and also when `check` itself
finds one of these (`tardis.Error`):

| Error | Meaning |
|---|---|
| `AssertionFailed` | an `always` was false, or an `eventually` timed out |
| `Deadlock` | every task is blocked |
| `Livelock` | an `expectProgress` bound ran out |
| `ResourceLeak` | the body returned with a task, a handle or an allocation still live (`Options.leak_check`, on by default) |
| `NonDeterministic` | a run did not repeat when run again with the same seed (`Options.determinism_check_every`, 16 by default; 0 turns it off) |
| `SometimesNeverTrue` | a `sometimes` never held in the whole campaign |
| `StraySyscall` | the code made a real system call while the trap was on |
| `SyscallModeUnsupported`, `FibersUnsupported` | the platform cannot do what was asked |

A test that expects a failure turns the report off so the log stays
quiet. Also from `examples/counter.zig`:

```zig
test "counter: read-then-write without a lock loses an update" {
    try std.testing.expectError(error.AssertionFailed, tardis.check(std.testing.allocator, buggy, .{
        .iterations = 200,
        .report = false,
    }));
}
```

### The loop form

`tardis.sim(gpa, options)` gives the iterations to a `while` loop in the
test, for a test that wants to drive them itself. From
[`src/tests/fs_test.zig`](../src/tests/fs_test.zig):

```zig
test "targeted fault injection: the Nth write fails" {
    var s = try tardis.sim(testing.allocator, .{ .iterations = 10, .personas = &.{.windows_ntfs} });
    defer s.deinit();
    while (s.step()) |env| {
        const io = env.io;
        var f = try env.dir.createFile(io, "wal.dat", .{});
        defer f.close(io);
        env.injectIoErrorAfter(.write, 1, error.NoSpaceLeft);
        try f.writePositionalAll(io, "a", 0);
        try testing.expectError(error.NoSpaceLeft, f.writePositionalAll(io, "b", 1));
        try f.writePositionalAll(io, "c", 1); // one-shot
    }
    try s.finish();
}
```

Prefer `check`. The loop form has limits that `check` does not: a
deadlock panics instead of failing the run, `expectProgress` does not
watch, system-call mode is refused, and the campaign variables of section
7 (`TARDIS_PRESET` and the others) are not read. It does read
`TARDIS_SEED`, `TARDIS_PERSONA` and `TARDIS_REPLAY`.

## 2. What `env` gives

`Env` has these fields:

| Field | What it is |
|---|---|
| `io` | a `std.Io`. Files, sockets, tasks, sleeping, clocks and random bytes all go through it |
| `dir` | the root of the simulated filesystem, a `std.Io.Dir`. It stays valid across crashes |
| `allocator` | the heap of the code under test. It is wiped at every crash and every iteration, it is checked for leaks, and it can be made to fail (`faults.oom_ppm`) |
| `seed`, `persona`, `iteration` | which run this is |
| `sim` | the simulator itself; tests rarely need it |

There is no separate clock or random field. Both come from `env.io`, the
way production code gets them.

**The clock.** From [`examples/lease.zig`](../examples/lease.zig):

```zig
fn now(io: Io, variant: Variant) i128 {
    // The whole difference: the time of day, or a clock that cannot be set.
    return switch (variant) {
        .buggy => Io.Clock.real.now(io).nanoseconds,
        .fixed => Io.Clock.awake.now(io).nanoseconds,
    };
}
```

Time is virtual. It moves only when every task waits (a sleep, a
timeout), never with the host's clock, so a test that sleeps for an hour
takes no real time. `env.nowNs()` is the virtual time since the run began,
and `env.advanceTimeNs(delta_ns)` sleeps the caller. The time of day
starts at `Options.epoch_offset_ns` (1,700,000,000 seconds after the
epoch) and can be stepped with `env.stepClock(node, delta_ns)`; monotonic
clocks are not affected by a step.

**Random bytes.** `env.io.random(&buf)` fills a buffer from the seed, as
in [`src/tests/determinism_test.zig`](../src/tests/determinism_test.zig).
Code under test that asks its `Io` for randomness gets the same bytes on
every replay.

**Test inputs.** `env.fuzz(T)` builds a value of type `T` from the seed:
integers (biased towards boundary values), structs, enums, optionals,
arrays and slices. Slices are freed at the end of the iteration. The
shrinker lowers these values along with the other decisions. From
[`examples/udp_retry.zig`](../examples/udp_retry.zig):

```zig
        const amount = 1 + (try env.fuzz(u8)) % 9;
```

Code that has an `Io` but no `Env` can call `tardis.fuzzInput(T, io)`
and `tardis.assertSometimes(io, name, cond)`. `tardis.isSimulated(io)`
says whether an `Io` is a simulated one.

**Child processes.** A program that shells out is tested by registering,
for the run, what each command does. `env.registerProgram(name, f)` makes
a `std.process.spawn` or `std.process.run` whose `argv[0]` is `name` (or a
path ending in it) run `f` as a process on the caller's node. `f` takes a
`*tardis.Process`, with its own `io`, `argv`, `stdin`, `stdout` and
`stderr`, and returns the exit code. From
[`src/tests/process_test.zig`](../src/tests/process_test.zig):

```zig
fn upper(p: *tardis.Process) anyerror!u8 {
    // reads p.stdin to its end, writes it upper-cased to p.stdout
}

try env.registerProgram("upper", upper);
var child = try std.process.spawn(env.io, .{ .argv = &.{"upper"}, .stdin = .pipe, .stdout = .pipe });
```

Pipes hold 64 KiB and block as real ones do, so the two classic bugs are
found as deadlocks: waiting for a child whose standard input was never
closed, and waiting before reading output larger than a pipe. A pipe end
passed to a second child (`.stdin = .{ .file = a.stdout.? }`) is
duplicated, so a pipeline works when the parent closes its copy. A child
never waited for is a leak. A command nobody registered fails with
`error.FileNotFound`; only `argv[0]` is matched. Not modelled: the working
directory and the environment of the child, signals other than `kill`
(which cancels the program at its next cancelation point, so a program
that never reaches one is waited for), resource usage statistics, and,
for the security layer, taint carried through a pipe.

## 3. The oracles

An oracle is how a test says what must be true. Give each a name: the
failure report prints it.

| Oracle | Use it for | Fails with |
|---|---|---|
| `try env.always(name, cond)` | something that must hold every time it is checked | `AssertionFailed`, in that run |
| `env.sometimes(name, cond)` | something that must happen at least once in the campaign: proof that the test reaches what it claims to | `SometimesNeverTrue`, at the end of the campaign |
| `try env.eventually(name, timeout_ns, ctx, predicate)` | something that must become true after a disturbance ends | `AssertionFailed`, when the timeout passes |
| `env.expectProgress(name, bound)` with `env.progress(name)` | a system that must keep getting work done | `Livelock`, when a bound runs out |

Two more are always on and need no call: a run in which every task is
blocked fails with `Deadlock`
([`examples/deadlock.zig`](../examples/deadlock.zig)), and a body that
returns with something still open or allocated fails with `ResourceLeak`.
`env.expectNoLeaks()` runs the leak check at a point of your choosing.

### `always`

See section 1. Check it wherever the property should hold, not only at
the end. From [`examples/oom_partial.zig`](../examples/oom_partial.zig):

```zig
    for (0..24) |i| {
        // Out of memory is an answer the caller lives with.
        index.add(gpa, @intCast(i), @intCast(i * 10), variant) catch {};
        try env.always("the index's two lists are the same length", index.names.items.len == index.sizes.items.len);
    }
```

### `sometimes`

An `always` that can never fail says nothing. A `sometimes` that never
holds says the test does not reach the code it was written for. From
[`examples/never_retried.zig`](../examples/never_retried.zig):

```zig
fn scenario(env: *Env, variant: Variant) !void {
    // A save that fails is an outcome the caller handles.
    const saved = save(env.io, env.dir, variant, "remember the milk") catch null;
    env.sometimes("a save succeeds on its second try", saved == .second_try);
}
```

With `workers` above one the outcome does not depend on thread timing.

### `eventually`

It calls `predicate(ctx)` every 10 ms of virtual time until it returns
true. The predicate may do I/O, and an error from it counts as "not yet".
From [`examples/replica.zig`](../examples/replica.zig):

```zig
fn agree(c: *Cluster) !bool {
    return try readValue(c.io, c.primary) == try readValue(c.io, c.replica);
}

    // In the body, after the partition has healed:
    try env.eventually("after the partition heals, the replica catches up", 30 * std.time.ns_per_s, &cluster, agree);
```

### `expectProgress`

A livelocked run does not fail an `always`: it never ends. Arm a watch,
report progress where the system does what it is for, and the run fails
when the bound runs out. From
[`examples/livelock.zig`](../examples/livelock.zig):

```zig
    env.expectProgress("a transfer completes", .{ .within_ns = std.time.ns_per_ms });
    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, transfer, .{ env, &accounts, 0, 30, 2, variant });
    try group.concurrent(io, transfer, .{ env, &accounts, 1, 20, arrives_us, variant });
    try group.await(io);
    env.progressDone("a transfer completes");
```

`transfer` calls `env.progress("a transfer completes")` when it is done.
`ProgressBound` has two limits, and at least one must be set:
`within_ns` is virtual time, and catches retries that sleep;
`within_steps` counts simulated operations and scheduling points, and
catches tasks that spin without sleeping. Choose bounds far above what
progress takes on a fair schedule. A run can hold up to eight watches.

## 4. Faults

The simulator injects faults by itself. `Options.faults` is a
`tardis.FaultOptions`; rates are in parts per million.

| Field | Default | What it does |
|---|---|---|
| `io_error_ppm` | 0 | a file operation fails with an I/O error |
| `short_io_ppm` | 200,000 | a read or write transfers fewer bytes than asked |
| `oom_ppm` | 0 | `env.allocator` returns `error.OutOfMemory` |
| `spurious_wakeup_ppm` | 50,000 | a futex wait returns without a wake |
| `io_latency_min_ns`, `io_latency_max_ns` | 1,000 and 100,000 | latency per file operation; both zero turns it off |
| `torn_writes` | true | on power loss, unsynced sectors may tear |
| `metadata_loss` | true | on power loss, uncommitted metadata operations may be lost |
| `net_reset_ppm` | 0 | a stream read or write finds its connection reset |
| `clock_drift_ppm_max` | 0 | each node's monotonic clock drifts by up to this |
| `datagram_loss_ppm` | 20,000 | a datagram is lost |
| `datagram_duplicate_ppm` | 5,000 | a datagram is delivered twice |

So by default a test sees short reads and writes, spurious wake-ups,
latency, datagram loss and duplication, and lossy power cuts. It does not
see I/O errors, allocation failures or connection resets until you ask
for them.

**Turning a fault up.** Set its rate. From
[`examples/oom_partial.zig`](../examples/oom_partial.zig) and
[`examples/never_retried.zig`](../examples/never_retried.zig):

```zig
pub const options: tardis.Options = .{ .iterations = 300, .faults = .{ .oom_ppm = 100_000 } };
```

```zig
pub const options: tardis.Options = .{ .iterations = 200, .faults = .{ .io_error_ppm = 100_000 } };
```

**Turning a fault down.** Set its rate to 0 (or its switch to false).

**Swarm testing.** `Options.swarm` is on by default: each iteration
draws a random subset of the fault classes and turns the others off for
that run. A rate you set is therefore in force in about half the runs.
Set `.swarm = false` to have every class in every run, as
`src/tests/fs_test.zig` does:

```zig
    var s = try tardis.sim(testing.allocator, .{ .iterations = 40, .swarm = false, .faults = .{ .oom_ppm = 300_000 } });
```

**One fault at a chosen point.**
`env.injectIoErrorAfter(op, successes, err)` lets the next `successes`
operations of kind `op` succeed and fails the one after with `err`, once.
The kinds are `open`, `read`, `write`, `sync`, `metadata`, `any`,
`connect`, `accept`, `net_read` and `net_write`. The example is in
section 1, under "The loop form".

**The schedule.** `Options.preempt_ppm` (250,000) is the chance of
switching tasks at each `std.Io` call. `Options.async_inline_ppm`
(200,000) is the chance that `io.async` runs its task inline.
`Options.schedule = .pct` picks tasks by priority instead: the runnable
task with the highest priority always runs, and a run lowers the running
task at `pct_depth - 1` points (3 by default, so two). It reaches orders
where one task runs for a long time while another waits, which a switch
at every fourth call almost never gives, and it is worse at bugs that
need a switch at one exact place
([measurements.md](measurements.md), section 4). When a task that could
run has waited more than 4,096 steps, the task above it gives way, so a
task that polls without blocking does not keep the others out for ever.
An `expectProgress` bound in steps should be above that under `.pct`.
`tardis.exhaustive` does not use the option.

**The network.** `Options.net` is a `tardis.NetOptions`: segment latency
(`latency_min_ns`, `latency_max_ns`: 50,000 and 2,000,000), the connect
timeout (10 s), and what a peer sees when a node crashes
(`blackhole_ppm`, 300,000: the connection times out instead of being
reset).

**Bounds.** `Options.limits` is a `tardis.Limits`: `tasks_max` (64),
`fiber_stack_bytes` (256 KiB), `heap_bytes_max` (64 MiB for
`env.allocator`), `fuzz_slice_len_max` (1024), `trace_ring_len` (64) and
the filesystem and network table sizes.

## 5. Crashes and durability

`env.crashAndReboot(mode)` crashes the machine and brings it back. Every
task except the caller is dropped without running its `defer`s, open
handles become invalid, `env.allocator` is wiped, and `env.dir` stays
valid. What the filesystem keeps depends on the mode:

| `CrashMode` | What survives |
|---|---|
| `.process_crash` | everything written: the page cache survives a killed process |
| `.power_loss` | what was made durable, plus whatever the persona and the seed let through |

From [`examples/rename_unsynced.zig`](../examples/rename_unsynced.zig):

```zig
pub const options: tardis.Options = .{ .iterations = 200, .personas = &.{ .linux_xfs, .posix_strict } };

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    try env.dir.writeFile(io, .{ .sub_path = "settings", .data = "volume=3" });
    try syncPath(io, env.dir, "settings");
    try syncPath(io, env.dir, ".");

    try replace(io, env.dir, "volume=7", variant);
    try env.crashAndReboot(.power_loss);

    var buf: [32]u8 = undefined;
    const got = try env.dir.readFile(io, "settings", &buf);
    const ok = std.mem.eql(u8, got, "volume=3") or std.mem.eql(u8, got, "volume=7");
    try env.always("the settings are the old ones or the new ones", ok);
}
```

The pattern is always the same: do the work, cut the power, then check
what the program promised about its files.

### Personas

A persona is a model of one filesystem. `Options.personas` lists the
ones to run; each gets `iterations` runs. The default is `linux_ext4`
alone.

| Persona | What sets it apart in the model |
|---|---|
| `linux_ext4` | a rename over an existing file flushes the new file's data first; an `fsync` of a file that has not changed commits no other metadata |
| `linux_xfs` | no flush on rename: a rename can be durable before the data it names; an `fsync` of a file or directory that has not changed commits no other metadata |
| `windows_ntfs` | names ignore case, `\` separates, Win32 name rules, an open file cannot be deleted |
| `macos_apfs` | names ignore case and Unicode normalization; `fsync` is taken to be durable |
| `freebsd_zfs` | copy-on-write: no torn sectors, and a rename is ordered after the data written before it |
| `posix_strict` | the least POSIX allows: an `fsync` of a file does not commit other metadata, and any subset of unsynced metadata operations may be lost |

On every persona but `posix_strict`, the metadata operations lost in a
power cut are the most recent ones. These rules are the functions of
`Persona` in `src/model/vfs.zig`.

The personas are models written from documentation. One rule of
`linux_ext4` has been checked against the real filesystem under power
loss, and corrected by it ([power-cut.md](power-cut.md)); the rest has
not ([qualification.md](qualification.md) says what has been checked). Run
`posix_strict` when you want the harshest reading, and several personas
when the code must be portable:

```zig
    try tardis.check(std.testing.allocator, scenario, .{
        .iterations = 200,
        .personas = &.{ .linux_ext4, .linux_xfs, .windows_ntfs, .posix_strict, .macos_apfs, .freebsd_zfs },
    });
```

(from the [tutorial](tutorial.md), step 7).

## 6. Several nodes and the network

`Options.nodes` is the number of simulated machines (1 by default). Each
has its own filesystem, heap, clock and address: node `n` is
`10.0.0.(n+1)`. The test body runs on node 0.

| Call | What it does |
|---|---|
| `env.spawnOn(node, function, args)` | runs `function` as a daemon on `node`. It is not awaited. If it returns an error other than `error.Canceled`, the run fails |
| `env.address(node, port)` | the node's address, as a `std.Io.net.IpAddress` |
| `env.nodeAllocator(node)` | that node's heap; give each daemon its own node's |
| `env.partition(a, b)` | cuts both directions between two nodes |
| `env.cutLink(from, to)`, `env.healLink(from, to)` | one direction only |
| `env.isolate(node)` | cuts a node off from all the others |
| `env.healAll()` | restores every link |
| `env.crashNode(node, mode)` | crashes and reboots one node; the others see a reset or a timeout |
| `env.stepClock(node, delta_ns)` | steps a node's time of day |
| `env.addHost(name, node)` | adds a name to the simulated DNS; `node<N>` and `localhost` always resolve |

From [`examples/replica.zig`](../examples/replica.zig): a client on node
0, a primary on node 1, a replica on node 2, and one partition.

```zig
pub const options: tardis.Options = .{ .nodes = 3, .iterations = 30, .shrink = false };

fn scenario(env: *Env, variant: Variant) !void {
    const io = env.io;
    try env.spawnOn(replica_node, node, .{ io, replica_port, null, variant });
    try env.spawnOn(primary_node, node, .{ io, primary_port, env.address(replica_node, replica_port), variant });
    try io.sleep(.fromMilliseconds(1), .awake);
    var cluster: Cluster = .{ .io = io, .primary = env.address(primary_node, primary_port), .replica = env.address(replica_node, replica_port) };

    // One write while the network is whole, one while the primary cannot
    // reach the replica.
    try writeValue(io, cluster.primary, 1);
    env.partition(primary_node, replica_node);
    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, writeValue, .{ io, cluster.primary, 2 + @as(u64, try env.fuzz(u8)) });
    try io.sleep(.fromMilliseconds(500), .awake);
    env.healAll();
    try group.await(io);

    try env.eventually("after the partition heals, the replica catches up", 30 * std.time.ns_per_s, &cluster, agree);
}
```

The servers listen and connect with the ordinary `std.Io.net` calls.
Datagram sockets work the same way; see
[`examples/udp_retry.zig`](../examples/udp_retry.zig).

### Chaos

Instead of placing each partition by hand, start a nemesis: a background
task that partitions, isolates, crashes and steps clocks at random
intervals. Its choices come from the seed, so a failure under chaos
replays and shrinks like any other. From
[`src/tests/chaos_test.zig`](../src/tests/chaos_test.zig):

```zig
    if (chaos) try env.startChaos(.{});
    var group: Io.Group = .init;
    defer group.cancel(io);
    for (0..3) |i| try group.concurrent(io, writer, .{ &ctx, i, try env.fuzz([5]u8) });
    try io.sleep(.fromSeconds(2), .awake);
    env.heal();
    try group.await(io);

    try env.eventually("the replica converges to the primary", 30 * std.time.ns_per_s, &ctx, replicasAgree);
```

`env.heal()` stops the nemesis, heals every link and turns off every
probabilistic fault for the rest of the run, so that what follows tests
recovery. A `tardis.Nemesis` partitions by default; `crashes` and
`clock_steps` are off until set, and it never crashes node 0.

`Options.chaos` does the same on a schedule: `check` starts the nemesis
before the body and heals after a drawn time (between
`duration_min_ns`, 500 ms, and `duration_max_ns`, 5 s). The body runs its
workload, calls `try env.awaitHeal()`, then checks recovery.

## 7. Choosing campaign size

`Options.iterations` is the number of runs per persona. The default is
100. Three presets give other sizes:

| Preset | Iterations | For |
|---|---|---|
| `.quick` | 20 | while writing a test |
| `.thorough` | 1,000 | before a release, or for something subtle |
| `.nightly` | 10,000, with guided exploration | a scheduled job |

A preset is an `Options` value:

```zig
try tardis.check(gpa, body, .quick);

var o: tardis.Options = .thorough;
o.nodes = 3;
try tardis.check(gpa, body, o);
```

Most tests should leave `iterations` alone and let the environment
choose. These variables are read by `check` in test builds only:

| Variable | Effect |
|---|---|
| `TARDIS_PRESET=quick\|thorough\|nightly` | sizes every `check` whose `iterations` is 100. A check with any other number keeps it. With `nightly`, a check whose `explore` is the default also becomes guided, unless it uses `fork` or `keep_going` |
| `TARDIS_ITERATIONS_SCALE=<n>` | multiplies every check's iterations by `n`, after the preset |
| `TARDIS_CAMPAIGN_SALT=<number>` | gives every check other seeds than its usual ones. A nightly job passes a new number each night |

A check that writes `.iterations = 100` cannot be told from one that left
it out, and is resized too. A test that needs exactly 100 should ask for
101.

Without a salt, a check draws the same seeds on every run of the suite
(`Options.campaign_seed`), so results repeat from one `zig build test` to
the next. `zig build` does not know when these variables change, so a
cached test result is not run again for them.

`Options.workers` runs the campaign on several threads, each with its own
simulator. Which failure is reported does not depend on thread timing.

## 8. Guided exploration and the corpus directory

By default every iteration uses a fresh seed (`.explore = .random`).
With `.explore = .guided`, runs that reach new coverage are kept in a
corpus, and half the iterations mutate a kept run instead of starting
fresh. This finds bugs that sit behind a sequence of unlikely choices.

Coverage comes from the simulator (different I/O outcomes are different
behaviour), from `sometimes` conditions that held, and from points you
name with `env.cover(name, value)`. From
[`src/tests/explore_test.zig`](../src/tests/explore_test.zig):

```zig
/// A bug behind five consecutive 1-in-16 choices: about one run in a
/// million reaches it at random. Each correct step is a coverage point.
fn combinationLock(env: *Env) !void {
    const code = [_]u8{ 7, 2, 13, 5, 11 };
    var depth: u64 = 0;
    for (code) |digit| {
        const d = (try env.fuzz(u8)) % 16;
        if (d != digit) break;
        depth += 1;
        env.cover("depth", depth);
    }
    try env.always("the lock stays shut", depth < code.len);
}
```

In that file 6,000 random iterations leave the lock shut, and 6,000
guided ones open it. Give `cover` small, meaningful values (a protocol
state, a depth, a phase), not raw data. It does nothing under random
exploration.

`TARDIS_EXPLORE=guided` (or `random`) sets the mode for every check of a
test run. `Options.corpus_max` (256) bounds the corpus, and
`Options.explore_report` receives what the campaign reached. `fork`
applies to random exploration only.

### Keeping the corpus

A campaign starts from nothing unless it is given a directory. With
`Options.corpus_dir`, or `TARDIS_CORPUS_DIR=<dir>` in tests, each check
keeps one file there:

- the runs that failed. The next campaign runs them first, and drops
  each once it passes;
- with guided exploration, the corpus and the coverage it reached, so
  the next campaign goes on where this one stopped.

From [`src/tests/corpus_test.zig`](../src/tests/corpus_test.zig):

```zig
        tardis.check(gpa, combinationLock, .{
            .iterations = iterations,
            .campaign_seed = 0xC0FFEE + c,
            .explore = .guided,
            .determinism_check_every = 0,
            .report = false,
            .shrink = false,
            .corpus_dir = dir,
            .corpus_name = "lock.corpus",
        }) catch |err| {
```

The file is named after the test that called `check`, plus a hash of the
personas, nodes, mode and workers; `Options.corpus_name` overrides that.
In a test the file is read and written through `std.testing.io`. Outside
a test nothing is kept unless `Options.corpus_io` is set. A seed or a
replay token replays without the directory.

For a nightly job, combine the three: `TARDIS_PRESET=nightly`, a new
`TARDIS_CAMPAIGN_SALT`, and a `TARDIS_CORPUS_DIR` that the job keeps
between runs. `.github/workflows/campaign.yml` is such a job.

## 9. Reading a failure and replaying it

A failing check prints the property, the run (iteration, persona, seed),
the last events, and two lines that run it again: one with `TARDIS_SEED`
and `TARDIS_PERSONA`, one with `TARDIS_REPLAY` for the shrunk run.
[reproducing.md](reproducing.md) explains the report, how to take it from
a CI log to your machine, and what must match for the replay to fail the
same way. [trace.md](trace.md) shows how to look at a run as a timeline
instead of reading its last events; with `Options.trace_dir`, or
`TARDIS_TRACE_DIR=<dir>` in tests, a failing check writes that timeline
to a file by itself.

From code, `Options.seed` and `Options.replay` do what the variables do.

A panic or a fault in the code under test ends the process with no
report; a `check` still prints the run it happened in and its replay line
before the process ends ([reproducing.md](reproducing.md), "When the
code under test crashes").

## 10. The history checkers

Some properties are about a whole history of operations, not about one
moment. Record the history as the test runs, then hand it to a checker.

### Linearizability: `tardis.lin`

Each client records what it asked (`invoke`) and what it was told (`ok`,
or `failed` when the operation certainly did not happen). An operation
left without an answer may or may not have taken effect, and the checker
allows for both. From
[`examples/lin_register.zig`](../examples/lin_register.zig):

```zig
const History = lin.History(lin.Register);

/// Tries to take the register (swap 0 for its own number), then reads it.
fn client(reg: *Register, history: *History, id: u32) Io.Cancelable!void {
    const mine: u64 = id + 1;
    const swap = history.invoke(id, .{ .cas = .{ .from = 0, .to = mine } }) catch return;
    // An operation that failed is left without an answer: it may or may
    // not have taken effect, and the checker allows for both.
    if (reg.cas(0, mine)) |won| history.ok(swap, .{ .cas = won }) else |_| {}

    const look = history.invoke(id, .read) catch return;
    if (reg.read()) |value| history.ok(look, .{ .value = value }) else |_| history.failed(look);
}
```

At the end of the body:

```zig
    try lin.expectLinearizable(env.allocator, lin.Register, &history, env.sim.config.report);
```

It fails with `error.NotLinearizable`. `lin.Register` and `lin.Kv` are
ready-made models. A model of your own is a type with `State`, `Input`
and `Output`, and `init`, `step` and `hash` functions; the comment at the
top of `src/check/lin.zig` gives the contract.

### Serializability: `tardis.elle`

Each transaction records what it read and wrote, and the checker looks
for a cycle of dependencies between transactions. From
[`examples/write_skew.zig`](../examples/write_skew.zig):

```zig
    const start = ctx.history.begin();
    // ... the transaction runs, filling `ops` with what it read and wrote:
        ops[k] = .{ .read_reg = .{ .key = k, .value = s.values[k] } };
    ops[doctors] = .{ .write = .{ .key = me, .value = me + 1 } };
    // ... and ends:
    ctx.history.finish(start, if (committed) .committed else .aborted, &ops) catch {};
```

At the end of the body:

```zig
    try elle.expectSerializable(env.allocator, &history, .{}, env.sim.config.report);
```

It fails with `error.TransactionalAnomaly`.

### Costs: `tardis.ledger`

Virtual time and byte counts are deterministic, so a performance property
can be asserted like a correctness one. `tardis.Histogram` records
samples and answers quantiles in parts per million. From
[`src/tests/chaos_test.zig`](../src/tests/chaos_test.zig):

```zig
        const t0 = ctx.now(ctx.io);
        if (roundTrip(ctx.io, ctx.primary, text, &out)) |_| {
            ctx.latency.record(ctx.now(ctx.io) - t0);
        } else |_| {}
```

```zig
        try env.always("healthy p99 write latency is under 50 ms", latency.quantile(990_000) < 50 * std.time.ns_per_ms);
```

`env.stats()` has the run's counters (bytes written and read, syncs,
network bytes, datagrams), and `env.flushedBytes()` the bytes that
reached the media. The same file compares the two for write
amplification with `tardis.ledger.ratioPpm`.

## 11. System-call mode, in brief

Everything above is the default mode, `.std_io`: the code under test does
its I/O through the `Io` it is given. Code that cannot take an `Io` (a C
library, Zig written against the kernel) can be tested in system-call
mode instead:

```zig
try tardis.check(gpa, body, .{ .mode = .syscalls });
```

It exists on Linux x86_64 only (kernel 5.11 or later), simulates fewer
things, and fails the run with `error.StraySyscall` on a call it does not
answer. Elsewhere `check` returns `error.SyscallModeUnsupported`;
`tardis.syscallModeAvailable()` lets a test skip. The body still has
`env.io` and `env.dir`, on the same simulated files.
["Choosing a mode"](../README.md#choosing-a-mode) in the README has the
table of what is simulated and the list of limits.
[`examples/syscall_rename.zig`](../examples/syscall_rename.zig) is a
worked example, and [c-libraries.md](c-libraries.md) is the guide to
testing a C library this way.

In the default mode, `TARDIS_TRAP_SYSCALLS=1` (or `Options.trap_syscalls`)
on the same platform fails a run that makes a real system call, and names
the call. It is a cheap way to learn that some code escapes the
simulation.

## 12. What is not simulated

- **Real threads.** Code that calls `std.Thread.spawn` runs outside the
  simulation and is not made deterministic. Use `io.async`,
  `io.concurrent` and `std.Io.Mutex`. [threads.md](threads.md) has the
  reasons and what to do instead.
- **I/O that does not go through `std.Io`**, in the default mode: a
  direct system call, a C library doing its own I/O.
- **Shared memory between tasks.** Tasks switch only at `std.Io` calls,
  so plain memory shared between them never changes under a task that
  makes no call. `tardis.atomic.Value(T)` is a drop-in for
  `std.atomic.Value` whose operations are scheduling points.
- **`std.Io` operations the simulator does not model.** Such a call gets
  an error and never reaches the real system. `env.refusedCalls()` lists
  them, and a failure report names them.
- **The real filesystems and networks.** The personas and the network
  are models. [qualification.md](qualification.md) lists what each has
  been compared with, and the known limits.

A green run means that no run broke a property you stated, across these
seeds, inputs and personas. It does not mean the program has no bugs.

---

TARDIS also has an optional security layer, which this guide does not
need: see [security.md](security.md).
