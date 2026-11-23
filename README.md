# TARDIS

Deterministic simulation testing for Zig programs written against `std.Io`.

A test body runs inside a simulator that owns the scheduler, the clock, the
filesystem and the network. Every choice the simulator makes (which task runs
next, whether an fsync is lost in a crash, whether a datagram arrives) comes
from a seed, so a failure can be replayed exactly, and shrunk to the few
decisions that cause it.

`tardis_sec`, in `src/sec`, is an optional security layer on top: taint and
secret tracking, lock-order checks, Byzantine peers, constant-time checks,
MC/DC and signed evidence bundles.

## Documentation

New here:

- [docs/tutorial.md](docs/tutorial.md) goes from an empty test to a found,
  shrunk and fixed bug.
- [docs/guide.md](docs/guide.md) is the user guide: oracles, faults,
  crashes, several nodes, campaign size, guided exploration, the history
  checkers.
- [`examples/`](examples) has twenty-six small programs, each with one
  planted bug and its fix.

When a test fails:

- [docs/reproducing.md](docs/reproducing.md) takes a failure from a CI log
  to your machine.
- [docs/trace.md](docs/trace.md) reads a run as a timeline in Perfetto.

Reference:

- `zig build docs` writes the API reference to `zig-out/docs`.
- [docs/stability.md](docs/stability.md) says what may change between
  releases, and what a seed is and is not promised to mean.
- [docs/measurements.md](docs/measurements.md) has which oracle catches
  which planted bug and how often, and what a simulator costs in memory.
- [docs/threads.md](docs/threads.md) says why real threads are outside the
  simulation and what to use instead.
- [docs/qualification.md](docs/qualification.md) lists what the tool is
  required to do, the tests behind each requirement, and its known
  limits, for anyone who has to justify relying on it.

The security layer, which the core does not need:

- [docs/security.md](docs/security.md).

Design record:

- [plan.md](plan.md) (core) and [plan2.md](plan2.md) (security layer) hold
  the design and its status. Both say what is verified by tests and what
  is not.
- [plan3.md](plan3.md) is the proposal for getting to a release.
- [CHANGELOG.md](CHANGELOG.md) lists what each revision changed.

Contributors:

- [CONTRIBUTING.md](CONTRIBUTING.md) says what a change needs.
- [docs/housekeeping.md](docs/housekeeping.md) says how to clean the build
  cache.

## Licence

[0BSD](LICENSE): do anything with it, no conditions.

## Requirements

- Zig 0.17.
- Windows or Linux on x86_64. The suite compiles for `aarch64-macos`, but has
  not been run there.

## A first test

```zig
const std = @import("std");
const tardis = @import("tardis");

/// Replaces `config` through a temp file and a rename, but forgets to
/// fsync the temp file first.
fn replaceConfig(env: *tardis.Env) !void {
    const io = env.io;
    try env.dir.writeFile(io, .{ .sub_path = "config", .data = "old-config" });
    {
        var f = try env.dir.openFile(io, "config", .{ .mode = .read_write });
        defer f.close(io);
        try f.sync(io);
    }
    try env.dir.writeFile(io, .{ .sub_path = "config.tmp", .data = "new-config" });
    try env.dir.rename("config.tmp", env.dir, "config", io);
    {
        var d = try env.dir.openFile(io, ".", .{});
        defer d.close(io);
        try d.sync(io);
    }

    try env.crashAndReboot(.power_loss);

    var buf: [32]u8 = undefined;
    const got = try env.dir.readFile(io, "config", &buf);
    const ok = std.mem.eql(u8, got, "old-config") or std.mem.eql(u8, got, "new-config");
    try env.always("config is either old or new", ok);
}

test "config survives a power loss" {
    try tardis.check(std.testing.allocator, replaceConfig, .{
        .iterations = 200,
        .personas = &.{ .linux_ext4, .linux_xfs },
    });
}
```

This test fails, and that is the point: the rename is durable but the new
file's contents are not, which ext4 forgives and XFS does not. `env.io` is a
`std.Io`; code under test uses it and `env.dir` as it would use the real
ones. `zig build run` runs the same body on six filesystem personas.

To use the library from another project, add it as a dependency and import
its `tardis` module (and `tardis_sec` for the security layer):

```zig
const dep = b.dependency("tardis", .{ .target = target, .optimize = optimize });
exe_tests.root_module.addImport("tardis", dep.module("tardis"));
```

## When a test fails

The report names the iteration, the persona and the seed, shows the last
events, and prints two ways to run it again:

| Variable | What it replays |
|---|---|
| `TARDIS_SEED=0x… TARDIS_PERSONA=…` | the failing run as it was |
| `TARDIS_REPLAY=<token>` | the shrunk run: only the decisions that matter keep their value |
| `TARDIS_CAMPAIGN_SALT=<number>` | nothing: it gives every `check` other seeds than its usual ones, for a long run on new ground |
| `TARDIS_ITERATIONS_SCALE=<n>` | nothing: it multiplies every `check`'s iterations |
| `TARDIS_CORPUS_DIR=<dir>` | nothing: each `check` keeps a file there, and the next campaign runs the runs that failed first and goes on exploring where the last stopped |
| `TARDIS_EXPLORE=guided` | nothing: every `check` explores guided by coverage |
| `TARDIS_PRESET=quick\|thorough\|nightly` | nothing: it sizes every `check` whose `iterations` is the default 100, written out or not (20, 1,000 or 10,000; `nightly` is also guided) |
| `TARDIS_TRACE_DIR=<dir>` | nothing: a failing check that is reported writes a Chrome trace of the failing run and of the shrunk run there ([`docs/trace.md`](docs/trace.md)) |
| `TARDIS_REPLAY_COMMAND=<command>` | nothing: replay lines end in it, not in `zig build test`; a build script sets it on a run step ([`docs/reproducing.md`](docs/reproducing.md)) |
| `TARDIS_REPLAY_FUZZY=2` | with `TARDIS_REPLAY`: if the token no longer fails because the code now draws a little differently, try it with its decisions moved by up to 2 draws |

`Options.seed`, `Options.replay` and `Options.replay_fuzzy` do the same from
code. The salt and the scale are for nightly campaigns
(`.github/workflows/campaign.yml` is one, and other repositories can call
it); `zig build` does not know they changed, so a cached test result is
not run again for them. To look at a run instead of reading its last events,
`tardis.traceJson` writes it as a Chrome trace that Perfetto opens: one track
per task, in virtual time ([docs/trace.md](docs/trace.md)). `tardis explain <token>` (the `tardis` program in `src/cmd/tardis`)
decodes a token. [docs/reproducing.md](docs/reproducing.md) has the whole
path from a failed CI run to a local replay, and what must match.

## Options worth knowing

| Option | Default | What it does |
|---|---|---|
| `iterations` | 100 | runs per persona |
| `personas` | `linux_ext4` | filesystems to simulate: `linux_ext4`, `linux_xfs`, `windows_ntfs`, `posix_strict`, `macos_apfs`, `freebsd_zfs` |
| `nodes` | 1 | simulated machines, each with its own files, heap and network address |
| `faults`, `net` | on | fault and network rates (loss, latency, short I/O) |
| `explore` | `.random` | `.guided` keeps runs that reach new coverage and mutates them |
| `workers` | 1 | threads; the result does not depend on the count |
| `setup`, `fork` | off | a warm-up, then each iteration from a copy of what it left: a snapshot when setup only wrote files, a forked process with `fork` on Linux, else setup again |
| `shrink` | on | reduce a failure to the decisions that cause it |
| `chaos` | off | a schedule of partitions, crashes and clock steps |
| `limits` | | task count, fiber stack size and other bounds |

Inside the body, `Env` gives the test its controls: `fuzz(T)` for inputs,
`always` and `sometimes` for properties, `crashAndReboot`, `crashNode`,
`partition`, `cutLink`, `stepClock`, `spawnOn(node, …)` and `address(node,
port)` for multi-node tests, and `injectIoErrorAfter` for a targeted fault.

Shared memory between tasks is not simulated, except through
`tardis.atomic.Value(T)`: a drop-in for `std.atomic.Value` whose operations
are scheduling points, and whose stores with an ordering weaker than
`.seq_cst` can be missed by other tasks for a while, as on x86.

Two other entry points:

- `tardis.sim(gpa, options)` is the loop form of `check`, for tests that
  drive iterations themselves.
- `tardis.exhaustive(gpa, body, options, .{ .depth_max = 12 })` runs every
  combination of the first decisions instead of sampling them. With
  `.reduce = true` it skips orders of steps that cannot differ; read the
  assumption on `ExhaustiveOptions.reduce` first.

## Choosing a mode

There are two ways for the code under test to reach the simulation, chosen
with `Options.mode`.

| | `.std_io` (the default) | `.syscalls` |
|---|---|---|
| The code does its I/O through | `std.Io` (`env.io`, `env.dir`) | its own system calls: `std.os.linux`, `std.posix`, a C library |
| Platforms | every one TARDIS runs on | Linux on x86_64, kernel 5.11 or later |
| What is simulated | everything `std.Io` offers: files, the network, the clock, tasks | files, IPv4 sockets, pipes, `eventfd`, `poll` and `epoll`, clock reads, sleeping, random bytes, and threads (the lists are at the top of `src/sim/sysemu.zig`, `sysnet.zig`, `sysfd.zig` and `systhread.zig`) |
| A call outside that | cannot be made through `env.io` | fails the run with `error.StraySyscall`, naming the call |

Use `.std_io` when the code takes an `Io`: it is the complete simulation,
and the only one on Windows and macOS. Use `.syscalls` for code that cannot
take one: a C library, or Zig code written against the kernel. In that mode
the body still has `env.io` and `env.dir`, on the same simulated files, so
a test can write through a C library and check the result through `env.dir`,
and `env.crashAndReboot` treats both alike.

```zig
try tardis.check(gpa, body, .{ .mode = .syscalls });
```

A thread the code under test starts (`pthread_create`, `std.Thread.spawn`)
becomes a simulated task with its own stack and thread pointer, scheduled
by the seed: two `pthread`s may share one SQLite connection. It needs a
processor and kernel with FSGSBASE (2012, Linux 5.9);
`tardis.syscallThreadsAvailable()` says. A thread may make system calls
and may not use `env.io`. Threads switch only at system calls, so one that
spins on memory waiting for another hangs the run.

A C library's locks work across tasks too: its `futex` waits block the
task, not the thread. But tasks made with `env.io.concurrent` share the
test's one thread identity, so a recursive mutex (whose owner is the
thread) does not keep a second such task out. Share an object behind a
recursive lock between threads, not between tasks.

`examples/syscall_rename.zig` is a planted bug in a program that only
makes system calls; `test/sqlite.zig` runs SQLite, built as it ships, and
loses an acknowledged commit to a power loss when its `synchronous` setting
allows that (`zig build test-sqlite -Dsqlite`). `test/rust.zig` runs a Rust
crate the same way: `std::thread`, `std::fs`, sockets, and tokio's two
runtimes (`zig build test-rust -Drust=<library>`).

What to know before relying on it:

- IPv4 sockets are emulated, blocking and non-blocking, with pipes,
  `eventfd`, `poll` and `epoll`. `select`, `mmap` of a file, `fork`,
  `dup2` and `dup3` are stray calls. Simulated descriptor numbers are large, so a
  library that indexes a table by descriptor (libuv, libevent) will not
  work.
- Edge-triggered `epoll` reports every edge Linux does and some it does
  not: a program that fails to drain a descriptor is not caught.
- Clock reads that libc answers through the vDSO are answered from the
  simulation too, by making the vDSO's code fault during a run.
- A task dropped (by a crash, or the end of a run) inside a C library
  call can leave that library's lock or state behind for later runs; the
  run says so, and so do later failure reports.
- Owners, permission bits and record locks are not modelled.
- State a library keeps for the life of the process is carried from one
  run to the next. `check` re-runs every 16th iteration and fails with
  `error.NonDeterministic` when that changes a run; reset such state at
  the start of the body.
- Where the mode does not exist, `check` returns
  `error.SyscallModeUnsupported`; `tardis.syscall_mode_supported` says so
  at compile time.

## The security layer

```zig
const sec = @import("tardis_sec");

try tardis.check(gpa, body, sec.withSecurity(.{ .base = .{ .nodes = 2 } }));
```

`zig build test -Dsec` (or `TARDIS_SEC=1`) attaches it to every `check` in a
build without changing the tests. A finding fails the run with
`error.SecurityViolation`, carries a CWE number, and shrinks and replays like
any other failure. `sec.certify` runs a campaign that does not stop at the
first failure and writes a signed evidence bundle (SARIF, requirement
traceability, MC/DC, replay capsules). The layer is not certified or
qualified under any standard, and using it certifies nothing: it produces
evidence in the shapes some standards ask for, which is for your own
assessors to judge.

[docs/security.md](docs/security.md) is the guide to the layer: each
detector with an example, the evidence campaign, and its limits.

C code linked into a test can take part: include `src/sec/c/tardis_sec.h`
after the system headers and export its functions from the Zig test with
`comptime { sec.exportC(); }`. The header's comment lists what it wraps.

Shadow memory finds a bad heap access where it happens, not when its
bytes leave. Build the code under test as an object with
`sanitize_thread = true` (and `use_llvm = true`), link it into a test
that is built without it (also with `use_llvm`), export the runtime with
`comptime { sec.exportSanitizer(); }`, and set `.shadow_memory = true`.
A write or read past the end of an allocation, or a use after free, in
that object then fails the run with CWE-787, 125 or 416. With
`.data_races = true`, two tasks of one node that touch one address from
that object, at least one with a store, with no spawn, wake, await,
atomic or mutex between them, fail the run with CWE-362, even though
the simulator itself never runs two tasks at once. With
`.atomic_lock_order = true`, two `std.Io.Mutex` taken in both orders by
that object fail the run with CWE-833, without a deadlock having to
happen.

In `build.zig`, one call builds the object and links it into the test:

```zig
const tardis_build = @import("tardis");
_ = tardis_build.addInstrumentedObject(b, tests, .{
    .name = "sut",
    .root_source_file = b.path("src/sut.zig"),
    .target = target,
    .optimize = optimize,
});
```

The test reaches the object through `extern fn` declarations;
`src/sec/tests/shadow_test.zig` and `src/sec/tests/shadow/sut.zig` are a
worked example.

## Build steps

| Command | What it runs |
|---|---|
| `zig build test` | the library, the security layer, the `tardis` program and the termancy suite |
| `zig build test-sec` | the security layer's tests |
| `zig build test-examples` | the examples: each finds its planted bug and passes its fix |
| `zig build test-termancy` | the suite that tests the `termancy` library under simulation |
| `zig build test-sqlite -Dsqlite` | SQLite under system-call mode (Linux x86_64; fetches SQLite's source) |
| `zig build test-edges` | guided exploration fed by Zig's edge counters (Linux or macOS targets) |
| `zig build evidence` | the certification campaigns, bundles in `zig-out/tardis-evidence` |
| `zig build bench` | throughput benchmarks, always optimized |
| `zig build bugbench` | the bug benchmark: each example's planted bug, whether a plain run sees it, whether a campaign finds it, what it shrinks to |
| `zig build bugbench-rates` | which oracle catches each planted bug, and in how many of 20 campaigns by size ([`docs/measurements.md`](docs/measurements.md)) |
| `zig build bugbench-schedules` | how often each planted bug is found with tasks switched at random and by priority, PCT ([`docs/measurements.md`](docs/measurements.md)) |
| `zig build bugbench-baselines` | whether each planted bug is still found with no faults injected, and with no preemption ([`docs/measurements.md`](docs/measurements.md)) |
| `zig build membench` | the memory one simulator takes, by option |
| `zig build docs` | the API reference, into `zig-out/docs` |
| `zig build run` | the demo |

`scripts/verify.sh` runs the formatting check and the suite in all four
build modes and with `-Dsec`; `.github/workflows/test.yml` runs the suite
on Linux, macOS and Windows. The build cache grows without bound;
[docs/housekeeping.md](docs/housekeeping.md) says how to clean it.

Useful flags: `-Dtest-filter=<text>`, `-Doptimize=<mode>`, `-Dsec`,
`-Dlibc` (link libc; the fork server then uses libc's `fork`),
`-Dedges` (with `evidence`: list code the campaigns never ran).

## Limits

- In the default mode only code that goes through `std.Io` is simulated. A
  direct system call escapes the simulation. On Linux x86_64,
  `TARDIS_TRAP_SYSCALLS=1` (or `Options.trap_syscalls`) fails the run that
  makes one and names the call, and `Options.mode = .syscalls` answers the
  file, clock, sleep and random-byte calls from the simulation instead
  ("Choosing a mode"). `Options.virtual_tsc` (same platform) answers
  `rdtsc` with the run's virtual time.
- Real threads are not simulated. Code that calls `std.Thread.spawn` runs
  outside the simulation and is not made deterministic; use `io.async`,
  `io.concurrent` and `std.Io.Mutex` instead
  ([docs/threads.md](docs/threads.md)).
- A fiber stack is 256 KiB by default. An overflow faults on the guard page
  below the stack; raise `limits.fiber_stack_bytes` if a test needs more.
- Shadow memory and the race detector check only code built as a separate
  instrumented object; shadow memory only its heap accesses. The test
  body itself is not checked, and a mutex it locks orders nothing for the
  race detector.
- The fork server and the edge-counter features need Linux (or macOS, unrun).
