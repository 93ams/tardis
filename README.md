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

New here? The [tutorial](docs/tutorial.md) goes from an empty test to a found,
shrunk and fixed bug, and [`examples/`](examples) has four small programs,
each with one planted bug and its fix. [docs/stability.md](docs/stability.md)
says what may change between releases, and what a seed is and is not
promised to mean.

The design and its status are in [plan.md](plan.md) (core) and
[plan2.md](plan2.md) (security layer). Both say what is verified by tests and
what is not. [CHANGELOG.md](CHANGELOG.md) lists what each revision changed,
and [plan3.md](plan3.md) is the proposal for getting to a release.

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
| `TARDIS_REPLAY_FUZZY=2` | with `TARDIS_REPLAY`: if the token no longer fails because the code now draws a little differently, try it with its decisions moved by up to 2 draws |

`Options.seed`, `Options.replay` and `Options.replay_fuzzy` do the same from
code. The salt and the scale are for nightly campaigns
(`.github/workflows/campaign.yml` is one, and other repositories can call
it); `zig build` does not know they changed, so a cached test result is
not run again for them. To look at a run instead of reading its last events,
`tardis.traceJson` writes it as a Chrome trace that Perfetto opens: one track
per task, in virtual time. `tardis explain <token>` (the `tardis` program in `src/cmd/tardis`)
decodes a token.

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
| `zig build test-termancy` | the suite that tests the `termancy` library under simulation (needs a sibling checkout) |
| `zig build test-edges` | guided exploration fed by Zig's edge counters (Linux or macOS targets) |
| `zig build evidence` | the certification campaigns, bundles in `zig-out/tardis-evidence` |
| `zig build bench` | throughput benchmarks, always optimized |
| `zig build bugbench` | the bug benchmark: each example's planted bug, whether a plain run sees it, whether a campaign finds it, what it shrinks to |
| `zig build run` | the demo |

`scripts/verify.sh` runs the formatting check and the suite in all four
build modes and with `-Dsec`; `.github/workflows/test.yml` runs the suite
on Linux, macOS and Windows.

Useful flags: `-Dtest-filter=<text>`, `-Doptimize=<mode>`, `-Dsec`,
`-Dlibc` (link libc; the fork server then uses libc's `fork`),
`-Dedges` (with `evidence`: list code the campaigns never ran).

## Limits

- Only code that goes through `std.Io` is simulated. A direct system call
  escapes the simulation. On Linux x86_64, `TARDIS_TRAP_SYSCALLS=1` (or
  `Options.trap_syscalls`) fails the run that makes one and names the
  call. `Options.virtual_tsc` (same platform) answers `rdtsc` with the
  run's virtual time.
- A fiber stack is 256 KiB by default. An overflow faults on the guard page
  below the stack; raise `limits.fiber_stack_bytes` if a test needs more.
- Shadow memory and the race detector check only code built as a separate
  instrumented object; shadow memory only its heap accesses. The test
  body itself is not checked, and a mutex it locks orders nothing for the
  race detector.
- The fork server and the edge-counter features need Linux (or macOS, unrun).
