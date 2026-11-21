# The security layer

`tardis_sec` is an optional module on top of the core. It watches the
same simulated runs for security defects: memory that leaves the program
when it should not, lock-order inversions, races an attacker can win,
hostile peers, and resource blow-ups. It can also run a campaign that
writes a signed bundle of evidence.

You do not need it to use TARDIS. The [user guide](guide.md) covers the
core and does not depend on anything here.

The code blocks are excerpts from tests in `src/sec/tests/`, which `zig
build test-sec` compiles and runs. Each names its file. They assume:

```zig
const std = @import("std");
const tardis = @import("tardis");
const sec = @import("tardis_sec");
const Env = tardis.Env;
const gpa = std.testing.allocator;
```

The design, and the status of each part, are in [plan2.md](../plan2.md).

## What it is not

`tardis_sec` is not certified, qualified or approved under DO-178C,
Common Criteria, FIPS 140-3, ISO 26262 or any other standard, and using
it certifies nothing. It produces evidence in the shapes those standards
ask for (MC/DC tables, requirement traceability, signed bundles). Whether
that evidence counts is decided by the organisation that uses it and by
its assessors, who would first have to qualify the tool themselves;
`plan2.md` §7.6 has notes on what that takes.

The names of options such as `.certification_eal7`, and of the function
`certify`, describe a mode of running. They do not describe a result.

Parts of the layer are experimental and may change in any release: the
instrumented-object detectors (shadow memory, the race detector, lock
order for `std.Io.Mutex`). See [stability.md](stability.md).

## Attaching it

There are two ways. A finding fails the run with
`error.SecurityViolation`, carries a CWE number, and shrinks and replays
like any other failure.

### To one check: `withSecurity`

```zig
try tardis.check(gpa, body, sec.withSecurity(.{ .base = .{ .nodes = 2 } }));
```

`sec.withSecurity(config)` takes a `sec.SecurityConfig` and returns a
`tardis.Options` whose `security` field names the layer. The core options
(iterations, personas, nodes and the rest) go in `config.base`.
`Options.security` is the field the core reads; `withSecurity` is the
supported way to fill it.

To use the module from another project, import it next to `tardis`:

```zig
const dep = b.dependency("tardis", .{ .target = target, .optimize = optimize });
exe_tests.root_module.addImport("tardis", dep.module("tardis"));
exe_tests.root_module.addImport("tardis_sec", dep.module("tardis_sec"));
```

### To every check of a build: `-Dsec` or `TARDIS_SEC=1`

```sh
zig build test -Dsec
TARDIS_SEC=1 zig build test
```

This attaches the layer to every `check` whose options name no security
layer, without changing the tests. It is a build switch: `build.zig`
reads the option (or the variable) and compiles the layer in. Without it
the core compiles no security code. `tardis.security_by_default` says
which build this is.

Attached this way, the layer only observes (`sec.default_config`): it
does not swap files, force task switches or rewrite network traffic, so a
passing test's runs stay the same and only a finding fails it. The
detectors that steer a run (marked "steers" below) need `withSecurity`.

`-Dsec` is an option of this repository's `build.zig`. Passing it from a
project that depends on TARDIS has not been tried for this guide.

### Reading a finding

`SecurityConfig.report` receives the findings of the last run, which is
the failing one when the check fails. From
[`src/sec/tests/pillar1_test.zig`](../src/sec/tests/pillar1_test.zig):

```zig
test "uninit: the unwritten tail of a heap buffer reaching a file is CWE-908" {
    var report: sec.engine.Report = .{};
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, uninitTail, sec.withSecurity(.{
        .report = &report,
        .base = .{ .iterations = 4, .report = false },
    })));
    try std.testing.expectEqual(@as(u16, 908), report.findings[0].cwe);
    try std.testing.expectEqual(tardis.sec_seam.Sink.Kind.file, report.findings[0].sink.?.kind);
    // The first window that is all pattern starts right after the header.
    try std.testing.expectEqual(@as(u32, 20), report.findings[0].offset);
    try tardis.check(gpa, initOnly, sec.withSecurity(.{ .base = .{ .iterations = 4 } }));
}
```

A failed check can also write its findings as a SARIF file, located at
the test's call to `check`, with the replay token: set
`SecurityConfig.check_sarif` to a directory, or `TARDIS_SARIF_DIR=<dir>`
in tests.

## The detectors

### Bytes that should not leave (always on)

The layer fills every allocation with a pattern drawn from the seed, and
overwrites freed memory with another. Every byte the program writes to a
file, a stream or a datagram is scanned for those patterns, and for the
bytes you mark.

| Finding | CWE |
|---|---|
| uninitialized heap bytes leaving | 908 |
| freed bytes leaving | 416 |
| a marked secret leaving | 200 |
| one tenant's bytes reaching another tenant's peer | 668 |
| a marked secret freed without being zeroed | 226 |
| a write past the end of an allocation, found when it is freed | 787 |
| the guard bytes after an allocation leaving (an over-read) | 125 |

Uninitialized bytes, from `pillar1_test.zig` (the test is above):

```zig
fn sendRecord(env: *Env, whole_buffer: bool) !void {
    const buf = try env.allocator.alloc(u8, 64);
    defer env.allocator.free(buf);
    const header = "LEN=0012 record body";
    @memcpy(buf[0..header.len], header);
    const out = if (whole_buffer) buf else buf[0..header.len];
    try env.dir.writeFile(env.io, .{ .sub_path = "record.bin", .data = out });
}
```

Secrets: call `sec.markSecret(bytes)` once the bytes hold their final
value. From the same file:

```zig
    env.io.random(key);
    sec.markSecret(key);
    defer if (zeroize) std.crypto.secureZero(u8, key);
    if (leak) try env.dir.writeFile(env.io, .{ .sub_path = "debug.log", .data = key[4..20] });
```

Tenants: `sec.markTenant(bytes, tenant)` says whose the bytes are,
`sec.bindNodeTenant(node, tenant)` says which tenant the client on a node
belongs to, and `sec.withTenant(tenant, f, args)` runs a function with
its allocations and received bytes tagged. The Heartbleed test in
`pillar1_test.zig` uses the first two.

### Lock order

`sec.Mutex` is a `std.Io.Mutex` with a lock class. Taking two classes in
both orders is CWE-833, even on a schedule that never deadlocks. From
[`src/sec/tests/pillar2_test.zig`](../src/sec/tests/pillar2_test.zig):

```zig
const Bank = struct {
    accounts: sec.Mutex = .{ .class = accounts_class },
    audit: sec.Mutex = .{ .class = audit_class },
    balance: u64 = 100,
    log_len: u64 = 0,
};
```

File locks taken in both orders are reported the same way, with no
`tardis_sec` type in the program.

### Double fetch (steers)

`sec.Shared(T)` wraps a value another party can change under the reader.
The second `load` of the same word by one task is a point where the
simulator may switch tasks (`double_fetch_preempt_ppm`, 500,000), so the
writer gets to run between the check and the use. The finding is the
program's own oracle failing, not a `SecurityViolation`. From
`pillar2_test.zig`:

```zig
    const n = msg.len.load();
    if (n > msg.data.len) return; // rejected: fine
    // The bug: the length is read again for the copy.
    const m = if (refetch) msg.len.load() else n;
    try env.always("the copy stays inside the message", m <= msg.data.len);
```

### Check-then-use races on files (steers)

After `sec.setToctouTarget(path)`, a path the task checks (`statFile`,
`access`) and then opens may be replaced between the two by a symlink or
a hard link to the target (`vfs_toctou_race_ppm`, 20,000 per pair).
`sec.setToctouDirTarget(dir)` does the same to a parent directory. The
layer makes the swap; what fails the run is what the program then does,
for example a marked secret leaving (CWE-200). From `pillar2_test.zig`:

```zig
    sec.markSecret(&key);
    try env.dir.writeFile(io, .{ .sub_path = "report.txt", .data = "quarterly report: all is well." });
    sec.setToctouTarget("secret.key");
```

```zig
        // The bug: check the name, then open the name.
        const st = try env.dir.statFile(io, "report.txt", .{ .follow_symlinks = false });
        if (st.kind != .file) return;
        n = (try env.dir.readFile(io, "report.txt", &buf)).len;
```

`sec.pathConfusions(persona, name)` generates other spellings of a file
name that the persona resolves to the same file (case, a trailing dot,
`::$DATA`, 8.3 short names, Unicode forms): the inputs that get past a
deny-list of names.

### Untrusted input reaching a sink

Bytes received from the network are untrusted until
`sec.markSanitized(bytes)`. A path that holds eight or more of them in a
row when it is opened, created, deleted or renamed is CWE-22
(`taint_paths`, on by default). From `pillar2_test.zig`:

```zig
    if (validated) {
        if (!safeName(name)) return;
        sec.markSanitized(name);
    }
    var path_buf: [96]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "files/{s}", .{name});
    var buf: [64]u8 = undefined;
    const data = dir.readFile(io, path, &buf) catch return;
```

Received bytes in the arguments of a process spawn are CWE-78.

### Capabilities used after initialization

`sec.enterSandbox(policy)` declares that a node's initialization is over.
From then until the node restarts, using a capability the policy does
not allow (a connect, a listen, a process spawn, a path outside the
allowed prefixes) is CWE-272. From `pillar2_test.zig`:

```zig
    var upstream = try upstream_address.connect(io, .{ .mode = .stream });
    defer upstream.close(io);
    sec.enterSandbox(.{ .allow_net_connect = false, .allow_net_listen = false });
```

### Hostile peers (steers)

- `sec.twoFaced(node, peers, mutate)`: what `node` sends to `peers` is
  rewritten by `mutate` with `byzantine_ppm` (50,000) per datagram or
  stream segment, while other peers get the original.
- `sec.replayer(node, peers)`: an attacker on the wire records
  datagrams and delivers them again later, also across a reboot.
- `sec.ByzantineFrameSpec(HeaderT, opts)` describes a frame format so
  that a rewrite can keep the checksum valid and reach the protocol
  logic.

`pillar2_test.zig` has a test for each (equivocation, replay, length
desync). As with the file races, the finding is the program's own
property failing.

### Resource amplification

Off unless `SecurityConfig.amplification` is set. The layer keeps four
ratios per run: work per input byte, allocated bytes per input byte,
bytes sent per byte received, and file pages written per input byte. A
ratio over its limit is CWE-407 (work) or CWE-400 (the others). Network
bytes count as input by themselves; `sec.untrustedInput(n)` declares
other input, and `sec.work(n)` counts work units. From
[`src/sec/tests/pillar45_test.zig`](../src/sec/tests/pillar45_test.zig):

```zig
        const k = try env.fuzz(u16);
        sec.untrustedInput(2);
        t.insert(k, randomized, seed);
```

```zig
const hashdos_limits: sec.AmplificationLimits = .{ .work_per_input_byte_milli_max = 3_000 };
```

The ratios also feed guided exploration, which is how that test finds a
set of colliding keys that random search does not.

### Timing and information flow

These are functions, not options. Each runs a body twice per seed and
compares the two traces (every I/O operation, its size and its virtual
time).

- `sec.assertConstantTime(gpa, body, secret_a, secret_b, seeds, options)`
  fails with `error.TimingLeak` if two secrets give different traces.
- `sec.assertNonInterference(gpa, body, public, high_a, high_b, seeds,
  options)` fails with `error.Interference`.
- `sec.assertDifferential(T, input, scratch_a, scratch_b, parse_a,
  parse_b)` fails with `error.DifferentialDivergence` when two parsers
  disagree on an input.

From [`src/sec/tests/example1.zig`](../src/sec/tests/example1.zig):

```zig
fn macThenSend(env: *tardis.Env, _: []const u8, key: []const u8) !void {
    var tag: [16]u8 = undefined;
    std.crypto.onetimeauth.Poly1305.create(&tag, "frame", key[0..32]);
    try env.dir.writeFile(env.io, .{ .sub_path = "tag", .data = &tag });
}

test "Poly1305 tagging is constant time at the I/O boundary" {
    const a: [32]u8 = @splat(0x11);
    const b: [32]u8 = @splat(0xEE);
    try tardis_sec.assertConstantTime(std.testing.allocator, macThenSend, &a, &b, 64, .{});
}
```

For Zig code the comparison is at the I/O boundary only: a difference
that no I/O operation shows is not seen.

### Glitched decisions (steers)

With `instruction_skip_glitch_ppm` set (0 by default),
`sec.criticalCheck(env, cond)` and `sec.criticalEql(T, a, b)` may return
the inverted answer, as a fault attack that skips one compare would. A
check that is done twice survives one glitch. From `example1.zig`:

```zig
            try env.always("forged frame rejected", !(tardis_sec.criticalCheck(env, ok) and tardis_sec.criticalCheck(env, ok)));
```

### The Spectre-v1 shape

`sec.spectre.boundsCheck`, `sec.spectre.load` and
`sec.spectre.indexNoSpec` let Zig code name a bounds check and the loads
after it. A load whose address follows the value an earlier load
returned is CWE-1037. This is a heuristic for the shape of the gadget,
not a model of speculation.

### MC/DC

`sec.mcdc.decision(id, conds, eval)` records the condition vector of a
decision and returns its value. `SecurityConfig.mcdc` receives the
campaign's table: which conditions were shown to decide the outcome on
their own, and which were not. From `pillar45_test.zig`:

```zig
    _ = sec.mcdc.decision(unlock_decision, .{ armed, sig_ok, override }, struct {
        fn f(c: anytype) bool {
            return c[0] and (c[1] or c[2]);
        }
    }.f);
```

`sec.mcdc.compare(a, op, b)` is a comparison that also offers `b` to
guided exploration as a value worth forcing. The compiler gives no help
here: only decisions written through the wrapper are measured.

### C code

C linked into a test can take part. Include `src/sec/c/tardis_sec.h`
after the system headers and export its functions from the Zig test:

```zig
comptime { sec.exportC(); }
```

The shims report received bytes in a format string (CWE-134), in SQL
text (CWE-89) and on a command line (CWE-78), and pthread mutexes taken
in both orders (CWE-833). The header's comment lists what it wraps;
`src/sec/tests/cshim_test.zig` has the tests. With C built with clang's
coverage tracing and `comptime { sec.exportCoverage(); }`, the
constant-time assertions also compare that C's control flow and division
widths (`src/sec/tests/ctrace_test.zig`).

### Instrumented objects (experimental)

Zig does not instrument loads and stores, so the detectors above work at
allocation, at free and at the I/O boundary. To check each access, build
the code under test as a separate object with the thread sanitizer's
callbacks and link it into the test. Three options then apply to that
object:

| Option | Finds | CWE |
|---|---|---|
| `shadow_memory` | a store or load past the end of an allocation, or a use after free, at the access | 787, 125, 416 |
| `data_races` | two tasks of one node touching one address, at least one with a store, with nothing ordering them | 362 |
| `atomic_lock_order` | two `std.Io.Mutex` taken in both orders | 833 |

In `build.zig`:

```zig
const tardis_build = @import("tardis");
_ = tardis_build.addInstrumentedObject(b, tests, .{
    .name = "sut",
    .root_source_file = b.path("src/sut.zig"),
    .target = target,
    .optimize = optimize,
});
```

The test exports the runtime with `comptime { sec.exportSanitizer(); }`
and reaches the object through `extern fn` declarations. From
[`src/sec/tests/shadow_test.zig`](../src/sec/tests/shadow_test.zig):

```zig
    try std.testing.expectError(error.SecurityViolation, tardis.check(gpa, counterPlain, sec.withSecurity(.{
        .data_races = true,
        .report = &report,
        .base = .{ .iterations = 50, .report = false },
    })));
```

That file and `src/sec/tests/shadow/sut.zig` are the worked example. The
README's section on the layer has more on the build.

### Every execution within a bound

`sec.verifyExhaustive(gpa, body, options, x)` is `tardis.exhaustive`: it
runs every combination of the first decisions of a body instead of
sampling them. The result says whether the bound was covered without
gaps. It is evidence within the model and the bound, never a proof
beyond them.

## The evidence campaign

`sec.certify(gpa, io, body, config, options)` runs a campaign and
collects, for every counted run, the requirement checks and the
findings. A test binds a check to a requirement with
`sec.requirement("SFR-…").check(ok)`.

In `.certification_eal7` mode (or with `TARDIS_CERT_EAL7` set, in tests)
the campaign does not stop at the first failure: every failure is shrunk
and kept, and a bundle is written to `<out>/<evidence_dir>/<id>/`
(`evidence_dir` is `zig-out/tardis-evidence` by default;
`TARDIS_EVIDENCE_DIR`, in tests, overrides both `out` and
`evidence_dir`). The bundle holds:

| File | Content |
|---|---|
| `manifest.json` | tool, Zig and campaign identity, outcome counts, repository revisions |
| `rtm.csv` | requirement to test traceability, with results |
| `mcdc.json` | per-decision MC/DC pairs and gaps |
| `findings.sarif` | SARIF v2.1.0: findings, failed requirements, failures |
| `sinks.json` | how often each taint sink was checked and hit |
| `determinism.txt` | golden trace hashes |
| `capsules/NNNN.tardis-replay` | one per logged failure: its token and expected error |
| `merkle.txt` | SHA-256 of every file above, and the Merkle root |
| `signature.ed25519` | the root signed with the project key, when `CertifyOptions.key` is set |

`certify` returns the campaign's error, if any, in `Certified.err`; it
fails itself only on I/O and allocation.

```sh
zig build evidence
```

runs this repository's certification campaigns (the tests of
`src/sec/tests/example2.zig`) with `TARDIS_CERT_EAL7=1`, and keeps their
bundles in `zig-out/tardis-evidence`. `-Dedges` adds a list of code the
campaigns never ran; it needs a Linux or macOS target.
[`src/sec/tests/example2.zig`](../src/sec/tests/example2.zig) is the
model for a campaign of your own.

To check a bundle: `sec.verifyEvidence` re-hashes every file, recomputes
the root and checks the signature, and `sec.replayEvidence` also re-runs
every capsule and the determinism hashes against the test body. The
`tardis` program has `tardis replay-evidence <dir>` for the first.

`.github/workflows/evidence.yml` runs the campaign and uploads the SARIF
file. It has not been run on GitHub yet.

## Limits

- **It is not a qualified tool.** See the top of this page.
- **Zig code is checked where a hook runs**: at allocation, at free, and
  where bytes cross `std.Io`. A plain pointer dereference between those
  points is not checked, unless the code is built as an instrumented
  object.
- **Instrumented objects only.** Shadow memory and the race detector
  check only code built as a separate instrumented object, and shadow
  memory only its heap accesses. The test body itself is not checked,
  and a mutex the test body locks orders nothing for the race detector.
- **Leaks shorter than 8 bytes are not seen.** Content is matched in
  8-byte windows. A received name shorter than 8 bytes, or one that
  reaches a path only in pieces, is not seen either.
- **Low-entropy content is not tracked.** A window with fewer than three
  distinct byte values is not fingerprinted, so an all-zero key is never
  matched.
- **A known false alarm.** In Debug and ReleaseSafe builds, undefined
  memory is filled with 0xAA, so a program that itself writes eight or
  more bytes of 0xAA is reported as leaking uninitialized memory. Set
  `SecurityConfig.undefined_fill_is_data` to give up that check.
- **Missing zeroization depends on the build mode.** In Debug and
  ReleaseSafe the allocator overwrites freed bytes before the layer sees
  them, so CWE-226 is reported only where the bytes survive the free
  (ReleaseFast, ReleaseSmall).
- **Fixed capacities.** 16,384 fingerprints, 256 marked regions and 64
  findings per run. Overflow is counted, not reported as a finding.
- **Constant time is at the I/O boundary for Zig code.** Control flow
  and cache effects are compared only for instrumented C.
- **MC/DC is per explicit wrapper**, and unique-cause.
- **The exhaustive search is bounded**, and its reduction rests on an
  assumption stated on `ExhaustiveOptions.reduce`.
- **The false-positive rate of each detector has not been measured.**
  `plan3.md` A7 lists that as work to do, and records the one false
  alarm counted so far (the 0xAA fill above). `plan2.md` records that
  the repository's whole suite passes with `-Dsec`; that was not re-run
  for this guide.
- **The findings are not in the Chrome trace**, except as one note event
  ([trace.md](trace.md)).

`plan2.md` tags every capability as verified by a test, designed, or a
target, and its Appendix A lists them all. Read it before relying on a
detector that this page only names.
