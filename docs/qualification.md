# Qualification kit

TARDIS is not certified or qualified under any standard, and this document
does not change that. Qualifying a tool is done by the organisation that
uses it, for its own project, under its own process and assessors.

What this document does is collect, in one place, what such a process
asks a tool's supplier for: what the tool is required to do, which tests
show that it does, what it is known not to do, and on which configurations
those tests were run. It is a starting point for your own tool
qualification plan, not a substitute for one.

It covers the core (`tardis`). The security layer (`tardis_sec`) is out of
its scope except where a row says otherwise; `plan2.md` §7.6 has notes on
that layer.

## 1. What the tool is used for

TARDIS runs test bodies written against Zig's `std.Io` inside a simulator
and reports whether stated properties held. In the vocabulary of the tool
standards it is a **verification tool**: it can fail to detect an error in
the software under test, and it cannot insert one, because it is not part
of what ships. (In DO-330 terms that is criteria 3; in ISO 26262-8 terms
the relevant question is tool error detection. Your own classification
depends on how you use its results.)

The risk to manage is therefore one: **a run that passes when the
property does not hold.** Sections 3 and 4 are about that.

## 2. Requirements and the tests that verify them

Each requirement names the tests that check it. The tests run with `zig
build test`; file names are under `src/tests/` unless they say otherwise.

| ID | The tool shall | Verified by |
|---|---|---|
| R1 | give the same run for the same seed, persona and options, on every supported platform and build mode | `determinism_test.zig` (a recorded trace hash, checked in every mode and on every platform the suite runs on); the re-run of every 16th iteration in every `check` (`plan.md` §7.4); `self_fuzz_test.zig` (every run executed twice) |
| R2 | give the same result whatever the number of worker threads or processes | `parallel_test.zig`; `fork_test.zig` (one process, a fork server, four worker processes) |
| R3 | report a failure with what is needed to run it again, and replay it exactly | `shrink_test.zig` (tokens replay); `bugs_test.zig` |
| R4 | reduce a failure to decisions that still cause it, never to a different failure | `shrink_test.zig`; `sec/tests/pillar1_test.zig` (seam 4: a security finding is kept only while the same finding reproduces) |
| R5 | model a power loss no more kindly than the persona's filesystem: what was not made durable may be lost | `fs_test.zig`, `link_test.zig`, `bugs_test.zig` (planted crash-consistency bugs are found per persona); `self_fuzz_test.zig` (what was synced survives) |
| R6 | answer filesystem calls as the real filesystem does when no fault is injected | `diff_fs_test.zig`: random operation sequences compared with the host's filesystem (NTFS, ext4) |
| R7 | answer stream-socket calls as the real loopback does when no fault is injected | `diff_net_test.zig`: five scenarios compared with the host |
| R8 | schedule tasks only at `std.Io` calls, and explore their interleavings from the seed | `scheduler_test.zig`; `examples/counter.zig`, `examples/check_then_act.zig` (races found) |
| R9 | detect a run in which every task is blocked, a run that makes no progress within a stated bound (`Env.expectProgress`), and a run that leaves a handle, a task or memory behind | `scheduler_test.zig`, `liveness_test.zig`, `fs_test.zig`, `net_test.zig`; `examples/deadlock.zig`, `examples/livelock.zig`, `examples/error_leak.zig` |
| R10 | deliver, delay, reorder, drop and duplicate network traffic only as its options allow, and hold stream data across a partition | `net_test.zig`, `udp_test.zig`, `chaos_test.zig` |
| R11 | check linearizability and transactional anomalies correctly on recorded histories | `lin_test.zig`, `elle_test.zig` (histories with known verdicts) |
| R12 | in the exhaustive search, visit every schedule within the stated depth, and with reduction or merging reach the same set of outcomes | `sec/tests/pillar45_test.zig` (the vote model: with reduction and with merging, fewer executions, the same verdicts and the same outcomes); `zig build bench` holds the counts, 9,216 and 3,073, to their recorded values |
| R13 | never let an unsimulated `std.Io` call reach the real system | by construction: the simulator's call table starts as `std.Io.failing` (`plan.md` §11) |
| R14 | find each bug in its benchmark of planted bugs, and pass each fix | `zig build bugbench` (twenty-six programs), run in CI; how often by campaign size: `docs/measurements.md` |
| R15 | in system-call mode (`Options.mode = .syscalls`, Linux x86_64), answer the file, clock, sleep and random-byte system calls from the simulation as the kernel would answer them with no fault, and fail the run that makes any other call | `sysmode_test.zig`: random sequences of file calls compared with the real kernel (ext4); the same program by system call and by `std.Io` gives one trace and one result after a crash; a call that is not emulated fails the run. `test/sqlite.zig` (not part of `zig build test`) |

Requirements R5, R6 and R7 are the ones that carry the tool's fidelity,
and they are the least complete: see section 3.

## 3. Known limits

A passing run means: for the seeds, inputs, personas and options that
ran, no run broke a property the test stated. It does not mean more.

**What the tool does not see**

- Code that does not go through `std.Io`: a C library doing its own I/O, a
  direct system call, a child process, real threads. On Linux x86_64
  `Options.trap_syscalls` turns a stray system call into a failure, and
  `Options.mode = .syscalls` (revision 75) answers the file, clock, sleep
  and random-byte calls from the simulation; on other platforms nothing
  does either.
- In system-call mode: tasks made through `std.Io` share one thread
  identity, so a recursive mutex (owned by the thread) does not exclude a
  second task. Do not share an object behind a recursive lock (a SQLite
  connection) between tasks. Threads the code starts itself are tasks with
  their own thread pointer (revision 97) and do not have this limit, but
  they switch only at system calls: a thread spinning on memory hangs the
  run unreported, and data races between threads are not explored. A
  thread may not use `std.Io`.
  A crash or the end of a run that drops a task holding a C library's
  mutex leaves it held, into the next run (C statics are the process's).
- In system-call mode: clock reads through the vDSO are answered from
  the simulation (revision 78); a thread inside the vDSO when a run
  begins makes that run fail with `StraySyscall`. `select`, `mmap` of a file,
  `fork`, `dup2` and `dup3` are not emulated (each fails
  the run). Before revision 99 a test linked with libc did not find the
  vDSO, and its C code read the host's clock. Edge-triggered
  `epoll` reports more edges than Linux (revision 97). Owners,
  permission bits and record locks are not modelled. State a library keeps
  for the life of the process is carried from one run to the next.
- Shared memory between tasks, except through `tardis.atomic.Value`.
- A property the test did not state.
- Liveness in general: `eventually` covers convergence after a fault
  heals, and `expectProgress` fails a run that makes no stated progress
  within a bound. Both are bounded checks: a property that holds only
  after the bound is reported as a failure, and a task that loops without
  any simulated operation is not seen at all.

**Where the models are known to be incomplete**

- The filesystem model has been compared with real NTFS and ext4 for
  whole-file and positional I/O, renames, directories and links, on 2,000
  random sequences per run. It has not been compared for several handles
  open at once, directory listing, permissions, or on APFS, XFS or ZFS.
  That comparison found eight errors in the model when it was first run
  (revisions 59 and 60); it is reasonable to assume it has not found the
  last.
- **The crash behaviour of each persona is written from documentation and
  has not been checked against the real filesystems under power loss.**
  This is the largest gap in R5.
- The network model has been compared with the real loopback on five
  stream scenarios. Datagrams, large transfers, timeouts and name lookup
  have not been compared.
- The personas are fixed models. A filesystem mounted with unusual
  options, or a newer kernel, may behave differently.

**Where the search is incomplete**

- A campaign samples seeds. A bug that needs a rare combination can be
  missed by any finite campaign; `plan3.md` F1 measures how quickly known
  bug classes are found, on small programs.
- The exhaustive search is bounded by depth, and its reduction rests on an
  assumption stated on `ExhaustiveOptions.reduce`.

**Known defects and oddities**

- Until revision 72 a fiber switch on 64-bit Windows did not preserve the
  vector registers a callee must (`xmm6` to `xmm15`), which could corrupt
  values an optimized build kept in them. It was seen as a crash in
  ReleaseFast; results from earlier revisions on Windows in an optimized
  build deserve a re-run.
- With the security layer attached, a program that writes eight or more
  bytes of 0xAA is reported as leaking undefined memory in safe builds
  (`SecurityConfig.undefined_fill_is_data` turns the check off).
- Zig's standard library panics instead of returning an error when a
  directory is renamed into itself, on Windows and, through a symbolic
  link, on Linux. That is outside TARDIS, and a program under test that
  does it stops the test process.

## 4. How a wrong pass could happen, and what guards against it

| Failure mode | Guard | Residual risk |
|---|---|---|
| The simulator is not deterministic, so a failure seen once cannot be reproduced | R1: every 16th iteration is run twice and compared; the trace hash test | A source of non-determinism that the trace does not record |
| A model is kinder than the real system (a crash loses less than a real one would) | R5, R6; the personas include `posix_strict`, which loses everything POSIX allows | The crash models are unvalidated against real hardware |
| A model is wrong about an error or a result, so the code under test takes a path it would not take in production | R6, R7 | Operations the comparisons do not cover |
| The oracle is wrong (a linearizability or anomaly check passes a bad history) | R11 | Histories unlike the tested ones |
| The shrinker changes the failure into a different one | R4 | None known |
| A reduction in the exhaustive search skips a schedule that matters | R12 | Programs that break the reduction's stated assumption |
| The code under test leaves the simulation | R13; `trap_syscalls` on Linux x86_64; R15 for code that makes system calls | Other platforms; threads; clock reads through the vDSO outside system-call mode |
| The test passes for want of coverage | `env.sometimes` fails a campaign that never reached a stated situation | Situations the test did not name |

## 5. Verified configurations

The suite has passed on:

| Platform | Zig | Build modes | How |
|---|---|---|---|
| Windows 11, x86_64 | 0.17.0 | Debug, ReleaseSafe, ReleaseFast, ReleaseSmall | run natively |
| Linux (Debian under WSL2), x86_64 | 0.17.0 | Debug | cross-compiled for `x86_64-linux-musl`, run natively |

System-call mode (R15) has run only on the second row, on kernel 6.18.

It compiles for `aarch64-macos` and has **not** been run there, nor on any
aarch64 machine, nor on a BSD. This table was last checked at revision 75
(`CHANGELOG.md`). The workflows in `.github/workflows/` are written to run
the suite on Linux, macOS and Windows; when this was written they had not
yet passed.

## 6. What your own qualification still has to supply

- The classification of the tool in your process, from how you use its
  results.
- Your operational requirements: which properties your tests state, and
  why a pass on them is evidence for your claim.
- A run of this suite on your platform and compiler, with the results
  kept. `scripts/verify.sh` is the procedure.
- An assessment of the limits in section 3 against your system: in
  particular whether your code does I/O outside `std.Io`, and whether your
  durability claims rest on crash behaviour this tool models but has not
  validated.
- Configuration control of the tool: the exact revision, the Zig version,
  and the options of each campaign. An evidence bundle from
  `tardis_sec.certify` records the last two and the repository's commit.
