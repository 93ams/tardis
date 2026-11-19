# TARDIS: the road to production

| | |
|---|---|
| **Scope** | What has to be true before TARDIS can be recommended to people who did not write it, and before it is a better choice than the alternatives for testing Zig programs. |
| **Relation to the other plans** | `plan.md` (core) and `plan2.md` (security layer) say what is built and verified, at revision 57. This plan is about everything else: trust, packaging, usability, reach, and proof of value. |
| **Status** | Proposal. Nothing in it is done unless it says so (B5, G1 and G2 are; A1, A2, B4, C1, C2, D1 and H1 say how far they got). |

## 0. The two targets, stated so they can be checked

**Production ready** means a stranger can do all of this without reading the source or asking the author:

1. Add TARDIS to a project with one command and write a passing test in under ten minutes.
2. Get a failure, understand the report, and replay it on another machine and another operating system.
3. Upgrade to the next release without their tests changing meaning silently.
4. Trust a green run: know which classes of bug it rules out and which it cannot see.
5. Run it in CI on Linux, macOS and Windows with no special setup.

**Better than the alternatives** means, on a public benchmark of real bug classes, TARDIS finds more of them, faster, with shorter reproductions, than the tools a Zig team would otherwise reach for. Until that benchmark exists (workstream F), "better" is an opinion.

## 1. Where the project stands

### 1.1 What is strong

- **Determinism that is checked, not assumed.** Every 16th iteration is re-run and compared; the golden trace hash recorded on Windows reproduces on Linux.
- **Breadth of fault model.** Crash consistency per filesystem persona, network partitions and reordering, multi-node clusters, weak-memory atomics, allocation failure.
- **Failures shrink.** A 77,960-decision failure reduces to 9 decisions; replay tokens are one line.
- **Speed.** An empty run costs about 1.6 µs; setups restore from a snapshot in tens of microseconds.
- **Oracles.** Linearizability, transactional anomalies (Elle-style), exhaustive search with reduction and state merging.
- **A security layer** with content tracking, taint sinks, constant-time and Spectre-shape checks, MC/DC, signed evidence, and (for instrumented objects) shadow memory, a race detector and lock order.
- **Honest documents.** Both plans mark each claim as verified or not, and record what was tried and rejected.

### 1.2 What stands between this and a release

| Gap | Evidence |
|---|---|
| No release exists | `build.zig.zon` says version `0.0.0`; there is no tag, no changelog, no license file. |
| One user | The only program tested with TARDIS besides its own suite is `termancy`, by the same author. |
| Never run in CI | Both workflows are written and have never run. macOS has never run the suite at all; no BSD has. |
| aarch64 never run | The fiber switch has an aarch64 path and the suite cross-compiles for `aarch64-macos`, but no aarch64 machine has run it. The syscall trap and the virtual counter are x86_64 Linux only. |
| The simulator's fidelity is asserted, not measured | The filesystem personas and the network model are written from documentation and experience. Until revision 59 nothing compared them against the real systems they imitate; the first such test found eight errors in the filesystem model (A2). The crash behaviour is still unmeasured; the network model has a first, small comparison (A4). |
| Zig 0.17 only | One pinned compiler. No policy for what happens when 0.18 changes `std.Io`. |
| Only `std.Io` code is simulated | Real threads, direct system calls, C libraries that do their own I/O, and child processes are outside the simulation. |
| The documentation is a design record | 3,600 lines of plans, a 190-line README, no tutorial, no API reference, no examples directory. The revision history was one 11,000-character table cell until it moved to `CHANGELOG.md`. |
| The newest detectors need an awkward build | Shadow memory, races and lock order work only for code split out as a separately built object. |
| No comparative evidence | No benchmark against any other tool. |

## 2. The alternatives

What a Zig team could use instead, and where each one is ahead today. The claims about other tools here are general knowledge and must be checked against each tool's current state before any of this is published (F4).

| Alternative | What it is | Where it is ahead of TARDIS | Where TARDIS is ahead |
|---|---|---|---|
| **Antithesis** | Commercial deterministic hypervisor; runs unmodified containers. | Tests the real binary with its real dependencies, kernel and all. Any language. No code changes. | Free, local, in-process: microseconds per run instead of a hosted service. Shrinks to a handful of decisions. Crash-consistency personas. |
| **A project's own simulator** (the FoundationDB and TigerBeetle approach) | A simulator written for one codebase. | Models exactly what that system needs; years of tuning. | Reusable. A new project gets a simulator on day one instead of building one. |
| **Rust simulation libraries** (Turmoil, MadSim, Shuttle, Loom) | Deterministic runtimes and schedulers for Rust. | Mature, used in production projects, good documentation. Loom explores small concurrent tests exhaustively. | They do not test Zig. Their designs are the bar for usability. |
| **Jepsen** | Black-box testing of real clusters with real faults. | Tests the deployed system, including configuration and operations. Widely trusted reports. | Deterministic and replayable; thousands of runs per second instead of minutes per run; finds the bug before deployment. |
| **Record and replay** (rr, Hermit) | Deterministic execution of ordinary Linux binaries. | No code changes; handles threads and system calls. | Injects faults and explores schedules instead of replaying one; portable beyond Linux. |
| **Fuzzers and sanitizers** (Zig's fuzzer, AFL++, libFuzzer, ASan, TSan) | Input mutation plus runtime checks. | Whole-program instrumentation with no build split; mature tooling; coverage-guided by default. | Explores schedules, crashes and network faults, not only inputs; a failure replays exactly. |
| **Model checkers** (TLA+, and similar) | Exhaustive checking of a design. | Proves properties of the design for all behaviours within bounds. | Checks the code that ships, not a model of it. |

Two conclusions drive the rest of this plan:

- **The honest weakness is reach.** Antithesis and rr test what they are given. TARDIS tests code written against `std.Io`. Workstream D narrows that gap; it will not close it, and the documentation must say so plainly.
- **The honest strength is the loop.** Seed in, failure out, shrunk, replayed anywhere, in microseconds, for free. Workstreams A, C and F are about making that loop trustworthy, pleasant and provably effective.

## 3. Workstreams

Priorities: **P0** blocks a first public release. **P1** blocks calling it production ready. **P2** is what makes it better than the alternatives.

### A. Trust in the simulator itself

A test tool that is wrong is worse than no tool: it gives false confidence. This is the workstream with the most risk in it.

| # | Item | Pri | Done when |
|---|---|---|---|
| A1 | **Run the suite on every supported platform in CI.** Push; fix what the first macOS run breaks. **First runs done** (commit `890863f`): the evidence workflow's own steps passed and its SARIF upload failed (two bundles under one category; fixed, unrun). The test workflow failed on all three systems, and a local reproduction of the CI checkout shows why: the published `termancy` `master` lacked a durability fix that existed only locally, and the termancy suite found the bug. Whether macOS and Linux have failures beyond that is unknown until a run with the fix. | P0 | `test.yml` and `evidence.yml` are green on Linux, macOS and Windows for a week of commits. |
| A2 | **Differential tests of the filesystem model.** Run the same operation sequences against the simulated filesystem (no faults) and the real one, and compare results and errors. **Revisions 59 and 60** (`src/tests/diff_fs_test.zig`, part of `zig build test`): 2,000 random sequences of 32 operations over seven paths, on the host's persona: write, read, delete, make and delete a directory, rename, stat, write and read at an offset and set the length through an open handle, exclusive create, access, and on POSIX hosts hard links, symbolic links and reading a link. It found eight errors in the model, all fixed:

  1. NTFS reports a path through a regular file as not found; the model said not a directory.
  2. POSIX kernels call a rename onto a directory the source lives under not empty; the model said is a directory.
  3. NTFS answers an exclusive create onto a directory with is a directory; the model said already exists.
  4. A hard link's destination is examined before the source's kind; the model refused a directory source first.
  5. POSIX creates the target of a dangling symbolic link when a file is created through it; the model said not found.
  6. A directory cannot be renamed onto a symbolic link on POSIX; the model allowed it.
  7. A symbolic link renamed onto a directory is is a directory; the model said not empty.
  8. A rename between two names of one file does nothing on POSIX; the model removed the old name.

  And one in the simulator's `std.Io` layer: `access` on a path through a file returned an I/O error where std returns not found. It also found two places where Zig's std panics on a real system instead of returning an error (a directory renamed into itself, on Windows and, through a symbolic link, on Linux), so those cases are not generated, and that std makes no hard links on Windows. Agrees now on Windows (NTFS) and Linux (ext4 under WSL2); APFS waits for a macOS run. Still to do: several handles open at once, directory listing, permissions, the crash behaviour (A3), and the 100,000-sequence corpus. | P1 | A generated corpus of 100,000 sequences agrees on Linux (ext4), macOS (APFS) and Windows (NTFS), or each difference is listed as deliberate. |
| A3 | **Ground the crash personas in evidence.** For each persona, cite the kernel behaviour it models, and where possible reproduce it on a real filesystem with a power-cut tool (dm-log-writes or similar). | P1 | Each persona has a short document: source, what it over-approximates, what it misses. |
| A4 | **Differential tests of the network model** against loopback sockets: ordering, partial reads, close and reset semantics, error codes. **Started in revision 63** (`src/tests/diff_net_test.zig`, part of `zig build test`): five stream scenarios, each one function run on the simulated network and on the real loopback: a half-closed echo, a close with no data, a close with unread data (the peer sees a reset), a refused connection, and a second listener on a taken port. Agrees on Linux on all five. On Windows four agree, and the fifth is a known difference: a second listener succeeds there through Zig's std, and the model, which has no per-system network behaviour, refuses it as POSIX does. No model error found. Not yet: datagrams, large transfers and partial reads, timeouts, several connections, name lookup. | P1 | Same criterion as A2. |
| A5 | **Mutation testing of the oracles.** Plant known bugs in small programs and require each oracle to catch its class. Most of this exists as paired tests; make it systematic and measured. | P1 | A table of bug classes with detection rate per oracle, published in the documentation. |
| A6 | **Fuzz the simulator.** Random programs against `std.Io`; assert determinism, no panics, no leaks, and agreement between cold and warm starts, fork and no-fork, one worker and many. **Started in revision 61** (`src/tests/self_fuzz_test.zig`, part of `zig build test`): random file, link, sleep, task and crash sequences on all six personas with I/O errors and allocation failures on, each run executed twice and compared, plus the same on four workers; a synced file in a synced directory must keep its content through a power loss. No finding in the core so far, and no bug has been planted to show the test can fail. Not yet: sockets, cold against warm starts, fork against no-fork, and a nightly run. | P1 | Runs nightly; a week with no finding. |
| A7 | **False-positive budget for the security detectors.** Run them over real Zig projects and count findings that are not bugs. **First one counted** (revision 61): the self-fuzz programs under `-Dsec` are reported for CWE-908 whenever they write eight bytes of 0xAA, because a safe build fills undefined memory with that byte and the engine fingerprints it (`plan2.md` §3.7). Any program that legitimately writes a run of 0xAA trips it. Revision 62 adds `SecurityConfig.undefined_fill_is_data` for such a program, at the price of that check; the default is unchanged, since in a safe build it is the only way uninitialized heap bytes are seen. | P1 | Each detector has a measured false-positive rate; any above the budget is off by default. |
| A8 | **External review** of the determinism contract and the certification claims in `plan2.md` §7 by someone who did not write them. | P2 | Review done; findings fixed or listed. |

### B. Release engineering

| # | Item | Pri | Done when |
|---|---|---|---|
| B1 | **License.** Choose one and add the file. | P0 | `LICENSE` exists and `build.zig.zon` lists it. |
| B2 | **Make the package fetchable.** `zig fetch --save` from a tagged release works, with no sibling checkout. | P0 | A fresh project on a clean machine builds a test from the README. |
| B3 | **Resolve the `termancy` dependency.** The `tardis` program needs a sibling checkout today. Publish `termancy`, or split the program into its own package. | P0 | The library and the program each build from a clean clone. |
| B4 | **Versioning and stability policy.** Semantic versions; which API is stable; a guarantee about replay tokens (a token from version N replays on N, and the release notes say when that breaks). **Drafted:** `docs/stability.md`, for the owner to accept or change. The golden trace hash test already exists. | P0 | Written, and enforced by a golden-hash test per release. |
| B5 | **Changelog.** Move the revision history out of the plan headers into `CHANGELOG.md`. **Done:** `CHANGELOG.md` has 55 entries (revisions 2 to 56) and the header of `plan2.md` is one line. | P0 | Plan headers are one line; the changelog has an entry per revision. |
| B6 | **Zig version policy.** Track the current stable Zig; say how long the previous one is supported; test against Zig's master weekly so breakage is seen early. **Done, unrun:** the policy is in `docs/stability.md`, the weekly job is `.github/workflows/zig-master.yml`. | P1 | A scheduled CI job; a documented policy. |
| B7 | **Release automation.** Tag, build, run the full verification, publish notes. | P1 | A release takes one command. |
| B8 | **Security policy.** How to report a vulnerability; how the evidence signing key is created, stored and rotated. **Done:** `SECURITY.md`. The key is the user's: a campaign signs only when given one, and TARDIS stores none. | P1 | `SECURITY.md`; key handling documented. |

### C. Ease of use

The Rust libraries in §2 are the bar. A user's first hour decides whether they stay.

| # | Item | Pri | Done when |
|---|---|---|---|
| C1 | **A tutorial.** From an empty directory to a found, shrunk and fixed bug, in one page. **Drafted:** `docs/tutorial.md`. Not yet timed with a newcomer, and its first step (`zig fetch`) waits on B2. | P0 | Someone who has never seen the project completes it in under ten minutes, timed. |
| C2 | **An `examples/` directory.** A key-value store with a write-ahead log, a replicated log, an HTTP service: each with a planted bug and its fix. **Four examples done** (`zig build test-examples`, part of `test`): `wal_kv` (acknowledged before durable), `counter` (lost update), `jobs` (applied twice after a restart), and `replica` on three simulated machines (a replica left behind by a partition). No HTTP service. | P0 | Three examples build and run in CI. |
| C3 | **Split the documentation by reader.** User guide, reference, design record. The plans stay as the design record. | P1 | A new user never needs to open `plan.md`. |
| C4 | **API reference** generated from doc comments and published. | P1 | Every public declaration has a comment; the site builds in CI. |
| C5 | **Failure reports a newcomer can read.** Usability-test the report: what happened, in what order, which decision mattered, how to replay. | P1 | Three people unfamiliar with the project explain a report correctly. |
| C6 | **One-command reproduction.** A failing CI run prints a command that reproduces it locally, and uploads the trace. | P1 | Documented workflow for GitHub Actions. |
| C7 | **Sensible defaults and fewer options.** Audit `Options` and `SecurityConfig`; group the rest; presets for "quick", "thorough" and "nightly". | P1 | A typical test passes no options. |
| C8 | **Remove the build split for the instrumented detectors.** Zig links its own sanitizer runtime into any executable with an instrumented module, which forces the separate object. Propose upstream a way to supply the runtime; until then, keep `addInstrumentedObject`. | P2 | An upstream issue exists; if accepted, the detectors work on an ordinary test. |
| C9 | **Trace viewer.** The Chrome-trace export exists; document it and add the security findings to it. | P2 | A failure can be read as a timeline. |
| C10 | **Editor integration.** Run and replay a test from the editor. | P2 | Works in one editor. |

### D. Reach: how much of a real program is simulated

| # | Item | Pri | Done when |
|---|---|---|---|
| D1 | **Complete the `std.Io` coverage matrix** (`plan.md` §11): every entry either simulated or documented as refused, with a clear error. **Holds by construction:** the simulator's table starts as `std.Io.failing`'s, so an entry it does not fill fails and never reaches the real system. Still to do: the error is std's own, and does not say that TARDIS refused the call or which one. | P0 | No entry silently falls through to the real system. |
| D2 | **aarch64.** The fiber switch for aarch64 is written and has never run. Run it on Apple Silicon and on aarch64 Linux, and fix what breaks. | P0 | The suite passes on a macOS runner and an aarch64 Linux runner. |
| D3 | **Fail loudly on escape.** Make the stray-system-call trap available on more targets, and default it on in CI presets where it exists. | P1 | A run that leaves the simulation fails by default on Linux. |
| D4 | **Child processes.** A model for `std.process` spawn: simulated programs registered by the test. | P1 | A program that shells out can be tested. |
| D5 | **Real threads.** Code that uses `std.Thread` directly is outside the simulation. Either map threads onto simulated tasks or refuse with an explanation. | P1 | Decided, implemented or documented. |
| D6 | **C dependencies.** A guide and shims for C libraries that do their own I/O (the C header covers taint sinks today, not I/O). | P2 | One real C library (SQLite is the obvious choice) runs under simulation. |
| D7 | **More personas and platforms.** ZFS, XFS, btrfs semantics where they differ; a BSD. | P2 | Each backed by A3-style evidence. |
| D8 | **Bigger simulations.** The limits today are small (64 tasks by default, 32 nodes in the security layer). Measure the cost of raising them. | P2 | 1,000 tasks and 100 nodes run at a documented cost. |

### E. Performance and scale

| # | Item | Pri | Done when |
|---|---|---|---|
| E1 | **Benchmarks in CI with regression thresholds.** The benchmarks exist; nothing guards them. **Done, unrun in CI** (revision 64): `scripts/bench_check.py` reads `zig build bench` and `scripts/bench_budgets.txt`. Five numbers that follow from the seed alone (executions explored, what a failure shrinks to, the iteration that finds a bug) must match exactly; five timings must stay under about ten times a developer machine's figure, so a shared runner passes and an order-of-magnitude slowdown does not. A 10% slowdown is not caught: shared runners vary by more than that. | P1 | A change that slows an empty run by 10% fails a check. |
| E2 | **Multi-core scaling.** Eight workers give about 1.15 times eight processes' throughput today; find what is shared. | P1 | Near-linear to the core count on a 16-core machine. |
| E3 | **Memory per simulator.** Measure and document; make the large tables lazy (the shadow is 8 MiB, the race detector 2 MiB). | P1 | A table of memory by option. |
| E4 | **Long campaigns.** Corpus persistence between runs, resumable campaigns, nightly budget control. **Budget control only** (revision 65): the iteration scale and the seed salt of I1. The guided explorer's corpus still lives and dies with one `check`. | P1 | A nightly job continues where the last one stopped. |
| E5 | **Exploration effectiveness.** Add priority-based scheduling (PCT), which `plan.md` lists as not started, and measure it against the current strategies on the F1 benchmark. | P2 | A measured recommendation for the default. |
| E6 | **The keyed-decision cost.** Profile the hot path on realistic workloads, not empty runs. | P2 | A profile-guided list, with the top item fixed. |

### F. Proof that it finds bugs

This is the workstream that turns "better" from a claim into a number.

| # | Item | Pri | Done when |
|---|---|---|---|
| F1 | **A public bug benchmark.** Twenty to thirty small programs, each with one real class of bug: torn writes, missing fsync of a directory, lost updates, stale reads after a partition, deadlocks, double-apply after retry, clock-skew errors. Each with the fix. **Runner done, four programs of the twenty to thirty** (revision 66): `zig build bugbench` prints, for each example, whether a plain run of the planted bug fails, whether a campaign finds it, how long that takes and what the failure shrinks to, and whether the fix passes; it exits non-zero if a bug is missed or a fix fails, and CI runs it. On a developer machine: all four found in 14 to 69 ms; three shrink to 1 to 3 decisions (from 41 to 112); the fourth is not shrunk. | P1 | The suite exists, runs in CI, and reports time-to-bug and reproduction size per program. |
| F2 | **Baselines.** The same programs under plain unit tests with retries, under Zig's fuzzer, and under random fault injection without guidance or shrinking. **One baseline** (revision 66): the plain run, which is the buggy program run once with every decision benign, as an ordinary test of it would be. Three of the four planted bugs pass it. The fourth, `replica`, fails it, because its test cuts the network itself: that program shows the oracle, not the fault injection. No comparison with Zig's fuzzer or with retries yet. | P1 | A table: found or not, time, reproduction size. |
| F3 | **Dogfooding on real projects.** Three open-source Zig projects that use `std.Io`, tested with their maintainers' agreement. Report what was found upstream. | P1 | Three write-ups; at least one confirmed upstream bug. |
| F4 | **Comparison with the alternatives, checked.** For each tool in §2 that can run a comparable test, run it; for those that cannot, say why, citing the tool's own documentation. | P2 | A comparison page whose every claim has a source or a measurement. |
| F5 | **Liveness.** Today's oracles are mostly safety. Add "eventually" properties with fairness, so a system that stops making progress is a finding. | P2 | A livelock in the benchmark is found. |

### G. The security layer

| # | Item | Pri | Done when |
|---|---|---|---|
| G1 | **Close the documented gaps in the new detectors**: message causality in the race detector, the shrink-in-place label in shadow memory, hold-across-yield for `std.Io.Mutex`. **Done in revision 57**, the last by deciding against it: an `std.Io.Mutex` is meant to be held across I/O. | P1 | The limits lists in `plan2.md` §3.8, §4.5 and §4.6 are shorter. |
| G2 | **Be precise about certification.** The layer produces evidence in the shape standards ask for (MC/DC, traceability, signed bundles). It is not a qualified tool. Say so in the first paragraph, and list what a real qualification would need. **Done:** the first paragraph of `plan2.md` §1.1 and the README's section on the layer say it; §7.6 has the notes. | P0 | No reader can come away thinking the tool is certified. |
| G3 | **Make the layer optional in the user's mind.** A user of the core should not have to learn it. | P1 | The tutorial does not mention it; a separate guide does. |
| G4 | **An independent look at the evidence format** by someone who works with one of the standards it names. | P2 | Feedback incorporated. |

### H. Project health

| # | Item | Pri | Done when |
|---|---|---|---|
| H1 | **Contribution guide, issue templates, code of conduct.** **Guide done** (`CONTRIBUTING.md`); templates and a code of conduct are not. | P1 | Present. |
| H2 | **A second maintainer**, or at least a second reviewer. One author is the largest risk to anyone depending on this. | P1 | Someone else has merged a change. |
| H3 | **Housekeeping.** The build cache reached 59 GB during development; document cleaning it, and keep CI caches bounded. | P1 | Documented. |
| H4 | **A public roadmap** derived from this plan. | P2 | Issues exist for every P0 and P1 item. |

## 4. Milestones

| Milestone | Contents | The test |
|---|---|---|
| **0.1: installable** | A1, B1–B5, C1, C2, D1, D2, G2 | A stranger adds the package, follows the tutorial, finds the planted bug, on any of three operating systems. |
| **0.5: trustworthy** | A2–A7, B6–B8, C3–C7, D3–D5, E1–E4, G1, G3, H1–H3, I1 | Each model has evidence behind it; each detector has a measured false-positive rate; benchmarks are guarded. |
| **1.0: proven** | F1–F3, plus whatever they expose | The benchmark table is public and three outside projects have used it. Stability policy takes effect. |
| **Beyond** | C8–C10, D6–D9, E5, E6, F4, F5, A8, G4, G5, H4 | Better than the alternatives, with numbers. |

Order within 0.1: push and fix CI first (A1), because everything else assumes the suite is green somewhere other than one desk. Then license and packaging (B1–B3), because nothing else can be tried by anyone until they exist. Then the tutorial and examples (C1, C2).

## 5. Risks

| Risk | Why it matters | What reduces it |
|---|---|---|
| **`std.Io` changes under us.** | The whole design rests on one interface in a pre-1.0 language. A redesign upstream is a rewrite here. | B6: test against Zig master weekly; keep the VTable layer thin; engage upstream. |
| **The models are wrong in a way the tests cannot show.** | Every test of a persona was written by the person who wrote the persona. | A2–A4: compare against the real thing. A8: outside review. |
| **Few Zig projects use `std.Io` yet.** | The audience is small until the ecosystem moves. | F3 finds out early. D4–D6 widen what can be tested. |
| **Scope.** | Two plans, fifty-six revisions, a security layer with certification vocabulary: more surface than one person can keep correct. | G3: the core is the product; the layer is optional. Cut, do not add, until 1.0. |
| **A false sense of safety.** | Users will read a green run as "no bugs". | C1 and the reference state, per bug class, what a green run does and does not mean. |

## 6. Boundaries, and how far each can be moved

Four things this plan does not set out to build. For three of them there is a cheaper thing that gives users most of what they would have wanted; those are items in their own right.

| Boundary | Why not | What moves it | Item |
|---|---|---|---|
| **A hosted service** | The advantage over a hosted product is that this runs on a laptop, free, with no account. Running a service is a business, not a feature. | What people want from a service is long campaigns they do not have to babysit, and a failure they can open. A reusable CI workflow gives that on the user's own runners: nightly budget, a corpus that persists between runs, failing seeds and traces uploaded, one command to reproduce. | **I1** (P1), with E4 and C6 |
| **Simulating arbitrary binaries** | That is a hypervisor or a record-and-replay tool, and years of work. | Most of the gap is code inside the test's own process that does not go through `std.Io`: C libraries, direct `std.posix` calls. On Linux x86_64 the stray-system-call trap already catches every such call. Answering the common ones from the simulator (files, time, randomness, sleeping, sockets) instead of only reporting them puts that code inside the simulation, with no change to it. A subset, one platform, same process: not arbitrary binaries, but the part of them users actually hit. | **D9** (P2), after D3 |
| **Formal tool qualification** | Qualification is a process carried out by the organisation that uses the tool, with its own auditors. Nobody can do it for them in advance. | What makes it cheap for them: the tool's requirements written down, each traced to the tests that verify it, the known limits and failure modes listed, and the configuration that was verified named. That is a qualification kit, and most of its content already exists in the two plans. | **G5** (P2), after G2 and G4 |
| **More detectors before 1.0** | The existing ones need measurement (A5, A7), not company. | Nothing: this is a discipline, not a gap. New detectors go to a backlog, opened after 1.0. | none |

The three items:

| # | Item | Pri | Done when |
|---|---|---|---|
| I1 | **A reusable campaign workflow.** One workflow file a project copies or calls: runs a budgeted campaign nightly, restores and saves the corpus, uploads the failure report, the replay token and the trace, and opens or updates an issue for a new failure. **Partly done, unrun** (revision 65): `TARDIS_CAMPAIGN_SALT` and `TARDIS_ITERATIONS_SCALE` turn any suite into a long run on new seeds, and `.github/workflows/campaign.yml` uses them nightly on three systems, keeps the log, and can be called from another repository. Tried locally: the self-fuzz and filesystem comparison at five times their iterations on salted seeds pass (10,000 new sequences against NTFS). Not done: a corpus kept between runs (E4), the trace as an artifact, an issue per new failure. | P1 | Two projects other than this one run it unmodified. |
| D9 | **System-call emulation on Linux x86_64.** Extend the stray-call trap: for an allowlisted set (open, read, write, pread, pwrite, fsync, rename, unlink, close, stat, clock reads that are real calls, getrandom, nanosleep, then sockets), perform the call against the simulator's filesystem, clock and network in place of the kernel. Anything else is still reported as stray. | P2 | A C library that does its own file I/O (SQLite built with its default VFS is the test) runs under simulation unmodified, and a crash-consistency bug planted in it is found. |
| G5 | **A qualification kit.** The tool's requirements, a trace from each to its tests, the limits and failure modes, and the verified configurations, in one document set that a user's process can cite. | P2 | Someone who works under one of the standards named in `plan2.md` §7 confirms it is the right shape. |

D9 is the one that changes what TARDIS is. It is also the riskiest: the simulator's file and socket models would have to match the system-call interface, not `std.Io`'s, closely enough that unmodified code cannot tell. A2 and A4 (the differential tests) are its foundation, which is why it comes after them.
