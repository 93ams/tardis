# Changelog

One entry per revision of the plans and the code, newest first. Section
numbers (§) are `plan2.md`'s unless an entry names `plan.md`. Revision 1
was the first draft of `plan2.md`; the core's earlier history is in
`plan.md` §9 and §14.

## Revision 66 (a program and CI)

`zig build bugbench` (`src/cmd/bugbench`): the bug benchmark over the four examples, with the plain run as a baseline, and a CI step that fails if a planted bug is missed or a fix fails (`plan3.md` F1, F2).

## Revision 65 (core and CI)

`TARDIS_CAMPAIGN_SALT` and `TARDIS_ITERATIONS_SCALE` (tests only): other seeds, and more iterations, for every `check` without editing a test. `.github/workflows/campaign.yml` runs a nightly campaign with them on Linux, macOS and Windows and can be called from another repository (`plan3.md` I1).

## Revision 64 (scripts and CI only)

A benchmark check (`scripts/bench_check.py`, `scripts/bench_budgets.txt`, a step of the test workflow on Linux): the benchmark numbers that follow from the seed must match exactly, and its timings must stay within generous budgets (`plan3.md` E1).

## Revision 63 (tests only)

A differential test of the network model against the real loopback interface (`src/tests/diff_net_test.zig`, `plan3.md` A4): five stream scenarios, compared on bytes, end of stream and errors. No model error found; one accepted difference on Windows, where a second listener on a taken port succeeds.

## Revision 62 (security layer; one constant in core)

`SecurityConfig.undefined_fill_is_data`: a program whose own data holds runs of 0xAA turns off the fingerprint that takes them for undefined memory (§3.7). The seam's parameter block grows from 16 words to 24.

## Revision 61 (tests and documents)

A self-fuzz test of the simulator (`src/tests/self_fuzz_test.zig`, `plan3.md` A6): random programs on every persona, every run executed twice and compared, on one worker and on four, with a durability check after power loss. `SECURITY.md`, and a weekly workflow that runs the suite against Zig's development branch. Under `-Dsec` the self-fuzz programs showed a false alarm of the security layer: eight bytes of 0xAA written by a program are taken for undefined memory (`plan3.md` A7).

## Revision 60 (core only)

The differential test of the filesystem model covers open handles (writes and reads at an offset, setting the length), exclusive create, `access`, and on POSIX hosts hard and symbolic links, over 2,000 sequences. Six more model errors found and fixed: an exclusive create onto a directory on NTFS, the order of a hard link's checks, creating a file through a dangling symbolic link, a directory renamed onto a symbolic link, a symbolic link renamed onto a directory, and a rename between two names of one file; and `access` on a path through a file now reports not found, as std does (`plan3.md` A2).

## Revision 59 (core only)

A differential test of the filesystem model against the real filesystem (`src/tests/diff_fs_test.zig`, `plan3.md` A2): random operation sequences run on both, every result compared. Two model errors found and fixed: on NTFS a path that goes through a regular file is not found (the model said not a directory), and on POSIX personas a rename onto a directory the source lives under is not empty (the model said is a directory).

## Revision 58 (examples and documents)

A fourth example, `replica`: three simulated machines, and a replica left behind by a partition. `docs/stability.md` (what may change between releases, and what a seed is promised to mean), `CONTRIBUTING.md`, and a plain statement at the top of `plan2.md` §1.1 and in the README that the security layer is not certified or qualified under any standard.

## Revision 57

An adversarial review of revisions 52 to 56 and its fixes: the virtual counter's fault handler is installed once however many workers start, looks at the faulting instruction only for the kind of fault `rdtsc` raises, and cannot recurse; the race detector keeps each access's node with the access, so a reused task slot no longer moves old accesses to another node; a copy or fill of no bytes is not an access; `tardis.sim`'s loop form ends the security layer's run. The race detector takes a read from a file or a socket as coming after earlier writes by the same node's tasks (§4.5), and a block shrunk in place has its guard at the new end in the shadow (§3.8). Three examples with planted bugs and fixes (`examples/`, `zig build test-examples`), a tutorial (`docs/tutorial.md`), and `plan3.md`, the plan for getting to a release. The evidence workflow uploads each bundle's SARIF under its own category. The revision history moved from the header of `plan2.md` to this file.

## Revision 56 (build and security layer)

`addInstrumentedObject` in `build.zig` wires an instrumented object into a test in one call; the per-access cost is measured and its lookup cut (§3.8); a test workflow runs the suite on Linux, macOS and Windows (`plan.md` §10).

## Revision 55 (core only)

`Options.virtual_tsc` answers `rdtsc` and `rdtscp` with the run's virtual time on Linux x86_64 (`plan.md` §9 M6).

## Revision 54 (security layer only)

Lock order for `std.Io.Mutex` in instrumented code (§4.6). The sanitizer runtime sees a 32-bit atomic go from zero to non-zero and back, treats it as a lock, and two of them taken in both orders are CWE-833.

## Revision 53

A happens-before data-race detector for instrumented code (§4.5). Core tells the layer what orders tasks through a new optional seam hook (`task_sync`: spawn, wake, await), the sanitizer's atomic callbacks order what a mutex guards, and two unordered accesses to one address, one of them a store, are CWE-362.

## Revision 52 (security layer only)

Shadow memory for code built with the sanitizer's callbacks (§3.8): a write or read past an allocation's end and a use after free are findings at the access. The claim that Zig emits no load or store callbacks was wrong and is corrected (§3.6, `plan.md` E3, Open items).

## Revision 51 (core only)

The filesystem's reset rewrites only the pages a run took, which takes an empty run from 4.4 µs to 1.6 µs (`plan.md` §10); the evidence workflow's revision check is fixed after a local dry run.

## Revision 50 (benchmark and reports only)

The exhaustive search is benchmarked, which settles snapshot restore as a no-go; `rdtsc` trapping, vector clocks and shadow memory are reported (`plan.md` §9 M6, Open items).

## Revision 49 (core only)

Warm restore copies only the page slots in use; the flight recorder is reported as a no-go (`plan.md` §9 M5, M6).

## Revision 48 (core only)

`Options.trap_syscalls` fails a run whose code makes a real system call, on Linux x86_64 (`plan.md` §9 M6).

## Revision 47 (core only)

Warm starts from an in-process snapshot of what setup left, 5 to 32 times faster than re-running setup (`plan.md` §9 M5).

## Revision 46 (core only)

`tardis.atomic.Value`, atomics with store buffers under simulation (`plan.md` §9 M6).

## Revision 45 (core only)

`tardis.traceJson` writes a run as a Chrome trace for Perfetto (`plan.md` §9 M6).

## Revision 44

State merging in the exhaustive search. Core keeps, per node and per datagram inbox, a hash of what it has seen, and `ExhaustiveOptions.merge` stops extending an execution at a state another one already reached (§7.2); the repository gets a `README.md`.

## Revision 43

The Spectre-v1 gadget shape. After a marked bounds check, a load whose address follows the value an earlier, index-addressed load returned is CWE-1037, in instrumented C and in Zig code that names its loads (§6.3).

## Revision 42 (core only)

The fork server has a libc backend, for macOS and the BSDs (`plan.md` §9 M5).

## Revision 41 (core only)

The multi-core scaling question is settled by a process-versus-worker benchmark (`plan.md` §9 M5).

## Revision 40

Zig's edge counters guide exploration. In an instrumented build every edge a run ran is a coverage feature, so guided exploration gets through code that does no I/O (§7.1, `plan.md` §9 M3).

## Revision 39

Decisions in C are recorded for MC/DC through `tardis_sec_mcdc` and the `TARDIS_SEC_VECTOR` macros, in the same table as Zig's (§7.1); core gets fuzzy replay (`plan.md` §9 M3).

## Revision 38 (core only)

A timer heap and select-by-halving in the scheduler, decided by a new scaling benchmark (`plan.md` §4.2, §4.4).

## Revision 37 (core only)

The shrinker cuts chunks in draw order (`plan.md` §9 M3).

## Revision 36 (core only)

A guard page below every fiber stack (`plan.md` §4.1).

## Revision 35

Glitch sites without an `env`. `tardis_sec.criticalEql` wraps `std.crypto.timing_safe.eql`, and C marks a check with `TARDIS_SEC_CRITICAL(cond)`; both may be inverted as one skipped compare (§7.4).

## Revision 34

Partial-order reduction in the exhaustive search. Core logs what each scheduling step touches outside its node, and `ExhaustiveOptions.reduce` stops extending an execution that runs two commuting steps in the order the search also covers the other way: the 3-node vote model needs 3,073 executions instead of 9,216, with the same verdicts and the same set of outcomes (§7.2).

## Revision 33

Comparison feedback for Zig conditions. `mcdc.compare(a, op, b)` offers the value a condition compares against to guided exploration, so a campaign completes the MC/DC of a decision behind a 32-bit match; `mcdc.json` names, per gap, the vector to test next, or says that no test can show the condition; the header also wraps `execl`, `execlp`, `execle`, `posix_spawn` and `posix_spawnp` (§7.1, §5.2).

## Revision 32

C process starts. The header also wraps `popen`, `execv`, `execvp` and `execve`, and every C process start (with `system`) now goes through the same check as a simulated spawn, so it is CWE-272 from a sandbox without `allow_process_spawn`; the sink sums of the audit log are tested in one process, through the fork server and on four worker processes (§5.2).

## Revision 31

The taint sink audit log. Every taint check (path, command, format string, SQL) is counted per counted run, summed by the campaign (the fork server carries them too), and written with each distinct hit to `sinks.json` in the evidence bundle (§5.2, §7.5).

## Revision 30

Comparison feedback. Instrumented C's edges are coverage features for guided exploration, and the constants it compares against reach core's mutator through a new optional seam hook (`tokens`), so exploration gets past a 32-bit magic-number check in 25 iterations (§7.1).

## Revision 29

Memory access patterns for instrumented C. With `trace-loads` and `trace-stores`, the cache set of every C load and store (address bits 6–11) joins the dual-execution trace, so a table lookup indexed by a secret is a timing leak; both runs now read their inputs from one fixed buffer (§6.3).

## Revision 28

The tracer for instrumented C. `tardis_sec.exportCoverage()` provides clang's SanitizerCoverage callbacks; C built with `-fsanitize-coverage=trace-pc,trace-cmp,trace-div` adds its edges and divisor widths to the traces `assertConstantTime` and `assertNonInterference` compare, and keeps the constants it compares against (§6.3).

## Revision 27

The C shims. `src/sec/c/tardis_sec.h` wraps `printf`/`snprintf` (CWE-134), `system` (CWE-78), `sqlite3_prepare_v2`/`sqlite3_exec` (CWE-89) and `pthread_mutex_lock`/`unlock` (lock order, CWE-833) for C code linked into a test, which exports the functions they call with `tardis_sec.exportC()` (§5.2, §4.2).

## Revision 26

`enterSandbox` is enforced, and process spawns are a taint sink. Core reports `connect`, `listen`, `bind`, `std.process.spawn` and `replace` through a new seam hook (`capability`); after a node's `enterSandbox`, a capability its policy dropped, or a path outside its prefixes, is CWE-272, and received bytes in a spawn's argv are CWE-78 (§5.2).

## Revision 25

Redzones and the reuse FIFO in core's heap. Every allocation is followed by a 16-byte guard and every freed block waits in a 4,096-slot FIFO, with or without `tardis_sec`; the engine reports a changed guard at free (CWE-787) and guard bytes at egress (CWE-125) (§3.5).

## Revision 24

Lock call sites in core for file locks. Core reports `File.lock`, `unlock` and the close of a locked handle through a new seam 3 hook `file_lock`, and each locked file gets its own lock class, so plain programs get lock-order checks (§4.2).

## Revision 23

Ingress taint and the VFS path sink. Received network bytes are tainted by content until `markSanitized`; a path holding them when it is opened, created, deleted or renamed is CWE-22, through a new seam 3 hook `path` (§3.7, §5.2).

## Revision 22

Length desynchronization in flight. `Spec.desyncFrame(delta, fix_checksum)` is a `twoFaced` rewrite that changes a frame's length claim and keeps its bytes, so a shortened frame smuggles its tail past a parser that reads frames back to back (§4.4).

## Revision 21

The replay pool. `replayer(node, peers)` records the datagrams a node sends and delivers an old one again before a later one, through a new seam 3 hook `replay`; the recording outlives a peer's reboot (§4.4).

## Revision 20

A two-faced node's rewrite applies to its stream writes too, one segment at a time and keeping the length, through a new seam 3 hook `stream` (§4.4).

## Revision 19

A won check-to-use race can also replace the file with an empty directory (`vfs_toctou_swaps.directory`, off by default), which drives the program into its error path at the open (§4.4).

## Revision 18

A won check-to-use race can also swap in a hard link or replace the path's parent directory with a symlink; seam 3's `vfs_op` returns the kind of swap, and `vfs_toctou_swaps` chooses which (§4.3, §4.4).

## Revision 17

The NTFS and APFS name-confusion personas. Core's `windows_ntfs` drops trailing dots and spaces and `::$DATA` and answers to 8.3 short names; `macos_apfs` treats composed and decomposed Latin-1 letters as one name; `tardis_sec.pathConfusions` generates the confusable spellings of a name per persona (§4.3).

## Revision 16

Dead-edge lines can be justified in the source, with a `// tardis-deactivated: <reason>` comment; the bundle carries the reason, SARIF makes the line a note, and a justified line that ran is reported as stale (§7.1).

## Revision 15

Made the manifest count staged changes, read from git's object store (loose objects and packs with their deltas) without running `git` (§7.5).

## Revision 14

Added dead edges from Zig's `-ffuzz` counters. `zig build evidence -Dedges` builds the campaigns with edge counters, and each bundle lists the certified code its campaign never ran (§7.1).

## Revision 13

Made the manifest count tracked files changed since the index, read from `.git/index` (§7.5).

## Revision 12

Added certification through fork worker processes, which forward their children's security tallies to the main process (§7.5).

## Revision 11

Added seam 4's emitter. Core calls `campaign_end` when `check` returns, and `tardis_sec` writes a failed check's SARIF, located at the test's call (§2.1, §8.2).

## Revision 10

Added certification through the fork server. A forked child sends its run's security tallies back through seam 4's `fork_export`/`fork_import` (§2.1, §7.5).

## Revision 9

Made the manifest record the git revision of each named repository, read from `.git` without running `git` (§7.5).

## Revision 8

Added MC/DC per requirement and the dead-code list (§7.1, §7.5).

## Revision 7

Added certification campaigns on several workers and through the fork server, with evidence that does not depend on the worker count (§7.5).

## Revision 6

Added seam 4 (§2.1, §8.2): the shrinker keeps a security counterexample only while the same finding reproduces, and `TARDIS_SEC=1` attaches the layer to every `check` in a build.

## Revision 5 (week 16 of §8.7)

Added certification campaigns that never stop early, the persisted requirement registry, signed evidence bundles with an independent verifier, SARIF in CI, and Example 2 running (§2.4, §7.5, §7.6, §8.5).

## Revision 4

Added amplification, MC/DC and exhaustive exploration (§6.1, §7.1, §7.2).

## Revision 3

Pillars II–III (§4.4).

## Revision 2

The security seam in core (§2.2) and Pillar I by content tracking (§3.7).
