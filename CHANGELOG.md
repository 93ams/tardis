# Changelog

One entry per revision of the plans and the code, newest first. Section
numbers (§) are `plan2.md`'s unless an entry names `plan.md`. Revision 1
was the first draft of `plan2.md`; the core's earlier history is in
`plan.md` §9 and §14.

## Revision 87 (examples and documents: the history checkers' planted bugs, and four guides)

Two examples give the history checkers a planted bug each (`plan3.md` A5): `examples/lin_register.zig` (a compare-and-swap on a register in a file that is not atomic, caught by `tardis.lin`) and `examples/write_skew.zig` (a commit that validates only the rows it wrote, caught by `tardis.elle` as G2). Both are in the bug benchmark and in the measured table: found in 20 of 20 campaigns of 200 iterations, `lin_register` in 13 of 20 at 10. New documents: `docs/reproducing.md` (from a failed CI run to the same failure locally; the test workflow now keeps `test.log` of a failed job as an artifact), `docs/trace.md` (reading a run as a timeline), `docs/housekeeping.md` (the build caches and a full drive), `docs/threads.md` (the decision on `std.Thread`: outside the simulation, not mapped; what to use, and what the trap catches). Issue templates, and a draft code of conduct for the owner to accept or change. An adversarial review of revisions 86 and 87 found six issues (`plan.md` §9.2), all fixed: `netInterfaceName` was a tenth-of-a-kind `unreachable` left reachable; copying a file was reported as two unmodelled calls the program never made; calls refused during `Options.setup` were lost on warm-started iterations; the option's comment said worker threads' setup is not trapped (it is); `docs/threads.md` showed a clean report for a started thread where a crash is likelier; and several statements in the new guides did not match the code.

## Revision 86 (core: refused calls are named, the trap in CI, network buffers on first use)

An `std.Io` operation the simulator does not model was answered by `std.Io.failing` with std's own error, and nothing said that the simulator had refused it or which call it was (`plan3.md` D1). Each such entry is now wrapped, but for five whose answer from std is a fine one or leads std to a simulated fallback (copying a file): the run remembers the names (`Env.refusedCalls`), and a failure report lists them. Twelve of the entries are `unreachable` in `std.Io.failing`, undefined behaviour in a release build; three of them a program can reach by asking about a terminal (`File.isTty`, `supportsAnsiEscapeCodes`, `enableAnsiEscapeCodes`), and these are now answered (no simulated file is a terminal). The other nine (`lockStderr`, `unlockStderr`, `netInterfaceName`, and the memory-map and child calls that need an earlier call to have succeeded) panic by name; that list is kept by hand. `Options.trap_syscalls` is now optional: left out, `TARDIS_TRAP_SYSCALLS=1` decides; `false` keeps a check untrapped whatever the environment says. With that the whole suite passes on Linux with the variable set (the filesystem differential test, which calls the real filesystem on purpose, opts out), and the first test step of the test workflow sets it (D3; the `-Dsec` and optimized steps have not been tried with it). The network's receive buffers (1 MiB with the default limits) are allocated when a run first opens a socket: a default simulator takes 1.4 MiB, from 2.4 MiB (E3). `zig build membench` has a row for 32 nodes, the most there can be (37.6 MiB).

## Revision 85 (release: a release command, the API reference, measured oracles)

`scripts/release.sh <version>` is a release in one command (`plan3.md` B7): it requires a clean tree, sets the version in `build.zig.zon`, runs the full verification, the bug benchmark, the benchmark budgets and the API reference build, writes the release notes from the CHANGELOG entries since the last release tag, commits and makes the annotated tag. It never pushes; `--dry-run` stops before the commit. `zig build docs` builds the API reference into `zig-out/docs` (C4), and `scripts/doc_check.py` lists public declarations without a doc comment in `src/root.zig` and the files a test author uses through it (`check/lin.zig`, `check/elle.zig`, `check/ledger.zig`, `search/fuzz.zig`, `sim/atomic.zig`): 76 were missing and are written, and CI runs both. `zig build bugbench-rates` prints which oracle catches each planted bug and in how many of 20 campaigns, at 10, 50 and 200 iterations (A5, `docs/measurements.md`); it fails if a campaign of 200 misses one. Two new examples give the determinism check and `sometimes` a planted bug each: `examples/hidden_state.zig` (a number kept in a global) and `examples/never_retried.zig` (a retry written against the wrong error). The non-determinism message now respects `Options.report`. An adversarial review of revisions 83 to 85 found twelve issues (`plan.md` §9.2); fixed, among others: a task that span while another was runnable was never stopped when no preemption was drawn, which hung the shrinker; a watch armed in `Options.setup` was lost on warm-started iterations; `tardis.elle` passed a history whose every cycle was longer than 16 transactions as serializable (now reported, `Report.cycle_too_long`); `env.fuzz` of `f80` or `f128` did not compile; and the release script could leave the version staged after a failed commit and took a mistyped option for a real release.

## Revision 84 (core: presets, and memory per simulator)

`Options.quick`, `.thorough` and `.nightly` are the defaults with a campaign of 20, 1,000 and 10,000 iterations (the last one guided), so a test can pass `.quick` as its whole options; `TARDIS_PRESET=quick|thorough|nightly` sizes every check whose `iterations` is the default 100 (written out or not; it cannot tell) and leaves the others alone (`plan3.md` C7). `zig build membench` prints the memory one simulator takes by option (E3, `docs/measurements.md`). The filesystem's page pool, 8 MiB per node allocated at the start, is now allocated in chunks of 256 KiB as runs first need them: the defaults go from 10.2 MiB to 2.4 MiB and eight nodes from 72.6 MiB to 10.6 MiB. Running out of host memory while growing a simulated disk panics; it is not reported to the program under test as a full disk.

## Revision 83 (core: liveness)

`Env.expectProgress(name, bound)` watches for a run that stays busy without getting anywhere (`plan3.md` F5): the run must call `Env.progress(name)` within the bound's virtual time and within its number of steps, or it fails with `error.Livelock`, at the point the bound runs out, replayable and shrunk like a deadlock. Before this such a run never ended. Steps are simulated operations (every point where the simulator may switch tasks) and scheduling points, so tasks that spin without sleeping are found although virtual time stands still, whether or not a preemption is drawn. Up to eight watches per run; `progressDone` ends one. `examples/livelock.zig` is the benchmark's case: two transfers that back off for the same time and retry in step (found in 19 of 20 campaigns of 10 iterations, shrunk to one decision). Limits: a task that loops without any simulated operation is not seen, and `sim`'s loop form does not watch. A deadlock or a livelock in a forked iteration (`Options.fork`) is now reported by the child as a failed run; before, the child returned through the parent's driver and went on as a second copy of the test process (the deadlock case is older than this revision).

## Revision 82 (core: non-blocking sockets and poll)

System-call mode emulates non-blocking sockets (`SOCK_NONBLOCK`, `accept4`'s flag, `fcntl(F_SETFL, O_NONBLOCK)`, `MSG_DONTWAIT`) and `poll` and `ppoll` (`plan.md` §9.2): a call that would wait fails with `EAGAIN`, a non-blocking `connect` says `EINPROGRESS` and leaves a failure for `SO_ERROR`, and `poll` gives Linux's events and waits in virtual time. The differential test covers them, and found ten more differences, fixed: among them a failed non-blocking `connect` leaving the socket shut down both ways and still "connecting" (`listen` refused; `shutdown` makes every later `connect` fail with `EINVAL`), UDP's `SHUT_RD` looked at only by a read that would wait, a successful `connect` keeping a `shutdown` recorded before it, and a UDP socket that connects again dropping what its old filter refused. `select` and `epoll` stay stray; `epoll` is now the tests' example of a call that is not emulated. An adversarial review of revisions 80 to 82 found thirteen issues (`plan.md` §9.2); ten are fixed, among them a `poll` or read on a datagram socket that a `shutdown` did not wake, a listener that lost its port when shut down with a connection open, a bound socket's slot reused during its `connect`, and corpus files shared by two checks of one test; three are documented. Finding a check's default corpus file name hung on Linux (the symbol lookup must use `std.debug`'s own I/O, as `sec/edges.zig` does); found by the Linux run.

## Revision 81 (core: the sockets against the kernel)

A differential test runs random sequences of socket calls in the simulator and on the kernel over loopback and compares every result (`src/tests/sysnet_diff_test.zig`, `plan.md` §9.2); 20,000 agree, the suite runs 5,000. It found twenty-odd differences from Linux, fixed in the emulator and the network model: ICMP port unreachable reported to a connected UDP socket, datagrams kept across a UDP `connect`, loopback source addresses, a stream `bind` that reserves its port (`Net` gains a bound state, `Sim.bindStream`, `listenBound`, `connectFrom`), the port and address a failed `connect` leaves, `shutdown` of unconnected sockets and of listeners, the errors of `accept`, `connect` and `send` in the wrong state, how a reset shows in `SO_ERROR` and `getpeername`, and data for a peer that shut down both ways resetting the connection (a model change that also applies to `env.io`). TCP's simultaneous open is not modelled.

## Revision 80 (core: a corpus kept between campaigns)

`Options.corpus_dir` (`TARDIS_CORPUS_DIR` in tests) keeps a file per `check` (`src/search/persist.zig`, `plan3.md` E4): the runs that failed, which the next campaign runs first until they pass, and the guided explorer's corpus, comparison constants and coverage. Named after the calling test and a hash of the options that shape the runs (`Options.corpus_name` overrides), written whole and renamed into place, checked by a hash. `TARDIS_EXPLORE=guided` turns guided exploration on for every check; the nightly workflow sets both. Campaigns of 300 iterations that keep the corpus open the five-digit lock in the 24th; starting empty, none does (`src/tests/corpus_test.zig`).

## Revision 79 (core: sockets in system-call mode)

System-call mode answers the socket calls of blocking IPv4 stream and datagram sockets from the simulated network (`src/sim/sysnet.zig`, `plan.md` §9.2), so a C library's network code meets the same latency, partitions, resets and crashes as `env.io` code. Non-blocking sockets, `poll` and `epoll`, `sendmsg` and `recvmsg`, and Unix-domain sockets stay stray; IPv6 fails with `EAFNOSUPPORT`. Tested with a TCP echo, datagrams and the error cases, all by system calls; writing them found two bugs in the first version (a short simulated write returned as a short `send`; `accept` choosing its slot before it waited), both fixed. The tests that used `socket` as their example of a call that is not emulated now use a Unix-domain socket. An adversarial review of revisions 75 to 79 found thirteen issues, fixed (`plan.md` §9.2): among them a real fault inside the vDSO that looped forever, glibc's vDSO `getrandom` going unanswered, a pointer argument taken for a socket descriptor, `shutdown` of a listener not waking `accept`, no `EPIPE`, a short stream `writev`, and the note on C state left behind firing for every server's parked daemon.

## Revision 78 (core: the vDSO, and C state a run leaves behind)

System-call mode answers the clock reads libc makes through the vDSO (`plan.md` §9.2), which are not system calls and so returned the host's time unreported. During a run the vDSO's code is `PROT_NONE`; a call into it faults, and the SIGSEGV handler of `tsc.zig` answers it as the matching system call and returns to the caller (`src/sim/vdso.zig`). Other threads and the harness get the kernel's answer; a thread caught inside the vDSO when a run begins makes the run fail with `StraySyscall`. Tested with `std.os.linux.clock_gettime`, and SQLite (musl's vDSO path) still passes. Also: a task dropped inside an emulated system call, where a C library may hold a lock, is noted with its seed, and later failure reports name that run as the likely cause when a failure does not replay (`tardis.droppedInCallSeed`). A report, not a cure.

## Revision 77 (release: the campaign workflow)

The campaign workflow does more of `plan3.md` I1. Each system's job splits the log into one report per failure, the way `tardis scan` reads it: the test, the error, the persona and seed, the last events of the trace and the replay line. It keeps them with the whole log, the replay tokens and a `failures.json` as the artifact `campaign-<os>`, and writes a table of the failures to the run's summary. A last job, the only one with `issues: write`, opens one issue per failure key (the test's name and its error, hashed into a marker in the issue's body), or comments on the open issue with that key; it labels them `tardis-campaign`, opens at most ten per run, and keeps any `@` from notifying anyone. It runs on this repository's nightly schedule and, when called from another repository or run by hand, only if `open_issues` is true. Each system restores and saves a directory in the Actions cache, named in `TARDIS_CORPUS_DIR`, with the history of the runs and the failures seen with their tokens. The file did not parse as YAML before: a `run:` line held `tardis: (`, and is now a block. Verified locally: every workflow parses; the two scripts ran under Node on a sample log and against a stubbed GitHub API, and found both failures with their names and tokens, marked them seen on a second run, commented on the open issue, opened a new one for the other key, and ignored a pull request with the same marker. Not done: the library does not read or write the corpus directory, so the guided explorer still starts empty each night (`plan3.md` E4); the workflow has not run on GitHub, so the cache, the artifacts and the issues are untried there.

## Revision 76 (core: C locks in system-call mode)

System-call mode answers `futex` (`plan.md` §9.2). Before, a C library that held a pthread mutex across an emulated call, with a second task waiting for the same mutex, put the one thread every fiber shares into a real `futex` wait, and the run hung with no report; revision 75 documented it and restricted C libraries to one task. Now a wait blocks only the calling task, on the simulator's futex for that address, a wake wakes simulated waiters, and a timed wait times out in virtual time; a deadlock between C locks is the simulator's reported deadlock. `FUTEX_WAIT`, `FUTEX_WAKE`, their bitset forms, `FUTEX_REQUEUE` and `FUTEX_CMP_REQUEUE` are emulated; priority inheritance and `FUTEX_WAKE_OP` stay stray. Tested by a three-state mutex held across file calls by two tasks, and by SQLite driven from two tasks with a database each; both hung before the change. A review found a lost wakeup (a timed wait reported a timeout after a wake had picked it, when its deadline had also passed) and a spent cancel; both are fixed. Still limits: a recursive mutex is owned by the thread, so it does not exclude a second task (share no SQLite connection between tasks); a C lock left held by a dropped task stays held into the next run, which reports a deadlock its seed alone does not reproduce; a lock shared with another real thread is outside the simulation.

## Revision 75 (core: a second mode)

System-call mode: `Options.mode = .syscalls` beside the default `.std_io` (`plan3.md` D9, `plan.md` §9.2). Linux on x86_64. The stray-call trap now answers the file calls, clock reads, sleeps and `getrandom` of the code under test from the simulation, by translating each into the simulator's own `std.Io` operation, so code that never sees an `Io` (direct `std.os.linux` calls, a C library) runs inside a run and meets a crash exactly as `env.dir` writes do. A simulated descriptor is a VFS handle with bit 30 set; a sleeping call yields its fiber from inside the signal handler. Verified: a differential test against the real kernel (20,000 random sequences of file calls agree; it found four differences, fixed); the same program by system call and by `std.Io` gives one trace hash and one result after a power loss; `examples/syscall_rename.zig`, the twenty-first program of the bug benchmark; and SQLite 3.46.0 built with its own VFS (`zig build test-sqlite -Dsqlite`), where a planted `synchronous=OFF` is found and shrunk to one decision and the documented gap of `synchronous=FULL` (a lost unlink of the journal rolls back a commit) to two. Not done: sockets, and clock reads that libc answers through the vDSO. Elsewhere the mode returns `error.SyscallModeUnsupported`. An adversarial review led to fixes: a stray is refused, never made for real, and fails a run whatever its result; libc's terminal checks are allowed; the processor count is one; open-file-description locks are not emulated; three open-flag cases now match Linux. It also found that a C library holding a pthread mutex across an emulated call can hang a run with several tasks: system-call mode supports C libraries driven from one task (`plan.md` §9.2).

## Revision 74 (core and CI)

The first CI logs read. On macOS (Apple Silicon, real APFS) and Windows every test passes but the filesystem differential test. Two differences it found on APFS are fixed for the `macos_apfs` persona: a hard link of a directory is refused before the destination is looked at, and a stat through a regular file is not found. The test can keep the sequence in progress in a file (`TARDIS_DIFF_TRACE`), since a real call that panics inside std takes the process with it, as one did on the Windows runner. First use on another of the owner's projects: a missing directory sync in `tigershark`'s checkpoint journal (`plan3.md` F3).

## Revision 73 (documents and CI)

The licence: BSD Zero Clause (0BSD). A draft report of the Windows register problem for the Zig project, unsent (`docs/disclosures/`). The test workflow publishes its failing lines as annotations; the campaign workflow's inputs are simplified after GitHub rejected the file. The plans record the first CI results on the current code: the evidence workflow and the Ubuntu tests pass, Windows and macOS fail in the test step.

## Revision 72 (core only)

The defect recorded in revision 71 is found and fixed: on 64-bit Windows a fiber switch did not preserve `xmm6` to `xmm15`, which a callee must. `std.Io.fiber.contextSwitch` names them as clobbered, and the compiler does not save them for the caller, so a value an optimized caller kept in one came back as another fiber's. `fiber.switchTo` saves and restores them; a test fills them from another fiber and fails without the fix. The skipped example test runs again.

## Revision 71 (examples only; one open defect recorded)

Four more examples in the bug benchmark, twenty in all, the first over the network besides `replica`: `udp_retry` (a retry applied twice), `udp_order` (trusting the order of arrival), `udp_no_timeout` (waiting for ever for a lost message) and `stale_read` (a stale read from a follower). Writing `udp_no_timeout` found a crash of the simulator on Windows in ReleaseFast after a deadlock with tasks waiting for datagrams; its cause is not established, the test is skipped in that configuration, and `plan.md` records what is known.

## Revision 70 (examples only)

Four more examples in the bug benchmark, sixteen in all: `in_place_rewrite`, `index_before_data` (two files made durable in the wrong order), `id_reuse` (an identifier handed out twice after a restart) and `short_read`.

## Revision 69 (documents only)

`docs/qualification.md`: the core's requirements traced to their tests, its known limits, the ways a wrong pass could happen and their guards, and the configurations the suite has passed on (`plan3.md` G5).

## Revision 68 (examples only)

Four more examples in the bug benchmark, twelve in all: `rename_unsynced` (renamed before the data is durable), `check_then_act`, `oom_partial` (a half-finished update when memory runs out) and `lease` (a duration measured with the wall clock).

## Revision 67 (examples only)

Four more examples in the bug benchmark: `dir_sync` (a missing fsync of a directory), `deadlock` (lock order), `short_write` (a short write taken for a whole one) and `error_leak` (a handle leaked on an error path). An example can name its own campaign options.

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
