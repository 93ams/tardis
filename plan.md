# TARDIS: Architecture & Engineering Specification

**Time-And-Relative-Determinism In Simulation: deterministic simulation testing for Zig `std.Io` programs**

| | |
|---|---|
| **Status** | Milestone 1 implemented; Milestone 2 implemented (virtual TCP and UDP, batch operations, multi-node with per-node heaps, partitions, node crashes, DNS, clock drift, directory listing, file locks, hard links, symlinks, six personas); M3 shrinking (decisions and their values, under `check` and `sim`), replay tokens and coverage-guided exploration implemented; M4 complete (linearizability and Elle-style list-append and register checkers, chaos with an automatic heal schedule and liveness checks, cost ledger); M5 partly implemented (multi-core campaigns including guided exploration, warm starts with a Linux fork server, benchmarks); M6 is research. |
| **Toolchain** | Zig `0.17.0` (pinned in `build.zig.zon`). Track `0.18-dev` on a branch only. |
| **Host support (M1)** | Fiber backend: `x86_64` (System V and Windows), `aarch64`, `riscv64`. This is the set `std.Io.fiber` supports. |
| **Revision** | v2. Rewrites the v1 draft. §12 lists every v1 claim that was changed or dropped, and why. |

---

## 0. Summary

TARDIS is a library that gives a program under test (the **SUT**) a `std.Io` whose every observable effect is decided by a seed. Effects include task interleavings, clock readings, random bytes, file contents after a crash, injected I/O errors, and short reads and writes. Running the same seed with the same binary and the same options replays the same execution, bit for bit. A failing run prints a one-line replay command.

Zig 0.17 routes concurrency, time, randomness, filesystem and network access through the `std.Io` interface. That makes the classic FoundationDB/TigerBeetle simulation approach (*inject the world as a dependency*) available to ordinary Zig code without a custom harness. TARDIS supplies that world.

```zig
test "WAL survives power loss" {
    try tardis.check(std.testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            var wal = try Wal.open(env.io, env.dir, "events.wal");
            try wal.append(env.io, try env.fuzz([]const u8));
            try wal.sync(env.io);
            try env.crashAndReboot(.power_loss);       // unsynced sectors may tear
            var recovered = try Wal.open(env.io, env.dir, "events.wal");
            defer recovered.close(env.io);
            try recovered.verify(env.io);
        }
    }.run, .{ .iterations = 200, .personas = &.{ .linux_ext4, .linux_xfs, .windows_ntfs } });
}
```

### 0.1 Design principles

1. **Ship the 80% that is cheap first.** Most of DST's value comes from a deterministic scheduler, a virtual clock, a crash-consistent fake disk and fault injection. Hypervisor-grade interposition comes after that core is trusted, and only where measurements justify it.
2. **Determinism is the product.** Every feature has to keep the determinism contract (§3). A feature that cannot keep it does not ship.
3. **Re-execution before snapshots.** Replaying from the seed is always correct. Snapshot/fork acceleration (M5) is an optimization that must produce the same trace hash as re-execution.
4. **TigerStyle where it buys safety.** Bounded resources, assertions on state boundaries, explicit units, no recursion in TARDIS runtime code. The pragmatic exceptions are listed in §2.3.
5. **No unverifiable performance claims.** Each performance target has a benchmark (§10) and is stated as a target until the benchmark exists.

---

## 1. Goals, Non-Goals, Success Criteria

### 1.1 Goals

| # | Goal | Milestone |
|---|------|-----------|
| G1 | Deterministic `std.Io` implementation: tasks, futex, cancellation, groups, clocks, randomness, files and directories | M1 |
| G2 | Crash-consistency testing: power loss with torn sectors, journal-prefix metadata loss, and per-filesystem quirks ("personas") | M1 |
| G3 | Fault injection: targeted (*fail the Nth write*) and probabilistic, with swarm testing (a random subset of fault classes per run), OOM, and short I/O | M1 |
| G4 | Low-ceremony API: `tardis.check` (one call), `tardis.sim` (a plain `while` loop), and `env.fuzz(T)` for structured inputs | M1 |
| G5 | Replay and diagnostics: replay seed on failure, recent-event trace, determinism self-check, leak detection | M1 |
| G6 | Virtual network and multi-node clusters with partitions and node crashes | M2 |
| G7 | Guided exploration: decision-addressed mutation, coverage feedback, shrinking | M3 |
| G8 | Correctness oracles: linearizability (Porcupine-style) and transactional anomalies (Elle-style) | M4 |
| G9 | Throughput: snapshot/fork of warm state, multi-core campaigns | M5 |
| G10 | Legacy and C interposition, weak-memory model checking | M6 (research) |

### 1.2 Non-Goals

- **Preemptive OS-thread simulation in M1–M5.** TARDIS controls interleavings at `std.Io` boundaries only (cooperative). Data races between two `std.Io` calls inside a single task are out of scope until M6.
- **Simulating code that bypasses `std.Io`** (direct `std.posix`, inline syscalls, `rdtsc`, C libraries) before M6. Such code still runs, but it runs non-deterministically. The determinism self-check (§7.4) is designed to surface the most common cases.
- **Bit-identical floating-point results across ISAs.** TARDIS's own runtime uses no floating point. SUT floating-point code is deterministic per host ISA, not across ISAs (§12, E7).
- **Being a hypervisor.** No VM, no kernel module, no ptrace.

### 1.3 Success criteria for M1 (all met in this revision)

1. `zig build test` passes on Windows x86_64 (192 library tests including M2–M5; four Linux-only tests skip, and one Windows-only test skips elsewhere; plus the `tardis` program's 6, the termancy suite's 7 (§9.1), and `tardis_sec`'s 120 over the security seam (`plan2.md` §3.7, §4.3, §4.4, §6.1, §7.1, §7.2, §7.5)) in Debug, ReleaseSafe, ReleaseFast and ReleaseSmall, and the same suite cross-compiled for `x86_64-linux-musl` passes all 192 (and the `tardis_sec` module's and Example 2's tests) on Linux (WSL2), including the golden trace hash recorded on Windows. macOS is not yet tested (§10).
2. Running the same `(seed, options)` twice produces identical trace hashes. The suite asserts this, `check()` re-verifies every Nth iteration, and a golden trace hash is identical across all four build modes.
3. The tests in `src/tests/` show:
   - (a) a lost acknowledged write under power loss;
   - (b) a torn "atomic" rename on `linux_xfs` that `linux_ext4` hides;
   - (c) a lost directory entry under `posix_strict`;
   - (d) an NTFS sharing violation;
   - (e) a lost-update race between tasks;
   - (f) a deadlock and an `async`-vs-`concurrent` misuse, both reported as errors rather than hangs;
   - (g) a swallowed I/O error exposed by fault injection;
   - (h) targeted Nth-operation error injection.
4. No heap allocation inside the simulator after `Sim.create`, except the SUT-visible arenas (`env.allocator` and fuzz scratch), which are budgeted and reset per boot. The one exception is a small temporary bitmap during crash garbage collection.

### 1.4 Success criteria for the M2 core (met)

1. Programs written against `std.Io.net` (`IpAddress.listen/connect`, `Server.accept`, `Stream.reader/writer`, `HostName.connect`) run unmodified on the virtual network.
2. `src/tests/net_test.zig` shows:
   - (a) a KV server that fsyncs file and directory before acknowledging keeps every acknowledged write across node power loss, on all four personas;
   - (b) the same server *without* the directory fsync is fine on `linux_ext4` but loses writes under `posix_strict` (found);
   - (c) a group-commit server that acknowledges before its background fsync loses acknowledged writes (found);
   - (d) partitions time out `connect` and hold in-flight bytes until the link heals;
   - (e) a crashed peer shows up as either `ConnectionResetByPeer` or `ConnectionTimedOut` (both outcomes are asserted reachable);
   - (f) virtual DNS, socket leak detection, daemon failure propagation, per-node clock drift and NTP steps.
3. `src/tests/dir_lock_test.zig` shows randomized readdir order catching order-dependent code, and exclusive locks serializing read-modify-write, with Windows locks mandatory and POSIX locks advisory.
4. The determinism self-check passes on every multi-node test, and the M1 golden trace hash is unchanged (M2 adds Decider streams and fault classes without perturbing existing ones).
5. `src/tests/udp_test.zig` shows a retrying UDP request/response client surviving loss, duplication and reordering (each asserted reachable), code that assumes reliable in-order datagrams caught, `operateTimeout` (the `Batch` path) timing out a read, a partition outlasting the retransmit timeout failing a TCP connection with `ConnectionTimedOut`, and per-node heap leak checks.
6. `src/tests/link_test.zig` shows hard links sharing an inode, publish-by-`link()` that survives power loss on all six personas (and loses data without the temp-file fsync), symlink semantics (intermediate and final following, relative targets, `readLink`, no-follow `stat`, loops, dangling links), a symlink-swap deploy that is safe with fsync and caught without it even on ext4, APFS case folding, and ZFS never tearing writes that ext4 tears.

---

## 2. Architecture

### 2.1 Layers

```
+---------------------------------------------------------------------------+
| L6  ORACLES            assertSometimes/Always, leak checks (M1)           |
|                        Porcupine, Elle, SLO ledger (M4)                   |
+---------------------------------------------------------------------------+
| L5  EXPLORATION        seeded Decider + swarm masks + replay (M1)         |
|                        decision keys, mutation overlay, shrinker (M3)     |
+---------------------------------------------------------------------------+
| L4  SUT BOUNDARY       std.Io VTable implementation (M1)                  |
|                        std overlay / C shims / syscall traps (M6)         |
+---------------------------------------------------------------------------+
| L3  VIRTUAL KERNEL     VFS + personas + crash model (M1)                  |
|                        virtual network, DNS, multi-node (M2)              |
+---------------------------------------------------------------------------+
| L2  SCHEDULER          fibers, run queue, timers, futex, cancel (M1)      |
+---------------------------------------------------------------------------+
| L1  SUBSTRATE          fixed pools allocated at init (M1)                 |
|                        CoW snapshots / fork server (M5)                   |
+---------------------------------------------------------------------------+
```

The invariant is that **no SUT-visible value comes from the host**. Time, randomness, scheduling order, file contents, handle values and error codes all come from simulator state and the `Decider` (§5.1).

### 2.2 Module layout

```
src/
  root.zig          public API: check, sim, Env, Options, re-exports (the only file at the top)
  sim/              the simulator (L1, L2, L4, L5 keys)
    Sim.zig         simulator state + std.Io VTable implementation (L4)
    sched.zig       Task, RunQueue, timers, fiber switching (L2)
    fiber.zig       stack allocation, entry trampolines, Windows TIB bookkeeping (L2)
    alloc.zig       budgeted, OOM-injecting, leak-counting SUT allocator (L1)
    decide.zig      SplitMix64/Wyhash-based Decider, Ppm, swarm masks (L5)
    fault.zig       targeted + probabilistic fault plans, error-set casting (L5)
    trace.zig       rolling trace hash + bounded recent-event ring (L6)
    forkserver.zig  fork/pipe/wait primitives for warm starts (Linux syscalls) (L1, M5)
    sec_seam.zig    the hooks an optional security layer plugs into (plan2.md §2.2)
    sec_default.zig the layer every check gets by default: none, or tardis_sec under TARDIS_SEC=1 (plan2.md §8.2)
  model/            the simulated world (L3)
    vfs.zig         page pool, inodes, dentries, metadata journal, personas, crash, locks
    net.zig         virtual TCP/UDP: sockets, receive rings, segments, reachability matrix (M2)
  search/           how runs are chosen and reduced (L5)
    explore.zig     coverage map, corpus, mutation for guided exploration (M3)
    fuzz.zig        comptime structure-aware input generation
    shrink.zig      ddmin over decision overlays, value shrinking, replay tokens (M3)
  check/            oracles (L6)
    oracle.zig      assertSometimes / assertAlways catalog
    lin.zig         linearizability checker (Wing–Gong + memoization, per-key partitions) (M4)
    elle.zig        list-append and rw-register dependency graphs, Tarjan SCC, Adya cycle classification (M4)
    ledger.zig      deterministic latency histogram and ratios (M4)
  sec/              `tardis_sec`, its own module over the seam (plan2.md)
    root.zig engine.zig races.zig tests/
  cmd/              one directory per program
    tardis/main.zig the `tardis` program (termancy cli/term/sys), §9.1
    demo/main.zig   `zig build run` demo: one crash-consistency bug, four personas
    bench/main.zig  `zig build bench`: simulator throughput (ReleaseFast)
  tests/
    scheduler_test.zig    concurrency semantics via std.Io.Mutex/Queue/Group/Future
    fs_test.zig           filesystem semantics via std.Io.Dir/File
    bugs_test.zig         buggy programs TARDIS must catch, next to fixed versions
    determinism_test.zig  reproducibility + golden trace hash
    net_test.zig          M2: network, nodes, partitions, node crashes, DNS, clocks
    udp_test.zig          M2: datagrams, batch timeouts, partition timeouts, per-node heaps
    link_test.zig         M2: hard links, symlinks, macos_apfs and freebsd_zfs personas
    shrink_test.zig       M3: shrinking failures, replay tokens
    explore_test.zig      M3: guided vs random exploration
    lin_test.zig          M4: linearizability of a replicated KV store
    elle_test.zig         M4: transactional anomalies of list-append and register stores
    chaos_test.zig        M4: nemesis, heal, automatic chaos schedule, eventually; write amplification; latency SLO
    parallel_test.zig     M5: multi-core campaigns match one thread
    fork_test.zig         M5: warm starts and the fork server
    dir_lock_test.zig     M2: directory listing order, file locks
    atomic_test.zig       createFileAtomic / renamePreserve / copyFile, under power loss
test/termancy.zig       termancy's files and self-update code under TARDIS, §9.1 (needs termancy's modules, so outside the library)
```

### 2.3 TigerStyle profile

| Rule | M1 practice |
|------|-------------|
| Bound everything | Every pool has a `*_max` field in `Options.limits`. Exhausting one returns the OS-equivalent error (`error.SystemResources`, `error.NoSpaceLeft`, `error.ProcessFdQuotaExceeded`, `error.ConcurrencyUnavailable`), never UB. |
| No allocation after init | All simulator state (task table, fiber stacks, page pool, inode/dentry tables, journal, trace ring) is allocated in `Sim.create`. **Exceptions:** `env.allocator` (SUT heap) and fuzz scratch are arenas. Their capacity is retained across iterations, so a warm campaign stops calling the backing allocator. |
| No recursion | Runtime code is iterative. `fuzz.generate` is comptime-specialized per `(T, depth)` with `depth_max = 8`, so its call graph is a bounded DAG, not runtime recursion. |
| Explicit units | `_ns`, `_bytes`, `_ppm`, `_max`, `_count` suffixes. Probabilities are `Ppm = u32` (parts per million). |
| Fixed-width types | `u64` for time and sizes in simulator state. `usize` appears only where the `std.Io` interface requires it. |
| Paired assertions | State transitions assert pre- and post-conditions. Compile-time size assertions on hot structs. |
| Fail loudly | A fiber stack overflow faults on the guard page below the stack, at the overflowing instruction; where the host cannot protect pages, a canary checked on every switch reports it as a panic. |

---

## 3. The Determinism Contract

**Definition.** A run is a function `Run(binary, options, seed) -> (outcome, trace_hash)`. TARDIS guarantees that this function is pure as long as the SUT performs all effects through `env.io` / `env.allocator`, and does not branch on pointer addresses or host state.

**Trace hash.** A rolling Wyhash over every simulator-visible event `(virtual_ns, task_id, event_kind, args…)`, where args are sizes, offsets, error codes and content hashes, never host pointers. `trace.zig` defines the encoding. It is stable within a TARDIS version and versioned in the replay token.

**Sources of non-determinism and how each is handled:**

| Source | Handling |
|--------|----------|
| Task interleaving | Only the scheduler switches tasks, and only at `std.Io` calls. Every choice comes from the `Decider`. |
| Time | Virtual clocks. `now()` never reads the host. Time advances only through sleeps, timeouts and modeled I/O latency. |
| Randomness | `random` / `randomSecure` draw from a dedicated Decider stream, so adding a `random()` call does not shift scheduling decisions (stream separation, §5.1). |
| Handle values | Encoded from `(boot_epoch, slot)`, so they are identical across hosts. |
| Pointer values | Not hashed by TARDIS. SUT code that hashes pointers into observable behavior is a determinism bug. The self-check (§7.4) catches it when the address varies between runs. |
| Host allocator | SUT memory comes from `env.allocator`. Its OOM decisions come from the Decider, never from real exhaustion (real exhaustion is reported as a TARDIS budget error). Every block is followed by a 16-byte guard, and a freed block waits in a 4,096-slot FIFO before it can be reused, in every build, so `tardis_sec` changes no address (`plan2.md` §3.5). |
| Bypassing `std.Io` | Not caught until M6. The self-check surfaces it opportunistically. |

**Cross-host guarantee (M1).** Simulator decisions use only integer arithmetic and a self-implemented PRNG (no dependence on `std.Random` algorithm changes). As a result, the decision sequence for a seed is identical across OSes and ISAs. A whole run is identical across hosts if the SUT's own computation is, which holds for typical integer-only systems code.

---

## 4. L2: Scheduler

### 4.1 Tasks and fibers

- **Task 0** is the *root task*. It runs on the host thread's own stack: the test body under `tardis.sim`, or the driver loop under `tardis.check`.
- **Tasks 1..`tasks_max`** run on fibers. Stacks are allocated once in `Sim.create` (`fiber_stack_bytes`, default 256 KiB). Each stack has an inaccessible guard page below it (`fiber.Stacks`: one page-aligned mapping, `VirtualProtect`/`mprotect` per guard), so an overflow faults at once instead of writing into the next task's stack; the test checks the protection on Windows and that a write into the guard kills a forked child on Linux. A 64-byte canary at the low end of each stack is still verified whenever that task switches away. A trampled canary panics with the task id and seed.
- Context switching uses `std.Io.fiber.contextSwitch` (saves `sp`, `fp`, `pc`; the inline asm clobber list forces the compiler to spill everything else). TARDIS supplies its own naked entry trampoline per ABI:
  - **Windows x64:** at entry `rsp ≡ 8 (mod 16)`, with 32 bytes of shadow space reserved above the fake return address. On each switch, `NT_TIB.StackBase` / `StackLimit` are updated so `__chkstk` probing and stack walkers see the fiber's bounds.
  - **System V x64 / AArch64 / RISC-V 64:** standard entry alignment; a zeroed frame pointer terminates unwinding.
- No dedicated scheduler fiber: the blocking task picks a successor and switches to it directly (one switch per handoff).
- A finished task's slot returns to the free list *before* its final switch. This is safe because a slot is only reused by a spawn, and a spawn runs on a different, live stack.

### 4.2 Run queue

`RunQueue` is a bitset of `ceil(tasks_max/64)` `u64` words plus a population count.

- `insert` and `remove` are O(1).
- `pickNth(rank)` walks the words subtracting `@popCount` per word, then selects within one word by halving (`selectBit`: six popcounts, portable, no BMI2). Cost is O(words) with words ≤ 4 at the default limits. Until the scheduler benchmark (§9 M2) it cleared the lowest set bit `rank` times, 32 times on average in a full word.
- Scheduling choice: `rank = decider.uniform(.schedule, count)`.

The v1 "RunQueue512 in one cache line with BMI2 `pdep`" design is not needed: `selectBit` does the same without a CPU feature.

### 4.3 Scheduling points and preemption

Every `std.Io` call is a scheduling point. At each point the Decider picks between:

- **continue** with probability `1 - preempt_ppm` (default 25%), or
- **yield** to a uniformly chosen runnable task, which may be the current one.

Blocking operations (sleep, futex wait, await, group await) always switch. When the run queue is empty:

1. If any task has a pending deadline, advance the clock to the earliest one (ties broken by lowest task id) and make every task with that deadline runnable.
2. Otherwise this is a **deadlock**. Under `check`, the driver gets `error.Deadlock` and a dump of the blocked tasks. Under `sim`, the run panics with the same dump and the replay seed, because the blocked frame is user code and cannot carry an error.

### 4.4 Timers

Each task has at most one pending deadline (a task blocks on one thing at a time), held in `timers[id]`. The earliest is the top of a binary min-heap of (deadline, task), ordered by deadline and then task id. An entry is pushed when a task blocks with a deadline and is never removed in place: one whose deadline is no longer its task's (the task was woken, blocked again, or freed) is stale and is dropped when it reaches the top. The heap holds four entries per task and is rebuilt from `timers` when it fills. Waking order does not matter (the run queue is a set), so the heap changes no trace hash: the golden hash still matches.

M1 scanned every task at every reschedule, twice when nothing was runnable. The scheduler benchmark showed that cost (§9 M2), and the heap replaced it. A heap fits "one deadline per task" better than the v1 4-level timing wheel, which stays unbuilt until per-packet network timers exist.

### 4.5 `std.Io` concurrency semantics

| VTable entry | Simulation semantics |
|--------------|----------------------|
| `async` | The Decider chooses **inline** (run now, return `null`; probability `async_inline_ppm`, default 20%) or **spawn**. Inline execution is legal per `std.Io` and exposes code that wrongly assumes `async` gives concurrency (it deadlocks, and TARDIS reports it). Falls back to inline if the pool is exhausted or the context or result is larger than the per-task buffer (`task_context_bytes`, default 1 KiB). |
| `concurrent` | Always spawns. Returns `error.ConcurrencyUnavailable` when the pool is exhausted. |
| `await` | Blocks until the target finishes, copies the result out, then frees the slot. |
| `cancel` | Sets `cancel_requested` on the target. If the target is blocked at a cancelation point it is woken, then awaited. |
| `groupAsync` / `groupConcurrent` | Like `async` / `concurrent`. `Group.token` holds a non-null marker while `Group.state` (pending count) > 0. |
| `groupAwait` | Blocks until pending = 0. A cancel received while waiting propagates to every member, waiting continues, and the call returns `error.Canceled`. |
| `groupCancel` | Requests cancel on all members, then waits without being cancelable. |
| `checkCancel` / `recancel` / `swapCancelProtection` | Per-task `cancel_requested` and `cancel_protection`. A cancelation point consumes the request (only the next point observes it), and `recancel` re-arms it. |
| `futexWait` | If `*ptr != expected`, returns immediately. Otherwise blocks on `ptr` with an optional deadline. With probability `spurious_wakeup_ppm` (a fault class) it returns early without a wake, which the futex contract allows. |
| `futexWake` | Wakes up to `max_waiters` tasks blocked on `ptr`, chosen in Decider order rather than FIFO. |
| `sleep` | Blocks until the deadline. `.none` blocks forever (until canceled). |
| `now` | `.real`: `epoch_offset_ns + virtual_ns`. Every other clock: `virtual_ns`. |
| `clockResolution` | 1 ns. |
| `random` | Decider stream `.random`. |
| `randomSecure` | Same as `random`. Simulated bytes are not secure, by design. |

---

## 5. L5 (M1 part): Decider, Faults, Swarm, Fuzz

### 5.1 Decider

```zig
pub const Stream = enum(u8) { schedule, fault, crash, latency, random, fuzz, alloc, swarm };
```

Each stream is an independent SplitMix64 generator seeded with `wyhash(run_seed, stream_tag)`. Stream separation is cheap edit-resilience: adding a fuzz draw does not perturb scheduling, and adding a `random()` call does not perturb faults. This is a deliberate down-payment on the M3 decision-key design (§9.3).

- `chance(stream, ppm) bool`: `next() % 1_000_000 < ppm`.
- `uniform(stream, n) u64`: Lemire's multiply-shift reduction (unbiased enough for testing; exact rejection is not needed).
- Seeds: `run_seed = splitmix(campaign_seed +% iteration_index *% golden_gamma)`, mixed with the persona index.

### 5.2 Fault model

```zig
pub const FaultClass = enum { io_error, short_io, latency, spurious_wakeup, oom, torn_write, metadata_loss };
```

| Mechanism | API | Notes |
|-----------|-----|-------|
| Targeted | `env.injectIoErrorAfter(.write, 2, error.NoSpaceLeft)` | One-shot: the 3rd matching op fails. The op kinds are `open`, `read`, `write`, `sync`, `metadata`, `any`. The error is converted at comptime into the operation's error set. If the error set lacks it, `InputOutput` is used, then `Unexpected`. |
| Probabilistic | `Options.faults.io_error_ppm`, … | Applied per eligible operation (read, write, sync). Defaults: `io_error_ppm = 0`, `short_io_ppm = 200_000`, `spurious_wakeup_ppm = 50_000`, latency 1–100 µs, torn writes and metadata loss on. |
| Short I/O | `short_io_ppm` | Reads and writes transfer `1..n-1` bytes. `std.Io.Reader`/`Writer` loops must cope. The caller's buffer is never shrunk. |
| Latency | `io_latency_min_ns..max_ns` | Every file op sleeps a Decider-chosen latency, so time advances and interleavings change. |
| Swarm testing | `Options.swarm = true` (default) | Each iteration disables each fault class independently with p = 1/2 (Groce et al., 2012). Some runs go deep with few faults, others are fault-dense. |
| OOM | `faults.oom_ppm` | `env.allocator` returns `error.OutOfMemory`. |
| Crash | `env.crashAndReboot(mode)` | See §6.5. |

### 5.3 Structure-aware fuzz input

`env.fuzz(T)` and `tardis.fuzzInput(T, io)` generate values by comptime reflection:

- Integers: about 12% boundary values (`0`, `1`, `max`, `min`, `-1`), otherwise uniform.
- `bool`, `enum` (uniform over fields), `?T` (25% null), arrays, structs, `union(enum)` (uniform tag).
- Slices: length biased small (half ≤ 16), capped at `fuzz_slice_len_max` (default 1024). Allocated from the per-iteration fuzz arena and freed automatically.
- Floats: uniform bit patterns plus specials (±0, ±inf, NaN).
- A type that declares `pub fn tardisGenerate(g: *tardis.Generator) !T` controls its own generation.
- Depth is capped at `depth_max = 8`. Beyond it, optionals become `null`, slices become empty, and non-optional single pointers are a compile error.

---

## 6. L3: Virtual Filesystem and Personas

### 6.1 Storage model

- **Page pool:** `pages_max` × 4 KiB pages allocated at init, with a `u16` refcount each. Page 0 is the shared zero page and is never written.
- **Inode:** `{ kind, cur: Content, dur: Content, counters }`, where `Content = { pages: []u32 (fixed slot of file_pages_max), len_bytes: u64 }`.
  - `cur` is what reads observe (the page cache). `dur` is what survives power loss (the media).
  - `cur` and `dur` share pages copy-on-write. A write to a page with refcount > 1 allocates a new page. `fsync` makes `dur` point at `cur`'s pages: O(file pages), no data copy.
- **Dentries:** two fixed tables, `cur_dentries` and `dur_dentries`, each `{ parent, name[name_bytes_max], inode }`. Lookup is a linear scan (bounded by `dentries_max`, default 1024).
- **Metadata journal:** an ordered log of namespace operations not yet durable: `link`, `unlink`, `rename(replaced_existing)`. Each records its inode and both names. When it fills up, the whole log is committed, as a real journal forces a commit.
- **Counters per inode** (`cur_links`, `dur_links`, `journal_refs`, `open_count`) make freeing O(1). An inode and its pages are freed only when all four reach zero.
- **Handles:** a fixed table of `{ inode, epoch, pos, mode }`. `File.Handle` / `Dir.Handle` values encode `(epoch << 16) | (slot + 1)`, as a pointer on Windows and a positive `fd_t` on POSIX.
  - The epoch restarts at 1 every run and increments on every crash, so handle values are part of the deterministic trace.
  - `env.dir` is a reserved root handle that stays valid across crashes.
  - Any directory handle not in the table (for example `Dir.cwd()`) resolves to the root.
  - A handle from an earlier boot epoch returns `error.Unexpected`, and closing one is a silent no-op.

### 6.2 Operation coverage (M1)

`dirCreateFile`, `dirOpenFile`, `dirOpenDir`, `dirCreateDir`, `dirCreateDirPath`, `dirCreateDirPathOpen`, `dirStat`, `dirStatFile`, `dirAccess`, `dirDeleteFile`, `dirDeleteDir`, `dirRename`, `dirClose`, `fileStat`, `fileLength`, `fileClose`, `fileReadPositional`, `fileWritePositional`, `fileSeekBy`, `fileSeekTo`, `fileSync`, `fileSetLength`, and `operate(.file_read_streaming / .file_write_streaming)`.

Everything else falls through to `std.Io.failing`, which returns errors for fallible calls and panics for calls that "cannot happen". M2 added `dirRead` (iteration, in an order drawn per listing) and the lock family (`fileLock`, `fileTryLock`, `fileUnlock`, `fileDowngradeLock`; mandatory under `windows_ntfs`, advisory elsewhere). Symlinks (`dirSymLink`, `dirReadLink`, followed during path resolution up to 40 hops, then `error.SymLinkLoop`; `statFile(.{ .follow_symlinks = false })`) and hard links (`dirHardLink`, `fileHardLink`; directories refused) came last in M2. A symlink's target is written with its inode, so it is durable exactly when its name is. Still deferred: memory maps, timestamps, permissions, and process and stdio operations. §11 tracks the VTable coverage matrix.

### 6.3 Crash model

`power_loss`:

1. **Metadata.** *Journaled* personas (`linux_ext4`, `linux_xfs`, `windows_ntfs`): a Decider-chosen **prefix** of the uncommitted journal survives (ordered journals commit atomically in order). `posix_strict`: each uncommitted op survives independently with p = 1/2, applied in order, and ops that no longer apply are skipped.
2. **Data.** For every inode whose `cur` differs from `dur`: the surviving length is either `dur.len` or `cur.len`. Each differing 512-byte sector independently persists the new contents or keeps the old ones. Old contents beyond `dur.len` read as zeros. Mixed pages are composed into a fresh page. This models the device write cache reordering sector writes.
3. **Garbage collection.** Inodes unreachable from the durable root are freed (orphan cleanup).
4. **Reset.** `cur := dur` everywhere. The journal and handle table are cleared, and the boot epoch is incremented.

`process_crash` (`kill -9`): the page cache survives, so all of `cur` becomes durable. Only volatile state is lost: tasks, handles and the SUT heap.

In both modes, every task other than the test body and the root is abandoned (its stack is reclaimed without running `defer`s, which is what a crash means), and `env.allocator` is reset.

- `crashAndReboot` must be called from the test body. Calling it from a spawned task panics, because the body itself would otherwise be dropped.
- Abandoned group members are removed from their group's pending count, so a surviving `group.await` returns instead of hanging.

### 6.4 Personas

| Persona | `fsync(file)` commits metadata? | Rename-over-existing | Names | Open-file delete/rename |
|---------|------|------|------|------|
| `linux_ext4` | Yes (journal commit) | `auto_da_alloc`: the renamed inode's data is made durable when the rename commits | case-sensitive, `/` | allowed (orphan inode stays readable through open handles) |
| `linux_xfs` | Yes | No implicit flush: an unsynced file renamed over a target can come back empty or torn | case-sensitive | allowed |
| `windows_ntfs` | Yes | No implicit flush | case-insensitive (ASCII and Latin-1 fold), case-preserving; `\` and `/` separators; reserved names (`CON`, `NUL`, `COM1`…) and `<>:"\|?*` are rejected with `error.BadPathName`; Win32 names: a component's trailing dots and spaces and a `::$DATA` suffix are dropped (`secret.key.` is `secret.key`), and a long name answers to its 8.3 short name (`PRIVAT~1.PEM`, ordinals `~1`–`~4` in creation order; given again after a crash) | **`error.FileBusy`** (sharing violation) |
| `posix_strict` | **No.** Only `fsync` of the *directory* commits that directory's entries (and every op before them) | No implicit flush | case-sensitive | allowed |
| `macos_apfs` | Yes (assumes a durable `fsync`; see below) | No implicit flush | case-insensitive (ASCII and Latin-1), case-preserving, normalization-insensitive for the Latin-1 letters (`é` as U+00E9 or `e` U+0301); other Unicode is compared as written | allowed |
| `freebsd_zfs` | Yes | Ordered: a rename commits after the data written before it (transaction groups) | case-sensitive | allowed; **unsynced data never tears** (copy-on-write: all-or-nothing per file) |

`posix_strict` is the "what POSIX actually promises" persona. It catches the missing-directory-fsync bug that ext4 hides. `freebsd_zfs` hides the same rename bug ext4 hides, for a different reason. The `zig build run` demo shows one bug found under four personas and hidden by two.

**The `F_FULLFSYNC` caveat.** Zig 0.17's `File.sync` calls `fsync(2)` on every POSIX system. On macOS that only pushes data to the drive, whose volatile cache can still lose it on power loss; `fcntl(F_FULLFSYNC)` is needed for durability, and `std.Io` has no way to request it. `macos_apfs` therefore models APFS *as if* `fsync` were durable. A stricter variant (synced data still lost with some probability) is an open question (§15): it would flag every Zig program, which is accurate but not yet actionable. Unicode normalization (NFD) is not modelled.

### 6.5 Leak detection

`env.expectNoLeaks()` fails with a description if any of the following hold:

- a handle is open (other than `env.dir`);
- a task is still alive (other than the caller and root);
- `env.allocator` has live allocations.

`tardis.check` calls it automatically after the body returns successfully (`Options.leak_check`, default on).

---

## 7. L6 (M1 part): Oracles and Diagnostics

### 7.1 Reachability assertions

- `env.sometimes("leader_elected", cond)` / `tardis.assertSometimes(io, name, cond)`: the campaign fails if `cond` was never true across all iterations, which protects against vacuous passes. The catalog lives in the `Sim` and persists across iterations and reboots. Capacity: `sometimes_max = 64`.
- `env.always(name, cond)` returns `error.AssertionFailed`, records the name in the trace, and counts how often the assertion was reached.

### 7.2 Failure report

Real output from `zig build run` (rename-without-fsync on xfs; the read after reboot returns 0 bytes):

```
tardis: FAILED  iteration 1/100  persona=linux_xfs  seed=0xad11fff9180e1e88
tardis: error.AssertionFailed
tardis: last 16 events (virtual time, task, event):
  0.000258767s  t1   rename        0 0 0  config.tmp
  0.000258767s  t1   open          65537 0 0  .
  0.000276127s  t1   sync          0 0 0
  0.000276127s  t1   crash         0 0 0  power_loss
  0.000276127s  t1   open          131073 2 0  config
  0.000297529s  t1   read          2 0 0
  0.000297529s  t1   assertion     0 0 0  config is either old or new
  ...
tardis: replay with:  TARDIS_SEED=0xad11fff9180e1e88 TARDIS_PERSONA=linux_xfs zig build test
```

The recent-event ring has `trace_ring_len` entries (default 64) and is formatted only on failure. Event arguments are raw integers in M1. Named, per-event formatting (and the swimlane view from v1) is an M3 deliverable alongside the shrinker, since an unshrunk trace is too long for a swimlane to help.

### 7.3 Replay

`TARDIS_SEED` (and optionally `TARDIS_PERSONA`) make `check` run exactly that run. `Options.seed` does the same programmatically. Since M3, a failure is also shrunk and printed as a replay token: `TARDIS_REPLAY=persona:seed:key.key… zig build test` (or `Options.replay`) runs exactly the shrunk case, where only the listed decisions take their natural value.

M3 changed how values are derived from a seed, so seeds printed by M1/M2 builds replay different runs. The golden trace hash was updated once, deliberately, for that change.

### 7.4 Determinism self-check

Every `determinism_check_every`-th iteration (default 16; 0 disables it), `check` re-runs the same seed and compares trace hashes and outcomes. A mismatch fails with `error.NonDeterministic` and both hashes. This replaces v1's "DetSan" with a mechanism that exists today. The v1 two-tier design (canaries, adjacent-slot lockstep) remains the M5 plan for snapshot mode.

---

## 8. Public API (M1, as implemented)

```zig
pub const Options = struct {
    seed: ?u64 = null,                 // replay exactly this run seed; null: TARDIS_SEED env var (tests)
    campaign_seed: u64 = default_campaign_seed,   // run seeds derive from this
    iterations: u32 = 100,
    personas: []const Persona = &.{.linux_ext4},
    preempt_ppm: Ppm = 250_000,
    async_inline_ppm: Ppm = 200_000,
    swarm: bool = true,
    faults: FaultOptions = .{},        // io_error_ppm, short_io_ppm, oom_ppm, spurious_wakeup_ppm, latency…
    limits: Limits = .{},              // tasks_max, fiber_stack_bytes, heap_bytes_max, vfs.{pages_max, …}
    leak_check: bool = true,
    determinism_check_every: u32 = 16, // 0 disables
    epoch_offset_ns: u64 = 1_700_000_000 * std.time.ns_per_s,
    report: bool = true,               // print failure reports; off for tests that expect failure
};

pub fn check(gpa: Allocator, comptime body: fn (*Env) anyerror!void, options: Options) !void;
pub fn sim(gpa: Allocator, options: Options) !Simulation;   // .step() ?*Env, .finish() !void, .deinit()
pub fn traceHash(gpa: Allocator, comptime body: fn (*Env) anyerror!void, seed: u64, persona: Persona, options: Options) !u64;
pub fn fuzzInput(comptime T: type, io: std.Io) !T;
pub fn assertSometimes(io: std.Io, comptime name: []const u8, cond: bool) void;
pub fn isSimulated(io: std.Io) bool;

pub const Env = struct {
    io: std.Io,
    dir: std.Io.Dir,                    // root of the virtual filesystem, valid across crashes
    allocator: std.mem.Allocator,       // volatile SUT heap (reset on crash), OOM-injecting
    seed: u64,
    persona: Persona,
    iteration: u32,

    pub fn fuzz(env: *Env, comptime T: type) !T;
    pub fn crashAndReboot(env: *Env, mode: CrashMode) !void;   // call from the test body only
    pub fn injectIoErrorAfter(env: *Env, op: OpKind, successes: u32, err: anyerror) void;
    pub fn advanceTimeNs(env: *Env, delta_ns: u64) !void;   // sleeps the caller
    pub fn nowNs(env: *const Env) u64;
    pub fn crashCount(env: *const Env) u32;
    pub fn expectNoLeaks(env: *Env) !void;
    pub fn sometimes(env: *Env, comptime name: []const u8, cond: bool) void;
    pub fn always(env: *Env, comptime name: []const u8, cond: bool) !void;

    // M2: nodes and network (Options.nodes, Options.net)
    pub fn nodeCount(env: *const Env) u8;
    pub fn address(env: *const Env, node: NodeId, port: u16) std.Io.net.IpAddress; // 10.0.0.(node+1)
    pub fn spawnOn(env: *Env, node: NodeId, comptime f: anytype, args: ArgsTuple(f)) !void;   // daemon task
    pub fn crashNode(env: *Env, node: NodeId, mode: CrashMode) void;
    pub fn cutLink(env: *Env, from: NodeId, to: NodeId) void;   // asymmetric
    pub fn healLink(env: *Env, from: NodeId, to: NodeId) void;
    pub fn partition(env: *Env, a: NodeId, b: NodeId) void;     // both directions
    pub fn isolate(env: *Env, node: NodeId) void;
    pub fn healAll(env: *Env) void;
    pub fn stepClock(env: *Env, node: NodeId, delta_ns: i64) void; // NTP step on .real
    pub fn addHost(env: *Env, name: []const u8, node: NodeId) void; // virtual DNS
    pub fn daemonError(env: *const Env) ?anyerror;
    pub fn nodeAllocator(env: *Env, node: NodeId) Allocator; // node 0's is env.allocator

    // M3: a coverage point for Options.explore = .guided
    pub fn cover(env: *Env, comptime name: []const u8, value: u64) void;
};
```

`check` runs the body on a control fiber, so a deadlock comes back as `error.Deadlock`. `sim` runs the body on the caller's stack (the root task), so a deadlock there panics with the replay seed.

The `while`-loop form:

```zig
test "imperative form" {
    var s = try tardis.sim(std.testing.allocator, .{ .iterations = 50, .personas = &.{.windows_ntfs} });
    defer s.deinit();                    // prints the replay seed if an iteration failed mid-way
    while (s.step()) |env| {
        var f = try env.dir.createFile(env.io, "wal.dat", .{});
        defer f.close(env.io);
        env.injectIoErrorAfter(.write, 1, error.NoSpaceLeft);
        try f.writePositionalAll(env.io, "a", 0);
        try std.testing.expectError(error.NoSpaceLeft, f.writePositionalAll(env.io, "b", 1));
    }
    try s.finish();                      // fails if any `sometimes` was never true
}
```

To have a failure shrunk under `sim`, report it with `s.fail(err)` instead of returning it. The following `step()` calls then hand out shrink candidates of that iteration (same seed, fewer and smaller decisions) as further iterations, and `finish()` returns the error after printing the shrunk replay token:

```zig
while (s.step()) |env| {
    body(env) catch |err| s.fail(err);
}
try s.finish();                          // the reported error, after shrinking
```

---

## 9. Roadmap

Each milestone ends with its acceptance tests green on the CI matrix (§10).

### M1: Deterministic single-node core. **Done in this revision.**
Scheduler, fibers, futex, cancellation, groups, clocks and randomness (§4); VFS with crash model and four personas (§6); targeted, probabilistic and swarm faults plus OOM and short I/O (§5); fuzz input (§5.3); `check` and `sim`; replay; trace ring; determinism self-check; leak checks (§7).

### M2: Network, multi-node, wider VTable. **Done**, except benchmark-gated scheduler scaling.

**Done:**
- **Nodes.** `Options.nodes`; node `n` has its own VFS, address `10.0.0.(n+1)`, monotonic drift and real-clock offset. Every task belongs to a node (inherited at spawn); `Sim.vfs` follows the running task's node on every switch. `env.spawnOn(node, f, args)` starts a daemon task on a node; a daemon's error fails the iteration.
- **`crashNode(node, mode)`** drops that node's tasks, crashes its VFS, and removes its sockets. Each peer connection is reset or black-holed (`NetOptions.blackhole_ppm`), the latter failing with `ConnectionTimedOut` after `blackhole_timeout_ns`. `crashAndReboot` now crashes every node.
- **Virtual TCP** (`net.zig`): `netListenIp`, `netAccept`, `netConnectIp`, `operate(.net_read/.net_write)`, `netClose`, `netShutdown`; `netWriteFile` returns `Unimplemented` so writers fall back to read+write. Per-segment latency with in-order delivery, flow control through a bounded receive ring, RST on close with unread data, RST a round trip after writing to a closed peer, refused connections, backlog limits, ephemeral ports, generation-checked handles.
- **Partitions:** a directed `[32]u32` reachability matrix; `cutLink`, `healLink`, `partition`, `isolate`, `healAll`. Cutting holds undelivered segments; healing schedules them; `connect` across a cut link waits for heal or times out.
- **Virtual DNS** (`netLookup`): `localhost`, `node<N>`, and `env.addHost(name, node)`; `HostName.connect` works unmodified.
- **Clock faults:** per-node drift drawn from `±FaultOptions.clock_drift_ppm_max` (sleeps and deadlines are in local time), and `env.stepClock` for NTP steps on `.real`.
- **Faults:** random connection resets (`net_reset_ppm`, swarm class `net_reset`); targeted `connect`, `accept`, `net_read`, `net_write`; short reads and writes on streams.
- **VTable:** `dirRead`, the lock family.
- **Datagrams** (`netBindIp`, `operate(.net_send/.net_receive)`): a separate UDP port space; per-datagram latency, so jitter reorders; loss and duplication (`datagram_loss_ppm`, `datagram_duplicate_ppm`, swarm class `datagram_loss`); drops across cut links, to unbound ports and into full buffers; truncation flagged.
- **Batch** (`batchAwaitAsync`, `batchAwaitConcurrent`, `batchCancel`): each submitted operation is tried without blocking; incomplete ones stay submitted (they have no side effects yet), so cancel has nothing to interrupt. This makes `operateTimeout`, `Socket.receiveTimeout` and friends work.
- **Retransmit timeout:** a connection whose sent data is held by a partition for `NetOptions.retransmit_timeout_ns` (60 s) fails with `ConnectionTimedOut`; healing first cancels it.
- **Per-node heaps:** `env.nodeAllocator(n)`, wiped when the node crashes. Leak checks skip only nodes that still run a daemon.
- **One wait primitive:** every network wait sleeps until the next network event on any socket (or a deadline) and re-checks, so `operate` and batches share the same non-blocking step functions.

**Remaining:**
- Nothing. The scheduler benchmark decided the scheduler-scaling item: `zig build bench` now runs the same 51,200 sleeps on 2, 64 and 512 tasks. Before, a sleep cost 93 ns at 2 tasks, 152 ns at 64 and 320 ns at 512, so about 70% of the time at 512 tasks grew with the task count, far over the 10% gate. With the timer heap (§4.4) and `selectBit` (§4.2), best of four runs: 93, 128 and 185 ns. The default benchmark (2 tasks, limit 64) went from 173 to 96 ns per sleep. What still grows with the task count is mostly 512 fiber stacks not fitting the cache.

**Original M2 scope, for reference:**
- Virtual network: L4 stream and datagram channels as bounded ring buffers. Per-link latency and jitter. Drops (UDP), resets and black-holes (TCP). Asymmetric partitions via a `[nodes_max]u32` reachability bitmask matrix. Covers `netListenIp`, `netAccept`, `netConnectIp`, `operate(.net_*)`, `netClose`, `netShutdown`, and `netLookup` backed by virtual DNS.
- Nodes: each task belongs to a node. `crashNode(id, mode)` abandons that node's tasks, closes its handles, resets its sockets on peers (RST or black-hole chosen by the Decider), and crashes its VFS (one VFS per node).
- `Universe` / `createCluster(n, Service, opts)` API, with restart-on-reboot of the service entry point.
- Persona additions: `macos_apfs`, `freebsd_zfs`. VTable additions: `dirRead`, locks (with NTFS mandatory semantics), `batch*`, symlinks, hard links.
- Scheduler scaling: hierarchical timing wheel (§4.4) and SIMD rank selection (§4.2), **only if** a scheduler benchmark in `src/cmd/bench` shows more than 10% of time in them at 512 tasks.
- Clock faults: per-node drift (±`drift_ppm`) on monotonic clocks, plus NTP steps on `.real`.

### M3: Guided exploration and shrinking (≈4 weeks)

**Done (shrinking and guided exploration):**
- **Decision keys** (`decide.zig`): every draw made during a run is keyed by `(stream, task spawn path, per-task per-stream counter)` and its value is derived from the key (`splitmix64(stream_seed ^ key)`), not from a sequential stream. A task's spawn path is `mix(parent path, child index)`, so a decision moves only when its own task's earlier control flow changes. This is simpler than the `(op_tag, resource_id)` key below and needs no annotation at call sites.
- **Zero is benign:** every call site is phrased so a raw value of 0 means nothing happened: `chance` false (no fault, no preemption, no OOM, no loss), `range` at its minimum (no latency), the first runnable task, swarm classes off, crash decisions where everything survives, and fuzz values on the ordinary path at 0 (empty slices, `false`, first enum tag).
- **Overlay** (`decide.Overlay`): `keep`, the sorted set of decisions that keep their natural value (every other keyed draw returns 0), and `forced`, decisions given an explicit raw value. A replay token is `persona:seed:KEEP[:FORCED]`, where KEEP is `*` (all natural) or `key.key…`, and FORCED is `key=value.…`.
- **Shrinker** (`shrink.Shrinker`): on failure, `check` records every decision of the failing run, then runs ddmin over that set by re-execution, accepting a candidate only when the run fails with the *same error* (and, for `error.SecurityViolation`, the same finding: the security layer's `finding_key`, `plan2.md` §2.1). After each success the set is narrowed to the decisions the reduced run actually drew. The set is kept in the order the run drew its decisions, so a ddmin chunk is a stretch of the run (a time window); keys are hashes, and in key order a chunk was a random sample of the whole run, which a failure with one cause seldom lets go. Measured over the 374 shrinks of the test suite: the decisions left fall from 749 to 318 and the runs from 14,191 to 12,904; the chaos run with 77,960 decisions, which stopped at the 2,000-run budget with 441 left, now shrinks to 9 in 764 runs. It prints `shrunk N -> M decisions in R runs`, the shrunk run's trace (kept decisions appear as `decision` events) and `TARDIS_REPLAY=<token>`. `Options.shrink_report` exposes the numbers to tests. `Options.keep_going` (for certification campaigns, `plan2.md` §7.5) does not stop at the first failure: every failing run is reported, shrunk and logged with its token (up to 32), the campaign runs to its last iteration, and `check` returns the first error. On several workers and through the fork server, workers and children only note failing runs (the lowest 32 by iteration and persona); the main thread then logs them in order as one thread would, so the log is the same for any worker count. Runs repeated by shrinking or the determinism check are marked `Sim.rerun`, so layers that tally per run count each iteration once.
- **Value shrinking** (same state machine): after ddmin, each kept decision's value is lowered by forcing it. First the fewest low bits that still fail are found (fuzz integers truncate the raw value, so this keeps them exact, while `uniform` draws keep the high bits they read), then a binary search finds the smallest raw value that still fails. Smaller raw values always mean more benign outcomes, so this lands on the boundary of the failure: the smallest failing input, the shortest latency. Lowered values go into the token's FORCED part, and forced decisions outside the kept set are dropped. The report reads `shrunk N -> M decisions and lowered K values in R runs`. Searches assume monotonicity and find a local minimum otherwise; every accepted step is a run that failed with the same error.
- **Shrinking under `tardis.sim`:** `Shrinker` is a resumable state machine (`next()` returns a candidate run, `result(failed)` takes the outcome) instead of a loop over a callback, so the caller owns the runs. `check` drives it in a loop. `Simulation.step()` drives it across the user's loop: after `s.fail(err)`, step re-runs the failure with a recorder, then returns each candidate as one more iteration, then the shrunk run (so the trace shows it), then null. `sim` also replays tokens (`Options.replay`, `TARDIS_REPLAY`).
- **One token, both entry points:** under `check` the body runs on a control fiber, under `sim` on the root task, and decision keys include the task's spawn path. The control fiber now takes the root key context, and the driver task gets a path of its own, so the body draws identical keys either way. A token shrunk under `sim` replays under `check` and vice versa (`shrink_test.zig` checks that both shrink a failure to the same token). This changed decision values under `check`, so the golden trace hash was re-recorded (`0xb990de4b5df96b20`, identical in all four modes on Windows and on Linux).
- **Results** (`src/tests/shrink_test.zig`): the torn-rename bug shrinks to at most 3 crash decisions (27 → 1 with the old key layout, 42 → 3 with the current one), a 4-worker lost update to at most 4 scheduling decisions, 41 fuzz draws to the 1 that matters, a failure needing no randomness to 0 in one run, and `a + b >= 5000` over two fuzzed `u32`s to a pair summing to exactly 5000 (the boundary), which replays from its token. Tokens replay the shrunk failure, and the same seed with an empty overlay passes.
- **Guided exploration** (`explore.zig`, `Options.explore = .guided`): each run fills a 64 Ki-bit coverage map from simulator event pairs `(previous kind, kind, label)` (labels carry paths, error names and assertion names; scheduling noise is excluded), `sometimes` assertions that held, and `env.cover(name, value)` points. A run that sets a new bit joins a corpus as `(persona, seed, forced decisions, 64 sampled decision keys)`. Half the iterations mutate a corpus entry instead, forcing one to three sampled decisions to a random value, all-ones or zero, or, once a security layer has reported compared constants through seam 3's `tokens` hook, to one of those (`plan2.md` §7.1). Failures report a token with the forced decisions, and shrinking keeps them. The `-ffuzz` code-coverage signal from the original design is not used yet: simulator events plus annotations give a signal without build-system integration.
- **Result** (`src/tests/explore_test.zig`): a bug behind five consecutive 1-in-16 choices (about one run in a million at random) is not found by 6,000 random iterations. Guided exploration finds it at iteration 2,889 with a 4-entry corpus, one per depth reached, and the failure shrinks to the 5 relevant decisions and replays from its token.

- **Fuzzy replay** (`Options.replay_fuzzy = Δ`, or `TARDIS_REPLAY_FUZZY`; off by default): a token names its decisions by key, a hash of (stream, task spawn path, counter), so code that draws once more or once less before them moves their keys and the token passes. When a token passes as written, `check` resolves each kept key against the (stream, task) pairs the run drew from (`decide.Anchors`), then re-runs with keys moved by up to Δ draws: all of them, then those of one task and stream, then that pair's keys from one counter on (an edit in the middle of a task). A moved decision keeps the value it had. The first run that fails is returned, with the token that fits the current code; at most 256 runs. The test edits a body to make two more or two fewer draws before the two decisions of a shrunk token: as written the token passes, with Δ = 2 it fails again and the reported token replays as written; an edit of four draws is outside the window and the replay passes. **Limits:** the token does not say which error it stood for, so any failure counts; `tardis.sim`'s loop form does not do it; a task whose spawn path changed is not found.

- **Edge coverage of the code under test** (through `tardis_sec`, `plan2.md` §7.1; ELF and Mach-O targets): in a build with Zig's edge counters (a module with `fuzz = true`), the security layer zeroes the counters when a run starts and, when it ends, makes every edge that ran a coverage feature. A run that reaches new code joins the corpus although it did no I/O. `zig build test-edges` (`src/sec/tests/edge_guided.zig`) checks an input one byte at a time against three bytes: guided exploration gets through at iteration 15,388 with 6 corpus entries, and 200,000 random iterations do not (one run in 2^24). **Limits:** an edge counts once however often it runs, so a loop's second pass adds nothing (the test's check is unrolled); the counters are per process, so edges are features with one worker only; core alone, without the layer, does not read them; COFF (Windows) has no counters.

**Remaining:** nothing; M3 is complete.

**Original M3 design, for reference:**
- **Decision keys:** every Decider draw gets a key `(stream, task_spawn_path_hash, op_tag, resource_id, per-key hit count)`. The task spawn path is a hash of the parent's path plus the spawn index, so it is stable when unrelated tasks spawn. This keeps v1's "Merkle spawn-tree" idea and drops `@returnAddress()`.
- **Mutation overlay:** a sparse fixed-capacity open-addressing table `key -> forced outcome` consulted before the PRNG. A replay token = `seed + overlay`.
- **Coverage feedback:** use Zig's built-in fuzzer instrumentation (`-ffuzz`, `std.testing.fuzz`) for SUT edge coverage, and abstract state hashes (`Service.tardisStateHash`) for protocol coverage. Corpus = overlays that found new coverage.
- **Shrinker:** delta-debug the overlay (drop faults, then crash points, then preemptions) by re-execution, stopping when no smaller overlay still fails. Report "shrunk N → M decisions".
- **Fuzzy replay** across code edits: anchors keyed by `(op_tag, resource_id)` with a ±Δ hit-count window.

### M4: Oracles (≈3 weeks)

**Done:**
- **Linearizability** (`lin.zig`): `History(Model)` records `invoke` / `ok` / `failed` (an operation left pending may or may not have taken effect). `check` runs Wing & Gong's search with Lowe's memoization: a doubly linked list of call and return entries, an explicit stack, dancing-links lift and unlift, and a cache keyed by a Zobrist hash of the linearized set mixed with the model state hash. Models with `partition` are checked one key at a time. Results are `linearizable`, `not_linearizable` (partition, deepest partial order, an operation that cannot be placed) or `unknown` (step budget). Ready-made models are `Register` (read/write/cas) and `Kv`. The report prints the partition's operations with their intervals and marks the stuck one.
- **Transactional anomalies** (`elle.zig`): list-append histories. Per-key version orders come from the longest read, and appends no read observed are placed after it. The checker builds ww, wr, rw and optional real-time edges, runs an iterative Tarjan SCC, and classifies a witness cycle per component as G0, G1c, G-single, G2 or real-time by restricted BFS. It also reports duplicate elements, incompatible orders, G1a and G1b.
- **Register histories** (`elle.zig`, ops `write` / `read_reg`): values are unique per key, so each read names its writer (wr edges). A register read does not reveal the version order, so the checker infers only what is certain: a transaction that read version `a` and then wrote `b` puts `a` before `b`, and the initial value precedes every write. Each known pair gives ww (writer of `a` to writer of `b`) and rw (each reader of `a` to writer of `b`); a reader of the initial value gets rw to every writer of the key. This is sound but incomplete, like Elle without its optional version-order assumptions. Extra anomalies: lost update (two committed transactions read the same version and both wrote the key), internal inconsistency, and garbage reads. List and register keys can share a history.
- **Results:** `lin_test.zig` runs a KV primary on node 1 and a replica on node 2 with three concurrent clients. Reading from the primary is linearizable; reading from the replica the primary updates after acknowledging is caught as a stale read. The failure shrinks, and the report shows the client's own acknowledged write followed by its stale read. In `elle_test.zig`, whole-transaction locking is strictly serializable, while per-operation locking is caught (for example, a G0 cycle from interleaved appends). The register store with read-modify-write transactions is strictly serializable under one lock per transaction; with a lock per operation the checker reports lost updates within 100 iterations.

- **Chaos and liveness** (`Env.startChaos`, `Env.heal`, `Env.eventually`): a nemesis task partitions, isolates, crashes nodes other than 0 (with a `restart` hook) and steps clocks at random intervals. Its choices are ordinary keyed decisions, and 0 means "heal", so they replay and shrink. `heal` stops it, heals every link and disables every probabilistic fault class. `eventually` polls a predicate (which may do I/O) every 10 ms of virtual time and fails like `always` at its deadline.
- **Automatic chaos → heal schedule** (`Options.chaos: ?Chaos`, `Env.awaitHeal`): `check` starts the nemesis before every iteration's body (after `setup`, in fork children too) and heals after a duration drawn from `[duration_min_ns, duration_max_ns]` (default 0.5–5 s of virtual time). The draw is an ordinary decision, so shrinking pulls it to the minimum, and value shrinking lands on the exact duration a failure needs. The body runs its workload, calls `env.awaitHeal()` (which sleeps straight to the heal time), then checks recovery with `eventually`. Tests: the retrying cluster converges under the schedule, fire-and-forget is caught and its failure shrinks and replays, a body that fails when chaos lasts 2 s or more shrinks to a run that heals at exactly 2 s, and the schedule works with warm starts and the fork server (one and two workers).
- **Cost ledger** (`ledger.zig`, `Env.stats`, `Env.flushedBytes`): per-run counters for logical disk bytes written and read, syncs, stream bytes and writes, and datagrams, plus pages actually flushed to media by the VFS. `Histogram` is a log-linear integer histogram (exact below 16, at most 6.25 % error above) with `quantile(ppm)`. `ratioPpm` gives exact ratios such as write amplification.
- **Results** (`chaos_test.zig`): replication that retries forwards converges within 30 s of virtual time after chaos heals. Fire-and-forget replication with a 100 ms forward timeout never converges (caught). Without chaos, the same cluster meets a p99 write latency SLO of 50 ms. Write amplification is exact: 64 records of 16 bytes fsynced one by one cost 256x (64 flushes of a 4 KiB page for 1 KiB), and fsyncing every 16 records costs 16x, so an `always(… <= 32x)` SLO catches the first.

**Remaining:** nothing; M4 is complete.

**Original M4 design, for reference:**
- Porcupine-style linearizability checker: iterative Wing–Gong search with an explicit stack, memoization keyed by (linearized bitset, model state hash), P-compositional partitioning by key, `backtrack_steps_max` bound, and `.in_doubt` outcomes for indeterminate operations.
- Elle-style list-append / rw-register anomaly detection: dependency graph plus iterative Tarjan SCC.
- `assertEventually` with automatic chaos → heal phase transition (requires M2).
- Deterministic cost ledger: per-operation virtual costs, plus p99 and write-amplification assertions in integer or Ppm units.

### M5: Throughput (≈4 weeks)

**Done:**
- **Benchmarks** (`zig build bench`, `src/cmd/bench/main.zig`, always ReleaseFast; `zig build bench-build` to cross-compile): empty runs, a file scenario with power loss, scheduler sleeps, loopback TCP echo, multi-core campaigns, find+shrink, and warm starts. Measured numbers are in §10.
- **A 2x speedup found by the first benchmark.** Each run cleared and every lookup scanned the VFS dentry tables (about 2,300 entries of ~110 bytes). High-water marks bound both, without changing which slot is chosen, so traces and the golden hash are unchanged. The file scenario went from 23k to 52k runs/s, and the test suite from 7 s to 3 s.
- **Multi-core campaigns** (`Options.workers`): worker `w` runs iterations `w, w+W, …` on its own `Sim`. A shared atomic holds the lowest failing iteration, and workers stop once past it. Every lower iteration is still run by someone, so the reported failure does not depend on thread timing. The main thread re-runs that iteration to report and shrink it, and `sometimes` catalogs are merged. `parallel_test.zig` checks that the shrunk token is identical to a one-thread campaign. Applies to `explore = .random`; guided exploration has its own scheme (below).
- **Warm starts** (`Options.setup`): a setup function runs before every body with a fixed setup seed, then `Sim.reseed` switches to the iteration seed and redraws the swarm mask. Replay, shrinking and the determinism check all include the setup, so every iteration starts from the same warm state.
- **Fork server** (`Options.fork`, `forkserver.zig`, Linux raw syscalls): per persona, the parent runs setup once inside a simulation, then forks a child per iteration *from inside the control fiber*. Each child reseeds, runs the body and its leak and daemon checks, and writes the outcome, trace hash and `sometimes` counts through a pipe, then `exit_group`s. The parent re-runs the lowest failing iteration in-process to report and shrink it, so output and tokens match a non-fork campaign (`fork_test.zig`). A child that crashes (for example a panic) is reported with its replay seed while the parent carries on. On other systems `fork = true` runs in-process with identical results.
- **Fork server with workers** (`fork = true, workers = W`): the parent forks W single-threaded *worker processes* (not threads: a child forked from a multi-threaded process could inherit a held allocator lock). Each runs its stride with its own per-iteration fork server and reports its first failure and `sometimes` counts. Each child zeroes its inherited counts first, so only deltas come back. A security layer's per-run tallies come back the same way (`fork_export`/`fork_import` on the seam, `plan2.md` §7.5); worker processes forward their children's tallies to the main process rather than importing them into their own copy. The minimum over workers is the campaign's lowest failing iteration, and the shrunk token matches a single process (`fork_test.zig`).
- **Per-run cost cut to 4–7 µs.** After the dentry fix, two more found by the benchmark: VFS reset cleared all 512 KiB of per-inode page slots every run (now bounded by an inode high-water mark), and every reschedule scanned all 65 task structs (2.2 KiB apart) twice for timers (now a compact `timers: []u64` array, cleaned lazily). Neither changes any decision, so traces and the golden hash are unchanged.

- **A corpus kept between campaigns** (revision 80, `plan3.md` E4; `Options.corpus_dir`, `TARDIS_CORPUS_DIR` in tests, `src/search/persist.zig`): a campaign keeps a file per `check` with what the next one needs: the runs that failed, which the next campaign runs first and drops once they pass, and with `explore = .guided` the corpus, its comparison constants and the coverage it reached, so exploration goes on where it stopped. The file is written whole and renamed into place, ends with a checksum, and keeps personas by name; one that does not decode is ignored and replaced. Its default name is the calling test's (from the program's debug info; the body's without it) with a hash of `personas`, `nodes`, `mode` and `workers`, so two checks in one test keep two files; `Options.corpus_name` names it. Nothing in it changes what a run does given its seed and forced decisions: every failure still replays from its token alone, without the file. `TARDIS_EXPLORE=guided` makes every check guided, which the nightly workflow sets. Measured on the five-digit lock of `explore_test.zig`: campaigns of 300 iterations each, every one with a new seed as the nightly salt gives, never get past the first digits when each starts empty (30 campaigns); keeping the corpus they reach the fourth digit by the third campaign and open the lock in the 24th, about 7,000 runs in all, as many as one long campaign needs (`src/tests/corpus_test.zig`).
- **Guided exploration on several workers** (`explore = .guided, workers = W`, `Options.epoch_iterations`, default 64): the campaign runs in epochs. Before each epoch the main thread plans every run (fresh seed or mutation) from the corpus as of the previous epoch. Persistent worker threads (the main thread is worker 0) claim jobs from an atomic counter and write each run's coverage map and decision-key sample into that job's slot, then meet at a spin-and-yield barrier (`check` has no host `Io` to block on). The main thread merges slots in job order and grows the corpus. Planning and merging never depend on which thread ran a job, so corpus, failure and shrunk token are identical for any W > 1 (`explore_test.zig` compares 2 and 4 workers). One-thread guided exploration, which updates the corpus after every run, is unchanged and differs slightly. On a six-digit lock (one run in 16 M at random) the epoch delay costs almost nothing (found at iteration 6,148 vs 6,129), and 8 workers cut wall-clock time from 31 to 13 ms on Windows (29 to 20 ms on WSL2) even though each run takes only ~5 µs. The serial merge of an 8 KiB coverage map per run is now the limit.

**Measured** (x86_64, 20 CPUs; Windows 11 and Linux on WSL2; see §10): forking costs a flat ~260–310 µs per iteration here, so on one process it only pays when setup costs more than that. It is 2.3x *slower* for a ~120 µs setup, 2.6x faster for ~670 µs, and 12.5x faster for ~3.9 ms. Eight worker processes multiply fork-server throughput by 4–7x (5–6k runs/s). Eight threads give 5–6.5x on the in-process file scenario on Windows.

**Remaining:**
- Fork server on macOS/BSD: the code is there, and unrun on those systems. `forkserver.zig` has a second backend through libc (`fork`, `pipe`, `read`, `write`, `waitpid`, `_exit`), chosen wherever libc is linked: always on macOS and the BSDs, and on Linux with `zig build -Dlibc`. `tardis.fork_supported` says whether `Options.fork` forks. The libc backend is run on Linux against glibc (WSL2, `-Dlibc -Dtarget=x86_64-linux-gnu.2.31`): all 178 library tests and the security suite pass, as they do on musl with raw syscalls. The whole suite compiles for `aarch64-macos`; no macOS or BSD machine has run it.
- User-space restore: done for the case that matters, as a snapshot of simulator state and not of process memory (`Sim.Warm`, `Options.warm_restore`, on by default). Setup is deterministic, so every iteration's setup leaves the same state. After the first setup on each persona (one snapshot per persona since revision 93), `check` keeps what setup changed: each node's filesystem, its clock offset, the virtual time, the body task's decision counters, the trace, the coverage bits, the cost counters and the host names. Later iterations start from that and skip setup.
  - **The filesystem costs no page copies on one persona.** Its pages are already copy-on-write above one reference, so the snapshot copies the tables and gives every page in use one more reference (`Vfs.snapshot`). A body's writes then copy the page they touch, and the snapshot's pages keep their contents. With several personas a filesystem holds the pages of one snapshot at a time: the others keep a copy, written back at their warm start (revision 93). Pages setup wrote stay taken when a body deletes them, so a body that fills the disk is refused sooner warm than cold.
  - **When it applies.** Only when setup left nothing else: no task, socket, heap block or open handle, no cut link, no crash, no assertion counted; and only for plain campaign runs, with no security layer, decision overlay, recorder or chaos schedule. A run that changes setup's decisions (a shrink candidate, a token replay) runs setup itself and discards the snapshot, since it may write other bytes into the shared pages. Otherwise setup runs every iteration, as before.
  - **The cross-check.** Every 64th warm start runs setup for real and compares its result with the snapshot (trace hash, time, counters, the filesystem's page tables, and the pages' contents where the snapshot holds a copy). A difference turns warm starts off for that simulator. `Options.warm_report` gives the counts.
  - **Measured** (`zig build bench`, Windows, where `fork` runs in-process): setup of 100 / 1,000 / 5,000 8-KiB writes with fsync, body one read. Setup every iteration: 100 µs, 660 µs, 3.1 ms. From the snapshot: 21 µs, 35 µs, 98 µs, the periodic real setups included. On Linux (WSL2), where `fork` really forks: 21 µs, 37 µs and 110 µs from the snapshot against 344 µs, 362 µs and 382 µs per forked iteration. The snapshot beats the fork server by 3.5 to 16 times, and works where there is no fork.
  - **Tests.** 200 iterations of the warm-state test make 208 warm starts and 4 cross-checks with no mismatch; a failing campaign gives the same token with and without; a body that overwrites, deletes, adds and power-fails setup's files leaves the next iteration's files as setup wrote them; a setup that leaves a socket gets no snapshot.
  - **Not done, and not sound in-process:** a snapshot of process memory (the arena and dirty-page design below), which a setup that leaves heap state or tasks would need. Such a setup leaves pointers into memory the simulator does not own; see Open items. The fork server is that snapshot on Linux.
- Multi-core scaling of the in-process path: settled by measurement, nothing to fix. `TARDIS_BENCH_SOLO=1` makes the benchmark program run only the one-worker file campaign; eight such processes at once, sharing nothing, total 828,592 runs/s on the 20-CPU Windows host (5.1 times one process: 161,720), four total 596,431 and two 327,311. Eight workers in one process reach 953,456 runs/s (5.7 times one worker). The workers scale at least as well as separate processes do, so what is missing to 8x is the machine (cores of unequal speed, shared caches and memory), not state the workers share.

**Original M5 design, for reference:**
- **Fork server first.** On POSIX, `fork()` at `markForkPoint()` and run each iteration in a child. Kernel CoW gives snapshot semantics for free, and it is the baseline that any user-space scheme must beat.
- **Then user-space restore**, evaluated against the fork server: a private arena for all SUT and simulator state (`VirtualAlloc`/`mmap` at a *hint*, not a fixed address), dirty-page harvesting via `GetWriteWatch` (Windows), `PAGEMAP_SCAN` + `UFFD_WP` (Linux 6.7+), or `mprotect` + fault handler (portable fallback), and restore by copying dirty pages from a baseline mapping. Targets are stated in §10 and must be measured.
- Multi-core campaigns: one `Sim` per worker thread (stateless sharing, since runs are independent). Merge the corpus deterministically at epoch barriers ordered by iteration id.

### M6: Research track (time-boxed spikes, each with a go/no-go report)
- `std` overlay for legacy Zig code (redirect `std.Thread`, `std.time`, `std.crypto.random` via build-graph module substitution). **Report: no-go.** Tried with Zig 0.17 on a three-file project: `module.addImport("std", overlay)` is accepted, but the build passes it as `-Mstd=overlay.zig`, which replaces the standard library for the whole compilation, not for that module. The compiler's own `builtin.zig` then resolves `std` to the overlay, and the overlay cannot reach the real library: its `@import("std")` is itself ("value of declaration depends on itself"). So one module cannot see a different `std` than the rest. The need has also shrunk: in 0.17 the clock, randomness and blocking calls go through `std.Io`, which the simulator already provides; `std.time.milliTimestamp`, which the spike first tried to redirect, no longer exists. What still escapes is `std.Thread.spawn` and raw atomics, for which `tardis.atomic.Value` is the opt-in.
- C interposition via `zig cc -include tardis_shim.h` plus symbol redefinition for static archives. **Report: go for C built from source, not done for archives.** `src/sec/c/tardis_sec.h` (`plan2.md` §5.2) renames calls with macros in C compiled with the header, and that works on Windows (MinGW) and Linux (musl, glibc): format strings, process starts, SQL text, pthread mutexes, MC/DC decisions and bounds checks reach the simulator. It covers the security sinks, not I/O: C `fopen` and sockets still bypass the simulation. A prebuilt archive needs link-time wrapping (`-Wl,--wrap`), which is not provided.
- Linux syscall user dispatch (`PR_SET_SYSCALL_USER_DISPATCH`) and `PR_SET_TSC` trapping for stray syscalls and `rdtsc`. **Report: go for system calls, built; go for `rdtsc`, built in revision 55 as `Options.virtual_tsc`.** `Options.trap_syscalls` (or `TARDIS_TRAP_SYSCALLS=1` for every check of a test run) fails a run with `error.StraySyscall` when its code makes a real system call, and names the first one. Linux on x86_64 only (`src/sim/syscalls.zig`). While a run is on, every system call the thread makes raises SIGSYS. The handler lets the calls the simulator and the harness make themselves count as expected (memory, writes to the terminal, futexes, signals, exiting), notes any other, and makes the call for the thread, so the program goes on as it would have. It returns through its own restorer, which the kernel is told to let through. Measured on WSL2 (kernel 6.18): about 1.1 µs per trapped call. The test asks the kernel for random bytes inside a body: `error.StraySyscall`, naming `getrandom`; a body that uses `env.io` for randomness, the clock, files, sleeping and a large allocation passes. With the trap forced on for every check, the whole Linux suite passes except that one deliberate call, so neither the simulator nor any test leaves the simulation during a run. **Limits:** calls the kernel answers through the vDSO (`clock_gettime`, `gettimeofday`) are not system calls and are not seen; forked iterations and other threads are not trapped. **`rdtsc`:** a spike on the same kernel shows it can be trapped and answered. After `prctl(PR_SET_TSC, PR_TSC_SIGSEGV)` the instruction raises SIGSEGV; a handler that finds the bytes `0F 31` at the faulting address puts its own value in RAX and RDX and steps over them, so two reads returned 1100 and 1200 instead of the counter. Revision 55 builds it as `Options.virtual_tsc` (`src/sim/tsc.zig`, Linux on x86_64): while a run is on, `rdtsc` and `rdtscp` return the run's virtual time in nanoseconds plus the number of reads so far, so code that times itself with the counter follows the seed. The handler owns SIGSEGV only for those two instructions; any other fault goes to the handler installed before it (Zig's crash report) or to the default action, and the fiber guard-page test still passes with it in the binary. The test times a 5 ms sleep with the counter and gets 5,000,000 ns plus its reads, also with `trap_syscalls` on; with the option off the same body fails. **Limits:** the kernel's vDSO reads the counter too, so a real `clock_gettime` made during such a run is wrong; forked iterations and other threads are not covered; the answer is a time in nanoseconds, not a count at the processor's frequency.
- Weak-memory and data-race checking for `tardis.atomic` (store buffers, vector clocks, PCT). **Report: go for store buffers; vector clocks built for instrumented code in revision 53 (`plan2.md` §4.5); PCT not started.** Revision 50 called vector clocks a no-go for the two reasons that follow. Both were wrong for code built as an instrumented object: Zig's `sanitize_thread` reports every load, store and atomic operation, the uncontended mutex path included (`plan2.md` §3.8, which uses those reports for shadow memory). The detector of `plan2.md` §4.5 runs on them. The reasons as first written: a vector-clock race detector needs two things the simulator does not get. It must see every read and write of shared memory, and Zig emits no load or store callbacks (`plan2.md` §1.2), so only cells the code wraps could be checked. And it must see every synchronization to order accesses, but the uncontended path of `std.Io.Mutex` is a user-space atomic that never calls the simulator, so data properly guarded by a mutex would be reported as racing. `tardis.atomic.Value(T)` (`src/sim/atomic.zig`) has `std.atomic.Value`'s operations and is the real atomic outside a simulation. Inside one, every operation is a scheduling point, and a store with an ordering weaker than `.seq_cst` goes to the storing task's store buffer: the task reads its own value, other tasks read the old one until the buffer drains. Whether a store is held is a keyed decision whose benign value is "not held", so a failure that needs one shrinks and replays. `.seq_cst` stores, read-modify-writes, blocking, any `std.Io` call and the task's end drain the buffer. This is the total-store-order model of x86, not C11's or ARM's: only a store overtaken by the same task's later loads is produced. The tests: in the store-buffering litmus test two `.release` stores are both missed within 500 iterations and the token replays, while `.seq_cst` stores never are; a load-then-store counter loses updates and `fetchAdd` does not. An atomic operation counts as touching every node for the exhaustive search's reduction and merging.
- Flight recorder (`std.Io` wrapper that logs completions in production for replay), Perfetto export, and a browser trace viewer. **Report: the export is done; the recorder is a no-go as a spike.** `std.Io.VTable` in Zig 0.17 has 106 entries, and each receives the interface's one `userdata` pointer. A wrapper that records has its own `userdata`, so it cannot keep any of the wrapped implementation's entries: every one of the 106 needs a hand-written forwarder with its exact signature (Zig cannot generate functions with arbitrary parameter lists), and the replaying side needs a matching reader for each result type. That is a subsystem of its own with a maintenance cost at every Zig release, not a spike. `tardis.traceJson(gpa, body, seed, persona, options, writer)` runs a body once, or `Options.replay`'s token, and writes the run's events as a Chrome trace (JSON): one instant event per simulator event, on a track per task, at its virtual time, with the event's integers and label as arguments. Perfetto and `chrome://tracing` open it, so no viewer of our own is needed. It holds the last `limits.trace_ring_len` events (64 by default; raise it for a whole run), and a failing run is written before its error is returned. The test traces a shrunk torn-rename token and parses the result: events in time order, one crash, the rename.

---

### 9.1 The `tardis` program and testing termancy

termancy (github.com/93ams/termancy, a sibling checkout) is a lazy dependency, requested only when TARDIS is the root project (`b.pkg_hash.len == 0`), so packages importing the library never fetch it. For a release, switch the `.path` to a pinned `git+https://…#tag` URL.

**`zig-out/bin/tardis`** (`src/cmd/tardis/main.zig`, termancy `cli`/`term`/`sys`), every command with `-o json`:

| Command | What it does |
|---|---|
| `tardis explain <token>` | persona (and what it models), seed, how many decisions are kept, forced values, and the replay command for sh and PowerShell |
| `tardis replay <token\|seed> [-f filter] [-p persona] [--dry-run]` | runs `zig build test` with `TARDIS_REPLAY` or `TARDIS_SEED`/`TARDIS_PERSONA` set (through `sys.process.stream`), passing the exit status through |
| `tardis scan <file\|->` | finds every TARDIS failure in test output: test name, error, persona, and a replay token (the shrunk one, else `persona:seed:*`, which replays the unshrunk run) |
| `tardis personas` | the six simulated filesystems as a table |
| `tardis replay-evidence <dir> [--key <hex>]` | verifies a `tardis_sec` evidence bundle (`plan2.md` §7.5): every file's hash, no unlisted file, the Merkle root, and the Ed25519 signature (against the project key with `--key`); lists the capsules and their expected errors |

Tests run the app in memory with `cli.testing.run`. Zig 0.17's build runner no longer forwards `zig build run -- args`, so there is no run step; use the installed binary.

**termancy under TARDIS** (`zig build test-termancy`, also part of `zig build test`): termancy's I/O goes through `std.Io`, so its code runs in the simulation unchanged. Making it run took three simulator additions: `dirCreateFileAtomic`, `dirRenamePreserve` and the permission calls. Results, with power loss at random points across personas:

| termancy code | Property | Result |
|---|---|---|
| `sys.files.writeAtomic` | old or new contents, never torn or missing (6 personas) | holds |
| `sys.files.writeAtomic` | a write that returned survives power loss | was a **bug** (posix_strict): the publishing rename was never followed by a directory fsync. Fixed |
| `sys.files.Store` | a blob is the old or new value (6 personas) | holds |
| `sys.update.install`, `rename_over` | power loss mid-install leaves the old or new executable (6 personas) | holds |
| `sys.update.install`, `move_aside` | the same, after the documented start-up `removeLeftovers` | was a **bug** (ext4, XFS): a crash between the two renames leaves only `<exe>.old`, which `removeLeftovers` deleted. Fixed: it now puts it back |
| `install`, rejected by the accept hook | the executable is intact after rollback + power loss | was a **bug** on XFS: the rollback copy came from `Dir.copyFile`, which never syncs. Fixed: the copy is synced |
| `install`, rejected by the accept hook | the rejected build stays rolled back | was a **bug** (ext4): no directory fsync after the rollback rename, so the swap to the rejected build could survive and the undo be lost. Fixed |

The four bugs are fixed on termancy's `fix/durable-file-updates` branch (uncommitted at the time of writing): a new `sys.files.syncDir`, a directory fsync in `writeAtomic` and after `install`'s swap and rollback, a synced rollback copy, and a `removeLeftovers` that restores `<exe>.old`. Every row now holds on all six personas, and each test's comment says how it failed before. Notes:

1. **Host-specific code escapes the simulation.** On a Windows host, termancy's `renameImage` (used by `move_aside` and by every rollback) calls `MoveFileExW` directly, not through `std.Io`, so those paths run only on other hosts (4 tests skip on Windows). termancy could route it through `std.Io` once std's rename asks for less access, or let callers inject it.
2. **`install` overflows the default fiber stack.** Two `Dir.max_path_bytes` buffers (~96 KiB each on Windows) plus `copyFile` exceed 256 KiB; the suite uses 1 MiB fibers (`Options.limits.fiber_stack_bytes`). TARDIS's overflow check was a canary noticed after the fact, so this surfaced as a segfault somewhere else; stacks now have guard pages, so an overflow faults at the frame that overflows.
3. **Not yet covered:** `sys.files.Lock` (decides liveness with a real `isAlive(pid)` outside `std.Io`), the SSH server and client (they use `std.Io.net` and should run on the virtual network with partitions), `cfg` write-back, and termancy's `tui` driver with TARDIS's `io` for fault-injected UI tests.

### 9.2 System-call mode (`plan3.md` D9)

A second way into the simulation, beside `std.Io`: `Options.mode = .syscalls`. The default stays `.std_io`. Linux on x86_64 only; elsewhere `check` returns `error.SyscallModeUnsupported` (`tardis.syscall_mode_supported` says which). In this mode the stray-call trap of §9 M6 (`src/sim/syscalls.zig`) answers an allowlisted set of system calls from the simulator in place of the kernel, so code that never sees an `Io` (direct `std.os.linux` calls, `std.posix`, a C library) runs inside the run. `env.io` and `env.dir` keep working in the same body: there is one simulated world and two ways to reach it.

The decisions, settled before building:

- **One model, not two.** The emulation (`src/sim/sysemu.zig`) is a translator: each trapped call becomes the matching operation on the simulator's own `std.Io` (`openat` is `Dir.openFile` or `Dir.createFile`, `pwrite64` is `File.writePositional`, `fsync` is `File.sync`). So a write made by system call draws the same faults, leaves the same trace events and is lost or kept by a crash exactly as one made through `env.dir`: it is the same code from the `Io` vtable down. The cost is that the system-call layer can only say what the `std.Io` layer can.
- **Descriptors.** A simulated descriptor is the VFS handle value (`epoch << 16 | slot + 1`, below 2^30) with bit 30 set: `0x4000_0000` to `0x7FFF_FFFF`. The kernel hands out the lowest free number, so a real descriptor is in that range only in a process with over a thousand million of them open; a real one and a simulated one do not collide. The mapping has no table to keep in step: the handle's epoch makes a descriptor closed twice, or kept across `crashAndReboot`, `EBADF`. What a system-call descriptor needs beyond the handle (`O_APPEND`, the position in a directory listing) is two fields on the VFS handle itself, cleared when a handle is opened. `AT_FDCWD` and absolute paths are the root of the node's filesystem. A call on a descriptor outside the range (other than writes to 1 and 2, which are the test's own output), or relative to a directory descriptor outside it, is not emulated: it is a stray call. So is a path under `/proc`, `/sys` or `/dev` (but `/dev/urandom`): the simulated filesystem has no such trees, and what asks for them is the harness (a crash report reading `/proc/self/exe`) or code that wants the real machine.
- **Blocking.** The handler runs on the calling fiber's stack and may yield: `nanosleep` blocks the fiber in the scheduler and other tasks run. Two things make that sound. SIGSYS is installed with `SA_NODEFER`, so it is not blocked while a fiber sits in the handler and another fiber traps. And the "trap or allow" selector byte, which is per thread, is saved and restored around every fiber switch (`Sim.switchToTask`), since a fiber inside the handler runs the simulator untrapped while one in user code is trapped. A fiber abandoned inside the handler (a crash drops it) leaves only a signal frame on a stack that is reused; the kernel keeps no other state for it.
- **Errors.** The `std.Io` error a simulated operation returns is mapped to an errno by name (`FileNotFound` is `ENOENT`, `PathAlreadyExists` `EEXIST`, `NotDir` `ENOTDIR`, `IsDir` `EISDIR`, `DirNotEmpty` `ENOTEMPTY`, `NoSpaceLeft` `ENOSPC`, `InputOutput` `EIO`, `NameTooLong` `ENAMETOOLONG`, `SymLinkLoop` `ELOOP`, `ProcessFdQuotaExceeded` `EMFILE`, `Canceled` `EINTR`, a stale handle `EBADF`, anything unnamed `EIO`), and the call returns `-errno` in `rax` as the kernel does.
- **Sockets (revisions 79, 81 and 82).** `socket`, `bind`, `listen`, `accept`, `accept4`, `connect`, `read`, `write`, `readv`, `writev`, `recvfrom`, `sendto`, `shutdown`, `close`, `getsockname`, `getpeername`, `setsockopt` (accepted, changes nothing), `getsockopt` (`SO_ERROR`, `SO_TYPE`), `fcntl`'s descriptor flags and `O_NONBLOCK`, and `poll` and `ppoll`, for IPv4 stream and datagram sockets, translated into the simulator's `std.Io` network operations (`src/sim/sysnet.zig`): a connection made by system call meets the same latency, partitions, resets and node crashes as one made through `env.io`. A socket descriptor is `0x2000_0000` plus a slot, above every real descriptor and below the simulated files'. `socket` only takes a slot, since `std.Io` creates a socket with its address; the simulated socket appears at `bind`, `listen` or `connect`. A blocking stream `send` sends everything, as Linux does, although the simulator's writes may be short. An IPv6 socket fails with `EAFNOSUPPORT`, the cue for code that tries IPv6 first to use IPv4. Not emulated (stray): `select`, `pselect6` and `epoll`; `sendmsg`, `recvmsg`, `MSG_PEEK`, `MSG_OOB`, `MSG_WAITALL`; Unix-domain sockets; `fstat` of a socket. A write after this end's `shutdown(SHUT_WR)`, or after a reset was reported once, fails with `EPIPE`, and no `SIGPIPE` is raised; a stream `bind` reserves its port (revision 81). Tested: a TCP echo over loopback by system calls (100 iterations, with faults), datagrams with their sender's address and an ephemeral port bound by the first send, the errors (`EAFNOSUPPORT`, `ECONNREFUSED`, `ENOTCONN`, `EBADF` after close), and (revision 82) a non-blocking echo driven by `poll`, `poll`'s timeout in virtual time, `MSG_DONTWAIT`, and `epoll` failing the run as stray. Writing the echo found two bugs in the first version, both fixed: a short simulated write was returned as a short `send` (Linux sends all of it), and `accept` chose its new slot before it waited, so a `socket` made by another task meanwhile took the same slot. The differential test against the kernel is revision 81's, below.

**Adversarial review (revisions 75 to 79), and what it changed.** A read-only review of system-call mode found thirteen issues; these are fixed: a real fault inside the vDSO (a bad pointer passed to `clock_gettime`) looped forever instead of crashing, since any fault there lifted the protection and retried (now only a fault on the image itself while it is protected is the trap's, and a write never is); glibc's `__vdso_getrandom` (2.41 and later) was not answered and lifted the protection (it is now answered as `getrandom`, and glibc's request for user-space state is refused, so it uses the system call); a call whose first argument is a pointer was sent to the socket code when the pointer's low half fell in the socket descriptors' range (only calls on a descriptor are, now; tested with a futex word mapped at that address); a vDSO call the emulator declined answered from the host uncounted (now a stray, refused); the SIGSEGV handler now runs on the alternate signal stack when the handler before it did, so a stack overflow is still reported; `shutdown` of a listener did not wake its `accept`; `EPIPE` was never produced; a stream `writev` sent only its first vector; `read` of zero bytes waited; an accepted socket's local address was the wildcard; a connected datagram socket had no peer for `getpeername` and received from anyone; a node's crash left its socket slots taken; and a descriptor closed while `connect` waited could be reused by the connection. The review also found that the note on C state left behind fired at the end of nearly every networked run, for daemons parked in `accept`: only a crash's drops are noted now, per `check`. New tests cover the socket cases and the address that looks like a descriptor; the fault-handler fixes are by reading, since a test of them would crash the test process.

**Revision 81: the sockets against the kernel.** A differential test (`src/tests/sysnet_diff_test.zig`) generates sequences of 40 calls on four descriptors (`socket` of either kind, `bind` to the wildcard, to loopback and to another socket's port, `listen`, `connect`, `accept`, `send`, `sendto`, `recv`, `shutdown` each way, `close`, `getsockname`, `getpeername`, `SO_ERROR`, `SO_TYPE`, and from revision 82 `O_NONBLOCK` and `poll`), runs each in the simulator with no faults and no latency, and on the kernel over loopback, and compares every result: the value or error, the bytes read, and the shape of an address (its family, whether its port is 0, its address; port numbers differ between the two and are not compared). The calls block, so the runner keeps a model of what is in flight and skips, in both runs alike, a call that would wait; on the kernel every socket has two-second timeouts, so a wrong model fails a call instead of hanging the test. 20,000 sequences agree; the suite runs 5,000. Writing it found these differences from Linux, all fixed in the emulator or the network model: a datagram to its peer that finds no socket there makes a connected UDP socket's next call fail with `ECONNREFUSED` (the kernel's ICMP port unreachable), also when the socket there is connected to someone else, and also for any port when the peer's port is 0; datagrams that arrived before a UDP `connect` are kept whatever their source; a datagram sent to 127.x comes from 127.0.0.1, and both ends of a connection to 127.x have loopback addresses; `sendto` port 0 binds the socket and then fails with `EINVAL`, and a send that fails for want of a destination still binds it; `accept` on a datagram socket fails with `EOPNOTSUPP`, `connect` on a listening one with `EISCONN`, and a send on an unconnected stream with `EPIPE`; a stream `bind` reserves its port (it reserved nothing until `listen`, and `bind` to port 0 read back port 0), and `listen` or `connect` after it use that port; a failed `connect` gives up a port the kernel chose and keeps one `bind` named, `getsockname` still shows it, and a socket once bound to an address keeps the attempt's source address (`SOCK_BINDADDR_LOCK`); a `shutdown` of an unconnected socket fails with `ENOTCONN` but is recorded, so a read then returns 0, and a failed `connect` (which disconnects the socket) clears it while a successful one keeps it; `shutdown` of a connected UDP socket works, and its `SHUT_WR` refuses later sends with `EPIPE` after the destination checks, as does a pending error, which comes first; `shutdown` of a listener for reading disconnects it (queued connections reset, a waiting `accept` fails, the socket closed again with its port if `bind` named one); `getpeername` fails with `ENOTCONN` for a UDP peer on port 0 and for a stream that was reset; a reset not yet reported shows in `SO_ERROR`, `poll` and the next `send`, as `EPIPE` when the peer's FIN came first, and a read after it returns 0; data for a peer that shut down both ways resets the connection (RFC 1122 4.2.2.13). Not modelled, and left out of the test: TCP's simultaneous open (a socket connecting to its own port connects to itself on Linux), and binding or connecting again a stream that was connected (Linux closes a reset stream, which may then be bound or connected anew; here it stays connected).

**Revision 82: non-blocking sockets and `poll`.** `SOCK_NONBLOCK`, `accept4`'s flag, `fcntl(F_SETFL, O_NONBLOCK)` and `MSG_DONTWAIT` make a call that would wait fail with `EAGAIN`: a read with nothing to read, an `accept` with nothing waiting, a stream write with no room (it writes what fits). A non-blocking `connect` completes before it returns, which POSIX allows, and still says `EINPROGRESS`, as Linux does on loopback; a failure is left for `SO_ERROR`, `poll` and the next call (`ECONNABORTED` from that call if `SO_ERROR` took it). `poll` and `ppoll` answer for sockets with the events Linux's `tcp_poll` and `datagram_poll` give (a closed TCP socket is hung up and writable, a reset one also readable and in error until the error is taken, a listener readable when a connection waits) and for simulated files as ready; they wait in virtual time for the network to change or the timeout to pass, and a real descriptor among them is a stray. The differential test covers `O_NONBLOCK`, `poll` with no timeout, and a non-blocking `connect` waited on with `poll`; 20,000 sequences agree. It found ten more differences, fixed: a failed non-blocking `connect` leaves the socket shut down both ways (`poll` shows it readable with the peer's end) and still "connecting", so `listen` fails with `EINVAL`, a `shutdown` then makes every later `connect` fail with `EINVAL`, and it keeps the attempt's source address until the next `connect` disconnects it, which also clears what a `shutdown` recorded; UDP looks at `SHUT_RD` only when a read would wait, so a non-blocking one says `EAGAIN`; a connected UDP socket's peer port 0 matches any source; only the peer's datagrams make it readable; and connecting again drops what the old filter refused (Linux never queued it). Still stray: `select`, `pselect6` and `epoll`.

**Adversarial review (revisions 80 to 82), and what it changed.** A read-only review found thirteen issues. Fixed: a bound socket closed while its `connect` waited for the handshake, and its network slot reused by another `bind`, was taken for the new one (it is now checked by handle, generation and all); `shutdown(SHUT_RD)` of a datagram socket woke nobody, so a `poll` or read waiting on it waited forever (it wakes them now, and a datagram read waits in the emulator, where sysnet's own state can end it; tested); a listener shut down for reading with a connection still open lost its port, as its accepted connections share it (it now stops in place, `Net.unlisten`; tested); the port `getsockname` shows after a failed `connect` was a second draw, not the one the attempt used; `accept` with a bad address-length pointer leaked the connection; only the first failure of a check was kept, so with `keep_going` a kept failure that failed again hid the new ones (four are kept now); the default corpus file name did not include the body's name, so two checks in one test with the same options shared a file; the temporary file's name could clash between two processes saving different contents (it now includes a hash of them); and running out of memory while handing over the corpus lost the failures too (the new corpus is built aside). Known and documented, not changed: a non-blocking `connect` still takes the handshake's virtual time, and a partitioned destination holds it until the connect timeout; the new rule that data for a peer shut down both ways resets the connection is decided when the data is sent, not when it arrives, and draws one more decision, so replay tokens of `env.io` programs that shut down both ways, and their traces, may change, as may those that read the 127.0.0.1 addresses loopback traffic now has; `TARDIS_CORPUS_DIR` and `TARDIS_EXPLORE` override what a check says, so the corpus tests' baselines are not baselines when they are set (the nightly workflow does not run those tests).

**Revision 97: an event loop's parts, and threads.** Two things kept code that waits on several descriptors, or starts a thread, out of system-call mode. Neither has a counterpart in `std.Io`, so neither is a translation.

*Pipes, `eventfd` and `epoll`* (`src/sim/sysfd.zig`) are objects of the emulation itself, with descriptors at `0x1000_0000` plus a slot. They hold nothing durable and never leave their node, so the crash and network models have nothing to say of them: a node's crash frees its descriptors. A task waiting on one waits where `poll` does, on the simulator's network wait, which every change here ends. Level-triggered reporting is exact. Edge-triggered is an over-approximation, because the simulator computes a socket's readiness from the clock and has no arrival event to hang an edge on: an event is reported once, and again after it was seen gone, after any call on the descriptor, after a write to or read from a pipe's other end, and for a socket after any network change or any passing of virtual time. A program gets every edge Linux gives and some it does not.

*Threads* (`src/sim/systhread.zig`). The decision was between refusing `clone` (as before), running real threads under a lock, and making a thread a task. Real threads under a lock would bring the kernel's scheduler into the run. A task is what the simulator already schedules: the child's fiber starts at the instruction after the `syscall`, with the parent's registers from the signal frame, `rax` 0, the caller's stack, and the caller's thread pointer in `fs`; its exit clears and wakes the `CLONE_CHILD_CLEARTID` word and ends the task in one step. The cost is the thread pointer: until now every task ran under one, and the simulator's own thread-local state is found through it. The SIGSYS and SIGSEGV handlers are therefore entered through a wrapper that looks the interrupted `fs` base up in a table of the process's simulated threads, loads the real thread's own base if it is one, and restores it on return; a fiber switch inside a handler keeps the saved base on the fiber's stack. Reading and writing the base needs FSGSBASE; the two instructions are on a page of their own, since Zig's backend has no encoding for them. Where the processor lacks it, `clone` stays a stray. A thread's `rt_sigprocmask` cannot reach the kernel (musl blocks every signal on a thread's way out, which on the one real thread would block the trap), so masks are kept per task; a detached thread's `munmap` of the stack it stands on is put off until its task has ended.

Verified on Linux (WSL2, kernel 6.18, static musl): the tests named in `CHANGELOG.md`, revision 97, among them an edge-triggered epoll server over 100 seeds and SQLite driven by two `pthread`s sharing a connection. The library suite: 263 passed, 2 skipped, with the 39 other binaries and the bug benchmark. Windows: the four build modes and `-Dsec` pass. A read-only review found six bugs, all fixed (`CHANGELOG.md`).

Not verified, and the limits: threads switch only at system calls, so a thread spinning on memory hangs the run unreported and data races are not explored; a thread may not use `env.io` (under its own thread pointer the simulator's state is not found; nothing detects the attempt); a thread's calls run on its own stack; simulated descriptor numbers are above `FD_SETSIZE`, which rules out `select` and libraries that index a table by descriptor; `dup`, `fork`, a signal to another thread and nested epoll sets are stray. Not run: glibc, Rust, C++, any async runtime, release builds that link libc, system-call mode on several worker threads.

**Revision 99: a Rust program, and what running one found.** `test/rust` is a Rust crate built by cargo as a static library for musl and linked into `test/rust.zig`: `std::thread`, `Mutex`, channels, `Condvar::wait_timeout`, `std::fs` across a power loss, blocking TCP, and tokio's single-threaded and work-stealing runtimes (two workers, and four), each over 50 seeds, in Debug, ReleaseSafe and ReleaseFast. It needed `dup` of an epoll set (mio duplicates its own; `dup`, `F_DUPFD` and `F_DUPFD_CLOEXEC` of a pipe end, an eventfd or an epoll set are emulated now) and it found two faults. In a test linked with libc the vDSO was never found, so it was never protected and a C library's clock reads were the host's, since revision 78: `std.os.linux.getauxval` has no vector to read when libc owns the program's start. Nothing reported it, because a run with no vDSO is a valid one. And revision 97's handling of a thread's signal to itself was never reached. Both fixed, with tests. A Rust program must run on a thread started inside the body, or the thread-local state its standard library seeds once (hash keys) outlives the run and the run is not a function of its seed; tokio's scheduler must be given a seed (`rng_seed`, behind `tokio_unstable`), because it otherwise takes one from a process-wide counter. A run that finds a vDSO and cannot trap it fails now.

Still not verified after revision 99: glibc; C++; a Rust program that is an executable and not a library linked into the test; tokio's blocking pool, signals and child processes; `dup` of a socket (`TcpStream::try_clone`) or a file, `dup2` and `dup3`, which are stray. A caught signal that a thread sends itself ran its handler outside the simulation, unreported; since revision 105 it fails the run. The libc clock test is behind `-Dsqlite`: the default suite links no libc, so it has no test of this.

**Revision 115: a reset is reported once.** Compared with Linux, the model reported a reset to every later call and lost the bytes that had arrived before it; Linux reads them, reports the reset once, then ends the stream and breaks writes. Fixed. One scenario of the comparison had never done what it said: its server read every byte, so its close was clean.

**Revision 113: a write to a connection the peer closed.** Compared with the real loopback, the model failed the writes that follow a peer's reset as reset, where Linux, having seen the peer's FIN first, fails them as a broken pipe and lets the read end the stream. Fixed; a datagram to a closed port agrees.

**Revision 111: programs that start other programs.** A test registers what each command does, and a spawn runs it as a simulated process, with pipes that hold 64 KiB and block as real ones do. Waiting for a child that waits for its input, or before reading more output than a pipe holds, is found as the deadlock it is.

**Revision 109: how often the security layer finds what it should.** A table for its oracles, like the core's: every planted bug of its tests found in every campaign of 200 iterations, no false alarm on a fixed program. One claim of a test did not hold: a hash seeded from the run's seed does not stop guided exploration, which keeps a parent's seed for the inputs it derives from it.

**Revision 108: the network model against the loopback, again.** Ten scenarios where there were five: large streams, several connections at once, and datagrams. The model agreed with Linux on all of them and with Windows wherever Windows agrees with POSIX.

**Revision 106: a thousand tasks.** Measured, a thousand tasks make a switch about twice as dear as two. A test runs a thousand tasks to their end, twice the same way.

**Revision 104: a hundred nodes.** The limit of 32 nodes was the width of one integer in the network model, and of a second one in the leak check that the first hundred-node test found. Both are 128 bits now. The security layer's tables stay at 32 nodes, and a check that asks for more with the layer attached is refused aloud.

**Revision 103: warm starts on three nodes, and when memory runs out.** Two tests for the paths of revision 93 that had none: the snapshots of several nodes' filesystems, and an allocation failing while a snapshot is taken or its pages are copied. They agree with cold starts and leak nothing; the review found, by reading, a page reference left behind when a snapshot of several nodes fails half way, now taken back.

**Revision 102: the fork server compared with one process.** The agreement test had cold against warm and one worker against four; it now has a forked child per run, and worker processes forking them, against a process that runs setup every time, on the simulator's own fuzz program. A second test puts failing runs, with their shrinking and replay, between warm starts, with a body that would see a wrong snapshot. Both agree; nothing was found.

**Revision 101: `dup` of a socket and of a file.** `dup` and `fcntl`'s `F_DUPFD` and `F_DUPFD_CLOEXEC` give a socket, a file or a directory a second number, sharing position and flags and closed with the last one; Rust's `try_clone` of a `TcpStream` and of a `File` run (`test/rust`, eight tests). Verified on Linux by the calls and by Rust; a review found three faults at the edges (an `mmap` of a duplicate that escaped the stray count, among them), fixed. Not done: `dup2` and `dup3`, which name the number and are mostly used to replace a real descriptor; they stay stray.

**Revision 107: C++, glibc, and a report of where two runs part.** A C++ program (`test/cpp`: threads, a mutex, a condition variable, both clocks, exceptions, streams, a synced file across a power loss, `std::random_device`) passes under system-call mode on musl and on glibc 2.41, and is part of `zig build test` on Linux, which had no libc-linked test before. It needed an answer to the `ioctl` by which musl's `fopen` asks whether a file is a terminal (every C program writing through stdio failed the run), and acceptance of glibc's `rseq` registration in a simulated thread (glibc aborts when it is refused). glibc's once-only draw of random bytes at a process's first thread made the first run of a seed differ from its replay; it was found by the new report, which prints the first event at which two runs of a seed differ where `NonDeterministic` printed two hashes. Verified on one glibc and one kernel, with one small program. Not verified: glibc linked statically, another glibc version, CI's Linux host (the tests fail there, and do not skip, if its C library does not run under the trap).

**Revision 110: SQLite and Rust on glibc.** Both pass on glibc 2.41 now (SQLite 7 of 7, the Rust crate with tokio 8 of 8), after two faults that SQLite found. Two tasks that met at a libc lock hung, because glibc's unlock wakes nobody while the process has never had a second thread and tasks are fibers on one: every run in system-call mode now starts one real thread first, once. And glibc's allocator opens a file under `/proc` once, late, which failed whichever run met it: that path is answered as missing. A stray call's report now names the file. Not verified: another glibc, a static glibc, the other files a C library reads once (named in `CHANGELOG.md`).

**Revision 112: the processor count.** A program that asks how many processors there are was a stray on glibc (C++'s `hardware_concurrency`, `sysconf`) and in Rust (`available_parallelism`, and tokio's runtime when no worker count is given). Four more files a runtime reads for this are answered as missing, each runtime then asks `sched_getaffinity`, and the answer is one on every machine. Tests in `test/cpp.zig`, `test/rust.zig` and the default suite. Not verified: another glibc, Rust or tokio; any other language's runtime.

**Revision 114: more than one processor.** `Options.processors` (1 to 64) is the count system-call mode tells the program, so a runtime that sizes itself by it can be tested at a size other than one: told of six, C++ and Rust report six and tokio's default runtime starts six workers. The threads are still simulated tasks, one at a time. Not verified: a runtime that pins threads (`sched_setaffinity` is a stray).

**Revision 117: the cost of a run.** Profiled on the bug benchmark (`plan3.md` E6, `docs/measurements.md` §5): a quarter of the instructions went to hashing trace events through Wyhash's streaming interface. One call over the same bytes gives the same hash: 16.5% fewer instructions, every trace hash unchanged. The keyed draw is second, at 9%.

**Revision 116: a web service, a name lookup, and `Options.prime`.** An HTTP/1.1 server and clients on hyper pass on both C libraries with no change. A host name looked up through the C library needed three: Unix-domain and netlink sockets refused with `EAFNOSUPPORT` where they were strays, `uname` answered, and `Options.prime`, one thrown-away run inside the simulation for a library that sets itself up once in the life of the process (glibc's lookup tables). The names are the ones the test writes to `/etc/hosts`. A stray's report gives its arguments. Not verified: another glibc; a name server; HTTP/2; TLS.

**Revision 118: a pair of connected sockets.** `socketpair` of the Unix domain, `SOCK_STREAM`, is answered in system-call mode (`src/sim/sysfd.zig`): two pipes, one each way, with the socket calls a pair needs (`recvfrom`, `sendto`, `shutdown`, the names, the options) and `poll` and `epoll` over it. Rust's `UnixStream::pair` between threads and tokio's between tasks pass on musl and glibc 2.41. Not emulated: datagram pairs, `sendmsg` and `recvmsg` (so no descriptor is passed), named Unix-domain sockets. A pair holds 64 KiB each way, less than Linux's. Not verified: a C or C++ program using a pair; libuv or libevent (their descriptor tables rule them out, revision 97).

**Revision 120: messages in pieces.** `sendmsg` and `recvmsg` are answered in system-call mode on IPv4 stream and datagram sockets (`src/sim/sysnet.zig`) and on a pair (`src/sim/sysfd.zig`): several buffers, the address in the header, `MSG_TRUNC` for a datagram that did not fit. `readv` and `writev` on a datagram socket now deal in whole datagrams (`readv` used to drop what did not fit in its first buffer). The `socket2` crate's vectored calls pass on musl and glibc 2.41 over UDP, TCP and a pair. Not emulated: ancillary data (so no descriptor passes, and no `IP_PKTINFO`), `sendmmsg` and `recvmmsg`, `MSG_PEEK`, a datagram of more than 4096 bytes sent from several buffers. Not verified: Boost.Asio (not installed here; it uses these two calls for everything, and `epoll` with a timerfd, which is not answered); a C program.

**Revision 121: where a stray call was made.** A stray call's report names any x86_64 call by the kernel's name and prints the stack the first one was made on, unwound from the signal frame (`src/sim/syscalls.zig`), in both modes and from a simulated thread. `docs/threads.md` says that `std.heap.smp_allocator` and `std.testing.allocator` ask for the processor count once per process. Not done: a stack for a vDSO clock read or for a call the emulator itself counts as stray.

**Revision 100: the last untried rows of the `fsync` rule on ext4.** Four more cases on the real filesystem: the one unsafe doubt (a write within a tick of the clock) could not be produced there, so the model takes the cautious side of it, and the two places where ext4 keeps more than the model (new blocks allotted at the sync) are left as they are and explained. A rename over a file with a full journal no longer hides the file's change from its own `fsync`.

**Revision 98: the model learns the commit interval, and `fdatasync`.** The two unsafe gaps revision 96 listed are measured on the real ext4 and narrowed (what is left is in `docs/power-cut.md`). The model keeps the time of the first change since the last commit, and after the persona's interval a change is no longer its file's own; it deliberately does not make anything durable by time alone, as ext4 does, but keeps what the periodic commit passed over within reach of the `fsync` of anything it names. `fdatasync` gets its own, narrower rule in the model and system-call mode stops treating it as `fsync`.

**Revision 96: the first rule of the crash model changed by evidence.** The power cut on a real ext4 (revision 94) showed the model keeping an unlink that ext4 loses when the `fsync` after it is of an unchanged file. The rule now asks, on `linux_ext4` (measured) and `linux_xfs` (from its source, not run), whether the synced file has changed since the last commit of everything waiting. The experiment was extended before and after a review, and corrected the rule three times: a directory's `fsync` commits everything on ext4 even when the directory is unchanged, and unsynced data alone, overwritten or appended, does not make a file's `fsync` commit anything else. What the model still lacks is a commit by time and a separate `fdatasync` (`docs/power-cut.md`).

**Revision 93: warm starts on every persona.** The limit revision 92 found (`plan3.md` E7) is removed: `Sim.Warm` keeps one snapshot per persona, and since a filesystem's pages can be shared with one snapshot only, the others hold copies, made when their persona's turn ends and written back when it comes again. The agreement test's cold-against-warm half now runs on three personas, with a setup whose content differs by persona so that a wrong page would be observed.

**Revision 92: the network under the simulator's own fuzz test, and the second CI run.** The self-fuzz test gained the network (`self_fuzz_net_test.zig`) and a comparison of configurations (`simulator agreement`): the same seeds on one worker and four, cold and warm, must observe the same things, measured as a sum of per-run hashes so that order does not matter. Neither found a defect. They did show that in a campaign over several personas no iteration's first run starts warm (`plan3.md` E7). The pushed commit's CI run failed on macOS and Windows in the filesystem differential test only; both sequences were regenerated locally from their seeds (the generator is a function of the seed and the host's kind), which gave one model fix (the order of `rename`'s checks on BSD kernels) and one more call the test does not make on Windows.

**Adversarial review (revisions 90 and 91), and what it changed.** Fixed: the run's own PCT draws and the first tasks' priorities shared decision keys (the body's task restarts the root's counters), so they were the same numbers, the paper's bound did not hold and the first table measured the skew (the run's draws now have a key path of their own, a new task's priority is drawn on its own keys, and the table was measured again: same conclusion, other counts); the bound on one task's steps in a row did not stop two tasks above a third that take turns by blocking (the bound is now on how long a runnable task waits, counted at every choice of a task); the tests of guided exploration, workers, fixed lengths and shrinking under priorities used a bug the random schedule finds too (they use one it does not find in that campaign, and say so by running it); the warm-start test never showed a warm start (it reads the warm report and counts setups); `exhaustive` under priorities enumerated one schedule (it now ignores the option); a replayed token wrote no trace; trace files were named by caller, persona and seed alone and overwrote each other (a taken name gets a number, the loop form passes its caller, a long name keeps its end); the trace tests could not tell the shrunk file from the found one; errors writing a trace were printed for unreported failures; and statements in the documents (the random schedule's switch rate, two change points at depth 3, the paper's bound, which tests leave files). Not changed: the security layer's own preemption points do not use their probability under priorities (documented); the benchmark's fixed programs all pass under priorities, which is now a column. Sound on review: initialisation of every field on every path, warm against cold, the priority bands, where the trace is written from and that the ring holds the failing run at each call.

**Revisions 90 and 91: a second schedule, and traces without code.** The scheduler switched tasks with a fixed probability at every operation, which reaches a switch at any one place quickly and a long uninterrupted stretch almost never. PCT is the known answer to the second, so it is now an option, built on the same keyed draws (a priority per task, the change points, a run length when none is given) so that shrinking and tokens need nothing new: with every draw benign all priorities are equal and the order is the one the random schedule has with every draw benign, until a task has waited 4,096 steps. One departure from the paper: when a runnable task has waited that long the task above it is demoted, because a poller above the task it waits for would otherwise run for ever. The measurement decided the default: the random schedule stays. A failing check can now write its trace to a directory, which closes the open half of C6: the trace ring already held the failing run at the moment of the report, so the file is that ring, and a longer trace is a matter of the ring's length.

**Adversarial review (revisions 88 and 89), and what it changed.** Fixed: the test for a refused thread asserted the spawn's error inside the body, but a run with a stray call returns `StraySyscall` whatever the body returned, so the assertion could not fail the test (the body now counts outcomes and the test checks them after the campaign); the package check searched the build's output for the names of the library's own dependencies, which says nothing when they are already in the cache (the fresh project now has a cache of its own and the check counts what lands in it); the line saying a call was refused was printed only when that call was the first stray one (the trap counts refusals); a baseline cell counted any failure of the buggy program (it must be the failure the default campaign finds); the comments of `syscalls.zig` still said every stray call is made; the changelog and the plan gave the spawn's error without saying it is the one without libc. Sound on review: the placement and encoding of the refusal, that the harness makes none of the four calls on a trapped thread, the replay command's state machine and its six call sites, the security label's length, the fingerprint of the generated project, the guides' options and defaults against the code.

**Revisions 88 and 89: more of the open rows.** The trap made every stray call again from inside its signal handler so that the caller saw what it would have seen; for a call that starts a thread that meant a child beginning inside the handler, so those four calls are now refused and the run fails cleanly. The replay line's command comes from the environment when a build script provides it, because only the build script knows which step runs a test. The security note in the trace carries the kind of finding. The package was fetched into an empty project from an archive of the tree, which is as far as B2 goes without the network. The bug benchmark gained ablation baselines, and the documentation is split by reader.

**Adversarial review (revisions 86 and 87), and what it changed.** Fixed: `netInterfaceName` is `unreachable` in `std.Io.failing`, is reachable without an earlier call (formatting a scoped IPv6 address) and was not on the list of entries that panic by name; `Dir.copyFile` goes through `fileWriteFilePositional`, which answers "unimplemented" so that std copies by reading and writing, and a later failure then named calls the program never made (those two entries are no longer wrapped; tested); the report said each refused call "failed", but setting timestamps does nothing and succeeds (reworded); calls refused during setup were missing from warm-started iterations (no snapshot is taken then); the comment of `Options.trap_syscalls` said the trap is off during setup on worker threads, which it is not, and did not say that system-call mode traps whatever the option says. In the guides: the precedence of options and environment, `fork` on macOS, what `diff_fs.trace` holds, which failures upload a log, the security note's label, and the claim that a started thread is reported cleanly under the trap (the handler makes the call again itself, so a `clone` onto a new stack most likely crashes). Left as it is: the receive buffers are allocated in the middle of a run, as the page pool's chunks are since revision 84, against the rule of no allocation after setup; both panic if the host has no memory. Sound on review: the initialisation and reset of the new state, workers and forks, the network change, the two examples and their fixes, the workflow.

**Revisions 86 and 87: what the simulator refuses, and the rest of the open rows that need no one else.** The `std.Io` table starts as `std.Io.failing`'s, which keeps an unmodelled call from the real system but answers with std's error and no word of who refused. Every entry still std's own is now behind a generated function that notes its name in the simulator before calling std's; the wrapper is made at compile time from the entry's type, so a new entry in a later Zig is covered without a change here. Reading that table showed that some of std's entries are `unreachable`, which a program asking whether a file is a terminal would have hit; those three are answered and the rest panic by name. `Options.trap_syscalls` became optional so that the environment can turn the trap on for a whole run while one check says no, which is what let CI run the suite trapped. The network's receive buffers moved to the first socket. Two examples plant bugs for `tardis.lin` and `tardis.elle`, and four guides (`docs/reproducing.md`, `trace.md`, `housekeeping.md`, `threads.md`) close C6, C9, H3 and D5 as far as documents can.

**Revisions 83 to 85: liveness, presets, memory, and what a release needs.** A run that stays busy without progress is now a finding: `Env.expectProgress` arms a watch with a bound in virtual time and in steps, `Env.progress` feeds it, and the scheduler ends the run with `error.Livelock` through the driver when a bound runs out, the way it ends a deadlocked run. The check sits at every scheduling point and at the simulated operations of a task that runs alone, where there is no scheduling point; the driver runs next without a draw, so the run ends at the same step on every replay. `Options.quick`, `.thorough` and `.nightly` and `TARDIS_PRESET` size campaigns. The filesystem page pool is allocated in 256 KiB chunks as used, which brings a default simulator from 10.2 MiB to 2.4 MiB (`docs/measurements.md`). `scripts/release.sh` makes a release locally in one command, `zig build docs` builds the API reference, and `zig build bugbench-rates` measures how often a campaign of a given size finds each planted bug.

**Adversarial review (revisions 83 to 85), and what it changed.** Fixed: the watch's steps were counted only where the simulator switched tasks or a task ran alone, so with two runnable tasks and no preemption drawn (a shrink candidate, `preempt_ppm = 0`) a spinning task was never stopped and the shrinker hung (every simulated operation is a step now; tested with shrinking on); a deadlock or livelock in a forked child returned through the driver the child had inherited, and the child carried on as a second test process (`Sim.child_abort`; the deadlock case predates the watch); a watch armed in setup was not in the warm-start snapshot (a snapshot is not taken then; tested); the liveness tests looped for ever without the watch, so a regression would have hung CI (their loops are bounded now); `expectProgress` with no bound was caught only by an assertion (it panics in every mode); `TARDIS_PRESET=nightly` turned guided exploration on for checks with `fork` or `keep_going`, which it changes (it leaves them); the memory benchmark's counting allocator was shared by worker threads without a lock; the release script restored `build.zig.zon` from the index (a failed commit left the version staged), took any unknown second argument for a real release, had no interrupt trap and used a GNU-only `\s`; `tardis.elle` reported nothing when every cycle through a component was longer than `cycle_max` (it reports the anomaly without a cycle, `Report.cycle_too_long`); `env.fuzz` of a float wider than 64 bits did not compile. Documented, not changed: `TARDIS_PRESET` cannot tell a written `.iterations = 100` from the default; the linearizability checker remembers states by a 64-bit hash, so a model's `hash` must separate its states (a collision can only give a false failure, never a false pass); in system-call mode a run ended by the watch may leave a C library's lock held, as one ended by a deadlock does.
- **Time and randomness.** `clock_gettime`, `gettimeofday` and `time` answer with the node's virtual clock; `nanosleep` and `clock_nanosleep` sleep in virtual time; `getrandom` draws from the decider's `random` stream. The same calls made through the vDSO, as libc and `std.os.linux` make them, are answered too (revision 78, below), and so is `getcpu` (processor 0).
- **Anything else is stray**, as before: noted, made for the thread, and the run fails with `error.StraySyscall` naming the first one.

**Built in revision 75, and what is verified** (Linux on WSL2, kernel 6.18, `x86_64-linux-musl`; `src/tests/sysmode_test.zig` unless another file is named):

- *Raw calls land in the simulated filesystem and meet a crash as `env.dir` writes do.* A body writes one file with `openat`, `write`, `fsync` and a directory `fsync`, and a second with no sync, then loses power. In a campaign of 300 runs on each of three personas the synced file always survives and the unsynced one is sometimes lost and sometimes kept. Then, seed by seed (200 seeds on each persona), the same program written with `env.dir` gives the same trace hash and the same bytes after the crash: the two ways in are one model.
- *The answers are the kernel's.* A differential test generates sequences of 32 calls (`openat` with ten flag combinations, `close`, `read`, `write`, `pread64`, `pwrite64`, `lseek`, `ftruncate`, `fsync`, `fdatasync`, `fstat`, `newfstatat`, `unlinkat` with and without `AT_REMOVEDIR`, `mkdirat`, `renameat`, `faccessat`, `getdents64`) and runs each once under the simulator and once on the real kernel (ext4) in an empty directory, comparing every return value, the bytes read, the kind and size a stat gives and the set of names listed. 20,000 sequences agreed when it was written; the suite runs 5,000. Getting there found four disagreements, each fixed in `sysemu.zig`: `faccessat` through a regular file (`ENOTDIR`, where `std.Io`'s `access` says not found), a transfer of no bytes on a descriptor not open for it (`EBADF`), `lseek` from the end of a directory (`EINVAL`), and listing a directory removed while open (`ENOENT`). Two things are left out of the comparison on purpose: seeking in a directory, and reading one after listing it, where ext4 answers from its own hash positions.
- *Blocking works.* Three tasks sleep in `nanosleep` at once, each inside the signal handler on its own fiber, and wake at their own virtual times; `clock_nanosleep` with an absolute deadline wakes at it; a hundred such runs take no real time to speak of.
- *Clock reads and `getrandom` follow the run*, when made as system calls: the monotonic clock equals `env.nowNs()`, and the same seed gives the same random bytes.
- *What is not emulated is still stray*: `socket`, and `pread64` on a descriptor the simulator did not issue, each fail the run with `error.StraySyscall`.
- *A planted bug is found, shrunk, replayed, and its fix passes*: `examples/syscall_rename.zig`, the rename-before-sync bug written with `std.os.linux` calls only, in the bug benchmark as its twenty-first program. It shrinks from 25 decisions to 1, as `rename_unsynced` (the same program through `std.Io`) does.
- *The done-when of `plan3.md` D9: SQLite.* `test/sqlite.zig` (`zig build test-sqlite -Dsqlite`) links SQLite 3.46.0's amalgamation, built with its own Unix VFS and no change but `-DSQLITE_OMIT_LOAD_EXTENSION`, into a test. It creates a table, commits two rows, loses power and reopens. With `synchronous=OFF` (the planted bug) the acknowledged row is lost or the file is damaged: found in a campaign of 100 runs on three personas and shrunk from 75 decisions to 1. With `synchronous=EXTRA` every run keeps the row. With `FULL`, SQLite's default, a run loses the acknowledged row, shrunk from 258 decisions to 2: the power loss undoes the unlink of the rollback journal, which `FULL` does not follow with a directory sync, and the next open rolls the commit back. That is SQLite's documented difference between `FULL` and `EXTRA`, found here without being looked for; with `faults.metadata_loss` off, `FULL` passes. Running SQLite needed three additions: the legacy forms of the calls (musl calls `open`, `stat`, `unlink` where Zig calls `openat` and the rest), `/dev/urandom` as a descriptor whose bytes are the decider's, and `sched_getaffinity` counted as the harness's own (Zig's libc `malloc` asks for the processor count on its first call).
- The whole Linux suite passes with the mode in the binary, and the Windows suite in the four build modes and with `-Dsec` (§10).

**Adversarial review (revision 75), and what it changed.** A read-only review of the mode found twelve issues; the confirmed ones that could be fixed are fixed and tested:

- *A stray reached the real machine.* A call the emulator declined (a path under `/dev`, `/proc` or `/sys`, a real directory descriptor) was still made for real, so `rename("/dev/shm/a", "state")` really moved a host file. In this mode a stray is now refused with `ENOSYS` and never made; a test puts a file in `/dev/shm`, makes the stray, and finds the file untouched.
- *A stray in a failing run went unseen.* `StraySyscall` replaced only a passing result. It now replaces any result, in both modes: a run that left the simulation proves nothing either way.
- *`printf` from C failed the run.* glibc's `fstat(1)` and musl's `ioctl(1, TIOCGWINSZ)` before the first output were strays. Those two, and `newfstatat` on descriptors 0 to 2, are now the harness's own calls.
- *`sched_getaffinity` had been let through in both modes,* so code under test could read the host's processor count. It is a stray again under `trap_syscalls`; system-call mode answers it with one processor, the same on every machine (tested).
- *Open-file-description locks were granted.* They conflict between two descriptions in one process, which is not modelled; `F_OFD_*` is now not emulated (stray).
- *Two open flags differed from Linux:* a directory opened for writing succeeded (Linux: `EISDIR`) and `O_RDONLY | O_TRUNC` did not truncate. Both fixed, and both flag sets added to the differential test, which then found a third case (`O_TRUNC` on a directory is `EISDIR` whatever the access), also fixed.

Not fixed, and recorded here:

- **A C library's mutex and several tasks** (found by the review; **fixed in revision 76**). Every fiber runs on one thread, and an emulated call can yield (a scheduling point, modelled latency, a sleep) from inside the signal handler. A C library that holds a pthread mutex across such a call, while a second task wants the same mutex, waited in a real `futex` call, which stopped the one thread for good: the run hung with no report. SQLite's Unix VFS holds a process-wide mutex across the `open` and `fstat` that find a file's inode, so two tasks with a database each was enough. Revision 76 answers `futex` in system-call mode: a wait blocks the calling task on the simulator's futex for that address, a wake wakes simulated waiters, and a timed wait times out in virtual time (`FUTEX_WAIT`, `FUTEX_WAKE`, their bitset forms, `FUTEX_REQUEUE` and `FUTEX_CMP_REQUEUE`, which wakes instead of moving; priority-inheritance operations and `FUTEX_WAKE_OP` stay stray). A deadlock between C locks is now the simulator's reported deadlock. Atomic emulated calls, the alternative considered, were not built: they would have hidden the interleavings this mode is for. Tested: a three-state mutex held across file calls by two tasks (it hung before the fix, and passes), and SQLite driven from two tasks with a database each (it hung until a 60-second timeout before the fix, and passes). **What remains:** a recursive mutex's owner is the thread, which every task shares, so a second task enters a recursive mutex another task holds (SQLite's connection mutex is recursive: share no connection between tasks); and a crash that drops a fiber while it holds a C library's mutex leaves the mutex held, so the next wait for it is a reported deadlock rather than progress. The same holds across runs: C statics belong to the process, not to a run, so a lock a run leaves held (a task dropped at the end of a run, or a crash, while it held SQLite's process-wide lock) is still held in the next run, which then reports a deadlock under a seed that passes when replayed alone; and every node of a run shares them. A lock shared with another real thread is outside the simulation too: only the trapped thread's `futex` calls are answered, so a wake from it never reaches a real waiter on another thread, and a real wake never ends a simulated wait.

A second review of revision 76 found that a timed wait decided `ETIMEDOUT` from the clock, after the wait, rather than from what ended it: a waiter a wake had picked, with its deadline also passed (a stepped wall clock, or a rounding nanosecond under drift), reported a timeout, and glibc's timed lock does not pass such a wake on, so a third task slept with the lock free. Fixed: the wait reports a timeout only when its deadline ended it, as the kernel does. Also fixed: a wait is no longer a cancelation point (a cancel turned into `EINTR` was spent on a libc that retries), and a null address faults on a wait and finds no waiter on a wake, as in the kernel.
- **Smaller gaps:** the differential test never uses a simulated directory descriptor or an absolute path; `lseek` and `fcntl` on the root descriptor return `EBADF`; seeking a directory before its first listing loses the position; a crash report from code that panics while trapped loses its symbols (opening the executable is emulated and not found); a fiber that changes the signal mask while another is parked in the handler can have the change undone; a bad non-null pointer passed to an emulated call faults the process where Linux returns `EFAULT`.

**Not verified, and the limits:**

- **The vDSO (closed in revision 78).** `time`, `gettimeofday`, `clock_gettime`, `clock_getres` and `getcpu` in libc and in `std.os.linux` are answered in user space and never trap, so they returned the host's time and nothing reported it. Now, while a system-call-mode run is on, the vDSO's code is `PROT_NONE` (`src/sim/vdso.zig`): a call into it faults at the function's first instruction, the SIGSEGV handler `tsc.zig` already installs finds the function by its address, answers it as the system call it stands for (from the simulator for the code under test; from the kernel for the harness and for other threads, which see the right time, slower), and returns as the function's `ret` would. Zig's and libc's lazy symbol lookups read the image's headers, so `begin` makes them first. A thread caught inside the vDSO when the protection begins, or a read of the image, lifts the protection for the rest of the run, which then fails with `StraySyscall` and says why. Only in system-call mode: under `trap_syscalls` alone the vDSO is still the host's, as before. Tested: clock reads through `std.os.linux.clock_gettime` give the run's virtual time, advance with an emulated sleep, and are the host's again after the run; SQLite, which reads clocks through musl's vDSO path, still passes its four tests.
- **C state left behind by a run (noted in revision 78).** A task dropped while parked inside an emulated system call (by a crash, or because the run ended) may have been inside a C library holding its lock or half way through changing its own state, which the next runs inherit. The simulator now records, for every parked task, whether it is parked inside such a call; a crash that drops one prints that it happened and the seed, and every later failure report in the same `check` names that run as the likely cause if the failure does not come back on replay (`tardis.droppedInCallSeed`). The end of a run drops daemons too, and is not counted: a server parked in `accept` is normal. It is a report, not a cure: the state is still inherited.
- **Sockets** are the second phase and not started; a socket call is stray. So are pipes, `dup`, `poll`, `mmap` of a simulated file (which keeps SQLite's WAL mode out) and `O_TMPFILE`.
- **Not modelled:** owners and permission bits (every file is 0644, owned by user 1000; `fchmod` and `fchown` succeed and change nothing), record locks (`fcntl` grants every one, which is what POSIX gives within one process, and the simulation is one process), `O_NOFOLLOW`, `O_SYNC`, `O_DIRECT`.
- **State a library keeps for the life of the process** is carried from run to run. SQLite seeds its random number generator once; the determinism re-run reported the second run of a seed as different until the test reset the generator at the start of the body. The simulator cannot reset memory it does not own.
- **Not run:** system-call mode on several worker threads, with guided exploration, and with the security layer attached; a kernel without syscall user dispatch (the mode should return `error.SyscallModeUnsupported` there; only the compile-time form of that is tested, on Windows). Forked iterations are refused: the mode runs every iteration in this process. `tardis.sim`'s loop form refuses the mode.
- **One persona family.** The differential test compares with ext4 only, and the emulation answers with Linux's errors whatever the persona.

## 10. Verification, CI and Benchmarks

**Test pyramid for TARDIS itself:**

1. **Unit tests:** RunQueue rank selection, Decider stream independence, page refcount conservation (`sum(refcounts) == live page references`, checked after every VFS test), journal prefix application, path parsing per persona, error-set casting.
2. **Semantic tests:** every implemented VTable entry against its documented contract (cancel consumed once, `recancel` re-arms, group await propagates cancel, futex value check, short reads honored by `Reader`, and so on).
3. **Determinism tests:** each example run twice per seed with equal trace hashes. The same suite under `-OReleaseFast` must produce the same hashes as Debug.
4. **Bug-finding tests:** deliberately buggy SUTs that TARDIS must catch within N iterations: missing fsync, rename without fsync on xfs, missing dir fsync under `posix_strict`, open-file delete on NTFS, `async`-vs-`concurrent` deadlock, futex lost-wakeup. Each asserts the failure is found, not just that the test passes.

**CI matrix (target):** `{x86_64-linux, aarch64-macos, x86_64-windows} × {Debug, ReleaseSafe}`. Cross-host determinism job: compute the trace hashes of the example suite on each host and diff them.

**Cross-host status:** Windows x86_64 (all four modes) and Linux x86_64 (`x86_64-linux-musl` cross-compiled, run on WSL2, Debug and ReleaseSafe) pass the full suite. The golden trace hash recorded on Windows matches on Linux, which confirms cross-host determinism for that scenario and exercises the System V fiber path. macOS and aarch64 are untested.

**Benchmarks** (`zig build bench`, ReleaseFast). Measured on one x86_64 machine with 20 CPUs; compare on one machine, not across machines.

| Metric | Target | Windows 11 | Linux (WSL2) |
|--------|--------|-----------|--------------|
| Empty run (`check` with a trivial body) | < 10 µs | 4–7 µs | 6 µs |
| File scenario (4 KiB write + fsync + read + power loss) | — | 8–11 µs/run (90–120k runs/s) | 10–12 µs/run |
| Scheduler round trip (sleep, 2 tasks) | — | 170–470 ns | 310–400 ns |
| Loopback TCP echo (connect, write, read, close) | — | 9–16 µs/run | 12 µs/run |
| File scenario, 8 workers | — | 415–467k runs/s (5–6.5x) | 324k runs/s (3.3x) |
| Torn rename: find + shrink 27 → 1 | — | ~1.2 ms | ~2–5 ms |
| Fork per iteration (fixed cost) | < 200 µs | n/a (in-process) | 260–310 µs |
| Fork per iteration, 8 worker processes | — | n/a | 165–195 µs/run (5–6k runs/s) |
| Guided: open a six-digit lock, 1 / 2 / 8 workers | — | 31 / 19 / 13 ms | 29 / 20 / 20 ms |

The empty-run target is met: it came down from 29 µs to 4–7 µs in M5 by bounding resets with high-water marks and keeping timers in a compact array, and to about 1.6 µs on Windows when the filesystem's reset stopped rebuilding its whole free-page list (2,047 entries per node) every run. A page high-water mark (`Vfs.page_hwm`) says which pages a run took; only the top of the list and the references below the mark are rewritten. The same change took one execution of the exhaustive search's 3-node model from 28 µs to about 14.5 µs. (Quiet runs; this machine's timings swing by 2x and more under load.) The fork-server target is missed on this machine; the in-process snapshot of §9 M5 beats it (21–98 µs per warm start). Timings on this machine vary by up to 2x between runs; use them for comparisons within one session.

---

## 11. `std.Io` VTable Coverage Matrix

| Group | Entries | M1 | Planned |
|-------|---------|----|---------|
| Tasks | async, concurrent, await, cancel | ✅ | |
| Groups | groupAsync, groupConcurrent, groupAwait, groupCancel | ✅ | |
| Cancel | recancel, swapCancelProtection, checkCancel | ✅ | |
| Futex | futexWait, futexWaitUncancelable, futexWake | ✅ | |
| Time | now, clockResolution, sleep | ✅ (per-node drift and NTP steps since M2) | |
| Random | random, randomSecure | ✅ | |
| Streaming ops | operate(file_read_streaming, file_write_streaming, net_read, net_write, net_send, net_receive) | ✅ | |
| Batch | batchAwaitAsync, batchAwaitConcurrent, batchCancel | ✅ | |
| Dir | createDir(Path)(Open), openDir, stat, statFile, access, createFile, openFile, close, deleteFile, deleteDir, rename, **read** | ✅ | |
| Dir (links) | symLink, readLink, hardLink | ✅ | |
| Dir (atomic files) | **createFileAtomic** (named temporary + `replace`/`link`), **renamePreserve**; so `copyFile` works | ✅ | |
| Permissions | **dirSetPermissions, dirSetFilePermissions, fileSetPermissions**: accepted and traced, not modelled | ✅ (no-op) | model modes later |
| Dir (more) | realPath(File), other set* (owner, timestamps) | ❌ | later |
| File | stat, length, close, read/writePositional, seekBy/To, sync, setLength, **lock, tryLock, unlock, downgradeLock** | ✅ | |
| File (links) | hardLink | ✅ | |
| File (more) | writeFile*, mmap family, set*, realPath, tty | ❌ | mmap later |
| Process | **processSpawn, childWait, childKill**: programs the test registers (`Env.registerProgram`), with pipes (revision 111) | ✅ | |
| Process (more) / stdio | processReplace, executable path, current directory, lockStderr, … | ❌ (failing) | not planned |
| Net (stream) | netListenIp, netAccept, netConnectIp, netClose, netShutdown, netLookup, netWriteFile (`Unimplemented`) | ✅ | |
| Net (datagram) | netBindIp | ✅ | |
| Net (other) | netListenUnix, netConnectUnix, netSocketCreatePair, interface names | ❌ (failing) | not planned |

---

## 12. Errata: Changes from the v1 Draft

| # | v1 claim | Problem | v2 resolution |
|---|----------|---------|---------------|
| E1 | "`<0.4 µs` restore" while copying 20–300 dirty 4 KiB pages | 300 pages is 1.2 MiB. At about 20 GB/s that alone takes about 60 µs, so the claim is off by roughly 100×. | No restore numbers until M5 benchmarks exist (§10). |
| E2 | Fixed virtual reservation at `0x7000_0000_0000 + (W << 30)` on all 64-bit hosts | Fixed-address mapping is not portable: macOS and Windows ASLR, and existing mappings at that address. Wasm has no `mmap` at all. | M5 uses hint-addressed arenas plus offset-relative hashing. M1 does not need fixed addresses because it never hashes pointers. |
| E3 | Card marking "inline via TSan/SUT store instrumentation" | Running an instrumentation callback for every store is not a "1-cycle" fast path. (This row first said Zig has no store-instrumentation pass for Zig code. It has one, `sanitize_thread`, usable only for code built as a separate object: `plan2.md` §3.8.) | Dirty tracking uses OS write-watch or `mprotect` in M5. No compiler-dependent card marking. |
| E4 | `-fsanitize-coverage=inline-8bit-counters,trace-cmp` on SUT modules | These are clang flags for C. Zig code uses its own `-ffuzz` instrumentation. | M3 uses Zig's fuzzer instrumentation. Clang flags apply only to C dependencies. |
| E5 | Wasm32/Wasm64 fiber support and in-browser replay of the same run | `std.Io.fiber` has no Wasm backend. The stack-switching proposal is not broadly shipped, and Asyncify changes code shape. | Wasm is out of scope until a stack-switching backend exists. The trace viewer (M6) consumes exported traces instead. |
| E6 | Windows TEB `GuaranteedStackBytes` at `0x1720` | On x64 that field is at `0x1748`. Only `StackBase`/`StackLimit` (`NT_TIB` at `0x08`/`0x10`) matter for `__chkstk` and unwinding. | M1 updates `NT_TIB.StackBase/StackLimit` only. Other fields are added if a concrete failure needs them. |
| E7 | "Set x87 precision control to 64-bit (`PC = 10`)" and cross-ISA bit-identical floats | `PC = 10b` is 53-bit (double) precision, not 64-bit. Cross-ISA bit-identical floating point also cannot be guaranteed by control registers alone (FMA contraction, libm differences). | Float determinism across ISAs is a non-goal (§1.2). TARDIS itself uses no floating point. |
| E8 | Windows `ProcessInstrumentationCallback` / `Wow64Transition` hooking | Undocumented, fragile across Windows builds, and flagged by EDR software. | M6 research only, Linux syscall user dispatch first. |
| E9 | Hierarchical timing wheel and RunQueue512 + BMI2 `pdep` as M1 requirements | Premature: M1 has ≤ 64 tasks per run, where a linear scan is faster and simpler. | The benchmark was run (§9 M2): a timer heap and a portable select replaced both scans; the wheel and `pdep` were not needed. |
| E10 | 1 GiB per worker × 64 workers + 128 GiB TSan shadow reserved up front | Exceeds commit limits on Windows and many CI containers. It also assumes the fixed address of E2. | Per-worker `Sim` instances sized by `Limits`. |
| E11 | `.data`/`.bss` clone-on-switch per node | Requires relocating or aliasing image sections, and fails with TLS, `dlopen` and relocations into those pages. | M6 research. M2 multi-node assumes the SUT keeps no mutable globals (documented requirement). |
| E12 | Marionette-compat shim (`tardis.compat.marionette`) | Depends on another project's API, which is a moving target. | Dropped from the plan. Revisit if users ask. |
| E13 | Linearizability via `recordComplete` "online prefix pruning" in Region C rolled back by restore | Coupled the oracle to snapshot internals. | Oracles in M4 are plain data structures owned by the test, independent of M5. |
| E14 | Inconsistent memory budgets (Region C "512 MiB exact" while also adding 160 MiB "headroom") | Arithmetic presented as a proof but not checkable. | All limits are runtime `Limits` fields with defaults, validated in `Sim.create`. |

---

## 13. Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| `std.Io` VTable churn between Zig releases | Breaks compilation | Pin the Zig version. A comptime check builds the VTable by overriding `std.Io.failing`, so new entries default to failing instead of breaking the build. |
| Stack overflow in fibers | Memory corruption | A guard page below each stack (`VirtualProtect`/`mprotect`), and a canary check per switch. Configurable stack size. |
| SUT bypasses `std.Io` | Silent non-determinism | Determinism self-check. Document the requirement. M6 interposition. |
| Abandoned fibers on crash skip `defer` | Resource accounting drift | The SUT heap is an arena reset on crash. Handles live in TARDIS tables. Nothing host-side leaks. |
| Exploration that is too weak (pure random) | Bugs missed | Swarm testing plus personas now. M3 guided search. |

---

## 14. M1 Implementation Notes

Findings from building M1. They are recorded because they validate (or refine) the design.

1. **The determinism self-check paid for itself immediately.** On its first run it flagged every filesystem test. The cause: the VFS boot epoch kept counting across runs, so handle values, which are in the trace, differed between two runs of the same seed. Fix: reset the epoch per run (§6.1). This is exactly the class of bug §7.4 exists for.
2. **Short-I/O injection found a bug in TARDIS's own test suite.** A test used a single `readPositional` and assumed a full read. TARDIS returned 5 of 10 bytes and the test failed with a replay seed. The same mistake in SUT code is the most common partial-I/O bug.
3. **`std.Io.failing` as the VTable base** made the implementation robust to VTable growth. Every entry not yet simulated fails safely, and the VTable is assembled at comptime by overriding fields.
4. **Zig 0.17 API drift seen while building:** `@typeInfo` uses `field_names` / `error_names` / `mode`, `std.meta.Int` became `@Int`, array repetition `**` is gone (use `@splat`), and `futexWait`/`futexWake` take a type parameter. The plan's code snippets use 0.17 spelling.
5. **The build runner flags any stderr output.** Hence `Options.report`: tests that *expect* TARDIS to find a bug turn reporting off, so `zig build test` output stays clean.

### 14.1 M2 notes

1. **`posix_strict` found a bug in the M2 test suite's own "correct" server** on the first run. The KV server fsynced its log before acknowledging but never fsynced the directory after creating the log, so under `posix_strict` the file's directory entry, and with it every acknowledged write, could vanish. That became test (b) of §1.4, and the correct server now syncs both.
2. **The first ack-before-fsync server was not caught**, because its fsync ran a few microseconds after the reply, well inside one network latency. The bug only shows when power can fail between the ack and the fsync. Two changes made it catchable: the realistic variant (group commit on a 20 ms timer), and a fuzzed delay before the crash. Lesson for M3: crash *timing* needs to be an explored decision, not only crash *placement*.
3. **Keeping old seeds stable while adding features.** New Decider streams (`net`, `clock`) and new fault classes appended to the end of their enums leave every existing decision sequence intact. The M1 golden hash did not change.
4. **Daemons and leak checks.** Daemon tasks legitimately outlive the test body and hold sockets, handles and memory, and a node crash strands whatever its tasks held in the shared heap. The first version therefore skipped resource leak checks once a run started daemons. Per-node heaps fixed that: a node crash wipes its heap, and only nodes that still run a daemon are skipped.
5. **`Sim.vfs` as a pointer switched with the task** kept the M1 filesystem code unchanged: every VTable entry still says `s.vfs`, and multi-node came for free.
6. **`Batch` falls out of non-blocking steps.** Splitting each network operation into a single non-blocking attempt gave `operate` (loop and wait) and `batchAwait*` (try all, wait for any) from the same code. Leaving incomplete operations on the `submitted` list instead of a private pending list means `Batch.cancel` needs no simulator work at all.
7. **Spurious wakeups as a design tool.** Waiting for "the next network event anywhere" and re-checking is simpler than tracking per-socket waiters, and still deterministic. The cost is extra context switches in busy clusters, which M5 can measure.
8. **`auto_da_alloc` protects the renamed inode, not what it points at.** A deploy that swaps a symlink to an unsynced release directory loses the release on ext4 too, because the inode ext4 flushes on rename is the link. `link_test.zig` keeps this as a regression test.
9. **Following symlinks without recursion.** Each expansion rewrites the remaining path into one of two alternating fixed buffers (`target ++ "/" ++ rest`) and continues the same loop. That keeps the VFS free of recursion and allocation, with a 40-hop limit like Linux.

### 14.2 M3 notes

1. **"Zero means nothing happened" made the shrinker almost trivial.** Once every call site maps a raw 0 to the boring outcome, shrinking does not need to know what a decision *means*. It only removes decisions from the kept set, and the run drifts toward no faults, no preemption, no crash loss and minimal input by itself. Two places had to be flipped for this: crash decisions (0 used to mean "lose it") and fuzz boundary values (0 used to select the boundary path).
2. **Deriving values from keys, not a stream, is what makes ddmin converge.** With sequential streams, removing one decision shifted every later value in that stream, so candidate runs were unrelated to the original. With per-task keys, removal changes only what depends on it.
3. **Narrowing to "decisions actually drawn"** after each successful step removes dead keys for free. In the torn-rename case most of the 27 decisions vanish in the first accepted candidate.
4. **The shrunk trace tells the story.** Latency decisions are zeroed, so virtual time stays at 0 and the 16-event window covers the whole scenario: write the temp file, rename, sync the directory, *one* crash decision, read, assertion.
5. **The cost of keyed values was one deliberate golden-hash change.** No statistical test needed retuning: every bug-finding test still finds its bug within its iteration budget.
6. **Forced values were the missing half of the overlay.** Shrinking needed "these natural, the rest zero"; mutation needs "these forced, the rest natural". One `Overlay` with both fields serves shrinking, guided exploration, and shrinking *of* a guided failure, and one token format replays all three.
7. **Guided exploration needs few, meaningful features.** Coverage counts only simulator events that reflect behaviour (I/O, faults, errors, assertions). Scheduling events are excluded, because every interleaving would otherwise look new and flood the corpus. `env.cover` values should be small states (a depth, a protocol phase), not raw data.

### 14.3 M4 notes

1. **Oracles compose with everything before them.** The stale-read test uses nodes, the virtual network, daemons, fuzz input, swarm faults and shrinking at once. The checkers are plain data structures fed by the test, as errata E13 intended, so none of that needed special support.
2. **Unobserved appends needed one inference.** Elle's version order comes from reads, so a committed append that no read observed has no position. It must come *after* the longest read (an earlier position would have made it visible), which gives the anti-dependency that turns "read an empty list after the append finished" into a real-time cycle.
3. **Pending operations need care in both checkers.** For linearizability, a pending operation may be placed anywhere after its invocation or never. The search succeeds once every *completed* operation is placed, and pending returns sort last, so they never block. In Elle, unknown transactions contribute writes but not reads.
4. **Memoization uses a hash, not the set.** The cache key mixes a Zobrist hash of the linearized set with the model state hash. A collision could prune a branch and so hide a violation. The probability is negligible at 64 bits, and the trade keeps the cache at 8 bytes per explored state.
5. **Chaos testing found a TARDIS bug on its first run.** When a link healed, held segments were released only for receivers whose sender still existed. A sender that wrote a request and then closed during the partition left its data, and its FIN, held forever, so the receiver hung and the run deadlocked. Receivers now remember the sending node (`peer_node`), so release does not depend on the sender. `net.zig` keeps a regression test.
6. **A liveness bug needs a realistic timeout to show.** TCP-like holding of segments makes forwards survive short partitions, so fire-and-forget replication looked correct until its forward used a 100 ms connect timeout, as real code does to avoid stalling the primary.
7. **Performance numbers are exact.** Virtual time and byte counts are deterministic, so write amplification comes out as exactly 256x and 16x, and an SLO assertion is as replayable and shrinkable as a correctness one.

### 14.4 M5 notes

1. **Measure before optimizing paid off immediately.** The first benchmark showed an empty run costing ~29 µs and 8 workers giving only 2.3x. Bounding the VFS dentry tables by high-water marks halved per-run cost without changing any decision or trace.
2. **The fork server is a baseline, not a win by default.** Forking this process costs ~300 µs because of its large mappings (64 fiber stacks of 256 KiB, VFS page pools). It only beats re-running setup when setup costs more than that. The benchmark prints the crossover so users can choose, and user-space restore now has a concrete number to beat.
3. **Forking from inside a fiber works.** The child resumes on the same (copied) control-fiber stack with the whole simulation intact, including daemons spawned during setup. It must leave with `exit_group`, never by returning through the test runner.
4. **Determinism across threads needs only "lowest failing iteration".** Workers race freely, but every iteration below the current best failure is still run, so the answer is the same as on one thread, and so are the shrunk replay token and the merged `sometimes` outcomes.
5. **Cross-host determinism is now checked, not assumed.** The WSL2 run reproduced the Windows golden trace hash on Linux, through a different fiber ABI, kernel and libc-free build.
6. **Counts from forked children must be deltas.** Each child inherits its parent's assertion catalog. Sending it back whole doubled the counts every iteration until they overflowed. The first multi-process test found it (in Debug, an integer-overflow panic). Children now zero their copy first.
7. **Small data layouts dominate a simulator this cheap.** At ~5 µs per run, a 512 KiB memset or a scan over 2 KiB-strided structs is most of the cost. Bounding work by high-water marks and keeping hot fields in compact arrays gave a 4-7x total speedup in M5 without changing a single decision.

---

## 15. Open Questions

1. Should `async` inline execution be the *default* exploration (to flush out `async`/`concurrent` misuse early) or opt-in? M1 uses 20%.
2. Should `posix_strict` be in the default persona set for `check`? It finds real bugs, but it also flags code that is correct on ext4.
3. What should the replay token format be in M3: a base64 overlay, or a file under `.zig-cache/tardis/`?
4. Should `macos_apfs` model `fsync` without `F_FULLFSYNC` as non-durable? That is what real Macs do, so every Zig program would fail it until `std.Io` can request a full sync. Could this be a separate `macos_apfs_volatile_cache` persona, or an upstream proposal for a `File.sync` durability option?

## Open items

What both plans still leave open, and why. Everything else in them is implemented and tested, or reported as not worth building, where it is described.

**Closed in revision 72: vector registers lost across a fiber switch on 64-bit Windows.** Revision 71 recorded a crash on Windows in ReleaseFast after a deadlock, cause unknown. The cause: 64-bit Windows requires a callee to preserve `xmm6` to `xmm15`, and the function that switches fibers (`Sim.reschedule`) did not. The switch itself comes from `std.Io.fiber.contextSwitch`, whose inline assembly names the vector registers as clobbered; that stops the function from relying on them, but the compiler does not save them on the caller's behalf, as the emitted assembly shows (the prologue pushes the general registers only). An optimized caller that kept a value in `xmm6` across a call that switched fibers got back what another fiber had left there: ReleaseFast kept a zero vector in it, and a field set to null read as all ones. It affected every fiber switch on Windows in every build mode; only ReleaseFast kept values in those registers long enough to show it. `fiber.switchTo` now saves the ten registers on the fiber's own stack and puts them back when it resumes, and a test fills them from another fiber and checks them (it fails without the fix). Zig's own users of `contextSwitch` on Windows may have the same problem; that has not been reported upstream.

| Item | Where | Why it is open |
|---|---|---|
| A run on macOS or a BSD | §10, §9 M5 | No such machine has run the suite. It compiles for `aarch64-macos`, with guard pages and the libc fork server. Since revision 56 `.github/workflows/test.yml` runs the suite on GitHub's Linux, macOS and Windows runners; it has not run yet, since the repository has not been pushed. No BSD job: GitHub hosts no BSD runner. |
| ~~The first run of the evidence workflow on GitHub~~ **closed**: it passed on GitHub at commit `e66ee33`, every step, with one SARIF upload per bundle. What follows is the history. | `plan2.md` §8 | The repository has not been pushed. The workflow's steps were dry-run on Linux (WSL2) with the same commands: the certification campaign with `-Dedges` in ReleaseSafe, the dead-edge check on both bundles, and `tardis replay-evidence` on both. That found one bug, now fixed: a bundle that names no repository made the revision check's `jq -e` fail. The revision check itself (it needs a git commit), the checkout of both repositories, and the two upload steps are unrun. |
| Shadow memory: the twelve-state `ShadowCell` | `plan2.md` §3.1 | A three-state shadow of the heap runs for code built as an instrumented object (`plan2.md` §3.8, revision 52); the earlier entry here, that Zig emits no load or store callbacks, was wrong. Still open: the per-byte uninitialized, secret and tenant states of §3.1 (content tracking, §3.7, covers them at the I/O boundary), stacks and globals, and instrumenting the test itself, which Zig prevents by linking its own sanitizer runtime into any executable with an instrumented module. |
| A snapshot of process memory | §9 M5 | Exists on Linux as the fork server, where the kernel copies everything. An in-process one cannot be sound: a setup that leaves tasks or heap blocks leaves pointers into memory the simulator does not own (the test's allocator, its globals), which the body changes and a snapshot of the simulator's own arenas would not put back. The arena design of §9 M5 assumed every allocation of the code under test could be moved into one arena; `check` takes the caller's allocator. So: fork where there is one, the simulator-state snapshot for setups that leave files, setup re-run otherwise. |
| Snapshot restore in the exhaustive search | `plan2.md` §7.2 | No-go by measurement at the size of model the search handles. `zig build bench` runs the 3-node vote model: one execution, replayed from the start, cost 28 µs when this was measured (about 14.5 µs since the free-list change of §10), and the whole reduced search (3,073 executions) took 84 ms. A forked copy costs 344 µs (§9 M5), twelve times a replay. A snapshot would have to hold fiber stacks and the test's own memory, which is the process-memory snapshot below. |
| Lock order for `std.Io.Mutex` | `plan2.md` §4.2 | Its uncontended path never calls the simulator, so core cannot see the acquire. In an instrumented object the acquire is a reported compare-and-swap (`plan2.md` §3.8), and since revision 54 a 32-bit atomic that goes from zero to non-zero and back is taken for a lock and checked for order (`plan2.md` §4.6); that shape is a guess, and `tryLock` is not told apart from `lock`. Open: code that is not built as an instrumented object. `tardis_sec.Mutex`, file locks and C mutexes are covered. `std.Thread.Mutex`, which this row also named, does not exist in Zig 0.17. |
| Flight recorder, `rdtsc` trapping, vector clocks | §9 M6 | Research items. The recorder is a no-go; §9 M6 gives the reasons. `rdtsc` is answered with virtual time since revision 55 (`Options.virtual_tsc`, Linux x86_64 only). The vector-clock race detector runs for instrumented objects since revision 53 (`plan2.md` §4.5); for an ordinary Zig build it stays impossible, as no access is reported. |
