# TARDIS-SEC (Layer 7): Modular Deterministic Vulnerability, Byzantine, Side-Channel & High-Assurance Certification Specification

*A Standalone, Comptime-Hooked Security Auditing, Formal State-Machine Verification, and EAL7 / DO-178C / FIPS 140-3 Evidence Package (`tardis_sec`) for TARDIS (`std.Io`)*

| | |
|---|---|
| **Document** | Companion Specification II to *TARDIS: Architecture & Engineering Specification* (`plan.md`) |
| **Package** | `tardis_sec`, in this repository under `src/sec/` as the module `tardis_sec` (`zig build test-sec`); it imports core only through `tardis`'s public API and can move to its own repository (`tardis-sec/`, §8.1) unchanged |
| **Toolchain** | Zig `0.17.0`, the same pin as core |
| **Status** | Design specification with a compiled SDK (§8.3) and a live content engine on core's seam (§3.7). Every claim carries one of the tags below. |
| **Revision** | 57. Each revision's changes are in [CHANGELOG.md](CHANGELOG.md). |

**How to read the claims in this document.** It specifies a security layer for a simulator whose core is still being built, so every capability is tagged:

| Tag | Meaning |
|---|---|
| **[Verified]** | Implemented in `src/sec/` (the SDK in §8.3 and the engine in §3.7), compiled with Zig 0.17.0 against the current core `tardis`, and covered by tests that pass in all four build modes (`zig build test-sec`: 119 tests: 40 in the module (11 SDK, 18 for the engine, the shadow, the race detector, the Spectre detector, race state, amplification, MC/DC, the registry, the bundle and git revisions, 4 for dead edges, 3 for the git object store, 2 that pull the files in), 13 Pillar I (3 of them for seam 4), 19 Pillar II–III and 10 Pillar IV–V simulation tests, 8 for the C shims (with C built against the header), 6 for the C tracer, 15 for shadow memory, data races and lock order (§3.8, §4.5, §4.6), 2 for Example 1, 5 for Example 2, 1 declaration check). |
| **[Design]** | Fully specified here, but needs one of the core seams in §2.1 that core `tardis` does not expose yet. |
| **[Target]** | A performance or capacity figure that is a requirement, not a measurement. |

**Prerequisites in core TARDIS.** This specification names core subsystems by their Layer 1–6 design names. Several of them do not exist in core `tardis` today. Each row below is a precondition for the **[Design]** parts that use it, and §8.7 schedules them:

| Name used here | Core today (`plan.md`, `src/`) | Gap |
|---|---|---|
| Chrono-Slab `64 x 1 GiB` strided worker arenas, `worker_base(W)` | Each worker thread owns a `Sim`; its SUT heap is an arena (`alloc.zig`) at addresses the OS picks | Fixed-address arenas reserved at `arena_window_base + (W << 30)` |
| `<0.4 µs` card-marking CoW snapshot, `Control.restore()` | Linux fork server, ~260–310 µs per iteration; user-space restore is an open M5 item | User-space snapshot/restore of the arena and Region C |
| Region A (SUT heap) / Region C (simulator tables) | One `Sim.create` allocation for simulator tables; SUT arena separate | Named regions with `reserveRegionCHeadroom` |
| `RunQueue512`, fibers | `sched.zig`, `Limits.tasks_max = 65` | none for this spec |
| `tardis.atomic` store buffers, TSan shadow | not implemented | Shadow memory window and a vector-clock epoch per fiber |
| C-ABI / syscall shims | header shims for linked C since revision 27 (`src/sec/c/tardis_sec.h`); no syscall interposition, so C I/O outside `std.Io` is not simulated | The C sinks in §5.2 |
| `CausalKey` (3-cycle) | Decision keys `(stream, task spawn path, counter)` (`decide.zig`) | Same idea; renamed |
| `VisitedKeyCatalog` | Coverage map + corpus (`explore.zig`) | Same role; needs the extra coverage features of §§4, 6, 7 |
| 64-iteration Epoch Barrier | Parallel guided exploration in epochs of `epoch_iterations = 64` | Exists |
| `.tardis_persist` | not implemented (the corpus lives in memory) | An on-disk campaign directory |
| `io_vtable.zig`, `det_allocator.zig`, `vfs_persona.zig`, `net_fabric.zig`, `causal_tree.zig` | `Sim.zig` (VTable), `alloc.zig`, `vfs.zig`, `net.zig`, `decide.zig` | Hook call sites for allocation, free, heap wipe and every byte read or written through `std.Io` **exist** (`src/sim/sec_seam.zig`, §2.2). So do a VFS-operation hook (checks and opens) and a datagram-rewrite hook (revision 3). Hooks on locks and scheduling decisions do not; locks are checked through `tardis_sec.Mutex` |
| `u.createCluster` | `env.spawnOn(node, …)` (original M2 `createCluster` was not built) | Cluster helper |
| `tardis reduce`, DetSan | The shrinker inside `check` (decisions + values), `determinism_check_every`, the golden trace hash | none: the layer keys shrinking on its finding through `Provider.finding_key` (seam 4, revision 6) |

Two limits shape the whole design and are stated once here:

1. **Zig does not instrument loads, stores or comparisons.** Zig 0.17's `-ffuzz` instrumentation emits inline 8-bit edge counters, a PC table and an indirect-call hook (`lib/fuzzer.zig` exports `__sanitizer_cov_8bit_counters_init`, `__sanitizer_cov_pcs_init`, `__sanitizer_cov_trace_pc_indir`), and nothing else. C code built with `zig cc` can use clang's full SanitizerCoverage and `-fcoverage-mcdc`; I checked that `zig cc -fprofile-instr-generate -fcoverage-mapping -fcoverage-mcdc` produces an object carrying LLVM's `.lprfb` MC/DC bitmap section. So shadow-memory checks (§3) run where a hook runs: in the allocator, at every `std.Io` boundary, in explicit `tardis_sec.load`/`store` and comparison wrappers, and in instrumented C code. Plain Zig pointer dereferences and comparisons between hooks are not checked until Zig offers such instrumentation (§3.6).
2. **A tool does not certify anything.** `tardis_sec` produces evidence that an evaluation lab, a certification authority, or a safety assessor may accept, and its qualification follows each standard's tool rules (DO-330, CC ALC_TAT, ISO 26262-8 §11). "Proof" here always means *within a stated bound and within the simulated model* (§7.2).

---

## 1. Executive Summary, Modular Seam & High-Assurance Certification Matrix

### 1.1 What `tardis_sec` is

Core `tardis` runs a program's `std.Io` (scheduling, filesystem, network, clocks, randomness) inside a deterministic simulation, injects faults, and shrinks every failure to a replay token. `tardis_sec` adds **Layer 7**: security oracles that only a deterministic, whole-system simulator can run.

- **Memory safety and secrets:** a 16-byte `ShadowCell` per 8-byte word records each byte's state (uninitialized, freed, secret, untrusted, tenant) and catches leaks at the egress point.
- **Concurrency and race attacks:** double fetches, lock-order inversions, and filesystem time-of-check/time-of-use races, with the scheduler steering into the race window.
- **Byzantine protocols:** in-flight frame mutation that keeps checksums valid, so the mutation reaches the protocol logic, plus split-brain equivocation.
- **Resource and timing attacks:** amplification ratios (DoS), constant-time and non-interference by dual execution, and simulated instruction-skip glitches.
- **Assurance evidence:** MC/DC coverage, bounded exhaustive exploration, requirement traceability, SARIF output, and a signed evidence bundle.

### 1.2 Why a comptime-hooked package, not a wrapper

An outer wrapper (a second `std.Io` around core's, or a second allocator around the arena) costs three things that a comptime seam does not:

| Wrapper cost | Why it happens | The seam's answer |
|---|---|---|
| **Double shadow lookups** | The wrapper keeps its own shadow beside core's race-detector shadow; every access maps two addresses and touches two cache lines. | One shared 16-byte `ShadowCell` (seam 1). The low word serves the race detector's same-fiber test and the security state at once, so the common case is one load and one compare (§3.2). |
| **Broken snapshot rollback** | Wrapper state lives outside the arena, so restoring a snapshot rewinds the program but not the wrapper's quarantine, lock graph, or exploration tables, and the two drift apart. | `tardis_sec` tables live in a reserved slice of each worker's Region C (seam 2), which the snapshot covers, so a restore rolls them back with everything else. |
| **Double VTable indirection** | Each `std.Io` call passes through the wrapper's VTable and then core's. | Hooks are a comptime type parameter of core (seam 3). `NoopSecurityHooks` inlines to nothing. `SecurityHooks` inlines into core's VTable functions, with no indirect call. |

Core stays fast to compile and free of dependencies: no crypto audit, MC/DC, DPOR, or SARIF code is compiled unless `tardis_sec` is imported. **[Design]**, because it needs the seams. The hook contract and the no-op default are **[Verified]** (§8.3, `assertHooks`).

### 1.3 Why fuzzers and sanitizers are not enough

- **They see one process and one schedule.** LibFuzzer and AFL++ mutate input bytes. Distributed bugs need a *schedule*: a partition at the right moment, a reordered message, two conflicting proposals delivered in the same nanosecond. A fuzzer cannot choose those, and cannot replay them.
- **Sanitizers report, they do not search.** ASan, TSan and MSan flag the bad access when it happens. They do not steer the program toward it, and TSan reports only races the OS scheduler happened to interleave.
- **Formal tools model, they do not run.** KLEE explores paths symbolically, but not real I/O across nodes. TLA+ checks a model that can diverge from the code.
- **Standards ask for evidence those tools do not produce.** DO-178C DAL-A asks for MC/DC structural coverage of the requirements-based tests. CC EAL6–7 ask for semi-formal and formal design verification and vulnerability analysis at high attack potential (AVA_VAN.5). ISO 26262 ASIL-D asks for MC/DC-class coverage and freedom from interference. FIPS 140-3 asks for zeroization and self-test evidence, and at Level 4 for fault-injection resistance. A fuzzer's crash list is none of these.

### 1.4 The certification matrix: what `tardis_sec` contributes

| Standard / level | Objective | `tardis_sec` evidence | Still needed outside the tool |
|---|---|---|---|
| **DO-178C DAL-A** (with DO-326A security) | MC/DC (Table A-7, obj. 5), dead and deactivated code analysis, requirements traceability | MC/DC pair tables per decision (§7.1), dead-code list, bidirectional requirement-to-test matrix (§7.5) | DO-330 tool qualification (TQL-5 for a verification tool), structural coverage at object level where required, independence of reviews |
| **CC EAL5–EAL7** | ADV_SPM / ADV_FSP (semi-formal and formal models), ATE_DPT, AVA_VAN.4/5 | Bounded exhaustive state exploration (§7.2), non-interference checks (§7.3), vulnerability findings with replay capsules, glitch resistance (§7.4) | A formal security policy model and proof, lab (CCTL) evaluation, ALC_TAT tool justification |
| **ISO 26262 ASIL-D** | Part 6 structural coverage at unit level (MC/DC highly recommended at ASIL D), freedom from interference between software elements (Part 6, Annex D) | MC/DC tables, tenant-isolation and cross-tenant findings (§3.4) | Tool confidence level analysis and qualification (Part 8, clause 11) |
| **FIPS 140-3 L3/L4** | Zeroisation of sensitive security parameters (ISO/IEC 19790 §7.9), self-tests, non-invasive attack mitigation, L4 environmental and fault protection | Zeroization proof per secret (§3.5), constant-time checks (§6.3), fail-closed behaviour under simulated glitches (§7.4) | CMVP lab testing on hardware; physical fault injection |

### 1.5 Comparison across ten axes

✓ covered, ◐ partial or indirect, ✗ not covered.

| # | Axis | LibFuzzer / AFL++ | ASan + TSan + MSan | KLEE / TLA+ | TARDIS-SEC |
|---|---|---|---|---|---|
| 1 | Spatial, temporal & uninitialized memory safety (Zig + C ABI) | ◐ through the sanitizers it links | ✓ for compiled-in code; three separate shadows | ◐ KLEE symbolic memory; ✗ TLA+ | ✓ at hook points, ◐ between hooks (§3.6); one 16-byte cell, one compare on the hot path |
| 2 | Double fetch, lockdep deadlock, VFS TOCTOU | ✗ | ◐ TSan sees only races that happened | ◐ TLA+ in the model | ✓ the scheduler steers into the window (§4) |
| 3 | Byzantine mutation, checksum fixup, equivocation | ◐ mutations die at the checksum | ✗ | ◐ TLA+ in the model | ✓ comptime field reflection (§5.1) **[Verified]** |
| 4 | Ingress-to-sink taint (injection, cross-tenant bleed) | ✗ | ✗ (MSan tracks only initialization) | ◐ | ✓ copy-preserving taint (§5.2) |
| 5 | Algorithmic complexity and amplification DoS | ◐ slow-unit detection | ✗ | ✗ | ✓ four ratios, fed back to exploration (§6.1) |
| 6 | Constant time, Spectre-v1, `secureZero` verification | ✗ | ✗ | ◐ KLEE-based CT tools | ✓ I/O-trace CT **[Verified]**; PC and cache-line CT for instrumented C and the Spectre-v1 shape **[Verified]** (§6.3) |
| 7 | DO-178C MC/DC and dead code | ✗ | ✗ | ✗ | ✓ with instrumentation (§7.1) |
| 8 | Bounded model checking, exhaustive DPOR | ✗ | ✗ | ✓ in the model | ✓ on the real code, bounded (§7.2) |
| 9 | Non-interference, fault-glitch resistance | ✗ | ✗ | ◐ in the model | ✓ dual execution **[Verified]**; glitch decisions **[Verified]** |
| 10 | Triage: shrinking, SARIF, signed evidence | ◐ minimizes input bytes | ✗ | ◐ counterexample traces | ✓ core shrinker + SARIF + Merkle/Ed25519 bundle **[Verified]** for SARIF and signing |

---

## 2. Layer 7 Plugin Architecture, Per-Worker Region C Budget & Epoch-Barrier Merge

### 2.1 Architecture

```
  ┌──────────────────────────────── tardis-sec/  (package tardis_sec) ─────────────────────────────────┐
  │  Pillar I  ShadowCell     Pillar II  Races        Pillar III Byzantine   Pillar IV DoS/CT   Pillar V Cert │
  │  shadow.zig egress.zig    dfetch.zig lockdep.zig  byzantine.zig taint.zig amplify.zig ct.zig mcdc.zig dpor.zig │
  │  quarantine.zig           toctou.zig              diff.zig sandbox.zig  spectre.zig      ni.zig glitch.zig  │
  │                                                                                          evidence.zig sarif.zig│
  │        │ SecurityHooks (comptime type)      │ Budget (comptime sum = 64 MiB)   │ oracles, emitters │
  └────────┼────────────────────────────────────┼──────────────────────────────────┼───────────────────┘
           │ seam 3                             │ seam 2                           │ seam 4
           ▼                                    ▼                                  ▼
  ┌───────────────────────────────────── core tardis (Layers 1–6) ─────────────────────────────────────┐
  │ L6 Oracles & diagnostics  ── oracle.zig, shrink.zig, trace.zig ◄── registerOracle / registerEmitter │
  │ L5 Exploration            ── decide.zig (decision keys), explore.zig (coverage, corpus), fault.zig │
  │ L4 std.Io VTable          ── Sim.zig: Hooks.onNetRead/Write, onVfsOp, onBranchCmp, onCausalStep    │
  │ L3 VFS / network personas ── vfs.zig (onVfsOp), net.zig (onNetRead/Write)                          │
  │ L2 Scheduler / fibers     ── sched.zig, fiber.zig (onCausalStep, onLockAcquire/Release)            │
  │ L1 Memory (Chrono-Slab)   ── alloc.zig (onAlloc/onFree, onWrite)                                   │
  │                                                                                                    │
  │   Worker W arena  [arena_window_base + (W << 30), +1 GiB)  ──►  Region A: SUT heap                  │
  │   Worker W shadow [0x7100_0000_0000 + (W << 31), +2 GiB)  ◄── seam 1: ShadowCell (16 B / 8 B word)  │
  │   Worker W Region C (≤ 512 MiB): core 352 MiB │ tardis_sec 64 MiB (seam 2) │ spare 96 MiB          │
  └────────────────────────────────────────────────────────────────────────────────────────────────────┘
                   every 64 iterations: Epoch Barrier ──► deterministic merge ──► .tardis_persist/
```

The four seams:

1. **Shared `ShadowCell` layout.** Core defines the 16-byte cell (§3.1) and maps its shadow window. The reserved fields (`per_byte_nibble`, `alloc_gen`, `taint_tenant_id`) stay zero without `tardis_sec`, so core's race detector reads only `last_scalar` and `vclock_epoch`. With `tardis_sec`, the same compare (`fast_word == epoch`) proves both "same fiber" and "all bytes clean".
2. **Region C headroom.** `tardis_sec` reserves its tables inside each worker's Region C at init: `ChronoSlab.reserveRegionCHeadroom(SEC_REGION_C_BYTES)`. The tables are inside the snapshot, so `Control.restore()` rolls them back.
3. **Comptime `SecurityHooks`.** Core's VTable functions are generic over a hooks type. The default `NoopSecurityHooks` has empty `inline` functions, so a build without `tardis_sec` contains no extra machine instructions for them.
4. **Oracle, shrinker and artifact registration.** `tardis_sec` registers failure predicates, so the core shrinker keeps a counterexample only while *the same security finding* reproduces (same CWE, same sink). It also registers artifact emitters that run at campaign teardown (SARIF, evidence bundle).

   **What runs today (revision 6).** The shrinker predicate is **[Verified]**. The seam's `Provider` has an optional `finding_key` hook, which `tardis_sec` answers with the campaign's deduplication key for the run's first finding (CWE, kind, detail, kind of sink, §7.5). For a run that failed with `error.SecurityViolation`, core's shrinker accepts a candidate only when it fails with the same error *and* the same key, so shrinking may move a leak's offset or time but never trade it for a different bug. Without the hook (or for other errors) the predicate is the error alone, as before. `pillar1_test.zig` plants a program whose leak depends on its input: lowering the input to 0 turns an uninitialized tail (CWE-908) into a logged key (CWE-200). Without the key, the shrinker reported the CWE-200 run; with it, the shrunk run and its replay token are still CWE-908. Seam 4's other half, running the layer in every `check` of a build, is the build switch in §8.2. A third pair of hooks, `fork_export` and `fork_import` (revision 10), carries a layer's per-run tallies out of a forked child (§7.5). Emitters are **[Verified]** since revision 11.
   - **The hook.** `check` calls the seam's `campaign_end` once when it returns, on the simulator that ran and shrank the campaign. It passes the error, the shrunk replay token, and `check`'s return address.
   - **What `tardis_sec` writes.** A failed `check` writes `<hash>.sarif`: a result per distinct finding (`CWE-n`), or `tardis/failure` when no finding explains the error, with the replay token. The file goes to `SecurityConfig.check_sarif`, or, in tests, to `TARDIS_SARIF_DIR`. So `TARDIS_SEC=1 TARDIS_SARIF_DIR=zig-out/sarif zig build test` turns every failing test into code-scanning results without `certify`.
   - **The location.** Code scanning needs one for each result. The return address is resolved through the program's own debug info (`std.debug.SelfInfo`: DWARF, or PDB on Windows) to the test's file and line, made relative to the current directory. Stripped builds have no location.
   - **The test.** `pillar1_test.zig` checks the CWE, the shrunk token, and that the location is the exact line of the test's `check` call, and that a passing check writes nothing.
   - **`certify`** campaigns emit nothing here: they write their own bundle.

### 2.2 The hook contract

Core calls these hooks; the signatures are the contract between the two packages. **[Verified]** as code: both `NoopSecurityHooks` and `SecurityHooks` pass the comptime check `assertHooks`.

| Hook | Called from (core) | Purpose |
|---|---|---|
| `onAlloc(ctx, addr, len)` | allocator, after placement | Mark bytes `uninit_heap`, tag tenant, bump `alloc_gen` |
| `onFree(ctx, addr, len)` | allocator, before the slot enters quarantine | Report unzeroized secrets (CWE-226), mark `freed_quarantine` |
| `onWrite(ctx, addr, bytes)` | `std.Io` read-into-buffer paths, `tardis_sec.store`, C `trace-stores` | Store state transitions (zero bytes scrub secrets) |
| `onNetRead(ctx, addr, bytes)` | network receive paths | Ingress taint (`untrusted_input`), amplification counters |
| `onNetWrite(ctx, addr, bytes, dest_tenant) bool` | network send and file write paths | 64-byte egress scan; `false` blocks the write and records a finding |
| `onVfsOp(ctx, op, path)` | every VFS operation | TOCTOU pairing, path-confusion checks, sandbox policy (live through the `path` and `capability` hooks since revision 26) |
| `onLockAcquire(ctx, class)` / `onLockRelease` | mutex, rwlock, futex, VFS lock paths | Lock-order bitmatrix |
| `onBranchCmp(ctx, site) bool` | `trace-cmp` callbacks from instrumented C, `criticalCheck`, `mcdc.decision` and comparison wrappers in Zig | Comparison tokens, MC/DC conditions, glitch injection |
| `onCausalStep(ctx, key)` | each scheduling decision | Fiber epoch advance; DPOR transition records |

**What core implements today (revision 2).** Seam 3 exists in core as `src/sim/sec_seam.zig`, at the I/O boundary. **[Verified]**:

| Core call site | Seam call | Covers |
|---|---|---|
| `alloc.zig` `alloc`, and the grown tail in `resize`/`remap` | `alloc(ctx, node, mem)` | every `env.allocator` / `env.nodeAllocator(n)` allocation |
| `alloc.zig` `free`, and the dropped tail in `resize`/`remap` | `free(ctx, node, mem) u16` | every free; non-zero is a CWE |
| `alloc.zig` `reset` | `heap_reset(ctx, node)` | node crash, new run |
| `Sim.readVectors`, `netReadStep`, `netReceiveStep` | `ingress(ctx, sink, bytes)` | file reads, stream reads, datagrams received |
| `Sim.writeVectors`, `netWriteStep`, `netSendStep` | `egress(ctx, sink, bytes) u16` | file writes (positional and streaming), stream writes, datagrams sent |
| `Sim.beginRun` | `begin_run(ctx, seed)` | per-run reset |
| `dirStatFile`, `dirAccess`, `dirOpenFile` | `vfs_op(ctx, node, op, dir, path) ?target` | path checks and uses; a target makes core swap the entry for a symlink before the open (revision 3) |
| `netSendStep` | `datagram(ctx, sink, payload, out) ?len` | in-flight rewriting of a datagram (revision 3) |
| `netWriteStep` | `stream(ctx, sink, bytes, out) bool` | in-flight rewriting of stream bytes, same length (revision 20) |
| `netSendStep` | `replay(ctx, sink, payload, out) ?len` | a recorded datagram delivered first (revision 21) |
| `dirOpenFile`, `dirCreateFile`, `dirDeleteFile`, `dirRename` | `path(ctx, node, op, path) u16` | the path sink: taint (revision 23) and the sandbox's prefixes (revision 26) |
| `fileLock`, `fileUnlock`, `fileClose` | `file_lock(ctx, node, inode, held)` | file-lock order (revision 24) |
| `netConnectIp`, `netListenIp`, `netBindIp`, `processSpawn`, `processReplace` | `capability(ctx, node, cap, argv) u16` | the sandbox, and the spawn sink (revision 26) |
| (called by the layer) | `Sim.preemptionPoint(ppm)` | a keyed task switch where core has no `std.Io` call (revision 3) |

A `Sink` names the kind (file, stream, datagram), the node doing the I/O, the peer node, and the socket slot or inode. A non-zero CWE from `free` or `egress` is recorded in the trace (`note`, `a` = the CWE) and fails the run with `error.SecurityViolation`, so the failure shrinks and replays like any other.

Two deliberate differences from the comptime design below:

1. **Run-time dispatch.** `Options.security` carries a provider (a table of function pointers) and eight configuration words; each `Sim` creates its own instance, so parallel workers share nothing. Without a layer the pointer is null: one predictable branch per allocation or I/O operation, next to the hundreds of instructions the simulated operation itself costs. It is not "zero instructions", and the claim in §1.2 applies only to per-access hooks (instrumented C, `load`/`store` wrappers), which never pass through core.
2. **Writes are not blocked.** A violating write still happens; the run is already failed, and refusing it would add an error path the program never sees in production.

```zig
// The comptime form, for per-access hooks (sketch):
pub fn SimWith(comptime Hooks: type) type {
    tardis_sec_contract.assertHooks(Hooks); // or core's own copy of the check
    return struct {
        fn netWrite(s: *Sim, addr: u64, bytes: []const u8, dest: u8) !usize {
            if (Hooks.enabled and !Hooks.onNetWrite(s.sec_ctx, addr, bytes, dest)) return error.SecurityViolation;
            return s.net.write(addr, bytes);
        }
    };
}
pub const Sim = SimWith(if (@hasDecl(root, "tardis_sec_hooks")) root.tardis_sec_hooks else NoopSecurityHooks);
```

### 2.3 Per-worker Region C budget

Every table has a fixed capacity and is allocated once, at `WorkerSec` init. The sums below are comptime assertions in the SDK (**[Verified]**: `Budget.total == SEC_REGION_C_BYTES` and `352 + 64 + 96 == 512` MiB).

| Table | Shape | Bytes | Merge at the Epoch Barrier |
|---|---|---|---|
| `QuarantineRing` | 32 nodes × 4096 slots × 16 B | 2.0 MiB | none (per-run state; rolled back by restore) |
| `LockdepGraph` | 32 nodes × (512 classes × 64 B bitmatrix row + 512 × 32 B metadata) | 1.5 MiB | edges OR-reduced into `.tardis_persist/lockdep.bin` |
| `LocalCmpTokenRing` | 65,536 × 32 B | 2.0 MiB | union into `.tardis_persist/global_cmp_dict` (sorted, de-duplicated) |
| `LocalMcdcTable` | 16,384 decisions × 64 B | 1.0 MiB | bitwise OR into `.tardis_persist/global_mcdc_table` |
| `ByzantineReplayPool` | 2048 frames × 16 KiB | 32.0 MiB | none (frames are captured per campaign phase) |
| `CostAmplificationLedger` | 32 nodes × 2048 ops × 64 B | 4.0 MiB | max per op key |
| `TaintSinkAuditLog` | 65,536 × 64 B | 4.0 MiB | appended in (iteration, worker) order |
| `DporStateTable` | 65,536 × 64 B transition traces | 4.0 MiB | none (one exhaustive run owns one worker) |
| `SecReservedHeadroom` | — | 13.5 MiB | — |
| **Total** | | **64.0 MiB** | |

Region C as a whole: `REGION_C_BYTES_MAX = 512 MiB` per worker, of which core uses 352 MiB, `tardis_sec` 64 MiB, and 96 MiB stays spare. With 64 workers that is 4 GiB of `tardis_sec` tables when every worker runs, reserved but touched only as used.

**Why per worker.** Each table is written by one worker only, so there are no atomics on the hot path and no false sharing. `LocalMcdcTable` in particular is 64 B per decision, one cache line, so no two workers ever write the same line.

**Merge determinism.** At each 64-iteration Epoch Barrier the main thread folds the tables in worker index order, using operations that are commutative and idempotent (OR, union, max) or explicitly ordered (append by `(iteration, worker)`). The persisted state is therefore the same for any worker count and any thread timing, just as core's parallel guided exploration gives the same corpus for any worker count above one.

### 2.4 The Requirement Traceability Registry

`.tardis_persist/requirements.bin` holds up to `REQUIREMENTS_MAX = 4096` rows of 128 B, 512 KiB in total. **[Verified]**: `@sizeOf(RequirementRecord) == 128`. Each row records:

- the requirement id (`"SFR-FDP_ACC.1"`, up to 48 bytes);
- checks passed and failed;
- a digest of the tests bound to it (for the reverse direction of the matrix);
- the seed of its first failure (the failing run with the lowest iteration, then persona, so the value does not depend on which worker committed first);
- the MC/DC decisions it covers.

Rows are created by `tardis_sec.requirement(id)` the first time a test names the requirement. Rows for requirements listed in the project's requirement file but never bound to a test show up as gaps.

**What runs today (revision 5).** **[Verified]** by `src/sec/registry.zig` and `src/sec/tests/example2.zig`.

- **The row.** The record is 128 bytes as specified.
  - The tests bound to a requirement are a 256-bit Bloom filter over test names, two bits per name, in what used to be the reserved bytes. `tests_digest` is a hash of that filter.
  - Merging is therefore a bitwise OR, the same in any order and idempotent.
  - `mcdc_decisions_covered` and `_total` are stored and merged but not yet filled: decisions are not attributed to requirements.
- **Counting.** Inside a `certify` campaign, `requirement(id).check(ok)` is tallied by the engine for the current run and committed when the run ends.
  - Only counted runs are committed. Shrinking runs and the determinism re-run repeat a run already counted; core marks them (`Sim.rerun`), and the engine skips them.
  - A 120-iteration certification campaign therefore records exactly 120 checks of a requirement checked once per run, even though certification mode re-runs every iteration for determinism.
  - Outside a campaign, checks go to a per-thread table (`requirementRecords`).
- **The persisted file.** `Table.save` writes the rows back to back, little-endian, to a temporary file, syncs it, and renames it over `.tardis_persist/requirements.bin`, so a crash leaves the old table or the new one. `load` validates whole rows and id lengths, and merges.
  - `certify(.., .{ .persist = dir })` loads, merges the campaign's table and saves.
  - Example 2 checks that a second campaign adds up (240 checks after two of 120) and that both tests are bound.
- **The requirement file.** One id per line, `#` comments. Ids declared there and never checked are `GAP` rows in the matrix.

---

## 3. Pillar I: Nibble-Granular Unified `ShadowCell` (Chrono-ASan + MSan + Taint)

### 3.1 Layout

One 16-byte `ShadowCell` shadows one aligned 8-byte application word. **[Verified]**: `extern struct` with `fast_word` at offset 0 and `meta_word` at 8, `@sizeOf == 16`, and both words are `packed struct(u64)`, with every bit offset checked at comptime.

```
 bit 127      120 119      112 111                                   65  64 63                    32 31                     0
 ┌──────────────┬────────────┬───────────────────────────────────────┬────┬────────────────────────┬────────────────────────┐
 │taint_tenant_id│ alloc_gen │            vclock_epoch (47)          │ cw │ per_byte_nibble (8 × 4)│ last_scalar            │
 │      u8      │    u8      │                                       │ u1 │ byte7 … byte0          │ fiber_id<<16 | epoch   │
 └──────────────┴────────────┴───────────────────────────────────────┴────┴────────────────────────┴────────────────────────┘
 └──────────────────────────── meta_word (u64) ──────────────────────────────┘└──────────────── fast_word (u64) ─────────────┘
```

| Field | Bits | Meaning |
|---|---|---|
| `last_scalar` | 0–31 | `(fiber_id << 16) \| local_epoch` of the last access (race detector) |
| `per_byte_nibble` | 32–63 | One 4-bit `ByteState` per byte of the word; byte *i* at bits `32 + 4i` |
| `vclock_epoch` | 64–110 | 47-bit vector-clock epoch of the last write |
| `has_concurrent_writer` | 111 | A write from another fiber is unordered with this fiber's view |
| `alloc_gen` | 112–119 | Allocation generation, incremented on each allocation of the slot |
| `taint_tenant_id` | 120–127 | 0 system, 1–254 tenant, 255 bytes mixed from two tenants (poison) |

The `ByteState` values (4 bits, `0xC`–`0xF` reserved):

| Value | State | Set by | Faults on |
|---|---|---|---|
| `0x0` | `valid_clean` | stores | — |
| `0x1` | `uninit_heap` | `onAlloc` | egress (CWE-908) |
| `0x2` | `uninit_stack` | stack frame entry (instrumented C) | egress (CWE-908) |
| `0x3` / `0x4` | `redzone_left` / `redzone_right` | allocator guard gaps | any access (CWE-124 / 125) |
| `0x5` | `freed_quarantine` | `onFree` | any access (CWE-416), egress |
| `0x6` | `stack_guard` | stack guard pages | any access (CWE-121) |
| `0x7` | `secret_key` | `markSecret` | egress (CWE-200), free while set (CWE-226) |
| `0x8` | `tenant_isolated` | `withTenant` boundaries | cross-tenant egress (CWE-125) |
| `0x9` | `untrusted_input` | `onNetRead`, file reads from untrusted paths | sinks (CWE-78, 89, 134, 22) |
| `0xA` | `double_fetch_armed` | first read of shared untrusted memory | second unsynchronized read (CWE-367) |
| `0xB` | `secret_zeroed` | zero stores over `0x7` | nothing: the secret was scrubbed |

`taint_tenant_id` is orthogonal to the nibbles: a key owned by tenant 2 is `secret_key` *and* tenant 2 at the same time. **[Verified]**: the shadow test sets both and reads both back.

### 3.2 Address mapping and the one-compare fast path

Worker *W*'s arena is `[arena_window_base + (W << 30), +1 GiB)`, with `arena_window_base = 0x4000_0000_0000` (aligned to 2^38). Its shadow is `[0x7100_0000_0000 + (W << 31), +2 GiB)`. One mask, one shift and one add map an address to its cell:

```zig
pub inline fn shadowAddress(virt: u64) u64 {
    return ((virt & 0x3F_FFFF_FFF8) << 1) + 0x7100_0000_0000;
}
```

**[Verified]**: a comptime loop over all 64 workers proves that the first and last word of each arena map to the first and last cell of that worker's shadow window.

Worked example: worker 3, offset `0x1238` → virt `0x4000_C000_1238`. Masked, that is `0xC000_1238`; shifted, `0x1_8000_2470`; plus the base, `0x7101_8000_2470` = `workerShadowBase(3) + 0x2470`.

The hot path is one compare:

```zig
if (cell.fast_word == @as(u64, current_fiber_epoch)) return; // same fiber, every byte clean
```

`current_fiber_epoch` is a `u32` zero-extended to 64 bits, so equality also requires `per_byte_nibble == 0`. Core's race detector already performs this compare. `tardis_sec` adds no instruction to the case where nothing is wrong. **[Target]** for cost; **[Verified]** for semantics (`isFastClean`).

### 3.3 Unaligned spans and the 64-byte egress scan

An access of 1–8 bytes at byte offset `o` of a word can straddle two cells. Concatenating both nibble words and shifting validates it without branches. **[Verified]** (`spanNibbles`, `statesIn`):

```zig
const both = (@as(u64, c1.fast().per_byte_nibble) << 32) | c0.fast().per_byte_nibble;
const nibbles = (both >> (@as(u6, o) * 4)) & ((@as(u64, 1) << (@as(u6, len) * 4)) - 1);
if (statesIn(nibbles) & ByteState.access_fault != 0) report(...);
```

At egress (`onNetWrite`, and file writes through the same hook), eight cells covering 64 payload bytes are checked at once. The eight `per_byte_nibble` words form a `@Vector(8, u32)`. For each of the eight nibble positions, a vector shift and mask extract one nibble per lane and turn it into a bit (`1 << nibble`). An OR-reduce gives the set of states in the 64 bytes, and one AND against `ByteState.egress_fault` classifies it. **[Verified]** (`egressScan`). It traps:

1. **Uninitialized or freed bytes leaving (CWE-908)**: struct padding, or a buffer sent with its unwritten tail.
2. **Secret or pointer exfiltration (CWE-200)**: any `secret_key` nibble.
3. **Cross-tenant bleed (CWE-125, Heartbleed class)**: a lane whose `taint_tenant_id` is neither the destination's tenant nor the system.

`secret_zeroed` (`0xB`) is deliberately not in `egress_fault`. **[Verified]**: the egress test shows a zeroed secret passing and an unzeroed one failing.

### 3.4 Tenants

`tardis_sec.withTenant(t, f, args)` runs `f` with allocations tagged `t`. Copying bytes keeps their source tenant. Combining bytes from two tenants in one word sets 255 (`tenant_poison`). The egress scan compares lanes against the destination's tenant, which comes from the socket or file the payload goes to. This is freedom-from-interference evidence in the sense of ISO 26262 Part 6, Annex D, for a multi-tenant service. **[Verified]**: `withTenant` and the cross-tenant lane check. Per-peer tenant binding is live through the engine: `bindNodeTenant(node, t)` binds the client on a node to a tenant, and the egress check compares against the peer node of each stream or datagram (§3.7, **[Verified]**).

### 3.5 Quarantine, address invariance, poisoning, and volatile-zero scrubbing

**Address invariance** means enabling `tardis_sec` never changes an address the SUT's allocator returns, so a seed means the same run with or without it. Two features normally break this: redzones (which move allocations apart) and quarantine (which delays reuse). Here core's deterministic allocator *always* leaves a 16-byte guard gap between allocations and *always* delays reuse of a freed slot through a FIFO of `4096` slots per node. `tardis_sec` only marks the gaps as `redzone_*` and the delayed slots as `freed_quarantine`. Core pays a small memory cost for this in every build, and in exchange seeds are portable between core and security builds.

**What runs (revision 25).** **[Verified]** by `src/sim/alloc.zig` and `pillar1_test.zig`, and with `TARDIS_SEC=1` over the whole repository. Core's heap (`SutAllocator`) asks its arena for `len + 16` bytes and writes the guard `sec_seam.redzone_pattern` after the block: eight distinct bytes, twice, so any 8 guard bytes in a row are a rotation of the first eight. A resize moves the guard to the new end. A free puts the block, guard included, in a FIFO of 4,096 slots per node (allocated in `Sim.create`, so a free never allocates); only the block that leaves the FIFO goes back to the arena, which reclaims it only if it is still its last block. Without the FIFO the arena handed the block just freed straight to the next allocation of that size. Both hold with or without a security layer, so attaching one changes no address. The engine:
- **at free** compares the guard (seam 3's `free` hook documents that it follows `mem`) and reports a changed byte as CWE-787 (`overflow`), with the offset of the first one. Without the shadow of §3.8 no store is checked, so a write past the end is found when its block is freed, or not at all for a block that is never freed;
- **at egress** fingerprints the guard's rotations like the uninitialized and freed patterns, so 8 guard bytes leaving the program are an over-read, CWE-125 (`redzone`).

The exit tests: a field copied into a 16-byte buffer with the client's length is CWE-787 at the first byte past the buffer, shrunk to at most 5 decisions, and the bounded copy passes; a 16-byte record sent with a claimed length up to 32 is CWE-125, and the bounded send passes; a dangling read after another allocation of the same size still sees freed bytes (CWE-416), where the arena alone gave it the new owner's text. The word shadow's nibble states (`redzone_*`, `freed_quarantine`) still wait on the shadow window.

`onFree`:

1. scans the range for `secret_key` and reports CWE-226 if any byte is still set;
2. sets every nibble to `freed_quarantine` and increments `alloc_gen` when the slot is next allocated;
3. has the allocator overwrite the bytes with `poisonWord(causal_seed) = 0xDEADBEEF_CAFEBABE ^ causal_seed`, deterministic per run, so a use-after-free reads the same garbage on every replay.

**Volatile-zero recognition.** A store of `0x00` to a `secret_key` byte moves it to `secret_zeroed`; a non-zero store leaves it secret. So unmodified `std.crypto.secureZero`, `explicit_bzero` and `OPENSSL_cleanse` work out of the box, and only a free of a still-secret byte traps (CWE-226). **[Verified]**: the hooks test zeroes a 32-byte key and frees it with no finding, then frees an unzeroed one and gets exactly one.

### 3.6 Which accesses are checked

Zig emits load and store callbacks for Zig code only in a module built with `sanitize_thread`, and such a module cannot share an executable with this runtime, so the code under test must then be a separate object (§3.8). Revisions up to 51 said Zig emits none, which was wrong. In an ordinary build, coverage comes from the other places:

| Source | Checked accesses |
|---|---|
| Allocator hooks | allocation, free, quarantine state, and the guard after each block (checked at free) |
| `std.Io` boundaries | every byte read into or written from a buffer (network, files, pipes) |
| Explicit wrappers | `tardis_sec.load(T, ptr)` / `store(T, ptr, v)` for code that opts in at hot data structures |
| C code | built with `-fsanitize-coverage=trace-loads,trace-stores,trace-cmp` (clang SanitizerCoverage), routed to `onWrite`, load checks and `onBranchCmp` |
| Zig objects built with `sanitize_thread` | every load, store, memory intrinsic and atomic operation, checked against the heap's shadow (§3.8) |
| Zig `-ffuzz` | edge counters and the PC table only: block counts for §6.1 and §7.1, no data accesses |

A use-after-free in Zig code is therefore caught when the freed bytes reach a hook: when they are sent, written, or touched by a wrapper. A pure in-memory read of freed memory that never reaches a hook is caught only in code built for the shadow (§3.8). The egress scan is designed around this: the bytes that matter for confidentiality are exactly the ones that reach an egress hook.

### 3.7 What runs today: content tracking through the seam

A word shadow (§3.1–3.3) needs to see stores. Zig code emits none (§3.6), and the bytes that leak almost always reach the socket through a copy: Heartbleed `memcpy`s heap bytes into the response. The shadow of the response buffer never saw those bytes. So the live engine (`src/sec/engine.zig`) tracks **content**, which survives any copy. **[Verified]** for everything in this section.

**Fingerprints.**

- **Uninitialized heap:** every allocation is filled with a per-run 8-byte pattern laid out by address. The byte at address `a` is `uninit[a % 8]`, so a copy at any alignment contains a rotation of the pattern, and all 8 rotations are fingerprints.
- **Freed heap:** every free overwrites the bytes with a second pattern (the deterministic poisoning of §3.5).
- **Secrets and tenant data:** `markSecret(bytes)` and `markTenant(bytes, t)` fingerprint every 8-byte window of the bytes as they are at that moment.

Both patterns derive from the run seed, with eight distinct non-zero bytes each, so a run replays bit for bit.

**The scan.** Every byte that `egress` sees is checked with a sliding 8-byte window against the fingerprint set, one hash lookup per byte. The first match per write decides:

| Match | Finding |
|---|---|
| uninitialized pattern | CWE-908, uninitialized bytes leaving |
| freed pattern | CWE-416, freed bytes leaving (a use after free made visible) |
| a `markSecret` window | CWE-200, a secret leaving through any sink |
| a `markTenant(t)` window, peer bound to tenant u ≠ t | CWE-668, cross-tenant exposure |
| — at `free`: a marked secret whose bytes are not all zero | CWE-226, missing zeroization |

`secureZero` leaves zeros, so it passes the free check without any recognition logic (§3.5's volatile-zero rule falls out).

**Exit tests** (`src/sec/tests/pillar1_test.zig`). Each pair of tests runs the planted bug and its fix:

| Test | Planted bug | Found as |
|---|---|---|
| Heartbleed | a 2-node echo replies with the length the client claims, over-reading from tenant 1's record into tenant 2's | `error.SecurityViolation`, CWE-668: tenant 2's bytes on node 1's stream to node 0, bound to tenant 1. The bounds-checked echo passes 200 iterations. |
| Uninitialized tail | a 64-byte heap buffer with a 20-byte header is written whole to a file | CWE-908 at payload offset 20 |
| Use after free | a freed cookie buffer written to a file | CWE-416 |
| Logged key | 16 bytes of a marked key written to a log | CWE-200 |
| Missing zeroization | a heap key freed without `secureZero` | CWE-226, in builds where the bytes survive the free (see below). The zeroized version passes. |
| Invariance | a benign 2-node workload, 16 seeds | identical trace hashes with and without `tardis_sec` |

**What the build mode changes.** In Debug and ReleaseSafe, `std.mem.Allocator.alloc` and `free` overwrite the bytes with `undefined` (0xAA) around the allocator call. Two consequences, both handled:

- In those modes, 8 bytes of 0xAA are also an uninitialized fingerprint. This also catches stack buffers declared `undefined`, struct padding included, when 8 or more of their bytes leave.
- A secret's bytes are already 0xAA when the free hook sees them. The secret is scrubbed in that build, so there is nothing to report: CWE-226 at free fires only where the bytes survive the free (ReleaseFast, ReleaseSmall, or a direct `rawFree`). The test asserts exactly that per mode.

**Limits, by construction.**

- **Short leaks:** a leak shorter than 8 bytes is not seen.
- **Low-entropy content:** windows with fewer than 3 distinct byte values are not fingerprinted, so an all-zero "key" is never matched against ordinary zeros.
- **Stack secrets:** a secret on the stack is checked at egress, but not at the end of its lifetime.
- **Ingress taint (revision 23):** received network bytes are tainted by content, in a set of their own (16,384 windows per run, overflow counted in `untrusted_dropped`), so they never cost the secret and tenant fingerprint budget and are never findings at egress. The same 8-byte limit applies: a received name shorter than 8 bytes, or one that lands in a path only in pieces, is not seen (§5.2).
- **False positives:** an unrelated 8-byte window must equal a fingerprint, about `fingerprints / 2^64` per byte scanned (at most 16,384 fingerprints).

**Capacities.** 16,384 fingerprints, 256 marked regions and 64 findings per run, all allocated when the simulator is created. Overflow is counted (`fingerprints_dropped`, `findings_dropped`), never silently ignored. `SecurityConfig.report` receives the findings of the last run, which is the failing one when `check` fails, because a failure ends the campaign with its replay.

**Relation to the shadow model.** Content tracking answers "did a forbidden byte leave?". The shadow answers "was this access legal?" (redzones, double fetch, races), which needs per-access hooks. The two coexist: the engine handles the I/O boundary today, and the `ShadowCell` types wait for instrumented paths.

### 3.8 Shadow memory for instrumented code (revision 52)

**[Verified]** by `src/sec/shadow.zig` and `src/sec/tests/shadow_test.zig`, in all four build modes on Windows and on Linux.

**The correction.** Revisions up to 51 said Zig emits no load or store callbacks for Zig code. It does: a module built with `sanitize_thread` gets LLVM's ThreadSanitizer pass, which calls `__tsan_read8`, `__tsan_write4`, `__tsan_memcpy`, `__tsan_atomic32_compare_exchange_val` and their siblings before every load, store, memory intrinsic and atomic operation. What Zig does not allow is using those callbacks inside one executable: it builds and links its own sanitizer runtime into any executable that has such a module (which fails outright for Windows targets, and collides with a second definition on Linux). An object file has no such runtime.

**How it is used.**

1. The code under test is built as an object: `addInstrumentedObject(b, tests, .{ ... })` from this package's `build.zig` (revision 56), which is `b.addObject` with `sanitize_thread = true` and `use_llvm = true`, linked into `tests`, with `tests` set to LLVM too. C takes part through clang's load and store tracing (`-fsanitize-coverage=trace-pc,trace-loads,trace-stores`, §6.3), since clang refuses `-fsanitize=thread` for Windows targets.
2. The test links the object, is itself built without the sanitizer (with `use_llvm = true` if Zig types cross the boundary), and exports the runtime: `comptime { tardis_sec.exportSanitizer(); }` (and `exportCoverage()` for the C).
3. `SecurityConfig.shadow_memory = true` shadows the simulated heap.

**The shadow.** One state byte per heap byte: `valid`, `redzone` (the 16-byte guard core leaves after every allocation, §3.5) or `freed` (a block in core's quarantine). It is sparse: 4 KiB shadow pages found through a hash of the page number, 2,048 of them per simulator (8 MiB of heap; marks beyond that are counted in `dropped` and not checked). The allocator hooks of seam 3 keep it, so core is unchanged and no address moves. An access outside the bounds of every mark returns after two compares; a new run forgets only the pages the last one used.

**Findings**, each at the access, each failing the run at once:

| Access | Finding |
|---|---|
| a store into a guard | CWE-787 (`write_past_end`), with how far past the end and how many bytes |
| a load from a guard | CWE-125 (`read_past_end`) |
| a load or store in a freed block | CWE-416 (`use_after_free`) |

Without the shadow, the store past the end is found only when the block is freed (§3.5), and the two loads are found only if the bytes they read later leave the program (§3.7).

**Exit tests.** A fill, a sum, a `@memcpy`, a one-byte read through a dangling pointer and an atomic increment of a freed counter in the Zig object; a parser in the object that allocates from the simulated heap through a `*const std.mem.Allocator` (found and shrunk to at most 4 decisions); a fill and an indexed read in C. Each has its bounded twin, which passes 50 iterations. With `shadow_memory` off the same binary reports the fill at the free and misses the read; outside a simulation the instrumented code just runs.

**Limits.**

- **Not the `ShadowCell` of §3.1.** Three states, not twelve: there is no uninitialized, secret or tenant state per byte. Content tracking (§3.7) covers those at the I/O boundary.
- **Heap only.** Stacks and globals are not shadowed.
- **The test itself is not instrumented.** A bad access made by the test body, or by `std` code compiled into the test, is not seen. The code under test must be separable behind C-ABI entry points. Passing a pointer to `std.mem.Allocator` across them works only when the test is built by the LLVM backend too (`use_llvm = true`): the allocator's functions have Zig's calling convention, on which Zig's own backend and LLVM differ (the Linux Debug run failed every allocation until this was set). The language promises neither that convention nor the struct's layout.
- **C's `memcpy` and `memset`** are libc's and are not traced; C loops are.
- **Cost per access** (revision 56, ReleaseFast, x86_64, one machine, reading 8,192 heap words through a one-load function in the object): about 12 cycles per load with the callbacks doing nothing, 19 with the shadow, 45 with the shadow and the race detector. Before revision 56 every callback walked from the thread's simulator to its engine; a thread-local pointer to the engine that is checking, set for the length of a run, took the three figures down from about 19, 27 and 85 (two separate runs on a noisy machine, so the differences between the columns mean more than the columns).

**What else the callbacks carry.** The data-race detector of §4.5 (revision 53). Lock-order checks for `std.Io.Mutex`, also once ruled out for want of these callbacks, are §4.6 (revision 54).

---

## 4. Pillar II: Double-Fetch, Lockdep Deadlock & Adversarial VFS TOCTOU Hunter

### 4.1 Double-fetch detector (CWE-367), free of false positives

A double fetch is two reads of the same shared word, with a validation between them, where a writer can change the word in between. The detector has three steps:

1. **Arm.** It arms only on words that can actually change under the reader: `ByteState.untrusted_input` (an IPC or DMA buffer the peer controls) or `has_concurrent_writer = 1` (another fiber has an unordered write). On the first read by fiber A, the nibbles become `double_fetch_armed` and the cell records A's epoch.
2. **Detect.** A second read by fiber A with no synchronization between the two reads (same vector-clock epoch) registers a *double-fetch hot spot*: the pair of read sites, keyed like a coverage feature.
3. **Exploit.** Exploration treats hot spots as targets. The next runs that reach the first read get a forced preemption *between* the two reads (a scheduling decision forced through the overlay, exactly as core's guided exploration forces decisions), handing control to the writer fiber, or to a simulated peer that rewrites the untrusted buffer. If the program's checks then fail open, the oracle (bounds, invariants, sinks) fires and the failure shrinks to the two reads and the one forced switch.

Words read once, words never written concurrently, and reads ordered by a lock are never armed, so there are no false positives by construction. What remains is a missed bug if the two reads go through code that reaches no hook (§3.6). **[Design]** as specified with the shadow; the opt-in form through `Shared(T)` is live (§4.4).

### 4.2 Lockdep: O(1) order checks and hold-across-yield (CWE-833)

Lock classes are numbered up to 512 per node, and `order[a]` is a 512-bit row (`[8]u64`): bit *b* set means "*a* was held while *b* was taken". The matrix is kept transitively closed when an edge is added (at most 512 × 8 word-ORs per new edge, bounded and without recursion). So acquiring *b* while holding *a* is an inversion exactly when `order[b]` has bit *a*, one bit test per held lock. **[Verified]**: the lockdep test builds 1→2 and 2→3, then takes 3 and then 1, and reports the transitive inversion against 1→3.

Lock classes cover `std.Thread.Mutex`, `RwLock`, futex-based locks and `std.Io.Mutex` (through core's futex hooks), `pthread_mutex_t` (through the C shims), and VFS file locks (`vfs.zig`'s lock calls). A lock still held at an `std.Io` yield point (any operation that can block the fiber) is reported as hold-across-yield. For spin-style locks that is a deadlock under a cooperative scheduler. **[Verified]**: `heldAtYield`. **[Design]**: core call sites for `std.Thread.Mutex` and futexes. Live today through `tardis_sec.Mutex` (§4.4), since revision 24 VFS file locks, and since revision 27 `pthread_mutex_t` in C compiled with the shims (§5.2).

**File locks (revision 24).** **[Verified]** by `pillar2_test.zig`. Core calls seam 3's `file_lock` hook when a task takes a file lock (`File.lock`, before it may wait) and when it drops one (`unlock`, or closing the handle that held it); a lock canceled while waiting is dropped too. `tryLock` is not reported, since it cannot deadlock. The engine gives each (node, inode) its own class, in first-locked order, from the reserved range 192–255 (`races.file_lock_class_first`; since revision 27 C mutexes take 128–191, and `Mutex` classes stay below 128 and assert so), and runs the same order matrix as for `Mutex`. Findings name them "file lock 1", "file lock 2" in SARIF. The exit test is AB-BA on two lock files, the second order 1 ms later, so no schedule deadlocks and core's deadlock detector cannot fire: CWE-833 with the two file classes, shrunk to at most 5 decisions; the same order twice passes. Under `TARDIS_SEC=1` every test in the repository still passes, core's file-lock tests included. `std.Io.Mutex` stays out of reach: its uncontended path never calls core, so core sees only contended acquires.

### 4.3 VFS TOCTOU and path confusion (`vfs_toctou_race_ppm`)

`onVfsOp` pairs each *check* (`statFile`, `access`, `readLink`, a directory listing) with the next *use* of the same path by the same fiber (`openFile`, `createFile`, `deleteFile`, `rename`). With probability `vfs_toctou_race_ppm` per pair, the simulator schedules an attacker fiber between them. That fiber swaps the path for a symlink or hard link to a target outside the allowed tree (core's VFS has both), or replaces a file with a directory. The decision is an ordinary keyed decision, so a race that breaks the program replays and shrinks.

Path-confusion inputs are generated per persona:

| Confusion | Persona | Core support today |
|---|---|---|
| Case folding (`Secret` vs `secret`) | `windows_ntfs`, `macos_apfs` | ✓ case-insensitive personas |
| NFD/NFC (`é` as one or two code points) | `macos_apfs` | ✓ for the Latin-1 letters (revision 17); other Unicode is compared as written |
| 8.3 short names (`PROGRA~1`) | `windows_ntfs` | ✓ `~1`–`~4` per short base and extension, in creation order (revision 17) |
| Trailing dots and spaces, `::$DATA` streams | `windows_ntfs` | ✓ the default stream (revision 17); named streams are rejected |
| `../` traversal (Zip-Slip, CWE-22) | all | ✓ paths resolve through the VFS, so the escape is observable |

The persona rules are in core (`src/model/vfs.zig`), so every program under `windows_ntfs` or `macos_apfs` sees them, with or without `tardis_sec`. **[Verified]** since revision 17. The symlink swap between a check and an open is live (§4.4).

**Generating the confusions (revision 17).** **[Verified]** by `pillar2_test.zig`. `tardis_sec.pathConfusions(persona, name)` returns the spellings of a name that the persona resolves to the same file while a byte comparison tells them apart: `./name` everywhere; the ASCII case swapped on case-insensitive personas; on `windows_ntfs` a trailing dot, a trailing space, `::$DATA` and the `~1` short name of a long name; on `macos_apfs` the decomposed or composed spelling. A test feeds them to the code under test through a keyed choice (`env.fuzz`), so a bypass replays and shrinks. The rules come from core's functions (`win32Name`, `shortName`, `decomposeLatin1`, `composeLatin1`), and a test opens every generated spelling through core's VFS and through the simulator's `std.Io` on three personas. The exit test is a file server that refuses `secret.key` with a careful deny-list: no leading `./`, case-insensitive. On `windows_ntfs` (and on `macos_apfs` with `clé.key`) a confusable spelling gets past it, the key is published, and the egress scan reports CWE-200. The run shrinks to at most 5 decisions. The same deny-list holds on `linux_ext4`, and an allow-list (`report.txt`, byte for byte) holds on all three. A short name's `~N` beyond 1, directory-name confusions and hard-link swaps are not generated.

### 4.4 What runs today (revision 3)

Through the engine (`src/sec/races.zig`) and core's seam. **[Verified]** for everything in this section, by the exit tests in `src/sec/tests/pillar2_test.zig`, in all four build modes and on Linux.

**Lock order.** `tardis_sec.Mutex` is `std.Io.Mutex` with a lock class. Taking it checks the per-run order matrix against what *this task* holds, before blocking. The matrix has 256 classes, 8 KiB, and is kept transitively closed. An inversion is CWE-833: the finding names the class held and the class taken, and it fails the run with `error.SecurityViolation`. The exit test runs a transfer (`accounts`, then `audit`) and, 1 ms of virtual time later, an audit job taking them in the other order. No schedule deadlocks, so core's deadlock detector can never fire; lockdep reports the inversion in the first iteration. **Not live:** core call sites for other lock kinds (§4.2), and hold-across-yield, which is normal for a fiber mutex.

**Double fetch.** Zig has no load hook, so code that reads memory a peer controls reads it through `tardis_sec.Shared(T).load` (a volatile read). The second read of the same word by the same task is a keyed preemption point, `Sim.preemptionPoint(double_fetch_preempt_ppm)`, with a default of 50%. The writer runs between the check and the use, and the program's own oracle decides. The exit test parses a message whose length is checked and then read again for the copy.
- **Without `tardis_sec`:** it passes 200 iterations, because there is no `std.Io` call between the two reads and so core has no point to switch.
- **With it:** the oracle fails.
- **Single fetch:** the version that reads the length once passes.

**Check-to-use races on paths.** Each `statFile`/`access` of a path is recorded per task. A later `openFile` of the same path by the same task consumes the pair. With `vfs_toctou_race_ppm` (a keyed decision on the fault stream), the engine returns the run's target (`setToctouTarget`), and core replaces the entry with a symlink to it just before the open. The trace records `toctou swap`. In the exit test a publisher checks that `report.txt` is a regular file (no-follow `stat`), then reads it by name and publishes it. The swap makes it publish `secret.key`, and the egress scan reports CWE-200, so two pillars compose. The version that opens once and checks the handle (`file.stat`) passes. Taint sinks on VFS paths are live since revision 23 (§5.2), and replacing a file with a directory since revision 19 (below). The NTFS/APFS name confusions are live since revision 17 (§4.3).

**Hard links and parent directories (revision 18).** **[Verified]** by `pillar2_test.zig`. A won race now makes one of three swaps, picked by a keyed decision among those that apply and are enabled (`vfs_toctou_swaps`, all by default):
- **a symlink** at the path, to `setToctouTarget`'s target (as before);
- **a hard link** at the path to the file at that target. The path is still a regular file, so a second `lstat` after the open does not see it;
- **a parent swap**: the path's first directory is moved aside and replaced by a symlink to `setToctouDirTarget`'s directory. No-follow applies to the last component only, so `lstat` of `public/report.txt` follows it.

Seam 3's `vfs_op` returns the swap (`sec_seam.Swap`: kind and target), and core makes it, recording `toctou swap`, `toctou hard link` or `toctou parent swap` in the trace. A swap core cannot make (no such target) leaves the path alone. The exit test publishes `public/report.txt` after `lstat`, open, `lstat` again: that catches the symlink, while the hard link and the parent swap each leak `private/report.txt` (CWE-200), shrunk to at most 5 decisions. Comparing the checked inode with the opened handle's (`file.stat`) holds against all three, with swaps made in the runs. `std.Io` in Zig 0.17 has no no-follow open, so `O_NOFOLLOW` is not a defense a program can use here.

**A directory in place of the file (revision 19).** **[Verified]** by `pillar2_test.zig`. A fourth swap, `directory`, deletes the entry and makes an empty directory there; it needs no target, and core records `toctou directory`. The open then fails with `IsDir` although the check said "regular file", so the swap's point is the program's error path. It is off by default (`vfs_toctou_swaps.directory = false`): a program that returns the error just fails the run, which is not a finding. The exit test is an export gate that checks `export.deny` is a regular file, then reads it; the buggy version takes a failed read as "no restrictions" (fail-open, CWE-636) and exports `private/report.txt`, which the egress scan reports as CWE-200, shrunk to at most 5 decisions. The same program passes with the default swaps, and the version that refuses the export when the read fails holds, with swaps made in the runs.

**Two-faced node.** `twoFaced(node, peers, mutate)` rewrites datagrams from `node` to the listed peers, with `byzantine_ppm` per datagram (keyed). The others get the original. `ByzantineFrameSpec(H).equivocateFrame(i, flip)` is a ready-made rewrite that flips payload byte `i` and recomputes length and checksum, so the frame verifies. `encode`/`decode` give the wire form of an `extern struct` header followed by the payload. In the exit test a leader proposes one value to two followers and is two-faced towards one of them. Followers that commit what the leader sends end up disagreeing. Followers that exchange echoes and commit only on agreement pass 100 iterations. The replay pool is live since revision 21, and length desynchronization in flight since revision 22 (both below).

**Streams (revision 20).** **[Verified]** by `pillar2_test.zig`. Seam 3 has a `stream` hook: core offers each segment it is about to push into a TCP stream (one write's span, or what is left of it after a short write), and the layer may hand back a rewrite of the same length. A stream has no message boundaries, so a rewrite that changes the length is dropped rather than desynchronizing core's byte accounting. `twoFaced` applies its `mutate` there too, with the same `byzantine_ppm` decision, and core records `byzantine` on the write. A mutation that works on whole frames, like `equivocateFrame`, applies when the frame goes out in one segment. The exit test is the equivocation test over TCP: the leader connects to each follower and writes its proposal as one frame. Followers that trust the frame disagree, shrunk to at most 5 decisions; followers that exchange echoes pass, with rewrites made in the runs.

**Replay pool (revision 21).** **[Verified]** by `pillar2_test.zig`. `replayer(node, peers)` puts an attacker on the links from `node` to `peers`. It records every datagram sent on them (16 frames of up to 256 bytes, oldest overwritten first) and, with `byzantine_ppm` per later datagram on the same link, delivers one recorded frame again just before it, picked by a keyed decision. Seam 3's `replay` hook hands core the extra datagram; core sends it without loss decisions (a chosen replay arrives) and records `replay`. It is an injection, not a substitution, so the program's own frame still arrives and a correct receiver can win. The pool belongs to the run, not to a node, so a frame recorded before a peer's reboot is replayed after it. The exit test sends four numbered commands to an actuator and crashes it between the second and the third. An actuator that keeps the last applied number in memory takes a replayed old command again after the reboot ("each command takes effect once, in order" fails, shrunk to at most 5 decisions). One that writes the number to a file and syncs it before acting passes, with replays made in the runs, and the forgetful one passes when nothing replays.

**Length desynchronization in flight (revision 22).** **[Verified]** by `pillar2_test.zig`. `Spec.desyncFrame(delta, fix_checksum)` is a rewrite for `twoFaced`: the frame's length field becomes `len + delta` (wrapping) and its bytes stay as sent. With `fix_checksum`, the checksum is recomputed over the span now claimed, so a shorter claim passes integrity and its tail reaches the parser as the next frame; a longer claim's checksum cannot be computed, so it is left alone. Without the fix, the frame goes out as is and a receiver that trusts the length over- or under-reads. The exit test is request smuggling (CWE-444): a client's text, sent by a proxy as one data frame, ends with bytes that encode an admin frame. On the wire the data frame is shortened by exactly that frame's size. A gateway that parses frames back to back runs the admin frame ("a client's text never runs as an admin frame" fails, shrunk to at most 5 decisions); one that takes one frame per datagram and requires it to use the datagram exactly passes, with rewrites made in the runs. A unit test checks the rewrite itself.

**Shrinking.** All four failures shrink, far below the "≤ 5 decisions" exit criterion:

| Planted bug | Natural decisions in the failing run | After shrinking |
|---|---|---|
| AB-BA lock order | 14 | 0 (the inversion needs no randomness) |
| Double fetch | 16 | 2 |
| Symlink TOCTOU | 27 | 2 |
| Equivocation | 27 | 1 |

### 4.5 Data races in instrumented code (revision 53)

**[Verified]** by `src/sec/datarace.zig` and the `race:` tests of `src/sec/tests/shadow_test.zig`, in all four build modes on Windows and on Linux.

The simulator runs one task at a time, so two tasks never touch a word at the same instant, and a load-then-store counter bumped by two tasks counts correctly in every run. On real threads the same code loses updates. With `SecurityConfig.data_races`, code built with the sanitizer's callbacks (§3.8) is checked for the pair real threads could interleave: two accesses to one address from two tasks of one node, at least one a store, with nothing ordering the first before the second. That is CWE-362 (`data_race`), at the second access, and it fails the run.

**Happens-before.** Each task has a vector clock (128 task slots). What orders one task's steps after another's:

| Event | Source | Effect |
|---|---|---|
| spawn | core, through the new optional seam hook `task_sync` | the child starts with the parent's clock |
| wake | `task_sync` | the woken task joins the waker's clock (a futex wake, a cancel, a finished task waking its awaiter) |
| await of a future or a group | `task_sync` | each finished task publishes its clock at its future or its group; the awaiter joins it, whether or not it had to wait |
| atomic operation | the sanitizer's atomic callbacks | a store or read-modify-write publishes the task's clock at that address, a load or read-modify-write joins it |

The last row is what a mutex needs. The uncontended path of `std.Io.Mutex` is a compare-and-swap that never reaches the simulator, which is why revision 50 called this detector a no-go. In an instrumented object that compare-and-swap is a reported atomic, the unlock is another, and the contended path adds a wake, so data guarded by a mutex locked in instrumented code is ordered with no knowledge of mutexes at all. The same holds for anything `std.Io` builds from atomics and futexes.

**Per address**, a direct-mapped table of 65,536 cells keeps the last store and the last load (task and clock). A cell from an earlier run, or evicted by another address, is empty. Addresses the simulated heap hands out again start with no history. Tasks of different nodes are different processes and never race.

**Exit tests.** Two tasks bump one heap counter with `p.* += 1` in the object: CWE-362 within 50 iterations, while the same test without the detector passes, since the count is right. The same bump under an `std.Io.Mutex` locked in the object, as one atomic add, or by two tasks spawned one after the other's await, passes 50 iterations each with the detector and the shadow on.

**Limits.**

- **Misses, by construction.** One store and one load are remembered per address, not every reader; accesses are matched by start address, so a 1-byte load inside an 8-byte store is not paired with it; a range is checked at its first byte and every eighth after it, up to 4 KiB; an evicted cell is forgotten.
- **Synchronization outside the object is not seen.** A mutex locked by the uninstrumented test body orders nothing, so data it guards is reported. Lock in the code under test.
- **Message causality is coarse** (revision 57). A task that reads from a file comes after every task of its node that wrote to any file before, and the same for sockets: one key per node for each. That removes the false report for a hand-off through a file or a socket, and hides a race between two tasks that merely both did I/O.
- **Which races are seen can differ between processes.** The table is indexed by address, two addresses that share a cell evict each other, and which pairs collide follows where the process was loaded.
- **Atomic minimum and maximum** are left to the processor by the compiler and order nothing.
- **Extra edges hide races.** A wake that core issues to every task blocked on the network is taken as an order between the waker and each of them.
- **Capacity.** 128 task slots and 512 synchronization addresses per run; a run that outgrows either reports nothing further (`Detector.blind`).

### 4.6 Lock order for `std.Io.Mutex` in instrumented code (revision 54)

**[Verified]** by the `lock order:` test of `src/sec/tests/shadow_test.zig`, in all four build modes on Windows and on Linux.

`std.Io.Mutex` keeps its state in a 32-bit atomic: zero is unlocked, `lock` takes it from zero with a compare-and-swap or an exchange, and `unlock` exchanges zero back. Core never sees the uncontended path. In code built with the sanitizer's callbacks (§3.8) the runtime performs those atomics itself, so it sees their operands and results. With `SecurityConfig.atomic_lock_order`:

- a 32-bit atomic that a successful compare-and-swap takes from zero to non-zero, or that an exchange of a non-zero value finds at zero, is **taken** by the current task;
- an exchange or a store of zero **drops** it, if it was ever taken.

Each such word gets a lock class by (node, address), from the range the C shims' mutexes use (§4.2), and the order matrix of §4.2 does the rest: taking two of them in both orders is CWE-833 (`lock_order`), reported at the second order, in a run that need not deadlock.

**Exit test.** One task takes mutex A then B in the object and finishes; a second takes B then A: CWE-833 within 20 iterations. The same order twice passes, with the race detector on as well. With the option off the inverted order passes, since no run deadlocks.

**Limits.**

- **The shape is a guess.** Any 32-bit atomic used as a zero/non-zero flag is taken for a lock. That is a lock in effect when it is a spin or try flag; a flag set once and never cleared stays "held" by its task and adds order edges from it to every lock that task takes later.
- **`tryLock` is not told apart** from `lock`'s fast path (they are the same compare-and-swap), so an inversion through a `tryLock`, which cannot deadlock, is reported.
- **64 classes** per run, shared with C mutexes; later words are not tracked.
- **Only instrumented code.** A mutex locked by the test body or by `std` code compiled into the test is not seen.
- **No hold-across-yield check** for these words, on purpose: an `std.Io.Mutex` is meant to be held across I/O.

---

## 5. Pillar III: Comptime-Reflected Byzantine Fuzzing, Checksum Fixup & Sink Auditing

### 5.1 In-flight Byzantine mutation: `ByzantineFrameSpec(HeaderT, opts)`

Random byte flips die at the first checksum, so they test the checksum and nothing else. `ByzantineFrameSpec` reflects over the protocol's header type at comptime. It finds the length field, the checksum field and the epoch field by name, checks their types (a CRC32 needs at least a `u32` field, xxHash64 a `u64`), and generates mutators that leave the frame *valid*. **[Verified]**: the Byzantine test builds two conflicting Raft frames that both verify, then breaks one by length desync.

```zig
const Spec = tardis_sec.ByzantineFrameSpec(RaftHeader, .{
    .length_field = "len", .checksum_field = "crc", .epoch_field = "term", .checksum = .crc32,
});
```

1. **Length desynchronization**: `Spec.desyncLength(&h, delta)` sets the length prefix to `len + delta` with wraparound, so the receiver over-reads, under-reads or wraps its arithmetic. Optionally the checksum is fixed over the shorter or longer span, so the frame passes integrity and reaches the parser.
2. **Two-faced equivocation (split brain)**: `Spec.equivocate(h, payload, index, flip, &h2, payload2)` clones a proposal, changes one byte, and recomputes length and checksum. The network layer delivers frame A to one half of the cluster and frame B to the other half *at the same virtual nanosecond* (core's network lets the simulator pick delivery per link). The safety oracle (for example "two nodes never commit different values for one index") then shows whether the protocol tolerates an equivocating peer. **[Design]** for streams and same-nanosecond delivery; live for datagrams (`twoFaced`, §4.4).
3. **Replay across reboots**: authentication and handshake frames are captured into `ByzantineReplayPool` (2048 × 16 KiB). After `env.crashNode` and restart, they are replayed to test nonce and epoch freshness. `Spec.epochOf` lets the oracle tell stale from fresh.

The mutation choice (which frame, which field, which byte, which half) is made of keyed decisions with 0 as "no mutation", so a Byzantine failure shrinks to the one mutation that matters.

### 5.2 Copy-preserving taint and sink traps

Ingress bytes get `untrusted_input` (`0x9`). Taint follows **copies only**: `memcpy`, slicing, `std.fmt` formatting of tainted bytes into a buffer, and `std.Io` writes into buffers. It does not follow control flow (a branch on a tainted byte does not taint what the branch writes), so taint cannot spread across the whole program.

`markSanitized(bytes)` clears it after validation. A tainted byte reaching a sink is a finding:

| Sink | CWE | Hook |
|---|---|---|
| `printf` / `fprintf` / `sprintf` / `snprintf` / `vsnprintf` format argument | 134 | C shim (live) |
| `system` command, `std.process` spawn argv | 78 | C shim (live); `processSpawn`/`processReplace` (live) |
| `sqlite3_prepare_v2` / `sqlite3_exec` SQL text | 89 | C shim (live) |
| VFS path (open, create, rename, delete) | 22 | `onVfsOp` |

Each hit goes to `TaintSinkAuditLog` (65,536 × 64 B: site, CWE, bytes, iteration) and to SARIF. **[Design]**: C sinks the header does not wrap (SQL APIs other than SQLite's). The taint states, every row of the table and, since revision 31, the audit log are **[Verified]**.

**The audit log (revision 31).** **[Verified]** by `pillar2_test.zig` and `evidence.zig`. Each taint check is counted per run by sink (`engine.SinkKind`: path, command, format, SQL), hit or not, while ingress taint is on. A counted run commits the counts with its findings, and the campaign sums them; the fork server carries them in its per-run header like the requirement counts. Since revision 32 a test certifies the raw-name file server in one process, through the fork server and on four worker processes, and expects the same sums and a byte-identical `sinks.json` (on Linux each run is a forked child; elsewhere `fork` runs in-process). The bundle gets a new file, `sinks.json`: the counted runs, and per sink its CWE, the checks made, the hits, and each distinct hit with its node, offset, first seed, occurrences and replay token. A sink that was checked thousands of times without a hit is evidence that the program's inputs reached it and were clean, which a list of findings cannot show. The exit test certifies the file server of the CWE-22 test: with the raw name every run checks at least three paths and the hit is listed with its replay token; with the validated name the path sink is checked in every run and nothing is listed. **Deviations from the design:** distinct hits are kept, not every hit (the campaign's 64 distinct findings bound them), and a hit records the finding's offset, not the bytes.

**Live since revision 27: the C shims.** **[Verified]** by `cshim_test.zig`, which links `tests/c/legacy.c`, built by `zig cc` against the header, on Windows (MinGW) and Linux (musl). C code includes `src/sec/c/tardis_sec.h` after its system headers. The header declares eight functions (six sinks and lock hooks, and since revisions 35 and 39 `tardis_sec_critical_check` and `tardis_sec_mcdc`), and inline wrappers that check and then make the real call; unless `TARDIS_SEC_NO_SHIMS` is defined, macros rename the wrapped calls:
- the format of `printf`, `fprintf`, `sprintf`, `snprintf` and `vsnprintf` is checked (CWE-134, `tainted_format`);
- the command of `system` and `popen` is checked (CWE-78, `tainted_command`), and they return -1 and NULL, since core runs no processes;
- since revision 32, the path and each argument of `execv`, `execvp` and `execve` are checked (CWE-78; up to 32 entries), and they return -1; since revision 33 also `execl`, `execlp` and `execle`, and after `<spawn.h>` `posix_spawn` and `posix_spawnp`, which return `ENOSYS`;
- since revision 32, each of these process starts is reported like a simulated spawn (`system` and `popen` as `/bin/sh -c command`), so from a node whose sandbox does not allow process spawning it is CWE-272;
- after `<sqlite3.h>`, the SQL text of `sqlite3_prepare_v2` and `sqlite3_exec` is checked (CWE-89, `tainted_sql`);
- after `<pthread.h>`, `pthread_mutex_lock` and `unlock` report the mutex by address, and the engine gives each (node, address) a lock class from 128–191 in first-locked order, for the same order matrix as `Mutex` and file locks (CWE-833, "C mutex N" in SARIF).

The Zig test exports them with `comptime { tardis_sec.exportC(); }`, so a build that links no C has none of them. The checks use the same ingress taint as the path sink: 8 or more received bytes in a row, not passed to `markSanitized`. A finding fails the run and the call goes on. Without an active simulation the functions do nothing. The exit tests: a C library that builds its greeting into a format string, pastes a name into SQL, or puts it on a shell command line is CWE-134, 89 and 78 for a name received over TCP, each shrunk to at most 5 decisions. Passing the name as an argument, binding it as a parameter, or keeping the command constant passes. A name in an `execvp`, `execlp` or `posix_spawnp` argv or a `popen` command is CWE-78 and constant ones pass; the constant `system` command from a sandboxed server is CWE-272 and passes when the sandbox allows spawning. A transfer and an audit job that take two pthread mutexes in opposite orders are CWE-833 with the two C classes; the same order passes. **Limits:** only calls compiled with the header are seen, so a prebuilt C library needs relinking (for example with `-Wl,--wrap`), which is not provided. C I/O (`fopen`, sockets) does not go through core, so its bytes are neither simulated nor tainted.

**Live since revision 23: ingress taint and the VFS path sink.** **[Verified]** by `pillar2_test.zig`. The content engine taints received network bytes by content: every distinctive 8-byte window of a stream read or a datagram goes into a per-run set of 16,384 (`untrusted_dropped` counts overflow). Copies keep the taint because it is the bytes that are matched, wherever they are: slicing, `memcpy`, `std.fmt` into a buffer. Seam 3's `path` hook sees the path of every `openFile`, `createFile`, `deleteFile` and `rename` (both paths). A path holding a tainted window is a finding, CWE-22 (`tainted_path`), with its offset, and fails the run. `markSanitized(bytes)` removes those windows after validation. Taint by content clears equal bytes elsewhere too, until they are received again. `SecurityConfig.taint_paths` (default on, and on under `TARDIS_SEC=1`, where every test in the repository still passes) turns both off. The exit test is a file server that reads `files/<name>` for a name sent over TCP. With the name used as received it is CWE-22, shrunk to at most 5 decisions; checking it is a plain name and marking it sanitized passes. **Limits:** names shorter than 8 bytes; file reads are not ingress (a name read from a file is not tainted); the other sinks of the table need the C shims.

`tardis_sec.enterSandbox(policy)` declares the end of initialization. After it, capabilities outside `SandboxPolicy` (outbound connects, process spawn, VFS writes outside allowed prefixes) are findings. This tests that the program actually drops privileges, which matters when it relies on `pledge`/`seccomp`/AppContainer in production.

**Live since revision 26: the sandbox and the spawn sink.** **[Verified]** by `pillar2_test.zig`, and with `TARDIS_SEC=1` over the whole repository. Core has a seam hook, `capability(ctx, node, cap, argv) u16`, called by `connect` (`net_connect`), `listen` and `bind` (`net_listen`), and `std.process.spawn` and `replace` (`process_spawn`, with the argv). Core runs no processes, so a spawn still fails with `OperationUnsupported`, after the layer has seen it. `enterSandbox` stores the policy for the calling node in the engine, until that node's program restarts: a crash or the next run clears it (the heap wipe), so a restarted program initializes with every capability again. After it:
- a capability the policy does not allow is CWE-272 (`privilege`, with the `Privilege` and the node);
- the `path` hook checks opens, creates, deletes and renames against `vfs_prefixes`, and creates, deletes and renames against `allow_vfs_write`; a path outside them is CWE-272 as well.

Like every hook, the call then goes on unchanged and the run fails at its end, so the trace is the same with and without the layer. With ingress taint on, a spawn argument holding 8 or more received bytes in a row is CWE-78 (`tainted_command`, with the argument's index), sandbox or not. The exit tests: a front end that reconnects to its backend on a refresh request, after `enterSandbox` dropped connects, is CWE-272, shrunk to at most 5 decisions; keeping the connection opened during initialization passes, through a restart whose initialization connects again. A job runner that passes a received job name to `convert` is CWE-78; validated and marked sanitized it passes, and then writing `jobs.log` outside `spool/`, or spawning under a policy without spawns, is CWE-272. **Limits:** prefixes are compared with the path as the program passes it, relative to its directory handle; directory creation and removal, links and permission changes are not checked; `std.Io.Dir` reads of a path go through `open`, so a policy with no prefixes forbids reads too.

### 5.3 Differential and request-smuggling oracles (`assertDifferential`)

Two implementations of one parser or protocol (two HTTP framers, a reference and an optimized decoder) receive the same fuzzed input, each in its own scratch buffer. They must agree: both reject, or both accept with equal results. A disagreement on message boundaries is request smuggling (CWE-444). **[Verified]**: the differential test catches a framing disagreement where one parser accepts trailing whitespace and the other rejects it. In the full system the scratch buffers are carved from Region C, so a divergence report includes both parsers' shadow states.

---

## 6. Pillar IV: Algorithmic Complexity (DoS), Spectre-v1 & Constant-Time Oracles

### 6.1 Resource amplification (`CostAmplificationLedger`, CWE-400 / CWE-407)

For each request, keyed by operation type and node, the ledger tracks N untrusted input bytes against four costs. Ratios are integers in thousandths, so no floating point is involved. **[Verified]**: `Amplification.exceeded`.

| Ratio | Numerator | Default limit (milli) |
|---|---|---|
| `blocks_per_input_byte` | edges executed (Zig `-ffuzz` inline 8-bit counters; SanitizerCoverage counters in C) | 64,000 |
| `alloc_bytes_per_input_byte` | Region A bytes allocated | 32,000 |
| `tx_bytes_per_rx_byte` | bytes sent per byte received (reflection) | 10,000 |
| `nvme_sectors_per_input_byte` | 4 KiB pages flushed by the VFS (core's `flushedBytes`) | 2,000 |

A ratio above its limit is a finding. More importantly, the peak ratio per operation becomes a coverage feature (bucketed by power of two), so exploration keeps and mutates the inputs that push it up. This is how hash-collision attacks (HashDoS against a fixed-seed hash table), decompression bombs and quadratic parsers are *synthesized*, not just waited for.

**What runs today (revision 4).** **[Verified]** by `src/sec/tests/pillar45_test.zig`.

- **The ledger:** `src/sec/amplify.zig`, per run.
  - Network bytes in count as input automatically; `tardis_sec.untrustedInput(n)` declares other input.
  - `tardis_sec.work(n)` counts work units (hash probes, loop steps). That is the numerator of `work_per_input_byte` until an edge tracer exists.
  - Allocations come from the allocator hook, and bytes out and file bytes from the egress hook.
- **Turning it on:** `SecurityConfig.amplification` enables the checks. They are off by default, because any program allocates more than its input in absolute terms.
- **At the end of the run:** a new seam call, `end_run`, feeds the work and allocation ratios to guided exploration as coverage features, 8 log-linear buckets per power of two. A ratio over its limit is a finding: CWE-407 for work, CWE-400 for the rest.
- **The exit test:**
  - **The program:** 16 untrusted `u16` keys go into a chained table with 16 buckets and a fixed multiplicative hash.
  - **The limit:** 3 comparisons per input byte. That needs about 13 keys in one bucket, about 1 run in 10^10 at random.
  - **Results:**
    - Guided exploration synthesizes a colliding key set at iteration **13,974**, with a corpus of 21. The run is deterministic, so this is the same in every mode and on Linux. That is under the 10^5 exit criterion.
    - Random exploration does not find it in 5,000 iterations.
    - The fix, a per-process hash seed, passes 10,000 guided iterations.
- **Limit:** the feature is the run's ratio, not a per-operation peak (one ledger per run, not per request type).

### 6.2 Starvation chaos

| Fault | Knob | Effect |
|---|---|---|
| Descriptor exhaustion | existing core limits (`Limits` handles) plus `EMFILE` injection | accept and open fail with `error.ProcessFdQuotaExceeded` |
| Slowloris | per-connection 1-byte drip schedule | tests read timeouts and per-connection budgets |
| Entropy starvation | `entropy_starvation_ppm` | `randomSecure` fails or blocks, testing fallback paths |

### 6.3 Constant time and Spectre-v1 (`assertConstantTime`, CWE-208 / CWE-1037)

**Dual execution.** The function under test runs twice on the same seed, once with `secret_A` and once with `secret_B`. The observable traces must be identical. **[Verified]** today at the **I/O boundary**: the SDK compares core trace hashes, which cover every `std.Io` operation, its size, its result, and its virtual time. The tests show a Poly1305 tag computation passing, and a function that exits early on the first secret byte failing with `error.TimingLeak`.

**The full tracer (§8.7).** With worker W running `secret_A` and worker W+1 running `secret_B` in lockstep, the comparison extends to three observables, each compared after normalization:

- **Control flow:** the edge trace (Zig `-ffuzz` 8-bit counters with the PC table, read per edge; SanitizerCoverage in C).
- **Memory access pattern:** the cache-line offset of each traced access within the arena, `@intFromPtr(ptr) & 0x3FFF_FFC0`. The two workers' arenas differ only in the bits above bit 30, so masking to 30 bits removes the arena difference and keeps the cache-line index (bits 6–29).
- **Variable-time instructions:** the operands of `div`/`udiv` at clang `trace-div` sites in C, and at `tardis_sec.div` wrappers in Zig.

**Live since revision 28: the tracer for instrumented C.** **[Verified]** by `ctrace_test.zig`, with `tests/c/ct.c` built by `zig cc -fsanitize-coverage=trace-pc,trace-cmp,trace-div`, on Windows (MinGW) and Linux (musl), in all four build modes. A test that links such C calls `comptime { tardis_sec.exportCoverage(); }`, which exports the callbacks: `trace_pc`, `trace_pc_guard` and its init, `trace_cmp1`–`8`, `trace_const_cmp1`–`8`, `trace_switch`, `trace_div4` and `div8`. While a simulation runs on the thread, `c_trace` folds two observables into one hash:
- **control flow:** every edge, in the order taken, named by its address (stable within a process, which is where both runs of a dual execution happen) or by its guard number;
- **memory access pattern (revision 29):** with `trace-loads,trace-stores`, the cache set of every load and store, address bits 6–11 (the 64 sets of a typical 32 KiB L1 data cache with 64-byte lines), with the access's size and direction. The two runs' heaps and fiber stacks are separate page-aligned allocations, so bits above 11 differ between runs and are left out, and bits 6–11 are the part of the address that a cache attack sees. So that the inputs themselves do not differ in address, `traceWith` copies each secret and public input (up to 4 KiB) into one fixed buffer per thread, which both runs read;
- **variable-time instructions:** the width in bits of every traced divisor. Clang passes the divisor only, and traces `/` but not `%` (and the optimizer may turn a hand-written remainder back into `%`).

Comparisons are counted, and the constants compared against (`const_cmp`, `switch` cases) are kept, up to 64 a run: since revision 30 they steer guided exploration (§7.1). Comparison operands are not folded, since constant-time code may compare secrets as long as it does not branch on them. `traceWith`, under `assertConstantTime` and `assertNonInterference`, resets the tracer before each run and mixes its hash into the core trace hash when it saw anything, so tests without traced C get the same hashes as before. The exit tests: an early-exit tag compare in C, with no I/O to show it, is `error.TimingLeak` for two secrets that differ from the forgery in the first and the last byte, and the OR-accumulate compare passes; dividing by a 2-bit secret and by an 8-bit one is `error.TimingLeak`, and dividing by a public value passes non-interference; an S-box style lookup in a 1 KiB table at entries 0 and 200 (12 lines apart) is `error.TimingLeak`, and a masked scan of the whole table passes (revision 29); `command_code` leaves its magic number and switch cases as tokens; C called outside a simulation is not traced. **Limits:** `trace-pc-guard` does not link for Windows GNU targets (clang emits ELF section bounds that `lld-link` does not define), so `trace-pc` is the portable choice; on Windows the coverage flags also make clang embed a link directive for its UBSan runtime, which Zig does not ship, so the C is built with `-fno-autolink`; only C is traced, since Zig emits none of these callbacks (§1.2); cache sets model one cache level and ignore prefetching and banks, and the 30-bit cache-line offsets of §6.3's design need fixed-address arenas; the Spectre-v1 shape is live since revision 43 (below).

**Spectre-v1 (revision 43).** **[Verified]** by `ctrace_test.zig` and `spectre.zig`, as a heuristic over what the program does in bounds; speculation is not modelled.
- **The marker.** `TARDIS_SEC_BOUNDS(index, len)` in C and `tardis_sec.spectre.boundsCheck(index, len)` in Zig are `index < len` for an index the attacker chooses. When the check holds, the engine watches the next 8 loads, for at most 16 traced edges. C loads come from `trace-loads`, which also gives the value about to be read; Zig has no load tracing, so the code passes its loads through `spectre.load(ptr)`.
- **The rule.** For every pair of loads in a window the detector keeps, per check site and over the campaign's runs, three observations in which the earlier load read different values from different addresses. If the later load's addresses lie on a line in those values, with a whole nonzero slope, the later address is `base + slope * value`: the gadget, CWE-1037, with the slope in the finding (64 for `probe[table[x] * 64]`).
- **Why the earlier load must move.** Unoptimized code reloads the index from its stack slot, and `table[x]` then looks addressed by a loaded value, with slope 1. That load is at one address; the load the attacker's index addresses is not. Measured: without this condition the test reported slope 1.
- **Hardening.** `tardis_sec_index_nospec(index, len)` and `spectre.indexNoSpec` return the index masked to 0 when it is out of bounds, and open no window: the detector trusts the marker and does not check the generated code.
- **The exit test.** The classic gadget over a 16-entry table, in C and in Zig, is found within 200 iterations with slope 64. The same lookup with a hardened index, and two plain loads after a check, pass.
- **Limits.** A site needs three different values; an address that is not linear in the value is missed; a table whose values are linear in the index makes a later load at `index + c` look value-addressed. **Deviations from the design:** the check is marked by the code, not recognized from tainted `trace-cmp` operands (content tracking does not follow integers); and the rule looks at the value a load returned, not at a `secret_key` byte, since in bounds the table is not secret.

**The design it replaces.** After each traced bounds check whose operands are tainted (`untrusted_input`), traced by clang `trace-cmp` in C or `tardis_sec.boundsCheck` in Zig, the tracer keeps a window of the next 16 basic blocks. If, within that window, a load's cache-line offset depends on a `secret_key` byte, and the load's index is not masked (`index & mask` or a `std.math.clamp`-style select that Zig and LLVM emit as a conditional move), it reports CWE-1037. This is a heuristic over traces, not a microarchitectural model: it finds the classic `array2[array1[x] * 64]` gadget shape. It does not prove the absence of other speculative leaks. Superseded by revision 43.

---

## 7. Pillar V: High-Assurance Certification Engine (DO-178C MC/DC, CC EAL7 & FIPS 140-3)

### 7.1 MC/DC and dead code (DO-178C DAL-A)

**Definition.** For a decision with conditions c1…cn (for example `A and (B or C)`), MC/DC requires that every condition is shown to independently affect the outcome. For each ci, two test vectors must exist that differ in ci, keep every other condition that matters the same (unique cause), or mask it (masking MC/DC, accepted per CAST-6), and produce different outcomes.

**Instrumentation.**

- **C code:** clang's `-fcoverage-mcdc` (with `-fprofile-instr-generate -fcoverage-mapping`) records a per-decision test-vector bitmap. `tardis_sec` reads the bitmaps after each run.
- **Zig code:** Zig has no MC/DC instrumentation. `tardis_sec` provides `mcdc.decision(id, .{ a, b, c }, outcome)`, a comptime wrapper that evaluates the conditions with short-circuit semantics preserved and records the vector. Projects instrument the decisions their requirements cover, and a lint lists unwrapped compound conditions in files marked DAL-A.

**Storage.** `LocalMcdcTable` holds 16,384 decisions × 64 B: the decision id, condition count (up to 8), and a 256-bit bitmap of observed vectors (2^8 combinations) with outcomes. At the Epoch Barrier the tables are OR-reduced, so coverage is monotone and the merge is the same for any worker count.

**Steering.** Each decision with an unproven condition is a coverage target. For condition ci, the engine computes the vectors that would complete an independence pair with an observed vector, and turns them into comparison tokens. These are the operand values that would flip ci, taken from the condition's recorded operands (`mcdc.decision` in Zig, `trace-cmp` in C), offered to `tardis.fuzzInput`'s mutator as forced values. This is the same mechanism core's guided exploration uses for forced decisions.

**Comparison feedback (revision 30).** **[Verified]** by `ctrace_test.zig` and `explore.zig`, for instrumented C. Two links join the C tracer (§6.3) to core's guided exploration (`Options.explore = .guided`):
- **edges as features:** every traced edge also sets a bit in the run's coverage map (`Sim.cover`), so C that does no I/O still grows the corpus;
- **constants as forced values:** seam 3 has an optional hook, `tokens(ctx) []const u64`, which core calls after each run. The engine answers with the constants the run's C compared against (the tracer is reset at each run's start). Core keeps up to 256 distinct ones in the corpus (`Corpus.addTokens`). When a mutation forces a decision, a fifth of the time the raw value is one of them, and an integer that `env.fuzz` draws from that decision then equals the constant. Without tokens, mutation draws exactly as before, so campaigns without the layer are unchanged.

With several workers each job carries its run's first 16 constants, merged in job order like the corpus, so the campaign is the same for any worker count. The exit test is a C header check against a 32-bit magic number, fed by `env.fuzz(u32)`: one value in 2^32, so 2,000 iterations without the layer never pass it. With it, guided exploration reaches the planted bug at iteration 25 on one worker, and within the 2,000 on two. **Limits:** a token reaches a value only through an integer draw of its width, not through byte buffers, which `env.fuzz` fills 8 bytes at a time.

**Zig conditions (revision 33).** **[Verified]** by `pillar45_test.zig` and `mcdc.zig`. Zig emits no comparison callbacks, so a condition that is a comparison is written `mcdc.compare(a, op, b)`: it returns `a op b` and offers `b`, the value compared against, to the same token table (for an ordering, `b - 1` and `b + 1` too). Integers and enums up to 64 bits. The input `a` is not offered: it differs in every run, and offering it filled the table with values not worth forcing (measured: the exit test then failed). The exit test is a gate, `armed and code == 0xC0DE600D`, with the code from `env.fuzz(u32)`: with `mcdc.compare`, 2,000 guided iterations show both conditions, on one worker and on two; with a plain `==` neither is shown. For each gap, `Entry.wanted(c)` gives a vector to test next: one whose partner with `c` flipped was seen, else one of an unseen pair. It is null when every pair was seen and the outcome never changed, so no test can show the condition and it is redundant. `mcdc.json` lists them per decision (`wanted`, in the order of `gaps`). **Deviation from the design:** the engine does not compute operand values itself; the code names the comparison.

**Dead code.** At campaign end, instrumented decisions never reached are listed as dead or deactivated code. So are edges whose counters stayed zero in requirement-bound tests (the PC table maps them back to source). The project then justifies each one (deactivated by configuration) or removes it.

**What runs today (revision 4).** **[Verified]** for Zig code. `src/sec/mcdc.zig` and `tardis_sec.mcdc.decision(id, .{ c0, … }, eval)` record each vector into a 256-decision table. The table outlives runs and is OR-merged from every worker into `SecurityConfig.mcdc`, so the result is the same for any worker count.

- **Steering:** each new vector is a coverage feature.
- **Coverage per condition:** `Entry.pair(c)` returns the unique-cause independence pair for condition c, `shown()` and `complete()` summarize, and `Report.write` prints one line per decision.
- **The exit test:**
  - `armed and (sig_ok or override)` is shown for all three conditions in 64 iterations.
  - `armed or (armed and sig_ok)` is reported with a **gap** for `sig_ok`, even though all four vectors ran. The condition can never affect the outcome: exactly the redundant logic MC/DC exists to expose.
- **Limits:**
  - Conditions are passed as evaluated booleans, so this is the stricter unique-cause form; masking MC/DC is not modelled.
  - The dead-decision list and MC/DC per requirement need the project's list of decision ids: since revision 8 that is `CertifyOptions.decisions` (below).
  - **C decisions (revision 39).** **[Verified]** by `cshim_test.zig`. C records a decision as Zig does: `tardis_sec_mcdc(id, n, vector, outcome)` returns the outcome and records the vector in the same 256-decision table, and `TARDIS_SEC_VECTOR2`/`3`/`4` build the vector from the conditions. The exit test records `armed && (sig || override)` from C over three fuzzed bits: all three conditions are shown in 64 iterations.
  - The clang MC/DC import for C is not done, and is no longer planned as the way in: `zig cc` 0.17 compiles with clang's MC/DC mode (the bitmap section is present), but the bitmaps mean nothing without clang's coverage mapping (`__llvm_covfun`: which bits belong to which decision and how many conditions it has), and Zig ships neither the profile runtime nor `llvm-cov` to read it. The wrapper above costs one call per decision instead.

**MC/DC per requirement and dead code (revision 8).** **[Verified]** by Example 2. The project declares its instrumented decisions to `certify` as `mcdc.Decl` values. Each has an id, a name, the requirement it implements, and, for code deactivated by configuration, the justification (DO-178C §6.4.4.3).

- **The registry row.** At campaign end each declared decision counts towards its requirement's row: `mcdc_decisions_total` is the number declared, `mcdc_decisions_covered` the number with every condition shown. `rtm.csv` carries both as its last two columns. A merge keeps the maximum, so a later campaign that declares nothing does not erase them.
- **`mcdc.json`.**
  - Each reached decision carries its name and requirement.
  - `unreached` lists declared decisions never reached: `dead`, or `deactivated` with its justification.
  - `undeclared` lists decisions reached but missing from the list, so the list itself is checked.
- **SARIF.**
  - Two more rules, `tardis/mcdc-gap` and `tardis/dead-decision`.
  - Each declared decision with an unshown condition is a warning. So is each dead one. A deactivated one is a note carrying its justification.
- **Example 2.**
  - The follower's commit `well_formed and same` is decision 1 for SFR-FDP_ITC.2. Over 120 iterations it sees only two vectors, because the Byzantine leader corrupts a value but never an echo's length. So `same` is shown and `well_formed` is reported as a gap: the requirement has 0 of 1 decisions covered. The campaign finds that no test sends a malformed echo.
  - A declared recovery decision for SFR-FPT_RCV.1 is reported dead.
  - A deactivated one is reported as a note.
- **Not done (revision 8):** edges whose counters stayed zero. Revision 14 adds them (below).

**Dead edges from coverage counters (revision 14).** **[Verified]** on Linux (WSL2), by Example 2 built with `-Dedges`, in Debug and ReleaseSafe.

- **Guidance (revision 40).** **[Verified]** on Linux (WSL2) by `zig build test-edges` (`edge_guided.zig`). The engine zeroes the counters at each run's start (under `certify`, folding them into the seen set first, as before) and at its end sets one coverage bit per edge that ran (`Sim.cover`), so `Options.explore = .guided` keeps runs that reach new code. A three-byte header checked one byte at a time is passed at iteration 15,388; 200,000 random iterations never pass it. Edges are features only while one engine exists: the counters are per process, and several workers would mix their runs.
- **The build.** `zig build evidence -Dedges` compiles the campaigns as Zig fuzz builds:
  - module `fuzz = true`, with the LLVM backend (and LLD on ELF);
  - an ELF or Mach-O target; on COFF (Windows) the step fails with a message, because Zig emits no counters there.

  Every edge then has an inline 8-bit counter in section `__sancov_cntrs` and its address in `__sancov_pcs1`, which the program reads through the linker's `__start_`/`__stop_` symbols.
- **The runner.** Zig's test runner runs a fuzz build only under `zig build`'s fuzzing server ("fuzz test requires server"). `src/sec/tests/edge_runner.zig` runs the tests as plain tests instead, and never starts the fuzzer. It defines the runner symbols Zig's fuzzer runtime links against, none of which is called.
- **Counting** (`src/sec/edges.zig`):
  - `certify` zeroes the counters when the campaign starts;
  - after each run, the engine's end-of-run hook folds them into a "seen" set and zeroes them again. A counter wraps after 255 hits, so sweeping once per campaign could read a busy edge as never run. Within one run the wrap remains: an edge hit exactly 256·k times in every run that reaches it reads as never run (a false "never ran", never a false "ran");
  - the counters are per process and unsynchronized, so an instrumented `certify` runs on one thread, without the fork server.
- **The scope.** `CertifyOptions.edge_scope` names the certified code: files by repository path, optionally narrowed to functions. Example 2 names its service, `follower` and `round`, not the tests in the same file.
- **Mapping.** At campaign end, each edge address is placed at its file, line and function through the program's own debug info. Two Zig 0.17 problems are worked around:
  - `std.debug`'s `getSymbols` hangs on Linux when given the caller's I/O and allocators, so it is called the way `std.debug` prints a stack trace (its I/O with cancellation blocked, its debug-info allocator). `evidence.locate` (seam 4's SARIF locations) had the same problem and is fixed the same way;
  - code inlined from an `inline fn` in another file (`std.mem.readInt`) carries that file's line number under the caller's file name. Such an edge (line 1961 of a 475-line file) is counted as `unplaced`, not listed.
- **The output.**
  - `edges.json`, in every bundle, says whether the build was instrumented, whether the counters were read, the scope, the edges in it and those that ran, and each line where an edge never ran with how many of its edges did.
  - The SARIF gets a `tardis/dead-edge` warning per such line, located at the line, for the project to justify (deactivated code) or remove.
  - The workflow builds the evidence with `-Dedges` and checks that every bundle with a scope measured something.
- **What the list means, measured on Example 2.**
  - Every listed edge never ran. In Debug, 18 of the service's 37 edges ran, and 13 lines are listed:
    - the error paths of `try`s: a bind, send, spawn or safety check that never fails;
    - the follower's rejection of a malformed frame (lines 41–42). The Byzantine leader sends wrong values in well-formed frames, so no test sends a malformed one: the same gap the MC/DC report finds for the echo (§7.1, revision 8).
  - A listed line's statement may still have run: a `try`'s own block is its error path, while the success path continues in a block counted on the next line.
  - The list is not complete. LLVM gives no counter to a block whose coverage follows from others (sanitizer-coverage pruning), so in Debug the followers' "trust the leader" branch, which the certified campaign never runs, has no counter of its own. In ReleaseSafe it has one, and line 44 (`if (!echo)`) is listed: 17 lines, 18 of 37 edges run.
- **Justifications (revision 16).** **[Verified]** on Linux (WSL2), by Example 2 built with `-Dedges`, in Debug and ReleaseSafe. Deactivated code is justified where it is written, as `mcdc.Decl.deactivated` justifies a decision:
  - **The marker.** `// tardis-deactivated: <reason>` at the end of a line marks that line. On a comment line of its own it marks the next line that is not blank or a comment. A marker without a reason marks nothing. `finish` reads the markers from the scoped files it already reads for their line counts.
  - **A listed line with a marker** carries the reason in `edges.json` (`justification`, and a `justified` count). In SARIF it is a `tardis/dead-edge` note with the reason instead of a warning.
  - **A marked line whose edges all ran** is `stale` in `edges.json` and a `tardis/stale-justification` warning: the code the justification calls deactivated ran, so the claim is wrong. A marked line with no edge of its own (pruned, or no code) is neither.
  - **Example 2** marks the echo socket's bind, which cannot fail on a fresh node. Its error path (line 50) is listed with the reason in both modes, 1 of 13 lines in Debug and 1 of 17 in ReleaseSafe, and nothing is stale.
- **Not done:** the comparison tracer, which needs more than Zig emits (§6.3).

### 7.2 Bounded exhaustive exploration with DPOR (`verifyExhaustive`, CC EAL6/EAL7)

**What it explores.** A service's reachable states up to `K` transitions, where a transition is one scheduling decision, one message delivery choice, or one fault decision: exactly the decisions core already keys.

**How.**

1. **State identity:** `Service.tardisStateHash()` (required at comptime; **[Verified]** as a comptime check) hashes the security-relevant state. Two schedules reaching the same hash at the same depth are merged.
2. **Partial-order reduction:** two transitions that touch disjoint resources commute (different nodes' local steps, messages on different links), so only one order is explored. This uses sleep sets plus source sets, the standard DPOR construction. The dependency relation comes from the resources each decision touches, which the simulator knows exactly.
3. **Storage:** `DporStateTable` holds 65,536 transition records of 64 B: the state hash, parent index, decision key and value, a backtrack bitmap, and a sleep-set summary.
4. **Restore, not re-run:** the search is depth-first with a stack of 16 snapshots (`Control.restore` in under 0.4 µs, **[Target]**). Deeper than 16, it restores the nearest snapshot and replays the forced decisions from there (stateless replay), so 65,536 states fit in 16 snapshot slots.

**What it returns.** `{ states_explored, transitions_pruned, complete }`. `complete = true` means every state reachable within K transitions, *in the simulated model*, was visited and the invariants held in all of them. That is bounded model checking of the implementation: strong evidence for ADV and ATE at EAL6/7. It is not an unbounded proof; an EAL7 evaluation still needs the formal model and its proof. **What runs today (revision 4): stateless, without DPOR.** **[Verified]**.

- **What it explores.** `tardis.exhaustive` in core, wrapped by `tardis_sec.verifyExhaustive`. The engine snapshots above remain **[Design]**; a partial-order reduction (revision 34) and a state table by history (revision 44) are live without them (below).
- **The domain log.** Core's `Decider` now logs every keyed draw with its domain:
  - `chance` and `boolean`: 2 outcomes;
  - `uniform(n)`: n outcomes;
  - raw draws: not enumerable.

  `valueFor` gives the raw value that forces each outcome.
- **The search.** Depth-first over forced prefixes:
  - an execution's unforced decisions take their benign value (0: no fault, no preemption, the first runnable task);
  - each child forces one more decision after its parent's last forced one, so each execution runs once;
  - each execution replays from the start (no snapshots).
- **The result:**
  - `executions`, `depth_seen`, `unenumerated` (raw or too-wide draws inside the window), and `depth_bounded`;
  - `complete`: every combination of the first `depth_max` branchable decisions ran and passed, with nothing unenumerated;
  - for a failure, the error and a replay token.
- **The exit test.** Three nodes each send a vote to the other two over UDP with 30% loss, then decide. Every draw in the model is made narrow, so the loss decisions and the scheduler's choices are the only nondeterminism.
  - **Decide the largest vote seen:** fails, and the counterexample replays from its token through `check`.
  - **Decide only with all three votes:** agrees in all **9,216** executions to depth 12, `complete = true`, nothing unenumerated.

  Executions make up to 15 branchable decisions, so the bound is real and stated.
- **The cost.** Without `reduce` it is the full product of outcomes: independent decisions are explored in every order. Snapshots would cut the per-execution cost, which is still a replay from the start.

**Partial-order reduction (revision 34).** **[Verified]** by `pillar45_test.zig`, with `ExhaustiveOptions.reduce = true` (off by default).

- **Steps and footprints.** A step is one task running from the point the scheduler chose it until it next yields or blocks. While a search runs with `reduce`, core logs each step (`Sim.Step`): its task and node, the tasks that were runnable when it was chosen, the tasks it woke, the datagram inboxes (node, port) it read or wrote (bind, send, receive, also an empty receive, and close), and a `global` flag. Every traced operation sets `global` unless it is known to stay inside the node: scheduling, the task's own keyed draws, and the node's files do; streams, spawns, crashes, link changes, futexes, clock steps, injected faults and everything not listed do not. Wakes by the clock are not the step's.
- **Independence.** Two steps commute when they ran on different nodes, neither is `global`, neither woke the other's task, and they share no inbox. Tasks of one node never commute: they share its memory, files and sockets.
- **The rule.** If step *b* runs right after step *a*, *b*'s task has the lower id and was runnable when *a* was chosen, and the two commute, then the execution that runs *b* first reaches the same state, and the search runs it too (it tries the lower task first). So the search still runs this execution, but creates no children that share its draws up to the end of *b*; `ExhaustiveResult.pruned` counts the alternatives not run. Of all orders of an execution's commuting steps, the one that always runs the lower task first is never cut, so every execution has an equivalent one that is run. This is the sleep-set idea limited to adjacent steps; it needs no snapshots and no state table.
- **What it assumes.** Tasks on different nodes share no memory except through the simulator. With a security layer attached every step is `global` (the engine's taint is by content, across nodes), so nothing is pruned: under `-Dsec` the reduced search runs all 9,216 executions.
- **The bound.** `complete` then means: every execution within the window was run or differs from one that was run only in the order of commuting steps. When `depth_bounded` is also true, the two orders can put different decisions past the bound.
- **Measured** on the vote model to depth 12: 9,216 executions without, 3,073 with (1,549 alternatives pruned), `complete` both times. The buggy election still fails and its token replays. A third body records each run's final decisions: the full and the reduced search reach the same set of outcomes. Two nodes sending to one inbox with equal latency do not commute, and the reduced search still sees both arrival orders.
- **Not done:** finer footprints for streams (every stream operation is `global`). **Snapshots: no-go by measurement.** `zig build bench` runs this model in ReleaseFast: an execution replayed from the start costs 28 µs (9,216 executions in 259 ms; 3,073 in 84 ms with `reduce`). The only snapshot of a running simulation that exists, a forked process, costs 344 µs on Linux (`plan.md` §9 M5), twelve times a replay; an in-process one would have to copy every live fiber stack and the test's own memory. Restore pays only when a prefix costs more than a snapshot, which this search's depth bound keeps from happening.

**State merging (revision 44).** **[Verified]** by `pillar45_test.zig`, with `ExhaustiveOptions.merge = true` (off by default). It is the state table of the design, with the state identified by history and not by a hash the service supplies.

- **Histories.** While a search runs with `merge`, core keeps one hash per node and one per datagram inbox (`Sim.History`). A node's hash folds, in order, what its tasks did (each traced event that stays inside the node), which of them was switched to, and every keyed draw they made with its value; the scheduler's own draws are left out, since what they chose shows as the tasks that ran. An inbox's hash folds each bind, send, receive and close with the hash of the node that did it. Any other event (streams, spawns, crashes, link changes, futexes, clock steps, time advancing) is folded together with all node and inbox hashes at the moment it happens, so nothing is reordered across it. Socket slots and handles are left out of the events: they depend on which node bound first.
- **Why it identifies the state.** A task's behaviour is a function of what it observes: its draws, its node's files and memory, what it receives, and the clock. Two executions with the same histories ran the same events per node and per inbox, only interleaved differently, so they are in the same state. This needs the assumption of `reduce`: tasks on different nodes share no memory except through the simulator.
- **The table.** Before each scheduling choice the search takes the state: all histories, the virtual time and the run queue. After a run, for each such state past the forced decisions, it looks the state up with the number of branchable decisions made so far. If another execution reached it with as few or fewer, this one creates no children from there on (`ExhaustiveResult.merged`); otherwise the state is recorded as reached with this count. A state reached with more of the window left covers one reached with less.
- **What it adds to `reduce`.** `reduce` sees two adjacent steps; merging sees any two executions that differ only in order. With a security layer attached, or a pending targeted fault, no state is taken.
- **Measured** on the vote model to depth 12: 3,073 executions with `merge` alone (769 merges), the same as with `reduce`; with both, `reduce` leaves nothing to merge. The buggy election still fails and replays; the full, merging and merging-and-reducing searches reach the same set of outcomes; two sends to one inbox are still seen in both orders. Folding socket slots into the events left 6,144 executions, which is how the slot dependence was found.

### 7.3 Goguen–Meseguer non-interference (`assertNonInterference`, CC EAL7)

Inputs are labeled LOW (public) and HIGH (secret). The program is non-interfering if, for every LOW input and any two HIGH inputs, the LOW observations are identical. LOW observations are bytes on public sockets, public files, error codes, and the normalized timing and branch traces of §6.3. The check runs dual executions with `(public, high_A)` and `(public, high_B)` over many seeds and fault schedules. **[Verified]** at the I/O-trace level, as with constant time. The full version adds the §6.3 tracer and the shadow-based labels: HIGH bytes are `secret_key` or a tenant other than the observer's.

### 7.4 Instruction-skip glitch resistance (`instruction_skip_glitch_ppm`, FIPS 140-3 L4 / CC AVA_VAN.5)

Physical fault attacks (voltage or clock glitches, laser) commonly skip one instruction, which in practice inverts one comparison. With `instruction_skip_glitch_ppm > 0`, `tardis_sec` inverts single comparisons, but only at security-critical sites:

- `tardis_sec.criticalCheck(env, cond)` (**[Verified]**: an inversion is a keyed decision on core's fault stream, so it replays and shrinks);
- `tardis_sec.criticalEql(T, a, b)`, which is `std.crypto.timing_safe.eql` as a glitch site and needs no `env` (**[Verified]** since revision 35 by `cshim_test.zig`; a call to `timing_safe.eql` itself is not intercepted);
- `TARDIS_SEC_CRITICAL(cond)` in C compiled with the shim header (**[Verified]** since revision 35). **Deviation from the design:** the design named comparisons seen by `trace-cmp`, but a SanitizerCoverage callback observes a comparison and cannot change its result, so C marks the check instead, as Zig does.

The exit test of revision 35 verifies a forged 16-byte tag, in C and in Zig: with one check and a glitch one run in five, some run in 200 accepts the forgery; with the check made twice, 200 runs at 1,000 ppm reject it; without glitches the single check rejects.

Restricting injection to these sites avoids meaningless crashes from glitched loop counters. The oracle checks fail-closed behaviour: a glitched signature or MAC check must not accept a forgery, and a detected inconsistency must zeroize keys. Example 1 (§8.4) accepts a forgery only if *both* of two redundant checks are glitched in the same run, and 200 iterations at 1,000 ppm pass. A single unprotected check would be bypassed in about 1 run in 1,000.

### 7.5 Signed evidence bundles (`requirement`, `.tardis-evidence`)

`tardis_sec.requirement("SFR-FDP_ACC.1").check(ok)` binds each assertion to a Security Functional Requirement, and the registry (§2.4) accumulates results. At campaign end the emitter writes:

```
zig-out/tardis-evidence/<campaign-id>/
  manifest.json            tool versions, Zig version, campaign seed, personas, options, git revisions
  rtm.csv                  bidirectional requirements traceability matrix (requirement ⇄ tests ⇄ results)
  mcdc.json                per-decision MC/DC pairs and gaps; dead-code list
  findings.sarif           SARIF v2.1.0 (one result per finding, CWE rule ids)
  sinks.json               taint sink audit log: checks and hits per sink (revision 31)
  determinism.txt          golden trace hashes per build mode and host (DetSan)
  capsules/*.tardis-replay one replay token per finding and per requirement-binding test
  merkle.txt               the Merkle tree over SHA-256 of every file above
  signature.ed25519        Ed25519 signature of the Merkle root
```

The Merkle root is computed iteratively over SHA-256 leaves (pairs hashed, an odd leaf promoted), and the root is signed with the project's Ed25519 key. **[Verified]**: `merkleRoot`, `signEvidence`, and the test verifies the signature. **[Verified]**: `writeSarif` emits valid SARIF v2.1.0 results with `CWE-n` rule ids. An evaluation lab can re-run every capsule with `TARDIS_REPLAY` and check that the result and determinism hashes match.

In `.certification_eal7` mode `stop_on_first_failure` is forced to `false` (**[Verified]**: `SecurityConfig.effective`), so a failing requirement does not truncate the coverage and traceability evidence of the rest of the campaign.

**What runs today (revision 5).** **[Verified]** by `src/sec/evidence.zig`, `src/sec/tests/example2.zig` and the `tardis` program's tests.

- **Never stopping early: `Options.keep_going` in core.**
  - A failing run is reported, shrunk and logged in a `FailureLog`: iteration, persona, seed, error, and the shrunk replay token.
  - The campaign then continues to its last iteration, and `check` returns the first failure's error.
  - It keeps 32 entries; later failures are counted, not shrunk.
  - On several workers, and through the fork server (one process or several), workers and children only note which runs failed, keeping the lowest 32 by (iteration, persona). The main thread then re-runs, reports, shrinks and logs those in order, exactly as a one-thread campaign would, so the log, its tokens and its overflow count are the same for any number of workers (`shrink_test.zig`, `fork_test.zig`). Guided exploration on several workers still stops at the first failure.
  - `certify` honours `workers`. It uses the fork server too, since revision 10.
    - **The hand-off.** After each forked run the engine packs its tallies into the child's result message: the requirement checks (by requirement id, since the parent's row numbers can differ), the findings, and the MC/DC entries reached so far. The parent commits the bytes of each counted run (not the determinism re-run's) as if the run had happened in-process.
    - **Worker processes (revision 12).** With `fork` and `workers > 1`, each worker process keeps its children's packed tallies (`SecRelay`) instead of importing them: importing would commit them to the worker's copy of the campaign, which dies with it. It sends them to the main process after its catalog, and the main process imports each one.
    - **The test.** On Linux, Example 2's failing campaign with a warm start writes the same bundle, with the same Merkle root, in one process, through one fork server, and through 4 worker processes.
    - **Limits.** MC/DC vectors cross the same path, but no forked test checks them yet. The campaign keeps nothing that depends on commit order. A requirement's first failure and a finding's first run are the lowest (iteration, persona) seen (`Sim.iteration`, `campaign.runOrder`). At the end, `Campaign.canonicalize` sorts findings by first run and puts rows created during the campaign, after the declared ones, in id order. Example 2's failing campaign on 4 workers writes a bundle with the same Merkle root as on one.
- **`tardis_sec.certify(gpa, io, body, config, options)`** is the campaign-end emitter. The test calls it; it is not registered with core.
  - It runs `check` with a `Campaign` collector attached. The collector holds the requirement table and the campaign's distinct findings, each with the seed of the first run that showed it and its count.
  - In certification mode (`config.mode`, or `TARDIS_CERT_EAL7` set in tests) it also records 8 golden trace hashes from runs outside the campaign's counts.
  - It then writes the bundle to `<out>/zig-out/tardis-evidence/<id>/`, where the id is a hash of the name, seed, iteration count and mode. `TARDIS_EVIDENCE_DIR` (tests) overrides the location.
  - In audit mode it only counts and persists.
- **The bundle, as built:**
  - `manifest.json`: tool and Zig versions, build mode, host, campaign identity, outcome counts, and the revision of each repository named in `CertifyOptions.repositories`.
    - **Reading the revision.** `evidence.readRevision` reads `.git` directly, so `certify` spawns no process. It handles `.git` as a directory or as a `gitdir:` file (worktrees, submodules) and HEAD naming a branch. The branch's commit comes from a loose ref or from `packed-refs`, in the git directory or its `commondir`. A detached HEAD is read as the commit itself. SHA-1 and SHA-256 object names are both accepted.
    - **When it cannot resolve HEAD** (not a checkout, an unknown layout), the manifest records `null` rather than guessing.
    - **Uncommitted changes (revision 13).** `modified_files` counts tracked files whose working copy differs from `.git/index`, the check `git diff --quiet` makes. It is read the way `git` reads it:
      - an index entry whose size and modification time match its file is unchanged;
      - any other entry is hashed as a blob and compared, first as it is, then with CRLF line endings turned into LF (`core.autocrlf` checkouts on Windows);
      - a missing file is modified;
      - symlinks, submodules, skip-worktree and unmerged entries are not compared.
      Index versions 2 and 3 are read. Version 4, SHA-256 repositories and a missing index give `null` ("unknown", never "clean").
    - **Staged changes (revision 15).** `staged_files` counts the paths whose index entry differs from the checked-out commit's tree, the check `git diff --cached --quiet` makes: an edit, an addition, a deletion, a mode change, or an unresolved conflict (one per path). Intent-to-add entries do not count. `src/sec/git.zig` reads the commit and its trees from the object store: loose objects, and version-2 pack indexes with their packs, including offset and reference deltas. In a worktree the store is the main repository's (`commondir`). An object it cannot find (an alternate store, a partial clone), a sparse index or an unsupported format gives `null`.
    - **What it does not see:** untracked files.
    - **Checked against `git` (revision 15)** on scratch repositories built with `git` 2.55 and packed by `git gc --aggressive` (43 blob and 10 tree deltas): the same counts as `git diff --cached` and `git diff` when clean, with three staged paths, with loose objects over the pack, in a linked worktree, and in a merge conflict; and on the `termancy` checkout. Unit tests build a pack with both delta kinds, and a tree with edits, additions, deletions and a conflict.
    - **Checked against `git`:** on the sibling `termancy` checkout (`core.autocrlf=true`), it reads the same commit and branch as `git rev-parse`, and 0 modified files as `git diff`. A unit test covers modified, deleted, CRLF and untracked files.
    - **Tests.** A unit test covers each layout. Example 2 records this repository and a fixture checkout, and the CI workflow checks that the recorded `tardis` commit is `GITHUB_SHA`.
  - `rtm.csv`: requirement, status (`PASS`/`FAIL`/`GAP`), bound test, counts, tests digest, the first failure's seed and replay token, and the requirement's MC/DC decisions covered and declared (§7.1).
  - `mcdc.json`: per decision, the independence pair of each condition and the gaps; with `CertifyOptions.decisions`, each decision's name and requirement, the declared decisions never reached (dead or deactivated), and reached decisions missing from the declarations (§7.1).
  - `findings.sarif`: SARIF v2.1.0. There is one result per distinct finding (rule `CWE-n`, with help links), per failed requirement (`tardis/requirement`), and per logged failure no finding explains (`tardis/failure`).
    - Each result has its seed, replay token and a stable `partialFingerprints` entry, and a location when the test passes `@src()`.
  - `sinks.json` (revision 31): per taint sink, the checks counted runs made, the hits, and each distinct hit with its first seed and replay token (§5.2).
  - `determinism.txt`: build mode, host, persona, seed and trace hash.
  - `capsules/NNNN.tardis-replay`: token and expected error for each logged failure. Requirement-binding tests that passed have no capsule; the determinism hashes stand for them.
  - `merkle.txt` and `signature.ed25519`. A leaf binds the path to the content: SHA-256 of a domain tag, the path, and the content's SHA-256. A renamed or swapped file therefore changes the root.
- **Verification.**
  - `verifyEvidence` re-hashes every listed file and rejects any file the list does not cover. It recomputes the root and checks the signature, against the project's public key when one is given (authenticity), else against the embedded key (integrity only).
  - `replayEvidence` also re-runs every capsule, which must fail with its recorded error, and recomputes the determinism hashes of rows from the same build mode and host.
  - `tardis replay-evidence <dir> [--key <hex>]` is the independent check from the command line: hashes, completeness, root and signature, with the capsules listed for `tardis replay`.
  - The tests cover a changed file, an extra capsule, a wrong key and a missing signature; each is rejected.
- **In CI.** `zig build evidence` runs the certification campaigns with `TARDIS_CERT_EAL7=1` and keeps the bundles in `zig-out/tardis-evidence`. `.github/workflows/evidence.yml` runs it on Linux, verifies each bundle with `tardis replay-evidence`, uploads the bundles as an artifact, and uploads their SARIF to code scanning.
  - It runs the campaigns meant to pass. The planted-bug campaigns would raise alerts on purpose.
  - Not yet run on GitHub: the repository has no remote here.

### 7.6 Tool qualification notes (DO-330 TQL-5, CC ALC_TAT)

`tardis_sec` is a verification tool: it can fail to detect an error, but it cannot insert one into the product. Under DO-178C §12.2 that is criterion 3, which is TQL-5 at every software level. These notes are the data a project would start from; qualification itself is the project's, per use.

- **Tool Operational Requirements (TOR).** What the project relies on, each tied to a test that checks it:
  - **Replay.** A replay token reproduces its run bit for bit: core's determinism tests, and Example 2's `replayEvidence`.
  - **Counting.** Requirement checks are counted once per campaign run: Example 2's exact counts (120, 240).
  - **The oracles find their planted defects:** the Pillar I–V exit tests (§8.7).
  - **The bundle detects any change:** `evidence.zig`'s tamper tests.
- **Verification of the TOR.**
  - The suite passes in all four build modes on Windows, and cross-compiled on Linux.
  - Golden trace hashes are recorded in every bundle and recomputed by `replayEvidence`.
- **Known limits that bound the tool's credit.** Each is stated where the feature is specified:
  - MC/DC is unique-cause and per explicit wrapper (§7.1);
  - exhaustive exploration replays every execution from the start, and its reduction and state merging treat every stream operation as touching all nodes (§7.2);
  - content tracking misses leaks shorter than 8 bytes (§3.7);
  - there are no edge counters (§6.3).
- **Configuration identification.** `manifest.json` records the tool version, Zig version, build mode and host of each campaign. The project pins the tool's revision in `build.zig.zon`.
- **CC ALC_TAT.** The implementation language and toolchain are Zig 0.17.0, as a pinned, versioned release. Build options are recorded in the manifest. The tool's own source is under the project's configuration management with the rest of the evaluated TOE's development tools.

The certification credit is never the tool's to claim: an evaluation lab or certification authority decides it (Appendix A).

---

## 8. Modular Repository Layout (`tardis-sec/`), Zig SDK (`src/root.zig`), Diagnostics & Roadmap

### 8.1 Repository layout

```
tardis-sec/
  build.zig                 addSecuritySimTests, evidence step, TARDIS_SEC / TARDIS_CERT_EAL7
  build.zig.zon             depends on tardis
  src/
    root.zig                public API (§8.3)
    shadow.zig egress.zig quarantine.zig           Pillar I
    dfetch.zig lockdep.zig toctou.zig              Pillar II
    byzantine.zig taint.zig sandbox.zig diff.zig   Pillar III
    amplify.zig ct.zig spectre.zig                 Pillar IV
    mcdc.zig dpor.zig ni.zig glitch.zig            Pillar V
    evidence.zig sarif.zig registry.zig            artifacts
  test/
    shadow_test.zig byzantine_test.zig ct_test.zig lockdep_test.zig evidence_test.zig
    examples/aead_tenant.zig examples/raft_cert.zig
  docs/
    cert-matrix.md tool-qualification.md
```

**Today (revision 15)** the package lives in this repository:

```
src/sec/
  root.zig                  the SDK (§8.3)
  engine.zig                the content engine behind core's seam (§3.7)
  races.zig                 lock order, double fetch, check-to-use pairs, the two-faced node (§4.4)
  amplify.zig mcdc.zig      amplification ledger (§6.1), MC/DC tables (§7.1)
  registry.zig              the requirement registry and its persistence (§2.4)
  campaign.zig              a certification campaign's collector (§7.5)
  evidence.zig              the bundle: writing, verifying, replaying (§7.5)
  git.zig                   the index and object store, read without `git` (§7.5)
  edges.zig                 dead edges from `-ffuzz` counters (§7.1)
  tests/pillar1_test.zig    Pillar I exit tests through the seam
  tests/pillar2_test.zig    Pillars II–III exit tests through the seam
  tests/pillar45_test.zig   Pillars IV–V exit tests
  tests/example1.zig        Example 1 (§8.4)
  tests/example2.zig        Example 2 (§8.5)
  tests/refall_test.zig     forces analysis of every declaration
  tests/edge_runner.zig     the test runner for edge-instrumented builds (§7.1)
src/sim/sec_seam.zig        core's side of the seam (§2.2)
src/cmd/tardis/main.zig     `tardis replay-evidence`
.github/workflows/evidence.yml
```

`build.zig` adds the module `tardis_sec` (importing `tardis`) and the step `test-sec`, which `zig build test` includes. The split into the files above is the target as the pillars grow.

### 8.2 Build wiring

```zig
// build.zig.zon
.dependencies = .{
    .tardis = .{ .url = "git+https://<host>/tardis#<pinned-revision>", .hash = "<hash>" },
},
```

```zig
// build.zig (excerpt)
const tardis_dep = b.dependency("tardis", .{ .target = target, .optimize = optimize });
const sec = b.addModule("tardis_sec", .{
    .root_source_file = b.path("src/root.zig"),
    .target = target,
    .optimize = optimize,
    .imports = &.{.{ .name = "tardis", .module = tardis_dep.module("tardis") }},
});

/// For projects: their simulation tests, built with `SecurityHooks` selected.
pub fn addSecuritySimTests(b: *std.Build, tests: *std.Build.Step.Compile, sec_mod: *std.Build.Module) void {
    tests.root_module.addImport("tardis_sec", sec_mod);
    const opts = b.addOptions();
    opts.addOption(bool, "tardis_sec", true);
    tests.root_module.addOptions("tardis_build", opts);
}
```

Environment overrides:

| Variable | Effect |
|---|---|
| `TARDIS_SARIF_DIR=<dir>` | with `tardis_sec` attached (`withSecurity`, or `TARDIS_SEC=1`), each failed `check` writes a SARIF file there, located at the test's call. **[Verified]** |
| `TARDIS_SEC=1 zig build test` (or `-Dsec`) | `.audit` mode for every `check` in the build whose options name no security layer. **[Verified]**: core imports `tardis_sec_default`, which `build.zig` points at a stub (`src/sim/sec_default.zig`, an untyped `null`, so no security code is compiled) or, with the switch, at `tardis_sec`, whose `default_security` attaches the content engine observing only (no symlink swaps, forced switches or Byzantine rewrites, which steer runs). `tardis.security_by_default` says which. The whole suite passes with it on |
| `TARDIS_CERT_EAL7=1 zig build test` | `.certification_eal7` for every `certify` campaign: never stops early, collects MC/DC and traceability, emits the bundle. **[Verified]** |
| `TARDIS_EVIDENCE_DIR=<dir>` | where `certify` writes bundles, relative to the current directory. **[Verified]** |
| `zig build evidence` | the certification campaigns with both of the above, bundles kept in `zig-out/tardis-evidence`. **[Verified]** |
| `TARDIS_REPLAY=<token>` | as in core: replays one shrunk run, now including its security finding |

### 8.3 The SDK (`src/root.zig`)

This is `src/sec/root.zig`, as compiled and tested with Zig 0.17.0 against the current core `tardis`. Its 12 tests follow the code in the repository; they are omitted here for length. The registry, campaign collector and bundle it re-exports are `registry.zig`, `campaign.zig` and `evidence.zig` (§2.4, §7.5). The content engine it re-exports is `src/sec/engine.zig` (§3.7). Items that need a core seam say so in their doc comments and behave honestly without it: they no-op. `verifyExhaustive` runs core's stateless exhaustive exploration (§7.2).

```zig
//! tardis_sec: Layer 7 of TARDIS. Security auditing, Byzantine fuzzing,
//! side-channel oracles and assurance evidence, as a separate package that
//! plugs into core `tardis` through four seams (plan2.md §2).
//!
//! Two layers live here. `engine.zig` is the live engine behind core's
//! run-time seam (`tardis.sec_seam`): it sees every allocation, free and
//! byte crossing an `std.Io` boundary, and tracks secrets, tenants and
//! uninitialized or freed heap bytes by content (`withSecurity` attaches
//! it). The `ShadowCell`/`WorkerSec`/`SecurityHooks` types below are the
//! per-word shadow model for paths that see individual loads and stores
//! (instrumented C, `load`/`store` wrappers); they are verified as types and
//! state machines, and wait for those paths.
//!
//! TigerStyle: no allocation after `WorkerSec.init`, an explicit bound on
//! every table, no recursion, units in names, comptime layout proofs.

const std = @import("std");
const tardis = @import("tardis");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

pub const engine = @import("engine.zig");
pub const Engine = engine.Engine;
pub const ContentFinding = engine.Finding;
pub const traceability = @import("registry.zig");
pub const Campaign = engine.campaign.Campaign;
pub const evidence = @import("evidence.zig");

// ===========================================================================
// §3 ByteState and the 16-byte ShadowCell

/// What one application byte is, 4 bits per byte. 0xC..0xF are reserved.
pub const ByteState = enum(u4) {
    valid_clean = 0x0,
    uninit_heap = 0x1,
    uninit_stack = 0x2,
    redzone_left = 0x3,
    redzone_right = 0x4,
    freed_quarantine = 0x5,
    stack_guard = 0x6,
    secret_key = 0x7,
    tenant_isolated = 0x8,
    untrusted_input = 0x9,
    double_fetch_armed = 0xA,
    secret_zeroed = 0xB,
    _,

    pub fn bit(s: ByteState) u16 {
        return @as(u16, 1) << @backingInt(s);
    }

    /// States that make a load or store invalid (CWE id per state).
    pub const access_fault: u16 = bit(.redzone_left) | bit(.redzone_right) |
        bit(.freed_quarantine) | bit(.stack_guard);
    /// States that must never leave the process (egress scan).
    pub const egress_fault: u16 = bit(.uninit_heap) | bit(.uninit_stack) |
        bit(.freed_quarantine) | bit(.secret_key) | bit(.redzone_left) |
        bit(.redzone_right) | bit(.stack_guard);

    pub fn cwe(s: ByteState) u16 {
        return switch (s) {
            .uninit_heap, .uninit_stack => 908,
            .redzone_left => 124,
            .redzone_right => 125,
            .freed_quarantine => 416,
            .stack_guard => 121,
            .secret_key => 200,
            .tenant_isolated => 125,
            .untrusted_input => 20,
            .double_fetch_armed => 367,
            else => 0,
        };
    }
};

/// Tenant ids: 0 is the system, 255 marks bytes mixed from two tenants.
pub const TenantId = u8;
pub const tenant_system: TenantId = 0;
pub const tenant_poison: TenantId = 255;

/// Low word: one comparison against the fiber's epoch proves "same fiber,
/// every byte clean" (`per_byte_nibble == 0`).
pub const FastWord = packed struct(u64) {
    /// `(fiber_id << 16) | local_epoch`.
    last_scalar: u32,
    /// Byte i of the 8-byte word is nibble i (bits 4i..4i+3).
    per_byte_nibble: u32,
};

/// High word: concurrency and provenance; orthogonal to the nibbles.
pub const MetaWord = packed struct(u64) {
    vclock_epoch: u47,
    has_concurrent_writer: u1,
    alloc_gen: u8,
    taint_tenant_id: TenantId,
};

/// Shadow of one aligned 8-byte application word.
pub const ShadowCell = extern struct {
    fast_word: u64 = 0,
    meta_word: u64 = 0,

    pub inline fn fast(c: ShadowCell) FastWord {
        return @bitCast(c.fast_word);
    }

    pub inline fn meta(c: ShadowCell) MetaWord {
        return @bitCast(c.meta_word);
    }

    pub inline fn setMeta(c: *ShadowCell, m: MetaWord) void {
        c.meta_word = @bitCast(m);
    }

    pub inline fn nibble(c: ShadowCell, byte_index: u3) ByteState {
        return @fromBackingInt(@intCast(@as(u4, @truncate(c.fast().per_byte_nibble >> (@as(u5, byte_index) * 4)))));
    }

    pub inline fn setNibble(c: *ShadowCell, byte_index: u3, s: ByteState) void {
        var f = c.fast();
        const shift: u5 = @as(u5, byte_index) * 4;
        f.per_byte_nibble = (f.per_byte_nibble & ~(@as(u32, 0xF) << shift)) | (@as(u32, @backingInt(s)) << shift);
        c.fast_word = @bitCast(f);
    }

    /// The hot path: same fiber epoch and every byte clean, in one compare.
    pub inline fn isFastClean(c: ShadowCell, epoch_scalar: u32) bool {
        return c.fast_word == @as(u64, epoch_scalar);
    }
};

comptime {
    assert(@sizeOf(ShadowCell) == 16);
    assert(@offsetOf(ShadowCell, "fast_word") == 0);
    assert(@offsetOf(ShadowCell, "meta_word") == 8);
    assert(@bitSizeOf(FastWord) == 64 and @bitSizeOf(MetaWord) == 64);
    assert(@bitOffsetOf(MetaWord, "taint_tenant_id") == 120 - 64);
    assert(@bitOffsetOf(MetaWord, "alloc_gen") == 112 - 64);
    assert(@typeInfo(ByteState).@"enum".tag_type == u4);
}

// --- Address mapping (Chrono-Slab: 64 workers x 1 GiB, strided) ----------

pub const workers_max = 64;
pub const worker_arena_bytes: u64 = 1 << 30;
pub const arena_window_base: u64 = 0x4000_0000_0000; // 2^46, aligned to 2^38
pub const shadow_base: u64 = 0x7100_0000_0000;
pub const arena_mask: u64 = 0x3F_FFFF_FFF8;

pub inline fn workerBase(w: u6) u64 {
    return arena_window_base + (@as(u64, w) << 30);
}

pub inline fn workerShadowBase(w: u6) u64 {
    return shadow_base + (@as(u64, w) << 31);
}

/// One instruction after the mask: application address to its ShadowCell.
pub inline fn shadowAddress(virt: u64) u64 {
    return ((virt & arena_mask) << 1) + shadow_base;
}

comptime {
    assert(arena_window_base % (1 << 38) == 0);
    for (0..workers_max) |w| {
        assert(shadowAddress(workerBase(w)) == workerShadowBase(w));
        assert(shadowAddress(workerBase(w) + worker_arena_bytes - 8) ==
            workerShadowBase(w) + 2 * worker_arena_bytes - 16);
    }
}

/// The nibbles of an access of `len_bytes` (1..8) at byte `offset` of a
/// word, possibly straddling into the next word's cell. Branch-free.
pub inline fn spanNibbles(c0: ShadowCell, c1: ShadowCell, offset: u3, len_bytes: u4) u64 {
    assert(len_bytes >= 1 and len_bytes <= 8);
    const both = (@as(u64, c1.fast().per_byte_nibble) << 32) | c0.fast().per_byte_nibble;
    const shifted = both >> (@as(u6, offset) * 4);
    const mask = (@as(u64, 1) << (@as(u6, len_bytes) * 4)) - 1;
    return shifted & mask;
}

/// Bit set of the ByteStates present in up to 16 nibbles.
pub inline fn statesIn(nibbles: u64) u16 {
    var set: u16 = 0;
    inline for (0..16) |k| set |= @as(u16, 1) << @as(u4, @truncate(nibbles >> (k * 4)));
    return set;
}

pub const EgressVerdict = struct {
    /// ByteStates seen in the 64 bytes (bit per state).
    states: u16,
    /// The first offending state, or null.
    fault: ?ByteState,
    /// True if a byte belongs to a tenant other than the destination's.
    cross_tenant: bool,
};

/// Scans 64 payload bytes (8 cells) at once: uninit/UAF bleed (CWE-908),
/// secret exfiltration (CWE-200), cross-tenant bleed (CWE-125).
pub fn egressScan(nibbles: @Vector(8, u32), tenants: @Vector(8, u8), dest_tenant: TenantId) EgressVerdict {
    var seen: @Vector(8, u16) = @splat(0);
    inline for (0..8) |k| {
        const n: @Vector(8, u32) = (nibbles >> @splat(@as(u5, k * 4))) & @as(@Vector(8, u32), @splat(0xF));
        seen |= @as(@Vector(8, u16), @splat(1)) << @as(@Vector(8, u4), @truncate(n));
    }
    const states = @reduce(.Or, seen);
    const bad = states & ByteState.egress_fault;
    const foreign = (tenants != @as(@Vector(8, u8), @splat(dest_tenant))) &
        (tenants != @as(@Vector(8, u8), @splat(tenant_system)));
    return .{
        .states = states,
        .fault = if (bad == 0) null else @fromBackingInt(@intCast(@as(u4, @intCast(@ctz(bad))))),
        .cross_tenant = @reduce(.Or, foreign),
    };
}

/// Free-time poison: deterministic per run, so reports replay.
pub inline fn poisonWord(causal_seed: u64) u64 {
    return 0xDEADBEEF_CAFEBABE ^ causal_seed;
}

// ===========================================================================
// §2 Region C budget (per worker, exact, comptime-checked)

pub const nodes_max = 32;
pub const region_c_bytes_max: u64 = 512 * 1024 * 1024;
pub const core_region_c_bytes: u64 = 352 * 1024 * 1024;
pub const SEC_REGION_C_BYTES: u64 = 64 * 1024 * 1024;
pub const region_c_spare_bytes: u64 = 96 * 1024 * 1024;

pub const Budget = struct {
    pub const quarantine_ring: u64 = nodes_max * 4096 * 16;
    pub const lockdep_graph: u64 = nodes_max * (512 * 64 + 512 * 32);
    pub const local_cmp_token_ring: u64 = 65_536 * 32;
    pub const local_mcdc_table: u64 = 16_384 * 64;
    pub const byzantine_replay_pool: u64 = 2048 * 16 * 1024;
    pub const cost_amplification_ledger: u64 = nodes_max * 2048 * 64;
    pub const taint_sink_audit_log: u64 = 65_536 * 64;
    pub const dpor_state_table: u64 = 65_536 * 64;
    pub const sec_reserved_headroom: u64 = 13 * 1024 * 1024 + 512 * 1024;

    pub const total: u64 = quarantine_ring + lockdep_graph + local_cmp_token_ring +
        local_mcdc_table + byzantine_replay_pool + cost_amplification_ledger +
        taint_sink_audit_log + dpor_state_table + sec_reserved_headroom;
};

comptime {
    const MiB = 1024 * 1024;
    assert(Budget.quarantine_ring == 2 * MiB);
    assert(Budget.lockdep_graph == 3 * MiB / 2);
    assert(Budget.local_cmp_token_ring == 2 * MiB);
    assert(Budget.local_mcdc_table == 1 * MiB);
    assert(Budget.byzantine_replay_pool == 32 * MiB);
    assert(Budget.cost_amplification_ledger == 4 * MiB);
    assert(Budget.taint_sink_audit_log == 4 * MiB);
    assert(Budget.dpor_state_table == 4 * MiB);
    assert(Budget.total == SEC_REGION_C_BYTES);
    assert(core_region_c_bytes + SEC_REGION_C_BYTES + region_c_spare_bytes == region_c_bytes_max);
}

pub const requirements_max = traceability.requirements_max;

/// One row of the Requirement Traceability Registry (128 bytes, §2.4).
pub const RequirementRecord = traceability.Record;

comptime {
    assert(@sizeOf(RequirementRecord) == 128);
    assert(requirements_max * @sizeOf(RequirementRecord) == 512 * 1024);
}

// ===========================================================================
// §2 Seam 3: the SecurityHooks contract

/// Every hook core `tardis` calls. Core uses `NoopSecurityHooks` unless
/// `tardis_sec` is imported, and every call then compiles to nothing.
pub const hook_names = [_][]const u8{
    "onAlloc", "onFree",        "onNetRead",   "onNetWrite",
    "onVfsOp", "onLockAcquire", "onBranchCmp", "onCausalStep",
    "onWrite", "onLockRelease",
};

pub const VfsOp = enum(u8) { stat, access, open, create, rename, delete, link, symlink, write, read };
pub const CmpSite = struct { pc: u64, lhs: u64, rhs: u64, width_bytes: u8, critical: bool };

pub const NoopSecurityHooks = struct {
    pub const enabled = false;
    pub inline fn onAlloc(_: *anyopaque, _: u64, _: u32) void {}
    pub inline fn onFree(_: *anyopaque, _: u64, _: u32) void {}
    pub inline fn onWrite(_: *anyopaque, _: u64, _: []const u8) void {}
    pub inline fn onNetRead(_: *anyopaque, _: u64, _: []const u8) void {}
    pub inline fn onNetWrite(_: *anyopaque, _: u64, _: []const u8, _: TenantId) bool {
        return true;
    }
    pub inline fn onVfsOp(_: *anyopaque, _: VfsOp, _: []const u8) void {}
    pub inline fn onLockAcquire(_: *anyopaque, _: u16) void {}
    pub inline fn onLockRelease(_: *anyopaque, _: u16) void {}
    pub inline fn onBranchCmp(_: *anyopaque, _: CmpSite) bool {
        return true;
    }
    pub inline fn onCausalStep(_: *anyopaque, _: u64) void {}
};

/// Comptime proof that `H` implements the whole contract.
pub fn assertHooks(comptime H: type) void {
    comptime {
        if (!@hasDecl(H, "enabled")) @compileError(@typeName(H) ++ " lacks `enabled`");
        for (hook_names) |name| {
            if (!@hasDecl(H, name)) @compileError(@typeName(H) ++ " lacks hook " ++ name);
        }
    }
}

comptime {
    assertHooks(NoopSecurityHooks);
    assertHooks(SecurityHooks);
}

// ===========================================================================
// Per-worker state (lives in the Region C carve-out)

pub const Finding = struct {
    cwe: u16,
    state: ByteState,
    addr: u64,
    tenant: TenantId,
    requirement: u16, // index into the registry, 0xFFFF: none
};

pub const findings_max = 256;
pub const lock_classes_max = 512;

/// Lock-order bitmatrix: `order[a]` bit b means "a held while taking b"
/// (transitively closed on insert). O(1) inversion test per held lock.
pub const LockdepGraph = struct {
    order: [lock_classes_max][lock_classes_max / 64]u64 = @splat(@splat(0)),
    held: [16]u16 = undefined,
    held_len: u8 = 0,

    pub fn acquire(g: *LockdepGraph, class: u16) ?u16 {
        assert(class < lock_classes_max);
        var inversion: ?u16 = null;
        for (g.held[0..g.held_len]) |a| {
            if (a == class) continue;
            // Taking `class` while holding `a`: inverted if class -> a was seen.
            if (bitSet(g.order[class], a)) inversion = a;
            g.addEdge(a, class);
        }
        assert(g.held_len < g.held.len);
        g.held[g.held_len] = class;
        g.held_len += 1;
        return inversion;
    }

    pub fn release(g: *LockdepGraph, class: u16) void {
        for (g.held[0..g.held_len], 0..) |h, i| {
            if (h != class) continue;
            g.held[i] = g.held[g.held_len - 1];
            g.held_len -= 1;
            return;
        }
    }

    /// Hold-across-yield: any lock held at an `std.Io` yield point.
    pub fn heldAtYield(g: *const LockdepGraph) bool {
        return g.held_len != 0;
    }

    fn addEdge(g: *LockdepGraph, a: u16, b: u16) void {
        if (bitSet(g.order[a], b)) return;
        // a -> b and everything b precedes; and so for every x preceding a.
        var row_b = g.order[b];
        setBit(&row_b, b);
        for (&g.order, 0..) |*row, x| {
            if (x == a or bitSet(row.*, a)) {
                for (row, row_b) |*w, rb| w.* |= rb;
            }
        }
    }

    fn bitSet(row: [lock_classes_max / 64]u64, i: u16) bool {
        return row[i / 64] & (@as(u64, 1) << @as(u6, @truncate(i))) != 0;
    }

    fn setBit(row: *[lock_classes_max / 64]u64, i: u16) void {
        row[i / 64] |= @as(u64, 1) << @as(u6, @truncate(i));
    }
};

/// Shadow and tables for one worker. In the full system `shadow` is the
/// worker's mapped shadow window; here it covers `[base, base + len)`.
pub const WorkerSec = struct {
    base: u64,
    shadow: []ShadowCell,
    epoch_scalar: u32 = 0,
    tenant: TenantId = tenant_system,
    lockdep: LockdepGraph = .{},
    findings: [findings_max]Finding = undefined,
    findings_len: u16 = 0,
    rx_bytes: u64 = 0,
    tx_bytes: u64 = 0,

    pub fn init(base: u64, shadow: []ShadowCell) WorkerSec {
        @memset(shadow, .{});
        return .{ .base = base, .shadow = shadow };
    }

    fn cell(ws: *WorkerSec, addr: u64) *ShadowCell {
        assert(addr >= ws.base);
        const i = (addr - ws.base) / 8;
        assert(i < ws.shadow.len);
        return &ws.shadow[i];
    }

    pub fn setRange(ws: *WorkerSec, addr: u64, len: u64, s: ByteState) void {
        var a = addr;
        while (a < addr + len) : (a += 1) ws.cell(a & ~@as(u64, 7)).setNibble(@truncate(a), s);
    }

    pub fn stateAt(ws: *WorkerSec, addr: u64) ByteState {
        return ws.cell(addr & ~@as(u64, 7)).nibble(@truncate(addr));
    }

    pub fn setTenant(ws: *WorkerSec, addr: u64, len: u64, tenant: TenantId) void {
        var a = addr & ~@as(u64, 7);
        while (a < addr + len) : (a += 8) {
            const c = ws.cell(a);
            var m = c.meta();
            m.taint_tenant_id = tenant;
            c.setMeta(m);
        }
    }

    pub fn report(ws: *WorkerSec, state: ByteState, addr: u64) void {
        if (ws.findings_len == findings_max) return;
        ws.findings[ws.findings_len] = .{
            .cwe = state.cwe(),
            .state = state,
            .addr = addr,
            .tenant = ws.cell(addr & ~@as(u64, 7)).meta().taint_tenant_id,
            .requirement = 0xFFFF,
        };
        ws.findings_len += 1;
    }

    pub fn findingsSlice(ws: *const WorkerSec) []const Finding {
        return ws.findings[0..ws.findings_len];
    }
};

/// The `tardis_sec` implementation of the hook contract. `ctx` is the
/// worker's `WorkerSec`.
pub const SecurityHooks = struct {
    pub const enabled = true;

    inline fn ws(ctx: *anyopaque) *WorkerSec {
        return @ptrCast(@alignCast(ctx));
    }

    pub fn onAlloc(ctx: *anyopaque, addr: u64, len: u32) void {
        const w = ws(ctx);
        w.setRange(addr, len, .uninit_heap);
        w.setTenant(addr, len, w.tenant);
        var a = addr & ~@as(u64, 7);
        while (a < addr + len) : (a += 8) {
            const c = w.cell(a);
            var m = c.meta();
            m.alloc_gen +%= 1;
            c.setMeta(m);
        }
    }

    pub fn onFree(ctx: *anyopaque, addr: u64, len: u32) void {
        const w = ws(ctx);
        var a = addr;
        while (a < addr + len) : (a += 1) {
            if (w.stateAt(a) == .secret_key) {
                w.report(.secret_key, a); // CWE-226 at free: not zeroized
                break;
            }
        }
        w.setRange(addr, len, .freed_quarantine);
    }

    /// Stores: zero bytes scrub secrets (`secureZero`), other bytes become
    /// valid; secrets and taint are kept by `copy`, not by stores.
    pub fn onWrite(ctx: *anyopaque, addr: u64, bytes: []const u8) void {
        const w = ws(ctx);
        for (bytes, 0..) |b, i| {
            const a = addr + i;
            const s = w.stateAt(a);
            if (ByteState.access_fault & s.bit() != 0) {
                w.report(s, a);
                continue;
            }
            const next: ByteState = switch (s) {
                .secret_key => if (b == 0) .secret_zeroed else .secret_key,
                .untrusted_input => .untrusted_input,
                else => .valid_clean,
            };
            w.setRange(a, 1, next);
        }
    }

    /// Ingress: received bytes are untrusted until `markSanitized`.
    pub fn onNetRead(ctx: *anyopaque, addr: u64, bytes: []const u8) void {
        const w = ws(ctx);
        w.rx_bytes += bytes.len;
        w.setRange(addr, bytes.len, .untrusted_input);
    }

    /// Egress: false (and a finding) if the payload must not leave.
    pub fn onNetWrite(ctx: *anyopaque, addr: u64, bytes: []const u8, dest_tenant: TenantId) bool {
        const w = ws(ctx);
        w.tx_bytes += bytes.len;
        var off: u64 = 0;
        while (off < bytes.len) : (off += 64) {
            var nib: @Vector(8, u32) = @splat(0);
            var ten: @Vector(8, u8) = @splat(dest_tenant);
            inline for (0..8) |k| {
                const a = addr + off + k * 8;
                if (a < addr + bytes.len) {
                    const c = w.cell(a & ~@as(u64, 7)).*;
                    nib[k] = c.fast().per_byte_nibble;
                    ten[k] = c.meta().taint_tenant_id;
                }
            }
            const v = egressScan(nib, ten, dest_tenant);
            if (v.fault) |f| {
                w.report(f, addr + off);
                return false;
            }
            if (v.cross_tenant) {
                w.report(.tenant_isolated, addr + off);
                return false;
            }
        }
        return true;
    }

    pub fn onVfsOp(_: *anyopaque, _: VfsOp, _: []const u8) void {}

    pub fn onLockAcquire(ctx: *anyopaque, class: u16) void {
        const w = ws(ctx);
        if (w.lockdep.acquire(class)) |_| {
            if (w.findings_len < findings_max) {
                w.findings[w.findings_len] = .{ .cwe = 833, .state = .valid_clean, .addr = class, .tenant = w.tenant, .requirement = 0xFFFF };
                w.findings_len += 1;
            }
        }
    }

    pub fn onLockRelease(ctx: *anyopaque, class: u16) void {
        ws(ctx).lockdep.release(class);
    }

    /// Returns the branch outcome to take: `cmp` result, or inverted by a
    /// glitch (decided by core's fault stream, so it replays and shrinks).
    pub fn onBranchCmp(_: *anyopaque, site: CmpSite) bool {
        return site.lhs == site.rhs;
    }

    pub fn onCausalStep(ctx: *anyopaque, _: u64) void {
        ws(ctx).epoch_scalar +%= 1;
    }
};

// ===========================================================================
// §5 Byzantine wire mutation with comptime checksum fixup

pub const ChecksumKind = enum { crc32, xxhash64 };

pub const FrameOptions = struct {
    length_field: []const u8,
    checksum_field: []const u8,
    epoch_field: ?[]const u8 = null,
    checksum: ChecksumKind = .crc32,
};

/// Reflects over `HeaderT` once, at comptime: which fields carry the
/// payload length, checksum and epoch, and how to recompute the checksum.
pub fn ByzantineFrameSpec(comptime HeaderT: type, comptime opts: FrameOptions) type {
    comptime {
        if (!@hasField(HeaderT, opts.length_field)) @compileError("no length field " ++ opts.length_field);
        if (!@hasField(HeaderT, opts.checksum_field)) @compileError("no checksum field " ++ opts.checksum_field);
        if (opts.epoch_field) |e| if (!@hasField(HeaderT, e)) @compileError("no epoch field " ++ e);
    }
    const LenT = @FieldType(HeaderT, opts.length_field);
    const SumT = @FieldType(HeaderT, opts.checksum_field);
    comptime {
        if (@bitSizeOf(SumT) < (if (opts.checksum == .crc32) 32 else 64)) @compileError("checksum field too narrow");
    }
    return struct {
        pub const Header = HeaderT;

        pub fn checksumOf(payload: []const u8) SumT {
            return switch (opts.checksum) {
                .crc32 => @intCast(std.hash.Crc32.hash(payload)),
                .xxhash64 => @intCast(std.hash.XxHash64.hash(0, payload)),
            };
        }

        /// Makes `header` valid for `payload` again after a mutation.
        pub fn fixup(header: *HeaderT, payload: []const u8) void {
            @field(header, opts.checksum_field) = checksumOf(payload);
        }

        pub fn isValid(header: HeaderT, payload: []const u8) bool {
            return @field(header, opts.checksum_field) == checksumOf(payload) and
                @field(header, opts.length_field) == payload.len;
        }

        /// Attack 1: the length prefix disagrees with the payload (wraps).
        pub fn desyncLength(header: *HeaderT, delta: i64) void {
            const old: i64 = @intCast(@field(header, opts.length_field));
            @field(header, opts.length_field) = @truncate(@as(u64, @bitCast(old +% delta)));
        }

        /// Attack 2: two-faced equivocation. Writes a second payload that
        /// differs at `index` and fixes both headers, so each half of the
        /// cluster receives a frame that verifies.
        pub fn equivocate(header: HeaderT, payload: []const u8, index: usize, flip: u8, out_header: *HeaderT, out_payload: []u8) void {
            assert(out_payload.len == payload.len and index < payload.len and flip != 0);
            @memcpy(out_payload, payload);
            out_payload[index] ^= flip;
            out_header.* = header;
            @field(out_header, opts.length_field) = @intCast(out_payload.len);
            fixup(out_header, out_payload);
        }

        /// Wire form: the header's bytes, then the payload (`HeaderT`
        /// must be an `extern struct`). Returns the frame length.
        pub fn encode(header: HeaderT, payload: []const u8, out: []u8) usize {
            comptime assert(@typeInfo(HeaderT).@"struct".layout == .@"extern");
            const hb = std.mem.asBytes(&header);
            @memcpy(out[0..hb.len], hb);
            @memcpy(out[hb.len..][0..payload.len], payload);
            return hb.len + payload.len;
        }

        pub const Decoded = struct { header: HeaderT, payload: []const u8 };

        /// Parses a wire frame; null if it is too short for its length field.
        pub fn decode(frame: []const u8) ?Decoded {
            comptime assert(@typeInfo(HeaderT).@"struct".layout == .@"extern");
            if (frame.len < @sizeOf(HeaderT)) return null;
            const h = std.mem.bytesToValue(HeaderT, frame[0..@sizeOf(HeaderT)]);
            const len: usize = @intCast(@field(h, opts.length_field));
            if (frame.len - @sizeOf(HeaderT) < len) return null;
            return .{ .header = h, .payload = frame[@sizeOf(HeaderT)..][0..len] };
        }

        /// `equivocate` on wire frames, for `tardis_sec.twoFaced`: the
        /// payload byte at `index` is flipped by `flip` and the checksum
        /// recomputed. Null (send the original) if the frame does not parse
        /// or is shorter than `index`.
        pub fn equivocateFrame(comptime index: usize, comptime flip: u8) fn ([]const u8, []u8) ?usize {
            return struct {
                fn f(in: []const u8, out: []u8) ?usize {
                    const d = decode(in) orelse return null;
                    if (index >= d.payload.len or in.len > out.len) return null;
                    var h2: HeaderT = undefined;
                    equivocate(d.header, d.payload, index, flip, &h2, out[@sizeOf(HeaderT)..][0..d.payload.len]);
                    @memcpy(out[0..@sizeOf(HeaderT)], std.mem.asBytes(&h2));
                    return @sizeOf(HeaderT) + d.payload.len;
                }
            }.f;
        }

        pub fn epochOf(header: HeaderT) u64 {
            const e = opts.epoch_field orelse return 0;
            return @intCast(@field(header, e));
        }

        comptime {
            _ = LenT;
        }
    };
}

// ===========================================================================
// §6 Amplification limits and the ledger

/// Ratios are in thousandths (milli) so they stay integers. The ledger
/// lives in `amplify.zig`; `SecurityConfig.amplification` turns the checks on.
pub const AmplificationLimits = engine.amplify.Limits;
pub const Amplification = engine.amplify.Ledger;
pub const AmplificationRatio = engine.amplify.Ratio;

/// Counts `n` work units (hash probes, loop steps, comparisons) for the
/// amplification ledger: the numerator of `work_per_input_byte`.
pub fn work(n: u64) void {
    engine.addWork(n);
}

/// Declares `n` bytes of untrusted input that did not arrive over the
/// network (network bytes are counted automatically).
pub fn untrustedInput(n: u64) void {
    engine.addInput(n);
}

// ===========================================================================
// §7.1 MC/DC for Zig code

pub const mcdc = struct {
    pub const Report = engine.mcdc.Report;
    pub const Entry = engine.mcdc.Entry;
    pub const Decl = engine.mcdc.Decl;
    pub const decisions_max = engine.mcdc.decisions_max;

    /// A decision with up to 8 conditions: records the vector and returns
    /// `eval(conds)`, the code's own expression over the conditions.
    ///
    ///     if (mcdc.decision(7, .{ armed, sig_ok, override }, struct {
    ///         fn f(c: anytype) bool { return c[0] and (c[1] or c[2]); }
    ///     }.f)) { ... }
    pub fn decision(comptime id: u8, conds: anytype, comptime eval: anytype) bool {
        const out: bool = eval(conds);
        const n = @typeInfo(@TypeOf(conds)).@"struct".field_names.len;
        engine.mcdcRecord(id, n, engine.mcdc.vectorOf(conds), out);
        return out;
    }
};

// ===========================================================================
// Configuration and the comptime entry point

pub const SecurityMode = enum {
    /// Shadow memory, taint, Byzantine and DoS oracles; stop at the first failure.
    audit,
    /// Everything in `audit`, plus MC/DC, DPOR and evidence; never stops early.
    certification_eal7,
};

pub const paths_max = engine.paths_max;
/// Post-init capability lockdown (`enterSandbox`): `allow_net_connect`
/// (false), `allow_net_listen` (true), `allow_process_spawn` (false),
/// `allow_vfs_write` (true), and up to `paths_max` `vfs_prefixes`.
pub const SandboxPolicy = engine.SandboxPolicy;

pub const SecurityConfig = struct {
    mode: SecurityMode = .audit,
    tenants_max: u8 = 8,
    vfs_toctou_race_ppm: tardis.Ppm = 20_000,
    /// Chance of a forced task switch at the second read of a `Shared`
    /// word by one task (the window a double fetch needs).
    double_fetch_preempt_ppm: tardis.Ppm = 500_000,
    entropy_starvation_ppm: tardis.Ppm = 0,
    instruction_skip_glitch_ppm: tardis.Ppm = 0,
    byzantine_ppm: tardis.Ppm = 50_000,
    /// Amplification checks and steering (§6.1); off unless set, since any
    /// program allocates more than its input in absolute terms.
    amplification: ?AmplificationLimits = null,
    /// Receives the campaign's MC/DC table (§7.1).
    mcdc: ?*mcdc.Report = null,
    /// Receives every counted run's requirement checks and findings
    /// (§7.5); `certify` sets it.
    campaign: ?*Campaign = null,
    /// Forced to false by `.certification_eal7`, so coverage and
    /// traceability evidence is complete even when defects are found.
    stop_on_first_failure: bool = true,
    evidence_dir: []const u8 = "zig-out/tardis-evidence",
    /// Receives the content findings of the last run (see `engine.Report`).
    report: ?*engine.Report = null,
    /// A failed `check` writes `<hash>.sarif` here: its findings, located
    /// at the test's call to `check`, with the replay token (seam 4). Under
    /// `TARDIS_SEC=1`, `TARDIS_SARIF_DIR` does the same for every check.
    check_sarif: ?*const std.Io.Dir = null,
    /// Base campaign options (iterations, personas, nodes, ...).
    base: tardis.Options = .{},

    pub fn effective(c: SecurityConfig) SecurityConfig {
        var out = c;
        if (c.mode == .certification_eal7) out.stop_on_first_failure = false;
        return out;
    }
};

/// The run's security configuration, readable from hooks and helpers.
threadlocal var active_config: SecurityConfig = .{};
threadlocal var active_worker: ?*WorkerSec = null;

/// `tardis.check(gpa, body, tardis_sec.withSecurity(.{ ... }))`: core
/// options with the security layer configured: the content engine
/// (`engine.zig`) is attached through core's run-time seam, one instance
/// per simulator, so every allocation and every byte crossing `std.Io` is
/// checked.
pub fn withSecurity(config: SecurityConfig) tardis.Options {
    const c = config.effective();
    active_config = c;
    var o = c.base;
    if (c.mode == .certification_eal7) o.determinism_check_every = 1;
    o.security = .{ .provider = &engine.provider, .params = paramsOf(c) };
    return o;
}

/// What `TARDIS_SEC=1` attaches to every `check` whose options name no
/// security layer (seam 4, plan2.md §8.2): the content engine in `.audit`
/// mode, observing only. Nothing that steers a run is on (no symlink swaps,
/// no forced switches inside `Shared` reads, no Byzantine rewrites, no
/// amplification limits), so a passing test's trace stays the same and
/// only real findings fail it.
pub const default_config: SecurityConfig = .{
    .vfs_toctou_race_ppm = 0,
    .double_fetch_preempt_ppm = 0,
    .byzantine_ppm = 0,
};
pub const default_security: ?tardis.sec_seam.Security = .{ .provider = &engine.provider, .params = paramsOf(default_config) };

/// The engine's configuration words for `c` (see `engine.Param`).
fn paramsOf(c: SecurityConfig) tardis.sec_seam.Params {
    var params: tardis.sec_seam.Params = @splat(0);
    params[@backingInt(engine.Param.glitch_ppm)] = c.instruction_skip_glitch_ppm;
    params[@backingInt(engine.Param.mode)] = @backingInt(c.mode);
    params[@backingInt(engine.Param.report)] = if (c.report) |r| @intFromPtr(r) else 0;
    params[@backingInt(engine.Param.toctou_ppm)] = c.vfs_toctou_race_ppm;
    params[@backingInt(engine.Param.double_fetch_ppm)] = c.double_fetch_preempt_ppm;
    params[@backingInt(engine.Param.byzantine_ppm)] = c.byzantine_ppm;
    if (c.amplification) |lim| {
        const w = engine.amplify.pack(lim);
        params[@backingInt(engine.Param.amplification)] = 1;
        params[@backingInt(engine.Param.amplification_limits_a)] = w[0];
        params[@backingInt(engine.Param.amplification_limits_b)] = w[1];
    }
    params[@backingInt(engine.Param.mcdc_report)] = if (c.mcdc) |r| @intFromPtr(r) else 0;
    params[@backingInt(engine.Param.campaign)] = if (c.campaign) |r| @intFromPtr(r) else 0;
    params[@backingInt(engine.Param.check_sarif)] = if (c.check_sarif) |d| @intFromPtr(d) else 0;
    return params;
}

/// Content findings of the current run so far (empty without the engine).
/// Call from the test body, or read `lastFindings` after `check` returns.
pub fn runFindings() []const ContentFinding {
    const e = engine.active() orelse return &.{};
    return e.findingsSlice();
}

/// The client on simulated node `node` belongs to `tenant` for the rest of
/// the run: bytes another tenant marked (`markTenant`, `withTenant`
/// secrets) must not reach it.
pub fn bindNodeTenant(node: tardis.NodeId, tenant: TenantId) void {
    assert(tenant != tenant_poison);
    const e = engine.active() orelse return;
    if (node < engine.nodes_max) e.tenant_of_node[node] = tenant;
}

/// Declares bytes as belonging to `tenant`: they may reach that tenant's
/// peers (and local files), not another tenant's (CWE-668).
pub fn markTenant(bytes: []const u8, tenant: TenantId) void {
    assert(tenant != tenant_poison);
    const e = engine.active() orelse return;
    e.mark(bytes, .tenant_data, tenant, currentNode());
}

fn currentNode() tardis.NodeId {
    const s = tardis.Sim.activeOrNull() orelse return 0;
    return s.currentNode();
}

pub fn attachWorker(w: ?*WorkerSec) void {
    active_worker = w;
}

fn spanOf(bytes: []const u8) u64 {
    return @intFromPtr(bytes.ptr);
}

fn inShadow(w: *WorkerSec, bytes: []const u8) bool {
    const a = spanOf(bytes);
    return a >= w.base and a + bytes.len <= w.base + w.shadow.len * 8;
}

/// Declares key material: a free before `secureZero` reports CWE-226, and
/// egress reports CWE-200.
/// Call it once the bytes hold their final value: the engine fingerprints
/// the content at this moment (8-byte windows, so secrets of at least 8
/// bytes).
pub fn markSecret(bytes: []const u8) void {
    if (engine.active()) |e| e.mark(bytes, .secret, e.current_tenant, currentNode());
    const w = active_worker orelse return;
    if (inShadow(w, bytes)) w.setRange(spanOf(bytes), bytes.len, .secret_key);
}

/// Declares validated input: clears its taint (plan2.md §5.2). The content
/// engine taints by content, so equal bytes elsewhere are cleared too until
/// they are received again; the shadow model clears these addresses.
pub fn markSanitized(bytes: []const u8) void {
    if (engine.active()) |e| e.sanitize(bytes);
    const w = active_worker orelse return;
    if (inShadow(w, bytes)) w.setRange(spanOf(bytes), bytes.len, .valid_clean);
}

/// Runs `f(args...)` with allocations and received bytes tagged `tenant`.
pub fn withTenant(tenant: TenantId, comptime f: anytype, args: anytype) @typeInfo(@TypeOf(f)).@"fn".return_type.? {
    assert(tenant != tenant_poison);
    if (engine.active()) |e| {
        const saved = e.current_tenant;
        e.current_tenant = tenant;
        defer e.current_tenant = saved;
        return withTenantShadow(tenant, f, args);
    }
    return withTenantShadow(tenant, f, args);
}

fn withTenantShadow(tenant: TenantId, comptime f: anytype, args: anytype) @typeInfo(@TypeOf(f)).@"fn".return_type.? {
    const w = active_worker orelse return @call(.auto, f, args);
    const saved = w.tenant;
    w.tenant = tenant;
    defer w.tenant = saved;
    return @call(.auto, f, args);
}

/// A security-critical decision. Under `instruction_skip_glitch_ppm` the
/// simulator may invert it (one skipped compare), deterministically.
pub fn criticalCheck(env: *tardis.Env, cond: bool) bool {
    const ppm: tardis.Ppm = if (engine.active()) |e|
        @intCast(e.param(.glitch_ppm))
    else
        active_config.instruction_skip_glitch_ppm;
    if (ppm != 0 and env.sim.decider.chance(.fault, ppm)) return !cond;
    return cond;
}

// --- Pillars II and III through the engine (plan2.md §4, §5.1) ------------

/// `std.Io.Mutex` with a lock class. Taking it checks the lock order of
/// every task so far (lockdep, §4.2): an inversion is CWE-833 and fails the
/// run even on a schedule that does not deadlock. Without the engine it is
/// a plain mutex.
pub const Mutex = struct {
    inner: std.Io.Mutex = .init,
    /// Lock class, below `engine.races.lock_classes_max`: one per kind of
    /// lock (all locks of one table share a class).
    class: u16,

    pub fn lock(m: *Mutex, io: std.Io) std.Io.Cancelable!void {
        engine.lockAcquire(m.class);
        m.inner.lock(io) catch |err| {
            engine.lockRelease(m.class);
            return err;
        };
    }

    pub fn unlock(m: *Mutex, io: std.Io) void {
        m.inner.unlock(io);
        engine.lockRelease(m.class);
    }
};

/// A value another party can change under the reader: memory shared with a
/// peer process, a DMA buffer, a ring written by another task. Zig has no
/// load instrumentation, so code that reads such memory opts in by reading
/// through `load`. The second read of the same word by one task is a
/// keyed preemption point (`double_fetch_preempt_ppm`): the writer gets to
/// run between the check and the use, and the program's own oracle shows
/// whether it re-validates (CWE-367, §4.1).
pub fn Shared(comptime T: type) type {
    return struct {
        const Self = @This();
        value: T,

        pub fn init(v: T) Self {
            return .{ .value = v };
        }

        pub fn load(s: *const Self) T {
            engine.sharedRead(@intFromPtr(s));
            return @as(*const volatile T, &s.value).*;
        }

        pub fn store(s: *Self, v: T) void {
            @as(*volatile T, &s.value).* = v;
        }
    };
}

/// For the rest of the run, a path this task checks (`statFile`, `access`)
/// and then opens may, with `vfs_toctou_race_ppm` per pair, be replaced by
/// a symlink to `target` between the two (§4.3). Paths up to 256 bytes.
pub fn setToctouTarget(target: []const u8) void {
    const e = engine.active() orelse return;
    assert(target.len > 0 and target.len <= engine.races.target_bytes_max);
    @memcpy(e.races.target[0..target.len], target);
    e.races.target_len = @intCast(target.len);
}

/// For the rest of the run, datagrams from `node` to the nodes in `peers`
/// are rewritten by `mutate` with `byzantine_ppm` per datagram, while the
/// other peers get the original: a two-faced node (§5.1). Use
/// `ByzantineFrameSpec(...).equivocateFrame(i, flip)` for a mutation that
/// keeps the checksum valid.
pub fn twoFaced(node: tardis.NodeId, peers: []const tardis.NodeId, mutate: engine.races.MutateFn) void {
    const e = engine.active() orelse return;
    var set: u32 = 0;
    for (peers) |p| {
        assert(p < 32);
        set |= @as(u32, 1) << @as(u5, @intCast(p));
    }
    e.races.equivocator = .{ .node = node, .peers = set, .mutate = mutate };
}

/// Counters of the current run (empty without the engine).
pub fn raceCounters() struct { double_fetches: u32, toctou_swaps: u32, mutations: u32 } {
    const e = engine.active() orelse return .{ .double_fetches = 0, .toctou_swaps = 0, .mutations = 0 };
    return .{ .double_fetches = e.races.double_fetches, .toctou_swaps = e.races.toctou_swaps, .mutations = e.races.mutations };
}

pub const Sandbox = struct {
    policy: SandboxPolicy,

    pub fn allowsPath(s: Sandbox, path: []const u8) bool {
        return s.policy.allowsPath(path);
    }
};

/// Outside any engine, `activeSandbox` still reports the policy; nothing
/// enforces it.
threadlocal var unenforced_sandbox: ?Sandbox = null;

/// Ends the calling node's initialization: until its program restarts,
/// a capability the policy dropped is CWE-272 (§5.2).
pub fn enterSandbox(policy: SandboxPolicy) void {
    if (engine.active()) |e| return e.enterSandbox(currentNode(), policy);
    unenforced_sandbox = .{ .policy = policy };
}

pub fn activeSandbox() ?Sandbox {
    if (engine.active()) |e| {
        const p = e.sandboxOf(currentNode()) orelse return null;
        return .{ .policy = p.* };
    }
    return unenforced_sandbox;
}

// --- Requirement Traceability Registry ------------------------------------

pub const Registry = traceability.Table;

/// Checks made outside any campaign (no engine, or no `certify`).
threadlocal var registry: Registry = .{};

pub const RequirementScope = struct {
    id: []const u8,

    /// Records one check of the requirement and returns `ok`. Inside a
    /// `certify` campaign the check counts for that campaign (once per
    /// counted run, not during shrinking); elsewhere it goes to this
    /// thread's `requirementRecords`.
    pub fn check(s: RequirementScope, ok: bool) bool {
        if (engine.requirementCheck(s.id, ok)) return ok;
        const i = registry.index(s.id) catch @panic("tardis_sec: requirement id too long, or requirements_max reached");
        const rec = &registry.records[i];
        if (ok) rec.checks_passed += 1 else rec.checks_failed += 1;
        return ok;
    }
};

/// Binds the following checks to a Security Functional Requirement, e.g.
/// `tardis_sec.requirement("SFR-FDP_ACC.1")` (ids up to 48 bytes).
pub fn requirement(id: []const u8) RequirementScope {
    assert(id.len > 0 and id.len <= traceability.id_bytes_max);
    return .{ .id = id };
}

/// Checks made outside a campaign on this thread.
pub fn requirementRecords() []const RequirementRecord {
    return registry.slice();
}

// ===========================================================================
// §6/§7 Dual-execution oracles

pub const Error = error{
    TimingLeak,
    Interference,
    DifferentialDivergence,
};

threadlocal var dual_secret: []const u8 = "";
threadlocal var dual_public: []const u8 = "";

fn traceWith(
    gpa: Allocator,
    comptime body: fn (*tardis.Env, []const u8, []const u8) anyerror!void,
    public: []const u8,
    secret: []const u8,
    seed: u64,
    persona: tardis.Persona,
    options: tardis.Options,
) !u64 {
    const Thunk = struct {
        fn run(env: *tardis.Env) anyerror!void {
            return body(env, dual_public, dual_secret);
        }
    };
    dual_public = public;
    dual_secret = secret;
    return tardis.traceHash(gpa, Thunk.run, seed, persona, options);
}

/// Runs `body` with `secret_a` and with `secret_b` on the same seeds and
/// requires identical observable traces (every I/O operation, its size and
/// its virtual time). With the PC/cache-line tracer linked (§6), the trace
/// also covers basic blocks and 30-bit cache-line offsets.
pub fn assertConstantTime(
    gpa: Allocator,
    comptime body: fn (*tardis.Env, []const u8, []const u8) anyerror!void,
    secret_a: []const u8,
    secret_b: []const u8,
    seeds: u32,
    options: tardis.Options,
) !void {
    var i: u32 = 0;
    while (i < seeds) : (i += 1) {
        const seed = tardis.runSeed(options.campaign_seed, i, 0);
        const persona = options.personas[0];
        const a = try traceWith(gpa, body, "", secret_a, seed, persona, options);
        const b = try traceWith(gpa, body, "", secret_b, seed, persona, options);
        if (a != b) return error.TimingLeak;
    }
}

/// Goguen-Meseguer non-interference: for one public input and two HIGH
/// secrets, LOW observations (the trace) must be identical.
pub fn assertNonInterference(
    gpa: Allocator,
    comptime body: fn (*tardis.Env, []const u8, []const u8) anyerror!void,
    public: []const u8,
    high_a: []const u8,
    high_b: []const u8,
    seeds: u32,
    options: tardis.Options,
) !void {
    var i: u32 = 0;
    while (i < seeds) : (i += 1) {
        const seed = tardis.runSeed(options.campaign_seed, i, 0);
        const persona = options.personas[0];
        const a = try traceWith(gpa, body, public, high_a, seed, persona, options);
        const b = try traceWith(gpa, body, public, high_b, seed, persona, options);
        if (a != b) return error.Interference;
    }
}

/// Two implementations of one parser or protocol must agree on `input`:
/// same accept/reject, and the same result when both accept (CWE-444).
pub fn assertDifferential(
    comptime T: type,
    input: []const u8,
    scratch_a: []u8,
    scratch_b: []u8,
    comptime parse_a: fn ([]const u8, []u8) anyerror!T,
    comptime parse_b: fn ([]const u8, []u8) anyerror!T,
) !void {
    const a = parse_a(input, scratch_a);
    const b = parse_b(input, scratch_b);
    if (a) |va| {
        const vb = b catch return error.DifferentialDivergence;
        if (!std.meta.eql(va, vb)) return error.DifferentialDivergence;
    } else |_| {
        _ = b catch return;
        return error.DifferentialDivergence;
    }
}

pub const ExhaustiveOptions = tardis.ExhaustiveOptions;
pub const ExhaustiveResult = tardis.ExhaustiveResult;

/// Bounded exhaustive exploration (§7.2): every combination of outcomes of
/// the first `depth_max` branchable decisions of `body`, by stateless
/// replay in core (`tardis.exhaustive`). Partial-order reduction and
/// snapshot restore are not applied yet, so the cost is the full product
/// of outcomes; `ExhaustiveResult.complete` says whether the bound was
/// covered without gaps. Evidence within the model and the bound, never a
/// proof beyond them.
pub fn verifyExhaustive(
    gpa: Allocator,
    comptime body: fn (*tardis.Env) anyerror!void,
    options: tardis.Options,
    x: ExhaustiveOptions,
) !ExhaustiveResult {
    return tardis.exhaustive(gpa, body, options, x);
}

// ===========================================================================
// §7 Evidence: SARIF v2.1.0 and the signed bundle

pub fn writeSarif(w: *std.Io.Writer, tool_version: []const u8, findings: []const Finding) !void {
    try w.print(
        \\{{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{{"tool":{{"driver":{{"name":"tardis_sec","version":"{s}"}}}},"results":[
    , .{tool_version});
    for (findings, 0..) |f, i| {
        if (i > 0) try w.writeAll(",");
        try w.print(
            \\{{"ruleId":"CWE-{d}","level":"error","message":{{"text":"{t} at 0x{x} (tenant {d})"}}}}
        , .{ f.cwe, f.state, f.addr, f.tenant });
    }
    try w.writeAll("]}]}\n");
}

/// Merkle root over SHA-256 leaves (pairs hashed; an odd leaf is promoted).
/// `leaves` is overwritten. Iterative, bounded by `leaves.len`.
pub const merkleRoot = evidence.merkleRoot;

pub const Ed25519 = std.crypto.sign.Ed25519;

/// Signs a bundle's Merkle root.
pub fn signEvidence(root: [32]u8, key: Ed25519.KeyPair) !Ed25519.Signature {
    return key.sign(&root, null);
}

// --- certification campaigns ----------------------------------------------

pub const version = "0.1.0";

/// `CertifyOptions.repositories`: a checkout and the name it goes by.
pub const Repository = struct { name: []const u8, dir: std.Io.Dir };
pub const repositories_max = 8;

pub const CertifyOptions = struct {
    /// The test (campaign) name, bound to every requirement it checks.
    name: []const u8,
    /// The project's requirement file (its contents): requirements listed
    /// there and never checked are gaps in the matrix.
    requirements: ?[]const u8 = null,
    /// The project directory holding `.tardis_persist/requirements.bin`:
    /// the campaign's results are merged into it.
    persist: ?std.Io.Dir = null,
    /// Where `SecurityConfig.evidence_dir` is created (default: the
    /// current directory). `TARDIS_EVIDENCE_DIR`, in tests, overrides both.
    out: ?std.Io.Dir = null,
    /// Signs the Merkle root; without it the bundle is integrity-checked only.
    key: ?Ed25519.KeyPair = null,
    /// `@src()` of the test, for SARIF locations.
    source: ?std.builtin.SourceLocation = null,
    /// Repository path of the test module's root, prepended to `source.file`.
    source_prefix: []const u8 = "",
    /// Golden trace hashes recorded (the first iterations' seeds).
    determinism_seeds: u32 = 8,
    /// The repositories whose checked-out revisions the manifest records
    /// (read from `.git`, no `git` process; §7.5).
    repositories: []const Repository = &.{},
    /// The project's instrumented decisions (§7.1): each one's MC/DC counts
    /// towards its requirement's row, and declared decisions never reached
    /// are listed as dead (or, with a justification, deactivated) code.
    decisions: []const mcdc.Decl = &.{},
    tool_version: []const u8 = version,
};

/// The outcome of `certify`. Heap-allocated (the requirement table is
/// 512 KiB); `deinit` frees it.
pub const Certified = struct {
    campaign: Campaign,
    failures: tardis.FailureLog,
    mcdc: mcdc.Report,
    mode: SecurityMode,
    /// The campaign's first failure (`check`'s error), if any.
    err: ?anyerror,
    /// `<16 hex digits>`: a hash of the name, seed, iterations and mode.
    id_buf: [16]u8,
    /// The bundle directory, open (certification mode only).
    bundle: ?std.Io.Dir,
    written: ?evidence.Written,
    determinism: [64]evidence.DeterminismRow,
    revisions: [repositories_max]evidence.Revision,
    revisions_len: u8,
    determinism_len: u32,
    io: std.Io,

    pub fn id(c: *const Certified) []const u8 {
        return &c.id_buf;
    }

    pub fn deinit(c: *Certified, gpa: Allocator) void {
        if (c.bundle) |d| d.close(c.io);
        gpa.destroy(c);
    }
};

fn testEnvSet(gpa: Allocator, name: []const u8) bool {
    if (!@import("builtin").is_test) return false;
    return std.testing.environ.containsUnempty(gpa, name) catch false;
}

/// Runs a certification campaign: `check` with every counted run's
/// requirement checks and findings collected, merged into the persisted
/// registry when `persist` is set. In `.certification_eal7` mode (or with
/// `TARDIS_CERT_EAL7` set in tests) the campaign never stops early (one
/// thread, `keep_going`: every failure is shrunk and kept as a capsule),
/// and the signed evidence bundle is written to
/// `<out>/<evidence_dir>/<id>/`. The campaign's error, if any, is in
/// `Certified.err`; `certify` itself fails only on I/O and allocation.
pub fn certify(
    gpa: Allocator,
    io: std.Io,
    comptime body: fn (*tardis.Env) anyerror!void,
    config: SecurityConfig,
    c: CertifyOptions,
) !*Certified {
    const r = try gpa.create(Certified);
    errdefer gpa.destroy(r);
    r.campaign.init(c.name);
    r.failures = .{};
    r.mcdc = .{};
    r.mode = if (config.mode == .certification_eal7 or testEnvSet(gpa, "TARDIS_CERT_EAL7")) .certification_eal7 else config.mode;
    r.err = null;
    r.bundle = null;
    r.written = null;
    r.determinism_len = 0;
    r.revisions_len = 0;
    r.io = io;
    if (c.repositories.len > repositories_max) return error.TooManyRepositories;
    for (c.repositories) |repo| {
        r.revisions[r.revisions_len] = evidence.readRevision(gpa, io, repo.dir, repo.name);
        r.revisions_len += 1;
    }
    if (c.requirements) |text| try r.campaign.requirements.declare(text);
    const declared = r.campaign.requirements.len;

    var cfg = config;
    cfg.mode = r.mode;
    cfg.campaign = &r.campaign;
    if (cfg.mcdc == null) cfg.mcdc = &r.mcdc;
    const eal7 = r.mode == .certification_eal7;
    if (eal7) cfg.base.keep_going = &r.failures;
    // Counted runs commit into this process's campaign. A forked child
    // sends its run's tallies back through the seam (`fork_export`), but
    // worker processes (`fork` with `workers > 1`) would need the same relay
    // one level up: those campaigns run on threads instead.
    if (cfg.base.workers > 1) cfg.base.fork = false;
    for (c.decisions, 0..) |d, k| {
        for (c.decisions[0..k]) |e| if (e.id == d.id) return error.DuplicateDecision;
    }
    tardis.check(gpa, body, withSecurity(cfg)) catch |err| {
        r.err = err;
    };
    // MC/DC per requirement: decisions declared for it, and those complete.
    const report = cfg.mcdc.?;
    for (c.decisions) |d| {
        const req = d.requirement orelse continue;
        const rec = &r.campaign.requirements.records[try r.campaign.requirements.index(req)];
        rec.mcdc_decisions_total += 1;
        if (report.entry(d.id).complete()) rec.mcdc_decisions_covered += 1;
    }
    r.campaign.canonicalize(declared);

    {
        var h = std.hash.Wyhash.init(0x5EC0_CE27);
        h.update(c.name);
        h.update(std.mem.asBytes(&cfg.base.campaign_seed));
        h.update(std.mem.asBytes(&cfg.base.iterations));
        h.update(@tagName(r.mode));
        const v = h.final();
        _ = std.fmt.bufPrint(&r.id_buf, "{x:0>16}", .{v}) catch unreachable;
    }

    if (c.persist) |dir| {
        const table = try gpa.create(Registry);
        defer gpa.destroy(table);
        table.len = 0;
        try table.load(io, gpa, dir, traceability.persist_path);
        try table.merge(&r.campaign.requirements);
        try table.save(io, dir, traceability.persist_path);
    }
    if (!eal7) return r;

    // Golden trace hashes, from runs outside the campaign's counts.
    var plain = cfg;
    plain.campaign = null;
    plain.mcdc = null;
    plain.report = null;
    plain.base.keep_going = null;
    const plain_options = withSecurity(plain);
    var i: u32 = 0;
    while (i < c.determinism_seeds and r.determinism_len < r.determinism.len) : (i += 1) {
        const persona = cfg.base.personas[0];
        const seed = tardis.runSeed(cfg.base.campaign_seed, i, 0);
        const hash = tardis.traceHash(gpa, body, seed, persona, plain_options) catch continue;
        r.determinism[r.determinism_len] = .{ .persona = persona, .seed = seed, .trace_hash = hash };
        r.determinism_len += 1;
    }

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const env_dir: ?[]u8 = if (@import("builtin").is_test) std.testing.environ.getAlloc(gpa, "TARDIS_EVIDENCE_DIR") catch null else null;
    defer if (env_dir) |d| gpa.free(d);
    // `TARDIS_EVIDENCE_DIR` is relative to the current directory and wins.
    const base_dir = if (env_dir != null) std.Io.Dir.cwd() else c.out orelse std.Io.Dir.cwd();
    const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ env_dir orelse config.evidence_dir, r.id() });
    const dir = try base_dir.createDirPathOpen(io, path, .{ .open_options = .{ .iterate = true } });
    r.bundle = dir;
    r.written = try evidence.write(gpa, io, dir, .{
        .manifest = .{
            .tool_version = c.tool_version,
            .campaign = c.name,
            .campaign_id = r.id(),
            .campaign_seed = cfg.base.campaign_seed,
            .iterations = cfg.base.iterations,
            .personas = cfg.base.personas,
            .nodes = cfg.base.nodes,
            .mode = @tagName(r.mode),
            .revisions = r.revisions[0..r.revisions_len],
        },
        .campaign = &r.campaign,
        .failures = &r.failures,
        .mcdc = report,
        .decisions = c.decisions,
        .determinism = r.determinism[0..r.determinism_len],
        .source = c.source,
        .source_prefix = c.source_prefix,
    }, c.key);
    return r;
}

/// Verifies a bundle (§7.5): hashes, completeness, root and signature.
pub const verifyEvidence = evidence.verify;

/// Verifies a bundle and re-runs its capsules and determinism hashes
/// against the campaign's body and options.
pub const replayEvidence = evidence.replay;
```

### 8.4 Example 1: single-node multi-tenant AEAD audit (18 lines)

This compiles and passes against the SDK above and the current core, in all four build modes. Since revision 2 the security parts are live: `withSecurity` attaches the engine, `markSecret` fingerprints the key, and the `writeFile` goes through the egress scan, so a key byte run, uninitialized heap bytes or freed bytes in `t2.bin` would fail the run (§3.7). `criticalCheck` glitch injection runs as before. The `pad` field is never written out, so the padding is not exercised here; `pillar1_test.zig` covers uninitialized bytes leaving.

```zig
const std = @import("std");
const tardis = @import("tardis");
const tardis_sec = @import("tardis_sec");
const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

test "tenant AEAD: isolation, zeroization, padding, glitch resistance" {
    try tardis.check(std.testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            var key: [32]u8 = undefined;
            env.io.random(&key);
            tardis_sec.markSecret(&key); // leaves the process: CWE-200; freed unzeroed: CWE-226
            defer std.crypto.secureZero(u8, &key); // 0x7 -> 0xB, so no false positive
            const msg = try env.fuzz([48]u8); // 0x9 untrusted; the DoS ledger steers the fuzzer
            var out: struct { ct: [48]u8, tag: [16]u8, pad: [16]u8 } = undefined; // pad: uninit
            var pt: [48]u8 = undefined;
            tardis_sec.withTenant(2, Aead.encrypt, .{ &out.ct, &out.tag, &msg, "", @as([12]u8, @splat(0)), key });
            try env.dir.writeFile(env.io, .{ .sub_path = "t2.bin", .data = out.ct[0..] }); // egress scan
            out.ct[0] ^= 1; // a forged frame: rejected even if one compare is glitched
            const ok = if (Aead.decrypt(&pt, &out.ct, out.tag, "", @as([12]u8, @splat(0)), key)) |_| true else |_| false;
            try env.always("forged frame rejected", !(tardis_sec.criticalCheck(env, ok) and tardis_sec.criticalCheck(env, ok)));
        }
    }.run, tardis_sec.withSecurity(.{ .instruction_skip_glitch_ppm = 1_000, .base = .{ .iterations = 200 } }));
}

// The constant-time oracle (7 more lines): two secrets, identical traces.
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

What the 18 lines cover once the seams are in:

- **Heartbleed-style cross-tenant over-read:** the `t2.bin` write is egress-scanned against tenant 2.
- **Uninitialized padding:** `out.pad` is never written, and any send that includes it traps CWE-908.
- **HashDoS and complexity bombs:** `env.fuzz` input is steered by the amplification ledger.
- **`secureZero` verification:** the `defer` moves the key to `0xB`; deleting it traps CWE-226 at free.
- **Glitch resistance:** the two redundant `criticalCheck`s must both be glitched to accept a forgery.

The explicit constant-time oracle is the seven-line second test.

### 8.5 Example 2: multi-node Byzantine equivocation, DPOR and certification

**What runs today (revision 5): `src/sec/tests/example2.zig`.** **[Verified]**

- **The model.** It is the replication round of §4.4 instead of a Raft cluster, because core has no `createCluster` yet.
  - Node 0 proposes a value to nodes 1 and 2, and is two-faced towards node 2: the frame is rewritten and its checksum recomputed, with probability 0.5.
  - The fixed followers commit only when the other follower echoes the same value.
- **The campaign.** `certify` runs 120 iterations in certification mode with the requirement file. `SFR-FDP_ITC.2` (agreement) and `SFR-FDP_UIT.1` (the committed value is the proposal) pass 120 and 240 checks; `SFR-FPT_RCV.1` is a gap.
- **The bundle.** It is signed with the project key and verified by `replayEvidence`: integrity, signature, and 8 golden trace hashes recomputed. The registry persists across a second campaign.
- **The broken followers trust the leader alone.**
  - The campaign keeps going: all 24 iterations run, 10 fail, and each failure shrinks to one decision (the rewrite).
  - The bundle has 10 capsules and 15 files. Its SARIF has the failed requirement and the 10 failures with their tokens.
  - Every capsule replays to `error.AssertionFailed`.
- **Exhaustive exploration** (§7.2) runs every execution of the fixed round, 64 of them with at most 6 decisions each, and all are safe. The broken round fails.
- **Non-interference:** the reply does not depend on the session token.

The target API below remains the goal. It needs core's `createCluster` and `Service.tardisStateHash`, and seams 2–4.

```zig
const RaftHeader = extern struct { term: u64, index: u64, len: u32, crc: u32 };
const Equivocator = tardis_sec.ByzantineFrameSpec(RaftHeader, .{
    .length_field = "len", .checksum_field = "crc", .epoch_field = "term",
});

test "raft: safety under an equivocating leader, exhaustively to depth 12, with evidence" {
    try tardis.check(gpa, struct {
        fn run(env: *tardis.Env) !void {
            const u = try env.createCluster(3, RaftNode, .{}); // core target API
            u.byzantine(0, Equivocator, .{ .equivocate_ppm = 200_000 }); // node 0 lies, frames stay valid
            try u.clientWrites(32);
            try env.awaitHeal();
            const agree = tardis_sec.requirement("SFR-FDP_ITC.2"); // integrity of imported data
            try env.always("no two nodes commit different entries", agree.check(u.logsPrefixConsistent()));
            const auth = tardis_sec.requirement("SFR-FIA_UAU.6"); // re-authentication after reboot
            try env.always("replayed handshakes are rejected", auth.check(u.replayedAccepted() == 0));
        }
    }.run, tardis_sec.withSecurity(.{
        .mode = .certification_eal7, // never stops early; emits .tardis-evidence
        .base = .{ .nodes = 3, .iterations = 5_000, .chaos = .{} },
    }));
    const r = try tardis_sec.verifyExhaustive(gpa, RaftNode.model, .{ .nodes = 3 }, .{ .depth_max = 12 });
    try std.testing.expect(r.complete); // every execution within 12 decisions satisfied the invariants
    try tardis_sec.assertNonInterference(gpa, RaftNode.handleClient, "GET k", "token-A", "token-B", 256, .{});
}
```

### 8.6 The auto-shrunk security and certification report

```
tardis_sec: FAILED  iteration 1842/5000  persona=linux_ext4  seed=0x3f1c09d2a771b5e4
tardis_sec: CWE-125 cross-tenant bleed (Heartbleed class)   requirement SFR-FDP_IFF.1   severity: high

  virtual time   node0 (server)              node1 (tenant 1's client)    network
  ───────────── ─────────────────────────── ──────────────────────────── ──────────────────────
  0.000120000s  alloc 0x4000_C000_1200 +256  ·                            ·
  0.000120400s  recv 9 B ──untrusted────────────────────────────────────── req: len=0x4000 (!)
  0.000121100s  memcpy reply ← buf[0..0x4000]
  0.000121900s  send 16 KiB ─────────────────────────────────────────────► node1   ✗ egress scan
                                         ▲
  ShadowCell @0x7101_8000_2440  fast_word=0x0000_0000_0003_0011  meta_word=0x0200_0000_0000_0042
    bytes 0..7: 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 (valid_clean)   tenant 2  ◄── destination is tenant 1
  ShadowCell @0x7101_8000_2450  per_byte_nibble=0x77777777 (secret_key ×8)  tenant 2  alloc_gen 3

tardis_sec: shrunk 412 -> 3 decisions and lowered 1 value in 61 runs: len 0x4000 -> 0x0101
tardis_sec: MC/DC  decisions 214/220 (97.3 %)  missing pairs: tls.zig:88 c2 (B), heartbeat.zig:41 c1 (A)
tardis_sec: dead code: 3 blocks (heartbeat.zig:57-61, legacy.zig:12, legacy.zig:30)
tardis_sec: artifacts  zig-out/tardis-evidence/7f3a…/findings.sarif
                       zig-out/tardis-evidence/7f3a…/  (rtm.csv, mcdc.json, merkle.txt, signature.ed25519)
tardis_sec: replay     TARDIS_REPLAY=linux_ext4:0x3f1c09d2a771b5e4:9a1e…:9a1e…=101 zig build test
```

The first ShadowCell line decodes as follows:

- **`fast_word`:** `last_scalar = 0x0003_0011` (fiber 3, epoch 17), `per_byte_nibble = 0`.
- **`meta_word`:** `taint_tenant_id = 0x02` (bits 120–127), `alloc_gen = 0`, `vclock_epoch = 0x42`.

### 8.7 Roadmap: Milestone 5 (SEC), weeks 13–16

`plan.md` already uses "M5" for core throughput. This is the security package's fifth milestone, scheduled after the core prerequisites below.

**Core prerequisites** (core work, before week 13):

- fixed-address worker arenas;
- the allocator's always-on guard gaps and reuse FIFO (§3.5);
- seam 3 call sites in `vfs.zig` (operations), lock paths and `decide.zig` (the allocation and I/O-byte call sites exist since revision 2);
- the shrinker and emitter registration (seam 4; the shrinker half and the `TARDIS_SEC` switch exist since revision 6);
- an on-disk `.tardis_persist`;
- `createCluster`.

Seam 2 and `verifyExhaustive` additionally need user-space snapshot/restore, an open core M5 item.

| Week | Deliverable | Exit test |
|---|---|---|
| 13 | Pillar I on seam 1 and 3: shadow window, `onAlloc`/`onFree`/`onWrite`/`onNetRead`/`onNetWrite`, quarantine marking, egress scan wired to sends and file writes, tenants per socket | Example 1 catches a planted Heartbleed over-read, a padding leak, and a missing `secureZero`; seeds identical with and without `tardis_sec` |
| 14 | Pillars II–III: double-fetch arming and forced preemption, lockdep call sites, VFS TOCTOU scheduler and the NTFS/APFS persona extensions, Byzantine delivery seam, replay pool, taint sinks for VFS paths | A planted double fetch, AB-BA deadlock, symlink TOCTOU and equivocation bug are found and shrink to ≤ 5 decisions |
| 15 | Pillars IV–V part 1: amplification features in exploration, edge-counter and comparison tracer, PC/cache-line constant-time, Spectre window, MC/DC wrapper and clang MC/DC import, DPOR on snapshot restore | A HashDoS input is synthesized in under 10^5 iterations; `verifyExhaustive` completes a 3-node model to depth 12 |
| 16 | Pillar V part 2: requirement registry persistence, evidence bundle, SARIF in CI, `TARDIS_CERT_EAL7`, tool qualification notes (DO-330 TQL-5 data, CC ALC_TAT justification) | Example 2 passes and emits a bundle that an independent `tardis replay-evidence` run verifies |

**Week 13 status (revision 2).**

- **Done:** seam 3 at the allocation and I/O boundary (§2.2). The content engine with egress scanning of file writes, stream writes and datagrams (§3.7), tenants bound per peer node, deterministic poisoning on free, CWE-226 at free.
- **Exit tests:** the planted Heartbleed over-read, an uninitialized buffer tail, a use after free, a logged key and a missing `secureZero` are all found. The invariance test shows identical traces with and without `tardis_sec`. The padding exit test is met for heap buffers in every mode, and for stack buffers in Debug and ReleaseSafe only (§3.7).
- **Not done:** the word shadow window (needs fixed-address arenas), redzones and the reuse FIFO in core's allocator (done in revision 25, §3.5), and ingress taint (done in revision 23).

**Week 14 status (revision 3).**

- **Done:** lockdep through `tardis_sec.Mutex`; double-fetch preemption through `Shared(T)`; the check-to-use symlink swap at core's VFS seam; two-faced datagram delivery with checksum-preserving rewrites (§4.4).
- **Exit test met:** the planted double fetch, AB-BA order, symlink TOCTOU and equivocation are all found and shrink to 2, 0, 2 and 1 decisions.
- **Not done:**
  - lock call sites in core (file locks done in revision 24; `std.Io.Mutex` cannot be seen uncontended);
  - stream-level Byzantine delivery and the replay pool (done in revisions 20 and 21);
  - taint sinks for VFS paths (done in revision 23).

**Week 15 status (revision 4).**

- **Done:**
  - amplification ledger, features and findings (§6.1);
  - MC/DC for Zig decisions, with steering and a merged report (§7.1);
  - bounded exhaustive exploration by stateless replay, with a domain log in core's `Decider` (§7.2).
- **Exit criteria:**
  - **HashDoS synthesis:** met. The input is synthesized at iteration 13,974 (< 10^5).
  - **"`verifyExhaustive` completes a 3-node model to depth 12":** met by stateless replay. That is 9,216 executions, complete within the bound; 3,073 with the partial-order reduction of revision 34. There is no snapshot restore.
- **Not done:**
  - the edge-counter and comparison tracer, and with it the PC/cache-line constant-time oracle and the Spectre window (§6.3). These need Zig's `-ffuzz` counters read per run. Since revision 14, `zig build evidence -Dedges` builds with the counters and reads them per run for dead edges (§7.1). Since revision 28 instrumented C's edges, comparisons and divisions are traced and compared by the dual-execution oracles; Zig's edges guide exploration since revision 40, and the Spectre-v1 shape is detected since revision 43; Zig's own cache lines are still not traced.
  - the clang MC/DC import (C decisions are recorded through `tardis_sec_mcdc` since revision 39);
  - snapshot restore (a partial-order reduction and a state table are live since revisions 34 and 44; every execution still replays from the start).

**Week 16 status (revision 5).**

- **Done:**
  - `Options.keep_going` in core, and `Sim.rerun`, so reruns are not counted;
  - the requirement registry with persistence and gaps (§2.4);
  - `certify`, the bundle, `verifyEvidence`/`replayEvidence` and `tardis replay-evidence` (§7.5);
  - `TARDIS_CERT_EAL7`, `TARDIS_EVIDENCE_DIR`, `zig build evidence` and the CI workflow;
  - the tool qualification notes (§7.6).
- **Exit test met:** Example 2 passes and emits a signed bundle that an independent `tardis replay-evidence` run verifies. `replayEvidence` re-runs its capsules and determinism hashes, in all four build modes, and on Linux for the module and Example 2.
- **Not done:**
  - seam 4 (`TARDIS_SEC=1` for every `check`, shrinker predicates keyed on the finding);
  - `keep_going` with several workers or `fork`;
  - MC/DC decisions per requirement, and a dead-code list;
  - git revisions in the manifest;
  - a run of the workflow on GitHub.

**After the roadmap (revision 6).**

- **Done:** seam 4's shrinker predicate (`Provider.finding_key`) and the `TARDIS_SEC=1` / `-Dsec` build switch (§2.1, §8.2).
- **Checked:** with the switch on, every test in the repository passes (core's 164 included), so plain test programs show no false findings. The new tests pass in all four build modes with the switch off, and with it on in Debug.
- **Done (revision 7):** `keep_going` on several workers and through the fork server, and `certify` on several workers with identical evidence (§7.5).
- **Done (revision 8):** MC/DC per requirement, and the dead and deactivated decision list in `mcdc.json` and SARIF (§7.1).
- **Done (revision 9):** git revisions in the manifest, read without `git` (§7.5).
- **Done (revision 10):** `certify` through the fork server (§7.5).
- **Done (revision 11):** emitter registration: `campaign_end`, and per-check SARIF located through debug info (§2.1).
- **Done (revision 12):** `certify` through fork worker processes (§7.5).
- **Done (revision 13):** modified tracked files in the manifest, from `.git/index` (§7.5).
- **Done (revision 14):** dead edges from `-ffuzz` counters, in the bundle and SARIF (§7.1).
- **Done (revision 15):** staged changes in the manifest, from the object store (§7.5).
- **Done (revision 16):** justifications for dead-edge lines, from source markers (§7.1).
- **Done (revision 17):** the NTFS/APFS name-confusion personas in core, and their generator in `tardis_sec` (§4.3).
- **Done (revision 18):** hard-link and parent-directory swaps for check-to-use races (§4.4).
- **Done (revision 19):** a directory in place of the checked file, for fail-open error paths (§4.4).
- **Done (revision 20):** Byzantine rewriting of stream writes (§4.4).
- **Done (revision 21):** the replay pool, across reboots (§4.4).
- **Done (revision 22):** length desynchronization in flight (§4.4).
- **Done (revision 23):** ingress taint and the VFS path sink, CWE-22 (§5.2).
- **Done (revision 24):** lock call sites in core for file locks (§4.2).
- **Done (revision 25):** redzones and the reuse FIFO in core's heap, CWE-787 at free and CWE-125 at egress (§3.5).
- **Done (revision 26):** `enterSandbox` enforced at core's calls (CWE-272), and the spawn sink for received bytes (CWE-78) (§5.2).
- **Done (revision 27):** the C shims: format strings (CWE-134), `system` (CWE-78), SQLite SQL text (CWE-89) and pthread mutex order (CWE-833) (§5.2, §4.2).
- **Done (revision 28):** the tracer for instrumented C: edges and divisor widths in constant-time and non-interference traces, comparison constants kept (§6.3).
- **Done (revision 29):** cache sets of instrumented C's loads and stores in the same traces, and dual-execution inputs at one fixed address (§6.3).
- **Done (revision 30):** comparison feedback: C edges as coverage features, and compared constants as forced values in guided exploration (§7.1).
- **Done (revision 31):** the taint sink audit log, `sinks.json` in the bundle (§5.2, §7.5).
- **Done (revision 44):** state merging in the exhaustive search, by per-node and per-inbox histories (§7.2); `README.md`.
- **Done (revision 43):** the Spectre-v1 gadget shape (§6.3).
- **Done (revision 40):** Zig edge counters as coverage features for guided exploration (§7.1).
- **Done (revision 39):** MC/DC for C decisions through the shim header (§7.1).
- **Done (revision 35):** `criticalEql` and `TARDIS_SEC_CRITICAL`, glitch sites for constant-time comparisons and C checks (§7.4).
- **Done (revision 34):** partial-order reduction in the exhaustive search, from step footprints logged by core (§7.2).
- **Done (revision 33):** `mcdc.compare`, the vector to test next per MC/DC gap, and the `execl` and `posix_spawn` wrappers (§7.1, §5.2).
- **Done (revision 32):** `popen` and `exec` wrappers, the sandbox check for C process starts, and the audit sums through `fork` and workers (§5.2).
- **Not done:** a run of the workflow on GitHub (needs the repository pushed).

---

## Appendix A. Claims ledger

| Claim | Status |
|---|---|
| `ShadowCell` is 16 B; field offsets and bit positions as specified | [Verified] comptime |
| Address mapping is correct for all 64 workers | [Verified] comptime |
| Region C budget sums to exactly 64 MiB; 352 + 64 + 96 = 512 MiB | [Verified] comptime |
| Requirement records are 128 B; registry 512 KiB | [Verified] comptime |
| One-compare fast path semantics; unaligned span validation; 64-byte SIMD egress scan | [Verified] tests |
| Volatile-zero scrubbing; CWE-226 on unzeroed free; CWE-908 on uninitialized egress | [Verified] tests (reference hooks), and live through the seam (§3.7) |
| Core security seam at allocation, free, heap wipe and every `std.Io` read and write | [Verified] `src/sim/sec_seam.zig`, `pillar1_test.zig` |
| Content-tracked egress: CWE-908, 416, 200, 668 at file writes, stream writes and datagrams; CWE-226 at free | [Verified] `pillar1_test.zig`, all four build modes |
| Heartbleed-style cross-tenant over-read found by exploration and shrunk | [Verified] `pillar1_test.zig` |
| Core's heap guards every block and delays reuse in every build; a write past the end is CWE-787 at free, guard bytes leaving are CWE-125 | [Verified] `alloc.zig`, `pillar1_test.zig` |
| A capability used after `enterSandbox` (connect, listen, spawn, a path outside the prefixes) is CWE-272, and a restart restores the program's capabilities; received bytes in a spawn's argv are CWE-78 | [Verified] `pillar2_test.zig` |
| C code built with `tardis_sec.h` reports received bytes in format strings (CWE-134), shell commands (CWE-78) and SQL text (CWE-89), and pthread mutex order (CWE-833) | [Verified] `cshim_test.zig`, `tests/c/legacy.c` |
| `assertConstantTime` catches an early-exit compare, a secret-width division and a secret-indexed table lookup in instrumented C that no I/O shows | [Verified] `ctrace_test.zig`, `tests/c/ct.c` |
| Comparison feedback from instrumented C gets guided exploration past a 32-bit magic number (iteration 25) that 2,000 unguided iterations miss | [Verified] `ctrace_test.zig`, `explore.zig` |
| The bundle's `sinks.json` counts every taint check of a campaign by sink, and lists each distinct hit with its replay token; the sums and the file are the same in one process, through the fork server and on four workers | [Verified] `pillar2_test.zig`, `evidence.zig` |
| `mcdc.compare` steers guided exploration to both independence pairs of a decision behind a 32-bit match, which a plain `==` never shows in 2,000 iterations; `mcdc.json` names the vector to test next for each gap | [Verified] `pillar45_test.zig`, `mcdc.zig` |
| A C `system`, `popen`, `exec` or `posix_spawn` call is checked like a simulated spawn: CWE-78 for received bytes, CWE-272 from a sandbox that forbids processes | [Verified] `cshim_test.zig` |
| Lockdep inversion (CWE-833) on a non-deadlocking schedule, through `tardis_sec.Mutex` | [Verified] `pillar2_test.zig` |
| NTFS trailing dots, `::$DATA` and 8.3 short names, and APFS NFC/NFD for Latin-1, resolve to the same file in core | [Verified] `vfs.zig` tests, and every `pathConfusions` spelling through the simulator in `pillar2_test.zig` |
| A check-to-use race that replaces the file with a directory makes a fail-open gate leak; failing closed holds | [Verified] `pillar2_test.zig` |
| A check-to-use race swaps in a symlink, a hard link or a symlinked parent directory; a second `lstat` misses the last two, an inode comparison catches all three | [Verified] `pillar2_test.zig` |
| A name deny-list is bypassed on NTFS and APFS by a generated spelling, found as CWE-200 and shrunk to ≤ 5 decisions | [Verified] `pillar2_test.zig`; holds on ext4, and an allow-list holds everywhere |
| Double fetch exposed by a keyed preemption at the second `Shared(T)` read; missed by core alone | [Verified] `pillar2_test.zig` |
| Symlink swap between `stat` and `open` at core's VFS seam | [Verified] `pillar2_test.zig` |
| Two-faced datagram delivery with checksum-preserving rewrites | [Verified] `pillar2_test.zig` |
| Week 14 bugs shrink to ≤ 5 decisions | [Verified]: 0, 2, 2, 1 |
| Amplification ratios as coverage features; HashDoS synthesized by guided exploration | [Verified] at iteration 13,974; random search misses it |
| MC/DC unique-cause pairs for Zig decisions; redundant condition reported as a gap | [Verified] `pillar45_test.zig` |
| Bounded exhaustive exploration of a 3-node model to depth 12 | [Verified] by stateless replay: 9,216 executions, complete within the bound |
| Same traces with and without `tardis_sec` | [Verified] for the engine (16 seeds, 2 nodes); the word shadow's address invariance still needs §3.5 |
| Transitively closed lockdep bitmatrix | [Verified] test |
| Checksum-preserving equivocation and length desync | [Verified] test |
| A two-faced node equivocates over TCP streams as well as datagrams | [Verified] `pillar2_test.zig` |
| A frame recorded before a reboot is replayed after it; only a durable sequence number rejects it | [Verified] `pillar2_test.zig` |
| A frame shortened in flight, checksum fixed, smuggles its tail past a batch parser | [Verified] `pillar2_test.zig` |
| File locks taken in both orders are CWE-833 on a schedule that never deadlocks, with no `tardis_sec` type in the program | [Verified] `pillar2_test.zig` |
| A received file name reaching a path is CWE-22; validating and sanitizing it passes; no other test in the repository has a false finding | [Verified] `pillar2_test.zig`, `-Dsec` |
| Integer amplification ratios | [Verified] test |
| Constant time and non-interference at the I/O-trace level | [Verified] tests |
| Differential oracle | [Verified] test |
| SARIF v2.1.0 output; Merkle root; Ed25519 signing | [Verified] test |
| Certification campaigns never stop early; every failure shrunk and kept as a capsule | [Verified] `Options.keep_going`, Example 2 (10 of 24 iterations, each shrunk to 1 decision) |
| The same failure log on 1 or 4 workers, in one process or through the fork server | [Verified] `shrink_test.zig`, `fork_test.zig` (fork on Linux) |
| The same signed bundle on 1 or 4 workers | [Verified] Example 2: identical Merkle root |
| The same signed bundle through the fork server, with or without worker processes, as in one process | [Verified] Example 2 on Linux (requirement checks and findings cross `fork_export`; MC/DC vectors cross it untested) |
| Manifest counts tracked files changed since the index (unstaged changes), without running `git` | [Verified] `git.zig`, and against `git diff` on a real CRLF checkout |
| Manifest counts staged changes against the commit's tree, read from loose objects and packs | [Verified] `git.zig`, and against `git diff --cached` on packed repositories, a worktree and a merge conflict; alternate object stores give `null` |
| Manifest names the commit of each repository under evidence, without running `git` | [Verified] `evidence.zig` (loose, packed, detached, worktree), Example 2; CI compares it with `GITHUB_SHA` (not yet run) |
| MC/DC per requirement; dead and deactivated decisions listed and justified | [Verified] Example 2 (declared decisions) |
| Edges whose counters stayed zero listed in the bundle and SARIF, mapped to source lines | [Verified] Example 2 with `-Dedges` on Linux (Debug, ReleaseSafe); sound, not complete (LLVM prunes counters of blocks implied by others) |
| Dead-edge lines justified by `// tardis-deactivated:` markers in the source; a justified line that ran is reported stale | [Verified] `edges.zig` tests, Example 2 with `-Dedges` on Linux (Debug, ReleaseSafe) |
| Requirement checks counted once per campaign run (not in shrinking or determinism re-runs) | [Verified] Example 2: exactly 120 and 240 |
| Persisted requirement registry; merge is order-independent; crash-safe save | [Verified] `registry.zig` tests, Example 2 |
| Signed bundle; tampering (changed, extra or missing file, wrong key, unsigned) detected | [Verified] `evidence.zig`, `tardis replay-evidence` tests |
| Capsules and golden trace hashes re-run from a bundle | [Verified] `replayEvidence` in Example 2, all four build modes |
| Shrinking keeps the original security finding, not just `error.SecurityViolation` | [Verified] `pillar1_test.zig` (CWE-908 stays CWE-908 where the error alone drifted to CWE-200) |
| A failed `check` under `tardis_sec` writes SARIF located at the test's call line, with its replay token | [Verified] `pillar1_test.zig` (Debug and ReleaseSafe resolve the line; stripped builds omit it) |
| `TARDIS_SEC=1` audits every `check` in a build; off, core compiles no security code | [Verified] `pillar1_test.zig`, whole suite passing with `-Dsec` |
| SARIF uploaded to code scanning in CI | [Design]: workflow written (`.github/workflows/evidence.yml`), not yet run on GitHub |
| Glitch injection at `criticalCheck`, deterministic and shrinkable | [Verified] example 1 |
| Zero extra instructions without `tardis_sec` | Not claimed for the I/O seam: one null-pointer branch per allocation or I/O operation (§2.2). [Design] for per-access hooks, where the no-op hooks are empty inline functions |
| Address-layout invariance | [Design] for the word shadow: needs core allocator changes. The engine does not move allocations (it only fills them) |
| `<0.4 µs` restore, `<10 ms` shrinking, 3-cycle keys | [Target] core today: fork ~300 µs, empty run 4–7 µs |
| PC/cache-line constant time | [Verified] for instrumented C (`ctrace_test.zig`); [Design] for Zig code |
| The Spectre-v1 gadget shape after a marked bounds check is CWE-1037, in instrumented C and in Zig code that names its loads | [Verified] `ctrace_test.zig`, `spectre.zig` (a heuristic, not a model of speculation) |
| MC/DC for Zig code | [Verified] through `mcdc.decision` (an explicit wrapper; no compiler support) |
| MC/DC for C through `zig cc` | compile [Verified] (`.lprfb` bitmap section present); runtime readout unverified |
| Zig `-ffuzz` gives edge counters, PC table and indirect calls only | [Verified] against `lib/fuzzer.zig` of Zig 0.17.0 |
| Bounded DPOR | [Verified] for a partial-order reduction over adjacent commuting steps and for state merging by per-node histories (`pillar45_test.zig`); [Design]: snapshot restore (§7.2) |
| Certification | Never claimed: the package produces evidence; standards require tool qualification and independent evaluation |
