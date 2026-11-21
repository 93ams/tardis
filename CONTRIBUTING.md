# Contributing

## Before you send a change

```sh
scripts/verify.sh
```

It checks formatting and runs the suite in all four build modes and with
the security layer attached to every check. It takes a while; `zig build
test` alone is the quick loop. CI runs the suite on Linux, macOS and
Windows.

The build cache grows with every mode and flag and is never trimmed. If a
build fails with an error named `Unexpected`, or WSL with `E_FAIL`, check
free disk space first: [docs/housekeeping.md](docs/housekeeping.md).

The build fetches [termancy](https://github.com/93ams/termancy), pinned to
a commit, for the `tardis` program and the suite that tests termancy. To
work on both at once, `zig build test --fork=../termancy` uses a local
checkout in its place.

## What a change needs

- **A test that fails without it.** For a bug-finding feature, that means a
  small program with the bug planted and the same program with it fixed:
  the first must fail, the second must pass. The examples and most of the
  suite are written this way.
- **Determinism.** Nothing in a run may depend on the wall clock, the
  address of an allocation, the order of a hash map, or the thread it
  happens to run on. Every choice comes from the `Decider`, keyed so that
  removing one decision does not shift the others (`plan.md` §5.1).
- **Benign zero.** A decision whose raw value is zero must mean "nothing
  happened": no fault, no preemption, the smallest input. Shrinking
  depends on it (`plan.md` §14.2).
- **No allocation after setup** in the simulator's hot paths; fixed
  capacities with a counted overflow instead (`plan.md` §2.3).
- **The documents.** `plan.md` and `plan2.md` record what is built and
  what is verified. A change that makes a claim true or false updates
  them, and adds an entry to `CHANGELOG.md`. Say what is not done and what
  was not tested.

## Layout

- `src/root.zig`: the public API of the core. `src/sim`, `src/model`,
  `src/search`, `src/check`: the simulator, the filesystem and network
  models, exploration and shrinking, the oracles.
- `src/sec`: the security layer, a separate module over the core's seam.
- `src/cmd`: the programs (`tardis`, the benchmarks, the demo).
- `examples/`, `docs/`: what a new user reads first.
- `.github/workflows`: CI. [docs/reproducing.md](docs/reproducing.md)
  says what each workflow keeps when it fails.

## Reporting a bug

A failing seed is the best report: the `tardis: replay with:` line from
the failure, the Zig version, the platform, and the options of the
failing check. The bug report template asks for each, and
[docs/reproducing.md](docs/reproducing.md) says where to find the line in
a CI log. If the simulator itself misbehaves (a run that is not
deterministic, a model that differs from the real system), say what the
real system does and how you know.

A vulnerability in TARDIS itself goes through the private route in
[SECURITY.md](SECURITY.md), not a public issue.

## Conduct

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) says how people here are
expected to treat each other. It is a draft until the owner accepts it.
