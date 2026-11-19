# Stability and versioning

This is the policy TARDIS intends to hold from version 1.0. Until then the
version is `0.x`, and anything may change between releases; the
[changelog](../CHANGELOG.md) says what did.

## Versions

Semantic versioning. From 1.0:

- **Patch** releases fix bugs. No test that passed stops compiling.
- **Minor** releases add things. Existing tests compile and mean the same.
- **Major** releases may remove or change public declarations.

## What is public

- Everything a test reaches through `@import("tardis")` and
  `@import("tardis_sec")` that has a doc comment, except what is marked
  experimental.
- `addInstrumentedObject` and the build options of `build.zig`.
- The environment variables the README documents (`TARDIS_SEED`,
  `TARDIS_REPLAY`, and the others).
- The `tardis` program's commands and the evidence bundle's file formats.

Not public: anything under `src/` that those two modules do not export, the
trace's event names, and the text of failure reports (people read them;
programs should not).

## Seeds and replay tokens

This is the promise that matters most to a test suite, and the one most
easily broken by accident:

- **Within one release, a seed means one run.** The same seed, persona and
  options give the same decisions on every supported platform and build
  mode. A test in the suite checks a recorded trace hash on each.
- **Across releases, a seed may mean a different run.** New fault kinds and
  new decision streams are added at the end of their tables so that old
  seeds usually keep their meaning, but this is not promised. The release
  notes say when a release changes what existing seeds do.
- **A replay token is tied to the code under test.** It names the decisions
  a failure needed. If the program changes how many decisions it draws
  before the failure, the token may stop reproducing it;
  `TARDIS_REPLAY_FUZZY` exists for that case.

So: commit seeds and tokens for regressions if you like, and expect to
refresh them when you upgrade TARDIS or change the code they exercise. A
regression test that states its property and runs a few hundred seeds is
more durable than one pinned token.

## The Zig version

TARDIS implements `std.Io`, which is still changing. Each release names
the one Zig version it supports. A new Zig release is followed by a
TARDIS release; the previous Zig version is not supported after that.

## Experimental features

Free to change in any release: the instrumented-object detectors (shadow
memory, the race detector, lock order for `std.Io.Mutex`), the
stray-system-call trap, the virtual time-stamp counter, and state merging
in the exhaustive search.
