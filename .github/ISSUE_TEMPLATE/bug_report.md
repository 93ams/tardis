---
name: Bug report
about: A failing seed, a run that does not replay, or a model that differs from the real system
title: ""
labels: bug
---

<!--
A security problem in TARDIS itself goes through the private route in
SECURITY.md, not here.
-->

## What happened

<!-- What you ran, what you expected, what you got. -->

## Replay line

<!--
Paste the lines the failure printed, whole. Both if there are two:

  tardis: replay with:  TARDIS_SEED=0x... TARDIS_PERSONA=... zig build test
  tardis: replay the shrunk run with:  TARDIS_REPLAY=... zig build test

The report above them (the FAILED line, the error, the last events) helps
too. docs/reproducing.md says where to find these in a CI log.
-->

```
```

Does the line fail again when you run it? <!-- every time / sometimes / never -->

## Versions

- TARDIS commit or version:
- Zig version (`zig version`):
- Target (operating system, architecture; kernel version on Linux):
- Build mode and flags (`-Doptimize=...`, `-Dsec`, `-Dlibc`, ...):

## Options

<!--
The Options the failing check was given: iterations, personas, nodes,
mode, faults, net, explore, workers, setup, fork, chaos, limits. Paste the
call to tardis.check if you can. Name any TARDIS_* environment variable
that was set.
-->

```zig
```

## The code under test

<!--
The smallest test body that still fails, or a link to the repository and
commit. If the simulator differs from the real system, say what the real
system does and how you know.
-->
