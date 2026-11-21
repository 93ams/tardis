# Housekeeping: caches and disk space

Zig keeps everything it builds and never throws any of it away. Working on
TARDIS fills a disk faster than most projects, and a full disk does not
say that it is full. This document says where the space goes, how to get
it back, and what bounds the caches in CI.

## Where the space goes

| Directory | What is in it | Tracked by git |
|---|---|---|
| `.zig-cache/` in the checkout | the local cache: every object, test binary and intermediate file of every build | no |
| `zig-out/` in the checkout | what `zig build` installs: the `tardis` program, `zig-out/docs`, the evidence bundles in `zig-out/tardis-evidence` | no |
| `zig-pkg/` in the checkout | the fetched dependencies (termancy; SQLite's source with `-Dsqlite`) | no |
| the global cache directory | what is shared between projects, such as the compiled standard library and the build runner | outside the checkout |

`zig env` prints the global directory as `global_cache_dir`. By default it
is `%LOCALAPPDATA%\zig` on Windows and `~/.cache/zig` on Linux. If you use
a Zig version manager, look before you delete: on the machine this was
written on, the manager keeps the compilers themselves in that directory,
under `p`.

The local cache is the one that grows. Each build mode, each flag
(`-Dsec`, `-Dlibc`, `-Dedges`, `-Dtest-filter`) and each edit to a source
file leaves new test binaries beside the old ones, and nothing removes
the old ones. `scripts/verify.sh` alone builds the suite five ways.

How large:

- The local cache reached **59 GB** once during development (`plan3.md`
  H3).
- On 21 November 2026 it was 29 GB on the same machine, nearly all of it
  under `.zig-cache/o`. `zig-out` was 464 MB and `zig-pkg` 22 MB.
- The global cache was not measured for this document.

## Cleaning

Everything in `.zig-cache` can be rebuilt. Deleting it costs one full
build and nothing else. Do it when no build is running.

```sh
rm -rf .zig-cache
```

```powershell
Remove-Item -Recurse -Force .zig-cache
```

`zig-out` can be rebuilt too, but look first: `zig-out/tardis-evidence`
holds the bundles of the last `zig build evidence`, and a bundle you
signed and meant to keep is not something a rebuild gives back the same.
Copy those out before deleting `zig-out`.

`zig-pkg` and the global cache can be deleted as well. Without `zig-pkg`
the next build needs the network, to fetch the dependencies again.
Without the global cache it compiles the shared parts again.

Do not reach for `git clean -fdx` to do this. It removes the caches, and
with them every untracked file: new examples and tests that have not been
added yet. `git clean -fdX` (capital X) removes only what `.gitignore`
names, which here is the caches, `zig-out`, `zig-pkg` and
`diff_fs.trace`. Run it with `-n` first to see the list.

A habit that works: check the size now and then, and delete `.zig-cache`
when it passes a size you choose, or before a long `scripts/verify.sh`.

```sh
du -sh .zig-cache zig-out
```

```powershell
"{0:N1} GB" -f ((Get-ChildItem .zig-cache -Recurse -File |
  Measure-Object Length -Sum).Sum / 1GB)
```

## A full disk does not say so

When the drive fills during a build, the error is rarely "no space left":

- Zig on Windows fails with errors named `Unexpected`, from a file
  operation that has nothing to do with your change.
- WSL fails to start, or a command in it fails, with `E_FAIL`.

**Check free space first** when either appears. It is the cheap check, and
it has been the answer here.

```powershell
Get-PSDrive C
```

```sh
df -h .
```

### Windows with WSL

A build inside WSL has its own caches, on the Linux side
(`~/.cache/zig`, and `.zig-cache` in a checkout that lives there). WSL
keeps the Linux filesystem in one virtual disk file on the Windows drive.
That file grows as the caches grow, and by default it does not shrink
when files in it are deleted. So:

- Deleting the Linux-side caches frees space inside WSL, and that is
  usually enough to work again.
- The Windows drive gets the space back only after the virtual disk is
  compacted. That needs WSL stopped, with `wsl --shutdown`.
  **`wsl --shutdown` stops every running distribution and everything
  running in them**, not only yours: other terminals, containers, a build
  in progress. Check what is running, and ask anyone who shares the
  machine, before you run it.
- A checkout on the Windows drive that is built from both sides (through
  `/mnt/c` in WSL) keeps one `.zig-cache` for both, and it grows twice as
  fast.

The steps for compacting the virtual disk depend on the Windows edition
and the WSL version, and are not given here. Follow Microsoft's WSL
documentation for the version you have.

## The caches in CI

The four workflows in `.github/workflows` set up Zig with
`mlugg/setup-zig@v2` and pass it only a version. None of them names a
cache size. What bounds them is therefore the action's defaults, which
its `action.yml` at tag `v2` gave as follows when this was written:

- `use-cache` is on: the action caches the global and local Zig cache
  directories between runs.
- `cache-size-limit` is 2048 (MiB): in the action's words, when the cache
  directory exceeds this size, it is cleared.

So each system's Zig cache is held to about 2 GiB by the action, not by
anything in this repository. If that default changes, the bound changes
with it. To make it explicit, set `cache-size-limit` on the
`mlugg/setup-zig` steps.

Two other things are kept between or after runs:

- **The campaign's corpus** (`campaign.yml`): the directory named in
  `TARDIS_CORPUS_DIR`, saved with `actions/cache` under a key that is
  unique to each run, and restored by prefix. Every nightly run on every
  system therefore adds one cache entry, and the workflow deletes none.
  The bound is GitHub's: it evicts cache entries that have not been used
  for a while and the oldest ones once a repository passes its cache
  quota. Inside the directory, a check's file holds at most 16 failed
  runs and 65,536 corpus entries (`src/search/persist.zig`); the history
  and failure lists the workflow appends to are not trimmed.
- **Artifacts**: `campaign-<os>` and `tardis-evidence` use the
  repository's default retention. `test-failure-<os>` is uploaded only
  when a test job fails, and is kept 14 days.

If the Actions cache page of the repository shows the corpus entries
piling up, delete the old ones there. Only the newest per system is ever
restored.
