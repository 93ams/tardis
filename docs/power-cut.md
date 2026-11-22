# A power cut on a real filesystem

The crash model says what a power loss may undo. This page records where
that has been checked against a real kernel, and where it has not
(`plan3.md` A3). So far: one rule, on ext4, with the SQLite finding that
rests on it, and one place where the model promises more than ext4 gives.

## The claim

In every persona but `posix_strict`, a change to a directory (a create, a
rename, an unlink) waits in a metadata journal. A call that has returned
is not a call that is durable: a power loss keeps a prefix of the waiting
changes, anything from none of them to all, and loses the rest
(`Persona.journalPrefixOnCrash`, `Vfs.crash` in `src/model/vfs.zig`). An
`fsync` of the directory commits them all, and so does an `fsync` of any
file (`Persona.fileSyncCommitsJournal`).

`test/sqlite.zig` rests on this. With `PRAGMA synchronous=FULL`, SQLite's
default, a commit in the default journal mode ends by unlinking the
rollback journal, and SQLite does not sync the directory after that. The
simulation finds a run where the power loss undoes the unlink: the
journal is back, the next open takes it for an unfinished transaction and
rolls back, and the acknowledged row is gone. With `EXTRA` the row is kept.
The test runs three personas (`linux_ext4`, `linux_xfs`, `posix_strict`)
and does not say which one the failing run was on.

## The experiment

`scripts/powercut/ext4.sh`, run as root on Linux. It makes an ext4
filesystem in a file, behind a loop device and a `dm-flakey` target, and
cuts the power the way xfstests does: the target is switched to drop every
write, the filesystem is unmounted (so what it still held in memory never
reaches the disk), the target is switched back, and the filesystem is
mounted again, which replays its journal.

Each round does seven things, each followed by a power cut:

1. Create a file, sync it and its directory, unlink it.
2. The same, then sync the directory.
3. The same, then `fsync` another file that has not changed since it was
   last synced.
4. The same, then append to another file and `fsync` that one.
5. `scripts/powercut/sqlite_commit.c`, which is the program of
   `test/sqlite.zig` in C (create a table, insert a row, commit a second
   row and print the acknowledgement), with `synchronous=OFF`.
6. The same with `FULL`.
7. The same with `EXTRA`.

After the cut it looks for the unlinked file, or for the database file and
its journal, then opens the database, runs `PRAGMA integrity_check` and
looks for the second row.

The C program is built by gcc from the amalgamation the build pins, with
`-DSQLITE_THREADSAFE=0`, which `zig build test-sqlite` does not pass. It
closes its connection before the cut, where the simulated program is cut
with the connection open. Neither changes the file calls of the commit.

## The result

Run on 2026-11-22: kernel 6.18.58.1 (WSL2), e2fsprogs 1.47.2, ext4 with the
default mount options, SQLite 3.46.0. Five rounds, the same in each:

| Step | After the power cut | The model |
|---|---|---|
| unlink, directory not synced | the file is back | allows it |
| unlink, then `fsync` of the directory | the file is gone | requires it |
| unlink, then `fsync` of an unchanged file | **the file is back** | **requires it gone: wrong** |
| unlink, then a write to another file and its `fsync` | the file is gone | requires it |
| SQLite, `synchronous=OFF` | the database file is gone, so there is no table to read | (not compared) |
| SQLite, `synchronous=FULL` | the database file is there, the integrity check passes, the journal is back, the acknowledged row is lost | finds such a run |
| SQLite, `synchronous=EXTRA` | the acknowledged row is kept, no journal | passes |

So the lost unlink is real on ext4, and the `FULL` finding is SQLite's
behaviour on a real kernel and not a product of the model. SQLite's
documentation says the same of `EXTRA`
(<https://www.sqlite.org/pragma.html#pragma_synchronous>).

## Where the model is wrong

The third row. The model takes the `fsync` of any file to commit every
waiting change. On ext4 the `fsync` of a file with nothing new to write
did not: the unlink before it was still lost. The fourth row shows the
other case: a file written after the unlink carried the unlink out with
its own `fsync`.

The model therefore keeps something ext4 loses, which is the unsafe
direction: a program that relies on an `fsync` of some other, unchanged
file to make a directory change durable passes in simulation and loses the
change on ext4. Only `posix_strict`, where an `fsync` of a file commits
nothing but that file, would find it. **Not fixed.** Until it is, name
`posix_strict` among a campaign's personas; the default is `linux_ext4`
alone.

## What this does not show

- **One filesystem, one kernel, one set of mount options.** XFS, btrfs,
  NTFS, APFS and ZFS have not been run, though all but `posix_strict`
  share the rule in the model.
- **One point in time, and by timing.** The cut comes after every call has
  returned and before ext4's next periodic commit (every five seconds by
  default), so everything waiting is lost at once. A commit that fell
  between the unlink and the cut would print "gone" in the first row, and
  would contradict nothing. That the kernel can keep a proper prefix of
  the waiting changes, which the model also allows, is not shown here.
- **Nothing about data.** No write was in flight at the cut, so this says
  nothing of torn writes, of which sectors of an unsynced file survive, or
  of `auto_da_alloc`.
- **Not a disk.** `dm-flakey` drops writes above the loop device. A drive
  that lies about its cache flush is another matter and is outside the
  model too.
- **`OFF` is not compared.** The simulated test fails for `OFF` as well,
  but which failure it reports was not set beside the kernel's.

The script leaves the `dm-flakey` kernel module loaded. It removes
everything else it made, and if an unmount or a removal fails it stops
there and says what is left.
