# A power cut on a real filesystem

The crash model says what a power loss may undo. This page records where
that has been checked against a real kernel, and where it has not
(`plan3.md` A3). So far: one rule, on ext4, with the SQLite finding that
rests on it, and one place where the model promised more than ext4 gives,
corrected since (revision 96).

## The claim

In every persona but `posix_strict`, a change to a directory (a create, a
rename, an unlink) waits in a metadata journal. A call that has returned
is not a call that is durable: a power loss keeps a prefix of the waiting
changes, anything from none of them to all, and loses the rest
(`Persona.journalPrefixOnCrash`, `Vfs.crash` in `src/model/vfs.zig`). An
`fsync` of a directory commits them all (on `linux_xfs`, only of a
directory with a change to one of its entries waiting). So does an `fsync`
of a file (`Persona.fileSyncCommitsJournal`): of any file on
`windows_ntfs`, `macos_apfs` and `freebsd_zfs`, and on `linux_ext4` and
`linux_xfs` of a file that has changed since the last time everything
waiting was committed (`Persona.syncNeedsOwnChange`, since revision 96;
before it, of any file on all five).

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

Each round does thirteen things, each followed by a power cut. They are
numbered as in the script; 4a to 4f were added in revision 96:

1. Create a file, sync it and its directory, unlink it.
2. The same, then sync the directory.
3. The same, then `fsync` another file that has not changed since it was
   last synced.
4. The same, then append to another file and `fsync` that one.
   - 4a. Append to another file, then unlink, then `fsync` the other file.
   - 4b. Unlink, then `fsync` another directory in which nothing changed.
   - 4c. Create another file, unlink, then `fsync` the created file.
   - 4d. Rename a synced file, then `fsync` it.
   - 4e. Overwrite a second file in place; append to a third and `fsync`
     it, which commits everything waiting; unlink; `fsync` the second.
   - 4f. The same with an append to the second file.
5. `scripts/powercut/sqlite_commit.c`, which is the program of
   `test/sqlite.zig` in C (create a table, insert a row, commit a second
   row and print the acknowledgement), with `synchronous=OFF`.
6. The same with `FULL`.
7. The same with `EXTRA`.

After the cut it looks for the unlinked file, or for the database file and
its journal, then opens the database, runs `PRAGMA integrity_check` and
looks for the second row.

The C program is built by gcc from a SQLite amalgamation (the one the
build pins in the first run, see below), with
`-DSQLITE_THREADSAFE=0`, which `zig build test-sqlite` does not pass. It
closes its connection before the cut, where the simulated program is cut
with the connection open. Neither changes the file calls of the commit.

## The result

Run on 2026-11-22: kernel 6.18.58.1 (WSL2), e2fsprogs 1.47.2, ext4 with the
default mount options. Rows 1 to 4 and the SQLite rows: five rounds with
SQLite 3.46.0, the same in each. Rows 4a to 4f: three rounds in a later
run on the same day, the same in each; that run repeated every other row
with the same results, its SQLite being 3.54.0, another amalgamation that
was on the machine.

| Step | After the power cut | The model |
|---|---|---|
| unlink, directory not synced | the file is back | allows it |
| unlink, then `fsync` of the directory | the file is gone | requires it |
| unlink, then `fsync` of an unchanged file | **the file is back** | required it gone, which was wrong; allows it since revision 96 |
| unlink, then a write to another file and its `fsync` | the file is gone | requires it |
| 4a: a write to another file, unlink, then that file's `fsync` | the file is gone | requires it |
| 4b: unlink, then `fsync` of an unchanged directory | the file is gone | requires it (not on `linux_xfs`) |
| 4c: a create, unlink, then `fsync` of the created file | the file is gone, the created file is there | requires both |
| 4d: a rename, then `fsync` of the renamed file | the rename is kept | requires it |
| 4e: an overwrite in place, a commit, unlink, then the overwritten file's `fsync` | the file is back, the overwritten data is there | allows it |
| 4f: an append, a commit, unlink, then the appended file's `fsync` | the file is back | allows it |
| SQLite, `synchronous=OFF` | the database file is gone, so there is no table to read | (not compared) |
| SQLite, `synchronous=FULL` | the database file is there, the integrity check passes, the journal is back, the acknowledged row is lost | finds such a run |
| SQLite, `synchronous=EXTRA` | the acknowledged row is kept, no journal | passes |

So the lost unlink is real on ext4, and the `FULL` finding is SQLite's
behaviour on a real kernel and not a product of the model. SQLite's
documentation says the same of `EXTRA`
(<https://www.sqlite.org/pragma.html#pragma_synchronous>).

## Where the model was wrong

The third row. The model took the `fsync` of any file to commit every
waiting change. On ext4 the `fsync` of a file with nothing new to write
did not: the unlink before it was still lost. The fourth row shows the
other case: a file written after the unlink carried the unlink out with
its own `fsync`.

The model therefore kept something ext4 loses, which is the unsafe
direction: a program that relies on an `fsync` of some other, unchanged
file to make a directory change durable passed in simulation and loses the
change on ext4. Only `posix_strict`, where an `fsync` of a file commits
nothing but that file, would find it.

**Fixed in revision 96** for `linux_ext4` and `linux_xfs`: an `fsync` of a
file commits the waiting changes only when the file has changed since the
last commit of everything waiting. A change is a write, a change of
length, or a change to one of the file's names (its creation, a link to it
or away from it, a rename of it or over it). Rows 4a to 4f were run to
find where that line is, and three of them corrected earlier versions of
the rule:

- **4b.** An `fsync` of a directory commits everything on ext4 even when
  nothing in that directory changed, so on `linux_ext4` any directory's
  `fsync` still commits all. By ext4's source as remembered, that is
  because it journals a directory's own blocks and forces a commit for
  every such inode; not looked up.
- **4e and 4f.** Unsynced data is not the criterion. A file written before
  a commit and synced after it gets its data written and commits nothing
  else: the commit in between had already taken the file's own change.
  This held for an append too, which a reading of the kernel had
  predicted otherwise (the append stayed inside the file's first block; a
  larger one was not tried).

Two unit tests in `src/model/vfs.zig` run these rows on the model.

What the fixed rule still gets wrong, or does not cover:

- **No commit by time.** ext4 commits everything waiting every five
  seconds by default. The model commits only at an `fsync`, so it does not
  know that a change made six seconds ago has left the file's hands: a
  create, a pause, an unlink of something else and the created file's
  `fsync` commit the unlink in the model, and on ext4 would not. That is
  the unsafe direction, and it needs timing to happen.
- **`fdatasync` is `fsync`.** In system-call mode both calls are the same.
  On ext4 an `fdatasync` commits for fewer changes (not for a change of
  times or of link count alone). Unsafe direction, not measured.
- **Changes the model does not see.** A change of length to the same
  length, an access time updated by a read, or the first use of a file
  the kernel had not yet loaded all make ext4 commit, by its source, where
  the model commits nothing. That direction loses more than ext4 does,
  and a program would have to rely on such an accident to notice. It also
  means the third row depends on the unchanged file being one the kernel
  already had in memory, which it was.
- **XFS is from its source as remembered, not from a run**: a file's
  `fsync` forces the log only when the file's inode has a change in it,
  and so does a directory's, which is why `linux_xfs` differs from
  `linux_ext4` in row 4b. No `mkfs.xfs` was at hand.
- **Not changed:** `windows_ntfs`, `macos_apfs` and `freebsd_zfs`, where an
  `fsync` of any file still commits everything and nothing has been run.
- **Other mount options** (`data=journal`, `nodelalloc`, fast commits) were
  not tried and would change these rows.

## What this does not show

- **One filesystem, one kernel, one set of mount options.** XFS, btrfs,
  NTFS, APFS and ZFS have not been run.
- **One transaction.** Wherever a file's `fsync` carried the unlink out,
  the file's change and the unlink were made within moments of each other,
  inside one of ext4's commit intervals.
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
