# A power cut on a real filesystem

The crash model says what a power loss may undo. This page records where
that has been checked against a real kernel, and where it has not
(`plan3.md` A3). So far: one rule, on ext4, with the SQLite finding that
rests on it, and one place where the model promised more than ext4 gives,
corrected since (revisions 96 and 98).

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
before it, of any file on all five). On those two a change stops counting
when the filesystem's own periodic commit has passed over it
(`Persona.commitIntervalNs`), and an `fdatasync` counts fewer changes than
an `fsync` (`Vfs.dataSync`), both since revision 98.

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

Each round does twenty-one things, each followed by a power cut. They are
numbered as in the script; 4a to 4f were added in revision 96 and 4g to
4n in revision 98:

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
   - 4g. As 4c, with a pause of seven seconds between the create and the
     unlink: longer than ext4's commit interval of five.
   - 4h. Unlink, a pause of seven seconds, and no `fsync` at all.
   - 4i. As 4, with `fdatasync` (`sync -d`) in place of `fsync`.
   - 4j. Unlink, then overwrite another file inside its length and
     `fdatasync` it. A fifth of a second passes before the unlink, so
     that the overwrite changes the file's time of modification.
   - 4k. The same with `fsync`.
   - 4n. As 4k without the pause, the other file having been written and
     synced just before.
   - 4l. As 4d with `fdatasync`.
   - 4m. As 4c with `fdatasync`.
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
was on the machine. Rows 4g to 4m: three rounds in a third run on the
same day, and five in a fourth, which added row 4n and looked for the
created file in 4g; the same in every round, and both runs repeated every
other row with the same results.

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
| 4g: a create, 7 s, unlink, then `fsync` of the created file | the file is back, the created file is there | allows the first since revision 98, requires the second |
| 4h: unlink, 7 s, no `fsync` | the file is gone | does not require it: see below |
| 4i: unlink, then an append to another file and its `fdatasync` | the file is gone | requires it |
| 4j: unlink, then an overwrite inside another file and its `fdatasync` | the file is back, the overwritten data is there | allows it since revision 98 |
| 4k: the same with `fsync` | the file is gone, the overwritten data is there | requires it |
| 4n: as 4k, at once after the other file's last change | the file is gone, the overwritten data is there | requires it |
| 4l: a rename, then `fdatasync` of the renamed file | the rename is undone | allows it since revision 98 |
| 4m: a create, unlink, then `fdatasync` of the created file | the file is gone, the created file is there | requires both |
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

## The commit by time, and `fdatasync` (revision 98)

Two things the rule of revision 96 still had wrong, both in the unsafe
direction, both now measured (rows 4g to 4m) and corrected for
`linux_ext4` and `linux_xfs`.

**The commit by time.** ext4 commits everything waiting five seconds after
the first change since its last commit (the default, `commit=5`). After
that the change is no longer in the file's hands: row 4g is row 4c with a
pause, and the created file's `fsync` no longer carries the unlink out.
The model now keeps the time of the first change since the last commit of
everything, and a change older than the persona's interval
(`Persona.commitIntervalNs`: five seconds on `linux_ext4`) stops counting
as the file's own. The time is the simulation's.

Row 4h is the other face of the same commit: left alone for seven
seconds, ext4 had made the unlink durable by itself. **The model does not
take that over.** In the model the periodic commit makes nothing durable
by itself: a change stays lost to a power cut until an `fsync` commits it,
however long the program waits. That loses more than ext4 does, which is
the safe direction, and it is deliberate: the interval is a mount option,
and a program that is correct only because five seconds passed is not
correct.

What the periodic commit passed over must still be within reach of an
`fsync`, or a correct program would fail: a file made, synced a minute
later with its directory, has to be there. So the model remembers how
many of the waiting changes the periodic commit passed over
(`Vfs.timed_len`), and the `fsync` or `fdatasync` of any file or directory
that one of them names commits those, and not the changes made after. In
row 4g that is the created file, kept, and the unlink, lost. (A first
version of this revision left those changes out of reach; the review
found it, and the row was then looked at again for the created file.)

**`fdatasync`.** In system-call mode it was `fsync`. On ext4 it commits
for fewer of the file's changes: for its creation (4m) and a change of its
length (4i), not for a write inside its length (4j, where `fsync` does
commit: 4k) and not for a rename (4l, where `fsync` does: 4d). The model
now has `Vfs.dataSync` with that rule, and the system call reaches it.
Only system-call mode has the call; `std.Io` has no `fdatasync`. The data
itself is durable after either call.

What the rule still gets wrong, or does not cover:

- **The interval is exact in the model and not on a kernel.** ext4 can
  commit sooner: when its journal fills, or when any other program on the
  machine syncs. A file changed, then an unlink, then the file's `fsync`
  within the interval (row 4a) commits the unlink in the model always, and
  on ext4 unless such a commit fell between the two. Unsafe direction; it
  needs another writer or a great deal of metadata. A program that wants
  the unlink durable syncs the directory.
- **`fdatasync` of a file with a hole filled, or with blocks allocated
  inside its length,** was not tried. By ext4's source as remembered it
  commits; the model takes it not to, which loses more.
- **A shortened file and `fdatasync`** commits in the model (a change of
  length); by the source, not run.
- **`fdatasync` of a directory** is `fsync` in the model; not run.
- **A write that changes nothing in the inode.** An overwrite made within
  the same tick of the kernel's clock as the file's last change may leave
  its time of modification as it was, and then the `fsync` of 4k would
  commit nothing. Row 4n tried for it, without the pause, and the `fsync`
  still committed in all five rounds; but a shell puts milliseconds
  between the calls, and a program that writes twice within one tick was
  not run. The model always counts a write for `fsync`. If the kernel
  does not, that is the unsafe direction, on the fast path of a database.
- **The interval's edge.** Seven seconds were measured, and none. The
  model takes a change of 4.99 seconds ago to be the file's own. A real
  transaction may have begun earlier than the program's first change.
- **A write that needs a new block** was not tried in 4e, 4f or after the
  interval: every append stayed inside a block the file had. By the
  source, the block is allotted at the `fsync` itself, which then
  commits; the model takes it not to, which loses more.
- **XFS and `fdatasync` after a rename.** By its source as remembered XFS
  commits there, where ext4 (4l) and the model do not. Loses more.
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
  `linux_ext4` in row 4b. Its interval in the model is thirty seconds (its
  periodic log work), and its `fdatasync` has ext4's rule; neither was
  run. No `mkfs.xfs` was at hand.
- **Not changed:** `windows_ntfs`, `macos_apfs` and `freebsd_zfs`, where an
  `fsync` of any file still commits everything and nothing has been run.
- **Other mount options** (`data=journal`, `nodelalloc`, fast commits) were
  not tried and would change these rows.

## What this does not show

- **One filesystem, one kernel, one set of mount options.** XFS, btrfs,
  NTFS, APFS and ZFS have not been run.
- **One transaction.** Wherever a file's `fsync` carried the unlink out,
  the file's change and the unlink were made within moments of each other,
  inside one of ext4's commit intervals. Row 4g is the one case across
  two, and only at seven seconds: the interval's edge was not looked for.
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
