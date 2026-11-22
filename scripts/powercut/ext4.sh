#!/usr/bin/env bash
# A power cut on a real ext4, to check what the crash model claims
# (docs/power-cut.md, plan3.md A3).
#
# usage (as root, on Linux): ext4.sh <directory with sqlite3.c and sqlite3.h> [rounds]
#
# The filesystem lives in a file, behind a loop device and a dm-flakey
# target. The power cut is the one xfstests uses: the target is switched to
# drop every write, the filesystem is unmounted (so nothing it still held in
# memory reaches the disk), the target is switched back and the filesystem
# mounted again, which replays its journal as after a real power loss.
#
# Everything is made under $HOME/tardis-check-powercut-<pid> and removed at
# the end, with the loop device and the device-mapper target.
set -u
sqlite="${1:?directory with sqlite3.c}"
rounds="${2:-5}"
here="$(cd "$(dirname "$0")" && pwd)"
work="$HOME/tardis-check-powercut-$$"
name="tardis-powercut-$$"
mnt="$work/mnt"
loop=""

# Each step only if the one before it worked: a filesystem still mounted
# is not deleted into, and a loop device still in use is not detached.
cleanup() {
  # A table switch that failed half way leaves the target suspended, and
  # an unmount would wait on it for ever.
  dmsetup resume "$name" >/dev/null 2>&1
  if mountpoint -q "$mnt"; then
    umount "$mnt" || { echo "left behind: $mnt is still mounted (target $name, $loop, $work)"; return; }
  fi
  if dmsetup info "$name" >/dev/null 2>&1; then
    dmsetup remove --retry "$name" || { echo "left behind: target $name ($loop, $work)"; return; }
  fi
  if [ -n "$loop" ]; then
    losetup -d "$loop" || { echo "left behind: $loop ($work)"; return; }
  fi
  rm -rf "$work"
}
trap cleanup EXIT

mkdir -p "$mnt" || exit 1
modprobe dm-flakey || exit 1
truncate -s 256M "$work/disk.img"
loop="$(losetup -f --show "$work/disk.img")" || exit 1
sectors="$(blockdev --getsz "$loop")"
up="0 $sectors flakey $loop 0 180 0"
down="0 $sectors flakey $loop 0 0 180 1 drop_writes"
dmsetup create "$name" --table "$up" || exit 1
dev="/dev/mapper/$name"
mkfs.ext4 -q "$dev" || exit 1
mount "$dev" "$mnt" || exit 1

table() {
  dmsetup suspend --nolockfs "$name" && dmsetup load "$name" --table "$1" && dmsetup resume "$name"
}

power_cut() {
  table "$down" || exit 1
  umount "$mnt" || exit 1
  table "$up" || exit 1
  mount "$dev" "$mnt" || exit 1
}

echo "kernel $(uname -r), $(mkfs.ext4 -V 2>&1 | head -1), mount options: $(findmnt -no OPTIONS "$mnt")"
echo "building SQLite $(grep -m1 '#define SQLITE_VERSION ' "$sqlite/sqlite3.h" | cut -d'"' -f2)"
cp "$sqlite/sqlite3.c" "$sqlite/sqlite3.h" "$here/sqlite_commit.c" "$work/" || exit 1
# Single-threaded, so it needs no thread library: the one difference from
# the build of `zig build test-sqlite`, and none to the file calls.
gcc -O1 -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_THREADSAFE=0 -o "$work/sqlite_commit" "$work/sqlite_commit.c" "$work/sqlite3.c" || exit 1

gcc -O1 -o "$work/tight" "$here/tight.c" || exit 1
echo "block size $(stat -f -c %S "$mnt")"

for round in $(seq 1 "$rounds"); do
  # 1. A finished unlink whose directory is not synced.
  echo data > "$mnt/a"; sync "$mnt/a"; sync "$mnt"
  rm "$mnt/a"
  power_cut
  [ -e "$mnt/a" ] && r=back || r=gone
  echo "round $round: unlink, no fsync of the directory: the file is $r"
  rm -f "$mnt/a"; sync "$mnt"

  # 2. The same with the directory synced.
  echo data > "$mnt/b"; sync "$mnt/b"; sync "$mnt"
  rm "$mnt/b"; sync "$mnt"
  power_cut
  [ -e "$mnt/b" ] && r=back || r=gone
  echo "round $round: unlink, then fsync of the directory: the file is $r"
  rm -f "$mnt/b"; sync "$mnt"

  # 3. Unlink, then fsync of another file that has not changed. The
  # model took the fsync of any file to commit every pending change
  # (until revision 96).
  echo data > "$mnt/c"; echo other > "$mnt/unrelated"; sync
  rm "$mnt/c"; sync "$mnt/unrelated"
  power_cut
  [ -e "$mnt/c" ] && r=back || r=gone
  echo "round $round: unlink, then fsync of an unchanged file: the file is $r"
  rm -f "$mnt/c" "$mnt/unrelated"; sync "$mnt"

  # 4. Unlink, then a write to another file and its fsync.
  echo data > "$mnt/d"; echo other > "$mnt/written"; sync
  rm "$mnt/d"; echo more >> "$mnt/written"; sync "$mnt/written"
  power_cut
  [ -e "$mnt/d" ] && r=back || r=gone
  echo "round $round: unlink, then a write to another file and its fsync: the file is $r"
  rm -f "$mnt/d" "$mnt/written"; sync "$mnt"

  # 4a. As 4, with the write before the unlink: the other file has data
  # waiting when the unlink is made.
  echo data > "$mnt/e"; echo other > "$mnt/waiting"; sync
  echo more >> "$mnt/waiting"; rm "$mnt/e"; sync "$mnt/waiting"
  power_cut
  [ -e "$mnt/e" ] && r=back || r=gone
  echo "round $round: a write to another file, unlink, then that file's fsync: the file is $r"
  rm -f "$mnt/e" "$mnt/waiting"; sync "$mnt"

  # 4b. Unlink, then fsync of another directory in which nothing changed.
  echo data > "$mnt/f"; mkdir "$mnt/quiet"; sync
  rm "$mnt/f"; sync "$mnt/quiet"
  power_cut
  [ -e "$mnt/f" ] && r=back || r=gone
  echo "round $round: unlink, then fsync of an unchanged directory: the file is $r"
  rm -f "$mnt/f"; rmdir "$mnt/quiet"; sync "$mnt"

  # 4c. Unlink, then fsync of a file created just before and never synced.
  echo data > "$mnt/g"; sync
  : > "$mnt/fresh"; rm "$mnt/g"; sync "$mnt/fresh"
  power_cut
  [ -e "$mnt/g" ] && r=back || r=gone
  [ -e "$mnt/fresh" ] && n=there || n=gone
  echo "round $round: a create, unlink, then fsync of the created file: the file is $r, the created file is $n"
  rm -f "$mnt/g" "$mnt/fresh"; sync "$mnt"

  # 4d. A rename, then fsync of the renamed file, whose data is synced.
  echo data > "$mnt/h"; sync
  mv "$mnt/h" "$mnt/h2"; sync "$mnt/h2"
  power_cut
  if [ -e "$mnt/h2" ] && [ ! -e "$mnt/h" ]; then r="kept"; elif [ -e "$mnt/h" ] && [ ! -e "$mnt/h2" ]; then r="undone"; else r="mixed"; fi
  echo "round $round: a rename, then fsync of the renamed file: the rename is $r"
  rm -f "$mnt/h" "$mnt/h2"; sync "$mnt"

  # 4e. A file overwritten in place, then a commit of everything (another
  # file's write and fsync), then the unlink, then the overwritten file's
  # fsync: its data is still waiting, its inode's change is committed.
  echo data > "$mnt/i"; echo 0123456789 > "$mnt/over"; echo other > "$mnt/carrier"; sync
  printf XXXX | dd of="$mnt/over" conv=notrunc status=none
  echo more >> "$mnt/carrier"; sync "$mnt/carrier"
  rm "$mnt/i"; sync "$mnt/over"
  power_cut
  [ -e "$mnt/i" ] && r=back || r=gone
  echo "round $round: an overwrite in place, a commit, unlink, then the overwritten file's fsync: the file is $r, the overwritten file holds $(head -c 4 "$mnt/over")"
  rm -f "$mnt/i" "$mnt/over" "$mnt/carrier"; sync "$mnt"

  # 4f. The same with an append in place of the overwrite: the file's new
  # length is not on disk until its own fsync.
  echo data > "$mnt/j"; echo 0123456789 > "$mnt/grown"; echo other > "$mnt/carrier"; sync
  echo more >> "$mnt/grown"
  echo more >> "$mnt/carrier"; sync "$mnt/carrier"
  rm "$mnt/j"; sync "$mnt/grown"
  power_cut
  [ -e "$mnt/j" ] && r=back || r=gone
  echo "round $round: an append, a commit, unlink, then the appended file's fsync: the file is $r"
  rm -f "$mnt/j" "$mnt/grown" "$mnt/carrier"; sync "$mnt"

  # 4g. A create, a pause longer than ext4's commit interval (five
  # seconds), unlink, then the created file's fsync: as 4c, but the
  # periodic commit has taken the creation before the unlink is made.
  echo data > "$mnt/k"; sync
  : > "$mnt/early"; sleep 7; rm "$mnt/k"; sync "$mnt/early"
  power_cut
  [ -e "$mnt/k" ] && r=back || r=gone
  [ -e "$mnt/early" ] && n=there || n=gone
  echo "round $round: a create, a pause of 7 s, unlink, then fsync of the created file: the file is $r, the created file is $n"
  rm -f "$mnt/k" "$mnt/early"; sync "$mnt"

  # 4h. Unlink, a pause longer than the commit interval, no fsync at all.
  echo data > "$mnt/l"; sync
  rm "$mnt/l"; sleep 7
  power_cut
  [ -e "$mnt/l" ] && r=back || r=gone
  echo "round $round: unlink, a pause of 7 s, no fsync: the file is $r"
  rm -f "$mnt/l"; sync "$mnt"

  # 4i. As 4, with fdatasync (sync -d) in place of fsync: the append
  # changes the file's length.
  echo data > "$mnt/m"; echo other > "$mnt/written"; sync
  rm "$mnt/m"; echo more >> "$mnt/written"; sync -d "$mnt/written"
  power_cut
  [ -e "$mnt/m" ] && r=back || r=gone
  echo "round $round: unlink, then an append to another file and its fdatasync: the file is $r"
  rm -f "$mnt/m" "$mnt/written"; sync "$mnt"

  # 4j. Unlink, then an overwrite in place of another file (no new length,
  # no new block) and its fdatasync. The short pause lets the clock move,
  # so that the overwrite changes the file's time of modification.
  echo data > "$mnt/n"; echo 0123456789 > "$mnt/over"; sync
  sleep 0.2
  rm "$mnt/n"; printf XXXX | dd of="$mnt/over" conv=notrunc status=none; sync -d "$mnt/over"
  power_cut
  [ -e "$mnt/n" ] && r=back || r=gone
  echo "round $round: unlink, then an overwrite in place of another file and its fdatasync: the file is $r, the overwritten file holds $(head -c 4 "$mnt/over")"
  rm -f "$mnt/n" "$mnt/over"; sync "$mnt"

  # 4k. The same with fsync.
  echo data > "$mnt/o"; echo 0123456789 > "$mnt/over"; sync
  sleep 0.2
  rm "$mnt/o"; printf XXXX | dd of="$mnt/over" conv=notrunc status=none; sync "$mnt/over"
  power_cut
  [ -e "$mnt/o" ] && r=back || r=gone
  echo "round $round: unlink, then an overwrite in place of another file and its fsync: the file is $r, the overwritten file holds $(head -c 4 "$mnt/over")"
  rm -f "$mnt/o" "$mnt/over"; sync "$mnt"

  # 4n. As 4k without the pause, and with the other file written just
  # before: the overwrite may fall in the same tick of the kernel's clock
  # as the file's last change, and then changes nothing in its inode.
  echo data > "$mnt/r"; echo 0123456789 > "$mnt/over"; sync "$mnt/over"; sync "$mnt"
  rm "$mnt/r"; printf XXXX | dd of="$mnt/over" conv=notrunc status=none; sync "$mnt/over"
  power_cut
  [ -e "$mnt/r" ] && r=back || r=gone
  echo "round $round: the same at once after the file's last change: the file is $r, the overwritten file holds $(head -c 4 "$mnt/over")"
  rm -f "$mnt/r" "$mnt/over"; sync "$mnt"

  # 4l. As 4d with fdatasync: a rename changes nothing fdatasync must keep.
  echo data > "$mnt/p"; sync
  mv "$mnt/p" "$mnt/p2"; sync -d "$mnt/p2"
  power_cut
  if [ -e "$mnt/p2" ] && [ ! -e "$mnt/p" ]; then r="kept"; elif [ -e "$mnt/p" ] && [ ! -e "$mnt/p2" ]; then r="undone"; else r="mixed"; fi
  echo "round $round: a rename, then fdatasync of the renamed file: the rename is $r"
  rm -f "$mnt/p" "$mnt/p2"; sync "$mnt"

  # 4m. As 4c with fdatasync.
  echo data > "$mnt/q"; sync
  : > "$mnt/fresh"; rm "$mnt/q"; sync -d "$mnt/fresh"
  power_cut
  [ -e "$mnt/q" ] && r=back || r=gone
  [ -e "$mnt/fresh" ] && n=there || n=gone
  echo "round $round: a create, unlink, then fdatasync of the created file: the file is $r, the created file is $n"
  rm -f "$mnt/q" "$mnt/fresh"; sync "$mnt"

  # 4o. As 4n from one program (tight.c), with nothing between the calls.
  # It prints whether the file's last change and the overwrite fell within
  # one tick of the kernel's clock; with a commit between them they did
  # not, where this was run.
  echo data > "$mnt/victim"; sync
  tick="$("$work/tight" "$mnt" fsync)" || exit 1
  power_cut
  [ -e "$mnt/victim" ] && r=back || r=gone
  echo "round $round: one program: a file synced, unlink, an overwrite inside it and its fsync, at once ($tick): the file is $r, the overwritten file holds $(head -c 4 "$mnt/over")"
  rm -f "$mnt/victim" "$mnt/over"; sync "$mnt"

  # 4p. As 4f with an append of 16 KiB, which needs new blocks.
  echo data > "$mnt/s"; echo 0123456789 > "$mnt/grown"; echo other > "$mnt/carrier"; sync
  head -c 16384 /dev/zero >> "$mnt/grown"
  echo more >> "$mnt/carrier"; sync "$mnt/carrier"
  rm "$mnt/s"; sync "$mnt/grown"
  power_cut
  [ -e "$mnt/s" ] && r=back || r=gone
  echo "round $round: an append of 16 KiB, a commit, unlink, then the appended file's fsync: the file is $r, the appended file has $(stat -c %s "$mnt/grown") bytes"
  rm -f "$mnt/s" "$mnt/grown" "$mnt/carrier"; sync "$mnt"

  # 4q. Unlink, then a write into a hole of another file (no new length,
  # a new block) and its fdatasync.
  echo data > "$mnt/t"; truncate -s 1M "$mnt/holey"; sync
  sleep 0.2
  rm "$mnt/t"; printf XXXX | dd of="$mnt/holey" bs=4096 seek=10 conv=notrunc status=none; sync -d "$mnt/holey"
  power_cut
  [ -e "$mnt/t" ] && r=back || r=gone
  echo "round $round: unlink, then a write into a hole of another file and its fdatasync: the file is $r"
  rm -f "$mnt/t" "$mnt/holey"; sync "$mnt"

  # 4r. Unlink, then another file shortened and its fdatasync.
  echo data > "$mnt/u"; echo 0123456789 > "$mnt/short"; sync
  rm "$mnt/u"; truncate -s 4 "$mnt/short"; sync -d "$mnt/short"
  power_cut
  [ -e "$mnt/u" ] && r=back || r=gone
  echo "round $round: unlink, then another file shortened and its fdatasync: the file is $r, the shortened file has $(stat -c %s "$mnt/short") bytes"
  rm -f "$mnt/u" "$mnt/short"; sync "$mnt"

  # 5. SQLite: commit, acknowledgement, power cut, reopen.
  for mode in OFF FULL EXTRA; do
    db="$mnt/$mode.db"
    rm -f "$db" "$db-journal"; sync "$mnt"
    ack="$("$work/sqlite_commit" write "$mode" "$db")"
    [ "$ack" = acknowledged ] || { echo "write failed: $ack"; exit 1; }
    power_cut
    # Looked at before the check, which makes a missing database and
    # deletes a journal it rolls back.
    [ -e "$db-journal" ] && j="journal back" || j="no journal"
    if [ ! -e "$db" ]; then f="database file gone"; elif [ ! -s "$db" ]; then f="database file empty"; else f="database file there"; fi
    echo "round $round: sqlite synchronous=$mode: $("$work/sqlite_commit" check "$db") ($f, $j)"
  done
done
