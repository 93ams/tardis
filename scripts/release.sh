#!/usr/bin/env bash
# A release in one command (plan3.md B7):
#
#     scripts/release.sh 0.1.0            # verify, write notes, commit, tag
#     scripts/release.sh 0.1.0 --dry-run  # verify and write notes only
#
# It checks that the working tree is clean, sets the version in
# build.zig.zon, runs the full local verification (scripts/verify.sh), the
# bug benchmark (a planted bug that is missed fails the release), the
# benchmark budgets and the API reference build, writes the release notes
# (the CHANGELOG entries since the last release tag) to
# zig-out/release/notes-<version>.md, commits the version and makes the
# annotated tag v<version>.
#
# It never pushes. Publishing is the last line it prints, for a person to
# run. If a check fails or the script is interrupted, nothing is committed
# or tagged and build.zig.zon is put back. (If only the last step, the tag,
# fails, the version commit exists and the script says how to undo it.)
#
# ZIG names the compiler (default: zig). SKIP_VERIFY=1 skips the long
# verification, for trying the script itself; it then refuses to tag.
set -u
cd "$(dirname "$0")/.." || exit 1
ZIG="${ZIG:-zig}"

version="${1:-}"
dry_run=0
case "${2:-}" in
  "") ;;
  --dry-run) dry_run=1 ;;
  *) version="" ;; # an option this script does not know: do nothing
esac
if [ "$#" -gt 2 ] || ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; then
  echo "usage: scripts/release.sh <major.minor.patch> [--dry-run]" >&2
  exit 2
fi
tag="v$version"

if [ -n "$(git status --porcelain)" ]; then
  echo "release: the working tree has uncommitted changes; commit or stash them first" >&2
  exit 1
fi
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  echo "release: the tag $tag already exists" >&2
  exit 1
fi
if [ "${SKIP_VERIFY:-0}" = "1" ] && [ "$dry_run" = "0" ]; then
  echo "release: SKIP_VERIFY=1 is for --dry-run only" >&2
  exit 1
fi

# Back to the committed build.zig.zon, in the index and in the tree.
restore() { git checkout -q HEAD -- build.zig.zon; }
trap 'echo "release: interrupted; nothing was committed or tagged" >&2; restore; exit 130' INT TERM
fail() {
  echo "release: $1; nothing was committed or tagged" >&2
  restore
  exit 1
}

# The version, where the package manager reads it.
sed -i.bak -E "s/^([[:space:]]*\.version = \")[^\"]*(\",)/\1$version\2/" build.zig.zon && rm -f build.zig.zon.bak
grep -q "\.version = \"$version\"," build.zig.zon || fail "could not set the version in build.zig.zon"

if [ "${SKIP_VERIFY:-0}" != "1" ]; then
  echo "== verification (formatting, four build modes, -Dsec)"
  ZIG="$ZIG" bash scripts/verify.sh || fail "the verification failed"
  echo "== bug benchmark"
  "$ZIG" build bugbench -Doptimize=ReleaseSafe || fail "the bug benchmark missed a planted bug, or a fix failed"
  echo "== benchmark budgets"
  (set -o pipefail; "$ZIG" build bench 2>&1 | python3 scripts/bench_check.py) || fail "a benchmark failed or is over its budget"
  echo "== API reference"
  "$ZIG" build docs || fail "the API reference did not build"
fi

# Release notes: the CHANGELOG entries newer than the last release's.
last_tag="$(git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || true)"
last_revision=0
if [ -n "$last_tag" ]; then
  last_revision="$(git show "$last_tag:CHANGELOG.md" | sed -n -E 's/^## Revision ([0-9]+).*/\1/p' | head -1)"
  last_revision="${last_revision:-0}"
fi
mkdir -p zig-out/release
notes="zig-out/release/notes-$version.md"
{
  echo "# TARDIS $version"
  echo
  if [ -n "$last_tag" ]; then echo "Changes since $last_tag."; else echo "The first release."; fi
  echo
  awk -v last="$last_revision" '
    /^## Revision [0-9]+/ { n = $3 + 0; keep = (n > last) }
    keep { print }
  ' CHANGELOG.md
} > "$notes"
entries="$(grep -c '^## Revision' "$notes")"
[ "$entries" -gt 0 ] || fail "the CHANGELOG has no entry newer than $last_tag"
echo "release: notes for $entries revisions in $notes"

if [ "$dry_run" = "1" ]; then
  restore
  echo "release: dry run; no commit, no tag"
  exit 0
fi

git add build.zig.zon || fail "could not stage build.zig.zon"
if ! git diff --cached --quiet; then
  git commit -q -m "Release $tag" || fail "could not commit the version"
fi
trap - INT TERM
git tag -a "$tag" -F "$notes" --cleanup=verbatim || {
  echo "release: could not make the tag $tag; the commit \"Release $tag\" is made and can be tagged by hand or undone with: git reset --hard HEAD~1" >&2
  exit 1
}
echo "release: committed and tagged $tag. To publish:"
echo "    git push origin HEAD && git push origin $tag"
