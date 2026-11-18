#!/usr/bin/env bash
# The local verification pass: formatting, the whole suite in the four
# build modes, and once more with the security layer attached to every
# check. `-j2` keeps the machine usable while it runs. CI
# (.github/workflows/test.yml) runs the suite on Linux, macOS and Windows.
set -u
cd "$(dirname "$0")/.." || exit 1
ZIG="${ZIG:-zig}"
failed=0
"$ZIG" fmt --check src build.zig || failed=1
for mode in Debug ReleaseSafe ReleaseFast ReleaseSmall; do
  echo "== $mode"
  "$ZIG" build test -j2 -Doptimize="$mode" --summary all 2>&1 | grep -E "Build Summary|error:|failed" || true
  [ "${PIPESTATUS[0]}" -eq 0 ] || failed=1
done
echo "== -Dsec"
"$ZIG" build test -j2 -Dsec --summary all 2>&1 | grep -E "Build Summary|error:|failed" || true
[ "${PIPESTATUS[0]}" -eq 0 ] || failed=1
exit "$failed"
