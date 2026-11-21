#!/usr/bin/env bash
# Checks that the package can be fetched and used from a fresh project
# (plan3.md B2), without the network:
#
#     scripts/package_check.sh
#
# It packs the committed tree (HEAD; uncommitted changes are not in it)
# into an archive, makes an empty project in a temporary directory, runs
# `zig fetch --save` on the archive, gives the project's test the `tardis`
# module the way docs/tutorial.md says, and runs examples/wal_kv.zig there
# as that test. The project has a package cache of its own, empty at the
# start. The check fails if the fetch, the build or the test fails, or if
# anything but the library ends up in that cache: a package that imports
# the library must never fetch the library's own dependencies (termancy,
# SQLite).
#
# What it does not check: the fetch from GitHub by URL, which needs the
# repository to be public and reachable; the archive stands in for it.
#
# ZIG names the compiler (default: zig). Everything is built in the
# temporary directory, so the first build there compiles the build runner
# again (a minute or two), and nothing is left behind.
set -u
cd "$(dirname "$0")/.." || exit 1
ZIG="${ZIG:-zig}"
root="$(pwd)"

work="$(mktemp -d)" || exit 1
trap 'cd "$root" && rm -rf "$work"' EXIT
export ZIG_GLOBAL_CACHE_DIR="$work/cache"
fail() {
  echo "package check: $1" >&2
  exit 1
}

git archive --format=tar.gz --prefix=tardis/ -o "$work/tardis.tar.gz" HEAD || fail "could not pack HEAD"

mkdir -p "$work/app/src" || fail "could not make the project"
cd "$work/app" || exit 1
cp "$root/examples/wal_kv.zig" src/wal_kv.zig || fail "could not copy the example"
cat > build.zig.zon <<'EOF'
.{
    .name = .app,
    .version = "0.0.0",
    .fingerprint = 0xc96e70cff04b69c7,
    .minimum_zig_version = "0.17.0",
    .dependencies = .{},
    .paths = .{ "build.zig", "build.zig.zon", "src" },
}
EOF
cat > build.zig <<'EOF'
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/wal_kv.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    // The two lines of docs/tutorial.md, step 1.
    const tardis = b.dependency("tardis", .{ .target = target, .optimize = optimize });
    tests.root_module.addImport("tardis", tardis.module("tardis"));
    b.step("test", "Run the test").dependOn(&b.addRunArtifact(tests).step);
}
EOF

"$ZIG" fetch --save "$work/tardis.tar.gz" > fetch.log 2>&1 || {
  cat fetch.log >&2
  fail "zig fetch --save failed"
}
grep -q '\.tardis = ' build.zig.zon || fail "zig fetch --save did not add the dependency under the name tardis"

"$ZIG" build test --summary all > build.log 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then
  cat build.log >&2
  fail "the fresh project's test did not build or pass"
fi
packages="$(ls "$work/cache/p" 2>/dev/null | wc -l)"
if [ "$packages" -ne 1 ]; then
  ls "$work/cache/p" >&2
  fail "the project's package cache holds $packages packages, not the library alone"
fi
grep -E "Build Summary" build.log
echo "package check: a fresh project fetched the package and ran examples/wal_kv.zig against it"
