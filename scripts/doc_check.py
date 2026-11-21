#!/usr/bin/env python3
"""Lists public declarations without a doc comment (plan3.md C4).

    python3 scripts/doc_check.py [file.zig ...]

With no arguments it checks the files that make up the API reference:
src/root.zig and the files a test author uses through it. A declaration
counts as documented when the line above it is a `///` comment (or an
attribute line under one). Fields of public structs are not checked: many
explain themselves. Exits with 1 if anything is listed.
"""
import re
import sys

DEFAULT = [
    "src/root.zig",
    "src/sim/atomic.zig",
    "src/check/lin.zig",
    "src/check/elle.zig",
    "src/check/ledger.zig",
    "src/search/fuzz.zig",
]
DECL = re.compile(r"^\s*pub (?:inline )?(?:fn|const|var) ([A-Za-z_][A-Za-z0-9_]*)")
# `pub const x = @import(...)` and plain aliases document themselves at the target.
ALIAS = re.compile(r"^\s*pub const [A-Za-z_][A-Za-z0-9_]* = (?:@import\(.*\)|[A-Za-z_][A-Za-z0-9_.]*);\s*$")


def undocumented(path):
    out = []
    lines = open(path, encoding="utf-8").read().splitlines()
    for i, line in enumerate(lines):
        m = DECL.match(line)
        if not m or ALIAS.match(line):
            continue
        above = lines[i - 1].strip() if i > 0 else ""
        if above.startswith("///"):
            continue
        out.append((i + 1, m.group(1)))
    return out


def main():
    paths = sys.argv[1:] or DEFAULT
    total = 0
    for p in paths:
        for line, name in undocumented(p):
            print(f"{p}:{line}: {name}")
            total += 1
    if total:
        print(f"{total} public declarations without a doc comment", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
