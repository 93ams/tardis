#!/usr/bin/env python3
"""Checks `zig build bench` output against scripts/bench_budgets.txt.

    zig build bench 2>&1 | python3 scripts/bench_check.py

Two kinds of check (plan3.md E1):

- exact: numbers that do not depend on the machine (how many executions a
  search made, what a failure shrank to, the iteration that found a bug).
  A change in one means the simulator decides differently than it did, and
  is either a bug or a deliberate change that updates the budget file.
- under: timings, in nanoseconds, against a budget several times what a
  developer machine measures, so that a shared CI runner passes and a
  change that makes something an order of magnitude slower does not.

Exit status 1 if any check fails or its line is missing from the output.
"""
import os
import re
import sys


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    output = sys.stdin.read()
    sys.stdout.write(output)
    lines = output.splitlines()
    failures = []
    checked = 0
    for raw in open(os.path.join(here, "bench_budgets.txt"), encoding="utf-8"):
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        kind, pattern, want = [part.strip() for part in raw.split("|")]
        regex = re.compile(pattern)
        match = None
        for line in lines:
            match = regex.search(line)
            if match:
                break
        if not match:
            failures.append(f"missing: no line matches {pattern!r}")
            continue
        checked += 1
        got = match.group(1)
        if kind == "exact":
            if got != want:
                failures.append(f"exact: {pattern!r} gave {got}, expected {want}")
        elif kind == "under":
            if int(got) > int(want):
                failures.append(f"under: {pattern!r} gave {got} ns, budget {want} ns")
        else:
            failures.append(f"bad budget line: {raw!r}")
    print(f"\nbench_check: {checked} checks, {len(failures)} failed")
    for failure in failures:
        print("bench_check: " + failure)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
