# Security

## Reporting a vulnerability

Please report it privately, through GitHub's "Report a vulnerability"
button on this repository's Security tab, not in a public issue. Say what
you found, how to reproduce it, and which version or commit you used.

## What counts

TARDIS is a testing tool. It runs the code under test in the same process,
with the privileges of whoever runs the tests, and it does not sandbox that
code. A test body that does something harmful is not a vulnerability in
TARDIS.

These are:

- A file TARDIS reads (a replay token, an evidence bundle, a corpus entry)
  that makes it run code, write outside the directory it was given, or
  crash in a way an attacker could use.
- `tardis replay-evidence` accepting a bundle that was altered after it was
  signed.
- The security layer reporting a run as clean when one of its documented
  checks should have fired, where the miss is not among the limits the
  plans list (`plan2.md` §3.8, §4.5, §4.6, and each section's limits).

## What the evidence bundles do and do not prove

A bundle carries a hash tree over its files, and a signature only if the
campaign was given a key (the `key` option of `certify`). The hash tree shows that
the files belong together; the signature shows that they have not changed
since the holder of that key signed them. Neither shows on what machine
the campaign ran, or that the code tested is the code shipped. The key is
yours to create, keep and rotate: TARDIS does not store one. If a bundle
has to carry weight, sign it with a key your organisation controls and
keep the campaign's inputs with it.

TARDIS and `tardis_sec` are not certified or qualified under any standard
(`plan2.md` §1.1).
