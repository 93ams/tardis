# Measurements

Two tables that the repository can print again at any time. Numbers in the
first follow from the seeds and are the same on every machine; the second
depends on the allocator's rounding and may move by a few kilobytes.

## 1. Which oracle catches which bug, and how often

`zig build bugbench-rates -Doptimize=ReleaseSafe` (`plan3.md` A5). Each
program in [`examples/`](../examples) has one class of bug planted. For
each, the table names the oracle that catches it and counts in how many of
20 campaigns, each with its own campaign seed, the bug was found, at three
campaign sizes. The command fails if a campaign of 200 iterations misses
any bug.

| Program | Bug class | Caught by | 10 iterations | 50 iterations | 200 iterations |
|---|---|---|---|---|---|
| `wal_kv` | acknowledged before durable | `always` | 20/20 | 20/20 | 20/20 |
| `dir_sync` | missing fsync of a directory | `always` | 19/20 | 20/20 | 20/20 |
| `rename_unsynced` | renamed before the data is durable | `always` | 20/20 | 20/20 | 20/20 |
| `in_place_rewrite` | a file rewritten in place | `always` | 18/20 | 20/20 | 20/20 |
| `index_before_data` | two files made durable in the wrong order | `always` | 20/20 | 20/20 | 20/20 |
| `id_reuse` | identifier handed out twice after a restart | `always` | 20/20 | 20/20 | 20/20 |
| `jobs` | applied twice after a restart | `always` | 20/20 | 20/20 | 20/20 |
| `short_write` | short write taken for a whole one | `always` | 11/20 | 20/20 | 20/20 |
| `short_read` | short read taken for a whole one | `always` | 13/20 | 19/20 | 20/20 |
| `error_leak` | resource leaked on an error path | leak check | 11/20 | 20/20 | 20/20 |
| `oom_partial` | half-finished update when memory runs out | `always` | 7/20 | 18/20 | 20/20 |
| `counter` | lost update between tasks | `always` | 20/20 | 20/20 | 20/20 |
| `check_then_act` | check, then act | `always` | 19/20 | 20/20 | 20/20 |
| `deadlock` | deadlock from lock order | deadlock | 20/20 | 20/20 | 20/20 |
| `livelock` | livelock from retrying in step | `expectProgress` | 19/20 | 20/20 | 20/20 |
| `hidden_state` | state that survives a run | determinism check | 20/20 | 20/20 | 20/20 |
| `never_retried` | code the test never reaches | `sometimes` | 20/20 | 20/20 | 20/20 |
| `lease` | a duration measured with the wall clock | `always` | 20/20 | 20/20 | 20/20 |
| `udp_retry` | a retry applied twice | `always` | 20/20 | 20/20 | 20/20 |
| `udp_order` | trusting the order of arrival | `always` | 20/20 | 20/20 | 20/20 |
| `udp_no_timeout` | waiting for ever for a lost message | deadlock | 20/20 | 20/20 | 20/20 |
| `stale_read` | a stale read from a follower | `always` | 20/20 | 20/20 | 20/20 |
| `replica` | replica left behind by a partition | `always` | 20/20 | 20/20 | 20/20 |

Measured on Windows at revision 85. `syscall_rename` (system-call mode,
Linux on x86_64) is not in this run; its bug is caught by `always`.

How to read it:

- The bugs that need a fault at the right moment (a short transfer, an
  allocation that fails, an I/O error on one path) are the ones a campaign
  of 10 iterations can miss. The default campaign is 100.
- These oracles have a row: `always`, `sometimes`, the deadlock and
  livelock detectors, the leak check and the determinism check.
- No row yet: the stray-system-call trap (Linux; its tests are in
  `syscall_test.zig`).
- Not in the table: the linearizability and transaction-anomaly checkers
  (`tardis.lin`, `tardis.elle`). They judge recorded histories, and their
  tests feed them histories with known verdicts (`lin_test.zig`,
  `elle_test.zig`); no example program plants a bug for them yet. The
  security layer has its own campaigns (`zig build evidence`).

## 2. Memory one simulator takes

`zig build membench` (`plan3.md` E3). Each row runs a one-iteration
campaign of a small body (one file, one allocation) through an allocator
that counts, and prints the most that was live at once, the fiber stack
reservation and the largest single allocations. The first of those:

| Options | Most memory live at once |
|---|---|
| defaults (`.{}`) | 2.4 MiB |
| `nodes = 3` | 4.8 MiB |
| `nodes = 8` | 10.6 MiB |
| `limits.tasks_max = 1024` | 4.7 MiB |
| `explore = .guided` | 2.7 MiB |
| `workers = 4` (four simulators and the caller's) | 12.2 MiB |
| `limits.trace_ring_len = 4096` | 2.8 MiB |
| security layer (`tardis_sec`, its defaults) | 3.2 MiB |
| security layer with `shadow_memory` | 11.3 MiB |
| security layer with `data_races` | 5.0 MiB |

Measured on Windows at revision 85.

What the numbers are made of:

- **Per node, about 1.2 MiB:** two tables of 256 KiB that map each file's
  pages (`limits.vfs.inodes_max` times `file_pages_max`), the directory
  entries, and the first 256 KiB chunk of the page pool. The pool grows by
  one chunk when a run first needs a page of it, up to
  `limits.vfs.pages_max` (8 MiB by default), and keeps what the fullest
  run of the campaign used. Before revision 84 every node took the whole
  8 MiB at the start: 10.2 MiB for the defaults and 72.6 MiB for 8 nodes.
- **Once, 1 MiB:** the network's receive buffers (`limits.net.sockets_max`
  times `rx_buffer_bytes`), whether or not the test opens a socket.
- **Fiber stacks are not in the count.** They are reserved address space,
  `limits.tasks_max` times `limits.fiber_stack_bytes` (16 MiB by default,
  256 MiB with 1024 tasks), and only the pages a task touches become
  memory.
- **The security layer's large tables are behind their options:** 8 MiB of
  shadow for `shadow_memory`, about 2 MiB for `data_races`. Neither is
  allocated otherwise.
- The files a test writes, `env.allocator` (up to
  `limits.heap_bytes_max`) and a guided corpus come on top, as the test
  uses them.
