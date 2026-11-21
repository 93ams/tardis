# Measurements

Four tables that the repository can print again at any time. Numbers in
the first, the third and the fourth follow from the seeds and are the
same on every machine; the second depends on the allocator's rounding and
may move by a few kilobytes.

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
| `lin_register` | a compare-and-swap that is not atomic | `tardis.lin` | 13/20 | 19/20 | 20/20 |
| `write_skew` | write skew between transactions | `tardis.elle` | 20/20 | 20/20 | 20/20 |
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

Measured on Windows at revision 87. `syscall_rename` (system-call mode,
Linux on x86_64) is not in this run; its bug is caught by `always`.

How to read it:

- The bugs that need a fault at the right moment (a short transfer, an
  allocation that fails, an I/O error on one path) are the ones a campaign
  of 10 iterations can miss. The default campaign is 100.
- These oracles have a row: `always`, `sometimes`, the deadlock and
  livelock detectors, the leak check, the determinism check, and the two
  history checkers (`tardis.lin`, `tardis.elle`).
- No row yet: the stray-system-call trap (Linux; its tests are in
  `syscall_test.zig`).
- Not in the table: the security layer's oracles, which have their own
  campaigns (`zig build evidence`).

## 2. Memory one simulator takes

`zig build membench` (`plan3.md` E3). Each row runs a one-iteration
campaign of a small body (one file, one allocation) through an allocator
that counts, and prints the most that was live at once, the fiber stack
reservation and the largest single allocations. The first of those:

| Options | Most memory live at once |
|---|---|
| defaults (`.{}`) | 1.4 MiB |
| `nodes = 3` | 3.8 MiB |
| `nodes = 8` | 9.6 MiB |
| `nodes = 32` (the most there can be) | 37.6 MiB |
| `limits.tasks_max = 1024` | 3.7 MiB |
| `explore = .guided` | 1.7 MiB |
| `workers = 4` (four simulators and the caller's) | 7.2 MiB |
| `limits.trace_ring_len = 4096` | 1.8 MiB |
| security layer (`tardis_sec`, its defaults) | 2.2 MiB |
| security layer with `shadow_memory` | 10.3 MiB |
| security layer with `data_races` | 4.0 MiB |

Measured on Windows at revision 86.

What the numbers are made of:

- **Per node, about 1.2 MiB:** two tables of 256 KiB that map each file's
  pages (`limits.vfs.inodes_max` times `file_pages_max`), the directory
  entries, and the first 256 KiB chunk of the page pool. The pool grows by
  one chunk when a run first needs a page of it, up to
  `limits.vfs.pages_max` (8 MiB by default), and keeps what the fullest
  run of the campaign used. Before revision 84 every node took the whole
  8 MiB at the start: 10.2 MiB for the defaults and 72.6 MiB for 8 nodes.
- **Once, 1 MiB, from the first socket:** the network's receive buffers
  (`limits.net.sockets_max` times `rx_buffer_bytes`). The benchmark's body
  opens no socket, so the table does not include them. Before revision 86
  they were allocated at the start (a default simulator took 2.4 MiB).
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

## 3. What each part of the exploration contributes

`zig build bugbench-baselines -Doptimize=ReleaseSafe` (`plan3.md` F2).
Each program runs the campaign of its own options four times, and a cell
says whether the bug was found. A campaign counts only if the fixed
program passes the same one.

- **No faults:** schedules are explored and nothing is injected. Every
  rate in `Options.faults` is zero, the ones the example sets included;
  file operations take no modeled time; a power loss neither tears a file
  nor loses metadata; `net.blackhole_ppm` is zero.
- **No preemption:** faults are injected, `preempt_ppm = 0` and
  `async_inline_ppm = 0`. A task is never switched out at a call that
  does not block. When a task does block (a lock, a sleep, a socket, the
  modeled time of a file operation) the scheduler still draws the next
  one among those that can run.
- **Neither:** both at once.
- **Default:** the campaign as the example asks for it. The last column is
  its failing run: decisions before shrinking and after.

No option takes away what an example's body does itself. The second
column names it, and the fault rates the example's options set. A power
loss the body calls still keeps or drops each unsynced file's data, whole,
by a draw, in every column. The inputs a body draws with `env.fuzz` and
the network's latency are drawn in every column too.

| Program | The example's own trouble | No faults | No preemption | Neither | Default | Failing run of the default |
|---|---|---|---|---|---|---|
| `wal_kv` | power loss | yes | yes | yes | yes | 52 -> 3 decisions |
| `dir_sync` | power loss | no | yes | no | yes | 13 -> 2 decisions |
| `rename_unsynced` | power loss | yes | yes | yes | yes | 25 -> 1 decisions |
| `syscall_rename` | not run: no system-call mode on this system | | | | | |
| `in_place_rewrite` | an I/O error on a write it chooses, power loss | yes | yes | yes | yes | 15 -> 0 decisions |
| `index_before_data` | power loss | yes | yes | yes | yes | 86 -> 3 decisions |
| `id_reuse` | power loss | yes | yes | yes | yes | 34 -> 2 decisions |
| `jobs` | power loss | yes | yes | yes | yes | 112 -> 1 decisions |
| `short_write` |  | no | yes | no | yes | 22 -> 2 decisions |
| `short_read` |  | no | yes | no | yes | 19 -> 2 decisions |
| `error_leak` | `io_error_ppm = 50000` | no | yes | no | yes | 28 -> 4 decisions |
| `oom_partial` | `oom_ppm = 100000` | no | yes | no | yes | 14 -> 2 decisions |
| `counter` |  | yes | yes | no | yes | 41 -> 1 decisions |
| `check_then_act` |  | yes | no | no | yes | 27 -> 4 decisions |
| `lin_register` |  | yes | yes | no | yes | 63 -> 2 decisions |
| `write_skew` |  | yes | yes | no | yes | 25 -> 1 decisions |
| `deadlock` | a sleep while holding one lock | yes | yes | yes | yes | 18 -> 0 decisions |
| `livelock` | sleeps while holding one lock | yes | yes | yes | yes | 521 -> 1 decisions |
| `hidden_state` |  | yes | yes | yes | yes | not shrunk |
| `never_retried` | `io_error_ppm = 100000` | no: the fix fails too | yes | no: the fix fails too | yes | not shrunk |
| `lease` | a step of the wall clock | yes | yes | yes | yes | 16 -> 1 decisions |
| `udp_retry` | `datagram_loss_ppm = 200000`, `datagram_duplicate_ppm = 0` | no | yes | no | yes | 96 -> 1 decisions |
| `udp_order` | `datagram_loss_ppm = 0`, `datagram_duplicate_ppm = 300000` | yes | yes | yes | yes | 30 -> 1 decisions |
| `udp_no_timeout` | `datagram_loss_ppm = 150000`, `datagram_duplicate_ppm = 0` | no | yes | no | yes | 22 -> 1 decisions |
| `stale_read` |  | yes | yes | yes | yes | not shrunk |
| `replica` | a partition | yes | yes | yes | yes | not shrunk |

Measured on Windows at revision 89. `syscall_rename` (system-call mode,
Linux on x86_64) is not in this run.

How to read it:

- **Bugs that need a fault** are the ones with "no" under "No faults":
  metadata lost in a power loss (`dir_sync`), a short transfer
  (`short_write`, `short_read`), an I/O error (`error_leak`), an
  allocation that fails (`oom_partial`), a datagram lost (`udp_retry`,
  `udp_no_timeout`). `never_retried` belongs here as well: its `sometimes`
  needs an I/O error, so without faults the fixed program fails it too and
  the campaign tells nothing apart.
- **Bugs that need schedule exploration** are `check_then_act`, `counter`,
  `lin_register` and `write_skew`: found with no faults, not found with
  neither. Only `check_then_act` needs preemption as such. The other
  three are still found with `preempt_ppm = 0`, because each file
  operation's modeled time is a point where a task blocks and the
  scheduler draws; take that away too and they pass.
- **Bugs that need neither** are the rest. Six need only the power loss
  their test calls and the draw of what unsynced data it keeps (`wal_kv`,
  `rename_unsynced`, `in_place_rewrite`, `index_before_data`, `id_reuse`,
  `jobs`). `deadlock` and `livelock` sleep while holding a lock, and the
  draw among the tasks that can run when one blocks is enough. `lease`
  steps the clock itself, `replica` partitions the network itself, and
  `udp_order` and `stale_read` are found with what is still drawn in
  that column (the network's latency, the task that runs when one
  blocks). `hidden_state` is caught by running a seed twice.
- Of those, `in_place_rewrite`, `deadlock` and `replica` fail in a plain
  run as well (`zig build bugbench`); the first two shrink to 0 decisions.
- The default campaign finds every bug, and the command fails if it does
  not. `hidden_state` and `never_retried` are not shrunk because their
  failure is not one run's; `stale_read` and `replica` turn shrinking off.

Zig's built-in fuzzer is not run as a baseline. `std.testing.fuzz` hands
the test a `std.testing.Smith` and chooses the values the test draws from
it, so what it drives is a program's input. Which task runs next, whether
a write is short and what a power loss keeps are decided by the `std.Io`
the test uses, which the fuzzer does not supply. A test binary that is
not built in fuzz mode runs only the corpus the test passes.

## 4. Switching tasks at random, or by priority

`zig build bugbench-schedules -Doptimize=ReleaseSafe` (`plan3.md` E5).
`Options.schedule` chooses how the next task is picked:

- **`.random`** (the default): at each simulated operation, with
  probability `preempt_ppm` (a quarter), the next task is drawn again,
  uniformly among those that can run, the current one included. With two
  tasks that is a switch at one operation in eight.
- **`.pct`**: priorities, after PCT (Burckhardt, Kothari, Musuvathi and
  Nagarakatte, ASPLOS 2010). Each task gets a random priority when it
  starts, and the runnable task with the highest one always runs. At
  `pct_depth - 1` steps of the run, drawn at its start, the running task
  drops below the others. Depth 1 changes nothing during a run: each run
  is one order of the tasks. A task stops only where it blocks, at a
  change point, when a task above it becomes runnable, or when a task
  below it has waited more than 4,096 steps.

Each cell is the number of campaigns, of 20 with different seeds, that
found the program's bug, at 10 and at 50 iterations. Only the failure a
campaign of the usual size finds is counted. Everything but the schedule
is as the example asks for it. The last column is the fixed program under
priorities at depth 3, at the usual size: a schedule must not fail a
correct program.

| Program | random, 10 | random, 50 | pct 1, 10 | pct 1, 50 | pct 2, 10 | pct 2, 50 | pct 3, 10 | pct 3, 50 | The fix under pct 3 |
|---|---|---|---|---|---|---|---|---|---|
| `wal_kv` | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | passes |
| `dir_sync` | 19/20 | 20/20 | 19/20 | 20/20 | 19/20 | 20/20 | 19/20 | 20/20 | passes |
| `rename_unsynced` | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | passes |
| `syscall_rename` | not run: no system-call mode on this system | | | | | | | | |
| `in_place_rewrite` | 18/20 | 20/20 | 18/20 | 20/20 | 18/20 | 20/20 | 18/20 | 20/20 | passes |
| `index_before_data` | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | passes |
| `id_reuse` | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | passes |
| `jobs` | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | passes |
| `short_write` | 11/20 | 20/20 | 11/20 | 20/20 | 11/20 | 20/20 | 11/20 | 20/20 | passes |
| `short_read` | 13/20 | 19/20 | 13/20 | 19/20 | 13/20 | 19/20 | 13/20 | 19/20 | passes |
| `error_leak` | 11/20 | 20/20 | 11/20 | 20/20 | 11/20 | 20/20 | 11/20 | 20/20 | passes |
| `oom_partial` | 7/20 | 18/20 | 7/20 | 18/20 | 7/20 | 18/20 | 7/20 | 18/20 | passes |
| `counter` | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | passes |
| `check_then_act` | 19/20 | 20/20 | 0/20 | 0/20 | 1/20 | 9/20 | 3/20 | 13/20 | passes |
| `lin_register` | 13/20 | 19/20 | 1/20 | 7/20 | 1/20 | 9/20 | 1/20 | 12/20 | passes |
| `write_skew` | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | passes |
| `deadlock` | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | passes |
| `livelock` | 19/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | passes |
| `hidden_state` | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | passes |
| `never_retried` | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | passes |
| `lease` | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | passes |
| `udp_retry` | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | passes |
| `udp_order` | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | passes |
| `udp_no_timeout` | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | passes |
| `stale_read` | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | passes |
| `replica` | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | passes |
| `(one long stretch)` | 0/20 | 1/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | 20/20 | |
| `(many short stretches)` | 20/20 | 20/20 | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 | |

The last two rows are not examples. They are in the benchmark's own
source (`src/cmd/bugbench/main.zig`), two tasks and one assertion each,
with no faults: in the first the bug shows when one task does all forty of
its operations while the other does its one; in the second, when the two
tasks have taken turns twelve times.

What the table says:

- **Most of the benchmark does not care.** Twenty-two of the 25 programs
  that run give the same count in every column: their bugs come from a
  fault, a power loss or the network, or from an order that a task
  blocking is enough to reach.
- **Bugs that need a switch at one exact place are found sooner at
  random.** `check_then_act` and `lin_register` need a task stopped
  between two particular operations. Under `.random` every operation may
  be such a stop; under `.pct` a run has at most two, at steps drawn from
  a length the run does not know in advance. At depth 1 there are none,
  and `check_then_act` is never found.
- **Bugs that need a long stretch are found only by priority.** One task
  running forty operations without the other starting has a chance near
  one in two under `.pct`, and about one in a thousand runs under
  `.random`: 1 campaign of 20 at 50 iterations.
- **Bugs that need many switches are found only at random.** Twelve
  alternations in one run are out of reach of two priority changes.

**The recommendation: `.random` stays the default.** On the bugs people
planted here it is never worse by more than one campaign in twenty
(`livelock` at 10 iterations), and it is far better on two. `.pct` is
for a suspicion of the first shape: a starved task, a queue that fills
because its reader never runs, a timeout that fires only if something
else runs for a long time. A nightly campaign can run both, as two checks
of the same body.

Limits: the two shapes were written to tell the schedules apart, so they
say what each can do, not how often such bugs occur; the examples are
small (two to four tasks, tens of operations), and PCT's guarantee is
about depth, which matters more as programs grow; `pct_steps` was left at
0, where each run draws a length from 16 to 16,384, and a length close to
the run's own would place the change points better.

Measured on Windows at revision 90.
