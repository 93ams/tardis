# Real threads

## The decision

TARDIS does not simulate operating-system threads, and will not map them
onto simulated tasks.

Code that starts a thread with `std.Thread.spawn`, or that does I/O
without going through the `std.Io` it was given, is outside the
simulation. The simulator does not schedule it, does not inject faults
into it, and cannot replay it. A run that contains such code is not made
deterministic: the same seed can give different results, and a replay
token may not bring a failure back.

This is `plan3.md` D5, decided as "document, do not map".

## Why

Every task of a run is a fiber on one thread. The simulator picks which
task runs next from the seed, and switches only at `std.Io` calls. That is
what makes a schedule something a seed can name.

A real thread is scheduled by the kernel, at any instruction, with timing
no seed controls. It shares memory with the tasks, and shared memory
between tasks is not modelled except through `tardis.atomic.Value`. Its
system calls go to the real kernel: the real clock, the real disk.

In the default mode nothing stops this. `std.Thread.spawn` inside a test
body starts a thread, the run goes on, and the report says nothing about
it unless one of the checks below is on.

## What to do instead

Write the code against `std.Io`, as the rest of the simulation asks:

- Take an `io: std.Io` parameter and pass it down. In a test it is
  `env.io`; in production it is whichever implementation you run on, and
  one backed by real threads gives you real threads there.
- Start work with `io.async(function, args)` and `await` the future, or
  with `io.concurrent` when the work must be able to run while the caller
  waits. Under TARDIS both make simulated tasks (`io.async` may also run
  the function at once, in the caller: `Options.async_inline_ppm`).
  `std.Io.Group` does the same for many tasks.
- Lock with `std.Io.Mutex` and wait with `std.Io.Condition`. Under TARDIS
  a task that waits for one is blocked, the others run, and a run where
  every task is blocked fails as a deadlock.
- For atomics that tasks share, use `tardis.atomic.Value(T)`. Its
  operations are scheduling points, so the interleavings around them are
  explored.
- For time, sleeping, random bytes, files and sockets, use `io`.

Then every interleaving the simulator can produce is one a seed names.

## Where tasks switch

The simulator switches tasks only at a scheduling point. Every `std.Io`
operation that can block or that the simulator models is one: a file or
socket operation, a sleep, `async`, `concurrent`, `await`, a group's
calls, `checkCancel`, a futex wait or wake. So is every operation of a
`tardis.atomic.Value`, and `tardis.yield()` (except in a thread the code
under test starts in system-call mode: there `tardis.yield()` does
nothing, and the thread switches at its system calls).

These are not:

- **An uncontended `std.Io.Mutex`.** `lock` is a compare-and-swap in the
  caller and reaches the `Io` only when the mutex is already held;
  `unlock` reaches it only when the lock has been contended (some task
  had to wait for it since it was last free). A lock taken and given
  back with no other task in the way is two atomic instructions the
  simulator never sees. (`std.Io.Condition.wait` always reaches it; `signal` and
  `broadcast` only when a task waits.)
- **`now`, `clockResolution`, `random` and `randomSecure`.** They are
  answered on the spot.
- **`std.atomic.Value`, plain memory, and anything else in the caller.**

Code whose tasks share memory under locks, with no file or network call
between, gives the simulator nowhere to switch: each task runs to its end
before the next starts, and a test of it passes while testing nothing.
The sign is a run of several tasks with few events in its trace, and a
`check` that passes says so:

```
tardis: warning: in 30 runs with the body and two or more other tasks, no task besides the body was switched away from before its end: each ran from its start to its end with no other task in between
```

It is printed when every run with the body and at least two other tasks
ran those others one after another, none of them stopping (to wait, or
switched away from) before its end while another ran. Daemons
(`Env.spawnOn`, chaos's healer and nemesis) are left out of both counts.
`Options.interleave_report` gives the counts. Forked iterations
(`Options.fork`) are not counted.

The warning is a floor, not a measure. One stop by one task in one run
silences it for the whole check: a worker that waits at a start gate, or
makes a single file or socket call outside its lock and is switched away
from there once, counts as interleaved, though its locked section still
runs from end to end every time. And the body's own steps are not
looked at: a body that yields between accesses the workers share still
gets the warning. A check that does not warn may still test nothing
between two lock holders. A
`tardis.yield()` where a switch could matter (after taking a lock, before
giving it back, between two accesses another task could come between)
gives the simulator the choice; so does `tardis.atomic.Value` for the
atomics.

More switch points are not always better for finding a bug. A user of
TARDIS whose bug needed one task to stay out while others did three
transactions found it in 1 to 37 seeds with three yields under the
random schedule, and needed about 1,500 when every lock and allocation
was a yield: with more points, a long stretch with no switch to one task
is less likely. The PCT schedule (`Options.schedule = .pct`), which
holds a task back by priority rather than at each point, found it in 4
to 26 either way. Run ordering tests under both.

## What tasks share

Every task of a run is a fiber on the one thread that runs the
simulation, so whatever belongs to a thread belongs to all of them:

- **The thread id.** `std.Thread.getCurrentId()` gives every task the
  same number. Code that keys something by it (a re-entrant lock's
  owner, a per-thread table) takes two tasks for one, under simulation
  only. `tardis.threadId()` gives each task its own number (and is
  `std.Thread.getCurrentId()` outside a simulation): use it where the
  code asks, or behind a seam the test sets. A run's first task has
  `0x2000_0000` and each task spawned the next, the same for a seed every
  time; the body of a `check` is the second task, while in the loop form
  (`tardis.sim`) it is the first, so the numbers differ by one between
  the two.
- **`threadlocal` variables.** One copy for every task, so state one task
  keeps in them is seen and changed by the others. TARDIS has no answer
  for this yet; keep such state in what the task is given.

In system-call mode a thread the code starts (`std.Thread.spawn`,
`pthread_create`) is a task with its own thread pointer, so it has its
own `threadlocal` variables and its own thread id from `gettid`.

Two things that look like exceptions and are not:

- `Options.workers` runs a campaign on several real threads. Each has its
  own simulator, and no run is shared between them. The result does not
  depend on the count.
- `Options.mode = .syscalls` answers the threads the code starts, but
  does not run them as real threads: each `clone` of a thread becomes a
  simulated task on the one real thread, and the seed decides when it
  runs (`src/sim/systhread.zig`). Tasks switch only at system calls, so
  a thread spinning on memory with no system call in the loop hangs the
  run, and a data race between two instructions is never explored. It
  needs Linux x86_64 with the FSGSBASE instructions (Linux 5.9); without
  them, starting a thread is a stray call.

If some code cannot take an `Io` and must start threads (a C library with
its own worker pool), system-call mode on Linux x86_64 runs those threads
as tasks, with the limits above. Elsewhere TARDIS cannot test its
concurrency: test the parts around it, and keep the threaded part behind
an interface the test can replace.

## What catches an escape

On Linux x86_64, with kernel 5.11 or later, the stray-system-call trap.
Turn it on for one check with `Options.trap_syscalls = true`, or for
every check of a test run with `TARDIS_TRAP_SYSCALLS=1`.

While a run is on, each system call made by the thread that runs the
simulation is intercepted. A call that the simulator and the test harness
do not make themselves is counted as stray. The call is then made as
usual, so the program goes on. When the run ends it fails with
`error.StraySyscall`, whatever else it did, and the report names the
first stray call, how many there were, the first one's arguments, and
where it was made from, in this form:

```
tardis: the code under test tried 1 real system call(s), the first one
getrandom (number 318): it left the simulation, so the run does not
depend on its seed alone
tardis: its first three arguments were 0x7cb90d977d00, 0x4, 0x0
tardis: it was made from:
.../lib/std/os/linux.zig:2195:20: 0x119df3e in getrandom (std.zig)
src/tests/syscall_test.zig:72:31: 0x129740e in strayFromHere (root.zig)
src/tests/syscall_test.zig:77:18: 0x12972d5 in strayCaller (root.zig)
...
```

The name is the kernel's for any x86_64 call number. The stack is unwound
from the call itself, so it shows the library function that made it and
who called that, up to sixteen frames; it is printed only for a call that
came through the trap (not for a clock read through the vDSO), and only
where the program has the tables to unwind it (and not when the stray call is `std.debug`'s own, made while it holds its lock).
The names come from the program's debug information, which is loaded
before the first run that traps, once per process (about a tenth of a
second for a large debug binary): in system-call mode the program's file
cannot be opened inside a run. So a stack printed inside a run, a
panic's, has them too.

**A call made once per process.** Some code asks the kernel something
the first time it needs it and keeps the answer for the rest of the
process. `std.heap.smp_allocator` and `std.testing.allocator` both ask
for the processor count (`sched_getaffinity`, number 204), the first
time two threads contend for them. Under the trap the run that happens to
ask first fails, and no later one does. In system-call mode the call is
answered from the simulation (`Options.processors`), but the answer is
still kept from whichever run asked first.

What it catches:

- Asking the kernel for anything through a system call: opening or
  reading a real file, a socket, `getrandom`, `nanosleep`, a clock read
  that is a real system call.
- Starting a thread or a process. `clone`, `clone3`, `fork` and `vfork`
  are not made at all (the other stray calls are made and counted; in
  system-call mode no stray call is made, and these get `ENOSYS` like
  the rest): the caller gets "try again" (`EAGAIN`), which
  `std.Thread.spawn` returns as `error.ThreadQuotaExceeded` without libc,
  and the run fails with `error.StraySyscall` and a line saying how many
  calls were refused. A thread
  begun from inside the trap's signal handler could not be left to run.
  Tested for `std.Thread.spawn` without libc (`syscall_test.zig`); with
  libc the call is libc's own, std maps the answer to
  `error.SystemResources`, and it has not been tried.

What it does not catch:

- **Threads that already exist.** The trap is set for the thread that
  runs the simulation. A thread that existed before the run began (a pool
  made outside the body) is not trapped, and its work is not seen.
- **Calls the harness makes too.** These are let through, whoever makes
  them: memory calls (`mmap`, `mprotect`, `munmap`, `brk`, `mremap`,
  `madvise`), `write` and `writev` to standard output and standard error,
  `fstat`, `ioctl` and `newfstatat` on the three standard descriptors,
  `futex`, the signal calls, `getpid`, `gettid`, `exit`, `exit_group`
  and `prctl`; and a signal to the calling thread (`tkill`, or `tgkill`
  with this process), as `abort` sends, or `kill` of this process with
  signal 0. So code that blocks on a real futex is not reported, and
  with every task on one thread it stops them all. A signal aimed
  anywhere else (another process, the process group, every process,
  another thread, or this process with a signal that any of its threads
  may take) is refused and fails the run, here too: it is not sent.
- **Clock reads through the vDSO.** `clock_gettime`, `gettimeofday` and
  `getcpu` are usually answered in user space and are not system calls.
  (System-call mode answers these from the simulation; the trap alone
  does not see them.)
- **`rdtsc`.** It is an instruction. `Options.virtual_tsc` answers it with
  virtual time.
- **Memory.** A thread or task that reads and writes shared memory makes
  no system call.
- **Runs where the trap is off.** It is ignored in forked iterations
  (`Options.fork`), in the loop form (`tardis.sim`), during a worker
  thread's setup, on a kernel without syscall user dispatch, and on every
  platform but Linux x86_64. `tardis.trap_syscalls_supported` says at
  compile time whether the platform has it.
- `TARDIS_TRAP_SYSCALLS` is read in test builds only, once per process,
  and only the value `1` turns the trap on.

The trap is an experimental feature ([stability.md](stability.md)).

One more check runs everywhere and is on by default: `check` runs every
16th iteration twice (`Options.determinism_check_every`) and fails with
`error.NonDeterministic` when the two traces differ. It can show that
something outside the simulation changed a run. It sees only differences
that reach the simulator's own events or the run's result, and only in
the iterations it repeats.

On Windows and macOS nothing else looks for an escape. Run the suite on
Linux x86_64 with `TARDIS_TRAP_SYSCALLS=1` once in a while if the code
under test might start threads or call the system directly.
