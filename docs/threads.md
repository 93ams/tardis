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

Two things that look like exceptions and are not:

- `Options.workers` runs a campaign on several real threads. Each has its
  own simulator, and no run is shared between them. The result does not
  depend on the count.
- `Options.mode = .syscalls` lets code make its own system calls. It does
  not add threads: every task still runs on one thread, and creating a
  thread is not among the calls it answers.

If some code cannot take an `Io` and must start threads (a C library with
its own worker pool), TARDIS cannot test its concurrency. Test the parts
around it, and keep the threaded part behind an interface the test can
replace.

## What catches an escape

On Linux x86_64, with kernel 5.11 or later, the stray-system-call trap.
Turn it on for one check with `Options.trap_syscalls = true`, or for
every check of a test run with `TARDIS_TRAP_SYSCALLS=1`.

While a run is on, each system call made by the thread that runs the
simulation is intercepted. A call that the simulator and the test harness
do not make themselves is counted as stray. The call is then made as
usual, so the program goes on. When the run ends it fails with
`error.StraySyscall`, whatever else it did, and the report names the
first stray call and how many there were, in this form:

```
tardis: the code under test made 1 real system call(s), the first one
getrandom (number 318): it left the simulation, so the run does not
depend on its seed alone
```

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
  `futex`, the signal calls, `getpid`, `gettid`, `kill`, `tgkill`, `exit`,
  `exit_group` and `prctl`. So code that blocks on a real futex is not
  reported, and with every task on one thread it stops them all.
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
