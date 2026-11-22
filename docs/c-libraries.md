# Testing a C library that does its own I/O

A C library opens, writes and syncs its files with system calls through
libc. It never sees an `Io`, so the default mode cannot bring it into the
simulation. System-call mode can, on Linux x86_64: it answers those calls
from the simulated filesystem, clock and network. This guide is what the
SQLite test (`test/sqlite.zig`) taught, for someone doing the same with
another library.

The README's ["Choosing a mode"](../README.md#choosing-a-mode) has the
table of what the mode simulates. Read its list of limits first: if the
library needs `mmap` of a file, `epoll`, pipes or real threads, stop there.

## 1. Build the library into the test

The library must be compiled into the test's executable, so that its calls
are made on the test's thread. A shared library the system provides works
the same way, but then the test runs whatever version is installed.

```zig
const mod = b.createModule(.{
    .root_source_file = b.path("test/sqlite.zig"),
    .target = target,
    .optimize = optimize,
    .imports = &.{.{ .name = "tardis", .module = tardis }},
    .link_libc = true,
});
mod.addCSourceFile(.{ .file = sqlite.path("sqlite3.c"), .flags = &.{"-DSQLITE_OMIT_LOAD_EXTENSION"} });
```

Nothing in the library is changed and it gets no shim: SQLite runs with its
own Unix VFS. The one flag only removes its use of `dlopen`.

The configuration that has been run is a static link against musl
(`-Dtarget=x86_64-linux-musl`). The emulation has code for glibc's ways of
making the same calls, and no C library has been run on glibc.

## 2. Write the body

Declare the library's functions and call them from the body. Ask for the
mode, and skip where it does not exist:

```zig
test "the acknowledged commit survives a power loss" {
    if (!tardis.syscall_mode_supported or !tardis.syscallModeAvailable()) return error.SkipZigTest;
    try tardis.check(testing.allocator, body, .{
        .mode = .syscalls,
        .personas = &.{ .linux_ext4, .linux_xfs, .posix_strict },
        .limits = .{ .fiber_stack_bytes = 1024 * 1024 },
    });
}
```

- **Paths.** A relative path, and an absolute one, are in the node's
  simulated filesystem, which starts empty in every run. `/proc`, `/sys`
  and `/dev` do not exist there, except `/dev/urandom`, whose bytes come
  from the run's seed.
- **Stack.** A task's stack is 256 KiB by default. A C library's parser
  or cache may want more: SQLite is given `fiber_stack_bytes` of 1 MiB.
- **Both ways in.** The body still has `env.io` and `env.dir`, on the same
  files. Write through the library and check the bytes through `env.dir`,
  or the other way round.
- **`posix_strict`.** Include it. It is the persona that assumes least of
  an `fsync`, and the other personas have promised more than a real ext4
  gives in one case (`docs/power-cut.md`).

## 3. Crash it

`env.crashAndReboot(.power_loss)` loses what the library had not made
durable, by the persona's rules, and closes every descriptor, as the end
of the process would. The library does not know: its handles are still in
memory, holding descriptors that are now closed.

So open the library's handle in a block, crash inside the block, and let
the handle be closed after the crash. The close then fails on its
descriptors and frees the memory, which is all it is wanted for:

```zig
{
    const db = try open();
    defer _ = sqlite3_close(db);
    try exec(db, "INSERT INTO kv VALUES(2, 'two')"); // acknowledged
    try env.crashAndReboot(.power_loss);
}
const db = try open(); // recovery runs here
```

Then state the property with `env.always`: what was acknowledged before
the crash is there after it.

## 4. Reset what the library keeps for the life of the process

A run must be a function of its seed. The simulator resets its own state
between runs; it cannot reset a C library's statics. SQLite seeds its
random number generator once, from `/dev/urandom`, so the second run of a
seed differed from the first, and `check`, which runs every sixteenth
iteration twice, failed with `error.NonDeterministic`.

The cure is the library's own reset, first thing in the body
(`sqlite3_randomness(0, null)` for SQLite). When `check` reports
`NonDeterministic` for a C library, look for state of this kind: a
generator, a cache, a counter, a table filled on first use.

## 5. Several tasks

A C library's locks work between tasks: a wait for a `pthread` mutex is a
`futex` call, which blocks the task and not the thread. Two tasks can each
drive their own database.

Every task runs on one thread, though, and that sets three limits:

- A **recursive mutex** belongs to the thread, so it does not keep a second
  task out. Do not share one SQLite connection between tasks, or anything
  else behind a recursive lock.
- **Thread-local storage** is shared by every task, `errno` included. A
  task must read `errno` before it makes another call that can let other
  tasks run.
- A task **dropped inside a library call**, by a crash or because the run
  ended, may leave the library's lock held or its state half changed, for
  the rest of the process. The run prints that it happened, with its seed,
  and later failure reports in the same `check` name that run as the
  likely cause when a failure does not come back on replay.

## 6. When the run fails with `StraySyscall`

The library made a call the mode does not answer. The report names the
call. The call was refused with `ENOSYS` and never reached the machine,
but the run proves nothing, so it fails whatever the body returned.

What to do depends on the call:

- A feature the library can do without: turn it off. SQLite's WAL mode
  maps a file into memory, which is not emulated; the default rollback
  journal needs no `mmap`.
- A call that asks about the real machine (a path under `/proc`, the
  number of processors): it is usually made once, on first use, and often
  has a compile-time or run-time switch.
- Anything else is a gap in the emulation. The list of what is answered is
  at the top of `src/sim/sysemu.zig` and `src/sim/sysnet.zig`.

## What has been run

One library: SQLite 3.46.0, `zig build test-sqlite -Dsqlite`, four tests.
With `synchronous=OFF` an acknowledged commit is lost to a power loss, and
the failure shrinks from 75 decisions to 1. With `EXTRA` it is kept. With
`FULL`, SQLite's default, it is lost too, which is SQLite's documented
behaviour and was then reproduced on a real ext4 (`docs/power-cut.md`).
Two tasks with a database each pass.

No library that uses the network has been run this way; the socket
emulation is tested with system calls written for the test.
