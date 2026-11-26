# Testing a C library that does its own I/O

A C library opens, writes and syncs its files with system calls through
libc. It never sees an `Io`, so the default mode cannot bring it into the
simulation. System-call mode can, on Linux x86_64: it answers those calls
from the simulated filesystem, clock and network. This guide is what the
SQLite test (`test/sqlite.zig`) taught, for someone doing the same with
another library.

The README's ["Choosing a mode"](../README.md#choosing-a-mode) has the
table of what the mode simulates. Read its list of limits first: if the
library needs `select` or `fork`, stop there.

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

The configuration that has been run most is a static link against musl
(`-Dtarget=x86_64-linux-musl`). SQLite, the C++ program and the Rust
crate have also been run on glibc 2.41, linked dynamically
(`-Dtarget=x86_64-linux-gnu`).

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
  from the run's seed, and the links `/proc/self/fd/N` of simulated
  descriptors, which name their files (`realpath` of an open file reads
  them).
- **Stack.** A task's stack is 256 KiB by default. A C library's parser
  or cache may want more: SQLite is given `fiber_stack_bytes` of 1 MiB.
- **Both ways in.** The body still has `env.io` and `env.dir`, on the same
  files. Write through the library and check the bytes through `env.dir`,
  or the other way round.
- **`posix_strict`.** Include it. It is the persona that assumes least of
  an `fsync`, and another persona has already promised more than the real
  filesystem gives in one case, corrected since (`docs/power-cut.md`,
  which also lists what the rule still does not cover).

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

The report says where to look: under the two hashes it prints the first
event at which the two runs differ, and the four before it.

```
tardis: the two runs agree for 2 events (virtual time, task, event):
    0.000000000s  t0   spawn         1 0 0
    0.000000000s  t1   switch_to     0 1 0
  first run:   0.000000000s  t1   random        8 0 0
  second run:  0.000000000s  t1   spawn         2 0 0
```

That one is glibc, which draws eight random bytes when a process starts
its first thread. It has no reset to call, and the tool now takes care
of it: a run in system-call mode starts one real thread first. Where a
library of yours has once-only work and no reset, set `.prime = true`
in the options: the body is run once first, inside the simulation, and
that run is thrown away. (Calling the code once outside `check` does the
work against the real machine, which is right only for code that makes
no system call.)

## 5. Several tasks, and threads

A C library's locks work between tasks: a wait for a `pthread` mutex is a
`futex` call, which blocks the task and not the thread.

There are two ways to run the library from more than one place at once.

**Threads the code starts itself** (`pthread_create`, or `std.Thread.spawn`
in the test) are the faithful way. Each becomes a simulated task with its
own stack and its own thread pointer, so `errno`, thread-local storage and
the owner of a recursive mutex are per thread, as on a real machine. Two
`pthread`s may share one SQLite connection. Skip the test where
`tardis.syscallThreadsAvailable()` is false. What to know:

- A thread may make system calls. It may not use `env.io` or `env.dir`.
- Threads switch only at system calls. One that waits for another by
  spinning on memory, with no system call in the loop, hangs the run, and
  nothing reports it.
- A thread's calls are answered on the thread's own stack. If the library
  makes threads with small stacks (musl's default is 128 KiB), give them
  more.
- A thread still running when the body returns is a leaked task: join
  them.

**Tasks made with `env.io.concurrent`** all run under the test's one
thread identity, and that sets two limits:

- A **recursive mutex** belongs to the thread, so it does not keep a second
  task out. Do not share one SQLite connection between tasks, or anything
  else behind a recursive lock.
- **Thread-local storage** is shared by every task, `errno` included. A
  task must read `errno` before it makes another call that can let other
  tasks run.

Either way:

- A task **dropped inside a library call**, by a crash or because the run
  ended, may leave the library's lock held or its state half changed, for
  the rest of the process. The run prints that it happened, with its seed,
  and later failure reports in the same `check` name that run as the
  likely cause when a failure does not come back on replay.

## 6. When the run fails with `StraySyscall`

The library made a call the mode does not answer. The report names the
call, gives its first three arguments, and the file when the call names
one. The call was refused with `ENOSYS` and never reached the machine,
but the run proves nothing, so it fails whatever the body returned.

What to do depends on the call:

- A feature the library can do without: turn it off.
- A call that asks about the real machine (a path under `/proc`): it is
  usually made once, on first use, and often has a compile-time or
  run-time switch. The number of processors is answered: one, or
  what the test's `processors` option says (`sysconf`, C++'s
  `hardware_concurrency`, Rust's `available_parallelism`).
- Anything else is a gap in the emulation. The list of what is answered is
  at the top of `src/sim/sysemu.zig` and `src/sim/sysnet.zig`.

## 7. A program in Rust

A Rust crate is tested the same way: built as a static library and linked
into the test (`test/rust`, `test/rust.zig`).

```
[lib]
crate-type = ["staticlib"]
```

```
cargo build --target x86_64-unknown-linux-musl
zig build test-rust -Dtarget=x86_64-linux-musl -Drust=<path to the .a>
```

Export an entry function with `#[no_mangle] pub extern "C"`, declare it in
the test, and call it from the body. The standard library's threads,
locks, channels, clock, files and sockets, and tokio's runtimes, make
system calls that the mode answers. Link `unwind` too: the standard
library's backtraces call it.

Two rules beyond the C ones, both section 4's problem with no reset to
call.

Rust's standard library keeps thread-local state that is seeded once: a
`HashMap`'s keys. On the thread the body runs on, it outlives the run.
Start a `std::thread` inside the entry function, run the program on it and
join it: a new thread's state is seeded from that run's `getrandom`.

tokio seeds each runtime's scheduler from a counter the process keeps.
Give it a seed drawn from the run instead, with `Builder::rng_seed`. That
method needs `--cfg tokio_unstable` in `RUSTFLAGS` or
`.cargo/config.toml`.

```rust
#[no_mangle]
pub extern "C" fn run() -> i32 {
    std::thread::spawn(|| {
        use std::hash::BuildHasher;
        let n = std::collections::hash_map::RandomState::new().hash_one(0u8);
        let seed = tokio::runtime::RngSeed::from_bytes(&n.to_le_bytes());
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().rng_seed(seed).build().unwrap();
        rt.block_on(program())
    })
    .join()
    .unwrap_or(101)
}
```

Build with `panic = "abort"`: a panic that unwinds into the Zig test is
not defined behaviour.

## What has been run

One C library: SQLite 3.46.0, `zig build test-sqlite -Dsqlite`, six tests.
With `synchronous=OFF` an acknowledged commit is lost to a power loss, and
the failure shrinks from 75 decisions to 1. With `EXTRA` it is kept. With
`FULL`, SQLite's default, it is lost too, which is SQLite's documented
behaviour and was then reproduced on a real ext4 (`docs/power-cut.md`).
Two tasks with a database each pass, as do two `pthread`s with a database
each and two sharing one connection. On musl and on glibc.

One Rust crate, written for the test (`test/rust`, Rust 1.99, tokio 1.54):
threads, a mutex, a channel, a timed wait, files across a power loss, a
blocking TCP echo, a connection and a file shared through `try_clone`,
and a TCP echo on tokio's single-threaded runtime and
on its work-stealing one with two and four workers, and with the
number it picks itself (one, or six when the test's `processors`
option says six); an HTTP/1.1 server and three clients on hyper;
`localhost` looked up through the C library; and `UnixStream::pair`,
the standard library's between threads and tokio's between tasks;
and `set_read_timeout` and `set_write_timeout` on a TCP stream and a
pair, which give up after their time in virtual time (`SO_RCVTIMEO`,
`SO_SNDTIMEO`, revision 137). On musl and on glibc.

A pair of connected sockets (`socketpair`, Unix domain, stream) is
answered. A named Unix-domain socket is not: `socket(AF_UNIX, ...)`
fails with `EAFNOSUPPORT`. A simulated file can be locked with
`flock` (revision 139), as `std.Io.File.lock` and lockfile helpers do,
and with open-file-description byte-range locks (`F_OFD_SETLK`), each
in virtual time. A simulated file can be mapped (`mmap`,
shared or private; revision 123), which SQLite's WAL mode needs.
`sendmsg` and `recvmsg` are answered on
IPv4 sockets and on a pair, without ancillary data: nothing passes a
descriptor from one end of a pair to the other, and `sendmmsg` and
`recvmmsg` are not answered.

A program that looks host names up finds the ones the test writes to
`/etc/hosts` in the simulated filesystem, which starts empty; there is
no name server. On glibc the lookup also needs `.prime = true`, since
glibc builds its lookup tables once (`test/rust.zig`, `resolves`).

One C++ program, written for the test (`test/cpp/probe.cpp`, libc++):
threads, a mutex, a condition variable, the steady and the system clock,
exceptions, streams, a synced file across a power loss, and
`std::random_device`, on musl and on glibc 2.41. It is part of
`zig build test` on Linux x86_64.

No C library that uses the network has been run this way.
