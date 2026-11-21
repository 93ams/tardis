# Tutorial: find, shrink and fix a bug in ten minutes

You will write a small key-value store with a write-ahead log, let TARDIS
find the bug in it, read the report, and fix it. The finished code is
[`examples/wal_kv.zig`](../examples/wal_kv.zig).

You need Zig 0.17 and a project with a `build.zig`.

## 1. Add TARDIS

```sh
zig fetch --save git+https://github.com/93ams/tardis
```

In `build.zig`, give your tests the module:

```zig
const tardis = b.dependency("tardis", .{ .target = target, .optimize = optimize });
tests.root_module.addImport("tardis", tardis.module("tardis"));
```

## 2. Write the store

A `put` appends a three-byte record to a log file: the key, the value, and
a check byte, so that a record cut short by a crash is recognised.

```zig
const std = @import("std");
const tardis = @import("tardis");
const Io = std.Io;

fn checkByte(key: u8, value: u8) u8 {
    return key ^ value ^ 0x5a;
}

const Store = struct {
    io: Io,
    log: Io.File,
    end: u64 = 0,

    fn put(s: *Store, key: u8, value: u8) !void {
        const record: [3]u8 = .{ key, value, checkByte(key, value) };
        try s.log.writePositionalAll(s.io, &record, s.end);
        s.end += record.len;
    }
};

/// Rebuilds the table from the log, stopping at the first bad record.
fn recover(io: Io, dir: Io.Dir, table: *[256]?u8) !void {
    var buf: [4096]u8 = undefined;
    const bytes = dir.readFile(io, "wal", &buf) catch |err| switch (err) {
        error.FileNotFound => return,
        else => |e| return e,
    };
    var at: usize = 0;
    while (at + 3 <= bytes.len) : (at += 3) {
        if (bytes[at + 2] != checkByte(bytes[at], bytes[at + 1])) return;
        table[bytes[at]] = bytes[at + 1];
    }
}
```

Nothing here mentions TARDIS. The store uses `std.Io`, as it would in
production.

## 3. Say what must be true

The property: **every `put` that returned is still there after a power
loss.** A test body receives an `Env`. Its `io` and `dir` are the simulated
world; `fuzz` draws inputs from the seed; `crashAndReboot` cuts the power.

```zig
fn scenario(env: *tardis.Env) !void {
    const io = env.io;
    var acknowledged: [256]?u8 = @splat(null);
    {
        const log = try env.dir.createFile(io, "wal", .{});
        defer log.close(io);
        // Create the log durably: the file, then its directory entry.
        try log.sync(io);
        var d = try env.dir.openFile(io, ".", .{});
        defer d.close(io);
        try d.sync(io);

        var store: Store = .{ .io = io, .log = log };
        const puts = 1 + (try env.fuzz(u8)) % 8;
        for (0..puts) |_| {
            const key = try env.fuzz(u8);
            const value = try env.fuzz(u8);
            try store.put(key, value);
            acknowledged[key] = value;
        }
    }

    try env.crashAndReboot(.power_loss);

    var recovered: [256]?u8 = @splat(null);
    try recover(io, env.dir, &recovered);
    for (acknowledged, recovered) |want, got| {
        const value = want orelse continue;
        try env.always("an acknowledged put survives a power loss", got != null and got.? == value);
    }
}

test "puts survive a power loss" {
    try tardis.check(std.testing.allocator, scenario, .{ .iterations = 200 });
}
```

`check` runs the body 200 times, each with a different seed. The seed
decides the inputs and what the power loss destroys.

## 4. Run it

```sh
zig build test
```

It fails. This is the report from one run of this tutorial's code (the
event lines are left out here):

```
tardis: always("an acknowledged put survives a power loss") failed
tardis: FAILED  iteration 2/200  persona=linux_ext4  seed=0x953a6cfbe1642f7f
tardis: error.AssertionFailed
tardis: last 16 events (virtual time, task, event):
  …
tardis: replay with:  TARDIS_SEED=0x953a6cfbe1642f7f TARDIS_PERSONA=linux_ext4 zig build test
tardis: shrunk 52 -> 3 decisions and lowered 3 values in 67 runs (every other decision is benign: no fault, no preemption, nothing lost in a crash, minimal input)
tardis: replay the shrunk run with:  TARDIS_REPLAY=linux_ext4:0x953a6cfbe1642f7f:1a419a8ba135b76a.221032ce553e82f2.34d043c0f6aa2ff5:1a419a8ba135b76a=1.221032ce553e82f2=1.34d043c0f6aa2ff5=1 zig build test
```

Read it from the top:

- **Which property** failed, by the name you gave it.
- **Which run**: the iteration, the filesystem being imitated (the
  *persona*) and the seed.
- **The last events**, in virtual time: the write, the crash, the read.
- **Two ways to run it again.** The first replays the run as it happened.
  The second replays the *shrunk* run: TARDIS kept only the decisions
  the failure needs and made every other one harmless. Fifty-two
  decisions became three.

Copy the `TARDIS_REPLAY=…` line and run it. It fails the same way, every
time, on any machine.

## 5. Understand the bug

`put` returned after `write`. The bytes were in the operating system's
cache, not on disk, and the power loss took them. On a machine that never
loses power the store is correct, which is why an ordinary test would
never have found this.

## 6. Fix it

A `put` may return only once its record is durable:

```zig
    fn put(s: *Store, key: u8, value: u8) !void {
        const record: [3]u8 = .{ key, value, checkByte(key, value) };
        try s.log.writePositionalAll(s.io, &record, s.end);
        s.end += record.len;
        try s.log.sync(s.io);
    }
```

Run the replay line again: it passes. Run `zig build test`: 200 seeds
pass.

## 7. Widen the test

Filesystems disagree about what a crash can lose. Ask for all of them:

```zig
    try tardis.check(std.testing.allocator, scenario, .{
        .iterations = 200,
        .personas = &.{ .linux_ext4, .linux_xfs, .windows_ntfs, .posix_strict, .macos_apfs, .freebsd_zfs },
    });
```

## What a green run means

It means: across these seeds, inputs and personas, no run broke the
properties you stated. It does not mean the program has no bugs.

- A property you did not state is not checked.
- Code that does not go through `std.Io` (a C library doing its own I/O, a
  direct system call) is not simulated. See *Limits* in the
  [README](../README.md).
- The personas are models of filesystems, written from their documented
  behaviour. They are not the filesystems.

## Where to go next

- [`examples/counter.zig`](../examples/counter.zig): a lost update between
  tasks, found by the scheduler.
- [`examples/jobs.zig`](../examples/jobs.zig): a job done twice after a
  restart, with every write synced.
- The [user guide](guide.md): the oracles, faults, crashes, several
  nodes, campaign size and guided exploration.
- [reproducing.md](reproducing.md) and [trace.md](trace.md): replaying a
  failure and reading a run as a timeline.
