# Reading a run as a timeline

A failure report ends with the last 16 events of the run, as text.
`tardis.traceJson` writes a run's events as a Chrome trace instead, which
Perfetto shows as one track per task, in virtual time.

## Getting the file

```zig
pub fn traceJson(
    gpa: Allocator,
    comptime body: fn (*Env) anyerror!void,
    seed: u64,
    persona: Persona,
    options: Options,
    w: *std.Io.Writer,
) !void
```

It runs `body` once and writes the trace to `w`. The run is the token in
`options.replay` if there is one, and `seed` and `persona` otherwise. If
the run fails, the trace is written first and the run's error is returned
after, so a failing run is traced like any other.

There is no environment variable and no command for this: it is called
from code, usually from a test written for the purpose. Take the token
from the failure report ([reproducing.md](reproducing.md)):

```zig
test "trace the failure" {
    const gpa = std.testing.allocator;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();

    var limits: tardis.Limits = .{};
    limits.trace_ring_len = 4096;

    // The run fails; the trace is complete all the same.
    tardis.traceJson(gpa, scenario, 0, .linux_ext4, .{
        .replay = "linux_ext4:0x953a…:…:…",
        .limits = limits,
    }, &out.writer) catch {};

    try std.Io.Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = "run.json",
        .data = out.written(),
    });
}
```

Give it the options the failing `check` had (`nodes`, `faults`, `net`,
`mode` and the rest): they are part of what a seed means. `setup` is
applied. `traceJson` does not read `TARDIS_REPLAY` or `TARDIS_SEED`: the
run is the one its arguments name.

Then open <https://ui.perfetto.dev>, choose "Open trace file", and pick
`run.json`. `chrome://tracing` reads the same file.

## What the file holds

A JSON array with one object per simulator event, oldest first:

```json
{"name":"write","ph":"i","s":"t","pid":0,"tid":3,"ts":2000.250,
 "args":{"a":7,"b":8,"c":9,"label":"wal"}}
```

| Field | Meaning |
|---|---|
| `name` | the kind of event (the list is `Kind` in `src/sim/trace.zig`) |
| `ph`, `s` | always `"i"` and `"t"`: an instant event on its task's track |
| `pid` | always 0 |
| `tid` | the id of the task that was running: one track per task |
| `ts` | virtual time in microseconds, with the nanoseconds as three decimals |
| `args.a`, `args.b`, `args.c` | three integers whose meaning depends on the kind |
| `args.label` | a short text: a path, a property's name, an error's name. Cut at 40 bytes. |

Time is the simulation's, not the host's. It moves only when the
simulator moves it (a sleep, a latency, a `clock_advance` when nothing can
run), so many events share one timestamp and the gaps between groups are
the waits.

Some kinds, and what their arguments are. These come from the calls in
`src/sim/Sim.zig` and `src/root.zig`; read the `record` call for a kind
that is not here.

| Kind | Arguments |
|---|---|
| `spawn` | `a`: the new task's id. When the task was run at once in its caller there is no new task: `a` is 0 and the label is `inline`. |
| `finish` | `a`: the task's id |
| `switch_to` | `a`: the task that ran before, `b`: the one that runs now |
| `sleep` | `a`: how long, in nanoseconds |
| `clock_advance` | `a`: how far the clock jumped, in nanoseconds |
| `open`, `create` | `a`: the handle, label: the path |
| `read`, `write` | `a`: the inode, `b`: the offset, `c`: the byte count |
| `sync` | `a`: the inode |
| `rename` | label: the old path |
| `fault` | an injected I/O error. Label: the error's name. `b` is 1 for one asked for with `injectIoErrorAfter`. |
| `net_fault` | a network fault; label: its name |
| `crash`, `node_crash` | `b`: journal operations kept, `c`: inodes torn, label: the crash mode |
| `link` | `a`, `b`: the two nodes, label: `cut` or `heal` |
| `clock_step` | `a`: the node |
| `decision` | one keyed draw. `b`: its key (a replay token lists the same keys, in hexadecimal), `c`: 1 if a token or the shrinker forced it, label: its stream. |
| `assertion` | an `always` that failed; label: its name |
| `deadlock` | every task was blocked |
| `note` | anything else; the label says what (`livelock`, `heal`, a daemon task's error) |

The event names are not part of the public API and may change in any
release ([stability.md](stability.md)).

## Limits

- **It holds the end of the run, not all of it.** Events go into a ring of
  `options.limits.trace_ring_len` entries, 64 by default, and the file is
  what is in the ring when the run ends. Raise the limit, as above, to see
  a whole run. The memory is taken when the simulator is created.
- **Instants only.** There are no spans, so a track does not show for how
  long a task ran or was blocked. Read it from the `switch_to`, `sleep`,
  `futex_wait` and `futex_wake` events.
- **One process, tasks as threads.** Nodes are not separate rows. Some
  events carry the node in an argument.
- **Integers without names.** `a`, `b` and `c` are raw: an inode number, a
  handle, an enum's value. The table above and the source say which.
- **Labels are cut at 40 bytes**, so a long path loses its end.
- **The security layer's findings are not in the trace.** When
  `tardis_sec` fails a run, the trace gets one `note` event on the task
  that was running: the node in `a`, the CWE number in `b`, and a label
  that starts with `security:` and names the kind of finding where the
  engine knows it (`security: data_race`, `security: lock_order`) or else
  where it was seen (`security: in a path`,
  `security: in bytes leaving the node`). Nothing else of the finding is
  there: not its message, not the addresses or tainted bytes, not the two
  accesses of a race. The layer keeps those itself; a `certify` campaign
  writes them to the evidence bundle's SARIF.
- **Only what the simulator saw.** Code that left the simulation
  ([threads.md](threads.md)) leaves no events.
- **A run of its own.** `traceJson` runs the body again; it does not dump
  a run that `check` made. If the token no longer fails, the trace is of a
  passing run. Reports are off inside it, so nothing is printed.
- The example above has not been compiled as written. It follows the test
  `traceJson: a run, or a replay token, as a Chrome trace that parses` in
  `src/tests/shrink_test.zig`, which is run and checks that the output
  parses as JSON. Nobody has recorded opening a trace in Perfetto in the
  repository's documents; if a file does not load, report it.
