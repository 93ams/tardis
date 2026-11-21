# Reproducing a failure

A failing `check` prints what is needed to run the same run again. This
document says what it prints, how to take that from a CI log to your own
machine, and what the workflows in this repository keep when they fail.

## What a failing check prints

The report goes to stderr. This one is from the
[tutorial](tutorial.md), with the event lines left out:

```
tardis: always("an acknowledged put survives a power loss") failed
tardis: FAILED  iteration 2/200  persona=linux_ext4  seed=0x953a6cfbe1642f7f
tardis: error.AssertionFailed
tardis: last 16 events (virtual time, task, event):
  …
tardis: replay with:  TARDIS_SEED=0x953a6cfbe1642f7f TARDIS_PERSONA=linux_ext4 zig build test
tardis: shrunk 52 -> 3 decisions and lowered 3 values in 67 runs (…)
tardis: replay the shrunk run with:  TARDIS_REPLAY=linux_ext4:0x953a…:…:… zig build test
```

The shrunk run's own last events are printed too, between the last two
lines. If the run called `std.Io` operations the simulator does not
model, one more line names them (`Env.refusedCalls`).

There are two replay lines, and they are not the same run.

| Line | What it runs |
|---|---|
| `replay with:  TARDIS_SEED=… TARDIS_PERSONA=…` | the failing run as it was found |
| `replay the shrunk run with:  TARDIS_REPLAY=<token>` | the shrunk run: the decisions the failure needs keep their value, every other one is made harmless |

Cases where the report differs:

- A failure found by guided exploration has no seed line. Its first line
  is already a token: `replay with:  TARDIS_REPLAY=…`.
- `tardis: not shrinking (…)` means there is no shrunk run: the failure
  did not come back when it was run again, or the run drew more decisions
  than `Options.shrink_decisions_max`. Use the first line.
- `tardis: the shrunk replay token is too long to print` means the token
  did not fit in 16 KiB. Use the first line.
- A check with `Options.report = false` prints nothing. With
  `Options.shrink = false` there is only the first line.
- A forked iteration whose child process crashed prints one line that
  ends in `replay with:  TARDIS_SEED=… TARDIS_PERSONA=…`.

Every line ends in `zig build test`. That text is fixed: the library does
not know which command started it. If the failing test runs under another
step (`zig build test-examples`, or your project's own step), put that
step in its place.

## Running it locally

Check out the commit that failed, copy one of the two lines, and run it.

```sh
TARDIS_REPLAY='linux_ext4:0x953a…:…:…' zig build test -Dtest-filter="puts survive"
```

In PowerShell the variable is set first, and stays set until removed:

```powershell
$env:TARDIS_REPLAY = 'linux_ext4:0x953a…:…:…'
zig build test -Dtest-filter="puts survive"
Remove-Item Env:TARDIS_REPLAY
```

Things to know:

- **The variables reach every `check` of the test run**, not only the one
  that failed. A token made for one body is then run against all the
  others. Narrow the run to the failing test with `-Dtest-filter=<text>`
  (this repository's `build.zig` has that option; in your own project use
  whatever filter your build offers).
- **The variables are read in test builds only.** A program that is not a
  Zig test passes `Options.replay` or `Options.seed` instead. In a
  test build the order is: `Options.replay`, `TARDIS_REPLAY`,
  `Options.seed`, `TARDIS_SEED`. A token comes before a seed, so a token
  in the environment wins over `Options.seed`.
- **A seed replay** runs that seed once on each persona the check lists,
  or only on `TARDIS_PERSONA` when that is set. It reports and shrinks
  again, so it prints the token again.
- **A token replay** runs once. The token carries its persona and seed, so
  `TARDIS_PERSONA` is not needed. On failure it prints `tardis: FAILED
  replay token` and the last 32 events. It does not shrink again.
- `TARDIS_CAMPAIGN_SALT`, `TARDIS_ITERATIONS_SCALE`, `TARDIS_PRESET` and
  `TARDIS_CORPUS_DIR` are not needed. They decide which runs a campaign
  chooses. The replay lines name the run itself.
- The README says of the salt and the scale that `zig build` does not know
  when they change, so a cached test result is not run again. We expect
  the same of the replay variables but have not tested it. A replay that
  passes at once and prints nothing may be a cached result from before
  the variable was set.

The `tardis` program (`zig build` installs it in `zig-out/bin`) helps with
tokens and logs:

- `tardis explain '<token>'` says what a token pins down, and prints the
  replay command for sh and for PowerShell.
- `tardis replay '<token or seed>'` runs `zig build test` with the right
  variable set. `-f <text>` adds a test filter, `-p <persona>` goes with a
  seed.
- `tardis scan <file>` lists the failures and replay tokens in saved test
  output (`-` reads stdin). It is the quick way through a downloaded log.

## What must match

A seed means one run only for the same code and the same options
([stability.md](stability.md)). To get the failure back, match these:

- **The commit**, of your code and of TARDIS. A token names decisions by
  where the code draws them. If the code now draws one more or one less
  before the failure, the token may pass. `TARDIS_REPLAY_FUZZY=2` retries
  it with its decisions moved by up to two draws, and prints the token
  that fits the new code if one fails.
- **The Zig version.** Each TARDIS release supports one.
- **The options.** Those written in the test come with the commit. Those
  given on the command line do not: `-Dsec` or `TARDIS_SEC=1` attaches the
  security layer to every check and changes the runs, and
  `TARDIS_TRAP_SYSCALLS=1` can turn a pass into `error.StraySyscall`. Use
  the flags the CI step used.
- **The build mode**, to be safe. The simulator makes the same decisions
  in every mode, and a test in the suite checks that. The code under test
  may still behave differently, for example when a bug is undefined
  behaviour that only a safe mode catches.
- **The target, where it matters.** The simulator's decisions are the same
  on every supported platform. These are not:
  - `Options.mode = .syscalls`, `Options.trap_syscalls` and
    `Options.virtual_tsc` work on Linux x86_64 only. Elsewhere a
    system-call-mode check returns `error.SyscallModeUnsupported`, and
    the trap and the counter are ignored. `Options.fork` forks on Linux
    (and on macOS when libc is linked, where it has not been run);
    elsewhere the same iterations run in the process.
  - A test that compares with the real system, as this repository's
    `diff_fs` and `diff_net` tests do, depends on that system.
  - Code under test that branches on the target is different code.
  - In system-call mode, state a C library keeps for the life of the
    process is carried from run to run. A failure that needed an earlier
    run's leftovers may not come back alone; the report says so when a
    task was dropped inside a system call.

If the replay passes with all of that matched, the run is not
deterministic. Report it: that is a bug in the test (something outside the
simulation, see [threads.md](threads.md)) or in TARDIS.

## What the workflows keep on failure

| Workflow | On failure |
|---|---|
| `test.yml` | Up to ten annotations on the run page: the `tardis: FAILED` line (iteration, persona, seed), the property, the error, cut at 300 characters. An artifact `test-failure-<os>`, kept 14 days, with `test.log` (the whole output of the test step that failed, replay lines included) and `diff_fs.trace`, the last sequence the filesystem comparison ran (the failing one only when that test is what failed). On Linux the first test step runs with `TARDIS_TRAP_SYSCALLS=1`; set it when replaying a `StraySyscall` failure from that step. |
| `campaign.yml` | A step that prints the `FAILED` and replay lines. An artifact `campaign-<os>`, uploaded on success too: `campaign.log`, one `failure-N.txt` per failure (its report, the last events, its replay line), `replay-tokens.txt` and `failures.json`. A table in the job summary. One issue per new failure when issues are on. |
| `evidence.yml` | Nothing extra. The `tardis-evidence` artifact and the SARIF upload happen only when the steps before them passed. |
| `zig-master.yml` | Nothing. Read the log. |

Limits of this:

- The annotations do not include the replay lines. The seed and persona in
  the `FAILED` annotation are enough to write the seed line by hand; the
  token is in the log and in the artifact.
- `test.log` is written by the three test steps only, each over the last,
  and the upload step comes right after them. A failure in the formatting
  check uploads nothing useful, and a failure in the bug benchmark, the
  API reference or the benchmarks, which run after the upload step,
  uploads nothing.
- No workflow uploads a Chrome trace. The library writes one only through
  `tardis.traceJson`, called from code ([trace.md](trace.md)); there is no
  environment variable that makes a failing check write a trace file. What
  the logs hold is the last 16 events of the failing run, as text.
- The artifact step in `test.yml` and the whole of `campaign.yml` have not
  been run on GitHub yet.

## A workflow for your own repository

To get the same in a project that uses TARDIS, keep the test output and
upload it when the job fails:

```yaml
      - name: Tests
        shell: bash
        run: |
          set -o pipefail
          zig build test --summary all 2>&1 | tee test.log
      - name: The replay lines of a failure
        if: failure()
        shell: bash
        run: grep -aE "tardis: (FAILED|replay)" test.log || true
      - name: Keep the log of a failure
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: test-failure-${{ runner.os }}
          path: test.log
          if-no-files-found: ignore
          retention-days: 14
```

Then, when a run goes red:

1. Open the run. The second step shows the `FAILED` and replay lines.
2. Check out the commit the run tested, with the same Zig version.
3. Run the `TARDIS_REPLAY=…` line, with your test step in place of
   `zig build test` if it differs, the flags the CI step used, and a
   filter for the failing test.
4. If the line is cut or there are many failures, download the artifact
   and run `tardis scan test.log`.

For long runs on new seeds every night, call `campaign.yml` from your
repository instead of copying it. The comment at the top of
`.github/workflows/campaign.yml` shows how, and what it keeps.
