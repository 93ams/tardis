# Changelog

One entry per revision of the plans and the code, newest first. Section
numbers (§) are `plan2.md`'s unless an entry names `plan.md`. Revision 1
was the first draft of `plan2.md`; the core's earlier history is in
`plan.md` §9 and §14.

## Revision 123 (core: a file mapped into memory)

`mmap` of a simulated file was a stray call in system-call mode, which kept out SQLite's write-ahead-log mode (its `-shm` index is a file every connection maps shared) and any write-ahead log that keeps its index the same way. A user writing a database asked for it.

**What it is** (`src/sim/sysemu.zig`, "file mappings"). The kernel has no simulated file to map, so the harness makes one it has: a memory file (`memfd_create`) per mapped simulated file, holding its bytes, mapped where the code asked, with the code's own address, protection, flags and offset. Every mapping of one file is of the one memory file, so a store through one is seen through another at once; a private mapping sees the file until it writes to a page. The memory file is as long as the file, to whole pages, so a page wholly past the end raises `SIGBUS`, as on Linux. The simulated file stays the one the simulator writes, syncs and crashes: what was stored into a shared mapping reaches it before a read, a write, a truncation or a sync of that file by system call, at `msync` of a range that maps it, and before a crash that only ends the process (the page cache survives that). A power loss loses what no sync wrote. Bytes written by system call reach the mappings where they landed, and so does a change of length. `MAP_SHARED` with `PROT_WRITE` needs a descriptor open for reading and writing and not for appending (`EACCES`), and a directory or the root descriptor cannot be mapped (`ENODEV`), as on Linux.

**Tested.** By system calls (`src/tests/sysmode_test.zig`): a store seen by `pread` and by `read`; a `pwrite` seen by the mapping, next to a store that stays; two mappings of one file at different offsets that are the same memory; a private mapping that sees the file and keeps its own stores; a file grown under a longer mapping and shrunk under it; the errors; a store kept through a power loss by `msync(MS_SYNC)` and by `fsync`, one lost with the power when nothing synced it, and one kept through a process crash; `msync` of one file's mapping that does not make another's stores durable; an appending `pwrite`; bytes stored past the end that read as zeros once the file grows over them; a deleted mapped file whose successor starts empty; a mapping made by one task while another writes the file. SQLite (`test/sqlite.zig`): in WAL mode, with `synchronous=FULL`, the acknowledged commit survives a power loss in all 100 runs on three file-system personas, and the same test fails on its `mmap` with this revision taken out. Two tests that expected a mapping of a simulated file, and of a duplicate of one, to be stray now expect them to work.

**Review.** A fresh reviewer found seven defects in the first version, all fixed: an appending `pwrite` was copied into the mapping at the offset given instead of the end, and the next carrying over put zeros back over it; a write that let another task map the file meanwhile was not copied into the new mapping; a mapped file deleted and closed gave its number to the next new file, which then took the old bytes (a mapped file is now kept while it is mapped, as Linux keeps the inode); bytes stored past the end came back when the file grew over them; a store that could not be written (the disk full) was dropped while `fsync` said it was done; `msync` carried over and synced every mapped file of the node, not those in its range; and a mapping that the kernel refused left its memory file behind.

Tested on Linux (WSL2, static musl, Debug): all 41 test binaries pass, the library suite with 316 passed and 2 skipped; the SQLite suite 8 of 8; Rust 15 of 15 on musl and on glibc 2.41. Windows, Debug: no test failed. Tested on top of revision 122; revision 119, committed meanwhile, touches none of the same code. Not run: the release configurations and `-Dsec`, on either system.

**Limits.** The test's own `env.dir` and `env.io` reads and writes of a mapped file are not carried over: a read there misses stores, and a write there is undone by the next carrying over. Linux writes dirty pages back on its own; here only the calls named above carry stores over, so a power loss keeps none that no call carried over and synced. What is carried over is written to the model directly, with no trace event and no fault injected (the `fsync` that follows is faulted as usual). `munmap` carries nothing over. A mapped file is kept until the run ends or its node crashes, where Linux lets it go at the last `munmap`, and mappings the code never unmapped stay in the process after its run. At most 16 mapped files at once (more is a stray) and 64 shared mappings remembered for `msync`. `/dev/urandom` cannot be mapped (stray).

## Revision 122 (core: locks on open files, and a second name for a file)

Two things a write-ahead log needs were stray calls in system-call mode: a lock that keeps two writers, or a writer and a checkpointer, out of the same bytes, and a second name for a file. Asked for by a user writing a database.

**Open-file-description locks** (`fcntl` `F_OFD_SETLK`, `F_OFD_SETLKW`, `F_OFD_GETLK`; `src/sim/sysemu.zig`). They belong to the open file, not to the process, so two `open`s of one file by one process do conflict, which is what makes them useful between threads; a `dup` shares its original's. A range locked for writing conflicts with any other over it, one locked for reading only with a write lock. `F_OFD_SETLKW` waits in virtual time until the range is free, and a run in which every task waits fails as a deadlock (Linux would wait forever: it does not look for one among these locks). A lock goes with the last descriptor of its open file and with its node's crash. An open file's own locks are split when part of one is unlocked or changes kind, and joined when they touch, as on Linux, so a log that locks record after record holds one range. `F_OFD_GETLK` says what is in the way, with no process (`l_pid` -1). Ranges from the start, the position or the end, backwards, and to the end, with Linux's `EINVAL` and `EOVERFLOW`.

**`link` and `linkat`**, with `AT_SYMLINK_FOLLOW` and `AT_EMPTY_PATH`, through the simulator's hard link: a crash treats the new name as it treats any other change of names.

**Tested** (`src/tests/sysmode_test.zig`): the conflicts between two opens and between reads and writes; a duplicate's locks; unlocking the middle of a range; a lock that changes kind over part of its range; ranges from the end, from the position and backwards; the errors; a waiter released by a close, after three virtual milliseconds, and by an unlock; a waiter whose own file is closed under it and whose number another open takes, which comes back holding nothing; three hundred records locked one after another and seen as one range; locks kept while a duplicate lives and gone with the last descriptor; a crash; two opens each waiting for the other's byte, which fails the run as a deadlock. Links: a second name that sees later writes and outlives the first, a link from a descriptor, both sides relative to a directory, and what Linux refuses (an existing name, a missing file or directory, a directory, an unknown flag, a file with no name left).

**Review.** A fresh reviewer found four defects, all fixed: a range that starts before the file panicked where Linux says `EINVAL`; a waiter whose file was closed and whose handle another open took would have taken the lock for that other open; a file with no name left could be given one again (`ENOENT` on Linux); and the comment said the limit on ranges was per node where it is per run. It also pointed out that adjacent ranges were not joined, so a log locking record after record would have run out of room after 128; they are joined now. And it listed gaps in the tests, filled.

Tested on Linux (WSL2, static musl, Debug): all 41 test binaries pass, the library suite with 315 passed and 2 skipped; Rust 15 of 15 on musl and on glibc 2.41. Windows, Debug: no test failed, 66 skipped. Not run: the release configurations and `-Dsec`, on either system.

**Limits.** A POSIX record lock (`F_SETLK`) is still granted without being recorded, so it never conflicts with an open-file-description lock, where on Linux the two kinds do. A run holds at most 128 ranges and 64 waiters (`ENOLCK`). `flock` is a stray. `linkat` of `/proc/self/fd/N` (the other way to link an open file) is a stray, as every path under `/proc` is.

## Revision 121 (core: a stray call's report says where it was made)

A stray system call's report named the call (for about sixty numbers; any other was "a system call", with its number), its count and its first three arguments. It did not say who made it, and in a large program a `sched_getaffinity` or an `ioctl` can come from anywhere: a user found that their stray `sched_getaffinity` came from `std.heap.smp_allocator`, by reading the standard library.

**What it says now.** Every x86_64 call number the kernel names has its name, from the standard library's table (`src/sim/syscalls.zig`). And the report prints the stack the first stray call was made on, unwound from the signal frame: the function that made the call, then its callers, up to sixteen frames, with file, line and function as a panic's trace has them. It is unwound at the first stray call of a run only, from the unwind tables in memory; names are looked up when the report is printed. It is printed in the default mode with the trap and in system-call mode, including for a call made by a thread the code under test started.

**Documented** (`docs/threads.md`): the new form of the report, and that `std.heap.smp_allocator` and `std.testing.allocator` ask for the processor count once per process, so under the trap only the run that asks first fails.

**Tested.** `src/tests/syscall_test.zig`: the names of three numbers (one with no name), and a stray `getrandom` whose stack holds a return address inside the function that made it and, next, one inside that function's caller. Looked at by hand: the printed report for that call, for a stray `socketpair` in system-call mode, and for a stray `io_uring_setup` made by a thread started with `std.Thread.spawn` (from the system call up to `clone`).

Tested on Linux (WSL2, static musl, Debug): all 41 test binaries pass, the library suite with 313 passed and 2 skipped; Rust 15 of 15 on musl and on glibc 2.41. Windows, Debug: no test failed, 62 skipped. Not run: the release configurations and `-Dsec`, on either system.

**Review.** A fresh reviewer found two defects in the first version, both fixed. A stray call made by `std.debug` itself while it holds its lock (a panic's trace, which reads the program's file to find names, and those reads are strays) would have unwound the stack, which takes the same lock, and the thread would have waited forever: now the stack is left out when that lock is held, and a test holds it and makes a stray call. And in system-call mode the unwinder's first use lists the program's modules, which reads the vDSO's headers after the run has trapped the vDSO, so the run would have reported the vDSO lifted: now it unwinds once before the first run that traps. It also found that the test could pass or fail for the wrong reason in a release build (a caller inlined, the first matching address taken): it now looks for the two functions as adjacent frames, and the caller is `noinline`; and that a stack cut at sixteen frames was printed as whole.

**Limits.** No stack for a clock read through the vDSO, nor for a call that the emulator counts as stray itself (`noteStray`). Code with no unwinding information (no `.eh_frame` and no frame pointers) gives a short stack or none. Only the first stray call of a run has one, and none when `std.debug` held its lock at that call.

## Revision 120 (core: messages sent and received in pieces)

`sendmsg` and `recvmsg` were stray calls in system-call mode. They are how much networking code does all of its socket I/O: Boost.Asio reads and writes its sockets with nothing else, libuv sends and receives its datagrams with them, and so does any program that sends a header and a body without copying them together, or that wants to know whether a datagram was cut. They are now answered on IPv4 stream and datagram sockets and on a pair of sockets (revision 118), without ancillary data.

**What they are.** `sendto` and `recvfrom` over several buffers, with the address in the message header (`src/sim/sysnet.zig`, and `src/sim/sysfd.zig` for a pair). A datagram goes out as one whatever the number of buffers, and comes in spread over the reader's, with its sender in `msg_name` and `MSG_TRUNC` in `msg_flags` when it did not fit. A stream sends every buffer in turn, and a stream read fills the first buffer with room and no more, which is a short read the caller has to expect anyway. `msg_controllen` comes back 0: nothing here produces ancillary data. Flags: `MSG_DONTWAIT` and `MSG_NOSIGNAL`, and `MSG_CMSG_CLOEXEC` to `recvmsg`.

**A fix on the way.** `readv` on a datagram socket read into its first buffer only and dropped the rest of the datagram without saying so, and `writev` of more than one buffer was a stray. Both now go through the same code as the message calls.

**Tested.** By system calls (`src/tests/sysmode_test.zig`): a TCP echo whose two sides use only these calls; a datagram of three pieces received in three with its sender; one cut short over several buffers and over one, and marked so; an empty one; one taken by a reader with no room; a connected socket; exactly 4096 bytes in two pieces; the header's errors (`EFAULT`, `EMSGSIZE` above 1024 buffers, `EINVAL` for a negative address length, `EAFNOSUPPORT`, `EPIPE` on a stream that is not connected); and on a pair, a message each way, `EISCONN` for one that names a destination, a full pair, a shutdown, and `ENOTSOCK` on a pipe. In Rust (`test/rust`, the `socket2` crate, which tokio depends on): a datagram sent in two pieces and received in two with its sender, one cut short and reported so, and 60,000 bytes echoed through a TCP connection and through a pair, each by three threads. It passed the first time it was run, on musl and on glibc 2.41.

**Review.** A fresh reviewer read the change against Linux's behaviour and found no defect in the layout of the header, in the buffer a datagram is gathered into (one for the thread: the simulator fills it and it is copied out with no scheduling point between), or in what `read`, `write`, `readv`, `writev`, `recvfrom` and `sendto` did before. It found five divergences, all fixed: a stream `sendmsg` of no bytes returned 0 on a stream that is not connected, where Linux says `EPIPE`; a negative `msg_namelen` was not refused; a control length with no control buffer was sent as if there were none (`EFAULT`); a read into several buffers faulted on a null one before it knew whether a datagram was there; and one of my tests read its buffer list from a block that had ended. It listed gaps in the tests, filled: the address given without a length and the length without an address, the 4096-byte boundary, a null buffer each way, the flags that stay stray on an IPv4 socket, and `readv` and `writev` above 1024 buffers.

Tested on Linux (WSL2, static musl, Debug): all 41 test binaries pass, the library suite with 312 passed and 2 skipped; Rust 15 of 15 on musl and on glibc 2.41. Windows, Debug: no test failed, 63 skipped (the new tests are Linux's); a first run had one example's test binary fail to compile with no message while another session built in the same cache, and a second run was clean. After these runs only the revision number in three comments changed (119 to 120). Not run: the release configurations and `-Dsec`, on either system.

**Limits.** No ancillary data: a `sendmsg` that carries any is a stray, so no descriptor or credential passes through a pair, and no packet information (`IP_PKTINFO`), timestamp or error queue is read. `sendmmsg` and `recvmmsg` are strays. So are `MSG_PEEK` (but for `recvfrom` on a pair), `MSG_WAITALL`, `MSG_TRUNC` asked of a read, `MSG_MORE` and `MSG_OOB`. A datagram sent from several buffers is put together on the task's stack, up to 4096 bytes; a longer one in pieces is a stray (in one buffer it has no such limit). A stream `recvmsg` or `readv` fills one buffer for each call. Two smaller divergences are left as they were: `recvfrom` on a TCP socket writes the peer's address where Linux writes none, and a message of no bytes to a pair whose other end has shut down returns 0 where Linux says `EPIPE`.

## Revision 119 (core: the next two costs of a run)

`plan3.md` E6, the two items revision 117 listed and left (`docs/measurements.md` §5). The network keeps a mark one past the highest slot a socket was opened in since the run's reset, and its scans of open sockets (the next event, a node's crash, a link cut or healed, the listener and port lookups, the counts) stop there instead of going through all 64 slots; a slot past the mark is free, as the scans already skipped. Each task's key context keeps, per stream, the part of a decision key that depends only on the stream and the task's path, two of the key's four SplitMix64 rounds, made at the stream's first draw (80 bytes more a task). The key is the same (a test checks it against `decisionKey` for every stream), so every replay token and trace hash is unchanged; the warm-start check compares a context's path and counters, not the kept parts. Under callgrind on the bug benchmark's detection table, from revision 118: 5.81 to 5.20 billion instructions, 10.5% fewer; the network's next-event scan from 552 to 104 million, the keyed draw from 649 to 518 million; the table printed byte for byte the same.

**Review.** A fresh reviewer found both claims hold: every write to a socket's kind is in the network's own code, a slot is taken only by `alloc`, which raises the mark, and the network is never copied or restored (a warm start needs it untouched), so a slot past the mark is always free; a task's path is never changed once a prefix is kept, and the warm-start check was the one comparison of whole contexts. Fixed, in the documents: the profile's last line named the wrong baseline, "the second and third items" was ambiguous by share, the 80 bytes a task were not mentioned, and this entry's paragraph in `plan.md` stood before 118's.

**Tested on** Windows (Debug, ReleaseSafe, ReleaseFast, ReleaseSmall and `-Dsec`, 84 of 84 steps each) and Linux x86_64 under WSL2 (40 test binaries, the library suite 316 passed and 2 skipped, plain and with the stray-call trap on).

## Revision 118 (core: a pair of connected sockets)

`socketpair` was a stray call in system-call mode. It is how a program hands bytes between two of its own threads or tasks through descriptors an event loop can watch: Rust's and tokio's `UnixStream::pair`, a C program's wake-up channel, a test double for a network connection. It is now answered for the Unix domain and `SOCK_STREAM`.

**What it is.** Two descriptors, each of which reads what was written to the other (`src/sim/sysfd.zig`): two of the existing pipes, one each way, so nothing new waits, wakes or is watched by `epoll`. On a pair: `read`, `write`, `readv`, `writev`, `recvfrom` (`MSG_DONTWAIT`, `MSG_PEEK`), `sendto` (`MSG_DONTWAIT`, `MSG_NOSIGNAL`), `shutdown` of either or both directions, `close`, `dup`, `poll` and `epoll` (with `POLLRDHUP` and `POLLHUP`), `fstat` (a socket), `fcntl`, `FIONBIO`, `FIONREAD`, `getsockname` and `getpeername` (unnamed), `setsockopt` (accepted, changes nothing), and `getsockopt` for `SO_ERROR`, `SO_TYPE`, `SO_DOMAIN`, `SO_SNDBUF`, `SO_RCVBUF`. A pair never leaves its node and holds nothing durable: no fault is injected into it, and a crash of the node closes it.

**Tested.** By system calls (`src/tests/sysmode_test.zig`): bytes each way; a look that leaves them; a reader that waits three virtual milliseconds for a writer; a full pair that takes part of a write and then says it would wait, and is writable again at exactly a quarter in use; each of the three kinds of `shutdown` and what both ends then read, write and are told by `poll`; a close; a duplicate that keeps its end open; a crash. An edge-triggered `epoll` loop sends 200,000 bytes through a pair to a task that echoes them and reads them all back. In Rust (`test/rust`): the standard library's `UnixStream::pair` between three threads, 300,000 bytes echoed, with `try_clone` and `shutdown`; and tokio's between two tasks, forty questions and answers and then 250,000 bytes one way, on the single-threaded runtime and on the work-stealing one with two workers. Both passed the first time they were run, on musl and on glibc 2.41.

**A side effect.** A socket call (`sendto`, `recvfrom`, `shutdown`, `getsockname`, `getpeername`, `setsockopt`, `getsockopt`) on a pipe, an eventfd or an epoll set now fails with `ENOTSOCK`, as on Linux, where it was a stray.

**Review.** A fresh reviewer read the change against Linux's behaviour and found no defect in the counting of the two pipes' ends, in the reuse of a pipe while a task waits on it, in the readiness masks, or in what plain pipes, eventfds and IPv4 sockets did before. It found one inconsistency, fixed: `recvfrom` with `MSG_NOSIGNAL` was a stray on a pair and is accepted on an IPv4 socket. It found gaps in the tests, filled: `shutdown` of the reading side and of both sides were never run (swapping the two pipes there would have passed), nor was a crash with a pair open, nor `readv` and `writev`; the quarter rule was not pinned; and the read-back comparison skipped bytes. And it found divergences that the file's comment did not state; they are stated there now and under Limits here.

Tested on Linux (WSL2, static musl, Debug): all 41 test binaries pass, the library suite with 309 passed and 2 skipped; Rust 14 of 14 on musl and on glibc 2.41. Windows, Debug: 436 of 497 passed, 61 skipped, none failed (the new tests are Linux's). Not run: the release configurations and `-Dsec`, on either system.

**Limits.** Stream pairs only: a pair of datagram or `SOCK_SEQPACKET` sockets is a stray. `sendmsg` and `recvmsg` are strays, so no descriptor or credential passes through a pair, and so is `SO_PEERCRED`. A named Unix-domain socket (`socket`, `bind`, `connect`) is still refused with `EAFNOSUPPORT` (revision 116). A pair holds 64 KiB each way where Linux's holds about 208 KiB: a task that writes more than that before anyone reads waits here and would not yet on Linux. Closing an end with unread bytes does not give the other end `ECONNRESET`. A timeout set with `SO_RCVTIMEO` or `SO_SNDTIMEO` is accepted and never expires, as on the IPv4 sockets. No `SIGPIPE`. `bind`, `connect`, `listen` and `accept` on a pair are strays. The pipes a thread may have open went from 32 to 64, a pair taking two.

## Revision 117 (core: what a run spends its time on)

`plan3.md` E6. The simulator profiled on realistic runs: the bug benchmark's detection table, 25 examples found 20 times each by campaigns of three sizes, under Valgrind's callgrind on Linux (the example that runs by system call left out with the bug benchmark's new `--without=<name>`: the profiler cannot run a program that traps its own calls; `zig build install-bugbench` installs the program to run under it). The list, with how to make it again, is `docs/measurements.md` §5. The keyed decision the row names is second, at 9.3% of the instructions; first, at 25.2%, is recording a trace event, whose hash used Wyhash's streaming interface, two updates and a finish for every event. It now hashes the event's words and label in one call of `Wyhash.hash`, which gives the same value, so every trace hash is unchanged: the golden hash test passes as it was, and the benchmark's table is printed the same. The ring of recent events wraps by a comparison instead of a division. 16.5% fewer instructions over the whole run, and `Trace.record` falls from 25.2% to 8.4%; in time, the median user time of five runs fell from 1.70 to 1.51 seconds, an indication only, inside this machine's noise. A new test pins the hash of a label too long for the one call against the streaming interface. Listed and not done: the decision key's first two rounds depend only on the stream and the task and could be kept per task; the network's wait scans all 64 socket slots.

**Review.** A fresh reviewer confirmed the hash is the same, by Wyhash's source and by a comparison of the two for every label length to 600 and every split of every length to 199, on five seeds; and found the ring unchanged and the build step right. One fault, fixed: the profile's command ran the example the profiler cannot run (it was left out by an edit of the program), so `--without` was added. Smaller, fixed: the trace's share overstated the work saved (some is counted to the functions it was inlined into), the time was within the noise, and "the table above" named the wrong table.

Tested on Linux (WSL2, static musl): all 40 test binaries pass, the library suite 307 passed and 2 skipped, with and without the stray-call trap; the profile's command, as documented, runs and counts the same 5.81 billion instructions. Windows: the four build modes and `-Dsec` pass (Debug on a second run, after Zig's `unable to load: Unexpected`, and on top of revision 118).

## Revision 116 (core: a web service in Rust, a host name looked up, and state a library sets up once)

Two more things a real service does were tried in system-call mode. The first passed as it was. The second failed on both C libraries, for different reasons, and what it needed is this revision.

**An HTTP server and its clients, on hyper.** `test/rust` gains an HTTP/1.1 server (hyper 1.13 on tokio 1.54) and three clients, each keeping one connection for four requests, the last of them with a body of 200 KiB each way, then a request to a handler that takes a minute, given up on after five seconds. On tokio's single-threaded runtime and on its work-stealing one with two workers, musl and glibc 2.41: passed with no change to the tool. The five seconds are virtual, and the test checks that they were five.

**A host name looked up through the C library** (`getaddrinfo`, as Rust's `"localhost:7200".to_socket_addrs()` and every `connect("localhost:...")` do) failed:

- On musl the lookup read `/etc/hosts`, which the simulated filesystem does not have, asked a name server at 127.0.0.1 that is not there, and gave up after five seconds of virtual time. Nothing for the tool to answer: the simulated machine's host names are the ones the test writes to `/etc/hosts`. The guide says so now. With the file, it passes.
- On glibc the lookup opens a Unix-domain socket (to a name-service cache) and a netlink socket (to list the interfaces), and calls `uname` (for the domain). All three were strays. **A socket of the Unix-domain or netlink family is now refused with `EAFNOSUPPORT`**, as IPv6 has been: the simulated machine has IPv4 and nothing else, and glibc goes on without them. **`uname` is answered**, with the same six strings on every machine (`Linux`, `tardis`, `6.1.0`, `#1 SMP`, `x86_64`, `(none)`). A raw or packet socket, and `socketpair`, are still strays.
- Then glibc's lookup failed as `NonDeterministic`: it builds its tables once in the life of the process, so the first run of a seed did work that its replay did not. The guide's advice for such state, to call the code once outside `check`, is wrong for code that makes system calls, since outside `check` they reach the real machine (here, the real `/etc/nsswitch.conf`, which glibc would then keep).

**`Options.prime`** is the answer to that, for any library: one run of the body, inside the simulation, before each simulator's first run, thrown away. With it glibc's lookup passes. It is made with seed 0 and counts for nothing; a replay, `traceHash`, `traceJson` and `exhaustive` make it too, so that a failure found after it replays after it. A test in the default suite (a body with work done once in the process) has two trace hashes of one seed differ without it and agree with it.

**A stray call's report gives its first three arguments.** `socket (number 41)` did not say which family; finding that it was the Unix-domain one took this line. Revision 110 added the path, for calls that name one.

**What this gives up.** A program that needs a Unix-domain socket (`syslog`, a local database socket) is now told the family is not supported, and may carry on without it where before the run failed and named the call.

**Review.** A fresh reviewer found five things in `prime` as first written, all fixed: what the thrown-away run reached with `sometimes` was counted for the campaign (so a `sometimes` true only in that run passed); a security layer tallied it as a run; `traceHash`, `traceJson` and `exhaustive` did not prime (it is done before a simulator's first run now, wherever that is); and the test's last assertion could not fail and another failed under `TARDIS_SEED` (rewritten on trace hashes). Two tests used a Unix-domain socket as their example of a stray and failed; they use a packet socket now. Written down and not changed: with `warm_restore` the primed run is the one that captures, so the report's counts of restores differ by one; the reviewer found no fault in `uname`, the refused families, the arguments or the Rust tests.

Tested on top of revision 115, on Linux: the library suite, 306 passed and 2 skipped, and all 41 Linux test binaries pass; Rust 13 of 13 on musl and on glibc 2.41. Windows: on top of revision 115, Debug (436 of 494 passed, 58 skipped, none failed); before that merge, the full verification script in all five configurations.

**Limits.** No name server is simulated: a name that is not in `/etc/hosts` is not found, after the C library's timeouts. glibc 2.41 only; `/etc/nsswitch.conf` is missing in the simulation, so glibc uses its built-in order. What a primed run's once-only work read stays for the process, a fault injected into it included. HTTP/1.1 only: no HTTP/2, no TLS. Three new crates in `test/rust` (hyper, hyper-util, http-body-util), behind the crate's `http` feature.

## Revision 115 (core: a reset is reported once)

`plan3.md` A4. The two gaps the review of revision 113 named, measured and closed. A new scenario of the network's differential test, `reset_then_calls`: the server sends 3 bytes and closes with the client's bytes unread, which resets the connection; later the client reads three times and writes twice, one call each. Linux answers: the 3 bytes, `ECONNRESET`, the end of the stream, then `EPIPE` (std: `error.SocketUnconnected`) for both writes. The model answered `error.ConnectionResetByPeer` to all five calls, the bytes never read. Linux reports a socket's error once (`sock_error` clears it) and copies what is in the receive queue before it looks at the error; the model now does both (`src/model/net.zig`, with a unit test): bytes that arrived before a reset or a timeout are read first, the error is reported to the first read or write that meets it, and after that a read ends the stream and a write fails as a broken pipe. A second scenario, `reset_write_first`, has a write meet the reset first: Linux answers `ECONNRESET`, the 3 bytes, the end, `EPIPE`, and so does the model now. System-call mode reported a reset once already, with its own record, but answered the end of the stream to a read after it, dropping the bytes still waiting; it now asks the model, and a new system-call test runs the write-first sequence.

The scenario of revision 63 that was to show a close with unread data, `close_with_unread`, never had any: its server read one byte through a buffered reader, which took all eight, so the close was a FIN and both sides saw the stream end. It now reads one byte by one call, and the client sees the reset, on Linux and in the model.

On Windows both new scenarios differ, accepted by name (the rest of the outcome still compared): Windows drops the bytes that came before a reset and reports the reset to every later call.

**Review.** A fresh reviewer confirmed the rule against Linux's source and the measurements, and found four faults, all fixed with a test: a segment due after a reset was still delivered, so with bytes now read before the error, a read could return bytes after the reset had been reported (a socket accepts nothing once it is reset); in system-call mode, a send after a reported timeout answered `ECONNRESET` (a broken pipe is now `EPIPE` there); system-call mode's dropped bytes, above; and a connection whose retransmit timeout had fired came back to life when its link healed (Linux closes it for good; the model now keeps the timeout). Smaller, fixed: the trace called every broken pipe "reset after fin", and the Windows exception compared nothing else. Not changed: in system-call mode `poll` shows a timed-out stream as neither an error nor hung up; only a reset is.

Found on the way, in std rather than here: `Io.net.Stream.read` does not compile (it destructures `ReadResult`, a struct); the test calls the operation it wraps.

Tested on Linux (WSL2, static musl): all 40 test binaries pass, the library suite 304 passed and 2 skipped, with and without the stray-call trap; the differential test agrees on all fourteen scenarios. Windows: the four build modes and `-Dsec` pass (Debug: 435 of 492 passed, 57 skipped, none failed).

## Revision 114 (core: a test says how many processors the program is told of)

Revision 112 made the processor count one on every machine, and gave as its first limit that a program could not be run as if on eight. A runtime that sizes itself by the count (a thread pool, tokio's workers) was therefore always tested at its smallest, with one worker, where work is never stolen and two workers never meet.

`Options.processors` (1 to 64, one unless the test says otherwise; a value outside is taken as the nearer end) is the count system-call mode gives: `sched_getaffinity` answers with the first so many processors. Told of six, C++'s `hardware_concurrency` and both of `sysconf`'s counts are six, Rust's `available_parallelism` is six, and tokio's work-stealing runtime, built with no worker count, starts six workers and passes its echo test (`test/cpp.zig`, `test/rust.zig`; the mask itself in the default suite, for 6, 64, 200 and 0). On musl and on glibc 2.41.

It changes what the program is told and nothing else. Its threads are simulated tasks, one running at a time, whatever the count; the count decides how many of them the program starts.

**Review.** A fresh reviewer found no fault in the change and that the option reaches every place a simulation is made from the options. Two comments still said the answer is one; corrected. Written down and not changed, all older than this revision and easier to meet now that a program can be told of several processors: `sched_setaffinity` is a stray, so a runtime that pins a thread to each processor fails the run; a thread's processor number is always 0 (the vDSO's `getcpu`, `rseq`), except on the test's own thread under glibc, where `sched_getcpu` gives the real machine's; `getcpu` as a direct system call is a stray.

Tested on Linux: on top of revision 113, the library suite, 300 passed and 2 skipped, and all 41 Linux test binaries pass; C++ 9 of 9 and Rust 11 of 11 on musl and on glibc 2.41, glibc also in ReleaseSafe. Windows: on top of revision 113, Debug (432 of 488 passed, 56 skipped, none failed); before that merge, the full verification script in all five configurations.

**Limits.** Those the review names. 64 processors at most. One glibc, one Rust, one tokio; no other language's runtime.

## Revision 113 (core: writing to a connection the peer closed)

`plan3.md` A4. Two more scenarios in the differential test of the network model (`src/tests/diff_net_test.zig`), run on the simulated network and on the machine's loopback interface. **A write after the peer has gone:** the server accepts and closes, the client reads to the end, then writes four times with a pause before each, then reads again. **A datagram to a closed port**, then one to a live server, echoed back to the same client socket.

The first found a fault in the model. On Linux the first write succeeds, the peer answers it with a reset, and every later write fails with `EPIPE` (std: `error.SocketUnconnected`), and the read after them ends the stream. The model failed those writes and that read with `error.ConnectionResetByPeer`. Linux is right by its own rules: the peer's FIN had arrived first, so the socket was in CLOSE_WAIT, where `tcp_reset` records `EPIPE`, not `ECONNRESET`, and a read checks for the FIN (`SOCK_DONE`) before the error. The model now does the same: after the peer's FIN, what arrived stays readable and then the stream ends, whatever error came after it, and a write after a reset fails with `error.SocketUnconnected` (`src/model/net.zig`, with unit tests). A reset with no FIN before it (the peer closed with bytes it never read, an injected reset) is unchanged. System-call mode's writes already answered `EPIPE` here; its reads answered `ECONNRESET` where Linux returns 0, and are fixed by the same change. A new system-call test runs the sequence Linux was measured to give (read 0, write 1, read 0, `EPIPE`, `EPIPE`, read 0), and again with a reset injected at every read and write.

The datagram to a closed port agrees on Linux: the send succeeds, nothing is reported, and the echo arrives. On Windows two results differ, both Windows behaviour rather than the model's, and are accepted by name, as revision 108's two were: an unconnected UDP socket reports an earlier datagram's port-unreachable on its next receive (`error.PortUnreachable`), and a write after the peer's reset fails with NTSTATUS `LOCAL_DISCONNECT`, which std does not map (`error.Unexpected`, with a stack trace in a debug build), so only the count of writes that succeeded first is compared there.

**Review.** A fresh reviewer confirmed the rule on Linux by raw system calls and found two faults the change brought, both fixed with a test: in system-call mode an injected reset after the FIN now reached a write as `ENOTCONN`, which Linux never gives there (the broken pipe is now reported as the reset, `EPIPE`); and the model drew the delivery of the peer's FIN and the arrival of its reset separately, so a reset could land first and a read could see the reset and later the data (a reset from the peer now arrives after every segment the peer sent before it, as TCP orders them). Two smaller ones, fixed: a timeout after the FIN still failed the read (Linux reads to the end first, whatever the error), and a reset with our own FIN sent too (LAST_ACK) was called a broken pipe where Linux records `ECONNRESET`. The Windows exception for the closed port was narrowed to compare the rest of the outcome. Older gaps it named, not changed: on the `std.Io` path a reset with no FIN before it is reported on every call, where Linux reports it once and then answers `EPIPE` and 0; and the model fails a read with the reset while bytes that came before it are still unread, where Linux returns them first.

Found on the way, in std rather than here: `netWriteWindows` has no case for `STATUS_LOCAL_DISCONNECT` (0xC000013B).

Still not compared: timeouts (the real run's `Io` refuses a timed receive) and name lookup (the model resolves only the names a test gives it).

Tested on Linux (WSL2, static musl): all 40 test binaries pass, the library suite 299 passed and 2 skipped, with and without the stray-call trap. Windows: the four build modes and `-Dsec` pass.

## Revision 112 (core: a program that asks how many processors there are)

Revision 110 named, as a limit, the files a runtime reads to count the machine's processors, and said none had been met. Three probes that ask were written, and all three failed with `StraySyscall`: C++'s `std::thread::hardware_concurrency` with `sysconf` on glibc (`/sys/devices/system/cpu/online`, then `/proc/stat`), Rust's `std::thread::available_parallelism` on both C libraries (`/proc/self/cgroup`), and tokio's work-stealing runtime built the way most programs build it, with no worker count given, which asks the same. The Rust tests since revision 99 passed because each gave tokio a worker count.

Four more paths are now answered as missing, as revision 110 answered glibc's `/proc/sys/vm/overcommit_memory`: `/sys/devices/system/cpu/online`, `/sys/devices/system/cpu/possible`, `/proc/stat` and `/proc/self/cgroup`. Each runtime then asks `sched_getaffinity`, which has said one processor since revision 75. So the answer is one, on every machine: `hardware_concurrency`, `sysconf(_SC_NPROCESSORS_ONLN)`, `sysconf(_SC_NPROCESSORS_CONF)` and `available_parallelism` all return 1, and tokio's default runtime starts one worker and passes its echo test. Each path is needed: with `/proc/stat` or `possible` taken off the list the glibc C++ test fails again, and `online` and `/proc/self/cgroup` are the two the first failures named.

**What this gives up.** A program that reads one of these five files for its own purposes finds it missing and is not told, as it was before, that it asked about the real machine. Every other path under `/proc` and `/sys` is still a stray. Only an `open` for reading is answered: one that writes, and `stat` or `access` of the same paths, is a stray.

**Review.** A fresh reviewer found no fault in the answer itself and three things worth changing, all changed: an `open` of one of these paths that writes or creates was answered as missing too (the kernel would not say that; it is a stray again); the tokio test showed only that the runtime ran, not how many workers it started (it now fails unless there is one); and the comment gave glibc's order of files without a version (2.41 was run; 2.36 and later read the same files by their source, and 2.34 and 2.35 list the directory `/sys/devices/system/cpu` for the configured count, which is still a stray). Written down and not changed: tokio reads `TOKIO_WORKER_THREADS` from the environment before it asks the machine; the C++ test on musl passed before this revision too, since musl asks `sched_getaffinity` only, so it is the glibc build that tests the change; `sysinfo` (glibc's count of memory pages) is a stray.

Tested on Linux: the library suite, 283 passed and 2 skipped, and all 41 Linux test binaries pass; C++ 8 of 8 and Rust 10 of 10 on musl and on glibc 2.41, glibc also in ReleaseSafe. Windows: the full verification script passed in all five configurations before the review's changes, and Debug after them (417 of 471 passed, 54 skipped, none failed).

**Limits.** One processor is the only answer: a program cannot be run as if on eight. One glibc (2.41), one Rust (1.99), one tokio (1.54); another version may read another file, and the report will name it. Go, Java, Python and Node count processors too and none has been run. `dup2` and `dup3` are still strays, and stay so: the program picks the number, and the simulated descriptors live in ranges of their own.

## Revision 111 (core: child processes)

`plan3.md` D4. A program that shells out can be tested: `env.registerProgram(name, f)` makes a `std.process.spawn` or `std.process.run` of `name` (or of a path ending in it) run `f(*tardis.Process)` as a task on the caller's node, with its own copy of the arguments, and pipes for the streams that ask for them; its return value is the exit code, and an error exits with 1 and is noted in the trace. `childWait` and `childKill` are simulated (a kill cancels the program at its next `Io` call). Pipes are a model of their own (`src/model/pipe.zig`), not the network's sockets, so no network fault reaches them: 64 KiB each, as Linux's default, a read of an empty pipe blocks while a writer is open, a full pipe blocks the writer, a closed reader breaks it. So the two classic bugs are deadlocks here as on a real system: waiting for a child whose standard input was never closed, and waiting before draining more output than a pipe holds; both are planted, with the fix of the second, in `src/tests/process_test.zig`. A child never waited for is a leak, and so is an open pipe end. A command nobody registered fails with `error.FileNotFound`, where every spawn used to fail with `error.OperationUnsupported`. Not modelled: the child's working directory and environment, `processReplace`, signals other than kill, resource usage. Programs registered in `Options.setup` turn warm starts off.

**Review.** A fresh reviewer found three faults by running code, all fixed with a test each: a pipe answered a positional read or write, a seek and a `stat` as a closed handle, where a real one answers `Unseekable` (and `stat` says a pipe), so std's default `reader()` and `writer()`, which fall back to streaming only on `Unseekable`, failed on it; a pipe end passed to a second child as its `StdIo.file` was the same end, not a duplicate, so a pipeline `say | cat` lost its input when the parent closed its copy (ends now count their holders); and `wait` could not be canceled while it waited, as std's own can. It also found, by reading, that the race detector saw no order through a pipe (a write now releases and a read acquires, as a future's result does) and that the filesystem's root handle passed for a pipe value. Not changed, and documented: taint is not carried through a pipe, `SpawnOptions.exe` is not looked at.

Found on the way, in std rather than here: `Io.Reader.discardRemaining` on a streaming `File.Reader` (a pipe) under-counts, because the bytes a read puts past its scratch buffer go into the reader's buffer after the count was taken. The test counts with reads instead.

## Revision 110 (core: SQLite and Rust on glibc, and the hang it found)

Revision 107 ran one small C++ program on glibc and said that was no claim about glibc programs in general. SQLite and the Rust crate (tokio included) are now run on it too: glibc 2.41, linked dynamically, Debian 13 in WSL2. The Rust crate passed 8 of 8 as it was. SQLite failed 3 of 7, for two reasons that are the tool's, both fixed, and now passes 7 of 7.

**Two tasks at one lock hung, on glibc.** While a process has never had a second thread, glibc's locks do no atomic work and its unlock wakes nobody. Simulated tasks are fibers on one real thread, so to glibc two of them were one thread: the second to reach a `pthread_mutex` waited, in the simulation, for a wake the first never sent, and the run ended as `error.Deadlock` in a program that has none (SQLite's two connections on two tasks; any C library with a lock, driven from two tasks, would have done the same). Every run in system-call mode now starts one real thread and joins it, once in the life of the process, before its calls are trapped; glibc then does the work. The same thread makes glibc do what it does once at a process's first thread (eight random bytes drawn, two signal handlers installed), which revision 107's C++ test had to do by hand before its first run: that code is gone from the test, and the first SQLite test, which failed as `NonDeterministic`, passes. A test in the default suite (two tasks, one `pthread_mutex`, a system call made with it held) fails with a deadlock on glibc without the thread and passes with it.

**glibc's allocator reads a file once.** The first time a thread's heap shrinks, it opens `/proc/sys/vm/overcommit_memory`, and a path under `/proc` is a stray: SQLite's two-thread test failed on whichever run came first. That one path is now answered as missing, at once and with no event, so the run in which glibc happens to ask is the same run as any other of its seed; glibc takes the missing file as the default setting.

**A stray call's report names the file.** It said `openat (number 257)` and nothing else; finding the path above took a debugger's work. For a call that names a path, the report now prints it.

`zig build test-rust` takes a glibc target (the library must be built for the same C library as the target).

**Review.** A fresh reviewer found four things, all fixed: `traceHash`, `traceJson` and `exhaustive` run without passing where the thread was first started (it is started by each run now); a thread that could not be started was never tried again; the new test left its lock held after a failed run, so that the replay of the failure would hang; and the Rust step's messages still said musl only. Written down and not changed: musl's internal locks (the time zone's, `random`'s; not `pthread_mutex`, not stdio) go back to doing nothing once the process is back to one thread, so two tasks that yield inside one are not kept apart.

Tested on Linux: the library suite, 283 passed and 2 skipped, and all 41 Linux test binaries pass; SQLite 7 of 7 and Rust 8 of 8 on musl and on glibc, in Debug and ReleaseSafe; C++ 7 of 7 on both. Windows: the full verification script passes in all five configurations (Debug: 417 of 471 passed, 54 skipped, none failed).

**Limits.** One glibc and one kernel still. Other files a C library reads once and late are not answered and will fail the run that meets them, with the path in the report now: the number of processors (`/sys/devices/system/cpu/online`), a process's cgroup (Rust's `available_parallelism`), `/etc/ld.so.cache` at the first `pthread_exit` or `pthread_cancel`. None was met by these three programs. A recursive lock of a C library cannot tell two tasks apart, on either C library: they have one thread number.

## Revision 109 (measurements: the security layer's oracles)

`plan3.md` A5, its last part: a planted bug for each security oracle, with a detection rate. `zig build secrates` runs the planted bugs of the layer's own tests (`pillar1_test.zig`, `pillar2_test.zig`, `pillar45_test.zig`, whose bodies are now `pub` and imported, so the table measures the code the tests run) in 20 campaigns at 10, 50 and 200 iterations, and the fixed version of each in 20 campaigns of 200 (`docs/measurements.md` §1). `zig build test` builds it. Seventeen rows: every bug found by every campaign of 200, the steered ones (double fetch, check-then-use) missed by two or three of 20 at 10 iterations, no false alarm on a fixed program. `secret not zeroed` is found only in a build without runtime safety, where `free` does not overwrite the key first.

**Found.** The fixed hash-flooding program (a hash seeded from the run) is flooded in 5 of 20 guided campaigns of 50,000 iterations. Its test passed because its one campaign of 10,000 does not. The cause is in the explorer: a mutated input keeps its parent's run seed, so a secret derived from the run seed is the same for every input the search refines from one parent; within the simulator no secret of the program is hidden from guided exploration. Not changed: a mutation that kept the decisions and changed the seed would no longer reproduce what it mutates. The test's name and comment now say what it shows.

**Review.** A fresh reviewer confirmed every row runs with its test's options, found the use-after-free row's "fixed" program to be another test's program (now "no fixed version"), the columns to be nested samples rather than independent ones (now said), and an unbounded copy of the label, now bounded.

Not in the table: the timing and information-flow assertions, glitched decisions, the Spectre-v1 shape, the C shims, shadow memory and the race detector.

## Revision 108 (tests: the network model against the loopback, datagrams and larger streams)

`plan3.md` A4. `diff_net_test.zig` compared five stream scenarios with the real loopback interface; it compares ten. New: 256 KiB each way over one connection; three connections made before any is written to, written in the reverse order of connecting, each answered with its place in the accept order; three datagrams of 5, 1,200 and 1 bytes echoed back (boundaries and order kept); a datagram of 100 bytes received into 10 (the first 10 bytes and the truncation flag); a datagram of no bytes followed by one of one byte (both arrive, the first empty).

Each side's bytes are summed weighed by their place, so a sum checks order as well as count. No model error found. Linux agrees on all ten. Windows agrees on eight, and on the other two is a known difference: a second listener on a taken port succeeds (as before), and a datagram larger than the receive buffer is an error there (`MessageOversize`, from WSAEMSGSIZE) where POSIX and the model truncate it; on Windows the truncation scenario therefore compares nothing. The stream scenarios run with the network's default range of latencies; the datagram scenarios with one latency, because a range lets the model reorder datagrams, which UDP allows and the loopback interface never does.

Found on the way, in the test and not in the model: sending a datagram of no bytes from `&.{}` makes the real `std` panic on Linux (the kernel answered EFAULT to that address although no bytes were sent, and `std` treats EFAULT as a programmer error); the simulator accepted it. The test sends from a real buffer. And the real run's `Io` refuses a receive with a timeout (`ConcurrencyUnavailable`), so the datagram scenarios receive without one, and a timeout is not compared.

**Review.** A fresh reviewer found the sums blind to order (a reordered stream of the repeating pattern summed the same), the truncation scenario checking no bytes, a failed second connect that would hang the real run (the server waited on a stream never shut; the test now returns and cancels it), the fixed latency applied to the stream scenarios too, and three comments that said more than the code. All fixed.

Not compared yet: timeouts, name lookup, datagrams to a port nobody listens on, and a stream written after the peer has gone.

## Revision 107 (core: a C++ program and glibc in system-call mode, and where two runs of a seed part)

C++ and glibc were the first two entries of every list of what system-call mode had not run. `test/cpp/probe.cpp` is C++ that knows nothing of TARDIS: four `std::thread`s with a `std::mutex` and a `std::condition_variable`, `sleep_for` and `wait_for` on the steady clock with the system clock beside them, exceptions thrown on a thread and on the body, an `ofstream` and an `ifstream`, a file written, synced and renamed that a power loss then keeps, and `std::random_device`. `test/cpp.zig` runs it, six tests of 50 seeds. Zig compiles the C++, so nothing is fetched: `zig build test-cpp`, and on Linux x86_64 it is part of `zig build test`, which until now linked no libc at all and so had no test of what revision 99 found (a C library's clock read through the vDSO; the first of the six tests is that one). It passes on musl, linked statically, and on glibc 2.41, linked dynamically (Debian 13 in WSL2, kernel 6.18), in Debug, ReleaseSafe and ReleaseFast.

**What it took.** *musl's `fopen` for writing failed the run*, and with it every C program that writes a file through stdio: it asks whether the file is a terminal (`ioctl(TIOCGWINSZ)`), and no `ioctl` on a simulated file was answered. The three requests that ask this (`TCGETS`, `TCGETS2`, `TIOCGWINSZ`) now answer `ENOTTY` on a file, a directory and the random device; any other `ioctl` on one is still stray. *glibc aborted at its first thread* ("rseq registration failed"): since 2.35 it registers restartable sequences in every thread and takes no refusal once the first thread was registered, and the emulator said `ENOSYS`. A simulated thread's registration is now accepted without being given to the kernel, and its area filled with processor 0; a critical section needs no restart, because no other simulated thread runs until this one makes a system call. On the thread the run began on the answer is still `ENOSYS`. *glibc draws eight random bytes when a process starts its first thread*, so the first run of a seed differed from its second and `check` said `NonDeterministic`: the test runs the program once outside the simulation before its first run, which is the rule of `docs/c-libraries.md` §4.

**Where two runs part.** `NonDeterministic` printed two hashes, and finding the cause was guesswork (revision 99 found tokio's by reading its source). The second run of a seed now records into a ring of its own, and the report prints the first event at which the two differ, with the four before it; the glibc draw above was found from that line. When the runs part before what the rings hold (`Options.limits.trace_ring_len`), it says so. In the one-process path only: the checks made by parallel workers, guided campaigns and forked children still print the hashes.

**Review.** A fresh reviewer found one fault, fixed and tested: the new report subtracted two event counts the wrong way round when one run was longer than the other by more than a ring, which is a panic in a safe build, in the very case the report is for. Also from the review: it claimed "the same events" for two wrapped rings whose difference had been dropped (now it says the runs part before what is kept); `TCGETS2`, which a newer glibc's `isatty` makes; and `rseq` accepted on the run's first thread, where a program registering by itself would have been told yes with no registration behind it.

Tested on Linux: the library suite, 280 passed, 2 skipped, with the 40 other binaries (the C++ test among them) and the bug benchmark; SQLite 7 of 7; Rust 8 of 8. Windows: the four build modes and `-Dsec` pass.

**Limits.** One glibc (2.41), one kernel, one small program: not a claim that glibc programs run in general, and nothing that links glibc statically was tried. On glibc `zig build test` now needs the host's C library to work under the trap; if it does not, the six tests fail and do not skip. `sched_getcpu` on the thread a run began on reads the area the kernel keeps and says the machine's processor. The priming run covers what the four-thread program touches; a library with other once-only state needs its own. `zig build test` on Linux compiles libc++ once. Still not run: Go, the JVM, CPython, Node, and any program that is not linked into the test.

## Revision 106 (tests and measurements: a thousand tasks)

The other half of `plan3.md` D8's exit criterion. `zig build bench` runs its scheduler row with 1,000 tasks too: a sleep, which is a switch to another task, takes 396 ns there against 176 ns with two tasks and 352 ns with 512, on this machine (`docs/measurements.md` §2). `a thousand tasks: every one runs to its end, and the same seed finishes them in the same order` (`scheduler_test.zig`) starts a thousand in one group, each sleeping three times for lengths of its own; every run is repeated and compared, the same campaign twice finishes them in the same order, and another campaign seed in another. No fault found. With revision 104 the criterion (1,000 tasks and 100 nodes at a documented cost) is met; both at once, and a test that does work on a hundred nodes, were not measured.

## Revision 105 (core: a caught signal a thread sends itself fails the run)

The one fault of revision 99's review that was written down and not fixed. In system-call mode a simulated thread's signal to itself (`raise`, `abort`, `pthread_kill` of itself) is raised on the real thread it runs on. With the default action or with the signal ignored that is right. With a handler the program installed, the handler ran inside the call with the simulator's thread pointer and its system calls not trapped, so whatever it did happened outside the simulation, and the run passed. Now the signal's action is read first (`rt_sigaction`), and if it is a handler the signal is not raised, the call is counted as a stray and answers `ENOSYS`, and the run fails with `StraySyscall`, as a signal to another simulated thread does since revision 99.

Tests, in the test of a thread's signal to itself: a thread raises `SIGUSR1` while the program ignores it (the call succeeds and nothing happens) and while the program catches it (the run fails). Linux (WSL2, kernel 6.18): the library suite, 278 passed, 2 skipped. Windows: the Debug suite passes. Not reviewed by a second reader: the change is twelve lines.

**Limits.** Only a simulated thread's signal is looked at. The thread a run began on has its real number, so its signal to itself goes to the kernel as before, and its handler runs on the body's own stack with its system calls trapped. A signal the kernel raises (`SIGSEGV`, `SIGPIPE`, a timer) is not modelled at all, as before.

## Revision 104 (core: up to 128 nodes)

`plan3.md` D8. A simulation could have 32 nodes: a row of the network's reachability matrix was 32 bits. It is 128 now (`tardis.nodes_max`), and `Options.nodes` up to 128 runs.

`a hundred nodes: each answers, and a cut link cuts those two and no others` (in `udp_test.zig`): an echo on each of 99 nodes answers the first; a partition between the first node and the 32nd, 33rd, 34th, 64th, 65th, 66th and 100th in turn silences that one and not its neighbours; a link cut in one direction lets the question through and not the answer. The test found a second 32-bit set of nodes, in the leak check, which panicked with a daemon on a node past the 32nd.

The security layer keeps state per node for 32 nodes (its memory budget is fixed, `plan2.md`), which was the core's limit too until now. A check with more than 32 nodes and a security layer attached panics with a message that says so, before the layer meets a node it has no place for, and the hundred-node test is skipped under `-Dsec`. That is a panic also when `TARDIS_SEC=1` or `-Dsec` attached the layer to a check that named none.

Cost (`zig build membench`, `docs/measurements.md` §2): 100 nodes take 117 MiB and 128 take 150 MiB, about 1.2 MiB a node as before; a campaign of 200 runs of a small body takes 0.58 ms a run with 100 nodes against 0.06 ms with one, on this machine; the campaign's start, which allots those 117 MiB, is in that figure and was not taken apart from the runs. Not measured: 1,000 tasks in time, and a test that does work on all its nodes. Not looked at: exhaustive exploration with more than 64 tasks, whose sets of tasks are 64 bits (`Sim.zig`, `bit`).

## Revision 103 (tests and core: warm starts with three nodes, and with allocations that fail)

The two warm-start cases revision 102 listed as not covered, and one small fault the review found on the way.

`warm restore: three nodes and three personas, the same runs as cold`: tasks on three nodes each find their node's filesystem as setup left it and then overwrite it past a page; 450 runs warm give what 450 runs cold observed, with more than 400 warm starts. Only the first node holds anything from setup: a setup that starts a task on another node turns warm starts off for the campaign (`Sim.warmOnlySnapshotState`), which this test met and which was written down nowhere but in the code. So the other nodes' snapshots are of empty filesystems, and the copying of pages is exercised on one node.

`warm restore: an allocation that fails anywhere gives the cold result or OutOfMemory, and leaks nothing`: the same campaign, short, in two parts. The allocator fails at one allocation after another (about forty of the campaign's 3,500, evenly spread): the check returns `OutOfMemory` or gives the cold result, and the test allocator sees no leak. Then the copy of a snapshot's pages is made to fail, each one of the campaign in turn, found by its size: the result is the cold one every time, with fewer warm starts.

**Fixed:** when a snapshot was taken of several nodes and the allocation for a later node failed, the earlier nodes' pages kept the snapshot's reference until the end of that run, so a body that filled the disk was refused sooner there than in a cold run. `Vfs.unpin` takes the reference back. Found by reading, in the review; no test above reaches it (the failing allocation is not singled out), and the new `vfs.zig` test covers `unpin` alone.

## Revision 102 (tests: forked children against one process, and failing runs between warm starts)

`plan3.md` A6. Two comparisons of configurations that were missing.

`simulator agreement: the same runs in one process, in forked children and in worker processes` (Linux): 900 runs of the simulator's own fuzz program (300 on each of three personas), with I/O errors, give the same sum of what every run observed when each run is a forked child of the process that ran setup, when three worker processes fork them, when one process runs setup before every run, and when it starts from a snapshot. The children add to a page shared with the parent, and the test checks that the parent itself observed nothing in the forked campaigns. Another campaign seed gives another sum.

`warm restore: failing runs between warm starts, on three personas, are the failures of cold starts` (every target): with `keep_going`, a body that reads and changes what setup left and fails on about one input in seven hundred logs the same failing iterations with the same shrunk tokens warm and cold. Each failure is shrunk and replayed before the next run starts, which drops the snapshots; the next run takes them again, and the test requires warm starts after a failure and to the end. After five failures warm starts stay off (`Sim.Warm`), so the body fails seldom. The review found the first version of this test unable to see a wrong snapshot.

No finding. Not covered still: forked runs with allocation failures or with the determinism re-run, the fork server outside Linux, warm starts with several nodes, and a failed allocation while a snapshot's pages are copied. Under `-Dsec` there are no warm starts, and both warm comparisons are cold against cold.

## Revision 101 (core: `dup` of a socket and of a file in system-call mode)

Revision 99 left `dup` of a socket or a file stray, so Rust's `TcpStream::try_clone` and `File::try_clone`, the usual way to give a connection's reading half to one thread and its writing half to another, failed the run. `dup`, and `fcntl` with `F_DUPFD` or `F_DUPFD_CLOEXEC`, now give a socket (`sysnet.zig`), a file or a directory (`sysemu.zig`) a second descriptor: one socket or one open file under two numbers, with one position and one set of flags (`O_NONBLOCK`, `O_APPEND`), closed when its last number is. A number that is closed is no descriptor from then on, though its duplicate lives; a node's crash closes its duplicates with its files and sockets.

Tests: in system-call mode by the calls themselves (a file, a directory, a connection, a listener, an epoll set over a duplicate, a crash), and in Rust, where a thread reads a connection through `try_clone` while another writes it, and a file's clone moves the position the file reads from (`test/rust`, now eight tests).

**Review.** A fresh reviewer read the change and found no fault in how the numbers and the tables are kept, and three at the edges, all fixed and tested. `mmap` of a file's duplicate went to the kernel, which said `EBADF`, where `mmap` of the file fails the run: the trap knew a simulated file by one bit of its number, and now takes every number from `0x1000_0000` up, so `mmap` of a socket or a pipe fails the run too, which it did not before this revision either. `fcntl(F_DUPFD_CLOEXEC)` of the random device said `EINVAL` and of the root descriptor `EBADF`, where `dup` of either is stray: both are stray now. And what was kept of a file's duplicates outlived a crash, harmless only because a handle's value changes with each crash: it is dropped with the node.

Tested on Linux (WSL2, kernel 6.18): the library suite, 273 passed, 2 skipped, with the 39 other binaries and the bug benchmark; SQLite 7 of 7; Rust 8 of 8 in Debug and ReleaseSafe. Windows: the four build modes and `-Dsec` pass.

**Limits.** `dup2` and `dup3` are stray: they name the number to take, and a program that moves a descriptor onto 0, 1 or 2 wants a real one. So is `dup` of the root descriptor and of the random device. As for a pipe (revision 99): a number leaves the epoll sets it is in when it is closed, and a task in `poll` on it sees `POLLNVAL`, where Linux keeps both while a duplicate lives; `F_DUPFD`'s lowest number is ignored. A run has 64 duplicates of sockets and 64 of files, over all its nodes; the next fails with `EMFILE`.

## Revision 100 (model: four more cases on ext4, and a rename over a file with the journal full)

Four cases the reviews of revisions 96 and 98 said were untried, run on the real ext4 as before (`scripts/powercut/ext4.sh` 4o to 4r, five rounds and then eight, the same each time).

- **4r** confirms the model: a shortened file's `fdatasync` commits the waiting unlink.
- **4p and 4q** show ext4 keeping what the model lets go: a sync that has to allot new blocks, for an append of 16 KiB or a write into a hole, commits everything. The model is left as it is there, losing more, because the kernel may have allotted those blocks earlier by itself.
- **4o** was meant to show whether a write inside a file, in the same tick of the kernel's clock as the file's last change, still makes the file's `fsync` commit. It could not: `scripts/powercut/tight.c` makes the calls with nothing between them, but the commit that has to come between the two writes took five ticks (the review saw this before the program measured it). The `fsync` committed, 20 ms apart. Since the case is possible on a faster disk and would be the unsafe direction, the model now takes the cautious side: on `linux_ext4` and `linux_xfs` a write inside a file's length within the same ten milliseconds of simulated time as the file's last change is no change of the file's own (`Persona.clockTickNs`). Inferred from 4j and 4k, not seen. A program that overwrites a file at once after syncing it and relies on that file's `fsync` for some other file's unlink now fails in simulation; a replay token of such a run may no longer reproduce.

One fault in the model, found by the review of revision 98 and older than it: a file replaced by a rename when the journal was full had its change counted as already committed, so its own `fsync` did not commit the rename (`linux_ext4`, `linux_xfs`). Fixed, with a test that fails without the fix.

## Revision 99 (core: a Rust program in system-call mode, and the two faults it found)

Revision 97 listed Rust, an async runtime, several workers and release builds as not run. `test/rust` is a Rust crate that knows nothing of TARDIS, built by cargo as a static library for `x86_64-unknown-linux-musl`; `test/rust.zig` links it and runs it under system-call mode (`zig build test-rust -Drust=<library>`, Linux x86_64). Seven tests pass, each over 50 seeds: four `std::thread`s with a `Mutex` and a channel; an hour's `thread::sleep` waited for with `Condvar::wait_timeout`, in virtual time; `std::fs` writing, syncing and renaming a file that a power loss then keeps, on three personas; a blocking TCP echo with a thread for each connection; a `HashMap` whose order follows the seed; tokio 1.54's single-threaded runtime (`epoll`, an `eventfd`, timers, a TCP echo, a channel, a timeout); and tokio's work-stealing runtime with two workers and with four. The same in Debug, ReleaseSafe and ReleaseFast with the crate built `--release`. Rust 1.99, musl, WSL2 with kernel 6.18.

**Two faults found, both older than this revision.** *A C library's clock was the machine's.* Clock reads through the vDSO are answered from the simulation by making the vDSO's code fault (revision 78), and the image is found through the auxiliary vector. In a test linked with libc that vector is libc's, `std.os.linux.getauxval` found nothing, the image was never protected, and every `clock_gettime` made by C code read the host: SQLite's, since revision 78, and unreported, because a run with no vDSO to protect is a valid one. Rust's timed wait computes an absolute deadline from that clock, so its timeout never came. `vdso.zig` asks libc for the vector now, `test/sqlite.zig` has a test that libc's clock is the virtual one, and a run in system-call mode that finds a vDSO and cannot trap it now fails with `StraySyscall` and says why, whatever the cause. *A thread's signal to itself was not raised.* Revision 97 wrote the handling of `tkill` and `tgkill` and did not route the calls to it, so a thread's `abort` sent its signal to a thread number the kernel does not have, and returned. Routed, with a test (signal 0 only: delivery is not tested). A signal to another simulated thread (`pthread_kill`, `pthread_cancel`) now fails the run as a stray, where the first routing answered `ENOSYS` and let the run pass; one to the thread the run began on goes to the kernel, as before. Not fixed: a handler the program installed for a signal a thread sends itself runs with the simulator's thread pointer and with its system calls untrapped, and nothing reports it.

**`dup`** of a pipe end, an eventfd or an epoll set, and `fcntl` with `F_DUPFD` and `F_DUPFD_CLOEXEC`: mio, and so tokio, duplicates its epoll descriptor. The duplicate is a second descriptor for the same object, which lives until the last is closed, and `O_NONBLOCK` is shared between them as it is on Linux. One divergence: a descriptor leaves the epoll sets it is in when it is closed, where Linux keeps it until its last duplicate is closed. A task waiting in a call on a descriptor that another task closes gets `EBADF`, where Linux goes on waiting when a duplicate keeps the object. `dup2`, `dup3`, and `dup` of a socket or a file are still stray.

**What a Rust program has to do.** The standard library and tokio keep thread-local state that is seeded once (a `HashMap`'s keys, tokio's random number generator). On the thread the test body runs on, that state outlives the run, and the second run of a seed differs from the first: tokio's single-threaded runtime failed with `error.NonDeterministic` on its first seed. Running the program on a `std::thread` started inside the body gives it fresh thread-locals, seeded from that run's `getrandom`; both tokio tests do. tokio also seeds each runtime's scheduler from a counter the process keeps, which no new thread resets: the tests give it a seed with `Builder::rng_seed`, drawn from the run's `getrandom`, and that needs `--cfg tokio_unstable` (`test/rust/.cargo/config.toml`). Without it the tests passed three times in three, and nothing says they always would. This is the rule of `docs/c-libraries.md` §4 (reset what outlives a run), and the guide has a section on Rust now.

Tested on Linux: the library suite, 270 passed, 2 skipped, with the 39 other binaries and the bug benchmark; SQLite 7 of 7; Rust 7 of 7 in three build modes. Windows: the four build modes and `-Dsec` pass (Debug and ReleaseSafe on a second run: the first stopped at a compiler file-load error, `unable to load: Unexpected`, which this machine gives under concurrent builds).

**Review.** A fresh reviewer read the change and reported six faults. Five are fixed: an edge-triggered eventfd written through a duplicate woke nobody; a thread's signal to the thread the run began on was answered `ESRCH` where revision 97 passed it to the kernel; a signal to another simulated thread passed silently; a vDSO that could not be protected was not reported; tokio's process-wide seed counter. One is written down above and not fixed (the handler of a signal a thread sends itself). Lesser ones: `readv` and `writev` left a descriptor non-blocking that they had found so (fixed); `tgkill`'s process number is not checked, and `F_DUPFD`'s lowest number is ignored (neither fixed). `zig build test-rust` refuses a target that is not musl.

**Limits**, beside revision 97's, which stand. The crate is linked into the test binary: a Rust program is tested as a library with an entry function, not as an executable, and nothing here runs a program that was not built for it (static, musl). `std::net::TcpStream::try_clone` duplicates a socket, which is stray. tokio's blocking pool (`tokio::fs`, DNS lookups) was not run, nor its signal handling or process spawning. Not run: glibc, C++, Go, anything with a runtime of its own that is not linked in (the JVM, CPython, Node).

## Revision 98 (model: the commit by time and `fdatasync` on ext4, by measurement)

The two gaps revision 96 left in the `fsync` rule, both in the unsafe direction. `scripts/powercut/ext4.sh` gained eight cases (4g to 4n), run on the real ext4 as before (kernel 6.18.58.1, WSL2, three rounds and then five, the same each time), and this time every one came out as predicted.

**The commit by time.** ext4 commits what is waiting five seconds after the first change since its last commit, and a change it has taken is no longer the file's own: a create, seven seconds, an unlink and the created file's `fsync` lose the unlink (4g), where without the pause they keep it (4c). On `linux_ext4` and `linux_xfs` the model now remembers when the first change since the last commit of everything was made (`Vfs.txn_start_ns`), and a change older than `Persona.commitIntervalNs` (five seconds; thirty on XFS, from memory and not run) no longer makes its file's `fsync` commit the journal. The periodic commit makes nothing durable by itself in the model, though on ext4 it does (4h): a program right only because five seconds passed stays wrong in simulation. The changes it passed over (`Vfs.timed_len`) are committed by the `fsync` of anything they name, so a file synced with its directory long after it was made is kept; the review found a first version in which it was not.

**`fdatasync`.** System-call mode treated it as `fsync`. On ext4 it commits the waiting changes for the file's creation (4m) and a change of its length (4i), not for a write inside its length (4j; `fsync` does, 4k) and not for a rename (4l; `fsync` does, 4d). `Vfs.dataSync` has that rule, `Sim.fileDataSync` reaches it, and system call 75 uses it. On the other personas it is `fsync` as before.

Tests: three in `vfs.zig` run the rows on the model (every persona but `posix_strict` for two of them), one in `fs_test.zig` runs 4c and 4g through a simulated sleep, and one in system-call mode runs 4j and 4k through the calls. The security layer's swap of a file now happens at the simulation's current time. A replay token of a run on these two personas in which more than the interval of simulated time passes between a file's change and its `fsync`, or which calls `fdatasync`, may no longer reproduce. Not covered, and listed in `docs/power-cut.md`: a commit that comes sooner than the interval (a full journal, another program's sync), a filled hole or a new block, a write that leaves the file's time unchanged (tried in 4n, not seen).

## Revision 97 (core: an event loop's parts, and threads, in system-call mode)

System-call mode gains what kept most C and Rust code that waits on several things, or starts a thread, out of it (`plan.md` §9.2). **Pipes, `eventfd` and `epoll`** (`src/sim/sysfd.zig`): `pipe`, `pipe2`, `eventfd`, `eventfd2`, `epoll_create`, `epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait` and `epoll_pwait2`, over sockets, pipes and eventfds, by level, by edge and one-shot, with `poll` over the same descriptors and `ioctl(FIONBIO)` on them and on sockets. **Threads** (`src/sim/systhread.zig`): a `clone` that starts a thread starts a simulated task with the stack and the thread pointer the caller gave, so `pthread_create` and `std.Thread.spawn` work; a thread is scheduled by the seed like any task, its sleeps and locks are the simulator's, and `tardis.syscallThreadsAvailable()` says whether the machine can (it needs FSGSBASE: a processor from 2012 on, Linux 5.9). The signal handlers find the simulator's thread-local state from under a thread's pointer through a table of the process. `rt_sigprocmask` is now kept per task and never given to the kernel, in this mode.

Tested on Linux (WSL2, kernel 6.18): a pipe's order, waits, end and `EPIPE`; an eventfd's count and semaphore; epoll's three ways of reporting, its errors and its timeout in virtual time; an edge-triggered echo server for three clients, stopped through an eventfd (100 seeds); threads joined, detached, with thread-local storage of their own, with a mutex between four of them, left running at the end of a run (a leaked task), and killed by a crash; and SQLite driven by two musl `pthread`s, with a database each and sharing one connection, which two tasks on one thread identity could not do (`test/sqlite.zig`, six tests). The library suite on Linux: 263 passed, 2 skipped, with the 39 other binaries and the bug benchmark. Windows: the four build modes and `-Dsec` pass.

An adversarial review found six bugs, fixed and tested where a test can show them: a real thread inherits its creator's `gs` base, which the first version trusted to find the simulator's state (the table replaced it); edge-triggered epoll missed a second write to a pipe that nobody had read, which Linux reports (a write to the other end, a network change and the passing of virtual time are edges now); a blocking `writev` on a full pipe returned short; no call on these descriptors was a scheduling point unless it waited; a signal mask outlived its task's number; and a descriptor closed and made again while a task waited on it was taken for the old one. Also from the review: a scan of an epoll set begins after the last entry it reported, and a thread's signal to itself (`abort`) is raised.

**Limits.** Threads switch only at system calls: one that spins on memory waiting for another, with no call in the loop, hangs the run unreported, and data races between threads are not explored. A thread may make system calls and may not use `env.io`. A thread's calls are answered on its own stack, so a small one (musl's default is 128 KiB) leaves less room than a task's. Edge-triggered epoll reports edges Linux would not, so a program that fails to drain a descriptor is not caught. Simulated descriptor numbers are far above `FD_SETSIZE`: `select` cannot be emulated, and a library that keeps a table indexed by descriptor (libuv, libevent) will ask for a table that size. Not emulated: `dup`, `fork`, a signal to another thread, an epoll set inside another, `mmap` of a file. Not run: glibc's threads, any Rust or C++ program, an async runtime, threads in release builds with libc, several worker threads.

## Revision 96 (model: an fsync of an unchanged file commits nothing else on ext4, by measurement, and on XFS, by its source)

The rule revision 94 found wrong is corrected. On `linux_ext4` and `linux_xfs` an `fsync` of a file commits the waiting directory changes only when the file has changed since the last commit of everything waiting: a write, a change of length, or a change to one of its names (`Persona.syncNeedsOwnChange`; `Inode.touch_seq` against `Vfs.commit_seq`). An `fsync` of some other, unchanged file commits nothing but that file's data, so a power loss may undo an unlink made before it, as on the real ext4. This is the default persona: a program that leaned on such an `fsync` passed before and can fail now, and a run on these two personas whose crash follows such an `fsync` draws from a longer journal, so its replay token and any kept corpus entry may no longer reproduce the same run.

`scripts/powercut/ext4.sh` gained six cases (4a to 4f) to find where the line is on the real ext4 (kernel 6.18.58.1, WSL2, three rounds, the same each time). A write to the other file before the unlink, the `fsync` of a file created before the unlink, and a rename followed by the renamed file's `fsync` all commit. Three cases corrected the rule as first written: the `fsync` of an unchanged directory does commit on ext4, so any directory's `fsync` still commits everything there; and a file written, then a commit, then the unlink and the file's `fsync` leaves the unlink lost, for an overwrite in place and for an append, so unsynced data is not the criterion. Two unit tests in `vfs.zig` run the rows on the model.

An adversarial review read the first version against ext4's and XFS's source as it remembered them, predicted the overwrite case (measured: right) and the append case (measured: wrong), and found that XFS does not commit for an unchanged directory, so `linux_xfs` asks the same of a directory (`Persona.dirSyncNeedsOwnChange`); a file renamed over now counts as changed. Known and not fixed, all in `docs/power-cut.md`: the model has no commit by time, `fdatasync` is treated as `fsync`, and XFS, NTFS, APFS and ZFS have not been run (the last three keep the old rule).

## Revision 95 (documents: a guide to testing a C library)

`plan3.md` D6. `docs/c-libraries.md` says how to bring a C library that does its own I/O into the simulation with system-call mode, from what the SQLite test needed: build the library into the test, where its paths land, the task's stack, crashing with the library's handle still open, resetting state the library keeps for the life of the process (the cause of `error.NonDeterministic`), what one thread under every task means for recursive locks and `errno`, and what to do about a stray call. It names what has been run (SQLite 3.46.0, static against musl) and what has not (a library that uses the network, glibc). `docs/guide.md` links to it. No code changed.

## Revision 94 (evidence: a power cut on a real ext4, and one rule of the model found wrong)

`plan3.md` A3, first step. `scripts/powercut/ext4.sh` makes an ext4 filesystem in a file behind a loop device and a `dm-flakey` target, and cuts the power as xfstests does (drop every write, unmount, mount again). On kernel 6.18.58.1 under WSL2, five rounds, the same each time. A finished unlink whose directory is not synced is back after the cut, and one whose directory is synced is gone, as the model says. Real SQLite 3.46.0 (`scripts/powercut/sqlite_commit.c`, the program of `test/sqlite.zig` in C) loses an acknowledged commit with `synchronous=FULL`, with the rollback journal back and the integrity check passing, and keeps it with `EXTRA`: what the simulation finds. SQLite's documentation of `PRAGMA synchronous`, read on its site, says the same of `EXTRA`.

**The model is wrong in one place, not fixed.** An unlink followed by an `fsync` of another file that has not changed is still undone on ext4; the model takes the `fsync` of any file to commit every waiting directory change (`Persona.fileSyncCommitsJournal`, every persona but `posix_strict`). It keeps what ext4 loses, so a program that leans on such an `fsync` passes in simulation and loses the change on the real filesystem; only `posix_strict` would find it, and the default persona is `linux_ext4` alone. When the other file was written after the unlink, its `fsync` does carry the unlink, on ext4 as in the model.

Written up in `docs/power-cut.md` with what it does not show: one filesystem and kernel, a cut at one point (everything waiting lost at once, no proper prefix), nothing about data, and `OFF` not compared. Not part of `zig build test`: it needs root and Linux. An adversarial review found nine issues, fixed: the wording for `OFF` (the database file is gone, not unreadable), a cleanup that could wait for ever on a suspended target or delete into a mounted filesystem, and claims that named `linux_ext4` for a rule most personas share; its fourth finding became the test above. Also rerun on Linux (WSL2) at commit `65f7e85` (revisions 77 to 79): the library suite (209 passed, 2 skipped), the 43 other test binaries with the bug benchmark, and SQLite (4 of 4).

## Revision 93 (core: a warm-start snapshot per persona)

`plan3.md` E7. A campaign takes its personas in turn, and the one snapshot of setup was of one persona, so with several personas only the second run of a determinism check started warm. `Sim.Warm` now keeps a snapshot per persona. A filesystem snapshot shares its pages with the running filesystem, which can hold one state's pages: when a run on another persona begins, the snapshot whose pages are there copies them out (`Vfs.savePages`, once), and a later warm start on its persona copies them back (`Vfs.loadPages`). A campaign on one persona copies nothing, as before. The periodic check that re-runs setup now also compares page contents with the copy, when there is one.

`simulator agreement` compares cold against warm on three personas (1,200 runs, more than 1,100 of them warm, and 21 checks, which is 7 per persona) with a setup that writes another content on each persona; with the copy back turned off by hand, the test fails. Not measured: what a warm start costs when personas alternate (one copy of setup's pages into the filesystem per run) against running setup, and the memory (a copy of setup's pages per persona, node and worker). A check whose setup does not finish now drops its snapshot. Found by the review and not from this change: in a warm run the pages setup wrote stay taken when the body deletes them, so a body that fills the disk is refused sooner than in a cold run; said at `Options.warm_restore`. Not covered by a test: several nodes, a failed allocation of the copy, and a failing run between warm starts on several personas.

## Revision 92 (tests and model: the simulator's network is fuzzed, configurations are compared, and the two failures of the second CI run are fixed or avoided)

The simulator's own fuzz test (`plan3.md` A6) now covers the network: `src/tests/self_fuzz_net_test.zig` runs random programs over three nodes (stream echoes, several at once, datagrams, cut and healed links, partitions, node crashes with the daemons started again, clock steps) with connection resets and datagram loss and duplication, every run twice for determinism, and again on four workers. Links are cut and servers crashed both between exchanges and under open streams. Its content oracles: an echo read to a clean end is the request, byte for byte, and a datagram arrives whole, only if this run sent it, and from an echo daemon. No finding in the network model. `simulator agreement` in `self_fuzz_test.zig` sums a hash of what each run of the file programs observed and compares the sum between one worker and four, and between cold and warm starts (alone and on four workers); they agree. Fork against no-fork is not compared: a forked run's observations stay in the child. Four planted bugs show the oracles can fail: the durable step without the directory's sync fails on strict POSIX (the assertion that the file is there; the one on its content is not shown to fail), and an echo daemon that changes one byte, loses one byte or cuts a datagram short is caught. The agreement test skips itself when the environment changes which runs a check makes (`TARDIS_EXPLORE`, `TARDIS_PRESET`, `TARDIS_SEED`, `TARDIS_REPLAY`, `TARDIS_CORPUS_DIR`); it and the planted bugs are not part of the nightly campaign.

Writing the agreement test showed a limit that was not documented: a warm start needs the run before it to have had the same persona, and a campaign over several personas takes them in turn at each iteration, so only the second run of a determinism check starts warm there (and no run does under guided exploration, chaos or a security layer). Now said at `Options.warm_restore` and in `plan3.md` (E7, open).

The second run of the workflows on GitHub, and the first since revision 74 (commit `05b086c`): the evidence workflow and the tests on Ubuntu pass; macOS and Windows each fail in the filesystem differential test, and nowhere else. The two sequences were regenerated here from their seeds:

- **APFS, a model error, fixed.** A symbolic link renamed onto the directory it is in gives `IsDir` on APFS, where the model said `DirNotEmpty`. Linux finds that the destination holds the source before it compares kinds; the BSD kernels compare kinds first. The model now does that for `macos_apfs` and `freebsd_zfs` (`Persona.renameComparesKindsFirst`). The FreeBSD half is from that kernel's source as remembered, not from a run.
- **Windows Server 2025, a panic in Zig's std, avoided.** A rename of an existing file to a path under a file (`c` to `d/x`, where `d` is a file) panics in std with `INVALID_PARAMETER` on the runner; on Windows 11 here the same call returns an error the model agrees with. Whether the runner's system or its volume makes the difference is not known. The test no longer generates that rename on Windows, so the model's answer for it is no longer compared there. The run printed its last operations before the panic, and this rename is the last of them; the next run will confirm it or not.

## Revision 91 (core and CI: a failing check writes its trace)

`Options.trace_dir`, or `TARDIS_TRACE_DIR` in tests, names a directory where a failing check leaves a Chrome trace of the run as found and of the shrunk run, named for the test, the persona and the seed (`plan3.md` C6). With the variable only a reported failure leaves files, so a test that expects a failure and turns the report off leaves none. A replayed seed or token that fails writes its trace too, and a name that is taken gets a number. The test workflow sets it on its first test step and uploads the directory with the log of a failed job. A file holds the last `limits.trace_ring_len` events (64 unless the check raises it).

## Revision 90 (core: priority scheduling, measured against the random schedule)

`Options.schedule = .pct` picks the runnable task with the highest priority and lowers the running task at `pct_depth - 1` points of the run (PCT, `plan3.md` E5); `pct_steps` bounds where those points fall, and by default each run draws a length. When a runnable task has waited more than 4,096 steps the task above it is put below every other, which PCT as published does not do and a polling task needs. The run's own draws (its length, the change points, the first priorities) have keys of their own, and a new task's priority is the first draw on that task's keys. Shrinking, replay tokens, guided exploration, workers and warm starts are tested with it (`src/tests/pct_test.zig`, on an order that the random schedule does not reach in the same campaign); `exhaustive` ignores the option. `zig build bugbench-schedules` compares the two schedules on the bug benchmark and on two ordering bugs of opposite shape (`docs/measurements.md` §4): twenty-two of the 25 programs do not care, the random schedule is far better on the two that need a switch at one exact place, priorities alone find a bug that needs one long stretch, and the random schedule alone finds one that needs many switches. Every fixed program passes under priorities. The default stays `.random`.

An adversarial review of revisions 90 and 91 found eleven issues (`plan.md` §9.2), fixed before the commit. The worst: the priority draws were made on the root task's keys, which the body's task starts over from zero, so the first tasks' priorities were the same numbers as the run's length and change points, and the first table measured that. Also: two tasks above a third that take turns by blocking were never made to give way; the tests of guided exploration, workers, shrinking and warm starts under priorities could not tell them from the random schedule, and the warm-start test did not check that a warm start happened; a replayed token wrote no trace; trace files of two checks on the same seed overwrote each other; and wording.

## Revision 89 (release and documents: the package from a fresh project, baselines, two guides)

`scripts/package_check.sh` packs the committed tree, runs `zig fetch --save` on it from an empty project, wires the module as the tutorial says and runs `examples/wal_kv.zig` there (`plan3.md` B2); the project has a package cache of its own, and the check fails if anything but the library ends up in it (one of the library's own dependencies). It passes here, and the test workflow and the release command run it. The fetch from GitHub by URL is still untried. `zig build bugbench-baselines` prints, for each planted bug, whether a campaign still finds it with no faults, with no preemption, and with neither (F2, `docs/measurements.md` §3): eight of the 25 that run need fault injection, one needs preemption as such, three more need one or the other to move the schedule, and thirteen are found by what the test and the simulator still do (a power loss the test calls, sleeps, the choice of task at a blocking point). `docs/guide.md` is the user guide for the core, by task, and `docs/security.md` the separate guide for the security layer (C3, G3); the README lists the documents by reader. An adversarial review of revisions 88 and 89 found six issues (`plan.md` §9.2), all fixed: the new trap test asserted inside a body whose result a stray call replaces, so it proved less than it said; the package check looked for a dependency's name in a log that stays silent when the dependency is already cached; the "refused" line was printed only when the refused call was the first stray one; a baseline cell counted any failure of the buggy program as the planted bug; and stale comments and statements.

## Revision 88 (core: threads refused under the trap, replay lines that can be pasted, security notes in the trace)

Under `Options.trap_syscalls` a stray `clone`, `clone3`, `fork` or `vfork` is no longer made from inside the trap's signal handler, where a new thread would have begun its life: the caller gets `EAGAIN` (`std.Thread.spawn` without libc returns `error.ThreadQuotaExceeded`), the run fails with `error.StraySyscall`, and the report says how many calls were refused (`plan3.md` D5; tested on Linux without libc; system-call mode answers them `ENOSYS`, as before). Replay lines end in `TARDIS_REPLAY_COMMAND` when a build script sets it on a run step, and in `zig build test` otherwise; this repository sets it for `zig build test-examples` (C6). The note a security finding leaves in the trace is labelled with the kind of finding or where it was seen (C9).

## Revision 87 (examples and documents: the history checkers' planted bugs, and four guides)

Two examples give the history checkers a planted bug each (`plan3.md` A5): `examples/lin_register.zig` (a compare-and-swap on a register in a file that is not atomic, caught by `tardis.lin`) and `examples/write_skew.zig` (a commit that validates only the rows it wrote, caught by `tardis.elle` as G2). Both are in the bug benchmark and in the measured table: found in 20 of 20 campaigns of 200 iterations, `lin_register` in 13 of 20 at 10. New documents: `docs/reproducing.md` (from a failed CI run to the same failure locally; the test workflow now keeps `test.log` of a failed job as an artifact), `docs/trace.md` (reading a run as a timeline), `docs/housekeeping.md` (the build caches and a full drive), `docs/threads.md` (the decision on `std.Thread`: outside the simulation, not mapped; what to use, and what the trap catches). Issue templates, and a draft code of conduct for the owner to accept or change. An adversarial review of revisions 86 and 87 found six issues (`plan.md` §9.2), all fixed: `netInterfaceName` was a tenth-of-a-kind `unreachable` left reachable; copying a file was reported as two unmodelled calls the program never made; calls refused during `Options.setup` were lost on warm-started iterations; the option's comment said worker threads' setup is not trapped (it is); `docs/threads.md` showed a clean report for a started thread where a crash is likelier; and several statements in the new guides did not match the code.

## Revision 86 (core: refused calls are named, the trap in CI, network buffers on first use)

An `std.Io` operation the simulator does not model was answered by `std.Io.failing` with std's own error, and nothing said that the simulator had refused it or which call it was (`plan3.md` D1). Each such entry is now wrapped, but for five whose answer from std is a fine one or leads std to a simulated fallback (copying a file): the run remembers the names (`Env.refusedCalls`), and a failure report lists them. Twelve of the entries are `unreachable` in `std.Io.failing`, undefined behaviour in a release build; three of them a program can reach by asking about a terminal (`File.isTty`, `supportsAnsiEscapeCodes`, `enableAnsiEscapeCodes`), and these are now answered (no simulated file is a terminal). The other nine (`lockStderr`, `unlockStderr`, `netInterfaceName`, and the memory-map and child calls that need an earlier call to have succeeded) panic by name; that list is kept by hand. `Options.trap_syscalls` is now optional: left out, `TARDIS_TRAP_SYSCALLS=1` decides; `false` keeps a check untrapped whatever the environment says. With that the whole suite passes on Linux with the variable set (the filesystem differential test, which calls the real filesystem on purpose, opts out), and the first test step of the test workflow sets it (D3; the `-Dsec` and optimized steps have not been tried with it). The network's receive buffers (1 MiB with the default limits) are allocated when a run first opens a socket: a default simulator takes 1.4 MiB, from 2.4 MiB (E3). `zig build membench` has a row for 32 nodes, the most there can be (37.6 MiB).

## Revision 85 (release: a release command, the API reference, measured oracles)

`scripts/release.sh <version>` is a release in one command (`plan3.md` B7): it requires a clean tree, sets the version in `build.zig.zon`, runs the full verification, the bug benchmark, the benchmark budgets and the API reference build, writes the release notes from the CHANGELOG entries since the last release tag, commits and makes the annotated tag. It never pushes; `--dry-run` stops before the commit. `zig build docs` builds the API reference into `zig-out/docs` (C4), and `scripts/doc_check.py` lists public declarations without a doc comment in `src/root.zig` and the files a test author uses through it (`check/lin.zig`, `check/elle.zig`, `check/ledger.zig`, `search/fuzz.zig`, `sim/atomic.zig`): 76 were missing and are written, and CI runs both. `zig build bugbench-rates` prints which oracle catches each planted bug and in how many of 20 campaigns, at 10, 50 and 200 iterations (A5, `docs/measurements.md`); it fails if a campaign of 200 misses one. Two new examples give the determinism check and `sometimes` a planted bug each: `examples/hidden_state.zig` (a number kept in a global) and `examples/never_retried.zig` (a retry written against the wrong error). The non-determinism message now respects `Options.report`. An adversarial review of revisions 83 to 85 found twelve issues (`plan.md` §9.2); fixed, among others: a task that span while another was runnable was never stopped when no preemption was drawn, which hung the shrinker; a watch armed in `Options.setup` was lost on warm-started iterations; `tardis.elle` passed a history whose every cycle was longer than 16 transactions as serializable (now reported, `Report.cycle_too_long`); `env.fuzz` of `f80` or `f128` did not compile; and the release script could leave the version staged after a failed commit and took a mistyped option for a real release.

## Revision 84 (core: presets, and memory per simulator)

`Options.quick`, `.thorough` and `.nightly` are the defaults with a campaign of 20, 1,000 and 10,000 iterations (the last one guided), so a test can pass `.quick` as its whole options; `TARDIS_PRESET=quick|thorough|nightly` sizes every check whose `iterations` is the default 100 (written out or not; it cannot tell) and leaves the others alone (`plan3.md` C7). `zig build membench` prints the memory one simulator takes by option (E3, `docs/measurements.md`). The filesystem's page pool, 8 MiB per node allocated at the start, is now allocated in chunks of 256 KiB as runs first need them: the defaults go from 10.2 MiB to 2.4 MiB and eight nodes from 72.6 MiB to 10.6 MiB. Running out of host memory while growing a simulated disk panics; it is not reported to the program under test as a full disk.

## Revision 83 (core: liveness)

`Env.expectProgress(name, bound)` watches for a run that stays busy without getting anywhere (`plan3.md` F5): the run must call `Env.progress(name)` within the bound's virtual time and within its number of steps, or it fails with `error.Livelock`, at the point the bound runs out, replayable and shrunk like a deadlock. Before this such a run never ended. Steps are simulated operations (every point where the simulator may switch tasks) and scheduling points, so tasks that spin without sleeping are found although virtual time stands still, whether or not a preemption is drawn. Up to eight watches per run; `progressDone` ends one. `examples/livelock.zig` is the benchmark's case: two transfers that back off for the same time and retry in step (found in 19 of 20 campaigns of 10 iterations, shrunk to one decision). Limits: a task that loops without any simulated operation is not seen, and `sim`'s loop form does not watch. A deadlock or a livelock in a forked iteration (`Options.fork`) is now reported by the child as a failed run; before, the child returned through the parent's driver and went on as a second copy of the test process (the deadlock case is older than this revision).

## Revision 82 (core: non-blocking sockets and poll)

System-call mode emulates non-blocking sockets (`SOCK_NONBLOCK`, `accept4`'s flag, `fcntl(F_SETFL, O_NONBLOCK)`, `MSG_DONTWAIT`) and `poll` and `ppoll` (`plan.md` §9.2): a call that would wait fails with `EAGAIN`, a non-blocking `connect` says `EINPROGRESS` and leaves a failure for `SO_ERROR`, and `poll` gives Linux's events and waits in virtual time. The differential test covers them, and found ten more differences, fixed: among them a failed non-blocking `connect` leaving the socket shut down both ways and still "connecting" (`listen` refused; `shutdown` makes every later `connect` fail with `EINVAL`), UDP's `SHUT_RD` looked at only by a read that would wait, a successful `connect` keeping a `shutdown` recorded before it, and a UDP socket that connects again dropping what its old filter refused. `select` and `epoll` stay stray; `epoll` is now the tests' example of a call that is not emulated. An adversarial review of revisions 80 to 82 found thirteen issues (`plan.md` §9.2); ten are fixed, among them a `poll` or read on a datagram socket that a `shutdown` did not wake, a listener that lost its port when shut down with a connection open, a bound socket's slot reused during its `connect`, and corpus files shared by two checks of one test; three are documented. Finding a check's default corpus file name hung on Linux (the symbol lookup must use `std.debug`'s own I/O, as `sec/edges.zig` does); found by the Linux run.

## Revision 81 (core: the sockets against the kernel)

A differential test runs random sequences of socket calls in the simulator and on the kernel over loopback and compares every result (`src/tests/sysnet_diff_test.zig`, `plan.md` §9.2); 20,000 agree, the suite runs 5,000. It found twenty-odd differences from Linux, fixed in the emulator and the network model: ICMP port unreachable reported to a connected UDP socket, datagrams kept across a UDP `connect`, loopback source addresses, a stream `bind` that reserves its port (`Net` gains a bound state, `Sim.bindStream`, `listenBound`, `connectFrom`), the port and address a failed `connect` leaves, `shutdown` of unconnected sockets and of listeners, the errors of `accept`, `connect` and `send` in the wrong state, how a reset shows in `SO_ERROR` and `getpeername`, and data for a peer that shut down both ways resetting the connection (a model change that also applies to `env.io`). TCP's simultaneous open is not modelled.

## Revision 80 (core: a corpus kept between campaigns)

`Options.corpus_dir` (`TARDIS_CORPUS_DIR` in tests) keeps a file per `check` (`src/search/persist.zig`, `plan3.md` E4): the runs that failed, which the next campaign runs first until they pass, and the guided explorer's corpus, comparison constants and coverage. Named after the calling test and a hash of the options that shape the runs (`Options.corpus_name` overrides), written whole and renamed into place, checked by a hash. `TARDIS_EXPLORE=guided` turns guided exploration on for every check; the nightly workflow sets both. Campaigns of 300 iterations that keep the corpus open the five-digit lock in the 24th; starting empty, none does (`src/tests/corpus_test.zig`).

## Revision 79 (core: sockets in system-call mode)

System-call mode answers the socket calls of blocking IPv4 stream and datagram sockets from the simulated network (`src/sim/sysnet.zig`, `plan.md` §9.2), so a C library's network code meets the same latency, partitions, resets and crashes as `env.io` code. Non-blocking sockets, `poll` and `epoll`, `sendmsg` and `recvmsg`, and Unix-domain sockets stay stray; IPv6 fails with `EAFNOSUPPORT`. Tested with a TCP echo, datagrams and the error cases, all by system calls; writing them found two bugs in the first version (a short simulated write returned as a short `send`; `accept` choosing its slot before it waited), both fixed. The tests that used `socket` as their example of a call that is not emulated now use a Unix-domain socket. An adversarial review of revisions 75 to 79 found thirteen issues, fixed (`plan.md` §9.2): among them a real fault inside the vDSO that looped forever, glibc's vDSO `getrandom` going unanswered, a pointer argument taken for a socket descriptor, `shutdown` of a listener not waking `accept`, no `EPIPE`, a short stream `writev`, and the note on C state left behind firing for every server's parked daemon.

## Revision 78 (core: the vDSO, and C state a run leaves behind)

System-call mode answers the clock reads libc makes through the vDSO (`plan.md` §9.2), which are not system calls and so returned the host's time unreported. During a run the vDSO's code is `PROT_NONE`; a call into it faults, and the SIGSEGV handler of `tsc.zig` answers it as the matching system call and returns to the caller (`src/sim/vdso.zig`). Other threads and the harness get the kernel's answer; a thread caught inside the vDSO when a run begins makes the run fail with `StraySyscall`. Tested with `std.os.linux.clock_gettime`, and SQLite (musl's vDSO path) still passes. Also: a task dropped inside an emulated system call, where a C library may hold a lock, is noted with its seed, and later failure reports name that run as the likely cause when a failure does not replay (`tardis.droppedInCallSeed`). A report, not a cure.

## Revision 77 (release: the campaign workflow)

The campaign workflow does more of `plan3.md` I1. Each system's job splits the log into one report per failure, the way `tardis scan` reads it: the test, the error, the persona and seed, the last events of the trace and the replay line. It keeps them with the whole log, the replay tokens and a `failures.json` as the artifact `campaign-<os>`, and writes a table of the failures to the run's summary. A last job, the only one with `issues: write`, opens one issue per failure key (the test's name and its error, hashed into a marker in the issue's body), or comments on the open issue with that key; it labels them `tardis-campaign`, opens at most ten per run, and keeps any `@` from notifying anyone. It runs on this repository's nightly schedule and, when called from another repository or run by hand, only if `open_issues` is true. Each system restores and saves a directory in the Actions cache, named in `TARDIS_CORPUS_DIR`, with the history of the runs and the failures seen with their tokens. The file did not parse as YAML before: a `run:` line held `tardis: (`, and is now a block. Verified locally: every workflow parses; the two scripts ran under Node on a sample log and against a stubbed GitHub API, and found both failures with their names and tokens, marked them seen on a second run, commented on the open issue, opened a new one for the other key, and ignored a pull request with the same marker. Not done: the library does not read or write the corpus directory, so the guided explorer still starts empty each night (`plan3.md` E4); the workflow has not run on GitHub, so the cache, the artifacts and the issues are untried there.

## Revision 76 (core: C locks in system-call mode)

System-call mode answers `futex` (`plan.md` §9.2). Before, a C library that held a pthread mutex across an emulated call, with a second task waiting for the same mutex, put the one thread every fiber shares into a real `futex` wait, and the run hung with no report; revision 75 documented it and restricted C libraries to one task. Now a wait blocks only the calling task, on the simulator's futex for that address, a wake wakes simulated waiters, and a timed wait times out in virtual time; a deadlock between C locks is the simulator's reported deadlock. `FUTEX_WAIT`, `FUTEX_WAKE`, their bitset forms, `FUTEX_REQUEUE` and `FUTEX_CMP_REQUEUE` are emulated; priority inheritance and `FUTEX_WAKE_OP` stay stray. Tested by a three-state mutex held across file calls by two tasks, and by SQLite driven from two tasks with a database each; both hung before the change. A review found a lost wakeup (a timed wait reported a timeout after a wake had picked it, when its deadline had also passed) and a spent cancel; both are fixed. Still limits: a recursive mutex is owned by the thread, so it does not exclude a second task (share no SQLite connection between tasks); a C lock left held by a dropped task stays held into the next run, which reports a deadlock its seed alone does not reproduce; a lock shared with another real thread is outside the simulation.

## Revision 75 (core: a second mode)

System-call mode: `Options.mode = .syscalls` beside the default `.std_io` (`plan3.md` D9, `plan.md` §9.2). Linux on x86_64. The stray-call trap now answers the file calls, clock reads, sleeps and `getrandom` of the code under test from the simulation, by translating each into the simulator's own `std.Io` operation, so code that never sees an `Io` (direct `std.os.linux` calls, a C library) runs inside a run and meets a crash exactly as `env.dir` writes do. A simulated descriptor is a VFS handle with bit 30 set; a sleeping call yields its fiber from inside the signal handler. Verified: a differential test against the real kernel (20,000 random sequences of file calls agree; it found four differences, fixed); the same program by system call and by `std.Io` gives one trace hash and one result after a power loss; `examples/syscall_rename.zig`, the twenty-first program of the bug benchmark; and SQLite 3.46.0 built with its own VFS (`zig build test-sqlite -Dsqlite`), where a planted `synchronous=OFF` is found and shrunk to one decision and the documented gap of `synchronous=FULL` (a lost unlink of the journal rolls back a commit) to two. Not done: sockets, and clock reads that libc answers through the vDSO. Elsewhere the mode returns `error.SyscallModeUnsupported`. An adversarial review led to fixes: a stray is refused, never made for real, and fails a run whatever its result; libc's terminal checks are allowed; the processor count is one; open-file-description locks are not emulated; three open-flag cases now match Linux. It also found that a C library holding a pthread mutex across an emulated call can hang a run with several tasks: system-call mode supports C libraries driven from one task (`plan.md` §9.2).

## Revision 74 (core and CI)

The first CI logs read. On macOS (Apple Silicon, real APFS) and Windows every test passes but the filesystem differential test. Two differences it found on APFS are fixed for the `macos_apfs` persona: a hard link of a directory is refused before the destination is looked at, and a stat through a regular file is not found. The test can keep the sequence in progress in a file (`TARDIS_DIFF_TRACE`), since a real call that panics inside std takes the process with it, as one did on the Windows runner. First use on another of the owner's projects: a missing directory sync in `tigershark`'s checkpoint journal (`plan3.md` F3).

## Revision 73 (documents and CI)

The licence: BSD Zero Clause (0BSD). A draft report of the Windows register problem for the Zig project, unsent (`docs/disclosures/`). The test workflow publishes its failing lines as annotations; the campaign workflow's inputs are simplified after GitHub rejected the file. The plans record the first CI results on the current code: the evidence workflow and the Ubuntu tests pass, Windows and macOS fail in the test step.

## Revision 72 (core only)

The defect recorded in revision 71 is found and fixed: on 64-bit Windows a fiber switch did not preserve `xmm6` to `xmm15`, which a callee must. `std.Io.fiber.contextSwitch` names them as clobbered, and the compiler does not save them for the caller, so a value an optimized caller kept in one came back as another fiber's. `fiber.switchTo` saves and restores them; a test fills them from another fiber and fails without the fix. The skipped example test runs again.

## Revision 71 (examples only; one open defect recorded)

Four more examples in the bug benchmark, twenty in all, the first over the network besides `replica`: `udp_retry` (a retry applied twice), `udp_order` (trusting the order of arrival), `udp_no_timeout` (waiting for ever for a lost message) and `stale_read` (a stale read from a follower). Writing `udp_no_timeout` found a crash of the simulator on Windows in ReleaseFast after a deadlock with tasks waiting for datagrams; its cause is not established, the test is skipped in that configuration, and `plan.md` records what is known.

## Revision 70 (examples only)

Four more examples in the bug benchmark, sixteen in all: `in_place_rewrite`, `index_before_data` (two files made durable in the wrong order), `id_reuse` (an identifier handed out twice after a restart) and `short_read`.

## Revision 69 (documents only)

`docs/qualification.md`: the core's requirements traced to their tests, its known limits, the ways a wrong pass could happen and their guards, and the configurations the suite has passed on (`plan3.md` G5).

## Revision 68 (examples only)

Four more examples in the bug benchmark, twelve in all: `rename_unsynced` (renamed before the data is durable), `check_then_act`, `oom_partial` (a half-finished update when memory runs out) and `lease` (a duration measured with the wall clock).

## Revision 67 (examples only)

Four more examples in the bug benchmark: `dir_sync` (a missing fsync of a directory), `deadlock` (lock order), `short_write` (a short write taken for a whole one) and `error_leak` (a handle leaked on an error path). An example can name its own campaign options.

## Revision 66 (a program and CI)

`zig build bugbench` (`src/cmd/bugbench`): the bug benchmark over the four examples, with the plain run as a baseline, and a CI step that fails if a planted bug is missed or a fix fails (`plan3.md` F1, F2).

## Revision 65 (core and CI)

`TARDIS_CAMPAIGN_SALT` and `TARDIS_ITERATIONS_SCALE` (tests only): other seeds, and more iterations, for every `check` without editing a test. `.github/workflows/campaign.yml` runs a nightly campaign with them on Linux, macOS and Windows and can be called from another repository (`plan3.md` I1).

## Revision 64 (scripts and CI only)

A benchmark check (`scripts/bench_check.py`, `scripts/bench_budgets.txt`, a step of the test workflow on Linux): the benchmark numbers that follow from the seed must match exactly, and its timings must stay within generous budgets (`plan3.md` E1).

## Revision 63 (tests only)

A differential test of the network model against the real loopback interface (`src/tests/diff_net_test.zig`, `plan3.md` A4): five stream scenarios, compared on bytes, end of stream and errors. No model error found; one accepted difference on Windows, where a second listener on a taken port succeeds.

## Revision 62 (security layer; one constant in core)

`SecurityConfig.undefined_fill_is_data`: a program whose own data holds runs of 0xAA turns off the fingerprint that takes them for undefined memory (§3.7). The seam's parameter block grows from 16 words to 24.

## Revision 61 (tests and documents)

A self-fuzz test of the simulator (`src/tests/self_fuzz_test.zig`, `plan3.md` A6): random programs on every persona, every run executed twice and compared, on one worker and on four, with a durability check after power loss. `SECURITY.md`, and a weekly workflow that runs the suite against Zig's development branch. Under `-Dsec` the self-fuzz programs showed a false alarm of the security layer: eight bytes of 0xAA written by a program are taken for undefined memory (`plan3.md` A7).

## Revision 60 (core only)

The differential test of the filesystem model covers open handles (writes and reads at an offset, setting the length), exclusive create, `access`, and on POSIX hosts hard and symbolic links, over 2,000 sequences. Six more model errors found and fixed: an exclusive create onto a directory on NTFS, the order of a hard link's checks, creating a file through a dangling symbolic link, a directory renamed onto a symbolic link, a symbolic link renamed onto a directory, and a rename between two names of one file; and `access` on a path through a file now reports not found, as std does (`plan3.md` A2).

## Revision 59 (core only)

A differential test of the filesystem model against the real filesystem (`src/tests/diff_fs_test.zig`, `plan3.md` A2): random operation sequences run on both, every result compared. Two model errors found and fixed: on NTFS a path that goes through a regular file is not found (the model said not a directory), and on POSIX personas a rename onto a directory the source lives under is not empty (the model said is a directory).

## Revision 58 (examples and documents)

A fourth example, `replica`: three simulated machines, and a replica left behind by a partition. `docs/stability.md` (what may change between releases, and what a seed is promised to mean), `CONTRIBUTING.md`, and a plain statement at the top of `plan2.md` §1.1 and in the README that the security layer is not certified or qualified under any standard.

## Revision 57

An adversarial review of revisions 52 to 56 and its fixes: the virtual counter's fault handler is installed once however many workers start, looks at the faulting instruction only for the kind of fault `rdtsc` raises, and cannot recurse; the race detector keeps each access's node with the access, so a reused task slot no longer moves old accesses to another node; a copy or fill of no bytes is not an access; `tardis.sim`'s loop form ends the security layer's run. The race detector takes a read from a file or a socket as coming after earlier writes by the same node's tasks (§4.5), and a block shrunk in place has its guard at the new end in the shadow (§3.8). Three examples with planted bugs and fixes (`examples/`, `zig build test-examples`), a tutorial (`docs/tutorial.md`), and `plan3.md`, the plan for getting to a release. The evidence workflow uploads each bundle's SARIF under its own category. The revision history moved from the header of `plan2.md` to this file.

## Revision 56 (build and security layer)

`addInstrumentedObject` in `build.zig` wires an instrumented object into a test in one call; the per-access cost is measured and its lookup cut (§3.8); a test workflow runs the suite on Linux, macOS and Windows (`plan.md` §10).

## Revision 55 (core only)

`Options.virtual_tsc` answers `rdtsc` and `rdtscp` with the run's virtual time on Linux x86_64 (`plan.md` §9 M6).

## Revision 54 (security layer only)

Lock order for `std.Io.Mutex` in instrumented code (§4.6). The sanitizer runtime sees a 32-bit atomic go from zero to non-zero and back, treats it as a lock, and two of them taken in both orders are CWE-833.

## Revision 53

A happens-before data-race detector for instrumented code (§4.5). Core tells the layer what orders tasks through a new optional seam hook (`task_sync`: spawn, wake, await), the sanitizer's atomic callbacks order what a mutex guards, and two unordered accesses to one address, one of them a store, are CWE-362.

## Revision 52 (security layer only)

Shadow memory for code built with the sanitizer's callbacks (§3.8): a write or read past an allocation's end and a use after free are findings at the access. The claim that Zig emits no load or store callbacks was wrong and is corrected (§3.6, `plan.md` E3, Open items).

## Revision 51 (core only)

The filesystem's reset rewrites only the pages a run took, which takes an empty run from 4.4 µs to 1.6 µs (`plan.md` §10); the evidence workflow's revision check is fixed after a local dry run.

## Revision 50 (benchmark and reports only)

The exhaustive search is benchmarked, which settles snapshot restore as a no-go; `rdtsc` trapping, vector clocks and shadow memory are reported (`plan.md` §9 M6, Open items).

## Revision 49 (core only)

Warm restore copies only the page slots in use; the flight recorder is reported as a no-go (`plan.md` §9 M5, M6).

## Revision 48 (core only)

`Options.trap_syscalls` fails a run whose code makes a real system call, on Linux x86_64 (`plan.md` §9 M6).

## Revision 47 (core only)

Warm starts from an in-process snapshot of what setup left, 5 to 32 times faster than re-running setup (`plan.md` §9 M5).

## Revision 46 (core only)

`tardis.atomic.Value`, atomics with store buffers under simulation (`plan.md` §9 M6).

## Revision 45 (core only)

`tardis.traceJson` writes a run as a Chrome trace for Perfetto (`plan.md` §9 M6).

## Revision 44

State merging in the exhaustive search. Core keeps, per node and per datagram inbox, a hash of what it has seen, and `ExhaustiveOptions.merge` stops extending an execution at a state another one already reached (§7.2); the repository gets a `README.md`.

## Revision 43

The Spectre-v1 gadget shape. After a marked bounds check, a load whose address follows the value an earlier, index-addressed load returned is CWE-1037, in instrumented C and in Zig code that names its loads (§6.3).

## Revision 42 (core only)

The fork server has a libc backend, for macOS and the BSDs (`plan.md` §9 M5).

## Revision 41 (core only)

The multi-core scaling question is settled by a process-versus-worker benchmark (`plan.md` §9 M5).

## Revision 40

Zig's edge counters guide exploration. In an instrumented build every edge a run ran is a coverage feature, so guided exploration gets through code that does no I/O (§7.1, `plan.md` §9 M3).

## Revision 39

Decisions in C are recorded for MC/DC through `tardis_sec_mcdc` and the `TARDIS_SEC_VECTOR` macros, in the same table as Zig's (§7.1); core gets fuzzy replay (`plan.md` §9 M3).

## Revision 38 (core only)

A timer heap and select-by-halving in the scheduler, decided by a new scaling benchmark (`plan.md` §4.2, §4.4).

## Revision 37 (core only)

The shrinker cuts chunks in draw order (`plan.md` §9 M3).

## Revision 36 (core only)

A guard page below every fiber stack (`plan.md` §4.1).

## Revision 35

Glitch sites without an `env`. `tardis_sec.criticalEql` wraps `std.crypto.timing_safe.eql`, and C marks a check with `TARDIS_SEC_CRITICAL(cond)`; both may be inverted as one skipped compare (§7.4).

## Revision 34

Partial-order reduction in the exhaustive search. Core logs what each scheduling step touches outside its node, and `ExhaustiveOptions.reduce` stops extending an execution that runs two commuting steps in the order the search also covers the other way: the 3-node vote model needs 3,073 executions instead of 9,216, with the same verdicts and the same set of outcomes (§7.2).

## Revision 33

Comparison feedback for Zig conditions. `mcdc.compare(a, op, b)` offers the value a condition compares against to guided exploration, so a campaign completes the MC/DC of a decision behind a 32-bit match; `mcdc.json` names, per gap, the vector to test next, or says that no test can show the condition; the header also wraps `execl`, `execlp`, `execle`, `posix_spawn` and `posix_spawnp` (§7.1, §5.2).

## Revision 32

C process starts. The header also wraps `popen`, `execv`, `execvp` and `execve`, and every C process start (with `system`) now goes through the same check as a simulated spawn, so it is CWE-272 from a sandbox without `allow_process_spawn`; the sink sums of the audit log are tested in one process, through the fork server and on four worker processes (§5.2).

## Revision 31

The taint sink audit log. Every taint check (path, command, format string, SQL) is counted per counted run, summed by the campaign (the fork server carries them too), and written with each distinct hit to `sinks.json` in the evidence bundle (§5.2, §7.5).

## Revision 30

Comparison feedback. Instrumented C's edges are coverage features for guided exploration, and the constants it compares against reach core's mutator through a new optional seam hook (`tokens`), so exploration gets past a 32-bit magic-number check in 25 iterations (§7.1).

## Revision 29

Memory access patterns for instrumented C. With `trace-loads` and `trace-stores`, the cache set of every C load and store (address bits 6–11) joins the dual-execution trace, so a table lookup indexed by a secret is a timing leak; both runs now read their inputs from one fixed buffer (§6.3).

## Revision 28

The tracer for instrumented C. `tardis_sec.exportCoverage()` provides clang's SanitizerCoverage callbacks; C built with `-fsanitize-coverage=trace-pc,trace-cmp,trace-div` adds its edges and divisor widths to the traces `assertConstantTime` and `assertNonInterference` compare, and keeps the constants it compares against (§6.3).

## Revision 27

The C shims. `src/sec/c/tardis_sec.h` wraps `printf`/`snprintf` (CWE-134), `system` (CWE-78), `sqlite3_prepare_v2`/`sqlite3_exec` (CWE-89) and `pthread_mutex_lock`/`unlock` (lock order, CWE-833) for C code linked into a test, which exports the functions they call with `tardis_sec.exportC()` (§5.2, §4.2).

## Revision 26

`enterSandbox` is enforced, and process spawns are a taint sink. Core reports `connect`, `listen`, `bind`, `std.process.spawn` and `replace` through a new seam hook (`capability`); after a node's `enterSandbox`, a capability its policy dropped, or a path outside its prefixes, is CWE-272, and received bytes in a spawn's argv are CWE-78 (§5.2).

## Revision 25

Redzones and the reuse FIFO in core's heap. Every allocation is followed by a 16-byte guard and every freed block waits in a 4,096-slot FIFO, with or without `tardis_sec`; the engine reports a changed guard at free (CWE-787) and guard bytes at egress (CWE-125) (§3.5).

## Revision 24

Lock call sites in core for file locks. Core reports `File.lock`, `unlock` and the close of a locked handle through a new seam 3 hook `file_lock`, and each locked file gets its own lock class, so plain programs get lock-order checks (§4.2).

## Revision 23

Ingress taint and the VFS path sink. Received network bytes are tainted by content until `markSanitized`; a path holding them when it is opened, created, deleted or renamed is CWE-22, through a new seam 3 hook `path` (§3.7, §5.2).

## Revision 22

Length desynchronization in flight. `Spec.desyncFrame(delta, fix_checksum)` is a `twoFaced` rewrite that changes a frame's length claim and keeps its bytes, so a shortened frame smuggles its tail past a parser that reads frames back to back (§4.4).

## Revision 21

The replay pool. `replayer(node, peers)` records the datagrams a node sends and delivers an old one again before a later one, through a new seam 3 hook `replay`; the recording outlives a peer's reboot (§4.4).

## Revision 20

A two-faced node's rewrite applies to its stream writes too, one segment at a time and keeping the length, through a new seam 3 hook `stream` (§4.4).

## Revision 19

A won check-to-use race can also replace the file with an empty directory (`vfs_toctou_swaps.directory`, off by default), which drives the program into its error path at the open (§4.4).

## Revision 18

A won check-to-use race can also swap in a hard link or replace the path's parent directory with a symlink; seam 3's `vfs_op` returns the kind of swap, and `vfs_toctou_swaps` chooses which (§4.3, §4.4).

## Revision 17

The NTFS and APFS name-confusion personas. Core's `windows_ntfs` drops trailing dots and spaces and `::$DATA` and answers to 8.3 short names; `macos_apfs` treats composed and decomposed Latin-1 letters as one name; `tardis_sec.pathConfusions` generates the confusable spellings of a name per persona (§4.3).

## Revision 16

Dead-edge lines can be justified in the source, with a `// tardis-deactivated: <reason>` comment; the bundle carries the reason, SARIF makes the line a note, and a justified line that ran is reported as stale (§7.1).

## Revision 15

Made the manifest count staged changes, read from git's object store (loose objects and packs with their deltas) without running `git` (§7.5).

## Revision 14

Added dead edges from Zig's `-ffuzz` counters. `zig build evidence -Dedges` builds the campaigns with edge counters, and each bundle lists the certified code its campaign never ran (§7.1).

## Revision 13

Made the manifest count tracked files changed since the index, read from `.git/index` (§7.5).

## Revision 12

Added certification through fork worker processes, which forward their children's security tallies to the main process (§7.5).

## Revision 11

Added seam 4's emitter. Core calls `campaign_end` when `check` returns, and `tardis_sec` writes a failed check's SARIF, located at the test's call (§2.1, §8.2).

## Revision 10

Added certification through the fork server. A forked child sends its run's security tallies back through seam 4's `fork_export`/`fork_import` (§2.1, §7.5).

## Revision 9

Made the manifest record the git revision of each named repository, read from `.git` without running `git` (§7.5).

## Revision 8

Added MC/DC per requirement and the dead-code list (§7.1, §7.5).

## Revision 7

Added certification campaigns on several workers and through the fork server, with evidence that does not depend on the worker count (§7.5).

## Revision 6

Added seam 4 (§2.1, §8.2): the shrinker keeps a security counterexample only while the same finding reproduces, and `TARDIS_SEC=1` attaches the layer to every `check` in a build.

## Revision 5 (week 16 of §8.7)

Added certification campaigns that never stop early, the persisted requirement registry, signed evidence bundles with an independent verifier, SARIF in CI, and Example 2 running (§2.4, §7.5, §7.6, §8.5).

## Revision 4

Added amplification, MC/DC and exhaustive exploration (§6.1, §7.1, §7.2).

## Revision 3

Pillars II–III (§4.4).

## Revision 2

The security seam in core (§2.2) and Pillar I by content tracking (§3.7).
