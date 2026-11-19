//! The security seam (plan2.md §2.2): the calls core makes into an optional
//! security layer such as `tardis_sec`.
//!
//! Core knows nothing about what the layer checks. It reports allocations,
//! frees, heap wipes, and every byte that crosses an `std.Io` boundary
//! (network and file reads and writes). The layer answers egress and free
//! calls with a non-zero CWE number when it found a violation; core records
//! it in the trace and fails the run with
//! `error.SecurityViolation`, so the failure shrinks and replays like any
//! other.
//!
//! The hooks are dispatched at run time through one pointer that is null
//! without a security layer: one predictable branch per I/O operation or
//! allocation, which is noise next to the simulation work around it. Hooks on
//! individual loads and stores (instrumented C, `tardis_sec.load`/`store`)
//! never go through core, so they need no seam here.

const std = @import("std");

pub const NodeId = u8;

/// Core's heap leaves this many guard bytes after every allocation, with or
/// without a security layer (so attaching one never moves an address,
/// plan2.md §3.5), and fills them with `redzone_pattern`.
pub const redzone_bytes = 16;
/// Eight distinct bytes, twice: any 8 guard bytes in a row are a rotation
/// of the first eight.
pub const redzone_pattern: [redzone_bytes]u8 = redzone_period ++ redzone_period;
pub const redzone_period = [8]u8{ 0x5A, 0xC3, 0x96, 0x3C, 0xE1, 0x0F, 0xB4, 0x87 };

/// Where bytes enter or leave the program.
pub const Sink = struct {
    pub const Kind = enum(u8) { net_stream, datagram, file };

    kind: Kind,
    /// The node doing the I/O.
    node: NodeId,
    /// The other end for network sinks (the node itself for files).
    peer_node: NodeId,
    /// Socket slot or inode.
    id: u32,
};

/// Filesystem operations the layer sees (by role: a check, or a use).
pub const VfsOp = enum(u8) {
    /// Checks: `statFile`, `access`.
    stat,
    access,
    /// Uses: `openFile`.
    open,
    /// Uses seen only by the `path` hook: `createFile`, `deleteFile`, and
    /// `rename` (once for each path).
    create,
    delete,
    rename,
};

/// Capabilities a program can give up after its initialization (plan2.md
/// §5.2, `tardis_sec.enterSandbox`).
pub const Capability = enum(u8) {
    /// `connect` to a peer.
    net_connect,
    /// `listen` on a stream port or `bind` a datagram port.
    net_listen,
    /// `std.process.spawn`, or `std.process.replace` (core runs neither).
    process_spawn,
};

/// What an attacker who wins a check-to-use race does to the path before
/// the use (plan2.md §4.3).
pub const Swap = struct {
    pub const Kind = enum(u8) {
        /// The entry becomes a symlink to `target`.
        symlink,
        /// The entry becomes a hard link to the file at `target` (resolved
        /// from the directory the path is relative to): the path is still a
        /// regular file, so a second `lstat` does not see it.
        hard_link,
        /// The path's first component, a directory, is moved aside and
        /// becomes a symlink to the directory `target`: every later
        /// component resolves inside it, and no-follow checks of the last
        /// component do not see it.
        parent_symlink,
        /// The entry becomes an empty directory (`target` is unused): the
        /// open fails with `IsDir`, which tests how the program handles a
        /// use that fails after its check passed.
        directory,
    };
    kind: Kind,
    target: []const u8,
};

pub const Provider = struct {
    /// One instance per simulator (per worker thread), created with it.
    create: *const fn (gpa: std.mem.Allocator, params: Params) error{OutOfMemory}!*anyopaque,
    destroy: *const fn (gpa: std.mem.Allocator, ctx: *anyopaque) void,
    /// A run starts with this seed: forget per-run state.
    begin_run: *const fn (ctx: *anyopaque, seed: u64) void,
    /// `mem` was just handed to the program by node `node`'s heap. Empty
    /// after a shrink in place: `mem.ptr` is the block's new end, where
    /// its guard now stands.
    alloc: *const fn (ctx: *anyopaque, node: NodeId, mem: []u8) void,
    /// `mem` is about to be freed (or the tail of a shrink). The
    /// `redzone_bytes` after it are its guard, still as the program left
    /// them. Non-zero: the CWE of a violation.
    free: *const fn (ctx: *anyopaque, node: NodeId, mem: []u8) u16,
    /// Node `node`'s heap was wiped (crash or new run).
    heap_reset: *const fn (ctx: *anyopaque, node: NodeId) void,
    /// `bytes` were just filled by a read from `sink`.
    ingress: *const fn (ctx: *anyopaque, sink: Sink, bytes: []u8) void,
    /// `bytes` are about to be written to `sink`. Non-zero: the CWE of a
    /// violation.
    egress: *const fn (ctx: *anyopaque, sink: Sink, bytes: []const u8) u16,
    /// A filesystem operation on `path` relative to directory inode `dir`,
    /// before core performs it. For a use, a non-null result is the swap
    /// core makes first (an attacker winning a check-to-use race, plan2.md
    /// §4.3). A swap core cannot make (no such target, no space) is skipped.
    vfs_op: *const fn (ctx: *anyopaque, node: NodeId, op: VfsOp, dir: u32, path: []const u8) ?Swap,
    /// A path about to be used (open, create, delete, rename): a sink for
    /// untrusted bytes (plan2.md §5.2). Non-zero: the CWE of a violation.
    path: *const fn (ctx: *anyopaque, node: NodeId, op: VfsOp, path: []const u8) u16,
    /// The current task is taking a file lock on `inode` (`held` true,
    /// before it may wait) or dropping it (unlock, or close of the handle
    /// that held it): lock order across file locks (plan2.md §4.2). A
    /// `tryLock` is not reported.
    file_lock: *const fn (ctx: *anyopaque, node: NodeId, inode: u32, held: bool) void,
    /// The program on `node` is about to use `cap`; for `process_spawn`,
    /// `argv` is the command (a sink for untrusted bytes), otherwise empty.
    /// Core reports it before it checks anything else about the call, and
    /// the call then goes on as it would have. Non-zero: the CWE of a
    /// violation.
    capability: *const fn (ctx: *anyopaque, node: NodeId, cap: Capability, argv: []const []const u8) u16,
    /// A datagram about to be sent. A non-null result is the length of a
    /// replacement payload written to `out` (in-flight Byzantine mutation,
    /// plan2.md §5.1).
    datagram: *const fn (ctx: *anyopaque, sink: Sink, payload: []const u8, out: []u8) ?usize,
    /// A segment about to be pushed into a stream (one write's span, or
    /// part of it after a short write). True: `out[0..bytes.len]` holds the
    /// rewrite core sends instead. A stream has no message boundaries, so a
    /// rewrite keeps the length; `out` is at least `bytes.len` long.
    stream: *const fn (ctx: *anyopaque, sink: Sink, bytes: []const u8, out: []u8) bool,
    /// A datagram `payload` (after any rewrite) is about to be sent. A
    /// non-null result is the length of an extra datagram in `out` that
    /// core delivers to the same port first: an attacker replaying a frame
    /// it recorded earlier in the run (plan2.md §5.1). The layer may record
    /// `payload` for later replays.
    replay: *const fn (ctx: *anyopaque, sink: Sink, payload: []const u8, out: []u8) ?usize,
    /// The run's body has returned (before leak checks). Non-zero: the CWE
    /// of a violation found over the whole run (resource amplification).
    end_run: *const fn (ctx: *anyopaque) u16,
    /// Seam 4: a key for the run's first finding (same CWE, same kind of
    /// sink: the same bug), or 0. Called after `end_run` when the run failed
    /// with `error.SecurityViolation`; the shrinker keeps a candidate only
    /// while it reproduces the original run's key, so shrinking never trades
    /// one finding for another. Null: any security violation will do.
    finding_key: ?*const fn (ctx: *anyopaque) u64 = null,
    /// Comparison feedback (plan2.md §7.1): after a run, the constants the
    /// program compared against in it. Guided exploration offers them as
    /// raw values when it forces a decision, so an integer drawn by
    /// `env.fuzz` can take a value the program checks for. Null: none.
    tokens: ?*const fn (ctx: *anyopaque) []const u64 = null,
    /// Seam 4, fork server: in a forked child, after its run, the layer
    /// packs what it tallies per run into `out` and returns the length (0:
    /// nothing). The parent hands the bytes of each counted run (not the
    /// determinism re-run's) to `fork_import` on its own instance. Without
    /// these hooks a layer's per-run tallies die with the child.
    fork_export: ?*const fn (ctx: *anyopaque, out: []u8) usize = null,
    fork_import: ?*const fn (ctx: *anyopaque, bytes: []const u8) void = null,
    /// Seam 4, emitters: called once when `check` returns, on the instance
    /// of the simulator that ran (and, on failure, shrank) the campaign, so
    /// the layer can write artifacts (plan2.md §2.1).
    campaign_end: ?*const fn (ctx: *anyopaque, end: *const CampaignEnd) void = null,
    /// What orders one task's steps after another's (plan2.md §4.5), for
    /// a layer that tracks happens-before. Null: not wanted.
    task_sync: ?*const fn (ctx: *anyopaque, op: TaskSync, a: usize, b: usize) void = null,
};

pub const TaskSync = enum(u8) {
    /// Task `a` spawned task `b`.
    spawn,
    /// Task `a` woke task `b`.
    wake,
    /// Task `a` finished into `b`: a group's address, or `futureKey`
    /// of its own id. Whoever acquires `b` comes after it.
    release,
    /// Task `a` waited for `b` (as for `release`) and has its result.
    acquire,
};

/// The `TaskSync` key of the future of task `id`: odd, so never an
/// address a group or an atomic has.
pub fn futureKey(id: usize) usize {
    return id * 2 + 1;
}

/// What `campaign_end` is told.
pub const CampaignEnd = struct {
    /// `check`'s error, or null when it passed.
    err: ?anyerror,
    /// The return address of the `check` call: the test's call site, which
    /// the layer can resolve to a file and line through debug info.
    caller: usize,
    /// The shrunk replay token of the failure (empty when there is none).
    token: []const u8,
    iterations: u32,
};

/// The most a layer may send back from one forked run.
pub const fork_bytes_max = 64 * 1024;

/// Configuration words the layer interprets (copied by value into every
/// simulator, so worker threads need no shared state).
pub const Params = [16]u64;

/// `Options.security`: the layer and its configuration.
pub const Security = struct {
    provider: *const Provider,
    params: Params = @splat(0),
};

/// A provider's instance, held by core.
pub const Attached = struct {
    provider: *const Provider,
    ctx: *anyopaque,
};

/// Core's side: what a violation reported outside a VTable call (a free)
/// does to the run.
pub const ViolationSink = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, cwe: u16) void,
};
