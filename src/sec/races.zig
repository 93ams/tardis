//! Pillars II and III state for the live engine (plan2.md §4, §5.1):
//! lock order per task, repeated reads of shared memory, check-to-use
//! pairs on paths, the equivocating node and the replayer. Fixed capacities, reset per
//! run, no allocation.

const std = @import("std");
const assert = std.debug.assert;
const tardis = @import("tardis");

pub const lock_classes_max = 256;
pub const held_max = 64;
pub const fetches_max = 64;
pub const checks_max = 32;
pub const target_bytes_max = 256;
/// Lock classes from `file_lock_class_first` up are given to files as they
/// are first locked in a run, one per (node, inode); `Mutex` classes stay
/// below it.
pub const file_lock_class_first = 192;
pub const file_lock_classes = lock_classes_max - file_lock_class_first;
/// Classes from `c_lock_class_first` to `file_lock_class_first` are given
/// to C mutexes (the C shims) and to lock-shaped atomics of instrumented
/// code (§4.6) as they are first locked in a run, one per
/// (node, address).
pub const c_lock_class_first = 128;
pub const c_lock_classes = file_lock_class_first - c_lock_class_first;
/// Frames the replayer keeps, and the bytes of each (longer frames are not
/// recorded).
pub const replay_frames_max = 16;
pub const replay_frame_bytes_max = 256;
const row_words = lock_classes_max / 64;

pub const Held = struct { task: u16, class: u16 };
pub const Fetch = struct { addr: usize, task: u16 };
pub const Check = struct { task: u16, key: u64 };

/// Rewrites a payload in flight. Returns the new length in `out`, or null
/// to leave this datagram alone.
pub const MutateFn = *const fn (payload: []const u8, out: []u8) ?usize;

pub const Equivocator = struct {
    /// The node whose datagrams are rewritten (it behaves two-faced).
    node: tardis.NodeId,
    /// Peers that receive the rewritten version; the rest get the original.
    peers: u32,
    mutate: MutateFn,
};

/// An attacker on the wire that records the frames `node` sends to `peers`
/// and later delivers an old one again (§5.1). The pool belongs to the run,
/// not to a node, so it survives the receiver's reboot.
pub const Replayer = struct {
    node: tardis.NodeId,
    peers: u32,
};

pub const Frame = struct {
    peer: tardis.NodeId,
    len: u16,
    bytes: [replay_frame_bytes_max]u8,
};

pub const State = struct {
    /// `order[a]` bit b: a was held while b was taken (transitively closed).
    order: [lock_classes_max][row_words]u64,
    held: [held_max]Held,
    held_len: u8,
    fetches: [fetches_max]Fetch,
    fetches_len: u8,
    fetches_next: u8,
    checks: [checks_max]Check,
    checks_len: u8,
    checks_next: u8,
    target: [target_bytes_max]u8,
    target_len: u16,
    /// The directory a parent swap points at.
    dir_target: [target_bytes_max]u8,
    dir_target_len: u16,
    equivocator: ?Equivocator,
    replayer: ?Replayer,
    /// The files given lock classes this run, in first-locked order.
    file_classes: [file_lock_classes]struct { node: tardis.NodeId, inode: u32 },
    file_classes_len: u16,
    c_classes: [c_lock_classes]struct { node: tardis.NodeId, addr: usize },
    c_classes_len: u16,
    /// The replayer's recorded frames, oldest first; when full, the oldest
    /// is overwritten (`pool_next`).
    pool: [replay_frames_max]Frame,
    pool_len: u8,
    pool_next: u8,
    /// Counters for reports and tests.
    double_fetches: u32,
    toctou_swaps: u32,
    mutations: u32,
    replays: u32,

    pub fn reset(st: *State) void {
        @memset(&st.order, @splat(0));
        st.held_len = 0;
        st.fetches_len = 0;
        st.fetches_next = 0;
        st.checks_len = 0;
        st.checks_next = 0;
        st.target_len = 0;
        st.dir_target_len = 0;
        st.equivocator = null;
        st.replayer = null;
        st.file_classes_len = 0;
        st.c_classes_len = 0;
        st.pool_len = 0;
        st.pool_next = 0;
        st.double_fetches = 0;
        st.toctou_swaps = 0;
        st.mutations = 0;
        st.replays = 0;
    }

    // --- lockdep (§4.2) ---------------------------------------------------

    /// Records that `task` takes `class`. Returns a class `task` holds that
    /// some task has taken *after* `class` before: an order inversion.
    pub fn acquire(st: *State, task: u16, class: u16) ?u16 {
        assert(class < lock_classes_max);
        var inversion: ?u16 = null;
        for (st.held[0..st.held_len]) |h| {
            if (h.task != task or h.class == class) continue;
            if (bitSet(st.order[class], h.class)) inversion = h.class;
            st.addEdge(h.class, class);
        }
        if (st.held_len < held_max) {
            st.held[st.held_len] = .{ .task = task, .class = class };
            st.held_len += 1;
        }
        return inversion;
    }

    pub fn release(st: *State, task: u16, class: u16) void {
        var i: usize = st.held_len;
        while (i > 0) {
            i -= 1;
            const h = st.held[i];
            if (h.task != task or h.class != class) continue;
            st.held[i] = st.held[st.held_len - 1];
            st.held_len -= 1;
            return;
        }
    }

    fn addEdge(st: *State, a: u16, b: u16) void {
        if (bitSet(st.order[a], b)) return;
        var row_b = st.order[b];
        setBit(&row_b, b);
        for (&st.order, 0..) |*row, x| {
            if (x == a or bitSet(row.*, a)) {
                for (row, row_b) |*w, rb| w.* |= rb;
            }
        }
    }

    fn bitSet(row: [row_words]u64, i: u16) bool {
        return row[i / 64] & (@as(u64, 1) << @as(u6, @truncate(i))) != 0;
    }

    fn setBit(row: *[row_words]u64, i: u16) void {
        row[i / 64] |= @as(u64, 1) << @as(u6, @truncate(i));
    }

    // --- double fetch (§4.1) ----------------------------------------------

    /// A read of shared word `addr` by `task`. True when `task` read it
    /// before: the second read of a double fetch.
    pub fn fetch(st: *State, addr: usize, task: u16) bool {
        for (st.fetches[0..st.fetches_len]) |f| {
            if (f.addr == addr and f.task == task) {
                st.double_fetches += 1;
                return true;
            }
        }
        st.fetches[st.fetches_next] = .{ .addr = addr, .task = task };
        st.fetches_next = @intCast((@as(usize, st.fetches_next) + 1) % fetches_max);
        if (st.fetches_len < fetches_max) st.fetches_len += 1;
        return false;
    }

    // --- check-to-use pairs (§4.3) ------------------------------------------

    pub fn pathKey(dir: u32, path: []const u8) u64 {
        return std.hash.Wyhash.hash(dir, path);
    }

    pub fn noteCheck(st: *State, task: u16, key: u64) void {
        for (st.checks[0..st.checks_len]) |c| if (c.task == task and c.key == key) return;
        st.checks[st.checks_next] = .{ .task = task, .key = key };
        st.checks_next = @intCast((@as(usize, st.checks_next) + 1) % checks_max);
        if (st.checks_len < checks_max) st.checks_len += 1;
    }

    /// A use of a path: true (and the pair is consumed) when `task`
    /// checked the same path first.
    pub fn takeCheck(st: *State, task: u16, key: u64) bool {
        for (st.checks[0..st.checks_len], 0..) |c, i| {
            if (c.task != task or c.key != key) continue;
            st.checks[i] = st.checks[st.checks_len - 1];
            st.checks_len -= 1;
            st.checks_next = st.checks_len % checks_max;
            return true;
        }
        return false;
    }

    pub fn targetSlice(st: *const State) ?[]const u8 {
        if (st.target_len == 0) return null;
        return st.target[0..st.target_len];
    }

    /// The lock class of a file, given on first use; null once all file
    /// classes are taken (that file's locks are then not checked).
    pub fn fileClass(st: *State, node: tardis.NodeId, inode: u32) ?u16 {
        for (st.file_classes[0..st.file_classes_len], 0..) |f, i| {
            if (f.node == node and f.inode == inode) return @intCast(file_lock_class_first + i);
        }
        if (st.file_classes_len == file_lock_classes) return null;
        st.file_classes[st.file_classes_len] = .{ .node = node, .inode = inode };
        st.file_classes_len += 1;
        return @intCast(file_lock_class_first + st.file_classes_len - 1);
    }

    /// The lock class of a C mutex, given on first use; null once all C
    /// classes are taken.
    pub fn cLockClass(st: *State, node: tardis.NodeId, addr: usize) ?u16 {
        for (st.c_classes[0..st.c_classes_len], 0..) |c, i| {
            if (c.node == node and c.addr == addr) return @intCast(c_lock_class_first + i);
        }
        if (st.c_classes_len == c_lock_classes) return null;
        st.c_classes[st.c_classes_len] = .{ .node = node, .addr = addr };
        st.c_classes_len += 1;
        return @intCast(c_lock_class_first + st.c_classes_len - 1);
    }

    /// The class `cLockClass` gave `addr`, if it gave one.
    pub fn cLockClassKnown(st: *const State, node: tardis.NodeId, addr: usize) ?u16 {
        for (st.c_classes[0..st.c_classes_len], 0..) |c, i| {
            if (c.node == node and c.addr == addr) return @intCast(c_lock_class_first + i);
        }
        return null;
    }

    // --- replay pool (§5.1) -------------------------------------------------

    /// Records a frame sent to `peer` (frames too long to keep are skipped).
    pub fn recordFrame(st: *State, peer: tardis.NodeId, bytes: []const u8) void {
        if (bytes.len > replay_frame_bytes_max) return;
        const f = &st.pool[st.pool_next];
        f.peer = peer;
        f.len = @intCast(bytes.len);
        @memcpy(f.bytes[0..bytes.len], bytes);
        st.pool_next = @intCast((@as(usize, st.pool_next) + 1) % replay_frames_max);
        if (st.pool_len < replay_frames_max) st.pool_len += 1;
    }

    /// How many recorded frames were sent to `peer`.
    pub fn framesFor(st: *const State, peer: tardis.NodeId) usize {
        var n: usize = 0;
        for (st.pool[0..st.pool_len]) |*f| n += @intFromBool(f.peer == peer);
        return n;
    }

    /// The `i`th recorded frame sent to `peer` (`i < framesFor(peer)`).
    pub fn frameFor(st: *const State, peer: tardis.NodeId, i: usize) []const u8 {
        var k: usize = 0;
        for (st.pool[0..st.pool_len]) |*f| {
            if (f.peer != peer) continue;
            if (k == i) return f.bytes[0..f.len];
            k += 1;
        }
        unreachable;
    }

    pub fn dirTargetSlice(st: *const State) ?[]const u8 {
        if (st.dir_target_len == 0) return null;
        return st.dir_target[0..st.dir_target_len];
    }
};

test "lockdep: AB-BA across two tasks, and the transitive case" {
    var st: State = undefined;
    st.reset();
    // Task 1: A then B.
    try std.testing.expectEqual(@as(?u16, null), st.acquire(1, 1));
    try std.testing.expectEqual(@as(?u16, null), st.acquire(1, 2));
    st.release(1, 2);
    st.release(1, 1);
    // Task 2: B then A, never at the same time as task 1: still inverted.
    try std.testing.expectEqual(@as(?u16, null), st.acquire(2, 2));
    try std.testing.expectEqual(@as(?u16, 2), st.acquire(2, 1));
    st.release(2, 1);
    st.release(2, 2);

    st.reset();
    _ = st.acquire(1, 1);
    _ = st.acquire(1, 2);
    st.release(1, 2);
    _ = st.acquire(1, 3); // 1 -> 3
    st.release(1, 3);
    st.release(1, 1);
    _ = st.acquire(2, 2);
    _ = st.acquire(2, 3); // 2 -> 3
    st.release(2, 3);
    st.release(2, 2);
    _ = st.acquire(3, 3);
    try std.testing.expectEqual(@as(?u16, 3), st.acquire(3, 1)); // 3 -> 1 against 1 -> 3
}

test "double fetch and check-to-use bookkeeping" {
    var st: State = undefined;
    st.reset();
    try std.testing.expect(!st.fetch(0x1000, 1));
    try std.testing.expect(!st.fetch(0x1000, 2)); // another task: not a double fetch
    try std.testing.expect(st.fetch(0x1000, 1));
    const k = State.pathKey(7, "upload/a.txt");
    st.noteCheck(1, k);
    try std.testing.expect(!st.takeCheck(2, k));
    try std.testing.expect(st.takeCheck(1, k));
    try std.testing.expect(!st.takeCheck(1, k)); // consumed
}
