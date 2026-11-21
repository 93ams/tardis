//! Transactional anomaly detection for list-append and register histories (plan §9 M4),
//! after Elle (Kingsbury & Alvaro, VLDB 2020).
//!
//! Transactions append values to per-key lists and read whole lists. Each
//! appended value must be unique per key. Because a read returns the whole
//! list, it reveals the order of every append before it, so the checker can
//! recover each key's version order and from it every dependency between
//! transactions:
//!
//! * ww: T1 appended the element right before T2's element;
//! * wr: T2 read a list whose last element T1 appended;
//! * rw: T1 read a list that T2's element would have extended (T1 did not
//!   see T2's write; an anti-dependency);
//! * rt (optional): T1 finished before T2 started (real time).
//!
//! A cycle in that graph is an anomaly, classified like Adya: G0 (ww only:
//! dirty write), G1c (ww/wr: circular information flow), G-single (exactly
//! one rw: read skew), G2 (several rw: write skew and friends), and
//! `realtime` (a cycle only with real-time edges: not strictly
//! serializable). Non-cycle anomalies: duplicate elements, reads that are
//! not prefixes of one another (incompatible order), G1a (reading an
//! aborted append) and G1b (reading an intermediate append).
//!
//! Read-write registers (`write` / `read_reg`) are checked too. A read names
//! its writer (values are unique per key), but a register read does not
//! reveal the version order, so it is inferred only where it is certain: a
//! transaction that read version `a` and then wrote `b`, and the initial
//! value before every write (see `registerEdges`). Register-only anomalies:
//! lost updates, internal inconsistency (a transaction not seeing its own
//! write, or two of its reads disagreeing) and garbage reads.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// How a transaction ended. `unknown`: the outcome was never learned, so its
/// writes may or may not be visible to others; its own reads are not checked.
pub const Status = enum(u8) { committed, aborted, unknown };

/// One operation of a transaction, with the result it observed. `append` and
/// `read` are for list-append keys, `write` and `read_reg` for register keys.
pub const Op = union(enum) {
    // List-append keys.
    append: struct { key: u64, value: u64 },
    read: struct { key: u64, values: []const u64 },
    // Read-write register keys (a key is used by one kind of op only).
    /// Values must be unique per key.
    write: struct { key: u64, value: u64 },
    /// `value` null: the key's initial value (never written).
    read_reg: struct { key: u64, value: ?u64 },
};

/// A recorded transaction: its operations in execution order, and the
/// history's logical clock at its `begin` (`start`) and `finish` (`end`).
/// The times are used only for real-time edges.
pub const Txn = struct {
    status: Status,
    ops: []const Op,
    start: u64,
    end: u64,
};

/// The transactions of one test run, in the order they finished. A
/// transaction's index in `txns` is the id that `Report` refers to.
pub const History = struct {
    arena: std.heap.ArenaAllocator,
    txns: std.ArrayList(Txn),
    clock: u64,

    /// An empty history. Everything recorded is allocated from an arena backed
    /// by `gpa`; release it with `deinit`.
    pub fn init(gpa: Allocator) History {
        return .{ .arena = .init(gpa), .txns = .empty, .clock = 0 };
    }

    /// Frees every recorded transaction. The history must not be used afterwards.
    pub fn deinit(h: *History) void {
        h.arena.deinit();
        h.* = undefined;
    }

    /// Call when a transaction starts; pass the result to `finish`.
    pub fn begin(h: *History) u64 {
        h.clock += 1;
        return h.clock;
    }

    /// Records a finished transaction (ops and read results are copied).
    pub fn finish(h: *History, start: u64, status: Status, ops: []const Op) !void {
        const a = h.arena.allocator();
        const copy = try a.alloc(Op, ops.len);
        for (ops, copy) |op, *c| {
            c.* = switch (op) {
                .append => op,
                .read => |r| .{ .read = .{ .key = r.key, .values = try a.dupe(u64, r.values) } },
                .write, .read_reg => op,
            };
        }
        h.clock += 1;
        try h.txns.append(a, .{ .status = status, .ops = copy, .start = start, .end = h.clock });
    }
};

/// The kinds of anomaly `check` reports (see the file header). The cycle
/// kinds `g0` to `realtime` are declared from most to least severe, and that
/// order decides which cycle a `Report` keeps.
pub const Anomaly = enum(u8) {
    duplicate_element,
    incompatible_order,
    aborted_read,
    intermediate_read,
    /// Registers: two committed transactions read the same version of a
    /// key and both wrote it.
    lost_update,
    /// A transaction's reads contradict its own earlier reads or writes.
    internal,
    /// A read of a value no transaction wrote.
    garbage_read,
    g0,
    g1c,
    g_single,
    g2,
    realtime,
};

/// The kind of a dependency edge between two transactions: write-write,
/// write-read, read-write (anti-dependency) or real time. See the file header.
pub const EdgeKind = enum(u8) { ww, wr, rw, rt };

/// What `check` should look for beyond plain serializability.
pub const Options = struct {
    /// Add real-time edges (check strict serializability, not just
    /// serializability).
    realtime: bool = false,
};

/// Capacity of a `Report`'s cycle buffer, in transactions. A longer cycle
/// is still an anomaly (`Report.cycle_too_long`), but it is not printed
/// and its kind is not worked out.
pub const cycle_max = 16;

/// The result of `check`: every kind of anomaly found, and one example cycle
/// if there was any. Holds no allocations.
pub const Report = struct {
    found: std.EnumSet(Anomaly) = .empty,
    /// The most severe cycle found: transaction indices and the kind of
    /// edge leaving each.
    cycle: [cycle_max]u32 = undefined,
    cycle_edges: [cycle_max]EdgeKind = undefined,
    cycle_len: usize = 0,
    cycle_kind: ?Anomaly = null,
    /// Some transactions lie on cycles, all longer than `cycle_max`: the
    /// anomaly is in `found` (as `g2`, or `realtime` when a real-time edge
    /// may be part of it; the true kind may be more severe) and there is
    /// no cycle to print for it.
    cycle_too_long: bool = false,

    /// True if no anomaly of any kind was found.
    pub fn ok(r: *const Report) bool {
        return r.found.count() == 0;
    }

    /// Prints the anomalies found and, if there is a cycle, each of its
    /// transactions with its operations and the edge leading to the next, to
    /// stderr. `h` must be the history this report was computed from.
    pub fn print(r: *const Report, h: *const History) void {
        std.debug.print("tardis: transactional anomalies:", .{});
        var it = r.found.iterator();
        while (it.next()) |a| std.debug.print(" {s}", .{@tagName(a)});
        std.debug.print("\n", .{});
        if (r.cycle_too_long) std.debug.print("tardis: some cycles are longer than {d} transactions and are not shown\n", .{cycle_max});
        if (r.cycle_kind) |k| {
            std.debug.print("tardis: {s} cycle:\n", .{@tagName(k)});
            for (r.cycle[0..r.cycle_len], r.cycle_edges[0..r.cycle_len]) |t, e| {
                std.debug.print("  T{d} ", .{t});
                for (h.txns.items[t].ops) |op| switch (op) {
                    .append => |ap| std.debug.print("[append {d} {d}]", .{ ap.key, ap.value }),
                    .read => |rd| std.debug.print("[read {d} {any}]", .{ rd.key, rd.values }),
                    .write => |w| std.debug.print("[w {d} {d}]", .{ w.key, w.value }),
                    .read_reg => |rd| if (rd.value) |v| std.debug.print("[r {d} {d}]", .{ rd.key, v }) else std.debug.print("[r {d} nil]", .{rd.key}),
                };
                std.debug.print("  --{s}->\n", .{@tagName(e)});
            }
        }
    }
};

const Edge = struct { from: u32, to: u32, kind: EdgeKind };
const Loc = struct { txn: u32, op: u32 };
const KeyValue = struct { key: u64, value: u64 };

/// Checks `h` for the anomalies described in the file header. Anomalies are
/// reported in the returned `Report`, not as errors: the only failure is
/// running out of memory. `gpa` is used for scratch memory only, all of
/// which is freed before returning.
pub fn check(gpa: Allocator, h: *const History, options: Options) !Report {
    var report: Report = .{};
    const txns = h.txns.items;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    // 1. Who appended each (key, value).
    var writer: std.AutoHashMapUnmanaged(KeyValue, Loc) = .empty;
    for (txns, 0..) |t, ti| {
        for (t.ops, 0..) |op, oi| switch (op) {
            .append => |ap| {
                const gop = try writer.getOrPut(a, .{ .key = ap.key, .value = ap.value });
                if (gop.found_existing) report.found.insert(.duplicate_element);
                gop.value_ptr.* = .{ .txn = @intCast(ti), .op = @intCast(oi) };
            },
            .read, .write, .read_reg => {},
        };
    }

    // 2. Each key's version order: the longest committed read, which every
    // other read must be a prefix of.
    var order: std.AutoHashMapUnmanaged(u64, []const u64) = .empty;
    for (txns) |t| {
        if (t.status != .committed) continue;
        for (t.ops) |op| switch (op) {
            .read => |rd| {
                if (hasDuplicate(rd.values)) report.found.insert(.duplicate_element);
                const gop = try order.getOrPut(a, rd.key);
                if (!gop.found_existing or rd.values.len > gop.value_ptr.len) gop.value_ptr.* = rd.values;
            },
            else => {},
        };
    }
    for (txns) |t| {
        if (t.status != .committed) continue;
        for (t.ops) |op| switch (op) {
            .read => |rd| {
                const longest = order.get(rd.key).?;
                if (!std.mem.startsWith(u64, longest, rd.values)) report.found.insert(.incompatible_order);
            },
            else => {},
        };
    }

    // 3. Edges.
    var edges: std.ArrayList(Edge) = .empty;
    var it = order.iterator();
    while (it.next()) |kv| {
        const key = kv.key_ptr.*;
        const vs = kv.value_ptr.*;
        var i: usize = 1;
        while (i < vs.len) : (i += 1) {
            const p = writer.get(.{ .key = key, .value = vs[i - 1] }) orelse continue;
            const q = writer.get(.{ .key = key, .value = vs[i] }) orelse continue;
            if (p.txn != q.txn) try edges.append(a, .{ .from = p.txn, .to = q.txn, .kind = .ww });
        }
    }
    for (txns, 0..) |t, ti| {
        if (t.status != .committed) continue;
        const r: u32 = @intCast(ti);
        for (t.ops) |op| switch (op) {
            .read => |rd| {
                const vs = order.get(rd.key).?;
                if (rd.values.len > 0) {
                    const last = rd.values[rd.values.len - 1];
                    if (writer.get(.{ .key = rd.key, .value = last })) |w| {
                        if (txns[w.txn].status == .aborted) report.found.insert(.aborted_read);
                        if (w.txn != r) {
                            if (!isLastAppend(txns[w.txn], w.op, rd.key)) report.found.insert(.intermediate_read);
                            try edges.append(a, .{ .from = w.txn, .to = r, .kind = .wr });
                        }
                    }
                }
                // The element this read did not see yet, if any.
                if (rd.values.len < vs.len and std.mem.startsWith(u64, vs, rd.values)) {
                    if (writer.get(.{ .key = rd.key, .value = vs[rd.values.len] })) |x| {
                        if (x.txn != r) try edges.append(a, .{ .from = r, .to = x.txn, .kind = .rw });
                    }
                } else if (rd.values.len == vs.len) {
                    // An append no read observed must come after every
                    // observed element (it would otherwise appear in the
                    // longest read), so this read did not see it either.
                    var wit = writer.iterator();
                    while (wit.next()) |w| {
                        if (w.key_ptr.key != rd.key or w.value_ptr.txn == r) continue;
                        if (txns[w.value_ptr.txn].status == .aborted) continue;
                        if (std.mem.indexOfScalar(u64, vs, w.key_ptr.value) != null) continue;
                        try edges.append(a, .{ .from = r, .to = w.value_ptr.txn, .kind = .rw });
                    }
                }
            },
            else => {},
        };
    }
    try registerEdges(a, txns, &report, &edges);
    if (options.realtime) {
        for (txns, 0..) |t1, i| {
            if (t1.status != .committed) continue;
            for (txns, 0..) |t2, j| {
                if (i == j or t2.status != .committed) continue;
                if (t1.end < t2.start) try edges.append(a, .{ .from = @intCast(i), .to = @intCast(j), .kind = .rt });
            }
        }
    }

    // 4. Cycles.
    const n: u32 = @intCast(txns.len);
    if (n == 0 or edges.items.len == 0) return report;
    const g = try Graph.init(a, n, edges.items);
    const scc = try g.tarjan(a);
    try classify(a, &g, scc, &report);
    return report;
}

fn hasDuplicate(vs: []const u64) bool {
    for (vs, 0..) |v, i| {
        for (vs[0..i]) |w| if (v == w) return true;
    }
    return false;
}

fn isLastAppend(t: Txn, op_index: u32, key: u64) bool {
    var i = t.ops.len;
    while (i > op_index + 1) {
        i -= 1;
        switch (t.ops[i]) {
            .append => |ap| if (ap.key == key) return false,
            else => {},
        }
    }
    return true;
}

fn isLastWrite(t: Txn, op_index: u32, key: u64) bool {
    for (t.ops[op_index + 1 ..]) |op| switch (op) {
        .write => |w| if (w.key == key) return false,
        else => {},
    };
    return true;
}

/// A version of a register key: a written value, or the initial value.
const Version = struct { key: u64, value: u64, initial: bool };

fn versionOf(key: u64, value: ?u64) Version {
    return .{ .key = key, .value = value orelse 0, .initial = value == null };
}

/// Register keys: infers what it can of each key's version order and adds
/// the dependency edges that follow.
///
/// Values are unique per key, so every read names its writer (wr). The
/// version order is not observable directly; it is known only where a
/// transaction read version `a` of a key and then wrote `b` (so `a` precedes
/// `b`), and the initial value precedes every write. From each known pair
/// `a -> b`: ww writer(a) -> writer(b), and rw from every reader of `a` to
/// writer(b). A reader of the initial value precedes every writer of the
/// key. Sound (no edge that is not implied by the history) but incomplete:
/// version orders no read-then-write reveals are not guessed.
fn registerEdges(a: Allocator, txns: []const Txn, report: *Report, edges: *std.ArrayList(Edge)) !void {
    var writer: std.AutoHashMapUnmanaged(KeyValue, Loc) = .empty;
    var writers_of: std.AutoHashMapUnmanaged(u64, std.ArrayList(u32)) = .empty;
    for (txns, 0..) |t, ti| {
        for (t.ops, 0..) |op, oi| switch (op) {
            .write => |w| {
                const gop = try writer.getOrPut(a, .{ .key = w.key, .value = w.value });
                if (gop.found_existing) report.found.insert(.duplicate_element);
                gop.value_ptr.* = .{ .txn = @intCast(ti), .op = @intCast(oi) };
                if (t.status == .aborted) continue;
                const list = try writers_of.getOrPut(a, w.key);
                if (!list.found_existing) list.value_ptr.* = .empty;
                const items = list.value_ptr.items;
                if (items.len == 0 or items[items.len - 1] != ti) try list.value_ptr.append(a, @intCast(ti));
            },
            else => {},
        };
    }
    if (writer.count() == 0) {
        // Reads of registers nobody wrote: only garbage reads to report.
        for (txns) |t| for (t.ops) |op| switch (op) {
            .read_reg => |rd| if (rd.value != null) report.found.insert(.garbage_read),
            else => {},
        };
        return;
    }

    const KeyState = struct { key: u64, own: ?u64 = null, external: ?Version = null };
    const Pair = struct { from: Version, to: u64 };
    var readers: std.AutoHashMapUnmanaged(Version, std.ArrayList(u32)) = .empty;
    var pairs: std.ArrayList(Pair) = .empty;
    var read_then_wrote: std.AutoHashMapUnmanaged(Version, u32) = .empty;
    var state: std.ArrayList(KeyState) = .empty;
    for (txns, 0..) |t, ti_usize| {
        if (t.status != .committed) continue;
        const ti: u32 = @intCast(ti_usize);
        state.clearRetainingCapacity();
        for (t.ops) |op| switch (op) {
            .read_reg => |rd| {
                const st = try keyState(KeyState, a, &state, rd.key);
                if (st.own) |w| {
                    // Must see its own latest write.
                    if (rd.value == null or rd.value.? != w) report.found.insert(.internal);
                    continue;
                }
                const v = versionOf(rd.key, rd.value);
                if (st.external) |e| {
                    // Repeated reads must agree.
                    if (!std.meta.eql(e, v)) report.found.insert(.internal);
                    continue;
                }
                st.external = v;
                const list = try readers.getOrPut(a, v);
                if (!list.found_existing) list.value_ptr.* = .empty;
                try list.value_ptr.append(a, ti);
                const value = rd.value orelse continue;
                const w = writer.get(.{ .key = rd.key, .value = value }) orelse {
                    report.found.insert(.garbage_read);
                    continue;
                };
                if (w.txn == ti) {
                    report.found.insert(.internal); // read its own write before making it
                    continue;
                }
                if (txns[w.txn].status == .aborted) report.found.insert(.aborted_read);
                if (!isLastWrite(txns[w.txn], w.op, rd.key)) report.found.insert(.intermediate_read);
                try edges.append(a, .{ .from = w.txn, .to = ti, .kind = .wr });
            },
            .write => |w| (try keyState(KeyState, a, &state, w.key)).own = w.value,
            else => {},
        };
        for (state.items) |st| {
            const own = st.own orelse continue;
            const from = st.external orelse continue;
            try pairs.append(a, .{ .from = from, .to = own });
            const gop = try read_then_wrote.getOrPut(a, from);
            if (gop.found_existing and gop.value_ptr.* != ti) report.found.insert(.lost_update);
            gop.value_ptr.* = ti;
        }
    }

    // Readers of the initial value precede every writer of the key.
    var rit = readers.iterator();
    while (rit.next()) |kv| {
        if (!kv.key_ptr.initial) continue;
        const ws = writers_of.get(kv.key_ptr.key) orelse continue;
        for (kv.value_ptr.items) |r| for (ws.items) |w| {
            if (r != w) try edges.append(a, .{ .from = r, .to = w, .kind = .rw });
        };
    }
    for (pairs.items) |p| {
        const to = writer.get(.{ .key = p.from.key, .value = p.to }).?.txn;
        if (p.from.initial) continue; // covered above
        if (writer.get(.{ .key = p.from.key, .value = p.from.value })) |from| {
            if (from.txn != to) try edges.append(a, .{ .from = from.txn, .to = to, .kind = .ww });
        }
        if (readers.get(p.from)) |rs| for (rs.items) |r| {
            if (r != to) try edges.append(a, .{ .from = r, .to = to, .kind = .rw });
        };
    }
}

fn keyState(comptime KeyState: type, a: Allocator, state: *std.ArrayList(KeyState), key: u64) !*KeyState {
    for (state.items) |*st| if (st.key == key) return st;
    try state.append(a, .{ .key = key });
    return &state.items[state.items.len - 1];
}

const Graph = struct {
    n: u32,
    /// Edges sorted by `from`; `offsets[v]..offsets[v+1]` are v's.
    edges: []Edge,
    offsets: []u32,

    fn init(a: Allocator, n: u32, unsorted: []const Edge) !Graph {
        const edges = try a.dupe(Edge, unsorted);
        std.mem.sort(Edge, edges, {}, struct {
            fn less(_: void, x: Edge, y: Edge) bool {
                return x.from < y.from;
            }
        }.less);
        const offsets = try a.alloc(u32, n + 1);
        @memset(offsets, 0);
        for (edges) |e| offsets[e.from + 1] += 1;
        for (1..n + 1) |i| offsets[i] += offsets[i - 1];
        return .{ .n = n, .edges = edges, .offsets = offsets };
    }

    fn out(g: *const Graph, v: u32) []const Edge {
        return g.edges[g.offsets[v]..g.offsets[v + 1]];
    }

    /// Iterative Tarjan. Returns the component id of each vertex.
    fn tarjan(g: *const Graph, a: Allocator) ![]u32 {
        const unvisited = std.math.maxInt(u32);
        const index = try a.alloc(u32, g.n);
        const low = try a.alloc(u32, g.n);
        const on_stack = try a.alloc(bool, g.n);
        const comp = try a.alloc(u32, g.n);
        @memset(index, unvisited);
        @memset(on_stack, false);
        var stack: std.ArrayList(u32) = .empty;
        const Frame = struct { v: u32, next_edge: u32 };
        var call: std.ArrayList(Frame) = .empty;
        var counter: u32 = 0;
        var comps: u32 = 0;
        for (0..g.n) |root_usize| {
            const root: u32 = @intCast(root_usize);
            if (index[root] != unvisited) continue;
            try call.append(a, .{ .v = root, .next_edge = g.offsets[root] });
            index[root] = counter;
            low[root] = counter;
            counter += 1;
            try stack.append(a, root);
            on_stack[root] = true;
            while (call.items.len > 0) {
                const f = &call.items[call.items.len - 1];
                const v = f.v;
                if (f.next_edge < g.offsets[v + 1]) {
                    const w = g.edges[f.next_edge].to;
                    f.next_edge += 1;
                    if (index[w] == unvisited) {
                        index[w] = counter;
                        low[w] = counter;
                        counter += 1;
                        try stack.append(a, w);
                        on_stack[w] = true;
                        try call.append(a, .{ .v = w, .next_edge = g.offsets[w] });
                    } else if (on_stack[w]) {
                        low[v] = @min(low[v], index[w]);
                    }
                    continue;
                }
                if (low[v] == index[v]) {
                    while (true) {
                        const w = stack.pop().?;
                        on_stack[w] = false;
                        comp[w] = comps;
                        if (w == v) break;
                    }
                    comps += 1;
                }
                _ = call.pop();
                if (call.items.len > 0) {
                    const parent = call.items[call.items.len - 1].v;
                    low[parent] = @min(low[parent], low[v]);
                }
            }
        }
        return comp;
    }
};

const KindMask = u8;

fn bit(k: EdgeKind) KindMask {
    return @as(KindMask, 1) << @intCast(@backingInt(k));
}

/// Shortest path `from` -> `to` inside component `c` using edge kinds in
/// `mask`; writes vertices (excluding `to`) and edge kinds into `report`'s
/// cycle buffer starting at `offset`. Returns the path length, or null.
fn bfs(a: Allocator, g: *const Graph, comp: []const u32, c: u32, from: u32, to: u32, mask: KindMask, report: *Report, offset: usize) !?usize {
    const parent = try a.alloc(u32, g.n);
    const parent_kind = try a.alloc(EdgeKind, g.n);
    const none = std.math.maxInt(u32);
    @memset(parent, none);
    var queue: std.ArrayList(u32) = .empty;
    try queue.append(a, from);
    parent[from] = from;
    var head: usize = 0;
    var found = false;
    outer: while (head < queue.items.len) : (head += 1) {
        const v = queue.items[head];
        for (g.out(v)) |e| {
            if (mask & bit(e.kind) == 0 or comp[e.to] != c) continue;
            if (e.to == to) {
                parent_kind[to] = e.kind;
                if (to != from) parent[to] = v else {
                    // Cycle back to the start: remember the last hop.
                    parent_kind[from] = e.kind;
                    queue.items[0] = v; // reuse slot 0 to hold the last vertex
                }
                found = true;
                break :outer;
            }
            if (parent[e.to] != none) continue;
            parent[e.to] = v;
            parent_kind[e.to] = e.kind;
            try queue.append(a, e.to);
        }
    }
    if (!found) return null;
    // Walk back from `to` to `from`.
    var path: [cycle_max]u32 = undefined;
    var kinds: [cycle_max]EdgeKind = undefined;
    var len: usize = 0;
    var v = if (to == from) queue.items[0] else parent[to];
    var k = parent_kind[to];
    while (true) {
        if (len == cycle_max) return null;
        path[len] = v;
        kinds[len] = k;
        len += 1;
        if (v == from) break;
        k = parent_kind[v];
        v = parent[v];
    }
    if (offset + len > cycle_max) return null;
    for (0..len) |i| {
        report.cycle[offset + i] = path[len - 1 - i];
        report.cycle_edges[offset + i] = kinds[len - 1 - i];
    }
    return len;
}

fn classify(a: Allocator, g: *const Graph, comp: []const u32, report: *Report) !void {
    // Component sizes.
    const sizes = try a.alloc(u32, g.n);
    @memset(sizes, 0);
    for (comp) |c| sizes[c] += 1;
    const ww = bit(.ww);
    const wwwr = ww | bit(.wr);
    const no_rt = wwwr | bit(.rw);
    const all = no_rt | bit(.rt);

    var best: ?Anomaly = null;
    for (0..g.n) |v_usize| {
        const v: u32 = @intCast(v_usize);
        const c = comp[v];
        if (sizes[c] < 2) continue;
        var kind: ?Anomaly = null;
        var scratch: Report = .{};
        if (try bfs(a, g, comp, c, v, v, ww, &scratch, 0)) |len| {
            kind = .g0;
            scratch.cycle_len = len;
        } else if (try bfs(a, g, comp, c, v, v, wwwr, &scratch, 0)) |len| {
            kind = .g1c;
            scratch.cycle_len = len;
        } else {
            // G-single: one rw edge v -> w, then back to v without rw.
            for (g.out(v)) |e| {
                if (e.kind != .rw or comp[e.to] != c) continue;
                scratch.cycle[0] = v;
                scratch.cycle_edges[0] = .rw;
                if (e.to == v) continue;
                if (try bfs(a, g, comp, c, e.to, v, wwwr, &scratch, 1)) |len| {
                    kind = .g_single;
                    scratch.cycle_len = len + 1;
                    break;
                }
            }
            if (kind == null) {
                if (try bfs(a, g, comp, c, v, v, no_rt, &scratch, 0)) |len| {
                    kind = .g2;
                    scratch.cycle_len = len;
                } else if (try bfs(a, g, comp, c, v, v, all, &scratch, 0)) |len| {
                    kind = .realtime;
                    scratch.cycle_len = len;
                }
            }
        }
        // A component of two or more transactions has a cycle through
        // each of them. When none of the searches above found one short
        // enough to hold (`cycle_max`), it is still an anomaly: reported
        // as the weakest kind, without a cycle to print.
        const k = kind orelse {
            var has_rt = false;
            for (g.out(v)) |e| has_rt = has_rt or (e.kind == .rt and comp[e.to] == c);
            report.found.insert(if (has_rt) .realtime else .g2);
            report.cycle_too_long = true;
            continue;
        };
        report.found.insert(k);
        if (best == null or @backingInt(k) < @backingInt(best.?)) {
            best = k;
            report.cycle = scratch.cycle;
            report.cycle_edges = scratch.cycle_edges;
            report.cycle_len = scratch.cycle_len;
            report.cycle_kind = k;
        }
    }
}

/// Checks `h`; on any anomaly prints the report (if `report`) and returns
/// `error.TransactionalAnomaly`.
pub fn expectSerializable(gpa: Allocator, h: *const History, options: Options, report: bool) !void {
    const r = try check(gpa, h, options);
    if (r.ok()) return;
    if (report) r.print(h);
    return error.TransactionalAnomaly;
}

// ----------------------------------------------------------------------
// Tests

const testing = std.testing;

fn txn(h: *History, status: Status, ops: []const Op) !void {
    try h.finish(h.begin(), status, ops);
}

test "serial history has no anomalies" {
    var h = History.init(testing.allocator);
    defer h.deinit();
    try txn(&h, .committed, &.{.{ .append = .{ .key = 1, .value = 1 } }});
    try txn(&h, .committed, &.{ .{ .read = .{ .key = 1, .values = &.{1} } }, .{ .append = .{ .key = 1, .value = 2 } } });
    try txn(&h, .committed, &.{.{ .read = .{ .key = 1, .values = &.{ 1, 2 } } }});
    const r = try check(testing.allocator, &h, .{ .realtime = true });
    try testing.expect(r.ok());
}

test "write skew is G2" {
    // T0 reads x=[] y=[], appends x; T1 reads x=[] y=[], appends y.
    var h = History.init(testing.allocator);
    defer h.deinit();
    try txn(&h, .committed, &.{ .{ .read = .{ .key = 1, .values = &.{} } }, .{ .read = .{ .key = 2, .values = &.{} } }, .{ .append = .{ .key = 1, .value = 10 } } });
    try txn(&h, .committed, &.{ .{ .read = .{ .key = 1, .values = &.{} } }, .{ .read = .{ .key = 2, .values = &.{} } }, .{ .append = .{ .key = 2, .value = 20 } } });
    try txn(&h, .committed, &.{ .{ .read = .{ .key = 1, .values = &.{10} } }, .{ .read = .{ .key = 2, .values = &.{20} } } });
    const r = try check(testing.allocator, &h, .{});
    try testing.expect(r.found.contains(.g2));
    try testing.expectEqual(Anomaly.g2, r.cycle_kind.?);
    try testing.expectEqual(@as(usize, 2), r.cycle_len);
}

test "a cycle longer than the report can hold is still an anomaly" {
    // A ring of write skew: T_i reads key i+1 empty and appends key i, so
    // each must come before the next, all the way round. Found by review
    // (revision 85): with every cycle longer than `cycle_max` the history
    // passed as serializable.
    const n = cycle_max + 4;
    var h = History.init(testing.allocator);
    defer h.deinit();
    for (0..n) |i| {
        try txn(&h, .committed, &.{ .{ .read = .{ .key = (i + 1) % n, .values = &.{} } }, .{ .append = .{ .key = i, .value = 1 } } });
    }
    for (0..n) |i| try txn(&h, .committed, &.{.{ .read = .{ .key = i, .values = &.{1} } }});
    const r = try check(testing.allocator, &h, .{});
    try testing.expect(!r.ok());
    try testing.expect(r.found.contains(.g2));
    try testing.expect(r.cycle_too_long);
    try testing.expectEqual(@as(?Anomaly, null), r.cycle_kind);
}

test "read skew is G-single" {
    // T0 appends x and y. T1 sees T0's x but not its y.
    var h = History.init(testing.allocator);
    defer h.deinit();
    try txn(&h, .committed, &.{ .{ .append = .{ .key = 1, .value = 1 } }, .{ .append = .{ .key = 2, .value = 1 } } });
    try txn(&h, .committed, &.{ .{ .read = .{ .key = 1, .values = &.{1} } }, .{ .read = .{ .key = 2, .values = &.{} } } });
    try txn(&h, .committed, &.{.{ .read = .{ .key = 2, .values = &.{1} } }});
    const r = try check(testing.allocator, &h, .{});
    try testing.expectEqual(Anomaly.g_single, r.cycle_kind.?);
}

test "aborted and intermediate reads, incompatible orders, duplicates" {
    var h = History.init(testing.allocator);
    defer h.deinit();
    try txn(&h, .aborted, &.{.{ .append = .{ .key = 1, .value = 1 } }});
    try txn(&h, .committed, &.{.{ .read = .{ .key = 1, .values = &.{1} } }});
    try txn(&h, .committed, &.{ .{ .append = .{ .key = 2, .value = 1 } }, .{ .append = .{ .key = 2, .value = 2 } } });
    try txn(&h, .committed, &.{.{ .read = .{ .key = 2, .values = &.{1} } }});
    try txn(&h, .committed, &.{.{ .read = .{ .key = 3, .values = &.{ 5, 6 } } }});
    try txn(&h, .committed, &.{.{ .read = .{ .key = 3, .values = &.{ 6, 5, 6 } } }});
    const r = try check(testing.allocator, &h, .{});
    try testing.expect(r.found.contains(.aborted_read));
    try testing.expect(r.found.contains(.intermediate_read));
    try testing.expect(r.found.contains(.incompatible_order));
    try testing.expect(r.found.contains(.duplicate_element));
}

test "a stale read is only a real-time anomaly" {
    var h = History.init(testing.allocator);
    defer h.deinit();
    try txn(&h, .committed, &.{.{ .append = .{ .key = 1, .value = 1 } }});
    try txn(&h, .committed, &.{.{ .read = .{ .key = 1, .values = &.{} } }}); // after T0 finished
    try testing.expect((try check(testing.allocator, &h, .{})).ok());
    const r = try check(testing.allocator, &h, .{ .realtime = true });
    try testing.expectEqual(Anomaly.realtime, r.cycle_kind.?);
}

fn regWrite(key: u64, value: u64) Op {
    return .{ .write = .{ .key = key, .value = value } };
}

fn regRead(key: u64, value: ?u64) Op {
    return .{ .read_reg = .{ .key = key, .value = value } };
}

test "registers: a serial history has no anomalies" {
    var h = History.init(testing.allocator);
    defer h.deinit();
    try txn(&h, .committed, &.{ regRead(1, null), regWrite(1, 1) });
    try txn(&h, .committed, &.{ regRead(1, 1), regWrite(1, 2), regRead(1, 2) });
    try txn(&h, .committed, &.{ regRead(1, 2), regRead(2, null) });
    try testing.expect((try check(testing.allocator, &h, .{ .realtime = true })).ok());
}

test "registers: a lost update" {
    var h = History.init(testing.allocator);
    defer h.deinit();
    try txn(&h, .committed, &.{regWrite(1, 1)});
    try txn(&h, .committed, &.{ regRead(1, 1), regWrite(1, 2) });
    try txn(&h, .committed, &.{ regRead(1, 1), regWrite(1, 3) });
    const rep = try check(testing.allocator, &h, .{});
    try testing.expect(rep.found.contains(.lost_update));
    try testing.expect(rep.found.contains(.g2));
}

test "registers: read skew is G-single, write skew is G2" {
    var skew = History.init(testing.allocator);
    defer skew.deinit();
    try txn(&skew, .committed, &.{ regWrite(1, 1), regWrite(2, 1) });
    try txn(&skew, .committed, &.{ regRead(1, 1), regRead(2, null) });
    try testing.expectEqual(Anomaly.g_single, (try check(testing.allocator, &skew, .{})).cycle_kind.?);

    var ws = History.init(testing.allocator);
    defer ws.deinit();
    try txn(&ws, .committed, &.{ regRead(1, null), regRead(2, null), regWrite(1, 1) });
    try txn(&ws, .committed, &.{ regRead(1, null), regRead(2, null), regWrite(2, 1) });
    const rep = try check(testing.allocator, &ws, .{});
    try testing.expectEqual(Anomaly.g2, rep.cycle_kind.?);
    try testing.expect(!rep.found.contains(.lost_update));
}

test "registers: aborted, intermediate, garbage and internal reads" {
    var h = History.init(testing.allocator);
    defer h.deinit();
    try txn(&h, .aborted, &.{regWrite(1, 5)});
    try txn(&h, .committed, &.{regRead(1, 5)});
    try txn(&h, .committed, &.{ regWrite(2, 1), regWrite(2, 2) });
    try txn(&h, .committed, &.{regRead(2, 1)});
    try txn(&h, .committed, &.{regRead(3, 99)});
    try txn(&h, .committed, &.{ regWrite(4, 1), regRead(4, 2) });
    const rep = try check(testing.allocator, &h, .{});
    try testing.expect(rep.found.contains(.aborted_read));
    try testing.expect(rep.found.contains(.intermediate_read));
    try testing.expect(rep.found.contains(.garbage_read));
    try testing.expect(rep.found.contains(.internal));
}

test "registers: a stale read is only a real-time anomaly" {
    var h = History.init(testing.allocator);
    defer h.deinit();
    try txn(&h, .committed, &.{regWrite(1, 1)});
    try txn(&h, .committed, &.{regRead(1, null)});
    try testing.expect((try check(testing.allocator, &h, .{})).ok());
    try testing.expectEqual(Anomaly.realtime, (try check(testing.allocator, &h, .{ .realtime = true })).cycle_kind.?);
}
