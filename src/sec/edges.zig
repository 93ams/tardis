//! Dead edges (plan2.md §7.1): code a certification campaign never ran.
//!
//! A build with Zig's `-ffuzz` instrumentation (module `fuzz = true`, the
//! LLVM backend, an ELF or Mach-O target) gives every edge an inline 8-bit
//! counter in section `__sancov_cntrs` and its address in `__sancov_pcs1`,
//! one entry per counter. Zig's own fuzzer reads them under `zig build`'s
//! server; nothing else needs it, so `certify` reads them directly:
//!
//! - `begin` zeroes every counter and allocates a "seen" byte per edge;
//! - after each run (`sweep`, from the engine's end-of-run hook) every
//!   counter is ORed into its seen byte and zeroed again. A counter wraps
//!   after 255 hits, so sweeping per run, not once per campaign, keeps an
//!   edge hit a multiple of 256 times in a campaign from reading as zero.
//!   Within one run the wrap remains: an edge hit exactly 256·k times in
//!   every run that reaches it reads as never run (a false "never ran",
//!   never a false "ran");
//! - `finish` maps each edge's address to its file, line and function
//!   through the program's own debug info, keeps the edges in the
//!   project's scope (`Scope`: files, optionally narrowed to functions),
//!   and reports each source line where an edge never ran, with how many
//!   of the line's edges did.
//!
//! What the list means: every edge listed never ran. A line can be listed
//! although its statement ran: its own block may be the error path of a
//! `try` (never taken), while the success path continues in a block
//! counted on the next line. The list is not complete either: LLVM does
//! not give a counter to a block whose coverage follows from others
//! (sanitizer-coverage pruning), so an untaken branch can have no counter
//! of its own. Measured on Example 2: the certified campaign never runs the
//! followers' "trust the leader" branch, which has no counter, while the
//! never-taken error paths of its `try`s are listed.
//!
//! Deactivated code is justified where it is written: a comment
//! `// tardis-deactivated: <reason>` at the end of a line, or on comment
//! lines of its own just above it, marks that line (`markers`). A listed
//! line with a marker carries the reason, as `mcdc.Decl.deactivated` does
//! for a decision; a marked line whose edges all ran is `stale`, because
//! the code the justification calls deactivated ran.
//!
//! The same counters guide exploration (`plan.md` §9 M3): at the end of
//! each run every edge that ran is a coverage feature (`Sim.cover`), so
//! with `Options.explore = .guided` a run that reaches new code joins the
//! corpus, also when that code does no I/O. The counters are zeroed at the
//! start of each run, so a run's features are its own.
//!
//! Counting is per process and not synchronized, so `certify` runs an
//! instrumented campaign on one thread and without the fork server, and
//! edges are features only while one engine exists (one worker).
//! Without instrumentation (the default build, Windows, COFF) `instrumented`
//! is false, the report is empty, and the bundle says so.

const std = @import("std");
const builtin = @import("builtin");
const tardis = @import("tardis");
const Allocator = std.mem.Allocator;
const Io = std.Io;

/// Whether this program carries edge counters `certify` can read.
pub const instrumented = builtin.fuzz and switch (builtin.object_format) {
    .elf, .macho => true,
    else => false,
};

const bounds: struct { start: []const u8, stop: []const u8 } = switch (builtin.object_format) {
    .elf => .{ .start = "__start_", .stop = "__stop_" },
    .macho => .{ .start = "\x01section$start$__DATA$", .stop = "\x01section$end$__DATA$" },
    else => .{ .start = "", .stop = "" },
};

fn section(comptime T: type, comptime name: []const u8) []T {
    if (!instrumented) return &.{};
    const start = @extern([*]T, .{ .name = bounds.start ++ name, .linkage = .weak }) orelse return &.{};
    const stop = @extern([*]T, .{ .name = bounds.stop ++ name, .linkage = .weak }) orelse return &.{};
    return start[0 .. stop - start];
}

/// The edge counters (empty without instrumentation).
pub fn counters() []u8 {
    return section(u8, "__sancov_cntrs");
}

/// Each edge's address, in counter order (empty without instrumentation).
pub fn pcs() []const usize {
    return section(usize, "__sancov_pcs1");
}

var seen: []u8 = &.{};
var tracking = false;

/// Starts counting: every counter zeroed, nothing seen yet.
pub fn begin(gpa: Allocator) Allocator.Error!void {
    if (!instrumented) return;
    const c = counters();
    if (seen.len != c.len) {
        if (seen.len > 0) gpa.free(seen);
        seen = &.{};
        seen = try gpa.alloc(u8, c.len);
    }
    @memset(seen, 0);
    @memset(c, 0);
    tracking = true;
}

/// Engines alive in the process: with more than one (several workers) the
/// counters mix their runs, and are not used as features.
var engines: std.atomic.Value(u32) = .init(0);

pub fn engineCreated() void {
    _ = engines.fetchAdd(1, .monotonic);
}

pub fn engineDestroyed() void {
    _ = engines.fetchSub(1, .monotonic);
}

const feature_label: u64 = 0x5EC0_ED6E_0000_0171;

/// Zeroes the counters (start of a run): what ran between runs (the
/// campaign loop, the shrinker) is not the run's.
pub fn clear() void {
    @disableInstrumentation();
    if (!instrumented) return;
    const c = counters();
    // Under `certify` they still count as run by the campaign.
    if (tracking) {
        for (c, seen) |x, *s| s.* |= x;
    }
    @memset(c, 0);
}

/// End of a run: every edge that ran is a coverage feature of `sim`'s run,
/// and the counters are folded into the seen set (under `certify`) and
/// zeroed.
pub fn sweep(sim: ?*tardis.Sim) void {
    @disableInstrumentation();
    if (!instrumented) return;
    const c = counters();
    if (sim) |s| {
        if (s.coverage != null and engines.load(.monotonic) == 1) {
            for (c, 0..) |x, i| {
                if (x != 0) s.cover(tardis.decide.mix(feature_label, i));
            }
        }
    }
    if (tracking) {
        for (c, seen) |x, *s| s.* |= x;
    }
    @memset(c, 0);
}

/// The code a report covers: a source file by its repository path, as the
/// debug info names it relative to the current directory (forward
/// slashes), optionally narrowed to functions by their unqualified names.
pub const Scope = struct {
    file: []const u8,
    /// Empty: the whole file.
    functions: []const []const u8 = &.{},

    pub fn matches(s: Scope, path: []const u8, function: ?[]const u8) bool {
        const file_ok = std.mem.eql(u8, path, s.file) or
            (path.len > s.file.len and path[path.len - s.file.len - 1] == '/' and std.mem.endsWith(u8, path, s.file));
        if (!file_ok) return false;
        if (s.functions.len == 0) return true;
        const name = function orelse return false;
        // `example2.follower`, `example2.Foo(u8).bar`: the last component.
        const last = name[if (std.mem.lastIndexOfScalar(u8, name, '.')) |i| i + 1 else 0..];
        for (s.functions) |f| if (std.mem.eql(u8, last, f)) return true;
        return false;
    }
};

/// A source line with at least one edge that never ran.
pub const Line = struct {
    /// `Scope.file` of the scope it belongs to (borrowed).
    file: []const u8,
    line: u32,
    /// Edges counted at this line, and those that ran.
    edges: u32,
    hit: u32,
    /// The reason of the line's `tardis-deactivated` marker (owned by the
    /// report), if it has one.
    justification: ?[]const u8 = null,
};

/// What marks deactivated code, after `//`.
pub const marker_tag = "tardis-deactivated:";

/// A `tardis-deactivated` marker: the line it justifies and its reason.
pub const Marker = struct { line: u32, reason: []const u8 };

/// The markers in `source`, by line. A marker at the end of a code line
/// marks that line; one on a comment line marks the next line that is not
/// blank or a comment. A marker without a reason marks nothing. Reasons
/// borrow `source`.
pub fn markers(gpa: Allocator, source: []const u8) Allocator.Error![]Marker {
    var out: std.ArrayList(Marker) = .empty;
    errdefer out.deinit(gpa);
    var pending: ?[]const u8 = null;
    var it = std.mem.splitScalar(u8, source, '\n');
    var n: u32 = 0;
    while (it.next()) |raw| {
        n += 1;
        const line = std.mem.trim(u8, raw, " \t\r");
        const comment_only = std.mem.startsWith(u8, line, "//");
        if (pending) |reason| if (line.len > 0 and !comment_only) {
            try out.append(gpa, .{ .line = n, .reason = reason });
            pending = null;
        };
        const at = std.mem.indexOf(u8, line, marker_tag) orelse continue;
        if (!std.mem.endsWith(u8, std.mem.trimEnd(u8, line[0..at], " \t"), "//")) continue;
        const reason = std.mem.trim(u8, line[at + marker_tag.len ..], " \t");
        if (reason.len == 0) continue;
        if (comment_only) {
            pending = reason;
        } else {
            try out.append(gpa, .{ .line = n, .reason = reason });
        }
    }
    return out.toOwnedSlice(gpa);
}

fn reasonAt(marks: []const Marker, line: u32) ?[]const u8 {
    for (marks) |m| if (m.line == line) return m.reason;
    return null;
}

fn freeLines(gpa: Allocator, lines: []const Line) void {
    for (lines) |l| if (l.justification) |j| gpa.free(j);
}

pub const Report = struct {
    /// Whether the counters were read (an instrumented build with a scope).
    measured: bool = false,
    scope: []const Scope = &.{},
    /// Edges in scope, and those that ran.
    edges: u32 = 0,
    hit: u32 = 0,
    /// Lines with an edge that never ran, by scope then line.
    lines: []Line = &.{},
    /// Lines with a `tardis-deactivated` marker whose edges all ran.
    stale: []Line = &.{},
    /// Edges the debug info could not place (anywhere in the program), or
    /// placed past the end of a scoped file (inlined code, see `finish`).
    unplaced: u32 = 0,

    /// Listed lines with a justification.
    pub fn justified(r: Report) u32 {
        var n: u32 = 0;
        for (r.lines) |l| n += @intFromBool(l.justification != null);
        return n;
    }

    pub fn deinit(r: *Report, gpa: Allocator) void {
        freeLines(gpa, r.lines);
        freeLines(gpa, r.stale);
        gpa.free(r.lines);
        gpa.free(r.stale);
        r.* = .{};
    }
};

/// One edge placed in scope: which scope, which line, whether it ran.
pub const Placed = struct { scope: u16, line: u32, hit: bool };

fn placedLess(_: void, a: Placed, b: Placed) bool {
    return if (a.scope != b.scope) a.scope < b.scope else a.line < b.line;
}

/// Groups placed edges by line and keeps the lines with an edge that never
/// ran, justified by `marks` (one list per scope, or none at all); a marked
/// line whose edges all ran is stale. Sorts `placed`.
pub fn aggregate(gpa: Allocator, scope: []const Scope, placed: []Placed, marks: []const []const Marker) Allocator.Error!Report {
    std.debug.assert(marks.len == 0 or marks.len == scope.len);
    std.mem.sort(Placed, placed, {}, placedLess);
    var lines: std.ArrayList(Line) = .empty;
    var stale: std.ArrayList(Line) = .empty;
    errdefer {
        freeLines(gpa, lines.items);
        freeLines(gpa, stale.items);
        lines.deinit(gpa);
        stale.deinit(gpa);
    }
    var r: Report = .{ .measured = true, .scope = scope, .edges = @intCast(placed.len) };
    var i: usize = 0;
    while (i < placed.len) {
        var l: Line = .{ .file = scope[placed[i].scope].file, .line = placed[i].line, .edges = 0, .hit = 0 };
        const at = placed[i];
        while (i < placed.len and placed[i].scope == at.scope and placed[i].line == at.line) : (i += 1) {
            l.edges += 1;
            l.hit += @intFromBool(placed[i].hit);
        }
        r.hit += l.hit;
        const reason = if (marks.len > 0) reasonAt(marks[at.scope], at.line) else null;
        if (l.hit == l.edges and reason == null) continue;
        const list = if (l.hit < l.edges) &lines else &stale;
        try list.ensureUnusedCapacity(gpa, 1);
        if (reason) |j| l.justification = try gpa.dupe(u8, j);
        list.appendAssumeCapacity(l);
    }
    const owned = try lines.toOwnedSlice(gpa);
    errdefer {
        freeLines(gpa, owned);
        gpa.free(owned);
    }
    r.stale = try stale.toOwnedSlice(gpa);
    r.lines = owned;
    return r;
}

/// The path of a debug-info file name relative to `cwd` when under it,
/// with forward slashes, in `buf`.
fn repoPath(buf: []u8, cwd: ?[]const u8, path: []const u8) []const u8 {
    var p = path;
    if (cwd) |c| if (p.len > c.len + 1 and std.mem.eql(u8, p[0..c.len], c) and (p[c.len] == '/' or p[c.len] == '\\')) {
        p = p[c.len + 1 ..];
    };
    const n = @min(p.len, buf.len);
    for (p[0..n], buf[0..n]) |ch, *out| out.* = if (ch == '\\') '/' else ch;
    return buf[0..n];
}

/// Ends counting and reports the lines in `scope` with edges that never
/// ran since `begin`. Without instrumentation, or with an empty scope, the
/// report is empty and not `measured`.
pub fn finish(gpa: Allocator, io: Io, scope: []const Scope) !Report {
    if (!instrumented or !tracking) return .{ .scope = scope };
    sweep(null);
    tracking = false;
    defer {
        gpa.free(seen);
        seen = &.{};
    }
    if (scope.len == 0) return .{ .scope = scope };
    if (scope.len > std.math.maxInt(u16)) return error.ScopeTooLarge;
    if (std.debug.SelfInfo == void) return .{ .scope = scope };
    const si = try std.debug.getSelfDebugInfo();

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const cwd: ?[]u8 = std.process.currentPathAlloc(io, arena.allocator()) catch null;
    // Each scoped file's line count: Zig 0.17's debug info gives code
    // inlined from another file (an `inline fn` of `std`) that file's line
    // numbers under the caller's file name, so a line past the end is not
    // where it says.
    // Its markers too.
    const lines_max = try arena.allocator().alloc(u32, scope.len);
    const marks = try arena.allocator().alloc([]const Marker, scope.len);
    for (scope, lines_max, marks) |sc, *m, *mk| {
        m.* = std.math.maxInt(u32);
        mk.* = &.{};
        const source = std.Io.Dir.cwd().readFileAlloc(io, sc.file, arena.allocator(), .limited(64 << 20)) catch continue;
        m.* = @intCast(std.mem.count(u8, source, "\n") + 1);
        mk.* = try markers(arena.allocator(), source);
    }
    var placed: std.ArrayList(Placed) = .empty;
    defer placed.deinit(gpa);
    // Symbolized the way `std.debug` symbolizes a stack trace: its I/O with
    // cancellation blocked, its allocator for the symbol list, the page
    // allocator under the text arena. With the caller's I/O and allocators
    // `getSymbols` hangs on Linux (Zig 0.17).
    const dio = std.Options.debug_io;
    const prev = dio.swapCancelProtection(.blocked);
    defer _ = dio.swapCancelProtection(prev);
    const symbol_allocator = std.debug.getDebugInfoAllocator();
    var symbols: std.ArrayList(std.debug.Symbol) = .empty;
    defer symbols.deinit(symbol_allocator);
    var unplaced: u32 = 0;
    var text: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer text.deinit();
    for (pcs(), seen) |pc, s| {
        // LLVM leaves placeholder entries of 1 in the table (`lib/fuzzer.zig`).
        if (pc <= 1) continue;
        symbols.clearRetainingCapacity();
        _ = text.reset(.retain_capacity);
        si.getSymbols(dio, symbol_allocator, text.allocator(), pc, false, &symbols) catch {
            unplaced += 1;
            continue;
        };
        if (symbols.items.len == 0) continue;
        const sym = symbols.items[0];
        const sl = sym.source_location orelse continue;
        if (sl.line == 0) continue;
        var buf: [Io.Dir.max_path_bytes]u8 = undefined;
        const path = repoPath(&buf, cwd, sl.file_name);
        for (scope, lines_max, 0..) |sc, m, k| if (sc.matches(path, sym.name)) {
            if (sl.line > m) {
                unplaced += 1;
                break;
            }
            try placed.append(gpa, .{ .scope = @intCast(k), .line = @intCast(sl.line), .hit = s != 0 });
            break;
        };
    }
    var r = try aggregate(gpa, scope, placed.items, marks);
    r.unplaced = unplaced;
    return r;
}

test "a scope matches its file, by repository path or path suffix, and its functions" {
    const whole: Scope = .{ .file = "src/sec/tests/example2.zig" };
    try std.testing.expect(whole.matches("src/sec/tests/example2.zig", null));
    try std.testing.expect(whole.matches("/home/ci/tardis/src/sec/tests/example2.zig", null));
    try std.testing.expect(!whole.matches("src/sec/tests/xexample2.zig", null));
    try std.testing.expect(!whole.matches("src/sec/tests/example1.zig", null));
    const narrow: Scope = .{ .file = "src/sec/tests/example2.zig", .functions = &.{ "follower", "round" } };
    try std.testing.expect(narrow.matches("src/sec/tests/example2.zig", "example2.follower"));
    try std.testing.expect(narrow.matches("src/sec/tests/example2.zig", "round"));
    try std.testing.expect(!narrow.matches("src/sec/tests/example2.zig", "example2.trusting"));
    try std.testing.expect(!narrow.matches("src/sec/tests/example2.zig", null));
}

test "a line is listed when one of its edges never ran, with how many did" {
    const scope = [_]Scope{ .{ .file = "a.zig" }, .{ .file = "b.zig" } };
    var placed = [_]Placed{
        .{ .scope = 1, .line = 3, .hit = false },
        .{ .scope = 0, .line = 9, .hit = true },
        .{ .scope = 0, .line = 9, .hit = false },
        .{ .scope = 0, .line = 2, .hit = true },
        .{ .scope = 0, .line = 2, .hit = true },
        .{ .scope = 1, .line = 3, .hit = false },
    };
    var r = try aggregate(std.testing.allocator, &scope, &placed, &.{});
    defer r.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 6), r.edges);
    try std.testing.expectEqual(@as(u32, 3), r.hit);
    try std.testing.expectEqual(@as(usize, 2), r.lines.len);
    try std.testing.expectEqualStrings("a.zig", r.lines[0].file);
    try std.testing.expectEqual(@as(u32, 9), r.lines[0].line);
    try std.testing.expectEqual(@as(u32, 1), r.lines[0].hit);
    try std.testing.expectEqualStrings("b.zig", r.lines[1].file);
    try std.testing.expectEqual(@as(u32, 0), r.lines[1].hit);
    try std.testing.expectEqual(@as(u32, 2), r.lines[1].edges);
}

test "markers justify their line or the next code line, and a fully run marked line is stale" {
    const source =
        \\fn f() void {
        \\    a(); // tardis-deactivated: only on the recovery board
        \\    // tardis-deactivated: the legacy wire format
        \\    // (kept for one release)
        \\
        \\    b();
        \\    c(); // tardis-deactivated:
        \\    d(); // see "tardis-deactivated: x" elsewhere
        \\    e(); //tardis-deactivated: no space
        \\}
    ;
    const gpa = std.testing.allocator;
    const marks = try markers(gpa, source);
    defer gpa.free(marks);
    try std.testing.expectEqual(@as(usize, 3), marks.len);
    try std.testing.expectEqual(@as(u32, 2), marks[0].line);
    try std.testing.expectEqualStrings("only on the recovery board", marks[0].reason);
    try std.testing.expectEqual(@as(u32, 6), marks[1].line);
    try std.testing.expectEqualStrings("the legacy wire format", marks[1].reason);
    try std.testing.expectEqual(@as(u32, 9), marks[2].line);
    try std.testing.expectEqualStrings("no space", marks[2].reason);

    const scope = [_]Scope{.{ .file = "f.zig" }};
    var placed = [_]Placed{
        .{ .scope = 0, .line = 2, .hit = false },
        .{ .scope = 0, .line = 6, .hit = true },
        .{ .scope = 0, .line = 7, .hit = false },
        .{ .scope = 0, .line = 8, .hit = true },
    };
    var r = try aggregate(gpa, &scope, &placed, &.{marks});
    defer r.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 2), r.lines.len);
    try std.testing.expectEqualStrings("only on the recovery board", r.lines[0].justification.?);
    try std.testing.expectEqual(@as(?[]const u8, null), r.lines[1].justification);
    try std.testing.expectEqual(@as(u32, 1), r.justified());
    try std.testing.expectEqual(@as(usize, 1), r.stale.len);
    try std.testing.expectEqual(@as(u32, 6), r.stale[0].line);
    try std.testing.expectEqualStrings("the legacy wire format", r.stale[0].justification.?);
}

test "without instrumentation nothing is measured" {
    if (instrumented) return error.SkipZigTest;
    try begin(std.testing.allocator);
    sweep(null);
    const r = try finish(std.testing.allocator, std.testing.io, &.{.{ .file = "a.zig" }});
    try std.testing.expect(!r.measured);
    try std.testing.expectEqual(@as(usize, 0), counters().len);
}
