//! Run queue (plan §4.2).
//!
//! A bitset of task ids with O(1) insert/remove and rank selection that
//! walks whole words with `@popCount`. With the default 64-task limit this is
//! one or two words.

const std = @import("std");
const assert = std.debug.assert;

pub const TaskId = u16;

pub const RunQueue = struct {
    words: []u64,
    count: u32,

    pub fn init(words: []u64) RunQueue {
        @memset(words, 0);
        return .{ .words = words, .count = 0 };
    }

    pub fn clear(q: *RunQueue) void {
        @memset(q.words, 0);
        q.count = 0;
    }

    pub fn contains(q: *const RunQueue, id: TaskId) bool {
        return q.words[id >> 6] & bit(id) != 0;
    }

    pub fn insert(q: *RunQueue, id: TaskId) void {
        if (q.contains(id)) return;
        q.words[id >> 6] |= bit(id);
        q.count += 1;
    }

    pub fn remove(q: *RunQueue, id: TaskId) void {
        if (!q.contains(id)) return;
        q.words[id >> 6] &= ~bit(id);
        q.count -= 1;
    }

    /// Returns the `rank`-th member in ascending id order.
    pub fn pickNth(q: *const RunQueue, rank: u64) TaskId {
        assert(rank < q.count);
        var remaining = rank;
        for (q.words, 0..) |word, w| {
            const pop: u64 = @popCount(word);
            if (remaining >= pop) {
                remaining -= pop;
                continue;
            }
            return @intCast(w * 64 + selectBit(word, @intCast(remaining)));
        }
        unreachable;
    }

    fn bit(id: TaskId) u64 {
        return @as(u64, 1) << @truncate(id);
    }
};

/// The position of the `rank`-th set bit of `word` (rank 0: the lowest),
/// by halving: six popcounts instead of clearing `rank` bits one by one.
fn selectBit(word: u64, rank: u32) u32 {
    assert(rank < @popCount(word));
    var w = word;
    var r = rank;
    var pos: u32 = 0;
    inline for (.{ 32, 16, 8, 4, 2, 1 }) |width| {
        const low = w & ((@as(u64, 1) << width) - 1);
        const count: u32 = @popCount(low);
        if (r >= count) {
            r -= count;
            w >>= width;
            pos += width;
        } else {
            w = low;
        }
    }
    return pos;
}

test "selectBit agrees with clearing the lowest bit rank times" {
    var x: u64 = 0x9E37_79B9_7F4A_7C15;
    for (0..200) |_| {
        x = x *% 0x2545_F491_4F6C_DD1D +% 1;
        const word = x | 1;
        var rest = word;
        for (0..@popCount(word)) |rank| {
            try std.testing.expectEqual(@as(u32, @ctz(rest)), selectBit(word, @intCast(rank)));
            rest &= rest - 1;
        }
    }
    try std.testing.expectEqual(@as(u32, 63), selectBit(1 << 63, 0));
    try std.testing.expectEqual(@as(u32, 63), selectBit(std.math.maxInt(u64), 63));
}

test "run queue rank selection" {
    var storage: [2]u64 = undefined;
    var q = RunQueue.init(&storage);
    q.insert(3);
    q.insert(70);
    q.insert(5);
    q.insert(5);
    try std.testing.expectEqual(@as(u32, 3), q.count);
    try std.testing.expectEqual(@as(TaskId, 3), q.pickNth(0));
    try std.testing.expectEqual(@as(TaskId, 5), q.pickNth(1));
    try std.testing.expectEqual(@as(TaskId, 70), q.pickNth(2));
    q.remove(5);
    try std.testing.expectEqual(@as(TaskId, 70), q.pickNth(1));
    try std.testing.expect(!q.contains(5));
}
