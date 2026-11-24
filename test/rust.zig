//! A Rust program under simulation (`plan3.md` D9, plan §9.2).
//!
//! `test/rust` is a Rust crate built as a static library for
//! `x86_64-unknown-linux-musl`: the standard library's threads, locks,
//! channels, clock, files and sockets, and tokio's two runtimes (the
//! work-stealing one with a worker count given and with the one it
//! picks), an HTTP server and clients on hyper, a host name looked up.
//! It knows
//! nothing of TARDIS. System-call mode answers its system calls from the
//! simulation, and its threads are simulated tasks.
//!
//! Build the library with `cargo build --target x86_64-unknown-linux-musl`
//! in `test/rust`, then `zig build test-rust -Dtarget=x86_64-linux-musl
//! -Drust=<path to the .a>` on
//! Linux x86_64. Or both for glibc: `x86_64-unknown-linux-gnu` and
//! `-Dtarget=x86_64-linux-gnu`.

const std = @import("std");
const tardis = @import("tardis");
const Env = tardis.Env;
const testing = std.testing;

const supported = tardis.syscall_mode_supported;

extern fn rust_threads() c_int;
extern fn rust_time() i64;
extern fn rust_files() c_int;
extern fn rust_files_kept() c_int;
extern fn rust_tcp() c_int;
extern fn rust_hash_order() u64;
extern fn rust_tokio_current() c_int;
extern fn rust_tokio_workers(workers: usize) c_int;

const options: tardis.Options = .{
    .iterations = 50,
    .mode = .syscalls,
    .limits = .{ .fiber_stack_bytes = 1024 * 1024 },
};

fn skip() bool {
    return !supported or !tardis.syscallModeAvailable() or !tardis.syscallThreadsAvailable();
}

fn threads(env: *Env) !void {
    _ = env;
    try testing.expectEqual(@as(c_int, 0), rust_threads());
}

test "rust: four threads, a mutex and a channel" {
    if (skip()) return error.SkipZigTest;
    try tardis.check(testing.allocator, threads, options);
}

fn time(env: *Env) !void {
    _ = env;
    // An hour's sleep, waited for with timeouts of a thousand seconds.
    const ns = rust_time();
    try testing.expect(ns >= 3600 * std.time.ns_per_s);
    try testing.expect(ns < 3601 * std.time.ns_per_s);
}

test "rust: a sleep and a timed wait pass in virtual time" {
    if (skip()) return error.SkipZigTest;
    try tardis.check(testing.allocator, time, options);
}

fn files(env: *Env) !void {
    try testing.expectEqual(@as(c_int, 0), rust_files());
    try env.crashAndReboot(.power_loss);
    // Written, synced, renamed, and the directory synced: it is kept.
    try testing.expectEqual(@as(c_int, 0), rust_files_kept());
}

test "rust: std::fs lands in the simulated filesystem and meets a power loss" {
    if (skip()) return error.SkipZigTest;
    var o = options;
    o.personas = &.{ .linux_ext4, .linux_xfs, .posix_strict };
    try tardis.check(testing.allocator, files, o);
}

fn tcp(env: *Env) !void {
    _ = env;
    try testing.expectEqual(@as(c_int, 0), rust_tcp());
}

test "rust: a blocking TCP echo, a thread for each connection" {
    if (skip()) return error.SkipZigTest;
    try tardis.check(testing.allocator, tcp, options);
}

extern fn rust_try_clone() c_int;

fn tryClone(env: *Env) !void {
    _ = env;
    try testing.expectEqual(@as(c_int, 0), rust_try_clone());
}

test "rust: try_clone of a TcpStream and of a File" {
    if (skip()) return error.SkipZigTest;
    try tardis.check(testing.allocator, tryClone, options);
}

threadlocal var orders: [2]u64 = @splat(0);
threadlocal var order_count: usize = 0;

fn hashOrder(env: *Env) !void {
    _ = env;
    const order = rust_hash_order();
    if (order_count < orders.len) orders[order_count] = order;
    order_count += 1;
}

test "rust: a HashMap's order follows the seed" {
    if (skip()) return error.SkipZigTest;
    // The map's keys are from `getrandom`, which follows the seed: the
    // same order for the same seed, another for another.
    order_count = 0;
    try tardis.check(testing.allocator, hashOrder, .{ .iterations = 1, .seed = 1, .mode = .syscalls });
    const first = orders[0];
    order_count = 0;
    try tardis.check(testing.allocator, hashOrder, .{ .iterations = 1, .seed = 1, .mode = .syscalls });
    try testing.expectEqual(first, orders[0]);
    order_count = 0;
    try tardis.check(testing.allocator, hashOrder, .{ .iterations = 1, .seed = 2, .mode = .syscalls });
    try testing.expect(first != orders[0]);
}

fn tokioCurrent(env: *Env) !void {
    _ = env;
    try testing.expectEqual(@as(c_int, 0), rust_tokio_current());
}

test "rust: tokio's single-threaded runtime" {
    if (skip()) return error.SkipZigTest;
    try tardis.check(testing.allocator, tokioCurrent, options);
}

fn tokioTwoWorkers(env: *Env) !void {
    _ = env;
    try testing.expectEqual(@as(c_int, 0), rust_tokio_workers(2));
}

fn tokioFourWorkers(env: *Env) !void {
    _ = env;
    try testing.expectEqual(@as(c_int, 0), rust_tokio_workers(4));
}

extern fn rust_parallelism() usize;
extern fn rust_tokio_default(expected: usize) c_int;

fn parallelism(env: *Env) !void {
    _ = env;
    try testing.expectEqual(@as(usize, 1), rust_parallelism());
}

test "rust: available_parallelism is one, on every machine" {
    if (skip()) return error.SkipZigTest;
    try tardis.check(testing.allocator, parallelism, options);
}

fn tokioDefault(env: *Env) !void {
    _ = env;
    try testing.expectEqual(@as(c_int, 0), rust_tokio_default(1));
}

test "rust: tokio's work-stealing runtime with the worker count it picks" {
    if (skip()) return error.SkipZigTest;
    try tardis.check(testing.allocator, tokioDefault, options);
}

fn sixProcessors(env: *Env) !void {
    _ = env;
    try testing.expectEqual(@as(usize, 6), rust_parallelism());
    try testing.expectEqual(@as(c_int, 0), rust_tokio_default(6));
}

test "rust: told of six processors, tokio starts six workers" {
    if (skip()) return error.SkipZigTest;
    var six = options;
    six.processors = 6;
    try tardis.check(testing.allocator, sixProcessors, six);
}

test "rust: tokio's work-stealing runtime, two workers and four" {
    if (skip()) return error.SkipZigTest;
    try tardis.check(testing.allocator, tokioTwoWorkers, options);
    try tardis.check(testing.allocator, tokioFourWorkers, options);
}

extern fn rust_http(workers: usize) c_int;

fn httpCurrent(env: *Env) !void {
    _ = env;
    try testing.expectEqual(@as(c_int, 0), rust_http(0));
}

fn httpTwoWorkers(env: *Env) !void {
    _ = env;
    try testing.expectEqual(@as(c_int, 0), rust_http(2));
}

test "rust: an HTTP server and three clients on hyper, on both of tokio's runtimes" {
    if (skip()) return error.SkipZigTest;
    try tardis.check(testing.allocator, httpCurrent, options);
    try tardis.check(testing.allocator, httpTwoWorkers, options);
}

extern fn rust_resolve() c_int;

/// The simulated filesystem starts empty: the program's host names are
/// the ones the test writes to `/etc/hosts`. Without the file a C library
/// asks a name server that is not there, and gives up after five seconds
/// of virtual time.
fn resolves(env: *Env) !void {
    _ = env;
    _ = std.c.mkdir("/etc", 0o755);
    const fd = std.c.open("/etc/hosts", .{ .ACCMODE = .WRONLY, .CREAT = true }, @as(std.c.mode_t, 0o644));
    const text = "127.0.0.1 localhost\n";
    var done: usize = 0;
    while (done < text.len) done += @intCast(std.c.write(fd, text[done..].ptr, text.len - done));
    _ = std.c.close(fd);
    try testing.expect(rust_resolve() > 0);
}

test "rust: localhost is looked up through the C library" {
    if (skip()) return error.SkipZigTest;
    // glibc builds its tables for looking names up once in the life of
    // the process: a run to do that, thrown away.
    var primed = options;
    primed.prime = true;
    try tardis.check(testing.allocator, resolves, primed);
}
