//! Fork server primitives (plan §9 M5): process-level copy-on-write
//! snapshots of a warmed-up simulation.
//!
//! Two backends with the same behaviour. On Linux without libc: raw
//! syscalls. With libc, on Linux, macOS and the BSDs: `fork`, `pipe`,
//! `read`, `write`, `waitpid` and `_exit` from libc. Elsewhere `supported`
//! is false and `check` runs the same iterations in-process, which produces
//! identical results: forking is purely an optimization.

const std = @import("std");
const builtin = @import("builtin");

const Backend = enum { none, linux, libc };

pub const backend: Backend = switch (builtin.os.tag) {
    .linux => if (builtin.link_libc) .libc else .linux,
    .macos, .ios, .freebsd, .netbsd, .openbsd, .dragonfly => if (builtin.link_libc) .libc else .none,
    else => .none,
};

pub const supported = backend != .none;

const linux = if (backend == .linux) std.os.linux else struct {};

const c = struct {
    extern "c" fn fork() c_int;
    extern "c" fn pipe(fds: *[2]c_int) c_int;
    extern "c" fn close(fd: c_int) c_int;
    extern "c" fn read(fd: c_int, buf: [*]u8, len: usize) isize;
    extern "c" fn write(fd: c_int, buf: [*]const u8, len: usize) isize;
    extern "c" fn waitpid(pid: c_int, status: ?*c_int, options: c_int) c_int;
    extern "c" fn _exit(code: c_int) noreturn;

    fn interrupted() bool {
        return std.c._errno().* == @backingInt(std.c.E.INTR);
    }
};

pub const Fd = i32;

pub const Fork = union(enum) {
    /// In the child: the write end of the result pipe.
    child: Fd,
    /// In the parent: the child's pid and the read end of its pipe.
    parent: struct { pid: i32, fd: Fd },
};

pub fn fork() !Fork {
    var fds: [2]i32 = undefined;
    const pid: i32 = switch (backend) {
        .none => return error.ForkUnsupported,
        .linux => blk: {
            if (linux.errno(linux.pipe(&fds)) != .SUCCESS) return error.SystemResources;
            const rc = linux.fork();
            if (linux.errno(rc) != .SUCCESS) {
                close(fds[0]);
                close(fds[1]);
                return error.SystemResources;
            }
            break :blk @intCast(rc);
        },
        .libc => blk: {
            if (c.pipe(&fds) != 0) return error.SystemResources;
            const rc = c.fork();
            if (rc < 0) {
                close(fds[0]);
                close(fds[1]);
                return error.SystemResources;
            }
            break :blk rc;
        },
    };
    if (pid == 0) {
        close(fds[0]);
        return .{ .child = fds[1] };
    }
    close(fds[1]);
    return .{ .parent = .{ .pid = pid, .fd = fds[0] } };
}

/// One `write`: the bytes written, 0 to retry (interrupted), or null on
/// an error.
fn writeSome(fd: Fd, bytes: []const u8) ?usize {
    switch (backend) {
        .none => return null,
        .linux => {
            const rc = linux.write(fd, bytes.ptr, bytes.len);
            return switch (linux.errno(rc)) {
                .SUCCESS => rc,
                .INTR => 0,
                else => null,
            };
        },
        .libc => {
            const rc = c.write(fd, bytes.ptr, bytes.len);
            if (rc >= 0) return @intCast(rc);
            return if (c.interrupted()) 0 else null;
        },
    }
}

const ReadResult = union(enum) { bytes: usize, retry, end };

fn readSome(fd: Fd, buf: []u8) ReadResult {
    switch (backend) {
        .none => return .end,
        .linux => {
            const rc = linux.read(fd, buf.ptr, buf.len);
            return switch (linux.errno(rc)) {
                .SUCCESS => if (rc == 0) .end else .{ .bytes = rc },
                .INTR => .retry,
                else => .end,
            };
        },
        .libc => {
            const rc = c.read(fd, buf.ptr, buf.len);
            if (rc > 0) return .{ .bytes = @intCast(rc) };
            if (rc == 0) return .end;
            return if (c.interrupted()) .retry else .end;
        },
    }
}

pub fn writeAll(fd: Fd, bytes: []const u8) void {
    var done: usize = 0;
    while (done < bytes.len) done += writeSome(fd, bytes[done..]) orelse return;
}

/// Reads until EOF or `buf` is full; returns the bytes read.
pub fn readAll(fd: Fd, buf: []u8) usize {
    var done: usize = 0;
    while (done < buf.len) switch (readSome(fd, buf[done..])) {
        .bytes => |n| done += n,
        .retry => {},
        .end => break,
    };
    return done;
}

pub fn close(fd: Fd) void {
    switch (backend) {
        .none => {},
        .linux => _ = linux.close(fd),
        .libc => _ = c.close(fd),
    }
}

/// Waits for `pid`; returns its raw wait status.
pub fn wait(pid: i32) u32 {
    var status: i32 = 0;
    switch (backend) {
        .none => {},
        .linux => while (linux.errno(linux.waitpid(pid, &status, 0)) == .INTR) {},
        .libc => while (c.waitpid(pid, &status, 0) < 0 and c.interrupted()) {},
    }
    return @bitCast(status);
}

/// Exits the child immediately: no `defer`s, no atexit handlers, no test
/// runner teardown in a process that is a copy of the parent.
pub fn exitNow(code: u8) noreturn {
    switch (backend) {
        .none => unreachable,
        .linux => linux.exit_group(code),
        .libc => c._exit(code),
    }
}
