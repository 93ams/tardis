const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_filters = b.option([]const []const u8, "test-filter", "Run only tests whose names contain this text") orelse &.{};

    // `-Dlibc` links libc into the library and its tests: on Linux the
    // fork server then goes through libc, as it does on macOS and the BSDs,
    // where libc is linked anyway.
    const libc = b.option(bool, "libc", "Link libc into the library (the fork server then uses libc's fork)") orelse false;

    // The library module consumers import as `@import("tardis")`.
    const mod = b.addModule("tardis", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = if (libc) true else null,
    });

    // Seam 4 (plan2.md §8.2): `TARDIS_SEC=1 zig build test`, or `-Dsec`,
    // attaches `tardis_sec` in `.audit` mode to every simulator whose options
    // name no security layer. Off, core imports a stub and compiles no
    // security code.
    const sec_everywhere = b.option(bool, "sec", "Attach tardis_sec (audit mode) to every check (default: TARDIS_SEC=1)") orelse
        std.mem.eql(u8, b.graph.environ_map.get("TARDIS_SEC") orelse "", "1");
    const no_sec = b.createModule(.{ .root_source_file = b.path("src/sim/sec_default.zig") });

    // `zig build test`: unit, semantic, determinism and bug-finding tests.
    const mod_tests = b.addTest(.{ .root_module = mod, .filters = test_filters });
    const run_mod_tests = b.addRunArtifact(mod_tests);
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_mod_tests.step);

    // `tardis_sec` (plan2.md): the security layer, as its own module over
    // the core seam. `zig build test-sec` runs its tests alone.
    const sec_mod = b.addModule("tardis_sec", .{
        .root_source_file = b.path("src/sec/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "tardis", .module = mod }},
    });
    mod.addImport("tardis_sec_default", if (sec_everywhere) sec_mod else no_sec);
    const sec_step = b.step("test-sec", "Run the tardis_sec tests");
    const sec_tests = b.addTest(.{ .root_module = sec_mod, .filters = test_filters });
    sec_step.dependOn(&b.addRunArtifact(sec_tests).step);
    const sec_imports: []const std.Build.Module.Import = &.{
        .{ .name = "tardis", .module = mod },
        .{ .name = "tardis_sec", .module = sec_mod },
    };
    for ([_][]const u8{ "src/sec/tests/pillar1_test.zig", "src/sec/tests/pillar2_test.zig", "src/sec/tests/pillar45_test.zig", "src/sec/tests/example1.zig", "src/sec/tests/example2.zig", "src/sec/tests/refall_test.zig" }) |path| {
        const t = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(path),
                .target = target,
                .optimize = optimize,
                .imports = sec_imports,
            }),
            .filters = test_filters,
        });
        sec_step.dependOn(&b.addRunArtifact(t).step);
    }
    // The C shims (plan2.md §5.2): C code built against `src/sec/c`.
    const cshim_mod = b.createModule(.{
        .root_source_file = b.path("src/sec/tests/cshim_test.zig"),
        .target = target,
        .optimize = optimize,
        .imports = sec_imports,
        .link_libc = true,
    });
    cshim_mod.addIncludePath(b.path("src/sec/c"));
    cshim_mod.addCSourceFile(.{ .file = b.path("src/sec/tests/c/legacy.c"), .flags = &.{ "-std=c99", "-Wall", "-Wno-format-security", "-Wno-unused-function" } });
    sec_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = cshim_mod, .filters = test_filters })).step);
    // The tracer for instrumented C (plan2.md §6.3): SanitizerCoverage.
    const ctrace_mod = b.createModule(.{
        .root_source_file = b.path("src/sec/tests/ctrace_test.zig"),
        .target = target,
        .optimize = optimize,
        .imports = sec_imports,
        .link_libc = true,
    });
    ctrace_mod.addIncludePath(b.path("src/sec/c"));
    ctrace_mod.addCSourceFile(.{ .file = b.path("src/sec/tests/c/ct.c"), .flags = &.{ "-std=c99", "-Wall", "-fsanitize-coverage=trace-pc,trace-cmp,trace-div,trace-loads,trace-stores", "-fno-autolink" } });
    sec_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = ctrace_mod, .filters = test_filters })).step);
    // Shadow memory (plan2.md §3.8): the code under test is an object built
    // with the sanitizer's callbacks, linked into a test that is not (Zig
    // links its own sanitizer runtime into anything that is). The C is
    // built with clang's load and store tracing, which every target has.
    const shadow_mod = b.createModule(.{
        .root_source_file = b.path("src/sec/tests/shadow_test.zig"),
        .target = target,
        .optimize = optimize,
        .imports = sec_imports,
        .link_libc = true,
    });
    shadow_mod.addCSourceFile(.{ .file = b.path("src/sec/tests/c/shadow.c"), .flags = &.{ "-std=c99", "-Wall", "-fsanitize-coverage=trace-pc,trace-loads,trace-stores", "-fno-autolink" } });
    const shadow_tests = b.addTest(.{ .root_module = shadow_mod, .filters = test_filters });
    _ = addInstrumentedObject(b, shadow_tests, .{
        .name = "shadow_sut",
        .root_source_file = b.path("src/sec/tests/shadow/sut.zig"),
        .target = target,
        .optimize = optimize,
    });
    sec_step.dependOn(&b.addRunArtifact(shadow_tests).step);
    test_step.dependOn(sec_step);

    // `zig build evidence`: the certification campaigns in certification
    // mode, with their signed bundles (and SARIF) kept under
    // zig-out/tardis-evidence for CI to upload.
    //
    // With `-Dedges` (Linux or macOS), the campaigns are built with Zig's
    // edge counters (`-ffuzz`, LLVM) and the bundles list the code they
    // never ran (`edges.json`, plan2.md §7.1). Zig's default test runner
    // only runs such a build under its fuzzer, so a plain runner runs it.
    const edges = b.option(bool, "edges", "With `evidence`: count edges and list dead code (needs an ELF or Mach-O target)") orelse false;
    const evidence_tests = if (edges) blk: {
        const fuzz_mod = b.createModule(.{ .root_source_file = b.path("src/root.zig"), .target = target, .optimize = optimize, .fuzz = true });
        const fuzz_sec = b.createModule(.{
            .root_source_file = b.path("src/sec/root.zig"),
            .target = target,
            .optimize = optimize,
            .fuzz = true,
            .imports = &.{.{ .name = "tardis", .module = fuzz_mod }},
        });
        fuzz_mod.addImport("tardis_sec_default", if (sec_everywhere) fuzz_sec else no_sec);
        break :blk b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/sec/tests/example2.zig"),
                .target = target,
                .optimize = optimize,
                .fuzz = true,
                .imports = &.{ .{ .name = "tardis", .module = fuzz_mod }, .{ .name = "tardis_sec", .module = fuzz_sec } },
            }),
            .filters = test_filters,
            .use_llvm = true,
            .use_lld = if (target.result.ofmt == .elf) true else null,
            .test_runner = .{ .path = b.path("src/sec/tests/edge_runner.zig"), .mode = .simple },
        });
    } else b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/sec/tests/example2.zig"),
            .target = target,
            .optimize = optimize,
            .imports = sec_imports,
        }),
        .filters = test_filters,
    });
    const run_evidence = b.addRunArtifact(evidence_tests);
    run_evidence.setCwd(b.path("."));
    run_evidence.setEnvironmentVariable("TARDIS_CERT_EAL7", "1");
    run_evidence.setEnvironmentVariable("TARDIS_EVIDENCE_DIR", "zig-out/tardis-evidence");
    run_evidence.has_side_effects = true;
    const evidence_step = b.step("evidence", "Run the certification campaigns and keep their evidence bundles in zig-out/tardis-evidence");
    if (edges and target.result.ofmt != .elf and target.result.ofmt != .macho) {
        evidence_step.dependOn(&b.addFail("-Dedges needs an ELF or Mach-O target (Linux or macOS): Zig's edge counters are not emitted for COFF").step);
    } else evidence_step.dependOn(&run_evidence.step);

    // `zig build test-edges`: guided exploration fed by Zig's edge
    // counters (`src/sec/tests/edge_guided.zig`). Its own step, since it
    // needs an instrumented build on an ELF or Mach-O target.
    const test_edges_step = b.step("test-edges", "Test edge coverage as guidance (needs an ELF or Mach-O target)");
    if (target.result.ofmt != .elf and target.result.ofmt != .macho) {
        test_edges_step.dependOn(&b.addFail("test-edges needs an ELF or Mach-O target (Linux or macOS): Zig's edge counters are not emitted for COFF").step);
    } else {
        const fuzz_mod = b.createModule(.{ .root_source_file = b.path("src/root.zig"), .target = target, .optimize = optimize, .fuzz = true });
        const fuzz_sec = b.createModule(.{
            .root_source_file = b.path("src/sec/root.zig"),
            .target = target,
            .optimize = optimize,
            .fuzz = true,
            .imports = &.{.{ .name = "tardis", .module = fuzz_mod }},
        });
        fuzz_mod.addImport("tardis_sec_default", if (sec_everywhere) fuzz_sec else no_sec);
        const edge_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/sec/tests/edge_guided.zig"),
                .target = target,
                .optimize = optimize,
                .fuzz = true,
                .imports = &.{ .{ .name = "tardis", .module = fuzz_mod }, .{ .name = "tardis_sec", .module = fuzz_sec } },
            }),
            .filters = test_filters,
            .use_llvm = true,
            .use_lld = if (target.result.ofmt == .elf) true else null,
            .test_runner = .{ .path = b.path("src/sec/tests/edge_runner.zig"), .mode = .simple },
        });
        test_edges_step.dependOn(&b.addRunArtifact(edge_tests).step);
    }

    // `zig build test-examples`: each example plants one class of bug and
    // shows its fix (examples/, plan3.md C2). Part of `test`.
    const examples_step = b.step("test-examples", "Run the examples: each finds its planted bug and passes its fix");
    for ([_][]const u8{ "examples/wal_kv.zig", "examples/counter.zig", "examples/jobs.zig", "examples/replica.zig", "examples/dir_sync.zig", "examples/deadlock.zig", "examples/livelock.zig", "examples/hidden_state.zig", "examples/never_retried.zig", "examples/short_write.zig", "examples/error_leak.zig", "examples/check_then_act.zig", "examples/rename_unsynced.zig", "examples/oom_partial.zig", "examples/lease.zig", "examples/in_place_rewrite.zig", "examples/index_before_data.zig", "examples/id_reuse.zig", "examples/short_read.zig", "examples/udp_retry.zig", "examples/udp_order.zig", "examples/udp_no_timeout.zig", "examples/stale_read.zig", "examples/syscall_rename.zig", "examples/lin_register.zig", "examples/write_skew.zig" }) |path| {
        const t = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(path),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "tardis", .module = mod }},
            }),
            .filters = test_filters,
        });
        const run_example = b.addRunArtifact(t);
        // A failure's replay line then names the step that runs it.
        run_example.setEnvironmentVariable("TARDIS_REPLAY_COMMAND", "zig build test-examples");
        examples_step.dependOn(&run_example.step);
    }
    test_step.dependOn(examples_step);

    // `zig build bugbench`: the bug benchmark (plan3.md F1): for each
    // example, what a plain run of the planted bug sees, whether a campaign
    // finds it, and what the failure shrinks to.
    const bugbench_mod = b.createModule(.{
        .root_source_file = b.path("src/cmd/bugbench/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "tardis", .module = mod }},
    });
    for ([_][]const u8{ "wal_kv", "counter", "jobs", "replica", "dir_sync", "deadlock", "livelock", "hidden_state", "never_retried", "short_write", "error_leak", "check_then_act", "rename_unsynced", "oom_partial", "lease", "in_place_rewrite", "index_before_data", "id_reuse", "short_read", "udp_retry", "udp_order", "udp_no_timeout", "stale_read", "syscall_rename", "lin_register", "write_skew" }) |name| {
        bugbench_mod.addImport(name, b.createModule(.{
            .root_source_file = b.path(b.fmt("examples/{s}.zig", .{name})),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "tardis", .module = mod }},
        }));
    }
    const bugbench = b.addExecutable(.{ .name = "tardis-bugbench", .root_module = bugbench_mod });
    const bugbench_step = b.step("bugbench", "Run the bug benchmark: planted bugs, found or not, and what they shrink to");
    // `zig build install-bugbench`: the program itself, to run under a
    // profiler (docs/measurements.md §5).
    const install_bugbench = b.step("install-bugbench", "Install the bug benchmark's program, to run under a profiler");
    install_bugbench.dependOn(&b.addInstallArtifact(bugbench, .{}).step);
    const run_bugbench = b.addRunArtifact(bugbench);
    bugbench_step.dependOn(&run_bugbench.step);
    // `zig build bugbench-rates`: the detection table (plan3.md A5).
    const run_rates = b.addRunArtifact(bugbench);
    run_rates.addArg("--rates");
    const rates_step = b.step("bugbench-rates", "Print which oracle catches each planted bug, and how often by campaign size");
    rates_step.dependOn(&run_rates.step);
    // `zig build bugbench-baselines`: the baseline table (plan3.md F2).
    const run_baselines = b.addRunArtifact(bugbench);
    run_baselines.addArg("--baselines");
    const baselines_step = b.step("bugbench-baselines", "Print whether each planted bug is still found without faults, and without preemption");
    baselines_step.dependOn(&run_baselines.step);
    // `zig build bugbench-schedules`: the schedule table (plan3.md E5).
    const run_schedules = b.addRunArtifact(bugbench);
    run_schedules.addArg("--schedules");
    const schedules_step = b.step("bugbench-schedules", "Print how often each planted bug is found with tasks switched at random and by priority (PCT)");
    schedules_step.dependOn(&run_schedules.step);

    // `zig build run`: demo of a crash-consistency bug found per persona.
    const demo = b.addExecutable(.{
        .name = "tardis-demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cmd/demo/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "tardis", .module = mod }},
        }),
    });
    b.installArtifact(demo);
    const run_demo = b.addRunArtifact(demo);
    run_demo.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the TARDIS demo");
    run_step.dependOn(&run_demo.step);

    // `zig build docs`: the API reference, generated from the doc comments
    // of `src/root.zig` and what it exports, into zig-out/docs (plan3.md
    // C4). `scripts/doc_check.py` lists public declarations without one.
    const docs_obj = b.addObject(.{
        .name = "tardis",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = .Debug,
            .imports = &.{.{ .name = "tardis_sec_default", .module = no_sec }},
        }),
    });
    const install_docs = b.addInstallDirectory(.{
        .source_dir = docs_obj.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    const docs_step = b.step("docs", "Build the API reference into zig-out/docs");
    docs_step.dependOn(&install_docs.step);

    // `zig build membench`: memory per simulator, by option (plan3.md E3).
    const membench = b.addExecutable(.{
        .name = "tardis-membench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cmd/membench/main.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
            .imports = sec_imports,
        }),
    });
    const membench_step = b.step("membench", "Print the memory one simulator takes, by option");
    membench_step.dependOn(&b.addRunArtifact(membench).step);

    // `zig build secrates`: the security layer's detection table
    // (plan3.md A5), over the planted bugs of its own tests.
    const secrates_mod = b.createModule(.{
        .root_source_file = b.path("src/cmd/secrates/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = sec_imports,
    });
    for ([_][2][]const u8{
        .{ "pillar1", "src/sec/tests/pillar1_test.zig" },
        .{ "pillar2", "src/sec/tests/pillar2_test.zig" },
        .{ "pillar45", "src/sec/tests/pillar45_test.zig" },
    }) |m| secrates_mod.addImport(m[0], b.createModule(.{
        .root_source_file = b.path(m[1]),
        .target = target,
        .optimize = optimize,
        .imports = sec_imports,
    }));
    const secrates = b.addExecutable(.{ .name = "tardis-secrates", .root_module = secrates_mod });
    const secrates_step = b.step("secrates", "Print how often the security layer's oracles find their planted bugs, and false alarms on the fixed versions");
    secrates_step.dependOn(&b.addRunArtifact(secrates).step);
    // Built by `zig build test`, so the table's program keeps compiling.
    test_step.dependOn(&secrates.step);

    // `zig build bench`: simulator throughput, always optimized.
    const bench_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .ReleaseFast,
        .imports = &.{.{ .name = "tardis_sec_default", .module = no_sec }},
    });
    const bench = b.addExecutable(.{
        .name = "tardis-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cmd/bench/main.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{.{ .name = "tardis", .module = bench_mod }},
        }),
    });
    const install_bench = b.addInstallArtifact(bench, .{});
    const bench_build_step = b.step("bench-build", "Build the benchmarks without running them");
    bench_build_step.dependOn(&install_bench.step);
    const run_bench = b.addRunArtifact(bench);
    const bench_step = b.step("bench", "Run the simulator benchmarks (ReleaseFast)");
    bench_step.dependOn(&run_bench.step);

    // `zig build test-cpp`: a C++ program (`test/cpp/probe.cpp`) under
    // system-call mode, which is also the default suite's test of a
    // program linked with libc. Zig compiles the C++, so nothing is
    // fetched and no other toolchain is needed: on Linux x86_64 it is part
    // of `zig build test`, against the target's C library (musl or glibc).
    const cpp_step = b.step("test-cpp", "Run a C++ program under system-call mode (Linux x86_64)");
    if (target.result.os.tag != .linux or target.result.cpu.arch != .x86_64) {
        cpp_step.dependOn(&b.addFail("test-cpp needs Linux on x86_64: system-call mode exists nowhere else").step);
    } else {
        const cpp_mod = b.createModule(.{
            .root_source_file = b.path("test/cpp.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "tardis", .module = mod }},
            .link_libc = true,
            .link_libcpp = true,
        });
        cpp_mod.addCSourceFile(.{ .file = b.path("test/cpp/probe.cpp"), .flags = &.{"-std=c++20"} });
        cpp_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = cpp_mod, .filters = test_filters })).step);
        test_step.dependOn(cpp_step);
    }

    // `zig build test-sqlite -Dsqlite`: SQLite's amalgamation, built as it
    // ships with its own Unix VFS, run under system-call mode (plan3.md
    // D9). Linux on x86_64. Behind an option, so that nothing else fetches
    // SQLite's source.
    const with_sqlite = b.option(bool, "sqlite", "With `test-sqlite`: fetch SQLite and test it under system-call mode (Linux x86_64)") orelse false;
    const sqlite_step = b.step("test-sqlite", "Run SQLite under system-call mode (needs -Dsqlite; Linux x86_64)");
    if (!with_sqlite) {
        sqlite_step.dependOn(&b.addFail("test-sqlite needs -Dsqlite, which fetches SQLite's source").step);
    } else if (target.result.os.tag != .linux or target.result.cpu.arch != .x86_64) {
        sqlite_step.dependOn(&b.addFail("test-sqlite needs Linux on x86_64: system-call mode exists nowhere else").step);
    } else if (b.lazyDependency("sqlite", .{})) |sqlite| {
        const sqlite_mod = b.createModule(.{
            .root_source_file = b.path("test/sqlite.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "tardis", .module = mod }},
            .link_libc = true,
        });
        sqlite_mod.addCSourceFile(.{ .file = sqlite.path("sqlite3.c"), .flags = &.{"-DSQLITE_OMIT_LOAD_EXTENSION"} });
        sqlite_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = sqlite_mod, .filters = test_filters })).step);
    }

    // `zig build test-rust -Drust=<libtardis_rust_probe.a>`: the Rust crate
    // in `test/rust`, built by cargo for `x86_64-unknown-linux-musl` (or
    // `-gnu`, with a glibc target here) as a
    // static library, run under system-call mode (`test/rust.zig`). Behind
    // an option: nothing else needs cargo.
    const rust_lib = b.option([]const u8, "rust", "With `test-rust`: the static library cargo built from `test/rust` (Linux x86_64; for the same C library as the target)");
    const rust_step = b.step("test-rust", "Run a Rust program under system-call mode (needs -Drust=<library>; Linux x86_64)");
    if (rust_lib == null) {
        rust_step.dependOn(&b.addFail("test-rust needs -Drust=<path>: the library `cargo build --target x86_64-unknown-linux-musl` (or -gnu, for a glibc target) makes in test/rust").step);
    } else if (target.result.os.tag != .linux or target.result.cpu.arch != .x86_64) {
        rust_step.dependOn(&b.addFail("test-rust needs Linux on x86_64: system-call mode exists nowhere else").step);
    } else {
        // The library and the target must name one C library: musl with
        // `x86_64-unknown-linux-musl`, glibc with `x86_64-unknown-linux-gnu`.
        // Two C libraries in one program do not work.
        const rust_mod = b.createModule(.{
            .root_source_file = b.path("test/rust.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "tardis", .module = mod }},
            .link_libc = true,
        });
        rust_mod.addObjectFile(.{ .cwd_relative = rust_lib.? });
        // The Rust standard library's backtraces call the unwinder.
        rust_mod.linkSystemLibrary("unwind", .{});
        rust_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = rust_mod, .filters = test_filters })).step);
    }

    // The `tardis` program and the termancy suite need termancy. Only when
    // TARDIS is the root project: a package importing the library never
    // fetches it.
    if (b.pkg_hash.len == 0) {
        if (b.lazyDependency("termancy", .{ .target = target, .optimize = optimize })) |termancy| {
            tools(b, termancy, mod, sec_mod, target, optimize, test_filters, test_step);
        }
    }
}

pub const InstrumentedObject = struct {
    name: []const u8,
    root_source_file: std.Build.LazyPath,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    imports: []const std.Build.Module.Import = &.{},
};

/// Builds the code under test as an object with the sanitizer's callbacks
/// and links it into `tests`, for `tardis_sec`'s shadow memory, race
/// detector and lock order (plan2.md §3.8, §4.5, §4.6). From a consumer's
/// `build.zig`: `@import("tardis").addInstrumentedObject(b, tests, .{ ... })`.
///
/// The test must export the runtime (`comptime { tardis_sec.exportSanitizer(); }`)
/// and reach the object through `extern fn` declarations. Both are built by
/// LLVM: Zig types that cross the boundary (an `Allocator`, an `Io`) carry
/// functions with Zig's calling convention, on which Zig's own backend and
/// LLVM differ. `tests` itself must not be built with `sanitize_thread`.
pub fn addInstrumentedObject(b: *std.Build, tests: *std.Build.Step.Compile, options: InstrumentedObject) *std.Build.Step.Compile {
    const object = b.addObject(.{
        .name = options.name,
        .root_module = b.createModule(.{
            .root_source_file = options.root_source_file,
            .target = options.target,
            .optimize = options.optimize,
            .imports = options.imports,
            .sanitize_thread = true,
        }),
        .use_llvm = true,
    });
    tests.root_module.addObject(object);
    tests.use_llvm = true;
    return object;
}

fn tools(
    b: *std.Build,
    termancy: *std.Build.Dependency,
    tardis: *std.Build.Module,
    tardis_sec: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    test_filters: []const []const u8,
    test_step: *std.Build.Step,
) void {
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "tardis", .module = tardis },
        .{ .name = "cli", .module = termancy.module("cli") },
        .{ .name = "term", .module = termancy.module("term") },
        .{ .name = "sys", .module = termancy.module("sys") },
        .{ .name = "field", .module = termancy.module("field") },
    };

    // `tardis`: explain and replay tokens, list personas, scan test
    // output, verify evidence bundles.
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/cmd/tardis/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = imports,
    });
    exe_mod.addImport("tardis_sec", tardis_sec);
    const exe = b.addExecutable(.{ .name = "tardis", .root_module = exe_mod });
    b.installArtifact(exe);
    const exe_tests = b.addTest(.{ .root_module = exe_mod, .filters = test_filters });
    test_step.dependOn(&b.addRunArtifact(exe_tests).step);

    // termancy's own code (files, self-update) under simulated crashes.
    const suite = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/termancy.zig"),
            .target = target,
            .optimize = optimize,
            .imports = imports,
        }),
        .filters = test_filters,
    });
    const run_suite = b.addRunArtifact(suite);
    const suite_step = b.step("test-termancy", "Test termancy's files and self-update code under TARDIS");
    suite_step.dependOn(&run_suite.step);
    test_step.dependOn(&run_suite.step);
}
