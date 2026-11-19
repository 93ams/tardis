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
    for ([_][]const u8{ "examples/wal_kv.zig", "examples/counter.zig", "examples/jobs.zig", "examples/replica.zig", "examples/dir_sync.zig", "examples/deadlock.zig", "examples/short_write.zig", "examples/error_leak.zig", "examples/check_then_act.zig", "examples/rename_unsynced.zig", "examples/oom_partial.zig", "examples/lease.zig", "examples/in_place_rewrite.zig", "examples/index_before_data.zig", "examples/id_reuse.zig", "examples/short_read.zig", "examples/udp_retry.zig", "examples/udp_order.zig", "examples/udp_no_timeout.zig", "examples/stale_read.zig" }) |path| {
        const t = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(path),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "tardis", .module = mod }},
            }),
            .filters = test_filters,
        });
        examples_step.dependOn(&b.addRunArtifact(t).step);
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
    for ([_][]const u8{ "wal_kv", "counter", "jobs", "replica", "dir_sync", "deadlock", "short_write", "error_leak", "check_then_act", "rename_unsynced", "oom_partial", "lease", "in_place_rewrite", "index_before_data", "id_reuse", "short_read", "udp_retry", "udp_order", "udp_no_timeout", "stale_read" }) |name| {
        bugbench_mod.addImport(name, b.createModule(.{
            .root_source_file = b.path(b.fmt("examples/{s}.zig", .{name})),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "tardis", .module = mod }},
        }));
    }
    const bugbench = b.addExecutable(.{ .name = "tardis-bugbench", .root_module = bugbench_mod });
    const bugbench_step = b.step("bugbench", "Run the bug benchmark: planted bugs, found or not, and what they shrink to");
    bugbench_step.dependOn(&b.addRunArtifact(bugbench).step);

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
