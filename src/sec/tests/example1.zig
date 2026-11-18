const std = @import("std");
const tardis = @import("tardis");
const tardis_sec = @import("tardis_sec");
const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

test "tenant AEAD: isolation, zeroization, padding, glitch resistance" {
    try tardis.check(std.testing.allocator, struct {
        fn run(env: *tardis.Env) !void {
            var key: [32]u8 = undefined;
            env.io.random(&key);
            tardis_sec.markSecret(&key); // leaves the process: CWE-200; freed unzeroed: CWE-226
            defer std.crypto.secureZero(u8, &key); // 0x7 -> 0xB, so no false positive
            const msg = try env.fuzz([48]u8); // 0x9 untrusted; the DoS ledger steers the fuzzer
            var out: struct { ct: [48]u8, tag: [16]u8, pad: [16]u8 } = undefined; // pad: uninit
            var pt: [48]u8 = undefined;
            tardis_sec.withTenant(2, Aead.encrypt, .{ &out.ct, &out.tag, &msg, "", @as([12]u8, @splat(0)), key });
            try env.dir.writeFile(env.io, .{ .sub_path = "t2.bin", .data = out.ct[0..] }); // egress scan
            out.ct[0] ^= 1; // a forged frame: rejected even if one compare is glitched
            const ok = if (Aead.decrypt(&pt, &out.ct, out.tag, "", @as([12]u8, @splat(0)), key)) |_| true else |_| false;
            try env.always("forged frame rejected", !(tardis_sec.criticalCheck(env, ok) and tardis_sec.criticalCheck(env, ok)));
        }
    }.run, tardis_sec.withSecurity(.{ .instruction_skip_glitch_ppm = 1_000, .base = .{ .iterations = 200 } }));
}

// The constant-time oracle (7 more lines): two secrets, identical traces.
fn macThenSend(env: *tardis.Env, _: []const u8, key: []const u8) !void {
    var tag: [16]u8 = undefined;
    std.crypto.onetimeauth.Poly1305.create(&tag, "frame", key[0..32]);
    try env.dir.writeFile(env.io, .{ .sub_path = "tag", .data = &tag });
}

test "Poly1305 tagging is constant time at the I/O boundary" {
    const a: [32]u8 = @splat(0x11);
    const b: [32]u8 = @splat(0xEE);
    try tardis_sec.assertConstantTime(std.testing.allocator, macThenSend, &a, &b, 64, .{});
}
