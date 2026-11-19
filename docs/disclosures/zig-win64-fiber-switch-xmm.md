# Draft report: `std.Io.fiber.contextSwitch` does not preserve `xmm6`–`xmm15` on 64-bit Windows

**Status: draft. Not sent to the Zig project, and not to be sent without the
owner's say-so.**

| | |
|---|---|
| Found | 2026-11-19, while writing a test for this repository (revision 71) |
| Fixed here | revision 72, `src/sim/fiber.zig` (`switchTo`) |
| Zig version | 0.17.0 |
| Target | `x86_64-windows` |
| Affects | callers of `std.Io.fiber.contextSwitch` on 64-bit Windows, in optimized builds |

## Summary

On 64-bit Windows a function must return with `xmm6` to `xmm15` holding what
they held when it was called. A function that switches fibers with
`std.Io.fiber.contextSwitch` does not: when its fiber is resumed, those
registers hold whatever the other fiber left in them, and nothing restores
them before the function returns. A caller that kept a value in one of
them across the call reads another fiber's value.

## Why it happens

`contextSwitch` is an `inline fn` wrapping inline assembly. The assembly
saves and restores `rsp`, `rbp` and `rip` through the `Context`, and lists
every other register as clobbered, the general registers and `zmm0` to
`zmm31` among them.

For the general registers that list does the right thing: the function
that contains the assembly pushes the callee-saved ones in its prologue and
pops them in its epilogue, so its own caller sees them unchanged.

For the vector registers it does not. The clobber stops the containing
function from keeping its own values in them across the switch, but the
compiler emits no save of `xmm6`–`xmm15` in the prologue and no restore in
the epilogue. In the assembly emitted for this repository's
`sim.Sim.reschedule` (ReleaseFast, the only function that contains the
switch) the prologue is:

```
push rbp
push r15
push r14
push r13
push r12
push rsi
push rdi
push rbx
sub  rsp, 136
lea  rbp, [rsp + 128]
```

with no `movaps [rsp + …], xmm6` and no `.seh_savexmm`.

On System V targets there is nothing to preserve: every vector register is
caller-saved. That is why the same code is correct on Linux and macOS.

## How it showed

A ReleaseFast build kept a zero vector in `xmm6` across a call that ran a
simulation (and so switched fibers many times), then used it to clear a
field:

```
vmovdqu xmmword ptr [r12 + 624], xmm6
```

Another fiber had filled `xmm6` with all ones (a vectorised
`@memset(timers, maxInt(u64))`). The field, an optional that should have
been null, read as non-null with a pointer of `0xffffffffffffffff`, and the
next use faulted at that address. Debug, ReleaseSafe and ReleaseSmall
builds of the same code did not keep a value in those registers across the
call and showed nothing.

## Reproduction

`src/sim/fiber.zig` in this repository has a test, "a switch keeps the
vector registers a Win64 callee must preserve". It zeroes `xmm6` and
`xmm15`, calls a function that switches to a fiber which fills `xmm6`–
`xmm15` with ones and switches back, and reads the two registers. With the
workaround below removed it fails: the registers come back as all ones.

A standalone reproduction needs only `std.Io.fiber`: two contexts, a fiber
whose body executes `pcmpeqd xmm6, xmm6` and switches back, and a caller
that compares `xmm6` before and after. (Not yet written as a single file.)

## Workaround used here

`switchTo` saves the ten registers to its own stack frame before the
switch and loads them back after it, on 64-bit Windows only:

```zig
var saved: [10][16]u8 align(16) = undefined;
asm volatile ("movups %%xmm6, 0(%[p]) …" … );
_ = sf.contextSwitch(&s);
asm volatile ("movups 0(%[p]), %%xmm6 …" … );
```

The frame is on the fiber's own stack, so each fiber gets its own values
back when it resumes.

## What a fix upstream might be

Either of:

- `contextSwitch` saves and restores `xmm6`–`xmm15` itself on Windows, in
  the `Context` or on the stack, as it does `rbp`.
- The compiler treats a clobber of a callee-saved vector register in
  inline assembly as it treats one of a callee-saved general register, and
  saves it in the prologue.

## What is not known

- Whether Zig's own users of `contextSwitch` on Windows, if it has any,
  are affected in practice. It depends on whether a caller keeps a value
  in those registers across a switch. That code has not been read.
- Whether the missing prologue save is intended behaviour of the compiler
  for inline-assembly clobbers, or a defect in itself.
- Whether `mxcsr` and the x87 control word, which Windows also expects a
  callee to preserve, need the same treatment. They are in the clobber
  list; this repository does not save them.
- aarch64 Windows, which has its own callee-saved vector registers
  (`v8`–`v15`), has not been looked at.
