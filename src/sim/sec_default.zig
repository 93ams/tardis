//! Seam 4's build switch (plan2.md §8.2): the security layer every
//! simulator gets when `Options.security` is null. This stub says "none";
//! `TARDIS_SEC=1 zig build test` (or `-Dsec`) points core's
//! `tardis_sec_default` import at `tardis_sec` instead, whose
//! `default_security` attaches the content engine in `.audit` mode to
//! every `check` in the build. Without the switch no security code is
//! compiled into core.
//!
//! The stub imports nothing (a file belongs to one module), so its value is
//! the untyped `null` that core coerces to `?sec_seam.Security`.

pub const default_security = null;
