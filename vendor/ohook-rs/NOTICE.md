# Ohook Rust source

Source: https://github.com/massgravel/ohook-rs
Pinned commit: `044af0e99d40a449c855d989feb7ad8ff042783f`
License: MIT; see LICENSE. Upstream copyright notices are preserved.

The Rust source and export definition are vendored for source-based builds, not extracted from MAS's embedded DLLs. Local adaptations, if any, are documented below. Both x86 and x64 DLLs must be built and their PE exports verified before embedding.

## Local adaptations

- Normalize source/DEF line endings and Rust formatting for this repository.
- Build with the current Rust compiler and its bundled LLD linker for both MSVC Windows targets; link without the C runtime and use LTO. No precompiled upstream DLL is redistributed.
- Omit the upstream `sppcs.rs` empty export stubs. They override forwarded exports with LLD; the original `.def` provides the required forwarders directly. Build-time PE inspection verifies every mapped export and the machine type.
- Replace the string-search call with a bounded UTF-16 search (SPP's buffer length is in bytes); stop at NUL and check returned pointers before reading.
- Use a nonrecursive abort-path spin loop, and assert the licensing status ABI size.
- Isolated fake-provider tests exercise error propagation, unlicensed/Grace preservation, and the modified licensing fields. These tests never call the real licensing service.

Original commit source hashes are available through the pinned GitHub tree above; local file changes are tracked in this project's git history. These adaptations retain the included MIT notice.
