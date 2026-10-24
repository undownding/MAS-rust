# Upstream provenance

Upstream: https://github.com/massgravel/Microsoft-Activation-Scripts
License: GPL-3.0 (see LICENSE). Upstream contributors retain their copyrights.
The vendored scripts are unmodified, including their original CRLF line endings.

| File | Commit | SHA-256 |
| --- | --- | --- |
| MAS_AIO.cmd (3.12) | 6401d2f36975dc07bcb6d22ea823a8498a75ec01 | 850f979665fb93999acae93f4790c1ff8ed2041532060b7966a121c2d29a0bfa |
| KMS38_Activation.cmd | c9789e9aa34145b6608204dba8d8f5f3e71c6d86 | 1c4f8ada8ad9ee7f0aedda6f06b6d083663a6a35e6a65278af130c13ec575f55 |

Original paths: MAS/All-In-One-Version-KL/MAS_AIO.cmd and MAS/Separate-Files-Version/Activators/KMS38_Activation.cmd.
KMS38's pinned commit is the parent of the removal commit 470d3b900e6aebfba224fde3ea7957308dd61230.

The Rust integration writes these bytes to an exclusive temporary directory and invokes only allowlisted options. It adds a separate launcher with -qedit to avoid the interactive script detaching before temporary-file cleanup, and waits for acknowledgement before closing the console. The scripts' network behavior is unchanged.

## Native migration data

`native/hwid.tsv`, `native/kms38.tsv`, their fallback tables, `native/ohook.tsv`, `native/office-msi.tsv`, `native/online-kms.tsv`, `native/online-kms-fallback.tsv`, `native/kms-servers.txt`, and `native/ticket-key.blob` are extracted from the above pinned files by `tools/extract_native_data.py`. The blob is the upstream public signing data, not a user credential. The original scripts remain unchanged. Rust implementations derived from those algorithms retain this project's GPL-3.0-only licensing. Independent reference tickets in `tests/fixtures` validate the Rust encoding and signature output.

Since v0.2.0 compatibility scripts are staged under LOCALAPPDATA/MAS-Rust/engine-runs, not the user's Temp subtree, because upstream rejects nested Temp paths. Noninteractive runs stream a log into the GUI. HWID/KMS38 primary activation routes no longer execute those scripts.

`native/tsforge-production.blob` and `native/tsforge-test.blob` are extracted
verbatim from the public `LibTSforge.Crypto.Keys` constants in the pinned
`MAS_AIO.cmd`. They are not credentials obtained from a local machine.
`tools/extract_native_data.py` reproduces the extraction. The Rust TSforge
storage codecs and crypto envelope are derived from the corresponding
LibTSforge classes in that same GPL-3.0 source.

`native/tsforge-hwid.bin` is the 38-byte `UniversalHWIDBlock` constant
from the same pinned LibTSforge source, reproduced by
`tools/extract_native_data.py`; it is not hardware data collected from a user.

`native/tsforge-activation-mac.bin` is the public 64-byte ActivationWs
MacKey constant from the pinned script, extracted by the same tool. It is
protocol data from upstream, not an account credential or locally obtained secret.

`native/tsforge-kms-v4.bin`, `tsforge-kms-v5.bin`, and `tsforge-kms-v6.bin`
are the pinned public KMS response constants used by LibTSforge. Extraction
is reproducible with `tools/extract_native_data.py`; they are not responses
collected from a user's KMS service.

`native/tsforge-editions.tsv` preserves the SKU/edition table and legacy alias order from the pinned `:ts_getedition:` section, extracted by `tools/extract_native_data.py` (GPL-3.0-only).
