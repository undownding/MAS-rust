# TSforge synthetic fixtures

These files contain no real system licensing data. The source specification is
LibTSforge embedded in `vendor/mas/MAS_AIO.cmd`, pinned in `vendor/mas/NOTICE.md`.

Regenerate binary records with `python3 tools/tsforge_codec_vectors.py`.
Regenerate encrypted envelopes with `python3 tools/tsforge_crypto_vectors.py`
(requires Python `cryptography`; generated here with version 46.0.5).
Both generators produce deterministic files independently of the Rust codecs.

Bag fixtures cover unknown record types, duplicate keys, empty key/value fields,
Vista reserved words and alignment. Store fixtures cover all three layouts,
unknown fields, duplicate modern keys and multiple groups. Envelopes cover
Vista/Windows 7/modern headers, production/test RSA keys, AES-128/192/256, and
salted SHA-1 versus HMAC-SHA1. Format and crypto fixtures are synthetic and do
not establish compatibility with all real Windows stores.

`python3 tools/tsforge_token_vectors.py` regenerates `tokens-modern.bin` and
`token-meta.bin` with Python's hashlib/struct (no external dependency). These
cover two directory blocks, named inactive slots, Unicode surrogate pairs,
empty populated content and duplicate metadata keys.

`python3 tools/tsforge_key_vectors.py` regenerates `key2009.json`. Five synthetic
PKEY2009 cases verify field packing, base-24/N encoding, binding bag and GUID
memory bytes, phone payloads, PID3 checksum and PID4 fixed Unicode fields.
The generator uses byte-wise long division and polynomial-division CRC, while
the Rust encoder uses u128 arithmetic and a bit-loop CRC. No installation occurs.

`python3 tools/tsforge_legacy_key_vectors.py` regenerates `key2005.json`, containing
five PKEY2005 encodings/PIDs and eleven seeded RNG sequences of 128 values each.
The seed list includes Int32.MinValue/MaxValue and seeds produced by unchecked
MAS group/serial arithmetic. `tools/verify_pkey2005.ps1` validates the sequences
and key suffixes using actual .NET Framework System.Random on Windows CI before
Rust tests. The script performs no licensing operations. Reference provenance
and MIT notice are preserved in `vendor/dotnet-reference`.
