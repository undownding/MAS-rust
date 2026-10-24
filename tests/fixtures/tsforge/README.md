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
