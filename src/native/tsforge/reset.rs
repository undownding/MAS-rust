//! Field-level equivalents of the four LibTSforge reset modifiers.
use super::physical::{Block, Format, Store};

#[derive(Clone, Copy, Debug)]
pub enum Step {
    Tamper,
    RearmAndGrace,
    KeyLock,
}

// MAS uses case-sensitive substring matching on UTF-16LE value names. Match
// on code-unit boundaries without normalizing unknown binary value names.
fn contains(value: &[u8], name: &str) -> bool {
    let pattern: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    value
        .windows(pattern.len())
        .enumerate()
        .any(|(offset, bytes)| offset % 2 == 0 && bytes == pattern)
}
fn numeric(value: &[u8], number: u32) -> bool {
    value.get(..4) == Some(number.to_le_bytes().as_slice())
}

pub fn apply(store: &mut Store, step: Step) -> usize {
    let mut changes = 0;
    let format = store.format;
    let mut keep = |block: &mut Block| {
        let value = &block.value;
        let (remove, zero) = match (step, format) {
            (Step::Tamper, Format::Vista) => (
                contains(value, "6BE8425B-E3CF-4e86-A6AF-5863E3DCB606"),
                false,
            ),
            (Step::Tamper, Format::Win7) => (false, numeric(value, 0xa0001)),
            (Step::Tamper, Format::Modern) => (
                contains(value, "__##USERSEP-RESERVED##__$$RECREATED-FLAG$$")
                    || contains(value, "__##USERSEP-RESERVED##__$$RECOVERED-FLAG$$"),
                false,
            ),
            (Step::RearmAndGrace, format) => {
                let grace = contains(value, "msft:sl/timer");
                let rearm = match format {
                    Format::Vista => contains(value, "740D70D8-6448-4b2f-9063-4A7A463600C5"),
                    Format::Win7 => numeric(value, 0xa0000),
                    Format::Modern => contains(value, "__##USERSEP-RESERVED##__$$REARM-COUNT$$"),
                };
                (
                    grace || (format == Format::Vista && rearm),
                    format != Format::Vista && rearm,
                )
            }
            (Step::KeyLock, Format::Vista) => (false, false),
            (Step::KeyLock, _) => (
                contains(value, "msft:spp/timebased/AB")
                    || contains(value, "msft:spp/timebased/CD"),
                false,
            ),
        };
        if remove {
            changes += 1;
            return false;
        }
        if zero && block.data != [0; 8] {
            block.data = vec![0; 8];
            changes += 1;
        }
        true
    };
    if format == Format::Modern {
        for group in &mut store.groups {
            for key in group {
                key.blocks.retain_mut(&mut keep);
            }
        }
    } else {
        store.blocks.retain_mut(&mut keep);
    }
    changes
}

/// Keep modern callers explicit while sharing authenticated decoding with legacy
/// layouts. Build 9600 uses Modern (version 3), not the dormant WinBlue envelope.
pub fn decode_modern(original: &[u8]) -> std::io::Result<(Store, bool)> {
    decode(original, super::crypto::Version::Modern)
}
pub fn decode(original: &[u8], version: super::crypto::Version) -> std::io::Result<(Store, bool)> {
    use super::crypto;
    let (plaintext, production) = match crypto::decrypt(original, true, version) {
        Ok(data) => (data, true),
        Err(production_error) => match crypto::decrypt(original, false, version) {
            Ok(data) => (data, false),
            Err(test_error) => {
                return Err(std::io::Error::other(format!(
                    "许可存储解密失败：生产密钥 {production_error}；测试密钥 {test_error}"
                )));
            }
        },
    };
    Ok((Store::decode(&plaintext, version.format())?, production))
}
pub fn transform(original: &[u8], step: Step) -> std::io::Result<(Vec<u8>, usize)> {
    transform_version(original, step, super::crypto::Version::Modern)
}
pub fn transform_version(
    original: &[u8],
    step: Step,
    version: super::crypto::Version,
) -> std::io::Result<(Vec<u8>, usize)> {
    use super::crypto;
    let (mut store, production) = decode(original, version)?;
    let changed = apply(&mut store, step);
    if changed == 0 {
        return Ok((original.to_vec(), 0));
    }
    let encoded = store.encode()?;
    if Store::decode(&encoded, version.format())? != store {
        return Err(std::io::Error::other("存储序列化校验失败"));
    }
    let encrypted = crypto::encrypt(&encoded, production, version)?;
    if crypto::decrypt(&encrypted, production, version)? != encoded {
        return Err(std::io::Error::other("存储加密校验失败"));
    }
    Ok((encrypted, changed))
}
/// Vista/7 use the primary file as input and mirror changed ciphertext to both
/// files. No fallback to a corrupt/different secondary; both originals belong in
/// the transaction backup. Even with zero changed records the secondary must
/// mirror the primary; callers must not infer no file changes from the count.
#[cfg_attr(not(test), allow(dead_code))]
pub fn transform_files(
    originals: &[&[u8]],
    step: Step,
    version: super::crypto::Version,
) -> std::io::Result<(Vec<Vec<u8>>, usize)> {
    let expected = if version.paired() { 2 } else { 1 };
    if originals.len() != expected {
        return Err(std::io::Error::other("许可存储文件数量与版本不符"));
    }
    let (changed, count) = transform_version(originals[0], step, version)?;
    let files = vec![changed; expected];
    Ok((files, count))
}

#[cfg(test)]
mod tests {
    use super::super::physical::Key;
    use super::*;
    fn block(value: Vec<u8>) -> Block {
        Block {
            kind: 1,
            flags: 0x1234,
            unknown: 0,
            key: vec![],
            value,
            data: vec![9; 19],
        }
    }
    fn text(value: &str) -> Block {
        block(
            value
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect(),
        )
    }
    #[test]
    fn modern_reset_preserves_unrelated_fields_and_is_idempotent() {
        let untouched = text("MSFT:sl/timer");
        let mut store = Store {
            header: *b"PREHEAD!",
            format: Format::Modern,
            blocks: vec![],
            groups: vec![vec![Key {
                name: vec![1, 0],
                blocks: vec![
                    text("prefix__##USERSEP-RESERVED##__$$RECREATED-FLAG$$suffix"),
                    text("__##USERSEP-RESERVED##__$$RECOVERED-FLAG$$"),
                    text("__##USERSEP-RESERVED##__$$REARM-COUNT$$"),
                    text("msft:sl/timer/expiry"),
                    text("msft:spp/timebased/AB"),
                    text("msft:spp/timebased/CD"),
                    untouched.clone(),
                ],
            }]],
        };
        assert_eq!(apply(&mut store, Step::Tamper), 2);
        assert_eq!(apply(&mut store, Step::RearmAndGrace), 2);
        assert_eq!(apply(&mut store, Step::KeyLock), 2);
        let remaining = &store.groups[0][0].blocks;
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].data, [0; 8]);
        assert_eq!(remaining[0].flags, 0x1234);
        assert_eq!(remaining[1], untouched);
        for step in [Step::Tamper, Step::RearmAndGrace, Step::KeyLock] {
            assert_eq!(apply(&mut store, step), 0);
        }
    }
    #[test]
    fn encrypted_reset_roundtrip_preserves_unrelated_records_and_rejects_corruption() {
        use super::super::crypto::{self, Version};
        for production in [false, true] {
            let mut original = Store::decode(
                include_bytes!("../../../tests/fixtures/tsforge/store-modern.bin"),
                Format::Modern,
            )
            .unwrap();
            original.groups[0][0]
                .blocks
                .push(text("__##USERSEP-RESERVED##__$$REARM-COUNT$$"));
            let encrypted =
                crypto::encrypt(&original.encode().unwrap(), production, Version::Modern).unwrap();
            let (output, count) = transform(&encrypted, Step::RearmAndGrace).unwrap();
            assert_eq!(count, 1);
            let actual = Store::decode(
                &crypto::decrypt(&output, production, Version::Modern).unwrap(),
                Format::Modern,
            )
            .unwrap();
            original.groups[0][0].blocks.last_mut().unwrap().data = vec![0; 8];
            assert_eq!(actual, original);
            assert_eq!(decode_modern(&output).unwrap().0, actual);
            let (again, count) = transform(&output, Step::RearmAndGrace).unwrap();
            assert_eq!(count, 0);
            assert_eq!(again, output);
            let mut corrupt = encrypted.clone();
            corrupt[16] ^= 1;
            assert!(transform(&corrupt, Step::RearmAndGrace).is_err());
        }
    }
    #[test]
    fn version_detection_preserves_upstream_build_boundaries() {
        use super::super::crypto::Version;
        for (build, version) in [
            (6000, Version::Vista),
            (6003, Version::Vista),
            (7600, Version::Win7),
            (7602, Version::Win7),
            (9200, Version::Win8),
            (9600, Version::Modern),
            (26100, Version::Modern),
        ] {
            assert_eq!(Version::detect(build).unwrap(), version);
        }
        for build in [0, 5999, 6004, 7599, 7603, 9199, 9201, 9599] {
            assert!(Version::detect(build).is_err());
        }
    }
    #[test]
    fn legacy_encrypted_reset_preserves_layout_and_mirrors_primary() {
        use super::super::crypto::{self, Version};
        for version in [
            Version::Vista,
            Version::Win7,
            Version::Win8,
            Version::WinBlue,
        ] {
            for production in [false, true] {
                let block = match version {
                    Version::Vista => text("740D70D8-6448-4b2f-9063-4A7A463600C5"),
                    Version::Win7 => block(0xa0000u32.to_le_bytes().to_vec()),
                    _ => text("__##USERSEP-RESERVED##__$$REARM-COUNT$$"),
                };
                let mut store = Store {
                    header: [0; 8],
                    format: version.format(),
                    blocks: vec![],
                    groups: vec![],
                };
                if version.format() == Format::Modern {
                    store.groups.push(vec![Key {
                        name: vec![65, 0],
                        blocks: vec![block],
                    }]);
                } else {
                    store.blocks.push(block);
                }
                let primary =
                    crypto::encrypt(&store.encode().unwrap(), production, version).unwrap();
                let secondary = b"different original backup bytes";
                let mut inputs = vec![primary.as_slice()];
                if version.paired() {
                    inputs.push(secondary);
                }
                let (outputs, count) =
                    transform_files(&inputs, Step::RearmAndGrace, version).unwrap();
                assert_eq!(count, 1);
                assert_eq!(outputs.len(), inputs.len());
                assert!(outputs.iter().all(|out| out == &outputs[0]));
                apply(&mut store, Step::RearmAndGrace);
                assert_eq!(decode(&outputs[0], version).unwrap().0, store);
                let mut inputs = vec![outputs[0].as_slice()];
                if version.paired() {
                    inputs.push(secondary);
                }
                let (unchanged, count) =
                    transform_files(&inputs, Step::RearmAndGrace, version).unwrap();
                assert_eq!(count, 0);
                assert!(unchanged.iter().all(|bytes| bytes == &outputs[0]));
                assert!(transform_files(&[], Step::RearmAndGrace, version).is_err());
                let mut corrupt = primary.clone();
                corrupt[16] ^= 1;
                let mut bad = vec![corrupt.as_slice()];
                if version.paired() {
                    bad.push(&primary);
                }
                assert!(transform_files(&bad, Step::RearmAndGrace, version).is_err());
            }
        }
    }
    #[test]
    fn paired_reset_transaction_backs_up_distinct_originals_before_mirroring() {
        use super::super::{
            crypto::{self, Version},
            transaction::Transaction,
        };
        let dir = tempfile::tempdir().unwrap();
        let paths = vec![dir.path().join("primary"), dir.path().join("secondary")];
        let store = Store {
            header: [0; 8],
            format: Format::Win7,
            groups: vec![],
            blocks: vec![block(0xa0000u32.to_le_bytes().to_vec())],
        };
        let primary = crypto::encrypt(&store.encode().unwrap(), true, Version::Win7).unwrap();
        let secondary = b"old secondary snapshot";
        std::fs::write(&paths[0], &primary).unwrap();
        std::fs::write(&paths[1], secondary).unwrap();
        let transaction = Transaction::edit(paths.clone(), |originals| {
            transform_files(originals, Step::RearmAndGrace, Version::Win7).map(|(files, _)| files)
        })
        .unwrap();
        let backup = transaction.backup_path().to_owned();
        assert_eq!(std::fs::read(backup.join("0.original")).unwrap(), primary);
        assert_eq!(std::fs::read(backup.join("1.original")).unwrap(), secondary);
        transaction.commit().unwrap();
        let a = std::fs::read(&paths[0]).unwrap();
        assert_eq!(a, std::fs::read(&paths[1]).unwrap());
        assert_eq!(decode(&a, Version::Win7).unwrap().0.blocks[0].data, [0; 8]);
        assert_eq!(std::fs::read(backup.join("1.original")).unwrap(), secondary);
    }
    #[test]
    fn legacy_reset_uses_version_specific_identifiers() {
        let mut store = Store {
            header: [0; 8],
            groups: vec![],
            format: Format::Win7,
            blocks: vec![
                block(0xa0000u32.to_le_bytes().to_vec()),
                block(0xa0001u32.to_le_bytes().to_vec()),
                block(vec![0]),
            ],
        };
        assert_eq!(apply(&mut store, Step::Tamper), 1);
        assert_eq!(apply(&mut store, Step::RearmAndGrace), 1);
        assert_eq!(store.blocks[0].data, [0; 8]);
        assert_eq!(store.blocks[1].data, [0; 8]);
        assert_eq!(store.blocks[2].data, [9; 19]);
        store.format = Format::Vista;
        store.blocks = vec![
            text("6BE8425B-E3CF-4e86-A6AF-5863E3DCB606"),
            text("740D70D8-6448-4b2f-9063-4A7A463600C5"),
            text("msft:spp/timebased/AB"),
        ];
        assert_eq!(apply(&mut store, Step::Tamper), 1);
        assert_eq!(apply(&mut store, Step::RearmAndGrace), 1);
        assert_eq!(apply(&mut store, Step::KeyLock), 0);
        assert_eq!(store.blocks.len(), 1);
    }
}
