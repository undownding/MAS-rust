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

/// Authenticated read/modify/write for the modern store used since build 9600.
/// Unknown formats fail before the transaction can write any replacement.
pub fn decode_modern(original: &[u8]) -> std::io::Result<(Store, bool)> {
    use super::crypto::{self, Version};
    let (plaintext, production) = match crypto::decrypt(original, true, Version::Modern) {
        Ok(data) => (data, true),
        Err(production_error) => match crypto::decrypt(original, false, Version::Modern) {
            Ok(data) => (data, false),
            Err(test_error) => {
                return Err(std::io::Error::other(format!(
                    "许可存储解密失败：生产密钥 {production_error}；测试密钥 {test_error}"
                )));
            }
        },
    };
    Ok((Store::decode(&plaintext, Format::Modern)?, production))
}

pub fn transform(original: &[u8], step: Step) -> std::io::Result<(Vec<u8>, usize)> {
    use super::crypto::{self, Version};
    let (mut store, production) = decode_modern(original)?;
    let changed = apply(&mut store, step);
    if changed == 0 {
        return Ok((original.to_vec(), 0));
    }
    let encoded = store.encode()?;
    if Store::decode(&encoded, Format::Modern)? != store {
        return Err(std::io::Error::other("存储序列化校验失败"));
    }
    let encrypted = crypto::encrypt(&encoded, production, Version::Modern)?;
    if crypto::decrypt(&encrypted, production, Version::Modern)? != encoded {
        return Err(std::io::Error::other("存储加密校验失败"));
    }
    Ok((encrypted, changed))
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
            let (again, count) = transform(&output, Step::RearmAndGrace).unwrap();
            assert_eq!(count, 0);
            assert_eq!(again, output);
            let mut corrupt = encrypted.clone();
            corrupt[16] ^= 1;
            assert!(transform(&corrupt, Step::RearmAndGrace).is_err());
        }
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
