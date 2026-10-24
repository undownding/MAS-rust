//! Versioned IID parameters, unique-ID removal and ZeroCID cache records.
#![cfg_attr(not(test), allow(dead_code))]
use super::{
    binary::{invalid, length},
    physical::{self, Store},
    pkey_config::Algorithm,
    product_key::{Key2005, Key2009, utf16},
    variable_bag as bag,
};
use sha2::{Digest, Sha256};
use std::io;
use uuid::Uuid;
pub const ZERO_CID: &str = "000000000000000000000000000000000000000000000000";
const HWID: &[u8] = include_bytes!("../../../vendor/mas/native/tsforge-hwid.bin");
pub struct Target {
    pub app: Uuid,
    pub sku: Uuid,
    pub key: Uuid,
}
pub enum Change<'a> {
    Iid {
        algorithm: Algorithm,
        group: u32,
        serial: u32,
        security: u64,
    },
    RemoveUniqueId,
    ZeroCid {
        installation_id: &'a str,
    },
}
fn framed(hash: &[u8], data: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    length(&mut out, hash.len())?;
    out.extend_from_slice(hash);
    length(&mut out, data.len())?;
    out.extend_from_slice(data);
    Ok(out)
}
/// Vista stores the short authenticator and group inside fixed UTF-16 fields.
fn vista_phone_data(basic: &[u8]) -> io::Result<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let field = |offset: usize| -> io::Result<String> {
        let bytes = basic
            .get(offset..offset + 0x80)
            .ok_or_else(|| invalid("truncated Vista PKeyBasicInfo"))?;
        let units: Vec<_> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|v| u16::from_le_bytes([v[0], v[1]]))
            .collect();
        String::from_utf16(&units)
            .map(|s| s.trim_matches('\0').to_owned())
            .map_err(|_| invalid("invalid Vista PKeyBasicInfo UTF-16"))
    };
    let unique = field(0x120)?;
    let pid = field(0x1a0)?;
    let group = pid
        .split('-')
        .nth(1)
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|v| *v != 0)
        .ok_or_else(|| invalid("invalid Vista extended PID group"))?;
    let encoded = unique
        .split('&')
        .nth(1)
        .ok_or_else(|| invalid("invalid Vista unique ID"))?;
    let encoded: String = encoded
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
        .collect();
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| invalid("invalid Vista unique ID base64"))?;
    let auth = u64::from_le_bytes(
        bytes
            .get(..8)
            .ok_or_else(|| invalid("truncated Vista authenticator"))?
            .try_into()
            .unwrap(),
    );
    Ok((auth | (u64::from(group) << 41)).to_le_bytes().to_vec())
}
/// Returns a new plaintext store. Errors leave the borrowed input unchanged.
pub fn apply(original: &Store, target: &Target, change: Change<'_>) -> io::Result<Store> {
    let vista = original.format == physical::Format::Vista;
    if vista && !matches!(change, Change::ZeroCid { .. }) {
        return Err(invalid(
            "Vista does not support IID parameter or Unique ID modifiers",
        ));
    }
    if target.app.is_nil() || target.sku.is_nil() || target.key.is_nil() {
        return Err(invalid("phone modifier requires nonzero IDs"));
    }
    let name = utf16(&format!("SPPSVC\\{}\\{}", target.app, target.sku));
    let value = utf16(&target.key.to_string());
    let legacy = original.format == physical::Format::Win7;
    let phone_name = if vista {
        "PKeyBasicInfo"
    } else if legacy {
        "SppPkeyShortAuthenticator"
    } else {
        "SppPkeyPhoneActivationData"
    };
    let mut store = original.clone();
    let blocks = if legacy || vista {
        &mut store.blocks
    } else {
        if store
            .groups
            .iter()
            .flatten()
            .filter(|k| k.name == name)
            .count()
            != 1
        {
            return Err(invalid("missing or ambiguous product store key"));
        }
        &mut store
            .groups
            .iter_mut()
            .flatten()
            .find(|k| k.name == name)
            .unwrap()
            .blocks
    };
    let matches: Vec<_> = blocks
        .iter()
        .enumerate()
        .filter(|(_, b)| b.value == value && (!legacy || b.key == name))
        .map(|(index, _)| index)
        .collect();
    if matches.len() != 1 {
        return Err(invalid(
            "installed product key absent or ambiguous in store",
        ));
    }
    let index = matches[0];
    let bag_format = if vista {
        bag::Format::Vista
    } else {
        bag::Format::Modern
    };
    let mut records = bag::decode(&blocks[index].data, bag_format)?;
    let mut cache = None;
    match change {
        Change::Iid {
            algorithm,
            group,
            serial,
            security,
        } => {
            let data = match algorithm {
                Algorithm::Pkey2005 => {
                    Key2005::new(group, serial, security, false)?.phone_data(legacy)
                }
                Algorithm::Pkey2009 => {
                    Key2009::new(group, serial, security, false)?.phone_data(legacy)
                }
            };
            let phone = records
                .iter_mut()
                .find(|r| r.key == utf16(phone_name))
                .ok_or_else(|| invalid("product key lacks phone activation data"))?;
            phone.value = data;
        }
        Change::RemoveUniqueId => {
            if let Some(index) = records
                .iter()
                .position(|r| r.key == utf16("SppPkeyUniqueIdToken"))
            {
                records.remove(index);
            }
        }
        Change::ZeroCid { installation_id } => {
            if installation_id.is_empty()
                || installation_id.len() > 4096
                || installation_id.contains('\0')
            {
                return Err(invalid("invalid installation ID"));
            }
            let phone = records
                .iter()
                .find(|r| r.key == utf16(phone_name))
                .ok_or_else(|| invalid("product key lacks phone activation data"))?
                .value
                .clone();
            let phone = if vista {
                vista_phone_data(&phone)?
            } else {
                phone
            };
            // EncodeString terminates the IID; modern layouts also include the CID separator.
            let hash_input = if legacy || vista {
                installation_id.to_owned()
            } else {
                format!("{installation_id}\0{ZERO_CID}")
            };
            let hash = Sha256::digest(utf16(&hash_input));
            let hash = if vista { &hash[..16] } else { &hash[..] };
            cache = Some((framed(hash, HWID)?, framed(hash, &phone)?));
            if let Some(index) = records
                .iter()
                .position(|r| r.key == utf16("SppPkeyVirtual"))
            {
                records.remove(index);
            }
        }
    }
    blocks[index].data = bag::encode(&records, bag_format)?;
    if let Some((hwid, key)) = cache {
        let phone_version = if vista { "6.0" } else { "7.0" };
        let cache_id = if vista { target.sku } else { target.key };
        for (kind, data) in [("HwidBlock", hwid), ("PKeyInfo", key)] {
            let value = utf16(&format!(
                "msft:Windows/{phone_version}/Phone/Cached/{kind}/{cache_id}"
            ));
            if let Some(index) = blocks
                .iter()
                .position(|b| b.value == value && (!legacy || b.key == name))
            {
                blocks.remove(index);
            }
            blocks.push(physical::Block {
                kind: 1,
                flags: 0,
                unknown: 0,
                key: if legacy { name.clone() } else { vec![] },
                value,
                data,
            });
        }
    }
    let encoded = store.encode()?;
    if Store::decode(&encoded, original.format)? != store {
        return Err(invalid("phone modifier store roundtrip mismatch"));
    }
    Ok(store)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Store, Target) {
        let target = Target {
            app: Uuid::from_u128(1),
            sku: Uuid::from_u128(2),
            key: Uuid::from_u128(3),
        };
        let records: Vec<_> = [
            ("SppPkeyPhoneActivationData", vec![1, 2, 3]),
            ("SppPkeyVirtual", vec![4]),
            ("SppPkeyUniqueIdToken", vec![5]),
            ("unknown", vec![6]),
        ]
        .into_iter()
        .map(|(k, value)| bag::Block {
            kind: 4,
            reserved: 0,
            key: utf16(k),
            value,
        })
        .collect();
        let block = physical::Block {
            kind: 1,
            flags: 0x402,
            unknown: 123,
            key: vec![],
            value: utf16(&target.key.to_string()),
            data: bag::encode(&records, bag::Format::Modern).unwrap(),
        };
        let store = Store {
            format: physical::Format::Modern,
            header: [9; 8],
            blocks: vec![],
            groups: vec![vec![physical::Key {
                name: utf16(&format!("SPPSVC\\{}\\{}", target.app, target.sku)),
                blocks: vec![block],
            }]],
        };
        (store, target)
    }
    #[test]
    fn iid_and_unique_id_modifications_preserve_unknown_fields_and_are_idempotent() {
        let (original, target) = fixture();
        let result = apply(
            &original,
            &target,
            Change::Iid {
                algorithm: Algorithm::Pkey2009,
                group: 100055,
                serial: 1000043,
                security: 1338662172562478,
            },
        )
        .unwrap();
        let blocks = &result.groups[0][0].blocks;
        assert_eq!((blocks[0].flags, blocks[0].unknown), (0x402, 123));
        let records = bag::decode(&blocks[0].data, bag::Format::Modern).unwrap();
        assert_eq!(
            records[0].value,
            Key2009::new(100055, 1000043, 1338662172562478, false)
                .unwrap()
                .phone_data(false)
        );
        assert_eq!(records[3].value, [6]);
        let removed = apply(&result, &target, Change::RemoveUniqueId).unwrap();
        assert_eq!(
            removed,
            apply(&removed, &target, Change::RemoveUniqueId).unwrap()
        );
        assert_eq!(original.groups[0][0].blocks[0].unknown, 123);
        assert!(
            apply(
                &original,
                &target,
                Change::Iid {
                    algorithm: Algorithm::Pkey2005,
                    group: 1 << 20,
                    serial: 0,
                    security: 0
                }
            )
            .is_err()
        );
    }
    #[test]
    fn zero_cid_records_match_independent_python_vectors_and_replace_existing_cache() {
        let (original, target) = fixture();
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/tsforge/phone.json"))
                .unwrap();
        let iid = fixture["iid"].as_str().unwrap();
        let result = apply(
            &original,
            &target,
            Change::ZeroCid {
                installation_id: iid,
            },
        )
        .unwrap();
        let blocks = &result.groups[0][0].blocks;
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex(&blocks[1].data),
            fixture["hwid_cache"].as_str().unwrap()
        );
        assert_eq!(hex(&blocks[2].data), fixture["key_cache"].as_str().unwrap());
        assert_eq!(blocks[1].flags, 0);
        assert_eq!(blocks[2].kind, 1);
        let records = bag::decode(&blocks[0].data, bag::Format::Modern).unwrap();
        assert!(!records.iter().any(|r| r.key == utf16("SppPkeyVirtual")));
        assert_eq!(
            result,
            apply(
                &result,
                &target,
                Change::ZeroCid {
                    installation_id: iid
                }
            )
            .unwrap()
        );
    }
    fn unhex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }
    fn vista_fixture() -> (Store, Target, serde_json::Value) {
        let (mut store, target) = fixture();
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/tsforge/phone-vista.json"
        ))
        .unwrap();
        let mut block = store.groups.remove(0).remove(0).blocks.remove(0);
        block.unknown = 0;
        let mut records = bag::decode(&block.data, bag::Format::Modern).unwrap();
        records[0].key = utf16("PKeyBasicInfo");
        records[0].value = unhex(vector["basic"].as_str().unwrap());
        records[3].reserved = 0x1234;
        block.data = bag::encode(&records, bag::Format::Vista).unwrap();
        store.format = physical::Format::Vista;
        store.blocks.push(block);
        (store, target, vector)
    }
    #[test]
    fn vista_cache_matches_independent_vectors_and_uses_activation_id() {
        let (store, target, vector) = vista_fixture();
        let iid = vector["iid"].as_str().unwrap();
        let result = apply(
            &store,
            &target,
            Change::ZeroCid {
                installation_id: iid,
            },
        )
        .unwrap();
        assert_eq!(
            result.blocks[1].data,
            unhex(vector["hwid_cache"].as_str().unwrap())
        );
        assert_eq!(
            result.blocks[2].data,
            unhex(vector["key_cache"].as_str().unwrap())
        );
        assert_eq!(
            result.blocks[1].value,
            utf16(&format!(
                "msft:Windows/6.0/Phone/Cached/HwidBlock/{}",
                target.sku
            ))
        );
        assert!(result.blocks[1].key.is_empty());
        let records = bag::decode(&result.blocks[0].data, bag::Format::Vista).unwrap();
        assert_eq!(records.last().unwrap().reserved, 0x1234);
        assert_eq!(records.last().unwrap().value, [6]);
        assert!(!records.iter().any(|b| b.key == utf16("SppPkeyVirtual")));
        assert_eq!(
            result,
            apply(
                &result,
                &target,
                Change::ZeroCid {
                    installation_id: iid
                }
            )
            .unwrap()
        );
        assert_eq!(
            result,
            Store::decode(&result.encode().unwrap(), physical::Format::Vista).unwrap()
        );
        assert!(apply(&store, &target, Change::RemoveUniqueId).is_err());
        assert!(
            apply(
                &store,
                &target,
                Change::Iid {
                    algorithm: Algorithm::Pkey2005,
                    group: 1,
                    serial: 1,
                    security: 1
                }
            )
            .is_err()
        );
    }
    #[test]
    fn vista_basic_info_rejects_truncation_invalid_fields_and_short_authenticator() {
        let (_, _, vector) = vista_fixture();
        let basic = unhex(vector["basic"].as_str().unwrap());
        assert_eq!(
            vista_phone_data(&basic).unwrap(),
            unhex(vector["phone_data"].as_str().unwrap())
        );
        for end in [0, 0x120, 0x19f, 0x21f] {
            assert!(vista_phone_data(&basic[..end]).is_err());
        }
        for (offset, text) in [
            (0x120, "no-separator"),
            (0x120, "prefix&%%%"),
            (0x120, "prefix&AQID"),
            (0x1a0, "pid-0-tail"),
            (0x1a0, "pid-4294967296-tail"),
            (0x1a0, "no-group"),
        ] {
            let mut bad = basic.clone();
            bad[offset..offset + 0x80].fill(0);
            let bytes = utf16(text);
            bad[offset..offset + bytes.len()].copy_from_slice(&bytes);
            assert!(vista_phone_data(&bad).is_err(), "{text}");
        }
        let mut bad = basic.clone();
        bad[0x120..0x122].copy_from_slice(&0xd800u16.to_le_bytes());
        assert!(vista_phone_data(&bad).is_err());
    }
    #[test]
    fn vista_bad_bag_and_ambiguous_key_leave_original_unchanged() {
        let (mut store, target, _) = vista_fixture();
        store.blocks[0].data[16] ^= 1; // Vista CRC field.
        let before = store.clone();
        assert!(
            apply(
                &store,
                &target,
                Change::ZeroCid {
                    installation_id: "123"
                }
            )
            .is_err()
        );
        assert_eq!(store, before);
        let (mut store, target, _) = vista_fixture();
        store.blocks.push(store.blocks[0].clone());
        assert!(
            apply(
                &store,
                &target,
                Change::ZeroCid {
                    installation_id: "123"
                }
            )
            .is_err()
        );
    }
    fn win7_fixture() -> (Store, Target) {
        let (mut store, target) = fixture();
        let mut group = store.groups.remove(0).remove(0);
        let mut block = group.blocks.remove(0);
        block.key = group.name;
        block.unknown = 0;
        let mut records = bag::decode(&block.data, bag::Format::Modern).unwrap();
        records[0].key = utf16("SppPkeyShortAuthenticator");
        records[0].value = vec![1, 2, 3, 4, 5, 6, 7, 8];
        block.data = bag::encode(&records, bag::Format::Modern).unwrap();
        store.format = physical::Format::Win7;
        store.blocks.push(block);
        (store, target)
    }
    #[test]
    fn win7_cache_matches_independent_hash_and_does_not_touch_other_product() {
        let (mut original, target) = win7_fixture();
        let mut other = original.blocks[0].clone();
        other.key = utf16("SPPSVC\\another-product");
        original.blocks.push(other.clone());
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/tsforge/phone-win7.json"
        ))
        .unwrap();
        let iid = fixture["iid"].as_str().unwrap();
        let result = apply(
            &original,
            &target,
            Change::ZeroCid {
                installation_id: iid,
            },
        )
        .unwrap();
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(result.blocks[1], other);
        assert_eq!(
            hex(&result.blocks[2].data),
            fixture["hwid_cache"].as_str().unwrap()
        );
        assert_eq!(
            hex(&result.blocks[3].data),
            fixture["key_cache"].as_str().unwrap()
        );
        assert_eq!(result.blocks[2].key, original.blocks[0].key);
        assert_eq!(result.blocks[2].flags, 0);
        assert_eq!(
            result,
            apply(
                &result,
                &target,
                Change::ZeroCid {
                    installation_id: iid
                }
            )
            .unwrap()
        );
        assert_eq!(
            Store::decode(&result.encode().unwrap(), physical::Format::Win7).unwrap(),
            result
        );
    }
    #[test]
    fn win7_iid_uses_short_authenticator_for_both_algorithms() {
        let (original, target) = win7_fixture();
        for algorithm in [Algorithm::Pkey2005, Algorithm::Pkey2009] {
            let result = apply(
                &original,
                &target,
                Change::Iid {
                    algorithm,
                    group: 123,
                    serial: 456,
                    security: 78,
                },
            )
            .unwrap();
            let records = bag::decode(&result.blocks[0].data, bag::Format::Modern).unwrap();
            let expected = match algorithm {
                Algorithm::Pkey2005 => Key2005::new(123, 456, 78, false).unwrap().phone_data(true),
                Algorithm::Pkey2009 => Key2009::new(123, 456, 78, false).unwrap().phone_data(true),
            };
            assert_eq!(records[0].value, expected);
            assert_eq!(result.blocks[0].flags, original.blocks[0].flags);
            assert_eq!(records[3].value, [6]);
            let removed = apply(&result, &target, Change::RemoveUniqueId).unwrap();
            let records = bag::decode(&removed.blocks[0].data, bag::Format::Modern).unwrap();
            assert!(
                !records
                    .iter()
                    .any(|r| r.key == utf16("SppPkeyUniqueIdToken"))
            );
            assert_eq!(
                removed,
                apply(&removed, &target, Change::RemoveUniqueId).unwrap()
            );
        }
    }
    #[test]
    fn duplicate_product_key_blocks_are_rejected_in_both_layouts() {
        for (mut original, target) in [fixture(), win7_fixture()] {
            if original.format == physical::Format::Win7 {
                original.blocks.push(original.blocks[0].clone());
            } else {
                let blocks = &mut original.groups[0][0].blocks;
                blocks.push(blocks[0].clone());
            }
            let before = original.clone();
            assert!(apply(&original, &target, Change::RemoveUniqueId).is_err());
            assert_eq!(original, before);
        }
    }
    #[test]
    fn missing_and_ambiguous_records_fail_without_modifying_original() {
        let (mut original, target) = fixture();
        let before = original.clone();
        assert!(
            apply(
                &original,
                &target,
                Change::ZeroCid {
                    installation_id: "bad\0id"
                }
            )
            .is_err()
        );
        assert_eq!(original, before);
        let duplicate = original.groups[0][0].clone();
        original.groups[0].push(duplicate);
        assert!(apply(&original, &target, Change::RemoveUniqueId).is_err());
        let (mut original, target) = fixture();
        original.groups[0][0].blocks[0].data = vec![];
        assert!(
            apply(
                &original,
                &target,
                Change::ZeroCid {
                    installation_id: "123"
                }
            )
            .is_err()
        );
    }
}
