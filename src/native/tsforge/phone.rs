//! Win7/modern IID parameters, unique-ID removal and ZeroCID cache records.
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
/// Returns a new plaintext store. Errors leave the borrowed input unchanged.
pub fn apply(original: &Store, target: &Target, change: Change<'_>) -> io::Result<Store> {
    if original.format == physical::Format::Vista {
        return Err(invalid("Vista phone records are not implemented yet"));
    }
    if target.app.is_nil() || target.sku.is_nil() || target.key.is_nil() {
        return Err(invalid("phone modifier requires nonzero IDs"));
    }
    let name = utf16(&format!("SPPSVC\\{}\\{}", target.app, target.sku));
    let value = utf16(&target.key.to_string());
    let legacy = original.format == physical::Format::Win7;
    let phone_name = if legacy {
        "SppPkeyShortAuthenticator"
    } else {
        "SppPkeyPhoneActivationData"
    };
    let mut store = original.clone();
    let blocks = if legacy {
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
    let mut records = bag::decode(&blocks[index].data, bag::Format::Modern)?;
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
            // EncodeString terminates the IID; modern layouts also include the CID separator.
            let hash_input = if legacy {
                installation_id.to_owned()
            } else {
                format!("{installation_id}\0{ZERO_CID}")
            };
            let hash = Sha256::digest(utf16(&hash_input));
            cache = Some((framed(&hash, HWID)?, framed(&hash, &phone)?));
            if let Some(index) = records
                .iter()
                .position(|r| r.key == utf16("SppPkeyVirtual"))
            {
                records.remove(index);
            }
        }
    }
    blocks[index].data = bag::encode(&records, bag::Format::Modern)?;
    if let Some((hwid, key)) = cache {
        for (kind, data) in [("HwidBlock", hwid), ("PKeyInfo", key)] {
            let value = utf16(&format!(
                "msft:Windows/7.0/Phone/Cached/{kind}/{}",
                target.key
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
