//! Modern-store IID parameters, unique-ID removal and ZeroCID cache records.
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
    if original.format != physical::Format::Modern {
        return Err(invalid("phone modifier requires modern store layout"));
    }
    if target.app.is_nil() || target.sku.is_nil() || target.key.is_nil() {
        return Err(invalid("phone modifier requires nonzero IDs"));
    }
    let name = utf16(&format!("SPPSVC\\{}\\{}", target.app, target.sku));
    let value = utf16(&target.key.to_string());
    if original
        .groups
        .iter()
        .flatten()
        .filter(|k| k.name == name)
        .count()
        != 1
    {
        return Err(invalid("missing or ambiguous product store key"));
    }
    let mut store = original.clone();
    let blocks = &mut store
        .groups
        .iter_mut()
        .flatten()
        .find(|k| k.name == name)
        .unwrap()
        .blocks;
    let index = blocks
        .iter()
        .position(|b| b.value == value)
        .ok_or_else(|| invalid("installed product key absent from store"))?;
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
                    Key2005::new(group, serial, security, false)?.phone_data(false)
                }
                Algorithm::Pkey2009 => {
                    Key2009::new(group, serial, security, false)?.phone_data(false)
                }
            };
            let phone = records
                .iter_mut()
                .find(|r| r.key == utf16("SppPkeyPhoneActivationData"))
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
                .find(|r| r.key == utf16("SppPkeyPhoneActivationData"))
                .ok_or_else(|| invalid("product key lacks phone activation data"))?
                .value
                .clone();
            // EncodeString adds a final UTF-16 NUL, in addition to the separator.
            let hash = Sha256::digest(utf16(&format!("{installation_id}\0{ZERO_CID}")));
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
            if let Some(index) = blocks.iter().position(|b| b.value == value) {
                blocks.remove(index);
            }
            blocks.push(physical::Block {
                kind: 1,
                flags: 0,
                unknown: 0,
                key: vec![],
                value,
                data,
            });
        }
    }
    let encoded = store.encode()?;
    if Store::decode(&encoded, physical::Format::Modern)? != store {
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
