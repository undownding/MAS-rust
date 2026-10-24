//! Modern KMS4k store records from pinned LibTSforge.Activators.KMS4k.
#![cfg_attr(not(test), allow(dead_code))]
use super::{
    binary::invalid,
    physical::{self, Store},
    product_key::utf16,
    variable_bag as bag,
};
use std::io;
use uuid::Uuid;
const GLOBAL: &str = r"__##USERSEP##\$$_RESERVED_$$\NAMESPACE__";
const CREATION: &str = "__##USERSEP-RESERVED##__$$GLOBAL-CREATION-TIME$$";
const TICKS: &str = "__##USERSEP-RESERVED##__$$GLOBAL-TICKCOUNT-UPTIME$$";
const DELTA: &str = "__##USERSEP-RESERVED##__$$UP-TIME-DELTA$$";
const TIMER_MAX: u64 = 2_147_483_640 * 600_000_000;
fn group<'a>(store: &'a Store, name: &[u8]) -> io::Result<&'a physical::Key> {
    let mut keys = store.groups.iter().flatten().filter(|k| k.name == name);
    let key = keys
        .next()
        .ok_or_else(|| invalid("missing KMS store key"))?;
    if keys.next().is_some() {
        return Err(invalid("ambiguous KMS store key"));
    }
    Ok(key)
}
fn counter(key: &physical::Key, name: &str) -> io::Result<i64> {
    let value = utf16(name);
    let block = key
        .blocks
        .iter()
        .find(|b| b.value == value)
        .ok_or_else(|| invalid("missing KMS clock counter"))?;
    let bytes = block
        .data
        .get(..8)
        .ok_or_else(|| invalid("truncated KMS clock counter"))?;
    Ok(i64::from_le_bytes(bytes.try_into().unwrap()))
}
pub fn apply(original: &Store, app: Uuid, sku: Uuid, filetime: u64) -> io::Result<Store> {
    if original.format != physical::Format::Modern {
        return Err(invalid("KMS4k runtime requires modern store layout"));
    }
    if app.is_nil() || sku.is_nil() {
        return Err(invalid("KMS4k requires nonzero application and SKU IDs"));
    }
    let name = utf16(&format!("SPPSVC\\{app}\\{sku}"));
    let global = group(original, &utf16(GLOBAL))?;
    let target = group(original, &name)?;
    // C# unchecked signed addition followed by an unsigned cast is intentional.
    let time1 = counter(global, CREATION)?
        .wrapping_add(counter(global, TICKS)?)
        .wrapping_add(counter(target, DELTA)?) as u64;
    let timer: Vec<_> = [0, time1, filetime / 10_000, TIMER_MAX / 10_000]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    let records = vec![
        bag::Block {
            kind: 4,
            reserved: 0,
            key: vec![],
            value: include_bytes!("../../../vendor/mas/native/tsforge-kms-v6.bin").to_vec(),
        },
        bag::Block {
            kind: 2,
            reserved: 0,
            key: vec![],
            value: utf16("msft:rm/algorithm/hwid/4.0"),
        },
        bag::Block {
            kind: 4,
            reserved: 0,
            key: utf16("SppBindingLicenseData"),
            value: include_bytes!("../../../vendor/mas/native/tsforge-hwid.bin").to_vec(),
        },
        bag::Block {
            kind: 2,
            reserved: 0,
            key: vec![],
            value: utf16("massgrave.dev"),
        },
        bag::Block {
            kind: 2,
            reserved: 0,
            key: vec![],
            value: utf16("6969"),
        },
    ];
    let binding = bag::encode(&records, bag::Format::Modern)?;
    let mut output = original.clone();
    let target = output
        .groups
        .iter_mut()
        .flatten()
        .find(|k| k.name == name)
        .unwrap();
    for (suffix, kind, flags, data) in [("store", 1, 0x400, binding), ("timer", 3, 4, timer)] {
        let value = utf16(&format!("msft:spp/kms/bind/2.0/{suffix}/{app}/{sku}"));
        if let Some(index) = target.blocks.iter().position(|b| b.value == value) {
            target.blocks.remove(index);
        }
        target.blocks.push(physical::Block {
            kind,
            flags,
            unknown: 0,
            key: vec![],
            value,
            data,
        });
    }
    if Store::decode(&output.encode()?, physical::Format::Modern)? != output {
        return Err(invalid("KMS4k store roundtrip mismatch"));
    }
    Ok(output)
}
/// Mirrors the wrapper's build-dependent acceptance test. The caller computes
/// the projected expiry year from local time, as DateTime.Now.AddMinutes does.
pub fn accepted(build: u32, grace: u32, expiry_year: u32) -> bool {
    (grace == 259_200 || expiry_year > 2038)
        && if build >= 26100 {
            grace >= 259_200
        } else {
            grace > 259_200
        }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn block(name: &str, value: i64) -> physical::Block {
        physical::Block {
            kind: 1,
            flags: 9,
            unknown: 17,
            key: vec![],
            value: utf16(name),
            data: value.to_le_bytes().to_vec(),
        }
    }
    fn fixture() -> (Store, Uuid, Uuid) {
        let app = Uuid::from_u128(1);
        let sku = Uuid::from_u128(2);
        (
            Store {
                format: physical::Format::Modern,
                header: [8; 8],
                blocks: vec![],
                groups: vec![vec![
                    physical::Key {
                        name: utf16(GLOBAL),
                        blocks: vec![block(CREATION, i64::MAX), block(TICKS, 17)],
                    },
                    physical::Key {
                        name: utf16(&format!("SPPSVC\\{app}\\{sku}")),
                        blocks: vec![block(DELTA, -3), block("unrelated", 42)],
                    },
                ]],
            },
            app,
            sku,
        )
    }
    #[test]
    fn independent_binding_and_timer_vectors_preserve_unknowns_and_wrap_like_csharp() {
        let (original, app, sku) = fixture();
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/tsforge/kms4k.json"))
                .unwrap();
        let now = vector["filetime"].as_u64().unwrap();
        let output = apply(&original, app, sku, now).unwrap();
        assert_eq!(original.groups[0][0], output.groups[0][0]);
        assert_eq!(
            original.groups[0][1].blocks,
            output.groups[0][1].blocks[..2]
        );
        let blocks = &output.groups[0][1].blocks;
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(&blocks[2].data), vector["binding"]);
        assert_eq!(hex(&blocks[3].data), vector["timer"]);
        assert_eq!((blocks[2].kind, blocks[2].flags), (1, 0x400));
        assert_eq!((blocks[3].kind, blocks[3].flags), (3, 4));
        assert_eq!(output, apply(&output, app, sku, now).unwrap());
    }
    #[test]
    fn missing_truncated_or_ambiguous_clock_data_is_rejected_without_mutation() {
        let (mut store, app, sku) = fixture();
        store.groups[0][0].blocks[0].data.truncate(7);
        let before = store.clone();
        assert!(apply(&store, app, sku, 0).is_err());
        assert_eq!(store, before);
        let (mut store, app, sku) = fixture();
        let duplicate = store.groups[0][0].clone();
        store.groups[0].push(duplicate);
        assert!(apply(&store, app, sku, 0).is_err());
        let (mut store, app, sku) = fixture();
        store.groups[0][1].blocks.clear();
        assert!(apply(&store, app, sku, 0).is_err());
    }
    #[test]
    fn grace_verification_matches_old_and_new_build_boundaries() {
        assert!(!accepted(26099, 259200, 2027));
        assert!(accepted(26100, 259200, 2027));
        assert!(!accepted(26100, 259199, 2040));
        assert!(!accepted(26099, 300000, 2038));
        assert!(accepted(26099, 300000, 2039));
        assert!(accepted(26100, 2_147_483_640, 6000));
    }
}
