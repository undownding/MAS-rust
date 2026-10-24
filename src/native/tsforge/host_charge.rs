//! Modern KMS host counters, derived from pinned LibTSforge KMSHostCharge.
#![cfg_attr(not(test), allow(dead_code))]
use super::{
    binary::invalid,
    physical::{self, Store},
    product_key::utf16,
    variable_bag as bag,
};
use std::{collections::HashSet, io};
use uuid::Uuid;
pub const CLIENTS: usize = 25;
pub fn apply(original: &Store, app: Uuid, filetime: i64, clients: &[Uuid]) -> io::Result<Store> {
    if original.format != physical::Format::Modern {
        return Err(invalid("host charging requires modern store layout"));
    }
    if app.is_nil()
        || clients.len() != CLIENTS
        || clients.iter().any(Uuid::is_nil)
        || clients.iter().collect::<HashSet<_>>().len() != CLIENTS
    {
        return Err(invalid(
            "host charging requires an application and 25 distinct client IDs",
        ));
    }
    let mut ids = Vec::new();
    for (index, client) in clients.iter().enumerate() {
        ids.extend_from_slice(&filetime.wrapping_sub(10 * (index as i64 + 1)).to_le_bytes());
        ids.extend_from_slice(&client.to_bytes_le());
    }
    let mut counts = vec![0u8; 40];
    counts[4] = CLIENTS as u8;
    counts[24] = CLIENTS as u8;
    let records = vec![
        bag::Block {
            kind: 4,
            reserved: 0,
            key: utf16("SppBindingLicenseData"),
            value: include_bytes!("../../../vendor/mas/native/tsforge-hwid.bin").to_vec(),
        },
        bag::Block {
            kind: 1,
            reserved: 0,
            key: vec![],
            value: 50u32.to_le_bytes().to_vec(),
        },
        bag::Block {
            kind: 1,
            reserved: 0,
            key: vec![],
            value: 1_051_200_000u32.to_le_bytes().to_vec(),
        },
        bag::Block {
            kind: 1,
            reserved: 0,
            key: vec![],
            value: (CLIENTS as u32).to_le_bytes().to_vec(),
        },
        bag::Block {
            kind: 4,
            reserved: 0,
            key: vec![],
            value: ids,
        },
        bag::Block {
            kind: 4,
            reserved: 0,
            key: vec![],
            value: counts,
        },
    ];
    let name = utf16(&format!("SPPSVC\\{app}"));
    if original
        .groups
        .iter()
        .flatten()
        .filter(|k| k.name == name)
        .count()
        > 1
    {
        return Err(invalid("ambiguous KMS host store key"));
    }
    let mut output = original.clone();
    if !output.groups.iter().flatten().any(|k| k.name == name) {
        if output.groups.is_empty() {
            output.groups.push(vec![]);
        }
        output.groups.last_mut().unwrap().push(physical::Key {
            name: name.clone(),
            blocks: vec![],
        });
    }
    let blocks = &mut output
        .groups
        .iter_mut()
        .flatten()
        .find(|k| k.name == name)
        .unwrap()
        .blocks;
    let value = utf16(&format!("msft:spp/kms/host/2.0/store/counters/{app}"));
    if let Some(index) = blocks.iter().position(|b| b.value == value) {
        blocks.remove(index);
    }
    blocks.push(physical::Block {
        kind: 1,
        flags: 0x400,
        unknown: 0,
        key: vec![],
        value,
        data: bag::encode(&records, bag::Format::Modern)?,
    });
    if Store::decode(&output.encode()?, physical::Format::Modern)? != output {
        return Err(invalid("host counters roundtrip mismatch"));
    }
    Ok(output)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn store() -> Store {
        Store {
            format: physical::Format::Modern,
            header: [1; 8],
            groups: vec![],
            blocks: vec![],
        }
    }
    fn clients() -> Vec<Uuid> {
        (1..=25)
            .map(|i| Uuid::from_u128(0x00112233_4455_6677_8899_aabbccdd0000 + i))
            .collect()
    }
    #[test]
    fn independent_vector_matches_guid_byte_order_timestamps_and_counter_layout() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/tsforge/host-charge.json"
        ))
        .unwrap();
        let app = Uuid::from_u128(100);
        let now = vector["filetime"].as_i64().unwrap();
        let output = apply(&store(), app, now, &clients()).unwrap();
        let block = &output.groups[0][0].blocks[0];
        assert_eq!((block.kind, block.flags), (1, 0x400));
        let hex: String = block.data.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, vector["binding"]);
        assert_eq!(output, apply(&output, app, now, &clients()).unwrap());
        let data = bag::decode(&block.data, bag::Format::Modern).unwrap();
        assert_eq!(data[4].value.len(), 600);
        assert_eq!(data[5].value.len(), 40);
    }
    #[test]
    fn replacement_preserves_unrelated_entries_and_uses_wrapping_timestamp_subtraction() {
        let app = Uuid::from_u128(100);
        let mut initial = apply(&store(), app, 0, &clients()).unwrap();
        let unrelated = physical::Block {
            kind: 99,
            flags: 77,
            unknown: 123,
            key: vec![],
            value: utf16("other"),
            data: vec![7],
        };
        initial.groups[0][0].blocks.insert(0, unrelated.clone());
        let output = apply(&initial, app, i64::MIN, &clients()).unwrap();
        assert_eq!(output.groups[0][0].blocks[0], unrelated);
        let data = bag::decode(&output.groups[0][0].blocks[1].data, bag::Format::Modern).unwrap();
        assert_eq!(
            &data[4].value[..8],
            &i64::MIN.wrapping_sub(10).to_le_bytes()
        );
    }
    #[test]
    fn invalid_client_sets_and_ambiguous_host_keys_leave_input_untouched() {
        let mut ids = clients();
        let app = Uuid::from_u128(100);
        let input = store();
        assert!(apply(&input, app, 0, &ids[..24]).is_err());
        ids[1] = ids[0];
        assert!(apply(&input, app, 0, &ids).is_err());
        ids = clients();
        ids[0] = Uuid::nil();
        assert!(apply(&input, app, 0, &ids).is_err());
        let mut input = apply(&input, app, 0, &clients()).unwrap();
        let duplicate = input.groups[0][0].clone();
        input.groups[0].push(duplicate);
        let before = input.clone();
        assert!(apply(&input, app, 0, &clients()).is_err());
        assert_eq!(input, before);
    }
}
