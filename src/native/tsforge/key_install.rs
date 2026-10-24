//! Side-effect-free PKEY2005 installation planning from MAS GenPKeyInstall.
//! System API calls, registry writes and cache invalidation are not connected yet.
use super::{
    binary::invalid,
    crypto::Version,
    physical::{self, Store},
    product_key::{Key2005, Metadata, guid_string, utf16},
    token, variable_bag as bag,
};
use std::{collections::HashSet, io::Result};

pub struct Request<'a> {
    pub version: Version,
    pub key: Key2005,
    pub metadata: Metadata<'a>,
    pub application_id: [u8; 16],
    /// Present only for the base Windows product, not add-ons or Office.
    pub windows_family: Option<&'a str>,
    pub pid_nonce: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RegistryData {
    pub product_id: String,
    pub digital_product_id: Vec<u8>,
    pub digital_product_id4: Vec<u8>,
    pub kms_host: bool,
}

#[derive(Debug)]
pub struct Plan {
    pub physical: Vec<u8>,
    pub tokens: Vec<u8>,
    pub registry: Option<RegistryData>,
}

/// Inputs are borrowed; even a late metadata/serialization error cannot mutate them.
pub fn prepare(physical: &[u8], tokens: &[u8], request: &Request<'_>) -> Result<Plan> {
    if !matches!(
        request.version,
        Version::Win8 | Version::WinBlue | Version::Modern
    ) {
        return Err(invalid(
            "key installation plan requires modern store layouts",
        ));
    }
    if request.metadata.activation_id == [0; 16] || request.application_id == [0; 16] {
        return Err(invalid(
            "key installation requires nonzero product and application IDs",
        ));
    }
    if request.windows_family.is_some_and(|s| s.contains('\0')) {
        return Err(invalid("Windows family contains NUL"));
    }
    let mut store = Store::decode(physical, physical::Format::Modern)?;
    let mut entries = token::decode(tokens)?;
    let key = request.key;
    let meta = &request.metadata;
    let product_id = key.pid2(meta.mpc, meta.eula, request.pid_nonce)?;
    let pid3 = key.pid3(meta, request.pid_nonce)?;
    let pid4 = key.pid4(meta)?;
    let data = [
        (2, "SppPkeyBindingProductKey", utf16(&key.to_string())),
        (2, "SppPkeyBindingMPC", utf16(meta.mpc)),
        (4, "SppPkeyBindingPid2", utf16(&product_id)),
        (4, "SppPkeyBindingPid3", pid3.clone()),
        (4, "SppPkeyBindingPid4", pid4.clone()),
        (2, "SppPkeyChannelId", utf16(meta.channel)),
        (2, "SppPkeyBindingEditionId", utf16(meta.edition)),
        (4, "SppPkeyPhoneActivationData", key.phone_data(false)),
        (4, "SppPkeyBindingMiscData", Vec::new()),
    ];
    let data: Vec<_> = data
        .into_iter()
        .map(|(kind, name, value)| bag::Block {
            kind,
            reserved: 0,
            key: utf16(name),
            value,
        })
        .collect();
    let data = bag::encode(&data, bag::Format::Modern)?;
    let pkey_id = guid_string(key.binding_id()?);
    let sku_id = guid_string(meta.activation_id);
    let app_id = guid_string(request.application_id);
    if let Some(family) = request.windows_family {
        edit_metadata(
            &mut entries,
            &format!("msft:spp/token/windows/productkeyid/{family}"),
            false,
            &[
                ("windowsComponentEditionPkeyId", &pkey_id),
                ("windowsComponentEditionSkuId", &sku_id),
            ],
        )?;
    }
    edit_metadata(
        &mut entries,
        "msft:spp/token/PKeyIdUriMapper_--_met",
        false,
        &[(&pkey_id, key.algorithm_uri())],
    )?;
    edit_metadata(
        &mut entries,
        &format!("{sku_id}_--_met"),
        true,
        &[("pkeyId", &pkey_id), ("pkeyIdList", &pkey_id)],
    )?;

    let name = utf16(&format!("SPPSVC\\{app_id}\\{sku_id}"));
    // The upstream dictionary cannot represent duplicate physical keys. Reject an
    // ambiguous target, while preserving unrelated duplicate keys verbatim.
    if store
        .groups
        .iter()
        .flatten()
        .filter(|k| k.name == name)
        .count()
        > 1
    {
        return Err(invalid("ambiguous physical product key"));
    }
    let block = physical::Block {
        kind: 1,
        flags: if matches!(request.version, Version::Modern) {
            0x402
        } else {
            2
        },
        unknown: 0,
        key: Vec::new(),
        value: utf16(&pkey_id),
        data,
    };
    if let Some(target) = store.groups.iter_mut().flatten().find(|k| k.name == name) {
        if let Some(index) = target.blocks.iter().position(|b| b.value == block.value) {
            target.blocks.remove(index);
        }
        target.blocks.push(block);
    } else {
        if store.groups.is_empty() {
            store.groups.push(Vec::new());
        }
        store.groups.last_mut().unwrap().push(physical::Key {
            name,
            blocks: vec![block],
        });
    }
    let physical = store.encode()?;
    let tokens = token::encode(&entries)?;
    if Store::decode(&physical, physical::Format::Modern)? != store {
        return Err(invalid("key installation physical roundtrip mismatch"));
    }
    // Reparse checks hashes, lengths and all serialized token offsets.
    token::decode(&tokens)?;
    Ok(Plan {
        physical,
        tokens,
        registry: request.windows_family.map(|_| RegistryData {
            product_id,
            digital_product_id: pid3,
            digital_product_id4: pid4,
            kms_host: meta.channel == "Volume:CSVLK",
        }),
    })
}

fn edit_metadata(
    entries: &mut Vec<token::Entry>,
    name: &str,
    remove_old: bool,
    updates: &[(&str, &str)],
) -> Result<()> {
    let mut meta = match entries
        .iter()
        .find(|e| e.name == name && e.extension == "xml" && e.data.is_some())
    {
        Some(entry) => token::Metadata::decode(entry.data.as_ref().unwrap())?,
        None => token::Metadata {
            name: name.into(),
            values: Vec::new(),
        },
    };
    let mut seen = HashSet::new();
    if meta
        .values
        .iter()
        .any(|(key, _)| !seen.insert(key.as_str()))
    {
        return Err(invalid("duplicate keys in target token metadata"));
    }
    if remove_old
        && let Some(index) = meta
            .values
            .iter()
            .position(|(k, _)| k.starts_with("pkeyId_"))
    {
        meta.values.remove(index);
    }
    for (key, value) in updates {
        if let Some((_, old)) = meta.values.iter_mut().find(|(k, _)| k == key) {
            *old = (*value).into();
        } else {
            meta.values.push(((*key).into(), (*value).into()));
        }
    }
    let data = meta.encode()?;
    entries.retain(|e| !(e.name == name && e.extension == "xml" && e.data.is_none()));
    if let Some(entry) = entries
        .iter_mut()
        .find(|e| e.name == name && e.extension == "xml" && e.data.is_some())
    {
        entry.data = Some(data);
    } else {
        entries.push(token::Entry {
            name: name.into(),
            extension: "xml".into(),
            data: Some(data),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const TOKENS: &[u8] = include_bytes!("../../../tests/fixtures/tsforge/tokens-modern.bin");
    fn request() -> Request<'static> {
        Request {
            version: Version::Modern,
            key: Key2005::new(206, 100_000_001, 0, false).unwrap(),
            metadata: Metadata {
                mpc: "03612",
                activation_id: [1; 16],
                edition: "Professional",
                part_number: "X00-12345",
                channel: "Retail",
                eula: "Retail",
                lcid: 1033,
                build: 26100,
                day: 298,
                year: 2026,
            },
            application_id: [2; 16],
            windows_family: Some("Professional"),
            pid_nonce: 123,
        }
    }
    fn physical() -> Vec<u8> {
        Store {
            header: [0; 8],
            groups: vec![],
            blocks: vec![],
            format: physical::Format::Modern,
        }
        .encode()
        .unwrap()
    }
    fn metadata(entries: &[token::Entry], name: &str) -> token::Metadata {
        token::Metadata::decode(
            entries
                .iter()
                .find(|e| e.name == name && e.data.is_some())
                .unwrap()
                .data
                .as_ref()
                .unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn installation_bag_metadata_and_registry_agree_and_preserve_unrelated_tokens() {
        let request = request();
        let plan = prepare(&physical(), TOKENS, &request).unwrap();
        let entries = token::decode(&plan.tokens).unwrap();
        let original = token::decode(TOKENS).unwrap();
        assert_eq!(&entries[..original.len()], original);
        let store = Store::decode(&plan.physical, physical::Format::Modern).unwrap();
        let block = &store.groups[0][0].blocks[0];
        assert_eq!((block.kind, block.flags, block.unknown), (1, 0x402, 0));
        let records = bag::decode(&block.data, bag::Format::Modern).unwrap();
        assert_eq!(records.len(), 9);
        assert_eq!(
            records.iter().map(|r| r.kind).collect::<Vec<_>>(),
            [2, 2, 4, 4, 4, 2, 2, 4, 4]
        );
        let registry = plan.registry.unwrap();
        assert_eq!(records[2].value, utf16(&registry.product_id));
        assert_eq!(records[3].value, registry.digital_product_id);
        assert_eq!(records[4].value, registry.digital_product_id4);
        assert!(!registry.kms_host);
        assert_eq!(records[7].value, request.key.phone_data(false));
        assert!(records[8].value.is_empty());
        let id = guid_string(request.key.binding_id().unwrap());
        assert_eq!(block.value, utf16(&id));
        let mapper = metadata(&entries, "msft:spp/token/PKeyIdUriMapper_--_met");
        assert_eq!(
            mapper.values,
            vec![(id.clone(), request.key.algorithm_uri().into())]
        );
        let edition = metadata(&entries, "msft:spp/token/windows/productkeyid/Professional");
        assert_eq!(edition.values[0].1, id);
        let again = prepare(&plan.physical, &plan.tokens, &request).unwrap();
        assert_eq!(again.physical, plan.physical);
        assert_eq!(again.tokens, plan.tokens);
    }
    #[test]
    fn metadata_changes_only_first_legacy_id_and_first_populated_entry() {
        let name = "sku";
        let meta = token::Metadata {
            name: name.into(),
            values: vec![
                ("pkeyId_old".into(), "old".into()),
                ("keep".into(), "测试😀".into()),
                ("pkeyId_second".into(), "second".into()),
                ("pkeyId".into(), "previous".into()),
            ],
        };
        let entry = token::Entry {
            name: name.into(),
            extension: "xml".into(),
            data: Some(meta.encode().unwrap()),
        };
        let mut inactive = entry.clone();
        inactive.data = None;
        let mut other_ext = inactive.clone();
        other_ext.extension = "dat".into();
        let mut entries = vec![inactive, entry.clone(), entry.clone(), other_ext.clone()];
        edit_metadata(
            &mut entries,
            name,
            true,
            &[("pkeyId", "new"), ("pkeyIdList", "new")],
        )
        .unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[1], entry);
        assert_eq!(entries[2], other_ext);
        assert_eq!(
            metadata(&entries, name).values,
            vec![
                ("keep".into(), "测试😀".into()),
                ("pkeyId_second".into(), "second".into()),
                ("pkeyId".into(), "new".into()),
                ("pkeyIdList".into(), "new".into()),
            ]
        );
    }
    #[test]
    fn version_and_product_scope_control_flags_and_registry() {
        for version in [Version::Win8, Version::WinBlue, Version::Modern] {
            let mut request = request();
            request.version = version;
            request.windows_family = None;
            let plan = prepare(&physical(), TOKENS, &request).unwrap();
            assert!(plan.registry.is_none());
            let entries = token::decode(&plan.tokens).unwrap();
            assert!(
                !entries
                    .iter()
                    .any(|e| e.name.starts_with("msft:spp/token/windows/productkeyid/"))
            );
            let store = Store::decode(&plan.physical, physical::Format::Modern).unwrap();
            assert_eq!(
                store.groups[0][0].blocks[0].flags,
                if matches!(version, Version::Modern) {
                    0x402
                } else {
                    2
                }
            );
        }
        let mut request = request();
        request.metadata.channel = "Volume:CSVLK";
        assert!(
            prepare(&physical(), TOKENS, &request)
                .unwrap()
                .registry
                .unwrap()
                .kms_host
        );
        for version in [Version::Vista, Version::Win7] {
            request.version = version;
            assert!(prepare(&physical(), TOKENS, &request).is_err());
        }
    }
    #[test]
    fn physical_replacement_preserves_unknown_records_and_rejects_ambiguous_targets() {
        let request = request();
        let initial = prepare(&physical(), TOKENS, &request).unwrap();
        let mut store = Store::decode(&initial.physical, physical::Format::Modern).unwrap();
        let mut unknown = store.groups[0][0].blocks[0].clone();
        unknown.value = utf16("unrelated");
        unknown.unknown = 0xdeadbeef;
        unknown.data = vec![1, 2, 3];
        store.groups[0][0].blocks.insert(0, unknown.clone());
        let updated = prepare(&store.encode().unwrap(), &initial.tokens, &request).unwrap();
        let decoded = Store::decode(&updated.physical, physical::Format::Modern).unwrap();
        assert_eq!(decoded.groups[0][0].blocks.len(), 2);
        assert_eq!(decoded.groups[0][0].blocks[0], unknown);
        store.groups.push(vec![store.groups[0][0].clone()]);
        assert!(prepare(&store.encode().unwrap(), TOKENS, &request).is_err());
    }
    #[test]
    fn invalid_target_metadata_and_overlong_names_leave_inputs_unchanged() {
        let mut request = request();
        let original = token::decode(TOKENS).unwrap();
        let mut entries = original.clone();
        entries.push(token::Entry {
            name: "msft:spp/token/PKeyIdUriMapper_--_met".into(),
            extension: "xml".into(),
            data: Some(vec![0; 4]),
        });
        let tokens = token::encode(&entries).unwrap();
        let before = tokens.clone();
        let physical = physical();
        assert!(prepare(&physical, &tokens, &request).is_err());
        assert_eq!(tokens, before);
        assert_eq!(&token::decode(&tokens).unwrap()[..entries.len()], entries);
        let long_name = "x".repeat(70);
        request.windows_family = Some(&long_name);
        assert!(prepare(&physical, TOKENS, &request).is_err());
        request.windows_family = None;
        request.metadata.activation_id = [0; 16];
        assert!(prepare(&physical, TOKENS, &request).is_err());
    }
}
