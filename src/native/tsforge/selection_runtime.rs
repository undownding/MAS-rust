//! Read-only native inputs for Windows-ActID; no services or keys are changed.
#![allow(dead_code)]
use super::{
    pkey_config,
    product_selection::{self, Candidate, Channel},
    sl,
};
use crate::native::{
    licensing::{Licensing, WINDOWS_APP, string},
    platform,
};
use std::{collections::HashSet, io::Read, path::Path};
use uuid::Uuid;

fn decode_xml(bytes: &[u8]) -> std::io::Result<String> {
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        let little = bytes[0] == 0xff;
        let (pairs, tail) = bytes[2..].as_chunks::<2>();
        if !tail.is_empty() {
            return Err(std::io::Error::other("odd UTF-16 license length"));
        }
        let words: Vec<_> = pairs
            .iter()
            .map(|b| {
                if little {
                    u16::from_le_bytes(*b)
                } else {
                    u16::from_be_bytes(*b)
                }
            })
            .collect();
        String::from_utf16(&words).map_err(std::io::Error::other)
    } else {
        String::from_utf8(
            bytes
                .strip_prefix(&[0xef, 0xbb, 0xbf])
                .unwrap_or(bytes)
                .to_vec(),
        )
        .map_err(std::io::Error::other)
    }
}
fn read_xml(path: &Path) -> Result<String, String> {
    const LIMIT: u64 = 64 * 1024 * 1024;
    let file = std::fs::File::open(path).map_err(|e| format!("读取 {}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > LIMIT {
        return Err(format!("许可文件过大: {}", path.display()));
    }
    decode_xml(&bytes).map_err(|e| format!("解析 {}: {e}", path.display()))
}

fn matching_files(
    directory: &Path,
    edition: &str,
    component: bool,
    candidates: &[Candidate],
    ids: &mut HashSet<Uuid>,
) -> Result<(), String> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("枚举 {}: {e}", directory.display())),
    };
    let edition = edition.to_ascii_lowercase();
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        let matches = if component {
            name.contains(&format!("-{edition}-"))
        } else {
            name.starts_with(&edition)
        };
        if !matches || !name.ends_with(".xrm-ms") || name.contains("beta") || name.contains("test")
        {
            continue;
        }
        if !entry.file_type().map_err(|e| e.to_string())?.is_file() {
            continue;
        }
        let xml = read_xml(&entry.path())?.to_ascii_lowercase();
        for candidate in candidates {
            // Match upstream's textual productSkuId marker, rather than accepting
            // IDs from unrelated metadata or different XML fields.
            if xml.contains(&format!("name=\"productskuid\">{{{}}}", candidate.id)) {
                ids.insert(candidate.id);
            }
        }
    }
    Ok(())
}

pub fn windows(edition: &str, channel: Channel) -> Result<Option<Uuid>, String> {
    if edition.is_empty()
        || !edition
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("Windows EditionID 不是有效的 SKU 目录名".into());
    }
    let licensing = Licensing::new()?;
    let context = sl::Context::open().map_err(|e| e.to_string())?;
    let mut candidates = Vec::new();
    for product in licensing.query(&format!("SELECT ID, Description, LicenseFamily FROM SoftwareLicensingProduct WHERE ApplicationID='{WINDOWS_APP}'"))? {
        let family = string(&product,"LicenseFamily")?;
        if !family.eq_ignore_ascii_case(edition) { continue; }
        let description = string(&product, "Description")?;
        if !channel.matches(&description) { continue; }
        let id = Uuid::parse_str(&string(&product,"ID")?).map_err(|e| format!("无效 Windows SKU: {e}"))?;
        let sku = windows_sys::core::GUID::from_u128(id.as_u128());
        let file_id = context.sku_information(&sku,"fileId").map_err(|e| e.to_string())?
            .ok_or_else(|| format!("产品 {id} 缺少 fileId"))?.string().map_err(|e| e.to_string())?;
        let file_id = Uuid::parse_str(&file_id).map_err(|e| format!("产品 {id} 的 fileId 无效: {e}"))?;
        let xml = context.license_xml(&windows_sys::core::GUID::from_u128(file_id.as_u128())).map_err(|e| e.to_string())?;
        let (mui_locked,kms_count) = product_selection::policies(&xml).map_err(|e| format!("产品 {id} 的许可策略无效: {e}"))?;
        candidates.push(Candidate {id,family,description:string(&product,"Description")?,mui_locked,kms_count});
    }
    let root = platform::system_file(r"spp\tokens")?;
    let mut file_ids = HashSet::new();
    matching_files(
        &root.join("skus").join(edition),
        edition,
        false,
        &candidates,
        &mut file_ids,
    )?;
    matching_files(
        &root
            .join("skus")
            .join(format!("Security-SPP-Component-SKU-{edition}")),
        edition,
        true,
        &candidates,
        &mut file_ids,
    )?;
    let mut config_path = root.join("pkeyconfig").join("pkeyconfig.xrm-ms");
    if channel == Channel::KmsHost {
        let csvlk = root.join("pkeyconfig").join("pkeyconfig-csvlk.xrm-ms");
        if csvlk.try_exists().map_err(|e| e.to_string())? {
            config_path = csvlk;
        }
    }
    let xml = read_xml(&config_path)?;
    let config = pkey_config::extract_config(&xml).map_err(|e| e.to_string())?;
    let products = pkey_config::parse_selection_config(&config).map_err(|e| e.to_string())?;
    product_selection::select(edition, channel, &candidates, &file_ids, &products)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_windows_selection_is_read_only() {
        use crate::native::registry::Key;
        use windows_sys::Win32::System::Registry::KEY_WOW64_64KEY;
        let key = Key::open(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            KEY_WOW64_64KEY,
            false,
        )
        .unwrap()
        .unwrap();
        let edition = key.string("EditionID").unwrap().unwrap();
        let selected = windows(&edition, Channel::Zero).unwrap();
        if let Some(id) = selected {
            assert!(!id.is_nil());
        }
    }
    #[test]
    fn license_text_handles_large_configs_and_bom_encodings() {
        let text = "a".repeat(1024 * 1024 + 1);
        assert_eq!(decode_xml(text.as_bytes()).unwrap(), text);
        for (bom, little) in [([0xff, 0xfe], true), ([0xfe, 0xff], false)] {
            let mut bytes = bom.to_vec();
            for word in "<许可/>".encode_utf16() {
                bytes.extend(if little {
                    word.to_le_bytes()
                } else {
                    word.to_be_bytes()
                });
            }
            assert_eq!(decode_xml(&bytes).unwrap(), "<许可/>");
            bytes.push(0);
            assert!(decode_xml(&bytes).is_err());
        }
    }
    #[test]
    fn file_patterns_ignore_preview_and_unrelated_ids() {
        let directory = tempfile::tempdir().unwrap();
        let id = Uuid::from_u128(1);
        let candidate = Candidate {
            id,
            family: "Professional".into(),
            description: "RETAIL".into(),
            mui_locked: false,
            kms_count: 0,
        };
        let content = format!("<info name=\"productSkuId\">{{{id}}}</info>");
        std::fs::write(directory.path().join("Professional-Test.xrm-ms"), &content).unwrap();
        std::fs::write(directory.path().join("Other.xrm-ms"), &content).unwrap();
        let mut ids = HashSet::new();
        matching_files(
            directory.path(),
            "Professional",
            false,
            std::slice::from_ref(&candidate),
            &mut ids,
        )
        .unwrap();
        assert!(ids.is_empty());
        std::fs::write(
            directory.path().join("Professional-Retail.xrm-ms"),
            &content,
        )
        .unwrap();
        matching_files(
            directory.path(),
            "Professional",
            false,
            std::slice::from_ref(&candidate),
            &mut ids,
        )
        .unwrap();
        assert_eq!(ids, HashSet::from([id]));
        ids.clear();
        matching_files(
            directory.path(),
            "Professional",
            true,
            std::slice::from_ref(&candidate),
            &mut ids,
        )
        .unwrap();
        assert!(ids.is_empty());
        std::fs::write(
            directory.path().join("SKU-Professional-Retail.xrm-ms"),
            content,
        )
        .unwrap();
        matching_files(
            directory.path(),
            "Professional",
            true,
            &[candidate],
            &mut ids,
        )
        .unwrap();
        assert_eq!(ids, HashSet::from([id]));
    }
}
