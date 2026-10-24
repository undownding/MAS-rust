//! Office license selection from the pinned upstream ksdata table.
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct License {
    pub id: &'static str,
    pub key: &'static str,
    pub product: &'static str,
}
pub fn select(version: u32, product: &str, allow_conversion: bool) -> Option<License> {
    include_str!("../../vendor/mas/native/online-kms.tsv")
        .lines()
        .filter_map(|line| {
            let row: Vec<_> = line.split('\t').collect();
            if row[0] != "office" || row[3].parse::<u32>().ok()? != version {
                return None;
            }
            let exact = row[4].eq_ignore_ascii_case(product);
            let alias = allow_conversion
                && row.get(5).is_some_and(|aliases| {
                    aliases
                        .split('-')
                        .any(|alias| alias.eq_ignore_ascii_case(product))
                });
            (exact || alias).then_some(License {
                id: row[1],
                key: row[2],
                product: row[4],
            })
        })
        .next()
}
pub fn license_prefix(product: &str) -> String {
    product
        .replace("-Preview", "")
        .replace("XVolume", "XC2RVL_")
        .replace("O365EduCloudRetail", "O365EduCloudEDUR_")
        .replace("ProjectProRetail", "ProjectProO365R_")
        .replace("ProjectStdRetail", "ProjectStdO365R_")
        .replace("VisioProRetail", "VisioProO365R_")
        .replace("VisioStdRetail", "VisioStdO365R_")
        .replace(
            "Volume",
            if product.ends_with("-Preview") {
                "PreviewVL_"
            } else {
                "VL_"
            },
        )
        .replace("Retail", "R_")
}
pub fn decode_license(bytes: &[u8]) -> Result<String, String> {
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        if !bytes.len().is_multiple_of(2) {
            return Err("许可文件 UTF-16 长度无效".into());
        }
        let le = bytes[0] == 0xff;
        let words: Vec<_> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| {
                if le {
                    u16::from_le_bytes([p[0], p[1]])
                } else {
                    u16::from_be_bytes([p[0], p[1]])
                }
            })
            .collect();
        String::from_utf16(&words).map_err(|e| e.to_string())
    } else {
        String::from_utf8(
            bytes
                .strip_prefix(&[0xef, 0xbb, 0xbf])
                .unwrap_or(bytes)
                .to_vec(),
        )
        .map_err(|e| e.to_string())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retail_conversion_is_explicit_and_version_specific() {
        assert!(select(16, "ProPlus2021Retail", false).is_none());
        let found = select(16, "ProPlus2021Retail", true).unwrap();
        assert_eq!(found.product, "ProPlus2021Volume");
        assert_eq!(found.key, "FXYTK-NJJ8C-GB6DW-3DYQT-6F7TH");
        assert_eq!(found.id, "fbdb3e18-a8ef-4fb3-9183-dffd60bd0984");
        assert!(select(15, "ProPlus2021Retail", true).is_none());
        assert!(select(16, "Plus2021Retail", true).is_none());
        assert_eq!(select(16, "ProPlus2021Volume", false).unwrap().id, found.id);
    }
    #[test]
    fn license_prefixes_match_upstream_patterns() {
        assert_eq!(license_prefix("ProPlus2021Volume"), "ProPlus2021VL_");
        assert_eq!(
            license_prefix("ProPlus2024Volume-Preview"),
            "ProPlus2024PreviewVL_"
        );
        assert_eq!(license_prefix("VisioProRetail"), "VisioProO365R_");
        assert_eq!(license_prefix("ProPlusXVolume"), "ProPlusXC2RVL_");
    }
    #[test]
    fn license_text_handles_boms_without_loss() {
        let xml = "<license>许可</license>";
        for le in [true, false] {
            let mut bytes = if le {
                vec![0xff, 0xfe]
            } else {
                vec![0xfe, 0xff]
            };
            for w in xml.encode_utf16() {
                bytes.extend(if le { w.to_le_bytes() } else { w.to_be_bytes() });
            }
            assert_eq!(decode_license(&bytes).unwrap(), xml);
        }
        assert_eq!(decode_license(xml.as_bytes()).unwrap(), xml);
        assert!(decode_license(&[0xff, 0xfe, 0]).is_err());
    }
}

pub fn license_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_type().map_err(|e| e.to_string())?.is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("xrm-ms"))
        {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

pub fn missing_files(dir: &Path, license: &License) -> Result<Vec<(PathBuf, String)>, String> {
    let files = license_files(dir)?;
    let prefix = license_prefix(license.product).to_ascii_lowercase();
    let is_product = |p: &PathBuf| {
        p.file_name()
            .unwrap()
            .to_string_lossy()
            .to_ascii_lowercase()
            .starts_with(&prefix)
    };
    if !files.iter().any(is_product) {
        return Err(format!(
            "缺少 {} 的许可文件：{}",
            license.product,
            dir.display()
        ));
    }
    let pkey = files
        .iter()
        .find(|p| {
            p.file_name()
                .unwrap()
                .eq_ignore_ascii_case("pkeyconfig-office.xrm-ms")
        })
        .ok_or("缺少 pkeyconfig-office.xrm-ms")?;
    let mut selected: Vec<_> = files
        .iter()
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .to_ascii_lowercase()
                .starts_with("client-issuance-")
        })
        .collect();
    selected.extend(files.iter().filter(|p| is_product(p)));
    selected.push(pkey);
    // Decode every file before the first mutation; UTF-16 BOMs occur in Office media.
    selected
        .into_iter()
        .map(|p| {
            let bytes = fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
            let xml = decode_license(&bytes)?;
            if !xml.trim_start().starts_with('<') {
                return Err(format!("许可文件不是 XML：{}", p.display()));
            }
            Ok((p.clone(), xml))
        })
        .collect()
}

#[cfg(test)]
mod file_tests {
    use super::*;
    #[test]
    fn import_plan_requires_product_and_pkey_and_orders_dependencies_first() {
        let dir = tempfile::tempdir().unwrap();
        let license = select(16, "ProPlus2021Volume", false).unwrap();
        for file in [
            "client-issuance-test.xrm-ms",
            "ProPlus2021VL_KMS_Client_AE.xrm-ms",
            "OtherProductVL_KMS.xrm-ms",
        ] {
            fs::write(dir.path().join(file), "<license />").unwrap();
        }
        assert!(missing_files(dir.path(), &license).is_err());
        fs::write(dir.path().join("pkeyconfig-office.xrm-ms"), "<license />").unwrap();
        let files = missing_files(dir.path(), &license).unwrap();
        assert_eq!(files.len(), 3);
        assert_eq!(
            files[0].0.file_name().unwrap(),
            "client-issuance-test.xrm-ms"
        );
        assert_eq!(
            files[1].0.file_name().unwrap(),
            "ProPlus2021VL_KMS_Client_AE.xrm-ms"
        );
        assert_eq!(files[2].0.file_name().unwrap(), "pkeyconfig-office.xrm-ms");
        fs::write(&files[1].0, [0xff, 0xfe, 0]).unwrap();
        assert!(missing_files(dir.path(), &license).is_err());
        assert!(
            missing_files(
                dir.path(),
                &select(16, "VisioPro2021Volume", false).unwrap()
            )
            .is_err()
        );
    }
}
