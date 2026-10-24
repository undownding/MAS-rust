//! Prepare the current edition's CSVLK files before any InstallLicense calls.
#![cfg_attr(not(test), allow(dead_code))]
use crate::native::office_catalog::decode_license;
use std::{
    io::Read,
    path::{Path, PathBuf},
};
pub struct License {
    pub path: PathBuf,
    pub xml: String,
}
pub fn import_all(
    licenses: &[License],
    mut install: impl FnMut(&License) -> Result<(), String>,
) -> Result<usize, String> {
    for (completed, license) in licenses.iter().enumerate() {
        install(license).map_err(|error| {
            format!(
                "CSVLK 导入失败，此前已导入 {completed} 个文件，不自动撤销：{}：{error}",
                license.path.display()
            )
        })?;
    }
    Ok(licenses.len())
}
pub fn prepare(root: &Path, edition: &str, build: u32) -> Result<Vec<License>, String> {
    if edition.is_empty()
        || !edition
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        return Err("无效的 Windows 版本目录名".into());
    }
    if build < 10586 {
        return Ok(Vec::new());
    }
    let directory = root.join(edition);
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("读取 CSVLK 目录：{error}")),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if name.contains("csvlk")
            && name.ends_with(".xrm-ms")
            && entry.file_type().map_err(|e| e.to_string())?.is_file()
        {
            paths.push(entry.path());
            if paths.len() > 256 {
                return Err("CSVLK 许可文件数量超出限制".into());
            }
        }
    }
    paths.sort_by_cached_key(|p| p.to_string_lossy().to_ascii_lowercase());
    let mut result = Vec::new();
    let mut remaining = 64 * 1024 * 1024u64;
    for path in paths {
        let mut bytes = Vec::new();
        std::fs::File::open(&path)
            .map_err(|e| e.to_string())?
            .take(remaining + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        remaining = remaining
            .checked_sub(bytes.len() as u64)
            .ok_or("CSVLK 许可文件总大小超出限制")?;
        let xml = decode_license(&bytes)?;
        let doc = roxmltree::Document::parse_with_options(
            &xml,
            roxmltree::ParsingOptions {
                allow_dtd: false,
                nodes_limit: 1_000_000,
                ..Default::default()
            },
        )
        .map_err(|e| format!("{}: {e}", path.display()))?;
        if doc.root_element().tag_name().name() != "licenseGroup" {
            return Err(format!("CSVLK 文件缺少 licenseGroup：{}", path.display()));
        }
        // Do not reserialize signed XRM content; InstallLicense receives the
        // decoded source text exactly, including whitespace and namespaces.
        result.push(License { path, xml });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn import_failure_retains_completed_count_and_stops() {
        let files = (0..3)
            .map(|i| License {
                path: PathBuf::from(i.to_string()),
                xml: "<licenseGroup/>".into(),
            })
            .collect::<Vec<_>>();
        let mut calls = 0;
        let error = import_all(&files, |_| {
            calls += 1;
            if calls == 2 {
                Err("HRESULT".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(calls, 2);
        assert!(error.contains("此前已导入 1") && error.contains("HRESULT"));
        assert_eq!(import_all(&files, |_| Ok(())).unwrap(), 3);
    }
    #[test]
    fn only_current_edition_csvlk_files_are_prepared_in_order() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("Professional");
        std::fs::create_dir(&dir).unwrap();
        let xml = "<licenseGroup xmlns=\"urn:test\">  </licenseGroup>";
        for name in [
            "b-CSVLK.xrm-ms",
            "a-csvlk.xrm-ms",
            "c-Retail.xrm-ms",
            "CSVLK.txt",
        ] {
            std::fs::write(dir.join(name), xml).unwrap();
        }
        let files = prepare(root.path(), "Professional", 10586).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path.file_name().unwrap(), "a-csvlk.xrm-ms");
        assert_eq!(files[0].xml, xml);
        assert!(
            prepare(root.path(), "Professional", 10585)
                .unwrap()
                .is_empty()
        );
        assert!(
            prepare(root.path(), "Enterprise", 10586)
                .unwrap()
                .is_empty()
        );
        assert!(prepare(root.path(), "../Professional", 10586).is_err());
    }
    #[test]
    fn bad_file_rejects_entire_plan_and_utf16_is_supported() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("Professional");
        std::fs::create_dir(&dir).unwrap();
        let xml = "<licenseGroup/>";
        let bytes: Vec<u8> = [0xff, 0xfe]
            .into_iter()
            .chain(xml.encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        std::fs::write(dir.join("a-CSVLK.xrm-ms"), bytes).unwrap();
        assert_eq!(
            prepare(root.path(), "Professional", 10586).unwrap()[0].xml,
            xml
        );
        std::fs::write(dir.join("b-CSVLK.xrm-ms"), "<broken>").unwrap();
        assert!(prepare(root.path(), "Professional", 10586).is_err());
        std::fs::write(
            dir.join("b-CSVLK.xrm-ms"),
            "<!DOCTYPE x [<!ENTITY a 'test'>]><licenseGroup>&a;</licenseGroup>",
        )
        .unwrap();
        assert!(prepare(root.path(), "Professional", 10586).is_err());
    }
}
