//! Native :xrm: ReinstallLicenses input preparation for Insider Office refresh.
#![cfg_attr(not(test), allow(dead_code))]
use std::{
    io::Read,
    path::{Path, PathBuf},
};
pub struct License {
    pub path: PathBuf,
    pub xml: String,
}
pub fn prepare(system: &Path) -> Result<Vec<License>, String> {
    let mut paths = Vec::new();
    for relative in ["oem", "licensing", "spp/tokens"] {
        let root = system.join(relative);
        if !root
            .try_exists()
            .map_err(|e| format!("{}：{e}", root.display()))?
        {
            continue;
        }
        let mut directories = vec![(root, 0)];
        let mut visited = 0;
        while let Some((directory, depth)) = directories.pop() {
            visited += 1;
            if depth > 32 || visited > 16384 {
                return Err("许可证目录层级或数量超出限制".into());
            }
            crate::native::hook_files::plain_ancestors(&directory)?;
            for entry in std::fs::read_dir(&directory)
                .map_err(|e| format!("{}：{e}", directory.display()))?
            {
                let entry = entry.map_err(|e| e.to_string())?;
                let kind = entry.file_type().map_err(|e| e.to_string())?;
                if kind.is_dir() {
                    directories.push((entry.path(), depth + 1));
                } else if entry
                    .path()
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("xrm-ms"))
                {
                    crate::native::hook_files::plain_ancestors(&entry.path())?;
                    if !kind.is_file() {
                        return Err(format!("许可路径不是普通文件：{}", entry.path().display()));
                    }
                    paths.push(entry.path());
                    if paths.len() > 16384 {
                        return Err("许可证文件数量超出限制".into());
                    }
                }
            }
        }
    }
    paths.sort_by_cached_key(|p| p.to_string_lossy().to_ascii_lowercase());
    let mut remaining = 128 * 1024 * 1024u64;
    let mut licenses = Vec::new();
    for path in paths {
        let mut bytes = Vec::new();
        std::fs::File::open(&path)
            .map_err(|e| e.to_string())?
            .take(remaining + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        remaining = remaining
            .checked_sub(bytes.len() as u64)
            .ok_or("许可证总大小超出限制")?;
        let xml = crate::native::office_catalog::decode_license(&bytes)?;
        roxmltree::Document::parse_with_options(
            &xml,
            roxmltree::ParsingOptions {
                allow_dtd: false,
                nodes_limit: 1_000_000,
                ..Default::default()
            },
        )
        .map_err(|e| format!("许可 XML 无效 {}：{e}", path.display()))?;
        licenses.push(License { path, xml });
    }
    Ok(licenses)
}
pub fn import(
    licenses: &[License],
    mut install: impl FnMut(&License) -> Result<(), String>,
) -> Result<(), String> {
    for (completed, license) in licenses.iter().enumerate() {
        install(license).map_err(|e| {
            format!(
                "重新导入许可失败，已导入 {completed} 个文件且不自动撤销：{}：{e}",
                license.path.display()
            )
        })?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recursive_fixed_roots_are_prevalidated_and_preserve_original_xml() {
        let dir = tempfile::tempdir().unwrap();
        for root in ["oem/nested", "licensing", "spp/tokens/skus", "unrelated"] {
            std::fs::create_dir_all(dir.path().join(root)).unwrap();
            std::fs::write(
                dir.path().join(root).join("sample.XRM-MS"),
                "<licenseGroup>\n</licenseGroup>",
            )
            .unwrap();
        }
        let files = prepare(dir.path()).unwrap();
        assert_eq!(files.len(), 3);
        assert!(
            files
                .iter()
                .all(|f| f.xml == "<licenseGroup>\n</licenseGroup>")
        );
        let mut count = 0;
        let e = import(&files, |_| {
            count += 1;
            if count == 2 {
                Err("failed".into())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert_eq!(count, 2);
        assert!(e.contains("已导入 1"));
        std::fs::write(&files[2].path, "<broken>").unwrap();
        assert!(prepare(dir.path()).is_err());
    }
}
