//! Filesystem part of Ohook removal, tested without an Office installation.
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::{fs, path::Path};
fn reparse(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        meta.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}
pub fn plain_ancestors(path: &Path) -> Result<(), String> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(ancestor) {
            Ok(meta) if reparse(&meta) => {
                return Err(format!("路径包含重解析点，未修改：{}", ancestor.display()));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", ancestor.display())),
        }
    }
    Ok(())
}
fn remove_file(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !reparse(&meta) && meta.permissions().readonly() {
            let mut permissions = meta.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            // Windows-only: removes FILE_ATTRIBUTE_READONLY, does not change the ACL.
            permissions.set_readonly(false);
            fs::set_permissions(path, permissions).map_err(|e| e.to_string())?;
        }
    }
    fs::remove_file(path)
        .map_err(|e| format!("删除 {}: {e}；请关闭 Office 应用后重试", path.display()))
}
pub fn remove_sppc(dir: &Path, recursive: bool, report: &dyn Fn(&str)) -> Result<usize, String> {
    plain_ancestors(dir)?;
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    };
    let mut removed = 0;
    let mut errors = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if meta.is_dir() {
            if recursive && !reparse(&meta) {
                match remove_sppc(&path, true, report) {
                    Ok(n) => removed += n,
                    Err(e) => errors.push(e),
                }
            }
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
        if name.starts_with("sppc") && name.ends_with(".dll") {
            match remove_file(&path) {
                Ok(()) => {
                    removed += 1;
                    report(&format!("已删除 {}", path.display()));
                }
                Err(e) => errors.push(e),
            }
        }
    }
    if errors.is_empty() {
        Ok(removed)
    } else {
        Err(errors.join("\n"))
    }
}
/// Upstream stores the original OSPPC as sppcs.dll and identifies its small
/// replacement by size. Never overwrite an already-present large original.
pub fn restore_ospp(dir: &Path, report: &dyn Fn(&str)) -> Result<usize, String> {
    plain_ancestors(dir)?;
    let mut changed = 0;
    for name in ["OSPPC.DLL", "sppcs.dll"] {
        let path = dir.join(name);
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.to_string()),
        };
        if reparse(&meta) || meta.is_dir() {
            return Err(format!("OSPPC 恢复路径不是普通文件：{}", path.display()));
        }
        if meta.len() > 0 && meta.len() < 100_000 {
            remove_file(&path)?;
            changed += 1;
            report(&format!("已删除 Ohook 文件 {}", path.display()));
        }
    }
    let backup = dir.join("sppcs.dll");
    let original = dir.join("OSPPC.DLL");
    if backup.is_file() && fs::metadata(&backup).map_err(|e| e.to_string())?.len() >= 100_000 {
        if original.exists() {
            return Err(format!(
                "{} 和原始备份同时存在，未覆盖；请检查后重试",
                original.display()
            ));
        }
        fs::rename(&backup, &original).map_err(|e| format!("还原 {}: {e}", original.display()))?;
        changed += 1;
        report(&format!("已还原 {}", original.display()));
    }
    Ok(changed)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn removes_only_hook_named_files_and_restores_original_bytes() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("sppc.dll"), b"hook").unwrap();
        fs::write(dir.path().join("keep.dll"), b"keep").unwrap();
        assert_eq!(remove_sppc(dir.path(), false, &|_| {}).unwrap(), 1);
        assert!(dir.path().join("keep.dll").exists());
        fs::write(dir.path().join("OSPPC.DLL"), b"hook").unwrap();
        let original = vec![0x6a; 100_001];
        fs::write(dir.path().join("sppcs.dll"), &original).unwrap();
        assert_eq!(restore_ospp(dir.path(), &|_| {}).unwrap(), 2);
        assert_eq!(fs::read(dir.path().join("OSPPC.DLL")).unwrap(), original);
        assert_eq!(restore_ospp(dir.path(), &|_| {}).unwrap(), 0);
    }
    #[test]
    fn does_not_overwrite_another_original() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("OSPPC.DLL"), vec![1; 100_001]).unwrap();
        fs::write(dir.path().join("sppcs.dll"), vec![2; 100_001]).unwrap();
        assert!(restore_ospp(dir.path(), &|_| {}).is_err());
        assert_eq!(fs::read(dir.path().join("OSPPC.DLL")).unwrap()[0], 1);
        assert_eq!(fs::read(dir.path().join("sppcs.dll")).unwrap()[0], 2);
    }
    #[cfg(unix)]
    #[test]
    fn unlinks_file_symlink_without_following_directory_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        fs::write(other.path().join("sppc.dll"), b"original").unwrap();
        std::os::unix::fs::symlink(other.path().join("sppc.dll"), dir.path().join("sppcs.dll"))
            .unwrap();
        std::os::unix::fs::symlink(other.path(), dir.path().join("linked-dir")).unwrap();
        assert_eq!(remove_sppc(dir.path(), true, &|_| {}).unwrap(), 1);
        assert_eq!(
            fs::read(other.path().join("sppc.dll")).unwrap(),
            b"original"
        );
        assert!(remove_sppc(&dir.path().join("linked-dir"), true, &|_| {}).is_err());
    }
}

pub enum Payload<'a> {
    Bytes(&'a [u8]),
    Link(&'a Path),
}
/// Stage every replacement first, then rotate old files. If rollback fails,
/// retain the staging directory and report its location instead of deleting backups.
pub fn deploy(dir: &Path, entries: &[(&str, Payload<'_>)]) -> Result<(), String> {
    plain_ancestors(dir)?;
    if !dir.exists() {
        fs::create_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let staged = tempfile::tempdir_in(dir).map_err(|e| e.to_string())?;
    for (name, payload) in entries {
        if name.contains(['\\', '/']) || *name == ".." {
            return Err("无效部署文件名".into());
        }
        let path = staged.path().join(name);
        match payload {
            Payload::Bytes(bytes) => fs::write(&path, bytes).map_err(|e| e.to_string())?,
            Payload::Link(target) => {
                #[cfg(windows)]
                std::os::windows::fs::symlink_file(target, &path)
                    .map_err(|e| format!("创建系统 DLL 链接：{e}"))?;
                #[cfg(unix)]
                std::os::unix::fs::symlink(target, &path).map_err(|e| e.to_string())?;
            }
        }
    }
    let mut changed: Vec<(&str, bool, bool)> = Vec::new();
    let result = (|| -> Result<(), String> {
        for (name, _) in entries {
            let path = dir.join(name);
            let backup = staged.path().join(format!("old-{name}"));
            let existed = match fs::symlink_metadata(&path) {
                Ok(meta) => {
                    if meta.is_dir() {
                        return Err(format!("部署目标为目录：{}", path.display()));
                    }
                    true
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                Err(e) => return Err(e.to_string()),
            };
            if existed {
                fs::rename(&path, &backup).map_err(|e| format!("备份 {}: {e}", path.display()))?;
            }
            changed.push((name, existed, false));
            fs::rename(staged.path().join(name), &path)
                .map_err(|e| format!("部署 {}: {e}", path.display()))?;
            changed.last_mut().unwrap().2 = true;
        }
        Ok(())
    })();
    if let Err(error) = result {
        let mut failures = Vec::new();
        for (name, existed, installed) in changed.into_iter().rev() {
            let path = dir.join(name);
            if installed && let Err(e) = remove_file(&path) {
                failures.push(e);
                continue;
            }
            if existed && let Err(e) = fs::rename(staged.path().join(format!("old-{name}")), &path)
            {
                failures.push(e.to_string());
            }
        }
        if !failures.is_empty() {
            return Err(format!(
                "{error}\n恢复失败：{}\n备份保留于 {}",
                failures.join("; "),
                staged.keep().display()
            ));
        }
        return Err(format!("{error}；已恢复原文件"));
    }
    Ok(())
}
#[cfg(test)]
mod deploy_tests {
    use super::*;
    #[test]
    fn failed_second_replacement_rolls_back_the_first() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("sppc.dll"), b"old").unwrap();
        fs::create_dir(dir.path().join("sppcs.dll")).unwrap();
        assert!(
            deploy(
                dir.path(),
                &[
                    ("sppc.dll", Payload::Bytes(b"new")),
                    ("sppcs.dll", Payload::Bytes(b"system"))
                ]
            )
            .is_err()
        );
        assert_eq!(fs::read(dir.path().join("sppc.dll")).unwrap(), b"old");
        assert!(dir.path().join("sppcs.dll").is_dir());
    }
    #[test]
    fn successful_deployment_replaces_only_named_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("keep.dll"), b"keep").unwrap();
        let source = dir.path().join("original.dll");
        fs::write(&source, b"original").unwrap();
        #[cfg(unix)]
        let original = Payload::Link(&source);
        #[cfg(not(unix))]
        let original = Payload::Bytes(b"original");
        deploy(
            dir.path(),
            &[
                ("sppc.dll", Payload::Bytes(b"new")),
                ("sppcs.dll", original),
            ],
        )
        .unwrap();
        assert_eq!(fs::read(dir.path().join("sppcs.dll")).unwrap(), b"original");
        assert_eq!(fs::read(dir.path().join("keep.dll")).unwrap(), b"keep");
    }
}
