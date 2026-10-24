//! Preserve WMI repositories by renaming them; never recursively delete either copy.
#![cfg_attr(not(test), allow(dead_code))]
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
fn error(message: &str) -> io::Error {
    io::Error::other(message)
}
fn directory(path: &Path) -> io::Result<bool> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(error("repository directory is a reparse point"));
        }
    }
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(error("repository must be a plain directory"));
    }
    Ok(true)
}
fn target(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() || path.file_name().and_then(|p| p.to_str()) != Some("Repository") {
        return Err(error("expected absolute WMI Repository path"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| error("repository has no parent"))?;
    if !directory(parent)? {
        return Err(error("WBEM directory is absent"));
    }
    Ok(parent.canonicalize()?.join("Repository"))
}
#[derive(Debug)]
pub struct Backup {
    pub root: PathBuf,
    original: PathBuf,
}
/// Caller must stop WMI and disable its automatic restart before moving the repository.
pub fn quarantine(path: &Path) -> io::Result<Backup> {
    let original = target(path)?;
    if !directory(&original)? {
        return Err(error("WMI Repository is absent; nothing to quarantine"));
    }
    let root = tempfile::Builder::new()
        .prefix("mas-wmi-backup-")
        .tempdir_in(original.parent().unwrap())?
        .keep();
    let backup = Backup { root, original };
    let manifest = serde_json::json!({ "version":1, "original":backup.original.to_str().ok_or_else(|| error("repository path is not Unicode"))? });
    let mut file = File::create(backup.root.join("repository.json"))?;
    file.write_all(manifest.to_string().as_bytes())?;
    file.sync_all()?;
    fs::rename(&backup.original, backup.root.join("Repository")).map_err(|e| {
        error(&format!(
            "repository rename failed; checkpoint {}: {e}",
            backup.root.display()
        ))
    })?;
    Ok(backup)
}
impl Backup {
    /// Fixed expected target comes from the system adapter, never from the manifest.
    pub fn load(root: &Path, expected: &Path) -> io::Result<Self> {
        let original = target(expected)?;
        if !directory(root)? {
            return Err(error("backup directory is absent"));
        }
        let root = root.canonicalize()?;
        if root.parent() != original.parent()
            || !root
                .file_name()
                .and_then(|p| p.to_str())
                .is_some_and(|p| p.starts_with("mas-wmi-backup-"))
        {
            return Err(error("backup is outside the fixed WBEM directory"));
        }
        let path = root.join("repository.json");
        let meta = fs::symlink_metadata(&path)?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err(error("repository manifest is a reparse point"));
            }
        }
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 65536 {
            return Err(error("invalid repository manifest"));
        }
        let mut text = String::new();
        File::open(path)?.take(65537).read_to_string(&mut text)?;
        let manifest: serde_json::Value = serde_json::from_str(&text).map_err(io::Error::other)?;
        if manifest["version"] != 1 || manifest["original"].as_str() != original.to_str() {
            return Err(error("repository backup target mismatch"));
        }
        if !directory(&root.join("Repository"))? {
            return Err(error("backup contains no original Repository"));
        }
        Ok(Self { root, original })
    }
    /// Restores the original and keeps any replacement in a separate checkpoint.
    /// Caller again holds WMI stopped. No automatic restore after new providers register.
    pub fn restore(self) -> io::Result<Option<PathBuf>> {
        let backup = Self::load(&self.root, &self.original)?;
        let replacement = if directory(&backup.original)? {
            Some(quarantine(&backup.original)?)
        } else {
            None
        };
        if let Err(e) = fs::rename(backup.root.join("Repository"), &backup.original) {
            let recovery = if let Some(current) = &replacement {
                fs::rename(current.root.join("Repository"), &backup.original)
                    .map_err(|e| e.to_string())
            } else {
                Ok(())
            };
            return Err(error(&format!(
                "original repository restore failed: {e}; replacement rollback: {recovery:?}; original backup: {}; replacement backup: {:?}",
                backup.root.display(),
                replacement.as_ref().map(|b| &b.root)
            )));
        }
        Ok(replacement.map(|p| p.root))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quarantines_and_restores_both_original_and_rebuilt_repository() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("Repository");
        fs::create_dir(&repo).unwrap();
        fs::write(repo.join("OBJECTS.DATA"), b"original").unwrap();
        let backup = quarantine(&repo).unwrap();
        assert!(!repo.exists());
        fs::create_dir(&repo).unwrap();
        fs::write(repo.join("OBJECTS.DATA"), b"rebuilt").unwrap();
        let current = Backup::load(&backup.root, &repo)
            .unwrap()
            .restore()
            .unwrap()
            .unwrap();
        assert_eq!(fs::read(repo.join("OBJECTS.DATA")).unwrap(), b"original");
        assert_eq!(
            fs::read(current.join("Repository/OBJECTS.DATA")).unwrap(),
            b"rebuilt"
        );
        assert!(Backup::load(&backup.root, &repo).is_err());
        Backup::load(&current, &repo).unwrap().restore().unwrap();
        assert_eq!(fs::read(repo.join("OBJECTS.DATA")).unwrap(), b"rebuilt");
    }
    #[test]
    fn validates_target_and_manifest_before_moving_anything() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("Repository");
        assert!(quarantine(&repo).is_err());
        assert!(quarantine(&temp.path().join("Other")).is_err());
        fs::create_dir(&repo).unwrap();
        let backup = quarantine(&repo).unwrap();
        fs::write(
            backup.root.join("repository.json"),
            r#"{"version":1,"original":"elsewhere"}"#,
        )
        .unwrap();
        assert!(Backup::load(&backup.root, &repo).is_err());
        assert!(backup.root.join("Repository").exists());
    }
    #[test]
    fn restores_when_no_replacement_was_created() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("Repository");
        fs::create_dir(&repo).unwrap();
        let backup = quarantine(&repo).unwrap();
        assert!(backup.restore().unwrap().is_none());
        assert!(repo.is_dir());
    }
    #[cfg(unix)]
    #[test]
    fn rejects_symlink_repository_without_touching_destination() {
        let temp = tempfile::tempdir().unwrap();
        let actual = temp.path().join("actual");
        fs::create_dir(&actual).unwrap();
        let repo = temp.path().join("Repository");
        std::os::unix::fs::symlink(&actual, &repo).unwrap();
        assert!(quarantine(&repo).is_err());
        assert!(actual.is_dir());
    }
}
