//! Reversible removal of licensing .dat files while the owning service is stopped.
#![cfg_attr(not(test), allow(dead_code))]
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};
fn error(s: impl Into<String>) -> io::Error {
    io::Error::other(s.into())
}
const LIMIT: u64 = 256 * 1024 * 1024;
fn plain(path: &Path) -> io::Result<fs::Metadata> {
    let meta = fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(error("token path is a reparse point"));
        }
    }
    if meta.file_type().is_symlink() {
        return Err(error("token path is a symbolic link"));
    }
    Ok(meta)
}
fn digest(path: &Path) -> io::Result<String> {
    let meta = plain(path)?;
    if !meta.is_file() || meta.len() > LIMIT {
        return Err(error(
            "token backup requires a regular file of at most 256 MiB",
        ));
    }
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut length = 0;
    loop {
        let count = file.read(&mut buf)?;
        if count == 0 {
            break;
        }
        length += count as u64;
        if length > LIMIT {
            return Err(error("token file grew beyond limit"));
        }
        hash.update(&buf[..count]);
    }
    if length != meta.len() {
        return Err(error("token file length changed during hashing"));
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn collect(root: &Path) -> io::Result<Vec<PathBuf>> {
    if !plain(root)?.is_dir() {
        return Err(error("token root is not a directory"));
    }
    let mut todo = vec![(root.to_path_buf(), 0)];
    let mut output = vec![];
    let mut seen = 0;
    while let Some((dir, depth)) = todo.pop() {
        seen += 1;
        if depth > 32 || seen > 4096 {
            return Err(error("token tree exceeds traversal limit"));
        }
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            let meta = plain(&path)?;
            if meta.is_dir() {
                todo.push((path, depth + 1));
            } else if meta.is_file()
                && path
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("dat"))
            {
                output.push(
                    path.strip_prefix(root)
                        .map_err(io::Error::other)?
                        .to_path_buf(),
                );
            }
            if output.len() > 4096 {
                return Err(error("too many token files"));
            }
        }
    }
    output.sort();
    Ok(output)
}
fn move_all(from: &Path, to: &Path, files: &[PathBuf]) -> io::Result<()> {
    let mut moved: Vec<&PathBuf> = vec![];
    for file in files {
        let source = from.join(file);
        let target = to.join(file);
        let result = (|| {
            if target.try_exists()? {
                return Err(error("refusing to overwrite token destination"));
            }
            fs::create_dir_all(target.parent().unwrap())?;
            fs::rename(&source, &target)
        })();
        if let Err(e) = result {
            let mut errors = vec![format!("move {} failed: {e}", source.display())];
            for previous in moved.into_iter().rev() {
                let original = from.join(previous);
                let saved = to.join(previous);
                if original.try_exists().unwrap_or(true) {
                    errors.push(format!(
                        "rollback refused occupied path {}",
                        original.display()
                    ));
                } else if let Err(e) = fs::rename(&saved, &original) {
                    errors.push(format!("rollback {} failed: {e}", saved.display()));
                }
            }
            return Err(error(errors.join("; ")));
        }
        moved.push(file);
    }
    Ok(())
}
#[derive(Debug)]
pub struct Backup {
    pub directory: PathBuf,
    root: PathBuf,
    files: Vec<PathBuf>,
}
pub fn quarantine(root: &Path) -> io::Result<Backup> {
    if !root.is_absolute() {
        return Err(error("token root must be absolute"));
    }
    plain(root)?;
    let root = root.canonicalize()?;
    let files = collect(&root)?;
    let mut total = 0u64;
    let mut records = vec![];
    let mut unique = std::collections::HashSet::new();
    for relative in &files {
        if !unique.insert(relative.to_string_lossy().to_lowercase()) {
            return Err(error(
                "case-colliding token paths cannot be backed up safely",
            ));
        }
        let path = root.join(relative);
        total = total
            .checked_add(plain(&path)?.len())
            .ok_or_else(|| error("token size overflow"))?;
        if total > 1024 * 1024 * 1024 {
            return Err(error("token backup exceeds 1 GiB"));
        }
        records.push(serde_json::json!({"path":relative.to_str().ok_or_else(||error("token path is not Unicode"))?,"sha256":digest(&path)?}));
    }
    let directory = tempfile::Builder::new()
        .prefix("mas-token-backup-")
        .tempdir_in(
            root.parent()
                .ok_or_else(|| error("token root has no parent"))?,
        )?
        .keep();
    fs::create_dir(directory.join("files"))?;
    let manifest = serde_json::json!({"version":1,"root":root.to_str().ok_or_else(||error("token root is not Unicode"))?,"files":records});
    let encoded = manifest.to_string();
    if encoded.len() > 1024 * 1024 {
        return Err(error("token manifest exceeds limit before any files move"));
    }
    let mut out = File::create(directory.join("manifest.json"))?;
    out.write_all(encoded.as_bytes())?;
    out.sync_all()?;
    move_all(&root, &directory.join("files"), &files)
        .map_err(|e| error(format!("{e}; backup: {}", directory.display())))?;
    Ok(Backup {
        directory,
        root,
        files,
    })
}
impl Backup {
    pub fn load(directory: &Path, expected: &Path) -> io::Result<Self> {
        if !expected.is_absolute() {
            return Err(error("expected token root must be absolute"));
        }
        plain(expected)?;
        let root = expected.canonicalize()?;
        if !plain(directory)?.is_dir() {
            return Err(error("token backup is not a directory"));
        }
        let directory = directory.canonicalize()?;
        if directory.parent() != root.parent()
            || !directory
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("mas-token-backup-"))
        {
            return Err(error("token backup lies outside expected location"));
        }
        let manifest = directory.join("manifest.json");
        if !plain(&manifest)?.is_file() || plain(&manifest)?.len() > 1024 * 1024 {
            return Err(error("token manifest exceeds limit"));
        }
        let mut text = String::new();
        File::open(manifest)?
            .take(1024 * 1024 + 1)
            .read_to_string(&mut text)?;
        let value: serde_json::Value = serde_json::from_str(&text).map_err(io::Error::other)?;
        if value["version"] != 1 || value["root"].as_str() != root.to_str() {
            return Err(error("token backup target mismatch"));
        }
        let records = value["files"]
            .as_array()
            .ok_or_else(|| error("missing token file records"))?;
        if records.len() > 4096 {
            return Err(error("too many token file records"));
        }
        let base = directory.join("files");
        if !plain(&base)?.is_dir() {
            return Err(error("missing token files directory"));
        }
        let mut files = vec![];
        let mut unique = std::collections::HashSet::new();
        for record in records {
            let relative = PathBuf::from(
                record["path"]
                    .as_str()
                    .ok_or_else(|| error("invalid token relative path"))?,
            );
            if relative.as_os_str().is_empty()
                || relative
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_)))
                || !relative
                    .extension()
                    .is_some_and(|s| s.eq_ignore_ascii_case("dat"))
                || !unique.insert(relative.to_string_lossy().to_lowercase())
            {
                return Err(error("unsafe or duplicate token relative path"));
            }
            let mut path = base.clone();
            for part in relative.components() {
                path.push(part);
                plain(&path)?;
            }
            if record["sha256"].as_str() != Some(&digest(&path)?) {
                return Err(error("token backup checksum mismatch"));
            }
            files.push(relative);
        }
        Ok(Self {
            directory,
            root,
            files,
        })
    }
    pub fn restore(self) -> io::Result<PathBuf> {
        let saved = Self::load(&self.directory, &self.root)?;
        let current = quarantine(&saved.root)?;
        if let Err(e) = move_all(&saved.directory.join("files"), &saved.root, &saved.files) {
            let rollback = move_all(
                &current.directory.join("files"),
                &saved.root,
                &current.files,
            );
            return Err(error(format!(
                "restore failed: {e}; rollback: {rollback:?}; original backup: {}; current backup: {}",
                saved.directory.display(),
                current.directory.display()
            )));
        }
        Ok(current.directory)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_original_is_restored_without_losing_generated_tokens() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("tokens");
        fs::create_dir(&root).unwrap();
        let backup = quarantine(&root).unwrap();
        fs::write(root.join("tokens.dat"), b"generated").unwrap();
        let current = backup.restore().unwrap();
        assert!(!root.join("tokens.dat").exists());
        assert_eq!(
            fs::read(current.join("files/tokens.dat")).unwrap(),
            b"generated"
        );
    }
    #[cfg(unix)]
    #[test]
    fn rejects_linked_token_tree_before_moving_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("tokens");
        fs::create_dir(&root).unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret.dat"), b"outside").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("linked")).unwrap();
        assert!(quarantine(&root).is_err());
        assert_eq!(fs::read(outside.join("secret.dat")).unwrap(), b"outside");
    }
    #[test]
    fn keeps_other_files_and_preserves_both_generations_on_restore() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("tokens");
        fs::create_dir_all(root.join("cache")).unwrap();
        fs::write(root.join("tokens.dat"), b"old").unwrap();
        fs::write(root.join("cache/cache.DAT"), b"cache").unwrap();
        fs::write(root.join("keep.txt"), b"keep").unwrap();
        let backup = quarantine(&root).unwrap();
        assert!(!root.join("tokens.dat").exists());
        assert!(root.join("keep.txt").exists());
        fs::write(root.join("tokens.dat"), b"new").unwrap();
        let current = backup.restore().unwrap();
        assert_eq!(fs::read(root.join("tokens.dat")).unwrap(), b"old");
        Backup::load(&current, &root).unwrap().restore().unwrap();
        assert_eq!(fs::read(root.join("tokens.dat")).unwrap(), b"new");
        assert!(root.join("keep.txt").exists());
    }
    #[test]
    fn corruption_and_traversal_are_rejected_before_current_files_move() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("tokens");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("tokens.dat"), b"old").unwrap();
        let backup = quarantine(&root).unwrap();
        fs::write(root.join("tokens.dat"), b"new").unwrap();
        fs::write(backup.directory.join("files/tokens.dat"), b"tampered").unwrap();
        assert!(Backup::load(&backup.directory, &root).is_err());
        assert_eq!(fs::read(root.join("tokens.dat")).unwrap(), b"new");
        let path = backup.directory.join("manifest.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["files"][0]["path"] = "../outside.dat".into();
        fs::write(path, value.to_string()).unwrap();
        assert!(Backup::load(&backup.directory, &root).is_err());
    }
    #[test]
    fn partial_move_failure_restores_already_moved_files() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&target).unwrap();
        fs::write(source.join("a.dat"), b"a").unwrap();
        assert!(move_all(&source, &target, &["a.dat".into(), "missing.dat".into()]).is_err());
        assert_eq!(fs::read(source.join("a.dat")).unwrap(), b"a");
        assert!(!target.join("a.dat").exists());
    }
}
