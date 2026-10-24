//! A paired legacy store uses one file transaction plus a mirror participant.
//! The mirror's absent/present state is durable before either file is modified.
#![cfg_attr(not(test), allow(dead_code))]
use super::transaction::{self, Failure, Participant, Participants, Transaction};
use crate::native::hook_files::plain_ancestors;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
const MARKER: &str = "paired-store.json";
const ORIGINAL: &str = "mirror.original";
const MAX_STORE: u64 = 64 * 1024 * 1024;
fn read_mirror(file: &mut File) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(MAX_STORE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STORE {
        return Err(invalid("paired store exceeds 64 MiB per-file limit"));
    }
    Ok(bytes)
}
fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn canonical(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(invalid("mirror path is not absolute"));
    }
    plain_ancestors(path).map_err(io::Error::other)?;
    let parent = fs::canonicalize(
        path.parent()
            .ok_or_else(|| invalid("mirror has no parent"))?,
    )?;
    Ok(parent.join(
        path.file_name()
            .ok_or_else(|| invalid("mirror has no filename"))?,
    ))
}
fn save(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
struct Mirror {
    path: PathBuf,
    file: Option<File>,
    original: Option<Vec<u8>>,
    desired: Option<Vec<u8>>,
    backup: PathBuf,
    created: bool,
    deleting: bool,
}
impl Mirror {
    fn capture(path: &Path, desired: Option<Vec<u8>>) -> io::Result<Self> {
        let path = canonical(path)?;
        let (file, original) = match transaction::open_target_access(&path, desired.is_none()) {
            Ok(mut file) => {
                let bytes = read_mirror(&mut file)?;
                (Some(file), Some(bytes))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (None, None),
            Err(error) => return Err(error),
        };
        Ok(Self {
            path,
            file,
            original,
            desired,
            backup: PathBuf::new(),
            created: false,
            deleting: false,
        })
    }
    fn unchanged(&mut self) -> io::Result<()> {
        match (&mut self.file, &self.original) {
            (Some(file), Some(bytes)) => {
                if read_mirror(file)? == *bytes {
                    Ok(())
                } else {
                    Err(invalid("mirror changed after preparation"))
                }
            }
            (None, None) if !self.path.try_exists()? => Ok(()),
            _ => Err(invalid("mirror changed after preparation")),
        }
    }
    fn create(&mut self) -> io::Result<()> {
        plain_ancestors(&self.path).map_err(io::Error::other)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options
                .share_mode(0)
                .access_mode(0xC0010000)
                .custom_flags(0x00200000);
        }
        // A competitor creating the name must cause failure, never overwrite.
        self.file = Some(options.open(&self.path)?);
        self.created = true;
        Ok(())
    }
    #[cfg(windows)]
    fn disposition(&self, delete: bool) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
        };
        let info = FILE_DISPOSITION_INFO {
            DeleteFile: delete as _,
        };
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| invalid("mirror handle is absent"))?;
        let result = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileDispositionInfo,
                (&info as *const FILE_DISPOSITION_INFO).cast(),
                std::mem::size_of_val(&info) as u32,
            )
        };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    fn delete(&mut self) -> io::Result<()> {
        if self.file.is_none() {
            return Ok(());
        }
        #[cfg(windows)]
        self.disposition(true)?;
        #[cfg(not(windows))]
        fs::rename(&self.path, self.backup.join("mirror.deleted"))?;
        self.deleting = true;
        transaction::sync_directory(self.path.parent().unwrap())?;
        transaction::sync_directory(&self.backup)
    }
    fn cancel_delete(&mut self) -> io::Result<()> {
        if !self.deleting {
            return Ok(());
        }
        #[cfg(windows)]
        self.disposition(false)?;
        #[cfg(not(windows))]
        {
            // hard_link fails rather than replacing a file created by a third party.
            fs::hard_link(self.backup.join("mirror.deleted"), &self.path)?;
            fs::remove_file(self.backup.join("mirror.deleted"))?;
        }
        self.deleting = false;
        transaction::sync_directory(self.path.parent().unwrap())
    }
}
impl Participant for Mirror {
    fn prepare(&mut self, backup: &Path) -> io::Result<()> {
        self.unchanged()?;
        self.backup = backup.into();
        if let Some(bytes) = &self.original {
            save(&backup.join(ORIGINAL), bytes)?;
        }
        save(
            &backup.join(MARKER),
            &serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1, "path": self.path.to_str().ok_or_else(|| invalid("non-Unicode mirror path"))?,
                "original_exists": self.original.is_some(), "original_sha256": self.original.as_deref().map(hash)
            }))?,
        )
    }
    fn commit(&mut self) -> io::Result<()> {
        self.unchanged()?;
        if let Some(bytes) = self.desired.take() {
            if self.file.is_none() {
                self.create()?;
            }
            transaction::write_all(self.file.as_mut().unwrap(), &bytes)?;
            transaction::sync_directory(self.path.parent().unwrap())
        } else {
            self.delete()
        }
    }
    fn rollback(&mut self) -> io::Result<()> {
        if let Some(bytes) = self.original.clone() {
            self.cancel_delete()?;
            transaction::write_all(
                self.file
                    .as_mut()
                    .ok_or_else(|| invalid("mirror rollback handle missing"))?,
                &bytes,
            )
        } else if self.created {
            self.delete()?;
            self.file.take(); // Windows completes deletion when this owned handle closes.
            Ok(())
        } else {
            Ok(())
        } // Failed create_new must never delete someone else's file.
    }
}
const EXTRA_REQUIRED: &str = "paired-extra-required";
struct WithExtra<'a>(Participants<'a>);
impl Participant for WithExtra<'_> {
    fn prepare(&mut self, backup: &Path) -> io::Result<()> {
        save(&backup.join(EXTRA_REQUIRED), b"1\n")?;
        self.0.prepare(backup)
    }
    fn commit(&mut self) -> io::Result<()> {
        self.0.commit()
    }
    fn rollback(&mut self) -> io::Result<()> {
        self.0.rollback()
    }
}
pub struct Prepared {
    primary: Transaction,
    mirror: Mirror,
}
impl Prepared {
    pub fn backup_path(&self) -> &Path {
        self.primary.backup_path()
    }
    pub fn commit(mut self) -> Result<PathBuf, Failure> {
        self.primary.commit_participating(&mut self.mirror)
    }
    pub fn commit_participating(mut self, extra: &mut dyn Participant) -> Result<PathBuf, Failure> {
        let mut participants = WithExtra(Participants::new(vec![&mut self.mirror, extra]));
        self.primary.commit_participating(&mut participants)
    }
}
pub fn edit(
    primary: &Path,
    secondary: &Path,
    transform: impl FnOnce(&[u8]) -> io::Result<Vec<u8>>,
) -> io::Result<Prepared> {
    edit_files(primary, secondary, &[], |originals| {
        transform(originals[0]).map(|bytes| vec![bytes])
    })
}
/// Additional existing files (e.g. tokens.dat) share the primary transaction.
pub fn edit_files(
    primary: &Path,
    secondary: &Path,
    additional: &[PathBuf],
    transform: impl FnOnce(&[&[u8]]) -> io::Result<Vec<Vec<u8>>>,
) -> io::Result<Prepared> {
    let mut paths = vec![canonical(primary)?];
    for path in additional {
        paths.push(canonical(path)?);
    }
    let secondary_path = canonical(secondary)?;
    if paths.iter().any(|p| p == &secondary_path) {
        return Err(invalid("paired store targets must differ"));
    }
    let mut mirror = Mirror::capture(&secondary_path, Some(Vec::new()))?;
    let primary = Transaction::edit(paths, |originals| {
        if originals[0].len() as u64 > MAX_STORE {
            return Err(invalid("paired primary exceeds 64 MiB limit"));
        }
        let replacements = transform(originals)?;
        let replacement = replacements
            .first()
            .ok_or_else(|| invalid("paired replacement missing primary"))?;
        if replacement.len() as u64 > MAX_STORE {
            return Err(invalid("paired replacement exceeds 64 MiB limit"));
        }
        mirror.desired = Some(replacement.clone());
        Ok(replacements)
    })?;
    Ok(Prepared { primary, mirror })
}

fn load(backup: &Path, expected: &Path) -> io::Result<Option<Vec<u8>>> {
    plain_ancestors(backup).map_err(io::Error::other)?;
    let marker = backup.join(MARKER);
    plain_ancestors(&marker).map_err(io::Error::other)?;
    let mut bytes = Vec::new();
    File::open(marker)?.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(invalid("paired-store manifest too large"));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if value["version"] != 1
        || value["path"].as_str().map(Path::new) != Some(canonical(expected)?.as_path())
    {
        return Err(invalid("paired-store target/version mismatch"));
    }
    match value["original_exists"].as_bool() {
        Some(false)
            if value["original_sha256"].is_null() && !backup.join(ORIGINAL).try_exists()? =>
        {
            Ok(None)
        }
        Some(true) => {
            let path = backup.join(ORIGINAL);
            plain_ancestors(&path).map_err(io::Error::other)?;
            let bytes = read_mirror(&mut File::open(path)?)?;
            if value["original_sha256"].as_str() != Some(hash(&bytes).as_str()) {
                return Err(invalid("mirror backup checksum mismatch"));
            }
            Ok(Some(bytes))
        }
        _ => Err(invalid("invalid mirror existence state")),
    }
}
pub fn restore(
    backup: &Path,
    primary: &Path,
    secondary: &Path,
    mut validate: impl FnMut(&[u8]) -> io::Result<()>,
) -> Result<PathBuf, Failure> {
    let mut mirror = (|| {
        if backup.join(EXTRA_REQUIRED).try_exists()? {
            return Err(invalid("paired backup requires external-state recovery"));
        }
        if canonical(primary)? == canonical(secondary)? {
            return Err(invalid("paired store targets must differ"));
        }
        Mirror::capture(secondary, load(backup, secondary)?)
    })()
    .map_err(|e| Failure {
        cause: e.to_string(),
        backup: backup.into(),
        rollback_errors: vec![],
    })?;
    transaction::restore_participating(
        backup,
        &[primary.into()],
        |_, bytes| {
            if bytes.len() as u64 > MAX_STORE {
                return Err(invalid("paired primary backup exceeds 64 MiB limit"));
            }
            validate(bytes)
        },
        &mut mirror,
    )
}

/// Restore a paired primary plus additional files and external state. The caller
/// supplies fixed target paths and loads the external backup before calling.
pub fn restore_participating(
    backup: &Path,
    primary: &Path,
    secondary: &Path,
    additional: &[PathBuf],
    mut validate: impl FnMut(usize, &[u8]) -> io::Result<()>,
    extra: &mut dyn Participant,
) -> Result<PathBuf, Failure> {
    let (paths, mut mirror) = (|| {
        plain_ancestors(&backup.join(EXTRA_REQUIRED)).map_err(io::Error::other)?;
        let mut marker = Vec::new();
        File::open(backup.join(EXTRA_REQUIRED))?
            .take(3)
            .read_to_end(&mut marker)?;
        if marker != b"1\n" {
            return Err(invalid("invalid paired external-state marker"));
        }
        let mut paths = vec![canonical(primary)?];
        for path in additional {
            paths.push(canonical(path)?);
        }
        let secondary = canonical(secondary)?;
        if paths.contains(&secondary) {
            return Err(invalid("paired store targets must differ"));
        }
        let mirror = Mirror::capture(&secondary, load(backup, &secondary)?)?;
        Ok((paths, mirror))
    })()
    .map_err(|e: io::Error| Failure {
        cause: e.to_string(),
        backup: backup.into(),
        rollback_errors: vec![],
    })?;
    let mut participants = WithExtra(Participants::new(vec![&mut mirror, extra]));
    transaction::restore_participating(
        backup,
        &paths,
        |index, bytes| {
            if index == 0 && bytes.len() as u64 > MAX_STORE {
                return Err(invalid("paired primary backup exceeds 64 MiB limit"));
            }
            validate(index, bytes)
        },
        &mut participants,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Extra {
        value: u8,
        original: u8,
        desired: u8,
        fail_commit: bool,
        fail_rollback: bool,
    }
    impl Participant for Extra {
        fn prepare(&mut self, backup: &Path) -> io::Result<()> {
            save(&backup.join("test-state.original"), &[self.original])
        }
        fn commit(&mut self) -> io::Result<()> {
            self.value = self.desired;
            if self.fail_commit {
                Err(invalid("external commit failed"))
            } else {
                Ok(())
            }
        }
        fn rollback(&mut self) -> io::Result<()> {
            if self.fail_rollback {
                return Err(invalid("external rollback failed"));
            }
            self.value = self.original;
            Ok(())
        }
    }
    #[test]
    fn combined_files_and_external_state_restore_absent_mirror_and_support_undo() {
        let (_dir, primary, mirror) = files(false);
        let tokens = primary.with_file_name("tokens");
        fs::write(&tokens, b"tokens old").unwrap();
        let mut extra = Extra {
            value: 1,
            original: 1,
            desired: 2,
            fail_commit: false,
            fail_rollback: false,
        };
        let prepared = edit_files(&primary, &mirror, std::slice::from_ref(&tokens), |_| {
            Ok(vec![b"primary new".to_vec(), b"tokens new".to_vec()])
        })
        .unwrap();
        let backup = prepared.commit_participating(&mut extra).unwrap();
        assert_eq!(extra.value, 2);
        assert_eq!(fs::read(&mirror).unwrap(), b"primary new");
        assert_eq!(fs::read(backup.join("test-state.original")).unwrap(), [1]);
        let mut restore_extra = Extra {
            value: 2,
            original: 2,
            desired: 1,
            fail_commit: false,
            fail_rollback: false,
        };
        let mut validated = vec![];
        let undo = restore_participating(
            &backup,
            &primary,
            &mirror,
            std::slice::from_ref(&tokens),
            |index, bytes| {
                validated.push(index);
                assert_eq!(
                    bytes,
                    if index == 0 {
                        &b"primary old"[..]
                    } else {
                        &b"tokens old"[..]
                    }
                );
                Ok(())
            },
            &mut restore_extra,
        )
        .unwrap();
        assert_eq!(validated, [0, 1]);
        assert!(!mirror.exists());
        assert_eq!(restore_extra.value, 1);
        assert_eq!(fs::read(&tokens).unwrap(), b"tokens old");
        let mut redo = Extra {
            value: 1,
            original: 1,
            desired: 2,
            fail_commit: false,
            fail_rollback: false,
        };
        restore_participating(
            &undo,
            &primary,
            &mirror,
            std::slice::from_ref(&tokens),
            |_, _| Ok(()),
            &mut redo,
        )
        .unwrap();
        assert_eq!(fs::read(&primary).unwrap(), b"primary new");
        assert_eq!(fs::read(&mirror).unwrap(), b"primary new");
        assert_eq!(fs::read(&tokens).unwrap(), b"tokens new");
        assert_eq!(redo.value, 2);
    }
    #[test]
    fn external_failure_rolls_back_all_files_even_when_external_rollback_fails() {
        for fail_rollback in [false, true] {
            let (_dir, primary, mirror) = files(false);
            let tokens = primary.with_file_name("tokens");
            fs::write(&tokens, b"tokens old").unwrap();
            let mut extra = Extra {
                value: 1,
                original: 1,
                desired: 2,
                fail_commit: true,
                fail_rollback,
            };
            let transaction = edit_files(&primary, &mirror, std::slice::from_ref(&tokens), |_| {
                Ok(vec![b"new".to_vec(), b"new tokens".to_vec()])
            })
            .unwrap();
            let error = transaction.commit_participating(&mut extra).unwrap_err();
            assert!(error.cause.contains("external commit failed"));
            assert_eq!(error.rollback_errors.is_empty(), !fail_rollback);
            assert_eq!(extra.value, if fail_rollback { 2 } else { 1 });
            assert!(!mirror.exists());
            assert_eq!(fs::read(&primary).unwrap(), b"primary old");
            assert_eq!(fs::read(&tokens).unwrap(), b"tokens old");
        }
    }
    #[test]
    fn joint_backup_cannot_be_restored_without_its_external_participant() {
        let (_dir, primary, mirror) = files(false);
        let mut extra = Extra {
            value: 1,
            original: 1,
            desired: 2,
            fail_commit: false,
            fail_rollback: false,
        };
        let backup = edit(&primary, &mirror, |_| Ok(b"new".to_vec()))
            .unwrap()
            .commit_participating(&mut extra)
            .unwrap();
        assert!(
            restore(&backup, &primary, &mirror, |_| Ok(()))
                .unwrap_err()
                .cause
                .contains("external-state")
        );
        assert_eq!(fs::read(&primary).unwrap(), b"new");
        assert_eq!(fs::read(&mirror).unwrap(), b"new");
    }
    #[test]
    fn external_prepare_failure_never_changes_files_or_invokes_commit() {
        struct FailPrepare;
        impl Participant for FailPrepare {
            fn prepare(&mut self, _: &Path) -> io::Result<()> {
                Err(invalid("prepare failed"))
            }
            fn commit(&mut self) -> io::Result<()> {
                panic!("must not commit");
            }
            fn rollback(&mut self) -> io::Result<()> {
                panic!("must not roll back untouched state");
            }
        }
        let (_dir, primary, mirror) = files(false);
        let tokens = primary.with_file_name("tokens");
        fs::write(&tokens, b"tokens old").unwrap();
        let prepared = edit_files(&primary, &mirror, std::slice::from_ref(&tokens), |_| {
            Ok(vec![b"new".to_vec(), b"new".to_vec()])
        })
        .unwrap();
        assert!(
            prepared
                .commit_participating(&mut FailPrepare)
                .unwrap_err()
                .cause
                .contains("prepare failed")
        );
        assert!(!mirror.exists());
        assert_eq!(fs::read(&primary).unwrap(), b"primary old");
        assert_eq!(fs::read(&tokens).unwrap(), b"tokens old");
    }
    #[test]
    fn additional_target_cannot_alias_mirror_and_missing_outputs_do_not_write() {
        let (_dir, primary, mirror) = files(true);
        assert!(
            edit_files(
                &primary,
                &mirror,
                std::slice::from_ref(&mirror),
                |_| unreachable!()
            )
            .is_err()
        );
        assert!(edit_files(&primary, &mirror, &[], |_| Ok(vec![])).is_err());
        assert_eq!(fs::read(&primary).unwrap(), b"primary old");
        assert_eq!(fs::read(&mirror).unwrap(), b"mirror old");
    }
    fn files(secondary: bool) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("primary");
        let mirror = dir.path().join("mirror");
        fs::write(&primary, b"primary old").unwrap();
        if secondary {
            fs::write(&mirror, b"mirror old").unwrap();
        }
        (dir, primary, mirror)
    }
    #[test]
    fn creates_missing_mirror_and_restore_reinstates_absence_then_undo_restores_both() {
        let (_dir, primary, mirror) = files(false);
        let prepared = edit(&primary, &mirror, |_| Ok(b"new".to_vec())).unwrap();
        assert!(prepared.backup_path().join("manifest.json").is_file());
        assert!(!mirror.exists());
        let backup = prepared.commit().unwrap();
        assert_eq!(fs::read(&primary).unwrap(), b"new");
        assert_eq!(fs::read(&mirror).unwrap(), b"new");
        assert!(
            transaction::restore_validated(&backup, std::slice::from_ref(&primary), |_, _| Ok(()))
                .is_err()
        );
        let undo = restore(&backup, &primary, &mirror, |bytes| {
            assert_eq!(bytes, b"primary old");
            Ok(())
        })
        .unwrap();
        assert_eq!(fs::read(&primary).unwrap(), b"primary old");
        assert!(!mirror.exists());
        restore(&undo, &primary, &mirror, |_| Ok(())).unwrap();
        assert_eq!(fs::read(&primary).unwrap(), b"new");
        assert_eq!(fs::read(&mirror).unwrap(), b"new");
    }
    #[test]
    fn restores_distinct_existing_originals_and_rejects_corrupt_mirror_backup() {
        let (_dir, primary, mirror) = files(true);
        let backup = edit(&primary, &mirror, |_| Ok(b"new".to_vec()))
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(fs::read(backup.join(ORIGINAL)).unwrap(), b"mirror old");
        fs::write(backup.join(ORIGINAL), b"corrupt").unwrap();
        assert!(
            restore(&backup, &primary, &mirror, |_| Ok(()))
                .unwrap_err()
                .cause
                .contains("checksum")
        );
        assert_eq!(fs::read(&primary).unwrap(), b"new");
        assert_eq!(fs::read(&mirror).unwrap(), b"new");
        fs::write(backup.join(ORIGINAL), b"mirror old").unwrap();
        restore(&backup, &primary, &mirror, |_| Ok(())).unwrap();
        assert_eq!(fs::read(primary).unwrap(), b"primary old");
        assert_eq!(fs::read(mirror).unwrap(), b"mirror old");
    }
    #[test]
    fn manifest_target_and_absent_state_are_validated_before_restore() {
        let (dir, primary, mirror) = files(false);
        let backup = edit(&primary, &mirror, |_| Ok(b"new".to_vec()))
            .unwrap()
            .commit()
            .unwrap();
        let marker = backup.join(MARKER);
        let original = fs::read(&marker).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        value["path"] = dir
            .path()
            .join("unrelated")
            .to_string_lossy()
            .into_owned()
            .into();
        fs::write(&marker, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(
            restore(&backup, &primary, &mirror, |_| Ok(()))
                .unwrap_err()
                .cause
                .contains("mismatch")
        );
        assert!(!dir.path().join("unrelated").exists());
        fs::write(marker, original).unwrap();
        fs::write(backup.join(ORIGINAL), b"ambiguous").unwrap();
        assert!(restore(&backup, &primary, &mirror, |_| Ok(())).is_err());
        assert_eq!(fs::read(primary).unwrap(), b"new");
        assert_eq!(fs::read(mirror).unwrap(), b"new");
    }
    struct FailAfter(Mirror);
    impl Participant for FailAfter {
        fn prepare(&mut self, backup: &Path) -> io::Result<()> {
            self.0.prepare(backup)
        }
        fn commit(&mut self) -> io::Result<()> {
            self.0.commit()?;
            Err(invalid("failure after mirror mutation"))
        }
        fn rollback(&mut self) -> io::Result<()> {
            self.0.rollback()
        }
    }
    #[test]
    fn failure_after_create_restores_primary_and_removes_only_created_mirror() {
        let (_dir, primary, mirror) = files(false);
        let prepared = edit(&primary, &mirror, |_| Ok(b"new".to_vec())).unwrap();
        let mut failing = FailAfter(prepared.mirror);
        let error = prepared
            .primary
            .commit_participating(&mut failing)
            .unwrap_err();
        assert!(error.rollback_errors.is_empty());
        drop(failing);
        assert_eq!(fs::read(primary).unwrap(), b"primary old");
        assert!(!mirror.exists());
    }
    #[test]
    fn failure_after_delete_restores_file_existence_contents_and_primary() {
        let (_dir, primary, mirror) = files(true);
        let mut failing = FailAfter(Mirror::capture(&mirror, None).unwrap());
        let txn = Transaction::prepare(vec![(primary.clone(), b"new".to_vec())]).unwrap();
        let error = txn.commit_participating(&mut failing).unwrap_err();
        assert!(error.rollback_errors.is_empty());
        drop(failing);
        assert_eq!(fs::read(primary).unwrap(), b"primary old");
        assert_eq!(fs::read(mirror).unwrap(), b"mirror old");
    }
    #[test]
    fn concurrent_creation_or_invalid_target_never_overwrites_other_files() {
        let (_dir, primary, mirror) = files(false);
        let prepared = edit(&primary, &mirror, |_| Ok(b"new".to_vec())).unwrap();
        fs::write(&mirror, b"someone else").unwrap();
        assert!(prepared.commit().unwrap_err().cause.contains("changed"));
        assert_eq!(fs::read(&primary).unwrap(), b"primary old");
        assert_eq!(fs::read(&mirror).unwrap(), b"someone else");
        assert!(edit(&primary, &primary, |_| Ok(vec![])).is_err());
    }
}
