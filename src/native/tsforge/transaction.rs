//! Durable backups and recoverable, in-place store writes (preserves file ACLs).
//! Caller must stop SPP and hold the application-wide licensing mutex throughout.
//! A process/power failure is not an atomic multi-file commit: the journal and
//! backups are intentionally retained for explicit recovery on the next run.
use super::binary::invalid;
use crate::native::hook_files::plain_ancestors;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

const MAX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILES: usize = 16;

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}
fn read_all(file: &mut File) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid("store exceeds supported 256 MiB limit"));
    }
    Ok(bytes)
}
fn write_all(file: &mut File, bytes: &[u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    file.write_all(bytes)?;
    file.set_len(bytes.len() as u64)?;
    file.sync_all()?;
    if read_all(file)? != bytes {
        return Err(invalid("store readback differs from written bytes"));
    }
    Ok(())
}
fn open_target(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(invalid("store path must be absolute"));
    }
    plain_ancestors(path).map_err(io::Error::other)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0).custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > MAX_BYTES {
        return Err(invalid("unsupported store file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return Err(invalid("store has hard links"));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::{fs::MetadataExt, io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        if meta.file_attributes() & 0x400 != 0 {
            return Err(invalid("store is a reparse point"));
        }
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.nNumberOfLinks != 1 {
            return Err(invalid("store has hard links"));
        }
    }
    Ok(file)
}
fn save(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    } // Windows backup files themselves use FlushFileBuffers via sync_all.
    Ok(())
}

struct Target {
    path: PathBuf,
    file: File,
    original: Vec<u8>,
    replacement: Vec<u8>,
}

pub struct Transaction {
    targets: Vec<Target>,
    backup: PathBuf,
    journal: File,
}

/// Non-file state participating in a store transaction (for example registry
/// values). Preparation must durably save its originals in `backup`, validate
/// current state, and never modify live state. Commit and rollback must verify
/// their writes. Caller holds the licensing mutex and keeps SPP stopped.
pub trait Participant {
    fn prepare(&mut self, backup: &Path) -> io::Result<()>;
    fn commit(&mut self) -> io::Result<()>;
    /// Must handle a partially failed commit and attempt every touched target.
    fn rollback(&mut self) -> io::Result<()>;
}

#[derive(Debug, thiserror::Error)]
#[error("{cause}; backup: {backup}; rollback errors: {rollback_errors:?}")]
pub struct Failure {
    pub cause: String,
    pub backup: PathBuf,
    pub rollback_errors: Vec<String>,
}

impl Transaction {
    /// Explicit replacement (used by recovery). For read/modify/write, use edit.
    pub fn prepare(plan: Vec<(PathBuf, Vec<u8>)>) -> io::Result<Self> {
        let (paths, replacements): (Vec<_>, Vec<_>) = plan.into_iter().unzip();
        Self::edit(paths, |_| Ok(replacements))
    }
    /// Acquire all file handles before decoding or transforming any store. The
    /// callback must validate every resulting format before returning replacements.
    pub fn edit(
        paths: Vec<PathBuf>,
        transform: impl FnOnce(&[&[u8]]) -> io::Result<Vec<Vec<u8>>>,
    ) -> io::Result<Self> {
        if paths.is_empty() || paths.len() > MAX_FILES {
            return Err(invalid("invalid store transaction file count"));
        }
        let mut targets = Vec::new();
        let mut seen = HashSet::new();
        let mut total = 0u64;
        for path in paths {
            if !path.is_absolute() {
                return Err(invalid("store path must be absolute"));
            }
            plain_ancestors(&path).map_err(io::Error::other)?;
            let path = fs::canonicalize(path)?;
            if !seen.insert(path.clone()) {
                return Err(invalid("duplicate transaction target"));
            }
            let mut file = open_target(&path)?;
            let original = read_all(&mut file)?;
            total += original.len() as u64;
            if total > MAX_BYTES {
                return Err(invalid("transaction exceeds supported 256 MiB total limit"));
            }
            targets.push(Target {
                path,
                file,
                original,
                replacement: Vec::new(),
            });
        }
        let originals: Vec<_> = targets
            .iter()
            .map(|target| target.original.as_slice())
            .collect();
        let replacements = transform(&originals)?;
        if replacements.len() != targets.len() {
            return Err(invalid("transform returned wrong file count"));
        }
        for (target, replacement) in targets.iter_mut().zip(replacements) {
            total = total
                .checked_add(replacement.len() as u64)
                .ok_or_else(|| invalid("store transaction size overflow"))?;
            if total > MAX_BYTES {
                return Err(invalid("transaction exceeds supported 256 MiB total limit"));
            }
            target.replacement = replacement;
        }
        let directory = tempfile::Builder::new()
            .prefix("mas-rust-store-backup-")
            .tempdir_in(
                targets[0]
                    .path
                    .parent()
                    .ok_or_else(|| invalid("store has no parent"))?,
            )?;
        let mut manifest = Vec::new();
        for (index, target) in targets.iter().enumerate() {
            let path = target
                .path
                .to_str()
                .ok_or_else(|| invalid("store path is not Unicode"))?;
            save(
                &directory.path().join(format!("{index}.original")),
                &target.original,
            )?;
            save(
                &directory.path().join(format!("{index}.replacement")),
                &target.replacement,
            )?;
            manifest.push(serde_json::json!({"path": path, "original_sha256": digest(&target.original), "replacement_sha256": digest(&target.replacement)}));
        }
        save(
            &directory.path().join("manifest.json"),
            &serde_json::to_vec_pretty(&serde_json::json!({"version": 1, "files": manifest}))?,
        )?;
        let mut journal = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.path().join("journal.txt"))?;
        journal.write_all(b"prepared\n")?;
        journal.sync_all()?;
        sync_directory(directory.path())?;
        let backup = directory.keep();
        sync_directory(backup.parent().unwrap())?;
        Ok(Self {
            targets,
            backup,
            journal,
        })
    }
    fn record(&mut self, text: &str) -> io::Result<()> {
        writeln!(self.journal, "{text}")?;
        self.journal.sync_all()
    }
    pub fn backup_path(&self) -> &Path {
        &self.backup
    }
    /// Persist both backups without modifying live state, then release file
    /// handles so licensing APIs can run. Used before uninstalling old keys.
    #[allow(dead_code)]
    pub fn checkpoint(mut self, participant: &mut dyn Participant) -> io::Result<PathBuf> {
        save(&self.backup.join("external-state-required"), b"1\n")?;
        participant.prepare(&self.backup)?;
        sync_directory(&self.backup)?;
        self.record("checkpoint-no-live-writes")?;
        Ok(self.backup)
    }
    pub fn commit(self) -> Result<PathBuf, Failure> {
        self.commit_with(|_, _, _| Ok(()))
    }
    #[allow(dead_code)] // Registry participant is being connected to installation.
    pub fn commit_participating(
        self,
        participant: &mut dyn Participant,
    ) -> Result<PathBuf, Failure> {
        self.commit_coordinated(Some(participant), |_, _, _| Ok(()))
    }
    /// Fault injection at each mutation boundary also exercises partial writes.
    fn commit_with(
        self,
        before: impl FnMut(usize, bool, &mut File) -> io::Result<()>,
    ) -> Result<PathBuf, Failure> {
        self.commit_coordinated(None, before)
    }
    fn commit_coordinated(
        mut self,
        mut participant: Option<&mut dyn Participant>,
        mut before: impl FnMut(usize, bool, &mut File) -> io::Result<()>,
    ) -> Result<PathBuf, Failure> {
        let mut touched = 0;
        let mut participant_touched = false;
        let result = (|| {
            // Detect changes between preparation and commit before modifying any file.
            for target in &mut self.targets {
                if read_all(&mut target.file)? != target.original {
                    return Err(invalid("store changed after preparation"));
                }
            }
            if let Some(extra) = participant.as_mut() {
                // Prevent the file-only recovery entry point from presenting a
                // partial compound restore as a complete recovery.
                save(&self.backup.join("external-state-required"), b"1\n")?;
                sync_directory(&self.backup)?;
                extra.prepare(&self.backup)?;
                sync_directory(&self.backup)?;
                self.record("participant-prepared")?;
            }
            self.record("writing")?;
            for index in 0..self.targets.len() {
                self.record(&format!("write {index}"))?;
                touched = index + 1;
                let target = &mut self.targets[index];
                before(index, false, &mut target.file)?;
                write_all(&mut target.file, &target.replacement)?;
            }
            if let Some(extra) = participant.as_mut() {
                self.record("participant-writing")?;
                participant_touched = true;
                extra.commit()?;
            }
            self.record("committed")
        })();
        if let Err(cause) = result {
            let mut rollback_errors = Vec::new();
            if participant_touched
                && let Some(extra) = participant.as_mut()
                && let Err(error) = extra.rollback()
            {
                rollback_errors.push(format!("participant: {error}"));
            }
            for index in (0..touched).rev() {
                let target = &mut self.targets[index];
                if let Err(error) = before(index, true, &mut target.file)
                    .and_then(|_| write_all(&mut target.file, &target.original))
                {
                    rollback_errors.push(format!("{}: {error}", target.path.display()));
                }
            }
            let state = if touched == 0 {
                "aborted-before-write"
            } else if rollback_errors.is_empty() {
                "aborted-originals-restored"
            } else {
                "recovery-required"
            };
            if let Err(error) = self.record(state) {
                rollback_errors.push(format!("journal: {error}"));
            }
            return Err(Failure {
                cause: cause.to_string(),
                backup: self.backup,
                rollback_errors,
            });
        }
        Ok(self.backup)
    }
}

/// Recovery never trusts manifest paths alone: the caller supplies exactly the
/// expected targets. Validate every backup first, then back up current state and
/// restore through a new transaction (so a failed recovery can also roll back).
#[cfg(test)]
pub fn restore(backup: &Path, expected: &[PathBuf]) -> Result<PathBuf, Failure> {
    restore_validated(backup, expected, |_, _| Ok(()))
}

pub fn restore_validated(
    backup: &Path,
    expected: &[PathBuf],
    validate: impl FnMut(usize, &[u8]) -> io::Result<()>,
) -> Result<PathBuf, Failure> {
    prepare_restore(backup, expected, validate, false)?.commit()
}

/// Caller must load and validate the external backup into the participant first.
/// The returned backup contains the pre-recovery state of both resource types.
#[allow(dead_code)] // Installation/recovery runtime integration is in progress.
pub fn restore_participating(
    backup: &Path,
    expected: &[PathBuf],
    validate: impl FnMut(usize, &[u8]) -> io::Result<()>,
    participant: &mut dyn Participant,
) -> Result<PathBuf, Failure> {
    prepare_restore(backup, expected, validate, true)?.commit_participating(participant)
}

fn prepare_restore(
    backup: &Path,
    expected: &[PathBuf],
    mut validate: impl FnMut(usize, &[u8]) -> io::Result<()>,
    external: bool,
) -> Result<Transaction, Failure> {
    let mut prepare = || -> io::Result<Transaction> {
        plain_ancestors(backup).map_err(io::Error::other)?;
        let marker = backup.join("external-state-required");
        if marker.try_exists()? != external {
            return Err(invalid(
                "backup external state mismatch; coordinated recovery required",
            ));
        }
        if external {
            plain_ancestors(&marker).map_err(io::Error::other)?;
            let mut version = Vec::new();
            File::open(marker)?.take(3).read_to_end(&mut version)?;
            if version != b"1\n" {
                return Err(invalid("unsupported external backup marker"));
            }
        }
        let manifest_path = backup.join("manifest.json");
        plain_ancestors(&manifest_path).map_err(io::Error::other)?;
        let mut bytes = Vec::new();
        File::open(manifest_path)?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 1024 * 1024 {
            return Err(invalid("backup manifest too large"));
        }
        let manifest: serde_json::Value = serde_json::from_slice(&bytes)?;
        if manifest["version"] != 1 {
            return Err(invalid("unsupported backup manifest version"));
        }
        let files = manifest["files"]
            .as_array()
            .ok_or_else(|| invalid("invalid backup file list"))?;
        if files.len() != expected.len() || files.is_empty() || files.len() > MAX_FILES {
            return Err(invalid("backup target count mismatch"));
        }
        let mut plan = Vec::new();
        let mut total = 0;
        for (index, (entry, expected)) in files.iter().zip(expected).enumerate() {
            plain_ancestors(expected).map_err(io::Error::other)?;
            let expected = fs::canonicalize(expected)?;
            let target = entry["path"]
                .as_str()
                .ok_or_else(|| invalid("invalid backup target path"))?;
            if Path::new(target) != expected {
                return Err(invalid(
                    "backup target differs from explicitly selected target",
                ));
            }
            let path = backup.join(format!("{index}.original"));
            plain_ancestors(&path).map_err(io::Error::other)?;
            let original = read_all(&mut File::open(path)?)?;
            if entry["original_sha256"].as_str() != Some(digest(&original).as_str()) {
                return Err(invalid("backup checksum mismatch"));
            }
            total += original.len() as u64;
            if total > MAX_BYTES {
                return Err(invalid("backup set exceeds supported size"));
            }
            validate(index, &original)?;
            plan.push((expected, original));
        }
        Transaction::prepare(plan)
    };
    prepare().map_err(|error| Failure {
        cause: error.to_string(),
        backup: backup.to_path_buf(),
        rollback_errors: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn stores() -> (tempfile::TempDir, Vec<PathBuf>) {
        let dir = tempfile::tempdir().unwrap();
        let paths = vec![dir.path().join("data.dat"), dir.path().join("tokens.dat")];
        for (index, path) in paths.iter().enumerate() {
            fs::write(path, format!("original-{index}")).unwrap();
        }
        (dir, paths)
    }
    fn plan(paths: &[PathBuf]) -> Vec<(PathBuf, Vec<u8>)> {
        paths
            .iter()
            .enumerate()
            .map(|(i, p)| (p.clone(), vec![i as u8; i * 19]))
            .collect()
    }
    fn assert_original(paths: &[PathBuf]) {
        for (index, path) in paths.iter().enumerate() {
            assert_eq!(
                fs::read(path).unwrap(),
                format!("original-{index}").as_bytes()
            );
        }
    }
    #[derive(Default)]
    struct ExtraState {
        value: u32,
        fail_prepare: bool,
        fail_commit: bool,
        fail_rollback: bool,
        calls: Vec<&'static str>,
        backup: PathBuf,
    }
    impl Participant for ExtraState {
        fn prepare(&mut self, backup: &Path) -> io::Result<()> {
            self.calls.push("prepare");
            if self.fail_prepare {
                return Err(invalid("participant preparation failed"));
            }
            self.backup = backup.into();
            save(&backup.join("extra.original"), &self.value.to_le_bytes())
        }
        fn commit(&mut self) -> io::Result<()> {
            self.calls.push("commit");
            let journal = fs::read_to_string(self.backup.join("journal.txt"))?;
            assert!(journal.ends_with("participant-writing\n"));
            assert!(self.backup.join("extra.original").is_file());
            self.value = 42; // Partial mutation occurs before the injected failure.
            if self.fail_commit {
                Err(invalid("participant commit failed"))
            } else {
                Ok(())
            }
        }
        fn rollback(&mut self) -> io::Result<()> {
            self.calls.push("rollback");
            if self.fail_rollback {
                return Err(invalid("participant rollback failed"));
            }
            self.value = u32::from_le_bytes(
                fs::read(self.backup.join("extra.original"))?
                    .try_into()
                    .unwrap(),
            );
            Ok(())
        }
    }
    #[test]
    fn compound_success_keeps_external_backup_and_prevents_file_only_recovery() {
        let (_dir, paths) = stores();
        let mut extra = ExtraState::default();
        let backup = Transaction::prepare(plan(&paths))
            .unwrap()
            .commit_participating(&mut extra)
            .unwrap();
        assert_eq!(extra.calls, ["prepare", "commit"]);
        assert_eq!(extra.value, 42);
        assert_eq!(fs::read(backup.join("extra.original")).unwrap(), [0; 4]);
        let error = restore(&backup, &paths).unwrap_err();
        assert!(error.cause.contains("coordinated recovery required"));
        assert_eq!(fs::read(&paths[0]).unwrap(), b"");
        assert_eq!(extra.value, 42);
    }
    #[test]
    fn compound_recovery_validates_files_before_preparing_external_state() {
        let (_dir, paths) = stores();
        let mut installed = ExtraState::default();
        let backup = Transaction::prepare(plan(&paths))
            .unwrap()
            .commit_participating(&mut installed)
            .unwrap();
        let mut recovery = ExtraState::default();
        let error = restore_participating(
            &backup,
            &paths,
            |index, _| {
                if index == 1 {
                    Err(invalid("second backup is invalid"))
                } else {
                    Ok(())
                }
            },
            &mut recovery,
        )
        .unwrap_err();
        assert!(error.cause.contains("second backup is invalid"));
        assert!(recovery.calls.is_empty());
        assert_eq!(fs::read(&paths[0]).unwrap(), b"");
        assert_eq!(fs::read(&paths[1]).unwrap(), vec![1; 19]);
        fs::write(backup.join("external-state-required"), b"2\n").unwrap();
        assert!(restore_participating(&backup, &paths, |_, _| Ok(()), &mut recovery).is_err());
        assert!(recovery.calls.is_empty());
    }
    #[test]
    fn failed_compound_recovery_rolls_files_back_to_pre_recovery_state() {
        let (_dir, paths) = stores();
        let mut installed = ExtraState::default();
        let backup = Transaction::prepare(plan(&paths))
            .unwrap()
            .commit_participating(&mut installed)
            .unwrap();
        let mut recovery = ExtraState {
            fail_commit: true,
            ..Default::default()
        };
        let error =
            restore_participating(&backup, &paths, |_, _| Ok(()), &mut recovery).unwrap_err();
        assert!(error.rollback_errors.is_empty());
        assert_eq!(recovery.calls, ["prepare", "commit", "rollback"]);
        assert_eq!(fs::read(&paths[0]).unwrap(), b"");
        assert_eq!(fs::read(&paths[1]).unwrap(), vec![1; 19]);
        assert_eq!(fs::read(error.backup.join("0.original")).unwrap(), b"");
    }
    #[test]
    fn checkpoint_prepares_both_backups_without_mutating_live_state() {
        let (_dir, paths) = stores();
        let mut extra = ExtraState::default();
        let backup = Transaction::prepare(plan(&paths))
            .unwrap()
            .checkpoint(&mut extra)
            .unwrap();
        assert_original(&paths);
        assert_eq!(extra.calls, ["prepare"]);
        assert_eq!(extra.value, 0);
        assert_eq!(fs::read(backup.join("extra.original")).unwrap(), [0; 4]);
        assert!(
            fs::read_to_string(backup.join("journal.txt"))
                .unwrap()
                .ends_with("checkpoint-no-live-writes\n")
        );
    }
    #[test]
    fn participant_preparation_failure_changes_no_live_state() {
        let (_dir, paths) = stores();
        let mut extra = ExtraState {
            fail_prepare: true,
            ..Default::default()
        };
        let error = Transaction::prepare(plan(&paths))
            .unwrap()
            .commit_participating(&mut extra)
            .unwrap_err();
        assert_eq!(extra.calls, ["prepare"]);
        assert_eq!(extra.value, 0);
        assert!(error.rollback_errors.is_empty());
        assert_original(&paths);
    }
    #[test]
    fn partial_participant_failure_rolls_back_external_state_then_both_files() {
        let (_dir, paths) = stores();
        let mut extra = ExtraState {
            fail_commit: true,
            ..Default::default()
        };
        let error = Transaction::prepare(plan(&paths))
            .unwrap()
            .commit_participating(&mut extra)
            .unwrap_err();
        assert_eq!(extra.calls, ["prepare", "commit", "rollback"]);
        assert_eq!(extra.value, 0);
        assert!(error.rollback_errors.is_empty());
        assert_original(&paths);
        assert!(
            fs::read_to_string(error.backup.join("journal.txt"))
                .unwrap()
                .ends_with("aborted-originals-restored\n")
        );
    }
    #[test]
    fn participant_rollback_failure_still_restores_files_and_reports_recovery_required() {
        let (_dir, paths) = stores();
        let mut extra = ExtraState {
            fail_commit: true,
            fail_rollback: true,
            ..Default::default()
        };
        let error = Transaction::prepare(plan(&paths))
            .unwrap()
            .commit_participating(&mut extra)
            .unwrap_err();
        assert_eq!(error.rollback_errors.len(), 1);
        assert!(error.rollback_errors[0].contains("participant rollback failed"));
        assert_original(&paths);
        assert_eq!(extra.value, 42);
        assert!(
            fs::read_to_string(error.backup.join("journal.txt"))
                .unwrap()
                .ends_with("recovery-required\n")
        );
    }
    #[test]
    fn file_failure_never_commits_prepared_external_state() {
        let (_dir, paths) = stores();
        let mut extra = ExtraState::default();
        let error = Transaction::prepare(plan(&paths))
            .unwrap()
            .commit_coordinated(Some(&mut extra), |index, rollback, file| {
                if index == 1 && !rollback {
                    file.write_all(b"partial")?;
                    return Err(invalid("file failure before registry"));
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(extra.calls, ["prepare"]);
        assert_eq!(extra.value, 0);
        assert!(error.rollback_errors.is_empty());
        assert_original(&paths);
    }
    #[test]
    fn commits_durable_backups_and_explicit_restore_preserves_previous_state() {
        let (_dir, paths) = stores();
        let tx = Transaction::prepare(plan(&paths)).unwrap();
        let backup = tx.backup_path().to_path_buf();
        assert_eq!(fs::read(backup.join("0.original")).unwrap(), b"original-0");
        tx.commit().unwrap();
        assert_eq!(fs::read(&paths[0]).unwrap(), b"");
        assert_eq!(fs::read(&paths[1]).unwrap(), vec![1; 19]);
        assert!(
            fs::read_to_string(backup.join("journal.txt"))
                .unwrap()
                .ends_with("committed\n")
        );
        let undo = restore(&backup, &paths).unwrap();
        assert_original(&paths);
        // Recovery itself retains the previous (modified) state for undo.
        assert_eq!(fs::read(undo.join("0.original")).unwrap(), b"");
        assert_eq!(fs::read(undo.join("1.original")).unwrap(), vec![1; 19]);
    }
    #[test]
    fn partial_second_write_rolls_back_both_files() {
        let (_dir, paths) = stores();
        let error = Transaction::prepare(plan(&paths))
            .unwrap()
            .commit_with(|index, rollback, file| {
                if index == 1 && !rollback {
                    file.seek(SeekFrom::Start(0))?;
                    file.write_all(b"partially modified")?;
                    return Err(io::Error::other("injected disk failure"));
                }
                Ok(())
            })
            .unwrap_err();
        assert!(error.rollback_errors.is_empty());
        assert_original(&paths);
        assert!(error.backup.join("1.original").exists());
    }
    #[test]
    fn failed_rollback_keeps_backups_for_explicit_recovery() {
        let (_dir, paths) = stores();
        let error = Transaction::prepare(plan(&paths))
            .unwrap()
            .commit_with(|index, rollback, _| {
                if (index == 1 && !rollback) || (index == 0 && rollback) {
                    return Err(io::Error::other("injected failure"));
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.rollback_errors.len(), 1);
        assert!(
            fs::read_to_string(error.backup.join("journal.txt"))
                .unwrap()
                .ends_with("recovery-required\n")
        );
        restore(&error.backup, &paths).unwrap();
        assert_original(&paths);
    }
    #[test]
    fn invalid_second_target_never_modifies_first() {
        let (_dir, paths) = stores();
        let mut changes = plan(&paths);
        changes[1].0 = paths[1].with_file_name("missing.dat");
        assert!(Transaction::prepare(changes).is_err());
        assert_original(&paths);
        assert!(
            Transaction::prepare(vec![
                (paths[0].clone(), vec![]),
                (paths[0].clone(), vec![1])
            ])
            .is_err()
        );
        assert_original(&paths);
    }
    #[test]
    fn corrupt_backup_or_wrong_target_prevents_any_restore_write() {
        let (_dir, paths) = stores();
        let backup = Transaction::prepare(plan(&paths))
            .unwrap()
            .commit()
            .unwrap();
        assert!(restore(&backup, &[paths[1].clone(), paths[0].clone()]).is_err());
        fs::write(backup.join("1.original"), b"corrupt").unwrap();
        assert!(restore(&backup, &paths).is_err());
        assert_eq!(fs::read(&paths[0]).unwrap(), b"");
        assert_eq!(fs::read(&paths[1]).unwrap(), vec![1; 19]);
    }
    #[test]
    fn transformation_uses_locked_originals_and_validation_failure_changes_nothing() {
        let (_dir, paths) = stores();
        assert!(Transaction::edit(paths.clone(), |_| Err(invalid("codec rejected data"))).is_err());
        assert!(Transaction::edit(paths.clone(), |_| Ok(vec![])).is_err());
        assert_original(&paths);
        Transaction::edit(paths.clone(), |originals| {
            assert_eq!(
                originals,
                &[b"original-0".as_slice(), b"original-1".as_slice()]
            );
            Ok(originals
                .iter()
                .map(|bytes| [*bytes, b"-edited"].concat())
                .collect())
        })
        .unwrap()
        .commit()
        .unwrap();
        assert_eq!(fs::read(&paths[0]).unwrap(), b"original-0-edited");
        assert_eq!(fs::read(&paths[1]).unwrap(), b"original-1-edited");
    }
    #[test]
    fn codec_rejection_of_any_backup_prevents_all_restore_writes() {
        let (_dir, paths) = stores();
        let backup = Transaction::prepare(plan(&paths))
            .unwrap()
            .commit()
            .unwrap();
        let mut checked = Vec::new();
        let result = restore_validated(&backup, &paths, |index, bytes| {
            checked.push(index);
            assert_eq!(bytes, format!("original-{index}").as_bytes());
            if index == 1 {
                Err(invalid("invalid encrypted store"))
            } else {
                Ok(())
            }
        });
        assert!(result.is_err());
        assert_eq!(checked, [0, 1]);
        assert_eq!(fs::read(&paths[0]).unwrap(), b"");
        assert_eq!(fs::read(&paths[1]).unwrap(), vec![1; 19]);
    }
    #[test]
    fn dropping_prepared_transaction_is_read_only() {
        let (_dir, paths) = stores();
        let tx = Transaction::prepare(plan(&paths)).unwrap();
        let backup = tx.backup_path().to_path_buf();
        drop(tx);
        assert_original(&paths);
        assert_eq!(
            fs::read_to_string(backup.join("journal.txt")).unwrap(),
            "prepared\n"
        );
    }
    #[test]
    fn rejects_hard_link_targets() {
        let (dir, paths) = stores();
        fs::hard_link(&paths[0], dir.path().join("alias.dat")).unwrap();
        assert!(Transaction::prepare(plan(&paths)).is_err());
        assert_original(&paths);
    }
    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_and_detects_changed_files_without_overwriting_them() {
        use std::os::unix::fs::symlink;
        let (dir, paths) = stores();
        let alias = dir.path().join("alias.dat");
        symlink(&paths[0], &alias).unwrap();
        assert!(Transaction::prepare(vec![(alias, vec![])]).is_err());
        let tx = Transaction::prepare(plan(&paths)).unwrap();
        fs::write(&paths[0], b"external change").unwrap();
        let error = tx.commit().unwrap_err();
        assert!(error.rollback_errors.is_empty());
        assert_eq!(fs::read(&paths[0]).unwrap(), b"external change");
        assert_eq!(fs::read(&paths[1]).unwrap(), b"original-1");
    }
    #[cfg(windows)]
    #[test]
    fn windows_exclusive_handles_prevent_concurrent_writers() {
        let (_dir, paths) = stores();
        let tx = Transaction::prepare(plan(&paths)).unwrap();
        assert!(OpenOptions::new().write(true).open(&paths[0]).is_err());
        drop(tx);
        assert!(OpenOptions::new().write(true).open(&paths[0]).is_ok());
    }
}
