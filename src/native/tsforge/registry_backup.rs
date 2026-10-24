//! Registry participant for compound licensing transactions. Logical IDs are
//! resolved by the caller; a backup never supplies an arbitrary registry path.
use super::{binary::invalid, transaction::Participant};
use crate::native::registry::{Key, RawValue};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

pub struct Edit<'a> {
    pub id: &'a str,
    pub key: &'a Key,
    pub name: &'a str,
    pub replacement: Option<RawValue>,
}
struct Saved<'a> {
    edit: Edit<'a>,
    original: Option<RawValue>,
}
#[allow(dead_code)] // Connected to the installer after coordinated recovery is ready.
pub struct RegistryValues<'a> {
    values: Vec<Saved<'a>>,
    touched: usize,
    prepared: bool,
}
#[allow(dead_code)]
impl<'a> RegistryValues<'a> {
    pub fn capture(edits: Vec<Edit<'a>>) -> io::Result<Self> {
        if edits.is_empty() || edits.len() > 32 {
            return Err(invalid("invalid registry edit count"));
        }
        let mut ids = HashSet::new();
        let mut total = 0usize;
        let mut values = Vec::new();
        for edit in edits {
            if edit.id.is_empty()
                || edit.id.len() > 256
                || edit.id.contains('\0')
                || !ids.insert(edit.id)
            {
                return Err(invalid("invalid or duplicate registry backup ID"));
            }
            let original = edit.key.raw_value(edit.name).map_err(io::Error::other)?;
            for value in original.iter().chain(edit.replacement.iter()) {
                value.validate_write().map_err(io::Error::other)?;
            }
            total += original.as_ref().map_or(0, |v| v.bytes.len())
                + edit.replacement.as_ref().map_or(0, |v| v.bytes.len());
            if total > 16 * 1024 * 1024 {
                return Err(invalid("registry backup exceeds 16 MiB"));
            }
            values.push(Saved { edit, original });
        }
        Ok(Self {
            values,
            touched: 0,
            prepared: false,
        })
    }
    fn unchanged(&self) -> io::Result<()> {
        for saved in &self.values {
            if saved
                .edit
                .key
                .raw_value(saved.edit.name)
                .map_err(io::Error::other)?
                != saved.original
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("registry value changed: {}", saved.edit.id),
                ));
            }
        }
        Ok(())
    }
}
#[allow(dead_code)] // Used by the staged participant implementation.
fn encode(value: &Option<RawValue>) -> serde_json::Value {
    match value {
        Some(v) => serde_json::json!({"type": v.kind, "base64": STANDARD.encode(&v.bytes)}),
        None => serde_json::Value::Null,
    }
}
impl Participant for RegistryValues<'_> {
    fn prepare(&mut self, backup: &Path) -> io::Result<()> {
        if self.prepared {
            return Err(invalid("registry participant already prepared"));
        }
        self.unchanged()?;
        let values: Vec<_> = self.values.iter().map(|v| serde_json::json!({
            "id": v.edit.id, "original": encode(&v.original), "replacement": encode(&v.edit.replacement)
        })).collect();
        let bytes =
            serde_json::to_vec_pretty(&serde_json::json!({"version": 1, "values": values}))?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(backup.join("registry.json"))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        let mut checksum = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(backup.join("registry.sha256"))?;
        checksum.write_all(&Sha256::digest(&bytes))?;
        checksum.sync_all()?;
        self.prepared = true;
        Ok(())
    }
    fn commit(&mut self) -> io::Result<()> {
        if !self.prepared || self.touched != 0 {
            return Err(invalid("registry participant is not ready"));
        }
        self.unchanged()?;
        for (index, saved) in self.values.iter().enumerate() {
            self.touched = index + 1;
            saved
                .edit
                .key
                .restore_value(saved.edit.name, saved.edit.replacement.as_ref())
                .map_err(io::Error::other)?;
        }
        Ok(())
    }
    fn rollback(&mut self) -> io::Result<()> {
        let mut errors = Vec::new();
        for saved in self.values[..self.touched].iter().rev() {
            if let Err(error) = saved
                .edit
                .key
                .restore_value(saved.edit.name, saved.original.as_ref())
            {
                errors.push(format!("{}: {error}", saved.edit.id));
            }
        }
        if errors.is_empty() {
            self.touched = 0;
            Ok(())
        } else {
            Err(io::Error::other(errors.join("; ")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::transaction::Transaction;
    use super::*;
    use crate::native::registry::tests::TestKey;
    use std::fs;
    use windows_sys::Win32::System::Registry::{REG_BINARY, REG_DWORD};
    fn change<'a>(id: &'a str, key: &'a Key, name: &'a str) -> Edit<'a> {
        Edit {
            id,
            key,
            name,
            replacement: Some(RawValue {
                kind: REG_BINARY,
                bytes: vec![1, 2, 3],
            }),
        }
    }
    #[test]
    fn real_registry_participant_persists_originals_and_restores_absent_and_binary_values() {
        let fixture = TestKey::new();
        let key = fixture.key();
        key.set_dword("existing", 42).unwrap();
        let mut participant = RegistryValues::capture(vec![
            change("windows.product", key, "existing"),
            change("windows.pid", key, "absent"),
        ])
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store");
        fs::write(&path, b"old").unwrap();
        let backup = Transaction::prepare(vec![(path.clone(), b"new".to_vec())])
            .unwrap()
            .commit_participating(&mut participant)
            .unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(backup.join("registry.json")).unwrap()).unwrap();
        assert_eq!(manifest["version"], 1);
        assert_eq!(manifest["values"][0]["original"]["type"], REG_DWORD);
        assert_eq!(
            manifest["values"][0]["original"]["base64"],
            STANDARD.encode(42u32.to_le_bytes())
        );
        assert!(manifest["values"][1]["original"].is_null());
        assert_eq!(key.raw_value("absent").unwrap().unwrap().bytes, [1, 2, 3]);
        participant.rollback().unwrap();
        assert_eq!(
            key.raw_value("existing").unwrap(),
            Some(RawValue {
                kind: REG_DWORD,
                bytes: 42u32.to_le_bytes().to_vec()
            })
        );
        assert!(key.raw_value("absent").unwrap().is_none());
        assert_eq!(fs::read(path).unwrap(), b"new"); // Participant rollback does not pretend to restore files.
    }
    #[test]
    fn changed_registry_and_duplicate_ids_abort_before_file_writes() {
        let fixture = TestKey::new();
        let key = fixture.key();
        assert!(
            RegistryValues::capture(vec![change("same", key, "one"), change("same", key, "two")])
                .is_err()
        );
        let mut participant = RegistryValues::capture(vec![change("one", key, "value")]).unwrap();
        key.set_dword("value", 99).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store");
        fs::write(&path, b"old").unwrap();
        let error = Transaction::prepare(vec![(path.clone(), b"new".to_vec())])
            .unwrap()
            .commit_participating(&mut participant)
            .unwrap_err();
        assert!(error.cause.contains("registry value changed"));
        assert!(error.rollback_errors.is_empty());
        assert_eq!(fs::read(path).unwrap(), b"old");
        assert_eq!(
            key.raw_value("value").unwrap().unwrap().bytes,
            99u32.to_le_bytes()
        );
    }
}
