//! Typed registry access for both Office registry views. No reg.exe subprocess.
use std::sync::atomic::{AtomicU64, Ordering};
use std::{os::windows::ffi::OsStrExt, path::Path, ptr};
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, SetLastError},
    Security::*,
    System::{
        Registry::*,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}
#[derive(Clone, Copy)]
pub enum Hive {
    Machine,
    Users,
}
impl Hive {
    fn raw(self) -> HKEY {
        match self {
            Self::Machine => HKEY_LOCAL_MACHINE,
            Self::Users => HKEY_USERS,
        }
    }
}
struct Privileges {
    token: HANDLE,
    previous: Vec<TOKEN_PRIVILEGES>,
}
impl Privileges {
    fn enable() -> Result<Self, String> {
        let mut token = ptr::null_mut();
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut guard = Self {
            token,
            previous: Vec::new(),
        };
        for name in ["SeBackupPrivilege", "SeRestorePrivilege"] {
            let mut state = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                ..Default::default()
            };
            if unsafe {
                LookupPrivilegeValueW(
                    ptr::null(),
                    wide(name).as_ptr(),
                    &mut state.Privileges[0].Luid,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
            state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            let mut previous = TOKEN_PRIVILEGES::default();
            let mut length = 0;
            unsafe {
                SetLastError(0);
            }
            let ok = unsafe {
                AdjustTokenPrivileges(
                    token,
                    0,
                    &state,
                    std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                    &mut previous,
                    &mut length,
                )
            };
            let code = unsafe { GetLastError() };
            if ok == 0 || code != 0 {
                return Err(format!("启用 {name}: Win32 {code}"));
            }
            guard.previous.push(previous);
        }
        Ok(guard)
    }
}
impl Drop for Privileges {
    fn drop(&mut self) {
        unsafe {
            for previous in self.previous.iter().rev() {
                AdjustTokenPrivileges(self.token, 0, previous, 0, ptr::null_mut(), ptr::null_mut());
            }
            CloseHandle(self.token);
        }
    }
}
pub struct Key {
    handle: HKEY,
    mount: Option<String>,
    _privileges: Option<Privileges>,
}

/// Exact registry representation: retain type, missing/empty distinction and
/// malformed string bytes so backups never normalize the original value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawValue {
    pub kind: u32,
    pub bytes: Vec<u8>,
}

const MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;

impl RawValue {
    pub fn validate_write(&self) -> Result<(), String> {
        validate_raw_write(self.kind, &self.bytes)
    }
}
fn validate_raw_write(kind: u32, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_VALUE_BYTES {
        return Err("注册表原始值超过 16 MiB 限制".into());
    }
    let terminator = match kind {
        REG_SZ | REG_EXPAND_SZ => 2,
        REG_MULTI_SZ => 4,
        _ => 0,
    };
    if terminator != 0
        && (!bytes.len().is_multiple_of(2)
            || bytes.len() < terminator
            || bytes[bytes.len() - terminator..].iter().any(|b| *b != 0))
    {
        return Err("注册表字符串未按 Win32 写入契约终止；拒绝隐式修补原始值".into());
    }
    Ok(())
}

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() {
                RegCloseKey(self.handle);
            }
            if let Some(mount) = &self.mount {
                RegUnLoadKeyW(HKEY_USERS, wide(mount).as_ptr());
            }
        }
    }
}
impl Key {
    pub fn open(path: &str, view: u32, write: bool) -> Result<Option<Self>, String> {
        Self::at(Hive::Machine, path, view, write)
    }
    pub fn at(hive: Hive, path: &str, view: u32, write: bool) -> Result<Option<Self>, String> {
        Self::open_raw(hive.raw(), path, view, write)
    }
    pub fn create_child(&self, path: &str) -> Result<Self, String> {
        let mut handle = ptr::null_mut();
        let code = unsafe {
            RegCreateKeyExW(
                self.handle,
                wide(path).as_ptr(),
                0,
                ptr::null(),
                0,
                KEY_READ | KEY_WRITE,
                ptr::null(),
                &mut handle,
                ptr::null_mut(),
            )
        };
        if code == 0 {
            Ok(Self {
                handle,
                mount: None,
                _privileges: None,
            })
        } else {
            Err(format!("创建注册表 {path}: Win32 {code}"))
        }
    }
    pub fn child(&self, path: &str, write: bool) -> Result<Option<Self>, String> {
        Self::open_raw(self.handle, path, 0, write)
    }
    fn open_raw(root: HKEY, path: &str, view: u32, write: bool) -> Result<Option<Self>, String> {
        let mut key = ptr::null_mut();
        let code = unsafe {
            RegOpenKeyExW(
                root,
                wide(path).as_ptr(),
                0,
                KEY_READ
                    | view
                    | if write {
                        KEY_WRITE | 0x00010000 /* DELETE */
                    } else {
                        0
                    },
                &mut key,
            )
        };
        match code {
            0 => Ok(Some(Self {
                handle: key,
                mount: None,
                _privileges: None,
            })),
            2 | 3 => Ok(None),
            _ => Err(format!("打开注册表 {path}: Win32 {code}")),
        }
    }
    pub fn load_offline(path: &Path) -> Result<Self, String> {
        if !path.is_file() {
            return Err(format!("用户配置不存在：{}", path.display()));
        }
        let privileges = Privileges::enable()?;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let mount = format!(
            "MAS-Rust-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let file: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        let code = unsafe { RegLoadKeyW(HKEY_USERS, wide(&mount).as_ptr(), file.as_ptr()) };
        if code != 0 {
            return Err(format!("加载用户配置 {}: Win32 {code}", path.display()));
        }
        let mut guard = Self {
            handle: ptr::null_mut(),
            mount: Some(mount.clone()),
            _privileges: Some(privileges),
        };
        let code = unsafe {
            RegOpenKeyExW(
                HKEY_USERS,
                wide(&mount).as_ptr(),
                0,
                KEY_ALL_ACCESS,
                &mut guard.handle,
            )
        };
        if code != 0 {
            return Err(format!("打开已加载用户配置: Win32 {code}"));
        }
        Ok(guard)
    }
    pub fn finish(mut self) -> Result<(), String> {
        let code = unsafe { RegFlushKey(self.handle) };
        if code != 0 {
            return Err(format!("保存用户配置: Win32 {code}"));
        }
        unsafe {
            RegCloseKey(self.handle);
        }
        self.handle = ptr::null_mut();
        if let Some(mount) = &self.mount {
            let code = unsafe { RegUnLoadKeyW(HKEY_USERS, wide(mount).as_ptr()) };
            if code != 0 {
                return Err(format!("卸载用户配置 {mount}: Win32 {code}"));
            }
            self.mount = None;
        }
        Ok(())
    }
    pub fn delete_tree(&self, path: &str) -> Result<bool, String> {
        if path.is_empty() {
            return Err("拒绝删除空注册表路径".into());
        }
        let code = unsafe { RegDeleteTreeW(self.handle, wide(path).as_ptr()) };
        match code {
            0 => Ok(true),
            2 | 3 => Ok(false),
            _ => Err(format!("删除注册表 {path}: Win32 {code}")),
        }
    }
    pub fn delete_value(&self, name: &str) -> Result<bool, String> {
        let code = unsafe { RegDeleteValueW(self.handle, wide(name).as_ptr()) };
        match code {
            0 => Ok(true),
            2 => Ok(false),
            _ => Err(format!("删除注册表值 {name}: Win32 {code}")),
        }
    }
    /// No string expansion or terminator repair (unlike RegGetValueW).
    #[allow(dead_code)] // Used by the staged TSforge registry recovery path.
    pub fn raw_value(&self, name: &str) -> Result<Option<RawValue>, String> {
        if name.contains('\0') {
            return Err("注册表值名称包含 NUL".into());
        }
        let name = wide(name);
        // Bound retries when another process continually changes the value size.
        for _ in 0..8 {
            let mut size = 0;
            let mut kind = 0;
            let code = unsafe {
                RegQueryValueExW(
                    self.handle,
                    name.as_ptr(),
                    ptr::null(),
                    &mut kind,
                    ptr::null_mut(),
                    &mut size,
                )
            };
            if code == 2 {
                return Ok(None);
            }
            if code != 0 {
                return Err(format!("查询注册表原始值: Win32 {code}"));
            }
            if size as usize > MAX_VALUE_BYTES {
                return Err("注册表原始值超过 16 MiB 限制".into());
            }
            // A non-null buffer also reads a zero-byte value rather than making
            // a second size-only query. Growth is reported as ERROR_MORE_DATA.
            let mut bytes = vec![0; (size as usize).max(1)];
            size = bytes.len() as u32;
            let code = unsafe {
                RegQueryValueExW(
                    self.handle,
                    name.as_ptr(),
                    ptr::null(),
                    &mut kind,
                    bytes.as_mut_ptr(),
                    &mut size,
                )
            };
            match code {
                2 => return Ok(None),
                234 => continue,
                0 if size as usize <= bytes.len() => {
                    bytes.truncate(size as usize);
                    return Ok(Some(RawValue { kind, bytes }));
                }
                _ => return Err(format!("读取注册表原始值: Win32 {code}")),
            }
        }
        Err("注册表值在读取期间持续变化".into())
    }
    pub fn set_raw(&self, name: &str, kind: u32, bytes: &[u8]) -> Result<(), String> {
        if name.contains('\0') {
            return Err("注册表值名称包含 NUL".into());
        }
        validate_raw_write(kind, bytes)?;
        let code = unsafe {
            RegSetValueExW(
                self.handle,
                wide(name).as_ptr(),
                0,
                kind,
                bytes.as_ptr(),
                bytes.len() as u32,
            )
        };
        if code == 0 {
            Ok(())
        } else {
            Err(format!("写入注册表 {name}: Win32 {code}"))
        }
    }
    #[allow(dead_code)] // Restore exact originals, including previously absent values.
    pub fn restore_value(&self, name: &str, original: Option<&RawValue>) -> Result<(), String> {
        if name.contains('\0') {
            return Err("注册表值名称包含 NUL".into());
        }
        match original {
            Some(value) => self.set_raw(name, value.kind, &value.bytes)?,
            None => {
                self.delete_value(name)?;
            }
        }
        let code = unsafe { RegFlushKey(self.handle) };
        if code != 0 {
            return Err(format!("保存注册表 {name}: Win32 {code}"));
        }
        if self.raw_value(name)?.as_ref() != original {
            return Err(format!("恢复注册表 {name} 后回读不一致"));
        }
        Ok(())
    }
    pub fn string(&self, name: &str) -> Result<Option<String>, String> {
        let mut size = 0;
        let name = wide(name);
        let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ;
        let code = unsafe {
            RegGetValueW(
                self.handle,
                ptr::null(),
                name.as_ptr(),
                flags,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut size,
            )
        };
        if code == 2 {
            return Ok(None);
        }
        if code != 0 {
            return Err(format!("读取注册表字符串: Win32 {code}"));
        }
        if size > 1_048_576 {
            return Err("注册表字符串超过大小限制".into());
        }
        let mut data = vec![0u16; (size as usize).div_ceil(2)];
        let code = unsafe {
            RegGetValueW(
                self.handle,
                ptr::null(),
                name.as_ptr(),
                flags,
                ptr::null_mut(),
                data.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if code != 0 {
            return Err(format!("读取注册表字符串: Win32 {code}"));
        }
        data.truncate(size as usize / 2);
        while data.last() == Some(&0) {
            data.pop();
        }
        String::from_utf16(&data)
            .map(Some)
            .map_err(|e| e.to_string())
    }
    pub fn children(&self) -> Result<Vec<String>, String> {
        let mut keys = Vec::new();
        for i in 0.. {
            let mut data = vec![0u16; 256]; // Windows registry key component limit: 255 characters.
            let mut size = data.len() as u32;
            let code = unsafe {
                RegEnumKeyExW(
                    self.handle,
                    i,
                    data.as_mut_ptr(),
                    &mut size,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if code == 259 {
                break;
            }
            if code != 0 {
                return Err(format!("枚举注册表: Win32 {code}"));
            }
            keys.push(String::from_utf16(&data[..size as usize]).map_err(|e| e.to_string())?);
        }
        Ok(keys)
    }
    pub fn value_names(&self) -> Result<Vec<String>, String> {
        let mut names = Vec::new();
        for index in 0.. {
            let mut data = vec![0u16; 16_384];
            let mut length = data.len() as u32;
            let code = unsafe {
                RegEnumValueW(
                    self.handle,
                    index,
                    data.as_mut_ptr(),
                    &mut length,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if code == 259 {
                break;
            }
            if code != 0 {
                return Err(format!("枚举注册表值: Win32 {code}"));
            }
            names.push(String::from_utf16(&data[..length as usize]).map_err(|e| e.to_string())?);
        }
        Ok(names)
    }
    pub fn set_string(&self, name: &str, value: &str) -> Result<(), String> {
        let data: Vec<_> = wide(value).into_iter().flat_map(u16::to_le_bytes).collect();
        self.set_raw(name, REG_SZ, &data)
    }
    pub fn set_dword(&self, name: &str, value: u32) -> Result<(), String> {
        self.set_raw(name, REG_DWORD, &value.to_le_bytes())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) struct TestKey {
        key: Option<Key>,
        path: String,
    }
    impl TestKey {
        pub(crate) fn new() -> Self {
            let path = format!(
                r"Software\MAS-Rust-Raw-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let parent = Key::open_raw(HKEY_CURRENT_USER, "Software", 0, true)
                .unwrap()
                .unwrap();
            let key = parent
                .create_child(path.strip_prefix("Software\\").unwrap())
                .unwrap();
            Self {
                key: Some(key),
                path,
            }
        }
        pub(crate) fn key(&self) -> &Key {
            self.key.as_ref().unwrap()
        }
    }
    impl Drop for TestKey {
        fn drop(&mut self) {
            drop(self.key.take());
            unsafe {
                RegDeleteTreeW(HKEY_CURRENT_USER, wide(&self.path).as_ptr());
            }
        }
    }
    #[test]
    fn raw_registry_backup_restores_exact_types_bytes_and_absence() {
        let fixture = TestKey::new();
        let key = fixture.key();
        let cases = [
            (REG_BINARY, vec![0, 255, 128, 0, 1]),
            (REG_BINARY, vec![]),
            (REG_NONE, vec![7]),
            (REG_SZ, vec![65, 0, 0, 0]),
            (
                REG_EXPAND_SZ,
                wide("%SystemRoot%\\测试")
                    .into_iter()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            ),
            (
                REG_MULTI_SZ,
                wide("first\0second\0")
                    .into_iter()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            ),
            (REG_DWORD, 0xdeadbeefu32.to_le_bytes().to_vec()),
            (REG_QWORD, u64::MAX.to_le_bytes().to_vec()),
        ];
        for (index, (kind, bytes)) in cases.into_iter().enumerate() {
            let name = format!("value-{index}");
            key.set_raw(&name, kind, &bytes).unwrap();
            let original = key.raw_value(&name).unwrap().unwrap();
            assert_eq!(original, RawValue { kind, bytes });
            key.set_string(&name, "changed").unwrap();
            key.restore_value(&name, Some(&original)).unwrap();
            assert_eq!(key.raw_value(&name).unwrap(), Some(original));
        }
        assert_eq!(key.raw_value("absent").unwrap(), None);
        key.set_dword("absent", 1).unwrap();
        key.restore_value("absent", None).unwrap();
        assert_eq!(key.raw_value("absent").unwrap(), None);
        key.set_raw("", REG_BINARY, &[]).unwrap(); // Unnamed default value.
        assert_eq!(
            key.raw_value("").unwrap(),
            Some(RawValue {
                kind: REG_BINARY,
                bytes: vec![]
            })
        );
    }
    #[test]
    fn raw_registry_rejects_invalid_names_and_reports_read_only_write_failures() {
        let fixture = TestKey::new();
        let key = fixture.key();
        key.set_dword("keep", 42).unwrap();
        let original = key.raw_value("keep").unwrap().unwrap();
        assert!(key.set_raw("keep\0suffix", REG_BINARY, &[0]).is_err());
        assert!(key.raw_value("keep\0suffix").is_err());
        assert!(key.restore_value("keep\0suffix", None).is_err());
        assert!(
            key.set_raw("keep", REG_BINARY, &vec![0; MAX_VALUE_BYTES + 1])
                .is_err()
        );
        for (kind, bytes) in [
            (REG_SZ, vec![65, 0]),
            (REG_SZ, vec![65]),
            (REG_MULTI_SZ, vec![0, 0]),
        ] {
            assert!(key.set_raw("keep", kind, &bytes).is_err());
        }
        assert_eq!(key.raw_value("keep").unwrap().as_ref(), Some(&original));
        let readonly = Key::open_raw(HKEY_CURRENT_USER, &fixture.path, 0, false)
            .unwrap()
            .unwrap();
        assert!(readonly.restore_value("keep", Some(&original)).is_err());
        assert_eq!(key.raw_value("keep").unwrap(), Some(original));
    }
    #[test]
    fn deletes_only_requested_test_tree_and_preserves_sibling() {
        let path = format!(
            r"Software\MAS-Rust-Tests-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                unsafe {
                    RegDeleteTreeW(HKEY_CURRENT_USER, wide(&self.0).as_ptr());
                }
            }
        }
        let _cleanup = Cleanup(path.clone());
        let create = |suffix: &str| {
            let path = format!(r"{path}\{suffix}");
            let mut handle = ptr::null_mut();
            let code = unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    wide(&path).as_ptr(),
                    0,
                    ptr::null(),
                    0,
                    KEY_ALL_ACCESS,
                    ptr::null(),
                    &mut handle,
                    ptr::null_mut(),
                )
            };
            assert_eq!(code, 0);
            Key {
                handle,
                mount: None,
                _privileges: None,
            }
        };
        {
            let child = create("remove");
            child.set_string("value", "test").unwrap();
        }
        {
            let child = create("keep");
            child.set_string("value", "保留").unwrap();
        }
        let root = Key::open_raw(HKEY_CURRENT_USER, &path, 0, true)
            .unwrap()
            .unwrap();
        assert!(root.delete_tree("").is_err());
        assert!(root.delete_tree("remove").unwrap());
        assert!(!root.delete_tree("remove").unwrap());
        let sibling = root.child("keep", true).unwrap().unwrap();
        assert_eq!(sibling.string("value").unwrap().as_deref(), Some("保留"));
        assert!(sibling.delete_value("value").unwrap());
        assert!(!sibling.delete_value("value").unwrap());
    }
}
