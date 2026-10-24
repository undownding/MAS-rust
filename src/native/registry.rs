//! Typed registry access for both Office registry views. No reg.exe subprocess.
use std::ptr;
use windows_sys::Win32::System::Registry::*;
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}
pub struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
impl Key {
    pub fn open(path: &str, view: u32, write: bool) -> Result<Option<Self>, String> {
        let mut key = ptr::null_mut();
        let code = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wide(path).as_ptr(),
                0,
                KEY_READ | view | if write { KEY_SET_VALUE } else { 0 },
                &mut key,
            )
        };
        match code {
            0 => Ok(Some(Self(key))),
            2 | 3 => Ok(None),
            _ => Err(format!("打开注册表 {path}: Win32 {code}")),
        }
    }
    pub fn string(&self, name: &str) -> Result<Option<String>, String> {
        let mut size = 0;
        let name = wide(name);
        let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ;
        let code = unsafe {
            RegGetValueW(
                self.0,
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
                self.0,
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
                    self.0,
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
                    self.0,
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
        let data = wide(value);
        let code = unsafe {
            RegSetValueExW(
                self.0,
                wide(name).as_ptr(),
                0,
                REG_SZ,
                data.as_ptr().cast(),
                (data.len() * 2) as u32,
            )
        };
        if code == 0 {
            Ok(())
        } else {
            Err(format!("写入注册表 {name}: Win32 {code}"))
        }
    }
    pub fn set_dword(&self, name: &str, value: u32) -> Result<(), String> {
        let code = unsafe {
            RegSetValueExW(
                self.0,
                wide(name).as_ptr(),
                0,
                REG_DWORD,
                (&value as *const u32).cast(),
                4,
            )
        };
        if code == 0 {
            Ok(())
        } else {
            Err(format!("写入注册表 {name}: Win32 {code}"))
        }
    }
}
