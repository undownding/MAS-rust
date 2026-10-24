//! RAII wrappers for the public slc.dll API used by LibTSforge.
//! Uses SDK types/constants rather than upstream hand-written enum/ABI layouts.
#![allow(
    dead_code,
    reason = "staged TSforge API; activation routes are not connected yet"
)]
use std::{ffi::c_void, marker::PhantomData, ptr, rc::Rc};
use windows_sys::{
    Win32::{
        Foundation::LocalFree, Security::Authentication::Identity::*, System::Memory::LocalSize,
    },
    core::GUID,
};

pub const WINDOWS_APP_ID: GUID = GUID::from_u128(0x55c92734_d682_4d71_983e_d6ec3f16059f);
const VALUE_NOT_FOUND: u32 = 0xc004f012;
const INVALID_DATA: u32 = 0x8007000d;
type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{operation}: HRESULT 0x{code:08X}")]
pub struct Error {
    pub operation: &'static str,
    pub code: u32,
}
fn check(operation: &'static str, code: i32) -> Result<()> {
    if code < 0 {
        Err(Error {
            operation,
            code: code as u32,
        })
    } else {
        Ok(())
    }
}
fn invalid(operation: &'static str) -> Error {
    Error {
        operation,
        code: INVALID_DATA,
    }
}
fn wide(value: &str) -> Result<Vec<u16>> {
    if value.contains('\0') {
        return Err(invalid("字符串包含 NUL"));
    }
    Ok(value.encode_utf16().chain([0]).collect())
}

/// Owns a LocalAlloc-compatible pointer returned by SLC, including error paths.
struct Buffer<T>(*mut T);
impl<T> Drop for Buffer<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0.cast());
            }
        }
    }
}
impl<T: Copy> Buffer<T> {
    fn copy(&self, count: usize) -> Result<Vec<T>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        if self.0.is_null() {
            return Err(invalid("SLC 返回空指针与非零长度"));
        }
        let len = count
            .checked_mul(size_of::<T>())
            .filter(|n| *n <= isize::MAX as usize)
            .ok_or_else(|| invalid("SLC 返回长度溢出"))?;
        // All wrapped out-buffers are documented LocalFree allocations. Check the
        // allocation before making a slice, not merely the reported element count.
        if unsafe { LocalSize(self.0.cast()) } < len {
            return Err(invalid("SLC 返回长度超出分配"));
        }
        Ok(unsafe { std::slice::from_raw_parts(self.0, count) }.to_vec())
    }
}
impl Buffer<u16> {
    fn string(&self) -> Result<String> {
        if self.0.is_null() {
            return Err(invalid("SLC 返回空字符串指针"));
        }
        let bytes = unsafe { LocalSize(self.0.cast()) };
        let words = self.copy(bytes / 2)?;
        let end = words
            .iter()
            .position(|w| *w == 0)
            .ok_or_else(|| invalid("SLC 字符串缺少结束符"))?;
        String::from_utf16(&words[..end]).map_err(|_| invalid("SLC 返回无效 UTF-16"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    pub kind: SLDATATYPE,
    pub bytes: Vec<u8>,
}
impl Value {
    pub fn string(&self) -> Result<String> {
        if self.kind != SL_DATA_SZ || !self.bytes.len().is_multiple_of(2) {
            return Err(invalid("SLC 属性不是 UTF-16 字符串"));
        }
        let words: Vec<_> = self
            .bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|v| u16::from_le_bytes(*v))
            .collect();
        let end = words
            .iter()
            .position(|w| *w == 0)
            .ok_or_else(|| invalid("SLC 属性缺少结束符"))?;
        if words[end..].iter().any(|w| *w != 0) {
            return Err(invalid("SLC 属性结束符后存在数据"));
        }
        String::from_utf16(&words[..end]).map_err(|_| invalid("SLC 属性含无效 UTF-16"))
    }
    pub fn dword(&self) -> Result<u32> {
        if self.kind != SL_DATA_DWORD || self.bytes.len() != 4 {
            return Err(invalid("SLC 属性不是 DWORD"));
        }
        Ok(u32::from_le_bytes(self.bytes[..].try_into().unwrap()))
    }
}

pub struct Context {
    handle: *mut c_void,
    _thread: PhantomData<Rc<()>>,
}
impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            SLClose(self.handle);
        }
    }
}
impl Context {
    pub fn open() -> Result<Self> {
        let mut handle = ptr::null_mut();
        let result = unsafe { SLOpen(&mut handle) };
        if result < 0 {
            if !handle.is_null() {
                unsafe {
                    SLClose(handle);
                }
            }
            check("SLOpen", result)?;
        }
        if handle.is_null() {
            return Err(invalid("SLOpen 返回空句柄"));
        }
        Ok(Self {
            handle,
            _thread: PhantomData,
        })
    }

    pub fn ids(&self, from: SLIDTYPE, id: &GUID, to: SLIDTYPE) -> Result<Vec<GUID>> {
        let mut count = 0;
        let mut output = Buffer(ptr::null_mut());
        check("SLGetSLIDList", unsafe {
            SLGetSLIDList(self.handle, from, id, to, &mut count, &mut output.0)
        })?;
        output.copy(count as usize)
    }

    pub fn statuses(&self, app: &GUID) -> Result<Vec<SL_LICENSING_STATUS>> {
        let mut count = 0;
        let mut output = Buffer(ptr::null_mut());
        check("SLGetLicensingStatusInformation", unsafe {
            SLGetLicensingStatusInformation(
                self.handle,
                app,
                ptr::null(),
                ptr::null(),
                &mut count,
                &mut output.0,
            )
        })?;
        output.copy(count as usize)
    }

    fn information(&self, id: &GUID, name: &str, product_key: bool) -> Result<Option<Value>> {
        let name = wide(name)?;
        let mut kind = 0;
        let mut len = 0;
        let mut output = Buffer(ptr::null_mut());
        let (operation, code) = if product_key {
            ("SLGetPKeyInformation", unsafe {
                SLGetPKeyInformation(
                    self.handle,
                    id,
                    name.as_ptr(),
                    &mut kind,
                    &mut len,
                    &mut output.0,
                )
            })
        } else {
            ("SLGetProductSkuInformation", unsafe {
                SLGetProductSkuInformation(
                    self.handle,
                    id,
                    name.as_ptr(),
                    &mut kind,
                    &mut len,
                    &mut output.0,
                )
            })
        };
        if code as u32 == VALUE_NOT_FOUND {
            return Ok(None);
        }
        check(operation, code)?;
        Ok(Some(Value {
            kind,
            bytes: output.copy(len as usize)?,
        }))
    }

    pub fn sku_information(&self, id: &GUID, name: &str) -> Result<Option<Value>> {
        self.information(id, name, false)
    }
    pub fn key_information(&self, id: &GUID, name: &str) -> Result<Option<Value>> {
        self.information(id, name, true)
    }
    pub fn is_addon(&self, id: &GUID) -> Result<bool> {
        Ok(self.sku_information(id, "DependsOn")?.is_some())
    }
    pub fn phone_activatable(&self, id: &GUID) -> Result<bool> {
        Ok(self
            .sku_information(id, "msft:sl/EUL/PHONE/PUBLIC")?
            .is_some())
    }
    pub fn installed_keys(&self, id: &GUID) -> Result<Vec<GUID>> {
        self.ids(SL_ID_PRODUCT_SKU, id, SL_ID_PKEY)
    }
    pub fn default_activation_id(
        &self,
        app: &GUID,
        include_activated: bool,
    ) -> Result<Option<GUID>> {
        for status in self.statuses(app)? {
            if !include_activated && status.eStatus == SL_LICENSING_STATUS_LICENSED {
                continue;
            }
            if self.installed_keys(&status.SkuId)?.is_empty() || self.is_addon(&status.SkuId)? {
                continue;
            }
            return Ok(Some(status.SkuId));
        }
        Ok(None)
    }
    pub fn license(&self, file: &GUID) -> Result<Vec<u8>> {
        let mut len = 0;
        let mut output = Buffer(ptr::null_mut());
        check("SLGetLicense", unsafe {
            SLGetLicense(self.handle, file, &mut len, &mut output.0)
        })?;
        output.copy(len as usize)
    }
    pub fn application_id(&self, sku: &GUID) -> Result<Option<GUID>> {
        Ok(self
            .ids(SL_ID_PRODUCT_SKU, sku, SL_ID_APPLICATION)?
            .first()
            .copied())
    }
    pub fn key_channel(&self, key: &GUID) -> Result<Option<String>> {
        self.key_information(key, "Channel")?
            .map(|v| v.string())
            .transpose()
    }
    pub fn pkey_config_file_id(&self, sku: &GUID) -> Result<Option<GUID>> {
        let Some(value) = self.sku_information(sku, "pkeyConfigLicenseId")? else {
            return Ok(None);
        };
        let text = value.string()?;
        let text = text
            .strip_prefix('{')
            .and_then(|v| v.strip_suffix('}'))
            .unwrap_or(&text);
        let id = windows::core::GUID::try_from(text)
            .map_err(|_| invalid("pkeyConfigLicenseId 不是 GUID"))?;
        let id = GUID::from_u128(id.to_u128());
        Ok(self
            .ids(SL_ID_LICENSE, &id, SL_ID_LICENSE_FILE)?
            .first()
            .copied())
    }
    pub fn license_xml(&self, file: &GUID) -> Result<String> {
        let data = self.license(file)?;
        let start = data
            .iter()
            .position(|v| *v == b'<')
            .ok_or_else(|| invalid("许可数据不含 XML"))?;
        String::from_utf8(data[start..].to_vec()).map_err(|_| invalid("许可 XML 不是 UTF-8"))
    }
    pub fn refresh_trusted_time(&self, sku: &GUID) -> Result<()> {
        self.sku_information(sku, "TrustedTime")?;
        Ok(())
    }
    /// Resolve the full list before any mutation. The caller must hold the app's
    /// global licensing-operation guard for the complete mutation sequence.
    pub fn uninstall_application_keys(&self, app: &GUID) -> Result<()> {
        let mut keys = Vec::new();
        for status in self.statuses(app)? {
            if self.is_addon(&status.SkuId)? {
                continue;
            }
            for key in self.installed_keys(&status.SkuId)? {
                if !keys.iter().any(|previous: &GUID| {
                    previous.data1 == key.data1
                        && previous.data2 == key.data2
                        && previous.data3 == key.data3
                        && previous.data4 == key.data4
                }) {
                    keys.push(key);
                }
            }
        }
        for key in keys {
            self.uninstall_key(&key)?;
        }
        Ok(())
    }
    pub fn installation_id(&self, sku: &GUID) -> Result<String> {
        let mut output = Buffer(ptr::null_mut());
        check("SLGenerateOfflineInstallationId", unsafe {
            SLGenerateOfflineInstallationId(self.handle, sku, &mut output.0)
        })?;
        output.string()
    }
    pub fn deposit_confirmation(
        &self,
        sku: &GUID,
        installation: &str,
        confirmation: &str,
    ) -> Result<()> {
        let installation = wide(installation)?;
        let confirmation = wide(confirmation)?;
        check("SLDepositOfflineConfirmationId", unsafe {
            SLDepositOfflineConfirmationId(
                self.handle,
                sku,
                installation.as_ptr(),
                confirmation.as_ptr(),
            )
        })
    }
    pub fn install_key(&self, algorithm: &str, key: &str) -> Result<GUID> {
        let algorithm = wide(algorithm)?;
        let key = wide(key)?;
        let mut id = GUID::from_u128(0);
        check("SLInstallProofOfPurchase", unsafe {
            SLInstallProofOfPurchase(
                self.handle,
                algorithm.as_ptr(),
                key.as_ptr(),
                0,
                ptr::null(),
                &mut id,
            )
        })?;
        Ok(id)
    }
    pub fn uninstall_key(&self, key: &GUID) -> Result<()> {
        check("SLUninstallProofOfPurchase", unsafe {
            SLUninstallProofOfPurchase(self.handle, key)
        })
    }
    pub fn set_current_key(&self, sku: &GUID, key: &GUID) -> Result<()> {
        check("SLSetCurrentProductKey", unsafe {
            SLSetCurrentProductKey(self.handle, sku, key)
        })
    }
    pub fn activate(&self, sku: &GUID) -> Result<()> {
        check("SLActivateProduct", unsafe {
            SLActivateProduct(
                self.handle,
                sku,
                0,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
            )
        })
    }
    pub fn state_changed(&self, app: &GUID) -> Result<()> {
        let event = wide("msft:rm/event/licensingstatechanged")?;
        check("SLFireEvent", unsafe {
            SLFireEvent(self.handle, event.as_ptr(), app)
        })
    }
}

/// This private export has no SDK binding. Resolve it at runtime so a missing
/// export becomes an explicit error, rather than preventing the GUI from loading.
/// The ABI matches the pinned upstream SLApi declaration; this is not a stable API.
fn license_refresher() -> Result<unsafe extern "system" fn(u32) -> i32> {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    let name = wide("slc.dll")?;
    // slc.dll is already loaded through the public SDK imports above. A borrowed
    // module handle must not be passed to FreeLibrary.
    let module = unsafe { GetModuleHandleW(name.as_ptr()) };
    if module.is_null() {
        return Err(invalid("slc.dll 尚未加载"));
    }
    let function = unsafe { GetProcAddress(module, c"SLConsumeWindowsRight".as_ptr().cast()) }
        .ok_or(Error {
            operation: "SLConsumeWindowsRight 不可用",
            code: 0x8007007f,
        })?;
    let function: unsafe extern "system" fn(u32) -> i32 = unsafe { std::mem::transmute(function) };
    Ok(function)
}
pub fn ensure_refresh_available() -> Result<()> {
    license_refresher().map(|_| ())
}
pub fn refresh_license_status() -> Result<()> {
    let function = license_refresher()?;
    check("SLConsumeWindowsRight", unsafe { function(0) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Memory::{LMEM_FIXED, LMEM_ZEROINIT, LocalAlloc};

    #[test]
    fn sdk_value_types_and_error_codes_are_not_guessed() {
        assert_eq!(SL_DATA_DWORD, 4);
        assert_eq!(
            Value {
                kind: SL_DATA_DWORD,
                bytes: 42u32.to_le_bytes().to_vec()
            }
            .dword()
            .unwrap(),
            42
        );
        assert!(
            Value {
                kind: 2,
                bytes: vec![0; 4]
            }
            .dword()
            .is_err()
        );
        assert!(
            Value {
                kind: SL_DATA_SZ,
                bytes: vec![0; 3]
            }
            .string()
            .is_err()
        );
        let bytes = "测试😀"
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(
            Value {
                kind: SL_DATA_SZ,
                bytes
            }
            .string()
            .unwrap(),
            "测试😀"
        );
        assert!(wide("key\0suffix").is_err());
        assert_eq!(
            check("test", VALUE_NOT_FOUND as i32).unwrap_err().code,
            VALUE_NOT_FOUND
        );
        assert!(check("test", 1).is_ok());
    }

    #[test]
    fn returned_buffers_check_allocation_bounds_and_terminators() {
        assert!(Buffer::<u8>(ptr::null_mut()).copy(1).is_err());
        assert!(Buffer::<u8>(ptr::null_mut()).copy(0).unwrap().is_empty());
        let raw = unsafe { LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, 16) };
        assert!(!raw.is_null());
        let buffer = Buffer(raw.cast::<u16>());
        unsafe {
            *buffer.0 = 0x41;
        }
        assert_eq!(buffer.string().unwrap(), "A");
        assert!(buffer.copy(usize::MAX).is_err());
        let count = unsafe { LocalSize(raw) } / 2;
        assert!(buffer.copy(count + 1).is_err());
        for index in 0..count {
            unsafe {
                *buffer.0.add(index) = 0x41;
            }
        }
        assert!(buffer.string().is_err());
    }

    #[test]
    fn native_status_query_is_read_only() {
        let context = Context::open().unwrap();
        let statuses = context.statuses(&WINDOWS_APP_ID).unwrap();
        assert!(!statuses.is_empty(), "Windows SLC returned no Windows SKUs");
        for status in statuses {
            // No key installation, CID deposit, status refresh or service changes.
            let name = context.sku_information(&status.SkuId, "Name").unwrap();
            assert!(name.is_some());
            assert!(!name.unwrap().string().unwrap().is_empty());
        }
    }
}
