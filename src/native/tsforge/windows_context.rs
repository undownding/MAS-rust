//! Read-only Windows scope preparation. No service, key, or store changes.
#![allow(dead_code)]
use super::{
    activation_flow::{self, Method},
    product_selection::Channel,
    selection_runtime, windows_edition,
};
use crate::native::{
    licensing::{Licensing, WINDOWS_APP, number, string},
    platform,
    registry::Key,
};
use std::{ffi::c_void, ptr};
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::{FreeLibrary, HMODULE, LocalFree},
    System::{
        LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW},
        Memory::{LPTR, LocalAlloc, LocalSize},
        Registry::KEY_WOW64_64KEY,
    },
};

struct Library(HMODULE);
impl Drop for Library {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.0);
        }
    }
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

/// Copy output while its DLL stays loaded. Accept image-owned strings or a
/// validated LocalAlloc buffer, without guessing an allocator for other memory.
fn edition_string(library: &Library, value: *mut u16) -> Result<String, String> {
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_IMAGE, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQuery,
    };
    if value.is_null() {
        return Err("pkeyhelper 返回空版本名称".into());
    }
    let mut info = MEMORY_BASIC_INFORMATION::default();
    if unsafe {
        VirtualQuery(
            value.cast(),
            &mut info,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    } == 0
        || info.State != MEM_COMMIT
        || info.Protect & (PAGE_GUARD | PAGE_NOACCESS) != 0
    {
        return Err("pkeyhelper 版本名称不在可读内存中".into());
    }
    let region_end = (info.BaseAddress as usize)
        .checked_add(info.RegionSize)
        .ok_or("版本名称内存范围溢出")?;
    let remaining = region_end
        .checked_sub(value as usize)
        .ok_or("版本名称指针越界")?;
    let (bytes, _owned) = if info.Type == MEM_IMAGE && info.AllocationBase == library.0.cast() {
        (remaining, Local(ptr::null_mut()))
    } else {
        let bytes = unsafe { LocalSize(value.cast()) };
        if bytes == 0 {
            return Err("pkeyhelper 返回的版本名称具有未知内存所有权".into());
        }
        (bytes.min(remaining), Local(value.cast()))
    };
    let mut words = Vec::new();
    for index in 0..(bytes / 2).min(256) {
        let word = unsafe { ptr::read_unaligned(value.add(index)) };
        if word == 0 {
            let result = String::from_utf16(&words).map_err(|_| "版本名称不是有效 UTF-16")?;
            if result.is_empty()
                || !result
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            {
                return Err("pkeyhelper 返回无效版本名称".into());
            }
            return Ok(result);
        }
        words.push(word);
    }
    Err("pkeyhelper 版本名称过长或没有结束符".into())
}
fn helper_edition(sku: u32) -> Result<String, String> {
    let name: Vec<_> = "pkeyhelper.dll".encode_utf16().chain([0]).collect();
    let library =
        unsafe { LoadLibraryExW(name.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if library.is_null() {
        return Err(format!(
            "加载系统 pkeyhelper.dll: {}",
            std::io::Error::last_os_error()
        ));
    }
    let library = Library(library);
    let function = unsafe { GetProcAddress(library.0, c"GetEditionNameFromId".as_ptr().cast()) }
        .ok_or("pkeyhelper 缺少 GetEditionNameFromId")?;
    let function: unsafe extern "system" fn(u32, *mut *mut u16) -> i32 =
        unsafe { std::mem::transmute(function) };
    let mut value = ptr::null_mut();
    let status = unsafe { function(sku, &mut value) };
    let result = edition_string(&library, value);
    if status < 0 {
        return Err(format!(
            "GetEditionNameFromId({sku}): 0x{:08X}",
            status as u32
        ));
    }
    result
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Subscription {
    enabled: u32,
    sku: u32,
    state: u32,
}
impl Subscription {
    fn active(self) -> bool {
        self.enabled >= 1 && self.state == 1
    }
}
type SubscriptionFn = unsafe extern "system" fn(*mut *mut Subscription) -> i32;

/// Pinned PrintSubscriptionStatus uses AllocHGlobal/FreeHGlobal for this buffer.
/// On Windows those allocations use LocalAlloc/LocalFree. Keep both ownerships
/// if the API replaces the initial pointer, and validate before reading 12 bytes.
fn query_subscription(function: SubscriptionFn) -> Result<Subscription, String> {
    let original = Local(unsafe { LocalAlloc(LPTR, size_of::<Subscription>()) });
    if original.0.is_null() {
        return Err("无法分配订阅状态缓冲区".into());
    }
    let mut returned = original.0.cast::<Subscription>();
    let status = unsafe { function(&mut returned) };
    let replacement = Local(if returned.cast() != original.0 {
        returned.cast()
    } else {
        ptr::null_mut()
    });
    let _keep_alive = &replacement;
    if status != 0 {
        return Err(format!(
            "ClipGetSubscriptionStatus: 0x{:08X}",
            status as u32
        ));
    }
    if returned.is_null() || unsafe { LocalSize(returned.cast()) } < size_of::<Subscription>() {
        return Err("订阅状态缓冲区缺失或长度不足".into());
    }
    Ok(unsafe { ptr::read_unaligned(returned) })
}
fn subscription(build: u32) -> Result<Option<Subscription>, String> {
    if build < 15063 {
        return Ok(None);
    }
    let name: Vec<_> = "clipc.dll".encode_utf16().chain([0]).collect();
    let library =
        unsafe { LoadLibraryExW(name.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if library.is_null() {
        return Err(format!(
            "加载系统 clipc.dll: {}",
            std::io::Error::last_os_error()
        ));
    }
    let library = Library(library);
    let function =
        unsafe { GetProcAddress(library.0, c"ClipGetSubscriptionStatus".as_ptr().cast()) }
            .ok_or("系统 clipc.dll 缺少 ClipGetSubscriptionStatus")?;
    let function: SubscriptionFn = unsafe { std::mem::transmute(function) };
    query_subscription(function).map(Some)
}

#[derive(Debug)]
pub struct Context {
    pub build: u32,
    pub revision: u32,
    pub sku: u32,
    pub slc_sku: Option<u32>,
    pub registry_sku: Option<u32>,
    pub subscription_active: bool,
    pub edition: String,
    pub permanently_activated: bool,
}
impl Context {
    pub fn read(report: &dyn Fn(&str)) -> Result<Self, String> {
        let licensing = Licensing::new()?;
        let systems =
            licensing.query("SELECT BuildNumber,OperatingSystemSKU FROM Win32_OperatingSystem")?;
        if systems.len() != 1 {
            return Err("Windows 系统记录缺失或不唯一".into());
        }
        let build = number(&systems[0], "BuildNumber")?;
        let wmi_sku = number(&systems[0], "OperatingSystemSKU").ok();
        let slc_sku = match platform::sku(build) {
            Ok(sku) => Some(sku),
            Err(e) => {
                report(&format!("SLC SKU 不可用，尝试其他来源：{e}"));
                None
            }
        };
        let registry_sku = Key::open(
            r"SYSTEM\CurrentControlSet\Control\ProductOptions",
            KEY_WOW64_64KEY,
            false,
        )?
        .map(|key| key.string("OSProductPfn"))
        .transpose()?
        .flatten()
        .and_then(|pfn| windows_edition::registry_sku(&pfn));
        let subscription_active = match subscription(build) {
            Ok(status) => status.is_some_and(Subscription::active),
            Err(e) => {
                report(&format!(
                    "未能确认 Windows 订阅激活状态，按上游使用普通 SKU 回退：{e}"
                ));
                false
            }
        };
        let sku =
            windows_edition::effective_sku(slc_sku, wmi_sku, registry_sku, subscription_active)
                .ok_or("无法读取有效 Windows SKU")?;
        let products = licensing.query(&format!("SELECT LicenseFamily FROM SoftwareLicensingProduct WHERE ApplicationID='{WINDOWS_APP}' AND LicenseDependsOn IS NULL"))?;
        let families = products
            .iter()
            .map(|p| string(p, "LicenseFamily"))
            .collect::<Result<Vec<_>, _>>()?;
        let edition = match windows_edition::edition(sku, &families, None) {
            Some(edition) => edition,
            None => {
                let helper = helper_edition(sku)?;
                windows_edition::edition(sku, &families, Some(&helper))
                    .ok_or_else(|| format!("SKU {sku} 的版本 {helper} 不在已安装基础许可证中"))?
            }
        };
        let revision =
            platform::registry_dword(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR")
                .unwrap_or(0);
        let products = licensing.query("SELECT Name,Description FROM SoftwareLicensingProduct WHERE LicenseStatus=1 AND GracePeriodRemaining=0 AND PartialProductKey IS NOT NULL AND LicenseDependsOn IS NULL")?;
        let mut permanently_activated = false;
        for product in products {
            if string(&product, "Name")?
                .to_ascii_lowercase()
                .contains("windows")
                && !string(&product, "Description")?
                    .to_ascii_uppercase()
                    .contains("KMS")
            {
                permanently_activated = true;
            }
        }
        Ok(Self {
            build,
            revision,
            sku,
            slc_sku,
            registry_sku,
            subscription_active,
            edition,
            permanently_activated,
        })
    }
}

#[derive(Debug)]
pub enum Plan {
    AlreadyPermanent,
    Evaluation,
    Legacy,
    Activate { sku: Uuid, method: Method },
}
/// Evaluation and legacy branches remain explicit, so a future dispatcher can
/// route them without incorrectly installing a generated key for an eval SKU.
pub fn plan(context: &Context, option: usize) -> Result<Plan, String> {
    let method = Method::windows(option, context.build)?;
    if context.edition.to_ascii_lowercase().contains("eval") {
        return Ok(Plan::Evaluation);
    }
    if activation_flow::skip_permanent(
        context.build,
        context.revision,
        context.permanently_activated,
    ) {
        return Ok(Plan::AlreadyPermanent);
    }
    if context.build < 9600 {
        return Ok(Plan::Legacy);
    }
    let channel = if method == Method::Kms4k {
        Channel::KmsClient
    } else {
        Channel::Zero
    };
    let sku = selection_runtime::windows(&context.edition, channel)?
        .ok_or_else(|| format!("没有适用于 {:?} 的 {} 产品许可证", method, context.edition))?;
    Ok(Plan::Activate { sku, method })
}

#[cfg(test)]
mod tests {
    use super::*;
    unsafe extern "system" fn in_place(out: *mut *mut Subscription) -> i32 {
        unsafe {
            **out = Subscription {
                enabled: 1,
                sku: 4,
                state: 1,
            };
        }
        0
    }
    unsafe extern "system" fn replaced(out: *mut *mut Subscription) -> i32 {
        unsafe {
            *out = LocalAlloc(LPTR, size_of::<Subscription>()).cast();
            in_place(out)
        }
    }
    unsafe extern "system" fn failed(out: *mut *mut Subscription) -> i32 {
        unsafe {
            *out = LocalAlloc(LPTR, size_of::<Subscription>()).cast();
        }
        0x80004005u32 as i32
    }
    unsafe extern "system" fn empty(out: *mut *mut Subscription) -> i32 {
        unsafe {
            *out = ptr::null_mut();
        }
        0
    }
    #[test]
    fn subscription_output_ownership_and_errors() {
        assert!(query_subscription(in_place).unwrap().active());
        assert!(query_subscription(replaced).unwrap().active());
        assert!(query_subscription(failed).unwrap_err().contains("80004005"));
        assert!(query_subscription(empty).is_err());
        assert!(
            !Subscription {
                enabled: 0,
                sku: 4,
                state: 1
            }
            .active()
        );
        assert!(
            !Subscription {
                enabled: 1,
                sku: 4,
                state: 0
            }
            .active()
        );
    }
    #[test]
    fn real_windows_context_is_read_only() {
        let context = Context::read(&|message| eprintln!("{message}")).unwrap();
        assert!(context.build > 0);
        assert!(context.sku > 0);
        assert!(!context.edition.is_empty());
    }
    #[test]
    fn system_edition_helper_is_read_only() {
        assert_eq!(helper_edition(48).unwrap(), "Professional");
    }
    #[test]
    fn eval_and_permanent_do_not_select_a_product() {
        let mut context = Context {
            build: 26100,
            revision: 4188,
            sku: 4,
            slc_sku: Some(4),
            registry_sku: Some(4),
            subscription_active: false,
            edition: "EnterpriseEval".into(),
            permanently_activated: true,
        };
        assert!(matches!(plan(&context, 0).unwrap(), Plan::Evaluation));
        context.edition = "Enterprise".into();
        assert!(matches!(plan(&context, 0).unwrap(), Plan::AlreadyPermanent));
        context.permanently_activated = false;
        context.build = 7601;
        assert!(matches!(plan(&context, 0).unwrap(), Plan::Legacy));
    }
}
