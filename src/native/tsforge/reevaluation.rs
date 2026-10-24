//! SPP scheduled-task reevaluation from the pinned :dk_reeval: routine.
pub fn finish(
    result: Result<String, String>,
    reevaluate: impl FnOnce() -> Result<(), String>,
) -> Result<String, String> {
    match (result, reevaluate()) {
        (result, Ok(())) => result,
        (Ok(message), Err(error)) => Err(format!(
            "{message}\n许可流程完成，但 SPP 任务重评估失败：{error}"
        )),
        (Err(original), Err(error)) => Err(format!("{original}\nSPP 任务重评估也失败：{error}")),
    }
}

#[cfg(windows)]
mod native {
    use crate::native::registry::{Hive, Key};
    use std::ptr;
    use windows_sys::{
        Win32::{
            Foundation::{FreeLibrary, HMODULE},
            System::{
                LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW},
                Registry::KEY_WOW64_64KEY,
            },
        },
        core::PCWSTR,
    };
    type Trigger = unsafe extern "system" fn(u32, *mut std::ffi::c_void, PCWSTR, u32) -> i32;
    struct Worker {
        module: HMODULE,
        trigger: Trigger,
    }
    impl Drop for Worker {
        fn drop(&mut self) {
            unsafe {
                FreeLibrary(self.module);
            }
        }
    }
    impl Worker {
        fn load() -> Result<Self, String> {
            let name: Vec<_> = "sppc.dll".encode_utf16().chain([0]).collect();
            let module = unsafe {
                LoadLibraryExW(name.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32)
            };
            if module.is_null() {
                return Err(format!(
                    "加载系统 sppc.dll: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let function =
                unsafe { GetProcAddress(module, c"SLpTriggerServiceWorker".as_ptr().cast()) };
            let Some(function) = function else {
                unsafe {
                    FreeLibrary(module);
                }
                return Err("sppc.dll 缺少 SLpTriggerServiceWorker".into());
            };
            let trigger: Trigger = unsafe { std::mem::transmute(function) };
            Ok(Self { module, trigger })
        }
        fn trigger(&self) -> Result<(), String> {
            let name: Vec<_> = "reeval".encode_utf16().chain([0]).collect();
            let status = unsafe { (self.trigger)(0, ptr::null_mut(), name.as_ptr(), 0) };
            if status < 0 {
                Err(format!("SLpTriggerServiceWorker: 0x{:08X}", status as u32))
            } else {
                Ok(())
            }
        }
    }
    pub fn run(build: u32, report: &dyn Fn(&str)) -> Result<(), String> {
        if build < 7600 {
            return Ok(());
        }
        // Resolve the export before changing state. Service coordination restores
        // an initially running SPP even if stopping or triggering fails.
        let worker = Worker::load()?;
        let key = Key::at(
            Hive::Users,
            r"S-1-5-20\Software\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\PersistedSystemState",
            KEY_WOW64_64KEY,
            true,
        )?;
        if let Some(key) = key {
            for name in ["State", "SuppressRulesEngine"] {
                if key.delete_value(name)? {
                    report(&format!("已清除 SPP 持久状态 {name}。"));
                }
                if key.raw_value(name)?.is_some() {
                    return Err(format!("SPP 持久状态 {name} 清理后仍存在"));
                }
            }
        }
        super::super::service::stopped("sppsvc", || worker.trigger())?;
        report("SPP 任务重评估请求已提交；系统异步处理，不作为激活成功的判断依据。");
        Ok(())
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn system_worker_export_can_be_loaded_without_triggering() {
            let _worker = Worker::load().unwrap();
        }
    }
}
#[cfg(windows)]
pub use native::run;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reevaluation_preserves_original_success_and_failures() {
        assert_eq!(
            finish(Ok("verified".into()), || Ok(())).unwrap(),
            "verified"
        );
        assert_eq!(
            finish(Err("activation failed".into()), || Ok(())).unwrap_err(),
            "activation failed"
        );
        let error = finish(Err("backup=/tmp/example".into()), || {
            Err("trigger failed".into())
        })
        .unwrap_err();
        assert!(error.contains("backup=/tmp/example") && error.contains("trigger failed"));
        let error = finish(Ok("verified".into()), || Err("trigger failed".into())).unwrap_err();
        assert!(error.contains("verified") && error.contains("trigger failed"));
    }
}
