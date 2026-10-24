//! Serialize GUI and scheduled renewal mutations across Windows sessions.
use std::{marker::PhantomData, ptr, rc::Rc};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject},
};
pub struct OperationGuard {
    handle: HANDLE,
    _thread: PhantomData<Rc<()>>,
}
impl OperationGuard {
    pub fn acquire() -> Result<Self, String> {
        Self::named(r"Global\MAS-Rust-LicenseOperation")
    }
    fn named(name: &str) -> Result<Self, String> {
        let name: Vec<u16> = name.encode_utf16().chain([0]).collect();
        let handle = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(format!(
                "无法取得操作锁：{}",
                std::io::Error::last_os_error()
            ));
        }
        let result = unsafe { WaitForSingleObject(handle, 0) };
        if matches!(result, WAIT_OBJECT_0 | WAIT_ABANDONED) {
            return Ok(Self {
                handle,
                _thread: PhantomData,
            });
        }
        let error = if result == WAIT_TIMEOUT {
            "另一个 MAS Rust 窗口或续期任务正在操作许可证；请等待完成后重试。".into()
        } else {
            format!("获取操作锁失败：{}", std::io::Error::last_os_error())
        };
        unsafe {
            CloseHandle(handle);
        }
        Err(error)
    }
}
impl Drop for OperationGuard {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.handle);
            CloseHandle(self.handle);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn competing_worker_is_excluded_and_drop_releases_lock() {
        let name = format!(
            r"Local\MAS-Rust-Test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let guard = OperationGuard::named(&name).unwrap();
        let other = name.clone();
        assert!(
            std::thread::spawn(move || OperationGuard::named(&other).is_err())
                .join()
                .unwrap()
        );
        drop(guard);
        assert!(
            std::thread::spawn(move || OperationGuard::named(&name).is_ok())
                .join()
                .unwrap()
        );
    }
}
