use std::{
    path::PathBuf,
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::System::{Registry::*, Services::*};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}
fn win_error(context: &str) -> String {
    format!("{context}: {}", std::io::Error::last_os_error())
}

pub fn registry_dword(path: &str, name: &str) -> Result<u32, String> {
    let mut value = 0u32;
    let mut size = 4u32;
    let code = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            wide(path).as_ptr(),
            wide(name).as_ptr(),
            RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY,
            ptr::null_mut(),
            (&mut value as *mut u32).cast(),
            &mut size,
        )
    };
    if code != 0 {
        return Err(format!("读取注册表 {name}: Win32 {code}"));
    }
    Ok(value)
}

struct Service(SC_HANDLE);
impl Drop for Service {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}
impl Service {
    fn open(name: &str) -> Result<Self, String> {
        let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
        if manager.is_null() {
            return Err(win_error("打开服务管理器"));
        }
        let manager = Service(manager);
        let handle = unsafe {
            OpenServiceW(
                manager.0,
                wide(name).as_ptr(),
                SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP,
            )
        };
        if handle.is_null() {
            return Err(win_error(&format!("打开服务 {name}")));
        }
        Ok(Service(handle))
    }
    fn state(&self) -> Result<u32, String> {
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut needed = 0;
        let ok = unsafe {
            QueryServiceStatusEx(
                self.0,
                SC_STATUS_PROCESS_INFO,
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                std::mem::size_of_val(&status) as u32,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(win_error("查询服务状态"));
        }
        Ok(status.dwCurrentState)
    }
    fn wait(&self, desired: u32) -> Result<(), String> {
        let started = Instant::now();
        while self.state()? != desired {
            if started.elapsed() > Duration::from_secs(25) {
                return Err(format!("等待服务状态 {desired} 超时（25 秒）"));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(())
    }
}

/// Read-only existence check; access failures are not mistaken for absence.
pub fn service_exists(name: &str) -> Result<bool, String> {
    if name.is_empty() || name.contains('\0') {
        return Err("无效服务名称".into());
    }
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(win_error("打开服务管理器"));
    }
    let manager = Service(manager);
    let handle = unsafe { OpenServiceW(manager.0, wide(name).as_ptr(), SERVICE_QUERY_STATUS) };
    if handle.is_null() {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(1060) {
            return Ok(false);
        }
        return Err(format!("查询服务 {name}：{error}"));
    }
    let _service = Service(handle);
    Ok(true)
}

#[cfg(test)]
mod service_discovery_tests {
    #[test]
    fn reads_existing_and_absent_services_without_start_or_stop() {
        assert!(super::service_exists("RpcSs").unwrap());
        assert!(!super::service_exists("MAS-Rust-test-7ed43ecf-NotInstalled").unwrap());
        assert!(super::service_exists("invalid\0name").is_err());
    }
}

pub fn service(name: &str, start: bool) -> Result<(), String> {
    let handle = Service::open(name)?;
    let mut state = handle.state()?;
    if state == SERVICE_START_PENDING {
        handle.wait(SERVICE_RUNNING)?;
        state = SERVICE_RUNNING;
    }
    if state == SERVICE_STOP_PENDING {
        handle.wait(SERVICE_STOPPED)?;
        state = SERVICE_STOPPED;
    }
    let target = if start {
        SERVICE_RUNNING
    } else {
        SERVICE_STOPPED
    };
    if state == target {
        return Ok(());
    }
    let success = if start {
        unsafe { StartServiceW(handle.0, 0, ptr::null()) }
    } else {
        let mut status = SERVICE_STATUS::default();
        unsafe { ControlService(handle.0, SERVICE_CONTROL_STOP, &mut status) }
    };
    if success == 0 {
        return Err(win_error(&format!(
            "{}服务 {name}",
            if start { "启动" } else { "停止" }
        )));
    }
    handle.wait(target).map_err(|e| format!("{name}: {e}"))
}

#[link(name = "slc")]
unsafe extern "system" {
    fn SLGetWindowsInformationDWORD(name: *const u16, value: *mut u32) -> i32;
}

pub fn sku(build: u32) -> Result<u32, String> {
    let mut sku = 0;
    let field = if build >= 14393 {
        "Kernel-BrandingInfo"
    } else {
        "Kernel-ProductInfo"
    };
    let result = unsafe { SLGetWindowsInformationDWORD(wide(field).as_ptr(), &mut sku) };
    if result < 0 || sku == 0 {
        return Err(format!(
            "SLGetWindowsInformationDWORD({field}): 0x{:08X}",
            result as u32
        ));
    }
    Ok(sku)
}

pub fn system_file(name: &str) -> Result<PathBuf, String> {
    Ok(
        PathBuf::from(std::env::var_os("SystemRoot").ok_or("SystemRoot 未定义")?)
            .join("System32")
            .join(name),
    )
}

pub fn clipup(report: &dyn Fn(&str)) -> Result<(), String> {
    use std::io::Read;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    let mut child = Command::new(system_file("clipup.exe")?)
        .args(["-v", "-o"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(0x08000000)
        .spawn()
        .map_err(|e| format!("启动系统 clipup: {e}"))?;
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut b = Vec::new();
        stdout.read_to_end(&mut b).map(|_| b)
    });
    let err = std::thread::spawn(move || {
        let mut b = Vec::new();
        stderr.read_to_end(&mut b).map(|_| b)
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < Duration::from_secs(60) => {
                std::thread::sleep(Duration::from_millis(200))
            }
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("等待 clipup 超时或失败：{result:?}"));
            }
        }
    };
    for pipe in [out, err] {
        let bytes = pipe
            .join()
            .map_err(|_| "clipup 输出线程失败")?
            .map_err(|e| e.to_string())?;
        let message = String::from_utf8_lossy(&bytes);
        if !message.trim().is_empty() {
            report(message.trim());
        }
    }
    if !status.success() {
        return Err(format!("clipup 退出码 {}", status.code().unwrap_or(-1)));
    }
    Ok(())
}
