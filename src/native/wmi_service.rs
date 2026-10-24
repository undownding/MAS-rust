//! Stop WMI and active dependents, then restore the captured service configuration.
#![cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug)]
pub struct State {
    pub start_type: u32,
    pub running: bool,
    pub dependents: Vec<String>,
}
pub trait Control {
    fn snapshot(&mut self) -> Result<State, String>;
    fn configure(&mut self, start_type: u32) -> Result<(), String>;
    fn service(&mut self, name: &str, start: bool) -> Result<(), String>;
}
fn restore(control: &mut impl Control, state: &State) -> Result<(), String> {
    let mut errors = vec![];
    if let Err(e) = control.configure(state.start_type) {
        errors.push(format!("恢复 Winmgmt 启动配置：{e}"));
    }
    if state.running
        && let Err(e) = control.service("Winmgmt", true)
    {
        errors.push(format!("恢复 Winmgmt：{e}"));
    }
    for name in state.dependents.iter().rev() {
        if let Err(e) = control.service(name, true) {
            errors.push(format!("恢复依赖服务 {name}：{e}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("；"))
    }
}
struct Guard<'a, C: Control> {
    control: &'a mut C,
    state: State,
    finished: bool,
}
impl<C: Control> Drop for Guard<'_, C> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = restore(self.control, &self.state);
        }
    }
}
pub fn paused<C: Control, T>(
    control: &mut C,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    coordinated(control, true, operation)
}
fn coordinated<C: Control, T>(
    control: &mut C,
    disable_restart: bool,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let state = control.snapshot()?;
    let mut guard = Guard {
        control,
        state,
        finished: false,
    };
    let result = (|| {
        if disable_restart {
            guard.control.configure(4)?;
        } // Registration may start WMI; repository moves may not.
        for name in &guard.state.dependents {
            guard.control.service(name, false)?;
        }
        guard.control.service("Winmgmt", false)?;
        operation()
    })();
    let recovery = restore(guard.control, &guard.state);
    guard.finished = true;
    match (result, recovery) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(format!("仓库操作完成，但服务恢复失败：{error}")),
        (Err(error), Err(recovery)) => Err(format!("{error}；服务恢复也失败：{recovery}")),
    }
}
#[cfg(windows)]
mod native {
    use super::*;
    use std::{collections::HashSet, mem, ptr};
    use windows_sys::Win32::System::Services::*;
    struct Handle(SC_HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
    fn failure() -> String {
        std::io::Error::last_os_error().to_string()
    }
    fn wide(name: &str) -> Vec<u16> {
        name.encode_utf16().chain([0]).collect()
    }
    struct Native {
        manager: Handle,
        wmi: Handle,
    }
    impl Native {
        fn new() -> Result<Self, String> {
            let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
            if manager.is_null() {
                return Err(failure());
            }
            let manager = Handle(manager);
            let wmi = unsafe {
                OpenServiceW(
                    manager.0,
                    wide("Winmgmt").as_ptr(),
                    SERVICE_QUERY_CONFIG
                        | SERVICE_QUERY_STATUS
                        | SERVICE_CHANGE_CONFIG
                        | SERVICE_ENUMERATE_DEPENDENTS,
                )
            };
            if wmi.is_null() {
                return Err(failure());
            }
            Ok(Self {
                manager,
                wmi: Handle(wmi),
            })
        }
        fn dependents(&self, handle: SC_HANDLE) -> Result<Vec<String>, String> {
            let (mut needed, mut count) = (0, 0);
            if unsafe {
                EnumDependentServicesW(
                    handle,
                    SERVICE_ACTIVE,
                    ptr::null_mut(),
                    0,
                    &mut needed,
                    &mut count,
                )
            } != 0
            {
                return Ok(vec![]);
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(234) {
                return Err(failure());
            }
            if needed == 0 || needed > 1024 * 1024 {
                return Err("依赖服务列表大小无效".into());
            }
            let mut buffer = vec![0usize; (needed as usize).div_ceil(mem::size_of::<usize>())];
            if unsafe {
                EnumDependentServicesW(
                    handle,
                    SERVICE_ACTIVE,
                    buffer.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                    &mut count,
                )
            } == 0
            {
                return Err(failure());
            }
            let bytes = buffer.len() * mem::size_of::<usize>();
            if count as usize > bytes / mem::size_of::<ENUM_SERVICE_STATUSW>() {
                return Err("依赖服务数量越界".into());
            }
            let rows = unsafe {
                std::slice::from_raw_parts(
                    buffer.as_ptr().cast::<ENUM_SERVICE_STATUSW>(),
                    count as usize,
                )
            };
            let mut names = vec![];
            for row in rows {
                if row.ServiceStatus.dwCurrentState != SERVICE_RUNNING {
                    return Err("依赖服务正在转换状态或已暂停，请稍后重试".into());
                }
                let address = row.lpServiceName as usize;
                let base = buffer.as_ptr() as usize;
                if address < base || address >= base + bytes || !address.is_multiple_of(2) {
                    return Err("依赖服务名指针越界".into());
                }
                let words = unsafe {
                    std::slice::from_raw_parts(row.lpServiceName, (base + bytes - address) / 2)
                };
                let end = words.iter().position(|c| *c == 0).ok_or("服务名未终止")?;
                names.push(String::from_utf16(&words[..end]).map_err(|e| e.to_string())?);
            }
            names.sort();
            Ok(names)
        }
        fn collect(
            &self,
            handle: SC_HANDLE,
            seen: &mut HashSet<String>,
            visiting: &mut HashSet<String>,
            output: &mut Vec<String>,
        ) -> Result<(), String> {
            for name in self.dependents(handle)? {
                if name.eq_ignore_ascii_case("Winmgmt") {
                    return Err("检测到 Winmgmt 循环依赖".into());
                }
                let identity = name.to_ascii_lowercase();
                if visiting.contains(&identity) {
                    return Err("检测到依赖服务循环".into());
                }
                if !seen.insert(identity.clone()) {
                    continue;
                }
                if seen.len() > 64 {
                    return Err("Winmgmt 活动依赖超过 64 项".into());
                }
                let dependent = unsafe {
                    OpenServiceW(
                        self.manager.0,
                        wide(&name).as_ptr(),
                        SERVICE_ENUMERATE_DEPENDENTS,
                    )
                };
                if dependent.is_null() {
                    return Err(failure());
                }
                let dependent = Handle(dependent);
                visiting.insert(identity.clone());
                self.collect(dependent.0, seen, visiting, output)?;
                visiting.remove(&identity);
                output.push(name);
            }
            Ok(())
        }
    }
    impl Control for Native {
        fn snapshot(&mut self) -> Result<State, String> {
            let mut needed = 0;
            unsafe {
                QueryServiceConfigW(self.wmi.0, ptr::null_mut(), 0, &mut needed);
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(122)
                || needed == 0
                || needed > 65536
            {
                return Err("无法读取 Winmgmt 原始配置".into());
            }
            let mut buffer = vec![0usize; (needed as usize).div_ceil(mem::size_of::<usize>())];
            if unsafe {
                QueryServiceConfigW(self.wmi.0, buffer.as_mut_ptr().cast(), needed, &mut needed)
            } == 0
            {
                return Err(failure());
            }
            let config = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
            if !matches!(
                config.dwStartType,
                SERVICE_AUTO_START | SERVICE_DEMAND_START | SERVICE_DISABLED
            ) {
                return Err("Winmgmt 启动配置无效".into());
            }
            let mut status = SERVICE_STATUS::default();
            if unsafe { QueryServiceStatus(self.wmi.0, &mut status) } == 0 {
                return Err(failure());
            }
            if !matches!(status.dwCurrentState, SERVICE_RUNNING | SERVICE_STOPPED) {
                return Err("Winmgmt 正在转换状态或已暂停，请稍后重试".into());
            }
            let mut dependents = vec![];
            self.collect(
                self.wmi.0,
                &mut HashSet::new(),
                &mut HashSet::new(),
                &mut dependents,
            )?;
            Ok(State {
                start_type: config.dwStartType,
                running: status.dwCurrentState == SERVICE_RUNNING,
                dependents,
            })
        }
        fn configure(&mut self, start_type: u32) -> Result<(), String> {
            if unsafe {
                ChangeServiceConfigW(
                    self.wmi.0,
                    SERVICE_NO_CHANGE,
                    start_type,
                    SERVICE_NO_CHANGE,
                    ptr::null(),
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                )
            } == 0
            {
                Err(failure())
            } else {
                Ok(())
            }
        }
        fn service(&mut self, name: &str, start: bool) -> Result<(), String> {
            crate::native::platform::service(name, start)
        }
    }
    pub fn stopped<T>(operation: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        paused(&mut Native::new()?, operation)
    }
    pub fn registration<T>(operation: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        coordinated(&mut Native::new()?, false, operation)
    }
    #[cfg(test)]
    #[test]
    fn service_snapshot_is_read_only() {
        let mut service = Native::new().unwrap();
        let state = service.snapshot().unwrap();
        assert!(matches!(state.start_type, 2..=4));
        assert!(state.dependents.len() <= 64);
    }
}
#[cfg(windows)]
pub use native::{registration, stopped};
#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        events: Vec<String>,
        fail: Option<String>,
        running: bool,
    }
    impl Control for Fake {
        fn snapshot(&mut self) -> Result<State, String> {
            self.events.push("snapshot".into());
            Ok(State {
                start_type: 3,
                running: self.running,
                dependents: vec!["child".into(), "parent".into()],
            })
        }
        fn configure(&mut self, start: u32) -> Result<(), String> {
            self.event(format!("config:{start}"))
        }
        fn service(&mut self, name: &str, start: bool) -> Result<(), String> {
            self.event(format!("{name}:{start}"))
        }
    }
    impl Fake {
        fn event(&mut self, name: String) -> Result<(), String> {
            self.events.push(name.clone());
            if self.fail.as_ref() == Some(&name) {
                Err(name)
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn pauses_dependents_in_order_and_restores_every_original_state() {
        let mut fake = Fake {
            events: vec![],
            fail: None,
            running: true,
        };
        assert_eq!(paused(&mut fake, || Ok(42)).unwrap(), 42);
        assert_eq!(
            fake.events,
            [
                "snapshot",
                "config:4",
                "child:false",
                "parent:false",
                "Winmgmt:false",
                "config:3",
                "Winmgmt:true",
                "parent:true",
                "child:true"
            ]
        );
        let mut fake = Fake {
            events: vec![],
            fail: None,
            running: false,
        };
        assert!(paused(&mut fake, || Err::<(), _>("repository failure".into())).is_err());
        assert!(!fake.events.iter().any(|s| s == "Winmgmt:true"));
    }
    #[test]
    fn registration_stops_dependencies_but_allows_provider_tools_to_start_wmi() {
        let mut fake = Fake {
            events: vec![],
            fail: None,
            running: true,
        };
        coordinated(&mut fake, false, || Ok(())).unwrap();
        assert!(!fake.events.iter().any(|e| e == "config:4"));
        assert!(fake.events.iter().any(|e| e == "Winmgmt:false"));
        assert!(fake.events.iter().any(|e| e == "Winmgmt:true"));
    }
    #[test]
    fn every_pause_failure_restores_configuration_and_skips_repository() {
        for fail in ["config:4", "child:false", "parent:false", "Winmgmt:false"] {
            let mut fake = Fake {
                events: vec![],
                fail: Some(fail.into()),
                running: true,
            };
            assert!(
                paused(&mut fake, || -> Result<(), String> {
                    panic!("must not move repository")
                })
                .is_err()
            );
            assert!(fake.events.ends_with(&[
                "config:3".into(),
                "Winmgmt:true".into(),
                "parent:true".into(),
                "child:true".into()
            ]));
        }
    }
    #[test]
    fn aggregates_recovery_errors_and_restores_on_unwind() {
        let mut fake = Fake {
            events: vec![],
            fail: Some("config:3".into()),
            running: true,
        };
        let error = paused(&mut fake, || Err::<(), _>("repository failure".into())).unwrap_err();
        assert!(error.contains("repository failure") && error.contains("config:3"));
        assert_eq!(fake.events.last().unwrap(), "child:true");
        let mut fake = Fake {
            events: vec![],
            fail: None,
            running: true,
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = paused(&mut fake, || -> Result<(), String> { panic!("fixture") });
        }));
        assert!(result.is_err());
        assert_eq!(fake.events.last().unwrap(), "child:true");
    }
}
