//! Stop/restore coordination; callers keep the global licensing mutex held.
trait Control {
    fn running(&mut self) -> Result<bool, String>;
    fn stop(&mut self) -> Result<(), String>;
    fn start(&mut self) -> Result<(), String>;
}

struct Paused<'a, S: Control> {
    service: &'a mut S,
    restart: bool,
    finished: bool,
}
impl<S: Control> Drop for Paused<'_, S> {
    fn drop(&mut self) {
        // Normal errors are returned explicitly below. This is only the unwind fallback.
        if self.restart && !self.finished {
            let _ = self.service.start();
        }
    }
}
fn with_stopped<S: Control, T>(
    service: &mut S,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let restart = service.running()?;
    let mut paused = Paused {
        service,
        restart,
        finished: false,
    };
    let result = paused.service.stop().and_then(|_| operation());
    let restored = if paused.restart {
        paused.service.start()
    } else {
        Ok(())
    };
    paused.finished = true;
    match (result, restored) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(format!("存储操作完成，但服务恢复失败：{error}")),
        (Err(operation), Err(restore)) => Err(format!("{operation}；服务恢复也失败：{restore}")),
    }
}

#[cfg(windows)]
#[allow(
    dead_code,
    reason = "used when staged TSforge store operations are connected"
)]
pub fn stopped<T>(
    service_name: &str,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    use std::ptr;
    use windows_sys::Win32::System::Services::*;
    struct Handle(SC_HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
    struct Native<'a>(&'a str);
    impl Control for Native<'_> {
        fn running(&mut self) -> Result<bool, String> {
            let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
            if manager.is_null() {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let manager = Handle(manager);
            let name: Vec<_> = self.0.encode_utf16().chain([0]).collect();
            let handle = unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_STATUS) };
            if handle.is_null() {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let handle = Handle(handle);
            let mut status = SERVICE_STATUS::default();
            if unsafe { QueryServiceStatus(handle.0, &mut status) } == 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            match status.dwCurrentState {
                SERVICE_RUNNING | SERVICE_START_PENDING => Ok(true),
                SERVICE_STOPPED | SERVICE_STOP_PENDING => Ok(false),
                value => Err(format!("服务 {} 处于不支持的状态 {value}", self.0)),
            }
        }
        fn stop(&mut self) -> Result<(), String> {
            crate::native::platform::service(self.0, false)
        }
        fn start(&mut self) -> Result<(), String> {
            crate::native::platform::service(self.0, true)
        }
    }
    if service_name.contains('\0') {
        return Err("服务名包含 NUL".into());
    }
    with_stopped(&mut Native(service_name), operation)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Mock {
        running: bool,
        fail_stop: bool,
        fail_start: bool,
        calls: Vec<&'static str>,
    }
    impl Control for Mock {
        fn running(&mut self) -> Result<bool, String> {
            self.calls.push("query");
            Ok(self.running)
        }
        fn stop(&mut self) -> Result<(), String> {
            self.calls.push("stop");
            self.running = false;
            if self.fail_stop {
                Err("stop failure".into())
            } else {
                Ok(())
            }
        }
        fn start(&mut self) -> Result<(), String> {
            self.calls.push("start");
            if self.fail_start {
                Err("start failure".into())
            } else {
                self.running = true;
                Ok(())
            }
        }
    }
    #[test]
    fn restores_initial_running_state_after_success_or_failure() {
        for fail in [false, true] {
            let mut service = Mock {
                running: true,
                ..Default::default()
            };
            let result = with_stopped(&mut service, || {
                if fail {
                    Err("operation".into())
                } else {
                    Ok(42)
                }
            });
            assert_eq!(result.is_err(), fail);
            assert!(service.running);
            assert_eq!(service.calls, ["query", "stop", "start"]);
        }
        let mut service = Mock::default();
        with_stopped(&mut service, || Ok(())).unwrap();
        assert_eq!(service.calls, ["query", "stop"]);
        assert!(!service.running);
    }
    #[test]
    fn stop_failure_prevents_operation_but_still_attempts_restore() {
        let mut service = Mock {
            running: true,
            fail_stop: true,
            ..Default::default()
        };
        assert!(
            with_stopped(&mut service, || -> Result<(), String> {
                panic!("must not execute");
            })
            .is_err()
        );
        assert!(service.running);
        assert_eq!(service.calls, ["query", "stop", "start"]);
    }
    #[test]
    fn reports_both_errors_and_restores_during_unwind() {
        let mut service = Mock {
            running: true,
            fail_start: true,
            ..Default::default()
        };
        let error = with_stopped(&mut service, || -> Result<(), String> {
            Err("operation failure".into())
        })
        .unwrap_err();
        assert!(error.contains("operation failure") && error.contains("start failure"));
        let mut service = Mock {
            running: true,
            ..Default::default()
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = with_stopped(&mut service, || -> Result<(), String> {
                panic!("test unwind");
            });
        }));
        assert!(result.is_err());
        assert!(service.running);
    }
}
