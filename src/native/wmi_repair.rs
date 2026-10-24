//! WMI health checks and the first salvage stage of the MAS repair routine.
#![cfg_attr(not(test), allow(dead_code))]
pub fn wmi_hresult(code: u32) -> bool {
    matches!(code & 0xffff_ff00, 0x8004_1000 | 0x8004_4000) || code == 0x8013_1501
}
#[derive(Debug)]
pub struct Health {
    pub failures: Vec<String>,
    pub notes: Vec<String>,
}
impl Health {
    pub fn healthy(&self) -> bool {
        self.failures.is_empty()
    }
}
pub trait Backend {
    fn server(&mut self) -> Result<bool, String>;
    fn check(&mut self) -> Result<Health, String>;
    fn salvage(&mut self) -> Result<(), String>;
}
pub fn repair(backend: &mut impl Backend) -> Result<String, String> {
    if backend.server()? {
        return Err("Windows Server 按上游规则不执行 WMI 修复。".into());
    }
    let before = backend.check()?;
    if before.healthy() {
        return Ok(format!(
            "WMI 检查通过，无需修复，未运行 salvage。\n{}",
            before.notes.join("\n")
        ));
    }
    let salvage = backend.salvage();
    let after = backend
        .check()
        .map_err(|e| format!("已尝试 WMI salvage，复查失败：{e}；不自动重试或重建仓库。"))?;
    let detail = salvage
        .err()
        .map(|e| format!("\nsalvage 报告：{e}"))
        .unwrap_or_default();
    if after.healthy() {
        Ok(format!(
            "WMI salvage 后检查通过。{detail}\n{}",
            after.notes.join("\n")
        ))
    } else {
        Err(format!(
            "WMI 基础修复后仍有异常：\n{}{detail}\n仓库重建和提供程序重新注册尚未迁移，请查看兼容菜单。",
            after.failures.join("\n")
        ))
    }
}
#[cfg(windows)]
mod native {
    use super::*;
    use crate::native::{licensing::string, platform};
    use std::{
        os::windows::process::CommandExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    use wmi::{WMIConnection, WMIError};
    struct Native<'a> {
        report: &'a dyn Fn(&str),
        plan: Option<Vec<crate::native::wmi_rebuild::Command>>,
    }
    fn command_args(
        executable: &std::path::Path,
        args: &[std::ffi::OsString],
        report: &dyn Fn(&str),
    ) -> Result<(), String> {
        let arg = format!("{} {:?}", executable.display(), args);
        let mut child = Command::new(executable)
            .args(args)
            .creation_flags(0x08000000)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        let start = Instant::now();
        let mut next = Duration::from_secs(15);
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|e| format!("修复进程可能仍运行：{e}"))?
            {
                return match status.code() {
                    Some(0) => Ok(()),
                    Some(code) => Err(format!("{arg}：{code} (0x{:08X})", code as u32)),
                    None => Err("修复进程未返回退出码".into()),
                };
            }
            if start.elapsed() >= next {
                report(&format!(
                    "{arg} 仍在运行，已等待 {} 秒",
                    start.elapsed().as_secs()
                ));
                next = start.elapsed() + Duration::from_secs(15);
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    fn command(arg: &str, report: &dyn Fn(&str)) -> Result<(), String> {
        command_args(
            &platform::system_file(r"wbem\winmgmt.exe")?,
            &[arg.into()],
            report,
        )
    }
    fn query(
        connection: &WMIConnection,
        query: &str,
    ) -> Result<Vec<wmi::IWbemClassWrapper>, WMIError> {
        connection.exec_query(query)?.collect()
    }
    impl Backend for Native<'_> {
        fn server(&mut self) -> Result<bool, String> {
            let system = platform::system_file("")?;
            let directory = system
                .parent()
                .ok_or("系统目录无效")?
                .join("Servicing/Packages");
            for entry in std::fs::read_dir(directory).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                if name.starts_with("microsoft-windows-server")
                    && name.contains("edition~")
                    && name.ends_with(".mum")
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        fn check(&mut self) -> Result<Health, String> {
            let mut health = Health {
                failures: vec![],
                notes: vec![],
            };
            match WMIConnection::new() {
                Err(e) => health.failures.push(format!("连接 WMI：{e}")),
                Ok(connection) => {
                    match query(
                        &connection,
                        "SELECT CreationClassName FROM Win32_ComputerSystem",
                    ) {
                        Ok(rows)
                            if rows.iter().any(|row| {
                                string(row, "CreationClassName").is_ok_and(|s| {
                                    s.to_ascii_lowercase().contains("computersystem")
                                })
                            }) =>
                        {
                            health.notes.push("Win32_ComputerSystem 查询通过".into())
                        }
                        Ok(_) => health
                            .failures
                            .push("Win32_ComputerSystem 未返回有效 CreationClassName".into()),
                        Err(e) => health.failures.push(format!("Win32_ComputerSystem：{e}")),
                    }
                    match query(&connection, "SELECT Version FROM SoftwareLicensingService") {
                        Ok(rows) => health.notes.push(format!(
                            "SoftwareLicensingService 查询完成：{} 项",
                            rows.len()
                        )),
                        Err(e) => {
                            let text = format!("SoftwareLicensingService：{e}");
                            if matches!(&e, WMIError::HResultError { hres } if wmi_hresult(*hres as u32))
                            {
                                health.failures.push(text);
                            } else {
                                health
                                    .notes
                                    .push(format!("非上游 WMI 损坏错误，不据此重建仓库：{text}"));
                            }
                        }
                    }
                }
            }
            match command("/verifyrepository", self.report) {
                Ok(()) => health.notes.push("WMI 仓库一致性检查通过".into()),
                Err(e) => health.failures.push(e),
            }
            for note in &health.notes {
                (self.report)(note);
            }
            for error in &health.failures {
                (self.report)(&format!("检查异常：{error}"));
            }
            Ok(health)
        }
        fn salvage(&mut self) -> Result<(), String> {
            (self.report)("尝试 WMI /salvagerepository；完成后重新检查，不自动删除仓库。");
            command("/salvagerepository", self.report)
        }
    }
    impl crate::native::wmi_rebuild::Rebuild for Native<'_> {
        fn prepare(&mut self) -> Result<(), String> {
            self.plan = Some(crate::native::wmi_rebuild::registration_plan(
                &platform::system_file("")?,
            )?);
            Ok(())
        }
        fn quarantine(&mut self) -> Result<String, String> {
            let repository = platform::system_file(r"wbem\Repository")?;
            let mut checkpoint = None;
            let result = crate::native::wmi_service::stopped(|| {
                if !repository.try_exists().map_err(|e| e.to_string())? {
                    (self.report)("WMI 原仓库不存在；恢复服务后重新检查。");
                    return Ok("原仓库不存在，无目录备份".to_owned());
                }
                let backup = crate::native::wmi_repository::quarantine(&repository)
                    .map_err(|e| e.to_string())?;
                let path = backup.root.display().to_string();
                checkpoint = Some(path.clone());
                (self.report)(&format!("WMI 原仓库已保留：{path}"));
                Ok(path)
            });
            result.map_err(|e| format!("WMI 仓库阶段失败：{e}；备份：{checkpoint:?}"))
        }
        fn register(&mut self) -> Result<(), String> {
            let plan = self.plan.take().ok_or("未准备 WMI 提供程序注册计划")?;
            crate::native::wmi_service::registration(|| {
                let mut errors = vec![];
                for item in plan {
                    (self.report)(&format!(
                        "运行 {} {:?}",
                        item.executable.display(),
                        item.args
                    ));
                    if let Err(e) = command_args(&item.executable, &item.args, self.report) {
                        errors.push(e);
                    }
                }
                if errors.is_empty() {
                    Ok(())
                } else {
                    Err(errors.join("\n"))
                }
            })
        }
    }
    pub fn restore(backup: &std::path::Path, report: &dyn Fn(&str)) -> Result<String, String> {
        let _guard = crate::native::session::OperationGuard::acquire()?;
        if !crate::process::is_admin() {
            return Err("请以管理员身份运行".into());
        }
        if std::env::var("PROCESSOR_ARCHITEW6432").is_ok_and(|v| !v.is_empty()) {
            return Err("WMI 恢复不支持跨架构仿真".into());
        }
        let mut native = Native { report, plan: None };
        if native.server()? {
            return Err("Windows Server 不执行此 WMI 仓库恢复".into());
        }
        let repository = platform::system_file(r"wbem\Repository")?;
        let loaded = crate::native::wmi_repository::Backup::load(backup, &repository)
            .map_err(|e| e.to_string())?;
        let mut replacement = None;
        crate::native::wmi_service::stopped(|| {
            replacement = loaded.restore().map_err(|e| e.to_string())?;
            report(&format!("原仓库已恢复；替换前仓库备份：{replacement:?}"));
            Ok(())
        })
        .map_err(|e| format!("WMI 恢复失败：{e}；替换前仓库：{replacement:?}"))?;
        let health = native.check()?;
        if health.healthy() {
            Ok(format!(
                "WMI 仓库恢复后检查通过；替换前仓库备份：{replacement:?}"
            ))
        } else {
            Err(format!(
                "WMI 仓库已恢复但检查仍异常：{}；替换前仓库：{replacement:?}",
                health.failures.join("；")
            ))
        }
    }
    pub fn rebuild(report: &dyn Fn(&str)) -> Result<String, String> {
        let _guard = crate::native::session::OperationGuard::acquire()?;
        if !crate::process::is_admin() {
            return Err("请以管理员身份运行".into());
        }
        if std::env::var("PROCESSOR_ARCHITEW6432").is_ok_and(|v| !v.is_empty()) {
            return Err("WMI 重建不支持跨架构仿真".into());
        }
        crate::native::wmi_rebuild::run(&mut Native { report, plan: None })
    }
    pub fn run(fix: bool, report: &dyn Fn(&str)) -> Result<String, String> {
        let _guard = crate::native::session::OperationGuard::acquire()?;
        if !crate::process::is_admin() {
            return Err("请以管理员身份运行".into());
        }
        if std::env::var("PROCESSOR_ARCHITEW6432").is_ok_and(|v| !v.is_empty()) {
            return Err("WMI 检查/修复不支持跨架构仿真".into());
        }
        let mut native = Native { report, plan: None };
        if fix {
            repair(&mut native)
        } else {
            let health = native.check()?;
            if health.healthy() {
                Ok("WMI 检查通过，未执行修复。".into())
            } else {
                Err(format!(
                    "WMI 检查存在异常，未执行修复：\n{}",
                    health.failures.join("\n")
                ))
            }
        }
    }
}
#[cfg(windows)]
pub use native::{rebuild, restore, run};
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn licensing_hresult_filter_does_not_treat_access_denied_as_corruption() {
        for code in [0x80041001, 0x80041010, 0x80044001, 0x80131501] {
            assert!(wmi_hresult(code));
        }
        for code in [0, 0x80070005, 0x800706ba, 0x80131502] {
            assert!(!wmi_hresult(code));
        }
    }
    struct Fake {
        server: bool,
        checks: usize,
        salvage: usize,
        healthy_before: bool,
        healthy_after: bool,
    }
    impl Backend for Fake {
        fn server(&mut self) -> Result<bool, String> {
            Ok(self.server)
        }
        fn check(&mut self) -> Result<Health, String> {
            self.checks += 1;
            let healthy = if self.checks == 1 {
                self.healthy_before
            } else {
                self.healthy_after
            };
            Ok(Health {
                failures: if healthy {
                    vec![]
                } else {
                    vec!["failed".into()]
                },
                notes: vec![],
            })
        }
        fn salvage(&mut self) -> Result<(), String> {
            self.salvage += 1;
            Ok(())
        }
    }
    #[test]
    fn repair_gates_and_postcheck_control_result_without_repeated_salvage() {
        for server in [false, true] {
            for before in [false, true] {
                for after in [false, true] {
                    let mut fake = Fake {
                        server,
                        checks: 0,
                        salvage: 0,
                        healthy_before: before,
                        healthy_after: after,
                    };
                    assert_eq!(repair(&mut fake).is_ok(), !server && (before || after));
                    assert_eq!(fake.salvage, usize::from(!server && !before));
                    assert_eq!(
                        fake.checks,
                        if server {
                            0
                        } else if before {
                            1
                        } else {
                            2
                        }
                    );
                }
            }
        }
    }
}
