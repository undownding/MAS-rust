//! Full WMI repair sequencing and pinned provider registration plan.
#![cfg_attr(not(test), allow(dead_code))]
use super::wmi_repair::Backend;
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};
#[derive(Debug)]
pub struct Command {
    pub executable: PathBuf,
    pub args: Vec<OsString>,
}
pub fn registration_plan(system: &Path) -> Result<Vec<Command>, String> {
    fn files(
        root: &Path,
        recursive: bool,
        depth: usize,
        output: &mut Vec<PathBuf>,
    ) -> Result<(), String> {
        if depth > 32 {
            return Err("WBEM 目录层级过深".into());
        }
        let mut entries = std::fs::read_dir(root)
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        entries.sort_by_key(|e| e.file_name().to_string_lossy().to_ascii_lowercase());
        for entry in entries {
            let meta = entry.metadata().map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if name == "repository" || name.starts_with("mas-wmi-backup-") {
                continue;
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if meta.file_attributes() & 0x400 != 0 {
                    return Err("WBEM 注册源包含重解析点".into());
                }
            }
            if entry.file_type().map_err(|e| e.to_string())?.is_symlink() {
                return Err("WBEM 注册源包含符号链接".into());
            }
            if meta.is_dir() && recursive {
                files(&entry.path(), true, depth + 1, output)?;
            } else if meta.is_file() {
                output.push(entry.path());
            }
            if output.len() > 16384 {
                return Err("WBEM 注册源过多".into());
            }
        }
        Ok(())
    }
    if !system.is_absolute() {
        return Err("系统目录必须为绝对路径".into());
    }
    let wbem = system.join("wbem");
    let mut nested = vec![];
    files(&wbem, true, 0, &mut nested)?;
    let mut direct = vec![];
    files(&wbem, false, 0, &mut direct)?;
    let reg = system.join("regsvr32.exe");
    let mof = wbem.join("mofcomp.exe");
    let wmi = wbem.join("winmgmt.exe");
    for executable in [&reg, &mof, &wmi] {
        if !executable.is_file() {
            return Err(format!("缺少系统程序：{}", executable.display()));
        }
    }
    let mut commands = vec![];
    let register = |file: PathBuf| Command {
        executable: reg.clone(),
        args: vec!["/s".into(), file.into_os_string()],
    };
    let compile = |file: PathBuf| Command {
        executable: mof.clone(),
        args: vec![file.into_os_string()],
    };
    for name in ["scecli.dll", "userenv.dll"] {
        commands.push(register(system.join(name)));
    }
    for name in ["cimwin32.mof", "cimwin32.mfl", "rsop.mof", "rsop.mfl"] {
        commands.push(compile(wbem.join(name)));
    }
    for file in nested {
        if file
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("dll"))
        {
            commands.push(register(file));
        }
    }
    for extension in ["mof", "mfl"] {
        for file in &direct {
            if file
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case(extension))
            {
                commands.push(compile(file.clone()));
            }
        }
    }
    for arg in ["/salvagerepository", "/resetrepository"] {
        commands.push(Command {
            executable: wmi.clone(),
            args: vec![arg.into()],
        });
    }
    Ok(commands)
}
pub trait Rebuild: Backend {
    fn prepare(&mut self) -> Result<(), String>;
    fn quarantine(&mut self) -> Result<String, String>;
    fn register(&mut self) -> Result<(), String>;
}
pub fn run(backend: &mut impl Rebuild) -> Result<String, String> {
    if backend.server()? {
        return Err("Windows Server 按上游规则不执行 WMI 重建。".into());
    }
    if backend.check()?.healthy() {
        return Ok("WMI 检查通过，未修改仓库。".into());
    }
    let salvage = backend.salvage();
    if backend.check()?.healthy() {
        return Ok(format!(
            "WMI 基础修复后检查通过，未重建仓库。{}",
            salvage
                .err()
                .map(|e| format!(" salvage 报告：{e}"))
                .unwrap_or_default()
        ));
    }
    backend.prepare()?;
    let backup = backend.quarantine()?;
    let result = (|| {
        if backend.check()?.healthy() {
            return Ok("WMI 仓库重新生成后检查通过。".to_owned());
        }
        let registration = backend.register();
        let health = backend.check()?;
        if !health.healthy() {
            return Err(format!(
                "WMI 重建后检查仍失败：{}；注册结果：{registration:?}",
                health.failures.join("；")
            ));
        }
        match registration {
            Ok(()) => Ok("WMI 提供程序注册后检查通过。".into()),
            Err(e) => Err(format!("WMI 当前检查通过，但提供程序注册存在失败：{e}")),
        }
    })();
    let detail = format!("原仓库备份：{backup}；已执行的服务/提供程序修改不自动撤销。");
    result
        .map(|s| format!("{s}\n{detail}"))
        .map_err(|e| format!("{e}\n{detail}"))
}
#[cfg(test)]
mod tests {
    use super::super::wmi_repair::Health;
    use super::*;
    struct Fake {
        checks: usize,
        good_at: usize,
        events: Vec<&'static str>,
        fail: Option<&'static str>,
    }
    impl Fake {
        fn step(&mut self, s: &'static str) -> Result<(), String> {
            self.events.push(s);
            if self.fail == Some(s) {
                Err(s.into())
            } else {
                Ok(())
            }
        }
    }
    impl Backend for Fake {
        fn server(&mut self) -> Result<bool, String> {
            Ok(false)
        }
        fn check(&mut self) -> Result<Health, String> {
            self.checks += 1;
            Ok(Health {
                failures: if self.checks >= self.good_at {
                    vec![]
                } else {
                    vec!["broken".into()]
                },
                notes: vec![],
            })
        }
        fn salvage(&mut self) -> Result<(), String> {
            self.step("salvage")
        }
    }
    impl Rebuild for Fake {
        fn prepare(&mut self) -> Result<(), String> {
            self.step("prepare")
        }
        fn quarantine(&mut self) -> Result<String, String> {
            self.step("quarantine")?;
            Ok("backup".into())
        }
        fn register(&mut self) -> Result<(), String> {
            self.step("register")
        }
    }
    #[test]
    fn escalates_only_after_failed_checks_and_reports_registration_failures() {
        for good_at in 1..=5 {
            let mut fake = Fake {
                checks: 0,
                good_at,
                events: vec![],
                fail: None,
            };
            let result = run(&mut fake);
            assert_eq!(result.is_ok(), good_at <= 4);
            assert_eq!(fake.events.contains(&"quarantine"), good_at >= 3);
            assert_eq!(fake.events.contains(&"register"), good_at >= 4);
        }
        for fail in ["prepare", "quarantine", "register"] {
            let mut fake = Fake {
                checks: 0,
                good_at: 4,
                events: vec![],
                fail: Some(fail),
            };
            let error = run(&mut fake).unwrap_err();
            assert!(error.contains(fail));
            if fail != "register" {
                assert!(!fake.events.contains(&"register"));
            } else {
                assert!(error.contains("backup"));
            }
        }
    }
    #[test]
    fn registration_plan_recurses_dlls_but_only_compiles_root_mof_files() {
        let temp = tempfile::tempdir().unwrap();
        let system = temp.path();
        let wbem = system.join("wbem");
        std::fs::create_dir_all(wbem.join("nested")).unwrap();
        for path in [
            system.join("regsvr32.exe"),
            wbem.join("mofcomp.exe"),
            wbem.join("winmgmt.exe"),
            wbem.join("nested/provider.dll"),
            wbem.join("nested/ignored.mof"),
            wbem.join("root.mof"),
        ] {
            std::fs::write(path, b"fixture").unwrap();
        }
        let plan = registration_plan(system).unwrap();
        assert_eq!(plan.len(), 10);
        assert_eq!(plan[0].executable, system.join("regsvr32.exe"));
        assert!(plan.iter().any(|p| {
            p.args
                .contains(&wbem.join("nested/provider.dll").into_os_string())
        }));
        assert!(!plan.iter().any(|p| {
            p.args
                .contains(&wbem.join("nested/ignored.mof").into_os_string())
        }));
        assert_eq!(
            plan.last().unwrap().args,
            [OsString::from("/resetrepository")]
        );
        assert!(registration_plan(Path::new("relative")).is_err());
    }
}
