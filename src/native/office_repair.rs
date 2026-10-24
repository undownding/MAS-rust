//! Native implementation of the pinned MAS Office repair launcher.
#![cfg_attr(not(test), allow(dead_code))]
use std::path::PathBuf;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Msi,
    C2r15,
    C2r16,
}
impl Kind {
    pub fn args(self) -> &'static [&'static str] {
        match self {
            Self::Msi => &[],
            Self::C2r15 => &["REPAIRUI", "RERUNMODE"],
            Self::C2r16 => &["Scenario=Repair", "RepairType=QuickRepair"],
        }
    }
}
#[derive(Debug)]
pub struct Repair {
    pub label: String,
    pub executable: PathBuf,
    pub kind: Kind,
}
/// Launch each distinct installer once, retaining failures from other installs.
pub fn execute(
    repairs: &[Repair],
    mut launch: impl FnMut(&Repair) -> Result<i32, String>,
) -> Result<String, String> {
    let mut seen = std::collections::HashSet::new();
    let mut errors = vec![];
    let mut completed = 0;
    for repair in repairs {
        if !repair.executable.is_absolute() {
            errors.push(format!("{}：修复程序路径不是绝对路径", repair.label));
            continue;
        }
        if !seen.insert(repair.executable.to_string_lossy().to_lowercase()) {
            continue;
        }
        match launch(repair) {
            Ok(0) => completed += 1,
            Ok(code) => errors.push(format!("{}：修复程序退出码 {code}", repair.label)),
            Err(e) => errors.push(format!("{}：{e}", repair.label)),
        }
    }
    let summary = format!(
        "{completed} 个 Office 修复程序已正常退出；退出码不代表许可或修复结果已经验证。请打开 Office 检查。"
    );
    if errors.is_empty() {
        Ok(summary)
    } else {
        Err(format!("{summary}\n{}", errors.join("\n")))
    }
}
#[cfg(windows)]
mod native {
    use super::*;
    use crate::native::{platform, registry::Key};
    use std::{path::Path, process::Command};
    use windows_sys::Win32::System::Registry::{KEY_WOW64_32KEY, KEY_WOW64_64KEY};
    const OFFICE: &str = r"SOFTWARE\Microsoft\Office";
    fn value(path: &str, view: u32, name: &str) -> Result<Option<String>, String> {
        Key::open(path, view, false)?
            .map(|key| key.string(name))
            .transpose()
            .map(Option::flatten)
    }
    fn contains(path: &Path, prefix: &str, suffix: &str) -> Result<bool, String> {
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(format!("读取 {}：{e}", path.display())),
        };
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if name.starts_with(prefix)
                && name.ends_with(suffix)
                && entry.file_type().map_err(|e| e.to_string())?.is_file()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub fn discover(report: &dyn Fn(&str)) -> Result<Vec<Repair>, String> {
        let system = platform::system_file("")?;
        let drive = system
            .parent()
            .and_then(Path::parent)
            .ok_or("无法确定 Windows 系统盘")?;
        let mut repairs = vec![];
        let mut problems = vec![];
        for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            let arch = if view == KEY_WOW64_64KEY {
                "x64"
            } else {
                "x86"
            };
            for version in [14, 15, 16] {
                if let Some(root) = value(
                    &format!(r"{OFFICE}\{version}.0\Common\InstallRoot"),
                    view,
                    "Path",
                )? && contains(Path::new(&root), "", "picker.dll")?
                {
                    let label = format!("Office {version} MSI {arch}");
                    report(&format!("发现 {label}"));
                    let executable = ["Program Files (x86)", "Program Files"].into_iter().map(|p| drive.join(p).join(format!(r"Common Files\Microsoft Shared\OFFICE{version}\Office Setup Controller\setup.exe"))).rfind(|p| p.is_file());
                    if let Some(executable) = executable {
                        repairs.push(Repair {
                            label,
                            executable,
                            kind: Kind::Msi,
                        });
                    } else {
                        problems.push(format!("{label} 缺少 Setup Controller"));
                    }
                }
            }
            if let Some(key) = Key::open(&format!(r"{OFFICE}\14.0\CVH"), view, false)?
                && key
                    .children()?
                    .iter()
                    .any(|k| k.to_ascii_lowercase().contains("click2run"))
            {
                report("Office 2010 C2R：按上游规则跳过修复。");
            }
            for version in [15, 16] {
                let root = if version == 15 {
                    format!(r"{OFFICE}\15.0\ClickToRun")
                } else {
                    format!(r"{OFFICE}\ClickToRun")
                };
                let Some(install) = value(&root, view, "InstallPath")? else {
                    continue;
                };
                let licenses = Path::new(&install).join("root").join(if version == 15 {
                    "Licenses"
                } else {
                    "Licenses16"
                });
                if !contains(&licenses, "proplus", ".xrm-ms")? {
                    continue;
                }
                let label = format!("Office {version} C2R {arch}");
                report(&format!("发现 {label}"));
                let executable = if version == 15 {
                    ["ClientX86", "ClientX64"]
                        .into_iter()
                        .map(|c| {
                            drive
                                .join("Program Files")
                                .join("Microsoft Office 15")
                                .join(c)
                                .join("integratedoffice.exe")
                        })
                        .rfind(|p| p.is_file())
                } else {
                    let mut found = None;
                    for config_view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
                        if let Some(folder) = value(
                            &format!(r"{OFFICE}\ClickToRun\Configuration"),
                            config_view,
                            "ClientFolder",
                        )? {
                            let file = PathBuf::from(folder).join("OfficeClickToRun.exe");
                            if file.is_file() {
                                found = Some(file);
                            }
                        }
                    }
                    found
                };
                if let Some(executable) = executable {
                    repairs.push(Repair {
                        label,
                        executable,
                        kind: if version == 15 {
                            Kind::C2r15
                        } else {
                            Kind::C2r16
                        },
                    });
                } else {
                    problems.push(format!("{label} 缺少修复程序"));
                }
            }
        }
        // UWP has no repair command in the upstream routine; leave it untouched.
        if !problems.is_empty() {
            return Err(problems.join("\n"));
        }
        Ok(repairs)
    }
    pub fn run(report: &dyn Fn(&str)) -> Result<String, String> {
        let _guard = crate::native::session::OperationGuard::acquire()?;
        if !crate::process::is_admin() {
            return Err("请以管理员身份运行".into());
        }
        let repairs = discover(report)?;
        if repairs.is_empty() {
            return Err(
                "未发现可启动的 Office MSI/C2R 修复程序；Office 2010 C2R 和 UWP 不在此修复范围。"
                    .into(),
            );
        }
        report("将打开 Office 修复程序。若出现选项，请选择快速修复；等待修复窗口关闭。");
        execute(&repairs, |repair| {
            report(&format!(
                "启动 {}：{}",
                repair.label,
                repair.executable.display()
            ));
            let status = Command::new(&repair.executable)
                .args(repair.kind.args())
                .status()
                .map_err(|e| e.to_string())?;
            status.code().ok_or_else(|| "修复进程没有退出码".into())
        })
    }
    #[cfg(test)]
    #[test]
    fn discovery_does_not_launch_installers() {
        discover(&|_| {}).unwrap();
    }
}
#[cfg(windows)]
pub use native::run;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn commands_are_structured_and_duplicate_installers_run_once() {
        assert_eq!(Kind::C2r15.args(), ["REPAIRUI", "RERUNMODE"]);
        assert_eq!(
            Kind::C2r16.args(),
            ["Scenario=Repair", "RepairType=QuickRepair"]
        );
        assert!(Kind::Msi.args().is_empty());
        let path = std::env::temp_dir().join("repair fixture.exe");
        let repairs = [
            Repair {
                label: "a".into(),
                executable: path.clone(),
                kind: Kind::Msi,
            },
            Repair {
                label: "b".into(),
                executable: path,
                kind: Kind::Msi,
            },
            Repair {
                label: "c".into(),
                executable: "relative.exe".into(),
                kind: Kind::C2r16,
            },
        ];
        let mut calls = 0;
        let error = execute(&repairs, |repair| {
            assert!(repair.kind.args().is_empty());
            calls += 1;
            Ok(42)
        })
        .unwrap_err();
        assert_eq!(calls, 1);
        assert!(error.contains("42") && error.contains("绝对路径"));
        assert!(
            execute(&repairs[..1], |_| Ok(0))
                .unwrap()
                .contains("不代表")
        );
    }
}
