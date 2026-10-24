//! Native HWID/KMS38 dispatch and explicit upstream compatibility backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Operation {
    pub title: &'static str,
    pub category: &'static str,
    pub args: &'static [&'static str],
    pub legacy: bool,
}

pub const OPERATIONS: &[Operation] = &[
    Operation {
        title: "HWID · Windows 数字许可证",
        category: "HWID",
        args: &["/HWID"],
        legacy: false,
    },
    Operation {
        title: "Ohook · Office 激活",
        category: "Ohook",
        args: &["/Ohook"],
        legacy: false,
    },
    Operation {
        title: "卸载 Ohook",
        category: "Ohook",
        args: &["/Ohook-Uninstall"],
        legacy: false,
    },
    Operation {
        title: "Windows",
        category: "TSforge",
        args: &["/Z-Windows"],
        legacy: false,
    },
    Operation {
        title: "Office",
        category: "TSforge",
        args: &["/Z-Office"],
        legacy: false,
    },
    Operation {
        title: "ESU 扩展安全更新",
        category: "TSforge",
        args: &["/Z-ESU"],
        legacy: false,
    },
    Operation {
        title: "Project / Visio",
        category: "TSforge",
        args: &["/Z-ProjectVisio"],
        legacy: false,
    },
    Operation {
        title: "Windows + Office + ESU",
        category: "TSforge",
        args: &["/Z-WindowsESUOffice"],
        legacy: false,
    },
    Operation {
        title: "Windows KMS Host",
        category: "TSforge",
        args: &["/Z-WinHost"],
        legacy: false,
    },
    Operation {
        title: "Office KMS Host",
        category: "TSforge",
        args: &["/Z-OffHost"],
        legacy: false,
    },
    Operation {
        title: "APPX",
        category: "TSforge",
        args: &["/Z-APPX"],
        legacy: false,
    },
    Operation {
        title: "重置激活计数",
        category: "TSforge",
        args: &["/Z-Reset"],
        legacy: false,
    },
    Operation {
        title: "Windows",
        category: "Online KMS",
        args: &["/K-Windows"],
        legacy: false,
    },
    Operation {
        title: "Office",
        category: "Online KMS",
        args: &["/K-Office"],
        legacy: false,
    },
    Operation {
        title: "Project / Visio",
        category: "Online KMS",
        args: &["/K-ProjectVisio"],
        legacy: false,
    },
    Operation {
        title: "Windows + Office",
        category: "Online KMS",
        args: &["/K-WindowsOffice"],
        legacy: false,
    },
    Operation {
        title: "清除 KMS 配置 / 本程序续期任务",
        category: "Online KMS",
        args: &["/K-Uninstall"],
        legacy: false,
    },
    Operation {
        title: "完整版兼容菜单（Office 修复 / 旧任务卸载）",
        category: "Online KMS",
        args: &[],
        legacy: false,
    },
    Operation {
        title: "KMS38 · 历史兼容模式",
        category: "KMS38",
        args: &["/KMS38"],
        legacy: true,
    },
    Operation {
        title: "KMS38 完整交互菜单",
        category: "KMS38",
        args: &[],
        legacy: true,
    },
    Operation {
        title: "完整 MAS 菜单 · 状态 / 版本切换 / 排障 / OEM",
        category: "工具箱",
        args: &[],
        legacy: false,
    },
];

#[derive(Clone)]
pub struct Options {
    pub no_edition_change: bool,
    pub no_renewal: bool,
    pub ts_method: usize,
    pub kms_server: String,
    pub kms_port: u16,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            no_edition_change: false,
            no_renewal: false,
            ts_method: 0,
            kms_server: String::new(),
            kms_port: 1688,
        }
    }
}

pub fn arguments(op: Operation, options: &Options) -> Vec<&'static str> {
    let mut args = op.args.to_vec();
    if args.is_empty() {
        return args;
    }
    if options.no_edition_change {
        match op.category {
            "HWID" => args.push("/HWID-NoEditionChange"),
            "KMS38" => args.push("/KMS38-NoEditionChange"),
            "Online KMS" => args.push("/K-NoEditionChange"),
            _ => {}
        }
    }
    if op.category == "Online KMS" && options.no_renewal {
        args.push("/K-NoRenewalTask");
    }
    if op.category == "TSforge"
        && let Some(method) =
            ["/Z-SCID", "/Z-ZCID", "/Z-KMS4k"].get(options.ts_method.wrapping_sub(1))
    {
        args.push(method);
    }
    args
}

#[cfg(not(windows))]
pub fn run(_op: Operation, _options: Options, _report: &dyn Fn(&str)) -> Result<String, String> {
    Err("激活引擎仅支持 Windows。当前系统可以预览界面。".into())
}

#[cfg(windows)]
pub fn run(op: Operation, options: Options, report: &dyn Fn(&str)) -> Result<String, String> {
    let _guard = crate::native::session::OperationGuard::acquire()?;
    if op.args == ["/Z-Windows"] {
        return match crate::native::tsforge::activate_windows(options.ts_method, report)? {
            Some(result) => Ok(result),
            None => run_compatibility(op, options, report),
        };
    }
    if op.args == ["/Z-Reset"] {
        return crate::native::tsforge::reset(report);
    }
    if op.args == ["/Ohook"] {
        return crate::native::ohook::install(report);
    }
    if op.args == ["/Ohook-Uninstall"] {
        return crate::native::ohook::uninstall(report);
    }
    if op.category == "Online KMS" && !op.args.is_empty() {
        if op.args == ["/K-Uninstall"] {
            return crate::native::online::uninstall(report);
        }
        let scope = crate::native::kms::Scope::from_switch(op.args[0]).ok_or("未知 KMS 操作")?;
        return crate::native::online::run(scope, &options, false, report);
    }
    if is_native(op) {
        return crate::native::run(op, &options, report);
    }
    run_compatibility(op, options, report)
}

pub fn restore_tsforge(backup: &str, report: &dyn Fn(&str)) -> Result<String, String> {
    #[cfg(windows)]
    {
        let _guard = crate::native::session::OperationGuard::acquire()?;
        crate::native::tsforge::restore(std::path::Path::new(backup), report)
    }
    #[cfg(not(windows))]
    {
        let _ = (backup, report);
        Err("TSforge 恢复需要在 Windows 上运行".into())
    }
}

pub fn is_native(op: Operation) -> bool {
    matches!(
        op.args,
        ["/Ohook"] | ["/Ohook-Uninstall"] | ["/Z-Reset"] | ["/Z-Windows"]
    ) || (!op.args.is_empty() && matches!(op.category, "HWID" | "KMS38" | "Online KMS"))
}

#[cfg(windows)]
fn run_compatibility(
    op: Operation,
    options: Options,
    report: &dyn Fn(&str),
) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    if std::env::var("PROCESSOR_ARCHITEW6432").is_ok_and(|arch| !arch.is_empty()) {
        return Err("当前构建不支持跨架构仿真运行，请在 Windows x64 上运行。".into());
    }
    if !crate::process::is_admin() {
        return Err("请以管理员身份启动应用。".into());
    }
    let base =
        std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA 未定义")?)
            .join("MAS-Rust");
    let runs = base.join("engine-runs");
    let logs = base.join("logs");
    std::fs::create_dir_all(&runs).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&logs).map_err(|e| e.to_string())?;
    let dir = tempfile::Builder::new()
        .prefix("run-")
        .tempdir_in(runs)
        .map_err(|e| e.to_string())?;
    let payload: &[u8] = if op.legacy {
        include_bytes!("../vendor/mas/KMS38_Activation.cmd")
    } else {
        include_bytes!("../vendor/mas/MAS_AIO.cmd")
    };
    // Only fixed filenames and allowlisted arguments enter cmd; the temp path is the working directory.
    std::fs::write(dir.path().join("engine.cmd"), payload).map_err(|e| e.to_string())?;
    let args = arguments(op, &options);
    let interactive = args.is_empty();
    let launcher = launcher(&args);
    std::fs::write(dir.path().join("launch.cmd"), launcher).map_err(|e| e.to_string())?;
    let root = std::env::var_os("SystemRoot").ok_or("SystemRoot 未定义")?;
    report("兼容引擎：此功能仍依赖上游脚本及 Windows PowerShell。");
    report(&format!("工作目录：{}", dir.path().display()));
    let mut child = Command::new(std::path::PathBuf::from(root).join("System32/cmd.exe"))
        .arg("/D")
        .arg("/C")
        .arg("launch.cmd")
        .current_dir(dir.path())
        .creation_flags(if interactive { 0x00000010 } else { 0x08000000 })
        .spawn()
        .map_err(|e| format!("启动兼容引擎：{e}"))?;
    let mut read_offset = 0;
    let log_path = dir.path().join("engine.log");
    let status = loop {
        if !interactive && let Ok(bytes) = std::fs::read(&log_path) {
            let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
            if complete > read_offset {
                report(&String::from_utf8_lossy(&bytes[read_offset..complete]));
                read_offset = complete;
            }
        }
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    };
    let mut detail = String::new();
    if !interactive {
        let bytes = std::fs::read(&log_path).unwrap_or_default();
        if bytes.len() > read_offset {
            report(&String::from_utf8_lossy(&bytes[read_offset..]));
        }
        let saved = logs.join(format!(
            "{}.log",
            dir.path().file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(&saved, &bytes).map_err(|e| format!("保存引擎日志失败：{e}"))?;
        detail = format!("\n完整日志：{}", saved.display());
        if bytes.is_empty() {
            detail.push_str("\n脚本未产生输出；请确认文件没有被隔离且 cmd.exe 可以运行。");
        }
    }
    if status.success() {
        Ok(format!(
            "兼容引擎已退出。请查询许可证状态确认实际结果。{detail}"
        ))
    } else {
        Err(format!(
            "兼容引擎退出码 {}。请查看日志页中的原始错误。{detail}",
            status
                .code()
                .map_or_else(|| "未知".into(), |code| code.to_string())
        ))
    }
}

#[cfg(any(windows, test))]
fn launcher(args: &[&str]) -> String {
    let redirect = if args.is_empty() {
        ""
    } else {
        " > \"%~dp0engine.log\" 2>&1"
    };
    let pause = if args.is_empty() {
        "echo Engine exited. Press a key to close.\r\npause >nul\r\n"
    } else {
        ""
    };
    format!(
        "@echo off\r\nchcp 65001 >nul\r\ncall \"%~dp0engine.cmd\" -qedit {}{redirect}\r\nset result=%errorlevel%\r\n{pause}exit /b %result%\r\n",
        args.join(" ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compatibility_launcher_preserves_path_and_error_output() {
        let text = launcher(&["/Ohook"]);
        assert!(text.contains("call \"%~dp0engine.cmd\" -qedit /Ohook > \"%~dp0engine.log\" 2>&1"));
        assert!(text.contains("set result=%errorlevel%\r\n"));
        assert!(!text.contains("pause"));
        let menu = launcher(&[]);
        assert!(!menu.contains("engine.log"));
        assert!(menu.contains("pause >nul"));
    }
    #[test]
    fn native_dispatch_is_explicit() {
        for op in OPERATIONS {
            assert_eq!(
                is_native(*op),
                matches!(
                    op.args,
                    ["/HWID"]
                        | ["/Z-Reset"]
                        | ["/Z-Windows"]
                        | ["/Ohook"]
                        | ["/Ohook-Uninstall"]
                        | ["/KMS38"]
                        | ["/K-Windows"]
                        | ["/K-Office"]
                        | ["/K-ProjectVisio"]
                        | ["/K-WindowsOffice"]
                        | ["/K-Uninstall"]
                )
            );
        }
    }
    #[test]
    fn switches_exist_in_pinned_sources() {
        let current = include_str!("../vendor/mas/MAS_AIO.cmd");
        let legacy = include_str!("../vendor/mas/KMS38_Activation.cmd");
        for op in OPERATIONS {
            for arg in arguments(
                *op,
                &Options {
                    no_edition_change: true,
                    no_renewal: true,
                    ts_method: 3,
                    ..Default::default()
                },
            ) {
                assert!(
                    (if op.legacy { legacy } else { current }).contains(arg),
                    "{arg}"
                );
                assert!(
                    arg.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"/-".contains(&b))
                );
            }
        }
    }
    #[test]
    fn interactive_menu_never_receives_unattended_switches() {
        for op in OPERATIONS.iter().filter(|op| op.args.is_empty()) {
            assert!(
                arguments(
                    *op,
                    &Options {
                        no_edition_change: true,
                        no_renewal: true,
                        ts_method: 1,
                        ..Default::default()
                    }
                )
                .is_empty()
            );
        }
    }
}
