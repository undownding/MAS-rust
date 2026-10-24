//! Fixed upstream engines. No scripts are downloaded at runtime.
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
        title: "卸载 Online KMS / 续期任务",
        category: "Online KMS",
        args: &["/K-Uninstall"],
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

#[derive(Clone, Default)]
pub struct Options {
    pub no_edition_change: bool,
    pub no_renewal: bool,
    pub ts_method: usize,
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
pub fn run(_op: Operation, _options: Options) -> Result<String, String> {
    Err("激活引擎仅支持 Windows。当前系统可以预览界面。".into())
}

#[cfg(windows)]
pub fn run(op: Operation, options: Options) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    if std::env::var("PROCESSOR_ARCHITEW6432").is_ok_and(|arch| !arch.is_empty()) {
        return Err("当前构建不支持跨架构仿真运行，请在 Windows x64 上运行。".into());
    }
    if !crate::process::is_admin() {
        return Err("请以管理员身份启动应用。".into());
    }
    let dir = tempfile::Builder::new()
        .prefix("mas-rust-")
        .tempdir()
        .map_err(|e| e.to_string())?;
    let payload: &[u8] = if op.legacy {
        include_bytes!("../vendor/mas/KMS38_Activation.cmd")
    } else {
        include_bytes!("../vendor/mas/MAS_AIO.cmd")
    };
    // Only fixed filenames and allowlisted arguments enter cmd; the temp path is the working directory.
    std::fs::write(dir.path().join("engine.cmd"), payload).map_err(|e| e.to_string())?;
    let args = arguments(op, &options);
    // Prevent the interactive engine from detaching into another console before
    // TempDir is dropped. Keep unattended output visible until acknowledged.
    let launcher = format!(
        "@echo off\r\ncall engine.cmd -qedit {}\r\nset result=%errorlevel%\r\necho.\r\necho Engine exited. Review the output above; then press a key to close.\r\npause >nul\r\nexit /b %result%\r\n",
        args.join(" ")
    );
    std::fs::write(dir.path().join("launch.cmd"), launcher).map_err(|e| e.to_string())?;
    let root = std::env::var_os("SystemRoot").ok_or("SystemRoot 未定义")?;
    let status = Command::new(std::path::PathBuf::from(root).join("System32/cmd.exe"))
        .arg("/D")
        .arg("/C")
        .arg("launch.cmd")
        .current_dir(dir.path())
        .creation_flags(0x00000010)
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok("引擎进程已退出。退出码不代表激活成功；请在“许可证”页查询状态，详细结果以引擎窗口为准。".into())
    } else {
        Err(format!(
            "引擎退出码：{:?}。请查看引擎窗口中的诊断结果。",
            status.code()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
                        ts_method: 1
                    }
                )
                .is_empty()
            );
        }
    }
}
