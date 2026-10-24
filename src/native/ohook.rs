//! Native Ohook removal. Installation's DLL port is still in progress.
use super::{hook_files, office_cleanup, registry::Key};
use std::{collections::BTreeSet, path::PathBuf};
use windows_sys::Win32::System::Registry::{KEY_WOW64_32KEY, KEY_WOW64_64KEY};
pub fn uninstall(report: &dyn Fn(&str)) -> Result<String, String> {
    if !crate::process::is_admin() {
        return Err("卸载 Ohook 需要管理员权限".into());
    }
    let mut directories = BTreeSet::new();
    let mut errors = Vec::new();
    for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
        for root in [
            r"SOFTWARE\Microsoft\Office\ClickToRun",
            r"SOFTWARE\Microsoft\Office\15.0\ClickToRun",
        ] {
            match Key::open(root, view, false).and_then(|key| {
                key.map(|k| k.string("InstallPath"))
                    .transpose()
                    .map(Option::flatten)
            }) {
                Ok(Some(path)) => {
                    for system in ["System", "SystemX86"] {
                        directories.insert((
                            PathBuf::from(&path).join("root").join("vfs").join(system),
                            true,
                        ));
                    }
                }
                Ok(None) => {}
                Err(e) => errors.push(e),
            }
        }
        for version in [14, 15, 16] {
            let root = format!(r"SOFTWARE\Microsoft\Office\{version}.0\Common\InstallRoot");
            match Key::open(&root, view, false).and_then(|key| {
                key.map(|k| k.string("Path"))
                    .transpose()
                    .map(Option::flatten)
            }) {
                Ok(Some(path)) => {
                    directories.insert((PathBuf::from(path), true));
                }
                Ok(None) => {}
                Err(e) => errors.push(e),
            }
        }
    }
    for variable in ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"] {
        if let Some(root) = std::env::var_os(variable) {
            let root = PathBuf::from(root);
            for version in [14, 15, 16] {
                directories.insert((
                    root.join("Microsoft Office")
                        .join(format!("Office{version}")),
                    false,
                ));
            }
            for office in ["Microsoft Office", "Microsoft Office 15"] {
                for system in ["System", "SystemX86"] {
                    directories.insert((
                        root.join(office).join("root").join("vfs").join(system),
                        false,
                    ));
                }
            }
        }
    }
    let mut changed = 0;
    for (path, recursive) in directories {
        match hook_files::remove_sppc(&path, recursive, report) {
            Ok(n) => changed += n,
            Err(e) => errors.push(e),
        }
    }
    let mut ospp = BTreeSet::new();
    for variable in [
        "CommonProgramFiles",
        "CommonProgramW6432",
        "CommonProgramFiles(x86)",
    ] {
        if let Some(root) = std::env::var_os(variable) {
            ospp.insert(
                PathBuf::from(root).join(r"Microsoft Shared\OfficeSoftwareProtectionPlatform"),
            );
        }
    }
    for path in ospp {
        match hook_files::restore_ospp(&path, report) {
            Ok(n) => changed += n,
            Err(e) => errors.push(e),
        }
    }
    if let Err(e) = office_cleanup::remove_ohook_registry(report) {
        errors.push(e);
    }
    if errors.is_empty() {
        Ok(format!(
            "Ohook 原生卸载完成：删除/恢复 {changed} 项文件；已清理 Resiliency 与 Office 横幅相关配置。未卸载 Office 产品密钥。"
        ))
    } else {
        Err(format!(
            "Ohook 卸载部分完成（{changed} 项文件）。\n{}",
            errors.join("\n")
        ))
    }
}
