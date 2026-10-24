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

pub struct Target {
    pub dir: PathBuf,
    pub x64: bool,
    pub ospp: bool,
}
fn dll(x64: bool) -> &'static [u8] {
    if x64 {
        include_bytes!(concat!(env!("OUT_DIR"), "/sppc64.dll"))
    } else {
        include_bytes!(concat!(env!("OUT_DIR"), "/sppc32.dll"))
    }
}
fn system_sppc(x64: bool) -> Result<PathBuf, String> {
    let root = std::env::var_os("SystemRoot").ok_or("SystemRoot 缺失")?;
    Ok(PathBuf::from(root)
        .join(if x64 { "System32" } else { "SysWOW64" })
        .join("sppc.dll"))
}
fn ospp_dirs(x64: bool) -> Result<Vec<(PathBuf, bool)>, String> {
    let mut paths = Vec::new();
    for (view, arch64) in [(KEY_WOW64_64KEY, true), (KEY_WOW64_32KEY, false)] {
        if x64 && !arch64 {
            continue;
        }
        let key = Key::open(
            r"SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform",
            view,
            false,
        )?
        .ok_or("缺少 Office 2010 OSPP 注册表")?;
        let path = key.string("Path")?.ok_or("缺少 OSPP 路径")?;
        paths.push((PathBuf::from(path), arch64));
    }
    Ok(paths)
}
fn ospp_original(dir: &std::path::Path) -> Result<PathBuf, String> {
    for name in ["sppcs.dll", "OSPPC.DLL"] {
        let file = dir.join(name);
        if let Ok(meta) = std::fs::symlink_metadata(&file)
            && meta.is_file()
            && meta.len() >= 100_000
        {
            hook_files::plain_ancestors(&file)?;
            return Ok(file);
        }
    }
    Err(format!("未找到 OSPPC 原 DLL：{}", dir.display()))
}
pub fn preflight(target: &Target) -> Result<(), String> {
    hook_files::plain_ancestors(&target.dir)?;
    if !target.dir.is_dir() && !target.dir.parent().is_some_and(|p| p.is_dir()) {
        return Err(format!("Office DLL 目录不存在：{}", target.dir.display()));
    }
    if target.ospp {
        for (dir, _) in ospp_dirs(target.x64)? {
            ospp_original(&dir)?;
        }
    } else if !system_sppc(target.x64)?.is_file() {
        return Err("缺少系统 sppc.dll".into());
    }
    Ok(())
}
fn install_target(target: &Target, report: &dyn Fn(&str)) -> Result<(), String> {
    use hook_files::Payload;
    preflight(target)?;
    if target.ospp {
        let dirs = ospp_dirs(target.x64)?;
        for (dir, x64) in &dirs {
            let original = std::fs::read(ospp_original(dir)?).map_err(|e| e.to_string())?;
            hook_files::deploy(
                dir,
                &[
                    ("OSPPC.DLL", Payload::Bytes(dll(*x64))),
                    ("sppcs.dll", Payload::Bytes(&original)),
                ],
            )?;
            report(&format!("已部署 Rust OSPPC：{}", dir.display()));
        }
        let source = dirs
            .iter()
            .find(|(_, x64)| *x64 == target.x64)
            .ok_or("缺少匹配架构的 OSPP 目录")?
            .0
            .join("sppcs.dll");
        hook_files::deploy(&target.dir, &[("sppcs.dll", Payload::Link(&source))])?;
    } else {
        let source = system_sppc(target.x64)?;
        hook_files::deploy(
            &target.dir,
            &[
                ("sppc.dll", Payload::Bytes(dll(target.x64))),
                ("sppcs.dll", Payload::Link(&source)),
            ],
        )?;
    }
    report(&format!(
        "Rust Ohook DLL 部署完成：{}",
        target.dir.display()
    ));
    Ok(())
}
pub fn install(report: &dyn Fn(&str)) -> Result<String, String> {
    if !crate::process::is_admin() {
        return Err("安装 Ohook 需要管理员权限".into());
    }
    let l = super::licensing::Licensing::new()?;
    let prepared = super::office::prepare_ohook(&l, report)?;
    let mut errors = prepared.errors;
    if prepared.targets.is_empty() {
        errors.push("没有已准备好的 Office 安装目标；请检查许可准备日志。".into());
    }
    let mut installed = 0;
    for target in &prepared.targets {
        match install_target(target, report) {
            Ok(()) => installed += 1,
            Err(e) => errors.push(e),
        }
    }
    if installed > 0 {
        if let Err(e) = office_cleanup::clear_blocks(prepared.keep_shared, report) {
            errors.push(e);
        }
        if prepared.c2r16
            && let Err(e) = office_cleanup::enable_resiliency(report)
        {
            errors.push(e);
        }
    }
    if errors.is_empty() {
        Ok(format!(
            "Rust Ohook 安装完成（{installed} 个目标）。请关闭并重新打开 Office 检查功能；WMI 授权状态不反映进程内 hook 效果。"
        ))
    } else {
        Err(format!(
            "Ohook 安装部分完成（{installed} 个目标）。\n{}",
            errors.join("\n")
        ))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn rust_dlls_load_and_preserve_provider_contract_in_x86_and_x64_processes() {
        let out = std::path::Path::new(env!("OUT_DIR"));
        for name in ["sppc32.dll", "sppc64.dll"] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::copy(out.join(name), dir.path().join("sppc.dll")).unwrap();
            std::fs::copy(
                out.join(format!("{name}-provider.dll")),
                dir.path().join("sppcs.dll"),
            )
            .unwrap();
            let runner = dir.path().join("runner.exe");
            std::fs::copy(out.join(format!("{name}-runner.exe")), &runner).unwrap();
            let mut child = std::process::Command::new(runner)
                .current_dir(dir.path())
                .spawn()
                .unwrap();
            let start = std::time::Instant::now();
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "{name}: {status}");
                    break;
                }
                if start.elapsed() > std::time::Duration::from_secs(15) {
                    child.kill().unwrap();
                    let _ = child.wait();
                    panic!("{name}: isolated test timed out");
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
}
