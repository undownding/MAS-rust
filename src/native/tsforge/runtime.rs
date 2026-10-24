use super::{
    reset::{self, Step},
    service, sl,
    transaction::Transaction,
};
use crate::native::{platform, registry::Key};
use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf};
use windows_sys::Win32::System::{
    Environment::ExpandEnvironmentStringsW, Registry::KEY_WOW64_64KEY,
};

fn expand(value: &str) -> Result<PathBuf, String> {
    if value.contains('\0') {
        return Err("TokenStore 路径包含 NUL".into());
    }
    let input: Vec<_> = value.encode_utf16().chain([0]).collect();
    let length = unsafe { ExpandEnvironmentStringsW(input.as_ptr(), std::ptr::null_mut(), 0) };
    if length == 0 || length > 32768 {
        return Err("无法展开 TokenStore 路径".into());
    }
    let mut output = vec![0; length as usize];
    let result = unsafe { ExpandEnvironmentStringsW(input.as_ptr(), output.as_mut_ptr(), length) };
    if result == 0 || result > length {
        return Err("TokenStore 路径展开失败或环境发生变化".into());
    }
    let path = PathBuf::from(OsString::from_wide(&output[..result as usize - 1]));
    if !path.is_absolute() {
        return Err("TokenStore 路径不是绝对路径".into());
    }
    Ok(path)
}
fn physical_path() -> Result<PathBuf, String> {
    if let Some(key) = Key::open(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform",
        KEY_WOW64_64KEY,
        false,
    )? && let Some(value) = key.string("TokenStore")?
        && !value.is_empty()
    {
        let path = expand(&value)?.join("data.dat");
        if path.is_file() {
            return Ok(path);
        }
    }
    for relative in [
        r"spp\store\data.dat",
        r"spp\store\2.0\data.dat",
        r"spp\store_test\data.dat",
        r"spp\store_test\2.0\data.dat",
    ] {
        let path = platform::system_file(relative)?;
        if path.is_file() {
            return Ok(path);
        }
    }
    Err("未找到 Windows 物理许可存储 data.dat".into())
}

/// engine::run already holds the process-wide licensing-operation mutex.
pub fn reset(report: &dyn Fn(&str)) -> Result<String, String> {
    if !crate::process::is_admin() {
        return Err("请以管理员身份运行".into());
    }
    if std::env::var("PROCESSOR_ARCHITEW6432").is_ok_and(|value| !value.is_empty()) {
        return Err("原生 TSforge 重置须在 Windows x64 本机运行，不支持跨架构仿真。".into());
    }
    let version_key = Key::open(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        KEY_WOW64_64KEY,
        false,
    )?
    .ok_or("无法读取 Windows 版本")?;
    let build: u32 = version_key
        .string("CurrentBuildNumber")?
        .ok_or("缺少 Windows 构建号")?
        .parse()
        .map_err(|_| "Windows 构建号无效")?;
    if build < 9600 {
        return Err("原生 TSforge 重置尚未接入 Vista/Windows 7/8 的存储与服务布局。".into());
    }
    sl::ensure_refresh_available().map_err(|error| error.to_string())?;
    let path = physical_path()?;
    report(&format!(
        "原生 Rust TSforge 重置：{}；每阶段先保存备份，不调用 PowerShell。",
        path.display()
    ));
    let mut completed = 0;
    let result: Result<(), String> = (|| {
        for (step, label, refresh) in [
            (Step::Tamper, "清理存储标记", true),
            (
                Step::RearmAndGrace,
                "重置 rearm 计数与宽限/评估计时器",
                true,
            ),
            (Step::KeyLock, "清理密钥变更锁", false),
        ] {
            report(label);
            service::stopped("sppsvc", || {
                let mut changed = 0;
                let transaction = Transaction::edit(vec![path.clone()], |originals| {
                    let (encrypted, count) = reset::transform(originals[0], step)?;
                    changed = count;
                    Ok(vec![encrypted])
                })
                .map_err(|error| error.to_string())?;
                report(&format!(
                    "阶段备份：{}",
                    transaction.backup_path().display()
                ));
                if changed == 0 {
                    report("未发现需要修改的对应记录。");
                    drop(transaction);
                } else {
                    transaction.commit().map_err(|error| error.to_string())?;
                    report(&format!("已修改 {changed} 条记录并完成回读校验。"));
                }
                completed += 1;
                Ok(())
            })?;
            if refresh {
                sl::refresh_license_status().map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => Ok(
            "原生 TSforge 重置流程完成；这不代表 Windows/Office 已激活。各阶段备份路径已记录。"
                .into(),
        ),
        Err(error) => Err(format!(
            "TSforge 重置失败（已完成 {completed}/3 个存储阶段）：{error}。此前完成的阶段仍有效，备份路径见日志。"
        )),
    }
}
