use super::{
    crypto::Version,
    paired_store,
    registry_backup::{Backup, Target},
    registry_targets,
    reset::{self, Step},
    service, sl,
    storage_layout::{self, Physical},
    token,
    transaction::{self, Transaction},
};
use crate::native::{
    platform,
    registry::{Hive, Key},
};
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
fn configured_store() -> Result<Option<PathBuf>, String> {
    if let Some(key) = Key::open(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform",
        KEY_WOW64_64KEY,
        false,
    )? && let Some(value) = key.string("TokenStore")?
        && !value.is_empty()
    {
        return expand(&value).map(Some);
    }
    Ok(None)
}
#[cfg(test)]
pub(super) fn store_path(filename: &str) -> Result<PathBuf, String> {
    super::storage_layout::modern_file(
        &platform::system_file("")?,
        configured_store()?.as_deref(),
        filename,
    )
}

pub(super) fn tokens_path(version: Version) -> Result<PathBuf, String> {
    let system = platform::system_file("")?;
    let windows = system.parent().ok_or("System32 路径缺少 Windows 父目录")?;
    let configured = if version.paired() {
        None
    } else {
        configured_store()?
    };
    storage_layout::tokens(version, windows, &system, configured.as_deref())
}

/// engine::run already holds the process-wide licensing-operation mutex.
pub(super) fn storage_preflight() -> Result<Physical, String> {
    if !crate::process::is_admin() {
        return Err("请以管理员身份运行".into());
    }
    if std::env::var("PROCESSOR_ARCHITEW6432").is_ok_and(|value| !value.is_empty()) {
        return Err("原生 TSforge 存储操作须在 Windows x64 本机运行，不支持跨架构仿真。".into());
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
    let version = super::crypto::Version::detect(build).map_err(|e| e.to_string())?;
    sl::ensure_refresh_available().map_err(|error| error.to_string())?;
    let configured = if version.paired() {
        None
    } else {
        configured_store()?
    };
    storage_layout::physical(build, &platform::system_file("")?, configured.as_deref())
}

pub fn reset(report: &dyn Fn(&str)) -> Result<String, String> {
    let layout = storage_preflight()?;
    let path = &layout.paths[0];
    report(&format!(
        "原生 Rust TSforge 重置：{}；每阶段先保存备份，不调用 PowerShell。",
        path.display()
    ));
    if layout.missing_secondary {
        report("旧版副本不存在；事务会记录其缺失状态，并在提交时创建副本。");
    }
    let total = if layout.version == Version::Vista {
        1
    } else {
        3
    };
    let mut completed = 0;
    let result: Result<(), String> = (|| {
        if layout.version == Version::Vista {
            sl::refresh_license_status().map_err(|error| error.to_string())?;
        }
        for (step, label, refresh) in [
            (Step::Tamper, "清理存储标记", true),
            (
                Step::RearmAndGrace,
                "重置 rearm 计数与宽限/评估计时器",
                true,
            ),
            (Step::KeyLock, "清理密钥变更锁", false),
        ] {
            if layout.version == Version::Vista && !matches!(step, Step::RearmAndGrace) {
                continue;
            }
            report(label);
            service::stopped(layout.service, || {
                if layout.version.paired() {
                    let mut changed = 0;
                    let transaction = paired_store::edit(path, &layout.paths[1], |original| {
                        let (bytes, count) =
                            reset::transform_version(original, step, layout.version)?;
                        changed = count;
                        Ok(bytes)
                    })
                    .map_err(|error| error.to_string())?;
                    report(&format!(
                        "阶段备份：{}",
                        transaction.backup_path().display()
                    ));
                    // A zero record count can still require creating/synchronizing the mirror.
                    transaction.commit().map_err(|error| error.to_string())?;
                    report(&format!("已修改 {changed} 条记录并同步主副文件。"));
                    completed += 1;
                    return Ok(());
                }
                let mut changed = 0;
                let transaction = Transaction::edit(vec![path.clone()], |originals| {
                    let (encrypted, count) =
                        reset::transform_version(originals[0], step, layout.version)?;
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
            if refresh && layout.version != Version::Vista {
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
            "TSforge 重置失败（已完成 {completed}/{total} 个存储阶段）：{error}。此前完成的阶段仍有效，备份路径见日志。"
        )),
    }
}

/// The engine holds OperationGuard; the manifest cannot select arbitrary targets.
pub fn restore(backup: &std::path::Path, report: &dyn Fn(&str)) -> Result<String, String> {
    if !backup.is_absolute() || !backup.is_dir() {
        return Err("请选择本机备份目录的绝对路径，目录中须有 manifest.json。".into());
    }
    let layout = storage_preflight()?;
    let path = &layout.paths[0];
    report(&format!(
        "原生 Rust TSforge 恢复：{} → {}",
        backup.display(),
        path.display()
    ));
    let mut restored = false;
    let mut cache = None;
    let result = service::stopped(layout.service, || {
        let paired = backup
            .join("paired-store.json")
            .try_exists()
            .map_err(|e| e.to_string())?;
        if paired != layout.version.paired() {
            return Err("备份类型与当前系统的主副文件布局不符。".into());
        }
        let extra = backup
            .join("paired-extra-required")
            .try_exists()
            .map_err(|e| e.to_string())?;
        if extra && !paired {
            return Err("联合副本标记缺少双文件清单。".into());
        }
        let undo = if paired && !extra {
            report("正在恢复旧版主副文件及副本原始存在状态。");
            paired_store::restore(backup, path, &layout.paths[1], |bytes| {
                reset::decode(bytes, layout.version).map(|_| ())
            })
        } else if extra
            || backup
                .join("external-state-required")
                .try_exists()
                .map_err(|e| e.to_string())?
        {
            let saved_registry = Backup::load(backup).map_err(|e| e.to_string())?;
            let specs =
                registry_targets::select(&saved_registry.ids()).map_err(|e| e.to_string())?;
            let keys: Vec<_> = specs
                .iter()
                .map(|spec| {
                    Key::at(
                        if spec.users {
                            Hive::Users
                        } else {
                            Hive::Machine
                        },
                        spec.path,
                        KEY_WOW64_64KEY,
                        true,
                    )?
                    .ok_or_else(|| format!("恢复目标注册表键不存在：{}", spec.path))
                })
                .collect::<Result<_, String>>()?;
            let targets = specs
                .iter()
                .zip(&keys)
                .map(|(spec, key)| Target {
                    id: spec.id,
                    key,
                    name: spec.name,
                })
                .collect();
            let mut registry = saved_registry.capture(targets).map_err(|e| e.to_string())?;
            let tokens = tokens_path(layout.version)?;
            let cache_path = tokens
                .parent()
                .ok_or("令牌路径缺少父目录")?
                .join("cache")
                .join("cache.dat");
            crate::native::hook_files::plain_ancestors(&cache_path)?;
            cache = Some(cache_path);
            report("正在校验并恢复物理存储、tokens.dat 与已备份的产品注册表值。");
            let validate = |index, bytes: &[u8]| {
                if index == 0 {
                    reset::decode(bytes, layout.version).map(|_| ())
                } else {
                    token::decode(bytes).map(|_| ())
                }
            };
            if paired {
                paired_store::restore_participating(
                    backup,
                    path,
                    &layout.paths[1],
                    &[tokens],
                    validate,
                    &mut registry,
                )
            } else {
                transaction::restore_participating(
                    backup,
                    &[path.clone(), tokens],
                    validate,
                    &mut registry,
                )
            }
        } else {
            transaction::restore_validated(backup, std::slice::from_ref(path), |_, bytes| {
                reset::decode(bytes, layout.version).map(|_| ())
            })
        }
        .map_err(|error| error.to_string())?;
        restored = true;
        report(&format!(
            "已恢复所选备份中的状态并完成回读校验。恢复前状态备份：{}",
            undo.display()
        ));

        if let Some(cache) = &cache {
            match std::fs::remove_file(cache) {
                Ok(()) => report("已清理派生许可缓存，系统将重新生成。"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("许可状态已恢复，但清理缓存失败：{error}")),
            }
        }
        Ok(())
    });
    if let Err(error) = result {
        return Err(format!(
            "恢复流程失败（存储{}恢复）：{error}",
            if restored { "已" } else { "尚未完整" }
        ));
    }
    sl::refresh_license_status()
        .map_err(|error| format!("存储已恢复，但许可状态刷新失败：{error}"))?;
    Ok("已恢复所选备份。恢复前的状态已另行备份，路径见日志；请检查 Windows/Office 状态。".into())
}
