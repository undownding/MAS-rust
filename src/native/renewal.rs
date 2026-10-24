//! Native Task Scheduler registration and script-free renewal entry point.
use super::{
    kms::{self, Scope},
    licensing::Licensing,
    online,
};
use crate::engine::Options;
use sha2::{Digest, Sha256};
use std::{fs, io::Write, os::windows::fs::MetadataExt, path::PathBuf};
use windows::{
    Win32::{
        System::{
            Com::{CLSCTX_INPROC_SERVER, CoCreateInstance, CoTaskMemFree},
            TaskScheduler::{
                ITaskFolder, ITaskService, TASK_CREATE_OR_UPDATE, TASK_LOGON_SERVICE_ACCOUNT,
                TaskScheduler,
            },
            Variant::VARIANT,
        },
        UI::Shell::{FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, SHGetKnownFolderPath},
    },
    core::BSTR,
};

fn folder() -> Result<ITaskFolder, String> {
    let _com = Licensing::new()?;
    unsafe {
        let service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| e.to_string())?;
        let empty = VARIANT::default();
        service
            .Connect(&empty, &empty, &empty, &empty)
            .map_err(|e| e.to_string())?;
        service
            .GetFolder(&BSTR::from("\\"))
            .map_err(|e| e.to_string())
    }
}
fn name(scope: Scope) -> &'static str {
    match scope {
        Scope::Windows => "MAS-Rust-KMS-Windows",
        Scope::Office | Scope::ProjectVisio => "MAS-Rust-KMS-Office",
        Scope::All => "MAS-Rust-KMS-All",
    }
}
fn existing(folder: &ITaskFolder, name: &str) -> Result<Option<String>, String> {
    match unsafe { folder.GetTask(&BSTR::from(name)) } {
        Ok(task) => {
            let xml = unsafe { task.Xml() }
                .map_err(|e| e.to_string())?
                .to_string();
            if !xml.contains("<Source>MAS-Rust</Source>") {
                return Err(format!(
                    "任务 {name} 已存在且不属于 MAS Rust；不会覆盖或删除。"
                ));
            }
            Ok(Some(xml))
        }
        Err(e) if e.code().0 as u32 == 0x80070002 => Ok(None),
        Err(e) => Err(format!("读取计划任务 {name}：{e}")),
    }
}

fn protected_directory() -> Result<PathBuf, String> {
    let raw = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, None) }
        .map_err(|e| e.to_string())?;
    let text = unsafe { raw.to_string() };
    unsafe {
        CoTaskMemFree(Some(raw.0.cast()));
    }
    let mut dir = PathBuf::from(text.map_err(|e| e.to_string())?);
    for segment in ["MAS-Rust", "Renewal"] {
        dir.push(segment);
        match fs::symlink_metadata(&dir) {
            Ok(meta) if !meta.is_dir() || meta.file_attributes() & 0x400 != 0 => {
                return Err(format!("续期目录不是普通目录：{}", dir.display()));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&dir).map_err(|e| e.to_string())?
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(dir)
}

pub fn install(scope: Scope, server: &str, port: u16) -> Result<(), String> {
    if !crate::process::is_admin() {
        return Err("注册续期需要管理员权限".into());
    }
    let folder = folder()?;
    let previous = existing(&folder, name(scope))?;
    // Installing a Project/Visio task must not narrow an existing Office task.
    let scope = if scope == Scope::ProjectVisio
        && previous
            .as_ref()
            .is_some_and(|xml| xml.contains("--kms-renew office"))
    {
        Scope::Office
    } else {
        scope
    };
    let dir = protected_directory()?;
    let bytes =
        fs::read(std::env::current_exe().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let exe = dir.join(format!("mas-rust-{}.exe", &digest[..16]));
    if exe.exists() {
        let meta = fs::symlink_metadata(&exe).map_err(|e| e.to_string())?;
        if meta.file_attributes() & 0x400 != 0
            || fs::read(&exe).map_err(|e| e.to_string())? != bytes
        {
            return Err("已有续期 EXE 与当前版本哈希不符".into());
        }
    } else {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&exe)
            .map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
    }
    let xml = kms::renewal_xml(&exe.to_string_lossy(), scope, server, port)?;
    unsafe {
        folder.RegisterTask(
            &BSTR::from(name(scope)),
            &BSTR::from(xml),
            TASK_CREATE_OR_UPDATE.0,
            &VARIANT::from("SYSTEM"),
            &VARIANT::default(),
            TASK_LOGON_SERVICE_ACCOUNT,
            &VARIANT::default(),
        )
    }
    .map_err(|e| format!("注册计划任务：{e}"))?;
    Ok(())
}

pub fn remove() -> Result<(), String> {
    let folder = folder()?;
    for scope in [Scope::Windows, Scope::Office, Scope::All] {
        if existing(&folder, name(scope))?.is_some() {
            unsafe { folder.DeleteTask(&BSTR::from(name(scope)), 0) }.map_err(|e| e.to_string())?;
        }
    }
    // Keep protected executable/log files: another renewal invocation may still
    // be running. Removing tasks stops future launches without racing its image.
    Ok(())
}

pub fn headless(args: &[String]) -> i32 {
    let log = std::cell::RefCell::new(String::new());
    let result = (|| -> Result<String, String> {
        let (scope, server, port) = kms::parse_renewal_args(args)?;
        let _guard = super::session::OperationGuard::acquire()?;
        online::run(
            scope,
            &Options {
                no_edition_change: true,
                no_renewal: true,
                kms_server: server,
                kms_port: port,
                ..Default::default()
            },
            true,
            &|line| {
                let mut log = log.borrow_mut();
                log.push_str(line);
                log.push('\n');
            },
        )
    })();
    let ok = result.is_ok();
    log.borrow_mut()
        .push_str(&result.unwrap_or_else(|e| format!("错误：{e}")));
    if crate::process::is_admin()
        && let Ok(dir) = protected_directory()
    {
        let _ = fs::write(dir.join("last-renewal.log"), log.into_inner());
    }
    if ok { 0 } else { 1 }
}
