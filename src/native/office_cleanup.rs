//! Native equivalents of oh_clearblock and the registry portion of oh_uninstall.
use super::registry::{Hive, Key};
use std::{
    fs,
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
};
use windows_sys::Win32::System::Registry::{KEY_WOW64_32KEY, KEY_WOW64_64KEY};
const PROFILES: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
const RESILIENCY: &str = r"Software\Microsoft\Office\16.0\Common\Licensing\Resiliency";

struct Profile {
    sid: String,
    path: PathBuf,
}
fn profiles() -> Result<Vec<Profile>, String> {
    let list = Key::open(PROFILES, KEY_WOW64_64KEY, false)?.ok_or("未找到用户 ProfileList")?;
    let mut profiles = Vec::new();
    for sid in list.children()? {
        // Exclude service/system accounts and stale backup registrations.
        if !(sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-")) || sid.ends_with(".bak")
        {
            continue;
        }
        let Some(entry) = list.child(&sid, false)? else {
            continue;
        };
        let Some(path) = entry.string("ProfileImagePath")? else {
            continue;
        };
        let path = PathBuf::from(path);
        if path.join("NTUSER.DAT").is_file() || Key::at(Hive::Users, &sid, 0, false)?.is_some() {
            profiles.push(Profile { sid, path });
        }
    }
    Ok(profiles)
}
fn user_hive(profile: &Profile) -> Result<Key, String> {
    if let Some(key) = Key::at(Hive::Users, &profile.sid, 0, true)? {
        Ok(key)
    } else {
        Key::load_offline(&profile.path.join("NTUSER.DAT"))
    }
}
fn delete(hive: Hive, path: &str, view: u32) -> Result<bool, String> {
    let (parent, leaf) = path.rsplit_once('\\').ok_or("无效注册表删除路径")?;
    match Key::at(hive, parent, view, true)? {
        Some(key) => key.delete_tree(leaf),
        None => Ok(false),
    }
}
/// Delete only the requested Office cache subtree; never follow a junction to a
/// different location. Individual file symlinks are unlinked, not traversed.
fn remove_cache(path: &Path) -> Result<(), String> {
    super::hook_files::plain_ancestors(path)?;
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    if meta.file_attributes() & 0x400 != 0 {
        return Err(format!("缓存目录包含重解析点，未删除：{}", path.display()));
    }
    if !meta.is_dir() {
        return Err(format!("缓存路径不是目录：{}", path.display()));
    }
    for item in fs::read_dir(path).map_err(|e| e.to_string())? {
        let item = item.map_err(|e| e.to_string())?;
        let meta = fs::symlink_metadata(item.path()).map_err(|e| e.to_string())?;
        if meta.is_dir() {
            remove_cache(&item.path())?;
        } else {
            fs::remove_file(item.path()).map_err(|e| format!("{}: {e}", item.path().display()))?;
        }
    }
    fs::remove_dir(path).map_err(|e| format!("{}: {e}", path.display()))
}
fn record(errors: &mut Vec<String>, result: Result<impl Sized, String>) {
    if let Err(e) = result {
        errors.push(e);
    }
}
fn finish(errors: Vec<String>) -> Result<(), String> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

pub fn clear_blocks(keep_shared: bool, report: &dyn Fn(&str)) -> Result<(), String> {
    let profiles = profiles()?;
    if profiles.is_empty() {
        return Err("未找到 Office 用户配置，未执行清理".into());
    }
    let mut errors = Vec::new();
    if let Some(data) = std::env::var_os("ProgramData") {
        record(
            &mut errors,
            remove_cache(&PathBuf::from(data).join(r"Microsoft\Office\Licenses")),
        );
    }
    for profile in &profiles {
        report(&format!("清理 Office 许可缓存：{}", profile.sid));
        match user_hive(profile) {
            Ok(hive) => {
                for version in [15, 16] {
                    record(
                        &mut errors,
                        hive.delete_tree(&format!(
                            r"Software\Microsoft\Office\{version}.0\Common\Licensing"
                        )),
                    );
                }
                record(&mut errors, hive.finish());
            }
            Err(e) => errors.push(e),
        }
        for relative in [
            r"AppData\Local\Microsoft\Office\Licenses",
            r"AppData\Local\Microsoft\Office\15.0\Licensing",
            r"AppData\Local\Microsoft\Office\16.0\Licensing",
            r"AppData\Local\Packages\Microsoft.Office.Desktop_8wekyb3d8bbwe\LocalCache\Local\Microsoft\Office\Licenses",
        ] {
            record(&mut errors, remove_cache(&profile.path.join(relative)));
        }
        let uwp=profile.path.join(r"AppData\Local\Packages\Microsoft.Office.Desktop_8wekyb3d8bbwe\SystemAppData\Helium\User.dat");
        if uwp.is_file() {
            record(
                &mut errors,
                (|| {
                    let hive = Key::load_offline(&uwp)?;
                    hive.delete_tree(r"Software\Microsoft\Office\16.0\Common\Licensing")?;
                    hive.finish()
                })(),
            );
        }
    }
    for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
        for version in [15, 16] {
            for root in [
                r"SOFTWARE\Microsoft\Office",
                r"SOFTWARE\Policies\Microsoft\Office",
            ] {
                record(
                    &mut errors,
                    delete(
                        Hive::Machine,
                        &format!(r"{root}\{version}.0\Common\Licensing"),
                        view,
                    ),
                );
            }
            record(
                &mut errors,
                delete(
                    Hive::Machine,
                    &format!(r"SOFTWARE\Microsoft\Office\{version}.0\Common\OEM"),
                    view,
                ),
            );
        }
        for path in [
            r"SOFTWARE\Microsoft\Office\ClickToRun\Configuration",
            r"SOFTWARE\Microsoft\Office\15.0\ClickToRun\Configuration",
        ] {
            record(
                &mut errors,
                (|| -> Result<(), String> {
                    if let Some(key) = Key::open(path, view, true)? {
                        if !keep_shared {
                            key.delete_value("SharedComputerLicensing")?;
                        }
                        for name in key.value_names()? {
                            if name.to_ascii_lowercase().ends_with(".devicebasedlicensing") {
                                key.delete_value(&name)?;
                            }
                        }
                    }
                    Ok(())
                })(),
            );
        }
    }
    for path in [
        r"S-1-5-20\Software\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\Policies\0ff1ce15-a989-479d-af46-f275c6370663",
        r"S-1-5-20\Software\Microsoft\OfficeSoftwareProtectionPlatform\Policies\0ff1ce15-a989-479d-af46-f275c6370663",
        r"S-1-5-20\Software\Microsoft\OfficeSoftwareProtectionPlatform\Policies\59a52881-a989-479d-af46-f275c6370663",
    ] {
        record(&mut errors, delete(Hive::Users, path, 0));
    }
    finish(errors)
}

pub fn remove_ohook_registry(report: &dyn Fn(&str)) -> Result<(), String> {
    let mut errors = Vec::new();
    for profile in profiles()? {
        record(
            &mut errors,
            (|| {
                let hive = user_hive(&profile)?;
                if hive.delete_tree(RESILIENCY)? {
                    report(&format!("删除 Ohook Resiliency：{}", profile.sid));
                }
                hive.finish()
            })(),
        );
    }
    if let Some(list) = Key::open(PROFILES, KEY_WOW64_64KEY, false)?
        && let Some(default) = list.string("Default")?
    {
        let path = PathBuf::from(default).join("NTUSER.DAT");
        if path.is_file() {
            record(
                &mut errors,
                (|| {
                    let hive = Key::load_offline(&path)?;
                    hive.delete_tree(RESILIENCY)?;
                    hive.finish()
                })(),
            );
        }
    }
    for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
        record(
            &mut errors,
            delete(
                Hive::Machine,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\0ff1ce15-a989-479d-af46-f275c6370663",
                view,
            ),
        );
    }
    finish(errors)
}
