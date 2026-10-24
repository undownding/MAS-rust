//! Native equivalent of the pinned :_taskclear-cache: registry operations.
#![cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    Machine,
    Users,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Native,
    Wow32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remove {
    Value(&'static str),
    Tree(&'static str),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub hive: Hive,
    pub view: View,
    pub parent: String,
    pub remove: Remove,
}
const SPP: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform";
const OLD_SPP: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SL";
const OSPP: &str = r"SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform";
const WINDOWS: &str = "55c92734-d682-4d71-983e-d6ec3f16059f";
const OFFICE: &str = "0ff1ce15-a989-479d-af46-f275c6370663";
const OFFICE14: &str = "59a52881-a989-479d-af46-f275c6370663";

pub fn targets(build: u32, old_spp_exists: bool) -> Vec<Target> {
    let spp = if build < 7600 && old_spp_exists {
        OLD_SPP
    } else {
        SPP
    };
    let mut result = Vec::new();
    let mut add = |hive, view, parent: &str, remove| {
        result.push(Target {
            hive,
            view,
            parent: parent.into(),
            remove,
        })
    };
    for image in ["SppExtComObj.exe", "sppsvc.exe", "SLsvc.exe"] {
        add(
            Hive::Machine,
            View::Native,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            Remove::Tree(image),
        );
    }
    for name in ["KeyManagementServiceName", "KeyManagementServicePort"] {
        for view in [View::Native, View::Wow32] {
            add(Hive::Machine, view, spp, Remove::Value(name));
        }
    }
    for name in [
        "DisableDnsPublishing",
        "DisableKeyManagementServiceHostCaching",
    ] {
        add(Hive::Machine, View::Native, spp, Remove::Value(name));
    }
    add(Hive::Machine, View::Native, spp, Remove::Tree(WINDOWS));
    if build >= 9200 {
        for view in [View::Native, View::Wow32] {
            add(Hive::Machine, view, spp, Remove::Tree(OFFICE));
        }
    }
    if build >= 9600 {
        let parent = format!(r"S-1-5-20\{spp}");
        for app in [WINDOWS, OFFICE] {
            add(Hive::Users, View::Native, &parent, Remove::Tree(app));
        }
    }
    for name in [
        "KeyManagementServiceName",
        "KeyManagementServicePort",
        "DisableDnsPublishing",
        "DisableKeyManagementServiceHostCaching",
    ] {
        add(Hive::Machine, View::Native, OSPP, Remove::Value(name));
    }
    for app in [OFFICE14, OFFICE] {
        add(Hive::Machine, View::Native, OSPP, Remove::Tree(app));
    }
    result
}

#[cfg(windows)]
fn remove(key: &crate::native::registry::Key, target: Remove) -> Result<bool, String> {
    match target {
        Remove::Value(name) => {
            let changed = key.delete_value(name)?;
            if key.raw_value(name)?.is_some() {
                return Err(format!("清理后注册表值仍存在：{name}"));
            }
            Ok(changed)
        }
        Remove::Tree(name) => {
            let changed = key.delete_tree(name)?;
            if key.child(name, false)?.is_some() {
                return Err(format!("清理后注册表子项仍存在：{name}"));
            }
            Ok(changed)
        }
    }
}

#[cfg(windows)]
pub fn clear(build: u32, report: &dyn Fn(&str)) -> Result<(), String> {
    use crate::native::registry::{Hive as RegistryHive, Key};
    use windows_sys::Win32::System::Registry::{KEY_WOW64_32KEY, KEY_WOW64_64KEY};
    let old = build < 7600 && Key::open(OLD_SPP, KEY_WOW64_64KEY, false)?.is_some();
    // Open every existing parent before the first removal. Absent registry paths
    // are expected; access failures are not silently treated as absent entries.
    let plan = targets(build, old);
    let mut opened = Vec::new();
    for target in &plan {
        let key = Key::at(
            match target.hive {
                Hive::Machine => RegistryHive::Machine,
                Hive::Users => RegistryHive::Users,
            },
            &target.parent,
            match target.view {
                View::Native => KEY_WOW64_64KEY,
                View::Wow32 => KEY_WOW64_32KEY,
            },
            true,
        )?;
        opened.push(key);
    }
    let mut count = 0;
    for (target, key) in plan.iter().zip(opened.iter()) {
        let Some(key) = key else {
            continue;
        };
        match remove(key, target.remove) {
            Ok(true) => {
                count += 1;
                report(&format!(
                    "已清理 {:?}/{:?} {} {:?}",
                    target.hive, target.view, target.parent, target.remove
                ));
            }
            Ok(false) => {}
            Err(e) => {
                return Err(format!(
                    "KMS 配置清理失败；此前已删除 {count} 项，未自动恢复：{e}"
                ));
            }
        }
    }
    report(&format!("KMS 配置清理完成，共删除并回读验证 {count} 项。"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_version_gates_and_registry_views() {
        let vista = targets(6002, true);
        assert_eq!(vista.len(), 16);
        assert!(vista.iter().any(|t| t.parent == OLD_SPP));
        assert!(
            !vista
                .iter()
                .any(|t| t.parent == SPP || t.hive == Hive::Users)
        );
        let win7 = targets(7601, true);
        assert_eq!(win7.len(), 16);
        assert!(win7.iter().any(|t| t.parent == SPP));
        let win8 = targets(9200, false);
        assert_eq!(win8.len(), 18);
        assert_eq!(
            win8.iter()
                .filter(|t| t.parent == SPP && t.remove == Remove::Tree(OFFICE))
                .count(),
            2
        );
        let modern = targets(9600, false);
        assert_eq!(modern.len(), 20);
        assert_eq!(modern.iter().filter(|t| t.hive == Hive::Users).count(), 2);
        assert_eq!(modern.iter().filter(|t| t.view == View::Wow32).count(), 3);
        assert!(modern.iter().all(|t| match t.remove {
            Remove::Value(s) | Remove::Tree(s) => !s.is_empty() && !s.contains('\\'),
        }));
    }
    #[cfg(windows)]
    #[test]
    fn deletion_is_idempotent_and_preserves_other_entries() {
        use crate::native::registry::tests::TestKey;
        let fixture = TestKey::new();
        let key = fixture.key();
        key.set_string("KeyManagementServiceName", "example.invalid")
            .unwrap();
        key.set_dword("Keep", 42).unwrap();
        let child = key.create_child(WINDOWS).unwrap();
        child
            .create_child("Nested")
            .unwrap()
            .set_dword("Data", 1)
            .unwrap();
        drop(child);
        assert!(remove(key, Remove::Value("KeyManagementServiceName")).unwrap());
        assert!(!remove(key, Remove::Value("KeyManagementServiceName")).unwrap());
        assert!(remove(key, Remove::Tree(WINDOWS)).unwrap());
        assert!(!remove(key, Remove::Tree(WINDOWS)).unwrap());
        assert!(key.raw_value("Keep").unwrap().is_some());
    }
}
