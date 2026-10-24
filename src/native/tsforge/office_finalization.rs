//! Office conflict-key and banner policy, plus native cleanup adapters.
#![cfg_attr(not(test), allow(dead_code))]
use uuid::Uuid;
pub fn retire(id: Uuid, family: &str, selected: &[Uuid], project_visio_only: bool) -> bool {
    let family = family.to_ascii_lowercase();
    !selected.contains(&id)
        && (!project_visio_only || family.contains("project") || family.contains("visio"))
}
#[cfg(windows)]
fn banner(parent: &crate::native::registry::Key) -> Result<(), String> {
    const APP: &str = "0ff1ce15-a989-479d-af46-f275c6370663";
    parent.delete_tree(APP)?;
    let key = parent.create_child(APP)?;
    key.set_string("KeyManagementServiceName", "10.0.0.10")?;
    if key.string("KeyManagementServiceName")?.as_deref() != Some("10.0.0.10") {
        return Err("Office KMS 配置写入后验证失败".into());
    }
    Ok(())
}
#[cfg(windows)]
pub fn finish(
    prepared: &super::office_runtime::Prepared,
    project_visio_only: bool,
    method: super::activation_flow::Method,
    report: &dyn Fn(&str),
) -> Result<(), String> {
    use crate::native::{
        licensing::{Licensing, string},
        registry::Key,
    };
    use windows_sys::Win32::System::Registry::{KEY_WOW64_32KEY, KEY_WOW64_64KEY};
    const APP: &str = "0ff1ce15-a989-479d-af46-f275c6370663";
    let licensing = Licensing::new()?;
    // Pre-read Insider media before any cache/key cleanup.
    let system = crate::native::platform::system_file("")?;
    let insider = system.join("spp/store_test/2.0/tokens.dat").is_file();
    let files = if insider {
        super::license_reinstall::prepare(&system)?
    } else {
        vec![]
    };
    if prepared.c2r16 && method == super::activation_flow::Method::Kms4k {
        let mut parents = Vec::new();
        for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
            parents.push(
                Key::open(
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform",
                    view,
                    true,
                )?
                .ok_or("缺少 SPP 配置注册表父项")?,
            );
        }
        for (completed, parent) in parents.iter().enumerate() {
            banner(parent).map_err(|e| {
                format!("Office KMS 配置失败，已完成 {completed} 个视图，不自动撤销：{e}")
            })?;
        }
    }
    crate::native::office_cleanup::clear_blocks(prepared.keep_shared, report)?;
    if prepared.errors.is_empty()
        && !prepared.has_msi
        && (prepared.has_c2r || prepared.has_uwp)
        && !prepared.ids.is_empty()
    {
        let products = licensing.products("SoftwareLicensingProduct", APP, true)?;
        let mut targets = Vec::new();
        for p in products {
            let id = Uuid::parse_str(&string(&p, "ID")?).map_err(|e| e.to_string())?;
            if retire(
                id,
                &string(&p, "LicenseFamily")?,
                &prepared.ids,
                project_visio_only,
            ) {
                targets.push((id, p));
            }
        }
        for (completed, (id, product)) in targets.iter().enumerate() {
            report(&format!("卸载冲突 Office 密钥：{id}"));
            licensing
                .product_method(product, "UninstallProductKey")
                .map_err(|e| {
                    format!("Office 密钥清理失败，已卸载 {completed} 项，不自动撤销：{e}")
                })?;
        }
        for product in licensing.products("SoftwareLicensingProduct", APP, true)? {
            let id = Uuid::parse_str(&string(&product, "ID")?).map_err(|e| e.to_string())?;
            if targets.iter().any(|(target, _)| target == &id) {
                return Err(format!("Office 冲突密钥卸载后仍存在：{id}"));
            }
        }
    }
    if insider {
        report(&format!(
            "重新导入 Insider 系统许可：{} 个文件",
            files.len()
        ));
        super::service::stopped("sppsvc", || {
            super::license_reinstall::import(&files, |file| {
                licensing.service(
                    "SoftwareLicensingService",
                    "InstallLicense",
                    &[("LicenseFile", wmi::Variant::String(file.xml.clone()))],
                )
            })
        })?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn project_visio_cleanup_keeps_other_families_and_all_selected_keys() {
        let target = Uuid::from_u128(1);
        let other = Uuid::from_u128(2);
        for family in ["ProjectPro", "visioStd", "ProPlus", ""] {
            assert!(!retire(target, family, &[target], true));
            assert!(retire(other, family, &[target], false));
        }
        assert!(retire(other, "pRoJeCtPro", &[target], true));
        assert!(retire(other, "VisioPro", &[target], true));
        assert!(!retire(other, "ProPlus", &[target], true));
        assert!(!retire(other, "", &[target], true));
    }
    #[cfg(windows)]
    #[test]
    fn banner_replaces_only_office_application_subtree() {
        let fixture = crate::native::registry::tests::TestKey::new();
        let parent = fixture.key();
        parent
            .create_child("0ff1ce15-a989-479d-af46-f275c6370663")
            .unwrap()
            .set_string("Old", "value")
            .unwrap();
        parent.set_dword("Keep", 42).unwrap();
        banner(parent).unwrap();
        let child = parent
            .child("0ff1ce15-a989-479d-af46-f275c6370663", false)
            .unwrap()
            .unwrap();
        assert!(child.raw_value("Old").unwrap().is_none());
        assert_eq!(
            child.string("KeyManagementServiceName").unwrap().as_deref(),
            Some("10.0.0.10")
        );
        assert!(parent.raw_value("Keep").unwrap().is_some());
    }
}
