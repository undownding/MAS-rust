//! C2R/MSI/UWP adapters for Office client license preparation. The GUI still uses
//! compatibility activation until final cleanup and activation are connected.
#![allow(dead_code)]
use super::{
    activation_flow::Method,
    office_preparation::{self, Backend},
    office_uwp, pkey_config,
};
use crate::native::{
    licensing::{Licensing, string},
    office,
    office_catalog::decode_license,
    registry::Key,
};
use std::{
    collections::HashSet,
    io::Read,
    path::{Path, PathBuf},
};
use uuid::Uuid;
use windows_sys::Win32::System::Registry::KEY_WOW64_64KEY;
use wmi::Variant;
const APP: &str = "0ff1ce15-a989-479d-af46-f275c6370663";

enum Installed {
    Uwp(office_uwp::Installation),
    C2r(office::Installation),
    Msi(office::MsiInstallation),
}
impl Installed {
    fn products(&self) -> &[String] {
        match self {
            Self::Uwp(i) => &i.products,
            Self::C2r(i) => &i.products,
            Self::Msi(i) => &i.products,
        }
    }
    fn version(&self) -> u32 {
        match self {
            Self::Uwp(_) => 16,
            Self::C2r(i) => i.version,
            Self::Msi(i) => i.version,
        }
    }
    fn licenses(&self) -> Option<&Path> {
        match self {
            Self::Uwp(i) => Some(&i.licenses),
            Self::C2r(i) => Some(&i.licenses),
            Self::Msi(_) => None,
        }
    }
    fn config_path(&self) -> Result<PathBuf, String> {
        match self {
            Self::Uwp(i) => Ok(i.root.join("Office16").join("pkeyconfig-office.xrm-ms")),
            Self::C2r(i) => Ok(i
                .licenses
                .parent()
                .ok_or("Office 根目录无效")?
                .join(format!("Office{}", i.version))
                .join("pkeyconfig-office.xrm-ms")),
            Self::Msi(i) => {
                // Match the upstream native-common-first ordering, independently
                // of the Office architecture. Never substitute an empty env var.
                for name in [
                    "CommonProgramW6432",
                    "CommonProgramFiles",
                    "CommonProgramFiles(x86)",
                ] {
                    if let Some(root) = std::env::var_os(name).filter(|p| !p.is_empty()) {
                        let path = PathBuf::from(root)
                            .join("Microsoft Shared")
                            .join(format!("OFFICE{}", i.version))
                            .join("Office Setup Controller")
                            .join("pkeyconfig-office.xrm-ms");
                        if path.is_file() {
                            return Ok(path);
                        }
                    }
                }
                Err(format!(
                    "Office {} MSI 未找到 pkeyconfig-office.xrm-ms",
                    i.version
                ))
            }
        }
    }
}
fn discover(build: u32) -> Result<Vec<Installed>, String> {
    let mut installed = office::discover()?
        .into_iter()
        .map(Installed::C2r)
        .collect::<Vec<_>>();
    installed.extend(
        office::discover_msi()?
            .into_iter()
            .filter(|i| i.version >= 15)
            .map(Installed::Msi),
    );
    installed.extend(office_uwp::discover(build)?.into_iter().map(Installed::Uwp));
    installed.sort_by_key(|i| {
        (
            match i {
                Installed::Uwp(_) => 0,
                Installed::C2r(_) => 1,
                Installed::Msi(_) => 2,
            },
            i.version(),
        )
    });
    Ok(installed)
}
fn installed_ids(licensing: &Licensing) -> Result<HashSet<Uuid>, String> {
    licensing
        .products("SoftwareLicensingProduct", APP, false)?
        .iter()
        .map(|p| {
            Uuid::parse_str(&string(p, "ID")?).map_err(|e| format!("Office 激活 ID 无效：{e}"))
        })
        .collect()
}
fn configs(path: &Path) -> Result<Vec<pkey_config::SelectionProduct>, String> {
    let mut bytes = Vec::new();
    const LIMIT: u64 = 64 * 1024 * 1024;
    std::fs::File::open(path)
        .map_err(|e| format!("{}：{e}", path.display()))?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > LIMIT {
        return Err("Office PKeyConfig 超出大小限制".into());
    }
    pkey_config::parse_selection_config(&decode_license(&bytes)?).map_err(|e| e.to_string())
}
struct Native<'a> {
    licensing: &'a Licensing,
    installation: &'a Installed,
    report: &'a dyn Fn(&str),
}
impl Backend for Native<'_> {
    fn conversion(&mut self, product: &office_preparation::Product) -> Result<(), String> {
        (self.report)(&format!(
            "Office 产品转换：{} → {}",
            product.source, product.target
        ));
        if let Installed::C2r(installation) = self.installation {
            office::ready(installation, &product.target)?;
        }
        Ok(())
    }
    fn import(&mut self, path: &Path, xml: &str) -> Result<(), String> {
        (self.report)(&format!("导入 Office 许可：{}", path.display()));
        self.licensing.service(
            "SoftwareLicensingService",
            "InstallLicense",
            &[("LicenseFile", Variant::String(xml.into()))],
        )?;
        Ok(())
    }
    fn verify(&mut self, id: Uuid) -> Result<(), String> {
        if installed_ids(self.licensing)?.contains(&id) {
            Ok(())
        } else {
            Err("未发现目标 Activation ID；未进入密钥安装".into())
        }
    }
}
pub struct Prepared {
    pub ids: Vec<Uuid>,
    pub errors: Vec<String>,
    pub has_msi: bool,
    pub has_c2r: bool,
    pub has_uwp: bool,
    pub keep_shared: bool,
}
/// Pre-read all plans, then import independently. Consumers must retain errors
/// and must not report a partially prepared set as a completely successful run.
pub fn prepare(
    build: u32,
    method: Method,
    project_visio_only: bool,
    report: &dyn Fn(&str),
) -> Result<Prepared, String> {
    let licensing = Licensing::new()?;
    let installed = discover(build)?;
    if installed.is_empty() {
        return Err("未发现受支持的 Office C2R/MSI/UWP 安装".into());
    }
    let ids = installed_ids(&licensing)?;
    let mut result = Prepared {
        ids: vec![],
        errors: vec![],
        has_msi: installed.iter().any(|i| matches!(i, Installed::Msi(_))),
        has_c2r: installed.iter().any(|i| matches!(i, Installed::C2r(_))),
        has_uwp: installed.iter().any(|i| matches!(i, Installed::Uwp(_))),
        keep_shared: false,
    };
    let mut plans = Vec::new();
    for i in &installed {
        report(&format!(
            "检查 Office {}：{}",
            i.version(),
            i.products().join(", ")
        ));
        let prepared = (|| {
            let configs = configs(&i.config_path()?)?;
            Ok::<_, String>(office_preparation::prepare(
                &office_preparation::Installation {
                    version: i.version(),
                    products: i.products(),
                    msi: matches!(i, Installed::Msi(_)),
                    licenses: i.licenses(),
                },
                &configs,
                &ids,
                project_visio_only,
                method,
            ))
        })();
        match prepared {
            Ok(p) => plans.push((i, p)),
            Err(e) => result.errors.push(format!("Office {}：{e}", i.version())),
        }
    }
    for (i, plan) in plans {
        result.errors.extend(plan.errors);
        for (product, skip) in plan.skipped {
            let reason = match skip {
                super::office_selection::Skip::MsiRetail => {
                    "MSI Retail 不支持 KMS4k，请选择其他方法"
                }
                super::office_selection::Skip::ProjectVisioOnly => "当前只处理 Project / Visio",
                super::office_selection::Skip::MondoIncludesProjectVisio => {
                    "由 O365 对应的 Mondo 产品处理"
                }
            };
            report(&format!("跳过 {product}：{reason}"));
        }
        // Avoid changing configuration when nothing can be prepared.
        if plan.products.is_empty() {
            continue;
        }
        if let Installed::C2r(c2r) = i {
            match configure(c2r, method, project_visio_only) {
                Ok(shared) => result.keep_shared |= shared,
                Err(e) => {
                    result
                        .errors
                        .push(format!("Office 配置准备失败，已写入的配置不自动撤销：{e}"));
                    continue;
                }
            }
        }
        let mut backend = Native {
            licensing: &licensing,
            installation: i,
            report,
        };
        for product in plan.products {
            match office_preparation::apply(&product, &mut backend) {
                Ok(()) => {
                    if !result.ids.contains(&product.id) {
                        result.ids.push(product.id);
                    }
                }
                Err(e) => result.errors.push(format!("{}：{e}", product.source)),
            }
        }
    }
    Ok(result)
}
fn configure(
    install: &office::Installation,
    method: Method,
    project_visio_only: bool,
) -> Result<bool, String> {
    let config = Key::open(&install.config, install.view, true)?.ok_or("Office 配置键已消失")?;
    if !project_visio_only {
        let name = if install.property_bag {
            "ProductReleaseId"
        } else {
            "ProductReleaseIds"
        };
        let current = config.string(name)?.unwrap_or_default();
        let products = install.products.join(",");
        if !current.eq_ignore_ascii_case(&products) {
            config.set_string(name, &products)?;
            if config.string(name)?.as_deref() != Some(&products) {
                return Err("Office 产品列表写入后验证失败".into());
            }
        }
    }
    let server = Key::open(
        r"SYSTEM\CurrentControlSet\Control\ProductOptions",
        KEY_WOW64_64KEY,
        false,
    )?
    .map(|k| k.string("ProductType"))
    .transpose()?
    .flatten()
    .is_some_and(|p| !p.eq_ignore_ascii_case("WinNT"));
    let modern = crate::native::office_catalog::license_files(&install.licenses)?
        .iter()
        .any(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .to_ascii_lowercase()
                .starts_with("word2019vl_kms_client_ae")
        });
    let shared = method != Method::Kms4k
        && server
        && modern
        && install
            .products
            .iter()
            .any(|p| p.to_ascii_lowercase().contains("retail"));
    if shared {
        config.set_string("SharedComputerLicensing", "1")?;
        if config.string("SharedComputerLicensing")?.as_deref() != Some("1") {
            return Err("SharedComputerLicensing 写入后验证失败".into());
        }
    }
    Ok(shared)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_office_discovery_and_license_ids_are_read_only() {
        let licensing = Licensing::new().unwrap();
        let ids = installed_ids(&licensing).unwrap();
        assert!(ids.iter().all(|id| !id.is_nil()));
        for i in discover(10240).unwrap() {
            assert!([15, 16].contains(&i.version()));
            assert!(!i.products().is_empty());
            if let Ok(path) = i.config_path() {
                assert!(path.ends_with("pkeyconfig-office.xrm-ms"));
            }
        }
    }
}
