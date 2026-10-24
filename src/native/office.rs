//! Native Click-to-Run discovery and Office license installation.
use super::office_catalog::license_files;
use super::{
    kms::Scope,
    licensing::{Licensing, string},
    office_catalog::{self, License},
    registry::Key,
};
use std::{collections::BTreeSet, path::PathBuf};
use windows_sys::Win32::System::Registry::{KEY_WOW64_32KEY, KEY_WOW64_64KEY};
use wmi::Variant;
const APP: &str = "0ff1ce15-a989-479d-af46-f275c6370663";
struct Installation {
    version: u32,
    licenses: PathBuf,
    products: Vec<String>,
    config: String,
    root_key: String,
    property_bag: bool,
    view: u32,
}
fn discover() -> Result<Vec<Installation>, String> {
    let mut found = Vec::new();
    let mut seen = BTreeSet::new();
    for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
        for (version, path) in [
            (16, r"SOFTWARE\Microsoft\Office\ClickToRun"),
            (15, r"SOFTWARE\Microsoft\Office\15.0\ClickToRun"),
        ] {
            let Some(root) = Key::open(path, view, false)? else {
                continue;
            };
            let Some(install) = root.string("InstallPath")? else {
                continue;
            };
            let root_dir = PathBuf::from(&install).join("root");
            let licenses = root_dir.join(if version == 16 {
                "Licenses16"
            } else {
                "Licenses"
            });
            if !licenses.is_dir() {
                continue;
            }
            let mut config = format!(r"{path}\Configuration");
            let property_bag = Key::open(&config, view, false)?.is_none();
            if property_bag {
                if version != 15 {
                    return Err(format!("Office {version} 配置注册表缺失"));
                }
                config = format!(r"{path}\propertyBag");
            }
            let product_root = format!(
                r"{path}\ProductReleaseIDs{}",
                if version == 15 { r"\Active" } else { "" }
            );
            let mut products = BTreeSet::new();
            if let Some(key) = Key::open(&product_root, view, false)? {
                for child in key.children()? {
                    let mut names = vec![child.clone()];
                    if version == 16
                        && let Some(sub) =
                            Key::open(&format!(r"{product_root}\{child}"), view, false)?
                    {
                        names.extend(sub.children()?);
                    }
                    for name in names {
                        let lower = name.to_ascii_lowercase();
                        if (lower.contains("retail") || lower.contains("volume"))
                            && (version == 15 || lower.ends_with(".16"))
                        {
                            products.insert(if version == 16 {
                                name[..name.len() - 3].to_owned()
                            } else {
                                name
                            });
                        }
                    }
                }
            }
            if products.is_empty() {
                return Err(format!(
                    "Office {version} 的 ProductReleaseIDs 中未发现已安装产品"
                ));
            }
            if !seen.insert(licenses.to_string_lossy().to_lowercase()) {
                continue;
            }
            found.push(Installation {
                version,
                licenses,
                products: products.into_iter().collect(),
                config,
                root_key: path.into(),
                property_bag,
                view,
            });
        }
    }
    Ok(found)
}
fn ready(install: &Installation, license: &License) -> Result<(), String> {
    let target = if install.property_bag {
        &install.root_key
    } else {
        &install.config
    };
    let config = Key::open(target, install.view, true)?.ok_or("Office 配置键已消失")?;
    let name = format!("{}.OSPPReady", license.product);
    if install.property_bag {
        config.set_dword(&name, 1)?;
    } else {
        config.set_string(&name, "1")?;
    }
    let modern = license_files(&install.licenses)?.iter().any(|p| {
        p.file_name()
            .unwrap()
            .to_string_lossy()
            .to_ascii_lowercase()
            .starts_with("word2019vl_kms_client_ae")
    });
    if !modern {
        let config =
            Key::open(&install.config, install.view, true)?.ok_or("Office 配置键已消失")?;
        let name = if install.property_bag {
            "ProductReleaseId"
        } else {
            "ProductReleaseIds"
        };
        let mut ids = config.string(name)?.unwrap_or_default();
        if !ids
            .split(',')
            .any(|p| p.trim().eq_ignore_ascii_case(license.product))
        {
            if !ids.is_empty() {
                ids.push(',');
            }
            ids.push_str(license.product);
            config.set_string(name, &ids)?;
        }
    }
    Ok(())
}
/// Adds missing C2R licenses/keys. Never called by unattended renewal.
/// Returns per-product failures so an unrelated installed license can still renew.
pub fn prepare_kms(
    l: &Licensing,
    scope: Scope,
    no_change: bool,
    report: &dyn Fn(&str),
) -> Result<Vec<String>, String> {
    let mut errors = prepare_msi(l, scope, report)?;
    let installs = discover()?;
    for install in installs {
        report(&format!(
            "发现 Office {} C2R：{}",
            install.version,
            install.products.join(", ")
        ));
        let o365 = install
            .products
            .iter()
            .any(|p| p.to_ascii_lowercase().starts_with("o365"));
        let files = license_files(&install.licenses)?;
        let preview = files.iter().any(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("ProPlus2024PreviewVL_")
        }) && !files.iter().any(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("ProPlus2024VL_")
        });
        let mut prepared = BTreeSet::new();
        for product in &install.products {
            if !scope.includes_office(product) {
                continue;
            }
            if scope != Scope::ProjectVisio
                && o365
                && (product.contains("Project") || product.contains("Visio"))
            {
                report(&format!("{product} 由 O365 对应的 Mondo 产品处理"));
                continue;
            }
            let product = if preview && product.contains("2024") {
                format!("{product}-Preview")
            } else {
                product.clone()
            };
            let Some(license) = office_catalog::select(install.version, &product, !no_change)
            else {
                if no_change {
                    report(&format!("禁止版本更改：跳过 {product}"));
                } else {
                    errors.push(format!(
                        "Office {} 的 {product} 未找到对应 KMS 许可",
                        install.version
                    ));
                }
                continue;
            };
            if !prepared.insert(license.id) {
                continue;
            }
            let result = (|| -> Result<(), String> {
                let all = l.products("SoftwareLicensingProduct", APP, false)?;
                let mut exists = false;
                for p in all {
                    if string(&p, "ID")?.eq_ignore_ascii_case(license.id) {
                        exists = true;
                        if product.eq_ignore_ascii_case(license.product)
                            && string(&p, "PartialProductKey")?
                                .eq_ignore_ascii_case(&license.key[24..])
                        {
                            return Ok(());
                        }
                    }
                }
                if !exists {
                    let files = office_catalog::missing_files(&install.licenses, &license)?;
                    for (path, xml) in files {
                        report(&format!(
                            "安装 Office 许可：{}",
                            path.file_name().unwrap().to_string_lossy()
                        ));
                        l.service(
                            "SoftwareLicensingService",
                            "InstallLicense",
                            &[("LicenseFile", Variant::String(xml))],
                        )?;
                    }
                    let mut present = false;
                    for p in l.products("SoftwareLicensingProduct", APP, false)? {
                        if string(&p, "ID")?.eq_ignore_ascii_case(license.id) {
                            present = true;
                        }
                    }
                    if !present {
                        return Err(format!("许可导入后仍未发现 Activation ID {}", license.id));
                    }
                }
                report(&format!(
                    "{product} → {}，安装密钥末五位 {}",
                    license.product,
                    &license.key[24..]
                ));
                l.install(license.key)?;
                if !product.eq_ignore_ascii_case(license.product) {
                    ready(&install, &license)?;
                }
                l.refresh()?;
                Ok(())
            })();
            if let Err(e) = result {
                errors.push(format!("{product}：{e}"));
            }
        }
    }
    Ok(errors)
}

fn prepare_msi(l: &Licensing, scope: Scope, report: &dyn Fn(&str)) -> Result<Vec<String>, String> {
    let mut errors = Vec::new();
    let mut installed = BTreeSet::new();
    for view in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
        for version in [14, 15, 16] {
            let path = format!(r"SOFTWARE\Microsoft\Office\{version}.0");
            let Some(packages) =
                Key::open(&format!(r"{path}\Common\InstalledPackages"), view, false)?
            else {
                continue;
            };
            let packages = packages.value_names()?.join(" ").to_ascii_uppercase();
            for row in include_str!("../../vendor/mas/native/office-msi.tsv").lines() {
                let row: Vec<_> = row.split('\t').collect();
                if row[0].parse::<u32>().ok() != Some(version) || !scope.includes_office(row[3]) {
                    continue;
                }
                let Some(reg) =
                    Key::open(&format!(r"{path}\Registration\{{{}}}", row[1]), view, false)?
                else {
                    continue;
                };
                let Some(code) = reg.string("ProductCode")? else {
                    continue;
                };
                let marker = format!("-{}-", row[2]);
                if !code.to_ascii_uppercase().contains(&marker) || !packages.contains(&marker) {
                    continue;
                }
                let Some(license) = office_catalog::select(version, row[3], false) else {
                    report(&format!(
                        "Office {version} MSI {} 不支持 KMS 转换；保留现有许可",
                        row[3]
                    ));
                    continue;
                };
                if !installed.insert(license.id) {
                    continue;
                }
                let result = (|| -> Result<(), String> {
                    let service = if version == 14 {
                        "OfficeSoftwareProtectionService"
                    } else {
                        "SoftwareLicensingService"
                    };
                    report(&format!(
                        "Office {version} MSI {}：安装密钥末五位 {}",
                        license.product,
                        &license.key[24..]
                    ));
                    l.service(
                        service,
                        "InstallProductKey",
                        &[("ProductKey", Variant::String(license.key.into()))],
                    )?;
                    l.service(service, "RefreshLicenseStatus", &[])
                })();
                if let Err(e) = result {
                    errors.push(format!("Office {version} MSI {}：{e}", row[3]));
                }
            }
        }
    }
    Ok(errors)
}
