//! Office client preparation: select products and pre-read missing license files.
//! No key installation or activation is performed by this module.
#![cfg_attr(not(test), allow(dead_code))]
use super::{activation_flow::Method, office_selection, pkey_config::SelectionProduct};
use crate::native::office_catalog;
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub struct Installation<'a> {
    pub version: u32,
    pub products: &'a [String],
    pub msi: bool,
    pub licenses: Option<&'a Path>,
}
pub struct Product {
    pub source: String,
    pub target: String,
    pub id: Uuid,
    pub conversion: bool,
    pub files: Vec<(PathBuf, String)>,
}
pub struct Preparation {
    pub products: Vec<Product>,
    pub skipped: Vec<(String, office_selection::Skip)>,
    pub errors: Vec<String>,
}
/// Keep unrelated products usable if one product has no matching configuration.
/// Every import plan is read and validated before the caller changes anything.
pub fn prepare(
    installation: &Installation<'_>,
    configs: &[SelectionProduct],
    installed_ids: &HashSet<Uuid>,
    project_visio_only: bool,
    method: Method,
) -> Preparation {
    let mut result = Preparation {
        products: vec![],
        skipped: vec![],
        errors: vec![],
    };
    let mut seen = HashSet::new();
    for source in installation.products {
        let plan = match office_selection::plan(
            installation.version,
            source,
            installation.msi,
            project_visio_only,
            installation.products,
            method,
        ) {
            Ok(plan) => plan,
            Err(skip) => {
                result.skipped.push((source.clone(), skip));
                continue;
            }
        };
        let item = (|| -> Result<Product, String> {
            let id = office_selection::activation_id(&plan.license, plan.key_type, configs)
                .ok_or_else(|| {
                    format!(
                        "Office {} / {} 未找到激活 ID",
                        installation.version, plan.license
                    )
                })?;
            let files = if installed_ids.contains(&id) || seen.contains(&id) {
                vec![]
            } else {
                let directory = installation
                    .licenses
                    .ok_or("MSI 许可缺失，请修复 Office 安装")?;
                let files = office_catalog::license_files(directory)?;
                let has = |prefix: &str| {
                    files.iter().any(|p| {
                        p.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .to_ascii_lowercase()
                            .starts_with(prefix)
                    })
                };
                let preview = source.contains("2024")
                    && has("proplus2024previewvl_")
                    && !has("proplus2024vl_");
                let name = if preview {
                    format!("{}-Preview", plan.license)
                } else {
                    plan.license.clone()
                };
                office_catalog::missing_product_files(directory, &name)?
            };
            Ok(Product {
                source: source.clone(),
                target: plan.license,
                id,
                conversion: plan.prepare_conversion,
                files,
            })
        })();
        match item {
            Ok(product) => {
                // Multiple O365/ARM products can map to the same Mondo license.
                // Its files/key only need processing once per installation.
                if seen.insert(product.id) {
                    result.products.push(product);
                }
            }
            Err(error) => result.errors.push(format!("{source}：{error}")),
        }
    }
    result
}

pub trait Backend {
    fn conversion(&mut self, product: &Product) -> Result<(), String>;
    fn import(&mut self, path: &Path, xml: &str) -> Result<(), String>;
    fn verify(&mut self, id: Uuid) -> Result<(), String>;
}
/// Fail closed on a failed import or missing Activation ID. Earlier successful
/// imports/configuration changes remain; they are not covered by SPP backups.
pub fn apply(product: &Product, backend: &mut impl Backend) -> Result<(), String> {
    if product.conversion {
        backend
            .conversion(product)
            .map_err(|e| format!("Office 转换配置失败：{e}"))?;
    }
    for (completed, (path, xml)) in product.files.iter().enumerate() {
        backend.import(path, xml).map_err(|e| format!(
            "Office 许可导入失败（此前已导入 {completed} 个文件；配置及导入不自动撤销）：{}：{e}", path.display()
        ))?;
    }
    backend.verify(product.id).map_err(|e| {
        format!(
            "Office 许可准备后未能验证 {}（已导入 {} 个文件，不自动撤销）：{e}",
            product.id,
            product.files.len()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(id: u128, edition: &str, channel: &str) -> SelectionProduct {
        SelectionProduct {
            activation_id: Uuid::from_u128(id),
            edition: edition.into(),
            description: "Office".into(),
            channel: Some(channel.into()),
            pkey2009: false,
            has_wau_range: false,
        }
    }
    fn media(dir: &Path, product: &str) {
        for name in [
            "client-issuance-test.xrm-ms",
            "pkeyconfig-office.xrm-ms",
            product,
        ] {
            std::fs::write(dir.join(name), "<licenseGroup>\n</licenseGroup>").unwrap();
        }
    }
    #[test]
    fn conversion_deduplicates_mondo_and_preserves_unrelated_errors() {
        let temp = tempfile::tempdir().unwrap();
        media(temp.path(), "MondoR_test.xrm-ms");
        let products = [
            "O365ProPlusRetail".into(),
            "O365HomePremRetail".into(),
            "UnknownRetail".into(),
        ];
        let install = Installation {
            version: 16,
            products: &products,
            msi: false,
            licenses: Some(temp.path()),
        };
        let result = prepare(
            &install,
            &[config(1, "MondoRetail", "Retail")],
            &HashSet::new(),
            false,
            Method::ZeroCid,
        );
        assert_eq!(result.products.len(), 1);
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].contains("UnknownRetail"));
        let p = &result.products[0];
        assert!(p.conversion);
        assert_eq!(p.source, "O365ProPlusRetail");
        assert_eq!(p.target, "MondoRetail");
        assert_eq!(p.files.len(), 3);
        assert_eq!(
            p.files[0].0.file_name().unwrap(),
            "client-issuance-test.xrm-ms"
        );
        assert_eq!(
            p.files[2].0.file_name().unwrap(),
            "pkeyconfig-office.xrm-ms"
        );
    }
    #[test]
    fn installed_msi_does_not_require_media_but_missing_msi_is_an_error() {
        let products = ["ProPlusVolume".into(), "ProjectProRetail".into()];
        let install = Installation {
            version: 16,
            products: &products,
            msi: true,
            licenses: None,
        };
        let configs = [config(1, "ProPlusVolume", "Volume:GVLK")];
        let installed = HashSet::from([Uuid::from_u128(1)]);
        let ready = prepare(&install, &configs, &installed, false, Method::Kms4k);
        assert_eq!(ready.products.len(), 1);
        assert!(ready.products[0].files.is_empty());
        assert_eq!(
            ready.skipped,
            [("ProjectProRetail".into(), office_selection::Skip::MsiRetail)]
        );
        let missing = prepare(&install, &configs, &HashSet::new(), false, Method::Kms4k);
        assert!(missing.products.is_empty());
        assert!(missing.errors[0].contains("修复 Office"));
    }
    #[test]
    fn preview_media_is_selected_and_malformed_group_never_becomes_a_plan() {
        let temp = tempfile::tempdir().unwrap();
        media(temp.path(), "ProPlus2024PreviewVL_test.xrm-ms");
        let products = ["ProPlus2024Retail".into()];
        let install = Installation {
            version: 16,
            products: &products,
            msi: false,
            licenses: Some(temp.path()),
        };
        let configs = [config(1, "ProPlus2024Volume", "Volume:GVLK")];
        let result = prepare(&install, &configs, &HashSet::new(), false, Method::Kms4k);
        assert_eq!(result.products.len(), 1);
        assert!(
            result.products[0].files[1]
                .0
                .ends_with("ProPlus2024PreviewVL_test.xrm-ms")
        );
        std::fs::write(temp.path().join("pkeyconfig-office.xrm-ms"), "<broken>").unwrap();
        let result = prepare(&install, &configs, &HashSet::new(), false, Method::Kms4k);
        assert!(result.products.is_empty());
        assert_eq!(result.errors.len(), 1);
    }
    struct Fake {
        calls: Vec<String>,
        fail: &'static str,
    }
    impl Backend for Fake {
        fn conversion(&mut self, _: &Product) -> Result<(), String> {
            self.step("convert")
        }
        fn import(&mut self, path: &Path, _: &str) -> Result<(), String> {
            self.step(path.to_str().unwrap())
        }
        fn verify(&mut self, _: Uuid) -> Result<(), String> {
            self.step("verify")
        }
    }
    impl Fake {
        fn step(&mut self, s: &str) -> Result<(), String> {
            self.calls.push(s.into());
            if self.fail == s {
                Err("fixture failure".into())
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn import_failure_stops_before_verification_and_retains_completed_count() {
        let p = Product {
            source: "source".into(),
            target: "target".into(),
            id: Uuid::from_u128(1),
            conversion: true,
            files: vec![
                ("first".into(), "xml".into()),
                ("second".into(), "xml".into()),
            ],
        };
        let mut backend = Fake {
            calls: vec![],
            fail: "second",
        };
        let e = apply(&p, &mut backend).unwrap_err();
        assert_eq!(backend.calls, ["convert", "first", "second"]);
        assert!(e.contains("此前已导入 1") && e.contains("fixture failure"));
        let mut backend = Fake {
            calls: vec![],
            fail: "verify",
        };
        assert!(apply(&p, &mut backend).unwrap_err().contains("已导入 2"));
        assert_eq!(backend.calls, ["convert", "first", "second", "verify"]);
        let mut backend = Fake {
            calls: vec![],
            fail: "convert",
        };
        assert!(apply(&p, &mut backend).is_err());
        assert_eq!(backend.calls, ["convert"]);
    }
}
