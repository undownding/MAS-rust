//! Public legacy key catalogs from pinned :ts_oldks and :ts_winvista.
#![cfg_attr(not(test), allow(dead_code))]
use super::crypto::Version;
use std::collections::HashSet;
use uuid::Uuid;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Kms,
    Phone,
}
#[derive(Debug, Clone)]
pub struct Product {
    pub method: Method,
    pub version: Version,
    pub id: Uuid,
    pub key: &'static str,
    pub channel: &'static str,
    pub edition: &'static str,
}
pub fn catalog() -> Vec<Product> {
    include_str!("../../../vendor/mas/native/tsforge-legacy-windows.tsv")
        .lines()
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 6, "pinned legacy catalog columns");
            Product {
                method: match fields[0] {
                    "kms" => Method::Kms,
                    "phone" => Method::Phone,
                    _ => panic!("pinned legacy method"),
                },
                version: match fields[1] {
                    "vista" => Version::Vista,
                    "win7" => Version::Win7,
                    _ => panic!("pinned legacy version"),
                },
                id: Uuid::parse_str(fields[2]).expect("pinned legacy activation ID"),
                key: fields[3],
                channel: fields[4],
                edition: fields[5],
            }
        })
        .collect()
}
/// No match means no generic-key route. Never choose an ID absent from this PC.
pub fn select(
    version: Version,
    method: Method,
    edition: &str,
    installed: &HashSet<Uuid>,
) -> Option<Product> {
    catalog().into_iter().find(|product| {
        product.version == version
            && product.method == method
            && product.edition.eq_ignore_ascii_case(edition)
            && installed.contains(&product.id)
    })
}
pub struct Installed {
    pub id: Uuid,
    pub suffix: String,
    pub channel: String,
}
pub trait Backend {
    fn install(&mut self, key: &str) -> Result<(), String>;
    fn refresh(&mut self) -> Result<(), String>;
    fn installed(&mut self, id: Uuid) -> Result<Installed, String>;
}
/// Success proves key mapping only; activation is a separate operation.
pub fn install(product: &Product, backend: &mut impl Backend) -> Result<(), String> {
    if !catalog().iter().any(|p| {
        p.id == product.id
            && p.version == product.version
            && p.method == product.method
            && p.key == product.key
            && p.channel == product.channel
            && p.edition == product.edition
    }) {
        return Err("所选密钥不在固定旧版目录中，未执行安装。".into());
    }
    backend.install(product.key).map_err(|e| {
        format!("旧版通用密钥安装调用失败：{e}；系统调用可能已改变密钥，不自动回滚或重试。")
    })?;
    let mut verify = || -> Result<(), String> {
        backend.refresh()?;
        let installed = backend.installed(product.id)?;
        if installed.id != product.id
            || !installed.suffix.eq_ignore_ascii_case(&product.key[24..])
            || !installed.channel.eq_ignore_ascii_case(product.channel)
        {
            return Err("安装后的许可证 ID、密钥末五位或通道与目录不符".into());
        }
        Ok(())
    };
    verify().map_err(|e| {
        format!("旧版通用密钥已提交，但映射校验失败：{e}；未执行后续激活，不自动撤销密钥安装。")
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        events: Vec<&'static str>,
        fail: Option<&'static str>,
        product: Product,
        mismatch: u8,
    }
    impl Fake {
        fn step(&mut self, name: &'static str) -> Result<(), String> {
            self.events.push(name);
            if self.fail == Some(name) {
                Err(name.into())
            } else {
                Ok(())
            }
        }
    }
    impl Backend for Fake {
        fn install(&mut self, _: &str) -> Result<(), String> {
            self.step("install")
        }
        fn refresh(&mut self) -> Result<(), String> {
            self.step("refresh")
        }
        fn installed(&mut self, _: Uuid) -> Result<Installed, String> {
            self.step("read")?;
            Ok(Installed {
                id: if self.mismatch == 1 {
                    Uuid::nil()
                } else {
                    self.product.id
                },
                suffix: if self.mismatch == 2 {
                    "wrong".into()
                } else {
                    self.product.key[24..].into()
                },
                channel: if self.mismatch == 3 {
                    "wrong".into()
                } else {
                    self.product.channel.into()
                },
            })
        }
    }
    #[test]
    fn install_stops_at_each_failure_and_never_claims_activation() {
        let product = catalog().remove(0);
        for (index, stage) in ["install", "refresh", "read"].iter().enumerate() {
            let mut fake = Fake {
                events: vec![],
                fail: Some(stage),
                product: product.clone(),
                mismatch: 0,
            };
            let error = install(&product, &mut fake).unwrap_err();
            assert_eq!(fake.events, ["install", "refresh", "read"][..=index]);
            assert!(error.contains("密钥"));
        }
        for mismatch in 0..=3 {
            let mut fake = Fake {
                events: vec![],
                fail: None,
                product: product.clone(),
                mismatch,
            };
            assert_eq!(install(&product, &mut fake).is_ok(), mismatch == 0);
        }
    }
    #[test]
    fn tampered_catalog_product_is_rejected_before_system_calls() {
        let mut product = catalog().remove(0);
        let mut fake = Fake {
            events: vec![],
            fail: None,
            product: product.clone(),
            mismatch: 0,
        };
        product.key = "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA";
        assert!(install(&product, &mut fake).is_err());
        assert!(fake.events.is_empty());
    }
    #[test]
    fn pinned_catalog_has_valid_unique_rows_and_preserves_server_aliases() {
        let products = catalog();
        assert_eq!(products.len(), 66);
        let mut unique = HashSet::new();
        for p in &products {
            assert!(!p.id.is_nil());
            assert!(unique.insert((
                format!("{:?}", p.method),
                format!("{:?}", p.version),
                p.edition
            )));
            let groups: Vec<_> = p.key.split('-').collect();
            assert_eq!(groups.len(), 5);
            assert!(groups.iter().all(|g| {
                g.len() == 5
                    && g.bytes()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            }));
            assert!(!p.key.contains('%'));
            match p.method {
                Method::Kms => assert_eq!(p.channel, "Volume:GVLK"),
                Method::Phone => {
                    assert_eq!(p.version, Version::Vista);
                    assert!(matches!(p.channel, "Retail" | "OEM:NONSLP"));
                }
            }
        }
        let normal = products
            .iter()
            .find(|p| p.version == Version::Win7 && p.edition == "ServerStandard")
            .unwrap();
        let core = products
            .iter()
            .find(|p| p.version == Version::Win7 && p.edition == "ServerStandardCore")
            .unwrap();
        assert_eq!(normal.id, core.id);
        assert_eq!(normal.key, core.key);
        assert!(products.iter().any(|p| p.edition == "Embedded_POSReady"));
        assert!(products.iter().any(|p| p.edition == "Embedded_ThinPC"));
    }
    #[test]
    fn every_row_selects_only_with_its_installed_id_and_requested_method() {
        for product in catalog() {
            assert!(
                select(
                    product.version,
                    product.method,
                    product.edition,
                    &HashSet::new()
                )
                .is_none()
            );
            let ids = HashSet::from([product.id]);
            let found = select(
                product.version,
                product.method,
                &product.edition.to_lowercase(),
                &ids,
            )
            .unwrap();
            assert_eq!(found.id, product.id);
            assert_eq!(found.key, product.key);
            assert!(select(Version::Win8, product.method, product.edition, &ids).is_none());
            assert!(select(Version::Modern, product.method, product.edition, &ids).is_none());
        }
    }
    #[test]
    fn overlapping_edition_names_do_not_cross_generations_or_key_methods() {
        let ids: HashSet<_> = catalog().iter().map(|p| p.id).collect();
        let vista = select(Version::Vista, Method::Kms, "Enterprise", &ids).unwrap();
        let win7 = select(Version::Win7, Method::Kms, "Enterprise", &ids).unwrap();
        let phone = select(Version::Vista, Method::Phone, "Enterprise", &ids).unwrap();
        assert_ne!(vista.id, win7.id);
        assert_ne!(vista.id, phone.id);
        assert!(select(Version::Win7, Method::Phone, "Enterprise", &ids).is_none());
        assert!(select(Version::Vista, Method::Phone, "StarterN", &ids).is_none());
        assert!(select(Version::Vista, Method::Phone, "ServerComputeClusterV", &ids).is_none());
        assert!(select(Version::Vista, Method::Kms, "Ultimate", &ids).is_none());
    }
}
