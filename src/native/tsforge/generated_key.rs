//! Generated-key preparation and PKEY2009 SLC installation. PKEY2005 uses the
//! separate store/registry plan; no activation route calls this installer yet.
#![cfg_attr(not(test), allow(dead_code))]
use super::{
    binary::invalid,
    pkey_config::{Algorithm, KeyRange, Product},
    product_key::{Key2005, Key2009},
};
use std::io;
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub enum Generated {
    Pkey2005(Key2005),
    Pkey2009(Key2009),
}
#[derive(Debug)]
pub struct Prepared {
    pub product: Product,
    pub range: KeyRange,
    pub key: Generated,
}
impl Prepared {
    pub fn sample(product: Product) -> io::Result<Self> {
        if product.activation_id.is_nil() {
            return Err(invalid("activation ID must be nonzero"));
        }
        let selected = product.sample()?;
        let range = selected.range.clone();
        let key = match product.algorithm {
            Algorithm::Pkey2005 => {
                Generated::Pkey2005(Key2005::new(product.group, selected.serial, 0, false)?)
            }
            Algorithm::Pkey2009 => {
                Generated::Pkey2009(Key2009::new(product.group, selected.serial, 0, false)?)
            }
        };
        Ok(Self {
            product,
            range,
            key,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    BeforeChange,
    OldKeyRemoved,
    NewKeyInstalled,
}
impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BeforeChange => "尚未完成密钥变更",
            Self::OldKeyRemoved => "原密钥已卸载，新密钥尚未确认安装",
            Self::NewKeyInstalled => "新密钥已安装，尚未完成回读验证",
        })
    }
}
#[derive(Debug, thiserror::Error)]
#[error("生成密钥安装失败（{stage}）：{detail}")]
pub struct Failure {
    pub stage: Stage,
    pub detail: String,
}

pub trait Licensing {
    fn keys(&self, sku: Uuid) -> Result<Vec<Uuid>, String>;
    fn uninstall(&self, key: Uuid) -> Result<(), String>;
    fn install(&self, algorithm: &str, text: &str) -> Result<Uuid, String>;
}
/// Matches upstream uninstall/install ordering. The caller holds OperationGuard.
/// SLC mutations are not an atomic transaction; errors retain the completed stage.
pub fn install2009(api: &impl Licensing, prepared: &Prepared) -> Result<Uuid, Failure> {
    let mut stage = Stage::BeforeChange;
    let result = (|| {
        let Generated::Pkey2009(key) = prepared.key else {
            return Err("PKEY2005 必须使用存储与注册表安装路径".into());
        };
        let old = api.keys(prepared.product.activation_id)?;
        if old.len() > 1 || old.first().is_some_and(Uuid::is_nil) {
            return Err("当前产品密钥映射不明确，未执行卸载".into());
        }
        if let Some(old) = old.first() {
            api.uninstall(*old)?;
            stage = Stage::OldKeyRemoved;
        }
        let installed = api.install(key.algorithm_uri(), &key.to_string())?;
        stage = Stage::NewKeyInstalled;
        if installed.is_nil() {
            return Err("许可 API 返回空密钥 ID".into());
        }
        if !api
            .keys(prepared.product.activation_id)?
            .contains(&installed)
        {
            return Err("安装后的密钥未出现在所选产品的密钥映射中".into());
        }
        Ok(installed)
    })();
    result.map_err(|detail| Failure { stage, detail })
}

#[cfg(windows)]
fn guid(id: Uuid) -> windows_sys::core::GUID {
    windows_sys::core::GUID::from_u128(id.as_u128())
}
#[cfg(windows)]
fn uuid(id: windows_sys::core::GUID) -> Uuid {
    Uuid::from_fields(id.data1, id.data2, id.data3, &id.data4)
}
#[cfg(windows)]
impl Licensing for super::sl::Context {
    fn keys(&self, sku: Uuid) -> Result<Vec<Uuid>, String> {
        self.installed_keys(&guid(sku))
            .map(|ids| ids.into_iter().map(uuid).collect())
            .map_err(|e| e.to_string())
    }
    fn uninstall(&self, key: Uuid) -> Result<(), String> {
        self.uninstall_key(&guid(key)).map_err(|e| e.to_string())
    }
    fn install(&self, algorithm: &str, text: &str) -> Result<Uuid, String> {
        self.install_key(algorithm, text)
            .map(uuid)
            .map_err(|e| e.to_string())
    }
}

/// Read-only discovery. Missing SKU-local config falls back to the application's
/// configurations. Malformed XML/API failures remain errors, not default keys.
#[cfg(windows)]
pub fn prepare(context: &super::sl::Context, sku: Uuid) -> io::Result<Prepared> {
    use super::pkey_config::ConfigSet;
    use windows_sys::Win32::Security::Authentication::Identity::{
        SL_ID_APPLICATION, SL_ID_PRODUCT_SKU,
    };
    if sku.is_nil() {
        return Err(invalid("activation ID must be nonzero"));
    }
    let mut config = ConfigSet::default();
    config.load_sku(context, &guid(sku))?;
    let mut skipped = 0usize;
    if !config.products.iter().any(|p| p.activation_id == sku) {
        let app = context
            .application_id(&guid(sku))
            .map_err(io::Error::other)?
            .ok_or_else(|| invalid("product has no licensing application"))?;
        for candidate in context
            .ids(SL_ID_APPLICATION, &app, SL_ID_PRODUCT_SKU)
            .map_err(io::Error::other)?
        {
            // LoadAllConfigs in the pinned source skips unrelated broken or
            // unavailable configurations. The requested SKU still must resolve.
            if config.load_sku(context, &candidate).is_err() {
                skipped += 1;
                continue;
            }
            if config.products.iter().any(|p| p.activation_id == sku) {
                break;
            }
        }
    }
    let product = config
        .products
        .into_iter()
        .find(|p| p.activation_id == sku)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound,
            format!("activation ID absent from PKeyConfig ({skipped} unrelated configurations failed to load)")))?;
    Prepared::sample(product)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    fn prepared(algorithm: Algorithm) -> Prepared {
        Prepared::sample(Product {
            activation_id: Uuid::from_u128(1),
            group: 206,
            edition: "Professional".into(),
            description: "fixture".into(),
            channel: "Retail".into(),
            randomized: false,
            algorithm,
            ranges: vec![KeyRange {
                start: 100_000_001,
                end: 100_000_001,
                eula: "Retail".into(),
                part_number: "X00-12345".into(),
                valid: true,
            }],
        })
        .unwrap()
    }
    struct Fake {
        keys: RefCell<Vec<Uuid>>,
        calls: RefCell<Vec<&'static str>>,
        fail_uninstall: bool,
        fail_install: bool,
        bad_mapping: bool,
    }
    impl Default for Fake {
        fn default() -> Self {
            Self {
                keys: RefCell::new(vec![Uuid::from_u128(2)]),
                calls: RefCell::new(vec![]),
                fail_uninstall: false,
                fail_install: false,
                bad_mapping: false,
            }
        }
    }
    impl Licensing for Fake {
        fn keys(&self, _: Uuid) -> Result<Vec<Uuid>, String> {
            self.calls.borrow_mut().push("keys");
            Ok(self.keys.borrow().clone())
        }
        fn uninstall(&self, _: Uuid) -> Result<(), String> {
            self.calls.borrow_mut().push("uninstall");
            if self.fail_uninstall {
                return Err("uninstall failed".into());
            }
            self.keys.borrow_mut().clear();
            Ok(())
        }
        fn install(&self, algorithm: &str, text: &str) -> Result<Uuid, String> {
            self.calls.borrow_mut().push("install");
            assert_eq!(algorithm, "msft:rm/algorithm/pkey/2009");
            assert_eq!(text.len(), 29);
            if self.fail_install {
                return Err("install failed".into());
            }
            let id = Uuid::from_u128(3);
            if !self.bad_mapping {
                self.keys.borrow_mut().push(id);
            }
            Ok(id)
        }
    }
    #[test]
    fn installs_and_verifies_selected_sku_after_uninstall() {
        let api = Fake::default();
        let plan = prepared(Algorithm::Pkey2009);
        assert_eq!(plan.range.start, plan.range.end);
        assert_eq!(install2009(&api, &plan).unwrap(), Uuid::from_u128(3));
        assert_eq!(
            *api.calls.borrow(),
            ["keys", "uninstall", "install", "keys"]
        );
    }
    #[test]
    fn failures_report_completed_stage_and_stop_following_operations() {
        let plan = prepared(Algorithm::Pkey2009);
        let api = Fake {
            fail_uninstall: true,
            ..Default::default()
        };
        assert_eq!(
            install2009(&api, &plan).unwrap_err().stage,
            Stage::BeforeChange
        );
        assert_eq!(*api.calls.borrow(), ["keys", "uninstall"]);
        let api = Fake {
            fail_install: true,
            ..Default::default()
        };
        assert_eq!(
            install2009(&api, &plan).unwrap_err().stage,
            Stage::OldKeyRemoved
        );
        let api = Fake {
            bad_mapping: true,
            ..Default::default()
        };
        assert_eq!(
            install2009(&api, &plan).unwrap_err().stage,
            Stage::NewKeyInstalled
        );
    }
    #[test]
    fn wrong_algorithm_or_ambiguous_existing_keys_never_mutate() {
        let api = Fake::default();
        let plan = prepared(Algorithm::Pkey2005);
        let Generated::Pkey2005(key) = plan.key else {
            panic!()
        };
        assert_eq!(key.to_string().len(), 29);
        assert_eq!(
            install2009(&api, &plan).unwrap_err().stage,
            Stage::BeforeChange
        );
        assert!(api.calls.borrow().is_empty());
        api.keys.borrow_mut().push(Uuid::from_u128(4));
        assert!(install2009(&api, &prepared(Algorithm::Pkey2009)).is_err());
        assert_eq!(*api.calls.borrow(), ["keys"]);
    }
    #[test]
    fn installs_without_old_key_and_rejects_zero_sku_before_sampling() {
        let api = Fake::default();
        api.keys.borrow_mut().clear();
        install2009(&api, &prepared(Algorithm::Pkey2009)).unwrap();
        assert_eq!(*api.calls.borrow(), ["keys", "install", "keys"]);
        let mut product = prepared(Algorithm::Pkey2009).product;
        product.activation_id = Uuid::nil();
        assert!(Prepared::sample(product).is_err());
    }
    #[cfg(windows)]
    #[test]
    fn prepares_from_real_windows_config_without_installing_any_key() {
        let context = super::super::sl::Context::open().unwrap();
        let sku = context
            .default_activation_id(&super::super::sl::WINDOWS_APP_ID, true)
            .unwrap()
            .expect("Windows SKU");
        let result = prepare(&context, uuid(sku)).unwrap();
        assert_eq!(result.product.activation_id, uuid(sku));
        assert!(result.range.start <= result.range.end);
        assert_eq!(uuid(guid(uuid(sku))), uuid(sku));
    }
}
