//! Shared generated-key -> activation sequence; backend methods verify results.
#![cfg_attr(not(test), allow(dead_code))]
use super::generated_key::Prepared;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    StaticCid,
    ZeroCid,
    Kms4k,
}
impl Method {
    /// Windows-only /Z-Windows default. Combined/Office/ESU requests have a
    /// different Auto policy and must not use this entry point.
    pub fn windows(option: usize, build: u32) -> Result<Self, String> {
        let method = match option {
            0 if build >= 26100 => Self::Kms4k,
            0 => Self::ZeroCid,
            1 => Self::StaticCid,
            2 => Self::ZeroCid,
            3 => Self::Kms4k,
            _ => return Err("未知 TSforge 方法".into()),
        };
        if method == Self::StaticCid && build < 9200 {
            return Err("StaticCID 需要 Windows 8 或更高版本".into());
        }
        Ok(method)
    }
}

pub fn skip_permanent(build: u32, revision: u32, permanent: bool) -> bool {
    permanent && !(build == 26100 && revision < 4188)
}

pub trait Backend {
    fn preflight(&mut self, sku: Uuid, method: Method) -> Result<(), String>;
    fn prepare(&mut self, sku: Uuid) -> Result<Prepared, String>;
    fn install(&mut self, prepared: &Prepared) -> Result<(), String>;
    fn office_without_phone_is_licensed(&mut self, sku: Uuid) -> Result<bool, String>;
    fn activate(&mut self, sku: Uuid, method: Method) -> Result<String, String>;
}

/// A failed SLC installation may already have removed the old key. Preserve its
/// detailed error and do not imply automatic rollback or try another method.
pub fn run(backend: &mut impl Backend, sku: Uuid, method: Method) -> Result<String, String> {
    if sku.is_nil() {
        return Err("TSforge 需要明确的产品激活 ID".into());
    }
    backend
        .preflight(sku, method)
        .map_err(|e| format!("激活前检查失败：{e}"))?;
    let prepared = backend
        .prepare(sku)
        .map_err(|e| format!("密钥准备失败（尚未安装）：{e}"))?;
    if prepared.product.activation_id != sku {
        return Err("生成密钥的 SKU 与所选产品不一致，未执行安装".into());
    }
    if method == Method::Kms4k && !prepared.product.channel.eq_ignore_ascii_case("Volume:GVLK") {
        return Err("KMS4k 要求 Volume:GVLK 产品，未执行安装".into());
    }
    backend
        .install(&prepared)
        .map_err(|e| format!("密钥安装阶段失败：{e}"))?;
    // Upstream checks this after installing: installing a retail Office key can
    // itself establish the license, so checking before install is not equivalent.
    if backend
        .office_without_phone_is_licensed(sku)
        .map_err(|e| format!("密钥已安装，Office 许可检查失败：{e}"))?
    {
        return Ok("Office 产品无需电话许可，安装后已验证许可状态。".into());
    }
    backend
        .activate(sku, method)
        .map_err(|e| format!("密钥已安装，后续激活流程失败：{e}"))
}

#[cfg(windows)]
#[allow(dead_code)] // Constructed by the upcoming product-scope dispatcher.
pub struct Native<'a> {
    pub report: &'a dyn Fn(&str),
}
#[cfg(windows)]
impl Backend for Native<'_> {
    fn preflight(&mut self, sku: Uuid, method: Method) -> Result<(), String> {
        use windows_sys::core::GUID;
        super::runtime::preflight()?;
        let context = super::sl::Context::open().map_err(|e| e.to_string())?;
        let id = GUID::from_u128(sku.as_u128());
        let app = context
            .application_id(&id)
            .map_err(|e| e.to_string())?
            .ok_or("所选 SKU 缺少应用 ID")?;
        if method != Method::Kms4k {
            // Office without a phone license is handled after installation.
            let app = Uuid::from_fields(app.data1, app.data2, app.data3, &app.data4);
            if app == Uuid::parse_str(crate::native::licensing::WINDOWS_APP).unwrap()
                && !context.phone_activatable(&id).map_err(|e| e.to_string())?
            {
                return Err("所选 Windows 产品不支持电话确认 ID，未执行安装".into());
            }
        }
        Ok(())
    }
    fn prepare(&mut self, sku: Uuid) -> Result<Prepared, String> {
        let context = super::sl::Context::open().map_err(|e| e.to_string())?;
        super::generated_key::prepare(&context, sku).map_err(|e| e.to_string())
    }
    fn install(&mut self, prepared: &Prepared) -> Result<(), String> {
        match prepared.key {
            super::generated_key::Generated::Pkey2005(_) => {
                let message = super::key_runtime::install(prepared, self.report)?;
                (self.report)(&message);
            }
            super::generated_key::Generated::Pkey2009(_) => {
                let context = super::sl::Context::open().map_err(|e| e.to_string())?;
                let key = super::generated_key::install2009(&context, prepared)
                    .map_err(|e| e.to_string())?;
                (self.report)(&format!("PKEY2009 已安装并验证产品映射：{key}"));
            }
        }
        Ok(())
    }
    fn office_without_phone_is_licensed(&mut self, sku: Uuid) -> Result<bool, String> {
        use crate::native::licensing::{Licensing, number, string};
        let licensing = Licensing::new()?;
        let products = licensing.query(&format!(
            "SELECT Name,Description,LicenseStatus FROM SoftwareLicensingProduct WHERE ID='{sku}'"
        ))?;
        if products.len() != 1 {
            return Err("安装后的产品记录缺失或不唯一".into());
        }
        let p = &products[0];
        if !string(p, "Name")?.to_ascii_lowercase().contains("office")
            || string(p, "Description")?
                .to_ascii_uppercase()
                .contains("KMS")
        {
            return Ok(false);
        }
        let context = super::sl::Context::open().map_err(|e| e.to_string())?;
        Ok(!context
            .phone_activatable(&windows_sys::core::GUID::from_u128(sku.as_u128()))
            .map_err(|e| e.to_string())?
            && number(p, "LicenseStatus")? == 1)
    }
    fn activate(&mut self, sku: Uuid, method: Method) -> Result<String, String> {
        match method {
            Method::StaticCid => super::static_cid::activate(sku, self.report),
            Method::ZeroCid => super::phone_runtime::zero_cid(sku, self.report),
            Method::Kms4k => super::kms4k_runtime::activate(sku, self.report),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::tsforge::pkey_config::{Algorithm, KeyRange, Product};
    struct Fake {
        calls: Vec<&'static str>,
        fail: &'static str,
        office: bool,
        channel: &'static str,
        mismatch: bool,
    }
    impl Fake {
        fn new() -> Self {
            Self {
                calls: vec![],
                fail: "",
                office: false,
                channel: "Retail",
                mismatch: false,
            }
        }
        fn step(&mut self, name: &'static str) -> Result<(), String> {
            self.calls.push(name);
            if self.fail == name {
                Err("fixture failure; backup retained".into())
            } else {
                Ok(())
            }
        }
    }
    impl Backend for Fake {
        fn preflight(&mut self, _: Uuid, _: Method) -> Result<(), String> {
            self.step("preflight")
        }
        fn prepare(&mut self, sku: Uuid) -> Result<Prepared, String> {
            self.step("prepare")?;
            Prepared::sample(Product {
                activation_id: if self.mismatch {
                    Uuid::from_u128(2)
                } else {
                    sku
                },
                group: 206,
                edition: "Professional".into(),
                description: String::new(),
                channel: self.channel.into(),
                randomized: false,
                algorithm: Algorithm::Pkey2009,
                ranges: vec![KeyRange {
                    start: 100_000_001,
                    end: 100_000_001,
                    eula: "Retail".into(),
                    part_number: "X00-12345".into(),
                    valid: true,
                }],
            })
            .map_err(|e| e.to_string())
        }
        fn install(&mut self, _: &Prepared) -> Result<(), String> {
            self.step("install")
        }
        fn office_without_phone_is_licensed(&mut self, _: Uuid) -> Result<bool, String> {
            self.step("office")?;
            Ok(self.office)
        }
        fn activate(&mut self, _: Uuid, _: Method) -> Result<String, String> {
            self.step("activate")?;
            Ok("verified".into())
        }
    }
    #[test]
    fn methods_and_permanent_activation_boundaries() {
        assert_eq!(Method::windows(0, 26099).unwrap(), Method::ZeroCid);
        assert_eq!(Method::windows(0, 26100).unwrap(), Method::Kms4k);
        assert_eq!(Method::windows(1, 26100).unwrap(), Method::StaticCid);
        assert_eq!(Method::windows(2, 26100).unwrap(), Method::ZeroCid);
        assert_eq!(Method::windows(3, 9600).unwrap(), Method::Kms4k);
        assert!(Method::windows(1, 7601).is_err());
        assert!(Method::windows(4, 26100).is_err());
        assert!(!skip_permanent(26100, 4187, true));
        assert!(skip_permanent(26100, 4188, true));
        assert!(skip_permanent(26099, 0, true));
        assert!(!skip_permanent(26100, 4188, false));
    }
    #[test]
    fn failures_stop_at_the_failed_stage_without_fallback() {
        let steps = ["preflight", "prepare", "install", "office", "activate"];
        for (index, stage) in steps.iter().enumerate() {
            let mut backend = Fake::new();
            backend.fail = stage;
            let error = run(&mut backend, Uuid::from_u128(1), Method::ZeroCid).unwrap_err();
            assert_eq!(backend.calls, steps[..=index]);
            assert!(error.contains("backup retained"));
            if index >= 3 {
                assert!(error.contains("密钥已安装"));
            }
        }
    }
    #[test]
    fn target_and_channel_mismatch_rejected_before_install() {
        let mut backend = Fake::new();
        assert!(run(&mut backend, Uuid::nil(), Method::ZeroCid).is_err());
        assert!(backend.calls.is_empty());
        backend.mismatch = true;
        assert!(run(&mut backend, Uuid::from_u128(1), Method::ZeroCid).is_err());
        assert_eq!(backend.calls, ["preflight", "prepare"]);
        let mut backend = Fake::new();
        assert!(run(&mut backend, Uuid::from_u128(1), Method::Kms4k).is_err());
        assert_eq!(backend.calls, ["preflight", "prepare"]);
    }
    #[test]
    fn office_check_is_after_install_and_methods_reach_verification() {
        let mut backend = Fake::new();
        backend.office = true;
        assert!(
            run(&mut backend, Uuid::from_u128(1), Method::ZeroCid)
                .unwrap()
                .contains("Office")
        );
        assert_eq!(backend.calls, ["preflight", "prepare", "install", "office"]);
        for method in [Method::StaticCid, Method::ZeroCid, Method::Kms4k] {
            let mut backend = Fake::new();
            backend.channel = "Volume:GVLK";
            assert_eq!(
                run(&mut backend, Uuid::from_u128(1), method).unwrap(),
                "verified"
            );
            assert_eq!(
                backend.calls,
                ["preflight", "prepare", "install", "office", "activate"]
            );
        }
    }
}
