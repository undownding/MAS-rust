//! Native fixed-key installation for the pinned legacy Windows catalogs.
#![allow(dead_code)]
use super::{
    crypto::Version,
    legacy_windows::{self, Backend, Installed, Method, Product},
    runtime, sl,
};
use crate::native::licensing::{Licensing, WINDOWS_APP, string};
use std::collections::HashSet;
use uuid::Uuid;
use windows_sys::core::GUID;

pub fn discover(
    version: Version,
    method: Method,
    edition: &str,
    licensing: &Licensing,
) -> Result<Option<Product>, String> {
    let ids = licensing
        .products("SoftwareLicensingProduct", WINDOWS_APP, false)?
        .iter()
        .map(|p| Uuid::parse_str(&string(p, "ID")?).map_err(|e| e.to_string()))
        .collect::<Result<HashSet<_>, _>>()?;
    Ok(legacy_windows::select(version, method, edition, &ids))
}
struct Native(Licensing);
impl Backend for Native {
    fn install(&mut self, key: &str) -> Result<(), String> {
        self.0.install(key)
    }
    fn refresh(&mut self) -> Result<(), String> {
        self.0.refresh()
    }
    fn installed(&mut self, id: Uuid) -> Result<Installed, String> {
        let rows = self.0.query(&format!("SELECT * FROM SoftwareLicensingProduct WHERE ApplicationID='{WINDOWS_APP}' AND ID='{id}' AND PartialProductKey IS NOT NULL AND LicenseDependsOn IS NULL"))?;
        if rows.len() != 1 {
            return Err("旧版目标基础许可证不存在或不唯一".into());
        }
        let actual = Uuid::parse_str(&string(&rows[0], "ID")?).map_err(|e| e.to_string())?;
        let context = sl::Context::open().map_err(|e| e.to_string())?;
        let keys = context
            .installed_keys(&GUID::from_u128(id.as_u128()))
            .map_err(|e| e.to_string())?;
        if keys.len() != 1 {
            return Err("旧版目标许可证未映射到唯一密钥".into());
        }
        let channel = context
            .key_channel(&keys[0])
            .map_err(|e| e.to_string())?
            .ok_or("已安装密钥缺少通道")?;
        Ok(Installed {
            id: actual,
            suffix: string(&rows[0], "PartialProductKey")?,
            channel,
        })
    }
}
/// Caller holds the engine operation guard; no activation is performed here.
pub fn install(
    version: Version,
    method: Method,
    edition: &str,
    report: &dyn Fn(&str),
) -> Result<Product, String> {
    let layout = runtime::storage_preflight()?;
    if layout.version != version || !version.paired() {
        return Err("旧版目录与本机系统版本不符，未安装密钥。".into());
    }
    let licensing = Licensing::new()?;
    let product = discover(version, method, edition, &licensing)?
        .ok_or("未找到匹配的本机旧版许可证与通用密钥，未执行安装。")?;
    legacy_windows::install(&product, &mut Native(licensing))?;
    report(&format!(
        "旧版通用密钥映射已验证：{} · {} · 末五位 {}；尚未激活。",
        product.edition,
        product.channel,
        &product.key[24..]
    ));
    Ok(product)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_legacy_discovery_only_reads_windows_licenses() {
        let licensing = Licensing::new().unwrap();
        let found = discover(Version::Win7, Method::Kms, "Professional", &licensing).unwrap();
        if let Some(product) = found {
            assert_eq!(product.version, Version::Win7);
            assert_eq!(product.edition, "Professional");
        }
    }
}
