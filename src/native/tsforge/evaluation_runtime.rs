//! Native versioned Windows evaluation activation; never invokes a script engine.
#![allow(dead_code)]
use super::{
    evaluation::{self, Backend, Product},
    windows_context::Context,
};
use crate::native::licensing::{Licensing, WINDOWS_APP, number, string};
use std::collections::HashSet;
use uuid::Uuid;
pub fn discover(edition: &str, licensing: &Licensing) -> Result<Option<Product>, String> {
    let ids = licensing
        .products("SoftwareLicensingProduct", WINDOWS_APP, false)?
        .iter()
        .map(|p| {
            Uuid::parse_str(&string(p, "ID")?).map_err(|e| format!("Windows 激活 ID 无效：{e}"))
        })
        .collect::<Result<HashSet<_>, _>>()?;
    Ok(evaluation::select(edition, &ids))
}
struct Native<'a> {
    licensing: Licensing,
    report: &'a dyn Fn(&str),
}
impl Native<'_> {
    fn product(&self, product: &Product) -> Result<wmi::IWbemClassWrapper, String> {
        let mut products = self.licensing.query(&format!("SELECT * FROM SoftwareLicensingProduct WHERE ApplicationID='{WINDOWS_APP}' AND ID='{}' AND PartialProductKey IS NOT NULL AND LicenseDependsOn IS NULL", product.id))?;
        if products.len() != 1 {
            return Err("目标评估许可缺失或不唯一".into());
        }
        Ok(products.remove(0))
    }
}
impl Backend for Native<'_> {
    fn reset(&mut self) -> Result<(), String> {
        let result = super::runtime::reset(self.report)?;
        (self.report)(&result);
        Ok(())
    }
    fn install(&mut self, product: &Product) -> Result<(), String> {
        self.licensing.install(product.key)?;
        self.licensing.refresh()?;
        let installed = self.product(product)?;
        if !string(&installed, "PartialProductKey")?.eq_ignore_ascii_case(&product.key[24..]) {
            return Err("安装后的密钥末五位与评估目录不符".into());
        }
        (self.report)(&format!(
            "已安装评估密钥：{} · 末五位 {}",
            product.id,
            &product.key[24..]
        ));
        Ok(())
    }
    fn activate(&mut self, product: &Product) -> Result<(), String> {
        self.licensing
            .product_method(&self.product(product)?, "Activate")?;
        self.licensing.refresh()
    }
    fn status(&mut self, product: &Product) -> Result<(u32, u32), String> {
        let installed = self.product(product)?;
        Ok((
            number(&installed, "LicenseStatus")?,
            number(&installed, "GracePeriodRemaining")?,
        ))
    }
}
pub fn activate(context: &Context, report: &dyn Fn(&str)) -> Result<String, String> {
    let layout = super::runtime::storage_preflight()?;
    if layout.version != super::crypto::Version::detect(context.build).map_err(|e| e.to_string())? {
        return Err("评估版上下文与本机存储版本不符，未执行重置。".into());
    }
    if !context.edition.to_ascii_lowercase().contains("eval") {
        return Err("当前 Windows 不是评估版，未执行评估重置".into());
    }
    let licensing = Licensing::new()?;
    let product = discover(&context.edition, &licensing)?
        .ok_or("未找到匹配的已安装评估许可证及密钥；未执行重置")?;
    if !super::connectivity::connected(report) {
        return Err("评估版激活需要联网；未执行重置或密钥安装".into());
    }
    report(&format!(
        "Windows {} / {} 评估版：将重置评估计时器并请求联网激活；不能转为永久许可。",
        product.edition, product.version
    ));
    let mut backend = Native { licensing, report };
    evaluation::run(&product, &mut backend)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_evaluation_discovery_is_read_only() {
        let licensing = Licensing::new().unwrap();
        let context = Context::read(&|_| {}).unwrap();
        if let Some(product) = discover(&context.edition, &licensing).unwrap() {
            assert!(context.edition.to_ascii_lowercase().contains("eval"));
            assert_eq!(product.key.len(), 29);
        }
    }
}
