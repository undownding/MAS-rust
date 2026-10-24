//! Windows KMS Host license preparation and native activation from the GUI.
use super::{
    activation_flow::{self, Method},
    connectivity, host_licenses,
    product_selection::Channel,
    reevaluation, selection_runtime,
    windows_context::Context,
};
use crate::native::{licensing::Licensing, platform};
use wmi::Variant;

pub fn activate(option: usize, report: &dyn Fn(&str)) -> Result<Option<String>, String> {
    if !crate::process::is_admin() {
        return Err("请以管理员身份运行".into());
    }
    if std::env::var("PROCESSOR_ARCHITEW6432").is_ok_and(|v| !v.is_empty()) {
        return Err("原生 TSforge 不支持跨架构仿真，请使用本机 x64 构建".into());
    }
    let context = Context::read(report)?;
    let method = host_licenses::method(option, context.build)?;
    let method = connectivity::resolve(method, option == 0, || connectivity::connected(report))?;
    if method == Method::Kms4k {
        return Err("Auto 未确认联网，KMS Host 不支持离线 KMS4k，未导入或安装许可".into());
    }
    let layout = super::runtime::storage_preflight()?;
    report(
        "KMS Host 使用主机许可证，会使 Software Protection 服务持续运行；部分 Windows 版本可能随后显示不同的版本名称。",
    );
    if layout.version == super::crypto::Version::Vista {
        let product = super::legacy_key_runtime::install(
            layout.version,
            super::legacy_windows::Method::Host,
            &context.edition,
            report,
        )?;
        let result = super::phone_runtime::zero_cid(product.id, report)
            .map_err(|e| format!("Vista CSVLK 密钥已安装，后续主机激活失败：{e}；不回退脚本。"));
        return reevaluation::finish(result, || reevaluation::run(context.build, report)).map(Some);
    }
    let files = host_licenses::prepare(
        &platform::system_file(r"spp\tokens\skus")?,
        &context.edition,
        context.build,
    )?;
    let licensing = Licensing::new()?;
    let imported = host_licenses::import_all(&files, |license| {
        report(&format!("导入 CSVLK 许可：{}", license.path.display()));
        licensing.service(
            "SoftwareLicensingService",
            "InstallLicense",
            &[("LicenseFile", Variant::String(license.xml.clone()))],
        )
    })?;
    let result = (|| {
        let sku = selection_runtime::windows(&context.edition, Channel::KmsHost)?
            .ok_or_else(|| format!("未找到 {} 的 KMS Host 产品许可证", context.edition))?;
        report(&format!(
            "KMS Host {} · {sku} · {method:?}",
            context.edition
        ));
        let mut backend = activation_flow::Native {
            report,
            cleanup_build: None,
            required_channel: Some("Volume:CSVLK"),
        };
        activation_flow::run(&mut backend, sku, method)
    })()
    .map_err(|error| format!("KMS Host 许可准备已导入 {imported} 个文件；后续失败：{error}"));
    reevaluation::finish(result, || reevaluation::run(context.build, report)).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn csvlk_discovery_reads_system_files_without_installing() {
        let context = Context::read(&|_| {}).unwrap();
        let files = host_licenses::prepare(
            &platform::system_file(r"spp\tokens\skus").unwrap(),
            &context.edition,
            context.build,
        )
        .unwrap();
        for file in files {
            assert!(!file.xml.is_empty());
        }
    }
}
