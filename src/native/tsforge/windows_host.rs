//! Windows KMS Host preparation and native activation. GUI integration follows
//! validation of the license-import and generated CSVLK path.
#![allow(dead_code)]
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
    if context.build < 9600 {
        return Ok(None);
    }
    let method = match option {
        0 if context.build >= 26100 => Method::StaticCid,
        0 | 2 => Method::ZeroCid,
        1 => Method::StaticCid,
        3 => return Err("Windows KMS Host 不支持 KMS4k；请选择 StaticCID 或 ZeroCID".into()),
        _ => return Err("未知 TSforge 方法".into()),
    };
    let method = connectivity::resolve(method, option == 0, || connectivity::connected(report))?;
    if method == Method::Kms4k {
        return Err("Auto 未确认联网，KMS Host 不支持离线 KMS4k，未导入或安装许可".into());
    }
    super::runtime::preflight()?;
    report(
        "KMS Host 使用主机许可证，会使 Software Protection 服务持续运行；部分 Windows 版本可能随后显示不同的版本名称。",
    );
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
