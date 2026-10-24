//! Office KMS Host and APPX sideloading orchestration, using installed SKUs only.
use super::{
    activation_flow::{self, Method},
    auxiliary::{self, Scope},
    connectivity, reevaluation,
    windows_context::Context,
};
use std::collections::HashSet;
use uuid::Uuid;
fn discover(scope: Scope) -> Result<Vec<auxiliary::Product>, String> {
    use crate::native::licensing::{Licensing, string};
    let licensing = Licensing::new()?;
    let mut installed = HashSet::new();
    for app in scope.applications() {
        for product in licensing.query(&format!(
            "SELECT ID FROM SoftwareLicensingProduct WHERE ApplicationID='{app}'"
        ))? {
            installed.insert(
                Uuid::parse_str(&string(&product, "ID")?)
                    .map_err(|e| format!("无效产品 ID：{e}"))?,
            );
        }
    }
    Ok(scope.select(&installed))
}
pub fn activate(
    scope: Scope,
    option: usize,
    report: &dyn Fn(&str),
) -> Result<Option<String>, String> {
    if !crate::process::is_admin() {
        return Err("请以管理员身份运行".into());
    }
    if std::env::var("PROCESSOR_ARCHITEW6432").is_ok_and(|v| !v.is_empty()) {
        return Err("原生 TSforge 不支持跨架构仿真，请使用本机 x64 构建".into());
    }
    let context = Context::read(report)?;
    if !scope.supported(context.build) {
        return Ok(Some(
            match scope {
                Scope::OfficeHost => "此 Windows 版本不支持 Office KMS Host",
                Scope::Appx => "APPX 旁加载许可仅适用于 Windows 8/8.1，当前系统未执行修改",
            }
            .into(),
        ));
    }
    if context.build < 9600 {
        return Ok(None);
    }
    let method = match option {
        0 if context.build >= 26100 => Method::StaticCid,
        0 | 2 => Method::ZeroCid,
        1 => Method::StaticCid,
        3 => return Err("此功能不支持 KMS4k，请选择 StaticCID 或 ZeroCID".into()),
        _ => return Err("未知 TSforge 方法".into()),
    };
    let method = connectivity::resolve(method, option == 0, || connectivity::connected(report))?;
    if method == Method::Kms4k {
        return Err("Auto 未确认联网，此功能不支持离线 KMS4k，未执行激活".into());
    }
    let products = discover(scope)?;
    if products.is_empty() {
        return Err(match scope {
            Scope::OfficeHost => "本机未安装 Office KMS Host 许可证，请先安装对应的许可证包",
            Scope::Appx => "本机未找到 APPX 旁加载许可证；此许可仅适用于相应 Pro 及更高版本",
        }
        .into());
    }
    if scope == Scope::OfficeHost {
        report(
            "Office KMS Host 是主机许可，不是 Office 客户端；Software Protection 服务将持续运行。",
        );
    }
    let batch = auxiliary::run(&products, |product| {
        report(&format!("{} · {} · {method:?}", product.name, product.id));
        let mut backend = activation_flow::Native {
            report,
            cleanup_build: None,
            required_channel: if scope == Scope::OfficeHost {
                Some("Volume:CSVLK")
            } else {
                None
            },
        };
        match activation_flow::run(&mut backend, product.id, method) {
            Ok(message) => {
                report(&message);
                Ok(())
            }
            Err(error) => {
                report(&error);
                Err(error)
            }
        }
    });
    let result = if batch.errors.is_empty() {
        Ok(format!("{scope:?} 已验证 {} 项许可状态。", batch.succeeded))
    } else {
        Err(format!(
            "{scope:?} 已验证 {}/{} 项；已完成修改不自动回滚：\n{}",
            batch.succeeded,
            products.len(),
            batch.errors.join("\n")
        ))
    };
    reevaluation::finish(result, || reevaluation::run(context.build, report)).map(Some)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovers_installed_applications_without_changing_licenses() {
        for scope in [Scope::OfficeHost, Scope::Appx] {
            let products = discover(scope).unwrap();
            assert!(products.iter().all(|p| !p.id.is_nil()));
        }
    }
}
