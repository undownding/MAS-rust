//! Legacy non-evaluation Windows dispatch; errors never retry through scripts.
use super::{
    activation_flow::{self, Method},
    crypto::Version,
    legacy_key_runtime,
    legacy_windows::{self, KeyRoute},
    product_selection::Channel,
    windows_context::Context,
};
use crate::native::licensing::Licensing;

pub fn activate(
    context: &Context,
    method: Method,
    auto: bool,
    report: &dyn Fn(&str),
) -> Result<String, String> {
    let layout = super::runtime::storage_preflight()?;
    let expected = Version::detect(context.build).map_err(|e| e.to_string())?;
    if layout.version != expected
        || expected == Version::Modern
        || context.edition.to_ascii_lowercase().contains("eval")
    {
        return Err("旧版普通 Windows 分派与本机版本不符，未执行安装。".into());
    }
    let method =
        super::connectivity::resolve(method, auto, || super::connectivity::connected(report))?;
    let route = legacy_windows::key_route(expected, method)?;
    let result = match route {
        KeyRoute::Fixed(catalog_method) => {
            let licensing = Licensing::new()?;
            let product = legacy_key_runtime::discover(
                expected,
                catalog_method,
                &context.edition,
                &licensing,
            )?
            .ok_or("未找到匹配的旧版固定密钥和本机许可证，未清理配置或安装。")?;
            drop(licensing);
            report(&format!(
                "原生旧版 Windows：{} · {} · {method:?}",
                context.edition, product.id
            ));
            (|| {
                if method == Method::Kms4k {
                    super::kms_cleanup::clear(context.build, report)?;
                }
                let installed = legacy_key_runtime::install(
                    expected,
                    catalog_method,
                    &context.edition,
                    report,
                )?;
                if installed.id != product.id {
                    return Err("目录目标在准备后发生变化；密钥可能已安装，未继续激活。".into());
                }
                let activation = match method {
                    Method::ZeroCid => super::phone_runtime::zero_cid(product.id, report),
                    Method::Kms4k => super::kms4k_runtime::activate(product.id, report),
                    Method::StaticCid => unreachable!("key_route rejects legacy StaticCID"),
                };
                activation.map_err(|e| {
                    format!("旧版固定密钥已安装，激活阶段失败：{e}；不自动卸载或回退脚本。")
                })
            })()
        }
        KeyRoute::Generated => {
            let channel = if method == Method::Kms4k {
                Channel::KmsClient
            } else {
                Channel::Zero
            };
            let sku = super::selection_runtime::windows(&context.edition, channel)?
                .ok_or("未找到适用的旧版 Windows 生成密钥目标，未执行安装。")?;
            report(&format!(
                "原生旧版 Windows：{} · {sku} · {method:?}",
                context.edition
            ));
            let mut backend = activation_flow::Native {
                required_channel: None,
                report,
                cleanup_build: (method == Method::Kms4k).then_some(context.build),
            };
            activation_flow::run(&mut backend, sku, method)
        }
    };
    super::reevaluation::finish(result, || super::reevaluation::run(context.build, report))
}
