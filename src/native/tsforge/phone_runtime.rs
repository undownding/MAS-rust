//! Native versioned phone activation operations. Legacy product routing is staged.
#![allow(dead_code)]
use super::{
    crypto::{self, Version},
    paired_store,
    phone::{self, Change, Target},
    phone_flow::{self, Backend},
    reset, runtime, service, sl,
    storage_layout::Physical,
    transaction::Transaction,
};
use std::path::PathBuf;
use uuid::Uuid;
use windows_sys::{
    Win32::Security::Authentication::Identity::SL_LICENSING_STATUS_LICENSED, core::GUID,
};
fn uuid(id: GUID) -> Uuid {
    Uuid::from_fields(id.data1, id.data2, id.data3, &id.data4)
}
fn guid(id: Uuid) -> GUID {
    GUID::from_u128(id.as_u128())
}
fn resolve(context: &sl::Context, sku: Uuid, include_activated: bool) -> Result<Target, String> {
    let sku = if sku.is_nil() {
        context
            .default_activation_id(&sl::WINDOWS_APP_ID, include_activated)
            .map_err(|e| e.to_string())?
            .ok_or("没有适用的 Windows 产品")?
    } else {
        guid(sku)
    };
    let app = context
        .application_id(&sku)
        .map_err(|e| e.to_string())?
        .ok_or("产品缺少应用 ID")?;
    let keys = context.installed_keys(&sku).map_err(|e| e.to_string())?;
    if keys.len() != 1 {
        return Err("产品必须恰有一个已安装密钥".into());
    }
    let target = Target {
        app: uuid(app),
        sku: uuid(sku),
        key: uuid(keys[0]),
    };
    if target.key.is_nil() {
        return Err("已安装密钥 ID 为空".into());
    }
    Ok(target)
}
fn write(
    layout: &Physical,
    target: &Target,
    change: Change<'_>,
    report: &dyn Fn(&str),
) -> Result<PathBuf, String> {
    service::stopped(layout.service, || {
        let transform = |original: &[u8]| {
            let (store, production) = reset::decode(original, layout.version)?;
            let changed = phone::apply(&store, target, change)?;
            if changed == store {
                return Ok(original.to_vec());
            }
            let plain = changed.encode()?;
            let encrypted = crypto::encrypt(&plain, production, layout.version)?;
            if crypto::decrypt(&encrypted, production, layout.version)? != plain {
                return Err(std::io::Error::other("电话许可存储加密校验失败"));
            }
            Ok(encrypted)
        };
        if layout.version.paired() {
            let transaction = paired_store::edit(&layout.paths[0], &layout.paths[1], transform)
                .map_err(|e| e.to_string())?;
            report(&format!(
                "电话许可双文件备份：{}",
                transaction.backup_path().display()
            ));
            transaction.commit().map_err(|e| e.to_string())
        } else {
            let transaction = Transaction::edit(layout.paths.clone(), |originals| {
                transform(originals[0]).map(|bytes| vec![bytes])
            })
            .map_err(|e| e.to_string())?;
            report(&format!(
                "电话许可存储备份：{}",
                transaction.backup_path().display()
            ));
            transaction.commit().map_err(|e| e.to_string())
        }
    })
}
/// Caller holds OperationGuard, as for every licensing mutation.
pub fn edit(sku: Uuid, change: Change<'_>, report: &dyn Fn(&str)) -> Result<PathBuf, String> {
    let layout = runtime::storage_preflight()?;
    let context = sl::Context::open().map_err(|e| e.to_string())?;
    let target = resolve(&context, sku, true)?;
    drop(context);
    write(&layout, &target, change, report)
}
pub fn zero_cid(sku: Uuid, report: &dyn Fn(&str)) -> Result<String, String> {
    let layout = runtime::storage_preflight()?;
    let context = sl::Context::open().map_err(|e| e.to_string())?;
    let target = resolve(&context, sku, false)?;
    if !context
        .phone_activatable(&guid(target.sku))
        .map_err(|e| e.to_string())?
    {
        return Err("此产品没有电话激活许可".into());
    }
    if layout.version != Version::Modern
        && context
            .key_channel(&guid(target.key))
            .map_err(|e| e.to_string())?
            .as_deref()
            == Some("Volume:CSVLK")
    {
        return Err("旧版 KMS Host 计数后处理尚未接入，未提交确认 ID 或修改存储。".into());
    }
    let iid = context
        .installation_id(&guid(target.sku))
        .map_err(|e| e.to_string())?;
    drop(context);
    struct Native<'a> {
        layout: &'a Physical,
        target: &'a Target,
        iid: &'a str,
        report: &'a dyn Fn(&str),
    }
    impl Backend for Native<'_> {
        fn deposit(&mut self) -> Result<(), String> {
            let context = sl::Context::open().map_err(|e| e.to_string())?;
            context
                .deposit_confirmation(&guid(self.target.sku), self.iid, phone::ZERO_CID)
                .map_err(|e| e.to_string())
        }
        fn write_store(&mut self) -> Result<PathBuf, String> {
            write(
                self.layout,
                self.target,
                Change::ZeroCid {
                    installation_id: self.iid,
                },
                self.report,
            )
        }
        fn verify(&mut self) -> Result<(), String> {
            sl::refresh_license_status().map_err(|e| e.to_string())?;
            let context = sl::Context::open().map_err(|e| e.to_string())?;
            context
                .state_changed(&guid(self.target.app))
                .map_err(|e| e.to_string())?;
            if !context
                .statuses(&guid(self.target.app))
                .map_err(|e| e.to_string())?
                .iter()
                .any(|s| {
                    uuid(s.SkuId) == self.target.sku && s.eStatus == SL_LICENSING_STATUS_LICENSED
                })
            {
                return Err("所选产品尚未报告已许可".into());
            }
            Ok(())
        }
    }
    let backup = phone_flow::run(
        layout.version,
        &mut Native {
            layout: &layout,
            target: &target,
            iid: &iid,
            report,
        },
    )?;
    super::host_runtime::after_activation(target.sku, report).map_err(|e| {
        format!(
            "ZeroCID 已验证许可状态，但后续 KMS Host 处理失败：{e}；存储备份：{}",
            backup.display()
        )
    })?;
    Ok(format!(
        "所选产品已报告许可状态；存储备份：{}",
        backup.display()
    ))
}
