//! Native modern-store phone activation operations. Activation routing is staged.
#![allow(dead_code)]
use super::{
    crypto::{self, Version},
    phone::{self, Change, Target},
    reset, runtime, service, sl,
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
    path: PathBuf,
    target: &Target,
    change: Change<'_>,
    report: &dyn Fn(&str),
) -> Result<PathBuf, String> {
    service::stopped("sppsvc", || {
        let transaction = Transaction::edit(vec![path], |originals| {
            let (store, production) = reset::decode_modern(originals[0])?;
            let changed = phone::apply(&store, target, change)?;
            if changed == store {
                return Ok(vec![originals[0].to_vec()]);
            }
            let plain = changed.encode()?;
            let encrypted = crypto::encrypt(&plain, production, Version::Modern)?;
            if crypto::decrypt(&encrypted, production, Version::Modern)? != plain {
                return Err(std::io::Error::other("电话许可存储加密校验失败"));
            }
            Ok(vec![encrypted])
        })
        .map_err(|e| e.to_string())?;
        report(&format!(
            "电话许可存储备份：{}",
            transaction.backup_path().display()
        ));
        transaction.commit().map_err(|e| e.to_string())
    })
}
/// Caller holds OperationGuard, as for every licensing mutation.
pub fn edit(sku: Uuid, change: Change<'_>, report: &dyn Fn(&str)) -> Result<PathBuf, String> {
    let path = runtime::preflight()?;
    let context = sl::Context::open().map_err(|e| e.to_string())?;
    let target = resolve(&context, sku, true)?;
    drop(context);
    write(path, &target, change, report)
}
pub fn zero_cid(sku: Uuid, report: &dyn Fn(&str)) -> Result<String, String> {
    let path = runtime::preflight()?;
    let context = sl::Context::open().map_err(|e| e.to_string())?;
    let target = resolve(&context, sku, false)?;
    if !context
        .phone_activatable(&guid(target.sku))
        .map_err(|e| e.to_string())?
    {
        return Err("此产品没有电话激活许可".into());
    }
    let iid = context
        .installation_id(&guid(target.sku))
        .map_err(|e| e.to_string())?;
    drop(context);
    let backup = write(
        path,
        &target,
        Change::ZeroCid {
            installation_id: &iid,
        },
        report,
    )?;
    let finish = || -> Result<(), String> {
        let context = sl::Context::open().map_err(|e| e.to_string())?;
        context
            .deposit_confirmation(&guid(target.sku), &iid, phone::ZERO_CID)
            .map_err(|e| e.to_string())?;
        drop(context);
        sl::refresh_license_status().map_err(|e| e.to_string())?;
        let context = sl::Context::open().map_err(|e| e.to_string())?;
        context
            .state_changed(&guid(target.app))
            .map_err(|e| e.to_string())?;
        if !context
            .statuses(&guid(target.app))
            .map_err(|e| e.to_string())?
            .iter()
            .any(|s| uuid(s.SkuId) == target.sku && s.eStatus == SL_LICENSING_STATUS_LICENSED)
        {
            return Err("确认 ID 已提交，但所选产品尚未报告已许可".into());
        }
        Ok(())
    };
    finish().map_err(|e| {
        format!(
            "ZeroCID 后续步骤失败：{e}。存储已修改；备份：{}",
            backup.display()
        )
    })?;
    super::host_runtime::after_activation(target.sku, report)
        .map_err(|e| format!("ZeroCID 已验证许可状态，但后续 KMS Host 处理失败：{e}"))?;
    Ok(format!(
        "所选产品已报告许可状态；存储备份：{}",
        backup.display()
    ))
}
