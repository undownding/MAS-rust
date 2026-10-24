//! Native StaticCID sequence from the pinned MAS wrapper.
#![allow(dead_code)]
use super::{
    activation_http,
    activation_ws::{RequestType, Response},
    phone::Change,
    phone_runtime,
    pkey_config::Algorithm,
    sl,
};
use uuid::Uuid;
use windows_sys::{
    Win32::Security::Authentication::Identity::SL_LICENSING_STATUS_LICENSED, core::GUID,
};
const EPID: &str = "31337-42069-123-456789-04-1337-2600.0000-2542001";
const ATTEMPTS: [(u32, u32, u64); 2] = [
    (100055, 1000043, 1338662172562478),
    (1345, 1003020, 6311608238084405),
];
/// Caller holds OperationGuard. Phone-data edits retain recoverable backups;
/// network failure is reported with the last completed store modification.
pub fn activate(sku: Uuid, report: &dyn Fn(&str)) -> Result<String, String> {
    if sku.is_nil() {
        return Err("SCID 需要明确的产品激活 ID".into());
    }
    let id = GUID::from_u128(sku.as_u128());
    let context = sl::Context::open().map_err(|e| e.to_string())?;
    let app = context
        .application_id(&id)
        .map_err(|e| e.to_string())?
        .ok_or("产品缺少应用 ID")?;
    drop(context);
    let mut last_backup = None;
    let mut stage = "设置 IID 参数";
    let operation = || -> Result<(), String> {
        let mut deposited = false;
        let mut last_error = String::new();
        for (index, (group, serial, security)) in ATTEMPTS.into_iter().enumerate() {
            stage = "设置 IID 参数";
            report(&format!("SCID 参数组 {}/2", index + 1));
            last_backup = Some(phone_runtime::edit(
                sku,
                Change::Iid {
                    algorithm: Algorithm::Pkey2009,
                    group,
                    serial,
                    security,
                },
                report,
            )?);
            stage = "生成 IID 并请求确认 ID";
            let context = sl::Context::open().map_err(|e| e.to_string())?;
            let iid = context.installation_id(&id).map_err(|e| e.to_string())?;
            drop(context);
            let response = activation_http::call(RequestType::Confirmation, &iid, EPID)
                .map_err(|e| e.to_string())?;
            let Response::Confirmation(cid) = response else {
                return Err("激活服务未返回确认 ID".into());
            };
            stage = "提交确认 ID";
            match sl::Context::open()
                .map_err(|e| e.to_string())?
                .deposit_confirmation(&id, &iid, &cid)
            {
                Ok(()) => {
                    deposited = true;
                    break;
                }
                Err(error) => {
                    last_error = error.to_string();
                    report(&format!("确认 ID 提交失败：{last_error}"));
                }
            }
        }
        if !deposited {
            return Err(format!("两组确认 ID 均未成功提交：{last_error}"));
        }
        stage = "刷新并验证许可状态";
        sl::refresh_license_status().map_err(|e| e.to_string())?;
        let context = sl::Context::open().map_err(|e| e.to_string())?;
        if !context
            .statuses(&app)
            .map_err(|e| e.to_string())?
            .iter()
            .any(|s| {
                Uuid::from_fields(s.SkuId.data1, s.SkuId.data2, s.SkuId.data3, &s.SkuId.data4)
                    == sku
                    && s.eStatus == SL_LICENSING_STATUS_LICENSED
            })
        {
            return Err("确认 ID 已提交，但所选产品尚未报告已许可".into());
        }
        Ok(())
    };
    let mut operation = operation;
    let result = operation();
    let backup = last_backup
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "尚未完成存储修改".into());
    result.map_err(|e| format!("SCID 失败（{stage}）：{e}；最近一次 IID 修改备份：{backup}"))?;
    Ok(format!(
        "所选产品已报告许可状态；最近一次 IID 修改备份：{backup}"
    ))
}
