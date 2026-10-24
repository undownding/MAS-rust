//! Native KMS host charging after successful SCID/ZeroCID activation.
#![allow(dead_code)]
use super::{
    crypto::{self, Version},
    host_charge, reset, runtime, service, sl,
    transaction::Transaction,
};
use rsa::rand_core::{OsRng, RngCore};
use std::collections::HashSet;
use uuid::Uuid;
use windows_sys::{
    Win32::{Foundation::FILETIME, System::SystemInformation::GetSystemTimeAsFileTime},
    core::GUID,
};
fn uuid(id: GUID) -> Uuid {
    Uuid::from_fields(id.data1, id.data2, id.data3, &id.data4)
}
fn clients() -> Result<Vec<Uuid>, String> {
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    for _ in 0..256 {
        let mut bytes = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|e| e.to_string())?;
        bytes[6] = (bytes[6] & 15) | 0x40;
        bytes[8] = (bytes[8] & 63) | 0x80;
        let id = Uuid::from_bytes(bytes);
        if seen.insert(id) {
            output.push(id);
        }
        if output.len() == host_charge::CLIENTS {
            return Ok(output);
        }
    }
    Err("无法生成不同的 KMS 客户端 ID".into())
}
/// Called only after the activation method has verified the selected SKU.
/// Non-CSVLK products are left untouched. Caller still holds OperationGuard.
pub fn after_activation(sku: Uuid, report: &dyn Fn(&str)) -> Result<(), String> {
    if sku.is_nil() {
        return Err("KMS Host Charge 需要明确的产品 ID".into());
    }
    let id = GUID::from_u128(sku.as_u128());
    let context = sl::Context::open().map_err(|e| e.to_string())?;
    let keys = context.installed_keys(&id).map_err(|e| e.to_string())?;
    if keys.len() != 1 {
        return Err("无法唯一确定激活后的产品密钥".into());
    }
    if context
        .key_channel(&keys[0])
        .map_err(|e| e.to_string())?
        .as_deref()
        != Some("Volume:CSVLK")
    {
        return Ok(());
    }
    let app = context
        .application_id(&id)
        .map_err(|e| e.to_string())?
        .ok_or("KMS Host 产品缺少应用 ID")?;
    drop(context);
    let path = runtime::preflight()?;
    let ids = clients()?;
    service::stopped("sppsvc", || {
        let transaction = Transaction::edit(vec![path], |originals| {
            let (store, production) = reset::decode_modern(originals[0])?;
            let mut now = FILETIME::default();
            unsafe {
                GetSystemTimeAsFileTime(&mut now);
            }
            let timestamp =
                ((u64::from(now.dwHighDateTime) << 32) | u64::from(now.dwLowDateTime)) as i64;
            let data = host_charge::apply(&store, uuid(app), timestamp, &ids)?.encode()?;
            let encrypted = crypto::encrypt(&data, production, Version::Modern)?;
            if crypto::decrypt(&encrypted, production, Version::Modern)? != data {
                return Err(std::io::Error::other("KMS Host 数据加密回读不一致"));
            }
            Ok(vec![encrypted])
        })
        .map_err(|e| e.to_string())?;
        report(&format!(
            "KMS Host 计数备份：{}",
            transaction.backup_path().display()
        ));
        transaction.commit().map_err(|e| e.to_string())?;
        Ok(())
    })?;
    sl::refresh_license_status()
        .map_err(|e| format!("KMS Host 记录已写入，但许可刷新失败：{e}"))?;
    report("KMS Host 已写入并回读校验 25 条客户端计数记录。");
    Ok(())
}
#[cfg(test)]
mod tests {
    #[test]
    fn client_ids_are_distinct_v4_guids_generated_without_licensing_calls() {
        let ids = super::clients().unwrap();
        assert_eq!(ids.len(), 25);
        assert_eq!(
            ids.iter().collect::<std::collections::HashSet<_>>().len(),
            25
        );
        for id in ids {
            assert_eq!(id.get_version_num(), 4);
            assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
        }
    }
}
