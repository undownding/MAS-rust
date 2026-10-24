//! Native KMS4k coordination; full TSforge product routing is still being migrated.
#![allow(dead_code)]
use super::{
    crypto::{self, Version},
    kms4k, reset, runtime, service, sl,
    transaction::Transaction,
};
use crate::native::{licensing, registry::Key};
use uuid::Uuid;
use windows_sys::{
    Win32::{
        Foundation::{FILETIME, SYSTEMTIME},
        System::{
            Registry::KEY_WOW64_64KEY,
            SystemInformation::{GetLocalTime, GetSystemTimeAsFileTime},
            Time::{FileTimeToSystemTime, SystemTimeToFileTime},
        },
    },
    core::GUID,
};
fn uuid(id: GUID) -> Uuid {
    Uuid::from_fields(id.data1, id.data2, id.data3, &id.data4)
}
fn ticks(time: FILETIME) -> u64 {
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}
fn projected_year(local: &SYSTEMTIME, minutes: u32) -> Result<u32, String> {
    let mut base = FILETIME::default();
    // Treat the local calendar fields as a continuous calendar, matching
    // DateTime.Now.AddMinutes without converting them to another timezone.
    if unsafe { SystemTimeToFileTime(local, &mut base) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let total = ticks(base)
        .checked_add(u64::from(minutes) * 600_000_000)
        .ok_or("宽限期日期溢出")?;
    let time = FILETIME {
        dwLowDateTime: total as u32,
        dwHighDateTime: (total >> 32) as u32,
    };
    let mut result = SYSTEMTIME::default();
    if unsafe { FileTimeToSystemTime(&time, &mut result) } == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if result.wYear > 9999 {
        return Err("宽限期超出日期范围".into());
    }
    Ok(result.wYear.into())
}
/// Caller holds OperationGuard for the entire operation.
pub fn activate(sku: Uuid, report: &dyn Fn(&str)) -> Result<String, String> {
    let path = runtime::preflight()?;
    let context = sl::Context::open().map_err(|e| e.to_string())?;
    let id = if sku.is_nil() {
        context
            .default_activation_id(&sl::WINDOWS_APP_ID, true)
            .map_err(|e| e.to_string())?
            .ok_or("没有适用的 Windows 产品")?
    } else {
        GUID::from_u128(sku.as_u128())
    };
    let sku = uuid(id);
    let app = context
        .application_id(&id)
        .map_err(|e| e.to_string())?
        .ok_or("产品缺少应用 ID")?;
    let keys = context.installed_keys(&id).map_err(|e| e.to_string())?;
    if keys.len() != 1 {
        return Err("KMS4k 要求所选产品恰有一个已安装密钥".into());
    }
    if context
        .key_channel(&keys[0])
        .map_err(|e| e.to_string())?
        .as_deref()
        != Some("Volume:GVLK")
    {
        return Err("KMS4k 需要 Volume:GVLK 产品密钥".into());
    }
    drop(context);
    let build: u32 = Key::open(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        KEY_WOW64_64KEY,
        false,
    )?
    .ok_or("缺少系统版本键")?
    .string("CurrentBuildNumber")?
    .ok_or("缺少系统构建号")?
    .parse()
    .map_err(|_| "系统构建号无效")?;
    let backup = service::stopped("sppsvc", || {
        let transaction = Transaction::edit(vec![path], |originals| {
            let (store, production) = reset::decode_modern(originals[0])?;
            let mut now = FILETIME::default();
            unsafe {
                GetSystemTimeAsFileTime(&mut now);
            }
            let modified = kms4k::apply(&store, uuid(app), sku, ticks(now))?.encode()?;
            let encrypted = crypto::encrypt(&modified, production, Version::Modern)?;
            if crypto::decrypt(&encrypted, production, Version::Modern)? != modified {
                return Err(std::io::Error::other("KMS4k 加密回读不一致"));
            }
            Ok(vec![encrypted])
        })
        .map_err(|e| e.to_string())?;
        report(&format!(
            "KMS4k 存储备份：{}",
            transaction.backup_path().display()
        ));
        transaction.commit().map_err(|e| e.to_string())
    })?;
    let finish = || -> Result<u32, String> {
        sl::refresh_license_status().map_err(|e| e.to_string())?;
        let context = sl::Context::open().map_err(|e| e.to_string())?;
        context.state_changed(&app).map_err(|e| e.to_string())?;
        let wmi = licensing::Licensing::new()?;
        let products = wmi.query(&format!(
            "SELECT GracePeriodRemaining FROM SoftwareLicensingProduct WHERE ID='{sku}'"
        ))?;
        if products.len() != 1 {
            return Err("无法唯一读取所选产品的宽限期".into());
        }
        let grace = licensing::number(&products[0], "GracePeriodRemaining")?;
        let mut local = SYSTEMTIME::default();
        unsafe {
            GetLocalTime(&mut local);
        }
        let year = projected_year(&local, grace)?;
        if !kms4k::accepted(build, grace, year) {
            return Err(format!("产品宽限期未达到 KMS4k 验收条件：{grace} 分钟"));
        }
        Ok(grace)
    };
    let grace = finish().map_err(|e| {
        format!(
            "KMS4k 存储已写入，但后续验证失败：{e}；备份：{}",
            backup.display()
        )
    })?;
    Ok(format!(
        "所选产品宽限期通过 KMS4k 版本规则检查：{grace} 分钟；备份：{}",
        backup.display()
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projected_local_calendar_handles_year_boundary_without_timezone_conversion() {
        let time = SYSTEMTIME {
            wYear: 2038,
            wMonth: 12,
            wDay: 31,
            wHour: 23,
            wMinute: 59,
            ..Default::default()
        };
        assert_eq!(projected_year(&time, 0).unwrap(), 2038);
        assert_eq!(projected_year(&time, 1).unwrap(), 2039);
        assert!(
            projected_year(
                &SYSTEMTIME {
                    wYear: 9999,
                    wMonth: 12,
                    wDay: 31,
                    ..Default::default()
                },
                1440
            )
            .is_err()
        );
    }
}
