//! Native PKEY2005 installation coordinator, awaiting activation route integration.
#![allow(dead_code)]
use super::{
    crypto::{self, Version},
    generated_key::{Generated, Prepared},
    key_install::{self, RegistryData, Request},
    pid_context, pkey_config,
    product_key::{Metadata, utf16},
    registry_backup::{Edit, RegistryValues},
    registry_targets::SPECS,
    reset, runtime, service, sl,
    transaction::Transaction,
};
use crate::native::{
    platform,
    registry::{Hive, Key, RawValue},
};
use std::{io, path::PathBuf};
use windows_sys::{
    Win32::{
        Foundation::SYSTEMTIME,
        Globalization::GetSystemDefaultLCID,
        System::{
            Registry::{KEY_WOW64_64KEY, REG_BINARY, REG_DWORD, REG_SZ},
            SystemInformation::GetLocalTime,
        },
    },
    core::GUID,
};

struct RegistryPlan {
    keys: Vec<Key>,
    changes: Vec<(usize, RawValue)>,
}
impl RegistryPlan {
    fn open(data: Option<&RegistryData>) -> Result<Self, String> {
        let mut result = Self {
            keys: vec![],
            changes: vec![],
        };
        let Some(data) = data else {
            return Ok(result);
        };
        let ie = Key::open(SPECS[3].path, KEY_WOW64_64KEY, false)?
            .map(|key| key.raw_value("ProductId"))
            .transpose()?
            .flatten()
            .is_some();
        for (index, spec) in SPECS.iter().enumerate() {
            if (3..6).contains(&index) && !ie || index == 6 && !data.kms_host {
                continue;
            }
            let key = Key::at(
                if spec.users {
                    Hive::Users
                } else {
                    Hive::Machine
                },
                spec.path,
                KEY_WOW64_64KEY,
                true,
            )?
            .ok_or_else(|| format!("产品注册表目标不存在：{}", spec.path))?;
            let value = match index {
                0 | 3 => RawValue {
                    kind: REG_SZ,
                    bytes: utf16(&data.product_id),
                },
                1 | 4 => RawValue {
                    kind: REG_BINARY,
                    bytes: data.digital_product_id.clone(),
                },
                2 | 5 => RawValue {
                    kind: REG_BINARY,
                    bytes: data.digital_product_id4.clone(),
                },
                _ => RawValue {
                    kind: REG_DWORD,
                    bytes: 1u32.to_le_bytes().to_vec(),
                },
            };
            result.keys.push(key);
            result.changes.push((index, value));
        }
        Ok(result)
    }
    fn capture(&self) -> io::Result<RegistryValues<'_>> {
        RegistryValues::capture(
            self.keys
                .iter()
                .zip(&self.changes)
                .map(|(key, (index, value))| Edit {
                    id: SPECS[*index].id,
                    key,
                    name: SPECS[*index].name,
                    replacement: Some(value.clone()),
                })
                .collect(),
        )
    }
}
fn transform(originals: &[&[u8]], request: &Request<'_>) -> io::Result<key_install::Plan> {
    let (store, production) = reset::decode_modern(originals[0])?;
    let mut plan = key_install::prepare(&store.encode()?, originals[1], request)?;
    let encrypted = crypto::encrypt(&plan.physical, production, Version::Modern)?;
    if crypto::decrypt(&encrypted, production, Version::Modern)? != plan.physical {
        return Err(io::Error::other("生成密钥存储加密回读不一致"));
    }
    plan.physical = encrypted;
    Ok(plan)
}
fn setup_text(path: PathBuf) -> Result<Option<String>, String> {
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("读取 {}：{e}", path.display())),
    };
    let text = if let Some(bytes) = bytes.strip_prefix(&[0xff, 0xfe]) {
        if !bytes.len().is_multiple_of(2) {
            return Err("setup.cfg UTF-16 长度无效".into());
        }
        String::from_utf16(
            &bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>(),
        )
        .map_err(|e| e.to_string())?
    } else {
        String::from_utf8(bytes).map_err(|e| format!("setup.cfg 编码不支持：{e}"))?
    };
    Ok(Some(text))
}
/// Caller holds OperationGuard. The pre-uninstall checkpoint is retained even
/// when later SLC operations fail; API side effects are not automatically undone.
pub fn install(prepared: &Prepared, report: &dyn Fn(&str)) -> Result<String, String> {
    let Generated::Pkey2005(key) = prepared.key else {
        return Err("此路径仅接受 PKEY2005".into());
    };
    let physical = runtime::preflight()?;
    let tokens = runtime::store_path("tokens.dat")?;
    let cache = tokens
        .parent()
        .ok_or("令牌路径缺少父目录")?
        .join("cache/cache.dat");
    crate::native::hook_files::plain_ancestors(&cache)?;
    let version =
        Key::open(SPECS[0].path, KEY_WOW64_64KEY, false)?.ok_or("Windows 版本键不存在")?;
    let build: u32 = version
        .string("CurrentBuildNumber")?
        .ok_or("Windows 构建号不存在")?
        .parse()
        .map_err(|_| "Windows 构建号无效")?;
    let architecture = std::env::var("PROCESSOR_ARCHITECTURE").map_err(|e| e.to_string())?;
    let setup = if prepared.product.edition.contains(';') {
        None
    } else {
        setup_text(platform::system_file(r"oobe\setup.cfg")?)?
    };
    let mpc = pid_context::mpc(
        build,
        &prepared.product.edition,
        &architecture,
        setup.as_deref(),
    )
    .map_err(|e| e.to_string())?;
    let mut now = SYSTEMTIME::default();
    unsafe {
        GetLocalTime(&mut now);
    }
    let day = pid_context::day_of_year(now.wYear.into(), now.wMonth.into(), now.wDay.into())
        .map_err(|e| e.to_string())?;
    let sku = GUID::from_u128(prepared.product.activation_id.as_u128());
    let (app, windows_base, family) = {
        let context = sl::Context::open().map_err(|e| e.to_string())?;
        let app = context
            .application_id(&sku)
            .map_err(|e| e.to_string())?
            .ok_or("产品缺少应用 ID")?;
        let windows = app.data1 == sl::WINDOWS_APP_ID.data1
            && app.data2 == sl::WINDOWS_APP_ID.data2
            && app.data3 == sl::WINDOWS_APP_ID.data3
            && app.data4 == sl::WINDOWS_APP_ID.data4;
        let base = windows && !context.is_addon(&sku).map_err(|e| e.to_string())?;
        let family = if base {
            context
                .sku_information(&sku, "Family")
                .map_err(|e| e.to_string())?
                .ok_or("Windows 产品缺少 Family")?
                .string()
                .map_err(|e| e.to_string())?
        } else {
            String::new()
        };
        (app, base, family)
    };
    let request = Request {
        version: Version::Modern,
        key,
        metadata: Metadata {
            mpc: &mpc,
            activation_id: prepared.product.activation_id.to_bytes_le(),
            edition: &prepared.product.edition,
            part_number: prepared.range.part_number(),
            channel: &prepared.product.channel,
            eula: &prepared.range.eula,
            lcid: unsafe { GetSystemDefaultLCID() },
            build,
            day,
            year: now.wYear.into(),
        },
        application_id: uuid::Uuid::from_fields(app.data1, app.data2, app.data3, &app.data4)
            .to_bytes_le(),
        windows_family: windows_base.then_some(family.as_str()),
        pid_nonce: pkey_config::random_below(1000).map_err(|e| e.to_string())?,
    };
    let paths = vec![physical, tokens];
    let mut registry_plan = None;
    let mut checkpoint = None;
    service::stopped("sppsvc", || {
        let mut registry_data = None;
        let transaction = Transaction::edit(paths.clone(), |originals| {
            let plan = transform(originals, &request)?;
            registry_data = plan.registry;
            Ok(vec![plan.physical, plan.tokens])
        })
        .map_err(|e| e.to_string())?;
        let registry = RegistryPlan::open(registry_data.as_ref())?;
        let mut participant = registry.capture().map_err(|e| e.to_string())?;
        report(&format!(
            "卸载前存储与产品注册表备份：{}",
            transaction.backup_path().display()
        ));
        checkpoint = Some(
            transaction
                .checkpoint(&mut participant)
                .map_err(|e| e.to_string())?,
        );
        drop(participant);
        registry_plan = Some(registry);
        Ok(())
    })?;
    let checkpoint = checkpoint.ok_or("未完成卸载前备份")?;
    let registry = registry_plan.ok_or("未准备注册表计划")?;
    let mut stage = "卸载旧密钥（可能已部分完成）";
    let result: Result<(), String> = (|| {
        {
            let context = sl::Context::open().map_err(|e| e.to_string())?;
            if windows_base {
                context
                    .uninstall_application_keys(&app)
                    .map_err(|e| e.to_string())?;
            } else {
                let keys = context.installed_keys(&sku).map_err(|e| e.to_string())?;
                if keys.len() > 1 {
                    return Err("产品存在多个密钥，未执行卸载".into());
                }
                if let Some(key) = keys.first() {
                    context.uninstall_key(key).map_err(|e| e.to_string())?;
                }
            }
        }
        stage = "写入生成密钥存储和注册表";
        service::stopped("sppsvc", || {
            let transaction = Transaction::edit(paths.clone(), |originals| {
                let plan = transform(originals, &request)?;
                Ok(vec![plan.physical, plan.tokens])
            })
            .map_err(|e| e.to_string())?;
            let mut participant = registry.capture().map_err(|e| e.to_string())?;
            report(&format!(
                "安装写入备份：{}",
                transaction.backup_path().display()
            ));
            transaction
                .commit_participating(&mut participant)
                .map_err(|e| e.to_string())?;
            stage = "生成密钥已写入，清理缓存并恢复服务";
            match std::fs::remove_file(&cache) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.to_string()),
            }
            Ok(())
        })?;
        stage = "生成密钥已写入，刷新可信时间";
        let context = sl::Context::open().map_err(|e| e.to_string())?;
        context
            .refresh_trusted_time(&sku)
            .map_err(|e| e.to_string())?;
        stage = "生成密钥已写入，验证所选产品密钥映射";
        let expected = uuid::Uuid::from_bytes_le(key.binding_id().map_err(|e| e.to_string())?);
        if !context
            .installed_keys(&sku)
            .map_err(|e| e.to_string())?
            .iter()
            .any(|id| uuid::Uuid::from_fields(id.data1, id.data2, id.data3, &id.data4) == expected)
        {
            return Err("生成密钥未出现在所选产品的密钥映射中".into());
        }
        Ok(())
    })();
    result.map_err(|error| {
        format!(
            "PKEY2005 安装失败（{stage}）：{error}。卸载前存储与产品注册表备份：{}；SLC 卸载操作未自动撤销。",
            checkpoint.display()
        )
    })?;
    Ok(format!(
        "PKEY2005 数据安装完成；这不代表产品已激活。卸载前备份：{}",
        checkpoint.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::super::product_key::Key2005;
    use super::*;
    #[test]
    fn encrypted_install_plan_preserves_envelope_key_and_rejects_bad_tokens() {
        let request = Request {
            version: Version::Modern,
            key: Key2005::new(206, 100_000_001, 0, false).unwrap(),
            metadata: Metadata {
                mpc: "03612",
                activation_id: [1; 16],
                edition: "Professional",
                part_number: "X00-12345",
                channel: "Retail",
                eula: "Retail",
                lcid: 1033,
                build: 26100,
                day: 1,
                year: 2026,
            },
            application_id: [2; 16],
            windows_family: Some("Professional"),
            pid_nonce: 123,
        };
        let plain = include_bytes!("../../../tests/fixtures/tsforge/store-modern.bin");
        let tokens = include_bytes!("../../../tests/fixtures/tsforge/tokens-modern.bin");
        for production in [true, false] {
            let original = crypto::encrypt(plain, production, Version::Modern).unwrap();
            let plan = transform(&[&original, tokens], &request).unwrap();
            let (_, retained) = reset::decode_modern(&plan.physical).unwrap();
            assert_eq!(retained, production);
            assert_ne!(
                crypto::decrypt(&plan.physical, production, Version::Modern).unwrap(),
                plain
            );
            super::super::token::decode(&plan.tokens).unwrap();
            assert!(plan.registry.is_some());
            let mut corrupt = tokens.to_vec();
            corrupt[40] ^= 1;
            assert!(transform(&[&original, &corrupt], &request).is_err());
            assert_eq!(
                crypto::decrypt(&original, production, Version::Modern).unwrap(),
                plain
            );
        }
    }
    #[test]
    fn setup_reader_handles_utf8_utf16_and_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("setup.cfg");
        assert!(setup_text(path.clone()).unwrap().is_none());
        std::fs::write(&path, b"X64.Pro=12345").unwrap();
        assert_eq!(setup_text(path.clone()).unwrap().unwrap(), "X64.Pro=12345");
        let bytes: Vec<u8> = [0xff, 0xfe]
            .into_iter()
            .chain("X64.Pro=12345".encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(setup_text(path.clone()).unwrap().unwrap(), "X64.Pro=12345");
        std::fs::write(&path, [0xff, 0xfe, 0x01]).unwrap();
        assert!(setup_text(path).is_err());
    }
}
