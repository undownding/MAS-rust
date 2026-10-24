use super::{
    kms::{self, Scope},
    licensing::{Licensing, WINDOWS_APP, number, string},
    platform, renewal,
};
use crate::engine::Options;
use wmi::{IWbemClassWrapper, Variant, WMIError};
const OFFICE_APP: &str = "0ff1ce15-a989-479d-af46-f275c6370663";
const OFFICE_2010: &str = "59a52881-a989-479d-af46-f275c6370663";

fn path(p: &IWbemClassWrapper) -> Result<String, String> {
    p.path().map_err(|e| e.to_string())
}
fn is_volume(p: &IWbemClassWrapper) -> Result<bool, String> {
    Ok(string(p, "Description")?
        .to_ascii_uppercase()
        .contains("KMSCLIENT"))
}
fn installed(p: &IWbemClassWrapper) -> Result<bool, String> {
    Ok(!string(p, "PartialProductKey")?.is_empty())
}
fn base(p: &IWbemClassWrapper) -> Result<bool, String> {
    Ok(string(p, "LicenseDependsOn")?.is_empty())
}
fn protected(p: &IWbemClassWrapper) -> Result<bool, String> {
    Ok(kms::protected_windows(
        &string(p, "ID")?,
        number(p, "LicenseStatus")?,
        number(p, "GracePeriodRemaining")?,
    ))
}

fn office_providers(l: &Licensing) -> Result<Vec<(&'static str, &'static str)>, String> {
    let mut providers = vec![("SoftwareLicensingProduct", OFFICE_APP)];
    match l.connection.get_object("OfficeSoftwareProtectionProduct") {
        Ok(_) => {
            providers.push(("OfficeSoftwareProtectionProduct", OFFICE_2010));
            providers.push(("OfficeSoftwareProtectionProduct", OFFICE_APP));
        }
        Err(WMIError::HResultError { hres }) if matches!(hres as u32, 0x80041010 | 0x80041002) => {}
        Err(e) => return Err(format!("Office WMI 提供程序：{e}")),
    }
    Ok(providers)
}

fn configure(l: &Licensing, p: &IWbemClassWrapper, host: &str, port: u32) -> Result<(), String> {
    let class = string(p, "__CLASS")?;
    let path = path(p)?;
    if host.is_empty() {
        l.invoke(&class, &path, "ClearKeyManagementServiceMachine", &[])?;
    } else {
        l.invoke(
            &class,
            &path,
            "SetKeyManagementServiceMachine",
            &[("MachineName", Variant::String(host.into()))],
        )?;
    }
    if port == 0 {
        l.invoke(&class, &path, "ClearKeyManagementServicePort", &[])
    } else {
        l.invoke(
            &class,
            &path,
            "SetKeyManagementServicePort",
            &[("PortNumber", Variant::UI4(port))],
        )
    }
}

fn activate(
    l: &Licensing,
    p: &IWbemClassWrapper,
    hosts: &[String],
    port: u16,
    report: &dyn Fn(&str),
) -> Result<(), String> {
    let old_host = string(p, "KeyManagementServiceMachine")?;
    let old_port = match p
        .get_property("KeyManagementServicePort")
        .map_err(|e| e.to_string())?
    {
        Variant::Null | Variant::Empty => 0,
        _ => number(p, "KeyManagementServicePort")?,
    };
    let name = string(p, "Name")?;
    let mut errors = Vec::new();
    for (i, host) in hosts.iter().enumerate() {
        report(&format!(
            "{name}：尝试 {host}:{port}（{}/{}）",
            i + 1,
            hosts.len()
        ));
        let attempt = (|| -> Result<(), String> {
            configure(l, p, host, port as u32)?;
            l.product_method(p, "Activate")?;
            let fresh = l
                .connection
                .get_object(path(p)?)
                .map_err(|e| e.to_string())?;
            if number(&fresh, "LicenseStatus")? != 1 || number(&fresh, "GracePeriodRemaining")? == 0
            {
                return Err("调用完成，但未获得有效 KMS 宽限期".into());
            }
            report(&format!(
                "{name}：已授权，剩余 {} 分钟",
                number(&fresh, "GracePeriodRemaining")?
            ));
            Ok(())
        })();
        match attempt {
            Ok(()) => return Ok(()),
            Err(e) => {
                report(&e);
                errors.push(format!("{host}: {e}"));
            }
        }
    }
    // A failed attempt must not leave the last public/custom host behind.
    let restored = configure(l, p, &old_host, old_port).map_or_else(
        |e| format!("恢复原 KMS 设置失败：{e}"),
        |_| "已恢复原 KMS 主机与端口".into(),
    );
    Err(format!(
        "{name} 激活失败；{restored}\n{}",
        errors.join("\n")
    ))
}

pub fn run(
    scope: Scope,
    options: &Options,
    renew_only: bool,
    report: &dyn Fn(&str),
) -> Result<String, String> {
    if !crate::process::is_admin() {
        return Err("原生 Online KMS 需要管理员权限".into());
    }
    if options.kms_port == 0 {
        return Err("KMS 端口不能为 0".into());
    }
    let rotation = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as usize;
    let hosts = kms::servers(&options.kms_server, rotation)?;
    let l = Licensing::new()?;
    let mut targets = Vec::new();
    let mut skipped = 0;
    let mut errors = Vec::new();
    if scope.windows() {
        let all = l.products("SoftwareLicensingProduct", WINDOWS_APP, false)?;
        let mut protected_license = false;
        for p in &all {
            if installed(p)? && base(p)? && protected(p)? {
                protected_license = true;
                report("Windows 已有永久数字许可证或 KMS38，保留现状。");
                break;
            }
        }
        if protected_license {
            skipped += 1;
        } else {
            let mut selected = None;
            for p in all.iter() {
                if installed(p)? && base(p)? && is_volume(p)? {
                    selected = Some(
                        l.connection
                            .get_object(path(p)?)
                            .map_err(|e| e.to_string())?,
                    );
                    break;
                }
            }
            if selected.is_none() && !renew_only {
                let systems = l.query("SELECT BuildNumber FROM Win32_OperatingSystem")?;
                let build = number(systems.first().ok_or("未找到 Windows 版本")?, "BuildNumber")?;
                let sku = platform::sku(build)?;
                let ids = all
                    .iter()
                    .map(|p| string(p, "ID"))
                    .collect::<Result<Vec<_>, _>>()?;
                match kms::windows_key(sku, &ids, options.no_edition_change) {
                    Ok((id, key)) => {
                        report(&format!(
                            "Windows：安装匹配 Activation ID {id} 的 GVLK（末五位 {}）",
                            &key[24..]
                        ));
                        l.install(&key)?;
                        l.refresh()?;
                        for p in l.products("SoftwareLicensingProduct", WINDOWS_APP, true)? {
                            if string(&p, "ID")?.eq_ignore_ascii_case(&id) {
                                selected = Some(p);
                                break;
                            }
                        }
                        if selected.is_none() {
                            errors.push("Windows：安装 GVLK 后未找到目标许可证".into());
                        }
                    }
                    Err(e) => errors.push(e),
                }
            }
            if let Some(p) = selected {
                targets.push((Scope::Windows, p));
            } else if renew_only {
                report("Windows 没有已安装的 KMSCLIENT 许可证，续期不安装密钥。");
                skipped += 1;
            }
        }
    }
    if scope.office() {
        if !renew_only {
            match super::office::prepare_kms(&l, scope, options.no_edition_change, report) {
                Ok(failures) => errors.extend(failures),
                Err(e) => errors.push(format!("Office 许可准备失败：{e}")),
            }
        }
        let mut found = 0;
        let mut unsupported = 0;
        for (class, app) in office_providers(&l)? {
            for p in l.products(class, app, true)? {
                let name = string(&p, "Name")?;
                if !scope.includes_office(&name) {
                    continue;
                }
                if is_volume(&p)? {
                    targets.push((
                        if scope == Scope::ProjectVisio {
                            scope
                        } else {
                            Scope::Office
                        },
                        p,
                    ));
                    found += 1;
                } else {
                    unsupported += 1;
                    report(&format!("保留非 KMS Office 许可证：{name}"));
                }
            }
        }
        if found == 0 && !renew_only {
            errors.push(format!("Office：没有已安装的批量许可 KMSCLIENT 产品（发现 {unsupported} 个其他许可）。请检查上方许可准备日志；复杂修复可使用完整版兼容菜单。"));
        } else if found == 0 {
            skipped += 1;
        }
    }
    let mut successes = Vec::new();
    for (family, p) in targets {
        match activate(&l, &p, &hosts, options.kms_port, report) {
            Ok(()) => {
                if !successes.contains(&family) {
                    successes.push(family);
                }
            }
            Err(e) => errors.push(e),
        }
    }
    if !renew_only && !options.no_renewal {
        for family in &successes {
            report(&format!("注册原生 {} 续期任务（每 6 小时）", family.name()));
            if let Err(e) = renewal::install(*family, &options.kms_server, options.kms_port) {
                errors.push(format!("激活已完成，但续期任务注册失败：{e}"));
            }
        }
    }
    if !errors.is_empty() {
        return Err(format!(
            "原生 Online KMS 完成，{} 类产品成功，{skipped} 项保留/跳过。\n{}\n若安装过 GVLK，激活失败不会自动还原此前的产品密钥。",
            successes.len(),
            errors.join("\n")
        ));
    }
    Ok(format!(
        "原生 Online KMS 完成：{} 类产品成功，{skipped} 项保留/跳过。",
        successes.len()
    ))
}

pub fn uninstall(report: &dyn Fn(&str)) -> Result<String, String> {
    if !crate::process::is_admin() {
        return Err("卸载需要管理员权限".into());
    }
    renewal::remove()?;
    let l = Licensing::new()?;
    let mut providers = office_providers(&l)?;
    providers.push(("SoftwareLicensingProduct", WINDOWS_APP));
    let mut cleared = 0;
    for (class, app) in providers {
        for p in l.products(class, app, true)? {
            if !is_volume(&p)? {
                continue;
            }
            if app == WINDOWS_APP && protected(&p)? {
                report("保留 Windows KMS38 专用主机。");
                continue;
            }
            configure(&l, &p, "", 0)?;
            cleared += 1;
        }
    }
    Ok(format!(
        "已移除 MAS Rust 自建续期任务并清除 {cleared} 个许可证专用 KMS 配置。未删除产品密钥；上游脚本的旧续期任务需通过完整版兼容菜单卸载。"
    ))
}
