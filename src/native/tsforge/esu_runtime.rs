//! Modern ESU orchestration; scope dispatcher integration is still in progress.
#![allow(dead_code)]
use super::{
    activation_flow::{self, Method},
    esu::{self, Selection, System},
    sl,
    windows_context::Context,
};
use crate::native::{licensing::WINDOWS_APP, platform};
use std::{
    collections::HashSet,
    path::Path,
    time::{Duration, Instant},
};
use uuid::Uuid;
use windows_sys::{
    Win32::Security::Authentication::Identity::{SL_ID_APPLICATION, SL_ID_PRODUCT_SKU},
    core::GUID,
};

#[derive(Default)]
struct Packages {
    server: bool,
    thin_pc: bool,
    pos: bool,
    standard: bool,
}
fn classify(name: &str, packages: &mut Packages) {
    let name = name.to_ascii_lowercase();
    if !name.ends_with(".mum") {
        return;
    }
    packages.server |= name.starts_with("microsoft-windows-server") && name.contains("edition~");
    packages.thin_pc |= name.starts_with("winemb-branding-embedded-thinpc-package");
    packages.pos |= name.starts_with("winemb-branding-embedded-posready7-package");
    packages.standard |= name.starts_with("winemb-branding-embedded-standard-package");
}
fn packages(path: &Path) -> Result<Packages, String> {
    let mut found = Packages::default();
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(found),
        Err(e) => return Err(format!("读取系统包目录：{e}")),
    };
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_type().map_err(|e| e.to_string())?.is_file() {
            classify(&entry.file_name().to_string_lossy(), &mut found);
        }
    }
    Ok(found)
}

pub fn prepare(context: &Context) -> Result<Selection, String> {
    let root = std::env::var_os("SystemRoot").ok_or("SystemRoot 未定义")?;
    let p = packages(&Path::new(&root).join("Servicing/Packages"))?;
    let licensing = sl::Context::open().map_err(|e| e.to_string())?;
    let app = GUID::from_u128(Uuid::parse_str(WINDOWS_APP).unwrap().as_u128());
    let installed = licensing
        .ids(SL_ID_APPLICATION, &app, SL_ID_PRODUCT_SKU)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|id| Uuid::from_fields(id.data1, id.data2, id.data3, &id.data4))
        .collect::<HashSet<_>>();
    Ok(esu::select(
        &System {
            edition: &context.edition,
            build: context.build,
            revision: context.revision,
            server: p.server,
            thin_pc: p.thin_pc,
            embedded_pos: p.pos,
            embedded_standard: p.standard,
        },
        &installed,
    ))
}

fn system_esu_tool(file: &str, args: &[&str], report: &dyn Fn(&str)) -> Result<(), String> {
    use std::{
        os::windows::process::CommandExt,
        process::{Command, Stdio},
    };
    let path = platform::system_file(file)?;
    if !path.try_exists().map_err(|e| e.to_string())? {
        return Ok(());
    }
    let mut child = Command::new(&path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x08000000)
        .spawn()
        .map_err(|e| format!("启动系统 {file}: {e}"))?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => {
                report(&format!("系统 {file} 后处理完成。"));
                return Ok(());
            }
            Ok(Some(status)) => {
                return Err(format!("系统 {file} 后处理退出码 {:?}", status.code()));
            }
            Ok(None) if started.elapsed() < Duration::from_secs(60) => {
                std::thread::sleep(Duration::from_millis(100))
            }
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("系统 {file} 后处理超时或等待失败：{result:?}"));
            }
        }
    }
}

/// Internal until common SPP reevaluation and GUI scope routing are connected.
/// Old stores return None before any activation; errors do not request fallback.
pub fn activate(option: usize, report: &dyn Fn(&str)) -> Result<Option<String>, String> {
    if !crate::process::is_admin() {
        return Err("请以管理员身份运行".into());
    }
    let context = Context::read(report)?;
    if context.build < 9600 {
        return Ok(None);
    }
    let method = match option {
        0 if context.build >= 26100 => Method::StaticCid,
        0 | 2 => Method::ZeroCid,
        1 => Method::StaticCid,
        3 => return Err("Windows ESU 不支持 KMS4k；请选择 StaticCID 或 ZeroCID".into()),
        _ => return Err("未知 TSforge 方法".into()),
    };
    let products = match prepare(&context)? {
        Selection::Products(products) => products,
        Selection::Ltsc => {
            return Ok(Some(
                "此 LTSC 版本已有更长支持周期，ESU 不适用，未执行修改。".into(),
            ));
        }
        Selection::Unavailable => {
            return Ok(Some("当前 Windows 版本没有适用 ESU，未执行修改。".into()));
        }
        Selection::MissingLicense => {
            return Err("本机未找到 ESU 许可证，请先安装适用的 Windows 更新".into());
        }
        Selection::UnsupportedEdition { update_may_help } => {
            return Err(if update_may_help {
                "已安装 ESU 许可证不支持当前版本/修订号，请先更新 Windows"
            } else {
                "已安装 ESU 许可证不支持当前 Windows 版本"
            }
            .into());
        }
    };
    let batch = esu::run_products(&products, |product| {
        report(&format!(
            "ESU {} · {} · {method:?}",
            product.name, product.id
        ));
        let mut backend = activation_flow::Native {
            report,
            cleanup_build: None,
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
    let succeeded = batch.succeeded;
    let mut errors = batch.errors;
    if batch.consumer_helpers {
        for (file, args) in [
            ("ClipESUConsumer.exe", &["-evaluateEligibility"][..]),
            ("ClipESU.exe", &[][..]),
        ] {
            if let Err(error) = system_esu_tool(file, args, report) {
                errors.push(error);
            }
        }
    }
    if !errors.is_empty() {
        return Err(format!(
            "ESU 已完成 {succeeded}/{} 项许可验证；存在失败，已完成的修改不会自动回滚：\n{}",
            products.len(),
            errors.join("\n")
        ));
    }
    Ok(Some(format!(
        "ESU 已完成 {succeeded} 项许可验证。许可证状态不代表所有年份均可通过 Windows Update 获取更新。"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn package_matching_uses_names_and_mum_extension() {
        let mut p = Packages::default();
        classify(
            "Microsoft-Windows-ServerDatacenterEdition~example.mum",
            &mut p,
        );
        classify(
            "WinEmb-Branding-Embedded-POSReady7-Package~example.MUM",
            &mut p,
        );
        classify(
            "WinEmb-Branding-Embedded-Standard-Package~example.cat",
            &mut p,
        );
        assert!(p.server && p.pos);
        assert!(!p.standard && !p.thin_pc);
        classify(
            "WinEmb-Branding-Embedded-ThinPC-Package~example.mum",
            &mut p,
        );
        assert!(p.thin_pc);
    }
    #[test]
    fn esu_discovery_reads_real_licenses_without_changes() {
        let context = Context::read(&|_| {}).unwrap();
        let selection = prepare(&context).unwrap();
        if let Selection::Products(products) = selection {
            assert!(!products.is_empty());
        }
    }
}
