use super::{
    catalog,
    licensing::{Licensing, WINDOWS_APP, number, string},
    platform, ticket,
};
use crate::engine::{Operation, Options};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};
use wmi::Variant;

struct TicketFile {
    path: PathBuf,
}
impl TicketFile {
    fn create(xml: &str) -> Result<Self, String> {
        let dir = PathBuf::from(std::env::var_os("ProgramData").ok_or("ProgramData 未定义")?)
            .join("Microsoft/Windows/ClipSVC/GenuineTicket");
        fs::create_dir_all(&dir).map_err(|e| format!("创建票据目录：{e}"))?;
        let path = dir.join("GenuineTicket.xml");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| format!("创建票据 {}：{e}。不会覆盖其他待处理票据。", path.display()))?;
        let ticket = Self { path };
        file.write_all(xml.as_bytes())
            .map_err(|e| format!("写入票据：{e}"))?;
        file.sync_all().map_err(|e| format!("保存票据：{e}"))?;
        Ok(ticket)
    }
}
impl Drop for TicketFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn target(licensing: &Licensing, id: &str) -> Result<wmi::IWbemClassWrapper, String> {
    licensing
        .products("SoftwareLicensingProduct", WINDOWS_APP, true)?
        .into_iter()
        .find(|p| string(p, "ID").is_ok_and(|s| s.eq_ignore_ascii_case(id)))
        .ok_or_else(|| format!("安装后未找到许可证 {id}"))
}

fn activated(licensing: &Licensing, id: &str, legacy: bool) -> Result<bool, String> {
    let p = target(licensing, id)?;
    let status = number(&p, "LicenseStatus")?;
    let grace = number(&p, "GracePeriodRemaining")?;
    Ok(if legacy {
        status == 1 && grace > 259_200
    } else {
        status == 1 && grace == 0
    })
}

pub fn run(op: Operation, options: &Options, report: &dyn Fn(&str)) -> Result<String, String> {
    if !crate::process::is_admin() {
        return Err("请以管理员身份运行".into());
    }
    report("原生 Rust 引擎：开始读取 Windows 版本与许可证（不启动 PowerShell）。");
    let l = Licensing::new()?;
    let systems = l.query("SELECT BuildNumber, Caption, ProductType FROM Win32_OperatingSystem")?;
    let os = systems.first().ok_or("未找到 Win32_OperatingSystem")?;
    let build = number(os, "BuildNumber")?;
    let revision =
        platform::registry_dword(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR")?;
    let sku = platform::sku(build)?;
    report(&format!(
        "{} · build {build}.{revision} · SKU {sku}",
        string(os, "Caption")?
    ));
    if build < 10240 {
        return Err("此原生实现要求 Windows 10 / Server 2016 或更高版本".into());
    }
    if op.legacy && !catalog::kms38_supported(build, revision) {
        return Err(format!(
            "KMS38 已不支持 build {build}.{revision}；不会更改密钥或许可数据。"
        ));
    }
    if !op.legacy && number(os, "ProductType")? != 1 {
        return Err("HWID 不支持 Windows Server，请选择对应的激活方式".into());
    }
    if !platform::system_file("clipup.exe")?.is_file() {
        return Err("缺少系统 clipup.exe；原生引擎不会下载或替换系统文件。".into());
    }
    let all = l.products("SoftwareLicensingProduct", WINDOWS_APP, false)?;
    let ids = all
        .iter()
        .map(|p| string(p, "ID"))
        .collect::<Result<Vec<_>, _>>()?;
    let entry = catalog::select(op.legacy, sku, &ids, options.no_edition_change)?;
    if let Ok(true) = activated(&l, &entry.id, op.legacy) {
        return Ok("目标许可证已处于所需激活状态，未执行修改。".into());
    }
    if entry.sku != sku {
        report(&format!(
            "按上游回退表切换许可证：SKU {sku} → {}",
            entry.sku
        ));
    }
    let session = if op.legacy {
        ticket::KMS38_SESSION.into()
    } else {
        ticket::hwid_session(entry.sku, &entry.part)?
    };
    let xml = ticket::generate(&session)?;
    report("UTF-16LE 会话编码、SHA-256 与 RSA PKCS#1 v1.5 签名已由 Rust 生成。");
    // Finish preflight (including a pending-ticket conflict) before installing a key.
    let dir = PathBuf::from(std::env::var_os("ProgramData").ok_or("ProgramData 未定义")?)
        .join("Microsoft/Windows/ClipSVC/GenuineTicket");
    if dir.join("GenuineTicket.xml").exists() {
        return Err("已有 GenuineTicket.xml 等待处理。请先解决现有票据，未修改密钥。".into());
    }
    for service in ["sppsvc", "ClipSVC"] {
        report(&format!("通过服务控制 API 启动 {service}"));
        platform::service(service, true)?;
    }
    report(&format!(
        "通过 COM/WMI 安装 SKU {} 的通用密钥（末五位 {}）",
        entry.sku,
        &entry.key[24..]
    ));
    l.install(&entry.key)?;
    l.refresh()?;
    if op.legacy {
        report("配置此许可证专用 KMS 主机 127.0.0.2，避免常规 KMS 续期覆盖 KMS38。");
        let p = target(&l, &entry.id)?;
        let path = p.path().map_err(|e| e.to_string())?;
        l.invoke(
            "SoftwareLicensingProduct",
            &path,
            "SetKeyManagementServiceMachine",
            &[("MachineName", Variant::String("127.0.0.2".into()))],
        )?;
        l.invoke(
            "SoftwareLicensingProduct",
            &path,
            "SetKeyManagementServicePort",
            &[("PortNumber", Variant::UI4(1688))],
        )?;
    }
    report("提交 GenuineTicket.xml，由 Windows ClipSVC / clipup 导入。");
    let ticket = TicketFile::create(&xml)?;
    // Always restart sppsvc even when ClipSVC/clipup fails after a KMS38 stop.
    let import_result = (|| -> Result<(), String> {
        if op.legacy {
            platform::service("sppsvc", false)?;
        }
        platform::service("ClipSVC", false)?;
        platform::service("ClipSVC", true)?;
        let wait = Instant::now();
        while ticket.path.exists() && wait.elapsed() < Duration::from_secs(4) {
            std::thread::sleep(Duration::from_millis(200));
        }
        if !ticket.path.exists() {
            drop(ticket);
            let second = TicketFile::create(&xml)?;
            platform::clipup(report)?;
            if second.path.exists() {
                report("第二次票据未被消费，将根据实际许可证状态判断结果。");
            }
        } else {
            platform::clipup(report)?;
        }
        Ok(())
    })();
    let spp_result = platform::service("sppsvc", true);
    // A failed stop can leave ClipSVC stopped; request start on every outcome.
    let clip_result = platform::service("ClipSVC", true);
    if let Err(e) = spp_result {
        return Err(format!(
            "恢复 sppsvc 失败：{e}；票据结果：{import_result:?}"
        ));
    }
    if let Err(e) = clip_result {
        return Err(format!(
            "恢复 ClipSVC 失败：{e}；票据结果：{import_result:?}"
        ));
    }
    if let Err(e) = import_result {
        report(&format!("票据导入提示：{e}；继续检查真实激活状态。"));
    }
    l.refresh()?;
    if !op.legacy {
        report("调用 SoftwareLicensingProduct.Activate 联机激活。");
        if let Err(e) = l.product_method(&target(&l, &entry.id)?, "Activate") {
            report(&e);
        }
    } else if !activated(&l, &entry.id, true)? {
        report("按上游流程执行目标 SKU 的 ReArmSku，再刷新许可证。");
        l.product_method(&target(&l, &entry.id)?, "ReArmSku")?;
        l.refresh()?;
    }
    let mut success = false;
    for _ in 0..10 {
        if activated(&l, &entry.id, op.legacy)? {
            success = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
        l.refresh()?;
    }
    let status = l.status("SoftwareLicensingProduct", WINDOWS_APP)?;
    if !success {
        return Err(format!(
            "原生流程结束，但未达到目标激活状态。密钥或主机设置可能已生效，请查看下方状态。\n{status}"
        ));
    }
    Ok(format!(
        "{}：已通过原生 WMI 校验目标激活状态。\n{status}",
        op.title
    ))
}
