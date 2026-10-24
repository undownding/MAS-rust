//! DISM/SFC repair plans and lossless diagnostic log capture.
#![cfg_attr(not(test), allow(dead_code))]
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Dism,
    Sfc,
}
impl Kind {
    pub fn executable(self) -> &'static str {
        match self {
            Self::Dism => "dism.exe",
            Self::Sfc => "sfc.exe",
        }
    }
    pub fn args(self) -> &'static [&'static str] {
        match self {
            Self::Dism => &["/English", "/Online", "/Cleanup-Image", "/RestoreHealth"],
            Self::Sfc => &["/scannow"],
        }
    }
    pub fn validate(self, build: u32) -> Result<(), String> {
        if build < 6000 || (self == Self::Dism && build < 9200) {
            Err("当前系统不支持此修复命令；DISM RestoreHealth 需要 Windows 8 或更高版本。".into())
        } else {
            Ok(())
        }
    }
    pub fn logs(self) -> &'static [&'static str] {
        match self {
            Self::Dism => &["CBS/CBS.log", "DISM/dism.log"],
            Self::Sfc => &["CBS/CBS.log"],
        }
    }
    pub fn result(self, code: i32) -> Result<String, String> {
        match code {
            0 => Ok(format!(
                "{} 已退出（0）；请检查命令输出和诊断日志确认修复结果。",
                self.executable()
            )),
            3010 if self == Self::Dism => {
                Ok("DISM 报告操作完成并需要重启（3010）；程序不会自动重启。".into())
            }
            code => Err(format!(
                "{} 退出码 {code}（0x{:08X}）；请检查诊断日志。",
                self.executable(),
                code as u32
            )),
        }
    }
}
const MAX_LOG: u64 = 512 * 1024 * 1024;
/// Preserve raw bytes (including UTF-16 output), never truncate a source log.
pub fn snapshot(source: &Path, destination: &Path) -> io::Result<bool> {
    let mut input = match File::open(source) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if !input.metadata()?.is_file() {
        return Err(io::Error::other("diagnostic source is not a regular file"));
    }
    let length = input.metadata()?.len();
    if length > MAX_LOG {
        return Err(io::Error::other("diagnostic log exceeds 512 MiB limit"));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let copied = io::copy(&mut (&mut input).take(length), &mut output)?;
    output.flush()?;
    output.sync_all()?;
    if copied != length {
        return Err(io::Error::other(
            "diagnostic log changed during snapshot; copy may be incomplete",
        ));
    }
    Ok(true)
}
pub fn capture(kind: Kind, log_root: &Path, directory: &Path, phase: &str) -> Vec<String> {
    let mut errors = vec![];
    for relative in kind.logs() {
        let name = relative.replace('/', "_");
        let destination = directory.join(format!("{phase}_{name}"));
        match snapshot(&log_root.join(relative), &destination) {
            Ok(true) => {
                #[cfg(any(windows, test))]
                if let Err(e) = super::cabinet::compress(
                    &destination,
                    &destination.with_extension("cab"),
                    &format!("{phase}_{name}"),
                ) {
                    errors.push(format!("压缩 {relative}：{e}；原始日志保留"));
                }
            }
            Ok(false) => errors.push(format!("{relative} 尚不存在")),
            Err(e) => errors.push(format!("复制 {relative}：{e}")),
        }
    }
    errors
}
#[cfg(windows)]
pub fn run(kind: Kind, report: &dyn Fn(&str)) -> Result<String, String> {
    use std::{
        os::windows::process::CommandExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    use windows::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_Desktop, KF_FLAG_DEFAULT, SHGetKnownFolderPath},
    };
    let _guard = super::session::OperationGuard::acquire()?;
    if !crate::process::is_admin() {
        return Err("请以管理员身份运行".into());
    }
    if std::env::var("PROCESSOR_ARCHITEW6432").is_ok_and(|v| !v.is_empty()) {
        return Err("系统修复不支持跨架构仿真。".into());
    }
    let version = super::registry::Key::open(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        0x100,
        false,
    )?
    .ok_or("无法读取 Windows 版本")?;
    let build = version
        .string("CurrentBuildNumber")?
        .ok_or("缺少构建号")?
        .parse()
        .map_err(|_| "构建号无效")?;
    kind.validate(build)?;
    let executable = super::platform::system_file(kind.executable())?;
    if !executable.is_absolute() || !executable.is_file() {
        return Err("找不到系统修复程序".into());
    }
    let raw = unsafe { SHGetKnownFolderPath(&FOLDERID_Desktop, KF_FLAG_DEFAULT, None) }
        .map_err(|e| e.to_string())?;
    let desktop = unsafe { raw.to_string() };
    unsafe { CoTaskMemFree(Some(raw.0.cast())) };
    let root = std::path::PathBuf::from(desktop.map_err(|e| e.to_string())?).join("AT_Logs");
    std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let directory = root.join(format!(
        "{:?}-{}",
        kind,
        uuid::Uuid::from_u128({
            use rsa::rand_core::{OsRng, RngCore};
            let mut bytes = [0u8; 16];
            OsRng
                .try_fill_bytes(&mut bytes)
                .map_err(|e| e.to_string())?;
            u128::from_le_bytes(bytes)
        })
    ));
    std::fs::create_dir(&directory).map_err(|e| e.to_string())?;
    let system = super::platform::system_file("")?;
    let log_root = system.parent().ok_or("系统目录无效")?.join("Logs");
    report(&format!("诊断日志：{}", directory.display()));
    for warning in capture(kind, &log_root, &directory, "before") {
        report(&format!("修复前日志：{warning}"));
    }
    let output_path = directory.join("command-output.bin");
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)
        .map_err(|e| e.to_string())?;
    let stderr = output.try_clone().map_err(|e| e.to_string())?;
    report(&format!(
        "正在执行 {} {}；可能持续十几分钟或更久。",
        executable.display(),
        kind.args().join(" ")
    ));
    let mut child = Command::new(executable)
        .args(kind.args())
        .creation_flags(0x08000000)
        .stdin(Stdio::null())
        .stdout(Stdio::from(output))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|e| format!("启动修复失败：{e}；日志：{}", directory.display()))?;
    let started = Instant::now();
    let mut next_report = Duration::from_secs(15);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => {
                return Err(format!(
                    "读取修复进程状态失败：{e}；进程可能仍在运行，请勿重复启动；日志：{}",
                    directory.display()
                ));
            }
        }
        if started.elapsed() >= next_report {
            report(&format!(
                "系统修复仍在运行，已等待 {} 秒；输出保存在 {}",
                started.elapsed().as_secs(),
                output_path.display()
            ));
            next_report = started.elapsed() + Duration::from_secs(15);
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    for warning in capture(kind, &log_root, &directory, "after") {
        report(&format!("修复后日志：{warning}"));
    }
    let code = status
        .code()
        .ok_or_else(|| format!("修复进程没有退出码；日志：{}", directory.display()))?;
    let result = kind.result(code);
    let summary = match &result {
        Ok(s) | Err(s) => s,
    };
    let summary = format!(
        "{summary}\n日志：{}\n命令输出保存为原始字节；SFC 可能使用 UTF-16。系统日志未删除，未自动重启。",
        directory.display()
    );
    std::fs::write(directory.join("result.txt"), &summary)
        .map_err(|e| format!("{summary}\n保存摘要失败：{e}"))?;
    result.map(|_| summary.clone()).map_err(|_| summary)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_support_and_status_do_not_claim_verified_repairs() {
        assert!(Kind::Dism.validate(7601).is_err());
        assert!(Kind::Dism.validate(9200).is_ok());
        assert!(Kind::Sfc.validate(7601).is_ok());
        assert_eq!(
            Kind::Dism.args(),
            ["/English", "/Online", "/Cleanup-Image", "/RestoreHealth"]
        );
        assert_eq!(Kind::Sfc.args(), ["/scannow"]);
        assert!(Kind::Dism.result(3010).unwrap().contains("重启"));
        assert!(Kind::Sfc.result(3010).is_err());
        assert!(Kind::Sfc.result(0).unwrap().contains("检查"));
        assert!(Kind::Dism.result(-1).unwrap_err().contains("FFFFFFFF"));
    }
    #[test]
    fn snapshots_preserve_bytes_and_never_overwrite_existing_files() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.log");
        let target = temp.path().join("copy.log");
        assert!(!snapshot(&source, &target).unwrap());
        let bytes = [0xff, 0xfe, 0x2d, 0x4e, 0, 0];
        std::fs::write(&source, bytes).unwrap();
        assert!(snapshot(&source, &target).unwrap());
        assert_eq!(std::fs::read(&target).unwrap(), bytes);
        assert_eq!(
            snapshot(&source, &target).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&source).unwrap(), bytes);
        assert_eq!(
            capture(Kind::Dism, temp.path(), temp.path(), "after").len(),
            2
        );
        assert_eq!(
            capture(Kind::Sfc, temp.path(), temp.path(), "after").len(),
            1
        );
    }
}
