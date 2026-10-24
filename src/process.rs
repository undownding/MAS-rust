use crate::operations::{Action, Product};
use std::sync::{Arc, atomic::AtomicBool};

#[derive(Debug)]
pub struct ExecutionResult {
    pub output: String,
}

#[cfg(windows)]
pub fn is_admin() -> bool {
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}

#[cfg(not(windows))]
pub fn is_admin() -> bool {
    false
}

pub fn execute(
    product: Product,
    action: Action,
    cancel: Arc<AtomicBool>,
) -> Result<ExecutionResult, String> {
    execute_platform(product, action, cancel)
}

#[cfg(not(windows))]
fn execute_platform(
    _product: Product,
    _action: Action,
    _cancel: Arc<AtomicBool>,
) -> Result<ExecutionResult, String> {
    Err(crate::operations::ValidationError::UnsupportedPlatform.to_string())
}

#[cfg(windows)]
fn execute_platform(
    product: Product,
    action: Action,
    cancel: Arc<AtomicBool>,
) -> Result<ExecutionResult, String> {
    use crate::operations::{office_command, windows_command};

    let mut spec = match product {
        Product::Windows => windows_command(&action),
        Product::Office => {
            let path = find_office_script().map_err(|error| error.to_string())?;
            office_command(&path, &action)
        }
    };

    // OSPP handles one option per invocation. Apply host and port sequentially.
    if let Action::SetKms { port, .. } = &action
        && product == Product::Office
    {
        spec.args.pop();
        let mut port_spec = spec.clone();
        *port_spec.args.last_mut().unwrap() = format!("/setprt:{port}");
        run_command(&spec, &cancel)?;
        spec = port_spec;
    }
    let output = run_command(&spec, &cancel).map_err(|mut error| {
        for secret in action.secrets() {
            error = error.replace(secret, "*****");
        }
        error
    })?;
    let mut output = output;
    for secret in action.secrets() {
        output = output.replace(secret, "*****");
    }
    Ok(ExecutionResult { output })
}

#[cfg(windows)]
fn run_command(
    spec: &crate::operations::CommandSpec,
    cancel: &AtomicBool,
) -> Result<String, String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};
    let program =
        std::path::PathBuf::from(std::env::var_os("SystemRoot").ok_or("SystemRoot 未定义")?)
            .join("System32/cscript.exe");
    let mut child = Command::new(program)
        .args(&spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(0x08000000)
        .spawn()
        .map_err(|error| format!("无法启动系统工具：{error}"))?;
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let err = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let start = Instant::now();
    loop {
        if cancel.load(Ordering::Relaxed) || start.elapsed() > Duration::from_secs(180) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = out.join();
            let _ = err.join();
            return Err("操作已取消或超时。系统修改可能已经部分生效，请重新查询状态。".into());
        }
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let stdout = out
        .join()
        .map_err(|_| "读取线程异常")?
        .map_err(|e| e.to_string())?;
    let stderr = err
        .join()
        .map_err(|_| "读取线程异常")?
        .map_err(|e| e.to_string())?;
    let status = child
        .wait()
        .map_err(|error| format!("获取系统工具退出状态时失败：{error}"))?;

    let mut output = String::new();
    if !stdout.is_empty() {
        output.push_str(&decode_console_output(&stdout));
    }
    if !stderr.is_empty() {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&decode_console_output(&stderr));
    }
    if output.trim().is_empty() {
        output = if status.success() {
            "系统工具已成功完成操作。".to_owned()
        } else {
            "系统工具未返回详细信息。".to_owned()
        };
    }

    if status.success() {
        Ok(output)
    } else {
        Err(format!(
            "系统工具返回失败（退出码 {}）。\n{}",
            status
                .code()
                .map_or_else(|| "未知".to_owned(), |code| code.to_string()),
            output.trim()
        ))
    }
}

#[cfg(windows)]
fn find_office_script() -> Result<String, crate::operations::ValidationError> {
    use crate::operations::{OfficeScriptLocator, ValidationError};
    use std::path::Path;

    let program_files = std::env::var("ProgramFiles").ok();
    let program_files_x86 = std::env::var("ProgramFiles(x86)").ok();
    OfficeScriptLocator::candidate_paths(program_files.as_deref(), program_files_x86.as_deref())
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .ok_or(ValidationError::OfficeScriptNotFound)
}

#[cfg(any(windows, test))]
fn decode_console_output(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(&[0xff, 0xfe]).unwrap_or(bytes);
    // cscript //U writes UTF-16LE to redirected pipes, including without a BOM.
    let words = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect::<Vec<_>>();
    String::from_utf16_lossy(&words)
}

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(test)]
mod tests {
    #[test]
    fn decodes_chinese_cscript_output_with_and_without_bom() {
        let bytes: Vec<_> = "许可证状态：已授权"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(super::decode_console_output(&bytes), "许可证状态：已授权");
        let mut with_bom = vec![0xff, 0xfe];
        with_bom.extend(bytes);
        assert_eq!(
            super::decode_console_output(&with_bom),
            "许可证状态：已授权"
        );
    }
}
