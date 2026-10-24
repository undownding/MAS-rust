#![cfg_attr(not(windows), allow(dead_code))]
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Product {
    Windows,
    Office,
}

impl Product {
    pub fn name(self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::Office => "Office",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    Query,
    InstallKey(String),
    Activate,
    UninstallKey(String),
    SetKms { host: String, port: u16 },
    ClearKms,
}

impl Action {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Query => "查询许可证状态",
            Self::InstallKey(_) => "安装产品密钥",
            Self::Activate => "联机激活",
            Self::UninstallKey(_) => "卸载产品密钥",
            Self::SetKms { .. } => "设置 KMS 服务器",
            Self::ClearKms => "清除 KMS 配置",
        }
    }

    pub fn secrets(&self) -> Vec<&str> {
        match self {
            Self::InstallKey(key) => vec![key.as_str()],
            _ => Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ValidationError {
    #[error("产品密钥应为 25 位字母或数字，可按每 5 位用连字符分隔")]
    InvalidProductKey,
    #[error("密钥末五位应为 5 位字母或数字")]
    InvalidKeyTail,
    #[error("KMS 主机不能为空，且不能包含空白、斜杠或协议前缀")]
    InvalidKmsHost,
    #[error("KMS 端口必须在 1 到 65535 之间")]
    InvalidKmsPort,
    #[error("未找到 Office 的 ospp.vbs，请确认安装了受支持的批量许可版 Office")]
    OfficeScriptNotFound,
    #[error("当前平台仅支持预览界面；授权管理功能需要在 Windows 上以管理员身份运行")]
    #[cfg(not(windows))]
    UnsupportedPlatform,
}

pub fn normalize_product_key(input: &str) -> Result<String, ValidationError> {
    let compact = input
        .trim()
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '-')
        .map(|character| character.to_ascii_uppercase())
        .collect::<String>();

    if compact.len() != 25 || !compact.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(ValidationError::InvalidProductKey);
    }

    Ok(compact
        .as_bytes()
        .chunks(5)
        .map(|chunk| std::str::from_utf8(chunk).expect("密钥已校验为 ASCII"))
        .collect::<Vec<_>>()
        .join("-"))
}

pub fn normalize_key_tail(input: &str) -> Result<String, ValidationError> {
    let tail = input.trim().to_ascii_uppercase();
    if tail.len() != 5 || !tail.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(ValidationError::InvalidKeyTail);
    }
    Ok(tail)
}

pub fn normalize_kms_host(input: &str) -> Result<String, ValidationError> {
    let trimmed = input.trim();
    let host = trimmed
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(trimmed);

    let valid_ip = host.parse::<std::net::IpAddr>().is_ok();
    let valid_dns = host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !valid_ip && !valid_dns {
        return Err(ValidationError::InvalidKmsHost);
    }
    Ok(host.to_owned())
}

pub fn validate_kms_port(input: &str) -> Result<u16, ValidationError> {
    input
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(ValidationError::InvalidKmsPort)
}

pub fn kms_address(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub fn windows_command(action: &Action) -> CommandSpec {
    let args = match action {
        Action::Query => vec!["/dlv".to_owned()],
        Action::InstallKey(key) => vec!["/ipk".into(), key.clone()],
        Action::Activate => vec!["/ato".into()],
        Action::UninstallKey(_) => vec!["/upk".into()],
        Action::SetKms { host, port } => vec!["/skms".into(), kms_address(host, *port)],
        Action::ClearKms => vec!["/ckms".into()],
    };
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    CommandSpec {
        program: format!(r"{root}\System32\cscript.exe"),
        args: script_args(&format!(r"{root}\System32\slmgr.vbs"), &args),
    }
}

pub fn office_command(script_path: &str, action: &Action) -> CommandSpec {
    let argument = match action {
        Action::Query => "/dstatus".to_owned(),
        Action::InstallKey(key) => format!("/inpkey:{key}"),
        Action::Activate => "/act".to_owned(),
        Action::UninstallKey(tail) => format!("/unpkey:{tail}"),
        Action::SetKms { host, port } => {
            return CommandSpec {
                program: "cscript.exe".to_owned(),
                args: script_args(
                    script_path,
                    &[format!("/sethst:{host}"), format!("/setprt:{port}")],
                ),
            };
        }
        Action::ClearKms => "/remhst".to_owned(),
    };
    script_command(script_path, argument)
}

fn script_command(script_path: &str, argument: String) -> CommandSpec {
    CommandSpec {
        program: "cscript.exe".to_owned(),
        args: script_args(script_path, &[argument]),
    }
}

fn script_args(script_path: &str, arguments: &[String]) -> Vec<String> {
    std::iter::once("//NoLogo".to_owned())
        .chain(std::iter::once("//B".to_owned()))
        .chain(std::iter::once("//U".to_owned()))
        .chain(std::iter::once(script_path.to_owned()))
        .chain(arguments.iter().cloned())
        .collect()
}

pub struct OfficeScriptLocator;

impl OfficeScriptLocator {
    pub fn candidate_paths(
        program_files: Option<&str>,
        program_files_x86: Option<&str>,
    ) -> Vec<String> {
        let mut paths = Vec::new();
        for root in [program_files, program_files_x86].into_iter().flatten() {
            for version in ["16", "15", "14"] {
                for directory in [format!("Office{version}"), format!("root\\Office{version}")] {
                    paths.push(format!(
                        "{}\\Microsoft Office\\{}\\OSPP.VBS",
                        root.trim_end_matches('\\'),
                        directory
                    ));
                }
            }
        }
        paths
    }
}

impl fmt::Display for Product {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_valid_product_key() {
        assert_eq!(
            normalize_product_key("aaaaa bbbbb-ccccc-ddddd-eeeee").unwrap(),
            "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"
        );
    }

    #[test]
    fn rejects_invalid_product_keys() {
        assert_eq!(
            normalize_product_key("short"),
            Err(ValidationError::InvalidProductKey)
        );
        assert_eq!(
            normalize_product_key("AAAAA-BBBBB-CCCCC-DDDDD-EEEE!"),
            Err(ValidationError::InvalidProductKey)
        );
    }

    #[test]
    fn validates_key_tail() {
        assert_eq!(normalize_key_tail("ab12c").unwrap(), "AB12C");
        assert_eq!(
            normalize_key_tail("ABC"),
            Err(ValidationError::InvalidKeyTail)
        );
    }

    #[test]
    fn validates_kms_settings() {
        assert_eq!(
            normalize_kms_host("kms.example.org").unwrap(),
            "kms.example.org"
        );
        assert_eq!(normalize_kms_host("[2001:db8::1]").unwrap(), "2001:db8::1");
        assert_eq!(
            normalize_kms_host("https://kms.example.org"),
            Err(ValidationError::InvalidKmsHost)
        );
        assert_eq!(validate_kms_port("1688").unwrap(), 1688);
        assert_eq!(validate_kms_port("0"), Err(ValidationError::InvalidKmsPort));
    }

    #[test]
    fn formats_ipv4_dns_and_ipv6_kms_addresses() {
        assert_eq!(kms_address("kms.example.org", 1688), "kms.example.org:1688");
        assert_eq!(kms_address("2001:db8::1", 1688), "[2001:db8::1]:1688");
    }

    #[test]
    fn builds_windows_commands_without_a_shell() {
        let command = windows_command(&Action::SetKms {
            host: "kms.example.org".to_owned(),
            port: 1688,
        });
        assert!(command.program.ends_with("cscript.exe"));
        assert_eq!(command.args[0], "//NoLogo");
        assert_eq!(command.args.last().unwrap(), "kms.example.org:1688");
    }

    #[test]
    fn builds_office_kms_command() {
        let command = office_command(
            r"C:\Office16\OSPP.VBS",
            &Action::SetKms {
                host: "kms.example.org".to_owned(),
                port: 1688,
            },
        );
        assert!(command.args.contains(&"/sethst:kms.example.org".to_owned()));
        assert!(command.args.contains(&"/setprt:1688".to_owned()));
    }

    #[test]
    fn finds_office_paths_for_both_architectures() {
        let paths = OfficeScriptLocator::candidate_paths(
            Some(r"C:\Program Files"),
            Some(r"C:\Program Files (x86)"),
        );
        assert!(
            paths.contains(&r"C:\Program Files\Microsoft Office\root\Office16\OSPP.VBS".to_owned())
        );
        assert!(
            paths
                .contains(&r"C:\Program Files (x86)\Microsoft Office\Office14\OSPP.VBS".to_owned())
        );
    }
}
