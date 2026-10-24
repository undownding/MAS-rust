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

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ValidationError {
    #[error("产品密钥应为 25 位字母或数字，可按每 5 位用连字符分隔")]
    ProductKey,
    #[error("密钥末五位应为 5 位字母或数字")]
    KeyTail,
    #[error("KMS 主机不能为空，且不能包含空白、斜杠或协议前缀")]
    KmsHost,
    #[error("KMS 端口必须在 1 到 65535 之间")]
    KmsPort,
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
        return Err(ValidationError::ProductKey);
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
        return Err(ValidationError::KeyTail);
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
        return Err(ValidationError::KmsHost);
    }
    Ok(host.to_owned())
}

pub fn validate_kms_port(input: &str) -> Result<u16, ValidationError> {
    input
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(ValidationError::KmsPort)
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
            Err(ValidationError::ProductKey)
        );
        assert_eq!(
            normalize_product_key("AAAAA-BBBBB-CCCCC-DDDDD-EEEE!"),
            Err(ValidationError::ProductKey)
        );
    }

    #[test]
    fn validates_key_tail() {
        assert_eq!(normalize_key_tail("ab12c").unwrap(), "AB12C");
        assert_eq!(normalize_key_tail("ABC"), Err(ValidationError::KeyTail));
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
            Err(ValidationError::KmsHost)
        );
        assert_eq!(validate_kms_port("1688").unwrap(), 1688);
        assert_eq!(validate_kms_port("0"), Err(ValidationError::KmsPort));
    }
}
