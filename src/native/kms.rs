//! Online KMS policy/data, independent of Windows so its decisions are testable.
use crate::operations::{normalize_kms_host, validate_kms_port};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Windows,
    Office,
    ProjectVisio,
    All,
}
impl Scope {
    pub fn from_switch(arg: &str) -> Option<Self> {
        match arg {
            "/K-Windows" | "windows" => Some(Self::Windows),
            "/K-Office" | "office" => Some(Self::Office),
            "/K-ProjectVisio" | "project-visio" => Some(Self::ProjectVisio),
            "/K-WindowsOffice" | "all" => Some(Self::All),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Office => "office",
            Self::ProjectVisio => "project-visio",
            Self::All => "all",
        }
    }
    pub fn windows(self) -> bool {
        matches!(self, Self::Windows | Self::All)
    }
    pub fn office(self) -> bool {
        self != Self::Windows
    }
    pub fn includes_office(self, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        self.office()
            && (self != Self::ProjectVisio || name.contains("project") || name.contains("visio"))
    }
}

pub fn protected_windows(id: &str, status: u32, grace: u32) -> bool {
    if status != 1 {
        return false;
    }
    if grace == 0 {
        return true;
    }
    let enterprise_g = [
        "e0b2d383-d112-413f-8a80-97f373a5820c",
        "e38454fb-41a4-4f59-a5dc-25080e354730",
    ]
    .iter()
    .any(|e| id.eq_ignore_ascii_case(e));
    grace > 259_200 && !enterprise_g
}

pub fn servers(custom: &str, rotation: usize) -> Result<Vec<String>, String> {
    if !custom.trim().is_empty() {
        return Ok(vec![normalize_kms_host(custom).map_err(|e| e.to_string())?]);
    }
    let mut servers: Vec<_> = include_str!("../../vendor/mas/native/kms-servers.txt")
        .lines()
        .map(str::to_owned)
        .collect();
    let len = servers.len();
    servers.rotate_left(rotation % len);
    Ok(servers)
}

pub fn windows_key(sku: u32, ids: &[String], no_change: bool) -> Result<(String, String), String> {
    let rows: Vec<Vec<_>> = include_str!("../../vendor/mas/native/online-kms.tsv")
        .lines()
        .map(|l| l.split('\t').collect())
        .collect();
    let has = |id: &str| ids.iter().any(|s| s.eq_ignore_ascii_case(id));
    if let Some(row) = rows
        .iter()
        .find(|r| r[0] == "windows" && r[3].parse::<u32>().ok() == Some(sku) && has(r[1]))
    {
        return Ok((row[1].into(), row[2].into()));
    }
    if !no_change {
        for line in include_str!("../../vendor/mas/native/online-kms-fallback.tsv").lines() {
            let row: Vec<_> = line.split('\t').collect();
            if row[0].parse::<u32>().ok() == Some(sku) && has(row[2]) && has(row[3]) {
                return Ok((row[3].into(), row[4].into()));
            }
        }
    }
    Err(format!(
        "SKU {sku} 没有匹配的已安装 KMS 许可证。未安装密钥，请通过完整版兼容菜单检查版本转换。"
    ))
}

pub fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn renewal_xml(
    executable: &str,
    scope: Scope,
    server: &str,
    port: u16,
) -> Result<String, String> {
    if executable.contains(['\r', '\n', '"']) || executable.is_empty() {
        return Err("无效的续期程序路径".into());
    }
    validate_kms_port(&port.to_string()).map_err(|e| e.to_string())?;
    let server = server.trim();
    let server_arg = if server.is_empty() {
        String::new()
    } else {
        format!(
            " --kms-server {}",
            normalize_kms_host(server).map_err(|e| e.to_string())?
        )
    };
    let args = format!("--kms-renew {}{server_arg} --kms-port {port}", scope.name());
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo><Author>MAS Rust</Author><Source>MAS-Rust</Source><Description>Renew existing KMS licenses only. Does not install keys or change editions.</Description></RegistrationInfo>
<Triggers><CalendarTrigger><Repetition><Interval>PT6H</Interval><Duration>P1D</Duration><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>2026-01-01T00:00:00</StartBoundary><Enabled>true</Enabled><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger></Triggers>
<Principals><Principal id="System"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable><ExecutionTimeLimit>PT20M</ExecutionTimeLimit><Enabled>true</Enabled></Settings>
<Actions Context="System"><Exec><Command>{}</Command><Arguments>{}</Arguments></Exec></Actions>
</Task>"#,
        xml_escape(executable),
        xml_escape(&args)
    ))
}

pub fn parse_renewal_args(args: &[String]) -> Result<(Scope, String, u16), String> {
    if args.len() < 2 || args[0] != "--kms-renew" {
        return Err("无效的续期参数".into());
    }
    let scope = Scope::from_switch(&args[1]).ok_or("未知续期范围")?;
    let mut server = String::new();
    let mut port = 1688;
    let mut seen_server = false;
    let mut seen_port = false;
    let mut index = 2;
    while index < args.len() {
        let value = args.get(index + 1).ok_or("续期参数缺少值")?;
        match args[index].as_str() {
            "--kms-server" if !seen_server => {
                server = normalize_kms_host(value).map_err(|e| e.to_string())?;
                seen_server = true;
            }
            "--kms-port" if !seen_port => {
                port = validate_kms_port(value).map_err(|e| e.to_string())?;
                seen_port = true;
            }
            _ => return Err("未知或重复的续期参数".into()),
        }
        index += 2;
    }
    Ok((scope, server, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protects_digital_and_kms38_but_not_enterprise_g() {
        assert!(protected_windows("test", 1, 0));
        assert!(protected_windows("test", 1, 3_000_000));
        assert!(!protected_windows("test", 0, 3_000_000));
        assert!(!protected_windows("test", 1, 259_200));
        assert!(!protected_windows(
            "e0b2d383-d112-413f-8a80-97f373a5820c",
            1,
            3_000_000
        ));
    }
    #[test]
    fn project_visio_does_not_include_other_office() {
        assert!(Scope::All.windows());
        assert!(!Scope::Office.windows());
        assert!(Scope::ProjectVisio.includes_office("Office 16, VisioPro"));
        assert!(!Scope::ProjectVisio.includes_office("Office 16, ProPlus"));
        assert!(!Scope::Windows.includes_office("Visio"));
    }
    #[test]
    fn custom_server_never_falls_back_to_public_servers() {
        assert_eq!(
            servers("kms.example.org", 3).unwrap(),
            vec!["kms.example.org"]
        );
        assert_eq!(servers("", 0).unwrap().len(), 15);
        assert!(servers("kms.example.org & calc", 0).is_err());
    }
    #[test]
    fn key_matches_sku_and_activation_id() {
        let id = "2de67392-b7a7-462a-b1ca-108dd189f588".to_owned();
        assert_eq!(
            windows_key(48, std::slice::from_ref(&id), true).unwrap().0,
            id
        );
        assert!(windows_key(4, &[id], true).is_err());
    }
    #[test]
    fn task_xml_escapes_executable_and_has_no_script_host() {
        let xml = renewal_xml(
            r"C:\Program Files\A&B\mas-rust.exe",
            Scope::Windows,
            "kms.example.org",
            1688,
        )
        .unwrap();
        assert!(xml.contains("A&amp;B"));
        assert!(xml.contains("--kms-renew windows"));
        assert!(!xml.contains("powershell"));
        assert!(!xml.contains("cmd.exe"));
        assert!(renewal_xml("app", Scope::Office, "a\" /bad", 1688).is_err());
    }
    #[test]
    fn renewal_args_reject_missing_unknown_or_duplicate_values() {
        let args = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            parse_renewal_args(&args("--kms-renew office --kms-port 1689")).unwrap(),
            (Scope::Office, String::new(), 1689)
        );
        for s in [
            "--kms-renew",
            "--kms-renew all --kms-port",
            "--kms-renew all --kms-port 0",
            "--kms-renew all --kms-port 1688 --kms-port 1",
            "--kms-renew all --activate",
        ] {
            assert!(parse_renewal_args(&args(s)).is_err());
        }
    }
}
