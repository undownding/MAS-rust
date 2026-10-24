//! WMI via COM directly. Never launches PowerShell, WMIC or cscript.
use crate::operations::{Action, Product};
use wmi::{IWbemClassWrapper, Variant, WMIConnection, WMIError};

pub const WINDOWS_APP: &str = "55c92734-d682-4d71-983e-d6ec3f16059f";
const OFFICE_APP: &str = "0ff1ce15-a989-479d-af46-f275c6370663";
pub struct Licensing {
    pub connection: WMIConnection,
}

pub fn string(obj: &IWbemClassWrapper, name: &str) -> Result<String, String> {
    match obj
        .get_property(name)
        .map_err(|e| format!("读取 {name}: {e}"))?
    {
        Variant::String(value) => Ok(value),
        Variant::Null | Variant::Empty => Ok(String::new()),
        other => Err(format!("{name} 的类型不是字符串：{other:?}")),
    }
}
pub fn number(obj: &IWbemClassWrapper, name: &str) -> Result<u32, String> {
    match obj
        .get_property(name)
        .map_err(|e| format!("读取 {name}: {e}"))?
    {
        Variant::UI4(value) => Ok(value),
        Variant::I4(value) => Ok(value as u32),
        Variant::UI2(value) => Ok(value as u32),
        Variant::String(value) => value.parse().map_err(|e| format!("解析 {name}: {e}")),
        other => Err(format!("{name} 的类型不是整数：{other:?}")),
    }
}
impl Licensing {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            connection: WMIConnection::new().map_err(|e| format!("连接本机 WMI: {e}"))?,
        })
    }
    pub fn query(&self, query: &str) -> Result<Vec<IWbemClassWrapper>, String> {
        self.connection
            .exec_query(query)
            .map_err(|e| format!("WMI 查询: {e}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("WMI 枚举: {e}"))
    }
    pub fn invoke(
        &self,
        class: &str,
        path: &str,
        method: &str,
        params: &[(&str, Variant)],
    ) -> Result<(), String> {
        let result = (|| -> wmi::WMIResult<_> {
            let definition = self.connection.get_object(class)?;
            let input = definition
                .get_method(method)?
                .map(|sig| sig.spawn_instance())
                .transpose()?;
            if let Some(input) = &input {
                for (key, value) in params {
                    input.put_property(key, value.clone())?;
                }
            } else if !params.is_empty() {
                return Err(WMIError::SerdeError("方法无输入参数".into()));
            }
            self.connection.exec_method(path, method, input.as_ref())
        })()
        .map_err(|e| format!("{class}.{method}: {e}"))?;
        if let Some(out) = result {
            let code = number(&out, "ReturnValue")?;
            if code != 0 {
                return Err(format!("{class}.{method} 返回 0x{code:08X}"));
            }
        }
        Ok(())
    }
    pub fn service(
        &self,
        class: &str,
        method: &str,
        params: &[(&str, Variant)],
    ) -> Result<(), String> {
        let services = self.query(&format!("SELECT * FROM {class}"))?;
        let service = services
            .first()
            .ok_or_else(|| format!("未找到 {class} 实例"))?;
        self.invoke(
            class,
            &service.path().map_err(|e| e.to_string())?,
            method,
            params,
        )
    }
    pub fn products(
        &self,
        class: &str,
        app: &str,
        installed_only: bool,
    ) -> Result<Vec<IWbemClassWrapper>, String> {
        self.query(&format!(
            "SELECT * FROM {class} WHERE ApplicationID='{app}'{}",
            if installed_only {
                " AND PartialProductKey IS NOT NULL"
            } else {
                ""
            }
        ))
    }
    pub fn refresh(&self) -> Result<(), String> {
        self.service("SoftwareLicensingService", "RefreshLicenseStatus", &[])
    }
    pub fn install(&self, key: &str) -> Result<(), String> {
        self.service(
            "SoftwareLicensingService",
            "InstallProductKey",
            &[("ProductKey", Variant::String(key.into()))],
        )
    }
    pub fn product_method(&self, product: &IWbemClassWrapper, method: &str) -> Result<(), String> {
        self.invoke(
            &string(product, "__CLASS")?,
            &product.path().map_err(|e| e.to_string())?,
            method,
            &[],
        )
    }
    pub fn status(&self, class: &str, app: &str) -> Result<String, String> {
        let products = self.products(class, app, true)?;
        if products.is_empty() {
            return Ok(format!("{class}: 没有已安装密钥的许可证。\n"));
        }
        let mut output = String::new();
        for p in products {
            let status = number(&p, "LicenseStatus")?;
            let label = [
                "未授权",
                "已授权",
                "初始宽限期",
                "额外宽限期",
                "非正版宽限期",
                "通知模式",
                "扩展宽限期",
            ]
            .get(status as usize)
            .copied()
            .unwrap_or("未知");
            output.push_str(&format!(
                "{}\nID: {}\n状态：{label} ({status})\n剩余宽限期：{} 分钟\n密钥末五位：{}\n\n",
                string(&p, "Name")?,
                string(&p, "ID")?,
                number(&p, "GracePeriodRemaining")?,
                string(&p, "PartialProductKey")?
            ));
        }
        Ok(output)
    }
}

pub fn execute(product: Product, action: &Action, report: &dyn Fn(&str)) -> Result<String, String> {
    let licensing = Licensing::new()?;
    let app = if product == Product::Windows {
        WINDOWS_APP
    } else {
        OFFICE_APP
    };
    let mut providers = vec![("SoftwareLicensingProduct", "SoftwareLicensingService", app)];
    if product == Product::Office {
        // Only an absent class is optional; provider/COM failures remain visible.
        match licensing
            .connection
            .get_object("OfficeSoftwareProtectionProduct")
        {
            Ok(_) => {
                providers.push((
                    "OfficeSoftwareProtectionProduct",
                    "OfficeSoftwareProtectionService",
                    "59a52881-a989-479d-af46-f275c6370663",
                ));
                providers.push((
                    "OfficeSoftwareProtectionProduct",
                    "OfficeSoftwareProtectionService",
                    OFFICE_APP,
                ));
            }
            Err(WMIError::HResultError { hres })
                if hres as u32 == 0x80041010 || hres as u32 == 0x80041002 => {}
            Err(e) => return Err(format!("查询 Office WMI 提供程序：{e}")),
        }
    }
    if matches!(action, Action::Query) {
        let mut output = String::new();
        for (class, _, app) in providers {
            output.push_str(&licensing.status(class, app)?);
        }
        return Ok(output);
    }
    if !crate::process::is_admin() {
        return Err("修改许可证需要管理员权限".into());
    }
    let mut applied = 0;
    for (class, service, app) in &providers {
        let all = licensing.products(class, app, false)?;
        if all.is_empty() {
            continue;
        }
        report(&format!("原生 COM/WMI：{service} / {}", action.label()));
        match action {
            Action::InstallKey(key) => {
                let key =
                    crate::operations::normalize_product_key(key).map_err(|e| e.to_string())?;
                licensing.service(
                    service,
                    "InstallProductKey",
                    &[("ProductKey", Variant::String(key))],
                )?;
                applied += 1;
                break; // Do not install the same key into a second provider.
            }
            Action::Activate | Action::UninstallKey(_) => {
                for p in all {
                    let tail = string(&p, "PartialProductKey")?;
                    if tail.is_empty() {
                        continue;
                    }
                    if let Action::UninstallKey(wanted) = action {
                        if product == Product::Office && !tail.eq_ignore_ascii_case(wanted) {
                            continue;
                        }
                        if product == Product::Windows
                            && !string(&p, "LicenseDependsOn")?.is_empty()
                        {
                            continue;
                        }
                    }
                    licensing.product_method(
                        &p,
                        if matches!(action, Action::Activate) {
                            "Activate"
                        } else {
                            "UninstallProductKey"
                        },
                    )?;
                    applied += 1;
                }
            }
            Action::SetKms { host, port } => {
                let host =
                    crate::operations::normalize_kms_host(host).map_err(|e| e.to_string())?;
                if *port == 0 {
                    return Err("KMS 端口不能为 0".into());
                }
                for p in all {
                    if string(&p, "PartialProductKey")?.is_empty() {
                        continue;
                    }
                    let path = p.path().map_err(|e| e.to_string())?;
                    licensing.invoke(
                        class,
                        &path,
                        "SetKeyManagementServiceMachine",
                        &[("MachineName", Variant::String(host.clone()))],
                    )?;
                    licensing
                        .invoke(
                            class,
                            &path,
                            "SetKeyManagementServicePort",
                            &[("PortNumber", Variant::UI4(*port as u32))],
                        )
                        .map_err(|e| {
                            format!("主机已设置，但端口设置失败：{e}。请重新设置或清除 KMS。")
                        })?;
                    applied += 1;
                }
            }
            Action::ClearKms => {
                for p in all {
                    if string(&p, "PartialProductKey")?.is_empty() {
                        continue;
                    }
                    licensing.product_method(&p, "ClearKeyManagementServiceMachine")?;
                    licensing.product_method(&p, "ClearKeyManagementServicePort")?;
                    applied += 1;
                }
            }
            Action::Query => unreachable!(),
        }
    }
    if applied == 0 {
        return Err("没有匹配的已安装产品或密钥。未执行修改。".into());
    }
    let mut result = format!("{}：原生 WMI 调用完成。\n", action.label());
    for (class, _, app) in providers {
        result.push_str(&licensing.status(class, app)?);
    }
    Ok(result)
}
