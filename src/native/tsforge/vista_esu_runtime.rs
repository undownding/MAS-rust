//! Native fixed MAK installation for the upstream Vista/Server 2008 ESU branch.
use super::{
    crypto::Version,
    runtime, sl,
    vista_esu::{self, Backend},
};
use crate::native::licensing::{Licensing, WINDOWS_APP, string};
use uuid::Uuid;
use windows_sys::core::GUID;
struct Native<'a> {
    licensing: Licensing,
    report: &'a dyn Fn(&str),
}
impl Backend for Native<'_> {
    fn install(&mut self, key: &str) -> Result<(), String> {
        self.licensing.install(key)
    }
    fn verify(&mut self, id: Uuid, suffix: &str) -> Result<(), String> {
        self.licensing.refresh()?;
        // ESU is an add-on: do not filter LicenseDependsOn to NULL here.
        let rows = self.licensing.query(&format!("SELECT ID, PartialProductKey FROM SoftwareLicensingProduct WHERE ApplicationID='{WINDOWS_APP}' AND ID='{id}' AND PartialProductKey IS NOT NULL"))?;
        if rows.len() != 1
            || Uuid::parse_str(&string(&rows[0], "ID")?).map_err(|e| e.to_string())? != id
            || !string(&rows[0], "PartialProductKey")?.eq_ignore_ascii_case(suffix)
        {
            return Err("Vista ESU 许可证 ID 或密钥末五位不匹配".into());
        }
        let context = sl::Context::open().map_err(|e| e.to_string())?;
        let keys = context
            .installed_keys(&GUID::from_u128(id.as_u128()))
            .map_err(|e| e.to_string())?;
        if keys.len() != 1
            || context
                .key_channel(&keys[0])
                .map_err(|e| e.to_string())?
                .as_deref()
                != Some("Volume:MAK")
        {
            return Err("Vista ESU 密钥映射不唯一或非 Volume:MAK".into());
        }
        (self.report)("Vista ESU 固定密钥映射已验证，继续 ZeroCID；此安装本身不代表已激活。");
        Ok(())
    }
    fn activate(&mut self, id: Uuid) -> Result<String, String> {
        super::phone_runtime::zero_cid(id, self.report)
    }
}
pub fn activate(id: Uuid, report: &dyn Fn(&str)) -> Result<String, String> {
    if runtime::storage_preflight()?.version != Version::Vista {
        return Err("Vista ESU 专用分支与本机版本不符，未安装密钥。".into());
    }
    let licensing = Licensing::new()?;
    let rows = licensing.query(&format!(
        "SELECT ID FROM SoftwareLicensingProduct WHERE ApplicationID='{WINDOWS_APP}' AND ID='{id}'"
    ))?;
    if rows.len() != 1 {
        return Err("本机没有唯一的目标 ESU 许可证，未安装密钥。".into());
    }
    vista_esu::run(id, &mut Native { licensing, report })
}
