//! Upstream's DNS-resolution test, followed by Network List Manager.
use super::activation_flow::Method;

pub fn resolve(
    method: Method,
    auto: bool,
    mut connected: impl FnMut() -> bool,
) -> Result<Method, String> {
    if method != Method::StaticCid || connected() {
        return Ok(method);
    }
    if auto {
        Ok(Method::Kms4k)
    } else {
        Err("StaticCID 需要联网；未安装密钥或修改许可存储".into())
    }
}

#[cfg(windows)]
pub fn connected(report: &dyn Fn(&str)) -> bool {
    use std::{net::ToSocketAddrs, sync::mpsc, time::Duration};
    // MAS parses the resolved address in ping's heading, not its exit code.
    // DNS resolution therefore reproduces that check without launching ping.
    let (sender, receiver) = mpsc::channel();
    let worker = std::thread::Builder::new()
        .name("tsforge-connectivity".into())
        .spawn(move || {
            let found = [
                "l.root-servers.net",
                "resolver1.opendns.com",
                "download.windowsupdate.com",
                "google.com",
            ]
            .iter()
            .any(|host| {
                (*host, 0)
                    .to_socket_addrs()
                    .is_ok_and(|mut addresses| addresses.next().is_some())
            });
            let _ = sender.send(found);
        });
    if worker.is_ok()
        && receiver
            .recv_timeout(Duration::from_secs(30))
            .unwrap_or(false)
    {
        report("网络预检查：DNS 已解析。此检查不保证激活服务可达。");
        return true;
    }
    match network_list_manager() {
        Ok(true) => {
            report("网络预检查：Windows 报告已连接互联网。");
            true
        }
        Ok(false) => {
            report("网络预检查：未检测到互联网连接。");
            false
        }
        Err(error) => {
            report(&format!("无法确认联网状态：{error}"));
            false
        }
    }
}

#[cfg(windows)]
fn network_list_manager() -> Result<bool, String> {
    use windows::Win32::{
        Networking::NetworkListManager::{INetworkListManager, NetworkListManager},
        System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance},
    };
    let _com = crate::native::licensing::Licensing::new()?;
    let manager: INetworkListManager =
        unsafe { CoCreateInstance(&NetworkListManager, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| e.to_string())?;
    unsafe { manager.IsConnectedToInternet() }
        .map(|value| value.0 != 0)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_static_checks_network_and_auto_is_the_only_fallback() {
        assert_eq!(
            resolve(Method::ZeroCid, true, || panic!("offline method")).unwrap(),
            Method::ZeroCid
        );
        assert_eq!(
            resolve(Method::Kms4k, false, || panic!("offline method")).unwrap(),
            Method::Kms4k
        );
        assert_eq!(
            resolve(Method::StaticCid, true, || false).unwrap(),
            Method::Kms4k
        );
        assert!(resolve(Method::StaticCid, false, || false).is_err());
        assert_eq!(
            resolve(Method::StaticCid, false, || true).unwrap(),
            Method::StaticCid
        );
    }
    #[cfg(windows)]
    #[test]
    fn nlm_is_read_only_and_does_not_require_dns() {
        let _status = network_list_manager().unwrap();
    }
}
