//! Pinned Server 2008 ESU fixed-key path; never generate a Vista key.
#![cfg_attr(not(test), allow(dead_code))]
use uuid::Uuid;
pub fn product() -> (Uuid, &'static str) {
    let (id, key) = include_str!("../../../vendor/mas/native/tsforge-vista-esu.tsv")
        .trim()
        .split_once('\t')
        .expect("pinned Vista ESU row");
    (Uuid::parse_str(id).expect("pinned Vista ESU ID"), key)
}
pub trait Backend {
    fn install(&mut self, key: &str) -> Result<(), String>;
    fn verify(&mut self, id: Uuid, suffix: &str) -> Result<(), String>;
    fn activate(&mut self, id: Uuid) -> Result<String, String>;
}
pub fn run(id: Uuid, backend: &mut impl Backend) -> Result<String, String> {
    let (expected, key) = product();
    if id != expected {
        return Err("Vista ESU 目标不在固定目录中，未执行密钥安装。".into());
    }
    backend.install(key).map_err(|e| {
        format!("Vista ESU 密钥安装调用失败：{e}；系统调用可能已改变密钥，不自动回滚。")
    })?;
    backend
        .verify(id, &key[24..])
        .map_err(|e| format!("Vista ESU 密钥已提交，映射校验失败：{e}；未继续激活。"))?;
    backend
        .activate(id)
        .map_err(|e| format!("Vista ESU 密钥已安装，ZeroCID 失败：{e}；不回退脚本或自动撤销安装。"))
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        calls: Vec<&'static str>,
        fail: Option<&'static str>,
    }
    impl Fake {
        fn step(&mut self, name: &'static str) -> Result<(), String> {
            self.calls.push(name);
            if self.fail == Some(name) {
                Err(name.into())
            } else {
                Ok(())
            }
        }
    }
    impl Backend for Fake {
        fn install(&mut self, key: &str) -> Result<(), String> {
            assert_eq!(key.len(), 29);
            self.step("install")
        }
        fn verify(&mut self, id: Uuid, suffix: &str) -> Result<(), String> {
            assert_eq!(id, product().0);
            assert_eq!(suffix, &product().1[24..]);
            self.step("verify")
        }
        fn activate(&mut self, _: Uuid) -> Result<String, String> {
            self.step("activate")?;
            Ok("verified".into())
        }
    }
    #[test]
    fn vista_esu_validates_target_and_stops_at_each_failed_stage() {
        let mut fake = Fake {
            calls: vec![],
            fail: None,
        };
        assert!(run(Uuid::nil(), &mut fake).is_err());
        assert!(fake.calls.is_empty());
        assert_eq!(run(product().0, &mut fake).unwrap(), "verified");
        assert_eq!(fake.calls, ["install", "verify", "activate"]);
        for (index, phase) in ["install", "verify", "activate"].iter().enumerate() {
            let mut fake = Fake {
                calls: vec![],
                fail: Some(phase),
            };
            assert!(run(product().0, &mut fake).unwrap_err().contains(phase));
            assert_eq!(fake.calls, ["install", "verify", "activate"][..=index]);
        }
    }
}
