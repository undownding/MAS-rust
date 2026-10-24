//! Version-specific CID ordering, with explicit partial-state errors.
#![cfg_attr(not(test), allow(dead_code))]
use super::crypto::Version;
use std::path::PathBuf;

pub trait Backend {
    fn deposit(&mut self) -> Result<(), String>;
    fn write_store(&mut self) -> Result<PathBuf, String>;
    fn verify(&mut self) -> Result<(), String>;
}

pub fn run(version: Version, backend: &mut impl Backend) -> Result<PathBuf, String> {
    let legacy = version.paired();
    if legacy {
        backend.deposit().map_err(|e| {
            format!("旧版确认 ID 提交失败：{e}；尚未执行存储修改。SLC 调用不具备自动回滚。")
        })?;
    }
    let backup = backend.write_store().map_err(|e| {
        if legacy {
            format!("旧版确认 ID 已提交，但存储阶段失败：{e}；确认 ID 提交未撤销。")
        } else {
            format!("电话许可存储阶段失败：{e}；尚未提交确认 ID。")
        }
    })?;
    if !legacy {
        backend.deposit().map_err(|e| {
            format!(
                "确认 ID 提交失败：{e}；存储已修改，备份：{}。SLC 调用不具备自动回滚。",
                backup.display()
            )
        })?;
    }
    backend.verify().map_err(|e| {
        format!(
            "确认 ID 已提交，但刷新/许可校验失败：{e}；存储已修改，备份：{}。",
            backup.display()
        )
    })?;
    Ok(backup)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        events: Vec<&'static str>,
        fail: Option<&'static str>,
    }
    impl Fake {
        fn step(&mut self, event: &'static str) -> Result<(), String> {
            self.events.push(event);
            if self.fail == Some(event) {
                Err(format!("failure-{event}"))
            } else {
                Ok(())
            }
        }
    }
    impl Backend for Fake {
        fn deposit(&mut self) -> Result<(), String> {
            self.step("deposit")
        }
        fn write_store(&mut self) -> Result<PathBuf, String> {
            self.step("store")?;
            Ok(PathBuf::from("checkpoint"))
        }
        fn verify(&mut self) -> Result<(), String> {
            self.step("verify")
        }
    }
    #[test]
    fn version_controls_deposit_order_and_every_failure_stops_later_steps() {
        for version in [
            Version::Vista,
            Version::Win7,
            Version::Win8,
            Version::WinBlue,
            Version::Modern,
        ] {
            let order = if version.paired() {
                ["deposit", "store", "verify"]
            } else {
                ["store", "deposit", "verify"]
            };
            let mut backend = Fake {
                events: vec![],
                fail: None,
            };
            assert_eq!(
                run(version, &mut backend).unwrap(),
                PathBuf::from("checkpoint")
            );
            assert_eq!(backend.events, order);
            for (index, event) in order.iter().enumerate() {
                let mut backend = Fake {
                    events: vec![],
                    fail: Some(event),
                };
                let error = run(version, &mut backend).unwrap_err();
                assert_eq!(backend.events, order[..=index]);
                assert!(error.contains(&format!("failure-{event}")));
                if *event == "verify" || (*event == "deposit" && !version.paired()) {
                    assert!(error.contains("checkpoint"));
                }
                if *event == "store" && version.paired() {
                    assert!(error.contains("确认 ID 提交未撤销"));
                }
            }
        }
    }
}
