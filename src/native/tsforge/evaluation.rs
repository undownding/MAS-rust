//! Pinned :ts_wineval catalog and reset/install/online-activation sequencing.
#![cfg_attr(not(test), allow(dead_code))]
use std::collections::HashSet;
use uuid::Uuid;
#[derive(Debug, Clone)]
pub struct Product {
    pub id: Uuid,
    pub key: &'static str,
    pub edition: &'static str,
    pub version: &'static str,
    pub known_activation_issue: bool,
}
pub fn catalog() -> Vec<Product> {
    include_str!("../../../vendor/mas/native/tsforge-evaluation.tsv")
        .lines()
        .map(|line| {
            let row: Vec<_> = line.split('\t').collect();
            Product {
                id: Uuid::parse_str(row[0]).expect("pinned evaluation ID"),
                key: row[1],
                edition: row[2],
                version: row[3],
                known_activation_issue: row[4] == "1",
            }
        })
        .collect()
}
pub fn select(edition: &str, installed: &HashSet<Uuid>) -> Option<Product> {
    catalog()
        .into_iter()
        .find(|p| p.edition.eq_ignore_ascii_case(edition) && installed.contains(&p.id))
}
pub fn verified_days(license_status: u32, minutes: u32) -> Result<u32, String> {
    let days = u64::from(minutes).div_ceil(1440);
    if license_status == 1 && matches!(days, 90 | 180) {
        Ok(days as u32)
    } else {
        Err(format!(
            "评估许可尚未验证：LicenseStatus={license_status}，剩余 {days} 天（{minutes} 分钟）；预期已许可且为 90 或 180 天"
        ))
    }
}
pub trait Backend {
    fn reset(&mut self) -> Result<(), String>;
    fn install(&mut self, product: &Product) -> Result<(), String>;
    fn activate(&mut self, product: &Product) -> Result<(), String>;
    fn status(&mut self, product: &Product) -> Result<(u32, u32), String>;
}
pub fn run(product: &Product, backend: &mut impl Backend) -> Result<String, String> {
    backend
        .reset()
        .map_err(|e| format!("评估计时器重置失败：{e}"))?;
    backend
        .install(product)
        .map_err(|e| format!("评估计时器已重置，密钥安装失败：{e}"))?;
    backend.activate(product).map_err(|e| {
        format!(
            "评估密钥已安装，联网激活失败：{e}{}",
            if product.known_activation_issue {
                "；上游标记此版本存在已知激活问题"
            } else {
                ""
            }
        )
    })?;
    let (status, minutes) = backend
        .status(product)
        .map_err(|e| format!("已请求评估激活，但读取结果失败：{e}"))?;
    let days = verified_days(status, minutes)?;
    Ok(format!(
        "Windows {} 评估许可已验证，剩余 {days} 天；这不是永久激活。",
        product.version
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_is_unique_and_selects_installed_version_in_pinned_order() {
        let rows = catalog();
        assert_eq!(rows.len(), 29);
        assert_eq!(
            rows.iter().map(|p| p.id).collect::<HashSet<_>>().len(),
            rows.len()
        );
        for p in &rows {
            assert_eq!(p.key.len(), 29);
            assert!(p.key.split('-').all(|group| group.len() == 5));
            let selected = select(&p.edition.to_ascii_lowercase(), &HashSet::from([p.id])).unwrap();
            assert_eq!(selected.id, p.id);
        }
        assert_eq!(rows.iter().filter(|p| p.known_activation_issue).count(), 1);
        assert!(select("EnterpriseEval", &HashSet::new()).is_none());
        assert!(select("Enterprise", &rows.iter().map(|p| p.id).collect()).is_none());
        let candidates = rows
            .iter()
            .filter(|p| p.edition == "EnterpriseSEval")
            .collect::<Vec<_>>();
        let ids = candidates.iter().map(|p| p.id).collect();
        assert_eq!(
            select("EnterpriseSEval", &ids).unwrap().id,
            candidates[0].id
        );
    }
    #[test]
    fn verification_uses_ceil_days_without_overflow_and_requires_licensed_state() {
        for days in [90, 180] {
            assert_eq!(verified_days(1, days * 1440).unwrap(), days);
            assert_eq!(verified_days(1, (days - 1) * 1440 + 1).unwrap(), days);
            assert!(verified_days(1, (days - 1) * 1440).is_err());
            assert!(verified_days(1, days * 1440 + 1).is_err());
            assert!(verified_days(0, days * 1440).is_err());
        }
        assert!(verified_days(1, u32::MAX).is_err());
        assert!(verified_days(1, 0).is_err());
    }
    struct Fake {
        fail: &'static str,
        calls: Vec<&'static str>,
    }
    impl Fake {
        fn step(&mut self, name: &'static str) -> Result<(), String> {
            self.calls.push(name);
            if self.fail == name {
                Err("fixture error; backup retained".into())
            } else {
                Ok(())
            }
        }
    }
    impl Backend for Fake {
        fn reset(&mut self) -> Result<(), String> {
            self.step("reset")
        }
        fn install(&mut self, _: &Product) -> Result<(), String> {
            self.step("install")
        }
        fn activate(&mut self, _: &Product) -> Result<(), String> {
            self.step("activate")
        }
        fn status(&mut self, _: &Product) -> Result<(u32, u32), String> {
            self.step("status")?;
            Ok((1, 90 * 1440))
        }
    }
    #[test]
    fn every_failure_stops_at_its_stage_and_preserves_backup_error() {
        let product = catalog()
            .into_iter()
            .find(|p| p.known_activation_issue)
            .unwrap();
        let stages = ["reset", "install", "activate", "status"];
        for (index, stage) in stages.iter().enumerate() {
            let mut fake = Fake {
                fail: stage,
                calls: vec![],
            };
            let error = run(&product, &mut fake).unwrap_err();
            assert!(error.contains("backup retained"));
            assert_eq!(fake.calls, stages[..=index]);
            if *stage == "activate" {
                assert!(error.contains("已知激活问题"));
            }
        }
        let mut fake = Fake {
            fail: "",
            calls: vec![],
        };
        assert!(run(&product, &mut fake).unwrap().contains("不是永久激活"));
        assert_eq!(fake.calls, stages);
    }
}
