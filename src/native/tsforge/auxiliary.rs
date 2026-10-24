//! Fixed Office KMS Host and APPX sideloading SKU catalogs from pinned MAS.
#![cfg_attr(not(test), allow(dead_code))]
use std::collections::HashSet;
use uuid::Uuid;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    OfficeHost,
    Appx,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Product {
    pub id: Uuid,
    pub name: &'static str,
}
impl Scope {
    pub fn supported(self, build: u32) -> bool {
        match self {
            Self::OfficeHost => build >= 7600,
            Self::Appx => (9200..=9600).contains(&build),
        }
    }
    pub fn applications(self) -> &'static [&'static str] {
        match self {
            Self::OfficeHost => &[
                "0ff1ce15-a989-479d-af46-f275c6370663",
                "59a52881-a989-479d-af46-f275c6370663",
            ],
            Self::Appx => &["55c92734-d682-4d71-983e-d6ec3f16059f"],
        }
    }
    pub fn select(self, installed: &HashSet<Uuid>) -> Vec<Product> {
        let data = match self {
            Self::OfficeHost => include_str!("../../../vendor/mas/native/tsforge-office-host.tsv"),
            Self::Appx => include_str!("../../../vendor/mas/native/tsforge-appx.tsv"),
        };
        data.lines()
            .filter_map(|line| {
                let (id, name) = line.split_once('\t').expect("validated catalog row");
                let id = Uuid::parse_str(id).expect("validated catalog GUID");
                installed.contains(&id).then_some(Product { id, name })
            })
            .collect()
    }
}
pub struct Batch {
    pub succeeded: usize,
    pub errors: Vec<String>,
}
pub fn run(
    products: &[Product],
    mut activate: impl FnMut(&Product) -> Result<(), String>,
) -> Batch {
    let mut result = Batch {
        succeeded: 0,
        errors: Vec::new(),
    };
    for product in products {
        match activate(product) {
            Ok(()) => result.succeeded += 1,
            Err(error) => result
                .errors
                .push(format!("{} ({}): {error}", product.name, product.id)),
        }
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_build_boundaries_and_application_ids() {
        assert!(!Scope::OfficeHost.supported(6002));
        assert!(Scope::OfficeHost.supported(7600));
        for build in [9199, 9601, 26100] {
            assert!(!Scope::Appx.supported(build));
        }
        for build in [9200, 9600] {
            assert!(Scope::Appx.supported(build));
        }
        assert_eq!(Scope::OfficeHost.applications().len(), 2);
        assert_ne!(
            Scope::OfficeHost.applications()[0],
            Scope::OfficeHost.applications()[1]
        );
        assert_eq!(Scope::Appx.applications().len(), 1);
    }
    #[test]
    fn installed_only_selection_preserves_upstream_host_order() {
        let ids = [
            "2e28138a-847f-42bc-9752-61b03fff33cd",
            "f3d89bbf-c0ec-47ce-a8fa-e5a5f97e447f",
            "bfe7a195-4f8f-4f0b-a622-cf13c7d16864",
        ]
        .map(|id| Uuid::parse_str(id).unwrap())
        .into_iter()
        .collect();
        let products = Scope::OfficeHost.select(&ids);
        assert_eq!(
            products.iter().map(|p| p.name).collect::<Vec<_>>(),
            [
                "KMSHost2010-ProPlusVL",
                "KMSHost2024Volume",
                "KMSHost2013Volume"
            ]
        );
        assert!(Scope::Appx.select(&ids).is_empty());
        assert!(Scope::OfficeHost.select(&HashSet::new()).is_empty());
        let appx =
            HashSet::from([Uuid::parse_str("ec67814b-30e6-4a50-bf7b-d55daf729d1e").unwrap()]);
        assert_eq!(Scope::Appx.select(&appx)[0].name, "APPXLOB-Client");
    }
    #[test]
    fn batches_continue_after_failure_and_keep_target_identity() {
        let products = vec![
            Product {
                id: Uuid::from_u128(1),
                name: "first",
            },
            Product {
                id: Uuid::from_u128(2),
                name: "second",
            },
        ];
        let mut visited = Vec::new();
        let result = run(&products, |p| {
            visited.push(p.id);
            if p.name == "first" {
                Err("backup retained".into())
            } else {
                Ok(())
            }
        });
        assert_eq!(visited.len(), 2);
        assert_eq!(result.succeeded, 1);
        assert!(result.errors[0].contains("first") && result.errors[0].contains("backup retained"));
    }
}
