//! Public legacy key catalogs from pinned :ts_oldks and :ts_winvista.
#![cfg_attr(not(test), allow(dead_code))]
use super::crypto::Version;
use std::collections::HashSet;
use uuid::Uuid;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Kms,
    Phone,
}
#[derive(Debug, Clone)]
pub struct Product {
    pub method: Method,
    pub version: Version,
    pub id: Uuid,
    pub key: &'static str,
    pub channel: &'static str,
    pub edition: &'static str,
}
pub fn catalog() -> Vec<Product> {
    include_str!("../../../vendor/mas/native/tsforge-legacy-windows.tsv")
        .lines()
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 6, "pinned legacy catalog columns");
            Product {
                method: match fields[0] {
                    "kms" => Method::Kms,
                    "phone" => Method::Phone,
                    _ => panic!("pinned legacy method"),
                },
                version: match fields[1] {
                    "vista" => Version::Vista,
                    "win7" => Version::Win7,
                    _ => panic!("pinned legacy version"),
                },
                id: Uuid::parse_str(fields[2]).expect("pinned legacy activation ID"),
                key: fields[3],
                channel: fields[4],
                edition: fields[5],
            }
        })
        .collect()
}
/// No match means no generic-key route. Never choose an ID absent from this PC.
pub fn select(
    version: Version,
    method: Method,
    edition: &str,
    installed: &HashSet<Uuid>,
) -> Option<Product> {
    catalog().into_iter().find(|product| {
        product.version == version
            && product.method == method
            && product.edition.eq_ignore_ascii_case(edition)
            && installed.contains(&product.id)
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_catalog_has_valid_unique_rows_and_preserves_server_aliases() {
        let products = catalog();
        assert_eq!(products.len(), 66);
        let mut unique = HashSet::new();
        for p in &products {
            assert!(!p.id.is_nil());
            assert!(unique.insert((
                format!("{:?}", p.method),
                format!("{:?}", p.version),
                p.edition
            )));
            let groups: Vec<_> = p.key.split('-').collect();
            assert_eq!(groups.len(), 5);
            assert!(groups.iter().all(|g| {
                g.len() == 5
                    && g.bytes()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            }));
            assert!(!p.key.contains('%'));
            match p.method {
                Method::Kms => assert_eq!(p.channel, "Volume:GVLK"),
                Method::Phone => {
                    assert_eq!(p.version, Version::Vista);
                    assert!(matches!(p.channel, "Retail" | "OEM:NONSLP"));
                }
            }
        }
        let normal = products
            .iter()
            .find(|p| p.version == Version::Win7 && p.edition == "ServerStandard")
            .unwrap();
        let core = products
            .iter()
            .find(|p| p.version == Version::Win7 && p.edition == "ServerStandardCore")
            .unwrap();
        assert_eq!(normal.id, core.id);
        assert_eq!(normal.key, core.key);
        assert!(products.iter().any(|p| p.edition == "Embedded_POSReady"));
        assert!(products.iter().any(|p| p.edition == "Embedded_ThinPC"));
    }
    #[test]
    fn every_row_selects_only_with_its_installed_id_and_requested_method() {
        for product in catalog() {
            assert!(
                select(
                    product.version,
                    product.method,
                    product.edition,
                    &HashSet::new()
                )
                .is_none()
            );
            let ids = HashSet::from([product.id]);
            let found = select(
                product.version,
                product.method,
                &product.edition.to_lowercase(),
                &ids,
            )
            .unwrap();
            assert_eq!(found.id, product.id);
            assert_eq!(found.key, product.key);
            assert!(select(Version::Win8, product.method, product.edition, &ids).is_none());
            assert!(select(Version::Modern, product.method, product.edition, &ids).is_none());
        }
    }
    #[test]
    fn overlapping_edition_names_do_not_cross_generations_or_key_methods() {
        let ids: HashSet<_> = catalog().iter().map(|p| p.id).collect();
        let vista = select(Version::Vista, Method::Kms, "Enterprise", &ids).unwrap();
        let win7 = select(Version::Win7, Method::Kms, "Enterprise", &ids).unwrap();
        let phone = select(Version::Vista, Method::Phone, "Enterprise", &ids).unwrap();
        assert_ne!(vista.id, win7.id);
        assert_ne!(vista.id, phone.id);
        assert!(select(Version::Win7, Method::Phone, "Enterprise", &ids).is_none());
        assert!(select(Version::Vista, Method::Phone, "StarterN", &ids).is_none());
        assert!(select(Version::Vista, Method::Phone, "ServerComputeClusterV", &ids).is_none());
        assert!(select(Version::Vista, Method::Kms, "Ultimate", &ids).is_none());
    }
}
