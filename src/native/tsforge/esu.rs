//! ESU catalog and eligibility from the pinned :ts_esu: section.
#![cfg_attr(not(test), allow(dead_code))]
use std::collections::HashSet;
use uuid::Uuid;
const TABLE: &str = include_str!("../../../vendor/mas/native/tsforge-esu.tsv");
const BASE: &str = "Education-EducationN-Enterprise-EnterpriseN-Professional-ProfessionalEducation-ProfessionalEducationN-ProfessionalN-ProfessionalWorkstation-ProfessionalWorkstationN";
#[derive(Debug, Clone)]
pub struct System<'a> {
    pub edition: &'a str,
    pub build: u32,
    pub revision: u32,
    pub server: bool,
    pub thin_pc: bool,
    pub embedded_pos: bool,
    pub embedded_standard: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Product {
    pub id: Uuid,
    pub name: &'static str,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Selection {
    Products(Vec<Product>),
    Ltsc,
    UnsupportedEdition { update_may_help: bool },
    MissingLicense,
    Unavailable,
}

pub struct Batch {
    pub succeeded: usize,
    pub errors: Vec<String>,
    pub consumer_helpers: bool,
}
pub fn run_products(
    products: &[Product],
    mut activate: impl FnMut(&Product) -> Result<(), String>,
) -> Batch {
    let mut batch = Batch {
        succeeded: 0,
        errors: Vec::new(),
        consumer_helpers: false,
    };
    for product in products {
        match activate(product) {
            Ok(()) => batch.succeeded += 1,
            Err(error) => batch.errors.push(format!("{}: {error}", product.id)),
        }
    }
    batch.consumer_helpers = batch.errors.is_empty()
        && products.iter().any(|p| {
            matches!(
                p.id.as_u128(),
                0x83d49986_add3_41d7_ba33_87c7bfb5c0fb | 0x0b533b5e_08b6_44f9_b885_c2de291ba456
            )
        });
    batch
}
fn same(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}
fn later_added(s: &System<'_>) -> bool {
    let min = if same(s.edition, "ServerRdsh") {
        5552
    } else if [
        "Core",
        "CoreN",
        "CoreCountrySpecific",
        "CoreSingleLanguage",
        "IoTEnterprise",
    ]
    .iter()
    .any(|e| same(s.edition, e))
    {
        6156
    } else if same(s.edition, "PPIPro") {
        6388
    } else {
        0
    };
    s.build == 19045 && min > 0 && s.revision >= min
}
pub fn select(system: &System<'_>, installed: &HashSet<Uuid>) -> Selection {
    if system.build > 14393
        && ["EnterpriseS", "IoTEnterpriseS", "IoTEnterpriseSK"]
            .iter()
            .any(|e| same(system.edition, e))
    {
        return Selection::Ltsc;
    }
    let later = later_added(system);
    let suffix = if same(system.edition, "Embedded") {
        // Upstream assigns Standard after POS when both packages exist.
        if system.embedded_standard {
            "[Standard]"
        } else if system.embedded_pos {
            "[POS]"
        } else {
            ""
        }
    } else {
        ""
    };
    let edition = format!("{}{suffix}", system.edition);
    let mut products = Vec::new();
    let mut found = false;
    if !system.thin_pc {
        for line in TABLE.lines() {
            let mut parts = line.split('\t');
            let id =
                Uuid::parse_str(parts.next().expect("catalog ID")).expect("validated catalog GUID");
            let name = parts.next().expect("catalog name");
            let editions = parts
                .next()
                .expect("catalog editions")
                .replace("%w10EsuEditions%", BASE)
                .replace(
                    "%w10EsuEditionsLaterAdded%",
                    if later { system.edition } else { "" },
                );
            if !installed.contains(&id) {
                continue;
            }
            found = true;
            if editions.split('-').any(|e| same(e, &edition)) {
                products.push(Product { id, name });
            }
        }
    }
    if !products.is_empty() {
        return Selection::Products(products);
    }
    if found {
        return Selection::UnsupportedEdition {
            update_may_help: system.build == 19045 && !later,
        };
    }
    let vista = system.build < 7600;
    let available = (vista && system.server)
        || (system.build <= 7602 && !vista && !system.thin_pc)
        || (system.build > 7602 && system.build <= 14393 && system.server)
        || ((10240..=19045).contains(&system.build) && !system.server)
        || system.build == 9600;
    if available {
        Selection::MissingLicense
    } else {
        Selection::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batch_attempts_all_products_and_only_postprocesses_complete_success() {
        let products = vec![
            Product {
                id: Uuid::from_u128(1),
                name: "first",
            },
            Product {
                id: Uuid::from_u128(0x83d49986_add3_41d7_ba33_87c7bfb5c0fb),
                name: "third year",
            },
        ];
        let mut visited = Vec::new();
        let batch = run_products(&products, |p| {
            visited.push(p.id);
            if p.name == "first" {
                Err("retained backup".into())
            } else {
                Ok(())
            }
        });
        assert_eq!(visited.len(), 2);
        assert_eq!(batch.succeeded, 1);
        assert_eq!(batch.errors.len(), 1);
        assert!(batch.errors[0].contains("retained backup"));
        assert!(!batch.consumer_helpers);
        assert!(run_products(&products, |_| Ok(())).consumer_helpers);
        assert!(!run_products(&products[..1], |_| Ok(())).consumer_helpers);
        assert!(!run_products(&[], |_| Ok(())).consumer_helpers);
    }
    fn system(edition: &str, build: u32, revision: u32) -> System<'_> {
        System {
            edition,
            build,
            revision,
            server: false,
            thin_pc: false,
            embedded_pos: false,
            embedded_standard: false,
        }
    }
    fn ids() -> HashSet<Uuid> {
        TABLE
            .lines()
            .map(|l| Uuid::parse_str(l.split('\t').next().unwrap()).unwrap())
            .collect()
    }
    fn products(selection: Selection) -> Vec<Product> {
        match selection {
            Selection::Products(p) => p,
            other => panic!("{other:?}"),
        }
    }
    #[test]
    fn later_editions_require_exact_build_and_revision_boundaries() {
        let installed =
            HashSet::from([Uuid::parse_str("f520e45e-7413-4a34-a497-d2765967d094").unwrap()]);
        for (edition, min) in [
            ("ServerRdsh", 5552),
            ("Core", 6156),
            ("CoreN", 6156),
            ("CoreCountrySpecific", 6156),
            ("CoreSingleLanguage", 6156),
            ("IoTEnterprise", 6156),
            ("PPIPro", 6388),
        ] {
            assert!(matches!(
                select(&system(edition, 19045, min - 1), &installed),
                Selection::UnsupportedEdition {
                    update_may_help: true
                }
            ));
            assert_eq!(
                products(select(&system(edition, 19045, min), &installed)).len(),
                1
            );
            assert!(matches!(
                select(&system(edition, 19044, min), &installed),
                Selection::UnsupportedEdition {
                    update_may_help: false
                }
            ));
        }
        assert_eq!(
            products(select(&system("professional", 19045, 0), &installed)).len(),
            1
        );
        assert_eq!(
            select(&system("Professional", 19045, 0), &HashSet::new()),
            Selection::MissingLicense
        );
    }
    #[test]
    fn ltsc_and_embedded_rules_are_not_generic_substring_matches() {
        let all = ids();
        assert_eq!(
            select(&system("EnterpriseS", 14394, 0), &all),
            Selection::Ltsc
        );
        assert_eq!(
            products(select(&system("EnterpriseS", 14393, 0), &all)).len(),
            2
        );
        // The upstream LTSC exclusion intentionally does not list EnterpriseSN.
        assert_eq!(
            products(select(&system("EnterpriseSN", 17763, 0), &all)).len(),
            2
        );
        let mut embedded = system("Embedded", 7601, 0);
        embedded.embedded_pos = true;
        assert!(products(select(&embedded, &all))[0].name.starts_with("POS"));
        embedded.embedded_standard = true;
        assert!(products(select(&embedded, &all))[0].name.starts_with("WES"));
        embedded.thin_pc = true;
        assert_eq!(select(&embedded, &all), Selection::Unavailable);
    }
    #[test]
    fn catalog_order_and_installed_license_intersection() {
        let all = ids();
        assert_eq!(all.len(), 17);
        let selected = products(select(&system("Professional", 19045, 0), &all));
        // Upstream gates by installed GUID and edition, not the table's comments.
        assert_eq!(selected.len(), 7);
        assert_eq!(
            selected[0].id.to_string(),
            "4220f546-f522-46df-8202-4d07afd26454"
        );
        let only = HashSet::from([selected[3].id]);
        assert_eq!(
            products(select(&system("Professional", 19045, 0), &only)),
            vec![selected[3].clone()]
        );
        assert_eq!(
            select(&system("Professional", 26100, 0), &HashSet::new()),
            Selection::Unavailable
        );
    }
}
