//! Fixed PKEY2005 registry targets. Backup IDs cannot choose paths or views.
use super::binary::invalid;
use std::{collections::HashSet, io};

pub struct Spec {
    pub id: &'static str,
    pub users: bool,
    pub path: &'static str,
    pub name: &'static str,
}
const WINDOWS: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const IE: &str = r"SOFTWARE\Microsoft\Internet Explorer\Registration";
const HOST: &str =
    r"S-1-5-20\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform";
pub const SPECS: [Spec; 7] = [
    Spec {
        id: "windows.product-id",
        users: false,
        path: WINDOWS,
        name: "ProductId",
    },
    Spec {
        id: "windows.digital-product-id",
        users: false,
        path: WINDOWS,
        name: "DigitalProductId",
    },
    Spec {
        id: "windows.digital-product-id4",
        users: false,
        path: WINDOWS,
        name: "DigitalProductId4",
    },
    Spec {
        id: "ie.product-id",
        users: false,
        path: IE,
        name: "ProductId",
    },
    Spec {
        id: "ie.digital-product-id",
        users: false,
        path: IE,
        name: "DigitalProductId",
    },
    Spec {
        id: "ie.digital-product-id4",
        users: false,
        path: IE,
        name: "DigitalProductId4",
    },
    Spec {
        id: "kms.host-config",
        users: true,
        path: HOST,
        name: "KmsHostConfig",
    },
];
pub fn select(ids: &[&str]) -> io::Result<Vec<&'static Spec>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let ids_set: HashSet<_> = ids.iter().copied().collect();
    if ids_set.len() != ids.len() || ids.iter().any(|id| !SPECS.iter().any(|s| s.id == *id)) {
        return Err(invalid("unknown or duplicate registry target ID"));
    }
    if !SPECS[..3].iter().all(|s| ids_set.contains(s.id)) {
        return Err(invalid("incomplete Windows product registry backup"));
    }
    let ie_count = SPECS[3..6]
        .iter()
        .filter(|s| ids_set.contains(s.id))
        .count();
    if ie_count != 0 && ie_count != 3 {
        return Err(invalid(
            "incomplete Internet Explorer product registry backup",
        ));
    }
    Ok(SPECS.iter().filter(|s| ids_set.contains(s.id)).collect())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn allows_only_complete_known_registry_groups_in_fixed_order() {
        for ie in [false, true] {
            for host in [false, true] {
                let mut ids: Vec<_> = SPECS[..3].iter().map(|s| s.id).collect();
                if ie {
                    ids.extend(SPECS[3..6].iter().map(|s| s.id));
                }
                if host {
                    ids.push(SPECS[6].id);
                }
                ids.reverse();
                let specs = select(&ids).unwrap();
                assert_eq!(specs[0].id, "windows.product-id");
                assert_eq!(specs.len(), 3 + if ie { 3 } else { 0 } + usize::from(host));
                assert!(specs[..3].iter().all(|s| !s.users && s.path == WINDOWS));
                assert_eq!(specs[0].name, "ProductId");
            }
        }
        assert!(select(&[]).unwrap().is_empty());
        assert!(select(&[SPECS[0].id]).is_err());
        let mut ids: Vec<_> = SPECS[..3].iter().map(|s| s.id).collect();
        ids.push(SPECS[3].id);
        assert!(select(&ids).is_err());
        ids.pop();
        ids.push(SPECS[0].id);
        assert!(select(&ids).is_err());
        ids.pop();
        ids.push("arbitrary.path");
        assert!(select(&ids).is_err());
    }
}
