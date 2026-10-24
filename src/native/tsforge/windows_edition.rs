//! SKU and edition policy from :dk_checksku: / :ts_getedition:.
#![cfg_attr(not(test), allow(dead_code))]
const EDITIONS: &str = include_str!("../../../vendor/mas/native/tsforge-editions.tsv");

pub fn registry_sku(product_pfn: &str) -> Option<u32> {
    product_pfn
        .split('.')
        .nth(2)?
        .parse()
        .ok()
        .filter(|v| *v > 0)
}

/// Subscription selection requires a positively activated subscription, not just
/// different registry/SLC values. WMI and registry are fallback sources only.
pub fn effective_sku(
    slc: Option<u32>,
    wmi: Option<u32>,
    registry: Option<u32>,
    subscription_active: bool,
) -> Option<u32> {
    let slc = slc.filter(|v| *v > 0);
    let wmi = wmi.filter(|v| *v > 0);
    let registry = registry.filter(|v| *v > 0);
    if subscription_active
        && let (Some(slc), Some(base)) = (slc, registry)
        && slc != base
    {
        return Some(base);
    }
    slc.or(wmi).or(registry)
}

pub fn edition(
    sku: u32,
    installed_base_families: &[String],
    helper_name: Option<&str>,
) -> Option<String> {
    let installed = |name: &str| {
        installed_base_families
            .iter()
            .any(|f| f.eq_ignore_ascii_case(name))
    };
    for line in EDITIONS.lines() {
        let (id, name) = line.split_once('\t')?;
        if id.parse::<u32>().ok()? == sku && installed(name) {
            return Some(name.to_owned());
        }
    }
    helper_name
        .filter(|name| installed(name))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subscription_and_missing_source_precedence() {
        assert_eq!(registry_sku("Microsoft.Windows.48.example"), Some(48));
        assert_eq!(registry_sku("Microsoft.Windows.invalid.example"), None);
        assert_eq!(registry_sku("Microsoft.Windows.0.example"), None);
        assert_eq!(effective_sku(Some(4), Some(4), Some(48), true), Some(48));
        assert_eq!(effective_sku(Some(4), Some(4), Some(48), false), Some(4));
        assert_eq!(effective_sku(None, Some(4), Some(48), true), Some(4));
        assert_eq!(effective_sku(Some(0), None, Some(48), false), Some(48));
        assert_eq!(effective_sku(None, None, None, false), None);
    }
    #[test]
    fn installed_family_is_required_and_alias_order_is_preserved() {
        let families = vec!["ProEnterprise".into(), "Enterprise".into()];
        assert_eq!(edition(4, &families, None).as_deref(), Some("Enterprise"));
        assert_eq!(
            edition(4, &families[..1], None).as_deref(),
            Some("ProEnterprise")
        );
        assert_eq!(edition(48, &families, None), None);
        assert_eq!(
            edition(9999, &families, Some("Enterprise")).as_deref(),
            Some("Enterprise")
        );
        assert_eq!(edition(9999, &families, Some("Professional")), None);
        assert_eq!(
            edition(9999, &families, Some("enterprise")).as_deref(),
            Some("enterprise")
        );
        for line in EDITIONS.lines() {
            let (sku, name) = line.split_once('\t').unwrap();
            assert_eq!(
                edition(sku.parse().unwrap(), &[name.to_owned()], None).as_deref(),
                Some(name)
            );
        }
    }
}
