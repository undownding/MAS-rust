//! Office selection/conversion from :ts_process:, :tsksdata: and :offtsid:.
#![cfg_attr(not(test), allow(dead_code))]
use super::{activation_flow::Method, pkey_config::SelectionProduct};
use uuid::Uuid;
const TABLE: &str = include_str!("../../../vendor/mas/native/tsforge-office-conversion.tsv");
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Zero,
    Kms,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    MsiRetail,
    ProjectVisioOnly,
    MondoIncludesProjectVisio,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    pub license: String,
    pub key_type: KeyType,
    pub prepare_conversion: bool,
}
fn contains(value: &str, part: &str) -> bool {
    value
        .to_ascii_lowercase()
        .contains(&part.to_ascii_lowercase())
}
fn same(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}
fn rows(version: u32) -> impl Iterator<Item = (&'static str, &'static str)> {
    TABLE.lines().filter_map(move |line| {
        let mut p = line.split('\t');
        let v = p.next()?.parse::<u32>().ok()?;
        let target = p.next()?;
        let aliases = p.next().unwrap_or("");
        (v == version).then_some((target, aliases))
    })
}
pub fn plan(
    version: u32,
    product: &str,
    msi: bool,
    project_visio_only: bool,
    installed_products: &[String],
    method: Method,
) -> Result<Plan, Skip> {
    let found = rows(version).any(|(target, _)| same(target, product));
    if msi && method == Method::Kms4k && !found {
        return Err(Skip::MsiRetail);
    }
    let project_visio = contains(product, "Project") || contains(product, "Visio");
    if project_visio_only && !project_visio {
        return Err(Skip::ProjectVisioOnly);
    }
    if !project_visio_only
        && method == Method::Kms4k
        && project_visio
        && installed_products.iter().any(|p| contains(p, "O365"))
    {
        return Err(Skip::MondoIncludesProjectVisio);
    }
    let mut license = product.to_owned();
    let mut conversion = false;
    if method != Method::Kms4k {
        if (version == 15 && contains(product, "O365HomePremRetail"))
            || (version == 16 && contains(product, "O365"))
            || (!msi && contains(product, "ARM"))
        {
            license = "MondoRetail".into();
            conversion = true;
        }
    } else if !msi && !found {
        // The batch loop keeps the last matching row; preserve that order.
        license = rows(version)
            .filter(|(_, aliases)| aliases.split('-').any(|p| same(p, product)))
            .map(|(target, _)| target)
            .last()
            .unwrap_or("MondoVolume")
            .into();
        conversion = true;
    }
    let key_type = if method == Method::Kms4k && !contains(&license, "Retail") {
        KeyType::Kms
    } else {
        KeyType::Zero
    };
    Ok(Plan {
        license,
        key_type,
        prepare_conversion: conversion,
    })
}
pub fn activation_id(
    edition: &str,
    key_type: KeyType,
    configs: &[SelectionProduct],
) -> Option<Uuid> {
    let channels: &[&str] = match key_type {
        KeyType::Zero => &["OEM:NONSLP", "Volume:MAK", "Retail"],
        KeyType::Kms => &["Volume:GVLK"],
    };
    let mut ordered = Vec::new();
    for channel in channels {
        ordered.extend(configs.iter().filter(|p| {
            same(&p.edition, edition)
                && p.channel.as_deref().is_some_and(|c| same(c, channel))
                && !["demo", "MSDN", "PIN"]
                    .iter()
                    .any(|s| contains(&p.description, s))
        }));
    }
    ordered
        .iter()
        .find(|p| {
            !["preview", "c2r"]
                .iter()
                .any(|s| contains(&p.description, s))
        })
        .or_else(|| ordered.first())
        .map(|p| p.activation_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selection_reads_channels_from_xml_and_keeps_range_less_metadata() {
        let xml = include_str!("../../../tests/fixtures/tsforge/pkey-config.xml");
        let configs = super::super::pkey_config::parse_selection_config(xml).unwrap();
        assert_eq!(
            activation_id("测试😀", KeyType::Zero, &configs),
            Some(Uuid::from_u128(1))
        );
        assert_eq!(
            activation_id("NoRange", KeyType::Zero, &configs),
            Some(Uuid::from_u128(3))
        );
        assert_eq!(activation_id("测试😀", KeyType::Kms, &configs), None);
    }
    fn p(product: &str, version: u32, msi: bool, method: Method) -> Result<Plan, Skip> {
        plan(version, product, msi, false, &[], method)
    }
    #[test]
    fn o365_and_arm_conversion_depends_on_version_method_and_install_type() {
        assert_eq!(
            p("O365HomePremRetail", 15, false, Method::ZeroCid)
                .unwrap()
                .license,
            "MondoRetail"
        );
        assert_eq!(
            p("O365ProPlusRetail", 15, false, Method::ZeroCid)
                .unwrap()
                .license,
            "O365ProPlusRetail"
        );
        assert_eq!(
            p("O365ProPlusRetail", 16, false, Method::StaticCid)
                .unwrap()
                .license,
            "MondoRetail"
        );
        assert_eq!(
            p("HomeStudentARM2019Retail", 16, false, Method::ZeroCid)
                .unwrap()
                .license,
            "MondoRetail"
        );
        assert_eq!(
            p("HomeStudentARM2019Retail", 16, true, Method::ZeroCid)
                .unwrap()
                .license,
            "HomeStudentARM2019Retail"
        );
        assert_eq!(
            p("O365ProPlusRetail", 16, false, Method::Kms4k)
                .unwrap()
                .license,
            "MondoVolume"
        );
    }
    #[test]
    fn kms_mapping_preserves_free_retail_and_msi_skip() {
        let free = p("OneNoteFree2021Retail", 16, true, Method::Kms4k).unwrap();
        assert_eq!(free.key_type, KeyType::Zero);
        assert!(!free.prepare_conversion);
        assert_eq!(
            p("ProPlus2024Retail", 16, true, Method::Kms4k),
            Err(Skip::MsiRetail)
        );
        assert_eq!(
            p("ProPlus2024Retail", 16, false, Method::Kms4k)
                .unwrap()
                .license,
            "ProPlus2024Volume"
        );
        assert_eq!(
            p("unknown", 16, false, Method::Kms4k).unwrap().license,
            "MondoVolume"
        );
        assert_eq!(
            p("MondoRetail", 16, false, Method::Kms4k).unwrap().key_type,
            KeyType::Zero
        );
    }
    #[test]
    fn project_visio_scope_and_mondo_skip_use_original_products() {
        let installed = vec!["O365ProPlusRetail".into()];
        assert_eq!(
            plan(
                16,
                "ProjectPro2024Retail",
                false,
                false,
                &installed,
                Method::Kms4k
            ),
            Err(Skip::MondoIncludesProjectVisio)
        );
        assert!(
            plan(
                16,
                "ProjectPro2024Retail",
                false,
                true,
                &installed,
                Method::Kms4k
            )
            .is_ok()
        );
        assert!(
            plan(
                16,
                "VisioPro2024Retail",
                false,
                false,
                &installed,
                Method::ZeroCid
            )
            .is_ok()
        );
        assert_eq!(
            plan(
                16,
                "ProPlus2024Retail",
                false,
                true,
                &installed,
                Method::ZeroCid
            ),
            Err(Skip::ProjectVisioOnly)
        );
    }
    fn config(id: u128, channel: Option<&str>, description: &str) -> SelectionProduct {
        SelectionProduct {
            activation_id: Uuid::from_u128(id),
            edition: "ProPlusVolume".into(),
            description: description.into(),
            channel: channel.map(str::to_owned),
            pkey2009: false,
            has_wau_range: false,
        }
    }
    #[test]
    fn channel_priority_exclusions_and_preview_fallback() {
        let mut configs = vec![
            config(1, Some("Retail"), "Retail"),
            config(2, Some("Volume:MAK"), "MAK"),
            config(3, Some("OEM:NONSLP"), "preview"),
            config(4, Some("OEM:NONSLP"), "MSDN"),
            config(5, Some("Volume:GVLK"), "KMS"),
            config(6, None, "absent"),
        ];
        assert_eq!(
            activation_id("proplusvolume", KeyType::Zero, &configs),
            Some(Uuid::from_u128(2))
        );
        configs[1].description = "demo".into();
        configs[0].description = "PIN".into();
        assert_eq!(
            activation_id("ProPlusVolume", KeyType::Zero, &configs),
            Some(Uuid::from_u128(3))
        );
        assert_eq!(
            activation_id("ProPlusVolume", KeyType::Kms, &configs),
            Some(Uuid::from_u128(5))
        );
        assert_eq!(activation_id("Other", KeyType::Zero, &configs), None);
    }
    #[test]
    fn every_conversion_alias_maps_to_the_pinned_target() {
        for version in [15, 16] {
            for (target, aliases) in rows(version) {
                assert!(
                    !p(target, version, false, Method::Kms4k)
                        .unwrap()
                        .prepare_conversion
                );
                for alias in aliases.split('-').filter(|v| !v.is_empty()) {
                    assert_eq!(
                        p(alias, version, false, Method::Kms4k).unwrap().license,
                        target
                    );
                }
            }
        }
    }
}
