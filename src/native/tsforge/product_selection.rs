//! Windows-ActID selection from the pinned MAS :wintsid: routine.
#![cfg_attr(not(test), allow(dead_code))]
use super::{binary::invalid, pkey_config::SelectionProduct};
use std::{collections::HashSet, io};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    Zero,
    KmsClient,
    Avma,
    KmsHost,
}
impl Channel {
    pub fn matches(self, description: &str) -> bool {
        let description = description.to_ascii_uppercase();
        self.patterns().iter().any(|p| description.contains(p))
    }
    fn patterns(self) -> &'static [&'static str] {
        match self {
            Self::Zero => &["OEM_DM", "OEM_COA_SLP", "OEM_COA_NSLP", "MAK", "RETAIL"],
            Self::KmsClient => &["KMSCLIENT"],
            Self::Avma => &["VIRTUAL_MACHINE"],
            Self::KmsHost => &["KMS_"],
        }
    }
}
#[derive(Debug, Clone)]
pub struct Candidate {
    pub id: Uuid,
    pub family: String,
    pub description: String,
    pub mui_locked: bool,
    pub kms_count: usize,
}

/// File IDs are the union of matching non-Beta/non-Test license files. Empty
/// means upstream's fallback to WMI order. Host ties keep WMI order explicitly;
/// PowerShell's hashtable enumeration gives no stable tie ordering.
pub fn select(
    edition: &str,
    channel: Channel,
    candidates: &[Candidate],
    file_ids: &HashSet<Uuid>,
    configs: &[SelectionProduct],
) -> io::Result<Option<Uuid>> {
    let mut seen = HashSet::new();
    if candidates
        .iter()
        .any(|c| c.id.is_nil() || !seen.insert(c.id))
    {
        return Err(invalid("empty or duplicate Windows product ID"));
    }
    let mut ordered = Vec::new();
    for pattern in channel.patterns() {
        for c in candidates {
            if c.family.eq_ignore_ascii_case(edition)
                && c.description.to_ascii_uppercase().contains(pattern)
                && !ordered.iter().any(|old: &&Candidate| old.id == c.id)
            {
                ordered.push(c);
            }
        }
    }
    if channel == Channel::KmsHost && ordered.iter().any(|c| c.kms_count > 0) {
        ordered.retain(|c| c.kms_count > 0);
        ordered.sort_by_key(|c| std::cmp::Reverse(c.kms_count));
    } else {
        ordered.retain(|c| {
            (file_ids.is_empty() || file_ids.contains(&c.id))
            // Preserve upstream's -notcontains scalar comparison, not a substring check.
            && (edition.eq_ignore_ascii_case("CountrySpecific") || !c.mui_locked)
        });
    }
    let mut eligible = Vec::new();
    let mut checked = None;
    for c in ordered {
        let mut beta = false;
        if let Some(p) = configs.iter().find(|p| p.activation_id == c.id) {
            let desc = p.description.to_ascii_lowercase();
            if ["mui locked", "tencent", "qihoo", "wau"]
                .iter()
                .any(|s| desc.contains(s))
            {
                continue;
            }
            beta = ["beta", "rc ", "next ", "test", "pre-"]
                .iter()
                .any(|s| desc.contains(s));
            // Upstream uses single quotes: '$edition' is a literal, not the input edition.
            let priority =
                !beta && channel != Channel::KmsHost && p.edition.eq_ignore_ascii_case("$edition");
            if !beta && !priority && p.pkey2009 && p.has_wau_range {
                continue;
            }
            if priority && checked.is_none() {
                checked = Some(c.id);
            }
        }
        eligible.push((c.id, beta));
    }
    Ok(checked.or_else(|| {
        eligible
            .iter()
            .find(|(_, beta)| !beta)
            .or(eligible.first())
            .map(|(id, _)| *id)
    }))
}

/// Read only the first license's grant/allConditions/allConditions/productPolicies
/// policyStr nodes, as upstream does; unrelated policies must not affect selection.
pub fn policies(xml: &str) -> io::Result<(bool, usize)> {
    if xml.len() > 16 * 1024 * 1024 {
        return Err(invalid("license XML exceeds selection limit"));
    }
    let doc = roxmltree::Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            allow_dtd: false,
            nodes_limit: 100_000,
            ..Default::default()
        },
    )
    .map_err(io::Error::other)?;
    let root = doc.root_element();
    if root.tag_name().name() != "licenseGroup" {
        return Err(invalid("missing licenseGroup"));
    }
    let license = root
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "license")
        .ok_or_else(|| invalid("missing license"))?;
    let mut nodes = vec![license];
    for name in [
        "grant",
        "allConditions",
        "allConditions",
        "productPolicies",
        "policyStr",
    ] {
        nodes = nodes
            .into_iter()
            .flat_map(|n| n.children())
            .filter(|n| n.is_element() && n.tag_name().name() == name)
            .collect();
    }
    let (mut mui, mut count) = (false, 0);
    for node in nodes {
        let text: String = node
            .descendants()
            .filter(|n| n.is_text())
            .filter_map(|n| n.text())
            .collect();
        match node.attribute("name") {
            Some("Kernel-MUI-Language-Allowed") => mui |= !text.eq_ignore_ascii_case("EMPTY"),
            Some("Security-SPP-KmsCountedIdList") => {
                count = text.replace([' ', '\n'], "").split(',').count()
            }
            _ => {}
        }
    }
    Ok((mui, count))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn c(id: u128, channel: &str) -> Candidate {
        Candidate {
            id: Uuid::from_u128(id),
            family: "Professional".into(),
            description: channel.into(),
            mui_locked: false,
            kms_count: 0,
        }
    }
    fn config(id: u128, description: &str) -> SelectionProduct {
        SelectionProduct {
            activation_id: Uuid::from_u128(id),
            edition: "Professional".into(),
            description: description.into(),
            pkey2009: true,
            has_wau_range: false,
        }
    }
    #[test]
    fn channels_files_and_mui() {
        let mut list = vec![
            c(1, "RETAIL"),
            c(2, "OEM_DM"),
            c(3, "MAK"),
            c(4, "KMSCLIENT"),
            c(5, "VIRTUAL_MACHINE"),
        ];
        let empty = HashSet::new();
        assert!(Channel::Zero.matches("OEM_DM channel"));
        assert!(!Channel::Zero.matches("KMSCLIENT"));
        assert_eq!(
            select("professional", Channel::Zero, &list, &empty, &[]).unwrap(),
            Some(list[1].id)
        );
        list[1].mui_locked = true;
        assert_eq!(
            select("Professional", Channel::Zero, &list, &empty, &[]).unwrap(),
            Some(list[2].id)
        );
        let files = HashSet::from([list[1].id]);
        assert_eq!(
            select("Professional", Channel::Zero, &list, &files, &[]).unwrap(),
            None
        );
        assert_eq!(
            select("Professional", Channel::KmsClient, &list, &empty, &[]).unwrap(),
            Some(list[3].id)
        );
        assert_eq!(
            select("Professional", Channel::Avma, &list, &empty, &[]).unwrap(),
            Some(list[4].id)
        );
        assert_eq!(
            select("Enterprise", Channel::Zero, &list, &empty, &[]).unwrap(),
            None
        );
        list.push(list[0].clone());
        assert!(select("Professional", Channel::Zero, &list, &empty, &[]).is_err());
    }
    #[test]
    fn host_count_overrides_files_and_mui_with_stable_ties() {
        let mut list = vec![c(1, "KMS_HOST"), c(2, "KMS_HOST"), c(3, "KMS_HOST")];
        list[0].kms_count = 1;
        list[1].kms_count = 5;
        list[2].kms_count = 5;
        list[1].mui_locked = true;
        assert_eq!(
            select(
                "Professional",
                Channel::KmsHost,
                &list,
                &HashSet::from([list[0].id]),
                &[]
            )
            .unwrap(),
            Some(list[1].id)
        );
    }
    #[test]
    fn exclusions_beta_fallback_and_literal_edition() {
        let list = vec![c(1, "OEM_DM"), c(2, "MAK"), c(3, "RETAIL")];
        let mut configs = vec![config(1, "Beta"), config(2, "Tencent"), config(3, "Retail")];
        let empty = HashSet::new();
        assert_eq!(
            select("Professional", Channel::Zero, &list, &empty, &configs).unwrap(),
            Some(list[2].id)
        );
        configs[2].description = "Test".into();
        assert_eq!(
            select("Professional", Channel::Zero, &list, &empty, &configs).unwrap(),
            Some(list[0].id)
        );
        configs[2].description = "Retail".into();
        configs[2].has_wau_range = true;
        assert_eq!(
            select("Professional", Channel::Zero, &list, &empty, &configs).unwrap(),
            Some(list[0].id)
        );
        configs[2].edition = "$edition".into();
        assert_eq!(
            select("Professional", Channel::Zero, &list, &empty, &configs).unwrap(),
            Some(list[2].id)
        );
    }
    #[test]
    fn policy_scope_and_invalid_xml() {
        let xml = r#"<licenseGroup xmlns="urn:test"><license><grant><allConditions><allConditions><productPolicies><policyStr name="Kernel-MUI-Language-Allowed">EMPTY</policyStr><policyStr name="Security-SPP-KmsCountedIdList">a, b, c</policyStr></productPolicies></allConditions></allConditions></grant></license><license><grant><allConditions><allConditions><productPolicies><policyStr name="Kernel-MUI-Language-Allowed">zh-CN</policyStr></productPolicies></allConditions></allConditions></grant></license></licenseGroup>"#;
        assert_eq!(policies(xml).unwrap(), (false, 3));
        assert_eq!(
            policies(&xml.replacen("EMPTY", "zh-CN", 1)).unwrap(),
            (true, 3)
        );
        assert!(policies("<licenseGroup/>").is_err());
        assert!(
            policies("<!DOCTYPE x [<!ENTITY a 'a'>]><licenseGroup>&a;</licenseGroup>").is_err()
        );
    }
}
