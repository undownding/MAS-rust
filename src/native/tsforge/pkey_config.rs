//! Namespace-aware parsing of the embedded PKeyConfig used by LibTSforge.
use super::binary::invalid;
use base64::{Engine, engine::general_purpose::STANDARD};
use roxmltree::{Document, Node, ParsingOptions};
use rsa::rand_core::{OsRng, RngCore};
use std::{
    collections::{HashMap, HashSet},
    io::Result,
};
use uuid::Uuid;

const CONFIG_NS: &str = "http://www.microsoft.com/DRM/PKEY/Configuration/2.0";
const RIGHTS_NS: &str = "urn:mpeg:mpeg21:2003:01-REL-R-NS";
const TABLE_NS: &str = "http://www.microsoft.com/DRM/XrML2/TM/v2";
const MAX_XML: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Pkey2005,
    Pkey2009,
}
impl Algorithm {
    fn parse(uri: &str) -> Result<Self> {
        match uri {
            "msft:rm/algorithm/pkey/2005" => Ok(Self::Pkey2005),
            "msft:rm/algorithm/pkey/2009" => Ok(Self::Pkey2009),
            _ => Err(invalid("unknown product-key algorithm")),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRange {
    pub start: u32,
    pub end: u32,
    pub eula: String,
    pub part_number: String,
    pub valid: bool,
}
impl KeyRange {
    fn sampling_width(&self) -> Result<u32> {
        if self.end >= 1 << 30 {
            return Err(invalid("serial range exceeds product-key encoding width"));
        }
        self.end
            .checked_sub(self.start)
            .map(|width| width.max(1))
            .ok_or_else(|| invalid("reversed product-key range"))
    }
    pub fn contains(&self, serial: u32) -> bool {
        self.start <= serial && serial <= self.end
    }
    pub fn part_number(&self) -> &str {
        self.part_number.split([':', ';']).next().unwrap_or("")
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Product {
    pub activation_id: Uuid,
    pub group: u32,
    pub edition: String,
    pub description: String,
    pub channel: String,
    pub randomized: bool,
    pub algorithm: Algorithm,
    pub ranges: Vec<KeyRange>,
}
#[derive(Debug)]
pub struct Selection<'a> {
    pub range: &'a KeyRange,
    pub serial: u32,
}
impl Product {
    fn eligible_ranges(&self) -> Vec<&KeyRange> {
        self.ranges
            .iter()
            .filter(|range| self.algorithm == Algorithm::Pkey2005 || !range.eula.contains("WAU"))
            .collect()
    }
    /// Mirrors upstream: MatchParams includes End, but Random.Next excludes End
    /// unless Start == End. IsValid is preserved, not silently used as a filter.
    pub fn select(&self, index: usize, serial_offset: u32) -> Result<Selection<'_>> {
        let ranges = self.eligible_ranges();
        let range = *ranges
            .get(index)
            .ok_or_else(|| invalid("no selectable product-key range (or WAU-only product)"))?;
        if serial_offset >= range.sampling_width()? {
            return Err(invalid("serial offset outside upstream sampling interval"));
        }
        Ok(Selection {
            range,
            serial: range.start + serial_offset,
        })
    }
    pub fn sample(&self) -> Result<Selection<'_>> {
        let ranges = self.eligible_ranges();
        let count: u32 = ranges
            .len()
            .try_into()
            .map_err(|_| invalid("too many key ranges"))?;
        let index = random_below(count)? as usize;
        let width = ranges[index].sampling_width()?;
        self.select(index, random_below(width)?)
    }
}
pub(super) fn random_below(bound: u32) -> Result<u32> {
    if bound == 0 {
        return Err(invalid("no selectable key ranges"));
    }
    let threshold = bound.wrapping_neg() % bound;
    loop {
        let mut bytes = [0; 4];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(std::io::Error::other)?;
        let value = u32::from_le_bytes(bytes);
        if value >= threshold {
            return Ok(value % bound);
        }
    }
}

#[derive(Default)]
pub struct ConfigSet {
    pub products: Vec<Product>,
    loaded: HashSet<Uuid>,
}
impl ConfigSet {
    pub fn load_license(&mut self, file_id: Uuid, xml: &str) -> Result<usize> {
        if self.loaded.contains(&file_id) {
            return Ok(0);
        }
        let payload = extract_config(xml)?;
        let products = parse_config(&payload)?;
        let mut known: HashSet<_> = self.products.iter().map(|p| p.activation_id).collect();
        let before = self.products.len();
        for product in products {
            // Same first-product-wins policy as upstream across loaded license files.
            if known.insert(product.activation_id) {
                self.products.push(product);
            }
        }
        self.loaded.insert(file_id);
        Ok(self.products.len() - before)
    }
    #[cfg(windows)]
    pub fn load_sku(
        &mut self,
        context: &super::sl::Context,
        sku: &windows_sys::core::GUID,
    ) -> Result<Option<usize>> {
        let Some(file) = context
            .pkey_config_file_id(sku)
            .map_err(std::io::Error::other)?
        else {
            return Ok(None);
        };
        let id = Uuid::from_fields(file.data1, file.data2, file.data3, &file.data4);
        if self.loaded.contains(&id) {
            return Ok(Some(0));
        }
        let xml = context.license_xml(&file).map_err(std::io::Error::other)?;
        self.load_license(id, &xml).map(Some)
    }
    pub fn match_params(&self, group: u32, serial: u32) -> Result<&Product> {
        self.products
            .iter()
            .find(|p| p.group == group && p.ranges.iter().any(|r| r.contains(serial)))
            .ok_or_else(|| invalid("no product matches group and serial"))
    }
}

fn document(xml: &str) -> Result<Document<'_>> {
    if xml.len() > MAX_XML {
        return Err(invalid("PKeyConfig XML exceeds 64 MiB"));
    }
    Document::parse_with_options(
        xml,
        ParsingOptions {
            allow_dtd: false,
            nodes_limit: 1_000_000,
            ..Default::default()
        },
    )
    .map_err(std::io::Error::other)
}
fn children<'a, 'b>(
    node: Node<'a, 'b>,
    ns: &'a str,
    name: &'a str,
) -> impl Iterator<Item = Node<'a, 'b>> {
    node.children()
        .filter(move |child| child.has_tag_name((ns, name)))
}
fn field(node: Node<'_, '_>, name: &str) -> Result<String> {
    let mut matches = node
        .children()
        .filter(|child| child.has_tag_name((CONFIG_NS, name)));
    let child = matches
        .next()
        .ok_or_else(|| std::io::Error::other(format!("missing PKeyConfig field {name}")))?;
    if matches.next().is_some() || child.children().any(|n| n.is_element()) {
        return Err(invalid("duplicate or nested PKeyConfig scalar"));
    }
    Ok(child
        .children()
        .filter(|n| n.is_text())
        .filter_map(|n| n.text())
        .collect())
}
fn number(node: Node<'_, '_>, name: &str) -> Result<u32> {
    field(node, name)?
        .trim()
        .parse()
        .map_err(|_| invalid("invalid unsigned PKeyConfig number"))
}
fn id(node: Node<'_, '_>, name: &str) -> Result<Uuid> {
    Uuid::parse_str(field(node, name)?.trim())
        .map_err(|_| invalid("invalid PKeyConfig activation GUID"))
}
pub fn extract_config(license: &str) -> Result<String> {
    let doc = document(license)?;
    let root = doc.root_element();
    if !root.has_tag_name((RIGHTS_NS, "licenseGroup")) {
        return Err(invalid("unexpected licensing XML root"));
    }
    let mut nodes = vec![root];
    for (ns, name) in [
        (RIGHTS_NS, "license"),
        (RIGHTS_NS, "otherInfo"),
        (TABLE_NS, "infoTables"),
        (TABLE_NS, "infoList"),
        (TABLE_NS, "infoBin"),
    ] {
        nodes = nodes
            .into_iter()
            .flat_map(|n| children(n, ns, name))
            .collect();
    }
    nodes.retain(|n| n.attribute("name") == Some("pkeyConfigData"));
    if nodes.len() != 1 {
        return Err(invalid("missing or ambiguous embedded pkeyConfigData"));
    }
    if nodes[0].children().any(|n| n.is_element()) {
        return Err(invalid("nested elements in pkeyConfigData"));
    }
    let text: String = nodes[0]
        .children()
        .filter(|n| n.is_text())
        .filter_map(|n| n.text())
        .collect();
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = STANDARD
        .decode(compact)
        .map_err(|_| invalid("invalid pkeyConfigData base64"))?;
    String::from_utf8(bytes).map_err(|_| invalid("pkeyConfigData is not UTF-8"))
}

#[derive(Debug, Clone)]
pub struct SelectionProduct {
    pub activation_id: Uuid,
    pub edition: String,
    pub description: String,
    pub pkey2009: bool,
    pub has_wau_range: bool,
}

/// Selection needs configuration descriptions even when no installable range
/// exists. Keep this separate from parse_config's key-generation constraints.
pub fn parse_selection_config(xml: &str) -> Result<Vec<SelectionProduct>> {
    let doc = document(xml)?;
    let root = doc.root_element();
    if !root.has_tag_name((CONFIG_NS, "ProductKeyConfiguration")) {
        return Err(invalid("missing ProductKeyConfiguration root"));
    }
    let mut pkey2009 = HashSet::new();
    for parent in children(root, CONFIG_NS, "PublicKeys") {
        for node in children(parent, CONFIG_NS, "PublicKey") {
            if field(node, "AlgorithmId")?.eq_ignore_ascii_case("msft:rm/algorithm/pkey/2009") {
                pkey2009.insert(number(node, "GroupId")?);
            }
        }
    }
    let mut wau = HashSet::new();
    for parent in children(root, CONFIG_NS, "KeyRanges") {
        for node in children(parent, CONFIG_NS, "KeyRange") {
            if field(node, "EulaType")?
                .to_ascii_uppercase()
                .contains("WAU")
            {
                wau.insert(id(node, "RefActConfigId")?);
            }
        }
    }
    let mut known = HashSet::new();
    let mut result = Vec::new();
    for parent in children(root, CONFIG_NS, "Configurations") {
        for node in children(parent, CONFIG_NS, "Configuration") {
            let activation_id = id(node, "ActConfigId")?;
            if !known.insert(activation_id) {
                return Err(invalid("duplicate selection activation configuration"));
            }
            result.push(SelectionProduct {
                activation_id,
                edition: field(node, "EditionId")?,
                description: field(node, "ProductDescription")?,
                pkey2009: pkey2009.contains(&number(node, "RefGroupId")?),
                has_wau_range: wau.contains(&activation_id),
            });
        }
    }
    Ok(result)
}

pub fn parse_config(xml: &str) -> Result<Vec<Product>> {
    let doc = document(xml)?;
    let mut roots = doc
        .descendants()
        .filter(|n| n.has_tag_name((CONFIG_NS, "ProductKeyConfiguration")));
    let root = roots
        .next()
        .ok_or_else(|| invalid("missing ProductKeyConfiguration"))?;
    if roots.next().is_some() {
        return Err(invalid("multiple ProductKeyConfiguration roots"));
    }
    let mut algorithms = HashMap::new();
    for parent in children(root, CONFIG_NS, "PublicKeys") {
        for node in children(parent, CONFIG_NS, "PublicKey") {
            let group = number(node, "GroupId")?;
            let algorithm = Algorithm::parse(field(node, "AlgorithmId")?.trim())?;
            if algorithms
                .insert(group, algorithm)
                .is_some_and(|previous| previous != algorithm)
            {
                return Err(invalid("conflicting algorithms for one product-key group"));
            }
        }
    }
    let mut ranges: HashMap<Uuid, Vec<KeyRange>> = HashMap::new();
    for parent in children(root, CONFIG_NS, "KeyRanges") {
        for node in children(parent, CONFIG_NS, "KeyRange") {
            let start = number(node, "Start")?;
            let end = number(node, "End")?;
            if start > end || end >= 1 << 30 {
                return Err(invalid("invalid product-key serial range"));
            }
            let valid = match field(node, "IsValid")?.to_ascii_lowercase().as_str() {
                "true" => true,
                "false" => false,
                _ => return Err(invalid("invalid IsValid boolean")),
            };
            ranges
                .entry(id(node, "RefActConfigId")?)
                .or_default()
                .push(KeyRange {
                    start,
                    end,
                    valid,
                    eula: field(node, "EulaType")?,
                    part_number: field(node, "PartNumber")?,
                });
        }
    }
    let mut products = Vec::new();
    let mut known = HashSet::new();
    for parent in children(root, CONFIG_NS, "Configurations") {
        for node in children(parent, CONFIG_NS, "Configuration") {
            let activation_id = id(node, "ActConfigId")?;
            let Some(ranges) = ranges.get(&activation_id) else {
                continue;
            };
            if !known.insert(activation_id) {
                continue;
            }
            let group = number(node, "RefGroupId")?;
            if group >= 1 << 20 {
                return Err(invalid("product-key group exceeds encoding width"));
            }
            let algorithm = *algorithms
                .get(&group)
                .ok_or_else(|| invalid("missing group algorithm (will not assume PKEY2005)"))?;
            let channel = field(node, "ProductKeyType")?;
            products.push(Product {
                activation_id,
                group,
                algorithm,
                ranges: ranges.clone(),
                edition: field(node, "EditionId")?,
                description: field(node, "ProductDescription")?,
                randomized: channel.eq_ignore_ascii_case("true"),
                channel,
            });
        }
    }
    Ok(products)
}

#[cfg(test)]
mod tests {
    #[test]
    fn selection_retains_configs_without_key_ranges() {
        let xml = r#"<ProductKeyConfiguration xmlns="http://www.microsoft.com/DRM/PKEY/Configuration/2.0"><PublicKeys><PublicKey><GroupId>1</GroupId><AlgorithmId>msft:rm/algorithm/pkey/2009</AlgorithmId></PublicKey></PublicKeys><Configurations><Configuration><ActConfigId>{00000000-0000-0000-0000-000000000001}</ActConfigId><RefGroupId>1</RefGroupId><EditionId>Professional</EditionId><ProductDescription>Tencent</ProductDescription></Configuration></Configurations></ProductKeyConfiguration>"#;
        let entries = super::parse_selection_config(xml).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].description, "Tencent");
        assert!(entries[0].pkey2009);
        assert!(!entries[0].has_wau_range);
        assert!(super::parse_config(xml).unwrap().is_empty());
        let ranges = r#"<KeyRanges><KeyRange><RefActConfigId>{00000000-0000-0000-0000-000000000001}</RefActConfigId><EulaType>Retail:WAU</EulaType></KeyRange></KeyRanges>"#;
        let xml = xml.replace(
            "</ProductKeyConfiguration>",
            &format!("{ranges}</ProductKeyConfiguration>"),
        );
        assert!(super::parse_selection_config(&xml).unwrap()[0].has_wau_range);
    }
    use super::*;
    const XML: &str = include_str!("../../../tests/fixtures/tsforge/pkey-config.xml");
    fn envelope(xml: &str) -> String {
        let encoded = STANDARD.encode(xml);
        format!(
            r#"<r:licenseGroup xmlns:r="{RIGHTS_NS}" xmlns:t="{TABLE_NS}"><r:license><r:otherInfo><t:infoTables><t:infoList><t:infoBin name="pkeyConfigData">{encoded}</t:infoBin></t:infoList></t:infoTables></r:otherInfo></r:license></r:licenseGroup>"#
        )
    }
    #[test]
    fn parses_namespaces_unicode_and_range_metadata_without_loss() {
        let products = parse_config(XML).unwrap();
        assert_eq!(products.len(), 2);
        let product = &products[0];
        assert_eq!(product.edition, "测试😀");
        assert_eq!(product.description, "A & B");
        assert_eq!(product.channel, "Retail");
        assert!(!product.randomized);
        assert_eq!(product.algorithm, Algorithm::Pkey2009);
        assert_eq!(product.ranges[0].part_number(), "X00-00001");
        assert_eq!(product.ranges[0].part_number, "X00-00001:extra;more");
        assert!(!product.ranges[1].valid);
        let aliased = XML
            .replace("xmlns:p=", "xmlns:other=")
            .replace("<p:", "<other:")
            .replace("</p:", "</other:");
        assert_eq!(parse_config(&aliased).unwrap(), products);
        assert_eq!(extract_config(&envelope(XML)).unwrap(), XML);
    }
    #[test]
    fn matching_and_sampling_follow_distinct_upstream_endpoint_rules() {
        let products = parse_config(XML).unwrap();
        let product = &products[0];
        assert!(product.ranges[0].contains(20));
        assert_eq!(product.select(0, 9).unwrap().serial, 19);
        assert!(product.select(0, 10).is_err());
        assert!(product.select(1, 0).is_err()); // Modern WAU excluded.
        let singleton = products[1].select(0, 0).unwrap();
        assert_eq!(singleton.serial, 30); // Legacy WAU retained; equal bounds allowed.
        assert_eq!(singleton.range.eula, "WAU");
        for _ in 0..32 {
            assert!((10..20).contains(&product.sample().unwrap().serial));
        }
        let mut only_wau = product.clone();
        only_wau.ranges.remove(0);
        assert!(only_wau.sample().is_err());
        assert_eq!(products[1].sample().unwrap().serial, 30);
    }
    #[test]
    fn load_is_transactional_cached_and_preserves_first_product() {
        let mut set = ConfigSet::default();
        let file = Uuid::from_u128(1);
        assert!(set.load_license(file, "bad XML").is_err());
        assert!(set.products.is_empty());
        assert_eq!(set.load_license(file, &envelope(XML)).unwrap(), 2);
        assert_eq!(
            set.load_license(file, "cached data is not parsed again")
                .unwrap(),
            0
        );
        assert_eq!(set.match_params(1, 20).unwrap().edition, "测试😀");
        assert!(set.match_params(1, 21).is_err());
        assert_eq!(
            set.load_license(
                Uuid::from_u128(2),
                &envelope(&XML.replace("测试", "changed"))
            )
            .unwrap(),
            0
        );
        assert_eq!(set.products[0].edition, "测试😀");
        let before = set.products.clone();
        assert!(
            set.load_license(
                Uuid::from_u128(3),
                &envelope(&XML.replace("<p:End>30", "<p:End>29"))
            )
            .is_err()
        );
        assert_eq!(set.products, before);
    }
    #[cfg(windows)]
    #[test]
    fn parses_configuration_from_real_windows_license_without_installing_keys() {
        use super::super::sl::{Context, WINDOWS_APP_ID};
        let context = Context::open().unwrap();
        let mut set = ConfigSet::default();
        for status in context.statuses(&WINDOWS_APP_ID).unwrap() {
            set.load_sku(&context, &status.SkuId).unwrap();
            if !set.products.is_empty() {
                break;
            }
        }
        assert!(
            !set.products.is_empty(),
            "no Windows PKeyConfig was available for read-only validation"
        );
        assert!(
            set.products
                .iter()
                .all(|product| !product.ranges.is_empty())
        );
    }
    #[test]
    fn rejects_ambiguous_algorithms_malformed_ranges_and_unexpected_xml() {
        for malformed in [
            XML.replace("pkey/2009", "pkey/9999"),
            XML.replace("<p:GroupId>2", "<p:GroupId>1"),
            XML.replace("<p:GroupId>1", "<p:GroupId>9"),
            XML.replace("<p:Start>10", "<p:Start>-1"),
            XML.replace("<p:End>20", "<p:End>9"),
            XML.replace("<p:End>20", "<p:End>1073741824"),
            XML.replace("<p:IsValid>true", "<p:IsValid>maybe"),
            XML.replace("<p:EditionId>", "<p:EditionId><p:nested/>"),
            XML.replace(
                "<p:RefGroupId>1</p:RefGroupId>",
                "<p:RefGroupId>1</p:RefGroupId><p:RefGroupId>2</p:RefGroupId>",
            ),
            XML.replace(CONFIG_NS, "urn:wrong"),
            XML.replace(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
                "<!DOCTYPE test [<!ENTITY injected 'data'>]>",
            ),
        ] {
            assert!(parse_config(&malformed).is_err());
        }
        assert!(extract_config(&envelope(XML).replace("pkeyConfigData", "other")).is_err());
        assert!(extract_config(&envelope(XML).replace(TABLE_NS, "urn:wrong")).is_err());
        assert!(
            extract_config(&envelope(XML).replace(
                "</t:infoList>",
                "<t:infoBin name=\"pkeyConfigData\">AA==</t:infoBin></t:infoList>"
            ))
            .is_err()
        );
        assert!(extract_config(&envelope(XML).replace(&STANDARD.encode(XML), "%%%")).is_err());
    }
}
