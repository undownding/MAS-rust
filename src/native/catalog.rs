#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub id: String,
    pub key: String,
    pub sku: u32,
    pub part: String,
    pub blocked: bool,
}

pub fn entries(legacy: bool) -> Vec<Entry> {
    let data = if legacy {
        include_str!("../../vendor/mas/native/kms38.tsv")
    } else {
        include_str!("../../vendor/mas/native/hwid.tsv")
    };
    data.lines()
        .map(|line| {
            let f: Vec<_> = line.split('\t').collect();
            Entry {
                id: f[0].into(),
                key: f[1].into(),
                sku: f[2].parse().expect("validated embedded SKU"),
                part: if legacy { String::new() } else { f[3].into() },
                blocked: !legacy && f[4] == "1",
            }
        })
        .collect()
}

pub fn select(
    legacy: bool,
    sku: u32,
    ids: &[String],
    no_edition_change: bool,
) -> Result<Entry, String> {
    let available = |id: &str| ids.iter().any(|s| s.eq_ignore_ascii_case(id));
    let table = entries(legacy);
    let candidate = table.iter().find(|e| e.sku == sku && available(&e.id));
    if let Some(entry) = candidate.filter(|e| !e.blocked) {
        return Ok(entry.clone());
    }
    if !no_edition_change {
        let data = if legacy {
            include_str!("../../vendor/mas/native/kms38-fallback.tsv")
        } else {
            include_str!("../../vendor/mas/native/hwid-fallback.tsv")
        };
        for row in data.lines() {
            let f: Vec<_> = row.split('\t').collect();
            if f[0].parse::<u32>().ok() == Some(sku)
                && available(f[2])
                && available(f[3])
                && let Some(entry) = table.iter().find(|e| e.id == f[3] && !e.blocked)
            {
                return Ok(entry.clone());
            }
        }
    }
    Err(format!(
        "SKU {sku} 没有匹配的可用激活 ID。不会安装猜测的产品密钥；请检查版本支持、许可证文件及禁止版本切换选项。"
    ))
}

pub fn kms38_supported(build: u32, revision: u32) -> bool {
    (10240..26100).contains(&build) || (build == 26100 && revision < 7019)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selects_installed_activation_id_not_just_sku() {
        let id = "706e0cfd-23f4-43bb-a9af-1a492b9f1302".to_owned();
        let e = select(false, 125, std::slice::from_ref(&id), true).unwrap();
        assert_eq!(e.id, id);
        assert_eq!(e.part, "X21-05035");
        assert!(select(false, 125, &[], false).is_err());
    }
    #[test]
    fn edition_fallback_respects_user_option() {
        let ids = vec![
            "cce9d2de-98ee-4ce2-8113-222620c64a27".into(),
            "ed655016-a9e8-4434-95d9-4345352c2552".into(),
        ];
        assert_eq!(select(false, 125, &ids, false).unwrap().sku, 191);
        assert!(select(false, 125, &ids, true).is_err());
    }
    #[test]
    fn kms38_compatibility_boundary() {
        assert!(kms38_supported(19045, 7000));
        assert!(kms38_supported(26100, 7018));
        assert!(!kms38_supported(26100, 7019));
        assert!(!kms38_supported(26200, 1));
    }
}
