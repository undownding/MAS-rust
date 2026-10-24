//! Bound the UTF-16 name search by the byte length supplied by the SPP API.
pub fn contains_grace(name: &[u16]) -> bool {
    let end = name.iter().position(|c| *c == 0).unwrap_or(name.len());
    name[..end].windows(5).any(|word| {
        word.iter().zip([103, 114, 97, 99, 101]).all(|(c, w)| {
            let lower = if (65..=90).contains(c) { *c + 32 } else { *c };
            lower == w
        })
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grace_search_is_case_insensitive_and_stops_at_nul() {
        let utf16 = |s: &str| s.encode_utf16().collect::<Vec<_>>();
        assert!(contains_grace(&utf16("Office 16 GRACE edition")));
        assert!(!contains_grace(&utf16("Office 16\0Grace")));
        assert!(!contains_grace(&utf16("Grac")));
        assert!(!contains_grace(&utf16("Office 16")));
    }
}
