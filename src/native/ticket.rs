//! Pure Rust equivalent of MAS :sign (UTF-16LE session + RSA/SHA-256).
use base64::{Engine, engine::general_purpose::STANDARD};
use rsa::{BigUint, Pkcs1v15Sign, RsaPrivateKey};
use sha2::{Digest, Sha256};

pub const KMS38_SESSION: &str = "OSMajorVersion=5;OSMinorVersion=1;OSPlatformId=2;PP=0;GVLKExp=2038-01-19T03:14:07Z;DownlevelGenuineState=1;";

fn signing_key(blob: &[u8]) -> Result<RsaPrivateKey, String> {
    if blob.len() != 596
        || blob[..20]
            != [
                7, 2, 0, 0, 0, 0xa4, 0, 0, 0x52, 0x53, 0x41, 0x32, 0, 4, 0, 0, 1, 0, 1, 0,
            ]
    {
        return Err("票据签名 CSP blob 头或长度不匹配".into());
    }
    let n = BigUint::from_bytes_le(&blob[20..148]);
    let p = BigUint::from_bytes_le(&blob[148..212]);
    let q = BigUint::from_bytes_le(&blob[212..276]);
    let d = BigUint::from_bytes_le(&blob[468..596]);
    let key = RsaPrivateKey::from_components(n, BigUint::from(65537u32), d, vec![p, q])
        .map_err(|e| e.to_string())?;
    key.validate().map_err(|e| e.to_string())?;
    Ok(key)
}

pub fn hwid_session(sku: u32, part_number: &str) -> Result<String, String> {
    if part_number.is_empty()
        || !part_number
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("无效的票据部件编号".into());
    }
    Ok(format!(
        "OSMajorVersion=5;OSMinorVersion=1;OSPlatformId=2;PP=0;Pfn=Microsoft.Windows.{sku}.{part_number}_8wekyb3d8bbwe;PKeyIID=221306452340115677963964261259250411589493550039199940431586886;"
    ))
}

pub fn generate(session: &str) -> Result<String, String> {
    let bytes: Vec<_> = session
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    let properties = format!(
        "OA3xOriginalProductId=;OA3xOriginalProductKey=;SessionId={};TimeStampClient=2022-10-11T12:00:00Z",
        STANDARD.encode(bytes)
    );
    let key = signing_key(include_bytes!("../../vendor/mas/native/ticket-key.blob"))?;
    let sig = key
        .sign(
            Pkcs1v15Sign::new::<Sha256>(),
            &Sha256::digest(properties.as_bytes()),
        )
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><genuineAuthorization xmlns=\"http://www.microsoft.com/DRM/SL/GenuineAuthorization/1.0\"><version>1.0</version><genuineProperties origin=\"sppclient\"><properties>{properties}</properties><signatures><signature name=\"clientLockboxKey\" method=\"rsa-sha256\">{}</signature></signatures></genuineProperties></genuineAuthorization>",
        STANDARD.encode(sig)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_bad_signing_blob() {
        assert!(signing_key(&[0; 596]).is_err());
    }
    #[test]
    fn ticket_matches_independent_openssl_vector() {
        assert_eq!(
            generate(KMS38_SESSION).unwrap(),
            include_str!("../../tests/fixtures/kms38-ticket.xml").trim_end()
        );
    }
    #[test]
    fn windows_pro_session_is_exact() {
        let session = hwid_session(48, "X19-98841").unwrap();
        assert!(session.contains("Pfn=Microsoft.Windows.48.X19-98841_8wekyb3d8bbwe;"));
        assert_eq!(
            generate(&session).unwrap(),
            include_str!("../../tests/fixtures/hwid-pro-ticket.xml").trim_end()
        );
        assert!(hwid_session(48, "<&").is_err());
    }
}
