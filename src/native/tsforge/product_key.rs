//! PKEY2005/PKEY2009 representation from the pinned LibTSforge ProductKey implementation.
//! Pure data encoding; does not install keys or alter licensing state.
use super::{
    binary::{crc32, invalid, word},
    variable_bag::{self, Block, Format},
};
use sha2::{Digest, Sha256};
use std::{fmt, io::Result};

const ALPHABET: &[u8; 24] = b"BCDFGHJKMPQRTVWXY2346789";
const URI: &str = "msft:rm/algorithm/pkey/2009";

#[derive(Debug, Clone, Copy)]
pub struct Key2009 {
    group: u32,
    serial: u32,
    security: u64,
    upgrade: bool,
    packed: u128,
}
impl Key2009 {
    pub fn new(group: u32, serial: u32, security: u64, upgrade: bool) -> Result<Self> {
        if group >= 1 << 20 || serial >= 1 << 30 || security >= 1 << 53 {
            return Err(invalid("product-key field exceeds PKEY2009 bit width"));
        }
        let mut packed = u128::from(group)
            | (u128::from(serial) << 20)
            | (u128::from(security) << 50)
            | (u128::from(upgrade) << 113);
        let checksum = crc32(&packed.to_le_bytes()) & 0x3ff;
        packed |= u128::from(checksum) << 103;
        Ok(Self {
            group,
            serial,
            security,
            upgrade,
            packed,
        })
    }
    pub fn bytes(self) -> [u8; 16] {
        self.packed.to_le_bytes()
    }
    pub fn algorithm_uri(self) -> &'static str {
        URI
    }
    pub fn binding(self) -> Result<Vec<u8>> {
        binding(&self.to_string(), URI)
    }

    /// Windows GUID memory order, as constructed by .NET Guid(byte[16]).
    pub fn binding_id(self) -> Result<[u8; 16]> {
        Ok(Sha256::digest(self.binding()?)[..16].try_into().unwrap())
    }
    pub fn phone_data(self, windows7: bool) -> Vec<u8> {
        if windows7 {
            return ((u64::from(self.group) << 41)
                | (self.security << 31)
                | (u64::from(self.serial) << 1)
                | u64::from(self.upgrade))
            .to_le_bytes()
            .to_vec();
        }
        let mut bytes = vec![
            0xef, 0x72, 0x06, 0x66, 0x09, 0x78, 0xfd, 0x4c, 0x8d, 0x54, 0x41, 0xb7, 0xfb, 0x73,
            0x89, 0x88,
        ];
        word(&mut bytes, self.group);
        word(&mut bytes, self.serial / 1_000_000);
        word(&mut bytes, self.serial % 1_000_000);
        word(&mut bytes, u32::from(self.upgrade));
        bytes.extend_from_slice(&self.security.to_le_bytes());
        bytes
    }
    pub fn pid3(self, part_number: &str) -> Result<Vec<u8>> {
        pid3(self.group, part_number, "")
    }
    pub fn extended_pid(self, metadata: &Metadata<'_>) -> Result<String> {
        if metadata.mpc.len() != 5
            || !metadata.mpc.bytes().all(|b| b.is_ascii_digit())
            || !(1..=366).contains(&metadata.day)
            || !(1..=9999).contains(&metadata.year)
        {
            return Err(invalid("invalid extended PID context"));
        }
        let license_type = match metadata.eula {
            "OEM" => 2,
            "Volume" => 3,
            _ => 0,
        };
        Ok(format!(
            "{}-{:05}-{:03}-{:06}-{license_type:02}-{:04}-{:04}.0000-{:03}{:04}",
            metadata.mpc,
            self.group,
            self.serial / 1_000_000,
            self.serial % 1_000_000,
            metadata.lcid,
            metadata.build,
            metadata.day,
            metadata.year
        ))
    }
    pub fn pid4(self, metadata: &Metadata<'_>) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        word(&mut bytes, 0x4f8);
        word(&mut bytes, 4);
        fixed(&mut bytes, &self.extended_pid(metadata)?, 0x80)?;
        fixed(&mut bytes, &guid_string(metadata.activation_id), 0x80)?;
        bytes.resize(bytes.len() + 0x10, 0);
        fixed(&mut bytes, metadata.edition, 0x208)?;
        bytes.extend_from_slice(&u64::from(self.upgrade).to_le_bytes());
        bytes.resize(bytes.len() + 0x50, 0);
        fixed(&mut bytes, metadata.part_number, 0x80)?;
        fixed(&mut bytes, metadata.channel, 0x80)?;
        fixed(&mut bytes, metadata.eula, 0x80)?;
        Ok(bytes)
    }
}
impl fmt::Display for Key2009 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut value = self.packed;
        let mut digits = [0; 25];
        let mut insertion = 0;
        for digit in digits.iter_mut().rev() {
            insertion = (value % 24) as usize;
            *digit = ALPHABET[insertion];
            value /= 24;
        }
        let mut letters = digits[1..].to_vec();
        letters.insert(insertion, b'N');
        for (index, chunk) in letters.chunks(5).enumerate() {
            if index != 0 {
                f.write_str("-")?;
            }
            f.write_str(std::str::from_utf8(chunk).unwrap())?;
        }
        Ok(())
    }
}

pub struct Metadata<'a> {
    pub mpc: &'a str,
    pub activation_id: [u8; 16],
    pub edition: &'a str,
    pub part_number: &'a str,
    pub channel: &'a str,
    pub eula: &'a str,
    pub lcid: u32,
    pub build: u32,
    pub day: u32,
    pub year: u32,
}
fn binding(text: &str, algorithm: &str) -> Result<Vec<u8>> {
    variable_bag::encode(
        &[
            Block {
                kind: 2,
                reserved: 0,
                key: utf16("SppPkeyBindingProductKey"),
                value: utf16(text),
            },
            Block {
                kind: 4,
                reserved: 0,
                key: utf16("SppPkeyBindingMiscData"),
                value: vec![],
            },
            Block {
                kind: 2,
                reserved: 0,
                key: utf16("SppPkeyBindingAlgorithm"),
                value: utf16(algorithm),
            },
        ],
        Format::Modern,
    )
}

fn pid3(group: u32, part_number: &str, pid2: &str) -> Result<Vec<u8>> {
    if !part_number.is_ascii()
        || part_number.contains('\0')
        || part_number.len() > 16
        || !pid2.is_ascii()
        || pid2.contains('\0')
        || pid2.len() > 24
    {
        return Err(invalid(
            "PID3 ASCII field exceeds width or contains invalid data",
        ));
    }
    let mut bytes = Vec::new();
    word(&mut bytes, 0xa4);
    word(&mut bytes, 3);
    bytes.extend_from_slice(pid2.as_bytes());
    bytes.resize(32, 0);
    word(&mut bytes, group);
    bytes.extend_from_slice(part_number.as_bytes());
    bytes.resize(160, 0);
    let reversed: Vec<_> = bytes.iter().rev().copied().collect();
    bytes.extend_from_slice(&(!crc32(&reversed)).to_be_bytes());
    Ok(bytes)
}

#[derive(Debug, Clone, Copy)]
pub struct Key2005(Key2009);
impl Key2005 {
    pub fn bytes(self) -> [u8; 16] {
        self.0.bytes()
    }
    pub fn new(group: u32, serial: u32, security: u64, upgrade: bool) -> Result<Self> {
        Key2009::new(group, serial, security, upgrade).map(Self)
    }
    pub fn algorithm_uri(self) -> &'static str {
        "msft:rm/algorithm/pkey/2005"
    }
    pub fn binding(self) -> Result<Vec<u8>> {
        binding(&self.to_string(), self.algorithm_uri())
    }
    pub fn binding_id(self) -> Result<[u8; 16]> {
        Ok(Sha256::digest(self.binding()?)[..16].try_into().unwrap())
    }
    pub fn phone_data(self, windows7: bool) -> Vec<u8> {
        let mut bytes = self.0.phone_data(windows7);
        if !windows7 {
            bytes[..16].copy_from_slice(&[
                0x95, 0x15, 0x73, 0xb8, 0xf6, 0xa2, 0x0b, 0x43, 0xa7, 0x99, 0xfb, 0xff, 0xb8, 0x1a,
                0x8d, 0x73,
            ]);
        }
        bytes
    }
    /// Non-OEM last-part entropy is supplied by the caller (0..1000), allowing
    /// deterministic tests and avoiding time-seeded RNG in runtime integration.
    pub fn pid2(self, mpc: &str, eula: &str, nonce: u32) -> Result<String> {
        if mpc.len() != 5 || !mpc.bytes().all(|b| b.is_ascii_digit()) || nonce >= 1000 {
            return Err(invalid("invalid PID2 MPC or nonce"));
        }
        let (high, low, last) = if eula == "OEM" {
            (
                "OEM".to_owned(),
                ((self.0.group / 2) % 100) * 10000 + self.0.serial / 100000,
                self.0.serial % 100000,
            )
        } else {
            (
                format!("{:03}", self.0.serial / 1000000),
                self.0.serial % 1000000,
                ((self.0.group / 2) % 100) * 1000 + nonce,
            )
        };
        let sum: u32 = low.to_string().bytes().map(|v| u32::from(v - b'0')).sum();
        let checksum = 7 - sum % 7;
        Ok(format!("{mpc}-{high}-{low:06}{checksum}-{last:05}"))
    }
    pub fn pid3(self, metadata: &Metadata<'_>, nonce: u32) -> Result<Vec<u8>> {
        pid3(
            self.0.group,
            metadata.part_number,
            &self.pid2(metadata.mpc, metadata.eula, nonce)?,
        )
    }
    pub fn pid4(self, metadata: &Metadata<'_>) -> Result<Vec<u8>> {
        self.0.pid4(metadata)
    }
}
impl fmt::Display for Key2005 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seed = (self.0.group as i32)
            .wrapping_mul(1000000000)
            .wrapping_add(self.0.serial as i32);
        let mut random = super::legacy_random::LegacyRandom::new(seed);
        let mut text = b"H4X3DH4X3DH4X3DH4X3D".to_vec();
        for _ in 0..5 {
            text.push(ALPHABET[random.next24()]);
        }
        for (index, chunk) in text.chunks(5).enumerate() {
            if index != 0 {
                f.write_str("-")?;
            }
            f.write_str(std::str::from_utf8(chunk).unwrap())?;
        }
        Ok(())
    }
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}
fn fixed(output: &mut Vec<u8>, text: &str, size: usize) -> Result<()> {
    if text.contains('\0') {
        return Err(invalid("PID field contains NUL"));
    }
    let value = utf16(text);
    if value.len() > size {
        return Err(invalid("PID field exceeds fixed width"));
    }
    let end = output.len() + size;
    output.extend_from_slice(&value);
    output.resize(end, 0);
    Ok(())
}
fn guid_string(bytes: [u8; 16]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
        u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn metadata() -> Metadata<'static> {
        Metadata {
            mpc: "03612",
            activation_id: [
                0x34, 0x27, 0xc9, 0x55, 0x82, 0xd6, 0x71, 0x4d, 0x98, 0x3e, 0xd6, 0xec, 0x3f, 0x16,
                0x05, 0x9f,
            ],
            edition: "测试😀",
            part_number: "X00-12345",
            channel: "Retail",
            eula: "Volume",
            lcid: 2052,
            build: 26100,
            day: 298,
            year: 2026,
        }
    }
    #[test]
    fn independent_integer_encoding_vectors_match_all_outputs() {
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/tsforge/key2009.json"))
                .unwrap();
        for fixture in fixtures.as_array().unwrap() {
            let key = Key2009::new(
                fixture["group"].as_u64().unwrap() as u32,
                fixture["serial"].as_u64().unwrap() as u32,
                fixture["security"].as_u64().unwrap(),
                fixture["upgrade"].as_bool().unwrap(),
            )
            .unwrap();
            assert_eq!(key.algorithm_uri(), URI);
            assert_eq!(key.to_string(), fixture["text"]);
            assert_eq!(hex(&key.bytes()), fixture["bytes"]);
            assert_eq!(hex(&key.binding().unwrap()), fixture["binding"]);
            assert_eq!(hex(&key.binding_id().unwrap()), fixture["binding_id"]);
            assert_eq!(hex(&key.phone_data(false)), fixture["phone"]);
            assert_eq!(hex(&key.phone_data(true)), fixture["phone_win7"]);
            assert_eq!(hex(&key.pid3("X00-12345").unwrap()), fixture["pid3"]);
            assert_eq!(
                key.extended_pid(&metadata()).unwrap(),
                fixture["extended_pid"]
            );
            assert_eq!(hex(&key.pid4(&metadata()).unwrap()), fixture["pid4"]);
        }
    }
    #[test]
    fn pkey2005_vectors_cover_suffix_pid2_and_binary_formats() {
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/tsforge/key2005.json"))
                .unwrap();
        for fixture in fixtures["keys"].as_array().unwrap() {
            let key = Key2005::new(
                fixture["group"].as_u64().unwrap() as u32,
                fixture["serial"].as_u64().unwrap() as u32,
                fixture["security"].as_u64().unwrap(),
                fixture["upgrade"].as_bool().unwrap(),
            )
            .unwrap();
            let mut context = metadata();
            context.eula = fixture["eula"].as_str().unwrap();
            let nonce = fixture["nonce"].as_u64().unwrap() as u32;
            assert_eq!(key.to_string(), fixture["text"]);
            assert_eq!(hex(&key.bytes()), fixture["bytes"]);
            assert_eq!(
                key.pid2(context.mpc, context.eula, nonce).unwrap(),
                fixture["pid2"]
            );
            assert_eq!(hex(&key.binding().unwrap()), fixture["binding"]);
            assert_eq!(hex(&key.binding_id().unwrap()), fixture["binding_id"]);
            assert_eq!(hex(&key.phone_data(false)), fixture["phone"]);
            assert_eq!(hex(&key.phone_data(true)), fixture["phone_win7"]);
            assert_eq!(hex(&key.pid3(&context, nonce).unwrap()), fixture["pid3"]);
            assert_eq!(hex(&key.pid4(&context).unwrap()), fixture["pid4"]);
        }
        let key = Key2005::new(1, 1, 1, false).unwrap();
        assert!(key.pid2("03612", "Retail", 1000).is_err());
        assert!(key.pid2("abcde", "OEM", 0).is_err());
    }
    #[test]
    fn rejects_out_of_range_fields_instead_of_silently_masking() {
        assert!(Key2009::new(1 << 20, 0, 0, false).is_err());
        assert!(Key2009::new(0, 1 << 30, 0, false).is_err());
        assert!(Key2009::new(0, 0, 1 << 53, false).is_err());
        let key = Key2009::new(0, 0, 0, false).unwrap();
        assert!(key.pid3("非ASCII").is_err());
        let mut context = metadata();
        context.edition = "bad\0edition";
        assert!(key.pid4(&context).is_err());
        context = metadata();
        context.day = 0;
        assert!(key.extended_pid(&context).is_err());
        let too_long = "😀".repeat(131);
        context = metadata();
        context.edition = &too_long;
        assert!(key.pid4(&context).is_err());
    }
}
