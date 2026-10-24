//! MAS physical-store envelopes: RSA PKCS#1 v1.5, AES-CBC and SHA-1/HMAC.
//! Legacy algorithms are required by this on-disk format, not general-purpose choices.
use super::binary::{invalid, word};
use aes::{Aes128, Aes192, Aes256};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use rsa::{
    Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey,
    rand_core::{OsRng, RngCore},
};
use sha1::{Digest, Sha1};
use std::io::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "legacy envelope versions await native store routing"
    )
)]
pub enum Version {
    Vista,
    Win7,
    Win8,
    WinBlue,
    Modern,
}

impl Version {
    pub fn detect(build: u32) -> Result<Self> {
        match build {
            6000..=6003 => Ok(Self::Vista),
            7600..=7602 => Ok(Self::Win7),
            9200 => Ok(Self::Win8),
            9600.. => Ok(Self::Modern),
            _ => Err(invalid("unsupported Windows physical-store build")),
        }
    }
    pub fn format(self) -> super::physical::Format {
        match self {
            Self::Vista => super::physical::Format::Vista,
            Self::Win7 => super::physical::Format::Win7,
            _ => super::physical::Format::Modern,
        }
    }
    pub fn paired(self) -> bool {
        matches!(self, Self::Vista | Self::Win7)
    }
    fn number(self) -> u32 {
        match self {
            Self::Vista | Self::WinBlue => 2,
            Self::Win7 => 5,
            Self::Win8 => 1,
            Self::Modern => 3,
        }
    }
}

fn key(production: bool) -> Result<RsaPrivateKey> {
    let bytes: &[u8] = if production {
        include_bytes!("../../../vendor/mas/native/tsforge-production.blob")
    } else {
        include_bytes!("../../../vendor/mas/native/tsforge-test.blob")
    };
    super::super::ticket::signing_key(bytes).map_err(std::io::Error::other)
}

fn checksum(salt: &[u8], data: &[u8], version: Version) -> Vec<u8> {
    if matches!(version, Version::Vista) {
        let mut hash = Sha1::new();
        hash.update(salt);
        hash.update(data);
        hash.finalize().to_vec()
    } else {
        let mut hmac = Hmac::<Sha1>::new_from_slice(salt).expect("HMAC accepts any key length");
        hmac.update(data);
        hmac.finalize().into_bytes().to_vec()
    }
}

fn decrypt_aes(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let iv = [0; 16];
    let result = match key.len() {
        16 => cbc::Decryptor::<Aes128>::new_from_slices(key, &iv)
            .unwrap()
            .decrypt_padded_vec_mut::<Pkcs7>(data),
        24 => cbc::Decryptor::<Aes192>::new_from_slices(key, &iv)
            .unwrap()
            .decrypt_padded_vec_mut::<Pkcs7>(data),
        32 => cbc::Decryptor::<Aes256>::new_from_slices(key, &iv)
            .unwrap()
            .decrypt_padded_vec_mut::<Pkcs7>(data),
        _ => return Err(invalid("unsupported physical-store AES key length")),
    };
    result.map_err(|_| invalid("invalid physical-store AES padding"))
}

pub fn decrypt(data: &[u8], production: bool, version: Version) -> Result<Vec<u8>> {
    if data.len() < 0x120 || !(data.len() - 0x110).is_multiple_of(16) {
        return Err(invalid("truncated physical-store envelope"));
    }
    if data[..4] != version.number().to_le_bytes() || &data[4..16] != b"UNTRUSTSTORE" {
        return Err(invalid("unsupported physical-store envelope header"));
    }
    let rsa = key(production)?;
    let encrypted_key = &data[0x90..0x110];
    rsa.to_public_key()
        .verify(
            Pkcs1v15Sign::new::<Sha1>(),
            &Sha1::digest(encrypted_key),
            &data[0x10..0x90],
        )
        .map_err(|_| invalid("invalid physical-store RSA signature"))?;
    let aes_key = rsa
        .decrypt_blinded(&mut OsRng, Pkcs1v15Encrypt, encrypted_key)
        .map_err(|_| invalid("invalid physical-store RSA ciphertext"))?;
    let clear = decrypt_aes(&data[0x110..], &aes_key)?;
    if clear.len() < 40 || clear[36..40] != [0; 4] {
        return Err(invalid("unsupported physical-store cleartext header"));
    }
    let salt = &clear[..16];
    let signature = &clear[16..36];
    let payload = &clear[40..];
    if matches!(version, Version::Vista) {
        if checksum(salt, payload, version) != signature {
            return Err(invalid("invalid physical-store SHA-1 checksum"));
        }
    } else {
        let mut hmac = Hmac::<Sha1>::new_from_slice(salt).expect("HMAC accepts any key length");
        hmac.update(payload);
        hmac.verify_slice(signature)
            .map_err(|_| invalid("invalid physical-store HMAC"))?;
    }
    Ok(payload.to_vec())
}

pub fn encrypt(data: &[u8], production: bool, version: Version) -> Result<Vec<u8>> {
    let rsa = key(production)?;
    let aes_key = b"massgrave.dev :3";
    let mut salt = [0; 16];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(std::io::Error::other)?;
    let encrypted_key = rsa
        .to_public_key()
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, aes_key)
        .map_err(std::io::Error::other)?;
    let signature = rsa
        .sign_with_rng(
            &mut OsRng,
            Pkcs1v15Sign::new::<Sha1>(),
            &Sha1::digest(&encrypted_key),
        )
        .map_err(std::io::Error::other)?;
    let mut clear = salt.to_vec();
    clear.extend_from_slice(&checksum(&salt, data, version));
    word(&mut clear, 0);
    clear.extend_from_slice(data);
    let encrypted = cbc::Encryptor::<Aes128>::new(aes_key.into(), (&[0; 16]).into())
        .encrypt_padded_vec_mut::<Pkcs7>(&clear);
    let mut output = Vec::new();
    word(&mut output, version.number());
    output.extend_from_slice(b"UNTRUSTSTORE");
    output.extend_from_slice(&signature);
    output.extend_from_slice(&encrypted_key);
    output.extend_from_slice(&encrypted);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    const PAYLOAD: &[u8] = b"independent TSforge envelope fixture\0\xff";

    #[test]
    fn independent_openssl_envelopes_decrypt() {
        for (version, production, bytes) in [
            (
                Version::Vista,
                true,
                include_bytes!("../../../tests/fixtures/tsforge/envelope-vista.bin").as_slice(),
            ),
            (
                Version::Modern,
                false,
                include_bytes!("../../../tests/fixtures/tsforge/envelope-modern.bin").as_slice(),
            ),
            (
                Version::Win7,
                true,
                include_bytes!("../../../tests/fixtures/tsforge/envelope-win7.bin").as_slice(),
            ),
        ] {
            assert_eq!(decrypt(bytes, production, version).unwrap(), PAYLOAD);
            assert!(decrypt(bytes, !production, version).is_err());
            for offset in [0, 4, 16, 144, 272, bytes.len() - 1] {
                let mut corrupt = bytes.to_vec();
                corrupt[offset] ^= 1;
                assert!(
                    decrypt(&corrupt, production, version).is_err(),
                    "offset {offset}"
                );
            }
            for end in [0, 16, 272, bytes.len() - 1] {
                assert!(decrypt(&bytes[..end], production, version).is_err());
            }
        }
    }

    #[test]
    fn every_version_and_key_roundtrips_with_fresh_randomness() {
        for version in [
            Version::Vista,
            Version::Win7,
            Version::Win8,
            Version::WinBlue,
            Version::Modern,
        ] {
            for production in [false, true] {
                let first = encrypt(PAYLOAD, production, version).unwrap();
                let second = encrypt(PAYLOAD, production, version).unwrap();
                assert_ne!(first, second);
                assert_eq!(decrypt(&first, production, version).unwrap(), PAYLOAD);
                assert_eq!(decrypt(&second, production, version).unwrap(), PAYLOAD);
            }
        }
    }

    #[test]
    fn invalid_aes_key_lengths_and_padding_fail() {
        assert!(decrypt_aes(&[0; 16], &[0; 15]).is_err());
        for len in [16, 24, 32] {
            assert!(decrypt_aes(&[0; 15], &vec![0; len]).is_err());
        }
    }
}
