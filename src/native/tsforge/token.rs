//! Modern tokens.dat codec. Strict validation precedes any reconstruction.
use super::binary::{Reader, invalid, length, word};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    io::Result,
};

const BLOCK_SIZE: usize = 0x4020;
const ENTRY_SIZE: usize = 0x9e;
const SLOTS: usize = BLOCK_SIZE / ENTRY_SIZE;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub extension: String,
    pub data: Option<Vec<u8>>,
}

impl Entry {
    fn empty() -> Self {
        Self {
            name: String::new(),
            extension: String::new(),
            data: None,
        }
    }
}

fn string(bytes: &[u8]) -> Result<String> {
    if !bytes.len().is_multiple_of(2) {
        return Err(invalid("odd UTF-16 token field length"));
    }
    let words: Vec<_> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u16::from_le_bytes([v[0], v[1]]))
        .collect();
    let end = words
        .iter()
        .position(|w| *w == 0)
        .ok_or_else(|| invalid("unterminated token field"))?;
    if words[end..].iter().any(|w| *w != 0) {
        return Err(invalid("unexpected bytes after token field terminator"));
    }
    String::from_utf16(&words[..end]).map_err(|_| invalid("invalid UTF-16 token field"))
}

fn encoded(value: &str) -> Result<Vec<u8>> {
    if value.contains('\0') {
        return Err(invalid("token string contains NUL"));
    }
    Ok(value
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect())
}

fn fixed(output: &mut Vec<u8>, value: &str, width: usize) -> Result<()> {
    let data = encoded(value)?;
    if data.len() > width {
        return Err(invalid("token field exceeds fixed width"));
    }
    output.extend_from_slice(&data);
    output.resize(output.len() + width - data.len(), 0);
    Ok(())
}

fn at(bytes: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| invalid("token offset overflow"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| invalid("token offset outside file"))
}

fn hash(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn file_hash(bytes: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(&bytes[..4]);
    hash.update(&bytes[0x24..]);
    hash.finalize().to_vec()
}

fn reserve_range(ranges: &mut BTreeMap<usize, usize>, start: usize, end: usize) -> Result<()> {
    if ranges
        .range(..=start)
        .next_back()
        .is_some_and(|(_, previous_end)| *previous_end > start)
        || ranges
            .range(start..)
            .next()
            .is_some_and(|(next_start, _)| *next_start < end)
    {
        return Err(invalid("overlapping token file ranges"));
    }
    ranges.insert(start, end);
    Ok(())
}

pub fn decode(bytes: &[u8]) -> Result<Vec<Entry>> {
    if bytes.len() < 0x24 + BLOCK_SIZE || bytes[..4] != 3u32.to_le_bytes() {
        return Err(invalid("unsupported or truncated token store"));
    }
    if file_hash(bytes) != bytes[4..0x24] {
        return Err(invalid("invalid token file hash"));
    }
    let mut entries = Vec::new();
    let mut offset = 0x24;
    let mut visited = HashSet::new();
    let mut ranges = BTreeMap::from([(0, 0x24)]);
    while offset != 0 {
        if !visited.insert(offset) {
            return Err(invalid("cycle in token block chain"));
        }
        let block = at(bytes, offset, BLOCK_SIZE)?;
        reserve_range(&mut ranges, offset, offset + BLOCK_SIZE)?;
        if hash(&block[..BLOCK_SIZE - 32]) != block[BLOCK_SIZE - 32..] {
            return Err(invalid("invalid token block hash"));
        }
        let mut reader = Reader::new(block);
        if reader.u32()? as usize != offset {
            return Err(invalid("token block self offset mismatch"));
        }
        let next = reader.u32()? as usize;
        for index in 0..SLOTS {
            let entry_offset = reader.u32()? as usize;
            if entry_offset != offset + 8 + index * ENTRY_SIZE {
                return Err(invalid("token entry self offset mismatch"));
            }
            let populated = reader.u32()?;
            let content_offset = reader.u32()? as usize;
            let content_len = reader.u32()? as usize;
            let allocation = reader.u32()? as usize;
            let name = string(reader.take(0x82)?)?;
            let extension = string(reader.take(8)?)?;
            let data = match populated {
                0 => {
                    if content_offset != 0
                        || content_len != u32::MAX as usize
                        || allocation != u32::MAX as usize
                    {
                        return Err(invalid("unsupported inactive token entry"));
                    }
                    None
                }
                1 => {
                    if allocation != content_len {
                        return Err(invalid("unsupported token allocation slack"));
                    }
                    let len = content_len
                        .checked_add(100)
                        .ok_or_else(|| invalid("token content length overflow"))?;
                    let content = at(bytes, content_offset, len)?;
                    reserve_range(&mut ranges, content_offset, content_offset + len)?;
                    if content[..32] != [0x55; 32] || content[len - 32..] != [0xaa; 32] {
                        return Err(invalid("invalid token content markers"));
                    }
                    if u32::from_le_bytes(content[32..36].try_into().unwrap()) as usize
                        != content_len
                    {
                        return Err(invalid("token content length mismatch"));
                    }
                    let payload = &content[68..len - 32];
                    if hash(payload) != content[36..68] {
                        return Err(invalid("invalid token content hash"));
                    }
                    Some(payload.to_vec())
                }
                _ => return Err(invalid("unknown token populated flag")),
            };
            entries.push(Entry {
                name,
                extension,
                data,
            });
        }
        if reader.take(0x66)?.iter().any(|b| *b != 0) {
            return Err(invalid("unsupported token block padding"));
        }
        offset = next;
    }
    // Canonical files contain no overlaps, hidden tails, allocation gaps or orphan blocks.
    // Reject unsupported layouts instead of silently dropping their bytes on rewrite.
    let mut end = 0;
    for (start, next) in ranges {
        if start != end {
            return Err(invalid("overlapping or unreferenced token file ranges"));
        }
        end = next;
    }
    if end != bytes.len() {
        return Err(invalid("unreferenced token file tail"));
    }
    Ok(entries)
}

fn patch(output: &mut [u8], offset: usize, value: usize) -> Result<()> {
    let value: u32 = value
        .try_into()
        .map_err(|_| invalid("token store exceeds u32 offsets"))?;
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub fn encode(entries: &[Entry]) -> Result<Vec<u8>> {
    let mut output = 3u32.to_le_bytes().to_vec();
    output.resize(0x24, 0);
    let count = entries.len().div_ceil(SLOTS).max(1);
    for group in 0..count {
        let offset = output.len();
        output.resize(
            offset
                .checked_add(BLOCK_SIZE)
                .ok_or_else(|| invalid("token store length overflow"))?,
            0,
        );
        patch(&mut output, offset, offset)?;
        for slot in 0..SLOTS {
            let empty = Entry::empty();
            let entry = entries.get(group * SLOTS + slot).unwrap_or(&empty);
            let entry_offset = offset + 8 + slot * ENTRY_SIZE;
            let mut record = Vec::new();
            length(&mut record, entry_offset)?;
            word(&mut record, u32::from(entry.data.is_some()));
            if let Some(data) = &entry.data {
                length(&mut record, output.len())?;
                length(&mut record, data.len())?;
                length(&mut record, data.len())?;
                output.extend_from_slice(&[0x55; 32]);
                length(&mut output, data.len())?;
                output.extend_from_slice(&hash(data));
                output.extend_from_slice(data);
                output.extend_from_slice(&[0xaa; 32]);
            } else {
                word(&mut record, 0);
                word(&mut record, u32::MAX);
                word(&mut record, u32::MAX);
            }
            fixed(&mut record, &entry.name, 0x82)?;
            fixed(&mut record, &entry.extension, 8)?;
            output[entry_offset..entry_offset + ENTRY_SIZE].copy_from_slice(&record);
        }
        if group + 1 < count {
            let next = output.len();
            patch(&mut output, offset + 4, next)?;
        }
        let digest = hash(&output[offset..offset + BLOCK_SIZE - 32]);
        output[offset + BLOCK_SIZE - 32..offset + BLOCK_SIZE].copy_from_slice(&digest);
    }
    let digest = file_hash(&output);
    output[4..0x24].copy_from_slice(&digest);
    Ok(output)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Metadata {
    pub name: String,
    pub values: Vec<(String, String)>,
}

impl Metadata {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        if reader.u32()? != 1 {
            return Err(invalid("unknown token metadata version"));
        }
        let len = reader.u32()? as usize;
        let name = string(reader.take(len)?)?;
        let mut values = Vec::new();
        while reader.remaining() != 0 {
            let key_len = reader.u32()? as usize;
            let value_len = reader.u32()? as usize;
            let key = string(reader.take(key_len)?)?;
            let value = string(reader.take(value_len)?)?;
            values.push((key, value));
        }
        Ok(Self { name, values })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        word(&mut output, 1);
        let name = encoded(&self.name)?;
        length(&mut output, name.len())?;
        output.extend_from_slice(&name);
        for (key, value) in &self.values {
            let key = encoded(key)?;
            let value = encoded(value)?;
            length(&mut output, key.len())?;
            length(&mut output, value.len())?;
            output.extend_from_slice(&key);
            output.extend_from_slice(&value);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const FIXTURE: &[u8] = include_bytes!("../../../tests/fixtures/tsforge/tokens-modern.bin");
    const META: &[u8] = include_bytes!("../../../tests/fixtures/tsforge/token-meta.bin");

    fn repair_hashes(bytes: &mut [u8], block: usize) {
        let digest = hash(&bytes[block..block + BLOCK_SIZE - 32]);
        bytes[block + BLOCK_SIZE - 32..block + BLOCK_SIZE].copy_from_slice(&digest);
        let digest = file_hash(bytes);
        bytes[4..36].copy_from_slice(&digest);
    }

    #[test]
    fn independent_multiblock_fixture_and_metadata_roundtrip_exactly() {
        let entries = decode(FIXTURE).unwrap();
        assert_eq!(entries.len(), SLOTS * 2);
        assert_eq!(entries[0].name, "测试😀");
        assert_eq!(entries[0].data.as_deref(), Some(META));
        assert_eq!(entries[1].name, "inactive");
        assert_eq!(entries[1].data, None);
        assert_eq!(entries[SLOTS].data.as_deref(), Some(&[][..]));
        assert_eq!(encode(&entries).unwrap(), FIXTURE);
        let meta = Metadata::decode(META).unwrap();
        assert_eq!(meta.name, "测试😀");
        assert_eq!(meta.values[0].0, meta.values[1].0);
        assert_eq!(meta.values[2], (String::new(), String::new()));
        assert_eq!(meta.encode().unwrap(), META);
    }

    #[test]
    fn hashes_cycles_offsets_and_corrupt_records_are_rejected() {
        for offset in [0, 4, 36, 44, 36 + BLOCK_SIZE + 68, FIXTURE.len() - 1] {
            let mut bad = FIXTURE.to_vec();
            bad[offset] ^= 1;
            assert!(decode(&bad).is_err());
        }
        // Recompute enclosing checksums so these exercise structural validation.
        for (offset, value) in [
            (40, 36),
            (44, 0),
            (48, 2),
            (52, u32::MAX),
            (56, u32::MAX),
            (60, 1),
        ] {
            let mut bad = FIXTURE.to_vec();
            bad[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            repair_hashes(&mut bad, 36);
            assert!(decode(&bad).is_err(), "offset {offset}");
        }
        let mut bad = FIXTURE.to_vec();
        bad[36 + BLOCK_SIZE + 68] ^= 1;
        repair_hashes(&mut bad, 36);
        assert!(
            decode(&bad)
                .unwrap_err()
                .to_string()
                .contains("content hash")
        );
        for end in [0, 35, 36, 36 + BLOCK_SIZE - 1, FIXTURE.len() - 1] {
            assert!(decode(&FIXTURE[..end]).is_err());
        }
    }

    #[test]
    fn reconstruction_is_stable_at_block_boundaries_and_preserves_changes() {
        for count in [0, 1, SLOTS - 1, SLOTS, SLOTS + 1, SLOTS * 2] {
            let entries = vec![
                Entry {
                    name: "x".into(),
                    extension: "xml".into(),
                    data: Some(vec![7; 19])
                };
                count
            ];
            let bytes = encode(&entries).unwrap();
            let decoded = decode(&bytes).unwrap();
            assert_eq!(&decoded[..count], &entries);
            assert_eq!(encode(&decoded).unwrap(), bytes);
        }
        let mut entries = decode(FIXTURE).unwrap();
        entries[0].data = Some(vec![42; 100]);
        let decoded = decode(&encode(&entries).unwrap()).unwrap();
        assert_eq!(decoded, entries);
    }

    #[test]
    fn invalid_strings_and_metadata_fail_instead_of_truncating() {
        let mut entry = Entry::empty();
        entry.name = "😀".repeat(33);
        assert!(encode(&[entry.clone()]).is_err());
        entry.name = "a\0b".into();
        assert!(encode(&[entry]).is_err());
        assert!(string(&[0, 0, 1, 0]).is_err());
        assert!(string(&[0, 0xd8, 0, 0]).is_err());
        let mut bad = META.to_vec();
        bad[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Metadata::decode(&bad).is_err());
        for end in 0..META.len() {
            if let Ok(meta) = Metadata::decode(&META[..end]) {
                assert_eq!(meta.encode().unwrap(), &META[..end]);
            }
        }
    }
}
