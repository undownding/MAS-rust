use super::binary::{Reader, align, crc32, invalid, length, word};
use std::io::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Vista,
    Modern,
}

/// Unknown types and raw keys survive decoding; duplicate keys retain their order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub kind: u32,
    pub reserved: u32,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

impl Block {
    fn checksum(&self, format: Format) -> Result<u32> {
        if format == Format::Vista {
            return Ok(crc32(&self.value));
        }
        let mut bytes = Vec::new();
        word(&mut bytes, 0);
        word(&mut bytes, self.kind);
        length(&mut bytes, self.key.len())?;
        length(&mut bytes, self.value.len())?;
        bytes.extend_from_slice(&self.key);
        bytes.extend_from_slice(&self.value);
        Ok(crc32(&bytes))
    }
}

pub fn decode(bytes: &[u8], format: Format) -> Result<Vec<Block>> {
    let mut reader = Reader::new(bytes);
    let mut blocks = Vec::new();
    while reader.remaining() != 0 {
        let (expected, kind, reserved, key_len, value_len) = match format {
            Format::Vista => {
                let kind = reader.u32()?;
                let reserved = reader.u32()?;
                let key_len = reader.u32()?;
                let value_len = reader.u32()?;
                (reader.u32()?, kind, reserved, key_len, value_len)
            }
            Format::Modern => {
                let expected = reader.u32()?;
                let kind = reader.u32()?;
                (expected, kind, 0, reader.u32()?, reader.u32()?)
            }
        };
        // Bounds checked before allocating; attacker-controlled lengths never set capacity.
        let key = reader.take(key_len as usize)?.to_vec();
        if format == Format::Modern {
            reader.align(8)?;
        }
        let value = reader.take(value_len as usize)?.to_vec();
        if format == Format::Modern {
            reader.align(8)?;
        }
        let block = Block {
            kind,
            reserved,
            key,
            value,
        };
        if block.checksum(format)? != expected {
            return Err(invalid("invalid variable-bag CRC"));
        }
        blocks.push(block);
    }
    Ok(blocks)
}

pub fn encode(blocks: &[Block], format: Format) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    for block in blocks {
        let crc = block.checksum(format)?;
        match format {
            Format::Vista => {
                word(&mut output, block.kind);
                word(&mut output, block.reserved);
                length(&mut output, block.key.len())?;
                length(&mut output, block.value.len())?;
                word(&mut output, crc);
            }
            Format::Modern => {
                if block.reserved != 0 {
                    return Err(invalid("modern bag has no reserved field"));
                }
                word(&mut output, crc);
                word(&mut output, block.kind);
                length(&mut output, block.key.len())?;
                length(&mut output, block.value.len())?;
            }
        }
        output.extend_from_slice(&block.key);
        if format == Format::Modern {
            align(&mut output, 8);
        }
        output.extend_from_slice(&block.value);
        if format == Format::Modern {
            align(&mut output, 8);
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> [(Format, &'static [u8]); 2] {
        [
            (
                Format::Vista,
                include_bytes!("../../../tests/fixtures/tsforge/bag-vista.bin"),
            ),
            (
                Format::Modern,
                include_bytes!("../../../tests/fixtures/tsforge/bag-modern.bin"),
            ),
        ]
    }

    #[test]
    fn independent_vectors_preserve_unknown_and_duplicate_records() {
        for (format, bytes) in fixtures() {
            let blocks = decode(bytes, format).unwrap();
            assert_eq!(blocks.len(), 3);
            assert_eq!(blocks[0].kind, 0xdeadbeef);
            assert_eq!(blocks[0].key, blocks[1].key);
            assert_eq!(blocks[0].value, b"123456789");
            assert!(blocks[2].key.is_empty());
            assert!(blocks[2].value.is_empty());
            assert_eq!(encode(&blocks, format).unwrap(), bytes);
        }
    }

    #[test]
    fn rejects_corruption_truncation_and_hostile_lengths() {
        for (format, bytes) in fixtures() {
            let first_end = if format == Format::Vista { 33 } else { 40 };
            for end in 1..first_end {
                assert!(
                    decode(&bytes[..end], format).is_err(),
                    "{format:?} length {end}"
                );
            }
            let mut corrupt = bytes.to_vec();
            corrupt[24] ^= 1;
            assert!(decode(&corrupt, format).is_err());
            let mut oversized = bytes.to_vec();
            oversized[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(decode(&oversized, format).is_err());
            let mut trailing = bytes.to_vec();
            trailing.push(0);
            assert!(decode(&trailing, format).is_err());
        }
    }

    #[test]
    fn edits_recompute_crc_and_empty_bags_are_valid() {
        for (format, bytes) in fixtures() {
            let mut blocks = decode(bytes, format).unwrap();
            blocks[0].value = vec![0xff; 19];
            assert_eq!(
                decode(&encode(&blocks, format).unwrap(), format).unwrap(),
                blocks
            );
            assert!(decode(&[], format).unwrap().is_empty());
        }
    }
}
