//! Plaintext physical-store containers. Authentication belongs to the envelope layer.
use super::binary::{Reader, align, invalid, length, word};
use std::io::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Vista,
    Win7,
    Modern,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub kind: u32,
    pub flags: u32,
    pub unknown: u32,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub name: Vec<u8>,
    pub blocks: Vec<Block>,
}

/// Group and key order are retained, including duplicate/empty keys.
/// Raw names avoid lossy UTF-16 decoding during load/save.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Store {
    pub header: [u8; 8],
    pub groups: Vec<Vec<Key>>,
    pub blocks: Vec<Block>,
    pub format: Format,
}

impl Store {
    pub fn decode(bytes: &[u8], format: Format) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let header = reader.take(8)?.try_into().unwrap();
        let mut groups = Vec::new();
        let mut blocks = Vec::new();
        while reader.remaining() > 0 {
            if format == Format::Modern {
                let count = reader.u32()? as usize;
                // Every key requires at least two length/count words.
                if count > reader.remaining() / 8 {
                    return Err(invalid("physical-store key count exceeds input"));
                }
                let mut keys = Vec::new();
                for _ in 0..count {
                    let len = reader.u32()? as usize;
                    let name = reader.take(len)?.to_vec();
                    let count = reader.u32()? as usize;
                    reader.align(4)?;
                    if count > reader.remaining() / 20 {
                        return Err(invalid("physical-store block count exceeds input"));
                    }
                    let mut values = Vec::new();
                    for _ in 0..count {
                        values.push(read_block(&mut reader, format)?);
                    }
                    keys.push(Key {
                        name,
                        blocks: values,
                    });
                }
                groups.push(keys);
            } else {
                blocks.push(read_block(&mut reader, format)?);
            }
        }
        Ok(Self {
            header,
            groups,
            blocks,
            format,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut output = self.header.to_vec();
        match self.format {
            Format::Modern => {
                if !self.blocks.is_empty() {
                    return Err(invalid("modern store cannot contain ungrouped blocks"));
                }
                for group in &self.groups {
                    length(&mut output, group.len())?;
                    for key in group {
                        length(&mut output, key.name.len())?;
                        output.extend_from_slice(&key.name);
                        length(&mut output, key.blocks.len())?;
                        align(&mut output, 4);
                        for block in &key.blocks {
                            write_block(&mut output, block, self.format)?;
                        }
                    }
                }
            }
            Format::Vista | Format::Win7 => {
                if !self.groups.is_empty() {
                    return Err(invalid("legacy store cannot contain grouped blocks"));
                }
                for block in &self.blocks {
                    write_block(&mut output, block, self.format)?;
                }
            }
        }
        Ok(output)
    }
}

fn read_block(reader: &mut Reader<'_>, format: Format) -> Result<Block> {
    let kind = reader.u32()?;
    let flags = reader.u32()?;
    let key_len = if format == Format::Win7 {
        reader.u32()? as usize
    } else {
        0
    };
    let value_len = reader.u32()? as usize;
    let data_len = reader.u32()? as usize;
    let unknown = if format == Format::Modern {
        reader.u32()?
    } else {
        0
    };
    let key = reader.take(key_len)?.to_vec();
    let value = reader.take(value_len)?.to_vec();
    let data = reader.take(data_len)?.to_vec();
    reader.align(4)?;
    Ok(Block {
        kind,
        flags,
        unknown,
        key,
        value,
        data,
    })
}

fn write_block(output: &mut Vec<u8>, block: &Block, format: Format) -> Result<()> {
    if (format != Format::Win7 && !block.key.is_empty())
        || (format != Format::Modern && block.unknown != 0)
    {
        return Err(invalid(
            "block fields not representable in selected store format",
        ));
    }
    word(output, block.kind);
    word(output, block.flags);
    if format == Format::Win7 {
        length(output, block.key.len())?;
    }
    length(output, block.value.len())?;
    length(output, block.data.len())?;
    if format == Format::Modern {
        word(output, block.unknown);
    }
    output.extend_from_slice(&block.key);
    output.extend_from_slice(&block.value);
    output.extend_from_slice(&block.data);
    align(output, 4);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> [(Format, &'static [u8]); 3] {
        [
            (
                Format::Vista,
                include_bytes!("../../../tests/fixtures/tsforge/store-vista.bin"),
            ),
            (
                Format::Win7,
                include_bytes!("../../../tests/fixtures/tsforge/store-win7.bin"),
            ),
            (
                Format::Modern,
                include_bytes!("../../../tests/fixtures/tsforge/store-modern.bin"),
            ),
        ]
    }

    #[test]
    fn independent_vectors_preserve_headers_groups_and_unknown_fields() {
        for (format, bytes) in fixtures() {
            let store = Store::decode(bytes, format).unwrap();
            assert_eq!(&store.header, b"PREHEAD!");
            let block = if format == Format::Modern {
                assert_eq!(store.groups.len(), 2);
                assert_eq!(store.groups[0][0].name, store.groups[0][1].name);
                assert!(store.groups[1].is_empty());
                assert_eq!(store.groups[0][0].blocks[0].unknown, 0xaabbccdd);
                &store.groups[0][0].blocks[0]
            } else {
                assert_eq!(store.blocks.len(), 2);
                &store.blocks[0]
            };
            assert_eq!(block.kind, 0xdeadbeef);
            assert_eq!(block.flags, 0x87654321);
            assert_eq!(block.data, b"abc");
            assert_eq!(store.encode().unwrap(), bytes);
        }
    }

    #[test]
    fn malformed_lengths_and_partial_records_fail_without_panicking() {
        for (format, bytes) in fixtures() {
            for end in 0..8 {
                assert!(Store::decode(&bytes[..end], format).is_err());
            }
            let mut bad = bytes.to_vec();
            if format == Format::Modern {
                bad[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
            } else {
                bad[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
            }
            assert!(Store::decode(&bad, format).is_err());
            for extra in 1..4 {
                let mut bad = bytes.to_vec();
                bad.extend(vec![0; extra]);
                assert!(Store::decode(&bad, format).is_err());
            }
            // Every prefix either fails or is itself a complete valid container.
            for end in 8..bytes.len() {
                if let Ok(store) = Store::decode(&bytes[..end], format) {
                    assert_eq!(store.encode().unwrap(), &bytes[..end]);
                }
            }
        }
    }

    #[test]
    fn edits_keep_adjacent_records_and_realign_data() {
        for (format, bytes) in fixtures() {
            let mut store = Store::decode(bytes, format).unwrap();
            if format == Format::Modern {
                store.groups[0][0].blocks[0].data = vec![1; 17];
            } else {
                store.blocks[0].data = vec![1; 17];
            }
            assert_eq!(
                Store::decode(&store.encode().unwrap(), format).unwrap(),
                store
            );
        }
    }
}
