use std::io::{Error, ErrorKind, Result};

pub fn invalid(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| invalid("length overflow"))?;
        let data = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| invalid("truncated TSforge record"))?;
        self.position = end;
        Ok(data)
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn align(&mut self, alignment: usize) -> Result<()> {
        let padding = self.take(self.position.wrapping_neg() & (alignment - 1))?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(invalid("unsupported nonzero record padding"));
        }
        Ok(())
    }
}

pub fn word(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

pub fn length(output: &mut Vec<u8>, value: usize) -> Result<()> {
    word(
        output,
        value
            .try_into()
            .map_err(|_| invalid("record exceeds u32 length"))?,
    );
    Ok(())
}

pub fn align(output: &mut Vec<u8>, alignment: usize) {
    let padding = output.len().wrapping_neg() & (alignment - 1);
    output.resize(output.len() + padding, 0);
}

/// CRC-32/BZIP2, not the reflected CRC used by ZIP files.
#[cfg(test)]
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte) << 24;
        for _ in 0..8 {
            crc = (crc << 1)
                ^ if crc & 0x8000_0000 != 0 {
                    0x04c1_1db7
                } else {
                    0
                };
        }
    }
    !crc
}

#[test]
fn crc_known_check_value() {
    assert_eq!(crc32(b"123456789"), 0xfc89_1918);
    assert_eq!(crc32(b""), 0);
}

#[test]
fn padding_is_bounded_and_never_silently_discarded() {
    let mut reader = Reader::new(&[1, 0, 0, 0]);
    reader.take(1).unwrap();
    reader.align(4).unwrap();
    assert_eq!(reader.remaining(), 0);
    let mut reader = Reader::new(&[1, 0, 2, 0]);
    reader.take(1).unwrap();
    assert!(reader.align(4).is_err());
    let mut reader = Reader::new(&[1, 0]);
    reader.take(1).unwrap();
    assert!(reader.align(4).is_err());
    assert!(Reader::new(&[0]).take(usize::MAX).is_err());
}
