//! Single-file MSZIP cabinets; MS-CAB 1.3, no spanning or optional checksums.
#![cfg_attr(not(test), allow(dead_code))]
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};
const CHUNK: usize = 32768;
const MAX: u64 = 512 * 1024 * 1024;
fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}
/// Publish only a complete cabinet. Original logs and existing destinations survive failure.
pub fn compress(source: &Path, destination: &Path, name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        || name == "."
        || name == ".."
    {
        return Err(invalid("cabinet entry must be a plain ASCII filename"));
    }
    let mut input = File::open(source)?;
    let metadata = input.metadata()?;
    let length = metadata.len();
    if !metadata.is_file() || length > MAX {
        return Err(invalid("cabinet input must be a file of at most 512 MiB"));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| invalid("cabinet destination has no parent"))?;
    let mut output = tempfile::NamedTempFile::new_in(parent)?;
    let blocks = length.div_ceil(CHUNK as u64) as u16;
    let data_offset = 44 + 16 + name.len() as u32 + 1;
    // CFHEADER, CFFOLDER, CFFILE. Archive timestamps are the DOS epoch.
    output.write_all(b"MSCF")?;
    for value in [0u32, 0, 0, 44, 0] {
        output.write_all(&value.to_le_bytes())?;
    }
    output.write_all(&[3, 1])?;
    for value in [1u16, 1, 0, 0, 0] {
        output.write_all(&value.to_le_bytes())?;
    }
    output.write_all(&data_offset.to_le_bytes())?;
    output.write_all(&blocks.to_le_bytes())?;
    output.write_all(&1u16.to_le_bytes())?; // MSZIP
    output.write_all(&(length as u32).to_le_bytes())?;
    output.write_all(&0u32.to_le_bytes())?;
    for value in [0u16, 0x21, 0, 0x20] {
        output.write_all(&value.to_le_bytes())?;
    }
    output.write_all(name.as_bytes())?;
    output.write_all(&[0])?;
    let mut remaining = length;
    let mut buffer = [0u8; CHUNK];
    while remaining > 0 {
        let count = remaining.min(CHUNK as u64) as usize;
        input.read_exact(&mut buffer[..count])?;
        // Independent raw DEFLATE blocks are valid MSZIP streams; no dictionary references.
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&buffer[..count])?;
        let data = encoder.finish()?;
        let compressed =
            u16::try_from(data.len() + 2).map_err(|_| invalid("MSZIP block too large"))?;
        output.write_all(&0u32.to_le_bytes())?; // Optional CFDATA checksum omitted.
        output.write_all(&compressed.to_le_bytes())?;
        output.write_all(&(count as u16).to_le_bytes())?;
        output.write_all(b"CK")?;
        output.write_all(&data)?;
        remaining -= count as u64;
    }
    if input.read(&mut buffer[..1])? != 0 {
        return Err(invalid("cabinet source grew while reading"));
    }
    let size = u32::try_from(output.stream_position()?)
        .map_err(|_| invalid("cabinet exceeds format limit"))?;
    output.seek(SeekFrom::Start(8))?;
    output.write_all(&size.to_le_bytes())?;
    output.flush()?;
    output.as_file().sync_all()?;
    output.persist_noclobber(destination).map_err(|e| e.error)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cabinet_blocks_roundtrip_empty_boundary_and_multiple_blocks() {
        let temp = tempfile::tempdir().unwrap();
        for length in [0, 1, CHUNK, CHUNK + 1, CHUNK * 3 + 51] {
            let bytes: Vec<_> = (0..length)
                .map(|i| ((i * 173 + i / 7) % 256) as u8)
                .collect();
            let source = temp.path().join("source");
            let cab = temp.path().join(format!("{length}.cab"));
            std::fs::write(&source, &bytes).unwrap();
            compress(&source, &cab, "repair.log").unwrap();
            let data = std::fs::read(&cab).unwrap();
            assert_eq!(&data[..4], b"MSCF");
            assert_eq!(
                u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize,
                data.len()
            );
            let mut at = u32::from_le_bytes(data[36..40].try_into().unwrap()) as usize;
            let mut decoded = vec![];
            while at < data.len() {
                let compressed =
                    u16::from_le_bytes(data[at + 4..at + 6].try_into().unwrap()) as usize;
                let size = u16::from_le_bytes(data[at + 6..at + 8].try_into().unwrap()) as usize;
                assert_eq!(&data[at + 8..at + 10], b"CK");
                let mut block = vec![];
                flate2::read::DeflateDecoder::new(&data[at + 10..at + 8 + compressed])
                    .read_to_end(&mut block)
                    .unwrap();
                assert_eq!(block.len(), size);
                decoded.extend(block);
                at += 8 + compressed;
            }
            assert_eq!(decoded, bytes);
            assert_eq!(
                compress(&source, &cab, "repair.log").unwrap_err().kind(),
                io::ErrorKind::AlreadyExists
            );
            assert_eq!(std::fs::read(&source).unwrap(), bytes);
            if let Some(root) = std::env::var_os("MAS_CAB_FIXTURE_DIR") {
                std::fs::copy(&cab, Path::new(&root).join(format!("{length}.cab"))).unwrap();
                std::fs::write(Path::new(&root).join(format!("{length}.raw")), &bytes).unwrap();
            }
            #[cfg(windows)]
            {
                let extracted = temp.path().join(format!("expanded-{length}.log"));
                let status = std::process::Command::new(
                    crate::native::platform::system_file("expand.exe").unwrap(),
                )
                .arg(&cab)
                .arg(&extracted)
                .status()
                .unwrap();
                assert!(status.success());
                assert_eq!(std::fs::read(extracted).unwrap(), bytes);
            }
        }
        let source = temp.path().join("source");
        assert!(compress(&source, &temp.path().join("bad.cab"), "../unsafe").is_err());
        assert!(!temp.path().join("bad.cab").exists());
    }
}
