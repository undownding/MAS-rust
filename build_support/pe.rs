//! Minimal bounded PE export reader, shared by build-time verification and tests.
use std::collections::BTreeMap;
pub struct Exports {
    pub machine: u16,
    pub names: BTreeMap<String, Option<String>>,
}
fn u16_at(data: &[u8], offset: usize) -> Result<u16, String> {
    let b = data
        .get(offset..offset.checked_add(2).ok_or("offset overflow")?)
        .ok_or("truncated PE")?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}
fn u32_at(data: &[u8], offset: usize) -> Result<u32, String> {
    let b = data
        .get(offset..offset.checked_add(4).ok_or("offset overflow")?)
        .ok_or("truncated PE")?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
pub fn read(data: &[u8]) -> Result<Exports, String> {
    if data.get(..2) != Some(b"MZ") {
        return Err("not a PE file".into());
    }
    let pe = u32_at(data, 0x3c)? as usize;
    if data.get(pe..pe.checked_add(4).ok_or("offset overflow")?) != Some(b"PE\0\0") {
        return Err("invalid PE signature".into());
    }
    let machine = u16_at(data, pe + 4)?;
    let sections = u16_at(data, pe + 6)? as usize;
    let optional_size = u16_at(data, pe + 20)? as usize;
    let optional = pe + 24;
    let directory = match u16_at(data, optional)? {
        0x10b => optional + 96,
        0x20b => optional + 112,
        _ => return Err("unknown PE optional header".into()),
    };
    let export_rva = u32_at(data, directory)?;
    let export_size = u32_at(data, directory + 4)?;
    let export_end = export_rva
        .checked_add(export_size)
        .ok_or("export range overflow")?;
    let headers = optional + optional_size;
    let offset = |rva: u32| -> Result<usize, String> {
        for index in 0..sections {
            let section = headers + index * 40;
            let start = u32_at(data, section + 12)?;
            let size = u32_at(data, section + 16)?;
            if rva >= start && rva - start < size {
                let file = u32_at(data, section + 20)? as usize + (rva - start) as usize;
                if file < data.len() {
                    return Ok(file);
                }
            }
        }
        Err("RVA outside file-backed sections".into())
    };
    let text = |rva: u32| -> Result<String, String> {
        let start = offset(rva)?;
        let rest = &data[start..];
        let end = rest
            .iter()
            .position(|b| *b == 0)
            .ok_or("unterminated PE string")?;
        std::str::from_utf8(&rest[..end])
            .map(str::to_owned)
            .map_err(|e| e.to_string())
    };
    let exports = offset(export_rva)?;
    let count = u32_at(data, exports + 24)? as usize;
    let functions_count = u32_at(data, exports + 20)? as usize;
    if count > 65536 || functions_count > 65536 {
        return Err("oversized export table".into());
    }
    let functions = offset(u32_at(data, exports + 28)?)?;
    let names = offset(u32_at(data, exports + 32)?)?;
    let ordinals = offset(u32_at(data, exports + 36)?)?;
    let mut result = BTreeMap::new();
    for i in 0..count {
        let name = text(u32_at(data, names + i * 4)?)?;
        let ordinal = u16_at(data, ordinals + i * 2)? as usize;
        if ordinal >= functions_count {
            return Err("invalid ordinal".into());
        }
        let rva = u32_at(data, functions + ordinal * 4)?;
        let target = if (export_rva..export_end).contains(&rva) {
            Some(text(rva)?)
        } else {
            offset(rva)?;
            None
        };
        if result.insert(name, target).is_some() {
            return Err("duplicate export".into());
        }
    }
    Ok(Exports {
        machine,
        names: result,
    })
}
pub fn verify(data: &[u8], machine: u16, definition: &str) -> Result<(), String> {
    let exports = read(data)?;
    if exports.machine != machine {
        return Err("wrong DLL architecture".into());
    }
    for line in definition.lines() {
        let Some((name, target)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        let target = target.trim();
        match exports.names.get(name) {
            Some(Some(actual)) if target.starts_with("SPPCS.") && actual == target => {}
            Some(None) if target == "SLGetLicensingStatusInformationHook" => {}
            _ => return Err(format!("incorrect export {name}; expected {target}")),
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_truncated_or_invalid_images() {
        for bytes in [vec![], vec![0; 64], b"MZ".to_vec()] {
            assert!(read(&bytes).is_err());
        }
        let mut bytes = vec![0; 64];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(read(&bytes).is_err());
        assert!(verify(&bytes, 0x8664, "EXPORTS").is_err());
    }
}
