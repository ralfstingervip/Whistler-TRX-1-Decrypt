use crate::error::{err, Result};

/// Size of the static key and of the salt in front of the image.
pub const KEY_LEN: usize = 64;

/// Platform bytes accepted in the header.
const PLATFORMS: std::ops::RangeInclusive<u8> = 0xE0..=0xEE;

struct Section {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_ptr: u32,
}

struct Image<'a> {
    bytes: &'a [u8],
    image_base: u32,
    size_of_image: u32,
    sections: Vec<Section>,
}

impl<'a> Image<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
            return Err(err("not a PE file"));
        }
        let e_lfanew = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
        if bytes.get(e_lfanew..e_lfanew.saturating_add(4)) != Some(b"PE\0\0".as_ref()) {
            return Err(err("not a PE file"));
        }
        let coff = e_lfanew + 4;
        need(bytes, coff, 20)?;
        let nsec = u16_at(bytes, coff + 2) as usize;
        let optsz = u16_at(bytes, coff + 16) as usize;
        let opt = coff + 20;
        need(bytes, opt, optsz)?;
        if optsz < 2 || u16_at(bytes, opt) != 0x10B {
            return Err(err("expected a PE32 updater"));
        }
        if optsz < 120 {
            return Err(err("PE32 optional header is too small"));
        }
        let image_base = u32_at(bytes, opt + 28);
        let size_of_image = u32_at(bytes, opt + 56);
        let sec_off = opt + optsz;
        need(bytes, sec_off, nsec * 40)?;
        let mut sections = Vec::with_capacity(nsec);
        for i in 0..nsec {
            let off = sec_off + i * 40;
            let name_raw = &bytes[off..off + 8];
            let end = name_raw.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_raw[..end]).into_owned();
            sections.push(Section {
                name,
                virtual_size: u32_at(bytes, off + 8),
                virtual_address: u32_at(bytes, off + 12),
                raw_size: u32_at(bytes, off + 16),
                raw_ptr: u32_at(bytes, off + 20),
            });
        }
        Ok(Self {
            bytes,
            image_base,
            size_of_image,
            sections,
        })
    }

    /// The section's raw bytes and the VA of its first byte.
    fn section(&self, name: &str) -> Result<(u64, &'a [u8])> {
        let matches: Vec<&Section> = self.sections.iter().filter(|s| s.name == name).collect();
        if matches.len() != 1 {
            return Err(err(format!("section {name} was not found once")));
        }
        let s = matches[0];
        let start = s.raw_ptr as u64;
        let end = start + s.raw_size as u64;
        if s.raw_size == 0 || end > self.bytes.len() as u64 {
            return Err(err(format!("section {name} is outside the file")));
        }
        let va = self.image_base as u64 + s.virtual_address as u64;
        Ok((va, &self.bytes[start as usize..end as usize]))
    }

    /// `len` bytes at `va`, all inside the raw data of one section.
    fn read_va(&self, va: u64, len: usize) -> Option<&'a [u8]> {
        if va < self.image_base as u64 {
            return None;
        }
        let rva_u = va - self.image_base as u64;
        if rva_u > u32::MAX as u64 {
            return None;
        }
        let rva = rva_u as u32;
        if rva as u64 + len as u64 > self.size_of_image as u64 {
            return None;
        }
        for s in &self.sections {
            let span = s.virtual_size.max(s.raw_size);
            let begin = s.virtual_address as u64;
            let end = begin + span as u64;
            if (rva as u64) >= begin && (rva as u64) < end {
                let delta = (rva - s.virtual_address) as u64;
                if delta + len as u64 > s.raw_size as u64 {
                    return None;
                }
                let start = s.raw_ptr as u64 + delta;
                let stop = start + len as u64;
                if stop > self.bytes.len() as u64 {
                    return None;
                }
                return Some(&self.bytes[start as usize..stop as usize]);
            }
        }
        None
    }
}

fn need(bytes: &[u8], off: usize, n: usize) -> Result<()> {
    if off.checked_add(n).map(|end| end <= bytes.len()) == Some(true) {
        Ok(())
    } else {
        Err(err("PE header is truncated"))
    }
}

fn u16_at(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([bytes[off], bytes[off + 1]])
}

fn u32_at(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

/// The firmware header and payload, and the key the updater would pick for it.
pub struct Firmware<'a> {
    pub platform: u8,
    pub version: u8,
    /// Bit 31 of the length dword. When set the updater sends the payload as stored.
    pub cipher_off: bool,
    /// Salt, then the image. The image size is the low 24 bits of the length dword.
    pub payload: &'a [u8],
    /// None when the key-select function returns NULL for this platform.
    pub key: Option<[u8; KEY_LEN]>,
}

/// The key-select function, as MSVC compiled it:
///
/// ```text
/// A1 hh hh hh hh        mov  eax, [header]        ; platform byte is the low byte
/// 25 FF 00 00 00        and  eax, 0FFh
/// 05 bb bb bb bb        add  eax, -first_platform
/// 83 F8 nn              cmp  eax, last_index
/// 77 dd                 ja   default
/// FF 24 85 tt tt tt tt  jmp  [table + eax*4]
/// ```
///
/// `None` bytes are operands. The pattern must match once in `.text`.
const KEY_SELECT: [Option<u8>; 27] = {
    const W: Option<u8> = None;
    [
        Some(0xA1), W, W, W, W,
        Some(0x25), Some(0xFF), Some(0x00), Some(0x00), Some(0x00),
        Some(0x05), W, W, W, W,
        Some(0x83), Some(0xF8), W,
        Some(0x77), W,
        Some(0xFF), Some(0x24), Some(0x85), W, W, W, W,
    ]
};

pub fn locate_firmware(pe: &[u8]) -> Result<Firmware<'_>> {
    let image = Image::parse(pe)?;
    let (text_va, text) = image.section(".text")?;
    let hits: Vec<usize> = (0..text.len().saturating_sub(KEY_SELECT.len() - 1))
        .filter(|&i| matches_at(text, i))
        .collect();
    if hits.len() != 1 {
        return Err(err(format!(
            "expected one key-select function in .text, found {}",
            hits.len()
        )));
    }
    let at = hits[0];
    let code = &text[at..at + KEY_SELECT.len()];
    let header_va = u32_at(code, 1) as u64;
    let first_platform = 0u32.wrapping_sub(u32_at(code, 11));
    let last_index = code[17] as usize;
    // `ja` is relative to the next instruction, the `jmp` at offset 20.
    let default_va = (text_va + at as u64 + 20).wrapping_add(code[19] as i8 as i64 as u64);
    let table_va = u32_at(code, 23) as u64;

    let header = image
        .read_va(header_va, 8)
        .ok_or_else(|| err(format!("firmware header {header_va:#x} is outside the image")))?;
    let platform = header[0];
    let version = header[1];
    if !PLATFORMS.contains(&platform) {
        return Err(err(format!("platform byte 0x{platform:02X} is not a Whistler model")));
    }
    let raw_len = u32_at(header, 4);
    let length = (raw_len & 0x00FF_FFFF) as usize;
    let cipher_off = raw_len & 0x8000_0000 != 0;
    let payload = image
        .read_va(header_va + 8, KEY_LEN + length)
        .ok_or_else(|| err(format!("payload of {length} bytes does not fit in its section")))?;

    // Out-of-range platforms take the `ja` branch. The rest go through the table.
    let index = (platform as u32).wrapping_sub(first_platform) as usize;
    let target = if index <= last_index {
        let slot = image
            .read_va(table_va + index as u64 * 4, 4)
            .ok_or_else(|| err(format!("jump table {table_va:#x} is outside the image")))?;
        u32_at(slot, 0) as u64
    } else {
        default_va
    };
    let key = match key_stub(&image, target)? {
        None => None,
        Some(key_va) => {
            let bytes = image
                .read_va(key_va, KEY_LEN)
                .ok_or_else(|| err(format!("static key {key_va:#x} is outside the image")))?;
            let mut key = [0u8; KEY_LEN];
            key.copy_from_slice(bytes);
            Some(key)
        }
    };

    Ok(Firmware {
        platform,
        version,
        cipher_off,
        payload,
        key,
    })
}

fn matches_at(text: &[u8], at: usize) -> bool {
    KEY_SELECT
        .iter()
        .zip(&text[at..])
        .all(|(p, &b)| p.is_none_or(|p| p == b))
}

/// Each switch case is `mov eax, key; ret` (`B8 imm32 C3`) or `xor eax, eax; ret`
/// (`33 C0 C3`), which is the NULL key.
fn key_stub(image: &Image<'_>, va: u64) -> Result<Option<u64>> {
    if let Some([0x33, 0xC0, 0xC3]) = image.read_va(va, 3) {
        return Ok(None);
    }
    match image.read_va(va, 6) {
        Some(&[0xB8, a, b, c, d, 0xC3]) => Ok(Some(u32::from_le_bytes([a, b, c, d]) as u64)),
        Some(_) => Err(err(format!("key-select case {va:#x} is not a key return"))),
        None => Err(err(format!("key-select case {va:#x} is outside the image"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_files_that_are_not_pe() {
        assert!(locate_firmware(b"").is_err());
        assert!(locate_firmware(b"MZ").is_err());
        let mut junk = vec![0x5Au8; 4096];
        junk[0..2].copy_from_slice(b"MZ");
        junk[0x3C..0x40].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        assert!(locate_firmware(&junk).is_err());
    }

    #[test]
    fn pattern_matches_the_compiled_switch() {
        let code = [
            0xA1, 0x18, 0xA6, 0x41, 0x00, 0x25, 0xFF, 0x00, 0x00, 0x00, 0x05, 0x20, 0xFF, 0xFF,
            0xFF, 0x83, 0xF8, 0x0A, 0x77, 0x2B, 0xFF, 0x24, 0x85, 0xD4, 0x14, 0x40, 0x00,
        ];
        assert!(matches_at(&code, 0));
        let mut other = code;
        other[5] = 0x0F;
        assert!(!matches_at(&other, 0));
    }
}
