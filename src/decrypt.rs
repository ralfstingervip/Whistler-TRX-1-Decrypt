use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::cipher;
use crate::error::{err, Result};
use crate::pe;

pub struct Report {
    pub platform: u8,
    pub version: u8,
    /// False when bit 31 of the length is set or the platform has no key.
    pub ciphered: bool,
    pub image: Vec<u8>,
}

impl Report {
    pub fn model_line(&self) -> String {
        format!("{} (platform 0x{:02X})", model_name(self.platform), self.platform)
    }

    /// High nibble, dot, low nibble: 0x59 is 5.9.
    pub fn version_line(&self) -> String {
        format!("{}.{}", self.version >> 4, self.version & 0x0F)
    }

    pub fn cipher_line(&self) -> &'static str {
        if self.ciphered {
            "RC4-drop256"
        } else {
            "none"
        }
    }
}

pub fn decrypt_pe(pe_bytes: &[u8]) -> Result<Report> {
    let fw = pe::locate_firmware(pe_bytes)?;
    // Without the cipher the updater sends the salt too, so the output does as well.
    let (ciphered, image) = match fw.key {
        Some(key) if !fw.cipher_off => (true, cipher::decrypt(fw.payload, &key)),
        _ => (false, fw.payload.to_vec()),
    };
    Ok(Report {
        platform: fw.platform,
        version: fw.version,
        ciphered,
        image,
    })
}

/// Model names as the updater lists them for each platform byte.
pub fn model_name(platform: u8) -> &'static str {
    match platform {
        0xE0 => "TRX-2e",
        0xE1 => "TRX-1e",
        0xE2 => "TRX-2",
        0xE3 => "TRX-1",
        0xE4 => "PRO-668",
        0xE6 => "WS1080/1088",
        0xE7 => "PRO-651/652",
        0xE8 => "WS1040/1065",
        0xEA => "WS1095/1098",
        0xEE => "PSR-800",
        _ => "unknown",
    }
}

pub fn default_output(input: &Path) -> Result<PathBuf> {
    let stem = input
        .file_stem()
        .ok_or_else(|| err("input path has no file name"))?;
    let mut name = OsString::from(stem);
    name.push(".bin");
    let mut out = input.to_path_buf();
    out.set_file_name(name);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_lines() {
        let report = Report {
            platform: 0xE3,
            version: 0x59,
            ciphered: true,
            image: Vec::new(),
        };
        assert_eq!(report.model_line(), "TRX-1 (platform 0xE3)");
        assert_eq!(report.version_line(), "5.9");
        assert_eq!(report.cipher_line(), "RC4-drop256");
        assert_eq!(model_name(0xE5), "unknown");
    }

    #[test]
    fn default_output_swaps_the_extension() {
        let out = default_output(Path::new("x/CPUUpdater_TRX1_U5.9.exe")).unwrap();
        assert_eq!(out, Path::new("x/CPUUpdater_TRX1_U5.9.bin"));
    }
}
