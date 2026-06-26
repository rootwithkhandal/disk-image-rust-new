use crate::{ingest::MemoryDump, translate::translate_virtual_address, Result};
use regex::bytes::Regex;
use byteorder::ByteOrder;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum OsFamily {
    Windows,
    Linux,
    MacOs,
    Unknown,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OsProfile {
    pub family: OsFamily,
    pub architecture: String,
    pub kernel_version: String,
    pub build_number: Option<u32>,
    pub kernel_base: Option<u64>,
    pub kernel_dtb: u64, // CR3
}

impl OsProfile {
    /// Attempts to auto-detect the OS profile from the memory dump
    pub fn detect(dump: &MemoryDump) -> Result<Self> {
        let mut family = OsFamily::Unknown;
        let mut kernel_version = "Unknown".to_string();
        let mut build_number = None;
        let kernel_base = None;
        let mut kernel_dtb = 0;

        // 1. Try to check if Windows Crash Dump header contained DTB
        if dump.format == crate::ingest::DumpFormat::WindowsCrashDump {
            family = OsFamily::Windows;
            // Complete memory dump header has the DTB at 0x10 (or 0x5c for 32-bit). Let's extract it if present.
            // Check signature PAGEDU64
            let mut header_buf = [0u8; 32];
            if dump.read_physical(0, &mut header_buf).is_ok() {
                if &header_buf[0..4] == b"PAGE" {
                    let dtb = byteorder::LittleEndian::read_u64(&header_buf[0x10..0x18]);
                    if dtb != 0 {
                        kernel_dtb = dtb;
                    }
                }
            }
        }

        // 2. Scan physical memory for OS banners (limit scanning to first 256MB or typical regions to be fast)
        let mut found_linux = false;
        let mut found_windows = false;
        let mut linux_banner = String::new();
        let mut windows_banner = String::new();

        // Compile scan regexes
        let linux_re = Regex::new(r"Linux version [0-9]+\.[0-9]+\.[a-zA-Z0-9_\-\+\.]+").unwrap();
        let win_re = Regex::new(r"Microsoft \(R\) Windows \(R\) Kernel Version [0-9]+\.[0-9]+").unwrap();

        // We scan physical memory in chunks to find banners
        let scan_limit = std::cmp::min(dump.file_size() as u64, 512 * 1024 * 1024); // Limit to first 512MB
        let mut scan_offset = 0;
        let mut temp_buf = vec![0u8; 1024 * 1024]; // 1MB scan window


        while scan_offset < scan_limit {
            let chunk_size = std::cmp::min(temp_buf.len() as u64, scan_limit - scan_offset) as usize;
            if dump.read_physical(scan_offset, &mut temp_buf[0..chunk_size]).is_ok() {
                let slice = &temp_buf[0..chunk_size];
                
                if !found_linux {
                    if let Some(m) = linux_re.find(slice) {
                        found_linux = true;
                        linux_banner = String::from_utf8_lossy(m.as_bytes()).to_string();
                    }
                }

                if !found_windows {
                    if let Some(m) = win_re.find(slice) {
                        found_windows = true;
                        windows_banner = String::from_utf8_lossy(m.as_bytes()).to_string();
                    }
                }
            }

            if found_linux || found_windows {
                break;
            }
            scan_offset += chunk_size as u64 - 1024; // Overlap to prevent splitting strings
        }

        if found_linux {
            family = OsFamily::Linux;
            kernel_version = linux_banner;
        } else if found_windows {
            family = OsFamily::Windows;
            kernel_version = windows_banner;
        }

        // 3. Brute force / guess DTB if not set yet
        if kernel_dtb == 0 {
            kernel_dtb = match family {
                OsFamily::Windows => {
                    // Windows standard DTBs on x64 are typically:
                    // 0x1aa000, 0x1ad000, 0x1a9000, etc.
                    // Let's test a few common ones or check directory table bases in physical memory
                    // We can verify a DTB by checking if it translates known Windows virtual addresses
                    // like 0xFFFFF78000000000 (KUSER_SHARED_DATA).
                    let candidates = [0x1aa000, 0x1ad000, 0x1a9000, 0x1b7000, 0x1ab000, 0x1ac000];
                    let mut chosen = 0x1aa000;
                    for &c in &candidates {
                        // Check if we can translate KUSER_SHARED_DATA (0xFFFFF78000000000)
                        if translate_virtual_address(dump, c, 0xFFFFF78000000000).is_ok() {
                            chosen = c;
                            break;
                        }
                    }
                    chosen
                }
                _ => {
                    // Linux/Mac DTBs can be complex to brute force.
                    // Usually, for Linux, it corresponds to init_level4_pgt.
                    // Let's use a standard default candidate of 0x1000 or look for kernel symbols.
                    0x1000
                }
            };
        }

        // Extract Windows build number from KUSER_SHARED_DATA if Windows
        if matches!(family, OsFamily::Windows) {
            let mut kuser_buf = [0u8; 512];
            // KUSER_SHARED_DATA is at 0xFFFFF78000000000
            if translate_virtual_address(dump, kernel_dtb, 0xFFFFF78000000000).is_ok() {
                if crate::translate::read_virtual_memory(dump, kernel_dtb, 0xFFFFF78000000000, &mut kuser_buf).is_ok() {
                    // NtBuildNumber is at offset 0x260 (u32)
                    let build = byteorder::LittleEndian::read_u32(&kuser_buf[0x260..0x264]);
                    // NtProductType is at offset 0x264 (u32)
                    build_number = Some(build);
                    kernel_version = format!("Windows Build {} (x64)", build);
                }
            }
        }

        Ok(Self {
            family,
            architecture: "x86_64".to_string(), // Default to x86_64 for now
            kernel_version,
            build_number,
            kernel_base,
            kernel_dtb,
        })
    }
}
