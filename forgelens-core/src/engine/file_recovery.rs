use crate::{ingest::MemoryDump, Result};
use byteorder::{ByteOrder, LittleEndian};

/// A file artifact recovered from memory.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveredFile {
    pub file_type: FileType,
    pub name: String,
    pub size: usize,
    pub physical_address: u64,
    pub source: String,
    pub description: String,
    pub threat_indicators: Vec<String>,
    /// First 256 bytes of the file (for preview/identification)
    pub header_preview: Vec<u8>,
}

/// Types of files that can be recovered from memory.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum FileType {
    PortableExecutable,  // PE (EXE/DLL)
    Pdf,
    OfficeDocument,      // OOXML or OLE compound
    Script,              // PowerShell, VBScript, JavaScript
    Archive,             // ZIP, RAR, 7z
    Image,               // PNG, JPEG, BMP
    ClipboardData,
    BrowserSession,
    ChatRemnant,
    Certificate,         // X.509, PFX
    Unknown,
}

/// Browser artifact extracted from memory.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BrowserArtifact {
    pub artifact_type: BrowserArtifactType,
    pub browser: String,
    pub data: String,
    pub url: String,
    pub physical_address: u64,
}

/// Types of browser artifacts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum BrowserArtifactType {
    Url,
    Cookie,
    FormData,
    SessionStorage,
    LocalStorage,
    DownloadHistory,
    CachedPage,
}

/// Full file recovery analysis result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileRecoveryResult {
    pub recovered_files: Vec<RecoveredFile>,
    pub browser_artifacts: Vec<BrowserArtifact>,
    pub pe_files_count: usize,
    pub document_count: usize,
    pub script_count: usize,
}

/// Performs comprehensive file artifact recovery from a memory dump.
pub fn recover_files(dump: &MemoryDump) -> Result<FileRecoveryResult> {
    let mut files = Vec::new();
    // browser_artifacts will be set later

    // 1. Carve PE files (EXE/DLL)
    let pe_files = carve_pe_files(dump)?;
    files.extend(pe_files);

    // 2. Carve documents (PDF, Office)
    let docs = carve_documents(dump)?;
    files.extend(docs);

    // 3. Carve scripts (PowerShell, VBScript, JS)
    let scripts = carve_scripts(dump)?;
    files.extend(scripts);

    // 4. Extract clipboard data
    let clipboard = extract_clipboard_data(dump)?;
    files.extend(clipboard);

    // 5. Extract browser artifacts
    let browser_artifacts = extract_browser_artifacts(dump)?;

    // 6. Carve archives and images
    let misc = carve_misc_files(dump)?;
    files.extend(misc);

    let pe_count = files.iter().filter(|f| f.file_type == FileType::PortableExecutable).count();
    let doc_count = files.iter().filter(|f| matches!(f.file_type, FileType::Pdf | FileType::OfficeDocument)).count();
    let script_count = files.iter().filter(|f| f.file_type == FileType::Script).count();

    Ok(FileRecoveryResult {
        recovered_files: files,
        browser_artifacts,
        pe_files_count: pe_count,
        document_count: doc_count,
        script_count: script_count,
    })
}

/// Carves PE (Portable Executable) files from physical memory.
fn carve_pe_files(dump: &MemoryDump) -> Result<Vec<RecoveredFile>> {
    let mut files = Vec::new();
    let scan_limit = std::cmp::min(dump.file_size() as u64, 512 * 1024 * 1024);
    let mut offset = 0u64;
    let mut buf = vec![0u8; 1024 * 1024];

    while offset + buf.len() as u64 <= scan_limit && files.len() < 100 {
        if dump.read_physical(offset, &mut buf).is_ok() {
            let mut i = 0;
            while i + 0x200 < buf.len() {
                // Look for MZ header
                if buf[i] == b'M' && buf[i + 1] == b'Z' {
                    // Validate PE structure
                    if let Some(pe_info) = validate_pe_header(&buf[i..]) {
                        let header_preview = buf[i..std::cmp::min(i + 256, buf.len())].to_vec();

                        let mut threat_indicators = Vec::new();

                        // Check for suspicious PE characteristics
                        if pe_info.section_count == 0 {
                            threat_indicators.push("Zero sections (packed/malformed)".to_string());
                        }
                        if pe_info.has_rwx_section {
                            threat_indicators.push("RWX section present".to_string());
                        }
                        if pe_info.entry_point_in_non_text {
                            threat_indicators.push("Entry point outside .text section".to_string());
                        }
                        if pe_info.is_dll && pe_info.size_of_image < 0x2000 {
                            threat_indicators.push("Suspiciously small DLL".to_string());
                        }

                        let pe_type = if pe_info.is_dll { "DLL" } else { "EXE" };
                        let name = if !pe_info.export_name.is_empty() {
                            pe_info.export_name.clone()
                        } else {
                            format!("carved_{}_0x{:X}.{}", pe_type.to_lowercase(), offset + i as u64, pe_type.to_lowercase())
                        };

                        files.push(RecoveredFile {
                            file_type: FileType::PortableExecutable,
                            name,
                            size: pe_info.size_of_image as usize,
                            physical_address: offset + i as u64,
                            source: "PE Carver".to_string(),
                            description: format!(
                                "{} PE file ({}-bit), {} sections, SizeOfImage: 0x{:X}",
                                pe_type,
                                if pe_info.is_64bit { 64 } else { 32 },
                                pe_info.section_count,
                                pe_info.size_of_image
                            ),
                            threat_indicators,
                            header_preview,
                        });

                        // Skip past this PE
                        i += std::cmp::max(pe_info.size_of_image as usize, 0x1000);
                        continue;
                    }
                }
                i += 0x200; // PE files are typically sector-aligned
            }
        }
        offset += buf.len() as u64 - 0x200;
    }

    Ok(files)
}

/// PE header validation info.
struct PeInfo {
    is_64bit: bool,
    is_dll: bool,
    size_of_image: u32,
    section_count: u16,
    has_rwx_section: bool,
    entry_point_in_non_text: bool,
    export_name: String,
}

/// Validates a PE header and extracts key information.
fn validate_pe_header(data: &[u8]) -> Option<PeInfo> {
    if data.len() < 0x100 || data[0] != b'M' || data[1] != b'Z' {
        return None;
    }

    let e_lfanew = LittleEndian::read_u32(&data[0x3C..0x40]) as usize;
    if e_lfanew + 0x18 >= data.len() || e_lfanew > 0x1000 {
        return None;
    }

    // Check PE signature
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }

    let machine = LittleEndian::read_u16(&data[e_lfanew + 4..e_lfanew + 6]);
    let is_64bit = machine == 0x8664; // AMD64

    let section_count = LittleEndian::read_u16(&data[e_lfanew + 6..e_lfanew + 8]);
    if section_count > 96 {
        return None; // Unreasonable section count
    }

    let characteristics = LittleEndian::read_u16(&data[e_lfanew + 22..e_lfanew + 24]);
    let is_dll = (characteristics & 0x2000) != 0;

    let opt_offset = e_lfanew + 24;
    let magic = LittleEndian::read_u16(&data[opt_offset..opt_offset + 2]);

    let (size_of_image, entry_point) = if magic == 0x20B {
        // PE32+
        if opt_offset + 0x3C > data.len() { return None; }
        let soi = LittleEndian::read_u32(&data[opt_offset + 0x38..opt_offset + 0x3C]);
        let ep = LittleEndian::read_u32(&data[opt_offset + 0x10..opt_offset + 0x14]);
        (soi, ep)
    } else if magic == 0x10B {
        // PE32
        if opt_offset + 0x3C > data.len() { return None; }
        let soi = LittleEndian::read_u32(&data[opt_offset + 0x38..opt_offset + 0x3C]);
        let ep = LittleEndian::read_u32(&data[opt_offset + 0x10..opt_offset + 0x14]);
        (soi, ep)
    } else {
        return None;
    };

    if size_of_image == 0 || size_of_image > 0x10000000 {
        return None; // Max 256MB
    }

    // Parse section headers for RWX detection
    let section_header_offset = if magic == 0x20B {
        opt_offset + 0xF0 // PE32+ optional header size
    } else {
        opt_offset + 0xE0 // PE32 optional header size
    };

    let mut has_rwx = false;
    let mut ep_in_text = false;
    let export_name = String::new();

    for s in 0..section_count as usize {
        let sec_off = section_header_offset + s * 40;
        if sec_off + 40 > data.len() { break; }

        let sec_chars = LittleEndian::read_u32(&data[sec_off + 36..sec_off + 40]);
        let sec_va = LittleEndian::read_u32(&data[sec_off + 12..sec_off + 16]);
        let sec_size = LittleEndian::read_u32(&data[sec_off + 8..sec_off + 12]);

        // IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE
        if (sec_chars & 0x20000000) != 0 && (sec_chars & 0x40000000) != 0 && (sec_chars & 0x80000000) != 0 {
            has_rwx = true;
        }

        // Check if entry point is in this section
        if entry_point >= sec_va && entry_point < sec_va + sec_size {
            let sec_name = &data[sec_off..sec_off + 8];
            if sec_name.starts_with(b".text") || sec_name.starts_with(b"CODE") {
                ep_in_text = true;
            }
        }
    }

    Some(PeInfo {
        is_64bit,
        is_dll,
        size_of_image,
        section_count,
        has_rwx_section: has_rwx,
        entry_point_in_non_text: !ep_in_text && entry_point != 0,
        export_name,
    })
}

/// Carves document files (PDF, Office) from memory.
fn carve_documents(dump: &MemoryDump) -> Result<Vec<RecoveredFile>> {
    let mut files = Vec::new();
    let scan_limit = std::cmp::min(dump.file_size() as u64, 256 * 1024 * 1024);
    let mut offset = 0u64;
    let mut buf = vec![0u8; 1024 * 1024];

    while offset + buf.len() as u64 <= scan_limit && files.len() < 50 {
        if dump.read_physical(offset, &mut buf).is_ok() {
            for i in 0..buf.len().saturating_sub(16) {
                // PDF: starts with %PDF
                if &buf[i..i + 4] == b"%PDF" {
                    let preview = buf[i..std::cmp::min(i + 256, buf.len())].to_vec();
                    // Estimate size by looking for %%EOF
                    let estimated_size = find_pdf_end(&buf[i..]) .unwrap_or(4096);

                    files.push(RecoveredFile {
                        file_type: FileType::Pdf,
                        name: format!("carved_doc_0x{:X}.pdf", offset + i as u64),
                        size: estimated_size,
                        physical_address: offset + i as u64,
                        source: "Document Carver".to_string(),
                        description: "PDF document found in memory".to_string(),
                        threat_indicators: Vec::new(),
                        header_preview: preview,
                    });
                }

                // Office OOXML: starts with PK (ZIP) and contains word/ or xl/ or ppt/
                if i + 30 < buf.len() && buf[i] == 0x50 && buf[i + 1] == 0x4B && buf[i + 2] == 0x03 && buf[i + 3] == 0x04 {
                    // Check if it's an Office document by looking for content types
                    let chunk_end = std::cmp::min(i + 4096, buf.len());
                    let chunk = &buf[i..chunk_end];
                    if chunk.windows(5).any(|w| w == b"word/" || w == b"xl/wo" || w == b"ppt/s") ||
                       chunk.windows(14).any(|w| w == b"[Content_Types") {
                        let preview = buf[i..std::cmp::min(i + 256, buf.len())].to_vec();
                        files.push(RecoveredFile {
                            file_type: FileType::OfficeDocument,
                            name: format!("carved_office_0x{:X}.docx", offset + i as u64),
                            size: 0,
                            physical_address: offset + i as u64,
                            source: "Document Carver".to_string(),
                            description: "Microsoft Office document (OOXML) found in memory".to_string(),
                            threat_indicators: Vec::new(),
                            header_preview: preview,
                        });
                    }
                }

                // OLE Compound Document: D0 CF 11 E0 (older Office formats)
                if i + 8 < buf.len() && buf[i] == 0xD0 && buf[i + 1] == 0xCF && buf[i + 2] == 0x11 && buf[i + 3] == 0xE0 {
                    let preview = buf[i..std::cmp::min(i + 256, buf.len())].to_vec();
                    files.push(RecoveredFile {
                        file_type: FileType::OfficeDocument,
                        name: format!("carved_ole_0x{:X}.doc", offset + i as u64),
                        size: 0,
                        physical_address: offset + i as u64,
                        source: "Document Carver".to_string(),
                        description: "OLE Compound Document (legacy Office format) found in memory".to_string(),
                        threat_indicators: vec!["Legacy format may contain VBA macros".to_string()],
                        header_preview: preview,
                    });
                }
            }
        }
        offset += buf.len() as u64 - 16;
    }

    Ok(files)
}

/// Finds the end of a PDF document (%%EOF marker).
fn find_pdf_end(data: &[u8]) -> Option<usize> {
    let max_search = std::cmp::min(data.len(), 10 * 1024 * 1024);
    for i in 0..max_search.saturating_sub(5) {
        if &data[i..i + 5] == b"%%EOF" {
            return Some(i + 5);
        }
    }
    None
}

/// Carves script files from memory (PowerShell, VBScript, JavaScript).
fn carve_scripts(dump: &MemoryDump) -> Result<Vec<RecoveredFile>> {
    let mut files = Vec::new();

    let script_markers: Vec<(&[u8], &str, Vec<&str>)> = vec![
        (b"powershell", "PowerShell Script", vec![
            "-EncodedCommand", "-NoProfile", "-WindowStyle Hidden",
            "Invoke-Expression", "IEX(", "Download", "Net.WebClient",
        ]),
        (b"<script", "JavaScript/HTML Script", vec![
            "eval(", "document.write", "XMLHttpRequest",
        ]),
        (b"WScript.Shell", "VBScript", vec![
            "CreateObject", "Run ", "Exec ",
        ]),
        (b"#!/bin/bash", "Bash Script", vec!["curl ", "wget ", "chmod "]),
        (b"#!/usr/bin/python", "Python Script", vec!["import os", "import subprocess"]),
    ];

    let scan_limit = std::cmp::min(dump.file_size() as u64, 256 * 1024 * 1024);
    let mut offset = 0u64;
    let mut buf = vec![0u8; 1024 * 1024];

    while offset + buf.len() as u64 <= scan_limit && files.len() < 30 {
        if dump.read_physical(offset, &mut buf).is_ok() {
            for (marker, script_type, threat_patterns) in &script_markers {
                for pos in 0..buf.len().saturating_sub(marker.len()) {
                    if buf[pos..pos + marker.len()].eq_ignore_ascii_case(marker) {
                        let context_end = std::cmp::min(pos + 4096, buf.len());
                        let context = &buf[pos..context_end];

                        let mut indicators = Vec::new();
                        for threat in threat_patterns {
                            if context.windows(threat.len()).any(|w| {
                                w.iter().zip(threat.as_bytes()).all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
                            }) {
                                indicators.push(format!("Contains '{}'", threat));
                            }
                        }

                        if !indicators.is_empty() {
                            let preview = buf[pos..std::cmp::min(pos + 256, buf.len())].to_vec();
                            files.push(RecoveredFile {
                                file_type: FileType::Script,
                                name: format!("carved_script_0x{:X}", offset + pos as u64),
                                size: 0,
                                physical_address: offset + pos as u64,
                                source: "Script Carver".to_string(),
                                description: format!("{} found in memory with suspicious patterns", script_type),
                                threat_indicators: indicators,
                                header_preview: preview,
                            });
                            break; // Only one per marker per chunk
                        }
                    }
                }
            }
        }
        offset += buf.len() as u64 - 256;
    }

    Ok(files)
}

/// Extracts Windows clipboard data from memory.
fn extract_clipboard_data(dump: &MemoryDump) -> Result<Vec<RecoveredFile>> {
    let mut files = Vec::new();

    // Windows clipboard data is stored in kernel objects managed by win32k.sys.
    // In user space, clipboard formats are stored in global memory allocations.
    // The clipboard owner window's process has the data in its address space.
    // We can scan for clipboard format headers:
    // CF_TEXT (1), CF_UNICODETEXT (13), CF_BITMAP (2), CF_DIB (8)

    // Heuristic: look for large UTF-16 text blocks that could be clipboard content
    let scan_limit = std::cmp::min(dump.file_size() as u64, 128 * 1024 * 1024);
    let mut offset = 0u64;
    let mut buf = vec![0u8; 1024 * 1024];

    while offset + buf.len() as u64 <= scan_limit && files.len() < 5 {
        if dump.read_physical(offset, &mut buf).is_ok() {
            // Look for clipboard format tag structures
            // Windows clipboard uses GlobalAlloc blocks with specific patterns
            for i in 0..buf.len().saturating_sub(64) {
                // Look for clipboard format marker followed by data
                // CF_UNICODETEXT format blocks often have a specific header pattern
                if buf[i] == 0x0D && buf[i + 1] == 0x00 && buf[i + 2] == 0x00 && buf[i + 3] == 0x00 {
                    // Potential CF_UNICODETEXT (format 13 = 0x0D)
                    let data_start = i + 16;
                    if data_start + 32 < buf.len() {
                        // Check if following data looks like UTF-16
                        let mut valid_utf16 = true;
                        let mut char_count = 0;
                        for j in (data_start..std::cmp::min(data_start + 512, buf.len())).step_by(2) {
                            if j + 1 >= buf.len() { break; }
                            let ch = LittleEndian::read_u16(&buf[j..j + 2]);
                            if ch == 0 { break; }
                            if ch < 0x20 && ch != 0x0D && ch != 0x0A && ch != 0x09 {
                                valid_utf16 = false;
                                break;
                            }
                            char_count += 1;
                        }

                        if valid_utf16 && char_count > 16 {
                            let preview = buf[data_start..std::cmp::min(data_start + 256, buf.len())].to_vec();
                            files.push(RecoveredFile {
                                file_type: FileType::ClipboardData,
                                name: format!("clipboard_text_0x{:X}", offset + i as u64),
                                size: char_count * 2,
                                physical_address: offset + i as u64,
                                source: "Clipboard Scanner".to_string(),
                                description: format!("Clipboard text data ({} characters)", char_count),
                                threat_indicators: Vec::new(),
                                header_preview: preview,
                            });
                        }
                    }
                }
            }
        }
        offset += buf.len() as u64 - 64;
    }

    Ok(files)
}

/// Extracts browser artifacts (URLs, cookies, sessions) from memory.
fn extract_browser_artifacts(dump: &MemoryDump) -> Result<Vec<BrowserArtifact>> {
    let mut artifacts = Vec::new();

    let url_patterns: Vec<&[u8]> = vec![
        b"https://",
        b"http://",
    ];

    let scan_limit = std::cmp::min(dump.file_size() as u64, 256 * 1024 * 1024);
    let mut offset = 0u64;
    let mut buf = vec![0u8; 1024 * 1024];
    let mut seen_urls = std::collections::HashSet::new();

    while offset + buf.len() as u64 <= scan_limit && artifacts.len() < 200 {
        if dump.read_physical(offset, &mut buf).is_ok() {
            for pattern in &url_patterns {
                let mut search_pos = 0;
                while search_pos + pattern.len() < buf.len() {
                    if let Some(pos) = buf[search_pos..].windows(pattern.len()).position(|w| w == *pattern) {
                        let abs_pos = search_pos + pos;
                        // Extract the full URL (up to whitespace or null)
                        let url_end = buf[abs_pos..].iter()
                            .position(|&b| b == 0 || b == b' ' || b == b'\n' || b == b'\r' || b == b'"' || b == b'\'' || b == b'>' || b == b')')
                            .unwrap_or(256);
                        let url_end = std::cmp::min(url_end, 2048);

                        let url = String::from_utf8_lossy(&buf[abs_pos..abs_pos + url_end]).to_string();

                        if url.len() > 10 && !seen_urls.contains(&url) {
                            seen_urls.insert(url.clone());

                            // Determine browser based on surrounding context
                            let browser = detect_browser_context(&buf, abs_pos);

                            artifacts.push(BrowserArtifact {
                                artifact_type: BrowserArtifactType::Url,
                                browser,
                                data: url.clone(),
                                url,
                                physical_address: offset + abs_pos as u64,
                            });
                        }

                        search_pos = abs_pos + url_end;
                    } else {
                        break;
                    }
                }
            }

            // Look for cookie strings
            for i in 0..buf.len().saturating_sub(32) {
                if buf[i..].starts_with(b"Set-Cookie:") || buf[i..].starts_with(b"Cookie:") {
                    let end = buf[i..].iter()
                        .position(|&b| b == 0 || b == b'\n')
                        .unwrap_or(256);
                    let end = std::cmp::min(end, 1024);
                    let cookie = String::from_utf8_lossy(&buf[i..i + end]).to_string();

                    if cookie.len() > 15 {
                        artifacts.push(BrowserArtifact {
                            artifact_type: BrowserArtifactType::Cookie,
                            browser: "Unknown".to_string(),
                            data: cookie,
                            url: String::new(),
                            physical_address: offset + i as u64,
                        });
                    }
                }
            }
        }
        offset += buf.len() as u64 - 256;
    }

    Ok(artifacts)
}

/// Detects which browser a URL belongs to based on surrounding memory context.
fn detect_browser_context(buf: &[u8], pos: usize) -> String {
    let start = pos.saturating_sub(4096);
    let end = std::cmp::min(pos + 4096, buf.len());
    let context = &buf[start..end];

    let browsers = [
        (b"chrome" as &[u8], "Google Chrome"),
        (b"Chrome", "Google Chrome"),
        (b"firefox", "Mozilla Firefox"),
        (b"Firefox", "Mozilla Firefox"),
        (b"edge", "Microsoft Edge"),
        (b"Edge", "Microsoft Edge"),
        (b"msedge", "Microsoft Edge"),
        (b"brave", "Brave"),
        (b"opera", "Opera"),
    ];

    for (marker, name) in &browsers {
        if context.windows(marker.len()).any(|w| w == *marker) {
            return name.to_string();
        }
    }

    "Unknown".to_string()
}

/// Carves miscellaneous files (archives, images, certificates).
fn carve_misc_files(dump: &MemoryDump) -> Result<Vec<RecoveredFile>> {
    let mut files = Vec::new();

    let signatures: Vec<(&[u8], FileType, &str)> = vec![
        (&[0x50, 0x4B, 0x03, 0x04], FileType::Archive, "ZIP Archive"),
        (&[0x52, 0x61, 0x72, 0x21], FileType::Archive, "RAR Archive"),
        (&[0x37, 0x7A, 0xBC, 0xAF], FileType::Archive, "7-Zip Archive"),
        (&[0x89, 0x50, 0x4E, 0x47], FileType::Image, "PNG Image"),
        (&[0xFF, 0xD8, 0xFF, 0xE0], FileType::Image, "JPEG Image"),
        (&[0xFF, 0xD8, 0xFF, 0xE1], FileType::Image, "JPEG Image (EXIF)"),
        (&[0x42, 0x4D], FileType::Image, "BMP Image"),
    ];

    let scan_limit = std::cmp::min(dump.file_size() as u64, 128 * 1024 * 1024);
    let mut offset = 0u64;
    let mut buf = vec![0u8; 1024 * 1024];

    while offset + buf.len() as u64 <= scan_limit && files.len() < 50 {
        if dump.read_physical(offset, &mut buf).is_ok() {
            for i in 0..buf.len().saturating_sub(8) {
                for (sig, ftype, desc) in &signatures {
                    if i + sig.len() <= buf.len() && &buf[i..i + sig.len()] == *sig {
                        let preview = buf[i..std::cmp::min(i + 256, buf.len())].to_vec();
                        let ext = match ftype {
                            FileType::Archive => "zip",
                            FileType::Image => "png",
                            _ => "bin",
                        };

                        files.push(RecoveredFile {
                            file_type: ftype.clone(),
                            name: format!("carved_file_0x{:X}.{}", offset + i as u64, ext),
                            size: 0,
                            physical_address: offset + i as u64,
                            source: "File Carver".to_string(),
                            description: format!("{} found in memory", desc),
                            threat_indicators: Vec::new(),
                            header_preview: preview,
                        });
                        break;
                    }
                }
            }
        }
        offset += buf.len() as u64 - 8;
    }

    Ok(files)
}
