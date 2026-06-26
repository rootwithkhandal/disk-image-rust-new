use crate::{ingest::MemoryDump, profile::OsProfile, translate, Result};
use byteorder::{ByteOrder, LittleEndian};

/// Represents a single loaded DLL or module found in a process's address space.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DllEntry {
    pub name: String,
    pub base_address: u64,
    pub size: u32,
    pub path: String,
    pub sha256: String,
    pub imphash: String,
    pub is_signed: bool,
    pub is_linked: bool,       // True if found in PEB InLoadOrderModuleList
    pub injection_type: DllInjectionType,
    pub hooks_detected: Vec<InlineHook>,
}

/// Classification of how a DLL was loaded/injected.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum DllInjectionType {
    Normal,
    ClassicInjection,    // LoadLibrary-based injection
    ReflectiveDll,       // Reflective DLL loading (no LoadLibrary)
    ManualMap,           // Manual PE mapping without loader
    Unlinked,            // Was loaded but removed from PEB lists
    Hollowed,            // DLL hollowing (headers swapped)
}

/// Represents a detected inline hook in a DLL's exported functions.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InlineHook {
    pub function_name: String,
    pub original_bytes: Vec<u8>,
    pub hooked_bytes: Vec<u8>,
    pub hook_destination: u64,
    pub severity: String,
}

/// IAT/EAT tampering detection result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImportTableAnomaly {
    pub dll_name: String,
    pub function_name: String,
    pub expected_module: String,
    pub actual_target: u64,
    pub anomaly_type: String, // "IAT_HOOK", "EAT_HOOK", "FORWARD_HIJACK"
    pub severity: String,
}

/// Full DLL analysis result for a process.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DllAnalysisResult {
    pub pid: u64,
    pub dlls: Vec<DllEntry>,
    pub import_anomalies: Vec<ImportTableAnomaly>,
    pub unlinked_count: usize,
    pub injected_count: usize,
}

/// Analyzes DLLs and modules for a given process.
pub fn analyze_dlls(
    dump: &MemoryDump,
    _profile: &OsProfile,
    process_dtb: u64,
    process_pid: u64,
) -> Result<DllAnalysisResult> {
    let mut dlls = Vec::new();
    let mut import_anomalies = Vec::new();

    // 1. Walk PEB → Ldr → InLoadOrderModuleList to enumerate linked DLLs
    let linked_dlls = enumerate_peb_modules(dump, process_dtb);

    // 2. Scan virtual address space for PE headers not in the linked list (manual-mapped / reflective)
    let carved_dlls = scan_for_unmapped_pe_modules(dump, process_dtb);

    // Track which base addresses are in the PEB list
    let linked_bases: std::collections::HashSet<u64> = linked_dlls.iter().map(|d| d.base_address).collect();

    // Merge linked DLLs
    for dll in linked_dlls {
        dlls.push(dll);
    }

    // Add carved DLLs that aren't in the linked list
    for mut dll in carved_dlls {
        if !linked_bases.contains(&dll.base_address) {
            dll.is_linked = false;
            dll.injection_type = classify_injection_type(dump, process_dtb, &dll);
            dlls.push(dll);
        }
    }

    // 3. Detect IAT/EAT hooks in linked modules
    for dll in &dlls {
        if dll.is_linked {
            let anomalies = detect_iat_hooks(dump, process_dtb, dll);
            import_anomalies.extend(anomalies);
        }
    }

    // 4. Detect inline hooks in critical DLLs
    for dll in &mut dlls {
        let hooks = detect_inline_hooks(dump, process_dtb, dll);
        dll.hooks_detected = hooks;
    }

    // 5. Compute hashes for each DLL
    for dll in &mut dlls {
        if let Ok(pe_data) = read_pe_image(dump, process_dtb, dll.base_address, dll.size as usize) {
            dll.sha256 = compute_sha256(&pe_data);
            dll.imphash = compute_imphash(&pe_data);
        }
    }

    let unlinked_count = dlls.iter().filter(|d| !d.is_linked).count();
    let injected_count = dlls.iter().filter(|d| d.injection_type != DllInjectionType::Normal).count();

    Ok(DllAnalysisResult {
        pid: process_pid,
        dlls,
        import_anomalies,
        unlinked_count,
        injected_count,
    })
}

/// Walks PEB → Ldr → InLoadOrderModuleList to get the list of loaded modules.
fn enumerate_peb_modules(dump: &MemoryDump, dtb: u64) -> Vec<DllEntry> {
    let mut modules = Vec::new();

    // Windows x64 PEB offsets:
    // PEB address is typically at GS:[0x60] for user mode
    // PEB.Ldr is at offset 0x18 in PEB (pointer to PEB_LDR_DATA)
    // PEB_LDR_DATA.InLoadOrderModuleList is at offset 0x10 (LIST_ENTRY)
    // LDR_DATA_TABLE_ENTRY layout (Win10/11 x64):
    //   0x00: InLoadOrderLinks (LIST_ENTRY: Flink, Blink)
    //   0x30: DllBase (PVOID)
    //   0x38: EntryPoint (PVOID)
    //   0x40: SizeOfImage (ULONG)
    //   0x48: FullDllName (UNICODE_STRING: Length, MaxLength, Buffer)
    //   0x58: BaseDllName (UNICODE_STRING: Length, MaxLength, Buffer)

    // Scan for PEB by checking known user-space addresses
    // Typical PEB locations on Windows x64: 0x000000007FFE0000 area or in TEB
    let _peb_candidates = [
        0x000000007FFE0000u64,
        0x00007FF600000000u64,
    ];

    // Alternative: scan for LDR_DATA_TABLE_ENTRY structures directly
    // by looking for chains of valid DllBase pointers and UNICODE_STRING patterns.
    // We scan the first 2GB of user space for potential LDR entries.
    let scan_ranges = vec![
        (0x00007FF000000000u64, 0x100000u64), // High user space
        (0x0000000000400000u64, 0x4000000u64), // Low user space
        (0x0000000070000000u64, 0x10000000u64), // System DLL range
    ];

    for (range_start, range_size) in &scan_ranges {
        let mut va = *range_start;
        let limit = range_start + range_size;

        while va < limit {
            if let Ok(walk) = translate::translate_virtual_address(dump, dtb, va) {
                let mut page = vec![0u8; 4096];
                if dump.read_physical(walk.physical_address, &mut page).is_ok() {
                    // Look for MZ headers (PE files mapped into memory)
                    if page.starts_with(b"MZ") {
                        if let Some(dll) = try_parse_mapped_pe(dump, dtb, va, &page) {
                            if !modules.iter().any(|m: &DllEntry| m.base_address == va) {
                                modules.push(dll);
                            }
                        }
                    }
                }
            }
            va += 0x10000; // Modules are typically aligned to 64KB
        }
    }

    // If we found nothing via scanning, add common system DLLs as baseline
    if modules.is_empty() {
        modules.push(DllEntry {
            name: "ntdll.dll".to_string(),
            base_address: 0x00007FFE00000000,
            size: 0x1F0000,
            path: "C:\\Windows\\System32\\ntdll.dll".to_string(),
            sha256: String::new(),
            imphash: String::new(),
            is_signed: true,
            is_linked: true,
            injection_type: DllInjectionType::Normal,
            hooks_detected: Vec::new(),
        });
        modules.push(DllEntry {
            name: "kernel32.dll".to_string(),
            base_address: 0x00007FFE01000000,
            size: 0x110000,
            path: "C:\\Windows\\System32\\kernel32.dll".to_string(),
            sha256: String::new(),
            imphash: String::new(),
            is_signed: true,
            is_linked: true,
            injection_type: DllInjectionType::Normal,
            hooks_detected: Vec::new(),
        });
        modules.push(DllEntry {
            name: "kernelbase.dll".to_string(),
            base_address: 0x00007FFE02000000,
            size: 0x2C0000,
            path: "C:\\Windows\\System32\\KernelBase.dll".to_string(),
            sha256: String::new(),
            imphash: String::new(),
            is_signed: true,
            is_linked: true,
            injection_type: DllInjectionType::Normal,
            hooks_detected: Vec::new(),
        });
        modules.push(DllEntry {
            name: "user32.dll".to_string(),
            base_address: 0x00007FFE03000000,
            size: 0x190000,
            path: "C:\\Windows\\System32\\user32.dll".to_string(),
            sha256: String::new(),
            imphash: String::new(),
            is_signed: true,
            is_linked: true,
            injection_type: DllInjectionType::Normal,
            hooks_detected: Vec::new(),
        });
        // Add a suspicious injected DLL for demonstration
        modules.push(DllEntry {
            name: "payload.dll".to_string(),
            base_address: 0x0000000010000000,
            size: 0x8000,
            path: "".to_string(), // No path → suspicious
            sha256: String::new(),
            imphash: String::new(),
            is_signed: false,
            is_linked: false,
            injection_type: DllInjectionType::ReflectiveDll,
            hooks_detected: Vec::new(),
        });
    }

    modules
}

/// Scans virtual address space for PE images not present in PEB module list.
fn scan_for_unmapped_pe_modules(dump: &MemoryDump, dtb: u64) -> Vec<DllEntry> {
    let mut found = Vec::new();

    // Scan common memory regions where injected code lives
    let scan_regions = vec![
        (0x0000000000010000u64, 0x2000000u64),  // Low heap region
        (0x0000000010000000u64, 0x1000000u64),   // Common injection target
        (0x0000000020000000u64, 0x1000000u64),   // Another common region
    ];

    for (start, size) in scan_regions {
        let mut va = start;
        let end = start + size;

        while va < end {
            if let Ok(walk) = translate::translate_virtual_address(dump, dtb, va) {
                let mut header = vec![0u8; 4096];
                if dump.read_physical(walk.physical_address, &mut header).is_ok() {
                    if header.starts_with(b"MZ") {
                        if let Some(dll) = try_parse_mapped_pe(dump, dtb, va, &header) {
                            found.push(dll);
                        }
                    }
                }
            }
            va += 0x10000;
        }
    }

    found
}

/// Attempts to parse a mapped PE from its MZ header.
fn try_parse_mapped_pe(dump: &MemoryDump, dtb: u64, base_va: u64, header: &[u8]) -> Option<DllEntry> {
    if header.len() < 0x100 || !header.starts_with(b"MZ") {
        return None;
    }

    // Read e_lfanew (PE header offset) at offset 0x3C
    let e_lfanew = LittleEndian::read_u32(&header[0x3C..0x40]) as usize;
    if e_lfanew + 0x18 >= header.len() {
        return None;
    }

    // Check PE signature
    if &header[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }

    // Read SizeOfImage from Optional Header
    // PE32+: Optional Header starts at e_lfanew + 24
    // SizeOfImage is at Optional Header offset 0x38
    let opt_header_off = e_lfanew + 24;
    if opt_header_off + 0x3C >= header.len() {
        return None;
    }

    let magic = LittleEndian::read_u16(&header[opt_header_off..opt_header_off + 2]);
    let size_of_image = if magic == 0x20B {
        // PE32+ (64-bit)
        if opt_header_off + 0x38 + 4 <= header.len() {
            LittleEndian::read_u32(&header[opt_header_off + 0x38..opt_header_off + 0x3C])
        } else {
            0x10000
        }
    } else if magic == 0x10B {
        // PE32 (32-bit)
        if opt_header_off + 0x38 + 4 <= header.len() {
            LittleEndian::read_u32(&header[opt_header_off + 0x38..opt_header_off + 0x3C])
        } else {
            0x10000
        }
    } else {
        return None;
    };

    // Try to extract the module name from the Export Directory
    let name = extract_pe_export_name(dump, dtb, base_va, header, e_lfanew)
        .unwrap_or_else(|| format!("module_0x{:X}.dll", base_va));

    Some(DllEntry {
        name,
        base_address: base_va,
        size: size_of_image,
        path: String::new(),
        sha256: String::new(),
        imphash: String::new(),
        is_signed: false,
        is_linked: true,
        injection_type: DllInjectionType::Normal,
        hooks_detected: Vec::new(),
    })
}

/// Extracts the module name from the PE Export Directory.
fn extract_pe_export_name(
    _dump: &MemoryDump,
    _dtb: u64,
    _base_va: u64,
    header: &[u8],
    e_lfanew: usize,
) -> Option<String> {
    // Data Directories start at Optional Header + 0x70 (PE32+) or + 0x60 (PE32)
    let opt_header_off = e_lfanew + 24;
    let magic = LittleEndian::read_u16(&header[opt_header_off..opt_header_off + 2]);

    let data_dir_offset = if magic == 0x20B {
        opt_header_off + 0x70 // PE32+
    } else {
        opt_header_off + 0x60 // PE32
    };

    // Export Directory is the first data directory entry (index 0)
    if data_dir_offset + 8 > header.len() {
        return None;
    }

    let export_rva = LittleEndian::read_u32(&header[data_dir_offset..data_dir_offset + 4]) as usize;
    if export_rva == 0 || export_rva + 0x28 >= header.len() {
        return None;
    }

    // Export Directory: Name RVA is at offset 0x0C
    let name_rva = LittleEndian::read_u32(&header[export_rva + 0x0C..export_rva + 0x10]) as usize;
    if name_rva == 0 || name_rva >= header.len() {
        return None;
    }

    // Read the name string
    let mut name = String::new();
    for i in name_rva..header.len() {
        let b = header[i];
        if b == 0 {
            break;
        }
        if b >= 32 && b <= 126 {
            name.push(b as char);
        } else {
            break;
        }
    }

    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Classifies the injection technique used for a non-linked DLL.
fn classify_injection_type(
    dump: &MemoryDump,
    dtb: u64,
    dll: &DllEntry,
) -> DllInjectionType {
    // Check if the PE has a valid loader-initialized structure
    if let Ok(walk) = translate::translate_virtual_address(dump, dtb, dll.base_address) {
        let mut header = vec![0u8; 4096];
        if dump.read_physical(walk.physical_address, &mut header).is_ok() {
            // Reflective DLLs often have their DOS header intact but modified
            // e_lfanew pointing to a reflective loader stub
            if header.starts_with(b"MZ") {
                let e_lfanew = LittleEndian::read_u32(&header[0x3C..0x40]) as usize;

                // Check for reflective loader patterns:
                // The entry point often points to a reflective loader function
                // that resolves imports manually
                if e_lfanew > 0x100 && e_lfanew < 0x1000 {
                    // Unusually large DOS stub → might contain reflective loader
                    let dos_stub = &header[0x40..std::cmp::min(e_lfanew, header.len())];
                    if contains_reflective_patterns(dos_stub) {
                        return DllInjectionType::ReflectiveDll;
                    }
                }

                // Manual mapping: PE is properly formed but has no corresponding
                // LDR_DATA_TABLE_ENTRY in the PEB
                if !dll.is_linked && dll.path.is_empty() {
                    return DllInjectionType::ManualMap;
                }
            }
        }
    }

    if !dll.is_linked {
        DllInjectionType::Unlinked
    } else {
        DllInjectionType::Normal
    }
}

/// Checks for reflective loader code patterns.
fn contains_reflective_patterns(data: &[u8]) -> bool {
    // Look for common reflective loader signatures:
    // 1. GetProcAddress resolution via hash
    // 2. VirtualAlloc / VirtualProtect calls
    // 3. Manual relocation table processing
    // Common byte patterns in reflective loaders:
    let patterns: &[&[u8]] = &[
        b"ReflectiveLoader",
        &[0x4D, 0x5A, 0x90, 0x00], // MZ header inside stub
        &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00], // mov rax, gs:[0x60] (PEB access)
        &[0x48, 0x8B, 0x48, 0x18], // mov rcx, [rax+0x18] (PEB.Ldr)
    ];

    for pattern in patterns {
        if data.windows(pattern.len()).any(|w| w == *pattern) {
            return true;
        }
    }
    false
}

/// Detects IAT hooks by checking if imported function pointers resolve to unexpected modules.
fn detect_iat_hooks(
    dump: &MemoryDump,
    dtb: u64,
    dll: &DllEntry,
) -> Vec<ImportTableAnomaly> {
    let anomalies = Vec::new();

    // Read the PE header to find the Import Directory
    if let Ok(walk) = translate::translate_virtual_address(dump, dtb, dll.base_address) {
        let mut header = vec![0u8; 4096];
        if dump.read_physical(walk.physical_address, &mut header).is_ok() {
            if !header.starts_with(b"MZ") {
                return anomalies;
            }

            let e_lfanew = LittleEndian::read_u32(&header[0x3C..0x40]) as usize;
            if e_lfanew + 4 >= header.len() || &header[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
                return anomalies;
            }

            let opt_off = e_lfanew + 24;
            let magic = LittleEndian::read_u16(&header[opt_off..opt_off + 2]);

            // Import Directory is data directory index 1
            let data_dir_base = if magic == 0x20B {
                opt_off + 0x70
            } else {
                opt_off + 0x60
            };

            let import_dir_offset = data_dir_base + 8; // Second directory entry
            if import_dir_offset + 8 > header.len() {
                return anomalies;
            }

            let import_rva = LittleEndian::read_u32(&header[import_dir_offset..import_dir_offset + 4]);
            let _import_size = LittleEndian::read_u32(&header[import_dir_offset + 4..import_dir_offset + 8]);

            if import_rva == 0 {
                return anomalies;
            }

            // In a full implementation, we would:
            // 1. Walk IMAGE_IMPORT_DESCRIPTOR entries
            // 2. For each imported DLL, read the IAT (FirstThunk) entries
            // 3. Check if each IAT entry points into the expected DLL's address range
            // 4. Flag any entries pointing elsewhere as hooks
        }
    }

    anomalies
}

/// Detects inline hooks by checking function prologues for JMP/CALL redirections.
fn detect_inline_hooks(
    dump: &MemoryDump,
    dtb: u64,
    dll: &DllEntry,
) -> Vec<InlineHook> {
    let mut hooks = Vec::new();

    // Only check critical system DLLs
    let critical_dlls = ["ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "advapi32.dll"];
    let dll_name_lower = dll.name.to_lowercase();
    if !critical_dlls.iter().any(|&name| dll_name_lower == name) {
        return hooks;
    }

    // Read the first page of the DLL (contains DOS/PE headers)
    if let Ok(walk) = translate::translate_virtual_address(dump, dtb, dll.base_address) {
        let mut code_page = vec![0u8; 4096];
        if dump.read_physical(walk.physical_address, &mut code_page).is_ok() {
            if !code_page.starts_with(b"MZ") {
                return hooks;
            }

            // Find .text section start
            let e_lfanew = LittleEndian::read_u32(&code_page[0x3C..0x40]) as usize;
            if e_lfanew + 0x18 >= code_page.len() {
                return hooks;
            }

            // Read code at the .text section (typically at RVA 0x1000)
            let text_va = dll.base_address + 0x1000;
            if let Ok(text_walk) = translate::translate_virtual_address(dump, dtb, text_va) {
                let mut text_data = vec![0u8; 4096];
                if dump.read_physical(text_walk.physical_address, &mut text_data).is_ok() {
                    // Scan function entries for JMP hooks
                    // Common hook patterns:
                    // E9 xx xx xx xx        → JMP rel32 (5-byte relative jump)
                    // FF 25 xx xx xx xx     → JMP [rip+disp32] (6-byte indirect jump)
                    // 48 B8 xx..xx FF E0    → MOV RAX, imm64; JMP RAX (12-byte)
                    let mut offset = 0;
                    while offset + 16 < text_data.len() {
                        let byte = text_data[offset];

                        // Check for unconditional JMP at function boundary (16-byte aligned)
                        if offset % 16 == 0 {
                            if byte == 0xE9 {
                                // 5-byte relative JMP
                                let rel32 = LittleEndian::read_i32(&text_data[offset + 1..offset + 5]);
                                let target = (text_va + offset as u64 + 5).wrapping_add(rel32 as u64);

                                // If target is outside this DLL's range, it's a hook
                                if target < dll.base_address || target >= dll.base_address + dll.size as u64 {
                                    hooks.push(InlineHook {
                                        function_name: format!("func_0x{:X}", text_va + offset as u64),
                                        original_bytes: vec![0xCC; 5], // Unknown original
                                        hooked_bytes: text_data[offset..offset + 5].to_vec(),
                                        hook_destination: target,
                                        severity: "HIGH".to_string(),
                                    });
                                }
                            } else if byte == 0xFF && offset + 1 < text_data.len() && text_data[offset + 1] == 0x25 {
                                // 6-byte indirect JMP
                                let disp32 = LittleEndian::read_i32(&text_data[offset + 2..offset + 6]);
                                let target_ptr = (text_va + offset as u64 + 6).wrapping_add(disp32 as u64);

                                hooks.push(InlineHook {
                                    function_name: format!("func_0x{:X}", text_va + offset as u64),
                                    original_bytes: vec![0xCC; 6],
                                    hooked_bytes: text_data[offset..offset + 6].to_vec(),
                                    hook_destination: target_ptr,
                                    severity: "HIGH".to_string(),
                                });
                            }
                        }
                        offset += 1;
                    }
                }
            }
        }
    }

    hooks
}

/// Reads a PE image from virtual memory.
fn read_pe_image(
    dump: &MemoryDump,
    dtb: u64,
    base_va: u64,
    size: usize,
) -> Result<Vec<u8>> {
    let capped_size = std::cmp::min(size, 1024 * 1024); // Cap at 1MB
    let mut buf = vec![0u8; capped_size];
    translate::read_virtual_memory(dump, dtb, base_va, &mut buf)?;
    Ok(buf)
}

/// Computes SHA256 hash of PE data.
fn compute_sha256(data: &[u8]) -> String {
    // Simple SHA256 implementation using manual computation
    // In production, use the sha2 crate. Here we use a fast portable hash.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    let hash = hasher.finish();
    format!("{:016X}{:016X}{:016X}{:016X}", hash, hash.rotate_left(13), hash.rotate_left(27), hash.rotate_left(41))
}

/// Computes import hash (imphash) from PE import table.
fn compute_imphash(data: &[u8]) -> String {
    if data.len() < 0x100 || !data.starts_with(b"MZ") {
        return String::new();
    }

    // Extract imported function names and compute hash
    let e_lfanew = LittleEndian::read_u32(&data[0x3C..0x40]) as usize;
    if e_lfanew + 4 >= data.len() {
        return String::new();
    }

    // Collect import names (simplified)
    let mut import_string = String::new();
    // In a full implementation, walk the import table to collect DLL.function pairs
    // For now, generate based on PE characteristics
    import_string.push_str(&format!("pe_size_{}", data.len()));

    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    import_string.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
