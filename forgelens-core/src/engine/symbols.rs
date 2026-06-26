use byteorder::ByteOrder;
use std::collections::HashMap;

/// Represents a resolved symbol.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SymbolInfo {
    pub name: String,
    pub address: u64,
    pub module: String,
    pub type_info: String,
    pub size: Option<u32>,
}

/// Known Windows kernel structure offsets for different builds.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KernelOffsets {
    pub build_number: u32,
    pub eprocess_image_file_name: u32,
    pub eprocess_unique_process_id: u32,
    pub eprocess_inherited_from: u32,
    pub eprocess_active_process_links: u32,
    pub eprocess_directory_table_base: u32,
    pub eprocess_peb: u32,
    pub eprocess_create_time: u32,
    pub eprocess_token: u32,
    pub eprocess_wow64process: u32,
    pub eprocess_vadroot: u32,
    pub eprocess_object_table: u32,
    pub ethread_cid: u32,
    pub ethread_start_address: u32,
    pub ethread_initial_stack: u32,
    pub ethread_teb: u32,
    pub kuser_shared_data: u64,
    pub peb_ldr: u32,
    pub peb_process_parameters: u32,
    pub ldr_in_load_order: u32,
    pub ldr_entry_dll_base: u32,
    pub ldr_entry_size_of_image: u32,
    pub ldr_entry_full_dll_name: u32,
    pub ldr_entry_base_dll_name: u32,
}

/// Symbol resolution engine that manages lookups and caching.
pub struct SymbolResolver {
    /// Cached symbol lookups: (module, name) -> address
    symbol_cache: HashMap<(String, String), u64>,
    /// Reverse cache: address -> (module, name)
    reverse_cache: HashMap<u64, (String, String)>,
    /// Kernel offsets for the detected build
    kernel_offsets: Option<KernelOffsets>,
    /// Module base addresses
    module_bases: HashMap<String, (u64, u32)>, // name -> (base, size)
}

impl SymbolResolver {
    pub fn new() -> Self {
        Self {
            symbol_cache: HashMap::new(),
            reverse_cache: HashMap::new(),
            kernel_offsets: None,
            module_bases: HashMap::new(),
        }
    }

    /// Initializes the resolver with a Windows build number.
    pub fn init_for_build(&mut self, build_number: u32) {
        self.kernel_offsets = Some(get_offsets_for_build(build_number));
    }

    /// Returns the kernel offsets for the current build.
    pub fn get_kernel_offsets(&self) -> Option<&KernelOffsets> {
        self.kernel_offsets.as_ref()
    }

    /// Registers a module and its base address for symbol resolution.
    pub fn register_module(&mut self, name: &str, base: u64, size: u32) {
        self.module_bases.insert(name.to_lowercase(), (base, size));
    }

    /// Resolves a symbol name to an address within a module.
    pub fn resolve(&self, module: &str, name: &str) -> Option<u64> {
        let key = (module.to_lowercase(), name.to_string());
        self.symbol_cache.get(&key).copied()
    }

    /// Looks up what symbol is at a given address.
    pub fn lookup_address(&self, address: u64) -> Option<SymbolInfo> {
        // Check reverse cache first
        if let Some((module, name)) = self.reverse_cache.get(&address) {
            return Some(SymbolInfo {
                name: name.clone(),
                address,
                module: module.clone(),
                type_info: "Function".to_string(),
                size: None,
            });
        }

        // Check which module the address falls in
        for (mod_name, (base, size)) in &self.module_bases {
            if address >= *base && address < base + *size as u64 {
                return Some(SymbolInfo {
                    name: format!("{}+0x{:X}", mod_name, address - base),
                    address,
                    module: mod_name.clone(),
                    type_info: "Offset".to_string(),
                    size: None,
                });
            }
        }

        None
    }

    /// Adds a symbol to the cache.
    pub fn add_symbol(&mut self, module: &str, name: &str, address: u64) {
        let key = (module.to_lowercase(), name.to_string());
        self.symbol_cache.insert(key, address);
        self.reverse_cache.insert(address, (module.to_lowercase(), name.to_string()));
    }

    /// Loads Windows kernel symbols from known offsets.
    pub fn load_windows_kernel_symbols(&mut self, ntoskrnl_base: u64) {
        let common_exports = [
            ("PsActiveProcessHead", 0x3A0A10u64),
            ("PsLoadedModuleList", 0x3A2C30),
            ("PsInitialSystemProcess", 0x3A0A00),
            ("KeServiceDescriptorTable", 0x3A1D80),
            ("KiServiceTable", 0x2C8600),
            ("MmNonPagedPoolStart", 0x3A1420),
            ("ObpRootDirectoryObject", 0x3A0540),
            ("CmpRegistryRootKey", 0x3CC420),
            ("KdDebuggerDataBlock", 0x3A3F90),
            ("NtBuildNumber", 0x3A0A38),
        ];

        for (name, rva) in &common_exports {
            self.add_symbol("ntoskrnl.exe", name, ntoskrnl_base + rva);
        }
    }

    /// Returns all registered modules.
    pub fn get_modules(&self) -> Vec<(String, u64, u32)> {
        self.module_bases.iter()
            .map(|(name, (base, size))| (name.clone(), *base, *size))
            .collect()
    }

    /// Gets the total number of cached symbols.
    pub fn symbol_count(&self) -> usize {
        self.symbol_cache.len()
    }
}

/// Returns known EPROCESS/ETHREAD offsets for a given Windows build number.
pub fn get_offsets_for_build(build_number: u32) -> KernelOffsets {
    match build_number {
        // Windows 11 23H2 (Build 22631)
        22621..=22631 => KernelOffsets {
            build_number,
            eprocess_image_file_name: 0x5A8,
            eprocess_unique_process_id: 0x440,
            eprocess_inherited_from: 0x540,
            eprocess_active_process_links: 0x448,
            eprocess_directory_table_base: 0x28,
            eprocess_peb: 0x550,
            eprocess_create_time: 0x4D0,
            eprocess_token: 0x4B8,
            eprocess_wow64process: 0x448,
            eprocess_vadroot: 0x7D8,
            eprocess_object_table: 0x570,
            ethread_cid: 0x478,
            ethread_start_address: 0x620,
            ethread_initial_stack: 0x28,
            ethread_teb: 0xF0,
            kuser_shared_data: 0xFFFFF78000000000,
            peb_ldr: 0x18,
            peb_process_parameters: 0x20,
            ldr_in_load_order: 0x10,
            ldr_entry_dll_base: 0x30,
            ldr_entry_size_of_image: 0x40,
            ldr_entry_full_dll_name: 0x48,
            ldr_entry_base_dll_name: 0x58,
        },
        // Windows 10 21H2/22H2 (Build 19044/19045)
        19041..=19045 => KernelOffsets {
            build_number,
            eprocess_image_file_name: 0x5A8,
            eprocess_unique_process_id: 0x440,
            eprocess_inherited_from: 0x540,
            eprocess_active_process_links: 0x448,
            eprocess_directory_table_base: 0x28,
            eprocess_peb: 0x550,
            eprocess_create_time: 0x4D0,
            eprocess_token: 0x4B8,
            eprocess_wow64process: 0x448,
            eprocess_vadroot: 0x7D8,
            eprocess_object_table: 0x570,
            ethread_cid: 0x478,
            ethread_start_address: 0x620,
            ethread_initial_stack: 0x28,
            ethread_teb: 0xF0,
            kuser_shared_data: 0xFFFFF78000000000,
            peb_ldr: 0x18,
            peb_process_parameters: 0x20,
            ldr_in_load_order: 0x10,
            ldr_entry_dll_base: 0x30,
            ldr_entry_size_of_image: 0x40,
            ldr_entry_full_dll_name: 0x48,
            ldr_entry_base_dll_name: 0x58,
        },
        // Windows 10 1809 (Build 17763)
        17763 => KernelOffsets {
            build_number,
            eprocess_image_file_name: 0x450,
            eprocess_unique_process_id: 0x2E8,
            eprocess_inherited_from: 0x3E0,
            eprocess_active_process_links: 0x2F0,
            eprocess_directory_table_base: 0x28,
            eprocess_peb: 0x3F8,
            eprocess_create_time: 0x390,
            eprocess_token: 0x360,
            eprocess_wow64process: 0x2F8,
            eprocess_vadroot: 0x658,
            eprocess_object_table: 0x418,
            ethread_cid: 0x478,
            ethread_start_address: 0x620,
            ethread_initial_stack: 0x28,
            ethread_teb: 0xF0,
            kuser_shared_data: 0xFFFFF78000000000,
            peb_ldr: 0x18,
            peb_process_parameters: 0x20,
            ldr_in_load_order: 0x10,
            ldr_entry_dll_base: 0x30,
            ldr_entry_size_of_image: 0x40,
            ldr_entry_full_dll_name: 0x48,
            ldr_entry_base_dll_name: 0x58,
        },
        // Windows 7 SP1 (Build 7601)
        7600..=7601 => KernelOffsets {
            build_number,
            eprocess_image_file_name: 0x2E0,
            eprocess_unique_process_id: 0x180,
            eprocess_inherited_from: 0x290,
            eprocess_active_process_links: 0x188,
            eprocess_directory_table_base: 0x28,
            eprocess_peb: 0x338,
            eprocess_create_time: 0x200,
            eprocess_token: 0x208,
            eprocess_wow64process: 0x320,
            eprocess_vadroot: 0x448,
            eprocess_object_table: 0x200,
            ethread_cid: 0x3B8,
            ethread_start_address: 0x390,
            ethread_initial_stack: 0x28,
            ethread_teb: 0xB8,
            kuser_shared_data: 0xFFFFF78000000000,
            peb_ldr: 0x18,
            peb_process_parameters: 0x20,
            ldr_in_load_order: 0x10,
            ldr_entry_dll_base: 0x30,
            ldr_entry_size_of_image: 0x40,
            ldr_entry_full_dll_name: 0x48,
            ldr_entry_base_dll_name: 0x58,
        },
        // Default fallback to Win10 20H2+ offsets
        _ => KernelOffsets {
            build_number,
            eprocess_image_file_name: 0x5A8,
            eprocess_unique_process_id: 0x440,
            eprocess_inherited_from: 0x540,
            eprocess_active_process_links: 0x448,
            eprocess_directory_table_base: 0x28,
            eprocess_peb: 0x550,
            eprocess_create_time: 0x4D0,
            eprocess_token: 0x4B8,
            eprocess_wow64process: 0x448,
            eprocess_vadroot: 0x7D8,
            eprocess_object_table: 0x570,
            ethread_cid: 0x478,
            ethread_start_address: 0x620,
            ethread_initial_stack: 0x28,
            ethread_teb: 0xF0,
            kuser_shared_data: 0xFFFFF78000000000,
            peb_ldr: 0x18,
            peb_process_parameters: 0x20,
            ldr_in_load_order: 0x10,
            ldr_entry_dll_base: 0x30,
            ldr_entry_size_of_image: 0x40,
            ldr_entry_full_dll_name: 0x48,
            ldr_entry_base_dll_name: 0x58,
        },
    }
}

/// PDB header parsing support (minimal).
#[derive(Debug, Clone)]
pub struct PdbInfo {
    pub guid: String,
    pub age: u32,
    pub pdb_path: String,
}

/// Extracts PDB debug information from a PE header in memory.
pub fn extract_pdb_info(pe_data: &[u8]) -> Option<PdbInfo> {
    if pe_data.len() < 0x100 || !pe_data.starts_with(b"MZ") {
        return None;
    }

    let e_lfanew = byteorder::LittleEndian::read_u32(&pe_data[0x3C..0x40]) as usize;
    if e_lfanew + 24 >= pe_data.len() {
        return None;
    }

    // Check PE signature
    if &pe_data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }

    let opt_off = e_lfanew + 24;
    let magic = byteorder::LittleEndian::read_u16(&pe_data[opt_off..opt_off + 2]);

    // Debug Directory is data directory index 6
    let data_dir_base = if magic == 0x20B {
        opt_off + 0x70
    } else {
        opt_off + 0x60
    };

    let debug_dir_offset = data_dir_base + 6 * 8; // 6th entry
    if debug_dir_offset + 8 > pe_data.len() {
        return None;
    }

    let debug_rva = byteorder::LittleEndian::read_u32(&pe_data[debug_dir_offset..debug_dir_offset + 4]) as usize;
    let _debug_size = byteorder::LittleEndian::read_u32(&pe_data[debug_dir_offset + 4..debug_dir_offset + 8]) as usize;

    if debug_rva == 0 || debug_rva + 28 > pe_data.len() {
        return None;
    }

    // IMAGE_DEBUG_DIRECTORY structure (28 bytes)
    // +0x00: Characteristics (u32)
    // +0x04: TimeDateStamp (u32)
    // +0x08: MajorVersion (u16)
    // +0x0A: MinorVersion (u16)
    // +0x0C: Type (u32) - 2 = IMAGE_DEBUG_TYPE_CODEVIEW
    // +0x10: SizeOfData (u32)
    // +0x14: AddressOfRawData (u32)
    // +0x18: PointerToRawData (u32)

    let debug_type = byteorder::LittleEndian::read_u32(&pe_data[debug_rva + 0x0C..debug_rva + 0x10]);
    if debug_type != 2 {
        // Not CodeView
        return None;
    }

    let raw_data_ptr = byteorder::LittleEndian::read_u32(&pe_data[debug_rva + 0x18..debug_rva + 0x1C]) as usize;
    if raw_data_ptr + 24 > pe_data.len() {
        return None;
    }

    // CodeView signature: "RSDS" (0x53445352)
    if &pe_data[raw_data_ptr..raw_data_ptr + 4] != b"RSDS" {
        return None;
    }

    // GUID (16 bytes at offset 4)
    let guid_bytes = &pe_data[raw_data_ptr + 4..raw_data_ptr + 20];
    let guid = format!(
        "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        byteorder::LittleEndian::read_u32(&guid_bytes[0..4]),
        byteorder::LittleEndian::read_u16(&guid_bytes[4..6]),
        byteorder::LittleEndian::read_u16(&guid_bytes[6..8]),
        guid_bytes[8], guid_bytes[9], guid_bytes[10], guid_bytes[11],
        guid_bytes[12], guid_bytes[13], guid_bytes[14], guid_bytes[15],
    );

    // Age (u32 at offset 20)
    let age = byteorder::LittleEndian::read_u32(&pe_data[raw_data_ptr + 20..raw_data_ptr + 24]);

    // PDB path (null-terminated string at offset 24)
    let path_start = raw_data_ptr + 24;
    let path_end = pe_data[path_start..].iter()
        .position(|&b| b == 0)
        .map(|p| path_start + p)
        .unwrap_or(std::cmp::min(path_start + 260, pe_data.len()));
    let pdb_path = String::from_utf8_lossy(&pe_data[path_start..path_end]).to_string();

    Some(PdbInfo {
        guid,
        age,
        pdb_path,
    })
}
