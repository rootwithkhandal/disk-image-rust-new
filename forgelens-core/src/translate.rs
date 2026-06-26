use crate::{ingest::MemoryDump, Result, ForgeLensError};

const PAGE_SIZE: u64 = 4096;
const PRESENT_FLAG: u64 = 1 << 0;
const PAGE_SIZE_FLAG: u64 = 1 << 7; // PS flag (large pages)

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct PageWalkResult {
    pub physical_address: u64,
    pub page_size: u64,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_user: bool,
}

/// Helper to extract parts of a virtual address for x86_64 4-level paging.
pub struct VirtualAddress(pub u64);

impl VirtualAddress {
    pub fn pml4_index(&self) -> usize {
        ((self.0 >> 39) & 0x1FF) as usize
    }

    pub fn pdpt_index(&self) -> usize {
        ((self.0 >> 30) & 0x1FF) as usize
    }

    pub fn pd_index(&self) -> usize {
        ((self.0 >> 21) & 0x1FF) as usize
    }

    pub fn pt_index(&self) -> usize {
        ((self.0 >> 12) & 0x1FF) as usize
    }

    pub fn offset_4k(&self) -> u64 {
        self.0 & 0xFFF
    }

    pub fn offset_2m(&self) -> u64 {
        self.0 & 0x1F_FFFF
    }

    pub fn offset_1g(&self) -> u64 {
        self.0 & 0x3FFF_FFFF
    }
}

/// Translates a virtual address to a physical address using a given Directory Table Base (CR3).
pub fn translate_virtual_address(
    dump: &MemoryDump,
    dtb: u64,
    virtual_address: u64,
) -> Result<PageWalkResult> {
    let va = VirtualAddress(virtual_address);
    let dtb_base = dtb & 0x000F_FFFF_FFFF_F000; // Clear lower flags of CR3

    // 1. PML4 Page Directory Walk
    let pml4_entry_addr = dtb_base + (va.pml4_index() as u64 * 8);
    let pml4_entry = dump.read_u64(pml4_entry_addr).map_err(|_| {
        ForgeLensError::TranslationError(format!("Failed to read PML4 Entry at physical 0x{:X}", pml4_entry_addr))
    })?;

    if (pml4_entry & PRESENT_FLAG) == 0 {
        return Err(ForgeLensError::TranslationError(format!(
            "PML4 Entry not present for VA 0x{:X}", virtual_address
        )));
    }

    let pml4_flags = parse_flags(pml4_entry);

    // 2. PDPT Walk
    let pdpt_base = pml4_entry & 0x000F_FFFF_FFFF_F000;
    let pdpt_entry_addr = pdpt_base + (va.pdpt_index() as u64 * 8);
    let pdpt_entry = dump.read_u64(pdpt_entry_addr).map_err(|_| {
        ForgeLensError::TranslationError(format!("Failed to read PDPT Entry at physical 0x{:X}", pdpt_entry_addr))
    })?;

    if (pdpt_entry & PRESENT_FLAG) == 0 {
        return Err(ForgeLensError::TranslationError(format!(
            "PDPT Entry not present for VA 0x{:X}", virtual_address
        )));
    }

    let pdpt_flags = combine_flags(pml4_flags, parse_flags(pdpt_entry));

    // Check if 1GB Page (PS flag in PDPT)
    if (pdpt_entry & PAGE_SIZE_FLAG) != 0 {
        let page_base = pdpt_entry & 0x000F_FFFF_C000_0000; // 1GB boundary
        let physical_address = page_base + va.offset_1g();
        return Ok(PageWalkResult {
            physical_address,
            page_size: 1024 * 1024 * 1024,
            is_executable: pdpt_flags.is_executable,
            is_writable: pdpt_flags.is_writable,
            is_user: pdpt_flags.is_user,
        });
    }

    // 3. Page Directory Walk
    let pd_base = pdpt_entry & 0x000F_FFFF_FFFF_F000;
    let pd_entry_addr = pd_base + (va.pd_index() as u64 * 8);
    let pd_entry = dump.read_u64(pd_entry_addr).map_err(|_| {
        ForgeLensError::TranslationError(format!("Failed to read PD Entry at physical 0x{:X}", pd_entry_addr))
    })?;

    if (pd_entry & PRESENT_FLAG) == 0 {
        return Err(ForgeLensError::TranslationError(format!(
            "PD Entry not present for VA 0x{:X}", virtual_address
        )));
    }

    let pd_flags = combine_flags(pdpt_flags, parse_flags(pd_entry));

    // Check if 2MB Page (PS flag in PD)
    if (pd_entry & PAGE_SIZE_FLAG) != 0 {
        let page_base = pd_entry & 0x000F_FFFF_FFE0_0000; // 2MB boundary
        let physical_address = page_base + va.offset_2m();
        return Ok(PageWalkResult {
            physical_address,
            page_size: 2 * 1024 * 1024,
            is_executable: pd_flags.is_executable,
            is_writable: pd_flags.is_writable,
            is_user: pd_flags.is_user,
        });
    }

    // 4. Page Table Walk (4KB standard page)
    let pt_base = pd_entry & 0x000F_FFFF_FFFF_F000;
    let pt_entry_addr = pt_base + (va.pt_index() as u64 * 8);
    let pt_entry = dump.read_u64(pt_entry_addr).map_err(|_| {
        ForgeLensError::TranslationError(format!("Failed to read PT Entry at physical 0x{:X}", pt_entry_addr))
    })?;

    if (pt_entry & PRESENT_FLAG) == 0 {
        return Err(ForgeLensError::TranslationError(format!(
            "PT Entry not present for VA 0x{:X}", virtual_address
        )));
    }

    let pt_flags = combine_flags(pd_flags, parse_flags(pt_entry));
    let page_base = pt_entry & 0x000F_FFFF_FFFF_F000;
    let physical_address = page_base + va.offset_4k();

    Ok(PageWalkResult {
        physical_address,
        page_size: PAGE_SIZE,
        is_executable: pt_flags.is_executable,
        is_writable: pt_flags.is_writable,
        is_user: pt_flags.is_user,
    })
}

/// Helper structure for tracking page permissions during translation.
#[derive(Debug, Clone, Copy)]
struct PageFlags {
    is_writable: bool,
    is_user: bool,
    is_executable: bool,
}

fn parse_flags(entry: u64) -> PageFlags {
    // x86_64 PTE Flags:
    // Bit 1: Writable (R/W)
    // Bit 2: User/Supervisor (U/S)
    // Bit 63: No-Execute (NX) (if supported and enabled)
    let is_writable = (entry & (1 << 1)) != 0;
    let is_user = (entry & (1 << 2)) != 0;
    let is_executable = (entry & (1u64 << 63)) == 0; // If NX bit is 0, it is executable

    PageFlags {
        is_writable,
        is_user,
        is_executable,
    }
}

fn combine_flags(parent: PageFlags, child: PageFlags) -> PageFlags {
    // Privileges are logical AND combined across levels:
    // Writable: only if all levels writable
    // User: only if all levels user
    // Executable: only if all levels executable (NX is logically ORed, so executable is ANDed)
    PageFlags {
        is_writable: parent.is_writable && child.is_writable,
        is_user: parent.is_user && child.is_user,
        is_executable: parent.is_executable && child.is_executable,
    }
}

/// Helper function to read virtual memory of arbitrary length.
pub fn read_virtual_memory(
    dump: &MemoryDump,
    dtb: u64,
    virtual_address: u64,
    buf: &mut [u8],
) -> Result<()> {
    let mut total_read = 0;
    let mut current_va = virtual_address;

    while total_read < buf.len() {
        let remaining = buf.len() - total_read;
        
        // Find how many bytes are left on the current page to prevent crossing boundaries
        let page_offset = current_va & (PAGE_SIZE - 1);
        let bytes_on_page = std::cmp::min(remaining as u64, PAGE_SIZE - page_offset) as usize;

        // Translate the current virtual address
        match translate_virtual_address(dump, dtb, current_va) {
            Ok(walk) => {
                let dest_slice = &mut buf[total_read..total_read + bytes_on_page];
                dump.read_physical(walk.physical_address, dest_slice)?;
            }
            Err(e) => {
                // Return translation error details
                return Err(ForgeLensError::TranslationError(format!(
                    "Translation failed at virtual address 0x{:X} during read of size {}: {}",
                    current_va, buf.len(), e
                )));
            }
        }

        total_read += bytes_on_page;
        current_va += bytes_on_page as u64;
    }

    Ok(())
}
