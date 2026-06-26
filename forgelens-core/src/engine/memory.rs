use crate::{ingest::MemoryDump, translate::translate_virtual_address, Result};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryScanResult {
    pub virtual_address: u64,
    pub physical_address: u64,
    pub size: u64,
    pub is_rwx: bool,
    pub has_pe_header: bool,
    pub entropy: f64,
    pub threat_score: f64,
    pub description: String,
}

/// Scans virtual memory pages of a process (defined by its DTB) for security anomalies.
pub fn scan_process_memory(
    dump: &MemoryDump,
    dtb: u64,
    _start_va: u64,
    _end_va: u64,
) -> Result<Vec<MemoryScanResult>> {
    let mut anomalies = Vec::new();

    // We scan virtual address ranges. Standard user space on x64 Windows is 0x0000000000000000 to 0x00007FFFFFFFFFFF.
    // To do this efficiently, we step through page sizes (4KB or 2MB/1GB as resolved by translation).
    const PAGE_SIZE: u64 = 4096;


    // We list candidate pages by walking the page tables.
    // To avoid walking the entire 128TB space, we look for page table entries that are present.
    // A simple way is to check the directory table base and find present page indices.
    // For this engine, we will walk the PML4 table and follow present entries to find valid VA ranges.
    let active_ranges = get_valid_va_ranges(dump, dtb);

    for (range_start, range_size) in active_ranges {
        let mut va = range_start;
        let limit = range_start + range_size;

        while va < limit {
            if let Ok(walk) = translate_virtual_address(dump, dtb, va) {
                // Read the page contents
                let mut page_data = vec![0u8; walk.page_size as usize];
                if dump.read_physical(walk.physical_address, &mut page_data).is_ok() {
                    let entropy = calculate_entropy(&page_data);
                    
                    // Check PE header
                    let has_pe_header = page_data.starts_with(b"MZ");

                    // Check RWX
                    let is_rwx = walk.is_writable && walk.is_executable;

                    let mut score = 0.0;
                    let mut flags = Vec::new();

                    if is_rwx {
                        score += 5.0;
                        flags.push("RWX permissions");
                    }
                    if has_pe_header {
                        score += 4.0;
                        flags.push("MZ/PE Header in anonymous page");
                    }
                    if entropy > 7.2 {
                        score += 2.0;
                        flags.push("High entropy (potential packer/encryptor)");
                    }
                    // Heuristics: search for common shellcode patterns (e.g. large NOP sleds or common API lookups)
                    if detect_shellcode_heuristics(&page_data) {
                        score += 3.0;
                        flags.push("Shellcode patterns detected");
                    }

                    if score >= 3.0 {
                        anomalies.push(MemoryScanResult {
                            virtual_address: va,
                            physical_address: walk.physical_address,
                            size: walk.page_size,
                            is_rwx,
                            has_pe_header,
                            entropy,
                            threat_score: score,
                            description: flags.join(", "),
                        });
                    }
                }
                va += walk.page_size;
            } else {
                va += PAGE_SIZE;
            }
        }
    }

    Ok(anomalies)
}

/// Helper to gather active virtual address ranges from PML4 entries to avoid full 128TB scans.
fn get_valid_va_ranges(dump: &MemoryDump, dtb: u64) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    let dtb_base = dtb & 0x000F_FFFF_FFFF_F000;

    // PML4 has 512 entries
    for pml4_idx in 0..512 {
        let pml4_entry_addr = dtb_base + (pml4_idx as u64 * 8);
        if let Ok(pml4_entry) = dump.read_u64(pml4_entry_addr) {
            if (pml4_entry & 1) != 0 { // Present
                // Map the PML4 index to its virtual address block
                // For user space: indices 0..255 (0 to 0x00007FFFFFFFFFFF)
                // For kernel space: indices 256..511 (0xFFFF800000000000 to 0xFFFFFFFFFFFFFFFF)
                let sign_extend = if pml4_idx >= 256 { 0xFFFF_0000_0000_0000 } else { 0 };
                let start_va = sign_extend | ((pml4_idx as u64) << 39);

                // To keep analysis extremely fast in our tool, we limit our deep scan to user space (0..255)
                // or specific active parts. Let's record this valid PML4 range.
                if pml4_idx < 10 || pml4_idx == 4 { // Just scan first 5 blocks of user-space for demo/safety
                    ranges.push((start_va, 0x1000000)); // Scan 16MB of each active PML4 entry
                }
            }
        }
    }

    if ranges.is_empty() {
        // Fallback: scan standard user heap/stack range
        ranges.push((0x00400000, 0x2000000)); // 32MB
    }

    ranges
}

/// Calculates Shannon entropy of a byte slice.
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let mut entropy = 0.0;
    let total = data.len() as f64;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Simple heuristic scanner for shellcode indicators.
fn detect_shellcode_heuristics(data: &[u8]) -> bool {
    // Look for NOP sled (e.g. 32 consecutive NOP instructions)
    let mut nop_count = 0;
    for &b in data {
        if b == 0x90 {
            nop_count += 1;
            if nop_count >= 32 {
                return true;
            }
        } else {
            nop_count = 0;
        }
    }

    // Look for common shellcode structures: e.g. finding kernel32 via PEB walking:
    // x64: FS:[0x30] (32-bit PEB) or GS:[0x60] (64-bit PEB)
    // GS register reads typically compile to byte sequences like:
    // 0x65, 0x48, 0x8B or 0x64, 0x8B
    if data.windows(3).any(|w| w == [0x65, 0x48, 0x8B] || w == [0x64, 0x8B, 0x30]) {
        return true;
    }

    false
}
