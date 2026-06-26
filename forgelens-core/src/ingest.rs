use std::fs::File;
use std::path::Path;
use memmap2::Mmap;
use crate::{Result, ForgeLensError};
use byteorder::{ByteOrder, LittleEndian, BigEndian};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PhysicalMemoryRange {
    pub start_address: u64,
    pub size: u64,
    pub file_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DumpFormat {
    Raw,
    Lime,
    ElfCore,
    Avml,
    WindowsCrashDump,
    VmwareVmem,
    VirtualBox,
    HyperV,
    Hibernation,
    WinPmem,
}

pub struct MemoryDump {
    pub format: DumpFormat,
    pub memory_map: Vec<PhysicalMemoryRange>,
    mmap: Mmap,
}

impl MemoryDump {
    /// Loads a memory dump from a file path and auto-detects its format.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        if mmap.is_empty() {
            return Err(ForgeLensError::InvalidFormat("Empty file".into()));
        }

        let (format, memory_map) = Self::detect_and_map(&mmap)?;

        Ok(Self {
            format,
            memory_map,
            mmap,
        })
    }

    /// Returns the raw size of the memory dump file.
    pub fn file_size(&self) -> usize {
        self.mmap.len()
    }

    /// Read bytes directly from a specific physical address if it matches our physical memory mapping.
    pub fn read_physical(&self, physical_addr: u64, buf: &mut [u8]) -> Result<()> {
        let size = buf.len() as u64;
        for range in &self.memory_map {
            if physical_addr >= range.start_address && (physical_addr + size) <= (range.start_address + range.size) {
                let offset = range.file_offset + (physical_addr - range.start_address);
                let offset_usize = offset as usize;
                let end_usize = (offset + size) as usize;
                if end_usize <= self.mmap.len() {
                    buf.copy_from_slice(&self.mmap[offset_usize..end_usize]);
                    return Ok(());
                }
            }
        }
        Err(ForgeLensError::TranslationError(format!(
            "Physical address 0x{:X} (len: {}) is not mapped in memory dump",
            physical_addr, size
        )))
    }

    /// Helper to read a primitive value at a physical address.
    pub fn read_u64(&self, physical_addr: u64) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.read_physical(physical_addr, &mut buf)?;
        Ok(LittleEndian::read_u64(&buf))
    }

    pub fn read_u32(&self, physical_addr: u64) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read_physical(physical_addr, &mut buf)?;
        Ok(LittleEndian::read_u32(&buf))
    }

    pub fn read_u8(&self, physical_addr: u64) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.read_physical(physical_addr, &mut buf)?;
        Ok(buf[0])
    }

    pub fn read_u16(&self, physical_addr: u64) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.read_physical(physical_addr, &mut buf)?;
        Ok(LittleEndian::read_u16(&buf))
    }

    /// Returns a slice of the raw memory-mapped data at a file offset.
    pub fn raw_slice(&self, file_offset: usize, len: usize) -> Option<&[u8]> {
        if file_offset + len <= self.mmap.len() {
            Some(&self.mmap[file_offset..file_offset + len])
        } else {
            None
        }
    }

    /// Scans raw physical memory for a pattern.
    pub fn scan_physical<F>(&self, mut callback: F) -> Result<()>
    where
        F: FnMut(u64, &[u8]) -> bool, // (Physical address, Page data) -> Continue
    {
        const PAGE_SIZE: usize = 4096;
        for range in &self.memory_map {
            let mut offset = range.file_offset;
            let mut addr = range.start_address;
            let end_addr = range.start_address + range.size;

            while addr < end_addr {
                let remaining = (end_addr - addr) as usize;
                let chunk_size = std::cmp::min(PAGE_SIZE, remaining);
                let slice = &self.mmap[offset as usize..(offset as usize + chunk_size)];
                if !callback(addr, slice) {
                    break;
                }
                addr += chunk_size as u64;
                offset += chunk_size as u64;
            }
        }
        Ok(())
    }

    fn detect_and_map(mmap: &[u8]) -> Result<(DumpFormat, Vec<PhysicalMemoryRange>)> {
        // Detect LiME: Magic word 'EML' (0x4c4d4558) or big-endian variant
        if mmap.len() >= 32 {
            let magic = LittleEndian::read_u32(&mmap[0..4]);
            if magic == 0x4c4d4558 || magic == 0x58454d4c {
                return Self::parse_lime(mmap, magic == 0x58454d4c);
            }
        }

        // Detect ELF core dump (starts with 0x7F 'E' 'L' 'F')
        if mmap.len() >= 64 && mmap.starts_with(b"\x7fELF") {
            return Self::parse_elf_core(mmap);
        }

        // Detect AVML (starts with 'AVML' or has JSON metadata tags)
        if mmap.len() >= 32 && mmap.starts_with(b"AVML") {
            return Self::parse_avml(mmap);
        }

        // Detect Windows Crash Dump: Check if starts with "PAGE" or "PAGEDU64"
        if mmap.len() >= 0x2000 {
            let sig = &mmap[0..4];
            if sig == b"PAGE" || sig == b"MDMP" {
                return Self::parse_windows_crashdump(mmap);
            }
        }

        // Detect VMware .vmem files (raw linear memory, but check for vmss/vmsn companion markers)
        // VMware VMEM is essentially raw, but may have a VMDK-like header or be accompanied by .vmss
        // Check for VMware snapshot header: 0xBED2BED2 or 0xD2BED2BE
        if mmap.len() >= 8 {
            let vm_magic = LittleEndian::read_u32(&mmap[0..4]);
            if vm_magic == 0xBED2BED2 || vm_magic == 0xD2BED2BE {
                let raw_range = PhysicalMemoryRange {
                    start_address: 0,
                    size: mmap.len() as u64,
                    file_offset: 0,
                };
                return Ok((DumpFormat::VmwareVmem, vec![raw_range]));
            }
        }

        // Detect Windows Hibernation file (hiberfil.sys): starts with "hibr" or "HIBR" or "wake"
        if mmap.len() >= 8 {
            if &mmap[0..4] == b"hibr" || &mmap[0..4] == b"HIBR" || &mmap[0..4] == b"wake" || &mmap[0..4] == b"WAKE" {
                // Hibernation files are compressed; treat as raw with metadata offset
                let raw_range = PhysicalMemoryRange {
                    start_address: 0,
                    size: mmap.len() as u64,
                    file_offset: 0x1000, // Skip header page
                };
                return Ok((DumpFormat::Hibernation, vec![raw_range]));
            }
        }

        // Detect WinPMEM format: has "PMEM" signature at offset 0
        if mmap.len() >= 32 && &mmap[0..4] == b"PMEM" {
            let raw_range = PhysicalMemoryRange {
                start_address: 0,
                size: mmap.len() as u64 - 4,
                file_offset: 4,
            };
            return Ok((DumpFormat::WinPmem, vec![raw_range]));
        }

        // Detect Hyper-V VMRS format: check for VMRS signature
        if mmap.len() >= 16 && &mmap[0..4] == b"VMRS" {
            let raw_range = PhysicalMemoryRange {
                start_address: 0,
                size: mmap.len() as u64,
                file_offset: 0x1000,
            };
            return Ok((DumpFormat::HyperV, vec![raw_range]));
        }

        // Detect VirtualBox core dump format (ELF with VirtualBox note sections)
        // Already handled by ELF parser above, but let's tag it
        if mmap.len() >= 64 && mmap.starts_with(b"\x7fELF") {
            // Check for VirtualBox note
            if mmap.windows(10).any(|w| w.starts_with(b"VBOX")) {
                return Self::parse_elf_core(mmap).map(|(_, ranges)| (DumpFormat::VirtualBox, ranges));
            }
        }

        // Default: Treat as Raw linear address space
        let raw_range = PhysicalMemoryRange {
            start_address: 0,
            size: mmap.len() as u64,
            file_offset: 0,
        };
        Ok((DumpFormat::Raw, vec![raw_range]))
    }

    fn parse_lime(mmap: &[u8], big_endian: bool) -> Result<(DumpFormat, Vec<PhysicalMemoryRange>)> {
        let mut ranges = Vec::new();
        let mut offset = 0;

        while offset + 32 <= mmap.len() {
            let magic = if big_endian {
                BigEndian::read_u32(&mmap[offset..offset+4])
            } else {
                LittleEndian::read_u32(&mmap[offset..offset+4])
            };

            if magic != 0x4c4d4558 && magic != 0x58454d4c {
                // Done parsing or reached padding/alignment boundaries
                break;
            }

            let version = if big_endian {
                BigEndian::read_u32(&mmap[offset+4..offset+8])
            } else {
                LittleEndian::read_u32(&mmap[offset+4..offset+8])
            };

            if version != 1 {
                return Err(ForgeLensError::InvalidFormat(format!("Unsupported LiME version: {}", version)));
            }

            let start = if big_endian {
                BigEndian::read_u64(&mmap[offset+8..offset+16])
            } else {
                LittleEndian::read_u64(&mmap[offset+8..offset+16])
            };

            let end = if big_endian {
                BigEndian::read_u64(&mmap[offset+16..offset+24])
            } else {
                LittleEndian::read_u64(&mmap[offset+16..offset+24])
            };

            let size = end - start + 1;
            let file_offset = (offset + 32) as u64;

            ranges.push(PhysicalMemoryRange {
                start_address: start,
                size,
                file_offset,
            });

            offset += 32 + size as usize;
        }

        if ranges.is_empty() {
            return Err(ForgeLensError::InvalidFormat("LiME file contained no valid memory ranges".into()));
        }

        Ok((DumpFormat::Lime, ranges))
    }

    fn parse_elf_core(mmap: &[u8]) -> Result<(DumpFormat, Vec<PhysicalMemoryRange>)> {
        // Parse basic ELF header and program headers (PHDRs) to locate LOAD segments (physical ranges)
        // Check 64-bit or 32-bit ELF. Volatile dumps are usually 64-bit ELF core dumps.
        if mmap[4] != 2 {
            return Err(ForgeLensError::InvalidFormat("Only 64-bit ELF Core dumps are supported".into()));
        }

        let phoff = LittleEndian::read_u64(&mmap[32..40]) as usize;
        let phnum = LittleEndian::read_u16(&mmap[56..58]) as usize;
        let phentsize = LittleEndian::read_u16(&mmap[54..56]) as usize;

        let mut ranges = Vec::new();
        for i in 0..phnum {
            let entry_offset = phoff + i * phentsize;
            if entry_offset + 56 > mmap.len() {
                break;
            }

            let p_type = LittleEndian::read_u32(&mmap[entry_offset..entry_offset+4]);
            if p_type == 1 { // PT_LOAD
                let p_offset = LittleEndian::read_u64(&mmap[entry_offset+8..entry_offset+16]);
                let p_paddr = LittleEndian::read_u64(&mmap[entry_offset+24..entry_offset+32]);
                let p_filesz = LittleEndian::read_u64(&mmap[entry_offset+40..entry_offset+48]);

                if p_filesz > 0 && p_offset + p_filesz <= mmap.len() as u64 {
                    ranges.push(PhysicalMemoryRange {
                        start_address: p_paddr,
                        size: p_filesz,
                        file_offset: p_offset,
                    });
                }
            }
        }

        if ranges.is_empty() {
            // Fall back to Raw if PT_LOAD segments are missing
            let raw_range = PhysicalMemoryRange {
                start_address: 0,
                size: mmap.len() as u64,
                file_offset: 0,
            };
            return Ok((DumpFormat::ElfCore, vec![raw_range]));
        }

        Ok((DumpFormat::ElfCore, ranges))
    }

    fn parse_avml(mmap: &[u8]) -> Result<(DumpFormat, Vec<PhysicalMemoryRange>)> {
        // AVML files have a header starting with "AVML" followed by metadata, or end-of-file metadata.
        // Let's create a single range representing the AVML payload.
        // Usually, AVML versions load physical memory starting at 0.
        let raw_range = PhysicalMemoryRange {
            start_address: 0,
            size: mmap.len() as u64 - 4, // Exclude magic bytes or meta trailing
            file_offset: 4,
        };
        Ok((DumpFormat::Avml, vec![raw_range]))
    }

    fn parse_windows_crashdump(mmap: &[u8]) -> Result<(DumpFormat, Vec<PhysicalMemoryRange>)> {
        // Windows DMP parsing:
        // A complete crash dump has a DMP_HEADER64 at offset 0.
        // DMP_HEADER64 signature is "PAGEDU64" or "PAGE"
        // It has a PhysicalMemoryBlock containing memory runs.
        // Let's check for standard header signatures.
        // DMP_HEADER64 layout:
        // 0x00: Signature (u32) "PAGE" (0x45474150)
        // 0x04: ValidDump (u32) "DU64" (0x34365544)
        // 0x08: MajorVersion (u32)
        // 0x0c: MinorVersion (u32)
        // 0x10: DirectoryTableBase (u64) -> CR3!
        // ...
        // 0x320: PhysicalMemoryBlock (DMP_PHYSICAL_MEMORY_BLOCK)
        // DMP_PHYSICAL_MEMORY_BLOCK layout:
        // 0x00: NumberOfRuns (u32)
        // 0x08: NumberOfPages (u64)
        // 0x10: RunArray of [PageStart, PageCount]
        let sig = LittleEndian::read_u32(&mmap[0..4]);
        let validsig = LittleEndian::read_u32(&mmap[4..8]);

        if sig == 0x45474150 && validsig == 0x34365544 { // PAGE & DU64 (64-bit dump)
            let num_runs = LittleEndian::read_u32(&mmap[0x320..0x324]) as usize;
            let mut ranges = Vec::new();
            let mut current_file_offset = 0x2000; // Typically data pages start at 0x2000 (Header is 8KB)

            for i in 0..num_runs {
                let entry_offset = 0x328 + i * 16;
                if entry_offset + 16 > mmap.len() {
                    break;
                }
                let base_page = LittleEndian::read_u64(&mmap[entry_offset..entry_offset+8]);
                let page_count = LittleEndian::read_u64(&mmap[entry_offset+8..entry_offset+16]);

                let start_address = base_page * 4096;
                let size = page_count * 4096;

                if current_file_offset + size <= mmap.len() as u64 {
                    ranges.push(PhysicalMemoryRange {
                        start_address,
                        size,
                        file_offset: current_file_offset,
                    });
                    current_file_offset += size;
                }
            }

            if !ranges.is_empty() {
                return Ok((DumpFormat::WindowsCrashDump, ranges));
            }
        }

        // Fallback: raw
        let raw_range = PhysicalMemoryRange {
            start_address: 0,
            size: mmap.len() as u64,
            file_offset: 0,
        };
        Ok((DumpFormat::WindowsCrashDump, vec![raw_range]))
    }
}
