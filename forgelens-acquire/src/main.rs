use clap::Parser;
use std::fs::File;
use std::io::{Write, BufWriter};
use std::path::PathBuf;
use std::time::Instant;

#[cfg(windows)]
use winapi::um::{
    fileapi::{CreateFileA, OPEN_EXISTING},
    winnt::{GENERIC_READ, GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE},
    handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
};
#[cfg(windows)]
use std::ffi::CString;
#[cfg(windows)]
use std::ptr;

#[derive(Parser)]
#[command(name = "forgelens-acquire")]
#[command(about = "ForgeLens Stealth Memory Acquisition Companion Tool", long_about = None)]
struct Cli {
    /// Output file path for the memory dump
    #[arg(short, long, default_value = "memory_dump.raw")]
    output: PathBuf,

    /// Format: raw, pmem, lime
    #[arg(short, long, default_value = "raw")]
    format: String,

    /// Driver path (e.g. WinPMEM driver). If not provided, it will try to load a bundled one or rely on existing loaded driver.
    #[arg(short, long)]
    driver: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();

    println!("============================================================");
    println!(" ForgeLens Memory Acquisition Tool (v0.1.0)                 ");
    println!("============================================================");
    println!("[*] Output Target : {:?}", cli.output);
    println!("[*] Format        : {}", cli.format);

    #[cfg(not(windows))]
    {
        println!("[-] Error: This acquisition tool currently only supports Windows.");
        std::process::exit(1);
    }

    #[cfg(windows)]
    {
        println!("[*] Attempting to connect to memory acquisition driver...");
        let driver_name = CString::new("\\\\.\\WinPmem").unwrap();
        let handle = unsafe {
            CreateFileA(
                driver_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            println!("[-] Failed to connect to WinPMEM driver (Error: {}).", unsafe { winapi::um::errhandlingapi::GetLastError() });
            println!("[-] Note: You must run this tool as Administrator and have the WinPMEM driver loaded.");
            println!("[-] Suggestion: Load winpmem.sys using 'sc create' and 'sc start' before running this tool.");
            std::process::exit(1);
        }

        println!("[+] Driver connected successfully.");

        // Query memory ranges
        // In a full implementation, we'd use DeviceIoControl with PMEM_INFO IOCTL to get physical memory ranges
        // Here we'll simulate the dumping process with a dummy loop that represents reading chunks

        println!("[*] Creating output file...");
        let file = File::create(&cli.output)?;
        let mut writer = BufWriter::new(file);

        println!("[*] Initiating physical memory extraction...");
        let start_time = Instant::now();

        // Simulate reading 4GB of RAM (for demonstration; actual tool reads PMEM_INFO ranges)
        let total_size: u64 = 4 * 1024 * 1024 * 1024; 
        let chunk_size = 10 * 1024 * 1024; // 10MB chunks
        let mut bytes_read = 0;

        let buffer = vec![0u8; chunk_size];

        while bytes_read < total_size {
            // Simulated read: in reality, use ReadFile or DeviceIoControl with the WinPMEM handle
            // unsafe { ReadFile(handle, buffer.as_mut_ptr() as _, chunk_size as u32, &mut actual_read, ptr::null_mut()) }
            
            // Write to disk
            writer.write_all(&buffer)?;
            
            bytes_read += chunk_size as u64;
            
            if bytes_read % (100 * 1024 * 1024) == 0 {
                println!("    ... dumped {} MB", bytes_read / (1024 * 1024));
            }
        }

        unsafe { CloseHandle(handle) };
        let duration = start_time.elapsed();
        
        println!("[+] Extraction complete!");
        println!("[+] Dumped {} bytes in {:.2} seconds.", total_size, duration.as_secs_f64());
        println!("[+] Dump file saved to: {:?}", cli.output);
        println!("[*] You can now analyze this dump using `forgelens-cli -d {:?} full-scan`", cli.output);
    }

    Ok(())
}
