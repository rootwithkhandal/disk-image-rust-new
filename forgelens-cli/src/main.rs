use clap::{Parser, Subcommand};
use forgelens_core::{
    ingest::MemoryDump,
    profile::OsProfile,
    engine::{
        process::analyze_processes,
        memory::scan_process_memory,
        network::analyze_network,
        registry::analyze_registry,
        kernel::analyze_kernel,
        dll::analyze_dlls,
        thread::analyze_threads,
        credentials::analyze_credentials,
        file_recovery::recover_files,
        yara_engine::scan_yara_ioc,
        malware::analyze_malware,
        reporting::{ReportBuilder, export_json, export_csv, export_html},
    },
    timeline::{generate_timeline, generate_extended_timeline, export_timeline_csv, export_timeline_splunk},
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "forgelens")]
#[command(about = "ForgeLens Volatile Memory Dump Forensic Analysis CLI", long_about = None)]
struct Cli {
    /// Path to the volatile memory dump file (RAW, LiME, AVML, VMEM, CrashDump, Hyper-V, VirtualBox, hiberfil)
    #[arg(short, long, value_name = "FILE")]
    dump: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Detect target system OS profile
    DetectProfile,
    /// List active and hidden processes (DKOM detection)
    PsList,
    /// Enumerate active/listening network sockets & connections
    Netstat,
    /// Scan process memory space for RWX pages, PE headers, and shellcode
    ScanMemory {
        /// Directory Table Base (CR3) of the process to scan (hex). Defaults to kernel DTB.
        #[arg(short, long)]
        dtb: Option<String>,
        /// Start virtual address (hex)
        #[arg(long, default_value = "0")]
        start_va: String,
        /// End virtual address (hex)
        #[arg(long, default_value = "7fffffffffff")]
        end_va: String,
    },
    /// Extract registry keys and values from system hives
    Registry,
    /// Analyze kernel drivers and detect SSDT/IDT hook anomalies
    Kernel,
    /// Generate a unified chronological timeline of events
    Timeline {
        /// Format: json, csv, or splunk
        #[arg(short, long, default_value = "json")]
        format: String,
    },
    /// Enumerate loaded DLLs and detect injection/hooks for a process
    Dlls {
        /// Process DTB (hex). Defaults to kernel DTB.
        #[arg(short, long)]
        dtb: Option<String>,
        /// Process PID for context
        #[arg(short, long, default_value = "4")]
        pid: u64,
    },
    /// Analyze threads for a process, detect APC injection and hijacking
    Threads {
        /// Process PID to analyze
        #[arg(short, long, default_value = "4")]
        pid: u64,
    },
    /// Extract credential artifacts (NTLM hashes, Kerberos tickets, SSH keys, etc.)
    Credentials,
    /// Recover file artifacts from memory (PE files, documents, scripts, browser data)
    Files,
    /// Run YARA rules and IOC matching against the memory dump
    Yara,
    /// Perform malware analysis (Cobalt Strike, Meterpreter, Sliver, reflective loaders)
    Malware,
    /// Generate a comprehensive forensic report
    Report {
        /// Report format: json, csv, or html
        #[arg(short, long, default_value = "json")]
        format: String,
        /// Output file path (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Run full analysis (all engines) and produce a summary
    FullScan,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let cli = Cli::parse();

    println!("[*] Ingesting memory dump: {:?}", cli.dump);
    let dump = MemoryDump::load(&cli.dump)?;
    println!("[+] Successfully loaded dump. Format: {:?}", dump.format);

    // Automatically detect OS profile
    let profile = OsProfile::detect(&dump)?;
    println!("[+] Detected OS Family: {:?}", profile.family);
    println!("[+] Kernel Version: {}", profile.kernel_version);
    println!("[+] Kernel Directory Table Base (CR3): 0x{:X}", profile.kernel_dtb);
    println!("------------------------------------------------------------");

    match cli.command {
        Commands::DetectProfile => {
            println!("OS Profile Summary:");
            println!("  Family:       {:?}", profile.family);
            println!("  Architecture: {}", profile.architecture);
            println!("  Version:      {}", profile.kernel_version);
            if let Some(build) = profile.build_number {
                println!("  Build Number: {}", build);
            }
            println!("  Kernel CR3:   0x{:X}", profile.kernel_dtb);
        }
        Commands::PsList => {
            println!("[*] Scanning for EPROCESS blocks and active process links...");
            let processes = analyze_processes(&dump, &profile)?;
            println!("{:<8} {:<8} {:<20} {:<16} {:<10}", "PID", "PPID", "Name", "DTB (CR3)", "Status");
            println!("{}", "-".repeat(68));
            for proc in processes {
                let status = if proc.active { "Active" } else { "Unlinked/Carved" };
                println!(
                    "{:<8} {:<8} {:<20} 0x{:<14X} {:<10}",
                    proc.pid, proc.ppid, proc.name, proc.dtb, status
                );
            }
        }
        Commands::Netstat => {
            println!("[*] Scanning memory for active network socket structures...");
            let conns = analyze_network(&dump, &profile)?;
            println!("{:<6} {:<16} {:<22} {:<22} {:<12}", "Proto", "PID", "Local Address", "Foreign Address", "State");
            println!("{}", "-".repeat(78));
            for conn in conns {
                let local = format!("{}:{}", conn.local_ip, conn.local_port);
                let foreign = format!("{}:{}", conn.remote_ip, conn.remote_port);
                println!(
                    "{:<6} {:<16} {:<22} {:<22} {:<12}",
                    conn.protocol, conn.pid, local, foreign, conn.state
                );
            }
        }
        Commands::ScanMemory { dtb, start_va, end_va } => {
            let cr3 = if let Some(hex_str) = dtb {
                u64::from_str_radix(hex_str.trim_start_matches("0x"), 16)?
            } else {
                profile.kernel_dtb
            };
            let start = u64::from_str_radix(start_va.trim_start_matches("0x"), 16)?;
            let end = u64::from_str_radix(end_va.trim_start_matches("0x"), 16)?;

            println!("[*] Scanning virtual memory with DTB: 0x{:X}...", cr3);
            let anomalies = scan_process_memory(&dump, cr3, start, end)?;
            if anomalies.is_empty() {
                println!("[+] No security anomalies detected in scanned pages.");
            } else {
                println!("{:<16} {:<16} {:<8} {:<8} {:<10} {}", "Virtual Addr", "Physical Addr", "RWX", "MZ/PE", "Entropy", "Indicators");
                println!("{}", "-".repeat(95));
                for anomaly in anomalies {
                    println!(
                        "0x{:<14X} 0x{:<14X} {:<8} {:<8} {:<10.4} {}",
                        anomaly.virtual_address,
                        anomaly.physical_address,
                        anomaly.is_rwx,
                        anomaly.has_pe_header,
                        anomaly.entropy,
                        anomaly.description
                    );
                }
            }
        }
        Commands::Registry => {
            println!("[*] Carving and parsing loaded Registry Hives...");
            let keys = analyze_registry(&dump)?;
            for key in keys {
                println!("\nKey: {}", key.path);
                println!("Last Written: {}", key.last_written);
                println!("Values:");
                for (name, val) in &key.values {
                    println!("  {:30} : {}", name, val);
                }
            }
        }
        Commands::Kernel => {
            println!("[*] Scanning kernel space structures, driver list, and SSDT/IDT tables...");
            let kernel_res = analyze_kernel(&dump, &profile)?;
            println!("\n[Loaded Kernel Modules / Drivers]");
            println!("{:<24} {:<18} {:<10} {:<8} {}", "Name", "Base Address", "Size", "Signed", "Path");
            println!("{}", "-".repeat(90));
            for driver in &kernel_res.drivers {
                println!(
                    "{:<24} 0x{:<16X} 0x{:<8X} {:<8} {}",
                    driver.name, driver.base_address, driver.size,
                    if driver.is_signed { "Yes" } else { "NO" },
                    driver.path
                );
            }

            println!("\n[Kernel Hooks & Integrity Anomaly Alerts]");
            println!("{:<10} {:<6} {:<24} {:<18} {:<14} {}", "Type", "Index", "Function Name", "Hook Address", "Target Module", "Severity");
            println!("{}", "-".repeat(90));
            for hook in &kernel_res.hooks {
                println!(
                    "{:<10} {:<6} {:<24} 0x{:<16X} {:<14} {}",
                    hook.hook_type, hook.index, hook.function_name, hook.hook_address, hook.target_module, hook.severity
                );
            }
        }
        Commands::Timeline { format } => {
            println!("[*] Generating chronological timeline of events...");
            let processes = analyze_processes(&dump, &profile)?;
            let conns = analyze_network(&dump, &profile)?;
            let keys = analyze_registry(&dump)?;
            let kernel_res = analyze_kernel(&dump, &profile).ok();
            let events = generate_extended_timeline(&processes, &conns, &keys, &[], kernel_res.as_ref());

            match format.to_lowercase().as_str() {
                "csv" => print!("{}", export_timeline_csv(&events)),
                "splunk" | "ndjson" | "elastic" => print!("{}", export_timeline_splunk(&events)),
                _ => {
                    let json_out = serde_json::to_string_pretty(&events)?;
                    println!("{}", json_out);
                }
            }
        }
        Commands::Dlls { dtb, pid } => {
            let cr3 = if let Some(hex_str) = dtb {
                u64::from_str_radix(hex_str.trim_start_matches("0x"), 16)?
            } else {
                profile.kernel_dtb
            };
            println!("[*] Analyzing DLLs for PID {} (DTB: 0x{:X})...", pid, cr3);
            let result = analyze_dlls(&dump, &profile, cr3, pid)?;
            println!("[+] Found {} DLLs ({} unlinked, {} injected)", result.dlls.len(), result.unlinked_count, result.injected_count);
            println!("{:<24} {:<18} {:<10} {:<8} {:<16} {}", "Name", "Base", "Size", "Linked", "Injection Type", "Hooks");
            println!("{}", "-".repeat(95));
            for dll in &result.dlls {
                println!(
                    "{:<24} 0x{:<16X} 0x{:<8X} {:<8} {:<16?} {}",
                    dll.name, dll.base_address, dll.size,
                    if dll.is_linked { "Yes" } else { "NO" },
                    dll.injection_type,
                    dll.hooks_detected.len()
                );
            }
            if !result.import_anomalies.is_empty() {
                println!("\n[Import Table Anomalies]");
                for anomaly in &result.import_anomalies {
                    println!("  {} :: {} -> 0x{:X} ({})", anomaly.dll_name, anomaly.function_name, anomaly.actual_target, anomaly.anomaly_type);
                }
            }
        }
        Commands::Threads { pid } => {
            println!("[*] Analyzing threads for PID {}...", pid);
            let processes = analyze_processes(&dump, &profile)?;
            let proc = processes.iter().find(|p| p.pid == pid).unwrap_or_else(|| &processes[0]);
            let module_ranges: Vec<(u64, u64, String)> = vec![
                (0x00007FFE00000000, 0x1F0000, "ntdll.dll".to_string()),
                (0x00007FFE01000000, 0x110000, "kernel32.dll".to_string()),
            ];
            let result = analyze_threads(&dump, &profile, pid, proc.dtb, &module_ranges)?;
            println!("[+] Found {} threads ({} suspicious)", result.threads.len(), result.suspicious_count);
            println!("APC injection: {} | Thread hijacking: {}", result.apc_injection_detected, result.thread_hijacking_detected);
            println!("{:<8} {:<18} {:<10} {:<8} {:<8} {}", "TID", "Start Address", "State", "Pri", "CSw", "Suspicious");
            println!("{}", "-".repeat(80));
            for t in &result.threads {
                println!(
                    "{:<8} 0x{:<16X} {:<10?} {:<8} {:<8} {}",
                    t.tid, t.start_address, t.state, t.priority, t.context_switches,
                    if t.is_suspicious { format!("YES: {}", t.suspicion_reasons.join("; ")) } else { "No".to_string() }
                );
            }
        }
        Commands::Credentials => {
            println!("[*] Scanning for credential artifacts...");
            let result = analyze_credentials(&dump, &profile)?;
            println!("[+] Found {} credential artifacts", result.credentials.len());
            println!("  NTLM Hashes: {} | Kerberos Tickets: {} | Keys: {}", result.total_hashes, result.total_tickets, result.total_keys);
            println!("  Dumping Activity: {} | Mimikatz: {} | LSASS Access: {}",
                result.dumping_activity_detected, result.mimikatz_detected, result.lsass_access_detected);
            println!("\n{:<18} {:<16} {:<20} {}", "Type", "Username", "Source", "Data");
            println!("{}", "-".repeat(90));
            for cred in &result.credentials {
                println!("{:<18?} {:<16} {:<20} {}", cred.credential_type, cred.username, cred.source, cred.data);
            }
        }
        Commands::Files => {
            println!("[*] Recovering file artifacts from memory...");
            let result = recover_files(&dump)?;
            println!("[+] Recovered {} files, {} browser artifacts", result.recovered_files.len(), result.browser_artifacts.len());
            println!("  PE Files: {} | Documents: {} | Scripts: {}", result.pe_files_count, result.document_count, result.script_count);
            println!("\n{:<18} {:<30} {:<10} {:<16} {}", "Type", "Name", "Size", "Address", "Threat Indicators");
            println!("{}", "-".repeat(100));
            for f in &result.recovered_files {
                let indicators = if f.threat_indicators.is_empty() { "None".to_string() } else { f.threat_indicators.join(", ") };
                println!("{:<18?} {:<30} {:<10} 0x{:<14X} {}", f.file_type, f.name, f.size, f.physical_address, indicators);
            }
        }
        Commands::Yara => {
            println!("[*] Running YARA rules and IOC matching...");
            let result = scan_yara_ioc(&dump, &[])?;
            println!("[+] Checked {} rules, {} IOCs | Threat Level: {}", result.total_rules_checked, result.total_iocs_checked, result.threat_level);
            if !result.yara_matches.is_empty() {
                println!("\n[YARA Matches]");
                for m in &result.yara_matches {
                    println!("  Rule: {} [{:?}]", m.rule_name, m.severity);
                    println!("    {}", m.description);
                    for s in &m.strings_matched {
                        println!("      {} at 0x{:X}: {}", s.identifier, s.offset, s.data_preview);
                    }
                }
            }
            if !result.ioc_matches.is_empty() {
                println!("\n[IOC Matches]");
                for ioc in &result.ioc_matches {
                    println!("  {:?}: {} (offset: 0x{:X})", ioc.ioc_type, ioc.value, ioc.match_offset.unwrap_or(0));
                    println!("    Context: {}", ioc.context);
                }
            }
        }
        Commands::Malware => {
            println!("[*] Running malware analysis...");
            let result = analyze_malware(&dump)?;
            println!("[+] Overall Threat Score: {:.1}/10", result.overall_threat_score);
            println!("  Indicators: {} | Reconstructed PEs: {} | Deobfuscated Strings: {}",
                result.indicators.len(), result.reconstructed_pes.len(), result.deobfuscated_strings.len());
            if !result.indicators.is_empty() {
                println!("\n[Malware Indicators]");
                for i in &result.indicators {
                    println!("  {} ({:?}, {:.0}% confidence)", i.malware_family, i.malware_type, i.confidence * 100.0);
                    println!("    {}", i.description);
                    for a in &i.artifacts {
                        println!("      - {}", a);
                    }
                    if let Some(ref cfg) = i.config_data {
                        if !cfg.c2_servers.is_empty() {
                            println!("    C2 Servers: {:?}", cfg.c2_servers);
                        }
                    }
                }
            }
            if !result.deobfuscated_strings.is_empty() {
                println!("\n[Deobfuscated Strings]");
                for s in result.deobfuscated_strings.iter().take(20) {
                    println!("  [{:?}] 0x{:X}: {}", s.encoding, s.original_offset, s.decoded_value);
                }
            }
        }
        Commands::Report { format, output } => {
            println!("[*] Generating comprehensive forensic report...");
            let processes = analyze_processes(&dump, &profile)?;
            let conns = analyze_network(&dump, &profile)?;
            let keys = analyze_registry(&dump)?;
            let kernel_res = analyze_kernel(&dump, &profile)?;
            let cred_res = analyze_credentials(&dump, &profile)?;
            let yara_res = scan_yara_ioc(&dump, &[])?;
            let malware_res = analyze_malware(&dump)?;
            let file_res = recover_files(&dump)?;
            let timeline = generate_timeline(&processes, &conns, &keys);

            let report = ReportBuilder::new(
                "ForgeLens Forensic Analysis Report",
                "ForgeLens Automated Triage",
                "FL-AUTO-001",
                &cli.dump.to_string_lossy(),
            )
            .with_profile(profile)
            .with_processes(processes)
            .with_connections(conns)
            .with_registry(keys)
            .with_kernel(kernel_res)
            .with_credentials(cred_res)
            .with_yara(yara_res)
            .with_malware(malware_res)
            .with_file_recovery(file_res)
            .with_timeline(timeline)
            .build();

            let content = match format.to_lowercase().as_str() {
                "html" => export_html(&report)?,
                "csv" => export_csv(&report)?,
                _ => export_json(&report)?,
            };

            if let Some(path) = output {
                std::fs::write(&path, &content)?;
                println!("[+] Report written to {:?}", path);
            } else {
                println!("{}", content);
            }
        }
        Commands::FullScan => {
            println!("[*] Running full forensic triage...\n");

            println!("=== PROCESS ANALYSIS ===");
            let processes = analyze_processes(&dump, &profile)?;
            let unlinked = processes.iter().filter(|p| !p.active).count();
            println!("[+] {} processes ({} unlinked/carved)", processes.len(), unlinked);

            println!("\n=== NETWORK ANALYSIS ===");
            let conns = analyze_network(&dump, &profile)?;
            println!("[+] {} connections found", conns.len());

            println!("\n=== REGISTRY ANALYSIS ===");
            let keys = analyze_registry(&dump)?;
            println!("[+] {} registry keys extracted", keys.len());

            println!("\n=== KERNEL ANALYSIS ===");
            let kernel_res = analyze_kernel(&dump, &profile)?;
            println!("[+] {} drivers, {} hooks", kernel_res.drivers.len(), kernel_res.hooks.len());

            println!("\n=== CREDENTIAL ANALYSIS ===");
            let cred_res = analyze_credentials(&dump, &profile)?;
            println!("[+] {} credentials | Mimikatz: {} | LSASS access: {}",
                cred_res.credentials.len(), cred_res.mimikatz_detected, cred_res.lsass_access_detected);

            println!("\n=== YARA / IOC SCAN ===");
            let yara_res = scan_yara_ioc(&dump, &[])?;
            println!("[+] {} YARA matches, {} IOCs | Threat: {}", yara_res.yara_matches.len(), yara_res.ioc_matches.len(), yara_res.threat_level);

            println!("\n=== MALWARE ANALYSIS ===");
            let malware_res = analyze_malware(&dump)?;
            println!("[+] {} indicators | Score: {:.1}/10", malware_res.indicators.len(), malware_res.overall_threat_score);

            println!("\n=== FILE RECOVERY ===");
            let file_res = recover_files(&dump)?;
            println!("[+] {} files recovered, {} browser artifacts", file_res.recovered_files.len(), file_res.browser_artifacts.len());

            println!("\n=== TIMELINE ===");
            let timeline = generate_timeline(&processes, &conns, &keys);
            println!("[+] {} events reconstructed", timeline.len());

            println!("\n============================================================");
            println!("[+] Full scan complete. Use 'forgelens report --format html -o report.html' for detailed report.");
        }
    }

    Ok(())
}
