use super::args::{CliArgs, CliSubcommand};
use crate::platform::DeviceBackend;
use std::io::Write;

pub fn run_cli(args: CliArgs) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        unsafe extern "system" {
            fn AttachConsole(dwProcessId: u32) -> i32;
        }
        const ATTACH_PARENT_PROCESS: u32 = 0xFFFFFFFF;
        unsafe {
            let _ = AttachConsole(ATTACH_PARENT_PROCESS);
        }
    }

    let command = match args.command {
        Some(cmd) => cmd,
        None => {
            println!("OpenForensic CLI mode invoked without a subcommand. Use --help to see available options.");
            return Ok(());
        }
    };

    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("Failed to initialize async runtime: {}", e))?;

    match command {
        CliSubcommand::ListDevices => {
            let devices = crate::platform::ActiveBackend::enumerate_devices().unwrap_or_default();
            println!("\n=== DETECTED BLOCK STORAGE DEVICES ===");
            println!("{:<20} {:<25} {:<15} {:<12} {:<10}", "PATH", "MODEL", "SERIAL", "SIZE", "TYPE");
            println!("{}", "-".repeat(85));
            for dev in devices {
                let size_gb = dev.size as f64 / 1_000_000_000.0;
                println!("{:<20} {:<25} {:<15} {:<10.2} GB {:<10}", dev.path, dev.model, dev.serial, size_gb, dev.device_type);
            }
            println!();
            Ok(())
        }
        CliSubcommand::ListVolumes => {
            use sysinfo::Disks;
            let disks = Disks::new_with_refreshed_list();
            println!("\n=== LOGICAL SYSTEM VOLUMES ===");
            println!("{:<15} {:<20} {:<15} {:<15} {:<15}", "MOUNT POINT", "NAME", "FILESYSTEM", "TOTAL SIZE", "FREE SPACE");
            println!("{}", "-".repeat(85));
            for disk in disks.list() {
                let mount = disk.mount_point().to_string_lossy();
                let name = disk.name().to_string_lossy();
                let fs = disk.file_system().to_string_lossy();
                let total_gb = disk.total_space() as f64 / 1_000_000_000.0;
                let free_gb = disk.available_space() as f64 / 1_000_000_000.0;
                println!("{:<15} {:<20} {:<15} {:<10.2} GB {:<10.2} GB", mount, name, fs, total_gb, free_gb);
            }
            println!();
            Ok(())
        }
        CliSubcommand::Acquire {
            source,
            dest,
            format,
            mode,
            compression,
            case_number,
            examiner,
            evidence_id,
            notes,
            block_size_kb,
            hashes,
            keywords,
            yara_rules,
            verify,
        } => rt.block_on(async {
            let hash_algos = super::args::parse_hash_algorithms(&hashes);
            let compression_fmt = match compression.to_lowercase().as_str() {
                "gzip" => crate::output::CompressionFormat::Gzip,
                "zstd" => crate::output::CompressionFormat::Zstd,
                _ => crate::output::CompressionFormat::None,
            };

            let config = crate::acquisition::AcquisitionConfig {
                hash_algorithms: hash_algos,
                block_size: block_size_kb * 1024,
                split_size: None,
                compression: compression_fmt,
                case_number,
                examiner,
                evidence_id,
                notes,
                pre_hash: None,
                imaging_mode: mode,
                format: format.clone(),
                read_verification: verify,
                keywords,
                yara_rules_path: yara_rules,
                active_plugins: vec![],
            };

            let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::acquisition::ProgressEvent>(100);

            let progress_handle = tokio::spawn(async move {
                while let Some(event) = rx.recv().await {
                    match event {
                        crate::acquisition::ProgressEvent::Progress { bytes_read, total_size, speed_bps, bad_sectors } => {
                            let pct = if total_size > 0 { (bytes_read as f64 / total_size as f64) * 100.0 } else { 0.0 };
                            let speed_mb = speed_bps / 1_000_000.0;
                            let read_gb = bytes_read as f64 / 1_000_000_000.0;
                            let total_gb = total_size as f64 / 1_000_000_000.0;
                            eprint!("\r[===>] Progress: {:>5.1}% | Read: {:>5.2}/{:>5.2} GB | Speed: {:>6.2} MB/s | Bad Sectors: {}", pct, read_gb, total_gb, speed_mb, bad_sectors);
                            let _ = std::io::stderr().flush();
                        }
                        crate::acquisition::ProgressEvent::Log(msg) => {
                            eprintln!("\n[LOG] {}", msg);
                        }
                        crate::acquisition::ProgressEvent::Error(err) => {
                            eprintln!("\n[ERROR] {}", err);
                        }
                        crate::acquisition::ProgressEvent::Finished { bytes_read, bad_sectors, hashes } => {
                            eprintln!("\n\n=== ACQUISITION FINISHED ===");
                            println!("Total Bytes Read: {}", bytes_read);
                            println!("Bad Sectors Encountered: {}", bad_sectors);
                            println!("\n--- CRYPTOGRAPHIC HASHES ---");
                            for (algo, hash_val) in hashes {
                                println!("{:?}: {}", algo, hash_val);
                            }
                        }
                        crate::acquisition::ProgressEvent::KeywordHit { keyword, offset } => {
                            eprintln!("\n[KEYWORD ALERT] Keyword '{}' hit at offset 0x{:X}", keyword, offset);
                        }
                        crate::acquisition::ProgressEvent::YaraHit { rule_name, offset, tags } => {
                            eprintln!("\n[YARA ALERT] Rule '{}' matched at offset 0x{:X} (Tags: {:?})", rule_name, offset, tags);
                        }
                        crate::acquisition::ProgressEvent::PluginLog { plugin_name, message } => {
                            eprintln!("\n[PLUGIN {}] {}", plugin_name, message);
                        }
                    }
                }
            });

            println!("Starting headless disk imaging: {} -> {}", source, dest);

            let mut source_dev = match crate::platform::ActiveBackend::open_readonly(&source) {
                Ok(s) => s,
                Err(e) => {
                    let _ = progress_handle.await;
                    return Err(format!("Failed to open source device {}: {}", source, e));
                }
            };

            if let Err(e) = crate::platform::ActiveBackend::enforce_write_block(&mut source_dev) {
                let _ = progress_handle.await;
                return Err(format!("Failed to enforce write blocker on {}: {}", source, e));
            }

            let dest_file_path = std::path::PathBuf::from(&dest);
            let checkpoint_path = dest_file_path.with_extension("checkpoint");

            let mut dest_writer = match crate::output::OutputWriter::new(
                &dest_file_path,
                config.split_size,
                config.compression,
                false,
                false,
                &config.format,
                &config.case_number,
                &config.examiner,
                &config.evidence_id,
                &config.notes,
            ) {
                Ok(w) => w,
                Err(e) => {
                    let _ = progress_handle.await;
                    return Err(format!("Failed to create destination writer {}: {}", dest, e));
                }
            };

            let _ = dest_writer.write_format_header(
                &config.format.to_uppercase(),
                &config.case_number,
                &config.examiner,
                &config.evidence_id,
                &config.notes,
            );

            match crate::acquisition::acquire(
                &mut source_dev,
                dest_writer,
                &config,
                tx,
                &checkpoint_path,
                0,
            ).await {
                Ok(_) => {
                    let _ = progress_handle.await;
                    Ok(())
                }
                Err(e) => {
                    let _ = progress_handle.await;
                    Err(format!("Acquisition failed: {}", e))
                }
            }
        }),
        CliSubcommand::Triage {
            dest,
            no_volatile,
            no_registry,
            no_browsers,
            no_eventlogs,
            siem_export,
            siem_endpoint,
            siem_type,
            siem_token,
            siem_index,
        } => rt.block_on(async {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::acquisition::ProgressEvent>(100);

            let progress_handle = tokio::spawn(async move {
                while let Some(event) = rx.recv().await {
                    match event {
                        crate::acquisition::ProgressEvent::Log(msg) => {
                            eprintln!("[TRIAGE] {}", msg);
                        }
                        crate::acquisition::ProgressEvent::Error(err) => {
                            eprintln!("[ERROR] {}", err);
                        }
                        _ => {}
                    }
                }
            });

            let siem_config = if siem_export {
                let dest_type = match siem_type.to_lowercase().as_str() {
                    "wazuh_socket" => crate::siem::SiemDestinationType::WazuhSocket,
                    "wazuh_local_log" => crate::siem::SiemDestinationType::WazuhLocalLog,
                    _ => crate::siem::SiemDestinationType::SplunkHec,
                };
                Some(crate::siem::SiemConfig {
                    destination_type: dest_type,
                    endpoint: siem_endpoint,
                    auth_token: siem_token,
                    index: siem_index,
                    enabled: true,
                })
            } else {
                None
            };

            println!("Starting headless system triage -> {}", dest);
            match crate::acquisition::acquire_triage(
                &dest,
                !no_registry,
                !no_volatile,
                !no_browsers,
                !no_eventlogs,
                siem_config,
                tx,
            ).await {
                Ok(_) => {
                    let _ = progress_handle.await;
                    println!("System triage completed successfully.");
                    Ok(())
                }
                Err(e) => {
                    let _ = progress_handle.await;
                    Err(format!("System triage failed: {}", e))
                }
            }
        }),
        CliSubcommand::Live {
            volume,
            dest,
            ram,
            locked_files,
            image_vss,
            cleanup,
            hashes,
        } => rt.block_on(async {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::acquisition::ProgressEvent>(100);

            let progress_handle = tokio::spawn(async move {
                while let Some(event) = rx.recv().await {
                    match event {
                        crate::acquisition::ProgressEvent::Log(msg) => {
                            eprintln!("[LIVE] {}", msg);
                        }
                        crate::acquisition::ProgressEvent::Error(err) => {
                            eprintln!("[ERROR] {}", err);
                        }
                        _ => {}
                    }
                }
            });

            let hash_algos = super::args::parse_hash_algorithms(&hashes);

            println!("Starting live system acquisition on volume {} -> {}", volume, dest);
            match crate::acquisition::acquire_live(
                &volume,
                &dest,
                ram,
                locked_files,
                true,
                image_vss,
                cleanup,
                hash_algos,
                tx,
            ).await {
                Ok(_) => {
                    let _ = progress_handle.await;
                    println!("Live system acquisition completed successfully.");
                    Ok(())
                }
                Err(e) => {
                    let _ = progress_handle.await;
                    Err(format!("Live acquisition failed: {}", e))
                }
            }
        }),
        CliSubcommand::Ram {
            dump,
            profile,
            ioc_enrich,
        } => rt.block_on(async {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::acquisition::ProgressEvent>(100);

            let log_handle = tokio::spawn(async move {
                while let Some(event) = rx.recv().await {
                    match event {
                        crate::acquisition::ProgressEvent::Log(msg) => {
                            println!("[VOLATILITY] {}", msg);
                        }
                        crate::acquisition::ProgressEvent::Error(err) => {
                            eprintln!("[ERROR] {}", err);
                        }
                        _ => {}
                    }
                }
            });

            let config = crate::ram_analysis::VolatilityConfig {
                image_path: dump.clone(),
                vol_path: "vol".to_string(),
                profile: profile.clone(),
                enrich_vt: ioc_enrich,
                enrich_mb: false,
                enrich_abuseip: ioc_enrich,
                vt_key: "".to_string(),
                mb_key: "".to_string(),
                abuseip_key: "".to_string(),
            };

            println!("Starting Volatility 3 RAM analysis on {} (profile: {})", dump, profile);
            match crate::ram_analysis::start_volatility_analysis_backend(
                &config,
                tx,
            ).await {
                Ok(_) => {
                    let _ = log_handle.await;
                    println!("RAM analysis completed successfully.");
                    Ok(())
                }
                Err(e) => {
                    let _ = log_handle.await;
                    Err(format!("RAM analysis failed: {}", e))
                }
            }
        }),
    }
}
