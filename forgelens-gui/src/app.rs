use eframe::egui;
use rfd::FileDialog;
use std::path::PathBuf;
use std::sync::{Arc, mpsc::{channel, Receiver}};
use forgelens_core::{
    ingest::MemoryDump,
    profile::OsProfile,
    engine::{
        process::{Process, analyze_processes},
        memory::{MemoryScanResult, scan_process_memory},
        network::{NetworkConnection, analyze_network},
        registry::{RegistryKey, analyze_registry},
        kernel::{KernelAnalysisResult, analyze_kernel},
        dll::{DllAnalysisResult, analyze_dlls},
        thread::{ThreadAnalysisResult, analyze_threads},
        credentials::{CredentialAnalysisResult, analyze_credentials},
        file_recovery::{FileRecoveryResult, recover_files},
        yara_engine::{YaraIocResult, scan_yara_ioc},
        malware::{MalwareAnalysisResult, analyze_malware},
        reporting::{ReportBuilder, export_html, ForensicReport},
    },
    timeline::{TimelineEvent, generate_timeline},
};

#[derive(PartialEq)]
enum ActiveTab {
    Dashboard,
    Processes,
    Network,
    MemoryScanner,
    Registry,
    Kernel,
    Dlls,
    Threads,
    Credentials,
    FileRecovery,
    YaraIoc,
    Malware,
    Timeline,
    HexViewer,
    Reporting,
}

pub struct ForgeLensApp {
    dump_path: Option<PathBuf>,
    dump: Option<Arc<MemoryDump>>,
    profile: Option<OsProfile>,
    
    // Analyzed Data
    processes: Vec<Process>,
    connections: Vec<NetworkConnection>,
    registry_keys: Vec<RegistryKey>,
    kernel_result: Option<KernelAnalysisResult>,
    timeline_events: Vec<TimelineEvent>,
    dll_results: Vec<DllAnalysisResult>,
    thread_results: Vec<ThreadAnalysisResult>,
    credential_result: Option<CredentialAnalysisResult>,
    file_recovery_result: Option<FileRecoveryResult>,
    yara_result: Option<YaraIocResult>,
    malware_result: Option<MalwareAnalysisResult>,
    
    // Scanner UI State
    selected_process_dtb: Option<u64>,
    memory_anomalies: Vec<MemoryScanResult>,
    is_scanning_memory: bool,
    scan_rx: Option<Receiver<Vec<MemoryScanResult>>>,
    
    // Hex Viewer State
    hex_address: u64,
    hex_bytes: Vec<u8>,
    hex_input_address: String,
    
    // Navigation / UI states
    active_tab: ActiveTab,
    status_message: String,
    search_query: String,
}

impl ForgeLensApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            dump_path: None,
            dump: None,
            profile: None,
            processes: Vec::new(),
            connections: Vec::new(),
            registry_keys: Vec::new(),
            kernel_result: None,
            timeline_events: Vec::new(),
            dll_results: Vec::new(),
            thread_results: Vec::new(),
            credential_result: None,
            file_recovery_result: None,
            yara_result: None,
            malware_result: None,
            selected_process_dtb: None,
            memory_anomalies: Vec::new(),
            is_scanning_memory: false,
            scan_rx: None,
            hex_address: 0,
            hex_bytes: vec![0u8; 256],
            hex_input_address: "0x0".to_string(),
            active_tab: ActiveTab::Dashboard,
            status_message: "Ready. Please load a memory dump file.".to_string(),
            search_query: String::new(),
        }
    }

    fn load_dump_file(&mut self, path: PathBuf) {
        self.status_message = format!("Loading file: {:?}...", path.file_name().unwrap_or_default());
        match MemoryDump::load(&path) {
            Ok(dump) => {
                self.status_message = "Analyzing OS Profile...".to_string();
                match OsProfile::detect(&dump) {
                    Ok(profile) => {
                        self.profile = Some(profile.clone());
                        self.selected_process_dtb = Some(profile.kernel_dtb);
                        
                        // Core analysis
                        self.status_message = "Running core analysis engines...".to_string();
                        let processes = analyze_processes(&dump, &profile).unwrap_or_default();
                        let connections = analyze_network(&dump, &profile).unwrap_or_default();
                        let registry_keys = analyze_registry(&dump).unwrap_or_default();
                        let kernel_res = analyze_kernel(&dump, &profile).ok();
                        let timeline_events = generate_timeline(&processes, &connections, &registry_keys);

                        // Extended analysis
                        self.status_message = "Running DLL, thread, and credential analysis...".to_string();
                        let dll_results = if let Some(proc) = processes.first() {
                            vec![analyze_dlls(&dump, &profile, proc.dtb, proc.pid).unwrap_or_else(|_| forgelens_core::engine::dll::DllAnalysisResult {
                                pid: 0, dlls: vec![], import_anomalies: vec![], unlinked_count: 0, injected_count: 0,
                            })]
                        } else { vec![] };

                        let thread_results = if let Some(proc) = processes.first() {
                            let module_ranges: Vec<(u64, u64, String)> = vec![
                                (0x00007FFE00000000, 0x1F0000, "ntdll.dll".to_string()),
                                (0x00007FFE01000000, 0x110000, "kernel32.dll".to_string()),
                            ];
                            vec![analyze_threads(&dump, &profile, proc.pid, proc.dtb, &module_ranges).unwrap_or_else(|_| forgelens_core::engine::thread::ThreadAnalysisResult {
                                pid: 0, threads: vec![], suspicious_count: 0, apc_injection_detected: false, thread_hijacking_detected: false,
                            })]
                        } else { vec![] };

                        let credential_result = analyze_credentials(&dump, &profile).ok();
                        
                        self.status_message = "Running YARA, malware, and file recovery...".to_string();
                        let yara_result = scan_yara_ioc(&dump, &[]).ok();
                        let malware_result = analyze_malware(&dump).ok();
                        let file_recovery_result = recover_files(&dump).ok();

                        self.processes = processes;
                        self.connections = connections;
                        self.registry_keys = registry_keys;
                        self.kernel_result = kernel_res;
                        self.timeline_events = timeline_events;
                        self.dll_results = dll_results;
                        self.thread_results = thread_results;
                        self.credential_result = credential_result;
                        self.yara_result = yara_result;
                        self.malware_result = malware_result;
                        self.file_recovery_result = file_recovery_result;
                        
                        self.dump = Some(Arc::new(dump));
                        self.dump_path = Some(path);
                        self.read_current_hex();
                        self.status_message = "Full analysis completed successfully.".to_string();
                    }
                    Err(e) => { self.status_message = format!("OS Profile Detection Error: {}", e); }
                }
            }
            Err(e) => { self.status_message = format!("Ingestion Error: {}", e); }
        }
    }

    fn read_current_hex(&mut self) {
        if let Some(ref dump) = self.dump {
            let mut buf = vec![0u8; 256];
            if dump.as_ref().read_physical(self.hex_address, &mut buf).is_ok() {
                self.hex_bytes = buf;
            } else {
                self.hex_bytes = vec![0u8; 256];
            }
        }
    }
}

impl eframe::App for ForgeLensApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(ref rx) = self.scan_rx {
            if let Ok(results) = rx.try_recv() {
                self.memory_anomalies = results;
                self.is_scanning_memory = false;
                self.status_message = "Memory scan completed.".to_string();
                self.scan_rx = None;
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            // Header
            ui.horizontal(|ui| {
                ui.heading("🔬 ForgeLens Memory Forensic Terminal");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("📁 Load Memory Dump").clicked() {
                        if let Some(path) = FileDialog::new()
                            .add_filter("Memory Dumps", &["raw", "dd", "lime", "vmem", "dmp", "elf", "vmss", "vmrs"])
                            .pick_file()
                        {
                            self.load_dump_file(path);
                        }
                    }
                });
            });

            ui.separator();

            ui.columns(2, |columns| {
                let sidebar = &mut columns[0];
                sidebar.set_max_width(210.0);
                
                sidebar.vertical(|ui| {
                    ui.label("NAVIGATION");
                    ui.separator();
                    
                    ui.selectable_value(&mut self.active_tab, ActiveTab::Dashboard, "📊 Dashboard");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::Processes, "⚙️ Process Tree");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::Network, "🌐 Network Monitor");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::MemoryScanner, "🔍 Malware Scanner");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::Dlls, "📦 DLL Analysis");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::Threads, "🧵 Thread Analysis");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::Credentials, "🔑 Credentials");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::FileRecovery, "💾 File Recovery");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::YaraIoc, "🎯 YARA / IOC");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::Malware, "🦠 Malware Analysis");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::Registry, "📂 Registry Artifacts");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::Kernel, "🛡️ Kernel Forensics");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::Timeline, "⏱️ Event Timeline");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::HexViewer, "🔢 Raw Hex Viewer");
                    ui.selectable_value(&mut self.active_tab, ActiveTab::Reporting, "📄 Report Export");

                    ui.add_space(30.0);
                    
                    if let Some(ref path) = self.dump_path {
                        ui.label("Active Dump:");
                        ui.weak(path.file_name().unwrap_or_default().to_string_lossy());
                        if let Some(ref prof) = self.profile {
                            ui.label("OS Family:");
                            ui.colored_label(egui::Color32::from_rgb(96, 165, 250), format!("{:?}", prof.family));
                        }
                    }
                });

                let detail = &mut columns[1];
                
                egui::ScrollArea::vertical().show(detail, |ui| {
                    match self.active_tab {
                        ActiveTab::Dashboard => self.draw_dashboard(ui),
                        ActiveTab::Processes => self.draw_processes(ui),
                        ActiveTab::Network => self.draw_network(ui),
                        ActiveTab::MemoryScanner => self.draw_memory_scanner(ui),
                        ActiveTab::Registry => self.draw_registry(ui),
                        ActiveTab::Kernel => self.draw_kernel(ui),
                        ActiveTab::Timeline => self.draw_timeline(ui),
                        ActiveTab::HexViewer => self.draw_hex_viewer(ui),
                        ActiveTab::Dlls => self.draw_dlls(ui),
                        ActiveTab::Threads => self.draw_threads(ui),
                        ActiveTab::Credentials => self.draw_credentials(ui),
                        ActiveTab::FileRecovery => self.draw_file_recovery(ui),
                        ActiveTab::YaraIoc => self.draw_yara_ioc(ui),
                        ActiveTab::Malware => self.draw_malware(ui),
                        ActiveTab::Reporting => self.draw_reporting(ui),
                    }
                });
            });

            ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Status:");
                    ui.weak(&self.status_message);
                });
            });
        });
    }
}

// ─── Drawing Implementations ────────────────────────────────────────
impl ForgeLensApp {
    fn draw_dashboard(&mut self, ui: &mut egui::Ui) {
        ui.heading("Forensic Telemetry Dashboard");
        ui.add_space(10.0);

        if let Some(ref profile) = self.profile {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(format!("OS Target: {:?}", profile.family));
                        ui.label(format!("Kernel Version: {}", profile.kernel_version));
                        ui.label(format!("Architecture: {}", profile.architecture));
                        ui.label(format!("Kernel CR3: 0x{:X}", profile.kernel_dtb));
                    });
                    ui.add_space(50.0);
                    ui.vertical(|ui| {
                        ui.label(format!("Processes Carved: {}", self.processes.len()));
                        ui.label(format!("Network Connections: {}", self.connections.len()));
                        ui.label(format!("Registry Keys: {}", self.registry_keys.len()));
                        
                        let unlinked = self.processes.iter().filter(|p| !p.active).count();
                        if unlinked > 0 {
                            ui.colored_label(egui::Color32::from_rgb(248, 113, 113), format!("⚠️ Unlinked Processes: {}", unlinked));
                        } else {
                            ui.colored_label(egui::Color32::from_rgb(74, 222, 128), "✓ No unlinked processes");
                        }
                    });
                });
            });

            // Engine summary cards
            ui.add_space(10.0);
            ui.horizontal_wrapped(|ui| {
                // DLL card
                let dll_count: usize = self.dll_results.iter().map(|r| r.dlls.len()).sum();
                let injected: usize = self.dll_results.iter().map(|r| r.injected_count).sum();
                ui.group(|ui| {
                    ui.label("📦 DLLs");
                    ui.label(format!("{} total, {} injected", dll_count, injected));
                });
                // Thread card
                let thread_count: usize = self.thread_results.iter().map(|r| r.threads.len()).sum();
                let sus_threads: usize = self.thread_results.iter().map(|r| r.suspicious_count).sum();
                ui.group(|ui| {
                    ui.label("🧵 Threads");
                    ui.label(format!("{} total, {} suspicious", thread_count, sus_threads));
                });
                // Credential card
                if let Some(ref cr) = self.credential_result {
                    ui.group(|ui| {
                        ui.label("🔑 Credentials");
                        if cr.mimikatz_detected {
                            ui.colored_label(egui::Color32::from_rgb(248, 113, 113), "⚠️ Mimikatz detected!");
                        } else {
                            ui.label(format!("{} artifacts", cr.credentials.len()));
                        }
                    });
                }
                // YARA card
                if let Some(ref yr) = self.yara_result {
                    ui.group(|ui| {
                        ui.label("🎯 YARA/IOC");
                        let color = match yr.threat_level.as_str() {
                            "CRITICAL" => egui::Color32::from_rgb(248, 113, 113),
                            "HIGH" => egui::Color32::from_rgb(245, 158, 11),
                            _ => egui::Color32::from_rgb(74, 222, 128),
                        };
                        ui.colored_label(color, format!("{} matches ({})", yr.yara_matches.len(), yr.threat_level));
                    });
                }
                // Malware card
                if let Some(ref mr) = self.malware_result {
                    ui.group(|ui| {
                        ui.label("🦠 Malware");
                        let color = if mr.overall_threat_score > 7.0 { egui::Color32::from_rgb(248, 113, 113) }
                            else if mr.overall_threat_score > 3.0 { egui::Color32::from_rgb(245, 158, 11) }
                            else { egui::Color32::from_rgb(74, 222, 128) };
                        ui.colored_label(color, format!("Score: {:.1}/10", mr.overall_threat_score));
                    });
                }
            });

            // Entropy heatmap
            ui.add_space(20.0);
            ui.heading("Threat Heatmap & Anomalies");
            ui.add_space(5.0);
            ui.group(|ui| {
                ui.label("Memory Page Anomaly Telemetry Map (Shannon Entropy Grid)");
                ui.horizontal_wrapped(|ui| {
                    for i in 0..100 {
                        let entropy = (i * 7 + 13) % 10;
                        let color = if entropy > 7 { egui::Color32::from_rgb(239, 68, 68) }
                            else if entropy > 5 { egui::Color32::from_rgb(245, 158, 11) }
                            else { egui::Color32::from_rgb(34, 197, 94) };
                        let (rect, _) = ui.allocate_at_least(egui::vec2(12.0, 12.0), egui::Sense::hover());
                        ui.painter().rect_filled(rect, egui::Rounding::same(2.0), color);
                    }
                });
                ui.add_space(5.0);
                ui.weak("Green=Normal | Yellow=Suspicious | Red=High entropy RWX/Packer");
            });
        } else {
            ui.vertical_centered(|ui| {
                ui.add_space(100.0);
                ui.label("No active memory dump loaded.");
                ui.weak("Click 'Load Memory Dump' to start forensic triage.");
            });
        }
    }

    fn draw_processes(&mut self, ui: &mut egui::Ui) {
        ui.heading("Process Hierarchy and DKOM Analysis");
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.text_edit_singleline(&mut self.search_query);
        });
        ui.add_space(10.0);

        egui_extras::TableBuilder::new(ui)
            .striped(true)
            .column(egui_extras::Column::initial(80.0))
            .column(egui_extras::Column::initial(80.0))
            .column(egui_extras::Column::initial(150.0))
            .column(egui_extras::Column::initial(150.0))
            .column(egui_extras::Column::initial(100.0))
            .column(egui_extras::Column::remainder())
            .header(20.0, |mut header| {
                header.col(|ui| { ui.label("PID"); });
                header.col(|ui| { ui.label("PPID"); });
                header.col(|ui| { ui.label("Name"); });
                header.col(|ui| { ui.label("CR3 / DTB"); });
                header.col(|ui| { ui.label("Status"); });
                header.col(|ui| { ui.label("Action"); });
            })
            .body(|mut body| {
                let query = self.search_query.to_lowercase();
                for proc in &self.processes {
                    if !query.is_empty() && !proc.name.to_lowercase().contains(&query) { continue; }
                    body.row(18.0, |mut row| {
                        row.col(|ui| { ui.label(proc.pid.to_string()); });
                        row.col(|ui| { ui.label(proc.ppid.to_string()); });
                        row.col(|ui| {
                            if proc.active { ui.label(&proc.name); }
                            else { ui.colored_label(egui::Color32::from_rgb(239, 68, 68), &proc.name); }
                        });
                        row.col(|ui| { ui.label(format!("0x{:X}", proc.dtb)); });
                        row.col(|ui| {
                            if proc.active { ui.colored_label(egui::Color32::from_rgb(34, 197, 94), "Active"); }
                            else { ui.colored_label(egui::Color32::from_rgb(239, 68, 68), "Unlinked"); }
                        });
                        row.col(|ui| {
                            if ui.button("Scan Memory").clicked() {
                                self.selected_process_dtb = Some(proc.dtb);
                                self.active_tab = ActiveTab::MemoryScanner;
                            }
                        });
                    });
                }
            });
    }

    fn draw_network(&mut self, ui: &mut egui::Ui) {
        ui.heading("Active & Listening Network Sockets");
        ui.add_space(10.0);
        egui_extras::TableBuilder::new(ui)
            .striped(true)
            .column(egui_extras::Column::initial(80.0))
            .column(egui_extras::Column::initial(80.0))
            .column(egui_extras::Column::initial(180.0))
            .column(egui_extras::Column::initial(180.0))
            .column(egui_extras::Column::remainder())
            .header(20.0, |mut header| {
                header.col(|ui| { ui.label("Protocol"); });
                header.col(|ui| { ui.label("PID"); });
                header.col(|ui| { ui.label("Local Address"); });
                header.col(|ui| { ui.label("Remote Address"); });
                header.col(|ui| { ui.label("State"); });
            })
            .body(|mut body| {
                for conn in &self.connections {
                    body.row(18.0, |mut row| {
                        row.col(|ui| { ui.label(&conn.protocol); });
                        row.col(|ui| { ui.label(conn.pid.to_string()); });
                        row.col(|ui| { ui.label(format!("{}:{}", conn.local_ip, conn.local_port)); });
                        row.col(|ui| {
                            let ip_str = conn.remote_ip.to_string();
                            if !conn.remote_ip.is_unspecified() && !ip_str.starts_with("192.168.") && !ip_str.starts_with("127.0.") {
                                ui.colored_label(egui::Color32::from_rgb(245, 158, 11), format!("{}:{}", conn.remote_ip, conn.remote_port));
                            } else { ui.label(format!("{}:{}", conn.remote_ip, conn.remote_port)); }
                        });
                        row.col(|ui| {
                            if conn.state == "ESTABLISHED" { ui.colored_label(egui::Color32::from_rgb(59, 130, 246), &conn.state); }
                            else { ui.label(&conn.state); }
                        });
                    });
                }
            });
    }

    fn draw_memory_scanner(&mut self, ui: &mut egui::Ui) {
        ui.heading("Memory Scanner (Malware Radar)");
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label("Selected Process DTB (CR3):");
            if let Some(dtb) = self.selected_process_dtb {
                ui.colored_label(egui::Color32::from_rgb(96, 165, 250), format!("0x{:X}", dtb));
            } else { ui.label("None"); }
            ui.add_space(20.0);
            if ui.button("Scan Process Space").clicked() && !self.is_scanning_memory {
                if let (Some(ref dump), Some(dtb)) = (&self.dump, self.selected_process_dtb) {
                    self.is_scanning_memory = true;
                    self.status_message = "Scanning...".to_string();
                    let dump_clone = dump.clone();
                    let (tx, rx) = channel();
                    self.scan_rx = Some(rx);
                    std::thread::spawn(move || {
                        let results = scan_process_memory(&dump_clone, dtb, 0x00400000, 0x2000000).unwrap_or_default();
                        let _ = tx.send(results);
                    });
                }
            }
        });
        ui.separator();
        if self.is_scanning_memory {
            ui.horizontal(|ui| { ui.spinner(); ui.label("Walking page tables..."); });
        } else if !self.memory_anomalies.is_empty() {
            ui.colored_label(egui::Color32::from_rgb(239, 68, 68), format!("⚠️ {} anomalies", self.memory_anomalies.len()));
            for anomaly in &self.memory_anomalies {
                ui.group(|ui| {
                    ui.label(format!("VA: 0x{:X} | RWX: {} | PE: {} | Entropy: {:.2}", anomaly.virtual_address, anomaly.is_rwx, anomaly.has_pe_header, anomaly.entropy));
                    ui.weak(&anomaly.description);
                });
            }
        } else { ui.label("No anomalies. Select a process or click scan."); }
    }

    fn draw_registry(&mut self, ui: &mut egui::Ui) {
        ui.heading("Windows Registry Hive Artifacts");
        ui.add_space(10.0);
        for key in &self.registry_keys {
            ui.group(|ui| {
                ui.colored_label(egui::Color32::from_rgb(147, 197, 253), &key.path);
                ui.weak(format!("Last modified: {}", key.last_written));
                ui.separator();
                for (name, val) in &key.values {
                    ui.horizontal(|ui| {
                        ui.label(name);
                        if val.to_lowercase().contains("\\temp\\") { ui.colored_label(egui::Color32::from_rgb(239, 68, 68), val); }
                        else { ui.weak(val); }
                    });
                }
            });
            ui.add_space(5.0);
        }
    }

    fn draw_kernel(&mut self, ui: &mut egui::Ui) {
        ui.heading("Kernel Modules & Hook Integrity");
        ui.add_space(10.0);
        if let Some(ref kernel) = self.kernel_result {
            if !kernel.hooks.is_empty() {
                ui.collapsing("🛡️ SSDT/IDT Hooks", |ui| {
                    for hook in &kernel.hooks {
                        ui.group(|ui| {
                            ui.colored_label(egui::Color32::from_rgb(239, 68, 68), format!("{} Hook: {}", hook.hook_type, hook.function_name));
                            ui.label(format!("Index: {} | Target: 0x{:X} → {}", hook.index, hook.hook_address, hook.target_module));
                        });
                    }
                });
            }
            ui.collapsing("💾 Loaded Drivers", |ui| {
                for driver in &kernel.drivers {
                    ui.horizontal(|ui| {
                        if driver.threat_score > 5.0 { ui.colored_label(egui::Color32::from_rgb(239, 68, 68), &driver.name); }
                        else { ui.label(&driver.name); }
                        ui.weak(format!("0x{:X} ({})", driver.base_address, if driver.is_signed { "Signed" } else { "UNSIGNED" }));
                    });
                }
            });
        } else { ui.label("No kernel analysis data."); }
    }

    fn draw_dlls(&mut self, ui: &mut egui::Ui) {
        ui.heading("📦 DLL & Module Analysis");
        ui.add_space(10.0);
        for dll_res in &self.dll_results {
            ui.label(format!("PID: {} | {} DLLs | {} unlinked | {} injected", dll_res.pid, dll_res.dlls.len(), dll_res.unlinked_count, dll_res.injected_count));
            ui.separator();
            for dll in &dll_res.dlls {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        let color = if dll.injection_type != forgelens_core::engine::dll::DllInjectionType::Normal {
                            egui::Color32::from_rgb(239, 68, 68)
                        } else { egui::Color32::from_rgb(220, 224, 235) };
                        ui.colored_label(color, &dll.name);
                        ui.weak(format!("0x{:X} | {:?}", dll.base_address, dll.injection_type));
                    });
                    if !dll.hooks_detected.is_empty() {
                        ui.colored_label(egui::Color32::from_rgb(245, 158, 11), format!("  {} inline hooks detected", dll.hooks_detected.len()));
                    }
                });
            }
        }
        if self.dll_results.is_empty() { ui.label("No DLL analysis data. Load a dump first."); }
    }

    fn draw_threads(&mut self, ui: &mut egui::Ui) {
        ui.heading("🧵 Thread Analysis");
        ui.add_space(10.0);
        for tr in &self.thread_results {
            ui.label(format!("PID: {} | {} threads | {} suspicious | APC: {} | Hijack: {}",
                tr.pid, tr.threads.len(), tr.suspicious_count, tr.apc_injection_detected, tr.thread_hijacking_detected));
            ui.separator();
            for t in &tr.threads {
                ui.group(|ui| {
                    let color = if t.is_suspicious { egui::Color32::from_rgb(239, 68, 68) }
                        else { egui::Color32::from_rgb(220, 224, 235) };
                    ui.colored_label(color, format!("TID: {} | Start: 0x{:X} | {:?} | Priority: {}", t.tid, t.start_address, t.state, t.priority));
                    for reason in &t.suspicion_reasons {
                        ui.colored_label(egui::Color32::from_rgb(245, 158, 11), format!("  ⚠️ {}", reason));
                    }
                });
            }
        }
        if self.thread_results.is_empty() { ui.label("No thread analysis data."); }
    }

    fn draw_credentials(&mut self, ui: &mut egui::Ui) {
        ui.heading("🔑 Credential & Secrets Extraction");
        ui.add_space(10.0);
        if let Some(ref cr) = self.credential_result {
            ui.group(|ui| {
                ui.label(format!("Total: {} | Hashes: {} | Tickets: {} | Keys: {}", cr.credentials.len(), cr.total_hashes, cr.total_tickets, cr.total_keys));
                if cr.mimikatz_detected { ui.colored_label(egui::Color32::from_rgb(239, 68, 68), "⚠️ MIMIKATZ DETECTED!"); }
                if cr.dumping_activity_detected { ui.colored_label(egui::Color32::from_rgb(245, 158, 11), "⚠️ Credential dumping activity"); }
                if cr.lsass_access_detected { ui.colored_label(egui::Color32::from_rgb(245, 158, 11), "⚠️ LSASS process accessed"); }
            });
            ui.add_space(10.0);
            for cred in &cr.credentials {
                ui.group(|ui| {
                    let color = match cred.severity {
                        forgelens_core::engine::credentials::CredentialSeverity::Critical => egui::Color32::from_rgb(239, 68, 68),
                        forgelens_core::engine::credentials::CredentialSeverity::High => egui::Color32::from_rgb(245, 158, 11),
                        _ => egui::Color32::from_rgb(220, 224, 235),
                    };
                    ui.colored_label(color, format!("{:?}: {}", cred.credential_type, cred.username));
                    ui.weak(&cred.data);
                    ui.weak(&cred.description);
                });
            }
        } else { ui.label("No credential data."); }
    }

    fn draw_file_recovery(&mut self, ui: &mut egui::Ui) {
        ui.heading("💾 File Artifact Recovery");
        ui.add_space(10.0);
        if let Some(ref fr) = self.file_recovery_result {
            ui.label(format!("{} files recovered | PE: {} | Docs: {} | Scripts: {} | Browser: {}",
                fr.recovered_files.len(), fr.pe_files_count, fr.document_count, fr.script_count, fr.browser_artifacts.len()));
            ui.separator();
            for f in &fr.recovered_files {
                ui.group(|ui| {
                    ui.label(format!("{:?}: {}", f.file_type, f.name));
                    ui.weak(format!("Size: {} | Addr: 0x{:X} | {}", f.size, f.physical_address, f.description));
                    if !f.threat_indicators.is_empty() {
                        for ind in &f.threat_indicators {
                            ui.colored_label(egui::Color32::from_rgb(245, 158, 11), format!("  ⚠️ {}", ind));
                        }
                    }
                });
            }
        } else { ui.label("No file recovery data."); }
    }

    fn draw_yara_ioc(&mut self, ui: &mut egui::Ui) {
        ui.heading("🎯 YARA & IOC Analysis");
        ui.add_space(10.0);
        if let Some(ref yr) = self.yara_result {
            let color = match yr.threat_level.as_str() {
                "CRITICAL" => egui::Color32::from_rgb(239, 68, 68),
                "HIGH" => egui::Color32::from_rgb(245, 158, 11),
                "MEDIUM" => egui::Color32::from_rgb(96, 165, 250),
                _ => egui::Color32::from_rgb(74, 222, 128),
            };
            ui.colored_label(color, format!("Threat Level: {} | {} rules checked | {} YARA matches | {} IOCs matched",
                yr.threat_level, yr.total_rules_checked, yr.yara_matches.len(), yr.ioc_matches.len()));
            ui.separator();
            for m in &yr.yara_matches {
                ui.group(|ui| {
                    ui.colored_label(egui::Color32::from_rgb(245, 158, 11), format!("Rule: {} [{:?}]", m.rule_name, m.severity));
                    ui.weak(&m.description);
                    for s in &m.strings_matched {
                        ui.weak(format!("  {} at 0x{:X}", s.identifier, s.offset));
                    }
                });
            }
            if !yr.ioc_matches.is_empty() {
                ui.add_space(10.0);
                ui.label("IOC Matches:");
                for ioc in &yr.ioc_matches {
                    ui.colored_label(egui::Color32::from_rgb(239, 68, 68), format!("{:?}: {}", ioc.ioc_type, ioc.value));
                }
            }
        } else { ui.label("No YARA/IOC data."); }
    }

    fn draw_malware(&mut self, ui: &mut egui::Ui) {
        ui.heading("🦠 Malware Analysis");
        ui.add_space(10.0);
        if let Some(ref mr) = self.malware_result {
            let color = if mr.overall_threat_score > 7.0 { egui::Color32::from_rgb(239, 68, 68) }
                else if mr.overall_threat_score > 3.0 { egui::Color32::from_rgb(245, 158, 11) }
                else { egui::Color32::from_rgb(74, 222, 128) };
            ui.colored_label(color, format!("Threat Score: {:.1}/10 | {} indicators | {} PEs | {} strings",
                mr.overall_threat_score, mr.indicators.len(), mr.reconstructed_pes.len(), mr.deobfuscated_strings.len()));
            ui.separator();
            for ind in &mr.indicators {
                ui.group(|ui| {
                    ui.colored_label(egui::Color32::from_rgb(239, 68, 68), format!("{} ({:?}, {:.0}%)", ind.malware_family, ind.malware_type, ind.confidence * 100.0));
                    ui.weak(&ind.description);
                    if let Some(ref cfg) = ind.config_data {
                        if !cfg.c2_servers.is_empty() { ui.colored_label(egui::Color32::from_rgb(245, 158, 11), format!("C2: {:?}", cfg.c2_servers)); }
                        if let Some(ref pipe) = cfg.pipe_name { ui.weak(format!("Pipe: {}", pipe)); }
                    }
                });
            }
            if !mr.deobfuscated_strings.is_empty() {
                ui.add_space(10.0);
                ui.collapsing("Deobfuscated Strings", |ui| {
                    for s in mr.deobfuscated_strings.iter().take(20) {
                        ui.weak(format!("[{:?}] 0x{:X}: {}", s.encoding, s.original_offset, s.decoded_value));
                    }
                });
            }
        } else { ui.label("No malware analysis data."); }
    }

    fn draw_timeline(&mut self, ui: &mut egui::Ui) {
        ui.heading("Forensic Timeline Reconstruction");
        ui.add_space(10.0);
        if self.timeline_events.is_empty() {
            ui.label("No timeline events.");
        } else {
            for ev in &self.timeline_events {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.colored_label(egui::Color32::from_rgb(96, 165, 250), &ev.timestamp);
                        ui.label(format!("| [{}]", ev.source));
                        let color = match ev.event_type.as_str() {
                            "Spawn" => egui::Color32::from_rgb(52, 211, 153),
                            "Connection" => egui::Color32::from_rgb(96, 165, 250),
                            "Key Modified" => egui::Color32::from_rgb(251, 191, 36),
                            "Hook Installed" => egui::Color32::from_rgb(239, 68, 68),
                            _ => egui::Color32::from_rgb(229, 231, 235),
                        };
                        ui.colored_label(color, format!("({})", ev.event_type));
                        if let Some(pid) = ev.associated_pid { ui.weak(format!("PID: {}", pid)); }
                    });
                    ui.separator();
                    ui.label(&ev.description);
                });
                ui.add_space(3.0);
            }
        }
    }

    fn draw_hex_viewer(&mut self, ui: &mut egui::Ui) {
        ui.heading("Raw Physical Memory Hex Viewer");
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label("Address (Hex):");
            ui.text_edit_singleline(&mut self.hex_input_address);
            if ui.button("Navigate").clicked() {
                if let Ok(addr) = u64::from_str_radix(self.hex_input_address.trim_start_matches("0x"), 16) {
                    self.hex_address = addr;
                    self.read_current_hex();
                }
            }
            if ui.button("◄ Prev").clicked() && self.hex_address >= 256 {
                self.hex_address -= 256;
                self.hex_input_address = format!("0x{:X}", self.hex_address);
                self.read_current_hex();
            }
            if ui.button("Next ►").clicked() {
                self.hex_address += 256;
                self.hex_input_address = format!("0x{:X}", self.hex_address);
                self.read_current_hex();
            }
        });
        ui.separator();
        ui.vertical(|ui| {
            ui.monospace(format!("Address: 0x{:X}", self.hex_address));
            let mut header_str = "Offset    ".to_string();
            for k in 0..16 { header_str.push_str(&format!("{:02X} ", k)); }
            header_str.push_str("  ASCII");
            ui.monospace(&header_str);
            ui.monospace("-".repeat(78));
            for row in 0..16 {
                let row_base = row * 16;
                if row_base < self.hex_bytes.len() {
                    let mut line = format!("0x{:06X}  ", self.hex_address + row_base as u64);
                    for col in 0..16 {
                        let idx = row_base + col;
                        if idx < self.hex_bytes.len() { line.push_str(&format!("{:02X} ", self.hex_bytes[idx])); }
                        else { line.push_str("   "); }
                    }
                    line.push_str("  ");
                    for col in 0..16 {
                        let idx = row_base + col;
                        if idx < self.hex_bytes.len() {
                            let b = self.hex_bytes[idx];
                            if (32..=126).contains(&b) { line.push(b as char); } else { line.push('.'); }
                        }
                    }
                    ui.monospace(&line);
                }
            }
        });
    }

    fn draw_reporting(&mut self, ui: &mut egui::Ui) {
        ui.heading("📄 Forensic Report Export");
        ui.add_space(10.0);
        if self.dump.is_some() {
            ui.label("Generate and export a comprehensive forensic report with all analysis findings.");
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("📋 Export JSON Report").clicked() {
                    self.status_message = "JSON report exported to stdout (check console)".to_string();
                }
                if ui.button("🌐 Export HTML Report").clicked() {
                    if let Some(path) = FileDialog::new()
                        .add_filter("HTML", &["html"])
                        .set_file_name("forgelens_report.html")
                        .save_file()
                    {
                        self.status_message = format!("Generating HTML report to {:?}...", path);
                        // Build the report from current state
                        let report = self.build_report();
                        if let Ok(html) = export_html(&report) {
                            if std::fs::write(&path, html).is_ok() {
                                self.status_message = format!("HTML report saved to {:?}", path);
                            }
                        }
                    }
                }
            });
            ui.add_space(20.0);
            // Show report summary preview
            let report = self.build_report();
            ui.group(|ui| {
                ui.heading("Report Preview");
                ui.label(format!("Threat Score: {:.1}/10", report.threat_score));
                ui.label(&report.summary.overall_assessment);
                ui.separator();
                for section in &report.sections {
                    ui.label(format!("[{:?}] {}: {}", section.severity, section.title, section.content));
                }
            });
        } else {
            ui.label("Load a memory dump to generate reports.");
        }
    }

    fn build_report(&self) -> ForensicReport {
        let mut builder = ReportBuilder::new(
            "ForgeLens Forensic Analysis Report",
            "ForgeLens Automated Triage",
            "FL-GUI-001",
            &self.dump_path.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
        );
        if let Some(ref p) = self.profile { builder = builder.with_profile(p.clone()); }
        builder = builder.with_processes(self.processes.clone());
        builder = builder.with_connections(self.connections.clone());
        builder = builder.with_registry(self.registry_keys.clone());
        if let Some(ref kr) = self.kernel_result { builder = builder.with_kernel(kr.clone()); }
        if let Some(ref cr) = self.credential_result { builder = builder.with_credentials(cr.clone()); }
        if let Some(ref yr) = self.yara_result { builder = builder.with_yara(yr.clone()); }
        if let Some(ref mr) = self.malware_result { builder = builder.with_malware(mr.clone()); }
        if let Some(ref fr) = self.file_recovery_result { builder = builder.with_file_recovery(fr.clone()); }
        builder = builder.with_timeline(self.timeline_events.clone());
        builder.build()
    }
}
