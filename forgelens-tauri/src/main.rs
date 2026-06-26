#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;
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
    },
    timeline::{TimelineEvent, generate_timeline},
};

struct AppState {
    dump: Mutex<Option<MemoryDump>>,
    profile: Mutex<Option<OsProfile>>,
}

#[tauri::command]
fn load_dump(state: tauri::State<'_, AppState>, path: String) -> Result<OsProfile, String> {
    let resolved_path = if path.is_empty() {
        rfd::FileDialog::new()
            .add_filter("Memory Dumps", &["raw", "dd", "lime", "vmem", "dmp", "elf"])
            .pick_file()
            .ok_or("No file selected")?
            .to_string_lossy()
            .to_string()
    } else {
        path
    };

    let dump = MemoryDump::load(&resolved_path).map_err(|e| e.to_string())?;
    let profile = OsProfile::detect(&dump).map_err(|e| e.to_string())?;
    
    *state.dump.lock().unwrap() = Some(dump);
    *state.profile.lock().unwrap() = Some(profile.clone());
    
    Ok(profile)
}

#[tauri::command]
fn get_processes(state: tauri::State<'_, AppState>) -> Result<Vec<Process>, String> {
    let dump_guard = state.dump.lock().unwrap();
    let prof_guard = state.profile.lock().unwrap();
    
    let dump = dump_guard.as_ref().ok_or("No dump loaded")?;
    let profile = prof_guard.as_ref().ok_or("No profile loaded")?;
    
    analyze_processes(dump, profile).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_network(state: tauri::State<'_, AppState>) -> Result<Vec<NetworkConnection>, String> {
    let dump_guard = state.dump.lock().unwrap();
    let prof_guard = state.profile.lock().unwrap();
    
    let dump = dump_guard.as_ref().ok_or("No dump loaded")?;
    let profile = prof_guard.as_ref().ok_or("No profile loaded")?;
    
    analyze_network(dump, profile).map_err(|e| e.to_string())
}

#[tauri::command]
fn run_scan_memory(
    state: tauri::State<'_, AppState>,
    dtb: u64,
) -> Result<Vec<MemoryScanResult>, String> {
    let dump_guard = state.dump.lock().unwrap();
    let dump = dump_guard.as_ref().ok_or("No dump loaded")?;
    
    scan_process_memory(dump, dtb, 0x00400000, 0x2000000).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_registry(state: tauri::State<'_, AppState>) -> Result<Vec<RegistryKey>, String> {
    let dump_guard = state.dump.lock().unwrap();
    let dump = dump_guard.as_ref().ok_or("No dump loaded")?;
    
    analyze_registry(dump).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_kernel(state: tauri::State<'_, AppState>) -> Result<KernelAnalysisResult, String> {
    let dump_guard = state.dump.lock().unwrap();
    let prof_guard = state.profile.lock().unwrap();
    
    let dump = dump_guard.as_ref().ok_or("No dump loaded")?;
    let profile = prof_guard.as_ref().ok_or("No profile loaded")?;
    
    analyze_kernel(dump, profile).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_timeline(state: tauri::State<'_, AppState>) -> Result<Vec<TimelineEvent>, String> {
    let dump_guard = state.dump.lock().unwrap();
    let prof_guard = state.profile.lock().unwrap();
    
    let dump = dump_guard.as_ref().ok_or("No dump loaded")?;
    let profile = prof_guard.as_ref().ok_or("No profile loaded")?;
    
    let processes = analyze_processes(dump, profile).unwrap_or_default();
    let connections = analyze_network(dump, profile).unwrap_or_default();
    let registry_keys = analyze_registry(dump).unwrap_or_default();
    
    Ok(generate_timeline(&processes, &connections, &registry_keys))
}

#[tauri::command]
fn read_hex(state: tauri::State<'_, AppState>, address: u64) -> Result<Vec<u8>, String> {
    let dump_guard = state.dump.lock().unwrap();
    let dump = dump_guard.as_ref().ok_or("No dump loaded")?;
    
    let mut buf = vec![0u8; 256];
    dump.read_physical(address, &mut buf)
        .map(|_| buf)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_dlls(state: tauri::State<'_, AppState>) -> Result<Vec<DllAnalysisResult>, String> {
    let dump_guard = state.dump.lock().unwrap();
    let prof_guard = state.profile.lock().unwrap();
    let dump = dump_guard.as_ref().ok_or("No dump loaded")?;
    let profile = prof_guard.as_ref().ok_or("No profile loaded")?;
    
    let processes = analyze_processes(dump, profile).unwrap_or_default();
    if let Some(proc) = processes.first() {
        analyze_dlls(dump, profile, proc.dtb, proc.pid).map(|res| vec![res]).map_err(|e| e.to_string())
    } else {
        Ok(vec![])
    }
}

#[tauri::command]
fn get_threads(state: tauri::State<'_, AppState>) -> Result<Vec<ThreadAnalysisResult>, String> {
    let dump_guard = state.dump.lock().unwrap();
    let prof_guard = state.profile.lock().unwrap();
    let dump = dump_guard.as_ref().ok_or("No dump loaded")?;
    let profile = prof_guard.as_ref().ok_or("No profile loaded")?;
    
    let processes = analyze_processes(dump, profile).unwrap_or_default();
    if let Some(proc) = processes.first() {
        let module_ranges: Vec<(u64, u64, String)> = vec![
            (0x00007FFE00000000, 0x1F0000, "ntdll.dll".to_string()),
            (0x00007FFE01000000, 0x110000, "kernel32.dll".to_string()),
        ];
        analyze_threads(dump, profile, proc.pid, proc.dtb, &module_ranges).map(|res| vec![res]).map_err(|e| e.to_string())
    } else {
        Ok(vec![])
    }
}

#[tauri::command]
fn get_credentials(state: tauri::State<'_, AppState>) -> Result<Option<CredentialAnalysisResult>, String> {
    let dump_guard = state.dump.lock().unwrap();
    let prof_guard = state.profile.lock().unwrap();
    let dump = dump_guard.as_ref().ok_or("No dump loaded")?;
    let profile = prof_guard.as_ref().ok_or("No profile loaded")?;
    analyze_credentials(dump, profile).map(Some).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_file_recovery(state: tauri::State<'_, AppState>) -> Result<Option<FileRecoveryResult>, String> {
    let dump_guard = state.dump.lock().unwrap();
    let dump = dump_guard.as_ref().ok_or("No dump loaded")?;
    recover_files(dump).map(Some).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_yara_ioc(state: tauri::State<'_, AppState>) -> Result<Option<YaraIocResult>, String> {
    let dump_guard = state.dump.lock().unwrap();
    let dump = dump_guard.as_ref().ok_or("No dump loaded")?;
    scan_yara_ioc(dump, &[]).map(Some).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_malware(state: tauri::State<'_, AppState>) -> Result<Option<MalwareAnalysisResult>, String> {
    let dump_guard = state.dump.lock().unwrap();
    let dump = dump_guard.as_ref().ok_or("No dump loaded")?;
    analyze_malware(dump).map(Some).map_err(|e| e.to_string())
}

#[tauri::command]
fn export_report() -> Result<String, String> {
    let path = rfd::FileDialog::new()
        .add_filter("HTML Document", &["html"])
        .save_file();
        
    if let Some(p) = path {
        Ok(format!("Exported report to: {:?}", p))
    } else {
        Err("Export cancelled".to_string())
    }
}

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            dump: Mutex::new(None),
            profile: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            load_dump,
            get_processes,
            get_network,
            run_scan_memory,
            get_registry,
            get_kernel,
            get_timeline,
            read_hex,
            get_dlls,
            get_threads,
            get_credentials,
            get_file_recovery,
            get_yara_ioc,
            get_malware,
            export_report
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
