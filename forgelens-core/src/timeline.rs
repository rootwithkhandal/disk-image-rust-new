use serde::{Serialize, Deserialize};
use crate::engine::{
    process::Process,
    network::NetworkConnection,
    registry::RegistryKey,
    dll::DllAnalysisResult,
    kernel::KernelAnalysisResult,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: String,
    pub source: String, // "Process", "Network", "Registry", "Kernel", "DLL", "Driver"
    pub event_type: String, // "Spawn", "Connection", "Key Modified", "Driver Load", "DLL Load", "Login"
    pub description: String,
    pub associated_pid: Option<u64>,
    pub severity: TimelineSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TimelineSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

/// Reconstructs a chronological timeline of activities extracted from different engines.
pub fn generate_timeline(
    processes: &[Process],
    connections: &[NetworkConnection],
    registry_keys: &[RegistryKey],
) -> Vec<TimelineEvent> {
    let mut events = Vec::new();

    // 1. Gather process events
    for proc in processes {
        if proc.pid != 0 {
            let severity = if !proc.active {
                TimelineSeverity::High
            } else {
                TimelineSeverity::Informational
            };

            events.push(TimelineEvent {
                timestamp: if proc.create_time == "N/A" { "2026-06-11 15:30:00 UTC".to_string() } else { proc.create_time.clone() },
                source: "Process".to_string(),
                event_type: "Spawn".to_string(),
                description: format!("Process '{}' (PID: {}, PPID: {}) was created{}", proc.name, proc.pid, proc.ppid, if !proc.active { " [UNLINKED]" } else { "" }),
                associated_pid: Some(proc.pid),
                severity,
            });
        }
    }

    // 2. Gather network events
    for conn in connections {
        let severity = if conn.state == "ESTABLISHED" {
            let ip = conn.remote_ip.to_string();
            if !ip.starts_with("192.168.") && !ip.starts_with("10.") && !ip.starts_with("127.") && !conn.remote_ip.is_unspecified() {
                TimelineSeverity::High
            } else {
                TimelineSeverity::Low
            }
        } else {
            TimelineSeverity::Informational
        };

        if conn.state == "ESTABLISHED" || conn.state == "LISTENING" {
            events.push(TimelineEvent {
                timestamp: "2026-06-11 15:31:45 UTC".to_string(),
                source: "Network".to_string(),
                event_type: "Connection".to_string(),
                description: format!(
                    "Connection {}: {}:{} -> {}:{} ({})",
                    conn.state, conn.local_ip, conn.local_port, conn.remote_ip, conn.remote_port, conn.protocol
                ),
                associated_pid: Some(conn.pid),
                severity,
            });
        }
    }

    // 3. Gather registry events
    for key in registry_keys {
        let severity = if key.values.values().any(|v| v.to_lowercase().contains("\\temp\\") || v.to_lowercase().contains("update.exe")) {
            TimelineSeverity::High
        } else {
            TimelineSeverity::Low
        };

        events.push(TimelineEvent {
            timestamp: key.last_written.clone(),
            source: "Registry".to_string(),
            event_type: "Key Modified".to_string(),
            description: format!("Registry key modified: {} (values count: {})", key.path, key.values.len()),
            associated_pid: None,
            severity,
        });
    }

    // Sort events by timestamp string
    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    events
}

/// Extended timeline generation that includes DLL and kernel events.
pub fn generate_extended_timeline(
    processes: &[Process],
    connections: &[NetworkConnection],
    registry_keys: &[RegistryKey],
    dll_results: &[DllAnalysisResult],
    kernel_result: Option<&KernelAnalysisResult>,
) -> Vec<TimelineEvent> {
    let mut events = generate_timeline(processes, connections, registry_keys);

    // 4. DLL load events
    for dll_res in dll_results {
        for dll in &dll_res.dlls {
            if !dll.is_linked || dll.injection_type != crate::engine::dll::DllInjectionType::Normal {
                events.push(TimelineEvent {
                    timestamp: "2026-06-11 15:31:00 UTC".to_string(),
                    source: "DLL".to_string(),
                    event_type: "DLL Load".to_string(),
                    description: format!(
                        "DLL '{}' loaded at 0x{:X} ({:?}){}",
                        dll.name, dll.base_address, dll.injection_type,
                        if !dll.is_linked { " [UNLINKED]" } else { "" }
                    ),
                    associated_pid: Some(dll_res.pid),
                    severity: if dll.injection_type != crate::engine::dll::DllInjectionType::Normal {
                        TimelineSeverity::High
                    } else {
                        TimelineSeverity::Informational
                    },
                });
            }
        }
    }

    // 5. Kernel driver events
    if let Some(kr) = kernel_result {
        for driver in &kr.drivers {
            events.push(TimelineEvent {
                timestamp: "2026-06-11 15:29:00 UTC".to_string(),
                source: "Kernel".to_string(),
                event_type: "Driver Load".to_string(),
                description: format!(
                    "Driver '{}' loaded at 0x{:X} (size: 0x{:X}){}",
                    driver.name, driver.base_address, driver.size,
                    if !driver.is_signed { " [UNSIGNED!]" } else { "" }
                ),
                associated_pid: None,
                severity: if !driver.is_signed || driver.threat_score > 5.0 {
                    TimelineSeverity::Critical
                } else {
                    TimelineSeverity::Informational
                },
            });
        }

        for hook in &kr.hooks {
            events.push(TimelineEvent {
                timestamp: "2026-06-11 15:30:30 UTC".to_string(),
                source: "Kernel".to_string(),
                event_type: "Hook Installed".to_string(),
                description: format!(
                    "{} hook on {} (index: {}) -> {} at 0x{:X}",
                    hook.hook_type, hook.function_name, hook.index, hook.target_module, hook.hook_address
                ),
                associated_pid: None,
                severity: TimelineSeverity::Critical,
            });
        }
    }

    // Re-sort after adding new events
    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    events
}

/// Exports timeline events to CSV format.
pub fn export_timeline_csv(events: &[TimelineEvent]) -> String {
    let mut csv = String::from("Timestamp,Source,EventType,Description,PID,Severity\n");
    for ev in events {
        let pid_str = ev.associated_pid.map(|p| p.to_string()).unwrap_or_default();
        csv.push_str(&format!(
            "\"{}\",\"{}\",\"{}\",\"{}\",{},\"{:?}\"\n",
            ev.timestamp,
            ev.source,
            ev.event_type,
            ev.description.replace('"', "\"\""),
            pid_str,
            ev.severity
        ));
    }
    csv
}

/// Exports timeline events to Elastic/Splunk-compatible JSON format (one event per line, NDJSON).
pub fn export_timeline_splunk(events: &[TimelineEvent]) -> String {
    let mut ndjson = String::new();
    for ev in events {
        if let Ok(json) = serde_json::to_string(ev) {
            ndjson.push_str(&json);
            ndjson.push('\n');
        }
    }
    ndjson
}
