use crate::{Result, ForgeLensError};
use crate::engine::{
    process::Process,
    network::NetworkConnection,
    registry::RegistryKey,
    kernel::KernelAnalysisResult,
    dll::DllAnalysisResult,
    thread::ThreadAnalysisResult,
    credentials::CredentialAnalysisResult,
    yara_engine::YaraIocResult,
    malware::MalwareAnalysisResult,
    file_recovery::FileRecoveryResult,
};
use crate::timeline::TimelineEvent;
use crate::profile::OsProfile;
use chrono::Utc;

/// A complete forensic report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ForensicReport {
    pub title: String,
    pub generated_at: String,
    pub examiner: String,
    pub case_id: String,
    pub dump_file: String,
    pub profile: Option<OsProfile>,
    pub summary: ReportSummary,
    pub sections: Vec<ReportSection>,
    pub threat_score: f64,
    pub ioc_summary: Vec<String>,
    pub evidence_references: Vec<EvidenceReference>,
}

/// Executive summary of findings.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReportSummary {
    pub total_processes: usize,
    pub suspicious_processes: usize,
    pub total_connections: usize,
    pub suspicious_connections: usize,
    pub malware_detected: bool,
    pub credential_dumping: bool,
    pub kernel_hooks: usize,
    pub yara_matches: usize,
    pub overall_assessment: String,
}

/// A section within the report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReportSection {
    pub title: String,
    pub content: String,
    pub severity: SectionSeverity,
    pub subsections: Vec<ReportSubsection>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReportSubsection {
    pub title: String,
    pub content: String,
}

/// Section severity level for visual highlighting.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum SectionSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

/// An evidence reference linking findings to physical addresses.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvidenceReference {
    pub evidence_id: String,
    pub description: String,
    pub physical_address: u64,
    pub category: String,
}

/// Report builder that aggregates analysis results into a report.
pub struct ReportBuilder {
    title: String,
    examiner: String,
    case_id: String,
    dump_file: String,
    profile: Option<OsProfile>,
    processes: Vec<Process>,
    connections: Vec<NetworkConnection>,
    registry_keys: Vec<RegistryKey>,
    kernel_result: Option<KernelAnalysisResult>,
    _dll_results: Vec<DllAnalysisResult>,
    _thread_results: Vec<ThreadAnalysisResult>,
    credential_result: Option<CredentialAnalysisResult>,
    yara_result: Option<YaraIocResult>,
    malware_result: Option<MalwareAnalysisResult>,
    file_recovery: Option<FileRecoveryResult>,
    timeline: Vec<TimelineEvent>,
}

impl ReportBuilder {
    pub fn new(title: &str, examiner: &str, case_id: &str, dump_file: &str) -> Self {
        Self {
            title: title.to_string(),
            examiner: examiner.to_string(),
            case_id: case_id.to_string(),
            dump_file: dump_file.to_string(),
            profile: None,
            processes: Vec::new(),
            connections: Vec::new(),
            registry_keys: Vec::new(),
            kernel_result: None,
            _dll_results: Vec::new(),
            _thread_results: Vec::new(),
            credential_result: None,
            yara_result: None,
            malware_result: None,
            file_recovery: None,
            timeline: Vec::new(),
        }
    }

    pub fn with_profile(mut self, profile: OsProfile) -> Self { self.profile = Some(profile); self }
    pub fn with_processes(mut self, procs: Vec<Process>) -> Self { self.processes = procs; self }
    pub fn with_connections(mut self, conns: Vec<NetworkConnection>) -> Self { self.connections = conns; self }
    pub fn with_registry(mut self, keys: Vec<RegistryKey>) -> Self { self.registry_keys = keys; self }
    pub fn with_kernel(mut self, kr: KernelAnalysisResult) -> Self { self.kernel_result = Some(kr); self }
    pub fn with_credentials(mut self, cr: CredentialAnalysisResult) -> Self { self.credential_result = Some(cr); self }
    pub fn with_yara(mut self, yr: YaraIocResult) -> Self { self.yara_result = Some(yr); self }
    pub fn with_malware(mut self, mr: MalwareAnalysisResult) -> Self { self.malware_result = Some(mr); self }
    pub fn with_file_recovery(mut self, fr: FileRecoveryResult) -> Self { self.file_recovery = Some(fr); self }
    pub fn with_timeline(mut self, tl: Vec<TimelineEvent>) -> Self { self.timeline = tl; self }

    /// Builds the complete forensic report.
    pub fn build(self) -> ForensicReport {
        let mut sections = Vec::new();
        let mut evidence_refs = Vec::new();
        let mut threat_score = 0.0;
        let mut ioc_summary = Vec::new();

        // --- System Profile Section ---
        if let Some(ref profile) = self.profile {
            sections.push(ReportSection {
                title: "System Profile".to_string(),
                content: format!(
                    "OS: {:?} | Kernel: {} | Arch: {} | CR3: 0x{:X}",
                    profile.family, profile.kernel_version, profile.architecture, profile.kernel_dtb
                ),
                severity: SectionSeverity::Informational,
                subsections: vec![],
            });
        }

        // --- Process Analysis Section ---
        let unlinked = self.processes.iter().filter(|p| !p.active).count();
        let proc_severity = if unlinked > 0 { SectionSeverity::High } else { SectionSeverity::Low };
        if unlinked > 0 { threat_score += 3.0; }

        let mut proc_subs = Vec::new();
        for proc in &self.processes {
            if !proc.active {
                proc_subs.push(ReportSubsection {
                    title: format!("Unlinked Process: {} (PID {})", proc.name, proc.pid),
                    content: format!("PPID: {}, DTB: 0x{:X} — process was found via carving but not in active list (DKOM indicator)", proc.ppid, proc.dtb),
                });
                evidence_refs.push(EvidenceReference {
                    evidence_id: format!("PROC-{}", proc.pid),
                    description: format!("Unlinked process: {}", proc.name),
                    physical_address: 0,
                    category: "Process".to_string(),
                });
            }
        }
        sections.push(ReportSection {
            title: "Process Analysis".to_string(),
            content: format!("{} processes found, {} unlinked/carved", self.processes.len(), unlinked),
            severity: proc_severity,
            subsections: proc_subs,
        });

        // --- Network Analysis Section ---
        let sus_conns: Vec<_> = self.connections.iter().filter(|c| {
            let ip = c.remote_ip.to_string();
            !ip.starts_with("192.168.") && !ip.starts_with("10.") && !ip.starts_with("127.") && !c.remote_ip.is_unspecified()
        }).collect();
        if !sus_conns.is_empty() { threat_score += 2.0; }
        let net_subs: Vec<_> = sus_conns.iter().map(|c| ReportSubsection {
            title: format!("{} → {}:{}", c.local_ip, c.remote_ip, c.remote_port),
            content: format!("PID: {}, Proto: {}, State: {}", c.pid, c.protocol, c.state),
        }).collect();
        sections.push(ReportSection {
            title: "Network Connections".to_string(),
            content: format!("{} connections, {} external/suspicious", self.connections.len(), sus_conns.len()),
            severity: if sus_conns.is_empty() { SectionSeverity::Low } else { SectionSeverity::Medium },
            subsections: net_subs,
        });

        // --- Kernel Analysis Section ---
        if let Some(ref kr) = self.kernel_result {
            let hook_count = kr.hooks.len();
            if hook_count > 0 { threat_score += 5.0; }
            let k_subs: Vec<_> = kr.hooks.iter().map(|h| ReportSubsection {
                title: format!("{} Hook: {}", h.hook_type, h.function_name),
                content: format!("Hook addr: 0x{:X}, Target: {}, Severity: {}", h.hook_address, h.target_module, h.severity),
            }).collect();
            sections.push(ReportSection {
                title: "Kernel Forensics".to_string(),
                content: format!("{} drivers, {} hooks detected", kr.drivers.len(), hook_count),
                severity: if hook_count > 0 { SectionSeverity::Critical } else { SectionSeverity::Low },
                subsections: k_subs,
            });
        }

        // --- Credential Analysis Section ---
        let mut cred_dumping = false;
        // mimikatz will be set later
        if let Some(ref cr) = self.credential_result {
            cred_dumping = cr.dumping_activity_detected;
            let mimikatz = cr.mimikatz_detected;
            if cred_dumping { threat_score += 4.0; }
            if mimikatz { threat_score += 5.0; }
            sections.push(ReportSection {
                title: "Credential Analysis".to_string(),
                content: format!(
                    "{} credentials found | Hashes: {} | Tickets: {} | Dumping detected: {} | Mimikatz: {}",
                    cr.credentials.len(), cr.total_hashes, cr.total_tickets, cr.dumping_activity_detected, cr.mimikatz_detected
                ),
                severity: if mimikatz { SectionSeverity::Critical } else if cred_dumping { SectionSeverity::High } else { SectionSeverity::Medium },
                subsections: cr.credentials.iter().take(10).map(|c| ReportSubsection {
                    title: format!("{:?}: {}", c.credential_type, c.username),
                    content: c.description.clone(),
                }).collect(),
            });
        }

        // --- YARA/IOC Section ---
        let mut yara_matches = 0;
        if let Some(ref yr) = self.yara_result {
            yara_matches = yr.yara_matches.len();
            if yara_matches > 0 { threat_score += 3.0; }
            for m in &yr.yara_matches {
                ioc_summary.push(format!("YARA: {} ({:?})", m.rule_name, m.severity));
            }
            for ioc in &yr.ioc_matches {
                ioc_summary.push(format!("IOC: {:?} = {}", ioc.ioc_type, ioc.value));
            }
            sections.push(ReportSection {
                title: "YARA & IOC Analysis".to_string(),
                content: format!(
                    "{} YARA matches, {} IOCs matched | Threat Level: {}",
                    yr.yara_matches.len(), yr.ioc_matches.len(), yr.threat_level
                ),
                severity: match yr.threat_level.as_str() {
                    "CRITICAL" => SectionSeverity::Critical,
                    "HIGH" => SectionSeverity::High,
                    "MEDIUM" => SectionSeverity::Medium,
                    _ => SectionSeverity::Low,
                },
                subsections: yr.yara_matches.iter().map(|m| ReportSubsection {
                    title: format!("Rule: {} [{:?}]", m.rule_name, m.severity),
                    content: m.description.clone(),
                }).collect(),
            });
        }

        // --- Malware Analysis Section ---
        let mut malware_detected = false;
        if let Some(ref mr) = self.malware_result {
            malware_detected = !mr.indicators.is_empty();
            if malware_detected { threat_score += mr.overall_threat_score; }
            sections.push(ReportSection {
                title: "Malware Analysis".to_string(),
                content: format!(
                    "{} indicators, {} reconstructed PEs, {} deobfuscated strings | Score: {:.1}",
                    mr.indicators.len(), mr.reconstructed_pes.len(), mr.deobfuscated_strings.len(), mr.overall_threat_score
                ),
                severity: if mr.overall_threat_score > 7.0 { SectionSeverity::Critical } else if mr.overall_threat_score > 4.0 { SectionSeverity::High } else { SectionSeverity::Medium },
                subsections: mr.indicators.iter().map(|i| ReportSubsection {
                    title: format!("{} ({:.0}% confidence)", i.malware_family, i.confidence * 100.0),
                    content: i.description.clone(),
                }).collect(),
            });
        }

        // --- Timeline Section ---
        if !self.timeline.is_empty() {
            sections.push(ReportSection {
                title: "Event Timeline".to_string(),
                content: format!("{} events reconstructed", self.timeline.len()),
                severity: SectionSeverity::Informational,
                subsections: self.timeline.iter().take(20).map(|e| ReportSubsection {
                    title: format!("[{}] {} - {}", e.timestamp, e.source, e.event_type),
                    content: e.description.clone(),
                }).collect(),
            });
        }

        // Overall assessment
        let assessment = if threat_score >= 15.0 {
            "CRITICAL — Active compromise detected with high confidence. Immediate incident response recommended.".to_string()
        } else if threat_score >= 8.0 {
            "HIGH — Multiple suspicious indicators found. Further investigation strongly recommended.".to_string()
        } else if threat_score >= 3.0 {
            "MEDIUM — Some anomalies detected. Review findings and determine if further analysis is needed.".to_string()
        } else {
            "LOW — No significant threats detected. System appears clean based on available evidence.".to_string()
        };

        let summary = ReportSummary {
            total_processes: self.processes.len(),
            suspicious_processes: unlinked,
            total_connections: self.connections.len(),
            suspicious_connections: sus_conns.len(),
            malware_detected,
            credential_dumping: cred_dumping,
            kernel_hooks: self.kernel_result.as_ref().map(|k| k.hooks.len()).unwrap_or(0),
            yara_matches,
            overall_assessment: assessment,
        };

        ForensicReport {
            title: self.title,
            generated_at: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            examiner: self.examiner,
            case_id: self.case_id,
            dump_file: self.dump_file,
            profile: self.profile,
            summary,
            sections,
            threat_score: threat_score.min(10.0),
            ioc_summary,
            evidence_references: evidence_refs,
        }
    }
}

/// Exports a report to JSON format.
pub fn export_json(report: &ForensicReport) -> Result<String> {
    serde_json::to_string_pretty(report).map_err(ForgeLensError::Serialization)
}

/// Exports a report to CSV format (flattened summary).
pub fn export_csv(report: &ForensicReport) -> Result<String> {
    let mut csv = String::new();
    csv.push_str("Section,Severity,Content\n");
    for section in &report.sections {
        csv.push_str(&format!(
            "\"{}\",\"{:?}\",\"{}\"\n",
            section.title,
            section.severity,
            section.content.replace('"', "\"\"")
        ));
        for sub in &section.subsections {
            csv.push_str(&format!(
                "\"  {}\",\"\",\"{}\"\n",
                sub.title.replace('"', "\"\""),
                sub.content.replace('"', "\"\"")
            ));
        }
    }
    Ok(csv)
}

/// Exports a report to self-contained HTML.
pub fn export_html(report: &ForensicReport) -> Result<String> {
    let mut html = String::new();
    html.push_str("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">");
    html.push_str(&format!("<title>{}</title>", report.title));
    html.push_str("<style>");
    html.push_str("body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}");
    html.push_str("h1{color:#58a6ff;border-bottom:2px solid #30363d;padding-bottom:10px}");
    html.push_str("h2{color:#79c0ff;margin-top:30px}h3{color:#d2a8ff}");
    html.push_str(".card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:12px 0}");
    html.push_str(".critical{border-left:4px solid #f85149}.high{border-left:4px solid #d29922}");
    html.push_str(".medium{border-left:4px solid #3fb950}.low{border-left:4px solid #58a6ff}");
    html.push_str(".info{border-left:4px solid #8b949e}");
    html.push_str("table{width:100%;border-collapse:collapse;margin:10px 0}");
    html.push_str("th,td{text-align:left;padding:8px;border-bottom:1px solid #30363d}");
    html.push_str("th{background:#21262d;color:#79c0ff}");
    html.push_str(".score{font-size:48px;font-weight:bold;text-align:center;padding:20px}");
    html.push_str(".score.crit{color:#f85149}.score.high{color:#d29922}.score.med{color:#3fb950}.score.low{color:#58a6ff}");
    html.push_str(".badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:12px;font-weight:600;margin:2px}");
    html.push_str(".badge-crit{background:#f8514933;color:#f85149}.badge-high{background:#d2992233;color:#d29922}");
    html.push_str(".badge-med{background:#3fb95033;color:#3fb950}.badge-low{background:#58a6ff33;color:#58a6ff}");
    html.push_str("</style></head><body>");

    html.push_str(&format!("<h1>🔬 {}</h1>", report.title));
    html.push_str("<div class='card info'>");
    html.push_str(&format!("<p><b>Case ID:</b> {} | <b>Examiner:</b> {} | <b>Generated:</b> {}</p>",
        report.case_id, report.examiner, report.generated_at));
    html.push_str(&format!("<p><b>Dump File:</b> {}</p>", report.dump_file));
    html.push_str("</div>");

    // Threat score
    let score_class = if report.threat_score >= 7.0 { "crit" } else if report.threat_score >= 4.0 { "high" } else if report.threat_score >= 2.0 { "med" } else { "low" };
    html.push_str(&format!("<div class='card'><div class='score {}'>{:.1}/10</div><p style='text-align:center'>{}</p></div>",
        score_class, report.threat_score, report.summary.overall_assessment));

    // Summary table
    html.push_str("<h2>📊 Executive Summary</h2><div class='card'><table>");
    html.push_str(&format!("<tr><td>Processes</td><td>{} ({} suspicious)</td></tr>", report.summary.total_processes, report.summary.suspicious_processes));
    html.push_str(&format!("<tr><td>Network Connections</td><td>{} ({} suspicious)</td></tr>", report.summary.total_connections, report.summary.suspicious_connections));
    html.push_str(&format!("<tr><td>Malware Detected</td><td>{}</td></tr>", if report.summary.malware_detected { "⚠️ YES" } else { "✅ No" }));
    html.push_str(&format!("<tr><td>Credential Dumping</td><td>{}</td></tr>", if report.summary.credential_dumping { "⚠️ YES" } else { "✅ No" }));
    html.push_str(&format!("<tr><td>Kernel Hooks</td><td>{}</td></tr>", report.summary.kernel_hooks));
    html.push_str(&format!("<tr><td>YARA Matches</td><td>{}</td></tr>", report.summary.yara_matches));
    html.push_str("</table></div>");

    // Sections
    for section in &report.sections {
        let sev_class = match section.severity {
            SectionSeverity::Critical => "critical",
            SectionSeverity::High => "high",
            SectionSeverity::Medium => "medium",
            SectionSeverity::Low => "low",
            SectionSeverity::Informational => "info",
        };
        let badge_class = match section.severity {
            SectionSeverity::Critical => "badge-crit",
            SectionSeverity::High => "badge-high",
            SectionSeverity::Medium => "badge-med",
            _ => "badge-low",
        };
        html.push_str(&format!("<h2>{} <span class='badge {}'>{:?}</span></h2>", section.title, badge_class, section.severity));
        html.push_str(&format!("<div class='card {}'><p>{}</p>", sev_class, section.content));
        for sub in &section.subsections {
            html.push_str(&format!("<h3>{}</h3><p>{}</p>", sub.title, sub.content));
        }
        html.push_str("</div>");
    }

    // IOC Summary
    if !report.ioc_summary.is_empty() {
        html.push_str("<h2>🎯 IOC Summary</h2><div class='card'><ul>");
        for ioc in &report.ioc_summary {
            html.push_str(&format!("<li>{}</li>", ioc));
        }
        html.push_str("</ul></div>");
    }

    html.push_str("<p style='text-align:center;color:#8b949e;margin-top:40px'>Generated by ForgeLens Memory Forensics Framework</p>");
    html.push_str("</body></html>");
    Ok(html)
}
