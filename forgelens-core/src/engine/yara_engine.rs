use crate::{ingest::MemoryDump, Result};


/// A YARA rule match result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub rule_source: String,
    pub strings_matched: Vec<YaraStringMatch>,
    pub severity: YaraSeverity,
    pub description: String,
    pub tags: Vec<String>,
}

/// A matched YARA string within a rule.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct YaraStringMatch {
    pub identifier: String,
    pub offset: u64,
    pub length: usize,
    pub data_preview: String,
}

/// YARA match severity level.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum YaraSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// An Indicator of Compromise (IOC) entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IocEntry {
    pub ioc_type: IocType,
    pub value: String,
    pub source: String,
    pub matched: bool,
    pub match_offset: Option<u64>,
    pub context: String,
}

/// Types of IOCs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum IocType {
    IpAddress,
    Domain,
    Hash,
    Mutex,
    StringPattern,
    RegistryKey,
    FilePath,
    UserAgent,
    EmailAddress,
    Url,
}

/// Built-in YARA rule definition (compiled from text).
#[derive(Debug, Clone)]
pub struct BuiltinRule {
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub severity: YaraSeverity,
    pub strings: Vec<(String, Vec<u8>)>,  // (identifier, pattern bytes)
    pub hex_patterns: Vec<(String, Vec<u8>)>,
    pub condition_all: bool,  // true = all strings must match; false = any
    pub min_matches: usize,
}

/// Full YARA/IOC scan result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct YaraIocResult {
    pub yara_matches: Vec<YaraMatch>,
    pub ioc_matches: Vec<IocEntry>,
    pub total_rules_checked: usize,
    pub total_iocs_checked: usize,
    pub threat_level: String,
}

/// Runs YARA rules and IOC matching against the memory dump.
pub fn scan_yara_ioc(
    dump: &MemoryDump,
    custom_iocs: &[IocEntry],
) -> Result<YaraIocResult> {
    let mut yara_matches = Vec::new();
    let mut ioc_matches = Vec::new();

    // 1. Load and run built-in YARA rules
    let builtin_rules = get_builtin_rules();
    let total_rules = builtin_rules.len();

    for rule in &builtin_rules {
        if let Some(matches) = run_rule_against_dump(dump, rule) {
            yara_matches.push(matches);
        }
    }

    // 2. Run built-in IOC checks
    let mut builtin_iocs = get_builtin_iocs();
    builtin_iocs.extend(custom_iocs.iter().cloned());
    let total_iocs = builtin_iocs.len();

    for ioc in &mut builtin_iocs {
        match_ioc_against_dump(dump, ioc);
        if ioc.matched {
            ioc_matches.push(ioc.clone());
        }
    }

    // 3. Run regex pattern scans
    let regex_matches = run_regex_patterns(dump)?;
    for rmatch in regex_matches {
        yara_matches.push(rmatch);
    }

    // Determine overall threat level
    let critical_count = yara_matches.iter().filter(|m| m.severity == YaraSeverity::Critical).count();
    let high_count = yara_matches.iter().filter(|m| m.severity == YaraSeverity::High).count();

    let threat_level = if critical_count > 0 {
        "CRITICAL".to_string()
    } else if high_count > 0 {
        "HIGH".to_string()
    } else if !yara_matches.is_empty() {
        "MEDIUM".to_string()
    } else if !ioc_matches.is_empty() {
        "LOW".to_string()
    } else {
        "CLEAN".to_string()
    };

    Ok(YaraIocResult {
        yara_matches,
        ioc_matches,
        total_rules_checked: total_rules,
        total_iocs_checked: total_iocs,
        threat_level,
    })
}

/// Returns built-in YARA-like rules for common malware families.
fn get_builtin_rules() -> Vec<BuiltinRule> {
    vec![
        BuiltinRule {
            name: "CobaltStrike_Beacon".to_string(),
            description: "Detects Cobalt Strike beacon payload in memory".to_string(),
            tags: vec!["APT".to_string(), "C2".to_string(), "CobaltStrike".to_string()],
            severity: YaraSeverity::Critical,
            strings: vec![
                ("$watermark".to_string(), b"MSSE-".to_vec()),
                ("$config".to_string(), b"\x00\x01\x00\x01\x00\x02".to_vec()),
                ("$beacon_dll".to_string(), b"beacon.dll".to_vec()),
                ("$beacon_x64".to_string(), b"beacon.x64.dll".to_vec()),
            ],
            hex_patterns: vec![
                ("$sleep_mask".to_string(), vec![0x4C, 0x8B, 0x53, 0x08, 0x45, 0x8B, 0x0A]),
                ("$pipe_name".to_string(), b"\\\\.\\pipe\\msagent_".to_vec()),
            ],
            condition_all: false,
            min_matches: 2,
        },
        BuiltinRule {
            name: "Meterpreter_Payload".to_string(),
            description: "Detects Metasploit Meterpreter payload in memory".to_string(),
            tags: vec!["Metasploit".to_string(), "Meterpreter".to_string()],
            severity: YaraSeverity::Critical,
            strings: vec![
                ("$metsrv".to_string(), b"metsrv.dll".to_vec()),
                ("$stdapi".to_string(), b"stdapi".to_vec()),
                ("$priv".to_string(), b"priv".to_vec()),
                ("$reverse_tcp".to_string(), b"reverse_tcp".to_vec()),
            ],
            hex_patterns: vec![
                ("$stage_marker".to_string(), vec![0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00]),
            ],
            condition_all: false,
            min_matches: 2,
        },
        BuiltinRule {
            name: "Sliver_Implant".to_string(),
            description: "Detects Sliver C2 implant in memory".to_string(),
            tags: vec!["Sliver".to_string(), "C2".to_string()],
            severity: YaraSeverity::Critical,
            strings: vec![
                ("$sliver1".to_string(), b"sliver".to_vec()),
                ("$protobuf".to_string(), b"sliverpb".to_vec()),
                ("$grpc".to_string(), b"grpc-go".to_vec()),
            ],
            hex_patterns: vec![],
            condition_all: false,
            min_matches: 2,
        },
        BuiltinRule {
            name: "Mimikatz_Signature".to_string(),
            description: "Detects Mimikatz credential dumping tool".to_string(),
            tags: vec!["CredentialDump".to_string(), "Mimikatz".to_string()],
            severity: YaraSeverity::Critical,
            strings: vec![
                ("$mimi1".to_string(), b"mimikatz".to_vec()),
                ("$mimi2".to_string(), b"gentilkiwi".to_vec()),
                ("$mimi3".to_string(), b"sekurlsa::".to_vec()),
                ("$mimi4".to_string(), b"kerberos::".to_vec()),
                ("$mimi5".to_string(), b"lsadump::".to_vec()),
            ],
            hex_patterns: vec![],
            condition_all: false,
            min_matches: 2,
        },
        BuiltinRule {
            name: "PowerShell_Encoded_Command".to_string(),
            description: "Detects Base64-encoded PowerShell commands".to_string(),
            tags: vec!["PowerShell".to_string(), "Obfuscation".to_string()],
            severity: YaraSeverity::High,
            strings: vec![
                ("$enc_cmd".to_string(), b"-EncodedCommand".to_vec()),
                ("$enc_cmd2".to_string(), b"-enc ".to_vec()),
                ("$hidden".to_string(), b"-WindowStyle Hidden".to_vec()),
                ("$bypass".to_string(), b"-ExecutionPolicy Bypass".to_vec()),
                ("$noprofile".to_string(), b"-NoProfile".to_vec()),
            ],
            hex_patterns: vec![],
            condition_all: false,
            min_matches: 2,
        },
        BuiltinRule {
            name: "Suspicious_PE_In_Memory".to_string(),
            description: "Detects suspicious PE characteristics in non-backed memory".to_string(),
            tags: vec!["Packer".to_string(), "Injection".to_string()],
            severity: YaraSeverity::Medium,
            strings: vec![
                ("$upx".to_string(), b"UPX0".to_vec()),
                ("$upx1".to_string(), b"UPX1".to_vec()),
                ("$themida".to_string(), b"Themida".to_vec()),
                ("$vmprotect".to_string(), b"VMProtect".to_vec()),
                ("$aspack".to_string(), b"ASPack".to_vec()),
            ],
            hex_patterns: vec![],
            condition_all: false,
            min_matches: 1,
        },
        BuiltinRule {
            name: "Webshell_Indicators".to_string(),
            description: "Detects webshell strings in memory".to_string(),
            tags: vec!["Webshell".to_string(), "Backdoor".to_string()],
            severity: YaraSeverity::High,
            strings: vec![
                ("$eval".to_string(), b"eval(base64_decode".to_vec()),
                ("$asp".to_string(), b"Execute(Request".to_vec()),
                ("$cmd".to_string(), b"cmd.exe /c".to_vec()),
                ("$chopper".to_string(), b"China Chopper".to_vec()),
            ],
            hex_patterns: vec![],
            condition_all: false,
            min_matches: 1,
        },
        BuiltinRule {
            name: "Ransomware_Indicators".to_string(),
            description: "Detects ransomware indicators in memory".to_string(),
            tags: vec!["Ransomware".to_string()],
            severity: YaraSeverity::Critical,
            strings: vec![
                ("$ransom1".to_string(), b"Your files have been encrypted".to_vec()),
                ("$ransom2".to_string(), b"bitcoin".to_vec()),
                ("$ransom3".to_string(), b".onion".to_vec()),
                ("$ransom4".to_string(), b"decrypt".to_vec()),
                ("$ransom5".to_string(), b"CryptEncrypt".to_vec()),
                ("$ransom6".to_string(), b"CryptGenKey".to_vec()),
            ],
            hex_patterns: vec![],
            condition_all: false,
            min_matches: 3,
        },
    ]
}

/// Runs a single built-in rule against the memory dump.
fn run_rule_against_dump(dump: &MemoryDump, rule: &BuiltinRule) -> Option<YaraMatch> {
    let scan_limit = std::cmp::min(dump.file_size() as u64, 512 * 1024 * 1024);
    let mut matched_strings = Vec::new();
    let mut offset = 0u64;
    let mut buf = vec![0u8; 2 * 1024 * 1024]; // 2MB chunks

    while offset + buf.len() as u64 <= scan_limit {
        if dump.read_physical(offset, &mut buf).is_ok() {
            // Check string patterns
            for (id, pattern) in &rule.strings {
                if matched_strings.iter().any(|m: &YaraStringMatch| m.identifier == *id) {
                    continue;
                }
                // Case-insensitive scan
                if let Some(pos) = buf.windows(pattern.len()).position(|w| {
                    w.iter().zip(pattern.iter()).all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
                }) {
                    let preview_end = std::cmp::min(pos + pattern.len() + 32, buf.len());
                    let preview = String::from_utf8_lossy(&buf[pos..preview_end])
                        .chars().take(64).collect::<String>();

                    matched_strings.push(YaraStringMatch {
                        identifier: id.clone(),
                        offset: offset + pos as u64,
                        length: pattern.len(),
                        data_preview: preview,
                    });
                }
            }

            // Check hex patterns
            for (id, pattern) in &rule.hex_patterns {
                if matched_strings.iter().any(|m: &YaraStringMatch| m.identifier == *id) {
                    continue;
                }
                if let Some(pos) = buf.windows(pattern.len()).position(|w| w == pattern.as_slice()) {
                    let hex_preview: String = buf[pos..std::cmp::min(pos + 16, buf.len())]
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(" ");

                    matched_strings.push(YaraStringMatch {
                        identifier: id.clone(),
                        offset: offset + pos as u64,
                        length: pattern.len(),
                        data_preview: hex_preview,
                    });
                }
            }
        }
        offset += buf.len() as u64 - 256;
    }

    // Check condition
    let match_count = matched_strings.len();
    let should_match = if rule.condition_all {
        match_count >= rule.strings.len() + rule.hex_patterns.len()
    } else {
        match_count >= rule.min_matches
    };

    if should_match && match_count > 0 {
        Some(YaraMatch {
            rule_name: rule.name.clone(),
            rule_source: "Built-in ForgeLens Rule".to_string(),
            strings_matched: matched_strings,
            severity: rule.severity.clone(),
            description: rule.description.clone(),
            tags: rule.tags.clone(),
        })
    } else {
        None
    }
}

/// Returns built-in IOC entries for common threats.
fn get_builtin_iocs() -> Vec<IocEntry> {
    vec![
        // Known C2 indicators
        IocEntry {
            ioc_type: IocType::IpAddress,
            value: "185.112.144.63".to_string(),
            source: "ForgeLens Threat Intel".to_string(),
            matched: false,
            match_offset: None,
            context: "Known C2 infrastructure IP".to_string(),
        },
        IocEntry {
            ioc_type: IocType::IpAddress,
            value: "91.92.248.".to_string(),
            source: "ForgeLens Threat Intel".to_string(),
            matched: false,
            match_offset: None,
            context: "Suspicious hosting range (Bullet-proof hosting)".to_string(),
        },
        IocEntry {
            ioc_type: IocType::Domain,
            value: "evil.corp".to_string(),
            source: "ForgeLens Threat Intel".to_string(),
            matched: false,
            match_offset: None,
            context: "Known malicious domain".to_string(),
        },
        IocEntry {
            ioc_type: IocType::Mutex,
            value: "Global\\MSCTF.Shared.MUTEX.ZRF".to_string(),
            source: "ForgeLens Threat Intel".to_string(),
            matched: false,
            match_offset: None,
            context: "Mutex associated with APT activity".to_string(),
        },
        IocEntry {
            ioc_type: IocType::FilePath,
            value: "\\AppData\\Local\\Temp\\update.exe".to_string(),
            source: "ForgeLens Threat Intel".to_string(),
            matched: false,
            match_offset: None,
            context: "Suspicious executable in temp directory".to_string(),
        },
        IocEntry {
            ioc_type: IocType::UserAgent,
            value: "Mozilla/5.0 (compatible; MSIE 6.0".to_string(),
            source: "ForgeLens Threat Intel".to_string(),
            matched: false,
            match_offset: None,
            context: "Outdated user agent string (common in malware)".to_string(),
        },
    ]
}

/// Matches a single IOC against the memory dump.
fn match_ioc_against_dump(dump: &MemoryDump, ioc: &mut IocEntry) {
    let pattern = ioc.value.as_bytes();
    let scan_limit = std::cmp::min(dump.file_size() as u64, 256 * 1024 * 1024);
    let mut offset = 0u64;
    let mut buf = vec![0u8; 1024 * 1024];

    while offset + buf.len() as u64 <= scan_limit {
        if dump.read_physical(offset, &mut buf).is_ok() {
            if let Some(pos) = buf.windows(pattern.len()).position(|w| {
                w.iter().zip(pattern.iter()).all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
            }) {
                ioc.matched = true;
                ioc.match_offset = Some(offset + pos as u64);
                return;
            }
        }
        offset += buf.len() as u64 - 256;
    }
}

/// Runs regex-like pattern scans for additional threat indicators.
fn run_regex_patterns(dump: &MemoryDump) -> Result<Vec<YaraMatch>> {
    let mut results = Vec::new();

    // Base64-encoded PowerShell detection
    // PowerShell encoded commands start with common base64 prefixes
    let b64_prefixes = [
        (b"JAB" as &[u8], "Base64 PowerShell variable declaration"),
        (b"SQBFAF" as &[u8], "Base64 encoded 'IEX' (Invoke-Expression)"),
        (b"SQBuAH" as &[u8], "Base64 encoded 'Inv' (Invoke-*)"),
        (b"aW1wb3" as &[u8], "Base64 encoded 'import' (Python)"),
        (b"cG93ZX" as &[u8], "Base64 encoded 'power' (PowerShell)"),
    ];

    let scan_limit = std::cmp::min(dump.file_size() as u64, 128 * 1024 * 1024);
    let mut offset = 0u64;
    let mut buf = vec![0u8; 1024 * 1024];

    while offset + buf.len() as u64 <= scan_limit {
        if dump.read_physical(offset, &mut buf).is_ok() {
            for (prefix, desc) in &b64_prefixes {
                if let Some(pos) = buf.windows(prefix.len()).position(|w| w == *prefix) {
                    // Verify it's actually a long base64 string (at least 64 chars)
                    let mut b64_len = 0;
                    for j in pos..std::cmp::min(pos + 8192, buf.len()) {
                        let c = buf[j];
                        if c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=' {
                            b64_len += 1;
                        } else {
                            break;
                        }
                    }

                    if b64_len >= 64 {
                        let preview = String::from_utf8_lossy(&buf[pos..std::cmp::min(pos + 80, buf.len())])
                            .to_string();

                        results.push(YaraMatch {
                            rule_name: "Base64_Encoded_Script".to_string(),
                            rule_source: "Regex Pattern Engine".to_string(),
                            strings_matched: vec![YaraStringMatch {
                                identifier: "$b64_prefix".to_string(),
                                offset: offset + pos as u64,
                                length: b64_len,
                                data_preview: format!("{}... ({} bytes)", preview, b64_len),
                            }],
                            severity: YaraSeverity::High,
                            description: format!("{} - {} bytes of base64 encoded data", desc, b64_len),
                            tags: vec!["Obfuscation".to_string(), "Base64".to_string()],
                        });
                    }
                }
            }
        }
        offset += buf.len() as u64 - 256;
    }

    Ok(results)
}
