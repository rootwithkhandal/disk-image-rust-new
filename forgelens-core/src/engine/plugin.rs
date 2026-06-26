use crate::Result;
use std::collections::HashMap;

/// Plugin trait that all ForgeLens plugins must implement.
pub trait Plugin: Send + Sync {
    /// Returns the plugin name.
    fn name(&self) -> &str;
    /// Returns the plugin version.
    fn version(&self) -> &str;
    /// Returns the plugin description.
    fn description(&self) -> &str;
    /// Returns the plugin type.
    fn plugin_type(&self) -> PluginType;
    /// Executes the plugin with the given input data and returns output.
    fn run(&self, input: &PluginInput) -> Result<PluginOutput>;
}

/// Types of plugins supported.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum PluginType {
    Parser,           // Custom memory format parsers
    Scanner,          // Custom memory scanners
    YaraModule,       // Additional YARA rule sets
    ArtifactExtractor, // Custom artifact extractors
    Analyzer,         // Custom analysis engines
    Exporter,         // Custom report exporters
}

/// Input data provided to a plugin.
#[derive(Debug, Clone)]
pub struct PluginInput {
    pub data: Vec<u8>,
    pub context: HashMap<String, String>,
    pub offset: u64,
    pub dump_size: u64,
}

/// Output from a plugin execution.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginOutput {
    pub plugin_name: String,
    pub success: bool,
    pub findings: Vec<PluginFinding>,
    pub metadata: HashMap<String, String>,
}

/// A single finding from a plugin.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginFinding {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub offset: u64,
    pub data: HashMap<String, String>,
}

/// Plugin manifest describing a plugin's metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub plugin_type: PluginType,
    pub min_forgelens_version: String,
    pub supported_formats: Vec<String>,
    pub entry_point: String,
}

/// Plugin registry that manages discovery, loading, and execution of plugins.
pub struct PluginRegistry {
    plugins: Vec<Box<dyn Plugin>>,
    manifests: Vec<PluginManifest>,
    _plugin_dir: String,
}

impl PluginRegistry {
    pub fn new(plugin_dir: &str) -> Self {
        Self {
            plugins: Vec::new(),
            manifests: Vec::new(),
            _plugin_dir: plugin_dir.to_string(),
        }
    }

    /// Registers a built-in plugin.
    pub fn register(&mut self, plugin: Box<dyn Plugin>) {
        self.plugins.push(plugin);
    }

    /// Lists all registered plugins.
    pub fn list_plugins(&self) -> Vec<PluginInfo> {
        self.plugins.iter().map(|p| PluginInfo {
            name: p.name().to_string(),
            version: p.version().to_string(),
            description: p.description().to_string(),
            plugin_type: p.plugin_type(),
        }).collect()
    }

    /// Runs all plugins of a given type with the provided input.
    pub fn run_plugins_by_type(&self, ptype: PluginType, input: &PluginInput) -> Vec<PluginOutput> {
        let mut outputs = Vec::new();
        for plugin in &self.plugins {
            if plugin.plugin_type() == ptype {
                match plugin.run(input) {
                    Ok(output) => outputs.push(output),
                    Err(e) => {
                        outputs.push(PluginOutput {
                            plugin_name: plugin.name().to_string(),
                            success: false,
                            findings: Vec::new(),
                            metadata: {
                                let mut m = HashMap::new();
                                m.insert("error".to_string(), e.to_string());
                                m
                            },
                        });
                    }
                }
            }
        }
        outputs
    }

    /// Runs a specific plugin by name.
    pub fn run_plugin(&self, name: &str, input: &PluginInput) -> Option<PluginOutput> {
        for plugin in &self.plugins {
            if plugin.name() == name {
                return Some(plugin.run(input).unwrap_or(PluginOutput {
                    plugin_name: name.to_string(),
                    success: false,
                    findings: Vec::new(),
                    metadata: HashMap::new(),
                }));
            }
        }
        None
    }

    /// Returns the number of registered plugins.
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    /// Discovers plugin manifests from the plugin directory.
    pub fn discover_plugins(&mut self) -> Vec<PluginManifest> {
        // In a full implementation, this would:
        // 1. Scan the plugin directory for .wasm files or manifest.json files
        // 2. Load and validate each manifest
        // 3. Compile WASM plugins using wasmtime
        // 4. Register discovered plugins
        //
        // For now, return the built-in manifests
        self.manifests.clone()
    }
}

/// Summary info about a registered plugin.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub plugin_type: PluginType,
}

// ─── Built-in Plugins ────────────────────────────────────────

/// A sample built-in scanner plugin that checks for suspicious strings.
pub struct SuspiciousStringScanner;

impl Plugin for SuspiciousStringScanner {
    fn name(&self) -> &str { "suspicious_string_scanner" }
    fn version(&self) -> &str { "1.0.0" }
    fn description(&self) -> &str { "Scans memory chunks for suspicious command-line strings" }
    fn plugin_type(&self) -> PluginType { PluginType::Scanner }

    fn run(&self, input: &PluginInput) -> Result<PluginOutput> {
        let mut findings = Vec::new();

        let suspicious_patterns = [
            ("whoami", "Reconnaissance command"),
            ("net user", "User enumeration command"),
            ("net group", "Group enumeration command"),
            ("net localgroup administrators", "Admin group enumeration"),
            ("ipconfig /all", "Network reconnaissance"),
            ("systeminfo", "System reconnaissance"),
            ("tasklist", "Process enumeration"),
            ("reg query", "Registry query command"),
            ("wmic", "WMI command usage"),
            ("certutil -decode", "Certutil abuse for file decode"),
            ("bitsadmin", "BITS transfer abuse"),
            ("schtasks /create", "Scheduled task creation"),
            ("sc create", "Service creation command"),
        ];

        for (pattern, desc) in &suspicious_patterns {
            if let Some(pos) = input.data.windows(pattern.len()).position(|w| {
                w.iter().zip(pattern.as_bytes()).all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
            }) {
                findings.push(PluginFinding {
                    title: desc.to_string(),
                    description: format!("Found '{}' at offset 0x{:X}", pattern, input.offset + pos as u64),
                    severity: "MEDIUM".to_string(),
                    offset: input.offset + pos as u64,
                    data: {
                        let mut d = HashMap::new();
                        d.insert("pattern".to_string(), pattern.to_string());
                        d
                    },
                });
            }
        }

        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            success: true,
            findings,
            metadata: HashMap::new(),
        })
    }
}

/// Built-in plugin for detecting persistence mechanisms.
pub struct PersistenceDetector;

impl Plugin for PersistenceDetector {
    fn name(&self) -> &str { "persistence_detector" }
    fn version(&self) -> &str { "1.0.0" }
    fn description(&self) -> &str { "Detects common persistence mechanism strings in memory" }
    fn plugin_type(&self) -> PluginType { PluginType::Scanner }

    fn run(&self, input: &PluginInput) -> Result<PluginOutput> {
        let mut findings = Vec::new();

        let persistence_indicators = [
            ("CurrentVersion\\Run", "Registry Run key persistence"),
            ("CurrentVersion\\RunOnce", "Registry RunOnce key"),
            ("Task Scheduler", "Task scheduler persistence"),
            ("schtasks", "Scheduled task command"),
            ("WMI Event Subscription", "WMI persistence"),
            ("BITS", "BITS job persistence"),
            ("AppInit_DLLs", "AppInit DLL persistence"),
            ("Image File Execution Options", "IFEO debugger persistence"),
            ("Winlogon\\Shell", "Winlogon shell hijack"),
            ("Userinit", "Userinit persistence"),
        ];

        for (indicator, desc) in &persistence_indicators {
            if input.data.windows(indicator.len()).any(|w| {
                w.iter().zip(indicator.as_bytes()).all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
            }) {
                findings.push(PluginFinding {
                    title: desc.to_string(),
                    description: format!("Persistence indicator '{}' found", indicator),
                    severity: "HIGH".to_string(),
                    offset: input.offset,
                    data: HashMap::new(),
                });
            }
        }

        Ok(PluginOutput {
            plugin_name: self.name().to_string(),
            success: true,
            findings,
            metadata: HashMap::new(),
        })
    }
}

/// Creates a default plugin registry with all built-in plugins.
pub fn create_default_registry() -> PluginRegistry {
    let mut registry = PluginRegistry::new("plugins");
    registry.register(Box::new(SuspiciousStringScanner));
    registry.register(Box::new(PersistenceDetector));
    registry
}
