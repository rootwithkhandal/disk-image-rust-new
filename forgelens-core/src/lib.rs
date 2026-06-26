pub mod ingest;
pub mod translate;
pub mod profile;
pub mod engine;
pub mod timeline;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ForgeLensError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Format detection failed: {0}")]
    InvalidFormat(String),

    #[error("Address translation error: {0}")]
    TranslationError(String),

    #[error("Profile match failed: {0}")]
    ProfileNotFound(String),

    #[error("Analysis error: {0}")]
    AnalysisError(String),

    #[error("DLL analysis error: {0}")]
    DllAnalysisError(String),

    #[error("Thread analysis error: {0}")]
    ThreadAnalysisError(String),

    #[error("Credential extraction error: {0}")]
    CredentialError(String),

    #[error("File recovery error: {0}")]
    FileRecoveryError(String),

    #[error("YARA/IOC scan error: {0}")]
    YaraError(String),

    #[error("Malware analysis error: {0}")]
    MalwareError(String),

    #[error("Symbol resolution error: {0}")]
    SymbolError(String),

    #[error("Reporting error: {0}")]
    ReportingError(String),

    #[error("Plugin error: {0}")]
    PluginError(String),

    #[error("Acquisition error: {0}")]
    AcquisitionError(String),
}

pub type Result<T> = std::result::Result<T, ForgeLensError>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::translate::VirtualAddress;
    use crate::engine::memory::calculate_entropy;

    #[test]
    fn test_virtual_address_parsing() {
        let va = VirtualAddress(0x7FFE0000);
        assert_eq!(va.pml4_index(), 0);
        assert_eq!(va.pdpt_index(), 1);
        assert_eq!(va.pd_index(), 399);
        assert_eq!(va.pt_index(), 480);
        assert_eq!(va.offset_4k(), 0);
    }

    #[test]
    fn test_entropy_calculation() {
        // Flat bytes (all zeros) should have zero entropy
        let data_zeros = vec![0u8; 100];
        assert_eq!(calculate_entropy(&data_zeros), 0.0);

        // Fully unique uniform distribution bytes
        let mut data_uniform = Vec::new();
        for i in 0..256 {
            data_uniform.push(i as u8);
        }
        // Max entropy for 256 states is 8.0 bits
        assert!((calculate_entropy(&data_uniform) - 8.0).abs() < 1e-9);
    }
}
