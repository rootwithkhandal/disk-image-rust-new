use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use crate::error::Result;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CheckpointState {
    pub bytes_read: u64,
    pub bad_sectors: u64,
    pub pre_hash: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl CheckpointState {
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        let mut file = File::create(path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let state: Self = serde_json::from_str(&content)?;
        Ok(state)
    }
}
