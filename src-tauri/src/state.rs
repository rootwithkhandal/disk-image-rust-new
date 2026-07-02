use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Mutex;
use tokio::sync::mpsc::Sender;
use tauri::{AppHandle, Manager};
use crate::error::Result;
use crate::acquisition::ProgressEvent;

#[allow(dead_code)]
pub type ActiveTaskState = Mutex<Option<Sender<ProgressEvent>>>;

#[allow(dead_code)]
pub fn clear_active_task(app_handle: &AppHandle) {
    let state_guard = app_handle.state::<ActiveTaskState>();
    let mut lock = state_guard.lock().unwrap();
    *lock = None;
}

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
