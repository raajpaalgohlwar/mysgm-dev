use serde::Serialize;
use std::{
    fs::OpenOptions,
    io::Write,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

static METRICS_FILE: OnceLock<Mutex<std::fs::File>> = OnceLock::new();

#[derive(Debug, Serialize)]
pub struct MetricsEvent {
    pub ts_start_ms: u128,
    pub ts_end_ms: u128,
    pub duration_ms: u128,
    pub node_id: Option<String>,
    pub gid: Option<String>,
    pub op: String,
    pub result: String,
    pub error: Option<String>,
    pub members_before: Option<usize>,
    pub members_after: Option<usize>,
    pub commit_bytes: Option<usize>,
    pub welcome_bytes: Option<usize>,
    pub update_count: Option<u64>,
    pub welcome_index: Option<u64>,
    pub commit_key: Option<String>,
    pub dht_key: Option<String>,
    pub payload_bytes: Option<usize>,
    pub http_status: Option<u16>,
    pub welcome_processed: Option<bool>,
    pub commit_merged: Option<bool>,
}

impl MetricsEvent {
    pub fn new(op: &str, ts_start_ms: u128, ts_end_ms: u128) -> Self {
        Self {
            ts_start_ms,
            ts_end_ms,
            duration_ms: ts_end_ms.saturating_sub(ts_start_ms),
            node_id: None,
            gid: None,
            op: op.to_string(),
            result: "ok".to_string(),
            error: None,
            members_before: None,
            members_after: None,
            commit_bytes: None,
            welcome_bytes: None,
            update_count: None,
            welcome_index: None,
            commit_key: None,
            dht_key: None,
            payload_bytes: None,
            http_status: None,
            welcome_processed: None,
            commit_merged: None,
        }
    }
}

pub fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub fn init_metrics_logger(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    METRICS_FILE
        .set(Mutex::new(file))
        .map_err(|_| "Metrics logger already initialized".into())
}

pub fn log_event(event: &MetricsEvent) {
    let Some(file_mutex) = METRICS_FILE.get() else {
        return;
    };

    if let Ok(mut file) = file_mutex.lock() {
        if let Ok(json_line) = serde_json::to_string(event) {
            let _ = writeln!(file, "{json_line}");
        }
    }
}
