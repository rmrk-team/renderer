use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::warn;

const DEFAULT_MAX_BYTES: u64 = 102_400;

#[derive(Clone)]
pub struct FailureLog {
    path: PathBuf,
    max_bytes: u64,
    guard: Arc<Mutex<()>>,
}

#[derive(Serialize)]
pub struct FailureLogEntry {
    pub timestamp_ms: u64,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub route_group: String,
    pub ip: Option<String>,
    pub identity: Option<String>,
    pub reason: Option<String>,
}

impl FailureLogEntry {
    pub fn new(
        method: String,
        path: String,
        status: u16,
        route_group: String,
        ip: Option<String>,
        identity: Option<String>,
        reason: Option<String>,
    ) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);
        Self {
            timestamp_ms,
            method,
            path,
            status,
            route_group,
            ip,
            identity,
            reason,
        }
    }
}

impl FailureLog {
    pub fn new(path: PathBuf, max_bytes: u64) -> Option<Self> {
        if path.as_os_str().is_empty() {
            return None;
        }
        let max_bytes = if max_bytes == 0 {
            DEFAULT_MAX_BYTES
        } else {
            max_bytes
        };
        Some(Self {
            path,
            max_bytes,
            guard: Arc::new(Mutex::new(())),
        })
    }

    pub async fn write(&self, entry: FailureLogEntry) {
        let line = match serde_json::to_string(&entry) {
            Ok(value) => value,
            Err(err) => {
                warn!(error = ?err, "failed to serialize failure log entry");
                return;
            }
        };
        let _guard = self.guard.lock().await;
        if let Some(parent) = self.path.parent() {
            if let Err(err) = fs::create_dir_all(parent).await {
                warn!(error = ?err, path = %self.path.display(), "failed to create failure log dir");
                return;
            }
        }
        let line_bytes = line.as_bytes();
        let line_len = line_bytes.len() as u64 + 1;
        match fs::metadata(&self.path).await {
            Ok(metadata) => {
                if metadata.len().saturating_add(line_len) > self.max_bytes {
                    if let Err(err) = fs::OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&self.path)
                        .await
                    {
                        warn!(error = ?err, path = %self.path.display(), "failed to truncate failure log");
                        return;
                    }
                }
            }
            Err(err) => {
                if err.kind() != std::io::ErrorKind::NotFound {
                    warn!(error = ?err, path = %self.path.display(), "failed to stat failure log");
                    return;
                }
            }
        }
        let mut file = match fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
        {
            Ok(file) => file,
            Err(err) => {
                warn!(error = ?err, path = %self.path.display(), "failed to open failure log");
                return;
            }
        };
        if let Err(err) = file.write_all(line_bytes).await {
            warn!(error = ?err, path = %self.path.display(), "failed to write failure log");
            return;
        }
        let _ = file.write_all(b"\n").await;
    }
}
