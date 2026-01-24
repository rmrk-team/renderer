use crate::config::Config;
use anyhow::{Result, anyhow};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;

#[derive(Clone)]
pub struct PinnedAssetStore {
    ipfs_dir: PathBuf,
    enabled: bool,
}

#[derive(Clone)]
pub struct PinnedAssetLocation {
    pub asset_key: String,
    pub cid: String,
    pub path: String,
    pub file_path: PathBuf,
}

impl PinnedAssetStore {
    pub fn new(config: &Config) -> Result<Self> {
        let ipfs_dir = config.pinned_dir.join("ipfs");
        if config.pinning_enabled {
            std::fs::create_dir_all(&ipfs_dir)?;
        }
        Ok(Self {
            ipfs_dir,
            enabled: config.pinning_enabled,
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn ipfs_location(&self, cid: &str, raw_path: &str) -> Result<PinnedAssetLocation> {
        if !is_valid_cid(cid) {
            return Err(anyhow!("invalid ipfs cid"));
        }
        let path = normalize_ipfs_path(raw_path)?;
        let file_path = if path.is_empty() {
            self.ipfs_dir.join(cid).join("__root__")
        } else {
            self.ipfs_dir.join(cid).join(&path)
        };
        let url_suffix = if path.is_empty() {
            String::new()
        } else {
            format!("/{}", path)
        };
        Ok(PinnedAssetLocation {
            asset_key: format!("ipfs://{cid}{url_suffix}"),
            cid: cid.to_string(),
            path,
            file_path,
        })
    }

    pub async fn store_bytes(&self, location: &PinnedAssetLocation, bytes: &[u8]) -> Result<()> {
        store_file_atomic(&location.file_path, bytes).await
    }
}

pub fn content_type_from_path(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".svg") || lower.ends_with(".svgz") {
        Some("image/svg+xml")
    } else if lower.ends_with(".png") {
        Some("image/png")
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        Some("image/jpeg")
    } else if lower.ends_with(".webp") {
        Some("image/webp")
    } else if lower.ends_with(".gif") {
        Some("image/gif")
    } else if lower.ends_with(".json") {
        Some("application/json")
    } else if lower.ends_with(".txt") {
        Some("text/plain; charset=utf-8")
    } else {
        None
    }
}

fn normalize_ipfs_path(path: &str) -> Result<String> {
    let trimmed = path.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.contains('\\') || trimmed.contains('\0') {
        return Err(anyhow!("invalid ipfs path"));
    }
    let candidate = Path::new(trimmed);
    for component in candidate.components() {
        match component {
            Component::Normal(_) => {}
            _ => return Err(anyhow!("invalid ipfs path")),
        }
    }
    Ok(trimmed.to_string())
}

fn is_valid_cid(cid: &str) -> bool {
    if cid.is_empty() {
        return false;
    }
    cid.chars().all(|ch| ch.is_ascii_alphanumeric())
}

async fn store_file_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("pinned");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let temp_path = parent.join(format!(".{file_name}.tmp-{nonce}"));
    if let Err(err) = fs::write(&temp_path, bytes).await {
        let _ = fs::remove_file(&temp_path).await;
        return Err(err.into());
    }
    if let Err(err) = fs::rename(&temp_path, path).await {
        let _ = fs::remove_file(&temp_path).await;
        return Err(err.into());
    }
    Ok(())
}
