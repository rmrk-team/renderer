use crate::config::Config;
use crate::render::OutputFormat;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub const FALLBACK_WIDTH_PRESETS: [(&str, u32); 6] = [
    ("thumb", 64u32),
    ("small", 128u32),
    ("medium", 256u32),
    ("large", 512u32),
    ("xl", 1024u32),
    ("xxl", 2048u32),
];
pub const FALLBACK_DEFAULT_WIDTH: u32 = 512;
pub const FALLBACK_OG_WIDTH: u32 = 1200;
pub const FALLBACK_OG_HEIGHT: u32 = 630;
pub const DEFAULT_UNAPPROVED_FALLBACK_LINE1: &str = "COLLECTION NOT APPROVED";
pub const DEFAULT_UNAPPROVED_FALLBACK_LINE2: &str = "PLEASE REGISTER TO VIEW";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackMeta {
    pub updated_at_ms: u64,
    pub source_sha256: String,
    pub source_width: u32,
    pub source_height: u32,
    pub variants: Vec<String>,
}

pub fn fallback_width_bucket(width_param: &Option<String>) -> u32 {
    if let Some(width) = width_param.as_ref() {
        if width == "original" {
            return FALLBACK_DEFAULT_WIDTH;
        }
        for (name, size) in FALLBACK_WIDTH_PRESETS.iter() {
            if width == name {
                return *size;
            }
        }
        if let Ok(value) = width.parse::<u32>() {
            let (_, nearest) = FALLBACK_WIDTH_PRESETS
                .iter()
                .min_by(|a, b| {
                    let da = a.1.abs_diff(value);
                    let db = b.1.abs_diff(value);
                    da.cmp(&db)
                })
                .unwrap_or(&("large", FALLBACK_DEFAULT_WIDTH));
            return *nearest;
        }
    }
    FALLBACK_DEFAULT_WIDTH
}

pub fn fallback_variant_label(og_mode: bool, width: u32) -> String {
    if og_mode {
        "og".to_string()
    } else {
        format!("w{width}")
    }
}

pub fn fallback_variant_filename(variant_label: &str, format: &OutputFormat) -> String {
    format!("{variant_label}.{}", format.extension())
}

pub fn fallback_etag(meta: &FallbackMeta, variant_label: &str, format: &OutputFormat) -> String {
    let mut hasher = Sha256::new();
    hasher.update(meta.source_sha256.as_bytes());
    hasher.update(b":");
    hasher.update(variant_label.as_bytes());
    hasher.update(b":");
    hasher.update(format.extension().as_bytes());
    hasher.update(b":");
    hasher.update(meta.updated_at_ms.to_string().as_bytes());
    let hash = hex::encode(hasher.finalize());
    format!("\"{hash}\"")
}

pub fn safe_dir_segment(value: &str, max_len: usize, label: &str) -> Result<String> {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        return Err(anyhow!("invalid {label} segment"));
    }
    if trimmed == "." || trimmed == ".." {
        return Err(anyhow!("invalid {label} segment"));
    }
    if trimmed.len() > max_len {
        return Err(anyhow!("{label} segment too long"));
    }
    Ok(trimmed)
}

pub fn global_unapproved_dir(config: &Config) -> PathBuf {
    config.fallbacks_dir.join("global").join("unapproved")
}

pub fn collection_fallback_dir(
    config: &Config,
    chain: &str,
    collection: &str,
    kind: &str,
) -> Result<PathBuf> {
    let chain_seg = safe_dir_segment(chain, 64, "chain")?;
    let collection_seg = safe_dir_segment(collection, 128, "collection")?;
    Ok(config
        .fallbacks_dir
        .join("collections")
        .join(chain_seg)
        .join(collection_seg)
        .join(kind))
}

pub fn token_override_dir(
    config: &Config,
    chain: &str,
    collection: &str,
    token_id: &str,
) -> Result<PathBuf> {
    let chain_seg = safe_dir_segment(chain, 64, "chain")?;
    let collection_seg = safe_dir_segment(collection, 128, "collection")?;
    let token_seg = safe_token_segment(token_id)?;
    Ok(config
        .fallbacks_dir
        .join("tokens")
        .join(chain_seg)
        .join(collection_seg)
        .join(token_seg)
        .join("override"))
}

fn safe_token_segment(token_id: &str) -> Result<String> {
    let mut out = String::new();
    for ch in token_id.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        return Err(anyhow!("invalid token_id segment"));
    }
    if trimmed == "." || trimmed == ".." {
        return Err(anyhow!("invalid token_id segment"));
    }
    if trimmed.len() > 128 {
        let mut hasher = Sha256::new();
        hasher.update(token_id.as_bytes());
        let hash = hex::encode(hasher.finalize());
        return Ok(format!("tok-{hash}"));
    }
    Ok(trimmed)
}
