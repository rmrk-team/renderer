use super::*;

pub(crate) fn build_variant_key(base_key: &str, request: &RenderRequest) -> String {
    let mut key = base_key.to_string();
    if request.og_mode && !key.contains("og") {
        key.push_str("_og");
    }
    if let Some(overlay) = normalize_overlay_for_key(&request.overlay) {
        key.push_str("_ov-");
        key.push_str(overlay);
    }
    if let Some(bg) = normalize_background_for_key(&request.background, request.format) {
        key.push_str("_bg-");
        key.push_str(&sanitize_key(&bg));
    }
    key
}

fn normalize_overlay_for_key(overlay: &Option<String>) -> Option<&'static str> {
    match overlay.as_deref() {
        Some("watermark") => Some("watermark"),
        _ => None,
    }
}

fn normalize_background_for_key(
    background: &Option<String>,
    format: OutputFormat,
) -> Option<String> {
    let default = default_background_color(&format);
    let resolved = resolve_background(background, format).unwrap_or(default);
    if resolved == default {
        return None;
    }
    Some(format_background_key(resolved))
}

fn default_background_color(format: &OutputFormat) -> Rgba<u8> {
    if matches!(format, OutputFormat::Jpeg) {
        return Rgba([255, 255, 255, 255]);
    }
    Rgba([0, 0, 0, 0])
}

fn format_background_key(color: Rgba<u8>) -> String {
    if color.0[3] == 0 {
        return "transparent".to_string();
    }
    format!("{:02x}{:02x}{:02x}", color.0[0], color.0[1], color.0[2])
}

pub(super) fn sanitize_key(value: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

#[derive(Debug, Clone)]
pub(crate) struct RenderCacheKey {
    pub(crate) path: PathBuf,
    pub(crate) etag: String,
}

#[derive(Debug, Clone)]
pub(super) struct CompositeCacheKey {
    pub(super) path: PathBuf,
}

pub(super) fn composite_cache_key(
    cache: &CacheManager,
    chain: &str,
    collection: &str,
    token_id: &str,
    asset_id: &str,
    cache_timestamp: &str,
    variant_key: &str,
) -> std::result::Result<CompositeCacheKey, RenderInputError> {
    let hash = composite_cache_key_hash(
        chain,
        collection,
        token_id,
        asset_id,
        cache_timestamp,
        variant_key,
    )?;
    let chain = safe_segment(chain, "chain", 64)?;
    let collection = safe_segment(collection, "collection", 128)?;
    let prefix = &hash[0..2];
    let path = cache
        .composites_dir
        .join(chain)
        .join(collection)
        .join(prefix)
        .join(format!("{hash}.png"));
    Ok(CompositeCacheKey { path })
}

fn composite_cache_key_hash(
    chain: &str,
    collection: &str,
    token_id: &str,
    asset_id: &str,
    cache_timestamp: &str,
    variant_key: &str,
) -> std::result::Result<String, RenderInputError> {
    validate_cache_timestamp(cache_timestamp)?;
    let chain = safe_segment(chain, "chain", 64)?;
    let collection = safe_segment(collection, "collection", 128)?;
    let token_id = safe_segment(token_id, "token_id", 128)?;
    let asset_id = safe_segment(asset_id, "asset_id", 128)?;
    let cache_timestamp = safe_segment(cache_timestamp, "cache_timestamp", 13)?;
    let hash_input = format!(
        "{chain}|{collection}|{token_id}|{asset_id}|{cache_timestamp}|{variant_key}|composite"
    );
    Ok(sha256_hex(&hash_input))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn render_cache_key(
    cache: &CacheManager,
    chain: &str,
    collection: &str,
    token_id: &str,
    asset_id: &str,
    cache_timestamp: &str,
    variant_key: &str,
    extension: &str,
) -> std::result::Result<RenderCacheKey, RenderInputError> {
    let hash = render_cache_key_hash(
        chain,
        collection,
        token_id,
        asset_id,
        cache_timestamp,
        variant_key,
        extension,
    )?;
    let chain = safe_segment(chain, "chain", 64)?;
    let collection = safe_segment(collection, "collection", 128)?;
    let prefix = &hash[0..2];
    let path = cache
        .renders_dir
        .join(chain)
        .join(collection)
        .join(prefix)
        .join(format!("{hash}.{extension}"));
    Ok(RenderCacheKey {
        path,
        etag: format!("\"{hash}\""),
    })
}

fn render_cache_key_hash(
    chain: &str,
    collection: &str,
    token_id: &str,
    asset_id: &str,
    cache_timestamp: &str,
    variant_key: &str,
    extension: &str,
) -> std::result::Result<String, RenderInputError> {
    validate_cache_timestamp(cache_timestamp)?;
    let chain = safe_segment(chain, "chain", 64)?;
    let collection = safe_segment(collection, "collection", 128)?;
    let token_id = safe_segment(token_id, "token_id", 128)?;
    let asset_id = safe_segment(asset_id, "asset_id", 128)?;
    let cache_timestamp = safe_segment(cache_timestamp, "cache_timestamp", 13)?;
    let hash_input = format!(
        "{chain}|{collection}|{token_id}|{asset_id}|{cache_timestamp}|{variant_key}|{extension}"
    );
    Ok(sha256_hex(&hash_input))
}

pub(crate) fn render_cache_variant_key(
    chain: &str,
    collection: &str,
    token_id: &str,
    asset_id: &str,
    variant_key: &str,
    extension: &str,
) -> std::result::Result<String, RenderInputError> {
    let chain = safe_segment(chain, "chain", 64)?;
    let collection = safe_segment(collection, "collection", 128)?;
    let token_id = safe_segment(token_id, "token_id", 128)?;
    let asset_id = safe_segment(asset_id, "asset_id", 128)?;
    Ok(format!(
        "{chain}|{collection}|{token_id}|{asset_id}|{variant_key}|{extension}"
    ))
}

pub(super) fn safe_segment<'a>(
    value: &'a str,
    field: &'static str,
    max_len: usize,
) -> std::result::Result<&'a str, RenderInputError> {
    if value.is_empty() || value.len() > max_len {
        return Err(RenderInputError::InvalidSegment { field });
    }
    if value.contains('\0') || value.contains('\\') || value.contains('/') || value.contains("..") {
        return Err(RenderInputError::InvalidSegment { field });
    }
    let mut components = Path::new(value).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(value),
        _ => Err(RenderInputError::InvalidSegment { field }),
    }
}

fn validate_cache_timestamp(value: &str) -> std::result::Result<(), RenderInputError> {
    if value.is_empty() || value.len() > 13 {
        return Err(RenderInputError::InvalidSegment {
            field: "cache_timestamp",
        });
    }
    if !value.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(RenderInputError::InvalidSegment {
            field: "cache_timestamp",
        });
    }
    Ok(())
}
