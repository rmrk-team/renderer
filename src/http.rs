use crate::assets::AssetFetchError;
use crate::canonical;
use crate::chain::{SELECTOR_TOKEN_HAS_NO_ASSETS, is_contract_revert_error, revert_selector};
use crate::config::{AccessMode, Config};
use crate::failure_log::FailureLogEntry;
use crate::fallbacks::{
    DEFAULT_UNAPPROVED_FALLBACK_LINE1, DEFAULT_UNAPPROVED_FALLBACK_LINE2, FALLBACK_OG_HEIGHT,
    FALLBACK_OG_WIDTH, FallbackMeta, fallback_etag, fallback_variant_filename,
    fallback_variant_label, fallback_width_bucket, global_unapproved_dir,
};
use crate::landing;
use crate::metrics;
use crate::rate_limit::RateLimitInfo;
use crate::render::{
    ApprovalCheckContext, OutputFormat, RenderInputError, RenderKeyLimit, RenderLimitError,
    RenderRequest, RenderTimeoutError, TOKEN_URI_FALLBACK_ASSET_ID,
    render_token_with_limit_checked,
};
use crate::state::{AppState, TokenOverrideEntry, token_override_cache_key};
use crate::usage::UsageEvent;
use crate::{admin, render};
use axum::body::Body;
use axum::extract::{ConnectInfo, Extension, Path, Query, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use image::{DynamicImage, ImageFormat, Rgba, RgbaImage};
use ipnet::IpNet;
use prometheus::Encoder;
use rand::random;
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path as StdPath, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio_util::io::ReaderStream;
use tracing::warn;
use url::Url;

mod admin_routes;
mod middleware;
mod render_routes;

pub(crate) use admin_routes::{admin_router, is_admin_authorized};
pub(crate) use middleware::{AccessContext, access_middleware, approval_context_from_access};

const OPENAPI_YAML: &str = include_str!("../openapi.yaml");
const MAX_FORWARDED_IPS: usize = 20;
const MIN_BEARER_TOKEN_LEN: usize = 20;
const MAX_BEARER_TOKEN_LEN: usize = 128;
const RATE_LIMIT_RETRY_AFTER_SECONDS: &str = "60";

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct PlaceholderKey {
    format: OutputFormat,
    width: u32,
    height: u32,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct FallbackCacheKey {
    format: OutputFormat,
    width: u32,
    height: u32,
    kind: String,
    lines: String,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct FallbackFileCacheKey {
    dir: PathBuf,
    variant_label: String,
    format: OutputFormat,
}

#[derive(Clone)]
struct FallbackFileCacheEntry {
    path: PathBuf,
    etag: String,
    content_length: u64,
    expires_at: Instant,
}

static PLACEHOLDER_CACHE: OnceLock<HashMap<PlaceholderKey, Arc<Vec<u8>>>> = OnceLock::new();
const PLACEHOLDER_PRESET_WIDTHS: [u32; 6] = [64u32, 128u32, 256u32, 512u32, 1024u32, 2048u32];
static FALLBACK_CACHE: OnceLock<DashMap<FallbackCacheKey, Arc<Vec<u8>>>> = OnceLock::new();
const FALLBACK_CACHE_MAX_ENTRIES: usize = 64;
static FALLBACK_FILE_CACHE: OnceLock<DashMap<FallbackFileCacheKey, FallbackFileCacheEntry>> =
    OnceLock::new();
const FALLBACK_FILE_CACHE_MAX_ENTRIES: usize = 256;
const FALLBACK_FILE_CACHE_TTL: Duration = Duration::from_secs(60);

pub fn init_placeholder_cache(config: &Config) {
    let mut cache = HashMap::new();
    let base_width = config.default_canvas_width;
    let base_height = config.default_canvas_height;
    let mut sizes = Vec::new();
    sizes.push((base_width, base_height));
    for width in PLACEHOLDER_PRESET_WIDTHS {
        let height = scale_placeholder_height(base_height, base_width, width);
        sizes.push((width, height));
    }
    sizes.push((1200, 630));
    let formats = [OutputFormat::Webp, OutputFormat::Png, OutputFormat::Jpeg];
    for (width, height) in sizes {
        for format in formats {
            let bytes = placeholder_bytes(&format, width, height);
            cache.insert(
                PlaceholderKey {
                    format,
                    width,
                    height,
                },
                Arc::new(bytes),
            );
        }
    }
    let _ = PLACEHOLDER_CACHE.set(cache);
}

fn fallback_cache() -> &'static DashMap<FallbackCacheKey, Arc<Vec<u8>>> {
    FALLBACK_CACHE.get_or_init(DashMap::new)
}

fn fallback_file_cache() -> &'static DashMap<FallbackFileCacheKey, FallbackFileCacheEntry> {
    FALLBACK_FILE_CACHE.get_or_init(DashMap::new)
}

fn is_top_asset_missing_error(err: &anyhow::Error) -> bool {
    matches!(
        revert_selector(err),
        Some(selector) if selector == SELECTOR_TOKEN_HAS_NO_ASSETS
    )
}

fn should_negative_cache_primary_asset(err: &anyhow::Error) -> bool {
    is_contract_revert_error(err)
}

pub(crate) fn clear_fallback_file_cache() {
    fallback_file_cache().clear();
}

#[derive(Debug, Deserialize)]
pub struct RenderQuery {
    pub cache: Option<String>,
    pub width: Option<String>,
    #[serde(rename = "img-width")]
    pub img_width: Option<String>,
    #[serde(rename = "ogImage")]
    pub og_image: Option<bool>,
    pub overlay: Option<String>,
    pub bg: Option<String>,
    pub onerror: Option<String>,
    pub fresh: Option<String>,
    pub debug: Option<String>,
    pub raw: Option<String>,
}

async fn apply_cache_policy(
    state: &AppState,
    chain: &str,
    collection: &str,
    provided: Option<String>,
    cache_param_present: bool,
    context: Option<&AccessContext>,
) -> Result<(Option<String>, bool), ApiError> {
    let mut cache_override = provided.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    });
    let mut cache_param_present = cache_param_present && cache_override.is_some();
    if cache_param_present {
        let allow_cache = context.map(|ctx| ctx.allow_cache).unwrap_or(false);
        if !allow_cache
            && !anon_cache_epoch_allowed(state, chain, collection, cache_override.as_deref())
                .await?
        {
            cache_override = None;
            cache_param_present = false;
        }
    }
    let cache_timestamp = render::resolve_cache_timestamp(state, chain, collection, cache_override)
        .await
        .map_err(map_render_error_anyhow)?;
    Ok((cache_timestamp, cache_param_present))
}

async fn anon_cache_epoch_allowed(
    state: &AppState,
    chain: &str,
    collection: &str,
    provided: Option<&str>,
) -> Result<bool, ApiError> {
    let Some(provided) = provided else {
        return Ok(false);
    };
    let allowed = render::resolve_cache_timestamp(state, chain, collection, None)
        .await
        .map_err(map_render_error_anyhow)?;
    let Some(allowed) = allowed else {
        return Ok(false);
    };
    if provided == allowed {
        return Ok(true);
    }
    let window = state.config.anon_cache_epoch_window_ms as i64;
    if window == 0 {
        return Ok(false);
    }
    let provided_value = provided.parse::<i64>().ok();
    let allowed_value = allowed.parse::<i64>().ok();
    match (provided_value, allowed_value) {
        (Some(provided_value), Some(allowed_value)) => {
            Ok((provided_value - allowed_value).abs() <= window)
        }
        _ => Ok(false),
    }
}

pub fn router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/status", get(status))
        .route("/status.json", get(status))
        .route("/openapi.yaml", get(openapi_yaml))
        .route("/metrics", get(metrics))
        .route(
            "/render/{chain}/{collection}/{token_id}/{asset_id}/{format}",
            get(render_routes::render_canonical).head(render_routes::head_render_canonical),
        )
        .route(
            "/render/{chain}/{collection}/{token_id}/{tail}",
            get(render_routes::render_primary_or_legacy_asset)
                .head(render_routes::head_render_primary_or_legacy_asset),
        )
        .route(
            "/render/{chain}/{collection}/{token_and_format}",
            get(render_routes::render_primary_compat),
        )
        .route(
            "/production/create/{chain}/{cache_timestamp}/{collection}/{token_id}/{asset_id}/{format}",
            get(render_routes::render_legacy).head(render_routes::head_render_legacy),
        )
        .route(
            "/production/create/{chain}/{cache_timestamp}/{collection}/{token_id}/{asset}",
            get(render_routes::render_legacy_compat).head(render_routes::head_render_legacy_compat),
        )
        .route(
            "/og/{chain}/{collection}/{token_id}/{asset_id}/{format}",
            get(render_routes::render_og).head(render_routes::head_render_og),
        )
        .route(
            "/og/{chain}/{collection}/{token_id}/{asset}",
            get(render_routes::render_og_compat).head(render_routes::head_render_og_compat),
        )
        .nest("/admin", admin_router(state))
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn status(State(state): State<Arc<AppState>>) -> Result<Json<serde_json::Value>, ApiError> {
    let (queued, running, done, failed) = state
        .db
        .warmup_stats()
        .await
        .map_err(map_render_error_anyhow)?;
    let approvals_required = render::require_approval(&state)
        .await
        .map_err(map_render_error_anyhow)?;
    let (render_bytes, asset_bytes) = state
        .cache
        .cached_sizes()
        .await
        .map_err(map_render_error_anyhow)?;
    let usage_summary = if state.config.usage_tracking_enabled {
        let rows = state
            .db
            .list_usage(1)
            .await
            .map_err(map_render_error_anyhow)?;
        let mut requests = 0i64;
        let mut cache_hits = 0i64;
        let mut cache_misses = 0i64;
        for row in rows {
            requests = requests.saturating_add(row.requests);
            cache_hits = cache_hits.saturating_add(row.cache_hits);
            cache_misses = cache_misses.saturating_add(row.cache_misses);
        }
        let total = cache_hits.saturating_add(cache_misses);
        let hit_rate = if total > 0 {
            (cache_hits as f64) / (total as f64)
        } else {
            0.0
        };
        Some(serde_json::json!({
            "requests_1h": requests,
            "cache_hits_1h": cache_hits,
            "cache_misses_1h": cache_misses,
            "cache_hit_rate_1h": hit_rate
        }))
    } else {
        None
    };
    let access_mode = match state.config.access_mode {
        crate::config::AccessMode::Open => "open",
        crate::config::AccessMode::KeyRequired => "key_required",
        crate::config::AccessMode::Hybrid => "hybrid",
        crate::config::AccessMode::DenylistOnly => "denylist_only",
        crate::config::AccessMode::AllowlistOnly => "allowlist_only",
    };
    Ok(Json(serde_json::json!({
        "cache": {
            "render_bytes": render_bytes,
            "asset_bytes": asset_bytes
        },
        "usage": usage_summary,
        "warmup": {
            "queued": queued,
            "running": running,
            "done": done,
            "failed": failed
        },
        "approvals_required": approvals_required,
        "access_mode": access_mode
    })))
}

async fn openapi_yaml() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/yaml"),
    );
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    (headers, OPENAPI_YAML)
}

async fn metrics(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    connect_info: ConnectInfo<SocketAddr>,
) -> Result<Response, ApiError> {
    let ip = client_ip_from_parts(&headers, Some(connect_info.0.ip()), &state);
    if !metrics_access_allowed(&state, &headers, ip).await {
        return Err(
            ApiError::new(StatusCode::UNAUTHORIZED, "metrics access denied")
                .with_code("metrics_access_denied"),
        );
    }
    state.metrics.flush_topk();
    let body = state.metrics.gather().map_err(ApiError::from)?;
    let mut headers = HeaderMap::new();
    let encoder = prometheus::TextEncoder::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(encoder.format_type())
            .unwrap_or(HeaderValue::from_static("text/plain; version=0.0.4")),
    );
    // Text fallbacks should never be cached by intermediaries.
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&body.len().to_string()).unwrap_or(HeaderValue::from_static("0")),
    );
    Ok((headers, body).into_response())
}

async fn head_cached_response(
    state: Arc<AppState>,
    request: RenderRequest,
    raw_mode: bool,
) -> Result<Response, ApiError> {
    render::validate_render_params(
        &request.chain,
        &request.collection,
        &request.token_id,
        Some(&request.asset_id),
    )
    .map_err(map_render_error_anyhow)?;
    let (chain, collection) =
        canonicalize_chain_collection(&state, &request.chain, &request.collection)?;
    let mut request = request;
    request.chain = chain;
    request.collection = collection;
    if request.fresh {
        return Ok(head_cache_miss_response(&request));
    }
    render::apply_cache_epoch(&state, &mut request)
        .await
        .map_err(map_render_error_anyhow)?;
    render::validate_query_lengths(
        &request,
        state.config.max_overlay_length,
        state.config.max_background_length,
    )
    .map_err(map_render_error_anyhow)?;
    if let Err(err) = render::ensure_collection_approved(
        &state,
        &request.chain,
        &request.collection,
        &request.approval_context,
    )
    .await
    {
        if !raw_mode {
            if let Some(response) = fallback_head_for_render_error(&state, &request, &err).await {
                return Ok(response);
            }
        }
        return Err(map_render_error(err));
    }
    if !raw_mode {
        if let Some(response) = resolve_token_override_head(&state, &request).await {
            return Ok(response);
        }
    }
    let cache_ts = match request.cache_timestamp.as_ref() {
        Some(value) => value,
        None => return Ok(head_cache_miss_response(&request)),
    };
    let (_, base_key) = render::resolve_width(&request.width_param, request.og_mode)
        .map_err(map_render_error_anyhow)?;
    let variant_key = render::build_variant_key(&base_key, &request);
    let cache_key = render::render_cache_key(
        &state.cache,
        &request.chain,
        &request.collection,
        &request.token_id,
        &request.asset_id,
        cache_ts,
        &variant_key,
        request.format.extension(),
    )
    .map_err(map_render_error_anyhow)?;
    let cached = state
        .cache
        .is_cached_file(&cache_key.path, state.cache.render_ttl)
        .await
        .map_err(map_render_error_anyhow)?;
    if !cached {
        return Ok(head_cache_miss_response(&request));
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(request.format.mime().as_ref())
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(&render::cache_control_header(state.cache.render_ttl))
            .unwrap_or(HeaderValue::from_static("no-store")),
    );
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(&cache_key.etag).unwrap_or(HeaderValue::from_static("")),
    );
    headers.insert("X-Renderer-Complete", HeaderValue::from_static("true"));
    headers.insert("X-Renderer-Result", HeaderValue::from_static("rendered"));
    headers.insert("X-Renderer-Cache-Hit", HeaderValue::from_static("true"));
    headers.insert("X-Renderer-Cache", HeaderValue::from_static("hit"));
    headers.insert("X-Cache", HeaderValue::from_static("HIT"));
    headers.insert(
        "Server-Timing",
        HeaderValue::from_static("cache;desc=\"HIT\""),
    );
    Ok((headers, ()).into_response())
}

fn head_cache_miss_response(request: &RenderRequest) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(request.format.mime().as_ref())
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("X-Renderer-Complete", HeaderValue::from_static("false"));
    headers.insert("X-Renderer-Result", HeaderValue::from_static("cache-miss"));
    headers.insert("X-Renderer-Cache-Hit", HeaderValue::from_static("false"));
    headers.insert("X-Renderer-Cache", HeaderValue::from_static("miss"));
    headers.insert("X-Cache", HeaderValue::from_static("MISS"));
    headers.insert(
        "Server-Timing",
        HeaderValue::from_static("cache;desc=\"MISS\""),
    );
    (StatusCode::OK, headers).into_response()
}

async fn to_http_response(
    response: render::RenderResponse,
    request_headers: &HeaderMap,
) -> Response {
    if let Some(etag) = response.etag.as_deref() {
        if is_cacheable(&response.cache_control) && matches_etag(request_headers, etag) {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::ETAG,
                HeaderValue::from_str(etag).unwrap_or(HeaderValue::from_static("")),
            );
            headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_str(&response.cache_control)
                    .unwrap_or(HeaderValue::from_static("no-store")),
            );
            return (StatusCode::NOT_MODIFIED, headers).into_response();
        }
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(response.content_type.as_ref())
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(
        "X-Renderer-Complete",
        HeaderValue::from_str(if response.complete { "true" } else { "false" })
            .unwrap_or(HeaderValue::from_static("false")),
    );
    headers.insert(
        "X-Renderer-Result",
        HeaderValue::from_str(if response.complete {
            "rendered"
        } else {
            "placeholder"
        })
        .unwrap_or(HeaderValue::from_static("rendered")),
    );
    headers.insert(
        "X-Renderer-Cache-Hit",
        HeaderValue::from_str(if response.cache_hit { "true" } else { "false" })
            .unwrap_or(HeaderValue::from_static("false")),
    );
    headers.insert(
        "X-Renderer-Cache",
        HeaderValue::from_static(if response.cache_hit { "hit" } else { "miss" }),
    );
    if let Some(strategy) = response.strategy {
        headers.insert(
            "X-Renderer-Strategy",
            HeaderValue::from_static(strategy.as_str()),
        );
    }
    if let Some(total_layers) = response.total_layers {
        headers.insert(
            "X-Renderer-Layers",
            HeaderValue::from_str(&total_layers.to_string())
                .unwrap_or(HeaderValue::from_static("0")),
        );
    }
    let cache_label = if response.cache_hit { "HIT" } else { "MISS" };
    headers.insert(
        "X-Cache",
        HeaderValue::from_static(if response.cache_hit { "HIT" } else { "MISS" }),
    );
    headers.insert(
        "Server-Timing",
        HeaderValue::from_str(&format!("cache;desc=\"{cache_label}\""))
            .unwrap_or(HeaderValue::from_static("cache")),
    );
    if response.missing_layers > 0 {
        headers.insert(
            "X-Renderer-Missing-Layers",
            HeaderValue::from_str(&response.missing_layers.to_string())
                .unwrap_or(HeaderValue::from_static("0")),
        );
    }
    if response.nonconforming_layers > 0 {
        headers.insert(
            "X-Renderer-Nonconforming-Layers",
            HeaderValue::from_str(&response.nonconforming_layers.to_string())
                .unwrap_or(HeaderValue::from_static("0")),
        );
    }
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(&response.cache_control)
            .unwrap_or(HeaderValue::from_static("no-store")),
    );
    if is_cacheable(&response.cache_control) {
        if let Some(etag) = response.etag.as_deref() {
            headers.insert(
                header::ETAG,
                HeaderValue::from_str(etag).unwrap_or(HeaderValue::from_static("")),
            );
        }
    }
    if let Some(length) = response.content_length {
        if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
            headers.insert(header::CONTENT_LENGTH, value);
        }
    }
    if let Some(path) = response.cached_path.as_ref() {
        match tokio::fs::File::open(path).await {
            Ok(file) => {
                let stream = ReaderStream::new(file);
                let body = Body::from_stream(stream);
                return (headers, body).into_response();
            }
            Err(err) => {
                tracing::warn!(error = ?err, path = %path.display(), "cached file open failed");
                return (StatusCode::NOT_FOUND, headers).into_response();
            }
        }
    }
    (headers, response.bytes).into_response()
}

fn placeholder_response(format: &OutputFormat, width: u32, height: u32) -> Response {
    let bytes = placeholder_bytes_cached(format, width, height);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(format.mime().as_ref())
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("X-Renderer-Complete", HeaderValue::from_static("false"));
    headers.insert("X-Renderer-Result", HeaderValue::from_static("placeholder"));
    headers.insert("X-Renderer-Error", HeaderValue::from_static("true"));
    if let Ok(value) = HeaderValue::from_str(&bytes.len().to_string()) {
        headers.insert(header::CONTENT_LENGTH, value);
    }
    (headers, bytes).into_response()
}

fn placeholder_bytes(format: &OutputFormat, width: u32, height: u32) -> Vec<u8> {
    let color = match format {
        OutputFormat::Jpeg => Rgba([255, 255, 255, 255]),
        _ => Rgba([0, 0, 0, 0]),
    };
    let image = DynamicImage::ImageRgba8(RgbaImage::from_pixel(width, height, color));
    let mut bytes = Vec::new();
    match format {
        OutputFormat::Webp => {
            let encoder = image::codecs::webp::WebPEncoder::new_lossless(&mut bytes);
            encoder
                .encode(
                    image.to_rgba8().as_raw(),
                    image.width(),
                    image.height(),
                    image::ExtendedColorType::Rgba8,
                )
                .ok();
        }
        OutputFormat::Png => {
            let _ = image.write_to(&mut std::io::Cursor::new(&mut bytes), ImageFormat::Png);
        }
        OutputFormat::Jpeg => {
            let rgb = image.to_rgb8();
            let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut bytes, 90);
            let _ = encoder.encode(
                rgb.as_raw(),
                rgb.width(),
                rgb.height(),
                image::ColorType::Rgb8.into(),
            );
        }
    }
    bytes
}

fn placeholder_bytes_cached(format: &OutputFormat, width: u32, height: u32) -> Vec<u8> {
    if let Some(cache) = PLACEHOLDER_CACHE.get() {
        let key = PlaceholderKey {
            format: *format,
            width,
            height,
        };
        if let Some(bytes) = cache.get(&key) {
            return bytes.as_ref().clone();
        }
    }
    placeholder_bytes(format, width, height)
}

async fn queued_fallback_response(
    format: &OutputFormat,
    width: u32,
    height: u32,
    retry_after_seconds: u64,
) -> Response {
    let lines = vec!["RENDER QUEUED".to_string(), "RETRY IN A MOMENT".to_string()];
    fallback_text_response(
        format,
        width,
        height,
        &lines,
        "queued",
        "queue_full",
        "render_queue_full",
        StatusCode::OK,
        Some(retry_after_seconds),
    )
    .await
}

async fn render_timeout_fallback_response(
    format: &OutputFormat,
    width: u32,
    height: u32,
    retry_after_seconds: u64,
    fallback_kind: &str,
    reason: &str,
    error_code: &str,
    line1: &str,
) -> Response {
    let lines = vec![line1.to_string(), "RETRY IN A MOMENT".to_string()];
    fallback_text_response(
        format,
        width,
        height,
        &lines,
        fallback_kind,
        reason,
        error_code,
        StatusCode::OK,
        Some(retry_after_seconds),
    )
    .await
}

async fn approval_rate_limited_fallback_response(
    format: &OutputFormat,
    width: u32,
    height: u32,
    chain: &str,
    collection: &str,
    retry_after_seconds: u64,
) -> Response {
    let mut lines = vec![
        "APPROVAL CHECK LIMITED".to_string(),
        "RETRY IN A MOMENT".to_string(),
    ];
    if width >= 512 {
        lines.push(format!("CHAIN: {}", chain.to_ascii_uppercase()));
        lines.push(format!(
            "COLLECTION: {}",
            format_collection_label(collection)
        ));
    }
    fallback_text_response(
        format,
        width,
        height,
        &lines,
        "approval_rate_limited",
        "approval_rate_limited",
        "approval_check_rate_limited",
        StatusCode::OK,
        Some(retry_after_seconds),
    )
    .await
}

async fn approval_stale_fallback_response(
    format: &OutputFormat,
    width: u32,
    height: u32,
    chain: &str,
    collection: &str,
) -> Response {
    let mut lines = vec!["APPROVAL STALE".to_string(), "RETRY LATER".to_string()];
    if width >= 512 {
        lines.push(format!("CHAIN: {}", chain.to_ascii_uppercase()));
        lines.push(format!(
            "COLLECTION: {}",
            format_collection_label(collection)
        ));
    }
    fallback_text_response(
        format,
        width,
        height,
        &lines,
        "approval_stale",
        "approval_stale",
        "approval_stale",
        StatusCode::OK,
        None,
    )
    .await
}

async fn fallback_bytes(
    format: &OutputFormat,
    width: u32,
    height: u32,
    lines: &[String],
    fallback_kind: &str,
) -> Vec<u8> {
    let lines_key = lines.join("\n");
    let key = FallbackCacheKey {
        format: *format,
        width,
        height,
        kind: fallback_kind.to_string(),
        lines: lines_key,
    };
    if let Some(entry) = fallback_cache().get(&key) {
        return entry.as_ref().clone();
    }
    let format_copy = *format;
    let lines_owned = lines.to_vec();
    let lines_for_task = lines_owned.clone();
    let bytes = tokio::task::spawn_blocking(move || {
        render_fallback_image(&format_copy, width, height, &lines_for_task)
    })
    .await
    .unwrap_or_else(|_| render_fallback_image(&format_copy, width, height, &lines_owned));
    let cache = fallback_cache();
    if cache.len() >= FALLBACK_CACHE_MAX_ENTRIES {
        cache.clear();
    }
    cache.insert(key, Arc::new(bytes.clone()));
    bytes
}

async fn fallback_text_response(
    format: &OutputFormat,
    width: u32,
    height: u32,
    lines: &[String],
    fallback_kind: &str,
    reason: &str,
    error_code: &str,
    status: StatusCode,
    retry_after_seconds: Option<u64>,
) -> Response {
    let bytes = fallback_bytes(format, width, height, lines, fallback_kind).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(format.mime().as_ref())
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("X-Renderer-Complete", HeaderValue::from_static("false"));
    headers.insert("X-Renderer-Result", HeaderValue::from_static("fallback"));
    headers.insert("X-Renderer-Strategy", HeaderValue::from_static("fallback"));
    headers.insert(
        "X-Renderer-Fallback",
        HeaderValue::from_str(fallback_kind).unwrap_or(HeaderValue::from_static("fallback")),
    );
    headers.insert(
        "X-Renderer-Fallback-Action",
        HeaderValue::from_static(fallback_action_for_kind(fallback_kind, retry_after_seconds)),
    );
    headers.insert(
        "X-Renderer-Fallback-Reason",
        HeaderValue::from_str(reason).unwrap_or(HeaderValue::from_static("unknown")),
    );
    headers.insert(
        "X-Renderer-Error-Code",
        HeaderValue::from_str(error_code).unwrap_or(HeaderValue::from_static("fallback")),
    );
    if error_code == "ipfs_negative_cache" {
        headers.insert(
            "X-Renderer-Error",
            HeaderValue::from_static("ipfs_negative_cache"),
        );
    }
    if error_code == "ipfs_negative_cache" {
        headers.insert(
            "X-Renderer-Error",
            HeaderValue::from_static("ipfs_negative_cache"),
        );
    }
    if let Ok(value) = HeaderValue::from_str(&bytes.len().to_string()) {
        headers.insert(header::CONTENT_LENGTH, value);
    }
    if let Some(retry_after) = retry_after_seconds {
        let value = HeaderValue::from_str(&retry_after.to_string())
            .unwrap_or(HeaderValue::from_static("5"));
        headers.insert(header::RETRY_AFTER, value);
    }
    if let Some(value) = fallback_until_header(retry_after_seconds) {
        headers.insert("X-Renderer-Fallback-Until", value);
    }
    (status, headers, bytes).into_response()
}

fn fallback_action_for_kind(fallback_kind: &str, retry_after_seconds: Option<u64>) -> &'static str {
    if retry_after_seconds.is_some() {
        return "backoff";
    }
    match fallback_kind {
        "unapproved" | "token_override" => "stop",
        "approval_stale"
        | "queued"
        | "timeout_queue"
        | "timeout_render"
        | "ipfs_negative_cache" => "backoff",
        "render_fallback" => "backoff",
        _ => "retry",
    }
}

fn fallback_until_header(retry_after_seconds: Option<u64>) -> Option<HeaderValue> {
    let seconds = retry_after_seconds?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let until = now.saturating_add(seconds);
    HeaderValue::from_str(&until.to_string()).ok()
}

fn normalize_source_label(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut normalized = trimmed.to_ascii_lowercase();
    normalized = normalized.replace('|', "_");
    if normalized.len() > 120 {
        normalized.truncate(120);
    }
    Some(normalized)
}

fn normalize_source_host(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut host = trimmed.to_ascii_lowercase();
    if host.ends_with('.') {
        host.pop();
    }
    if host.len() > 253 {
        return None;
    }
    let (host_part, port) = if let Some((left, right)) = host.rsplit_once(':') {
        if right.chars().all(|ch| ch.is_ascii_digit()) && !left.contains(':') {
            let port_value = right.parse::<u16>().ok()?;
            if port_value == 0 {
                return None;
            }
            (left, Some(port_value))
        } else {
            (host.as_str(), None)
        }
    } else {
        (host.as_str(), None)
    };
    if host_part.parse::<IpAddr>().is_ok() {
        return None;
    }
    let labels: Vec<&str> = host_part.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !label
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        {
            return None;
        }
    }
    Some(if let Some(port) = port {
        format!("{host_part}:{port}")
    } else {
        host_part.to_string()
    })
}

fn source_labels_enabled(config: &Config) -> bool {
    config.metrics_top_sources > 0 || config.metrics_top_source_failure_reasons > 0
}

fn ip_label_for_log(config: &Config, ip: IpAddr) -> String {
    metrics::ip_label_for_mode(config.identity_ip_label_mode, ip)
}

fn ip_identity_key(config: &Config, ip: IpAddr) -> Arc<str> {
    let label = ip_label_for_log(config, ip);
    Arc::from(format!("ip:{label}"))
}

fn host_from_header_url(value: &HeaderValue) -> Option<String> {
    let raw = value.to_str().ok()?.trim();
    if raw.eq_ignore_ascii_case("null") {
        return None;
    }
    let parsed = Url::parse(raw).ok()?;
    let host = parsed.host_str()?;
    let label = if let Some(port) = parsed.port() {
        format!("{host}:{port}")
    } else {
        host.to_string()
    };
    normalize_source_host(&label)
}

fn source_label_from_headers(
    headers: &HeaderMap,
    identity: Option<&AccessContext>,
) -> Option<String> {
    let identity = identity?;
    identity.client_key_id?;
    if let Some(value) = headers.get("X-Renderer-Source") {
        if let Ok(raw) = value.to_str() {
            if raw.contains("://") {
                if let Ok(parsed) = Url::parse(raw) {
                    if let Some(host) = parsed.host_str() {
                        let label = if let Some(port) = parsed.port() {
                            format!("{host}:{port}")
                        } else {
                            host.to_string()
                        };
                        if let Some(label) = normalize_source_host(&label) {
                            return Some(label);
                        }
                    }
                }
            }
            if let Some(label) = normalize_source_host(raw) {
                return Some(label);
            }
        }
    }
    if let Some(value) = headers.get(header::ORIGIN) {
        if let Some(label) = host_from_header_url(value) {
            return Some(label);
        }
    }
    if let Some(value) = headers.get(header::REFERER) {
        if let Some(label) = host_from_header_url(value) {
            return Some(label);
        }
    }
    normalize_source_label(identity.identity_key.as_ref())
}

async fn unapproved_fallback_lines(state: &AppState) -> Vec<String> {
    if let Some(lines) = state.unapproved_fallback_cache.get().await {
        return lines;
    }
    let line1_override = match state.db.get_setting("unapproved_fallback_line1").await {
        Ok(value) => value.and_then(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }),
        Err(err) => {
            warn!(error = ?err, "failed to load unapproved fallback line1");
            None
        }
    };
    let line2_override = match state.db.get_setting("unapproved_fallback_line2").await {
        Ok(value) => value.and_then(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }),
        Err(err) => {
            warn!(error = ?err, "failed to load unapproved fallback line2");
            None
        }
    };
    let lines = vec![
        line1_override.unwrap_or_else(|| DEFAULT_UNAPPROVED_FALLBACK_LINE1.to_string()),
        line2_override.unwrap_or_else(|| DEFAULT_UNAPPROVED_FALLBACK_LINE2.to_string()),
    ];
    state.unapproved_fallback_cache.set(lines.clone()).await;
    lines
}

fn render_fallback_image(
    format: &OutputFormat,
    width: u32,
    height: u32,
    lines: &[String],
) -> Vec<u8> {
    let mut image = RgbaImage::from_pixel(width, height, Rgba([255, 255, 255, 255]));
    let scale = fallback_text_scale(width);
    let line_spacing = scale;
    let line_height = 7 * scale + line_spacing;
    let total_height = line_height
        .saturating_mul(lines.len() as u32)
        .saturating_sub(line_spacing);
    let start_y = if height > total_height {
        (height - total_height) / 2
    } else {
        0
    };
    let margin = scale.saturating_mul(4);
    for (idx, line) in lines.iter().enumerate() {
        let line = line.to_ascii_uppercase();
        let max_chars = max_line_chars(width, margin, scale);
        let line = truncate_line(&line, max_chars);
        let line_width = text_width(&line, scale);
        let x = if width > line_width {
            ((width - line_width) / 2).max(margin)
        } else {
            margin
        };
        let y = start_y + idx as u32 * line_height;
        draw_text(&mut image, x, y, scale, &line, Rgba([24, 24, 24, 255]));
    }
    encode_image_bytes(format, image)
}

struct FallbackVariantFile {
    path: PathBuf,
    content_length: u64,
    etag: String,
}

async fn read_fallback_meta(dir: &StdPath) -> Option<FallbackMeta> {
    let meta_path = dir.join("meta.json");
    let metadata = tokio::fs::symlink_metadata(&meta_path).await.ok()?;
    if metadata.file_type().is_symlink() {
        warn!(
            path = %meta_path.display(),
            "fallback meta.json is a symlink"
        );
        return None;
    }
    let bytes = tokio::fs::read(meta_path).await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

async fn load_fallback_variant(
    dir: &StdPath,
    format: &OutputFormat,
    width_param: &Option<String>,
    og_mode: bool,
) -> Option<FallbackVariantFile> {
    let width = if og_mode {
        FALLBACK_OG_WIDTH
    } else {
        fallback_width_bucket(width_param)
    };
    let variant_label = fallback_variant_label(og_mode, width);
    let key = FallbackFileCacheKey {
        dir: dir.to_path_buf(),
        variant_label: variant_label.clone(),
        format: *format,
    };
    if let Some(entry) = fallback_file_cache().get(&key) {
        if entry.expires_at > Instant::now() {
            return Some(FallbackVariantFile {
                path: entry.path.clone(),
                content_length: entry.content_length,
                etag: entry.etag.clone(),
            });
        }
        fallback_file_cache().remove(&key);
    }
    let meta = read_fallback_meta(dir).await?;
    let filename = fallback_variant_filename(&variant_label, format);
    let path = dir.join(filename);
    let metadata = tokio::fs::symlink_metadata(&path).await.ok()?;
    if metadata.file_type().is_symlink() {
        warn!(
            path = %path.display(),
            "fallback variant is a symlink"
        );
        return None;
    }
    let etag_label = if og_mode {
        format!("og-{}x{}", FALLBACK_OG_WIDTH, FALLBACK_OG_HEIGHT)
    } else {
        variant_label.clone()
    };
    let etag = fallback_etag(&meta, &etag_label, format);
    let entry = FallbackFileCacheEntry {
        path: path.clone(),
        content_length: metadata.len(),
        etag: etag.clone(),
        expires_at: Instant::now() + FALLBACK_FILE_CACHE_TTL,
    };
    let cache = fallback_file_cache();
    if cache.len() >= FALLBACK_FILE_CACHE_MAX_ENTRIES {
        cache.clear();
    }
    cache.insert(key, entry);
    Some(FallbackVariantFile {
        path,
        content_length: metadata.len(),
        etag,
    })
}

async fn fallback_file_response(
    dir: &StdPath,
    format: &OutputFormat,
    width_param: &Option<String>,
    og_mode: bool,
    fallback_kind: &str,
    fallback_source: &str,
    cache_control: &str,
    complete: bool,
    retry_after_seconds: Option<u64>,
    request_headers: &HeaderMap,
) -> Option<Response> {
    let file = load_fallback_variant(dir, format, width_param, og_mode).await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(format.mime().as_ref())
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&file.content_length.to_string())
            .unwrap_or(HeaderValue::from_static("0")),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(cache_control).unwrap_or(HeaderValue::from_static("no-store")),
    );
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(&file.etag).unwrap_or(HeaderValue::from_static("")),
    );
    headers.insert(
        "X-Renderer-Complete",
        HeaderValue::from_static(if complete { "true" } else { "false" }),
    );
    headers.insert("X-Renderer-Result", HeaderValue::from_static("fallback"));
    headers.insert("X-Renderer-Strategy", HeaderValue::from_static("fallback"));
    headers.insert(
        "X-Renderer-Fallback",
        HeaderValue::from_str(fallback_kind).unwrap_or(HeaderValue::from_static("fallback")),
    );
    headers.insert(
        "X-Renderer-Fallback-Action",
        HeaderValue::from_static(fallback_action_for_kind(fallback_kind, retry_after_seconds)),
    );
    headers.insert(
        "X-Renderer-Fallback-Source",
        HeaderValue::from_str(fallback_source).unwrap_or(HeaderValue::from_static("unknown")),
    );
    headers.insert(
        "X-Renderer-Error-Code",
        HeaderValue::from_str(fallback_kind).unwrap_or(HeaderValue::from_static("fallback")),
    );
    if let Some(retry_after) = retry_after_seconds {
        let value = HeaderValue::from_str(&retry_after.to_string())
            .unwrap_or(HeaderValue::from_static("5"));
        headers.insert(header::RETRY_AFTER, value);
    }
    if let Some(value) = fallback_until_header(retry_after_seconds) {
        headers.insert("X-Renderer-Fallback-Until", value);
    }
    if if_none_match_matches(request_headers, &file.etag) {
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        return Some((StatusCode::NOT_MODIFIED, headers).into_response());
    }
    match tokio::fs::File::open(&file.path).await {
        Ok(file) => {
            let stream = ReaderStream::new(file);
            let body = Body::from_stream(stream);
            Some((headers, body).into_response())
        }
        Err(err) => {
            tracing::warn!(error = ?err, path = %file.path.display(), "fallback file open failed");
            None
        }
    }
}

fn if_none_match_matches(headers: &HeaderMap, etag: &str) -> bool {
    let value = match headers.get(header::IF_NONE_MATCH) {
        Some(value) => value.to_str().unwrap_or(""),
        None => return false,
    };
    if value.trim() == "*" {
        return true;
    }
    value
        .split(',')
        .map(|item| item.trim())
        .any(|item| item == etag)
}

async fn fallback_head_from_dir(
    dir: &StdPath,
    format: &OutputFormat,
    width_param: &Option<String>,
    og_mode: bool,
    fallback_kind: &str,
    fallback_source: &str,
    cache_control: &str,
    complete: bool,
    retry_after_seconds: Option<u64>,
) -> Option<Response> {
    let file = load_fallback_variant(dir, format, width_param, og_mode).await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(format.mime().as_ref())
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&file.content_length.to_string())
            .unwrap_or(HeaderValue::from_static("0")),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(cache_control).unwrap_or(HeaderValue::from_static("no-store")),
    );
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(&file.etag).unwrap_or(HeaderValue::from_static("")),
    );
    headers.insert(
        "X-Renderer-Complete",
        HeaderValue::from_static(if complete { "true" } else { "false" }),
    );
    headers.insert("X-Renderer-Result", HeaderValue::from_static("fallback"));
    headers.insert(
        "X-Renderer-Fallback",
        HeaderValue::from_str(fallback_kind).unwrap_or(HeaderValue::from_static("fallback")),
    );
    headers.insert(
        "X-Renderer-Fallback-Action",
        HeaderValue::from_static(fallback_action_for_kind(fallback_kind, retry_after_seconds)),
    );
    headers.insert(
        "X-Renderer-Fallback-Source",
        HeaderValue::from_str(fallback_source).unwrap_or(HeaderValue::from_static("unknown")),
    );
    if let Some(retry_after) = retry_after_seconds {
        let value = HeaderValue::from_str(&retry_after.to_string())
            .unwrap_or(HeaderValue::from_static("5"));
        headers.insert(header::RETRY_AFTER, value);
    }
    if let Some(value) = fallback_until_header(retry_after_seconds) {
        headers.insert("X-Renderer-Fallback-Until", value);
    }
    Some((StatusCode::OK, headers).into_response())
}

async fn resolve_unapproved_fallback_head(
    state: &AppState,
    request: &RenderRequest,
) -> Option<Response> {
    let config = state
        .db
        .get_collection_fallback_config(&request.chain, &request.collection)
        .await
        .ok()
        .flatten();
    if let Some(config) = config {
        if config.unapproved_fallback_enabled {
            if let Some(dir) = config.unapproved_fallback_dir.as_ref() {
                let dir_path = PathBuf::from(dir);
                if !is_safe_fallback_dir(&state.config.fallbacks_dir, &dir_path) {
                    warn!(
                        path = %dir_path.display(),
                        "unapproved fallback dir outside fallbacks dir"
                    );
                    return None;
                }
                if let Some(response) = fallback_head_from_dir(
                    dir_path.as_path(),
                    &request.format,
                    &request.width_param,
                    request.og_mode,
                    "unapproved",
                    "collection",
                    "public, max-age=60",
                    false,
                    None,
                )
                .await
                {
                    return Some(response);
                }
            }
        }
    }
    let dir = global_unapproved_dir(&state.config);
    fallback_head_from_dir(
        &dir,
        &request.format,
        &request.width_param,
        request.og_mode,
        "unapproved",
        "global",
        "public, max-age=60",
        false,
        None,
    )
    .await
}

async fn resolve_token_override_head(
    state: &AppState,
    request: &RenderRequest,
) -> Option<Response> {
    let override_entry = token_override_cached(state, request).await?;
    if !override_entry.enabled {
        return None;
    }
    fallback_head_from_dir(
        StdPath::new(&override_entry.override_dir),
        &request.format,
        &request.width_param,
        request.og_mode,
        "token_override",
        "token",
        "public, max-age=3600",
        true,
        None,
    )
    .await
}

async fn resolve_unapproved_fallback(
    state: &AppState,
    request: &RenderRequest,
    headers: &HeaderMap,
) -> Option<Response> {
    let config = state
        .db
        .get_collection_fallback_config(&request.chain, &request.collection)
        .await
        .ok()
        .flatten();
    if let Some(config) = config {
        if config.unapproved_fallback_enabled {
            if let Some(dir) = config.unapproved_fallback_dir.as_ref() {
                let dir_path = PathBuf::from(dir);
                if !is_safe_fallback_dir(&state.config.fallbacks_dir, &dir_path) {
                    warn!(
                        path = %dir_path.display(),
                        "unapproved fallback dir outside fallbacks dir"
                    );
                    return None;
                }
                if let Some(response) = fallback_file_response(
                    dir_path.as_path(),
                    &request.format,
                    &request.width_param,
                    request.og_mode,
                    "unapproved",
                    "collection",
                    "public, max-age=60",
                    false,
                    None,
                    headers,
                )
                .await
                {
                    return Some(response);
                }
            }
        }
    }
    let dir = global_unapproved_dir(&state.config);
    if let Some(response) = fallback_file_response(
        &dir,
        &request.format,
        &request.width_param,
        request.og_mode,
        "unapproved",
        "global",
        "public, max-age=60",
        false,
        None,
        headers,
    )
    .await
    {
        return Some(response);
    }
    let (width, height) = placeholder_dimensions(state, &request.width_param, request.og_mode);
    let lines = unapproved_fallback_lines(state).await;
    Some(
        fallback_text_response(
            &request.format,
            width,
            height,
            &lines,
            "unapproved",
            "missing_fallback",
            "unapproved",
            StatusCode::OK,
            None,
        )
        .await,
    )
}

async fn resolve_render_failure_fallback_with(
    state: &AppState,
    request: &RenderRequest,
    headers: &HeaderMap,
    fallback_kind: &str,
    retry_after_seconds: Option<u64>,
) -> Option<Response> {
    let config = state
        .db
        .get_collection_fallback_config(&request.chain, &request.collection)
        .await
        .ok()
        .flatten();
    if let Some(config) = config {
        if config.render_fallback_enabled {
            if let Some(dir) = config.render_fallback_dir.as_ref() {
                let dir_path = PathBuf::from(dir);
                if !is_safe_fallback_dir(&state.config.fallbacks_dir, &dir_path) {
                    warn!(
                        path = %dir_path.display(),
                        "render fallback dir outside fallbacks dir"
                    );
                    return None;
                }
                return fallback_file_response(
                    dir_path.as_path(),
                    &request.format,
                    &request.width_param,
                    request.og_mode,
                    fallback_kind,
                    "collection",
                    "public, max-age=300",
                    false,
                    retry_after_seconds,
                    headers,
                )
                .await;
            }
        }
    }
    None
}

async fn resolve_render_failure_fallback_head_with(
    state: &AppState,
    request: &RenderRequest,
    fallback_kind: &str,
    retry_after_seconds: Option<u64>,
) -> Option<Response> {
    let config = state
        .db
        .get_collection_fallback_config(&request.chain, &request.collection)
        .await
        .ok()
        .flatten();
    if let Some(config) = config {
        if config.render_fallback_enabled {
            if let Some(dir) = config.render_fallback_dir.as_ref() {
                let dir_path = PathBuf::from(dir);
                if !is_safe_fallback_dir(&state.config.fallbacks_dir, &dir_path) {
                    warn!(
                        path = %dir_path.display(),
                        "render fallback dir outside fallbacks dir"
                    );
                    return None;
                }
                return fallback_head_from_dir(
                    dir_path.as_path(),
                    &request.format,
                    &request.width_param,
                    request.og_mode,
                    fallback_kind,
                    "collection",
                    "public, max-age=300",
                    false,
                    retry_after_seconds,
                )
                .await;
            }
        }
    }
    None
}

async fn resolve_render_failure_fallback(
    state: &AppState,
    request: &RenderRequest,
    headers: &HeaderMap,
) -> Option<Response> {
    resolve_render_failure_fallback_with(state, request, headers, "render_fallback", None).await
}

async fn resolve_token_override(
    state: &AppState,
    request: &RenderRequest,
    headers: &HeaderMap,
) -> Option<Response> {
    let override_entry = token_override_cached(state, request).await?;
    if !override_entry.enabled {
        return None;
    }
    fallback_file_response(
        StdPath::new(&override_entry.override_dir),
        &request.format,
        &request.width_param,
        request.og_mode,
        "token_override",
        "token",
        "public, max-age=3600",
        true,
        None,
        headers,
    )
    .await
}

async fn token_override_cached(
    state: &AppState,
    request: &RenderRequest,
) -> Option<TokenOverrideEntry> {
    let cache_key =
        token_override_cache_key(&request.chain, &request.collection, &request.token_id);
    if let Some(cached) = state.token_override_cache.get(&cache_key).await {
        return cached;
    }
    let row = state
        .db
        .get_token_override(&request.chain, &request.collection, &request.token_id)
        .await
        .ok()
        .flatten();
    let value = row.and_then(|row| {
        let dir = PathBuf::from(&row.override_dir);
        if !is_safe_fallback_dir(&state.config.fallbacks_dir, &dir) {
            warn!(
                path = %dir.display(),
                "token override path outside fallbacks dir"
            );
            return None;
        }
        Some(TokenOverrideEntry {
            enabled: row.enabled,
            override_dir: row.override_dir,
        })
    });
    state
        .token_override_cache
        .insert(cache_key, value.clone())
        .await;
    value
}

async fn fallback_for_render_error(
    state: &AppState,
    request: &RenderRequest,
    placeholder_width: &Option<String>,
    headers: &HeaderMap,
    error: &anyhow::Error,
) -> Option<Response> {
    if let Some(cached_error) = error.downcast_ref::<render::TokenStateCachedError>() {
        let retry_after = cached_error.retry_after_seconds.max(1);
        if let Some(response) = resolve_render_failure_fallback_with(
            state,
            request,
            headers,
            "token_state_cached",
            Some(retry_after),
        )
        .await
        {
            return Some(response);
        }
        let (width, height) = placeholder_dimensions(state, placeholder_width, request.og_mode);
        return Some(
            fallback_text_response(
                &request.format,
                width,
                height,
                &["TOKEN STATE CACHED".to_string(), "RETRY LATER".to_string()],
                "token_state_cached",
                "token_state_cached",
                "token_state_cached",
                StatusCode::OK,
                Some(retry_after),
            )
            .await,
        );
    }
    if error.downcast_ref::<render::TokenNotFoundError>().is_some() {
        if let Some(response) =
            resolve_render_failure_fallback_with(state, request, headers, "token_not_found", None)
                .await
        {
            return Some(response);
        }
        let (width, height) = placeholder_dimensions(state, placeholder_width, request.og_mode);
        return Some(
            fallback_text_response(
                &request.format,
                width,
                height,
                &["TOKEN NOT FOUND".to_string()],
                "token_not_found",
                "token_not_found",
                "token_not_found",
                StatusCode::OK,
                None,
            )
            .await,
        );
    }
    if error
        .downcast_ref::<render::UnsupportedStrategyError>()
        .is_some()
    {
        if let Some(response) = resolve_render_failure_fallback_with(
            state,
            request,
            headers,
            "unsupported_collection",
            None,
        )
        .await
        {
            return Some(response);
        }
        let (width, height) = placeholder_dimensions(state, placeholder_width, request.og_mode);
        return Some(
            fallback_text_response(
                &request.format,
                width,
                height,
                &["UNSUPPORTED COLLECTION".to_string()],
                "unsupported_collection",
                "unsupported_collection",
                "unsupported_collection",
                StatusCode::OK,
                None,
            )
            .await,
        );
    }
    if let Some(approval_error) = error.downcast_ref::<render::ApprovalCheckError>() {
        let (width, height) = placeholder_dimensions(state, placeholder_width, request.og_mode);
        return match approval_error {
            render::ApprovalCheckError::NotApproved => {
                resolve_unapproved_fallback(state, request, headers).await
            }
            render::ApprovalCheckError::RateLimited {
                retry_after_seconds,
            } => Some(
                approval_rate_limited_fallback_response(
                    &request.format,
                    width,
                    height,
                    &request.chain,
                    &request.collection,
                    *retry_after_seconds,
                )
                .await,
            ),
            render::ApprovalCheckError::Stale => Some(
                approval_stale_fallback_response(
                    &request.format,
                    width,
                    height,
                    &request.chain,
                    &request.collection,
                )
                .await,
            ),
        };
    }
    if error.downcast_ref::<render::RenderQueueError>().is_some() {
        let (width, height) = placeholder_dimensions(state, placeholder_width, request.og_mode);
        return Some(queued_fallback_response(&request.format, width, height, 5).await);
    }
    if let Some(timeout_error) = error.downcast_ref::<RenderTimeoutError>() {
        let (width, height) = placeholder_dimensions(state, placeholder_width, request.og_mode);
        let response = match timeout_error {
            RenderTimeoutError::QueueWait { .. } => {
                render_timeout_fallback_response(
                    &request.format,
                    width,
                    height,
                    5,
                    "timeout_queue",
                    "render_timeout_queue",
                    "render_timeout_queue",
                    "QUEUE WAIT TIMEOUT",
                )
                .await
            }
            RenderTimeoutError::RenderExec { .. } => {
                render_timeout_fallback_response(
                    &request.format,
                    width,
                    height,
                    5,
                    "timeout_render",
                    "render_timeout_render",
                    "render_timeout_render",
                    "RENDER TIMEOUT",
                )
                .await
            }
        };
        return Some(response);
    }
    if let Some(fetch_error) = error.downcast_ref::<AssetFetchError>() {
        if let AssetFetchError::NegativeCache {
            retry_after_seconds,
            ..
        } = fetch_error
        {
            let (width, height) = placeholder_dimensions(state, placeholder_width, request.og_mode);
            return Some(
                fallback_text_response(
                    &request.format,
                    width,
                    height,
                    &["IPFS NEGATIVE CACHE".to_string(), "RETRY LATER".to_string()],
                    "ipfs_negative_cache",
                    "ipfs_negative_cache",
                    "ipfs_negative_cache",
                    StatusCode::OK,
                    Some(*retry_after_seconds),
                )
                .await,
            );
        }
    }
    resolve_render_failure_fallback(state, request, headers).await
}

fn fallback_head_response(
    format: &OutputFormat,
    fallback_kind: &str,
    reason: &str,
    error_code: &str,
    retry_after_seconds: Option<u64>,
) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(format.mime().as_ref())
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("X-Renderer-Complete", HeaderValue::from_static("false"));
    headers.insert("X-Renderer-Result", HeaderValue::from_static("fallback"));
    headers.insert("X-Renderer-Strategy", HeaderValue::from_static("fallback"));
    headers.insert(
        "X-Renderer-Fallback",
        HeaderValue::from_str(fallback_kind).unwrap_or(HeaderValue::from_static("fallback")),
    );
    headers.insert(
        "X-Renderer-Fallback-Action",
        HeaderValue::from_static(fallback_action_for_kind(fallback_kind, retry_after_seconds)),
    );
    headers.insert(
        "X-Renderer-Fallback-Reason",
        HeaderValue::from_str(reason).unwrap_or(HeaderValue::from_static("unknown")),
    );
    headers.insert(
        "X-Renderer-Error-Code",
        HeaderValue::from_str(error_code).unwrap_or(HeaderValue::from_static("fallback")),
    );
    if let Some(retry_after) = retry_after_seconds {
        let value = HeaderValue::from_str(&retry_after.to_string())
            .unwrap_or(HeaderValue::from_static("5"));
        headers.insert(header::RETRY_AFTER, value);
    }
    if let Some(value) = fallback_until_header(retry_after_seconds) {
        headers.insert("X-Renderer-Fallback-Until", value);
    }
    (StatusCode::OK, headers).into_response()
}

async fn fallback_head_for_render_error(
    state: &AppState,
    request: &RenderRequest,
    error: &anyhow::Error,
) -> Option<Response> {
    if let Some(cached_error) = error.downcast_ref::<render::TokenStateCachedError>() {
        let retry_after = cached_error.retry_after_seconds.max(1);
        return resolve_render_failure_fallback_head_with(
            state,
            request,
            "token_state_cached",
            Some(retry_after),
        )
        .await
        .or_else(|| {
            Some(fallback_head_response(
                &request.format,
                "token_state_cached",
                "token_state_cached",
                "token_state_cached",
                Some(retry_after),
            ))
        });
    }
    if error.downcast_ref::<render::TokenNotFoundError>().is_some() {
        return resolve_render_failure_fallback_head_with(state, request, "token_not_found", None)
            .await
            .or_else(|| {
                Some(fallback_head_response(
                    &request.format,
                    "token_not_found",
                    "token_not_found",
                    "token_not_found",
                    None,
                ))
            });
    }
    if error
        .downcast_ref::<render::UnsupportedStrategyError>()
        .is_some()
    {
        return resolve_render_failure_fallback_head_with(
            state,
            request,
            "unsupported_collection",
            None,
        )
        .await
        .or_else(|| {
            Some(fallback_head_response(
                &request.format,
                "unsupported_collection",
                "unsupported_collection",
                "unsupported_collection",
                None,
            ))
        });
    }
    if let Some(approval_error) = error.downcast_ref::<render::ApprovalCheckError>() {
        return match approval_error {
            render::ApprovalCheckError::NotApproved => {
                resolve_unapproved_fallback_head(state, request).await
            }
            render::ApprovalCheckError::RateLimited {
                retry_after_seconds,
            } => Some(fallback_head_response(
                &request.format,
                "approval_rate_limited",
                "approval_rate_limited",
                "approval_check_rate_limited",
                Some(*retry_after_seconds),
            )),
            render::ApprovalCheckError::Stale => Some(fallback_head_response(
                &request.format,
                "approval_stale",
                "approval_stale",
                "approval_stale",
                None,
            )),
        };
    }
    if error.downcast_ref::<render::RenderQueueError>().is_some() {
        return Some(fallback_head_response(
            &request.format,
            "queued",
            "queue_full",
            "render_queue_full",
            Some(5),
        ));
    }
    if let Some(timeout_error) = error.downcast_ref::<RenderTimeoutError>() {
        return Some(match timeout_error {
            RenderTimeoutError::QueueWait { .. } => fallback_head_response(
                &request.format,
                "timeout_queue",
                "render_timeout_queue",
                "render_timeout_queue",
                Some(5),
            ),
            RenderTimeoutError::RenderExec { .. } => fallback_head_response(
                &request.format,
                "timeout_render",
                "render_timeout_render",
                "render_timeout_render",
                Some(5),
            ),
        });
    }
    if let Some(fetch_error) = error.downcast_ref::<AssetFetchError>() {
        if let AssetFetchError::NegativeCache {
            retry_after_seconds,
            ..
        } = fetch_error
        {
            return Some(fallback_head_response(
                &request.format,
                "ipfs_negative_cache",
                "ipfs_negative_cache",
                "ipfs_negative_cache",
                Some(*retry_after_seconds),
            ));
        }
    }
    None
}

fn fallback_text_scale(width: u32) -> u32 {
    if width >= 1200 {
        4
    } else if width >= 800 {
        3
    } else if width >= 400 {
        2
    } else {
        1
    }
}

fn max_line_chars(width: u32, margin: u32, scale: u32) -> usize {
    let glyph_width = 5 * scale;
    let spacing = scale;
    let available = width.saturating_sub(margin.saturating_mul(2));
    let per_char = glyph_width.saturating_add(spacing);
    if per_char == 0 {
        return 0;
    }
    (available / per_char).max(1) as usize
}

fn truncate_line(line: &str, max_chars: usize) -> String {
    if line.len() <= max_chars {
        return line.to_string();
    }
    if max_chars <= 3 {
        return line.chars().take(max_chars).collect();
    }
    let mut out: String = line.chars().take(max_chars - 3).collect();
    out.push_str("...");
    out
}

fn text_width(text: &str, scale: u32) -> u32 {
    if text.is_empty() {
        return 0;
    }
    let glyph_width = 5 * scale;
    let spacing = scale;
    let len = text.chars().count() as u32;
    glyph_width
        .saturating_mul(len)
        .saturating_add(spacing.saturating_mul(len.saturating_sub(1)))
}

fn draw_text(image: &mut RgbaImage, x: u32, y: u32, scale: u32, text: &str, color: Rgba<u8>) {
    let mut cursor_x = x;
    let spacing = scale;
    for ch in text.chars() {
        draw_glyph(image, cursor_x, y, scale, ch, color);
        cursor_x = cursor_x.saturating_add(5 * scale + spacing);
    }
}

fn draw_glyph(image: &mut RgbaImage, x: u32, y: u32, scale: u32, ch: char, color: Rgba<u8>) {
    let rows = glyph_rows(ch);
    for (row_idx, row) in rows.iter().enumerate() {
        for col in 0..5 {
            if (row >> (4 - col)) & 1 == 1 {
                let px = x.saturating_add(col * scale);
                let py = y.saturating_add(row_idx as u32 * scale);
                for dy in 0..scale {
                    for dx in 0..scale {
                        let tx = px.saturating_add(dx);
                        let ty = py.saturating_add(dy);
                        if tx < image.width() && ty < image.height() {
                            image.put_pixel(tx, ty, color);
                        }
                    }
                }
            }
        }
    }
}

fn glyph_rows(ch: char) -> [u8; 7] {
    match ch.to_ascii_uppercase() {
        'A' => [
            0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001,
        ],
        'B' => [
            0b11110, 0b10001, 0b10001, 0b11110, 0b10001, 0b10001, 0b11110,
        ],
        'C' => [
            0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110,
        ],
        'D' => [
            0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110,
        ],
        'E' => [
            0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111,
        ],
        'F' => [
            0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000,
        ],
        'G' => [
            0b01110, 0b10001, 0b10000, 0b10000, 0b10011, 0b10001, 0b01110,
        ],
        'H' => [
            0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001,
        ],
        'I' => [
            0b01110, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110,
        ],
        'J' => [
            0b00111, 0b00010, 0b00010, 0b00010, 0b00010, 0b10010, 0b01100,
        ],
        'K' => [
            0b10001, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001,
        ],
        'L' => [
            0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111,
        ],
        'M' => [
            0b10001, 0b11011, 0b10101, 0b10101, 0b10001, 0b10001, 0b10001,
        ],
        'N' => [
            0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001, 0b10001,
        ],
        'O' => [
            0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110,
        ],
        'P' => [
            0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000,
        ],
        'Q' => [
            0b01110, 0b10001, 0b10001, 0b10001, 0b10101, 0b10010, 0b01101,
        ],
        'R' => [
            0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001,
        ],
        'S' => [
            0b01110, 0b10001, 0b10000, 0b01110, 0b00001, 0b10001, 0b01110,
        ],
        'T' => [
            0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100,
        ],
        'U' => [
            0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110,
        ],
        'V' => [
            0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01010, 0b00100,
        ],
        'W' => [
            0b10001, 0b10001, 0b10001, 0b10101, 0b10101, 0b10101, 0b01010,
        ],
        'X' => [
            0b10001, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001, 0b10001,
        ],
        'Y' => [
            0b10001, 0b10001, 0b01010, 0b00100, 0b00100, 0b00100, 0b00100,
        ],
        'Z' => [
            0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b10000, 0b11111,
        ],
        '0' => [
            0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110,
        ],
        '1' => [
            0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110,
        ],
        '2' => [
            0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111,
        ],
        '3' => [
            0b01110, 0b10001, 0b00001, 0b00110, 0b00001, 0b10001, 0b01110,
        ],
        '4' => [
            0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010,
        ],
        '5' => [
            0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110,
        ],
        '6' => [
            0b00110, 0b01000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110,
        ],
        '7' => [
            0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000,
        ],
        '8' => [
            0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110,
        ],
        '9' => [
            0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00010, 0b11100,
        ],
        '-' => [
            0b00000, 0b00000, 0b00000, 0b11111, 0b00000, 0b00000, 0b00000,
        ],
        '.' => [
            0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00100, 0b00100,
        ],
        ':' => [
            0b00000, 0b00100, 0b00100, 0b00000, 0b00100, 0b00100, 0b00000,
        ],
        '/' => [
            0b00001, 0b00010, 0b00100, 0b01000, 0b10000, 0b00000, 0b00000,
        ],
        ' ' => [
            0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000,
        ],
        _ => [
            0b01110, 0b10001, 0b00010, 0b00100, 0b00000, 0b00100, 0b00100,
        ],
    }
}

fn encode_image_bytes(format: &OutputFormat, image: RgbaImage) -> Vec<u8> {
    let mut bytes = Vec::new();
    match format {
        OutputFormat::Webp => {
            let encoder = image::codecs::webp::WebPEncoder::new_lossless(&mut bytes);
            let _ = encoder.encode(
                image.as_raw(),
                image.width(),
                image.height(),
                image::ExtendedColorType::Rgba8,
            );
        }
        OutputFormat::Png => {
            let _ = image.write_to(&mut std::io::Cursor::new(&mut bytes), ImageFormat::Png);
        }
        OutputFormat::Jpeg => {
            let rgb = DynamicImage::ImageRgba8(image).to_rgb8();
            let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut bytes, 90);
            let _ = encoder.encode(
                rgb.as_raw(),
                rgb.width(),
                rgb.height(),
                image::ColorType::Rgb8.into(),
            );
        }
    }
    bytes
}

fn format_collection_label(collection: &str) -> String {
    let value = collection.trim();
    if value.len() <= 14 {
        return value.to_ascii_uppercase();
    }
    let start = value.chars().take(6).collect::<String>();
    let end = value.chars().rev().take(4).collect::<String>();
    format!(
        "{}...{}",
        start.to_ascii_uppercase(),
        end.chars().rev().collect::<String>().to_ascii_uppercase()
    )
}

fn matches_etag(headers: &HeaderMap, etag: &str) -> bool {
    let header_value = match headers.get(header::IF_NONE_MATCH) {
        Some(value) => value.to_str().unwrap_or(""),
        None => return false,
    };
    if header_value.trim() == "*" {
        return true;
    }
    header_value
        .split(',')
        .map(|item| item.trim())
        .any(|value| value == etag)
}

fn is_cacheable(cache_control: &str) -> bool {
    !cache_control.contains("no-store")
}

fn placeholder_dimensions(
    state: &AppState,
    width_param: &Option<String>,
    og_mode: bool,
) -> (u32, u32) {
    if og_mode {
        return (1200, 630);
    }
    let base_width = state.config.default_canvas_width;
    let base_height = state.config.default_canvas_height;
    let width = resolve_placeholder_width(width_param).unwrap_or(base_width);
    let height = scale_placeholder_height(base_height, base_width, width);
    (width, height)
}

fn resolve_placeholder_width(width_param: &Option<String>) -> Option<u32> {
    let presets = vec![
        ("thumb", 64u32),
        ("small", 128u32),
        ("medium", 256u32),
        ("large", 512u32),
        ("xl", 1024u32),
        ("xxl", 2048u32),
    ];
    let width = width_param.as_ref()?;
    if width == "original" {
        return None;
    }
    for (name, size) in &presets {
        if width == name {
            return Some(*size);
        }
    }
    if let Ok(value) = width.parse::<u32>() {
        let (_, nearest) = presets.iter().min_by(|a, b| {
            let da = a.1.abs_diff(value);
            let db = b.1.abs_diff(value);
            da.cmp(&db)
        })?;
        return Some(*nearest);
    }
    None
}

fn scale_placeholder_height(original_height: u32, original_width: u32, target_width: u32) -> u32 {
    if original_width == 0 {
        return original_height;
    }
    let ratio = target_width as f64 / original_width as f64;
    (original_height as f64 * ratio).round() as u32
}

#[allow(clippy::result_large_err)]
fn canonicalize_chain_collection(
    state: &AppState,
    chain: &str,
    collection: &str,
) -> Result<(String, String), ApiError> {
    canonical::canonicalize_collection(chain, collection, &state.config)
        .map_err(|err| ApiError::bad_request(&err.to_string()))
}

fn parse_fresh_flag(raw: Option<&str>) -> bool {
    parse_bool_flag(raw)
}

fn parse_bool_flag(raw: Option<&str>) -> bool {
    raw.map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .map(|value| value == "1" || value == "true" || value == "yes")
        .unwrap_or(false)
}

fn wants_json_response(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase())
        .map(|value| value.contains("application/json") || value.contains("+json"))
        .unwrap_or(false)
}

fn fresh_key(chain: &str, collection: &str, token_id: &str, asset_id: &str) -> String {
    format!("{chain}:{collection}:{token_id}:{asset_id}")
}

fn fresh_rate_limit_info(retry_after_seconds: u64) -> RateLimitInfo {
    RateLimitInfo {
        allowed: false,
        limit: 1,
        remaining: 0,
        reset_seconds: retry_after_seconds,
    }
}

async fn metrics_access_allowed(state: &AppState, headers: &HeaderMap, ip: Option<IpAddr>) -> bool {
    if state.config.metrics_public {
        return true;
    }
    if let Some(ip) = ip {
        if state
            .config
            .metrics_allow_ips
            .iter()
            .any(|net| net.contains(&ip))
        {
            return true;
        }
    }
    if is_metrics_bearer_authorized(&state.config, headers) {
        return true;
    }
    if is_admin_authorized(&state.config, headers) {
        return true;
    }
    if state.config.metrics_require_admin_key {
        return false;
    }
    if let Some(ip) = ip {
        if let Some(rule) = ip_rule_for_ip(state, ip).await {
            return rule == "allow";
        }
    }
    false
}

fn rate_limit_response(info: Option<RateLimitInfo>) -> Response {
    let retry_after = info
        .as_ref()
        .map(|info| info.reset_seconds)
        .filter(|value| *value > 0)
        .unwrap_or_else(|| RATE_LIMIT_RETRY_AFTER_SECONDS.parse().unwrap_or(60));
    let mut response = ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded")
        .with_code("rate_limited")
        .with_field("retry_after_seconds", serde_json::json!(retry_after))
        .into_response();
    let _ = response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&retry_after.to_string())
            .unwrap_or(HeaderValue::from_static(RATE_LIMIT_RETRY_AFTER_SECONDS)),
    );
    if let Some(info) = info {
        let _ = response.headers_mut().insert(
            "X-RateLimit-Limit",
            HeaderValue::from_str(&info.limit.to_string()).unwrap_or(HeaderValue::from_static("0")),
        );
        let _ = response.headers_mut().insert(
            "X-RateLimit-Remaining",
            HeaderValue::from_str(&info.remaining.to_string())
                .unwrap_or(HeaderValue::from_static("0")),
        );
        let _ = response.headers_mut().insert(
            "X-RateLimit-Reset",
            HeaderValue::from_str(&info.reset_seconds.to_string())
                .unwrap_or(HeaderValue::from_static("0")),
        );
    }
    response
}

async fn ip_rule_for_ip(state: &AppState, ip: IpAddr) -> Option<String> {
    state.ip_rules.rule_for_ip(ip).await
}

pub(crate) fn client_ip(request: &axum::http::Request<Body>, state: &AppState) -> Option<IpAddr> {
    let peer_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip());
    if state.config.trusted_proxies.is_empty() {
        return peer_ip;
    }
    let peer_ip = peer_ip?;
    let trusted = state
        .config
        .trusted_proxies
        .iter()
        .any(|net| net.contains(&peer_ip));
    if !trusted {
        return Some(peer_ip);
    }
    let mut forwarded = parse_forwarded_chain(request.headers());
    if forwarded.len() > MAX_FORWARDED_IPS {
        forwarded.truncate(MAX_FORWARDED_IPS);
    }
    Some(select_client_ip(
        forwarded,
        &state.config.trusted_proxies,
        peer_ip,
    ))
}

fn client_ip_from_parts(
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    state: &AppState,
) -> Option<IpAddr> {
    if state.config.trusted_proxies.is_empty() {
        return peer_ip;
    }
    let peer_ip = peer_ip?;
    let trusted = state
        .config
        .trusted_proxies
        .iter()
        .any(|net| net.contains(&peer_ip));
    if !trusted {
        return Some(peer_ip);
    }
    let mut forwarded = parse_forwarded_chain(headers);
    if forwarded.len() > MAX_FORWARDED_IPS {
        forwarded.truncate(MAX_FORWARDED_IPS);
    }
    Some(select_client_ip(
        forwarded,
        &state.config.trusted_proxies,
        peer_ip,
    ))
}

fn select_client_ip(mut forwarded: Vec<IpAddr>, trusted: &[IpNet], peer_ip: IpAddr) -> IpAddr {
    forwarded.push(peer_ip);
    for ip in forwarded.iter().rev() {
        let is_trusted = trusted.iter().any(|net| net.contains(ip));
        if !is_trusted {
            return *ip;
        }
    }
    peer_ip
}

fn parse_forwarded_chain(headers: &HeaderMap) -> Vec<IpAddr> {
    if let Some(value) = headers.get("x-forwarded-for") {
        if let Ok(value) = value.to_str() {
            return parse_x_forwarded_for(value);
        }
    }
    if let Some(value) = headers.get("forwarded") {
        if let Ok(value) = value.to_str() {
            return parse_forwarded_header(value);
        }
    }
    Vec::new()
}

fn parse_x_forwarded_for(value: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for item in value.split(',') {
        if ips.len() >= MAX_FORWARDED_IPS {
            break;
        }
        if let Some(ip) = parse_ip_candidate(item.trim()) {
            ips.push(ip);
        }
    }
    ips
}

fn parse_forwarded_header(value: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for segment in value.split(',') {
        if ips.len() >= MAX_FORWARDED_IPS {
            break;
        }
        for pair in segment.split(';') {
            if ips.len() >= MAX_FORWARDED_IPS {
                break;
            }
            let pair = pair.trim();
            let (key, value) = match pair.split_once('=') {
                Some((key, value)) => (key.trim(), value.trim()),
                None => continue,
            };
            if !key.eq_ignore_ascii_case("for") {
                continue;
            }
            let cleaned = value.trim_matches('"');
            if let Some(ip) = parse_ip_candidate(cleaned) {
                ips.push(ip);
            }
        }
    }
    ips
}

fn parse_ip_candidate(value: &str) -> Option<IpAddr> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") {
        return None;
    }
    if let Some(bracketed) = trimmed.strip_prefix('[') {
        if let Some(end) = bracketed.find(']') {
            if let Ok(addr) = bracketed[..end].parse::<IpAddr>() {
                return Some(addr);
            }
        }
    }
    if let Ok(addr) = trimmed.parse::<IpAddr>() {
        return Some(addr);
    }
    if let Some((host, _)) = trimmed.rsplit_once(':') {
        if let Ok(addr) = host.parse::<IpAddr>() {
            return Some(addr);
        }
    }
    None
}

#[allow(clippy::result_large_err)]
fn split_dotted_segment(segment: &str) -> Result<(String, String), ApiError> {
    let (left, right) = segment
        .rsplit_once('.')
        .ok_or_else(|| ApiError::bad_request("invalid path segment"))?;
    if left.is_empty() || right.is_empty() {
        return Err(ApiError::bad_request("invalid path segment"));
    }
    Ok((left.to_string(), right.to_string()))
}

fn is_public_landing_path(state: &AppState, path: &str) -> bool {
    if !state.config.landing_public || state.config.landing.is_none() {
        return false;
    }
    if path.starts_with("/render/")
        || path.starts_with("/production/create/")
        || path.starts_with("/og/")
        || path == "/openapi.yaml"
    {
        return false;
    }
    landing::is_landing_asset_path(path)
}

fn is_status_path(path: &str) -> bool {
    matches!(path, "/status" | "/status.json")
}

fn is_openapi_path(path: &str) -> bool {
    path == "/openapi.yaml"
}

fn is_public_status_path(state: &AppState, path: &str) -> bool {
    if !state.config.status_public {
        return false;
    }
    is_status_path(path)
}

fn is_public_openapi_path(state: &AppState, path: &str) -> bool {
    state.config.openapi_public && is_openapi_path(path)
}

fn is_metrics_path(path: &str) -> bool {
    path == "/metrics"
}

fn is_metrics_bearer_authorized(config: &Config, headers: &HeaderMap) -> bool {
    let token = match config.metrics_bearer_token.as_deref() {
        Some(token) => token,
        None => return false,
    };
    let bearer = match extract_bearer_token(headers) {
        Some(bearer) => bearer,
        None => return false,
    };
    bool::from(token.as_bytes().ct_eq(bearer.as_bytes()))
}

pub(crate) fn is_safe_fallback_dir(root: &StdPath, candidate: &StdPath) -> bool {
    if !candidate.is_absolute() {
        return false;
    }
    if candidate
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return false;
    }
    if !candidate.starts_with(root) {
        return false;
    }
    let root = match std::fs::canonicalize(root) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let candidate = match std::fs::canonicalize(candidate) {
        Ok(value) => value,
        Err(_) => return false,
    };
    candidate.starts_with(&root)
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let mut parts = value.split_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    if scheme.eq_ignore_ascii_case("bearer") {
        Some(token)
    } else {
        None
    }
}

fn is_reasonable_token_len(token: &str) -> bool {
    let len = token.len();
    (MIN_BEARER_TOKEN_LEN..=MAX_BEARER_TOKEN_LEN).contains(&len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assets::AssetResolver;
    use crate::cache::CacheManager;
    use crate::chain::ChainClient;
    use crate::db::Database;
    use crate::pinning::PinnedAssetStore;
    use crate::state::AppState;
    use axum::body::to_bytes;
    use axum::http::header;
    use tempfile::tempdir;
    use tokio::sync::Semaphore;

    struct EnvGuard {
        keys: Vec<String>,
    }

    impl EnvGuard {
        fn new(values: Vec<(&str, String)>) -> Self {
            let mut keys = Vec::new();
            for (key, value) in values {
                unsafe {
                    std::env::set_var(key, value);
                }
                keys.push(key.to_string());
            }
            Self { keys }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for key in self.keys.drain(..) {
                unsafe {
                    std::env::remove_var(key);
                }
            }
        }
    }

    async fn build_state(config: Config) -> Arc<AppState> {
        let db = Database::new(&config).await.unwrap();
        let cache = CacheManager::new(&config).unwrap();
        let metrics = Arc::new(crate::metrics::Metrics::new(&config));
        let pinned_store = if config.pinning_enabled {
            Some(Arc::new(PinnedAssetStore::new(&config).unwrap()))
        } else {
            None
        };
        let ipfs_semaphore = Arc::new(Semaphore::new(config.max_concurrent_ipfs_fetches));
        let blocking_semaphore = Arc::new(Semaphore::new(config.max_blocking_tasks));
        let assets = AssetResolver::new(
            Arc::new(config.clone()),
            cache.clone(),
            db.clone(),
            pinned_store,
            ipfs_semaphore,
            blocking_semaphore.clone(),
            metrics.clone(),
        )
        .unwrap();
        let rpc_limit = if config.max_concurrent_rpc_calls == 0 {
            usize::MAX
        } else {
            config.max_concurrent_rpc_calls
        };
        let rpc_semaphore = Arc::new(Semaphore::new(rpc_limit));
        let chain = ChainClient::new(
            Arc::new(config.clone()),
            db.clone(),
            metrics.clone(),
            rpc_semaphore.clone(),
        );
        Arc::new(AppState::new(
            config,
            db,
            cache,
            assets,
            chain,
            metrics,
            blocking_semaphore,
            rpc_semaphore,
            None,
            None,
            None,
        ))
    }

    #[test]
    fn openapi_yaml_parses() {
        let spec: openapiv3::OpenAPI =
            serde_yaml::from_str(OPENAPI_YAML).expect("valid openapi yaml");
        assert!(spec.openapi.starts_with('3'));
        assert!(!spec.paths.paths.is_empty());
    }

    #[tokio::test]
    async fn fallback_file_response_sets_headers_and_body() {
        let dir = tempdir().unwrap();
        let meta = FallbackMeta {
            updated_at_ms: 123,
            source_sha256: "deadbeef".to_string(),
            source_width: 10,
            source_height: 20,
            variants: vec!["w512.png".to_string()],
        };
        let meta_bytes = serde_json::to_vec(&meta).unwrap();
        std::fs::write(dir.path().join("meta.json"), meta_bytes).unwrap();
        std::fs::write(dir.path().join("w512.png"), b"hello").unwrap();

        let response = fallback_file_response(
            dir.path(),
            &OutputFormat::Png,
            &None,
            false,
            "unapproved",
            "global",
            "public, max-age=60",
            false,
            None,
            &HeaderMap::new(),
        )
        .await
        .expect("fallback response");

        let headers = response.headers();
        assert_eq!(
            headers
                .get("X-Renderer-Fallback")
                .and_then(|value| value.to_str().ok()),
            Some("unapproved")
        );
        assert_eq!(
            headers
                .get("X-Renderer-Fallback-Source")
                .and_then(|value| value.to_str().ok()),
            Some("global")
        );
        assert_eq!(
            headers
                .get("X-Renderer-Fallback-Action")
                .and_then(|value| value.to_str().ok()),
            Some("stop")
        );
        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("public, max-age=60")
        );
        assert_eq!(
            headers
                .get(header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some("5")
        );
        let expected_etag = fallback_etag(&meta, "w512", &OutputFormat::Png);
        assert_eq!(
            headers
                .get(header::ETAG)
                .and_then(|value| value.to_str().ok()),
            Some(expected_etag.as_str())
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body, "hello");
    }

    #[tokio::test]
    async fn fallback_file_response_honors_if_none_match() {
        let dir = tempdir().unwrap();
        let meta = FallbackMeta {
            updated_at_ms: 123,
            source_sha256: "deadbeef".to_string(),
            source_width: 10,
            source_height: 20,
            variants: vec!["w512.png".to_string()],
        };
        let meta_bytes = serde_json::to_vec(&meta).unwrap();
        std::fs::write(dir.path().join("meta.json"), meta_bytes).unwrap();
        std::fs::write(dir.path().join("w512.png"), b"hello").unwrap();

        let expected_etag = fallback_etag(&meta, "w512", &OutputFormat::Png);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::IF_NONE_MATCH,
            HeaderValue::from_str(&expected_etag).unwrap(),
        );

        let response = fallback_file_response(
            dir.path(),
            &OutputFormat::Png,
            &None,
            false,
            "unapproved",
            "global",
            "public, max-age=60",
            false,
            None,
            &headers,
        )
        .await
        .expect("fallback response");

        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn fallback_variant_cache_avoids_meta_read() {
        let dir = tempdir().unwrap();
        let width = fallback_width_bucket(&None);
        let variant_label = fallback_variant_label(false, width);
        let filename = fallback_variant_filename(&variant_label, &OutputFormat::Png);
        let meta = FallbackMeta {
            updated_at_ms: 123,
            source_sha256: "deadbeef".to_string(),
            source_width: 10,
            source_height: 10,
            variants: vec![filename.clone()],
        };
        std::fs::write(
            dir.path().join("meta.json"),
            serde_json::to_vec_pretty(&meta).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.path().join(&filename), b"hello").unwrap();

        let first = load_fallback_variant(dir.path(), &OutputFormat::Png, &None, false)
            .await
            .expect("first fallback variant");
        assert_eq!(first.content_length, 5);

        std::fs::remove_file(dir.path().join("meta.json")).unwrap();

        let second = load_fallback_variant(dir.path(), &OutputFormat::Png, &None, false)
            .await
            .expect("cached fallback variant");
        assert_eq!(second.content_length, 5);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fallback_file_response_rejects_symlink_variant() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let width = fallback_width_bucket(&None);
        let variant_label = fallback_variant_label(false, width);
        let filename = fallback_variant_filename(&variant_label, &OutputFormat::Png);
        let meta = FallbackMeta {
            updated_at_ms: 123,
            source_sha256: "deadbeef".to_string(),
            source_width: 10,
            source_height: 10,
            variants: vec![filename.clone()],
        };
        std::fs::write(
            dir.path().join("meta.json"),
            serde_json::to_vec_pretty(&meta).unwrap(),
        )
        .unwrap();
        let target = dir.path().join("real.png");
        std::fs::write(&target, b"hello").unwrap();
        symlink(&target, dir.path().join(filename)).unwrap();

        let response = fallback_file_response(
            dir.path(),
            &OutputFormat::Png,
            &None,
            false,
            "unapproved",
            "global",
            "public, max-age=60",
            false,
            None,
            &HeaderMap::new(),
        )
        .await;
        assert!(response.is_none());
    }

    #[test]
    fn safe_fallback_dir_rejects_dot_components() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("fallbacks");
        std::fs::create_dir_all(&root).unwrap();
        let child = root.join("collection");
        std::fs::create_dir_all(&child).unwrap();
        assert!(!is_safe_fallback_dir(
            &root,
            root.join("..").join("secrets").as_path()
        ));
        assert!(!is_safe_fallback_dir(&root, StdPath::new("relative/path")));
        assert!(is_safe_fallback_dir(&root, &child));
    }

    #[tokio::test]
    async fn unapproved_fallback_uses_placeholder_when_missing() {
        let dir = tempdir().unwrap();
        let _env = EnvGuard::new(vec![
            ("ADMIN_PASSWORD", "test-admin".to_string()),
            (
                "DB_PATH",
                dir.path().join("renderer.db").to_string_lossy().to_string(),
            ),
            (
                "CACHE_DIR",
                dir.path().join("cache").to_string_lossy().to_string(),
            ),
            (
                "FALLBACKS_DIR",
                dir.path().join("fallbacks").to_string_lossy().to_string(),
            ),
            ("PINNING_ENABLED", "false".to_string()),
            ("I_KNOW_WHAT_I_AM_DOING", "true".to_string()),
        ]);
        let mut config = Config::from_env().unwrap();
        config.metrics_allow_ips = vec!["127.0.0.1/32".parse().unwrap()];
        config.metrics_public = false;
        config.metrics_require_admin_key = false;
        let state = build_state(config).await;
        let request = RenderRequest {
            chain: "base".to_string(),
            collection: "0xabc".to_string(),
            token_id: "1".to_string(),
            asset_id: "1".to_string(),
            format: OutputFormat::Png,
            cache_timestamp: None,
            cache_param_present: false,
            width_param: None,
            og_mode: false,
            overlay: None,
            background: None,
            fresh: false,
            approval_context: ApprovalCheckContext::deny(),
        };
        let response = resolve_unapproved_fallback(&state, &request, &HeaderMap::new())
            .await
            .expect("fallback response");
        assert_eq!(response.status(), StatusCode::OK);
        let action = response
            .headers()
            .get("X-Renderer-Fallback-Action")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert_eq!(action, "stop");
        let reason = response
            .headers()
            .get("X-Renderer-Fallback-Reason")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert_eq!(reason, "missing_fallback");
    }

    #[tokio::test]
    async fn unapproved_fallback_lines_use_admin_settings() {
        let dir = tempdir().unwrap();
        let _env = EnvGuard::new(vec![
            ("ADMIN_PASSWORD", "test-admin".to_string()),
            (
                "DB_PATH",
                dir.path().join("renderer.db").to_string_lossy().to_string(),
            ),
            (
                "CACHE_DIR",
                dir.path().join("cache").to_string_lossy().to_string(),
            ),
            (
                "FALLBACKS_DIR",
                dir.path().join("fallbacks").to_string_lossy().to_string(),
            ),
            ("PINNING_ENABLED", "false".to_string()),
            ("I_KNOW_WHAT_I_AM_DOING", "true".to_string()),
        ]);
        let config = Config::from_env().unwrap();
        let state = build_state(config).await;
        state
            .db
            .set_setting("unapproved_fallback_line1", Some("REGISTER HERE"))
            .await
            .unwrap();
        state
            .db
            .set_setting(
                "unapproved_fallback_line2",
                Some("https://example.test/register"),
            )
            .await
            .unwrap();
        state.clear_unapproved_fallback_cache().await;
        let lines = unapproved_fallback_lines(&state).await;
        assert_eq!(lines[0], "REGISTER HERE");
        assert_eq!(lines[1], "https://example.test/register");
    }

    #[test]
    fn source_label_from_headers_prefers_override() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Renderer-Source",
            HeaderValue::from_static("https://singular.app/path"),
        );
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://opensea.io"),
        );
        let identity = AccessContext {
            identity_key: Arc::from("client:1"),
            client_key_id: Some(1),
            max_concurrent_renders_override: None,
            allow_cache: false,
            allow_fresh: false,
            allow_on_demand_approval: false,
            allow_debug: false,
        };
        let label = source_label_from_headers(&headers, Some(&identity)).expect("source label");
        assert_eq!(label, "singular.app");
    }

    #[test]
    fn source_label_from_headers_uses_origin_host() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://example.test:8443"),
        );
        let identity = AccessContext {
            identity_key: Arc::from("client:1"),
            client_key_id: Some(1),
            max_concurrent_renders_override: None,
            allow_cache: false,
            allow_fresh: false,
            allow_on_demand_approval: false,
            allow_debug: false,
        };
        let label = source_label_from_headers(&headers, Some(&identity)).expect("source label");
        assert_eq!(label, "example.test:8443");
    }

    #[test]
    fn failure_result_detection() {
        assert!(is_failure_result("error"));
        assert!(is_failure_result("unapproved_fallback"));
        assert!(is_failure_result("render_fallback"));
        assert!(is_failure_result("queue_full"));
        assert!(is_failure_result("rate_limited"));
        assert!(!is_failure_result("ok"));
        assert!(!is_failure_result("cache_hit"));
        assert!(!is_failure_result("cache_miss"));
        assert!(!is_failure_result("token_override"));
    }

    #[tokio::test]
    async fn metrics_requires_auth_by_default() {
        let dir = tempdir().unwrap();
        let _env = EnvGuard::new(vec![
            ("ADMIN_PASSWORD", "test-admin".to_string()),
            (
                "DB_PATH",
                dir.path().join("renderer.db").to_string_lossy().to_string(),
            ),
            (
                "CACHE_DIR",
                dir.path().join("cache").to_string_lossy().to_string(),
            ),
            (
                "FALLBACKS_DIR",
                dir.path().join("fallbacks").to_string_lossy().to_string(),
            ),
            ("PINNING_ENABLED", "false".to_string()),
            ("METRICS_PUBLIC", "false".to_string()),
            ("METRICS_ALLOW_IPS", "".to_string()),
            ("METRICS_REQUIRE_ADMIN_KEY", "false".to_string()),
            ("I_KNOW_WHAT_I_AM_DOING", "true".to_string()),
        ]);
        let config = Config::from_env().unwrap();
        let state = build_state(config).await;
        let headers = HeaderMap::new();
        let response = metrics(
            State(state.clone()),
            headers,
            ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4242))),
        )
        .await
        .unwrap_err()
        .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn metrics_allows_metrics_bearer_token() {
        let dir = tempdir().unwrap();
        let _env = EnvGuard::new(vec![
            ("ADMIN_PASSWORD", "test-admin".to_string()),
            (
                "DB_PATH",
                dir.path().join("renderer.db").to_string_lossy().to_string(),
            ),
            (
                "CACHE_DIR",
                dir.path().join("cache").to_string_lossy().to_string(),
            ),
            (
                "FALLBACKS_DIR",
                dir.path().join("fallbacks").to_string_lossy().to_string(),
            ),
            ("PINNING_ENABLED", "false".to_string()),
            ("METRICS_PUBLIC", "false".to_string()),
            ("METRICS_ALLOW_IPS", "".to_string()),
            ("METRICS_BEARER_TOKEN", "metrics-token-123".to_string()),
            ("I_KNOW_WHAT_I_AM_DOING", "true".to_string()),
        ]);
        let config = Config::from_env().unwrap();
        let state = build_state(config).await;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer metrics-token-123"),
        );
        let response = metrics(
            State(state.clone()),
            headers,
            ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4242))),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_rejects_api_key() {
        let dir = tempdir().unwrap();
        let _env = EnvGuard::new(vec![
            ("ADMIN_PASSWORD", "test-admin".to_string()),
            (
                "DB_PATH",
                dir.path().join("renderer.db").to_string_lossy().to_string(),
            ),
            (
                "CACHE_DIR",
                dir.path().join("cache").to_string_lossy().to_string(),
            ),
            (
                "FALLBACKS_DIR",
                dir.path().join("fallbacks").to_string_lossy().to_string(),
            ),
            ("PINNING_ENABLED", "false".to_string()),
            ("API_KEY_SECRET", "secret".to_string()),
            ("METRICS_PUBLIC", "false".to_string()),
            ("METRICS_ALLOW_IPS", "".to_string()),
            ("METRICS_REQUIRE_ADMIN_KEY", "false".to_string()),
            ("I_KNOW_WHAT_I_AM_DOING", "true".to_string()),
        ]);
        let config = Config::from_env().unwrap();
        let state = build_state(config).await;
        let token = "test-token-1234567890-abc";
        let hash = hash_api_key("secret", token);
        let client_id = state.db.create_client("metrics", None).await.unwrap();
        let prefix = &token[..8];
        state
            .db
            .create_client_key(client_id, &hash, prefix, None, None, None, false)
            .await
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        let response = metrics(
            State(state.clone()),
            headers,
            ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4242))),
        )
        .await
        .unwrap_err()
        .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn metrics_allows_allowlisted_ip() {
        let dir = tempdir().unwrap();
        let _env = EnvGuard::new(vec![
            ("ADMIN_PASSWORD", "test-admin".to_string()),
            (
                "DB_PATH",
                dir.path().join("renderer.db").to_string_lossy().to_string(),
            ),
            (
                "CACHE_DIR",
                dir.path().join("cache").to_string_lossy().to_string(),
            ),
            (
                "FALLBACKS_DIR",
                dir.path().join("fallbacks").to_string_lossy().to_string(),
            ),
            ("PINNING_ENABLED", "false".to_string()),
            ("I_KNOW_WHAT_I_AM_DOING", "true".to_string()),
        ]);
        let mut config = Config::from_env().unwrap();
        config.metrics_allow_ips = vec!["127.0.0.1/32".parse().unwrap()];
        config.metrics_public = false;
        config.metrics_require_admin_key = false;
        let state = build_state(config).await;
        let headers = HeaderMap::new();
        let response = metrics(
            State(state.clone()),
            headers,
            ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4242))),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_require_admin_key_blocks_api_keys() {
        let dir = tempdir().unwrap();
        let _env = EnvGuard::new(vec![
            ("ADMIN_PASSWORD", "test-admin".to_string()),
            (
                "DB_PATH",
                dir.path().join("renderer.db").to_string_lossy().to_string(),
            ),
            (
                "CACHE_DIR",
                dir.path().join("cache").to_string_lossy().to_string(),
            ),
            (
                "FALLBACKS_DIR",
                dir.path().join("fallbacks").to_string_lossy().to_string(),
            ),
            ("PINNING_ENABLED", "false".to_string()),
            ("API_KEY_SECRET", "secret".to_string()),
            ("METRICS_REQUIRE_ADMIN_KEY", "true".to_string()),
            ("METRICS_PUBLIC", "false".to_string()),
            ("METRICS_ALLOW_IPS", "".to_string()),
            ("METRICS_BEARER_TOKEN", "metrics-token-123".to_string()),
            ("I_KNOW_WHAT_I_AM_DOING", "true".to_string()),
        ]);
        let config = Config::from_env().unwrap();
        let state = build_state(config).await;
        let token = "test-token-1234567890-abc";
        let hash = hash_api_key("secret", token);
        let client_id = state.db.create_client("metrics", None).await.unwrap();
        let prefix = &token[..8];
        state
            .db
            .create_client_key(client_id, &hash, prefix, None, None, None, false)
            .await
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        let response = metrics(
            State(state.clone()),
            headers,
            ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4242))),
        )
        .await
        .unwrap_err()
        .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test-admin"),
        );
        let response = metrics(
            State(state.clone()),
            headers,
            ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4242))),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer metrics-token-123"),
        );
        let response = metrics(
            State(state.clone()),
            headers,
            ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4242))),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

fn hash_api_key(secret: &str, token: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac can take key of any size");
    mac.update(token.as_bytes());
    let result = mac.finalize().into_bytes();
    hex::encode(result)
}

fn route_group(path: &str) -> &'static str {
    if is_status_path(path) {
        return "status";
    }
    if is_openapi_path(path) {
        return "openapi";
    }
    if is_metrics_path(path) {
        return "metrics";
    }
    if path.starts_with("/render/") || path.starts_with("/production/create/") {
        return "render";
    }
    if path.starts_with("/og/") {
        return "render";
    }
    if path.starts_with("/admin") {
        return "admin";
    }
    if path == "/healthz" {
        return "health";
    }
    "other"
}

fn record_usage(
    state: &AppState,
    route_group: &'static str,
    response: &Response,
    identity: Option<AccessContext>,
) {
    if !state.config.usage_tracking_enabled {
        return;
    }
    if state.config.usage_sample_rate <= 0.0 {
        return;
    }
    if state.config.usage_sample_rate < 1.0 && random::<f64>() > state.config.usage_sample_rate {
        return;
    }
    let Some(sender) = state.usage_tx.as_ref() else {
        return;
    };
    let identity_key = identity
        .as_ref()
        .map(|ctx| Arc::clone(&ctx.identity_key))
        .unwrap_or_else(|| Arc::from("anonymous"));
    let bytes_out = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);
    let cache_hit = response
        .headers()
        .get("X-Renderer-Cache-Hit")
        .and_then(|value| value.to_str().ok())
        .map(|value| value == "true")
        .unwrap_or(false);
    let hour_bucket = current_hour_bucket();
    let event = UsageEvent {
        hour_bucket,
        identity_key,
        route_group,
        bytes_out,
        cache_hit,
    };
    let _ = sender.try_send(event);
}

fn response_bytes(response: &Response) -> u64 {
    response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

fn record_http_metrics(
    state: &AppState,
    route_group: &'static str,
    method: &axum::http::Method,
    response: &Response,
    ip: Option<IpAddr>,
) {
    let status = response.status().as_u16().to_string();
    let bytes = response_bytes(response);
    state
        .metrics
        .observe_http_request(route_group, method.as_str(), &status);
    state.metrics.add_http_response_bytes(route_group, bytes);
    if let Some(ip) = ip {
        state.metrics.observe_top_ip(ip, bytes);
    }
}

fn classify_render_response(response: &Response) -> &'static str {
    if let Some(value) = response.headers().get("X-Renderer-Result") {
        if let Ok(value) = value.to_str() {
            if value == "placeholder" {
                return "placeholder";
            }
        }
    }
    if let Some(value) = response.headers().get("X-Renderer-Fallback") {
        if let Ok(value) = value.to_str() {
            return match value {
                "token_override" => "token_override",
                "unapproved" => "unapproved_fallback",
                "render_fallback" => "render_fallback",
                "queued" => "queue_full",
                "approval_rate_limited" => "rate_limited",
                "approval_stale" => "approval_stale",
                _ => "error",
            };
        }
    }
    if let Some(value) = response.headers().get("X-Renderer-Cache-Hit") {
        if let Ok(value) = value.to_str() {
            return if value == "true" {
                "cache_hit"
            } else {
                "cache_miss"
            };
        }
    }
    if response.status().is_success() || response.status().is_redirection() {
        "ok"
    } else {
        "error"
    }
}

fn is_failure_result(result: &str) -> bool {
    !matches!(result, "ok" | "cache_hit" | "cache_miss" | "token_override")
}

fn error_code_from_response(response: &Response) -> Option<String> {
    response
        .headers()
        .get("X-Renderer-Error-Code")
        .and_then(|value| value.to_str().ok())
        .map(sanitize_error_header)
        .filter(|value| !value.is_empty())
}

fn is_approval_error_code(code: &str) -> bool {
    matches!(
        code,
        "collection_not_approved" | "approval_stale" | "approval_check_rate_limited"
    )
}

fn should_track_collection_for_response(result: &str, response: &Response) -> bool {
    if result == "unapproved_fallback" {
        return false;
    }
    if let Some(code) = error_code_from_response(response) {
        if is_approval_error_code(&code) {
            return false;
        }
    }
    true
}

fn failure_reason_from_response(result: &str, response: &Response) -> String {
    if result != "error" && is_failure_result(result) {
        return result.to_string();
    }
    if let Some(code) = error_code_from_response(response) {
        return code;
    }
    "error".to_string()
}

fn failure_reason_from_error_code(error_code: Option<&str>) -> String {
    if let Some(code) = error_code {
        let sanitized = sanitize_error_header(code);
        if !sanitized.is_empty() {
            return sanitized;
        }
    }
    "error".to_string()
}

fn record_render_metrics(
    state: &AppState,
    response: &Response,
    duration: Duration,
    chain: &str,
    collection: &str,
    source_label: Option<&str>,
) {
    let result = classify_render_response(response);
    let bytes = response_bytes(response);
    state.metrics.observe_render_result(result);
    state.metrics.observe_render_duration("total", duration);
    let track_collection = should_track_collection_for_response(result, response);
    if track_collection {
        state
            .metrics
            .observe_top_collection(chain, collection, bytes);
    }
    if let Some(source) = source_label {
        state.metrics.observe_source_bytes(source, bytes);
    }
    if let Some(source) = source_label {
        match result {
            "cache_hit" => state
                .metrics
                .observe_source_cache_bytes(source, bytes, true),
            "cache_miss" => state
                .metrics
                .observe_source_cache_bytes(source, bytes, false),
            _ => {}
        }
    }
    if is_failure_result(result) {
        if track_collection {
            state.metrics.observe_failure_collection(chain, collection);
        }
        let source = source_label.unwrap_or("unknown");
        let reason = failure_reason_from_response(result, response);
        state.metrics.observe_failure_source(source);
        state.metrics.observe_failure_reason(&reason);
        state.metrics.observe_failure_source_reason(source, &reason);
    }
}

fn record_render_error_metrics(
    state: &AppState,
    duration: Duration,
    chain: &str,
    collection: &str,
    source_label: Option<&str>,
    error_code: Option<&str>,
) {
    state.metrics.observe_render_result("error");
    state.metrics.observe_render_duration("total", duration);
    let track_collection = !error_code.map(is_approval_error_code).unwrap_or(false);
    if track_collection {
        state.metrics.observe_failure_collection(chain, collection);
    }
    let source = source_label.unwrap_or("unknown");
    let reason = failure_reason_from_error_code(error_code);
    state.metrics.observe_failure_source(source);
    state.metrics.observe_failure_reason(&reason);
    state.metrics.observe_failure_source_reason(source, &reason);
}

fn should_log_failure(status: StatusCode) -> bool {
    status.is_server_error()
        || matches!(
            status,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
        )
}

fn log_failure_if_needed(
    state: &AppState,
    response: &Response,
    method: &axum::http::Method,
    uri: &axum::http::Uri,
    route_group: &'static str,
    ip: Option<IpAddr>,
    identity: Option<&AccessContext>,
    request_id: Option<&str>,
) {
    let Some(failure_log_tx) = state.failure_log_tx.as_ref() else {
        return;
    };
    let status = response.status();
    if !should_log_failure(status) {
        return;
    }
    let reason = response
        .extensions()
        .get::<ErrorLogContext>()
        .map(|context| context.detail.clone())
        .or_else(|| {
            response
                .headers()
                .get("X-Renderer-Error")
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string())
        });
    let path = if let Some(query) = uri.query() {
        format!("{}?{}", uri.path(), query)
    } else {
        uri.path().to_string()
    };
    let entry = FailureLogEntry::new(
        method.to_string(),
        path,
        status.as_u16(),
        route_group.to_string(),
        ip.map(|ip| ip_label_for_log(&state.config, ip)),
        identity.map(|ctx| ctx.identity_key.as_ref().to_string()),
        reason,
        request_id.map(|value| value.to_string()),
    );
    let _ = failure_log_tx.try_send(entry);
}

fn current_hour_bucket() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    (now / 3600 * 3600) as i64
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub body: Value,
    pub headers: HeaderMap,
    pub log_detail: Option<String>,
    pub code: Option<String>,
}

impl ApiError {
    pub fn new(status: StatusCode, message: &str) -> Self {
        Self {
            status,
            body: serde_json::json!({ "code": "error", "message": message, "error": message }),
            headers: HeaderMap::new(),
            log_detail: None,
            code: Some("error".to_string()),
        }
    }

    pub fn bad_request(message: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message).with_code("bad_request")
    }

    pub fn with_code(mut self, code: &str) -> Self {
        self.code = Some(code.to_string());
        if let Value::Object(map) = &mut self.body {
            map.insert("code".to_string(), Value::String(code.to_string()));
        }
        self
    }

    pub fn with_header(mut self, name: header::HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn with_field(mut self, key: &str, value: Value) -> Self {
        if let Value::Object(map) = &mut self.body {
            map.insert(key.to_string(), value);
        }
        self
    }

    pub fn with_log_detail(mut self, detail: String) -> Self {
        if !detail.is_empty() {
            self.log_detail = Some(detail);
        }
        self
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        tracing::warn!(error = ?error, "request failed");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "request failed")
            .with_log_detail(error.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let error_message = extract_error_message(&self.body);
        let error_code = extract_error_code(&self.body).or_else(|| self.code.clone());
        let body = Json(self.body);
        let mut response = (self.status, body).into_response();
        response.headers_mut().extend(self.headers);
        if let Some(code) = error_code.as_ref() {
            if let Ok(value) = HeaderValue::from_str(code) {
                response
                    .headers_mut()
                    .insert("X-Renderer-Error-Code", value);
            }
        }
        if let Some(message) = error_message.as_ref() {
            let sanitized = sanitize_error_header(message);
            if let Ok(value) = HeaderValue::from_str(&sanitized) {
                response.headers_mut().insert("X-Renderer-Error", value);
            }
        }
        if let Some(detail) = self
            .log_detail
            .or_else(|| error_message.map(|message| sanitize_error_header(&message)))
        {
            response.extensions_mut().insert(ErrorLogContext { detail });
        }
        response
    }
}

#[derive(Clone)]
struct ErrorLogContext {
    detail: String,
}

fn extract_error_message(body: &Value) -> Option<String> {
    let Value::Object(map) = body else {
        return None;
    };
    if let Some(message) = map.get("message").and_then(|value| value.as_str()) {
        return Some(message.to_string());
    }
    map.get("error")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
}

fn extract_error_code(body: &Value) -> Option<String> {
    let Value::Object(map) = body else {
        return None;
    };
    map.get("code")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
}

fn sanitize_error_header(value: &str) -> String {
    let mut sanitized: String = value
        .chars()
        .filter(|ch| ch.is_ascii() && !ch.is_control())
        .collect();
    sanitized.truncate(200);
    sanitized
}

fn map_render_error_anyhow<E: Into<anyhow::Error>>(error: E) -> ApiError {
    map_render_error(error.into())
}

fn map_render_error(error: anyhow::Error) -> ApiError {
    let detail = error.to_string();
    if error.downcast_ref::<RenderInputError>().is_some() {
        return ApiError::bad_request("invalid render request")
            .with_code("invalid_request")
            .with_log_detail(detail);
    }
    if error.downcast_ref::<RenderLimitError>().is_some() {
        return ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "render exceeds limits")
            .with_code("render_limit_exceeded")
            .with_log_detail(detail);
    }
    if error.downcast_ref::<render::RenderQueueError>().is_some() {
        return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "render queue full")
            .with_code("render_queue_full")
            .with_field("queue_full", Value::Bool(true))
            .with_header(header::RETRY_AFTER, HeaderValue::from_static("5"))
            .with_log_detail(detail);
    }
    if let Some(timeout_error) = error.downcast_ref::<RenderTimeoutError>() {
        let (code, scope, seconds) = match timeout_error {
            RenderTimeoutError::QueueWait { seconds } => {
                ("render_timeout_queue", "queue_wait", *seconds)
            }
            RenderTimeoutError::RenderExec { seconds } => {
                ("render_timeout_render", "render_exec", *seconds)
            }
        };
        return ApiError::new(StatusCode::GATEWAY_TIMEOUT, "render timeout")
            .with_code(code)
            .with_field("timeout_seconds", Value::Number(seconds.into()))
            .with_field("timeout_scope", Value::String(scope.to_string()))
            .with_header(header::RETRY_AFTER, HeaderValue::from_static("5"))
            .with_log_detail(detail);
    }
    if let Some(cached_error) = error.downcast_ref::<render::TokenStateCachedError>() {
        let retry_after = cached_error.retry_after_seconds.max(1);
        return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "token state cached")
            .with_code("token_state_cached")
            .with_field("retry_after_seconds", Value::Number(retry_after.into()))
            .with_header(
                header::RETRY_AFTER,
                HeaderValue::from_str(&retry_after.to_string())
                    .unwrap_or(HeaderValue::from_static("30")),
            )
            .with_log_detail(detail);
    }
    if error.downcast_ref::<render::TokenNotFoundError>().is_some() {
        return ApiError::new(StatusCode::NOT_FOUND, "token not found")
            .with_code("token_not_found")
            .with_log_detail(detail);
    }
    if error
        .downcast_ref::<render::UnsupportedStrategyError>()
        .is_some()
    {
        return ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported collection")
            .with_code("unsupported_collection")
            .with_log_detail(detail);
    }
    if let Some(approval_error) = error.downcast_ref::<render::ApprovalCheckError>() {
        return match approval_error {
            render::ApprovalCheckError::NotApproved => {
                ApiError::new(StatusCode::FORBIDDEN, "collection not approved")
                    .with_code("collection_not_approved")
                    .with_log_detail(detail)
            }
            render::ApprovalCheckError::RateLimited {
                retry_after_seconds,
            } => ApiError::new(StatusCode::TOO_MANY_REQUESTS, "approval check rate limited")
                .with_code("approval_check_rate_limited")
                .with_field(
                    "retry_after_seconds",
                    Value::Number((*retry_after_seconds).into()),
                )
                .with_header(
                    header::RETRY_AFTER,
                    HeaderValue::from_str(&retry_after_seconds.to_string())
                        .unwrap_or(HeaderValue::from_static("60")),
                )
                .with_log_detail(detail),
            render::ApprovalCheckError::Stale => {
                ApiError::new(StatusCode::FORBIDDEN, "approval stale")
                    .with_code("approval_stale")
                    .with_log_detail(detail)
            }
        };
    }
    if let Some(fetch_error) = error.downcast_ref::<AssetFetchError>() {
        return match fetch_error {
            AssetFetchError::InvalidUri => ApiError::bad_request("invalid asset uri")
                .with_code("invalid_asset_uri")
                .with_log_detail(detail),
            AssetFetchError::Blocked => ApiError::bad_request("asset uri not allowed")
                .with_code("asset_uri_blocked")
                .with_log_detail(detail),
            AssetFetchError::DataUriTooLarge { .. } => {
                ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "data uri too large")
                    .with_code("data_uri_too_large")
                    .with_log_detail(detail)
            }
            AssetFetchError::TooLarge => {
                ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "asset too large")
                    .with_code("asset_too_large")
                    .with_log_detail(detail)
            }
            AssetFetchError::NegativeCache {
                retry_after_seconds,
                ..
            } => {
                let mut error = ApiError::new(
                    StatusCode::BAD_GATEWAY,
                    "asset fetch blocked by ipfs negative cache",
                )
                .with_code("ipfs_negative_cache")
                .with_field("ipfs_negative_cache", Value::Bool(true))
                .with_field(
                    "retry_after_seconds",
                    Value::Number((*retry_after_seconds).into()),
                )
                .with_log_detail(detail)
                .with_header(
                    header::HeaderName::from_static("x-renderer-error"),
                    HeaderValue::from_static("ipfs_negative_cache"),
                );
                let retry_after = HeaderValue::from_str(&retry_after_seconds.to_string())
                    .unwrap_or(HeaderValue::from_static("30"));
                error = error.with_header(header::RETRY_AFTER, retry_after);
                error
            }
            AssetFetchError::UpstreamStatus { .. } | AssetFetchError::Upstream { .. } => {
                ApiError::new(StatusCode::BAD_GATEWAY, "asset fetch failed")
                    .with_code("asset_fetch_failed")
                    .with_log_detail(detail)
            }
        };
    }
    if error.downcast_ref::<reqwest::Error>().is_some() {
        return ApiError::new(StatusCode::BAD_GATEWAY, "asset fetch failed")
            .with_code("asset_fetch_failed")
            .with_log_detail(detail);
    }
    tracing::warn!(error = ?error, "render failed");
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "render failed")
        .with_code("render_failed")
        .with_log_detail(detail)
}
