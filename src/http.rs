use crate::assets::AssetFetchError;
use crate::canonical;
use crate::config::{AccessMode, Config};
use crate::failure_log::FailureLogEntry;
use crate::landing;
use crate::rate_limit::RateLimitInfo;
use crate::render::{
    OutputFormat, RenderInputError, RenderKeyLimit, RenderLimitError, RenderRequest,
    render_token_with_limit,
};
use crate::state::AppState;
use crate::usage::UsageEvent;
use crate::{admin, render};
use axum::body::Body;
use axum::extract::{ConnectInfo, Extension, Path, Query, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use hmac::{Hmac, Mac};
use image::{DynamicImage, ImageFormat, Rgba, RgbaImage};
use ipnet::IpNet;
use rand::random;
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_util::io::ReaderStream;

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

static PLACEHOLDER_CACHE: OnceLock<HashMap<PlaceholderKey, Arc<Vec<u8>>>> = OnceLock::new();
const PLACEHOLDER_PRESET_WIDTHS: [u32; 6] = [64u32, 128u32, 256u32, 512u32, 1024u32, 2048u32];

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
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/status", get(status))
        .route("/status.json", get(status))
        .route("/openapi.yaml", get(openapi_yaml))
        .route(
            "/render/{chain}/{collection}/{token_id}/{asset_id}/{format}",
            get(render_canonical).head(head_render_canonical),
        )
        .route(
            "/render/{chain}/{collection}/{token_id}/{tail}",
            get(render_primary_or_legacy_asset).head(head_render_primary_or_legacy_asset),
        )
        .route(
            "/render/{chain}/{collection}/{token_and_format}",
            get(render_primary_compat),
        )
        .route(
            "/production/create/{chain}/{cache_timestamp}/{collection}/{token_id}/{asset_id}/{format}",
            get(render_legacy).head(head_render_legacy),
        )
        .route(
            "/production/create/{chain}/{cache_timestamp}/{collection}/{token_id}/{asset}",
            get(render_legacy_compat).head(head_render_legacy_compat),
        )
        .route(
            "/og/{chain}/{collection}/{token_id}/{asset_id}/{format}",
            get(render_og).head(head_render_og),
        )
        .route(
            "/og/{chain}/{collection}/{token_id}/{asset}",
            get(render_og_compat).head(head_render_og_compat),
        )
        .nest("/admin", admin::router(state.clone()))
        .with_state(state)
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

async fn render_canonical(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_id, asset_id, format)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<RenderQuery>,
    headers: HeaderMap,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    let format = OutputFormat::from_extension(&format)
        .ok_or_else(|| ApiError::bad_request("unsupported image format"))?;
    render::validate_render_params(&chain, &collection, &token_id, Some(&asset_id))
        .map_err(map_render_error_anyhow)?;
    let (chain, collection) = canonicalize_chain_collection(&state, &chain, &collection)?;
    let width_param = query.width.or(query.img_width);
    let placeholder_width = width_param.clone();
    let cache_param_present = query.cache.is_some();
    let cache_timestamp = query.cache;
    let fresh_requested = parse_fresh_flag(query.fresh.as_deref());
    let allow_fresh = context
        .as_ref()
        .map(|ctx| ctx.0.allow_fresh)
        .unwrap_or(false);
    let fresh = if fresh_requested {
        if allow_fresh {
            true
        } else {
            let key = fresh_key(&chain, &collection, &token_id, &asset_id);
            let limit = state
                .db
                .check_fresh_request(&key, state.config.fresh_rate_limit_seconds)
                .await
                .map_err(map_render_error_anyhow)?;
            if !limit.allowed {
                let retry_after = limit.retry_after_seconds.unwrap_or(60);
                return Ok(rate_limit_response(Some(fresh_rate_limit_info(
                    retry_after,
                ))));
            }
            true
        }
    } else {
        false
    };
    let request = RenderRequest {
        chain,
        collection,
        token_id,
        asset_id,
        format,
        cache_timestamp,
        cache_param_present,
        width_param,
        og_mode: query.og_image.unwrap_or(false),
        overlay: query.overlay,
        background: query.bg,
        fresh,
    };
    let render_limit = context.as_ref().and_then(|ctx| ctx.0.render_limit());
    match render_token_with_limit(state.clone(), request, render_limit).await {
        Ok(response) => Ok(to_http_response(response, &headers).await),
        Err(err) => {
            if query.onerror.as_deref() == Some("placeholder") {
                let (width, height) = placeholder_dimensions(&state, &placeholder_width, false);
                return Ok(placeholder_response(&format, width, height));
            }
            Err(map_render_error(err))
        }
    }
}

async fn render_og(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_id, asset_id, format)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<RenderQuery>,
    headers: HeaderMap,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    let format = OutputFormat::from_extension(&format)
        .ok_or_else(|| ApiError::bad_request("unsupported image format"))?;
    render::validate_render_params(&chain, &collection, &token_id, Some(&asset_id))
        .map_err(map_render_error_anyhow)?;
    let (chain, collection) = canonicalize_chain_collection(&state, &chain, &collection)?;
    let width_param = query.width.or(query.img_width);
    let placeholder_width = width_param.clone();
    let cache_param_present = query.cache.is_some();
    let cache_timestamp = query.cache;
    let fresh_requested = parse_fresh_flag(query.fresh.as_deref());
    let allow_fresh = context
        .as_ref()
        .map(|ctx| ctx.0.allow_fresh)
        .unwrap_or(false);
    let fresh = if fresh_requested {
        if allow_fresh {
            true
        } else {
            let key = fresh_key(&chain, &collection, &token_id, &asset_id);
            let limit = state
                .db
                .check_fresh_request(&key, state.config.fresh_rate_limit_seconds)
                .await
                .map_err(map_render_error_anyhow)?;
            if !limit.allowed {
                let retry_after = limit.retry_after_seconds.unwrap_or(60);
                return Ok(rate_limit_response(Some(fresh_rate_limit_info(
                    retry_after,
                ))));
            }
            true
        }
    } else {
        false
    };
    let request = RenderRequest {
        chain,
        collection,
        token_id,
        asset_id,
        format,
        cache_timestamp,
        cache_param_present,
        width_param,
        og_mode: true,
        overlay: query.overlay,
        background: query.bg,
        fresh,
    };
    let render_limit = context.as_ref().and_then(|ctx| ctx.0.render_limit());
    match render_token_with_limit(state.clone(), request, render_limit).await {
        Ok(response) => Ok(to_http_response(response, &headers).await),
        Err(err) => {
            if query.onerror.as_deref() == Some("placeholder") {
                let (width, height) = placeholder_dimensions(&state, &placeholder_width, true);
                return Ok(placeholder_response(&format, width, height));
            }
            Err(map_render_error(err))
        }
    }
}

async fn render_legacy(
    State(state): State<Arc<AppState>>,
    Path((chain, cache_timestamp, collection, token_id, asset_id, format)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<RenderQuery>,
    headers: HeaderMap,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    let format = OutputFormat::from_extension(&format)
        .ok_or_else(|| ApiError::bad_request("unsupported image format"))?;
    render::validate_render_params(&chain, &collection, &token_id, Some(&asset_id))
        .map_err(map_render_error_anyhow)?;
    let (chain, collection) = canonicalize_chain_collection(&state, &chain, &collection)?;
    let width_param = query.width.or(query.img_width);
    let placeholder_width = width_param.clone();
    let fresh_requested = parse_fresh_flag(query.fresh.as_deref());
    let allow_fresh = context
        .as_ref()
        .map(|ctx| ctx.0.allow_fresh)
        .unwrap_or(false);
    let fresh = if fresh_requested {
        if allow_fresh {
            true
        } else {
            let key = fresh_key(&chain, &collection, &token_id, &asset_id);
            let limit = state
                .db
                .check_fresh_request(&key, state.config.fresh_rate_limit_seconds)
                .await
                .map_err(map_render_error_anyhow)?;
            if !limit.allowed {
                let retry_after = limit.retry_after_seconds.unwrap_or(60);
                return Ok(rate_limit_response(Some(fresh_rate_limit_info(
                    retry_after,
                ))));
            }
            true
        }
    } else {
        false
    };
    let request = RenderRequest {
        chain,
        collection,
        token_id,
        asset_id,
        format,
        cache_timestamp: Some(cache_timestamp),
        cache_param_present: true,
        width_param,
        og_mode: query.og_image.unwrap_or(false),
        overlay: query.overlay,
        background: query.bg,
        fresh,
    };
    let render_limit = context.as_ref().and_then(|ctx| ctx.0.render_limit());
    match render_token_with_limit(state.clone(), request, render_limit).await {
        Ok(response) => Ok(to_http_response(response, &headers).await),
        Err(err) => {
            if query.onerror.as_deref() == Some("placeholder") {
                let (width, height) = placeholder_dimensions(
                    &state,
                    &placeholder_width,
                    query.og_image.unwrap_or(false),
                );
                return Ok(placeholder_response(&format, width, height));
            }
            Err(map_render_error(err))
        }
    }
}

async fn render_primary(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_id, format)): Path<(String, String, String, String)>,
    Query(query): Query<RenderQuery>,
    RawQuery(raw_query): RawQuery,
) -> Result<Response, ApiError> {
    let format = OutputFormat::from_extension(&format)
        .ok_or_else(|| ApiError::bad_request("unsupported image format"))?;
    render::validate_render_params(&chain, &collection, &token_id, None)
        .map_err(map_render_error_anyhow)?;
    let (chain, collection) = canonicalize_chain_collection(&state, &chain, &collection)?;
    let cache_timestamp =
        render::resolve_cache_timestamp(&state, &chain, &collection, query.cache.clone())
            .await
            .map_err(map_render_error_anyhow)?;
    let cache_stamp = cache_timestamp
        .clone()
        .unwrap_or_else(|| "none".to_string());
    let primary_cache_key = format!("{chain}:{collection}:{token_id}:{cache_stamp}");
    let fresh_requested = parse_fresh_flag(query.fresh.as_deref());
    let asset_id = if fresh_requested {
        let _permit = state
            .rpc_semaphore
            .acquire()
            .await
            .map_err(|err| ApiError::from(anyhow::Error::new(err)))?;
        match state
            .chain
            .get_top_asset_id(&chain, &collection, &token_id)
            .await
        {
            Ok(asset_id) => {
                state
                    .primary_asset_cache
                    .insert(primary_cache_key.clone(), asset_id)
                    .await;
                asset_id
            }
            Err(err) => {
                state
                    .primary_asset_cache
                    .insert_negative(primary_cache_key.clone())
                    .await;
                return Err(ApiError::from(err));
            }
        }
    } else {
        match state.primary_asset_cache.get(&primary_cache_key).await {
            Some(crate::state::PrimaryAssetCacheValue::Hit(asset_id)) => asset_id,
            Some(crate::state::PrimaryAssetCacheValue::Negative) => {
                return Err(ApiError::new(
                    StatusCode::BAD_GATEWAY,
                    "primary asset lookup failed",
                ));
            }
            None => {
                let _permit = state
                    .rpc_semaphore
                    .acquire()
                    .await
                    .map_err(|err| ApiError::from(anyhow::Error::new(err)))?;
                match state
                    .chain
                    .get_top_asset_id(&chain, &collection, &token_id)
                    .await
                {
                    Ok(asset_id) => {
                        state
                            .primary_asset_cache
                            .insert(primary_cache_key.clone(), asset_id)
                            .await;
                        asset_id
                    }
                    Err(err) => {
                        state
                            .primary_asset_cache
                            .insert_negative(primary_cache_key.clone())
                            .await;
                        return Err(ApiError::from(err));
                    }
                }
            }
        }
    };
    let mut target = format!(
        "/render/{}/{}/{}/{}/{}",
        chain,
        collection,
        token_id,
        asset_id,
        format.extension()
    );
    let mut query_string = raw_query.unwrap_or_default();
    if query.cache.is_none() {
        if let Some(cache_value) = cache_timestamp {
            if query_string.is_empty() {
                query_string = format!("cache={cache_value}");
            } else {
                query_string.push_str("&cache=");
                query_string.push_str(&cache_value);
            }
        }
    }
    if !query_string.is_empty() {
        target.push('?');
        target.push_str(&query_string);
    }
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "X-Renderer-Primary-AssetId",
        HeaderValue::from_str(&asset_id.to_string()).unwrap_or(HeaderValue::from_static("0")),
    );
    Ok((headers, Redirect::temporary(&target)).into_response())
}

async fn render_primary_or_legacy_asset(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_id, tail)): Path<(String, String, String, String)>,
    Query(query): Query<RenderQuery>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    if let Some((asset_id, format)) = tail.rsplit_once('.') {
        render_canonical(
            State(state),
            Path((
                chain,
                collection,
                token_id,
                asset_id.to_string(),
                format.to_string(),
            )),
            Query(query),
            headers,
            context,
        )
        .await
    } else {
        render_primary(
            State(state),
            Path((chain, collection, token_id, tail)),
            Query(query),
            RawQuery(raw_query),
        )
        .await
    }
}

async fn render_primary_compat(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_and_format)): Path<(String, String, String)>,
    Query(query): Query<RenderQuery>,
    RawQuery(raw_query): RawQuery,
) -> Result<Response, ApiError> {
    let (token_id, format) = split_dotted_segment(&token_and_format)?;
    render_primary(
        State(state),
        Path((chain, collection, token_id, format)),
        Query(query),
        RawQuery(raw_query),
    )
    .await
}

async fn render_legacy_compat(
    State(state): State<Arc<AppState>>,
    Path((chain, cache_timestamp, collection, token_id, asset)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<RenderQuery>,
    headers: HeaderMap,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    let (asset_id, format) = split_dotted_segment(&asset)?;
    render_legacy(
        State(state),
        Path((
            chain,
            cache_timestamp,
            collection,
            token_id,
            asset_id,
            format,
        )),
        Query(query),
        headers,
        context,
    )
    .await
}

async fn render_og_compat(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_id, asset)): Path<(String, String, String, String)>,
    Query(query): Query<RenderQuery>,
    headers: HeaderMap,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    let (asset_id, format) = split_dotted_segment(&asset)?;
    render_og(
        State(state),
        Path((chain, collection, token_id, asset_id, format)),
        Query(query),
        headers,
        context,
    )
    .await
}

async fn head_render_canonical(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_id, asset_id, format)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<RenderQuery>,
) -> Result<Response, ApiError> {
    let format = OutputFormat::from_extension(&format)
        .ok_or_else(|| ApiError::bad_request("unsupported image format"))?;
    let width_param = query.width.or(query.img_width);
    let cache_param_present = query.cache.is_some();
    let cache_timestamp = query.cache;
    let fresh = parse_fresh_flag(query.fresh.as_deref());
    let request = RenderRequest {
        chain,
        collection,
        token_id,
        asset_id,
        format,
        cache_timestamp,
        cache_param_present,
        width_param,
        og_mode: query.og_image.unwrap_or(false),
        overlay: query.overlay,
        background: query.bg,
        fresh,
    };
    head_cached_response(state, request).await
}

async fn head_render_og(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_id, asset_id, format)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<RenderQuery>,
) -> Result<Response, ApiError> {
    let format = OutputFormat::from_extension(&format)
        .ok_or_else(|| ApiError::bad_request("unsupported image format"))?;
    let width_param = query.width.or(query.img_width);
    let cache_param_present = query.cache.is_some();
    let cache_timestamp = query.cache;
    let fresh = parse_fresh_flag(query.fresh.as_deref());
    let request = RenderRequest {
        chain,
        collection,
        token_id,
        asset_id,
        format,
        cache_timestamp,
        cache_param_present,
        width_param,
        og_mode: true,
        overlay: query.overlay,
        background: query.bg,
        fresh,
    };
    head_cached_response(state, request).await
}

async fn head_render_legacy(
    State(state): State<Arc<AppState>>,
    Path((chain, cache_timestamp, collection, token_id, asset_id, format)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<RenderQuery>,
) -> Result<Response, ApiError> {
    let format = OutputFormat::from_extension(&format)
        .ok_or_else(|| ApiError::bad_request("unsupported image format"))?;
    let width_param = query.width.or(query.img_width);
    let fresh = parse_fresh_flag(query.fresh.as_deref());
    let request = RenderRequest {
        chain,
        collection,
        token_id,
        asset_id,
        format,
        cache_timestamp: Some(cache_timestamp),
        cache_param_present: true,
        width_param,
        og_mode: query.og_image.unwrap_or(false),
        overlay: query.overlay,
        background: query.bg,
        fresh,
    };
    head_cached_response(state, request).await
}

async fn head_render_primary_or_legacy_asset(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_id, tail)): Path<(String, String, String, String)>,
    Query(query): Query<RenderQuery>,
) -> Result<Response, ApiError> {
    if let Some((asset_id, format)) = tail.rsplit_once('.') {
        head_render_canonical(
            State(state),
            Path((
                chain,
                collection,
                token_id,
                asset_id.to_string(),
                format.to_string(),
            )),
            Query(query),
        )
        .await
    } else {
        Err(ApiError::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "head not supported for primary renders",
        ))
    }
}

async fn head_render_legacy_compat(
    State(state): State<Arc<AppState>>,
    Path((chain, cache_timestamp, collection, token_id, asset)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<RenderQuery>,
) -> Result<Response, ApiError> {
    let (asset_id, format) = split_dotted_segment(&asset)?;
    head_render_legacy(
        State(state),
        Path((
            chain,
            cache_timestamp,
            collection,
            token_id,
            asset_id,
            format,
        )),
        Query(query),
    )
    .await
}

async fn head_render_og_compat(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_id, asset)): Path<(String, String, String, String)>,
    Query(query): Query<RenderQuery>,
) -> Result<Response, ApiError> {
    let (asset_id, format) = split_dotted_segment(&asset)?;
    head_render_og(
        State(state),
        Path((chain, collection, token_id, asset_id, format)),
        Query(query),
    )
    .await
}

async fn head_cached_response(
    state: Arc<AppState>,
    request: RenderRequest,
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
    render::ensure_collection_approved(&state, &request.chain, &request.collection)
        .await
        .map_err(map_render_error_anyhow)?;
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
    if let Some(path) = response.cached_path.as_ref() {
        if let Some(length) = response.content_length {
            if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
                headers.insert(header::CONTENT_LENGTH, value);
            }
        }
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
    raw.map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .map(|value| value == "1" || value == "true" || value == "yes")
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

#[derive(Clone, Debug)]
struct AccessContext {
    identity_key: Arc<str>,
    client_key_id: Option<i64>,
    max_concurrent_renders_override: Option<usize>,
    allow_fresh: bool,
}

impl AccessContext {
    fn render_limit(&self) -> Option<RenderKeyLimit> {
        let limit = self.max_concurrent_renders_override?;
        if limit == 0 {
            return None;
        }
        let key_id = self.client_key_id?;
        Some(RenderKeyLimit {
            key_id,
            max_concurrent: limit,
        })
    }
}

pub async fn access_middleware(
    state: Arc<AppState>,
    mut request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path();
    if path == "/healthz" {
        return next.run(request).await;
    }
    let route_group = route_group(path);
    let ip = client_ip(&request, &state);
    let ip_identity = ip.map(|ip| AccessContext {
        identity_key: Arc::from(format!("ip:{ip}")),
        client_key_id: None,
        max_concurrent_renders_override: None,
        allow_fresh: false,
    });
    let is_admin = path == "/admin" || path.starts_with("/admin/");
    let is_public_landing = is_public_landing_path(&state, path);
    let is_public_status = is_public_status_path(&state, path);
    let is_public_openapi = is_public_openapi_path(&state, path);

    if let Some(ip) = ip {
        let info = apply_ip_rate_limit(&state, ip).await;
        if !info.allowed {
            let response = rate_limit_response(Some(info));
            let identity = ip_identity.clone();
            log_failure_if_needed(
                &state,
                &response,
                &method,
                &uri,
                route_group,
                Some(ip),
                identity.as_ref(),
            );
            record_usage(&state, route_group, &response, identity);
            return response;
        }
    }

    let should_check_key = match state.config.access_mode {
        AccessMode::Open | AccessMode::DenylistOnly => state.config.track_keys_in_open_mode,
        _ => true,
    };
    let bearer = if should_check_key {
        extract_bearer_token(request.headers()).filter(|token| is_reasonable_token_len(token))
    } else {
        None
    };
    let key_info =
        if let (Some(token), Some(secret)) = (bearer, state.config.api_key_secret.as_deref()) {
            let hash = hash_api_key(secret, token);
            if let Some(key) = state.api_key_cache.get(&hash).await {
                Some(key)
            } else {
                let fetched = state.db.find_client_key_by_hash(&hash).await.ok().flatten();
                if let Some(key) = fetched.as_ref() {
                    state.api_key_cache.insert(hash, key.clone()).await;
                }
                fetched
            }
        } else {
            None
        };

    let identity = if let Some(key) = key_info.as_ref() {
        Some(AccessContext {
            identity_key: Arc::from(format!("client:{}", key.client_id)),
            client_key_id: Some(key.id),
            max_concurrent_renders_override: key
                .max_concurrent_renders_override
                .and_then(|value| value.try_into().ok()),
            allow_fresh: key.allow_fresh,
        })
    } else if ip_identity.is_some() {
        ip_identity.clone()
    } else {
        None
    };

    if !is_admin
        && !is_public_landing
        && !is_public_status
        && !is_public_openapi
        && !is_access_allowed(&state, ip, key_info.as_ref()).await
    {
        if let Some(ip) = ip {
            let info = apply_auth_fail_limit(&state, ip).await;
            if !info.allowed {
                let response = rate_limit_response(Some(info));
                log_failure_if_needed(
                    &state,
                    &response,
                    &method,
                    &uri,
                    route_group,
                    Some(ip),
                    identity.as_ref(),
                );
                record_usage(&state, route_group, &response, identity.clone());
                return response;
            }
        }
        let response = ApiError::new(StatusCode::UNAUTHORIZED, "access denied")
            .with_header(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"renderer\""),
            )
            .into_response();
        log_failure_if_needed(
            &state,
            &response,
            &method,
            &uri,
            route_group,
            ip,
            identity.as_ref(),
        );
        record_usage(&state, route_group, &response, identity.clone());
        return response;
    }

    if let Some(key) = key_info.as_ref() {
        let info = apply_key_rate_limit(&state, key).await;
        if !info.allowed {
            let response = rate_limit_response(Some(info));
            log_failure_if_needed(
                &state,
                &response,
                &method,
                &uri,
                route_group,
                ip,
                identity.as_ref(),
            );
            record_usage(&state, route_group, &response, identity.clone());
            return response;
        }
    }

    if let Some(context) = identity.clone() {
        request.extensions_mut().insert(context);
    }

    let response = next.run(request).await;
    log_failure_if_needed(
        &state,
        &response,
        &method,
        &uri,
        route_group,
        ip,
        identity.as_ref(),
    );
    record_usage(&state, route_group, &response, identity);
    response
}

async fn is_access_allowed(
    state: &AppState,
    ip: Option<std::net::IpAddr>,
    key: Option<&crate::db::ClientKey>,
) -> bool {
    use crate::config::AccessMode;
    match state.config.access_mode {
        AccessMode::Open => true,
        AccessMode::KeyRequired => key.map(|k| k.active).unwrap_or(false),
        AccessMode::Hybrid => {
            if let Some(key) = key {
                return key.active;
            }
            let ip_rule = if let Some(ip) = ip {
                ip_rule_for_ip(state, ip).await
            } else {
                None
            };
            !matches!(ip_rule.as_deref(), Some("deny"))
        }
        AccessMode::DenylistOnly => {
            if let Some(key) = key {
                if !key.active {
                    return false;
                }
            }
            let ip_rule = if let Some(ip) = ip {
                ip_rule_for_ip(state, ip).await
            } else {
                None
            };
            !matches!(ip_rule.as_deref(), Some("deny"))
        }
        AccessMode::AllowlistOnly => {
            if let Some(key) = key {
                return key.active;
            }
            let ip_rule = if let Some(ip) = ip {
                ip_rule_for_ip(state, ip).await
            } else {
                None
            };
            matches!(ip_rule.as_deref(), Some("allow"))
        }
    }
}

async fn apply_ip_rate_limit(state: &AppState, ip: std::net::IpAddr) -> RateLimitInfo {
    state.rate_limiter.check(ip).await
}

async fn apply_auth_fail_limit(state: &AppState, ip: std::net::IpAddr) -> RateLimitInfo {
    state.auth_fail_limiter.check(ip).await
}

async fn apply_key_rate_limit(state: &AppState, key: &crate::db::ClientKey) -> RateLimitInfo {
    if !key.active {
        return RateLimitInfo {
            allowed: false,
            limit: 0,
            remaining: 0,
            reset_seconds: 0,
        };
    }
    let rate = key
        .rate_limit_per_minute
        .map(|value| value as u64)
        .unwrap_or(state.config.key_rate_limit_per_minute);
    let burst = key
        .burst
        .map(|value| value as u64)
        .unwrap_or(state.config.key_rate_limit_burst);
    state.key_rate_limiter.check(key.id, rate, burst).await
}

fn rate_limit_response(info: Option<RateLimitInfo>) -> Response {
    let mut response =
        ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    let retry_after = info
        .as_ref()
        .map(|info| info.reset_seconds)
        .filter(|value| *value > 0)
        .unwrap_or_else(|| RATE_LIMIT_RETRY_AFTER_SECONDS.parse().unwrap_or(60));
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

fn is_public_status_path(state: &AppState, path: &str) -> bool {
    if !state.config.status_public {
        return false;
    }
    matches!(path, "/status" | "/status.json")
}

fn is_public_openapi_path(state: &AppState, path: &str) -> bool {
    state.config.openapi_public && path == "/openapi.yaml"
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
    use super::OPENAPI_YAML;

    #[test]
    fn openapi_yaml_parses() {
        let spec: openapiv3::OpenAPI =
            serde_yaml::from_str(OPENAPI_YAML).expect("valid openapi yaml");
        assert!(spec.openapi.starts_with('3'));
        assert!(!spec.paths.paths.is_empty());
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
    if path.starts_with("/render/") || path.starts_with("/production/create/") {
        return "render";
    }
    if path.starts_with("/og/") {
        return "og";
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

fn log_failure_if_needed(
    state: &AppState,
    response: &Response,
    method: &axum::http::Method,
    uri: &axum::http::Uri,
    route_group: &'static str,
    ip: Option<IpAddr>,
    identity: Option<&AccessContext>,
) {
    let Some(failure_log) = state.failure_log.as_ref() else {
        return;
    };
    let status = response.status();
    if !(status.is_client_error() || status.is_server_error()) {
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
        ip.map(|ip| ip.to_string()),
        identity.map(|ctx| ctx.identity_key.as_ref().to_string()),
        reason,
    );
    let failure_log = failure_log.clone();
    tokio::spawn(async move {
        failure_log.write(entry).await;
    });
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
}

impl ApiError {
    pub fn new(status: StatusCode, message: &str) -> Self {
        Self {
            status,
            body: serde_json::json!({ "error": message }),
            headers: HeaderMap::new(),
            log_detail: None,
        }
    }

    pub fn bad_request(message: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn forbidden(message: &str) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
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
        let body = Json(self.body);
        let mut response = (self.status, body).into_response();
        response.headers_mut().extend(self.headers);
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
    map.get("error")
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
        return ApiError::bad_request("invalid render request").with_log_detail(detail);
    }
    if error.downcast_ref::<RenderLimitError>().is_some() {
        return ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "render exceeds limits")
            .with_log_detail(detail);
    }
    if error.downcast_ref::<render::RenderQueueError>().is_some() {
        return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "render queue full")
            .with_field("queue_full", Value::Bool(true))
            .with_header(header::RETRY_AFTER, HeaderValue::from_static("5"))
            .with_log_detail(detail);
    }
    if let Some(fetch_error) = error.downcast_ref::<AssetFetchError>() {
        return match fetch_error {
            AssetFetchError::InvalidUri => {
                ApiError::bad_request("invalid asset uri").with_log_detail(detail)
            }
            AssetFetchError::Blocked => {
                ApiError::bad_request("asset uri not allowed").with_log_detail(detail)
            }
            AssetFetchError::TooLarge => {
                ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "asset too large")
                    .with_log_detail(detail)
            }
            AssetFetchError::UpstreamStatus { .. } | AssetFetchError::Upstream { .. } => {
                ApiError::new(StatusCode::BAD_GATEWAY, "asset fetch failed").with_log_detail(detail)
            }
        };
    }
    if error.downcast_ref::<reqwest::Error>().is_some() {
        return ApiError::new(StatusCode::BAD_GATEWAY, "asset fetch failed")
            .with_log_detail(detail);
    }
    let message = error.to_string();
    if message.contains("collection not approved") {
        return ApiError::forbidden("collection not approved").with_log_detail(detail);
    }
    tracing::warn!(error = ?error, "render failed");
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "render failed").with_log_detail(detail)
}
