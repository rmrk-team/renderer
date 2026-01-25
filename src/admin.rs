use crate::canonical;
use crate::catalog_warmup::{CatalogWarmupRequest, enqueue_catalog_warmup};
use crate::config::{AdminCollectionInput, Config};
use crate::db::{
    Client, ClientKey, CollectionConfig, HashReplacement, IpRule, PinnedAssetCounts, RpcEndpoint,
    UsageRow, WarmupJob,
};
use crate::http::client_ip;
use crate::rate_limit::RateLimitInfo;
use crate::render::refresh_canvas_size;
use crate::state::AppState;
use crate::token_warmup::{TokenWarmupRequest, enqueue_token_warmup};
use crate::warmup::{WarmupRequest, enqueue_warmup};
use anyhow::{Context, anyhow};
use axum::body::Body;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::Engine;
use ethers::providers::Middleware;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::warn;

pub fn router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    let max_body = if state.config.max_admin_body_bytes == 0 {
        usize::MAX
    } else {
        state.config.max_admin_body_bytes
    };
    let api = Router::new()
        .route(
            "/api/collections",
            get(list_collections).post(upsert_collection),
        )
        .route(
            "/api/collections/{chain}/{collection}",
            delete(delete_collection),
        )
        .route(
            "/api/collections/{chain}/{collection}/approve",
            post(approve_collection),
        )
        .route(
            "/api/collections/{chain}/{collection}/refresh-canvas",
            post(refresh_canvas),
        )
        .route(
            "/api/collections/{chain}/{collection}/cache-epoch",
            post(update_cache_epoch),
        )
        .route("/api/warmup", get(warmup_stats).post(start_warmup))
        .route("/api/warmup/catalog", post(start_catalog_warmup))
        .route("/api/warmup/tokens", post(start_token_warmup_range))
        .route("/api/warmup/tokens/manual", post(start_token_warmup_manual))
        .route("/api/warmup/status", get(catalog_warmup_status))
        .route("/api/warmup/jobs", get(list_warmup_jobs))
        .route("/api/warmup/jobs/{id}/cancel", post(cancel_warmup_job))
        .route("/api/warmup/pause", post(pause_warmup))
        .route("/api/warmup/resume", post(resume_warmup))
        .route("/api/cache", get(cache_stats))
        .route("/api/pinned", get(pinned_stats))
        .route("/api/cache/purge", post(purge_cache))
        .route(
            "/api/hash-replacements",
            get(list_hash_replacements).post(upload_hash_replacement),
        )
        .route(
            "/api/hash-replacements/{cid}",
            delete(delete_hash_replacement),
        )
        .route("/api/rpc/{chain}", get(list_rpc).put(replace_rpc))
        .route("/api/rpc/{chain}/health", get(rpc_health))
        .route("/api/clients", get(list_clients).post(create_client))
        .route(
            "/api/clients/{id}",
            put(update_client).delete(delete_client),
        )
        .route(
            "/api/clients/{id}/keys",
            get(list_client_keys).post(create_client_key),
        )
        .route("/api/clients/keys/{key_id}", delete(revoke_client_key))
        .route("/api/ip-rules", get(list_ip_rules).post(create_ip_rule))
        .route("/api/ip-rules/{id}", delete(delete_ip_rule))
        .route("/api/usage", get(list_usage))
        .route("/api/settings", get(get_settings))
        .route("/api/settings/require-approval", put(set_require_approval))
        .layer(middleware::from_fn_with_state(state, require_admin))
        .layer(RequestBodyLimitLayer::new(max_body));
    Router::new()
        .route("/", get(admin_page))
        .route("/static/admin.css", get(admin_css))
        .route("/static/admin.js", get(admin_js))
        .merge(api)
        .layer(middleware::from_fn(admin_security_headers))
}

async fn admin_security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'",
        ),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn admin_page() -> impl IntoResponse {
    Html(ADMIN_HTML)
}

async fn admin_css() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/css; charset=utf-8"),
        )],
        ADMIN_CSS,
    )
}

async fn admin_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/javascript; charset=utf-8"),
        )],
        ADMIN_JS,
    )
}

async fn list_collections(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<CollectionConfig>>, AdminError> {
    let collections = state.db.list_collections().await?;
    Ok(Json(collections))
}

async fn upsert_collection(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AdminCollectionInput>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let (chain, collection_address) =
        canonicalize_chain_collection(&state, &payload.chain, &payload.collection_address)?;
    let collection_key = collection_address.clone();
    let input = AdminCollectionInput {
        chain,
        collection_address,
        og_focal_point: payload.og_focal_point,
        og_overlay_uri: payload.og_overlay_uri,
        watermark_overlay_uri: payload.watermark_overlay_uri,
        warmup_strategy: payload.warmup_strategy,
        approved: payload.approved,
    };
    state.db.upsert_collection_config(&input).await?;
    state
        .invalidate_collection_cache(&input.chain, &collection_key)
        .await;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

async fn delete_collection(
    State(state): State<Arc<AppState>>,
    Path((chain, collection)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let (chain, collection) = canonicalize_chain_collection(&state, &chain, &collection)?;
    state.db.delete_collection(&chain, &collection).await?;
    state.invalidate_collection_cache(&chain, &collection).await;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

#[derive(Debug, Deserialize)]
struct ApproveRequest {
    approved: bool,
}

async fn approve_collection(
    State(state): State<Arc<AppState>>,
    Path((chain, collection)): Path<(String, String)>,
    Json(payload): Json<ApproveRequest>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let (chain, collection) = canonicalize_chain_collection(&state, &chain, &collection)?;
    let input = AdminCollectionInput {
        chain,
        collection_address: collection.clone(),
        og_focal_point: None,
        og_overlay_uri: None,
        watermark_overlay_uri: None,
        warmup_strategy: None,
        approved: Some(payload.approved),
    };
    state.db.upsert_collection_config(&input).await?;
    state
        .invalidate_collection_cache(&input.chain, &collection)
        .await;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

#[derive(Debug, Deserialize)]
struct CanvasRefreshRequest {
    token_id: String,
    asset_id: String,
}

async fn refresh_canvas(
    State(state): State<Arc<AppState>>,
    Path((chain, collection)): Path<(String, String)>,
    Json(payload): Json<CanvasRefreshRequest>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let (chain, collection) = canonicalize_chain_collection(&state, &chain, &collection)?;
    let cache_chain = chain.clone();
    let cache_collection = collection.clone();
    let (width, height) = refresh_canvas_size(
        state.clone(),
        chain,
        collection,
        payload.token_id,
        payload.asset_id,
    )
    .await?;
    state
        .invalidate_collection_cache(&cache_chain, &cache_collection)
        .await;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "canvas_width": width,
        "canvas_height": height
    })))
}

#[derive(Debug, Deserialize)]
struct CacheEpochRequest {
    epoch: Option<i64>,
}

async fn update_cache_epoch(
    State(state): State<Arc<AppState>>,
    Path((chain, collection)): Path<(String, String)>,
    Json(payload): Json<CacheEpochRequest>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let (chain, collection) = canonicalize_chain_collection(&state, &chain, &collection)?;
    let max_epoch = 9_999_999_999_999i64;
    let epoch = match payload.epoch {
        Some(value) => {
            if value < 0 || value > max_epoch {
                return Err(AdminError::bad_request("epoch must be 0..=9999999999999"));
            }
            state
                .db
                .set_collection_cache_epoch(&chain, &collection, value)
                .await?;
            value
        }
        None => {
            let current = state
                .db
                .get_collection_cache_epoch(&chain, &collection)
                .await?
                .unwrap_or(0);
            let next = current.saturating_add(1).min(max_epoch);
            state
                .db
                .set_collection_cache_epoch(&chain, &collection, next)
                .await?;
            next
        }
    };
    state.clear_primary_asset_cache().await;
    state.invalidate_collection_cache(&chain, &collection).await;
    Ok(Json(serde_json::json!({ "status": "ok", "epoch": epoch })))
}

async fn start_warmup(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<WarmupRequest>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let (chain, collection) =
        canonicalize_chain_collection(&state, &payload.chain, &payload.collection)?;
    let request = WarmupRequest {
        chain,
        collection,
        token_ids: payload.token_ids,
        asset_id: payload.asset_id,
        cache_timestamp: payload.cache_timestamp,
        widths: payload.widths,
        include_og: payload.include_og,
        strategy: payload.strategy,
        from_block: payload.from_block,
        to_block: payload.to_block,
        range_start: payload.range_start,
        range_end: payload.range_end,
        allow_sequential: payload.allow_sequential,
    };
    let count = enqueue_warmup(state.clone(), request).await?;
    Ok(Json(serde_json::json!({ "status": "ok", "jobs": count })))
}

async fn warmup_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let (queued, running, done, failed) = state.db.warmup_stats().await?;
    let paused = state.db.is_warmup_paused().await?;
    Ok(Json(serde_json::json!({
        "queued": queued,
        "running": running,
        "done": done,
        "failed": failed,
        "paused": paused
    })))
}

#[derive(Debug, Deserialize)]
struct WarmupJobsQuery {
    limit: Option<i64>,
}

async fn list_warmup_jobs(
    State(state): State<Arc<AppState>>,
    Query(query): Query<WarmupJobsQuery>,
) -> Result<Json<Vec<WarmupJob>>, AdminError> {
    let limit = query.limit.unwrap_or(100);
    let jobs = state.db.list_warmup_jobs(limit).await?;
    Ok(Json(jobs))
}

async fn cancel_warmup_job(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let canceled = state.db.cancel_warmup_job(id).await?;
    Ok(Json(
        serde_json::json!({ "status": "ok", "canceled": canceled }),
    ))
}

async fn pause_warmup(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AdminError> {
    state.db.set_warmup_paused(true).await?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

async fn resume_warmup(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AdminError> {
    state.db.set_warmup_paused(false).await?;
    state.warmup_notify.notify_one();
    state.catalog_warmup_notify.notify_one();
    state.token_warmup_notify.notify_one();
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

#[derive(Debug, Serialize)]
struct CatalogWarmupStatus {
    job_id: Option<i64>,
    status: String,
    last_error: Option<String>,
    catalog_address: Option<String>,
    parts_total: i64,
    parts_queued: i64,
    parts_running: i64,
    parts_done: i64,
    parts_failed: i64,
    assets_total: i64,
    assets_pinned: i64,
    assets_failed: i64,
    token_job_id: Option<i64>,
    token_status: String,
    token_last_error: Option<String>,
    tokens_total: i64,
    tokens_queued: i64,
    tokens_running: i64,
    tokens_done: i64,
    tokens_failed: i64,
    token_assets_total: i64,
    token_assets_pinned: i64,
    token_assets_failed: i64,
}

#[derive(Debug, Deserialize)]
struct CatalogWarmupStatusQuery {
    chain: String,
    collection: String,
}

async fn start_catalog_warmup(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CatalogWarmupRequest>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let (chain, collection) =
        canonicalize_chain_collection(&state, &payload.chain, &payload.collection)?;
    let request = CatalogWarmupRequest {
        chain,
        collection,
        catalog_address: payload.catalog_address,
        token_id: payload.token_id,
        asset_id: payload.asset_id,
        from_block: payload.from_block,
        to_block: payload.to_block,
        force: payload.force,
    };
    let result = enqueue_catalog_warmup(state.clone(), request).await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "job_id": result.job_id,
        "parts_total": result.parts_total
    })))
}

#[derive(Debug, Deserialize)]
struct TokenWarmupRangeRequest {
    chain: String,
    collection: String,
    start_token: u64,
    end_token: u64,
    step: Option<u64>,
    asset_id: Option<String>,
    force: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct TokenWarmupManualRequest {
    chain: String,
    collection: String,
    token_ids: Vec<String>,
    asset_id: Option<String>,
    force: Option<bool>,
}

async fn start_token_warmup_range(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TokenWarmupRangeRequest>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let (chain, collection) =
        canonicalize_chain_collection(&state, &payload.chain, &payload.collection)?;
    let request = TokenWarmupRequest {
        chain,
        collection,
        start_token: Some(payload.start_token),
        end_token: Some(payload.end_token),
        step: payload.step,
        token_ids: None,
        asset_id: payload.asset_id,
        force: payload.force,
    };
    let result = enqueue_token_warmup(state.clone(), request).await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "job_id": result.job_id,
        "tokens_total": result.tokens_total
    })))
}

async fn start_token_warmup_manual(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TokenWarmupManualRequest>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let (chain, collection) =
        canonicalize_chain_collection(&state, &payload.chain, &payload.collection)?;
    let request = TokenWarmupRequest {
        chain,
        collection,
        start_token: None,
        end_token: None,
        step: None,
        token_ids: Some(payload.token_ids),
        asset_id: payload.asset_id,
        force: payload.force,
    };
    let result = enqueue_token_warmup(state.clone(), request).await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "job_id": result.job_id,
        "tokens_total": result.tokens_total
    })))
}

async fn catalog_warmup_status(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CatalogWarmupStatusQuery>,
) -> Result<Json<CatalogWarmupStatus>, AdminError> {
    let (chain, collection) =
        canonicalize_chain_collection(&state, &query.chain, &query.collection)?;
    let job = state.db.get_catalog_warmup_job(&chain, &collection).await?;
    let (job_id, catalog_address, status, last_error) = match job {
        Some((job_id, catalog_address, status, last_error)) => {
            (Some(job_id), Some(catalog_address), status, last_error)
        }
        None => (None, None, "idle".to_string(), None),
    };
    let (parts_queued, parts_running, parts_done, parts_failed, parts_total) = match job_id {
        Some(job_id) => state.db.catalog_warmup_item_counts(job_id).await?,
        None => (0, 0, 0, 0, 0),
    };
    let (assets_total, assets_pinned, assets_failed) =
        state.db.catalog_asset_counts(&chain, &collection).await?;
    let token_job = state.db.get_token_warmup_job(&chain, &collection).await?;
    let (token_job_id, token_status, token_last_error) = match token_job {
        Some((job_id, _asset_id, status, last_error)) => (Some(job_id), status, last_error),
        None => (None, "idle".to_string(), None),
    };
    let (tokens_queued, tokens_running, tokens_done, tokens_failed, tokens_total) =
        match token_job_id {
            Some(job_id) => state.db.token_warmup_item_counts(job_id).await?,
            None => (0, 0, 0, 0, 0),
        };
    let (token_assets_total, token_assets_pinned, token_assets_failed) =
        state.db.token_asset_counts(&chain, &collection).await?;
    Ok(Json(CatalogWarmupStatus {
        job_id,
        status,
        last_error,
        catalog_address,
        parts_total,
        parts_queued,
        parts_running,
        parts_done,
        parts_failed,
        assets_total,
        assets_pinned,
        assets_failed,
        token_job_id,
        token_status,
        token_last_error,
        tokens_total,
        tokens_queued,
        tokens_running,
        tokens_done,
        tokens_failed,
        token_assets_total,
        token_assets_pinned,
        token_assets_failed,
    }))
}

#[derive(Debug, Deserialize)]
struct CachePurgeRequest {
    chain: Option<String>,
    collection: Option<String>,
    include_assets: Option<bool>,
}

async fn purge_cache(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CachePurgeRequest>,
) -> Result<Json<serde_json::Value>, AdminError> {
    if let (Some(chain), Some(collection)) = (payload.chain, payload.collection) {
        let (chain, collection) = canonicalize_chain_collection(&state, &chain, &collection)?;
        let render_path = state.cache.renders_dir.join(chain).join(collection);
        state.cache.remove_dir_if_exists(&render_path).await?;
    } else if payload.include_assets.unwrap_or(false) {
        state
            .cache
            .remove_dir_if_exists(&state.cache.base_dir)
            .await?;
        state.cache.ensure_dirs().await?;
    } else {
        state
            .cache
            .remove_dir_if_exists(&state.cache.renders_dir)
            .await?;
    }
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

async fn cache_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let (render_bytes, asset_bytes) = state.cache.cached_sizes().await?;
    Ok(Json(serde_json::json!({
        "render_bytes": render_bytes,
        "asset_bytes": asset_bytes,
        "total_bytes": render_bytes + asset_bytes
    })))
}

async fn pinned_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<PinnedAssetCounts>, AdminError> {
    let stats = state.db.pinned_asset_counts().await?;
    Ok(Json(stats))
}

async fn list_hash_replacements(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<HashReplacement>>, AdminError> {
    let replacements = state.db.list_hash_replacements().await?;
    Ok(Json(replacements))
}

async fn upload_hash_replacement(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, AdminError> {
    let mut cid_input: Option<String> = None;
    let mut content_type: Option<String> = None;
    let mut bytes: Option<bytes::Bytes> = None;
    while let Some(field) = multipart.next_field().await.map_err(|err| anyhow!(err))? {
        let name = field.name().unwrap_or_default().to_string();
        if name == "cid" {
            cid_input = Some(field.text().await.map_err(|err| anyhow!(err))?);
        } else if name == "file" {
            content_type = field.content_type().map(|value| value.to_string());
            bytes = Some(field.bytes().await.map_err(|err| anyhow!(err))?);
        }
    }
    let cid_raw = cid_input.ok_or_else(|| anyhow!("missing cid"))?;
    let cid = normalize_hash_replacement_cid(&cid_raw)?;
    let bytes = bytes.ok_or_else(|| anyhow!("missing file"))?;
    if bytes.is_empty() {
        return Err(anyhow!("empty replacement file").into());
    }
    let content_type = content_type.unwrap_or_else(|| "application/octet-stream".to_string());
    let replacement_dir = state.config.pinned_dir.join("hash-replacements");
    tokio::fs::create_dir_all(&replacement_dir)
        .await
        .context("create hash replacement dir")?;
    let file_path = replacement_dir.join(&cid);
    tokio::fs::write(&file_path, &bytes)
        .await
        .context("write hash replacement file")?;
    let file_path = file_path.to_string_lossy().to_string();
    state
        .db
        .upsert_hash_replacement(&cid, &content_type, &file_path)
        .await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "cid": cid,
        "content_type": content_type,
        "file_path": file_path
    })))
}

async fn delete_hash_replacement(
    State(state): State<Arc<AppState>>,
    Path(cid): Path<String>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let cid = normalize_hash_replacement_cid(&cid)?;
    let removed = state.db.delete_hash_replacement(&cid).await?;
    if let Some(replacement) = removed.as_ref() {
        if let Err(err) = tokio::fs::remove_file(&replacement.file_path).await {
            warn!(
                error = ?err,
                path = %replacement.file_path,
                "failed to remove hash replacement file"
            );
        }
    }
    Ok(Json(serde_json::json!({
        "status": "ok",
        "removed": removed.is_some()
    })))
}

async fn list_rpc(
    State(state): State<Arc<AppState>>,
    Path(chain): Path<String>,
) -> Result<Json<Vec<RpcEndpoint>>, AdminError> {
    let chain = canonicalize_chain(&state, &chain)?;
    let endpoints = state.db.list_rpc_endpoints(Some(&chain)).await?;
    Ok(Json(endpoints))
}

#[derive(Debug, Serialize)]
struct RpcHealthResponse {
    url: String,
    ok: bool,
    block_number: Option<u64>,
    latency_ms: Option<u128>,
    error: Option<String>,
}

async fn rpc_health(
    State(state): State<Arc<AppState>>,
    Path(chain): Path<String>,
) -> Result<Json<Vec<RpcHealthResponse>>, AdminError> {
    let chain = canonicalize_chain(&state, &chain)?;
    let endpoints = state.db.list_rpc_endpoints(Some(&chain)).await?;
    let mut results = Vec::new();
    for endpoint in endpoints {
        if !endpoint.enabled {
            results.push(RpcHealthResponse {
                url: endpoint.url,
                ok: false,
                block_number: None,
                latency_ms: None,
                error: Some("disabled".to_string()),
            });
            continue;
        }
        let url = endpoint.url.clone();
        let started = std::time::Instant::now();
        match state.chain.provider_for_url(url.as_str()) {
            Ok(provider) => match provider.get_block_number().await {
                Ok(block) => results.push(RpcHealthResponse {
                    url,
                    ok: true,
                    block_number: Some(block.as_u64()),
                    latency_ms: Some(started.elapsed().as_millis()),
                    error: None,
                }),
                Err(err) => results.push(RpcHealthResponse {
                    url,
                    ok: false,
                    block_number: None,
                    latency_ms: Some(started.elapsed().as_millis()),
                    error: Some(err.to_string()),
                }),
            },
            Err(err) => results.push(RpcHealthResponse {
                url,
                ok: false,
                block_number: None,
                latency_ms: None,
                error: Some(err.to_string()),
            }),
        }
    }
    Ok(Json(results))
}

#[derive(Debug, Deserialize)]
struct ClientCreateRequest {
    name: String,
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClientUpdateRequest {
    name: String,
    notes: Option<String>,
}

async fn list_clients(State(state): State<Arc<AppState>>) -> Result<Json<Vec<Client>>, AdminError> {
    let clients = state.db.list_clients().await?;
    Ok(Json(clients))
}

async fn create_client(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ClientCreateRequest>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let id = state
        .db
        .create_client(&payload.name, payload.notes.as_deref())
        .await?;
    Ok(Json(serde_json::json!({ "status": "ok", "id": id })))
}

async fn update_client(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(payload): Json<ClientUpdateRequest>,
) -> Result<Json<serde_json::Value>, AdminError> {
    state
        .db
        .update_client(id, &payload.name, payload.notes.as_deref())
        .await?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

async fn delete_client(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AdminError> {
    state.db.delete_client(id).await?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

#[derive(Debug, Deserialize)]
struct ClientKeyCreateRequest {
    rate_limit_per_minute: Option<i64>,
    burst: Option<i64>,
    max_concurrent_renders_override: Option<i64>,
    allow_fresh: Option<bool>,
}

async fn list_client_keys(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<Vec<ClientKey>>, AdminError> {
    let keys = state.db.list_client_keys(id).await?;
    Ok(Json(keys))
}

async fn create_client_key(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(payload): Json<ClientKeyCreateRequest>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let secret = state
        .config
        .api_key_secret
        .as_deref()
        .ok_or_else(|| AdminError::bad_request("API_KEY_SECRET is not configured"))?;
    let api_key = generate_api_key();
    let key_hash = hash_api_key(secret, &api_key);
    let key_prefix = api_key.chars().take(8).collect::<String>();
    let key_id = state
        .db
        .create_client_key(
            id,
            &key_hash,
            &key_prefix,
            payload.rate_limit_per_minute,
            payload.burst,
            payload.max_concurrent_renders_override,
            payload.allow_fresh.unwrap_or(false),
        )
        .await?;
    Ok(Json(serde_json::json!({
        "status": "ok",
        "key_id": key_id,
        "api_key": api_key,
        "key_prefix": key_prefix
    })))
}

async fn revoke_client_key(
    State(state): State<Arc<AppState>>,
    Path(key_id): Path<i64>,
) -> Result<Json<serde_json::Value>, AdminError> {
    state.db.revoke_client_key(key_id).await?;
    state.clear_api_key_cache().await;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

#[derive(Debug, Deserialize)]
struct IpRuleCreateRequest {
    ip_cidr: String,
    mode: String,
}

async fn list_ip_rules(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<IpRule>>, AdminError> {
    let rules = state.db.list_ip_rules().await?;
    Ok(Json(rules))
}

async fn create_ip_rule(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<IpRuleCreateRequest>,
) -> Result<Json<serde_json::Value>, AdminError> {
    if payload.mode != "allow" && payload.mode != "deny" {
        return Err(AdminError::bad_request("mode must be allow or deny"));
    }
    let id = state
        .db
        .create_ip_rule(&payload.ip_cidr, &payload.mode)
        .await?;
    state.refresh_ip_rules().await?;
    Ok(Json(serde_json::json!({ "status": "ok", "id": id })))
}

async fn delete_ip_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AdminError> {
    state.db.delete_ip_rule(id).await?;
    state.refresh_ip_rules().await?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

#[derive(Debug, Deserialize)]
struct UsageQuery {
    hours: Option<i64>,
}

async fn list_usage(
    State(state): State<Arc<AppState>>,
    Query(query): Query<UsageQuery>,
) -> Result<Json<Vec<UsageRow>>, AdminError> {
    let hours = query.hours.unwrap_or(24).clamp(1, 168);
    let usage = state.db.list_usage(hours).await?;
    Ok(Json(usage))
}

async fn replace_rpc(
    State(state): State<Arc<AppState>>,
    Path(chain): Path<String>,
    Json(payload): Json<Vec<RpcEndpoint>>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let chain = canonicalize_chain(&state, &chain)?;
    let endpoints = payload
        .into_iter()
        .map(|mut endpoint| {
            endpoint.chain = chain.clone();
            endpoint
        })
        .collect();
    state.db.replace_rpc_endpoints(&chain, endpoints).await?;
    state.chain.refresh_rpc_endpoints(&chain).await?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

#[derive(Debug, Serialize)]
struct SettingsResponse {
    require_approval: bool,
    require_approval_override: Option<bool>,
}

async fn get_settings(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SettingsResponse>, AdminError> {
    let override_value = state.db.get_setting_bool("require_approval").await?;
    let effective = override_value.unwrap_or(state.config.require_approval);
    Ok(Json(SettingsResponse {
        require_approval: effective,
        require_approval_override: override_value,
    }))
}

#[derive(Debug, Deserialize)]
struct RequireApprovalRequest {
    require_approval: Option<bool>,
}

async fn set_require_approval(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RequireApprovalRequest>,
) -> Result<Json<serde_json::Value>, AdminError> {
    match payload.require_approval {
        Some(value) => {
            state
                .db
                .set_setting(
                    "require_approval",
                    Some(if value { "true" } else { "false" }),
                )
                .await?
        }
        None => state.db.set_setting("require_approval", None).await?,
    }
    state.clear_require_approval_cache().await;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

async fn require_admin(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if is_authorized(&state.config, request.headers()) {
        return next.run(request).await;
    }
    if let Some(ip) = client_ip(&request, &state) {
        let info = state.auth_fail_limiter.check(ip).await;
        if !info.allowed {
            return rate_limit_response(info);
        }
    }
    let mut response = Response::new("Unauthorized".into());
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"renderer\""),
    );
    response
}

fn rate_limit_response(info: RateLimitInfo) -> Response {
    let mut response = Response::new("Too many requests".into());
    *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    let retry_after = info.reset_seconds.max(60);
    response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&retry_after.to_string()).unwrap_or(HeaderValue::from_static("60")),
    );
    let _ = response.headers_mut().insert(
        "X-RateLimit-Limit",
        HeaderValue::from_str(&info.limit.to_string()).unwrap_or(HeaderValue::from_static("0")),
    );
    let _ = response.headers_mut().insert(
        "X-RateLimit-Remaining",
        HeaderValue::from_str(&info.remaining.to_string()).unwrap_or(HeaderValue::from_static("0")),
    );
    let _ = response.headers_mut().insert(
        "X-RateLimit-Reset",
        HeaderValue::from_str(&info.reset_seconds.to_string())
            .unwrap_or(HeaderValue::from_static("0")),
    );
    response
}

fn is_authorized(config: &Config, headers: &HeaderMap) -> bool {
    let password = config.admin_password.as_str();
    let auth = match headers.get(header::AUTHORIZATION) {
        Some(value) => value.to_str().unwrap_or(""),
        None => return false,
    };
    let mut parts = auth.split_whitespace();
    let scheme = match parts.next() {
        Some(value) => value,
        None => return false,
    };
    let token = match parts.next() {
        Some(value) => value,
        None => return false,
    };
    if scheme.eq_ignore_ascii_case("bearer") {
        return bool::from(password.as_bytes().ct_eq(token.as_bytes()));
    }
    false
}

#[derive(Debug)]
pub struct AdminError {
    status: StatusCode,
    message: String,
}

fn canonicalize_chain_collection(
    state: &AppState,
    chain: &str,
    collection: &str,
) -> Result<(String, String), AdminError> {
    canonical::canonicalize_collection(chain, collection, &state.config)
        .map_err(|err| AdminError::bad_request(&err.to_string()))
}

fn canonicalize_chain(state: &AppState, chain: &str) -> Result<String, AdminError> {
    canonical::canonicalize_chain(chain, &state.config)
        .map_err(|err| AdminError::bad_request(&err.to_string()))
}

fn normalize_hash_replacement_cid(input: &str) -> Result<String, AdminError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(AdminError::bad_request("cid is required"));
    }
    let mut value = trimmed;
    if let Some(stripped) = value.strip_prefix("ipfs://") {
        value = stripped;
    }
    if let Some(stripped) = value.strip_prefix("ipfs/") {
        value = stripped;
    }
    if let Some(stripped) = value.strip_prefix("/ipfs/") {
        value = stripped;
    }
    let cid = value.split('/').next().unwrap_or_default().trim();
    if cid.is_empty() || !cid.chars().all(|ch| ch.is_ascii_alphanumeric()) {
        return Err(AdminError::bad_request("invalid ipfs cid"));
    }
    Ok(cid.to_string())
}

fn generate_api_key() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn hash_api_key(secret: &str, token: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac can take key of any size");
    mac.update(token.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

impl AdminError {
    pub fn bad_request(message: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.to_string(),
        }
    }
}

impl From<anyhow::Error> for AdminError {
    fn from(error: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

const ADMIN_CSS: &str = include_str!("admin.css");
const ADMIN_JS: &str = include_str!("admin.js");
const ADMIN_HTML: &str = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8"/>
    <title>RMRK Renderer Admin</title>
    <link rel="stylesheet" href="/admin/static/admin.css" />
  </head>
  <body>
    <h1>RMRK Renderer Admin</h1>
    <p>Authenticate with <code>Authorization: Bearer &lt;ADMIN_PASSWORD&gt;</code>. This page does not persist your password.</p>

    <fieldset>
      <legend>Authentication</legend>
      <label for="authToken">Admin password</label>
      <input id="authToken" type="password" placeholder="ADMIN_PASSWORD" />
      <button id="saveTokenBtn">Save Token</button>
      <span class="small" id="authStatus"></span>
    </fieldset>

    <fieldset>
      <legend>Settings</legend>
      <label>Require approval (self-hosted toggle)</label>
      <select id="requireApproval">
        <option value="inherit">Use environment default</option>
        <option value="true">Require approval</option>
        <option value="false">No approval required</option>
      </select>
      <button id="updateRequireApprovalBtn">Update Setting</button>
      <div class="small" id="settingsStatus"></div>
    </fieldset>

    <fieldset>
      <legend>Collections</legend>
      <div class="row">
        <div>
          <label>Chain</label>
          <input id="colChain" placeholder="base" />
        </div>
        <div>
          <label>Collection address</label>
          <input id="colAddress" placeholder="0x..." />
        </div>
      </div>
      <div class="row">
        <div>
          <label>OG focal point (%)</label>
          <input id="colOgFocal" placeholder="25" />
        </div>
        <div>
          <label>Warmup strategy</label>
          <input id="colWarmupStrategy" placeholder="auto" />
        </div>
      </div>
      <label>OG overlay URI</label>
      <input id="colOgOverlay" placeholder="ipfs://..." />
      <label>Watermark overlay URI</label>
      <input id="colWatermark" placeholder="ipfs://..." />
      <label>Approved</label>
      <select id="colApproved">
        <option value="true">Approved</option>
        <option value="false">Not approved</option>
      </select>
      <button id="saveCollectionBtn">Save Collection</button>

      <h3>Existing collections</h3>
      <table>
        <thead>
          <tr>
            <th>Chain</th>
            <th>Collection</th>
            <th>Canvas</th>
            <th>Cache epoch</th>
            <th>Approved</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="collectionsTable"></tbody>
      </table>
    </fieldset>

    <fieldset>
      <legend>Collection Cache Epoch</legend>
      <div class="row">
        <div>
          <label>Chain</label>
          <input id="epochChain" placeholder="base" />
        </div>
        <div>
          <label>Collection</label>
          <input id="epochCollection" placeholder="0x..." />
        </div>
      </div>
      <label>Epoch (optional)</label>
      <input id="epochValue" placeholder="1700000000000" />
      <button id="updateCacheEpochBtn">Update Epoch</button>
      <div class="small" id="epochStatus"></div>
    </fieldset>

    <fieldset>
      <legend>Refresh Canvas Size</legend>
      <div class="row">
        <div>
          <label>Chain</label>
          <input id="refreshChain" placeholder="base" />
        </div>
        <div>
          <label>Collection</label>
          <input id="refreshCollection" placeholder="0x..." />
        </div>
      </div>
      <div class="row">
        <div>
          <label>Token ID</label>
          <input id="refreshToken" placeholder="1" />
        </div>
        <div>
          <label>Asset ID</label>
          <input id="refreshAsset" placeholder="100" />
        </div>
      </div>
      <button id="refreshCanvasBtn">Refresh Canvas</button>
      <div class="small" id="refreshStatus"></div>
    </fieldset>

    <fieldset>
      <legend>Render Warmup (Phase C, optional)</legend>
      <div class="small">Warning: large warmups can be expensive. Jobs are capped by server config and assume Phase A+B are complete.</div>
      <div class="row">
        <div>
          <label>Chain</label>
          <input id="warmChain" placeholder="base" />
        </div>
        <div>
          <label>Collection</label>
          <input id="warmCollection" placeholder="0x..." />
        </div>
      </div>
      <label>Token IDs (comma separated)</label>
      <input id="warmTokens" placeholder="1,2,3" />
      <div class="row">
        <div>
          <label>Asset ID (optional)</label>
          <input id="warmAsset" placeholder="100" />
        </div>
        <div>
          <label>Cache timestamp (ms)</label>
          <input id="warmCache" placeholder="1700000000000" />
        </div>
      </div>
      <div class="row">
        <div>
          <label>Widths (comma separated)</label>
          <input id="warmWidths" placeholder="medium,large" />
        </div>
        <div>
          <label>Include OG</label>
          <select id="warmOg">
            <option value="true">true</option>
            <option value="false">false</option>
          </select>
        </div>
      </div>
      <div class="row">
        <div>
          <label>Strategy</label>
          <select id="warmStrategy">
            <option value="auto">auto</option>
            <option value="list">list</option>
            <option value="erc721_enumerable">erc721_enumerable</option>
            <option value="transfer_log">transfer_log</option>
            <option value="sequential">sequential</option>
          </select>
        </div>
        <div>
          <label>Allow sequential</label>
          <select id="warmSequential">
            <option value="false">false</option>
            <option value="true">true</option>
          </select>
        </div>
      </div>
      <div class="row">
        <div>
          <label>From block</label>
          <input id="warmFromBlock" placeholder="0" />
        </div>
        <div>
          <label>To block</label>
          <input id="warmToBlock" placeholder="latest" />
        </div>
      </div>
      <div class="row">
        <div>
          <label>Range start</label>
          <input id="warmRangeStart" placeholder="1" />
        </div>
        <div>
          <label>Range end</label>
          <input id="warmRangeEnd" placeholder="100" />
        </div>
      </div>
      <button id="startWarmupBtn">Start Warmup</button>
      <button id="pauseWarmupBtn">Pause Warmup</button>
      <button id="resumeWarmupBtn">Resume Warmup</button>
      <button id="loadWarmupStatsBtn">Refresh Stats</button>
      <div class="small" id="warmupStatus"></div>
    </fieldset>

    <fieldset>
      <legend>Catalog Warmup</legend>
      <div class="small">Pins catalog part metadata and part assets.</div>
      <div class="row">
        <div>
          <label>Chain</label>
          <input id="catalogWarmChain" placeholder="base" />
        </div>
        <div>
          <label>Collection</label>
          <input id="catalogWarmCollection" placeholder="0x..." />
        </div>
      </div>
      <div class="row">
        <div>
          <label>Catalog address (optional)</label>
          <input id="catalogWarmAddress" placeholder="0x..." />
        </div>
        <div>
          <label>Token ID (fallback)</label>
          <input id="catalogWarmToken" placeholder="1" />
        </div>
        <div>
          <label>Asset ID (fallback)</label>
          <input id="catalogWarmAsset" placeholder="100" />
        </div>
      </div>
      <div class="row">
        <div>
          <label>From block</label>
          <input id="catalogWarmFromBlock" placeholder="0" />
        </div>
        <div>
          <label>To block</label>
          <input id="catalogWarmToBlock" placeholder="latest" />
        </div>
        <div>
          <label>Force</label>
          <select id="catalogWarmForce">
            <option value="false">false</option>
            <option value="true">true</option>
          </select>
        </div>
      </div>
      <button id="startCatalogWarmupBtn">Warm Catalog</button>
      <button id="loadCatalogWarmupBtn">Refresh Catalog Status</button>
      <div class="small" id="catalogWarmupStatus"></div>
    </fieldset>

    <fieldset>
      <legend>Token Warmup</legend>
      <div class="small">Scans tokens to pin token-specific assets.</div>
      <div class="row">
        <div>
          <label>Chain</label>
          <input id="tokenWarmChain" placeholder="base" />
        </div>
        <div>
          <label>Collection</label>
          <input id="tokenWarmCollection" placeholder="0x..." />
        </div>
      </div>
      <div class="row">
        <div>
          <label>Start token</label>
          <input id="tokenWarmStart" placeholder="1" />
        </div>
        <div>
          <label>End token</label>
          <input id="tokenWarmEnd" placeholder="1000" />
        </div>
        <div>
          <label>Step</label>
          <input id="tokenWarmStep" placeholder="1" />
        </div>
      </div>
      <div class="row">
        <div>
          <label>Asset ID (optional)</label>
          <input id="tokenWarmAsset" placeholder="100" />
        </div>
        <div>
          <label>Force</label>
          <select id="tokenWarmForce">
            <option value="false">false</option>
            <option value="true">true</option>
          </select>
        </div>
      </div>
      <label>Token IDs (comma separated)</label>
      <input id="tokenWarmTokens" placeholder="1,2,3" />
      <button id="startTokenWarmRangeBtn">Warm Token Range</button>
      <button id="startTokenWarmManualBtn">Warm Token IDs</button>
      <button id="loadTokenWarmupBtn">Refresh Token Status</button>
      <div class="small" id="tokenWarmupStatus"></div>
    </fieldset>

    <fieldset>
      <legend>Warmup Jobs</legend>
      <button id="loadWarmupJobsBtn">Load Jobs</button>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Chain</th>
            <th>Collection</th>
            <th>Token</th>
            <th>Status</th>
            <th>Last error</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="warmupJobsTable"></tbody>
      </table>
    </fieldset>

    <fieldset>
      <legend>Cache</legend>
      <button id="loadCacheStatsBtn">Refresh Cache Stats</button>
      <div class="small" id="cacheStats"></div>
      <div class="row">
        <div>
          <label>Chain</label>
          <input id="purgeChain" placeholder="base" />
        </div>
        <div>
          <label>Collection</label>
          <input id="purgeCollection" placeholder="0x..." />
        </div>
      </div>
      <button id="purgeCollectionBtn">Purge Collection Renders</button>
      <button id="purgeRendersBtn">Purge All Renders</button>
      <button id="purgeAllBtn">Purge All (including assets)</button>
    </fieldset>

    <fieldset>
      <legend>Hash Replacements</legend>
      <div class="small">Upload a static image to serve in place of a missing IPFS CID.</div>
      <div class="row">
        <div>
          <label>CID</label>
          <input id="hashReplacementCid" placeholder="Qm..." />
        </div>
        <div>
          <label>File</label>
          <input id="hashReplacementFile" type="file" accept="image/*" />
        </div>
      </div>
      <button id="uploadHashReplacementBtn">Upload Replacement</button>
      <button id="loadHashReplacementsBtn">Refresh</button>
      <div class="small" id="hashReplacementStatus"></div>
      <table>
        <thead>
          <tr>
            <th>CID</th>
            <th>Content type</th>
            <th>File path</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="hashReplacementTable"></tbody>
      </table>
    </fieldset>

    <fieldset>
      <legend>RPC Endpoints</legend>
      <label>Chain</label>
      <input id="rpcChain" placeholder="base" />
      <button id="loadRpcBtn">Load RPC Endpoints</button>
      <button id="loadRpcHealthBtn">Check RPC Health</button>
      <textarea id="rpcJson" rows="6" placeholder='[{"url":"https://...","priority":0,"enabled":true}]'></textarea>
      <button id="saveRpcBtn">Save RPC Endpoints</button>
      <div class="small" id="rpcStatus"></div>
      <table>
        <thead>
          <tr>
            <th>URL</th>
            <th>OK</th>
            <th>Block</th>
            <th>Latency (ms)</th>
            <th>Error</th>
          </tr>
        </thead>
        <tbody id="rpcHealthTable"></tbody>
      </table>
    </fieldset>

    <fieldset>
      <legend>Clients</legend>
      <div class="row">
        <div>
          <label>Name</label>
          <input id="clientName" placeholder="Marketplace XYZ" />
        </div>
        <div>
          <label>Notes</label>
          <input id="clientNotes" placeholder="optional" />
        </div>
      </div>
      <button id="createClientBtn">Create Client</button>
      <div class="small" id="clientStatus"></div>
      <h3>Existing clients</h3>
      <button id="loadClientsBtn">Refresh Clients</button>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Notes</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="clientsTable"></tbody>
      </table>
    </fieldset>

    <fieldset>
      <legend>Client Keys</legend>
      <div class="row">
        <div>
          <label>Client ID</label>
          <input id="clientKeyClientId" placeholder="1" />
        </div>
        <div>
          <label>Rate limit per minute (optional)</label>
          <input id="clientKeyRate" placeholder="0" />
        </div>
      </div>
      <div class="row">
        <div>
          <label>Burst (optional)</label>
          <input id="clientKeyBurst" placeholder="0" />
        </div>
        <div>
          <label>Max concurrent renders override (optional)</label>
          <input id="clientKeyConcurrent" placeholder="0" />
        </div>
        <div>
          <label>Allow fresh bypass</label>
          <select id="clientKeyAllowFresh">
            <option value="false">false</option>
            <option value="true">true</option>
          </select>
        </div>
      </div>
      <button id="createClientKeyBtn">Create Key</button>
      <button id="loadClientKeysBtn">Load Keys</button>
      <div class="small" id="clientKeyStatus"></div>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Prefix</th>
            <th>Active</th>
            <th>Rate/min</th>
            <th>Burst</th>
            <th>Fresh</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="clientKeysTable"></tbody>
      </table>
    </fieldset>

    <fieldset>
      <legend>IP Rules</legend>
      <div class="small">Rule evaluation: longest prefix wins; deny beats allow on ties.</div>
      <div class="row">
        <div>
          <label>IP/CIDR</label>
          <input id="ipRuleCidr" placeholder="203.0.113.10/32" />
        </div>
        <div>
          <label>Mode</label>
          <select id="ipRuleMode">
            <option value="allow">allow</option>
            <option value="deny">deny</option>
          </select>
        </div>
      </div>
      <button id="createIpRuleBtn">Add Rule</button>
      <button id="loadIpRulesBtn">Load Rules</button>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>IP/CIDR</th>
            <th>Mode</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="ipRulesTable"></tbody>
      </table>
    </fieldset>

    <fieldset>
      <legend>Usage</legend>
      <div class="row">
        <div>
          <label>Hours</label>
          <input id="usageHours" placeholder="24" />
        </div>
        <div>
          <label>&nbsp;</label>
          <button id="loadUsageBtn">Load Usage</button>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Hour bucket</th>
            <th>Identity</th>
            <th>Route</th>
            <th>Requests</th>
            <th>Bytes out</th>
            <th>Cache hits</th>
            <th>Cache misses</th>
          </tr>
        </thead>
        <tbody id="usageTable"></tbody>
      </table>
    </fieldset>

    <script src="/admin/static/admin.js"></script>
  </body>
</html>"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, RasterMismatchPolicy, RenderPolicy};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::time::Duration;

    fn base_config() -> Config {
        Config {
            host: "127.0.0.1".to_string(),
            port: 8080,
            admin_password: "secret".to_string(),
            db_path: PathBuf::from("renderer.db"),
            cache_dir: PathBuf::from("cache"),
            pinning_enabled: false,
            pinned_dir: PathBuf::from("pinned"),
            local_ipfs_enabled: false,
            local_ipfs_bind: "127.0.0.1".to_string(),
            local_ipfs_port: 18180,
            cache_max_size_bytes: 0,
            render_cache_min_ttl: Duration::from_secs(0),
            asset_cache_min_ttl: Duration::from_secs(0),
            cache_touch_interval: Duration::from_secs(0),
            cache_evict_interval: Duration::from_secs(0),
            max_concurrent_renders: 1,
            max_concurrent_ipfs_fetches: 1,
            max_concurrent_rpc_calls: 1,
            default_canvas_width: 1,
            default_canvas_height: 1,
            default_cache_timestamp: None,
            default_cache_ttl: Duration::from_secs(0),
            rpc_endpoints: HashMap::new(),
            render_utils_addresses: HashMap::new(),
            approval_contracts: HashMap::new(),
            approval_start_blocks: HashMap::new(),
            approval_poll_interval_seconds: 30,
            approval_confirmations: 0,
            chain_id_map: HashMap::new(),
            approval_sync_interval_seconds: 900,
            approval_negative_cache_seconds: 0,
            approval_negative_cache_capacity: 0,
            approval_enumeration_enabled: true,
            max_approval_staleness_seconds: 0,
            approvals_contract_chain: None,
            ipfs_gateways: Vec::new(),
            ipfs_timeout_seconds: 1,
            max_metadata_json_bytes: 1,
            max_svg_bytes: 1,
            max_svg_node_count: 1,
            max_raster_bytes: 1,
            max_raster_resize_bytes: 1,
            max_raster_resize_dim: 1,
            max_layers_per_render: 1,
            max_canvas_pixels: 1,
            max_total_raster_pixels: 1,
            max_cache_variants_per_key: 1,
            max_decoded_raster_pixels: 1,
            max_overlay_length: 1,
            max_background_length: 1,
            max_in_flight_requests: 1,
            max_admin_body_bytes: 1,
            rate_limit_per_minute: 0,
            rate_limit_burst: 0,
            auth_failure_rate_limit_per_minute: 0,
            auth_failure_rate_limit_burst: 0,
            access_mode: crate::config::AccessMode::Open,
            api_key_secret: None,
            key_rate_limit_per_minute: 0,
            key_rate_limit_burst: 0,
            api_key_cache_ttl: Duration::from_secs(0),
            api_key_cache_capacity: 0,
            track_keys_in_open_mode: false,
            trusted_proxies: Vec::new(),
            usage_tracking_enabled: true,
            usage_sample_rate: 1.0,
            usage_channel_capacity: 1,
            usage_flush_interval: Duration::from_secs(1),
            usage_flush_max_entries: 1,
            usage_retention_days: 30,
            render_queue_capacity: 1,
            render_layer_concurrency: 1,
            composite_cache_enabled: false,
            cache_size_refresh_interval: Duration::from_secs(1),
            rpc_timeout_seconds: 1,
            rpc_connect_timeout_seconds: 1,
            rpc_failure_threshold: 0,
            rpc_failure_cooldown_seconds: 0,
            failure_log_path: None,
            failure_log_max_bytes: 0,
            require_approval: false,
            allow_http: true,
            allow_private_networks: false,
            warmup_widths: Vec::new(),
            warmup_include_og: false,
            warmup_max_tokens: 0,
            warmup_max_renders_per_job: 0,
            warmup_job_timeout_seconds: 0,
            warmup_max_block_span: 0,
            warmup_max_concurrent_asset_pins: 1,
            token_state_check_ttl_seconds: 0,
            fresh_rate_limit_seconds: 0,
            primary_asset_cache_ttl: Duration::from_secs(0),
            primary_asset_negative_ttl: Duration::from_secs(0),
            primary_asset_cache_capacity: 0,
            outbound_client_cache_ttl: Duration::from_secs(0),
            outbound_client_cache_capacity: 0,
            openapi_public: true,
            render_policy: RenderPolicy {
                raster_mismatch_fixed: RasterMismatchPolicy::TopLeftNoScale,
                raster_mismatch_child: RasterMismatchPolicy::TopLeftNoScale,
            },
            collection_render_overrides: HashMap::new(),
            status_public: false,
            landing_public: false,
            landing: None,
        }
    }

    #[test]
    fn authorize_bearer() {
        let config = base_config();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret"),
        );
        assert!(is_authorized(&config, &headers));
    }

    #[test]
    fn reject_invalid_auth() {
        let config = base_config();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong"),
        );
        assert!(!is_authorized(&config, &headers));
    }
}
