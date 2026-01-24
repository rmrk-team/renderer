use crate::assets::AssetFetchError;
use crate::canonical;
use crate::chain::{ComposeResult, FixedPart};
use crate::db::TokenWarmupItem;
use crate::pinning::PinnedAssetLocation;
use crate::state::AppState;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

const NON_COMPOSABLE_ASSET_REVERT: &str = "0x7a062578";

#[derive(Debug, Deserialize)]
pub struct TokenWarmupRequest {
    pub chain: String,
    pub collection: String,
    pub start_token: Option<u64>,
    pub end_token: Option<u64>,
    pub step: Option<u64>,
    pub token_ids: Option<Vec<String>>,
    pub asset_id: Option<String>,
    pub force: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct TokenWarmupEnqueueResult {
    pub job_id: i64,
    pub tokens_total: usize,
}

pub async fn enqueue_token_warmup(
    state: Arc<AppState>,
    request: TokenWarmupRequest,
) -> Result<TokenWarmupEnqueueResult> {
    let (chain, collection) =
        canonical::canonicalize_collection(&request.chain, &request.collection, &state.config)?;
    let tokens = resolve_tokens(&state, &request)?;
    if tokens.is_empty() {
        return Err(anyhow!("no tokens provided for token warmup"));
    }
    if state.config.warmup_max_tokens > 0 && tokens.len() > state.config.warmup_max_tokens {
        return Err(anyhow!(
            "token list exceeds limit ({} > {})",
            tokens.len(),
            state.config.warmup_max_tokens
        ));
    }
    let job_id = state
        .db
        .upsert_token_warmup_job(
            &chain,
            &collection,
            request.asset_id.as_deref(),
            "queued",
            None,
        )
        .await?;
    if request.force.unwrap_or(false) {
        state.db.clear_token_warmup_items(job_id).await?;
        let _ = state
            .db
            .clear_token_asset_refs_for_tokens(&chain, &collection, &tokens)
            .await;
    }
    state.db.insert_token_warmup_items(job_id, &tokens).await?;
    state.token_warmup_notify.notify_one();
    Ok(TokenWarmupEnqueueResult {
        job_id,
        tokens_total: tokens.len(),
    })
}

pub async fn spawn_workers(state: Arc<AppState>) {
    let max_workers = state.config.warmup_max_concurrent_asset_pins;
    let worker_count = if max_workers == 0 { 1 } else { max_workers };
    for _ in 0..worker_count {
        let worker_state = state.clone();
        tokio::spawn(async move {
            run_worker(worker_state).await;
        });
    }
}

async fn run_worker(state: Arc<AppState>) {
    loop {
        if state.db.is_warmup_paused().await.unwrap_or(false) {
            state.token_warmup_notify.notified().await;
            continue;
        }
        let item = match state.db.fetch_next_token_warmup_item().await {
            Ok(Some(item)) => item,
            Ok(None) => {
                tokio::select! {
                    _ = state.token_warmup_notify.notified() => {},
                    _ = sleep(Duration::from_secs(5)) => {},
                }
                continue;
            }
            Err(err) => {
                warn!(error = ?err, "token warmup fetch failed");
                sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        let _ = state
            .db
            .set_token_warmup_job_status(item.job_id, "running", None)
            .await;
        let result = run_item(state.clone(), &item).await;
        if let Err(err) = result {
            if is_invalid_uri_error(&err) {
                warn!(
                    error = ?err,
                    chain = %item.chain,
                    collection = %item.collection_address,
                    token_id = %item.token_id,
                    "token warmup invalid uri, skipping"
                );
                let _ = state
                    .db
                    .update_token_warmup_item_status(item.id, "done", None)
                    .await;
                continue;
            }
            warn!(
                error = ?err,
                chain = %item.chain,
                collection = %item.collection_address,
                token_id = %item.token_id,
                "token warmup item failed"
            );
            let _ = state
                .db
                .update_token_warmup_item_status(item.id, "failed", Some(&err.to_string()))
                .await;
        } else {
            let _ = state
                .db
                .update_token_warmup_item_status(item.id, "done", None)
                .await;
        }
        let _ = finalize_job_if_ready(&state, item.job_id).await;
    }
}

async fn run_item(state: Arc<AppState>, item: &TokenWarmupItem) -> Result<()> {
    let asset_id = match item.asset_id.as_deref() {
        Some(value) => value.to_string(),
        None => {
            let _permit = state.rpc_semaphore.acquire().await?;
            state
                .chain
                .get_top_asset_id(&item.chain, &item.collection_address, &item.token_id)
                .await?
                .to_string()
        }
    };
    let compose = load_compose(&state, item, &asset_id).await?;
    let metadata_uris = collect_metadata_uris(&compose);
    let mut art_uris = HashSet::new();
    for metadata_uri in metadata_uris {
        let mut resolved_uris = scan_metadata_uri(&state, item, &metadata_uri).await?;
        art_uris.extend(resolved_uris.drain());
    }
    for art_uri in art_uris {
        let art_uri = art_uri.trim().to_string();
        if art_uri.is_empty() {
            warn!(
                chain = %item.chain,
                collection = %item.collection_address,
                token_id = %item.token_id,
                "empty asset uri, skipping"
            );
            continue;
        }
        let location = record_token_asset_ref(&state, item, &art_uri, "token_asset").await;
        if let Err(err) = state.assets.fetch_asset(&art_uri).await {
            if is_invalid_uri_error(&err) {
                warn!(
                    chain = %item.chain,
                    collection = %item.collection_address,
                    token_id = %item.token_id,
                    art_uri = %art_uri,
                    "invalid asset uri, skipping"
                );
                continue;
            }
            let wrapped = anyhow!("asset fetch failed for {art_uri}: {err}");
            record_pinned_failure(&state, location.as_ref(), &art_uri, &wrapped).await;
            return Err(wrapped);
        }
    }
    info!(
        chain = %item.chain,
        collection = %item.collection_address,
        token_id = %item.token_id,
        "token warmup completed"
    );
    Ok(())
}

async fn load_compose(
    state: &AppState,
    item: &TokenWarmupItem,
    asset_id: &str,
) -> Result<ComposeResult> {
    match state
        .chain
        .compose_equippables(
            &item.chain,
            &item.collection_address,
            &item.token_id,
            asset_id,
        )
        .await
    {
        Ok(compose) => Ok(compose),
        Err(err) => {
            if !is_non_composable_error(&err) {
                return Err(err);
            }
            let _permit = state.rpc_semaphore.acquire().await?;
            let metadata_uri = state
                .chain
                .get_asset_metadata(
                    &item.chain,
                    &item.collection_address,
                    &item.token_id,
                    asset_id,
                )
                .await?;
            let part_id = asset_id.parse::<u64>().context("invalid asset id")?;
            Ok(ComposeResult {
                metadata_uri: metadata_uri.clone(),
                catalog_address: "0x0000000000000000000000000000000000000000".to_string(),
                fixed_parts: vec![FixedPart {
                    part_id,
                    z: 0,
                    metadata_uri,
                }],
                slot_parts: Vec::new(),
            })
        }
    }
}

fn collect_metadata_uris(compose: &ComposeResult) -> Vec<String> {
    let mut uris = Vec::new();
    if !compose.metadata_uri.trim().is_empty() {
        uris.push(compose.metadata_uri.clone());
    }
    for part in &compose.fixed_parts {
        if !part.metadata_uri.trim().is_empty() {
            uris.push(part.metadata_uri.clone());
        }
    }
    for part in &compose.slot_parts {
        if !part.part_metadata.trim().is_empty() {
            uris.push(part.part_metadata.clone());
        }
        if !part.child_asset_metadata.trim().is_empty() {
            uris.push(part.child_asset_metadata.clone());
        }
    }
    let mut seen = HashSet::new();
    uris.into_iter()
        .filter(|uri| seen.insert(uri.clone()))
        .collect()
}

async fn scan_metadata_uri(
    state: &AppState,
    item: &TokenWarmupItem,
    metadata_uri: &str,
) -> Result<HashSet<String>> {
    if metadata_uri.trim().is_empty() {
        warn!(
            chain = %item.chain,
            collection = %item.collection_address,
            token_id = %item.token_id,
            "empty metadata uri, skipping"
        );
        return Ok(HashSet::new());
    }
    let location = record_token_asset_ref(state, item, metadata_uri, "token_metadata").await;
    let mut art_uris = HashSet::new();
    for prefer_thumb in [false, true] {
        match state
            .assets
            .resolve_metadata(metadata_uri, prefer_thumb)
            .await
        {
            Ok(Some(resolved)) => {
                art_uris.insert(resolved.art_uri);
            }
            Ok(None) => {
                warn!(
                    chain = %item.chain,
                    collection = %item.collection_address,
                    token_id = %item.token_id,
                    metadata_uri = %metadata_uri,
                    "metadata has no renderable asset; skipping"
                );
            }
            Err(err) => {
                if is_invalid_uri_error(&err) {
                    warn!(
                        chain = %item.chain,
                        collection = %item.collection_address,
                        token_id = %item.token_id,
                        metadata_uri = %metadata_uri,
                        "invalid metadata uri, skipping"
                    );
                    continue;
                }
                let wrapped = anyhow!("metadata resolve failed for {metadata_uri}: {err}");
                record_pinned_failure(state, location.as_ref(), metadata_uri, &wrapped).await;
                return Err(wrapped);
            }
        }
    }
    Ok(art_uris)
}

async fn record_token_asset_ref(
    state: &AppState,
    item: &TokenWarmupItem,
    uri: &str,
    source: &str,
) -> Option<PinnedAssetLocation> {
    let store = state.assets.pinned_store()?;
    let location = store.ipfs_location_from_uri(uri).ok()?;
    let _ = state
        .db
        .upsert_token_asset_ref(
            &item.chain,
            &item.collection_address,
            &item.token_id,
            &location.asset_key,
            source,
        )
        .await;
    Some(location)
}

async fn record_pinned_failure(
    state: &AppState,
    location: Option<&PinnedAssetLocation>,
    uri: &str,
    err: &anyhow::Error,
) {
    let location = match location {
        Some(location) => location.clone(),
        None => {
            let store = match state.assets.pinned_store() {
                Some(store) => store,
                None => return,
            };
            let Ok(location) = store.ipfs_location_from_uri(uri) else {
                return;
            };
            location
        }
    };
    let _ = state
        .db
        .record_pinned_asset_failure(
            &location.asset_key,
            &location.cid,
            &location.path,
            &err.to_string(),
        )
        .await;
}

fn is_invalid_uri_error(err: &anyhow::Error) -> bool {
    if err.to_string().contains("invalid asset uri") {
        return true;
    }
    err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<AssetFetchError>(),
            Some(AssetFetchError::InvalidUri)
        )
    })
}

async fn finalize_job_if_ready(state: &AppState, job_id: i64) -> Result<()> {
    let _ = state.db.mark_token_warmup_invalid_uris_done(job_id).await;
    let (queued, running, _done, failed, total) = state.db.token_warmup_item_counts(job_id).await?;
    if total == 0 {
        return Ok(());
    }
    if queued + running > 0 {
        return Ok(());
    }
    let status = if failed > 0 { "failed" } else { "done" };
    state
        .db
        .set_token_warmup_job_status(job_id, status, None)
        .await?;
    Ok(())
}

fn resolve_tokens(state: &AppState, request: &TokenWarmupRequest) -> Result<Vec<String>> {
    if let Some(tokens) = request.token_ids.clone() {
        let mut seen = HashSet::new();
        return Ok(tokens
            .into_iter()
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty())
            .filter(|token| seen.insert(token.clone()))
            .collect());
    }
    let start = request
        .start_token
        .ok_or_else(|| anyhow!("start_token required"))?;
    let end = request
        .end_token
        .ok_or_else(|| anyhow!("end_token required"))?;
    if end < start {
        return Err(anyhow!("end_token must be >= start_token"));
    }
    let step = request.step.unwrap_or(1);
    if step == 0 {
        return Err(anyhow!("step must be >= 1"));
    }
    let step_usize = usize::try_from(step).map_err(|_| anyhow!("step too large"))?;
    let count = (end - start) / step + 1;
    if state.config.warmup_max_tokens > 0 && count as usize > state.config.warmup_max_tokens {
        return Err(anyhow!(
            "token range exceeds warmup token limit ({} > {})",
            count,
            state.config.warmup_max_tokens
        ));
    }
    Ok((start..=end)
        .step_by(step_usize)
        .map(|id| id.to_string())
        .collect())
}

fn is_non_composable_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        let message = cause.to_string();
        message.contains(NON_COMPOSABLE_ASSET_REVERT) || message.contains("RMRKNotComposableAsset")
    })
}
