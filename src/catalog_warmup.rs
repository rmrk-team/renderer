use crate::canonical;
use crate::db::CatalogWarmupItem;
use crate::state::AppState;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::warn;

#[derive(Debug, Deserialize)]
pub struct CatalogWarmupRequest {
    pub chain: String,
    pub collection: String,
    pub catalog_address: Option<String>,
    pub token_id: Option<String>,
    pub asset_id: Option<String>,
    pub from_block: Option<u64>,
    pub to_block: Option<u64>,
    pub force: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct CatalogWarmupEnqueueResult {
    pub job_id: i64,
    pub parts_total: usize,
}

pub async fn enqueue_catalog_warmup(
    state: Arc<AppState>,
    request: CatalogWarmupRequest,
) -> Result<CatalogWarmupEnqueueResult> {
    let (chain, collection) =
        canonical::canonicalize_collection(&request.chain, &request.collection, &state.config)?;
    let catalog_address = resolve_catalog_address(&state, &chain, &collection, &request).await?;
    let from_block = request.from_block.unwrap_or(0);
    let to_block = request.to_block;
    validate_log_span(&state, from_block, to_block)?;
    let parts = state
        .chain
        .scan_catalog_parts(&chain, &catalog_address, from_block, to_block)
        .await?;
    let part_items = parts
        .into_iter()
        .filter(|part| !part.metadata_uri.trim().is_empty())
        .map(|part| (part.part_id.to_string(), part.metadata_uri))
        .collect::<Vec<_>>();
    if part_items.is_empty() {
        return Err(anyhow!("no catalog parts discovered"));
    }
    let force = request.force.unwrap_or(false);
    let job_id = state
        .db
        .upsert_catalog_warmup_job(&chain, &collection, &catalog_address, "queued", None)
        .await?;
    if force {
        state.db.clear_catalog_warmup_items(job_id).await?;
        let _ = state
            .db
            .clear_collection_asset_refs(&chain, &collection, "catalog_asset")
            .await;
    }
    state
        .db
        .insert_catalog_warmup_items(job_id, &part_items)
        .await?;
    state
        .db
        .set_collection_catalog_address(&chain, &collection, &catalog_address)
        .await?;
    state.catalog_warmup_notify.notify_one();
    Ok(CatalogWarmupEnqueueResult {
        job_id,
        parts_total: part_items.len(),
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
            state.catalog_warmup_notify.notified().await;
            continue;
        }
        let item = match state.db.fetch_next_catalog_warmup_item().await {
            Ok(Some(item)) => item,
            Ok(None) => {
                tokio::select! {
                    _ = state.catalog_warmup_notify.notified() => {},
                    _ = sleep(Duration::from_secs(5)) => {},
                }
                continue;
            }
            Err(err) => {
                warn!(error = ?err, "catalog warmup fetch failed");
                sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        let _ = state
            .db
            .set_catalog_warmup_job_status(item.job_id, "running", None)
            .await;
        let result = run_item(state.clone(), &item).await;
        if let Err(err) = result {
            warn!(
                error = ?err,
                chain = %item.chain,
                collection = %item.collection_address,
                part_id = %item.part_id,
                "catalog warmup item failed"
            );
            let _ = state
                .db
                .update_catalog_warmup_item_status(item.id, "failed", Some(&err.to_string()))
                .await;
        } else {
            let _ = state
                .db
                .update_catalog_warmup_item_status(item.id, "done", None)
                .await;
        }
        let _ = finalize_job_if_ready(&state, item.job_id).await;
    }
}

async fn run_item(state: Arc<AppState>, item: &CatalogWarmupItem) -> Result<()> {
    let metadata_uri = item.metadata_uri.trim();
    if metadata_uri.is_empty() {
        return Err(anyhow!("missing catalog metadata uri"));
    }
    let resolved = match state.assets.resolve_metadata(metadata_uri, false).await {
        Ok(Some(resolved)) => resolved,
        Ok(None) => {
            warn!(
                chain = %item.chain,
                collection = %item.collection_address,
                part_id = %item.part_id,
                "catalog metadata has no renderable asset; skipping"
            );
            return Ok(());
        }
        Err(err) => {
            record_pin_failure(&state, metadata_uri, &err).await;
            return Err(err);
        }
    };
    let store = state.assets.pinned_store();
    if let Some(store) = store.as_ref() {
        if let Ok(location) = store.ipfs_location_from_uri(metadata_uri) {
            let _ = state
                .db
                .upsert_collection_asset_ref(
                    &item.chain,
                    &item.collection_address,
                    &location.asset_key,
                    "catalog_metadata",
                    Some(&item.part_id),
                )
                .await;
        }
        if let Ok(location) = store.ipfs_location_from_uri(&resolved.art_uri) {
            let _ = state
                .db
                .upsert_collection_asset_ref(
                    &item.chain,
                    &item.collection_address,
                    &location.asset_key,
                    "catalog_asset",
                    Some(&item.part_id),
                )
                .await;
        }
    }
    if let Err(err) = state.assets.fetch_asset(&resolved.art_uri).await {
        record_pin_failure(&state, &resolved.art_uri, &err).await;
        return Err(err);
    }
    Ok(())
}

async fn finalize_job_if_ready(state: &AppState, job_id: i64) -> Result<()> {
    let (queued, running, _done, failed, total) =
        state.db.catalog_warmup_item_counts(job_id).await?;
    if total == 0 {
        return Ok(());
    }
    if queued + running > 0 {
        return Ok(());
    }
    let status = if failed > 0 { "failed" } else { "done" };
    state
        .db
        .set_catalog_warmup_job_status(job_id, status, None)
        .await?;
    Ok(())
}

async fn record_pin_failure(state: &AppState, uri: &str, err: &anyhow::Error) {
    let store = state.assets.pinned_store();
    let Some(store) = store.as_ref() else {
        return;
    };
    let Ok(location) = store.ipfs_location_from_uri(uri) else {
        return;
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

async fn resolve_catalog_address(
    state: &AppState,
    chain: &str,
    collection: &str,
    request: &CatalogWarmupRequest,
) -> Result<String> {
    if let Some(address) = request.catalog_address.as_deref() {
        let catalog = canonical::canonicalize_collection_address(address)?;
        if is_zero_address(&catalog) {
            return Err(anyhow!("catalog address is zero"));
        }
        return Ok(catalog);
    }
    if let Some(cached) = state
        .db
        .get_collection_catalog_address(chain, collection)
        .await?
    {
        if !is_zero_address(&cached) {
            return Ok(cached);
        }
    }
    if let (Some(token_id), Some(asset_id)) =
        (request.token_id.as_deref(), request.asset_id.as_deref())
    {
        let _permit = state.rpc_semaphore.acquire().await?;
        let compose = state
            .chain
            .compose_equippables(chain, collection, token_id, asset_id)
            .await?;
        if is_zero_address(&compose.catalog_address) {
            return Err(anyhow!("catalog address is zero"));
        }
        return Ok(compose.catalog_address);
    }
    Err(anyhow!(
        "catalog address unknown; provide catalog_address or token_id+asset_id"
    ))
}

fn validate_log_span(state: &AppState, from_block: u64, to_block: Option<u64>) -> Result<()> {
    let max_span = state.config.warmup_max_block_span;
    if max_span == 0 {
        return Ok(());
    }
    let Some(to_block) = to_block else {
        return Ok(());
    };
    if to_block < from_block {
        return Err(anyhow!("to_block must be >= from_block"));
    }
    let span = to_block.saturating_sub(from_block);
    if span > max_span {
        return Err(anyhow!(
            "catalog range exceeds max block span ({} > {})",
            span,
            max_span
        ));
    }
    Ok(())
}

fn is_zero_address(address: &str) -> bool {
    address.eq_ignore_ascii_case("0x0000000000000000000000000000000000000000")
}
