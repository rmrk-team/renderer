use super::{Layer, LayerKind, get_collection_config_cached, rasterize_bytes};
use crate::canonical;
use crate::db::CollectionPinnedAsset;
use crate::state::AppState;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, warn};

#[derive(Debug, Deserialize)]
pub(crate) struct HeavyWarmupRequest {
    pub chain: String,
    pub collection: String,
    pub max_assets: Option<usize>,
}

#[derive(Debug, Serialize)]
pub(crate) struct HeavyWarmupSummary {
    pub status: String,
    pub max_assets: usize,
}

pub(crate) async fn enqueue_heavy_warmup(
    state: Arc<AppState>,
    request: HeavyWarmupRequest,
) -> Result<HeavyWarmupSummary> {
    if state.assets.pinned_store().is_none() {
        return Err(anyhow!("pinning is disabled"));
    }
    let chain = request.chain.trim().to_ascii_lowercase();
    let collection = canonical::canonicalize_collection_address(&request.collection)?;
    let max_assets = request
        .max_assets
        .unwrap_or(state.config.heavy_warmup_max_assets)
        .max(1);
    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(err) =
            run_heavy_warmup(state_clone, chain.clone(), collection.clone(), max_assets).await
        {
            warn!(
                chain = %chain,
                collection = %collection,
                error = ?err,
                "heavy warmup failed"
            );
        }
    });
    Ok(HeavyWarmupSummary {
        status: "queued".to_string(),
        max_assets,
    })
}

async fn run_heavy_warmup(
    state: Arc<AppState>,
    chain: String,
    collection: String,
    max_assets: usize,
) -> Result<()> {
    let Some(config) = get_collection_config_cached(&state, &chain, &collection).await? else {
        return Err(anyhow!("collection config not found"));
    };
    let (canvas_width, canvas_height) = match (config.canvas_width, config.canvas_height) {
        (Some(width), Some(height)) if width > 0 && height > 0 => (width as u32, height as u32),
        _ => {
            return Err(anyhow!(
                "collection canvas size missing; render once before heavy warmup"
            ));
        }
    };
    let assets = state
        .db
        .list_collection_pinned_assets(&chain, &collection, "catalog_asset")
        .await?;
    if assets.is_empty() {
        warn!(
            chain = %chain,
            collection = %collection,
            "no pinned catalog assets found for heavy warmup"
        );
        return Ok(());
    }
    let mut warmed = 0usize;
    let mut heavy = 0usize;
    let mut scanned = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    for asset in assets {
        if warmed >= max_assets {
            break;
        }
        scanned += 1;
        if !is_svg_asset_ref(&asset) {
            skipped += 1;
            continue;
        }
        let fetched = match state.assets.fetch_asset(&asset.asset_key).await {
            Ok(asset) => asset.bytes,
            Err(err) => {
                failed += 1;
                warn!(
                    chain = %chain,
                    collection = %collection,
                    asset_key = %asset.asset_key,
                    error = ?err,
                    "heavy warmup asset fetch failed"
                );
                continue;
            }
        };
        if !super::raster::is_svg(&fetched) {
            skipped += 1;
            continue;
        }
        let svg_bytes = fetched.to_vec();
        let blocking = state.blocking_semaphore.clone();
        let config = state.config.clone();
        let stats = match super::spawn_blocking_with_semaphore(blocking, move || -> Result<_> {
            let (_, stats) = super::raster::parse_svg(
                &svg_bytes,
                config.max_svg_bytes,
                config.max_svg_node_count,
                config.max_raster_bytes,
                config.max_decoded_raster_pixels,
            )?;
            Ok(stats)
        })
        .await
        {
            Ok(result) => result,
            Err(err) => {
                failed += 1;
                warn!(
                    chain = %chain,
                    collection = %collection,
                    asset_key = %asset.asset_key,
                    error = ?err,
                    "heavy warmup svg parse failed"
                );
                continue;
            }
        };
        if !stats.is_heavy(
            state.config.heavy_svg_node_threshold,
            state.config.heavy_svg_feature_threshold,
        ) {
            continue;
        }
        heavy += 1;
        let layer = Layer {
            z: 0,
            required: false,
            kind: LayerKind::Fixed,
            metadata_uri: asset.asset_key.clone(),
        };
        if let Err(err) = rasterize_bytes(
            &fetched,
            canvas_width,
            canvas_height,
            None,
            false,
            &state.assets,
            state.metrics.as_ref(),
            state.config.as_ref(),
            &state.blocking_semaphore,
            &state.heavy_svg_semaphore,
            &layer,
            0,
            Some(&asset.asset_key),
            None,
        )
        .await
        {
            failed += 1;
            warn!(
                chain = %chain,
                collection = %collection,
                asset_key = %asset.asset_key,
                error = ?err,
                "heavy warmup rasterization failed"
            );
            continue;
        }
        warmed += 1;
    }
    debug!(
        chain = %chain,
        collection = %collection,
        scanned,
        heavy,
        warmed,
        skipped,
        failed,
        "heavy warmup complete"
    );
    Ok(())
}

fn is_svg_asset_ref(asset: &CollectionPinnedAsset) -> bool {
    if let Some(content_type) = asset.content_type.as_deref() {
        if content_type.eq_ignore_ascii_case("image/svg+xml") {
            return true;
        }
    }
    let lower = asset.path.to_ascii_lowercase();
    lower.ends_with(".svg") || lower.ends_with(".svgz")
}
