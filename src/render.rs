use crate::assets::{AssetResolver, ResolvedMetadata};
use crate::cache::{CacheManager, RenderCacheEntry};
use crate::chain::ComposeResult;
use crate::canonical;
use crate::config::{ChildLayerMode, Config, RasterMismatchPolicy, RenderPolicy};
use crate::db::CollectionConfig;
use crate::state::{collection_cache_key, AppState, ThemeSourceCache};
use anyhow::{anyhow, Context, Result};
use image::codecs::png::PngEncoder;
use image::imageops::FilterType;
use image::{DynamicImage, ImageEncoder, ImageFormat, ImageReader, Rgba, RgbaImage};
use mime::Mime;
use serde::Deserialize;
use sha2::Digest;
use std::borrow::Cow;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::{self, JoinSet};
use tracing::{debug, warn};
use usvg::ImageKind;

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

const WIDTH_PRESETS: [(&str, u32); 6] = [
    ("thumb", 64u32),
    ("small", 128u32),
    ("medium", 256u32),
    ("large", 512u32),
    ("xl", 1024u32),
    ("xxl", 2048u32),
];

#[cfg(test)]
static SVG_STRING_RESOLVER_CALLED: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
fn reset_svg_string_resolver_called() {
    SVG_STRING_RESOLVER_CALLED.store(false, Ordering::Relaxed);
}

#[derive(Debug, Clone)]
pub struct RenderRequest {
    pub chain: String,
    pub collection: String,
    pub token_id: String,
    pub asset_id: String,
    pub format: OutputFormat,
    pub cache_timestamp: Option<String>,
    pub cache_param_present: bool,
    pub width_param: Option<String>,
    pub og_mode: bool,
    pub overlay: Option<String>,
    pub background: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RenderResponse {
    pub bytes: Vec<u8>,
    pub content_type: Mime,
    pub complete: bool,
    pub missing_layers: usize,
    pub nonconforming_layers: usize,
    pub cache_hit: bool,
    pub cache_control: String,
    pub etag: Option<String>,
    pub cached_path: Option<PathBuf>,
    pub content_length: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputFormat {
    Webp,
    Png,
    Jpeg,
}

#[derive(Debug, Error)]
pub enum RenderInputError {
    #[error("invalid {field} segment")]
    InvalidSegment { field: &'static str },
    #[error("invalid {field} parameter")]
    InvalidParam { field: &'static str },
}

#[derive(Debug, Error)]
pub enum RenderLimitError {
    #[error("render exceeds layer limit")]
    TooManyLayers,
    #[error("render canvas too large")]
    CanvasTooLarge,
    #[error("render exceeds raster pixel limit")]
    RasterPixelsExceeded,
}

#[derive(Debug, Error)]
pub enum RenderQueueError {
    #[error("render queue full")]
    QueueFull,
}

#[derive(Debug, Clone, Copy)]
pub struct RenderKeyLimit {
    pub key_id: i64,
    pub max_concurrent: usize,
}

impl OutputFormat {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "webp" => Some(Self::Webp),
            "png" => Some(Self::Png),
            "jpg" | "jpeg" => Some(Self::Jpeg),
            _ => None,
        }
    }

    pub fn mime(&self) -> Mime {
        match self {
            Self::Webp => "image/webp".parse().unwrap(),
            Self::Png => "image/png".parse().unwrap(),
            Self::Jpeg => "image/jpeg".parse().unwrap(),
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            Self::Webp => "webp",
            Self::Png => "png",
            Self::Jpeg => "jpg",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum LayerKind {
    Fixed,
    SlotPart,
    SlotChild,
    Overlay,
}

#[derive(Debug, Clone)]
struct Layer {
    z: u8,
    required: bool,
    kind: LayerKind,
    metadata_uri: String,
}

#[derive(Debug)]
struct LayerImage {
    image: RgbaImage,
    offset_x: i64,
    offset_y: i64,
    nonconforming: bool,
}

struct RenderCacheSelection {
    key: RenderCacheKey,
    variant_key: String,
    fingerprint: String,
}

#[derive(Debug, Clone)]
struct ThemeReplaceMap {
    source: [String; 4],
    dest: [String; 4],
}

#[derive(Debug, Deserialize)]
struct ThemeColors {
    #[serde(rename = "theme_color_1")]
    theme_color_1: Option<String>,
    #[serde(rename = "theme_color_2")]
    theme_color_2: Option<String>,
    #[serde(rename = "theme_color_3")]
    theme_color_3: Option<String>,
    #[serde(rename = "theme_color_4")]
    theme_color_4: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CatalogThemes {
    themes: Option<std::collections::HashMap<String, ThemeColors>>,
}

pub async fn render_token(state: Arc<AppState>, request: RenderRequest) -> Result<RenderResponse> {
    render_token_with_limit(state, request, None).await
}

pub async fn render_token_with_limit(
    state: Arc<AppState>,
    request: RenderRequest,
    key_limit: Option<RenderKeyLimit>,
) -> Result<RenderResponse> {
    let mut request = request;
    apply_cache_epoch(&state, &mut request).await?;
    ensure_collection_approved(&state, &request.chain, &request.collection).await?;

    validate_query_lengths(&request, state.config.max_overlay_length, state.config.max_background_length)?;
    let (width, base_key) = resolve_width(&request.width_param, request.og_mode)?;
    let variant_key = build_variant_key(&base_key, &request);
    let cache_enabled = request.cache_timestamp.is_some();

    let singleflight_key = format!(
        "{}:{}:{}:{}:{}",
        request.chain, request.collection, request.token_id, request.asset_id, variant_key
    );

    loop {
        let permit = state.render_singleflight.acquire(&singleflight_key).await;
        if !permit.is_leader() {
            let _notified = permit.wait_result(Duration::from_secs(30)).await;
            if cache_enabled {
                if let Some(selection) =
                    compute_render_cache_key_for_request(&state, &request, &variant_key).await?
                {
                    if let Some(size) = state
                        .cache
                        .cached_file_len(&selection.key.path, state.cache.render_ttl)
                        .await?
                    {
                        return Ok(RenderResponse {
                            bytes: Vec::new(),
                            content_type: request.format.mime(),
                            complete: true,
                            missing_layers: 0,
                            nonconforming_layers: 0,
                            cache_hit: true,
                            cache_control: cache_control_for_request(
                                &request,
                                state.cache.render_ttl,
                                state.config.default_cache_ttl,
                            ),
                            etag: Some(selection.key.etag.clone()),
                            cached_path: Some(selection.key.path.clone()),
                            content_length: Some(size),
                        });
                    }
                }
            }
            continue;
        }
        if cache_enabled {
            if let Some(queue) = state.render_queue_tx.as_ref() {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let job = crate::render_queue::RenderJob {
                    request: request.clone(),
                    width,
                    variant_key: variant_key.clone(),
                    singleflight_permit: permit,
                    key_limit,
                    respond_to: tx,
                };
                crate::render_queue::try_enqueue(queue, job)?;
                return Ok(rx.await??);
            }
            let state = state.clone();
            let request = request.clone();
            let variant_key = variant_key.clone();
            let key_limit = key_limit;
            let handle = tokio::spawn(async move {
                let _singleflight = permit;
                let _key_permit = acquire_key_permit(&state, key_limit).await?;
                let _permit = state.render_semaphore.acquire().await?;
                render_token_uncached(&state, &request, width, &variant_key).await
            });
            return Ok(handle.await??);
        }
        let _key_permit = acquire_key_permit(&state, key_limit).await?;
        let _permit = state.render_semaphore.acquire().await?;
        let result = render_token_uncached(&state, &request, width, &variant_key).await;
        return result;
    }
}

async fn acquire_key_permit(
    state: &AppState,
    key_limit: Option<RenderKeyLimit>,
) -> Result<Option<OwnedSemaphorePermit>> {
    if let Some(limit) = key_limit {
        if limit.max_concurrent == 0 {
            return Ok(None);
        }
        let permit = state
            .key_render_limiter
            .acquire(limit.key_id, limit.max_concurrent)
            .await?;
        return Ok(Some(permit));
    }
    Ok(None)
}

pub(crate) async fn require_approval(state: &AppState) -> Result<bool> {
    if let Some(value) = state.require_approval_cache.get().await {
        return Ok(value);
    }
    let value = state
        .db
        .get_setting_bool("require_approval")
        .await?
        .unwrap_or(state.config.require_approval);
    state.require_approval_cache.set(value).await;
    Ok(value)
}

pub async fn apply_cache_epoch(state: &AppState, request: &mut RenderRequest) -> Result<()> {
    if request.cache_timestamp.is_some() {
        return Ok(());
    }
    request.cache_timestamp = resolve_cache_timestamp(
        state,
        &request.chain,
        &request.collection,
        None,
    )
    .await?;
    Ok(())
}

pub async fn resolve_cache_timestamp(
    state: &AppState,
    chain: &str,
    collection: &str,
    provided: Option<String>,
) -> Result<Option<String>> {
    if provided.is_some() {
        return Ok(provided);
    }
    let cache_key = collection_cache_key(chain, collection);
    if let Some(cached) = state.collection_epoch_cache.get(&cache_key).await {
        return Ok(epoch_to_timestamp(
            cached,
            &state.config.default_cache_timestamp,
        ));
    }
    let epoch = state
        .db
        .get_collection_cache_epoch(chain, collection)
        .await?;
    state
        .collection_epoch_cache
        .insert(cache_key, epoch)
        .await;
    Ok(epoch_to_timestamp(
        epoch,
        &state.config.default_cache_timestamp,
    ))
}

pub async fn ensure_collection_approved(
    state: &AppState,
    chain: &str,
    collection: &str,
) -> Result<()> {
    if !require_approval(state).await? {
        return Ok(());
    }
    let config = get_collection_config_cached(state, chain, collection).await?;
    let has_config = config.is_some();
    let approved = config
        .as_ref()
        .map(is_collection_approved)
        .unwrap_or(false);
    let stale = config
        .as_ref()
        .map(|config| is_approval_stale(config, state.config.max_approval_staleness_seconds))
        .unwrap_or(false);
    if approved && !stale {
        return Ok(());
    }
    if !has_config && state.approval_negative_cache.contains(&format!("{chain}:{collection}")).await
    {
        return Err(anyhow!("collection not approved"));
    }
    if let Some(config) = config.as_ref() {
        let now = now_epoch();
        if should_skip_on_demand(config, now, state.config.approval_negative_cache_seconds) {
            return Err(anyhow!("collection not approved"));
        }
    }
    match on_demand_approval_check(state, chain, collection).await? {
        Some(approved_until) => {
            state
                .db
                .upsert_collection_approval(
                    chain,
                    collection,
                    approved_until,
                    "on_demand_state",
                    None,
                )
                .await?;
            if has_config {
                state.db.record_approval_check(chain, collection, true).await?;
            }
            state.invalidate_collection_cache(chain, collection).await;
            Ok(())
        }
        None => {
            if has_config {
                state.db.record_approval_check(chain, collection, false).await?;
                state.invalidate_collection_cache(chain, collection).await;
            } else {
                state.approval_negative_cache
                    .insert(format!("{chain}:{collection}"))
                    .await;
            }
            Err(anyhow!("collection not approved"))
        }
    }
}

fn is_collection_approved(config: &CollectionConfig) -> bool {
    if let Some(until) = config.approved_until {
        let now = now_epoch();
        return until > now;
    }
    config.approved
}

fn is_approval_stale(config: &CollectionConfig, max_staleness_seconds: u64) -> bool {
    if max_staleness_seconds == 0 {
        return false;
    }
    if matches!(config.approval_source.as_deref(), Some("admin")) {
        return false;
    }
    let Some(last_sync) = config.last_approval_sync_at else {
        return false;
    };
    let now = now_epoch();
    now.saturating_sub(last_sync) > max_staleness_seconds as i64
}

fn should_skip_on_demand(config: &CollectionConfig, now: i64, ttl_seconds: u64) -> bool {
    if ttl_seconds == 0 {
        return false;
    }
    match (config.last_approval_check_at, config.last_approval_check_result) {
        (Some(at), Some(false)) => now.saturating_sub(at) < ttl_seconds as i64,
        _ => false,
    }
}

async fn on_demand_approval_check(
    state: &AppState,
    chain: &str,
    collection: &str,
) -> Result<Option<i64>> {
    let chain_id = match state.config.chain_id_for_name(chain) {
        Some(chain_id) => chain_id,
        None => return Ok(None),
    };
    let contract_chain = state
        .config
        .approvals_contract_chain
        .as_deref()
        .unwrap_or(chain);
    let collection = canonical::canonicalize_collection_address(collection)?;
    let address = ethers::types::Address::from_str(&collection)?;
    let _permit = state
        .rpc_semaphore
        .acquire()
        .await
        .map_err(anyhow::Error::new)?;
    let result = state
        .chain
        .call_with_approvals(contract_chain, move |contract| async move {
            contract
                .approved_until(chain_id.into(), address)
                .call()
                .await
                .map_err(|err| err.into())
        })
        .await?;
    let Some(approved_until) = result else {
        return Ok(None);
    };
    if approved_until == 0 {
        return Ok(None);
    }
    let approved_until = approval_until_to_i64(approved_until);
    let now = now_epoch();
    if approved_until <= now {
        return Ok(None);
    }
    Ok(Some(approved_until))
}

fn approval_until_to_i64(value: u64) -> i64 {
    let max = i64::MAX as u64;
    if value > max {
        i64::MAX
    } else {
        value as i64
    }
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) async fn render_token_uncached(
    state: &AppState,
    request: &RenderRequest,
    width: Option<u32>,
    variant_key: &str,
) -> Result<RenderResponse> {
    let collection_config = get_collection_config_cached(state, &request.chain, &request.collection)
        .await?
        .unwrap_or(CollectionConfig {
            chain: request.chain.clone(),
            collection_address: request.collection.clone(),
            canvas_width: None,
            canvas_height: None,
            canvas_fingerprint: None,
            og_focal_point: 25,
            og_overlay_uri: None,
            watermark_overlay_uri: None,
            warmup_strategy: "auto".to_string(),
            cache_epoch: None,
            approved: true,
            approved_until: None,
            approval_source: None,
            last_approval_sync_at: None,
            last_approval_sync_block: None,
            last_approval_check_at: None,
            last_approval_check_result: None,
        });
    let composite_variant_key = build_variant_key("base", request);
    let mut composite_key: Option<CompositeCacheKey> = None;
    let mut composite_from_cache = false;
    let mut canvas: Option<RgbaImage> = None;
    let mut cache_selection: Option<RenderCacheSelection> = None;
    if let Some(image) = canvas.as_ref() {
        let canvas_pixels = (image.width() as u64).saturating_mul(image.height() as u64);
        if canvas_pixels > state.config.max_canvas_pixels {
            return Err(RenderLimitError::CanvasTooLarge.into());
        }
    }

    let mut layers_to_composite = Vec::new();
    let mut missing_layers = 0usize;
    let mut nonconforming_layers = 0usize;
    let mut total_raster_pixels = 0u64;
    if canvas.is_none() {
        let compose = state
            .chain
            .compose_equippables(
                &request.chain,
                &request.collection,
                &request.token_id,
                &request.asset_id,
            )
            .await?;
        let theme_replace = load_theme_replace_map(state, &request.chain, &compose).await;
        let theme_replace = theme_replace.map(Arc::new);
        if let Some(theme) = theme_replace.as_ref() {
            debug!(
                metadata_uri = %compose.metadata_uri,
                source = ?theme.source,
                dest = ?theme.dest,
                "theme palette resolved"
            );
        }
        debug!(
            chain = %request.chain,
            collection = %request.collection,
            token_id = %request.token_id,
            asset_id = %request.asset_id,
            metadata_uri = %compose.metadata_uri,
            catalog_address = %compose.catalog_address,
            fixed_parts = compose.fixed_parts.len(),
            slot_parts = compose.slot_parts.len(),
            "compose_equippables loaded"
        );
        debug!(
            fixed_parts = ?compose.fixed_parts,
            slot_parts = ?compose.slot_parts,
            "compose parts detail"
        );
        let render_policy =
            render_policy_for_collection(&state.config, &request.chain, &request.collection);
        debug!(
            child_layer_mode = ?render_policy.child_layer_mode,
            raster_mismatch_fixed = ?render_policy.raster_mismatch_fixed,
            raster_mismatch_child = ?render_policy.raster_mismatch_child,
            "render policy"
        );
        let (canvas_width, canvas_height) =
            ensure_canvas_size(state, &compose, &collection_config, false).await?;
        let canvas_pixels = (canvas_width as u64).saturating_mul(canvas_height as u64);
        if canvas_pixels > state.config.max_canvas_pixels {
            return Err(RenderLimitError::CanvasTooLarge.into());
        }
        let slot_part_layers = compose
            .slot_parts
            .iter()
            .filter(|part| !part.part_metadata.trim().is_empty())
            .count();
        let slot_child_layers = compose
            .slot_parts
            .iter()
            .filter(|part| !part.child_asset_metadata.trim().is_empty())
            .count();
        let mut layers = build_layers(&compose, render_policy.child_layer_mode);
        if let Some(overlay) = overlay_layer(&collection_config, request) {
            layers.push(overlay);
        }
        layers.sort_by_key(|layer| layer_sort_key(layer, render_policy.child_layer_mode));
        let required_layers = layers.iter().filter(|layer| layer.required).count();
        debug!(
            layers = layers.len(),
            required_layers,
            slot_part_layers,
            slot_child_layers,
            "render layers prepared"
        );
        if layers.len() > state.config.max_layers_per_render {
            return Err(RenderLimitError::TooManyLayers.into());
        }
        if canvas_pixels > state.config.max_total_raster_pixels {
            return Err(RenderLimitError::RasterPixelsExceeded.into());
        }
        cache_selection = compute_render_cache_key_for_layers(
            state,
            request,
            variant_key,
            &layers,
            render_policy,
            theme_replace.as_deref(),
            canvas_width,
            canvas_height,
        )
        .await?;
        if let Some(selection) = cache_selection.as_ref() {
            if let Some(size) = state
                .cache
                .cached_file_len(&selection.key.path, state.cache.render_ttl)
                .await?
            {
                return Ok(RenderResponse {
                    bytes: Vec::new(),
                    content_type: request.format.mime(),
                    complete: true,
                    missing_layers: 0,
                    nonconforming_layers: 0,
                    cache_hit: true,
                    cache_control: cache_control_for_request(
                        request,
                        state.cache.render_ttl,
                        state.config.default_cache_ttl,
                    ),
                    etag: Some(selection.key.etag.clone()),
                    cached_path: Some(selection.key.path.clone()),
                    content_length: Some(size),
                });
            }
        }
        if state.config.composite_cache_enabled {
            if let Some(selection) = cache_selection.as_ref() {
                let composite_variant_key =
                    format!("{composite_variant_key}_fp-{}", selection.fingerprint);
                composite_key = Some(composite_cache_key(
                    &state.cache,
                    &request.chain,
                    &request.collection,
                    &request.token_id,
                    &request.asset_id,
                    request
                        .cache_timestamp
                        .as_ref()
                        .ok_or_else(|| anyhow!("missing cache timestamp"))?,
                    &composite_variant_key,
                )?);
                if let Some(key) = composite_key.as_ref() {
                    if let Some(bytes) = state
                        .cache
                        .load_cached_file(&key.path, state.cache.render_ttl)
                        .await?
                    {
                        let max_pixels = state.config.max_decoded_raster_pixels;
                        let image =
                            task::spawn_blocking(move || decode_raster(&bytes, max_pixels)).await??;
                        composite_from_cache = true;
                        canvas = Some(image);
                    }
                }
            }
        }
        if let Some(image) = canvas.as_ref() {
            let canvas_pixels =
                (image.width() as u64).saturating_mul(image.height() as u64);
            if canvas_pixels > state.config.max_canvas_pixels {
                return Err(RenderLimitError::CanvasTooLarge.into());
            }
        }
        if canvas.is_none() {
            let background = resolve_background(&request.background, request.format.clone());
            let mut results: Vec<Option<Result<Option<LayerImage>>>> =
                Vec::with_capacity(layers.len());
            results.resize_with(layers.len(), || None);
            let layer_limit = state.config.render_layer_concurrency.max(1);
            let semaphore = Arc::new(Semaphore::new(layer_limit));
            let mut join_set = JoinSet::new();
        let theme_source_cache = state.theme_source_cache.clone();
        for (idx, layer) in layers.iter().enumerate() {
                let permit = semaphore.clone().acquire_owned().await?;
                let assets = state.assets.clone();
                let layer = layer.clone();
                let max_svg_bytes = state.config.max_svg_bytes;
                let max_svg_nodes = state.config.max_svg_node_count;
                let max_decoded = state.config.max_decoded_raster_pixels;
                let max_raster_bytes = state.config.max_raster_bytes;
                let raster_fixed = render_policy.raster_mismatch_fixed;
                let raster_child = render_policy.raster_mismatch_child;
            let theme_replace = theme_replace.clone();
            let theme_source_cache = theme_source_cache.clone();
                join_set.spawn(async move {
                    let _permit = permit;
                    let result = load_layer(
                        &assets,
                        &layer,
                        canvas_width,
                        canvas_height,
                        max_svg_bytes,
                        max_svg_nodes,
                        max_raster_bytes,
                        max_decoded,
                        raster_fixed,
                        raster_child,
                    theme_replace,
                    theme_source_cache,
                    )
                    .await;
                    (idx, result)
                });
            }
            while let Some(joined) = join_set.join_next().await {
                let (idx, result) = joined?;
                results[idx] = Some(result);
            }

            for (idx, layer) in layers.iter().enumerate() {
                let result = results
                    .get_mut(idx)
                    .and_then(|entry| entry.take())
                    .unwrap_or(Ok(None));
                match result {
                    Ok(Some(layer_image)) => {
                        if layer_image.nonconforming {
                            nonconforming_layers += 1;
                        }
                        total_raster_pixels =
                            total_raster_pixels.saturating_add(canvas_pixels);
                        if total_raster_pixels > state.config.max_total_raster_pixels {
                            return Err(RenderLimitError::RasterPixelsExceeded.into());
                        }
                        layers_to_composite.push(layer_image);
                    }
                    Ok(None) => {
                        debug!(
                            metadata_uri = %layer.metadata_uri,
                            required = layer.required,
                            "layer returned no image"
                        );
                        if layer.required {
                            missing_layers += 1;
                        }
                    }
                    Err(err) => {
                        if layer.required {
                            warn!(
                                error = ?err,
                                metadata_uri = %layer.metadata_uri,
                                required = layer.required,
                                "layer load failed"
                            );
                            missing_layers += 1;
                        } else {
                            debug!(
                                error = ?err,
                                metadata_uri = %layer.metadata_uri,
                                required = layer.required,
                                "layer load failed"
                            );
                        }
                    }
                }
            }
            debug!(
                total_layers = layers.len(),
                loaded_layers = layers_to_composite.len(),
                missing_layers,
                nonconforming_layers,
                "layer load summary"
            );

            let mut base = RgbaImage::from_pixel(
                canvas_width,
                canvas_height,
                background.unwrap_or_else(|| Rgba([0, 0, 0, 0])),
            );
            for layer in layers_to_composite {
                image::imageops::overlay(&mut base, &layer.image, layer.offset_x, layer.offset_y);
            }
            canvas = Some(base);
        }
    }

    let canvas = canvas.ok_or_else(|| anyhow!("missing composite canvas"))?;
    let og_mode = request.og_mode;
    let focal_point = collection_config.og_focal_point;
    let output_format = request.format.clone();
    let should_store_composite =
        !composite_from_cache && composite_key.is_some() && missing_layers == 0;
    let (bytes, composite_bytes) = task::spawn_blocking(move || -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        let composite_bytes = if should_store_composite {
            let mut bytes = Vec::new();
            let encoder = PngEncoder::new(&mut bytes);
            encoder.write_image(
                canvas.as_raw(),
                canvas.width(),
                canvas.height(),
                image::ColorType::Rgba8.into(),
            )?;
            Some(bytes)
        } else {
            None
        };
        let mut final_image = DynamicImage::ImageRgba8(canvas);
        if og_mode {
            final_image = apply_og_crop(final_image, focal_point);
        }
        if let Some(width) = width {
            let height = scale_height(final_image.height(), final_image.width(), width);
            final_image = final_image.resize_exact(width, height, FilterType::Lanczos3);
        }
        let bytes = encode_image(final_image, &output_format)?;
        Ok((bytes, composite_bytes))
    })
    .await??;
    if let (Some(key), Some(bytes)) = (composite_key, composite_bytes) {
        let _ = state.cache.store_file(&key.path, &bytes).await;
    }
    let complete = missing_layers == 0;
    let cache_control = if complete {
        cache_control_for_request(request, state.cache.render_ttl, state.config.default_cache_ttl)
    } else {
        "no-store".to_string()
    };

    let mut etag = None;
    if complete {
        if let Some(selection) = cache_selection.as_ref() {
            state.cache.store_file(&selection.key.path, &bytes).await?;
            etag = Some(selection.key.etag.clone());
            let limiter_key = render_cache_variant_key(
                &request.chain,
                &request.collection,
                &request.token_id,
                &request.asset_id,
                &selection.variant_key,
                request.format.extension(),
            )?;
            let evicted = state.render_cache_limiter.register(
                &limiter_key,
                RenderCacheEntry {
                    path: selection.key.path.clone(),
                },
            );
            for evicted_path in evicted {
                if evicted_path != selection.key.path {
                    let _ = tokio::fs::remove_file(evicted_path).await;
                }
            }
        }
    }

    if cache_control == "no-store" {
        etag = None;
    }
    Ok(RenderResponse {
        bytes,
        content_type: request.format.mime(),
        complete,
        missing_layers,
        nonconforming_layers,
        cache_hit: false,
        cache_control,
        etag,
        cached_path: None,
        content_length: None,
    })
}

fn build_layers(compose: &ComposeResult, child_layer_mode: ChildLayerMode) -> Vec<Layer> {
    let mut layers = Vec::new();
    for part in &compose.fixed_parts {
        layers.push(Layer {
            z: part.z,
            required: true,
            kind: LayerKind::Fixed,
            metadata_uri: part.metadata_uri.clone(),
        });
    }
    for part in &compose.slot_parts {
        if !part.part_metadata.trim().is_empty() {
            layers.push(Layer {
                z: part.z,
                required: false,
                kind: LayerKind::SlotPart,
                metadata_uri: part.part_metadata.clone(),
            });
        }
        if !part.child_asset_metadata.trim().is_empty() {
            let child_z = match child_layer_mode {
                ChildLayerMode::AboveSlot => part.z.saturating_add(1),
                ChildLayerMode::BelowSlot => part.z.saturating_sub(1),
                ChildLayerMode::SameZAfter | ChildLayerMode::SameZBefore => part.z,
            };
            layers.push(Layer {
                z: child_z,
                required: false,
                kind: LayerKind::SlotChild,
                metadata_uri: part.child_asset_metadata.clone(),
            });
        }
    }
    layers
}

fn layer_sort_key(layer: &Layer, child_layer_mode: ChildLayerMode) -> (u16, u8) {
    let order = match layer.kind {
        LayerKind::Fixed => 0,
        LayerKind::SlotPart => match child_layer_mode {
            ChildLayerMode::SameZBefore => 2,
            ChildLayerMode::SameZAfter => 1,
            _ => 1,
        },
        LayerKind::SlotChild => match child_layer_mode {
            ChildLayerMode::SameZBefore => 1,
            ChildLayerMode::SameZAfter => 2,
            _ => 2,
        },
        LayerKind::Overlay => 3,
    };
    (layer.z as u16, order)
}

fn overlay_layer(config: &CollectionConfig, request: &RenderRequest) -> Option<Layer> {
    if request.og_mode {
        return config.og_overlay_uri.as_ref().map(|uri| Layer {
            z: u8::MAX,
            required: false,
            kind: LayerKind::Overlay,
            metadata_uri: uri.clone(),
        });
    }
    if let Some(overlay) = request.overlay.as_ref() {
        if overlay == "watermark" {
            return config.watermark_overlay_uri.as_ref().map(|uri| Layer {
                z: u8::MAX,
                required: false,
                kind: LayerKind::Overlay,
                metadata_uri: uri.clone(),
            });
        }
    }
    None
}

fn render_policy_for_collection(
    config: &Config,
    chain: &str,
    collection: &str,
) -> RenderPolicy {
    let key = format!("{}:{}", chain, collection).to_ascii_lowercase();
    match config.collection_render_overrides.get(&key) {
        Some(override_entry) => config.render_policy.apply_override(override_entry),
        None => config.render_policy,
    }
}

async fn load_theme_replace_map(
    state: &AppState,
    chain: &str,
    compose: &ComposeResult,
) -> Option<ThemeReplaceMap> {
    let bytes = match state
        .assets
        .fetch_metadata_json(&compose.metadata_uri)
        .await
    {
        Ok(bytes) => bytes,
        Err(err) => {
            debug!(
                error = ?err,
                metadata_uri = %compose.metadata_uri,
                "failed to fetch parent metadata for theme"
            );
            return None;
        }
    };
    let metadata_value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(err) => {
            debug!(
                error = ?err,
                metadata_uri = %compose.metadata_uri,
                "parent metadata was not valid json for theme"
            );
            return None;
        }
    };
    if let Some(dest) = theme_colors_from_metadata(&metadata_value) {
        return Some(ThemeReplaceMap {
            source: legacy_theme_source(),
            dest,
        });
    }
    let theme_id = match extract_theme_id(&metadata_value) {
        Some(value) => value,
        None => {
            debug!(
                metadata_uri = %compose.metadata_uri,
                "no theme id or theme colors found in parent metadata"
            );
            return None;
        }
    };
    let dest = match resolve_theme_from_catalog(
        state,
        chain,
        &compose.catalog_address,
        &theme_id,
    )
    .await
    {
        Some(dest) => dest,
        None => {
            debug!(
                metadata_uri = %compose.metadata_uri,
                catalog_address = %compose.catalog_address,
                theme_id = %theme_id,
                "catalog theme lookup failed"
            );
            return None;
        }
    };
    Some(ThemeReplaceMap {
        source: legacy_theme_source(),
        dest,
    })
}

fn legacy_theme_source() -> [String; 4] {
    [
        "#ffe271".to_string(),
        "#a8f4ff".to_string(),
        "#5d74ab".to_string(),
        "#b4cffd".to_string(),
    ]
}

fn theme_colors_from_metadata(value: &serde_json::Value) -> Option<[String; 4]> {
    let theme = value.get("theme")?;
    if theme.is_object() {
        return theme_colors_from_value(theme);
    }
    None
}

fn extract_theme_id(value: &serde_json::Value) -> Option<String> {
    if let Some(id) = value.get("themeId").or_else(|| value.get("theme_id")) {
        return theme_id_from_value(id);
    }
    if let Some(theme) = value.get("theme") {
        if let Some(id) = theme_id_from_value(theme) {
            return Some(id);
        }
        if let Some(obj) = theme.as_object() {
            for key in ["themeId", "theme_id", "id", "name"] {
                if let Some(candidate) = obj.get(key) {
                    if let Some(id) = theme_id_from_value(candidate) {
                        return Some(id);
                    }
                }
            }
        }
    }
    None
}

fn theme_id_from_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn theme_colors_from_value(value: &serde_json::Value) -> Option<[String; 4]> {
    let obj = value.as_object()?;
    let color_1 = obj.get("theme_color_1")?.as_str()?;
    let color_2 = obj.get("theme_color_2")?.as_str()?;
    let color_3 = obj.get("theme_color_3")?.as_str()?;
    let color_4 = obj.get("theme_color_4")?.as_str()?;
    Some([
        normalize_theme_color(color_1)?,
        normalize_theme_color(color_2)?,
        normalize_theme_color(color_3)?,
        normalize_theme_color(color_4)?,
    ])
}

async fn resolve_theme_from_catalog(
    state: &AppState,
    chain: &str,
    catalog_address: &str,
    theme_id: &str,
) -> Option<[String; 4]> {
    if is_zero_address(catalog_address) {
        debug!(
            catalog_address = %catalog_address,
            "catalog address is zero, cannot resolve theme"
        );
        return None;
    }
    let catalog_key = format!(
        "{}:{}",
        chain.to_ascii_lowercase(),
        catalog_address.to_ascii_lowercase()
    );
    let catalog_uri = if let Some(cached) = state.catalog_metadata_cache.get(&catalog_key).await {
        cached
    } else {
        let uri = match state
            .chain
            .get_catalog_metadata_uri(chain, catalog_address)
            .await
        {
            Ok(uri) => uri,
            Err(err) => {
                debug!(
                    error = ?err,
                    catalog_address = %catalog_address,
                    "failed to fetch catalog metadata uri"
                );
                return None;
            }
        };
        state
            .catalog_metadata_cache
            .insert(catalog_key, uri.clone())
            .await;
        uri
    };
    let themes = if let Some(cached) = state.catalog_theme_cache.get(&catalog_uri).await {
        cached
    } else {
        let bytes = match state.assets.fetch_metadata_json(&catalog_uri).await {
            Ok(bytes) => bytes,
            Err(err) => {
                debug!(
                    error = ?err,
                    catalog_uri = %catalog_uri,
                    "failed to fetch catalog metadata json"
                );
                return None;
            }
        };
        let catalog: CatalogThemes = serde_json::from_slice(&bytes).ok()?;
        let themes = catalog.themes?;
        let mut normalized = std::collections::HashMap::new();
        for (key, theme) in themes {
            if let Some(colors) = theme_colors_from_struct(&theme) {
                normalized.insert(key.to_ascii_lowercase(), colors);
            }
        }
        if normalized.is_empty() {
            return None;
        }
        let themes = Arc::new(normalized);
        state
            .catalog_theme_cache
            .insert(catalog_uri.clone(), themes.clone())
            .await;
        themes
    };
    let lookup = theme_id.trim().to_ascii_lowercase();
    themes.get(&lookup).cloned()
}

fn theme_colors_from_struct(theme: &ThemeColors) -> Option<[String; 4]> {
    Some([
        normalize_theme_color(theme.theme_color_1.as_deref()?)?,
        normalize_theme_color(theme.theme_color_2.as_deref()?)?,
        normalize_theme_color(theme.theme_color_3.as_deref()?)?,
        normalize_theme_color(theme.theme_color_4.as_deref()?)?,
    ])
}

fn is_zero_address(value: &str) -> bool {
    value
        .trim_start_matches("0x")
        .chars()
        .all(|ch| ch == '0')
}

fn normalize_theme_color(value: &str) -> Option<String> {
    let value = value.trim();
    if value.len() > 16 {
        return None;
    }
    if value.len() != 7 && value.len() != 9 {
        return None;
    }
    let bytes = value.as_bytes();
    if bytes.first().copied() != Some(b'#') {
        return None;
    }
    if !bytes[1..].iter().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

async fn apply_theme_if_svg<'a>(
    bytes: &'a [u8],
    theme: Option<&ThemeReplaceMap>,
    layer: &Layer,
    theme_source_cache: &ThemeSourceCache,
) -> Result<Cow<'a, [u8]>> {
    let theme = match theme {
        Some(theme) if !matches!(layer.kind, LayerKind::Overlay) => theme,
        _ => return Ok(Cow::Borrowed(bytes)),
    };
    if !is_svg(bytes) {
        return Ok(Cow::Borrowed(bytes));
    }
    let sources = if find_case_insensitive(bytes, b"data-theme_color_").is_some() {
        let hash = sha256_hex_bytes(bytes);
        if let Some(cached) = theme_source_cache.get(&hash).await {
            cached
        } else {
            let extracted = extract_svg_theme_sources(bytes);
            theme_source_cache.insert(hash, extracted.clone()).await;
            extracted
        }
    } else {
        [None, None, None, None]
    };
    let has_declared_sources = sources.iter().any(|value| value.is_some());
    let use_declared = has_declared_sources;
    let should_attempt = if use_declared {
        sources
            .iter()
            .flatten()
            .any(|value| find_case_insensitive(bytes, value.as_bytes()).is_some())
    } else {
        theme
            .source
            .iter()
            .any(|value| find_case_insensitive(bytes, value.as_bytes()).is_some())
    };
    if !should_attempt {
        return Ok(Cow::Borrowed(bytes));
    }
    let (themed, replaced) = apply_theme_to_svg_bytes(bytes, theme, &sources, use_declared);
    if replaced {
        debug!(
            metadata_uri = %layer.metadata_uri,
            sources = ?sources,
            dest = ?theme.dest,
            "applied svg theme replacement"
        );
        Ok(Cow::Owned(themed))
    } else {
        Ok(Cow::Borrowed(bytes))
    }
}

fn find_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    for index in 0..=haystack.len() - needle.len() {
        if haystack[index..index + needle.len()].eq_ignore_ascii_case(needle) {
            return Some(index);
        }
    }
    None
}

fn extract_svg_data_theme_color(svg_bytes: &[u8], idx: usize) -> Option<String> {
    let attr = format!("data-theme_color_{idx}");
    let attr_bytes = attr.as_bytes();
    let mut search_from = 0usize;
    while search_from < svg_bytes.len() {
        let pos =
            find_case_insensitive(&svg_bytes[search_from..], attr_bytes)? + search_from;
        let mut i = pos + attr_bytes.len();
        if i < svg_bytes.len() {
            let next = svg_bytes[i];
            if !(next == b'=' || next.is_ascii_whitespace()) {
                search_from = i;
                continue;
            }
        }
        while i < svg_bytes.len() && svg_bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= svg_bytes.len() || svg_bytes[i] != b'=' {
            search_from = i;
            continue;
        }
        i += 1;
        while i < svg_bytes.len() && svg_bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= svg_bytes.len() {
            return None;
        }
        let quote = svg_bytes[i];
        if quote != b'"' && quote != b'\'' {
            search_from = i;
            continue;
        }
        i += 1;
        let start = i;
        let max_len = 32usize;
        while i < svg_bytes.len() && svg_bytes[i] != quote {
            if i - start > max_len {
                return None;
            }
            i += 1;
        }
        if i >= svg_bytes.len() {
            return None;
        }
        let raw = std::str::from_utf8(&svg_bytes[start..i]).ok()?;
        if let Some(color) = normalize_theme_color(raw) {
            return Some(color);
        }
        search_from = i;
    }
    None
}

fn extract_svg_theme_sources(svg_bytes: &[u8]) -> [Option<String>; 4] {
    [
        extract_svg_data_theme_color(svg_bytes, 1),
        extract_svg_data_theme_color(svg_bytes, 2),
        extract_svg_data_theme_color(svg_bytes, 3),
        extract_svg_data_theme_color(svg_bytes, 4),
    ]
}

fn apply_theme_to_svg_bytes(
    bytes: &[u8],
    theme: &ThemeReplaceMap,
    sources: &[Option<String>; 4],
    use_declared: bool,
) -> (Vec<u8>, bool) {
    const THEME_PLACEHOLDERS: [&str; 4] = [
        "__THEME_C1__",
        "__THEME_C2__",
        "__THEME_C3__",
        "__THEME_C4__",
    ];
    let mut current = bytes.to_vec();
    let mut replaced_any = false;
    for (idx, placeholder) in THEME_PLACEHOLDERS.iter().enumerate() {
        let src = if use_declared {
            sources[idx].as_ref()
        } else {
            Some(&theme.source[idx])
        };
        if let Some(src) = src {
            let (next, replaced) =
                replace_case_insensitive_bytes(&current, src, placeholder);
            current = next;
            replaced_any |= replaced;
        }
    }
    for (idx, placeholder) in THEME_PLACEHOLDERS.iter().enumerate() {
        let (next, replaced) =
            replace_case_insensitive_bytes(&current, placeholder, &theme.dest[idx]);
        current = next;
        replaced_any |= replaced;
    }
    (current, replaced_any)
}

fn replace_case_insensitive_bytes(
    input: &[u8],
    needle: &str,
    replacement: &str,
) -> (Vec<u8>, bool) {
    let needle_bytes = needle.as_bytes();
    if needle_bytes.is_empty() {
        return (input.to_vec(), false);
    }
    let needle_lower: Vec<u8> = needle_bytes
        .iter()
        .map(|byte| byte.to_ascii_lowercase())
        .collect();
    let mut out = Vec::with_capacity(input.len());
    let mut replaced = false;
    let mut index = 0;
    while index + needle_bytes.len() <= input.len() {
        let candidate = &input[index..index + needle_bytes.len()];
        if candidate
            .iter()
            .zip(needle_lower.iter())
            .all(|(left, right)| left.to_ascii_lowercase() == *right)
        {
            out.extend_from_slice(replacement.as_bytes());
            index += needle_bytes.len();
            replaced = true;
        } else {
            out.push(input[index]);
            index += 1;
        }
    }
    out.extend_from_slice(&input[index..]);
    (out, replaced)
}

async fn compute_render_cache_key_for_layers(
    state: &AppState,
    request: &RenderRequest,
    variant_key: &str,
    layers: &[Layer],
    render_policy: RenderPolicy,
    theme_replace: Option<&ThemeReplaceMap>,
    canvas_width: u32,
    canvas_height: u32,
) -> Result<Option<RenderCacheSelection>> {
    let cache_timestamp = match request.cache_timestamp.as_ref() {
        Some(cache) => cache,
        None => return Ok(None),
    };
    let fingerprint = compute_render_fingerprint(
        state,
        layers,
        render_policy,
        theme_replace,
        canvas_width,
        canvas_height,
    )
    .await?;
    let fingerprinted_variant_key = format!("{variant_key}_fp-{fingerprint}");
    let key = render_cache_key(
        &state.cache,
        &request.chain,
        &request.collection,
        &request.token_id,
        &request.asset_id,
        cache_timestamp,
        &fingerprinted_variant_key,
        request.format.extension(),
    )?;
    Ok(Some(RenderCacheSelection {
        key,
        variant_key: fingerprinted_variant_key,
        fingerprint,
    }))
}

async fn compute_render_cache_key_for_request(
    state: &AppState,
    request: &RenderRequest,
    variant_key: &str,
) -> Result<Option<RenderCacheSelection>> {
    if request.cache_timestamp.is_none() {
        return Ok(None);
    }
    let render_policy =
        render_policy_for_collection(&state.config, &request.chain, &request.collection);
    let collection_config = get_collection_config_cached(state, &request.chain, &request.collection)
        .await?
        .unwrap_or(CollectionConfig {
            chain: request.chain.clone(),
            collection_address: request.collection.clone(),
            canvas_width: None,
            canvas_height: None,
            canvas_fingerprint: None,
            og_focal_point: 25,
            og_overlay_uri: None,
            watermark_overlay_uri: None,
            warmup_strategy: "auto".to_string(),
            cache_epoch: None,
            approved: true,
            approved_until: None,
            approval_source: None,
            last_approval_sync_at: None,
            last_approval_sync_block: None,
            last_approval_check_at: None,
            last_approval_check_result: None,
        });
    let compose = state
        .chain
        .compose_equippables(
            &request.chain,
            &request.collection,
            &request.token_id,
            &request.asset_id,
        )
        .await?;
    let theme_replace = load_theme_replace_map(state, &request.chain, &compose).await;
    let (canvas_width, canvas_height) =
        ensure_canvas_size(state, &compose, &collection_config, false).await?;
    let canvas_pixels = (canvas_width as u64).saturating_mul(canvas_height as u64);
    if canvas_pixels > state.config.max_canvas_pixels {
        return Err(RenderLimitError::CanvasTooLarge.into());
    }
    let mut layers = build_layers(&compose, render_policy.child_layer_mode);
    if layers.len() > state.config.max_layers_per_render {
        return Err(RenderLimitError::TooManyLayers.into());
    }
    if let Some(overlay) = overlay_layer(&collection_config, request) {
        layers.push(overlay);
    }
    layers.sort_by_key(|layer| layer_sort_key(layer, render_policy.child_layer_mode));
    let selection = compute_render_cache_key_for_layers(
        state,
        request,
        variant_key,
        &layers,
        render_policy,
        theme_replace.as_ref(),
        canvas_width,
        canvas_height,
    )
    .await?;
    Ok(selection)
}

async fn compute_render_fingerprint(
    state: &AppState,
    layers: &[Layer],
    render_policy: RenderPolicy,
    theme_replace: Option<&ThemeReplaceMap>,
    canvas_width: u32,
    canvas_height: u32,
) -> Result<String> {
    let assets = state.assets.clone();
    let mut join_set = JoinSet::new();
    let mut results: Vec<Option<ResolvedMetadata>> = vec![None; layers.len()];
    let layer_limit = state.config.render_layer_concurrency.max(1);
    let semaphore = Arc::new(Semaphore::new(layer_limit));
    for (idx, layer) in layers.iter().enumerate() {
        let permit = semaphore.clone().acquire_owned().await?;
        let assets = assets.clone();
        let metadata_uri = layer.metadata_uri.clone();
        let required = layer.required;
        let kind = layer.kind;
        join_set.spawn(async move {
            let _permit = permit;
            let resolved = assets.resolve_metadata(&metadata_uri, false).await?;
            Ok::<_, anyhow::Error>((idx, metadata_uri, required, kind, resolved))
        });
    }
    while let Some(result) = join_set.join_next().await {
        let (idx, metadata_uri, required, kind, resolved) = result??;
        match resolved {
            Some(resolved) => results[idx] = Some(resolved),
            None => {
                if required {
                    warn!(
                        metadata_uri = %metadata_uri,
                        kind = ?kind,
                        "render fingerprint missing required metadata"
                    );
                    return Err(anyhow!("missing required layer metadata"));
                }
            }
        }
    }
    let mut fingerprint_input = format!(
        "policy:{:?}:{:?}:{:?};canvas:{}x{};",
        render_policy.child_layer_mode,
        render_policy.raster_mismatch_fixed,
        render_policy.raster_mismatch_child,
        canvas_width,
        canvas_height
    );
    if let Some(theme) = theme_replace {
        fingerprint_input.push_str("theme:");
        for (src, dest) in theme.source.iter().zip(theme.dest.iter()) {
            fingerprint_input.push_str(src);
            fingerprint_input.push('>');
            fingerprint_input.push_str(dest);
            fingerprint_input.push(';');
        }
    } else {
        fingerprint_input.push_str("theme:none;");
    }
    for resolved in results.into_iter().flatten() {
        fingerprint_input.push_str(&resolved.art_uri);
        fingerprint_input.push('|');
    }
    Ok(sha256_hex(&fingerprint_input))
}

async fn ensure_canvas_size(
    state: &AppState,
    compose: &ComposeResult,
    config: &CollectionConfig,
    force: bool,
) -> Result<(u32, u32)> {
    let mut fixed_parts = compose.fixed_parts.clone();
    fixed_parts.sort_by(|a, b| a.z.cmp(&b.z));
    let first = fixed_parts
        .first()
        .ok_or_else(|| anyhow!("no fixed parts for canvas size derivation"))?;
    let resolved = state
        .assets
        .resolve_metadata(&first.metadata_uri, false)
        .await
        .ok()
        .flatten();
    if let Some(resolved) = resolved.as_ref() {
        debug!(
            metadata_uri = %first.metadata_uri,
            art_uri = %resolved.art_uri,
            field = %resolved.source,
            "resolved base part metadata"
        );
    } else {
        debug!(
            metadata_uri = %first.metadata_uri,
            "base part metadata unavailable, using direct asset"
        );
    }
    let art_uri = resolved
        .as_ref()
        .map(|resolved| resolved.art_uri.as_str())
        .unwrap_or(&first.metadata_uri);

    if !force {
        if let (Some(width), Some(height), Some(fingerprint)) =
            (config.canvas_width, config.canvas_height, config.canvas_fingerprint.as_ref())
        {
            let expected = sha256_hex(&format!("{art_uri}:{width}x{height}"));
            if fingerprint == &expected {
                return Ok((width as u32, height as u32));
            }
        }
    }

    let (width, height, used_fallback) = match state.assets.fetch_asset(art_uri).await {
        Ok(asset) => {
            let bytes = asset.bytes.to_vec();
            let default_width = state.config.default_canvas_width;
            let default_height = state.config.default_canvas_height;
            let max_svg_bytes = state.config.max_svg_bytes;
            let max_svg_nodes = state.config.max_svg_node_count;
            let max_decoded_raster_pixels = state.config.max_decoded_raster_pixels;
            let max_raster_bytes = state.config.max_raster_bytes;
            match task::spawn_blocking(move || {
                derive_canvas_from_asset(
                    &bytes,
                    default_width,
                    default_height,
                    max_svg_bytes,
                    max_svg_nodes,
                max_raster_bytes,
                    max_decoded_raster_pixels,
                )
            })
            .await
            {
                Ok(Ok(result)) => result,
                Ok(Err(err)) => {
                    warn!(error = ?err, "failed to parse base asset, using defaults");
                    (default_width, default_height, true)
                }
                Err(err) => {
                    warn!(error = ?err, "failed to join base asset parse, using defaults");
                    (default_width, default_height, true)
                }
            }
        }
        Err(err) => {
            warn!(error = ?err, "failed to fetch base asset, using defaults");
            (
                state.config.default_canvas_width,
                state.config.default_canvas_height,
                true,
            )
        }
    };
    let mut fingerprint = sha256_hex(&format!("{art_uri}:{width}x{height}"));
    if used_fallback {
        fingerprint = format!("fallback:{fingerprint}");
    }
    debug!(
        width,
        height,
        used_fallback,
        fingerprint = %fingerprint,
        "canvas size resolved"
    );
    if config.canvas_fingerprint.as_ref() != Some(&fingerprint)
        || config.canvas_width != Some(width as i64)
        || config.canvas_height != Some(height as i64)
    {
        state
            .db
            .set_canvas_size(
                &config.chain,
                &config.collection_address,
                width as i64,
                height as i64,
                &fingerprint,
            )
            .await?;
        state
            .invalidate_collection_cache(&config.chain, &config.collection_address)
            .await;
    }
    Ok((width, height))
}

pub async fn refresh_canvas_size(
    state: Arc<AppState>,
    chain: String,
    collection: String,
    token_id: String,
    asset_id: String,
) -> Result<(u32, u32)> {
    let compose = state
        .chain
        .compose_equippables(&chain, &collection, &token_id, &asset_id)
        .await?;
    let collection_config = get_collection_config_cached(&state, &chain, &collection)
        .await?
        .unwrap_or(CollectionConfig {
            chain,
            collection_address: collection,
            canvas_width: None,
            canvas_height: None,
            canvas_fingerprint: None,
            og_focal_point: 25,
            og_overlay_uri: None,
            watermark_overlay_uri: None,
            warmup_strategy: "auto".to_string(),
            cache_epoch: None,
            approved: true,
            approved_until: None,
            approval_source: None,
            last_approval_sync_at: None,
            last_approval_sync_block: None,
            last_approval_check_at: None,
            last_approval_check_result: None,
        });
    ensure_canvas_size(&state, &compose, &collection_config, true).await
}

fn derive_canvas_from_asset(
    bytes: &[u8],
    default_width: u32,
    default_height: u32,
    max_svg_bytes: usize,
    max_svg_nodes: usize,
    max_raster_bytes: usize,
    max_decoded_raster_pixels: u64,
) -> Result<(u32, u32, bool)> {
    if is_svg(bytes) {
        let raw = std::str::from_utf8(bytes).context("svg not utf-8")?;
        if let Some((width, height)) = extract_svg_dimensions(raw) {
            if width > 0 && height > 0 {
                return Ok((width, height, false));
            }
        }
        let tree = parse_svg(
            bytes,
            max_svg_bytes,
            max_svg_nodes,
            max_raster_bytes,
            max_decoded_raster_pixels,
        )?;
        let size = tree.size();
        let width = size.width().round() as u32;
        let height = size.height().round() as u32;
        if width > 0 && height > 0 {
            return Ok((width, height, false));
        }
    }
    if let Ok((width, height)) = raster_dimensions(bytes, max_decoded_raster_pixels) {
        if width > 0 && height > 0 {
            return Ok((width, height, false));
        }
    }
    Ok((default_width, default_height, true))
}

async fn load_layer(
    assets: &AssetResolver,
    layer: &Layer,
    canvas_width: u32,
    canvas_height: u32,
    max_svg_bytes: usize,
    max_svg_nodes: usize,
    max_raster_bytes: usize,
    max_decoded_raster_pixels: u64,
    raster_mismatch_fixed: RasterMismatchPolicy,
    raster_mismatch_child: RasterMismatchPolicy,
    theme_replace: Option<Arc<ThemeReplaceMap>>,
    theme_source_cache: ThemeSourceCache,
) -> Result<Option<LayerImage>> {
    debug!(
        metadata_uri = %layer.metadata_uri,
        required = layer.required,
        "loading layer"
    );
    if layer.metadata_uri.starts_with("local://") {
        let bytes = assets.fetch_local_bytes(&layer.metadata_uri).await?;
        let themed =
            apply_theme_if_svg(&bytes, theme_replace.as_deref(), layer, &theme_source_cache)
                .await?;
        let (image, nonconforming) = rasterize_bytes(
            themed.as_ref(),
            canvas_width,
            canvas_height,
            max_svg_bytes,
            max_svg_nodes,
        max_raster_bytes,
            max_decoded_raster_pixels,
            assets,
        )
        .await?;
        let policy = raster_policy_for_layer(layer, raster_mismatch_fixed, raster_mismatch_child);
        let layer_image =
            apply_raster_mismatch_policy(layer, image, nonconforming, policy, canvas_width, canvas_height)?;
        return Ok(Some(layer_image));
    }
    let asset = match assets.resolve_metadata(&layer.metadata_uri, false).await {
        Ok(Some(resolved)) => {
            debug!(
                metadata_uri = %layer.metadata_uri,
                art_uri = %resolved.art_uri,
                field = %resolved.source,
                "resolved layer metadata"
            );
            assets.fetch_asset(&resolved.art_uri).await?
        }
        Ok(None) => {
            if matches!(layer.kind, LayerKind::SlotPart | LayerKind::SlotChild | LayerKind::Overlay) {
                debug!(
                    metadata_uri = %layer.metadata_uri,
                    kind = ?layer.kind,
                    "metadata has no renderable media, skipping layer"
                );
                return Ok(None);
            }
            return Err(anyhow!("metadata has no renderable media"));
        }
        Err(err) => {
            debug!(
                error = ?err,
                metadata_uri = %layer.metadata_uri,
                "metadata resolve failed, treating as direct asset"
            );
            assets.fetch_asset(&layer.metadata_uri).await?
        }
    };
    debug!(
        metadata_uri = %layer.metadata_uri,
        bytes = asset.bytes.len(),
        "fetched layer asset"
    );
    let themed =
        apply_theme_if_svg(&asset.bytes, theme_replace.as_deref(), layer, &theme_source_cache)
            .await?;
    let (image, nonconforming) = rasterize_bytes(
        themed.as_ref(),
        canvas_width,
        canvas_height,
        max_svg_bytes,
        max_svg_nodes,
        max_raster_bytes,
        max_decoded_raster_pixels,
        assets,
    )
    .await?;
    let policy = raster_policy_for_layer(layer, raster_mismatch_fixed, raster_mismatch_child);
    let layer_image =
        apply_raster_mismatch_policy(layer, image, nonconforming, policy, canvas_width, canvas_height)?;
    Ok(Some(layer_image))
}

async fn rasterize_bytes(
    bytes: &[u8],
    canvas_width: u32,
    canvas_height: u32,
    max_svg_bytes: usize,
    max_svg_nodes: usize,
    max_raster_bytes: usize,
    max_decoded_raster_pixels: u64,
    assets: &AssetResolver,
) -> Result<(RgbaImage, bool)> {
    if is_svg(bytes) {
        let cache_key = sha256_hex_bytes(bytes);
        if let Some(raster) = assets
            .fetch_raster_cache(&cache_key, canvas_width, canvas_height)
            .await?
        {
            match task::spawn_blocking(move || -> Result<RgbaImage> {
                decode_raster(&raster, max_decoded_raster_pixels)
            })
            .await
            {
                Ok(Ok(image)) => return Ok((image, false)),
                Ok(Err(_)) | Err(_) => {
                    let _ = assets
                        .remove_raster_cache(&cache_key, canvas_width, canvas_height)
                        .await;
                }
            }
        }
        let svg_bytes = bytes.to_vec();
        let (image, png_bytes) = task::spawn_blocking(move || -> Result<(RgbaImage, Vec<u8>)> {
            let tree = parse_svg(
                &svg_bytes,
                max_svg_bytes,
                max_svg_nodes,
                max_raster_bytes,
                max_decoded_raster_pixels,
            )?;
            let pixmap = render_svg_to_pixmap(&tree, canvas_width, canvas_height)?;
            let image = RgbaImage::from_raw(canvas_width, canvas_height, pixmap.data().to_vec())
                .ok_or_else(|| anyhow!("failed to build raster image"))?;
            let mut png_bytes = Vec::new();
            image.write_to(&mut std::io::Cursor::new(&mut png_bytes), ImageFormat::Png)?;
            Ok((image, png_bytes))
        })
        .await??;
        assets
            .store_raster_cache(&cache_key, canvas_width, canvas_height, &png_bytes)
            .await?;
        return Ok((image, false));
    }
    let bytes = bytes.to_vec();
    let image = task::spawn_blocking(move || -> Result<RgbaImage> {
        decode_raster(&bytes, max_decoded_raster_pixels)
    })
    .await??;
    let nonconforming = image.width() != canvas_width || image.height() != canvas_height;
    Ok((image, nonconforming))
}

fn raster_policy_for_layer(
    layer: &Layer,
    raster_mismatch_fixed: RasterMismatchPolicy,
    raster_mismatch_child: RasterMismatchPolicy,
) -> RasterMismatchPolicy {
    match layer.kind {
        LayerKind::SlotChild => raster_mismatch_child,
        _ => raster_mismatch_fixed,
    }
}

fn apply_raster_mismatch_policy(
    layer: &Layer,
    image: RgbaImage,
    nonconforming: bool,
    policy: RasterMismatchPolicy,
    canvas_width: u32,
    canvas_height: u32,
) -> Result<LayerImage> {
    if !nonconforming {
        return Ok(LayerImage {
            image,
            offset_x: 0,
            offset_y: 0,
            nonconforming: false,
        });
    }
    warn!(
        metadata_uri = %layer.metadata_uri,
        kind = ?layer.kind,
        policy = ?policy,
        image_width = image.width(),
        image_height = image.height(),
        canvas_width,
        canvas_height,
        "nonconforming raster layer dimensions"
    );
    match policy {
        RasterMismatchPolicy::Error => Err(anyhow!("nonconforming raster dimensions")),
        RasterMismatchPolicy::ScaleToCanvas => {
            let resized = image::imageops::resize(
                &image,
                canvas_width,
                canvas_height,
                FilterType::Lanczos3,
            );
            Ok(LayerImage {
                image: resized,
                offset_x: 0,
                offset_y: 0,
                nonconforming: true,
            })
        }
        RasterMismatchPolicy::CenterNoScale => {
            let offset_x = ((canvas_width as i64 - image.width() as i64) / 2).max(0);
            let offset_y = ((canvas_height as i64 - image.height() as i64) / 2).max(0);
            Ok(LayerImage {
                image,
                offset_x,
                offset_y,
                nonconforming: true,
            })
        }
        RasterMismatchPolicy::TopLeftNoScale => Ok(LayerImage {
            image,
            offset_x: 0,
            offset_y: 0,
            nonconforming: true,
        }),
    }
}

fn render_svg_to_pixmap(
    tree: &usvg::Tree,
    width: u32,
    height: u32,
) -> Result<tiny_skia::Pixmap> {
    let mut pixmap =
        tiny_skia::Pixmap::new(width, height).ok_or_else(|| anyhow!("invalid pixmap size"))?;
    let size = tree.size();
    let scale_x = if size.width() > 0.0 {
        width as f32 / size.width()
    } else {
        1.0
    };
    let scale_y = if size.height() > 0.0 {
        height as f32 / size.height()
    } else {
        1.0
    };
    let transform = tiny_skia::Transform::from_scale(scale_x, scale_y);
    let mut pixmap_mut = pixmap.as_mut();
    resvg::render(tree, transform, &mut pixmap_mut);
    Ok(pixmap)
}

fn raster_dimensions(bytes: &[u8], max_pixels: u64) -> Result<(u32, u32)> {
    let mut reader = ImageReader::new(std::io::Cursor::new(bytes)).with_guessed_format()?;
    reader.limits(raster_limits(max_pixels));
    let (width, height) = reader.into_dimensions()?;
    let pixels = (width as u64).saturating_mul(height as u64);
    if pixels > max_pixels {
        return Err(anyhow!("raster exceeds max decoded pixels"));
    }
    Ok((width, height))
}

fn decode_raster(bytes: &[u8], max_pixels: u64) -> Result<RgbaImage> {
    let (width, height) = raster_dimensions(bytes, max_pixels)?;
    if width == 0 || height == 0 {
        return Err(anyhow!("raster has invalid dimensions"));
    }
    let mut reader = ImageReader::new(std::io::Cursor::new(bytes)).with_guessed_format()?;
    reader.limits(raster_limits(max_pixels));
    let image = reader.decode()?;
    let pixels = (image.width() as u64).saturating_mul(image.height() as u64);
    if pixels > max_pixels {
        return Err(anyhow!("raster exceeds max decoded pixels"));
    }
    Ok(image.to_rgba8())
}

fn raster_limits(max_pixels: u64) -> image::Limits {
    let max_dim = max_pixels.min(u32::MAX as u64) as u32;
    let max_alloc = max_pixels.saturating_mul(4);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(max_dim);
    limits.max_image_height = Some(max_dim);
    limits.max_alloc = Some(max_alloc);
    limits
}

fn parse_svg(
    bytes: &[u8],
    max_svg_bytes: usize,
    max_svg_nodes: usize,
    max_raster_bytes: usize,
    max_decoded_raster_pixels: u64,
) -> Result<usvg::Tree> {
    if bytes.len() > max_svg_bytes {
        return Err(anyhow!("svg exceeds max size"));
    }
    let raw = std::str::from_utf8(bytes).context("svg not utf-8")?;
    if contains_ascii_case_insensitive(raw.as_bytes(), b"<script")
        || contains_external_svg_url(raw)
    {
        return Err(anyhow!("svg contains disallowed external references"));
    }
    let mut options = usvg::Options::default();
    options.image_href_resolver.resolve_data = Box::new(move |mime, data, _opts| {
        if data.len() > max_raster_bytes {
            return None;
        }
        match mime {
            "image/png" => {
                data_uri_raster_kind(data, max_decoded_raster_pixels).map(ImageKind::PNG)
            }
            "image/jpg" | "image/jpeg" => {
                data_uri_raster_kind(data, max_decoded_raster_pixels).map(ImageKind::JPEG)
            }
            "image/webp" => data_uri_raster_kind(data, max_decoded_raster_pixels)
                .map(ImageKind::WEBP),
            _ => None,
        }
    });
    options.image_href_resolver.resolve_string = Box::new(|_href, _opts| {
        #[cfg(test)]
        {
            SVG_STRING_RESOLVER_CALLED.store(true, Ordering::Relaxed);
        }
        None
    });
    let tree = usvg::Tree::from_data(bytes, &options)?;
    let node_count = count_nodes(tree.root());
    if node_count > max_svg_nodes {
        return Err(anyhow!("svg node count exceeds limit"));
    }
    Ok(tree)
}

fn data_uri_raster_kind(data: Arc<Vec<u8>>, max_pixels: u64) -> Option<Arc<Vec<u8>>> {
    let reader = image::ImageReader::new(std::io::Cursor::new(data.as_slice()))
        .with_guessed_format()
        .ok()?;
    let (width, height) = reader.into_dimensions().ok()?;
    let pixels = (width as u64).saturating_mul(height as u64);
    if pixels > max_pixels {
        return None;
    }
    Some(data)
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    let last_start = haystack.len() - needle.len();
    for start in 0..=last_start {
        let mut matched = true;
        for (offset, target) in needle.iter().enumerate() {
            if haystack[start + offset].to_ascii_lowercase() != *target {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

fn contains_external_svg_url(raw: &str) -> bool {
    let lowered = raw.to_ascii_lowercase();
    // Allow data: URIs (embedded images), block only external http(s) references.
    let needles = [
        "href=\"http://",
        "href='http://",
        "href=\"https://",
        "href='https://",
        "xlink:href=\"http://",
        "xlink:href='http://",
        "xlink:href=\"https://",
        "xlink:href='https://",
        "url(http://",
        "url('http://",
        "url(\"http://",
        "url(https://",
        "url('https://",
        "url(\"https://",
        "@import \"http://",
        "@import 'http://",
        "@import \"https://",
        "@import 'https://",
        "@import url(http://",
        "@import url('http://",
        "@import url(\"http://",
        "@import url(https://",
        "@import url('https://",
        "@import url(\"https://",
    ];
    needles.iter().any(|needle| lowered.contains(needle))
}

fn is_svg(bytes: &[u8]) -> bool {
    let sample = std::str::from_utf8(bytes).unwrap_or("");
    sample.contains("<svg") || sample.contains("<?xml")
}

pub(crate) fn resolve_width(
    width_param: &Option<String>,
    og_mode: bool,
) -> Result<(Option<u32>, String)> {
    if og_mode {
        return Ok((Some(1200), "og".to_string()));
    }
    if let Some(width) = width_param.as_ref() {
        if width == "original" {
            return Ok((None, "original".to_string()));
        }
        for (name, size) in WIDTH_PRESETS.iter() {
            if width == name {
                return Ok((Some(*size), format!("w{}", size)));
            }
        }
        if let Ok(value) = width.parse::<u32>() {
            let (_, nearest) = WIDTH_PRESETS
                .iter()
                .min_by(|a, b| {
                    let da = a.1.abs_diff(value);
                    let db = b.1.abs_diff(value);
                    da.cmp(&db)
                })
                .ok_or_else(|| anyhow!("no width presets"))?;
            return Ok((Some(*nearest), format!("w{}", nearest)));
        }
    }
    Ok((None, "original".to_string()))
}

pub(crate) fn build_variant_key(base_key: &str, request: &RenderRequest) -> String {
    let mut key = base_key.to_string();
    if request.og_mode && !key.contains("og") {
        key.push_str("_og");
    }
    if let Some(overlay) = normalize_overlay_for_key(&request.overlay) {
        key.push_str("_ov-");
        key.push_str(overlay);
    }
    if let Some(bg) = normalize_background_for_key(&request.background, request.format.clone()) {
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

fn sanitize_key(value: &str) -> String {
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
struct CompositeCacheKey {
    path: PathBuf,
}

fn composite_cache_key(
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

fn safe_segment<'a>(
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

pub(crate) fn validate_query_lengths(
    request: &RenderRequest,
    max_overlay_length: usize,
    max_background_length: usize,
) -> std::result::Result<(), RenderInputError> {
    if let Some(overlay) = request.overlay.as_ref() {
        if overlay.len() > max_overlay_length {
            return Err(RenderInputError::InvalidParam { field: "overlay" });
        }
    }
    if let Some(background) = request.background.as_ref() {
        if background.len() > max_background_length {
            return Err(RenderInputError::InvalidParam { field: "bg" });
        }
    }
    Ok(())
}

pub(crate) fn validate_render_params(
    chain: &str,
    collection: &str,
    token_id: &str,
    asset_id: Option<&str>,
) -> std::result::Result<(), RenderInputError> {
    validate_chain_segment(chain)?;
    validate_collection_address(collection)?;
    validate_numeric_param(token_id, 78, "token_id")?;
    if let Some(asset_id) = asset_id {
        validate_numeric_param(asset_id, 20, "asset_id")?;
    }
    Ok(())
}

fn validate_chain_segment(chain: &str) -> std::result::Result<(), RenderInputError> {
    safe_segment(chain, "chain", 64).map(|_| ())
}

fn validate_collection_address(collection: &str) -> std::result::Result<(), RenderInputError> {
    if collection.len() != 42 || !collection.starts_with("0x") {
        return Err(RenderInputError::InvalidParam { field: "collection" });
    }
    if !collection[2..].chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(RenderInputError::InvalidParam { field: "collection" });
    }
    Ok(())
}

fn validate_numeric_param(
    value: &str,
    max_len: usize,
    field: &'static str,
) -> std::result::Result<(), RenderInputError> {
    if value.is_empty() || value.len() > max_len {
        return Err(RenderInputError::InvalidParam { field });
    }
    if !value.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(RenderInputError::InvalidParam { field });
    }
    Ok(())
}

pub(crate) fn cache_control_header(ttl: Duration) -> String {
    format!("public, max-age={}", ttl.as_secs())
}

fn cache_control_for_request(
    request: &RenderRequest,
    render_ttl: Duration,
    default_ttl: Duration,
) -> String {
    if request.cache_timestamp.is_none() {
        return "no-store".to_string();
    }
    if request.cache_param_present {
        return cache_control_header(render_ttl);
    }
    if default_ttl.is_zero() {
        return "no-store".to_string();
    }
    cache_control_header(default_ttl)
}

fn scale_height(original_height: u32, original_width: u32, target_width: u32) -> u32 {
    if original_width == 0 {
        return original_height;
    }
    let ratio = target_width as f64 / original_width as f64;
    (original_height as f64 * ratio).round() as u32
}

fn apply_og_crop(image: DynamicImage, focal_point: i64) -> DynamicImage {
    let width = image.width();
    let height = image.height();
    if width == 0 || height == 0 {
        return image;
    }
    let og_ratio = 1200.0 / 630.0;
    let target_height = (width as f64 / og_ratio).round() as u32;
    let crop_height = target_height.min(height);
    let max_offset = height.saturating_sub(crop_height);
    let bias = (focal_point.clamp(0, 100) as f64 / 100.0) * max_offset as f64;
    let top = bias.round() as u32;
    let cropped = image.crop_imm(0, top, width, crop_height);
    cropped.resize_exact(1200, 630, FilterType::Lanczos3)
}

fn encode_image(image: DynamicImage, format: &OutputFormat) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    match format {
        OutputFormat::Webp => {
            let encoder = image::codecs::webp::WebPEncoder::new_lossless(&mut bytes);
            encoder.encode(
                image.to_rgba8().as_raw(),
                image.width(),
                image.height(),
                image::ExtendedColorType::Rgba8,
            )?;
        }
        OutputFormat::Png => {
            image.write_to(&mut std::io::Cursor::new(&mut bytes), ImageFormat::Png)?;
        }
        OutputFormat::Jpeg => {
            let rgb = image.to_rgb8();
            let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut bytes, 90);
            encoder.encode(
                rgb.as_raw(),
                rgb.width(),
                rgb.height(),
                image::ColorType::Rgb8.into(),
            )?;
        }
    }
    Ok(bytes)
}

fn resolve_background(background: &Option<String>, format: OutputFormat) -> Option<Rgba<u8>> {
    if let Some(value) = background.as_ref() {
        if let Some(color) = parse_color(value) {
            if matches!(format, OutputFormat::Jpeg) && color.0[3] == 0 {
                return Some(Rgba([255, 255, 255, 255]));
            }
            return Some(color);
        }
    }
    if matches!(format, OutputFormat::Jpeg) {
        return Some(Rgba([255, 255, 255, 255]));
    }
    None
}

fn parse_color(value: &str) -> Option<Rgba<u8>> {
    if value == "transparent" {
        return Some(Rgba([0, 0, 0, 0]));
    }
    let value = value.trim_start_matches('#');
    if value.len() == 6 {
        let r = u8::from_str_radix(&value[0..2], 16).ok()?;
        let g = u8::from_str_radix(&value[2..4], 16).ok()?;
        let b = u8::from_str_radix(&value[4..6], 16).ok()?;
        return Some(Rgba([r, g, b, 255]));
    }
    None
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn sha256_hex_bytes(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn extract_svg_dimensions(raw: &str) -> Option<(u32, u32)> {
    let lower = raw.to_ascii_lowercase();
    if let Some((width, height)) = parse_viewbox(&lower) {
        return Some((width, height));
    }
    let width = parse_svg_length(&lower, "width")?;
    let height = parse_svg_length(&lower, "height")?;
    Some((width, height))
}

fn parse_viewbox(lower: &str) -> Option<(u32, u32)> {
    let idx = lower.find("viewbox=")?;
    let quote = lower[idx..].chars().nth(8)?;
    let start = idx + 9;
    let end = lower[start..].find(quote)? + start;
    let value = &lower[start..end];
    let parts = value
        .split_whitespace()
        .filter_map(|item| item.parse::<f32>().ok())
        .collect::<Vec<_>>();
    if parts.len() >= 4 {
        return Some((parts[2].round() as u32, parts[3].round() as u32));
    }
    None
}

fn parse_svg_length(lower: &str, name: &str) -> Option<u32> {
    let needle = format!("{name}=");
    let idx = lower.find(&needle)?;
    let quote = lower[idx + name.len() + 1..].chars().next()?;
    let start = idx + name.len() + 2;
    let end = lower[start..].find(quote)? + start;
    let value = lower[start..end].trim();
    let trimmed = value.trim_end_matches("px");
    trimmed.parse::<f32>().ok().map(|v| v.round() as u32)
}

fn count_nodes(group: &usvg::Group) -> usize {
    let mut count = 0usize;
    let mut stack = vec![group];
    while let Some(group) = stack.pop() {
        count = count.saturating_add(1);
        for child in group.children() {
            count = count.saturating_add(1);
            if let usvg::Node::Group(child_group) = child {
                stack.push(child_group);
            }
        }
    }
    count
}

fn epoch_to_timestamp(epoch: Option<i64>, default: &Option<String>) -> Option<String> {
    if let Some(epoch) = epoch {
        if epoch >= 0 {
            let value = epoch.to_string();
            if value.len() <= 13 {
                return Some(value);
            }
        }
    }
    default.clone()
}

async fn get_collection_config_cached(
    state: &AppState,
    chain: &str,
    collection: &str,
) -> Result<Option<CollectionConfig>> {
    let key = collection_cache_key(chain, collection);
    if let Some(cached) = state.collection_config_cache.get(&key).await {
        return Ok(cached);
    }
    let fetched = state.db.get_collection_config(chain, collection).await?;
    state
        .collection_config_cache
        .insert(key, fetched.clone())
        .await;
    Ok(fetched)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CacheManager;
    use crate::chain::ChainClient;
    use crate::db::Database;
    use crate::state::AppState;
    use anyhow::{Context, Result};
    use std::env;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::sync::Semaphore;

    #[test]
    fn resolve_width_presets() {
        let (width, key) = resolve_width(&Some("medium".to_string()), false).unwrap();
        assert_eq!(width, Some(256));
        assert_eq!(key, "w256");
    }

    #[test]
    fn resolve_width_rounds() {
        let (width, key) = resolve_width(&Some("300".to_string()), false).unwrap();
        assert_eq!(width, Some(256));
        assert_eq!(key, "w256");
    }

    #[test]
    fn resolve_width_original() {
        let (width, key) = resolve_width(&Some("original".to_string()), false).unwrap();
        assert_eq!(width, None);
        assert_eq!(key, "original");
    }

    #[test]
    fn variant_key_includes_overlay_and_bg() {
        let mut request = RenderRequest {
            chain: "base".to_string(),
            collection: "0xabc".to_string(),
            token_id: "1".to_string(),
            asset_id: "10".to_string(),
            format: OutputFormat::Png,
            cache_timestamp: None,
            cache_param_present: false,
            width_param: Some("medium".to_string()),
            og_mode: false,
            overlay: Some("watermark".to_string()),
            background: Some("#ffffff".to_string()),
        };
        let (_, base_key) = resolve_width(&request.width_param, request.og_mode).unwrap();
        let key = build_variant_key(&base_key, &request);
        assert!(key.contains("ov-watermark"));
        assert!(key.contains("bg-ffffff"));

        request.og_mode = true;
        let (_, base_key) = resolve_width(&request.width_param, request.og_mode).unwrap();
        let key = build_variant_key(&base_key, &request);
        assert!(key.contains("og"));
    }

    #[test]
    fn variant_key_normalizes_overlay_and_bg() {
        let request = RenderRequest {
            chain: "base".to_string(),
            collection: "0xabc".to_string(),
            token_id: "1".to_string(),
            asset_id: "10".to_string(),
            format: OutputFormat::Png,
            cache_timestamp: None,
            cache_param_present: false,
            width_param: Some("medium".to_string()),
            og_mode: false,
            overlay: Some("invalid".to_string()),
            background: Some("not-a-color".to_string()),
        };
        let (_, base_key) = resolve_width(&request.width_param, request.og_mode).unwrap();
        let key = build_variant_key(&base_key, &request);
        assert!(!key.contains("ov-"));
        assert!(!key.contains("bg-"));

        let transparent_request = RenderRequest {
            background: Some("transparent".to_string()),
            ..request
        };
        let (_, base_key) =
            resolve_width(&transparent_request.width_param, transparent_request.og_mode).unwrap();
        let key = build_variant_key(&base_key, &transparent_request);
        assert!(!key.contains("bg-"));
    }

    #[test]
    fn parse_color_hex() {
        let color = parse_color("#ff00aa").unwrap();
        assert_eq!(color.0, [255, 0, 170, 255]);
    }

    #[test]
    fn parse_color_transparent() {
        let color = parse_color("transparent").unwrap();
        assert_eq!(color.0, [0, 0, 0, 0]);
    }

    #[test]
    fn theme_color_normalization_accepts_hex() {
        assert_eq!(
            normalize_theme_color("#Aa11Bb").as_deref(),
            Some("#aa11bb")
        );
        assert!(normalize_theme_color("bad").is_none());
        assert!(normalize_theme_color("#12345").is_none());
    }

    #[test]
    fn theme_replacement_uses_svg_declared_sources() {
        let theme = ThemeReplaceMap {
            source: [
                "#ffe271".to_string(),
                "#a8f4ff".to_string(),
                "#5d74ab".to_string(),
                "#b4cffd".to_string(),
            ],
            dest: [
                "#5278ff".to_string(),
                "#31fcc6".to_string(),
                "#0e2f6b".to_string(),
                "#0a566d".to_string(),
            ],
        };
        let svg = b"<svg data-theme_color_1=\"#AABBCC\" fill=\"#aabbcc\" data-theme_color_2=\"#DDEEFF\" stroke=\"#DDeeFf\"></svg>";
        let sources = extract_svg_theme_sources(svg);
        let (themed, replaced) = apply_theme_to_svg_bytes(svg, &theme, &sources, true);
        assert!(replaced);
        let themed = std::str::from_utf8(&themed).unwrap();
        assert!(themed.contains("#5278ff"));
        assert!(themed.contains("#31fcc6"));
    }

    #[test]
    fn theme_replacement_falls_back_to_legacy_palette() {
        let theme = ThemeReplaceMap {
            source: [
                "#ffe271".to_string(),
                "#a8f4ff".to_string(),
                "#5d74ab".to_string(),
                "#b4cffd".to_string(),
            ],
            dest: [
                "#5278ff".to_string(),
                "#31fcc6".to_string(),
                "#0e2f6b".to_string(),
                "#0a566d".to_string(),
            ],
        };
        let svg = b"<svg fill=\"#FFE271\" stroke=\"#a8F4ff\"></svg>";
        let sources = [None, None, None, None];
        let (themed, replaced) = apply_theme_to_svg_bytes(svg, &theme, &sources, false);
        assert!(replaced);
        let themed = std::str::from_utf8(&themed).unwrap();
        assert!(themed.contains("#5278ff"));
        assert!(themed.contains("#31fcc6"));
    }

    #[tokio::test]
    async fn golden_render_kanaria() -> Result<()> {
        if env::var("LIVE_RENDER_GOLDEN_TESTS")
            .ok()
            .map(|value| value == "1")
            != Some(true)
        {
            return Ok(());
        }

        let rpc_raw = env::var("LIVE_BASE_RPC_URLS")
            .or_else(|_| env::var("LIVE_BASE_RPC_URL"))
            .context("LIVE_BASE_RPC_URLS not set")?;
        let render_utils = env::var("LIVE_BASE_RENDER_UTILS")
            .context("LIVE_BASE_RENDER_UTILS not set")?;
        let reference_1 = env::var("LIVE_RENDER_REF_1_URL")
            .context("LIVE_RENDER_REF_1_URL not set")?;
        let reference_3005 = env::var("LIVE_RENDER_REF_3005_URL")
            .context("LIVE_RENDER_REF_3005_URL not set")?;

        let rpc_urls = parse_rpc_urls(&rpc_raw)?;
        if rpc_urls.is_empty() {
            return Err(anyhow!("LIVE_BASE_RPC_URLS empty"));
        }

        let temp = tempdir().context("tempdir")?;
        let db_path = temp.path().join("renderer.db");
        let cache_dir = temp.path().join("cache");
        let _env_guard = EnvGuard::new(vec![
            ("ADMIN_PASSWORD", "test-secret".to_string()),
            ("DB_PATH", db_path.to_string_lossy().to_string()),
            ("CACHE_DIR", cache_dir.to_string_lossy().to_string()),
            (
                "RPC_ENDPOINTS",
                serde_json::json!({ "base": rpc_urls }).to_string(),
            ),
            (
                "RENDER_UTILS_ADDRESSES",
                serde_json::json!({ "base": render_utils }).to_string(),
            ),
            ("ACCESS_MODE", "open".to_string()),
        ]);

        let config = Config::from_env().context("config")?;
        let db = Database::new(&config).await.context("db")?;
        let cache = CacheManager::new(&config).context("cache")?;
        let ipfs_semaphore = Arc::new(Semaphore::new(config.max_concurrent_ipfs_fetches));
        let assets = AssetResolver::new(Arc::new(config.clone()), cache.clone(), ipfs_semaphore)
            .context("assets")?;
        let chain = ChainClient::new(Arc::new(config.clone()), db.clone());
        let state = Arc::new(AppState::new(
            config,
            db,
            cache,
            assets,
            chain,
            None,
            None,
        ));

        let collection = "0x011ff409bc4803ec5cfab41c3fd1db99fd05c004".to_string();
        let cache_timestamp = Some("1700787357000".to_string());

        let cases = [
            ("kanaria-1", "1", "9987", &reference_1),
            ("kanaria-3005", "3005", "15528", &reference_3005),
        ];

        for (label, token_id, asset_id, reference_url) in cases {
            let request = RenderRequest {
                chain: "base".to_string(),
                collection: collection.clone(),
                token_id: token_id.to_string(),
                asset_id: asset_id.to_string(),
                format: OutputFormat::Png,
                cache_timestamp: cache_timestamp.clone(),
                cache_param_present: true,
                width_param: Some("large".to_string()),
                og_mode: false,
                overlay: None,
                background: None,
            };

            let render = render_token(state.clone(), request).await?;
            let actual = decode_rgba(&render.bytes).context("decode local render")?;
            let reference_bytes = fetch_reference_bytes(reference_url).await?;
            let expected = decode_rgba(&reference_bytes).context("decode reference")?;

            assert_eq!(
                actual.dimensions(),
                expected.dimensions(),
                "{label} dimensions mismatch"
            );
            let actual_hash = sha256_hex_bytes(actual.as_raw());
            let expected_hash = sha256_hex_bytes(expected.as_raw());
            assert_eq!(
                actual_hash, expected_hash,
                "{label} pixel hash mismatch"
            );
        }

        Ok(())
    }

    fn parse_rpc_urls(raw: &str) -> Result<Vec<String>> {
        let trimmed = raw.trim();
        if trimmed.starts_with('[') {
            let urls: Vec<String> =
                serde_json::from_str(trimmed).context("parse rpc urls json")?;
            return Ok(urls);
        }
        let urls = trimmed
            .split(',')
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty())
            .collect::<Vec<_>>();
        Ok(urls)
    }

    async fn fetch_reference_bytes(url: &str) -> Result<Vec<u8>> {
        let response = reqwest::get(url).await.context("fetch reference")?;
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!("reference request failed: {status}"));
        }
        Ok(response.bytes().await?.to_vec())
    }

    fn decode_rgba(bytes: &[u8]) -> Result<RgbaImage> {
        let image = image::load_from_memory(bytes).context("decode image")?;
        Ok(image.to_rgba8())
    }

    struct EnvGuard {
        original: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        fn new(pairs: Vec<(&str, String)>) -> Self {
            let mut original = Vec::with_capacity(pairs.len());
            for (key, value) in pairs {
                let key_owned = key.to_string();
                let prev = env::var(key).ok();
                unsafe {
                    env::set_var(key, value);
                }
                original.push((key_owned, prev));
            }
            Self { original }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.original.drain(..) {
                if let Some(value) = value {
                    unsafe {
                        env::set_var(&key, value);
                    }
                } else {
                    unsafe {
                        env::remove_var(&key);
                    }
                }
            }
        }
    }

    #[test]
    fn sanitize_key_removes_bad_chars() {
        let key = sanitize_key("a/b?c");
        assert_eq!(key, "a-b-c");
    }

    #[test]
    fn parse_svg_rejects_external_urls() {
        let svg = r#"<svg><image href="https://example.org/x.png"/></svg>"#;
        let result = parse_svg(svg.as_bytes(), 10_000, 10_000, 50_000, 1_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn parse_svg_allows_xmlns_http_namespace() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"></svg>"#;
        let result = parse_svg(svg.as_bytes(), 10_000, 10_000, 50_000, 1_000_000);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_svg_allows_data_uri_image() {
        let svg = r#"<svg width="1" height="1"><image href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO6nY9sAAAAASUVORK5CYII=" width="1" height="1"/></svg>"#;
        let result = parse_svg(svg.as_bytes(), 50_000, 10_000, 50_000, 1_000_000);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_svg_disables_string_href_resolution() {
        reset_svg_string_resolver_called();
        let svg = r#"<svg width="1" height="1"><image href="/dev/zero" width="1" height="1"/></svg>"#;
        let result = parse_svg(svg.as_bytes(), 10_000, 10_000, 50_000, 1_000_000);
        assert!(result.is_ok());
        assert!(SVG_STRING_RESOLVER_CALLED.load(Ordering::Relaxed));
    }

    #[test]
    fn parse_svg_extract_viewbox() {
        let svg = r#"<svg viewBox="0 0 100 200"></svg>"#;
        let (width, height) = extract_svg_dimensions(svg).unwrap();
        assert_eq!(width, 100);
        assert_eq!(height, 200);
    }
}
