use super::*;
use crate::db::TokenStateCacheEntry;

pub(super) fn build_layers(compose: &ComposeResult) -> Vec<Layer> {
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
        let has_child = !part.child_asset_metadata.trim().is_empty();
        if !has_child && !part.part_metadata.trim().is_empty() {
            layers.push(Layer {
                z: part.z,
                required: false,
                kind: LayerKind::SlotPart,
                metadata_uri: part.part_metadata.clone(),
            });
        }
        if has_child {
            layers.push(Layer {
                z: part.z,
                required: false,
                kind: LayerKind::SlotChild,
                metadata_uri: part.child_asset_metadata.clone(),
            });
        }
    }
    layers
}

pub(super) fn layer_sort_key(layer: &Layer) -> (u16, u8) {
    let order = match layer.kind {
        LayerKind::Fixed => 0,
        LayerKind::SlotPart => 1,
        LayerKind::SlotChild => 2,
        LayerKind::Overlay => 3,
    };
    (layer.z as u16, order)
}

pub(super) fn overlay_layer(config: &CollectionConfig, request: &RenderRequest) -> Option<Layer> {
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

pub(super) async fn load_compose_for_request(
    state: &AppState,
    chain: &str,
    collection: &str,
    token_id: &str,
    asset_id: &str,
    fresh: bool,
) -> Result<(ComposeResult, bool)> {
    let now = now_epoch();
    let ttl = i64::try_from(state.config.token_state_check_ttl_seconds).unwrap_or(i64::MAX);
    let expires_at = now.saturating_add(ttl.max(0));
    let db_get_started = Instant::now();
    let cached_entry = state
        .db
        .get_token_state(chain, collection, token_id, asset_id)
        .await?;
    debug!(
        step = "compose_db_get",
        elapsed_ms = db_get_started.elapsed().as_millis(),
        chain = %chain,
        collection = %collection,
        token_id = %token_id,
        asset_id = %asset_id,
        cache_hit = cached_entry.is_some(),
        "compose profile"
    );
    let cached_compose = cached_entry
        .as_ref()
        .and_then(|entry| entry.state_json.as_ref())
        .and_then(|value| serde_json::from_str::<ComposeResult>(value).ok());
    let cached_fallback = cached_entry
        .as_ref()
        .map(|entry| entry.fallback_used)
        .unwrap_or(false);
    let cached_valid = cached_entry
        .as_ref()
        .map(|entry| entry.expires_at > now)
        .unwrap_or(false);
    let cached_error = cached_entry
        .as_ref()
        .and_then(|entry| entry.last_error.as_ref())
        .map(|value| value.to_string());
    if !fresh {
        if let Some(compose) = cached_compose.clone() {
            if cached_valid {
                debug!(
                    step = "compose_cache_hit",
                    chain = %chain,
                    collection = %collection,
                    token_id = %token_id,
                    asset_id = %asset_id,
                    fallback_used = cached_fallback,
                    "compose profile"
                );
                return Ok((compose, cached_fallback));
            }
        }
        if cached_valid && cached_compose.is_none() {
            if let (Some(error), Some(entry)) = (cached_error.clone(), cached_entry.as_ref()) {
                let retry_after_seconds = entry.expires_at.saturating_sub(now).max(0) as u64;
                debug!(
                    step = "compose_cache_error_hit",
                    chain = %chain,
                    collection = %collection,
                    token_id = %token_id,
                    asset_id = %asset_id,
                    retry_after_seconds,
                    "compose profile"
                );
                return Err(TokenStateCachedError {
                    error,
                    retry_after_seconds,
                }
                .into());
            }
        }
    }

    let singleflight_key = format!("{chain}:{collection}:{token_id}:{asset_id}");
    let permit = state
        .token_state_singleflight
        .acquire(&singleflight_key)
        .await;
    if !permit.is_leader() {
        let wait_started = Instant::now();
        let _ = permit.wait_result(Duration::from_secs(30)).await;
        debug!(
            step = "compose_singleflight_wait",
            elapsed_ms = wait_started.elapsed().as_millis(),
            chain = %chain,
            collection = %collection,
            token_id = %token_id,
            asset_id = %asset_id,
            "compose profile"
        );
        if let Some(entry) = state
            .db
            .get_token_state(chain, collection, token_id, asset_id)
            .await?
        {
            if let Some(state_json) = entry.state_json.as_ref() {
                if let Ok(compose) = serde_json::from_str::<ComposeResult>(state_json) {
                    debug!(
                        step = "compose_singleflight_cache_hit",
                        chain = %chain,
                        collection = %collection,
                        token_id = %token_id,
                        asset_id = %asset_id,
                        fallback_used = entry.fallback_used,
                        "compose profile"
                    );
                    return Ok((compose, entry.fallback_used));
                }
            }
            if entry.expires_at > now {
                if let Some(error) = entry.last_error.as_ref() {
                    let retry_after_seconds = entry.expires_at.saturating_sub(now).max(0) as u64;
                    debug!(
                        step = "compose_singleflight_error_hit",
                        chain = %chain,
                        collection = %collection,
                        token_id = %token_id,
                        asset_id = %asset_id,
                        retry_after_seconds,
                        "compose profile"
                    );
                    return Err(TokenStateCachedError {
                        error: error.to_string(),
                        retry_after_seconds,
                    }
                    .into());
                }
            }
        }
    }

    let (compose, fallback_used) = if asset_id == TOKEN_URI_FALLBACK_ASSET_ID {
        let cache_key = crate::state::token_uri_negative_cache_key(chain, collection);
        if let Some(retry_after_seconds) = state
            .token_uri_negative_cache
            .get_retry_after(&cache_key)
            .await
        {
            warn!(
                chain = %chain,
                collection = %collection,
                token_id = %token_id,
                retry_after_seconds,
                "token URI negative cache hit"
            );
            return Err(TokenUriNegativeCacheError {
                retry_after_seconds,
            }
            .into());
        }
        let token_uri_started = Instant::now();
        let token_uri = match state.chain.get_token_uri(chain, collection, token_id).await {
            Ok(value) => value,
            Err(err) => {
                warn!(
                    chain = %chain,
                    collection = %collection,
                    token_id = %token_id,
                    error = ?err,
                    "token URI lookup failed"
                );
                if crate::chain::is_contract_revert_error(&err) {
                    state
                        .token_uri_negative_cache
                        .insert(cache_key.clone())
                        .await;
                }
                let error_string = err.to_string();
                let error_expires_at =
                    token_state_error_expires_at(state, &err, cached_entry.as_ref(), &error_string);
                let _ = state
                    .db
                    .record_token_state_error(
                        chain,
                        collection,
                        token_id,
                        asset_id,
                        &error_string,
                        error_expires_at,
                    )
                    .await;
                return Err(err);
            }
        };
        let token_uri = token_uri.trim();
        state.token_uri_negative_cache.remove(&cache_key).await;
        if token_uri.is_empty() {
            warn!(
                chain = %chain,
                collection = %collection,
                token_id = %token_id,
                "token URI empty"
            );
            let err = anyhow::Error::new(TokenUriEmptyError);
            let error_string = err.to_string();
            let error_expires_at =
                token_state_error_expires_at(state, &err, cached_entry.as_ref(), &error_string);
            let _ = state
                .db
                .record_token_state_error(
                    chain,
                    collection,
                    token_id,
                    asset_id,
                    &error_string,
                    error_expires_at,
                )
                .await;
            return Err(err);
        }
        debug!(
            step = "compose_fallback_token_uri",
            elapsed_ms = token_uri_started.elapsed().as_millis(),
            chain = %chain,
            collection = %collection,
            token_id = %token_id,
            asset_id = %asset_id,
            "compose profile"
        );
        (
            ComposeResult {
                metadata_uri: token_uri.to_string(),
                catalog_address: "0x0000000000000000000000000000000000000000".to_string(),
                fixed_parts: vec![FixedPart {
                    part_id: 0,
                    z: 0,
                    metadata_uri: token_uri.to_string(),
                }],
                slot_parts: Vec::<SlotPart>::new(),
            },
            true,
        )
    } else {
        let compose_started = Instant::now();
        let refresh_result = state
            .chain
            .compose_equippables(chain, collection, token_id, asset_id)
            .await;
        debug!(
            step = "compose_equippables",
            elapsed_ms = compose_started.elapsed().as_millis(),
            chain = %chain,
            collection = %collection,
            token_id = %token_id,
            asset_id = %asset_id,
            status = if refresh_result.is_ok() { "ok" } else { "error" },
            "compose profile"
        );
        match refresh_result {
            Ok(compose) => (compose, false),
            Err(err) => {
                if !is_non_composable_error(&err) {
                    let record_started = Instant::now();
                    let error_string = err.to_string();
                    let error_expires_at = token_state_error_expires_at(
                        state,
                        &err,
                        cached_entry.as_ref(),
                        &error_string,
                    );
                    let _ = state
                        .db
                        .record_token_state_error(
                            chain,
                            collection,
                            token_id,
                            asset_id,
                            &error_string,
                            error_expires_at,
                        )
                        .await;
                    debug!(
                        step = "compose_record_error",
                        elapsed_ms = record_started.elapsed().as_millis(),
                        chain = %chain,
                        collection = %collection,
                        token_id = %token_id,
                        asset_id = %asset_id,
                        "compose profile"
                    );
                    if let Some(compose) = cached_compose {
                        return Ok((compose, cached_fallback));
                    }
                    return Err(err);
                }
                debug!(
                    error = ?err,
                    chain = %chain,
                    collection = %collection,
                    token_id = %token_id,
                    asset_id = %asset_id,
                    "asset is non-composable; falling back to static asset metadata"
                );
                let metadata_started = Instant::now();
                let metadata_uri = state
                    .chain
                    .get_asset_metadata(chain, collection, token_id, asset_id)
                    .await?;
                debug!(
                    step = "compose_fallback_metadata",
                    elapsed_ms = metadata_started.elapsed().as_millis(),
                    chain = %chain,
                    collection = %collection,
                    token_id = %token_id,
                    asset_id = %asset_id,
                    "compose profile"
                );
                let part_id = asset_id.parse::<u64>().context("invalid asset id")?;
                (
                    ComposeResult {
                        metadata_uri: metadata_uri.clone(),
                        catalog_address: "0x0000000000000000000000000000000000000000".to_string(),
                        fixed_parts: vec![FixedPart {
                            part_id,
                            z: 0,
                            metadata_uri,
                        }],
                        slot_parts: Vec::<SlotPart>::new(),
                    },
                    true,
                )
            }
        }
    };

    if !is_zero_address(&compose.catalog_address) {
        let catalog_started = Instant::now();
        let _ = state
            .db
            .set_collection_catalog_address(chain, collection, &compose.catalog_address)
            .await;
        debug!(
            step = "compose_set_catalog",
            elapsed_ms = catalog_started.elapsed().as_millis(),
            chain = %chain,
            collection = %collection,
            token_id = %token_id,
            asset_id = %asset_id,
            "compose profile"
        );
    }
    if let Ok(state_json) = serde_json::to_string(&compose) {
        let state_hash = sha256_hex_bytes(state_json.as_bytes());
        let upsert_started = Instant::now();
        let _ = state
            .db
            .upsert_token_state(
                chain,
                collection,
                token_id,
                asset_id,
                &state_hash,
                Some(&state_json),
                None,
                expires_at,
                fallback_used,
            )
            .await;
        debug!(
            step = "compose_upsert_state",
            elapsed_ms = upsert_started.elapsed().as_millis(),
            chain = %chain,
            collection = %collection,
            token_id = %token_id,
            asset_id = %asset_id,
            "compose profile"
        );
    }
    Ok((compose, fallback_used))
}

fn token_state_error_expires_at(
    state: &AppState,
    err: &anyhow::Error,
    cached_entry: Option<&TokenStateCacheEntry>,
    error_label: &str,
) -> i64 {
    let ttl_seconds = if is_permanent_token_state_error(err) {
        permanent_error_backoff_ttl(
            state.config.token_state_error_permanent_ttl_seconds,
            cached_entry,
            error_label,
        )
    } else {
        state.config.token_state_error_ttl_seconds
    };
    let ttl = i64::try_from(ttl_seconds).unwrap_or(i64::MAX);
    now_epoch().saturating_add(ttl.max(0))
}

fn is_permanent_token_state_error(err: &anyhow::Error) -> bool {
    crate::chain::is_contract_revert_error(err)
        || err.downcast_ref::<TokenUriEmptyError>().is_some()
}

fn permanent_error_backoff_ttl(
    base_ttl_seconds: u64,
    cached_entry: Option<&TokenStateCacheEntry>,
    error_label: &str,
) -> u64 {
    if base_ttl_seconds == 0 {
        return 0;
    }
    let mut ttl = base_ttl_seconds;
    if let Some(entry) = cached_entry {
        if entry.last_error.as_deref() == Some(error_label) {
            let previous_ttl = entry
                .expires_at
                .saturating_sub(entry.last_checked_at)
                .max(0) as u64;
            let step_one = base_ttl_seconds;
            let step_two = base_ttl_seconds.saturating_mul(6);
            let step_three = base_ttl_seconds.saturating_mul(24);
            ttl = if previous_ttl >= step_two {
                step_three
            } else if previous_ttl >= step_one {
                step_two
            } else {
                step_one
            };
        }
    }
    ttl
}
