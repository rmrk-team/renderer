use crate::canonical;
use crate::db::WarmupJob;
use crate::render::{render_token, OutputFormat, RenderRequest};
use crate::state::AppState;
use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
pub struct WarmupRequest {
    pub chain: String,
    pub collection: String,
    pub token_ids: Option<Vec<String>>,
    pub asset_id: Option<String>,
    pub cache_timestamp: Option<String>,
    pub widths: Option<Vec<String>>,
    pub include_og: Option<bool>,
    pub strategy: Option<String>,
    pub from_block: Option<u64>,
    pub to_block: Option<u64>,
    pub range_start: Option<u64>,
    pub range_end: Option<u64>,
    pub allow_sequential: Option<bool>,
}

pub async fn enqueue_warmup(state: Arc<AppState>, request: WarmupRequest) -> Result<usize> {
    let (chain, collection) =
        canonical::canonicalize_collection(&request.chain, &request.collection, &state.config)?;
    let mut request = request;
    request.chain = chain.clone();
    request.collection = collection.clone();
    let token_ids = resolve_tokens(state.clone(), &request).await?;
    if token_ids.is_empty() {
        return Err(anyhow!("no tokens discovered for warmup"));
    }
    if state.config.warmup_max_tokens > 0 && token_ids.len() > state.config.warmup_max_tokens {
        return Err(anyhow!(
            "warmup token list exceeds limit ({} > {})",
            token_ids.len(),
            state.config.warmup_max_tokens
        ));
    }
    let widths = request
        .widths
        .clone()
        .unwrap_or_else(|| state.config.warmup_widths.clone());
    let widths_str = if widths.is_empty() {
        None
    } else {
        Some(widths.join(","))
    };
    let include_og = request
        .include_og
        .unwrap_or(state.config.warmup_include_og);
    let cache_timestamp = request.cache_timestamp.clone();

    let jobs = token_ids
        .into_iter()
        .map(|token_id| WarmupJob {
            id: 0,
            chain: chain.clone(),
            collection_address: collection.clone(),
            token_id,
            asset_id: request.asset_id.clone(),
            cache_timestamp: cache_timestamp.clone(),
            widths: widths_str.clone(),
            include_og,
            status: "queued".to_string(),
            last_error: None,
        })
        .collect::<Vec<_>>();
    state.db.insert_warmup_jobs(&jobs).await?;
    state.warmup_notify.notify_one();
    Ok(jobs.len())
}

pub async fn spawn_worker(state: Arc<AppState>) {
    loop {
        if state.db.is_warmup_paused().await.unwrap_or(false) {
            state.warmup_notify.notified().await;
            continue;
        }
        let job = match state.db.fetch_next_warmup_job().await {
            Ok(Some(job)) => job,
            Ok(None) => {
                tokio::select! {
                    _ = state.warmup_notify.notified() => {},
                    _ = sleep(Duration::from_secs(5)) => {},
                }
                continue;
            }
            Err(err) => {
                warn!(error = ?err, "warmup job fetch failed");
                sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        if state.render_semaphore.available_permits() == 0 {
            let _ = state
                .db
                .update_warmup_job_status(job.id, "queued", Some("renderer busy".to_string()))
                .await;
            sleep(Duration::from_secs(2)).await;
            continue;
        }

        let timeout = state.config.warmup_job_timeout_seconds;
        let result = if timeout == 0 {
            run_job(state.clone(), job.clone()).await
        } else {
            match tokio::time::timeout(Duration::from_secs(timeout), run_job(state.clone(), job.clone())).await {
                Ok(result) => result,
                Err(_) => {
                    let _ = state
                        .db
                        .update_warmup_job_status(job.id, "failed", Some("warmup timeout".to_string()))
                        .await;
                    continue;
                }
            }
        };

        if let Err(err) = result {
            warn!(error = ?err, "warmup job failed");
            let _ = state
                .db
                .update_warmup_job_status(job.id, "failed", Some(err.to_string()))
                .await;
        }
    }
}

async fn run_job(state: Arc<AppState>, job: WarmupJob) -> Result<()> {
    if state.db.is_warmup_job_canceled(job.id).await? {
        return Ok(());
    }
    let asset_id = match job.asset_id.clone() {
        Some(asset_id) => asset_id,
        None => {
            let _permit = state.rpc_semaphore.acquire().await?;
            let asset_id = state
                .chain
                .get_top_asset_id(&job.chain, &job.collection_address, &job.token_id)
                .await?;
            asset_id.to_string()
        }
    };
    let cache_timestamp = match crate::render::resolve_cache_timestamp(
        &state,
        &job.chain,
        &job.collection_address,
        job.cache_timestamp.clone(),
    )
    .await?
    {
        Some(value) => value,
        None => {
            return Err(anyhow!(
                "cache_timestamp required for warmup renders (or set DEFAULT_CACHE_TIMESTAMP)"
            ))
        }
    };
    let widths = parse_widths(job.widths.as_deref(), &state);
    let mut widths = widths;
    let max_renders = state.config.warmup_max_renders_per_job;
    if max_renders > 0 {
        let reserved_for_og = if job.include_og { 1 } else { 0 };
        let allow_widths = max_renders.saturating_sub(reserved_for_og);
        if widths.len() > allow_widths {
            widths.truncate(allow_widths);
        }
    }
    let mut errors = Vec::new();

    for width in widths {
        if state.db.is_warmup_job_canceled(job.id).await? {
            return Ok(());
        }
        let request = RenderRequest {
            chain: job.chain.clone(),
            collection: job.collection_address.clone(),
            token_id: job.token_id.clone(),
            asset_id: asset_id.clone(),
            format: OutputFormat::Webp,
            cache_timestamp: Some(cache_timestamp.clone()),
            width_param: Some(width),
            og_mode: false,
            overlay: None,
            background: None,
        };
        match render_token(state.clone(), request).await {
            Ok(response) => {
                if !response.complete {
                    errors.push("missing layers".to_string());
                }
            }
            Err(err) => errors.push(err.to_string()),
        }
    }

    if job.include_og {
        if state.db.is_warmup_job_canceled(job.id).await? {
            return Ok(());
        }
        let request = RenderRequest {
            chain: job.chain.clone(),
            collection: job.collection_address.clone(),
            token_id: job.token_id.clone(),
            asset_id: asset_id.clone(),
            format: OutputFormat::Webp,
            cache_timestamp: Some(cache_timestamp.clone()),
            width_param: None,
            og_mode: true,
            overlay: None,
            background: None,
        };
        match render_token(state.clone(), request).await {
            Ok(response) => {
                if !response.complete {
                    errors.push("missing layers".to_string());
                }
            }
            Err(err) => errors.push(err.to_string()),
        }
    }

    if errors.is_empty() {
        if state.db.is_warmup_job_canceled(job.id).await? {
            return Ok(());
        }
        state
            .db
            .update_warmup_job_status(job.id, "done", None)
            .await?;
        info!(
            chain = %job.chain,
            collection = %job.collection_address,
            token_id = %job.token_id,
            "warmup job completed"
        );
        Ok(())
    } else {
        if state.db.is_warmup_job_canceled(job.id).await? {
            return Ok(());
        }
        let error = errors.join("; ");
        state
            .db
            .update_warmup_job_status(job.id, "failed", Some(error.clone()))
            .await?;
        Err(anyhow!(error))
    }
}

fn parse_widths(raw: Option<&str>, state: &AppState) -> Vec<String> {
    if let Some(raw) = raw {
        let widths = raw
            .split(',')
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if !widths.is_empty() {
            return widths;
        }
    }
    state.config.warmup_widths.clone()
}

async fn resolve_tokens(state: Arc<AppState>, request: &WarmupRequest) -> Result<Vec<String>> {
    let strategy = request
        .strategy
        .clone()
        .unwrap_or_else(|| "auto".to_string());
    match strategy.as_str() {
        "list" | "admin" => request
            .token_ids
            .clone()
            .ok_or_else(|| anyhow!("token_ids required for list strategy")),
        "erc721_enumerable" => state
            .chain
            .erc721_token_ids_enumerable(&request.chain, &request.collection)
            .await,
        "transfer_log" => {
            let from_block = request
                .from_block
                .ok_or_else(|| anyhow!("from_block required for transfer_log"))?;
            let to_block = request
                .to_block
                .ok_or_else(|| anyhow!("to_block required for transfer_log"))?;
            validate_log_span(&state, from_block, to_block)?;
            let tokens = state
                .chain
                .scan_transfer_logs(&request.chain, &request.collection, from_block, to_block)
                .await?;
            Ok(dedup(tokens))
        }
        "sequential" => {
            if !request.allow_sequential.unwrap_or(false) {
                return Err(anyhow!("sequential strategy disabled"));
            }
            let start = request
                .range_start
                .ok_or_else(|| anyhow!("range_start required"))?;
            let end = request.range_end.ok_or_else(|| anyhow!("range_end required"))?;
            if end < start {
                return Err(anyhow!("range_end must be >= range_start"));
            }
            let count = end.saturating_sub(start).saturating_add(1);
            if state.config.warmup_max_tokens > 0
                && count as usize > state.config.warmup_max_tokens
            {
                return Err(anyhow!(
                    "sequential range exceeds warmup token limit ({} > {})",
                    count,
                    state.config.warmup_max_tokens
                ));
            }
            Ok((start..=end).map(|id| id.to_string()).collect())
        }
        "auto" => {
            if let Some(tokens) = request.token_ids.clone() {
                if !tokens.is_empty() {
                    return Ok(tokens);
                }
            }
            if let Ok(tokens) = state
                .chain
                .erc721_token_ids_enumerable(&request.chain, &request.collection)
                .await
            {
                if !tokens.is_empty() {
                    return Ok(tokens);
                }
            }
            if request.from_block.is_some() && request.to_block.is_some() {
                validate_log_span(
                    &state,
                    request.from_block.unwrap(),
                    request.to_block.unwrap(),
                )?;
                let tokens = state
                    .chain
                    .scan_transfer_logs(
                        &request.chain,
                        &request.collection,
                        request.from_block.unwrap(),
                        request.to_block.unwrap(),
                    )
                    .await?;
                return Ok(dedup(tokens));
            }
            if request.allow_sequential.unwrap_or(false) {
                let start = request
                    .range_start
                    .ok_or_else(|| anyhow!("range_start required"))?;
                let end = request.range_end.ok_or_else(|| anyhow!("range_end required"))?;
                return Ok((start..=end).map(|id| id.to_string()).collect());
            }
            Err(anyhow!("no viable warmup strategy"))
        }
        other => Err(anyhow!("unknown warmup strategy: {other}")),
    }
}

fn dedup(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn validate_log_span(state: &AppState, from_block: u64, to_block: u64) -> Result<()> {
    if to_block < from_block {
        return Err(anyhow!("to_block must be >= from_block"));
    }
    let max_span = state.config.warmup_max_block_span;
    if max_span == 0 {
        return Ok(());
    }
    let span = to_block.saturating_sub(from_block);
    if span > max_span {
        return Err(anyhow!(
            "transfer_log range exceeds max block span ({} > {})",
            span,
            max_span
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_tokens() {
        let tokens = vec!["1".to_string(), "2".to_string(), "1".to_string()];
        let deduped = dedup(tokens);
        assert_eq!(deduped.len(), 2);
        assert!(deduped.contains(&"1".to_string()));
        assert!(deduped.contains(&"2".to_string()));
    }

}
