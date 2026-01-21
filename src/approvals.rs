use crate::canonical;
use crate::chain::{ApprovalRevokedFilter, ApprovalUpdatedFilter};
use crate::config::Config;
use crate::state::AppState;
use anyhow::Result;
use ethers::prelude::*;
use std::cmp::min;
use std::str::FromStr;
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tracing::{info, warn};

pub async fn spawn_approval_watchers(state: Arc<AppState>) {
    if !state.config.require_approval || state.config.approval_contracts.is_empty() {
        return;
    }
    if state.config.approval_poll_interval_seconds == 0 {
        warn!("approval watcher disabled (APPROVAL_POLL_INTERVAL_SECONDS=0)");
        return;
    }
    for chain in approval_watch_chains(&state.config) {
        let chain = chain.to_string();
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = watch_chain(state, chain).await {
                warn!(error = ?err, "approval watcher stopped");
            }
        });
    }
}

pub async fn spawn_approval_sync(state: Arc<AppState>) {
    if !state.config.require_approval || state.config.approval_contracts.is_empty() {
        return;
    }
    if state.config.approval_sync_interval_seconds == 0 {
        return;
    }
    for chain in approval_watch_chains(&state.config) {
        let chain = chain.to_string();
        let state = state.clone();
        tokio::spawn(async move {
            let mut first = true;
            loop {
                if let Err(err) = sync_chain(state.clone(), &chain).await {
                    warn!(error = ?err, "approval sync failed");
                }
                if first {
                    first = false;
                }
                sleep(Duration::from_secs(
                    state.config.approval_sync_interval_seconds,
                ))
                .await;
            }
        });
    }
}

fn approval_watch_chains(config: &Config) -> Vec<String> {
    if let Some(chain) = config.approvals_contract_chain.as_ref() {
        return vec![chain.clone()];
    }
    config.approval_contracts.keys().cloned().collect()
}

async fn watch_chain(state: Arc<AppState>, chain: String) -> Result<()> {
    loop {
        let latest_block = match state
            .chain
            .call_with_approvals(&chain, |contract| async move {
                let provider = contract.client();
                provider.get_block_number().await.map_err(|err| err.into())
            })
            .await
        {
            Ok(Some(block)) => block.as_u64(),
            Ok(None) => {
                sleep(Duration::from_secs(
                    state.config.approval_poll_interval_seconds,
                ))
                .await;
                continue;
            }
            Err(err) => {
                warn!(error = ?err, "approval watcher failed to fetch block number");
                sleep(Duration::from_secs(
                    state.config.approval_poll_interval_seconds,
                ))
                .await;
                continue;
            }
        };
        let confirmed_latest = latest_block.saturating_sub(state.config.approval_confirmations);

        let start_block = if let Some(last) = state.db.get_approval_last_block(&chain).await? {
            (last as u64).saturating_add(1)
        } else if let Some(start) = state.config.approval_start_blocks.get(&chain) {
            *start
        } else {
            confirmed_latest
        };

        if start_block > confirmed_latest {
            sleep(Duration::from_secs(
                state.config.approval_poll_interval_seconds,
            ))
            .await;
            continue;
        }

        let to_block = min(start_block + 10_000, confirmed_latest);
        let updated_events = match state
            .chain
            .call_with_approvals(&chain, |contract| async move {
                contract
                    .approval_updated_filter()
                    .from_block(start_block)
                    .to_block(to_block)
                    .query()
                    .await
                    .map_err(|err| err.into())
            })
            .await
        {
            Ok(Some(events)) => events,
            Ok(None) => {
                sleep(Duration::from_secs(
                    state.config.approval_poll_interval_seconds,
                ))
                .await;
                continue;
            }
            Err(err) => {
                warn!(error = ?err, "approval watcher failed to query updates");
                sleep(Duration::from_secs(
                    state.config.approval_poll_interval_seconds,
                ))
                .await;
                continue;
            }
        };
        let revoked_events = match state
            .chain
            .call_with_approvals(&chain, |contract| async move {
                contract
                    .approval_revoked_filter()
                    .from_block(start_block)
                    .to_block(to_block)
                    .query()
                    .await
                    .map_err(|err| err.into())
            })
            .await
        {
            Ok(Some(events)) => events,
            Ok(None) => {
                sleep(Duration::from_secs(
                    state.config.approval_poll_interval_seconds,
                ))
                .await;
                continue;
            }
            Err(err) => {
                warn!(error = ?err, "approval watcher failed to query revokes");
                sleep(Duration::from_secs(
                    state.config.approval_poll_interval_seconds,
                ))
                .await;
                continue;
            }
        };

        for event in updated_events {
            if let Err(err) = handle_update(state.clone(), &chain, &event).await {
                warn!(error = ?err, "approval watcher failed to handle update");
            }
        }
        for event in revoked_events {
            if let Err(err) = handle_revoke(state.clone(), &chain, &event).await {
                warn!(error = ?err, "approval watcher failed to handle revoke");
            }
        }

        if let Err(err) = state
            .db
            .set_approval_last_block(&chain, to_block as i64)
            .await
        {
            warn!(error = ?err, "approval watcher failed to persist last block");
        }

        sleep(Duration::from_secs(
            state.config.approval_poll_interval_seconds,
        ))
        .await;
    }
}

async fn handle_update(
    state: Arc<AppState>,
    watcher_chain: &str,
    event: &ApprovalUpdatedFilter,
) -> Result<()> {
    let chain_id = event.chain_id.as_u64();
    let target_chain = match state.config.chain_id_map.get(&chain_id) {
        Some(chain) => chain.to_string(),
        None => {
            let collection_address = format!("{:#x}", event.collection);
            let payer = format!("{:#x}", event.payer);
            state
                .db
                .insert_approval_quarantine(
                    watcher_chain,
                    chain_id,
                    &collection_address,
                    &payer,
                    &event.amount_paid.to_string(),
                )
                .await?;
            warn!(
                chain_id = chain_id,
                chain = %watcher_chain,
                collection = %collection_address,
                "approval event chainId is not mapped; quarantined"
            );
            return Ok(());
        }
    };
    let chain = match canonical::canonicalize_chain(&target_chain, &state.config) {
        Ok(chain) => chain,
        Err(err) => {
            let collection_address = format!("{:#x}", event.collection);
            let payer = format!("{:#x}", event.payer);
            state
                .db
                .insert_approval_quarantine(
                    watcher_chain,
                    chain_id,
                    &collection_address,
                    &payer,
                    &event.amount_paid.to_string(),
                )
                .await?;
            warn!(
                error = ?err,
                chain = %target_chain,
                chain_id = chain_id,
                collection = %collection_address,
                "approval event chainId mapped to invalid chain; quarantined"
            );
            return Ok(());
        }
    };
    let collection_address = format!("{:#x}", event.collection);
    let collection_address = canonical::canonicalize_collection_address(&collection_address)?;
    let approved_until = approval_until_to_i64(event.approved_until);
    state
        .db
        .upsert_collection_approval(&chain, &collection_address, approved_until, "event", None)
        .await?;
    state
        .invalidate_collection_cache(&chain, &collection_address)
        .await;
    info!(
        chain = %chain,
        collection = %collection_address,
        "collection approved via on-chain event"
    );
    Ok(())
}

async fn handle_revoke(
    state: Arc<AppState>,
    watcher_chain: &str,
    event: &ApprovalRevokedFilter,
) -> Result<()> {
    let chain_id = event.chain_id.as_u64();
    let target_chain = match state.config.chain_id_map.get(&chain_id) {
        Some(chain) => chain.to_string(),
        None => {
            let collection_address = format!("{:#x}", event.collection);
            state
                .db
                .insert_approval_quarantine(
                    watcher_chain,
                    chain_id,
                    &collection_address,
                    "0x0000000000000000000000000000000000000000",
                    "0",
                )
                .await?;
            warn!(
                chain_id = chain_id,
                chain = %watcher_chain,
                collection = %collection_address,
                "approval revoke chainId is not mapped; quarantined"
            );
            return Ok(());
        }
    };
    let chain = match canonical::canonicalize_chain(&target_chain, &state.config) {
        Ok(chain) => chain,
        Err(err) => {
            let collection_address = format!("{:#x}", event.collection);
            state
                .db
                .insert_approval_quarantine(
                    watcher_chain,
                    chain_id,
                    &collection_address,
                    "0x0000000000000000000000000000000000000000",
                    "0",
                )
                .await?;
            warn!(
                error = ?err,
                chain = %target_chain,
                chain_id = chain_id,
                collection = %collection_address,
                "approval revoke chainId mapped to invalid chain; quarantined"
            );
            return Ok(());
        }
    };
    let collection_address = format!("{:#x}", event.collection);
    let collection_address = canonical::canonicalize_collection_address(&collection_address)?;
    state
        .db
        .upsert_collection_approval(&chain, &collection_address, 0, "event", None)
        .await?;
    state
        .invalidate_collection_cache(&chain, &collection_address)
        .await;
    info!(
        chain = %chain,
        collection = %collection_address,
        "collection approval revoked via on-chain event"
    );
    Ok(())
}

async fn sync_chain(state: Arc<AppState>, contract_chain: &str) -> Result<()> {
    sync_known_collections(state.clone(), contract_chain).await?;
    if state.config.approval_enumeration_enabled {
        sync_all_collections(state, contract_chain).await?;
    }
    Ok(())
}

async fn sync_known_collections(state: Arc<AppState>, contract_chain: &str) -> Result<()> {
    let collections = state.db.list_collections().await?;
    for collection in collections {
        let chain_id = match state.config.chain_id_for_name(&collection.chain) {
            Some(chain_id) => chain_id,
            None => continue,
        };
        let address = Address::from_str(&collection.collection_address)?;
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
            return Ok(());
        };
        let approved_until = approval_until_to_i64(approved_until);
        state
            .db
            .upsert_collection_approval(
                &collection.chain,
                &collection.collection_address,
                approved_until,
                "state_sync",
                None,
            )
            .await?;
        state
            .invalidate_collection_cache(&collection.chain, &collection.collection_address)
            .await;
    }
    Ok(())
}

async fn sync_all_collections(state: Arc<AppState>, watcher_chain: &str) -> Result<()> {
    let total = match state
        .chain
        .call_with_approvals(watcher_chain, |contract| async move {
            contract
                .approval_key_count()
                .call()
                .await
                .map_err(|err| err.into())
        })
        .await?
    {
        Some(total) => total.as_u64(),
        None => return Ok(()),
    };
    if total == 0 {
        return Ok(());
    }
    let mut start = 0u64;
    let page = 200u64;
    while start < total {
        let result = state
            .chain
            .call_with_approvals(watcher_chain, move |contract| async move {
                contract
                    .approval_keys_page(start.into(), page.into())
                    .call()
                    .await
                    .map_err(|err| err.into())
            })
            .await?;
        let Some((chain_ids, collections, approved_untils)) = result else {
            return Ok(());
        };
        for ((chain_id, collection), approved_until) in chain_ids
            .into_iter()
            .zip(collections.into_iter())
            .zip(approved_untils.into_iter())
        {
            let chain_id = chain_id.as_u64();
            let chain = match state.config.chain_id_map.get(&chain_id) {
                Some(chain) => chain.to_string(),
                None => {
                    let collection_address = format!("{:#x}", collection);
                    state
                        .db
                        .insert_approval_quarantine(
                            watcher_chain,
                            chain_id,
                            &collection_address,
                            "0x0000000000000000000000000000000000000000",
                            "0",
                        )
                        .await?;
                    warn!(
                        chain_id = chain_id,
                        chain = %watcher_chain,
                        collection = %collection_address,
                        "approval key chainId is not mapped; quarantined"
                    );
                    continue;
                }
            };
            let chain = match canonical::canonicalize_chain(&chain, &state.config) {
                Ok(chain) => chain,
                Err(err) => {
                    let collection_address = format!("{:#x}", collection);
                    state
                        .db
                        .insert_approval_quarantine(
                            watcher_chain,
                            chain_id,
                            &collection_address,
                            "0x0000000000000000000000000000000000000000",
                            "0",
                        )
                        .await?;
                    warn!(
                        error = ?err,
                        chain = %chain,
                        chain_id = chain_id,
                        collection = %collection_address,
                        "approval key mapped to invalid chain; quarantined"
                    );
                    continue;
                }
            };
            let collection_address = format!("{:#x}", collection);
            let collection_address =
                canonical::canonicalize_collection_address(&collection_address)?;
            let approved_until = approval_until_to_i64(approved_until);
            state
                .db
                .upsert_collection_approval(
                    &chain,
                    &collection_address,
                    approved_until,
                    "state_sync",
                    None,
                )
                .await?;
            state
                .invalidate_collection_cache(&chain, &collection_address)
                .await;
        }
        start = start.saturating_add(page);
    }
    Ok(())
}

fn approval_until_to_i64(value: u64) -> i64 {
    let max = i64::MAX as u64;
    if value > max { i64::MAX } else { value as i64 }
}
