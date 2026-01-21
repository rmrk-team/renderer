use crate::db::{Database, UsageBatchRow};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct UsageEvent {
    pub hour_bucket: i64,
    pub identity_key: Arc<str>,
    pub route_group: &'static str,
    pub bytes_out: i64,
    pub cache_hit: bool,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct UsageKey {
    hour_bucket: i64,
    identity_key: Arc<str>,
    route_group: &'static str,
}

#[derive(Debug, Default, Clone)]
struct UsageTotals {
    requests: i64,
    bytes_out: i64,
    cache_hits: i64,
    cache_misses: i64,
}

pub async fn run_usage_aggregator(
    db: Database,
    mut receiver: mpsc::Receiver<UsageEvent>,
    flush_interval: Duration,
    max_entries: usize,
) {
    let mut ticker = tokio::time::interval(flush_interval);
    let mut buffer: HashMap<UsageKey, UsageTotals> = HashMap::new();
    loop {
        tokio::select! {
            event = receiver.recv() => {
                match event {
                    Some(event) => {
                        let key = UsageKey {
                            hour_bucket: event.hour_bucket,
                            identity_key: event.identity_key,
                            route_group: event.route_group,
                        };
                        let totals = buffer.entry(key).or_default();
                        totals.requests = totals.requests.saturating_add(1);
                        totals.bytes_out = totals.bytes_out.saturating_add(event.bytes_out);
                        if event.cache_hit {
                            totals.cache_hits = totals.cache_hits.saturating_add(1);
                        } else {
                            totals.cache_misses = totals.cache_misses.saturating_add(1);
                        }
                        if max_entries > 0 && buffer.len() >= max_entries {
                            if let Err(err) = flush_usage(&db, &mut buffer).await {
                                warn!(error = ?err, "usage aggregation flush failed");
                            }
                        }
                    }
                    None => break,
                }
            }
            _ = ticker.tick() => {
                if let Err(err) = flush_usage(&db, &mut buffer).await {
                    warn!(error = ?err, "usage aggregation flush failed");
                }
            }
        }
    }
    if let Err(err) = flush_usage(&db, &mut buffer).await {
        warn!(error = ?err, "usage aggregation final flush failed");
    }
}

async fn flush_usage(
    db: &Database,
    buffer: &mut HashMap<UsageKey, UsageTotals>,
) -> anyhow::Result<()> {
    if buffer.is_empty() {
        return Ok(());
    }
    let mut rows = Vec::with_capacity(buffer.len());
    for (key, totals) in buffer.iter() {
        rows.push(UsageBatchRow {
            hour_bucket: key.hour_bucket,
            identity_key: key.identity_key.as_ref().to_string(),
            route_group: key.route_group.to_string(),
            requests: totals.requests,
            bytes_out: totals.bytes_out,
            cache_hits: totals.cache_hits,
            cache_misses: totals.cache_misses,
        });
    }
    db.record_usage_batch(&rows).await?;
    buffer.clear();
    Ok(())
}
