use crate::config::{Config, MetricsIpLabelMode};
use crate::state::AppState;
use anyhow::Result;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

pub struct Metrics {
    registry: Registry,
    http_requests: IntCounterVec,
    http_response_bytes: IntCounterVec,
    render_requests: IntCounterVec,
    upstream_failures: IntCounterVec,
    render_duration: HistogramVec,
    fetch_duration: HistogramVec,
    inflight_requests: IntGauge,
    semaphore_in_use: IntGaugeVec,
    render_queue_depth: IntGauge,
    warmup_queue_size: IntGauge,
    disk_bytes: IntGaugeVec,
    cache_entries: IntGaugeVec,
    approved_collections: IntGaugeVec,
    top_ip_requests: IntCounterVec,
    top_ip_bytes: IntCounterVec,
    top_collection_requests: IntCounterVec,
    top_collection_bytes: IntCounterVec,
    top_ip_request_tracker: Mutex<SpaceSaving>,
    top_ip_bytes_tracker: Mutex<SpaceSaving>,
    top_collection_request_tracker: Mutex<SpaceSaving>,
    top_collection_bytes_tracker: Mutex<SpaceSaving>,
    top_ip_request_last: Mutex<HashMap<String, u64>>,
    top_ip_bytes_last: Mutex<HashMap<String, u64>>,
    top_collection_request_last: Mutex<HashMap<String, u64>>,
    top_collection_bytes_last: Mutex<HashMap<String, u64>>,
    ip_label_mode: MetricsIpLabelMode,
    top_ip_capacity: usize,
    top_collection_capacity: usize,
    expensive_cache: Mutex<ExpensiveMetricsCache>,
    expensive_interval: Duration,
}

impl Metrics {
    pub fn new(config: &Config) -> Self {
        let registry = Registry::new();
        let http_requests = IntCounterVec::new(
            Opts::new(
                "renderer_http_requests_total",
                "HTTP request count by route group, method, and status",
            ),
            &["route_group", "method", "status"],
        )
        .expect("http_requests_total");
        let http_response_bytes = IntCounterVec::new(
            Opts::new(
                "renderer_http_response_bytes_total",
                "HTTP response bytes by route group",
            ),
            &["route_group"],
        )
        .expect("http_response_bytes_total");
        let render_requests = IntCounterVec::new(
            Opts::new(
                "renderer_render_requests_total",
                "Render requests by result class",
            ),
            &["result"],
        )
        .expect("render_requests_total");
        let upstream_failures = IntCounterVec::new(
            Opts::new(
                "renderer_upstream_failures_total",
                "Upstream failures by kind",
            ),
            &["kind"],
        )
        .expect("upstream_failures_total");
        let render_duration = HistogramVec::new(
            HistogramOpts::new(
                "renderer_render_duration_seconds",
                "Render duration by stage",
            )
            .buckets(vec![
                0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0,
            ]),
            &["stage"],
        )
        .expect("render_duration_seconds");
        let fetch_duration = HistogramVec::new(
            HistogramOpts::new("renderer_fetch_duration_seconds", "Fetch duration by kind")
                .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
            &["kind"],
        )
        .expect("fetch_duration_seconds");
        let inflight_requests = IntGauge::new("renderer_inflight_requests", "Requests in flight")
            .expect("inflight_requests");
        let semaphore_in_use = IntGaugeVec::new(
            Opts::new("renderer_semaphore_in_use", "Semaphore usage by kind"),
            &["kind"],
        )
        .expect("semaphore_in_use");
        let render_queue_depth = IntGauge::new("renderer_render_queue_depth", "Render queue depth")
            .expect("render_queue_depth");
        let warmup_queue_size = IntGauge::new("renderer_warmup_queue_size", "Warmup queue size")
            .expect("warmup_queue_size");
        let disk_bytes = IntGaugeVec::new(
            Opts::new("renderer_disk_bytes", "Disk usage by path"),
            &["path"],
        )
        .expect("disk_bytes");
        let cache_entries = IntGaugeVec::new(
            Opts::new("renderer_cache_entries", "Cache entry counts"),
            &["cache"],
        )
        .expect("cache_entries");
        let approved_collections = IntGaugeVec::new(
            Opts::new(
                "renderer_approved_collections_total",
                "Approved collections by chain",
            ),
            &["chain"],
        )
        .expect("approved_collections_total");
        let top_ip_requests = IntCounterVec::new(
            Opts::new(
                "renderer_top_ip_requests_total",
                "Top IP requests (bounded)",
            ),
            &["ip"],
        )
        .expect("top_ip_requests");
        let top_ip_bytes = IntCounterVec::new(
            Opts::new("renderer_top_ip_bytes_total", "Top IP bytes (bounded)"),
            &["ip"],
        )
        .expect("top_ip_bytes");
        let top_collection_requests = IntCounterVec::new(
            Opts::new(
                "renderer_top_collection_requests_total",
                "Top collection requests (bounded)",
            ),
            &["chain", "collection"],
        )
        .expect("top_collection_requests");
        let top_collection_bytes = IntCounterVec::new(
            Opts::new(
                "renderer_top_collection_bytes_total",
                "Top collection bytes (bounded)",
            ),
            &["chain", "collection"],
        )
        .expect("top_collection_bytes");
        registry
            .register(Box::new(http_requests.clone()))
            .expect("register http_requests");
        registry
            .register(Box::new(http_response_bytes.clone()))
            .expect("register http_response_bytes");
        registry
            .register(Box::new(render_requests.clone()))
            .expect("register render_requests");
        registry
            .register(Box::new(upstream_failures.clone()))
            .expect("register upstream_failures");
        registry
            .register(Box::new(render_duration.clone()))
            .expect("register render_duration");
        registry
            .register(Box::new(fetch_duration.clone()))
            .expect("register fetch_duration");
        registry
            .register(Box::new(inflight_requests.clone()))
            .expect("register inflight_requests");
        registry
            .register(Box::new(semaphore_in_use.clone()))
            .expect("register semaphore_in_use");
        registry
            .register(Box::new(render_queue_depth.clone()))
            .expect("register render_queue_depth");
        registry
            .register(Box::new(warmup_queue_size.clone()))
            .expect("register warmup_queue_size");
        registry
            .register(Box::new(disk_bytes.clone()))
            .expect("register disk_bytes");
        registry
            .register(Box::new(cache_entries.clone()))
            .expect("register cache_entries");
        registry
            .register(Box::new(approved_collections.clone()))
            .expect("register approved_collections");
        registry
            .register(Box::new(top_ip_requests.clone()))
            .expect("register top_ip_requests");
        registry
            .register(Box::new(top_ip_bytes.clone()))
            .expect("register top_ip_bytes");
        registry
            .register(Box::new(top_collection_requests.clone()))
            .expect("register top_collection_requests");
        registry
            .register(Box::new(top_collection_bytes.clone()))
            .expect("register top_collection_bytes");

        Self {
            registry,
            http_requests,
            http_response_bytes,
            render_requests,
            upstream_failures,
            render_duration,
            fetch_duration,
            inflight_requests,
            semaphore_in_use,
            render_queue_depth,
            warmup_queue_size,
            disk_bytes,
            cache_entries,
            approved_collections,
            top_ip_requests,
            top_ip_bytes,
            top_collection_requests,
            top_collection_bytes,
            top_ip_request_tracker: Mutex::new(SpaceSaving::new(config.metrics_top_ips)),
            top_ip_bytes_tracker: Mutex::new(SpaceSaving::new(config.metrics_top_ips)),
            top_collection_request_tracker: Mutex::new(SpaceSaving::new(
                config.metrics_top_collections,
            )),
            top_collection_bytes_tracker: Mutex::new(SpaceSaving::new(
                config.metrics_top_collections,
            )),
            top_ip_request_last: Mutex::new(HashMap::new()),
            top_ip_bytes_last: Mutex::new(HashMap::new()),
            top_collection_request_last: Mutex::new(HashMap::new()),
            top_collection_bytes_last: Mutex::new(HashMap::new()),
            ip_label_mode: config.metrics_ip_label_mode,
            top_ip_capacity: config.metrics_top_ips,
            top_collection_capacity: config.metrics_top_collections,
            expensive_cache: Mutex::new(ExpensiveMetricsCache::default()),
            expensive_interval: config.metrics_expensive_refresh_interval,
        }
    }

    pub fn gather(&self) -> Result<String> {
        let metric_families = self.registry.gather();
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8_lossy(&buffer).to_string())
    }

    pub fn inflight_guard(self: &Arc<Self>) -> InflightGuard {
        self.inflight_requests.inc();
        InflightGuard {
            metrics: Arc::clone(self),
        }
    }

    pub fn observe_http_request(&self, route_group: &str, method: &str, status: &str) {
        self.http_requests
            .with_label_values(&[route_group, method, status])
            .inc();
    }

    pub fn add_http_response_bytes(&self, route_group: &str, bytes: u64) {
        self.http_response_bytes
            .with_label_values(&[route_group])
            .inc_by(bytes);
    }

    pub fn observe_render_result(&self, result: &str) {
        self.render_requests.with_label_values(&[result]).inc();
    }

    pub fn observe_render_duration(&self, stage: &str, duration: Duration) {
        self.render_duration
            .with_label_values(&[stage])
            .observe(duration.as_secs_f64());
    }

    pub fn observe_fetch_duration(&self, kind: &str, duration: Duration) {
        self.fetch_duration
            .with_label_values(&[kind])
            .observe(duration.as_secs_f64());
    }

    pub fn observe_upstream_failure(&self, kind: &str) {
        self.upstream_failures.with_label_values(&[kind]).inc();
    }

    pub fn set_semaphore_in_use(&self, kind: &str, in_use: i64) {
        self.semaphore_in_use.with_label_values(&[kind]).set(in_use);
    }

    pub fn set_render_queue_depth(&self, depth: i64) {
        self.render_queue_depth.set(depth);
    }

    pub fn set_warmup_queue_size(&self, size: i64) {
        self.warmup_queue_size.set(size);
    }

    pub fn set_disk_bytes(&self, path: &str, bytes: u64) {
        self.disk_bytes.with_label_values(&[path]).set(bytes as i64);
    }

    pub fn set_cache_entries(&self, cache: &str, entries: u64) {
        self.cache_entries
            .with_label_values(&[cache])
            .set(entries as i64);
    }

    pub fn set_approved_collections(&self, chain: &str, count: i64) {
        self.approved_collections
            .with_label_values(&[chain])
            .set(count);
    }

    pub fn observe_top_ip(&self, ip: IpAddr, bytes: u64) {
        if self.top_ip_capacity == 0 {
            return;
        }
        let label = self.ip_label(ip);
        {
            let mut tracker = self
                .top_ip_request_tracker
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            tracker.update(&label, 1);
        }
        {
            let mut tracker = self
                .top_ip_bytes_tracker
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            tracker.update(&label, bytes);
        }
    }

    pub fn observe_top_collection(&self, chain: &str, collection: &str, bytes: u64) {
        if self.top_collection_capacity == 0 {
            return;
        }
        let key = format!("{chain}|{collection}");
        {
            let mut tracker = self
                .top_collection_request_tracker
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            tracker.update(&key, 1);
        }
        {
            let mut tracker = self
                .top_collection_bytes_tracker
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            tracker.update(&key, bytes);
        }
    }

    pub fn flush_topk(&self) {
        if self.top_ip_capacity == 0 && self.top_collection_capacity == 0 {
            return;
        }
        let top_ips = {
            let tracker = self
                .top_ip_request_tracker
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            tracker.snapshot()
        };
        let top_ip_bytes = {
            let tracker = self
                .top_ip_bytes_tracker
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            tracker.snapshot()
        };
        let top_collections = {
            let tracker = self
                .top_collection_request_tracker
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            tracker.snapshot()
        };
        let top_collection_bytes = {
            let tracker = self
                .top_collection_bytes_tracker
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            tracker.snapshot()
        };

        flush_counter_single(
            &self.top_ip_requests,
            &mut self
                .top_ip_request_last
                .lock()
                .unwrap_or_else(|err| err.into_inner()),
            top_ips,
        );
        flush_counter_single(
            &self.top_ip_bytes,
            &mut self
                .top_ip_bytes_last
                .lock()
                .unwrap_or_else(|err| err.into_inner()),
            top_ip_bytes,
        );
        flush_counter_pair(
            &self.top_collection_requests,
            &mut self
                .top_collection_request_last
                .lock()
                .unwrap_or_else(|err| err.into_inner()),
            top_collections,
        );
        flush_counter_pair(
            &self.top_collection_bytes,
            &mut self
                .top_collection_bytes_last
                .lock()
                .unwrap_or_else(|err| err.into_inner()),
            top_collection_bytes,
        );
    }

    fn ip_label(&self, ip: IpAddr) -> String {
        match self.ip_label_mode {
            MetricsIpLabelMode::Plain => ip.to_string(),
            MetricsIpLabelMode::Sha256Prefix => {
                let mut hasher = Sha256::new();
                hasher.update(ip.to_string().as_bytes());
                let hash = hex::encode(hasher.finalize());
                format!("sha256:{}", &hash[..12])
            }
        }
    }
}

pub struct InflightGuard {
    metrics: Arc<Metrics>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.metrics.inflight_requests.dec();
    }
}

#[derive(Default)]
struct ExpensiveMetricsCache {
    updated_at: Option<std::time::Instant>,
    render_entries: u64,
    fallback_entries: u64,
    fallback_bytes: u64,
    pinned_entries: u64,
    pinned_bytes: u64,
}

#[derive(Debug)]
struct SpaceSaving {
    capacity: usize,
    counts: HashMap<String, u64>,
}

impl SpaceSaving {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            counts: HashMap::new(),
        }
    }

    fn update(&mut self, key: &str, weight: u64) {
        if self.capacity == 0 {
            return;
        }
        if let Some(value) = self.counts.get_mut(key) {
            *value = value.saturating_add(weight);
            return;
        }
        if self.counts.len() < self.capacity {
            self.counts.insert(key.to_string(), weight);
            return;
        }
        let Some((min_key, min_value)) = self
            .counts
            .iter()
            .min_by_key(|(_, value)| *value)
            .map(|(key, value)| (key.clone(), *value))
        else {
            return;
        };
        let next_value = min_value.saturating_add(weight);
        self.counts.remove(&min_key);
        self.counts.insert(key.to_string(), next_value);
    }

    fn snapshot(&self) -> Vec<(String, u64)> {
        self.counts
            .iter()
            .map(|(key, value)| (key.clone(), *value))
            .collect()
    }
}

fn flush_counter_single(
    counter: &IntCounterVec,
    last: &mut HashMap<String, u64>,
    candidates: Vec<(String, u64)>,
) {
    let mut active = HashSet::new();
    for (label, value) in candidates {
        active.insert(label.clone());
        let prev = last.get(&label).copied().unwrap_or(0);
        if value > prev {
            counter
                .with_label_values(&[label.as_str()])
                .inc_by(value - prev);
            last.insert(label, value);
        }
    }
    let stale: Vec<String> = last
        .keys()
        .filter(|label| !active.contains(*label))
        .cloned()
        .collect();
    for label in stale {
        let _ = counter.remove_label_values(&[label.as_str()]);
        last.remove(&label);
    }
}

fn flush_counter_pair(
    counter: &IntCounterVec,
    last: &mut HashMap<String, u64>,
    candidates: Vec<(String, u64)>,
) {
    let mut active = HashSet::new();
    for (label, value) in candidates {
        active.insert(label.clone());
        let prev = last.get(&label).copied().unwrap_or(0);
        if value > prev {
            let (chain, collection) = split_pair_label(&label);
            counter
                .with_label_values(&[chain, collection])
                .inc_by(value - prev);
            last.insert(label, value);
        }
    }
    let stale: Vec<String> = last
        .keys()
        .filter(|label| !active.contains(*label))
        .cloned()
        .collect();
    for label in stale {
        let (chain, collection) = split_pair_label(&label);
        let _ = counter.remove_label_values(&[chain, collection]);
        last.remove(&label);
    }
}

fn split_pair_label(label: &str) -> (&str, &str) {
    match label.split_once('|') {
        Some((chain, collection)) => (chain, collection),
        None => ("unknown", "unknown"),
    }
}

pub async fn refresh_metrics(state: &AppState) {
    let metrics = &state.metrics;
    if let Ok((render_bytes, asset_bytes)) = state.cache.cached_sizes().await {
        metrics.set_disk_bytes("render_cache", render_bytes);
        metrics.set_disk_bytes("asset_cache", asset_bytes);
    }
    if let Ok(metadata) = tokio::fs::metadata(&state.config.db_path).await {
        metrics.set_disk_bytes("db", metadata.len());
    }

    let (render_entries, fallback_entries, fallback_bytes, pinned_entries, pinned_bytes) =
        refresh_expensive_metrics(state, metrics).await;
    metrics.set_cache_entries("render_cache", render_entries);
    metrics.set_cache_entries("fallback_variants", fallback_entries);
    metrics.set_cache_entries("pinned_assets", pinned_entries);
    metrics.set_disk_bytes("pinned", pinned_bytes);
    metrics.set_disk_bytes("fallbacks", fallback_bytes);

    metrics.set_semaphore_in_use(
        "render",
        semaphore_in_use(state.config.max_concurrent_renders, &state.render_semaphore),
    );
    metrics.set_semaphore_in_use(
        "rpc",
        semaphore_in_use(state.config.max_concurrent_rpc_calls, &state.rpc_semaphore),
    );
    metrics.set_semaphore_in_use(
        "ipfs",
        semaphore_in_use(
            state.config.max_concurrent_ipfs_fetches,
            state.assets.ipfs_semaphore(),
        ),
    );

    if let Some(queue) = state.render_queue_tx.as_ref() {
        let capacity = state.config.render_queue_capacity;
        let available = queue.capacity();
        let depth = capacity.saturating_sub(available);
        metrics.set_render_queue_depth(depth as i64);
    } else {
        metrics.set_render_queue_depth(0);
    }

    if let Ok((queued, _running, _done, _failed)) = state.db.warmup_stats().await {
        metrics.set_warmup_queue_size(queued);
    }

    if let Ok(rows) = state.db.approved_collections_by_chain().await {
        for (chain, total) in rows {
            metrics.set_approved_collections(&chain, total);
        }
    }
}

async fn refresh_expensive_metrics(
    state: &AppState,
    metrics: &Metrics,
) -> (u64, u64, u64, u64, u64) {
    if metrics.expensive_interval.is_zero() {
        let cache = metrics
            .expensive_cache
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        return (
            cache.render_entries,
            cache.fallback_entries,
            cache.fallback_bytes,
            cache.pinned_entries,
            cache.pinned_bytes,
        );
    }
    let (should_refresh, cached_values) = {
        let cache = metrics
            .expensive_cache
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let should_refresh = cache
            .updated_at
            .map(|updated| updated.elapsed() >= metrics.expensive_interval)
            .unwrap_or(true);
        (
            should_refresh,
            (
                cache.render_entries,
                cache.fallback_entries,
                cache.fallback_bytes,
                cache.pinned_entries,
                cache.pinned_bytes,
            ),
        )
    };
    if !should_refresh {
        return cached_values;
    }
    let render_entries = count_files(&state.cache.renders_dir).await;
    let fallback_entries = count_files(&state.config.fallbacks_dir).await;
    let fallback_bytes = state
        .cache
        .scan_dir_size(&state.config.fallbacks_dir)
        .await
        .unwrap_or(0);
    let pinned_entries = state
        .db
        .pinned_asset_counts()
        .await
        .map(|counts| counts.pinned as u64)
        .unwrap_or(0);
    let pinned_bytes = state.db.pinned_asset_bytes().await.unwrap_or(0);
    let mut cache = metrics
        .expensive_cache
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    cache.render_entries = render_entries;
    cache.fallback_entries = fallback_entries;
    cache.fallback_bytes = fallback_bytes;
    cache.pinned_entries = pinned_entries;
    cache.pinned_bytes = pinned_bytes;
    cache.updated_at = Some(std::time::Instant::now());
    (
        render_entries,
        fallback_entries,
        fallback_bytes,
        pinned_entries,
        pinned_bytes,
    )
}

fn semaphore_in_use(max: usize, semaphore: &Semaphore) -> i64 {
    if max == 0 {
        return 0;
    }
    let available = semaphore.available_permits();
    max.saturating_sub(available) as i64
}

async fn count_files(path: &std::path::Path) -> u64 {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || count_files_sync(&path))
        .await
        .unwrap_or(0)
}

fn count_files_sync(path: &std::path::Path) -> u64 {
    if !path.exists() {
        return 0;
    }
    let mut stack = vec![path.to_path_buf()];
    let mut total = 0u64;
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => continue,
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file() {
                total = total.saturating_add(1);
            }
        }
    }
    total
}
