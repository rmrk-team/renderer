#![allow(clippy::collapsible_if)]

mod admin;
mod approvals;
mod assets;
mod cache;
mod canonical;
mod catalog_warmup;
mod chain;
mod config;
mod db;
mod failure_log;
mod fallbacks;
mod http;
mod landing;
mod local_ipfs;
mod metrics;
mod pinning;
mod rate_limit;
mod render;
mod render_queue;
mod state;
mod token_warmup;
mod usage;
mod warmup;

use crate::assets::AssetResolver;
use crate::cache::CacheManager;
use crate::chain::ChainClient;
use crate::config::Config;
use crate::db::Database;
use crate::failure_log::FailureLog;
use crate::pinning::PinnedAssetStore;
use crate::state::AppState;
use axum::Router;
use axum::body::HttpBody;
use axum::http::{Response, header};
use axum::middleware;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::compression::{
    CompressionLayer,
    predicate::{DefaultPredicate, Predicate},
};
use tower_http::sensitive_headers::SetSensitiveHeadersLayer;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::info;
use tracing::warn;

#[derive(Clone)]
struct NoImageCompression {
    inner: DefaultPredicate,
}

impl NoImageCompression {
    fn new() -> Self {
        Self {
            inner: DefaultPredicate::new(),
        }
    }
}

impl Predicate for NoImageCompression {
    fn should_compress<B>(&self, response: &Response<B>) -> bool
    where
        B: HttpBody,
    {
        if let Some(content_type) = response.headers().get(header::CONTENT_TYPE) {
            if let Ok(content_type) = content_type.to_str() {
                if content_type.starts_with("image/") {
                    return false;
                }
            }
        }
        self.inner.should_compress(response)
    }
}

fn build_app(state: Arc<AppState>) -> Router {
    let max_in_flight = if state.config.max_in_flight_requests == 0 {
        usize::MAX
    } else {
        state.config.max_in_flight_requests
    };
    let access_state = state.clone();
    let mut app = http::router(state.clone());
    if let Some(landing) = state.config.landing.as_ref() {
        app = app.fallback_service(landing::router(landing).into_service());
    }
    app.layer(CompressionLayer::new().compress_when(NoImageCompression::new()))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().include_headers(false)),
        )
        .layer(SetSensitiveHeadersLayer::new([
            header::AUTHORIZATION,
            header::COOKIE,
            header::SET_COOKIE,
        ]))
        .layer(middleware::from_fn(move |request, next| {
            let state = access_state.clone();
            async move { http::access_middleware(state, request, next).await }
        }))
        .layer(ConcurrencyLimitLayer::new(max_in_flight))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env()?;
    if config
        .trusted_proxies
        .iter()
        .any(|net| net.prefix_len() == 0)
    {
        warn!("TRUSTED_PROXY_CIDRS contains a /0 range; clients can spoof forwarded IPs");
    }
    info!(
        access_mode = ?config.access_mode,
        require_approval = config.require_approval,
        render_queue_capacity = config.render_queue_capacity,
        rate_limit_per_minute = config.rate_limit_per_minute,
        auth_failure_rate_limit_per_minute = config.auth_failure_rate_limit_per_minute,
        landing_enabled = config.landing.is_some(),
        landing_public = config.landing_public,
        status_public = config.status_public,
        "startup config summary"
    );
    let usage_tracking_enabled = config.usage_tracking_enabled;
    let usage_channel_capacity = config.usage_channel_capacity;
    let render_queue_capacity = config.render_queue_capacity;
    let render_workers = config.max_concurrent_renders;
    http::init_placeholder_cache(&config);
    let db = Database::new(&config).await?;
    let cache = CacheManager::new(&config)?;
    let metrics = Arc::new(metrics::Metrics::new(&config));
    let pinned_store = Arc::new(PinnedAssetStore::new(&config)?);
    if config.local_ipfs_enabled && config.pinning_enabled {
        let local_addr = format!("{}:{}", config.local_ipfs_bind, config.local_ipfs_port);
        match TcpListener::bind(&local_addr).await {
            Ok(local_listener) => {
                let store = pinned_store.clone();
                tokio::spawn(async move {
                    info!(address = %local_addr, "local ipfs gateway listening");
                    if let Err(err) = axum::serve(
                        local_listener,
                        local_ipfs::router(store).into_make_service(),
                    )
                    .await
                    {
                        warn!(error = ?err, "local ipfs gateway failed");
                    }
                });
            }
            Err(err) => {
                warn!(error = ?err, address = %local_addr, "local ipfs bind failed");
            }
        }
    }
    let ipfs_semaphore = Arc::new(Semaphore::new(config.max_concurrent_ipfs_fetches));
    let assets = AssetResolver::new(
        Arc::new(config.clone()),
        cache.clone(),
        db.clone(),
        Some(pinned_store.clone()),
        ipfs_semaphore.clone(),
        metrics.clone(),
    )?;
    let chain = ChainClient::new(Arc::new(config.clone()), db.clone(), metrics.clone());
    let (usage_tx, usage_rx) = if usage_tracking_enabled {
        let capacity = usage_channel_capacity.max(1);
        let (tx, rx) = mpsc::channel(capacity);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let (render_queue_tx, render_queue_rx) = if render_queue_capacity == 0 {
        (None, None)
    } else {
        let capacity = render_queue_capacity.max(1);
        let (tx, rx) = mpsc::channel(capacity);
        (Some(tx), Some(rx))
    };
    let failure_log = match config.failure_log_path.clone() {
        Some(path) => FailureLog::new(path, config.failure_log_max_bytes),
        None => None,
    };
    let state = Arc::new(AppState::new(
        config,
        db,
        cache.clone(),
        assets,
        chain,
        metrics,
        usage_tx,
        render_queue_tx,
        failure_log,
    ));
    if let Err(err) = state.refresh_ip_rules().await {
        warn!(error = ?err, "failed to load ip rules cache");
    }

    let cache_eviction = cache.clone();
    let cache_evict_interval = state.config.cache_evict_interval;
    if !cache_evict_interval.is_zero() {
        tokio::spawn(async move {
            cache_eviction.evict_loop(cache_evict_interval).await;
        });
    }

    let usage_db = state.db.clone();
    let usage_retention_days = state.config.usage_retention_days;
    tokio::spawn(async move {
        if usage_retention_days == 0 {
            return;
        }
        loop {
            if let Err(err) = usage_db.prune_usage(usage_retention_days).await {
                warn!(error = ?err, "usage retention cleanup failed");
            }
            tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
        }
    });

    let fresh_db = state.db.clone();
    let fresh_retention_days = state.config.fresh_request_retention_days;
    tokio::spawn(async move {
        if fresh_retention_days == 0 {
            return;
        }
        loop {
            if let Err(err) = fresh_db.prune_fresh_requests(fresh_retention_days).await {
                warn!(error = ?err, "fresh request cleanup failed");
            }
            tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
        }
    });

    let metrics_state = state.clone();
    tokio::spawn(async move {
        loop {
            metrics::refresh_metrics(&metrics_state).await;
            tokio::time::sleep(metrics_state.config.metrics_refresh_interval).await;
        }
    });

    if let Some(usage_rx) = usage_rx {
        let usage_db = state.db.clone();
        let flush_interval = state.config.usage_flush_interval;
        let max_entries = state.config.usage_flush_max_entries;
        tokio::spawn(async move {
            usage::run_usage_aggregator(usage_db, usage_rx, flush_interval, max_entries).await;
        });
    }

    if let Some(render_queue_rx) = render_queue_rx {
        render_queue::spawn_workers(state.clone(), render_queue_rx, render_workers);
    }

    let warmup_state = state.clone();
    tokio::spawn(async move {
        warmup::spawn_worker(warmup_state).await;
    });
    catalog_warmup::spawn_workers(state.clone()).await;
    token_warmup::spawn_workers(state.clone()).await;

    approvals::spawn_approval_watchers(state.clone()).await;
    approvals::spawn_approval_sync(state.clone()).await;

    let app = build_app(state.clone());

    let addr = format!("{}:{}", state.config.host, state.config.port);
    let listener = TcpListener::bind(&addr).await?;
    info!(address = %addr, "renderer listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AccessMode, LandingConfig, RasterMismatchPolicy, RenderPolicy};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::tempdir;
    use tower::ServiceExt;

    fn test_config(
        landing_public: bool,
        landing_dir: PathBuf,
        db_path: PathBuf,
        cache_dir: PathBuf,
    ) -> Config {
        Config {
            host: "127.0.0.1".to_string(),
            port: 0,
            admin_password: "secret".to_string(),
            db_path,
            cache_dir,
            fallbacks_dir: PathBuf::from("cache/fallbacks"),
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
            approval_sync_interval_seconds: 0,
            approval_negative_cache_seconds: 0,
            approval_negative_cache_capacity: 0,
            approval_on_demand_rate_limit_per_minute: 0,
            approval_on_demand_rate_limit_burst: 0,
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
            fallback_upload_max_bytes: 1,
            fallback_upload_max_pixels: 1,
            metrics_public: false,
            metrics_require_admin_key: false,
            metrics_allow_ips: Vec::new(),
            metrics_top_ips: 0,
            metrics_top_collections: 0,
            metrics_ip_label_mode: crate::config::MetricsIpLabelMode::Sha256Prefix,
            metrics_refresh_interval: Duration::from_secs(1),
            rate_limit_per_minute: 0,
            rate_limit_burst: 0,
            auth_failure_rate_limit_per_minute: 0,
            auth_failure_rate_limit_burst: 0,
            access_mode: AccessMode::KeyRequired,
            api_key_secret: Some("secret".to_string()),
            key_rate_limit_per_minute: 0,
            key_rate_limit_burst: 0,
            api_key_cache_ttl: Duration::from_secs(0),
            api_key_cache_capacity: 0,
            track_keys_in_open_mode: false,
            trusted_proxies: Vec::new(),
            usage_tracking_enabled: false,
            usage_sample_rate: 1.0,
            usage_channel_capacity: 1,
            usage_flush_interval: Duration::from_secs(1),
            usage_flush_max_entries: 1,
            usage_retention_days: 0,
            render_queue_capacity: 0,
            render_layer_concurrency: 1,
            composite_cache_enabled: false,
            cache_size_refresh_interval: Duration::from_secs(0),
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
            fresh_request_retention_days: 0,
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
            landing_public,
            landing: Some(LandingConfig {
                dir: landing_dir,
                file: "index.html".to_string(),
                strict_headers: true,
            }),
        }
    }

    #[tokio::test]
    async fn landing_respects_access_gating() {
        let dir = tempdir().unwrap();
        let landing_dir = dir.path().join("landing");
        std::fs::create_dir_all(&landing_dir).unwrap();
        std::fs::write(landing_dir.join("index.html"), "hello").unwrap();

        let config = test_config(
            false,
            landing_dir.clone(),
            dir.path().join("renderer.db"),
            dir.path().join("cache"),
        );
        let db = Database::new(&config).await.unwrap();
        let cache = CacheManager::new(&config).unwrap();
        let metrics = Arc::new(metrics::Metrics::new(&config));
        let pinned_store = Arc::new(PinnedAssetStore::new(&config).unwrap());
        let ipfs_semaphore = Arc::new(Semaphore::new(config.max_concurrent_ipfs_fetches));
        let assets = AssetResolver::new(
            Arc::new(config.clone()),
            cache.clone(),
            db.clone(),
            Some(pinned_store),
            ipfs_semaphore,
            metrics.clone(),
        )
        .unwrap();
        let chain = ChainClient::new(Arc::new(config.clone()), db.clone(), metrics.clone());
        let state = Arc::new(AppState::new(
            config, db, cache, assets, chain, metrics, None, None, None,
        ));
        let app = build_app(state);
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let config = test_config(
            true,
            landing_dir,
            dir.path().join("renderer2.db"),
            dir.path().join("cache2"),
        );
        let db = Database::new(&config).await.unwrap();
        let cache = CacheManager::new(&config).unwrap();
        let metrics = Arc::new(metrics::Metrics::new(&config));
        let pinned_store = Arc::new(PinnedAssetStore::new(&config).unwrap());
        let ipfs_semaphore = Arc::new(Semaphore::new(config.max_concurrent_ipfs_fetches));
        let assets = AssetResolver::new(
            Arc::new(config.clone()),
            cache.clone(),
            db.clone(),
            Some(pinned_store),
            ipfs_semaphore,
            metrics.clone(),
        )
        .unwrap();
        let chain = ChainClient::new(Arc::new(config.clone()), db.clone(), metrics.clone());
        let state = Arc::new(AppState::new(
            config, db, cache, assets, chain, metrics, None, None, None,
        ));
        let app = build_app(state);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
