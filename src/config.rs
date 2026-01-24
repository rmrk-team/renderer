use anyhow::{Context, Result, anyhow};
use ipnet::IpNet;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::env;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub admin_password: String,
    pub db_path: PathBuf,
    pub cache_dir: PathBuf,
    pub pinning_enabled: bool,
    pub pinned_dir: PathBuf,
    pub local_ipfs_enabled: bool,
    pub local_ipfs_bind: String,
    pub local_ipfs_port: u16,
    pub cache_max_size_bytes: u64,
    pub render_cache_min_ttl: Duration,
    pub asset_cache_min_ttl: Duration,
    pub cache_touch_interval: Duration,
    pub cache_evict_interval: Duration,
    pub max_concurrent_renders: usize,
    pub max_concurrent_ipfs_fetches: usize,
    pub max_concurrent_rpc_calls: usize,
    pub default_canvas_width: u32,
    pub default_canvas_height: u32,
    pub default_cache_timestamp: Option<String>,
    pub default_cache_ttl: Duration,
    pub rpc_endpoints: HashMap<String, Vec<String>>,
    pub render_utils_addresses: HashMap<String, String>,
    pub approval_contracts: HashMap<String, String>,
    pub approval_start_blocks: HashMap<String, u64>,
    pub approval_poll_interval_seconds: u64,
    pub approval_confirmations: u64,
    pub chain_id_map: HashMap<u64, String>,
    pub approval_sync_interval_seconds: u64,
    pub approval_negative_cache_seconds: u64,
    pub approval_negative_cache_capacity: usize,
    pub approval_enumeration_enabled: bool,
    pub max_approval_staleness_seconds: u64,
    pub approvals_contract_chain: Option<String>,
    pub ipfs_gateways: Vec<String>,
    pub ipfs_timeout_seconds: u64,
    pub max_metadata_json_bytes: usize,
    pub max_svg_bytes: usize,
    pub max_svg_node_count: usize,
    pub max_raster_bytes: usize,
    pub max_raster_resize_bytes: usize,
    pub max_raster_resize_dim: u32,
    pub max_layers_per_render: usize,
    pub max_canvas_pixels: u64,
    pub max_total_raster_pixels: u64,
    pub max_cache_variants_per_key: usize,
    pub max_decoded_raster_pixels: u64,
    pub max_overlay_length: usize,
    pub max_background_length: usize,
    pub max_in_flight_requests: usize,
    pub max_admin_body_bytes: usize,
    pub rate_limit_per_minute: u64,
    pub rate_limit_burst: u64,
    pub auth_failure_rate_limit_per_minute: u64,
    pub auth_failure_rate_limit_burst: u64,
    pub access_mode: AccessMode,
    pub api_key_secret: Option<String>,
    pub key_rate_limit_per_minute: u64,
    pub key_rate_limit_burst: u64,
    pub api_key_cache_ttl: Duration,
    pub api_key_cache_capacity: usize,
    pub track_keys_in_open_mode: bool,
    pub trusted_proxies: Vec<IpNet>,
    pub usage_tracking_enabled: bool,
    pub usage_sample_rate: f64,
    pub usage_channel_capacity: usize,
    pub usage_flush_interval: Duration,
    pub usage_flush_max_entries: usize,
    pub usage_retention_days: u64,
    pub render_queue_capacity: usize,
    pub render_layer_concurrency: usize,
    pub composite_cache_enabled: bool,
    pub cache_size_refresh_interval: Duration,
    pub rpc_timeout_seconds: u64,
    pub rpc_connect_timeout_seconds: u64,
    pub rpc_failure_threshold: u32,
    pub rpc_failure_cooldown_seconds: u64,
    pub failure_log_path: Option<PathBuf>,
    pub failure_log_max_bytes: u64,
    pub require_approval: bool,
    pub allow_http: bool,
    pub allow_private_networks: bool,
    pub warmup_widths: Vec<String>,
    pub warmup_include_og: bool,
    pub warmup_max_tokens: usize,
    pub warmup_max_renders_per_job: usize,
    pub warmup_job_timeout_seconds: u64,
    pub warmup_max_block_span: u64,
    pub warmup_max_concurrent_asset_pins: usize,
    pub token_state_check_ttl_seconds: u64,
    pub fresh_rate_limit_seconds: u64,
    pub primary_asset_cache_ttl: Duration,
    pub primary_asset_negative_ttl: Duration,
    pub primary_asset_cache_capacity: usize,
    pub outbound_client_cache_ttl: Duration,
    pub outbound_client_cache_capacity: usize,
    pub openapi_public: bool,
    pub render_policy: RenderPolicy,
    pub collection_render_overrides: HashMap<String, RenderPolicyOverride>,
    pub status_public: bool,
    pub landing_public: bool,
    pub landing: Option<LandingConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildLayerMode {
    AboveSlot,
    BelowSlot,
    SameZAfter,
    SameZBefore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RasterMismatchPolicy {
    Error,
    ScaleToCanvas,
    CenterNoScale,
    TopLeftNoScale,
}

#[derive(Debug, Clone, Copy)]
pub struct RenderPolicy {
    pub child_layer_mode: ChildLayerMode,
    pub raster_mismatch_fixed: RasterMismatchPolicy,
    pub raster_mismatch_child: RasterMismatchPolicy,
}

#[derive(Debug, Clone, Default)]
pub struct RenderPolicyOverride {
    pub child_layer_mode: Option<ChildLayerMode>,
    pub raster_mismatch_fixed: Option<RasterMismatchPolicy>,
    pub raster_mismatch_child: Option<RasterMismatchPolicy>,
}

impl RenderPolicy {
    pub fn apply_override(&self, override_entry: &RenderPolicyOverride) -> RenderPolicy {
        RenderPolicy {
            child_layer_mode: override_entry
                .child_layer_mode
                .unwrap_or(self.child_layer_mode),
            raster_mismatch_fixed: override_entry
                .raster_mismatch_fixed
                .unwrap_or(self.raster_mismatch_fixed),
            raster_mismatch_child: override_entry
                .raster_mismatch_child
                .unwrap_or(self.raster_mismatch_child),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RenderPolicyOverrideRaw {
    child_layer_mode: Option<String>,
    raster_mismatch_fixed: Option<String>,
    raster_mismatch_child: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    Open,
    KeyRequired,
    Hybrid,
    DenylistOnly,
    AllowlistOnly,
}

#[derive(Debug, Clone)]
pub struct LandingConfig {
    pub dir: PathBuf,
    pub file: String,
    pub strict_headers: bool,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = parse_u16("PORT", 8080);
        let admin_password =
            env::var("ADMIN_PASSWORD").context("ADMIN_PASSWORD is required for /admin access")?;

        let db_path = PathBuf::from(
            env::var("DB_PATH").unwrap_or_else(|_| "/var/lib/renderer/renderer.db".to_string()),
        );
        let cache_dir = PathBuf::from(
            env::var("CACHE_DIR").unwrap_or_else(|_| "/var/cache/renderer".to_string()),
        );
        let pinning_enabled = parse_bool("PINNING_ENABLED", true);
        let pinned_dir = PathBuf::from(
            env::var("PINNED_DIR").unwrap_or_else(|_| "/var/lib/renderer/pinned".to_string()),
        );
        let local_ipfs_enabled = parse_bool("LOCAL_IPFS_ENABLED", pinning_enabled);
        let local_ipfs_bind =
            env::var("LOCAL_IPFS_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
        let local_ipfs_port = parse_u16("LOCAL_IPFS_PORT", 18180);
        if local_ipfs_enabled && !pinning_enabled {
            return Err(anyhow!("LOCAL_IPFS_ENABLED requires PINNING_ENABLED=true"));
        }
        if local_ipfs_enabled && !is_loopback_bind(&local_ipfs_bind) {
            return Err(anyhow!(
                "LOCAL_IPFS_BIND must be a loopback address when LOCAL_IPFS_ENABLED=true"
            ));
        }

        let cache_max_size_gb = parse_u64("CACHE_MAX_SIZE_GB", 50);
        let cache_max_size_bytes = cache_max_size_gb.saturating_mul(1024 * 1024 * 1024);
        let render_cache_min_ttl =
            Duration::from_secs(parse_u64("RENDER_CACHE_MIN_TTL_DAYS", 7) * 24 * 3600);
        let asset_cache_min_ttl =
            Duration::from_secs(parse_u64("ASSET_CACHE_MIN_TTL_DAYS", 30) * 24 * 3600);
        let cache_touch_interval =
            Duration::from_secs(parse_u64("CACHE_TOUCH_INTERVAL_SECONDS", 300));
        let cache_evict_interval =
            Duration::from_secs(parse_u64("CACHE_EVICT_INTERVAL_SECONDS", 3600));

        let max_concurrent_renders = parse_usize("MAX_CONCURRENT_RENDERS", 4);
        let max_concurrent_ipfs_fetches = parse_usize("MAX_CONCURRENT_IPFS_FETCHES", 16);
        let max_concurrent_rpc_calls = parse_usize("MAX_CONCURRENT_RPC_CALLS", 16);

        let default_canvas_width = parse_u32("DEFAULT_CANVAS_WIDTH", 1080);
        let default_canvas_height = parse_u32("DEFAULT_CANVAS_HEIGHT", 1512);
        let default_cache_timestamp = parse_default_cache_timestamp()?;
        let default_cache_ttl =
            Duration::from_secs(parse_u64("DEFAULT_CACHE_TTL_SECONDS", 604_800));

        let rpc_endpoints = normalize_chain_map(
            parse_json_env::<HashMap<String, Vec<String>>>("RPC_ENDPOINTS").unwrap_or_default(),
        );
        let render_utils_addresses = normalize_chain_map(
            parse_json_env::<HashMap<String, String>>("RENDER_UTILS_ADDRESSES").unwrap_or_default(),
        );
        let approval_contracts = normalize_chain_map(
            parse_json_env::<HashMap<String, String>>("APPROVALS_CONTRACTS").unwrap_or_default(),
        );
        let approval_start_blocks = normalize_chain_map(
            parse_json_env::<HashMap<String, u64>>("APPROVAL_START_BLOCKS").unwrap_or_default(),
        );
        let approval_poll_interval_seconds = parse_u64("APPROVAL_POLL_INTERVAL_SECONDS", 30);
        let approval_confirmations = parse_u64("APPROVAL_CONFIRMATIONS", 6);
        let chain_id_map = parse_chain_id_map("CHAIN_ID_MAP")?;
        let approval_sync_interval_seconds = parse_u64("APPROVAL_SYNC_INTERVAL_SECONDS", 900);
        let approval_negative_cache_seconds = parse_u64("APPROVAL_NEGATIVE_CACHE_SECONDS", 600);
        let approval_negative_cache_capacity =
            parse_usize("APPROVAL_NEGATIVE_CACHE_CAPACITY", 10_000);
        let approval_enumeration_enabled = parse_bool("APPROVAL_ENUMERATION_ENABLED", true);
        let max_approval_staleness_seconds = parse_u64("MAX_APPROVAL_STALENESS_SECONDS", 0);
        let approvals_contract_chain = env::var("APPROVALS_CONTRACT_CHAIN")
            .ok()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty());

        let mut ipfs_gateways: Vec<String> = parse_json_env("IPFS_GATEWAYS").unwrap_or_else(|| {
            vec![
                "https://rmrk.myfilebase.com/ipfs/".to_string(),
                "https://cloudflare-ipfs.com/ipfs/".to_string(),
                "https://ipfs.io/ipfs/".to_string(),
            ]
        });
        if local_ipfs_enabled {
            let local_gateway = format_local_gateway_url(&local_ipfs_bind, local_ipfs_port);
            if !ipfs_gateways
                .iter()
                .any(|gateway| gateway == &local_gateway)
            {
                ipfs_gateways.insert(0, local_gateway);
            }
        }
        let ipfs_timeout_seconds = parse_u64("IPFS_TIMEOUT_SECONDS", 30);
        let max_metadata_json_bytes = parse_usize("MAX_METADATA_JSON_BYTES", 524_288);
        let max_svg_bytes = parse_usize("MAX_SVG_BYTES", 2_097_152);
        let max_svg_node_count = parse_usize("MAX_SVG_NODE_COUNT", 200_000);
        let max_raster_bytes = parse_usize("MAX_RASTER_BYTES", 10 * 1024 * 1024);
        let max_raster_resize_bytes = parse_usize(
            "MAX_RASTER_RESIZE_BYTES",
            max_raster_bytes.saturating_mul(5),
        );
        let max_raster_resize_dim = parse_u32("MAX_RASTER_RESIZE_DIM", 2048);
        let max_layers_per_render = parse_usize("MAX_LAYERS_PER_RENDER", 200);
        let max_canvas_pixels = parse_u64("MAX_CANVAS_PIXELS", 16_000_000);
        let max_total_raster_pixels = parse_u64("MAX_TOTAL_RASTER_PIXELS", 64_000_000);
        let max_cache_variants_per_key = parse_usize(
            "MAX_CACHE_VARIANTS_PER_KEY",
            parse_usize("MAX_CACHE_VARIANTS_PER_CHAIN", 5),
        );
        let max_decoded_raster_pixels = parse_u64("MAX_DECODED_RASTER_PIXELS", max_canvas_pixels);
        let max_overlay_length = parse_usize("MAX_OVERLAY_LENGTH", 64);
        let max_background_length = parse_usize("MAX_BG_LENGTH", 64);
        let max_in_flight_requests = parse_usize("MAX_IN_FLIGHT_REQUESTS", 512);
        let max_admin_body_bytes = parse_usize("MAX_ADMIN_BODY_BYTES", 1_048_576);
        let rate_limit_per_minute = parse_u64("RATE_LIMIT_PER_MINUTE", 0);
        let rate_limit_burst = parse_u64("RATE_LIMIT_BURST", 0);
        let auth_failure_rate_limit_per_minute = parse_u64("AUTH_FAILURE_RATE_LIMIT_PER_MINUTE", 0);
        let auth_failure_rate_limit_burst = parse_u64("AUTH_FAILURE_RATE_LIMIT_BURST", 0);
        let access_mode = parse_access_mode("ACCESS_MODE");
        let api_key_secret = env::var("API_KEY_SECRET")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let key_rate_limit_per_minute = parse_u64("KEY_RATE_LIMIT_PER_MINUTE", 0);
        let key_rate_limit_burst = parse_u64("KEY_RATE_LIMIT_BURST", 0);
        let api_key_cache_ttl = Duration::from_secs(parse_u64("API_KEY_CACHE_TTL_SECONDS", 300));
        let api_key_cache_capacity = parse_usize("API_KEY_CACHE_CAPACITY", 10_000);
        let track_keys_in_open_mode = parse_bool("TRACK_KEYS_IN_OPEN_MODE", false);
        let trusted_proxies = parse_trusted_proxies("TRUSTED_PROXY_CIDRS")?;
        warn_on_broad_proxy_ranges(&trusted_proxies);
        let usage_tracking_enabled = parse_bool("USAGE_TRACKING_ENABLED", true);
        let usage_sample_rate = parse_f64("USAGE_SAMPLE_RATE", 1.0).clamp(0.0, 1.0);
        let usage_channel_capacity = parse_usize("USAGE_CHANNEL_CAPACITY", 2000);
        let usage_flush_interval =
            Duration::from_secs(parse_u64("USAGE_FLUSH_INTERVAL_SECONDS", 5).max(1));
        let usage_flush_max_entries =
            parse_usize("USAGE_FLUSH_MAX_ENTRIES", usage_channel_capacity);
        let usage_retention_days = parse_u64("USAGE_RETENTION_DAYS", 30);
        let render_queue_capacity = parse_usize("RENDER_QUEUE_CAPACITY", 256);
        let render_layer_concurrency = parse_usize("RENDER_LAYER_CONCURRENCY", 8).max(1);
        let composite_cache_enabled = parse_bool("COMPOSITE_CACHE_ENABLED", true);
        let cache_size_refresh_interval =
            Duration::from_secs(parse_u64("CACHE_SIZE_REFRESH_SECONDS", 60).max(1));
        let rpc_timeout_seconds = parse_u64("RPC_TIMEOUT_SECONDS", 30);
        let rpc_connect_timeout_seconds = parse_u64("RPC_CONNECT_TIMEOUT_SECONDS", 5);
        let rpc_failure_threshold =
            parse_u64("RPC_FAILURE_THRESHOLD", 2).min(u32::MAX as u64) as u32;
        let rpc_failure_cooldown_seconds = parse_u64("RPC_FAILURE_COOLDOWN_SECONDS", 60);
        let failure_log_path = env::var("FAILURE_LOG_PATH")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case("off"))
            .map(PathBuf::from)
            .or_else(|| Some(PathBuf::from("/var/log/renderer-failures.log")));
        let failure_log_max_bytes = parse_u64("FAILURE_LOG_MAX_BYTES", 102_400);

        if access_mode != AccessMode::Open && api_key_secret.is_none() {
            return Err(anyhow::anyhow!(
                "API_KEY_SECRET is required when ACCESS_MODE is not open"
            ));
        }

        let require_approval = parse_bool("REQUIRE_APPROVAL", true);
        let allow_http = parse_bool("ALLOW_HTTP", false);
        let allow_private_networks = parse_bool("ALLOW_PRIVATE_NETWORKS", false);

        let warmup_widths = parse_list_env("WARMUP_WIDTHS")
            .unwrap_or_else(|| vec!["medium".to_string(), "large".to_string()]);
        let warmup_include_og = parse_bool("WARMUP_INCLUDE_OG", true);
        let warmup_max_tokens = parse_usize("WARMUP_MAX_TOKENS", 1000);
        let warmup_max_renders_per_job = parse_usize("WARMUP_MAX_RENDERS_PER_JOB", 6);
        let warmup_job_timeout_seconds = parse_u64("WARMUP_JOB_TIMEOUT_SECONDS", 600);
        let warmup_max_block_span = parse_u64("WARMUP_MAX_BLOCK_SPAN", 0);
        let warmup_max_concurrent_asset_pins = parse_usize("WARMUP_MAX_CONCURRENT_ASSET_PINS", 4);
        let token_state_check_ttl_seconds = parse_u64("TOKEN_STATE_CHECK_TTL_SECONDS", 86400);
        let fresh_rate_limit_seconds = parse_u64("FRESH_RATE_LIMIT_SECONDS", 300);
        let primary_asset_cache_ttl =
            Duration::from_secs(parse_u64("PRIMARY_ASSET_CACHE_TTL_SECONDS", 60));
        let primary_asset_negative_ttl =
            Duration::from_secs(parse_u64("PRIMARY_ASSET_NEGATIVE_TTL_SECONDS", 15));
        let primary_asset_cache_capacity = parse_usize("PRIMARY_ASSET_CACHE_CAPACITY", 10_000);
        let outbound_client_cache_ttl =
            Duration::from_secs(parse_u64("OUTBOUND_CLIENT_CACHE_TTL_SECONDS", 900));
        let outbound_client_cache_capacity = parse_usize("OUTBOUND_CLIENT_CACHE_CAPACITY", 256);
        let landing = parse_landing_config()?;
        let openapi_public = parse_bool("OPENAPI_PUBLIC", true);
        let landing_public = parse_bool("LANDING_PUBLIC", false) && landing.is_some();
        let status_public = parse_bool("STATUS_PUBLIC", landing_public);
        let render_policy = RenderPolicy {
            child_layer_mode: parse_child_layer_mode(
                "CHILD_LAYER_MODE",
                ChildLayerMode::AboveSlot,
            )?,
            raster_mismatch_fixed: parse_raster_mismatch_policy(
                "RASTER_MISMATCH_FIXED",
                RasterMismatchPolicy::TopLeftNoScale,
            )?,
            raster_mismatch_child: parse_raster_mismatch_policy(
                "RASTER_MISMATCH_CHILD",
                RasterMismatchPolicy::TopLeftNoScale,
            )?,
        };
        let collection_render_overrides =
            parse_collection_render_overrides("COLLECTION_RENDER_OVERRIDES")?;

        Ok(Self {
            host,
            port,
            admin_password,
            db_path,
            cache_dir,
            pinning_enabled,
            pinned_dir,
            local_ipfs_enabled,
            local_ipfs_bind,
            local_ipfs_port,
            cache_max_size_bytes,
            render_cache_min_ttl,
            asset_cache_min_ttl,
            cache_touch_interval,
            cache_evict_interval,
            max_concurrent_renders,
            max_concurrent_ipfs_fetches,
            max_concurrent_rpc_calls,
            default_canvas_width,
            default_canvas_height,
            default_cache_timestamp,
            default_cache_ttl,
            rpc_endpoints,
            render_utils_addresses,
            approval_contracts,
            approval_start_blocks,
            approval_poll_interval_seconds,
            approval_confirmations,
            chain_id_map,
            approval_sync_interval_seconds,
            approval_negative_cache_seconds,
            approval_negative_cache_capacity,
            approval_enumeration_enabled,
            max_approval_staleness_seconds,
            approvals_contract_chain,
            ipfs_gateways,
            ipfs_timeout_seconds,
            max_metadata_json_bytes,
            max_svg_bytes,
            max_svg_node_count,
            max_raster_bytes,
            max_raster_resize_bytes,
            max_raster_resize_dim,
            max_layers_per_render,
            max_canvas_pixels,
            max_total_raster_pixels,
            max_cache_variants_per_key,
            max_decoded_raster_pixels,
            max_overlay_length,
            max_background_length,
            max_in_flight_requests,
            max_admin_body_bytes,
            rate_limit_per_minute,
            rate_limit_burst,
            auth_failure_rate_limit_per_minute,
            auth_failure_rate_limit_burst,
            access_mode,
            api_key_secret,
            key_rate_limit_per_minute,
            key_rate_limit_burst,
            api_key_cache_ttl,
            api_key_cache_capacity,
            track_keys_in_open_mode,
            trusted_proxies,
            usage_tracking_enabled,
            usage_sample_rate,
            usage_channel_capacity,
            usage_flush_interval,
            usage_flush_max_entries,
            usage_retention_days,
            render_queue_capacity,
            render_layer_concurrency,
            composite_cache_enabled,
            cache_size_refresh_interval,
            rpc_timeout_seconds,
            rpc_connect_timeout_seconds,
            rpc_failure_threshold,
            rpc_failure_cooldown_seconds,
            failure_log_path,
            failure_log_max_bytes,
            require_approval,
            allow_http,
            allow_private_networks,
            warmup_widths,
            warmup_include_og,
            warmup_max_tokens,
            warmup_max_renders_per_job,
            warmup_job_timeout_seconds,
            warmup_max_block_span,
            warmup_max_concurrent_asset_pins,
            token_state_check_ttl_seconds,
            fresh_rate_limit_seconds,
            primary_asset_cache_ttl,
            primary_asset_negative_ttl,
            primary_asset_cache_capacity,
            outbound_client_cache_ttl,
            outbound_client_cache_capacity,
            openapi_public,
            render_policy,
            collection_render_overrides,
            status_public,
            landing_public,
            landing,
        })
    }

    pub fn chain_id_for_name(&self, chain: &str) -> Option<u64> {
        let chain = chain.to_ascii_lowercase();
        self.chain_id_map
            .iter()
            .find(|(_, name)| **name == chain)
            .map(|(id, _)| *id)
    }
}

fn parse_access_mode(key: &str) -> AccessMode {
    match env::var(key)
        .unwrap_or_else(|_| "open".to_string())
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "key_required" => AccessMode::KeyRequired,
        "hybrid" => AccessMode::Hybrid,
        "denylist_only" => AccessMode::DenylistOnly,
        "allowlist_only" => AccessMode::AllowlistOnly,
        _ => AccessMode::Open,
    }
}

fn parse_u16(key: &str, default: u16) -> u16 {
    env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn parse_u32(key: &str, default: u32) -> u32 {
    env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn parse_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn parse_usize(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn parse_f64(key: &str, default: f64) -> f64 {
    env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn parse_bool(key: &str, default: bool) -> bool {
    env::var(key)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn parse_json_env<T: DeserializeOwned>(key: &str) -> Option<T> {
    let raw = env::var(key).ok()?;
    serde_json::from_str(&raw).ok()
}

fn normalize_chain_map<T>(map: HashMap<String, T>) -> HashMap<String, T> {
    let mut normalized = HashMap::new();
    for (key, value) in map {
        normalized.insert(key.to_ascii_lowercase(), value);
    }
    normalized
}

fn parse_chain_id_map(key: &str) -> Result<HashMap<u64, String>> {
    let raw: HashMap<String, String> = parse_json_env(key).unwrap_or_default();
    let mut parsed = HashMap::new();
    for (id, chain) in raw {
        let chain_id = id
            .parse::<u64>()
            .with_context(|| format!("invalid chain id in {key}"))?;
        parsed.insert(chain_id, chain.to_ascii_lowercase());
    }
    Ok(parsed)
}

fn parse_default_cache_timestamp() -> Result<Option<String>> {
    let value = match env::var("DEFAULT_CACHE_TIMESTAMP") {
        Ok(value) => value,
        Err(_) => return Ok(Some("0".to_string())),
    };
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("off")
        || trimmed.eq_ignore_ascii_case("none")
        || trimmed.eq_ignore_ascii_case("disabled")
    {
        return Ok(None);
    }
    if trimmed.len() > 13 || !trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(anyhow::anyhow!(
            "DEFAULT_CACHE_TIMESTAMP must be numeric and at most 13 digits"
        ));
    }
    Ok(Some(trimmed.to_string()))
}

fn is_loopback_bind(bind: &str) -> bool {
    let trimmed = bind.trim();
    if trimmed.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match trimmed.parse::<IpAddr>() {
        Ok(addr) => addr.is_loopback(),
        Err(_) => false,
    }
}

fn format_local_gateway_url(bind: &str, port: u16) -> String {
    let trimmed = bind.trim();
    let host = if trimmed.contains(':') && !trimmed.starts_with('[') && !trimmed.ends_with(']') {
        format!("[{trimmed}]")
    } else {
        trimmed.to_string()
    };
    format!("http://{host}:{port}/ipfs/")
}

fn parse_child_layer_mode(key: &str, default: ChildLayerMode) -> Result<ChildLayerMode> {
    let value = env::var(key)
        .ok()
        .map(|value| value.trim().to_ascii_lowercase());
    match value.as_deref() {
        None => Ok(default),
        Some("above_slot") | Some("above") => Ok(ChildLayerMode::AboveSlot),
        Some("below_slot") | Some("below") => Ok(ChildLayerMode::BelowSlot),
        Some("same_z_after") | Some("same_after") => Ok(ChildLayerMode::SameZAfter),
        Some("same_z_before") | Some("same_before") => Ok(ChildLayerMode::SameZBefore),
        Some(_) => Err(anyhow!("invalid {key} value")),
    }
}

fn parse_raster_mismatch_policy(
    key: &str,
    default: RasterMismatchPolicy,
) -> Result<RasterMismatchPolicy> {
    let value = env::var(key)
        .ok()
        .map(|value| value.trim().to_ascii_lowercase());
    match value.as_deref() {
        None => Ok(default),
        Some("error") => Ok(RasterMismatchPolicy::Error),
        Some("scale_to_canvas") | Some("scale") => Ok(RasterMismatchPolicy::ScaleToCanvas),
        Some("center_no_scale") | Some("center") => Ok(RasterMismatchPolicy::CenterNoScale),
        Some("top_left_no_scale") | Some("top_left") => Ok(RasterMismatchPolicy::TopLeftNoScale),
        Some(_) => Err(anyhow!("invalid {key} value")),
    }
}

fn parse_collection_render_overrides(key: &str) -> Result<HashMap<String, RenderPolicyOverride>> {
    let raw: HashMap<String, RenderPolicyOverrideRaw> = parse_json_env(key).unwrap_or_default();
    let mut parsed = HashMap::new();
    for (collection_key, value) in raw {
        let normalized = collection_key.trim().to_ascii_lowercase();
        let override_entry = RenderPolicyOverride {
            child_layer_mode: match value.child_layer_mode.as_deref() {
                None => None,
                Some(_) => Some(parse_child_layer_mode_value(
                    key,
                    value.child_layer_mode.as_deref().unwrap(),
                )?),
            },
            raster_mismatch_fixed: match value.raster_mismatch_fixed.as_deref() {
                None => None,
                Some(raw_value) => Some(parse_raster_mismatch_value(key, raw_value)?),
            },
            raster_mismatch_child: match value.raster_mismatch_child.as_deref() {
                None => None,
                Some(raw_value) => Some(parse_raster_mismatch_value(key, raw_value)?),
            },
        };
        parsed.insert(normalized, override_entry);
    }
    Ok(parsed)
}

fn parse_child_layer_mode_value(key: &str, raw: &str) -> Result<ChildLayerMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "above_slot" | "above" => Ok(ChildLayerMode::AboveSlot),
        "below_slot" | "below" => Ok(ChildLayerMode::BelowSlot),
        "same_z_after" | "same_after" => Ok(ChildLayerMode::SameZAfter),
        "same_z_before" | "same_before" => Ok(ChildLayerMode::SameZBefore),
        _ => Err(anyhow!("invalid {key} child_layer_mode value")),
    }
}

fn parse_raster_mismatch_value(key: &str, raw: &str) -> Result<RasterMismatchPolicy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "error" => Ok(RasterMismatchPolicy::Error),
        "scale_to_canvas" | "scale" => Ok(RasterMismatchPolicy::ScaleToCanvas),
        "center_no_scale" | "center" => Ok(RasterMismatchPolicy::CenterNoScale),
        "top_left_no_scale" | "top_left" => Ok(RasterMismatchPolicy::TopLeftNoScale),
        _ => Err(anyhow!("invalid {key} raster mismatch value")),
    }
}

fn parse_list_env(key: &str) -> Option<Vec<String>> {
    let raw = env::var(key).ok()?;
    if raw.trim_start().starts_with('[') {
        serde_json::from_str(&raw).ok()
    } else {
        let list = raw
            .split(',')
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect::<Vec<_>>();
        if list.is_empty() { None } else { Some(list) }
    }
}

fn parse_trusted_proxies(key: &str) -> Result<Vec<IpNet>> {
    let values = match parse_list_env(key) {
        Some(values) => values,
        None => return Ok(Vec::new()),
    };
    let mut parsed = Vec::new();
    for value in values {
        if let Ok(net) = value.parse::<IpNet>() {
            parsed.push(net);
            continue;
        }
        if let Ok(addr) = value.parse::<IpAddr>() {
            parsed.push(IpNet::from(addr));
            continue;
        }
        return Err(anyhow::anyhow!("invalid trusted proxy entry: {value}"));
    }
    Ok(parsed)
}

fn warn_on_broad_proxy_ranges(trusted: &[IpNet]) {
    for net in trusted {
        let prefix = net.prefix_len();
        if net.addr().is_ipv4() {
            if prefix <= 8 {
                warn!(
                    cidr = %net,
                    "trusted proxy range is very broad; clients may spoof IPs"
                );
            }
        } else if prefix <= 32 {
            warn!(
                cidr = %net,
                "trusted proxy range is very broad; clients may spoof IPs"
            );
        }
    }
}

fn parse_landing_config() -> Result<Option<LandingConfig>> {
    if cfg!(windows) {
        if env::var("LANDING").is_ok() || env::var("LANDING_DIR").is_ok() {
            return Err(anyhow::anyhow!(
                "LANDING is not supported on Windows builds"
            ));
        }
    }
    let landing_dir = env::var("LANDING_DIR").ok().map(PathBuf::from);
    let landing_file = env::var("LANDING").ok();
    match (landing_dir, landing_file) {
        (None, None) => Ok(None),
        (Some(dir), Some(file)) => {
            let file = file.trim().to_string();
            if file.is_empty() {
                return Err(anyhow::anyhow!("LANDING must be a file name"));
            }
            let candidate = std::path::Path::new(&file);
            let mut components = candidate.components();
            match (components.next(), components.next()) {
                (Some(std::path::Component::Normal(_)), None) => {}
                _ => return Err(anyhow::anyhow!("LANDING must be a single file name")),
            }
            let is_html = candidate
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("html"))
                .unwrap_or(false);
            if !is_html {
                return Err(anyhow::anyhow!("LANDING must be an .html file"));
            }
            if !dir.exists() || !dir.is_dir() {
                return Err(anyhow::anyhow!(
                    "LANDING_DIR does not exist or is not a directory"
                ));
            }
            let strict_headers = parse_bool("LANDING_STRICT_HEADERS", true);
            Ok(Some(LandingConfig {
                dir,
                file,
                strict_headers,
            }))
        }
        _ => Err(anyhow::anyhow!("LANDING and LANDING_DIR must both be set")),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminCollectionInput {
    pub chain: String,
    pub collection_address: String,
    pub og_focal_point: Option<i64>,
    pub og_overlay_uri: Option<String>,
    pub watermark_overlay_uri: Option<String>,
    pub warmup_strategy: Option<String>,
    pub approved: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn with_env_lock<F: FnOnce()>(f: F) {
        let lock = ENV_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock.lock().unwrap();
        f();
    }

    #[test]
    fn parse_list_env_csv() {
        with_env_lock(|| {
            unsafe { env::set_var("WARMUP_WIDTHS", "medium, large , ,xl") };
            let list = parse_list_env("WARMUP_WIDTHS").unwrap();
            assert_eq!(list, vec!["medium", "large", "xl"]);
            unsafe { env::remove_var("WARMUP_WIDTHS") };
        });
    }

    #[test]
    fn parse_list_env_json() {
        with_env_lock(|| {
            unsafe { env::set_var("WARMUP_WIDTHS", r#"["thumb","large"]"#) };
            let list = parse_list_env("WARMUP_WIDTHS").unwrap();
            assert_eq!(list, vec!["thumb", "large"]);
            unsafe { env::remove_var("WARMUP_WIDTHS") };
        });
    }

    #[test]
    fn default_cache_timestamp_defaults_to_zero() {
        with_env_lock(|| {
            unsafe { env::remove_var("DEFAULT_CACHE_TIMESTAMP") };
            let value = parse_default_cache_timestamp().unwrap();
            assert_eq!(value, Some("0".to_string()));
        });
    }

    #[test]
    fn default_cache_timestamp_can_disable() {
        with_env_lock(|| {
            unsafe { env::set_var("DEFAULT_CACHE_TIMESTAMP", "off") };
            let value = parse_default_cache_timestamp().unwrap();
            assert_eq!(value, None);
            unsafe { env::remove_var("DEFAULT_CACHE_TIMESTAMP") };
        });
    }

    #[test]
    fn from_env_requires_admin_password() {
        with_env_lock(|| {
            unsafe { env::remove_var("ADMIN_PASSWORD") };
            let result = Config::from_env();
            assert!(result.is_err());
        });
    }

    #[test]
    fn from_env_parses_rpc_endpoints() {
        with_env_lock(|| {
            unsafe { env::set_var("ADMIN_PASSWORD", "test") };
            unsafe { env::set_var("RPC_ENDPOINTS", r#"{"base":["https://example.org"]}"#) };
            unsafe { env::set_var("RENDER_UTILS_ADDRESSES", r#"{"base":"0x123"}"#) };
            let config = Config::from_env().unwrap();
            assert_eq!(
                config.rpc_endpoints.get("base").unwrap(),
                &vec!["https://example.org".to_string()]
            );
            unsafe { env::remove_var("ADMIN_PASSWORD") };
            unsafe { env::remove_var("RPC_ENDPOINTS") };
            unsafe { env::remove_var("RENDER_UTILS_ADDRESSES") };
        });
    }
}
