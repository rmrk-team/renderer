use crate::config::Config;
use crate::db::{Database, RpcEndpoint};
use anyhow::{Context, Result, anyhow};
use ethers::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use url::Url;

abigen!(
    RmrkEquipRenderUtils,
    r#"[
        {
            "type":"function",
            "name":"composeEquippables",
            "stateMutability":"view",
            "inputs":[
                {"name":"target","type":"address"},
                {"name":"tokenId","type":"uint256"},
                {"name":"assetId","type":"uint64"}
            ],
            "outputs":[
                {"name":"metadataURI","type":"string"},
                {"name":"equippableGroupId","type":"uint64"},
                {"name":"catalogAddress","type":"address"},
                {"name":"fixedParts","type":"tuple[]","components":[
                    {"name":"partId","type":"uint64"},
                    {"name":"z","type":"uint8"},
                    {"name":"metadataURI","type":"string"}
                ]},
                {"name":"slotParts","type":"tuple[]","components":[
                    {"name":"partId","type":"uint64"},
                    {"name":"childAssetId","type":"uint64"},
                    {"name":"z","type":"uint8"},
                    {"name":"childAddress","type":"address"},
                    {"name":"childId","type":"uint256"},
                    {"name":"childAssetMetadata","type":"string"},
                    {"name":"partMetadata","type":"string"}
                ]}
            ]
        },
        {
            "type":"function",
            "name":"getTopAssetAndEquippableDataForToken",
            "stateMutability":"view",
            "inputs":[
                {"name":"target","type":"address"},
                {"name":"tokenId","type":"uint256"}
            ],
            "outputs":[
                {"name":"topAsset","type":"tuple","components":[
                    {"name":"id","type":"uint64"},
                    {"name":"equippableGroupId","type":"uint64"},
                    {"name":"priority","type":"uint64"},
                    {"name":"catalogAddress","type":"address"},
                    {"name":"metadata","type":"string"},
                    {"name":"partIds","type":"uint64[]"}
                ]}
            ]
        },
        {
            "type":"function",
            "name":"getAssetIdWithTopPriority",
            "stateMutability":"view",
            "inputs":[
                {"name":"target","type":"address"},
                {"name":"tokenId","type":"uint256"}
            ],
            "outputs":[
                {"name":"assetId","type":"uint64"},
                {"name":"priority","type":"uint64"}
            ]
        }
    ]"#
);

abigen!(
    RmrkMultiAsset,
    r#"[
        {
            "type":"function",
            "name":"getAssetMetadata",
            "stateMutability":"view",
            "inputs":[
                {"name":"tokenId","type":"uint256"},
                {"name":"assetId","type":"uint64"}
            ],
            "outputs":[
                {"name":"metadata","type":"string"}
            ]
        }
    ]"#
);

abigen!(
    RmrkCatalog,
    r#"[
        event AddedPart(uint64 indexed partId,uint8 indexed itemType,uint8 zIndex,address[] equippableAddresses,string metadataURI)
        function getMetadataURI() view returns (string)
    ]"#
);

abigen!(
    RendererApprovals,
    r#"[
        event ApprovalUpdated(uint256 indexed chainId,address indexed collection,uint64 approvedUntil,address payer,uint256 amountPaid)
        event ApprovalRevoked(uint256 indexed chainId,address indexed collection)
        function getApproval(uint256 chainId, address collection) view returns (uint64 approvedUntil, uint64 approvedAt, address payer)
        function approved(uint256 chainId, address collection) view returns (bool)
        function isApproved(uint256 chainId, address collection) view returns (bool)
        function approvedUntil(uint256 chainId, address collection) view returns (uint64)
        function approvalKeyCount() view returns (uint256)
        function approvalKeyAt(uint256 index) view returns (uint256 chainId, address collection, uint64 approvedUntil)
        function approvalKeysPage(uint256 start, uint256 limit) view returns (uint256[] chainIds, address[] collections, uint64[] approvedUntil)
    ]"#
);

abigen!(
    ERC721Enumerable,
    r#"[
        function totalSupply() view returns (uint256)
        function tokenByIndex(uint256) view returns (uint256)
    ]"#
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixedPart {
    pub part_id: u64,
    pub z: u8,
    pub metadata_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotPart {
    pub part_id: u64,
    pub child_asset_id: u64,
    pub z: u8,
    pub child_address: String,
    pub child_id: String,
    pub child_asset_metadata: String,
    pub part_metadata: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposeResult {
    pub metadata_uri: String,
    pub catalog_address: String,
    pub fixed_parts: Vec<FixedPart>,
    pub slot_parts: Vec<SlotPart>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogPart {
    pub part_id: u64,
    pub item_type: u8,
    pub z: u8,
    pub metadata_uri: String,
}

#[derive(Clone)]
pub struct ChainClient {
    config: Arc<Config>,
    db: Database,
    providers: Arc<Mutex<HashMap<String, Arc<Provider<Http>>>>>,
    endpoint_cache: Arc<Mutex<HashMap<String, Vec<RpcEndpoint>>>>,
    endpoint_health: Arc<Mutex<HashMap<String, EndpointHealth>>>,
}

#[derive(Debug, Clone)]
struct EndpointHealth {
    failures: u32,
    cooldown_until: Option<Instant>,
}

impl ChainClient {
    pub fn new(config: Arc<Config>, db: Database) -> Self {
        Self {
            config,
            db,
            providers: Arc::new(Mutex::new(HashMap::new())),
            endpoint_cache: Arc::new(Mutex::new(HashMap::new())),
            endpoint_health: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn compose_equippables(
        &self,
        chain: &str,
        collection: &str,
        token_id: &str,
        asset_id: &str,
    ) -> Result<ComposeResult> {
        let render_utils_address = self.render_utils_address(chain)?;
        let collection = Address::from_str(collection)?;
        let token_id = U256::from_dec_str(token_id)?;
        let asset_id = asset_id.parse::<u64>()?;
        let response = self
            .call_with_failover(chain, move |provider| {
                let contract = RmrkEquipRenderUtils::new(render_utils_address, provider);
                let collection = collection;
                let token_id = token_id;
                let asset_id = asset_id;
                async move {
                    contract
                        .compose_equippables(collection, token_id, asset_id)
                        .call()
                        .await
                        .map_err(|err| err.into())
                }
            })
            .await?;
        let (metadata_uri, _equippable_group_id, catalog_address, fixed_parts, slot_parts) =
            response;
        let fixed_parts = fixed_parts
            .into_iter()
            .map(|(part_id, z, metadata_uri)| FixedPart {
                part_id,
                z,
                metadata_uri,
            })
            .collect();
        let slot_parts = slot_parts
            .into_iter()
            .map(
                |(
                    part_id,
                    child_asset_id,
                    z,
                    child_address,
                    child_id,
                    child_asset_metadata,
                    part_metadata,
                )| SlotPart {
                    part_id,
                    child_asset_id,
                    z,
                    child_address: format!("{:#x}", child_address),
                    child_id: child_id.to_string(),
                    child_asset_metadata,
                    part_metadata,
                },
            )
            .collect();
        Ok(ComposeResult {
            metadata_uri,
            catalog_address: format!("{:#x}", catalog_address),
            fixed_parts,
            slot_parts,
        })
    }

    pub async fn get_top_asset_id(
        &self,
        chain: &str,
        collection: &str,
        token_id: &str,
    ) -> Result<u64> {
        let render_utils_address = self.render_utils_address(chain)?;
        let collection = Address::from_str(collection)?;
        let token_id = U256::from_dec_str(token_id)?;
        let response = self
            .call_with_failover(chain, move |provider| {
                let contract = RmrkEquipRenderUtils::new(render_utils_address, provider);
                let collection = collection;
                let token_id = token_id;
                async move {
                    contract
                        .get_asset_id_with_top_priority(collection, token_id)
                        .call()
                        .await
                        .map_err(|err| err.into())
                }
            })
            .await?;
        Ok(response.0)
    }

    pub async fn get_asset_metadata(
        &self,
        chain: &str,
        collection: &str,
        token_id: &str,
        asset_id: &str,
    ) -> Result<String> {
        let collection = Address::from_str(collection)?;
        let token_id = U256::from_dec_str(token_id)?;
        let asset_id = asset_id.parse::<u64>().context("invalid asset id")?;
        let response = self
            .call_with_failover(chain, move |provider| {
                let contract = RmrkMultiAsset::new(collection, provider);
                async move {
                    contract
                        .get_asset_metadata(token_id, asset_id)
                        .call()
                        .await
                        .map_err(|err| err.into())
                }
            })
            .await?;
        Ok(response)
    }

    pub async fn get_catalog_metadata_uri(
        &self,
        chain: &str,
        catalog_address: &str,
    ) -> Result<String> {
        let catalog = Address::from_str(catalog_address)?;
        let response = self
            .call_with_failover(chain, move |provider| {
                let contract = RmrkCatalog::new(catalog, provider);
                async move {
                    contract
                        .get_metadata_uri()
                        .call()
                        .await
                        .map_err(|err| err.into())
                }
            })
            .await?;
        Ok(response)
    }

    pub async fn scan_catalog_parts(
        &self,
        chain: &str,
        catalog_address: &str,
        from_block: u64,
        to_block: Option<u64>,
    ) -> Result<Vec<CatalogPart>> {
        let catalog = Address::from_str(catalog_address)?;
        self.call_with_failover(chain, move |provider| {
            let catalog = catalog;
            async move {
                let latest_block = provider.get_block_number().await?;
                let to_block = to_block.unwrap_or_else(|| latest_block.as_u64());
                let events = RmrkCatalog::new(catalog, provider)
                    .event::<AddedPartFilter>()
                    .from_block(from_block)
                    .to_block(to_block)
                    .query()
                    .await?;
                Ok(events
                    .into_iter()
                    .map(|event| CatalogPart {
                        part_id: event.part_id,
                        item_type: event.item_type,
                        z: event.z_index,
                        metadata_uri: event.metadata_uri,
                    })
                    .collect())
            }
        })
        .await
    }

    pub async fn erc721_token_ids_enumerable(
        &self,
        chain: &str,
        collection: &str,
    ) -> Result<Vec<String>> {
        let collection = Address::from_str(collection)?;
        self.call_with_failover(chain, move |provider| {
            let contract = ERC721Enumerable::new(collection, provider);
            async move {
                let total_supply: U256 = contract.total_supply().call().await?;
                let mut token_ids = Vec::new();
                for index in 0..total_supply.as_u64() {
                    let token_id: U256 = contract.token_by_index(index.into()).call().await?;
                    token_ids.push(token_id.to_string());
                }
                Ok(token_ids)
            }
        })
        .await
    }

    pub async fn scan_transfer_logs(
        &self,
        chain: &str,
        collection: &str,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<String>> {
        let collection = Address::from_str(collection)?;
        self.call_with_failover(chain, move |provider| {
            let collection = collection;
            async move {
                let zero = H256::zero();
                let filter = Filter::new()
                    .address(collection)
                    .event("Transfer(address,address,uint256)")
                    .topic1(zero)
                    .from_block(from_block)
                    .to_block(to_block);
                let logs = provider.get_logs(&filter).await?;
                let mut token_ids = Vec::new();
                for log in logs {
                    if log.topics.len() >= 4 {
                        let token_id = U256::from_big_endian(log.topics[3].as_bytes());
                        token_ids.push(token_id.to_string());
                    }
                }
                Ok(token_ids)
            }
        })
        .await
    }

    pub async fn call_with_approvals<T, F, Fut>(&self, chain: &str, f: F) -> Result<Option<T>>
    where
        F: Fn(RendererApprovals<Provider<Http>>) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let address = match self.config.approval_contracts.get(chain) {
            Some(address) => Address::from_str(address)?,
            None => return Ok(None),
        };
        let result = self
            .call_with_failover(chain, move |provider| {
                let contract = RendererApprovals::new(address, provider);
                f(contract)
            })
            .await?;
        Ok(Some(result))
    }

    fn render_utils_address(&self, chain: &str) -> Result<Address> {
        let address = self
            .config
            .render_utils_addresses
            .get(chain)
            .ok_or_else(|| anyhow!("missing render utils address for chain {chain}"))?;
        Address::from_str(address).context("invalid render utils address")
    }

    pub async fn refresh_rpc_endpoints(&self, chain: &str) -> Result<()> {
        let endpoints = self.db.list_rpc_endpoints(Some(chain)).await?;
        self.endpoint_cache
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .insert(chain.to_string(), endpoints);
        Ok(())
    }

    async fn endpoints_for_chain(&self, chain: &str) -> Result<Vec<RpcEndpoint>> {
        if let Some(cached) = self
            .endpoint_cache
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get(chain)
            .cloned()
        {
            return Ok(cached);
        }
        let endpoints = self.db.list_rpc_endpoints(Some(chain)).await?;
        self.endpoint_cache
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .insert(chain.to_string(), endpoints.clone());
        Ok(endpoints)
    }

    async fn call_with_failover<T, F, Fut>(&self, chain: &str, f: F) -> Result<T>
    where
        F: Fn(Arc<Provider<Http>>) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let endpoints = self.endpoints_for_chain(chain).await?;
        let now = Instant::now();
        let mut available = Vec::new();
        let mut cooldown = Vec::new();
        for endpoint in endpoints {
            if !endpoint.enabled {
                continue;
            }
            if self.is_endpoint_on_cooldown(&endpoint.url, now) {
                cooldown.push(endpoint);
            } else {
                available.push(endpoint);
            }
        }
        if available.is_empty() {
            available = cooldown;
        }
        if available.is_empty() {
            return Err(anyhow!("no rpc endpoints configured for {chain}"));
        }
        let mut last_err: Option<anyhow::Error> = None;
        for endpoint in available {
            let provider = match self.provider_for_url(&endpoint.url) {
                Ok(provider) => provider,
                Err(err) => {
                    self.record_endpoint_failure(&endpoint.url);
                    last_err = Some(anyhow!(
                        "rpc endpoint {} init failed: {}",
                        endpoint.url,
                        err
                    ));
                    continue;
                }
            };
            match f(provider).await {
                Ok(result) => {
                    self.record_endpoint_success(&endpoint.url);
                    return Ok(result);
                }
                Err(err) => {
                    self.record_endpoint_failure(&endpoint.url);
                    last_err = Some(anyhow!("rpc endpoint {} failed: {}", endpoint.url, err));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("rpc call failed for {chain}")))
    }

    fn is_endpoint_on_cooldown(&self, url: &str, now: Instant) -> bool {
        let mut map = self
            .endpoint_health
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if let Some(entry) = map.get_mut(url) {
            if let Some(until) = entry.cooldown_until {
                if until > now {
                    return true;
                }
                entry.cooldown_until = None;
            }
        }
        false
    }

    fn record_endpoint_failure(&self, url: &str) {
        if self.config.rpc_failure_threshold == 0 || self.config.rpc_failure_cooldown_seconds == 0 {
            return;
        }
        let mut map = self
            .endpoint_health
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let entry = map.entry(url.to_string()).or_insert(EndpointHealth {
            failures: 0,
            cooldown_until: None,
        });
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= self.config.rpc_failure_threshold {
            entry.failures = 0;
            entry.cooldown_until = Some(
                Instant::now() + Duration::from_secs(self.config.rpc_failure_cooldown_seconds),
            );
        }
    }

    fn record_endpoint_success(&self, url: &str) {
        let mut map = self
            .endpoint_health
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if let Some(entry) = map.get_mut(url) {
            entry.failures = 0;
            entry.cooldown_until = None;
        }
    }

    pub fn provider_for_url(&self, url: &str) -> Result<Arc<Provider<Http>>> {
        if let Some(provider) = self
            .providers
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .get(url)
            .cloned()
        {
            return Ok(provider);
        }
        let client = reqwest11::Client::builder()
            .timeout(Duration::from_secs(self.config.rpc_timeout_seconds))
            .connect_timeout(Duration::from_secs(self.config.rpc_connect_timeout_seconds))
            .build()
            .context("build rpc http client")?;
        let url = Url::parse(url).context("invalid rpc url")?;
        let key = url.to_string();
        let http = Http::new_with_client(url, client);
        let provider = Arc::new(Provider::new(http));
        self.providers
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .insert(key, provider.clone());
        Ok(provider)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AccessMode, ChildLayerMode, Config, RasterMismatchPolicy, RenderPolicy};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::tempdir;

    fn live_base_config(
        db_path: PathBuf,
        cache_dir: PathBuf,
        rpc_urls: Vec<String>,
        render_utils: String,
        rpc_timeout_seconds: u64,
        rpc_connect_timeout_seconds: u64,
    ) -> Config {
        let mut rpc_endpoints = HashMap::new();
        rpc_endpoints.insert("base".to_string(), rpc_urls);
        let mut render_utils_addresses = HashMap::new();
        render_utils_addresses.insert("base".to_string(), render_utils);

        Config {
            host: "127.0.0.1".to_string(),
            port: 0,
            admin_password: "test".to_string(),
            db_path,
            cache_dir,
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
            max_concurrent_rpc_calls: 4,
            default_canvas_width: 1,
            default_canvas_height: 1,
            default_cache_timestamp: None,
            default_cache_ttl: Duration::from_secs(0),
            rpc_endpoints,
            render_utils_addresses,
            approval_contracts: HashMap::new(),
            approval_start_blocks: HashMap::new(),
            approval_poll_interval_seconds: 0,
            approval_confirmations: 0,
            chain_id_map: HashMap::new(),
            approval_sync_interval_seconds: 0,
            approval_negative_cache_seconds: 0,
            approval_negative_cache_capacity: 0,
            approval_enumeration_enabled: false,
            max_approval_staleness_seconds: 0,
            approvals_contract_chain: None,
            ipfs_gateways: Vec::new(),
            ipfs_timeout_seconds: 1,
            max_metadata_json_bytes: 1,
            max_svg_bytes: 1,
            max_svg_node_count: 1,
            max_raster_bytes: 1,
            max_layers_per_render: 1,
            max_canvas_pixels: 1,
            max_total_raster_pixels: 1,
            max_cache_variants_per_key: 1,
            max_decoded_raster_pixels: 1,
            max_overlay_length: 1,
            max_background_length: 1,
            max_in_flight_requests: 1,
            max_admin_body_bytes: 1,
            rate_limit_per_minute: 0,
            rate_limit_burst: 0,
            auth_failure_rate_limit_per_minute: 0,
            auth_failure_rate_limit_burst: 0,
            access_mode: AccessMode::Open,
            api_key_secret: None,
            key_rate_limit_per_minute: 0,
            key_rate_limit_burst: 0,
            api_key_cache_ttl: Duration::from_secs(0),
            api_key_cache_capacity: 0,
            track_keys_in_open_mode: false,
            trusted_proxies: Vec::new(),
            usage_tracking_enabled: false,
            usage_sample_rate: 0.0,
            usage_channel_capacity: 0,
            usage_flush_interval: Duration::from_secs(0),
            usage_flush_max_entries: 0,
            usage_retention_days: 0,
            render_queue_capacity: 0,
            render_layer_concurrency: 1,
            composite_cache_enabled: false,
            cache_size_refresh_interval: Duration::from_secs(0),
            rpc_timeout_seconds,
            rpc_connect_timeout_seconds,
            rpc_failure_threshold: 0,
            rpc_failure_cooldown_seconds: 0,
            failure_log_path: None,
            failure_log_max_bytes: 0,
            require_approval: false,
            allow_http: false,
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
            primary_asset_cache_ttl: Duration::from_secs(0),
            primary_asset_negative_ttl: Duration::from_secs(0),
            primary_asset_cache_capacity: 0,
            outbound_client_cache_ttl: Duration::from_secs(0),
            outbound_client_cache_capacity: 0,
            openapi_public: true,
            render_policy: RenderPolicy {
                child_layer_mode: ChildLayerMode::AboveSlot,
                raster_mismatch_fixed: RasterMismatchPolicy::TopLeftNoScale,
                raster_mismatch_child: RasterMismatchPolicy::TopLeftNoScale,
            },
            collection_render_overrides: HashMap::new(),
            status_public: false,
            landing_public: false,
            landing: None,
        }
    }

    #[tokio::test]
    async fn live_base_top_asset_id_smoke() {
        let rpc_urls = match std::env::var("LIVE_BASE_RPC_URLS") {
            Ok(value) => parse_rpc_urls(&value),
            Err(_) => match std::env::var("LIVE_BASE_RPC_URL") {
                Ok(value) => vec![value],
                Err(_) => {
                    eprintln!("skipping live test; set LIVE_BASE_RPC_URL(S) to enable");
                    return;
                }
            },
        };
        if rpc_urls.is_empty() {
            eprintln!("skipping live test; LIVE_BASE_RPC_URLS was empty");
            return;
        }
        let render_utils = std::env::var("LIVE_BASE_RENDER_UTILS")
            .unwrap_or_else(|_| "0x8c2CA0412c2bf5974535fb8Fcb12bE3B7F36d6aD".to_string());
        let collection = std::env::var("LIVE_BASE_COLLECTION")
            .unwrap_or_else(|_| "0x011ff409bc4803ec5cfab41c3fd1db99fd05c004".to_string());
        let token_id = std::env::var("LIVE_BASE_TOKEN_ID").unwrap_or_else(|_| "3005".to_string());
        let expected_asset_id = std::env::var("LIVE_BASE_EXPECTED_ASSET_ID")
            .ok()
            .and_then(|value| value.parse::<u64>().ok());
        let rpc_timeout_seconds = std::env::var("LIVE_BASE_RPC_TIMEOUT_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(30);
        let rpc_connect_timeout_seconds = std::env::var("LIVE_BASE_RPC_CONNECT_TIMEOUT_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(5);

        let dir = tempdir().unwrap();
        let cache_dir = dir.path().join("cache");
        let config = live_base_config(
            dir.path().join("renderer.db"),
            cache_dir,
            rpc_urls,
            render_utils,
            rpc_timeout_seconds,
            rpc_connect_timeout_seconds,
        );
        let db = Database::new(&config).await.unwrap();
        let client = ChainClient::new(Arc::new(config), db);

        let asset_id = client
            .get_top_asset_id("base", &collection, &token_id)
            .await
            .unwrap();
        if let Some(expected) = expected_asset_id {
            assert_eq!(asset_id, expected);
        } else {
            assert!(asset_id > 0);
        }
    }

    fn parse_rpc_urls(raw: &str) -> Vec<String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }
        if trimmed.starts_with('[') {
            serde_json::from_str::<Vec<String>>(trimmed).unwrap_or_default()
        } else {
            trimmed
                .split(',')
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect()
        }
    }
}
