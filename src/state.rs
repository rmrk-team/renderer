use crate::assets::AssetResolver;
use crate::cache::{CacheManager, RenderCacheLimiter, RenderSingleflight};
use crate::chain::ChainClient;
use crate::config::Config;
use crate::db::{ClientKey, CollectionConfig, Database, IpRule};
use crate::failure_log::FailureLog;
use crate::rate_limit::{KeyRateLimiter, RateLimiter};
use crate::render_queue::RenderJob;
use crate::usage::UsageEvent;
use anyhow::Result;
use ipnet::IpNet;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, RwLock, Semaphore, mpsc};
use tracing::warn;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Database,
    pub cache: CacheManager,
    pub assets: AssetResolver,
    pub chain: ChainClient,
    pub render_singleflight: RenderSingleflight,
    pub render_semaphore: Arc<Semaphore>,
    pub rpc_semaphore: Arc<Semaphore>,
    pub warmup_notify: Arc<Notify>,
    pub render_cache_limiter: RenderCacheLimiter,
    pub rate_limiter: RateLimiter,
    pub key_rate_limiter: KeyRateLimiter,
    pub auth_fail_limiter: RateLimiter,
    pub key_render_limiter: KeyRenderLimiter,
    pub usage_tx: Option<mpsc::Sender<UsageEvent>>,
    pub render_queue_tx: Option<mpsc::Sender<RenderJob>>,
    pub api_key_cache: ApiKeyCache,
    pub primary_asset_cache: PrimaryAssetCache,
    pub approval_negative_cache: ApprovalNegativeCache,
    pub ip_rules: IpRuleCache,
    pub require_approval_cache: RequireApprovalCache,
    pub collection_config_cache: CollectionConfigCache,
    pub collection_epoch_cache: CollectionEpochCache,
    pub theme_source_cache: ThemeSourceCache,
    pub catalog_metadata_cache: CatalogMetadataCache,
    pub catalog_theme_cache: CatalogThemeCache,
    pub failure_log: Option<FailureLog>,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Config,
        db: Database,
        cache: CacheManager,
        assets: AssetResolver,
        chain: ChainClient,
        usage_tx: Option<mpsc::Sender<UsageEvent>>,
        render_queue_tx: Option<mpsc::Sender<RenderJob>>,
        failure_log: Option<FailureLog>,
    ) -> Self {
        let render_singleflight = RenderSingleflight::new();
        let render_semaphore = Arc::new(Semaphore::new(config.max_concurrent_renders));
        let rpc_limit = if config.max_concurrent_rpc_calls == 0 {
            usize::MAX
        } else {
            config.max_concurrent_rpc_calls
        };
        let rpc_semaphore = Arc::new(Semaphore::new(rpc_limit));
        let warmup_notify = Arc::new(Notify::new());
        let render_cache_limiter = RenderCacheLimiter::new(config.max_cache_variants_per_key);
        let rate_limiter = RateLimiter::new(config.rate_limit_per_minute, config.rate_limit_burst);
        let key_rate_limiter = KeyRateLimiter::new();
        let auth_fail_limiter = RateLimiter::new(
            config.auth_failure_rate_limit_per_minute,
            config.auth_failure_rate_limit_burst,
        );
        let key_render_limiter = KeyRenderLimiter::new();
        let api_key_cache =
            ApiKeyCache::new(config.api_key_cache_ttl, config.api_key_cache_capacity);
        let primary_asset_cache = PrimaryAssetCache::new(
            config.primary_asset_cache_ttl,
            config.primary_asset_negative_ttl,
            config.primary_asset_cache_capacity,
        );
        let approval_negative_cache = ApprovalNegativeCache::new(
            Duration::from_secs(config.approval_negative_cache_seconds),
            config.approval_negative_cache_capacity,
        );
        let ip_rules = IpRuleCache::new();
        let require_approval_cache = RequireApprovalCache::new(REQUIRE_APPROVAL_CACHE_TTL);
        let collection_config_cache = CollectionConfigCache::new(
            COLLECTION_CONFIG_CACHE_TTL,
            COLLECTION_CONFIG_CACHE_CAPACITY,
        );
        let collection_epoch_cache =
            CollectionEpochCache::new(COLLECTION_EPOCH_CACHE_TTL, COLLECTION_EPOCH_CACHE_CAPACITY);
        let theme_source_cache =
            ThemeSourceCache::new(THEME_SOURCE_CACHE_TTL, THEME_SOURCE_CACHE_CAPACITY);
        let catalog_metadata_cache =
            CatalogMetadataCache::new(CATALOG_META_CACHE_TTL, CATALOG_META_CACHE_CAPACITY);
        let catalog_theme_cache =
            CatalogThemeCache::new(CATALOG_THEME_CACHE_TTL, CATALOG_THEME_CACHE_CAPACITY);
        Self {
            config: Arc::new(config),
            db,
            cache,
            assets,
            chain,
            render_singleflight,
            render_semaphore,
            rpc_semaphore,
            warmup_notify,
            render_cache_limiter,
            rate_limiter,
            key_rate_limiter,
            auth_fail_limiter,
            key_render_limiter,
            usage_tx,
            render_queue_tx,
            api_key_cache,
            primary_asset_cache,
            approval_negative_cache,
            ip_rules,
            require_approval_cache,
            collection_config_cache,
            collection_epoch_cache,
            theme_source_cache,
            catalog_metadata_cache,
            catalog_theme_cache,
            failure_log,
        }
    }

    pub async fn refresh_ip_rules(&self) -> anyhow::Result<()> {
        self.ip_rules.refresh(&self.db).await
    }

    pub async fn clear_api_key_cache(&self) {
        self.api_key_cache.clear().await;
    }

    pub async fn clear_primary_asset_cache(&self) {
        self.primary_asset_cache.clear().await;
    }

    pub async fn clear_require_approval_cache(&self) {
        self.require_approval_cache.clear().await;
    }

    pub async fn invalidate_collection_cache(&self, chain: &str, collection: &str) {
        let key = collection_cache_key(chain, collection);
        self.collection_config_cache.invalidate(&key).await;
        self.collection_epoch_cache.invalidate(&key).await;
    }
}

const REQUIRE_APPROVAL_CACHE_TTL: Duration = Duration::from_secs(10);
const COLLECTION_CONFIG_CACHE_TTL: Duration = Duration::from_secs(60);
const COLLECTION_CONFIG_CACHE_CAPACITY: usize = 2048;
const COLLECTION_EPOCH_CACHE_TTL: Duration = Duration::from_secs(30);
const COLLECTION_EPOCH_CACHE_CAPACITY: usize = 2048;
const THEME_SOURCE_CACHE_TTL: Duration = Duration::from_secs(600);
const THEME_SOURCE_CACHE_CAPACITY: usize = 4096;
const CATALOG_META_CACHE_TTL: Duration = Duration::from_secs(3600);
const CATALOG_META_CACHE_CAPACITY: usize = 2048;
const CATALOG_THEME_CACHE_TTL: Duration = Duration::from_secs(3600);
const CATALOG_THEME_CACHE_CAPACITY: usize = 2048;

#[derive(Clone)]
pub struct KeyRenderLimiter {
    inner: Arc<Mutex<HashMap<i64, KeyRenderEntry>>>,
}

struct KeyRenderEntry {
    limit: usize,
    semaphore: Arc<Semaphore>,
}

impl KeyRenderLimiter {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn acquire(&self, key_id: i64, limit: usize) -> Result<OwnedSemaphorePermit> {
        let semaphore = {
            let mut guard = self.inner.lock().await;
            let entry = guard.entry(key_id).or_insert_with(|| KeyRenderEntry {
                limit,
                semaphore: Arc::new(Semaphore::new(limit.max(1))),
            });
            if entry.limit != limit {
                entry.limit = limit;
                entry.semaphore = Arc::new(Semaphore::new(limit.max(1)));
            }
            entry.semaphore.clone()
        };
        Ok(semaphore.acquire_owned().await?)
    }
}

#[derive(Clone)]
pub struct ApiKeyCache {
    ttl: Duration,
    capacity: usize,
    inner: Arc<Mutex<ApiKeyCacheInner>>,
}

#[derive(Clone)]
pub struct PrimaryAssetCache {
    ttl: Duration,
    negative_ttl: Duration,
    capacity: usize,
    inner: Arc<Mutex<PrimaryAssetCacheInner>>,
}

#[derive(Clone)]
pub struct ApprovalNegativeCache {
    ttl: Duration,
    capacity: usize,
    inner: Arc<Mutex<ApprovalNegativeCacheInner>>,
}

#[derive(Clone)]
pub struct RequireApprovalCache {
    ttl: Duration,
    inner: Arc<Mutex<Option<CachedBool>>>,
}

struct CachedBool {
    value: bool,
    expires_at: Instant,
}

#[derive(Clone)]
pub struct CollectionConfigCache {
    ttl: Duration,
    capacity: usize,
    inner: Arc<Mutex<CollectionConfigCacheInner>>,
}

#[derive(Clone)]
pub struct ThemeSourceCache {
    ttl: Duration,
    capacity: usize,
    inner: Arc<Mutex<ThemeSourceCacheInner>>,
}

struct ThemeSourceCacheInner {
    map: HashMap<String, CachedThemeSources>,
    order: VecDeque<String>,
}

struct CachedThemeSources {
    sources: [Option<String>; 4],
    expires_at: Instant,
}

#[derive(Clone)]
pub struct CatalogMetadataCache {
    ttl: Duration,
    capacity: usize,
    inner: Arc<Mutex<CatalogMetadataCacheInner>>,
}

struct CatalogMetadataCacheInner {
    map: HashMap<String, CachedCatalogMetadata>,
    order: VecDeque<String>,
}

struct CachedCatalogMetadata {
    metadata_uri: String,
    expires_at: Instant,
}

#[derive(Clone)]
pub struct CatalogThemeCache {
    ttl: Duration,
    capacity: usize,
    inner: Arc<Mutex<CatalogThemeCacheInner>>,
}

struct CatalogThemeCacheInner {
    map: HashMap<String, CachedCatalogThemes>,
    order: VecDeque<String>,
}

struct CachedCatalogThemes {
    themes: Arc<HashMap<String, [String; 4]>>,
    expires_at: Instant,
}

struct CollectionConfigCacheInner {
    map: HashMap<String, CachedCollectionConfig>,
    order: VecDeque<String>,
}

struct CachedCollectionConfig {
    value: Option<CollectionConfig>,
    expires_at: Instant,
}

#[derive(Clone)]
pub struct CollectionEpochCache {
    ttl: Duration,
    capacity: usize,
    inner: Arc<Mutex<CollectionEpochCacheInner>>,
}

struct CollectionEpochCacheInner {
    map: HashMap<String, CachedCollectionEpoch>,
    order: VecDeque<String>,
}

struct CachedCollectionEpoch {
    value: Option<i64>,
    expires_at: Instant,
}

struct ApprovalNegativeCacheInner {
    map: HashMap<String, Instant>,
    order: VecDeque<String>,
}

struct PrimaryAssetCacheInner {
    map: HashMap<String, CachedAssetId>,
    order: VecDeque<String>,
}

struct CachedAssetId {
    asset_id: Option<u64>,
    expires_at: Instant,
}

#[derive(Debug, Clone, Copy)]
pub enum PrimaryAssetCacheValue {
    Hit(u64),
    Negative,
}

impl PrimaryAssetCache {
    pub fn new(ttl: Duration, negative_ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            negative_ttl,
            capacity,
            inner: Arc::new(Mutex::new(PrimaryAssetCacheInner {
                map: HashMap::new(),
                order: VecDeque::new(),
            })),
        }
    }

    pub async fn get(&self, key: &str) -> Option<PrimaryAssetCacheValue> {
        if self.capacity == 0 || (self.ttl.is_zero() && self.negative_ttl.is_zero()) {
            return None;
        }
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        if let Some(entry) = inner.map.get(key) {
            if entry.expires_at <= now {
                inner.map.remove(key);
                inner.order.retain(|item| item != key);
                return None;
            }
            let asset_id = entry.asset_id;
            touch_key(&mut inner.order, key);
            return match asset_id {
                Some(asset_id) => Some(PrimaryAssetCacheValue::Hit(asset_id)),
                None => Some(PrimaryAssetCacheValue::Negative),
            };
        }
        None
    }

    pub async fn insert(&self, key: String, asset_id: u64) {
        if self.capacity == 0 || self.ttl.is_zero() {
            return;
        }
        let mut inner = self.inner.lock().await;
        if inner.map.contains_key(&key) {
            inner.order.retain(|item| item != &key);
        }
        inner.order.push_back(key.clone());
        inner.map.insert(
            key.clone(),
            CachedAssetId {
                asset_id: Some(asset_id),
                expires_at: Instant::now() + self.ttl,
            },
        );
        while inner.order.len() > self.capacity {
            if let Some(oldest) = inner.order.pop_front() {
                inner.map.remove(&oldest);
            }
        }
    }

    pub async fn insert_negative(&self, key: String) {
        if self.capacity == 0 || self.negative_ttl.is_zero() {
            return;
        }
        let mut inner = self.inner.lock().await;
        if inner.map.contains_key(&key) {
            inner.order.retain(|item| item != &key);
        }
        inner.order.push_back(key.clone());
        inner.map.insert(
            key.clone(),
            CachedAssetId {
                asset_id: None,
                expires_at: Instant::now() + self.negative_ttl,
            },
        );
        while inner.order.len() > self.capacity {
            if let Some(oldest) = inner.order.pop_front() {
                inner.map.remove(&oldest);
            }
        }
    }

    pub async fn clear(&self) {
        let mut inner = self.inner.lock().await;
        inner.map.clear();
        inner.order.clear();
    }
}

struct ApiKeyCacheInner {
    map: HashMap<String, CachedKey>,
    order: VecDeque<String>,
}

struct CachedKey {
    key: ClientKey,
    expires_at: Instant,
}

impl ApiKeyCache {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity,
            inner: Arc::new(Mutex::new(ApiKeyCacheInner {
                map: HashMap::new(),
                order: VecDeque::new(),
            })),
        }
    }

    pub async fn get(&self, key_hash: &str) -> Option<ClientKey> {
        if self.capacity == 0 || self.ttl.is_zero() {
            return None;
        }
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        if let Some(entry) = inner.map.get(key_hash) {
            if entry.expires_at <= now {
                inner.map.remove(key_hash);
                inner.order.retain(|item| item != key_hash);
                return None;
            }
            let key = entry.key.clone();
            touch_key(&mut inner.order, key_hash);
            return Some(key);
        }
        None
    }

    pub async fn insert(&self, key_hash: String, key: ClientKey) {
        if self.capacity == 0 || self.ttl.is_zero() {
            return;
        }
        let mut inner = self.inner.lock().await;
        if inner.map.contains_key(&key_hash) {
            inner.order.retain(|item| item != &key_hash);
        }
        inner.order.push_back(key_hash.clone());
        inner.map.insert(
            key_hash.clone(),
            CachedKey {
                key,
                expires_at: Instant::now() + self.ttl,
            },
        );
        while inner.order.len() > self.capacity {
            if let Some(oldest) = inner.order.pop_front() {
                inner.map.remove(&oldest);
            }
        }
    }

    pub async fn clear(&self) {
        let mut inner = self.inner.lock().await;
        inner.map.clear();
        inner.order.clear();
    }
}

impl ApprovalNegativeCache {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity,
            inner: Arc::new(Mutex::new(ApprovalNegativeCacheInner {
                map: HashMap::new(),
                order: VecDeque::new(),
            })),
        }
    }

    pub async fn contains(&self, key: &str) -> bool {
        if self.capacity == 0 || self.ttl.is_zero() {
            return false;
        }
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        if let Some(expires_at) = inner.map.get(key).copied() {
            if expires_at <= now {
                inner.map.remove(key);
                inner.order.retain(|item| item != key);
                return false;
            }
            touch_key(&mut inner.order, key);
            return true;
        }
        false
    }

    pub async fn insert(&self, key: String) {
        if self.capacity == 0 || self.ttl.is_zero() {
            return;
        }
        let mut inner = self.inner.lock().await;
        if inner.map.contains_key(&key) {
            inner.order.retain(|item| item != &key);
        }
        inner.order.push_back(key.clone());
        inner.map.insert(key.clone(), Instant::now() + self.ttl);
        while inner.order.len() > self.capacity {
            if let Some(oldest) = inner.order.pop_front() {
                inner.map.remove(&oldest);
            }
        }
    }
}

impl RequireApprovalCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn get(&self) -> Option<bool> {
        if self.ttl.is_zero() {
            return None;
        }
        let now = Instant::now();
        let mut guard = self.inner.lock().await;
        if let Some(entry) = guard.as_ref() {
            if entry.expires_at > now {
                return Some(entry.value);
            }
        }
        *guard = None;
        None
    }

    pub async fn set(&self, value: bool) {
        if self.ttl.is_zero() {
            return;
        }
        let mut guard = self.inner.lock().await;
        *guard = Some(CachedBool {
            value,
            expires_at: Instant::now() + self.ttl,
        });
    }

    pub async fn clear(&self) {
        let mut guard = self.inner.lock().await;
        *guard = None;
    }
}

impl CollectionConfigCache {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity,
            inner: Arc::new(Mutex::new(CollectionConfigCacheInner {
                map: HashMap::new(),
                order: VecDeque::new(),
            })),
        }
    }

    pub async fn get(&self, key: &str) -> Option<Option<CollectionConfig>> {
        if self.capacity == 0 || self.ttl.is_zero() {
            return None;
        }
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        if let Some(entry) = inner.map.get(key) {
            if entry.expires_at <= now {
                inner.map.remove(key);
                inner.order.retain(|item| item != key);
                return None;
            }
            let value = entry.value.clone();
            touch_key(&mut inner.order, key);
            return Some(value);
        }
        None
    }

    pub async fn insert(&self, key: String, value: Option<CollectionConfig>) {
        if self.capacity == 0 || self.ttl.is_zero() {
            return;
        }
        let mut inner = self.inner.lock().await;
        if inner.map.contains_key(&key) {
            inner.order.retain(|item| item != &key);
        }
        inner.order.push_back(key.clone());
        inner.map.insert(
            key.clone(),
            CachedCollectionConfig {
                value,
                expires_at: Instant::now() + self.ttl,
            },
        );
        while inner.order.len() > self.capacity {
            if let Some(oldest) = inner.order.pop_front() {
                inner.map.remove(&oldest);
            }
        }
    }

    pub async fn invalidate(&self, key: &str) {
        let mut inner = self.inner.lock().await;
        inner.map.remove(key);
        inner.order.retain(|item| item != key);
    }
}

impl CollectionEpochCache {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity,
            inner: Arc::new(Mutex::new(CollectionEpochCacheInner {
                map: HashMap::new(),
                order: VecDeque::new(),
            })),
        }
    }

    pub async fn get(&self, key: &str) -> Option<Option<i64>> {
        if self.capacity == 0 || self.ttl.is_zero() {
            return None;
        }
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        if let Some(entry) = inner.map.get(key) {
            if entry.expires_at <= now {
                inner.map.remove(key);
                inner.order.retain(|item| item != key);
                return None;
            }
            let value = entry.value;
            touch_key(&mut inner.order, key);
            return Some(value);
        }
        None
    }

    pub async fn insert(&self, key: String, value: Option<i64>) {
        if self.capacity == 0 || self.ttl.is_zero() {
            return;
        }
        let mut inner = self.inner.lock().await;
        if inner.map.contains_key(&key) {
            inner.order.retain(|item| item != &key);
        }
        inner.order.push_back(key.clone());
        inner.map.insert(
            key.clone(),
            CachedCollectionEpoch {
                value,
                expires_at: Instant::now() + self.ttl,
            },
        );
        while inner.order.len() > self.capacity {
            if let Some(oldest) = inner.order.pop_front() {
                inner.map.remove(&oldest);
            }
        }
    }

    pub async fn invalidate(&self, key: &str) {
        let mut inner = self.inner.lock().await;
        inner.map.remove(key);
        inner.order.retain(|item| item != key);
    }
}

impl ThemeSourceCache {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity,
            inner: Arc::new(Mutex::new(ThemeSourceCacheInner {
                map: HashMap::new(),
                order: VecDeque::new(),
            })),
        }
    }

    pub async fn get(&self, key: &str) -> Option<[Option<String>; 4]> {
        if self.capacity == 0 || self.ttl.is_zero() {
            return None;
        }
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        if let Some(entry) = inner.map.get(key) {
            if entry.expires_at <= now {
                inner.map.remove(key);
                inner.order.retain(|item| item != key);
                return None;
            }
            let sources = entry.sources.clone();
            touch_key(&mut inner.order, key);
            return Some(sources);
        }
        None
    }

    pub async fn insert(&self, key: String, sources: [Option<String>; 4]) {
        if self.capacity == 0 || self.ttl.is_zero() {
            return;
        }
        let mut inner = self.inner.lock().await;
        if inner.map.contains_key(&key) {
            inner.order.retain(|item| item != &key);
        }
        inner.order.push_back(key.clone());
        inner.map.insert(
            key.clone(),
            CachedThemeSources {
                sources,
                expires_at: Instant::now() + self.ttl,
            },
        );
        while inner.order.len() > self.capacity {
            if let Some(oldest) = inner.order.pop_front() {
                inner.map.remove(&oldest);
            }
        }
    }
}

impl CatalogMetadataCache {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity,
            inner: Arc::new(Mutex::new(CatalogMetadataCacheInner {
                map: HashMap::new(),
                order: VecDeque::new(),
            })),
        }
    }

    pub async fn get(&self, key: &str) -> Option<String> {
        if self.capacity == 0 || self.ttl.is_zero() {
            return None;
        }
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        if let Some(entry) = inner.map.get(key) {
            if entry.expires_at <= now {
                inner.map.remove(key);
                inner.order.retain(|item| item != key);
                return None;
            }
            let value = entry.metadata_uri.clone();
            touch_key(&mut inner.order, key);
            return Some(value);
        }
        None
    }

    pub async fn insert(&self, key: String, metadata_uri: String) {
        if self.capacity == 0 || self.ttl.is_zero() {
            return;
        }
        let mut inner = self.inner.lock().await;
        if inner.map.contains_key(&key) {
            inner.order.retain(|item| item != &key);
        }
        inner.order.push_back(key.clone());
        inner.map.insert(
            key.clone(),
            CachedCatalogMetadata {
                metadata_uri,
                expires_at: Instant::now() + self.ttl,
            },
        );
        while inner.order.len() > self.capacity {
            if let Some(oldest) = inner.order.pop_front() {
                inner.map.remove(&oldest);
            }
        }
    }
}

impl CatalogThemeCache {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity,
            inner: Arc::new(Mutex::new(CatalogThemeCacheInner {
                map: HashMap::new(),
                order: VecDeque::new(),
            })),
        }
    }

    pub async fn get(&self, key: &str) -> Option<Arc<HashMap<String, [String; 4]>>> {
        if self.capacity == 0 || self.ttl.is_zero() {
            return None;
        }
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        if let Some(entry) = inner.map.get(key) {
            if entry.expires_at <= now {
                inner.map.remove(key);
                inner.order.retain(|item| item != key);
                return None;
            }
            let value = entry.themes.clone();
            touch_key(&mut inner.order, key);
            return Some(value);
        }
        None
    }

    pub async fn insert(&self, key: String, themes: Arc<HashMap<String, [String; 4]>>) {
        if self.capacity == 0 || self.ttl.is_zero() {
            return;
        }
        let mut inner = self.inner.lock().await;
        if inner.map.contains_key(&key) {
            inner.order.retain(|item| item != &key);
        }
        inner.order.push_back(key.clone());
        inner.map.insert(
            key.clone(),
            CachedCatalogThemes {
                themes,
                expires_at: Instant::now() + self.ttl,
            },
        );
        while inner.order.len() > self.capacity {
            if let Some(oldest) = inner.order.pop_front() {
                inner.map.remove(&oldest);
            }
        }
    }
}

fn touch_key(order: &mut VecDeque<String>, key_hash: &str) {
    if let Some(pos) = order.iter().position(|item| item == key_hash) {
        order.remove(pos);
        order.push_back(key_hash.to_string());
    }
}

pub(crate) fn collection_cache_key(chain: &str, collection: &str) -> String {
    format!("{chain}:{collection}")
}

#[derive(Clone)]
pub struct IpRuleCache {
    inner: Arc<RwLock<Vec<IpRuleEntry>>>,
}

#[derive(Clone)]
struct IpRuleEntry {
    mode: String,
    net: IpNet,
    prefix_len: u8,
    is_deny: bool,
}

impl IpRuleCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn refresh(&self, db: &Database) -> anyhow::Result<()> {
        let rules = db.list_ip_rules().await?;
        let mut parsed = Vec::new();
        for rule in rules {
            if let Some(entry) = parse_ip_rule(&rule) {
                parsed.push(entry);
            }
        }
        parsed.sort_by(|a, b| {
            b.prefix_len
                .cmp(&a.prefix_len)
                .then_with(|| b.is_deny.cmp(&a.is_deny))
        });
        let mut guard = self.inner.write().await;
        *guard = parsed;
        Ok(())
    }

    pub async fn rule_for_ip(&self, ip: IpAddr) -> Option<String> {
        let guard = self.inner.read().await;
        for rule in guard.iter() {
            if rule.net.contains(&ip) {
                return Some(rule.mode.clone());
            }
        }
        None
    }
}

fn parse_ip_rule(rule: &IpRule) -> Option<IpRuleEntry> {
    let net = if let Ok(net) = rule.ip_cidr.parse::<IpNet>() {
        net
    } else if let Ok(addr) = rule.ip_cidr.parse::<IpAddr>() {
        IpNet::from(addr)
    } else {
        warn!(cidr = %rule.ip_cidr, "invalid ip rule");
        return None;
    };
    let is_deny = rule.mode == "deny";
    Some(IpRuleEntry {
        mode: rule.mode.clone(),
        prefix_len: net.prefix_len(),
        net,
        is_deny,
    })
}
