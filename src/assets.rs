use crate::cache::CacheManager;
use crate::config::Config;
use crate::db::Database;
use crate::pinning::{PinnedAssetStore, content_type_from_path};
use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use mime::Mime;
use reqwest::{StatusCode, header};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::lookup_host;
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, warn};
use url::{Host, Url};

#[derive(Clone)]
pub struct AssetResolver {
    client: reqwest::Client,
    client_cache: ClientCache,
    cache: CacheManager,
    config: Arc<Config>,
    db: Database,
    pin_store: Option<Arc<PinnedAssetStore>>,
    ipfs_semaphore: Arc<Semaphore>,
    nonrenderable_meta_cache: Arc<Mutex<NonRenderableMetaCache>>,
}

#[derive(Debug, Clone)]
pub struct ResolvedAsset {
    pub bytes: Bytes,
}

#[derive(Debug, Clone)]
pub struct ResolvedMetadata {
    pub art_uri: String,
    pub source: &'static str,
}

#[derive(Debug, Default)]
struct NonRenderableMetaCache {
    map: HashMap<String, Instant>,
    order: VecDeque<String>,
}

impl NonRenderableMetaCache {
    fn contains(&mut self, key: &str, ttl: Duration) -> bool {
        let Some(when) = self.map.get(key).copied() else {
            return false;
        };
        if when.elapsed() <= ttl {
            return true;
        }
        self.map.remove(key);
        false
    }

    fn insert(&mut self, key: String, ttl: Duration, capacity: usize) {
        if self.map.contains_key(&key) {
            return;
        }
        self.map.insert(key.clone(), Instant::now());
        self.order.push_back(key);
        while self.order.len() > capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
        self.evict_expired(ttl);
    }

    fn evict_expired(&mut self, ttl: Duration) {
        let mut kept = VecDeque::with_capacity(self.order.len());
        while let Some(key) = self.order.pop_front() {
            let expired = self
                .map
                .get(&key)
                .map(|when| when.elapsed() > ttl)
                .unwrap_or(true);
            if expired {
                self.map.remove(&key);
            } else {
                kept.push_back(key);
            }
        }
        self.order = kept;
    }
}

const NONRENDERABLE_META_CACHE_TTL: Duration = Duration::from_secs(10 * 60);
const NONRENDERABLE_META_CACHE_CAPACITY: usize = 10_000;

#[derive(Debug, Clone, Copy)]
enum FetchKind {
    Metadata,
    Asset,
}

#[derive(Debug, Clone)]
struct FetchedBytes {
    bytes: Bytes,
    content_type: Option<Mime>,
}

#[derive(Debug, Clone)]
struct ResolvedHttpUrl {
    parsed: Url,
    host: String,
    addrs: Vec<SocketAddr>,
    is_ip_literal: bool,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ClientCacheKey {
    scheme: String,
    host: String,
    port: u16,
    ip: IpAddr,
}

#[derive(Clone)]
struct ClientCache {
    capacity: usize,
    ttl: Duration,
    inner: Arc<Mutex<ClientCacheInner>>,
}

struct ClientCacheInner {
    map: HashMap<ClientCacheKey, ClientCacheEntry>,
    order: VecDeque<ClientCacheKey>,
}

struct ClientCacheEntry {
    client: reqwest::Client,
    expires_at: Instant,
}

#[derive(Debug, Error)]
pub enum AssetFetchError {
    #[error("invalid asset uri")]
    InvalidUri,
    #[error("asset fetch blocked")]
    Blocked,
    #[error("asset too large")]
    TooLarge,
    #[error("asset fetch failed from {url}: {status}")]
    UpstreamStatus { status: StatusCode, url: String },
    #[error("asset fetch failed from {url}")]
    Upstream { url: String },
}

#[derive(Debug, Deserialize)]
struct MetadataJson {
    image: Option<String>,
    #[serde(rename = "mediaUri")]
    media_uri: Option<String>,
    #[serde(rename = "media_uri")]
    media_uri_alt: Option<String>,
    #[serde(rename = "animation_url")]
    animation_url: Option<String>,
    #[serde(rename = "animationUrl")]
    animation_url_alt: Option<String>,
    src: Option<String>,
    #[serde(rename = "thumbnailUri")]
    thumbnail_uri: Option<String>,
    #[serde(rename = "thumbnail_uri")]
    thumbnail_uri_alt: Option<String>,
}

impl AssetResolver {
    pub fn new(
        config: Arc<Config>,
        cache: CacheManager,
        db: Database,
        pin_store: Option<Arc<PinnedAssetStore>>,
        ipfs_semaphore: Arc<Semaphore>,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.ipfs_timeout_seconds))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("rmrk-renderer/1.2")
            .build()
            .context("build reqwest client")?;
        let client_cache = ClientCache::new(
            config.outbound_client_cache_capacity,
            config.outbound_client_cache_ttl,
        );
        Ok(Self {
            client,
            client_cache,
            cache,
            config,
            db,
            pin_store,
            ipfs_semaphore,
            nonrenderable_meta_cache: Arc::new(Mutex::new(NonRenderableMetaCache::default())),
        })
    }

    pub fn pinned_store(&self) -> Option<Arc<PinnedAssetStore>> {
        self.pin_store.clone()
    }

    pub async fn resolve_metadata(
        &self,
        metadata_uri: &str,
        prefer_thumb: bool,
    ) -> Result<Option<ResolvedMetadata>> {
        {
            let mut cache = self.nonrenderable_meta_cache.lock().await;
            if cache.contains(metadata_uri, NONRENDERABLE_META_CACHE_TTL) {
                debug!(metadata_uri = %metadata_uri, "metadata cached as non-renderable");
                return Ok(None);
            }
        }
        let bytes = self.fetch_metadata_json(metadata_uri).await?;
        let json: MetadataJson = match serde_json::from_slice(&bytes) {
            Ok(parsed) => parsed,
            Err(err) => {
                if looks_like_asset_bytes(&bytes) {
                    debug!(
                        metadata_uri = %metadata_uri,
                        "metadata is non-json asset bytes, treating as direct asset"
                    );
                    return Ok(Some(ResolvedMetadata {
                        art_uri: metadata_uri.to_string(),
                        source: "raw",
                    }));
                }
                return Err(anyhow!(err).context("parse metadata json"));
            }
        };
        if let Some((art_uri, source)) = select_render_uri(&json, prefer_thumb) {
            debug!(
                metadata_uri = %metadata_uri,
                art_uri = %art_uri,
                field = %source,
                "resolved metadata render uri"
            );
            return Ok(Some(ResolvedMetadata { art_uri, source }));
        }
        {
            let mut cache = self.nonrenderable_meta_cache.lock().await;
            cache.insert(
                metadata_uri.to_string(),
                NONRENDERABLE_META_CACHE_TTL,
                NONRENDERABLE_META_CACHE_CAPACITY,
            );
        }
        debug!(
            metadata_uri = %metadata_uri,
            "metadata has no renderable media"
        );
        Ok(None)
    }

    pub async fn fetch_asset(&self, uri: &str) -> Result<ResolvedAsset> {
        let resolved = self.resolve_uri(uri)?;
        if let Some(bytes) = self.load_pinned_ipfs(&resolved).await {
            return Ok(ResolvedAsset { bytes });
        }
        let cache_key = resolved.cache_key.clone();
        let prefix = &cache_key[0..2];
        let cache_path = self.cache.asset_raw_dir.join(prefix).join(cache_key);
        if let Some(bytes) = self
            .cache
            .load_cached_file(&cache_path, self.cache.asset_ttl)
            .await?
        {
            let bytes = Bytes::from(bytes);
            if resolved.is_ipfs {
                self.pin_ipfs_bytes(&resolved, &bytes, None).await;
            }
            return Ok(ResolvedAsset { bytes });
        }
        let fetched = self
            .fetch_bytes_with_retry(&resolved, FetchKind::Asset)
            .await?;
        self.cache.store_file(&cache_path, &fetched.bytes).await?;
        if resolved.is_ipfs {
            self.pin_ipfs_bytes(&resolved, &fetched.bytes, fetched.content_type.as_ref())
                .await;
        }
        Ok(ResolvedAsset {
            bytes: fetched.bytes,
        })
    }

    pub async fn fetch_metadata_json(&self, metadata_uri: &str) -> Result<Bytes> {
        let resolved = self.resolve_uri(metadata_uri)?;
        if let Some(bytes) = self.load_pinned_ipfs(&resolved).await {
            return Ok(bytes);
        }
        let prefix = &resolved.cache_key[0..2];
        let cache_path = self
            .cache
            .asset_meta_dir
            .join(prefix)
            .join(format!("{}.json", resolved.cache_key));
        if let Some(bytes) = self
            .cache
            .load_cached_file(&cache_path, self.cache.asset_ttl)
            .await?
        {
            let bytes = Bytes::from(bytes);
            if resolved.is_ipfs {
                self.pin_ipfs_bytes(&resolved, &bytes, None).await;
            }
            return Ok(bytes);
        }
        let fetched = self
            .fetch_bytes_with_retry(&resolved, FetchKind::Metadata)
            .await?;
        if fetched.bytes.len() > self.config.max_metadata_json_bytes {
            return Err(anyhow!(
                "metadata json too large ({} bytes)",
                fetched.bytes.len()
            ));
        }
        self.cache.store_file(&cache_path, &fetched.bytes).await?;
        if resolved.is_ipfs {
            self.pin_ipfs_bytes(&resolved, &fetched.bytes, fetched.content_type.as_ref())
                .await;
        }
        Ok(fetched.bytes)
    }

    pub async fn fetch_raster_cache(
        &self,
        cache_key: &str,
        width: u32,
        height: u32,
    ) -> Result<Option<Vec<u8>>> {
        let path = self.raster_cache_path(cache_key, width, height);
        self.cache
            .load_cached_file(&path, self.cache.asset_ttl)
            .await
    }

    pub async fn store_raster_cache(
        &self,
        cache_key: &str,
        width: u32,
        height: u32,
        bytes: &[u8],
    ) -> Result<()> {
        let path = self.raster_cache_path(cache_key, width, height);
        self.cache.store_file(&path, bytes).await
    }

    pub async fn remove_raster_cache(
        &self,
        cache_key: &str,
        width: u32,
        height: u32,
    ) -> Result<()> {
        let path = self.raster_cache_path(cache_key, width, height);
        let _ = tokio::fs::remove_file(path).await;
        Ok(())
    }

    pub fn local_path(&self, uri: &str) -> Result<PathBuf> {
        let path = uri.trim_start_matches("local://").trim();
        if path.is_empty() {
            return Err(anyhow!("invalid local overlay path"));
        }
        if path.contains("..") || path.contains('\\') || path.contains('\0') {
            return Err(anyhow!("invalid local overlay path"));
        }
        let candidate = Path::new(path);
        if candidate.is_absolute() {
            return Err(anyhow!("invalid local overlay path"));
        }
        let mut components = candidate.components();
        match (components.next(), components.next()) {
            (Some(std::path::Component::Normal(_)), None) => {}
            _ => return Err(anyhow!("invalid local overlay path")),
        }
        Ok(self.cache.overlays_dir.join(path))
    }

    pub async fn fetch_local_bytes(&self, uri: &str) -> Result<Bytes> {
        let path = self.local_path(uri)?;
        let max_bytes = local_max_bytes(
            &path,
            self.config.max_svg_bytes,
            self.config.max_raster_bytes,
        );
        let metadata = tokio::fs::metadata(&path).await?;
        if metadata.len() > max_bytes as u64 {
            return Err(anyhow!("local overlay exceeds max size"));
        }
        let bytes = tokio::fs::read(&path).await?;
        if bytes.len() > max_bytes {
            return Err(anyhow!("local overlay exceeds max size"));
        }
        Ok(Bytes::from(bytes))
    }

    fn pin_store(&self) -> Option<&PinnedAssetStore> {
        self.pin_store.as_deref().filter(|store| store.enabled())
    }

    async fn load_pinned_ipfs(&self, resolved: &ResolvedUri) -> Option<Bytes> {
        if !resolved.is_ipfs {
            return None;
        }
        let store = self.pin_store()?;
        let location = match store.ipfs_location(&resolved.cid, &resolved.path) {
            Ok(location) => location,
            Err(err) => {
                warn!(error = ?err, cid = %resolved.cid, path = %resolved.path, "invalid pinned ipfs path");
                return None;
            }
        };
        match tokio::fs::read(&location.file_path).await {
            Ok(bytes) => Some(Bytes::from(bytes)),
            Err(err) if err.kind() == ErrorKind::NotFound => None,
            Err(err) => {
                warn!(
                    error = ?err,
                    path = %location.file_path.display(),
                    "pinned asset read failed"
                );
                None
            }
        }
    }

    async fn pin_ipfs_bytes(
        &self,
        resolved: &ResolvedUri,
        bytes: &Bytes,
        content_type: Option<&Mime>,
    ) {
        if !resolved.is_ipfs {
            return;
        }
        let Some(store) = self.pin_store() else {
            return;
        };
        let location = match store.ipfs_location(&resolved.cid, &resolved.path) {
            Ok(location) => location,
            Err(err) => {
                warn!(error = ?err, cid = %resolved.cid, path = %resolved.path, "invalid pinned ipfs path");
                return;
            }
        };
        let exists = tokio::fs::metadata(&location.file_path).await.is_ok();
        if !exists {
            if let Err(err) = store.store_bytes(&location, bytes).await {
                warn!(
                    error = ?err,
                    path = %location.file_path.display(),
                    "pinned asset write failed"
                );
                return;
            }
        }
        let content_type = content_type
            .map(|mime| mime.essence_str().to_string())
            .or_else(|| content_type_from_path(&location.path).map(|value| value.to_string()));
        if let Err(err) = self
            .db
            .upsert_pinned_asset(
                &location.asset_key,
                &location.cid,
                &location.path,
                content_type.as_deref(),
                bytes.len() as i64,
            )
            .await
        {
            warn!(error = ?err, asset_key = %location.asset_key, "pinned asset db update failed");
        }
    }

    fn resolve_uri(&self, uri: &str) -> Result<ResolvedUri> {
        let uri = uri.trim();
        if uri.starts_with("ipfs://") {
            let (cid, path) = parse_ipfs_uri(uri)?;
            let gateway = self
                .config
                .ipfs_gateways
                .first()
                .ok_or_else(|| anyhow!("no ipfs gateways configured"))?;
            let url = format!("{}{}{}", gateway, cid, path);
            return Ok(ResolvedUri {
                url,
                cache_key: sha256_hex(&format!("{cid}{path}")),
                is_ipfs: true,
                cid,
                path,
            });
        }
        let parsed = Url::parse(uri).map_err(|_| AssetFetchError::InvalidUri)?;
        let scheme = parsed.scheme();
        if scheme == "http" && !self.config.allow_http {
            return Err(AssetFetchError::Blocked.into());
        }
        if scheme != "http" && scheme != "https" {
            return Err(AssetFetchError::InvalidUri.into());
        }
        Ok(ResolvedUri {
            url: uri.to_string(),
            cache_key: sha256_hex(uri),
            is_ipfs: false,
            cid: String::new(),
            path: String::new(),
        })
    }

    fn is_local_ipfs_url(&self, url: &Url) -> bool {
        if !self.config.local_ipfs_enabled {
            return false;
        }
        let port = url
            .port_or_known_default()
            .unwrap_or_else(|| if url.scheme() == "https" { 443 } else { 80 });
        if port != self.config.local_ipfs_port {
            return false;
        }
        let host = url
            .host_str()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let bind = self.config.local_ipfs_bind.trim().to_ascii_lowercase();
        if host == bind {
            return true;
        }
        host == "localhost" && (bind == "127.0.0.1" || bind == "::1" || bind == "localhost")
    }

    async fn fetch_bytes_with_retry(
        &self,
        resolved: &ResolvedUri,
        kind: FetchKind,
    ) -> Result<FetchedBytes> {
        if !resolved.is_ipfs {
            return self.fetch_http_bytes(&resolved.url, kind).await;
        }
        let gateways = &self.config.ipfs_gateways;
        let mut last_err = None;
        for (index, gateway) in gateways.iter().enumerate() {
            let url = format!("{}{}{}", gateway, resolved.cid, resolved.path);
            match self.fetch_http_bytes(&url, kind).await {
                Ok(fetched) => return Ok(fetched),
                Err(err) => {
                    last_err = Some(err);
                    warn!(
                        ipfs_url = %url,
                        attempt = index + 1,
                        "ipfs fetch failed, rotating gateway"
                    );
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("ipfs fetch failed")))
    }

    async fn fetch_http_bytes(&self, url: &str, kind: FetchKind) -> Result<FetchedBytes> {
        let resolved = self.validate_http_url(url).await?;
        let _permit = self.ipfs_semaphore.acquire().await?;
        let mut response = self.send_pinned_request(&resolved).await?;
        if response.status() != StatusCode::OK {
            return Err(AssetFetchError::UpstreamStatus {
                status: response.status(),
                url: resolved.parsed.as_str().to_string(),
            }
            .into());
        }
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<Mime>().ok());
        let max_bytes = match kind {
            FetchKind::Metadata => self.config.max_metadata_json_bytes,
            FetchKind::Asset => self.max_asset_bytes(&resolved.parsed, content_type.as_ref()),
        };
        if let Some(length) = response.content_length() {
            if length > max_bytes as u64 {
                return Err(AssetFetchError::TooLarge.into());
            }
        }
        let mut buffer = BytesMut::with_capacity(std::cmp::min(max_bytes, 64 * 1024));
        let mut total = 0usize;
        while let Some(chunk) = response.chunk().await? {
            total = total.saturating_add(chunk.len());
            if total > max_bytes {
                return Err(AssetFetchError::TooLarge.into());
            }
            buffer.extend_from_slice(&chunk);
        }
        debug!(url = %url, size = total, "fetched asset");
        Ok(FetchedBytes {
            bytes: buffer.freeze(),
            content_type,
        })
    }

    async fn validate_http_url(
        &self,
        url: &str,
    ) -> std::result::Result<ResolvedHttpUrl, AssetFetchError> {
        let parsed = Url::parse(url).map_err(|_| AssetFetchError::InvalidUri)?;
        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(AssetFetchError::InvalidUri);
        }
        if scheme == "http" && !self.config.allow_http {
            return Err(AssetFetchError::Blocked);
        }
        let allow_private = self.config.allow_private_networks || self.is_local_ipfs_url(&parsed);
        let (addrs, is_ip_literal) = self.resolve_public_host(&parsed, allow_private).await?;
        let host = parsed
            .host_str()
            .ok_or(AssetFetchError::InvalidUri)?
            .to_string();
        Ok(ResolvedHttpUrl {
            parsed,
            host,
            addrs,
            is_ip_literal,
        })
    }

    async fn resolve_public_host(
        &self,
        url: &Url,
        allow_private: bool,
    ) -> std::result::Result<(Vec<SocketAddr>, bool), AssetFetchError> {
        let host_raw = url.host_str().ok_or(AssetFetchError::InvalidUri)?;
        let host = host_raw.trim_end_matches('.');
        let port = url
            .port_or_known_default()
            .unwrap_or_else(|| if url.scheme() == "https" { 443 } else { 80 });
        if !allow_private
            && (host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost"))
        {
            return Err(AssetFetchError::Blocked);
        }
        if let Some(host) = url.host() {
            match host {
                Host::Ipv4(addr) => {
                    if !allow_private && is_private_ip(IpAddr::V4(addr)) {
                        return Err(AssetFetchError::Blocked);
                    }
                    return Ok((vec![SocketAddr::new(IpAddr::V4(addr), port)], true));
                }
                Host::Ipv6(addr) => {
                    if !allow_private && is_private_ip(IpAddr::V6(addr)) {
                        return Err(AssetFetchError::Blocked);
                    }
                    return Ok((vec![SocketAddr::new(IpAddr::V6(addr), port)], true));
                }
                Host::Domain(_) => {}
            }
        }
        let mut addrs: Vec<SocketAddr> = lookup_host((host, port))
            .await
            .map_err(|_| AssetFetchError::Upstream {
                url: url.as_str().to_string(),
            })?
            .collect();
        if !allow_private {
            addrs.retain(|addr| !is_private_ip(addr.ip()));
        }
        if addrs.is_empty() {
            return Err(AssetFetchError::Blocked);
        }
        Ok((addrs, false))
    }

    async fn send_pinned_request(
        &self,
        resolved: &ResolvedHttpUrl,
    ) -> std::result::Result<reqwest::Response, AssetFetchError> {
        if resolved.is_ip_literal {
            return self
                .client
                .get(resolved.parsed.clone())
                .send()
                .await
                .map_err(|_| AssetFetchError::Upstream {
                    url: resolved.parsed.as_str().to_string(),
                });
        }
        let mut last_err = None;
        let scheme = resolved.parsed.scheme().to_string();
        let host = resolved.host.clone();
        for addr in resolved.addrs.iter().copied() {
            let key = ClientCacheKey {
                scheme: scheme.clone(),
                host: host.clone(),
                port: addr.port(),
                ip: addr.ip(),
            };
            let client = if let Some(client) = self.client_cache.get(&key).await {
                client
            } else {
                let client = self.client_with_resolve(&host, addr)?;
                self.client_cache.insert(key, client.clone()).await;
                client
            };
            match client.get(resolved.parsed.clone()).send().await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    last_err = Some(err);
                }
            }
        }
        Err(last_err
            .map(|_| AssetFetchError::Upstream {
                url: resolved.parsed.as_str().to_string(),
            })
            .unwrap_or(AssetFetchError::Upstream {
                url: resolved.parsed.as_str().to_string(),
            }))
    }

    fn client_with_resolve(
        &self,
        host: &str,
        addr: SocketAddr,
    ) -> std::result::Result<reqwest::Client, AssetFetchError> {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(self.config.ipfs_timeout_seconds))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("rmrk-renderer/1.2")
            .resolve(host, addr)
            .build()
            .map_err(|_| AssetFetchError::Upstream {
                url: format!("{host}@{addr}"),
            })
    }

    fn max_asset_bytes(&self, url: &Url, content_type: Option<&Mime>) -> usize {
        if looks_like_svg(url, content_type) {
            self.config.max_svg_bytes
        } else {
            self.config.max_raster_bytes
        }
    }
}

impl ClientCache {
    fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            capacity,
            ttl,
            inner: Arc::new(Mutex::new(ClientCacheInner {
                map: HashMap::new(),
                order: VecDeque::new(),
            })),
        }
    }

    fn enabled(&self) -> bool {
        self.capacity > 0 && self.ttl > Duration::from_secs(0)
    }

    async fn get(&self, key: &ClientCacheKey) -> Option<reqwest::Client> {
        if !self.enabled() {
            return None;
        }
        let now = Instant::now();
        let mut guard = self.inner.lock().await;
        if let Some((client, expires_at)) = guard
            .map
            .get(key)
            .map(|entry| (entry.client.clone(), entry.expires_at))
        {
            if expires_at <= now {
                guard.map.remove(key);
                guard.order.retain(|item| item != key);
                return None;
            }
            touch_client_key(&mut guard.order, key);
            return Some(client);
        }
        None
    }

    async fn insert(&self, key: ClientCacheKey, client: reqwest::Client) {
        if !self.enabled() {
            return;
        }
        let expires_at = Instant::now() + self.ttl;
        let mut guard = self.inner.lock().await;
        guard
            .map
            .insert(key.clone(), ClientCacheEntry { client, expires_at });
        touch_client_key(&mut guard.order, &key);
        while guard.map.len() > self.capacity {
            if let Some(oldest) = guard.order.pop_front() {
                guard.map.remove(&oldest);
            }
        }
    }
}

fn touch_client_key(order: &mut VecDeque<ClientCacheKey>, key: &ClientCacheKey) {
    if let Some(pos) = order.iter().position(|item| item == key) {
        order.remove(pos);
    }
    order.push_back(key.clone());
}

impl AssetResolver {
    fn raster_cache_path(&self, cache_key: &str, width: u32, height: u32) -> PathBuf {
        let prefix = &cache_key[0..2];
        self.cache
            .asset_raster_dir
            .join(prefix)
            .join(cache_key)
            .join(format!("{}x{}.png", width, height))
    }
}

#[derive(Debug, Clone)]
struct ResolvedUri {
    url: String,
    cache_key: String,
    is_ipfs: bool,
    cid: String,
    path: String,
}

fn parse_ipfs_uri(uri: &str) -> Result<(String, String)> {
    let without_scheme = uri.trim_start_matches("ipfs://");
    let without_prefix = without_scheme
        .strip_prefix("ipfs/")
        .unwrap_or(without_scheme);
    let mut parts = without_prefix.splitn(2, '/');
    let cid = parts
        .next()
        .ok_or_else(|| anyhow!("invalid ipfs uri"))?
        .to_string();
    if !is_valid_cid(&cid) {
        return Err(anyhow!("invalid ipfs cid"));
    }
    let path = parts
        .next()
        .map(|path| format!("/{path}"))
        .unwrap_or_default();
    Ok((cid, path))
}

fn is_valid_cid(cid: &str) -> bool {
    if cid.is_empty() {
        return false;
    }
    cid.chars().all(|ch| ch.is_ascii_alphanumeric())
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn local_max_bytes(path: &Path, max_svg_bytes: usize, max_raster_bytes: usize) -> usize {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("svg") | Some("svgz") => max_svg_bytes,
        _ => max_raster_bytes,
    }
}

fn looks_like_svg(url: &Url, content_type: Option<&Mime>) -> bool {
    if let Some(mime) = content_type {
        let essence = mime.essence_str();
        if essence.eq_ignore_ascii_case("image/svg+xml")
            || essence.eq_ignore_ascii_case("image/svg")
            || essence.eq_ignore_ascii_case("text/xml")
            || essence.eq_ignore_ascii_case("application/xml")
        {
            return true;
        }
    }
    if let Some(mut segments) = url.path_segments() {
        if let Some(last) = segments.next_back() {
            let last = last.to_ascii_lowercase();
            return last.ends_with(".svg");
        }
    }
    false
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => is_private_v4(addr),
        IpAddr::V6(addr) => {
            if let Some(v4) = addr.to_ipv4() {
                return is_private_v4(v4);
            }
            if addr.is_loopback()
                || addr.is_unicast_link_local()
                || addr.is_unique_local()
                || addr.is_multicast()
                || addr.is_unspecified()
            {
                return true;
            }
            false
        }
    }
}

fn is_private_v4(addr: std::net::Ipv4Addr) -> bool {
    addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || addr.is_broadcast()
        || addr.is_multicast()
        || addr.is_unspecified()
        || is_cgnat_v4(addr)
}

fn is_cgnat_v4(addr: std::net::Ipv4Addr) -> bool {
    let [a, b, _, _] = addr.octets();
    a == 100 && (b & 0b1100_0000) == 0b0100_0000
}

fn select_render_uri(
    metadata: &MetadataJson,
    prefer_thumb: bool,
) -> Option<(String, &'static str)> {
    let thumb = metadata
        .thumbnail_uri
        .as_ref()
        .or(metadata.thumbnail_uri_alt.as_ref());
    if prefer_thumb {
        if let Some(value) = thumb {
            return Some((value.clone(), "thumbnailUri"));
        }
    }
    let media = metadata
        .media_uri
        .as_ref()
        .or(metadata.media_uri_alt.as_ref());
    if let Some(value) = media {
        return Some((value.clone(), "mediaUri"));
    }
    if let Some(value) = metadata.animation_url.as_ref() {
        return Some((value.clone(), "animation_url"));
    }
    if let Some(value) = metadata.animation_url_alt.as_ref() {
        return Some((value.clone(), "animationUrl"));
    }
    if let Some(value) = metadata.image.as_ref() {
        return Some((value.clone(), "image"));
    }
    if let Some(value) = metadata.src.as_ref() {
        return Some((value.clone(), "src"));
    }
    if let Some(value) = thumb {
        return Some((value.clone(), "thumbnailUri"));
    }
    None
}

fn looks_like_asset_bytes(bytes: &[u8]) -> bool {
    let sample = std::str::from_utf8(bytes).unwrap_or("");
    if sample.contains("<svg") || sample.contains("<?xml") {
        return true;
    }
    image::guess_format(bytes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipfs_uri_basic() {
        let (cid, path) = parse_ipfs_uri("ipfs://bafy123").unwrap();
        assert_eq!(cid, "bafy123");
        assert_eq!(path, "");
    }

    #[test]
    fn parse_ipfs_uri_with_path() {
        let (cid, path) = parse_ipfs_uri("ipfs://bafy123/assets/1.svg").unwrap();
        assert_eq!(cid, "bafy123");
        assert_eq!(path, "/assets/1.svg");
    }

    #[test]
    fn parse_ipfs_uri_with_ipfs_prefix() {
        let (cid, path) = parse_ipfs_uri("ipfs://ipfs/bafy123/meta.json").unwrap();
        assert_eq!(cid, "bafy123");
        assert_eq!(path, "/meta.json");
    }

    #[test]
    fn parse_ipfs_uri_rejects_invalid_cid() {
        assert!(parse_ipfs_uri("ipfs://ba..fy").is_err());
        assert!(parse_ipfs_uri("ipfs://bafy?123").is_err());
    }

    #[test]
    fn metadata_prefers_media_uri_over_image() {
        let metadata = MetadataJson {
            image: Some("ipfs://image".to_string()),
            media_uri: Some("ipfs://media".to_string()),
            media_uri_alt: None,
            animation_url: None,
            animation_url_alt: None,
            src: None,
            thumbnail_uri: None,
            thumbnail_uri_alt: None,
        };
        let selected = select_render_uri(&metadata, false).unwrap();
        assert_eq!(selected.0, "ipfs://media");
        assert_eq!(selected.1, "mediaUri");
    }

    #[test]
    fn metadata_prefers_thumbnail_when_requested() {
        let metadata = MetadataJson {
            image: Some("ipfs://image".to_string()),
            media_uri: Some("ipfs://media".to_string()),
            media_uri_alt: None,
            animation_url: None,
            animation_url_alt: None,
            src: None,
            thumbnail_uri: Some("ipfs://thumb".to_string()),
            thumbnail_uri_alt: None,
        };
        let selected = select_render_uri(&metadata, true).unwrap();
        assert_eq!(selected.0, "ipfs://thumb");
        assert_eq!(selected.1, "thumbnailUri");
    }

    #[test]
    fn metadata_none_when_no_media_fields() {
        let metadata = MetadataJson {
            image: None,
            media_uri: None,
            media_uri_alt: None,
            animation_url: None,
            animation_url_alt: None,
            src: None,
            thumbnail_uri: None,
            thumbnail_uri_alt: None,
        };
        assert!(select_render_uri(&metadata, false).is_none());
    }

    #[test]
    fn is_private_ip_handles_ipv4_mapped_ipv6() {
        let loopback: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_private_ip(loopback));
        let metadata: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(is_private_ip(metadata));
        let public: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(!is_private_ip(public));
    }

    #[test]
    fn is_private_ip_handles_ipv4_compatible_ipv6() {
        let loopback: IpAddr = "::127.0.0.1".parse().unwrap();
        assert!(is_private_ip(loopback));
        let public: IpAddr = "::8.8.8.8".parse().unwrap();
        assert!(!is_private_ip(public));
    }

    #[test]
    fn is_private_ip_blocks_cgnat_range() {
        assert!(!is_private_ip("100.63.255.255".parse().unwrap()));
        assert!(is_private_ip("100.64.0.0".parse().unwrap()));
        assert!(is_private_ip("100.127.255.255".parse().unwrap()));
        assert!(!is_private_ip("100.128.0.0".parse().unwrap()));
    }
}
