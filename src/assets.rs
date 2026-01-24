use crate::cache::CacheManager;
use crate::config::Config;
use crate::db::Database;
use crate::pinning::{PinnedAssetStore, content_type_from_path};
use anyhow::{Context, Result, anyhow};
use base64::Engine;
use bytes::{Bytes, BytesMut};
use image::codecs::jpeg::JpegEncoder;
use image::codecs::png::{CompressionType, FilterType as PngFilterType, PngEncoder};
use image::codecs::webp::WebPEncoder;
use image::imageops::FilterType;
use image::{DynamicImage, GenericImageView, ImageEncoder, ImageFormat, ImageReader};
use mime::Mime;
use reqwest::{StatusCode, header};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::io::{Cursor, ErrorKind};
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
            let mut art_uri = art_uri.trim().to_string();
            if let Some(resolved) = resolve_relative_art_uri(&art_uri, metadata_uri) {
                art_uri = resolved;
            }
            if let Some(normalized) = normalize_arweave_uri(&art_uri) {
                art_uri = normalized;
            }
            if let Some(normalized) = normalize_ipfs_uri(&art_uri) {
                art_uri = normalized;
            }
            if art_uri.is_empty() || !is_supported_asset_uri(&art_uri) {
                warn!(
                    metadata_uri = %metadata_uri,
                    art_uri = %art_uri,
                    field = %source,
                    "metadata render uri invalid, treating as non-renderable"
                );
                let mut cache = self.nonrenderable_meta_cache.lock().await;
                cache.insert(
                    metadata_uri.to_string(),
                    NONRENDERABLE_META_CACHE_TTL,
                    NONRENDERABLE_META_CACHE_CAPACITY,
                );
                return Ok(None);
            }
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
        let uri = uri.trim();
        if uri.starts_with("data:") {
            let (bytes, content_type) = parse_data_uri(uri)?;
            let bytes = if bytes.len() > self.config.max_raster_bytes {
                if let Some(format) = infer_image_format(content_type.as_ref(), &bytes) {
                    resize_raster_bytes(
                        &bytes,
                        format,
                        self.config.max_raster_resize_dim,
                        self.config.max_decoded_raster_pixels,
                    )
                    .map(Bytes::from)
                    .unwrap_or(bytes)
                } else {
                    bytes
                }
            } else {
                bytes
            };
            return Ok(ResolvedAsset { bytes });
        }
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
        let fetched = match self
            .fetch_bytes_with_retry(&resolved, FetchKind::Asset)
            .await
        {
            Ok(fetched) => fetched,
            Err(err) => {
                if is_too_large_asset_error(&err) {
                    if let Some(resized) = self.fetch_resized_raster(&resolved).await? {
                        self.cache.store_file(&cache_path, &resized.bytes).await?;
                        if resolved.is_ipfs {
                            self.pin_ipfs_bytes(
                                &resolved,
                                &resized.bytes,
                                resized.content_type.as_ref(),
                            )
                            .await;
                        }
                        return Ok(ResolvedAsset {
                            bytes: resized.bytes,
                        });
                    }
                }
                return Err(err);
            }
        };
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
        let uri = metadata_uri.trim();
        if uri.starts_with("data:") {
            let (bytes, _) = parse_data_uri(uri)?;
            if bytes.len() > self.config.max_metadata_json_bytes {
                return Err(anyhow!("metadata json too large ({} bytes)", bytes.len()));
            }
            return Ok(bytes);
        }
        let resolved = self.resolve_uri(uri)?;
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
        let mut uri = uri.trim().to_string();
        if let Some(arweave_uri) = normalize_arweave_uri(&uri) {
            uri = arweave_uri;
        }
        if let Some(ipfs_uri) = normalize_ipfs_uri(&uri) {
            let (cid, path) = parse_ipfs_uri(&ipfs_uri)?;
            let gateway = self
                .config
                .ipfs_gateways
                .first()
                .ok_or_else(|| anyhow!("no ipfs gateways configured"))?;
            let url = Url::parse(gateway)
                .and_then(|base| base.join(&format!("{cid}{path}")))
                .map(|value| value.to_string())
                .map_err(|_| AssetFetchError::InvalidUri)?;
            return Ok(ResolvedUri {
                url,
                cache_key: sha256_hex(&format!("{cid}{path}")),
                is_ipfs: true,
                cid,
                path,
            });
        }
        let parsed = Url::parse(&uri)
            .or_else(|_| Url::parse(&uri.replace(' ', "%20")))
            .map_err(|_| AssetFetchError::InvalidUri)
            .with_context(|| format!("invalid asset uri: {uri}"))?;
        let scheme = parsed.scheme();
        if scheme == "http" && !self.config.allow_http {
            return Err(AssetFetchError::Blocked.into());
        }
        if scheme != "http" && scheme != "https" {
            return Err(AssetFetchError::InvalidUri)
                .with_context(|| format!("invalid asset uri: {uri}"));
        }
        if let Some((cid, path)) = parse_ipfs_http_url(&parsed) {
            let gateway = self
                .config
                .ipfs_gateways
                .first()
                .ok_or_else(|| anyhow!("no ipfs gateways configured"))?;
            let url = Url::parse(gateway)
                .and_then(|base| base.join(&format!("{cid}{path}")))
                .map(|value| value.to_string())
                .map_err(|_| AssetFetchError::InvalidUri)?;
            return Ok(ResolvedUri {
                url,
                cache_key: sha256_hex(&format!("{cid}{path}")),
                is_ipfs: true,
                cid,
                path,
            });
        }
        let normalized = parsed.to_string();
        Ok(ResolvedUri {
            url: normalized.clone(),
            cache_key: sha256_hex(&normalized),
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

    async fn fetch_http_bytes_with_limit(
        &self,
        url: &str,
        max_bytes: usize,
    ) -> Result<FetchedBytes> {
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

    async fn fetch_resized_raster(&self, resolved: &ResolvedUri) -> Result<Option<FetchedBytes>> {
        let max_bytes = self.config.max_raster_resize_bytes;
        if max_bytes == 0 || max_bytes <= self.config.max_raster_bytes {
            return Ok(None);
        }
        let fetched = self
            .fetch_http_bytes_with_limit(&resolved.url, max_bytes)
            .await?;
        let format = match infer_image_format(fetched.content_type.as_ref(), &fetched.bytes) {
            Some(format) => format,
            None => {
                return Ok(None);
            }
        };
        if !matches!(
            format,
            ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::WebP
        ) {
            return Ok(None);
        }
        let encoded = resize_raster_bytes(
            &fetched.bytes,
            format,
            self.config.max_raster_resize_dim,
            self.config.max_decoded_raster_pixels,
        )?;
        Ok(Some(FetchedBytes {
            bytes: Bytes::from(encoded),
            content_type: mime_for_format(format),
        }))
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

fn normalize_ipfs_uri(uri: &str) -> Option<String> {
    let trimmed = uri.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("ipfs://") {
        let remainder = &trimmed[7..];
        if let Some((cid, _)) = remainder.split_once('/') {
            if !is_valid_cid(cid) {
                return None;
            }
        } else if !is_valid_cid(remainder) {
            return None;
        }
        return Some(format!("ipfs://{remainder}"));
    }
    if lower.starts_with("ipfs/") {
        let remainder = &trimmed[5..];
        if let Some((cid, _)) = remainder.split_once('/') {
            if !is_valid_cid(cid) {
                return None;
            }
        } else if !is_valid_cid(remainder) {
            return None;
        }
        return Some(format!("ipfs://{remainder}"));
    }
    if lower.starts_with("/ipfs/") {
        let remainder = &trimmed[6..];
        if let Some((cid, _)) = remainder.split_once('/') {
            if !is_valid_cid(cid) {
                return None;
            }
        } else if !is_valid_cid(remainder) {
            return None;
        }
        return Some(format!("ipfs://{remainder}"));
    }
    if is_valid_cid(trimmed) {
        return Some(format!("ipfs://{trimmed}"));
    }
    if let Some((cid, rest)) = trimmed.split_once('/') {
        if is_valid_cid(cid) {
            return Some(format!("ipfs://{cid}/{rest}"));
        }
    }
    None
}

fn normalize_arweave_uri(uri: &str) -> Option<String> {
    let trimmed = uri.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("ar://") {
        return Some(format!("https://arweave.net/{}", &trimmed[5..]));
    }
    if lower.starts_with("arweave://") {
        return Some(format!("https://arweave.net/{}", &trimmed[10..]));
    }
    None
}

fn parse_ipfs_http_url(parsed: &Url) -> Option<(String, String)> {
    let path = parsed.path().trim_start_matches('/');
    let mut parts = path.splitn(3, '/');
    let prefix = parts.next()?.to_ascii_lowercase();
    if prefix != "ipfs" {
        return None;
    }
    let cid = parts.next()?.to_string();
    if !is_valid_cid(&cid) {
        return None;
    }
    let rest = parts.next().unwrap_or("");
    let path = if rest.is_empty() {
        String::new()
    } else {
        format!("/{rest}")
    };
    Some((cid, path))
}

fn is_valid_cid(cid: &str) -> bool {
    if cid.is_empty() {
        return false;
    }
    cid.chars().all(|ch| ch.is_ascii_alphanumeric())
}

fn parse_data_uri(uri: &str) -> Result<(Bytes, Option<Mime>)> {
    let Some((meta, data)) = uri.split_once(',') else {
        return Err(anyhow!("invalid data uri"));
    };
    let meta = meta
        .strip_prefix("data:")
        .ok_or_else(|| anyhow!("invalid data uri"))?;
    let mut content_type = None;
    let mut is_base64 = false;
    for (idx, part) in meta.split(';').enumerate() {
        if idx == 0 && !part.is_empty() && part.contains('/') {
            content_type = part.parse::<Mime>().ok();
            continue;
        }
        if part.eq_ignore_ascii_case("base64") {
            is_base64 = true;
        }
    }
    let bytes = if is_base64 {
        Bytes::from(
            base64::engine::general_purpose::STANDARD
                .decode(data.as_bytes())
                .context("data uri base64 decode failed")?,
        )
    } else {
        Bytes::from(percent_decode_bytes(data)?)
    };
    Ok((bytes, content_type))
}

fn percent_decode_bytes(data: &str) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(data.len());
    let mut bytes = data.as_bytes().iter().copied();
    while let Some(value) = bytes.next() {
        if value == b'%' {
            let hi = bytes
                .next()
                .ok_or_else(|| anyhow!("invalid percent encoding"))?;
            let lo = bytes
                .next()
                .ok_or_else(|| anyhow!("invalid percent encoding"))?;
            let hi = (hi as char)
                .to_digit(16)
                .ok_or_else(|| anyhow!("invalid percent encoding"))?;
            let lo = (lo as char)
                .to_digit(16)
                .ok_or_else(|| anyhow!("invalid percent encoding"))?;
            output.push(((hi << 4) + lo) as u8);
        } else {
            output.push(value);
        }
    }
    Ok(output)
}

fn is_too_large_asset_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<AssetFetchError>(),
            Some(AssetFetchError::TooLarge)
        )
    })
}

fn is_supported_asset_uri(uri: &str) -> bool {
    let trimmed = uri.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.to_ascii_lowercase().starts_with("data:") {
        return true;
    }
    if normalize_arweave_uri(trimmed).is_some() {
        return true;
    }
    if normalize_ipfs_uri(trimmed).is_some() {
        return true;
    }
    let parsed = Url::parse(trimmed).or_else(|_| Url::parse(&trimmed.replace(' ', "%20")));
    if let Ok(parsed) = parsed {
        return matches!(parsed.scheme(), "http" | "https");
    }
    false
}

fn infer_image_format(content_type: Option<&Mime>, bytes: &[u8]) -> Option<ImageFormat> {
    if let Some(content_type) = content_type {
        match content_type.essence_str() {
            "image/png" => return Some(ImageFormat::Png),
            "image/jpeg" | "image/jpg" => return Some(ImageFormat::Jpeg),
            "image/webp" => return Some(ImageFormat::WebP),
            _ => {}
        }
    }
    image::guess_format(bytes).ok()
}

fn mime_for_format(format: ImageFormat) -> Option<Mime> {
    match format {
        ImageFormat::Png => Some(mime::IMAGE_PNG),
        ImageFormat::Jpeg => Some(mime::IMAGE_JPEG),
        ImageFormat::WebP => Some("image/webp".parse().ok()?),
        _ => None,
    }
}

fn resize_image_to_limit(image: DynamicImage, max_dim: u32) -> DynamicImage {
    if max_dim == 0 {
        return image;
    }
    let (width, height) = image.dimensions();
    if width <= max_dim && height <= max_dim {
        return image;
    }
    let ratio = (max_dim as f32 / width as f32).min(max_dim as f32 / height as f32);
    let target_w = ((width as f32) * ratio).round().max(1.0) as u32;
    let target_h = ((height as f32) * ratio).round().max(1.0) as u32;
    image.resize_exact(target_w, target_h, FilterType::Lanczos3)
}

fn resize_raster_bytes(
    bytes: &[u8],
    format: ImageFormat,
    max_dim: u32,
    max_pixels: u64,
) -> Result<Vec<u8>> {
    let mut reader = ImageReader::new(Cursor::new(bytes));
    reader.set_format(format);
    reader.limits(raster_limits(max_pixels));
    let image = reader.decode()?;
    let resized = resize_image_to_limit(image, max_dim);
    encode_raster_image(resized, format)
}

fn encode_raster_image(image: DynamicImage, format: ImageFormat) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    match format {
        ImageFormat::Png => {
            let rgba = image.to_rgba8();
            let encoder = PngEncoder::new_with_quality(
                &mut bytes,
                CompressionType::Best,
                PngFilterType::Adaptive,
            );
            encoder.write_image(
                rgba.as_raw(),
                image.width(),
                image.height(),
                image::ExtendedColorType::Rgba8,
            )?;
        }
        ImageFormat::Jpeg => {
            let rgb = image.to_rgb8();
            let mut encoder = JpegEncoder::new_with_quality(&mut bytes, 85);
            encoder.encode(
                rgb.as_raw(),
                rgb.width(),
                rgb.height(),
                image::ColorType::Rgb8.into(),
            )?;
        }
        ImageFormat::WebP => {
            let encoder = WebPEncoder::new_lossless(&mut bytes);
            encoder.encode(
                image.to_rgba8().as_raw(),
                image.width(),
                image.height(),
                image::ColorType::Rgba8.into(),
            )?;
        }
        _ => return Err(anyhow!("unsupported raster format for resize")),
    }
    Ok(bytes)
}

fn raster_limits(max_pixels: u64) -> image::Limits {
    let max_dim = max_pixels.min(u32::MAX as u64) as u32;
    let max_alloc = max_pixels.saturating_mul(4);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(max_dim);
    limits.max_image_height = Some(max_dim);
    limits.max_alloc = Some(max_alloc);
    limits
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
            if !value.trim().is_empty() {
                return Some((value.clone(), "thumbnailUri"));
            }
        }
    }
    let media = metadata
        .media_uri
        .as_ref()
        .or(metadata.media_uri_alt.as_ref());
    if let Some(value) = media {
        if !value.trim().is_empty() {
            return Some((value.clone(), "mediaUri"));
        }
    }
    if let Some(value) = metadata.animation_url.as_ref() {
        if !value.trim().is_empty() {
            return Some((value.clone(), "animation_url"));
        }
    }
    if let Some(value) = metadata.animation_url_alt.as_ref() {
        if !value.trim().is_empty() {
            return Some((value.clone(), "animationUrl"));
        }
    }
    if let Some(value) = metadata.image.as_ref() {
        if !value.trim().is_empty() {
            return Some((value.clone(), "image"));
        }
    }
    if let Some(value) = metadata.src.as_ref() {
        if !value.trim().is_empty() {
            return Some((value.clone(), "src"));
        }
    }
    if let Some(value) = thumb {
        if !value.trim().is_empty() {
            return Some((value.clone(), "thumbnailUri"));
        }
    }
    None
}

fn resolve_relative_art_uri(art_uri: &str, metadata_uri: &str) -> Option<String> {
    let trimmed = art_uri.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("data:")
        || lower.starts_with("http://")
        || lower.starts_with("https://")
        || normalize_ipfs_uri(trimmed).is_some()
        || normalize_arweave_uri(trimmed).is_some()
    {
        return None;
    }
    if let Some(ipfs_uri) = normalize_ipfs_uri(metadata_uri) {
        if let Ok((cid, path)) = parse_ipfs_uri(&ipfs_uri) {
            let base_dir = path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");
            let suffix = trimmed.trim_start_matches('/');
            let joined = if base_dir.is_empty() {
                format!("/{suffix}")
            } else {
                format!("{base_dir}/{suffix}")
            };
            return Some(format!("ipfs://{cid}{joined}"));
        }
    }
    if let Ok(base) = Url::parse(metadata_uri) {
        if matches!(base.scheme(), "http" | "https") {
            if let Ok(joined) = base.join(trimmed) {
                return Some(joined.to_string());
            }
        }
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
    fn normalize_ipfs_uri_accepts_bare_cid() {
        let normalized = normalize_ipfs_uri("bafy123").unwrap();
        assert_eq!(normalized, "ipfs://bafy123");
    }

    #[test]
    fn normalize_ipfs_uri_accepts_cid_path() {
        let normalized = normalize_ipfs_uri("bafy123/metadata.json").unwrap();
        assert_eq!(normalized, "ipfs://bafy123/metadata.json");
    }

    #[test]
    fn normalize_arweave_uri_to_https() {
        let normalized = normalize_arweave_uri("ar://tx123/path.png").unwrap();
        assert_eq!(normalized, "https://arweave.net/tx123/path.png");
    }

    #[test]
    fn resolve_relative_art_uri_with_http_base() {
        let resolved =
            resolve_relative_art_uri("image.png", "https://example.com/meta/metadata.json")
                .unwrap();
        assert_eq!(resolved, "https://example.com/meta/image.png");
    }

    #[test]
    fn resolve_relative_art_uri_with_ipfs_base() {
        let resolved =
            resolve_relative_art_uri("image.png", "ipfs://bafy123/metadata/metadata.json").unwrap();
        assert_eq!(resolved, "ipfs://bafy123/metadata/image.png");
    }

    #[test]
    fn parse_ipfs_http_url_extracts_cid() {
        let parsed = Url::parse("https://ipfs.io/ipfs/bafy123/dir/file.png").unwrap();
        let (cid, path) = parse_ipfs_http_url(&parsed).unwrap();
        assert_eq!(cid, "bafy123");
        assert_eq!(path, "/dir/file.png");
    }

    #[test]
    fn parse_data_uri_base64() {
        let (bytes, mime) = parse_data_uri("data:text/plain;base64,SGVsbG8=").unwrap();
        assert_eq!(mime.unwrap().essence_str(), "text/plain");
        assert_eq!(bytes.as_ref(), b"Hello");
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
    fn metadata_skips_empty_strings() {
        let metadata = MetadataJson {
            image: Some("   ".to_string()),
            media_uri: None,
            media_uri_alt: None,
            animation_url: None,
            animation_url_alt: None,
            src: Some("".to_string()),
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
