use crate::config::Config;
use anyhow::{Context, Result};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use filetime::FileTime;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;
use tracing::{info, warn};

#[derive(Clone)]
pub struct CacheManager {
    pub renders_dir: PathBuf,
    pub assets_dir: PathBuf,
    pub asset_meta_dir: PathBuf,
    pub asset_raw_dir: PathBuf,
    pub asset_raster_dir: PathBuf,
    pub composites_dir: PathBuf,
    pub overlays_dir: PathBuf,
    pub render_ttl: Duration,
    pub asset_ttl: Duration,
    pub max_size_bytes: u64,
    pub touch_interval: Duration,
    size_cache_ttl: Duration,
    size_cache: Arc<Mutex<CacheSizeCache>>,
}

#[derive(Debug, Clone)]
pub struct RenderCacheEntry {
    pub path: PathBuf,
}

#[derive(Debug, Default)]
struct CacheSizeCache {
    render_bytes: u64,
    asset_bytes: u64,
    updated_at: Option<Instant>,
}

const DEFAULT_MAX_RENDER_CACHE_KEYS: usize = 100_000;

#[derive(Clone)]
pub struct RenderCacheLimiter {
    max_variants_per_key: usize,
    max_keys: usize,
    inner: Arc<Mutex<RenderCacheLimiterInner>>,
}

struct RenderCacheLimiterInner {
    map: HashMap<String, VecDeque<RenderCacheEntry>>,
    order: VecDeque<String>,
}

impl RenderCacheLimiter {
    pub fn new(max_variants_per_key: usize) -> Self {
        Self {
            max_variants_per_key,
            max_keys: DEFAULT_MAX_RENDER_CACHE_KEYS,
            inner: Arc::new(Mutex::new(RenderCacheLimiterInner {
                map: HashMap::new(),
                order: VecDeque::new(),
            })),
        }
    }

    pub fn register(&self, key: &str, entry: RenderCacheEntry) -> Vec<PathBuf> {
        if self.max_variants_per_key == 0 {
            return vec![entry.path];
        }
        let mut inner = self.inner.lock().unwrap_or_else(|err| err.into_inner());
        let key = key.to_string();
        if inner.map.contains_key(&key) {
            inner.order.retain(|item| item != &key);
        }
        inner.order.push_back(key.clone());
        let queue = inner.map.entry(key.clone()).or_default();
        if let Some(pos) = queue.iter().position(|item| item.path == entry.path) {
            queue.remove(pos);
        }
        queue.push_back(entry);
        let mut evicted = Vec::new();
        while queue.len() > self.max_variants_per_key {
            if let Some(oldest) = queue.pop_front() {
                evicted.push(oldest.path);
            }
        }
        if self.max_keys > 0 {
            while inner.map.len() > self.max_keys {
                let Some(oldest_key) = inner.order.pop_front() else {
                    break;
                };
                if let Some(entries) = inner.map.remove(&oldest_key) {
                    for entry in entries {
                        evicted.push(entry.path);
                    }
                }
            }
        }
        evicted
    }
}

impl CacheManager {
    pub fn new(config: &Config) -> Result<Self> {
        let base_dir = config.cache_dir.clone();
        let renders_dir = base_dir.join("renders");
        let assets_dir = base_dir.join("assets");
        let asset_meta_dir = assets_dir.join("meta");
        let asset_raw_dir = assets_dir.join("raw");
        let asset_raster_dir = assets_dir.join("raster");
        let composites_dir = renders_dir.join("composites");
        let overlays_dir = base_dir.join("overlays");
        std::fs::create_dir_all(&renders_dir)?;
        std::fs::create_dir_all(&asset_meta_dir)?;
        std::fs::create_dir_all(&asset_raw_dir)?;
        std::fs::create_dir_all(&asset_raster_dir)?;
        std::fs::create_dir_all(&composites_dir)?;
        std::fs::create_dir_all(&overlays_dir)?;
        Ok(Self {
            renders_dir,
            assets_dir,
            asset_meta_dir,
            asset_raw_dir,
            asset_raster_dir,
            composites_dir,
            overlays_dir,
            render_ttl: config.render_cache_min_ttl,
            asset_ttl: config.asset_cache_min_ttl,
            max_size_bytes: config.cache_max_size_bytes,
            touch_interval: config.cache_touch_interval,
            size_cache_ttl: config.cache_size_refresh_interval,
            size_cache: Arc::new(Mutex::new(CacheSizeCache::default())),
        })
    }

    pub async fn load_cached_file(&self, path: &Path, ttl: Duration) -> Result<Option<Vec<u8>>> {
        let metadata = match tokio::fs::metadata(path).await {
            Ok(meta) => meta,
            Err(_) => return Ok(None),
        };
        let modified = match metadata.modified() {
            Ok(modified) => modified,
            Err(_) => return Ok(None),
        };
        if is_expired(modified, ttl) {
            let _ = tokio::fs::remove_file(path).await;
            return Ok(None);
        }
        let bytes = tokio::fs::read(path).await?;
        if should_touch(modified, self.touch_interval) {
            touch_path(path).await?;
        }
        Ok(Some(bytes))
    }

    pub async fn is_cached_file(&self, path: &Path, ttl: Duration) -> Result<bool> {
        let metadata = match tokio::fs::metadata(path).await {
            Ok(meta) => meta,
            Err(_) => return Ok(false),
        };
        if let Ok(modified) = metadata.modified() {
            if is_expired(modified, ttl) {
                let _ = tokio::fs::remove_file(path).await;
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub async fn cached_file_len(&self, path: &Path, ttl: Duration) -> Result<Option<u64>> {
        let metadata = match tokio::fs::metadata(path).await {
            Ok(meta) => meta,
            Err(_) => return Ok(None),
        };
        if let Ok(modified) = metadata.modified() {
            if is_expired(modified, ttl) {
                let _ = tokio::fs::remove_file(path).await;
                return Ok(None);
            }
            if should_touch(modified, self.touch_interval) {
                touch_path(path).await?;
            }
        }
        Ok(Some(metadata.len()))
    }

    pub async fn store_file(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("cache");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let temp_path = parent.join(format!(".{file_name}.tmp-{nonce}"));
        if let Err(err) = tokio::fs::write(&temp_path, bytes).await {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(err.into());
        }
        if let Err(err) = tokio::fs::rename(&temp_path, path).await {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(err.into());
        }
        Ok(())
    }

    pub async fn remove_dir_if_exists(&self, path: &Path) -> Result<()> {
        if path.exists() {
            tokio::fs::remove_dir_all(path).await?;
        }
        Ok(())
    }

    pub async fn ensure_dirs(&self) -> Result<()> {
        tokio::fs::create_dir_all(&self.renders_dir).await?;
        tokio::fs::create_dir_all(&self.asset_meta_dir).await?;
        tokio::fs::create_dir_all(&self.asset_raw_dir).await?;
        tokio::fs::create_dir_all(&self.asset_raster_dir).await?;
        tokio::fs::create_dir_all(&self.composites_dir).await?;
        tokio::fs::create_dir_all(&self.overlays_dir).await?;
        Ok(())
    }

    pub async fn evict_loop(self, interval: Duration) {
        loop {
            if let Err(err) = self.evict_once().await {
                warn!(error = ?err, "cache eviction error");
            }
            tokio::time::sleep(interval).await;
        }
    }

    pub async fn scan_dir_size(&self, path: &Path) -> Result<u64> {
        tokio::task::spawn_blocking({
            let path = path.to_path_buf();
            move || -> Result<u64> {
                if !path.exists() {
                    return Ok(0);
                }
                let mut total = 0u64;
                for entry in walk_dir(&path)? {
                    let metadata = match entry.metadata() {
                        Ok(meta) => meta,
                        Err(_) => continue,
                    };
                    if metadata.is_file() {
                        total = total.saturating_add(metadata.len());
                    }
                }
                Ok(total)
            }
        })
        .await?
    }

    pub async fn cached_sizes(&self) -> Result<(u64, u64)> {
        if self.size_cache_ttl == Duration::from_secs(0) {
            let render_bytes = self.scan_dir_size(&self.renders_dir).await?;
            let asset_bytes = self.scan_dir_size(&self.assets_dir).await?;
            return Ok((render_bytes, asset_bytes));
        }
        let now = Instant::now();
        {
            let guard = self
                .size_cache
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            if let Some(updated) = guard.updated_at {
                if now.duration_since(updated) < self.size_cache_ttl {
                    return Ok((guard.render_bytes, guard.asset_bytes));
                }
            }
        }
        let render_bytes = self.scan_dir_size(&self.renders_dir).await?;
        let asset_bytes = self.scan_dir_size(&self.assets_dir).await?;
        let mut guard = self
            .size_cache
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        guard.render_bytes = render_bytes;
        guard.asset_bytes = asset_bytes;
        guard.updated_at = Some(now);
        Ok((render_bytes, asset_bytes))
    }

    async fn evict_once(&self) -> Result<()> {
        let render_stats = tokio::task::spawn_blocking({
            let dir = self.renders_dir.clone();
            let ttl = self.render_ttl;
            move || collect_files(&dir, ttl)
        })
        .await
        .context("scan render cache")??;
        let asset_stats = tokio::task::spawn_blocking({
            let dir = self.assets_dir.clone();
            let ttl = self.asset_ttl;
            move || collect_files(&dir, ttl)
        })
        .await
        .context("scan asset cache")??;

        let total_size = render_stats
            .total_size
            .saturating_add(asset_stats.total_size);
        if total_size > self.max_size_bytes {
            let mut files = render_stats.files;
            files.extend(asset_stats.files);
            evict_oldest(&files, self.max_size_bytes)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct RenderSingleflight {
    inner: Arc<DashMap<String, Arc<Notify>>>,
}

impl RenderSingleflight {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    pub async fn acquire(&self, key: &str) -> SingleflightPermit {
        match self.inner.entry(key.to_string()) {
            Entry::Occupied(entry) => {
                SingleflightPermit::waiter(self.inner.clone(), entry.get().clone(), key.to_string())
            }
            Entry::Vacant(entry) => {
                let notify = Arc::new(Notify::new());
                entry.insert(notify.clone());
                SingleflightPermit::leader(self.inner.clone(), notify, key.to_string())
            }
        }
    }
}

pub struct SingleflightPermit {
    key: String,
    notify: Arc<Notify>,
    is_leader: bool,
    inner: Arc<DashMap<String, Arc<Notify>>>,
}

impl SingleflightPermit {
    fn leader(inner: Arc<DashMap<String, Arc<Notify>>>, notify: Arc<Notify>, key: String) -> Self {
        Self {
            key,
            notify,
            is_leader: true,
            inner,
        }
    }

    fn waiter(inner: Arc<DashMap<String, Arc<Notify>>>, notify: Arc<Notify>, key: String) -> Self {
        Self {
            key,
            notify,
            is_leader: false,
            inner,
        }
    }

    pub fn is_leader(&self) -> bool {
        self.is_leader
    }
}

impl SingleflightPermit {
    pub async fn wait_result(self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, self.notify.notified())
            .await
            .is_ok()
    }
}

impl Drop for SingleflightPermit {
    fn drop(&mut self) {
        if !self.is_leader {
            return;
        }
        if let Some((_, notify)) = self.inner.remove(&self.key) {
            notify.notify_waiters();
        }
    }
}

fn is_expired(modified: SystemTime, ttl: Duration) -> bool {
    if let Ok(age) = SystemTime::now().duration_since(modified) {
        age > ttl
    } else {
        false
    }
}

fn should_touch(modified: SystemTime, interval: Duration) -> bool {
    if interval.is_zero() {
        return true;
    }
    match SystemTime::now().duration_since(modified) {
        Ok(age) => age >= interval,
        Err(_) => true,
    }
}

async fn touch_path(path: &Path) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let now = FileTime::from_system_time(SystemTime::now());
        filetime::set_file_mtime(path, now).ok();
    })
    .await?;
    Ok(())
}

struct CacheScan {
    total_size: u64,
    files: Vec<CacheFile>,
}

#[derive(Clone)]
struct CacheFile {
    path: PathBuf,
    modified: SystemTime,
    size: u64,
}

fn collect_files(dir: &Path, ttl: Duration) -> Result<CacheScan> {
    let mut total_size = 0u64;
    let mut files = Vec::new();
    if !dir.exists() {
        return Ok(CacheScan { total_size, files });
    }
    for entry in walk_dir(dir)? {
        let metadata = match entry.metadata() {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        if metadata.is_dir() {
            continue;
        }
        if let Ok(modified) = metadata.modified() {
            if is_expired(modified, ttl) {
                let _ = std::fs::remove_file(entry.path());
                continue;
            }
            let size = metadata.len();
            total_size = total_size.saturating_add(size);
            files.push(CacheFile {
                path: entry.path().to_path_buf(),
                modified,
                size,
            });
        }
    }
    Ok(CacheScan { total_size, files })
}

fn evict_oldest(files: &[CacheFile], target_size: u64) -> Result<()> {
    let mut sorted = files.to_vec();
    sorted.sort_by_key(|file| file.modified);
    let mut total_size: u64 = sorted.iter().map(|file| file.size).sum();
    if total_size <= target_size {
        return Ok(());
    }
    for file in sorted {
        let _ = std::fs::remove_file(&file.path);
        total_size = total_size.saturating_sub(file.size);
        if total_size <= target_size {
            info!(path = ?file.path, "cache evicted");
            break;
        }
    }
    Ok(())
}

fn walk_dir(dir: &Path) -> Result<Vec<std::fs::DirEntry>> {
    let mut entries = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                stack.push(path);
            } else {
                entries.push(entry);
            }
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn expired_check() {
        let now = SystemTime::now();
        assert!(!is_expired(now, Duration::from_secs(10)));
        let past = now - Duration::from_secs(11);
        assert!(is_expired(past, Duration::from_secs(10)));
    }

    #[test]
    fn walk_dir_counts_files() {
        let dir = tempdir().unwrap();
        let path = dir.path();
        std::fs::write(path.join("a.txt"), b"a").unwrap();
        std::fs::create_dir_all(path.join("nested")).unwrap();
        std::fs::write(path.join("nested/b.txt"), b"b").unwrap();
        let entries = walk_dir(path).unwrap();
        assert_eq!(entries.len(), 2);
    }
}
