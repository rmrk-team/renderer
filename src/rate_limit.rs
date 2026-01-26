use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::hash::Hash;

const MAX_ENTRIES: usize = 10_000;
const EVICT_AFTER: Duration = Duration::from_secs(60 * 60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy)]
pub struct RateLimitInfo {
    pub allowed: bool,
    pub limit: u64,
    pub remaining: u64,
    pub reset_seconds: u64,
}

#[derive(Clone)]
pub struct RateLimiter {
    enabled: bool,
    rate_per_second: f64,
    burst: f64,
    buckets: Arc<DashMap<IpAddr, Bucket>>,
    last_cleanup_epoch: Arc<AtomicU64>,
}

#[derive(Clone)]
pub struct KeyRateLimiter {
    buckets: Arc<DashMap<i64, KeyBucket>>,
    last_cleanup_epoch: Arc<AtomicU64>,
}

#[derive(Clone)]
pub struct IdentityRateLimiter {
    buckets: Arc<DashMap<String, KeyBucket>>,
    last_cleanup_epoch: Arc<AtomicU64>,
}

#[derive(Debug)]
struct KeyBucket {
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
    rate_per_second: f64,
    burst: f64,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

impl RateLimiter {
    pub fn new(rate_per_minute: u64, burst: u64) -> Self {
        if rate_per_minute == 0 {
            return Self {
                enabled: false,
                rate_per_second: 0.0,
                burst: 0.0,
                buckets: Arc::new(DashMap::new()),
                last_cleanup_epoch: Arc::new(AtomicU64::new(0)),
            };
        }
        let burst = if burst == 0 {
            rate_per_minute.max(1)
        } else {
            burst
        };
        Self {
            enabled: true,
            rate_per_second: rate_per_minute as f64 / 60.0,
            burst: burst as f64,
            buckets: Arc::new(DashMap::new()),
            last_cleanup_epoch: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn check(&self, ip: IpAddr) -> RateLimitInfo {
        if !self.enabled {
            return RateLimitInfo {
                allowed: true,
                limit: 0,
                remaining: 0,
                reset_seconds: 0,
            };
        }
        let now = Instant::now();
        maybe_cleanup(&self.buckets, &self.last_cleanup_epoch, now);
        let mut entry = self.buckets.entry(ip).or_insert(Bucket {
            tokens: self.burst,
            last_refill: now,
            last_seen: now,
        });
        let bucket = entry.value_mut();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate_per_second).min(self.burst);
        bucket.last_refill = now;
        bucket.last_seen = now;
        let limit = self.burst.max(1.0).ceil() as u64;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            let remaining = bucket.tokens.floor().max(0.0) as u64;
            return RateLimitInfo {
                allowed: true,
                limit,
                remaining,
                reset_seconds: 0,
            };
        }
        let reset_seconds = if self.rate_per_second > 0.0 {
            ((1.0 - bucket.tokens) / self.rate_per_second)
                .ceil()
                .max(1.0) as u64
        } else {
            0
        };
        RateLimitInfo {
            allowed: false,
            limit,
            remaining: 0,
            reset_seconds,
        }
    }
}

impl KeyRateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            last_cleanup_epoch: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn check(&self, key_id: i64, rate_per_minute: u64, burst: u64) -> RateLimitInfo {
        if rate_per_minute == 0 {
            return RateLimitInfo {
                allowed: true,
                limit: 0,
                remaining: 0,
                reset_seconds: 0,
            };
        }
        let burst = if burst == 0 {
            rate_per_minute.max(1)
        } else {
            burst
        };
        let rate_per_second = rate_per_minute as f64 / 60.0;
        let now = Instant::now();
        maybe_cleanup(&self.buckets, &self.last_cleanup_epoch, now);
        let mut entry = self.buckets.entry(key_id).or_insert(KeyBucket {
            tokens: burst as f64,
            last_refill: now,
            last_seen: now,
            rate_per_second,
            burst: burst as f64,
        });
        let bucket = entry.value_mut();
        if (bucket.rate_per_second - rate_per_second).abs() > f64::EPSILON
            || (bucket.burst - burst as f64).abs() > f64::EPSILON
        {
            bucket.rate_per_second = rate_per_second;
            bucket.burst = burst as f64;
            bucket.tokens = bucket.tokens.min(bucket.burst);
        }
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * bucket.rate_per_second).min(bucket.burst);
        bucket.last_refill = now;
        bucket.last_seen = now;
        let limit = burst.max(1);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            let remaining = bucket.tokens.floor().max(0.0) as u64;
            return RateLimitInfo {
                allowed: true,
                limit,
                remaining,
                reset_seconds: 0,
            };
        }
        let reset_seconds = if rate_per_second > 0.0 {
            ((1.0 - bucket.tokens) / rate_per_second).ceil().max(1.0) as u64
        } else {
            0
        };
        RateLimitInfo {
            allowed: false,
            limit,
            remaining: 0,
            reset_seconds,
        }
    }
}

trait HasLastSeen {
    fn last_seen(&self) -> Instant;
}

impl HasLastSeen for Bucket {
    fn last_seen(&self) -> Instant {
        self.last_seen
    }
}

impl HasLastSeen for KeyBucket {
    fn last_seen(&self) -> Instant {
        self.last_seen
    }
}

impl IdentityRateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            last_cleanup_epoch: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn check(
        &self,
        key: &str,
        rate_per_minute: u64,
        burst: u64,
    ) -> RateLimitInfo {
        if rate_per_minute == 0 {
            return RateLimitInfo {
                allowed: true,
                limit: 0,
                remaining: 0,
                reset_seconds: 0,
            };
        }
        let burst = if burst == 0 {
            rate_per_minute.max(1)
        } else {
            burst
        };
        let rate_per_second = rate_per_minute as f64 / 60.0;
        let now = Instant::now();
        maybe_cleanup(&self.buckets, &self.last_cleanup_epoch, now);
        let mut entry = self
            .buckets
            .entry(key.to_string())
            .or_insert(KeyBucket {
                tokens: burst as f64,
                last_refill: now,
                last_seen: now,
                rate_per_second,
                burst: burst as f64,
            });
        let bucket = entry.value_mut();
        if (bucket.rate_per_second - rate_per_second).abs() > f64::EPSILON
            || (bucket.burst - burst as f64).abs() > f64::EPSILON
        {
            bucket.rate_per_second = rate_per_second;
            bucket.burst = burst as f64;
            bucket.tokens = bucket.tokens.min(bucket.burst);
        }
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * bucket.rate_per_second).min(bucket.burst);
        bucket.last_refill = now;
        bucket.last_seen = now;
        let limit = burst.max(1);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            let remaining = bucket.tokens.floor().max(0.0) as u64;
            return RateLimitInfo {
                allowed: true,
                limit,
                remaining,
                reset_seconds: 0,
            };
        }
        let reset_seconds = if rate_per_second > 0.0 {
            ((1.0 - bucket.tokens) / rate_per_second).ceil().max(1.0) as u64
        } else {
            0
        };
        RateLimitInfo {
            allowed: false,
            limit,
            remaining: 0,
            reset_seconds,
        }
    }
}

fn maybe_cleanup<K: Eq + Hash + Clone, V: HasLastSeen>(
    map: &DashMap<K, V>,
    last_cleanup_epoch: &AtomicU64,
    now: Instant,
) {
    if map.len() <= MAX_ENTRIES {
        return;
    }
    if !should_cleanup(last_cleanup_epoch) {
        return;
    }
    map.retain(|_, bucket| now.duration_since(bucket.last_seen()) <= EVICT_AFTER);
    if map.len() > MAX_ENTRIES {
        let mut entries = map
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().last_seen()))
            .collect::<Vec<_>>();
        entries.sort_by_key(|(_, last_seen)| *last_seen);
        let overflow = entries.len().saturating_sub(MAX_ENTRIES);
        for (key, _) in entries.into_iter().take(overflow) {
            map.remove(&key);
        }
    }
}

fn should_cleanup(last_cleanup_epoch: &AtomicU64) -> bool {
    let now_epoch = now_epoch_seconds();
    let last = last_cleanup_epoch.load(Ordering::Relaxed);
    if now_epoch.saturating_sub(last) < CLEANUP_INTERVAL.as_secs() {
        return false;
    }
    last_cleanup_epoch
        .compare_exchange(last, now_epoch, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

fn now_epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
