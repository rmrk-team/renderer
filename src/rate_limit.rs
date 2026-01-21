use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const MAX_ENTRIES: usize = 10_000;
const EVICT_AFTER: Duration = Duration::from_secs(60 * 60);

#[derive(Clone)]
pub struct RateLimiter {
    enabled: bool,
    rate_per_second: f64,
    burst: f64,
    state: Arc<Mutex<HashMap<IpAddr, Bucket>>>,
}

#[derive(Clone)]
pub struct KeyRateLimiter {
    state: Arc<Mutex<HashMap<i64, KeyBucket>>>,
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
                state: Arc::new(Mutex::new(HashMap::new())),
            };
        }
        let burst = if burst == 0 { rate_per_minute.max(1) } else { burst };
        Self {
            enabled: true,
            rate_per_second: rate_per_minute as f64 / 60.0,
            burst: burst as f64,
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn allow(&self, ip: IpAddr) -> bool {
        if !self.enabled {
            return true;
        }
        let now = Instant::now();
        let mut map = self.state.lock().await;
        if map.len() > MAX_ENTRIES {
            map.retain(|_, bucket| now.duration_since(bucket.last_seen) <= EVICT_AFTER);
            if map.len() > MAX_ENTRIES {
                let mut entries = map
                    .iter()
                    .map(|(ip, bucket)| (*ip, bucket.last_seen))
                    .collect::<Vec<_>>();
                entries.sort_by_key(|(_, last_seen)| *last_seen);
                let overflow = map.len() - MAX_ENTRIES;
                for (ip, _) in entries.into_iter().take(overflow) {
                    map.remove(&ip);
                }
            }
        }
        let bucket = map.entry(ip).or_insert(Bucket {
            tokens: self.burst,
            last_refill: now,
            last_seen: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate_per_second).min(self.burst);
        bucket.last_refill = now;
        bucket.last_seen = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl KeyRateLimiter {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn allow(&self, key_id: i64, rate_per_minute: u64, burst: u64) -> bool {
        if rate_per_minute == 0 {
            return true;
        }
        let burst = if burst == 0 {
            rate_per_minute.max(1)
        } else {
            burst
        };
        let rate_per_second = rate_per_minute as f64 / 60.0;
        let now = Instant::now();
        let mut map = self.state.lock().await;
        if map.len() > MAX_ENTRIES {
            map.retain(|_, bucket| now.duration_since(bucket.last_seen) <= EVICT_AFTER);
            if map.len() > MAX_ENTRIES {
                let mut entries = map
                    .iter()
                    .map(|(key, bucket)| (*key, bucket.last_seen))
                    .collect::<Vec<_>>();
                entries.sort_by_key(|(_, last_seen)| *last_seen);
                let overflow = map.len() - MAX_ENTRIES;
                for (key, _) in entries.into_iter().take(overflow) {
                    map.remove(&key);
                }
            }
        }
        let bucket = map.entry(key_id).or_insert(KeyBucket {
            tokens: burst as f64,
            last_refill: now,
            last_seen: now,
            rate_per_second,
            burst: burst as f64,
        });
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
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}
