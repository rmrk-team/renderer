use crate::canonical;
use crate::config::{AdminCollectionInput, Config};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionConfig {
    pub chain: String,
    pub collection_address: String,
    pub canvas_width: Option<i64>,
    pub canvas_height: Option<i64>,
    pub canvas_fingerprint: Option<String>,
    pub og_focal_point: i64,
    pub og_overlay_uri: Option<String>,
    pub watermark_overlay_uri: Option<String>,
    pub warmup_strategy: String,
    pub cache_epoch: Option<i64>,
    pub catalog_address: Option<String>,
    pub approved: bool,
    pub approved_until: Option<i64>,
    pub approval_source: Option<String>,
    pub last_approval_sync_at: Option<i64>,
    pub last_approval_sync_block: Option<i64>,
    pub last_approval_check_at: Option<i64>,
    pub last_approval_check_result: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcEndpoint {
    pub chain: String,
    pub url: String,
    pub priority: i64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarmupJob {
    pub id: i64,
    pub chain: String,
    pub collection_address: String,
    pub token_id: String,
    pub asset_id: Option<String>,
    pub cache_timestamp: Option<String>,
    pub widths: Option<String>,
    pub include_og: bool,
    pub status: String,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub id: i64,
    pub name: String,
    pub notes: Option<String>,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientKey {
    pub id: i64,
    pub client_id: i64,
    pub key_prefix: String,
    pub active: bool,
    pub rate_limit_per_minute: Option<i64>,
    pub burst: Option<i64>,
    pub max_concurrent_renders_override: Option<i64>,
    pub allow_fresh: bool,
    pub created_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRule {
    pub id: i64,
    pub ip_cidr: String,
    pub mode: String,
    pub created_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRow {
    pub hour_bucket: i64,
    pub identity_key: String,
    pub route_group: String,
    pub requests: i64,
    pub bytes_out: i64,
    pub cache_hits: i64,
    pub cache_misses: i64,
}

#[derive(Debug, Clone)]
pub struct UsageBatchRow {
    pub hour_bucket: i64,
    pub identity_key: String,
    pub route_group: String,
    pub requests: i64,
    pub bytes_out: i64,
    pub cache_hits: i64,
    pub cache_misses: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedAssetCounts {
    pub pinned: i64,
    pub missing: i64,
    pub failed: i64,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogWarmupItem {
    pub id: i64,
    pub job_id: i64,
    pub chain: String,
    pub collection_address: String,
    pub part_id: String,
    pub metadata_uri: String,
    pub status: String,
    pub attempts: i64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenWarmupItem {
    pub id: i64,
    pub job_id: i64,
    pub chain: String,
    pub collection_address: String,
    pub token_id: String,
    pub asset_id: Option<String>,
    pub status: String,
    pub attempts: i64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashReplacement {
    pub cid: String,
    pub content_type: String,
    pub file_path: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStateCacheEntry {
    pub chain: String,
    pub collection_address: String,
    pub token_id: String,
    pub asset_id: String,
    pub state_hash: String,
    pub state_json: Option<String>,
    pub last_checked_at: i64,
    pub last_checked_block: Option<i64>,
    pub expires_at: i64,
    pub fallback_used: bool,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct FreshLimitResult {
    pub allowed: bool,
    pub retry_after_seconds: Option<u64>,
}

impl Database {
    pub async fn new(config: &Config) -> Result<Self> {
        if let Some(parent) = config.db_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create db directory {:?}", parent))?;
            }
        }
        let db_url = format!("sqlite://{}?mode=rwc", config.db_path.display());
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .context("connect to sqlite")?;
        let db = Self { pool };
        db.init_schema().await?;
        db.seed_rpc_endpoints(&config.rpc_endpoints).await?;
        db.normalize_collection_config().await?;
        db.normalize_warmup_jobs().await?;
        db.normalize_rpc_endpoints().await?;
        db.normalize_approval_state().await?;
        Ok(db)
    }

    async fn init_schema(&self) -> Result<()> {
        let schema = r#"
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS collection_config (
          id INTEGER PRIMARY KEY,
          chain TEXT NOT NULL,
          collection_address TEXT NOT NULL,
          canvas_width INTEGER,
          canvas_height INTEGER,
          canvas_fingerprint TEXT,
          og_focal_point INTEGER DEFAULT 25,
          og_overlay_uri TEXT,
          watermark_overlay_uri TEXT,
          warmup_strategy TEXT DEFAULT 'auto',
          cache_epoch INTEGER,
          catalog_address TEXT,
          approved INTEGER DEFAULT 0,
          approved_until INTEGER,
          approval_source TEXT,
          last_approval_sync_at INTEGER,
          last_approval_sync_block INTEGER,
          last_approval_check_at INTEGER,
          last_approval_check_result INTEGER,
          created_at INTEGER,
          updated_at INTEGER,
          UNIQUE(chain, collection_address)
        );
        CREATE TABLE IF NOT EXISTS rpc_endpoints (
          id INTEGER PRIMARY KEY,
          chain TEXT NOT NULL,
          url TEXT NOT NULL,
          priority INTEGER DEFAULT 0,
          enabled INTEGER DEFAULT 1,
          UNIQUE(chain, url)
        );
        CREATE TABLE IF NOT EXISTS warmup_jobs (
          id INTEGER PRIMARY KEY,
          chain TEXT NOT NULL,
          collection_address TEXT NOT NULL,
          token_id TEXT NOT NULL,
          asset_id TEXT,
          cache_timestamp TEXT,
          widths TEXT,
          include_og INTEGER DEFAULT 0,
          status TEXT NOT NULL,
          last_error TEXT,
          created_at INTEGER,
          updated_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS warmup_state (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          paused INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS approval_state (
          chain TEXT PRIMARY KEY,
          last_block INTEGER
        );
        CREATE TABLE IF NOT EXISTS approval_quarantine (
          id INTEGER PRIMARY KEY,
          watcher_chain TEXT NOT NULL,
          chain_id INTEGER NOT NULL,
          collection_address TEXT NOT NULL,
          payer TEXT NOT NULL,
          amount TEXT NOT NULL,
          created_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS clients (
          id INTEGER PRIMARY KEY,
          name TEXT NOT NULL,
          notes TEXT,
          created_at INTEGER,
          updated_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS client_keys (
          id INTEGER PRIMARY KEY,
          client_id INTEGER NOT NULL,
          key_hash TEXT NOT NULL UNIQUE,
          key_prefix TEXT NOT NULL,
          active INTEGER DEFAULT 1,
          rate_limit_per_minute INTEGER,
          burst INTEGER,
          max_concurrent_renders_override INTEGER,
          allow_fresh INTEGER DEFAULT 0,
          created_at INTEGER,
          revoked_at INTEGER,
          FOREIGN KEY(client_id) REFERENCES clients(id)
        );
        CREATE TABLE IF NOT EXISTS client_ip_rules (
          id INTEGER PRIMARY KEY,
          ip_cidr TEXT NOT NULL,
          mode TEXT NOT NULL,
          created_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS client_usage_hourly (
          hour_bucket INTEGER NOT NULL,
          identity_key TEXT NOT NULL,
          route_group TEXT NOT NULL,
          requests INTEGER NOT NULL,
          bytes_out INTEGER NOT NULL,
          cache_hits INTEGER NOT NULL,
          cache_misses INTEGER NOT NULL,
          PRIMARY KEY (hour_bucket, identity_key, route_group)
        );
        CREATE TABLE IF NOT EXISTS renderer_settings (
          key TEXT PRIMARY KEY,
          value TEXT
        );
        CREATE TABLE IF NOT EXISTS pinned_assets (
          id INTEGER PRIMARY KEY,
          asset_key TEXT NOT NULL UNIQUE,
          cid TEXT NOT NULL,
          path TEXT NOT NULL,
          content_type TEXT,
          size_bytes INTEGER,
          status TEXT NOT NULL,
          attempts INTEGER DEFAULT 0,
          last_error TEXT,
          first_seen_at INTEGER,
          pinned_at INTEGER,
          last_attempt_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS pinned_assets_cid_idx ON pinned_assets(cid);
        CREATE INDEX IF NOT EXISTS pinned_assets_path_idx ON pinned_assets(path);
        CREATE TABLE IF NOT EXISTS hash_replacements (
          cid TEXT PRIMARY KEY,
          content_type TEXT NOT NULL,
          file_path TEXT NOT NULL,
          created_at INTEGER,
          updated_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS catalog_warmup_jobs (
          id INTEGER PRIMARY KEY,
          chain TEXT NOT NULL,
          collection_address TEXT NOT NULL,
          catalog_address TEXT NOT NULL,
          status TEXT NOT NULL,
          last_error TEXT,
          created_at INTEGER,
          updated_at INTEGER,
          UNIQUE(chain, collection_address)
        );
        CREATE TABLE IF NOT EXISTS catalog_warmup_items (
          id INTEGER PRIMARY KEY,
          job_id INTEGER NOT NULL,
          part_id TEXT NOT NULL,
          metadata_uri TEXT NOT NULL,
          status TEXT NOT NULL,
          attempts INTEGER DEFAULT 0,
          last_error TEXT,
          created_at INTEGER,
          updated_at INTEGER,
          UNIQUE(job_id, metadata_uri),
          FOREIGN KEY(job_id) REFERENCES catalog_warmup_jobs(id)
        );
        CREATE INDEX IF NOT EXISTS catalog_warmup_items_status_idx ON catalog_warmup_items(job_id, status);
        CREATE TABLE IF NOT EXISTS collection_asset_refs (
          id INTEGER PRIMARY KEY,
          chain TEXT NOT NULL,
          collection_address TEXT NOT NULL,
          asset_key TEXT NOT NULL,
          source TEXT NOT NULL,
          part_id TEXT,
          created_at INTEGER,
          updated_at INTEGER,
          UNIQUE(chain, collection_address, asset_key, source, part_id)
        );
        CREATE INDEX IF NOT EXISTS collection_asset_refs_lookup_idx
          ON collection_asset_refs(chain, collection_address, source);
        CREATE TABLE IF NOT EXISTS token_warmup_jobs (
          id INTEGER PRIMARY KEY,
          chain TEXT NOT NULL,
          collection_address TEXT NOT NULL,
          asset_id TEXT,
          status TEXT NOT NULL,
          last_error TEXT,
          created_at INTEGER,
          updated_at INTEGER,
          UNIQUE(chain, collection_address)
        );
        CREATE TABLE IF NOT EXISTS token_warmup_items (
          id INTEGER PRIMARY KEY,
          job_id INTEGER NOT NULL,
          token_id TEXT NOT NULL,
          status TEXT NOT NULL,
          attempts INTEGER DEFAULT 0,
          last_error TEXT,
          created_at INTEGER,
          updated_at INTEGER,
          UNIQUE(job_id, token_id),
          FOREIGN KEY(job_id) REFERENCES token_warmup_jobs(id)
        );
        CREATE INDEX IF NOT EXISTS token_warmup_items_status_idx
          ON token_warmup_items(job_id, status);
        CREATE TABLE IF NOT EXISTS token_asset_refs (
          id INTEGER PRIMARY KEY,
          chain TEXT NOT NULL,
          collection_address TEXT NOT NULL,
          token_id TEXT NOT NULL,
          asset_key TEXT NOT NULL,
          source TEXT NOT NULL,
          created_at INTEGER,
          updated_at INTEGER,
          UNIQUE(chain, collection_address, token_id, asset_key, source)
        );
        CREATE INDEX IF NOT EXISTS token_asset_refs_lookup_idx
          ON token_asset_refs(chain, collection_address, token_id, source);
        CREATE TABLE IF NOT EXISTS token_state_cache (
          id INTEGER PRIMARY KEY,
          chain TEXT NOT NULL,
          collection_address TEXT NOT NULL,
          token_id TEXT NOT NULL,
          asset_id TEXT NOT NULL,
          state_hash TEXT NOT NULL,
          state_json TEXT,
          last_checked_at INTEGER NOT NULL,
          last_checked_block INTEGER,
          expires_at INTEGER NOT NULL,
          fallback_used INTEGER DEFAULT 0,
          last_error TEXT,
          UNIQUE(chain, collection_address, token_id, asset_id)
        );
        CREATE INDEX IF NOT EXISTS token_state_cache_lookup_idx
          ON token_state_cache(chain, collection_address, token_id, asset_id);
        CREATE TABLE IF NOT EXISTS fresh_requests (
          key TEXT PRIMARY KEY,
          last_refresh_at INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO warmup_state (id, paused) VALUES (1, 0);
        "#;
        sqlx::query(schema).execute(&self.pool).await?;
        let _ = sqlx::query("ALTER TABLE warmup_jobs ADD COLUMN widths TEXT")
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("ALTER TABLE warmup_jobs ADD COLUMN include_og INTEGER DEFAULT 0")
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("ALTER TABLE collection_config ADD COLUMN approved_until INTEGER")
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("ALTER TABLE collection_config ADD COLUMN approval_source TEXT")
            .execute(&self.pool)
            .await;
        let _ =
            sqlx::query("ALTER TABLE collection_config ADD COLUMN last_approval_sync_at INTEGER")
                .execute(&self.pool)
                .await;
        let _ = sqlx::query(
            "ALTER TABLE collection_config ADD COLUMN last_approval_sync_block INTEGER",
        )
        .execute(&self.pool)
        .await;
        let _ = sqlx::query("ALTER TABLE collection_config ADD COLUMN cache_epoch INTEGER")
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("ALTER TABLE collection_config ADD COLUMN catalog_address TEXT")
            .execute(&self.pool)
            .await;
        let _ =
            sqlx::query("ALTER TABLE collection_config ADD COLUMN last_approval_check_at INTEGER")
                .execute(&self.pool)
                .await;
        let _ = sqlx::query(
            "ALTER TABLE collection_config ADD COLUMN last_approval_check_result INTEGER",
        )
        .execute(&self.pool)
        .await;
        let _ = sqlx::query("ALTER TABLE client_keys ADD COLUMN allow_fresh INTEGER DEFAULT 0")
            .execute(&self.pool)
            .await;
        let _ =
            sqlx::query("ALTER TABLE token_state_cache ADD COLUMN fallback_used INTEGER DEFAULT 0")
                .execute(&self.pool)
                .await;
        self.migrate_usage_table().await?;
        Ok(())
    }

    async fn migrate_usage_table(&self) -> Result<()> {
        let columns = sqlx::query("PRAGMA table_info(client_usage_hourly)")
            .fetch_all(&self.pool)
            .await?;
        let has_identity_key = columns.iter().any(|row| {
            row.get::<String, _>("name")
                .eq_ignore_ascii_case("identity_key")
        });
        if has_identity_key {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS client_usage_hourly_v2 (
              hour_bucket INTEGER NOT NULL,
              identity_key TEXT NOT NULL,
              route_group TEXT NOT NULL,
              requests INTEGER NOT NULL,
              bytes_out INTEGER NOT NULL,
              cache_hits INTEGER NOT NULL,
              cache_misses INTEGER NOT NULL,
              PRIMARY KEY (hour_bucket, identity_key, route_group)
            )
            "#,
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO client_usage_hourly_v2 (
              hour_bucket, identity_key, route_group, requests, bytes_out, cache_hits, cache_misses
            )
            SELECT
              hour_bucket,
              CASE
                WHEN identity_type = 'api_key' AND client_id IS NOT NULL THEN 'client:' || client_id
                WHEN identity_type = 'ip' THEN 'ip:anon'
                WHEN identity_type = 'anonymous' THEN 'anonymous'
                ELSE identity_type
              END AS identity_key,
              route_group,
              requests,
              bytes_out,
              cache_hits,
              cache_misses
            FROM client_usage_hourly
            "#,
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query("DROP TABLE client_usage_hourly")
            .execute(&mut *tx)
            .await?;
        sqlx::query("ALTER TABLE client_usage_hourly_v2 RENAME TO client_usage_hourly")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn seed_rpc_endpoints(
        &self,
        rpc_endpoints: &std::collections::HashMap<String, Vec<String>>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for (chain, urls) in rpc_endpoints {
            sqlx::query("DELETE FROM rpc_endpoints WHERE lower(chain) = lower(?1)")
                .bind(chain)
                .execute(&mut *tx)
                .await?;
            for (priority, url) in urls.iter().enumerate() {
                sqlx::query(
                    r#"
                    INSERT INTO rpc_endpoints (chain, url, priority, enabled)
                    VALUES (?1, ?2, ?3, 1)
                    "#,
                )
                .bind(chain)
                .bind(url)
                .bind(priority as i64)
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    async fn normalize_collection_config(&self) -> Result<()> {
        let rows = sqlx::query(
            r#"
            SELECT id, chain, collection_address, canvas_width, canvas_height, canvas_fingerprint,
                   og_focal_point, og_overlay_uri, watermark_overlay_uri, warmup_strategy, cache_epoch, catalog_address, approved,
                   approved_until, approval_source, last_approval_sync_at, last_approval_sync_block,
                   last_approval_check_at, last_approval_check_result, created_at, updated_at
            FROM collection_config
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        if rows.is_empty() {
            return Ok(());
        }

        #[derive(Clone)]
        struct RowData {
            id: i64,
            chain: String,
            collection_address: String,
            canvas_width: Option<i64>,
            canvas_height: Option<i64>,
            canvas_fingerprint: Option<String>,
            og_focal_point: i64,
            og_overlay_uri: Option<String>,
            watermark_overlay_uri: Option<String>,
            warmup_strategy: String,
            cache_epoch: Option<i64>,
            catalog_address: Option<String>,
            approved: bool,
            approved_until: Option<i64>,
            approval_source: Option<String>,
            last_approval_sync_at: Option<i64>,
            last_approval_sync_block: Option<i64>,
            last_approval_check_at: Option<i64>,
            last_approval_check_result: Option<bool>,
            created_at: Option<i64>,
            updated_at: Option<i64>,
        }

        let mut grouped: std::collections::HashMap<(String, String), Vec<RowData>> =
            std::collections::HashMap::new();
        for row in rows {
            let chain_raw: String = row.get("chain");
            let chain = match canonical::canonicalize_chain_unchecked(&chain_raw) {
                Ok(chain) => chain,
                Err(err) => {
                    warn!(error = ?err, chain = %chain_raw, "invalid chain in collection_config");
                    continue;
                }
            };
            let collection_raw: String = row.get("collection_address");
            let collection_address = match canonical::canonicalize_collection_address(
                &collection_raw,
            ) {
                Ok(address) => address,
                Err(err) => {
                    warn!(error = ?err, address = %collection_raw, "invalid collection address in collection_config");
                    continue;
                }
            };
            let data = RowData {
                id: row.get("id"),
                chain: chain_raw,
                collection_address: collection_raw,
                canvas_width: row.get("canvas_width"),
                canvas_height: row.get("canvas_height"),
                canvas_fingerprint: row.get("canvas_fingerprint"),
                og_focal_point: row.get::<i64, _>("og_focal_point"),
                og_overlay_uri: row.get("og_overlay_uri"),
                watermark_overlay_uri: row.get("watermark_overlay_uri"),
                warmup_strategy: row.get::<String, _>("warmup_strategy"),
                cache_epoch: row.get("cache_epoch"),
                catalog_address: row.get("catalog_address"),
                approved: row.get::<i64, _>("approved") == 1,
                approved_until: row.get("approved_until"),
                approval_source: row.get("approval_source"),
                last_approval_sync_at: row.get("last_approval_sync_at"),
                last_approval_sync_block: row.get("last_approval_sync_block"),
                last_approval_check_at: row.get("last_approval_check_at"),
                last_approval_check_result: row
                    .get::<Option<i64>, _>("last_approval_check_result")
                    .map(|value| value == 1),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            };
            grouped
                .entry((chain, collection_address))
                .or_default()
                .push(data);
        }

        let mut tx = self.pool.begin().await?;
        for ((chain, collection_address), mut rows) in grouped {
            let needs_merge = rows.len() > 1
                || rows[0].chain != chain
                || rows[0].collection_address != collection_address;
            if !needs_merge {
                continue;
            }
            if rows.len() > 1 {
                warn!(
                    chain = %chain,
                    collection = %collection_address,
                    count = rows.len(),
                    "merging duplicate collection_config rows"
                );
            }

            let mut merged = rows.remove(0);
            for row in rows.iter() {
                merged.approved = merged.approved || row.approved;
                merged.approved_until = match (merged.approved_until, row.approved_until) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (None, Some(b)) => Some(b),
                    (Some(a), None) => Some(a),
                    _ => None,
                };
                if let Some(until) = row.approved_until {
                    if until > 0 {
                        merged.approved = true;
                    }
                }
                if merged.approval_source.is_none() {
                    merged.approval_source = row.approval_source.clone();
                }
                merged.last_approval_sync_at =
                    match (merged.last_approval_sync_at, row.last_approval_sync_at) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        (None, Some(b)) => Some(b),
                        (Some(a), None) => Some(a),
                        _ => None,
                    };
                merged.last_approval_sync_block = match (
                    merged.last_approval_sync_block,
                    row.last_approval_sync_block,
                ) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (None, Some(b)) => Some(b),
                    (Some(a), None) => Some(a),
                    _ => None,
                };
                match (merged.last_approval_check_at, row.last_approval_check_at) {
                    (Some(a), Some(b)) => {
                        if b > a {
                            merged.last_approval_check_at = Some(b);
                            merged.last_approval_check_result = row.last_approval_check_result;
                        }
                    }
                    (None, Some(b)) => {
                        merged.last_approval_check_at = Some(b);
                        merged.last_approval_check_result = row.last_approval_check_result;
                    }
                    _ => {}
                }
                if merged.last_approval_check_result.is_none() {
                    merged.last_approval_check_result = row.last_approval_check_result;
                }
                merged.canvas_width = merged.canvas_width.or(row.canvas_width);
                merged.canvas_height = merged.canvas_height.or(row.canvas_height);
                merged.canvas_fingerprint = merged
                    .canvas_fingerprint
                    .clone()
                    .or_else(|| row.canvas_fingerprint.clone());
                if merged.og_focal_point == 25 && row.og_focal_point != 25 {
                    merged.og_focal_point = row.og_focal_point;
                }
                if merged.og_overlay_uri.is_none() {
                    merged.og_overlay_uri = row.og_overlay_uri.clone();
                }
                if merged.watermark_overlay_uri.is_none() {
                    merged.watermark_overlay_uri = row.watermark_overlay_uri.clone();
                }
                merged.cache_epoch = match (merged.cache_epoch, row.cache_epoch) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (None, Some(b)) => Some(b),
                    (Some(a), None) => Some(a),
                    _ => None,
                };
                if merged.catalog_address.is_none() {
                    merged.catalog_address = row.catalog_address.clone();
                }
                if merged.warmup_strategy == "auto" && row.warmup_strategy != "auto" {
                    merged.warmup_strategy = row.warmup_strategy.clone();
                }
                merged.created_at = match (merged.created_at, row.created_at) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (None, Some(b)) => Some(b),
                    (Some(a), None) => Some(a),
                    _ => None,
                };
                merged.updated_at = match (merged.updated_at, row.updated_at) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (None, Some(b)) => Some(b),
                    (Some(a), None) => Some(a),
                    _ => None,
                };
            }

            for row in rows.into_iter().chain(std::iter::once(merged.clone())) {
                sqlx::query("DELETE FROM collection_config WHERE id = ?1")
                    .bind(row.id)
                    .execute(&mut *tx)
                    .await?;
            }

            let now = now_epoch();
            sqlx::query(
                r#"
                INSERT INTO collection_config (
                  chain, collection_address, canvas_width, canvas_height, canvas_fingerprint,
                  og_focal_point, og_overlay_uri, watermark_overlay_uri, warmup_strategy, cache_epoch, catalog_address, approved,
                  approved_until, approval_source, last_approval_sync_at, last_approval_sync_block,
                  last_approval_check_at, last_approval_check_result, created_at, updated_at
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
                "#,
            )
            .bind(&chain)
            .bind(&collection_address)
            .bind(merged.canvas_width)
            .bind(merged.canvas_height)
            .bind(&merged.canvas_fingerprint)
            .bind(merged.og_focal_point)
            .bind(&merged.og_overlay_uri)
            .bind(&merged.watermark_overlay_uri)
            .bind(&merged.warmup_strategy)
            .bind(merged.cache_epoch)
            .bind(&merged.catalog_address)
            .bind(if merged.approved { 1 } else { 0 })
            .bind(merged.approved_until)
            .bind(&merged.approval_source)
            .bind(merged.last_approval_sync_at)
            .bind(merged.last_approval_sync_block)
            .bind(merged.last_approval_check_at)
            .bind(merged.last_approval_check_result.map(|value| if value { 1 } else { 0 }))
            .bind(merged.created_at.unwrap_or(now))
            .bind(merged.updated_at.unwrap_or(now))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn normalize_warmup_jobs(&self) -> Result<()> {
        let rows = sqlx::query("SELECT id, chain, collection_address FROM warmup_jobs")
            .fetch_all(&self.pool)
            .await?;
        if rows.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for row in rows {
            let id: i64 = row.get("id");
            let chain_raw: String = row.get("chain");
            let collection_raw: String = row.get("collection_address");
            let chain = match canonical::canonicalize_chain_unchecked(&chain_raw) {
                Ok(chain) => chain,
                Err(err) => {
                    warn!(error = ?err, chain = %chain_raw, "invalid chain in warmup_jobs");
                    continue;
                }
            };
            let collection = match canonical::canonicalize_collection_address(&collection_raw) {
                Ok(address) => address,
                Err(err) => {
                    warn!(error = ?err, address = %collection_raw, "invalid collection address in warmup_jobs");
                    continue;
                }
            };
            if chain != chain_raw || collection != collection_raw {
                sqlx::query(
                    "UPDATE warmup_jobs SET chain = ?1, collection_address = ?2 WHERE id = ?3",
                )
                .bind(&chain)
                .bind(&collection)
                .bind(id)
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    async fn normalize_rpc_endpoints(&self) -> Result<()> {
        let rows = sqlx::query(
            r#"
            SELECT id, chain, url, priority, enabled
            FROM rpc_endpoints
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        if rows.is_empty() {
            return Ok(());
        }

        #[derive(Clone)]
        struct RpcRow {
            id: i64,
            chain: String,
            priority: i64,
            enabled: bool,
        }

        let mut grouped: std::collections::HashMap<(String, String), Vec<RpcRow>> =
            std::collections::HashMap::new();
        for row in rows {
            let chain_raw: String = row.get("chain");
            let chain = match canonical::canonicalize_chain_unchecked(&chain_raw) {
                Ok(chain) => chain,
                Err(err) => {
                    warn!(error = ?err, chain = %chain_raw, "invalid chain in rpc_endpoints");
                    continue;
                }
            };
            let url: String = row.get("url");
            let data = RpcRow {
                id: row.get("id"),
                chain,
                priority: row.get("priority"),
                enabled: row.get::<i64, _>("enabled") == 1,
            };
            grouped
                .entry((data.chain.clone(), url))
                .or_default()
                .push(data);
        }

        let mut tx = self.pool.begin().await?;
        for ((chain, url), rows) in grouped {
            let mut merged = rows[0].clone();
            for row in rows.iter().skip(1) {
                merged.priority = merged.priority.min(row.priority);
                merged.enabled = merged.enabled || row.enabled;
            }
            for row in rows {
                sqlx::query("DELETE FROM rpc_endpoints WHERE id = ?1")
                    .bind(row.id)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query(
                r#"
                INSERT INTO rpc_endpoints (chain, url, priority, enabled)
                VALUES (?1, ?2, ?3, ?4)
                "#,
            )
            .bind(&chain)
            .bind(&url)
            .bind(merged.priority)
            .bind(if merged.enabled { 1 } else { 0 })
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn normalize_approval_state(&self) -> Result<()> {
        let rows = sqlx::query("SELECT chain, last_block FROM approval_state")
            .fetch_all(&self.pool)
            .await?;
        if rows.is_empty() {
            return Ok(());
        }
        let mut grouped: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        for row in rows {
            let chain_raw: String = row.get("chain");
            let chain = match canonical::canonicalize_chain_unchecked(&chain_raw) {
                Ok(chain) => chain,
                Err(err) => {
                    warn!(error = ?err, chain = %chain_raw, "invalid chain in approval_state");
                    continue;
                }
            };
            let last_block: Option<i64> = row.get("last_block");
            let entry = grouped.entry(chain).or_insert(i64::MIN);
            if let Some(value) = last_block {
                *entry = (*entry).max(value);
            }
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM approval_state")
            .execute(&mut *tx)
            .await?;
        for (chain, last_block) in grouped {
            let value = if last_block == i64::MIN {
                None
            } else {
                Some(last_block)
            };
            sqlx::query("INSERT INTO approval_state (chain, last_block) VALUES (?1, ?2)")
                .bind(&chain)
                .bind(value)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn list_collections(&self) -> Result<Vec<CollectionConfig>> {
        let rows = sqlx::query(
            r#"
            SELECT chain, collection_address, canvas_width, canvas_height, canvas_fingerprint,
                   og_focal_point, og_overlay_uri, watermark_overlay_uri, warmup_strategy, cache_epoch, catalog_address, approved,
                   approved_until, approval_source, last_approval_sync_at, last_approval_sync_block,
                   last_approval_check_at, last_approval_check_result
            FROM collection_config
            ORDER BY chain, collection_address
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        let configs = rows
            .into_iter()
            .map(|row| CollectionConfig {
                chain: row.get("chain"),
                collection_address: row.get("collection_address"),
                canvas_width: row.get("canvas_width"),
                canvas_height: row.get("canvas_height"),
                canvas_fingerprint: row.get("canvas_fingerprint"),
                og_focal_point: row.get::<i64, _>("og_focal_point"),
                og_overlay_uri: row.get("og_overlay_uri"),
                watermark_overlay_uri: row.get("watermark_overlay_uri"),
                warmup_strategy: row.get::<String, _>("warmup_strategy"),
                cache_epoch: row.get("cache_epoch"),
                catalog_address: row.get("catalog_address"),
                approved: row.get::<i64, _>("approved") == 1,
                approved_until: row.get("approved_until"),
                approval_source: row.get("approval_source"),
                last_approval_sync_at: row.get("last_approval_sync_at"),
                last_approval_sync_block: row.get("last_approval_sync_block"),
                last_approval_check_at: row.get("last_approval_check_at"),
                last_approval_check_result: row
                    .get::<Option<i64>, _>("last_approval_check_result")
                    .map(|value| value == 1),
            })
            .collect();
        Ok(configs)
    }

    pub async fn get_collection_config(
        &self,
        chain: &str,
        collection_address: &str,
    ) -> Result<Option<CollectionConfig>> {
        let row = sqlx::query(
            r#"
            SELECT chain, collection_address, canvas_width, canvas_height, canvas_fingerprint,
                   og_focal_point, og_overlay_uri, watermark_overlay_uri, warmup_strategy, cache_epoch, catalog_address, approved,
                   approved_until, approval_source, last_approval_sync_at, last_approval_sync_block,
                   last_approval_check_at, last_approval_check_result
            FROM collection_config
            WHERE chain = ?1 AND collection_address = ?2
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| CollectionConfig {
            chain: row.get("chain"),
            collection_address: row.get("collection_address"),
            canvas_width: row.get("canvas_width"),
            canvas_height: row.get("canvas_height"),
            canvas_fingerprint: row.get("canvas_fingerprint"),
            og_focal_point: row.get::<i64, _>("og_focal_point"),
            og_overlay_uri: row.get("og_overlay_uri"),
            watermark_overlay_uri: row.get("watermark_overlay_uri"),
            warmup_strategy: row.get::<String, _>("warmup_strategy"),
            cache_epoch: row.get("cache_epoch"),
            catalog_address: row.get("catalog_address"),
            approved: row.get::<i64, _>("approved") == 1,
            approved_until: row.get("approved_until"),
            approval_source: row.get("approval_source"),
            last_approval_sync_at: row.get("last_approval_sync_at"),
            last_approval_sync_block: row.get("last_approval_sync_block"),
            last_approval_check_at: row.get("last_approval_check_at"),
            last_approval_check_result: row
                .get::<Option<i64>, _>("last_approval_check_result")
                .map(|value| value == 1),
        }))
    }

    pub async fn get_collection_cache_epoch(
        &self,
        chain: &str,
        collection_address: &str,
    ) -> Result<Option<i64>> {
        let row = sqlx::query(
            r#"
            SELECT cache_epoch
            FROM collection_config
            WHERE chain = ?1 AND collection_address = ?2
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|row| row.get::<Option<i64>, _>("cache_epoch")))
    }

    pub async fn set_collection_cache_epoch(
        &self,
        chain: &str,
        collection_address: &str,
        epoch: i64,
    ) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            INSERT INTO collection_config (
              chain, collection_address, cache_epoch, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(chain, collection_address) DO UPDATE SET
              cache_epoch = excluded.cache_epoch,
              updated_at = excluded.updated_at
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .bind(epoch)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_collection_catalog_address(
        &self,
        chain: &str,
        collection_address: &str,
    ) -> Result<Option<String>> {
        let row = sqlx::query(
            r#"
            SELECT catalog_address
            FROM collection_config
            WHERE chain = ?1 AND collection_address = ?2
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|row| row.get::<Option<String>, _>("catalog_address")))
    }

    pub async fn set_collection_catalog_address(
        &self,
        chain: &str,
        collection_address: &str,
        catalog_address: &str,
    ) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            INSERT INTO collection_config (
              chain, collection_address, catalog_address, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(chain, collection_address) DO UPDATE SET
              catalog_address = excluded.catalog_address,
              updated_at = excluded.updated_at
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .bind(catalog_address)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_collection_config(&self, input: &AdminCollectionInput) -> Result<()> {
        let now = now_epoch();
        let approved_until = match input.approved {
            Some(true) => Some(i64::MAX),
            Some(false) => Some(0),
            None => None,
        };
        let approval_source = input.approved.map(|_| "admin");
        sqlx::query(
            r#"
            INSERT INTO collection_config (
              chain, collection_address, og_focal_point, og_overlay_uri,
              watermark_overlay_uri, warmup_strategy, approved, approved_until,
              approval_source, created_at, updated_at
            )
            VALUES (?1, ?2, COALESCE(?3, 25), ?4, ?5, COALESCE(?6, 'auto'), COALESCE(?7, 0), ?8, ?9, ?10, ?11)
            ON CONFLICT(chain, collection_address) DO UPDATE SET
              og_focal_point = COALESCE(excluded.og_focal_point, collection_config.og_focal_point),
              og_overlay_uri = COALESCE(excluded.og_overlay_uri, collection_config.og_overlay_uri),
              watermark_overlay_uri = COALESCE(excluded.watermark_overlay_uri, collection_config.watermark_overlay_uri),
              warmup_strategy = COALESCE(excluded.warmup_strategy, collection_config.warmup_strategy),
              approved = COALESCE(excluded.approved, collection_config.approved),
              approved_until = COALESCE(excluded.approved_until, collection_config.approved_until),
              approval_source = COALESCE(excluded.approval_source, collection_config.approval_source),
              updated_at = excluded.updated_at
            "#,
        )
        .bind(&input.chain)
        .bind(&input.collection_address)
        .bind(input.og_focal_point)
        .bind(&input.og_overlay_uri)
        .bind(&input.watermark_overlay_uri)
        .bind(&input.warmup_strategy)
        .bind(input.approved.map(|value| if value { 1 } else { 0 }))
        .bind(approved_until)
        .bind(approval_source)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_collection(&self, chain: &str, collection_address: &str) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM collection_config WHERE chain = ?1 AND collection_address = ?2
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_canvas_size(
        &self,
        chain: &str,
        collection_address: &str,
        width: i64,
        height: i64,
        fingerprint: &str,
    ) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            UPDATE collection_config
            SET canvas_width = ?1, canvas_height = ?2, canvas_fingerprint = ?3, updated_at = ?4
            WHERE chain = ?5 AND collection_address = ?6
            "#,
        )
        .bind(width)
        .bind(height)
        .bind(fingerprint)
        .bind(now)
        .bind(chain)
        .bind(collection_address)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_collection_approval(
        &self,
        chain: &str,
        collection_address: &str,
        approved_until: i64,
        source: &str,
        last_sync_block: Option<i64>,
    ) -> Result<()> {
        let now = now_epoch();
        let approved = approved_until > now;
        sqlx::query(
            r#"
            INSERT INTO collection_config (
              chain, collection_address, approved, approved_until, approval_source,
              last_approval_sync_at, last_approval_sync_block, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(chain, collection_address) DO UPDATE SET
              approved = excluded.approved,
              approved_until = excluded.approved_until,
              approval_source = excluded.approval_source,
              last_approval_sync_at = excluded.last_approval_sync_at,
              last_approval_sync_block = COALESCE(excluded.last_approval_sync_block, collection_config.last_approval_sync_block),
              updated_at = excluded.updated_at
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .bind(if approved { 1 } else { 0 })
        .bind(approved_until)
        .bind(source)
        .bind(now)
        .bind(last_sync_block)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn record_approval_check(
        &self,
        chain: &str,
        collection_address: &str,
        approved: bool,
    ) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            INSERT INTO collection_config (
              chain, collection_address, approved, approved_until, approval_source,
              last_approval_check_at, last_approval_check_result, created_at, updated_at
            )
            VALUES (?1, ?2, 0, 0, 'on_demand_check', ?3, ?4, ?5, ?6)
            ON CONFLICT(chain, collection_address) DO UPDATE SET
              last_approval_check_at = excluded.last_approval_check_at,
              last_approval_check_result = excluded.last_approval_check_result,
              updated_at = excluded.updated_at
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .bind(now)
        .bind(if approved { 1 } else { 0 })
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_rpc_endpoints(&self, chain: Option<&str>) -> Result<Vec<RpcEndpoint>> {
        let rows = if let Some(chain) = chain {
            sqlx::query(
                r#"
                SELECT chain, url, priority, enabled FROM rpc_endpoints
                WHERE chain = ?1
                ORDER BY priority ASC
                "#,
            )
            .bind(chain)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT chain, url, priority, enabled FROM rpc_endpoints
                ORDER BY chain, priority ASC
                "#,
            )
            .fetch_all(&self.pool)
            .await?
        };
        Ok(rows
            .into_iter()
            .map(|row| RpcEndpoint {
                chain: row.get("chain"),
                url: row.get("url"),
                priority: row.get("priority"),
                enabled: row.get::<i64, _>("enabled") == 1,
            })
            .collect())
    }

    pub async fn replace_rpc_endpoints(
        &self,
        chain: &str,
        endpoints: Vec<RpcEndpoint>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM rpc_endpoints WHERE chain = ?1")
            .bind(chain)
            .execute(&mut *tx)
            .await?;
        for endpoint in endpoints {
            sqlx::query(
                r#"
                INSERT INTO rpc_endpoints (chain, url, priority, enabled)
                VALUES (?1, ?2, ?3, ?4)
                "#,
            )
            .bind(&endpoint.chain)
            .bind(&endpoint.url)
            .bind(endpoint.priority)
            .bind(if endpoint.enabled { 1 } else { 0 })
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn insert_warmup_jobs(&self, jobs: &[WarmupJob]) -> Result<()> {
        let now = now_epoch();
        let mut tx = self.pool.begin().await?;
        for job in jobs {
            sqlx::query(
                r#"
                INSERT INTO warmup_jobs (
                  chain, collection_address, token_id, asset_id, cache_timestamp,
                  widths, include_og, status, last_error, created_at, updated_at
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                "#,
            )
            .bind(&job.chain)
            .bind(&job.collection_address)
            .bind(&job.token_id)
            .bind(&job.asset_id)
            .bind(&job.cache_timestamp)
            .bind(&job.widths)
            .bind(if job.include_og { 1 } else { 0 })
            .bind(&job.status)
            .bind(&job.last_error)
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn fetch_next_warmup_job(&self) -> Result<Option<WarmupJob>> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            r#"
            SELECT id, chain, collection_address, token_id, asset_id, cache_timestamp, widths, include_og, status, last_error
            FROM warmup_jobs
            WHERE status = 'queued'
            ORDER BY id ASC
            LIMIT 1
            "#,
        )
        .fetch_optional(&mut *tx)
        .await?;
        let row = match row {
            Some(row) => row,
            None => {
                tx.commit().await?;
                return Ok(None);
            }
        };
        let id: i64 = row.get("id");
        let updated = sqlx::query(
            r#"
            UPDATE warmup_jobs
            SET status = 'running', updated_at = ?1
            WHERE id = ?2 AND status = 'queued'
            "#,
        )
        .bind(now_epoch())
        .bind(id)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() == 0 {
            tx.commit().await?;
            return Ok(None);
        }
        tx.commit().await?;
        Ok(Some(WarmupJob {
            id,
            chain: row.get("chain"),
            collection_address: row.get("collection_address"),
            token_id: row.get("token_id"),
            asset_id: row.get("asset_id"),
            cache_timestamp: row.get("cache_timestamp"),
            widths: row.get("widths"),
            include_og: row.get::<i64, _>("include_og") == 1,
            status: row.get("status"),
            last_error: row.get("last_error"),
        }))
    }

    pub async fn update_warmup_job_status(
        &self,
        id: i64,
        status: &str,
        last_error: Option<String>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE warmup_jobs
            SET status = ?1, last_error = ?2, updated_at = ?3
            WHERE id = ?4
            "#,
        )
        .bind(status)
        .bind(last_error)
        .bind(now_epoch())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn warmup_stats(&self) -> Result<(i64, i64, i64, i64)> {
        let row = sqlx::query(
            r#"
            SELECT
              SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END) as queued,
              SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running,
              SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END) as done,
              SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed
            FROM warmup_jobs
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok((
            row.get::<i64, _>("queued"),
            row.get::<i64, _>("running"),
            row.get::<i64, _>("done"),
            row.get::<i64, _>("failed"),
        ))
    }

    pub async fn list_warmup_jobs(&self, limit: i64) -> Result<Vec<WarmupJob>> {
        let limit = limit.clamp(1, 500);
        let rows = sqlx::query(
            r#"
            SELECT id, chain, collection_address, token_id, asset_id, cache_timestamp, widths,
                   include_og, status, last_error
            FROM warmup_jobs
            ORDER BY id DESC
            LIMIT ?1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| WarmupJob {
                id: row.get("id"),
                chain: row.get("chain"),
                collection_address: row.get("collection_address"),
                token_id: row.get("token_id"),
                asset_id: row.get("asset_id"),
                cache_timestamp: row.get("cache_timestamp"),
                widths: row.get("widths"),
                include_og: row.get::<i64, _>("include_og") == 1,
                status: row.get("status"),
                last_error: row.get("last_error"),
            })
            .collect())
    }

    pub async fn cancel_warmup_job(&self, id: i64) -> Result<bool> {
        let updated = sqlx::query(
            r#"
            UPDATE warmup_jobs
            SET status = 'canceled', updated_at = ?1
            WHERE id = ?2 AND status IN ('queued', 'running')
            "#,
        )
        .bind(now_epoch())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(updated.rows_affected() > 0)
    }

    pub async fn is_warmup_job_canceled(&self, id: i64) -> Result<bool> {
        let row = sqlx::query("SELECT status FROM warmup_jobs WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(matches!(
            row.and_then(|row| row.get::<Option<String>, _>("status")),
            Some(status) if status == "canceled"
        ))
    }

    pub async fn set_warmup_paused(&self, paused: bool) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE warmup_state SET paused = ?1 WHERE id = 1
            "#,
        )
        .bind(if paused { 1 } else { 0 })
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn is_warmup_paused(&self) -> Result<bool> {
        let row = sqlx::query("SELECT paused FROM warmup_state WHERE id = 1")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>("paused") == 1)
    }

    pub async fn upsert_catalog_warmup_job(
        &self,
        chain: &str,
        collection_address: &str,
        catalog_address: &str,
        status: &str,
        last_error: Option<&str>,
    ) -> Result<i64> {
        let now = now_epoch();
        sqlx::query(
            r#"
            INSERT INTO catalog_warmup_jobs (
              chain, collection_address, catalog_address, status, last_error, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(chain, collection_address) DO UPDATE SET
              catalog_address = excluded.catalog_address,
              status = excluded.status,
              last_error = excluded.last_error,
              updated_at = excluded.updated_at
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .bind(catalog_address)
        .bind(status)
        .bind(last_error)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        let row = sqlx::query(
            r#"
            SELECT id
            FROM catalog_warmup_jobs
            WHERE chain = ?1 AND collection_address = ?2
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get("id"))
    }

    pub async fn get_catalog_warmup_job(
        &self,
        chain: &str,
        collection_address: &str,
    ) -> Result<Option<(i64, String, String, Option<String>)>> {
        let row = sqlx::query(
            r#"
            SELECT id, catalog_address, status, last_error
            FROM catalog_warmup_jobs
            WHERE chain = ?1 AND collection_address = ?2
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| {
            (
                row.get("id"),
                row.get("catalog_address"),
                row.get("status"),
                row.get("last_error"),
            )
        }))
    }

    pub async fn clear_catalog_warmup_items(&self, job_id: i64) -> Result<()> {
        sqlx::query("DELETE FROM catalog_warmup_items WHERE job_id = ?1")
            .bind(job_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn insert_catalog_warmup_items(
        &self,
        job_id: i64,
        items: &[(String, String)],
    ) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let now = now_epoch();
        let mut tx = self.pool.begin().await?;
        for (part_id, metadata_uri) in items {
            sqlx::query(
                r#"
                INSERT OR IGNORE INTO catalog_warmup_items (
                  job_id, part_id, metadata_uri, status, created_at, updated_at
                )
                VALUES (?1, ?2, ?3, 'queued', ?4, ?5)
                "#,
            )
            .bind(job_id)
            .bind(part_id)
            .bind(metadata_uri)
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn fetch_next_catalog_warmup_item(&self) -> Result<Option<CatalogWarmupItem>> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            r#"
            SELECT i.id, i.job_id, j.chain, j.collection_address, i.part_id, i.metadata_uri,
                   i.status, i.attempts, i.last_error
            FROM catalog_warmup_items i
            JOIN catalog_warmup_jobs j ON i.job_id = j.id
            WHERE i.status = 'queued'
            ORDER BY i.id ASC
            LIMIT 1
            "#,
        )
        .fetch_optional(&mut *tx)
        .await?;
        let row = match row {
            Some(row) => row,
            None => {
                tx.commit().await?;
                return Ok(None);
            }
        };
        let id: i64 = row.get("id");
        let attempts: i64 = row.get("attempts");
        let now = now_epoch();
        sqlx::query(
            r#"
            UPDATE catalog_warmup_items
            SET status = 'running', attempts = ?1, updated_at = ?2
            WHERE id = ?3
            "#,
        )
        .bind(attempts + 1)
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(CatalogWarmupItem {
            id,
            job_id: row.get("job_id"),
            chain: row.get("chain"),
            collection_address: row.get("collection_address"),
            part_id: row.get("part_id"),
            metadata_uri: row.get("metadata_uri"),
            status: "running".to_string(),
            attempts: attempts + 1,
            last_error: row.get("last_error"),
        }))
    }

    pub async fn update_catalog_warmup_item_status(
        &self,
        id: i64,
        status: &str,
        last_error: Option<&str>,
    ) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            UPDATE catalog_warmup_items
            SET status = ?1, last_error = ?2, updated_at = ?3
            WHERE id = ?4
            "#,
        )
        .bind(status)
        .bind(last_error)
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn catalog_warmup_item_counts(
        &self,
        job_id: i64,
    ) -> Result<(i64, i64, i64, i64, i64)> {
        let row = sqlx::query(
            r#"
            SELECT
              SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END) AS queued,
              SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running,
              SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END) AS done,
              SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
              COUNT(1) AS total
            FROM catalog_warmup_items
            WHERE job_id = ?1
            "#,
        )
        .bind(job_id)
        .fetch_one(&self.pool)
        .await?;
        Ok((
            row.get::<Option<i64>, _>("queued").unwrap_or(0),
            row.get::<Option<i64>, _>("running").unwrap_or(0),
            row.get::<Option<i64>, _>("done").unwrap_or(0),
            row.get::<Option<i64>, _>("failed").unwrap_or(0),
            row.get::<Option<i64>, _>("total").unwrap_or(0),
        ))
    }

    pub async fn set_catalog_warmup_job_status(
        &self,
        job_id: i64,
        status: &str,
        last_error: Option<&str>,
    ) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            UPDATE catalog_warmup_jobs
            SET status = ?1, last_error = ?2, updated_at = ?3
            WHERE id = ?4
            "#,
        )
        .bind(status)
        .bind(last_error)
        .bind(now)
        .bind(job_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_token_warmup_job(
        &self,
        chain: &str,
        collection_address: &str,
        asset_id: Option<&str>,
        status: &str,
        last_error: Option<&str>,
    ) -> Result<i64> {
        let now = now_epoch();
        sqlx::query(
            r#"
            INSERT INTO token_warmup_jobs (
              chain, collection_address, asset_id, status, last_error, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(chain, collection_address) DO UPDATE SET
              asset_id = COALESCE(excluded.asset_id, token_warmup_jobs.asset_id),
              status = excluded.status,
              last_error = excluded.last_error,
              updated_at = excluded.updated_at
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .bind(asset_id)
        .bind(status)
        .bind(last_error)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        let row = sqlx::query(
            r#"
            SELECT id
            FROM token_warmup_jobs
            WHERE chain = ?1 AND collection_address = ?2
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get("id"))
    }

    pub async fn get_token_warmup_job(
        &self,
        chain: &str,
        collection_address: &str,
    ) -> Result<Option<(i64, Option<String>, String, Option<String>)>> {
        let row = sqlx::query(
            r#"
            SELECT id, asset_id, status, last_error
            FROM token_warmup_jobs
            WHERE chain = ?1 AND collection_address = ?2
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| {
            (
                row.get("id"),
                row.get("asset_id"),
                row.get("status"),
                row.get("last_error"),
            )
        }))
    }

    pub async fn clear_token_warmup_items(&self, job_id: i64) -> Result<()> {
        sqlx::query("DELETE FROM token_warmup_items WHERE job_id = ?1")
            .bind(job_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn mark_token_warmup_invalid_uris_done(&self, job_id: i64) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            UPDATE token_warmup_items
            SET status = 'done', last_error = NULL, updated_at = ?1
            WHERE job_id = ?2
              AND status = 'failed'
              AND last_error LIKE '%invalid asset uri%'
            "#,
        )
        .bind(now)
        .bind(job_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert_token_warmup_items(&self, job_id: i64, tokens: &[String]) -> Result<()> {
        if tokens.is_empty() {
            return Ok(());
        }
        let now = now_epoch();
        let mut tx = self.pool.begin().await?;
        for token_id in tokens {
            sqlx::query(
                r#"
                INSERT OR IGNORE INTO token_warmup_items (
                  job_id, token_id, status, created_at, updated_at
                )
                VALUES (?1, ?2, 'queued', ?3, ?4)
                "#,
            )
            .bind(job_id)
            .bind(token_id)
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn fetch_next_token_warmup_item(&self) -> Result<Option<TokenWarmupItem>> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            r#"
            SELECT i.id, i.job_id, j.chain, j.collection_address, i.token_id,
                   j.asset_id, i.status, i.attempts, i.last_error
            FROM token_warmup_items i
            JOIN token_warmup_jobs j ON i.job_id = j.id
            WHERE i.status = 'queued'
            ORDER BY i.id ASC
            LIMIT 1
            "#,
        )
        .fetch_optional(&mut *tx)
        .await?;
        let row = match row {
            Some(row) => row,
            None => {
                tx.commit().await?;
                return Ok(None);
            }
        };
        let id: i64 = row.get("id");
        let attempts: i64 = row.get("attempts");
        let now = now_epoch();
        sqlx::query(
            r#"
            UPDATE token_warmup_items
            SET status = 'running', attempts = ?1, updated_at = ?2
            WHERE id = ?3
            "#,
        )
        .bind(attempts + 1)
        .bind(now)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(TokenWarmupItem {
            id,
            job_id: row.get("job_id"),
            chain: row.get("chain"),
            collection_address: row.get("collection_address"),
            token_id: row.get("token_id"),
            asset_id: row.get("asset_id"),
            status: "running".to_string(),
            attempts: attempts + 1,
            last_error: row.get("last_error"),
        }))
    }

    pub async fn update_token_warmup_item_status(
        &self,
        id: i64,
        status: &str,
        last_error: Option<&str>,
    ) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            UPDATE token_warmup_items
            SET status = ?1, last_error = ?2, updated_at = ?3
            WHERE id = ?4
            "#,
        )
        .bind(status)
        .bind(last_error)
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn token_warmup_item_counts(&self, job_id: i64) -> Result<(i64, i64, i64, i64, i64)> {
        let row = sqlx::query(
            r#"
            SELECT
              SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END) AS queued,
              SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running,
              SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END) AS done,
              SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
              COUNT(1) AS total
            FROM token_warmup_items
            WHERE job_id = ?1
            "#,
        )
        .bind(job_id)
        .fetch_one(&self.pool)
        .await?;
        Ok((
            row.get::<Option<i64>, _>("queued").unwrap_or(0),
            row.get::<Option<i64>, _>("running").unwrap_or(0),
            row.get::<Option<i64>, _>("done").unwrap_or(0),
            row.get::<Option<i64>, _>("failed").unwrap_or(0),
            row.get::<Option<i64>, _>("total").unwrap_or(0),
        ))
    }

    pub async fn set_token_warmup_job_status(
        &self,
        job_id: i64,
        status: &str,
        last_error: Option<&str>,
    ) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            UPDATE token_warmup_jobs
            SET status = ?1, last_error = ?2, updated_at = ?3
            WHERE id = ?4
            "#,
        )
        .bind(status)
        .bind(last_error)
        .bind(now)
        .bind(job_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_collection_asset_ref(
        &self,
        chain: &str,
        collection_address: &str,
        asset_key: &str,
        source: &str,
        part_id: Option<&str>,
    ) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO collection_asset_refs (
              chain, collection_address, asset_key, source, part_id, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .bind(asset_key)
        .bind(source)
        .bind(part_id)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn clear_collection_asset_refs(
        &self,
        chain: &str,
        collection_address: &str,
        source: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM collection_asset_refs
            WHERE chain = ?1 AND collection_address = ?2 AND source = ?3
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .bind(source)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn catalog_asset_counts(
        &self,
        chain: &str,
        collection_address: &str,
    ) -> Result<(i64, i64, i64)> {
        let total_row = sqlx::query(
            r#"
            SELECT COUNT(DISTINCT asset_key) AS total
            FROM collection_asset_refs
            WHERE chain = ?1 AND collection_address = ?2 AND source = 'catalog_asset'
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .fetch_one(&self.pool)
        .await?;
        let total = total_row.get::<Option<i64>, _>("total").unwrap_or(0);

        let pinned_row = sqlx::query(
            r#"
            SELECT COUNT(DISTINCT refs.asset_key) AS count
            FROM collection_asset_refs refs
            JOIN pinned_assets pinned ON refs.asset_key = pinned.asset_key
            WHERE refs.chain = ?1
              AND refs.collection_address = ?2
              AND refs.source = 'catalog_asset'
              AND pinned.status = 'pinned'
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .fetch_one(&self.pool)
        .await?;
        let pinned = pinned_row.get::<Option<i64>, _>("count").unwrap_or(0);

        let failed_row = sqlx::query(
            r#"
            SELECT COUNT(DISTINCT refs.asset_key) AS count
            FROM collection_asset_refs refs
            JOIN pinned_assets pinned ON refs.asset_key = pinned.asset_key
            WHERE refs.chain = ?1
              AND refs.collection_address = ?2
              AND refs.source = 'catalog_asset'
              AND pinned.status = 'failed'
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .fetch_one(&self.pool)
        .await?;
        let failed = failed_row.get::<Option<i64>, _>("count").unwrap_or(0);

        Ok((total, pinned, failed))
    }

    pub async fn upsert_token_asset_ref(
        &self,
        chain: &str,
        collection_address: &str,
        token_id: &str,
        asset_key: &str,
        source: &str,
    ) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO token_asset_refs (
              chain, collection_address, token_id, asset_key, source, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .bind(token_id)
        .bind(asset_key)
        .bind(source)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn clear_token_asset_refs_for_tokens(
        &self,
        chain: &str,
        collection_address: &str,
        token_ids: &[String],
    ) -> Result<()> {
        if token_ids.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for token_id in token_ids {
            sqlx::query(
                r#"
                DELETE FROM token_asset_refs
                WHERE chain = ?1 AND collection_address = ?2 AND token_id = ?3
                "#,
            )
            .bind(chain)
            .bind(collection_address)
            .bind(token_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn token_asset_counts(
        &self,
        chain: &str,
        collection_address: &str,
    ) -> Result<(i64, i64, i64)> {
        let total_row = sqlx::query(
            r#"
            SELECT COUNT(DISTINCT asset_key) AS total
            FROM token_asset_refs
            WHERE chain = ?1 AND collection_address = ?2
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .fetch_one(&self.pool)
        .await?;
        let total = total_row.get::<Option<i64>, _>("total").unwrap_or(0);

        let pinned_row = sqlx::query(
            r#"
            SELECT COUNT(DISTINCT refs.asset_key) AS count
            FROM token_asset_refs refs
            JOIN pinned_assets pinned ON refs.asset_key = pinned.asset_key
            WHERE refs.chain = ?1
              AND refs.collection_address = ?2
              AND pinned.status = 'pinned'
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .fetch_one(&self.pool)
        .await?;
        let pinned = pinned_row.get::<Option<i64>, _>("count").unwrap_or(0);

        let failed_row = sqlx::query(
            r#"
            SELECT COUNT(DISTINCT refs.asset_key) AS count
            FROM token_asset_refs refs
            JOIN pinned_assets pinned ON refs.asset_key = pinned.asset_key
            WHERE refs.chain = ?1
              AND refs.collection_address = ?2
              AND pinned.status = 'failed'
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .fetch_one(&self.pool)
        .await?;
        let failed = failed_row.get::<Option<i64>, _>("count").unwrap_or(0);

        Ok((total, pinned, failed))
    }

    pub async fn get_token_state(
        &self,
        chain: &str,
        collection_address: &str,
        token_id: &str,
        asset_id: &str,
    ) -> Result<Option<TokenStateCacheEntry>> {
        let row = sqlx::query(
            r#"
            SELECT chain, collection_address, token_id, asset_id, state_hash, state_json,
                   last_checked_at, last_checked_block, expires_at, fallback_used, last_error
            FROM token_state_cache
            WHERE chain = ?1 AND collection_address = ?2 AND token_id = ?3 AND asset_id = ?4
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .bind(token_id)
        .bind(asset_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| TokenStateCacheEntry {
            chain: row.get("chain"),
            collection_address: row.get("collection_address"),
            token_id: row.get("token_id"),
            asset_id: row.get("asset_id"),
            state_hash: row.get("state_hash"),
            state_json: row.get("state_json"),
            last_checked_at: row.get("last_checked_at"),
            last_checked_block: row.get("last_checked_block"),
            expires_at: row.get("expires_at"),
            fallback_used: row.get::<i64, _>("fallback_used") == 1,
            last_error: row.get("last_error"),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_token_state(
        &self,
        chain: &str,
        collection_address: &str,
        token_id: &str,
        asset_id: &str,
        state_hash: &str,
        state_json: Option<&str>,
        last_checked_block: Option<i64>,
        expires_at: i64,
        fallback_used: bool,
    ) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            INSERT INTO token_state_cache (
              chain, collection_address, token_id, asset_id, state_hash, state_json,
              last_checked_at, last_checked_block, expires_at, fallback_used, last_error
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL)
            ON CONFLICT(chain, collection_address, token_id, asset_id) DO UPDATE SET
              state_hash = excluded.state_hash,
              state_json = excluded.state_json,
              last_checked_at = excluded.last_checked_at,
              last_checked_block = COALESCE(excluded.last_checked_block, token_state_cache.last_checked_block),
              expires_at = excluded.expires_at,
              fallback_used = excluded.fallback_used,
              last_error = NULL
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .bind(token_id)
        .bind(asset_id)
        .bind(state_hash)
        .bind(state_json)
        .bind(now)
        .bind(last_checked_block)
        .bind(expires_at)
        .bind(if fallback_used { 1 } else { 0 })
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn record_token_state_error(
        &self,
        chain: &str,
        collection_address: &str,
        token_id: &str,
        asset_id: &str,
        error: &str,
        expires_at: i64,
    ) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            INSERT INTO token_state_cache (
              chain, collection_address, token_id, asset_id, state_hash, state_json,
              last_checked_at, expires_at, last_error
            )
            VALUES (?1, ?2, ?3, ?4, '', NULL, ?5, ?6, ?7)
            ON CONFLICT(chain, collection_address, token_id, asset_id) DO UPDATE SET
              last_checked_at = excluded.last_checked_at,
              expires_at = excluded.expires_at,
              last_error = excluded.last_error
            "#,
        )
        .bind(chain)
        .bind(collection_address)
        .bind(token_id)
        .bind(asset_id)
        .bind(now)
        .bind(expires_at)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn check_fresh_request(
        &self,
        key: &str,
        cooldown_seconds: u64,
    ) -> Result<FreshLimitResult> {
        if cooldown_seconds == 0 {
            return Ok(FreshLimitResult {
                allowed: true,
                retry_after_seconds: None,
            });
        }
        let now = now_epoch();
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT last_refresh_at FROM fresh_requests WHERE key = ?1")
            .bind(key)
            .fetch_optional(&mut *tx)
            .await?;
        if let Some(row) = row {
            let last_refresh_at: i64 = row.get("last_refresh_at");
            let earliest = last_refresh_at.saturating_add(cooldown_seconds as i64);
            if now < earliest {
                tx.commit().await?;
                let retry_after = (earliest - now).max(1) as u64;
                return Ok(FreshLimitResult {
                    allowed: false,
                    retry_after_seconds: Some(retry_after),
                });
            }
        }
        sqlx::query(
            r#"
            INSERT INTO fresh_requests (key, last_refresh_at)
            VALUES (?1, ?2)
            ON CONFLICT(key) DO UPDATE SET last_refresh_at = excluded.last_refresh_at
            "#,
        )
        .bind(key)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(FreshLimitResult {
            allowed: true,
            retry_after_seconds: None,
        })
    }

    pub async fn get_approval_last_block(&self, chain: &str) -> Result<Option<i64>> {
        let row = sqlx::query("SELECT last_block FROM approval_state WHERE chain = ?1")
            .bind(chain)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| row.get::<i64, _>("last_block")))
    }

    pub async fn set_approval_last_block(&self, chain: &str, block: i64) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO approval_state (chain, last_block)
            VALUES (?1, ?2)
            ON CONFLICT(chain) DO UPDATE SET last_block = excluded.last_block
            "#,
        )
        .bind(chain)
        .bind(block)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn create_client(&self, name: &str, notes: Option<&str>) -> Result<i64> {
        let now = now_epoch();
        let result = sqlx::query(
            r#"
            INSERT INTO clients (name, notes, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4)
            "#,
        )
        .bind(name)
        .bind(notes)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn list_clients(&self) -> Result<Vec<Client>> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, notes, created_at, updated_at
            FROM clients
            ORDER BY id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| Client {
                id: row.get("id"),
                name: row.get("name"),
                notes: row.get("notes"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })
            .collect())
    }

    pub async fn update_client(&self, id: i64, name: &str, notes: Option<&str>) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            UPDATE clients
            SET name = ?1, notes = ?2, updated_at = ?3
            WHERE id = ?4
            "#,
        )
        .bind(name)
        .bind(notes)
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_client(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM client_keys WHERE client_id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM clients WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_client_key(
        &self,
        client_id: i64,
        key_hash: &str,
        key_prefix: &str,
        rate_limit_per_minute: Option<i64>,
        burst: Option<i64>,
        max_concurrent_renders_override: Option<i64>,
        allow_fresh: bool,
    ) -> Result<i64> {
        let now = now_epoch();
        let result = sqlx::query(
            r#"
            INSERT INTO client_keys (
              client_id, key_hash, key_prefix, active, rate_limit_per_minute, burst,
              max_concurrent_renders_override, allow_fresh, created_at
            )
            VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?7, ?8)
            "#,
        )
        .bind(client_id)
        .bind(key_hash)
        .bind(key_prefix)
        .bind(rate_limit_per_minute)
        .bind(burst)
        .bind(max_concurrent_renders_override)
        .bind(if allow_fresh { 1 } else { 0 })
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn list_client_keys(&self, client_id: i64) -> Result<Vec<ClientKey>> {
        let rows = sqlx::query(
            r#"
            SELECT id, client_id, key_prefix, active, rate_limit_per_minute, burst,
                   max_concurrent_renders_override, allow_fresh, created_at, revoked_at
            FROM client_keys
            WHERE client_id = ?1
            ORDER BY id ASC
            "#,
        )
        .bind(client_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| ClientKey {
                id: row.get("id"),
                client_id: row.get("client_id"),
                key_prefix: row.get("key_prefix"),
                active: row.get::<i64, _>("active") == 1,
                rate_limit_per_minute: row.get("rate_limit_per_minute"),
                burst: row.get("burst"),
                max_concurrent_renders_override: row.get("max_concurrent_renders_override"),
                allow_fresh: row.get::<i64, _>("allow_fresh") == 1,
                created_at: row.get("created_at"),
                revoked_at: row.get("revoked_at"),
            })
            .collect())
    }

    pub async fn revoke_client_key(&self, key_id: i64) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            UPDATE client_keys
            SET active = 0, revoked_at = ?1
            WHERE id = ?2
            "#,
        )
        .bind(now)
        .bind(key_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn find_client_key_by_hash(&self, key_hash: &str) -> Result<Option<ClientKey>> {
        let row = sqlx::query(
            r#"
            SELECT id, client_id, key_prefix, active, rate_limit_per_minute, burst,
                   max_concurrent_renders_override, allow_fresh, created_at, revoked_at
            FROM client_keys
            WHERE key_hash = ?1
            "#,
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| ClientKey {
            id: row.get("id"),
            client_id: row.get("client_id"),
            key_prefix: row.get("key_prefix"),
            active: row.get::<i64, _>("active") == 1,
            rate_limit_per_minute: row.get("rate_limit_per_minute"),
            burst: row.get("burst"),
            max_concurrent_renders_override: row.get("max_concurrent_renders_override"),
            allow_fresh: row.get::<i64, _>("allow_fresh") == 1,
            created_at: row.get("created_at"),
            revoked_at: row.get("revoked_at"),
        }))
    }

    pub async fn list_ip_rules(&self) -> Result<Vec<IpRule>> {
        let rows = sqlx::query(
            r#"
            SELECT id, ip_cidr, mode, created_at
            FROM client_ip_rules
            ORDER BY id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| IpRule {
                id: row.get("id"),
                ip_cidr: row.get("ip_cidr"),
                mode: row.get("mode"),
                created_at: row.get("created_at"),
            })
            .collect())
    }

    pub async fn create_ip_rule(&self, ip_cidr: &str, mode: &str) -> Result<i64> {
        let now = now_epoch();
        let result = sqlx::query(
            r#"
            INSERT INTO client_ip_rules (ip_cidr, mode, created_at)
            VALUES (?1, ?2, ?3)
            "#,
        )
        .bind(ip_cidr)
        .bind(mode)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn delete_ip_rule(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM client_ip_rules WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn record_usage_batch(&self, rows: &[UsageBatchRow]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for row in rows {
            sqlx::query(
                r#"
                INSERT INTO client_usage_hourly (
                  hour_bucket, identity_key, route_group,
                  requests, bytes_out, cache_hits, cache_misses
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(hour_bucket, identity_key, route_group)
                DO UPDATE SET
                  requests = client_usage_hourly.requests + excluded.requests,
                  bytes_out = client_usage_hourly.bytes_out + excluded.bytes_out,
                  cache_hits = client_usage_hourly.cache_hits + excluded.cache_hits,
                  cache_misses = client_usage_hourly.cache_misses + excluded.cache_misses
                "#,
            )
            .bind(row.hour_bucket)
            .bind(&row.identity_key)
            .bind(&row.route_group)
            .bind(row.requests)
            .bind(row.bytes_out)
            .bind(row.cache_hits)
            .bind(row.cache_misses)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn list_usage(&self, hours: i64) -> Result<Vec<UsageRow>> {
        let cutoff = now_epoch().saturating_sub(hours.saturating_mul(3600));
        let rows = sqlx::query(
            r#"
            SELECT hour_bucket, identity_key, route_group,
                   requests, bytes_out, cache_hits, cache_misses
            FROM client_usage_hourly
            WHERE hour_bucket >= ?1
            ORDER BY hour_bucket DESC, identity_key
            "#,
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| UsageRow {
                hour_bucket: row.get("hour_bucket"),
                identity_key: row.get("identity_key"),
                route_group: row.get("route_group"),
                requests: row.get("requests"),
                bytes_out: row.get("bytes_out"),
                cache_hits: row.get("cache_hits"),
                cache_misses: row.get("cache_misses"),
            })
            .collect())
    }

    pub async fn prune_usage(&self, retention_days: u64) -> Result<u64> {
        if retention_days == 0 {
            return Ok(0);
        }
        let cutoff_seconds = retention_days
            .saturating_mul(24 * 3600)
            .min(i64::MAX as u64) as i64;
        let cutoff = now_epoch().saturating_sub(cutoff_seconds);
        let cutoff = cutoff / 3600 * 3600;
        let result = sqlx::query(
            r#"
            DELETE FROM client_usage_hourly
            WHERE hour_bucket < ?1
            "#,
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn insert_approval_quarantine(
        &self,
        watcher_chain: &str,
        chain_id: u64,
        collection_address: &str,
        payer: &str,
        amount: &str,
    ) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            INSERT INTO approval_quarantine (
              watcher_chain, chain_id, collection_address, payer, amount, created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
        )
        .bind(watcher_chain)
        .bind(chain_id as i64)
        .bind(collection_address)
        .bind(payer)
        .bind(amount)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_pinned_asset(
        &self,
        asset_key: &str,
        cid: &str,
        path: &str,
        content_type: Option<&str>,
        size_bytes: i64,
    ) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            INSERT INTO pinned_assets (
              asset_key, cid, path, content_type, size_bytes, status, attempts,
              last_error, first_seen_at, pinned_at, last_attempt_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, 'pinned', 1, NULL, ?6, ?7, ?8)
            ON CONFLICT(asset_key) DO UPDATE SET
              cid = excluded.cid,
              path = excluded.path,
              content_type = COALESCE(excluded.content_type, pinned_assets.content_type),
              size_bytes = COALESCE(excluded.size_bytes, pinned_assets.size_bytes),
              status = excluded.status,
              attempts = pinned_assets.attempts + 1,
              last_error = NULL,
              first_seen_at = COALESCE(pinned_assets.first_seen_at, excluded.first_seen_at),
              pinned_at = COALESCE(pinned_assets.pinned_at, excluded.pinned_at),
              last_attempt_at = excluded.last_attempt_at
            "#,
        )
        .bind(asset_key)
        .bind(cid)
        .bind(path)
        .bind(content_type)
        .bind(size_bytes)
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn record_pinned_asset_failure(
        &self,
        asset_key: &str,
        cid: &str,
        path: &str,
        error: &str,
    ) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            INSERT INTO pinned_assets (
              asset_key, cid, path, status, attempts, last_error, first_seen_at, last_attempt_at
            )
            VALUES (?1, ?2, ?3, 'failed', 1, ?4, ?5, ?6)
            ON CONFLICT(asset_key) DO UPDATE SET
              cid = excluded.cid,
              path = excluded.path,
              status = 'failed',
              attempts = pinned_assets.attempts + 1,
              last_error = excluded.last_error,
              first_seen_at = COALESCE(pinned_assets.first_seen_at, excluded.first_seen_at),
              last_attempt_at = excluded.last_attempt_at
            "#,
        )
        .bind(asset_key)
        .bind(cid)
        .bind(path)
        .bind(error)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn pinned_asset_counts(&self) -> Result<PinnedAssetCounts> {
        let row = sqlx::query(
            r#"
            SELECT
              COALESCE(SUM(CASE WHEN status = 'pinned' THEN 1 ELSE 0 END), 0) as pinned,
              COALESCE(SUM(CASE WHEN status = 'missing' THEN 1 ELSE 0 END), 0) as missing,
              COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) as failed,
              COUNT(*) as total
            FROM pinned_assets
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(PinnedAssetCounts {
            pinned: row.get::<i64, _>("pinned"),
            missing: row.get::<i64, _>("missing"),
            failed: row.get::<i64, _>("failed"),
            total: row.get::<i64, _>("total"),
        })
    }

    pub async fn list_hash_replacements(&self) -> Result<Vec<HashReplacement>> {
        let rows = sqlx::query(
            r#"
            SELECT cid, content_type, file_path, created_at, updated_at
            FROM hash_replacements
            ORDER BY cid ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| HashReplacement {
                cid: row.get::<String, _>("cid"),
                content_type: row.get::<String, _>("content_type"),
                file_path: row.get::<String, _>("file_path"),
                created_at: row.get::<i64, _>("created_at"),
                updated_at: row.get::<i64, _>("updated_at"),
            })
            .collect())
    }

    pub async fn get_hash_replacement(&self, cid: &str) -> Result<Option<HashReplacement>> {
        let row = sqlx::query(
            r#"
            SELECT cid, content_type, file_path, created_at, updated_at
            FROM hash_replacements
            WHERE cid = ?1
            "#,
        )
        .bind(cid)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| HashReplacement {
            cid: row.get::<String, _>("cid"),
            content_type: row.get::<String, _>("content_type"),
            file_path: row.get::<String, _>("file_path"),
            created_at: row.get::<i64, _>("created_at"),
            updated_at: row.get::<i64, _>("updated_at"),
        }))
    }

    pub async fn upsert_hash_replacement(
        &self,
        cid: &str,
        content_type: &str,
        file_path: &str,
    ) -> Result<()> {
        let now = now_epoch();
        sqlx::query(
            r#"
            INSERT INTO hash_replacements (cid, content_type, file_path, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(cid) DO UPDATE SET
              content_type = excluded.content_type,
              file_path = excluded.file_path,
              updated_at = excluded.updated_at
            "#,
        )
        .bind(cid)
        .bind(content_type)
        .bind(file_path)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_hash_replacement(&self, cid: &str) -> Result<Option<HashReplacement>> {
        let existing = self.get_hash_replacement(cid).await?;
        if existing.is_none() {
            return Ok(None);
        }
        sqlx::query("DELETE FROM hash_replacements WHERE cid = ?1")
            .bind(cid)
            .execute(&self.pool)
            .await?;
        Ok(existing)
    }

    pub async fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM renderer_settings WHERE key = ?1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| row.get::<String, _>("value")))
    }

    pub async fn set_setting(&self, key: &str, value: Option<&str>) -> Result<()> {
        if let Some(value) = value {
            sqlx::query(
                r#"
                INSERT INTO renderer_settings (key, value)
                VALUES (?1, ?2)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                "#,
            )
            .bind(key)
            .bind(value)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query("DELETE FROM renderer_settings WHERE key = ?1")
                .bind(key)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    pub async fn get_setting_bool(&self, key: &str) -> Result<Option<bool>> {
        let value = self.get_setting(key).await?;
        Ok(value.map(|value| value == "true" || value == "1"))
    }
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{ComposeResult, FixedPart, SlotPart};
    use crate::config::{Config, RasterMismatchPolicy, RenderPolicy};
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn test_config(path: PathBuf) -> Config {
        Config {
            host: "127.0.0.1".to_string(),
            port: 8080,
            admin_password: "secret".to_string(),
            db_path: path,
            cache_dir: PathBuf::from("cache"),
            pinning_enabled: false,
            pinned_dir: PathBuf::from("pinned"),
            local_ipfs_enabled: false,
            local_ipfs_bind: "127.0.0.1".to_string(),
            local_ipfs_port: 18180,
            cache_max_size_bytes: 0,
            render_cache_min_ttl: std::time::Duration::from_secs(0),
            asset_cache_min_ttl: std::time::Duration::from_secs(0),
            cache_touch_interval: std::time::Duration::from_secs(0),
            cache_evict_interval: std::time::Duration::from_secs(0),
            max_concurrent_renders: 1,
            max_concurrent_ipfs_fetches: 1,
            max_concurrent_rpc_calls: 1,
            default_canvas_width: 1,
            default_canvas_height: 1,
            default_cache_timestamp: None,
            default_cache_ttl: std::time::Duration::from_secs(0),
            rpc_endpoints: std::collections::HashMap::new(),
            render_utils_addresses: std::collections::HashMap::new(),
            approval_contracts: std::collections::HashMap::new(),
            approval_start_blocks: std::collections::HashMap::new(),
            approval_poll_interval_seconds: 30,
            approval_confirmations: 0,
            chain_id_map: std::collections::HashMap::new(),
            approval_sync_interval_seconds: 900,
            approval_negative_cache_seconds: 0,
            approval_negative_cache_capacity: 0,
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
            rate_limit_per_minute: 0,
            rate_limit_burst: 0,
            auth_failure_rate_limit_per_minute: 0,
            auth_failure_rate_limit_burst: 0,
            access_mode: crate::config::AccessMode::Open,
            api_key_secret: None,
            key_rate_limit_per_minute: 0,
            key_rate_limit_burst: 0,
            api_key_cache_ttl: std::time::Duration::from_secs(0),
            api_key_cache_capacity: 0,
            track_keys_in_open_mode: false,
            trusted_proxies: Vec::new(),
            usage_tracking_enabled: true,
            usage_sample_rate: 1.0,
            usage_channel_capacity: 1,
            usage_flush_interval: std::time::Duration::from_secs(1),
            usage_flush_max_entries: 1,
            usage_retention_days: 30,
            render_queue_capacity: 1,
            render_layer_concurrency: 1,
            composite_cache_enabled: false,
            cache_size_refresh_interval: std::time::Duration::from_secs(1),
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
            primary_asset_cache_ttl: std::time::Duration::from_secs(0),
            primary_asset_negative_ttl: std::time::Duration::from_secs(0),
            primary_asset_cache_capacity: 0,
            outbound_client_cache_ttl: std::time::Duration::from_secs(0),
            outbound_client_cache_capacity: 0,
            openapi_public: true,
            render_policy: RenderPolicy {
                raster_mismatch_fixed: RasterMismatchPolicy::TopLeftNoScale,
                raster_mismatch_child: RasterMismatchPolicy::TopLeftNoScale,
            },
            collection_render_overrides: std::collections::HashMap::new(),
            status_public: false,
            landing_public: false,
            landing: None,
        }
    }

    #[tokio::test]
    async fn settings_roundtrip() {
        let dir = tempdir().unwrap();
        let config = test_config(dir.path().join("renderer.db"));
        let db = Database::new(&config).await.unwrap();

        db.set_setting("require_approval", Some("true"))
            .await
            .unwrap();
        assert_eq!(
            db.get_setting_bool("require_approval").await.unwrap(),
            Some(true)
        );

        db.set_setting("require_approval", None).await.unwrap();
        assert_eq!(db.get_setting_bool("require_approval").await.unwrap(), None);
    }

    #[tokio::test]
    async fn warmup_job_roundtrip() {
        let dir = tempdir().unwrap();
        let config = test_config(dir.path().join("renderer.db"));
        let db = Database::new(&config).await.unwrap();

        let job = WarmupJob {
            id: 0,
            chain: "base".to_string(),
            collection_address: "0xabc".to_string(),
            token_id: "1".to_string(),
            asset_id: Some("10".to_string()),
            cache_timestamp: Some("123".to_string()),
            widths: Some("medium,large".to_string()),
            include_og: true,
            status: "queued".to_string(),
            last_error: None,
        };
        db.insert_warmup_jobs(&[job]).await.unwrap();
        let next = db.fetch_next_warmup_job().await.unwrap().unwrap();
        assert_eq!(next.token_id, "1");
        assert_eq!(next.widths.as_deref(), Some("medium,large"));
        assert!(next.include_og);
    }

    #[tokio::test]
    async fn catalog_warmup_roundtrip() {
        let dir = tempdir().unwrap();
        let config = test_config(dir.path().join("renderer.db"));
        let db = Database::new(&config).await.unwrap();

        let job_id = db
            .upsert_catalog_warmup_job("base", "0xabc", "0xdef", "queued", None)
            .await
            .unwrap();
        db.insert_catalog_warmup_items(
            job_id,
            &[
                ("1".to_string(), "ipfs://cid/part1.json".to_string()),
                ("2".to_string(), "ipfs://cid/part2.json".to_string()),
            ],
        )
        .await
        .unwrap();

        let (queued, running, done, failed, total) =
            db.catalog_warmup_item_counts(job_id).await.unwrap();
        assert_eq!(queued, 2);
        assert_eq!(running, 0);
        assert_eq!(done, 0);
        assert_eq!(failed, 0);
        assert_eq!(total, 2);

        let first = db.fetch_next_catalog_warmup_item().await.unwrap().unwrap();
        assert_eq!(first.part_id, "1");
        assert_eq!(first.attempts, 1);
        db.update_catalog_warmup_item_status(first.id, "done", None)
            .await
            .unwrap();

        let second = db.fetch_next_catalog_warmup_item().await.unwrap().unwrap();
        assert_eq!(second.part_id, "2");
        db.update_catalog_warmup_item_status(second.id, "failed", Some("boom"))
            .await
            .unwrap();

        let (queued, running, done, failed, total) =
            db.catalog_warmup_item_counts(job_id).await.unwrap();
        assert_eq!(queued, 0);
        assert_eq!(running, 0);
        assert_eq!(done, 1);
        assert_eq!(failed, 1);
        assert_eq!(total, 2);

        db.upsert_collection_asset_ref(
            "base",
            "0xabc",
            "ipfs://cid/file1.svg",
            "catalog_asset",
            Some("1"),
        )
        .await
        .unwrap();
        db.upsert_collection_asset_ref(
            "base",
            "0xabc",
            "ipfs://cid/file2.svg",
            "catalog_asset",
            Some("2"),
        )
        .await
        .unwrap();
        db.upsert_pinned_asset("ipfs://cid/file1.svg", "cid", "file1.svg", None, 12)
            .await
            .unwrap();
        db.record_pinned_asset_failure("ipfs://cid/file2.svg", "cid", "file2.svg", "failure")
            .await
            .unwrap();

        let (assets_total, assets_pinned, assets_failed) =
            db.catalog_asset_counts("base", "0xabc").await.unwrap();
        assert_eq!(assets_total, 2);
        assert_eq!(assets_pinned, 1);
        assert_eq!(assets_failed, 1);
    }

    #[tokio::test]
    async fn token_warmup_roundtrip() {
        let dir = tempdir().unwrap();
        let config = test_config(dir.path().join("renderer.db"));
        let db = Database::new(&config).await.unwrap();

        let job_id = db
            .upsert_token_warmup_job("base", "0xabc", None, "queued", None)
            .await
            .unwrap();
        db.insert_token_warmup_items(job_id, &["1".to_string(), "2".to_string(), "3".to_string()])
            .await
            .unwrap();

        let (queued, running, done, failed, total) =
            db.token_warmup_item_counts(job_id).await.unwrap();
        assert_eq!(queued, 3);
        assert_eq!(running, 0);
        assert_eq!(done, 0);
        assert_eq!(failed, 0);
        assert_eq!(total, 3);

        let first = db.fetch_next_token_warmup_item().await.unwrap().unwrap();
        assert_eq!(first.token_id, "1");
        db.update_token_warmup_item_status(first.id, "done", None)
            .await
            .unwrap();
        let second = db.fetch_next_token_warmup_item().await.unwrap().unwrap();
        assert_eq!(second.token_id, "2");
        db.update_token_warmup_item_status(second.id, "failed", Some("boom"))
            .await
            .unwrap();
        let third = db.fetch_next_token_warmup_item().await.unwrap().unwrap();
        assert_eq!(third.token_id, "3");
        db.update_token_warmup_item_status(third.id, "done", None)
            .await
            .unwrap();

        let (queued, running, done, failed, total) =
            db.token_warmup_item_counts(job_id).await.unwrap();
        assert_eq!(queued, 0);
        assert_eq!(running, 0);
        assert_eq!(done, 2);
        assert_eq!(failed, 1);
        assert_eq!(total, 3);

        db.upsert_token_asset_ref("base", "0xabc", "1", "ipfs://cid/token1.svg", "token_asset")
            .await
            .unwrap();
        db.upsert_token_asset_ref("base", "0xabc", "2", "ipfs://cid/token2.svg", "token_asset")
            .await
            .unwrap();
        db.upsert_pinned_asset("ipfs://cid/token1.svg", "cid", "token1.svg", None, 12)
            .await
            .unwrap();
        db.record_pinned_asset_failure("ipfs://cid/token2.svg", "cid", "token2.svg", "failure")
            .await
            .unwrap();

        let (assets_total, assets_pinned, assets_failed) =
            db.token_asset_counts("base", "0xabc").await.unwrap();
        assert_eq!(assets_total, 2);
        assert_eq!(assets_pinned, 1);
        assert_eq!(assets_failed, 1);
    }

    #[tokio::test]
    async fn token_state_cache_roundtrip() {
        let dir = tempdir().unwrap();
        let config = test_config(dir.path().join("renderer.db"));
        let db = Database::new(&config).await.unwrap();

        let compose = ComposeResult {
            metadata_uri: "ipfs://cid/meta.json".to_string(),
            catalog_address: "0x0000000000000000000000000000000000000000".to_string(),
            fixed_parts: vec![FixedPart {
                part_id: 1,
                z: 0,
                metadata_uri: "ipfs://cid/part.svg".to_string(),
            }],
            slot_parts: Vec::<SlotPart>::new(),
        };
        let state_json = serde_json::to_string(&compose).unwrap();
        db.upsert_token_state(
            "base",
            "0xabc",
            "1",
            "10",
            "hash",
            Some(&state_json),
            None,
            now_epoch() + 60,
            false,
        )
        .await
        .unwrap();

        let entry = db
            .get_token_state("base", "0xabc", "1", "10")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.state_hash, "hash");
        assert_eq!(entry.state_json.as_deref(), Some(state_json.as_str()));

        db.record_token_state_error("base", "0xabc", "1", "10", "boom", now_epoch() + 120)
            .await
            .unwrap();
        let entry = db
            .get_token_state("base", "0xabc", "1", "10")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.last_error.as_deref(), Some("boom"));
        assert_eq!(entry.state_json.as_deref(), Some(state_json.as_str()));
    }

    #[tokio::test]
    async fn hash_replacements_roundtrip() {
        let dir = tempdir().unwrap();
        let config = test_config(dir.path().join("renderer.db"));
        let db = Database::new(&config).await.unwrap();
        let file_path = dir.path().join("replacement.png");
        db.upsert_hash_replacement("QmTestCid", "image/png", file_path.to_str().unwrap())
            .await
            .unwrap();

        let list = db.list_hash_replacements().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].cid, "QmTestCid");

        let fetched = db.get_hash_replacement("QmTestCid").await.unwrap().unwrap();
        assert_eq!(fetched.content_type, "image/png");
        assert_eq!(fetched.file_path, file_path.to_str().unwrap());

        let removed = db
            .delete_hash_replacement("QmTestCid")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(removed.cid, "QmTestCid");
        assert!(
            db.get_hash_replacement("QmTestCid")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn fresh_rate_limit_blocks_until_cooldown() {
        let dir = tempdir().unwrap();
        let config = test_config(dir.path().join("renderer.db"));
        let db = Database::new(&config).await.unwrap();

        let first = db
            .check_fresh_request("base:0xabc:1:10", 300)
            .await
            .unwrap();
        assert!(first.allowed);
        let second = db
            .check_fresh_request("base:0xabc:1:10", 300)
            .await
            .unwrap();
        assert!(!second.allowed);
        assert!(second.retry_after_seconds.unwrap_or(0) > 0);
    }

    #[tokio::test]
    async fn prune_usage_removes_old_rows() {
        let dir = tempdir().unwrap();
        let config = test_config(dir.path().join("renderer.db"));
        let db = Database::new(&config).await.unwrap();

        let now = now_epoch();
        let current_hour = now / 3600 * 3600;
        let old_hour = current_hour - 48 * 3600;
        let recent_hour = current_hour - 3600;

        let rows = vec![
            UsageBatchRow {
                hour_bucket: old_hour,
                identity_key: "ip:anon".to_string(),
                route_group: "render".to_string(),
                requests: 1,
                bytes_out: 10,
                cache_hits: 0,
                cache_misses: 1,
            },
            UsageBatchRow {
                hour_bucket: recent_hour,
                identity_key: "ip:anon".to_string(),
                route_group: "render".to_string(),
                requests: 1,
                bytes_out: 20,
                cache_hits: 1,
                cache_misses: 0,
            },
        ];
        db.record_usage_batch(&rows).await.unwrap();

        let before = db.list_usage(72).await.unwrap();
        assert_eq!(before.len(), 2);

        let pruned = db.prune_usage(1).await.unwrap();
        assert_eq!(pruned, 1);

        let after = db.list_usage(72).await.unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].hour_bucket, recent_hour);
    }
}
