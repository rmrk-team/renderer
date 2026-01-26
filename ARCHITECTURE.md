# Architecture

## Request flow
- Requests enter via `src/http.rs` where access control, error shaping, and headers are applied.
- The render pipeline lives in `src/render.rs` and is responsible for composition, rasterization, and cache keys.
- Asset resolution + pinning live in `src/assets.rs` with local IPFS support from `src/local_ipfs.rs`.
- Disk caches and eviction live in `src/cache.rs`.
- SQLite state is handled in `src/db.rs` (collections, approvals, warmup state, usage).

## Module boundaries
- `http`: request parsing, access gating, response formatting, fallbacks.
- `render`: pure-ish rendering logic; avoid HTTP concerns.
- `admin`: admin-only mutations and cache invalidations.
- `assets`: URI normalization, fetch limits, pinning.
- `warmup/*`: background jobs and progress tracking.

## Background workers
- Warmup workers (`src/warmup.rs`, `src/catalog_warmup.rs`, `src/token_warmup.rs`).
- Approval watchers (`src/approvals.rs`).
- Usage aggregator (`src/usage.rs`).
- Cache eviction loop (`src/cache.rs`).
- Fresh-request cleanup (`src/main.rs`).

## Metrics guidance
- If adding Prometheus metrics, bound label cardinality (avoid raw IPs and unbounded collection labels).
