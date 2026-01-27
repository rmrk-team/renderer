# RMRK Renderer — Technical Specification

**Version**: 1.2 (MVP)  
**Date**: January 2026  
**License**: Open Source (MIT)  
**Repository**: rmrk-team/renderer

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Technical Stack](#3-technical-stack)
4. [Rendering Pipeline](#4-rendering-pipeline)
5. [Catalog & Parts System](#5-catalog--parts-system)
6. [Asset Resolution](#6-asset-resolution)
7. [Image Caching](#7-image-caching)
8. [Collection Approval & Warmup](#8-collection-approval--warmup)
9. [API Reference](#9-api-reference)
10. [Admin Panel](#10-admin-panel)
11. [Configuration](#11-configuration)
12. [Deployment](#12-deployment)
13. [Self-Hosting Guide](#13-self-hosting-guide)
14. [Appendix A: SVG Sizing Rules](#appendix-a-svg-sizing-rules)
15. [Appendix B: Change Log](#appendix-b-change-log)

---

## 1. Overview

### 1.1 Concept

The RMRK Renderer is a standalone service that composites **ERC-6220 / RMRK Equippable** NFTs into flat images.

It:

- Reads on-chain equippable composition via **RMRKEquipRenderUtils** (`composeEquippables`)
- Resolves each part’s `metadataURI` → **metadata JSON** → `image` / `mediaUri` → actual artwork URI
- Fetches part artwork (primarily **SVG**, but also PNG/JPG where applicable)
- Rasterizes + layers parts in z-order
- Returns cached, resized images (WebP by default)

### 1.2 Design Principles

- **Self-contained**: single Rust binary (+ embedded admin UI)
- **Self-hostable**: anyone can run it with their own RPC + cache directory
- **Predictable rendering**: deterministic output and cache keys (cache busting is URL-driven)
- **Low manual overhead**: derive canvas size from source art; avoid per-collection hand configuration
- **Operational simplicity**: SQLite for small state, filesystem for image cache

### 1.3 Hosted vs Self-Hosted

**Hosted (renderer.rmrk.app):**
- Collection approval required (100 RMRK one-time fee)
- Managed warmup + caching
- Public endpoints used by Singular and ecosystem apps

**Self-hosted:**
- No approval needed
- Full control over which collections are enabled
- Requires own RPC endpoints and disk for cache

### 1.4 Rationale for Key Choices

- **SVG-first**: Kanaria parts are SVG, and many RMRK collections use vector parts for crisp compositing at multiple resolutions.
- **Canvas size derived from art**: Kanaria is *card-shaped*, not square. Deriving from the first fixed part SVG’s `viewBox`/`width`/`height` removes error-prone manual config and avoids incorrect aspect ratios.
- **No caching of partial renders**: an incomplete render “poisoning” the cache for days is worse than a slow refresh. Partial renders may be returned, but are not persisted.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        RMRK RENDERER                             │
│                                                                  │
│  ┌────────────────┐    ┌────────────────┐    ┌────────────────┐ │
│  │  HTTP Server   │───▶│  Render Engine │───▶│  Cache Layer   │ │
│  │  (API + Admin) │    │ (SVG+Raster)   │    │  (Filesystem)  │ │
│  └────────────────┘    └────────────────┘    └────────────────┘ │
│          │                     │                     │          │
│          │                     ▼                     │          │
│          │            ┌────────────────┐             │          │
│          │            │  Catalog Cache │             │          │
│          │            │  (SQLite)      │             │          │
│          │            └────────────────┘             │          │
│          │                     │                     │          │
│          │         ┌──────────┴──────────┐          │          │
│          │         ▼                     ▼          │          │
│          │  ┌────────────┐      ┌────────────┐      │          │
│          │  │  RPC       │      │  IPFS/HTTP │      │          │
│          │  │  (chain)   │      │  (assets)  │      │          │
│          │  └────────────┘      └────────────┘      │          │
│          │                                          │          │
│          ▼                                          │          │
│  ┌────────────────────────────────────────────────────────────┐│
│  │                     Warmup Queue                            ││
│  │               (background rendering)                        ││
│  └────────────────────────────────────────────────────────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Technical Stack

| Component | Technology |
|-----------|------------|
| Language | Rust |
| HTTP Server | Axum |
| Database | SQLite |
| Cache Storage | Local filesystem |
| Raster Image Processing | `image` crate |
| SVG Rasterization | `resvg` (via `usvg` + `tiny-skia`) |
| HTTP Fetching | `reqwest` |
| Admin UI | Embedded static assets served by same binary |
| Metrics | Prometheus client + Grafana dashboards (optional) |

---

## 4. Rendering Pipeline

### 4.1 Request Flow

1. Request arrives:
   - **Canonical (asset-specific):**
     - **v2 (current):** `GET /render/{chain}/{collection}/{tokenId}/{assetId}/{format}?cache={timestamp}&width={pixels}`
     - **v1 (legacy compat):** `GET /render/{chain}/{collection}/{tokenId}/{assetId}.{format}?cache={timestamp}&width={pixels}`
   - **Convenience (token-only primary asset):**
     - **v2 (current):** `GET /render/{chain}/{collection}/{tokenId}/{format}?cache={timestamp}&width={pixels}`
     - **v1 (legacy compat):** `GET /render/{chain}/{collection}/{tokenId}.{format}?cache={timestamp}&width={pixels}`
     - This endpoint resolves the token’s current primary assetId on-chain and **redirects** to the canonical URL.

2. Check final-image cache key (see Section 7.1).
3. If hit: return cached bytes.
4. If miss:
   1. Fetch equippable composition from chain (`composeEquippables`)
   2. Determine **canonical canvas size** (base width + height) from **first fixed part SVG**
   3. Resolve and load all layers (fixed parts + equipped slot parts)
   4. Composite by z-order into an RGBA canvas
   5. Apply optional overlays/backgrounds
   6. Resize to requested width preset (maintaining aspect ratio)
   7. Encode to requested format
   8. Cache **only if complete** (no missing required layers)
   9. Return response

**Non-composable fallback:** if `composeEquippables` reverts with
`RMRKNotComposableAsset`, the renderer treats the asset as **single-layer**:
it fetches the asset metadata (`getAssetMetadata`), resolves the media URI, and
renders it directly. Catalog/theme lookups are skipped (catalog address is zero),
and canvas size is derived from that asset.
Original-size responses from this fallback are not cached; resized/OG variants
remain cacheable to avoid becoming a large-asset CDN.
Raster assets larger than `MAX_RASTER_BYTES` are resized (bounded by
`MAX_RASTER_RESIZE_BYTES` and `MAX_RASTER_RESIZE_DIM`). If the resized asset is
still too large and `thumbnailUri` is present, the renderer falls back to the
thumbnail for both canvas derivation and render.

### 4.2 Canonical Canvas Size Derivation

**Goal:** determine the “native” coordinate system for the collection (e.g., Kanaria is **1080×1512**, not square).

**Derivation algorithm (per collection, cached):**

1. Identify a deterministic “first fixed part”:
   - Choose the fixed part with the smallest `z` value (or first in `fixedParts[]` if stable).
2. Resolve its `metadataURI` → metadata JSON → `image/mediaUri` → artwork URI.
3. Fetch the artwork and parse:
   - If SVG:
     - Prefer `viewBox` width/height as canonical canvas size.
     - If missing, fallback to root `width`/`height` attributes (px or unitless).
   - If PNG/JPG:
     - Use pixel dimensions from the decoded image.
4. Store `{canvas_width, canvas_height, canvas_fingerprint}` in SQLite for reuse:
   - `canvas_fingerprint` = hash of the resolved artwork URI (or CID) + dimensions.
5. On subsequent renders, reuse cached canvas dimensions unless the fingerprint changes.

**Fallbacks:**
- If parsing fails (invalid SVG, missing sizing), fallback to `DEFAULT_CANVAS_WIDTH/HEIGHT` (configurable) and mark collection as “needs review” in admin UI.

**Rationale:** Deriving from the first fixed part removes per-collection manual configuration while preserving correct aspect ratios for collections like Kanaria.

### 4.3 Layer Resolution and Rasterization

For each layer (fixed or equipped slot):

1. Resolve `metadataURI` (JSON) → `image` (preferred) → else `mediaUri` → else `thumbnailUri`.
2. Fetch the artwork bytes.
3. Convert to a raster layer matching `{canvas_width, canvas_height}`:
   - SVG → rasterize to `canvas_width × canvas_height` (RGBA)
   - PNG/JPG/WebP → decode.
     - If dimensions match the canonical canvas: use as-is.
     - If dimensions do **not** match: apply the raster mismatch policy:
       - `error`: treat as missing and increment `X-Renderer-Nonconforming-Layers`.
       - `scale_to_canvas`: rescale to the canvas.
       - `center_no_scale`: composite centered without resizing.
       - `top_left_no_scale`: composite at origin (0,0) without resizing (default).

### 4.4 Composition

- Sort all resolved layers by `z_index` ascending.
- Slot children render at the slot part’s `z`; slot fallback metadata is only used when no child is equipped.
- Composite using standard alpha-over.
- Canvas is initialized transparent.
- If output is JPEG (no alpha), either:
  - default to white background, or
  - use `bg=` query param / per-collection config background.

### 4.5 Missing Part Handling

Parts fall into two classes:

- **Required**: fixed parts (they define the base body/artwork)
- **Optional**: slot parts (may be empty if nothing is equipped)

Handling rules:

1. If an optional slot part fails to load: omit it.
2. If a required fixed part fails to load:
   - Render continues without it (partial image), and the response includes:
     - `X-Renderer-Complete: false`
     - `X-Renderer-Missing-Layers: <count>`
   - **Do not cache** this result (Section 7.4).

Retry behavior:
- Each missing asset is retried once with a different gateway (if IPFS) before being considered missing.

### 4.6 Fallback overrides (disk-backed)

The renderer supports admin-managed fallback assets, stored on disk under `FALLBACKS_DIR`
(kept outside cache directories):

- **Unapproved collections**: when approvals are required and a collection is not approved, return a configured unapproved fallback (collection-specific first, then global).
- **Token overrides**: if a token override exists for `(chain, collection, token_id)`, serve it directly and skip rendering.
- **Render-failure fallback**: if a collection-specific render failure fallback is configured, return it when render fails.

Fallbacks are preprocessed into multiple width variants plus an OG variant (1200×630 with letterboxing).
Each fallback directory contains a `meta.json` with source dimensions and variant list. Raw errors can
still be returned to authorized clients via `?debug=1` or `?raw=1`. See the admin
section below for endpoints and storage layout.
Fallback directories loaded from DB must be absolute, contain no `.`/`..` components, and live under
`FALLBACKS_DIR`. If no uploaded unapproved fallback exists, the renderer returns a generated
fallback-text image to preserve the upsell UX. The two CTA lines for this generated image are
configurable via admin settings. These CTA lines are intentionally unvalidated and treated as
trusted admin content to maximize conversion control; this is an accepted risk and relies on
admin access protection.

---

## 5. Catalog & Parts System

### 5.1 On-Chain Source of Truth

Renderer reads composition via `RMRKEquipRenderUtils.composeEquippables(...)`, which returns:

- parent metadata URI (for the asset)
- catalog address
- `fixedParts[]` (part id, z, metadataURI)
- `slotParts[]` (slot id, z, child info, metadataURI)

This is sufficient to render without off-chain indexing.

### 5.2 Catalog Caching

Catalog/parts can be cached in SQLite for warmup and debugging, but the renderer should always be able to render **on-demand** by calling `composeEquippables`.

Catalogs are expected to be effectively immutable; nevertheless, the admin UI provides a manual refresh.

---

## 6. Asset Resolution

### 6.1 Supported URI Schemes

- `ipfs://...` (preferred)
- bare CID or CID/path (normalized to `ipfs://`)
- `https://...`
- `http://...` (allowed, but discouraged; can be disabled via config)
- `ar://...` (normalized to `https://arweave.net/`)
- `data:...` (metadata and asset bytes)

Additional resolution rules:

- Relative asset URIs are resolved against the metadata URI base (HTTP or IPFS).
- HTTP gateway URLs containing `/ipfs/<cid>` are normalized to `ipfs://` so gateway rotation applies.

### 6.2 IPFS Gateway Strategy

- Maintain a list of gateways.
- On fetch failure, rotate gateway and retry.
- Cache successful fetches by CID to reduce load and eliminate flakiness.
- If a CID matches a hash replacement entry, the replacement bytes are served directly (no network fetch).
- When the local IPFS gateway is enabled, it is inserted at the head of the gateway list.

### 6.3 Metadata JSON Shape

Part `metadataURI` typically points to JSON containing one or more of:

- `image`
- `mediaUri`
- `animation_url`
- `src`
- `thumbnailUri`

The renderer treats these as equivalent and prefers `image`, then `mediaUri`, then `animation_url`, then `src`, then `thumbnailUri`.

### 6.4 SVG Security Rules

To avoid SSRF and “SVG as an attack surface” issues:

- External resource loading is disabled (no `<image href="http://...">`, no remote fonts).
- Scripts are ignored/disallowed.
- Maximum SVG size enforced (bytes + node count limits).
- Rasterization happens in-process using `resvg` (no external binaries).

If an SVG violates limits, it is treated as “failed to load” and handled via missing-part rules.

### 6.5 Raster Size Limits & Resizing

- Raster responses larger than `MAX_RASTER_BYTES` trigger a resize attempt (PNG/JPG/WebP).
- The renderer fetches and decodes up to `MAX_RASTER_RESIZE_BYTES`, then downscales to fit within `MAX_RASTER_RESIZE_DIM`.
- If the resized asset still exceeds limits or decoding fails, the layer is treated as missing.

---

## 7. Image Caching

### 7.1 Cache Key Structure (Final Renders)

Final rendered images are cached at:

```
{cache_dir}/renders/{chain}/{collection}/{token_id}/{asset_id}/{cache_timestamp}/{variant_key}.{format}
```

Where `variant_key` encodes:
- width preset (e.g. `w512`)
- og mode flag (`og`)
- overlay name (if any)
- background (if any)

Example:
```
/var/cache/renderer/renders/base/0x011ff4.../3005/15528/1700787357000/w600.webp
```

### 7.2 IPFS/HTTP Asset Caching

Raw asset bytes cached by content address when possible:

- IPFS: by CID (and path)
- HTTP: by `sha256(url)` + optional ETag/Last-Modified (best-effort)

Suggested structure:

```
{cache_dir}/assets/meta/{key}.json         # metadata JSON fetched from metadataURI
{cache_dir}/assets/raw/{key}              # raw SVG/PNG bytes
{cache_dir}/assets/raster/{key}/{w}x{h}.png  # rasterized SVG cached as PNG
```

### 7.3 Cache Stampede Protection

To prevent concurrent requests rendering the same token repeatedly:

- Use “singleflight” per render key:
  - first request performs render
  - other requests wait for the result (bounded)
- Global concurrency limiter to cap simultaneous renders (configurable)

### 7.4 Partial Render Caching Policy

- **Complete renders** (all required fixed parts present) are cached normally.
- **Partial renders** (missing required parts) are **never cached**, regardless of HTTP status.

Rationale: IPFS flakiness should not poison cache entries for long periods. Refreshing should have a chance to succeed.

### 7.5 Cache Eviction

Two layers are evicted independently:

1. **Final renders**: TTL + LRU
2. **Asset caches (raw + raster)**: TTL + LRU, with longer TTL than final renders

Suggested defaults:
- Final renders minimum TTL: 7 days
- Asset caches minimum TTL: 30 days

LRU eviction triggers when disk usage exceeds `CACHE_MAX_SIZE_GB`.

### 7.6 Pinned Assets

- Warmup can pin IPFS content into a separate “pinned” store.
- Pinned assets are never evicted by cache GC.
- When the local IPFS gateway is enabled, pinned assets are served from it first.

---

## 8. Collection Approval & Warmup

### 8.1 Collection Approval (Hosted Only)

Approval exists to (a) fund hosting and (b) bound warmup load. It is intentionally simple:

- A one-time **100 RMRK** fee per collection.
- No additional anti-spam measures (the fee itself is the gate).

**Important implementation detail (mapping payment → collection):**

For autopilot approval, the hosted service SHOULD use an on-chain approval contract:

- `RendererApprovals.approve(chainId, collectionAddress)`
  - pulls 100 RMRK via `transferFrom`
  - emits `CollectionApproved(payer, chainId, collectionAddress, amount)`

The renderer backend watches these events (event indexer can be Kvasyr later) and auto-approves the collection.

**Rationale:** plain ERC-20 transfers to a wallet do not include a reliable memo for “which collection is being approved”. An approval contract provides an unambiguous event.

Self-hosted instances set `REQUIRE_APPROVAL=false` and can add collections freely.

### 8.2 Warmup Goals

Warmup tries to:

- cache catalog/equippable data
- cache part assets and rasterizations
- pre-render common sizes for existing tokens/assets
- reduce first-request latency and IPFS hits

Warmup is best-effort and must never block live rendering.

### 8.3 Token Discovery Strategies (Warmup)

Warmup MUST NOT assume sequential token IDs.

Supported strategies (in priority order):

1. **Admin-provided token list/range** (fastest, most reliable)
2. **ERC721Enumerable** (`totalSupply` + `tokenByIndex`) if available
3. **Transfer log scan** (archive RPC recommended):
   - scan `Transfer(0x0 → to, tokenId)` for minted tokenIds
   - cache discovered tokenIds
4. **Sequential fallback** (only if explicitly enabled per collection)

If none available, warmup can be “assets-only” (cache parts + rasterize) and let renders happen on-demand.

### 8.4 Warmup Work Queue

- Background queue with configurable concurrency and delay.
- Live requests take priority over warmup tasks.
- Warmup progress tracked in SQLite and visible in admin UI.

### 8.5 Warmup Error Handling

- Invalid or empty asset URIs are logged and skipped (marked done) so jobs stay healthy.
- If top-asset lookup reverts for a missing asset, warmup falls back to `tokenURI()` and treats it as a single-layer asset.

---

## 9. API Reference

### 9.1 Canonical Render Endpoint

```
GET /render/{chain}/{collection}/{tokenId}/{assetId}/{format}
    ?cache={timestamp}
    &width={pixels|preset}
    &ogImage=true|false
    &overlay={name}
    &bg={hex|transparent}
```

Legacy compatibility:

```
GET /render/{chain}/{collection}/{tokenId}/{assetId}.{format}
```

**Parameters:**
- `chain`: chain name (`base`, `moonbeam`, `polygon`, etc.)
- `collection`: contract address
- `tokenId`: token id
- `assetId`: composable asset id
- `format`: `webp|png|jpg|jpeg`

**Query parameters:**
- `cache` (required for effective caching): equipment/update timestamp (ms)
- `width`: output width. Also supports legacy alias `img-width`.
- `ogImage=true`: triggers OG mode (1200×630 crop). Equivalent to calling `/og/...`.
- `overlay`: optional overlay name (must be configured for this collection)
- `bg`: background fill, used for JPEG or when explicitly requested

**Response headers:**
- `X-Renderer-Complete: true|false`
- `X-Renderer-Result: rendered|placeholder|cache-miss|fallback`
- `X-Renderer-Cache-Hit: true|false`
- `X-Cache: HIT|MISS`
- `X-Renderer-Fallback: unapproved|render_fallback|token_override|queued|approval_rate_limited`
- `X-Renderer-Fallback-Source: global|collection|token` (disk-backed fallbacks)
- `X-Renderer-Fallback-Action: register_collection|retry|none`
- `X-Renderer-Error-Code: <code>`
- `Cache-Control: public, max-age=...` (safe due to cache busting in URL)

### 9.2 Primary Asset Convenience Endpoint (Token-only)

```
GET /render/{chain}/{collection}/{tokenId}/{format}
    ?cache={timestamp}
    &width={pixels|preset}
    &ogImage=true|false
    &overlay={name}
    &bg={hex|transparent}
```

Legacy compatibility:

```
GET /render/{chain}/{collection}/{tokenId}.{format}
```

**Behavior:**
- Resolve the token’s current **top/primary assetId** on-chain via:
  - `RMRKEquipRenderUtils.getTopAssetAndEquippableDataForToken(collection, tokenId)`
- Respond with a **302 redirect** to the canonical endpoint:
  - `/render/{chain}/{collection}/{tokenId}/{assetId}/{format}` (preserving query params)

**Notes:**
- `HEAD` is only supported on canonical (asset-specific) render routes, not on token-only routes.
- `HEAD` acts as a cache probe and never renders; it returns `200` with headers
  only. Cache misses set `X-Renderer-Cache-Hit: false` (`X-Cache: MISS`,
  `X-Renderer-Result: cache-miss`) and `Cache-Control: no-store`.

**Redirect response headers:**
- `Cache-Control: no-store` (prevents “sticky” redirects when primary asset changes)
- `X-Renderer-Primary-AssetId: <assetId>`

**Rationale:**
- Enables “render the current primary look” without requiring clients to know `assetId`.
- Ensures caching is busted when the **primary asset changes**, because the redirected URL includes `assetId`.

### 9.3 Legacy Compatibility Endpoint (Drop-in Replacement)

To support cutover from `composable.rmrk.link`, the renderer MUST support legacy and current paths:

```
GET /production/create/{chain}/{cacheTimestamp}/{collection}/{tokenId}/{assetId}/{format}?img-width=600&ogImage=true
```

Legacy compatibility:

```
GET /production/create/{chain}/{cacheTimestamp}/{collection}/{tokenId}/{assetId}.{format}?img-width=600&ogImage=true
```

Mapping:
- `{cacheTimestamp}` → `cache`
- `img-width` → `width`
- `ogImage=true` → OG render mode

### 9.4 OG Endpoint

```
GET /og/{chain}/{collection}/{tokenId}/{assetId}/{format}?cache={timestamp}
```

Legacy compatibility:

```
GET /og/{chain}/{collection}/{tokenId}/{assetId}.{format}?cache={timestamp}
```

- Returns a 1200×630 image.
- Uses per-collection `og_focal_point` to bias cropping vertically (defaults to 25% from top).
- Applies per-collection OG overlay if configured.

### 9.5 Width Presets

Renderer supports fixed presets (arbitrary widths are rounded to nearest preset):

| Preset | Width |
|--------|------:|
| thumb | 64 |
| small | 128 |
| medium | 256 |
| large | 512 |
| xl | 1024 |
| xxl | 2048 |
| original | no resize |

Aspect ratio is preserved; height is derived from canonical canvas size.

### 9.6 Metrics Endpoint

```
GET /metrics
```

Returns Prometheus text format. Access is **private by default** and granted when any of:

- `METRICS_PUBLIC=true`
- request IP matches `METRICS_ALLOW_IPS`
- bearer matches `METRICS_BEARER_TOKEN` (recommended)
- admin bearer auth is presented (`ADMIN_PASSWORD`)

Metrics are kept low-cardinality (Top-K for IPs/collections). See `metrics/README.md`
for dashboards and scrape configuration.

Note: keep `METRICS_REQUIRE_ADMIN_KEY=true` in production to prevent render allowlisted IPs from
implicitly gaining `/metrics` access; use `METRICS_ALLOW_IPS` or `METRICS_BEARER_TOKEN` for scrapes.

---

## 10. Admin Panel

Served at `/admin` (password protected).

### 10.1 Collection Management

- Add/remove collections
- Toggle approval requirement (self-hosted)
- View per-collection canvas size (derived)
- Refresh derived canvas size (re-derive from fixed part)
- Configure OG focal point
- Configure overlays per collection:
  - OG overlay (applied in OG mode)
  - Optional watermark overlay (applied in all modes or selected modes)

### 10.2 Warmup Controls

- Start/pause/restart warmup
- Token discovery method selection
- View warmup progress and failures

### 10.3 Cache Controls

- View cache size breakdown
- Purge cache for a collection
- Purge all caches

### 10.4 RPC Configuration

- Add/edit RPC endpoints per chain
- Configure failover order
- View lag/health stats

### 10.5 Hash Replacements

- Upload a static image to replace a specific IPFS CID.
- The replacement is served directly in place of the CID (no network fetch).
- Used for permanently missing IPFS content.

### 10.6 Fallback Overrides

- Upload and manage fallback images for unapproved collections (global or per-collection).
- Upload a per-collection render-failure fallback image.
- Upload per-token overrides keyed by `(chain, collection, token_id)`.

Assets are resized/encoded on upload, stored under `FALLBACKS_DIR`, and served directly from disk.
All DB-provided fallback paths are validated to be under `FALLBACKS_DIR` before serving.
See the Admin API section in this spec for the full surface area.

---

## 11. Configuration

### 11.1 Environment Variables

```env
# Server
HOST=0.0.0.0
PORT=8080
ADMIN_PASSWORD=your-secure-password

# Database
DB_PATH=/var/lib/renderer/renderer.db

# Cache
CACHE_DIR=/var/cache/renderer
CACHE_MAX_SIZE_GB=50
RENDER_CACHE_MIN_TTL_DAYS=7
ASSET_CACHE_MIN_TTL_DAYS=30
CACHE_SIZE_REFRESH_SECONDS=300
PINNING_ENABLED=true
PINNED_DIR=/var/lib/renderer/pinned
LOCAL_IPFS_ENABLED=true
LOCAL_IPFS_BIND=127.0.0.1
LOCAL_IPFS_PORT=18180

# Fallback assets
FALLBACKS_DIR=/var/lib/renderer/fallbacks
MAX_ADMIN_BODY_BYTES=104857600
FALLBACK_UPLOAD_MAX_BYTES=5242880
FALLBACK_UPLOAD_MAX_PIXELS=16000000

# Metrics
METRICS_PUBLIC=false
METRICS_REQUIRE_ADMIN_KEY=true
METRICS_BEARER_TOKEN=
METRICS_ALLOW_IPS=127.0.0.1/32
METRICS_TOP_IPS=20
METRICS_TOP_COLLECTIONS=50
METRICS_TOP_FAILURE_COLLECTIONS=50
METRICS_TOP_SOURCES=50
METRICS_TOP_FAILURE_REASONS=20
METRICS_TOP_SOURCE_FAILURE_REASONS=100
METRICS_IP_LABEL_MODE=sha256_prefix
METRICS_REFRESH_INTERVAL_SECONDS=10
METRICS_EXPENSIVE_REFRESH_SECONDS=300

# Usage tracking (privacy + retention)
USAGE_TRACKING_ENABLED=true
USAGE_SAMPLE_RATE=0.1
USAGE_RETENTION_DAYS=7
IDENTITY_IP_LABEL_MODE=sha256_prefix

# Token override cache
TOKEN_OVERRIDE_CACHE_TTL_SECONDS=30
TOKEN_OVERRIDE_CACHE_CAPACITY=100000

# Rendering concurrency
MAX_CONCURRENT_RENDERS=4
MAX_CONCURRENT_IPFS_FETCHES=16
MAX_CONCURRENT_RPC_CALLS=16

# Default canvas fallback (only used if derivation fails)
DEFAULT_CANVAS_WIDTH=1080
DEFAULT_CANVAS_HEIGHT=1512

# RPCs (JSON map of chain -> [rpc_urls])
RPC_ENDPOINTS={"base":["https://mainnet.base.org"],"moonbeam":["https://rpc.api.moonbeam.network"]}

# IPFS/HTTP fetch
IPFS_GATEWAYS=["https://rmrk.myfilebase.com/ipfs/","https://cloudflare-ipfs.com/ipfs/","https://ipfs.io/ipfs/"]
IPFS_TIMEOUT_SECONDS=30
ALLOW_HTTP=true
ALLOW_PRIVATE_NETWORKS=false
MAX_METADATA_JSON_BYTES=524288
MAX_SVG_BYTES=2097152
MAX_SVG_NODE_COUNT=200000
MAX_RASTER_BYTES=10485760
MAX_RASTER_RESIZE_BYTES=52428800
MAX_RASTER_RESIZE_DIM=2048
MAX_CANVAS_PIXELS=16000000
MAX_TOTAL_RASTER_PIXELS=64000000
MAX_DECODED_RASTER_PIXELS=16000000
MAX_LAYERS_PER_RENDER=200

# Hosted approval
REQUIRE_APPROVAL=true
APPROVAL_FEE_RMRK=100
RMRK_TOKEN_ADDRESS=0x...
RENDERER_APPROVALS_CONTRACT=0x...
```

### 11.2 Per-Collection Config (SQLite)

```sql
CREATE TABLE collection_config (
  id INTEGER PRIMARY KEY,
  chain TEXT NOT NULL,
  collection_address TEXT NOT NULL,

  -- Derived canvas
  canvas_width INTEGER,
  canvas_height INTEGER,
  canvas_fingerprint TEXT,

  -- OG config
  og_focal_point INTEGER DEFAULT 25, -- percent from top

  -- Overlays
  og_overlay_uri TEXT,               -- ipfs://... or local://...
  watermark_overlay_uri TEXT,        -- optional

  -- Warmup config
  warmup_strategy TEXT DEFAULT 'auto',

  UNIQUE(chain, collection_address)
);
```

---

## 12. Deployment

- Single statically-linked binary is preferred.
- systemd-managed service on a standard Ubuntu VPS.
- Cloudflare can sit in front for caching/DDoS protection, but is optional.
- Prometheus/Grafana can run on the same host and scrape `/metrics` locally (see `metrics/README.md`).

---

## 13. Self-Hosting Guide

1. Provide RPC endpoints for your target chain(s).
2. Provide a cache directory with sufficient disk.
3. Run with `REQUIRE_APPROVAL=false` unless you also deploy an approval contract.
4. Add collections via `/admin`.

---

## Appendix A: SVG Sizing Rules

When parsing an SVG to determine canvas size:

1. Prefer `viewBox="minX minY width height"`:
   - Use `width` and `height` from viewBox as canonical dimensions.
2. Else fallback to root `width` and `height`:
   - Support unitless or `px`.
   - Other units are not guaranteed (MVP).
3. If both missing, derivation fails and falls back to defaults.

When rasterizing:
- Render the SVG into a target pixel buffer of `{canvas_width × canvas_height}`.
- The renderer assumes parts are authored for the same coordinate system and should align at origin (0,0).

---

## Appendix B: Change Log

### v1.2 (Current)
- Added **SVG-first** pipeline (resvg/usvg) while retaining PNG/JPG support.
- Added **metadata URI indirection** (`metadataURI` → JSON → `image/mediaUri`) as first-class behavior.
- Added **canvas size derivation** from first fixed part SVG; Kanaria not assumed square.
- Changed caching policy: **partial renders are not cached**.
- Added legacy compatibility requirements: `img-width` alias and `ogImage=true`.
- Added a safe **overlay system** (configured, not arbitrary URLs).
- Documented robust warmup token discovery (no sequential assumption).
- Added **token-only primary-asset endpoint** that redirects to asset-specific URLs (cache busts when primary asset changes).
- Added raster mismatch policies for non-full-canvas raster layers (warn + policy-driven handling).
- Added support for `data:` URIs, `ar://` normalization, relative asset URIs, and IPFS gateway URL normalization.
- Added raster size limits with optional resize for oversized raster assets.
- Added raster mismatch policies (`error`, `scale_to_canvas`, `center_no_scale`, `top_left_no_scale`).
- Added hash replacements to serve static content for missing IPFS CIDs.
- Clarified slot children always render at their slot’s `z`.
- Added disk-backed fallback overrides for unapproved collections, render failures, and token-level overrides.
- Added Prometheus `/metrics` endpoint with low-cardinality instrumentation and Grafana guidance.

---

*End of RMRK Renderer Specification*
