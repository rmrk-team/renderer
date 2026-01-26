# RMRK Renderer (proj-renderer)

Standalone Rust service that renders RMRK equippable NFTs into flat images.
SVG-first rendering, deterministic caching, and a minimal admin panel and API.

## Features

- Canonical render endpoints with cache-busting via `cache=` query param
- SVG + PNG/JPG/WebP asset support (SVG rasterized with `resvg`)
- Deterministic canvas size derived from first fixed part
- Partial renders are **not cached**
- IPFS gateway rotation + asset caching
- Warmup queue with safe concurrency
- Embedded admin panel (`/admin`) with JSON API
- Admin-managed fallback overrides for unapproved collections and token-level fixes
- Prometheus `/metrics` endpoint with Top-K tracking for IPs/collections

## Quickstart

```bash
cd proj-renderer
cargo build --release

export ADMIN_PASSWORD="change-me"
export RPC_ENDPOINTS='{"base":["https://mainnet.base.org"]}'

./target/release/proj-renderer
```

See `env.example` for a full configuration template.

Health check:

```bash
curl http://localhost:8080/healthz
```

## Configuration

All configuration is done via environment variables. See env.example for possibilities.

Note: outbound HTTP(S) fetches block private/loopback/link-local hosts and do not
follow redirects by default. Use `ALLOW_PRIVATE_NETWORKS=true` only in trusted
environments.

Render safety caps:

- `MAX_LAYERS_PER_RENDER` limits total layers processed per render.
- `MAX_CANVAS_PIXELS` caps the canvas area (width × height).
- `MAX_TOTAL_RASTER_PIXELS` caps total raster pixels across layers.
- `MAX_DECODED_RASTER_PIXELS` caps raster decode dimensions before allocation.
- `MAX_RASTER_RESIZE_BYTES` allows oversized raster downloads for resize.
- `MAX_RASTER_RESIZE_DIM` rescales oversized rasters to fit within a max dimension.
- `MAX_CACHE_VARIANTS_PER_KEY` limits cached timestamps per token/variant (evicts oldest).
- `MAX_OVERLAY_LENGTH` and `MAX_BG_LENGTH` cap query param length.

HTTP safety caps:

- `MAX_IN_FLIGHT_REQUESTS` limits total concurrent HTTP requests.
- `RATE_LIMIT_PER_MINUTE` / `RATE_LIMIT_BURST` enable per-IP rate limiting (0 disables).
- `APPROVAL_ON_DEMAND_RATE_LIMIT_PER_MINUTE` / `APPROVAL_ON_DEMAND_RATE_LIMIT_BURST` throttle on-demand approval checks for unknown collections (per identity).
- `MAX_ADMIN_BODY_BYTES` caps admin API request bodies.
- Asset/metadata fetches resolve DNS once per request and pin the connection to the resolved IPs to reduce DNS rebinding risk.
- `CACHE_SIZE_REFRESH_SECONDS` controls how often cache size stats are refreshed for `/status` and admin dashboard.
- `OUTBOUND_CLIENT_CACHE_TTL_SECONDS` / `OUTBOUND_CLIENT_CACHE_CAPACITY` cache pinned HTTP clients for outbound fetches.
- `CACHE_EVICT_INTERVAL_SECONDS` sets how often the cache eviction loop runs (0 disables).
- `MAX_CONCURRENT_RPC_CALLS` caps concurrent RPC calls (primary-route lookups + warmup fallbacks).
- `PRIMARY_ASSET_NEGATIVE_TTL_SECONDS` caches failed primary-asset lookups briefly to avoid RPC hammering.
- `DEFAULT_CACHE_TTL_SECONDS` sets a default HTTP cache TTL when `cache` is omitted.

### Render policy

- Child assets render at the slot part’s `z`. If slot fallback metadata exists, it is drawn before the child at the same `z`.
- `RASTER_MISMATCH_FIXED`: `error`, `scale_to_canvas`, `center_no_scale`, or `top_left_no_scale`.
- `RASTER_MISMATCH_CHILD`: same values as `RASTER_MISMATCH_FIXED`, applied to equipped child layers.
- `COLLECTION_RENDER_OVERRIDES`: JSON map `"chain:collection" => { raster_mismatch_fixed, raster_mismatch_child }`.

Example (Base ME avatars `0xb30b909c1fa58fd2b0f95eeea3fa0399b6f2382d`):

- The skin is a fixed part at z=1, while the background is a slot child at z=0.
- Because child assets render at their slot’s z, the background remains at z=0 and the skin stays visible.

Access control:

- `ACCESS_MODE`: `open`, `key_required`, `hybrid`, `denylist_only`, or `allowlist_only`.
- `API_KEY_SECRET`: required unless `ACCESS_MODE=open`.
- `KEY_RATE_LIMIT_PER_MINUTE` / `KEY_RATE_LIMIT_BURST`: default per-key limits (overrides can be set per key).
- `AUTH_FAILURE_RATE_LIMIT_PER_MINUTE` / `AUTH_FAILURE_RATE_LIMIT_BURST`: rate limit for unauthorized requests.
- `USAGE_RETENTION_DAYS`: retention for hourly usage aggregates (0 disables cleanup).
- `TRACK_KEYS_IN_OPEN_MODE`: when `ACCESS_MODE=open` or `denylist_only`, skip DB lookups for bearer tokens unless set to `true`.
- API keys are accepted via `Authorization: Bearer` only (query-string keys are not supported).

### Observability (Prometheus + Grafana)

The renderer exposes a Prometheus endpoint at `GET /metrics`. It is **private by default** and
access is granted when any of the following are true:

- `METRICS_PUBLIC=true`
- request IP is in `METRICS_ALLOW_IPS`
- a valid API key is presented (unless `METRICS_REQUIRE_ADMIN_KEY=true`)
- admin bearer auth is presented (`METRICS_REQUIRE_ADMIN_KEY=true`)

See `metrics/README.md` for dashboards, Docker compose, and non-Docker setup guidance.
Specification details live in `spec-docs/MINI_GRAFANA.md`.

Minimal non-Docker steps:

1. Install Prometheus + Grafana (package manager or upstream binaries).
2. Configure Prometheus to scrape `http://127.0.0.1:8080/metrics` and either:
   - allowlist `METRICS_ALLOW_IPS=127.0.0.1/32`, or
   - use a bearer token in the scrape config.
3. Add Prometheus as a Grafana datasource and use the panel queries from `metrics/README.md`.

AccessMode semantics:

- `open`: all requests allowed.
- `key_required`: only valid API keys allowed.
- `hybrid`: valid API keys always allowed; otherwise deny if an IP rule matches `deny`.
- `denylist_only`: deny if API key is inactive or IP rule matches `deny`.
- `allowlist_only`: allow if API key is active; otherwise allow only if IP rule matches `allow`.

IP rule precedence: longest CIDR prefix wins; on ties, `deny` beats `allow`.

On-demand approval checks for unknown collections only run when the request is
authenticated with a valid API key or comes from an allowlisted IP.

### Security invariants

- SVG parsing must never read local files.
- HTTP fetches must never reach private/loopback/link-local IPs.
- `overlay` and `bg` are normalized before cache key creation.

### Hosted approvals (optional)

```sh
REQUIRE_APPROVAL=true
APPROVALS_CONTRACTS={"base":"0xYourRendererApprovalsContract"}
APPROVALS_CONTRACT_CHAIN=base
CHAIN_ID_MAP={"1":"ethereum","56":"bsc","137":"polygon","8453":"base","84532":"base-sepolia","1284":"moonbeam","1285":"moonriver","1287":"moonbase-alpha","31337":"hardhat"}
# See approval section in env.example for more
```

Set `APPROVAL_POLL_INTERVAL_SECONDS=0` to disable approval watchers.
`APPROVAL_NEGATIVE_CACHE_SECONDS` and `APPROVAL_NEGATIVE_CACHE_CAPACITY` control
the in-memory negative cache for on-demand approval checks.
If `REQUIRE_APPROVAL=true` and you accept open traffic, use `ACCESS_MODE=key_required`
or strict rate limits to prevent on-demand approval checks from becoming an RPC
cost/availability lever.
Include a chain ID entry for every chain you enable.

Set `MAX_APPROVAL_STALENESS_SECONDS` to force an on-demand recheck when approval
sync is older than the configured window (0 disables the guardrail).

The Solidity contract for approvals (`RendererApprovalsV2`) is in `solidity/RendererApprovals.sol`.
It implements a minimal `IRendererApprovalPolicy` interface so other deployers can supply their
own on-chain policy contract as long as it exposes:

- `approved(chainId, collection) -> bool`
- `approvedUntil(chainId, collection) -> uint64`
- optional enumeration: `approvalKeyCount`, `approvalKeysPage`

`CHAIN_ID_MAP` is required to map approval events to configured chains. Use
`APPROVALS_CONTRACT_CHAIN` when a single approvals contract is deployed on one chain.
Set `APPROVAL_ENUMERATION_ENABLED=false` if your approvals contract does not implement
enumeration (the renderer will rely on on-demand checks + events only).

### Warmup defaults

```env
WARMUP_WIDTHS=["medium","large"]
WARMUP_INCLUDE_OG=true
WARMUP_MAX_TOKENS=1000
WARMUP_MAX_RENDERS_PER_JOB=6
WARMUP_JOB_TIMEOUT_SECONDS=600
WARMUP_MAX_BLOCK_SPAN=0
```

`WARMUP_MAX_BLOCK_SPAN` caps transfer-log block ranges (0 disables the guardrail).

Cacheless requests default to `DEFAULT_CACHE_TIMESTAMP=0`, which also powers warmup
renders. When `cache=` is omitted, the renderer prefers a collection `cache_epoch`
(if set) and falls back to `DEFAULT_CACHE_TIMESTAMP`. Set
`DEFAULT_CACHE_TIMESTAMP=off` to disable default caching.

### Token state cache + fresh revalidation

```env
TOKEN_STATE_CHECK_TTL_SECONDS=86400
FRESH_RATE_LIMIT_SECONDS=300
FRESH_REQUEST_RETENTION_DAYS=7
```

- `TOKEN_STATE_CHECK_TTL_SECONDS` controls how long token state is considered fresh.
- `FRESH_RATE_LIMIT_SECONDS` enforces the per-NFT cooldown for `?fresh=1`.
- `FRESH_REQUEST_RETENTION_DAYS` prunes old `fresh=1` limiter rows (0 disables cleanup).
- `?fresh=1` forces an on-chain state refresh, returns `Cache-Control: no-store`, and
  still updates the canonical cache for subsequent non-fresh requests.
- Client keys can bypass the fresh limiter by setting `allow_fresh=true` in the admin UI.

### Disk sizing guidance

- `PINNED_DIR` holds all unique IPFS assets discovered in Phase A+B. Plan for growth
  equal to the total distinct media for your collections (often tens of GB).
- `CACHE_DIR` stores rendered outputs and resized variants; allocate 2-4x the total
  expected pinned asset size if you plan to cache multiple widths/OG renders.
- Start with 50-200 GB for mid-sized collections and adjust after observing
  `/status` cache stats and warmup asset counts.

### Landing page (optional)

```env
LANDING_DIR=/opt/renderer/landing
LANDING=index.html
LANDING_STRICT_HEADERS=true
LANDING_PUBLIC=false
STATUS_PUBLIC=false
OPENAPI_PUBLIC=true
```

When enabled, the service will serve `LANDING` at `/` and static assets from
`LANDING_DIR`. Render routes still take priority.

`LANDING` must be an `.html` file and this feature is disabled on Windows builds.

Set `LANDING_PUBLIC=true` to allow the landing page and its static assets to be
served without access gating (render routes remain protected).

`LANDING_STRICT_HEADERS=true` adds CSP, `X-Frame-Options`, and `Referrer-Policy`;
disable it if your landing needs embedding or external assets.

If the landing file is missing, the renderer serves a built-in minimal template
with canonical, primary, and HEAD examples.

Landing serves only allowlisted extensions and does not expose directory indexes.

Do not place secrets or sensitive files under `LANDING_DIR`; any allowlisted file
extension can be served if requested.

Landing does not provide SPA-style fallbacks for deep links (e.g., `/docs` will not map to `index.html`).
For best UX, include copy-paste examples for the canonical vs primary route and
note that the primary route is slower (RPC lookup) while canonical is cache-first.

Set `STATUS_PUBLIC=true` to expose `/status` and `/status.json` for a lightweight
status widget (cache size, warmup queue, approvals, access mode). Avoid polling
these endpoints at high frequency.

If `STATUS_PUBLIC=false` or `OPENAPI_PUBLIC=false`, those endpoints require an
API key or an allowlisted IP even in `ACCESS_MODE=open`.

Set `OPENAPI_PUBLIC=true` to expose `/openapi.yaml` without access gating.

### Landing templates (Bun)

Static landing templates live under `src/templates/<name>`. Build one template
into `dist/<name>`:

```sh
bun install
bun run build:landing
bun run build:approval
```

Run `bun run build` to build every template folder under `src/templates`.

The approvals template reads build-time settings from `.env`:

- `APPROVALS_CONTRACTS` + `APPROVALS_CONTRACT_CHAIN`
- `RPC_ENDPOINTS`
- `CHAIN_ID_MAP`

Optional overrides:

- `LANDING_RENDERER_BASE_URL` (defaults to `window.location.origin`)
- `LANDING_SINGULAR_BASE_URL`
- `LANDING_APPROVALS_LIMIT`
- `LANDING_APPROVALS_PREVIEW_TOKENS`

If you point `LANDING_RENDERER_BASE_URL` at a different origin while using
`LANDING_STRICT_HEADERS=true`, disable strict headers or host the landing page
on the same origin so CSP allows image loads.

The approvals template performs client-side RPC calls. When serving it through
the renderer, either disable strict headers or expose an RPC proxy on the same
origin so `connect-src` allows the JSON-RPC requests.

### Reverse proxy deployment

When deploying behind a reverse proxy (nginx/ALB/Cloudflare):

- Set `TRUSTED_PROXY_CIDRS` to the proxy’s IP ranges.
- Keep `RATE_LIMIT_PER_MINUTE` / `AUTH_FAILURE_RATE_LIMIT_PER_MINUTE` enabled at the proxy and app.
- Terminate TLS at the proxy, and forward `X-Forwarded-For` / `Forwarded`.
- Avoid overly broad `TRUSTED_PROXY_CIDRS` like `0.0.0.0/0` unless you fully trust clients.
- Configure the proxy to **overwrite** forwarded headers; the app selects the
  last untrusted IP in the chain (bounded to 20 entries).
- If you have multiple proxies (e.g., Cloudflare → nginx), include **all** proxy
  CIDRs in `TRUSTED_PROXY_CIDRS` or client IP attribution will break.

#### Nginx HTTPS (certbot quickstart)

Put the config in `/etc/nginx/sites-available/renderer.rmrk.app`, then enable it:

```sh
sudo ln -s /etc/nginx/sites-available/renderer.rmrk.app \
  /etc/nginx/sites-enabled/renderer.rmrk.app
sudo nginx -t
sudo systemctl reload nginx
```

Start with HTTP only so certbot can validate the domain:

```nginx
upstream renderer {
    server 127.0.0.1:8080;
}

server {
    listen 80;
    server_name renderer.rmrk.app;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        proxy_pass http://renderer;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Then issue the cert (ensure port 80 is open in your firewall/security group):

```sh
sudo mkdir -p /var/www/certbot/.well-known/acme-challenge
sudo certbot certonly --webroot -w /var/www/certbot -d renderer.rmrk.app
```

After the cert exists, add HTTPS and redirect HTTP:

```nginx
server {
    listen 80;
    server_name renderer.rmrk.app;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name renderer.rmrk.app;

    ssl_certificate /etc/letsencrypt/live/renderer.rmrk.app/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/renderer.rmrk.app/privkey.pem;

    client_max_body_size 2m;

    # Legacy: /nft/{chainId}/{collection}/{tokenId}?extension=png&img-width=600
    location ~ ^/nft/(?<chain_id>[^/]+)/(?<collection>0x[0-9A-Fa-f]+)/(?<token_id>[0-9]+)$ {
        set $chain $chain_id;
        if ($chain_id = "8453") { set $chain "base"; }

        set $format $arg_extension;
        if ($format = "") { set $format "png"; }

        rewrite ^ /render/$chain/$collection/$token_id/$format break;
        proxy_pass http://renderer;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 10s;
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }

    location / {
        proxy_pass http://renderer;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 10s;
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }
}
```

If `nginx -t` reports `no "ssl_certificate" is defined`, remove `ssl` from the
`listen 443 ssl` line until certbot has created the cert, then re-enable HTTPS.

#### Nginx legacy path shims (optional)

If you are replacing legacy domains such as `composable.rmrk.link` and
`nft-renderer.rmrk.app`, you can keep old URLs working by proxying to the renderer
and rewriting `/nft/...` to the token-only route. `/production/create/...` is already
supported by the renderer and does not need a rewrite.

```nginx
upstream renderer {
    server 127.0.0.1:8080;
}

server {
    listen 443 ssl;
    server_name composable.rmrk.link nft-renderer.rmrk.app;

    # Legacy: /nft/{chainId}/{collection}/{tokenId}?extension=png&img-width=600
    location ~ ^/nft/(?<chain_id>[^/]+)/(?<collection>0x[0-9A-Fa-f]+)/(?<token_id>[0-9]+)$ {
        set $chain $chain_id;
        if ($chain_id = "8453") { set $chain "base"; }

        set $format $arg_extension;
        if ($format = "") { set $format "png"; }

        rewrite ^ /render/$chain/$collection/$token_id/$format break;
        proxy_pass http://renderer;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        proxy_pass http://renderer;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Add more `chain_id` mappings as needed. If you prefer to keep numeric chain IDs
in the URL, you can instead use numeric keys in `RPC_ENDPOINTS` and
`RENDER_UTILS_ADDRESSES` (and drop the `chain_id` mapping above).

### Go-live checklist

- Put the service behind a reverse proxy for TLS + connection throttling.
- Keep `/admin` private: IP allowlist, VPN, or additional proxy auth.
- Keep rate limits nonzero (even modest).
- Use `ACCESS_MODE=hybrid` or `key_required` with strong `API_KEY_SECRET`.
- Leave `STATUS_PUBLIC=false` unless you intentionally expose it.

## API Endpoints

### Canonical render

```sh
GET /render/{chain}/{collection}/{tokenId}/{assetId}/{format}
    ?cache={timestamp}
    &width={pixels|preset}
    &ogImage=true|false
    &overlay=watermark
    &bg={hex|transparent}
    &onerror=placeholder
```

`format` is now a path segment (e.g. `/render/.../png`), not a file extension.

Legacy dotted routes are still accepted for drop-in compatibility:

```sh
GET /render/{chain}/{collection}/{tokenId}/{assetId}.{format}
HEAD /render/{chain}/{collection}/{tokenId}/{assetId}.{format}?cache={timestamp}
```

```sh
HEAD /render/{chain}/{collection}/{tokenId}/{assetId}/{format}?cache={timestamp}
```

`cache=` selects a specific cache epoch. Omit it to use the collection cache
epoch (if set) or `DEFAULT_CACHE_TIMESTAMP`.

`HEAD` is supported on cached render routes and returns headers without a body. It
acts as a cache probe and never renders; cache misses return `200` with
`X-Renderer-Cache-Hit: false` (`X-Cache: MISS`, `X-Renderer-Result: cache-miss`)
and `Cache-Control: no-store`.

### Token-only convenience (redirect)

```sh
GET /render/{chain}/{collection}/{tokenId}/{format}
```

Response includes `X-Renderer-Primary-AssetId` and `Cache-Control: no-store`.
`HEAD` is only supported on canonical asset routes (`/render/.../{assetId}/...`).

Legacy dotted route:

```sh
GET /render/{chain}/{collection}/{tokenId}.{format}
```

### Legacy compatibility

```sh
GET /production/create/{chain}/{cacheTimestamp}/{collection}/{tokenId}/{assetId}/{format}
    ?img-width=600&ogImage=true
```

Legacy dotted route:

```sh
GET /production/create/{chain}/{cacheTimestamp}/{collection}/{tokenId}/{assetId}.{format}
    ?img-width=600&ogImage=true
```

### OG render

```sh
GET /og/{chain}/{collection}/{tokenId}/{assetId}/{format}?cache={timestamp}
```

Legacy dotted route:

```sh
GET /og/{chain}/{collection}/{tokenId}/{assetId}.{format}?cache={timestamp}
```

### Response headers

- `X-Renderer-Complete: true|false`
- `X-Renderer-Result: rendered|placeholder|cache-miss|fallback`
- `X-Renderer-Cache-Hit: true|false` (cached renders and HEAD probes)
- `X-Cache: HIT|MISS`
- `X-Renderer-Missing-Layers: <count>` (when missing required layers)
- `X-Renderer-Nonconforming-Layers: <count>` (when raster sizes mismatch)
- `X-Renderer-Fallback: unapproved|render_fallback|token_override|queued|approval_rate_limited`
- `X-Renderer-Fallback-Source: global|collection|token` (disk-backed fallbacks)
- `X-Renderer-Fallback-Reason: approval_required|queue_full|rate_limited` (dynamic fallbacks)
- `X-Renderer-Error-Code: <code>` (JSON errors and fallbacks)
- `X-Request-Id: <id>` for correlation
- `Cache-Control: public, max-age=...` when cacheable
- `ETag` for conditional GET on cached renders

When `onerror=placeholder` is set, failed renders return a tiny placeholder image
with `X-Renderer-Error: true` instead of JSON.

## Admin API

The admin panel HTML is served at `/admin` (no secrets). The `/admin/api/**` endpoints require:

- `Authorization: Bearer <ADMIN_PASSWORD>`

Runtime settings (e.g. toggling approval requirements) are exposed at `/admin/api/settings`.

### Collections

```bash
curl -H "Authorization: Bearer $ADMIN_PASSWORD" \
  http://localhost:8080/admin/api/collections

curl -X POST -H "Authorization: Bearer $ADMIN_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"chain":"base","collection_address":"0x...","approved":true}' \
  http://localhost:8080/admin/api/collections
```

### Refresh canvas size

```bash
curl -X POST -H "Authorization: Bearer $ADMIN_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"token_id":"1","asset_id":"100"}' \
  http://localhost:8080/admin/api/collections/base/0x.../refresh-canvas
```

### Collection cache epoch (bust caches)

```bash
curl -X POST -H "Authorization: Bearer $ADMIN_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"epoch":123}' \
  http://localhost:8080/admin/api/collections/base/0x.../cache-epoch
```

Omit `epoch` to auto-bump by 1.

### Recommended ops flow (Phases A/B/C)

1. Approve the collection (if approvals are required).
2. Phase A: catalog warmup (pins shared assets).
3. Phase B: token scan warmup (pins token-specific assets).
4. Phase C: render warmup (optional pre-render of thumbnails/OG).

### Catalog warmup (Phase A)

```bash
curl -X POST -H "Authorization: Bearer $ADMIN_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"chain":"base","collection":"0x...","token_id":"1","asset_id":"100"}' \
  http://localhost:8080/admin/api/warmup/catalog
```

### Token warmup (Phase B)

```bash
curl -X POST -H "Authorization: Bearer $ADMIN_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"chain":"base","collection":"0x...","start_token":1,"end_token":100}' \
  http://localhost:8080/admin/api/warmup/tokens

curl -X POST -H "Authorization: Bearer $ADMIN_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"chain":"base","collection":"0x...","token_ids":["1","2","3"]}' \
  http://localhost:8080/admin/api/warmup/tokens/manual
```

### Render warmup (Phase C, optional)

Render warmup uses the normal render pipeline (pinned assets + token state cache).

```bash
curl -X POST -H "Authorization: Bearer $ADMIN_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{
    "chain":"base",
    "collection":"0x...",
    "token_ids":["1","2","3"],
    "widths":["medium","large"],
    "include_og":true,
    "cache_timestamp":"1700000000000"
  }' \
  http://localhost:8080/admin/api/warmup
```

### Warmup status (Phases A/B)

```bash
curl -H "Authorization: Bearer $ADMIN_PASSWORD" \
  "http://localhost:8080/admin/api/warmup/status?chain=base&collection=0x..."
```

### Warmup jobs (list + cancel)

```bash
curl -H "Authorization: Bearer $ADMIN_PASSWORD" \
  http://localhost:8080/admin/api/warmup/jobs?limit=100

curl -X POST -H "Authorization: Bearer $ADMIN_PASSWORD" \
  http://localhost:8080/admin/api/warmup/jobs/123/cancel
```

### Cache purge

```bash
# Purge renders for a collection
curl -X POST -H "Authorization: Bearer $ADMIN_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"chain":"base","collection":"0x..."}' \
  http://localhost:8080/admin/api/cache/purge

# Purge everything (renders + assets + overlays)
curl -X POST -H "Authorization: Bearer $ADMIN_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"include_assets":true}' \
  http://localhost:8080/admin/api/cache/purge
```

## Overlays

Per-collection overlays can be configured in the admin table:

- `og_overlay_uri` for OG mode
- `watermark_overlay_uri` for `overlay=watermark`

Note: only `overlay=watermark` is supported in this MVP.

Supported schemes:

- `ipfs://...`
- `https://...`
- `local://filename.svg` (resolved relative to `CACHE_DIR/overlays/`)

## Fallbacks & overrides (mini override)

The admin API supports disk-backed fallback/override images for:

- Global unapproved collections
- Per-collection unapproved and render-failure fallbacks
- Per-token overrides (`chain + collection + token_id`)

Images are processed on upload (size limits + re-encoding), stored under `FALLBACKS_DIR`,
and served directly from disk with consistent `ETag` + cache headers. Authorized clients
can still bypass fallbacks with `?debug=1`/`?raw=1` to see JSON errors.

See `spec-docs/MINI_OVERRIDE.md` for detailed behavior and endpoints.

## Build & Deploy

### Build

```bash
cargo build --release
```

### Tests

```bash
cargo test
```

### Local smoke test (prod-style env)

```bash
set -a
source .env
set +a

# Terminal 1
cargo run
```

```bash
# Terminal 2 (warmup A + B + optional C)
curl -X POST -H "Authorization: Bearer $ADMIN_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"chain":"base","collection":"0x...","token_id":"1","asset_id":"100"}' \
  http://localhost:8085/admin/api/warmup/catalog

curl -X POST -H "Authorization: Bearer $ADMIN_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"chain":"base","collection":"0x...","start_token":1,"end_token":50}' \
  http://localhost:8085/admin/api/warmup/tokens

curl -X POST -H "Authorization: Bearer $ADMIN_PASSWORD" \
  -H "Content-Type: application/json" \
  -d '{"chain":"base","collection":"0x...","token_ids":["1","2","3"],"widths":["medium"],"cache_timestamp":"1700000000000"}' \
  http://localhost:8085/admin/api/warmup
```

```bash
# Terminal 3 (simulate a marketplace grid)
bun run scripts/marketplace-sim.ts \
  --base-url http://127.0.0.1:8085 \
  --chain base \
  --collection 0x... \
  --start 1 \
  --count 100 \
  --concurrency 20 \
  --width medium
```

```bash
# Terminal 4 (capture rendered outputs)
bun run scripts/render-output.ts \
  --base-url http://127.0.0.1:8085 \
  --chain base \
  --collection 0x... \
  --start 1 \
  --count 100 \
  --output-dir ./pinned-testXX/outputs \
  --width 512 \
  --format png
```

### CI suggestions

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo audit
```

- Optional: `cargo deny check`

### Run (systemd example)

```env
[Unit]
Description=RMRK Renderer
After=network.target

[Service]
Type=simple
User=renderer
Group=renderer
WorkingDirectory=/opt/renderer
EnvironmentFile=/opt/renderer/.env
ExecStart=/opt/renderer/renderer
Restart=on-failure
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Replace `renderer` with your service user (e.g. `bitfalls`) and adjust paths to match your install.

After creating or updating the unit and env file:

```sh
sudo mkdir -p /var/lib/renderer /var/cache/renderer
sudo chown -R renderer:renderer /var/lib/renderer /var/cache/renderer

sudo systemctl daemon-reload
sudo systemctl enable --now renderer
sudo systemctl status renderer
```

If you update `/opt/renderer/.env` or swap the binary, restart the service (don't forget to +x chmod a new binary):

```sh
sudo systemctl restart renderer
sudo journalctl -u renderer -f
```

Then validate and reload nginx (renderer first, nginx second):

```sh
sudo nginx -t
sudo systemctl reload nginx
```

Quick sanity checks:

```sh
curl -I http://127.0.0.1:8080/
# If you expose it: curl -I http://127.0.0.1:8080/status
```

### Run (locally)

```sh
set -a
source .env
set +a
cargo run
# or ./target/release/proj-renderer if compiled
```

### Reverse proxy

Put a CDN or reverse proxy (e.g., Cloudflare or Nginx) in front if desired.
Cache control is safe because cache busting is URL-driven via the `cache=` parameter.

## Troubleshooting

### Failure log

- Failure responses (4xx/5xx) are logged as JSON lines to `FAILURE_LOG_PATH`.
- Set `FAILURE_LOG_PATH=off` to disable logging.
- `FAILURE_LOG_MAX_BYTES` caps file size (oldest entries are truncated).

### Warmup status

- `/status` and `/admin/api/warmup/status` include queued/running/done/failed counts.
- If warmups stop progressing, check pause state and resume via `/admin/api/warmup/resume`.
- Use `/admin/api/warmup/jobs` and `/admin/api/warmup/jobs/{id}/cancel` to inspect or stop jobs.

### Hash replacements

- Use the Admin UI → “Hash Replacements” to upload a static image for a CID that is missing or unpinned.
- The uploaded image is returned as-is (no resizing) whenever that CID is requested.
- Files are stored under `PINNED_DIR/hash-replacements/`.

## Notes

- Canvas size is derived from the first fixed part’s art. If SVG sizing is invalid,
  defaults are used and the collection should be reviewed.
- Raster layers that do not match the canonical canvas size are treated as nonconforming.
- Non-composable primary assets fall back to a single-layer render using asset metadata.
- Original-size fallback renders are not cached; resized/OG variants are.
- If a raster asset exceeds size limits, the renderer attempts a resize; if it still fails and
  `thumbnailUri` exists, the thumbnail is used.
- Usage identity keys for non-API requests include the client IP (ensure `TRUSTED_PROXY_CIDRS` is set when proxying).
- Failure responses (4xx/5xx) are logged as JSON lines to `FAILURE_LOG_PATH` (default `/var/log/renderer-failures.log`) and capped by `FAILURE_LOG_MAX_BYTES` (set `FAILURE_LOG_PATH=off` to disable).
- `?fresh=1` forces a state refresh and returns `Cache-Control: no-store`. If rate-limited, expect 429 with `Retry-After`.
- Oversized raster assets are fetched with a higher byte cap and resized to `MAX_RASTER_RESIZE_DIM` during pinning/asset fetch.
- Token warmup skips invalid/empty asset URIs (logged) so jobs can complete.
- Relative asset URIs are resolved against the metadata URI; `ar://` is normalized to `https://arweave.net/`.
- HTTP gateway URLs with `/ipfs/<cid>` are normalized to `ipfs://` so gateway rotation can recover from flaky gateways.
- Warmup renders **only cache** when a `cache_timestamp` is provided.
- See `PRODUCTION.md` for a deployment checklist and `openapi.yaml` for a minimal API spec.
- `*_PUBLIC` flags bypass access gating only; they do not disable routes entirely.
- Metrics: see `metrics/README.md` for Prometheus/Grafana setup and panel queries.
- Fallback overrides are served from `FALLBACKS_DIR` and can replace unapproved/failed renders.

### Deployment profiles

- Local dev: `ACCESS_MODE=open`, `REQUIRE_APPROVAL=false`, permissive limits.
- Staging: `ACCESS_MODE=key_required`, `OPENAPI_PUBLIC=false`, moderate limits.
- Prod: approvals on, key or allowlist mode, strict limits.

### CI checks

- `cargo fmt --check`
- `cargo clippy`
- `cargo test`
- `cargo audit` (or `cargo deny`) on a schedule

### Common footguns

- `TRUSTED_PROXY_CIDRS` too broad lets clients spoof IPs (rate limiting/denylist bypass).
- `ALLOW_PRIVATE_NETWORKS=true` enables internal SSRF paths; use only in trusted networks.
- `ALLOW_HTTP=true` weakens transport safety; keep off in production.
