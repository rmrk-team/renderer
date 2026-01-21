# RMRK Renderer (proj-renderer)

Standalone Rust service that renders RMRK equippable NFTs into flat images.
SVG-first rendering, deterministic caching, and a minimal admin API.

## Features

- Canonical render endpoints with cache-busting via `cache=` query param
- SVG + PNG/JPG asset support (SVG rasterized with `resvg`)
- Deterministic canvas size derived from first fixed part
- Partial renders are **not cached**
- IPFS gateway rotation + asset caching
- Warmup queue with safe concurrency
- Embedded admin panel (`/admin`) with JSON API

## Quickstart

```bash
cd proj-renderer
cargo build --release

export ADMIN_PASSWORD="change-me"
export RPC_ENDPOINTS='{"base":["https://mainnet.base.org"]}'
export RENDER_UTILS_ADDRESSES='{"base":"0xYourRMRKEquipRenderUtils"}'

./target/release/proj-renderer
```

See `env.example` for a full configuration template.

Health check:

```bash
curl http://localhost:8080/healthz
```

## Configuration

All configuration is done via environment variables.

### Required

```env
ADMIN_PASSWORD=your-secure-password
RPC_ENDPOINTS={"base":["https://mainnet.base.org"]}
RENDER_UTILS_ADDRESSES={"base":"0x..."}
```

### Optional (common)

```env
HOST=0.0.0.0
PORT=8080
DB_PATH=/var/lib/renderer/renderer.db
CACHE_DIR=/var/cache/renderer
CACHE_MAX_SIZE_GB=50
RENDER_CACHE_MIN_TTL_DAYS=7
ASSET_CACHE_MIN_TTL_DAYS=30
CACHE_EVICT_INTERVAL_SECONDS=3600
CACHE_SIZE_REFRESH_SECONDS=60
MAX_CONCURRENT_RENDERS=4
MAX_CONCURRENT_IPFS_FETCHES=16
MAX_CONCURRENT_RPC_CALLS=16
MAX_IN_FLIGHT_REQUESTS=512
MAX_ADMIN_BODY_BYTES=1048576
RATE_LIMIT_PER_MINUTE=0
RATE_LIMIT_BURST=0
ACCESS_MODE=open
API_KEY_SECRET=change-me
KEY_RATE_LIMIT_PER_MINUTE=0
KEY_RATE_LIMIT_BURST=0
AUTH_FAILURE_RATE_LIMIT_PER_MINUTE=0
AUTH_FAILURE_RATE_LIMIT_BURST=0
TRACK_KEYS_IN_OPEN_MODE=false
USAGE_RETENTION_DAYS=30
RENDER_QUEUE_CAPACITY=256
RENDER_LAYER_CONCURRENCY=8
COMPOSITE_CACHE_ENABLED=true
PRIMARY_ASSET_CACHE_TTL_SECONDS=60
PRIMARY_ASSET_NEGATIVE_TTL_SECONDS=15
PRIMARY_ASSET_CACHE_CAPACITY=10000
OUTBOUND_CLIENT_CACHE_TTL_SECONDS=900
OUTBOUND_CLIENT_CACHE_CAPACITY=256
RPC_TIMEOUT_SECONDS=30
RPC_CONNECT_TIMEOUT_SECONDS=5
DEFAULT_CANVAS_WIDTH=1080
DEFAULT_CANVAS_HEIGHT=1512
DEFAULT_CACHE_TIMESTAMP=0
CHILD_LAYER_MODE=above_slot
RASTER_MISMATCH_FIXED=top_left_no_scale
RASTER_MISMATCH_CHILD=top_left_no_scale
COLLECTION_RENDER_OVERRIDES={}
ALLOW_HTTP=false
ALLOW_PRIVATE_NETWORKS=false
LANDING_PUBLIC=false
STATUS_PUBLIC=false
```

### IPFS / metadata limits

```env
IPFS_GATEWAYS=["https://rmrk.myfilebase.com/ipfs/","https://cloudflare-ipfs.com/ipfs/","https://ipfs.io/ipfs/"]
IPFS_TIMEOUT_SECONDS=30
MAX_METADATA_JSON_BYTES=524288
MAX_SVG_BYTES=2097152
MAX_SVG_NODE_COUNT=200000
MAX_RASTER_BYTES=10485760
MAX_LAYERS_PER_RENDER=200
MAX_CANVAS_PIXELS=50000000
MAX_TOTAL_RASTER_PIXELS=250000000
MAX_DECODED_RASTER_PIXELS=50000000
MAX_CACHE_VARIANTS_PER_KEY=5
MAX_OVERLAY_LENGTH=64
MAX_BG_LENGTH=64
```

Note: outbound HTTP(S) fetches block private/loopback/link-local hosts and do not
follow redirects by default. Use `ALLOW_PRIVATE_NETWORKS=true` only in trusted
environments.

Render safety caps:

- `MAX_LAYERS_PER_RENDER` limits total layers processed per render.
- `MAX_CANVAS_PIXELS` caps the canvas area (width × height).
- `MAX_TOTAL_RASTER_PIXELS` caps total raster pixels across layers.
- `MAX_DECODED_RASTER_PIXELS` caps raster decode dimensions before allocation.
- `MAX_CACHE_VARIANTS_PER_KEY` limits cached timestamps per token/variant (evicts oldest).
- `MAX_OVERLAY_LENGTH` and `MAX_BG_LENGTH` cap query param length.

HTTP safety caps:

- `MAX_IN_FLIGHT_REQUESTS` limits total concurrent HTTP requests.
- `RATE_LIMIT_PER_MINUTE` / `RATE_LIMIT_BURST` enable per-IP rate limiting (0 disables).
- `MAX_ADMIN_BODY_BYTES` caps admin API request bodies.
- Asset/metadata fetches resolve DNS once per request and pin the connection to the resolved IPs to reduce DNS rebinding risk.
- `CACHE_SIZE_REFRESH_SECONDS` controls how often cache size stats are refreshed for `/status` and admin dashboard.
- `OUTBOUND_CLIENT_CACHE_TTL_SECONDS` / `OUTBOUND_CLIENT_CACHE_CAPACITY` cache pinned HTTP clients for outbound fetches.
- `CACHE_EVICT_INTERVAL_SECONDS` sets how often the cache eviction loop runs (0 disables).
- `MAX_CONCURRENT_RPC_CALLS` caps concurrent RPC calls (primary-route lookups + warmup fallbacks).
- `PRIMARY_ASSET_NEGATIVE_TTL_SECONDS` caches failed primary-asset lookups briefly to avoid RPC hammering.

### Render policy overrides

- `CHILD_LAYER_MODE`: `above_slot`, `below_slot`, `same_z_after`, or `same_z_before`.
- `RASTER_MISMATCH_FIXED`: `error`, `scale_to_canvas`, `center_no_scale`, or `top_left_no_scale`.
- `RASTER_MISMATCH_CHILD`: same values as `RASTER_MISMATCH_FIXED`, applied to equipped child layers.
- `COLLECTION_RENDER_OVERRIDES`: JSON map `"chain:collection" => { child_layer_mode, raster_mismatch_fixed, raster_mismatch_child }`.

Access control:

- `ACCESS_MODE`: `open`, `key_required`, `hybrid`, `denylist_only`, or `allowlist_only`.
- `API_KEY_SECRET`: required unless `ACCESS_MODE=open`.
- `KEY_RATE_LIMIT_PER_MINUTE` / `KEY_RATE_LIMIT_BURST`: default per-key limits (overrides can be set per key).
- `AUTH_FAILURE_RATE_LIMIT_PER_MINUTE` / `AUTH_FAILURE_RATE_LIMIT_BURST`: rate limit for unauthorized requests.
- `USAGE_RETENTION_DAYS`: retention for hourly usage aggregates (0 disables cleanup).
- `TRACK_KEYS_IN_OPEN_MODE`: when `ACCESS_MODE=open` or `denylist_only`, skip DB lookups for bearer tokens unless set to `true`.

AccessMode semantics:

- `open`: all requests allowed.
- `key_required`: only valid API keys allowed.
- `hybrid`: valid API keys always allowed; otherwise deny if an IP rule matches `deny`.
- `denylist_only`: deny if API key is inactive or IP rule matches `deny`.
- `allowlist_only`: allow if API key is active; otherwise allow only if IP rule matches `allow`.

IP rule precedence: longest CIDR prefix wins; on ties, `deny` beats `allow`.

### Security invariants

- SVG parsing must never read local files.
- HTTP fetches must never reach private/loopback/link-local IPs.
- `overlay` and `bg` are normalized before cache key creation.

### Hosted approvals (optional)

```env
REQUIRE_APPROVAL=true
APPROVALS_CONTRACTS={"base":"0xYourRendererApprovalsContract"}
APPROVALS_CONTRACT_CHAIN=base
CHAIN_ID_MAP={"1":"ethereum","56":"bsc","137":"polygon","8453":"base","84532":"base-sepolia","1284":"moonbeam","1285":"moonriver","1287":"moonbase-alpha","31337":"hardhat"}
APPROVAL_START_BLOCKS={"base":123456}
APPROVAL_POLL_INTERVAL_SECONDS=30
APPROVAL_CONFIRMATIONS=6
APPROVAL_SYNC_INTERVAL_SECONDS=900
APPROVAL_NEGATIVE_CACHE_CAPACITY=10000
APPROVAL_ENUMERATION_ENABLED=true
MAX_APPROVAL_STALENESS_SECONDS=0
```

Set `APPROVAL_POLL_INTERVAL_SECONDS=0` to disable approval watchers.
`APPROVAL_NEGATIVE_CACHE_SECONDS` and `APPROVAL_NEGATIVE_CACHE_CAPACITY` control
the in-memory negative cache for on-demand approval checks.
If `REQUIRE_APPROVAL=true` and you accept open traffic, use `ACCESS_MODE=key_required`
or strict rate limits to prevent on-demand approval checks from becoming an RPC
cost/availability lever.
Include a chain ID entry for every chain you enable.

### Renderer approvals contract deployment (Base)

The Foundry subproject lives at `proj-renderer/renderer-contracts` and contains
`RendererApprovalsV2` (the on-chain approval policy).

```bash
cd proj-renderer/renderer-contracts

export BASE_RPC_URL=https://mainnet.base.org
export PRIVATE_KEY=<deployer_private_key>
export APPROVALS_TOKEN=<erc20_fee_token>
export APPROVALS_TREASURY=<treasury_address>
export APPROVALS_FEE=<fee_in_smallest_unit>
export ETHERSCAN_API_KEY=<basescan_api_key>

forge script script/DeployRendererApprovals.s.sol:DeployRendererApprovals \
  --rpc-url "$BASE_RPC_URL" \
  --broadcast \
  --verify \
  --etherscan-api-key "$ETHERSCAN_API_KEY" \
  --retries 10 \
  --delay 15
```
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
Set `OPENAPI_PUBLIC=true` to expose `/openapi.yaml` without access gating.

### Reverse proxy deployment

When deploying behind a reverse proxy (nginx/ALB/Cloudflare):

- Set `TRUSTED_PROXY_CIDRS` to the proxy’s IP ranges.
- Keep `RATE_LIMIT_PER_MINUTE` / `AUTH_FAILURE_RATE_LIMIT_PER_MINUTE` enabled at the proxy and app.
- Terminate TLS at the proxy, and forward `X-Forwarded-For` / `Forwarded`.
- Avoid overly broad `TRUSTED_PROXY_CIDRS` like `0.0.0.0/0` unless you fully trust clients.
- Configure the proxy to **overwrite** forwarded headers; the app selects the last untrusted IP in the chain (bounded to 20 entries).
- If you have multiple proxies (e.g., Cloudflare → nginx), include **all** proxy CIDRs in `TRUSTED_PROXY_CIDRS` or client IP attribution will break.

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

`HEAD` is supported on cached render routes and returns headers without a body.

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
- `X-Renderer-Missing-Layers: <count>` (when missing required layers)
- `X-Renderer-Nonconforming-Layers: <count>` (when PNG/JPG sizes mismatch)
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

### Warmup queue

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

## Build & Deploy

### Build

```bash
cargo build --release
```

### Tests

```bash
cargo test
```

### CI suggestions

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test`
- `cargo audit`
- Optional: `cargo deny check`

### Run (systemd example)

```env
[Unit]
Description=RMRK Renderer
After=network.target

[Service]
Type=simple
User=renderer
WorkingDirectory=/opt/proj-renderer
EnvironmentFile=/etc/renderer.env
ExecStart=/opt/proj-renderer/target/release/proj-renderer
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
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

## Notes

- Canvas size is derived from the first fixed part’s art. If SVG sizing is invalid,
  defaults are used and the collection should be reviewed.
- PNG/JPG layers that do not match the canonical canvas size are treated as nonconforming.
- Warmup renders **only cache** when a `cache_timestamp` is provided.
- See `PRODUCTION.md` for a deployment checklist and `openapi.yaml` for a minimal API spec.
- The OpenAPI spec is served at `/openapi.yaml`; set `OPENAPI_PUBLIC=false` to gate it.
