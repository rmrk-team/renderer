# Production checklist

This renderer is exposed to untrusted input. Use the checklist below before
shipping a public instance.

## Required env vars

- `ADMIN_PASSWORD` set to a strong secret.
- `RPC_ENDPOINTS` and `RENDER_UTILS_ADDRESSES` configured for your chains.

## Recommended safety defaults

- `ALLOW_HTTP=false` and `ALLOW_PRIVATE_NETWORKS=false`.
- `MAX_IN_FLIGHT_REQUESTS` set to a sane ceiling (e.g., 256–1024).
- `RATE_LIMIT_PER_MINUTE` / `RATE_LIMIT_BURST` enabled for public traffic.
- `MAX_ADMIN_BODY_BYTES` kept low (<= 1MB).
- `MAX_DECODED_RASTER_PIXELS` aligned with `MAX_CANVAS_PIXELS`.
- `MAX_LAYERS_PER_RENDER` / `MAX_TOTAL_RASTER_PIXELS` tuned to your hardware.
- `MAX_CONCURRENT_RPC_CALLS` set to protect RPC providers.
- If using API keys, set `ACCESS_MODE` and a strong `API_KEY_SECRET`.
- Set `USAGE_RETENTION_DAYS` to keep usage tables bounded.
  - Consider `PRIMARY_ASSET_NEGATIVE_TTL_SECONDS` to reduce RPC hammering.

## Reverse proxy / CDN

- Enforce max URL length, header size, and body size upstream.
- Apply per-IP rate limits and caching at the edge when possible.
- Set request timeouts appropriate for render latency.
- Overwrite `X-Forwarded-For` / `Forwarded` headers and block direct access to the app port.
- If multiple proxies are in the path, include all CIDR ranges in `TRUSTED_PROXY_CIDRS`.

## Network egress

- Enforce **deny-by-default** egress (block RFC1918/metadata ranges).
- Keep DNS rebinding mitigations at the network layer.

## Logging and observability

- Do not log `Authorization`, `Cookie`, or `Set-Cookie` headers.
- Avoid DEBUG logging in production unless headers are explicitly redacted.

## Storage

- Monitor cache disk usage; set `CACHE_MAX_SIZE_GB` conservatively.
- Use fast local disk if possible; cached renders are read frequently.
- If `PINNING_ENABLED=true`, plan and monitor `PINNED_DIR` growth (pinned assets are never evicted).
- Keep `FALLBACKS_DIR` outside `CACHE_DIR` so cache purges never delete fallback assets.

## Suggested deployment profiles

These are starting points. Tune to your RPC latency, render complexity, and
available CPU/RAM.

### Profile A: shared host (1–2 vCPU, 2–4GB RAM, other apps running)

```env
MAX_CONCURRENT_RENDERS=2
MAX_CONCURRENT_IPFS_FETCHES=8
MAX_CONCURRENT_RPC_CALLS=8
MAX_IN_FLIGHT_REQUESTS=256
RENDER_QUEUE_CAPACITY=128
RENDER_LAYER_CONCURRENCY=6
CACHE_MAX_SIZE_GB=10
CACHE_EVICT_INTERVAL_SECONDS=3600
CACHE_SIZE_REFRESH_SECONDS=120
PRIMARY_ASSET_CACHE_TTL_SECONDS=60
PRIMARY_ASSET_NEGATIVE_TTL_SECONDS=15
PRIMARY_ASSET_CACHE_CAPACITY=5000
OUTBOUND_CLIENT_CACHE_TTL_SECONDS=900
OUTBOUND_CLIENT_CACHE_CAPACITY=128
RATE_LIMIT_PER_MINUTE=120
RATE_LIMIT_BURST=60
AUTH_FAILURE_RATE_LIMIT_PER_MINUTE=30
AUTH_FAILURE_RATE_LIMIT_BURST=15
WARMUP_MAX_TOKENS=500
WARMUP_MAX_RENDERS_PER_JOB=4
WARMUP_JOB_TIMEOUT_SECONDS=600
```

### Profile B: dedicated renderer host (2–4 vCPU, 4–8GB RAM, renderer only)

```env
MAX_CONCURRENT_RENDERS=6
MAX_CONCURRENT_IPFS_FETCHES=24
MAX_CONCURRENT_RPC_CALLS=16
MAX_IN_FLIGHT_REQUESTS=1024
RENDER_QUEUE_CAPACITY=768
RENDER_LAYER_CONCURRENCY=12
CACHE_MAX_SIZE_GB=50
CACHE_EVICT_INTERVAL_SECONDS=1800
CACHE_SIZE_REFRESH_SECONDS=60
PRIMARY_ASSET_CACHE_TTL_SECONDS=60
PRIMARY_ASSET_NEGATIVE_TTL_SECONDS=20
PRIMARY_ASSET_CACHE_CAPACITY=20000
OUTBOUND_CLIENT_CACHE_TTL_SECONDS=1800
OUTBOUND_CLIENT_CACHE_CAPACITY=512
RATE_LIMIT_PER_MINUTE=300
RATE_LIMIT_BURST=150
AUTH_FAILURE_RATE_LIMIT_PER_MINUTE=60
AUTH_FAILURE_RATE_LIMIT_BURST=30
WARMUP_MAX_TOKENS=1500
WARMUP_MAX_RENDERS_PER_JOB=8
WARMUP_JOB_TIMEOUT_SECONDS=900
```

Notes:

- If RPC providers are slow or rate-limited, reduce `MAX_CONCURRENT_RENDERS`
  and `MAX_CONCURRENT_IPFS_FETCHES`.
- If disk is limited, lower `CACHE_MAX_SIZE_GB` and `PRIMARY_ASSET_CACHE_CAPACITY`.
- If you expose `/status`, avoid polling it more than once per minute.

## Landing page (optional)

- Set both `LANDING_DIR` and `LANDING`; do not default to `.`.
- Serve only the intended static assets from that directory.
- `LANDING` must be an `.html` file; landing is disabled on Windows builds.
