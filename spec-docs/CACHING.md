# How caching works

This document summarizes the renderer caching layers and when cache epochs are required.

## Cache layers

### Raw asset cache
- Caches fetched metadata JSON and raw art bytes (IPFS/HTTP).
- Reduces upstream fetch traffic and amortizes IPFS gateway latency.

### Raster cache
- Stores rasterized PNG output for SVG layers.
- Keyed by SVG bytes + canvas size.
- Avoids repeated SVG parse/render for repeated assets.

### Composite cache
- Stores composited PNG results for layered renders.
- Keyed by chain/collection/token/asset + cache epoch + variant key.
- Used before final encoding to avoid repeating layer composition.

### Render cache
- Stores the final response bytes per format (webp/png/jpg).
- Keyed by chain/collection/token/asset + cache epoch + variant key + format.
- This is what `HEAD` cache probes are checking.

## What goes into a cache key

- Chain + collection + token ID + asset ID.
- Cache timestamp (epoch).
- Variant key (width, OG mode, overlay, background).
- Output format (webp/png/jpg/jpeg).

Changing any of these inputs results in a new cache entry.

## `cache=` parameter rules

### When `cache=` is allowed
- Authenticated requests (API key or allowlisted IP) can provide any `cache=` value.
- Anonymous requests can only provide `cache=` within the configured
  `ANON_CACHE_EPOCH_WINDOW_MS` window around the collection epoch.
- If the provided `cache=` is not allowed, it is ignored and the request
  falls back to the resolved epoch.

### When `cache=` is required
- Explicit `cache=` is not required for normal requests.
- The renderer will resolve a cache timestamp using the collection epoch
  or the configured `DEFAULT_CACHE_TTL_SECONDS` fallback.

## Collection epochs

- Each collection has a cache epoch stored in the database.
- Epochs are cached in memory for efficiency.
- Bumping a collection epoch invalidates composite/render caches by changing
  the cache timestamp used in keys.

If you are running warmups or cache probes, prefer using the resolved epoch
to avoid unnecessary cache churn.
