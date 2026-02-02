# Heavy Render Problem (Kanaria SVGs)

## Summary

Some Kanaria SVG layers are extremely expensive to rasterize at full resolution
(1080x1512). The renderer spends the majority of render time inside `svg_render`
and `rasterize_svg_total`, even when network fetches are fast. This inflates
render latency, increases queue pressure, and creates timeouts under concurrent
load.

The bottleneck is not explained by node count alone. The slowest SVGs are heavy
in gradient stops and clip paths, and often embed raster images. These features
inflate the rendering cost in `resvg`/`tiny-skia` even when node counts are
moderate.

## Evidence (Recent Profiling)

Profiling was collected with `RUST_LOG=proj_renderer=debug` and layer profiling
enabled. The renderer logs `svg_render` with complexity stats extracted from the
parsed `usvg::Tree`.

From run `2026-01-30T19-31-35-109Z-a4158dd`:

- `ipfs://QmbDqHraq1zs3iPK2X8sgoeVGrb1gbt2FWXkj5e3ptzCCp/default_background.svg`
  - `svg_render` ~18.9s, `nodes=478`
  - `linear+radial gradients=21`, `gradient_stops=68`
  - `clipPaths=15`, `masks=1`, `filters=0`
- `ipfs://QmWJGXcHg8u9qXHAn4bvCqwZgZqYJ4toDKv7JiNobr7VLF/rarity_superfounder.svg`
  - `svg_render` ~12.4s, `nodes=812`
  - `linear+radial gradients=106`, `gradient_stops=1145`
  - `clipPaths=49`, `filters=0`
- `ipfs://QmWJGXcHg8u9qXHAn4bvCqwZgZqYJ4toDKv7JiNobr7VLF/rarity_limited.svg`
  - `svg_render` ~7.1s, `nodes=69`
  - `linear+radial gradients=24`, `gradient_stops=222`
  - `clipPaths=2`, `filters=0`

Observations:

- Node count alone does not predict cost (`nodes=69` still ~7s).
- Gradient stop count and clip-path usage correlate with render time.
- These SVGs render at 1080x1512 even for small width presets.

## Impact

- Cold renders for Kanaria can spend 10-20s on a *single* layer.
- Render queues back up under modest parallel load.
- Tail latency grows quickly because CPU-heavy rasterization competes with
  async runtime tasks.

## Current Caching Behavior

- **Compose cache** short-circuits *all* rendering work when the token state is
  cached and valid. This is why `cached` benchmark mode shows near-zero time and
  no `svg_render` logs.
- **Raster cache** stores PNGs keyed by `art_uri` + canvas size + variant. This
  helps only when the same SVG is rendered at the same size/variant.
- In practice, a single benchmark run often sees *one miss per heavy SVG* even
  if a few hits appear later, because variant/size differences create distinct
  cache keys.

## Reproduction

1. Run benchmark with debug logs enabled:
   - `bun run scripts/renderer-benchmark.ts --modes fresh --iterations 1`
2. Inspect `benchmarks/runs/<runId>/fresh.log` for `step="svg_render"` and
   `svg_*` fields.
3. Observe `svg_render` elapsed times for the heavy SVGs listed above.

## Likely Root Causes

- Heavy gradients and clip paths cause expensive path evaluation and raster
  blending in `resvg`.
- Embedded raster images increase memory pressure and render setup time.
- Each unique size/variant leads to a separate raster cache entry; most
  requests do not reuse the exact same cached raster.

## Possible Solutions

### Renderer-Level Changes

1. **Canonical-size raster cache with downscaling**
   - Rasterize once at canonical size, then downscale for width presets.
   - Reduces duplicate raster work across variants.
2. **Pre-rasterization during warmup**
   - Detect heavy SVGs by complexity stats and precompute PNGs.
   - Store pre-rasterized PNGs in raster cache keyed by canonical size.
3. **Complexity-aware throttling**
   - If gradients/stops exceed a threshold, route to a lower-priority pool or
     reduce concurrency for that layer to prevent queue starvation.
4. **Content-aware fallback**
   - For extremely heavy assets, optionally render at a lower resolution or
     use a pre-approved PNG override.

### Content-Level Changes

1. **Pre-render heavy SVGs to PNG**
   - Store as pinned/static assets and reference via metadata overrides.
2. **Simplify SVGs**
   - Reduce gradient stop counts, clip-path nesting, and embedded rasters.

### Operational Changes

1. **Warmup critical collections**
   - Ensure hot assets and their raster caches are built before traffic.
2. **Dedicated render capacity**
   - Use higher `MAX_BLOCKING_TASKS` or separate instances for heavy collections
     if workload isolation is required.

## Mitigations applied

- Render timeouts now record a token-state timeout error (TTL controlled by
  `TOKEN_STATE_ERROR_TTL_SECONDS`) so subsequent requests short-circuit to
  fallback instead of redoing heavy CPU work immediately.
- Timeout events enqueue a token warmup job (best-effort) to populate caches in
  the background.
- Heavy SVG detection thresholds route complex layers through a dedicated
  `HEAVY_SVG_CONCURRENCY` semaphore to isolate tail latency.
- SVG fast-path rasterization (`SVG_FAST_PATH_MAX_WIDTH` /
  `SVG_FAST_PATH_TARGET_WIDTH`) reduces heavy SVG cost for small widths.
- Scaled render mode (`SCALED_RENDER_MAX_WIDTH`) composites small outputs at
  scaled canvas sizes and skips the final downscale.

## Observability

- `renderer_heavy_svg_hit_total`
- `renderer_heavy_svg_queue_wait_seconds`
- `renderer_heavy_svg_raster_seconds`

These are exported to Prometheus and included in the Grafana full dashboard.

## Notes

- These issues are expected for SVGs with heavy gradients and clip paths.
- The current profiling instrumentation captures enough detail to automate
  complexity-driven decisions (e.g., pre-rasterization thresholds).
