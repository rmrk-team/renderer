# Renderer Metrics (Prometheus + Grafana)

This directory contains local-first Prometheus/Grafana configs for the renderer.

## Start the stack

```
docker compose -f docker-compose.metrics.yml up -d
```

By default Prometheus scrapes `host.docker.internal:8080`. If your renderer runs on a different
port, update `metrics/prometheus.yml`. On Linux, `host.docker.internal` may not resolve; use
`172.17.0.1` or run Prometheus on the host and scrape `127.0.0.1`.

## Copy/paste quickstart (auth)

1. Set a dedicated metrics token in the renderer:

```
METRICS_BEARER_TOKEN=change-me
```

2. Add authorization to the Prometheus scrape job:

```
scrape_configs:
  - job_name: renderer
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials: "change-me"
    static_configs:
      - targets: ["host.docker.internal:8080"]
```

On Linux, replace `host.docker.internal` with `172.17.0.1` (or scrape `127.0.0.1` if Prometheus runs on the host).

Security defaults:

- The compose file binds Prometheus, Grafana, and node_exporter to `127.0.0.1`.
- Anonymous Grafana access is disabled.
- Set `GRAFANA_ADMIN_USER` / `GRAFANA_ADMIN_PASSWORD` before first start.
- Do not expose these ports publicly; use SSH tunneling or a reverse proxy with auth if needed.
- Docker images are pinned to versions in `docker-compose.metrics.yml` for reproducibility.

Performance note:

- `METRICS_REFRESH_INTERVAL_SECONDS` controls the cheap refresh loop (set to `0` to disable).
- `METRICS_EXPENSIVE_REFRESH_SECONDS` controls disk scans for fallback/render counts (defaults to 300s).
- For ultra-high RPS, set `METRICS_TOP_IPS=0` and `METRICS_TOP_COLLECTIONS=0` to skip Top‑K work.

Grafana provisioning:

- The compose file mounts `metrics/grafana/dashboards/renderer.json` and auto-provisions it.

## Non-Docker setup (production-friendly)

1. Install Prometheus + Grafana (OS packages or upstream binaries).
2. Configure Prometheus to scrape the renderer:

```
scrape_configs:
  - job_name: renderer
    metrics_path: /metrics
    static_configs:
      - targets: ["127.0.0.1:8080"]
```

3. Provide access to `/metrics` via one of:

- `METRICS_ALLOW_IPS=127.0.0.1/32` (recommended for local scrape), or
- a dedicated bearer token (set `METRICS_BEARER_TOKEN`) in the Prometheus config:

```
scrape_configs:
  - job_name: renderer
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials: "<metrics-bearer-token>"
    static_configs:
      - targets: ["127.0.0.1:8080"]
```

4. Add Prometheus as a Grafana datasource and use the queries below to build panels.

Notes:

- Admin bearer (`ADMIN_PASSWORD`) can access `/metrics`. Set `METRICS_REQUIRE_ADMIN_KEY=true` if
  you want to require admin auth (allowlisted IPs and `METRICS_BEARER_TOKEN` still work).

## Dashboards (minimum viable panels)

### Renderer Overview
- Requests/sec: `sum(rate(renderer_http_requests_total[1m]))`
- Error rate: `sum(rate(renderer_render_requests_total{result="error"}[5m])) / sum(rate(renderer_render_requests_total[5m]))`
- p95/p99 render duration: `histogram_quantile(0.95, sum(rate(renderer_render_duration_seconds_bucket{stage="total"}[5m])) by (le))`
- Cache hit rate: `sum(rate(renderer_render_requests_total{result="cache_hit"}[5m])) / sum(rate(renderer_render_requests_total[5m]))`

### Cache
- Render cache bytes: `renderer_disk_bytes{path="render_cache"}`
- Asset cache bytes: `renderer_disk_bytes{path="asset_cache"}`
- Pinned bytes: `renderer_disk_bytes{path="pinned"}`
- Fallback bytes: `renderer_disk_bytes{path="fallbacks"}`
- Cache entries: `renderer_cache_entries`

### Upstreams
- RPC failures: `sum(rate(renderer_upstream_failures_total{kind="rpc_call"}[5m]))`
- IPFS/HTTP failures: `sum(rate(renderer_upstream_failures_total{kind=~"ipfs_fetch|http_fetch"}[5m]))`
- Fetch latency p95/p99: `histogram_quantile(0.95, sum(rate(renderer_fetch_duration_seconds_bucket[5m])) by (le, kind))`

### Top Consumers
- Top collections by bytes: `topk(10, rate(renderer_top_collection_bytes_total[5m]))`
- Top IPs by bytes: `topk(10, rate(renderer_top_ip_bytes_total[5m]))`
