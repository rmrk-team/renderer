# Renderer Metrics (Prometheus + Grafana)

This directory contains local-first Prometheus/Grafana configs for the renderer.

## Start the stack

```
docker compose -f docker-compose.metrics.yml up -d
```

By default Prometheus scrapes `host.docker.internal:8080`. If your renderer runs on a different
port, update `metrics/prometheus.yml`.

Security defaults:

- The compose file binds Prometheus, Grafana, and node_exporter to `127.0.0.1`.
- Anonymous Grafana access is disabled.
- Set `GRAFANA_ADMIN_USER` / `GRAFANA_ADMIN_PASSWORD` before first start.
- Do not expose these ports publicly; use SSH tunneling or a reverse proxy with auth if needed.

Performance note:

- `METRICS_REFRESH_INTERVAL_SECONDS` controls the cheap refresh loop (set to `0` to disable).
- `METRICS_EXPENSIVE_REFRESH_SECONDS` controls disk scans for fallback/render counts (defaults to 300s).

Grafana provisioning:

- The compose file mounts `metrics/dashboards/renderer-overview.json` and auto-provisions it.

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
- a bearer token in the Prometheus config:

```
scrape_configs:
  - job_name: renderer
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials: "<api-key-or-admin-password>"
    static_configs:
      - targets: ["127.0.0.1:8080"]
```

4. Add Prometheus as a Grafana datasource and use the queries below to build panels.

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
