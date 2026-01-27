# Renderer Metrics (Prometheus + Grafana)

This directory contains local-first Prometheus/Grafana configs for the renderer.
Native (non-Docker) installs are the primary production path; Docker compose is provided
for convenience.

## Start the stack

```
docker compose -f docker-compose.metrics.yml up -d
```

By default Prometheus scrapes `host.docker.internal:8080`. If your renderer runs on a different
port, update `metrics/prometheus.yml`. The compose file adds a Linux host‑gateway mapping, but if
`host.docker.internal` still does not resolve, use `172.17.0.1` or run Prometheus on the host and
scrape `127.0.0.1`.

Prometheus data is persisted in the `prometheus_data` volume.

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
- `/metrics` access is still private by default; use `METRICS_ALLOW_IPS` and/or
  `METRICS_BEARER_TOKEN` (recommended), and keep `METRICS_REQUIRE_ADMIN_KEY=true` in production.

Performance note:

- `METRICS_REFRESH_INTERVAL_SECONDS` controls the cheap refresh loop (set to `0` to disable).
- `METRICS_EXPENSIVE_REFRESH_SECONDS` controls disk scans for fallback/render counts (defaults to 300s).
- For ultra-high RPS, set `METRICS_TOP_IPS=0`, `METRICS_TOP_COLLECTIONS=0`,
  `METRICS_TOP_FAILURE_COLLECTIONS=0`, `METRICS_TOP_SOURCES=0`,
  `METRICS_TOP_FAILURE_REASONS=0`, and `METRICS_TOP_SOURCE_FAILURE_REASONS=0`
  to skip Top‑K work.

Grafana provisioning:

- The compose file mounts `metrics/grafana/dashboards/renderer.json` (overview) and
  `metrics/grafana/dashboards/full_dash.json` (full) and auto-provisions both.

## Non-Docker setup (production-friendly)

### Prometheus setup

1. Install Prometheus (OS package or upstream binary).
2. Edit the Prometheus config file:
   - Debian/Ubuntu: `/etc/prometheus/prometheus.yml`
   - Homebrew (macOS): `/usr/local/etc/prometheus.yml`
   - Custom path: run Prometheus with `--config.file=/path/to/prometheus.yml`
3. Add a scrape job for the renderer:

```
scrape_configs:
  - job_name: renderer
    metrics_path: /metrics
    static_configs:
      - targets: ["127.0.0.1:8080"]
```

4. Restart Prometheus (or re-run the binary) after updating the config.

### Metrics auth (renderer)

Provide access to `/metrics` via one of:

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

If Prometheus runs on another host, allowlist its IP or use the bearer token.

### Grafana setup

1. Install Grafana (OS package or upstream binary).
2. Start the service (Ubuntu):

```
sudo systemctl enable --now grafana-server
sudo systemctl status grafana-server
```

If it fails to start, check logs:

```
journalctl -u grafana-server -n 200 --no-pager
```

3. Access Grafana:
   - Local host: `http://127.0.0.1:3000`
   - Through nginx (recommended): `https://grafana.yourdomain.tld`

Default credentials are `admin` / `admin` (you will be prompted to change them on first login).

4. Add Prometheus as a datasource:
   - UI: Settings → Data sources → Add data source → Prometheus → URL `http://127.0.0.1:9090`
   - Or provisioning:

```
# /etc/grafana/provisioning/datasources/renderer.yml
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://127.0.0.1:9090
```

5. Import the dashboard:
   - UI: Dashboards → Import → upload `metrics/grafana/dashboards/renderer.json`, or
   - Provisioning:

```
# /etc/grafana/provisioning/dashboards/renderer.yml
apiVersion: 1
providers:
  - name: renderer
    type: file
    disableDeletion: true
    editable: false
    options:
      path: /var/lib/grafana/dashboards
```

Then copy the dashboard JSON to `/var/lib/grafana/dashboards/renderer.json`.

6. (Optional) nginx reverse proxy example:

```
server {
  listen 443 ssl;
  server_name grafana.yourdomain.tld;

  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

If you serve Grafana under a subpath (e.g. `/grafana/`), set:
`root_url = %(protocol)s://%(domain)s/grafana/` and `serve_from_sub_path = true`
in `/etc/grafana/grafana.ini`.

Notes:

- Admin bearer (`ADMIN_PASSWORD`) can access `/metrics`. Keep `METRICS_REQUIRE_ADMIN_KEY=true`
  in production; it prevents render allowlisted IPs from silently gaining metrics access.
- Source attribution for top-source metrics is derived from `Origin`/`Referer` host when available.
  For server-to-server callers, you can send `X-Renderer-Source: your-domain` to label requests.
- Failure metrics include non-success render outcomes (errors, fallbacks, queue/rate limits), so you
  can see which collections or sources are degrading even if a fallback image is returned.
- Cache hit/miss source bytes let you identify clients with poor cache behavior.

### Data retention (Prometheus)

Grafana does not store time-series data; Prometheus does. Retention applies to **all** metrics
(not just failures). To cap retention at 7 days:

- Docker: set `--storage.tsdb.retention.time=7d` in `docker-compose.metrics.yml` (already present).
- Linux systemd: set `--storage.tsdb.retention.time=7d` in the Prometheus service unit.
- Native binary: pass `--storage.tsdb.retention.time=7d` on the command line.
- To prevent disks from filling, consider adding a size cap:
  `--storage.tsdb.retention.size=<cap>` (e.g., `20GB`).
- Prometheus stores data under `--storage.tsdb.path` (Docker uses `/prometheus` in a named volume).
- For native installs, that path is often `/var/lib/prometheus` or `/usr/local/var/lib/prometheus`,
  but confirm in your service config.
- If you want to keep failures longer, increase or remove the retention limit (or use remote
  storage). Prometheus does not support per-metric retention.
- To wipe data immediately, stop Prometheus and delete its data directory.

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

Full dashboard additions:

- Top failing collections: `topk(10, rate(renderer_top_collection_failures_total[5m]))`
- Top failing sources: `topk(10, rate(renderer_top_source_failures_total[5m]))`
- Top sources by bytes: `topk(10, rate(renderer_top_source_bytes_total[5m]))`
- Top failure reasons: `topk(10, rate(renderer_top_failure_reasons_total[5m]))`
- Top source bytes (cache hit): `topk(10, rate(renderer_top_source_cache_hit_bytes_total[5m]))`
- Top source bytes (cache miss): `topk(10, rate(renderer_top_source_cache_miss_bytes_total[5m]))`
- Top failure reasons by source: `topk(10, rate(renderer_top_source_failure_reasons_total[5m]))`
- Cache hit ratio by source: `sum by (source) (rate(renderer_top_source_cache_hit_bytes_total[5m])) / (sum by (source) (rate(renderer_top_source_cache_hit_bytes_total[5m])) + sum by (source) (rate(renderer_top_source_cache_miss_bytes_total[5m])))`
