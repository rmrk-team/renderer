# Development

## Run locally
```bash
export ADMIN_PASSWORD="change-me"
export DB_PATH="./tmp/renderer.db"
export CACHE_DIR="./tmp/cache"
export FALLBACKS_DIR="./tmp/fallbacks"
export PINNED_DIR="./tmp/pinned"
export ACCESS_MODE="open"
export REQUIRE_APPROVAL="false"
export RPC_ENDPOINTS='{"base":["https://mainnet.base.org"]}'

cargo run
```

Smoke check:
```bash
curl http://127.0.0.1:8080/healthz
```

Note: keep `FALLBACKS_DIR` outside `CACHE_DIR` so cache purges never delete fallbacks.

## Tests
```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
```

## Warmup flow
1. Approve the collection (if approvals are required).
2. Phase A: catalog warmup.
3. Phase B: token warmup (range or manual IDs).
4. Phase C: optional render warmup for common sizes.

## Debugging
- `DEBUG_RENDER_TOKENS` / `DEBUG_RENDER_COLLECTIONS` to narrow logging.
- `FAILURE_LOG_PATH` for JSON failure logs.
