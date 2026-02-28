# Renderer Debug Playbook

## 1. Reproduce Precisely

1. Start from the user's exact failing URL.
2. Probe token-only route and canonical route.
3. Capture:
- Status code
- Redirect `location` (primary asset id)
- `X-Renderer-*` headers
- JSON error body if returned

Use:

```bash
skills/renderer-debug/scripts/probe-render.sh \
  https://renderer.rmrk.app base 0xCOLLECTION 1234 png
```

## 2. Run Local Renderer With Comparable Inputs

Use project `.env`, but force writable temp paths:

```bash
set -a; source .env; set +a
export I_KNOW_WHAT_I_AM_DOING=true
export DB_PATH=/tmp/proj-renderer-debug/renderer.db
export CACHE_DIR=/tmp/proj-renderer-debug/cache
export FALLBACKS_DIR=/tmp/proj-renderer-debug/fallbacks
export PINNED_DIR=/tmp/proj-renderer-debug/pinned
export FAILURE_LOG_PATH=/tmp/proj-renderer-debug/logs/renderer-failures.log
export DEBUG_RENDER_TOKENS=1234
export DEBUG_RENDER_COLLECTIONS=0xcollection
export RUST_LOG=proj_renderer=debug,sqlx=warn
cargo run
```

If startup fails in open access mode, set `I_KNOW_WHAT_I_AM_DOING=true` or configure rate limits.

## 3. Interpret Common Failure Signatures

- `307` + `x-renderer-primary-assetid`: Token-only route is healthy; inspect canonical route.
- `x-renderer-fallback=timeout_render`: Render timed out; fallback image returned with `Retry-After`.
- `x-renderer-error-code=render_failed`: Hard render failure; inspect logs for concrete reason.
- `x-renderer-error-code=primary_asset_lookup_failed`: Top-asset lookup failed or negative-cached.
- `x-renderer-fallback=token_state_cached`: Cached error backoff path is active.
- `x-renderer-fallback=unapproved`: Approval gating, not renderer composition failure.

## 4. Trace Root Cause From Logs

Target log markers:

- `debug compose ... fixed_parts=... slot_parts=...`
- `top asset lookup reverted ...`
- `failed to fetch parent metadata for theme`
- `render timed out ...`
- `render failed error=...`

Most useful invariants:

- `fixed_parts=[]` with no fallback strategy often leads to canvas derivation failure.
- Unreachable metadata CID/URI commonly causes timeouts and downstream render errors.
- Fallback responses can mask the underlying error unless `debug=1`/`raw=1` is allowed.

## 5. Verify Upstream Content, Not Only Renderer Code

For metadata CIDs:

```bash
CID=Qm...
for u in \
  "https://rmrk.myfilebase.com/ipfs/$CID" \
  "https://gateway.pinata.cloud/ipfs/$CID" \
  "https://dweb.link/ipfs/$CID" \
  "https://cloudflare-ipfs.com/ipfs/$CID" \
  "https://ipfs.io/ipfs/$CID"
do
  echo "== $u"
  curl -sS -L --max-time 12 -o /tmp/cid.out -w 'http_code=%{http_code} total=%{time_total}s size=%{size_download}\n' "$u" || true
done
```

If all gateways fail (timeout/429/5xx), treat as upstream content availability issue.

## 6. Inspect Cached Token State

```bash
sqlite3 /tmp/proj-renderer-debug/renderer.db \
  "select chain,collection_address,token_id,asset_id,last_error,expires_at,fallback_used,last_checked_at \
   from token_state_cache \
   where chain='base' and collection_address='0xcollection' and token_id='1234';"
```

Also inspect failure log:

```bash
rg -n "0xcollection|1234" /tmp/proj-renderer-debug/logs/renderer-failures.log
```

## 7. Non-Rendering NFT Decision Rules

1. `307` redirects but canonical `500 render_failed`:
- Renderer can resolve primary asset, but composition/content rendering fails.

2. Canonical sometimes returns timeout fallback and sometimes 500:
- Usually unstable gateway timing around the same metadata URI/CID.
- Distinguish symptom (`timeout_render`) from structural error (for example no fixed parts).

3. `fixed_parts=[]` and missing render fallback image:
- Expect hard 5xx unless code falls back to tokenURI/single-layer path.
- Apply collection render fallback or token override as immediate mitigation.

4. `primary_asset_lookup_failed` without redirect:
- Investigate on-chain top-asset lookup selectors and capability strategy.

## 8. Recommended Remediation Types

- Content remediation:
  - Re-pin/fix metadata CID.
  - Fix malformed/empty metadata image fields.
- Runtime remediation:
  - Upload collection render fallback.
  - Upload per-token override for known-bad token.
- Code remediation:
  - Add safe fallback when compose returns zero fixed parts.
  - Improve cached error handling and backoff behavior for repeated metadata failures.
