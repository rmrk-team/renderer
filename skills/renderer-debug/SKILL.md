---
name: renderer-debug
description: Diagnose failing or incorrect NFT renders in the RMRK renderer service. Use when `/render` or `/og` responses return 4xx/5xx, unexpected fallback images, timeouts, missing layers, wrong primary asset redirects, or token-specific rendering mismatches. Covers local reproduction with project `.env`, production parity checks, header/error-code triage, render-log tracing, and upstream metadata/IPFS validation.
---

# Renderer Debug

## Overview

Resolve renderer failures quickly and consistently by following one deterministic investigation flow.
Prefer concrete evidence from headers, redirect targets, logs, DB cache rows, and upstream metadata fetches.

## Workflow

1. Reproduce exact failure route.
- Check token-only route first (`/render/{chain}/{collection}/{token}.{format}`) to capture redirect and primary asset id.
- Check canonical route (`/render/{chain}/{collection}/{token}/{asset}/{format}`) to isolate rendering itself.
- Run [`scripts/probe-render.sh`](scripts/probe-render.sh) for fast triage summaries.

2. Confirm production vs local parity.
- Probe production URL (`https://renderer.rmrk.app`) and local URL with same path/query.
- If local differs, run local server with project `.env` plus writable temp overrides (`DB_PATH`, `CACHE_DIR`, `FALLBACKS_DIR`, `PINNED_DIR`, `FAILURE_LOG_PATH`).
- Enable targeted debug logs with `DEBUG_RENDER_TOKENS` and `DEBUG_RENDER_COLLECTIONS`.

3. Classify failure by renderer signals.
- Read `X-Renderer-*` headers and JSON `code`.
- Treat `X-Renderer-Fallback` as a controlled fallback path.
- Treat `x-renderer-error-code=render_failed` as true render failure; inspect server logs for the concrete reason.
- Distinguish timeout fallback (`timeout_render`) from hard failures (`render_failed`).

4. Trace compose and asset provenance.
- Extract compose shape from debug logs (`fixed_parts`, `slot_parts`, `metadata_uri`, `catalog_address`).
- If compose has no required fixed parts, expect canvas derivation failures unless a fallback path is used.
- Test metadata CID/URI directly across gateways to confirm content availability vs gateway instability.

5. Validate cached state and fallback behavior.
- Inspect `token_state_cache` for `last_error`, `expires_at`, `fallback_used`.
- Inspect failure logs (`FAILURE_LOG_PATH`) for user-facing reason strings.
- Verify whether collection render fallback or token override exists; if missing, hard errors will return 5xx JSON.

6. Report root cause and remediation.
- Provide exact failing path(s), headers, and key log lines.
- Separate root cause from symptoms.
- Recommend concrete fixes: content fix (pin/repair metadata), policy fix (fallback/override), or code fix.

## Quick Commands

Use project root as working directory, or call the globally installed symlink path directly.

```bash
# Token-only triage (captures redirect + renderer headers)
"$CODEX_HOME"/skills/renderer-debug/scripts/probe-render.sh \
  http://127.0.0.1:8085 base 0xCOLLECTION 1234 png

# Canonical triage (asset-specific)
"$CODEX_HOME"/skills/renderer-debug/scripts/probe-render.sh \
  https://renderer.rmrk.app base 0xCOLLECTION 1234 png 5678 "fresh=1"
```

Read detailed procedures and diagnosis patterns in:
- [`references/debug-playbook.md`](references/debug-playbook.md)
