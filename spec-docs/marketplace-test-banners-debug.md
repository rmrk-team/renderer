# Marketplace test: banners failure outputs

Context:

- Collection: `base` `0x923c768ac53b24a188333f3709b71cb343db20b2`
- Render fallback enabled: `collection_fallback_config.render_fallback_enabled = 1`
- Render fallback dir: `/tmp/renderer-marketplace/fallbacks/collections/base/0x923c768ac53b24a188333f3709b71cb343db20b2/render`
- Failure log path: `/tmp/renderer-marketplace/failures.log`
- Debug allowlist: `/admin/api/ip-rules` includes `127.0.0.1/32` in `allow` mode

## Token 1 (fallback-enabled failure)

HTTP headers (token-only route → redirect):

```
HTTP/1.1 307 Temporary Redirect
location: /render/base/0x923c768ac53b24a188333f3709b71cb343db20b2/1/1/webp?width=medium&cache=0
cache-control: no-store
x-renderer-primary-assetid: 1
x-request-id: 0000019c15bc7a5b-2d75a39d9b6dbfbc
content-length: 0
date: Sat, 31 Jan 2026 20:26:40 GMT
```

HTTP headers (canonical render → fallback served):

```
HTTP/1.1 200 OK
content-type: image/webp
content-length: 142
cache-control: public, max-age=300
etag: "934a17bce2aea1755efabb37001b2a5e79a4e295d5156c6bc1ba905c55e6523c"
x-renderer-complete: false
x-renderer-result: fallback
x-renderer-fallback: render_fallback
x-renderer-fallback-action: backoff
x-renderer-fallback-source: collection
x-renderer-error-code: render_fallback
x-request-id: 0000019c15bc8f29-ffa0e3c77d0b7fbd
date: Sat, 31 Jan 2026 20:26:45 GMT
```

`debug=1` response (raw JSON error):

```
{"code":"render_failed","error":"render failed","message":"render failed"}
```

Failure log entry:

```
{"timestamp":"2026-01-31T20:27:49.491077Z","timestamp_ms":1769891269491,"request_id":"0000019c15bd8932-897c6bc423a40947","method":"GET","path":"/render/base/0x923c768ac53b24a188333f3709b71cb343db20b2/1/1/webp?width=medium&cache=0&debug=1","status":500,"route_group":"render","ip":"sha256:12ca17b49af2","identity":"ip:sha256:12ca17b49af2","reason":"rpc endpoint https://1rpc.io/base failed: contract call reverted"}
```

Renderer debug log snippets:

```
2026-01-31T20:26:44.906900Z DEBUG proj_renderer::render::compose: compose profile step="compose_db_get" elapsed_ms=0 chain=base collection=0x923c768ac53b24a188333f3709b71cb343db20b2 token_id=1 asset_id=1 cache_hit=true
2026-01-31T20:26:45.053435Z DEBUG proj_renderer::render::compose: compose profile step="compose_equippables" elapsed_ms=146 chain=base collection=0x923c768ac53b24a188333f3709b71cb343db20b2 token_id=1 asset_id=1 status="error"
2026-01-31T20:26:45.054654Z DEBUG proj_renderer::render::compose: compose profile step="compose_record_error" elapsed_ms=1 chain=base collection=0x923c768ac53b24a188333f3709b71cb343db20b2 token_id=1 asset_id=1
```

Database records:

```
token_state_cache:
[
  {
    "chain": "base",
    "collection_address": "0x923c768ac53b24a188333f3709b71cb343db20b2",
    "token_id": "1",
    "asset_id": "1",
    "state_hash": "",
    "state_json": null,
    "last_error": "rpc endpoint https://1rpc.io/base failed: contract call reverted",
    "fallback_used": 0,
    "last_checked_at": 1769891269,
    "last_checked_block": null,
    "expires_at": 1769977668
  }
]

token_overrides: []
token_asset_refs: []
collection_asset_refs: []
```

Collection fallback config:

```
[
  {
    "chain": "base",
    "collection_address": "0x923c768ac53b24a188333f3709b71cb343db20b2",
    "render_fallback_enabled": 1,
    "render_fallback_dir": "/tmp/renderer-marketplace/fallbacks/collections/base/0x923c768ac53b24a188333f3709b71cb343db20b2/render",
    "unapproved_fallback_enabled": 0,
    "unapproved_fallback_dir": null,
    "updated_at_ms": 1769887568437
  }
]
```

Fallback `meta.json`:

```
{
  "updated_at_ms": 1769887562039,
  "source_sha256": "69539b5b3777cffda28a66d7f2aa9b17c91ee1ec8fd50c00c442af91753a60f7",
  "source_width": 1,
  "source_height": 1,
  "variants": [
    "w64.webp",
    "w64.png",
    "w64.jpg",
    "w128.webp",
    "w128.png",
    "w128.jpg",
    "w256.webp",
    "w256.png",
    "w256.jpg",
    "w512.webp",
    "w512.png",
    "w512.jpg",
    "w1024.webp",
    "w1024.png",
    "w1024.jpg",
    "w2048.webp",
    "w2048.png",
    "w2048.jpg",
    "og.webp",
    "og.png",
    "og.jpg"
  ]
}
```

`tokenURI()` eth_call (Base RPC):

```
{
  "token": 1,
  "response": {
    "jsonrpc": "2.0",
    "id": 1,
    "result": "0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000035697066733a2f2f516d5134656273505a577a69334744723464626e31587543334e5043675a5a64316f664e39514b756f6b6e4865470000000000000000000000"
  },
  "decoded": "ipfs://QmQ4ebsPZWzi3GDr4dbn1XuC3NPCgZZd1ofN9QKuoknHeG"
}
```

Metadata (IPFS gateway):

```
{"image":"ipfs://bafybeiftfeedhzask5oxy75pyj2i5umoedlcm2xzezqutmti3iutz6dnne","thumbnailUri":"ipfs://bafybeiahpcduqj2pkbxpcu4ynb6h765fawbsdxm4hrforkl2vu77aq7uge","name":"BubbleScape","description":"And your pixel army can't save you now, my finger's on the kill switch","attributes":[],"mediaUri":"ipfs://bafybeiftfeedhzask5oxy75pyj2i5umoedlcm2xzezqutmti3iutz6dnne"}
```

Pinned asset lookup for metadata CIDs:

```
[]
```

## Token 6 (superfail)

HTTP headers (token-only route):

```
HTTP/1.1 500 Internal Server Error
content-type: application/json
x-renderer-error-code: error
x-renderer-error: request failed
vary: accept-encoding
x-request-id: 0000019c15bd9d61-abbd6623f17e37c1
content-length: 68
date: Sat, 31 Jan 2026 20:27:54 GMT
```

`debug=1` response (raw JSON error):

```
{"code":"error","error":"request failed","message":"request failed"}
```

Failure log entry:

```
{"timestamp":"2026-01-31T20:27:59.087803Z","timestamp_ms":1769891279088,"request_id":"0000019c15bdaff6-ce75fbe876576e8e","method":"GET","path":"/render/base/0x923c768ac53b24a188333f3709b71cb343db20b2/6/webp?width=medium&debug=1","status":500,"route_group":"render","ip":"sha256:12ca17b49af2","identity":"ip:sha256:12ca17b49af2","reason":"rpc endpoint https://1rpc.io/base failed: contract call reverted"}
```

Renderer debug log snippets:

```
2026-01-31T20:27:54.198181Z  WARN request{method=GET uri=/render/base/0x923c768ac53b24a188333f3709b71cb343db20b2/6/webp?width=medium version=HTTP/1.1}: proj_renderer::chain: rpc endpoint call failed endpoint=https://1rpc.io/base error=contract call reverted
2026-01-31T20:27:54.307528Z  WARN request{method=GET uri=/render/base/0x923c768ac53b24a188333f3709b71cb343db20b2/6/webp?width=medium version=HTTP/1.1}: proj_renderer::http: request failed error=rpc endpoint https://1rpc.io/base failed: contract call reverted
```

Database records:

```
token_state_cache: []
token_overrides: []
token_asset_refs: []
collection_asset_refs: []
```

`tokenURI()` eth_call (Base RPC):

```
{
  "token": 6,
  "response": {
    "jsonrpc": "2.0",
    "id": 6,
    "error": {
      "code": 3,
      "message": "execution reverted: panic: array out-of-bounds access (0x32)",
      "data": "0x4e487b710000000000000000000000000000000000000000000000000000000000000032"
    }
  },
  "decoded": null
}
```
