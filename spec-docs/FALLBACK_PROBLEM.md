# Fallback Problem: 0x923c... Collection

## Summary

We attempted to render tokens from collection
`base/0x923c768ac53b24a188333f3709b71cb343db20b2` by falling back from
primary-asset lookup (`get_asset_id_with_top_priority`) to `tokenURI()` when the
top-asset lookup reverted. The fallback did **not** produce images because the
`tokenURI()` call itself reverts for the same set of tokens.

This document records the revert data per token ID and the current
interpretation.

## Test Run

- Renderer build: local debug build after tokenURI fallback patch
- Base URL: `http://127.0.0.1:8085`
- Tokens tested (25 total, includes 1749/1750)
- Marketplace sim: `scripts/marketplace-sim.ts` with concurrency 4
- Result: `200=13`, `500=12`

## Observed Reverts (Per Token)

The following tokens first failed top-asset lookup with `0x3456866f`, then
`tokenURI()` reverted with `0x89ba7e10`.

| Token ID | Top-asset revert | tokenURI revert |
|---------:|------------------|-----------------|
| 1856 | 0x3456866f | 0x89ba7e10 |
| 1919 | 0x3456866f | 0x89ba7e10 |
| 1962 | 0x3456866f | 0x89ba7e10 |
| 2296 | 0x3456866f | 0x89ba7e10 |
| 2367 | 0x3456866f | 0x89ba7e10 |
| 2455 | 0x3456866f | 0x89ba7e10 |
| 2559 | 0x3456866f | 0x89ba7e10 |
| 2588 | 0x3456866f | 0x89ba7e10 |
| 2598 | 0x3456866f | 0x89ba7e10 |
| 2777 | 0x3456866f | 0x89ba7e10 |
| 2877 | 0x3456866f | 0x89ba7e10 |
| 2889 | 0x3456866f | 0x89ba7e10 |

## Interpretation (Current)

- `0x3456866f`
  - Observed during top-asset lookup (`get_asset_id_with_top_priority`).
  - Interpreted as “top asset missing / not resolvable”.
  - Triggered the tokenURI fallback path.
- `0x89ba7e10`
  - Observed during `tokenURI()` calls for the same tokens.
  - Interpreted as “tokenURI not supported / interface mismatch”.
  - Causes the tokenURI fallback to fail and return `500`.

## Implication

These tokens appear to require an **interface-based fallback decision** rather
than mapping individual revert selectors. The collection may not implement
ERC721 `tokenURI()` for every token (or at all), so the fallback must be chosen
based on supported interfaces instead of revert codes alone.
