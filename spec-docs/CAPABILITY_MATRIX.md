# Renderer capability matrix

This table describes how the renderer behaves based on detected interfaces.

| Interface support | Renderer path | Notes |
| --- | --- | --- |
| ERC721Metadata only | `tokenURI` fetch | Renders the token-level metadata image. |
| RMRK MultiAsset | top asset / asset metadata | Uses `getAssetIdWithTopPriority` + asset metadata when available. |
| RMRK Equippable | `composeEquippables` | Builds layered composition using fixed parts, slot parts, and equipped children. |
| No known interfaces | best-effort fallback | Returns a fallback image or error depending on policy. |

Additional behavior:

- Token-only routes redirect to the resolved primary asset when possible.
- The renderer uses the `token_uri` fallback asset ID when it must render from `tokenURI`.
- Overlay and background variants are encoded into cache keys and do not affect interface selection.
