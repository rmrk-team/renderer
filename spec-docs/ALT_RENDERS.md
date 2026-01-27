# Alternate Render Notes

## Problem: GLB-only collections return placeholder

During debugging for:

`/render/moonbeam/0x972009b42a51cacd43e059a2c56e92541ef2bc2f/750/1/png?cache=1762899534000`

the renderer returns a blank canvas (placeholder). The required base fixed part
resolves to `mediaUri` that points to a GLB (`model/gltf-binary`). The renderer
only supports SVG/PNG/JPG, so the base layer fails to decode and the render is
marked incomplete (`X-Renderer-Complete: false`, `X-Renderer-Result: placeholder`).

The metadata for both the part and the token only include `mediaUri` (GLB) and
do not provide `image` or `thumbnailUri`, so there is no 2D fallback.

## Why this is skippable for now

This is not a renderer bug; it is a content mismatch. The current pipeline is
2D rasterization only.

## Future direction (3D / alt renders)

We should decide how to support GLB-only collections. Options to explore:

- Add a secondary render path for 3D assets (GLB), separate from the 2D pipeline.
- Use a headless browser (e.g., Chromium) to load a lightweight 3D viewer and
  capture a screenshot as the render output.
- Define a policy to prefer `image`/`thumbnailUri` when present, and treat GLB
  as non-renderable unless an alternate renderer is enabled.

This file is a placeholder for future design work around alternative rendering.
