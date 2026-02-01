use super::*;
use crate::layer_profile;

pub(super) fn derive_canvas_from_asset(
    bytes: &[u8],
    default_width: u32,
    default_height: u32,
    max_svg_bytes: usize,
    max_svg_nodes: usize,
    max_raster_bytes: usize,
    max_decoded_raster_pixels: u64,
) -> Result<(u32, u32, bool)> {
    if is_svg(bytes) {
        let raw = std::str::from_utf8(bytes).context("svg not utf-8")?;
        if let Some((width, height)) = extract_svg_dimensions(raw) {
            if width > 0 && height > 0 {
                return Ok((width, height, false));
            }
        }
        let (tree, _) = parse_svg(
            bytes,
            max_svg_bytes,
            max_svg_nodes,
            max_raster_bytes,
            max_decoded_raster_pixels,
        )?;
        let size = tree.size();
        let width = size.width().round() as u32;
        let height = size.height().round() as u32;
        if width > 0 && height > 0 {
            return Ok((width, height, false));
        }
    }
    if let Ok((width, height)) = raster_dimensions(bytes, max_decoded_raster_pixels) {
        if width > 0 && height > 0 {
            return Ok((width, height, false));
        }
    }
    Ok((default_width, default_height, true))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn rasterize_bytes(
    bytes: &[u8],
    canvas_width: u32,
    canvas_height: u32,
    max_svg_bytes: usize,
    max_svg_nodes: usize,
    max_raster_bytes: usize,
    max_decoded_raster_pixels: u64,
    assets: &AssetResolver,
    blocking_semaphore: &Arc<Semaphore>,
    layer: &Layer,
    layer_index: usize,
    art_uri: Option<&str>,
    debug_context: Option<&DebugRenderContext>,
) -> Result<(RgbaImage, bool)> {
    let rasterize_started = Instant::now();
    if is_svg(bytes) {
        let cache_key = sha256_hex_bytes(bytes);
        let cache_lookup_started = Instant::now();
        let cached = assets
            .fetch_raster_cache(&cache_key, canvas_width, canvas_height)
            .await?;
        layer_profile!(
            debug_context,
            layer,
            layer_index,
            "raster_cache_lookup",
            cache_lookup_started.elapsed(),
            cache_hit = cached.is_some(),
            bytes = bytes.len(),
            art_uri = art_uri.unwrap_or("none"),
            canvas_width = canvas_width,
            canvas_height = canvas_height
        );
        if let Some(raster) = cached {
            let raster_len = raster.len();
            let decode_started = Instant::now();
            let blocking = blocking_semaphore.clone();
            match spawn_blocking_with_semaphore(blocking, move || -> Result<RgbaImage> {
                decode_raster(&raster, max_decoded_raster_pixels)
            })
            .await
            {
                Ok(image) => {
                    layer_profile!(
                        debug_context,
                        layer,
                        layer_index,
                        "raster_cache_decode",
                        decode_started.elapsed(),
                        bytes = raster_len
                    );
                    layer_profile!(
                        debug_context,
                        layer,
                        layer_index,
                        "rasterize_svg_total",
                        rasterize_started.elapsed(),
                        cache_hit = true
                    );
                    return Ok((image, false));
                }
                Err(_) => {
                    assets.observe_upstream_failure("decode");
                    let _ = assets
                        .remove_raster_cache(&cache_key, canvas_width, canvas_height)
                        .await;
                }
            }
        }
        let svg_bytes = bytes.to_vec();
        let blocking = blocking_semaphore.clone();
        let (
            image,
            png_bytes,
            parse_ms,
            render_ms,
            image_ms,
            encode_ms,
            stats,
            svg_width,
            svg_height,
        ) = match spawn_blocking_with_semaphore(
            blocking,
            move || -> Result<(
                RgbaImage,
                Vec<u8>,
                u128,
                u128,
                u128,
                u128,
                SvgComplexityStats,
                u32,
                u32,
            )> {
                let parse_started = Instant::now();
                let (tree, stats) = parse_svg(
                    &svg_bytes,
                    max_svg_bytes,
                    max_svg_nodes,
                    max_raster_bytes,
                    max_decoded_raster_pixels,
                )?;
                let parse_ms = parse_started.elapsed().as_millis();
                let size = tree.size();
                let svg_width = size.width().round() as u32;
                let svg_height = size.height().round() as u32;
                let render_started = Instant::now();
                let pixmap = render_svg_to_pixmap(&tree, canvas_width, canvas_height)?;
                let render_ms = render_started.elapsed().as_millis();
                let image_started = Instant::now();
                let image =
                    RgbaImage::from_raw(canvas_width, canvas_height, pixmap.data().to_vec())
                        .ok_or_else(|| anyhow!("failed to build raster image"))?;
                let image_ms = image_started.elapsed().as_millis();
                let encode_started = Instant::now();
                let mut png_bytes = Vec::new();
                image.write_to(&mut std::io::Cursor::new(&mut png_bytes), ImageFormat::Png)?;
                let encode_ms = encode_started.elapsed().as_millis();
                Ok((
                    image,
                    png_bytes,
                    parse_ms,
                    render_ms,
                    image_ms,
                    encode_ms,
                    stats,
                    svg_width,
                    svg_height,
                ))
            },
        )
        .await
        {
            Ok(result) => result,
            Err(err) => {
                assets.observe_upstream_failure("svg_parse");
                layer_profile!(
                    debug_context,
                    layer,
                    layer_index,
                    "rasterize_svg_total",
                    rasterize_started.elapsed(),
                    status = "error"
                );
                return Err(err);
            }
        };
        layer_profile!(
            debug_context,
            layer,
            layer_index,
            "svg_parse",
            Duration::from_millis(parse_ms as u64),
            bytes = bytes.len(),
            svg_node_count = stats.node_count,
            svg_width = svg_width,
            svg_height = svg_height,
            svg_linear_gradients = stats.linear_gradients,
            svg_radial_gradients = stats.radial_gradients,
            svg_gradient_stops = stats.gradient_stops,
            svg_filter_defs = stats.filter_defs,
            svg_filter_uses = stats.filter_uses,
            svg_clip_paths = stats.clip_path_defs,
            svg_clip_path_uses = stats.clip_path_uses,
            svg_masks = stats.mask_defs,
            svg_mask_uses = stats.mask_uses,
            art_uri = art_uri.unwrap_or("none"),
            canvas_width = canvas_width,
            canvas_height = canvas_height
        );
        layer_profile!(
            debug_context,
            layer,
            layer_index,
            "svg_render",
            Duration::from_millis(render_ms as u64),
            svg_node_count = stats.node_count,
            svg_width = svg_width,
            svg_height = svg_height,
            svg_linear_gradients = stats.linear_gradients,
            svg_radial_gradients = stats.radial_gradients,
            svg_gradient_stops = stats.gradient_stops,
            svg_filter_defs = stats.filter_defs,
            svg_filter_uses = stats.filter_uses,
            svg_clip_paths = stats.clip_path_defs,
            svg_clip_path_uses = stats.clip_path_uses,
            svg_masks = stats.mask_defs,
            svg_mask_uses = stats.mask_uses,
            art_uri = art_uri.unwrap_or("none"),
            canvas_width = canvas_width,
            canvas_height = canvas_height
        );
        layer_profile!(
            debug_context,
            layer,
            layer_index,
            "svg_image_build",
            Duration::from_millis(image_ms as u64)
        );
        layer_profile!(
            debug_context,
            layer,
            layer_index,
            "svg_png_encode",
            Duration::from_millis(encode_ms as u64),
            png_bytes = png_bytes.len()
        );
        let cache_store_started = Instant::now();
        assets
            .store_raster_cache(&cache_key, canvas_width, canvas_height, &png_bytes)
            .await?;
        layer_profile!(
            debug_context,
            layer,
            layer_index,
            "raster_cache_store",
            cache_store_started.elapsed(),
            png_bytes = png_bytes.len()
        );
        layer_profile!(
            debug_context,
            layer,
            layer_index,
            "rasterize_svg_total",
            rasterize_started.elapsed(),
            cache_hit = false
        );
        return Ok((image, false));
    }
    let bytes = bytes.to_vec();
    let bytes_len = bytes.len();
    let blocking = blocking_semaphore.clone();
    let decode_started = Instant::now();
    let image = match spawn_blocking_with_semaphore(blocking, move || -> Result<RgbaImage> {
        decode_raster(&bytes, max_decoded_raster_pixels)
    })
    .await
    {
        Ok(image) => image,
        Err(err) => {
            assets.observe_upstream_failure("decode");
            return Err(err);
        }
    };
    layer_profile!(
        debug_context,
        layer,
        layer_index,
        "raster_decode",
        decode_started.elapsed(),
        bytes = bytes_len,
        width = image.width(),
        height = image.height()
    );
    let nonconforming = image.width() != canvas_width || image.height() != canvas_height;
    layer_profile!(
        debug_context,
        layer,
        layer_index,
        "rasterize_raster_total",
        rasterize_started.elapsed(),
        nonconforming = nonconforming
    );
    Ok((image, nonconforming))
}

pub(super) fn raster_policy_for_layer(
    layer: &Layer,
    raster_mismatch_fixed: RasterMismatchPolicy,
    raster_mismatch_child: RasterMismatchPolicy,
) -> RasterMismatchPolicy {
    match layer.kind {
        LayerKind::SlotChild => raster_mismatch_child,
        _ => raster_mismatch_fixed,
    }
}

pub(super) fn apply_raster_mismatch_policy(
    layer: &Layer,
    image: RgbaImage,
    nonconforming: bool,
    policy: RasterMismatchPolicy,
    canvas_width: u32,
    canvas_height: u32,
) -> Result<LayerImage> {
    if !nonconforming {
        return Ok(LayerImage {
            image,
            offset_x: 0,
            offset_y: 0,
            nonconforming: false,
        });
    }
    warn!(
        metadata_uri = %layer.metadata_uri,
        kind = ?layer.kind,
        policy = ?policy,
        image_width = image.width(),
        image_height = image.height(),
        canvas_width,
        canvas_height,
        "nonconforming raster layer dimensions"
    );
    match policy {
        RasterMismatchPolicy::Error => Err(anyhow!("nonconforming raster dimensions")),
        RasterMismatchPolicy::ScaleToCanvas => {
            let resized =
                image::imageops::resize(&image, canvas_width, canvas_height, FilterType::Lanczos3);
            Ok(LayerImage {
                image: resized,
                offset_x: 0,
                offset_y: 0,
                nonconforming: true,
            })
        }
        RasterMismatchPolicy::CenterNoScale => {
            let offset_x = ((canvas_width as i64 - image.width() as i64) / 2).max(0);
            let offset_y = ((canvas_height as i64 - image.height() as i64) / 2).max(0);
            Ok(LayerImage {
                image,
                offset_x,
                offset_y,
                nonconforming: true,
            })
        }
        RasterMismatchPolicy::TopLeftNoScale => Ok(LayerImage {
            image,
            offset_x: 0,
            offset_y: 0,
            nonconforming: true,
        }),
    }
}

fn render_svg_to_pixmap(tree: &usvg::Tree, width: u32, height: u32) -> Result<tiny_skia::Pixmap> {
    let mut pixmap =
        tiny_skia::Pixmap::new(width, height).ok_or_else(|| anyhow!("invalid pixmap size"))?;
    let size = tree.size();
    let scale_x = if size.width() > 0.0 {
        width as f32 / size.width()
    } else {
        1.0
    };
    let scale_y = if size.height() > 0.0 {
        height as f32 / size.height()
    } else {
        1.0
    };
    let transform = tiny_skia::Transform::from_scale(scale_x, scale_y);
    let mut pixmap_mut = pixmap.as_mut();
    resvg::render(tree, transform, &mut pixmap_mut);
    Ok(pixmap)
}

fn raster_dimensions(bytes: &[u8], max_pixels: u64) -> Result<(u32, u32)> {
    let mut reader = ImageReader::new(std::io::Cursor::new(bytes)).with_guessed_format()?;
    reader.limits(raster_limits(max_pixels));
    let (width, height) = reader.into_dimensions()?;
    let pixels = (width as u64).saturating_mul(height as u64);
    if pixels > max_pixels {
        return Err(anyhow!("raster exceeds max decoded pixels"));
    }
    Ok((width, height))
}

pub(super) fn decode_raster(bytes: &[u8], max_pixels: u64) -> Result<RgbaImage> {
    let (width, height) = raster_dimensions(bytes, max_pixels)?;
    if width == 0 || height == 0 {
        return Err(anyhow!("raster has invalid dimensions"));
    }
    let mut reader = ImageReader::new(std::io::Cursor::new(bytes)).with_guessed_format()?;
    reader.limits(raster_limits(max_pixels));
    let image = reader.decode()?;
    let pixels = (image.width() as u64).saturating_mul(image.height() as u64);
    if pixels > max_pixels {
        return Err(anyhow!("raster exceeds max decoded pixels"));
    }
    Ok(image.to_rgba8())
}

fn raster_limits(max_pixels: u64) -> image::Limits {
    let max_dim = max_pixels.min(u32::MAX as u64) as u32;
    let max_alloc = max_pixels.saturating_mul(4);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(max_dim);
    limits.max_image_height = Some(max_dim);
    limits.max_alloc = Some(max_alloc);
    limits
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SvgComplexityStats {
    node_count: usize,
    linear_gradients: usize,
    radial_gradients: usize,
    gradient_stops: usize,
    filter_defs: usize,
    filter_uses: usize,
    clip_path_defs: usize,
    clip_path_uses: usize,
    mask_defs: usize,
    mask_uses: usize,
}

pub(super) fn parse_svg(
    bytes: &[u8],
    max_svg_bytes: usize,
    max_svg_nodes: usize,
    max_raster_bytes: usize,
    max_decoded_raster_pixels: u64,
) -> Result<(usvg::Tree, SvgComplexityStats)> {
    if bytes.len() > max_svg_bytes {
        return Err(anyhow!("svg exceeds max size"));
    }
    let raw = std::str::from_utf8(bytes).context("svg not utf-8")?;
    if contains_ascii_case_insensitive(raw.as_bytes(), b"<script") || contains_external_svg_url(raw)
    {
        return Err(anyhow!("svg contains disallowed external references"));
    }
    let mut options = usvg::Options::default();
    options.image_href_resolver.resolve_data = Box::new(move |mime, data, _opts| {
        if data.len() > max_raster_bytes {
            return None;
        }
        match mime {
            "image/png" => {
                data_uri_raster_kind(data, max_decoded_raster_pixels).map(ImageKind::PNG)
            }
            "image/jpg" | "image/jpeg" => {
                data_uri_raster_kind(data, max_decoded_raster_pixels).map(ImageKind::JPEG)
            }
            "image/webp" => {
                data_uri_raster_kind(data, max_decoded_raster_pixels).map(ImageKind::WEBP)
            }
            _ => None,
        }
    });
    options.image_href_resolver.resolve_string = Box::new(|_href, _opts| {
        #[cfg(test)]
        {
            SVG_STRING_RESOLVER_CALLED.store(true, Ordering::Relaxed);
        }
        None
    });
    let tree = usvg::Tree::from_data(bytes, &options)?;
    let stats = svg_complexity_stats(&tree);
    if stats.node_count > max_svg_nodes {
        return Err(anyhow!("svg node count exceeds limit"));
    }
    Ok((tree, stats))
}

fn svg_complexity_stats(tree: &usvg::Tree) -> SvgComplexityStats {
    let gradient_stops = tree
        .linear_gradients()
        .iter()
        .map(|gradient| gradient.stops().len())
        .sum::<usize>()
        .saturating_add(
            tree.radial_gradients()
                .iter()
                .map(|gradient| gradient.stops().len())
                .sum::<usize>(),
        );
    let mut stats = SvgComplexityStats {
        node_count: 0,
        linear_gradients: tree.linear_gradients().len(),
        radial_gradients: tree.radial_gradients().len(),
        gradient_stops,
        filter_defs: tree.filters().len(),
        filter_uses: 0,
        clip_path_defs: tree.clip_paths().len(),
        clip_path_uses: 0,
        mask_defs: tree.masks().len(),
        mask_uses: 0,
    };
    fn walk_group(group: &usvg::Group, stats: &mut SvgComplexityStats) {
        stats.node_count = stats.node_count.saturating_add(1);
        stats.filter_uses = stats.filter_uses.saturating_add(group.filters().len());
        if group.clip_path().is_some() {
            stats.clip_path_uses = stats.clip_path_uses.saturating_add(1);
        }
        if group.mask().is_some() {
            stats.mask_uses = stats.mask_uses.saturating_add(1);
        }
        for child in group.children() {
            stats.node_count = stats.node_count.saturating_add(1);
            if let usvg::Node::Group(child_group) = child {
                walk_group(child_group, stats);
            }
            child.subroots(|subroot| walk_group(subroot, stats));
        }
    }
    walk_group(tree.root(), &mut stats);
    stats
}

fn data_uri_raster_kind(data: Arc<Vec<u8>>, max_pixels: u64) -> Option<Arc<Vec<u8>>> {
    let reader = image::ImageReader::new(std::io::Cursor::new(data.as_slice()))
        .with_guessed_format()
        .ok()?;
    let (width, height) = reader.into_dimensions().ok()?;
    let pixels = (width as u64).saturating_mul(height as u64);
    if pixels > max_pixels {
        return None;
    }
    Some(data)
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    let last_start = haystack.len() - needle.len();
    for start in 0..=last_start {
        let mut matched = true;
        for (offset, target) in needle.iter().enumerate() {
            if haystack[start + offset].to_ascii_lowercase() != *target {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

fn contains_external_svg_url(raw: &str) -> bool {
    let lowered = raw.to_ascii_lowercase();
    // Allow data: URIs (embedded images), block only external http(s) references.
    let needles = [
        "href=\"http://",
        "href='http://",
        "href=\"https://",
        "href='https://",
        "xlink:href=\"http://",
        "xlink:href='http://",
        "xlink:href=\"https://",
        "xlink:href='https://",
        "url(http://",
        "url('http://",
        "url(\"http://",
        "url(https://",
        "url('https://",
        "url(\"https://",
        "@import \"http://",
        "@import 'http://",
        "@import \"https://",
        "@import 'https://",
        "@import url(http://",
        "@import url('http://",
        "@import url(\"http://",
        "@import url(https://",
        "@import url('https://",
        "@import url(\"https://",
    ];
    needles.iter().any(|needle| lowered.contains(needle))
}

pub(super) fn is_svg(bytes: &[u8]) -> bool {
    let sample = std::str::from_utf8(bytes).unwrap_or("");
    sample.contains("<svg") || sample.contains("<?xml")
}

pub(super) fn extract_svg_dimensions(raw: &str) -> Option<(u32, u32)> {
    let lower = raw.to_ascii_lowercase();
    if let Some((width, height)) = parse_viewbox(&lower) {
        return Some((width, height));
    }
    let width = parse_svg_length(&lower, "width")?;
    let height = parse_svg_length(&lower, "height")?;
    Some((width, height))
}

fn parse_viewbox(lower: &str) -> Option<(u32, u32)> {
    let idx = lower.find("viewbox=")?;
    let quote = lower[idx..].chars().nth(8)?;
    let start = idx + 9;
    let end = lower[start..].find(quote)? + start;
    let value = &lower[start..end];
    let parts = value
        .split_whitespace()
        .filter_map(|item| item.parse::<f32>().ok())
        .collect::<Vec<_>>();
    if parts.len() >= 4 {
        return Some((parts[2].round() as u32, parts[3].round() as u32));
    }
    None
}

fn parse_svg_length(lower: &str, name: &str) -> Option<u32> {
    let needle = format!("{name}=");
    let idx = lower.find(&needle)?;
    let quote = lower[idx + name.len() + 1..].chars().next()?;
    let start = idx + name.len() + 2;
    let end = lower[start..].find(quote)? + start;
    let value = lower[start..end].trim();
    let trimmed = value.trim_end_matches("px");
    trimmed.parse::<f32>().ok().map(|v| v.round() as u32)
}
