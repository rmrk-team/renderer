use super::*;

pub(super) async fn render_canonical(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_id, asset_id, format)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<RenderQuery>,
    headers: HeaderMap,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    let format = OutputFormat::from_extension(&format)
        .ok_or_else(|| ApiError::bad_request("unsupported image format"))?;
    render::validate_render_params(&chain, &collection, &token_id, Some(&asset_id))
        .map_err(map_render_error_anyhow)?;
    let (chain, collection) = canonicalize_chain_collection(&state, &chain, &collection)?;
    let started = Instant::now();
    let width_param = query.width.clone().or_else(|| query.img_width.clone());
    let placeholder_width = width_param.clone();
    let (cache_timestamp, cache_param_present) = apply_cache_policy(
        &state,
        &chain,
        &collection,
        query.cache.clone(),
        query.cache.is_some(),
        context.as_ref().map(|ctx| &ctx.0),
    )
    .await?;
    let fresh_requested = parse_fresh_flag(query.fresh.as_deref());
    let allow_fresh = context
        .as_ref()
        .map(|ctx| ctx.0.allow_fresh)
        .unwrap_or(false);
    let fresh = if fresh_requested {
        if allow_fresh {
            true
        } else {
            let key = fresh_key(&chain, &collection, &token_id, &asset_id);
            let limit = state
                .db
                .check_fresh_request(&key, state.config.fresh_rate_limit_seconds)
                .await
                .map_err(map_render_error_anyhow)?;
            if !limit.allowed {
                let retry_after = limit.retry_after_seconds.unwrap_or(60);
                let response = rate_limit_response(Some(fresh_rate_limit_info(retry_after)));
                state.metrics.observe_render_result("rate_limited");
                state
                    .metrics
                    .observe_render_duration("total", started.elapsed());
                state.metrics.observe_top_collection(
                    &chain,
                    &collection,
                    response_bytes(&response),
                );
                return Ok(response);
            }
            true
        }
    } else {
        false
    };
    let debug_requested =
        parse_bool_flag(query.debug.as_deref()) || parse_bool_flag(query.raw.as_deref());
    let allow_debug = context
        .as_ref()
        .map(|ctx| ctx.0.allow_debug)
        .unwrap_or(false);
    let raw_mode = debug_requested && allow_debug;
    let prefer_json = raw_mode || wants_json_response(&headers);
    let approval_context = approval_context_from_access(context.as_ref().map(|ctx| &ctx.0));
    let request = RenderRequest {
        chain,
        collection,
        token_id,
        asset_id,
        format,
        cache_timestamp,
        cache_param_present,
        width_param,
        og_mode: query.og_image.unwrap_or(false),
        overlay: query.overlay,
        background: query.bg,
        fresh,
        approval_context,
    };
    let source_label = if source_labels_enabled(&state.config) {
        source_label_from_headers(&headers, context.as_ref().map(|ctx| &ctx.0))
    } else {
        None
    };
    let render_limit = context.as_ref().and_then(|ctx| ctx.0.render_limit());
    if let Err(err) = render::ensure_collection_approved(
        &state,
        &request.chain,
        &request.collection,
        &request.approval_context,
    )
    .await
    {
        if !prefer_json {
            if let Some(response) =
                fallback_for_render_error(&state, &request, &placeholder_width, &headers, &err)
                    .await
            {
                record_render_metrics(
                    &state,
                    &response,
                    started.elapsed(),
                    &request.chain,
                    &request.collection,
                    source_label.as_deref(),
                );
                return Ok(response);
            }
        }
        let api_error = map_render_error(err);
        record_render_error_metrics(
            &state,
            started.elapsed(),
            &request.chain,
            &request.collection,
            source_label.as_deref(),
            api_error.code.as_deref(),
        );
        return Err(api_error);
    }
    if !prefer_json {
        if let Some(response) = resolve_token_override(&state, &request, &headers).await {
            record_render_metrics(
                &state,
                &response,
                started.elapsed(),
                &request.chain,
                &request.collection,
                source_label.as_deref(),
            );
            return Ok(response);
        }
    }
    match render_token_with_limit_checked(state.clone(), request.clone(), render_limit).await {
        Ok(response) => {
            let response = to_http_response(response, &headers).await;
            record_render_metrics(
                &state,
                &response,
                started.elapsed(),
                &request.chain,
                &request.collection,
                source_label.as_deref(),
            );
            Ok(response)
        }
        Err(err) => {
            if !prefer_json {
                if let Some(response) =
                    fallback_for_render_error(&state, &request, &placeholder_width, &headers, &err)
                        .await
                {
                    record_render_metrics(
                        &state,
                        &response,
                        started.elapsed(),
                        &request.chain,
                        &request.collection,
                        source_label.as_deref(),
                    );
                    return Ok(response);
                }
                if query.onerror.as_deref() == Some("placeholder") {
                    let (width, height) = placeholder_dimensions(&state, &placeholder_width, false);
                    let response = placeholder_response(&format, width, height);
                    record_render_metrics(
                        &state,
                        &response,
                        started.elapsed(),
                        &request.chain,
                        &request.collection,
                        source_label.as_deref(),
                    );
                    return Ok(response);
                }
            }
            let api_error = map_render_error(err);
            record_render_error_metrics(
                &state,
                started.elapsed(),
                &request.chain,
                &request.collection,
                source_label.as_deref(),
                api_error.code.as_deref(),
            );
            Err(api_error)
        }
    }
}

pub(super) async fn render_og(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_id, asset_id, format)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<RenderQuery>,
    headers: HeaderMap,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    let format = OutputFormat::from_extension(&format)
        .ok_or_else(|| ApiError::bad_request("unsupported image format"))?;
    render::validate_render_params(&chain, &collection, &token_id, Some(&asset_id))
        .map_err(map_render_error_anyhow)?;
    let (chain, collection) = canonicalize_chain_collection(&state, &chain, &collection)?;
    let started = Instant::now();
    let width_param = query.width.clone().or_else(|| query.img_width.clone());
    let placeholder_width = width_param.clone();
    let (cache_timestamp, cache_param_present) = apply_cache_policy(
        &state,
        &chain,
        &collection,
        query.cache.clone(),
        query.cache.is_some(),
        context.as_ref().map(|ctx| &ctx.0),
    )
    .await?;
    let fresh_requested = parse_fresh_flag(query.fresh.as_deref());
    let allow_fresh = context
        .as_ref()
        .map(|ctx| ctx.0.allow_fresh)
        .unwrap_or(false);
    let fresh = if fresh_requested {
        if allow_fresh {
            true
        } else {
            let key = fresh_key(&chain, &collection, &token_id, &asset_id);
            let limit = state
                .db
                .check_fresh_request(&key, state.config.fresh_rate_limit_seconds)
                .await
                .map_err(map_render_error_anyhow)?;
            if !limit.allowed {
                let retry_after = limit.retry_after_seconds.unwrap_or(60);
                let response = rate_limit_response(Some(fresh_rate_limit_info(retry_after)));
                state.metrics.observe_render_result("rate_limited");
                state
                    .metrics
                    .observe_render_duration("total", started.elapsed());
                state.metrics.observe_top_collection(
                    &chain,
                    &collection,
                    response_bytes(&response),
                );
                return Ok(response);
            }
            true
        }
    } else {
        false
    };
    let debug_requested =
        parse_bool_flag(query.debug.as_deref()) || parse_bool_flag(query.raw.as_deref());
    let allow_debug = context
        .as_ref()
        .map(|ctx| ctx.0.allow_debug)
        .unwrap_or(false);
    let raw_mode = debug_requested && allow_debug;
    let prefer_json = raw_mode || wants_json_response(&headers);
    let approval_context = approval_context_from_access(context.as_ref().map(|ctx| &ctx.0));
    let request = RenderRequest {
        chain,
        collection,
        token_id,
        asset_id,
        format,
        cache_timestamp,
        cache_param_present,
        width_param,
        og_mode: true,
        overlay: query.overlay,
        background: query.bg,
        fresh,
        approval_context,
    };
    let source_label = if source_labels_enabled(&state.config) {
        source_label_from_headers(&headers, context.as_ref().map(|ctx| &ctx.0))
    } else {
        None
    };
    let render_limit = context.as_ref().and_then(|ctx| ctx.0.render_limit());
    if let Err(err) = render::ensure_collection_approved(
        &state,
        &request.chain,
        &request.collection,
        &request.approval_context,
    )
    .await
    {
        if !prefer_json {
            if let Some(response) =
                fallback_for_render_error(&state, &request, &placeholder_width, &headers, &err)
                    .await
            {
                record_render_metrics(
                    &state,
                    &response,
                    started.elapsed(),
                    &request.chain,
                    &request.collection,
                    source_label.as_deref(),
                );
                return Ok(response);
            }
        }
        let api_error = map_render_error(err);
        record_render_error_metrics(
            &state,
            started.elapsed(),
            &request.chain,
            &request.collection,
            source_label.as_deref(),
            api_error.code.as_deref(),
        );
        return Err(api_error);
    }
    if !prefer_json {
        if let Some(response) = resolve_token_override(&state, &request, &headers).await {
            record_render_metrics(
                &state,
                &response,
                started.elapsed(),
                &request.chain,
                &request.collection,
                source_label.as_deref(),
            );
            return Ok(response);
        }
    }
    match render_token_with_limit_checked(state.clone(), request.clone(), render_limit).await {
        Ok(response) => {
            let response = to_http_response(response, &headers).await;
            record_render_metrics(
                &state,
                &response,
                started.elapsed(),
                &request.chain,
                &request.collection,
                source_label.as_deref(),
            );
            Ok(response)
        }
        Err(err) => {
            if !prefer_json {
                if let Some(response) =
                    fallback_for_render_error(&state, &request, &placeholder_width, &headers, &err)
                        .await
                {
                    record_render_metrics(
                        &state,
                        &response,
                        started.elapsed(),
                        &request.chain,
                        &request.collection,
                        source_label.as_deref(),
                    );
                    return Ok(response);
                }
                if query.onerror.as_deref() == Some("placeholder") {
                    let (width, height) = placeholder_dimensions(&state, &placeholder_width, true);
                    let response = placeholder_response(&format, width, height);
                    record_render_metrics(
                        &state,
                        &response,
                        started.elapsed(),
                        &request.chain,
                        &request.collection,
                        source_label.as_deref(),
                    );
                    return Ok(response);
                }
            }
            let api_error = map_render_error(err);
            record_render_error_metrics(
                &state,
                started.elapsed(),
                &request.chain,
                &request.collection,
                source_label.as_deref(),
                api_error.code.as_deref(),
            );
            Err(api_error)
        }
    }
}

pub(super) async fn render_legacy(
    State(state): State<Arc<AppState>>,
    Path((chain, cache_epoch, collection, token_id, asset_id, format)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<RenderQuery>,
    headers: HeaderMap,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    let format = OutputFormat::from_extension(&format)
        .ok_or_else(|| ApiError::bad_request("unsupported image format"))?;
    render::validate_render_params(&chain, &collection, &token_id, Some(&asset_id))
        .map_err(map_render_error_anyhow)?;
    let (chain, collection) = canonicalize_chain_collection(&state, &chain, &collection)?;
    let started = Instant::now();
    let width_param = query.width.clone().or_else(|| query.img_width.clone());
    let placeholder_width = width_param.clone();
    let fresh_requested = parse_fresh_flag(query.fresh.as_deref());
    let allow_fresh = context
        .as_ref()
        .map(|ctx| ctx.0.allow_fresh)
        .unwrap_or(false);
    let fresh = if fresh_requested {
        if allow_fresh {
            true
        } else {
            let key = fresh_key(&chain, &collection, &token_id, &asset_id);
            let limit = state
                .db
                .check_fresh_request(&key, state.config.fresh_rate_limit_seconds)
                .await
                .map_err(map_render_error_anyhow)?;
            if !limit.allowed {
                let retry_after = limit.retry_after_seconds.unwrap_or(60);
                let response = rate_limit_response(Some(fresh_rate_limit_info(retry_after)));
                state.metrics.observe_render_result("rate_limited");
                state
                    .metrics
                    .observe_render_duration("total", started.elapsed());
                state.metrics.observe_top_collection(
                    &chain,
                    &collection,
                    response_bytes(&response),
                );
                return Ok(response);
            }
            true
        }
    } else {
        false
    };
    let debug_requested =
        parse_bool_flag(query.debug.as_deref()) || parse_bool_flag(query.raw.as_deref());
    let allow_debug = context
        .as_ref()
        .map(|ctx| ctx.0.allow_debug)
        .unwrap_or(false);
    let raw_mode = debug_requested && allow_debug;
    let prefer_json = raw_mode || wants_json_response(&headers);
    let approval_context = approval_context_from_access(context.as_ref().map(|ctx| &ctx.0));
    let (cache_timestamp, cache_param_present) = apply_cache_policy(
        &state,
        &chain,
        &collection,
        Some(cache_epoch),
        true,
        context.as_ref().map(|ctx| &ctx.0),
    )
    .await?;
    let request = RenderRequest {
        chain,
        collection,
        token_id,
        asset_id,
        format,
        cache_timestamp,
        cache_param_present,
        width_param,
        og_mode: query.og_image.unwrap_or(false),
        overlay: query.overlay,
        background: query.bg,
        fresh,
        approval_context,
    };
    let source_label = if source_labels_enabled(&state.config) {
        source_label_from_headers(&headers, context.as_ref().map(|ctx| &ctx.0))
    } else {
        None
    };
    let render_limit = context.as_ref().and_then(|ctx| ctx.0.render_limit());
    if let Err(err) = render::ensure_collection_approved(
        &state,
        &request.chain,
        &request.collection,
        &request.approval_context,
    )
    .await
    {
        if !prefer_json {
            if let Some(response) =
                fallback_for_render_error(&state, &request, &placeholder_width, &headers, &err)
                    .await
            {
                record_render_metrics(
                    &state,
                    &response,
                    started.elapsed(),
                    &request.chain,
                    &request.collection,
                    source_label.as_deref(),
                );
                return Ok(response);
            }
        }
        let api_error = map_render_error(err);
        record_render_error_metrics(
            &state,
            started.elapsed(),
            &request.chain,
            &request.collection,
            source_label.as_deref(),
            api_error.code.as_deref(),
        );
        return Err(api_error);
    }
    if !prefer_json {
        if let Some(response) = resolve_token_override(&state, &request, &headers).await {
            record_render_metrics(
                &state,
                &response,
                started.elapsed(),
                &request.chain,
                &request.collection,
                source_label.as_deref(),
            );
            return Ok(response);
        }
    }
    match render_token_with_limit_checked(state.clone(), request.clone(), render_limit).await {
        Ok(response) => {
            let response = to_http_response(response, &headers).await;
            record_render_metrics(
                &state,
                &response,
                started.elapsed(),
                &request.chain,
                &request.collection,
                source_label.as_deref(),
            );
            Ok(response)
        }
        Err(err) => {
            if !prefer_json {
                if let Some(response) =
                    fallback_for_render_error(&state, &request, &placeholder_width, &headers, &err)
                        .await
                {
                    record_render_metrics(
                        &state,
                        &response,
                        started.elapsed(),
                        &request.chain,
                        &request.collection,
                        source_label.as_deref(),
                    );
                    return Ok(response);
                }
                if query.onerror.as_deref() == Some("placeholder") {
                    let (width, height) = placeholder_dimensions(
                        &state,
                        &placeholder_width,
                        query.og_image.unwrap_or(false),
                    );
                    let response = placeholder_response(&format, width, height);
                    record_render_metrics(
                        &state,
                        &response,
                        started.elapsed(),
                        &request.chain,
                        &request.collection,
                        source_label.as_deref(),
                    );
                    return Ok(response);
                }
            }
            let api_error = map_render_error(err);
            record_render_error_metrics(
                &state,
                started.elapsed(),
                &request.chain,
                &request.collection,
                source_label.as_deref(),
                api_error.code.as_deref(),
            );
            Err(api_error)
        }
    }
}

pub(super) async fn render_primary(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_id, format)): Path<(String, String, String, String)>,
    Query(query): Query<RenderQuery>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    let format = OutputFormat::from_extension(&format)
        .ok_or_else(|| ApiError::bad_request("unsupported image format"))?;
    render::validate_render_params(&chain, &collection, &token_id, None)
        .map_err(map_render_error_anyhow)?;
    let (chain, collection) = canonicalize_chain_collection(&state, &chain, &collection)?;
    let started = Instant::now();
    let width_param = query.width.clone().or_else(|| query.img_width.clone());
    let placeholder_width = width_param.clone();
    let debug_requested =
        parse_bool_flag(query.debug.as_deref()) || parse_bool_flag(query.raw.as_deref());
    let allow_debug = context
        .as_ref()
        .map(|ctx| ctx.0.allow_debug)
        .unwrap_or(false);
    let raw_mode = debug_requested && allow_debug;
    let prefer_json = raw_mode || wants_json_response(&headers);
    let approval_context = approval_context_from_access(context.as_ref().map(|ctx| &ctx.0));
    let (cache_timestamp, cache_param_present) = apply_cache_policy(
        &state,
        &chain,
        &collection,
        query.cache.clone(),
        query.cache.is_some(),
        context.as_ref().map(|ctx| &ctx.0),
    )
    .await?;
    let cache_stamp = cache_timestamp
        .clone()
        .unwrap_or_else(|| "none".to_string());
    let primary_cache_key = format!("{chain}:{collection}:{token_id}:{cache_stamp}");
    let fresh_requested = parse_fresh_flag(query.fresh.as_deref());
    let mut request = RenderRequest {
        chain: chain.clone(),
        collection: collection.clone(),
        token_id: token_id.clone(),
        asset_id: "primary".to_string(),
        format,
        cache_timestamp: cache_timestamp.clone(),
        cache_param_present,
        width_param: width_param.clone(),
        og_mode: query.og_image.unwrap_or(false),
        overlay: query.overlay.clone(),
        background: query.bg.clone(),
        fresh: fresh_requested,
        approval_context,
    };
    let source_label = if source_labels_enabled(&state.config) {
        source_label_from_headers(&headers, context.as_ref().map(|ctx| &ctx.0))
    } else {
        None
    };
    if let Err(err) = render::ensure_collection_approved(
        &state,
        &request.chain,
        &request.collection,
        &request.approval_context,
    )
    .await
    {
        if !prefer_json {
            if let Some(response) =
                fallback_for_render_error(&state, &request, &placeholder_width, &headers, &err)
                    .await
            {
                record_render_metrics(
                    &state,
                    &response,
                    started.elapsed(),
                    &request.chain,
                    &request.collection,
                    source_label.as_deref(),
                );
                return Ok(response);
            }
        }
        let api_error = map_render_error(err);
        record_render_error_metrics(
            &state,
            started.elapsed(),
            &request.chain,
            &request.collection,
            source_label.as_deref(),
            api_error.code.as_deref(),
        );
        return Err(api_error);
    }
    if !prefer_json {
        if let Some(response) = resolve_token_override(&state, &request, &headers).await {
            record_render_metrics(
                &state,
                &response,
                started.elapsed(),
                &request.chain,
                &request.collection,
                source_label.as_deref(),
            );
            return Ok(response);
        }
    }
    let strategy = render::resolve_primary_strategy(&state, &chain, &collection)
        .await
        .map_err(map_render_error_anyhow)?;
    if matches!(strategy, render::PrimaryRenderStrategy::Erc721Metadata) {
        let cache_key = crate::state::token_uri_negative_cache_key(&chain, &collection);
        if let Some(retry_after_seconds) = state
            .token_uri_negative_cache
            .get_retry_after(&cache_key)
            .await
        {
            let err = anyhow::Error::new(render::TokenUriNegativeCacheError {
                retry_after_seconds,
            });
            if !prefer_json {
                if let Some(response) =
                    fallback_for_render_error(&state, &request, &placeholder_width, &headers, &err)
                        .await
                {
                    record_render_metrics(
                        &state,
                        &response,
                        started.elapsed(),
                        &request.chain,
                        &request.collection,
                        source_label.as_deref(),
                    );
                    return Ok(response);
                }
            }
            let api_error = map_render_error(err);
            record_render_error_metrics(
                &state,
                started.elapsed(),
                &request.chain,
                &request.collection,
                source_label.as_deref(),
                api_error.code.as_deref(),
            );
            return Err(api_error);
        }
        request.asset_id = TOKEN_URI_FALLBACK_ASSET_ID.to_string();
        match state.chain.owner_of(&chain, &collection, &token_id).await {
            Ok(owner) => {
                if owner == ethers::types::Address::zero() {
                    let err = anyhow::Error::new(render::TokenNotFoundError);
                    if !prefer_json {
                        if let Some(response) = fallback_for_render_error(
                            &state,
                            &request,
                            &placeholder_width,
                            &headers,
                            &err,
                        )
                        .await
                        {
                            record_render_metrics(
                                &state,
                                &response,
                                started.elapsed(),
                                &request.chain,
                                &request.collection,
                                source_label.as_deref(),
                            );
                            return Ok(response);
                        }
                    }
                    let api_error = map_render_error(err);
                    record_render_error_metrics(
                        &state,
                        started.elapsed(),
                        &request.chain,
                        &request.collection,
                        source_label.as_deref(),
                        api_error.code.as_deref(),
                    );
                    return Err(api_error);
                }
            }
            Err(err) => {
                if is_contract_revert_error(&err) {
                    let err = anyhow::Error::new(render::TokenNotFoundError);
                    if !prefer_json {
                        if let Some(response) = fallback_for_render_error(
                            &state,
                            &request,
                            &placeholder_width,
                            &headers,
                            &err,
                        )
                        .await
                        {
                            record_render_metrics(
                                &state,
                                &response,
                                started.elapsed(),
                                &request.chain,
                                &request.collection,
                                source_label.as_deref(),
                            );
                            return Ok(response);
                        }
                    }
                    let api_error = map_render_error(err);
                    record_render_error_metrics(
                        &state,
                        started.elapsed(),
                        &request.chain,
                        &request.collection,
                        source_label.as_deref(),
                        api_error.code.as_deref(),
                    );
                    return Err(api_error);
                }
                let api_error = map_render_error(err);
                record_render_error_metrics(
                    &state,
                    started.elapsed(),
                    &request.chain,
                    &request.collection,
                    source_label.as_deref(),
                    api_error.code.as_deref(),
                );
                return Err(api_error);
            }
        }
        return render_canonical(
            State(state),
            Path((
                chain,
                collection,
                token_id,
                TOKEN_URI_FALLBACK_ASSET_ID.to_string(),
                format.extension().to_string(),
            )),
            Query(query),
            headers,
            context,
        )
        .await;
    }
    if matches!(strategy, render::PrimaryRenderStrategy::FallbackOnly) {
        let err = anyhow::Error::new(render::UnsupportedStrategyError);
        if !prefer_json {
            if let Some(response) =
                fallback_for_render_error(&state, &request, &placeholder_width, &headers, &err)
                    .await
            {
                record_render_metrics(
                    &state,
                    &response,
                    started.elapsed(),
                    &request.chain,
                    &request.collection,
                    source_label.as_deref(),
                );
                return Ok(response);
            }
        }
        let api_error = map_render_error(err);
        record_render_error_metrics(
            &state,
            started.elapsed(),
            &request.chain,
            &request.collection,
            source_label.as_deref(),
            api_error.code.as_deref(),
        );
        return Err(api_error);
    }
    let asset_id = if fresh_requested {
        match state
            .chain
            .get_top_asset_id(&chain, &collection, &token_id)
            .await
        {
            Ok(asset_id) => {
                state
                    .primary_asset_cache
                    .insert(primary_cache_key.clone(), asset_id)
                    .await;
                asset_id
            }
            Err(err) => {
                if should_negative_cache_primary_asset(&err) {
                    state
                        .primary_asset_cache
                        .insert_negative(primary_cache_key.clone())
                        .await;
                }
                if is_top_asset_missing_error(&err) {
                    let supports_metadata = match render::collection_supports_erc721metadata(
                        &state,
                        &chain,
                        &collection,
                    )
                    .await
                    {
                        Ok(Some(true)) => true,
                        Ok(_) => false,
                        Err(check_err) => {
                            warn!(
                                chain = %chain,
                                collection = %collection,
                                token_id = %token_id,
                                error = ?check_err,
                                "metadata capability lookup failed; skipping token URI fallback"
                            );
                            false
                        }
                    };
                    if supports_metadata {
                        warn!(
                            chain = %chain,
                            collection = %collection,
                            token_id = %token_id,
                            error = ?err,
                            "top asset lookup reverted; falling back to token URI"
                        );
                        return render_canonical(
                            State(state.clone()),
                            Path((
                                chain,
                                collection,
                                token_id,
                                TOKEN_URI_FALLBACK_ASSET_ID.to_string(),
                                format.extension().to_string(),
                            )),
                            Query(query),
                            headers,
                            context,
                        )
                        .await;
                    }
                    warn!(
                        chain = %chain,
                        collection = %collection,
                        token_id = %token_id,
                        error = ?err,
                        "top asset lookup reverted; ERC721 metadata unsupported; using render fallback"
                    );
                    if !prefer_json {
                        if let Some(response) = fallback_for_render_error(
                            &state,
                            &request,
                            &placeholder_width,
                            &headers,
                            &err,
                        )
                        .await
                        {
                            record_render_metrics(
                                &state,
                                &response,
                                started.elapsed(),
                                &request.chain,
                                &request.collection,
                                source_label.as_deref(),
                            );
                            return Ok(response);
                        }
                    }
                    let api_error = ApiError::from(err);
                    record_render_error_metrics(
                        &state,
                        started.elapsed(),
                        &request.chain,
                        &request.collection,
                        source_label.as_deref(),
                        api_error.code.as_deref(),
                    );
                    return Err(api_error);
                }
                let api_error = ApiError::from(err);
                record_render_error_metrics(
                    &state,
                    started.elapsed(),
                    &request.chain,
                    &request.collection,
                    source_label.as_deref(),
                    api_error.code.as_deref(),
                );
                return Err(api_error);
            }
        }
    } else {
        match state.primary_asset_cache.get(&primary_cache_key).await {
            Some(crate::state::PrimaryAssetCacheValue::Hit(asset_id)) => asset_id,
            Some(crate::state::PrimaryAssetCacheValue::Negative) => {
                let api_error =
                    ApiError::new(StatusCode::BAD_GATEWAY, "primary asset lookup failed")
                        .with_code("primary_asset_lookup_failed");
                record_render_error_metrics(
                    &state,
                    started.elapsed(),
                    &request.chain,
                    &request.collection,
                    source_label.as_deref(),
                    api_error.code.as_deref(),
                );
                return Err(api_error);
            }
            None => {
                match state
                    .chain
                    .get_top_asset_id(&chain, &collection, &token_id)
                    .await
                {
                    Ok(asset_id) => {
                        state
                            .primary_asset_cache
                            .insert(primary_cache_key.clone(), asset_id)
                            .await;
                        asset_id
                    }
                    Err(err) => {
                        if should_negative_cache_primary_asset(&err) {
                            state
                                .primary_asset_cache
                                .insert_negative(primary_cache_key.clone())
                                .await;
                        }
                        if is_top_asset_missing_error(&err) {
                            let supports_metadata =
                                match render::collection_supports_erc721metadata(
                                    &state,
                                    &chain,
                                    &collection,
                                )
                                .await
                                {
                                    Ok(Some(true)) => true,
                                    Ok(_) => false,
                                    Err(check_err) => {
                                        warn!(
                                            chain = %chain,
                                            collection = %collection,
                                            token_id = %token_id,
                                            error = ?check_err,
                                            "metadata capability lookup failed; skipping token URI fallback"
                                        );
                                        false
                                    }
                                };
                            if supports_metadata {
                                warn!(
                                    chain = %chain,
                                    collection = %collection,
                                    token_id = %token_id,
                                    error = ?err,
                                    "top asset lookup reverted; falling back to token URI"
                                );
                                return render_canonical(
                                    State(state.clone()),
                                    Path((
                                        chain,
                                        collection,
                                        token_id,
                                        TOKEN_URI_FALLBACK_ASSET_ID.to_string(),
                                        format.extension().to_string(),
                                    )),
                                    Query(query),
                                    headers,
                                    context,
                                )
                                .await;
                            }
                            warn!(
                                chain = %chain,
                                collection = %collection,
                                token_id = %token_id,
                                error = ?err,
                                "top asset lookup reverted; ERC721 metadata unsupported; using render fallback"
                            );
                            if !prefer_json {
                                if let Some(response) = fallback_for_render_error(
                                    &state,
                                    &request,
                                    &placeholder_width,
                                    &headers,
                                    &err,
                                )
                                .await
                                {
                                    record_render_metrics(
                                        &state,
                                        &response,
                                        started.elapsed(),
                                        &request.chain,
                                        &request.collection,
                                        source_label.as_deref(),
                                    );
                                    return Ok(response);
                                }
                            }
                            let api_error = ApiError::from(err);
                            record_render_error_metrics(
                                &state,
                                started.elapsed(),
                                &request.chain,
                                &request.collection,
                                source_label.as_deref(),
                                api_error.code.as_deref(),
                            );
                            return Err(api_error);
                        }
                        let api_error = ApiError::from(err);
                        record_render_error_metrics(
                            &state,
                            started.elapsed(),
                            &request.chain,
                            &request.collection,
                            source_label.as_deref(),
                            api_error.code.as_deref(),
                        );
                        return Err(api_error);
                    }
                }
            }
        }
    };
    let mut target = format!(
        "/render/{}/{}/{}/{}/{}",
        chain,
        collection,
        token_id,
        asset_id,
        format.extension()
    );
    let mut query_string = raw_query.unwrap_or_default();
    if query.cache.is_none() {
        if let Some(cache_value) = cache_timestamp {
            if query_string.is_empty() {
                query_string = format!("cache={cache_value}");
            } else {
                query_string.push_str("&cache=");
                query_string.push_str(&cache_value);
            }
        }
    }
    if !query_string.is_empty() {
        target.push('?');
        target.push_str(&query_string);
    }
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "X-Renderer-Primary-AssetId",
        HeaderValue::from_str(&asset_id.to_string()).unwrap_or(HeaderValue::from_static("0")),
    );
    let response = (headers, Redirect::temporary(&target)).into_response();
    record_render_metrics(
        &state,
        &response,
        started.elapsed(),
        &request.chain,
        &request.collection,
        source_label.as_deref(),
    );
    Ok(response)
}

pub(super) async fn render_primary_or_legacy_asset(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_id, tail)): Path<(String, String, String, String)>,
    Query(query): Query<RenderQuery>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    if let Some((asset_id, format)) = tail.rsplit_once('.') {
        render_canonical(
            State(state),
            Path((
                chain,
                collection,
                token_id,
                asset_id.to_string(),
                format.to_string(),
            )),
            Query(query),
            headers,
            context,
        )
        .await
    } else {
        render_primary(
            State(state),
            Path((chain, collection, token_id, tail)),
            Query(query),
            RawQuery(raw_query),
            headers,
            context,
        )
        .await
    }
}

pub(super) async fn render_primary_compat(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_and_format)): Path<(String, String, String)>,
    Query(query): Query<RenderQuery>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    let (token_id, format) = split_dotted_segment(&token_and_format)?;
    render_primary(
        State(state),
        Path((chain, collection, token_id, format)),
        Query(query),
        RawQuery(raw_query),
        headers,
        context,
    )
    .await
}

pub(super) async fn render_legacy_compat(
    State(state): State<Arc<AppState>>,
    Path((chain, cache_timestamp, collection, token_id, asset)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<RenderQuery>,
    headers: HeaderMap,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    let (asset_id, format) = split_dotted_segment(&asset)?;
    render_legacy(
        State(state),
        Path((
            chain,
            cache_timestamp,
            collection,
            token_id,
            asset_id,
            format,
        )),
        Query(query),
        headers,
        context,
    )
    .await
}

pub(super) async fn render_og_compat(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_id, asset)): Path<(String, String, String, String)>,
    Query(query): Query<RenderQuery>,
    headers: HeaderMap,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    let (asset_id, format) = split_dotted_segment(&asset)?;
    render_og(
        State(state),
        Path((chain, collection, token_id, asset_id, format)),
        Query(query),
        headers,
        context,
    )
    .await
}

pub(super) async fn head_render_canonical(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_id, asset_id, format)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<RenderQuery>,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    let format = OutputFormat::from_extension(&format)
        .ok_or_else(|| ApiError::bad_request("unsupported image format"))?;
    let width_param = query.width.or(query.img_width);
    let (cache_timestamp, cache_param_present) = apply_cache_policy(
        &state,
        &chain,
        &collection,
        query.cache.clone(),
        query.cache.is_some(),
        context.as_ref().map(|ctx| &ctx.0),
    )
    .await?;
    let fresh = parse_fresh_flag(query.fresh.as_deref());
    let debug_requested =
        parse_bool_flag(query.debug.as_deref()) || parse_bool_flag(query.raw.as_deref());
    let allow_debug = context
        .as_ref()
        .map(|ctx| ctx.0.allow_debug)
        .unwrap_or(false);
    let raw_mode = debug_requested && allow_debug;
    let approval_context = approval_context_from_access(context.as_ref().map(|ctx| &ctx.0));
    let request = RenderRequest {
        chain,
        collection,
        token_id,
        asset_id,
        format,
        cache_timestamp,
        cache_param_present,
        width_param,
        og_mode: query.og_image.unwrap_or(false),
        overlay: query.overlay,
        background: query.bg,
        fresh,
        approval_context,
    };
    head_cached_response(state, request, raw_mode).await
}

pub(super) async fn head_render_og(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_id, asset_id, format)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<RenderQuery>,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    let format = OutputFormat::from_extension(&format)
        .ok_or_else(|| ApiError::bad_request("unsupported image format"))?;
    let width_param = query.width.or(query.img_width);
    let (cache_timestamp, cache_param_present) = apply_cache_policy(
        &state,
        &chain,
        &collection,
        query.cache.clone(),
        query.cache.is_some(),
        context.as_ref().map(|ctx| &ctx.0),
    )
    .await?;
    let fresh = parse_fresh_flag(query.fresh.as_deref());
    let debug_requested =
        parse_bool_flag(query.debug.as_deref()) || parse_bool_flag(query.raw.as_deref());
    let allow_debug = context
        .as_ref()
        .map(|ctx| ctx.0.allow_debug)
        .unwrap_or(false);
    let raw_mode = debug_requested && allow_debug;
    let approval_context = approval_context_from_access(context.as_ref().map(|ctx| &ctx.0));
    let request = RenderRequest {
        chain,
        collection,
        token_id,
        asset_id,
        format,
        cache_timestamp,
        cache_param_present,
        width_param,
        og_mode: true,
        overlay: query.overlay,
        background: query.bg,
        fresh,
        approval_context,
    };
    head_cached_response(state, request, raw_mode).await
}

pub(super) async fn head_render_legacy(
    State(state): State<Arc<AppState>>,
    Path((chain, cache_epoch, collection, token_id, asset_id, format)): Path<(
        String,
        String,
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<RenderQuery>,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    let format = OutputFormat::from_extension(&format)
        .ok_or_else(|| ApiError::bad_request("unsupported image format"))?;
    let width_param = query.width.or(query.img_width);
    let (cache_timestamp, cache_param_present) = apply_cache_policy(
        &state,
        &chain,
        &collection,
        Some(cache_epoch),
        true,
        context.as_ref().map(|ctx| &ctx.0),
    )
    .await?;
    let fresh = parse_fresh_flag(query.fresh.as_deref());
    let debug_requested =
        parse_bool_flag(query.debug.as_deref()) || parse_bool_flag(query.raw.as_deref());
    let allow_debug = context
        .as_ref()
        .map(|ctx| ctx.0.allow_debug)
        .unwrap_or(false);
    let raw_mode = debug_requested && allow_debug;
    let approval_context = approval_context_from_access(context.as_ref().map(|ctx| &ctx.0));
    let request = RenderRequest {
        chain,
        collection,
        token_id,
        asset_id,
        format,
        cache_timestamp,
        cache_param_present,
        width_param,
        og_mode: query.og_image.unwrap_or(false),
        overlay: query.overlay,
        background: query.bg,
        fresh,
        approval_context,
    };
    head_cached_response(state, request, raw_mode).await
}

pub(super) async fn head_render_primary_or_legacy_asset(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_id, tail)): Path<(String, String, String, String)>,
    Query(query): Query<RenderQuery>,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    if let Some((asset_id, format)) = tail.rsplit_once('.') {
        head_render_canonical(
            State(state),
            Path((
                chain,
                collection,
                token_id,
                asset_id.to_string(),
                format.to_string(),
            )),
            Query(query),
            context,
        )
        .await
    } else {
        Err(ApiError::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "head not supported for primary renders",
        )
        .with_code("method_not_allowed"))
    }
}

pub(super) async fn head_render_legacy_compat(
    State(state): State<Arc<AppState>>,
    Path((chain, cache_timestamp, collection, token_id, asset)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    Query(query): Query<RenderQuery>,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    let (asset_id, format) = split_dotted_segment(&asset)?;
    head_render_legacy(
        State(state),
        Path((
            chain,
            cache_timestamp,
            collection,
            token_id,
            asset_id,
            format,
        )),
        Query(query),
        context,
    )
    .await
}

pub(super) async fn head_render_og_compat(
    State(state): State<Arc<AppState>>,
    Path((chain, collection, token_id, asset)): Path<(String, String, String, String)>,
    Query(query): Query<RenderQuery>,
    context: Option<Extension<AccessContext>>,
) -> Result<Response, ApiError> {
    let (asset_id, format) = split_dotted_segment(&asset)?;
    head_render_og(
        State(state),
        Path((chain, collection, token_id, asset_id, format)),
        Query(query),
        context,
    )
    .await
}
