use super::*;

#[derive(Clone, Debug)]
pub(crate) struct AccessContext {
    pub(crate) identity_key: Arc<str>,
    pub(crate) client_key_id: Option<i64>,
    pub(crate) max_concurrent_renders_override: Option<usize>,
    pub(crate) allow_cache: bool,
    pub(crate) allow_fresh: bool,
    pub(crate) allow_on_demand_approval: bool,
    pub(crate) allow_debug: bool,
}

impl AccessContext {
    pub(crate) fn render_limit(&self) -> Option<RenderKeyLimit> {
        let limit = self.max_concurrent_renders_override?;
        if limit == 0 {
            return None;
        }
        let key_id = self.client_key_id?;
        Some(RenderKeyLimit {
            key_id,
            max_concurrent: limit,
        })
    }
}

fn generate_request_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    let rand: u64 = random();
    format!("{now:016x}-{rand:016x}")
}

fn attach_request_id(response: &mut Response, request_id: &str) {
    if let Ok(value) = HeaderValue::from_str(request_id) {
        response.headers_mut().insert("X-Request-Id", value);
    }
}

pub(crate) fn approval_context_from_access(
    context: Option<&AccessContext>,
) -> ApprovalCheckContext {
    match context {
        Some(ctx) if ctx.allow_on_demand_approval => {
            ApprovalCheckContext::allow(Some(Arc::clone(&ctx.identity_key)))
        }
        _ => ApprovalCheckContext::deny(),
    }
}

pub async fn access_middleware(
    state: Arc<AppState>,
    mut request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path();
    let _inflight = state.metrics.inflight_guard();
    let request_id = generate_request_id();
    if path == "/healthz" {
        let mut response = next.run(request).await;
        attach_request_id(&mut response, &request_id);
        record_http_metrics(&state, route_group(path), &method, &response, None);
        return response;
    }
    let route_group = route_group(path);
    let ip = client_ip(&request, &state);
    let is_admin = path == "/admin" || path.starts_with("/admin/");
    let is_public_landing = is_public_landing_path(&state, path);
    let is_public_status = is_public_status_path(&state, path);
    let is_public_openapi = is_public_openapi_path(&state, path);
    let is_public_metrics = is_metrics_path(path);
    let enforce_private = (is_status_path(path) && !state.config.status_public)
        || (is_openapi_path(path) && !state.config.openapi_public);

    if let Some(ip) = ip {
        let info = apply_ip_rate_limit(&state, ip).await;
        if !info.allowed {
            let mut response = rate_limit_response(Some(info));
            attach_request_id(&mut response, &request_id);
            log_failure_if_needed(
                &state,
                &response,
                &method,
                &uri,
                route_group,
                Some(ip),
                None,
                Some(&request_id),
            );
            record_usage(&state, route_group, &response, None);
            if route_group == "render" {
                state.metrics.observe_render_result("rate_limited");
            }
            record_http_metrics(&state, route_group, &method, &response, Some(ip));
            return response;
        }
    }

    let should_check_key = if enforce_private {
        true
    } else {
        match state.config.access_mode {
            AccessMode::Open | AccessMode::DenylistOnly => state.config.track_keys_in_open_mode,
            _ => true,
        }
    };
    let bearer = if should_check_key {
        extract_bearer_token(request.headers()).filter(|token| is_reasonable_token_len(token))
    } else {
        None
    };
    let key_info =
        if let (Some(token), Some(secret)) = (bearer, state.config.api_key_secret.as_deref()) {
            let hash = hash_api_key(secret, token);
            if let Some(key) = state.api_key_cache.get(&hash).await {
                Some(key)
            } else {
                let fetched = state.db.find_client_key_by_hash(&hash).await.ok().flatten();
                if let Some(key) = fetched.as_ref() {
                    state.api_key_cache.insert(hash, key.clone()).await;
                }
                fetched
            }
        } else {
            None
        };

    let ip_rule = if let Some(ip) = ip {
        ip_rule_for_ip(&state, ip).await
    } else {
        None
    };
    let key_active = key_info.as_ref().map(|key| key.active).unwrap_or(false);
    let allow_on_demand_approval = key_active || matches!(ip_rule.as_deref(), Some("allow"));
    let allow_debug = key_active || matches!(ip_rule.as_deref(), Some("allow"));
    let allow_cache = key_active || matches!(ip_rule.as_deref(), Some("allow"));

    let ip_identity = ip.map(|ip| AccessContext {
        identity_key: ip_identity_key(&state.config, ip),
        client_key_id: None,
        max_concurrent_renders_override: None,
        allow_cache,
        allow_fresh: false,
        allow_on_demand_approval,
        allow_debug,
    });

    let identity = if let Some(key) = key_info.as_ref() {
        Some(AccessContext {
            identity_key: Arc::from(format!("client:{}", key.client_id)),
            client_key_id: Some(key.id),
            max_concurrent_renders_override: key
                .max_concurrent_renders_override
                .and_then(|value| value.try_into().ok()),
            allow_cache,
            allow_fresh: key.allow_fresh,
            allow_on_demand_approval,
            allow_debug,
        })
    } else if ip_identity.is_some() {
        ip_identity.clone()
    } else {
        None
    };

    if !is_admin
        && !is_public_landing
        && !is_public_status
        && !is_public_openapi
        && !is_public_metrics
        && !(if enforce_private {
            is_private_access_allowed(key_info.as_ref(), ip_rule.as_deref())
        } else {
            is_access_allowed(&state, key_info.as_ref(), ip_rule.as_deref()).await
        })
    {
        if let Some(ip) = ip {
            let info = apply_auth_fail_limit(&state, ip).await;
            if !info.allowed {
                let mut response = rate_limit_response(Some(info));
                attach_request_id(&mut response, &request_id);
                log_failure_if_needed(
                    &state,
                    &response,
                    &method,
                    &uri,
                    route_group,
                    Some(ip),
                    identity.as_ref(),
                    Some(&request_id),
                );
                record_usage(&state, route_group, &response, identity.clone());
                if route_group == "render" {
                    state.metrics.observe_render_result("rate_limited");
                }
                record_http_metrics(&state, route_group, &method, &response, Some(ip));
                return response;
            }
        }
        let mut response = ApiError::new(StatusCode::UNAUTHORIZED, "access denied")
            .with_code("access_denied")
            .with_header(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"renderer\""),
            )
            .into_response();
        attach_request_id(&mut response, &request_id);
        log_failure_if_needed(
            &state,
            &response,
            &method,
            &uri,
            route_group,
            ip,
            identity.as_ref(),
            Some(&request_id),
        );
        record_usage(&state, route_group, &response, identity.clone());
        record_http_metrics(&state, route_group, &method, &response, ip);
        return response;
    }

    if let Some(key) = key_info.as_ref() {
        let info = apply_key_rate_limit(&state, key).await;
        if !info.allowed {
            let mut response = rate_limit_response(Some(info));
            attach_request_id(&mut response, &request_id);
            log_failure_if_needed(
                &state,
                &response,
                &method,
                &uri,
                route_group,
                ip,
                identity.as_ref(),
                Some(&request_id),
            );
            record_usage(&state, route_group, &response, identity.clone());
            if route_group == "render" {
                state.metrics.observe_render_result("rate_limited");
            }
            record_http_metrics(&state, route_group, &method, &response, ip);
            return response;
        }
    }

    if let Some(context) = identity.clone() {
        request.extensions_mut().insert(context);
    }

    let mut response = next.run(request).await;
    attach_request_id(&mut response, &request_id);
    log_failure_if_needed(
        &state,
        &response,
        &method,
        &uri,
        route_group,
        ip,
        identity.as_ref(),
        Some(&request_id),
    );
    record_usage(&state, route_group, &response, identity);
    record_http_metrics(&state, route_group, &method, &response, ip);
    response
}

async fn is_access_allowed(
    state: &AppState,
    key: Option<&crate::db::ClientKey>,
    ip_rule: Option<&str>,
) -> bool {
    match state.config.access_mode {
        AccessMode::Open => true,
        AccessMode::KeyRequired => key.map(|k| k.active).unwrap_or(false),
        AccessMode::Hybrid => {
            if let Some(key) = key {
                return key.active;
            }
            !matches!(ip_rule, Some("deny"))
        }
        AccessMode::DenylistOnly => {
            if let Some(key) = key {
                if !key.active {
                    return false;
                }
            }
            !matches!(ip_rule, Some("deny"))
        }
        AccessMode::AllowlistOnly => {
            if let Some(key) = key {
                return key.active;
            }
            matches!(ip_rule, Some("allow"))
        }
    }
}

fn is_private_access_allowed(key: Option<&crate::db::ClientKey>, ip_rule: Option<&str>) -> bool {
    if let Some(key) = key {
        if key.active {
            return true;
        }
    }
    matches!(ip_rule, Some("allow"))
}

async fn apply_ip_rate_limit(state: &AppState, ip: std::net::IpAddr) -> RateLimitInfo {
    state.rate_limiter.check(ip).await
}

async fn apply_auth_fail_limit(state: &AppState, ip: std::net::IpAddr) -> RateLimitInfo {
    state.auth_fail_limiter.check(ip).await
}

async fn apply_key_rate_limit(state: &AppState, key: &crate::db::ClientKey) -> RateLimitInfo {
    if !key.active {
        return RateLimitInfo {
            allowed: false,
            limit: 0,
            remaining: 0,
            reset_seconds: 0,
        };
    }
    let rate = key
        .rate_limit_per_minute
        .map(|value| value as u64)
        .unwrap_or(state.config.key_rate_limit_per_minute);
    let burst = key
        .burst
        .map(|value| value as u64)
        .unwrap_or(state.config.key_rate_limit_burst);
    state.key_rate_limiter.check(key.id, rate, burst).await
}
