use super::*;

pub(crate) fn admin_router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    admin::router(state)
}

pub(crate) fn is_admin_authorized(config: &Config, headers: &HeaderMap) -> bool {
    let password = config.admin_password.as_str();
    let auth = match headers.get(header::AUTHORIZATION) {
        Some(value) => value.to_str().unwrap_or(""),
        None => return false,
    };
    let mut parts = auth.split_whitespace();
    let scheme = match parts.next() {
        Some(value) => value,
        None => return false,
    };
    let token = match parts.next() {
        Some(value) => value,
        None => return false,
    };
    if scheme.eq_ignore_ascii_case("bearer") {
        return bool::from(password.as_bytes().ct_eq(token.as_bytes()));
    }
    false
}
