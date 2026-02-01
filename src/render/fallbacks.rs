use super::*;

pub(super) fn is_non_composable_error(err: &anyhow::Error) -> bool {
    match revert_selector(err) {
        Some(selector) => {
            selector == SELECTOR_NON_COMPOSABLE_ASSET
                || selector == SELECTOR_NON_COMPOSABLE_ASSET_ALT
                || selector == SELECTOR_COMPOSE_EQUIP_REVERT
        }
        None => false,
    }
}

pub(super) fn is_asset_too_large_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        if let Some(fetch_error) = cause.downcast_ref::<AssetFetchError>() {
            matches!(fetch_error, AssetFetchError::TooLarge)
        } else {
            cause.to_string().contains("asset too large")
        }
    })
}
