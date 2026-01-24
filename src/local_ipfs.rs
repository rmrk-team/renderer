use crate::pinning::{PinnedAssetStore, content_type_from_path};
use axum::body::Body;
use axum::extract::Path;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use std::io::ErrorKind;
use std::sync::Arc;
use tokio_util::io::ReaderStream;

pub fn router(store: Arc<PinnedAssetStore>) -> Router {
    Router::new()
        .route("/ipfs/{*path}", get(serve_ipfs))
        .layer(Extension(store))
}

async fn serve_ipfs(
    Extension(store): Extension<Arc<PinnedAssetStore>>,
    Path(path): Path<String>,
) -> Response {
    if !store.enabled() {
        return (StatusCode::NOT_FOUND, "not pinned").into_response();
    }
    let raw = path.as_str().trim_matches('/');
    if raw.is_empty() {
        return (StatusCode::BAD_REQUEST, "missing ipfs cid").into_response();
    }
    let mut parts = raw.splitn(2, '/');
    let cid = parts.next().unwrap_or_default();
    let rest = parts.next().unwrap_or_default();
    let full_path = if rest.is_empty() {
        String::new()
    } else {
        format!("/{}", rest)
    };
    let location = match store.ipfs_location(cid, &full_path) {
        Ok(location) => location,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid ipfs path").into_response(),
    };
    let file = match tokio::fs::File::open(&location.file_path).await {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return (StatusCode::NOT_FOUND, "not pinned").into_response();
        }
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "read failed").into_response(),
    };
    let mut headers = HeaderMap::new();
    let content_type = content_type_from_path(&location.path).unwrap_or("application/octet-stream");
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    if let Ok(metadata) = file.metadata().await {
        if let Ok(value) = HeaderValue::from_str(&metadata.len().to_string()) {
            headers.insert(header::CONTENT_LENGTH, value);
        }
    }
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);
    (headers, body).into_response()
}
