use crate::config::LandingConfig;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, get_service};
use axum::Router;
use std::path::{Component, Path};
use tower_http::services::{ServeDir, ServeFile};

const ALLOWED_EXTENSIONS: &[&str] = &[
    "html", "css", "js", "png", "jpg", "jpeg", "svg", "webp", "ico", "json",
];
const DEFAULT_LANDING_HTML: &str = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Renderer</title>
    <style>
      body { font-family: system-ui, sans-serif; max-width: 860px; margin: 40px auto; padding: 0 16px; }
      code, pre { background: #f4f4f4; padding: 2px 6px; border-radius: 4px; }
      pre { padding: 12px; overflow-x: auto; }
    </style>
  </head>
  <body>
    <h1>Renderer</h1>
    <p>Use the canonical render path for cache-first performance.</p>
    <h3>Canonical render</h3>
    <pre>GET /render/{chain}/{collection}/{tokenId}/{assetId}/png?cache=1700000000000</pre>
    <h3>Primary render (redirects)</h3>
    <pre>GET /render/{chain}/{collection}/{tokenId}/png?cache=1700000000000</pre>
    <h3>HEAD (cache probe)</h3>
    <pre>HEAD /render/{chain}/{collection}/{tokenId}/{assetId}/png?cache=1700000000000</pre>
    <p><code>cache=</code> selects a specific cache epoch; omit it to use collection cache epoch or default.</p>
  </body>
</html>
"#;

pub fn router(config: &LandingConfig) -> Router {
    let index_path = config.dir.join(&config.file);
    let serve_file = if index_path.exists() {
        get_service(ServeFile::new(index_path))
    } else {
        get(default_landing)
    };
    let serve_dir = ServeDir::new(&config.dir);
    let strict_headers = config.strict_headers;
    Router::new()
        .route("/", serve_file)
        .fallback_service(serve_dir)
        .layer(axum::middleware::from_fn(move |request, next| {
            landing_allowlist(request, next, strict_headers)
        }))
}

async fn default_landing() -> Html<&'static str> {
    Html(DEFAULT_LANDING_HTML)
}

async fn landing_allowlist(
    request: Request<Body>,
    next: Next,
    strict_headers: bool,
) -> Response {
    let path = request.uri().path();
    if is_landing_asset_path(path) {
        let mut response = next.run(request).await;
        apply_landing_headers(&mut response, strict_headers);
        return response;
    }
    let mut response = StatusCode::NOT_FOUND.into_response();
    apply_landing_headers(&mut response, strict_headers);
    response
}

pub fn is_landing_asset_path(path: &str) -> bool {
    if !is_safe_landing_path(path) {
        return false;
    }
    if path == "/" {
        return true;
    }
    if let Some(ext) = Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
    {
        let ext = ext.to_ascii_lowercase();
        return ALLOWED_EXTENSIONS.iter().any(|allowed| *allowed == ext);
    }
    false
}

fn is_safe_landing_path(path: &str) -> bool {
    if path.contains('\0') || path.contains('\\') {
        return false;
    }
    let lowered = path.to_ascii_lowercase();
    if lowered.contains("%2e") || lowered.contains("%2f") || lowered.contains("%5c") {
        return false;
    }
    for component in Path::new(path).components() {
        match component {
            Component::RootDir | Component::Normal(_) => {}
            _ => return false,
        }
    }
    true
}

fn apply_landing_headers(response: &mut Response, strict_headers: bool) {
    response.headers_mut().insert(
        "X-Content-Type-Options",
        axum::http::HeaderValue::from_static("nosniff"),
    );
    if strict_headers {
        response.headers_mut().insert(
            "Content-Security-Policy",
            axum::http::HeaderValue::from_static(
                "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'",
            ),
        );
        response.headers_mut().insert(
            "X-Frame-Options",
            axum::http::HeaderValue::from_static("DENY"),
        );
        response.headers_mut().insert(
            "Referrer-Policy",
            axum::http::HeaderValue::from_static("no-referrer"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tempfile::tempdir;
    use tower::ServiceExt;

    #[tokio::test]
    async fn landing_serves_index_and_asset() {
        let dir = tempdir().unwrap();
        let index_path = dir.path().join("index.html");
        let asset_path = dir.path().join("app.js");
        std::fs::write(&index_path, "hello").unwrap();
        std::fs::write(&asset_path, "console.log('ok')").unwrap();

        let config = LandingConfig {
            dir: dir.path().to_path_buf(),
            file: "index.html".to_string(),
            strict_headers: true,
        };
        let app = router(&config);

        let response = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body, "hello");

        let response = app
            .clone()
            .oneshot(Request::builder().uri("/app.js").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(body.starts_with(b"console.log"));

        let response = app
            .oneshot(Request::builder().uri("/secret.env").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn landing_rejects_traversal_paths() {
        let dir = tempdir().unwrap();
        let index_path = dir.path().join("index.html");
        std::fs::write(&index_path, "hello").unwrap();

        let config = LandingConfig {
            dir: dir.path().to_path_buf(),
            file: "index.html".to_string(),
            strict_headers: true,
        };
        let app = router(&config);

        let response = app
            .clone()
            .oneshot(Request::builder().uri("/../secret.env").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/%2e%2e/secret.env")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn landing_falls_back_to_default_template() {
        let dir = tempdir().unwrap();
        let config = LandingConfig {
            dir: dir.path().to_path_buf(),
            file: "missing.html".to_string(),
            strict_headers: true,
        };
        let app = router(&config);

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(body.starts_with(b"<!doctype html>"));
    }
}
