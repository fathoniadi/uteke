//! Axum application builder — assembles the router with correct route
//! priority (specific routes before the catch-all proxy fallback).

use axum::Router;
use axum::http::{HeaderName, Method};
use axum::response::Response;
use axum::routing::{get, post};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::dashboard;
use crate::oauth;
use crate::proxy;
use crate::state::AppState;

/// Build the full uteke-web axum router.
pub fn build_app(state: AppState) -> Router {
    // Check CORS config before state is moved into the router.
    let cors_layer = if state.config.cors.enabled {
        Some(build_cors_layer(&state.config.cors))
    } else {
        None
    };

    // Specific routes (matched first by axum's router).
    let local = Router::new()
        // Root — explicit 404 so it never falls through to the proxy
        // catch-all (which would forward to upstream and can trigger a
        // browser download for non-HTML responses).
        .route(
            "/",
            get(|| async move {
                axum::http::StatusCode::NOT_FOUND
            }),
        )
        // OAuth2 auth server
        .route("/oauth2/auth", get(oauth::authorize))
        .route("/oauth2/login", post(oauth::login))
        .route("/oauth2/token", post(oauth::token))
        .route("/oauth2/register", post(oauth::register))
        .route("/oauth2/revoke", post(oauth::revoke))
        .route("/oauth2/introspect", post(oauth::introspect))
        // Well-known
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth::metadata),
        )
        .route("/.well-known/jwks-uri", get(oauth::jwks))
        // Profile + health
        .route("/profile", get(oauth::profile))
        .route("/healthz", get(oauth::healthz))
        // Metrics (M9)
        .route(
            "/metrics",
            get(|| async move { Response::new(axum::body::Body::from(crate::metrics::render())) }),
        )
        // Dashboard (M7) — merged as a sub-router
        .merge(dashboard::dashboard_router());

    let mut router = Router::new()
        .merge(local)
        .merge(proxy::proxy_route())
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    // CORS layer (only if enabled in config).
    if let Some(cors) = cors_layer {
        router = router.layer(cors);
    }

    router
}

/// Build a `CorsLayer` from config.
fn build_cors_layer(cors: &crate::config::CorsConfig) -> CorsLayer {
    let mut layer = CorsLayer::new();

    // Origins
    if cors.allow_origins.len() == 1 && cors.allow_origins[0] == "*" {
        // Wildcard — credentials must be false (enforced by spec).
        layer = layer.allow_origin(AllowOrigin::any());
    } else {
        let origins: Vec<axum::http::HeaderValue> = cors
            .allow_origins
            .iter()
            .filter_map(|o| axum::http::HeaderValue::from_str(o).ok())
            .collect();
        layer = layer.allow_origin(origins);
    }

    // Methods
    let methods: Vec<Method> = cors
        .allow_methods
        .iter()
        .filter_map(|m| m.parse::<Method>().ok())
        .collect();
    layer = layer.allow_methods(methods);

    // Headers
    let headers: Vec<HeaderName> = cors
        .allow_headers
        .iter()
        .filter_map(|h| HeaderName::from_bytes(h.as_bytes()).ok())
        .collect();
    layer = layer.allow_headers(headers);

    // Credentials
    if cors.allow_credentials {
        layer = layer.allow_credentials(true);
    }

    // Max age
    layer = layer.max_age(std::time::Duration::from_secs(cors.max_age_secs));

    layer
}
