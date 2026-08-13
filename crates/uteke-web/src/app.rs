//! Axum application builder — assembles the router with correct route
//! priority (specific routes before the catch-all proxy fallback).

use axum::Router;
use axum::response::Response;
use axum::routing::{get, post};
use tower_http::trace::TraceLayer;

use crate::dashboard;
use crate::oauth;
use crate::proxy;
use crate::state::AppState;

/// Build the full uteke-web axum router.
pub fn build_app(state: AppState) -> Router {
    // Specific routes (matched first by axum's router).
    let local = Router::new()
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

    // Catch-all proxy fallback (M5 + M6).
    Router::new()
        .merge(local)
        .merge(proxy::proxy_route())
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}
