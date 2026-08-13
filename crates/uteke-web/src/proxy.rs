//! Reverse proxy (M5 + M6) — JWT validation middleware + forwarding to
//! uteke-server with a static upstream token injected.
//!
//! Route priority: axum matches specific routes first; the catch-all `/*` is
//! the fallback proxy. CORS headers from upstream are stripped to avoid
//! double-setting. Upstream errors: 502 (connection), 504 (timeout).

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;

use crate::jwt;
use crate::state::AppState;

/// CORS-related headers to strip from upstream responses (uteke-server sets
/// its own; we don't want duplicates).
const CORS_HEADERS_STRIP: &[&str] = &[
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-allow-credentials",
    "access-control-expose-headers",
    "access-control-max-age",
];

/// Build the catch-all proxy route.
pub fn proxy_route() -> axum::Router<AppState> {
    axum::Router::new().route("/{*path}", any(proxy_handler))
}

/// The proxy handler: validate JWT → forward to upstream with static token.
pub async fn proxy_handler(
    State(state): State<AppState>,
    method: Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // 1. Validate JWT access token.
    let token = match extract_bearer(&headers) {
        Some(t) => t,
        None => {
            return proxy_unauthorized("missing_bearer", "Authorization: Bearer <token> required");
        }
    };
    let claims =
        match jwt::verify_access_token(&state.config.jwt_secret, &state.config.issuer, &token) {
            Ok(c) => c,
            Err(_) => return proxy_unauthorized("invalid_token", "token invalid or expired"),
        };

    // 2. Scope enforcement: read = GET, write = POST/PUT/PATCH, admin = DELETE.
    let scope: Vec<&str> = claims.scope.split_whitespace().collect();
    let needs_admin = method == Method::DELETE;
    let needs_write = matches!(method, Method::POST | Method::PUT | Method::PATCH);
    if needs_admin && !scope.contains(&"admin") {
        return proxy_forbidden("insufficient_scope", "admin scope required for DELETE");
    }
    if needs_write && !scope.contains(&"write") && !scope.contains(&"admin") {
        return proxy_forbidden("insufficient_scope", "write scope required");
    }

    // 3. Build upstream URL (preserve path + query).
    let path = uri.path();
    let query = uri.query().unwrap_or("");
    let upstream_url = if query.is_empty() {
        format!("{}{}", state.config.upstream, path)
    } else {
        format!("{}{}?{}", state.config.upstream, path, query)
    };

    // 4. Forward request with static token + extra headers injected.
    crate::metrics::inc_proxy_requests();
    let mut req_headers = headers.clone();
    // Remove the client's Authorization header; inject the static upstream token.
    req_headers.remove("authorization");
    req_headers.remove("host");
    state.apply_upstream_auth(&mut req_headers);

    let proxy_req = state
        .http_client
        .request(
            reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
            &upstream_url,
        )
        .headers(req_headers)
        .body(body);

    let resp = match proxy_req.send().await {
        Ok(r) => r,
        Err(e) => {
            crate::metrics::inc_proxy_errors();
            if e.is_timeout() {
                tracing::warn!("upstream timeout: {e}");
                return proxy_error(StatusCode::GATEWAY_TIMEOUT, "upstream timeout");
            }
            tracing::warn!("upstream connection error: {e}");
            return proxy_error(StatusCode::BAD_GATEWAY, "upstream unavailable");
        }
    };

    // 5. Map response back, stripping CORS headers.
    let status =
        StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut out_headers = HeaderMap::new();
    for (name, value) in resp.headers().iter() {
        let lower = name.as_str().to_lowercase();
        if CORS_HEADERS_STRIP.contains(&lower.as_str()) {
            continue;
        }
        // Skip hop-by-hop headers.
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        if let Ok(n) = HeaderName::from_bytes(name.as_str().as_bytes()) {
            if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
                out_headers.insert(n, v);
            }
        }
    }

    let body_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("upstream body read error: {e}");
            return proxy_error(StatusCode::BAD_GATEWAY, "upstream body read failed");
        }
    };

    let mut response = Response::new(Body::from(body_bytes));
    *response.status_mut() = status;
    *response.headers_mut() = out_headers;
    response
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let h = headers.get("authorization")?.to_str().ok()?;
    let token = h.strip_prefix("Bearer ")?;
    Some(token.trim().to_string())
}

fn proxy_unauthorized(error: &str, description: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            "WWW-Authenticate",
            format!("Bearer error=\"{error}\", error_description=\"{description}\""),
        )],
        Json(serde_json::json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

fn proxy_forbidden(error: &str, description: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

fn proxy_error(code: StatusCode, msg: &str) -> Response {
    (
        code,
        Json(serde_json::json!({ "error": "proxy_error", "error_description": msg })),
    )
        .into_response()
}

/// Re-export Json for response helpers in this module.
use axum::response::Json;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_detection() {
        assert!(is_hop_by_hop("Connection"));
        assert!(is_hop_by_hop("transfer-encoding"));
        assert!(!is_hop_by_hop("content-type"));
    }

    #[test]
    fn extract_bearer_from_headers() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer xyz".parse().unwrap());
        assert_eq!(extract_bearer(&h).as_deref(), Some("xyz"));
        assert!(extract_bearer(&HeaderMap::new()).is_none());
    }
}
