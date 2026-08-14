//! Dashboard (M7) — SPA shell, OAuth2 callback, session cookie, CSRF, and
//! the typed `/dashboard/api/*` REST layer (see `dashboard_api.rs`).
//!
//! Flow:
//! 1. `GET /dashboard` — no valid session cookie → redirect to `/oauth2/auth`
//!    with the dashboard's own client_id. With a valid session → serve SPA.
//! 2. `GET /dashboard/callback` — exchange auth code for access token, fetch
//!    `/profile`, create server-side session, set signed cookie, redirect.
//! 3. `GET/POST/PUT/DELETE /dashboard/api/*` — typed handlers that validate
//!    session cookie + CSRF, then translate the call to uteke-server.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Json, Redirect, Response};
use axum::routing::{delete, get, post};
use serde::Deserialize;

use crate::session;
use crate::state::AppState;

use crate::dashboard_api;

/// The dashboard's own OAuth2 client_id (registered at startup).
pub const DASHBOARD_CLIENT_ID: &str = "uteke-web-dashboard";

/// CSRF header name expected on all `/dashboard/api/*` mutations.
pub(crate) const CSRF_HEADER: &str = "x-csrf-token";
/// CSRF cookie name.
const CSRF_COOKIE: &str = "csrf_token";
/// Session cookie name.
const SESSION_COOKIE: &str = "uteke_session";

/// Build the dashboard router.
pub fn dashboard_router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/dashboard", get(dashboard_index))
        // Trailing-slash alias — axum 0.8 does not auto-redirect `/dashboard/`
        // to `/dashboard`, so without this the catch-all proxy swallows it
        // and returns 401 instead of the OAuth2 login redirect.
        .route("/dashboard/", get(dashboard_index))
        // Alias so a bookmarked/typed "/dashboard/login" behaves exactly
        // like "/dashboard" (serve SPA if a valid session exists, else
        // redirect to OAuth2 authorize) instead of 404ing.
        .route("/dashboard/login", get(dashboard_index))
        .route("/dashboard/callback", get(dashboard_callback))
        .route("/dashboard/logout", post(dashboard_logout))
        // Typed browser-facing API (M7.1) — replaces the generic passthrough.
        .route(
            "/dashboard/api/memories",
            get(dashboard_api::handle_list_memories).post(dashboard_api::handle_create_memory),
        )
        .route(
            "/dashboard/api/memories/{id}",
            get(dashboard_api::handle_get_memory)
                .put(dashboard_api::handle_update_memory)
                .delete(dashboard_api::handle_forget_memory),
        )
        .route(
            "/dashboard/api/memories/{id}/doc-refs",
            get(dashboard_api::handle_memory_doc_refs),
        )
        .route("/dashboard/api/tags", get(dashboard_api::handle_tags))
        .route(
            "/dashboard/api/namespaces",
            get(dashboard_api::handle_namespaces),
        )
        .route("/dashboard/api/stats", get(dashboard_api::handle_stats))
        .route("/dashboard/api/profile", get(dashboard_api::handle_profile))
        // Documents (PLAN-docs.md) — wrap upstream `/doc/*`.
        .route(
            "/dashboard/api/documents",
            get(dashboard_api::handle_list_documents).post(dashboard_api::handle_create_document),
        )
        .route(
            "/dashboard/api/documents/search",
            get(dashboard_api::handle_search_documents),
        )
        .route(
            "/dashboard/api/documents/{slug}",
            get(dashboard_api::handle_get_document)
                .put(dashboard_api::handle_update_document)
                .delete(dashboard_api::handle_delete_document),
        )
        .route(
            "/dashboard/api/documents/{slug}/mem-refs",
            get(dashboard_api::handle_document_mem_refs),
        )
        .route(
            "/dashboard/api/documents/{slug}/move",
            post(dashboard_api::handle_move_document),
        )
        // Rooms (PLAN-rooms.md) — wrap upstream `/room/*`.
        .route(
            "/dashboard/api/rooms",
            get(dashboard_api::handle_list_rooms).post(dashboard_api::handle_create_room),
        )
        .route(
            "/dashboard/api/rooms/{id}",
            get(dashboard_api::handle_get_room).delete(dashboard_api::handle_delete_room),
        )
        .route(
            "/dashboard/api/rooms/{id}/memories",
            get(dashboard_api::handle_list_room_memories)
                .post(dashboard_api::handle_create_room_memory),
        )
        .route(
            "/dashboard/api/rooms/{id}/documents",
            get(dashboard_api::handle_list_room_documents)
                .post(dashboard_api::handle_link_room_document)
                .delete(dashboard_api::handle_unlink_room_document),
        )
        // Room summary & recall (Tier 1) — wrap upstream `/room/summary`,
        // `/room/summary-document`, `/room/recall`.
        .route(
            "/dashboard/api/rooms/{id}/summary",
            get(dashboard_api::handle_room_summary),
        )
        .route(
            "/dashboard/api/rooms/{id}/summary-document",
            get(dashboard_api::handle_room_summary_document),
        )
        .route(
            "/dashboard/api/rooms/{id}/recall",
            get(dashboard_api::handle_room_recall),
        )
        // Memory feedback, graph, timeline (Tier 1).
        .route(
            "/dashboard/api/memories/{id}/feedback",
            post(dashboard_api::handle_memory_feedback),
        )
        .route(
            "/dashboard/api/memories/{id}/graph",
            get(dashboard_api::handle_memory_graph),
        )
        .route(
            "/dashboard/api/memories/{id}/edges",
            post(dashboard_api::handle_memory_edges_add)
                .delete(dashboard_api::handle_memory_edges_remove),
        )
        .route(
            "/dashboard/api/memories/{id}/timeline",
            get(dashboard_api::handle_memory_timeline),
        )
        // Tags management (Tier 1) — wrap upstream `/tags/rename`, `/tags/delete`.
        .route(
            "/dashboard/api/tags/rename",
            post(dashboard_api::handle_tag_rename),
        )
        .route(
            "/dashboard/api/tags/{tag}",
            delete(dashboard_api::handle_tag_delete),
        )
        // Import / Export (Tier 1) — wrap upstream `/export`, `/import`.
        .route("/dashboard/api/export", get(dashboard_api::handle_export))
        .route("/dashboard/api/import", post(dashboard_api::handle_import))
        // Document rooms (Tier 1) — wrap upstream `/doc/room/list`.
        .route(
            "/dashboard/api/documents/{slug}/rooms",
            get(dashboard_api::handle_document_rooms),
        )
}

// ── Dashboard index ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// `GET /dashboard` — serve SPA if authenticated, else redirect to authorize.
pub async fn dashboard_index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !state.config.dashboard.enabled {
        return (StatusCode::NOT_FOUND, "dashboard disabled").into_response();
    }
    // Check for valid session cookie.
    if let Some(session_id) = extract_session(&headers, &state.config.jwt_secret) {
        if state.store.get_session(&session_id).is_some() {
            // The SPA shell is served fresh from disk on every request (see
            // dashboard_spa()) specifically so edits take effect without a
            // rebuild — but without this header the browser is free to
            // cache the HTML response itself, which then silently serves a
            // stale JS bundle on normal navigation until a hard refresh.
            let mut resp = Html(dashboard_spa()).into_response();
            resp.headers_mut().insert(
                axum::http::header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            );
            return resp;
        }
    }
    // No valid session → redirect to OAuth2 authorize.
    let verifier = crate::pkce::random_verifier();
    let challenge = crate::pkce::s256_challenge(&verifier);
    // We can't persist the verifier across the redirect without a session, so
    // we encode it in the state param (it's only used once and short-lived).
    // state = base64(verifier) so callback can recover it.
    let state_param = crate::auth_store::base64_url(verifier.as_bytes());
    let redirect_uri = format!("{}/dashboard/callback", state.config.issuer);
    let auth_url = format!(
        "{issuer}/oauth2/auth?response_type=code&client_id={cid}&redirect_uri={ru}&scope=read+write&state={st}&code_challenge={cc}&code_challenge_method=S256",
        issuer = state.config.issuer,
        cid = DASHBOARD_CLIENT_ID,
        ru = urlencoding::encode(&redirect_uri),
        st = urlencoding::encode(&state_param),
        cc = urlencoding::encode(&challenge),
    );
    Redirect::to(&auth_url).into_response()
}

/// `GET /dashboard/callback` — exchange code, create session, set cookie.
pub async fn dashboard_callback(
    State(state): State<AppState>,
    Query(params): Query<CallbackParams>,
) -> Response {
    if let Some(err) = params.error {
        let body = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>uteke — Login Failed</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
</head>
<body class="d-flex align-items-center justify-content-center min-vh-100 bg-light">
<div class="card shadow-sm" style="max-width:420px;">
  <div class="card-body p-4 text-center">
    <i class="bi bi-x-octagon fs-1 text-danger"></i>
    <h1 class="h4 mt-2">Login failed</h1>
    <p class="text-muted">{}</p>
    <a href="/dashboard" class="btn btn-outline-primary btn-sm"><i class="bi bi-arrow-left"></i> Back</a>
  </div>
</div>
</body>
</html>"#,
            html_escape(&err)
        );
        return (StatusCode::BAD_REQUEST, Html(body)).into_response();
    }
    let code = match params.code {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "missing code").into_response(),
    };
    let state_param = params.state.unwrap_or_default();
    // Recover the PKCE verifier from state.
    let verifier = match crate::auth_store::base64_url_decode(&state_param) {
        Some(v) => String::from_utf8(v).unwrap_or_default(),
        None => return (StatusCode::BAD_REQUEST, "invalid state").into_response(),
    };
    // Exchange code for access token via the token endpoint (internal HTTP call).
    let token_url = format!("{}/oauth2/token", state.config.issuer);
    let redirect_uri = format!("{}/dashboard/callback", state.config.issuer);
    let token_resp = state
        .http_client
        .post(&token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", DASHBOARD_CLIENT_ID),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await;
    let token_json: serde_json::Value = match token_resp {
        Ok(r) if r.status().is_success() => r.json().await.unwrap_or(serde_json::json!({})),
        Ok(r) => {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            tracing::warn!("token exchange failed: {status} {body}");
            return (StatusCode::BAD_GATEWAY, "token exchange failed").into_response();
        }
        Err(e) => {
            tracing::warn!("token exchange error: {e}");
            return (StatusCode::BAD_GATEWAY, "token exchange error").into_response();
        }
    };
    let access_token = token_json
        .get("access_token")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if access_token.is_empty() {
        return (StatusCode::BAD_GATEWAY, "no access token in response").into_response();
    }
    // Fetch /profile to get username.
    let profile_url = format!("{}/profile", state.config.issuer);
    let profile_resp = state
        .http_client
        .get(&profile_url)
        .header("authorization", format!("Bearer {access_token}"))
        .send()
        .await;
    let username = match profile_resp {
        Ok(r) if r.status().is_success() => {
            let pj: serde_json::Value = r.json().await.unwrap_or_default();
            pj.get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        }
        _ => String::new(),
    };
    if username.is_empty() {
        return (StatusCode::BAD_GATEWAY, "failed to fetch profile").into_response();
    }
    // Create server-side session.
    let session_id = session::new_session_id();
    let csrf_token = session::new_csrf_token();
    let ttl = (state.config.dashboard.session_ttl_hours as i64) * 3600;
    if let Err(e) = state
        .store
        .add_session(&session_id, &username, &csrf_token, ttl)
    {
        tracing::error!("session store error: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "session error").into_response();
    }
    // Set signed cookie + CSRF cookie, redirect to /dashboard.
    // SameSite=Lax (not Strict) — allows cookie on top-level redirect from
    // OAuth2 callback. Lax still blocks cross-site POST (CSRF protection).
    let signed = session::sign_session_cookie(&session_id, &state.config.jwt_secret);
    let secure = state.config.issuer.starts_with("https://");
    let secure_flag = if secure { "; Secure" } else { "" };
    let cookie_val = format!(
        "{SESSION_COOKIE}={signed}; Path=/; HttpOnly; SameSite=Lax{secure_flag}; Max-Age={ttl}"
    );
    let csrf_cookie =
        format!("{CSRF_COOKIE}={csrf_token}; Path=/; SameSite=Lax{secure_flag}; Max-Age={ttl}");
    let mut headers = HeaderMap::new();
    headers.append(
        "set-cookie",
        HeaderValue::from_str(&cookie_val).unwrap_or(HeaderValue::from_static("")),
    );
    headers.append(
        "set-cookie",
        HeaderValue::from_str(&csrf_cookie).unwrap_or(HeaderValue::from_static("")),
    );
    (headers, Redirect::to("/dashboard")).into_response()
}

/// `POST /dashboard/logout` — delete session, clear cookies.
pub async fn dashboard_logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(session_id) = extract_session(&headers, &state.config.jwt_secret) {
        let _ = state.store.delete_session(&session_id);
    }
    let mut out = HeaderMap::new();
    out.append(
        "set-cookie",
        HeaderValue::from_str(&format!("{SESSION_COOKIE}=; Path=/; Max-Age=0"))
            .unwrap_or(HeaderValue::from_static("")),
    );
    out.append(
        "set-cookie",
        HeaderValue::from_str(&format!("{CSRF_COOKIE}=; Path=/; Max-Age=0"))
            .unwrap_or(HeaderValue::from_static("")),
    );
    (out, Redirect::to("/dashboard")).into_response()
}

// ── SPA HTML ────────────────────────────────────────────────────────────────

fn dashboard_spa() -> String {
    // Serve from disk when available so UI edits (HTML/CSS/JS — this SPA
    // has no server-side templating, it's a static shell) take effect on
    // refresh without a rebuild+restart. Falls back to the copy embedded
    // at compile time (assets/dashboard.html) for packaged/fresh installs
    // that don't have the external file yet.
    if let Ok(home) = uteke_core::uteke_home() {
        let path = home.join("web").join("dashboard.html");
        if let Ok(s) = std::fs::read_to_string(&path) {
            return s;
        }
    }
    include_str!("../assets/dashboard.html").to_string()
}
// ── Helpers ─────────────────────────────────────────────────────────────────

pub(crate) fn extract_session(headers: &HeaderMap, secret: &str) -> Option<String> {
    let cookie = headers.get("cookie")?.to_str().ok()?;
    for pair in cookie.split(';') {
        let pair = pair.trim();
        if let Some(rest) = pair.strip_prefix(&format!("{SESSION_COOKIE}=")) {
            return session::verify_session_cookie(rest, secret);
        }
    }
    None
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub(crate) fn api_unauthorized(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "unauthorized", "detail": msg })),
    )
        .into_response()
}

pub(crate) fn api_forbidden(msg: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": "forbidden", "detail": msg })),
    )
        .into_response()
}

pub(crate) fn api_error(code: StatusCode, msg: &str) -> Response {
    (
        code,
        Json(serde_json::json!({ "error": "proxy_error", "detail": msg })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_basic() {
        assert_eq!(html_escape("a<b>c"), "a&lt;b&gt;c");
    }
}
