//! Dashboard (M7) — SPA shell, OAuth2 callback, session cookie, CSRF, and
//! the `/dashboard/api/*` JSON proxy to uteke-server (server-side, static token).
//!
//! Flow:
//! 1. `GET /dashboard` — no valid session cookie → redirect to `/oauth2/auth`
//!    with the dashboard's own client_id. With a valid session → serve SPA.
//! 2. `GET /dashboard/callback` — exchange auth code for access token, fetch
//!    `/profile`, create server-side session, set signed cookie, redirect.
//! 3. `GET/POST/PUT/DELETE /dashboard/api/*` — validate session cookie + CSRF,
//!    then proxy to uteke-server with the static upstream token.

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{Html, IntoResponse, Json, Redirect, Response};
use axum::routing::{any, get, post};
use serde::Deserialize;

use crate::session;
use crate::state::AppState;

/// The dashboard's own OAuth2 client_id (registered at startup).
pub const DASHBOARD_CLIENT_ID: &str = "uteke-web-dashboard";

/// CSRF header name expected on all `/dashboard/api/*` mutations.
const CSRF_HEADER: &str = "x-csrf-token";
/// CSRF cookie name.
const CSRF_COOKIE: &str = "csrf_token";
/// Session cookie name.
const SESSION_COOKIE: &str = "uteke_session";

/// Build the dashboard router.
pub fn dashboard_router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/dashboard", get(dashboard_index))
        .route("/dashboard/callback", get(dashboard_callback))
        .route("/dashboard/logout", post(dashboard_logout))
        .route("/dashboard/api/{*path}", any(dashboard_api))
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
            return Html(dashboard_spa()).into_response();
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
            r#"<html><body><h1>Login failed</h1><p>{}</p></body></html>"#,
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

// ── Dashboard API proxy ─────────────────────────────────────────────────────

/// `GET/POST/PUT/DELETE /dashboard/api/*` — session-authenticated proxy to
/// uteke-server. CSRF required for mutations.
pub async fn dashboard_api(
    State(state): State<AppState>,
    Path(api_path): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // 1. Validate session cookie.
    let session_id = match extract_session(&headers, &state.config.jwt_secret) {
        Some(s) => s,
        None => return api_unauthorized("no session"),
    };
    let sess = match state.store.get_session(&session_id) {
        Some(s) => s,
        None => return api_unauthorized("session expired"),
    };

    // 2. CSRF check for mutations.
    let is_mutation = matches!(
        method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    );
    if is_mutation {
        let header_token = headers
            .get(CSRF_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if header_token.is_empty() || header_token != sess.csrf_token {
            return api_forbidden("CSRF token missing or mismatched");
        }
    }

    // 3. Proxy to uteke-server with static token + extra headers (no client JWT forwarded).
    let upstream_url = format!("{}/{}", state.config.upstream, api_path);
    let mut req_headers = headers.clone();
    req_headers.remove("authorization");
    req_headers.remove("host");
    req_headers.remove("cookie");
    req_headers.remove(CSRF_HEADER);
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
            if e.is_timeout() {
                return api_error(StatusCode::GATEWAY_TIMEOUT, "upstream timeout");
            }
            return api_error(StatusCode::BAD_GATEWAY, "upstream unavailable");
        }
    };

    let status =
        StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let ct = resp.headers().get("content-type").cloned();
    let body_bytes = resp.bytes().await.unwrap_or_default();
    let mut response = Response::new(Body::from(body_bytes));
    *response.status_mut() = status;
    // Pass through content-type.
    if let Some(ct) = ct {
        if let Ok(v) = HeaderValue::from_bytes(ct.as_bytes()) {
            response.headers_mut().insert("content-type", v);
        }
    }
    response
}

// ── SPA HTML ────────────────────────────────────────────────────────────────

fn dashboard_spa() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>uteke — Dashboard</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 0; background: #f8fafc; color: #1e293b; }
  header { background: #1e293b; color: #fff; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
  header h1 { font-size: 1.25rem; margin: 0; }
  main { max-width: 960px; margin: 2rem auto; padding: 0 1rem; }
  .card { background: #fff; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
  input, textarea, button { font-size: 1rem; }
  input, textarea { width: 100%; padding: 0.5rem; border: 1px solid #cbd5e1; border-radius: 4px; box-sizing: border-box; margin-bottom: 0.75rem; }
  button { padding: 0.5rem 1rem; background: #2563eb; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
  button:hover { background: #1d4ed8; }
  button.secondary { background: #64748b; }
  button.secondary:hover { background: #475569; }
  pre { background: #f1f5f9; padding: 1rem; border-radius: 4px; overflow-x: auto; font-size: 0.85rem; }
  .row { display: flex; gap: 0.75rem; }
  .row > * { flex: 1; }
  label { display: block; font-size: 0.8rem; color: #64748b; margin-bottom: 0.25rem; }
</style>
</head>
<body>
<header>
  <h1>uteke Dashboard</h1>
  <button class="secondary" onclick="logout()">Logout</button>
</header>
<main>
  <div class="card">
    <h2>Recall</h2>
    <label>Query</label>
    <input id="query" placeholder="Search memories..." onkeydown="if(event.key==='Enter')recall()">
    <button onclick="recall()">Search</button>
    <pre id="recall-results">Results will appear here.</pre>
  </div>
  <div class="card">
    <h2>Remember</h2>
    <label>Content</label>
    <textarea id="content" rows="3" placeholder="Memory content..."></textarea>
    <label>Tags (comma-separated)</label>
    <input id="tags" placeholder="tag1, tag2">
    <button onclick="remember()">Save</button>
    <pre id="remember-result"></pre>
  </div>
</main>
<script>
const CSRF = document.cookie.match(/csrf_token=([^;]+)/)?.[1] || '';
function getCSRF() { return document.cookie.match(/csrf_token=([^;]+)/)?.[1] || ''; }

async function recall() {
  const q = document.getElementById('query').value.trim();
  if (!q) return;
  const res = await fetch('/dashboard/api/recall', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ query: q, limit: 10 })
  });
  const data = await res.json();
  document.getElementById('recall-results').textContent = JSON.stringify(data, null, 2);
}

async function remember() {
  const content = document.getElementById('content').value.trim();
  if (!content) return;
  const tags = document.getElementById('tags').value.split(',').map(t=>t.trim()).filter(Boolean);
  const res = await fetch('/dashboard/api/remember', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCSRF()},
    body: JSON.stringify({ content, tags })
  });
  const data = await res.json();
  document.getElementById('remember-result').textContent = JSON.stringify(data, null, 2);
  document.getElementById('content').value = '';
}

async function logout() {
  await fetch('/dashboard/logout', { method: 'POST', headers: {'X-CSRF-Token': getCSRF()} });
  window.location.href = '/dashboard';
}
</script>
</body>
</html>"#.to_string()
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn extract_session(headers: &HeaderMap, secret: &str) -> Option<String> {
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

fn api_unauthorized(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "unauthorized", "detail": msg })),
    )
        .into_response()
}

fn api_forbidden(msg: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": "forbidden", "detail": msg })),
    )
        .into_response()
}

fn api_error(code: StatusCode, msg: &str) -> Response {
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
