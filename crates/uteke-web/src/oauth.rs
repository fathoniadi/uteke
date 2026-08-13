//! OAuth2 auth server handlers (M4a + M4b).
//!
//! Endpoints:
//! - `GET /oauth2/auth` — authorize, render login page
//! - `POST /oauth2/login` — submit credentials (rate-limited + lockout)
//! - `POST /oauth2/token` — grant authorization_code (PKCE) + refresh_token (rotation)
//! - `POST /oauth2/register` — RFC 7591 dynamic client registration
//! - `GET /.well-known/oauth-authorization-server` — RFC 8414 metadata
//! - `GET /.well-known/jwks-uri` — JWKS placeholder (HS256 → empty keys)
//! - `POST /oauth2/revoke` — RFC 7009
//! - `POST /oauth2/introspect` — RFC 7662
//! - `GET /profile` — userinfo (Bearer → non-secret identity)
//! - `GET /healthz` — health check (upstream connectivity)

use axum::Form;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Json, Redirect, Response};
use serde::{Deserialize, Serialize};

use crate::auth_store::{AuthError, AuthStore};
use crate::jwt;
use crate::pkce;
use crate::state::AppState;

// ── Constants ───────────────────────────────────────────────────────────────

/// Authorization code TTL in seconds.
const AUTH_CODE_TTL: i64 = 60;
/// Access token TTL in seconds (1 hour).
const ACCESS_TOKEN_TTL: i64 = 3600;
/// Refresh token TTL in seconds (30 days).
const REFRESH_TOKEN_TTL: i64 = 30 * 24 * 3600;
/// Rate limit: max failed logins per IP per minute.
const LOGIN_RATE_LIMIT: i64 = 5;
/// Rate limit window in seconds.
const LOGIN_RATE_WINDOW: i64 = 60;

// ── Query/body structs ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    // Hidden fields echoed back from the authorize page.
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub refresh_token: Option<String>,
    pub code_verifier: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterRequest {
    pub redirect_uris: Option<Vec<String>>,
    pub client_name: Option<String>,
    pub scope: Option<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub token_endpoint_auth_method: Option<String>,
    pub contacts: Option<Vec<String>>,
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub tos_uri: Option<String>,
    pub jwks_uri: Option<String>,
    pub software_id: Option<String>,
    pub software_version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub scope: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Extract client IP from `X-Forwarded-For`, but only if the request came
/// through a trusted reverse proxy (configured via `web.trusted_proxies`).
///
/// **Security:** Without `trusted_proxies` configured, XFF is **ignored** and
/// the IP falls back to `"unknown"`. This prevents spoofing.
///
/// TODO: use axum `ConnectInfo<SocketAddr>` to get the real peer IP and
/// check it against `trusted_proxies` before trusting XFF.
fn client_ip(headers: &HeaderMap, trusted_proxies: &[String]) -> String {
    if !trusted_proxies.is_empty() {
        if let Some(xff) = headers.get("x-forwarded-for") {
            if let Ok(s) = xff.to_str() {
                return s.split(',').next().unwrap_or("unknown").trim().to_string();
            }
        }
    }
    "unknown".to_string()
}

/// Parse Basic auth header → (client_id, client_secret).
fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let header = headers.get("authorization")?.to_str().ok()?;
    let rest = header.strip_prefix("Basic ")?;
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(rest)
        .ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (id, secret) = s.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

/// Resolve the client for a token request: from Basic auth or body fields.
fn resolve_client(
    state: &AppState,
    body: &TokenRequest,
    headers: &HeaderMap,
) -> Option<crate::auth_store::Client> {
    if let Some((id, secret)) = parse_basic_auth(headers) {
        let client = state.store.get_client_by_id(&id)?;
        if !client.public && !AuthStore::verify_client_secret(&client, &secret) {
            return None;
        }
        return Some(client);
    }
    let id = body.client_id.as_ref()?;
    let client = state.store.get_client_by_id(id)?;
    if !client.public {
        if let Some(secret) = &body.client_secret {
            if !AuthStore::verify_client_secret(&client, secret) {
                return None;
            }
        } else {
            return None;
        }
    }
    Some(client)
}

/// Check if a redirect_uri is allowed for a client.
fn redirect_uri_allowed(client: &crate::auth_store::Client, uri: &str) -> bool {
    client.redirect_uris.iter().any(|allowed| allowed == uri)
}

// ── Handlers: Authorize + Login (M4a) ───────────────────────────────────────

/// `GET /oauth2/auth` — render the login page with authorize params as hidden fields.
pub async fn authorize(
    State(state): State<AppState>,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    if params.response_type != "code" {
        return error_page("unsupported response_type (only 'code' is supported)");
    }
    let client = match state.store.get_client_by_id(&params.client_id) {
        Some(c) => c,
        None => return error_page("unknown client_id"),
    };
    if !redirect_uri_allowed(&client, &params.redirect_uri) {
        return error_page("redirect_uri not registered for this client");
    }
    if params.code_challenge.is_none() {
        return error_page("PKCE code_challenge is required");
    }
    let method = params.code_challenge_method.as_deref().unwrap_or("S256");
    if method != "S256" {
        return error_page("only S256 code_challenge_method is supported");
    }
    let scope = params.scope.clone().unwrap_or_default();
    let state_param = params.state.clone().unwrap_or_default();
    let nonce = params.nonce.clone().unwrap_or_default();
    let html = login_page(
        &params.client_id,
        &params.redirect_uri,
        &scope,
        &state_param,
        params.code_challenge.as_deref().unwrap_or(""),
        method,
        &nonce,
    );
    Html(html).into_response()
}

/// `POST /oauth2/login` — validate credentials, issue auth code, redirect.
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let ip = client_ip(&headers, &state.config.trusted_proxies);

    // Rate limit: 5 failures per minute per IP.
    match state.store.count_recent_failures(&ip, LOGIN_RATE_WINDOW) {
        Ok(count) if count >= LOGIN_RATE_LIMIT => {
            state.audit.log(
                "login_rate_limited",
                Some(&form.username),
                Some(&form.client_id),
                Some(&ip),
                "too many failed attempts from this IP",
            );
            return error_page("too many login attempts from this IP, try again in a minute");
        }
        _ => {}
    }

    // Verify credentials — bcrypt is CPU-intensive (~100ms at cost 12),
    // so offload to a blocking thread to avoid stalling the async runtime.
    let store = state.store.clone();
    let username = form.username.clone();
    let password = form.password.clone();
    let verify_result =
        match tokio::task::spawn_blocking(move || store.verify_user(&username, &password)).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("verify_user task join error: {e}");
                crate::metrics::inc_login_failure();
                return error_page("internal error, please retry").into_response();
            }
        };
    match verify_result {
        Ok(user) => {
            crate::metrics::inc_login_success();
            let _ = state
                .store
                .record_login_attempt(&ip, Some(&form.username), true);
            state.audit.log(
                "login_success",
                Some(&form.username),
                Some(&form.client_id),
                Some(&ip),
                "credentials verified",
            );
            // Issue authorization code.
            let code = crate::auth_store::random_token(32);
            let scope = if form.scope.is_empty() {
                "read write"
            } else {
                &form.scope
            };
            if let Err(e) = state.store.add_auth_code(
                &code,
                &form.client_id,
                &user.username,
                &form.redirect_uri,
                scope,
                &form.code_challenge,
                &form.code_challenge_method,
                AUTH_CODE_TTL,
            ) {
                tracing::error!("failed to store auth code: {e}");
                return error_page("internal error, please retry");
            }
            // Redirect to client with code + state.
            let sep = if form.redirect_uri.contains('?') {
                '&'
            } else {
                '?'
            };
            let redirect = format!(
                "{redirect_uri}{sep}code={code}&state={state}",
                redirect_uri = form.redirect_uri,
                code = urlencoding::encode(&code),
                state = urlencoding::encode(&form.state),
            );
            Redirect::to(&redirect).into_response()
        }
        Err(AuthError::Locked) => {
            crate::metrics::inc_login_failure();
            let _ = state
                .store
                .record_login_attempt(&ip, Some(&form.username), false);
            state.audit.log(
                "login_locked",
                Some(&form.username),
                Some(&form.client_id),
                Some(&ip),
                "account locked",
            );
            error_page("account is locked, contact an administrator").into_response()
        }
        Err(e) => {
            crate::metrics::inc_login_failure();
            let _ = state
                .store
                .record_login_attempt(&ip, Some(&form.username), false);
            state.audit.log(
                "login_failure",
                Some(&form.username),
                Some(&form.client_id),
                Some(&ip),
                format!("{e}"),
            );
            // Re-render login page with error.
            let html = login_page_with_error(
                &form.client_id,
                &form.redirect_uri,
                &form.scope,
                &form.state,
                &form.code_challenge,
                &form.code_challenge_method,
                &form.nonce,
                "invalid username or password",
            );
            (StatusCode::UNAUTHORIZED, Html(html)).into_response()
        }
    }
}

// ── Handlers: Token (M4b) ───────────────────────────────────────────────────

/// `POST /oauth2/token` — issue access tokens (authorization_code + refresh_token).
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<TokenRequest>,
) -> Response {
    match body.grant_type.as_str() {
        "authorization_code" => handle_code_grant(&state, &body, &headers).await,
        "refresh_token" => handle_refresh_grant(&state, &body, &headers).await,
        other => Json(ErrorResponse {
            error: "unsupported_grant_type".to_string(),
            error_description: Some(format!("grant_type '{other}' not supported")),
        })
        .with_status(StatusCode::BAD_REQUEST)
        .into_response(),
    }
}

async fn handle_code_grant(state: &AppState, body: &TokenRequest, headers: &HeaderMap) -> Response {
    let code = match &body.code {
        Some(c) => c,
        None => return token_error("invalid_request", "code is required"),
    };
    let redirect_uri = match &body.redirect_uri {
        Some(r) => r,
        None => return token_error("invalid_request", "redirect_uri is required"),
    };
    let verifier = match &body.code_verifier {
        Some(v) => v,
        None => return token_error("invalid_request", "code_verifier is required (PKCE)"),
    };
    let client = match resolve_client(state, body, headers) {
        Some(c) => c,
        None => return token_error("invalid_client", "client authentication failed"),
    };
    let auth_code = match state.store.consume_auth_code(code) {
        Ok(c) => c,
        Err(AuthError::Invalid(msg)) => return token_error("invalid_grant", &msg),
        Err(e) => {
            tracing::error!("auth code consume error: {e}");
            return token_error("invalid_grant", "authorization code invalid");
        }
    };
    if auth_code.client_id != client.client_id {
        return token_error("invalid_grant", "code was issued to a different client");
    }
    if auth_code.redirect_uri != *redirect_uri {
        return token_error("invalid_grant", "redirect_uri mismatch");
    }
    if !pkce::verify_pkce(
        verifier,
        &auth_code.code_challenge,
        &auth_code.code_challenge_method,
    ) {
        return token_error("invalid_grant", "PKCE verification failed");
    }
    // Mint access token.
    let (access_token, jti) = match jwt::mint_access_token(
        &state.config.jwt_secret,
        &state.config.issuer,
        &auth_code.username,
        &client.client_id,
        &auth_code.scope,
        ACCESS_TOKEN_TTL,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("jwt mint error: {e}");
            return token_error("server_error", "failed to mint access token");
        }
    };
    // Mint refresh token.
    let refresh = crate::auth_store::random_token(48);
    if let Err(e) = state.store.add_refresh_token(
        &refresh,
        &client.client_id,
        &auth_code.username,
        &auth_code.scope,
        REFRESH_TOKEN_TTL,
    ) {
        tracing::error!("refresh token store error: {e}");
        return token_error("server_error", "failed to store refresh token");
    }
    state.audit.log(
        "token_issued",
        Some(&auth_code.username),
        Some(&client.client_id),
        None,
        format!("jti={jti} scope={}", auth_code.scope),
    );
    crate::metrics::inc_tokens_issued();
    Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: ACCESS_TOKEN_TTL,
        refresh_token: Some(refresh),
        scope: auth_code.scope,
    })
    .into_response()
}

async fn handle_refresh_grant(
    state: &AppState,
    body: &TokenRequest,
    headers: &HeaderMap,
) -> Response {
    let refresh = match &body.refresh_token {
        Some(r) => r,
        None => return token_error("invalid_request", "refresh_token is required"),
    };
    let client = match resolve_client(state, body, headers) {
        Some(c) => c,
        None => return token_error("invalid_client", "client authentication failed"),
    };
    let new_refresh = crate::auth_store::random_token(48);
    let old = match state.store.consume_refresh_token(refresh, &new_refresh) {
        Ok(t) => t,
        Err(AuthError::Invalid(msg)) => return token_error("invalid_grant", &msg),
        Err(e) => {
            tracing::error!("refresh consume error: {e}");
            return token_error("invalid_grant", "refresh token invalid");
        }
    };
    if old.client_id != client.client_id {
        return token_error(
            "invalid_grant",
            "refresh token belongs to a different client",
        );
    }
    let scope = body.scope.as_deref().unwrap_or(&old.scope).to_string();
    let (access_token, jti) = match jwt::mint_access_token(
        &state.config.jwt_secret,
        &state.config.issuer,
        &old.username,
        &client.client_id,
        &scope,
        ACCESS_TOKEN_TTL,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("jwt mint error: {e}");
            return token_error("server_error", "failed to mint access token");
        }
    };
    if let Err(e) = state.store.add_refresh_token(
        &new_refresh,
        &client.client_id,
        &old.username,
        &scope,
        REFRESH_TOKEN_TTL,
    ) {
        tracing::error!("new refresh token store error: {e}");
        return token_error("server_error", "failed to store refresh token");
    }
    state.audit.log(
        "token_refreshed",
        Some(&old.username),
        Some(&client.client_id),
        None,
        format!("jti={jti}"),
    );
    crate::metrics::inc_tokens_refreshed();
    Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: ACCESS_TOKEN_TTL,
        refresh_token: Some(new_refresh),
        scope,
    })
    .into_response()
}

// ── Handlers: Register (RFC 7591) ───────────────────────────────────────────

/// `POST /oauth2/register` — dynamic client registration.
pub async fn register(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> Response {
    let redirect_uris = body.redirect_uris.unwrap_or_default();
    if redirect_uris.is_empty() {
        return Json(ErrorResponse {
            error: "invalid_client_metadata".to_string(),
            error_description: Some("redirect_uris is required".to_string()),
        })
        .with_status(StatusCode::BAD_REQUEST)
        .into_response();
    }
    let client_id = uuid::Uuid::new_v4().to_string();
    let client_secret = crate::auth_store::random_token(48);
    let scope_str = body
        .scope
        .clone()
        .unwrap_or_else(|| "read write".to_string());
    let scopes = scope_str
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let client = match state.store.add_client(
        &client_id,
        &client_secret,
        redirect_uris,
        scopes,
        false,
        true,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("register error: {e}");
            return Json(ErrorResponse {
                error: "server_error".to_string(),
                error_description: Some(e.to_string()),
            })
            .with_status(StatusCode::INTERNAL_SERVER_ERROR)
            .into_response();
        }
    };
    state.audit.log(
        "client_registered",
        None,
        Some(&client.client_id),
        None,
        "dynamic registration",
    );
    Json(serde_json::json!({
        "client_id": client.client_id,
        "client_secret": client_secret,
        "client_id_issued_at": client.created_at,
        "client_secret_expires_at": 0,
        "redirect_uris": client.redirect_uris,
        "grant_types": client.grants,
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
        "scope": scope_str,
    }))
    .into_response()
}

// ── Handlers: Metadata (RFC 8414) + JWKS ────────────────────────────────────

/// `GET /.well-known/oauth-authorization-server` — RFC 8414 metadata.
pub async fn metadata(State(state): State<AppState>) -> Json<serde_json::Value> {
    let issuer = &state.config.issuer;
    Json(serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth2/auth"),
        "token_endpoint": format!("{issuer}/oauth2/token"),
        "registration_endpoint": format!("{issuer}/oauth2/register"),
        "revocation_endpoint": format!("{issuer}/oauth2/revoke"),
        "introspection_endpoint": format!("{issuer}/oauth2/introspect"),
        "userinfo_endpoint": format!("{issuer}/profile"),
        "jwks_uri": format!("{issuer}/.well-known/jwks-uri"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "scopes_supported": ["read", "write", "admin"],
    }))
}

/// `GET /.well-known/jwks-uri` — JWKS placeholder. HS256 returns empty keys set
/// (migration path to RS256 documented in PLAN.md §5).
pub async fn jwks() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "keys": [] }))
}

// ── Handlers: Profile ───────────────────────────────────────────────────────

/// `GET /profile` — verify Bearer JWT, return non-secret identity.
pub async fn profile(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let token = match extract_bearer(&headers) {
        Some(t) => t,
        None => return unauthorized("missing_bearer", "Authorization: Bearer <token> required"),
    };
    let claims =
        match jwt::verify_access_token(&state.config.jwt_secret, &state.config.issuer, &token) {
            Ok(c) => c,
            Err(_) => return unauthorized("invalid_token", "token invalid or expired"),
        };
    Json(serde_json::json!({
        "username": claims.sub,
        "client_id": claims.client_id,
        "scope": claims.scope,
        "iss": claims.iss,
        "exp": claims.exp,
    }))
    .into_response()
}

// ── Handlers: Revoke (RFC 7009) + Introspect (RFC 7662) ─────────────────────

/// `POST /oauth2/revoke` — revoke a refresh token (RFC 7009).
///
/// Requires client authentication (Basic or body) per RFC 7009 §2.1.
pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<RevokeRequest>,
) -> Response {
    // Authenticate the client.
    let client = match resolve_client_from_revoke(&state, &body, &headers) {
        Some(c) => c,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Basic realm=\"oauth2\"")],
                Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: Some("client authentication required".to_string()),
                }),
            )
                .into_response();
        }
    };
    if let Some(token) = &body.token {
        let _ = state.store.revoke_refresh_token(token);
        state.audit.log(
            "token_revoked",
            None,
            Some(&client.client_id),
            None,
            "refresh token revoked",
        );
    }
    // RFC 7009: always return 200, even if token was already invalid.
    StatusCode::OK.into_response()
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: Option<String>,
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// Resolve client from RevokeRequest (Basic auth or body fields).
/// Same logic as `resolve_client` but for the RevokeRequest shape.
fn resolve_client_from_revoke(
    state: &AppState,
    body: &RevokeRequest,
    headers: &HeaderMap,
) -> Option<crate::auth_store::Client> {
    if let Some((id, secret)) = parse_basic_auth(headers) {
        let client = state.store.get_client_by_id(&id)?;
        if !client.public && !AuthStore::verify_client_secret(&client, &secret) {
            return None;
        }
        return Some(client);
    }
    let id = body.client_id.as_ref()?;
    let client = state.store.get_client_by_id(id)?;
    if !client.public {
        if let Some(secret) = &body.client_secret {
            if !AuthStore::verify_client_secret(&client, secret) {
                return None;
            }
        } else {
            return None;
        }
    }
    Some(client)
}

/// `POST /oauth2/introspect` — introspect a token (RFC 7662).
///
/// Requires client authentication per RFC 7662 §2.1.
pub async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<RevokeRequest>,
) -> Response {
    // Authenticate the client.
    let client = match resolve_client_from_revoke(&state, &body, &headers) {
        Some(c) => c,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Basic realm=\"oauth2\"")],
                Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: Some("client authentication required".to_string()),
                }),
            )
                .into_response();
        }
    };
    let token = match &body.token {
        Some(t) => t,
        None => {
            return Json(serde_json::json!({ "active": false })).into_response();
        }
    };
    // Try as JWT access token first.
    if let Ok(claims) =
        jwt::verify_access_token(&state.config.jwt_secret, &state.config.issuer, token)
    {
        return Json(serde_json::json!({
            "active": true,
            "scope": claims.scope,
            "client_id": claims.client_id,
            "username": claims.sub,
            "token_type": "Bearer",
            "exp": claims.exp,
            "iss": claims.iss,
        }))
        .into_response();
    }
    // Fall back: not active (refresh tokens are opaque; we don't introspect them
    // without a lookup that would leak validity — return inactive per RFC 7662).
    let _ = client; // client authenticated; result is inactive regardless.
    Json(serde_json::json!({ "active": false })).into_response()
}

// ── Handlers: Health ────────────────────────────────────────────────────────

/// `GET /healthz` — check upstream uteke-server connectivity.
pub async fn healthz(State(state): State<AppState>) -> Response {
    let upstream_health = format!("{}/health", state.config.upstream);
    match state.http_client.get(&upstream_health).send().await {
        Ok(resp) => {
            let status_code = resp.status();
            if status_code.is_success() {
                Json(serde_json::json!({
                    "status": "ok",
                    "upstream": state.config.upstream,
                }))
                .into_response()
            } else {
                Json(serde_json::json!({
                    "status": "degraded",
                    "upstream": state.config.upstream,
                    "upstream_status": status_code.as_u16(),
                }))
                .with_status(StatusCode::SERVICE_UNAVAILABLE)
                .into_response()
            }
        }
        Err(e) => Json(serde_json::json!({
            "status": "degraded",
            "upstream": state.config.upstream,
            "error": e.to_string(),
        }))
        .with_status(StatusCode::SERVICE_UNAVAILABLE)
        .into_response(),
    }
}

// ── HTML pages ──────────────────────────────────────────────────────────────

fn login_page(
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    state: &str,
    code_challenge: &str,
    code_challenge_method: &str,
    nonce: &str,
) -> String {
    login_page_inner(
        client_id,
        redirect_uri,
        scope,
        state,
        code_challenge,
        code_challenge_method,
        nonce,
        "",
    )
}

#[allow(clippy::too_many_arguments)]
fn login_page_with_error(
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    state: &str,
    code_challenge: &str,
    code_challenge_method: &str,
    nonce: &str,
    error: &str,
) -> String {
    login_page_inner(
        client_id,
        redirect_uri,
        scope,
        state,
        code_challenge,
        code_challenge_method,
        nonce,
        error,
    )
}

#[allow(clippy::too_many_arguments)]
fn login_page_inner(
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    state: &str,
    code_challenge: &str,
    code_challenge_method: &str,
    nonce: &str,
    error: &str,
) -> String {
    let error_html = if error.is_empty() {
        String::new()
    } else {
        format!(r#"<p class="error">{}</p>"#, html_escape(error))
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>uteke-web — Login</title>
<style>
  body {{ font-family: system-ui, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
  .card {{ background: #fff; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); width: 100%; max-width: 360px; }}
  h1 {{ font-size: 1.25rem; margin: 0 0 1.5rem; }}
  label {{ display: block; margin-bottom: 0.25rem; font-size: 0.875rem; color: #555; }}
  input {{ width: 100%; padding: 0.5rem; margin-bottom: 1rem; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }}
  button {{ width: 100%; padding: 0.6rem; background: #2563eb; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }}
  button:hover {{ background: #1d4ed8; }}
  .error {{ color: #dc2626; margin-bottom: 1rem; font-size: 0.875rem; }}
</style>
</head>
<body>
<div class="card">
  <h1>Sign in to uteke</h1>
  {error_html}
  <form method="POST" action="/oauth2/login">
    <input type="hidden" name="client_id" value="{client_id}">
    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
    <input type="hidden" name="scope" value="{scope}">
    <input type="hidden" name="state" value="{state}">
    <input type="hidden" name="code_challenge" value="{code_challenge}">
    <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
    <input type="hidden" name="nonce" value="{nonce}">
    <label for="username">Username</label>
    <input id="username" name="username" type="text" required autofocus>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" required>
    <button type="submit">Sign in</button>
  </form>
</div>
</body>
</html>"#,
        client_id = html_escape(client_id),
        redirect_uri = html_escape(redirect_uri),
        scope = html_escape(scope),
        state = html_escape(state),
        code_challenge = html_escape(code_challenge),
        code_challenge_method = html_escape(code_challenge_method),
        nonce = html_escape(nonce),
    )
}

fn error_page(msg: &str) -> Response {
    let body = format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Error</title></head>
<body><h1>Authentication Error</h1><p>{}</p></body></html>"#,
        html_escape(msg)
    );
    (StatusCode::BAD_REQUEST, Html(body)).into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

// ── Response helpers ────────────────────────────────────────────────────────

fn token_error(error: &str, description: &str) -> Response {
    Json(ErrorResponse {
        error: error.to_string(),
        error_description: Some(description.to_string()),
    })
    .with_status(StatusCode::BAD_REQUEST)
    .into_response()
}

fn unauthorized(error: &str, description: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            "WWW-Authenticate",
            format!("Bearer error=\"{error}\", error_description=\"{description}\""),
        )],
        Json(ErrorResponse {
            error: error.to_string(),
            error_description: Some(description.to_string()),
        }),
    )
        .into_response()
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let h = headers.get("authorization")?.to_str().ok()?;
    let token = h.strip_prefix("Bearer ")?;
    Some(token.trim().to_string())
}

/// Trait extension to set status on a Json response.
trait WithStatus {
    fn with_status(self, code: StatusCode) -> Response;
}

impl<T: serde::Serialize> WithStatus for Json<T> {
    fn with_status(self, code: StatusCode) -> Response {
        (code, self).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_escapes_special_chars() {
        assert_eq!(
            html_escape("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&#x27;f"
        );
    }

    #[test]
    fn parse_basic_auth_works() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("myclient:mysecret");
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Basic {encoded}").parse().unwrap());
        let (id, secret) = parse_basic_auth(&headers).expect("parse");
        assert_eq!(id, "myclient");
        assert_eq!(secret, "mysecret");
    }

    #[test]
    fn extract_bearer_works() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer abc123".parse().unwrap());
        assert_eq!(extract_bearer(&headers).as_deref(), Some("abc123"));
    }
}
