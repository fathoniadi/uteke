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
///
/// Per RFC 8252 §7.3, loopback redirects (http://localhost or
/// http://127.0.0.1) may use any port — the port is ignored when matching.
/// Non-loopback URIs must match exactly.
fn redirect_uri_allowed(client: &crate::auth_store::Client, uri: &str) -> bool {
    client.redirect_uris.iter().any(|allowed| {
        if allowed == uri {
            return true;
        }
        // Loopback exception: ignore port for localhost/127.0.0.1.
        if let (Some(a), Some(u)) = (parse_uri_parts(allowed), parse_uri_parts(uri)) {
            if a.scheme == u.scheme
                && a.host == u.host
                && a.path == u.path
                && is_loopback(&a.host)
                && a.scheme == "http"
            {
                return true;
            }
        }
        false
    })
}

/// Parsed URI components (scheme, host, port, path) for redirect_uri matching.
struct UriParts {
    scheme: String,
    host: String,
    #[allow(dead_code)]
    port: Option<String>,
    path: String,
}

/// Parse a URI into scheme, host, port, path.
fn parse_uri_parts(uri: &str) -> Option<UriParts> {
    let (scheme, rest) = uri.split_once("://")?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = authority
        .rsplit_once(':')
        .map(|(h, p)| (h.to_string(), Some(p.to_string())))
        .unwrap_or((authority.to_string(), None));
    Some(UriParts {
        scheme: scheme.to_string(),
        host,
        port,
        path: format!("/{path}"),
    })
}

/// True if host is a loopback address (localhost or 127.0.0.1).
fn is_loopback(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1"
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

/// `POST /oauth2/register` — dynamic client registration (RFC 7591).
///
/// Returns **201 Created** with the registered client metadata.
/// Supports `token_endpoint_auth_method` = "none" (public client, PKCE-only).
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

    // Determine auth method: "none" = public client (PKCE-only), else confidential.
    let auth_method = body
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("client_secret_post");
    let is_public = auth_method == "none";

    let client_id = uuid::Uuid::new_v4().to_string();
    let client_secret = if is_public {
        String::new()
    } else {
        crate::auth_store::random_token(48)
    };

    // Default scope: "mcp offline_access" — matches what MCP clients
    // (Claude, etc.) expect. offline_access enables refresh tokens.
    let scope_str = body
        .scope
        .clone()
        .unwrap_or_else(|| "mcp offline_access".to_string());
    let scopes = scope_str
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    let client = match state.store.add_client(
        &client_id,
        &client_secret,
        redirect_uris,
        scopes,
        is_public,
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
        format!("dynamic registration, public={is_public}"),
    );

    // RFC 7591 §3.2.1: client_id_issued_at = epoch seconds (int).
    let issued_at = chrono::Utc::now().timestamp();

    let mut resp = serde_json::json!({
        "client_id": client.client_id,
        "client_id_issued_at": issued_at,
        "client_secret_expires_at": 0,
        "redirect_uris": client.redirect_uris,
        "grant_types": client.grants,
        "response_types": ["code"],
        "token_endpoint_auth_method": auth_method,
        "scope": scope_str,
    });
    // Only include client_secret for confidential clients.
    if !is_public {
        resp["client_secret"] = serde_json::Value::String(client_secret);
    }

    (StatusCode::CREATED, Json(resp)).into_response()
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
        format!(
            r#"<div class="alert alert-danger" role="alert"><i class="bi bi-exclamation-triangle"></i> {}</div>"#,
            html_escape(error)
        )
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>uteke — Login</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
<style>
  /* Flat design theme variables (synced with dashboard.html) */
  [data-theme="indigo"] {{ --u-accent:#6366f1; --u-accent-text:#fff; --u-accent-subtle:#e0e7ff; --u-bg:#fff; --u-surface:#f8fafc; --u-surface-hover:#f1f5f9; --u-border:#e2e8f0; --u-border-strong:#cbd5e1; --u-text:#1e293b; --u-text-muted:#64748b; --u-sidebar-bg:#1e1b4b; --u-success:#16a34a; --u-warning:#d97706; --u-danger:#dc2626; --u-info:#0ea5e9; }}
  [data-theme="indigo"][data-mode="dark"] {{ --u-accent:#818cf8; --u-accent-text:#0f172a; --u-accent-subtle:#312e81; --u-bg:#0f172a; --u-surface:#1e293b; --u-surface-hover:#334155; --u-border:#334155; --u-border-strong:#475569; --u-text:#e2e8f0; --u-text-muted:#94a3b8; --u-sidebar-bg:#0c0a1f; --u-success:#4ade80; --u-warning:#fbbf24; --u-danger:#f87171; --u-info:#38bdf8; }}
  [data-theme="slate"] {{ --u-accent:#0d9488; --u-accent-text:#fff; --u-accent-subtle:#ccfbf1; --u-bg:#fff; --u-surface:#f1f5f9; --u-surface-hover:#e2e8f0; --u-border:#e2e8f0; --u-border-strong:#cbd5e1; --u-text:#1e293b; --u-text-muted:#64748b; --u-sidebar-bg:#1e293b; --u-success:#16a34a; --u-warning:#d97706; --u-danger:#dc2626; --u-info:#0ea5e9; }}
  [data-theme="slate"][data-mode="dark"] {{ --u-accent:#2dd4bf; --u-accent-text:#0f172a; --u-accent-subtle:#134e4a; --u-bg:#0f172a; --u-surface:#1e293b; --u-surface-hover:#334155; --u-border:#334155; --u-border-strong:#475569; --u-text:#e2e8f0; --u-text-muted:#94a3b8; --u-sidebar-bg:#020617; --u-success:#4ade80; --u-warning:#fbbf24; --u-danger:#f87171; --u-info:#38bdf8; }}
  [data-theme="warm"] {{ --u-accent:#d97706; --u-accent-text:#fff; --u-accent-subtle:#fef3c7; --u-bg:#fffbeb; --u-surface:#fef3c7; --u-surface-hover:#fde68a; --u-border:#e7e5e4; --u-border-strong:#d6d3d1; --u-text:#292524; --u-text-muted:#78716c; --u-sidebar-bg:#451a03; --u-success:#16a34a; --u-warning:#ca8a04; --u-danger:#dc2626; --u-info:#0ea5e9; }}
  [data-theme="warm"][data-mode="dark"] {{ --u-accent:#fbbf24; --u-accent-text:#1c1917; --u-accent-subtle:#422006; --u-bg:#1c1917; --u-surface:#292524; --u-surface-hover:#44403c; --u-border:#44403c; --u-border-strong:#57534e; --u-text:#e7e5e4; --u-text-muted:#a8a29e; --u-sidebar-bg:#0c0a09; --u-success:#4ade80; --u-warning:#fbbf24; --u-danger:#f87171; --u-info:#38bdf8; }}
  [data-theme="mono"] {{ --u-accent:#171717; --u-accent-text:#fff; --u-accent-subtle:#e5e5e5; --u-bg:#fff; --u-surface:#f5f5f5; --u-surface-hover:#e5e5e5; --u-border:#e5e5e5; --u-border-strong:#d4d4d4; --u-text:#171717; --u-text-muted:#737373; --u-sidebar-bg:#171717; --u-success:#16a34a; --u-warning:#d97706; --u-danger:#dc2626; --u-info:#0ea5e9; }}
  [data-theme="mono"][data-mode="dark"] {{ --u-accent:#fafafa; --u-accent-text:#0a0a0a; --u-accent-subtle:#262626; --u-bg:#0a0a0a; --u-surface:#171717; --u-surface-hover:#262626; --u-border:#262626; --u-border-strong:#404040; --u-text:#fafafa; --u-text-muted:#a3a3a3; --u-sidebar-bg:#000; --u-success:#4ade80; --u-warning:#fbbf24; --u-danger:#f87171; --u-info:#38bdf8; }}
  :root {{ --bs-primary: var(--u-accent); --bs-body-bg: var(--u-bg); --bs-body-color: var(--u-text); --bs-border-color: var(--u-border); --bs-border-radius: 4px; --bs-link-color: var(--u-accent); }}
  * {{ box-shadow: none !important; }}
  body {{ background: var(--u-bg); color: var(--u-text); }}
  .login-card {{ max-width: 380px; }}
  .card {{ background: var(--u-surface); border: 1px solid var(--u-border); border-radius: 4px; }}
  .card-body {{ background: var(--u-bg); }}
  .text-primary {{ color: var(--u-accent) !important; }}
  .form-control {{ background: var(--u-bg); border: 1px solid var(--u-border-strong); border-radius: 4px; color: var(--u-text); }}
  .form-control:focus {{ border-color: var(--u-accent); box-shadow: 0 0 0 1px var(--u-accent) !important; }}
  .form-label {{ color: var(--u-text-muted); font-weight: 500; font-size: 0.8rem; }}
  .input-group-text {{ background: var(--u-surface); border-color: var(--u-border-strong); color: var(--u-text-muted); }}
  .btn-primary {{ --bs-btn-bg: var(--u-accent); --bs-btn-border-color: var(--u-accent); --bs-btn-hover-bg: var(--u-accent); --bs-btn-hover-border-color: var(--u-accent); --bs-btn-color: var(--u-accent-text); --bs-btn-hover-color: var(--u-accent-text); border-radius: 4px; }}
  .alert-danger {{ background: var(--u-danger); border: none; border-radius: 4px; color: #fff; }}
</style>
<script>
  (function() {{
    try {{
      var t = localStorage.getItem("uteke_theme") || "indigo";
      var m = localStorage.getItem("uteke_mode") || "light";
      document.documentElement.setAttribute("data-theme", t);
      document.documentElement.setAttribute("data-mode", m);
    }} catch(e) {{
      document.documentElement.setAttribute("data-theme", "indigo");
      document.documentElement.setAttribute("data-mode", "light");
    }}
  }})();
</script>
</head>
<body class="d-flex align-items-center justify-content-center min-vh-100">
<div class="card login-card">
  <div class="card-body p-4">
    <div class="text-center mb-3">
      <i class="bi bi-shield-lock fs-1 text-primary"></i>
      <h1 class="h4 mb-0 mt-2">Sign in to uteke</h1>
    </div>
    {error_html}
    <form method="POST" action="/oauth2/login">
    <input type="hidden" name="client_id" value="{client_id}">
    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
    <input type="hidden" name="scope" value="{scope}">
    <input type="hidden" name="state" value="{state}">
    <input type="hidden" name="code_challenge" value="{code_challenge}">
    <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
    <input type="hidden" name="nonce" value="{nonce}">
    <div class="mb-3">
      <label for="username" class="form-label">Username</label>
      <div class="input-group">
        <span class="input-group-text"><i class="bi bi-person"></i></span>
        <input id="username" name="username" type="text" class="form-control" required autofocus>
      </div>
    </div>
    <div class="mb-3">
      <label for="password" class="form-label">Password</label>
      <div class="input-group">
        <span class="input-group-text"><i class="bi bi-key"></i></span>
        <input id="password" name="password" type="password" class="form-control" required>
      </div>
    </div>
    <button type="submit" class="btn btn-primary w-100"><i class="bi bi-box-arrow-in-right"></i> Sign in</button>
  </form>
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
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
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>uteke — Error</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
<style>
  [data-theme="indigo"] {{ --u-accent:#6366f1; --u-bg:#fff; --u-surface:#f8fafc; --u-border:#e2e8f0; --u-text:#1e293b; --u-text-muted:#64748b; --u-danger:#dc2626; }}
  [data-theme="indigo"][data-mode="dark"] {{ --u-accent:#818cf8; --u-bg:#0f172a; --u-surface:#1e293b; --u-border:#334155; --u-text:#e2e8f0; --u-text-muted:#94a3b8; --u-danger:#f87171; }}
  [data-theme="slate"] {{ --u-accent:#0d9488; --u-bg:#fff; --u-surface:#f1f5f9; --u-border:#e2e8f0; --u-text:#1e293b; --u-text-muted:#64748b; --u-danger:#dc2626; }}
  [data-theme="slate"][data-mode="dark"] {{ --u-accent:#2dd4bf; --u-bg:#0f172a; --u-surface:#1e293b; --u-border:#334155; --u-text:#e2e8f0; --u-text-muted:#94a3b8; --u-danger:#f87171; }}
  [data-theme="warm"] {{ --u-accent:#d97706; --u-bg:#fffbeb; --u-surface:#fef3c7; --u-border:#e7e5e4; --u-text:#292524; --u-text-muted:#78716c; --u-danger:#dc2626; }}
  [data-theme="warm"][data-mode="dark"] {{ --u-accent:#fbbf24; --u-bg:#1c1917; --u-surface:#292524; --u-border:#44403c; --u-text:#e7e5e4; --u-text-muted:#a8a29e; --u-danger:#f87171; }}
  [data-theme="mono"] {{ --u-accent:#171717; --u-bg:#fff; --u-surface:#f5f5f5; --u-border:#e5e5e5; --u-text:#171717; --u-text-muted:#737373; --u-danger:#dc2626; }}
  [data-theme="mono"][data-mode="dark"] {{ --u-accent:#fafafa; --u-bg:#0a0a0a; --u-surface:#171717; --u-border:#262626; --u-text:#fafafa; --u-text-muted:#a3a3a3; --u-danger:#f87171; }}
  * {{ box-shadow: none !important; }}
  body {{ background: var(--u-bg); color: var(--u-text); }}
  .card {{ background: var(--u-surface); border: 1px solid var(--u-border); border-radius: 4px; }}
  .card-body {{ background: var(--u-bg); }}
  .text-danger {{ color: var(--u-danger) !important; }}
  .text-muted {{ color: var(--u-text-muted) !important; }}
  .bg-light {{ background: var(--u-bg) !important; }}
</style>
<script>
  (function() {{
    try {{
      var t = localStorage.getItem("uteke_theme") || "indigo";
      var m = localStorage.getItem("uteke_mode") || "light";
      document.documentElement.setAttribute("data-theme", t);
      document.documentElement.setAttribute("data-mode", m);
    }} catch(e) {{
      document.documentElement.setAttribute("data-theme", "indigo");
      document.documentElement.setAttribute("data-mode", "light");
    }}
  }})();
</script>
</head>
<body class="d-flex align-items-center justify-content-center min-vh-100">
<div class="card" style="max-width:420px;">
  <div class="card-body p-4 text-center">
    <i class="bi bi-exclamation-octagon fs-1 text-danger"></i>
    <h1 class="h4 mt-2">Authentication Error</h1>
    <p class="text-muted">{}</p>
  </div>
</div>
</body>
</html>"#,
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
