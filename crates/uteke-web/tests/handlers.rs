//! Integration tests for uteke-web HTTP handlers.
//!
//! Uses `tower::ServiceExt::oneshot` to drive the axum router without binding
//! a real TCP listener. A mock upstream (via `wiremock`-free approach using
//! `axum::serve` on an ephemeral port) is spawned for proxy/dashboard tests.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use common::TestApp;

// ── Health & metadata ───────────────────────────────────────────────────────

#[tokio::test]
async fn healthz_returns_degraded_without_upstream() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // No upstream running → degraded (503).
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn metadata_returns_oauth2_endpoints() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/oauth-authorization-server")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["issuer"], "http://localhost:8768");
    assert_eq!(
        json["authorization_endpoint"],
        "http://localhost:8768/oauth2/auth"
    );
    assert_eq!(json["token_endpoint"], "http://localhost:8768/oauth2/token");
    assert_eq!(json["response_types_supported"][0], "code");
    assert_eq!(json["code_challenge_methods_supported"][0], "S256");
}

#[tokio::test]
async fn jwks_returns_empty_keys() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks-uri")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["keys"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn metrics_endpoint_returns_prometheus_text() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("uteke_web_tokens_issued_total"));
    assert!(text.contains("uteke_web_login_success_total"));
    assert!(text.contains("uteke_web_proxy_requests_total"));
}

// ── Profile ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn profile_without_bearer_returns_401() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/profile")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn profile_with_valid_jwt_returns_identity() {
    let app = TestApp::new().await;
    let (token, _) = uteke_web::jwt::mint_access_token(
        &app.state.config.jwt_secret,
        &app.state.config.issuer,
        "alice",
        "test-client",
        "read write",
        3600,
    )
    .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/profile")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["username"], "alice");
    assert_eq!(json["client_id"], "test-client");
    assert_eq!(json["scope"], "read write");
}

#[tokio::test]
async fn profile_with_invalid_jwt_returns_401() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/profile")
                .header("authorization", "Bearer invalid.token.here")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── Authorize ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn authorize_unknown_client_returns_error_page() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth2/auth?response_type=code&client_id=unknown&redirect_uri=http://localhost/cb&code_challenge=abc&code_challenge_method=S256")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn authorize_missing_pkce_returns_error() {
    let app = TestApp::new().await;
    // Register a client first.
    app.state
        .store
        .add_client(
            "test-cid",
            "secret",
            vec!["http://localhost/cb".into()],
            vec!["read".into()],
            false,
            false,
        )
        .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth2/auth?response_type=code&client_id=test-cid&redirect_uri=http://localhost/cb")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn authorize_valid_renders_login_page() {
    let app = TestApp::new().await;
    app.state
        .store
        .add_client(
            "test-cid2",
            "secret",
            vec!["http://localhost/cb".into()],
            vec!["read".into()],
            false,
            false,
        )
        .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth2/auth?response_type=code&client_id=test-cid2&redirect_uri=http://localhost/cb&code_challenge=abc&code_challenge_method=S256&state=xyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("Sign in to uteke"));
    assert!(html.contains(r#"name="client_id" value="test-cid2""#));
    assert!(html.contains(r#"name="state" value="xyz""#));
}

#[tokio::test]
async fn authorize_unsupported_response_type_returns_error() {
    let app = TestApp::new().await;
    app.state
        .store
        .add_client(
            "test-rt",
            "secret",
            vec!["http://localhost/cb".into()],
            vec!["read".into()],
            false,
            false,
        )
        .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth2/auth?response_type=token&client_id=test-rt&redirect_uri=http://localhost/cb&code_challenge=abc")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Login + full auth code flow ─────────────────────────────────────────────

#[tokio::test]
async fn full_auth_code_flow_with_pkce() {
    let app = TestApp::new().await;
    // Register client + user.
    app.state
        .store
        .add_client(
            "flow-client",
            "flow-secret",
            vec!["http://localhost/cb".into()],
            vec!["read".into(), "write".into()],
            false,
            false,
        )
        .unwrap();
    app.state.store.add_user("flowuser", "flowpass").unwrap();

    // 1. Authorize → login page.
    let verifier = uteke_web::pkce::random_verifier();
    let challenge = uteke_web::pkce::s256_challenge(&verifier);
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/oauth2/auth?response_type=code&client_id=flow-client&redirect_uri=http://localhost/cb&code_challenge={challenge}&code_challenge_method=S256&state=st123"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Login → redirect with code.
    let login_body = "username=flowuser&password=flowpass&client_id=flow-client&redirect_uri=http://localhost/cb&scope=read+write&state=st123&code_challenge={challenge}&code_challenge_method=S256&nonce=";
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(login_body.replace("{challenge}", &challenge)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("http://localhost/cb?code="));
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    assert!(!code.is_empty());

    // 3. Token exchange.
    let token_body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri=http://localhost/cb&client_id=flow-client&client_secret=flow-secret&code_verifier={verifier}"
    );
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(token_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["token_type"], "Bearer");
    assert!(json["access_token"].as_str().unwrap().len() > 50);
    assert!(json["refresh_token"].as_str().unwrap().len() > 20);
    assert_eq!(json["scope"], "read write");
}

#[tokio::test]
async fn login_wrong_password_renders_error() {
    let app = TestApp::new().await;
    app.state
        .store
        .add_client(
            "wrong-pass-client",
            "secret",
            vec!["http://localhost/cb".into()],
            vec!["read".into()],
            false,
            false,
        )
        .unwrap();
    app.state.store.add_user("wronguser", "rightpass").unwrap();
    let body = "username=wronguser&password=wrongpass&client_id=wrong-pass-client&redirect_uri=http://localhost/cb&scope=read&state=s&code_challenge=c&code_challenge_method=S256&nonce=";
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("invalid username or password"));
}

// ── Token: refresh rotation ─────────────────────────────────────────────────

#[tokio::test]
async fn refresh_token_rotation_works() {
    let app = TestApp::new().await;
    app.state
        .store
        .add_client(
            "rot-client",
            "rot-secret",
            vec!["http://localhost/cb".into()],
            vec!["read".into()],
            false,
            false,
        )
        .unwrap();
    app.state.store.add_user("rotuser", "rotpass").unwrap();
    // Manually insert a refresh token.
    let rt = "test-refresh-token-12345";
    app.state
        .store
        .add_refresh_token(rt, "rot-client", "rotuser", "read", 3600)
        .unwrap();
    let body = format!(
        "grant_type=refresh_token&refresh_token={rt}&client_id=rot-client&client_secret=rot-secret"
    );
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["access_token"].as_str().unwrap().len() > 50);
    let new_rt = json["refresh_token"].as_str().unwrap();
    assert_ne!(new_rt, rt);

    // Old token should now be invalid.
    let body2 = format!(
        "grant_type=refresh_token&refresh_token={rt}&client_id=rot-client&client_secret=rot-secret"
    );
    let resp2 = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body2))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn token_unsupported_grant_type() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=client_credentials"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "unsupported_grant_type");
}

// ── Dynamic registration (RFC 7591) ─────────────────────────────────────────

#[tokio::test]
async fn register_creates_client() {
    let app = TestApp::new().await;
    let body = r#"{"redirect_uris":["http://localhost/cb"],"scope":"read write"}"#;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/register")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    // RFC 7591 §3.2.1: must return 201 Created.
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["client_id"].as_str().unwrap().len() > 10);
    assert!(json["client_secret"].as_str().unwrap().len() > 10);
    assert_eq!(json["redirect_uris"][0], "http://localhost/cb");
    // client_id_issued_at must be a number (epoch seconds).
    assert!(
        json["client_id_issued_at"].is_number(),
        "client_id_issued_at should be a number, got: {}",
        json["client_id_issued_at"]
    );
    assert_eq!(json["client_secret_expires_at"], 0);
    assert_eq!(json["token_endpoint_auth_method"], "client_secret_post");
    assert_eq!(json["scope"], "read write");
}

#[tokio::test]
async fn register_public_client_no_secret() {
    let app = TestApp::new().await;
    let body = r#"{"redirect_uris":["http://localhost:54321/cb"],"token_endpoint_auth_method":"none","scope":"mcp offline_access"}"#;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/register")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["client_id"].as_str().unwrap().len() > 10);
    // Public client: no client_secret in response.
    assert!(
        json.get("client_secret").is_none() || json["client_secret"].as_str().is_none(),
        "public client should not have client_secret"
    );
    assert_eq!(json["token_endpoint_auth_method"], "none");
    assert_eq!(json["scope"], "mcp offline_access");
}

#[tokio::test]
async fn register_without_redirect_uris_returns_400() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/register")
                .header("content-type", "application/json")
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Revoke + Introspect ─────────────────────────────────────────────────────

#[tokio::test]
async fn revoke_returns_200() {
    let app = TestApp::new().await;
    app.state
        .store
        .add_client(
            "revoke-client",
            "revoke-secret",
            vec!["http://localhost/cb".into()],
            vec!["read".into()],
            false,
            false,
        )
        .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/revoke")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "token=some-token&client_id=revoke-client&client_secret=revoke-secret",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn revoke_without_client_auth_returns_401() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/revoke")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("token=some-token"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn introspect_active_access_token() {
    let app = TestApp::new().await;
    app.state
        .store
        .add_client(
            "intro-client",
            "intro-secret",
            vec!["http://localhost/cb".into()],
            vec!["read".into()],
            false,
            false,
        )
        .unwrap();
    let (token, _) = uteke_web::jwt::mint_access_token(
        &app.state.config.jwt_secret,
        &app.state.config.issuer,
        "alice",
        "cid",
        "read",
        3600,
    )
    .unwrap();
    let body = format!("token={token}&client_id=intro-client&client_secret=intro-secret");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["active"], true);
    assert_eq!(json["username"], "alice");
}

#[tokio::test]
async fn introspect_without_client_auth_returns_401() {
    let app = TestApp::new().await;
    let (token, _) = uteke_web::jwt::mint_access_token(
        &app.state.config.jwt_secret,
        &app.state.config.issuer,
        "alice",
        "cid",
        "read",
        3600,
    )
    .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("token={token}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn introspect_invalid_token_inactive() {
    let app = TestApp::new().await;
    app.state
        .store
        .add_client(
            "intro-client2",
            "intro-secret2",
            vec!["http://localhost/cb".into()],
            vec!["read".into()],
            false,
            false,
        )
        .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "token=garbage&client_id=intro-client2&client_secret=intro-secret2",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["active"], false);
}

// ── Proxy ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn proxy_without_bearer_returns_401() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/remember")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn proxy_with_invalid_jwt_returns_401() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/recall")
                .header("authorization", "Bearer bad.token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn proxy_write_scope_enforced() {
    let app = TestApp::new().await;
    // Token with only "read" scope.
    let (token, _) = uteke_web::jwt::mint_access_token(
        &app.state.config.jwt_secret,
        &app.state.config.issuer,
        "alice",
        "cid",
        "read",
        3600,
    )
    .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/remember")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(r#"{"content":"hi"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    // No upstream running → but scope check happens first, so 403.
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn proxy_admin_scope_for_delete() {
    let app = TestApp::new().await;
    let (token, _) = uteke_web::jwt::mint_access_token(
        &app.state.config.jwt_secret,
        &app.state.config.issuer,
        "alice",
        "cid",
        "read write",
        3600,
    )
    .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/forget/some-id")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── Dashboard ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn dashboard_without_session_redirects_to_authorize() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.contains("/oauth2/auth"));
    assert!(loc.contains("client_id=uteke-web-dashboard"));
}

#[tokio::test]
async fn dashboard_api_without_session_returns_401() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/memories")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn dashboard_trailing_slash_also_redirects_to_authorize() {
    // Regression: `/dashboard/` (trailing slash) used to fall through to the
    // catch-all proxy and return 401 instead of the OAuth2 login redirect.
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(loc.contains("/oauth2/auth"));
    assert!(loc.contains("client_id=uteke-web-dashboard"));
}

#[tokio::test]
async fn dashboard_api_with_valid_session_proxies() {
    let app = TestApp::new().await;
    // Create a session directly in the store.
    let session_id = uteke_web::session::new_session_id();
    let csrf = uteke_web::session::new_csrf_token();
    app.state
        .store
        .add_session(&session_id, "alice", &csrf, 3600)
        .unwrap();
    let cookie_val =
        uteke_web::session::sign_session_cookie(&session_id, &app.state.config.jwt_secret);
    // Typed GET (stats) doesn't need CSRF; upstream not running → 502.
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/stats")
                .header("cookie", format!("uteke_session={cookie_val}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // Upstream not running → 502.
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn dashboard_api_post_without_csrf_returns_403() {
    let app = TestApp::new().await;
    let session_id = uteke_web::session::new_session_id();
    let csrf = uteke_web::session::new_csrf_token();
    app.state
        .store
        .add_session(&session_id, "alice", &csrf, 3600)
        .unwrap();
    let cookie_val =
        uteke_web::session::sign_session_cookie(&session_id, &app.state.config.jwt_secret);
    // Typed create endpoint requires CSRF on mutations.
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/memories")
                .header("cookie", format!("uteke_session={cookie_val}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"content":"hi"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn dashboard_logout_clears_cookie() {
    let app = TestApp::new().await;
    let session_id = uteke_web::session::new_session_id();
    let csrf = uteke_web::session::new_csrf_token();
    app.state
        .store
        .add_session(&session_id, "alice", &csrf, 3600)
        .unwrap();
    let cookie_val =
        uteke_web::session::sign_session_cookie(&session_id, &app.state.config.jwt_secret);
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/logout")
                .header("cookie", format!("uteke_session={cookie_val}"))
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookies: Vec<&str> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert!(
        cookies
            .iter()
            .any(|c| c.contains("uteke_session=;") && c.contains("Max-Age=0"))
    );
    // Session deleted from store.
    assert!(app.state.store.get_session(&session_id).is_none());
}

// ── Dashboard index with session ────────────────────────────────────────────

#[tokio::test]
async fn dashboard_with_valid_session_serves_spa() {
    let app = TestApp::new().await;
    let session_id = uteke_web::session::new_session_id();
    let csrf = uteke_web::session::new_csrf_token();
    app.state
        .store
        .add_session(&session_id, "alice", &csrf, 3600)
        .unwrap();
    let cookie_val =
        uteke_web::session::sign_session_cookie(&session_id, &app.state.config.jwt_secret);
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard")
                .header("cookie", format!("uteke_session={cookie_val}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("<title>uteke — Dashboard</title>"));
}

#[tokio::test]
async fn dashboard_with_tampered_cookie_redirects_to_authorize() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard")
                .header("cookie", "uteke_session=tampered-value")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.contains("/oauth2/auth"));
}

// ── Dashboard callback error paths ──────────────────────────────────────────

#[tokio::test]
async fn dashboard_callback_with_error_param_renders_error() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/callback?error=access_denied")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("Login failed"));
    assert!(html.contains("access_denied"));
}

#[tokio::test]
async fn dashboard_callback_without_code_returns_400() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/callback?state=abc")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn dashboard_callback_with_invalid_state_returns_400() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/callback?code=abc&state=!!!invalid-base64!!!")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Proxy with mock upstream ────────────────────────────────────────────────

#[tokio::test]
async fn proxy_forwards_get_to_upstream() {
    let upstream = common::spawn_mock_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (token, _) = uteke_web::jwt::mint_access_token(
        &app.state.config.jwt_secret,
        &app.state.config.issuer,
        "alice",
        "cid",
        "read",
        3600,
    )
    .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/recall?q=test")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["method"], "GET");
    assert_eq!(json["path"], "/recall");
}

#[tokio::test]
async fn proxy_forwards_post_with_write_scope() {
    let upstream = common::spawn_mock_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (token, _) = uteke_web::jwt::mint_access_token(
        &app.state.config.jwt_secret,
        &app.state.config.issuer,
        "alice",
        "cid",
        "read write",
        3600,
    )
    .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/remember")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"content":"hello"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["method"], "POST");
    assert_eq!(json["path"], "/remember");
}

#[tokio::test]
async fn proxy_strips_cors_headers_from_upstream() {
    use axum::Router;
    use axum::routing::any;
    let app_mock = Router::new().route(
        "/{*path}",
        any(|| async {
            (
                [(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
                "ok",
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app_mock).await.unwrap();
    });

    let app = TestApp::with_upstream(addr).await;
    let (token, _) = uteke_web::jwt::mint_access_token(
        &app.state.config.jwt_secret,
        &app.state.config.issuer,
        "alice",
        "cid",
        "read",
        3600,
    )
    .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/anything")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // CORS header should be stripped.
    assert!(resp.headers().get("access-control-allow-origin").is_none());
}

// ── Dashboard API with mock upstream ────────────────────────────────────────
// The full typed-handler integration suite (with a shape-accurate mock
// upstream) lives in `tests/dashboard_api.rs`. The cases below cover the
// session/expiry gating that is specific to this handler set.

#[tokio::test]
async fn dashboard_api_expired_session_returns_401() {
    let app = TestApp::new().await;
    let fake_session = "fake-session-id-not-in-store";
    let cookie_val =
        uteke_web::session::sign_session_cookie(fake_session, &app.state.config.jwt_secret);
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/memories")
                .header("cookie", format!("uteke_session={cookie_val}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── Memory doc-refs (M7 cross-reference) ────────────────────────────────────

/// Spawn a mock upstream that handles `POST /memory/doc-refs`.
async fn spawn_memory_docrefs_upstream() -> std::net::SocketAddr {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::post;

    async fn memory_doc_refs(_b: String) -> impl IntoResponse {
        (
            StatusCode::OK,
            r#"{"memory_id":"m1","doc_slugs":["deploy-runbook","api-spec"]}"#.to_string(),
        )
    }

    let app = axum::Router::new().route("/memory/doc-refs", post(memory_doc_refs));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn memory_doc_refs_requires_session() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/memories/m1/doc-refs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn memory_doc_refs_returns_doc_slugs() {
    let upstream = spawn_memory_docrefs_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let session_id = uteke_web::session::new_session_id();
    let csrf = uteke_web::session::new_csrf_token();
    app.state
        .store
        .add_session(&session_id, "alice", &csrf, 3600)
        .unwrap();
    let cookie_val =
        uteke_web::session::sign_session_cookie(&session_id, &app.state.config.jwt_secret);
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/memories/m1/doc-refs")
                .header("cookie", format!("uteke_session={cookie_val}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["memory_id"], "m1");
    assert_eq!(json["doc_slugs"][0], "deploy-runbook");
    assert_eq!(json["doc_slugs"][1], "api-spec");
}

#[tokio::test]
async fn memory_doc_refs_upstream_down_returns_502() {
    let app = TestApp::new().await; // upstream = 127.0.0.1:59999 (nothing listening)
    let session_id = uteke_web::session::new_session_id();
    let csrf = uteke_web::session::new_csrf_token();
    app.state
        .store
        .add_session(&session_id, "alice", &csrf, 3600)
        .unwrap();
    let cookie_val =
        uteke_web::session::sign_session_cookie(&session_id, &app.state.config.jwt_secret);
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/memories/m1/doc-refs")
                .header("cookie", format!("uteke_session={cookie_val}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

// ── Healthz with mock upstream ──────────────────────────────────────────────

#[tokio::test]
async fn healthz_ok_when_upstream_healthy() {
    let upstream = common::spawn_mock_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
}

// ── Token edge cases ────────────────────────────────────────────────────────

#[tokio::test]
async fn token_code_grant_missing_code_returns_400() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=authorization_code&redirect_uri=http://localhost/cb",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_request");
}

#[tokio::test]
async fn token_code_grant_missing_verifier_returns_400() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=authorization_code&code=abc&redirect_uri=http://localhost/cb",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(json["error"], "invalid_request");
}

#[tokio::test]
async fn token_code_grant_invalid_client_returns_400() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "grant_type=authorization_code&code=abc&redirect_uri=http://localhost/cb&code_verifier=xyz&client_id=nonexistent",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(json["error"], "invalid_client");
}

#[tokio::test]
async fn token_refresh_missing_token_returns_400() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("grant_type=refresh_token"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(json["error"], "invalid_request");
}

#[tokio::test]
async fn token_with_basic_auth_client() {
    let app = TestApp::new().await;
    app.state
        .store
        .add_client(
            "basic-client",
            "basic-secret",
            vec!["http://localhost/cb".into()],
            vec!["read".into()],
            false,
            false,
        )
        .unwrap();
    app.state.store.add_user("basicuser", "basicpass").unwrap();

    // Do full flow to get a code.
    let verifier = uteke_web::pkce::random_verifier();
    let challenge = uteke_web::pkce::s256_challenge(&verifier);
    // Authorize.
    let _ = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/oauth2/auth?response_type=code&client_id=basic-client&redirect_uri=http://localhost/cb&code_challenge={challenge}&code_challenge_method=S256"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // Login.
    let login_body = format!(
        "username=basicuser&password=basicpass&client_id=basic-client&redirect_uri=http://localhost/cb&scope=read&state=s&code_challenge={challenge}&code_challenge_method=S256&nonce="
    );
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(login_body))
                .unwrap(),
        )
        .await
        .unwrap();
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();

    // Token exchange with Basic auth.
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode("basic-client:basic-secret");
    let token_body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri=http://localhost/cb&code_verifier={verifier}"
    );
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("authorization", format!("Basic {encoded}"))
                .body(Body::from(token_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(json["access_token"].as_str().unwrap().len() > 50);
}

// ── Introspect without token ────────────────────────────────────────────────

#[tokio::test]
async fn introspect_without_token_returns_inactive() {
    let app = TestApp::new().await;
    app.state
        .store
        .add_client(
            "intro-notoken",
            "intro-notoken-secret",
            vec!["http://localhost/cb".into()],
            vec!["read".into()],
            false,
            false,
        )
        .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth2/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "client_id=intro-notoken&client_secret=intro-notoken-secret",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(json["active"], false);
}

// ── Authorize redirect_uri mismatch ─────────────────────────────────────────

#[tokio::test]
async fn authorize_redirect_uri_mismatch_returns_error() {
    let app = TestApp::new().await;
    app.state
        .store
        .add_client(
            "mismatch-client",
            "secret",
            vec!["http://localhost/cb".into()],
            vec!["read".into()],
            false,
            false,
        )
        .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth2/auth?response_type=code&client_id=mismatch-client&redirect_uri=http://evil.com/cb&code_challenge=abc&code_challenge_method=S256")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("redirect_uri not registered"));
}

// ── Authorize with plain method (not S256) ──────────────────────────────────

#[tokio::test]
async fn authorize_plain_method_rejected() {
    let app = TestApp::new().await;
    app.state
        .store
        .add_client(
            "plain-client",
            "secret",
            vec!["http://localhost/cb".into()],
            vec!["read".into()],
            false,
            false,
        )
        .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth2/auth?response_type=code&client_id=plain-client&redirect_uri=http://localhost/cb&code_challenge=abc&code_challenge_method=plain")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("only S256"));
}
