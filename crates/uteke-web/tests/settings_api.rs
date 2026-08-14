//! Integration tests for the settings API (clients, users, sessions).
#![allow(dead_code)]

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use tower::ServiceExt;

use common::TestApp;

// ── Test helpers ────────────────────────────────────────────────────────────

fn make_session(app: &TestApp, username: &str) -> (String, String) {
    let sid = uteke_web::session::new_session_id();
    let csrf = uteke_web::session::new_csrf_token();
    let ttl = 3600;
    app.state
        .store
        .add_session(&sid, username, &csrf, ttl)
        .unwrap();
    let signed = uteke_web::session::sign_session_cookie(&sid, &app.state.config.jwt_secret);
    let cookie = format!("uteke_session={signed}");
    (cookie, csrf)
}

// ── Clients tests ───────────────────────────────────────────────────────────

#[tokio::test]
async fn settings_list_clients_requires_session() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/settings/clients")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn settings_list_clients_empty() {
    let app = TestApp::new().await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/settings/clients")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(&body[..], b"[]");
}

#[tokio::test]
async fn settings_create_client_requires_csrf() {
    let app = TestApp::new().await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/settings/clients")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"client_id":"test-client","client_secret":"secret"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn settings_create_client_success() {
    let app = TestApp::new().await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/settings/clients")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"client_id":"test-client","client_secret":"s3cr3t","redirect_uris":["http://localhost/cb"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["client_id"], "test-client");
    assert_eq!(json["public"], false);
}

#[tokio::test]
async fn settings_create_client_rejects_empty_id() {
    let app = TestApp::new().await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/settings/clients")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"client_id":"","client_secret":"s"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn settings_create_client_rejects_non_public_without_secret() {
    let app = TestApp::new().await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/settings/clients")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"client_id":"no-secret","public":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn settings_delete_client_success() {
    let app = TestApp::new().await;
    let (cookie, csrf) = make_session(&app, "alice");
    // Create a client first.
    app.state
        .store
        .add_client("del-client", "secret", vec![], vec![], false, false)
        .unwrap();
    let clients = app.state.store.list_clients().unwrap();
    let id = clients
        .iter()
        .find(|c| c.client_id == "del-client")
        .map(|c| c.id.clone())
        .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/dashboard/api/settings/clients/{id}"))
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Verify it's gone.
    assert!(app.state.store.get_client_by_id("del-client").is_none());
}

#[tokio::test]
async fn settings_delete_client_not_found() {
    let app = TestApp::new().await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/dashboard/api/settings/clients/nonexistent")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Users tests ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn settings_list_users_requires_session() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/settings/users")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn settings_create_user_success() {
    let app = TestApp::new().await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/settings/users")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"bob","password":"pass123"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["username"], "bob");
    assert_eq!(json["locked"], false);
}

#[tokio::test]
async fn settings_create_user_rejects_duplicate() {
    let app = TestApp::new().await;
    let (cookie, csrf) = make_session(&app, "alice");
    // Create first.
    app.state.store.add_user("dup", "pass123").unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/settings/users")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"dup","password":"pass123"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn settings_delete_user_prevents_self_deletion() {
    let app = TestApp::new().await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/dashboard/api/settings/users/alice")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn settings_delete_user_success() {
    let app = TestApp::new().await;
    let (cookie, csrf) = make_session(&app, "alice");
    app.state.store.add_user("todelete", "pass123").unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/dashboard/api/settings/users/todelete")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(app.state.store.get_user("todelete").is_none());
}

#[tokio::test]
async fn settings_change_password_success() {
    let app = TestApp::new().await;
    let (cookie, csrf) = make_session(&app, "alice");
    app.state.store.add_user("pwuser", "oldpass").unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/dashboard/api/settings/users/pwuser/password")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"new_password":"newpass123"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Verify the new password works.
    let user = app.state.store.verify_user("pwuser", "newpass123").unwrap();
    assert_eq!(user.username, "pwuser");
}

#[tokio::test]
async fn settings_unlock_user_success() {
    let app = TestApp::new().await;
    let (cookie, csrf) = make_session(&app, "alice");
    app.state.store.add_user("lockeduser", "pass").unwrap();
    // Lock the user by simulating 10 failed attempts.
    for _ in 0..10 {
        let _ = app.state.store.verify_user("lockeduser", "wrong");
    }
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/settings/users/lockeduser/unlock")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let user = app.state.store.get_user("lockeduser").unwrap();
    assert!(!user.locked);
    assert_eq!(user.failed_attempts, 0);
}

// ── Sessions tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn settings_list_sessions_requires_session() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/settings/sessions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn settings_list_sessions_returns_active() {
    let app = TestApp::new().await;
    let (cookie, _csrf) = make_session(&app, "alice");
    // The make_session helper already created one session.
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/settings/sessions")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array());
    assert!(!json.as_array().unwrap().is_empty());
    assert_eq!(json[0]["username"], "alice");
}

#[tokio::test]
async fn settings_revoke_session_prevents_self() {
    let app = TestApp::new().await;
    let (cookie, csrf) = make_session(&app, "alice");
    // Extract the session_id from the cookie (it's the part before the dot).
    let sid = cookie
        .strip_prefix("uteke_session=")
        .and_then(|s| s.split('.').next())
        .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/dashboard/api/settings/sessions/{sid}"))
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn settings_revoke_session_success() {
    let app = TestApp::new().await;
    let (cookie, csrf) = make_session(&app, "alice");
    // Create a second session for a different user.
    let sid2 = uteke_web::session::new_session_id();
    let csrf2 = uteke_web::session::new_csrf_token();
    app.state
        .store
        .add_session(&sid2, "bob", &csrf2, 3600)
        .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/dashboard/api/settings/sessions/{sid2}"))
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Verify session is gone.
    assert!(app.state.store.get_session(&sid2).is_none());
}

// ── OAuth2 Tokens tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn settings_list_tokens_requires_session() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/settings/tokens")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn settings_list_tokens_empty() {
    let app = TestApp::new().await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/settings/tokens")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(&body[..], b"[]");
}

#[tokio::test]
async fn settings_list_tokens_returns_active() {
    let app = TestApp::new().await;
    let (cookie, _csrf) = make_session(&app, "alice");
    // Add a refresh token.
    app.state
        .store
        .add_refresh_token("rt-test-1", "mcp-client", "agent-a", "read write", 3600)
        .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/settings/tokens")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array());
    assert!(!json.as_array().unwrap().is_empty());
    assert_eq!(json[0]["client_id"], "mcp-client");
    assert_eq!(json[0]["username"], "agent-a");
    assert_eq!(json[0]["scope"], "read write");
}

#[tokio::test]
async fn settings_revoke_token_requires_csrf() {
    let app = TestApp::new().await;
    let (cookie, _csrf) = make_session(&app, "alice");
    app.state
        .store
        .add_refresh_token("rt-revoke-1", "cid", "alice", "read", 3600)
        .unwrap();
    // Get the hash.
    let tokens = app.state.store.list_refresh_tokens().unwrap();
    let hash = tokens
        .iter()
        .find(|t| t.client_id == "cid")
        .map(|t| t.token_hash.clone())
        .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/dashboard/api/settings/tokens/{hash}"))
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn settings_revoke_token_success() {
    let app = TestApp::new().await;
    let (cookie, csrf) = make_session(&app, "alice");
    app.state
        .store
        .add_refresh_token("rt-revoke-2", "cid2", "agent-b", "read", 3600)
        .unwrap();
    let tokens = app.state.store.list_refresh_tokens().unwrap();
    let hash = tokens
        .iter()
        .find(|t| t.client_id == "cid2")
        .map(|t| t.token_hash.clone())
        .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/dashboard/api/settings/tokens/{hash}"))
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Verify token is revoked (no longer in active list).
    let active = app.state.store.list_refresh_tokens().unwrap();
    assert!(active.iter().all(|t| t.token_hash != hash));
}

#[tokio::test]
async fn settings_revoke_token_not_found() {
    let app = TestApp::new().await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/dashboard/api/settings/tokens/abc123nonexistent")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
