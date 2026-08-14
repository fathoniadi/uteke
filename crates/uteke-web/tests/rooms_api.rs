//! Integration tests for the Rooms dashboard API layer.
//!
//! Drives the axum router via `tower::ServiceExt::oneshot` against a mock
//! uteke-server that returns properly-shaped JSON for each `/room/*` endpoint.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use common::TestApp;

// ── Test helpers ────────────────────────────────────────────────────────────

/// Create a live session and return (cookie, csrf) for authenticated requests.
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

/// A valid Room JSON (from `/room/list`).
const ROOM_JSON: &str = r#"{"id":"room-1","title":"Planning","namespace":"default","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}"#;

/// A valid RoomStats JSON (from `/room/stats`).
const ROOM_STATS_JSON: &str = r#"{"room_id":"room-1","title":"Planning","memory_count":3,"participant_count":2,"participants":["alice","bob"],"created_at":"2026-01-01T00:00:00Z","last_activity":"2026-01-02T00:00:00Z"}"#;

/// A valid Memory JSON (from `/room/memories`).
const MEMORY_JSON: &str = r#"{"id":"m1","content":"hello room","embedding":[],"tags":["plan"],"metadata":{},"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","namespace":"default","access_count":0,"last_accessed":null,"deprecated":false,"valid_from":null,"valid_until":null,"memory_type":"note","importance":0.5,"pinned":false,"content_type":"text","slug":null,"source":null,"source_type":"user"}"#;

/// Spawn a mock uteke-server that returns properly-shaped responses for `/room/*`.
async fn spawn_room_upstream() -> std::net::SocketAddr {
    use axum::extract::Query;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::{delete, get, post, put};
    use std::collections::HashMap;

    async fn room_list(_q: axum::extract::Query<HashMap<String, String>>) -> impl IntoResponse {
        (StatusCode::OK, format!("[{ROOM_JSON}]"))
    }
    async fn room_create(_b: String) -> impl IntoResponse {
        (
            StatusCode::OK,
            r#"{"created":"room-1","namespace":"default"}"#.to_string(),
        )
    }
    async fn room_stats(_b: String) -> impl IntoResponse {
        (StatusCode::OK, ROOM_STATS_JSON.to_string())
    }
    async fn room_memories(Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
        let _ = q.get("room_id");
        (StatusCode::OK, format!("[{MEMORY_JSON}]"))
    }
    async fn room_remember(_b: String) -> impl IntoResponse {
        (
            StatusCode::OK,
            r#"{"id":"m1","room_id":"room-1"}"#.to_string(),
        )
    }
    async fn room_doc_list(_b: String) -> impl IntoResponse {
        (
            StatusCode::OK,
            r#"{"room_id":"room-1","doc_slugs":["deploy-runbook"]}"#.to_string(),
        )
    }
    async fn room_doc_add(_b: String) -> impl IntoResponse {
        (
            StatusCode::OK,
            r#"{"status":"linked","room_id":"room-1","doc_slug":"deploy-runbook"}"#.to_string(),
        )
    }
    async fn room_doc_remove(_b: String) -> impl IntoResponse {
        (
            StatusCode::OK,
            r#"{"status":"unlinked","room_id":"room-1","doc_slug":"deploy-runbook"}"#.to_string(),
        )
    }
    async fn room_delete(Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
        let id = q.get("room_id").cloned().unwrap_or_default();
        (StatusCode::OK, format!(r#"{{"deleted":"{id}"}}"#))
    }

    let app = axum::Router::new()
        .route("/room/list", get(room_list))
        .route("/room/create", post(room_create))
        .route("/room/stats", post(room_stats))
        .route("/room/memories", get(room_memories))
        .route("/room/remember", post(room_remember))
        .route("/room/document/list", post(room_doc_list))
        .route("/room/document/add", put(room_doc_add))
        .route("/room/document/remove", delete(room_doc_remove))
        .route("/room/delete", delete(room_delete));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

async fn read_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)
}

// ── Auth gating ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn room_list_requires_session() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/rooms")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn room_get_requires_session() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/rooms/room-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn room_create_requires_csrf() {
    let upstream = spawn_room_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/rooms")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"room_id":"room-1"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn room_delete_requires_csrf() {
    let upstream = spawn_room_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/dashboard/api/rooms/room-1")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn room_add_memory_requires_csrf() {
    let upstream = spawn_room_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/rooms/room-1/memories")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"content":"hi"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn room_link_doc_requires_csrf() {
    let upstream = spawn_room_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/rooms/room-1/documents")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"doc_slug":"deploy-runbook"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── Happy path ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn room_list_returns_rooms() {
    let upstream = spawn_room_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/rooms")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert!(json.is_array());
    assert_eq!(json[0]["id"], "room-1");
    assert_eq!(json[0]["title"], "Planning");
    assert_eq!(json[0]["namespace"], "default");
}

#[tokio::test]
async fn room_get_returns_stats() {
    let upstream = spawn_room_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/rooms/room-1")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["room_id"], "room-1");
    assert_eq!(json["memory_count"], 3);
    assert_eq!(json["participant_count"], 2);
    assert_eq!(json["participants"][0], "alice");
}

#[tokio::test]
async fn room_create_returns_created() {
    let upstream = spawn_room_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/rooms")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"room_id":"room-1","title":"Planning"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["created"], "room-1");
}

#[tokio::test]
async fn room_create_rejects_empty_id() {
    let upstream = spawn_room_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/rooms")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"room_id":""}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn room_list_memories_returns_memories() {
    let upstream = spawn_room_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/rooms/room-1/memories?limit=100")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert!(json.is_array());
    assert_eq!(json[0]["id"], "m1");
    assert_eq!(json[0]["content"], "hello room");
}

#[tokio::test]
async fn room_add_memory_returns_id() {
    let upstream = spawn_room_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/rooms/room-1/memories")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"content":"hello room","tags":["plan"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["id"], "m1");
    assert_eq!(json["room_id"], "room-1");
}

#[tokio::test]
async fn room_add_memory_rejects_empty_content() {
    let upstream = spawn_room_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/rooms/room-1/memories")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"content":"  "}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn room_list_documents_returns_slugs() {
    let upstream = spawn_room_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/rooms/room-1/documents")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["room_id"], "room-1");
    assert_eq!(json["doc_slugs"][0], "deploy-runbook");
}

#[tokio::test]
async fn room_link_document_returns_linked() {
    let upstream = spawn_room_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/rooms/room-1/documents")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"doc_slug":"deploy-runbook"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["status"], "linked");
}

#[tokio::test]
async fn room_unlink_document_returns_unlinked() {
    let upstream = spawn_room_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/dashboard/api/rooms/room-1/documents")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"doc_slug":"deploy-runbook"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["status"], "unlinked");
}

#[tokio::test]
async fn room_delete_returns_deleted() {
    let upstream = spawn_room_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/dashboard/api/rooms/room-1")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["deleted"], "room-1");
}

// ── Upstream errors ─────────────────────────────────────────────────────────

#[tokio::test]
async fn room_list_upstream_down_returns_502() {
    let app = TestApp::new().await; // upstream = 127.0.0.1:59999 (nothing listening)
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/rooms")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}
