//! Integration tests for the Documents dashboard API layer (PLAN-docs.md D1+D2).
//!
//! Drives the axum router via `tower::ServiceExt::oneshot` against a mock
//! uteke-server that returns properly-shaped JSON for each `/doc/*` endpoint.

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

/// A valid DocumentSummary JSON (from `/doc/list`).
const DOC_SUMMARY_JSON: &str = r#"{"id":"d1","slug":"deploy-runbook","title":"Deploy Runbook","namespace":null,"author":null,"version":1,"updated_at":"2026-01-01T00:00:00Z","parent_id":null,"depth":0,"has_children":false,"sort_order":0}"#;

/// A valid full Document JSON (from `/doc/get`, `/doc/create`, `/doc/update`).
const DOC_FULL_JSON: &str = r##"{"id":"d1","slug":"deploy-runbook","title":"Deploy Runbook","content":"# Deploy\n\nStep 1...","namespace":null,"author":null,"tags":["ops"],"metadata":null,"version":1,"content_type":"markdown","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","parent_id":null,"path":"/d1/","depth":0,"sort_order":0,"has_children":false}"##;

/// A valid DocumentSearchResult JSON (from `/doc/search`).
const DOC_SEARCH_JSON: &str = r##"{"document":{"id":"d1","slug":"deploy-runbook","title":"Deploy Runbook","namespace":null,"author":null,"version":1,"updated_at":"2026-01-01T00:00:00Z","parent_id":null,"depth":0,"has_children":false,"sort_order":0},"chunk_heading":"# Deploy","chunk_snippet":"Step 1...","score":0.81,"mode":"hybrid"}"##;

/// Spawn a mock uteke-server that returns properly-shaped responses for `/doc/*`.
async fn spawn_doc_upstream() -> std::net::SocketAddr {
    use axum::extract::Query;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::{delete, post};
    use std::collections::HashMap;

    async fn doc_list(_b: String) -> impl IntoResponse {
        (StatusCode::OK, format!("[{DOC_SUMMARY_JSON}]"))
    }
    async fn doc_get(b: String) -> impl IntoResponse {
        // Return the document only for the known slug "deploy-runbook";
        // return null for any other slug so the auto-generation collision
        // check sees them as available.
        let slug = serde_json::from_str::<serde_json::Value>(&b)
            .ok()
            .and_then(|v| v.get("slug").and_then(|s| s.as_str()).map(String::from))
            .unwrap_or_default();
        if slug == "deploy-runbook" {
            (StatusCode::OK, DOC_FULL_JSON.to_string())
        } else {
            (StatusCode::OK, "null".to_string())
        }
    }
    async fn doc_search(_b: String) -> impl IntoResponse {
        (StatusCode::OK, format!("[{DOC_SEARCH_JSON}]"))
    }
    async fn doc_create(_b: String) -> impl IntoResponse {
        (StatusCode::OK, DOC_FULL_JSON.to_string())
    }
    async fn doc_update(_b: String) -> impl IntoResponse {
        (StatusCode::OK, DOC_FULL_JSON.to_string())
    }
    async fn doc_move(_b: String) -> impl IntoResponse {
        (StatusCode::OK, r#"{"moved":1}"#.to_string())
    }
    async fn doc_delete(Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
        let id = q.get("id").cloned().unwrap_or_default();
        (
            StatusCode::OK,
            format!(r#"{{"deleted":true,"subtree_size":0,"id":"{id}"}}"#),
        )
    }
    async fn doc_mem_refs(_b: String) -> impl IntoResponse {
        (
            StatusCode::OK,
            r#"{"doc_slug":"deploy-runbook","memory_ids":["m1","m2"]}"#.to_string(),
        )
    }

    let app = axum::Router::new()
        .route("/doc/list", post(doc_list))
        .route("/doc/get", post(doc_get))
        .route("/doc/search", post(doc_search))
        .route("/doc/create", post(doc_create))
        .route("/doc/update", post(doc_update))
        .route("/doc/move", post(doc_move))
        .route("/doc/delete", delete(doc_delete))
        .route("/doc/mem-refs", post(doc_mem_refs));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Spawn a mock upstream where `/doc/get` returns null (document not found).
async fn spawn_doc_upstream_not_found() -> std::net::SocketAddr {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::post;

    async fn doc_get_null(_b: String) -> impl IntoResponse {
        (StatusCode::OK, "null")
    }

    let app = axum::Router::new().route("/doc/get", post(doc_get_null));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Spawn a mock upstream where `/doc/update` returns null (document not found).
async fn spawn_doc_upstream_update_null() -> std::net::SocketAddr {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::post;

    async fn doc_update_null(_b: String) -> impl IntoResponse {
        (StatusCode::OK, "null")
    }

    let app = axum::Router::new().route("/doc/update", post(doc_update_null));

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

// ── D1: Read path — auth gating ─────────────────────────────────────────────

#[tokio::test]
async fn doc_list_requires_session() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/documents")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn doc_get_requires_session() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/documents/deploy-runbook")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn doc_search_requires_session() {
    let app = TestApp::new().await;
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/documents/search?q=deploy")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── D1: Read path — happy path ──────────────────────────────────────────────

#[tokio::test]
async fn doc_list_returns_summaries() {
    let upstream = spawn_doc_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/documents?limit=50")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert!(json.is_array());
    assert_eq!(json[0]["id"], "d1");
    assert_eq!(json[0]["slug"], "deploy-runbook");
    assert_eq!(json[0]["title"], "Deploy Runbook");
    // Summary should NOT have content/tags (DocumentSummary has no content field).
    assert!(json[0].get("content").is_none() || json[0]["content"].is_null());
    assert!(json[0].get("tags").is_none() || json[0]["tags"].is_null());
    // Summary should have tree fields.
    assert_eq!(json[0]["depth"], 0);
    assert_eq!(json[0]["has_children"], false);
}

#[tokio::test]
async fn doc_list_roots_only_param_forwarded() {
    let upstream = spawn_doc_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/documents?roots_only=true")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert!(json.is_array());
    assert_eq!(json[0]["slug"], "deploy-runbook");
}

#[tokio::test]
async fn doc_search_returns_results_with_score() {
    let upstream = spawn_doc_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/documents/search?q=deploy&mode=hybrid")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert!(json.is_array());
    assert_eq!(json[0]["slug"], "deploy-runbook");
    assert_eq!(json[0]["score"], 0.81);
    assert_eq!(json[0]["mode"], "hybrid");
    assert_eq!(json[0]["chunk_heading"], "# Deploy");
    assert_eq!(json[0]["chunk_snippet"], "Step 1...");
}

#[tokio::test]
async fn doc_search_rejects_empty_query() {
    let upstream = spawn_doc_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/documents/search?q=")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn doc_get_returns_full_document() {
    let upstream = spawn_doc_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/documents/deploy-runbook")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["id"], "d1");
    assert_eq!(json["slug"], "deploy-runbook");
    assert_eq!(json["title"], "Deploy Runbook");
    assert_eq!(json["content"], "# Deploy\n\nStep 1...");
    assert_eq!(json["tags"][0], "ops");
    assert_eq!(json["version"], 1);
    assert_eq!(json["created_at"], "2026-01-01T00:00:00Z");
}

#[tokio::test]
async fn doc_get_null_maps_to_404() {
    let upstream = spawn_doc_upstream_not_found().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/documents/nonexistent")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn doc_mem_refs_returns_memory_ids() {
    let upstream = spawn_doc_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/documents/deploy-runbook/mem-refs")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["doc_slug"], "deploy-runbook");
    assert_eq!(json["memory_ids"][0], "m1");
    assert_eq!(json["memory_ids"][1], "m2");
}

// ── D1: Read path — upstream errors ─────────────────────────────────────────

#[tokio::test]
async fn doc_list_upstream_down_returns_502() {
    let app = TestApp::new().await; // upstream = 127.0.0.1:59999 (nothing listening)
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/documents")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

// ── D2: Write path — CSRF gating ────────────────────────────────────────────

#[tokio::test]
async fn doc_create_requires_csrf() {
    let upstream = spawn_doc_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/documents")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"slug":"test","content":"hello"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn doc_create_rejects_bad_csrf() {
    let upstream = spawn_doc_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/documents")
                .header("cookie", &cookie)
                .header("x-csrf-token", "wrong-token")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"slug":"test","content":"hello"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn doc_update_requires_csrf() {
    let upstream = spawn_doc_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/dashboard/api/documents/deploy-runbook")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"content":"updated"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn doc_delete_requires_csrf() {
    let upstream = spawn_doc_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/dashboard/api/documents/deploy-runbook")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn doc_move_requires_csrf() {
    let upstream = spawn_doc_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/documents/deploy-runbook/move")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"new_parent":"ops"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── D2: Write path — happy path ─────────────────────────────────────────────

#[tokio::test]
async fn doc_create_returns_full_document() {
    let upstream = spawn_doc_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/documents")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    r##"{"title":"Deploy Runbook","content":"# Deploy","tags":["ops"]}"##,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["id"], "d1");
    assert_eq!(json["slug"], "deploy-runbook");
    assert_eq!(json["content"], "# Deploy\n\nStep 1...");
    assert_eq!(json["tags"][0], "ops");
}

#[tokio::test]
async fn doc_create_auto_generates_slug_from_title() {
    // The dashboard API ignores any client-supplied slug and auto-generates
    // one from the title. The response carries the upstream document, whose
    // slug is whatever the upstream /doc/create returned.
    let upstream = spawn_doc_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/documents")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                // No title either — slug should be derived from first heading.
                .body(Body::from(r##"{"content":"# Hello World\nbody"}"##))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn doc_create_rejects_empty_content() {
    let upstream = spawn_doc_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/documents")
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
async fn doc_update_returns_full_document() {
    let upstream = spawn_doc_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/dashboard/api/documents/deploy-runbook")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    r##"{"content":"# Updated","tags":["ops","dev"]}"##,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["id"], "d1");
    assert_eq!(json["content"], "# Deploy\n\nStep 1...");
}

#[tokio::test]
async fn doc_update_null_maps_to_404() {
    let upstream = spawn_doc_upstream_update_null().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/dashboard/api/documents/nonexistent")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"content":"updated"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn doc_delete_returns_deleted_and_subtree() {
    let upstream = spawn_doc_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/dashboard/api/documents/deploy-runbook")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["deleted"], true);
    assert!(json.get("subtree_size").is_some());
}

#[tokio::test]
async fn doc_move_returns_moved_count() {
    let upstream = spawn_doc_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/documents/deploy-runbook/move")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"new_parent":"ops"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["moved"], 1);
}

#[tokio::test]
async fn doc_move_to_root_with_empty_parent() {
    let upstream = spawn_doc_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/documents/deploy-runbook/move")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["moved"], 1);
}
