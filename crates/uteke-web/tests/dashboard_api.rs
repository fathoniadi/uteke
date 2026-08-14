//! Integration tests for the typed dashboard API layer (M7.1).
//!
//! Drives the axum router via `tower::ServiceExt::oneshot` against a mock
//! uteke-server that returns properly-shaped JSON for each endpoint.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use common::TestApp;

// ── Test helpers ────────────────────────────────────────────────────────────

/// Create a live session in the store and return the `Cookie` + `X-CSRF-Token`
/// header values to authenticate dashboard API requests.
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

/// A minimal valid Memory JSON for the mock upstream.
const MEM_JSON: &str = r#"{"id":"m1","content":"hello world","tags":["t1","t2"],"metadata":{},"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","namespace":"default","memory_type":"note","importance":0.7,"pinned":true}"#;

/// Spawn a mock uteke-server that returns properly-shaped responses for the
/// endpoints the typed dashboard API calls.
async fn spawn_typed_upstream() -> std::net::SocketAddr {
    use axum::extract::Query;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::{delete, get, post};
    use std::collections::HashMap;

    async fn list(_b: String) -> impl IntoResponse {
        (StatusCode::OK, format!("[{MEM_JSON}]"))
    }
    async fn recall(_b: String) -> impl IntoResponse {
        (
            StatusCode::OK,
            r#"[{"result_type":"memory","score":0.81,"content":"hello world","memory_id":"m1","tags":["t1"],"memory_type":"note","importance":0.7,"pinned":true,"namespace":"default","created_at":"2026-01-01T00:00:00Z"}]"#,
        )
    }
    async fn search(_b: String) -> impl IntoResponse {
        (
            StatusCode::OK,
            format!(r#"[{{"memory":{MEM_JSON},"score":0.9}}]"#),
        )
    }
    async fn memory_get(Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
        if q.get("id").map(String::as_str) == Some("m1") {
            (StatusCode::OK, MEM_JSON.to_string())
        } else {
            (
                StatusCode::NOT_FOUND,
                r#"{"error":"not found"}"#.to_string(),
            )
        }
    }
    async fn remember(_b: String) -> impl IntoResponse {
        (StatusCode::OK, r#"{"id":"m1"}"#.to_string())
    }
    async fn memory_put(_b: String) -> impl IntoResponse {
        (StatusCode::OK, r#"{"updated":"m1"}"#.to_string())
    }
    async fn forget(Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
        let id = q.get("id").cloned().unwrap_or_default();
        (StatusCode::OK, format!(r#"{{"forgotten":"{id}"}}"#))
    }
    async fn tags(Query(_q): Query<HashMap<String, String>>) -> impl IntoResponse {
        (
            StatusCode::OK,
            r#"[{"name":"t1","count":3},{"name":"t2","count":1}]"#.to_string(),
        )
    }
    async fn namespaces() -> impl IntoResponse {
        (StatusCode::OK, r#"["default","agent-a"]"#.to_string())
    }
    async fn stats(Query(_q): Query<HashMap<String, String>>) -> impl IntoResponse {
        (
            StatusCode::OK,
            r#"{"total_memories":42,"unique_tags":5,"db_size_bytes":1024,"hot":3,"warm":7,"cold":32,"cache_hits":10,"cache_misses":20,"total_documents":3}"#,
        )
    }
    async fn memory_feedback(_b: String) -> impl IntoResponse {
        (
            StatusCode::OK,
            r#"{"id":"m1","feedback":"helpful","delta":0.05,"importance":0.75}"#.to_string(),
        )
    }
    async fn graph(Query(_q): Query<HashMap<String, String>>) -> impl IntoResponse {
        (
            StatusCode::OK,
            r#"{"nodes":[{"id":"n1","label":"Entity1","entity_type":"person","properties":{},"memory_id":"m1","created_at":"2026-01-01T00:00:00Z"}],"edges":[{"id":"e1","source_id":"n1","target_id":"n2","relation":"related_to","weight":1.0,"created_at":"2026-01-01T00:00:00Z"}],"stats":{"node_count":1,"edge_count":1,"relation_types":["related_to"]}}"#.to_string(),
        )
    }
    async fn graph_edge(_b: String) -> impl IntoResponse {
        (StatusCode::OK, r#"{"ok":true}"#.to_string())
    }
    async fn graph_edge_delete(Query(_q): Query<HashMap<String, String>>) -> impl IntoResponse {
        (StatusCode::OK, r#"{"ok":true}"#.to_string())
    }
    async fn timeline(Query(_q): Query<HashMap<String, String>>) -> impl IntoResponse {
        (
            StatusCode::OK,
            r#"[{"id":1,"memory_id":"m1","event_type":"created","event_data":null,"created_at":"2026-01-01T00:00:00Z"}]"#.to_string(),
        )
    }
    async fn tags_rename(_b: String) -> impl IntoResponse {
        (
            StatusCode::OK,
            r#"{"renamed":true,"count":3,"old":"foo","new":"bar"}"#.to_string(),
        )
    }
    async fn tags_delete(_b: String) -> impl IntoResponse {
        (
            StatusCode::OK,
            r#"{"deleted":true,"count":3,"tag":"foo"}"#.to_string(),
        )
    }
    async fn export(Query(_q): Query<HashMap<String, String>>) -> impl IntoResponse {
        (
            StatusCode::OK,
            [("content-type", "application/x-ndjson")],
            r#"{"id":"m1","content":"hello"}"#.to_string(),
        )
    }
    async fn import(_b: String) -> impl IntoResponse {
        (StatusCode::OK, r#"{"imported":1,"skipped":0}"#.to_string())
    }

    let app = axum::Router::new()
        .route("/list", post(list))
        .route("/recall", post(recall))
        .route("/search", post(search))
        .route("/memory", get(memory_get).put(memory_put))
        .route("/remember", post(remember))
        .route("/forget", delete(forget))
        .route("/tags", get(tags))
        .route("/namespaces", get(namespaces))
        .route("/stats", get(stats))
        .route("/memory/feedback", post(memory_feedback))
        .route("/graph", get(graph))
        .route("/graph/edge", post(graph_edge).delete(graph_edge_delete))
        .route("/timeline", get(timeline))
        .route("/tags/rename", post(tags_rename))
        .route("/tags/delete", post(tags_delete))
        .route("/export", get(export))
        .route("/import", post(import));

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
async fn api_requires_session() {
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
async fn api_profile_returns_username_from_session() {
    let app = TestApp::new().await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/profile")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["username"], "alice");
}

#[tokio::test]
async fn api_create_requires_csrf() {
    let app = TestApp::new().await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/memories")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"content":"x"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn api_create_rejects_bad_csrf() {
    let app = TestApp::new().await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/memories")
                .header("cookie", &cookie)
                .header("x-csrf-token", "wrong-token")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"content":"x"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── Typed handlers against a mock upstream ──────────────────────────────────

#[tokio::test]
async fn list_mode_returns_envelope_from_upstream_list() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/memories?mode=list&limit=20&offset=0")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["mode"], "list");
    assert_eq!(json["limit"], 20);
    assert_eq!(json["offset"], 0);
    assert!(json["memories"].is_array());
    assert_eq!(json["memories"][0]["id"], "m1");
    assert_eq!(json["memories"][0]["content"], "hello world");
    // list mode has no score.
    assert!(json["memories"][0].get("score").is_none() || json["memories"][0]["score"].is_null());
}

#[tokio::test]
async fn semantic_mode_returns_scored_rows() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/memories?mode=semantic&q=hello&limit=20")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["mode"], "semantic");
    assert_eq!(json["memories"][0]["id"], "m1");
    assert_eq!(json["memories"][0]["score"], 0.81);
}

#[tokio::test]
async fn fts_mode_returns_scored_rows() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/memories?mode=fts&q=hello&limit=20")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["mode"], "fts");
    assert_eq!(json["memories"][0]["score"], 0.9);
}

#[tokio::test]
async fn get_memory_returns_single_row() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/memories/m1")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["id"], "m1");
    assert_eq!(json["memory_type"], "note");
    assert_eq!(json["importance"], 0.7);
    assert_eq!(json["pinned"], true);
}

#[tokio::test]
async fn create_memory_returns_full_row() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/memories")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"content":"hello world","tags":["t1"],"memory_type":"note"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    // The handler fetches the created memory → returns a full DashboardMemory.
    assert_eq!(json["id"], "m1");
    assert_eq!(json["content"], "hello world");
}

#[tokio::test]
async fn create_memory_rejects_invalid_memory_type() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    // "bogus" is not in the taxonomy → normalized to None → "type" omitted.
    // Upstream still returns id m1, so this should succeed but without type.
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/memories")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"content":"hello","memory_type":"bogus"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    // Invalid type is dropped (not forwarded), create still succeeds.
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn update_memory_returns_full_row() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/dashboard/api/memories/m1")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"content":"updated","importance":0.9,"pinned":false}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["id"], "m1");
}

#[tokio::test]
async fn forget_memory_returns_forgotten_id() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/dashboard/api/memories/m1")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["forgotten"], "m1");
}

#[tokio::test]
async fn tags_endpoint_returns_tag_info() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/tags")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert!(json.is_array());
    assert_eq!(json[0]["name"], "t1");
    assert_eq!(json[0]["count"], 3);
}

#[tokio::test]
async fn namespaces_endpoint_returns_list() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/namespaces")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json, serde_json::json!(["default", "agent-a"]));
}

#[tokio::test]
async fn stats_endpoint_returns_store_stats() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/stats")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["total_memories"], 42);
    assert_eq!(json["unique_tags"], 5);
}

#[tokio::test]
async fn empty_query_in_semantic_mode_falls_back_to_list() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/memories?mode=semantic&q=&limit=20")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    // Falls back to list mode (no score).
    assert_eq!(json["mode"], "list");
}

// ── Memory feedback tests ───────────────────────────────────────────────────

#[tokio::test]
async fn memory_feedback_requires_csrf() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/memories/m1/feedback")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"feedback":"helpful"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn memory_feedback_returns_updated_importance() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/memories/m1/feedback")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"feedback":"helpful"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["feedback"], "helpful");
    assert_eq!(json["delta"], 0.05);
    assert_eq!(json["importance"], 0.75);
}

#[tokio::test]
async fn memory_feedback_rejects_invalid_feedback() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/memories/m1/feedback")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"feedback":"bogus"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Memory graph & timeline tests ───────────────────────────────────────────

#[tokio::test]
async fn memory_graph_returns_nodes_edges() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/memories/m1/graph")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert!(json["nodes"].is_array());
    assert!(json["edges"].is_array());
    assert_eq!(json["stats"]["node_count"], 1);
}

#[tokio::test]
async fn memory_timeline_returns_events() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/memories/m1/timeline?limit=10")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert!(json.is_array());
    assert!(!json.as_array().unwrap().is_empty());
    assert_eq!(json[0]["event_type"], "created");
}

#[tokio::test]
async fn memory_edges_add_requires_csrf() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/memories/m1/edges")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"target":"m2"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn memory_edges_add_rejects_self_loop() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/memories/m1/edges")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"target":"m1"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Tag rename/delete tests ─────────────────────────────────────────────────

#[tokio::test]
async fn tag_rename_requires_csrf() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/tags/rename")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"old":"foo","new":"bar"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn tag_rename_returns_count() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/tags/rename")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"old":"foo","new":"bar"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["renamed"], true);
    assert_eq!(json["count"], 3);
}

#[tokio::test]
async fn tag_delete_requires_csrf() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/dashboard/api/tags/foo")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn tag_delete_returns_count() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/dashboard/api/tags/foo")
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
    assert_eq!(json["count"], 3);
}

// ── Import/Export tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn export_returns_jsonl() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/export")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(ct, "application/x-ndjson");
}

#[tokio::test]
async fn import_requires_csrf() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/import")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"content":"{\"id\":\"m1\"}"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn import_returns_counts() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/import")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"content":"{\"id\":\"m1\"}"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["imported"], 1);
    assert_eq!(json["skipped"], 0);
}
