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
    async fn namespaces(Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
        if q.get("with_counts").map(String::as_str) == Some("true") {
            (
                StatusCode::OK,
                r#"[{"name":"default","count":5,"active":4,"deprecated":1},{"name":"agent-a","count":2,"active":2,"deprecated":0}]"#
                    .to_string(),
            )
        } else {
            (StatusCode::OK, r#"["default","agent-a"]"#.to_string())
        }
    }
    // Echo the forwarded body back so tests can assert what the dashboard
    // actually sent upstream, with the upstream result fields merged in.
    async fn namespaces_rename(b: String) -> impl IntoResponse {
        let mut v: serde_json::Value = serde_json::from_str(&b).unwrap_or_default();
        v["moved"] = serde_json::json!(2);
        v["target_existed"] = serde_json::json!(false);
        (StatusCode::OK, v.to_string())
    }
    async fn namespaces_delete(b: String) -> impl IntoResponse {
        let mut v: serde_json::Value = serde_json::from_str(&b).unwrap_or_default();
        v["affected"] = serde_json::json!(3);
        v["empty"] = serde_json::json!(false);
        (StatusCode::OK, v.to_string())
    }
    async fn importance(_b: String) -> impl IntoResponse {
        (StatusCode::OK, r#"{"updated":42}"#.to_string())
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
        .route("/namespaces/rename", post(namespaces_rename))
        .route("/namespaces/delete", post(namespaces_delete))
        .route("/importance", post(importance))
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

// ── Recall strategy passthrough + list pagination metadata ──────────────────

/// Spawn a mock upstream whose `/recall` and `/list` handlers record the raw
/// request body and reply with fixed payloads, so tests can assert on what
/// the dashboard actually sent upstream.
async fn spawn_capturing_upstream(
    recall_resp: &'static str,
    list_resp: &'static str,
) -> (
    std::net::SocketAddr,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) {
    use axum::routing::post;
    use std::sync::{Arc, Mutex};

    let recall_seen = Arc::new(Mutex::new(Vec::new()));
    let list_seen = Arc::new(Mutex::new(Vec::new()));
    let recall_capture = recall_seen.clone();
    let list_capture = list_seen.clone();

    let app = axum::Router::new()
        .route(
            "/recall",
            post(move |b: String| {
                recall_capture.lock().unwrap().push(b);
                async move { (axum::http::StatusCode::OK, recall_resp.to_string()) }
            }),
        )
        .route(
            "/list",
            post(move |b: String| {
                list_capture.lock().unwrap().push(b);
                async move { (axum::http::StatusCode::OK, list_resp.to_string()) }
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, recall_seen, list_seen)
}

const RECALL_JSON: &str = r#"[{"result_type":"memory","score":0.5,"content":"hello world","memory_id":"m1","tags":["t1"],"memory_type":"note","importance":0.7,"pinned":false,"namespace":"default","created_at":"2026-01-01T00:00:00Z"}]"#;

#[tokio::test]
async fn semantic_mode_omits_strategy_by_default() {
    let (upstream, recall_seen, _list_seen) = spawn_capturing_upstream(RECALL_JSON, "[]").await;
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
    let bodies = recall_seen.lock().unwrap();
    assert_eq!(bodies.len(), 1);
    let body: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
    // No strategy field → upstream default applies (fusion since 0.16.0,
    // or [recall] default_strategy from uteke.toml).
    assert!(
        body.get("strategy").is_none(),
        "strategy must be omitted by default, got: {}",
        bodies[0]
    );
}

#[tokio::test]
async fn semantic_mode_passes_strategy_through() {
    let (upstream, recall_seen, _list_seen) = spawn_capturing_upstream(RECALL_JSON, "[]").await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/memories?mode=semantic&q=hello&strategy=graph&limit=20")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bodies = recall_seen.lock().unwrap();
    assert_eq!(bodies.len(), 1);
    let body: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
    assert_eq!(body["strategy"], "graph");
}

/// A richer recall response used to exercise `DashboardMemory` normalization.
const RECALL_JSON_FULL: &str = r#"[{"result_type":"memory","score":0.5,"content":"hello world","memory_id":"m1","tags":["t1","t2"],"memory_type":"note","importance":0.7,"pinned":false,"namespace":"default","created_at":"2026-01-01T00:00:00Z","source":"meeting.md","source_type":"file","metadata":{"project":"uteke"},"linked_doc_slugs":["doc/arch"],"access_count":3,"last_accessed":"2026-06-01T12:00:00Z"}]"#;

#[tokio::test]
async fn semantic_mode_sends_enrich_search_type_and_filters() {
    let (upstream, recall_seen, _list_seen) = spawn_capturing_upstream(RECALL_JSON, "[]").await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/memories?mode=semantic&q=hello&search_type=all&tags=project%3Auteke,auth&entity=api-gateway&category=architecture&min_score=0.75&strict=true&at=2026-06-01T12%3A00%3A00Z&after=2026-01-01T00%3A00%3A00Z&before=2026-12-31T23%3A59%3A59Z&limit=20")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bodies = recall_seen.lock().unwrap();
    assert_eq!(bodies.len(), 1);
    let body: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
    assert_eq!(body["search_type"], "all");
    assert_eq!(body["enrich"], true);
    assert_eq!(body["tags"], serde_json::json!(["project:uteke", "auth"]));
    assert_eq!(body["entity"], "api-gateway");
    assert_eq!(body["category"], "architecture");
    assert_eq!(body["min_score"], 0.75);
    assert_eq!(body["strict"], true);
    assert_eq!(body["at"], "2026-06-01T12:00:00Z");
    assert_eq!(body["after"], "2026-01-01T00:00:00Z");
    assert_eq!(body["before"], "2026-12-31T23:59:59Z");
}

#[tokio::test]
async fn semantic_mode_normalizes_rich_upstream_fields() {
    let (upstream, _recall_seen, _list_seen) =
        spawn_capturing_upstream(RECALL_JSON_FULL, "[]").await;
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
    assert_eq!(json["memories"][0]["id"], "m1");
    assert_eq!(json["memories"][0]["score"], 0.5);
    assert_eq!(json["memories"][0]["source"], "meeting.md");
    assert_eq!(json["memories"][0]["source_type"], "file");
    assert_eq!(json["memories"][0]["metadata"]["project"], "uteke");
    assert_eq!(json["memories"][0]["linked_doc_slugs"][0], "doc/arch");
    assert_eq!(json["memories"][0]["access_count"], 3);
    assert_eq!(
        json["memories"][0]["last_accessed"],
        "2026-06-01T12:00:00+00:00"
    );
    assert_eq!(json["memories"][0]["result_type"], "memory");
}

#[tokio::test]
async fn semantic_mode_treats_document_results_as_documents() {
    const DOC_JSON: &str = r#"[{"result_type":"document","score":0.6,"content":"Doc excerpt","doc_slug":"doc/arch","doc_title":"Architecture","tags":["docs"],"created_at":"2026-01-01T00:00:00Z"}]"#;
    let (upstream, _recall_seen, _list_seen) = spawn_capturing_upstream(DOC_JSON, "[]").await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/memories?mode=semantic&q=hello&search_type=doc&limit=20")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["memories"][0]["id"], "doc/arch");
    assert_eq!(json["memories"][0]["memory_type"], "document");
    assert_eq!(json["memories"][0]["result_type"], "document");
}

#[tokio::test]
async fn list_mode_reads_has_more_from_include_meta_envelope() {
    // One memory in the page (less than limit=20) but has_more=true —
    // the old page-length heuristic would have reported has_more=false.
    let list_resp: &'static str = r#"{"memories":[],"total":5,"has_more":true,"next_offset":40}"#;
    let (upstream, _recall_seen, list_seen) =
        spawn_capturing_upstream(RECALL_JSON, list_resp).await;
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
    assert_eq!(json["has_more"], true);

    // The dashboard must have requested the metadata envelope (#1188).
    let bodies = list_seen.lock().unwrap();
    assert_eq!(bodies.len(), 1);
    let body: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
    assert_eq!(body["include_meta"], true);
}

#[tokio::test]
async fn list_mode_falls_back_to_bare_array_from_older_upstream() {
    // Older uteke-server (< 0.17) ignores include_meta and returns a bare
    // array — has_more falls back to the page-length heuristic.
    let list_resp: &'static str = r#"[{"id":"m1","content":"hello world","tags":["t1","t2"],"metadata":{},"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","namespace":"default","memory_type":"note","importance":0.7,"pinned":true}]"#;
    let (upstream, _recall_seen, _list_seen) =
        spawn_capturing_upstream(RECALL_JSON, list_resp).await;
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
    assert_eq!(json["memories"][0]["id"], "m1");
    assert_eq!(json["has_more"], false);
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

// ── Namespace management tests (#1181) ──────────────────────────────────────

#[tokio::test]
async fn namespaces_counts_mode_returns_enriched_rows() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/namespaces?counts=true")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert!(json.is_array());
    assert_eq!(json[0]["name"], "default");
    assert_eq!(json[0]["count"], 5);
    assert_eq!(json[0]["active"], 4);
    assert_eq!(json[0]["deprecated"], 1);
}

#[tokio::test]
async fn namespace_rename_requires_csrf() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/namespaces/rename")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"from":"old","to":"new"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn namespace_rename_forwards_body_and_returns_result() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/namespaces/rename")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"from":"old","to":"new"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    // Echoed back by the mock — proves the dashboard forwarded {from, to}.
    assert_eq!(json["from"], "old");
    assert_eq!(json["to"], "new");
    // Upstream result fields.
    assert_eq!(json["moved"], 2);
    assert_eq!(json["target_existed"], false);
}

#[tokio::test]
async fn namespace_rename_rejects_empty_fields() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    for body in [
        r#"{"from":"","to":"new"}"#,
        r#"{"from":"old","to":""}"#,
        r#"{"from":"same","to":"same"}"#,
    ] {
        let resp = app
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/dashboard/api/namespaces/rename")
                    .header("cookie", &cookie)
                    .header("x-csrf-token", &csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "body: {body}");
    }
}

#[tokio::test]
async fn namespace_delete_requires_csrf() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/dashboard/api/namespaces/old?strategy=deprecate")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn namespace_delete_forwards_strategy_and_target() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/dashboard/api/namespaces/old?strategy=merge&target=archive")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    // Echoed back by the mock — proves name/strategy/target were forwarded.
    assert_eq!(json["name"], "old");
    assert_eq!(json["strategy"], "merge");
    assert_eq!(json["target"], "archive");
    assert_eq!(json["affected"], 3);
}

#[tokio::test]
async fn namespace_delete_defaults_to_refuse() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/dashboard/api/namespaces/old")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["name"], "old");
    assert_eq!(json["strategy"], "refuse");
}

#[tokio::test]
async fn namespace_delete_merge_requires_target() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/dashboard/api/namespaces/old?strategy=merge")
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
async fn namespace_delete_rejects_unknown_strategy() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri("/dashboard/api/namespaces/old?strategy=purge")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Importance recompute tests ──────────────────────────────────────────────

#[tokio::test]
async fn importance_recompute_requires_csrf() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, _csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/importance")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn importance_recompute_returns_updated_count() {
    let upstream = spawn_typed_upstream().await;
    let app = TestApp::with_upstream(upstream).await;
    let (cookie, csrf) = make_session(&app, "alice");
    let resp = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/dashboard/api/importance")
                .header("cookie", &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = read_json(resp).await;
    assert_eq!(json["updated"], 42);
}
