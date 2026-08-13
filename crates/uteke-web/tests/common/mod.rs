//! Shared test helpers for uteke-web integration tests.

use std::net::SocketAddr;

use uteke_web::app;
use uteke_web::audit::AuditLog;
use uteke_web::auth_store::AuthStore;
use uteke_web::config::WebConfig;
use uteke_web::state::AppState;

/// A test app with a configured router and shared state.
pub struct TestApp {
    pub router: axum::Router,
    pub state: AppState,
}

impl TestApp {
    /// Build a test app with a temp DB, valid JWT secret, and a fake upstream
    /// URL (no real upstream running — proxy tests expect 502/504).
    pub async fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("test-auth.db");
        let audit_path = dir.path().join("audit.jsonl");
        // Leak the tempdir so files survive the test.
        std::mem::forget(dir);

        let store = AuthStore::open(&db_path.to_string_lossy()).expect("open store");
        let audit = AuditLog::new(&audit_path.to_string_lossy());

        let mut config = WebConfig {
            jwt_secret: "test-secret-at-least-32-bytes-long-aaaaaa".to_string(),
            upstream: "http://127.0.0.1:59999".to_string(), // nothing listening
            upstream_token: "test-upstream-token".to_string(),
            issuer: "http://localhost:8768".to_string(),
            listen: "127.0.0.1:0".to_string(),
            ..WebConfig::default()
        };
        config.expand_paths();

        let state = AppState::new(config, store, audit);
        let router = app::build_app(state.clone());
        Self { router, state }
    }

    /// Build a test app whose upstream points at a real mock server.
    pub async fn with_upstream(upstream: SocketAddr) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("test-auth.db");
        let audit_path = dir.path().join("audit.jsonl");
        std::mem::forget(dir);

        let store = AuthStore::open(&db_path.to_string_lossy()).expect("open store");
        let audit = AuditLog::new(&audit_path.to_string_lossy());

        let mut config = WebConfig {
            jwt_secret: "test-secret-at-least-32-bytes-long-aaaaaa".to_string(),
            upstream: format!("http://{upstream}"),
            upstream_token: "test-upstream-token".to_string(),
            issuer: "http://localhost:8768".to_string(),
            listen: "127.0.0.1:0".to_string(),
            ..WebConfig::default()
        };
        config.expand_paths();

        let state = AppState::new(config, store, audit);
        let router = app::build_app(state.clone());
        Self { router, state }
    }
}

/// Spawn a mock upstream server on an ephemeral port. Returns its address.
#[allow(dead_code)] // not every test binary uses this helper
pub async fn spawn_mock_upstream() -> SocketAddr {
    use axum::Router;
    use axum::extract::State as AxumState;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::any;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct CounterState(Arc<AtomicUsize>);

    async fn handler(
        AxumState(s): AxumState<CounterState>,
        req: axum::extract::Request,
    ) -> (StatusCode, String) {
        s.0.fetch_add(1, Ordering::SeqCst);
        let method = req.method().to_string();
        let uri = req.uri().path().to_string();
        (
            StatusCode::OK,
            format!(r#"{{"method":"{method}","path":"{uri}"}}"#),
        )
    }

    async fn health_handler() -> impl IntoResponse {
        (StatusCode::OK, r#"{"status":"ok"}"#)
    }

    let counter = CounterState(Arc::new(AtomicUsize::new(0)));
    let app: Router = Router::new()
        .route("/health", any(health_handler))
        .route("/{path}", any(handler))
        .with_state(counter);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}
