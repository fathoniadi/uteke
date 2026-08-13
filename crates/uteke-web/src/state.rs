//! Shared application state for uteke-web.

use std::sync::Arc;

use axum::http::{HeaderMap, HeaderName, HeaderValue};

use crate::audit::AuditLog;
use crate::auth_store::AuthStore;
use crate::config::WebConfig;

/// Shared state injected into all axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<WebConfig>,
    pub store: Arc<AuthStore>,
    pub audit: Arc<AuditLog>,
    pub http_client: reqwest::Client,
}

impl AppState {
    pub fn new(config: WebConfig, store: AuthStore, audit: AuditLog) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("reqwest client");
        Self {
            config: Arc::new(config),
            store: Arc::new(store),
            audit: Arc::new(audit),
            http_client,
        }
    }

    /// Apply the static upstream token + any configured `upstream_headers`
    /// onto an outbound header map destined for uteke-server.
    ///
    /// - Removes any existing `authorization` header.
    /// - If `upstream_token` is non-empty, inserts `Authorization: Bearer <token>`.
    /// - Inserts each `upstream_headers` entry (skipping invalid header names/values).
    pub fn apply_upstream_auth(&self, headers: &mut HeaderMap) {
        headers.remove("authorization");
        if !self.config.upstream_token.is_empty() {
            if let Ok(val) =
                HeaderValue::from_str(&format!("Bearer {}", self.config.upstream_token))
            {
                headers.insert("authorization", val);
            }
        }
        for h in &self.config.upstream_headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(h.name.as_bytes()),
                HeaderValue::from_str(&h.value),
            ) {
                headers.insert(name, val);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_state(upstream_token: &str, headers: Vec<(&str, &str)>) -> AppState {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("test.db");
        let store = AuthStore::open(&db.to_string_lossy()).expect("store");
        let audit = AuditLog::new(&dir.path().join("audit.jsonl").to_string_lossy());
        let mut config = WebConfig {
            jwt_secret: "a".repeat(64),
            upstream_token: upstream_token.to_string(),
            upstream_headers: headers
                .iter()
                .map(|(n, v)| crate::config::UpstreamHeader {
                    name: n.to_string(),
                    value: v.to_string(),
                })
                .collect(),
            ..WebConfig::default()
        };
        config.expand_paths();
        std::mem::forget(dir);
        AppState::new(config, store, audit)
    }

    #[test]
    fn apply_upstream_auth_sets_bearer() {
        let state = tmp_state("tok123", vec![]);
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer old".parse().unwrap());
        state.apply_upstream_auth(&mut h);
        assert_eq!(
            h.get("authorization").unwrap().to_str().unwrap(),
            "Bearer tok123"
        );
    }

    #[test]
    fn apply_upstream_auth_no_token_clears_header() {
        let state = tmp_state("", vec![]);
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer old".parse().unwrap());
        state.apply_upstream_auth(&mut h);
        assert!(h.get("authorization").is_none());
    }

    #[test]
    fn apply_upstream_auth_adds_extra_headers() {
        let state = tmp_state(
            "tok",
            vec![("X-Source", "uteke-web"), ("X-Request-Id", "abc")],
        );
        let mut h = HeaderMap::new();
        state.apply_upstream_auth(&mut h);
        assert_eq!(h.get("x-source").unwrap().to_str().unwrap(), "uteke-web");
        assert_eq!(h.get("x-request-id").unwrap().to_str().unwrap(), "abc");
        assert_eq!(
            h.get("authorization").unwrap().to_str().unwrap(),
            "Bearer tok"
        );
    }

    #[test]
    fn apply_upstream_auth_skips_invalid_header_name() {
        let state = tmp_state("tok", vec![("invalid header\nname", "val")]);
        let mut h = HeaderMap::new();
        state.apply_upstream_auth(&mut h);
        // Bearer still set; invalid header skipped.
        assert_eq!(
            h.get("authorization").unwrap().to_str().unwrap(),
            "Bearer tok"
        );
        assert_eq!(h.len(), 1);
    }
}
