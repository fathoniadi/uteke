//! Audit trail — append-only JSONL logger for security events.
//!
//! Always ON (per PLAN.md). Writes one JSON object per line to the configured
//! audit log path.

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

use chrono::Utc;
use serde::Serialize;

/// Audit event record.
#[derive(Debug, Serialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub event: String,
    pub username: Option<String>,
    pub client_id: Option<String>,
    pub ip: Option<String>,
    pub detail: String,
}

/// Thread-safe audit logger writing to a JSONL file.
pub struct AuditLog {
    path: String,
    file: Mutex<Option<std::fs::File>>,
}

impl AuditLog {
    /// Create a new audit logger. The file is opened lazily on first write
    /// so construction never fails (audit must not block the request path).
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
            file: Mutex::new(None),
        }
    }

    /// Append an audit event. Errors are logged via tracing but do not
    /// propagate — audit failure must not break the request.
    pub fn log(
        &self,
        event: &str,
        username: Option<&str>,
        client_id: Option<&str>,
        ip: Option<&str>,
        detail: impl Into<String>,
    ) {
        let entry = AuditEvent {
            timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            event: event.to_string(),
            username: username.map(|s| s.to_string()),
            client_id: client_id.map(|s| s.to_string()),
            ip: ip.map(|s| s.to_string()),
            detail: detail.into(),
        };
        let line = serde_json::to_string(&entry).unwrap_or_else(|_| "{}".to_string());
        if let Err(e) = self.write_line(&line) {
            tracing::warn!("audit log write failed: {e}");
        }
    }

    fn write_line(&self, line: &str) -> std::io::Result<()> {
        let mut guard = self.file.lock().expect("audit mutex poisoned");
        if guard.is_none() {
            if let Some(parent) = std::path::Path::new(&self.path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            *guard = Some(f);
        }
        if let Some(ref mut f) = *guard {
            writeln!(f, "{line}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_jsonl() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::new(&path.to_string_lossy());
        log.log("login_success", Some("alice"), None, Some("1.2.3.4"), "ok");
        log.log(
            "login_failure",
            Some("bob"),
            None,
            Some("5.6.7.8"),
            "bad password",
        );
        let content = std::fs::read_to_string(&path).expect("read");
        assert_eq!(content.lines().count(), 2);
        assert!(content.contains("alice"));
        assert!(content.contains("login_failure"));
    }

    #[test]
    fn log_with_all_none_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit-none.jsonl");
        let log = AuditLog::new(&path.to_string_lossy());
        log.log("server_started", None, None, None, "uteke-web up");
        let content = std::fs::read_to_string(&path).expect("read");
        assert!(content.contains("server_started"));
        // Verify it's valid JSON.
        let entry: serde_json::Value = serde_json::from_str(content.trim()).expect("parse");
        assert!(entry["username"].is_null());
        assert!(entry["client_id"].is_null());
        assert!(entry["ip"].is_null());
    }

    #[test]
    fn log_creates_parent_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("nested").join("sub").join("audit.jsonl");
        let log = AuditLog::new(&nested.to_string_lossy());
        log.log("test_event", Some("alice"), None, None, "creates dirs");
        assert!(nested.exists());
    }

    #[test]
    fn log_to_invalid_path_does_not_panic() {
        // Path that cannot be created — should not panic, just log warning.
        let log = AuditLog::new("/nonexistent-root-dir/audit.jsonl");
        log.log("test", None, None, None, "should not panic");
        // If we reach here, the test passes.
    }
}
