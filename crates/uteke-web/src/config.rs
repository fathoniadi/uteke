//! Configuration for uteke-web.
//!
//! Reads the `[web]` section from the same `uteke.toml` used by other uteke
//! crates. Layered resolution: defaults → `{uteke_home}/uteke.toml` →
//! `.uteke/uteke.toml` → env vars.
//!
//! Only the `[web]` section is consumed here; the rest of `uteke.toml` is
//! owned by uteke-core/uteke-cli/uteke-server and is left untouched.

use std::path::PathBuf;

// ── Config sections ─────────────────────────────────────────────────────────

/// `[web]` section — top-level uteke-web configuration.
#[derive(serde::Deserialize, Clone)]
#[serde(default)]
pub struct WebConfig {
    /// Bind address, e.g. "127.0.0.1:8768".
    pub listen: String,
    /// Issuer URL — base URL for OAuth2 endpoints (must be reachable by clients).
    pub issuer: String,
    /// Upstream uteke-server URL to reverse-proxy to.
    pub upstream: String,
    /// Static token injected as `Authorization: Bearer <token>` to upstream.
    /// Env: UTEKE_WEB_UPSTREAM_TOKEN
    pub upstream_token: String,
    /// JWT signing secret (HS256). Env: UTEKE_WEB_JWT_SECRET
    pub jwt_secret: String,
    /// SQLite DB path for the auth store.
    ///
    /// Default resolves via `uteke_core::uteke_home()` (UTEKE_HOME env >
    /// ~/.codecora/uteke) so an isolated UTEKE_HOME never silently writes
    /// to the real auth store — the same canonical resolver the CLI and
    /// MCP use for the memory store. An explicit `db_path` in uteke.toml
    /// still wins.
    pub db_path: String,
    /// Audit trail JSONL path (always ON).
    ///
    /// Default follows `db_path`'s uteke_home resolution (see above).
    pub audit_log_path: String,
    /// Extra headers injected into every upstream (uteke-server) request,
    /// in addition to the static `Authorization: Bearer <upstream_token>`.
    ///
    /// TOML format:
    /// ```toml
    /// [[web.upstream_headers]]
    /// name = "X-Internal-Source"
    /// value = "uteke-web"
    /// ```
    pub upstream_headers: Vec<UpstreamHeader>,
    /// List of trusted reverse-proxy IPs allowed to set `X-Forwarded-For`.
    /// If empty, XFF is ignored and the client IP falls back to "unknown"
    /// (rate limiting uses connection peer IP when available).
    /// Env: not overridable (set in TOML).
    ///
    /// TOML format:
    /// ```toml
    /// trusted_proxies = ["127.0.0.1", "10.0.0.1"]
    /// ```
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Directory for daily-rotated log files. Empty = no file logging
    /// (stdout only). Env: UTEKE_WEB_LOG_DIR
    ///
    /// Files are named `uteke-web.log.YYYY-MM-DD` and rotated daily at
    /// midnight (local time). Old files are **not** auto-deleted —
    /// configure external log rotation (logrotate, etc.) if needed.
    ///
    /// TOML format:
    /// ```toml
    /// log_dir = "~/.codecora/uteke/logs"
    /// ```
    #[serde(default)]
    pub log_dir: String,
    /// Log level for both console and file. Env: UTEKE_WEB_LOG_LEVEL
    /// Default: "info". Options: "error", "warn", "info", "debug", "trace".
    #[serde(default)]
    pub log_level: String,
    /// Dashboard sub-section.
    pub dashboard: DashboardConfig,
    /// TLS sub-section (optional standalone TLS).
    pub tls: TlsConfig,
    /// CORS sub-section (optional).
    pub cors: CorsConfig,
}

/// A single extra header to inject into upstream requests.
#[derive(serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpstreamHeader {
    /// Header name (case-insensitive per HTTP spec; stored as-is).
    pub name: String,
    /// Header value.
    pub value: String,
}

impl Default for WebConfig {
    fn default() -> Self {
        // Auth store + audit log live beside the memory store, resolved via
        // the canonical uteke_home() (UTEKE_HOME env > ~/.codecora/uteke) —
        // NOT a hardcoded tilde path. A hardcoded default silently ignored
        // UTEKE_HOME and wrote to the real auth store even when the operator
        // pointed every other uteke binary at an isolated home (found during
        // a smoke test: `uteke-web user add` created a user in the real DB).
        // Fallback keeps the literal tilde path (expand_tilde resolves it)
        // when the home directory cannot be determined at all.
        let home_defaults = uteke_core::uteke_home().ok().map(|h| {
            (
                h.join("uteke-web.db").to_string_lossy().into_owned(),
                h.join("uteke-web-audit.jsonl")
                    .to_string_lossy()
                    .into_owned(),
            )
        });
        let (db_path, audit_log_path) = home_defaults.unwrap_or_else(|| {
            (
                "~/.codecora/uteke/uteke-web.db".to_string(),
                "~/.codecora/uteke/uteke-web-audit.jsonl".to_string(),
            )
        });
        Self {
            listen: "127.0.0.1:8768".to_string(),
            issuer: "http://localhost:8768".to_string(),
            upstream: "http://127.0.0.1:8767".to_string(),
            upstream_token: String::new(),
            jwt_secret: String::new(),
            db_path,
            audit_log_path,
            upstream_headers: Vec::new(),
            trusted_proxies: Vec::new(),
            log_dir: String::new(),
            log_level: "info".to_string(),
            dashboard: DashboardConfig::default(),
            tls: TlsConfig::default(),
            cors: CorsConfig::default(),
        }
    }
}

/// `[web.dashboard]` sub-section.
#[derive(serde::Deserialize, Clone)]
#[serde(default)]
pub struct DashboardConfig {
    /// Enable the dashboard web UI.
    pub enabled: bool,
    /// Session TTL in hours.
    pub session_ttl_hours: u64,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            session_ttl_hours: 24,
        }
    }
}

/// `[web.tls]` sub-section (optional).
#[derive(serde::Deserialize, Clone, Default)]
#[serde(default)]
pub struct TlsConfig {
    /// Path to cert PEM (optional).
    pub cert: String,
    /// Path to key PEM (optional).
    pub key: String,
}

impl TlsConfig {
    /// True if both cert and key are set.
    #[allow(dead_code)]
    pub fn is_configured(&self) -> bool {
        !self.cert.is_empty() && !self.key.is_empty()
    }
}

/// `[web.cors]` sub-section — CORS policy for browser-facing endpoints.
///
/// TOML format:
/// ```toml
/// [web.cors]
/// enabled = true
/// allow_origins = ["https://app.example.com"]
/// allow_methods = ["GET", "POST", "PUT", "DELETE"]
/// allow_headers = ["Authorization", "Content-Type"]
/// allow_credentials = true
/// max_age_secs = 3600
/// ```
#[derive(serde::Deserialize, Clone)]
#[serde(default)]
pub struct CorsConfig {
    /// Enable CORS. Default: false (backward compatible).
    pub enabled: bool,
    /// Allowed origins. `["*"]` = any origin (credentials must be false
    /// when using wildcard). Default: `["*"]`.
    pub allow_origins: Vec<String>,
    /// Allowed methods. Default: GET, POST, PUT, PATCH, DELETE, OPTIONS.
    pub allow_methods: Vec<String>,
    /// Allowed request headers. Default: Authorization, Content-Type,
    /// X-CSRF-Token.
    pub allow_headers: Vec<String>,
    /// Allow cookies/credentials. Default: false.
    /// Must be false when allow_origins contains "*".
    pub allow_credentials: bool,
    /// Preflight cache max-age in seconds. Default: 3600.
    pub max_age_secs: u64,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_origins: vec!["*".to_string()],
            allow_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "PATCH".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
            ],
            allow_headers: vec![
                "Authorization".to_string(),
                "Content-Type".to_string(),
                "X-CSRF-Token".to_string(),
            ],
            allow_credentials: false,
            max_age_secs: 3600,
        }
    }
}

// ── Loading ─────────────────────────────────────────────────────────────────

impl WebConfig {
    /// Load the `[web]` section with layered resolution:
    /// 1. Defaults
    /// 2. Global `{uteke_home}/uteke.toml`
    /// 3. Project `.uteke/uteke.toml`
    /// 4. Environment variables (highest priority)
    pub fn load() -> Self {
        let mut config = Self::default();

        // Layer 1: global config at uteke_home
        if let Some(global_path) = global_config_path() {
            config = config.merge_from_file(&global_path);
        }

        // Layer 2: project .uteke/uteke.toml
        if let Ok(cwd) = std::env::current_dir() {
            let project_path = cwd.join(".uteke").join("uteke.toml");
            config = config.merge_from_file(&project_path);
        }

        // Layer 3: environment variables
        config = config.apply_env_overrides();

        config
    }

    /// Merge `[web]` values from a TOML file on top of this config.
    /// Only keys explicitly present override existing values.
    fn merge_from_file(mut self, path: &std::path::Path) -> Self {
        if !path.exists() {
            return self;
        }
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Cannot read config {}: {e}", path.display());
                return self;
            }
        };
        let raw: toml::Value = match toml::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("Invalid config {}: {e}", path.display());
                return self;
            }
        };
        let web_table = match raw.get("web").and_then(|v| v.as_table()) {
            Some(t) => t,
            None => return self,
        };
        let overlay: WebConfig = match toml::from_str(
            &toml::to_string(&toml::Value::Table(web_table.clone())).unwrap_or_default(),
        ) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Invalid [web] section in {}: {e}", path.display());
                return self;
            }
        };

        if web_table.contains_key("listen") {
            self.listen = overlay.listen.clone();
        }
        if web_table.contains_key("issuer") {
            self.issuer = overlay.issuer.clone();
        }
        if web_table.contains_key("upstream") {
            self.upstream = overlay.upstream.clone();
        }
        if web_table.contains_key("upstream_token") {
            self.upstream_token = overlay.upstream_token.clone();
        }
        if web_table.contains_key("jwt_secret") {
            self.jwt_secret = overlay.jwt_secret.clone();
        }
        if web_table.contains_key("db_path") {
            self.db_path = overlay.db_path.clone();
        }
        if web_table.contains_key("audit_log_path") {
            self.audit_log_path = overlay.audit_log_path.clone();
        }
        if web_table.contains_key("upstream_headers") {
            self.upstream_headers = overlay.upstream_headers.clone();
        }
        if web_table.contains_key("trusted_proxies") {
            self.trusted_proxies = overlay.trusted_proxies.clone();
        }
        if web_table.contains_key("log_dir") {
            self.log_dir = overlay.log_dir.clone();
        }
        if web_table.contains_key("log_level") {
            self.log_level = overlay.log_level.clone();
        }
        if let Some(dash) = web_table.get("dashboard").and_then(|v| v.as_table()) {
            if dash.contains_key("enabled") {
                self.dashboard.enabled = overlay.dashboard.enabled;
            }
            if dash.contains_key("session_ttl_hours") {
                self.dashboard.session_ttl_hours = overlay.dashboard.session_ttl_hours;
            }
        }
        if let Some(tls) = web_table.get("tls").and_then(|v| v.as_table()) {
            if tls.contains_key("cert") {
                self.tls.cert = overlay.tls.cert.clone();
            }
            if tls.contains_key("key") {
                self.tls.key = overlay.tls.key.clone();
            }
        }
        if let Some(cors) = web_table.get("cors").and_then(|v| v.as_table()) {
            if cors.contains_key("enabled") {
                self.cors.enabled = overlay.cors.enabled;
            }
            if cors.contains_key("allow_origins") {
                self.cors.allow_origins = overlay.cors.allow_origins.clone();
            }
            if cors.contains_key("allow_methods") {
                self.cors.allow_methods = overlay.cors.allow_methods.clone();
            }
            if cors.contains_key("allow_headers") {
                self.cors.allow_headers = overlay.cors.allow_headers.clone();
            }
            if cors.contains_key("allow_credentials") {
                self.cors.allow_credentials = overlay.cors.allow_credentials;
            }
            if cors.contains_key("max_age_secs") {
                self.cors.max_age_secs = overlay.cors.max_age_secs;
            }
        }
        self
    }

    /// Apply environment variable overrides for secrets.
    fn apply_env_overrides(mut self) -> Self {
        if let Ok(v) = std::env::var("UTEKE_WEB_JWT_SECRET") {
            if !v.is_empty() {
                self.jwt_secret = v;
            }
        }
        if let Ok(v) = std::env::var("UTEKE_WEB_UPSTREAM_TOKEN") {
            if !v.is_empty() {
                self.upstream_token = v;
            }
        }
        if let Ok(v) = std::env::var("UTEKE_WEB_LOG_DIR") {
            if !v.is_empty() {
                self.log_dir = v;
            }
        }
        if let Ok(v) = std::env::var("UTEKE_WEB_LOG_LEVEL") {
            if !v.is_empty() {
                self.log_level = v;
            }
        }
        self
    }

    /// Expand `~` in path fields to the user's home directory.
    pub fn expand_paths(&mut self) {
        self.db_path = expand_tilde(&self.db_path);
        self.audit_log_path = expand_tilde(&self.audit_log_path);
        self.log_dir = expand_tilde(&self.log_dir);
        self.tls.cert = expand_tilde(&self.tls.cert);
        self.tls.key = expand_tilde(&self.tls.key);
    }

    /// Validate required fields. Returns an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.jwt_secret.is_empty() {
            return Err(
                "web.jwt_secret is empty. Set it in uteke.toml [web] or UTEKE_WEB_JWT_SECRET env var."
                    .to_string(),
            );
        }
        if self.jwt_secret.len() < 32 {
            return Err("web.jwt_secret must be at least 32 bytes for HS256 security.".to_string());
        }
        if self.upstream.is_empty() {
            return Err("web.upstream must be set (uteke-server URL).".to_string());
        }
        if self.issuer.is_empty() {
            return Err("web.issuer must be set (base URL for OAuth2).".to_string());
        }
        Ok(())
    }
}

/// Expand a leading `~` to the home directory.
pub fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest).to_string_lossy().to_string();
        }
    }
    path.to_string()
}

/// Return the global config path `{uteke_home}/uteke.toml`.
fn global_config_path() -> Option<PathBuf> {
    uteke_core::uteke_home().ok().map(|h| h.join("uteke.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let c = WebConfig::default();
        assert!(!c.listen.is_empty());
        assert!(c.dashboard.enabled);
        assert_eq!(c.dashboard.session_ttl_hours, 24);
    }

    #[test]
    fn env_override_jwt_secret() {
        unsafe {
            std::env::set_var("UTEKE_WEB_JWT_SECRET", "a".repeat(64));
            std::env::set_var("UTEKE_WEB_UPSTREAM_TOKEN", "tok");
        }
        let c = WebConfig::load();
        assert_eq!(c.jwt_secret, "a".repeat(64));
        assert_eq!(c.upstream_token, "tok");
        unsafe {
            std::env::remove_var("UTEKE_WEB_JWT_SECRET");
            std::env::remove_var("UTEKE_WEB_UPSTREAM_TOKEN");
        }
    }

    /// UTEKE_HOME must redirect the default auth-store DB and audit log —
    /// a hardcoded tilde default silently wrote to the real auth store even
    /// with an isolated home (regression test for the smoke-test incident).
    #[test]
    fn uteke_home_redirects_default_db_paths() {
        unsafe {
            std::env::set_var("UTEKE_HOME", "/tmp/uteke-web-iso-home");
        }
        let c = WebConfig::default();
        assert_eq!(
            c.db_path, "/tmp/uteke-web-iso-home/uteke-web.db",
            "db_path must follow UTEKE_HOME"
        );
        assert_eq!(
            c.audit_log_path, "/tmp/uteke-web-iso-home/uteke-web-audit.jsonl",
            "audit_log_path must follow UTEKE_HOME"
        );
        unsafe {
            std::env::remove_var("UTEKE_HOME");
        }
    }

    #[test]
    fn validate_rejects_short_secret() {
        let c = WebConfig {
            jwt_secret: "short".to_string(),
            ..WebConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_accepts_long_secret() {
        let c = WebConfig {
            jwt_secret: "a".repeat(64),
            ..WebConfig::default()
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn expand_tilde_works() {
        let p = expand_tilde("~/foo");
        assert!(!p.starts_with('~'));
        assert!(p.ends_with("/foo"));
        assert_eq!(expand_tilde("/abs/path"), "/abs/path");
    }

    #[test]
    fn merge_from_file_overrides_present_keys() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg_path = dir.path().join("uteke.toml");
        let mut f = std::fs::File::create(&cfg_path).expect("create");
        writeln!(
            f,
            r#"[web]
listen = "0.0.0.0:9999"
issuer = "http://example.com"
upstream = "http://upstream.example.com"
jwt_secret = "this-is-a-very-long-secret-aaaaaa"
upstream_token = "tok123"
db_path = "/tmp/test.db"
audit_log_path = "/tmp/test-audit.jsonl"

[web.dashboard]
enabled = false
session_ttl_hours = 48

[web.tls]
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"

[[web.upstream_headers]]
name = "X-Custom"
value = "custom-value"
"#
        )
        .expect("write");

        let base = WebConfig::default();
        let merged = base.merge_from_file(&cfg_path);
        assert_eq!(merged.listen, "0.0.0.0:9999");
        assert_eq!(merged.issuer, "http://example.com");
        assert_eq!(merged.upstream, "http://upstream.example.com");
        assert_eq!(merged.jwt_secret, "this-is-a-very-long-secret-aaaaaa");
        assert_eq!(merged.upstream_token, "tok123");
        assert_eq!(merged.db_path, "/tmp/test.db");
        assert_eq!(merged.audit_log_path, "/tmp/test-audit.jsonl");
        assert!(!merged.dashboard.enabled);
        assert_eq!(merged.dashboard.session_ttl_hours, 48);
        assert_eq!(merged.tls.cert, "/tmp/cert.pem");
        assert_eq!(merged.tls.key, "/tmp/key.pem");
        assert_eq!(merged.upstream_headers.len(), 1);
        assert_eq!(merged.upstream_headers[0].name, "X-Custom");
        assert_eq!(merged.upstream_headers[0].value, "custom-value");
    }

    #[test]
    fn merge_from_file_nonexistent_returns_default() {
        let base = WebConfig::default();
        let merged = base.merge_from_file(std::path::Path::new("/nonexistent/path.toml"));
        assert_eq!(merged.listen, WebConfig::default().listen);
    }

    #[test]
    fn merge_from_file_invalid_toml_returns_default() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg_path = dir.path().join("bad.toml");
        let mut f = std::fs::File::create(&cfg_path).expect("create");
        writeln!(f, "this is not valid toml = = =").expect("write");
        let base = WebConfig::default();
        let merged = base.merge_from_file(&cfg_path);
        assert_eq!(merged.listen, WebConfig::default().listen);
    }

    #[test]
    fn merge_from_file_without_web_section_returns_default() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg_path = dir.path().join("no-web.toml");
        let mut f = std::fs::File::create(&cfg_path).expect("create");
        writeln!(f, "[other]\nkey = \"value\"").expect("write");
        let base = WebConfig::default();
        let merged = base.merge_from_file(&cfg_path);
        assert_eq!(merged.listen, WebConfig::default().listen);
    }

    #[test]
    fn validate_rejects_empty_upstream() {
        let c = WebConfig {
            jwt_secret: "a".repeat(64),
            upstream: String::new(),
            ..WebConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_issuer() {
        let c = WebConfig {
            jwt_secret: "a".repeat(64),
            issuer: String::new(),
            ..WebConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_jwt_secret() {
        let c = WebConfig {
            jwt_secret: String::new(),
            ..WebConfig::default()
        };
        let err = c.validate().unwrap_err();
        assert!(err.contains("jwt_secret"));
    }

    #[test]
    fn tls_is_configured_when_both_set() {
        let tls = crate::config::TlsConfig {
            cert: "/tmp/c.pem".to_string(),
            key: "/tmp/k.pem".to_string(),
        };
        assert!(tls.is_configured());
        assert!(!crate::config::TlsConfig::default().is_configured());
    }

    #[test]
    fn expand_paths_expands_tilde() {
        let mut c = WebConfig {
            db_path: "~/test-db.db".to_string(),
            audit_log_path: "~/test-audit.jsonl".to_string(),
            tls: crate::config::TlsConfig {
                cert: "~/cert.pem".to_string(),
                key: "~/key.pem".to_string(),
            },
            ..WebConfig::default()
        };
        c.expand_paths();
        assert!(!c.db_path.starts_with('~'));
        assert!(!c.audit_log_path.starts_with('~'));
        assert!(!c.tls.cert.starts_with('~'));
        assert!(!c.tls.key.starts_with('~'));
    }
}
