//! Prometheus metrics endpoint (M9).
//!
//! Exposes basic counters via `/metrics` in Prometheus text format.

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

// ── Counters ────────────────────────────────────────────────────────────────

static TOKENS_ISSUED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static TOKENS_REFRESHED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static LOGIN_SUCCESS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static LOGIN_FAILURE: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static PROXY_REQUESTS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
static PROXY_ERRORS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

pub fn inc_tokens_issued() {
    TOKENS_ISSUED.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_tokens_refreshed() {
    TOKENS_REFRESHED.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_login_success() {
    LOGIN_SUCCESS.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_login_failure() {
    LOGIN_FAILURE.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_proxy_requests() {
    PROXY_REQUESTS.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_proxy_errors() {
    PROXY_ERRORS.fetch_add(1, Ordering::Relaxed);
}

/// Render the metrics in Prometheus text exposition format.
pub fn render() -> String {
    let mut out = String::new();
    out.push_str("# HELP uteke_web_tokens_issued_total Total access tokens issued.\n");
    out.push_str("# TYPE uteke_web_tokens_issued_total counter\n");
    out.push_str(&format!(
        "uteke_web_tokens_issued_total {}\n",
        TOKENS_ISSUED.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP uteke_web_tokens_refreshed_total Total refresh token rotations.\n");
    out.push_str("# TYPE uteke_web_tokens_refreshed_total counter\n");
    out.push_str(&format!(
        "uteke_web_tokens_refreshed_total {}\n",
        TOKENS_REFRESHED.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP uteke_web_login_success_total Total successful logins.\n");
    out.push_str("# TYPE uteke_web_login_success_total counter\n");
    out.push_str(&format!(
        "uteke_web_login_success_total {}\n",
        LOGIN_SUCCESS.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP uteke_web_login_failure_total Total failed logins.\n");
    out.push_str("# TYPE uteke_web_login_failure_total counter\n");
    out.push_str(&format!(
        "uteke_web_login_failure_total {}\n",
        LOGIN_FAILURE.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP uteke_web_proxy_requests_total Total proxied requests to upstream.\n");
    out.push_str("# TYPE uteke_web_proxy_requests_total counter\n");
    out.push_str(&format!(
        "uteke_web_proxy_requests_total {}\n",
        PROXY_REQUESTS.load(Ordering::Relaxed)
    ));
    out.push_str("# HELP uteke_web_proxy_errors_total Total proxy errors (502/504).\n");
    out.push_str("# TYPE uteke_web_proxy_errors_total counter\n");
    out.push_str(&format!(
        "uteke_web_proxy_errors_total {}\n",
        PROXY_ERRORS.load(Ordering::Relaxed)
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_contains_all_metrics() {
        let out = render();
        assert!(out.contains("uteke_web_tokens_issued_total"));
        assert!(out.contains("uteke_web_tokens_refreshed_total"));
        assert!(out.contains("uteke_web_login_success_total"));
        assert!(out.contains("uteke_web_login_failure_total"));
        assert!(out.contains("uteke_web_proxy_requests_total"));
        assert!(out.contains("uteke_web_proxy_errors_total"));
    }

    #[test]
    fn render_has_prometheus_format() {
        let out = render();
        // Each metric should have HELP and TYPE lines.
        assert!(out.contains("# HELP"));
        assert!(out.contains("# TYPE"));
        assert!(out.contains("counter"));
    }

    #[test]
    fn inc_increments_counters() {
        // Record current values.
        let before = render();
        let before_issued = extract_counter(&before, "uteke_web_tokens_issued_total");
        let before_login = extract_counter(&before, "uteke_web_login_success_total");

        inc_tokens_issued();
        inc_login_success();
        inc_login_failure();
        inc_proxy_requests();
        inc_proxy_errors();
        inc_tokens_refreshed();

        let after = render();
        let after_issued = extract_counter(&after, "uteke_web_tokens_issued_total");
        let after_login = extract_counter(&after, "uteke_web_login_success_total");

        assert_eq!(after_issued, before_issued + 1);
        assert_eq!(after_login, before_login + 1);
    }

    fn extract_counter(rendered: &str, metric: &str) -> u64 {
        for line in rendered.lines() {
            if line.starts_with(metric) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    return parts[1].parse().unwrap_or(0);
                }
            }
        }
        0
    }
}
