//! Dashboard session cookie helpers — HMAC-SHA256 signed session ID.
//!
//! Cookie format: `<session_id>.<hex_hmac>`. The session_id is the opaque
//! server-side store key; the HMAC prevents tampering.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Sign a session ID with the JWT secret. Returns `id.signature`.
pub fn sign_session_cookie(session_id: &str, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(session_id.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("{session_id}.{sig}")
}

/// Verify and extract the session ID from a signed cookie value.
/// Returns None if the signature is invalid or the format is wrong.
///
/// Uses `Hmac::verify_slice` for constant-time comparison to prevent
/// timing attacks.
pub fn verify_session_cookie(cookie_value: &str, secret: &str) -> Option<String> {
    let (id, sig) = cookie_value.split_once('.')?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(id.as_bytes());
    mac.verify_slice(&hex::decode(sig).ok()?).ok()?;
    Some(id.to_string())
}

/// Generate a new random session ID (32 bytes, URL-safe base64).
pub fn new_session_id() -> String {
    crate::auth_store::random_token(32)
}

/// Generate a new random CSRF token (32 bytes, URL-safe base64).
pub fn new_csrf_token() -> String {
    crate::auth_store::random_token(32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let secret = "a".repeat(64);
        let id = new_session_id();
        let cookie = sign_session_cookie(&id, &secret);
        let extracted = verify_session_cookie(&cookie, &secret);
        assert_eq!(extracted.as_deref(), Some(id.as_str()));
    }

    #[test]
    fn verify_rejects_tampered() {
        let secret = "a".repeat(64);
        let _cookie = sign_session_cookie("sid123", &secret);
        let tampered = "sid123.deadbeef".to_string();
        assert!(verify_session_cookie(&tampered, &secret).is_none());
        assert!(verify_session_cookie("no-dot", &secret).is_none());
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let cookie = sign_session_cookie("sid", "secret-a");
        assert!(verify_session_cookie(&cookie, "secret-b").is_none());
    }
}
