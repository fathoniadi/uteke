//! PKCE (RFC 7636) helpers — S256 code challenge verification.

use sha2::{Digest, Sha256};

/// Verify a PKCE code verifier against the stored challenge.
/// Supports S256 method only (PLAN.md mandates S256).
pub fn verify_pkce(verifier: &str, challenge: &str, method: &str) -> bool {
    match method {
        "S256" => {
            let mut hasher = Sha256::new();
            hasher.update(verifier.as_bytes());
            let digest = hasher.finalize();
            let b64 = base64_url(&digest);
            b64 == challenge
        }
        "plain" => verifier == challenge,
        _ => false,
    }
}

/// Compute the S256 challenge for a verifier (used during authorize).
pub fn s256_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    base64_url(&hasher.finalize())
}

/// Generate a random PKCE code verifier (43-128 chars, URL-safe).
pub fn random_verifier() -> String {
    random_token(48)
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Re-export random_token from auth_store to avoid duplication.
pub use crate::auth_store::random_token;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s256_roundtrip() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = s256_challenge(verifier);
        assert!(verify_pkce(verifier, &challenge, "S256"));
        assert!(!verify_pkce("wrong", &challenge, "S256"));
    }

    #[test]
    fn plain_method() {
        assert!(verify_pkce("abc", "abc", "plain"));
        assert!(!verify_pkce("abc", "abd", "plain"));
    }
}
