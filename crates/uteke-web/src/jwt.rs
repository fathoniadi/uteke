//! JWT (HS256) issuance and verification for OAuth2 access tokens.
//!
//! Claims: `iss`, `sub`, `aud`, `client_id`, `scope`, `iat`, `exp`, `jti`.

use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

/// JWT access token claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub client_id: String,
    pub scope: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

/// Mint a new HS256 access token.
pub fn mint_access_token(
    secret: &str,
    issuer: &str,
    username: &str,
    client_id: &str,
    scope: &str,
    ttl_seconds: i64,
) -> Result<(String, String), JwtError> {
    let now = Utc::now().timestamp();
    let jti = uuid::Uuid::new_v4().to_string();
    let claims = AccessClaims {
        iss: issuer.to_string(),
        sub: username.to_string(),
        aud: client_id.to_string(),
        client_id: client_id.to_string(),
        scope: scope.to_string(),
        iat: now,
        exp: now + ttl_seconds,
        jti: jti.clone(),
    };
    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret(secret.as_bytes());
    let token = encode(&header, &claims, &key)?;
    Ok((token, jti))
}

/// Verify an HS256 access token. Returns the claims on success.
///
/// Validates `exp` (no leeway) and `iss` (must match `expected_iss`).
/// `aud` is **not** validated — it carries the `client_id` and varies per
/// token; the resource server authorizes via `scope`, not `aud`.
pub fn verify_access_token(
    secret: &str,
    expected_iss: &str,
    token: &str,
) -> Result<AccessClaims, JwtError> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_aud = false;
    validation.leeway = 0;
    validation.required_spec_claims = ["exp".to_string()].into_iter().collect();
    validation.set_issuer(&[expected_iss]);
    let data = decode::<AccessClaims>(token, &key, &validation)?;
    Ok(data.claims)
}

/// JWT error wrapper.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_and_verify_roundtrip() {
        let secret = "a".repeat(64);
        let (token, jti) = mint_access_token(
            &secret,
            "http://issuer",
            "alice",
            "client1",
            "read write",
            3600,
        )
        .expect("mint");
        assert!(!token.is_empty());
        assert!(!jti.is_empty());
        let claims = verify_access_token(&secret, "http://issuer", &token).expect("verify");
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.client_id, "client1");
        assert_eq!(claims.scope, "read write");
        assert_eq!(claims.iss, "http://issuer");
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let secret = "a".repeat(64);
        let (token, _) =
            mint_access_token(&secret, "iss", "alice", "c", "read", 3600).expect("mint");
        assert!(verify_access_token("wrong-secret", "iss", &token).is_err());
    }

    #[test]
    fn verify_rejects_expired() {
        let secret = "a".repeat(64);
        let (token, _) =
            mint_access_token(&secret, "iss", "alice", "c", "read", -120).expect("mint");
        assert!(verify_access_token(&secret, "iss", &token).is_err());
    }

    #[test]
    fn verify_rejects_wrong_issuer() {
        let secret = "a".repeat(64);
        let (token, _) =
            mint_access_token(&secret, "http://real-issuer", "alice", "c", "read", 3600)
                .expect("mint");
        assert!(verify_access_token(&secret, "http://fake-issuer", &token).is_err());
    }
}
