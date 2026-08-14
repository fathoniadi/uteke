//! Auth store — SQLite-backed persistence for OAuth2 clients, users,
//! authorization codes, refresh tokens, and dashboard sessions.
//!
//! All secrets are hashed before storage:
//! - `client_secret`, `password_hash` → bcrypt
//! - `auth_codes.code_hash`, `refresh_tokens.token_hash` → SHA-256
//! - `sessions.session_id` → opaque random (cookie is HMAC-signed separately)

use std::sync::Mutex;

use bcrypt::{BcryptError, DEFAULT_COST, hash as bcrypt_hash, verify as bcrypt_verify};
use chrono::Utc;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::expand_tilde;

/// Schema SQL embedded at compile time.
const SCHEMA_V1: &str = include_str!("../schema/v1.sql");

/// Current schema version.
const CURRENT_VERSION: i64 = 1;

// ── Errors ──────────────────────────────────────────────────────────────────

/// Auth store error.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("bcrypt error: {0}")]
    Bcrypt(#[from] BcryptError),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("locked: account is locked, contact admin")]
    Locked,
}

// ── Types ───────────────────────────────────────────────────────────────────

/// OAuth2 client record.
#[derive(Debug, Clone)]
pub struct Client {
    pub id: String,
    pub client_id: String,
    pub client_secret: String, // bcrypt hash
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub grants: Vec<String>,
    pub public: bool,
    pub dynamic: bool,
    pub created_at: String,
}

/// Dashboard user record.
#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub created_at: String,
    pub locked: bool,
    pub failed_attempts: i64,
}

/// Authorization code record (looked up by hash).
#[derive(Debug, Clone)]
pub struct AuthCode {
    pub client_id: String,
    pub username: String,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub expires_at: String,
    pub used: bool,
}

/// Refresh token record (looked up by hash).
#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub client_id: String,
    pub username: String,
    pub scope: String,
    pub expires_at: String,
    pub used: bool,
}

/// Refresh token info for the settings page (admin view).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RefreshTokenInfo {
    pub token_hash: String,
    pub client_id: String,
    pub username: String,
    pub scope: String,
    pub created_at: String,
    pub expires_at: String,
}

/// Session record.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Session {
    pub session_id: String,
    pub username: String,
    pub csrf_token: String,
    pub created_at: String,
    pub expires_at: String,
}

// ── Store ───────────────────────────────────────────────────────────────────

/// Thread-safe auth store backed by SQLite.
pub struct AuthStore {
    conn: Mutex<Connection>,
}

impl AuthStore {
    /// Open (or create) the auth store at `db_path`, running migrations if needed.
    pub fn open(db_path: &str) -> Result<Self, AuthError> {
        let path = expand_tilde(db_path);
        if let Some(parent) = std::path::Path::new(&path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AuthError::Invalid(format!("cannot create db dir {}: {e}", parent.display()))
            })?;
        }
        let conn = Connection::open(&path)?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    /// Run schema migrations up to CURRENT_VERSION.
    fn migrate(&self) -> Result<(), AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let current: Option<i64> = conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
            .ok()
            .flatten();
        if current.unwrap_or(0) < CURRENT_VERSION {
            conn.execute_batch(SCHEMA_V1)?;
            // Ensure version row exists (schema SQL inserts v1).
            tracing::info!("uteke-web auth store migrated to v{CURRENT_VERSION}");
        }
        Ok(())
    }

    // ── Clients ──────────────────────────────────────────────────────────────

    /// Insert a new client. Returns the stored Client.
    #[allow(clippy::too_many_arguments)]
    pub fn add_client(
        &self,
        client_id: &str,
        client_secret: &str,
        redirect_uris: Vec<String>,
        scopes: Vec<String>,
        public: bool,
        dynamic: bool,
    ) -> Result<Client, AuthError> {
        let secret_hash = if public {
            String::new()
        } else {
            bcrypt_hash(client_secret, DEFAULT_COST)?
        };
        let id = Uuid::new_v4().to_string();
        let redirect_json = serde_json::to_string(&redirect_uris).unwrap_or_else(|_| "[]".into());
        let scopes_json = serde_json::to_string(&scopes).unwrap_or_else(|_| "[]".into());
        let grants_json = serde_json::to_string(&["authorization_code", "refresh_token"])
            .unwrap_or_else(|_| "[]".into());
        {
            let conn = self.conn.lock().expect("auth store mutex poisoned");
            // Check uniqueness
            let exists: bool = conn
                .query_row(
                    "SELECT 1 FROM clients WHERE client_id = ?1",
                    rusqlite::params![client_id],
                    |_| Ok(true),
                )
                .unwrap_or(false);
            if exists {
                return Err(AuthError::AlreadyExists(format!("client_id '{client_id}'")));
            }
            conn.execute(
                "INSERT INTO clients (id, client_id, client_secret, redirect_uris, scopes, grants, public, dynamic)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    id,
                    client_id,
                    secret_hash,
                    redirect_json,
                    scopes_json,
                    grants_json,
                    public as i64,
                    dynamic as i64,
                ],
            )?;
        } // lock released here
        self.get_client_by_id(client_id)
            .ok_or_else(|| AuthError::NotFound("client just inserted".into()))
    }

    /// Look up a client by its public `client_id`.
    pub fn get_client_by_id(&self, client_id: &str) -> Option<Client> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        conn.query_row(
            "SELECT id, client_id, client_secret, redirect_uris, scopes, grants, public, dynamic, created_at
             FROM clients WHERE client_id = ?1",
            rusqlite::params![client_id],
            row_to_client,
        )
        .ok()
    }

    /// List all clients.
    pub fn list_clients(&self) -> Result<Vec<Client>, AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, client_id, client_secret, redirect_uris, scopes, grants, public, dynamic, created_at
             FROM clients ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], row_to_client)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Delete a client by row ID (UUID) or client_id.
    pub fn delete_client(&self, id_or_client_id: &str) -> Result<usize, AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let n = conn.execute(
            "DELETE FROM clients WHERE id = ?1 OR client_id = ?1",
            rusqlite::params![id_or_client_id],
        )?;
        Ok(n)
    }

    /// Verify a client's secret.
    pub fn verify_client_secret(client: &Client, secret: &str) -> bool {
        if client.public {
            return secret.is_empty();
        }
        bcrypt_verify(secret, &client.client_secret).unwrap_or(false)
    }

    // ── Users ────────────────────────────────────────────────────────────────

    /// Create a new user.
    pub fn add_user(&self, username: &str, password: &str) -> Result<User, AuthError> {
        let id = Uuid::new_v4().to_string();
        let hash = bcrypt_hash(password, DEFAULT_COST)?;
        {
            let conn = self.conn.lock().expect("auth store mutex poisoned");
            let exists: bool = conn
                .query_row(
                    "SELECT 1 FROM users WHERE username = ?1",
                    rusqlite::params![username],
                    |_| Ok(true),
                )
                .unwrap_or(false);
            if exists {
                return Err(AuthError::AlreadyExists(format!("username '{username}'")));
            }
            conn.execute(
                "INSERT INTO users (id, username, password_hash) VALUES (?1, ?2, ?3)",
                rusqlite::params![id, username, hash],
            )?;
        } // lock released here
        self.get_user(username)
            .ok_or_else(|| AuthError::NotFound("user just inserted".into()))
    }

    /// Look up a user by username.
    pub fn get_user(&self, username: &str) -> Option<User> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        conn.query_row(
            "SELECT id, username, password_hash, created_at, locked, failed_attempts
             FROM users WHERE username = ?1",
            rusqlite::params![username],
            row_to_user,
        )
        .ok()
    }

    /// Look up a user by row ID or username.
    #[allow(dead_code)]
    pub fn get_user_by_id_or_name(&self, id_or_name: &str) -> Option<User> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        conn.query_row(
            "SELECT id, username, password_hash, created_at, locked, failed_attempts
             FROM users WHERE id = ?1 OR username = ?1",
            rusqlite::params![id_or_name],
            row_to_user,
        )
        .ok()
    }

    /// List all users.
    pub fn list_users(&self) -> Result<Vec<User>, AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, username, password_hash, created_at, locked, failed_attempts
             FROM users ORDER BY created_at",
        )?;
        let rows = stmt.query_map([], row_to_user)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Delete a user by row ID or username.
    pub fn delete_user(&self, id_or_name: &str) -> Result<usize, AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let n = conn.execute(
            "DELETE FROM users WHERE id = ?1 OR username = ?1",
            rusqlite::params![id_or_name],
        )?;
        Ok(n)
    }

    /// Change a user's password.
    pub fn change_password(&self, id_or_name: &str, new_password: &str) -> Result<(), AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let hash = bcrypt_hash(new_password, DEFAULT_COST)?;
        let n = conn.execute(
            "UPDATE users SET password_hash = ?2 WHERE id = ?1 OR username = ?1",
            rusqlite::params![id_or_name, hash],
        )?;
        if n == 0 {
            return Err(AuthError::NotFound(id_or_name.to_string()));
        }
        Ok(())
    }

    /// Unlock a user (reset failed_attempts + locked flag).
    pub fn unlock_user(&self, id_or_name: &str) -> Result<(), AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let n = conn.execute(
            "UPDATE users SET locked = 0, failed_attempts = 0 WHERE id = ?1 OR username = ?1",
            rusqlite::params![id_or_name],
        )?;
        if n == 0 {
            return Err(AuthError::NotFound(id_or_name.to_string()));
        }
        Ok(())
    }

    /// Verify user credentials. On success returns the user. On failure,
    /// increments `failed_attempts` and locks if threshold reached.
    pub fn verify_user(&self, username: &str, password: &str) -> Result<User, AuthError> {
        let user = self
            .get_user(username)
            .ok_or(AuthError::NotFound("invalid username or password".into()))?;
        if user.locked {
            return Err(AuthError::Locked);
        }
        if bcrypt_verify(password, &user.password_hash).unwrap_or(false) {
            // Reset failed attempts on success.
            self.reset_failed_attempts(&user.id)?;
            Ok(user)
        } else {
            self.record_failed_login(&user.id)?;
            Err(AuthError::Invalid("invalid username or password".into()))
        }
    }

    fn reset_failed_attempts(&self, user_id: &str) -> Result<(), AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        conn.execute(
            "UPDATE users SET failed_attempts = 0 WHERE id = ?1",
            rusqlite::params![user_id],
        )?;
        Ok(())
    }

    fn record_failed_login(&self, user_id: &str) -> Result<(), AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        conn.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?1",
            rusqlite::params![user_id],
        )?;
        // Lock after 10 cumulative failures.
        conn.execute(
            "UPDATE users SET locked = 1 WHERE id = ?1 AND failed_attempts >= 10",
            rusqlite::params![user_id],
        )?;
        Ok(())
    }

    // ── Login attempts (rate limit) ──────────────────────────────────────────

    /// Record a login attempt.
    pub fn record_login_attempt(
        &self,
        ip: &str,
        username: Option<&str>,
        success: bool,
    ) -> Result<(), AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        conn.execute(
            "INSERT INTO login_attempts (ip, username, success) VALUES (?1, ?2, ?3)",
            rusqlite::params![ip, username, success as i64],
        )?;
        Ok(())
    }

    /// Count failed login attempts from an IP in the last `seconds`.
    pub fn count_recent_failures(&self, ip: &str, seconds: i64) -> Result<i64, AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let cutoff = (Utc::now() - chrono::Duration::seconds(seconds))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM login_attempts WHERE ip = ?1 AND success = 0 AND created_at >= ?2",
            rusqlite::params![ip, cutoff],
            |r| r.get(0),
        )?;
        Ok(count)
    }

    // ── Authorization codes ──────────────────────────────────────────────────

    /// Store a new authorization code (hashed). Returns nothing — caller keeps
    /// the plaintext to return to the client.
    #[allow(clippy::too_many_arguments)]
    pub fn add_auth_code(
        &self,
        plaintext_code: &str,
        client_id: &str,
        username: &str,
        redirect_uri: &str,
        scope: &str,
        code_challenge: &str,
        code_challenge_method: &str,
        ttl_seconds: i64,
    ) -> Result<(), AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let hash = sha256_hex(plaintext_code);
        let expires_at = (Utc::now() + chrono::Duration::seconds(ttl_seconds))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        conn.execute(
            "INSERT INTO auth_codes (code_hash, client_id, username, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![hash, client_id, username, redirect_uri, scope, code_challenge, code_challenge_method, expires_at],
        )?;
        Ok(())
    }

    /// Consume an authorization code (single-use). Returns the code record on
    /// success. Marks it used; rejects if already used or expired.
    pub fn consume_auth_code(&self, plaintext_code: &str) -> Result<AuthCode, AuthError> {
        let hash = sha256_hex(plaintext_code);
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let row: Option<AuthCode> = conn
            .query_row(
                "SELECT client_id, username, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, used
                 FROM auth_codes WHERE code_hash = ?1",
                rusqlite::params![hash],
                |r| {
                    Ok(AuthCode {
                        client_id: r.get(0)?,
                        username: r.get(1)?,
                        redirect_uri: r.get(2)?,
                        scope: r.get(3)?,
                        code_challenge: r.get(4)?,
                        code_challenge_method: r.get(5)?,
                        expires_at: r.get(6)?,
                        used: r.get::<_, i64>(7)? != 0,
                    })
                },
            )
            .ok();
        let code = row.ok_or(AuthError::Invalid("invalid authorization code".into()))?;
        if code.used {
            return Err(AuthError::Invalid("authorization code already used".into()));
        }
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        if code.expires_at < now {
            return Err(AuthError::Invalid("authorization code expired".into()));
        }
        conn.execute(
            "UPDATE auth_codes SET used = 1 WHERE code_hash = ?1",
            rusqlite::params![hash],
        )?;
        Ok(code)
    }

    // ── Refresh tokens ───────────────────────────────────────────────────────

    /// Store a refresh token (hashed).
    pub fn add_refresh_token(
        &self,
        plaintext_token: &str,
        client_id: &str,
        username: &str,
        scope: &str,
        ttl_seconds: i64,
    ) -> Result<(), AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let hash = sha256_hex(plaintext_token);
        let expires_at = (Utc::now() + chrono::Duration::seconds(ttl_seconds))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        conn.execute(
            "INSERT INTO refresh_tokens (token_hash, client_id, username, scope, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![hash, client_id, username, scope, expires_at],
        )?;
        Ok(())
    }

    /// Consume a refresh token (rotation). Marks old token used and returns
    /// its record so the caller can mint a new one.
    pub fn consume_refresh_token(
        &self,
        plaintext_token: &str,
        new_plaintext: &str,
    ) -> Result<RefreshToken, AuthError> {
        let hash = sha256_hex(plaintext_token);
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let row: Option<RefreshToken> = conn
            .query_row(
                "SELECT client_id, username, scope, expires_at, used
                 FROM refresh_tokens WHERE token_hash = ?1",
                rusqlite::params![hash],
                |r| {
                    Ok(RefreshToken {
                        client_id: r.get(0)?,
                        username: r.get(1)?,
                        scope: r.get(2)?,
                        expires_at: r.get(3)?,
                        used: r.get::<_, i64>(4)? != 0,
                    })
                },
            )
            .ok();
        let token = row.ok_or(AuthError::Invalid("invalid refresh token".into()))?;
        if token.used {
            return Err(AuthError::Invalid("refresh token already used".into()));
        }
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        if token.expires_at < now {
            return Err(AuthError::Invalid("refresh token expired".into()));
        }
        let new_hash = sha256_hex(new_plaintext);
        conn.execute(
            "UPDATE refresh_tokens SET used = 1, rotated_to = ?2 WHERE token_hash = ?1",
            rusqlite::params![hash, new_hash],
        )?;
        Ok(token)
    }

    /// Revoke a token by its plaintext (access via JWT jti blocklist is
    /// handled separately; this covers refresh tokens).
    pub fn revoke_refresh_token(&self, plaintext: &str) -> Result<(), AuthError> {
        let hash = sha256_hex(plaintext);
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        conn.execute(
            "UPDATE refresh_tokens SET used = 1 WHERE token_hash = ?1",
            rusqlite::params![hash],
        )?;
        Ok(())
    }

    /// Revoke a refresh token by its hash (for admin revocation from the
    /// dashboard settings page, where we don't have the plaintext token).
    pub fn revoke_refresh_token_by_hash(&self, hash: &str) -> Result<usize, AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let n = conn.execute(
            "UPDATE refresh_tokens SET used = 1 WHERE token_hash = ?1 AND used = 0",
            rusqlite::params![hash],
        )?;
        Ok(n)
    }

    /// List all active (not used, not expired) refresh tokens.
    /// Used by the settings page to show AI agent OAuth2 sessions.
    /// Returns (token_hash, client_id, username, scope, created_at, expires_at).
    pub fn list_refresh_tokens(&self) -> Result<Vec<RefreshTokenInfo>, AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut stmt = conn.prepare(
            "SELECT token_hash, client_id, username, scope, created_at, expires_at
             FROM refresh_tokens WHERE used = 0 AND expires_at >= ?1
             ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(rusqlite::params![now], |r| {
            Ok(RefreshTokenInfo {
                token_hash: r.get(0)?,
                client_id: r.get(1)?,
                username: r.get(2)?,
                scope: r.get(3)?,
                created_at: r.get(4)?,
                expires_at: r.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    // ── Sessions ─────────────────────────────────────────────────────────────

    /// Create a new server-side session.
    pub fn add_session(
        &self,
        session_id: &str,
        username: &str,
        csrf_token: &str,
        ttl_seconds: i64,
    ) -> Result<Session, AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let expires_at = (Utc::now() + chrono::Duration::seconds(ttl_seconds))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        conn.execute(
            "INSERT INTO sessions (session_id, username, csrf_token, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![session_id, username, csrf_token, expires_at],
        )?;
        Ok(Session {
            session_id: session_id.to_string(),
            username: username.to_string(),
            csrf_token: csrf_token.to_string(),
            created_at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            expires_at,
        })
    }

    /// Look up a session by ID. Returns None if not found or expired.
    pub fn get_session(&self, session_id: &str) -> Option<Session> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let s: Option<Session> = conn
            .query_row(
                "SELECT session_id, username, csrf_token, created_at, expires_at
                 FROM sessions WHERE session_id = ?1",
                rusqlite::params![session_id],
                |r| {
                    Ok(Session {
                        session_id: r.get(0)?,
                        username: r.get(1)?,
                        csrf_token: r.get(2)?,
                        created_at: r.get(3)?,
                        expires_at: r.get(4)?,
                    })
                },
            )
            .ok();
        if let Some(ref sess) = s {
            let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
            if sess.expires_at < now {
                return None;
            }
        }
        s
    }

    /// Delete a session (logout).
    pub fn delete_session(&self, session_id: &str) -> Result<(), AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        conn.execute(
            "DELETE FROM sessions WHERE session_id = ?1",
            rusqlite::params![session_id],
        )?;
        Ok(())
    }

    /// List all active sessions (not expired). Used by the settings page.
    pub fn list_sessions(&self) -> Result<Vec<Session>, AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut stmt = conn.prepare(
            "SELECT session_id, username, csrf_token, created_at, expires_at
             FROM sessions WHERE expires_at >= ?1 ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(rusqlite::params![now], |r| {
            Ok(Session {
                session_id: r.get(0)?,
                username: r.get(1)?,
                csrf_token: r.get(2)?,
                created_at: r.get(3)?,
                expires_at: r.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Purge expired sessions (maintenance).
    pub fn purge_expired_sessions(&self) -> Result<usize, AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let n = conn.execute(
            "DELETE FROM sessions WHERE expires_at < ?1",
            rusqlite::params![now],
        )?;
        Ok(n)
    }

    /// Purge expired auth codes and used refresh tokens, and prune old
    /// login attempts (older than 24h). Call periodically to prevent
    /// unbounded growth.
    pub fn purge_expired(&self) -> Result<usize, AuthError> {
        let conn = self.conn.lock().expect("auth store mutex poisoned");
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let cutoff_24h = (Utc::now() - chrono::Duration::hours(24))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let mut total = 0;
        total += conn.execute(
            "DELETE FROM auth_codes WHERE expires_at < ?1 OR used = 1",
            rusqlite::params![now],
        )?;
        total += conn.execute(
            "DELETE FROM refresh_tokens WHERE expires_at < ?1 OR used = 1",
            rusqlite::params![now],
        )?;
        total += conn.execute(
            "DELETE FROM login_attempts WHERE created_at < ?1",
            rusqlite::params![cutoff_24h],
        )?;
        Ok(total)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// SHA-256 of input, returned as lowercase hex.
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a cryptographically random opaque token (URL-safe base64).
pub fn random_token(len: usize) -> String {
    use rand::Rng;
    let bytes: Vec<u8> = (0..len).map(|_| rand::rng().random::<u8>()).collect();
    base64_url(&bytes)
}

/// URL-safe base64 encode (no padding).
pub fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// URL-safe base64 decode (no padding). Returns None on error.
pub fn base64_url_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}

fn row_to_client(r: &rusqlite::Row) -> rusqlite::Result<Client> {
    let redirect_uris: String = r.get(3)?;
    let scopes: String = r.get(4)?;
    let grants: String = r.get(5)?;
    Ok(Client {
        id: r.get(0)?,
        client_id: r.get(1)?,
        client_secret: r.get(2)?,
        redirect_uris: serde_json::from_str(&redirect_uris).unwrap_or_default(),
        scopes: serde_json::from_str(&scopes).unwrap_or_default(),
        grants: serde_json::from_str(&grants).unwrap_or_default(),
        public: r.get::<_, i64>(6)? != 0,
        dynamic: r.get::<_, i64>(7)? != 0,
        created_at: r.get(8)?,
    })
}

fn row_to_user(r: &rusqlite::Row) -> rusqlite::Result<User> {
    Ok(User {
        id: r.get(0)?,
        username: r.get(1)?,
        password_hash: r.get(2)?,
        created_at: r.get(3)?,
        locked: r.get::<_, i64>(4)? != 0,
        failed_attempts: r.get(5)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store() -> AuthStore {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.db");
        let path_str = path.to_string_lossy().to_string();
        // Leak the tempdir so the DB file survives the test.
        std::mem::forget(dir);
        AuthStore::open(&path_str).expect("open store")
    }

    #[test]
    fn add_and_get_user() {
        let store = tmp_store();
        let u = store.add_user("alice", "password123").expect("add user");
        assert_eq!(u.username, "alice");
        let fetched = store.get_user("alice").expect("get user");
        assert_eq!(fetched.id, u.id);
    }

    #[test]
    fn duplicate_user_rejected() {
        let store = tmp_store();
        store.add_user("bob", "pw").expect("add");
        let err = store.add_user("bob", "pw").unwrap_err();
        assert!(matches!(err, AuthError::AlreadyExists(_)));
    }

    #[test]
    fn verify_user_correct_password() {
        let store = tmp_store();
        store.add_user("carol", "secret").expect("add");
        let u = store.verify_user("carol", "secret").expect("verify");
        assert_eq!(u.username, "carol");
    }

    #[test]
    fn verify_user_wrong_password_increments_attempts() {
        let store = tmp_store();
        store.add_user("dave", "right").expect("add");
        assert!(store.verify_user("dave", "wrong").is_err());
        let u = store.get_user("dave").expect("get");
        assert_eq!(u.failed_attempts, 1);
    }

    #[test]
    fn lockout_after_10_failures() {
        let store = tmp_store();
        store.add_user("eve", "right").expect("add");
        for _ in 0..10 {
            let _ = store.verify_user("eve", "wrong");
        }
        let u = store.get_user("eve").expect("get");
        assert!(u.locked);
        let err = store.verify_user("eve", "right").unwrap_err();
        assert!(matches!(err, AuthError::Locked));
    }

    #[test]
    fn unlock_resets_state() {
        let store = tmp_store();
        store.add_user("frank", "right").expect("add");
        for _ in 0..10 {
            let _ = store.verify_user("frank", "wrong");
        }
        store.unlock_user("frank").expect("unlock");
        let u = store.get_user("frank").expect("get");
        assert!(!u.locked);
        assert_eq!(u.failed_attempts, 0);
    }

    #[test]
    fn add_and_get_client() {
        let store = tmp_store();
        let c = store
            .add_client(
                "my-client",
                "secret",
                vec!["http://localhost/cb".into()],
                vec!["read".into()],
                false,
                false,
            )
            .expect("add client");
        assert_eq!(c.client_id, "my-client");
        assert!(!c.public);
        let fetched = store.get_client_by_id("my-client").expect("get client");
        assert_eq!(fetched.id, c.id);
        assert!(AuthStore::verify_client_secret(&fetched, "secret"));
        assert!(!AuthStore::verify_client_secret(&fetched, "wrong"));
    }

    #[test]
    fn auth_code_single_use() {
        let store = tmp_store();
        store
            .add_auth_code(
                "code123",
                "cid",
                "alice",
                "http://cb",
                "read",
                "challenge",
                "S256",
                60,
            )
            .expect("add code");
        let c1 = store.consume_auth_code("code123").expect("consume");
        assert_eq!(c1.username, "alice");
        let err = store.consume_auth_code("code123").unwrap_err();
        assert!(matches!(err, AuthError::Invalid(_)));
    }

    #[test]
    fn refresh_token_rotation() {
        let store = tmp_store();
        store
            .add_refresh_token("rt1", "cid", "alice", "read", 3600)
            .expect("add rt");
        let t = store.consume_refresh_token("rt1", "rt2").expect("consume");
        assert_eq!(t.username, "alice");
        let err = store.consume_refresh_token("rt1", "rt3").unwrap_err();
        assert!(matches!(err, AuthError::Invalid(_)));
    }

    #[test]
    fn session_create_get_delete() {
        let store = tmp_store();
        let s = store
            .add_session("sid1", "alice", "csrf1", 3600)
            .expect("add session");
        assert_eq!(s.username, "alice");
        let got = store.get_session("sid1").expect("get session");
        assert_eq!(got.csrf_token, "csrf1");
        store.delete_session("sid1").expect("delete");
        assert!(store.get_session("sid1").is_none());
    }

    #[test]
    fn login_attempt_rate_limit_count() {
        let store = tmp_store();
        for _ in 0..5 {
            store
                .record_login_attempt("1.2.3.4", Some("alice"), false)
                .expect("record");
        }
        let count = store.count_recent_failures("1.2.3.4", 60).expect("count");
        assert_eq!(count, 5);
    }

    #[test]
    fn sha256_hex_is_deterministic() {
        assert_eq!(sha256_hex("hello"), sha256_hex("hello"));
        assert_ne!(sha256_hex("hello"), sha256_hex("world"));
        assert_eq!(sha256_hex("hello").len(), 64);
    }

    #[test]
    fn random_token_is_unique() {
        let a = random_token(32);
        let b = random_token(32);
        assert_ne!(a, b);
        assert!(a.len() >= 32);
    }

    #[test]
    fn base64_url_roundtrip() {
        let original = b"hello world 123";
        let encoded = base64_url(original);
        let decoded = base64_url_decode(&encoded).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn base64_url_decode_invalid_returns_none() {
        assert!(base64_url_decode("!!!invalid!!!").is_none());
    }

    #[test]
    fn get_nonexistent_user_returns_none() {
        let store = tmp_store();
        assert!(store.get_user("ghost").is_none());
    }

    #[test]
    fn get_nonexistent_client_returns_none() {
        let store = tmp_store();
        assert!(store.get_client_by_id("ghost-client").is_none());
    }

    #[test]
    fn add_duplicate_client_rejected() {
        let store = tmp_store();
        store
            .add_client(
                "dup",
                "s",
                vec!["http://cb".into()],
                vec!["read".into()],
                false,
                false,
            )
            .expect("first");
        let err = store
            .add_client(
                "dup",
                "s",
                vec!["http://cb".into()],
                vec!["read".into()],
                false,
                false,
            )
            .unwrap_err();
        assert!(matches!(err, AuthError::AlreadyExists(_)));
    }

    #[test]
    fn consume_nonexistent_auth_code_returns_invalid() {
        let store = tmp_store();
        let err = store.consume_auth_code("nonexistent").unwrap_err();
        assert!(matches!(err, AuthError::Invalid(_)));
    }

    #[test]
    fn consume_nonexistent_refresh_token_returns_invalid() {
        let store = tmp_store();
        let err = store
            .consume_refresh_token("nonexistent", "new")
            .unwrap_err();
        assert!(matches!(err, AuthError::Invalid(_)));
    }

    #[test]
    fn revoke_refresh_token_succeeds() {
        let store = tmp_store();
        store
            .add_refresh_token("rt-rev", "cid", "alice", "read", 3600)
            .expect("add");
        store.revoke_refresh_token("rt-rev").expect("revoke");
        // Consuming a revoked token should fail.
        let err = store.consume_refresh_token("rt-rev", "new").unwrap_err();
        assert!(matches!(err, AuthError::Invalid(_)));
    }

    #[test]
    fn revoke_nonexistent_refresh_token_is_silent() {
        let store = tmp_store();
        // Should not error even if token doesn't exist.
        store.revoke_refresh_token("nonexistent").expect("no error");
    }

    #[test]
    fn purge_expired_sessions_removes_old() {
        let store = tmp_store();
        // Add a session with TTL of 0 seconds (immediately expired).
        store
            .add_session("expired-sid", "alice", "csrf", 0)
            .expect("add");
        // Sleep briefly to ensure expiry.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let purged = store.purge_expired_sessions().expect("purge");
        assert!(purged >= 1);
        assert!(store.get_session("expired-sid").is_none());
    }

    #[test]
    fn delete_nonexistent_session_is_silent() {
        let store = tmp_store();
        store.delete_session("ghost").expect("no error");
    }

    #[test]
    fn unlock_nonexistent_user_returns_error() {
        let store = tmp_store();
        let err = store.unlock_user("ghost").unwrap_err();
        assert!(matches!(err, AuthError::NotFound(_)));
    }

    #[test]
    fn verify_nonexistent_user_returns_error() {
        let store = tmp_store();
        let err = store.verify_user("ghost", "pw").unwrap_err();
        assert!(matches!(err, AuthError::NotFound(_)));
    }

    #[test]
    fn add_client_with_empty_secret_is_public() {
        let store = tmp_store();
        let c = store
            .add_client(
                "pub",
                "",
                vec!["http://cb".into()],
                vec!["read".into()],
                true,
                false,
            )
            .expect("add");
        assert!(c.public);
        // Public client should be retrievable without secret verification.
        let fetched = store.get_client_by_id("pub").expect("get");
        assert!(fetched.public);
    }

    #[test]
    fn count_recent_failures_empty_returns_zero() {
        let store = tmp_store();
        let count = store.count_recent_failures("1.2.3.4", 60).expect("count");
        assert_eq!(count, 0);
    }

    #[test]
    fn record_login_attempt_success() {
        let store = tmp_store();
        store
            .record_login_attempt("1.2.3.4", Some("alice"), true)
            .expect("record success");
        // Success attempts shouldn't count toward failure rate limit.
        let count = store.count_recent_failures("1.2.3.4", 60).expect("count");
        assert_eq!(count, 0);
    }

    #[test]
    fn purge_expired_removes_used_and_expired() {
        let store = tmp_store();
        // Add an auth code with TTL 0 (immediately expired).
        store
            .add_auth_code(
                "expire-code",
                "cid",
                "alice",
                "http://cb",
                "read",
                "ch",
                "S256",
                0,
            )
            .expect("add");
        // Add a used refresh token.
        store
            .add_refresh_token("used-rt", "cid", "alice", "read", 3600)
            .expect("add");
        store.revoke_refresh_token("used-rt").expect("revoke");
        // Add a login attempt.
        store
            .record_login_attempt("1.2.3.4", Some("alice"), false)
            .expect("record");

        std::thread::sleep(std::time::Duration::from_millis(1100));
        let purged = store.purge_expired().expect("purge");
        // At least the expired auth code + used refresh token.
        assert!(purged >= 2);
        // Auth code should be gone.
        assert!(store.consume_auth_code("expire-code").is_err());
        // Used refresh token should be gone.
        assert!(store.consume_refresh_token("used-rt", "new").is_err());
    }
}
