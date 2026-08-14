-- uteke-web schema v1
-- SQLite auth store for OAuth2 server + dashboard sessions.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ── OAuth2 clients (RFC 6749 / RFC 7591) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS clients (
    id            TEXT PRIMARY KEY,          -- UUID
    client_id     TEXT NOT NULL UNIQUE,      -- public client identifier
    client_secret TEXT NOT NULL,             -- bcrypt hash (empty for public clients)
    redirect_uris TEXT NOT NULL DEFAULT '[]', -- JSON array of strings
    scopes        TEXT NOT NULL DEFAULT '[]', -- JSON array of strings
    grants        TEXT NOT NULL DEFAULT '["authorization_code","refresh_token"]', -- JSON array
    public        INTEGER NOT NULL DEFAULT 0, -- 1 = public client (no secret)
    dynamic       INTEGER NOT NULL DEFAULT 0, -- 1 = registered via RFC 7591
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_clients_client_id ON clients(client_id);

-- ── Dashboard users ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,        -- UUID
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,           -- bcrypt
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    locked          INTEGER NOT NULL DEFAULT 0,  -- 1 = locked (account lockout)
    failed_attempts INTEGER NOT NULL DEFAULT 0   -- cumulative failed logins
);
-- username UNIQUE constraint auto-creates an index.

-- ── Authorization codes (single-use, PKCE) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash      TEXT PRIMARY KEY,         -- SHA-256 of the plaintext code
    client_id      TEXT NOT NULL,
    username       TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    scope          TEXT NOT NULL DEFAULT '',
    code_challenge TEXT NOT NULL,            -- PKCE S256 challenge
    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
    created_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at     TEXT NOT NULL,            -- short TTL (~60s)
    used           INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_auth_codes_client ON auth_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON auth_codes(expires_at);

-- ── Refresh tokens (single-use, rotation) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash    TEXT PRIMARY KEY,          -- SHA-256 of plaintext token
    client_id     TEXT NOT NULL,
    username      TEXT NOT NULL,
    scope         TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at    TEXT NOT NULL,
    used          INTEGER NOT NULL DEFAULT 0,  -- 1 = rotated/revoked
    rotated_to    TEXT                        -- hash of the replacement token (rotation chain)
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client ON refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);

-- ── Server-side sessions (dashboard) ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
    session_id  TEXT PRIMARY KEY,            -- random opaque ID (cookie value is signed)
    username    TEXT NOT NULL,
    csrf_token  TEXT NOT NULL,               -- double-submit CSRF token
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at  TEXT NOT NULL,
    refresh_token_hash TEXT                  -- SHA-256 of the OAuth2 refresh token issued at login; revoked on logout
);
CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- ── Login attempts (rate limiting + audit) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS login_attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL,
    username    TEXT,                         -- NULL if username not provided
    success     INTEGER NOT NULL,            -- 1 = success, 0 = failure
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip, created_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username);

-- ── Schema version tracking ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
INSERT INTO schema_version (version) VALUES (1);
