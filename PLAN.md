# PLAN — uteke-web

> Status: draft final (validasi Thoni 2026-08-13). Belum ada crate di `~/uteke`.

## 1. Tujuan

- Satu binary Rust (axum) dengan tiga peran dalam satu proses: **reverse proxy OAuth2**, **auth server**, **dashboard web**.
- Semua request ke **uteke-server** melewati autentikasi OAuth2.
- uteke-server **TIDAK diubah**; uteke-web → uteke-server pakai **token statis** dari config.
- DB auth: **uteke-web.db** (SQLite).

## 2. Arsitektur

```
Client (browser / MCP)
   │  Authorization: Bearer <JWT / static / read-only>
   ▼
uteke-web (satu binary, tiga peran)
   ├─ auth server OAuth2
   ├─ dashboard web
   └─ reverse proxy ──► uteke-server (REST)
                        (inject Authorization: Bearer <token statis>)
```

## 3. Routing HTTP

### Lokal (ditangani uteke-web)

| Method & path | Fungsi |
|---|---|
| `GET /oauth2/auth` | Authorize, render login page |
| `POST /oauth2/login` | Submit username/password (rate-limited) |
| `POST /oauth2/token` | Grant authorization_code (PKCE) + refresh_token (rotasi) |
| `POST /oauth2/register` | RFC 7591 dynamic client registration |
| `GET /.well-known/oauth-authorization-server` | Metadata RFC 8414 |
| `GET /.well-known/jwks-uri` | JWKS placeholder (untuk migrasi RS256, HS256 return empty keys) |
| `POST /oauth2/revoke` | RFC 7009 — revoke token (access/refresh) |
| `POST /oauth2/introspect` | RFC 7662 — introspect token status |
| `GET /profile` | Userinfo (Bearer → identitas non-secret) |
| `GET /healthz` | Health check |
| `GET /dashboard` | UI SPA (session cookie) |
| `GET /dashboard/callback` | OAuth2 callback dashboard (exchange + /profile + set cookie) |
| `POST /dashboard/logout` | Hapus cookie |
| `GET/POST/PUT/DELETE /dashboard/api/*` | JSON API memory (cookie + CSRF) |

### Proxy (catch-all)

- `/*` → reverse proxy ke uteke-server.
- Middleware validasi: JWT (OAuth2 access token) → 401.
- Setelah valid, inject `Authorization: Bearer <token statis uteke-server>`.
- **Route priority**: axum router match specific routes (`/oauth2/*`, `/dashboard/*`, `/.well-known/*`, `/healthz`, `/profile`) sebelum fallback `/*`.
- **Dependency**: HTTP client `reqwest` untuk proxy ke uteke-server (uteke-server pakai `tiny_http`, bukan axum).
- **API versioning**: preserve path prefix `/api/v1/` dan `/api/v2/` dari uteke-server, jangan di-strip.
- **CORS passthrough**: uteke-server sudah punya CORS handling sendiri. Strip CORS headers dari response upstream agar tidak double-set.
- **Error handling upstream**: jika uteke-server down → return 502 Bad Gateway. Timeout 30s → 504 Gateway Timeout. Tidak ada retry (fail fast).

## 4. CLI

CLI `credential` dan `user` adalah subcommand dari binary **`uteke-web`** (bukan `uteke` CLI yang sudah ada). `uteke` CLI tetap fokus ke memory operations.

```
uteke-web serve                              # jalankan server (axum)
uteke-web credential add <client_id> <client_secret> [--redirect-uri URL]
uteke-web credential delete <id>
uteke-web credential list
uteke-web user add <username> <password>
uteke-web user delete <id>
uteke-web user change-password <id> <new_password>
uteke-web user unlock <id>
uteke-web user list
```

Catatan: secret user & client disimpan bcrypt, PK UUID, UNIQUE key `client_id` & `username`.

## 5. Model Auth

- Authorization code + PKCE (S256), refresh token rotasi, dynamic registration RFC 7591.
- Access token = JWT HS256 (`iss`, `sub`, `aud=client_id`, `client_id`, `scope`, `iat`, `exp`, `jti`), secret dari config `jwt_secret`.
- **Scope**: `read` (GET recall/search), `write` (POST/PUT remember/update), `admin` (DELETE + user/credential management). Default scope untuk dashboard = `read write`.
- `/profile` (GET): verify JWT → return `{ username, created_at, scope }` — hanya data non-secret, TANPA `password_hash`/token.
- Rate limit di `/oauth2/login`: 5 gagal / menit / IP.
- **Account lockout**: lock akun setelah 10 gagal total (cross-IP). Reset oleh admin via `uteke-web user unlock <id>`. Tabel `users` tambah kolom `locked` (boolean) + `failed_attempts` (integer).
- **CSRF protection** untuk `/dashboard/api/*`: double-submit cookie pattern. Set cookie `csrf_token` (non-HttpOnly, sama dengan value di session). Client wajib kirim header `X-CSRF-Token` yang match. Reject 403 jika tidak match.
- **Migration path HS256 → RS256**: saat ini HS256 (shared secret). Jika nanti auth server terpisah, migrasi ke RS256 (asymmetric). Endpoint `/.well-known/jwks-uri` sudah disiapkan sebagai placeholder (HS256 return empty keys set).

## 6. Flow Dashboard

1. `GET /dashboard` → tanpa cookie → redirect `/oauth2/auth?client_id=uteke-web-dashboard&redirect_uri={issuer}/dashboard/callback&code_challenge...&state...`.
2. Login di login page tunggal (rate-limited).
3. Redirect `/dashboard/callback?code...&state...`.
4. Exchange code → access token → `GET /profile` (Bearer) → username → set cookie sesi → redirect `/dashboard`.
5. API dashboard pakai cookie; call ke uteke-server server-side pakai token statis (token uteke-server tidak bocor ke browser).

## 7. Session Dashboard

- Cookie bertanda tangan HMAC-SHA256 (pakai `jwt_secret`).
- `HttpOnly`, `SameSite=Strict`, `Secure` (di belakang HTTPS), TTL dari config.
- **Session ID rotation**: generate session ID baru setelah login sukses (ceg session fixation). Cookie lama invalid.
- **Server-side session store**: table `sessions` di SQLite (`session_id` PK, `username`, `created_at`, `expires_at`). Cookie berisi signed session ID. Lookup ke DB untuk validasi — agar bisa revoke session (logout, admin force-logout, expiry).

## 8. Storage (uteke-web.db)

- `clients`: client_id UNIQUE, secret bcrypt, redirect_uris, scopes, grants, public, dynamic
- `users`: username UNIQUE, password_hash bcrypt, created_at, locked (bool), failed_attempts (int)
- `refresh_tokens`: single-use, rotasi, TTL — **disimpan hashed (SHA-256)**, bukan plaintext
- `auth_codes`: single-use, PKCE challenge, TTL — **disimpan hashed (SHA-256)**, bukan plaintext
- `sessions`: session_id PK, username, created_at, expires_at — server-side session store
- `login_attempts`: rate limit login
- `schema_version`: version (int) — tracking migration version
- audit trail JSONL — **default ON** (bukan opsional). Path dari config `audit_log_path`.

### Index

- `users`: INDEX pada `username` (UNIQUE constraint sudah auto-index)
- `clients`: INDEX pada `client_id` (UNIQUE constraint sudah auto-index)
- `refresh_tokens`: INDEX pada `token_hash`
- `auth_codes`: INDEX pada `code_hash`
- `sessions`: INDEX pada `username`, `expires_at`
- `login_attempts`: INDEX pada `ip`, `created_at`

### Migration strategy

- Embed SQL schema di code (`const SCHEMA_V1: &str = include_str!("../schema/v1.sql")`).
- Jalankan saat startup: cek `schema_version`, run migration jika perlu.
- Tidak pakai crate eksternal (refinery dll) — cukup manual versioned SQL untuk scope ini.

### Backup & recovery

- `uteke-web.db` berisi user credentials + active tokens. Admin wajib backup file ini secara berkala.
- Dokumentasikan di README: `cp uteke-web.db uteke-web.db.bak` (hot backup SQLite via VACUUM INTO).

Storage driver: **rusqlite** (bundled, default).

## 9. Config

`uteke-web` membaca **`uteke.toml`** yang sama dengan crate uteke lainnya. Config uteke-web ada di section `[web]`. Layered resolution sama: defaults → `{uteke_home}/uteke.toml` → `.uteke/uteke.toml` → env vars.

### Section `[web]` di `uteke.toml`

```toml
[web]
# Bind address untuk uteke-web
listen = "127.0.0.1:8768"

# Issuer URL (base URL untuk OAuth2 endpoints)
issuer = "http://localhost:8768"

# URL uteke-server yang di-proxy
upstream = "http://127.0.0.1:8767"

# Token statis untuk autentikasi ke uteke-server
# Env: UTEKE_WEB_UPSTREAM_TOKEN
upstream_token = ""

# JWT signing secret (HS256)
# Env: UTEKE_WEB_JWT_SECRET
jwt_secret = ""

# Path SQLite DB untuk auth store
db_path = "~/.codecora/uteke/uteke-web.db"

# Audit trail JSONL path (default ON)
audit_log_path = "~/.codecora/uteke/uteke-web-audit.jsonl"

[web.dashboard]
# Enable dashboard web UI
enabled = true

# Session TTL dalam jam
session_ttl_hours = 24

[web.tls]
# Opsional: untuk deployment standalone tanpa reverse proxy TLS
# cert = "/path/to/cert.pem"
# key = "/path/to/key.pem"
```

### Env var override untuk secrets

Semua secret bisa di-override via env var (prioritas: env var > config file):

- `UTEKE_WEB_JWT_SECRET` → `web.jwt_secret`
- `UTEKE_WEB_UPSTREAM_TOKEN` → `web.upstream_token`

Tujuan: secret tidak tertinggal di config file yang mungkin ter-commit ke git.

### Contoh file `uteke.toml` lengkap

Lihat `examples/uteke-web.toml` untuk contoh config lengkap dengan semua section uteke + section `[web]`.

## 10. Tahapan

- **M1** — crate `uteke-web` + config (env var override) + app builder (axum) + CLI skeleton (`serve` / `credential` / `user` subcommand)
- **M2** — schema OAuth2 (SQLite uteke-web.db) + migrasi (versioned SQL) + index
- **M3** — auth store + token hashing (SHA-256 untuk refresh_tokens & auth_codes)
- **M4a** — auth server bagian 1: authorize, login page + rate limit (IP + account lockout), CSRF cookie
- **M4b** — auth server bagian 2: token (JWT + PKCE + refresh rotasi), register (RFC 7591), metadata (RFC 8414), profile, revoke (RFC 7009), introspect (RFC 7662), JWKS placeholder
- **M5** — middleware proxy (JWT validation → 401) + route priority
- **M6** — reverse proxy + inject token statis + CORS passthrough + upstream error handling (502/504)
- **M7** — dashboard (SPA + callback + API + session cookie + session rotation + server-side session store)
  - **M7.1–M7.6** ✅ (2026-08-13) — Upgrade dashboard dari minimal (recall+remember) → full memory management UI. Detail di `PLAN-WEB.md`.
    - Typed API layer (`dashboard_api.rs`): 9 handler (`/dashboard/api/memories`, `/memories/{id}`, `/tags`, `/namespaces`, `/stats`, `/profile`), `UtekeClient` wrapper, `memory_type` validated against core taxonomy. Generic passthrough dihapus.
    - SPA rewrite: Bootstrap 5 (CDN) + vanilla.js + Bootstrap Icons. Browse table 20/page, 3 mode search (browse/semantic/fts) + debounce 300ms, filter ns/tag (count), sort client-side, detail/create/edit/forget modal, chip tag editor, importance slider, pin toggle, stats cards, user label, type badges, responsive. Trailing-slash `/dashboard/` redirect fix.
    - Test: 5 unit + 16 integration (+1 trailing-slash regression test). 142 test total lulus, clippy clean, fmt clean.
- **M8** — CLI credential + user (add/delete/list/change-password/unlock)
- **M9** — logging (tracing structured) + metrics (`/metrics` Prometheus) + graceful shutdown + upstream health check (`/healthz` cek koneksi uteke-server)

### Testing per milestone

Setiap milestone wajib include:
- **Unit test**: logic murni (token verify, bcrypt, rate limit counter, CSRF check)
- **Integration test**: HTTP endpoint via axum test client (auth flow, proxy, dashboard API)

### Dependency graph

```
M1 → M2 → M3 → M4a → M4b
                   ↓
              M5 → M6    (paralel dengan M7 setelah M4b)
                   ↓
                   M7
                   ↓
                   M8
                   ↓
                   M9 (bisa mulai paralel dari M5 untuk logging)
```

M5+M6 dan M7 bisa dikerjakan paralel setelah M4b selesai. M9 (logging) bisa mulai dari M5.

---

## 10. Post-M9 Fixes & Enhancements

> Dilakukan setelah semua milestone M1–M9 selesai dan test coverage >80% tercapai.
> Berdasarkan security audit, performance review, dan production testing dengan Claude.ai.

### 10.1 Security Fixes

| ID | Severity | Issue | Fix | File |
|----|----------|-------|-----|------|
| S1 | **High** | JWT `iss` tidak divalidasi → cross-client token replay | `verify_access_token` sekarang require `expected_iss` parameter, validate via `validation.set_issuer()` | `jwt.rs`, `proxy.rs`, `oauth.rs` |
| S2 | **Medium** | `/oauth2/revoke` & `/oauth2/introspect` tanpa client auth | Tambah `resolve_client_from_revoke()` — Basic auth atau body `client_id`+`client_secret`. Tanpa auth → 401 | `oauth.rs` |
| S3 | **Medium** | `X-Forwarded-For` dipercaya blindly → rate limit bypass | Tambah config `trusted_proxies: Vec<String>`. XFF hanya dipakai jika request dari IP yang ada di list. Default empty = XFF diabaikan | `config.rs`, `oauth.rs` |
| S4 | **Medium** | Cookie tanpa `Secure` flag | `Secure` flag auto-set jika `issuer` pakai `https://` | `dashboard.rs` |

### 10.2 Bug Fixes

| ID | Severity | Issue | Fix | File |
|----|----------|-------|-----|------|
| B2 | **Medium** | `ensure_dashboard_client` hardcode redirect_uri `localhost:8768` | Pakai `config.issuer` untuk generate redirect_uri dinamis | `main.rs` |
| B3 | **Low** | `verify_session_cookie` compute MAC dua kali (dead code) | Hapus double computation, pakai `verify_slice` saja | `session.rs` |
| B4 | **Low** | `merge_from_file` parse seluruh file sebagai `WebConfig` (bukan `[web]` section) | Parse `web_table` langsung dari TOML | `config.rs` |
| B5 | **Low** | Dashboard `set-cookie` pakai `insert` (overwrite) untuk multiple cookies | Ganti ke `append` | `dashboard.rs` |

### 10.3 Performance Fixes

| ID | Severity | Issue | Fix | File |
|----|----------|-------|-----|------|
| P2 | **Medium** | bcrypt (~100ms) block async worker thread | `verify_user` dijalankan via `tokio::task::spawn_blocking` | `oauth.rs` |
| P3 | **Low** | `login_attempts`, `auth_codes`, `refresh_tokens` tidak pernah di-purge | Method `purge_expired()` — purge expired/used codes + tokens, login_attempts >24h. Dipanggil di startup | `auth_store.rs`, `main.rs` |

### 10.4 RFC 7591 Compliance Fixes (Claude.ai Integration)

| ID | Issue | Fix | File |
|----|-------|-----|------|
| R1 | HTTP 200 (harusnya 201 Created) | Return `StatusCode::CREATED` | `oauth.rs` |
| R2 | `client_id_issued_at` ISO string (harusnya epoch int) | Pakai `chrono::Utc::now().timestamp()` | `oauth.rs` |
| R3 | Default scope `read write` (Claude butuh `offline_access`) | Default → `mcp offline_access` | `oauth.rs` |
| R4 | `token_endpoint_auth_method: "none"` diabaikan | Dihormati → public client (no secret, PKCE-only). `client_secret` tidak di-return | `oauth.rs` |
| R5 | Loopback redirect port exact match only | RFC 8252 §7.3: `http://localhost:PORT` match regardless of port | `oauth.rs` |
| R6 | `RegisterRequest` reject unknown fields | Accept semua field RFC 7591 (`contacts`, `logo_uri`, `software_id`, dll) | `oauth.rs` |

### 10.5 Dashboard Fixes

| ID | Issue | Fix | File |
|----|-------|-----|------|
| D1 | Cookie `SameSite=Strict` → session hilang setelah OAuth2 redirect | Ganti ke `SameSite=Lax` (masih aman, block cross-site POST) | `dashboard.rs` |
| D2 | `recall()` POST tanpa `X-CSRF-Token` header → CSRF error | Tambah `'X-CSRF-Token': getCSRF()` ke fetch header | `dashboard.rs` |

### 10.6 Feature Enhancements

| ID | Feature | Detail | File |
|----|---------|--------|------|
| F1 | **Daily log rotation** | `tracing-appender` crate. Config `log_dir` + `log_level`. File: `uteke-web.log.YYYY-MM-DD`, rotated at midnight. Console (stdout) + file (no ANSI). Env: `UTEKE_WEB_LOG_DIR`, `UTEKE_WEB_LOG_LEVEL` | `main.rs`, `config.rs` |
| F2 | **CORS config** | `[web.cors]` section. `enabled`, `allow_origins`, `allow_methods`, `allow_headers`, `allow_credentials`, `max_age_secs`. `tower-http::cors::CorsLayer`. Default: disabled (backward compatible) | `config.rs`, `app.rs` |
| F3 | **E2E test runbook** | 35 test cases dalam 12 phase. `e2e-test/e2e-uteke-web.md` | `e2e-test/` |

### 10.7 Config Additions (uteke.toml)

```toml
[web]
# ... existing fields ...

# Logging (F1)
log_dir = "~/.codecora/uteke/logs"     # empty = stdout only
log_level = "info"                      # error|warn|info|debug|trace

# Trusted proxies (S3)
trusted_proxies = ["127.0.0.1"]         # IPs yang boleh set X-Forwarded-For

[web.cors]                              # F2
enabled = false
allow_origins = ["*"]
allow_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
allow_headers = ["Authorization", "Content-Type", "X-CSRF-Token"]
allow_credentials = false
max_age_secs = 3600
```

### 10.8 Test Coverage

- **142 test lulus** (75 unit + 16 integration dashboard_api + 51 integration handler)
- Coverage: **83.02%** line, 89.39% library (excluding `main.rs`) — sebelum M7.1–M7.6
- `cargo clippy --all-targets -- -D warnings` lulus
- `cargo fmt` lulus
