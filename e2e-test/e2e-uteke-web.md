# uteke-web E2E Production Runbook

> Skenario end-to-end untuk verifikasi uteke-web di production.
> Didesain untuk dieksekusi oleh AI agent atau operator manusia.
> Setiap step punya **Expected** (output yang harus muncul) dan **Pass Criteria**.

## Prerequisites

### Variabel (set sebelum mulai)

```bash
# ── SET INI SESUAI PRODUCTION ──────────────────────────────────────────────
export WEB_BASE="http://localhost:8768"          # URL uteke-web
export UPSTREAM_BASE="http://localhost:8767"      # URL uteke-server (upstream)
export JWT_SECRET=""                              # dari config/uteke.toml [web] jwt_secret
export ISSUER="$WEB_BASE"                         # biasanya sama dengan WEB_BASE

# Client credentials (dari `uteke-web credential add`)
export CLIENT_ID="test-e2e-client"
export CLIENT_SECRET="test-e2e-client-secret"
export REDIRECT_URI="http://localhost:9999/callback"

# User credentials (dari `uteke-web user add`)
export USERNAME="e2e-tester"
export PASSWORD="e2e-test-password-123"

# PKCE verifier (generate random)
export VERIFIER="$(openssl rand -base64 32 | tr -d '=+/' | head -c 48)"
export CHALLENGE="$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | base64 | tr -d '=+/' | tr '+/' '-_')"
```

### Checklist sebelum mulai

```bash
# 1. uteke-web running
curl -sf "$WEB_BASE/healthz" | jq . && echo "✅ uteke-web is up" || echo "❌ uteke-web not reachable"

# 2. Upstream uteke-server running
curl -sf "$UPSTREAM_BASE/health" && echo "✅ upstream is up" || echo "❌ upstream not reachable"

# 3. Register test client + user (jika belum ada)
uteke-web credential add --client-id "$CLIENT_ID" --client-secret "$CLIENT_SECRET" --redirect-uris "$REDIRECT_URI"
uteke-web user add --username "$USERNAME" --password "$PASSWORD"
```

---

## Phase 1: OAuth2 Discovery & Metadata

### Step 1.1 — RFC 8414 Metadata

```bash
RESP=$(curl -sf "$WEB_BASE/.well-known/oauth-authorization-server")
echo "$RESP" | jq .
```

**Expected:**
```json
{
  "issuer": "http://localhost:8768",
  "authorization_endpoint": "http://localhost:8768/oauth2/auth",
  "token_endpoint": "http://localhost:8768/oauth2/token",
  "registration_endpoint": "http://localhost:8768/oauth2/register",
  "revocation_endpoint": "http://localhost:8768/oauth2/revoke",
  "introspection_endpoint": "http://localhost:8768/oauth2/introspect",
  "userinfo_endpoint": "http://localhost:8768/profile",
  "jwks_uri": "http://localhost:8768/.well-known/jwks-uri",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "scopes_supported": ["read", "write", "admin"]
}
```

**Pass criteria:**
- [ ] `issuer` == `$ISSUER`
- [ ] `authorization_endpoint` == `$ISSUER/oauth2/auth`
- [ ] `code_challenge_methods_supported` contains `"S256"`

---

### Step 1.2 — JWKS URI

```bash
curl -sf "$WEB_BASE/.well-known/jwks-uri" | jq .
```

**Expected:**
```json
{ "keys": [] }
```

**Pass criteria:**
- [ ] `keys` is empty array (HS256 → no public keys)

---

## Phase 2: OAuth2 Authorization Code Flow (PKCE)

### Step 2.1 — Authorize endpoint (render login page)

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
  "$WEB_BASE/oauth2/auth?response_type=code&client_id=$CLIENT_ID&redirect_uri=$(python3 -c 'import urllib.parse;import os;print(urllib.parse.quote(os.environ["REDIRECT_URI"]))')&scope=read+write&state=test-state-123&code_challenge=$CHALLENGE&code_challenge_method=S256")
echo "HTTP $RESP"
```

**Expected:** `HTTP 200`

**Pass criteria:**
- [ ] Status 200 (login page rendered)
- [ ] Body contains `"Sign in to uteke"` (cek manual: `curl -sf "...same url..." | grep "Sign in to uteke"`)

---

### Step 2.2 — Authorize: unknown client_id → error

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
  "$WEB_BASE/oauth2/auth?response_type=code&client_id=nonexistent-client&redirect_uri=$REDIRECT_URI&code_challenge=$CHALLENGE&code_challenge_method=S256")
echo "HTTP $RESP"
```

**Expected:** `HTTP 400`

**Pass criteria:**
- [ ] Status 400
- [ ] Body contains `"unknown client_id"`

---

### Step 2.3 — Authorize: redirect_uri mismatch → error

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
  "$WEB_BASE/oauth2/auth?response_type=code&client_id=$CLIENT_ID&redirect_uri=http://evil.com/cb&code_challenge=$CHALLENGE&code_challenge_method=S256")
echo "HTTP $RESP"
```

**Expected:** `HTTP 400`

**Pass criteria:**
- [ ] Status 400
- [ ] Body contains `"redirect_uri not registered"`

---

### Step 2.4 — Authorize: missing PKCE → error

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
  "$WEB_BASE/oauth2/auth?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI")
echo "HTTP $RESP"
```

**Expected:** `HTTP 400`

**Pass criteria:**
- [ ] Status 400
- [ ] Body contains `"PKCE code_challenge is required"`

---

### Step 2.5 — Login (POST credentials → get auth code)

```bash
# Start a local listener to capture the redirect (port 9999)
python3 -c "
import http.server, urllib.parse, sys, os
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        code = params.get('code', [None])[0]
        state = params.get('state', [None])[0]
        if code:
            print(f'CODE={code}')
            print(f'STATE={state}')
            sys.stdout.flush()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')
    def log_message(self, *a): pass
http.server.HTTPServer(('0.0.0.0', 9999), H).handle_request()
" &
LISTENER_PID=$!
sleep 0.5

# POST login
curl -sf -o /dev/null -w "%{http_code}" -L \
  -X POST "$WEB_BASE/oauth2/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$USERNAME&password=$PASSWORD&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=read+write&state=test-state-123&code_challenge=$CHALLENGE&code_challenge_method=S256&nonce="

# Wait for listener to capture the code
sleep 1
kill $LISTENER_PID 2>/dev/null
```

**Expected:**
```
CODE=<some-auth-code>
STATE=test-state-123
```

**Pass criteria:**
- [ ] `CODE` is non-empty
- [ ] `STATE` == `test-state-123`

**Save the code:**
```bash
export AUTH_CODE="<paste CODE value here>"
```

> **AI automation tip:** Untuk eksekusi otomatis, gunakan `curl -D-` untuk capture `Location` header
> daripada menjalankan listener. Lihat Step 2.5b di bawah.

### Step 2.5b — Login via redirect header (untuk AI agent)

```bash
LOCATION=$(curl -sf -o /dev/null -w "%{redirect_url}" \
  -X POST "$WEB_BASE/oauth2/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$USERNAME&password=$PASSWORD&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=read+write&state=test-state-123&code_challenge=$CHALLENGE&code_challenge_method=S256&nonce=")

echo "Location: $LOCATION"
AUTH_CODE=$(echo "$LOCATION" | grep -oP 'code=\K[^&]+')
echo "Auth code: $AUTH_CODE"
```

**Pass criteria:**
- [ ] `AUTH_CODE` is non-empty

---

### Step 2.6 — Login with wrong password → 401

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X POST "$WEB_BASE/oauth2/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$USERNAME&password=wrong-password&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=read&state=s&code_challenge=$CHALLENGE&code_challenge_method=S256&nonce=")
echo "HTTP $RESP"
```

**Expected:** `HTTP 401`

**Pass criteria:**
- [ ] Status 401
- [ ] Body contains `"invalid username or password"`

---

## Phase 3: Token Exchange

### Step 3.1 — Exchange auth code for access + refresh token

```bash
RESP=$(curl -sf \
  -X POST "$WEB_BASE/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$AUTH_CODE&redirect_uri=$REDIRECT_URI&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&code_verifier=$VERIFIER")
echo "$RESP" | jq .
```

**Expected:**
```json
{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<opaque-token>",
  "scope": "read write"
}
```

**Pass criteria:**
- [ ] `access_token` is non-empty (JWT, ~200+ chars)
- [ ] `token_type` == `"Bearer"`
- [ ] `expires_in` == `3600`
- [ ] `refresh_token` is non-empty
- [ ] `scope` == `"read write"`

**Save tokens:**
```bash
export ACCESS_TOKEN=$(echo "$RESP" | jq -r .access_token)
export REFRESH_TOKEN=$(echo "$RESP" | jq -r .refresh_token)
```

---

### Step 3.2 — Replay auth code → rejected (single-use)

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X POST "$WEB_BASE/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$AUTH_CODE&redirect_uri=$REDIRECT_URI&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&code_verifier=$VERIFIER")
echo "HTTP $RESP"
```

**Expected:** `HTTP 400`

**Pass criteria:**
- [ ] Status 400 (code sudah consumed)
- [ ] Body contains `"invalid_grant"` or `"already used"`

---

### Step 3.3 — Token: unsupported grant_type

```bash
RESP=$(curl -sf \
  -X POST "$WEB_BASE/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials")
echo "$RESP" | jq .
```

**Expected:**
```json
{
  "error": "unsupported_grant_type",
  "error_description": "grant_type 'client_credentials' not supported"
}
```

**Pass criteria:**
- [ ] `error` == `"unsupported_grant_type"`

---

## Phase 4: Profile (UserInfo)

### Step 4.1 — Profile with valid token

```bash
RESP=$(curl -sf \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  "$WEB_BASE/profile")
echo "$RESP" | jq .
```

**Expected:**
```json
{
  "username": "e2e-tester",
  "client_id": "test-e2e-client",
  "scope": "read write",
  "iss": "http://localhost:8768",
  "exp": <unix-timestamp>
}
```

**Pass criteria:**
- [ ] `username` == `$USERNAME`
- [ ] `client_id` == `$CLIENT_ID`
- [ ] `scope` == `"read write"`
- [ ] `iss` == `$ISSUER`

---

### Step 4.2 — Profile without token → 401

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}" "$WEB_BASE/profile")
echo "HTTP $RESP"
```

**Expected:** `HTTP 401`

**Pass criteria:**
- [ ] Status 401

---

### Step 4.3 — Profile with invalid token → 401

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer invalid.token.here" \
  "$WEB_BASE/profile")
echo "HTTP $RESP"
```

**Expected:** `HTTP 401`

**Pass criteria:**
- [ ] Status 401

---

### Step 4.4 — Profile with token from wrong issuer → 401 (S1 fix)

```bash
# Mint a token with a fake issuer using the same secret
# (This requires the JWT secret — only testable if you have it)
if [ -n "$JWT_SECRET" ]; then
  FAKE_TOKEN=$(python3 -c "
import jwt, time
claims = {
    'iss': 'http://fake-issuer',
    'sub': '$USERNAME',
    'aud': '$CLIENT_ID',
    'client_id': '$CLIENT_ID',
    'scope': 'read',
    'iat': int(time.time()),
    'exp': int(time.time()) + 3600,
    'jti': 'fake-jti-123'
}
print(jwt.encode(claims, '$JWT_SECRET', algorithm='HS256'))
" 2>/dev/null || echo "")

  if [ -n "$FAKE_TOKEN" ]; then
    RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
      -H "Authorization: Bearer $FAKE_TOKEN" \
      "$WEB_BASE/profile")
    echo "HTTP $RESP (wrong issuer token)"
  else
    echo "SKIP — PyJWT not installed"
  fi
else
  echo "SKIP — JWT_SECRET not set"
fi
```

**Expected:** `HTTP 401`

**Pass criteria:**
- [ ] Status 401 (token dengan issuer berbeda ditolak)

---

## Phase 5: Reverse Proxy (Scope Enforcement)

### Step 5.1 — Proxy GET with read scope → 200

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  "$WEB_BASE/recall?q=test&limit=5")
echo "HTTP $RESP"
```

**Expected:** `HTTP 200` (atau 404/502 jika upstream tidak punya endpoint `/recall`)

**Pass criteria:**
- [ ] Status bukan 401 atau 403 (proxy accept token, forward ke upstream)

---

### Step 5.2 — Proxy POST with write scope → 200

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"content":"e2e test memory"}' \
  "$WEB_BASE/remember")
echo "HTTP $RESP"
```

**Expected:** `HTTP 200` (atau 201 jika upstream accept)

**Pass criteria:**
- [ ] Status bukan 401 atau 403

---

### Step 5.3 — Proxy without token → 401

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}" "$WEB_BASE/recall")
echo "HTTP $RESP"
```

**Expected:** `HTTP 401`

**Pass criteria:**
- [ ] Status 401
- [ ] Response header `WWW-Authenticate` contains `Bearer`

---

### Step 5.4 — Scope enforcement: read-only token cannot POST

```bash
# Mint a read-only token via refresh with narrowed scope
READONLY_RESP=$(curl -sf \
  -X POST "$WEB_BASE/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=read")
export READONLY_TOKEN=$(echo "$READONLY_RESP" | jq -r .access_token)
export NEW_REFRESH=$(echo "$READONLY_RESP" | jq -r .refresh_token)

RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Authorization: Bearer $READONLY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"content":"should fail"}' \
  "$WEB_BASE/remember")
echo "HTTP $RESP (read-only token, POST)"
```

**Expected:** `HTTP 403`

**Pass criteria:**
- [ ] Status 403
- [ ] Body contains `"insufficient_scope"` or `"write scope required"`

---

### Step 5.5 — Scope enforcement: DELETE requires admin

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X DELETE \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  "$WEB_BASE/forget/some-id")
echo "HTTP $RESP (DELETE without admin scope)"
```

**Expected:** `HTTP 403`

**Pass criteria:**
- [ ] Status 403
- [ ] Body contains `"admin scope required"`

---

## Phase 6: Refresh Token Rotation

### Step 6.1 — Refresh token → new access + refresh token

```bash
RESP=$(curl -sf \
  -X POST "$WEB_BASE/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$NEW_REFRESH&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET")
echo "$RESP" | jq .
```

**Expected:**
```json
{
  "access_token": "<new-JWT>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<new-opaque-token>",
  "scope": "read"
}
```

**Pass criteria:**
- [ ] `access_token` is non-empty
- [ ] `refresh_token` is non-empty
- [ ] `refresh_token` != `$NEW_REFRESH` (rotation)

**Save new refresh token:**
```bash
export ROTATED_REFRESH=$(echo "$RESP" | jq -r .refresh_token)
```

---

### Step 6.2 — Old refresh token rejected (rotation)

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X POST "$WEB_BASE/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$NEW_REFRESH&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET")
echo "HTTP $RESP (old refresh token)"
```

**Expected:** `HTTP 400`

**Pass criteria:**
- [ ] Status 400 (old token sudah di-rotate, tidak valid lagi)

---

## Phase 7: Token Revocation & Introspection (S2 fix)

### Step 7.1 — Introspect active token (with client auth)

```bash
RESP=$(curl -sf \
  -X POST "$WEB_BASE/oauth2/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ACCESS_TOKEN&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET")
echo "$RESP" | jq .
```

**Expected:**
```json
{
  "active": true,
  "scope": "read write",
  "client_id": "test-e2e-client",
  "username": "e2e-tester",
  "token_type": "Bearer",
  "exp": <timestamp>,
  "iss": "http://localhost:8768"
}
```

**Pass criteria:**
- [ ] `active` == `true`
- [ ] `username` == `$USERNAME`

---

### Step 7.2 — Introspect without client auth → 401 (S2 fix)

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X POST "$WEB_BASE/oauth2/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ACCESS_TOKEN")
echo "HTTP $RESP"
```

**Expected:** `HTTP 401`

**Pass criteria:**
- [ ] Status 401 (client auth required)

---

### Step 7.3 — Revoke refresh token (with client auth)

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X POST "$WEB_BASE/oauth2/revoke" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ROTATED_REFRESH&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET")
echo "HTTP $RESP"
```

**Expected:** `HTTP 200`

**Pass criteria:**
- [ ] Status 200 (always 200 per RFC 7009)

---

### Step 7.4 — Revoked refresh token cannot be used

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X POST "$WEB_BASE/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$ROTATED_REFRESH&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET")
echo "HTTP $RESP (revoked refresh token)"
```

**Expected:** `HTTP 400`

**Pass criteria:**
- [ ] Status 400 (revoked token rejected)

---

### Step 7.5 — Revoke without client auth → 401 (S2 fix)

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X POST "$WEB_BASE/oauth2/revoke" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=some-token")
echo "HTTP $RESP"
```

**Expected:** `HTTP 401`

**Pass criteria:**
- [ ] Status 401

---

## Phase 8: Dynamic Client Registration (RFC 7591)

### Step 8.1 — Register a new client

```bash
RESP=$(curl -sf \
  -X POST "$WEB_BASE/oauth2/register" \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris":["http://localhost:8888/cb"],"scope":"read write","client_name":"e2e-dynamic"}')
echo "$RESP" | jq .
```

**Expected:**
```json
{
  "client_id": "<uuid>",
  "client_secret": "<random>",
  "client_id_issued_at": "<timestamp>",
  "redirect_uris": ["http://localhost:8888/cb"],
  "grant_types": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_method": "client_secret_post"
}
```

**Pass criteria:**
- [ ] `client_id` is non-empty UUID
- [ ] `client_secret` is non-empty
- [ ] `redirect_uris` matches input

---

### Step 8.2 — Register without redirect_uris → 400

```bash
RESP=$(curl -sf \
  -X POST "$WEB_BASE/oauth2/register" \
  -H "Content-Type: application/json" \
  -d '{}')
echo "$RESP" | jq .
```

**Expected:**
```json
{
  "error": "invalid_client_metadata",
  "error_description": "redirect_uris is required"
}
```

**Pass criteria:**
- [ ] `error` == `"invalid_client_metadata"`

---

## Phase 9: Dashboard

### Step 9.1 — Dashboard without session → redirect to authorize

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}\n%{redirect_url}" \
  "$WEB_BASE/dashboard")
echo ""
```

**Expected:**
```
303
http://localhost:8768/oauth2/auth?response_type=code&client_id=uteke-web-dashboard&...
```

**Pass criteria:**
- [ ] Status 303 (SEE_OTHER)
- [ ] Redirect URL contains `/oauth2/auth`
- [ ] Redirect URL contains `client_id=uteke-web-dashboard`

---

### Step 9.2 — Dashboard API without session → 401

```bash
RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
  "$WEB_BASE/dashboard/api/recall")
echo "HTTP $RESP"
```

**Expected:** `HTTP 401`

**Pass criteria:**
- [ ] Status 401
- [ ] Body contains `"unauthorized"`

---

### Step 9.3 — Dashboard API POST without CSRF → 403

> Untuk test ini, perlu session cookie yang valid. Skip jika tidak punya session.
> Dashboard flow lengkap butuh browser (OAuth2 callback loop).

```bash
# Cek apakah dashboard di-enable
RESP=$(curl -sf -o /dev/null -w "%{http_code}" "$WEB_BASE/dashboard")
if [ "$RESP" == "303" ]; then
  echo "Dashboard enabled (redirects to authorize) — full CSRF test needs browser session"
  echo "SKIP — manual test via browser required"
else
  echo "Dashboard might be disabled (HTTP $RESP)"
fi
```

---

## Phase 10: Security Edge Cases

### Step 10.1 — Rate limiting (5 failures per minute per IP)

```bash
# Send 6 wrong-password logins rapidly
for i in $(seq 1 6); do
  RESP=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST "$WEB_BASE/oauth2/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "X-Forwarded-For: 10.0.0.99" \
    -d "username=ratelimit-test&password=wrong&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=read&state=s&code_challenge=$CHALLENGE&code_challenge_method=S256&nonce=")
  echo "Attempt $i: HTTP $RESP"
done
```

**Expected:**
```
Attempt 1: HTTP 401
Attempt 2: HTTP 401
Attempt 3: HTTP 401
Attempt 4: HTTP 401
Attempt 5: HTTP 401
Attempt 6: HTTP 400 (rate limited)
```

> **Note:** Jika `trusted_proxies` tidak di-config, XFF diabaikan dan semua
> request dianggap dari IP yang sama ("unknown"). Rate limit tetap berlaku
> tapi berdasarkan IP "unknown", bukan XFF.

**Pass criteria:**
- [ ] Attempt 6 returns 400 (atau 401 dengan pesan "too many login attempts")
- [ ] Body contains `"too many login attempts"`

---

### Step 10.2 — X-Forwarded-For ignored without trusted_proxies (S3 fix)

```bash
# Jika trusted_proxies tidak di-config, XFF harus diabaikan
# Rate limit dari IP berbeda (XFF) harusnya tetap digabung (semua "unknown")
RESP1=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X POST "$WEB_BASE/oauth2/login" \
  -H "X-Forwarded-For: 1.2.3.4" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=xff-test&password=wrong&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=read&state=s&code_challenge=$CHALLENGE&code_challenge_method=S256&nonce=")

RESP2=$(curl -sf -o /dev/null -w "%{http_code}" \
  -X POST "$WEB_BASE/oauth2/login" \
  -H "X-Forwarded-For: 5.6.7.8" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=xff-test&password=wrong&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=read&state=s&code_challenge=$CHALLENGE&code_challenge_method=S256&nonce=")

echo "XFF 1.2.3.4: $RESP1, XFF 5.6.7.8: $RESP2"
```

**Expected:** Kedua request dihitung ke rate limit yang sama (IP "unknown") jika trusted_proxies kosong.

**Pass criteria:**
- [ ] Jika trusted_proxies kosong: kedua request share rate limit counter
- [ ] Jika trusted_proxies diisi: XFF dihormati, counter terpisah

---

### Step 10.3 — Cookie Secure flag (S4 fix)

```bash
# Cek apakah issuer pakai HTTPS
if [[ "$ISSUER" == https://* ]]; then
  echo "Issuer is HTTPS — cookie should have Secure flag"
  echo "Verify via browser DevTools → Application → Cookies"
  echo "  uteke_session cookie should have Secure=true"
  echo "  csrf_token cookie should have Secure=true"
else
  echo "Issuer is HTTP — Secure flag tidak di-set (expected)"
fi
```

---

## Phase 11: Health & Metrics

### Step 11.1 — Healthz (upstream connectivity)

```bash
RESP=$(curl -sf "$WEB_BASE/healthz")
echo "$RESP" | jq .
```

**Expected (upstream healthy):**
```json
{
  "status": "ok",
  "upstream": "http://localhost:8767"
}
```

**Expected (upstream down):**
```json
{
  "status": "degraded",
  "upstream": "http://localhost:8767",
  "error": "..."
}
```
(HTTP 503)

**Pass criteria:**
- [ ] `status` == `"ok"` jika upstream running
- [ ] `upstream` == `$UPSTREAM_BASE`

---

### Step 11.2 — Prometheus metrics

```bash
RESP=$(curl -sf "$WEB_BASE/metrics")
echo "$RESP"
```

**Expected:**
```
# HELP uteke_web_tokens_issued_total Total access tokens issued.
# TYPE uteke_web_tokens_issued_total counter
uteke_web_tokens_issued_total <N>
# HELP uteke_web_tokens_refreshed_total Total refresh token rotations.
# TYPE uteke_web_tokens_refreshed_total counter
uteke_web_tokens_refreshed_total <N>
# HELP uteke_web_login_success_total Total successful logins.
# TYPE uteke_web_login_success_total counter
uteke_web_login_success_total <N>
# HELP uteke_web_login_failure_total Total failed logins.
# TYPE uteke_web_login_failure_total counter
uteke_web_login_failure_total <N>
# HELP uteke_web_proxy_requests_total Total proxied requests to upstream.
# TYPE uteke_web_proxy_requests_total counter
uteke_web_proxy_requests_total <N>
# HELP uteke_web_proxy_errors_total Total proxy errors (502/504).
# TYPE uteke_web_proxy_errors_total counter
uteke_web_proxy_errors_total <N>
```

**Pass criteria:**
- [ ] All 6 metrics present
- [ ] `uteke_web_tokens_issued_total` >= 1 (kita just minted tokens)
- [ ] `uteke_web_login_success_total` >= 1
- [ ] `uteke_web_login_failure_total` >= 5 (dari rate limit test)
- [ ] `uteke_web_proxy_requests_total` >= 2 (dari proxy test)

---

## Phase 12: Cleanup

### Step 12.1 — Revoke all tokens

```bash
# Revoke refresh token
curl -sf -X POST "$WEB_BASE/oauth2/revoke" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$REFRESH_TOKEN&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET" \
  -o /dev/null

echo "Tokens revoked"
```

---

## Summary Checklist

| Phase | Test | Status |
|-------|------|--------|
| 1 | Metadata (RFC 8414) | ☐ |
| 1 | JWKS URI | ☐ |
| 2 | Authorize renders login | ☐ |
| 2 | Authorize rejects unknown client | ☐ |
| 2 | Authorize rejects redirect_uri mismatch | ☐ |
| 2 | Authorize rejects missing PKCE | ☐ |
| 2 | Login → auth code | ☐ |
| 2 | Login wrong password → 401 | ☐ |
| 3 | Token exchange (auth code → JWT) | ☐ |
| 3 | Auth code single-use | ☐ |
| 3 | Unsupported grant type | ☐ |
| 4 | Profile with valid token | ☐ |
| 4 | Profile without token → 401 | ☐ |
| 4 | Profile with invalid token → 401 | ☐ |
| 4 | Profile with wrong-issuer token → 401 (S1) | ☐ |
| 5 | Proxy GET with read scope | ☐ |
| 5 | Proxy POST with write scope | ☐ |
| 5 | Proxy without token → 401 | ☐ |
| 5 | Read-only token cannot POST → 403 | ☐ |
| 5 | DELETE requires admin → 403 | ☐ |
| 6 | Refresh token rotation | ☐ |
| 6 | Old refresh token rejected | ☐ |
| 7 | Introspect active token (with auth) | ☐ |
| 7 | Introspect without auth → 401 (S2) | ☐ |
| 7 | Revoke token (with auth) | ☐ |
| 7 | Revoked token rejected | ☐ |
| 7 | Revoke without auth → 401 (S2) | ☐ |
| 8 | Dynamic registration | ☐ |
| 8 | Registration without redirect_uris → 400 | ☐ |
| 9 | Dashboard redirect to authorize | ☐ |
| 9 | Dashboard API without session → 401 | ☐ |
| 10 | Rate limiting (5 failures/min) | ☐ |
| 10 | XFF ignored without trusted_proxies (S3) | ☐ |
| 10 | Cookie Secure flag (S4) | ☐ |
| 11 | Healthz | ☐ |
| 11 | Prometheus metrics | ☐ |

**Total: 35 checks**

---

## AI Agent Execution Notes

1. **Jalankan secara berurutan** — beberapa step depend on tokens dari step sebelumnya.
2. **Save output** setiap step ke variabel environment (`export ACCESS_TOKEN=...`).
3. **Jika step gagal**, STOP dan investigasi sebelum lanjut. Jangan skip.
4. **Untuk AI agent**: Parse output dengan `jq` dan compare dengan expected values.
5. **Rate limit test (Phase 10)** butuh IP unik — gunakan `X-Forwarded-For` hanya jika `trusted_proxies` di-config.
6. **Dashboard CSRF test (Step 9.3)** butuh browser session — skip untuk AI-only testing.
7. **Wrong-issuer test (Step 4.4)** butuh `JWT_SECRET` dan `PyJWT` — skip jika tidak tersedia.
