//! Dashboard (M7) — SPA shell, OAuth2 callback, session cookie, CSRF, and
//! the typed `/dashboard/api/*` REST layer (see `dashboard_api.rs`).
//!
//! Flow:
//! 1. `GET /dashboard` — no valid session cookie → redirect to `/oauth2/auth`
//!    with the dashboard's own client_id. With a valid session → serve SPA.
//! 2. `GET /dashboard/callback` — exchange auth code for access token, fetch
//!    `/profile`, create server-side session, set signed cookie, redirect.
//! 3. `GET/POST/PUT/DELETE /dashboard/api/*` — typed handlers that validate
//!    session cookie + CSRF, then translate the call to uteke-server.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Json, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use crate::session;
use crate::state::AppState;

use crate::dashboard_api;

/// The dashboard's own OAuth2 client_id (registered at startup).
pub const DASHBOARD_CLIENT_ID: &str = "uteke-web-dashboard";

/// CSRF header name expected on all `/dashboard/api/*` mutations.
pub(crate) const CSRF_HEADER: &str = "x-csrf-token";
/// CSRF cookie name.
const CSRF_COOKIE: &str = "csrf_token";
/// Session cookie name.
const SESSION_COOKIE: &str = "uteke_session";

/// Build the dashboard router.
pub fn dashboard_router() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/dashboard", get(dashboard_index))
        // Trailing-slash alias — axum 0.8 does not auto-redirect `/dashboard/`
        // to `/dashboard`, so without this the catch-all proxy swallows it
        // and returns 401 instead of the OAuth2 login redirect.
        .route("/dashboard/", get(dashboard_index))
        .route("/dashboard/callback", get(dashboard_callback))
        .route("/dashboard/logout", post(dashboard_logout))
        // Typed browser-facing API (M7.1) — replaces the generic passthrough.
        .route(
            "/dashboard/api/memories",
            get(dashboard_api::handle_list_memories).post(dashboard_api::handle_create_memory),
        )
        .route(
            "/dashboard/api/memories/{id}",
            get(dashboard_api::handle_get_memory)
                .put(dashboard_api::handle_update_memory)
                .delete(dashboard_api::handle_forget_memory),
        )
        .route("/dashboard/api/tags", get(dashboard_api::handle_tags))
        .route(
            "/dashboard/api/namespaces",
            get(dashboard_api::handle_namespaces),
        )
        .route("/dashboard/api/stats", get(dashboard_api::handle_stats))
        .route("/dashboard/api/profile", get(dashboard_api::handle_profile))
}

// ── Dashboard index ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// `GET /dashboard` — serve SPA if authenticated, else redirect to authorize.
pub async fn dashboard_index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !state.config.dashboard.enabled {
        return (StatusCode::NOT_FOUND, "dashboard disabled").into_response();
    }
    // Check for valid session cookie.
    if let Some(session_id) = extract_session(&headers, &state.config.jwt_secret) {
        if state.store.get_session(&session_id).is_some() {
            return Html(dashboard_spa()).into_response();
        }
    }
    // No valid session → redirect to OAuth2 authorize.
    let verifier = crate::pkce::random_verifier();
    let challenge = crate::pkce::s256_challenge(&verifier);
    // We can't persist the verifier across the redirect without a session, so
    // we encode it in the state param (it's only used once and short-lived).
    // state = base64(verifier) so callback can recover it.
    let state_param = crate::auth_store::base64_url(verifier.as_bytes());
    let redirect_uri = format!("{}/dashboard/callback", state.config.issuer);
    let auth_url = format!(
        "{issuer}/oauth2/auth?response_type=code&client_id={cid}&redirect_uri={ru}&scope=read+write&state={st}&code_challenge={cc}&code_challenge_method=S256",
        issuer = state.config.issuer,
        cid = DASHBOARD_CLIENT_ID,
        ru = urlencoding::encode(&redirect_uri),
        st = urlencoding::encode(&state_param),
        cc = urlencoding::encode(&challenge),
    );
    Redirect::to(&auth_url).into_response()
}

/// `GET /dashboard/callback` — exchange code, create session, set cookie.
pub async fn dashboard_callback(
    State(state): State<AppState>,
    Query(params): Query<CallbackParams>,
) -> Response {
    if let Some(err) = params.error {
        let body = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>uteke — Login Failed</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
</head>
<body class="d-flex align-items-center justify-content-center min-vh-100 bg-light">
<div class="card shadow-sm" style="max-width:420px;">
  <div class="card-body p-4 text-center">
    <i class="bi bi-x-octagon fs-1 text-danger"></i>
    <h1 class="h4 mt-2">Login failed</h1>
    <p class="text-muted">{}</p>
    <a href="/dashboard" class="btn btn-outline-primary btn-sm"><i class="bi bi-arrow-left"></i> Back</a>
  </div>
</div>
</body>
</html>"#,
            html_escape(&err)
        );
        return (StatusCode::BAD_REQUEST, Html(body)).into_response();
    }
    let code = match params.code {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "missing code").into_response(),
    };
    let state_param = params.state.unwrap_or_default();
    // Recover the PKCE verifier from state.
    let verifier = match crate::auth_store::base64_url_decode(&state_param) {
        Some(v) => String::from_utf8(v).unwrap_or_default(),
        None => return (StatusCode::BAD_REQUEST, "invalid state").into_response(),
    };
    // Exchange code for access token via the token endpoint (internal HTTP call).
    let token_url = format!("{}/oauth2/token", state.config.issuer);
    let redirect_uri = format!("{}/dashboard/callback", state.config.issuer);
    let token_resp = state
        .http_client
        .post(&token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", DASHBOARD_CLIENT_ID),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await;
    let token_json: serde_json::Value = match token_resp {
        Ok(r) if r.status().is_success() => r.json().await.unwrap_or(serde_json::json!({})),
        Ok(r) => {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            tracing::warn!("token exchange failed: {status} {body}");
            return (StatusCode::BAD_GATEWAY, "token exchange failed").into_response();
        }
        Err(e) => {
            tracing::warn!("token exchange error: {e}");
            return (StatusCode::BAD_GATEWAY, "token exchange error").into_response();
        }
    };
    let access_token = token_json
        .get("access_token")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if access_token.is_empty() {
        return (StatusCode::BAD_GATEWAY, "no access token in response").into_response();
    }
    // Fetch /profile to get username.
    let profile_url = format!("{}/profile", state.config.issuer);
    let profile_resp = state
        .http_client
        .get(&profile_url)
        .header("authorization", format!("Bearer {access_token}"))
        .send()
        .await;
    let username = match profile_resp {
        Ok(r) if r.status().is_success() => {
            let pj: serde_json::Value = r.json().await.unwrap_or_default();
            pj.get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        }
        _ => String::new(),
    };
    if username.is_empty() {
        return (StatusCode::BAD_GATEWAY, "failed to fetch profile").into_response();
    }
    // Create server-side session.
    let session_id = session::new_session_id();
    let csrf_token = session::new_csrf_token();
    let ttl = (state.config.dashboard.session_ttl_hours as i64) * 3600;
    if let Err(e) = state
        .store
        .add_session(&session_id, &username, &csrf_token, ttl)
    {
        tracing::error!("session store error: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "session error").into_response();
    }
    // Set signed cookie + CSRF cookie, redirect to /dashboard.
    // SameSite=Lax (not Strict) — allows cookie on top-level redirect from
    // OAuth2 callback. Lax still blocks cross-site POST (CSRF protection).
    let signed = session::sign_session_cookie(&session_id, &state.config.jwt_secret);
    let secure = state.config.issuer.starts_with("https://");
    let secure_flag = if secure { "; Secure" } else { "" };
    let cookie_val = format!(
        "{SESSION_COOKIE}={signed}; Path=/; HttpOnly; SameSite=Lax{secure_flag}; Max-Age={ttl}"
    );
    let csrf_cookie =
        format!("{CSRF_COOKIE}={csrf_token}; Path=/; SameSite=Lax{secure_flag}; Max-Age={ttl}");
    let mut headers = HeaderMap::new();
    headers.append(
        "set-cookie",
        HeaderValue::from_str(&cookie_val).unwrap_or(HeaderValue::from_static("")),
    );
    headers.append(
        "set-cookie",
        HeaderValue::from_str(&csrf_cookie).unwrap_or(HeaderValue::from_static("")),
    );
    (headers, Redirect::to("/dashboard")).into_response()
}

/// `POST /dashboard/logout` — delete session, clear cookies.
pub async fn dashboard_logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(session_id) = extract_session(&headers, &state.config.jwt_secret) {
        let _ = state.store.delete_session(&session_id);
    }
    let mut out = HeaderMap::new();
    out.append(
        "set-cookie",
        HeaderValue::from_str(&format!("{SESSION_COOKIE}=; Path=/; Max-Age=0"))
            .unwrap_or(HeaderValue::from_static("")),
    );
    out.append(
        "set-cookie",
        HeaderValue::from_str(&format!("{CSRF_COOKIE}=; Path=/; Max-Age=0"))
            .unwrap_or(HeaderValue::from_static("")),
    );
    (out, Redirect::to("/dashboard")).into_response()
}

// ── SPA HTML ────────────────────────────────────────────────────────────────

fn dashboard_spa() -> String {
    r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>uteke — Dashboard</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
<style>
  body { background: #f1f5f9; }
  .stat-num { font-size: 1.35rem; font-weight: 700; line-height: 1.1; }
  .stat-label { font-size: 0.7rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.04em; }
  .content-cell { max-width: 420px; }
  .content-cell .trunc { display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; cursor: pointer; }
  .id-mono { font-family: ui-monospace, monospace; font-size: 0.76rem; color: #64748b; cursor: pointer; }
  .tag-pill { cursor: pointer; }
  .imp-bar { width: 64px; height: 6px; background: #e2e8f0; border-radius: 999px; overflow: hidden; display: inline-block; vertical-align: middle; }
  .imp-bar > span { display: block; height: 100%; }
  .type-badge { text-transform: lowercase; font-weight: 600; font-size: 0.72rem; }
  .type-text { text-transform: lowercase; font-weight: 600; font-size: 0.82rem; }
  .table td { vertical-align: middle; }
  .table thead th { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em; color: #64748b; }
  .chips { display: flex; flex-wrap: wrap; gap: 0.3rem; padding: 0.35rem; border: 1px solid #dee2e6; border-radius: 0.375rem; min-height: 2.6rem; align-items: center; }
  .chip { display: inline-flex; align-items: center; gap: 0.3rem; background: #e0f2fe; color: #0369a1; border-radius: 999px; padding: 0.1rem 0.5rem; font-size: 0.78rem; }
  .chip .chip-x { background: transparent; border: none; color: #0369a1; padding: 0; font-size: 0.85rem; line-height: 1; cursor: pointer; }
  .chips input { border: none; outline: none; flex: 1; min-width: 120px; padding: 0.2rem; font-size: 0.85rem; background: transparent; }
  .toast-container { z-index: 1100; }
  .cursor-pointer { cursor: pointer; }
</style>
</head>
<body>
<nav class="navbar navbar-dark bg-dark px-3 py-2">
  <span class="navbar-brand mb-0 h1">uteke Dashboard</span>
  <div class="d-flex align-items-center gap-3">
    <span class="text-secondary small" id="user-label">—</span>
    <button class="btn btn-sm btn-outline-light" onclick="logout()"><i class="bi bi-box-arrow-right"></i> Logout</button>
  </div>
</nav>

<main class="container-fluid py-3" style="max-width:1180px;">
  <!-- Stats -->
  <div class="row g-2 mb-3" id="stats"></div>

  <!-- Controls -->
  <div class="card mb-3">
    <div class="card-body">
      <div class="row g-2 align-items-end">
        <div class="col-md-4">
          <label class="form-label small text-muted mb-1">Search</label>
          <input id="q" class="form-control form-control-sm" placeholder="Query (semantic / keyword)…">
        </div>
        <div class="col-6 col-md-2">
          <label class="form-label small text-muted mb-1">Mode</label>
          <select id="mode" class="form-select form-select-sm">
            <option value="list">Browse</option>
            <option value="semantic">Semantic</option>
            <option value="fts">Keyword</option>
          </select>
        </div>
        <div class="col-6 col-md-2">
          <label class="form-label small text-muted mb-1">Namespace</label>
          <select id="ns" class="form-select form-select-sm"></select>
        </div>
        <div class="col-6 col-md-2">
          <label class="form-label small text-muted mb-1">Tag</label>
          <select id="tag" class="form-select form-select-sm"></select>
        </div>
        <div class="col-6 col-md-2">
          <label class="form-label small text-muted mb-1">Sort</label>
          <select id="sort" class="form-select form-select-sm">
            <option value="created:desc">Newest</option>
            <option value="created:asc">Oldest</option>
            <option value="importance:desc">Importance ↓</option>
            <option value="importance:asc">Importance ↑</option>
            <option value="memory_type:asc">Type</option>
            <option value="id:asc">ID</option>
          </select>
        </div>
        <div class="col-12 d-flex gap-2">
          <button class="btn btn-sm btn-outline-secondary" onclick="resetFilters()"><i class="bi bi-arrow-counterclockwise"></i> Reset</button>
          <button class="btn btn-sm btn-primary" onclick="openCreate()"><i class="bi bi-plus-lg"></i> New memory</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Table -->
  <div class="card">
    <div class="table-responsive">
      <table class="table table-sm table-hover mb-0 align-middle">
        <thead>
          <tr>
            <th style="width:28px;">★</th>
            <th class="content-cell">Content</th>
            <th>Tags</th>
            <th>Type</th>
            <th>Imp.</th>
            <th>Created</th>
            <th>ID</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    <div id="empty" class="text-center text-muted py-4" style="display:none;">No memories.</div>
    <div class="card-footer d-flex justify-content-end align-items-center gap-2">
      <span class="text-muted small me-2" id="page-info"></span>
      <nav><ul class="pagination pagination-sm mb-0" id="pager"></ul></nav>
    </div>
  </div>
</main>

<!-- Detail modal -->
<div class="modal fade" id="m-detail" tabindex="-1">
  <div class="modal-dialog modal-lg">
    <div class="modal-content">
      <div class="modal-header"><h5 class="modal-title">Memory detail</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
      <div class="modal-body" id="detail-body"></div>
      <div class="modal-footer">
        <button class="btn btn-outline-secondary" data-bs-dismiss="modal">Close</button>
        <button class="btn btn-warning" onclick="editFromDetail()"><i class="bi bi-pencil"></i> Edit</button>
        <button class="btn btn-danger" onclick="forgetFromDetail()"><i class="bi bi-trash"></i> Forget</button>
      </div>
    </div>
  </div>
</div>

<!-- Create modal -->
<div class="modal fade" id="m-create" tabindex="-1">
  <div class="modal-dialog modal-lg">
    <div class="modal-content">
      <div class="modal-header"><h5 class="modal-title">New memory</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
      <div class="modal-body">
        <div class="mb-3"><label class="form-label">Content</label><textarea id="c-content" class="form-control" rows="4"></textarea></div>
        <div class="mb-3"><label class="form-label">Tags</label><div class="chips" id="c-tags"></div></div>
        <div class="row g-3">
          <div class="col-md-6"><label class="form-label">Namespace</label><input id="c-ns" class="form-control" list="ns-list" placeholder="default"></div>
          <div class="col-md-6"><label class="form-label">Type</label><select id="c-type" class="form-select"></select></div>
        </div>
        <datalist id="ns-list"></datalist>
      </div>
      <div class="modal-footer">
        <button class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
        <button class="btn btn-primary" onclick="submitCreate()"><i class="bi bi-save"></i> Save</button>
      </div>
    </div>
  </div>
</div>

<!-- Edit modal -->
<div class="modal fade" id="m-edit" tabindex="-1">
  <div class="modal-dialog modal-lg">
    <div class="modal-content">
      <div class="modal-header"><h5 class="modal-title">Edit memory</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
      <div class="modal-body">
        <div class="mb-3"><label class="form-label">Content</label><textarea id="e-content" class="form-control" rows="4"></textarea></div>
        <div class="mb-3"><label class="form-label">Tags</label><div class="chips" id="e-tags"></div></div>
        <div class="row g-3">
          <div class="col-md-4"><label class="form-label">Type</label><select id="e-type" class="form-select"></select></div>
          <div class="col-md-4">
            <label class="form-label">Importance <span id="e-imp-val" class="text-muted"></span></label>
            <input type="range" id="e-imp" class="form-range" min="0" max="1" step="0.05">
          </div>
          <div class="col-md-4 d-flex align-items-end">
            <div class="form-check"><input class="form-check-input" type="checkbox" id="e-pin"><label class="form-check-label" for="e-pin"> Pin ★</label></div>
          </div>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
        <button class="btn btn-primary" onclick="submitEdit()"><i class="bi bi-save"></i> Save</button>
      </div>
    </div>
  </div>
</div>

<!-- Forget confirm -->
<div class="modal fade" id="m-forget" tabindex="-1">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-header"><h5 class="modal-title text-danger"><i class="bi bi-exclamation-triangle"></i> Forget memory?</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
      <div class="modal-body"><p id="f-msg" class="text-muted mb-0"></p></div>
      <div class="modal-footer">
        <button class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
        <button class="btn btn-danger" onclick="confirmForget()"><i class="bi bi-trash"></i> Forget</button>
      </div>
    </div>
  </div>
</div>

<div class="toast-container position-fixed bottom-0 start-50 translate-middle-x p-3">
  <div id="toast" class="toast text-bg-dark" role="alert"><div class="d-flex"><div class="toast-body" id="toast-body"></div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div></div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
const TYPES = ["fact","procedure","preference","decision","context","note","insight","reference","event"];
const LIMIT = 20;
let S = { q:"", mode:"list", ns:"", tag:"", sort:"created:desc", offset:0, rows:[], hasMore:false };
let detailMem = null, forgetId = null, editId = null;
let bsModals = {};

function getCSRF(){ return document.cookie.match(/csrf_token=([^;]+)/)?.[1] || ''; }
function $(id){ return document.getElementById(id); }
function esc(s){ return (s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
function shortId(id){ return (id||"").slice(0,8); }
function fmtDate(s){ if(!s) return "—"; const d = new Date(s); if(isNaN(d)) return s; return d.toLocaleString(undefined,{year:"numeric",month:"short",day:"2-digit",hour:"2-digit",minute:"2-digit"}); }
function toast(msg){ $("toast-body").textContent = msg; bsModals.toast.show(); }

// ── Bootstrap modal helpers ──────────────────────────────────────────────
function initModals(){
  ["m-detail","m-create","m-edit","m-forget"].forEach(id => { bsModals[id] = new bootstrap.Modal(document.getElementById(id)); });
  bsModals.toast = new bootstrap.Toast($("toast"), { delay: 1800 });
}
function openModal(id){ bsModals[id].show(); }
function closeModal(id){ bsModals[id].hide(); }

// ── Chip tag editor ──────────────────────────────────────────────────────
function makeChips(el, tags){
  el.innerHTML = "";
  const input = document.createElement("input");
  input.placeholder = "add tag + Enter";
  el._get = () => Array.from(el.querySelectorAll(".chip span")).map(s => s.textContent);
  function addTag(t){
    t = t.trim(); if(!t) return;
    if(el.querySelectorAll(".chip span").length >= 20) return;
    for(const c of el.querySelectorAll(".chip span")){ if(c.textContent===t) return; }
    const chip = document.createElement("span"); chip.className="chip";
    const label = document.createElement("span"); label.textContent=t;
    const x = document.createElement("button"); x.type="button"; x.className="chip-x"; x.textContent="×";
    x.onclick = ()=>{ chip.remove(); };
    chip.appendChild(label); chip.appendChild(x);
    el.insertBefore(chip, input);
  }
  input.onkeydown = (e)=>{
    if(e.key==="Enter" || e.key===","){ e.preventDefault(); addTag(input.value); input.value=""; }
    else if(e.key==="Backspace" && input.value===""){
      const chips = el.querySelectorAll(".chip"); if(chips.length){ chips[chips.length-1].remove(); }
    }
  };
  el.appendChild(input);
  (tags||[]).forEach(addTag);
}

// ── API ──────────────────────────────────────────────────────────────────
async function api(path, opts){
  const res = await fetch(path, opts);
  if(!res.ok){
    let detail = ""; try { detail = (await res.json()).detail || res.statusText; } catch(_){ detail = res.statusText; }
    throw new Error(detail || res.status);
  }
  return res.json();
}
function apiGet(path){ return api(path, {}); }
function apiMutate(path, method, body){
  return api(path, { method, headers: {"Content-Type":"application/json","X-CSRF-Token":getCSRF()}, body: body?JSON.stringify(body):undefined });
}

async function loadProfile(){
  try { const p = await apiGet("/dashboard/api/profile"); $("user-label").textContent = "👤 " + (p.username||"—"); }
  catch(_){ $("user-label").textContent = "—"; }
}
async function loadNamespaces(){
  let list = [""]; try { list = (await apiGet("/dashboard/api/namespaces")) || []; } catch(_){}
  const sel = $("ns"); const dl = $("ns-list");
  sel.innerHTML = '<option value="">All namespaces</option>' + list.map(n=>`<option value="${esc(n)}">${esc(n)}</option>`).join("");
  dl.innerHTML = list.map(n=>`<option value="${esc(n)}">`).join("");
  sel.value = S.ns;
}
async function loadTags(){
  let tags = []; try { tags = await apiGet("/dashboard/api/tags"+(S.ns?("?namespace="+encodeURIComponent(S.ns)):"")); } catch(_){}
  const sel = $("tag");
  sel.innerHTML = '<option value="">All tags</option>' + tags.map(t=>`<option value="${esc(t.name)}">${esc(t.name)} (${t.count})</option>`).join("");
  sel.value = S.tag;
}
async function loadStats(){
  try {
    const s = await apiGet("/dashboard/api/stats"+(S.ns?("?namespace="+encodeURIComponent(S.ns)):""));
    const cards = [
      ["Memories", s.total_memories, "primary"], ["Tags", s.unique_tags, "info"],
      ["Hot", s.hot, "success"], ["Warm", s.warm, "warning"], ["Cold", s.cold, "secondary"],
    ];
    $("stats").innerHTML = cards.map(([l,n,c])=>`
      <div class="col-6 col-md">
        <div class="card text-center h-100"><div class="card-body py-2 px-2">
          <div class="stat-num text-${c}">${n}</div><div class="stat-label">${l}</div>
        </div></div>
      </div>`).join("");
  } catch(_){ $("stats").innerHTML = ""; }
}

async function load(){
  const params = new URLSearchParams();
  if(S.q) params.set("q", S.q);
  if(S.mode) params.set("mode", S.mode);
  if(S.tag) params.set("tag", S.tag);
  if(S.ns) params.set("namespace", S.ns);
  params.set("limit", LIMIT);
  params.set("offset", S.offset);
  try {
    const data = await apiGet("/dashboard/api/memories?"+params.toString());
    S.rows = data.memories || [];
    S.hasMore = !!data.has_more;
    render();
  } catch(e){ toast("Load failed: "+e.message); }
}

// ── Render ───────────────────────────────────────────────────────────────
function impColor(v){
  if(v >= 0.8) return "#16a34a"; if(v >= 0.5) return "#d97706"; if(v >= 0.3) return "#ea580c"; return "#94a3b8";
}
function applySort(rows){
  const [field, dir] = S.sort.split(":");
  const mul = dir === "asc" ? 1 : -1;
  return [...rows].sort((a,b)=>{
    let va = a[field], vb = b[field];
    if(field === "created"){ va = a.created_at? new Date(a.created_at).getTime():0; vb = b.created_at? new Date(b.created_at).getTime():0; }
    else if(field === "importance"){ va = a.importance??0; vb = b.importance??0; }
    else if(field === "memory_type" || field === "id"){ va = va||""; vb = vb||""; }
    if(va < vb) return -1*mul; if(va > vb) return 1*mul; return 0;
  });
}
function render(){
  const rows = applySort(S.rows);
  const tb = $("rows");
  if(!rows.length){ tb.innerHTML=""; $("empty").style.display="block"; }
  else {
    $("empty").style.display="none";
    tb.innerHTML = rows.map(m=>{
      const tags = (m.tags||[]).map(t=>`<span class="badge bg-info text-white tag-pill me-1" onclick="filterTag('${esc(t)}')">${esc(t)}</span>`).join("");
      const imp = m.importance??0;
      const pin = m.pinned ? "★" : "☆";
      const pinClr = m.pinned ? "text-warning" : "text-secondary";
      return `<tr>
        <td><span class="${pinClr} cursor-pointer" onclick="togglePin('${esc(m.id)}', ${!m.pinned})">${pin}</span></td>
        <td class="content-cell"><div class="trunc" onclick="openDetail('${esc(m.id)}')">${esc(m.content)}</div></td>
        <td>${tags}</td>
        <td><span class="text-${typeColor(m.memory_type||"note")} type-text">${esc(m.memory_type||"note")}</span></td>
        <td><span class="imp-bar"><span style="width:${Math.round(imp*100)}%;background:${impColor(imp)}"></span></span> <span class="text-muted small">${imp.toFixed(2)}</span></td>
        <td style="white-space:nowrap" class="small">${fmtDate(m.created_at)}</td>
        <td><span class="id-mono" onclick="openDetail('${esc(m.id)}')">${esc(shortId(m.id))}</span></td>
        <td>
          <div class="btn-group btn-group-sm">
            <button class="btn btn-outline-secondary" onclick="openDetail('${esc(m.id)}')"><i class="bi bi-eye"></i></button>
            <button class="btn btn-outline-primary" onclick="openEdit('${esc(m.id)}')"><i class="bi bi-pencil"></i></button>
            <button class="btn btn-outline-danger" onclick="openForget('${esc(m.id)}', '${esc(shortId(m.id))}')"><i class="bi bi-trash"></i></button>
          </div>
        </td>
      </tr>`;
    }).join("");
  }
  const page = Math.floor(S.offset / LIMIT) + 1;
  // Build Bootstrap pagination with page numbers.
  // We only know "has_more" (next page exists), not total count, so we
  // render a sliding window: show current page, ±2 neighbors, plus first/last
  // if far away. Since total is unknown, we treat hasMore=false as the last page.
  const pager = $("pager");
  const canPrev = S.offset > 0;
  const canNext = S.hasMore;
  // Estimate total pages: if no hasMore, current page is the last.
  // Otherwise we know there's at least one more page.
  const totalPages = canNext ? page + 1 : page;
  // Build page list: show up to 5 numbers around current.
  let startP = Math.max(1, page - 2);
  let endP = Math.min(totalPages, page + 2);
  // Expand window if we're near the start.
  if (endP - startP < 4 && totalPages > 5) { endP = Math.min(totalPages, startP + 4); }
  if (endP - startP < 4 && startP > 1) { startP = Math.max(1, endP - 4); }
  let html = "";
  // Prev
  html += `<li class="page-item ${canPrev ? "" : "disabled"}"><a class="page-link" href="#" onclick="pagePrev();return false;">&laquo;</a></li>`;
  // First + ellipsis
  if (startP > 1) {
    html += `<li class="page-item"><a class="page-link" href="#" onclick="goToPage(1);return false;">1</a></li>`;
    if (startP > 2) { html += `<li class="page-item disabled"><span class="page-link">&hellip;</span></li>`; }
  }
  // Page numbers
  for (let p = startP; p <= endP; p++) {
    html += `<li class="page-item ${p === page ? "active" : ""}"><a class="page-link" href="#" onclick="goToPage(${p});return false;">${p}</a></li>`;
  }
  // Ellipsis + last (only if we know there are more pages beyond endP)
  if (canNext && endP < totalPages) {
    if (endP < totalPages - 1) { html += `<li class="page-item disabled"><span class="page-link">&hellip;</span></li>`; }
    html += `<li class="page-item"><a class="page-link" href="#" onclick="goToPage(${totalPages});return false;">${totalPages}</a></li>`;
  }
  // Next
  html += `<li class="page-item ${canNext ? "" : "disabled"}"><a class="page-link" href="#" onclick="pageNext();return false;">&raquo;</a></li>`;
  pager.innerHTML = html;
  $("page-info").textContent = `Page ${page}` + (S.hasMore ? " (more available)" : "");
}
function typeColor(t){
  const map = { fact:"primary", procedure:"success", preference:"info", decision:"warning", context:"secondary", note:"light", insight:"danger", reference:"info", event:"dark" };
  return map[t] || "secondary";
}

// ── Filters / paging ─────────────────────────────────────────────────────
let debounceT = null;
function onSearchInput(){
  clearTimeout(debounceT);
  debounceT = setTimeout(()=>{
    S.q = $("q").value.trim();
    S.offset = 0;
    if(!S.q && (S.mode==="semantic"||S.mode==="fts")){ S.mode="list"; $("mode").value="list"; }
    load();
  }, 300);
}
function onModeChange(){ S.mode = $("mode").value; S.offset = 0; if((S.mode==="semantic"||S.mode==="fts") && !S.q){ $("q").focus(); } load(); }
function onNsChange(){ S.ns = $("ns").value; S.offset = 0; loadTags(); loadStats(); load(); }
function onTagChange(){ S.tag = $("tag").value; S.offset = 0; load(); }
function onSortChange(){ S.sort = $("sort").value; render(); }
function filterTag(t){ $("tag").value = t; S.tag = t; S.offset = 0; load(); }
function resetFilters(){ S={q:"",mode:"list",ns:"",tag:"",sort:"created:desc",offset:0,rows:[],hasMore:false}; $("q").value=""; $("mode").value="list"; $("ns").value=""; $("tag").value=""; $("sort").value="created:desc"; loadTags(); loadStats(); load(); }
function pagePrev(){ if(S.offset>=LIMIT){ S.offset-=LIMIT; load(); } }
function pageNext(){ if(S.hasMore){ S.offset+=LIMIT; load(); } }
function goToPage(p){ const off = (p - 1) * LIMIT; if(off >= 0 && off !== S.offset){ S.offset = off; load(); } }

// ── Detail ───────────────────────────────────────────────────────────────
async function openDetail(id){
  try {
    const m = await apiGet("/dashboard/api/memories/"+encodeURIComponent(id));
    detailMem = m;
    $("detail-body").innerHTML = `
      <dl class="row mb-0">
        <dt class="col-sm-3">ID</dt><dd class="col-sm-9 id-mono">${esc(m.id)}</dd>
        <dt class="col-sm-3">Content</dt><dd class="col-sm-9" style="white-space:pre-wrap;word-break:break-word">${esc(m.content)}</dd>
        <dt class="col-sm-3">Type</dt><dd class="col-sm-9"><span class="badge type-badge bg-${typeColor(m.memory_type||"note")}">${esc(m.memory_type||"note")}</span></dd>
        <dt class="col-sm-3">Tags</dt><dd class="col-sm-9">${(m.tags||[]).map(t=>`<span class="badge bg-info text-white me-1">${esc(t)}</span>`).join("") || "—"}</dd>
        <dt class="col-sm-3">Importance</dt><dd class="col-sm-9"><span class="imp-bar"><span style="width:${Math.round((m.importance??0)*100)}%;background:${impColor(m.importance??0)}"></span></span> ${(m.importance??0).toFixed(2)}</dd>
        <dt class="col-sm-3">Pinned</dt><dd class="col-sm-9">${m.pinned ? "★ yes" : "no"}</dd>
        <dt class="col-sm-3">Namespace</dt><dd class="col-sm-9">${esc(m.namespace||"—")}</dd>
        <dt class="col-sm-3">Created</dt><dd class="col-sm-9">${fmtDate(m.created_at)}</dd>
        ${m.score!=null ? `<dt class="col-sm-3">Score</dt><dd class="col-sm-9">${m.score.toFixed(3)}</dd>` : ""}
      </dl>`;
    openModal("m-detail");
  } catch(e){ toast("Failed: "+e.message); }
}
function editFromDetail(){ if(detailMem){ closeModal("m-detail"); openEdit(detailMem.id); } }
function forgetFromDetail(){ if(detailMem){ const id=detailMem.id; closeModal("m-detail"); openForget(id, shortId(id)); } }

// ── Create ───────────────────────────────────────────────────────────────
function openCreate(){
  $("c-content").value = "";
  makeChips($("c-tags"), []);
  $("c-ns").value = S.ns || "";
  fillTypeSelect($("c-type"), "note");
  openModal("m-create");
}
function fillTypeSelect(sel, val){
  sel.innerHTML = TYPES.map(t=>`<option value="${t}"${t===val?" selected":""}>${t}</option>`).join("");
}
async function submitCreate(){
  const content = $("c-content").value.trim();
  if(!content){ toast("Content required"); return; }
  const tags = $("c-tags")._get();
  const ns = $("c-ns").value.trim();
  const memory_type = $("c-type").value;
  const body = { content, tags };
  if(ns) body.namespace = ns;
  if(memory_type) body.memory_type = memory_type;
  try {
    await apiMutate("/dashboard/api/memories","POST",body);
    closeModal("m-create"); toast("Saved"); loadStats(); load();
  } catch(e){ toast("Save failed: "+e.message); }
}

// ── Edit ─────────────────────────────────────────────────────────────────
async function openEdit(id){
  try {
    const m = await apiGet("/dashboard/api/memories/"+encodeURIComponent(id));
    editId = id;
    $("e-content").value = m.content || "";
    makeChips($("e-tags"), m.tags || []);
    fillTypeSelect($("e-type"), m.memory_type || "note");
    $("e-imp").value = m.importance ?? 0.5;
    $("e-imp-val").textContent = (m.importance??0.5).toFixed(2);
    $("e-pin").checked = !!m.pinned;
    openModal("m-edit");
  } catch(e){ toast("Failed: "+e.message); }
}
async function submitEdit(){
  if(!editId) return;
  const body = {
    content: $("e-content").value,
    tags: $("e-tags")._get(),
    memory_type: $("e-type").value,
    importance: parseFloat($("e-imp").value),
    pinned: $("e-pin").checked,
  };
  try {
    await apiMutate("/dashboard/api/memories/"+encodeURIComponent(editId),"PUT",body);
    closeModal("m-edit"); toast("Updated"); loadStats(); load();
  } catch(e){ toast("Update failed: "+e.message); }
}

// ── Pin toggle ───────────────────────────────────────────────────────────
async function togglePin(id, pinned){
  try {
    await apiMutate("/dashboard/api/memories/"+encodeURIComponent(id),"PUT",{ pinned });
    toast(pinned ? "Pinned ★" : "Unpinned");
    load();
  } catch(e){ toast("Failed: "+e.message); }
}

// ── Forget ───────────────────────────────────────────────────────────────
function openForget(id, label){
  forgetId = id;
  $("f-msg").textContent = `Forget memory ${label}? This is a soft-delete.`;
  openModal("m-forget");
}
async function confirmForget(){
  if(!forgetId) return;
  try {
    await apiMutate("/dashboard/api/memories/"+encodeURIComponent(forgetId),"DELETE");
    closeModal("m-forget"); toast("Forgotten"); loadStats(); load();
  } catch(e){ toast("Forget failed: "+e.message); }
}

async function logout(){
  await fetch("/dashboard/logout",{method:"POST",headers:{"X-CSRF-Token":getCSRF()}});
  window.location.href = "/dashboard";
}

// ── Init ─────────────────────────────────────────────────────────────────
function init(){
  initModals();
  $("q").addEventListener("input", onSearchInput);
  $("mode").addEventListener("change", onModeChange);
  $("ns").addEventListener("change", onNsChange);
  $("tag").addEventListener("change", onTagChange);
  $("sort").addEventListener("change", onSortChange);
  $("e-imp").addEventListener("input", e => $("e-imp-val").textContent = parseFloat(e.target.value).toFixed(2));
  loadProfile(); loadNamespaces(); loadTags(); loadStats(); load();
}
init();
</script>
</body>
</html>"##.to_string()
}
// ── Helpers ─────────────────────────────────────────────────────────────────

pub(crate) fn extract_session(headers: &HeaderMap, secret: &str) -> Option<String> {
    let cookie = headers.get("cookie")?.to_str().ok()?;
    for pair in cookie.split(';') {
        let pair = pair.trim();
        if let Some(rest) = pair.strip_prefix(&format!("{SESSION_COOKIE}=")) {
            return session::verify_session_cookie(rest, secret);
        }
    }
    None
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub(crate) fn api_unauthorized(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "unauthorized", "detail": msg })),
    )
        .into_response()
}

pub(crate) fn api_forbidden(msg: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": "forbidden", "detail": msg })),
    )
        .into_response()
}

pub(crate) fn api_error(code: StatusCode, msg: &str) -> Response {
    (
        code,
        Json(serde_json::json!({ "error": "proxy_error", "detail": msg })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_basic() {
        assert_eq!(html_escape("a<b>c"), "a&lt;b&gt;c");
    }
}
