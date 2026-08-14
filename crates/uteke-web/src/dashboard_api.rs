//! Dashboard typed API layer (M7.1) — browser-facing REST handlers that
//! translate clean `/dashboard/api/*` contracts into uteke-server calls.
//!
//! The browser never sees the upstream endpoint shape; this module is the
//! "translator". All handlers require a valid session cookie; mutations
//! (POST/PUT/DELETE) additionally require a matching CSRF token.
//!
//! Contract: see PLAN-WEB.md §4.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde::{Deserialize, Serialize};

use uteke_core::DEFAULT_NAMESPACE;
use uteke_core::memory::types::{Memory, SearchResult, StoreStats, TagInfo, UnifiedSearchResult};
use uteke_core::{Document, DocumentSearchResult, DocumentSummary};

use crate::auth_store::Session;
use crate::state::AppState;

use crate::dashboard::{CSRF_HEADER, api_error, api_forbidden, api_unauthorized, extract_session};

/// Default page size for browse/list.
const DEFAULT_PAGE_LIMIT: usize = 20;
/// Hard cap on page size (matches uteke-server MAX_LIMIT).
const MAX_PAGE_LIMIT: usize = 100;
/// Cap for search-mode fetches (recall/search have no offset pagination, so
/// we fetch a window and slice client-side).
const SEARCH_FETCH_CAP: usize = 100;

// ── Typed response structs (browser-facing) ─────────────────────────────────

/// Normalized memory row for the SPA table. Same shape regardless of whether
/// the source was list (Memory), semantic recall (UnifiedSearchResult), or
/// keyword search (SearchResult).
#[derive(Debug, Clone, Serialize)]
pub struct DashboardMemory {
    pub id: String,
    pub content: String,
    pub tags: Vec<String>,
    pub memory_type: String,
    pub importance: f64,
    pub pinned: bool,
    pub created_at: String,
    pub namespace: String,
    /// Relevance score (only set for semantic/fts modes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
}

impl From<Memory> for DashboardMemory {
    fn from(m: Memory) -> Self {
        Self {
            id: m.id,
            content: m.content,
            tags: m.tags,
            memory_type: m.memory_type,
            importance: m.importance,
            pinned: m.pinned,
            created_at: m.created_at.to_rfc3339(),
            namespace: m.namespace,
            score: None,
        }
    }
}

impl From<SearchResult> for DashboardMemory {
    fn from(r: SearchResult) -> Self {
        let score = r.score;
        let mut d = DashboardMemory::from(r.memory);
        d.score = Some(score);
        d
    }
}

impl From<UnifiedSearchResult> for DashboardMemory {
    fn from(r: UnifiedSearchResult) -> Self {
        Self {
            id: r.memory_id.unwrap_or_default(),
            content: r.content,
            tags: r.tags,
            memory_type: r.memory_type.unwrap_or_else(|| "note".to_string()),
            importance: r.importance.unwrap_or(0.5),
            pinned: r.pinned.unwrap_or(false),
            created_at: r.created_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
            namespace: r.namespace.unwrap_or_else(|| DEFAULT_NAMESPACE.to_string()),
            score: Some(r.score),
        }
    }
}

/// Paginated list envelope returned by `GET /dashboard/api/memories`.
#[derive(Debug, Serialize)]
pub struct MemoryListResponse {
    pub memories: Vec<DashboardMemory>,
    pub limit: usize,
    pub offset: usize,
    pub has_more: bool,
    pub mode: String,
}

/// `GET /dashboard/api/memories` query params.
#[derive(Debug, Deserialize)]
pub struct MemoryQuery {
    #[serde(default)]
    pub q: Option<String>,
    /// "semantic" | "fts" | "list" (default: list).
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default = "default_page_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

fn default_page_limit() -> usize {
    DEFAULT_PAGE_LIMIT
}

/// `POST /dashboard/api/memories` body.
#[derive(Debug, Deserialize)]
pub struct CreateMemoryRequest {
    pub content: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub namespace: Option<String>,
    /// Fixed taxonomy (fact/procedure/preference/decision/context/note/
    /// insight/reference/event). Validated against the core taxonomy.
    #[serde(default)]
    pub memory_type: Option<String>,
}

/// `PUT /dashboard/api/memories/{id}` body.
#[derive(Debug, Deserialize)]
pub struct UpdateMemoryRequest {
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub memory_type: Option<String>,
    #[serde(default)]
    pub importance: Option<f64>,
    #[serde(default)]
    pub pinned: Option<bool>,
}

/// `GET /dashboard/api/tags` query params.
#[derive(Debug, Deserialize)]
pub struct TagsQuery {
    #[serde(default)]
    pub namespace: Option<String>,
}

/// `GET /dashboard/api/stats` query params.
#[derive(Debug, Deserialize)]
pub struct StatsQuery {
    #[serde(default)]
    pub namespace: Option<String>,
}

// ── Upstream client ─────────────────────────────────────────────────────────

/// Thin wrapper over `AppState` that injects the static upstream token on
/// every call to uteke-server.
struct UtekeClient<'a> {
    state: &'a AppState,
}

impl<'a> UtekeClient<'a> {
    fn new(state: &'a AppState) -> Self {
        Self { state }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.state.config.upstream, path)
    }

    async fn get(&self, path: &str) -> Result<reqwest::Response, reqwest::Error> {
        let mut h = HeaderMap::new();
        self.state.apply_upstream_auth(&mut h);
        self.state
            .http_client
            .get(self.url(path))
            .headers(h)
            .send()
            .await
    }

    async fn post<T: Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let mut h = HeaderMap::new();
        self.state.apply_upstream_auth(&mut h);
        self.state
            .http_client
            .post(self.url(path))
            .headers(h)
            .json(body)
            .send()
            .await
    }

    async fn put<T: Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let mut h = HeaderMap::new();
        self.state.apply_upstream_auth(&mut h);
        self.state
            .http_client
            .put(self.url(path))
            .headers(h)
            .json(body)
            .send()
            .await
    }

    async fn delete(&self, path: &str) -> Result<reqwest::Response, reqwest::Error> {
        let mut h = HeaderMap::new();
        self.state.apply_upstream_auth(&mut h);
        self.state
            .http_client
            .delete(self.url(path))
            .headers(h)
            .send()
            .await
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Validate a session cookie and return the live session, or an error response.
#[allow(clippy::result_large_err)]
fn require_session(state: &AppState, headers: &HeaderMap) -> Result<Session, Response> {
    let sid = extract_session(headers, &state.config.jwt_secret)
        .ok_or_else(|| api_unauthorized("no session"))?;
    state
        .store
        .get_session(&sid)
        .ok_or_else(|| api_unauthorized("session expired"))
}

/// Validate the CSRF double-submit token for mutations.
#[allow(clippy::result_large_err)]
fn require_csrf(sess: &Session, headers: &HeaderMap) -> Result<(), Response> {
    let tok = headers
        .get(CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !tok.is_empty() && tok == sess.csrf_token {
        Ok(())
    } else {
        Err(api_forbidden("CSRF token missing or mismatched"))
    }
}

/// Convert a reqwest error into a gateway error response.
fn upstream_err(e: reqwest::Error) -> Response {
    if e.is_timeout() {
        api_error(StatusCode::GATEWAY_TIMEOUT, "upstream timeout")
    } else {
        api_error(StatusCode::BAD_GATEWAY, "upstream unavailable")
    }
}

/// Read + deserialize a successful upstream JSON response, preserving the
/// upstream status code on failure.
async fn parse_json<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, Response> {
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let code =
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        return Err(api_error(code, &body));
    }
    resp.json::<T>().await.map_err(|e| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("upstream decode error: {e}"),
        )
    })
}

/// Resolve a memory_type string against the fixed taxonomy; returns None if
/// empty/invalid. Used to validate create/update payloads.
fn normalize_memory_type(s: &Option<String>) -> Option<String> {
    s.as_deref()
        .filter(|t| !t.is_empty())
        .and_then(uteke_core::MemoryType::from_str_opt)
        .map(|t| t.as_str().to_string())
}

/// Fetch a single memory by id and convert to DashboardMemory.
async fn fetch_memory(client: &UtekeClient<'_>, id: &str) -> Result<DashboardMemory, Response> {
    let resp = client
        .get(&format!("/memory?id={}", urlencoding::encode(id)))
        .await
        .map_err(upstream_err)?;
    let mem: Memory = parse_json(resp).await?;
    Ok(DashboardMemory::from(mem))
}

// ── Handlers ────────────────────────────────────────────────────────────────

/// `GET /dashboard/api/memories` — browse / search (list·semantic·fts).
pub async fn handle_list_memories(
    State(state): State<AppState>,
    Query(q): Query<MemoryQuery>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };

    let client = UtekeClient::new(&state);
    let limit = q.limit.clamp(1, MAX_PAGE_LIMIT);
    let offset = q.offset;
    let query = q.q.as_deref().unwrap_or("").trim().to_string();
    // Search modes require a non-empty query; otherwise fall back to browse.
    let mode = q.mode.as_deref().unwrap_or("list").to_string();
    let mode = if (mode == "semantic" || mode == "fts") && query.is_empty() {
        "list".to_string()
    } else {
        mode
    };

    match mode.as_str() {
        "semantic" => {
            // POST /recall {query, limit, search_type:"memory", strategy:"hybrid", tags?, namespace?}
            let fetch_limit = (offset + limit + 1).min(SEARCH_FETCH_CAP);
            let mut body = serde_json::json!({
                "query": query,
                "limit": fetch_limit,
                "search_type": "memory",
                "strategy": "hybrid",
            });
            if let Some(t) = q.tag.as_deref().filter(|t| !t.is_empty()) {
                body["tags"] = serde_json::json!([t]);
            }
            if let Some(ns) = q.namespace.as_deref().filter(|n| !n.is_empty()) {
                body["namespace"] = serde_json::json!(ns);
            }
            let resp = match client.post("/recall", &body).await {
                Ok(r) => r,
                Err(e) => return upstream_err(e),
            };
            let results: Vec<UnifiedSearchResult> = match parse_json(resp).await {
                Ok(v) => v,
                Err(r) => return r,
            };
            let total = results.len();
            let slice: Vec<DashboardMemory> = results
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(DashboardMemory::from)
                .collect();
            let has_more = total > offset + limit;
            Json(MemoryListResponse {
                memories: slice,
                limit,
                offset,
                has_more,
                mode,
            })
            .into_response()
        }
        "fts" => {
            // POST /search {query, limit, tags?, namespace?}
            let fetch_limit = (offset + limit + 1).min(SEARCH_FETCH_CAP);
            let mut body = serde_json::json!({
                "query": query,
                "limit": fetch_limit,
            });
            if let Some(t) = q.tag.as_deref().filter(|t| !t.is_empty()) {
                body["tags"] = serde_json::json!([t]);
            }
            if let Some(ns) = q.namespace.as_deref().filter(|n| !n.is_empty()) {
                body["namespace"] = serde_json::json!(ns);
            }
            let resp = match client.post("/search", &body).await {
                Ok(r) => r,
                Err(e) => return upstream_err(e),
            };
            let results: Vec<SearchResult> = match parse_json(resp).await {
                Ok(v) => v,
                Err(r) => return r,
            };
            let total = results.len();
            let slice: Vec<DashboardMemory> = results
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(DashboardMemory::from)
                .collect();
            let has_more = total > offset + limit;
            Json(MemoryListResponse {
                memories: slice,
                limit,
                offset,
                has_more,
                mode,
            })
            .into_response()
        }
        // "list" (default)
        _ => {
            // POST /list {limit, offset, tag?, namespace?}
            let mut body = serde_json::json!({
                "limit": limit,
                "offset": offset,
            });
            if let Some(t) = q.tag.as_deref().filter(|t| !t.is_empty()) {
                body["tag"] = serde_json::json!(t);
            }
            if let Some(ns) = q.namespace.as_deref().filter(|n| !n.is_empty()) {
                body["namespace"] = serde_json::json!(ns);
            }
            let resp = match client.post("/list", &body).await {
                Ok(r) => r,
                Err(e) => return upstream_err(e),
            };
            let memories: Vec<Memory> = match parse_json(resp).await {
                Ok(v) => v,
                Err(r) => return r,
            };
            let has_more = memories.len() == limit;
            let rows: Vec<DashboardMemory> =
                memories.into_iter().map(DashboardMemory::from).collect();
            Json(MemoryListResponse {
                memories: rows,
                limit,
                offset,
                has_more,
                mode: "list".to_string(),
            })
            .into_response()
        }
    }
}

/// `GET /dashboard/api/memories/{id}` — detail.
pub async fn handle_get_memory(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let client = UtekeClient::new(&state);
    match fetch_memory(&client, &id).await {
        Ok(m) => Json(m).into_response(),
        Err(r) => r,
    }
}

/// `GET /dashboard/api/memories/{id}/doc-refs` — documents referenced by a memory.
/// Wraps upstream `POST /memory/doc-refs` (note: upstream field is `memory_id`).
/// Returns `{ "memory_id": "...", "doc_slugs": [...] }`; empty array when the
/// memory has no `[[doc-slug]]` wikilinks.
pub async fn handle_memory_doc_refs(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let client = UtekeClient::new(&state);
    let body = serde_json::json!({ "memory_id": id });
    let resp = match client.post("/memory/doc-refs", &body).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

/// `POST /dashboard/api/memories` — create.
pub async fn handle_create_memory(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let req: CreateMemoryRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    if req.content.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "content must not be empty");
    }
    let mem_type = normalize_memory_type(&req.memory_type);
    let mut payload = serde_json::json!({
        "content": req.content,
        "tags": req.tags,
    });
    if let Some(ns) = req.namespace.as_deref().filter(|n| !n.is_empty()) {
        payload["namespace"] = serde_json::json!(ns);
    }
    if let Some(t) = mem_type {
        payload["type"] = serde_json::json!(t);
    }
    let client = UtekeClient::new(&state);
    let resp = match client.post("/remember", &payload).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let created: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let id = created
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if id.is_empty() {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "upstream returned no id");
    }
    // Fetch the freshly created memory so the SPA gets a full row back.
    match fetch_memory(&client, &id).await {
        Ok(m) => Json(m).into_response(),
        // Fall back to the bare id if the immediate fetch fails.
        Err(_) => Json(serde_json::json!({ "id": id })).into_response(),
    }
}

/// `PUT /dashboard/api/memories/{id}` — edit.
pub async fn handle_update_memory(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let req: UpdateMemoryRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    let mem_type = normalize_memory_type(&req.memory_type);
    let mut payload = serde_json::json!({ "id": id });
    if let Some(c) = req.content {
        payload["content"] = serde_json::json!(c);
    }
    if let Some(t) = req.tags {
        payload["tags"] = serde_json::json!(t);
    }
    if let Some(t) = mem_type {
        payload["memory_type"] = serde_json::json!(t);
    }
    if let Some(i) = req.importance {
        payload["importance"] = serde_json::json!(i);
    }
    if let Some(p) = req.pinned {
        payload["pinned"] = serde_json::json!(p);
    }
    let client = UtekeClient::new(&state);
    let resp = match client.put("/memory", &payload).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    if let Err(r) = parse_json::<serde_json::Value>(resp).await {
        return r;
    }
    // Return the updated memory.
    match fetch_memory(&client, &id).await {
        Ok(m) => Json(m).into_response(),
        Err(_) => Json(serde_json::json!({ "updated": id })).into_response(),
    }
}

/// `DELETE /dashboard/api/memories/{id}` — forget (soft-delete).
pub async fn handle_forget_memory(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let client = UtekeClient::new(&state);
    let resp = match client
        .delete(&format!("/forget?id={}", urlencoding::encode(&id)))
        .await
    {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

/// `GET /dashboard/api/tags` — tag list with counts.
pub async fn handle_tags(
    State(state): State<AppState>,
    Query(q): Query<TagsQuery>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let client = UtekeClient::new(&state);
    let path = match q.namespace.as_deref().filter(|n| !n.is_empty()) {
        Some(ns) => format!("/tags?namespace={}", urlencoding::encode(ns)),
        None => "/tags".to_string(),
    };
    let resp = match client.get(&path).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let tags: Vec<TagInfo> = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(tags).into_response()
}

/// `GET /dashboard/api/namespaces` — namespace list.
pub async fn handle_namespaces(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let client = UtekeClient::new(&state);
    let resp = match client.get("/namespaces").await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let ns: Vec<String> = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(ns).into_response()
}

/// `GET /dashboard/api/stats` — store stats (optionally scoped to a namespace).
pub async fn handle_stats(
    State(state): State<AppState>,
    Query(q): Query<StatsQuery>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let client = UtekeClient::new(&state);
    let path = match q.namespace.as_deref().filter(|n| !n.is_empty()) {
        Some(ns) => format!("/stats?namespace={}", urlencoding::encode(ns)),
        None => "/stats".to_string(),
    };
    let resp = match client.get(&path).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let stats: StoreStats = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(stats).into_response()
}

/// `GET /dashboard/api/profile` — current user (from session, no upstream call).
pub async fn handle_profile(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    Json(serde_json::json!({ "username": sess.username })).into_response()
}

// ── Documents (PLAN-docs.md) ────────────────────────────────────────────────
//
// Three typed response structs (Opsi A — locked Thoni 2026-08-13):
//   DashboardDocumentSummary   — list & search document field (no content/tags)
//   DashboardDocument          — get/create/update (full content + tags)
//   DashboardDocumentSearchResult — search (summary + chunk info + score + mode)
//
// Upstream `/doc/*` endpoints are all POST (except delete). Browser never sees
// the upstream shape — these handlers translate to clean `/dashboard/api/*`.

/// Default document list limit.
const DEFAULT_DOC_LIMIT: usize = 50;
/// Hard cap on document list limit.
const MAX_DOC_LIMIT: usize = 200;

fn default_doc_limit() -> usize {
    DEFAULT_DOC_LIMIT
}

/// Normalized document summary for list & search results.
/// Wraps `uteke_core::DocumentSummary` — no content/tags (upstream `/doc/list`
/// and `/doc/search` return summaries, not full documents).
#[derive(Debug, Clone, Serialize)]
pub struct DashboardDocumentSummary {
    pub id: String,
    pub slug: String,
    pub title: String,
    /// Parent document UUID (None = root).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// Depth in tree (0 = root).
    pub depth: i64,
    /// Whether this document has children.
    pub has_children: bool,
    /// Manual ordering within siblings.
    pub sort_order: i64,
    /// Version number (incremented on each edit).
    pub version: i64,
    pub updated_at: String,
}

impl From<DocumentSummary> for DashboardDocumentSummary {
    fn from(s: DocumentSummary) -> Self {
        Self {
            id: s.id,
            slug: s.slug,
            title: s.title,
            parent_id: s.parent_id,
            depth: s.depth,
            has_children: s.has_children,
            sort_order: s.sort_order,
            version: s.version,
            updated_at: s.updated_at,
        }
    }
}

/// Full document for get/create/update.
/// Wraps `uteke_core::Document` — includes content, tags, and all metadata.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardDocument {
    pub id: String,
    pub slug: String,
    pub title: String,
    pub content: String,
    pub tags: Vec<String>,
    /// Parent document UUID (None = root).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// Depth in tree (0 = root).
    pub depth: i64,
    /// Whether this document has children.
    pub has_children: bool,
    /// Manual ordering within siblings.
    pub sort_order: i64,
    /// Version number (incremented on each edit).
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Document> for DashboardDocument {
    fn from(d: Document) -> Self {
        Self {
            id: d.id,
            slug: d.slug,
            title: d.title,
            content: d.content,
            tags: d.tags,
            parent_id: d.parent_id,
            depth: d.depth,
            has_children: d.has_children,
            sort_order: d.sort_order,
            version: d.version,
            created_at: d.created_at,
            updated_at: d.updated_at,
        }
    }
}

/// Search result for documents — summary + chunk info + score.
/// Wraps `uteke_core::DocumentSearchResult`.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardDocumentSearchResult {
    #[serde(flatten)]
    pub document: DashboardDocumentSummary,
    pub chunk_heading: String,
    pub chunk_snippet: String,
    pub score: f32,
    pub mode: String,
}

impl From<DocumentSearchResult> for DashboardDocumentSearchResult {
    fn from(r: DocumentSearchResult) -> Self {
        let summary = DashboardDocumentSummary::from(r.document);
        Self {
            document: summary,
            chunk_heading: r.chunk_heading,
            chunk_snippet: r.chunk_snippet,
            score: r.score,
            mode: r.mode,
        }
    }
}

/// `GET /dashboard/api/documents` query params.
#[derive(Debug, Deserialize)]
pub struct DocumentListQuery {
    #[serde(default)]
    pub roots_only: bool,
    /// Parent slug to list children of.
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default = "default_doc_limit")]
    pub limit: usize,
}

/// `GET /dashboard/api/documents/search` query params.
#[derive(Debug, Deserialize)]
pub struct DocumentSearchQuery {
    pub q: String,
    /// "hybrid" | "semantic" | "fts" (default: hybrid).
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default = "default_doc_limit")]
    pub limit: usize,
}

/// `POST /dashboard/api/documents` body.
#[derive(Debug, Deserialize)]
pub struct CreateDocumentRequest {
    pub slug: String,
    #[serde(default)]
    pub title: Option<String>,
    pub content: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Parent slug (None = root).
    #[serde(default)]
    pub parent: Option<String>,
}

/// `PUT /dashboard/api/documents/{slug}` body — partial update.
#[derive(Debug, Deserialize)]
pub struct UpdateDocumentRequest {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

/// `POST /dashboard/api/documents/{slug}/move` body.
#[derive(Debug, Deserialize)]
pub struct MoveDocumentRequest {
    /// New parent slug (None = move to root).
    #[serde(default)]
    pub new_parent: Option<String>,
}

// ── Document handlers ───────────────────────────────────────────────────────

/// `GET /dashboard/api/documents` — list documents (tree/roots/children).
/// Wraps upstream `POST /doc/list`.
pub async fn handle_list_documents(
    State(state): State<AppState>,
    Query(q): Query<DocumentListQuery>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let client = UtekeClient::new(&state);
    let limit = q.limit.clamp(1, MAX_DOC_LIMIT);
    let body = serde_json::json!({
        "limit": limit,
        "roots_only": q.roots_only,
        "parent": q.parent,
    });
    let resp = match client.post("/doc/list", &body).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let docs: Vec<DocumentSummary> = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let rows: Vec<DashboardDocumentSummary> = docs
        .into_iter()
        .map(DashboardDocumentSummary::from)
        .collect();
    Json(rows).into_response()
}

/// `GET /dashboard/api/documents/search` — hybrid/semantic/fts search.
/// Wraps upstream `POST /doc/search`. Read-only (GET, no CSRF).
pub async fn handle_search_documents(
    State(state): State<AppState>,
    Query(q): Query<DocumentSearchQuery>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let query = q.q.trim().to_string();
    if query.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "query (q) must not be empty");
    }
    let mode = q.mode.as_deref().unwrap_or("hybrid").to_string();
    let limit = q.limit.clamp(1, MAX_DOC_LIMIT);
    let client = UtekeClient::new(&state);
    let body = serde_json::json!({
        "query": query,
        "limit": limit,
        "mode": mode,
    });
    let resp = match client.post("/doc/search", &body).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let results: Vec<DocumentSearchResult> = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let rows: Vec<DashboardDocumentSearchResult> = results
        .into_iter()
        .map(DashboardDocumentSearchResult::from)
        .collect();
    Json(rows).into_response()
}

/// Fetch a single document by slug and convert to DashboardDocument.
/// Returns 404 if upstream returns null (slug not found).
async fn fetch_document(
    client: &UtekeClient<'_>,
    slug: &str,
) -> Result<DashboardDocument, Response> {
    let body = serde_json::json!({ "slug": slug });
    let resp = client.post("/doc/get", &body).await.map_err(upstream_err)?;
    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        let code =
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        return Err(api_error(code, &body_text));
    }
    let doc: Option<Document> = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            return Err(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("upstream decode error: {e}"),
            ));
        }
    };
    doc.map(DashboardDocument::from)
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "document not found"))
}

/// `GET /dashboard/api/documents/{slug}` — detail (full document).
/// Wraps upstream `POST /doc/get`. Maps null → 404.
pub async fn handle_get_document(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let client = UtekeClient::new(&state);
    match fetch_document(&client, &slug).await {
        Ok(d) => Json(d).into_response(),
        Err(r) => r,
    }
}

/// `GET /dashboard/api/documents/{slug}/mem-refs` — memories referencing a doc.
/// Wraps upstream `POST /doc/mem-refs` (note: upstream field is `doc_slug`).
pub async fn handle_document_mem_refs(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let client = UtekeClient::new(&state);
    let body = serde_json::json!({ "doc_slug": slug });
    let resp = match client.post("/doc/mem-refs", &body).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

/// `POST /dashboard/api/documents` — create document.
/// Wraps upstream `POST /doc/create`. Requires session + CSRF.
pub async fn handle_create_document(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let req: CreateDocumentRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    if req.slug.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "slug must not be empty");
    }
    if req.content.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "content must not be empty");
    }
    let client = UtekeClient::new(&state);
    let payload = serde_json::json!({
        "slug": req.slug,
        "title": req.title,
        "content": req.content,
        "tags": req.tags,
        "parent": req.parent,
    });
    let resp = match client.post("/doc/create", &payload).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    // #doc/create only returns {id, slug}, not the full Document — fetch it
    // to build a response consistent with the other document endpoints
    // (previously this tried to decode the create response as a full
    // Document and always failed with "upstream decode error").
    let created: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let slug = created
        .get("slug")
        .and_then(|v| v.as_str())
        .unwrap_or(&req.slug);
    match fetch_document(&client, slug).await {
        Ok(d) => Json(d).into_response(),
        Err(r) => r,
    }
}

/// `PUT /dashboard/api/documents/{slug}` — partial update.
/// Wraps upstream `POST /doc/update`. Maps null → 404. Requires session + CSRF.
pub async fn handle_update_document(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let req: UpdateDocumentRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    let client = UtekeClient::new(&state);
    let mut payload = serde_json::json!({ "slug": slug });
    if let Some(t) = req.title {
        payload["title"] = serde_json::json!(t);
    }
    if let Some(c) = req.content {
        payload["content"] = serde_json::json!(c);
    }
    if let Some(t) = req.tags {
        payload["tags"] = serde_json::json!(t);
    }
    let resp = match client.post("/doc/update", &payload).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        let code =
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        return api_error(code, &body_text);
    }
    let doc: Option<Document> = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("upstream decode error: {e}"),
            );
        }
    };
    match doc {
        Some(d) => Json(DashboardDocument::from(d)).into_response(),
        None => api_error(StatusCode::NOT_FOUND, "document not found"),
    }
}

/// `DELETE /dashboard/api/documents/{slug}` — delete + cascade.
/// Wraps upstream `DELETE /doc/delete?id=`. Requires session + CSRF.
pub async fn handle_delete_document(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let client = UtekeClient::new(&state);
    let path = format!("/doc/delete?id={}", urlencoding::encode(&slug));
    let resp = match client.delete(&path).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

/// `POST /dashboard/api/documents/{slug}/move` — move to new parent.
/// Wraps upstream `POST /doc/move`. Requires session + CSRF.
pub async fn handle_move_document(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let req: MoveDocumentRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    let client = UtekeClient::new(&state);
    let payload = serde_json::json!({
        "slug": slug,
        "new_parent": req.new_parent,
    });
    let resp = match client.post("/doc/move", &payload).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

// ── Rooms (PLAN-rooms.md) ───────────────────────────────────────────────────
//
// Typed wrappers around upstream `/room/*` and `/doc/room/*` endpoints.
// Rooms are cross-namespace collaboration spaces — a room links memories
// from multiple agents/namespaces into a shared context.
//
// Dashboard contract:
//   GET    /dashboard/api/rooms                 — list rooms
//   POST   /dashboard/api/rooms                 — create room
//   GET    /dashboard/api/rooms/{id}            — room stats (summary info)
//   DELETE /dashboard/api/rooms/{id}            — delete room
//   GET    /dashboard/api/rooms/{id}/memories   — list memories in room
//   POST   /dashboard/api/rooms/{id}/memories   — add memory to room
//   GET    /dashboard/api/rooms/{id}/documents  — list documents linked to room
//   POST   /dashboard/api/rooms/{id}/documents  — link a document to room
//   DELETE /dashboard/api/rooms/{id}/documents  — unlink a document from room

use uteke_core::{Room, RoomStats};

/// Normalized room row for the SPA table.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardRoom {
    pub id: String,
    pub title: String,
    pub namespace: String,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Room> for DashboardRoom {
    fn from(r: Room) -> Self {
        Self {
            id: r.id,
            title: r.title.unwrap_or_default(),
            namespace: r.namespace,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// `GET /dashboard/api/rooms` query params.
#[derive(Debug, Deserialize)]
pub struct RoomListQuery {
    #[serde(default)]
    pub namespace: Option<String>,
}

/// `POST /dashboard/api/rooms` body.
#[derive(Debug, Deserialize)]
pub struct CreateRoomRequest {
    pub room_id: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub namespace: Option<String>,
}

/// `POST /dashboard/api/rooms/{id}/memories` body.
#[derive(Debug, Deserialize)]
pub struct CreateRoomMemoryRequest {
    pub content: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub memory_type: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
}

/// `POST /dashboard/api/rooms/{id}/documents` body.
#[derive(Debug, Deserialize)]
pub struct LinkRoomDocumentRequest {
    pub doc_slug: String,
}

/// `GET /dashboard/api/rooms/{id}/memories` query params.
#[derive(Debug, Deserialize)]
pub struct RoomMemoriesQuery {
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default = "default_room_limit")]
    pub limit: usize,
}

/// `GET /dashboard/api/rooms/{id}/memories` query params.
fn default_room_limit() -> usize {
    100
}

// ── Room handlers ───────────────────────────────────────────────────────────

/// `GET /dashboard/api/rooms` — list rooms.
/// Wraps upstream `GET /room/list`.
pub async fn handle_list_rooms(
    State(state): State<AppState>,
    Query(q): Query<RoomListQuery>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let client = UtekeClient::new(&state);
    let path = match q.namespace.as_deref().filter(|n| !n.is_empty()) {
        Some(ns) => format!("/room/list?namespace={}", urlencoding::encode(ns)),
        None => "/room/list".to_string(),
    };
    let resp = match client.get(&path).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let rooms: Vec<Room> = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let rows: Vec<DashboardRoom> = rooms.into_iter().map(DashboardRoom::from).collect();
    Json(rows).into_response()
}

/// `POST /dashboard/api/rooms` — create room.
/// Wraps upstream `POST /room/create`. Requires session + CSRF.
pub async fn handle_create_room(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let req: CreateRoomRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    if req.room_id.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "room_id must not be empty");
    }
    let client = UtekeClient::new(&state);
    let mut payload = serde_json::json!({
        "room_id": req.room_id,
        "title": req.title,
    });
    if let Some(ns) = req.namespace.as_deref().filter(|n| !n.is_empty()) {
        payload["namespace"] = serde_json::json!(ns);
    }
    let resp = match client.post("/room/create", &payload).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

/// `GET /dashboard/api/rooms/{id}` — room stats.
/// Wraps upstream `POST /room/stats`.
pub async fn handle_get_room(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let client = UtekeClient::new(&state);
    let body = serde_json::json!({ "room_id": id });
    let resp = match client.post("/room/stats", &body).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        let code =
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        return api_error(code, &body_text);
    }
    let stats: Option<RoomStats> = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("upstream decode error: {e}"),
            );
        }
    };
    match stats {
        Some(s) => Json(s).into_response(),
        None => api_error(StatusCode::NOT_FOUND, "room not found"),
    }
}

/// `DELETE /dashboard/api/rooms/{id}` — delete room.
/// Wraps upstream `DELETE /room/delete?room_id=`. Requires session + CSRF.
pub async fn handle_delete_room(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let client = UtekeClient::new(&state);
    let path = format!("/room/delete?room_id={}", urlencoding::encode(&id));
    let resp = match client.delete(&path).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

/// `GET /dashboard/api/rooms/{id}/memories` — list memories in a room.
/// Wraps upstream `GET /room/memories?room_id=&author=&limit=`.
pub async fn handle_list_room_memories(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<RoomMemoriesQuery>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let client = UtekeClient::new(&state);
    let mut path = format!(
        "/room/memories?room_id={}&limit={}",
        urlencoding::encode(&id),
        q.limit
    );
    if let Some(a) = q.author.as_deref().filter(|a| !a.is_empty()) {
        path.push_str(&format!("&author={}", urlencoding::encode(a)));
    }
    let resp = match client.get(&path).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let memories: Vec<Memory> = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let rows: Vec<DashboardMemory> = memories.into_iter().map(DashboardMemory::from).collect();
    Json(rows).into_response()
}

/// `POST /dashboard/api/rooms/{id}/memories` — add memory to room.
/// Wraps upstream `POST /room/remember`. Requires session + CSRF.
pub async fn handle_create_room_memory(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let req: CreateRoomMemoryRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    if req.content.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "content must not be empty");
    }
    let mem_type = normalize_memory_type(&req.memory_type);
    let client = UtekeClient::new(&state);
    let mut payload = serde_json::json!({
        "room_id": id,
        "content": req.content,
        "tags": req.tags,
    });
    if let Some(t) = mem_type {
        payload["type"] = serde_json::json!(t);
    }
    if let Some(a) = req.author.as_deref().filter(|a| !a.is_empty()) {
        payload["author"] = serde_json::json!(a);
    }
    let resp = match client.post("/room/remember", &payload).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

/// `GET /dashboard/api/rooms/{id}/documents` — list documents linked to room.
/// Wraps upstream `POST /room/document/list`.
pub async fn handle_list_room_documents(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let client = UtekeClient::new(&state);
    let body = serde_json::json!({ "room_id": id });
    let resp = match client.post("/room/document/list", &body).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

/// `POST /dashboard/api/rooms/{id}/documents` — link a document to a room.
/// Wraps upstream `PUT /room/document/add`. Requires session + CSRF.
pub async fn handle_link_room_document(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let req: LinkRoomDocumentRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    if req.doc_slug.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "doc_slug must not be empty");
    }
    let client = UtekeClient::new(&state);
    let payload = serde_json::json!({
        "room_id": id,
        "doc_slug": req.doc_slug,
    });
    let resp = match client.put("/room/document/add", &payload).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

/// `DELETE /dashboard/api/rooms/{id}/documents` — unlink a document from a room.
/// Wraps upstream `DELETE /room/document/remove`. Requires session + CSRF.
pub async fn handle_unlink_room_document(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if let Err(r) = require_csrf(&sess, &headers) {
        return r;
    }
    let req: LinkRoomDocumentRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    let client = UtekeClient::new(&state);
    let payload = serde_json::json!({
        "room_id": id,
        "doc_slug": req.doc_slug,
    });
    // Upstream DELETE expects a JSON body (not query params).
    let mut h = HeaderMap::new();
    state.apply_upstream_auth(&mut h);
    let resp = match client
        .state
        .http_client
        .delete(client.url("/room/document/remove"))
        .headers(h)
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_memory_type_valid() {
        assert_eq!(
            normalize_memory_type(&Some("fact".to_string())),
            Some("fact".to_string())
        );
        assert_eq!(
            normalize_memory_type(&Some("NOTE".to_string())),
            Some("note".to_string())
        );
    }

    #[test]
    fn normalize_memory_type_invalid_returns_none() {
        assert_eq!(normalize_memory_type(&Some("bogus".to_string())), None);
        assert_eq!(normalize_memory_type(&None), None);
        assert_eq!(normalize_memory_type(&Some("".to_string())), None);
    }

    #[test]
    fn dashboard_memory_from_memory_drops_score() {
        let m = Memory {
            id: "abc".into(),
            content: "hello".into(),
            embedding: vec![],
            tags: vec!["t".into()],
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            namespace: "default".into(),
            access_count: 0,
            last_accessed: None,
            deprecated: false,
            valid_from: None,
            valid_until: None,
            memory_type: "note".into(),
            importance: 0.5,
            pinned: false,
            content_type: "text".into(),
            slug: None,
            source: None,
            source_type: "user".into(),
        };
        let d = DashboardMemory::from(m);
        assert_eq!(d.id, "abc");
        assert_eq!(d.content, "hello");
        assert!(d.score.is_none());
    }

    #[test]
    fn dashboard_memory_from_search_result_keeps_score() {
        let m = Memory {
            id: "abc".into(),
            content: "hello".into(),
            embedding: vec![],
            tags: vec![],
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            namespace: "default".into(),
            access_count: 0,
            last_accessed: None,
            deprecated: false,
            valid_from: None,
            valid_until: None,
            memory_type: "fact".into(),
            importance: 0.5,
            pinned: false,
            content_type: "text".into(),
            slug: None,
            source: None,
            source_type: "user".into(),
        };
        let r = SearchResult {
            memory: m,
            score: 0.87,
        };
        let d = DashboardMemory::from(r);
        assert_eq!(d.score, Some(0.87));
    }

    #[test]
    fn dashboard_memory_from_unified_uses_memory_id() {
        let r = UnifiedSearchResult {
            result_type: uteke_core::memory::types::SearchResultType::Memory,
            score: 0.42,
            content: "c".into(),
            memory_id: Some("id1".into()),
            doc_slug: None,
            doc_title: None,
            chunk_heading: None,
            chunk_snippet: None,
            tags: vec!["a".into()],
            metadata: None,
            memory_type: Some("note".into()),
            namespace: Some("ns".into()),
            source: None,
            source_type: None,
            importance: Some(0.9),
            pinned: Some(true),
            access_count: None,
            last_accessed: None,
            created_at: None,
            updated_at: None,
            linked_doc_slugs: None,
            linked_memory_ids: None,
        };
        let d = DashboardMemory::from(r);
        assert_eq!(d.id, "id1");
        assert_eq!(d.score, Some(0.42));
        assert_eq!(d.importance, 0.9);
        assert!(d.pinned);
        assert_eq!(d.namespace, "ns");
    }
}
