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
use uteke_core::memory::types::{
    Memory, SearchResult, SearchResultType, StoreStats, TagInfo, UnifiedSearchResult,
};
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
/// Max collision-retry attempts when auto-generating a slug or room_id.
const SLUG_MAX_RETRIES: usize = 5;
/// Length of the random alphanumeric suffix appended to auto-generated slugs.
const SLUG_SUFFIX_LEN: usize = 6;

// ── Slug / room_id auto-generation ───────────────────────────────────────────
//
// Implements the uteke naming convention (key:uteke_slug_room_id_rule):
//   slug (or room_id) = escaped_title + "-" + random_suffix
//
// escaped_title:
//   1. lowercase(title)
//   2. replace spaces and periods with "-"
//   3. strip non-alphanumeric characters (dashes excluded)
//   4. trim leading/trailing dashes only (consecutive dashes in the
//      middle are NOT collapsed)
//
// random_suffix: 6 alphanumeric characters (a-z0-9)
//
// MANDATORY: check the store for a collision before insert; if a collision
// occurs, regenerate the suffix and retry (max SLUG_MAX_RETRIES attempts).

/// Escape a human-readable title into the slug-safe prefix per the uteke
/// naming convention. Returns an empty string when `title` is empty or
/// contains no alphanumeric characters.
fn escape_title(title: &str) -> String {
    let lower = title.to_lowercase();
    let replaced: String = lower
        .chars()
        .map(|c| if c == ' ' || c == '.' { '-' } else { c })
        .collect();
    let stripped: String = replaced
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    stripped.trim_matches('-').to_string()
}

/// Generate a random alphanumeric suffix of `len` characters (a-z0-9).
fn random_suffix(len: usize) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Simple LCG seeded from wall-clock nanos — sufficient for slug suffix
    // uniqueness within a single request; collision is handled by the retry
    // loop in the caller.
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15);
    let chars: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..len)
        .map(|_| {
            // xorshift64
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            chars[(seed % chars.len() as u64) as usize] as char
        })
        .collect()
}

/// Build a candidate slug/room_id from a title.
/// If the escaped title is empty, the result is just the random suffix
/// (no leading dash).
fn build_slug(title: &str) -> String {
    let escaped = escape_title(title);
    let suffix = random_suffix(SLUG_SUFFIX_LEN);
    if escaped.is_empty() {
        suffix
    } else {
        format!("{escaped}-{suffix}")
    }
}

/// Extract the first Markdown ATX/Setext heading from `content`.
/// Returns the heading text trimmed, or `None` if no heading is found.
fn extract_first_heading(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim_start();
        // ATX heading: "# Title", "## Title", etc.
        if let Some(rest) = trimmed.strip_prefix('#') {
            let rest = rest.trim_start_matches('#');
            let text = rest.trim();
            if !text.is_empty() {
                return Some(text.to_string());
            }
        }
    }
    None
}

/// Check whether a document slug already exists in the upstream store.
/// Returns `true` if the slug resolves to an existing document.
async fn doc_slug_exists(client: &UtekeClient<'_>, slug: &str) -> bool {
    let body = serde_json::json!({ "slug": slug });
    match client.post("/doc/get", &body).await {
        Ok(resp) if resp.status().is_success() => {
            matches!(resp.json::<Option<serde_json::Value>>().await, Ok(Some(_)))
        }
        _ => false,
    }
}

/// Check whether a room_id already exists in the upstream store.
/// Returns `true` if the room resolves to existing room stats.
async fn room_id_exists(client: &UtekeClient<'_>, room_id: &str) -> bool {
    let body = serde_json::json!({ "room_id": room_id });
    match client.post("/room/stats", &body).await {
        Ok(resp) if resp.status().is_success() => {
            matches!(resp.json::<Option<serde_json::Value>>().await, Ok(Some(_)))
        }
        _ => false,
    }
}

/// Auto-generate a unique document slug from `title` (or `content`'s first
/// heading when the title is empty). Retries with a fresh random suffix on
/// collision, up to `SLUG_MAX_RETRIES` times.
async fn generate_unique_doc_slug(
    client: &UtekeClient<'_>,
    title: Option<&str>,
    content: &str,
) -> Result<String, String> {
    let base = title
        .filter(|t| !t.trim().is_empty())
        .map(|t| t.trim().to_string())
        .or_else(|| extract_first_heading(content))
        .unwrap_or_default();
    for _ in 0..SLUG_MAX_RETRIES {
        let candidate = build_slug(&base);
        if !doc_slug_exists(client, &candidate).await {
            return Ok(candidate);
        }
    }
    Err(format!(
        "could not generate a unique slug after {SLUG_MAX_RETRIES} attempts"
    ))
}

/// Auto-generate a unique room_id from `title`. Retries with a fresh random
/// suffix on collision, up to `SLUG_MAX_RETRIES` times.
async fn generate_unique_room_id(
    client: &UtekeClient<'_>,
    title: Option<&str>,
) -> Result<String, String> {
    let base = title
        .filter(|t| !t.trim().is_empty())
        .map(|t| t.trim().to_string())
        .unwrap_or_default();
    for _ in 0..SLUG_MAX_RETRIES {
        let candidate = build_slug(&base);
        if !room_id_exists(client, &candidate).await {
            return Ok(candidate);
        }
    }
    Err(format!(
        "could not generate a unique room_id after {SLUG_MAX_RETRIES} attempts"
    ))
}

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
    /// Whether this memory has been superseded by a newer one (supersession
    /// workflow, uteke 0.15.0 #1069). Search surfaces filter these out;
    /// the flag surfaces on direct get-by-id (detail view).
    #[serde(skip_serializing_if = "is_false")]
    pub deprecated: bool,
    /// Relevance score (only set for semantic/fts modes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
    /// Source provenance, e.g. "user" or a file path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Source type, e.g. "user", "file", "url".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
    /// Arbitrary JSON metadata from the upstream memory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Document slugs referenced by this memory via `[[slug]]` wikilinks.
    /// Populated when semantic recall uses `enrich: true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linked_doc_slugs: Option<Vec<String>>,
    /// How many times this memory has been accessed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_count: Option<u32>,
    /// Last access timestamp (RFC3339).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_accessed: Option<String>,
    /// Upstream result type: "memory" or "document".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_type: Option<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
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
            deprecated: m.deprecated,
            score: None,
            source: m.source,
            source_type: Some(m.source_type),
            metadata: Some(m.metadata),
            linked_doc_slugs: None,
            access_count: Some(m.access_count),
            last_accessed: m.last_accessed.map(|t| t.to_rfc3339()),
            result_type: Some("memory".to_string()),
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
        let is_doc = r.result_type == SearchResultType::Document;
        Self {
            id: if is_doc {
                r.doc_slug.unwrap_or_default()
            } else {
                r.memory_id.unwrap_or_default()
            },
            content: r.content,
            tags: r.tags,
            memory_type: if is_doc {
                "document".to_string()
            } else {
                r.memory_type.unwrap_or_else(|| "note".to_string())
            },
            importance: r.importance.unwrap_or(0.5),
            pinned: if is_doc {
                false
            } else {
                r.pinned.unwrap_or(false)
            },
            created_at: r.created_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
            namespace: r.namespace.unwrap_or_else(|| DEFAULT_NAMESPACE.to_string()),
            // UnifiedSearchResult carries no deprecated flag; the recall
            // path filters superseded memories before they reach this shape.
            deprecated: false,
            score: Some(r.score),
            source: r.source,
            source_type: r.source_type,
            metadata: r.metadata,
            linked_doc_slugs: r.linked_doc_slugs,
            access_count: if is_doc { None } else { r.access_count },
            last_accessed: r.last_accessed.map(|t| t.to_rfc3339()),
            result_type: Some(match r.result_type {
                SearchResultType::Memory => "memory".to_string(),
                SearchResultType::Document => "document".to_string(),
            }),
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

/// Upstream `POST /list` response with `include_meta: true` (uteke 0.17.0
/// #1188): `{memories, total, has_more, next_offset}` instead of the bare
/// array. `total`/`next_offset` are not needed by the dashboard envelope.
#[derive(Debug, Deserialize)]
struct ListMetaEnvelope {
    memories: Vec<Memory>,
    has_more: bool,
}

/// Map an upstream JSON decode failure to a 500 response.
fn bad_upstream(e: serde_json::Error) -> Response {
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        &format!("upstream decode error: {e}"),
    )
}

/// `GET /dashboard/api/memories` query params.
#[derive(Debug, Deserialize)]
pub struct MemoryQuery {
    #[serde(default)]
    pub q: Option<String>,
    /// "semantic" | "fts" | "list" (default: list).
    #[serde(default)]
    pub mode: Option<String>,
    /// Recall strategy override for semantic mode: "fusion" | "hybrid" |
    /// "vector" | "fts5" | "graph". When absent, the upstream server default
    /// applies (fusion since uteke 0.16.0, or `[recall] default_strategy`
    /// in uteke.toml). Ignored for list/fts modes.
    #[serde(default)]
    pub strategy: Option<String>,
    /// Single tag filter (legacy; prefer `tags`).
    #[serde(default)]
    pub tag: Option<String>,
    /// Comma-separated multi-tag filter, e.g. `tags=project%3Auteke,auth`.
    /// Combined with `tag` for backward compatibility.
    #[serde(default)]
    pub tags: Option<String>,
    /// Filter by memory metadata `entity`.
    #[serde(default)]
    pub entity: Option<String>,
    /// Filter by memory metadata `category`.
    #[serde(default)]
    pub category: Option<String>,
    /// Minimum similarity score (0.0–1.0). Semantic mode only.
    #[serde(default)]
    pub min_score: Option<f32>,
    /// Use strict threshold semantics (default false).
    #[serde(default)]
    pub strict: bool,
    /// Time-travel: recall memories that existed at this RFC3339 timestamp.
    #[serde(default)]
    pub at: Option<String>,
    /// Temporal filter: only return memories created at or after this timestamp.
    #[serde(default)]
    pub after: Option<String>,
    /// Temporal filter: only return memories created at or before this timestamp.
    #[serde(default)]
    pub before: Option<String>,
    /// Search scope for semantic mode: "memory" | "doc" | "all".
    #[serde(default)]
    pub search_type: Option<String>,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default = "default_page_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

impl MemoryQuery {
    /// Resolve the list of tag filters from `tags` (comma-separated) and `tag`.
    pub fn tag_list(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(s) = self.tags.as_deref() {
            for t in s.split(',').map(|s| s.trim().to_string()) {
                if !t.is_empty() && !out.contains(&t) {
                    out.push(t);
                }
            }
        }
        if let Some(t) = self.tag.as_deref() {
            let t = t.trim().to_string();
            if !t.is_empty() && !out.contains(&t) {
                out.push(t);
            }
        }
        out
    }

    /// Resolve search type with a safe default.
    pub fn search_type_value(&self) -> String {
        let s = self.search_type.as_deref().unwrap_or("memory");
        if s.eq_ignore_ascii_case("doc") || s.eq_ignore_ascii_case("document") {
            "doc".to_string()
        } else if s.eq_ignore_ascii_case("all") {
            "all".to_string()
        } else {
            "memory".to_string()
        }
    }
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
            // POST /recall {query, limit, search_type, strategy, tags, namespace,
            // entity, category, min_score, strict, at, after, before, enrich}
            // `strategy` is omitted unless explicitly requested, so the
            // upstream default applies (fusion since uteke 0.16.0 #1123, or
            // `[recall] default_strategy` from uteke.toml) — keeping the
            // dashboard in sync with CLI/MCP recall behavior.
            let fetch_limit = (offset + limit + 1).min(SEARCH_FETCH_CAP);
            let mut body = serde_json::json!({
                "query": query,
                "limit": fetch_limit,
                "search_type": q.search_type_value(),
                "enrich": true,
            });
            if let Some(s) = q.strategy.as_deref().filter(|s| !s.is_empty()) {
                body["strategy"] = serde_json::json!(s);
            }
            let tags = q.tag_list();
            if !tags.is_empty() {
                body["tags"] = serde_json::json!(tags);
            }
            if let Some(ns) = q.namespace.as_deref().filter(|n| !n.is_empty()) {
                body["namespace"] = serde_json::json!(ns);
            }
            if let Some(ent) = q.entity.as_deref().filter(|n| !n.is_empty()) {
                body["entity"] = serde_json::json!(ent);
            }
            if let Some(cat) = q.category.as_deref().filter(|n| !n.is_empty()) {
                body["category"] = serde_json::json!(cat);
            }
            if let Some(ms) = q.min_score {
                body["min_score"] = serde_json::json!(ms);
            }
            if q.strict {
                body["strict"] = serde_json::json!(true);
            }
            if let Some(ts) = q.at.as_deref().filter(|n| !n.is_empty()) {
                body["at"] = serde_json::json!(ts);
            }
            if let Some(ts) = q.after.as_deref().filter(|n| !n.is_empty()) {
                body["after"] = serde_json::json!(ts);
            }
            if let Some(ts) = q.before.as_deref().filter(|n| !n.is_empty()) {
                body["before"] = serde_json::json!(ts);
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
            // Upstream /search only supports tags + namespace, so other
            // filters are intentionally ignored in keyword mode.
            let fetch_limit = (offset + limit + 1).min(SEARCH_FETCH_CAP);
            let mut body = serde_json::json!({
                "query": query,
                "limit": fetch_limit,
            });
            let tags = q.tag_list();
            if !tags.is_empty() {
                body["tags"] = serde_json::json!(tags);
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
            // POST /list {limit, offset, tag?, namespace?, at?, include_meta:true}
            // include_meta (uteke 0.17.0 #1188) asks upstream for exact
            // pagination metadata instead of guessing from page length.
            let mut body = serde_json::json!({
                "limit": limit,
                "offset": offset,
                "include_meta": true,
            });
            // /list supports a single tag; prefer the legacy `tag` param,
            // falling back to the first tag in `tags`.
            if let Some(t) = q.tag.as_deref().filter(|t| !t.is_empty()) {
                body["tag"] = serde_json::json!(t);
            } else if let Some(t) = q.tag_list().first() {
                body["tag"] = serde_json::json!(t);
            }
            if let Some(ns) = q.namespace.as_deref().filter(|n| !n.is_empty()) {
                body["namespace"] = serde_json::json!(ns);
            }
            if let Some(ts) = q.at.as_deref().filter(|n| !n.is_empty()) {
                body["at"] = serde_json::json!(ts);
            }
            let resp = match client.post("/list", &body).await {
                Ok(r) => r,
                Err(e) => return upstream_err(e),
            };
            let val: serde_json::Value = match parse_json(resp).await {
                Ok(v) => v,
                Err(r) => return r,
            };
            // Upstream ≥ 0.17 answers with the {memories, has_more, …}
            // envelope; older upstreams ignore include_meta and return the
            // bare array — fall back to the page-length heuristic there.
            let (memories, has_more): (Vec<Memory>, bool) = if val.is_array() {
                match serde_json::from_value::<Vec<Memory>>(val) {
                    Ok(memories) => {
                        let has_more = memories.len() == limit;
                        (memories, has_more)
                    }
                    Err(e) => return bad_upstream(e),
                }
            } else {
                match serde_json::from_value::<ListMetaEnvelope>(val) {
                    Ok(env) => (env.memories, env.has_more),
                    Err(e) => return bad_upstream(e),
                }
            };
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

/// `GET /dashboard/api/namespaces` query params.
#[derive(Debug, Deserialize)]
pub struct NamespacesQuery {
    /// When true, forward `?with_counts=true` upstream (#1181) and return the
    /// `{name, count, active, deprecated}` rows instead of the bare name list.
    #[serde(default)]
    pub counts: bool,
}

/// `GET /dashboard/api/namespaces` — namespace list.
/// `?counts=true` returns the lifecycle-enriched rows (used by the
/// Namespaces page); the default stays a bare `Vec<String>` for the filter
/// dropdowns.
pub async fn handle_namespaces(
    State(state): State<AppState>,
    Query(q): Query<NamespacesQuery>,
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
    let path = if q.counts {
        "/namespaces?with_counts=true"
    } else {
        "/namespaces"
    };
    let resp = match client.get(path).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    if q.counts {
        // Pass the upstream row objects through untouched.
        let val: serde_json::Value = match parse_json(resp).await {
            Ok(v) => v,
            Err(r) => return r,
        };
        return Json(val).into_response();
    }
    let ns: Vec<String> = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(ns).into_response()
}

/// `POST /dashboard/api/namespaces/rename` body.
#[derive(Debug, Deserialize, Serialize)]
pub struct NamespaceRenameRequest {
    /// Current namespace name.
    pub from: String,
    /// New namespace name — an existing target means merge (#1181).
    pub to: String,
}

/// `POST /dashboard/api/namespaces/rename` — rename a namespace, merging into
/// the target when it already exists. Wraps upstream `POST /namespaces/rename`.
/// Requires session + CSRF.
pub async fn handle_namespace_rename(
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
    let req: NamespaceRenameRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    if req.from.trim().is_empty() || req.to.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "from and to must not be empty");
    }
    if req.from == req.to {
        return api_error(StatusCode::BAD_REQUEST, "from and to must differ");
    }
    let client = UtekeClient::new(&state);
    let resp = match client.post("/namespaces/rename", &req).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

/// `DELETE /dashboard/api/namespaces/{name}` query params.
#[derive(Debug, Deserialize)]
pub struct NamespaceDeleteQuery {
    /// What happens to the namespace's memories: `refuse` (default — 409
    /// while any memory references the name), `merge` (move all memories to
    /// `target`), or `deprecate` (soft-delete — restorable, never hard-deleted).
    #[serde(default = "default_ns_delete_strategy")]
    pub strategy: String,
    /// Target namespace when strategy is `merge`.
    #[serde(default)]
    pub target: Option<String>,
}

fn default_ns_delete_strategy() -> String {
    "refuse".to_string()
}

/// `DELETE /dashboard/api/namespaces/{name}` — delete a namespace with an
/// explicit strategy for its memories. Wraps upstream `POST /namespaces/delete`
/// (RESTful → POST translator). Requires session + CSRF.
pub async fn handle_namespace_delete(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<NamespaceDeleteQuery>,
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
    if name.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "namespace name must not be empty");
    }
    match q.strategy.as_str() {
        "refuse" | "merge" | "deprecate" => {}
        other => {
            return api_error(
                StatusCode::BAD_REQUEST,
                &format!("unknown strategy '{other}' — use refuse, merge, or deprecate"),
            );
        }
    }
    if q.strategy == "merge" && q.target.as_deref().map(str::trim).unwrap_or("").is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "strategy=merge requires a 'target' namespace",
        );
    }
    let payload = serde_json::json!({
        "name": name,
        "strategy": q.strategy,
        "target": q.target,
    });
    let client = UtekeClient::new(&state);
    let resp = match client.post("/namespaces/delete", &payload).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

/// `POST /dashboard/api/importance` — recompute importance scores for all
/// memories. Wraps upstream `POST /importance` (global — the upstream
/// `namespace` field is currently a no-op). Requires session + CSRF.
pub async fn handle_recompute_importance(
    State(state): State<AppState>,
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
    let resp = match client.post("/importance", &serde_json::json!({})).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
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
///
/// The `slug` is **auto-generated** by the server from `title` (or the first
/// Markdown heading in `content` when `title` is empty) following the uteke
/// naming convention (`escaped_title + "-" + random_suffix`). A `slug` field
/// sent by the client is accepted for backward compatibility but **ignored**.
#[derive(Debug, Deserialize)]
pub struct CreateDocumentRequest {
    /// Ignored — slug is always auto-generated. Kept for backward compat.
    #[serde(default)]
    pub slug: Option<String>,
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
    if req.content.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "content must not be empty");
    }
    let client = UtekeClient::new(&state);
    // Auto-generate slug from title (or first heading in content) with
    // collision check — client-supplied slug is ignored.
    let slug = match generate_unique_doc_slug(&client, req.title.as_deref(), &req.content).await {
        Ok(s) => s,
        Err(e) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };
    let payload = serde_json::json!({
        "slug": slug,
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
    let created_slug = created
        .get("slug")
        .and_then(|v| v.as_str())
        .unwrap_or(&slug);
    match fetch_document(&client, created_slug).await {
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
///
/// The `room_id` is **auto-generated** by the server from `title` following
/// the uteke naming convention (`escaped_title + "-" + random_suffix`). A
/// `room_id` field sent by the client is accepted for backward compatibility
/// but **ignored**. When `title` is empty the room_id is just the random
/// suffix.
#[derive(Debug, Deserialize)]
pub struct CreateRoomRequest {
    /// Ignored — room_id is always auto-generated. Kept for backward compat.
    #[serde(default)]
    pub room_id: Option<String>,
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
    let client = UtekeClient::new(&state);
    // Auto-generate room_id from title with collision check —
    // client-supplied room_id is ignored.
    let room_id = match generate_unique_room_id(&client, req.title.as_deref()).await {
        Ok(s) => s,
        Err(e) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };
    let mut payload = serde_json::json!({
        "room_id": room_id,
        "title": req.title,
    });
    if let Some(ns) = req.namespace.as_deref().filter(|n| !n.is_empty()) {
        payload["namespace"] = serde_json::json!(ns);
    }
    let resp = match client.post("/room/create", &payload).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let mut val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // Ensure the response carries the generated room_id so the frontend can
    // navigate to the new room without a separate lookup.
    if val.get("created").is_none() {
        val["created"] = serde_json::json!(room_id);
    }
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

// ── Room summary & recall (Tier 1) ──────────────────────────────────────────

/// `GET /dashboard/api/rooms/{id}/summary` — topic clusters & overview.
/// Wraps upstream `POST /room/summary`. Returns RoomSummary JSON.
pub async fn handle_room_summary(
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
    let resp = match client.post("/room/summary", &body).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

/// `GET /dashboard/api/rooms/{id}/summary-document` — structured meeting minutes.
/// Wraps upstream `POST /room/summary-document`. Returns RoomDocument JSON.
pub async fn handle_room_summary_document(
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
    let resp = match client.post("/room/summary-document", &body).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

/// `GET /dashboard/api/rooms/{id}/recall` query params.
#[derive(Debug, Deserialize)]
pub struct RoomRecallQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub author: Option<String>,
}

/// `GET /dashboard/api/rooms/{id}/recall` — semantic search within a room.
/// Wraps upstream `POST /room/recall`. Empty query falls back to chronological.
pub async fn handle_room_recall(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<RoomRecallQuery>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let limit = q.limit.unwrap_or(DEFAULT_PAGE_LIMIT).min(MAX_PAGE_LIMIT);
    let payload = serde_json::json!({
        "room_id": id,
        "query": q.q,
        "limit": limit,
        "author": q.author,
    });
    let client = UtekeClient::new(&state);
    let resp = match client.post("/room/recall", &payload).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

// ── Memory feedback, graph, timeline (Tier 1) ───────────────────────────────

/// `POST /dashboard/api/memories/{id}/feedback` body.
#[derive(Debug, Deserialize)]
pub struct MemoryFeedbackRequest {
    /// "helpful" or "unhelpful"
    pub feedback: String,
}

/// `POST /dashboard/api/memories/{id}/feedback` — trust scoring feedback.
/// Wraps upstream `POST /memory/feedback`. Requires session + CSRF.
pub async fn handle_memory_feedback(
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
    let req: MemoryFeedbackRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    let feedback = req.feedback.trim().to_lowercase();
    if feedback != "helpful" && feedback != "unhelpful" {
        return api_error(
            StatusCode::BAD_REQUEST,
            "feedback must be 'helpful' or 'unhelpful'",
        );
    }
    let payload = serde_json::json!({ "id": id, "feedback": feedback });
    let client = UtekeClient::new(&state);
    let resp = match client.post("/memory/feedback", &payload).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

/// `GET /dashboard/api/memories/{id}/graph` — full knowledge graph.
/// Wraps upstream `GET /graph` (returns all nodes + edges + stats).
/// The frontend renders this with vis.js for full graph visualization.
pub async fn handle_memory_graph(
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
    // Fetch the full graph — the frontend will highlight the node for this
    // memory. The `id` path param is used by the UI to center the view.
    let _ = &id; // validated by upstream when UI requests node details
    let client = UtekeClient::new(&state);
    let resp = match client.get("/graph").await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

/// `POST /dashboard/api/memories/{id}/edges` body.
#[derive(Debug, Deserialize)]
pub struct AddEdgeRequest {
    pub target: String,
    #[serde(default)]
    pub edge_type: Option<String>,
    #[serde(default)]
    pub weight: Option<f64>,
}

/// `POST /dashboard/api/memories/{id}/edges` — add a graph edge.
/// Wraps upstream `POST /graph/edge`. Requires session + CSRF.
pub async fn handle_memory_edges_add(
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
    let req: AddEdgeRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    if req.target.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "target must not be empty");
    }
    if req.target == id {
        return api_error(StatusCode::BAD_REQUEST, "self-loop edges are not allowed");
    }
    let payload = serde_json::json!({
        "source": id,
        "target": req.target,
        "edge_type": req.edge_type,
        "weight": req.weight,
    });
    let client = UtekeClient::new(&state);
    let resp = match client.post("/graph/edge", &payload).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

/// `DELETE /dashboard/api/memories/{id}/edges?target=...` — remove a graph edge.
/// Wraps upstream `DELETE /graph/edge?source=...&target=...`. Requires session + CSRF.
pub async fn handle_memory_edges_remove(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
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
    let target = match params.get("target") {
        Some(t) if !t.is_empty() => t,
        _ => return api_error(StatusCode::BAD_REQUEST, "target query parameter required"),
    };
    let path = format!(
        "/graph/edge?source={}&target={}",
        urlencoding::encode(&id),
        urlencoding::encode(target)
    );
    let client = UtekeClient::new(&state);
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

/// `GET /dashboard/api/memories/{id}/timeline` query params.
#[derive(Debug, Deserialize)]
pub struct TimelineQuery {
    #[serde(default)]
    pub limit: Option<usize>,
}

/// `GET /dashboard/api/memories/{id}/timeline` — event history for a memory.
/// Wraps upstream `GET /timeline?id=...&limit=...`.
pub async fn handle_memory_timeline(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<TimelineQuery>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let limit = q.limit.unwrap_or(50).min(MAX_PAGE_LIMIT);
    let path = format!("/timeline?id={}&limit={}", urlencoding::encode(&id), limit);
    let client = UtekeClient::new(&state);
    let resp = match client.get(&path).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

// ── Tags management (Tier 1) ────────────────────────────────────────────────

/// `POST /dashboard/api/tags/rename` body.
#[derive(Debug, Deserialize, Serialize)]
pub struct TagRenameRequest {
    pub old: String,
    pub new: String,
    #[serde(default)]
    pub namespace: Option<String>,
}

/// `POST /dashboard/api/tags/rename` — rename a tag across all memories.
/// Wraps upstream `POST /tags/rename`. Requires session + CSRF.
pub async fn handle_tag_rename(
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
    let req: TagRenameRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    if req.old.trim().is_empty() || req.new.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "old and new must not be empty");
    }
    let client = UtekeClient::new(&state);
    let resp = match client.post("/tags/rename", &req).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

/// `DELETE /dashboard/api/tags/{tag}` — delete a tag from all memories.
/// Wraps upstream `POST /tags/delete` (RESTful → POST translator). Requires session + CSRF.
pub async fn handle_tag_delete(
    State(state): State<AppState>,
    Path(tag): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
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
    let namespace = params.get("namespace").cloned();
    let payload = serde_json::json!({ "tag": tag, "namespace": namespace });
    let client = UtekeClient::new(&state);
    let resp = match client.post("/tags/delete", &payload).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

// ── Import / Export (Tier 1) ────────────────────────────────────────────────

/// `GET /dashboard/api/export` query params.
#[derive(Debug, Deserialize)]
pub struct ExportQuery {
    #[serde(default)]
    pub namespace: Option<String>,
}

/// `GET /dashboard/api/export` — download all memories as JSONL.
/// Wraps upstream `GET /export`. Returns raw JSONL with Content-Disposition.
pub async fn handle_export(
    State(state): State<AppState>,
    Query(q): Query<ExportQuery>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let path = match q.namespace.as_deref().filter(|n| !n.is_empty()) {
        Some(ns) => format!("/export?namespace={}", urlencoding::encode(ns)),
        None => "/export".to_string(),
    };
    let client = UtekeClient::new(&state);
    let resp = match client.get(&path).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let code =
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        return api_error(code, &body);
    }
    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => return upstream_err(e),
    };
    // Return raw JSONL with download headers.
    let mut headers_out = HeaderMap::new();
    headers_out.insert(
        axum::http::header::CONTENT_TYPE,
        "application/x-ndjson".parse().unwrap(),
    );
    headers_out.insert(
        axum::http::header::CONTENT_DISPOSITION,
        "attachment; filename=\"uteke-export.jsonl\""
            .parse()
            .unwrap(),
    );
    (StatusCode::OK, headers_out, bytes).into_response()
}

/// `POST /dashboard/api/import` body.
#[derive(Debug, Deserialize, Serialize)]
pub struct ImportRequest {
    /// JSONL content to import.
    pub content: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// `POST /dashboard/api/import` — import memories from JSONL.
/// Wraps upstream `POST /import`. Requires session + CSRF.
pub async fn handle_import(
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
    let req: ImportRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    if req.content.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "content must not be empty");
    }
    let client = UtekeClient::new(&state);
    let resp = match client.post("/import", &req).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

// ── Document rooms (Tier 1) ─────────────────────────────────────────────────

/// `GET /dashboard/api/documents/{slug}/rooms` — list rooms linked to a document.
/// Wraps upstream `POST /doc/room/list`.
pub async fn handle_document_rooms(
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
    let body = serde_json::json!({ "doc_slug": slug });
    let client = UtekeClient::new(&state);
    let resp = match client.post("/doc/room/list", &body).await {
        Ok(r) => r,
        Err(e) => return upstream_err(e),
    };
    let val: serde_json::Value = match parse_json(resp).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    Json(val).into_response()
}

// ── Settings: Clients (OAuth2 credentials) ──────────────────────────────────

/// `GET /dashboard/api/settings/clients` — list all OAuth2 clients.
pub async fn handle_settings_list_clients(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.store.list_clients() {
        Ok(clients) => {
            let rows: Vec<serde_json::Value> = clients
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "id": c.id,
                        "client_id": c.client_id,
                        "redirect_uris": c.redirect_uris,
                        "scopes": c.scopes,
                        "grants": c.grants,
                        "public": c.public,
                        "dynamic": c.dynamic,
                        "created_at": c.created_at,
                    })
                })
                .collect();
            Json(rows).into_response()
        }
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store error: {e}"),
        ),
    }
}

/// `POST /dashboard/api/settings/clients` body.
#[derive(Debug, Deserialize)]
pub struct CreateClientRequest {
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub public: bool,
}

/// `POST /dashboard/api/settings/clients` — register a new OAuth2 client.
/// Requires session + CSRF.
pub async fn handle_settings_create_client(
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
    let req: CreateClientRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    if req.client_id.trim().is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "client_id must not be empty");
    }
    let secret = req.client_secret.as_deref().unwrap_or("");
    if !req.public && secret.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "client_secret required for non-public clients",
        );
    }
    match state.store.add_client(
        &req.client_id,
        secret,
        req.redirect_uris,
        vec!["read".to_string(), "write".to_string()],
        req.public,
        false,
    ) {
        Ok(c) => Json(serde_json::json!({
            "id": c.id,
            "client_id": c.client_id,
            "redirect_uris": c.redirect_uris,
            "scopes": c.scopes,
            "public": c.public,
            "created_at": c.created_at,
        }))
        .into_response(),
        Err(e) => api_error(StatusCode::CONFLICT, &format!("create failed: {e}")),
    }
}

/// `DELETE /dashboard/api/settings/clients/{id}` — delete an OAuth2 client.
/// Requires session + CSRF.
pub async fn handle_settings_delete_client(
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
    match state.store.delete_client(&id) {
        Ok(n) if n > 0 => Json(serde_json::json!({"deleted": true, "id": id})).into_response(),
        Ok(_) => api_error(StatusCode::NOT_FOUND, "client not found"),
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("delete failed: {e}"),
        ),
    }
}

// ── Settings: Users (dashboard users) ───────────────────────────────────────

/// `GET /dashboard/api/settings/users` — list all dashboard users.
pub async fn handle_settings_list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.store.list_users() {
        Ok(users) => {
            let rows: Vec<serde_json::Value> = users
                .iter()
                .map(|u| {
                    serde_json::json!({
                        "id": u.id,
                        "username": u.username,
                        "created_at": u.created_at,
                        "locked": u.locked,
                        "failed_attempts": u.failed_attempts,
                    })
                })
                .collect();
            Json(rows).into_response()
        }
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store error: {e}"),
        ),
    }
}

/// `POST /dashboard/api/settings/users` body.
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
}

/// `POST /dashboard/api/settings/users` — create a new dashboard user.
/// Requires session + CSRF.
pub async fn handle_settings_create_user(
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
    let req: CreateUserRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    if req.username.trim().is_empty() || req.password.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "username and password must not be empty",
        );
    }
    match state.store.add_user(&req.username, &req.password) {
        Ok(u) => Json(serde_json::json!({
            "id": u.id,
            "username": u.username,
            "created_at": u.created_at,
            "locked": u.locked,
            "failed_attempts": u.failed_attempts,
        }))
        .into_response(),
        Err(e) => api_error(StatusCode::CONFLICT, &format!("create failed: {e}")),
    }
}

/// `DELETE /dashboard/api/settings/users/{id}` — delete a dashboard user.
/// Requires session + CSRF. Prevents self-deletion.
pub async fn handle_settings_delete_user(
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
    // Prevent self-deletion.
    if id == sess.username || id == sess.session_id {
        return api_error(StatusCode::BAD_REQUEST, "cannot delete your own account");
    }
    match state.store.delete_user(&id) {
        Ok(n) if n > 0 => Json(serde_json::json!({"deleted": true, "id": id})).into_response(),
        Ok(_) => api_error(StatusCode::NOT_FOUND, "user not found"),
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("delete failed: {e}"),
        ),
    }
}

/// `PUT /dashboard/api/settings/users/{id}/password` body.
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub new_password: String,
}

/// `PUT /dashboard/api/settings/users/{id}/password` — change a user's password.
/// Requires session + CSRF.
pub async fn handle_settings_change_password(
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
    let req: ChangePasswordRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, &format!("invalid body: {e}")),
    };
    if req.new_password.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "password must not be empty");
    }
    match state.store.change_password(&id, &req.new_password) {
        Ok(_) => Json(serde_json::json!({"changed": true, "id": id})).into_response(),
        Err(e) => api_error(StatusCode::NOT_FOUND, &format!("change failed: {e}")),
    }
}

/// `POST /dashboard/api/settings/users/{id}/unlock` — unlock a locked user.
/// Requires session + CSRF.
pub async fn handle_settings_unlock_user(
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
    match state.store.unlock_user(&id) {
        Ok(_) => Json(serde_json::json!({"unlocked": true, "id": id})).into_response(),
        Err(e) => api_error(StatusCode::NOT_FOUND, &format!("unlock failed: {e}")),
    }
}

// ── Settings: Sessions ──────────────────────────────────────────────────────

/// `GET /dashboard/api/settings/sessions` — list all active sessions.
pub async fn handle_settings_list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.store.list_sessions() {
        Ok(sessions) => {
            let rows: Vec<serde_json::Value> = sessions
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "session_id": s.session_id,
                        "username": s.username,
                        "created_at": s.created_at,
                        "expires_at": s.expires_at,
                    })
                })
                .collect();
            Json(rows).into_response()
        }
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store error: {e}"),
        ),
    }
}

/// `DELETE /dashboard/api/settings/sessions/{id}` — revoke a session.
/// Requires session + CSRF. Prevents self-revocation (use logout instead).
pub async fn handle_settings_revoke_session(
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
    // Prevent self-revocation — use /dashboard/logout instead.
    if id == sess.session_id {
        return api_error(
            StatusCode::BAD_REQUEST,
            "cannot revoke your own session — use logout",
        );
    }
    match state.store.delete_session(&id) {
        Ok(_) => Json(serde_json::json!({"revoked": true, "id": id})).into_response(),
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("revoke failed: {e}"),
        ),
    }
}

// ── Settings: OAuth2 Tokens (AI agent sessions) ─────────────────────────────

/// `GET /dashboard/api/settings/tokens` — list all active OAuth2 refresh tokens.
/// These represent AI agents that authenticated via OAuth2 (e.g. MCP clients).
pub async fn handle_settings_list_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if !state.config.dashboard.enabled {
        return api_error(StatusCode::NOT_FOUND, "dashboard disabled");
    }
    let _sess = match require_session(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match state.store.list_refresh_tokens() {
        Ok(tokens) => {
            let rows: Vec<serde_json::Value> = tokens
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "token_hash": t.token_hash,
                        "client_id": t.client_id,
                        "username": t.username,
                        "scope": t.scope,
                        "created_at": t.created_at,
                        "expires_at": t.expires_at,
                    })
                })
                .collect();
            Json(rows).into_response()
        }
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("store error: {e}"),
        ),
    }
}

/// `DELETE /dashboard/api/settings/tokens/{hash}` — revoke an OAuth2 refresh
/// token by its hash. This forces the AI agent to re-authenticate after its
/// current access token expires. Requires session + CSRF.
pub async fn handle_settings_revoke_token(
    State(state): State<AppState>,
    Path(hash): Path<String>,
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
    match state.store.revoke_refresh_token_by_hash(&hash) {
        Ok(n) if n > 0 => Json(serde_json::json!({"revoked": true, "hash": hash})).into_response(),
        Ok(_) => api_error(StatusCode::NOT_FOUND, "token not found or already revoked"),
        Err(e) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("revoke failed: {e}"),
        ),
    }
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
            deprecated_at: None,
            valid_from: None,
            valid_until: None,
            memory_type: "note".into(),
            importance: 0.5,
            pinned: false,
            content_type: "text".into(),
            slug: None,
            source: None,
            source_type: "user".into(),
            author_type: "agent".into(),
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
            deprecated_at: None,
            valid_from: None,
            valid_until: None,
            memory_type: "fact".into(),
            importance: 0.5,
            pinned: false,
            content_type: "text".into(),
            slug: None,
            source: None,
            source_type: "user".into(),
            author_type: "agent".into(),
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
