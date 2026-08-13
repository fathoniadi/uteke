# PLAN — Documents (docs) di uteke-web

> Status: final (disetujui Thoni, 2026-08-13) — dokumen handoff buat AI lain yang ngerjain implementasi.
> Scope: menambah **section "Documents"** di dashboard uteke-web — memanfaatkan doc engine (`/doc/*`) di uteke-server.
> Out of scope: memory (sudah ada), rooms, graph, tags. Plan ini khusus docs.

## 1. Konteks

- uteke-server sudah punya **doc engine** (wiki/knowledge base): dokumen markdown hierarkis (parent-child), auto-chunking per heading, hybrid search (semantic + FTS5), slug unik global, wikilink `[[slug]]` dari memori.
- Dashboard uteke-web **belum expose docs sama sekali** — `dashboard_api.rs` cuma punya memories/tags/namespaces/stats/profile. Memory section sudah jadi, docs = greenfield.
- Pattern yang dipakai: handler `/dashboard/api/*` (cookie session + CSRF) → `UtekeClient` → uteke-server pakai token statis. Browser **tidak** pernah pegang token uteke-server.

## 2. Tujuan

1. Menu/section **Documents** di dashboard (entry sidebar + hash `#/documents`).
2. User bisa: **list** (tree/breadcrumb), **lihat** (render markdown), **buat/edit**, **cari** (hybrid/semantic/fts), **pindah parent**, **hapus** dokumen.
3. Semua akses lewat `/dashboard/api/documents*` (cookie + CSRF), bukan proxy langsung.

## 3. Keputusan desain

| Aspek | Pilihan | Catatan |
|---|---|---|
| Container | Sidebar collapsible (auto-hide layar kecil) + hash routing | ✅ sudah disepakati Thoni. Docs = 1 item menu. |
| Route section | `#/documents` + sub-route `#/documents/{slug}` | Deep-linkable, refresh aman. |
| Data | `/dashboard/api/documents*` (cookie + CSRF) | Ikut pattern memory yang ada. |
| Markdown render | **marked.js** (via CDN) + sanitize (DOMPurify) | ✅ Diputusin Thoni: boleh render. Sanitasi wajib (konten bisa dari user/import). |
| Editor | **EasyMDE** (markdown editor: toolbar + live preview) | ✅ Diputusin Thoni: butuh lebih kaya, bukan textarea polos. Vanilla + CDN, tanpa build step. |
| Hirarki | **Tree penuh (indent)** + breadcrumb di detail | ✅ Diputusin Thoni: hirarki penuh. Bentuk dilihat dulu setelah deploy, boleh revisi. |

## 4. Backend — handler baru di `dashboard_api.rs`

Wrap endpoint `/doc/*` uteke-server. Semua handler pakai `require_session` (+ `require_csrf` untuk mutasi).

| Dashboard route | Method | CSRF | Wrap ke uteke-server | Keterangan |
|---|---|---|---|---|
| `/dashboard/api/documents` | GET | ❌ | `/doc/list` | list (param `roots_only`, `parent`, `limit`) |
| `/dashboard/api/documents/search` | GET | ❌ | `/doc/search` | param `q` + `mode` (hybrid/semantic/fts) — read-only |
| `/dashboard/api/documents/{slug}` | GET | ❌ | `/doc/get` | detail by slug |
| `/dashboard/api/documents/{slug}/mem-refs` | GET | ❌ | `/doc/mem-refs` | memori yang merefer doc (opsional) |
| `/dashboard/api/documents` | POST | ✅ **wajib** | `/doc/create` | body: slug, title, content, tags, parent |
| `/dashboard/api/documents/{slug}` | PUT | ✅ **wajib** | `/doc/update` | partial update |
| `/dashboard/api/documents/{slug}` | DELETE | ✅ **wajib** | `/doc/delete` | hapus + cascade chunk |
| `/dashboard/api/documents/{slug}/move` | POST | ✅ **wajib** | `/doc/move` | body: new_parent |

Catatan implementasi:
- Response di-normalize ke **dua struct** (lihat §10 untuk detail shape upstream):
  - `DashboardDocumentSummary` — untuk list & search results (wrap `DocumentSummary` / `DocumentSearchResult`). Field: `id, slug, title, parent_id, depth, has_children, sort_order, updated_at`. **Tidak ada `content`/`tags`** (upstream `/doc/list` & `/doc/search` balik summary, bukan full doc).
  - `DashboardDocument` — untuk get/create/update (wrap `Document`). Field: `id, slug, title, content, tags, parent_id, depth, has_children, sort_order, version, created_at, updated_at`. Plus optional `metadata, author, content_type, path` kalau perlu.
  - Untuk search results, tambah field optional `score, chunk_heading, chunk_snippet, mode` di struct terpisah `DashboardDocumentSearchResult` (atau flatten ke summary dengan field optional).
- `parent_id` di response = **UUID** (`Document.parent_id: Option<String>`). Tapi request `DocCreateRequest.parent` & `DocMoveRequest.new_parent` pakai **slug**. Frontend parent picker kirim slug; display parent di tree/breadcrumb perlu lookup slug→title terpisah (atau pakai `doc_breadcrumbs` upstream — ada di `lib.rs:1559`).
- `slug` unik global; validasi slug di frontend + serahkan ke uteke-server (dia auto-migrasi duplicate).
- **Max depth 10** — `doc_upsert_with_parent` & `doc_move` reject kalau exceed (`lib.rs:1292`). Frontend parent picker harus cek depth atau tangani error 400 dari upstream.
- **CSRF per-handler, BUKAN middleware `axum-csrf`** — ikut pattern `dashboard_api.rs` yang ada: `require_csrf()` cek header `x-csrf-token` (double-submit token) untuk semua mutasi.
- **Semua mutasi** (POST create, PUT update, DELETE delete, POST move) = `require_session` + `require_csrf`. **Read-only** (GET list/search/get/mem-refs) = `require_session` saja.
- **Tidak ada PATCH di scope docs** — update pakai PUT. (Kalau nanti ada PATCH, wajib CSRF juga.)
- `search` dibuat **GET** (read-only, tanpa CSRF); handler nge-translate ke upstream `POST /doc/search` server-side.
- `/doc/update` balik `Option<Document>` — `None` kalau slug tidak ditemukan. Dashboard handler harus map `None` → **404** (jangan teruskan 200 + null ke browser).
- `/doc/move` balik `{"moved": usize}` (count baris yang dipindah), **bukan bool**. Frontend jangan assume boolean.
- `/doc/delete` balik `{"deleted": bool, "subtree_size": usize}` — subtree_size = jumlah children ter-cascade.

## 5. Frontend — view baru di `dashboard_spa()`

1. **List view** (`#/documents`): tree indented (parent-child) + tombol "New document" + search box + mode selector.
2. **Detail view** (`#/documents/{slug}`): render markdown + breadcrumb + tombol Edit / Move / Delete + panel mem-refs (opsional).
3. **Create/Edit modal** (atau view): editor **EasyMDE** (toolbar + live preview) + field slug, title, tags, parent picker.
4. **Search**: hasil hybrid dengan snippet + heading chunk.
5. **Empty/loading/error state** per view (konsisten memory section).

Semua tetap vanilla JS + Bootstrap 5 + Bootstrap Icons + marked.js CDN.

## 6. Tahapan (milestone)

- **D1 — Backend read path.** `UtekeClient` + handler list/get/search + route di `dashboard_router()`.
- **D2 — Backend write path.** create/update/delete/move (cookie + CSRF).
- **D3 — List view.** Tree + search + entry sidebar + hash `#/documents`.
- **D4 — Detail view.** Markdown render + breadcrumb + mem-refs.
- **D5 — Create/Edit.** EasyMDE (toolbar + preview) + parent picker + tags.
- **D6 — Polish.** Empty/loading/error, responsive, validasi slug, uji e2e (`tests/dashboard_api.rs`).

D1–D2 = backend; D3–D5 = frontend; tiap milestone mandiri & bisa di-review.

## 7. Keputusan terkunci (dari Thoni)

- ✅ **Scope v1 = semua** — CRUD lengkap: list, lihat, cari, buat, edit, pindah parent, hapus.
- ✅ **Markdown render** — boleh render (marked.js + DOMPurify).
- ✅ **Editor lebih kaya** — EasyMDE (toolbar + preview), bukan textarea polos.
- ✅ **Hirarki penuh** — tree indent + breadcrumb. Bentuk dicek setelah deploy; kalau kurang pas, revisi.
- ✅ **Struct split (Opsi A)** — 3 struct terpisah: `DashboardDocumentSummary` (list/search), `DashboardDocument` (get/create/update full), `DashboardDocumentSearchResult` (search + chunk info). Dipilih Thoni 2026-08-13 karena type-safe — frontend nggak bisa "lupa" kalau list nggak ada content. Trade-off: lebih banyak boilerplate daripada unified, tapi bentuk response bersih & bug jadi compile error bukan runtime error.

## 8. Catatan implementasi

- **EasyMDE** via CDN (vanilla, tanpa build step); renderer internal pakai marked.
- **Sanitasi output** pakai DOMPurify — konten doc bisa datang dari user/import/ekstraksi, wajib anti-XSS.
## 9. Testing (unit + integration)

### 9.1 Infrastruktur

- File baru: **`tests/documents_api.rs`** (mirror `tests/dashboard_api.rs`).
- Reuse **`tests/common/mod.rs`**: `TestApp::with_upstream(addr)` + `spawn_mock_upstream()`. Mock upstream diperluas buat handle `/doc/*`.
- Helper **`make_session(app, username) -> (cookie, csrf)`** (sama kayak memory) → bikin session valid + CSRF token buat autentikasi request.
- Drive router via **`tower::ServiceExt::oneshot`** (tanpa bind TCP), baca body pakai `http_body_util::BodyExt`.
- Run: **`cargo test -p uteke-web --test documents_api`** (atau `cargo test -p uteke-web` buat semua).

### 9.2 Mock upstream (bentuk `/doc/*` uteke-server)

Perhatikan: endpoint doc uteke-server **semua POST** (kecuali delete), body JSON:

| Upstream | Method | Body |
|---|---|---|
| `/doc/list` | POST | `{"limit":n,"roots_only":bool,"parent":null}` → `[DocumentSummary]` |
| `/doc/get` | POST | `{"id":null,"slug":"..."}` → `Document` (full) |
| `/doc/search` | POST | `{"query":"...","limit":n,"mode":"hybrid\|semantic\|fts"}` → `[DocumentSearchResult]` |
| `/doc/create` | POST | `{slug,title?,content,tags?,parent?}` → `Document` (full, bentuknya `DocCreateRequest` di `types.rs:12`) |
| `/doc/update` | POST | `{id\|slug,title?,content?,tags?,metadata?}` → `Option<Document>` (None = not found → map 404) |
| `/doc/move` | POST | `{id\|slug,new_parent?,new_sort_order?}` → `{"moved": usize}` (count, bukan bool) |
| `/doc/mem-refs` | POST | `{"doc_slug":"..."}` → `{"doc_slug":"...","memory_ids":[...]}` ⚠️ field `doc_slug` BUKAN `slug` |
| `/doc/delete` | DELETE | `?id=<slug-or-uuid>` (accept `?id=` atau `?slug=`) → `{"deleted":bool,"subtree_size":usize}` |

Contoh JSON dokumen yang dikembalikan mock:

**`Document` (full, dari `/doc/get` & `/doc/create`):**
```json
{"id":"d1","slug":"deploy-runbook","title":"Deploy Runbook","content":"# Deploy\n...","namespace":null,"author":null,"tags":["ops"],"metadata":null,"version":1,"content_type":"markdown","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","parent_id":null,"path":"/d1/","depth":0,"sort_order":0,"has_children":false}
```

**`DocumentSummary` (dari `/doc/list`):**
```json
{"id":"d1","slug":"deploy-runbook","title":"Deploy Runbook","namespace":null,"author":null,"version":1,"updated_at":"2026-01-01T00:00:00Z","parent_id":null,"depth":0,"has_children":false,"sort_order":0}
```
⚠️ Summary **tidak punya** `content`, `tags`, `metadata`, `created_at`, `path`, `content_type`.

**`DocumentSearchResult` (dari `/doc/search`):**
```json
{"document":{"id":"d1","slug":"deploy-runbook","title":"Deploy Runbook","updated_at":"...","parent_id":null,"depth":0,"has_children":false,"sort_order":0,"version":1},"chunk_heading":"# Deploy","chunk_snippet":"...","score":0.81,"mode":"hybrid"}
```

### 9.3 Test case (group by milestone)

**D1 — read path:**
- [ ] `GET /dashboard/api/documents` tanpa session → **401**
- [ ] `GET /dashboard/api/documents/{slug}` tanpa session → **401**
- [ ] `GET /dashboard/api/documents` (valid) → **200** + array `DashboardDocumentSummary` (id, slug, title, parent_id, depth, has_children, sort_order, updated_at) — **tanpa content/tags** (upstream `/doc/list` balik summary)
- [ ] `GET /dashboard/api/documents?roots_only=true` → param diteruskan ke `/doc/list`
- [ ] `GET /dashboard/api/documents/search?q=...&mode=hybrid` → **200** + array `DashboardDocumentSearchResult` (document summary + chunk_heading + chunk_snippet + score + mode)
- [ ] `GET /dashboard/api/documents/{slug}` → **200** + `DashboardDocument` full (id, slug, title, content, tags, parent_id, depth, has_children, version, created_at, updated_at)
- [ ] `GET /dashboard/api/documents/{slug}` upstream **404** → **404**
- [ ] `GET /dashboard/api/documents/{slug}` upstream 200 + `null` (slug tidak ditemukan) → **404** (jangan teruskan null)
- [ ] upstream down/timeout → **502/504**
- [ ] slug karakter khusus (spasi, `/`, unicode) → URL-encoded benar ke upstream

**D2 — write path (semua butuh session + CSRF):**
- [ ] `POST /dashboard/api/documents` tanpa CSRF → **403**
- [ ] `PUT /dashboard/api/documents/{slug}` CSRF salah → **403**
- [ ] `DELETE /dashboard/api/documents/{slug}` CSRF salah → **403**
- [ ] `POST /dashboard/api/documents` (valid) → **200/201**, body diteruskan ke `/doc/create` (slug/title/content/tags/parent)
- [ ] `PUT /dashboard/api/documents/{slug}` (valid) → **200** + `DashboardDocument` (full)
- [ ] `PUT /dashboard/api/documents/{slug}` upstream 200 + `null` (not found) → **404**
- [ ] `DELETE /dashboard/api/documents/{slug}` (valid) → **200** + `{"deleted":bool,"subtree_size":usize}`
- [ ] `POST /dashboard/api/documents/{slug}/move` (valid) → **200** + `{"moved": usize}` (count, bukan bool)
- [ ] `POST /dashboard/api/documents/{slug}/move` body `new_parent` melebihi depth 10 → upstream 400 → **400**
- [ ] `GET /dashboard/api/documents/{slug}/mem-refs` → **200** + `{"doc_slug":"...","memory_ids":[...]}` (upstream pakai field `doc_slug` di request body)

**D6 — unit + final:**
- [ ] Fungsi normalisasi `DashboardDocumentSummary::from(DocumentSummary)`, `DashboardDocument::from(Document)`, `DashboardDocumentSearchResult::from(DocumentSearchResult)` → field mapping benar
- [ ] Full pass `cargo test -p uteke-web` (nggak break test memory/proxy/handler yang udah ada)

### 9.4 Non-unit (manual/visual)

- D3–D5 (tree, render markdown, EasyMDE, parent picker) = verifikasi **manual di browser** setelah deploy (Thoni e2e), bukan `cargo test`.
- Opsional smoke: `GET /dashboard` → login → navigasi `#/documents`.

## 10. Verifikasi vs kode aktual (2026-08-13)

> Hasil trace endpoint upstream & type ke sumbernya. Wajib dibaca sebelum implementasi.

### 10.1 Endpoint upstream — semua ada

| Upstream | Lokasi handler | Request struct | Response type |
|---|---|---|---|
| `POST /doc/create` | `uteke-server/src/handlers.rs:1509` | `DocCreateRequest` (`types.rs:12`) | `Document` (full) |
| `POST /doc/get` | `handlers.rs:1547` | `DocGetRequest` (`types.rs:24`) | `Option<Document>` |
| `POST /doc/list` | `handlers.rs:1593` | `DocListParams` (`types.rs:31`) | `Vec<DocumentSummary>` |
| `POST /doc/search` | `handlers.rs:1614` | `DocSearchRequest` (`types.rs:42`) | `Vec<DocumentSearchResult>` |
| `POST /doc/update` | `handlers.rs:1567` | `DocUpdateRequest` (`types.rs:65`) | `Option<Document>` |
| `POST /doc/move` | `handlers.rs:1636` | `DocMoveRequest` (`types.rs:53`) | `{"moved": usize}` |
| `DELETE /doc/delete` | `handlers.rs:1659` | query `?id=` atau `?slug=` | `{"deleted":bool,"subtree_size":usize}` |
| `POST /doc/mem-refs` | `handlers.rs:1716` | `{"doc_slug":"..."}` (inline struct) | `{"doc_slug":"...","memory_ids":[...]}` |
| `POST /doc/room/list` | `handlers.rs:1368` | inline | rooms linked to doc |

### 10.2 Type shapes — `uteke-core/src/memory/documents.rs`

**`Document` (line 19-63)** — full, dari `/doc/get` & `/doc/create`:
- `id, slug, title, content, namespace?, author?, tags, metadata, version, content_type, created_at, updated_at, parent_id?, path, depth, sort_order, has_children`

**`DocumentSummary` (line 89-111)** — dari `/doc/list`:
- `id, slug, title, namespace?, author?, version, updated_at, parent_id?, depth, has_children, sort_order`
- ⚠️ **Tidak ada** `content, tags, metadata, created_at, path, content_type`

**`DocumentSearchResult` (line 115-128)** — dari `/doc/search`:
- `{document: DocumentSummary, chunk_heading, chunk_snippet, score: f32, mode: String}`

### 10.3 Impl notes wajib

1. **`parent_id` = UUID di response, slug di request.** `DocCreateRequest.parent` & `DocMoveRequest.new_parent` pakai slug (`lib.rs:1300, 1567`). Frontend parent picker kirim slug; display parent di tree butuh lookup slug→title (atau pakai `doc_breadcrumbs` upstream — `lib.rs:1559`).
2. **Max depth 10** — `doc_upsert_with_parent` & `doc_move` reject kalau exceed (`lib.rs:1292`). Tangani error 400 dari upstream.
3. **`/doc/update` balik `Option<Document>`** — `None` kalau not found. Dashboard handler **wajib** map `None` → 404, jangan teruskan 200 + null.
4. **`/doc/move` balik `{"moved": usize}`** — count baris yang dipindah, bukan bool.
5. **`/doc/mem-refs` request field = `doc_slug`** (bukan `slug`) — lihat `handlers.rs:1719`.
6. **`DashboardDocument` di-split jadi 3 struct (Opsi A — locked Thoni 2026-08-13)** karena shape upstream beda:
   - `DashboardDocumentSummary` (list & search document field) — id, slug, title, parent_id, depth, has_children, sort_order, updated_at
   - `DashboardDocument` (get/create/update — full content) — id, slug, title, content, tags, parent_id, depth, has_children, version, created_at, updated_at
   - `DashboardDocumentSearchResult` (search — wrap summary + chunk info + score, mode)
   - Dipilih split atas unified (1 struct dengan field optional) demi type safety: frontend nggak bisa "lupa" kalau list nggak ada content → compile error bukan runtime bug.
7. **`DocCreateRequest` tidak punya `metadata` & `author`** — field ini di-set upstream (default null/None). Frontend create form tidak perlu expose.
8. **Test infra sudah ada** — `tests/common/mod.rs` punya `TestApp::with_upstream()` + `spawn_mock_upstream()`. `tests/dashboard_api.rs:19-30` punya helper `make_session()`. Pattern: drive router via `tower::ServiceExt::oneshot`, baca body pakai `http_body_util::BodyExt`. Mock upstream perlu diperluas buat handle `/doc/*` dengan shape response yang benar (lihat §10.2).
