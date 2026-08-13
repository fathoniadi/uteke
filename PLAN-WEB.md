# PLAN — uteke-web Dashboard (upgrade SPA ke feature set lengkap)

> Status: **SELESAI** — 2026-08-13 (semua milestone M7.1–M7.6 done, 142 test lulus, Bootstrap 5 + vanilla.js)
> Scope: upgrade SPA dashboard `uteke-web` dari minimal (recall+remember) → feature set lengkap untuk manajemen memory, dengan layer API REST typed di Rust.

## 1. Tujuan

Membawa fitur manajemen memory yang lengkap ke dashboard `uteke-web` — **tanpa mengubah `uteke-server`** (tetap dipanggil via token statis) — dengan kontrak API browser-facing yang bersih (RESTful).

Fitur target:
- **Browsing** — tabel memory terpaginate (20/page), kolom: ID, content, tags, type, importance, created, actions.
- **Pencarian** — 3 mode: semantic (recall), keyword FTS (search), browse (list).
- **Filter & sort** — dropdown namespace, dropdown tag (dengan count), search debounce 300ms, sort kolom asc/desc (importance, created, tags, type, id).
- **CRUD** — detail modal, create (chip tag editor + namespace), edit (content/tags/type/importance/pinned), forget (soft-delete + konfirmasi).
- **Info & visual** — stats (total memory), label user, pin ⭐, importance bar berwarna, type badges, tag-click filter, responsive.

## 2. Gap analysis

### uteke-web SEKARANG (dashboard minimal, M7)
- SPA polos: hanya **Recall (search)** + **Remember (create)**.
- `dashboard_api` = passthrough generik ke upstream, **query string HILANG**, dan bentuk endpoint upstream **mentah** (POST /recall, POST /remember, dst).
- Tidak ada endpoint `GET /dashboard/api/profile`.
- Recall body cuma `{query, limit}` (tidak set `search_type`/`strategy`).

### Target (yang harus dibangun)
- Semua fitur di §1 Tujuan yang belum ada: browsing table, 3 mode search, filter namespace/tag, sort, pagination, detail modal, edit, forget, stats, tags, namespaces, profile.

## 3. Arsitektur (OPSI B — typed API layer)

SPA memanggil **API REST bersih milik uteke-web** (`/dashboard/api/...`), lalu Rust **menerjemahkan** ke endpoint uteke-server di sisi server.

```
Browser (SPA)
   │  GET/POST/PUT/DELETE /dashboard/api/memories, /tags, /namespaces, /stats, /profile
   ▼
uteke-web  ── typed handler + UtekeClient (Rust) ──►  uteke-server
   (session cookie + CSRF)              (inject Bearer <token statis>)
```

- Browser **tidak pernah** melihat bentuk endpoint uteke-server.
- uteke-web jadi "penerjemah": parse kontrak REST → panggil uteke-server dengan path/body yang benar (mapping di §4).

## 4. Kontrak API browser-facing (typed)

| Aksi SPA | Method | Path | Body/query |
|---|---|---|---|
| browse / search (list·semantic·fts) | GET | `/dashboard/api/memories` | `q, mode, tag, namespace, limit, offset` |
| detail | GET | `/dashboard/api/memories/{id}` | — |
| create | POST | `/dashboard/api/memories` | `{content, tags, namespace}` |
| edit | PUT | `/dashboard/api/memories/{id}` | `{content, tags, memory_type, importance, pinned}` |
| forget | DELETE | `/dashboard/api/memories/{id}` | — |
| tags | GET | `/dashboard/api/tags` | `namespace?` |
| namespaces | GET | `/dashboard/api/namespaces` | — |
| stats | GET | `/dashboard/api/stats` | `namespace?` |
| profile | GET | `/dashboard/api/profile` | — (dari session, bukan upstream) |

### Mapping ke uteke-server (server-side)

| Kontrak | → upstream call |
|---|---|
| GET memories (mode=semantic) | POST `/api/v1/recall` `{query, limit, search_type:"memory", strategy:"hybrid", namespace?}` |
| GET memories (mode=fts) | POST `/search` `{query, limit, namespace?}` |
| GET memories (mode=list / default) | POST `/list` `{limit, offset, tag?, namespace?}` |
| GET memories/{id} | GET `/memory?id=<id>` |
| POST memories | POST `/remember` `{content, tags, type:"note", namespace?}` |
| PUT memories/{id} | PUT `/memory` `{id, content, tags, importance, pinned, memory_type}` |
| DELETE memories/{id} | DELETE `/forget?id=<id>` |
| GET tags | GET `/tags?namespace=<ns>` |
| GET namespaces | GET `/namespaces` |
| GET stats | GET `/stats?namespace=<ns>` |

Catatan endpoint recall: uteke-server strip prefix `/api/vN/` (#737), jadi `/api/v1/recall` ≡ `/recall`.

Response shape: `/recall` & `/search` = `SearchResult[]`, `/list` = `Memory[]`, `/memory` = `Memory`, `/stats` = `StoreStats`, `/tags` = `TagEntry[]`, `/namespaces` = `string[]`, `/remember` = `Memory`.

## 5. Perubahan backend (Rust)

1. **Module typed client** (baru, misal `dashboard_api.rs`):
   - Struct response: `Memory`, `SearchResult`, `TagEntry`, `StoreStats`, payload create/update.
   - Helper `UtekeClient` (atau function di `AppState`) yang panggil upstream via `http_client` + inject `Authorization: Bearer <upstream_token>`.
2. **Typed handlers**:
   - `handle_list_memories` (dispatch mode → recall/search/list), `handle_get_memory`, `handle_create_memory`, `handle_update_memory`, `handle_forget_memory`, `handle_tags`, `handle_namespaces`, `handle_stats`, `handle_profile`.
3. **CSRF** tetap untuk mutasi (POST/PUT/DELETE) via double-submit cookie — sudah ada, dipakai ulang.
4. **Route registration** — ganti generic `/dashboard/api/*` passthrough dengan route typed eksplisit (method + path), tetap di bawah `require session`.
5. **Hapus** generic `dashboard_api` passthrough (default: hapus, eksplisit semua).

## 6. Perubahan frontend (port SPA)

- Table browse + pagination (PAGE=20).
- `load()` panggil `GET /dashboard/api/memories?q&mode&tag&namespace&limit&offset`.
- Filter namespace + tag, search debounce 300ms.
- Sort client-side (importance/created/tags/type/id).
- Detail modal, create modal (chip tags), edit modal (type/importance/pinned), forget confirm.
- Stats + user label (`/profile`), pin ⭐, importance bar, type badges, tag-click filter, responsive.
- Semua fetch mutasi kirim `X-CSRF-Token: getCSRF()`.
- Hapus junk `// Placeholder - will be added via edit`.

## 7. Tahapan (milestone)

- **M7.1** ✅ — Backend typed layer: struct response + UtekeClient + handler list/get/create/update/forget/tags/namespaces/stats/profile + route registration + CSRF. Unit test (client URL/body mapping, handler) + integration (axum test client + httptest upstream).
  - File: `crates/uteke-web/src/dashboard_api.rs` (baru), `crates/uteke-web/src/dashboard.rs` (route typed), `crates/uteke-web/src/lib.rs` (module register).
  - Test: 5 unit test (struct conversion + type normalization) + 16 integration test (auth gating, CSRF, all 9 typed handlers against shape-accurate mock upstream, empty-query fallback).
- **M7.2** ✅ — SPA: browse table + pagination + list mode + sort.
- **M7.3** ✅ — SPA: 3 mode search (semantic/keyword/browse) + debounce 300ms.
- **M7.4** ✅ — SPA: filter namespace + tag (dengan count) + stats cards + user label.
- **M7.5** ✅ — SPA: detail modal + create modal (chip tag editor) + edit modal (type/importance slider/pin) + forget confirm. CSRF di semua mutasi.
- **M7.6** ✅ — Polish: pin toggle, importance bar berwarna, type badges, tag-click filter, responsive layout. Bootstrap 5 (CDN) + vanilla.js + Bootstrap Icons — no build step, no framework runtime. Smoke test end-to-end via browser preview (login flow + mock upstream).

## 7.1. Status implementasi (2026-08-13)

| Milestone | Status | Catatan |
|-----------|--------|---------|
| M7.1 | ✅ done | 5 unit + 16 integration test, clippy clean |
| M7.2 | ✅ done | Tabel 20/page, sort client-side (newest/oldest/importance/type/id) |
| M7.3 | ✅ done | 3 mode (browse/semantic/fts), debounce 300ms, empty query → fallback list |
| M7.4 | ✅ done | Filter ns + tag (count), stats cards, user label dari `/profile` |
| M7.5 | ✅ done | Detail/create/edit/forget modal, chip tag editor, importance slider, pin checkbox |
| M7.6 | ✅ done | Bootstrap 5 + vanilla.js, pin toggle, importance bar, type badges, responsive, trailing-slash redirect fix |

**Verifikasi**: 142 test lulus (75 unit + 16 integration dashboard_api + 51 handler), `cargo clippy -p uteke-web --all-targets -- -D warnings` clean, `cargo fmt -p uteke-web -- --check` clean.

## 8. Open questions

1. ~~Opsi A atau B?~~ → **OPSI B**.
2. Type default saat create memory: `note` atau `fact`? (default: `note`)
3. Perlu tidak room/doc ikut diport? Scope awal fokus memory saja. (default: tidak)
4. Dashboard tetap satu proses dengan OAuth2 auth server + proxy? (default: ya, tidak blocking)

## 9. Referensi

- Endpoint uteke-server: `/home/ubuntu/uteke/crates/uteke-server/src/handlers.rs` + `api_registry.rs` (versioning #737 di `types.rs`).
- Kode target: `/home/ubuntu/uteke/crates/uteke-web/src/dashboard.rs` (+ module baru `dashboard_api.rs`).
- Plan induk uteke-web: `/home/ubuntu/uteke/PLAN.md` (M7).
