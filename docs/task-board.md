---
title: Task Board
---

# Task Board: Boards, Columns, and Tasks

> **Uteke grows a work queue.** Boards are projects, columns are statuses, tasks are cards. Tasks are their own entity — outside memories, documents, and rooms — so agents can list, move, and finish work through the same HTTP API and MCP surface they already use.

## What is a Task Board?

A **board** is a project container. Each board holds an ordered set of **columns** (statuses), and each column holds ordered **task cards**. A task belongs to exactly one board and cannot move between boards.

```
Board: "uteke"
├── Backlog        [ card ] [ card ] [ card ]
├── Pending        [ card ]
├── On Going       [ card ]
├── Done           [ card ] [ card ]
└── Blocked        [ card ]
```

| Concept | Entity | Scope |
|---|---|---|
| Board | `boards` | Global — **no namespace** |
| Column | `board_columns` | Belongs to one board |
| Task | `tasks` | Belongs to one board, sits in one column |
| Checklist item | `task_checklist_items` | Belongs to one task |
| Tags | `task_tags` | Per task, **separate from memory tags** |
| Attachments | `task_memories`, `task_documents` | Point at existing memories / documents |

### Why a separate entity

Tasks are not memories. They have their own lifecycle (open → moved → done → deleted), their own ordering, and their own status vocabulary. Folding them into `memories` or `documents` would force the task vocabulary into an enum that cannot represent arbitrary user-defined columns, and would drag the `memories` column list (read positionally at 31 call sites) into every change.

## Design decisions (locked)

These were settled deliberately. Do not re-litigate them during implementation.

1. **Route 4 — new entity.** Tasks live in their own tables with their own endpoints and MCP tools.
2. **Global boards, no namespace.** Boards and tasks carry no `namespace` column. This removes the entire `/namespaces` enumeration problem, because `list_namespaces` is `SELECT DISTINCT namespace FROM memories` and would otherwise never show a board-only namespace.
3. **Board = project container.** Hierarchy is board → column → task.
4. **One board per task, no cross-board moves.** A move is only ever between columns of the *same* board.
5. **Subtask = checklist item.** Not a child task. A checklist item is `done`/`undone` only — it has no tags, no attachments, and never appears as a card.
6. **Deletion cascades, with no guard.** Deleting a column deletes its tasks. Deleting a board deletes its columns and tasks. There is no `strategy` parameter and no `refuse` mode.
7. **No trash.** Deletion is permanent. There is no soft-delete for tasks — `deprecated` is a *memory* lifecycle flag and must not be reused here.
8. **New cards go to the bottom.** `sort_order = MAX(sort_order) + 1` within the destination column.
9. **Dates are RFC3339 and both optional.** `start_at` and `due_at` are full RFC3339 timestamps, not date-only strings. Both are nullable and neither is required to create a task — a card with no dates is a normal card, not an incomplete one.
10. **Task tags are separate.** `GET /tags` reads `memory_tags` only; task tags never appear there.
11. **Title search uses FTS5** (`tasks_fts`).
12. **One MCP endpoint, many tools.** `POST /mcp` already exists; new tools are dispatched from `tools/call`.
13. **Attachments are created from the task side.** There is no existing "attach an existing memory to X" route anywhere in the repo — not even for rooms. Each attachment route must be written new.
14. **Default protections.** The default board cannot be renamed or deleted. Default columns can be renamed but not deleted.

## Schema (v20)

`CURRENT_SCHEMA_VERSION` is **19**; this feature bumps it to **20**. The migration arm is added to the `loop { version += 1; match version { … } }` in `crates/uteke-core/src/memory/schema.rs`.

```sql
CREATE TABLE IF NOT EXISTS boards (
    id         TEXT PRIMARY KEY,
    title      TEXT NOT NULL,
    is_default INTEGER NOT NULL DEFAULT 0,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS board_columns (
    id         TEXT PRIMARY KEY,
    board_id   TEXT NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
    title      TEXT NOT NULL,
    is_default INTEGER NOT NULL DEFAULT 0,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_board_columns_board
    ON board_columns(board_id, sort_order);

CREATE TABLE IF NOT EXISTS tasks (
    id          TEXT PRIMARY KEY,
    board_id    TEXT NOT NULL REFERENCES boards(id)         ON DELETE CASCADE,
    column_id   TEXT NOT NULL REFERENCES board_columns(id)  ON DELETE CASCADE,
    title       TEXT NOT NULL,
    description TEXT,
    sort_order  INTEGER NOT NULL DEFAULT 0,
    start_at    TEXT,
    due_at      TEXT,
    author      TEXT DEFAULT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_column ON tasks(column_id, sort_order);
CREATE INDEX IF NOT EXISTS idx_tasks_board  ON tasks(board_id);
CREATE INDEX IF NOT EXISTS idx_tasks_due    ON tasks(due_at);

CREATE TABLE IF NOT EXISTS task_checklist_items (
    id         TEXT PRIMARY KEY,
    task_id    TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    text       TEXT NOT NULL,
    done       INTEGER NOT NULL DEFAULT 0,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_task_checklist_task
    ON task_checklist_items(task_id, sort_order);

CREATE TABLE IF NOT EXISTS task_tags (
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    tag     TEXT NOT NULL COLLATE NOCASE,
    PRIMARY KEY (task_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_task_tags_tag ON task_tags(tag);

CREATE TABLE IF NOT EXISTS task_memories (
    task_id   TEXT NOT NULL REFERENCES tasks(id)    ON DELETE CASCADE,
    memory_id TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
    added_at  TEXT NOT NULL,
    PRIMARY KEY (task_id, memory_id)
);
CREATE INDEX IF NOT EXISTS idx_task_memories_task   ON task_memories(task_id);
CREATE INDEX IF NOT EXISTS idx_task_memories_memory ON task_memories(memory_id);

CREATE TABLE IF NOT EXISTS task_documents (
    task_id  TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    doc_slug TEXT NOT NULL,          -- deliberately NO FK
    added_at TEXT NOT NULL,
    PRIMARY KEY (task_id, doc_slug)
);
CREATE INDEX IF NOT EXISTS idx_task_documents_task ON task_documents(task_id);
CREATE INDEX IF NOT EXISTS idx_task_documents_slug ON task_documents(doc_slug);

CREATE VIRTUAL TABLE IF NOT EXISTS tasks_fts USING fts5(
    title,
    content='tasks',
    content_rowid='rowid'
);
```

### Notes on the schema

- **Index the second column of every junction PK.** `task_memories` indexes `memory_id` and `task_documents` indexes `doc_slug` so the reverse question ("which task holds this memory?") is a lookup, not a scan. `room_memories` omits this index — do not copy that omission.
- **No FK on `task_documents.doc_slug`** — matching `room_documents`. Document slugs are globally unique and not namespace-isolated, and documents can be deleted. Validate the slug resolves to a real document at attach time instead.
- **`PRAGMA foreign_keys=ON`** is set on every store open, so every `ON DELETE CASCADE` above genuinely fires — including recursively (board → columns → tasks → checklist/junctions).
- **Domain validation lives in Rust, not SQL `CHECK`.** `memory_type` is validated via `MemoryType::from_str_opt` and the house does not use `CHECK` constraints. Do the same for column and board title rules.
- **IDs** are `uuid::Uuid::now_v7().to_string()` — time-ordered, not v4.
- **Timestamps** are RFC3339 `String` columns. On write, always parse client input into `chrono::DateTime<Utc>` and re-serialize with `to_rfc3339()`. Never store a raw client string.
- **`start_at` and `due_at` are optional (`NULL` allowed).** Only `created_at` and `updated_at` are `NOT NULL`. A task with no dates is valid at every layer: the column is nullable, the request fields are `Option<String>`, and the response omits or nulls them. Do not default a missing `due_at` to the current time, and do not treat a missing date as a validation error.
- **Date filters exclude undated tasks.** `due_before` / `due_after` must match only rows where `due_at IS NOT NULL`; a plain `WHERE due_at < ?` is fine because SQL comparisons against `NULL` are not true, but write it deliberately and say so in the endpoint description — otherwise someone will "fix" it later into `coalesce(due_at, ...)` and start reporting undated tasks as overdue.
- **No date means not overdue.** A task with `due_at = NULL` is never overdue and must never be counted in an overdue badge or a "past due" filter. Guard the comparison on the nullable side, not on `now()`.
- **`column_id` must belong to the task's `board_id`.** SQLite has no composite FK here and the repo uses none, so this is a Rust-side validation with no compile-time gate. A missed check silently places a card in another board's column.

### Seeding

The migration creates one default board with the five default columns:

`Backlog`, `Pending`, `On Going`, `Done`, `Blocked`

Each new board created later is seeded with the same five columns. Those five are `is_default = 1` and cannot be deleted (rename is allowed). Custom columns are `is_default = 0` and can be added and deleted. This guarantees every board always has at least five columns, so "card has nowhere to go" is structurally impossible.

## FTS5: use the `'delete'` command, not `DELETE FROM`

This is the single most important implementation detail in this document. Getting it wrong produces silently wrong search results.

For an FTS5 table declared with `content=<table>` (external content), the index is **not** stored inline, so plain `DELETE FROM ftstable WHERE rowid = ...` does **not** remove the term entries. The correct form issues the special command through the FTS table:

```sql
-- correct
INSERT INTO tasks_fts(tasks_fts, rowid, title) VALUES ('delete', old.rowid, old.title);
```

The triggers must be:

```sql
CREATE TRIGGER IF NOT EXISTS tasks_fts_ai AFTER INSERT ON tasks BEGIN
    INSERT INTO tasks_fts(rowid, title) VALUES (new.rowid, new.title);
END;

CREATE TRIGGER IF NOT EXISTS tasks_fts_ad AFTER DELETE ON tasks BEGIN
    INSERT INTO tasks_fts(tasks_fts, rowid, title) VALUES ('delete', old.rowid, old.title);
END;

CREATE TRIGGER IF NOT EXISTS tasks_fts_au AFTER UPDATE ON tasks BEGIN
    INSERT INTO tasks_fts(tasks_fts, rowid, title) VALUES ('delete', old.rowid, old.title);
    INSERT INTO tasks_fts(rowid, title) VALUES (new.rowid, new.title);
END;
```

### Two failure modes the wrong pattern produces

1. **Stale matches.** A deleted task's title still matches. Measured: delete 1 of 2 tasks sharing a keyword, `MATCH` still returns 2 instead of 1.
2. **Ghost rows after rowid reuse.** SQLite assigns `max(rowid) + 1`. Delete all tasks in a column, then insert a new task — it reuses the freed rowid, and the stale FTS entry now resolves to the **new** task. Searching for a word from the deleted task returns an unrelated card.

`integrity-check` **passes** on a stale index, so this is never self-detected.

### The same bug already exists in `documents_fts` — fix it in this change

`crates/uteke-core/src/memory/schema.rs` defines the wrong pattern twice: once in the v12 migration (best-effort `let _ = execute`) and once in `ensure_documents_fts_create()`. Both the `_update` and `_delete` triggers are affected:

```sql
-- currently in the repo — WRONG for content= tables
CREATE TRIGGER documents_fts_update AFTER UPDATE ON documents BEGIN
  UPDATE documents_fts SET title = new.title, slug = new.slug, content = new.content
  WHERE rowid = new.rowid; END;
CREATE TRIGGER documents_fts_delete AFTER DELETE ON documents BEGIN
  DELETE FROM documents_fts WHERE rowid = old.rowid; END;
```

Why it has gone unnoticed: `Store::search_documents_fts` joins back to `documents` on `rowid`, which **masks** orphaned index rows. Measured: plain `MATCH` returns 2 for a stale keyword while the joined query returns 1. The mask only holds while no new document reuses the freed rowid — the ghost-row case is not masked.

Repair, as part of this change:

1. **Drop and recreate** the affected triggers. `CREATE TRIGGER IF NOT EXISTS` will not replace an existing wrong trigger — the old definition survives untouched. Drop the `documents_fts_insert` / `_update` / `_delete` triggers and recreate the update/delete pair in the correct form.
2. **Rebuild** the index afterwards: `INSERT INTO documents_fts(documents_fts) VALUES ('rebuild')`. A rebuild does clear stale rows (verified — a stale `MATCH` of 1 drops to 0).
3. **Do the same repair for `memories_fts` if it exists.** Its triggers in `crates/uteke-core/src/memory/fts5.rs` already use the correct `'delete'` command, so verify rather than assume, and leave it alone if it is already correct.
4. **Drop then create, do not `IF NOT EXISTS`.** This is the same pattern the v14 migration uses when it rebuilds `memories_fts` for a changed column set — follow it.

Because the triggers must be recreated, this repair is best placed in the new migration arm (v20) plus inside the `ensure_*` path, so both fresh and existing stores converge.

## Implementation surfaces (all four, in order)

Nothing here is optional, and only one of them is enforced by a build gate.

### 1. `uteke-core`

- `crates/uteke-core/src/memory/store.rs` — bump `CURRENT_SCHEMA_VERSION` to `20`; add the new tables to `SCHEMA` (base `CREATE TABLE` list).
- `crates/uteke-core/src/memory/schema.rs` — add `20 => self.migrate_v19_to_v20()?` to the match in `run_migrations`, and write `migrate_v19_to_v20()`. Follow the house style: `tracing::info!` a one-line summary, `CREATE TABLE IF NOT EXISTS`, idempotent statements.
- If you use `column_exists_in`, add the new tables to its `ALLOWED_TABLES` whitelist — it returns `false` for unlisted tables, silently.
- New modules: `tasks.rs` (public `Uteke` surface) plus `memory/tasks.rs` (SQL), mirroring the `rooms.rs` / `memory/rooms.rs` split.
- Add an idempotent `ensure_tasks_fts()` in the `ensure_schema_*` family that creates the virtual table, creates all three triggers, and backfills. Do **not** rely on a best-effort migration for this.

### 2. `uteke-server`

- `crates/uteke-server/src/types.rs` — request structs. Note `deny_unknown_fields` is used on `RememberRequest` / `RoomRememberRequest`; a client sending a new field to an older server gets a 400, not a silent ignore. Ship the server first.
- `crates/uteke-server/src/handlers.rs` — one `(Method::X, "/path")` arm per route, plus registration in `read_only_post_paths` for POST-based read endpoints.
- `crates/uteke-server/src/api_registry.rs` — an `Endpoint { … }` entry per route. The test `registry_covers_handler_routes` parses `handlers.rs` as **source text**, so a missing entry fails `cargo test -p uteke-server`. Note it only sees literal paths — a route built with `format!` is invisible to the gate.
- Regenerate `docs/api-reference.md` with `cargo run -p docgen`. Never hand-edit it; CI fails on staleness.

### 3. `uteke-mcp`

- `crates/uteke-mcp/src/lib.rs` — a `tool_*()` builder **and** an arm in `tools/call`. These two lists are independent and drift silently: a name present in one and missing from the other yields `Unknown tool`, with no server-side log.
- Update the tool table in `docs/mcp.md`.

### 4. `uteke-web`

- `crates/uteke-web/src/dashboard_api.rs` — handler + request struct.
- `crates/uteke-web/src/dashboard.rs` — route.
- `crates/uteke-web/assets/dashboard.html` — the board view (SPA is Bootstrap 5.3 + vanilla JS; there is no sortable library today).

## Integration points no gate catches

A new entity is silently missing from these unless added deliberately. None of them fails a build:

- **`read_only_post_paths`** in `handlers.rs` is a hand-maintained list (16 entries today). A POST-based read endpoint (the `/doc/list`, `/room/stats` pattern) returns **403 for read-only tokens** until listed.
- **`/mcp` is not in that list.** The read-only gate runs *before* the route match, so a read-only token currently receives 403 on **every** MCP call. If read-only MCP access is wanted, gate per-tool inside the MCP handler rather than per-endpoint — one JSON-RPC endpoint carries many tools.
- **`SECTIONS`** in `crates/uteke-core/src/structural_export.rs` is a fixed list, and the import pass-2 match has no arm for unknown tags: an older binary importing a newer export **drops task records with no error**. Decide whether the export format version moves.
- **`rebuild_fts5()`** rebuilds `memories_fts` only, and is what structural import runs afterwards. Task import needs its own rebuild.
- **`categorize()`** in `crates/docgen/src/main.rs` ends in a fallback, so `/board/*`, `/column/*`, and `/task/*` land in "📝 Other" until a bucket is added.
- **`timeline_events.memory_id`** is a `NOT NULL REFERENCES memories(id)` column, so the per-record audit log cannot record task changes. A history feature needs its own table or is out of scope.
- **`list_namespaces`** is `SELECT DISTINCT namespace FROM memories` — not an issue here, because boards have no namespace. This is why the global-board decision removed a whole integration point.

## API surface

All POST-based reads must also be added to `read_only_post_paths`.

### Boards

| Method | Path | Notes |
|---|---|---|
| POST | `/board/create` | `{title}` → new board + 5 default columns |
| GET | `/board/list` | All boards with column counts |
| GET | `/board/get?id=` | Board + its columns |
| POST | `/board/rename` | `{id, title}` → 409 if `is_default` |
| DELETE | `/board/delete?id=` | Cascades columns + tasks. 409 if `is_default` |

### Columns

| Method | Path | Notes |
|---|---|---|
| POST | `/column/create` | `{board_id, title}` → appended at the end |
| GET | `/column/list?board_id=` | Ordered by `sort_order` |
| POST | `/column/rename` | `{id, title}` → allowed for default columns |
| POST | `/column/reorder` | `{board_id, ordered_ids}` → dense reindex |
| DELETE | `/column/delete?id=` | Cascades its tasks. 409 if `is_default` |

### Tasks

| Method | Path | Notes |
|---|---|---|
| POST | `/task/create` | `{board_id, column_id, title}` required; `description`, `start_at`, `due_at`, `tags` all optional → appended at the bottom |
| POST | `/task/list` | Filter by `board_id`, `column_id`, `tag`, `due_before`, `due_after` (date filters skip undated tasks); aggregate counts |
| GET | `/task/get?id=` | Task + checklist + attachment lists |
| POST | `/task/update` | Partial; `title`/`description`/dates/tags. Dates are nullable — an explicit `null` clears a previously set date, so distinguish "absent" (leave unchanged) from "null" (clear) |
| POST | `/task/move` | `{id, column_id, sort_order}` → column must belong to the task's board |
| POST | `/task/search` | FTS5 over title |
| DELETE | `/task/delete?id=` | Permanent |

### Checklist, tags, attachments

| Method | Path | Notes |
|---|---|---|
| POST | `/task/checklist/add` | `{task_id, text}` |
| POST | `/task/checklist/update` | `{id, text?, done?}` |
| DELETE | `/task/checklist/remove?id=` | |
| PUT | `/task/tag/add` | `{task_id, tag}` → `INSERT OR IGNORE` |
| DELETE | `/task/tag/remove?task_id=&tag=` | |
| PUT | `/task/memory/add` | `{task_id, memory_id}` → validate the UUID resolves, then `INSERT OR IGNORE` |
| DELETE | `/task/memory/remove` | |
| PUT | `/task/document/add` | `{task_id, doc_slug}` → validate the slug resolves, then `INSERT OR IGNORE` |
| DELETE | `/task/document/remove` | |

### Response shape for a board

Return aggregates in one pass, never per card:

```
card = {
  id, title, column_id, sort_order,
  start_at, due_at,
  memory_count, doc_count,          -- GROUP BY over the junctions
  checklist: { done, total },        -- GROUP BY over checklist items
  tags: [...]
}
```

Fetching attachments per card is N+1: `get_by_ids` exists in core but is **not** exposed over HTTP, so a card with k attachments costs k lookups unless a batch call is added as its own decision.

## MCP tools

Tools are prefixed by entity, matching the existing `uteke_room_*` convention:

`uteke_board_create`, `uteke_board_list`, `uteke_board_get`, `uteke_board_rename`, `uteke_board_delete`,
`uteke_column_create`, `uteke_column_list`, `uteke_column_rename`, `uteke_column_reorder`, `uteke_column_delete`,
`uteke_task_create`, `uteke_task_list`, `uteke_task_get`, `uteke_task_update`, `uteke_task_move`, `uteke_task_delete`, `uteke_task_search`,
plus checklist, tag, and attachment tools.

Every one of these is a thin adapter over a core method — MCP opens the store directly (`Uteke::open`) and calls core methods, it does not go through HTTP. So each new operation is **one core method plus two thin wrappers**, not two implementations.

There are no MCP `annotations` / `destructiveHint` in this codebase, so a delete tool gives an agent no warning at all. Cascade behaviour must be documented in the tool description text.

## Testing

- Core: round-trip create → move → checklist → attach → delete, asserting cascade removes checklist and junction rows.
- **Dateless tasks are first-class.** Create a task with neither `start_at` nor `due_at` and assert it is created, listed, moved, and returned without error. Then assert it does **not** appear in a `due_before` filter and is not counted as overdue — a `NULL` date silently changing a comparison result is the failure this test exists to catch.
- **FTS correctness is its own test.** Assert that after deleting a task, `MATCH` on its title returns zero — and specifically re-test **after inserting a new task**, to catch rowid reuse.
- Server: `cargo test -p uteke-server` enforces the API registry gate.
- FTS sync test must fail on the wrong pattern. Write it so the pre-fix implementation cannot pass.

## Pitfalls checklist for the implementing agent

1. `tasks_fts` triggers must use the `'delete'` command — not `DELETE FROM` / `UPDATE`.
2. `CREATE TRIGGER IF NOT EXISTS` will **not** repair an existing wrong trigger: drop then create.
3. Validate `column_id` belongs to the task's `board_id` in Rust; no composite FK exists.
4. Add new tables to `column_exists_in`'s `ALLOWED_TABLES` if you call it.
5. Add POST read routes to `read_only_post_paths`, or read-only tokens get 403.
6. Add the entity to `SECTIONS` and the import match, or exports silently drop it.
7. Add a `categorize()` bucket for the new paths in `docgen`.
8. Parse all incoming timestamps to `DateTime<Utc>`; never store the raw string.
9. Add the tool in **both** MCP lists and update `docs/mcp.md`.
10. Treat `start_at` and `due_at` as optional everywhere — nullable column, `Option` in the request, no defaulting, and excluded from date-range filters.
