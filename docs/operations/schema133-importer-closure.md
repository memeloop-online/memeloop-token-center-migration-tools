# Schema133 importer qualification

This is separate from the [historical schema132 qualification](schema132-importer-closure.md). A132 artifact is not qualified for133; the133 artifact rejects132. Actual target migration inventory must match at execution time. This source change neither asserts production has upgraded nor authorizes import.

## Immutable product and closure

Product revision: `a31f28f497036b0374a37077c218505a63aecbc0` (merged PR653).
Cargo.lock SHA256: `083e616fe14a58cde159c7ff33607389f91be4df90e5bbb7c4cbe266ddd7705a`, including ctutils0.4.4. The compile-only plugin fixture remains `21489f4fee6266de99fe7e258349468ce77af8bd`.

`schema133-files.json` binds extracted importer files and three assembled module exports to the final product bytes. Existing CI checks the checkout, lock and closure before building with Rust1.95 and `--locked`, then seals the binary, retained source archive and exact133 compatibility manifest. No runtime downloading, compilation or migration is introduced.

## Actual132 to133 impact

Both product migration lists add `migrations/common/0133_proxy_operational_terminals.sql`: one independent runtime-receipt table, a unique reservation constraint, timestamp/status/duration checks and two tenant/key/time indexes. CPA tables, financial columns, observation prefix representation and title/summary tables are unchanged. The exact inventory is1..113,115..133 (132 rows);114 remains absent.

CPA exact/unlinked writes still call the unchanged synchronous `record_conversation_observation_in_transaction`. Prefix and title lifecycle APIs are unchanged. Retirement retains same-transaction, tenant/key/session-scoped title cleanup and old-lease fencing. CPA must not create, delete, rewrite or financially acknowledge operational receipts.

Queries do change: request/archive reads join receipts by request ID, created time, tenant, key and reservation. A non-gap request-record response takes priority; otherwise receipt response evidence is used. Projected conversation events can use operational outcome/timing while retaining request-sourced accounting. Session active filters exclude operationally completed requests even when financial completion remains unknown. Unknown usage must not become zero cost, release a hold or retire financial recovery.

The importer now probes every receipt column read-only in addition to existing importer/title/summary relations. Missing133, older132, newer134, missing relations and renamed identity/content columns fail before importer/checkpoint writes. No older-schema or observation-array compatibility branch is added.

## Existing GHA matrix

- SQLite and isolated PostgreSQL: reconstruct132 by removing only the133 table/inventory row, reject import read-only, then apply the product's actual133 DDL and accept the exact inventory; retain missing-version/table/column rejection.
- Existing exact/unlinked/quarantine/CAS, large-record prefix/conversation readback, snapshot/delta/replay and financial invariant fixtures run against the new pin on both backends.
- Exact-import fixtures retain an independent operational receipt across import, injected finalization rollback, tombstone retirement and replay. Archive readback prefers the imported non-gap response and returns retained gap evidence after retirement; financial, usage membership and title assertions remain.
- Existing title lifecycle/retirement tests preserve active/other-key titles, rollback, replay idempotency and rejection of old lease writes.
- Explicitly run product `db::requests::operational_terminal::tests` in the PostgreSQL-required job: SQLite/PostgreSQL unknown-finance statistics, filters, cache/cost coverage, conversation projection, receipt authority/replay, storage rollback and financial recovery.
- Artifact substitution tests reject132/134. All existing sealing/release verification must pass before a133 artifact is qualified. A PR or schema label alone is not qualification evidence.

No local build/test/install, cluster action, source-volume access, import or deployment is included. Newton retains exclusive operational ownership. Offline source digest needs no PostgreSQL target and is not blocked, nor is product TEST/release publishing. No migration number, source format, financial or metadata standard changes.
