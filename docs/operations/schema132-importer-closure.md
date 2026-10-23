# Schema132 importer source closure

The importer is owned exclusively by migration-tools. The product retired its one-shot importer surface, so changing the old engine70 pin alone cannot produce a current importer.

## Source plan and ownership

Use product master base `072769105392e7d24a12dc4780fa16ab6a01d1e7`, whose SQLite/PostgreSQL migration lists end at132. The recovery owner's read-only evidence on 2026-10-23 reports production max132, 131 migration rows, and versions1..113,115..132. That evidence is a point-in-time observation: the import owner must confirm the actual schema again at execution time. The runtime accepts only its exact qualified migration list.

`ops/runtime-engine` extracts the existing one-shot parser/plan/apply modules, CLI, three archive DB adapters, archive session-total helper and regression fixtures from `a65097f952e174ac482abe6ff719966fa9d330cb`. PR44's configurable large-record reader and regressions are incorporated directly; digest/export implementation stays in its existing location. There is one importer implementation, not a second runtime path.

CI assembles this closure into an isolated checkout of the exact product base using three module/export additions. The closure calls the product's current `record_conversation_observation_in_transaction` API with explicit upstream-response and materialization state. Product owns prefix construction, fingerprint encoding, tenant path validation, archive storage and conversation reading. No prefix storage implementation, migration, old observation decoder or serving fallback is copied into the closure.

The tools-owned CLI reads only target DB/object-store configuration and never migrates. Its read-only precondition requires the complete exact132 migration set, importer relations and the current session reading columns, rejecting missing versions, relation drift and newer133 targets. Retained source export formats are migration inputs, not a product runtime storage fallback.

Version identity is compared against the product's actual migration list, not a contiguous numeric range: this exact base intentionally has no114 entry. The bounded read also rejects unexpected entries without weakening the target version check.

`schema132-files.json` binds every extracted file and assembled product module to exact SHA256 bytes. The immutable product revision, Cargo.lock, closure manifest hash, compiler and target are checked before CI build and again before sealing. The retained source archive includes all extracted untracked files. Release verification rejects stale closure, substituted artifacts and a different target schema manifest.

Compiling the product library tests also requires its reviewed `memeloop-token-center-example-plugins` fixture repository at `21489f4fee6266de99fe7e258349468ce77af8bd`, the same pin as the product's checkout action. CI checks that out under the ignored `.plugin-examples` directory; its identity is retained in the compatibility manifest. It is a test compile dependency, not a runtime fallback or a production plugin installation.

## CI acceptance matrix

- Current product library: importer parser/bounded reader tests, including the PR44 20921650-byte case and exact configured budget rejection.
- SQLite132 and PostgreSQL132: exact migration inventory, missing127/131/132 and unexpected0/114/133 rejection, missing title/summary relations and renamed columns rejected without migration or importer checkpoint writes.
- SQLite132: existing import, exact/unlinked/quarantine, full stable snapshot/delta, tenant/replay/CAS/financial invariants; large-record current-format fingerprint and conversation readback; current title enqueue and replay without duplicate jobs or synthesized response summaries.
- PostgreSQL132 service: existing native-type quarantine/unlinked/locator-CAS/advisory-lock cases; full large-record import/dry-run/replay/financial invariant fixture in its own schema with current fingerprint, conversation readback and title job assertions. CI requires the PostgreSQL URL, so this row cannot silently skip.
- Current product session reading merge regression: moves only the owned key's response summary, preserves ready titles and invalidates stale title leases.
- Exact-observation retirement on both databases: a genuinely settled, nonzero-cost request is projected through the current terminal outbox, then imported and tombstoned. Previous-cluster and unlinked cases assert request/outbox/fact membership, exact totals/hourly/daily contributions, unchanged ledger and balances, finalization rollback and replay. Restoration reuses the product's session reclassification helper within the import transaction.
- Retirement title lifecycle on both databases: remove title state only after the last observation in that tenant/key/session retires, within the same transaction. Actual product title claims/completions verify active-session lease preservation, rollback restoration and rejection of stale completion after commit/replay; unrelated tenant/key/session title state remains unchanged. The existing full tombstone fixture additionally checks running-title rollback, removal and replay.
- Locked release build: importer CLI help, packaged byte identity, complete retained source closure, compatibility manifest and existing standalone release verification.

The importer integration binaries run with one test thread in CI: PostgreSQL's importer advisory lock is database-scoped, so isolated fixture schemas must not run independent imports concurrently. This changes only test scheduling; the production lock, runtime limits and no-retry behavior remain unchanged.

## Schema write-path impact and separate133 scope

Migration131 creates `session_generated_titles`. The current product observation writer called by both exact and unlinked CPA import enqueues an initial title when no explicit session name is present. This is a real new write dependency, even though importer-owned tables and the prefix fingerprint format are unchanged.

Migration132 creates `session_response_summaries`. Current product cluster merges called during observation reconciliation move response summaries and title jobs within the same credential scope using `merge_session_reading_in_transaction`. The importer does not synthesize summaries or run title/response workers. The new precondition probes both tables and their columns before planning or apply; schema version metadata alone is insufficient.

PR653 was reviewed separately at `c4183bdd43de51912540d2d285dd141faa22cc04`. Its133 DDL adds `proxy_operational_terminals` without altering importer-owned tables or the prefix representation. The CPA adapter calls the synchronous `record_conversation_observation_in_transaction`; that method and its session reclassification helper are unchanged by the reviewed PR. The new operational receipt joins belong to the asynchronous projection event path and request/statistics reads, not this synchronous import write path. Thus the reviewed133 change introduces no direct CPA write-schema conversion, while product request views and operational/financial readback semantics do change. The exact schema gate still rejects133. A separate tools change must pin the final merged product revision and lock, refresh the closure, rerun exact/unlinked/CAS/replay/financial and operational-receipt readback regressions, and seal a133 artifact. This scope allocates no product migration number.

Offline digest preparation uses source SQLite only and has no PostgreSQL target-schema requirement. The runtime schema gate applies to target import, including dry-run, and does not block the recovery owner's digest continuation. Source format, digest checkpoints, finance invariants and metadata standards stay unchanged.

No local build/test/install, source-volume read, import, PG write, storage placement change or production rollout is part of implementation. Newton/native01a16593 retains exclusive ownership of the work volume, digest continuation and operational acceptance; this source scope does not touch that work or recovery metadata.
