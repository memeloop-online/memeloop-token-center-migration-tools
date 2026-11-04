# Schema152 CPA importer qualification

This continues PR52 against approved release candidate `00f4792483db1f00e2208872d51b7d734094f9be`; it does not claim deployment. Static comparison with production source `4c539fea` finds no changes under `migrations/` or `src/db/migrations/`; both inventories end at152.

The exact target inventory contains151 rows: versions1..113 and115..152, including the separate142 receipt `plaintext state instead of sealed envelopes`. Migration145 is now present as `request history export queue`; the old146 qualification excluded it. Every version and name must match. Missing, renamed, old146, extra153 and conflicting142 receipts fail closed without DDL or metadata writes.

The Cargo.lock SHA256 is `7a4fb6bcc072558a4eb20f86ebd0c79a2593135f02dde6669628aeb73216f3a8`. The existing source closure is tracked in `ops/runtime-patches/schema152-files.json`. Original SQLite/PostgreSQL real-DDL fixtures are updated for inventory and relation/column drift; full-body, tool-call/result, image/audio byte readback, title, financial unknown, retirement and replay fixtures remain.

Migration145 adds request-history state/backfill and a view over archive/native/event sources. Migration147 adds explicit title provenance, name synchronization and session/thread relationships. Readonly admission checks include those fields and relations. Product title behavior preserves explicit names; importer commit/projection SQL remains unchanged. Migrations148–152 add background-action authority, supplier/probe evidence, network proxies, larger proxy member indices and group-allocation usage. They do not change archive financial authority. All migration identities are required; unrelated business tables are not written by the importer.

The source digest/seal, canonical JSONL formats, fingerprints, session set, sequence and checkpoints remain unchanged. Last proven export checkpoint is153208/531730 records against the existing6071-session seal. No repeated source digest, new backup, actual import or volume retirement is part of this qualification. Prior142/146 artifacts remain historical qualifications only.

No local build/test/install. Use the existing Actions qualification/build path without a separate test cycle. The new head needs its actual Actions result and independent review; prior146 success does not qualify152. Official merged artifacts, fresh target admission after infrastructure recovery, apply/replay and full content/reference/financial/title/finaldelta reconciliation remain operational gates. The existing142 importer stays suspended.
