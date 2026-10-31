# Separate product-source proposal — not an execution path for59b6

Owner/source: `memeloop-online/memeloop-token-center`, principally
`src/db/mod.rs`, `src/main.rs`, and `src/db/migrations/mod.rs`, with a dedicated
PostgreSQL online143 module and integration tests. This document proposes work;
it does not implement, publish or authorize an alternate migrator.

## Migration-job timeout handling

Exact59b6's migration connection `after_connect` unconditionally writes60000ms
lock and900000ms statement limits. Merely adding lower URL options does not
protect the job. The separate product change must honor explicitly configured
migration-job limits on the actual backend (including PostgreSQL17 transaction
timeout), test them with `SHOW` after pool initialization, and prove rollback
with a real held writer. Leave `ConnectionProfile::Serve`, customer request
configuration, admission, forwarding and in-flight request lifetimes unchanged.
Do not use `ALTER SYSTEM`, role/database defaults or a server-wide cancellation
policy. Preserve existing defaults when no explicit job override is provided
unless a separate reviewed compatibility decision changes them.

## Supported online143 handling if measured blocking is unacceptable

Four concurrent ready indexes remove index-building time, not the ALTER/check
scans or their transaction-long AccessExclusive locks. A product-owned online
implementation needs separately committed, resumable phases:

1. Check exact baseline/intermediate catalog semantics under coordinated
   partition/migration ownership. Reject unknown definitions, invalid indexes,
   unexpected old receipts and ambiguous intermediate state. Never infer success
   from an index name or create a fake applied-version receipt.
2. Add nullable `response_archive_spools.body_blake3` without an inline validating
   CHECK, then add its exact original predicate `NOT VALID` in a short, bounded
   metadata transaction.
3. For each table, atomically replace each affected old CHECK with its exact143
   predicate as `NOT VALID`. DROP and replacement ADD must commit together:
   never expose a constraint-free interval. New writes are checked immediately.
   Commit each table's metadata change before scanning any heap.
4. `VALIDATE CONSTRAINT` outside the final upgrade transaction, using the
   PostgreSQL validation lock that permits ordinary writers. Retain strict
   migration-job bounds/retry and fail on invalid rows; do not disable checks,
   rewrite rows or change customer error/deadline policy. PostgreSQL17 documents
   this lock and NOT VALID behavior in
   [ALTER TABLE](https://www.postgresql.org/docs/17/sql-altertable.html#SQL-ALTERTABLE-DESC-VALIDATE-CONSTRAINT).
5. Prepare/verify the four exact143 indexes with CIC. Preserve failed-CIC
   inventories and clean up only proven owned invalid objects, individually.
6. The new supported runner must verify the complete final143 catalog and all
   validation bits before its **normal source-owned** ledger insertion with the
   original143 name. Its resumable state machine must not mark partial work
   applied. Existing143 receipts and immutable SQL bytes remain untouched.
   Then run unchanged144/146 and normal partition maintenance/COMMIT with all
   locks and write delays measured.

The final CHECK definitions, nullable column and indexes must equal original143;
the execution strategy intentionally differs. This cannot be retrofitted into
an unchanged59b6 transaction by operational SQL plus a hand-inserted ledger row.
It requires product review, PostgreSQL17.5 concurrency/rollback tests, and a new
official artifact through existing release machinery before use.

Crash/retry tests should cover the few actual phase boundaries, invalid catalog
state and real writer contention—not a combinatorial matrix. A partial online
preparation should remain additive/compatible where possible, preserve validated
old protections until their atomic replacement, and be resumable rather than
“rolled back” by deleting history. Parent decides compatibility and production
authority; the current qualification grants neither.
