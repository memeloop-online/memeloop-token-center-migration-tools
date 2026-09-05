# CPA to Token Center cutover

This runbook keeps CPA available until the new gateway and its imported history
have been validated. It assumes a full CPAMP and session-archive baseline was
imported after recording a trusted UTC fence immediately before that baseline
started. A 2026-08-23 override permits a temporary, reversible CPA/API2 trial,
but no command below authorizes API3 mutation or a final source write barrier.
API3 remains unchanged until the user explicitly declares a production window
open; only that later approved barrier may change source availability.

## Preconditions

- Production PostgreSQL and S3 satisfy the HA and backup gates in the other
  operations documents.
- A recent restore drill succeeded with the exact application image digest.
- Argo CD is synced and healthy, the migration hook succeeded, all expected pods
  are Ready, and there are no database pool acquisition errors.
- Dashboards and alerts cover gateway errors/latency, database pool, archive
  gaps, generation queue and import lag.
- The old CPA Deployment and PVC remain unchanged and recoverable.
- Existing CPA credentials resolve to stable Token Center identities with the
  expected historical request counts and policy.
- The collector's supported session-index repair/backfill completed before the
  baseline. On a consistent source SQLite snapshot, this returns zero:

  ```sql
  SELECT COUNT(*)
    FROM records r
    LEFT JOIN session_indexed_requests i ON i.request_id = r.request_id
   WHERE r.session_id = ''
      OR i.request_id IS NULL
      OR i.session_id <> r.session_id;

  WITH indexed AS (
    SELECT i.session_id,
           COUNT(*) AS requests,
           MIN(r.started_at) AS first_at,
           MAX(r.completed_at) AS last_at
      FROM session_indexed_requests i
      JOIN records r ON r.request_id = i.request_id
     GROUP BY i.session_id
  ), invalid AS (
    SELECT i.session_id
      FROM indexed i
      LEFT JOIN session_summaries s ON s.session_id = i.session_id
     WHERE s.session_id IS NULL
        OR s.requests <> i.requests
        OR s.first_at <> i.first_at
        OR s.last_at <> i.last_at
    UNION ALL
    SELECT s.session_id
      FROM session_summaries s
      LEFT JOIN indexed i ON i.session_id = s.session_id
     WHERE i.session_id IS NULL
  )
  SELECT COUNT(*) FROM invalid;
  ```

- No identity repair, payload rewrite or session-index rebuild will run between
  the baseline fence and cutover. The delta protocol assumes archived records
  are insert-only.
- A private evidence directory has capacity for whole-session downloads, the
  de-duplication spool, output JSONL and importer plan. Management tokens are
  projected as mode-`0600` regular files, never passed in argv or environment.
- CPA, API2, PostgreSQL and the export host are time-synchronized; the measured
  clock skew is below the exporter's reviewed future-skew limit.
- The same tenant, `CPAMP_IMPORT_SOURCE` and `SESSION_ARCHIVE_IMPORT_SOURCE` are
  used for every baseline and delta. Changing a source name creates a different
  idempotency namespace and is forbidden during cutover.

## Online catch-up

Repeat this while CPA remains live. With the legacy v0.7.21 source, run it
frequently enough that fewer than 1000 sessions can enter one overlap window.
Larger windows require the reviewed
`session-snapshot-cursor-v1`/snapshot-bound export contract documented in
`docs/session-archive-import.md`; no client-side time split can replace its
upper-fence guarantee. In either mode, choose an overlap longer than the maximum
observed collector/CPAMP queue delay.

1. Take an approved consistent CPAMP SQLite snapshot and run
   `node ops/migrate-cpamp.ts`. The CPAMP importer must complete before the matching
   archive delta so key identities and request links exist first.
   The source `failed` bit is authoritative: a failed row keeps an actual
   4xx/5xx status, while a missing, zero, 1xx, 2xx, 3xx or out-of-range failure
   code is normalized to `502`/`upstream_error`. It must never enter target
   facts or aggregates as a success merely because the legacy collector stored
   an HTTP-success code next to a failed outcome.
2. Acquire an archive delta through API2. The first post-baseline invocation uses
   the recorded fence; every later invocation omits `--since` and uses a new
   output filename:

   ```sh
   node ops/export-cpa-session-archive-delta.ts \
     --base-url https://REPLACE_API2_ORIGIN \
     --token-file /run/secrets/cpa-management-token \
     --checkpoint /private-evidence/archive-source-checkpoint.json \
     --output /private-evidence/archive-delta-000001.jsonl \
     --since 2026-08-16T00:00:00Z \
     --overlap-seconds 86400
   ```

   The exporter fails closed if either legacy projection changes, a
   snapshot-cursor page has a duplicate/gap/order/digest error, a
   snapshot-bound ticket or export disagrees with its summary count/digest, or a
   saturated legacy boundary cannot negotiate the stable protocol. A stable
   export re-enumerates
   the same opaque snapshot, so concurrent records beyond its upper fence are
   deferred to the next run and selected by the persisted ingest fence even when
   their provider timestamp predates the overlap. `--require-stable-source`
   performs a final stats read after snapshot replay, but remains a verification
   of an external write barrier rather than a replacement for one.
   Retry genuine source drift with a new filename. Use `--resume` with the same
   filename only when a durable manifest/pending output exists and its checkpoint
   transition was interrupted.
3. Independently verify the output SHA-256 against the adjacent manifest, retain
   both files read-only, and record the manifest sequence, projection protocol,
   source/snapshot request counts, lower bound, watermarks and selected-session
   count. For a stable projection, also record the non-secret prior/current
   ingest fences and retain only the opaque snapshot's digest; do not copy the
   snapshot capability, payloads, session ids or tickets into operator logs.
4. Mount the JSONL read-only and run `node ops/import-cpa-session-archive.ts` in this
   order: dry run (`SESSION_ARCHIVE_APPLY=false`), apply
   (`SESSION_ARCHIVE_APPLY=true`), then the exact same apply once more. The
   replay must report `imported: 0`; `replayed` may be non-zero because the
   overlap is deliberate. Set `SESSION_ARCHIVE_OVERLAP_MS` to at least the
   manifest's `overlap_seconds * 1000` for all three invocations.
5. Record CPAMP and archive importer JSON summaries plus their target checkpoint
   rows separately. A nonzero CPAMP checkpoint proves only usage/request
   statistics migration; it does not prove that request/response bodies entered
   object storage. Before any traffic shift, run
   `node ops/audit-cpa-migration.ts` with `EXPECTED_CPAMP_EVENTS` from the
   consistent CPAMP snapshot and `EXPECTED_ARCHIVE_RECORDS` from the verified
   API2 manifest. The command must pass and report its archive checkpoint,
   exact/unlinked correlations, unresolved quarantine, watermark, correlated
   conversation clusters/observations/edges, and CPAMP link counts. A zero
   archive checkpoint or remaining `gap://` baseline is incomplete migration.
   If the target correlation count lags API2's indexed-record count, first
   widen the overlap (up to the exporter limit) or fall back to a new consistent
   full export; never advance a checkpoint by hand.

## Final delta

1. Complete one online catch-up and record its source manifest and target counts.
2. Establish the approved CPA request write barrier, drain in-flight requests and
   queued archive/CPAMP events, then prove request, CPAMP event and archive index
   counts remain stable. Merely copying a live SQLite main file without its WAL
   is not a barrier or a consistent snapshot.
3. Take the approved final CPA, CPAMP and archive SQLite backups. Re-run the source
   session-index invariant from Preconditions on that snapshot. If it is nonzero,
   abort; API2 deltas cannot see the missing rows.
4. Run the final CPAMP import, followed by the final archive export with a new
   output name and `--require-stable-source`, then archive dry-run/apply/replay.
   The stable-source flag supplements the operational barrier; it does not
   replace it.
5. Without lifting the barrier, acquire one more verification delta with
   `--require-stable-source` and a new filename. Apply and replay it. Both applies
   must report `imported: 0`, and its `source_records_before` must equal
   `source_records_after` and the previous final manifest count.
6. Reconcile source and target. With the production tenant/source supplied as
   safe `psql` variables, capture this result:

   ```sql
   WITH selected_tenant AS (
     SELECT id FROM tenants WHERE external_id = :'tenant_external_id'
   )
   SELECT
     COUNT(*) AS correlated,
     COUNT(*) FILTER (WHERE disposition = 'exact') AS exact,
     COUNT(*) FILTER (WHERE disposition = 'unlinked') AS unlinked,
     COUNT(DISTINCT external_request_id) AS distinct_source_requests
   FROM session_archive_correlations
   WHERE tenant_id = (SELECT id FROM selected_tenant)
     AND source = :'archive_source';

   SELECT COUNT(*) AS exact_provenance
   FROM session_archive_import_records
   WHERE tenant_id = (SELECT id FROM tenants WHERE external_id = :'tenant_external_id')
     AND source = :'archive_source';

   SELECT COUNT(*) AS unlinked_projection
   FROM session_archive_unlinked_requests
   WHERE tenant_id = (SELECT id FROM tenants WHERE external_id = :'tenant_external_id')
     AND source = :'archive_source';

   SELECT watermark_ms, watermark_request_id, imported_records
   FROM session_archive_import_checkpoints
   WHERE tenant_id = (SELECT id FROM tenants WHERE external_id = :'tenant_external_id')
     AND source = :'archive_source';
   ```

   `correlated`, `distinct_source_requests` and checkpoint `imported_records` must
   equal the final manifest's `source_records_after`. `exact_provenance` must
   equal `exact`; `unlinked_projection` must equal `unlinked`. The checkpoint
   `watermark_ms` is completed-at based and must cover the manifest's final
   `watermark_completed_at`. Any difference is an abort, including a source count
   increase whose timestamp fell outside the overlap.
7. Sample exact and unlinked rows across old/new timestamps, success/errors and
   large bodies. Verify their stored request/response object digests by reading
   the target S3 objects through the importer's restricted credentials. Confirm
   ordinary request statistics and billing did not increase for unlinked archive
   projections.
8. Confirm every expected legacy credential still resolves to exactly one stable
   key identity with unchanged permissions, balance/history and self-service
   visibility.

Attach unchanged client credentials with the strict dry-run/apply/replay
procedure in [Unchanged CPA credential attachment](legacy-cpa-credentials.md).
Plaintext credentials must remain stdin/Secret/API-stream inputs, and its
count-only one-to-one preflight is a cutover gate.

The archive and CPAMP importers use a shared PostgreSQL advisory lock; the archive
import also holds a tenant/source lock. Treat lock acquisition failure as an
abort. Do not bypass the lock or run another importer build that lacks it.

## Traffic shift

1. Send synthetic OpenAI, Anthropic, image and asynchronous generation requests
   through a canary credential and verify permission, rate limit, accounting,
   archive and self-service views.
2. Shift a small client cohort to Token Center. Compare upstream response errors,
   latency and accounting with CPA.
3. Increase traffic in bounded steps. Keep CPA deployed but do not dual-submit a
   billable request unless the client has an explicit idempotency contract.
4. After the observation window, switch the remaining clients. Keep the write
   barrier and final import evidence.

## Rollback

Rollback routes clients to CPA; it must not reverse database migrations or delete
Token Center records. Record the Token Center traffic interval so any later
reconciliation can distinguish requests that never reached CPA. Preserve both
data stores and archive buckets read-only as needed for investigation.

Abort and roll back when any of these occurs:

- credential identity, permissions, balances or historical counts disagree;
- sustained error/latency thresholds are exceeded;
- database pool acquisition errors, archive gaps or generation queue age grow;
- the final import cannot establish a fixed watermark;
- source/target totals, exact/unlinked provenance or object samples disagree;
- API2 reaches the session-list completeness boundary or the final source index
  invariant is nonzero;
- PostgreSQL, object storage or proxy loses redundancy.
