# Final session/archive snapshot and delta reconciliation

`ops/finalize-session-archive-delta.ts` is the final, offline coordinator for
the normal session/archive importer. It never decodes or emits archive JSONL,
credentials, tickets, database values, content locators, request IDs, or response
bodies. It only seals artifact bytes to their existing SHA-256 manifests and
emits aggregate, non-secret receipts.

The command is dry-run by default. A dry run performs no database, object-store,
control-plane, or cluster write. It validates one final source sequence made of:

- an initial sequence-1 offline full collector snapshot;
- one or more contiguous collector deltas with the same source fingerprint,
  output-digest chain, watermark chain, and ingest-fence chain;
- stable snapshot cursor protocol and snapshot schema version 2 throughout; and
- a final delta exported with the source-stability requirement enabled.

Each input JSONL and adjacent `.manifest.json` must be a private regular file.
The coordinator streams artifact bytes solely to calculate SHA-256; it does not
parse their lines. Artifacts from the older projection or snapshot contracts are
not sufficient for the final cut.

## Dry-run receipt

Use one new private receipt path per attempt:

```text
node ops/finalize-session-archive-delta.ts \
  --artifact /private-evidence/session-baseline.jsonl \
  --artifact /private-evidence/session-final-delta.jsonl \
  --receipt /private-evidence/session-final-dry-run-receipt.json
```

The receipt has an artifact-set digest plus planned checkpoint, correlation,
provenance, quarantine, unlinked, and content-locator receipt sections. Target
sections explicitly state `measurement: "not-performed"`; a dry run must never
be represented as imported history.

## Approved apply and idempotency proof

Apply is rejected unless `--apply` and a separate private approval receipt are
provided. The approval is metadata only and must match the artifact-set digest,
migration-window ID, tenant, source labels and expected request-event count:

```json
{"approval_id":"approved-window-01","approved_at":"<OWNER_REVIEWED_UTC_TIMESTAMP>","archive_source":"session-archive-final","artifact_set_sha256":"<SEALED_DIGEST>","cpamp_source":"request-events-final","expected_cpamp_records":"<OWNER_REVIEWED_COUNT>","migration_window_id":"window-01","tenant_external_id":"default","version":1,"workflow":"final-session-archive-delta-v1"}
```

The final operator supplies the normal importer and PostgreSQL credentials only
through the existing approved secret-injection paths. Do not put values in this
repository, this approval, shell history, or command-line arguments. An approved
run uses the existing normal-model importer once for every sealed artifact, then
uses the read-only aggregate audit, replays the same sealed artifacts, and
requires every aggregate to remain byte-identical:

```text
node ops/finalize-session-archive-delta.ts --apply \
  --artifact /private-evidence/session-baseline.jsonl \
  --artifact /private-evidence/session-final-delta.jsonl \
  --receipt /private-evidence/session-final-apply-receipt.json \
  --approval-file /private-evidence/session-final-approval.json \
  --migration-window-id window-01 \
  --tenant-external-id default \
  --archive-source session-archive-final \
  --cpamp-source request-events-final \
  --expected-cpamp-records OWNER_REVIEWED_COUNT \
  --overlap-ms 86400000 \
  --plan-directory /plan
```

The final apply receipt records only aggregate evidence: target checkpoint and
watermark; total/exact/unlinked correlations; exact provenance; unresolved
quarantine; archive-only conversation projections; non-gap and gap locator
counts; and the replay aggregate digest. It fails closed when checkpoint,
correlation, provenance, quarantine, `gap://`, or locator evidence does not
reconcile. A nonzero archive import must include at least one non-gap content
locator; zero is treated as absence of the import, not successful completion.

If an approved import stops partway through, preserve the source artifacts and
do not overwrite the intended receipt. Correct the external fault and rerun the
same artifact chain with a new receipt path. Existing provenance and the required
same-file replay make that recovery idempotent. Do not start blue/green ownership
or delete retained migration/runtime boundaries until this apply receipt and the
separate key, price, and per-key/model/day/cache receipts have been reviewed.
