# Historical migration acceptance boundary

Credential recovery is a bounded cohort operation, not proof of complete
requests, sessions, original request/response archives, billing, OAuth, or grants.
Dynamic inventory, receipts and detailed operational evidence remain in the
protected external audit store under the [extraction boundary](../extraction-boundaries.md).
Do not commit source/target inventory or operational logs to this public repository.

## Required evidence

| Area | Completion evidence |
| --- | --- |
| Requests | Final consistent CPAMP snapshot/delta, digest, cutoff, full identity-link coverage, replay and per-key/model/day/status/cache/cost equality |
| Conversations | Stable-schema-v2 offline baseline and contiguous deltas, complete session projections, exact/unlinked correlation and provenance |
| Raw archives | Payload/manifest digest verification, non-gap/gap locator and object reconciliation, explicit unrecoverable-gap decisions |
| Billing | Exact decimal totals, cache read/write and missing-price checks, duplicate-billing checks and replay |
| OAuth/accounts | Native-only source-to-target mappings, unavailable capabilities, quarantine and reauth decisions, usability evidence |
| Keys/grants | Exact source-to-target identities/generations/states; individual and group grant equivalence, independent of credential-copy availability |

Source auth-file, candidate-account and target-account counts are not equivalent.
Route explicit credential edges exclude group-derived grants. Different snapshot
dates/projections must not be subtracted. Unknown counts are not zero. Successful
service health, SSE, credential copy or a backup TOC check cannot replace final
history reconciliation and restore evidence.

## Executable sequence

1. Collect bounded read-only source capabilities/counts and target aggregates.
   Verify sealed source files, tool release commands/assets and pinned runtime
   digests. Keep real inputs and receipts private.
2. Resolve a consistent isolated clone and compatible collector runtime using
   the [collector-direct runbook](collector-direct-archive-runbook.md).
   Stable cursor/offline-full capability and capacity proof are prerequisites.
   Export-ticket digest preparation may write collector metadata: obtaining a
   ticket is not merely a read-only capability check.
3. Import CPAMP identities first, with complete-history initial overlap, reviewed
   plan and separately approved apply/replay, following the
   [identity prerequisites](../session-archive-import.md).
4. Export a sequence-1 offline full archive baseline and every contiguous delta,
   preserving source fingerprint, private Service, checkpoint, digest/watermark/
   ingest-fence chain. The final delta requires `--require-stable-source` and a
   separately approved source-stability window, not implicit source shutdown.
5. Run `finalize-session-archive-delta` without `--apply` on the sealed chain,
   using a new private receipt path. This is offline byte/manifest verification;
   target measurement remains `not-performed`.
6. After separate approval and pinned external Rust importer availability, use
   the [finalizer](../final-session-archive-reconciliation.md) with approval bound
   to artifact-set digest, window, tenant, sources and freshly verified expected
   CPAMP count. Require import, aggregate audit, same-file replay and identical
   aggregates. Do not use a historical example count as the final expected count.
7. Run [price/cache reconciliation](final-price-cache-reconciliation.md) with a
   read-only target identity and protected pgpass file. Reconcile keys, grants
   and native accounts independently. Classify unavailable capabilities instead
   of deleting source grants to force equality.
8. Review every receipt, unrecoverable gap and restore/rollback proof before any
   old source/database/PVC cleanup. Accepted exceptions need an explicit owner
   decision; absent receipts do not imply completion.

The TypeScript importer wrapper does not itself supply the Rust import engine.
A zero-replica, read-only old collector template likewise does not prove a
compatible final-export runtime. Resolve both prerequisites explicitly without
rewriting the importer opportunistically or making the original source PVC
writable. This document authorizes no import, export, source maintenance, key
rotation, quota reset or cleanup operation.
