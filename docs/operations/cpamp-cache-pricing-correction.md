# CPAMP cache and pricing correction

The CPAMP importer requires the post-cache-accounting SQLite schema. It imports
`normalized_total_input_tokens` as the request's inclusive input total,
`normalized_cache_read_tokens` as cache reads, and
`normalized_cache_creation_tokens` as cache writes. It preserves the raw token
buckets, reasoning and TTFT, requested/resolved models, effective service tier,
selected context/service price rule, exact effective rates, and a canonical
pricing-configuration snapshot in `cpamp_import_event_provenance`. Source price
rows are evidence only; the importer never changes Token Center's global model
price book. A missing normalized dimension or required source price stops the
whole run instead of recording zero as an exact value.

Rows written by the older importer have the legacy source digest and cannot be
fixed by ordinary replay. Use the independent v2 correction only with the same
sealed SQLite snapshot, tenant, and import source that produced those links.
First run the read-only plan:

```sh
CPAMP_CORRECTION_MODE=plan node ops/migrate-cpamp.ts
```

The plan groups old/new tokens and cost by UTC day, model, and key. It must show
zero non-USD and zero live candidates. Correction modes deliberately scan the
entire sealed usage history rather than the ordinary overlap window. Preserve its output with the sealed
source digest and target backup. Do not apply if the candidate count, source
digest, tenant/source identity, or expected old/new totals are unexplained.

Apply requires a second explicit fence:

```sh
CPAMP_CORRECTION_MODE=apply \
CPAMP_CORRECTION_CONFIRM=CORRECT_CPAMP_IMPORTED_USAGE \
node ops/migrate-cpamp.ts
```

The apply runs under a serializable transaction, advisory lock, and table locks.
It compare-and-swaps only the exact deterministic request/link/fact shape from
the legacy importer, writes before/after audit rows, advances links to the full
source digest, and rebuilds request, usage-analysis, and session projections for
that tenant. It does not write balances, credit reservations, ledger entries,
or global prices. Any partially changed, non-USD, non-import reservation, missing
fact/locator, or source-drifted row aborts the transaction.

After apply, run the same apply command a second time and then an ordinary
replay. Both must report zero corrected/imported events and leave request/fact
and aggregate totals unchanged. Reconcile the source token buckets and price
rules against `cpamp_import_event_provenance`, and retain
`cpamp_import_correction_audit` plus the checkpoint correction revision as the
rollback/audit boundary. This procedure corrects usage history only; it must
never be used as evidence for, or a mechanism to change, account balances.
