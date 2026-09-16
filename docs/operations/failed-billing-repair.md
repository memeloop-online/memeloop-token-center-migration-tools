# Failed-request billing audit and zero-cost repair

`ops/reconcile-failed-billing.ts` is a read-only PostgreSQL audit. It must be
run with an explicit local time zone and a half-open local interval; it never
assumes that a displayed browser time is UTC. The query converts that interval
to epoch milliseconds inside PostgreSQL, so daylight-saving transitions are
resolved by the target database's time-zone data.

Required inputs are supplied through the environment, not command-line
arguments or committed files:

```text
FAILED_BILLING_FROM_LOCAL=2026-09-16 11:00:00
FAILED_BILLING_TO_LOCAL=2026-09-16 13:00:00
FAILED_BILLING_TIME_ZONE=Asia/Shanghai
FAILED_BILLING_PGHOST=...
FAILED_BILLING_PGPORT=5432
FAILED_BILLING_PGUSER=...
FAILED_BILLING_PGDATABASE=...
FAILED_BILLING_PGPASSFILE=/protected/path/pgpass
FAILED_BILLING_TENANT_EXTERNAL_ID=...       # optional; empty means all tenants
```

The receipt separates three decisions:

- A terminal non-success request (`499`, `502`, `503`, `504`, or any other
  non-2xx/3xx status) defaults to cost `0` and `not_observed`.
- `provider_reported` and `provider_estimated` values are preserved. A status
  code alone is never evidence of supplier usage.
- Historical `NULL`/blank `usage_basis`, response-archive-bound requests, and
  any reservation, ledger, feed, or fact mismatch are manual-review data. They
  are not auto-selected by a broad status/error predicate.

The safe candidate set is deliberately narrower. Every candidate must be a
terminal text request with `usage_basis=contract_ceiling`, positive old cost,
an unavailable response archive (`gap` and no bound response locator), a
settled reservation whose `actual_micros` equals the old request cost, one
matching usage ledger entry, one matching settlement-feed row, and a matching
`request_stats_facts` row. The receipt records the old values, all these
invariants, and the proposed `(cost_micros=0, usage_basis=not_observed)` state.

The repair plan is intentionally not a SQL `UPDATE`. After human approval of
the receipt digest and each evidence set, `ops/apply-failed-billing-rebates.ts`
can apply a forward-only rebate through the product's settlement-adjustment
endpoint. It is dry-run by default; `--apply` requires the expected row and
micros totals, an exact approved plan SHA-256, an HTTPS API URL, an explicit
`FAILED_BILLING_ALLOW_WRITE=I_UNDERSTAND_SETTLEMENT_ADJUSTMENT_API` opt-in, and
a service token supplied only through the environment. It uses the emitted
settlement ID, request ID, and idempotency key, then stops on the first API,
ledger/reservation/fact/feed, or aggregate mismatch. The endpoint keeps the
immutable gross feed, reservation, and original ledger entry as the
rollback/audit baseline while returning the attributed credit through the
supported entitlement/account path. Replaying the same idempotency key is
safe; changing its payload must be rejected.

For an approved all-history plan, stage the audit receipt outside this public
repository with mode `0600`, then use an invocation equivalent to:

```text
FAILED_BILLING_PLAN_FILE=/protected-evidence/failed-billing-all-history.json
FAILED_BILLING_EXPECTED_ROWS=1590
FAILED_BILLING_EXPECTED_MICROS=28868679418
FAILED_BILLING_APPROVED_PLAN_SHA256=<reviewed-digest>
FAILED_BILLING_API_BASE_URL=https://token-operator.k3s.onetwo.website
FAILED_BILLING_SERVICE_TOKEN=<in-memory-secret>
FAILED_BILLING_PGHOST=...
FAILED_BILLING_PGPORT=5432
FAILED_BILLING_PGUSER=...
FAILED_BILLING_PGDATABASE=...
FAILED_BILLING_PGPASSFILE=/protected-evidence/pgpass
FAILED_BILLING_ALLOW_WRITE=I_UNDERSTAND_SETTLEMENT_ADJUSTMENT_API \
  node ./commands/apply-failed-billing-rebates.mjs --apply
```

The real receipt, token, request IDs, and batch receipts must remain outside
this repository and any public CI log.

Before any `--apply` write, the runner performs a read-only, paginated
`settlement-correction-previews` sweep for each candidate account. It uses
inclusive millisecond windows no wider than 93 days, follows the returned
`after_created_at`/`after_request_id` cursor, and requires the exact plan
selection: terminal failed, `contract_ceiling`, response archive `gap`, no
response, `ready_for_evidence`, and a matched settlement feed. The preview
must reproduce the immutable 1590-row / 28868679418-micros safe set and the
five bound rows are reported but excluded. A `--preflight` invocation can run
the same API preview when both API environment variables are supplied; the
preview is read-only and a non-200 response stops the operation before any
write.

`statistics_sources` compares request facts, the settlement feed, daily
aggregates, and hourly request buckets. Day/hour rows are reported as
overlapping buckets; a correction implementation must rebuild or compensate
every affected bucket rather than subtracting an arbitrary local-time slice.
Keep the emitted receipt outside this public repository because it can contain
production request IDs and amounts.

The 2026-09-17 00:00 investigation also illustrates why the explicit time
zone matters: the `US$6.83` value belongs to UTC hour bucket `497103`
(`2026-09-16 15:00–16:00 UTC`, Beijing 23:00–00:00), while the real Beijing
00:00–01:00 bucket is `497104`. The UI label was shifted by one hour; the
underlying hourly aggregate is not a low-value billing loss. The exact
supplier-evidenced failed rows in that bucket remain preserved, while the
ordinary failed rows are zero-cost.

Run only the reviewed release bundle in the approved migration environment:

```text
node ./commands/reconcile-failed-billing.mjs --dry-run
```

There is no `--apply` mode. Production correction requires a separately
approved product/API operation after the dry-run receipt has been reviewed.
