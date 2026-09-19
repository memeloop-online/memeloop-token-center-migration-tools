# Failed request cost adjustments

`adjust-failed-request-costs` is an operator command for correcting a bounded
set of terminal requests that have durable billing evidence. It uses a
plan/approval/apply sequence:

1. `--plan` reads the selected request range at `REPEATABLE READ` isolation,
   cross-checks `request_records`, `request_stats_facts`, reservations, and the
   original usage ledger entry, then writes a mode-`0600` approval artifact.
2. A human reviews the receipt and the sealed plan. Any ambiguous accounting
   evidence blocks the plan rather than applying a partial refund.
3. `--apply` consumes that exact plan after an explicit confirmation. It
   appends a `failed_request_refund` ledger entry linked to the original usage
   entry and updates balance, key-budget, entitlement, and derived daily
   projections in one transaction.
4. `--rebuild-derived` can rebuild the derived daily correction projection
   from append-only adjustment evidence; it has a separate explicit
   confirmation.
5. `--verify` is read-only and validates plan/item totals, linked ledger pairs,
   account and budget projections, entitlement allocations, and the request
   daily/hourly analytics projections.

The original request, fact, and usage-ledger rows remain immutable. The plan
contains opaque accounting identifiers and belongs in a private operator
directory; its public receipt only includes a tenant hash, scope, counts, and
money totals.

## Create a plan

The default selected statuses are `499,502,503`. A `504` is selected only when
it is explicitly included in `FRA_STATUS_CODES`.

```text
FRA_PGHOST=REPLACE_HOST \
FRA_PGPORT=5432 \
FRA_PGUSER=REPLACE_OPERATOR_USER \
FRA_PGDATABASE=REPLACE_DATABASE \
FRA_PGPASSFILE=/private-evidence/pgpass \
FRA_TENANT_EXTERNAL_ID=REPLACE_TENANT \
FRA_FROM_MS=REPLACE_INCLUSIVE_EPOCH_MS \
FRA_TO_MS=REPLACE_EXCLUSIVE_EPOCH_MS \
FRA_PLAN_OUTPUT=/private-evidence/failed-request-plan.json \
node ops/adjust-failed-request-costs.ts --plan \
  > /private-evidence/failed-request-plan-receipt.json
```

`FRA_FROM_MS` is inclusive and `FRA_TO_MS` is exclusive. To select a reviewed
set of additional terminal statuses, pass a unique comma-separated list such
as `FRA_STATUS_CODES=499,502,503,504`.

The command creates the plan path with exclusive creation and mode `0600`.
Choose a new filename for every planning attempt. A blocked receipt is useful
evidence for resolving data consistency; it must not be approved for apply.

## Apply an approved plan

Use the exact mode-`0600` plan file produced above. The approval reference is a
human-review ticket or change record, retained with the applied plan.

```text
FRA_PGHOST=REPLACE_HOST \
FRA_PGPORT=5432 \
FRA_PGUSER=REPLACE_OPERATOR_USER \
FRA_PGDATABASE=REPLACE_DATABASE \
FRA_PGPASSFILE=/private-evidence/pgpass \
FRA_APPROVED_PLAN=/private-evidence/failed-request-plan.json \
FRA_APPROVAL_REFERENCE=REPLACE_APPROVAL_RECORD \
FRA_APPLY_CONFIRM=APPLY_FAILED_REQUEST_COST_ADJUSTMENTS \
node ops/adjust-failed-request-costs.ts --apply \
  > /private-evidence/failed-request-apply-receipt.json
```

Each original usage ledger entry has one adjustment identity. Replaying the
same approved plan returns its existing receipt without creating another
refund. A changed request, fact, reservation, ledger, or projection prevents a
new apply and rolls back the transaction.

## Verify derived projections

When a derived daily row needs to be recomputed from the immutable adjustment
evidence, run the explicit rebuild before verification:

```text
FRA_PGHOST=REPLACE_HOST \
FRA_PGPORT=5432 \
FRA_PGUSER=REPLACE_OPERATOR_USER \
FRA_PGDATABASE=REPLACE_DATABASE \
FRA_PGPASSFILE=/private-evidence/pgpass \
FRA_TENANT_EXTERNAL_ID=REPLACE_TENANT \
FRA_DERIVED_CONFIRM=REBUILD_FAILED_REQUEST_ADJUSTMENT_DAILY \
node ops/adjust-failed-request-costs.ts --rebuild-derived \
  > /private-evidence/failed-request-adjustment-rebuild.json
```

The rebuild deterministically recalculates the affected request daily/hourly
analytics costs and `failed_request_cost_adjustment_daily` from immutable facts
and append-only adjustment evidence. It does not modify requests, facts, or
ledger evidence.

```text
FRA_PGHOST=REPLACE_HOST \
FRA_PGPORT=5432 \
FRA_PGUSER=REPLACE_READONLY_USER \
FRA_PGDATABASE=REPLACE_DATABASE \
FRA_PGPASSFILE=/private-evidence/pgpass \
FRA_TENANT_EXTERNAL_ID=REPLACE_TENANT \
node ops/adjust-failed-request-costs.ts --verify \
  > /private-evidence/failed-request-adjustment-verification.json
```

Keep the plan, plan receipt, apply receipt, and verification receipt together
with the human approval record.
