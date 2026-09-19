/* FRA_VERIFY_READ_ONLY_V1
 * Verify append-only refund evidence and the derived daily correction view.
 */
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '30s';

WITH selected_tenant AS MATERIALIZED (
  SELECT id FROM tenants WHERE external_id = :'tenant_external_id'
), items AS MATERIALIZED (
  SELECT item.*
    FROM failed_request_cost_adjustment_items item
   WHERE item.tenant_id = (SELECT id FROM selected_tenant)
), ledger_evidence AS MATERIALIZED (
  SELECT item.request_id,
         original.id AS original_ledger_id,
         original.kind AS original_kind,
         original.amount_micros AS original_amount_micros,
         original.account_id AS original_account_id,
         original.key_id AS original_key_id,
         original.currency AS original_currency,
         refund.id AS refund_ledger_id,
         refund.kind AS refund_kind,
         refund.amount_micros AS refund_amount_micros,
         refund.account_id AS refund_account_id,
         refund.key_id AS refund_key_id,
         refund.currency AS refund_currency,
         refund.reference_entry_id AS refund_reference_entry_id
    FROM items item
    LEFT JOIN ledger_entries original ON original.id = item.usage_ledger_id
    LEFT JOIN ledger_entries refund ON refund.id = item.refund_ledger_id
), expected_daily AS MATERIALIZED (
  SELECT tenant_id, key_id, usage_ledger_created_at / 86400000 AS day_bucket,
         currency, status_code, count(*) AS adjustment_count,
         sum(refund_micros) AS refund_micros
    FROM items
   GROUP BY tenant_id, key_id, usage_ledger_created_at / 86400000, currency, status_code
), daily_mismatches AS MATERIALIZED (
  SELECT expected.tenant_id, expected.key_id, expected.day_bucket,
         expected.currency, expected.status_code
    FROM expected_daily expected
    LEFT JOIN failed_request_cost_adjustment_daily actual
      ON actual.tenant_id = expected.tenant_id AND actual.key_id = expected.key_id
     AND actual.day_bucket = expected.day_bucket AND actual.currency = expected.currency
     AND actual.status_code = expected.status_code
   WHERE actual.adjustment_count <> expected.adjustment_count
      OR actual.refund_micros <> expected.refund_micros
      OR actual.tenant_id IS NULL
  UNION ALL
  SELECT actual.tenant_id, actual.key_id, actual.day_bucket,
         actual.currency, actual.status_code
    FROM failed_request_cost_adjustment_daily actual
   WHERE actual.tenant_id = (SELECT id FROM selected_tenant)
     AND NOT EXISTS (
       SELECT 1 FROM expected_daily expected
        WHERE expected.tenant_id = actual.tenant_id AND expected.key_id = actual.key_id
          AND expected.day_bucket = actual.day_bucket AND expected.currency = actual.currency
          AND expected.status_code = actual.status_code
     )
), measured AS MATERIALIZED (
  SELECT
    (SELECT count(*) FROM items) AS item_count,
    (SELECT COALESCE(sum(refund_micros), 0) FROM items) AS planned_refund_micros,
    (SELECT count(*) FROM ledger_evidence
      WHERE original_ledger_id IS NULL OR original_kind IS DISTINCT FROM 'usage'
         OR original_amount_micros IS DISTINCT FROM -refund_amount_micros
         OR original_account_id IS DISTINCT FROM refund_account_id
         OR original_key_id IS DISTINCT FROM refund_key_id
         OR original_currency IS DISTINCT FROM refund_currency OR refund_ledger_id IS NULL
         OR refund_kind IS DISTINCT FROM 'failed_request_refund'
         OR refund_reference_entry_id IS DISTINCT FROM original_ledger_id) AS invalid_ledger_pairs,
    (SELECT count(*) FROM daily_mismatches) AS derived_daily_mismatches,
    (SELECT count(*) FROM failed_request_cost_adjustment_plans p
      JOIN selected_tenant t ON t.id = p.tenant_id) AS plan_count
)
SELECT json_build_object(
  'outcome', CASE WHEN (SELECT count(*) FROM selected_tenant) <> 1 THEN 'blocked'
                  WHEN (SELECT invalid_ledger_pairs FROM measured) <> 0 THEN 'blocked'
                  WHEN (SELECT derived_daily_mismatches FROM measured) <> 0 THEN 'blocked'
                  ELSE 'pass' END,
  'aggregate_counts', json_build_object(
    'plans', (SELECT plan_count::text FROM measured),
    'items', (SELECT item_count::text FROM measured),
    'refund_micros', (SELECT planned_refund_micros::text FROM measured),
    'invalid_ledger_pairs', (SELECT invalid_ledger_pairs::text FROM measured),
    'derived_daily_mismatches', (SELECT derived_daily_mismatches::text FROM measured)
  )
);
ROLLBACK;
