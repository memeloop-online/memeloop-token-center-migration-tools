/* FRA_REBUILD_DERIVED_V1
 * Rebuild only the derived daily correction projection from append-only
 * adjustment evidence. It never changes request, fact, or ledger evidence.
 */
BEGIN;
SET LOCAL statement_timeout = '60s';

LOCK TABLE failed_request_cost_adjustment_items,
  failed_request_cost_adjustment_daily IN SHARE ROW EXCLUSIVE MODE;

WITH selected_tenant AS MATERIALIZED (
  SELECT id FROM tenants WHERE external_id = :'tenant_external_id'
)
DELETE FROM failed_request_cost_adjustment_daily daily
 WHERE daily.tenant_id = (SELECT id FROM selected_tenant);

INSERT INTO failed_request_cost_adjustment_daily
  (tenant_id, key_id, day_bucket, currency, status_code, adjustment_count,
   refund_micros, rebuilt_at)
SELECT item.tenant_id, item.key_id, item.usage_ledger_created_at / 86400000,
       item.currency, item.status_code, count(*), sum(item.refund_micros),
       :'now_ms'::bigint
  FROM failed_request_cost_adjustment_items item
 WHERE item.tenant_id = (SELECT id FROM tenants WHERE external_id = :'tenant_external_id')
 GROUP BY item.tenant_id, item.key_id, item.usage_ledger_created_at / 86400000,
          item.currency, item.status_code;

SELECT json_build_object(
  'outcome', CASE WHEN EXISTS (SELECT 1 FROM tenants WHERE external_id = :'tenant_external_id')
                    THEN 'rebuilt' ELSE 'blocked' END,
  'daily_rows', (SELECT count(*)::text FROM failed_request_cost_adjustment_daily daily
                   WHERE daily.tenant_id = (SELECT id FROM tenants WHERE external_id = :'tenant_external_id'))
);
COMMIT;
