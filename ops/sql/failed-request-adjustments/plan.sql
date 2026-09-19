/* FRA_PLAN_READ_ONLY_V1
 * This query intentionally selects accounting coordinates only. It never
 * selects request/response objects, credentials, provider configuration, or
 * archive payloads.
 */
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '30s';

WITH selected_tenant AS MATERIALIZED (
  SELECT id
    FROM tenants
   WHERE external_id = :'tenant_external_id'
), scoped_requests AS MATERIALIZED (
  SELECT r.id, r.created_at, r.tenant_id, r.key_id, r.reservation_id,
         r.status_code, r.currency, r.cost_micros
    FROM request_records r
   WHERE r.tenant_id = (SELECT id FROM selected_tenant)
     AND r.created_at >= :'from_ms'::bigint
     AND r.created_at < :'to_ms'::bigint
     AND r.completed_at IS NOT NULL
     AND r.status_code = ANY(string_to_array(:'status_codes', ',')::bigint[])
), facts AS MATERIALIZED (
  SELECT r.id AS request_id, r.tenant_id, count(*) AS fact_count,
         min(f.cost_micros) AS fact_cost_micros
    FROM scoped_requests r
    JOIN request_stats_facts f ON f.request_id = r.id AND f.tenant_id = r.tenant_id
   GROUP BY r.id, r.tenant_id
), reservations AS MATERIALIZED (
  SELECT r.id AS request_id, count(*) AS reservation_count,
         min(u.account_id) AS reservation_account_id, min(u.key_id) AS reservation_key_id,
         min(u.actual_micros) AS reservation_actual_micros, min(u.status) AS reservation_status
    FROM scoped_requests r
    JOIN usage_reservations u ON u.id = r.reservation_id
   GROUP BY r.id
), usage_ledgers AS MATERIALIZED (
  SELECT r.id AS request_id, count(*) AS ledger_count, min(l.id) AS usage_ledger_id,
         min(l.created_at) AS usage_ledger_created_at,
         min(l.account_id) AS usage_ledger_account_id, min(l.key_id) AS usage_ledger_key_id,
         min(l.currency) AS usage_ledger_currency, min(l.amount_micros) AS usage_ledger_amount_micros
    FROM scoped_requests r
    JOIN ledger_entries l ON l.source = r.reservation_id AND l.kind = 'usage'
   GROUP BY r.id
), prior_refunds AS MATERIALIZED (
  SELECT usage.request_id, count(refund.id) AS refund_count
    FROM usage_ledgers usage
    LEFT JOIN ledger_entries refund ON refund.kind = 'failed_request_refund'
      AND refund.reference_entry_id = usage.usage_ledger_id
   GROUP BY usage.request_id
), entitlement_allocations AS MATERIALIZED (
  SELECT usage.request_id, COALESCE(sum(a.amount_micros), 0) AS entitlement_allocated_micros
    FROM usage_ledgers usage
    LEFT JOIN entitlement_usage_allocations a ON a.usage_ledger_entry_id = usage.usage_ledger_id
   GROUP BY usage.request_id
), observed AS MATERIALIZED (
  SELECT r.*,
         k.account_id AS expected_account_id,
         k.currency AS key_currency,
         f.fact_count, f.fact_cost_micros,
         u.reservation_count, u.reservation_account_id, u.reservation_key_id,
         u.reservation_actual_micros, u.reservation_status,
         l.ledger_count, l.usage_ledger_id, l.usage_ledger_created_at,
         l.usage_ledger_account_id, l.usage_ledger_key_id,
         l.usage_ledger_currency, l.usage_ledger_amount_micros,
         a.refund_count,
         COALESCE(e.entitlement_allocated_micros, 0) AS entitlement_allocated_micros
    FROM scoped_requests r
    LEFT JOIN key_records k ON k.id = r.key_id AND k.tenant_id = r.tenant_id
    LEFT JOIN facts f ON f.request_id = r.id AND f.tenant_id = r.tenant_id
    LEFT JOIN reservations u ON u.request_id = r.id
    LEFT JOIN usage_ledgers l ON l.request_id = r.id
    LEFT JOIN prior_refunds a ON a.request_id = r.id
    LEFT JOIN entitlement_allocations e ON e.request_id = r.id
), classified AS MATERIALIZED (
  SELECT o.*,
         CASE
           WHEN o.expected_account_id IS NULL THEN 'key_record_missing_or_tenant_mismatch'
           WHEN o.cost_micros <= 0 THEN 'already_zero_cost'
           WHEN o.fact_count IS DISTINCT FROM 1 THEN 'request_stats_fact_count'
           WHEN o.fact_cost_micros IS DISTINCT FROM o.cost_micros THEN 'request_stats_cost_mismatch'
           WHEN o.reservation_count IS DISTINCT FROM 1 THEN 'usage_reservation_count'
           WHEN o.reservation_status IS DISTINCT FROM 'settled' THEN 'usage_reservation_not_settled'
           WHEN o.reservation_account_id IS DISTINCT FROM o.expected_account_id
             OR o.reservation_key_id IS DISTINCT FROM o.key_id
             OR o.reservation_actual_micros IS DISTINCT FROM o.cost_micros THEN 'usage_reservation_mismatch'
           WHEN o.ledger_count IS DISTINCT FROM 1 THEN 'usage_ledger_count'
           WHEN o.usage_ledger_amount_micros IS DISTINCT FROM -o.cost_micros THEN 'usage_ledger_amount_mismatch'
           WHEN o.usage_ledger_account_id IS DISTINCT FROM o.expected_account_id
             OR o.usage_ledger_key_id IS DISTINCT FROM o.key_id THEN 'usage_ledger_identity_mismatch'
           WHEN o.usage_ledger_currency IS DISTINCT FROM o.currency OR o.key_currency IS DISTINCT FROM o.currency THEN 'currency_mismatch'
           WHEN o.refund_count IS DISTINCT FROM 0 THEN 'already_adjusted'
           WHEN o.entitlement_allocated_micros > o.cost_micros THEN 'entitlement_allocation_mismatch'
           ELSE 'eligible'
         END AS classification
    FROM observed o
), blocker_counts AS MATERIALIZED (
  SELECT classification AS reason, count(*)::text AS count
    FROM classified
   WHERE classification <> 'eligible' AND classification <> 'already_zero_cost'
   GROUP BY classification
)
SELECT json_build_object(
  'selected_tenant_count', (SELECT count(*)::text FROM selected_tenant),
  'observed_request_count', (SELECT count(*)::text FROM classified),
  'eligible_candidates', COALESCE((
    SELECT json_agg(json_build_object(
      'request_id', id,
      'request_created_at', created_at::text,
      'tenant_id', tenant_id,
      'key_id', key_id,
      'account_id', expected_account_id,
      'reservation_id', reservation_id,
      'usage_ledger_id', usage_ledger_id,
      'usage_ledger_created_at', usage_ledger_created_at::text,
      'status_code', status_code::text,
      'currency', currency,
      'refund_micros', cost_micros::text
    ) ORDER BY id)
      FROM classified WHERE classification = 'eligible'
  ), '[]'::json),
  'already_zero_cost_count', (SELECT count(*)::text FROM classified WHERE classification = 'already_zero_cost'),
  'blockers', COALESCE((
    SELECT json_agg(json_build_object('reason', reason, 'count', count) ORDER BY reason)
      FROM blocker_counts
  ), '[]'::json)
);
ROLLBACK;
