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
         e.entitlement_allocated_micros
    FROM scoped_requests r
    JOIN key_records k ON k.id = r.key_id AND k.tenant_id = r.tenant_id
    LEFT JOIN LATERAL (
      SELECT count(*) AS fact_count, min(cost_micros) AS fact_cost_micros
        FROM request_stats_facts f
       WHERE f.request_id = r.id AND f.tenant_id = r.tenant_id
    ) f ON true
    LEFT JOIN LATERAL (
      SELECT count(*) AS reservation_count,
             min(account_id) AS reservation_account_id,
             min(key_id) AS reservation_key_id,
             min(actual_micros) AS reservation_actual_micros,
             min(status) AS reservation_status
        FROM usage_reservations u
       WHERE u.id = r.reservation_id
    ) u ON true
    LEFT JOIN LATERAL (
      SELECT count(*) AS ledger_count,
             min(id) AS usage_ledger_id,
             min(created_at) AS usage_ledger_created_at,
             min(account_id) AS usage_ledger_account_id,
             min(key_id) AS usage_ledger_key_id,
             min(currency) AS usage_ledger_currency,
             min(amount_micros) AS usage_ledger_amount_micros
        FROM ledger_entries l
       WHERE l.source = r.reservation_id AND l.kind = 'usage'
    ) l ON true
    LEFT JOIN LATERAL (
      SELECT count(*) AS refund_count
        FROM ledger_entries refund
       WHERE refund.kind = 'failed_request_refund'
         AND refund.reference_entry_id = l.usage_ledger_id
    ) a ON true
    LEFT JOIN LATERAL (
      SELECT COALESCE(sum(a.amount_micros), 0) AS entitlement_allocated_micros
        FROM entitlement_usage_allocations a
       WHERE a.usage_ledger_entry_id = l.usage_ledger_id
    ) e ON true
), classified AS MATERIALIZED (
  SELECT o.*,
         CASE
           WHEN o.cost_micros <= 0 THEN 'already_zero_cost'
           WHEN o.fact_count <> 1 THEN 'request_stats_fact_count'
           WHEN o.fact_cost_micros <> o.cost_micros THEN 'request_stats_cost_mismatch'
           WHEN o.reservation_count <> 1 THEN 'usage_reservation_count'
           WHEN o.reservation_status <> 'settled' THEN 'usage_reservation_not_settled'
           WHEN o.reservation_account_id <> o.expected_account_id
             OR o.reservation_key_id <> o.key_id
             OR o.reservation_actual_micros <> o.cost_micros THEN 'usage_reservation_mismatch'
           WHEN o.ledger_count <> 1 THEN 'usage_ledger_count'
           WHEN o.usage_ledger_amount_micros <> -o.cost_micros THEN 'usage_ledger_amount_mismatch'
           WHEN o.usage_ledger_account_id <> o.expected_account_id
             OR o.usage_ledger_key_id <> o.key_id THEN 'usage_ledger_identity_mismatch'
           WHEN o.usage_ledger_currency <> o.currency OR o.key_currency <> o.currency THEN 'currency_mismatch'
           WHEN o.refund_count <> 0 THEN 'already_adjusted'
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
  'observed_request_count', (SELECT count(*)::text FROM classified),
  'eligible_candidates', COALESCE((
    SELECT json_agg(json_build_object(
      'request_id', request_id,
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
    ) ORDER BY request_id)
      FROM classified WHERE classification = 'eligible'
  ), '[]'::json),
  'already_zero_cost_count', (SELECT count(*)::text FROM classified WHERE classification = 'already_zero_cost'),
  'blockers', COALESCE((
    SELECT json_agg(json_build_object('reason', reason, 'count', count) ORDER BY reason)
      FROM blocker_counts
  ), '[]'::json)
);
ROLLBACK;
