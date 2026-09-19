/* FRA_VERIFY_READ_ONLY_V2: immutable evidence and derived-view verification. */
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '60s';

WITH selected_tenant AS MATERIALIZED (
  SELECT id FROM tenants WHERE external_id = :'tenant_external_id'
), plans AS MATERIALIZED (
  SELECT p.* FROM failed_request_cost_adjustment_plans p WHERE p.tenant_id = (SELECT id FROM selected_tenant)
), items AS MATERIALIZED (
  SELECT i.* FROM failed_request_cost_adjustment_items i WHERE i.tenant_id = (SELECT id FROM selected_tenant)
), plan_mismatches AS MATERIALIZED (
  SELECT p.plan_sha256 FROM plans p LEFT JOIN (
    SELECT plan_sha256, count(*) AS candidate_count, COALESCE(sum(refund_micros), 0) AS refund_micros FROM items GROUP BY plan_sha256
  ) i ON i.plan_sha256 = p.plan_sha256
  WHERE p.candidate_count <> COALESCE(i.candidate_count, 0) OR p.refund_micros <> COALESCE(i.refund_micros, 0)
), ledger_mismatches AS MATERIALIZED (
  SELECT i.request_id FROM items i
  LEFT JOIN ledger_entries original ON original.id = i.usage_ledger_id
  LEFT JOIN ledger_entries refund ON refund.id = i.refund_ledger_id
  WHERE original.id IS NULL OR original.kind IS DISTINCT FROM 'usage' OR original.amount_micros IS DISTINCT FROM -i.refund_micros
     OR original.account_id IS DISTINCT FROM i.account_id OR original.key_id IS DISTINCT FROM i.key_id OR original.currency IS DISTINCT FROM i.currency
     OR refund.id IS NULL OR refund.kind IS DISTINCT FROM 'failed_request_refund' OR refund.amount_micros IS DISTINCT FROM i.refund_micros
     OR refund.account_id IS DISTINCT FROM i.account_id OR refund.key_id IS DISTINCT FROM i.key_id OR refund.currency IS DISTINCT FROM i.currency
     OR refund.reference_entry_id IS DISTINCT FROM i.usage_ledger_id
), account_mismatches AS MATERIALIZED (
  SELECT affected.account_id FROM (SELECT DISTINCT account_id FROM items) affected
  LEFT JOIN credit_accounts a ON a.id = affected.account_id
  LEFT JOIN account_usage_state s ON s.account_id = affected.account_id
  WHERE a.id IS NULL OR s.account_id IS NULL
     OR s.settled_lifetime_micros IS DISTINCT FROM COALESCE((SELECT sum(-l.amount_micros) FROM ledger_entries l WHERE l.account_id = affected.account_id AND l.kind = 'usage'), 0)
          - COALESCE((SELECT sum(i.refund_micros) FROM items i WHERE i.account_id = affected.account_id), 0)
     OR a.available_micros + a.reserved_micros IS DISTINCT FROM COALESCE((SELECT sum(l.amount_micros) FROM ledger_entries l WHERE l.account_id = affected.account_id), 0)
), key_state_mismatches AS MATERIALIZED (
  SELECT affected.key_id FROM (SELECT DISTINCT key_id FROM items) affected
  LEFT JOIN key_budget_state s ON s.key_id = affected.key_id
  WHERE s.key_id IS NULL
     OR s.settled_lifetime_micros IS DISTINCT FROM COALESCE((SELECT sum(-l.amount_micros) FROM ledger_entries l WHERE l.key_id = affected.key_id AND l.kind = 'usage'), 0)
          - COALESCE((SELECT sum(i.refund_micros) FROM items i WHERE i.key_id = affected.key_id), 0)
), budget_daily_mismatches AS MATERIALIZED (
  SELECT affected.key_id, affected.day_bucket FROM (SELECT DISTINCT key_id, usage_ledger_created_at / 86400000 AS day_bucket FROM items) affected
  LEFT JOIN key_budget_daily_rollups d ON affected.key_id = d.key_id AND affected.day_bucket = d.day_bucket
  WHERE d.key_id IS NULL
     OR d.settled_micros IS DISTINCT FROM COALESCE((SELECT sum(-l.amount_micros) FROM ledger_entries l WHERE l.key_id = affected.key_id AND l.kind = 'usage' AND l.created_at / 86400000 = affected.day_bucket), 0)
          - COALESCE((SELECT sum(i.refund_micros) FROM items i WHERE i.key_id = affected.key_id AND i.usage_ledger_created_at / 86400000 = affected.day_bucket), 0)
), usage_event_mismatches AS MATERIALIZED (
  SELECT i.refund_ledger_id FROM items i WHERE i.usage_ledger_created_at >= :'now_ms'::bigint - 7 * 86400000
    AND NOT EXISTS (SELECT 1 FROM key_budget_usage_events e WHERE e.usage_entry_id = i.refund_ledger_id AND e.reservation_id = i.reservation_id
      AND e.key_id = i.key_id AND e.account_id = i.account_id AND e.amount_micros = -i.refund_micros AND e.settled_at = i.usage_ledger_created_at)
), entitlement_mismatches AS MATERIALIZED (
  SELECT affected.entitlement_cycle_id FROM (
    SELECT DISTINCT a.entitlement_cycle_id FROM entitlement_usage_allocations a JOIN items i ON i.usage_ledger_id = a.usage_ledger_entry_id
  ) affected LEFT JOIN entitlement_cycles c ON affected.entitlement_cycle_id = c.id
  WHERE c.id IS NULL OR c.consumed_micros IS DISTINCT FROM COALESCE((SELECT sum(a.amount_micros) FROM entitlement_usage_allocations a WHERE a.entitlement_cycle_id = affected.entitlement_cycle_id), 0)
), expected_correction_daily AS MATERIALIZED (
  SELECT tenant_id, key_id, request_created_at / 86400000 AS day_bucket, currency, status_code, count(*) AS adjustment_count, sum(refund_micros) AS refund_micros
  FROM items GROUP BY tenant_id, key_id, request_created_at / 86400000, currency, status_code
), correction_daily_mismatches AS MATERIALIZED (
  SELECT e.tenant_id, e.key_id, e.day_bucket, e.currency, e.status_code FROM expected_correction_daily e
  LEFT JOIN failed_request_cost_adjustment_daily a ON a.tenant_id=e.tenant_id AND a.key_id=e.key_id AND a.day_bucket=e.day_bucket AND a.currency=e.currency AND a.status_code=e.status_code
  WHERE a.adjustment_count IS DISTINCT FROM e.adjustment_count OR a.refund_micros IS DISTINCT FROM e.refund_micros
  UNION ALL
  SELECT a.tenant_id, a.key_id, a.day_bucket, a.currency, a.status_code FROM failed_request_cost_adjustment_daily a
  WHERE a.tenant_id=(SELECT id FROM selected_tenant) AND NOT EXISTS (SELECT 1 FROM expected_correction_daily e WHERE e.tenant_id=a.tenant_id AND e.key_id=a.key_id AND e.day_bucket=a.day_bucket AND e.currency=a.currency AND e.status_code=a.status_code)
), affected_dimensions AS MATERIALIZED (
  SELECT DISTINCT f.tenant_id, f.key_id, f.created_at / 86400000 AS day_bucket, f.created_at / 3600000 AS hour_bucket,
    f.model, f.protocol, f.status_class, f.error_code, f.upstream_account_id, f.model_route_id, f.service_tier, f.currency
  FROM request_stats_facts f JOIN items i ON i.request_id=f.request_id AND i.tenant_id=f.tenant_id
), rollup_mismatches AS MATERIALIZED (
  SELECT d.tenant_id, d.key_id, d.day_bucket, d.model FROM affected_dimensions d
  LEFT JOIN request_daily_aggregates r ON r.tenant_id=d.tenant_id AND r.key_id=d.key_id AND r.day_bucket=d.day_bucket AND r.model=d.model AND r.protocol=d.protocol AND r.status_class=d.status_class AND r.error_code=d.error_code AND r.upstream_account_id=d.upstream_account_id AND r.model_route_id=d.model_route_id AND r.service_tier=d.service_tier AND r.currency=d.currency
  LEFT JOIN usage_analysis_hourly h ON h.tenant_id=d.tenant_id AND h.key_id=d.key_id AND h.hour_bucket=d.hour_bucket AND h.source_kind='request' AND h.model=d.model AND h.protocol=CASE WHEN d.protocol='anthropic' OR d.protocol LIKE 'anthropic-%' THEN 'anthropic' WHEN d.protocol='openai-image' THEN 'openai-image' ELSE 'openai' END AND h.status_class=d.status_class AND h.error_code=d.error_code AND h.upstream_account_id=d.upstream_account_id AND h.model_route_id=d.model_route_id AND h.service_tier=d.service_tier AND h.currency=d.currency
  LEFT JOIN usage_analysis_daily a ON a.tenant_id=d.tenant_id AND a.key_id=d.key_id AND a.day_bucket=d.day_bucket AND a.source_kind='request' AND a.model=d.model AND a.protocol=CASE WHEN d.protocol='anthropic' OR d.protocol LIKE 'anthropic-%' THEN 'anthropic' WHEN d.protocol='openai-image' THEN 'openai-image' ELSE 'openai' END AND a.status_class=d.status_class AND a.error_code=d.error_code AND a.upstream_account_id=d.upstream_account_id AND a.model_route_id=d.model_route_id AND a.service_tier=d.service_tier AND a.currency=d.currency
  WHERE r.cost_micros IS DISTINCT FROM (SELECT sum(f.cost_micros-COALESCE(i.refund_micros,0)) FROM request_stats_facts f LEFT JOIN items i ON i.request_id=f.request_id AND i.tenant_id=f.tenant_id WHERE f.tenant_id=d.tenant_id AND f.key_id=d.key_id AND f.created_at/86400000=d.day_bucket AND f.model=d.model AND f.protocol=d.protocol AND f.status_class=d.status_class AND f.error_code=d.error_code AND f.upstream_account_id=d.upstream_account_id AND f.model_route_id=d.model_route_id AND f.service_tier=d.service_tier AND f.currency=d.currency)
     OR h.cost_micros IS DISTINCT FROM (SELECT sum(f.cost_micros-COALESCE(i.refund_micros,0)) FROM request_stats_facts f LEFT JOIN items i ON i.request_id=f.request_id AND i.tenant_id=f.tenant_id WHERE f.tenant_id=d.tenant_id AND f.key_id=d.key_id AND f.created_at/3600000=d.hour_bucket AND f.model=d.model AND f.protocol=d.protocol AND f.status_class=d.status_class AND f.error_code=d.error_code AND f.upstream_account_id=d.upstream_account_id AND f.model_route_id=d.model_route_id AND f.service_tier=d.service_tier AND f.currency=d.currency)
     OR a.cost_micros IS DISTINCT FROM (SELECT sum(f.cost_micros-COALESCE(i.refund_micros,0)) FROM request_stats_facts f LEFT JOIN items i ON i.request_id=f.request_id AND i.tenant_id=f.tenant_id WHERE f.tenant_id=d.tenant_id AND f.key_id=d.key_id AND f.created_at/86400000=d.day_bucket AND f.model=d.model AND f.protocol=d.protocol AND f.status_class=d.status_class AND f.error_code=d.error_code AND f.upstream_account_id=d.upstream_account_id AND f.model_route_id=d.model_route_id AND f.service_tier=d.service_tier AND f.currency=d.currency)
), measured AS MATERIALIZED (
 SELECT (SELECT count(*) FROM selected_tenant) tenant_count, (SELECT count(*) FROM plans) plan_count, (SELECT count(*) FROM items) item_count, (SELECT COALESCE(sum(refund_micros),0) FROM items) refund_micros,
  (SELECT count(*) FROM plan_mismatches) plan_mismatches, (SELECT count(*) FROM ledger_mismatches) ledger_mismatches, (SELECT count(*) FROM account_mismatches) account_mismatches, (SELECT count(*) FROM key_state_mismatches) key_state_mismatches,
  (SELECT count(*) FROM budget_daily_mismatches) budget_daily_mismatches, (SELECT count(*) FROM usage_event_mismatches) usage_event_mismatches, (SELECT count(*) FROM entitlement_mismatches) entitlement_mismatches, (SELECT count(*) FROM correction_daily_mismatches) correction_daily_mismatches, (SELECT count(*) FROM rollup_mismatches) rollup_mismatches
)
SELECT json_build_object('outcome', CASE WHEN (SELECT tenant_count FROM measured)<>1 OR (SELECT plan_count FROM measured)=0 OR (SELECT item_count FROM measured)=0 THEN 'blocked' WHEN (SELECT plan_mismatches+ledger_mismatches+account_mismatches+key_state_mismatches+budget_daily_mismatches+usage_event_mismatches+entitlement_mismatches+correction_daily_mismatches+rollup_mismatches FROM measured)<>0 THEN 'blocked' ELSE 'pass' END,
 'aggregate_counts', json_build_object('plans',(SELECT plan_count::text FROM measured),'items',(SELECT item_count::text FROM measured),'refund_micros',(SELECT refund_micros::text FROM measured),'plan_mismatches',(SELECT plan_mismatches::text FROM measured),'ledger_mismatches',(SELECT ledger_mismatches::text FROM measured),'account_mismatches',(SELECT account_mismatches::text FROM measured),'key_state_mismatches',(SELECT key_state_mismatches::text FROM measured),'budget_daily_mismatches',(SELECT budget_daily_mismatches::text FROM measured),'usage_event_mismatches',(SELECT usage_event_mismatches::text FROM measured),'entitlement_mismatches',(SELECT entitlement_mismatches::text FROM measured),'correction_daily_mismatches',(SELECT correction_daily_mismatches::text FROM measured),'rollup_mismatches',(SELECT rollup_mismatches::text FROM measured)));
ROLLBACK;
