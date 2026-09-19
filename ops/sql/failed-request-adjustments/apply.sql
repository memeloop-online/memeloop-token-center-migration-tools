/* FRA_APPLY_APPROVED_PLAN_V1
 * The plan is checked again inside this transaction. Immutable request and
 * usage-ledger rows are read-only evidence; the only ledger mutation is an
 * appended, idempotent failed_request_refund row.
 */
BEGIN;
SET LOCAL statement_timeout = '60s';

CREATE TABLE IF NOT EXISTS failed_request_cost_adjustment_plans (
  plan_sha256 TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  scope_json JSONB NOT NULL,
  approval_reference TEXT NOT NULL,
  candidate_count BIGINT NOT NULL,
  refund_micros BIGINT NOT NULL,
  applied_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS failed_request_cost_adjustment_items (
  plan_sha256 TEXT NOT NULL REFERENCES failed_request_cost_adjustment_plans(plan_sha256),
  request_id TEXT NOT NULL,
  request_created_at BIGINT NOT NULL,
  usage_ledger_id TEXT NOT NULL UNIQUE,
  refund_ledger_id TEXT NOT NULL UNIQUE,
  tenant_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  reservation_id TEXT NOT NULL,
  usage_ledger_created_at BIGINT NOT NULL,
  status_code BIGINT NOT NULL,
  currency TEXT NOT NULL,
  refund_micros BIGINT NOT NULL CHECK (refund_micros > 0),
  PRIMARY KEY(plan_sha256, request_id)
);
CREATE TABLE IF NOT EXISTS failed_request_cost_adjustment_daily (
  tenant_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  day_bucket BIGINT NOT NULL,
  currency TEXT NOT NULL,
  status_code BIGINT NOT NULL,
  adjustment_count BIGINT NOT NULL,
  refund_micros BIGINT NOT NULL,
  rebuilt_at BIGINT NOT NULL,
  PRIMARY KEY(tenant_id, key_id, day_bucket, currency, status_code)
);

CREATE TEMP TABLE fra_plan_payload (payload JSONB NOT NULL) ON COMMIT DROP;
-- FRA_PLAN_PAYLOAD_STDIN
CREATE TEMP TABLE fra_scope ON COMMIT DROP AS
SELECT (payload->'scope'->>'tenant_external_id') AS tenant_external_id,
       (payload->'scope') AS scope_json
  FROM fra_plan_payload;
CREATE TEMP TABLE fra_input (
  request_id TEXT PRIMARY KEY,
  request_created_at BIGINT NOT NULL,
  tenant_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  reservation_id TEXT NOT NULL,
  usage_ledger_id TEXT NOT NULL UNIQUE,
  usage_ledger_created_at BIGINT NOT NULL,
  status_code BIGINT NOT NULL,
  currency TEXT NOT NULL,
  refund_micros BIGINT NOT NULL CHECK (refund_micros > 0)
) ON COMMIT DROP;
INSERT INTO fra_input
SELECT request_id, request_created_at, tenant_id, key_id, account_id,
       reservation_id, usage_ledger_id, usage_ledger_created_at, status_code,
       currency, refund_micros
  FROM fra_plan_payload payload,
       jsonb_to_recordset(payload.payload->'candidates') AS input(
    request_id TEXT, request_created_at BIGINT, tenant_id TEXT, key_id TEXT,
    account_id TEXT, reservation_id TEXT, usage_ledger_id TEXT,
    usage_ledger_created_at BIGINT, status_code BIGINT, currency TEXT,
    refund_micros BIGINT
  );

/* Lock only rows that this approved plan can change, before taking the
 * evidence snapshot used by the preconditions below. */
DO $$
BEGIN
  PERFORM 1 FROM request_records request_row
    JOIN fra_input input ON input.request_id = request_row.id
   FOR UPDATE OF request_row;
  PERFORM 1 FROM ledger_entries ledger_row
    JOIN fra_input input ON input.usage_ledger_id = ledger_row.id
   FOR UPDATE OF ledger_row;
  PERFORM 1 FROM credit_accounts account_row
    JOIN fra_input input ON input.account_id = account_row.id
   FOR UPDATE OF account_row;
  PERFORM 1 FROM account_usage_state account_state
    JOIN fra_input input ON input.account_id = account_state.account_id
   FOR UPDATE OF account_state;
  PERFORM 1 FROM key_budget_state key_state
    JOIN fra_input input ON input.key_id = key_state.key_id
   FOR UPDATE OF key_state;
  PERFORM 1 FROM key_budget_daily_rollups daily_rollup
    JOIN fra_input input ON input.key_id = daily_rollup.key_id
      AND input.usage_ledger_created_at / 86400000 = daily_rollup.day_bucket
   FOR UPDATE OF daily_rollup;
  PERFORM 1 FROM entitlement_cycles cycle_row
    JOIN entitlement_usage_allocations allocation ON allocation.entitlement_cycle_id = cycle_row.id
    JOIN fra_input input ON input.usage_ledger_id = allocation.usage_ledger_entry_id
   FOR UPDATE OF cycle_row;
END $$;

CREATE TEMP TABLE fra_new_plan ON COMMIT DROP AS
WITH inserted AS (
  INSERT INTO failed_request_cost_adjustment_plans
    (plan_sha256, tenant_id, scope_json, approval_reference, candidate_count,
     refund_micros, applied_at)
  SELECT :'plan_sha256', t.id, s.scope_json, :'approval_reference',
         count(i.request_id), COALESCE(sum(i.refund_micros), 0), :'now_ms'::bigint
    FROM fra_scope s
    JOIN tenants t ON t.external_id = s.tenant_external_id
    LEFT JOIN fra_input i ON true
   GROUP BY t.id, s.scope_json
  ON CONFLICT (plan_sha256) DO NOTHING
  RETURNING plan_sha256
)
SELECT plan_sha256 FROM inserted;

CREATE TEMP TABLE fra_fence (
  reason TEXT NOT NULL,
  invalid BOOLEAN NOT NULL CHECK (invalid = false)
) ON COMMIT DROP;
INSERT INTO fra_fence(reason, invalid)
SELECT 'tenant_missing', true
 WHERE NOT EXISTS (SELECT 1 FROM fra_scope s JOIN tenants t ON t.external_id = s.tenant_external_id);
INSERT INTO fra_fence(reason, invalid)
SELECT 'existing_plan_conflict', true
 WHERE NOT EXISTS (SELECT 1 FROM fra_new_plan)
   AND NOT EXISTS (
     SELECT 1 FROM failed_request_cost_adjustment_plans p
      JOIN fra_scope s ON true
      JOIN tenants t ON t.external_id = s.tenant_external_id
     WHERE p.plan_sha256 = :'plan_sha256' AND p.tenant_id = t.id
       AND p.scope_json = s.scope_json
   );
INSERT INTO fra_fence(reason, invalid)
SELECT 'empty_candidate_plan', true
 WHERE EXISTS (SELECT 1 FROM fra_new_plan)
   AND NOT EXISTS (SELECT 1 FROM fra_input);

CREATE TEMP TABLE fra_observed ON COMMIT DROP AS
WITH facts AS MATERIALIZED (
  SELECT i.request_id, i.tenant_id, count(*) AS fact_count, min(f.cost_micros) AS fact_cost_micros
    FROM fra_input i JOIN request_stats_facts f ON f.request_id = i.request_id AND f.tenant_id = i.tenant_id
   GROUP BY i.request_id, i.tenant_id
), reservations AS MATERIALIZED (
  SELECT i.request_id, count(*) AS reservation_count, min(u.account_id) AS reservation_account_id,
         min(u.key_id) AS reservation_key_id, min(u.actual_micros) AS reservation_actual_micros,
         min(u.status) AS reservation_status
    FROM fra_input i JOIN usage_reservations u ON u.id = i.reservation_id
   GROUP BY i.request_id
), usage_ledgers AS MATERIALIZED (
  SELECT i.request_id, count(*) AS usage_count, min(l.id) AS usage_ledger_id,
         min(l.created_at) AS usage_ledger_created_at, min(l.account_id) AS usage_ledger_account_id,
         min(l.key_id) AS usage_ledger_key_id, min(l.currency) AS usage_ledger_currency,
         min(l.amount_micros) AS usage_ledger_amount_micros
    FROM fra_input i JOIN ledger_entries l ON l.source = i.reservation_id AND l.kind = 'usage'
   GROUP BY i.request_id
), prior_refunds AS MATERIALIZED (
  SELECT i.request_id, count(refund.id) AS refund_count
    FROM fra_input i LEFT JOIN ledger_entries refund ON refund.kind = 'failed_request_refund'
      AND refund.reference_entry_id = i.usage_ledger_id
   GROUP BY i.request_id
), entitlement_allocations AS MATERIALIZED (
  SELECT i.request_id, COALESCE(sum(a.amount_micros), 0) AS entitlement_allocated_micros
    FROM fra_input i LEFT JOIN entitlement_usage_allocations a ON a.usage_ledger_entry_id = i.usage_ledger_id
   GROUP BY i.request_id
)
SELECT i.*, r.id AS observed_request_id, r.created_at AS observed_request_created_at,
       r.tenant_id AS observed_tenant_id, r.key_id AS observed_key_id,
       r.reservation_id AS observed_reservation_id, r.status_code AS observed_status_code,
       r.currency AS observed_currency, r.cost_micros AS observed_cost_micros,
       k.account_id AS observed_account_id, k.currency AS observed_key_currency,
       f.fact_count, f.fact_cost_micros,
       u.reservation_count, u.reservation_account_id, u.reservation_key_id,
       u.reservation_actual_micros, u.reservation_status,
       l.usage_count, l.usage_ledger_id AS observed_usage_ledger_id,
       l.usage_ledger_created_at AS observed_usage_ledger_created_at,
       l.usage_ledger_account_id, l.usage_ledger_key_id, l.usage_ledger_currency,
       l.usage_ledger_amount_micros,
       prior_refund.refund_count,
       COALESCE(a.entitlement_allocated_micros, 0) AS entitlement_allocated_micros,
       c.available_micros, aus.settled_lifetime_micros AS account_settled_micros,
       kbs.settled_lifetime_micros AS key_settled_micros,
       kbd.settled_micros AS day_settled_micros,
       lower(substr(md5('failed-request-refund-v1:' || :'plan_sha256' || ':' || i.request_id), 1, 8)
         || '-' || substr(md5('failed-request-refund-v1:' || :'plan_sha256' || ':' || i.request_id), 9, 4)
         || '-5' || substr(md5('failed-request-refund-v1:' || :'plan_sha256' || ':' || i.request_id), 14, 3)
         || '-a' || substr(md5('failed-request-refund-v1:' || :'plan_sha256' || ':' || i.request_id), 18, 3)
         || '-' || substr(md5('failed-request-refund-v1:' || :'plan_sha256' || ':' || i.request_id), 21, 12)
       ) AS refund_ledger_id
  FROM fra_input i
  LEFT JOIN request_records r ON r.id = i.request_id
  LEFT JOIN key_records k ON k.id = r.key_id AND k.tenant_id = r.tenant_id
  LEFT JOIN facts f ON f.request_id = i.request_id AND f.tenant_id = i.tenant_id
  LEFT JOIN reservations u ON u.request_id = i.request_id
  LEFT JOIN usage_ledgers l ON l.request_id = i.request_id
  LEFT JOIN prior_refunds prior_refund ON prior_refund.request_id = i.request_id
  LEFT JOIN entitlement_allocations a ON a.request_id = i.request_id
  LEFT JOIN credit_accounts c ON c.id = i.account_id
  LEFT JOIN account_usage_state aus ON aus.account_id = i.account_id
  LEFT JOIN key_budget_state kbs ON kbs.key_id = i.key_id
  LEFT JOIN key_budget_daily_rollups kbd
    ON kbd.key_id = i.key_id AND kbd.day_bucket = i.usage_ledger_created_at / 86400000;

CREATE TEMP TABLE fra_account_refunds ON COMMIT DROP AS
SELECT account_id, sum(refund_micros) AS refund_micros
  FROM fra_observed GROUP BY account_id;
CREATE TEMP TABLE fra_key_refunds ON COMMIT DROP AS
SELECT key_id, sum(refund_micros) AS refund_micros
  FROM fra_observed GROUP BY key_id;
CREATE TEMP TABLE fra_budget_day_refunds ON COMMIT DROP AS
SELECT key_id, usage_ledger_created_at / 86400000 AS day_bucket,
       sum(refund_micros) AS refund_micros
  FROM fra_observed GROUP BY key_id, usage_ledger_created_at / 86400000;
CREATE TEMP TABLE fra_entitlement_refund_requirements ON COMMIT DROP AS
SELECT allocation.entitlement_cycle_id,
       sum(allocation.amount_micros) AS refund_micros
  FROM fra_input input
  JOIN entitlement_usage_allocations allocation ON allocation.usage_ledger_entry_id = input.usage_ledger_id
 GROUP BY allocation.entitlement_cycle_id;
CREATE TEMP TABLE fra_planned_request_daily_refunds ON COMMIT DROP AS
SELECT f.tenant_id, f.key_id, f.created_at / 86400000 AS day_bucket,
       f.model, f.protocol, f.status_class,
       f.error_code, f.upstream_account_id, f.model_route_id, f.service_tier,
       f.currency, sum(o.refund_micros) AS refund_micros
  FROM fra_observed o
  JOIN request_stats_facts f ON f.request_id = o.request_id AND f.tenant_id = o.tenant_id
 GROUP BY f.tenant_id, f.key_id, f.created_at / 86400000, f.model, f.protocol, f.status_class,
          f.error_code, f.upstream_account_id, f.model_route_id, f.service_tier, f.currency;
CREATE TEMP TABLE fra_planned_analysis_hourly_refunds ON COMMIT DROP AS
SELECT f.tenant_id, f.key_id, f.created_at / 3600000 AS hour_bucket, f.model,
       CASE WHEN f.protocol = 'anthropic' OR f.protocol LIKE 'anthropic-%' THEN 'anthropic'
            WHEN f.protocol = 'openai-image' THEN 'openai-image' ELSE 'openai' END AS protocol,
       f.status_class, f.error_code, f.upstream_account_id, f.model_route_id,
       f.service_tier, f.currency, sum(o.refund_micros) AS refund_micros
  FROM fra_observed o
  JOIN request_stats_facts f ON f.request_id = o.request_id AND f.tenant_id = o.tenant_id
 GROUP BY f.tenant_id, f.key_id, f.created_at / 3600000, f.model,
          CASE WHEN f.protocol = 'anthropic' OR f.protocol LIKE 'anthropic-%' THEN 'anthropic'
               WHEN f.protocol = 'openai-image' THEN 'openai-image' ELSE 'openai' END,
          f.status_class, f.error_code, f.upstream_account_id, f.model_route_id,
          f.service_tier, f.currency;
CREATE TEMP TABLE fra_planned_analysis_daily_refunds ON COMMIT DROP AS
SELECT f.tenant_id, f.key_id, f.created_at / 86400000 AS day_bucket, f.model,
       CASE WHEN f.protocol = 'anthropic' OR f.protocol LIKE 'anthropic-%' THEN 'anthropic'
            WHEN f.protocol = 'openai-image' THEN 'openai-image' ELSE 'openai' END AS protocol,
       f.status_class, f.error_code, f.upstream_account_id, f.model_route_id,
       f.service_tier, f.currency, sum(o.refund_micros) AS refund_micros
  FROM fra_observed o
  JOIN request_stats_facts f ON f.request_id = o.request_id AND f.tenant_id = o.tenant_id
 GROUP BY f.tenant_id, f.key_id, f.created_at / 86400000, f.model,
          CASE WHEN f.protocol = 'anthropic' OR f.protocol LIKE 'anthropic-%' THEN 'anthropic'
               WHEN f.protocol = 'openai-image' THEN 'openai-image' ELSE 'openai' END,
          f.status_class, f.error_code, f.upstream_account_id, f.model_route_id,
          f.service_tier, f.currency;
CREATE TEMP TABLE fra_expected_request_daily ON COMMIT DROP AS
SELECT planned.*, sum(fact.cost_micros - COALESCE(item.refund_micros, 0)) AS current_cost_micros
  FROM fra_planned_request_daily_refunds planned
  JOIN request_stats_facts fact ON fact.tenant_id = planned.tenant_id AND fact.key_id = planned.key_id
    AND fact.created_at / 86400000 = planned.day_bucket AND fact.model = planned.model
    AND fact.protocol = planned.protocol AND fact.status_class = planned.status_class
    AND fact.error_code = planned.error_code AND fact.upstream_account_id = planned.upstream_account_id
    AND fact.model_route_id = planned.model_route_id AND fact.service_tier = planned.service_tier
    AND fact.currency = planned.currency
  LEFT JOIN failed_request_cost_adjustment_items item ON item.request_id = fact.request_id AND item.tenant_id = fact.tenant_id
 GROUP BY planned.tenant_id, planned.key_id, planned.day_bucket, planned.model, planned.protocol,
          planned.status_class, planned.error_code, planned.upstream_account_id, planned.model_route_id,
          planned.service_tier, planned.currency, planned.refund_micros;
CREATE TEMP TABLE fra_expected_analysis_hourly ON COMMIT DROP AS
SELECT planned.*, sum(fact.cost_micros - COALESCE(item.refund_micros, 0)) AS current_cost_micros
  FROM fra_planned_analysis_hourly_refunds planned
  JOIN request_stats_facts fact ON fact.tenant_id = planned.tenant_id AND fact.key_id = planned.key_id
    AND fact.created_at / 3600000 = planned.hour_bucket AND fact.model = planned.model
    AND (CASE WHEN fact.protocol = 'anthropic' OR fact.protocol LIKE 'anthropic-%' THEN 'anthropic'
              WHEN fact.protocol = 'openai-image' THEN 'openai-image' ELSE 'openai' END) = planned.protocol
    AND fact.status_class = planned.status_class AND fact.error_code = planned.error_code
    AND fact.upstream_account_id = planned.upstream_account_id AND fact.model_route_id = planned.model_route_id
    AND fact.service_tier = planned.service_tier AND fact.currency = planned.currency
  LEFT JOIN failed_request_cost_adjustment_items item ON item.request_id = fact.request_id AND item.tenant_id = fact.tenant_id
 GROUP BY planned.tenant_id, planned.key_id, planned.hour_bucket, planned.model, planned.protocol,
          planned.status_class, planned.error_code, planned.upstream_account_id, planned.model_route_id,
          planned.service_tier, planned.currency, planned.refund_micros;
CREATE TEMP TABLE fra_expected_analysis_daily ON COMMIT DROP AS
SELECT planned.*, sum(fact.cost_micros - COALESCE(item.refund_micros, 0)) AS current_cost_micros
  FROM fra_planned_analysis_daily_refunds planned
  JOIN request_stats_facts fact ON fact.tenant_id = planned.tenant_id AND fact.key_id = planned.key_id
    AND fact.created_at / 86400000 = planned.day_bucket AND fact.model = planned.model
    AND (CASE WHEN fact.protocol = 'anthropic' OR fact.protocol LIKE 'anthropic-%' THEN 'anthropic'
              WHEN fact.protocol = 'openai-image' THEN 'openai-image' ELSE 'openai' END) = planned.protocol
    AND fact.status_class = planned.status_class AND fact.error_code = planned.error_code
    AND fact.upstream_account_id = planned.upstream_account_id AND fact.model_route_id = planned.model_route_id
    AND fact.service_tier = planned.service_tier AND fact.currency = planned.currency
  LEFT JOIN failed_request_cost_adjustment_items item ON item.request_id = fact.request_id AND item.tenant_id = fact.tenant_id
 GROUP BY planned.tenant_id, planned.key_id, planned.day_bucket, planned.model, planned.protocol,
          planned.status_class, planned.error_code, planned.upstream_account_id, planned.model_route_id,
          planned.service_tier, planned.currency, planned.refund_micros;

/* Projection preconditions and updates operate on these exact rows. */
DO $$
BEGIN
  PERFORM 1 FROM request_daily_aggregates daily
    JOIN fra_planned_request_daily_refunds refund ON daily.tenant_id = refund.tenant_id AND daily.key_id = refund.key_id
      AND daily.day_bucket = refund.day_bucket AND daily.model = refund.model
      AND daily.protocol = refund.protocol AND daily.status_class = refund.status_class
      AND daily.error_code = refund.error_code AND daily.upstream_account_id = refund.upstream_account_id
      AND daily.model_route_id = refund.model_route_id AND daily.service_tier = refund.service_tier
      AND daily.currency = refund.currency
   FOR UPDATE OF daily;
  PERFORM 1 FROM usage_analysis_hourly hourly
    JOIN fra_planned_analysis_hourly_refunds refund ON hourly.tenant_id = refund.tenant_id AND hourly.key_id = refund.key_id
      AND hourly.hour_bucket = refund.hour_bucket AND hourly.source_kind = 'request'
      AND hourly.model = refund.model
      AND hourly.protocol = refund.protocol
      AND hourly.status_class = refund.status_class AND hourly.error_code = refund.error_code
      AND hourly.upstream_account_id = refund.upstream_account_id AND hourly.model_route_id = refund.model_route_id
      AND hourly.service_tier = refund.service_tier AND hourly.currency = refund.currency
   FOR UPDATE OF hourly;
  PERFORM 1 FROM usage_analysis_daily daily
    JOIN fra_planned_analysis_daily_refunds refund ON daily.tenant_id = refund.tenant_id AND daily.key_id = refund.key_id
      AND daily.day_bucket = refund.day_bucket AND daily.source_kind = 'request'
      AND daily.model = refund.model
      AND daily.protocol = refund.protocol
      AND daily.status_class = refund.status_class AND daily.error_code = refund.error_code
      AND daily.upstream_account_id = refund.upstream_account_id AND daily.model_route_id = refund.model_route_id
      AND daily.service_tier = refund.service_tier AND daily.currency = refund.currency
   FOR UPDATE OF daily;
END $$;

INSERT INTO fra_fence(reason, invalid)
SELECT 'candidate_drift_or_missing_evidence', true
 WHERE EXISTS (SELECT 1 FROM fra_new_plan)
   AND EXISTS (
   SELECT 1 FROM fra_observed o
    CROSS JOIN fra_scope scope
    JOIN tenants scoped_tenant ON scoped_tenant.external_id = scope.tenant_external_id
    WHERE o.observed_request_id IS NULL
       OR o.tenant_id <> scoped_tenant.id
       OR o.request_created_at < (scope.scope_json->>'from_ms')::bigint
       OR o.request_created_at >= (scope.scope_json->>'to_ms')::bigint
       OR NOT EXISTS (
         SELECT 1 FROM jsonb_array_elements_text(scope.scope_json->'status_codes') status
          WHERE status::bigint = o.status_code
       )
       OR o.observed_request_created_at IS DISTINCT FROM o.request_created_at
       OR o.observed_tenant_id IS DISTINCT FROM o.tenant_id OR o.observed_key_id IS DISTINCT FROM o.key_id
       OR o.observed_account_id IS DISTINCT FROM o.account_id OR o.observed_reservation_id IS DISTINCT FROM o.reservation_id
       OR o.observed_status_code IS DISTINCT FROM o.status_code OR o.observed_currency IS DISTINCT FROM o.currency
       OR o.observed_cost_micros IS DISTINCT FROM o.refund_micros
       OR o.fact_count IS DISTINCT FROM 1 OR o.fact_cost_micros IS DISTINCT FROM o.refund_micros
       OR o.reservation_count IS DISTINCT FROM 1 OR o.reservation_status IS DISTINCT FROM 'settled'
       OR o.reservation_account_id IS DISTINCT FROM o.account_id OR o.reservation_key_id IS DISTINCT FROM o.key_id
       OR o.reservation_actual_micros IS DISTINCT FROM o.refund_micros
       OR o.usage_count IS DISTINCT FROM 1 OR o.observed_usage_ledger_id IS DISTINCT FROM o.usage_ledger_id
       OR o.observed_usage_ledger_created_at IS DISTINCT FROM o.usage_ledger_created_at
       OR o.usage_ledger_account_id IS DISTINCT FROM o.account_id OR o.usage_ledger_key_id IS DISTINCT FROM o.key_id
       OR o.usage_ledger_currency IS DISTINCT FROM o.currency OR o.usage_ledger_amount_micros IS DISTINCT FROM -o.refund_micros
       OR o.observed_key_currency IS DISTINCT FROM o.currency
       OR o.refund_count IS DISTINCT FROM 0
       OR o.entitlement_allocated_micros > o.refund_micros
 );
INSERT INTO fra_fence(reason, invalid)
SELECT 'refund_projection_precondition_failed', true
 WHERE EXISTS (SELECT 1 FROM fra_new_plan)
   AND (
   EXISTS (
   SELECT 1 FROM fra_account_refunds refund
    LEFT JOIN credit_accounts account ON account.id = refund.account_id
    LEFT JOIN account_usage_state usage_state ON usage_state.account_id = refund.account_id
    WHERE account.available_micros IS NULL
       OR account.available_micros > 9223372036854775807 - refund.refund_micros
       OR usage_state.settled_lifetime_micros IS NULL OR usage_state.settled_lifetime_micros < refund.refund_micros
 )
   OR EXISTS (
   SELECT 1 FROM fra_key_refunds refund
    LEFT JOIN key_budget_state state ON state.key_id = refund.key_id
    WHERE state.settled_lifetime_micros IS NULL OR state.settled_lifetime_micros < refund.refund_micros
 )
   OR EXISTS (
   SELECT 1 FROM fra_budget_day_refunds refund
    LEFT JOIN key_budget_daily_rollups rollup
      ON rollup.key_id = refund.key_id AND rollup.day_bucket = refund.day_bucket
    WHERE rollup.settled_micros IS NULL OR rollup.settled_micros < refund.refund_micros
 )
   OR EXISTS (
   SELECT 1 FROM fra_expected_request_daily refund
    LEFT JOIN request_daily_aggregates daily
      ON daily.tenant_id = refund.tenant_id AND daily.key_id = refund.key_id
     AND daily.day_bucket = refund.day_bucket AND daily.model = refund.model
     AND daily.protocol = refund.protocol AND daily.status_class = refund.status_class
     AND daily.error_code = refund.error_code AND daily.upstream_account_id = refund.upstream_account_id
     AND daily.model_route_id = refund.model_route_id AND daily.service_tier = refund.service_tier
     AND daily.currency = refund.currency
   WHERE daily.cost_micros IS DISTINCT FROM refund.current_cost_micros
      OR daily.cost_micros < refund.refund_micros
 )
   OR EXISTS (
   SELECT 1 FROM fra_expected_analysis_hourly refund
    LEFT JOIN usage_analysis_hourly hourly
      ON hourly.tenant_id = refund.tenant_id AND hourly.key_id = refund.key_id
     AND hourly.hour_bucket = refund.hour_bucket AND hourly.source_kind = 'request'
     AND hourly.model = refund.model
     AND hourly.protocol = refund.protocol
     AND hourly.status_class = refund.status_class AND hourly.error_code = refund.error_code
     AND hourly.upstream_account_id = refund.upstream_account_id AND hourly.model_route_id = refund.model_route_id
     AND hourly.service_tier = refund.service_tier AND hourly.currency = refund.currency
   WHERE hourly.cost_micros IS DISTINCT FROM refund.current_cost_micros
      OR hourly.cost_micros < refund.refund_micros
 )
   OR EXISTS (
   SELECT 1 FROM fra_expected_analysis_daily refund
    LEFT JOIN usage_analysis_daily analysis_daily
      ON analysis_daily.tenant_id = refund.tenant_id AND analysis_daily.key_id = refund.key_id
     AND analysis_daily.day_bucket = refund.day_bucket AND analysis_daily.source_kind = 'request'
     AND analysis_daily.model = refund.model
     AND analysis_daily.protocol = refund.protocol
     AND analysis_daily.status_class = refund.status_class AND analysis_daily.error_code = refund.error_code
     AND analysis_daily.upstream_account_id = refund.upstream_account_id AND analysis_daily.model_route_id = refund.model_route_id
     AND analysis_daily.service_tier = refund.service_tier AND analysis_daily.currency = refund.currency
   WHERE analysis_daily.cost_micros IS DISTINCT FROM refund.current_cost_micros
      OR analysis_daily.cost_micros < refund.refund_micros
 ));
INSERT INTO fra_fence(reason, invalid)
SELECT 'already_refunded_by_another_plan', true
 WHERE EXISTS (
   SELECT 1 FROM fra_observed o
    JOIN failed_request_cost_adjustment_items item ON item.usage_ledger_id = o.usage_ledger_id
   WHERE EXISTS (SELECT 1 FROM fra_new_plan)
     AND item.plan_sha256 <> :'plan_sha256'
 );
INSERT INTO fra_fence(reason, invalid)
SELECT 'entitlement_projection_precondition_failed', true
 WHERE EXISTS (SELECT 1 FROM fra_new_plan)
   AND EXISTS (
   SELECT 1 FROM fra_entitlement_refund_requirements refund
    LEFT JOIN entitlement_cycles cycle ON cycle.id = refund.entitlement_cycle_id
   WHERE cycle.consumed_micros IS NULL OR cycle.consumed_micros < refund.refund_micros
 );

CREATE TEMP TABLE fra_refunds ON COMMIT DROP AS
WITH inserted AS (
  INSERT INTO ledger_entries
    (id, account_id, key_id, kind, amount_micros, currency, source,
     idempotency_key, reference_entry_id, created_at)
  SELECT o.refund_ledger_id, o.account_id, o.key_id, 'failed_request_refund',
         o.refund_micros, o.currency,
         'failed-request-adjustment:' || :'plan_sha256',
         'failed-request-refund-v1:' || :'plan_sha256' || ':' || o.usage_ledger_id,
         o.usage_ledger_id, :'now_ms'::bigint
    FROM fra_observed o
   WHERE EXISTS (SELECT 1 FROM fra_new_plan)
  ON CONFLICT DO NOTHING
  RETURNING id
)
SELECT o.* FROM fra_observed o JOIN inserted i ON i.id = o.refund_ledger_id;
INSERT INTO fra_fence(reason, invalid)
SELECT 'refund_ledger_idempotency_conflict', true
 WHERE EXISTS (SELECT 1 FROM fra_new_plan)
   AND (SELECT count(*) FROM fra_refunds) <> (SELECT count(*) FROM fra_input);

CREATE TEMP TABLE fra_refund_entitlement_allocations ON COMMIT DROP AS
SELECT r.refund_ledger_id, allocation.entitlement_cycle_id,
       sum(allocation.amount_micros) AS amount_micros
  FROM fra_refunds r
 JOIN entitlement_usage_allocations allocation ON allocation.usage_ledger_entry_id = r.usage_ledger_id
 GROUP BY r.refund_ledger_id, allocation.entitlement_cycle_id;
CREATE TEMP TABLE fra_refund_entitlements ON COMMIT DROP AS
SELECT entitlement_cycle_id, sum(amount_micros) AS amount_micros
  FROM fra_refund_entitlement_allocations
 GROUP BY entitlement_cycle_id;
CREATE TEMP TABLE fra_applied_account_refunds ON COMMIT DROP AS
SELECT account_id, sum(refund_micros) AS refund_micros
  FROM fra_refunds GROUP BY account_id;
CREATE TEMP TABLE fra_applied_key_refunds ON COMMIT DROP AS
SELECT key_id, sum(refund_micros) AS refund_micros
  FROM fra_refunds GROUP BY key_id;
CREATE TEMP TABLE fra_applied_budget_day_refunds ON COMMIT DROP AS
SELECT key_id, usage_ledger_created_at / 86400000 AS day_bucket,
       sum(refund_micros) AS refund_micros
  FROM fra_refunds GROUP BY key_id, usage_ledger_created_at / 86400000;

INSERT INTO failed_request_cost_adjustment_items
  (plan_sha256, request_id, request_created_at, usage_ledger_id, refund_ledger_id,
   tenant_id, key_id, account_id, reservation_id, usage_ledger_created_at,
   status_code, currency, refund_micros)
SELECT :'plan_sha256', request_id, request_created_at, usage_ledger_id,
       refund_ledger_id, tenant_id, key_id, account_id, reservation_id,
       usage_ledger_created_at, status_code, currency, refund_micros
  FROM fra_refunds;

UPDATE credit_accounts account
   SET available_micros = account.available_micros + refund.refund_micros,
       updated_at = :'now_ms'::bigint
  FROM fra_applied_account_refunds refund
 WHERE account.id = refund.account_id;
UPDATE account_usage_state state
   SET settled_lifetime_micros = state.settled_lifetime_micros - refund.refund_micros,
       updated_at = :'now_ms'::bigint
  FROM fra_applied_account_refunds refund
 WHERE state.account_id = refund.account_id;
UPDATE key_budget_state state
   SET settled_lifetime_micros = state.settled_lifetime_micros - refund.refund_micros,
       updated_at = :'now_ms'::bigint
  FROM fra_applied_key_refunds refund
 WHERE state.key_id = refund.key_id;
UPDATE key_budget_daily_rollups rollup
   SET settled_micros = rollup.settled_micros - refund.refund_micros
 FROM fra_applied_budget_day_refunds refund
 WHERE rollup.key_id = refund.key_id
   AND rollup.day_bucket = refund.day_bucket;
INSERT INTO key_budget_usage_events
  (usage_entry_id, reservation_id, key_id, account_id, amount_micros, settled_at)
SELECT refund_ledger_id, reservation_id, key_id, account_id, -refund_micros,
       usage_ledger_created_at
  FROM fra_refunds
 WHERE usage_ledger_created_at >= :'now_ms'::bigint - 7 * 86400000;
UPDATE entitlement_cycles cycle
   SET consumed_micros = cycle.consumed_micros - refund.amount_micros,
       updated_at = :'now_ms'::bigint
  FROM fra_refund_entitlements refund
 WHERE cycle.id = refund.entitlement_cycle_id;
INSERT INTO entitlement_usage_allocations
  (id, entitlement_cycle_id, usage_ledger_entry_id, amount_micros, created_at)
SELECT lower(substr(md5('failed-request-entitlement-refund-v1:' || refund.refund_ledger_id || ':' || refund.entitlement_cycle_id), 1, 8)
       || '-' || substr(md5('failed-request-entitlement-refund-v1:' || refund.refund_ledger_id || ':' || refund.entitlement_cycle_id), 9, 4)
       || '-5' || substr(md5('failed-request-entitlement-refund-v1:' || refund.refund_ledger_id || ':' || refund.entitlement_cycle_id), 14, 3)
       || '-a' || substr(md5('failed-request-entitlement-refund-v1:' || refund.refund_ledger_id || ':' || refund.entitlement_cycle_id), 18, 3)
       || '-' || substr(md5('failed-request-entitlement-refund-v1:' || refund.refund_ledger_id || ':' || refund.entitlement_cycle_id), 21, 12)
       ), refund.entitlement_cycle_id, refund.refund_ledger_id,
       -refund.amount_micros, :'now_ms'::bigint
  FROM fra_refund_entitlement_allocations refund;
UPDATE request_daily_aggregates daily
   SET cost_micros = daily.cost_micros - refund.refund_micros
  FROM fra_planned_request_daily_refunds refund
  CROSS JOIN fra_new_plan
 WHERE daily.tenant_id = refund.tenant_id AND daily.key_id = refund.key_id
   AND daily.day_bucket = refund.day_bucket AND daily.model = refund.model
   AND daily.protocol = refund.protocol AND daily.status_class = refund.status_class
   AND daily.error_code = refund.error_code AND daily.upstream_account_id = refund.upstream_account_id
   AND daily.model_route_id = refund.model_route_id AND daily.service_tier = refund.service_tier
   AND daily.currency = refund.currency;
UPDATE usage_analysis_hourly hourly
   SET cost_micros = hourly.cost_micros - refund.refund_micros
  FROM fra_planned_analysis_hourly_refunds refund
  CROSS JOIN fra_new_plan
 WHERE hourly.tenant_id = refund.tenant_id AND hourly.key_id = refund.key_id
   AND hourly.hour_bucket = refund.hour_bucket AND hourly.source_kind = 'request'
   AND hourly.model = refund.model
   AND hourly.protocol = refund.protocol
   AND hourly.status_class = refund.status_class AND hourly.error_code = refund.error_code
   AND hourly.upstream_account_id = refund.upstream_account_id AND hourly.model_route_id = refund.model_route_id
   AND hourly.service_tier = refund.service_tier AND hourly.currency = refund.currency;
UPDATE usage_analysis_daily daily
   SET cost_micros = daily.cost_micros - refund.refund_micros
  FROM fra_planned_analysis_daily_refunds refund
  CROSS JOIN fra_new_plan
 WHERE daily.tenant_id = refund.tenant_id AND daily.key_id = refund.key_id
   AND daily.day_bucket = refund.day_bucket AND daily.source_kind = 'request'
   AND daily.model = refund.model
   AND daily.protocol = refund.protocol
   AND daily.status_class = refund.status_class AND daily.error_code = refund.error_code
   AND daily.upstream_account_id = refund.upstream_account_id AND daily.model_route_id = refund.model_route_id
   AND daily.service_tier = refund.service_tier AND daily.currency = refund.currency;
INSERT INTO failed_request_cost_adjustment_daily
  (tenant_id, key_id, day_bucket, currency, status_code, adjustment_count,
   refund_micros, rebuilt_at)
SELECT tenant_id, key_id, request_created_at / 86400000, currency, status_code,
       count(*), sum(refund_micros), :'now_ms'::bigint
  FROM fra_refunds
 GROUP BY tenant_id, key_id, request_created_at / 86400000, currency, status_code
ON CONFLICT (tenant_id, key_id, day_bucket, currency, status_code) DO UPDATE SET
  adjustment_count = failed_request_cost_adjustment_daily.adjustment_count + excluded.adjustment_count,
  refund_micros = failed_request_cost_adjustment_daily.refund_micros + excluded.refund_micros,
  rebuilt_at = excluded.rebuilt_at;

SELECT json_build_object(
  'outcome', CASE WHEN EXISTS (SELECT 1 FROM fra_new_plan) THEN 'applied' ELSE 'already_applied' END,
  'candidate_count', CASE WHEN EXISTS (SELECT 1 FROM fra_new_plan)
                           THEN (SELECT count(*)::text FROM fra_refunds)
                           ELSE (SELECT candidate_count::text FROM failed_request_cost_adjustment_plans WHERE plan_sha256 = :'plan_sha256') END,
  'refund_micros', CASE WHEN EXISTS (SELECT 1 FROM fra_new_plan)
                        THEN (SELECT COALESCE(sum(refund_micros), 0)::text FROM fra_refunds)
                        ELSE (SELECT refund_micros::text FROM failed_request_cost_adjustment_plans WHERE plan_sha256 = :'plan_sha256') END,
  'plan_sha256', :'plan_sha256'
);
COMMIT;
