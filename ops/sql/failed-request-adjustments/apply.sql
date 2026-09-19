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

LOCK TABLE request_records, request_stats_facts, ledger_entries, usage_reservations,
  credit_accounts, account_usage_state, key_budget_state, key_budget_daily_rollups,
  key_budget_usage_events, entitlement_cycles, entitlement_usage_allocations,
  failed_request_cost_adjustment_plans, failed_request_cost_adjustment_items,
  failed_request_cost_adjustment_daily IN SHARE ROW EXCLUSIVE MODE;

CREATE TEMP TABLE fra_scope ON COMMIT DROP AS
SELECT (:'plan_json'::jsonb->'scope'->>'tenant_external_id') AS tenant_external_id,
       (:'plan_json'::jsonb->'scope') AS scope_json;
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
  FROM jsonb_to_recordset(:'plan_json'::jsonb->'candidates') AS input(
    request_id TEXT, request_created_at BIGINT, tenant_id TEXT, key_id TEXT,
    account_id TEXT, reservation_id TEXT, usage_ledger_id TEXT,
    usage_ledger_created_at BIGINT, status_code BIGINT, currency TEXT,
    refund_micros BIGINT
  );

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

CREATE TEMP TABLE fra_observed ON COMMIT DROP AS
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
  LEFT JOIN LATERAL (
    SELECT count(*) AS fact_count, min(cost_micros) AS fact_cost_micros
      FROM request_stats_facts f WHERE f.request_id = i.request_id AND f.tenant_id = i.tenant_id
  ) f ON true
  LEFT JOIN LATERAL (
    SELECT count(*) AS reservation_count, min(account_id) AS reservation_account_id,
           min(key_id) AS reservation_key_id, min(actual_micros) AS reservation_actual_micros,
           min(status) AS reservation_status
      FROM usage_reservations u WHERE u.id = i.reservation_id
  ) u ON true
  LEFT JOIN LATERAL (
    SELECT count(*) AS usage_count, min(id) AS usage_ledger_id,
           min(created_at) AS usage_ledger_created_at, min(account_id) AS usage_ledger_account_id,
           min(key_id) AS usage_ledger_key_id, min(currency) AS usage_ledger_currency,
           min(amount_micros) AS usage_ledger_amount_micros
      FROM ledger_entries l WHERE l.source = i.reservation_id AND l.kind = 'usage'
  ) l ON true
  LEFT JOIN LATERAL (
    SELECT count(*) AS refund_count
      FROM ledger_entries refund
     WHERE refund.kind = 'failed_request_refund'
       AND refund.reference_entry_id = i.usage_ledger_id
  ) prior_refund ON true
  LEFT JOIN LATERAL (
    SELECT sum(amount_micros) AS entitlement_allocated_micros
      FROM entitlement_usage_allocations a WHERE a.usage_ledger_entry_id = i.usage_ledger_id
  ) a ON true
  LEFT JOIN credit_accounts c ON c.id = i.account_id
  LEFT JOIN account_usage_state aus ON aus.account_id = i.account_id
  LEFT JOIN key_budget_state kbs ON kbs.key_id = i.key_id
  LEFT JOIN key_budget_daily_rollups kbd
    ON kbd.key_id = i.key_id AND kbd.day_bucket = i.usage_ledger_created_at / 86400000;

INSERT INTO fra_fence(reason, invalid)
SELECT 'candidate_drift_or_missing_evidence', true
 WHERE EXISTS (SELECT 1 FROM fra_new_plan)
   AND EXISTS (
   SELECT 1 FROM fra_observed o
    WHERE o.observed_request_id IS NULL
       OR o.observed_request_created_at <> o.request_created_at
       OR o.observed_tenant_id <> o.tenant_id OR o.observed_key_id <> o.key_id
       OR o.observed_account_id <> o.account_id OR o.observed_reservation_id <> o.reservation_id
       OR o.observed_status_code <> o.status_code OR o.observed_currency <> o.currency
       OR o.observed_cost_micros <> o.refund_micros
       OR o.fact_count <> 1 OR o.fact_cost_micros <> o.refund_micros
       OR o.reservation_count <> 1 OR o.reservation_status <> 'settled'
       OR o.reservation_account_id <> o.account_id OR o.reservation_key_id <> o.key_id
       OR o.reservation_actual_micros <> o.refund_micros
       OR o.usage_count <> 1 OR o.observed_usage_ledger_id <> o.usage_ledger_id
       OR o.observed_usage_ledger_created_at <> o.usage_ledger_created_at
       OR o.usage_ledger_account_id <> o.account_id OR o.usage_ledger_key_id <> o.key_id
       OR o.usage_ledger_currency <> o.currency OR o.usage_ledger_amount_micros <> -o.refund_micros
       OR o.observed_key_currency <> o.currency
       OR o.refund_count <> 0
       OR o.entitlement_allocated_micros > o.refund_micros
 );
INSERT INTO fra_fence(reason, invalid)
SELECT 'refund_projection_precondition_failed', true
 WHERE EXISTS (SELECT 1 FROM fra_new_plan)
   AND EXISTS (
   SELECT 1 FROM fra_observed o
    WHERE o.available_micros IS NULL OR o.available_micros > 9223372036854775807 - o.refund_micros
       OR o.account_settled_micros IS NULL OR o.account_settled_micros < o.refund_micros
       OR o.key_settled_micros IS NULL OR o.key_settled_micros < o.refund_micros
       OR o.day_settled_micros IS NULL OR o.day_settled_micros < o.refund_micros
 );
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
   SELECT 1
     FROM fra_observed o
     JOIN entitlement_usage_allocations allocation ON allocation.usage_ledger_entry_id = o.usage_ledger_id
     JOIN entitlement_cycles cycle ON cycle.id = allocation.entitlement_cycle_id
    GROUP BY o.usage_ledger_id, cycle.id, cycle.consumed_micros
   HAVING cycle.consumed_micros < sum(allocation.amount_micros)
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

CREATE TEMP TABLE fra_refund_entitlements ON COMMIT DROP AS
SELECT r.refund_ledger_id, allocation.entitlement_cycle_id,
       sum(allocation.amount_micros) AS amount_micros
  FROM fra_refunds r
  JOIN entitlement_usage_allocations allocation ON allocation.usage_ledger_entry_id = r.usage_ledger_id
 GROUP BY r.refund_ledger_id, allocation.entitlement_cycle_id;

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
  FROM fra_refunds refund
 WHERE account.id = refund.account_id;
UPDATE account_usage_state state
   SET settled_lifetime_micros = state.settled_lifetime_micros - refund.refund_micros,
       updated_at = :'now_ms'::bigint
  FROM fra_refunds refund
 WHERE state.account_id = refund.account_id;
UPDATE key_budget_state state
   SET settled_lifetime_micros = state.settled_lifetime_micros - refund.refund_micros,
       updated_at = :'now_ms'::bigint
  FROM fra_refunds refund
 WHERE state.key_id = refund.key_id;
UPDATE key_budget_daily_rollups rollup
   SET settled_micros = rollup.settled_micros - refund.refund_micros
  FROM fra_refunds refund
 WHERE rollup.key_id = refund.key_id
   AND rollup.day_bucket = refund.usage_ledger_created_at / 86400000;
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
  FROM fra_refund_entitlements refund;
INSERT INTO failed_request_cost_adjustment_daily
  (tenant_id, key_id, day_bucket, currency, status_code, adjustment_count,
   refund_micros, rebuilt_at)
SELECT tenant_id, key_id, usage_ledger_created_at / 86400000, currency, status_code,
       count(*), sum(refund_micros), :'now_ms'::bigint
  FROM fra_refunds
 GROUP BY tenant_id, key_id, usage_ledger_created_at / 86400000, currency, status_code
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
