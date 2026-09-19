/* FRA_REBUILD_DERIVED_V2: rebuild operator cost projections from facts minus append-only adjustments. */
BEGIN;
SET LOCAL statement_timeout = '60s';

CREATE TEMP TABLE fra_rebuild_dimensions ON COMMIT DROP AS
SELECT DISTINCT fact.tenant_id, fact.key_id, fact.created_at / 86400000 AS day_bucket,
       fact.created_at / 3600000 AS hour_bucket, fact.model, fact.protocol,
       fact.status_class, fact.error_code, fact.upstream_account_id,
       fact.model_route_id, fact.service_tier, fact.currency
  FROM request_stats_facts fact
 JOIN failed_request_cost_adjustment_items item
    ON item.request_id = fact.request_id AND item.tenant_id = fact.tenant_id
 WHERE fact.tenant_id = (SELECT id FROM tenants WHERE external_id = :'tenant_external_id');
CREATE TEMP TABLE fra_rebuild_request_daily_targets ON COMMIT DROP AS
SELECT DISTINCT tenant_id,key_id,day_bucket,model,protocol,status_class,error_code,
       upstream_account_id,model_route_id,service_tier,currency
  FROM fra_rebuild_dimensions;
CREATE TEMP TABLE fra_rebuild_hourly_targets ON COMMIT DROP AS
SELECT DISTINCT tenant_id,key_id,hour_bucket,model,
       CASE WHEN protocol='anthropic' OR protocol LIKE 'anthropic-%' THEN 'anthropic'
            WHEN protocol='openai-image' THEN 'openai-image' ELSE 'openai' END AS protocol,
       status_class,error_code,upstream_account_id,model_route_id,service_tier,currency
  FROM fra_rebuild_dimensions;
CREATE TEMP TABLE fra_rebuild_analysis_daily_targets ON COMMIT DROP AS
SELECT DISTINCT tenant_id,key_id,day_bucket,model,
       CASE WHEN protocol='anthropic' OR protocol LIKE 'anthropic-%' THEN 'anthropic'
            WHEN protocol='openai-image' THEN 'openai-image' ELSE 'openai' END AS protocol,
       status_class,error_code,upstream_account_id,model_route_id,service_tier,currency
  FROM fra_rebuild_dimensions;
CREATE TEMP TABLE fra_rebuild_fence (
  reason TEXT NOT NULL,
  invalid BOOLEAN NOT NULL CHECK (invalid = false)
) ON COMMIT DROP;
INSERT INTO fra_rebuild_fence(reason, invalid)
SELECT 'request_daily_projection_missing', true
 WHERE EXISTS (SELECT 1 FROM fra_rebuild_request_daily_targets target
   LEFT JOIN request_daily_aggregates actual ON actual.tenant_id=target.tenant_id AND actual.key_id=target.key_id AND actual.day_bucket=target.day_bucket AND actual.model=target.model AND actual.protocol=target.protocol AND actual.status_class=target.status_class AND actual.error_code=target.error_code AND actual.upstream_account_id=target.upstream_account_id AND actual.model_route_id=target.model_route_id AND actual.service_tier=target.service_tier AND actual.currency=target.currency
   WHERE actual.tenant_id IS NULL);
INSERT INTO fra_rebuild_fence(reason, invalid)
SELECT 'analysis_hourly_projection_missing', true
 WHERE EXISTS (SELECT 1 FROM fra_rebuild_hourly_targets target
   LEFT JOIN usage_analysis_hourly actual ON actual.tenant_id=target.tenant_id AND actual.key_id=target.key_id AND actual.hour_bucket=target.hour_bucket AND actual.source_kind='request' AND actual.model=target.model AND actual.protocol=target.protocol AND actual.status_class=target.status_class AND actual.error_code=target.error_code AND actual.upstream_account_id=target.upstream_account_id AND actual.model_route_id=target.model_route_id AND actual.service_tier=target.service_tier AND actual.currency=target.currency
   WHERE actual.tenant_id IS NULL);
INSERT INTO fra_rebuild_fence(reason, invalid)
SELECT 'analysis_daily_projection_missing', true
 WHERE EXISTS (SELECT 1 FROM fra_rebuild_analysis_daily_targets target
   LEFT JOIN usage_analysis_daily actual ON actual.tenant_id=target.tenant_id AND actual.key_id=target.key_id AND actual.day_bucket=target.day_bucket AND actual.source_kind='request' AND actual.model=target.model AND actual.protocol=target.protocol AND actual.status_class=target.status_class AND actual.error_code=target.error_code AND actual.upstream_account_id=target.upstream_account_id AND actual.model_route_id=target.model_route_id AND actual.service_tier=target.service_tier AND actual.currency=target.currency
   WHERE actual.tenant_id IS NULL);

WITH expected AS (
  SELECT d.tenant_id, d.key_id, d.day_bucket, d.model, d.protocol, d.status_class,
         d.error_code, d.upstream_account_id, d.model_route_id, d.service_tier,
         d.currency, sum(fact.cost_micros - COALESCE(item.refund_micros, 0)) AS cost_micros
    FROM fra_rebuild_request_daily_targets d
    JOIN request_stats_facts fact ON fact.tenant_id=d.tenant_id AND fact.key_id=d.key_id
     AND fact.created_at/86400000=d.day_bucket AND fact.model=d.model AND fact.protocol=d.protocol
     AND fact.status_class=d.status_class AND fact.error_code=d.error_code AND fact.upstream_account_id=d.upstream_account_id
     AND fact.model_route_id=d.model_route_id AND fact.service_tier=d.service_tier AND fact.currency=d.currency
    LEFT JOIN failed_request_cost_adjustment_items item ON item.request_id=fact.request_id AND item.tenant_id=fact.tenant_id
   GROUP BY d.tenant_id,d.key_id,d.day_bucket,d.model,d.protocol,d.status_class,d.error_code,d.upstream_account_id,d.model_route_id,d.service_tier,d.currency
)
UPDATE request_daily_aggregates actual SET cost_micros=expected.cost_micros FROM expected
 WHERE actual.tenant_id=expected.tenant_id AND actual.key_id=expected.key_id AND actual.day_bucket=expected.day_bucket
   AND actual.model=expected.model AND actual.protocol=expected.protocol AND actual.status_class=expected.status_class
   AND actual.error_code=expected.error_code AND actual.upstream_account_id=expected.upstream_account_id
   AND actual.model_route_id=expected.model_route_id AND actual.service_tier=expected.service_tier AND actual.currency=expected.currency;

WITH expected AS (
  SELECT d.tenant_id, d.key_id, d.hour_bucket, d.model, d.protocol,
         d.status_class,d.error_code,d.upstream_account_id,d.model_route_id,d.service_tier,d.currency,
         sum(fact.cost_micros-COALESCE(item.refund_micros,0)) AS cost_micros
    FROM fra_rebuild_hourly_targets d JOIN request_stats_facts fact ON fact.tenant_id=d.tenant_id AND fact.key_id=d.key_id
     AND fact.created_at/3600000=d.hour_bucket AND fact.model=d.model
     AND (CASE WHEN fact.protocol='anthropic' OR fact.protocol LIKE 'anthropic-%' THEN 'anthropic' WHEN fact.protocol='openai-image' THEN 'openai-image' ELSE 'openai' END)=d.protocol
     AND fact.status_class=d.status_class AND fact.error_code=d.error_code AND fact.upstream_account_id=d.upstream_account_id AND fact.model_route_id=d.model_route_id AND fact.service_tier=d.service_tier AND fact.currency=d.currency
    LEFT JOIN failed_request_cost_adjustment_items item ON item.request_id=fact.request_id AND item.tenant_id=fact.tenant_id
   GROUP BY d.tenant_id,d.key_id,d.hour_bucket,d.model,d.protocol,d.status_class,d.error_code,d.upstream_account_id,d.model_route_id,d.service_tier,d.currency
)
UPDATE usage_analysis_hourly actual SET cost_micros=expected.cost_micros FROM expected
 WHERE actual.tenant_id=expected.tenant_id AND actual.key_id=expected.key_id AND actual.hour_bucket=expected.hour_bucket AND actual.source_kind='request'
   AND actual.model=expected.model AND actual.protocol=expected.protocol AND actual.status_class=expected.status_class AND actual.error_code=expected.error_code AND actual.upstream_account_id=expected.upstream_account_id AND actual.model_route_id=expected.model_route_id AND actual.service_tier=expected.service_tier AND actual.currency=expected.currency;

WITH expected AS (
  SELECT d.tenant_id, d.key_id, d.day_bucket, d.model, d.protocol,
         d.status_class,d.error_code,d.upstream_account_id,d.model_route_id,d.service_tier,d.currency,
         sum(fact.cost_micros-COALESCE(item.refund_micros,0)) AS cost_micros
    FROM fra_rebuild_analysis_daily_targets d JOIN request_stats_facts fact ON fact.tenant_id=d.tenant_id AND fact.key_id=d.key_id
     AND fact.created_at/86400000=d.day_bucket AND fact.model=d.model
     AND (CASE WHEN fact.protocol='anthropic' OR fact.protocol LIKE 'anthropic-%' THEN 'anthropic' WHEN fact.protocol='openai-image' THEN 'openai-image' ELSE 'openai' END)=d.protocol
     AND fact.status_class=d.status_class AND fact.error_code=d.error_code AND fact.upstream_account_id=d.upstream_account_id AND fact.model_route_id=d.model_route_id AND fact.service_tier=d.service_tier AND fact.currency=d.currency
    LEFT JOIN failed_request_cost_adjustment_items item ON item.request_id=fact.request_id AND item.tenant_id=fact.tenant_id
   GROUP BY d.tenant_id,d.key_id,d.day_bucket,d.model,d.protocol,d.status_class,d.error_code,d.upstream_account_id,d.model_route_id,d.service_tier,d.currency
)
UPDATE usage_analysis_daily actual SET cost_micros=expected.cost_micros FROM expected
 WHERE actual.tenant_id=expected.tenant_id AND actual.key_id=expected.key_id AND actual.day_bucket=expected.day_bucket AND actual.source_kind='request'
   AND actual.model=expected.model AND actual.protocol=expected.protocol AND actual.status_class=expected.status_class AND actual.error_code=expected.error_code AND actual.upstream_account_id=expected.upstream_account_id AND actual.model_route_id=expected.model_route_id AND actual.service_tier=expected.service_tier AND actual.currency=expected.currency;

WITH selected_tenant AS MATERIALIZED (
  SELECT id FROM tenants WHERE external_id = :'tenant_external_id'
)
DELETE FROM failed_request_cost_adjustment_daily daily
 WHERE daily.tenant_id = (SELECT id FROM selected_tenant);

INSERT INTO failed_request_cost_adjustment_daily
  (tenant_id, key_id, day_bucket, currency, status_code, adjustment_count,
   refund_micros, rebuilt_at)
SELECT item.tenant_id, item.key_id, item.request_created_at / 86400000,
       item.currency, item.status_code, count(*), sum(item.refund_micros),
       :'now_ms'::bigint
  FROM failed_request_cost_adjustment_items item
 WHERE item.tenant_id = (SELECT id FROM tenants WHERE external_id = :'tenant_external_id')
 GROUP BY item.tenant_id, item.key_id, item.request_created_at / 86400000,
          item.currency, item.status_code;

SELECT json_build_object(
  'outcome', CASE WHEN EXISTS (SELECT 1 FROM tenants WHERE external_id = :'tenant_external_id')
                    THEN 'rebuilt' ELSE 'blocked' END,
  'daily_rows', (SELECT count(*)::text FROM failed_request_cost_adjustment_daily daily
                   WHERE daily.tenant_id = (SELECT id FROM tenants WHERE external_id = :'tenant_external_id'))
);
COMMIT;
