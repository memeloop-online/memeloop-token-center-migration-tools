DELETE FROM usage_daily_aggregates a
 WHERE a.key_id IN (
   SELECT k.id FROM key_records k JOIN tenants t ON t.id = k.tenant_id
    WHERE t.external_id = :'tenant_external_id'
 ) AND EXISTS (SELECT 1 FROM cpamp_correction_candidates);
INSERT INTO usage_daily_aggregates
  (key_id, day_bucket, model, status_class, error_code, requests,
   input_tokens, output_tokens, cost_micros)
SELECT f.key_id, f.created_at / 86400000, f.model, f.status_class,
       f.error_code, COUNT(*), COALESCE(SUM(f.input_tokens), 0),
       COALESCE(SUM(f.output_tokens), 0), COALESCE(SUM(f.cost_micros), 0)
  FROM request_stats_facts f JOIN tenants t ON t.id = f.tenant_id
 WHERE t.external_id = :'tenant_external_id'
   AND EXISTS (SELECT 1 FROM cpamp_correction_candidates)
 GROUP BY f.key_id, f.created_at / 86400000, f.model, f.status_class, f.error_code;

DELETE FROM request_daily_aggregates a
 WHERE a.tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id')
   AND EXISTS (SELECT 1 FROM cpamp_correction_candidates);
INSERT INTO request_daily_aggregates
  (tenant_id, key_id, day_bucket, model, protocol, status_class, error_code,
   upstream_account_id, model_route_id, service_tier, currency, requests,
   input_tokens, output_tokens, cached_input_tokens, cache_write_tokens,
   duration_count, duration_sum_ms, cost_micros)
SELECT f.tenant_id, f.key_id, f.created_at / 86400000, f.model, f.protocol,
       f.status_class, f.error_code, f.upstream_account_id, f.model_route_id,
       f.service_tier, f.currency, COUNT(*), COALESCE(SUM(f.input_tokens), 0),
       COALESCE(SUM(f.output_tokens), 0), COALESCE(SUM(f.cached_input_tokens), 0),
       COALESCE(SUM(f.cache_write_tokens), 0), COUNT(*),
       COALESCE(SUM(f.duration_ms), 0), COALESCE(SUM(f.cost_micros), 0)
  FROM request_stats_facts f JOIN tenants t ON t.id = f.tenant_id
 WHERE t.external_id = :'tenant_external_id'
   AND EXISTS (SELECT 1 FROM cpamp_correction_candidates)
 GROUP BY f.tenant_id, f.key_id, f.created_at / 86400000, f.model, f.protocol,
          f.status_class, f.error_code, f.upstream_account_id, f.model_route_id,
          f.service_tier, f.currency;

DELETE FROM usage_analysis_hourly a
 WHERE a.tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id')
   AND a.source_kind = 'request'
   AND EXISTS (SELECT 1 FROM cpamp_correction_candidates);
INSERT INTO usage_analysis_hourly
  (tenant_id, key_id, hour_bucket, source_kind, model, protocol, status_class,
   error_code, upstream_account_id, model_route_id, service_tier, currency,
   requests, input_tokens, output_tokens, cached_input_tokens,
   cache_write_tokens, generation_units, duration_count, duration_sum_ms,
   duration_bucket_0, duration_bucket_1, duration_bucket_2, duration_bucket_3,
   duration_bucket_4, duration_bucket_5, duration_bucket_6, duration_bucket_7,
   duration_bucket_8, duration_bucket_9, duration_bucket_10,
   duration_bucket_11, cost_micros)
SELECT f.tenant_id, f.key_id, f.created_at / 3600000, 'request', f.model,
       CASE WHEN f.protocol = 'anthropic' OR f.protocol LIKE 'anthropic-%' THEN 'anthropic'
            WHEN f.protocol = 'openai-image' THEN 'openai-image' ELSE 'openai' END,
       f.status_class, f.error_code, f.upstream_account_id, f.model_route_id,
       f.service_tier, f.currency, COUNT(*),
       COALESCE(SUM(CASE WHEN f.input_tokens >= f.cached_input_tokens + f.cache_write_tokens
                         THEN f.input_tokens - f.cached_input_tokens - f.cache_write_tokens
                         ELSE 0 END), 0),
       COALESCE(SUM(f.output_tokens), 0), COALESCE(SUM(f.cached_input_tokens), 0),
       COALESCE(SUM(f.cache_write_tokens), 0), 0, COUNT(*),
       COALESCE(SUM(f.duration_ms), 0),
       COALESCE(SUM(CASE WHEN f.duration_ms <= 10 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN f.duration_ms > 10 AND f.duration_ms <= 50 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN f.duration_ms > 50 AND f.duration_ms <= 100 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN f.duration_ms > 100 AND f.duration_ms <= 250 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN f.duration_ms > 250 AND f.duration_ms <= 500 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN f.duration_ms > 500 AND f.duration_ms <= 1000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN f.duration_ms > 1000 AND f.duration_ms <= 2500 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN f.duration_ms > 2500 AND f.duration_ms <= 5000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN f.duration_ms > 5000 AND f.duration_ms <= 10000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN f.duration_ms > 10000 AND f.duration_ms <= 30000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN f.duration_ms > 30000 AND f.duration_ms <= 60000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN f.duration_ms > 60000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(f.cost_micros), 0)
  FROM request_stats_facts f JOIN tenants t ON t.id = f.tenant_id
 WHERE t.external_id = :'tenant_external_id'
   AND EXISTS (SELECT 1 FROM cpamp_correction_candidates)
 GROUP BY f.tenant_id, f.key_id, f.created_at / 3600000, f.model,
          CASE WHEN f.protocol = 'anthropic' OR f.protocol LIKE 'anthropic-%' THEN 'anthropic'
               WHEN f.protocol = 'openai-image' THEN 'openai-image' ELSE 'openai' END,
          f.status_class, f.error_code, f.upstream_account_id, f.model_route_id,
          f.service_tier, f.currency;

DELETE FROM usage_analysis_daily a
 WHERE a.tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id')
   AND a.source_kind = 'request'
   AND EXISTS (SELECT 1 FROM cpamp_correction_candidates);
INSERT INTO usage_analysis_daily
  (tenant_id, key_id, day_bucket, source_kind, model, protocol, status_class,
   error_code, upstream_account_id, model_route_id, service_tier, currency,
   requests, input_tokens, output_tokens, cached_input_tokens,
   cache_write_tokens, generation_units, duration_count, duration_sum_ms,
   duration_bucket_0, duration_bucket_1, duration_bucket_2, duration_bucket_3,
   duration_bucket_4, duration_bucket_5, duration_bucket_6, duration_bucket_7,
   duration_bucket_8, duration_bucket_9, duration_bucket_10,
   duration_bucket_11, cost_micros)
SELECT tenant_id, key_id, hour_bucket / 24, source_kind, model, protocol,
       status_class, error_code, upstream_account_id, model_route_id,
       service_tier, currency, COALESCE(SUM(requests), 0),
       COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0),
       COALESCE(SUM(cached_input_tokens), 0), COALESCE(SUM(cache_write_tokens), 0),
       0, COALESCE(SUM(duration_count), 0), COALESCE(SUM(duration_sum_ms), 0),
       COALESCE(SUM(duration_bucket_0), 0), COALESCE(SUM(duration_bucket_1), 0),
       COALESCE(SUM(duration_bucket_2), 0), COALESCE(SUM(duration_bucket_3), 0),
       COALESCE(SUM(duration_bucket_4), 0), COALESCE(SUM(duration_bucket_5), 0),
       COALESCE(SUM(duration_bucket_6), 0), COALESCE(SUM(duration_bucket_7), 0),
       COALESCE(SUM(duration_bucket_8), 0), COALESCE(SUM(duration_bucket_9), 0),
       COALESCE(SUM(duration_bucket_10), 0), COALESCE(SUM(duration_bucket_11), 0),
       COALESCE(SUM(cost_micros), 0)
  FROM usage_analysis_hourly h
 WHERE h.tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id')
   AND h.source_kind = 'request'
   AND EXISTS (SELECT 1 FROM cpamp_correction_candidates)
 GROUP BY tenant_id, key_id, hour_bucket / 24, source_kind, model, protocol,
          status_class, error_code, upstream_account_id, model_route_id,
          service_tier, currency;

DELETE FROM session_usage_totals a
 WHERE a.tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id')
   AND EXISTS (SELECT 1 FROM cpamp_correction_candidates);
DELETE FROM session_usage_hourly a
 WHERE a.tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id')
   AND EXISTS (SELECT 1 FROM cpamp_correction_candidates);
DELETE FROM session_usage_daily a
 WHERE a.tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id')
   AND EXISTS (SELECT 1 FROM cpamp_correction_candidates);

INSERT INTO session_usage_totals
  (tenant_id, key_id, session_id, currency, last_activity_at, requests, errors,
   input_tokens, output_tokens, cached_input_tokens, cache_write_tokens,
   generation_units, duration_count, duration_sum_ms, cost_micros)
SELECT f.tenant_id, f.key_id, COALESCE(NULLIF(f.session_id, ''), 'unlinked:' || f.key_id),
       f.currency, MAX(f.created_at), COUNT(*),
       COALESCE(SUM(CASE WHEN f.status_class = 'failure' THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN f.input_tokens >= f.cached_input_tokens + f.cache_write_tokens
                         THEN f.input_tokens - f.cached_input_tokens - f.cache_write_tokens
                         ELSE 0 END), 0),
       COALESCE(SUM(f.output_tokens), 0), COALESCE(SUM(f.cached_input_tokens), 0),
       COALESCE(SUM(f.cache_write_tokens), 0), 0, COUNT(*),
       COALESCE(SUM(f.duration_ms), 0), COALESCE(SUM(f.cost_micros), 0)
  FROM request_stats_facts f JOIN tenants t ON t.id = f.tenant_id
 WHERE t.external_id = :'tenant_external_id'
   AND EXISTS (SELECT 1 FROM cpamp_correction_candidates)
 GROUP BY f.tenant_id, f.key_id,
          COALESCE(NULLIF(f.session_id, ''), 'unlinked:' || f.key_id), f.currency;
INSERT INTO session_usage_totals
  (tenant_id, key_id, session_id, currency, last_activity_at, requests, errors,
   input_tokens, output_tokens, cached_input_tokens, cache_write_tokens,
   generation_units, duration_count, duration_sum_ms, cost_micros)
SELECT g.tenant_id, g.key_id, 'unlinked:' || g.key_id, g.currency,
       MAX(g.created_at), COUNT(*),
       COALESCE(SUM(CASE WHEN g.status_class = 'failure' THEN 1 ELSE 0 END), 0),
       0, 0, 0, 0, COALESCE(SUM(g.billed_units), 0), COUNT(*),
       COALESCE(SUM(g.duration_ms), 0), COALESCE(SUM(g.cost_micros), 0)
  FROM generation_stats_facts g JOIN tenants t ON t.id = g.tenant_id
 WHERE t.external_id = :'tenant_external_id'
   AND EXISTS (SELECT 1 FROM cpamp_correction_candidates)
 GROUP BY g.tenant_id, g.key_id, g.currency
ON CONFLICT (tenant_id, key_id, session_id, currency) DO UPDATE SET
  last_activity_at = GREATEST(session_usage_totals.last_activity_at, excluded.last_activity_at),
  requests = session_usage_totals.requests + excluded.requests,
  errors = session_usage_totals.errors + excluded.errors,
  generation_units = session_usage_totals.generation_units + excluded.generation_units,
  duration_count = session_usage_totals.duration_count + excluded.duration_count,
  duration_sum_ms = session_usage_totals.duration_sum_ms + excluded.duration_sum_ms,
  cost_micros = session_usage_totals.cost_micros + excluded.cost_micros;

INSERT INTO session_usage_hourly
  (tenant_id, key_id, session_id, hour_bucket, model, protocol, status_class,
   error_code, upstream_account_id, model_route_id, currency, requests,
   input_tokens, output_tokens, cached_input_tokens, cache_write_tokens,
   generation_units, duration_count, duration_sum_ms, cost_micros)
SELECT f.tenant_id, f.key_id, COALESCE(NULLIF(f.session_id, ''), 'unlinked:' || f.key_id),
       f.created_at / 3600000, f.model,
       CASE WHEN f.protocol = 'anthropic' OR f.protocol LIKE 'anthropic-%' THEN 'anthropic'
            WHEN f.protocol = 'openai-image' THEN 'openai-image' ELSE 'openai' END,
       f.status_class, f.error_code, f.upstream_account_id, f.model_route_id,
       f.currency, COUNT(*),
       COALESCE(SUM(CASE WHEN f.input_tokens >= f.cached_input_tokens + f.cache_write_tokens
                         THEN f.input_tokens - f.cached_input_tokens - f.cache_write_tokens
                         ELSE 0 END), 0),
       COALESCE(SUM(f.output_tokens), 0), COALESCE(SUM(f.cached_input_tokens), 0),
       COALESCE(SUM(f.cache_write_tokens), 0), 0, COUNT(*),
       COALESCE(SUM(f.duration_ms), 0), COALESCE(SUM(f.cost_micros), 0)
  FROM request_stats_facts f JOIN tenants t ON t.id = f.tenant_id
 WHERE t.external_id = :'tenant_external_id'
   AND EXISTS (SELECT 1 FROM cpamp_correction_candidates)
 GROUP BY f.tenant_id, f.key_id,
          COALESCE(NULLIF(f.session_id, ''), 'unlinked:' || f.key_id),
          f.created_at / 3600000, f.model,
          CASE WHEN f.protocol = 'anthropic' OR f.protocol LIKE 'anthropic-%' THEN 'anthropic'
               WHEN f.protocol = 'openai-image' THEN 'openai-image' ELSE 'openai' END,
          f.status_class, f.error_code, f.upstream_account_id, f.model_route_id, f.currency;
INSERT INTO session_usage_hourly
  (tenant_id, key_id, session_id, hour_bucket, model, protocol, status_class,
   error_code, upstream_account_id, model_route_id, currency, requests,
   input_tokens, output_tokens, cached_input_tokens, cache_write_tokens,
   generation_units, duration_count, duration_sum_ms, cost_micros)
SELECT g.tenant_id, g.key_id, 'unlinked:' || g.key_id, g.created_at / 3600000,
       g.model, 'generation', g.status_class, g.error_code, g.upstream_account_id,
       g.model_route_id, g.currency, COUNT(*), 0, 0, 0, 0,
       COALESCE(SUM(g.billed_units), 0), COUNT(*),
       COALESCE(SUM(g.duration_ms), 0), COALESCE(SUM(g.cost_micros), 0)
  FROM generation_stats_facts g JOIN tenants t ON t.id = g.tenant_id
 WHERE t.external_id = :'tenant_external_id'
   AND EXISTS (SELECT 1 FROM cpamp_correction_candidates)
 GROUP BY g.tenant_id, g.key_id, g.created_at / 3600000, g.model,
          g.status_class, g.error_code, g.upstream_account_id, g.model_route_id, g.currency;

INSERT INTO session_usage_daily
  (tenant_id, key_id, session_id, day_bucket, model, protocol, status_class,
   error_code, upstream_account_id, model_route_id, currency, requests,
   input_tokens, output_tokens, cached_input_tokens, cache_write_tokens,
   generation_units, duration_count, duration_sum_ms, cost_micros)
SELECT tenant_id, key_id, session_id, hour_bucket / 24, model, protocol,
       status_class, error_code, upstream_account_id, model_route_id, currency,
       COALESCE(SUM(requests), 0), COALESCE(SUM(input_tokens), 0),
       COALESCE(SUM(output_tokens), 0), COALESCE(SUM(cached_input_tokens), 0),
       COALESCE(SUM(cache_write_tokens), 0), COALESCE(SUM(generation_units), 0),
       COALESCE(SUM(duration_count), 0), COALESCE(SUM(duration_sum_ms), 0),
       COALESCE(SUM(cost_micros), 0)
  FROM session_usage_hourly h
 WHERE h.tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id')
   AND EXISTS (SELECT 1 FROM cpamp_correction_candidates)
 GROUP BY tenant_id, key_id, session_id, hour_bucket / 24, model, protocol,
          status_class, error_code, upstream_account_id, model_route_id, currency;

UPDATE cpamp_import_checkpoints checkpoint
   SET correction_revision = 'cpamp-cache-pricing-v2',
       corrected_events = checkpoint.corrected_events +
         (SELECT count(*) FROM cpamp_correction_candidates),
       corrected_at = (extract(epoch from clock_timestamp()) * 1000)::bigint,
       updated_at = (extract(epoch from clock_timestamp()) * 1000)::bigint
 WHERE checkpoint.tenant_external_id = :'tenant_external_id'
   AND checkpoint.source = :'import_source'
   AND EXISTS (SELECT 1 FROM cpamp_correction_candidates);

SELECT count(*) AS corrected_events,
       COALESCE(sum(old_cost_micros), 0) AS old_cost_micros,
       COALESCE(sum(cost_micros), 0) AS new_cost_micros
  FROM cpamp_correction_candidates;

COMMIT;
ANALYZE request_records;
ANALYZE usage_daily_aggregates;
ANALYZE request_stats_facts;
ANALYZE request_daily_aggregates;
ANALYZE usage_analysis_hourly;
ANALYZE usage_analysis_daily;
ANALYZE session_usage_totals;
ANALYZE session_usage_hourly;
ANALYZE session_usage_daily;
