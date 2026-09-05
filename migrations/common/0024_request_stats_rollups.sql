-- Request terminal rows cache the usage fields needed by bounded analytics.  Currency is
-- snapshotted from the key so historical costs are never accidentally combined after a join.
ALTER TABLE request_records ADD COLUMN cached_input_tokens BIGINT NOT NULL DEFAULT 0;
ALTER TABLE request_records ADD COLUMN cache_write_tokens BIGINT NOT NULL DEFAULT 0;
ALTER TABLE request_records ADD COLUMN service_tier TEXT NOT NULL DEFAULT 'default';
ALTER TABLE request_records ADD COLUMN currency TEXT NOT NULL DEFAULT '';

UPDATE request_records
   SET currency = COALESCE(
       (SELECT k.currency FROM key_records k WHERE k.id = request_records.key_id),
       ''
   )
 WHERE currency = '';

CREATE TABLE request_stats_facts (
    request_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    model TEXT NOT NULL,
    protocol TEXT NOT NULL,
    status_class TEXT NOT NULL,
    error_code TEXT NOT NULL,
    upstream_account_id TEXT NOT NULL,
    model_route_id TEXT NOT NULL,
    duration_ms BIGINT NOT NULL,
    input_tokens BIGINT NOT NULL,
    output_tokens BIGINT NOT NULL,
    cached_input_tokens BIGINT NOT NULL DEFAULT 0,
    cache_write_tokens BIGINT NOT NULL DEFAULT 0,
    service_tier TEXT NOT NULL DEFAULT 'default',
    currency TEXT NOT NULL DEFAULT '',
    cost_micros BIGINT NOT NULL
);

CREATE INDEX request_stats_facts_tenant_created_idx
    ON request_stats_facts (tenant_id, created_at, key_id, model, protocol, status_class);

CREATE INDEX request_stats_facts_key_created_idx
    ON request_stats_facts (key_id, created_at, model, protocol, status_class);

-- Global usage analysis fact indexes bound the two incomplete inclusive edge-bucket scans.
CREATE INDEX request_stats_facts_created_idx
    ON request_stats_facts (created_at, tenant_id, key_id);

CREATE INDEX generation_stats_facts_created_idx
    ON generation_stats_facts (created_at, tenant_id, key_id);

CREATE INDEX request_stats_facts_tenant_error_created_idx
    ON request_stats_facts (tenant_id, error_code, created_at)
    WHERE error_code <> '';

CREATE TABLE request_daily_aggregates (
    tenant_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    day_bucket BIGINT NOT NULL,
    model TEXT NOT NULL,
    protocol TEXT NOT NULL,
    status_class TEXT NOT NULL,
    error_code TEXT NOT NULL,
    upstream_account_id TEXT NOT NULL,
    model_route_id TEXT NOT NULL,
    service_tier TEXT NOT NULL DEFAULT 'default',
    currency TEXT NOT NULL DEFAULT '',
    requests BIGINT NOT NULL,
    input_tokens BIGINT NOT NULL,
    output_tokens BIGINT NOT NULL,
    cached_input_tokens BIGINT NOT NULL DEFAULT 0,
    cache_write_tokens BIGINT NOT NULL DEFAULT 0,
    duration_count BIGINT NOT NULL DEFAULT 0,
    duration_sum_ms BIGINT NOT NULL DEFAULT 0,
    cost_micros BIGINT NOT NULL,
    PRIMARY KEY (
        tenant_id,
        key_id,
        day_bucket,
        model,
        protocol,
        status_class,
        error_code,
        upstream_account_id,
        model_route_id,
        service_tier,
        currency
    )
);

CREATE INDEX request_daily_aggregates_tenant_day_idx
    ON request_daily_aggregates (tenant_id, day_bucket, model, protocol, status_class);

CREATE INDEX request_daily_aggregates_key_day_idx
    ON request_daily_aggregates (key_id, day_bucket, model, protocol, status_class);

-- The analysis tables intentionally use the same row shape for token requests and generation
-- jobs. generation rows have zero token counts and expose billed_units as generation_units.
-- duration_bucket_0..11 are mutually exclusive: <=10, <=50, <=100, <=250, <=500,
-- <=1000, <=2500, <=5000, <=10000, <=30000, <=60000, and >60000 milliseconds.
CREATE TABLE usage_analysis_hourly (
    tenant_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    hour_bucket BIGINT NOT NULL,
    source_kind TEXT NOT NULL,
    model TEXT NOT NULL,
    protocol TEXT NOT NULL,
    status_class TEXT NOT NULL,
    error_code TEXT NOT NULL,
    upstream_account_id TEXT NOT NULL,
    model_route_id TEXT NOT NULL,
    service_tier TEXT NOT NULL,
    currency TEXT NOT NULL,
    requests BIGINT NOT NULL,
    input_tokens BIGINT NOT NULL,
    output_tokens BIGINT NOT NULL,
    cached_input_tokens BIGINT NOT NULL,
    cache_write_tokens BIGINT NOT NULL,
    generation_units BIGINT NOT NULL,
    duration_count BIGINT NOT NULL,
    duration_sum_ms BIGINT NOT NULL,
    duration_bucket_0 BIGINT NOT NULL,
    duration_bucket_1 BIGINT NOT NULL,
    duration_bucket_2 BIGINT NOT NULL,
    duration_bucket_3 BIGINT NOT NULL,
    duration_bucket_4 BIGINT NOT NULL,
    duration_bucket_5 BIGINT NOT NULL,
    duration_bucket_6 BIGINT NOT NULL,
    duration_bucket_7 BIGINT NOT NULL,
    duration_bucket_8 BIGINT NOT NULL,
    duration_bucket_9 BIGINT NOT NULL,
    duration_bucket_10 BIGINT NOT NULL,
    duration_bucket_11 BIGINT NOT NULL,
    cost_micros BIGINT NOT NULL,
    PRIMARY KEY (
        tenant_id, key_id, hour_bucket, source_kind, model, protocol, status_class,
        error_code, upstream_account_id, model_route_id, service_tier, currency
    )
);

CREATE INDEX usage_analysis_hourly_tenant_time_idx
    ON usage_analysis_hourly (tenant_id, hour_bucket, key_id, model, protocol, status_class);
CREATE INDEX usage_analysis_hourly_key_time_idx
    ON usage_analysis_hourly (key_id, hour_bucket, model, protocol, status_class);
CREATE INDEX usage_analysis_hourly_time_idx
    ON usage_analysis_hourly (hour_bucket, tenant_id);
CREATE INDEX usage_analysis_hourly_tenant_upstream_time_idx
    ON usage_analysis_hourly (tenant_id, upstream_account_id, hour_bucket)
    WHERE upstream_account_id <> '';

CREATE TABLE usage_analysis_daily (
    tenant_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    day_bucket BIGINT NOT NULL,
    source_kind TEXT NOT NULL,
    model TEXT NOT NULL,
    protocol TEXT NOT NULL,
    status_class TEXT NOT NULL,
    error_code TEXT NOT NULL,
    upstream_account_id TEXT NOT NULL,
    model_route_id TEXT NOT NULL,
    service_tier TEXT NOT NULL,
    currency TEXT NOT NULL,
    requests BIGINT NOT NULL,
    input_tokens BIGINT NOT NULL,
    output_tokens BIGINT NOT NULL,
    cached_input_tokens BIGINT NOT NULL,
    cache_write_tokens BIGINT NOT NULL,
    generation_units BIGINT NOT NULL,
    duration_count BIGINT NOT NULL,
    duration_sum_ms BIGINT NOT NULL,
    duration_bucket_0 BIGINT NOT NULL,
    duration_bucket_1 BIGINT NOT NULL,
    duration_bucket_2 BIGINT NOT NULL,
    duration_bucket_3 BIGINT NOT NULL,
    duration_bucket_4 BIGINT NOT NULL,
    duration_bucket_5 BIGINT NOT NULL,
    duration_bucket_6 BIGINT NOT NULL,
    duration_bucket_7 BIGINT NOT NULL,
    duration_bucket_8 BIGINT NOT NULL,
    duration_bucket_9 BIGINT NOT NULL,
    duration_bucket_10 BIGINT NOT NULL,
    duration_bucket_11 BIGINT NOT NULL,
    cost_micros BIGINT NOT NULL,
    PRIMARY KEY (
        tenant_id, key_id, day_bucket, source_kind, model, protocol, status_class,
        error_code, upstream_account_id, model_route_id, service_tier, currency
    )
);

CREATE INDEX usage_analysis_daily_tenant_time_idx
    ON usage_analysis_daily (tenant_id, day_bucket, key_id, model, protocol, status_class);
CREATE INDEX usage_analysis_daily_key_time_idx
    ON usage_analysis_daily (key_id, day_bucket, model, protocol, status_class);
CREATE INDEX usage_analysis_daily_time_idx
    ON usage_analysis_daily (day_bucket, tenant_id);
CREATE INDEX usage_analysis_daily_tenant_upstream_time_idx
    ON usage_analysis_daily (tenant_id, upstream_account_id, day_bucket)
    WHERE upstream_account_id <> '';

INSERT INTO request_stats_facts (
    request_id, tenant_id, key_id, created_at, model, protocol, status_class, error_code,
    upstream_account_id, model_route_id, duration_ms, input_tokens, output_tokens,
    cached_input_tokens, cache_write_tokens, service_tier, currency, cost_micros
)
SELECT id,
       tenant_id,
       key_id,
       created_at,
       model,
       protocol,
       CASE WHEN status_code BETWEEN 200 AND 399 THEN 'success' ELSE 'failure' END,
       COALESCE(error_code, ''),
       COALESCE(upstream_account_id, ''),
       COALESCE(model_route_id, ''),
       COALESCE(duration_ms, 0),
       input_tokens,
       output_tokens,
       cached_input_tokens,
       cache_write_tokens,
       service_tier,
       currency,
       cost_micros
FROM request_records
WHERE completed_at IS NOT NULL
  AND status_code IS NOT NULL
ON CONFLICT (request_id) DO NOTHING;

INSERT INTO request_daily_aggregates (
    tenant_id, key_id, day_bucket, model, protocol, status_class, error_code,
    upstream_account_id, model_route_id, service_tier, currency, requests,
    input_tokens, output_tokens, cached_input_tokens, cache_write_tokens,
    duration_count, duration_sum_ms, cost_micros
)
SELECT tenant_id,
       key_id,
       created_at / 86400000,
       model,
       protocol,
       status_class,
       error_code,
       upstream_account_id,
       model_route_id,
       service_tier,
       currency,
       COUNT(*),
       COALESCE(SUM(input_tokens), 0),
       COALESCE(SUM(output_tokens), 0),
       COALESCE(SUM(cached_input_tokens), 0),
       COALESCE(SUM(cache_write_tokens), 0),
       COUNT(*),
       COALESCE(SUM(duration_ms), 0),
       COALESCE(SUM(cost_micros), 0)
FROM request_stats_facts
GROUP BY tenant_id, key_id, created_at / 86400000, model, protocol, status_class,
         error_code, upstream_account_id, model_route_id, service_tier, currency
ON CONFLICT (
    tenant_id, key_id, day_bucket, model, protocol, status_class, error_code,
    upstream_account_id, model_route_id, service_tier, currency
) DO NOTHING;

INSERT INTO usage_analysis_hourly (
    tenant_id, key_id, hour_bucket, source_kind, model, protocol, status_class,
    error_code, upstream_account_id, model_route_id, service_tier, currency, requests,
    input_tokens, output_tokens, cached_input_tokens, cache_write_tokens, generation_units,
    duration_count, duration_sum_ms, duration_bucket_0, duration_bucket_1,
    duration_bucket_2, duration_bucket_3, duration_bucket_4, duration_bucket_5,
    duration_bucket_6, duration_bucket_7, duration_bucket_8, duration_bucket_9,
    duration_bucket_10, duration_bucket_11, cost_micros
)
SELECT tenant_id, key_id, created_at / 3600000, 'request', model,
       CASE
           WHEN protocol = 'anthropic' OR protocol LIKE 'anthropic-%' THEN 'anthropic'
           WHEN protocol = 'openai-image' THEN 'openai-image'
           ELSE 'openai'
       END,
       status_class, error_code, upstream_account_id, model_route_id, service_tier, currency,
       COUNT(*), COALESCE(SUM(CASE
           WHEN input_tokens >= cached_input_tokens + cache_write_tokens
           THEN input_tokens - cached_input_tokens - cache_write_tokens ELSE 0 END), 0),
       COALESCE(SUM(output_tokens), 0),
       COALESCE(SUM(cached_input_tokens), 0), COALESCE(SUM(cache_write_tokens), 0), 0,
       COUNT(*), COALESCE(SUM(duration_ms), 0),
       COALESCE(SUM(CASE WHEN duration_ms <= 10 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN duration_ms > 10 AND duration_ms <= 50 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN duration_ms > 50 AND duration_ms <= 100 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN duration_ms > 100 AND duration_ms <= 250 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN duration_ms > 250 AND duration_ms <= 500 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN duration_ms > 500 AND duration_ms <= 1000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN duration_ms > 1000 AND duration_ms <= 2500 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN duration_ms > 2500 AND duration_ms <= 5000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN duration_ms > 5000 AND duration_ms <= 10000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN duration_ms > 10000 AND duration_ms <= 30000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN duration_ms > 30000 AND duration_ms <= 60000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN duration_ms > 60000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(cost_micros), 0)
FROM request_stats_facts
GROUP BY tenant_id, key_id, created_at / 3600000, model,
         CASE
             WHEN protocol = 'anthropic' OR protocol LIKE 'anthropic-%' THEN 'anthropic'
             WHEN protocol = 'openai-image' THEN 'openai-image'
             ELSE 'openai'
         END,
         status_class, error_code, upstream_account_id, model_route_id, service_tier, currency;

INSERT INTO usage_analysis_hourly (
    tenant_id, key_id, hour_bucket, source_kind, model, protocol, status_class,
    error_code, upstream_account_id, model_route_id, service_tier, currency, requests,
    input_tokens, output_tokens, cached_input_tokens, cache_write_tokens, generation_units,
    duration_count, duration_sum_ms, duration_bucket_0, duration_bucket_1,
    duration_bucket_2, duration_bucket_3, duration_bucket_4, duration_bucket_5,
    duration_bucket_6, duration_bucket_7, duration_bucket_8, duration_bucket_9,
    duration_bucket_10, duration_bucket_11, cost_micros
)
SELECT g.tenant_id, g.key_id, g.created_at / 3600000, 'generation', g.model, 'generation',
       g.status_class, g.error_code, g.upstream_account_id, '', 'default', k.currency,
       COUNT(*), 0, 0, 0, 0, COALESCE(SUM(g.billed_units), 0), COUNT(*),
       COALESCE(SUM(g.duration_ms), 0),
       COALESCE(SUM(CASE WHEN g.duration_ms <= 10 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN g.duration_ms > 10 AND g.duration_ms <= 50 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN g.duration_ms > 50 AND g.duration_ms <= 100 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN g.duration_ms > 100 AND g.duration_ms <= 250 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN g.duration_ms > 250 AND g.duration_ms <= 500 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN g.duration_ms > 500 AND g.duration_ms <= 1000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN g.duration_ms > 1000 AND g.duration_ms <= 2500 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN g.duration_ms > 2500 AND g.duration_ms <= 5000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN g.duration_ms > 5000 AND g.duration_ms <= 10000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN g.duration_ms > 10000 AND g.duration_ms <= 30000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN g.duration_ms > 30000 AND g.duration_ms <= 60000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN g.duration_ms > 60000 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(g.cost_micros), 0)
FROM generation_stats_facts g
JOIN key_records k ON k.id = g.key_id
GROUP BY g.tenant_id, g.key_id, g.created_at / 3600000, g.model, g.status_class,
         g.error_code, g.upstream_account_id, k.currency;

-- Daily analysis is derived from the compact hourly rollup, never from request_records.
INSERT INTO usage_analysis_daily (
    tenant_id, key_id, day_bucket, source_kind, model, protocol, status_class,
    error_code, upstream_account_id, model_route_id, service_tier, currency, requests,
    input_tokens, output_tokens, cached_input_tokens, cache_write_tokens, generation_units,
    duration_count, duration_sum_ms, duration_bucket_0, duration_bucket_1,
    duration_bucket_2, duration_bucket_3, duration_bucket_4, duration_bucket_5,
    duration_bucket_6, duration_bucket_7, duration_bucket_8, duration_bucket_9,
    duration_bucket_10, duration_bucket_11, cost_micros
)
SELECT tenant_id, key_id, hour_bucket / 24, source_kind, model, protocol, status_class,
       error_code, upstream_account_id, model_route_id, service_tier, currency,
       COALESCE(SUM(requests), 0), COALESCE(SUM(input_tokens), 0),
       COALESCE(SUM(output_tokens), 0), COALESCE(SUM(cached_input_tokens), 0),
       COALESCE(SUM(cache_write_tokens), 0), COALESCE(SUM(generation_units), 0),
       COALESCE(SUM(duration_count), 0), COALESCE(SUM(duration_sum_ms), 0),
       COALESCE(SUM(duration_bucket_0), 0), COALESCE(SUM(duration_bucket_1), 0),
       COALESCE(SUM(duration_bucket_2), 0), COALESCE(SUM(duration_bucket_3), 0),
       COALESCE(SUM(duration_bucket_4), 0), COALESCE(SUM(duration_bucket_5), 0),
       COALESCE(SUM(duration_bucket_6), 0), COALESCE(SUM(duration_bucket_7), 0),
       COALESCE(SUM(duration_bucket_8), 0), COALESCE(SUM(duration_bucket_9), 0),
       COALESCE(SUM(duration_bucket_10), 0), COALESCE(SUM(duration_bucket_11), 0),
       COALESCE(SUM(cost_micros), 0)
FROM usage_analysis_hourly
GROUP BY tenant_id, key_id, hour_bucket / 24, source_kind, model, protocol, status_class,
         error_code, upstream_account_id, model_route_id, service_tier, currency;
