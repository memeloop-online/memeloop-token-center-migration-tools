BEGIN;

CREATE TEMP TABLE cpamp_import_canonical ON COMMIT DROP AS
SELECT DISTINCT ON (event_hash) u.*
  FROM cpamp_import_evaluated u
 ORDER BY event_hash, timestamp_ms DESC, request_id DESC;

-- Once an event hash has durable provenance, the source payload is immutable. Abort the
-- whole transaction before accepting a changed row under an already-imported identity.
CREATE TEMP TABLE cpamp_import_source_conflicts (
  event_hash text,
  invalid boolean NOT NULL CHECK (invalid = false)
) ON COMMIT DROP;
INSERT INTO cpamp_import_source_conflicts (event_hash, invalid)
SELECT u.event_hash, true
  FROM cpamp_import_canonical u
  JOIN tenants t ON t.external_id = :'tenant_external_id'
  JOIN import_request_links l
    ON l.tenant_id = t.id
   AND l.source = :'import_source'
   AND l.external_event_hash = u.event_hash
 WHERE l.source_digest <> '' AND l.source_digest <> u.source_digest;

WITH digest AS (SELECT md5('tenant:' || :'tenant_external_id') AS value)
INSERT INTO tenants (id, external_id, created_at)
SELECT substr(value,1,8)||'-'||substr(value,9,4)||'-5'||substr(value,14,3)||'-a'||substr(value,18,3)||'-'||substr(value,21,12),
       :'tenant_external_id', (extract(epoch from clock_timestamp()) * 1000)::bigint
  FROM digest
ON CONFLICT (external_id) DO NOTHING;

WITH digest AS (SELECT md5('principal:' || :'tenant_external_id' || ':cpamp-import') AS value)
INSERT INTO principals (id, tenant_id, external_id, created_at)
SELECT substr(value,1,8)||'-'||substr(value,9,4)||'-5'||substr(value,14,3)||'-a'||substr(value,18,3)||'-'||substr(value,21,12),
       t.id, 'cpamp-import', (extract(epoch from clock_timestamp()) * 1000)::bigint
  FROM digest CROSS JOIN tenants t WHERE t.external_id = :'tenant_external_id'
ON CONFLICT (tenant_id, external_id) DO NOTHING;

INSERT INTO cpamp_import_identities (api_key_hash, key_id, account_id, alias)
SELECT h.api_key_hash,
       substr(k.value,1,8)||'-'||substr(k.value,9,4)||'-5'||substr(k.value,14,3)||'-a'||substr(k.value,18,3)||'-'||substr(k.value,21,12),
       substr(a.value,1,8)||'-'||substr(a.value,9,4)||'-5'||substr(a.value,14,3)||'-a'||substr(a.value,18,3)||'-'||substr(a.value,21,12),
       COALESCE(NULLIF(x.alias, ''), 'CPA ' || substr(h.api_key_hash, 1, 8))
  FROM (SELECT api_key_hash FROM cpamp_import_usage UNION SELECT api_key_hash FROM cpamp_import_aliases) h
  LEFT JOIN cpamp_import_aliases x USING (api_key_hash)
  CROSS JOIN LATERAL (SELECT md5('key:' || :'tenant_external_id' || ':' || h.api_key_hash) AS value) k
  CROSS JOIN LATERAL (SELECT md5('account:' || :'tenant_external_id' || ':' || h.api_key_hash) AS value) a
 WHERE length(h.api_key_hash) = 64;

INSERT INTO credit_accounts
  (id, tenant_id, principal_id, currency, available_micros, reserved_micros, created_at, updated_at)
SELECT i.account_id, t.id, p.id, 'USD', 0, 0,
       (extract(epoch from clock_timestamp()) * 1000)::bigint,
       (extract(epoch from clock_timestamp()) * 1000)::bigint
  FROM cpamp_import_identities i
  JOIN tenants t ON t.external_id = :'tenant_external_id'
  JOIN principals p ON p.tenant_id = t.id AND p.external_id = 'cpamp-import'
ON CONFLICT (id) DO NOTHING;

-- Schema v22 introduced this rollup after credit_accounts already existed.
-- Keep imported and replayed identities grantable even when an older import
-- created the account before the rollup row. Derive from durable usage ledger
-- entries so repairing a non-empty legacy account never makes an old grant
-- incorrectly reversible.
INSERT INTO account_usage_state
  (account_id, settled_lifetime_micros, updated_at)
SELECT i.account_id,
       COALESCE((
         SELECT sum(CASE WHEN l.amount_micros < 0 THEN -l.amount_micros ELSE 0 END)
           FROM ledger_entries l
          WHERE l.account_id = i.account_id AND l.kind = 'usage'
       ), 0),
       (extract(epoch from clock_timestamp()) * 1000)::bigint
  FROM cpamp_import_identities i
  JOIN credit_accounts a ON a.id = i.account_id
ON CONFLICT (account_id) DO NOTHING;

INSERT INTO key_records
  (id, tenant_id, principal_id, account_id, alias, currency, policy_json,
   status, credential_generation, created_at, updated_at)
SELECT i.key_id, t.id, p.id, i.account_id, i.alias, 'USD',
       '{"requests_per_minute":60,"tokens_per_minute":1000000,"max_concurrency":4,"daily_budget":null,"weekly_budget":null,"lifetime_budget":null}',
       'active', 0,
       (extract(epoch from clock_timestamp()) * 1000)::bigint,
       (extract(epoch from clock_timestamp()) * 1000)::bigint
  FROM cpamp_import_identities i
  JOIN tenants t ON t.external_id = :'tenant_external_id'
  JOIN principals p ON p.tenant_id = t.id AND p.external_id = 'cpamp-import'
ON CONFLICT (id) DO UPDATE SET alias = excluded.alias, updated_at = excluded.updated_at
  WHERE key_records.alias IS DISTINCT FROM excluded.alias;

INSERT INTO cpamp_import_new_requests
  (id, tenant_id, key_id, created_at, completed_at, protocol, model,
   status_code, duration_ms, input_tokens, output_tokens, cost_micros,
   error_code, request_object, response_object, reservation_id,
   cached_input_tokens, cache_write_tokens, service_tier, currency)
SELECT substr(r.value,1,8)||'-'||substr(r.value,9,4)||'-5'||substr(r.value,14,3)||'-a'||substr(r.value,18,3)||'-'||substr(r.value,21,12),
       t.id, i.key_id, u.timestamp_ms,
       u.timestamp_ms + GREATEST(COALESCE(u.latency_ms, 0), 0),
       COALESCE(NULLIF(u.provider, ''), 'openai'), COALESCE(NULLIF(u.model, ''), '-'),
       CASE WHEN u.failed = 0 THEN 200
            WHEN u.fail_status_code BETWEEN 400 AND 599 THEN u.fail_status_code
            ELSE 502 END,
       GREATEST(COALESCE(u.latency_ms, 0), 0), u.normalized_total_input_tokens,
       GREATEST(COALESCE(u.output_tokens, 0), 0),
       u.cost_micros,
       CASE WHEN u.failed <> 0 THEN
            CASE WHEN u.fail_status_code BETWEEN 400 AND 599
                 THEN 'http_' || u.fail_status_code::text
                 ELSE 'upstream_error' END END,
       'gap://cpamp/' || u.event_hash || '/request',
       'gap://cpamp/' || u.event_hash || '/response',
       'cpamp-import:' || u.event_hash,
       u.normalized_cache_read_tokens, u.normalized_cache_creation_tokens,
       u.applied_service_tier, 'USD'
  FROM cpamp_import_canonical u
  JOIN cpamp_import_identities i USING (api_key_hash)
  JOIN tenants t ON t.external_id = :'tenant_external_id'
  CROSS JOIN LATERAL (SELECT md5('request:cpamp:' ||
    CASE WHEN :'tenant_external_id' = 'cpa-dogfood-import' AND :'import_source' = 'cpamp-usage-events-v1'
         THEN '' ELSE :'tenant_external_id' || ':' || :'import_source' || ':' END || u.event_hash) AS value) r
;

CREATE TEMP TABLE cpamp_import_claimed_requests (
  id text PRIMARY KEY
) ON COMMIT DROP;
WITH claimed AS (
  INSERT INTO request_record_locators (id, created_at, tenant_id, key_id)
  SELECT id, created_at, tenant_id, key_id
    FROM cpamp_import_new_requests
  ON CONFLICT (id) DO NOTHING
  RETURNING id
)
INSERT INTO cpamp_import_claimed_requests (id)
SELECT id FROM claimed;

-- A replay is accepted only when the stable routing coordinates are identical
-- and the pointed-to leaf row exists.  The CHECK makes every other collision
-- abort the surrounding transaction instead of silently selecting one row.
CREATE TEMP TABLE cpamp_import_locator_conflicts (
  id text,
  invalid boolean NOT NULL CHECK (invalid = false)
) ON COMMIT DROP;
INSERT INTO cpamp_import_locator_conflicts (id, invalid)
SELECT n.id, true
  FROM cpamp_import_new_requests n
  JOIN request_record_locators l ON l.id = n.id
 WHERE l.created_at <> n.created_at
    OR l.tenant_id <> n.tenant_id
    OR l.key_id <> n.key_id
    OR (
      NOT EXISTS (SELECT 1 FROM cpamp_import_claimed_requests c WHERE c.id = n.id)
      AND NOT EXISTS (
        SELECT 1 FROM request_records r
         WHERE r.id = l.id AND r.created_at = l.created_at
           AND r.tenant_id = l.tenant_id AND r.key_id = l.key_id
      )
    );

-- Only the transaction that won the locator claim may create the partitioned
-- leaf and contribute aggregates.  Exact-coordinate replays remain no-ops.
DELETE FROM cpamp_import_new_requests n
 WHERE NOT EXISTS (SELECT 1 FROM cpamp_import_claimed_requests c WHERE c.id = n.id);

INSERT INTO request_records SELECT * FROM cpamp_import_new_requests;

INSERT INTO request_stats_facts
  (request_id, tenant_id, key_id, created_at, model, protocol, status_class,
   error_code, upstream_account_id, model_route_id, duration_ms,
   input_tokens, output_tokens, cached_input_tokens, cache_write_tokens,
   service_tier, currency, cost_micros, session_id)
SELECT id, tenant_id, key_id, created_at, model, protocol,
       CASE WHEN status_code BETWEEN 200 AND 399 THEN 'success' ELSE 'failure' END,
       COALESCE(error_code, ''), COALESCE(upstream_account_id, ''),
       COALESCE(model_route_id, ''), COALESCE(duration_ms, 0),
       input_tokens, output_tokens, cached_input_tokens, cache_write_tokens,
       service_tier, currency, cost_micros, 'unlinked:' || key_id
  FROM cpamp_import_new_requests
 WHERE completed_at IS NOT NULL AND status_code IS NOT NULL
ON CONFLICT (request_id) DO NOTHING;

-- All aggregate deltas are derived from the facts whose locator was claimed by this
-- transaction. Exact replays therefore cannot increment any legacy or v24 analysis table.
CREATE TEMP TABLE cpamp_import_new_request_facts ON COMMIT DROP AS
SELECT f.*
  FROM request_stats_facts f
  JOIN cpamp_import_claimed_requests c ON c.id = f.request_id;

INSERT INTO request_daily_aggregates
  (tenant_id, key_id, day_bucket, model, protocol, status_class, error_code,
   upstream_account_id, model_route_id, service_tier, currency, requests,
   input_tokens, output_tokens, cached_input_tokens, cache_write_tokens,
   duration_count, duration_sum_ms, cost_micros)
SELECT tenant_id, key_id, created_at / 86400000, model, protocol,
       status_class, error_code, upstream_account_id, model_route_id,
       service_tier, currency, COUNT(*), COALESCE(SUM(input_tokens), 0),
       COALESCE(SUM(output_tokens), 0), COALESCE(SUM(cached_input_tokens), 0),
       COALESCE(SUM(cache_write_tokens), 0), COUNT(*),
       COALESCE(SUM(duration_ms), 0), COALESCE(SUM(cost_micros), 0)
  FROM cpamp_import_new_request_facts
 GROUP BY tenant_id, key_id, created_at / 86400000, model, protocol,
          status_class, error_code, upstream_account_id, model_route_id,
          service_tier, currency
ON CONFLICT (tenant_id, key_id, day_bucket, model, protocol, status_class,
             error_code, upstream_account_id, model_route_id, service_tier,
             currency) DO UPDATE SET
  requests = request_daily_aggregates.requests + excluded.requests,
  input_tokens = request_daily_aggregates.input_tokens + excluded.input_tokens,
  output_tokens = request_daily_aggregates.output_tokens + excluded.output_tokens,
  cached_input_tokens = request_daily_aggregates.cached_input_tokens + excluded.cached_input_tokens,
  cache_write_tokens = request_daily_aggregates.cache_write_tokens + excluded.cache_write_tokens,
  duration_count = request_daily_aggregates.duration_count + excluded.duration_count,
  duration_sum_ms = request_daily_aggregates.duration_sum_ms + excluded.duration_sum_ms,
  cost_micros = request_daily_aggregates.cost_micros + excluded.cost_micros;

INSERT INTO usage_analysis_hourly
  (tenant_id, key_id, hour_bucket, source_kind, model, protocol, status_class,
   error_code, upstream_account_id, model_route_id, service_tier, currency,
   requests, input_tokens, output_tokens, cached_input_tokens,
   cache_write_tokens, generation_units, duration_count, duration_sum_ms,
   duration_bucket_0, duration_bucket_1, duration_bucket_2, duration_bucket_3,
   duration_bucket_4, duration_bucket_5, duration_bucket_6, duration_bucket_7,
   duration_bucket_8, duration_bucket_9, duration_bucket_10,
   duration_bucket_11, cost_micros)
SELECT tenant_id, key_id, created_at / 3600000, 'request', model,
       CASE WHEN protocol = 'anthropic' OR protocol LIKE 'anthropic-%'
            THEN 'anthropic' WHEN protocol = 'openai-image' THEN 'openai-image'
            ELSE 'openai' END,
       status_class, error_code, upstream_account_id, model_route_id,
       service_tier, currency, COUNT(*),
       COALESCE(SUM(CASE WHEN input_tokens >= cached_input_tokens + cache_write_tokens
                         THEN input_tokens - cached_input_tokens - cache_write_tokens
                         ELSE 0 END), 0),
       COALESCE(SUM(output_tokens), 0), COALESCE(SUM(cached_input_tokens), 0),
       COALESCE(SUM(cache_write_tokens), 0), 0, COUNT(*),
       COALESCE(SUM(duration_ms), 0),
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
  FROM cpamp_import_new_request_facts
 GROUP BY tenant_id, key_id, created_at / 3600000, model,
          CASE WHEN protocol = 'anthropic' OR protocol LIKE 'anthropic-%'
               THEN 'anthropic' WHEN protocol = 'openai-image' THEN 'openai-image'
               ELSE 'openai' END,
          status_class, error_code, upstream_account_id, model_route_id,
          service_tier, currency
ON CONFLICT (tenant_id, key_id, hour_bucket, source_kind, model, protocol,
             status_class, error_code, upstream_account_id, model_route_id,
             service_tier, currency) DO UPDATE SET
  requests = usage_analysis_hourly.requests + excluded.requests,
  input_tokens = usage_analysis_hourly.input_tokens + excluded.input_tokens,
  output_tokens = usage_analysis_hourly.output_tokens + excluded.output_tokens,
  cached_input_tokens = usage_analysis_hourly.cached_input_tokens + excluded.cached_input_tokens,
  cache_write_tokens = usage_analysis_hourly.cache_write_tokens + excluded.cache_write_tokens,
  generation_units = usage_analysis_hourly.generation_units + excluded.generation_units,
  duration_count = usage_analysis_hourly.duration_count + excluded.duration_count,
  duration_sum_ms = usage_analysis_hourly.duration_sum_ms + excluded.duration_sum_ms,
  duration_bucket_0 = usage_analysis_hourly.duration_bucket_0 + excluded.duration_bucket_0,
  duration_bucket_1 = usage_analysis_hourly.duration_bucket_1 + excluded.duration_bucket_1,
  duration_bucket_2 = usage_analysis_hourly.duration_bucket_2 + excluded.duration_bucket_2,
  duration_bucket_3 = usage_analysis_hourly.duration_bucket_3 + excluded.duration_bucket_3,
  duration_bucket_4 = usage_analysis_hourly.duration_bucket_4 + excluded.duration_bucket_4,
  duration_bucket_5 = usage_analysis_hourly.duration_bucket_5 + excluded.duration_bucket_5,
  duration_bucket_6 = usage_analysis_hourly.duration_bucket_6 + excluded.duration_bucket_6,
  duration_bucket_7 = usage_analysis_hourly.duration_bucket_7 + excluded.duration_bucket_7,
  duration_bucket_8 = usage_analysis_hourly.duration_bucket_8 + excluded.duration_bucket_8,
  duration_bucket_9 = usage_analysis_hourly.duration_bucket_9 + excluded.duration_bucket_9,
  duration_bucket_10 = usage_analysis_hourly.duration_bucket_10 + excluded.duration_bucket_10,
  duration_bucket_11 = usage_analysis_hourly.duration_bucket_11 + excluded.duration_bucket_11,
  cost_micros = usage_analysis_hourly.cost_micros + excluded.cost_micros;

INSERT INTO usage_analysis_daily
  (tenant_id, key_id, day_bucket, source_kind, model, protocol, status_class,
   error_code, upstream_account_id, model_route_id, service_tier, currency,
   requests, input_tokens, output_tokens, cached_input_tokens,
   cache_write_tokens, generation_units, duration_count, duration_sum_ms,
   duration_bucket_0, duration_bucket_1, duration_bucket_2, duration_bucket_3,
   duration_bucket_4, duration_bucket_5, duration_bucket_6, duration_bucket_7,
   duration_bucket_8, duration_bucket_9, duration_bucket_10,
   duration_bucket_11, cost_micros)
SELECT tenant_id, key_id, created_at / 86400000, 'request', model,
       CASE WHEN protocol = 'anthropic' OR protocol LIKE 'anthropic-%'
            THEN 'anthropic' WHEN protocol = 'openai-image' THEN 'openai-image'
            ELSE 'openai' END,
       status_class, error_code, upstream_account_id, model_route_id,
       service_tier, currency, COUNT(*),
       COALESCE(SUM(CASE WHEN input_tokens >= cached_input_tokens + cache_write_tokens
                         THEN input_tokens - cached_input_tokens - cache_write_tokens
                         ELSE 0 END), 0),
       COALESCE(SUM(output_tokens), 0), COALESCE(SUM(cached_input_tokens), 0),
       COALESCE(SUM(cache_write_tokens), 0), 0, COUNT(*),
       COALESCE(SUM(duration_ms), 0),
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
  FROM cpamp_import_new_request_facts
 GROUP BY tenant_id, key_id, created_at / 86400000, model,
          CASE WHEN protocol = 'anthropic' OR protocol LIKE 'anthropic-%'
               THEN 'anthropic' WHEN protocol = 'openai-image' THEN 'openai-image'
               ELSE 'openai' END,
          status_class, error_code, upstream_account_id, model_route_id,
          service_tier, currency
ON CONFLICT (tenant_id, key_id, day_bucket, source_kind, model, protocol,
             status_class, error_code, upstream_account_id, model_route_id,
             service_tier, currency) DO UPDATE SET
  requests = usage_analysis_daily.requests + excluded.requests,
  input_tokens = usage_analysis_daily.input_tokens + excluded.input_tokens,
  output_tokens = usage_analysis_daily.output_tokens + excluded.output_tokens,
  cached_input_tokens = usage_analysis_daily.cached_input_tokens + excluded.cached_input_tokens,
  cache_write_tokens = usage_analysis_daily.cache_write_tokens + excluded.cache_write_tokens,
  generation_units = usage_analysis_daily.generation_units + excluded.generation_units,
  duration_count = usage_analysis_daily.duration_count + excluded.duration_count,
  duration_sum_ms = usage_analysis_daily.duration_sum_ms + excluded.duration_sum_ms,
  duration_bucket_0 = usage_analysis_daily.duration_bucket_0 + excluded.duration_bucket_0,
  duration_bucket_1 = usage_analysis_daily.duration_bucket_1 + excluded.duration_bucket_1,
  duration_bucket_2 = usage_analysis_daily.duration_bucket_2 + excluded.duration_bucket_2,
  duration_bucket_3 = usage_analysis_daily.duration_bucket_3 + excluded.duration_bucket_3,
  duration_bucket_4 = usage_analysis_daily.duration_bucket_4 + excluded.duration_bucket_4,
  duration_bucket_5 = usage_analysis_daily.duration_bucket_5 + excluded.duration_bucket_5,
  duration_bucket_6 = usage_analysis_daily.duration_bucket_6 + excluded.duration_bucket_6,
  duration_bucket_7 = usage_analysis_daily.duration_bucket_7 + excluded.duration_bucket_7,
  duration_bucket_8 = usage_analysis_daily.duration_bucket_8 + excluded.duration_bucket_8,
  duration_bucket_9 = usage_analysis_daily.duration_bucket_9 + excluded.duration_bucket_9,
  duration_bucket_10 = usage_analysis_daily.duration_bucket_10 + excluded.duration_bucket_10,
  duration_bucket_11 = usage_analysis_daily.duration_bucket_11 + excluded.duration_bucket_11,
  cost_micros = usage_analysis_daily.cost_micros + excluded.cost_micros;

INSERT INTO session_usage_totals
  (tenant_id, key_id, session_id, currency, last_activity_at, requests,
   errors, input_tokens, output_tokens, cached_input_tokens,
   cache_write_tokens, generation_units, duration_count, duration_sum_ms,
   cost_micros)
SELECT tenant_id, key_id, session_id, currency, MAX(created_at), COUNT(*),
       COALESCE(SUM(CASE WHEN status_class = 'failure' THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN input_tokens >= cached_input_tokens + cache_write_tokens
                         THEN input_tokens - cached_input_tokens - cache_write_tokens
                         ELSE 0 END), 0),
       COALESCE(SUM(output_tokens), 0), COALESCE(SUM(cached_input_tokens), 0),
       COALESCE(SUM(cache_write_tokens), 0), 0, COUNT(*),
       COALESCE(SUM(duration_ms), 0), COALESCE(SUM(cost_micros), 0)
  FROM cpamp_import_new_request_facts
 GROUP BY tenant_id, key_id, session_id, currency
ON CONFLICT (tenant_id, key_id, session_id, currency) DO UPDATE SET
  last_activity_at = GREATEST(session_usage_totals.last_activity_at, excluded.last_activity_at),
  requests = session_usage_totals.requests + excluded.requests,
  errors = session_usage_totals.errors + excluded.errors,
  input_tokens = session_usage_totals.input_tokens + excluded.input_tokens,
  output_tokens = session_usage_totals.output_tokens + excluded.output_tokens,
  cached_input_tokens = session_usage_totals.cached_input_tokens + excluded.cached_input_tokens,
  cache_write_tokens = session_usage_totals.cache_write_tokens + excluded.cache_write_tokens,
  duration_count = session_usage_totals.duration_count + excluded.duration_count,
  duration_sum_ms = session_usage_totals.duration_sum_ms + excluded.duration_sum_ms,
  cost_micros = session_usage_totals.cost_micros + excluded.cost_micros;

INSERT INTO session_usage_hourly
  (tenant_id, key_id, session_id, hour_bucket, model, protocol, status_class,
   error_code, upstream_account_id, model_route_id, currency, requests,
   input_tokens, output_tokens, cached_input_tokens, cache_write_tokens,
   generation_units, duration_count, duration_sum_ms, cost_micros)
SELECT tenant_id, key_id, session_id, created_at / 3600000, model,
       CASE WHEN protocol = 'anthropic' OR protocol LIKE 'anthropic-%' THEN 'anthropic'
            WHEN protocol = 'openai-image' THEN 'openai-image' ELSE 'openai' END,
       status_class, error_code, upstream_account_id, model_route_id, currency,
       COUNT(*),
       COALESCE(SUM(CASE WHEN input_tokens >= cached_input_tokens + cache_write_tokens
                         THEN input_tokens - cached_input_tokens - cache_write_tokens
                         ELSE 0 END), 0),
       COALESCE(SUM(output_tokens), 0), COALESCE(SUM(cached_input_tokens), 0),
       COALESCE(SUM(cache_write_tokens), 0), 0, COUNT(*),
       COALESCE(SUM(duration_ms), 0), COALESCE(SUM(cost_micros), 0)
  FROM cpamp_import_new_request_facts
 GROUP BY tenant_id, key_id, session_id, created_at / 3600000, model,
          CASE WHEN protocol = 'anthropic' OR protocol LIKE 'anthropic-%' THEN 'anthropic'
               WHEN protocol = 'openai-image' THEN 'openai-image' ELSE 'openai' END,
          status_class, error_code, upstream_account_id, model_route_id, currency
ON CONFLICT (tenant_id, key_id, session_id, hour_bucket, model, protocol,
             status_class, error_code, upstream_account_id, model_route_id, currency)
DO UPDATE SET
  requests = session_usage_hourly.requests + excluded.requests,
  input_tokens = session_usage_hourly.input_tokens + excluded.input_tokens,
  output_tokens = session_usage_hourly.output_tokens + excluded.output_tokens,
  cached_input_tokens = session_usage_hourly.cached_input_tokens + excluded.cached_input_tokens,
  cache_write_tokens = session_usage_hourly.cache_write_tokens + excluded.cache_write_tokens,
  duration_count = session_usage_hourly.duration_count + excluded.duration_count,
  duration_sum_ms = session_usage_hourly.duration_sum_ms + excluded.duration_sum_ms,
  cost_micros = session_usage_hourly.cost_micros + excluded.cost_micros;

INSERT INTO session_usage_daily
  (tenant_id, key_id, session_id, day_bucket, model, protocol, status_class,
   error_code, upstream_account_id, model_route_id, currency, requests,
   input_tokens, output_tokens, cached_input_tokens, cache_write_tokens,
   generation_units, duration_count, duration_sum_ms, cost_micros)
SELECT tenant_id, key_id, session_id, created_at / 86400000, model,
       CASE WHEN protocol = 'anthropic' OR protocol LIKE 'anthropic-%' THEN 'anthropic'
            WHEN protocol = 'openai-image' THEN 'openai-image' ELSE 'openai' END,
       status_class, error_code, upstream_account_id, model_route_id, currency,
       COUNT(*),
       COALESCE(SUM(CASE WHEN input_tokens >= cached_input_tokens + cache_write_tokens
                         THEN input_tokens - cached_input_tokens - cache_write_tokens
                         ELSE 0 END), 0),
       COALESCE(SUM(output_tokens), 0), COALESCE(SUM(cached_input_tokens), 0),
       COALESCE(SUM(cache_write_tokens), 0), 0, COUNT(*),
       COALESCE(SUM(duration_ms), 0), COALESCE(SUM(cost_micros), 0)
  FROM cpamp_import_new_request_facts
 GROUP BY tenant_id, key_id, session_id, created_at / 86400000, model,
          CASE WHEN protocol = 'anthropic' OR protocol LIKE 'anthropic-%' THEN 'anthropic'
               WHEN protocol = 'openai-image' THEN 'openai-image' ELSE 'openai' END,
          status_class, error_code, upstream_account_id, model_route_id, currency
ON CONFLICT (tenant_id, key_id, session_id, day_bucket, model, protocol,
             status_class, error_code, upstream_account_id, model_route_id, currency)
DO UPDATE SET
  requests = session_usage_daily.requests + excluded.requests,
  input_tokens = session_usage_daily.input_tokens + excluded.input_tokens,
  output_tokens = session_usage_daily.output_tokens + excluded.output_tokens,
  cached_input_tokens = session_usage_daily.cached_input_tokens + excluded.cached_input_tokens,
  cache_write_tokens = session_usage_daily.cache_write_tokens + excluded.cache_write_tokens,
  duration_count = session_usage_daily.duration_count + excluded.duration_count,
  duration_sum_ms = session_usage_daily.duration_sum_ms + excluded.duration_sum_ms,
  cost_micros = session_usage_daily.cost_micros + excluded.cost_micros;

INSERT INTO cpamp_import_event_provenance (
  tenant_id, source, external_event_hash, target_request_id, source_digest,
  legacy_source_digest, billing_model, requested_model, resolved_model,
  pricing_model, source_service_tier, request_service_tier,
  response_service_tier, cache_input_mode, applied_service_tier,
  context_threshold_tokens,
  pricing_rule, pricing_source, pricing_digest, pricing_config_json,
  raw_input_tokens, raw_cached_tokens, raw_cache_tokens,
  raw_cache_read_tokens, raw_cache_creation_tokens, residual_cached_tokens,
  normalized_uncached_input_tokens, normalized_total_input_tokens,
  normalized_cache_read_tokens, normalized_cache_creation_tokens,
  reasoning_tokens, total_tokens, ttft_ms, prompt_micros_per_million,
  legacy_cache_micros_per_million, cache_read_micros_per_million,
  cache_creation_micros_per_million, output_micros_per_million, cost_micros,
  correction_revision, created_at, updated_at)
SELECT t.id, :'import_source', u.event_hash, n.id, u.source_digest,
       u.legacy_source_digest, u.billing_model, u.requested_model,
       u.resolved_model, u.pricing_model, u.source_service_tier,
       u.request_service_tier, u.response_service_tier,
       u.cache_input_mode, u.applied_service_tier, u.context_threshold_tokens, u.pricing_rule,
       u.pricing_source, u.pricing_digest, u.pricing_config_json,
       u.raw_input_tokens, u.raw_cached_tokens, u.raw_cache_tokens,
       u.raw_cache_read_tokens, u.raw_cache_creation_tokens,
       u.residual_cached_tokens,
       u.normalized_uncached_input_tokens, u.normalized_total_input_tokens,
       u.normalized_cache_read_tokens, u.normalized_cache_creation_tokens,
       u.reasoning_tokens, u.total_tokens, u.ttft_ms,
       u.prompt_micros_per_million, u.legacy_cache_micros_per_million,
       u.cache_read_micros_per_million, u.cache_creation_micros_per_million,
       u.output_micros_per_million, u.cost_micros, 'cpamp-cache-pricing-v2',
       (extract(epoch from clock_timestamp()) * 1000)::bigint,
       (extract(epoch from clock_timestamp()) * 1000)::bigint
  FROM cpamp_import_canonical u
  JOIN tenants t ON t.external_id = :'tenant_external_id'
  JOIN cpamp_import_new_requests n
    ON n.reservation_id = 'cpamp-import:' || u.event_hash
ON CONFLICT (tenant_id, source, external_event_hash) DO NOTHING;

-- Preserve the source request identity independently from the deterministic target UUID.
-- cpa-session-archive uses the same CPA request id; keeping the CPAMP event hash, timestamp,
-- model and key hash here lets its body importer fail closed instead of guessing by time.
INSERT INTO import_request_links
  (tenant_id, source, external_event_hash, external_request_id, source_key_hash,
   target_request_id, source_created_at, source_model, source_digest, created_at)
SELECT t.id, :'import_source', u.event_hash, u.request_id, u.api_key_hash,
       substr(r.value,1,8)||'-'||substr(r.value,9,4)||'-5'||substr(r.value,14,3)||'-a'||substr(r.value,18,3)||'-'||substr(r.value,21,12),
       u.timestamp_ms, COALESCE(NULLIF(u.model, ''), '-'), u.source_digest,
       (extract(epoch from clock_timestamp()) * 1000)::bigint
  FROM cpamp_import_canonical u
  JOIN tenants t ON t.external_id = :'tenant_external_id'
  CROSS JOIN LATERAL (SELECT md5('request:cpamp:' ||
    CASE WHEN :'tenant_external_id' = 'cpa-dogfood-import' AND :'import_source' = 'cpamp-usage-events-v1'
         THEN '' ELSE :'tenant_external_id' || ':' || :'import_source' || ':' END || u.event_hash) AS value) r
 WHERE COALESCE(u.request_id, '') <> '' AND length(COALESCE(u.api_key_hash, '')) = 64
ON CONFLICT (tenant_id, source, external_event_hash) DO UPDATE SET
  external_request_id = excluded.external_request_id,
  source_key_hash = excluded.source_key_hash,
  target_request_id = excluded.target_request_id,
  source_created_at = excluded.source_created_at,
  source_model = excluded.source_model,
  source_digest = CASE WHEN import_request_links.source_digest = ''
                       THEN excluded.source_digest ELSE import_request_links.source_digest END
 WHERE import_request_links.external_request_id IS DISTINCT FROM excluded.external_request_id
    OR import_request_links.source_key_hash IS DISTINCT FROM excluded.source_key_hash
    OR import_request_links.target_request_id IS DISTINCT FROM excluded.target_request_id
    OR import_request_links.source_created_at IS DISTINCT FROM excluded.source_created_at
    OR import_request_links.source_model IS DISTINCT FROM excluded.source_model
    OR import_request_links.source_digest = '';

-- Earlier CPAMP imports stored tiny synthetic inline-json markers instead of bodies. Normalize
-- only an exact marker reconstructed from the currently staged source row and its durable link.
-- A real inline body, CAS locator, or already archived object can never satisfy this predicate.
UPDATE request_records r
   SET request_object = 'gap://cpamp/' || l.external_event_hash || '/request'
  FROM import_request_links l
  JOIN request_record_locators rl
    ON rl.id = l.target_request_id AND rl.tenant_id = l.tenant_id
  JOIN cpamp_import_canonical u
    ON u.event_hash = l.external_event_hash
   AND u.request_id = l.external_request_id
 WHERE l.tenant_id = r.tenant_id
   AND l.target_request_id = r.id
   AND rl.created_at = r.created_at
   AND l.source = :'import_source'
   AND r.request_object = 'inline-json:' ||
       jsonb_build_object('source','cpamp','request_id',u.request_id,'endpoint',u.endpoint)::text;

UPDATE request_records r
   SET response_object = 'gap://cpamp/' || l.external_event_hash || '/response'
  FROM import_request_links l
  JOIN request_record_locators rl
    ON rl.id = l.target_request_id AND rl.tenant_id = l.tenant_id
  JOIN cpamp_import_canonical u
    ON u.event_hash = l.external_event_hash
   AND u.request_id = l.external_request_id
 WHERE l.tenant_id = r.tenant_id
   AND l.target_request_id = r.id
   AND rl.created_at = r.created_at
   AND l.source = :'import_source'
   AND u.failed <> 0
   AND r.response_object = 'inline-json:' ||
       jsonb_build_object('source','cpamp','error',u.fail_summary)::text;

INSERT INTO usage_daily_aggregates
  (key_id, day_bucket, model, status_class, error_code, requests,
   input_tokens, output_tokens, cost_micros)
SELECT key_id, created_at / 86400000, model,
       CASE WHEN status_code BETWEEN 200 AND 399 THEN 'success' ELSE 'failure' END,
       COALESCE(error_code, ''), count(*), sum(input_tokens), sum(output_tokens), sum(cost_micros)
  FROM cpamp_import_new_requests
 GROUP BY key_id, created_at / 86400000, model,
          CASE WHEN status_code BETWEEN 200 AND 399 THEN 'success' ELSE 'failure' END,
          COALESCE(error_code, '')
ON CONFLICT (key_id, day_bucket, model, status_class, error_code) DO UPDATE SET
  requests = usage_daily_aggregates.requests + excluded.requests,
  input_tokens = usage_daily_aggregates.input_tokens + excluded.input_tokens,
  output_tokens = usage_daily_aggregates.output_tokens + excluded.output_tokens,
  cost_micros = usage_daily_aggregates.cost_micros + excluded.cost_micros;

INSERT INTO cpamp_import_checkpoints
  (tenant_external_id, source, watermark_ms, watermark_hash, imported_events, updated_at)
SELECT :'tenant_external_id', :'import_source', COALESCE(max(timestamp_ms), 0),
       COALESCE((array_agg(event_hash ORDER BY timestamp_ms DESC, event_hash DESC))[1], ''),
       (SELECT count(*) FROM cpamp_import_new_requests),
       (extract(epoch from clock_timestamp()) * 1000)::bigint
  FROM cpamp_import_usage
ON CONFLICT (tenant_external_id, source) DO UPDATE SET
  watermark_ms = GREATEST(cpamp_import_checkpoints.watermark_ms, excluded.watermark_ms),
  watermark_hash = CASE WHEN excluded.watermark_ms >= cpamp_import_checkpoints.watermark_ms
                        THEN excluded.watermark_hash ELSE cpamp_import_checkpoints.watermark_hash END,
  imported_events = cpamp_import_checkpoints.imported_events + excluded.imported_events,
  updated_at = excluded.updated_at
 WHERE excluded.imported_events > 0
    OR excluded.watermark_ms > cpamp_import_checkpoints.watermark_ms;

COMMIT;
ANALYZE request_records;
ANALYZE usage_daily_aggregates;
ANALYZE request_stats_facts;
ANALYZE request_daily_aggregates;
ANALYZE usage_analysis_hourly;
ANALYZE usage_analysis_daily;
SELECT imported_events AS total_imported_events, watermark_ms
  FROM cpamp_import_checkpoints
 WHERE tenant_external_id = :'tenant_external_id' AND source = :'import_source';
