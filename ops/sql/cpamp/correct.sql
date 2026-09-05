BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;
SET LOCAL lock_timeout = '5s';
SELECT pg_advisory_xact_lock(
  hashtextextended('memeloop-token-center:cpamp:cache-pricing-v2', 734627102948315)
);

LOCK TABLE request_records, request_record_locators, request_stats_facts,
           request_daily_aggregates, usage_daily_aggregates,
           usage_analysis_hourly, usage_analysis_daily,
           session_usage_totals, session_usage_hourly, session_usage_daily,
           import_request_links, cpamp_import_event_provenance,
           cpamp_import_correction_audit
  IN SHARE ROW EXCLUSIVE MODE;

CREATE TEMP TABLE cpamp_correction_candidates ON COMMIT DROP AS
SELECT e.*, t.id AS tenant_id, l.target_request_id,
       l.source_digest AS old_source_digest, r.key_id, r.created_at,
       r.input_tokens AS old_input_tokens,
       r.cached_input_tokens AS old_cached_input_tokens,
       r.cache_write_tokens AS old_cache_write_tokens,
       r.service_tier AS old_service_tier,
       r.cost_micros AS old_cost_micros,
       f.input_tokens AS old_fact_input_tokens,
       f.cached_input_tokens AS old_fact_cached_input_tokens,
       f.cache_write_tokens AS old_fact_cache_write_tokens,
       f.service_tier AS old_fact_service_tier,
       f.cost_micros AS old_fact_cost_micros
  FROM cpamp_import_evaluated e
  JOIN tenants t ON t.external_id = :'tenant_external_id'
  JOIN import_request_links l
    ON l.tenant_id = t.id AND l.source = :'import_source'
   AND l.external_event_hash = e.event_hash
  JOIN request_record_locators locator
    ON locator.id = l.target_request_id AND locator.tenant_id = t.id
  JOIN request_records r
    ON r.id = locator.id AND r.created_at = locator.created_at
   AND r.tenant_id = locator.tenant_id AND r.key_id = locator.key_id
  JOIN request_stats_facts f
    ON f.request_id = r.id AND f.tenant_id = r.tenant_id
   AND f.key_id = r.key_id AND f.created_at = r.created_at
  LEFT JOIN cpamp_import_correction_audit audit
    ON audit.tenant_id = t.id AND audit.source = :'import_source'
   AND audit.external_event_hash = e.event_hash
   AND audit.correction_revision = 'cpamp-cache-pricing-v2'
 WHERE l.source_digest = e.legacy_source_digest
   AND l.source_digest <> e.source_digest
   AND audit.external_event_hash IS NULL;

-- Compare-and-swap guard: v2 may only replace the exact projection emitted by
-- the legacy CPAMP importer. A live request, non-USD record, already-partial
-- correction, changed locator, or source drift aborts the whole transaction.
CREATE TEMP TABLE cpamp_correction_guard (
  event_hash text,
  invalid boolean NOT NULL CHECK (invalid = false)
) ON COMMIT DROP;
INSERT INTO cpamp_correction_guard (event_hash, invalid)
SELECT 'scope-mismatch', true
 WHERE (
   SELECT count(*)
     FROM cpamp_import_evaluated e
     JOIN tenants t ON t.external_id = :'tenant_external_id'
     JOIN import_request_links l
       ON l.tenant_id = t.id AND l.source = :'import_source'
      AND l.external_event_hash = e.event_hash
     LEFT JOIN cpamp_import_correction_audit audit
       ON audit.tenant_id = t.id AND audit.source = :'import_source'
      AND audit.external_event_hash = e.event_hash
      AND audit.correction_revision = 'cpamp-cache-pricing-v2'
    WHERE l.source_digest = e.legacy_source_digest
      AND l.source_digest <> e.source_digest
      AND audit.external_event_hash IS NULL
 ) <> (SELECT count(*) FROM cpamp_correction_candidates);
INSERT INTO cpamp_correction_guard (event_hash, invalid)
SELECT c.event_hash, true
  FROM cpamp_correction_candidates c
  JOIN request_records r
    ON r.id = c.target_request_id AND r.created_at = c.created_at
   AND r.tenant_id = c.tenant_id AND r.key_id = c.key_id
  JOIN request_stats_facts f
    ON f.request_id = r.id AND f.tenant_id = r.tenant_id
   AND f.key_id = r.key_id AND f.created_at = r.created_at
  CROSS JOIN LATERAL (
    SELECT md5('request:cpamp:' ||
      CASE WHEN :'tenant_external_id' = 'cpa-dogfood-import'
                 AND :'import_source' = 'cpamp-usage-events-v1'
           THEN '' ELSE :'tenant_external_id' || ':' || :'import_source' || ':' END
      || c.event_hash) AS value
  ) digest
 WHERE c.target_request_id <>
       substr(digest.value,1,8)||'-'||substr(digest.value,9,4)||'-5'||substr(digest.value,14,3)||'-a'||substr(digest.value,18,3)||'-'||substr(digest.value,21,12)
    OR r.reservation_id <> 'cpamp-import:' || c.event_hash
    OR r.currency <> 'USD' OR f.currency <> 'USD'
    OR r.input_tokens <> GREATEST(COALESCE(c.raw_input_tokens, 0), 0)
    OR r.cached_input_tokens <> 0 OR r.cache_write_tokens <> 0
    OR r.service_tier <> 'default'
    OR f.input_tokens <> r.input_tokens OR f.output_tokens <> r.output_tokens
    OR f.cached_input_tokens <> r.cached_input_tokens
    OR f.cache_write_tokens <> r.cache_write_tokens
    OR f.service_tier <> r.service_tier OR f.cost_micros <> r.cost_micros
    OR r.model <> COALESCE(NULLIF(c.model, ''), '-')
    OR r.protocol <> COALESCE(NULLIF(c.provider, ''), 'openai');

INSERT INTO cpamp_import_correction_audit (
  tenant_id, source, external_event_hash, correction_revision,
  target_request_id, source_digest_before, source_digest_after,
  input_tokens_before, input_tokens_after,
  cached_input_tokens_before, cached_input_tokens_after,
  cache_write_tokens_before, cache_write_tokens_after,
  service_tier_before, service_tier_after,
  cost_micros_before, cost_micros_after, pricing_digest_after, corrected_at)
SELECT tenant_id, :'import_source', event_hash, 'cpamp-cache-pricing-v2',
       target_request_id, old_source_digest, source_digest,
       old_input_tokens, normalized_total_input_tokens,
       old_cached_input_tokens, normalized_cache_read_tokens,
       old_cache_write_tokens, normalized_cache_creation_tokens,
       old_service_tier, applied_service_tier,
       old_cost_micros, cost_micros, pricing_digest,
       (extract(epoch from clock_timestamp()) * 1000)::bigint
  FROM cpamp_correction_candidates;

UPDATE request_records r
   SET input_tokens = c.normalized_total_input_tokens,
       output_tokens = c.output_tokens,
       cached_input_tokens = c.normalized_cache_read_tokens,
       cache_write_tokens = c.normalized_cache_creation_tokens,
       service_tier = c.applied_service_tier,
       cost_micros = c.cost_micros
  FROM cpamp_correction_candidates c
 WHERE r.id = c.target_request_id AND r.created_at = c.created_at
   AND r.tenant_id = c.tenant_id AND r.key_id = c.key_id
   AND r.input_tokens = c.old_input_tokens
   AND r.cached_input_tokens = c.old_cached_input_tokens
   AND r.cache_write_tokens = c.old_cache_write_tokens
   AND r.service_tier = c.old_service_tier
   AND r.cost_micros = c.old_cost_micros;

UPDATE request_stats_facts f
   SET input_tokens = c.normalized_total_input_tokens,
       output_tokens = c.output_tokens,
       cached_input_tokens = c.normalized_cache_read_tokens,
       cache_write_tokens = c.normalized_cache_creation_tokens,
       service_tier = c.applied_service_tier,
       cost_micros = c.cost_micros,
       session_id = COALESCE(NULLIF(f.session_id, ''), 'unlinked:' || f.key_id)
  FROM cpamp_correction_candidates c
 WHERE f.request_id = c.target_request_id AND f.created_at = c.created_at
   AND f.tenant_id = c.tenant_id AND f.key_id = c.key_id
   AND f.input_tokens = c.old_fact_input_tokens
   AND f.cached_input_tokens = c.old_fact_cached_input_tokens
   AND f.cache_write_tokens = c.old_fact_cache_write_tokens
   AND f.service_tier = c.old_fact_service_tier
   AND f.cost_micros = c.old_fact_cost_micros;

UPDATE import_request_links l
   SET source_digest = c.source_digest
  FROM cpamp_correction_candidates c
 WHERE l.tenant_id = c.tenant_id AND l.source = :'import_source'
   AND l.external_event_hash = c.event_hash
   AND l.target_request_id = c.target_request_id
   AND l.source_digest = c.old_source_digest;

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
SELECT tenant_id, :'import_source', event_hash, target_request_id, source_digest,
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
       'cpamp-cache-pricing-v2',
       (extract(epoch from clock_timestamp()) * 1000)::bigint,
       (extract(epoch from clock_timestamp()) * 1000)::bigint
  FROM cpamp_correction_candidates
ON CONFLICT (tenant_id, source, external_event_hash) DO UPDATE SET
  target_request_id = excluded.target_request_id,
  source_digest = excluded.source_digest,
  legacy_source_digest = excluded.legacy_source_digest,
  billing_model = excluded.billing_model,
  requested_model = excluded.requested_model,
  resolved_model = excluded.resolved_model,
  pricing_model = excluded.pricing_model,
  source_service_tier = excluded.source_service_tier,
  request_service_tier = excluded.request_service_tier,
  response_service_tier = excluded.response_service_tier,
  cache_input_mode = excluded.cache_input_mode,
  applied_service_tier = excluded.applied_service_tier,
  context_threshold_tokens = excluded.context_threshold_tokens,
  pricing_rule = excluded.pricing_rule,
  pricing_source = excluded.pricing_source,
  pricing_digest = excluded.pricing_digest,
  pricing_config_json = excluded.pricing_config_json,
  raw_input_tokens = excluded.raw_input_tokens,
  raw_cached_tokens = excluded.raw_cached_tokens,
  raw_cache_tokens = excluded.raw_cache_tokens,
  raw_cache_read_tokens = excluded.raw_cache_read_tokens,
  raw_cache_creation_tokens = excluded.raw_cache_creation_tokens,
  residual_cached_tokens = excluded.residual_cached_tokens,
  normalized_uncached_input_tokens = excluded.normalized_uncached_input_tokens,
  normalized_total_input_tokens = excluded.normalized_total_input_tokens,
  normalized_cache_read_tokens = excluded.normalized_cache_read_tokens,
  normalized_cache_creation_tokens = excluded.normalized_cache_creation_tokens,
  reasoning_tokens = excluded.reasoning_tokens,
  total_tokens = excluded.total_tokens,
  ttft_ms = excluded.ttft_ms,
  prompt_micros_per_million = excluded.prompt_micros_per_million,
  legacy_cache_micros_per_million = excluded.legacy_cache_micros_per_million,
  cache_read_micros_per_million = excluded.cache_read_micros_per_million,
  cache_creation_micros_per_million = excluded.cache_creation_micros_per_million,
  output_micros_per_million = excluded.output_micros_per_million,
  cost_micros = excluded.cost_micros,
  correction_revision = excluded.correction_revision,
  updated_at = excluded.updated_at;
