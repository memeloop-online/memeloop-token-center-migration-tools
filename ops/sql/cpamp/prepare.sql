CREATE TABLE IF NOT EXISTS cpamp_import_checkpoints (
  tenant_external_id text NOT NULL,
  source text NOT NULL,
  watermark_ms bigint NOT NULL,
  watermark_hash text NOT NULL,
  imported_events bigint NOT NULL,
  updated_at bigint NOT NULL,
  PRIMARY KEY (tenant_external_id, source)
);
ALTER TABLE cpamp_import_checkpoints
  ADD COLUMN IF NOT EXISTS correction_revision text NOT NULL DEFAULT '';
ALTER TABLE cpamp_import_checkpoints
  ADD COLUMN IF NOT EXISTS corrected_events bigint NOT NULL DEFAULT 0;
ALTER TABLE cpamp_import_checkpoints
  ADD COLUMN IF NOT EXISTS corrected_at bigint;
ALTER TABLE cpamp_import_checkpoints
  ADD COLUMN IF NOT EXISTS tenant_external_id text;
UPDATE cpamp_import_checkpoints
   SET tenant_external_id = :'tenant_external_id'
 WHERE tenant_external_id IS NULL;
ALTER TABLE cpamp_import_checkpoints
  ALTER COLUMN tenant_external_id SET NOT NULL;
ALTER TABLE cpamp_import_checkpoints
  DROP CONSTRAINT IF EXISTS cpamp_import_checkpoints_pkey;
ALTER TABLE cpamp_import_checkpoints
  ADD CONSTRAINT cpamp_import_checkpoints_pkey PRIMARY KEY (tenant_external_id, source);
-- These tables are disposable, process-global staging protected by the importer's
-- advisory lock. Recreate them so installations left with an older staging shape
-- are upgraded without altering durable checkpoints, provenance, audit, or user data.
DROP TABLE IF EXISTS cpamp_import_usage, cpamp_import_aliases,
  cpamp_import_prices, cpamp_import_context_prices,
  cpamp_import_service_prices, cpamp_import_identities,
  cpamp_import_new_requests, cpamp_import_evaluated;
CREATE UNLOGGED TABLE cpamp_import_usage (
  event_hash text, request_id text, timestamp_ms bigint, provider text,
  model text, endpoint text, api_key_hash text, requested_model text,
  resolved_model text, reasoning_effort text, service_tier text,
  request_service_tier text, response_service_tier text, cache_input_mode text,
  input_tokens bigint, output_tokens bigint, reasoning_tokens bigint,
  cached_tokens bigint, cache_tokens bigint, cache_read_tokens bigint,
  cache_creation_tokens bigint, normalized_uncached_input_tokens bigint,
  normalized_total_input_tokens bigint, normalized_cache_read_tokens bigint,
  normalized_cache_creation_tokens bigint, total_tokens bigint,
  latency_ms bigint, ttft_ms bigint, failed bigint,
  fail_status_code bigint, fail_summary text
);
CREATE UNLOGGED TABLE cpamp_import_aliases (
  api_key_hash text, alias text, updated_at_ms bigint
);
CREATE UNLOGGED TABLE cpamp_import_prices (
  model text, prompt_per_1m numeric, completion_per_1m numeric,
  cache_per_1m numeric, cache_read_per_1m numeric,
  cache_creation_per_1m numeric, prompt_configured bigint,
  completion_configured bigint, cache_read_configured bigint,
  cache_creation_configured bigint, source text, source_model_id text,
  updated_at_ms bigint
);
CREATE UNLOGGED TABLE cpamp_import_context_prices (
  model text, threshold_tokens bigint, prompt_per_1m numeric,
  completion_per_1m numeric, cache_per_1m numeric, cache_read_per_1m numeric,
  cache_creation_per_1m numeric, prompt_configured bigint,
  completion_configured bigint, cache_configured bigint,
  cache_read_configured bigint, cache_creation_configured bigint
);
CREATE UNLOGGED TABLE cpamp_import_service_prices (
  model text, mode text, service_tier text, prompt_per_1m numeric,
  completion_per_1m numeric, cache_per_1m numeric, cache_read_per_1m numeric,
  cache_creation_per_1m numeric, prompt_configured bigint,
  completion_configured bigint, cache_configured bigint,
  cache_read_configured bigint, cache_creation_configured bigint
);
CREATE UNLOGGED TABLE cpamp_import_identities (
  api_key_hash text PRIMARY KEY, key_id text NOT NULL, account_id text NOT NULL,
  alias text NOT NULL
);
CREATE UNLOGGED TABLE cpamp_import_new_requests
  (LIKE request_records INCLUDING DEFAULTS);
CREATE UNLOGGED TABLE cpamp_import_evaluated (
  event_hash text, request_id text, timestamp_ms bigint, provider text,
  model text, endpoint text, api_key_hash text, requested_model text,
  resolved_model text, reasoning_effort text, source_service_tier text,
  request_service_tier text, response_service_tier text, cache_input_mode text,
  raw_input_tokens bigint, output_tokens bigint, reasoning_tokens bigint,
  raw_cached_tokens bigint, raw_cache_tokens bigint, raw_cache_read_tokens bigint,
  raw_cache_creation_tokens bigint, normalized_uncached_input_tokens bigint,
  normalized_total_input_tokens bigint, normalized_cache_read_tokens bigint,
  normalized_cache_creation_tokens bigint, total_tokens bigint,
  latency_ms bigint, ttft_ms bigint, failed bigint, fail_status_code bigint,
  fail_summary text, legacy_source_digest text, source_digest text,
  billing_model text, pricing_model text, applied_service_tier text,
  context_threshold_tokens bigint, pricing_rule text, pricing_source text,
  prompt_micros_per_million bigint, legacy_cache_micros_per_million bigint,
  cache_read_micros_per_million bigint, cache_creation_micros_per_million bigint,
  output_micros_per_million bigint, residual_cached_tokens bigint,
  cost_micros bigint, pricing_digest text, pricing_config_json text,
  validation_error text
);
CREATE TABLE IF NOT EXISTS cpamp_import_event_provenance (
  tenant_id text NOT NULL, source text NOT NULL, external_event_hash text NOT NULL,
  target_request_id text NOT NULL, source_digest text NOT NULL,
  legacy_source_digest text NOT NULL, billing_model text NOT NULL,
  requested_model text NOT NULL, resolved_model text NOT NULL,
  pricing_model text NOT NULL, source_service_tier text NOT NULL,
  request_service_tier text NOT NULL, response_service_tier text NOT NULL,
  cache_input_mode text NOT NULL, applied_service_tier text NOT NULL,
  context_threshold_tokens bigint NOT NULL,
  pricing_rule text NOT NULL, pricing_source text NOT NULL,
  pricing_digest text NOT NULL, pricing_config_json text NOT NULL,
  raw_input_tokens bigint NOT NULL, raw_cached_tokens bigint NOT NULL,
  raw_cache_tokens bigint NOT NULL, raw_cache_read_tokens bigint NOT NULL,
  raw_cache_creation_tokens bigint NOT NULL, residual_cached_tokens bigint NOT NULL,
  normalized_uncached_input_tokens bigint NOT NULL,
  normalized_total_input_tokens bigint NOT NULL,
  normalized_cache_read_tokens bigint NOT NULL,
  normalized_cache_creation_tokens bigint NOT NULL,
  reasoning_tokens bigint NOT NULL, total_tokens bigint NOT NULL,
  ttft_ms bigint, prompt_micros_per_million bigint NOT NULL,
  legacy_cache_micros_per_million bigint NOT NULL,
  cache_read_micros_per_million bigint NOT NULL,
  cache_creation_micros_per_million bigint NOT NULL,
  output_micros_per_million bigint NOT NULL, cost_micros bigint NOT NULL,
  correction_revision text NOT NULL, created_at bigint NOT NULL,
  updated_at bigint NOT NULL,
  PRIMARY KEY (tenant_id, source, external_event_hash)
);
ALTER TABLE cpamp_import_event_provenance
  ADD COLUMN IF NOT EXISTS pricing_config_json text;
ALTER TABLE cpamp_import_event_provenance
  ADD COLUMN IF NOT EXISTS cache_input_mode text;
ALTER TABLE cpamp_import_event_provenance
  ADD COLUMN IF NOT EXISTS raw_cached_tokens bigint;
ALTER TABLE cpamp_import_event_provenance
  ADD COLUMN IF NOT EXISTS raw_cache_tokens bigint;
ALTER TABLE cpamp_import_event_provenance
  ADD COLUMN IF NOT EXISTS raw_cache_read_tokens bigint;
ALTER TABLE cpamp_import_event_provenance
  ADD COLUMN IF NOT EXISTS raw_cache_creation_tokens bigint;
ALTER TABLE cpamp_import_event_provenance
  ADD COLUMN IF NOT EXISTS residual_cached_tokens bigint;
ALTER TABLE cpamp_import_event_provenance
  ALTER COLUMN pricing_config_json SET NOT NULL;
ALTER TABLE cpamp_import_event_provenance
  ALTER COLUMN cache_input_mode SET NOT NULL;
ALTER TABLE cpamp_import_event_provenance
  ALTER COLUMN raw_cached_tokens SET NOT NULL;
ALTER TABLE cpamp_import_event_provenance
  ALTER COLUMN raw_cache_tokens SET NOT NULL;
ALTER TABLE cpamp_import_event_provenance
  ALTER COLUMN raw_cache_read_tokens SET NOT NULL;
ALTER TABLE cpamp_import_event_provenance
  ALTER COLUMN raw_cache_creation_tokens SET NOT NULL;
ALTER TABLE cpamp_import_event_provenance
  ALTER COLUMN residual_cached_tokens SET NOT NULL;

CREATE TABLE IF NOT EXISTS cpamp_import_correction_audit (
  tenant_id text NOT NULL, source text NOT NULL, external_event_hash text NOT NULL,
  correction_revision text NOT NULL, target_request_id text NOT NULL,
  source_digest_before text NOT NULL, source_digest_after text NOT NULL,
  input_tokens_before bigint NOT NULL, input_tokens_after bigint NOT NULL,
  cached_input_tokens_before bigint NOT NULL, cached_input_tokens_after bigint NOT NULL,
  cache_write_tokens_before bigint NOT NULL, cache_write_tokens_after bigint NOT NULL,
  service_tier_before text NOT NULL, service_tier_after text NOT NULL,
  cost_micros_before bigint NOT NULL, cost_micros_after bigint NOT NULL,
  pricing_digest_after text NOT NULL, corrected_at bigint NOT NULL,
  PRIMARY KEY (tenant_id, source, external_event_hash, correction_revision)
);

DO $cpamp_target_schema_guard$
BEGIN
  IF to_regclass('request_stats_facts') IS NULL
     OR to_regclass('session_usage_totals') IS NULL
     OR to_regclass('session_usage_hourly') IS NULL
     OR to_regclass('session_usage_daily') IS NULL
     OR NOT EXISTS (
       SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'request_stats_facts' AND column_name = 'session_id'
     ) THEN
    RAISE EXCEPTION 'CPAMP importer requires the complete session-usage schema';
  END IF;
END
$cpamp_target_schema_guard$;

TRUNCATE cpamp_import_usage, cpamp_import_aliases, cpamp_import_prices,
         cpamp_import_context_prices, cpamp_import_service_prices,
         cpamp_import_identities, cpamp_import_new_requests,
         cpamp_import_evaluated;
