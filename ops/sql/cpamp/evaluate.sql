TRUNCATE cpamp_import_evaluated;

WITH raw_events AS MATERIALIZED (
  SELECT u.*,
         COALESCE(NULLIF(u.resolved_model, ''), NULLIF(u.model, ''), '-') AS billing_model_value,
         GREATEST(
           GREATEST(COALESCE(u.cached_tokens, 0), COALESCE(u.cache_tokens, 0))
             - GREATEST(COALESCE(u.cache_read_tokens, 0), 0)
             - GREATEST(COALESCE(u.cache_creation_tokens, 0), 0),
           0
         ) AS residual_cached_tokens_value,
         CASE lower(trim(COALESCE(u.service_tier, '')))
           WHEN '' THEN 'default'
           WHEN 'fast' THEN 'priority'
           ELSE lower(trim(u.service_tier))
         END AS target_service_tier,
         encode(sha256(convert_to(jsonb_build_array(
           u.request_id, u.timestamp_ms, u.provider, u.model, u.endpoint,
           u.api_key_hash, u.input_tokens, u.output_tokens, u.latency_ms,
           u.failed, u.fail_status_code, u.fail_summary
         )::text, 'UTF8')), 'hex') AS legacy_source_digest_value,
         encode(sha256(convert_to(jsonb_build_array(
           u.request_id, u.timestamp_ms, u.provider, u.model, u.endpoint,
           u.api_key_hash, u.requested_model, u.resolved_model,
           u.reasoning_effort, u.service_tier, u.request_service_tier,
           u.response_service_tier, u.cache_input_mode, u.input_tokens,
           u.output_tokens, u.reasoning_tokens, u.cached_tokens, u.cache_tokens,
           u.cache_read_tokens, u.cache_creation_tokens,
           u.normalized_uncached_input_tokens, u.normalized_total_input_tokens,
           u.normalized_cache_read_tokens, u.normalized_cache_creation_tokens,
           u.total_tokens, u.latency_ms, u.ttft_ms, u.failed,
           u.fail_status_code, u.fail_summary
         )::text, 'UTF8')), 'hex') AS source_digest_value
    FROM cpamp_import_usage u
), priced_events AS MATERIALIZED (
  SELECT r.*, p.model AS price_row_model, p.prompt_per_1m AS base_prompt,
         p.completion_per_1m AS base_completion, p.cache_per_1m AS base_cache,
         p.cache_read_per_1m AS base_cache_read,
         p.cache_creation_per_1m AS base_cache_creation,
         p.prompt_configured AS base_prompt_configured,
         p.completion_configured AS base_completion_configured,
         p.cache_read_configured AS base_cache_read_configured,
         p.cache_creation_configured AS base_cache_creation_configured,
         p.source AS base_source, p.source_model_id AS source_model_id,
         p.updated_at_ms AS base_updated_at,
         COALESCE(p.model, r.billing_model_value) AS pricing_model_value
    FROM raw_events r
    LEFT JOIN LATERAL (
      SELECT candidate.*
        FROM cpamp_import_prices candidate
       WHERE candidate.model = r.billing_model_value
          OR candidate.model = r.model
       ORDER BY CASE WHEN candidate.model = r.billing_model_value THEN 0 ELSE 1 END
       LIMIT 1
    ) p ON true
), classified_events AS MATERIALIZED (
  SELECT p.*, context_price.threshold_tokens AS selected_context_threshold,
         context_price.prompt_per_1m AS context_prompt,
         context_price.completion_per_1m AS context_completion,
         context_price.cache_per_1m AS context_cache,
         context_price.cache_read_per_1m AS context_cache_read,
         context_price.cache_creation_per_1m AS context_cache_creation,
         context_price.prompt_configured AS context_prompt_configured,
         context_price.completion_configured AS context_completion_configured,
         context_price.cache_configured AS context_cache_configured,
         context_price.cache_read_configured AS context_cache_read_configured,
         context_price.cache_creation_configured AS context_cache_creation_configured,
         service_price.mode AS selected_service_mode,
         service_price.service_tier AS selected_service_tier,
         service_price.prompt_per_1m AS service_prompt,
         service_price.completion_per_1m AS service_completion,
         service_price.cache_per_1m AS service_cache,
         service_price.cache_read_per_1m AS service_cache_read,
         service_price.cache_creation_per_1m AS service_cache_creation,
         service_price.prompt_configured AS service_prompt_configured,
         service_price.completion_configured AS service_completion_configured,
         service_price.cache_configured AS service_cache_configured,
         service_price.cache_read_configured AS service_cache_read_configured,
         service_price.cache_creation_configured AS service_cache_creation_configured,
         EXISTS (
           SELECT 1 FROM cpamp_import_context_prices any_context
            WHERE any_context.model = p.pricing_model_value
         ) AS has_context_prices,
         regexp_replace(lower(p.billing_model_value), '^.*/', '') AS behavior_slug
    FROM priced_events p
    LEFT JOIN LATERAL (
      SELECT tier.* FROM cpamp_import_context_prices tier
       WHERE tier.model = p.pricing_model_value
         AND p.normalized_total_input_tokens > tier.threshold_tokens
       ORDER BY tier.threshold_tokens DESC LIMIT 1
    ) context_price ON true
    LEFT JOIN LATERAL (
      SELECT tier.* FROM cpamp_import_service_prices tier
       WHERE tier.model = p.pricing_model_value
         AND lower(trim(COALESCE(p.service_tier, ''))) IN (tier.mode, tier.service_tier)
       ORDER BY tier.mode, tier.service_tier LIMIT 1
    ) service_price ON true
), rule_selection AS MATERIALIZED (
  SELECT c.*,
         c.selected_context_threshold IS NOT NULL AS use_context_price,
         NOT c.has_context_prices
           AND c.normalized_total_input_tokens > 272000
           AND (
             c.behavior_slug = 'gpt-5.5' OR c.behavior_slug LIKE 'gpt-5.5-20%'
             OR c.behavior_slug = 'gpt-5.4' OR c.behavior_slug LIKE 'gpt-5.4-20%'
             OR c.behavior_slug = 'gpt-5.4-pro' OR c.behavior_slug LIKE 'gpt-5.4-pro-20%'
             OR c.behavior_slug = 'gpt-5.6' OR c.behavior_slug LIKE 'gpt-5.6-%'
           ) AS use_legacy_long_context,
         c.selected_service_mode IS NOT NULL
           AND c.selected_context_threshold IS NULL AS service_price_available
    FROM classified_events c
), effective_prices AS MATERIALIZED (
  SELECT s.*,
         CASE
           WHEN s.use_context_price AND s.context_prompt_configured <> 0 THEN s.context_prompt
           WHEN s.service_price_available
             AND NOT (s.use_legacy_long_context AND lower(trim(COALESCE(s.service_tier, ''))) IN ('priority', 'fast'))
             AND s.service_prompt_configured <> 0 THEN s.service_prompt
           ELSE s.base_prompt END AS effective_prompt,
         CASE
           WHEN s.use_context_price AND s.context_prompt_configured <> 0 THEN true
           WHEN s.service_price_available
             AND NOT (s.use_legacy_long_context AND lower(trim(COALESCE(s.service_tier, ''))) IN ('priority', 'fast'))
             AND s.service_prompt_configured <> 0 THEN true
           ELSE s.base_prompt_configured <> 0 END AS effective_prompt_configured,
         CASE
           WHEN s.use_context_price AND s.context_completion_configured <> 0 THEN s.context_completion
           WHEN s.service_price_available
             AND NOT (s.use_legacy_long_context AND lower(trim(COALESCE(s.service_tier, ''))) IN ('priority', 'fast'))
             AND s.service_completion_configured <> 0 THEN s.service_completion
           ELSE s.base_completion END AS effective_completion,
         CASE
           WHEN s.use_context_price AND s.context_completion_configured <> 0 THEN true
           WHEN s.service_price_available
             AND NOT (s.use_legacy_long_context AND lower(trim(COALESCE(s.service_tier, ''))) IN ('priority', 'fast'))
             AND s.service_completion_configured <> 0 THEN true
           ELSE s.base_completion_configured <> 0 END AS effective_completion_configured,
         CASE
           WHEN s.use_context_price AND s.context_cache_configured <> 0 THEN s.context_cache
           WHEN s.service_price_available
             AND NOT (s.use_legacy_long_context AND lower(trim(COALESCE(s.service_tier, ''))) IN ('priority', 'fast'))
             AND s.service_cache_configured <> 0 THEN s.service_cache
           ELSE s.base_cache END AS effective_cache,
         CASE
           WHEN s.use_context_price AND s.context_cache_read_configured <> 0 THEN s.context_cache_read
           WHEN s.service_price_available
             AND NOT (s.use_legacy_long_context AND lower(trim(COALESCE(s.service_tier, ''))) IN ('priority', 'fast'))
             AND s.service_cache_read_configured <> 0 THEN s.service_cache_read
           ELSE s.base_cache_read END AS selected_cache_read,
         CASE
           WHEN s.use_context_price AND s.context_cache_creation_configured <> 0 THEN s.context_cache_creation
           WHEN s.service_price_available
             AND NOT (s.use_legacy_long_context AND lower(trim(COALESCE(s.service_tier, ''))) IN ('priority', 'fast'))
             AND s.service_cache_creation_configured <> 0 THEN s.service_cache_creation
           ELSE s.base_cache_creation END AS selected_cache_creation,
         CASE
           WHEN s.use_context_price AND s.context_cache_read_configured <> 0 THEN true
           WHEN s.service_price_available
             AND NOT (s.use_legacy_long_context AND lower(trim(COALESCE(s.service_tier, ''))) IN ('priority', 'fast'))
             AND s.service_cache_read_configured <> 0 THEN true
           ELSE s.base_cache_read_configured <> 0 END AS cache_read_configured,
         CASE
           WHEN s.use_context_price AND s.context_cache_creation_configured <> 0 THEN true
           WHEN s.service_price_available
             AND NOT (s.use_legacy_long_context AND lower(trim(COALESCE(s.service_tier, ''))) IN ('priority', 'fast'))
             AND s.service_cache_creation_configured <> 0 THEN true
           ELSE s.base_cache_creation_configured <> 0 END AS cache_creation_configured,
         CASE
           WHEN s.use_context_price THEN 1::numeric
           WHEN s.service_price_available THEN 1::numeric
           WHEN s.use_legacy_long_context
             AND lower(trim(COALESCE(s.service_tier, ''))) IN ('priority', 'fast') THEN 1::numeric
           WHEN lower(trim(COALESCE(s.service_tier, ''))) IN ('flex', 'batch') THEN 0.5::numeric
           WHEN lower(trim(COALESCE(s.service_tier, ''))) IN ('priority', 'fast')
             AND (s.behavior_slug = 'gpt-5.5' OR s.behavior_slug LIKE 'gpt-5.5-20%') THEN 2.5::numeric
           WHEN lower(trim(COALESCE(s.service_tier, ''))) IN ('priority', 'fast')
             AND (s.behavior_slug = 'gpt-5.6' OR s.behavior_slug LIKE 'gpt-5.6-%'
                  OR s.behavior_slug = 'gpt-5.4' OR s.behavior_slug LIKE 'gpt-5.4-%'
                  OR s.behavior_slug = 'gpt-5.3-codex' OR s.behavior_slug LIKE 'gpt-5.3-codex-%') THEN 2::numeric
           ELSE 1::numeric END AS service_multiplier,
         CASE WHEN s.use_legacy_long_context THEN 2::numeric ELSE 1::numeric END AS input_multiplier,
         CASE WHEN s.use_legacy_long_context THEN 1.5::numeric ELSE 1::numeric END AS output_multiplier
    FROM rule_selection s
), finalized_prices AS MATERIALIZED (
  SELECT e.*,
         CASE
           WHEN e.cache_read_configured OR COALESCE(e.selected_cache_read, 0) > 0
             THEN e.selected_cache_read
           WHEN COALESCE(e.effective_cache, 0) > 0 THEN e.effective_cache
           ELSE e.effective_prompt * 0.1::numeric
         END AS effective_cache_read,
         CASE
           WHEN e.cache_creation_configured OR COALESCE(e.selected_cache_creation, 0) > 0
             THEN e.selected_cache_creation
           ELSE e.effective_prompt
         END AS effective_cache_creation,
         CASE
           WHEN e.use_context_price THEN 'context'
           WHEN e.use_legacy_long_context
             AND lower(trim(COALESCE(e.service_tier, ''))) IN ('priority', 'fast') THEN 'legacy-long-base'
           WHEN e.service_price_available THEN 'service'
           WHEN e.use_legacy_long_context THEN 'legacy-long'
           ELSE 'base' END AS pricing_rule_value
    FROM effective_prices e
), evaluated AS MATERIALIZED (
  SELECT f.*,
         jsonb_build_object(
           'schema', 'cpamp-v1.11.12-price-v1',
           'behavior_model', f.billing_model_value,
           'pricing_model', f.pricing_model_value,
           'source', COALESCE(f.base_source, ''),
           'source_model_id', COALESCE(f.source_model_id, ''),
           'source_updated_at_ms', COALESCE(f.base_updated_at, 0),
           'pricing_rule', CASE WHEN f.price_row_model IS NULL THEN 'zero-token' ELSE f.pricing_rule_value END,
           'applied_service_tier', f.target_service_tier,
           'context_threshold_tokens', COALESCE(f.selected_context_threshold, -1),
           'selected_service_mode', COALESCE(f.selected_service_mode, ''),
           'selected_service_tier', COALESCE(f.selected_service_tier, ''),
           'base', jsonb_build_object(
             'prompt', f.base_prompt, 'completion', f.base_completion,
             'cache', f.base_cache, 'cache_read', f.base_cache_read,
             'cache_creation', f.base_cache_creation,
             'prompt_configured', f.base_prompt_configured,
             'completion_configured', f.base_completion_configured,
             'cache_read_configured', f.base_cache_read_configured,
             'cache_creation_configured', f.base_cache_creation_configured
           ),
           'context_override', CASE WHEN f.selected_context_threshold IS NULL THEN NULL ELSE jsonb_build_object(
             'prompt', f.context_prompt, 'completion', f.context_completion,
             'cache', f.context_cache, 'cache_read', f.context_cache_read,
             'cache_creation', f.context_cache_creation,
             'prompt_configured', f.context_prompt_configured,
             'completion_configured', f.context_completion_configured,
             'cache_configured', f.context_cache_configured,
             'cache_read_configured', f.context_cache_read_configured,
             'cache_creation_configured', f.context_cache_creation_configured
           ) END,
           'service_override', CASE WHEN f.selected_service_mode IS NULL THEN NULL ELSE jsonb_build_object(
             'prompt', f.service_prompt, 'completion', f.service_completion,
             'cache', f.service_cache, 'cache_read', f.service_cache_read,
             'cache_creation', f.service_cache_creation,
             'prompt_configured', f.service_prompt_configured,
             'completion_configured', f.service_completion_configured,
             'cache_configured', f.service_cache_configured,
             'cache_read_configured', f.service_cache_read_configured,
             'cache_creation_configured', f.service_cache_creation_configured
           ) END,
           'effective', jsonb_build_object(
             'prompt', f.effective_prompt, 'completion', f.effective_completion,
             'cache', f.effective_cache, 'cache_read', f.effective_cache_read,
             'cache_creation', f.effective_cache_creation,
             'prompt_configured', f.effective_prompt_configured,
             'completion_configured', f.effective_completion_configured,
             'cache_read_configured', f.cache_read_configured,
             'cache_creation_configured', f.cache_creation_configured,
             'input_multiplier', f.input_multiplier,
             'output_multiplier', f.output_multiplier,
             'service_multiplier', f.service_multiplier
           )
         )::text AS pricing_config_json_value,
         CASE
           WHEN f.price_row_model IS NULL
             AND COALESCE(f.normalized_total_input_tokens, 0) + COALESCE(f.output_tokens, 0) > 0
             THEN 'missing source model price'
           WHEN f.normalized_uncached_input_tokens IS NULL
             OR f.normalized_total_input_tokens IS NULL
             OR f.normalized_cache_read_tokens IS NULL
             OR f.normalized_cache_creation_tokens IS NULL
             THEN 'cache-accounting migration is incomplete'
           WHEN LEAST(f.input_tokens, f.output_tokens, f.reasoning_tokens,
                      f.cached_tokens, f.cache_tokens, f.cache_read_tokens,
                      f.cache_creation_tokens, f.normalized_uncached_input_tokens,
                      f.normalized_total_input_tokens, f.normalized_cache_read_tokens,
                      f.normalized_cache_creation_tokens, f.total_tokens) < 0
             THEN 'negative token dimension'
           WHEN f.normalized_total_input_tokens <>
                f.normalized_uncached_input_tokens + f.normalized_cache_read_tokens
                  + f.normalized_cache_creation_tokens
             THEN 'normalized input buckets do not sum to total input'
           WHEN f.normalized_cache_read_tokens <>
                f.residual_cached_tokens_value + GREATEST(f.cache_read_tokens, 0)
             THEN 'cache-read normalization disagrees with source cache buckets'
           WHEN f.normalized_cache_creation_tokens <> GREATEST(f.cache_creation_tokens, 0)
             THEN 'cache-creation normalization disagrees with source cache buckets'
           WHEN f.target_service_tier NOT IN
                ('default', 'auto', 'priority', 'flex', 'scale', 'batch', 'standard_only')
             THEN 'unsupported effective service tier'
           WHEN f.normalized_uncached_input_tokens > 0
             AND (f.effective_prompt IS NULL OR NOT f.effective_prompt_configured)
             THEN 'missing exact prompt price'
           WHEN f.output_tokens > 0
             AND (f.effective_completion IS NULL OR NOT f.effective_completion_configured)
             THEN 'missing exact output price'
           WHEN f.cache_read_tokens > 0
             AND NOT f.cache_read_configured
             AND COALESCE(f.effective_cache, 0) <= 0
             AND NOT f.effective_prompt_configured
             THEN 'missing exact cache-read price fallback'
           WHEN f.normalized_cache_creation_tokens > 0
             AND NOT f.cache_creation_configured
             AND NOT f.effective_prompt_configured
             THEN 'missing exact cache-creation price fallback'
           ELSE '' END AS validation_error_value
    FROM finalized_prices f
)
INSERT INTO cpamp_import_evaluated (
  event_hash, request_id, timestamp_ms, provider, model, endpoint, api_key_hash,
  requested_model, resolved_model, reasoning_effort, source_service_tier,
  request_service_tier, response_service_tier, cache_input_mode,
  raw_input_tokens, output_tokens, reasoning_tokens, raw_cached_tokens,
  raw_cache_tokens, raw_cache_read_tokens, raw_cache_creation_tokens,
  normalized_uncached_input_tokens, normalized_total_input_tokens,
  normalized_cache_read_tokens, normalized_cache_creation_tokens, total_tokens,
  latency_ms, ttft_ms, failed, fail_status_code, fail_summary,
  legacy_source_digest, source_digest, billing_model, pricing_model,
  applied_service_tier, context_threshold_tokens, pricing_rule, pricing_source,
  prompt_micros_per_million, legacy_cache_micros_per_million,
  cache_read_micros_per_million, cache_creation_micros_per_million,
  output_micros_per_million, residual_cached_tokens, cost_micros,
  pricing_digest, pricing_config_json, validation_error
)
SELECT event_hash, request_id, timestamp_ms, provider, model, endpoint, api_key_hash,
       COALESCE(requested_model, ''), COALESCE(resolved_model, ''),
       COALESCE(reasoning_effort, ''), COALESCE(service_tier, ''),
       COALESCE(request_service_tier, ''), COALESCE(response_service_tier, ''),
       COALESCE(cache_input_mode, ''), input_tokens, output_tokens,
       reasoning_tokens, cached_tokens, cache_tokens, cache_read_tokens,
       cache_creation_tokens, normalized_uncached_input_tokens,
       normalized_total_input_tokens, normalized_cache_read_tokens,
       normalized_cache_creation_tokens, total_tokens, latency_ms, ttft_ms,
       failed, fail_status_code, fail_summary, legacy_source_digest_value,
       source_digest_value, billing_model_value, pricing_model_value,
       target_service_tier, COALESCE(selected_context_threshold, -1),
       CASE WHEN price_row_model IS NULL THEN 'zero-token' ELSE pricing_rule_value END,
       COALESCE(base_source, ''),
       round(COALESCE(effective_prompt, 0) * 1000000)::bigint,
       round(COALESCE(effective_cache, 0) * 1000000)::bigint,
       round(COALESCE(effective_cache_read, 0) * 1000000)::bigint,
       round(COALESCE(effective_cache_creation, 0) * 1000000)::bigint,
       round(COALESCE(effective_completion, 0) * 1000000)::bigint,
       residual_cached_tokens_value,
       round((
         COALESCE(normalized_uncached_input_tokens, 0) * COALESCE(effective_prompt, 0)
         + residual_cached_tokens_value * COALESCE(effective_cache, 0)
         + GREATEST(COALESCE(cache_read_tokens, 0), 0) * COALESCE(effective_cache_read, 0)
         + COALESCE(normalized_cache_creation_tokens, 0) * COALESCE(effective_cache_creation, 0)
       ) * input_multiplier * service_multiplier
       + COALESCE(output_tokens, 0) * COALESCE(effective_completion, 0)
         * output_multiplier * service_multiplier)::bigint,
       encode(sha256(convert_to(pricing_config_json_value, 'UTF8')), 'hex'),
       pricing_config_json_value,
       validation_error_value
  FROM evaluated;
