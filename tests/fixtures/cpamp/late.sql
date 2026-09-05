INSERT INTO usage_events
  (event_hash, request_id, timestamp_ms, provider, model, endpoint,
   api_key_hash, input_tokens, output_tokens, latency_ms, failed,
   fail_status_code, fail_summary, requested_model, resolved_model,
   reasoning_effort, service_tier, request_service_tier,
   response_service_tier, cache_input_mode, reasoning_tokens,
   cached_tokens, cache_tokens, cache_read_tokens, cache_creation_tokens,
   normalized_uncached_input_tokens, normalized_total_input_tokens,
   normalized_cache_read_tokens, normalized_cache_creation_tokens,
   total_tokens, ttft_ms)
VALUES
  ('fixture-event-late-overlap', 'legacy-request-late', 299000000, 'openai', 'fixture-model', '/v1/responses', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 19, 7, 90, 0, NULL, NULL, 'fixture-model', 'fixture-model', 'medium', 'default', 'default', 'default', 'included_in_input', 0, 0, 0, 0, 0, 19, 19, 0, 0, 26, 15),
  ('fixture-event-new-watermark', 'legacy-request-new', 400000000, 'anthropic', 'fixture-model', '/v1/messages', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 23, 11, 210, 0, NULL, NULL, 'fixture-model', 'fixture-model', 'medium', 'default', 'default', 'default', 'separate_from_input', 0, 0, 0, 0, 0, 23, 23, 0, 0, 34, 25);
