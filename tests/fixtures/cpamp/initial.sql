CREATE TABLE usage_events (
  event_hash TEXT NOT NULL,
  request_id TEXT NOT NULL,
  timestamp_ms INTEGER NOT NULL,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  api_key_hash TEXT NOT NULL,
  input_tokens INTEGER NOT NULL,
  output_tokens INTEGER NOT NULL,
  latency_ms INTEGER NOT NULL,
  failed INTEGER NOT NULL,
  fail_status_code INTEGER,
  fail_summary TEXT,
  requested_model TEXT,
  resolved_model TEXT,
  reasoning_effort TEXT,
  service_tier TEXT,
  request_service_tier TEXT,
  response_service_tier TEXT,
  cache_input_mode TEXT,
  reasoning_tokens INTEGER NOT NULL DEFAULT 0,
  cached_tokens INTEGER NOT NULL DEFAULT 0,
  cache_tokens INTEGER NOT NULL DEFAULT 0,
  cache_read_tokens INTEGER NOT NULL DEFAULT 0,
  cache_creation_tokens INTEGER NOT NULL DEFAULT 0,
  normalized_uncached_input_tokens INTEGER,
  normalized_total_input_tokens INTEGER,
  normalized_cache_read_tokens INTEGER,
  normalized_cache_creation_tokens INTEGER,
  total_tokens INTEGER NOT NULL DEFAULT 0,
  ttft_ms INTEGER
);

CREATE TABLE api_key_aliases (
  api_key_hash TEXT PRIMARY KEY,
  alias TEXT NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

CREATE TABLE model_prices (
  model TEXT PRIMARY KEY,
  prompt_per_1m REAL NOT NULL,
  completion_per_1m REAL NOT NULL,
  cache_per_1m REAL NOT NULL,
  cache_read_per_1m REAL NOT NULL,
  cache_creation_per_1m REAL NOT NULL,
  prompt_configured INTEGER NOT NULL,
  completion_configured INTEGER NOT NULL,
  cache_read_configured INTEGER NOT NULL,
  cache_creation_configured INTEGER NOT NULL,
  source TEXT NOT NULL,
  source_model_id TEXT,
  updated_at_ms INTEGER NOT NULL
);

CREATE TABLE model_price_context_tiers (
  model TEXT NOT NULL,
  threshold_tokens INTEGER NOT NULL,
  prompt_per_1m REAL NOT NULL,
  completion_per_1m REAL NOT NULL,
  cache_per_1m REAL NOT NULL,
  cache_read_per_1m REAL NOT NULL,
  cache_creation_per_1m REAL NOT NULL,
  prompt_configured INTEGER NOT NULL,
  completion_configured INTEGER NOT NULL,
  cache_configured INTEGER NOT NULL,
  cache_read_configured INTEGER NOT NULL,
  cache_creation_configured INTEGER NOT NULL,
  PRIMARY KEY (model, threshold_tokens)
);

CREATE TABLE model_price_service_tiers (
  model TEXT NOT NULL,
  mode TEXT NOT NULL,
  service_tier TEXT NOT NULL,
  prompt_per_1m REAL NOT NULL,
  completion_per_1m REAL NOT NULL,
  cache_per_1m REAL NOT NULL,
  cache_read_per_1m REAL NOT NULL,
  cache_creation_per_1m REAL NOT NULL,
  prompt_configured INTEGER NOT NULL,
  completion_configured INTEGER NOT NULL,
  cache_configured INTEGER NOT NULL,
  cache_read_configured INTEGER NOT NULL,
  cache_creation_configured INTEGER NOT NULL,
  PRIMARY KEY (model, mode, service_tier)
);

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
  ('fixture-event-initial-a', 'legacy-request-a', 200000000, 'openai', 'fixture-model', '/v1/chat/completions', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 11, 3, 120, 0, NULL, NULL, 'fixture-model', 'fixture-model', 'medium', 'default', 'default', 'default', 'included_in_input', 0, 0, 0, 0, 0, 11, 11, 0, 0, 14, 20),
  ('fixture-event-initial-b', 'legacy-request-b', 300000000, 'openai', 'fixture-model', '/v1/chat/completions', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 17, 5, 180, 1, 502, 'fixture upstream failure', 'fixture-model', 'fixture-model', 'high', 'default', 'default', 'default', 'included_in_input', 0, 0, 0, 0, 0, 17, 17, 0, 0, 22, 30);

INSERT INTO api_key_aliases VALUES
  ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'Fixture Linux Codex', 300000000);

INSERT INTO model_prices VALUES
  ('fixture-model', 2.0, 4.0, 0.5, 0.25, 3.0, 1, 1, 1, 1, 'fixture', 'fixture-model', 300000000);
