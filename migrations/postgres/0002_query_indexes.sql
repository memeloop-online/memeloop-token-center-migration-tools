CREATE INDEX IF NOT EXISTS request_records_key_time_idx
    ON request_records (key_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS request_records_id_idx
    ON request_records (id);
CREATE INDEX IF NOT EXISTS request_records_tenant_time_idx
    ON request_records (tenant_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS request_records_tenant_model_time_idx
    ON request_records (tenant_id, model, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS request_records_error_idx
    ON request_records (tenant_id, error_code, created_at DESC, id DESC)
    WHERE error_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS request_records_status_time_idx
    ON request_records (tenant_id, status_code, created_at DESC, id DESC)
    WHERE status_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS request_records_upstream_time_idx
    ON request_records (upstream_account_id, created_at DESC, id DESC)
    WHERE upstream_account_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS request_records_conversation_time_idx
    ON request_records (key_id, conversation_cluster_id, created_at ASC, id ASC)
    WHERE conversation_cluster_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS request_records_created_brin_idx
    ON request_records USING BRIN (created_at) WITH (pages_per_range = 32);
CREATE INDEX IF NOT EXISTS ledger_entries_key_time_idx
    ON ledger_entries (key_id, created_at DESC)
    WHERE key_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS usage_reservations_key_status_idx
    ON usage_reservations (key_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS rate_limit_windows_expiry_idx
    ON rate_limit_windows (window_start);
CREATE INDEX IF NOT EXISTS upstream_accounts_tenant_driver_idx
    ON upstream_accounts (tenant_id, driver, status);
CREATE INDEX IF NOT EXISTS upstream_credentials_active_idx
    ON upstream_credentials (upstream_account_id, revoked_at, generation DESC);
CREATE INDEX IF NOT EXISTS model_routes_lookup_idx
    ON model_routes (tenant_id, public_model, protocol, enabled, priority);
CREATE INDEX IF NOT EXISTS usage_daily_key_day_idx
    ON usage_daily_aggregates (key_id, day_bucket DESC);
CREATE INDEX IF NOT EXISTS conversation_clusters_principal_time_idx
    ON conversation_clusters (tenant_id, principal_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS conversation_observations_key_time_idx
    ON conversation_observations (key_id, created_at DESC);
CREATE INDEX IF NOT EXISTS conversation_observations_cluster_time_idx
    ON conversation_observations (cluster_id, created_at ASC);
CREATE INDEX IF NOT EXISTS conversation_edges_cluster_target_idx
    ON conversation_edges (cluster_id, to_observation_id);

