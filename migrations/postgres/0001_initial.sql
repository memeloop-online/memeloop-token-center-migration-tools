CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    external_id TEXT NOT NULL UNIQUE,
    created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS principals (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    external_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    UNIQUE(tenant_id, external_id)
);
CREATE TABLE IF NOT EXISTS credit_accounts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    currency TEXT NOT NULL,
    available_micros BIGINT NOT NULL,
    reserved_micros BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS key_records (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    currency TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    status TEXT NOT NULL,
    credential_generation BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS key_credentials (
    id TEXT PRIMARY KEY,
    key_id TEXT NOT NULL,
    generation BIGINT NOT NULL,
    secret_hash BYTEA NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    revoked_at BIGINT,
    UNIQUE(key_id, generation)
);
CREATE TABLE IF NOT EXISTS ledger_entries (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    key_id TEXT,
    kind TEXT NOT NULL,
    amount_micros BIGINT NOT NULL,
    currency TEXT NOT NULL,
    source TEXT NOT NULL,
    idempotency_key TEXT UNIQUE,
    created_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS model_prices (
    id TEXT PRIMARY KEY,
    model TEXT NOT NULL,
    currency TEXT NOT NULL,
    input_micros_per_million BIGINT NOT NULL,
    output_micros_per_million BIGINT NOT NULL,
    source TEXT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE(model, currency)
);
CREATE TABLE IF NOT EXISTS upstream_accounts (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    driver TEXT NOT NULL,
    auth_kind TEXT NOT NULL,
    config_json TEXT NOT NULL,
    status TEXT NOT NULL,
    credential_generation BIGINT NOT NULL,
    oauth_session_id TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE(tenant_id, name)
);
CREATE TABLE IF NOT EXISTS upstream_credentials (
    id TEXT PRIMARY KEY,
    upstream_account_id TEXT NOT NULL,
    generation BIGINT NOT NULL,
    credential_ciphertext TEXT NOT NULL,
    expires_at BIGINT,
    created_at BIGINT NOT NULL,
    revoked_at BIGINT,
    UNIQUE(upstream_account_id, generation)
);
CREATE TABLE IF NOT EXISTS model_routes (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    public_model TEXT NOT NULL,
    upstream_account_id TEXT NOT NULL,
    upstream_model TEXT NOT NULL,
    protocol TEXT NOT NULL,
    priority BIGINT NOT NULL,
    enabled BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE(tenant_id, public_model, protocol, priority)
);
CREATE TABLE IF NOT EXISTS usage_reservations (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    price_id TEXT NOT NULL,
    reserved_micros BIGINT NOT NULL,
    reserved_tokens BIGINT NOT NULL,
    rate_window_start BIGINT NOT NULL,
    actual_micros BIGINT,
    status TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    settled_at BIGINT
);
CREATE TABLE IF NOT EXISTS rate_limit_windows (
    key_id TEXT NOT NULL,
    window_start BIGINT NOT NULL,
    requests BIGINT NOT NULL,
    tokens BIGINT NOT NULL,
    PRIMARY KEY(key_id, window_start)
);
CREATE TABLE IF NOT EXISTS key_runtime_state (
    key_id TEXT PRIMARY KEY,
    active_requests BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS request_records (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    completed_at BIGINT,
    protocol TEXT NOT NULL,
    model TEXT NOT NULL,
    status_code BIGINT,
    duration_ms BIGINT,
    input_tokens BIGINT NOT NULL,
    output_tokens BIGINT NOT NULL,
    cost_micros BIGINT NOT NULL,
    error_code TEXT,
    request_object TEXT NOT NULL,
    response_object TEXT,
    reservation_id TEXT NOT NULL,
    conversation_cluster_id TEXT,
    upstream_account_id TEXT,
    model_route_id TEXT
) PARTITION BY RANGE (created_at);
CREATE TABLE IF NOT EXISTS usage_daily_aggregates (
    key_id TEXT NOT NULL,
    day_bucket BIGINT NOT NULL,
    model TEXT NOT NULL,
    status_class TEXT NOT NULL,
    error_code TEXT NOT NULL,
    requests BIGINT NOT NULL,
    input_tokens BIGINT NOT NULL,
    output_tokens BIGINT NOT NULL,
    cost_micros BIGINT NOT NULL,
    PRIMARY KEY(key_id, day_bucket, model, status_class, error_code)
);
CREATE TABLE IF NOT EXISTS semantic_atoms (
    tenant_id TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    instance_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    kind TEXT NOT NULL,
    content_json TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY(tenant_id, content_hash)
);
CREATE TABLE IF NOT EXISTS context_nodes (
    tenant_id TEXT NOT NULL,
    node_hash TEXT NOT NULL,
    parent_hash TEXT,
    atom_hash TEXT NOT NULL,
    depth BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY(tenant_id, node_hash)
);
CREATE TABLE IF NOT EXISTS conversation_clusters (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    explicit_session_id TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS conversation_observations (
    id TEXT PRIMARY KEY,
    cluster_id TEXT NOT NULL,
    request_id TEXT NOT NULL UNIQUE,
    key_id TEXT NOT NULL,
    leaf_node_hash TEXT,
    atom_hashes_json TEXT NOT NULL,
    explicit_session_id TEXT,
    client_name TEXT,
    created_at BIGINT NOT NULL,
    inference_version BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS conversation_edges (
    id TEXT PRIMARY KEY,
    cluster_id TEXT NOT NULL,
    from_observation_id TEXT,
    to_observation_id TEXT NOT NULL,
    relation_kind TEXT NOT NULL,
    confidence_millis BIGINT NOT NULL,
    evidence_json TEXT NOT NULL,
    pinned BIGINT NOT NULL DEFAULT 0,
    inference_version BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

