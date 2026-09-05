CREATE TABLE IF NOT EXISTS generation_prices (
    id TEXT PRIMARY KEY,
    model TEXT NOT NULL,
    currency TEXT NOT NULL,
    billing_unit TEXT NOT NULL,
    micros_per_unit BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE(model, currency)
);

CREATE TABLE IF NOT EXISTS generation_jobs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    upstream_account_id TEXT NOT NULL,
    reservation_id TEXT NOT NULL,
    public_model TEXT NOT NULL,
    upstream_model TEXT NOT NULL,
    driver TEXT NOT NULL,
    status TEXT NOT NULL,
    request_object TEXT NOT NULL,
    upstream_job_id TEXT,
    result_json TEXT,
    error_code TEXT,
    estimated_units BIGINT NOT NULL,
    billed_units BIGINT,
    cost_micros BIGINT NOT NULL DEFAULT 0,
    attempt_count BIGINT NOT NULL DEFAULT 0,
    failure_count BIGINT NOT NULL DEFAULT 0,
    next_attempt_at BIGINT NOT NULL,
    lease_owner TEXT,
    lease_expires_at BIGINT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    completed_at BIGINT
);

CREATE INDEX IF NOT EXISTS generation_jobs_key_created_idx
    ON generation_jobs (key_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS generation_jobs_tenant_status_created_idx
    ON generation_jobs (tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS generation_jobs_claim_idx
    ON generation_jobs (next_attempt_at, created_at, id)
    WHERE status IN ('queued', 'running');
CREATE INDEX IF NOT EXISTS generation_jobs_upstream_idx
    ON generation_jobs (upstream_account_id, upstream_job_id)
    WHERE upstream_job_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS generation_jobs_reservation_idx
    ON generation_jobs (reservation_id);
CREATE INDEX IF NOT EXISTS generation_jobs_created_brin_idx
    ON generation_jobs USING BRIN (created_at) WITH (pages_per_range = 32);
CREATE INDEX IF NOT EXISTS request_records_reservation_idx
    ON request_records (reservation_id);
CREATE INDEX IF NOT EXISTS usage_reservations_orphan_scan_idx
    ON usage_reservations (created_at, id)
    WHERE status = 'reserved';
