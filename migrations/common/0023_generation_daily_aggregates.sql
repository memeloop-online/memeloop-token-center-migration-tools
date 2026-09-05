ALTER TABLE generation_jobs ADD COLUMN stats_aggregated_at BIGINT;

CREATE TABLE generation_stats_facts (
    job_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    model TEXT NOT NULL,
    status_class TEXT NOT NULL,
    error_code TEXT NOT NULL,
    upstream_account_id TEXT NOT NULL,
    duration_ms BIGINT NOT NULL,
    cost_micros BIGINT NOT NULL,
    billed_units BIGINT NOT NULL
);

CREATE INDEX generation_stats_facts_tenant_created_idx
    ON generation_stats_facts (tenant_id, created_at, key_id, model, status_class);

CREATE INDEX generation_stats_facts_key_created_idx
    ON generation_stats_facts (key_id, created_at, model, status_class);

INSERT INTO generation_stats_facts (
    job_id,
    tenant_id,
    key_id,
    created_at,
    model,
    status_class,
    error_code,
    upstream_account_id,
    duration_ms,
    cost_micros,
    billed_units
)
SELECT id,
       tenant_id,
       key_id,
       created_at,
       public_model,
       CASE WHEN status = 'succeeded' THEN 'success' ELSE 'failure' END,
       COALESCE(error_code, ''),
       COALESCE(upstream_account_id, ''),
       CASE
           WHEN completed_at IS NULL OR completed_at < created_at THEN 0
           ELSE completed_at - created_at
       END,
       cost_micros,
       COALESCE(billed_units, 0)
FROM generation_jobs
WHERE status IN ('succeeded', 'failed', 'cancelled')
ON CONFLICT (job_id) DO NOTHING;

CREATE TABLE generation_daily_aggregates (
    tenant_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    day_bucket BIGINT NOT NULL,
    model TEXT NOT NULL,
    status_class TEXT NOT NULL,
    error_code TEXT NOT NULL,
    upstream_account_id TEXT NOT NULL,
    requests BIGINT NOT NULL,
    billed_units BIGINT NOT NULL,
    cost_micros BIGINT NOT NULL,
    PRIMARY KEY (
        tenant_id,
        key_id,
        day_bucket,
        model,
        status_class,
        error_code,
        upstream_account_id
    )
);

CREATE INDEX generation_daily_aggregates_tenant_day_idx
    ON generation_daily_aggregates (tenant_id, day_bucket, model, status_class);

CREATE INDEX generation_daily_aggregates_key_day_idx
    ON generation_daily_aggregates (key_id, day_bucket, model, status_class);

INSERT INTO generation_daily_aggregates (
    tenant_id,
    key_id,
    day_bucket,
    model,
    status_class,
    error_code,
    upstream_account_id,
    requests,
    billed_units,
    cost_micros
)
SELECT tenant_id,
       key_id,
       created_at / 86400000,
       public_model,
       CASE WHEN status = 'succeeded' THEN 'success' ELSE 'failure' END,
       COALESCE(error_code, ''),
       COALESCE(upstream_account_id, ''),
       COUNT(*),
       COALESCE(SUM(COALESCE(billed_units, 0)), 0),
       COALESCE(SUM(cost_micros), 0)
FROM generation_jobs
WHERE status IN ('succeeded', 'failed', 'cancelled')
GROUP BY tenant_id,
         key_id,
         created_at / 86400000,
         public_model,
         CASE WHEN status = 'succeeded' THEN 'success' ELSE 'failure' END,
         COALESCE(error_code, ''),
         COALESCE(upstream_account_id, '')
ON CONFLICT (
    tenant_id,
    key_id,
    day_bucket,
    model,
    status_class,
    error_code,
    upstream_account_id
) DO UPDATE SET
    requests = generation_daily_aggregates.requests + excluded.requests,
    billed_units = generation_daily_aggregates.billed_units + excluded.billed_units,
    cost_micros = generation_daily_aggregates.cost_micros + excluded.cost_micros;

UPDATE generation_jobs
SET stats_aggregated_at = COALESCE(completed_at, updated_at, created_at)
WHERE status IN ('succeeded', 'failed', 'cancelled')
  AND stats_aggregated_at IS NULL;

CREATE INDEX generation_jobs_unaggregated_terminal_idx
    ON generation_jobs (created_at, id)
    WHERE stats_aggregated_at IS NULL
      AND status IN ('succeeded', 'failed', 'cancelled');

CREATE INDEX generation_jobs_pending_stats_fallback_idx
    ON generation_jobs (tenant_id, created_at, key_id, public_model, upstream_account_id)
    WHERE status IN ('queued', 'running');
