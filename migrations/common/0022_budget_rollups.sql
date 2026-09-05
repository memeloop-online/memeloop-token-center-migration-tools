CREATE TABLE IF NOT EXISTS key_budget_state (
    key_id TEXT PRIMARY KEY,
    settled_lifetime_micros BIGINT NOT NULL,
    reserved_micros BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS key_budget_daily_rollups (
    key_id TEXT NOT NULL,
    day_bucket BIGINT NOT NULL,
    settled_micros BIGINT NOT NULL,
    PRIMARY KEY(key_id, day_bucket)
);

-- These rows retain only the boundary-day detail needed to evaluate an exact
-- rolling 7x24-hour budget. The worker can remove rows older than that boundary.
-- usage_reservations and ledger_entries remain the durable audit trail.
CREATE TABLE IF NOT EXISTS key_budget_usage_events (
    usage_entry_id TEXT PRIMARY KEY,
    reservation_id TEXT,
    key_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    amount_micros BIGINT NOT NULL,
    settled_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS key_budget_usage_events_key_time_idx
    ON key_budget_usage_events (key_id, settled_at, usage_entry_id);

CREATE INDEX IF NOT EXISTS key_budget_daily_rollups_day_idx
    ON key_budget_daily_rollups (day_bucket, key_id);

CREATE TABLE IF NOT EXISTS account_usage_state (
    account_id TEXT PRIMARY KEY,
    settled_lifetime_micros BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

ALTER TABLE ledger_entries ADD COLUMN account_usage_micros_snapshot BIGINT;

INSERT INTO key_budget_state (
    key_id,
    settled_lifetime_micros,
    reserved_micros,
    updated_at
)
SELECT k.id,
       COALESCE(l.settled_micros, 0),
       COALESCE(r.reserved_micros, 0),
       k.updated_at
FROM key_records k
LEFT JOIN (
    SELECT key_id,
           SUM(CASE WHEN amount_micros < 0 THEN -amount_micros ELSE 0 END) AS settled_micros
    FROM ledger_entries
    WHERE kind = 'usage' AND key_id IS NOT NULL
    GROUP BY key_id
) l ON l.key_id = k.id
LEFT JOIN (
    SELECT key_id, SUM(reserved_micros) AS reserved_micros
    FROM usage_reservations
    WHERE status = 'reserved'
    GROUP BY key_id
) r ON r.key_id = k.id
ON CONFLICT(key_id) DO NOTHING;

INSERT INTO key_budget_daily_rollups (key_id, day_bucket, settled_micros)
SELECT key_id,
       created_at / 86400000,
       SUM(CASE WHEN amount_micros < 0 THEN -amount_micros ELSE 0 END)
FROM ledger_entries
WHERE kind = 'usage' AND key_id IS NOT NULL
GROUP BY key_id, created_at / 86400000
ON CONFLICT(key_id, day_bucket) DO NOTHING;

INSERT INTO key_budget_usage_events (
    usage_entry_id,
    reservation_id,
    key_id,
    account_id,
    amount_micros,
    settled_at
)
SELECT l.id,
       r.id,
       l.key_id,
       l.account_id,
       CASE WHEN l.amount_micros < 0 THEN -l.amount_micros ELSE 0 END,
       l.created_at
FROM ledger_entries l
LEFT JOIN usage_reservations r ON r.id = l.source
WHERE l.kind = 'usage' AND l.key_id IS NOT NULL
ON CONFLICT(usage_entry_id) DO NOTHING;

INSERT INTO account_usage_state (account_id, settled_lifetime_micros, updated_at)
SELECT a.id,
       COALESCE(l.settled_micros, 0),
       a.updated_at
FROM credit_accounts a
LEFT JOIN (
    SELECT account_id,
           SUM(CASE WHEN amount_micros < 0 THEN -amount_micros ELSE 0 END) AS settled_micros
    FROM ledger_entries
    WHERE kind = 'usage'
    GROUP BY account_id
) l ON l.account_id = a.id
ON CONFLICT(account_id) DO NOTHING;

-- A grant is reversible only while the account's settled usage cumulative is
-- unchanged from grant creation. This one-time correlated backfill preserves
-- the legacy "usage at or after grant time" rule without a hot-path ledger scan.
UPDATE ledger_entries
SET account_usage_micros_snapshot = (
    SELECT COALESCE(
        SUM(CASE WHEN usage.amount_micros < 0 THEN -usage.amount_micros ELSE 0 END),
        0
    )
    FROM ledger_entries usage
    WHERE usage.account_id = ledger_entries.account_id
      AND usage.kind = 'usage'
      AND usage.created_at < ledger_entries.created_at
)
WHERE kind = 'grant' AND account_usage_micros_snapshot IS NULL;
