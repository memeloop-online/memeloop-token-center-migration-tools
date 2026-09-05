-- PostgreSQL cannot enforce an id-only unique constraint on a range-partitioned
-- table.  These small, non-partitioned tables are the global ownership records;
-- the timestamp then routes point reads and writes to exactly one leaf partition.
CREATE TABLE IF NOT EXISTS request_record_locators (
    id TEXT PRIMARY KEY,
    created_at BIGINT NOT NULL,
    tenant_id TEXT NOT NULL,
    key_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS request_event_locators (
    id TEXT PRIMARY KEY,
    created_at BIGINT NOT NULL,
    tenant_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    request_id TEXT NOT NULL
);

-- Deliberately do not use ON CONFLICT here.  Any historical duplicate id,
-- including a duplicate spread across PostgreSQL partitions, aborts the whole
-- migration instead of choosing an arbitrary row.
INSERT INTO request_record_locators (id, created_at, tenant_id, key_id)
SELECT id, created_at, tenant_id, key_id
FROM request_records;

INSERT INTO request_event_locators (id, created_at, tenant_id, key_id, request_id)
SELECT event_id, event_at, tenant_id, key_id, request_id
FROM request_events;
