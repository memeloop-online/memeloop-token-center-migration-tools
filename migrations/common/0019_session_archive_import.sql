CREATE TABLE IF NOT EXISTS import_request_links (
    tenant_id TEXT NOT NULL,
    source TEXT NOT NULL,
    external_event_hash TEXT NOT NULL,
    external_request_id TEXT NOT NULL,
    source_key_hash TEXT NOT NULL,
    target_request_id TEXT NOT NULL,
    source_created_at BIGINT NOT NULL,
    source_model TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, source, external_event_hash),
    UNIQUE (tenant_id, source, target_request_id)
);
CREATE INDEX IF NOT EXISTS import_request_links_external_request_idx
    ON import_request_links (tenant_id, source, external_request_id);

CREATE TABLE IF NOT EXISTS session_archive_import_records (
    tenant_id TEXT NOT NULL,
    source TEXT NOT NULL,
    external_request_id TEXT NOT NULL,
    target_request_id TEXT NOT NULL,
    external_event_hash TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    request_digest TEXT,
    response_digest TEXT,
    request_object TEXT,
    response_object TEXT,
    source_started_at BIGINT NOT NULL,
    imported_at BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, source, external_request_id),
    UNIQUE (tenant_id, source, target_request_id)
);
CREATE INDEX IF NOT EXISTS session_archive_import_records_watermark_idx
    ON session_archive_import_records (tenant_id, source, source_started_at, external_request_id);

CREATE TABLE IF NOT EXISTS session_archive_import_checkpoints (
    tenant_id TEXT NOT NULL,
    source TEXT NOT NULL,
    watermark_ms BIGINT NOT NULL,
    watermark_request_id TEXT NOT NULL,
    imported_records BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, source)
);
