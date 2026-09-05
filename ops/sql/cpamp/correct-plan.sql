BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;

WITH candidates AS MATERIALIZED (
  SELECT e.*, t.id AS tenant_id, l.target_request_id, l.source_digest AS old_source_digest,
         r.key_id, r.created_at, r.input_tokens AS old_input_tokens,
         r.cached_input_tokens AS old_cached_input_tokens,
         r.cache_write_tokens AS old_cache_write_tokens,
         r.service_tier AS old_service_tier, r.cost_micros AS old_cost_micros,
         r.currency, r.reservation_id
    FROM cpamp_import_evaluated e
    JOIN tenants t ON t.external_id = :'tenant_external_id'
    JOIN import_request_links l
      ON l.tenant_id = t.id AND l.source = :'import_source'
     AND l.external_event_hash = e.event_hash
    JOIN request_record_locators locator
      ON locator.id = l.target_request_id AND locator.tenant_id = t.id
    JOIN request_records r
      ON r.id = locator.id AND r.created_at = locator.created_at
     AND r.tenant_id = locator.tenant_id AND r.key_id = locator.key_id
    LEFT JOIN cpamp_import_correction_audit audit
      ON audit.tenant_id = t.id AND audit.source = :'import_source'
     AND audit.external_event_hash = e.event_hash
     AND audit.correction_revision = 'cpamp-cache-pricing-v2'
   WHERE l.source_digest = e.legacy_source_digest
     AND l.source_digest <> e.source_digest
     AND audit.external_event_hash IS NULL
)
SELECT 'candidate_events=' || count(*)
       || ' non_usd_candidates=' || count(*) FILTER (WHERE currency <> 'USD')
       || ' live_candidates=' || count(*) FILTER (
            WHERE reservation_id <> 'cpamp-import:' || event_hash)
       || ' old_cost_micros=' || COALESCE(sum(old_cost_micros), 0)
       || ' new_cost_micros=' || COALESCE(sum(cost_micros), 0)
  FROM candidates;

WITH candidates AS MATERIALIZED (
  SELECT e.*, r.key_id, r.created_at, r.input_tokens AS old_input_tokens,
         r.cached_input_tokens AS old_cached_input_tokens,
         r.cache_write_tokens AS old_cache_write_tokens,
         r.cost_micros AS old_cost_micros
    FROM cpamp_import_evaluated e
    JOIN tenants t ON t.external_id = :'tenant_external_id'
    JOIN import_request_links l
      ON l.tenant_id = t.id AND l.source = :'import_source'
     AND l.external_event_hash = e.event_hash
    JOIN request_record_locators locator
      ON locator.id = l.target_request_id AND locator.tenant_id = t.id
    JOIN request_records r
      ON r.id = locator.id AND r.created_at = locator.created_at
     AND r.tenant_id = locator.tenant_id AND r.key_id = locator.key_id
    LEFT JOIN cpamp_import_correction_audit audit
      ON audit.tenant_id = t.id AND audit.source = :'import_source'
     AND audit.external_event_hash = e.event_hash
     AND audit.correction_revision = 'cpamp-cache-pricing-v2'
   WHERE l.source_digest = e.legacy_source_digest
     AND l.source_digest <> e.source_digest
     AND audit.external_event_hash IS NULL
)
SELECT to_char(to_timestamp(created_at / 1000.0) AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS utc_day,
       model, key_id, count(*) AS events,
       sum(old_input_tokens) AS old_total_input,
       sum(normalized_total_input_tokens) AS new_total_input,
       sum(old_cached_input_tokens) AS old_cache_read,
       sum(normalized_cache_read_tokens) AS new_cache_read,
       sum(old_cache_write_tokens) AS old_cache_write,
       sum(normalized_cache_creation_tokens) AS new_cache_write,
       sum(old_cost_micros) AS old_cost_micros,
       sum(cost_micros) AS new_cost_micros
  FROM candidates
 GROUP BY 1, model, key_id
 ORDER BY 1, model, key_id;

ROLLBACK;
