BEGIN;
SELECT set_config('mtc.cpamp_reset_tenant', :'tenant_external_id', true);
SELECT set_config('mtc.cpamp_reset_source', :'import_source', true);
DO $reset_guard$
BEGIN
  IF EXISTS (
    SELECT 1 FROM tenants t
    JOIN upstream_accounts u ON u.tenant_id = t.id
    WHERE t.external_id = current_setting('mtc.cpamp_reset_tenant')
  ) OR EXISTS (
    SELECT 1 FROM tenants t
    JOIN model_routes r ON r.tenant_id = t.id
    WHERE t.external_id = current_setting('mtc.cpamp_reset_tenant')
  ) THEN
    RAISE EXCEPTION 'CPAMP reset refused: tenant has provider accounts or model routes not owned by the usage importer';
  END IF;
  IF EXISTS (
    SELECT 1 FROM cpamp_import_checkpoints
    WHERE tenant_external_id = current_setting('mtc.cpamp_reset_tenant')
      AND source <> current_setting('mtc.cpamp_reset_source')
  ) OR EXISTS (
    SELECT 1 FROM import_request_links l
    JOIN tenants t ON t.id = l.tenant_id
    WHERE t.external_id = current_setting('mtc.cpamp_reset_tenant')
      AND l.source <> current_setting('mtc.cpamp_reset_source')
  ) THEN
    RAISE EXCEPTION 'CPAMP reset refused: tenant contains a different import source';
  END IF;
  IF EXISTS (
    SELECT 1 FROM principals p JOIN tenants t ON t.id = p.tenant_id
    WHERE t.external_id = current_setting('mtc.cpamp_reset_tenant')
      AND p.external_id <> 'cpamp-import'
  ) OR EXISTS (
    SELECT 1 FROM key_records k JOIN tenants t ON t.id = k.tenant_id
    LEFT JOIN principals p ON p.id = k.principal_id AND p.tenant_id = k.tenant_id
    WHERE t.external_id = current_setting('mtc.cpamp_reset_tenant')
      AND COALESCE(p.external_id, '') <> 'cpamp-import'
  ) OR EXISTS (
    SELECT 1 FROM credit_accounts a JOIN tenants t ON t.id = a.tenant_id
    LEFT JOIN principals p ON p.id = a.principal_id AND p.tenant_id = a.tenant_id
    WHERE t.external_id = current_setting('mtc.cpamp_reset_tenant')
      AND COALESCE(p.external_id, '') <> 'cpamp-import'
  ) THEN
    RAISE EXCEPTION 'CPAMP reset refused: tenant contains identities not owned by the usage importer';
  END IF;
END
$reset_guard$;
DELETE FROM request_event_locators
 WHERE tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id');
DELETE FROM request_events
 WHERE tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id');
DELETE FROM conversation_edges
 WHERE cluster_id IN (
   SELECT id FROM conversation_clusters
    WHERE tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id')
 );
DELETE FROM conversation_observations
 WHERE key_id IN (
   SELECT k.id FROM key_records k JOIN tenants t ON t.id = k.tenant_id
    WHERE t.external_id = :'tenant_external_id'
 );
DELETE FROM conversation_clusters
 WHERE tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id');
DELETE FROM context_nodes
 WHERE tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id');
DELETE FROM semantic_atoms
 WHERE tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id');
DELETE FROM generation_jobs
 WHERE tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id');
DELETE FROM usage_analysis_hourly
 WHERE tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id');
DELETE FROM usage_analysis_daily
 WHERE tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id');
DELETE FROM request_daily_aggregates
 WHERE tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id');
DELETE FROM request_stats_facts
 WHERE tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id');
DELETE FROM usage_daily_aggregates
 WHERE key_id IN (
   SELECT k.id FROM key_records k JOIN tenants t ON t.id = k.tenant_id
    WHERE t.external_id = :'tenant_external_id'
 ) OR key_id LIKE 'cpamp-key-%';
DELETE FROM request_record_locators
 WHERE tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id');
DELETE FROM cpamp_import_correction_audit
 WHERE tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id')
   AND source = :'import_source';
DELETE FROM cpamp_import_event_provenance
 WHERE tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id')
   AND source = :'import_source';
DELETE FROM request_records
 WHERE tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id');
DELETE FROM key_credentials
 WHERE key_id IN (
   SELECT k.id FROM key_records k JOIN tenants t ON t.id = k.tenant_id
    WHERE t.external_id = :'tenant_external_id'
 );
DELETE FROM rate_limit_windows
 WHERE key_id IN (
   SELECT k.id FROM key_records k JOIN tenants t ON t.id = k.tenant_id
    WHERE t.external_id = :'tenant_external_id'
 );
DELETE FROM key_runtime_state
 WHERE key_id IN (
   SELECT k.id FROM key_records k JOIN tenants t ON t.id = k.tenant_id
    WHERE t.external_id = :'tenant_external_id'
 );
DELETE FROM usage_reservations
 WHERE account_id IN (
   SELECT a.id FROM credit_accounts a JOIN tenants t ON t.id = a.tenant_id
    WHERE t.external_id = :'tenant_external_id'
 );
DELETE FROM ledger_entries
 WHERE account_id IN (
   SELECT a.id FROM credit_accounts a JOIN tenants t ON t.id = a.tenant_id
    WHERE t.external_id = :'tenant_external_id'
 );
DELETE FROM account_usage_state
 WHERE account_id IN (
   SELECT a.id FROM credit_accounts a JOIN tenants t ON t.id = a.tenant_id
    WHERE t.external_id = :'tenant_external_id'
 );
DELETE FROM key_records
 WHERE tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id');
DELETE FROM credit_accounts
 WHERE tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id');
DELETE FROM principals
 WHERE tenant_id IN (SELECT id FROM tenants WHERE external_id = :'tenant_external_id');
DELETE FROM tenants WHERE external_id = :'tenant_external_id';
DELETE FROM cpamp_import_checkpoints
 WHERE tenant_external_id = :'tenant_external_id' AND source = :'import_source';
COMMIT;
