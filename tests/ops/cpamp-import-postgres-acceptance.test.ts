import assert from "node:assert/strict";
import { mkdirSync, readFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import test from "node:test";

const requiredNames = ["ACCEPTANCE_SCHEMA", "ACCEPTANCE_RUN_ID", "PGHOST", "PGUSER", "PGPASSWORD", "PGDATABASE"] as const;
const configured = requiredNames.every((name) => Boolean(process.env[name]));

type Variables = Record<string, string>;

function run(command: string, args: string[], input?: string, env: NodeJS.ProcessEnv = process.env): SpawnSyncReturns<string> {
  return spawnSync(command, args, {
    encoding: "utf8",
    env,
    input,
    maxBuffer: 16 * 1024 * 1024,
    shell: false,
  });
}

function requireSuccess(result: SpawnSyncReturns<string>, label: string): string {
  assert.equal(result.error, undefined, `${label}: ${result.error?.message ?? "spawn failed"}`);
  assert.equal(result.status, 0, `${label}: ${result.stderr}`);
  return result.stdout.trim();
}

test("CPAMP import is transactional, replay-safe, bounded by watermarks, and tenant/source isolated", { skip: !configured }, () => {
  const schema = process.env.ACCEPTANCE_SCHEMA!;
  const runId = process.env.ACCEPTANCE_RUN_ID!;
  const workRoot = process.env.ACCEPTANCE_WORK_ROOT ?? "/work";
  assert.ok(isAbsolute(workRoot), "ACCEPTANCE_WORK_ROOT must be absolute");
  assert.match(schema, /^mig_[a-f0-9]+$/, "refusing to run outside an isolated mig_<uuid> schema");
  assert.match(runId, /^[a-z0-9-]+$/, "ACCEPTANCE_RUN_ID contains unsupported characters");

  const environment = { ...process.env, PGOPTIONS: `-csearch_path=${schema}` };
  const workDirectory = join("/tmp", runId);
  mkdirSync(workDirectory, { recursive: true });
  const importer = join(workRoot, "migrate-cpamp.ts");
  const databases = {
    source: join(workDirectory, "source.sqlite"),
    unmapped: join(workDirectory, "unmapped.sqlite"),
    same: join(workDirectory, "same-duplicate.sqlite"),
    conflicting: join(workDirectory, "conflicting-duplicate.sqlite"),
    failed200: join(workDirectory, "failed-success-code.sqlite"),
    pricing: join(workDirectory, "pricing.sqlite"),
    oldSchema: join(workDirectory, "old-schema.sqlite"),
    missingPrice: join(workDirectory, "missing-price.sqlite"),
  };
  const tenant = `cpamp-${runId}-main`;
  const otherTenant = `cpamp-${runId}-tenant`;
  const source = `cpamp-acceptance:${runId}`;
  const otherSource = `cpamp-acceptance:${runId}:source`;
  const duplicateSource = `cpamp-acceptance:${runId}:duplicates`;

  const psql = (sql: string, variables: Variables = {}): string => {
    const variableArgs = Object.entries(variables).flatMap(([name, value]) => ["-v", `${name}=${value}`]);
    return requireSuccess(run("psql", ["-X", "-v", "ON_ERROR_STOP=1", "--no-psqlrc", "-At", ...variableArgs], sql, environment), "psql");
  };
  const sqlite = (database: string, sql: string): string => requireSuccess(run("sqlite3", [database], sql, environment), "sqlite3");
  const initializeSqlite = (database: string): void => { sqlite(database, readFileSync(join(workRoot, "initial.sql"), "utf8")); };
  const basicEvent = (
    hash: string,
    request: string,
    timestamp: number,
    provider: string,
    model: string,
    endpoint: string,
    keyHash: string,
    input: number,
    output: number,
    latency: number,
    failed: number,
    status: number | null = null,
    summary = "",
  ): string => {
    const quote = (value: string): string => `'${value.replaceAll("'", "''")}'`;
    return `INSERT INTO usage_events (
      event_hash,request_id,timestamp_ms,provider,model,endpoint,api_key_hash,
      input_tokens,output_tokens,latency_ms,failed,fail_status_code,fail_summary,
      requested_model,resolved_model,reasoning_effort,service_tier,
      request_service_tier,response_service_tier,cache_input_mode,
      reasoning_tokens,cached_tokens,cache_tokens,cache_read_tokens,
      cache_creation_tokens,normalized_uncached_input_tokens,
      normalized_total_input_tokens,normalized_cache_read_tokens,
      normalized_cache_creation_tokens,total_tokens,ttft_ms
    ) VALUES (${quote(hash)},${quote(request)},${timestamp},${quote(provider)},${quote(model)},${quote(endpoint)},${quote(keyHash)},${input},${output},${latency},${failed},${status ?? "NULL"},${quote(summary)},${quote(model)},${quote(model)},'medium','default','default','default','included_in_input',0,0,0,0,0,${input},${input},0,0,${input + output},10);`;
  };
  const pricedEvent = (event: {
    hash: string;
    request: string;
    timestamp: number;
    provider: string;
    serviceTier: string;
    cacheInputMode: string;
    rawInput: number;
    output: number;
    reasoning: number;
    cached: number;
    cacheRead: number;
    cacheCreation: number;
    uncached: number;
    totalInput: number;
    normalizedCacheRead: number;
    normalizedCacheCreation: number;
  }): string => {
    const quote = (value: string): string => `'${value.replaceAll("'", "''")}'`;
    return `INSERT INTO usage_events (
      event_hash,request_id,timestamp_ms,provider,model,endpoint,api_key_hash,
      input_tokens,output_tokens,latency_ms,failed,fail_status_code,fail_summary,
      requested_model,resolved_model,reasoning_effort,service_tier,
      request_service_tier,response_service_tier,cache_input_mode,
      reasoning_tokens,cached_tokens,cache_tokens,cache_read_tokens,
      cache_creation_tokens,normalized_uncached_input_tokens,
      normalized_total_input_tokens,normalized_cache_read_tokens,
      normalized_cache_creation_tokens,total_tokens,ttft_ms
    ) VALUES (${quote(event.hash)},${quote(event.request)},${event.timestamp},${quote(event.provider)},'display-alias','/v1/responses','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',${event.rawInput},${event.output},125,0,NULL,'','display-alias','exact-model','high',${quote(event.serviceTier)},${quote(event.serviceTier)},${quote(event.serviceTier)},${quote(event.cacheInputMode)},${event.reasoning},${event.cached},0,${event.cacheRead},${event.cacheCreation},${event.uncached},${event.totalInput},${event.normalizedCacheRead},${event.normalizedCacheCreation},${event.totalInput + event.output},15);`;
  };
  const runImport = (importTenant: string, importSource: string, database: string, extra: NodeJS.ProcessEnv = {}): SpawnSyncReturns<string> => run(
    process.execPath,
    [importer],
    undefined,
    {
      ...environment,
      CPAMP_SQLITE_PATH: database,
      IMPORT_TENANT_EXTERNAL_ID: importTenant,
      CPAMP_IMPORT_SOURCE: importSource,
      CPAMP_OVERLAP_MS: "86400000",
      CPAMP_RESET_IMPORT: "false",
      CPAMP_ALLOW_UNMAPPED: "false",
      ...extra,
    },
  );
  const importOk = (importTenant: string, importSource: string, database: string): void => {
    requireSuccess(runImport(importTenant, importSource, database), "CPAMP importer");
  };

  assert.equal(psql("SELECT current_schema();"), schema, "PostgreSQL search_path isolation");
  for (const migration of [
    "0001_initial.sql", "0002_query_indexes.sql", "0004_request_events.sql",
    "0005_generation_jobs.sql", "0018_model_price_tiers.sql", "0019_session_archive_import.sql",
    "0021_request_locators.sql", "0022_budget_rollups.sql", "0023_generation_daily_aggregates.sql",
    "0024_request_stats_rollups.sql", "0027_cpamp_source_digests.sql",
  ]) {
    requireSuccess(run("psql", ["-X", "-v", "ON_ERROR_STOP=1", "--no-psqlrc", "-f", join(workRoot, migration)], undefined, environment), migration);
  }
  psql(`ALTER TABLE request_stats_facts ADD COLUMN session_id TEXT NOT NULL DEFAULT '';
ALTER TABLE generation_stats_facts ADD COLUMN currency TEXT NOT NULL DEFAULT 'USD';
ALTER TABLE generation_stats_facts ADD COLUMN model_route_id TEXT NOT NULL DEFAULT '';
CREATE TABLE session_usage_totals (
  tenant_id TEXT NOT NULL,key_id TEXT NOT NULL,session_id TEXT NOT NULL,currency TEXT NOT NULL,
  last_activity_at BIGINT NOT NULL,requests BIGINT NOT NULL,errors BIGINT NOT NULL,
  input_tokens BIGINT NOT NULL,output_tokens BIGINT NOT NULL,cached_input_tokens BIGINT NOT NULL DEFAULT 0,
  cache_write_tokens BIGINT NOT NULL DEFAULT 0,generation_units BIGINT NOT NULL DEFAULT 0,
  duration_count BIGINT NOT NULL,duration_sum_ms BIGINT NOT NULL,cost_micros BIGINT NOT NULL,
  PRIMARY KEY(tenant_id,key_id,session_id,currency));
CREATE TABLE session_usage_hourly (
  tenant_id TEXT NOT NULL,key_id TEXT NOT NULL,session_id TEXT NOT NULL,hour_bucket BIGINT NOT NULL,
  model TEXT NOT NULL,protocol TEXT NOT NULL,status_class TEXT NOT NULL,error_code TEXT NOT NULL,
  upstream_account_id TEXT NOT NULL,model_route_id TEXT NOT NULL,currency TEXT NOT NULL,
  requests BIGINT NOT NULL,input_tokens BIGINT NOT NULL,output_tokens BIGINT NOT NULL,
  cached_input_tokens BIGINT NOT NULL DEFAULT 0,cache_write_tokens BIGINT NOT NULL DEFAULT 0,
  generation_units BIGINT NOT NULL DEFAULT 0,duration_count BIGINT NOT NULL,
  duration_sum_ms BIGINT NOT NULL,cost_micros BIGINT NOT NULL,
  PRIMARY KEY(tenant_id,key_id,session_id,hour_bucket,model,protocol,status_class,error_code,upstream_account_id,model_route_id,currency));
CREATE TABLE session_usage_daily (
  tenant_id TEXT NOT NULL,key_id TEXT NOT NULL,session_id TEXT NOT NULL,day_bucket BIGINT NOT NULL,
  model TEXT NOT NULL,protocol TEXT NOT NULL,status_class TEXT NOT NULL,error_code TEXT NOT NULL,
  upstream_account_id TEXT NOT NULL,model_route_id TEXT NOT NULL,currency TEXT NOT NULL,
  requests BIGINT NOT NULL,input_tokens BIGINT NOT NULL,output_tokens BIGINT NOT NULL,
  cached_input_tokens BIGINT NOT NULL DEFAULT 0,cache_write_tokens BIGINT NOT NULL DEFAULT 0,
  generation_units BIGINT NOT NULL DEFAULT 0,duration_count BIGINT NOT NULL,
  duration_sum_ms BIGINT NOT NULL,cost_micros BIGINT NOT NULL,
  PRIMARY KEY(tenant_id,key_id,session_id,day_bucket,model,protocol,status_class,error_code,upstream_account_id,model_route_id,currency));`);
  psql("CREATE TABLE IF NOT EXISTS request_records_default PARTITION OF request_records DEFAULT;");

  // A previous importer release left process-global UNLOGGED staging tables in
  // place. The current importer must replace only that disposable schema while
  // preserving durable checkpoint rows.
  psql(`CREATE TABLE cpamp_import_checkpoints (
    tenant_external_id TEXT NOT NULL, source TEXT NOT NULL,
    watermark_ms BIGINT NOT NULL, watermark_hash TEXT NOT NULL,
    imported_events BIGINT NOT NULL, updated_at BIGINT NOT NULL,
    PRIMARY KEY (tenant_external_id, source));
  INSERT INTO cpamp_import_checkpoints
    (tenant_external_id,source,watermark_ms,watermark_hash,imported_events,updated_at)
    VALUES ('legacy-staging-sentinel','legacy-source',17,'legacy-hash',3,19);
  CREATE UNLOGGED TABLE cpamp_import_usage (
    event_hash TEXT, request_id TEXT, timestamp_ms BIGINT,
    provider TEXT, model TEXT, endpoint TEXT, api_key_hash TEXT);
  INSERT INTO cpamp_import_usage VALUES
    ('stale-event','stale-request',1,'legacy','legacy','/v1/responses','stale-key');`);

  initializeSqlite(databases.same);
  sqlite(databases.same, `DELETE FROM usage_events;
${basicEvent('fixture-event-same-duplicate','legacy-request-same-duplicate',100000000,'openai','fixture-model','/v1/responses','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',5,2,40,0)}
${basicEvent('fixture-event-same-duplicate','legacy-request-same-duplicate',100000000,'openai','fixture-model','/v1/responses','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',5,2,40,0)}`);
  const sameTenant = `cpamp-${runId}-same-duplicate`;
  importOk(sameTenant, duplicateSource, databases.same);
  assert.equal(psql("SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='cpamp_import_usage';"), "31", "legacy staging table is rebuilt to the current shape");
  assert.equal(psql("SELECT watermark_ms || '|' || watermark_hash || '|' || imported_events || '|' || updated_at FROM cpamp_import_checkpoints WHERE tenant_external_id='legacy-staging-sentinel' AND source='legacy-source';"), "17|legacy-hash|3|19", "durable checkpoint survives staging rebuild");
  importOk(sameTenant, duplicateSource, databases.same);
  assert.equal(sqlite(databases.same, "SELECT count(*) || '|' || count(DISTINCT event_hash) FROM usage_events;"), "2|1");
  assert.equal(psql(`SELECT
    (SELECT count(*) FROM request_records r JOIN tenants t ON t.id=r.tenant_id WHERE t.external_id=:'tenant') || '|' ||
    (SELECT count(*) FROM import_request_links l JOIN tenants t ON t.id=l.tenant_id WHERE t.external_id=:'tenant' AND l.source=:'source') || '|' ||
    (SELECT count(*) FROM request_stats_facts f JOIN tenants t ON t.id=f.tenant_id WHERE t.external_id=:'tenant') || '|' ||
    (SELECT imported_events FROM cpamp_import_checkpoints WHERE tenant_external_id=:'tenant' AND source=:'source');`, { tenant: sameTenant, source: duplicateSource }), "1|1|1|1");

  initializeSqlite(databases.conflicting);
  sqlite(databases.conflicting, `DELETE FROM usage_events;
${basicEvent('fixture-event-conflicting-duplicate','legacy-request-conflicting-duplicate',100000000,'openai','fixture-model','/v1/responses','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',5,2,40,0)}
${basicEvent('fixture-event-conflicting-duplicate','legacy-request-conflicting-duplicate',100000000,'openai','fixture-model','/v1/responses','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',6,2,40,0)}`);
  const conflictingTenant = `cpamp-${runId}-conflicting-duplicate`;
  const conflicting = runImport(conflictingTenant, duplicateSource, databases.conflicting);
  assert.notEqual(conflicting.status, 0, "conflicting duplicate import unexpectedly succeeded");
  assert.match(conflicting.stderr, /1 event hashes map to conflicting source rows/);
  assert.equal(psql("SELECT (SELECT count(*) FROM tenants WHERE external_id=:'tenant') || '|' || (SELECT count(*) FROM cpamp_import_checkpoints WHERE tenant_external_id=:'tenant' AND source=:'source');", { tenant: conflictingTenant, source: duplicateSource }), "0|0");

  initializeSqlite(databases.failed200);
  sqlite(databases.failed200, `DELETE FROM usage_events;${basicEvent('fixture-event-failed-http-200','legacy-request-failed-http-200',100000000,'openai','fixture-model','/v1/responses','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',5,2,40,1,200,'provider returned an unusable success envelope')}`);
  const failedTenant = `cpamp-${runId}-failed-success-code`;
  importOk(failedTenant, duplicateSource, databases.failed200);
  importOk(failedTenant, duplicateSource, databases.failed200);
  assert.equal(psql(`SELECT
    (SELECT count(*) FROM request_records r JOIN tenants t ON t.id=r.tenant_id WHERE t.external_id=:'tenant' AND r.status_code=502 AND r.error_code='upstream_error') || '|' ||
    (SELECT count(*) FROM request_stats_facts f JOIN tenants t ON t.id=f.tenant_id WHERE t.external_id=:'tenant' AND f.status_class='failure' AND f.error_code='upstream_error') || '|' ||
    (SELECT COALESCE(sum(a.requests),0) FROM request_daily_aggregates a JOIN tenants t ON t.id=a.tenant_id WHERE t.external_id=:'tenant' AND a.status_class='failure' AND a.error_code='upstream_error');`, { tenant: failedTenant }), "1|1|1");

  initializeSqlite(databases.source);
  importOk(tenant, source, databases.source);
  importOk(tenant, source, databases.source);
  const tenantId = psql("SELECT id FROM tenants WHERE external_id=:'tenant';", { tenant });
  assert.equal(sqlite(databases.source, "SELECT count(*) || '|' || count(DISTINCT event_hash) || '|' || sum(input_tokens) || '|' || sum(output_tokens) FROM usage_events;"), "2|2|28|8");
  assert.equal(psql("SELECT count(*) || '|' || count(DISTINCT id) || '|' || sum(input_tokens) || '|' || sum(output_tokens) || '|' || sum(cost_micros) || '|' || count(*) FILTER (WHERE error_code='http_502') FROM request_records WHERE tenant_id=:'tenant_id';", { tenant_id: tenantId }), "2|2|28|8|88|1");
  assert.equal(psql("SELECT count(*) || '|' || count(*) FILTER (WHERE EXISTS (SELECT 1 FROM request_records r WHERE r.id=l.id AND r.created_at=l.created_at AND r.tenant_id=l.tenant_id AND r.key_id=l.key_id)) FROM request_record_locators l WHERE l.tenant_id=:'tenant_id';", { tenant_id: tenantId }), "2|2");
  assert.equal(psql("SELECT count(*) || '|' || count(s.account_id) FROM credit_accounts a LEFT JOIN account_usage_state s ON s.account_id=a.id WHERE a.tenant_id=:'tenant_id';", { tenant_id: tenantId }), "1|1");
  assert.equal(psql("SELECT sum(a.requests) || '|' || sum(a.input_tokens) || '|' || sum(a.output_tokens) || '|' || sum(a.cost_micros) FROM usage_daily_aggregates a JOIN key_records k ON k.id=a.key_id WHERE k.tenant_id=:'tenant_id';", { tenant_id: tenantId }), "2|28|8|88");
  assert.equal(psql("SELECT watermark_ms || '|' || watermark_hash || '|' || imported_events FROM cpamp_import_checkpoints WHERE tenant_external_id=:'tenant' AND source=:'source';", { tenant, source }), "300000000|fixture-event-initial-b|2");
  assert.equal(psql("SELECT count(*) FILTER (WHERE request_object LIKE 'gap://cpamp/fixture-event-initial-b/request' AND response_object='gap://cpamp/fixture-event-initial-b/response') || '|' || count(*) FILTER (WHERE request_object LIKE 'gap://cpamp/fixture-event-initial-a/request' AND response_object='gap://cpamp/fixture-event-initial-a/response') FROM request_records WHERE tenant_id=:'tenant_id';", { tenant_id: tenantId }), "1|1");

  sqlite(databases.source, basicEvent('fixture-event-late-overlap','legacy-request-late',299000000,'openai','fixture-model','/v1/responses','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',19,7,90,0));
  importOk(tenant, source, databases.source);
  importOk(tenant, source, databases.source);
  assert.equal(psql("SELECT count(*) || '|' || count(DISTINCT id) || '|' || sum(input_tokens) || '|' || sum(output_tokens) || '|' || sum(cost_micros) FROM request_records WHERE tenant_id=:'tenant_id';", { tenant_id: tenantId }), "3|3|47|15|154");
  assert.equal(psql("SELECT watermark_ms || '|' || watermark_hash || '|' || imported_events FROM cpamp_import_checkpoints WHERE tenant_external_id=:'tenant' AND source=:'source';", { tenant, source }), "300000000|fixture-event-initial-b|3");

  sqlite(databases.source, basicEvent('fixture-event-new-watermark','legacy-request-new',400000000,'anthropic','fixture-model','/v1/messages','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',23,11,210,0));
  importOk(tenant, source, databases.source);
  const identityQuery = "SELECT string_agg(id, ',' ORDER BY id) FROM request_records WHERE tenant_id=:'tenant_id';";
  const finalIds = psql(identityQuery, { tenant_id: tenantId });
  const analysisQuery = `SELECT
    (SELECT count(*) || ':' || COALESCE(sum(input_tokens),0) || ':' || COALESCE(sum(output_tokens),0) || ':' || COALESCE(sum(cost_micros),0) FROM request_stats_facts WHERE tenant_id=:'tenant_id') || '|' ||
    (SELECT count(*) || ':' || COALESCE(sum(requests),0) || ':' || COALESCE(sum(input_tokens),0) || ':' || COALESCE(sum(output_tokens),0) || ':' || COALESCE(sum(cost_micros),0) FROM request_daily_aggregates WHERE tenant_id=:'tenant_id') || '|' ||
    (SELECT count(*) || ':' || COALESCE(sum(requests),0) || ':' || COALESCE(sum(input_tokens),0) || ':' || COALESCE(sum(output_tokens),0) || ':' || COALESCE(sum(cost_micros),0) FROM usage_analysis_hourly WHERE tenant_id=:'tenant_id') || '|' ||
    (SELECT count(*) || ':' || COALESCE(sum(requests),0) || ':' || COALESCE(sum(input_tokens),0) || ':' || COALESCE(sum(output_tokens),0) || ':' || COALESCE(sum(cost_micros),0) FROM usage_analysis_daily WHERE tenant_id=:'tenant_id');`;
  const analysisBeforeReplay = psql(analysisQuery, { tenant_id: tenantId });
  importOk(tenant, source, databases.source);
  assert.equal(psql(identityQuery, { tenant_id: tenantId }), finalIds, "deterministic request IDs after replay");
  assert.equal(psql(analysisQuery, { tenant_id: tenantId }), analysisBeforeReplay, "analytics remain stable after replay");
  assert.equal(sqlite(databases.source, "SELECT count(*) || '|' || count(DISTINCT event_hash) || '|' || sum(input_tokens) || '|' || sum(output_tokens) FROM usage_events;"), "4|4|70|26");
  assert.equal(psql("SELECT count(*) || '|' || count(DISTINCT id) || '|' || count(DISTINCT reservation_id) || '|' || sum(input_tokens) || '|' || sum(output_tokens) || '|' || sum(cost_micros) FROM request_records WHERE tenant_id=:'tenant_id';", { tenant_id: tenantId }), "4|4|4|70|26|244");
  assert.equal(psql("SELECT count(*) || '|' || count(*) FILTER (WHERE EXISTS (SELECT 1 FROM request_records r WHERE r.id=l.id AND r.created_at=l.created_at AND r.tenant_id=l.tenant_id AND r.key_id=l.key_id)) FROM request_record_locators l WHERE l.tenant_id=:'tenant_id';", { tenant_id: tenantId }), "4|4");
  assert.equal(psql("SELECT sum(a.requests) || '|' || sum(a.input_tokens) || '|' || sum(a.output_tokens) || '|' || sum(a.cost_micros) FROM usage_daily_aggregates a JOIN key_records k ON k.id=a.key_id WHERE k.tenant_id=:'tenant_id';", { tenant_id: tenantId }), "4|70|26|244");
  assert.equal(psql("SELECT count(*) || '|' || count(DISTINCT request_id) || '|' || sum(input_tokens) || '|' || sum(output_tokens) || '|' || sum(cost_micros) || '|' || sum(duration_ms) || '|' || count(*) FILTER (WHERE status_class='success') || '|' || count(*) FILTER (WHERE status_class='failure' AND error_code='http_502') || '|' || count(*) FILTER (WHERE protocol='openai') || '|' || count(*) FILTER (WHERE protocol='anthropic') || '|' || count(*) FILTER (WHERE service_tier='default' AND currency='USD') || '|' || count(*) FILTER (WHERE upstream_account_id='' AND model_route_id='') FROM request_stats_facts WHERE tenant_id=:'tenant_id';", { tenant_id: tenantId }), "4|4|70|26|244|600|3|1|3|1|4|4");
  assert.equal(psql("SELECT sum(requests) || '|' || sum(input_tokens) || '|' || sum(output_tokens) || '|' || sum(cached_input_tokens) || '|' || sum(cache_write_tokens) || '|' || sum(duration_count) || '|' || sum(duration_sum_ms) || '|' || sum(cost_micros) || '|' || sum(requests) FILTER (WHERE protocol='openai') || '|' || sum(requests) FILTER (WHERE protocol='anthropic') || '|' || sum(requests) FILTER (WHERE status_class='failure' AND error_code='http_502') || '|' || count(DISTINCT currency) || '|' || min(currency) FROM request_daily_aggregates WHERE tenant_id=:'tenant_id';", { tenant_id: tenantId }), "4|70|26|0|0|4|600|244|3|1|1|1|USD");
  const rollupQuery = (table: string) => `SELECT sum(requests) || '|' || sum(input_tokens) || '|' || sum(output_tokens) || '|' || sum(cached_input_tokens) || '|' || sum(cache_write_tokens) || '|' || sum(generation_units) || '|' || sum(duration_count) || '|' || sum(duration_sum_ms) || '|' || sum(cost_micros) || '|' || sum(duration_bucket_2) || '|' || sum(duration_bucket_3) || '|' || sum(duration_bucket_0+duration_bucket_1+duration_bucket_2+duration_bucket_3+duration_bucket_4+duration_bucket_5+duration_bucket_6+duration_bucket_7+duration_bucket_8+duration_bucket_9+duration_bucket_10+duration_bucket_11) || '|' || sum(requests) FILTER (WHERE protocol='openai') || '|' || sum(requests) FILTER (WHERE protocol='anthropic') || '|' || sum(requests) FILTER (WHERE status_class='failure' AND error_code='http_502') || '|' || count(*) FILTER (WHERE source_kind<>'request' OR service_tier<>'default' OR currency<>'USD') FROM ${table} WHERE tenant_id=:'tenant_id';`;
  assert.equal(psql(rollupQuery("usage_analysis_hourly"), { tenant_id: tenantId }), "4|70|26|0|0|0|4|600|244|1|3|4|3|1|1|0");
  assert.equal(psql(rollupQuery("usage_analysis_daily"), { tenant_id: tenantId }), "4|70|26|0|0|0|4|600|244|1|3|4|3|1|1|0");
  assert.equal(psql("SELECT watermark_ms || '|' || watermark_hash || '|' || imported_events FROM cpamp_import_checkpoints WHERE tenant_external_id=:'tenant' AND source=:'source';", { tenant, source }), "400000000|fixture-event-new-watermark|4");

  importOk(otherTenant, source, databases.source);
  importOk(tenant, otherSource, databases.source);
  assert.equal(psql("SELECT count(*) || '|' || count(DISTINCT tenant_external_id || ':' || source) FROM cpamp_import_checkpoints WHERE (tenant_external_id=:'tenant' AND source IN (:'source',:'other_source')) OR (tenant_external_id=:'other_tenant' AND source=:'source');", { tenant, other_tenant: otherTenant, source, other_source: otherSource }), "3|3");
  assert.equal(psql("SELECT count(*) || '|' || count(DISTINCT r.id) || '|' || (SELECT count(*) FROM request_stats_facts f WHERE f.tenant_id IN (SELECT id FROM tenants WHERE external_id IN (:'tenant',:'other_tenant'))) || '|' || (SELECT sum(requests) FROM usage_analysis_hourly h WHERE h.tenant_id IN (SELECT id FROM tenants WHERE external_id IN (:'tenant',:'other_tenant'))) || '|' || (SELECT sum(requests) FROM usage_analysis_daily d WHERE d.tenant_id IN (SELECT id FROM tenants WHERE external_id IN (:'tenant',:'other_tenant'))) FROM request_records r JOIN tenants t ON t.id=r.tenant_id WHERE t.external_id IN (:'tenant',:'other_tenant');", { tenant, other_tenant: otherTenant }), "12|12|12|12|12");

  initializeSqlite(databases.unmapped);
  sqlite(databases.unmapped, `DELETE FROM usage_events;${basicEvent('fixture-event-unmapped','legacy-unmapped',500000000,'openai','fixture-model','/v1/responses','invalid-hash',1,1,10,0)}DELETE FROM api_key_aliases;`);
  const unmappedTenant = `cpamp-${runId}-unmapped`;
  const unmapped = runImport(unmappedTenant, source, databases.unmapped);
  assert.notEqual(unmapped.status, 0, "unmapped import unexpectedly succeeded");
  assert.match(unmapped.stderr, /staged events have no supported key identity/);
  assert.equal(psql("SELECT (SELECT count(*) FROM tenants WHERE external_id=:'tenant') || '|' || (SELECT count(*) FROM cpamp_import_checkpoints WHERE tenant_external_id=:'tenant');", { tenant: unmappedTenant }), "0|0");

  initializeSqlite(databases.pricing);
  sqlite(databases.pricing, `DELETE FROM usage_events;
DELETE FROM model_prices;
INSERT INTO model_prices VALUES ('exact-model',2.0,4.0,0.5,0.25,3.0,1,1,1,1,'fixture-exact','exact-model',600000000);
INSERT INTO model_price_context_tiers VALUES ('exact-model',100,10.0,20.0,1.0,2.0,12.0,1,1,1,1,1);
INSERT INTO model_price_service_tiers VALUES ('exact-model','priority','priority',3.0,5.0,0.6,0.2,4.0,1,1,1,1,1);
${pricedEvent({hash:'pricing-codex-inclusive',request:'pricing-request-codex',timestamp:500000000,provider:'openai',serviceTier:'priority',cacheInputMode:'included_in_input',rawInput:100,output:10,reasoning:3,cached:40,cacheRead:0,cacheCreation:0,uncached:60,totalInput:100,normalizedCacheRead:40,normalizedCacheCreation:0})}
${pricedEvent({hash:'pricing-claude-separate',request:'pricing-request-claude',timestamp:600001000,provider:'anthropic',serviceTier:'default',cacheInputMode:'separate',rawInput:80,output:5,reasoning:2,cached:30,cacheRead:20,cacheCreation:10,uncached:80,totalInput:110,normalizedCacheRead:20,normalizedCacheCreation:10})}
${pricedEvent({hash:'pricing-auto-base',request:'pricing-request-auto',timestamp:600002000,provider:'openai',serviceTier:'auto',cacheInputMode:'included_in_input',rawInput:10,output:1,reasoning:0,cached:0,cacheRead:0,cacheCreation:0,uncached:10,totalInput:10,normalizedCacheRead:0,normalizedCacheCreation:0})}`);
  const pricingTenant = `cpamp-${runId}-pricing`;
  const pricingSource = `cpamp-acceptance:${runId}:pricing`;
  importOk(pricingTenant, pricingSource, databases.pricing);
  const pricingTenantId = psql("SELECT id FROM tenants WHERE external_id=:'tenant';", { tenant: pricingTenant });
  assert.equal(psql(`SELECT count(*) || '|' || sum(input_tokens) || '|' || sum(output_tokens) || '|' ||
    sum(cached_input_tokens) || '|' || sum(cache_write_tokens) || '|' || sum(cost_micros) || '|' ||
    count(*) FILTER (WHERE service_tier='priority') || '|' || count(*) FILTER (WHERE service_tier='auto')
    FROM request_records WHERE tenant_id=:'tenant_id';`, { tenant_id: pricingTenantId }), "3|220|16|60|10|1338|1|1");
  assert.equal(psql(`SELECT count(*) || '|' || count(*) FILTER (WHERE pricing_model='exact-model') || '|' ||
    count(*) FILTER (WHERE pricing_rule='service') || '|' || count(*) FILTER (WHERE pricing_rule='context') || '|' ||
    count(*) FILTER (WHERE pricing_rule='base') || '|' || sum(reasoning_tokens) || '|' || sum(ttft_ms) || '|' ||
    sum(normalized_total_input_tokens) || '|' || sum(normalized_cache_read_tokens) || '|' ||
    sum(normalized_cache_creation_tokens) || '|' || sum(cost_micros) || '|' ||
    count(*) FILTER (WHERE pricing_config_json::jsonb->>'schema'='cpamp-v1.11.12-price-v1') || '|' ||
    count(*) FILTER (WHERE cache_input_mode='separate' AND raw_cached_tokens=30
      AND raw_cache_read_tokens=20 AND raw_cache_creation_tokens=10 AND residual_cached_tokens=0)
    FROM cpamp_import_event_provenance WHERE tenant_id=:'tenant_id' AND source=:'source';`,
    { tenant_id: pricingTenantId, source: pricingSource }), "3|3|1|1|1|5|45|220|60|10|1338|3|1");
  assert.equal(psql("SELECT count(*) FROM model_prices WHERE model='exact-model';"), "0", "CPAMP source pricing must not mutate global MTC prices");
  assert.equal(psql(`SELECT sum(requests) || '|' || sum(input_tokens) || '|' || sum(output_tokens) || '|' ||
    sum(cached_input_tokens) || '|' || sum(cache_write_tokens) || '|' || sum(cost_micros)
    FROM usage_analysis_daily WHERE tenant_id=:'tenant_id' AND source_kind='request';`, { tenant_id: pricingTenantId }), "3|150|16|60|10|1338");
  assert.equal(psql(`SELECT sum(requests) || '|' || sum(input_tokens) || '|' || sum(output_tokens) || '|' ||
    sum(cached_input_tokens) || '|' || sum(cache_write_tokens) || '|' || sum(cost_micros)
    FROM session_usage_totals WHERE tenant_id=:'tenant_id';`, { tenant_id: pricingTenantId }), "3|150|16|60|10|1338");

  psql(`UPDATE import_request_links l SET source_digest=p.legacy_source_digest
    FROM cpamp_import_event_provenance p
   WHERE p.tenant_id=:'tenant_id' AND p.source=:'source'
     AND l.tenant_id=p.tenant_id AND l.source=p.source AND l.external_event_hash=p.external_event_hash;
UPDATE request_records r SET input_tokens=p.raw_input_tokens,cached_input_tokens=0,
       cache_write_tokens=0,service_tier='default',cost_micros=0
  FROM cpamp_import_event_provenance p
 WHERE p.tenant_id=:'tenant_id' AND p.source=:'source'
   AND r.tenant_id=p.tenant_id AND r.id=p.target_request_id;
UPDATE request_stats_facts f SET input_tokens=p.raw_input_tokens,cached_input_tokens=0,
       cache_write_tokens=0,service_tier='default',cost_micros=0
  FROM cpamp_import_event_provenance p
 WHERE p.tenant_id=:'tenant_id' AND p.source=:'source'
   AND f.tenant_id=p.tenant_id AND f.request_id=p.target_request_id;
DELETE FROM cpamp_import_event_provenance WHERE tenant_id=:'tenant_id' AND source=:'source';
UPDATE usage_daily_aggregates SET requests=999 WHERE key_id IN (SELECT id FROM key_records WHERE tenant_id=:'tenant_id');
UPDATE request_daily_aggregates SET requests=999 WHERE tenant_id=:'tenant_id';
UPDATE usage_analysis_hourly SET requests=999 WHERE tenant_id=:'tenant_id' AND source_kind='request';
UPDATE usage_analysis_daily SET requests=999 WHERE tenant_id=:'tenant_id' AND source_kind='request';
UPDATE session_usage_totals SET requests=999 WHERE tenant_id=:'tenant_id';
UPDATE session_usage_hourly SET requests=999 WHERE tenant_id=:'tenant_id';
UPDATE session_usage_daily SET requests=999 WHERE tenant_id=:'tenant_id';`,
    { tenant_id: pricingTenantId, source: pricingSource });

  const projectionSnapshot = (): string => psql(`SELECT
    (SELECT COALESCE(sum(requests),0) FROM usage_daily_aggregates WHERE key_id IN (SELECT id FROM key_records WHERE tenant_id=:'tenant_id')) || '|' ||
    (SELECT COALESCE(sum(requests),0) FROM request_daily_aggregates WHERE tenant_id=:'tenant_id') || '|' ||
    (SELECT COALESCE(sum(requests),0) FROM usage_analysis_hourly WHERE tenant_id=:'tenant_id' AND source_kind='request') || '|' ||
    (SELECT COALESCE(sum(requests),0) FROM usage_analysis_daily WHERE tenant_id=:'tenant_id' AND source_kind='request') || '|' ||
    (SELECT COALESCE(sum(requests),0) FROM session_usage_totals WHERE tenant_id=:'tenant_id') || '|' ||
    (SELECT COALESCE(sum(requests),0) FROM session_usage_hourly WHERE tenant_id=:'tenant_id') || '|' ||
    (SELECT COALESCE(sum(requests),0) FROM session_usage_daily WHERE tenant_id=:'tenant_id');`,
    { tenant_id: pricingTenantId });
  const projectionsBeforeCorrection = projectionSnapshot();

  const ordinaryBeforeCorrection = runImport(pricingTenant, pricingSource, databases.pricing);
  assert.notEqual(ordinaryBeforeCorrection.status, 0, "ordinary replay corrected a legacy digest");
  assert.match(ordinaryBeforeCorrection.stderr, /require the explicit cache\/pricing correction mode/);
  assert.equal(projectionSnapshot(), projectionsBeforeCorrection, "rejected replay changed projections");
  const plan = runImport(pricingTenant, pricingSource, databases.pricing, { CPAMP_CORRECTION_MODE: "plan" });
  assert.equal(plan.status, 0, `correction plan failed: ${plan.stderr}`);
  assert.match(plan.stdout, /candidate_events=3 non_usd_candidates=0 live_candidates=0/);
  assert.match(plan.stdout, /display-alias/);
  assert.equal(projectionSnapshot(), projectionsBeforeCorrection, "dry-run changed projections");

  const correction = runImport(pricingTenant, pricingSource, databases.pricing, {
    CPAMP_CORRECTION_MODE: "apply",
    CPAMP_CORRECTION_CONFIRM: "CORRECT_CPAMP_IMPORTED_USAGE",
  });
  assert.equal(correction.status, 0, `correction apply failed: ${correction.stderr}`);
  assert.match(correction.stdout, /corrected_events/);
  assert.doesNotMatch(correction.stdout, /total_imported_events/, "correction unexpectedly ran ordinary replay");
  assert.equal(psql(`SELECT count(*) || '|' || sum(input_tokens) || '|' || sum(output_tokens) || '|' ||
    sum(cached_input_tokens) || '|' || sum(cache_write_tokens) || '|' || sum(cost_micros)
    FROM request_records WHERE tenant_id=:'tenant_id';`, { tenant_id: pricingTenantId }), "3|220|16|60|10|1338");
  assert.equal(psql(`SELECT count(*) || '|' || count(*) FILTER (WHERE source_digest<>legacy_source_digest) || '|' ||
    count(*) FILTER (WHERE correction_revision='cpamp-cache-pricing-v2') || '|' || sum(cost_micros)
    FROM cpamp_import_event_provenance WHERE tenant_id=:'tenant_id' AND source=:'source';`,
    { tenant_id: pricingTenantId, source: pricingSource }), "3|3|3|1338");
  assert.equal(psql(`SELECT
    (SELECT count(*) FROM cpamp_import_correction_audit WHERE tenant_id=:'tenant_id' AND source=:'source') || '|' ||
    (SELECT count(*) FROM import_request_links WHERE tenant_id=:'tenant_id' AND source=:'source' AND source_digest<>'') || '|' ||
    (SELECT correction_revision FROM cpamp_import_checkpoints WHERE tenant_external_id=:'tenant' AND source=:'source') || '|' ||
    (SELECT corrected_events FROM cpamp_import_checkpoints WHERE tenant_external_id=:'tenant' AND source=:'source');`,
    { tenant_id: pricingTenantId, tenant: pricingTenant, source: pricingSource }), "3|3|cpamp-cache-pricing-v2|3");
  const correctedProjection = psql(`SELECT
    (SELECT sum(requests)||':'||sum(input_tokens)||':'||sum(cost_micros) FROM usage_daily_aggregates WHERE key_id IN (SELECT id FROM key_records WHERE tenant_id=:'tenant_id')) || '|' ||
    (SELECT sum(requests)||':'||sum(input_tokens)||':'||sum(cached_input_tokens)||':'||sum(cache_write_tokens)||':'||sum(cost_micros) FROM request_daily_aggregates WHERE tenant_id=:'tenant_id') || '|' ||
    (SELECT sum(requests)||':'||sum(input_tokens)||':'||sum(cached_input_tokens)||':'||sum(cache_write_tokens)||':'||sum(cost_micros) FROM usage_analysis_hourly WHERE tenant_id=:'tenant_id' AND source_kind='request') || '|' ||
    (SELECT sum(requests)||':'||sum(input_tokens)||':'||sum(cached_input_tokens)||':'||sum(cache_write_tokens)||':'||sum(cost_micros) FROM usage_analysis_daily WHERE tenant_id=:'tenant_id' AND source_kind='request') || '|' ||
    (SELECT sum(requests)||':'||sum(input_tokens)||':'||sum(cached_input_tokens)||':'||sum(cache_write_tokens)||':'||sum(cost_micros) FROM session_usage_totals WHERE tenant_id=:'tenant_id') || '|' ||
    (SELECT sum(requests)||':'||sum(input_tokens)||':'||sum(cached_input_tokens)||':'||sum(cache_write_tokens)||':'||sum(cost_micros) FROM session_usage_hourly WHERE tenant_id=:'tenant_id') || '|' ||
    (SELECT sum(requests)||':'||sum(input_tokens)||':'||sum(cached_input_tokens)||':'||sum(cache_write_tokens)||':'||sum(cost_micros) FROM session_usage_daily WHERE tenant_id=:'tenant_id');`,
    { tenant_id: pricingTenantId });
  assert.equal(correctedProjection, "3:220:1338|3:220:60:10:1338|3:150:60:10:1338|3:150:60:10:1338|3:150:60:10:1338|3:150:60:10:1338|3:150:60:10:1338");

  const secondCorrection = runImport(pricingTenant, pricingSource, databases.pricing, {
    CPAMP_CORRECTION_MODE: "apply",
    CPAMP_CORRECTION_CONFIRM: "CORRECT_CPAMP_IMPORTED_USAGE",
  });
  assert.equal(secondCorrection.status, 0, `second correction failed: ${secondCorrection.stderr}`);
  assert.match(secondCorrection.stdout, /correction_revision=cpamp-cache-pricing-v2 corrected_events=0 replay=unchanged/);
  assert.doesNotMatch(secondCorrection.stderr, /CPAMP staged=/, "second correction restaged the all-history source");
  assert.doesNotMatch(secondCorrection.stdout, /total_imported_events/, "second correction unexpectedly ran ordinary replay");
  assert.equal(psql("SELECT count(*) FROM cpamp_import_correction_audit WHERE tenant_id=:'tenant_id' AND source=:'source';", { tenant_id: pricingTenantId, source: pricingSource }), "3");
  assert.equal(psql(`SELECT
    (SELECT sum(requests)||':'||sum(input_tokens)||':'||sum(cost_micros) FROM usage_daily_aggregates WHERE key_id IN (SELECT id FROM key_records WHERE tenant_id=:'tenant_id')) || '|' ||
    (SELECT sum(requests)||':'||sum(input_tokens)||':'||sum(cached_input_tokens)||':'||sum(cache_write_tokens)||':'||sum(cost_micros) FROM request_daily_aggregates WHERE tenant_id=:'tenant_id') || '|' ||
    (SELECT sum(requests)||':'||sum(input_tokens)||':'||sum(cached_input_tokens)||':'||sum(cache_write_tokens)||':'||sum(cost_micros) FROM usage_analysis_daily WHERE tenant_id=:'tenant_id' AND source_kind='request') || '|' ||
    (SELECT sum(requests)||':'||sum(input_tokens)||':'||sum(cached_input_tokens)||':'||sum(cache_write_tokens)||':'||sum(cost_micros) FROM session_usage_totals WHERE tenant_id=:'tenant_id');`, { tenant_id: pricingTenantId }),
    "3:220:1338|3:220:60:10:1338|3:150:60:10:1338|3:150:60:10:1338");
  importOk(pricingTenant, pricingSource, databases.pricing);
  assert.equal(psql("SELECT count(*) || '|' || sum(cost_micros) FROM request_records WHERE tenant_id=:'tenant_id';", { tenant_id: pricingTenantId }), "3|1338");

  sqlite(databases.oldSchema, `CREATE TABLE usage_events (event_hash TEXT,request_id TEXT,timestamp_ms INTEGER,provider TEXT,model TEXT,endpoint TEXT,api_key_hash TEXT,input_tokens INTEGER,output_tokens INTEGER,latency_ms INTEGER,failed INTEGER,fail_status_code INTEGER,fail_summary TEXT);
CREATE TABLE api_key_aliases (api_key_hash TEXT,alias TEXT,updated_at_ms INTEGER);
CREATE TABLE model_prices (model TEXT,prompt_per_1m REAL,completion_per_1m REAL);`);
  const oldSchemaTenant = `cpamp-${runId}-old-schema`;
  const oldSchema = runImport(oldSchemaTenant, `${pricingSource}:old`, databases.oldSchema);
  assert.notEqual(oldSchema.status, 0, "old source schema unexpectedly imported");
  assert.match(oldSchema.stderr, /source schema is too old for exact billing/);
  assert.equal(psql("SELECT count(*) FROM tenants WHERE external_id=:'tenant';", { tenant: oldSchemaTenant }), "0");

  initializeSqlite(databases.missingPrice);
  sqlite(databases.missingPrice, "DELETE FROM model_prices;");
  const missingPriceTenant = `cpamp-${runId}-missing-price`;
  const missingPrice = runImport(missingPriceTenant, `${pricingSource}:missing`, databases.missingPrice);
  assert.notEqual(missingPrice.status, 0, "missing source price unexpectedly imported");
  assert.match(missingPrice.stderr, /lack exact token\/pricing provenance/);
  assert.equal(psql("SELECT count(*) FROM tenants WHERE external_id=:'tenant';", { tenant: missingPriceTenant }), "0");

  const resetTenant = "cpa-dogfood-import";
  const resetSource = `cpamp-reset-guard:${runId}`;
  importOk(resetTenant, resetSource, databases.source);
  psql(`WITH identity AS (SELECT md5('cpamp-reset-provider-guard') AS value)
    INSERT INTO upstream_accounts (id,tenant_id,name,driver,auth_kind,config_json,status,credential_generation,created_at,updated_at)
    SELECT substr(value,1,8)||'-'||substr(value,9,4)||'-5'||substr(value,14,3)||'-a'||substr(value,18,3)||'-'||substr(value,21,12), t.id, 'operator-owned-provider','http-json','none','{"base_url":"https://api.example.test"}','active',1,1,1 FROM identity CROSS JOIN tenants t WHERE t.external_id=:'tenant';`, { tenant: resetTenant });
  const reset = runImport(resetTenant, resetSource, databases.source, { CPAMP_RESET_IMPORT: "true", CPAMP_RESET_CONFIRM: "DELETE_CPA_DOGFOOD_IMPORT" });
  assert.notEqual(reset.status, 0, "reset with an operator-owned provider unexpectedly succeeded");
  assert.match(reset.stderr, /tenant has provider accounts or model routes not owned by the usage importer/);
  assert.equal(psql("SELECT (SELECT count(*) FROM upstream_accounts u JOIN tenants t ON t.id=u.tenant_id WHERE t.external_id=:'tenant') || '|' || (SELECT count(*) FROM request_records r JOIN tenants t ON t.id=r.tenant_id WHERE t.external_id=:'tenant') || '|' || (SELECT sum(requests) FROM usage_analysis_hourly h JOIN tenants t ON t.id=h.tenant_id WHERE t.external_id=:'tenant') || '|' || (SELECT sum(requests) FROM usage_analysis_daily d JOIN tenants t ON t.id=d.tenant_id WHERE t.external_id=:'tenant');", { tenant: resetTenant }), "1|4|4|4");

  process.stdout.write(`CPAMP PostgreSQL acceptance: PASS schema=${schema}\n`);
});
