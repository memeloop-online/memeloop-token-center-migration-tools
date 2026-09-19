import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { repository } from "./contract-helpers.ts";

const configured = ["PGHOST", "PGUSER", "PGPASSWORD", "PGDATABASE"].every((name) => Boolean(process.env[name]));
const tool = join(repository, "ops/adjust-failed-request-costs.ts");

function execute(command: string, args: readonly string[], input: string | undefined, environment: NodeJS.ProcessEnv): SpawnSyncReturns<string> {
  return spawnSync(command, args, { encoding: "utf8", input, env: environment, shell: false, maxBuffer: 16 * 1024 * 1024 });
}

function success(result: SpawnSyncReturns<string>, label: string): string {
  assert.equal(result.error, undefined, `${label}: ${result.error?.message ?? "spawn failed"}`);
  assert.equal(result.status, 0, `${label}: ${result.stderr}`);
  return result.stdout.trim();
}

test("failed-request adjustment aggregates shared projections and is replay-safe", { skip: !configured }, () => {
  const suffix = `${process.pid}_${Math.random().toString(16).slice(2)}`.replace(/[^a-z0-9_]/gu, "");
  const schema = `fra_accept_${suffix}`;
  const root = mkdtempSync(join(tmpdir(), "mtc-fra-acceptance."));
  const passFile = join(root, "pgpass");
  const planFile = join(root, "approved.json");
  const database = process.env.PGDATABASE!;
  const port = process.env.PGPORT ?? "5432";
  writeFileSync(passFile, `${process.env.PGHOST}:${port}:${database}:${process.env.PGUSER}:${process.env.PGPASSWORD}\n`, { mode: 0o600 });
  chmodSync(passFile, 0o600);
  const environment: NodeJS.ProcessEnv = {
    ...process.env,
    PGOPTIONS: `-csearch_path=${schema}`,
    FRA_PGHOST: process.env.PGHOST,
    FRA_PGPORT: port,
    FRA_PGUSER: process.env.PGUSER,
    FRA_PGDATABASE: database,
    FRA_PGPASSFILE: passFile,
    FRA_TENANT_EXTERNAL_ID: `fra-${suffix}`,
    FRA_FROM_MS: "1726358400000",
    FRA_TO_MS: "1726444800000",
    FRA_PLAN_OUTPUT: planFile,
  };
  const psql = (sql: string): string => success(execute("psql", ["-X", "--no-psqlrc", "-v", "ON_ERROR_STOP=1", "-At"], sql, environment), "psql");
  const command = (mode: string, extra: NodeJS.ProcessEnv = {}): SpawnSyncReturns<string> => execute(process.execPath, [tool, mode], undefined, { ...environment, ...extra });

  try {
    psql(`CREATE SCHEMA ${schema};
      CREATE TABLE tenants (id TEXT PRIMARY KEY, external_id TEXT UNIQUE NOT NULL);
      CREATE TABLE credit_accounts (id TEXT PRIMARY KEY, available_micros BIGINT NOT NULL, reserved_micros BIGINT NOT NULL, updated_at BIGINT NOT NULL);
      CREATE TABLE key_records (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, account_id TEXT NOT NULL, currency TEXT NOT NULL);
      CREATE TABLE request_records (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, key_id TEXT NOT NULL, created_at BIGINT NOT NULL, completed_at BIGINT, reservation_id TEXT NOT NULL, status_code BIGINT NOT NULL, currency TEXT NOT NULL, cost_micros BIGINT NOT NULL);
      CREATE TABLE request_stats_facts (request_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, key_id TEXT NOT NULL, created_at BIGINT NOT NULL, model TEXT NOT NULL, protocol TEXT NOT NULL, status_class TEXT NOT NULL, error_code TEXT NOT NULL, upstream_account_id TEXT NOT NULL, model_route_id TEXT NOT NULL, service_tier TEXT NOT NULL, currency TEXT NOT NULL, cost_micros BIGINT NOT NULL);
      CREATE TABLE usage_reservations (id TEXT PRIMARY KEY, account_id TEXT NOT NULL, key_id TEXT NOT NULL, actual_micros BIGINT NOT NULL, status TEXT NOT NULL);
      CREATE TABLE ledger_entries (id TEXT PRIMARY KEY, account_id TEXT NOT NULL, key_id TEXT, kind TEXT NOT NULL, amount_micros BIGINT NOT NULL, currency TEXT NOT NULL, source TEXT NOT NULL, idempotency_key TEXT UNIQUE, reference_entry_id TEXT, created_at BIGINT NOT NULL);
      CREATE TABLE account_usage_state (account_id TEXT PRIMARY KEY, settled_lifetime_micros BIGINT NOT NULL, updated_at BIGINT NOT NULL);
      CREATE TABLE key_budget_state (key_id TEXT PRIMARY KEY, settled_lifetime_micros BIGINT NOT NULL, updated_at BIGINT NOT NULL);
      CREATE TABLE key_budget_daily_rollups (key_id TEXT NOT NULL, day_bucket BIGINT NOT NULL, settled_micros BIGINT NOT NULL, PRIMARY KEY(key_id, day_bucket));
      CREATE TABLE key_budget_usage_events (usage_entry_id TEXT PRIMARY KEY, reservation_id TEXT, key_id TEXT NOT NULL, account_id TEXT NOT NULL, amount_micros BIGINT NOT NULL, settled_at BIGINT NOT NULL);
      CREATE TABLE entitlement_cycles (id TEXT PRIMARY KEY, consumed_micros BIGINT NOT NULL, updated_at BIGINT NOT NULL);
      CREATE TABLE entitlement_usage_allocations (id TEXT PRIMARY KEY, entitlement_cycle_id TEXT NOT NULL, usage_ledger_entry_id TEXT NOT NULL, amount_micros BIGINT NOT NULL, created_at BIGINT NOT NULL);
      CREATE TABLE request_daily_aggregates (tenant_id TEXT NOT NULL, key_id TEXT NOT NULL, day_bucket BIGINT NOT NULL, model TEXT NOT NULL, protocol TEXT NOT NULL, status_class TEXT NOT NULL, error_code TEXT NOT NULL, upstream_account_id TEXT NOT NULL, model_route_id TEXT NOT NULL, service_tier TEXT NOT NULL, currency TEXT NOT NULL, cost_micros BIGINT NOT NULL, PRIMARY KEY(tenant_id,key_id,day_bucket,model,protocol,status_class,error_code,upstream_account_id,model_route_id,service_tier,currency));
      CREATE TABLE usage_analysis_hourly (tenant_id TEXT NOT NULL, key_id TEXT NOT NULL, hour_bucket BIGINT NOT NULL, source_kind TEXT NOT NULL, model TEXT NOT NULL, protocol TEXT NOT NULL, status_class TEXT NOT NULL, error_code TEXT NOT NULL, upstream_account_id TEXT NOT NULL, model_route_id TEXT NOT NULL, service_tier TEXT NOT NULL, currency TEXT NOT NULL, cost_micros BIGINT NOT NULL, PRIMARY KEY(tenant_id,key_id,hour_bucket,source_kind,model,protocol,status_class,error_code,upstream_account_id,model_route_id,service_tier,currency));
      CREATE TABLE usage_analysis_daily (tenant_id TEXT NOT NULL, key_id TEXT NOT NULL, day_bucket BIGINT NOT NULL, source_kind TEXT NOT NULL, model TEXT NOT NULL, protocol TEXT NOT NULL, status_class TEXT NOT NULL, error_code TEXT NOT NULL, upstream_account_id TEXT NOT NULL, model_route_id TEXT NOT NULL, service_tier TEXT NOT NULL, currency TEXT NOT NULL, cost_micros BIGINT NOT NULL, PRIMARY KEY(tenant_id,key_id,day_bucket,source_kind,model,protocol,status_class,error_code,upstream_account_id,model_route_id,service_tier,currency));
      INSERT INTO tenants VALUES ('tenant','fra-${suffix}');
      INSERT INTO credit_accounts VALUES ('account',0,0,0);
      INSERT INTO key_records VALUES ('key','tenant','account','USD');
      INSERT INTO account_usage_state VALUES ('account',200,0);
      INSERT INTO key_budget_state VALUES ('key',200,0);
      INSERT INTO key_budget_daily_rollups VALUES ('key',19981,200);
      INSERT INTO entitlement_cycles VALUES ('cycle',200,0);
      INSERT INTO ledger_entries VALUES ('grant','account','key','grant',200,'USD','fixture',NULL,NULL,1726358300000),('usage-1','account','key','usage',-100,'USD','reservation-1','usage-1',NULL,1726358400000),('usage-2','account','key','usage',-100,'USD','reservation-2','usage-2',NULL,1726358400000);
      INSERT INTO usage_reservations VALUES ('reservation-1','account','key',100,'settled'),('reservation-2','account','key',100,'settled');
      INSERT INTO request_records VALUES ('request-1','tenant','key',1726358400000,1726358400001,'reservation-1',503,'USD',100),('request-2','tenant','key',1726358400000,1726358400001,'reservation-2',503,'USD',100);
      INSERT INTO request_stats_facts VALUES ('request-1','tenant','key',1726358400000,'gpt','openai','failure','http_503','upstream','route','default','USD',100),('request-2','tenant','key',1726358400000,'gpt','openai','failure','http_503','upstream','route','default','USD',100);
      INSERT INTO entitlement_usage_allocations VALUES ('allocation-1','cycle','usage-1',100,0),('allocation-2','cycle','usage-2',100,0);
      INSERT INTO request_daily_aggregates VALUES ('tenant','key',19981,'gpt','openai','failure','http_503','upstream','route','default','USD',200);
      INSERT INTO usage_analysis_hourly VALUES ('tenant','key',479544,'request','gpt','openai','failure','http_503','upstream','route','default','USD',200);
      INSERT INTO usage_analysis_daily VALUES ('tenant','key',19981,'request','gpt','openai','failure','http_503','upstream','route','default','USD',200);`);

    assert.equal(success(command("--plan"), "plan").includes("ready_for_approval"), true);
    assert.equal(success(command("--apply", { FRA_APPLY_CONFIRM: "APPLY_FAILED_REQUEST_COST_ADJUSTMENTS", FRA_APPROVED_PLAN: planFile, FRA_APPROVAL_REFERENCE: "acceptance" }), "apply").includes("applied"), true);
    assert.equal(success(command("--apply", { FRA_APPLY_CONFIRM: "APPLY_FAILED_REQUEST_COST_ADJUSTMENTS", FRA_APPROVED_PLAN: planFile, FRA_APPROVAL_REFERENCE: "acceptance" }), "replay").includes("already_applied"), true);
    assert.equal(success(command("--verify"), "verify").includes('"outcome":"pass"'), true);
    assert.equal(psql("SELECT count(*) || '|' || sum(amount_micros) FROM ledger_entries WHERE kind='failed_request_refund';"), "2|200");
    assert.equal(psql("SELECT available_micros || '|' || (SELECT settled_lifetime_micros FROM account_usage_state) || '|' || (SELECT settled_lifetime_micros FROM key_budget_state) || '|' || (SELECT settled_micros FROM key_budget_daily_rollups) FROM credit_accounts;"), "200|0|0|0");
    assert.equal(psql("SELECT consumed_micros || '|' || (SELECT sum(amount_micros) FROM entitlement_usage_allocations) FROM entitlement_cycles;"), "0|0");
    assert.equal(psql("SELECT (SELECT cost_micros FROM request_daily_aggregates) || '|' || (SELECT cost_micros FROM usage_analysis_hourly) || '|' || (SELECT cost_micros FROM usage_analysis_daily) || '|' || (SELECT refund_micros FROM failed_request_cost_adjustment_daily);"), "0|0|0|200");
  } finally {
    try { execute("psql", ["-X", "--no-psqlrc", "-v", "ON_ERROR_STOP=1", "-At"], `DROP SCHEMA IF EXISTS ${schema} CASCADE;`, { ...process.env, PGOPTIONS: "" }); } finally { rmSync(root, { recursive: true, force: true }); }
  }
});
