import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  PurgeFailure,
  buildSql,
  manifestSha256,
  parseManifest,
  type ReviewedManifest,
} from "../../ops/release/purge-retired-api2-trial.ts";

const repository = join(import.meta.dirname, "../..");
const tool = join(repository, "ops/release/purge-retired-api2-trial.ts");
const uuid = (value: number): string => `00000000-0000-4000-8000-${String(value).padStart(12, "0")}`;

function fixtureManifest(): ReviewedManifest {
  const snapshots = Array.from({ length: 17 }, (_, index) => ({
    upstream_account_id: uuid(100 + index),
    name: index < 9 ? `legacy-cpa-bridge-fixture-${index}` : `cpa-fixture-${index}`,
    driver: "retired-driver",
    auth_kind: "api_key",
    credential_generation: 2,
    created_at: 1000 + index,
    deleted_at: 2000 + index,
  }));
  const keys = Array.from({ length: 7 }, (_, index) => {
    const keyId = uuid(200 + index);
    const credentialId = uuid(300 + index);
    return {
      key_id: keyId,
      principal_id: uuid(400 + index),
      account_id: uuid(500 + index),
      alias: `api2-trial-fixture-${index}`,
      currency: "USD",
      credential_generation: 1,
      archived_at: 3000 + index,
      created_at: 1000 + index,
      updated_at: 3000 + index,
      issued_ciphertext_present: index < 2,
      credentials: [{ credential_id: credentialId, generation: 1, fingerprint: `fixture-${index}`, created_at: 1000 + index, revoked_at: 2900 + index, plaintext_present: index < 3 }],
      recovery_secrets: index < 2 ? [{ credential_id: credentialId, credential_generation: 1, created_at: 1500 + index, updated_at: 2500 + index }] : [],
      source_proofs: [{ credential_id: credentialId, proof_kind: "fixture-source-v1", source_digest: `fixture-only-source-${index}`, created_at: 1000 + index }],
      rotation_replays: [{ idempotency_key: `rotate-${index}`, request_hash: `request-${index}`, expires_at: 999999, created_at: 1000 + index, response_ciphertext_present: true }],
      credential_group_memberships: index < 3 ? [{ credential_group_id: uuid(600 + index), created_at: 1800 + index }] : [],
      routing_grants: Array.from({ length: index < 2 ? 3 : 2 }, (_, grant) => ({
        model_route_id: index === 6 && grant === 0 ? null : uuid(700 + index * 3 + grant),
        route_group_id: index === 6 && grant === 0 ? uuid(900) : null,
        created_at: 1900 + index * 3 + grant,
      })),
      routing_revision: { revision: 10 + index },
    };
  });
  const conversation_rewrites = Array.from({ length: 170 }, (_, index) => {
    const key = keys[index % keys.length]!;
    const sessionName = index < 20 ? `api2 trial session ${index}` : null;
    const labelsJson = index === 0
      ? JSON.stringify({ ui: "preserve-this-label" })
      : JSON.stringify({ alias: `cpa-fixture-${index}`, cohort: "bridge" });
    const labelsContainLegacyText = index !== 0;
    return {
      observation_id: uuid(800 + index),
      key_id: key.key_id,
      session_name: sessionName,
      labels_json: labelsJson,
      replacement_session_name: null,
      replacement_labels_json: labelsContainLegacyText ? JSON.stringify({ state: "retired" }) : labelsJson,
    };
  });
  const conversation_projection_outbox = keys.map((key, index) => {
    const request = JSON.stringify({ fixture: index });
    const hints = JSON.stringify({});
    return {
      request_id: uuid(1200 + index),
      tenant_id: uuid(1),
      key_id: key.key_id,
      principal_id: key.principal_id,
      request_json_bytes: Buffer.byteLength(request),
      hints_json_bytes: Buffer.byteLength(hints),
      request_json_sha256: createHash("sha256").update(request).digest("hex"),
      hints_json_sha256: createHash("sha256").update(hints).digest("hex"),
      client_name: index % 2 === 0 ? "fixture-client" : null,
      upstream_response_id: index % 2 === 0 ? `response-${index}` : null,
      observed_at: 2000 + index,
      lease_owner: null,
      lease_expires_at: null,
      attempts: 1,
      projected_at: 2800 + index,
    };
  });
  const synchronous_image_idempotency = Array.from({ length: 24 }, (_, index) => {
    const key = keys[index % keys.length]!;
    const status = index < 16 ? "completed" as const : index < 23 ? "failed" as const : "pending" as const;
    const response = status === "completed" ? JSON.stringify({ data: [{ url: `fixture-only-${index}` }] }) : null;
    return {
      key_id: key.key_id,
      idempotency_key: `fixture-image-${String(index).padStart(2, "0")}`,
      request_hash: createHash("sha256").update(`image-request-${index}`).digest("hex"),
      request_id: uuid(1600 + index),
      reservation_id: uuid(1700 + index),
      status,
      response_status: status === "pending" ? null : status === "completed" ? 200 : 502,
      response_object_present: response !== null,
      response_object_bytes: response === null ? 0 : Buffer.byteLength(response),
      response_object_sha256: response === null ? null : createHash("sha256").update(response).digest("hex"),
      error_code: status === "failed" ? "fixture_image_failed" : null,
      created_at: 2000 + index,
      lease_expires_at: 2500 + index,
      completed_at: status === "pending" ? null : 3000 + index,
    };
  }).sort((left, right) => `${left.key_id}:${left.idempotency_key}`.localeCompare(`${right.key_id}:${right.idempotency_key}`));
  const credential_groups = keys.flatMap(key => key.credential_group_memberships.map(membership => {
    const suffix = Number(membership.credential_group_id.slice(-12)) - 600;
    return { id: membership.credential_group_id, tenant_id: uuid(1), name: `legacy-group-${suffix}`, normalized_name: `legacy-group-${suffix}`, created_at: 1700 + suffix, updated_at: 1800 + suffix };
  }));
  const route_groups = [{ id: uuid(900), tenant_id: uuid(1), name: "legacy-route-group", normalized_name: "legacy-route-group", created_at: 1700, updated_at: 1800 }];
  return parseManifest({
    schema_version: 5,
    idempotency_key: "retired-api2-trial-fixture-v1",
    tenant_external_id: "fixture-tenant",
    expected: { deleted_upstream_account_snapshots: 17, key_records: 7, routing_grants: 16, routing_revisions: 7, conversation_observations: 170, synchronous_image_idempotency: 24 },
    snapshots,
    keys,
    credential_groups,
    route_groups,
    conversation_projection_outbox,
    conversation_rewrites,
    synchronous_image_idempotency,
  } as never);
}

function baseSchema(postgres: boolean): string {
  const auto = postgres ? "BYTEA" : "BLOB";
  const protectedTables = [
    "request_events", "request_record_locators", "request_event_locators",
    "request_stats_facts", "request_daily_aggregates", "usage_daily_aggregates",
    "usage_analysis_hourly", "usage_analysis_daily", "session_usage_totals",
    "session_usage_hourly", "session_usage_daily", "session_archive_totals",
    "session_archive_quarantine_resolutions",
    "generation_stats_facts", "generation_daily_aggregates",
    "generation_usage_dimensions_hourly", "generation_usage_dimensions_daily",
    "ledger_entries", "account_settlement_feed", "key_budget_state",
    "key_budget_daily_rollups", "key_budget_usage_events", "rate_limit_windows",
    "key_runtime_state", "metered_usage_projection_outbox",
    "key_credential_recovery_audit", "key_credential_recovery_access_audit",
    "conversation_key_clusters",
  ];
  return `${postgres ? "" : "PRAGMA foreign_keys=ON;"}
CREATE TABLE tenants(id TEXT PRIMARY KEY,external_id TEXT UNIQUE NOT NULL);
CREATE TABLE principals(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,external_id TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE credit_accounts(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,principal_id TEXT NOT NULL);
CREATE TABLE key_records(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,principal_id TEXT NOT NULL,account_id TEXT NOT NULL,alias TEXT NOT NULL,currency TEXT NOT NULL,status TEXT NOT NULL,credential_generation BIGINT NOT NULL,issued_key_ciphertext TEXT,archived_at BIGINT,created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL);
CREATE TABLE key_credentials(id TEXT PRIMARY KEY,key_id TEXT NOT NULL,generation BIGINT NOT NULL,secret_hash ${auto},fingerprint TEXT NOT NULL,created_at BIGINT NOT NULL,revoked_at BIGINT,secret_plaintext TEXT);
CREATE TABLE credential_rotation_replays(idempotency_key TEXT PRIMARY KEY,resource_kind TEXT NOT NULL,resource_id TEXT NOT NULL,request_hash TEXT NOT NULL,response_ciphertext TEXT,expires_at BIGINT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE key_credential_recovery_secrets(credential_id TEXT PRIMARY KEY,key_id TEXT NOT NULL REFERENCES key_records(id) ON DELETE CASCADE,credential_generation BIGINT NOT NULL,ciphertext TEXT NOT NULL,created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL);
CREATE TABLE key_credential_source_proofs(credential_id TEXT NOT NULL REFERENCES key_credentials(id) ON DELETE CASCADE,proof_kind TEXT NOT NULL,source_digest TEXT NOT NULL,created_at BIGINT NOT NULL,PRIMARY KEY(credential_id,proof_kind));
CREATE TABLE credential_groups(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,name TEXT NOT NULL,normalized_name TEXT NOT NULL,created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL);
CREATE TABLE credential_group_memberships(tenant_id TEXT NOT NULL,credential_group_id TEXT NOT NULL,key_id TEXT NOT NULL REFERENCES key_records(id) ON DELETE CASCADE,created_at BIGINT NOT NULL,PRIMARY KEY(credential_group_id,key_id));
CREATE TABLE route_groups(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,name TEXT NOT NULL,normalized_name TEXT NOT NULL,created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL);
CREATE TABLE model_route_group_memberships(tenant_id TEXT NOT NULL,route_group_id TEXT NOT NULL,model_route_id TEXT NOT NULL);
CREATE TABLE routing_grants(tenant_id TEXT NOT NULL,key_id TEXT NOT NULL REFERENCES key_records(id) ON DELETE CASCADE,model_route_id TEXT,route_group_id TEXT,created_at BIGINT NOT NULL);
CREATE TABLE routing_grant_relation_revisions(tenant_id TEXT NOT NULL,subject_kind TEXT NOT NULL,subject_id TEXT NOT NULL,key_id TEXT REFERENCES key_records(id) ON DELETE CASCADE,model_route_id TEXT,revision BIGINT NOT NULL,PRIMARY KEY(tenant_id,subject_kind,subject_id));
CREATE TABLE deleted_upstream_account_snapshots(upstream_account_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,name TEXT NOT NULL,driver TEXT NOT NULL,auth_kind TEXT NOT NULL,credential_generation BIGINT NOT NULL,created_at BIGINT NOT NULL,deleted_at BIGINT NOT NULL);
CREATE TABLE conversation_observations(id TEXT PRIMARY KEY,key_id TEXT NOT NULL,session_name TEXT,labels_json TEXT NOT NULL);
CREATE TABLE conversation_clusters(id TEXT PRIMARY KEY,principal_id TEXT NOT NULL);
CREATE TABLE session_archive_correlations(id TEXT PRIMARY KEY,key_id TEXT NOT NULL,principal_id TEXT NOT NULL);
CREATE TABLE session_archive_unlinked_requests(id TEXT PRIMARY KEY,key_id TEXT NOT NULL,principal_id TEXT NOT NULL);
CREATE TABLE memeloop_cloud_subscription_events(id TEXT PRIMARY KEY,key_id TEXT NOT NULL,principal_id TEXT NOT NULL);
CREATE TABLE request_records(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,key_id TEXT NOT NULL,completed_at BIGINT,response_object TEXT);
CREATE TABLE session_archive_import_records(tenant_id TEXT NOT NULL,source TEXT NOT NULL,external_request_id TEXT NOT NULL,target_request_id TEXT NOT NULL,external_event_hash TEXT NOT NULL,record_digest TEXT NOT NULL,source_started_at BIGINT NOT NULL,imported_at BIGINT NOT NULL,PRIMARY KEY(tenant_id,source,external_request_id));
CREATE TABLE usage_reservations(id TEXT PRIMARY KEY,key_id TEXT NOT NULL,status TEXT NOT NULL);
CREATE TABLE synchronous_image_idempotency(key_id TEXT NOT NULL REFERENCES key_records(id) ON DELETE CASCADE,idempotency_key TEXT NOT NULL,request_hash TEXT NOT NULL,request_id TEXT NOT NULL,reservation_id TEXT REFERENCES usage_reservations(id),status TEXT NOT NULL,response_status BIGINT,response_object TEXT,error_code TEXT,created_at BIGINT NOT NULL,lease_expires_at BIGINT NOT NULL,completed_at BIGINT,PRIMARY KEY(key_id,idempotency_key));
CREATE TABLE generation_jobs(id TEXT PRIMARY KEY,key_id TEXT NOT NULL,status TEXT NOT NULL,stats_aggregated_at BIGINT);
CREATE TABLE conversation_projection_outbox(request_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,key_id TEXT NOT NULL,principal_id TEXT NOT NULL,request_json TEXT NOT NULL,hints_json TEXT NOT NULL,client_name TEXT,upstream_response_id TEXT,observed_at BIGINT NOT NULL,lease_owner TEXT,lease_expires_at BIGINT,attempts BIGINT NOT NULL,projected_at BIGINT);
CREATE TABLE conversation_unresolved_explicit_parents(child_observation_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,principal_id TEXT NOT NULL,key_id TEXT NOT NULL,parent_reference TEXT NOT NULL,subagent BIGINT NOT NULL DEFAULT 0,created_at BIGINT NOT NULL);
CREATE TABLE session_routing_terminals(tenant_id TEXT NOT NULL,principal_id TEXT NOT NULL,key_id TEXT NOT NULL,explicit_session_id TEXT NOT NULL,model TEXT NOT NULL,protocol TEXT NOT NULL,request_id TEXT PRIMARY KEY,observed_at BIGINT NOT NULL,status_code BIGINT NOT NULL,error_code TEXT,model_route_id TEXT,upstream_account_id TEXT,expires_at BIGINT NOT NULL);
${protectedTables.map(name => `CREATE TABLE ${name}(id TEXT PRIMARY KEY,key_id TEXT NOT NULL);`).join("\n")}
`;
}

function fixtureSql(manifest: ReviewedManifest, postgres: boolean): string {
  const q = (value: string): string => `'${value.replaceAll("'", "''")}'`;
  const tenantId = uuid(1);
  const statements = [baseSchema(postgres), `INSERT INTO tenants VALUES (${q(tenantId)},'fixture-tenant');`];
  for (const snapshot of manifest.snapshots) statements.push(`INSERT INTO deleted_upstream_account_snapshots VALUES (${q(snapshot.upstream_account_id)},${q(tenantId)},${q(snapshot.name)},${q(snapshot.driver)},${q(snapshot.auth_kind)},${snapshot.credential_generation},${snapshot.created_at},${snapshot.deleted_at});`);
  for (const [index, key] of manifest.keys.entries()) {
    statements.push(`INSERT INTO principals VALUES (${q(key.principal_id)},${q(tenantId)},${q(`api2-principal-${index}`)},${key.created_at});`);
    if (index >= 2) statements.push(`INSERT INTO credit_accounts VALUES (${q(key.account_id)},${q(tenantId)},${q(key.principal_id)});`);
    statements.push(`INSERT INTO key_records VALUES (${q(key.key_id)},${q(tenantId)},${q(key.principal_id)},${q(key.account_id)},${q(key.alias)},${q(key.currency)},'revoked',${key.credential_generation},${key.issued_ciphertext_present ? q("fixture-only-ciphertext") : "NULL"},${key.archived_at},${key.created_at},${key.updated_at});`);
    statements.push(`INSERT INTO credential_rotation_replays VALUES (${q(`rotate-${index}`)},'key',${q(key.key_id)},${q(`request-${index}`)},${q(`recoverable-result-${index}`)},999999,${key.created_at});`);
    for (const credential of key.credentials) statements.push(`INSERT INTO key_credentials VALUES (${q(credential.credential_id)},${q(key.key_id)},${credential.generation},${postgres ? "decode('00','hex')" : "X'00'"},${q(credential.fingerprint)},${credential.created_at},${credential.revoked_at},${credential.plaintext_present ? q("fixture-only-plaintext") : "NULL"});`);
    for (const recovery of key.recovery_secrets) statements.push(`INSERT INTO key_credential_recovery_secrets VALUES (${q(recovery.credential_id)},${q(key.key_id)},${recovery.credential_generation},'fixture-only-recovery-ciphertext',${recovery.created_at},${recovery.updated_at});`);
    for (const proof of key.source_proofs) statements.push(`INSERT INTO key_credential_source_proofs VALUES (${q(proof.credential_id)},${q(proof.proof_kind)},${q(proof.source_digest)},${proof.created_at});`);
    for (const membership of key.credential_group_memberships) {
      statements.push(`INSERT INTO credential_groups VALUES (${q(membership.credential_group_id)},${q(tenantId)},${q(`legacy-group-${index}`)},${q(`legacy-group-${index}`)},${1700 + index},${1800 + index});`);
      statements.push(`INSERT INTO credential_group_memberships VALUES (${q(tenantId)},${q(membership.credential_group_id)},${q(key.key_id)},${membership.created_at});`);
    }
    for (const grant of key.routing_grants) {
      if (grant.route_group_id) statements.push(`INSERT INTO route_groups VALUES (${q(grant.route_group_id)},${q(tenantId)},'legacy-route-group','legacy-route-group',1700,1800);`);
      statements.push(`INSERT INTO routing_grants VALUES (${q(tenantId)},${q(key.key_id)},${grant.model_route_id ? q(grant.model_route_id) : "NULL"},${grant.route_group_id ? q(grant.route_group_id) : "NULL"},${grant.created_at});`);
    }
    statements.push(`INSERT INTO routing_grant_relation_revisions VALUES (${q(tenantId)},'credential',${q(key.key_id)},${q(key.key_id)},NULL,${key.routing_revision.revision});`);
    statements.push(`INSERT INTO request_records(id,tenant_id,key_id,completed_at) VALUES (${q(`request_records-${index}`)},${q(tenantId)},${q(key.key_id)},${key.archived_at});`);
    statements.push(`INSERT INTO session_archive_import_records VALUES (${q(tenantId)},'cpa-session-archive',${q(`external-${index}`)},${q(`request_records-${index}`)},${q(`event-${index}`)},${q(`digest-${index}`)},${key.created_at},${key.archived_at});`);
    statements.push(`INSERT INTO usage_reservations VALUES (${q(`usage_reservations-${index}`)},${q(key.key_id)},'settled');`);
    statements.push(`INSERT INTO generation_jobs VALUES (${q(`generation_jobs-${index}`)},${q(key.key_id)},'succeeded',${key.archived_at});`);
    const projection = manifest.conversation_projection_outbox[index]!;
    statements.push(`INSERT INTO conversation_projection_outbox VALUES (${q(projection.request_id)},${q(projection.tenant_id)},${q(projection.key_id)},${q(projection.principal_id)},${q(JSON.stringify({ fixture: index }))},'{}',${projection.client_name ? q(projection.client_name) : "NULL"},${projection.upstream_response_id ? q(projection.upstream_response_id) : "NULL"},${projection.observed_at},NULL,NULL,${projection.attempts},${projection.projected_at});`);
    for (const table of ["request_events", "request_record_locators", "request_event_locators", "request_stats_facts", "request_daily_aggregates", "usage_daily_aggregates", "usage_analysis_hourly", "usage_analysis_daily", "session_usage_totals", "session_usage_hourly", "session_usage_daily", "session_archive_totals", "session_archive_quarantine_resolutions", "generation_stats_facts", "generation_daily_aggregates", "generation_usage_dimensions_hourly", "generation_usage_dimensions_daily", "ledger_entries", "account_settlement_feed", "key_budget_state", "key_budget_daily_rollups", "key_budget_usage_events", "rate_limit_windows", "key_runtime_state", "metered_usage_projection_outbox", "key_credential_recovery_audit", "key_credential_recovery_access_audit", "conversation_key_clusters"]) statements.push(`INSERT INTO ${table} VALUES (${q(`${table}-${index}`)},${q(key.key_id)});`);
    if (index === 0) statements.push(`INSERT INTO conversation_unresolved_explicit_parents VALUES (${q(uuid(1400))},${q(tenantId)},${q(key.principal_id)},${q(key.key_id)},'parent-fixture',0,${key.created_at});`);
    if (index === 1) statements.push(`INSERT INTO session_routing_terminals VALUES (${q(tenantId)},${q(key.principal_id)},${q(key.key_id)},'session-fixture','fixture-model','responses',${q(uuid(1500))},${key.created_at},200,NULL,NULL,NULL,999999);`);
    statements.push(`INSERT INTO session_archive_correlations VALUES (${q(`correlation-${index}`)},${q(key.key_id)},${q(key.principal_id)});`);
    statements.push(`INSERT INTO session_archive_unlinked_requests VALUES (${q(`unlinked-${index}`)},${q(key.key_id)},${q(key.principal_id)});`);
    statements.push(`INSERT INTO memeloop_cloud_subscription_events VALUES (${q(`cloud-${index}`)},${q(key.key_id)},${q(key.principal_id)});`);
  }
  for (const replay of manifest.synchronous_image_idempotency) {
    const index = Number(replay.idempotency_key.slice(-2));
    const completedResponse = JSON.stringify({ data: [{ url: `fixture-only-${index}` }] });
    const requestResponse = replay.status === "completed" ? completedResponse : JSON.stringify({ status: replay.status });
    statements.push(`INSERT INTO usage_reservations VALUES (${q(replay.reservation_id)},${q(replay.key_id)},'settled');`);
    statements.push(`INSERT INTO request_records VALUES (${q(replay.request_id)},${q(tenantId)},${q(replay.key_id)},${3000 + index},${q(requestResponse)});`);
    statements.push(`INSERT INTO synchronous_image_idempotency VALUES (${q(replay.key_id)},${q(replay.idempotency_key)},${q(replay.request_hash)},${q(replay.request_id)},${q(replay.reservation_id)},${q(replay.status)},${replay.response_status ?? "NULL"},${replay.status === "completed" ? q(completedResponse) : "NULL"},${replay.error_code ? q(replay.error_code) : "NULL"},${replay.created_at},${replay.lease_expires_at},${replay.completed_at ?? "NULL"});`);
  }
  const retained = manifest.keys[6]!;
  statements.push(`INSERT INTO key_records VALUES (${q(uuid(999))},${q(tenantId)},${q(retained.principal_id)},${q(uuid(998))},'ordinary-archived-key','USD','revoked',1,NULL,6000,5000,6000);`);
  for (const rewrite of manifest.conversation_rewrites) statements.push(`INSERT INTO conversation_observations VALUES (${q(rewrite.observation_id)},${q(rewrite.key_id)},${rewrite.session_name === null ? "NULL" : q(rewrite.session_name)},${q(rewrite.labels_json)});`);
  return statements.join("\n");
}

function run(binary: string, args: string[], input?: string, env: NodeJS.ProcessEnv = process.env): SpawnSyncReturns<string> {
  return spawnSync(binary, args, { encoding: "utf8", input, env, shell: false, maxBuffer: 8 * 1024 * 1024 });
}

function success(result: SpawnSyncReturns<string>, label: string): string {
  assert.equal(result.error, undefined, `${label}: ${result.error?.message ?? "spawn failed"}`);
  assert.equal(result.status, 0, `${label}: ${result.stderr}`);
  return result.stdout.trim();
}

function writePrivate(path: string, body: string): void {
  writeFileSync(path, body, { mode: 0o600 });
  chmodSync(path, 0o600);
}

function toolArgs(workspace: string, manifestPath: string, receiptPath: string, databaseArgs: string[], apply = false): string[] {
  const args = [tool, "--manifest", manifestPath, "--receipt-output", receiptPath, ...databaseArgs];
  if (apply) args.push("--apply", "--approved-manifest-sha256", manifestSha256(parseManifest(JSON.parse(readFileSync(manifestPath, "utf8")) as never)));
  return args;
}

test("reviewed manifest is fixed to the production-audited cohort", () => {
  const manifest = fixtureManifest();
  assert.equal(manifest.snapshots.length, 17);
  assert.equal(manifest.keys.length, 7);
  assert.equal(manifest.keys.reduce((sum, key) => sum + key.routing_grants.length, 0), 16);
  assert.equal(manifest.keys.length, 7);
  assert.equal(manifest.conversation_rewrites.length, 170);
  assert.equal(manifest.conversation_rewrites.filter(entry => entry.session_name === null).length, 150);
  assert.equal(manifest.conversation_rewrites[0]!.replacement_labels_json, manifest.conversation_rewrites[0]!.labels_json);
  assert.equal(manifest.conversation_rewrites[20]!.replacement_session_name, null);
  assert.equal(manifest.synchronous_image_idempotency.length, 24);
  const invalid = JSON.parse(JSON.stringify(manifest));
  invalid.snapshots.pop();
  assert.throws(() => parseManifest(invalid), (error: unknown) => error instanceof PurgeFailure && error.code === "manifest_invalid");
  const unsafe = JSON.parse(JSON.stringify(manifest));
  unsafe.conversation_rewrites[0].replacement_session_name = "retired-session-00000000-0000-4000-8000-000000000001";
  assert.throws(() => parseManifest(unsafe), (error: unknown) => error instanceof PurgeFailure && error.code === "manifest_invalid");
  const oldSchema = JSON.parse(JSON.stringify(manifest));
  oldSchema.schema_version = 4;
  assert.throws(() => parseManifest(oldSchema), (error: unknown) => error instanceof PurgeFailure && error.code === "manifest_invalid");
  const badProjectionDigest = JSON.parse(JSON.stringify(manifest));
  badProjectionDigest.conversation_projection_outbox[0].request_json_sha256 = "invalid";
  assert.throws(() => parseManifest(badProjectionDigest), (error: unknown) => error instanceof PurgeFailure && error.code === "manifest_invalid");
  const rewrittenUnmarkedLabels = JSON.parse(JSON.stringify(manifest));
  rewrittenUnmarkedLabels.conversation_rewrites[0].replacement_labels_json = JSON.stringify({ state: "retired" });
  assert.throws(() => parseManifest(rewrittenUnmarkedLabels), (error: unknown) => error instanceof PurgeFailure && error.code === "manifest_invalid");
  const fabricatedUnnamedTitle = JSON.parse(JSON.stringify(manifest));
  fabricatedUnnamedTitle.conversation_rewrites[20].replacement_session_name = "generated-title";
  assert.throws(() => parseManifest(fabricatedUnnamedTitle), (error: unknown) => error instanceof PurgeFailure && error.code === "manifest_invalid");
});

test("generated SQL clears recoverable secrets before exact deletes and rolls back by default", () => {
  const manifest = fixtureManifest();
  const sql = buildSql(manifest, manifestSha256(manifest), false, "sqlite", 1234);
  assert.ok(sql.indexOf("UPDATE key_records SET issued_key_ciphertext=NULL") < sql.indexOf("DELETE FROM key_records"));
  assert.ok(sql.indexOf("UPDATE key_credentials SET secret_plaintext=NULL") < sql.indexOf("DELETE FROM key_credentials"));
  assert.ok(sql.indexOf("UPDATE key_credential_recovery_secrets SET ciphertext=''") < sql.indexOf("DELETE FROM key_credential_recovery_secrets"));
  assert.ok(sql.indexOf("UPDATE credential_rotation_replays SET response_ciphertext=NULL") < sql.indexOf("DELETE FROM credential_rotation_replays"));
  assert.doesNotMatch(sql, /legacy_key_credentials/u);
  assert.match(sql, /request_records WHERE key_id IN \(SELECT key_id FROM target_keys\) AND completed_at IS NULL/u);
  assert.match(sql, /usage_reservations WHERE key_id IN \(SELECT key_id FROM target_keys\) AND \(status IS NULL OR status<>'settled'\)/u);
  assert.match(sql, /generation_jobs WHERE key_id IN \(SELECT key_id FROM target_keys\) AND \(status IS NULL OR status NOT IN \('succeeded','failed','cancelled'\) OR stats_aggregated_at IS NULL\)/u);
  assert.match(sql, /target_rotation_replays expected LEFT JOIN credential_rotation_replays/u);
  assert.match(sql, /target_credential_groups expected LEFT JOIN credential_groups/u);
  assert.match(sql, /target_route_groups expected LEFT JOIN route_groups/u);
  assert.match(sql, /target_conversation_projections expected LEFT JOIN conversation_projection_outbox/u);
  assert.match(sql, /target_synchronous_image_idempotency expected LEFT JOIN synchronous_image_idempotency/u);
  assert.match(sql, /target_rewrites\(observation_id TEXT PRIMARY KEY,key_id TEXT NOT NULL,session_name TEXT,labels_json TEXT NOT NULL/u);
  assert.match(sql, /actual\.session_name IS NULL/u);
  assert.match(sql, /DELETE FROM synchronous_image_idempotency WHERE \(key_id,idempotency_key\) IN/u);
  assert.match(sql, /conversation_projection_outbox WHERE key_id IN \(SELECT key_id FROM target_keys\) AND projected_at IS NULL/u);
  assert.match(sql, /SHA256_TEXT\(actual\.request_json\)<>expected\.request_json_sha256/u);
  assert.match(sql, /NOT EXISTS \(SELECT 1 FROM key_records remaining WHERE remaining\.principal_id=principals\.id\)/u);
  assert.match(sql, /NOT EXISTS \(SELECT 1 FROM conversation_unresolved_explicit_parents remaining WHERE remaining\.principal_id=principals\.id\)/u);
  assert.match(sql, /NOT EXISTS \(SELECT 1 FROM session_routing_terminals remaining WHERE remaining\.principal_id=principals\.id\)/u);
  assert.match(sql, /session_archive_import_records row JOIN request_records request_row ON request_row\.id=row\.target_request_id/u);
  assert.doesNotMatch(sql, /remaining\.status='active'/u);
  assert.match(sql, /ROLLBACK;\s*$/u);
  assert.doesNotMatch(sql, /DELETE FROM (?:request_records|ledger_entries|usage_reservations|generation_jobs|conversation_observations)/u);
});

test("PostgreSQL plan locks mutable dependencies and applies the same fail-closed contract", () => {
  const manifest = fixtureManifest();
  const sql = buildSql(manifest, manifestSha256(manifest), false, "postgres", 1234);
  assert.match(sql, /^BEGIN;\nSET TRANSACTION ISOLATION LEVEL SERIALIZABLE;/u);
  assert.match(sql, /LOCK TABLE .*request_records, usage_reservations, generation_jobs.*conversation_projection_outbox, conversation_unresolved_explicit_parents, session_routing_terminals, synchronous_image_idempotency IN SHARE ROW EXCLUSIVE MODE;/u);
  assert.doesNotMatch(sql, /legacy_key_credentials/u);
  assert.match(sql, /target_rotation_replays expected LEFT JOIN credential_rotation_replays/u);
  assert.match(sql, /completed_at IS NULL/u);
  assert.match(sql, /stats_aggregated_at IS NULL/u);
  assert.match(sql, /SHA256\(CONVERT_TO\(actual\.request_json,'UTF8'\)\)/u);
  assert.match(sql, /ROLLBACK;\s*$/u);
});

test("SQLite dry-run fails closed on unfinished requests, reservations and generations", () => {
  const workspace = mkdtempSync(join(tmpdir(), "mtc-api2-purge-guards-"));
  const database = join(workspace, "fixture.sqlite");
  const manifest = fixtureManifest();
  const manifestPath = join(workspace, "manifest.json");
  writePrivate(manifestPath, `${JSON.stringify(manifest)}\n`);
  success(run("sqlite3", [database], fixtureSql(manifest, false)), "initialize guard fixture");
  chmodSync(database, 0o600);
  const databaseArgs = ["--backend", "sqlite", "--sqlite-database", database];
  const blockers = [
    ["UPDATE request_records SET completed_at=NULL WHERE id='request_records-0';", "UPDATE request_records SET completed_at=3000 WHERE id='request_records-0';"],
    ["UPDATE usage_reservations SET status='reserved' WHERE id='usage_reservations-0';", "UPDATE usage_reservations SET status='settled' WHERE id='usage_reservations-0';"],
    ["UPDATE generation_jobs SET status='running' WHERE id='generation_jobs-0';", "UPDATE generation_jobs SET status='succeeded' WHERE id='generation_jobs-0';"],
    ["UPDATE generation_jobs SET stats_aggregated_at=NULL WHERE id='generation_jobs-0';", "UPDATE generation_jobs SET stats_aggregated_at=3000 WHERE id='generation_jobs-0';"],
    ["UPDATE conversation_projection_outbox SET projected_at=NULL WHERE request_id='00000000-0000-4000-8000-000000001200';", "UPDATE conversation_projection_outbox SET projected_at=2800 WHERE request_id='00000000-0000-4000-8000-000000001200';"],
    ["UPDATE synchronous_image_idempotency SET lease_expires_at=9999999999999 WHERE idempotency_key='fixture-image-00';", "UPDATE synchronous_image_idempotency SET lease_expires_at=2500 WHERE idempotency_key='fixture-image-00';"],
  ];
  for (const [index, [introduce, restore]] of blockers.entries()) {
    success(run("sqlite3", [database], introduce), `introduce blocker ${index}`);
    const result = run(process.execPath, toolArgs(workspace, manifestPath, join(workspace, `blocked-${index}.json`), databaseArgs));
    assert.notEqual(result.status, 0, `blocker ${index} must reject the purge`);
    success(run("sqlite3", [database], restore), `restore blocker ${index}`);
  }
});

test("SQLite dry-run fails closed on reviewed child and group CAS drift", () => {
  const workspace = mkdtempSync(join(tmpdir(), "mtc-api2-purge-cas-"));
  const database = join(workspace, "fixture.sqlite");
  const manifest = fixtureManifest();
  const manifestPath = join(workspace, "manifest.json");
  writePrivate(manifestPath, `${JSON.stringify(manifest)}\n`);
  success(run("sqlite3", [database], fixtureSql(manifest, false)), "initialize CAS fixture");
  chmodSync(database, 0o600);
  const databaseArgs = ["--backend", "sqlite", "--sqlite-database", database];
  const drifts = [
    ["UPDATE routing_grants SET created_at=0 WHERE key_id='00000000-0000-4000-8000-000000000200' AND model_route_id='00000000-0000-4000-8000-000000000700';", "UPDATE routing_grants SET created_at=1900 WHERE key_id='00000000-0000-4000-8000-000000000200' AND model_route_id='00000000-0000-4000-8000-000000000700';"],
    ["UPDATE credential_rotation_replays SET request_hash='drift' WHERE idempotency_key='rotate-0';", "UPDATE credential_rotation_replays SET request_hash='request-0' WHERE idempotency_key='rotate-0';"],
    ["UPDATE credential_groups SET name='drift' WHERE id='00000000-0000-4000-8000-000000000600';", "UPDATE credential_groups SET name='legacy-group-0' WHERE id='00000000-0000-4000-8000-000000000600';"],
    ["UPDATE route_groups SET name='drift' WHERE id='00000000-0000-4000-8000-000000000900';", "UPDATE route_groups SET name='legacy-route-group' WHERE id='00000000-0000-4000-8000-000000000900';"],
    ["UPDATE conversation_projection_outbox SET request_json='{\"fixture\":9}' WHERE request_id='00000000-0000-4000-8000-000000001200';", "UPDATE conversation_projection_outbox SET request_json='{\"fixture\":0}' WHERE request_id='00000000-0000-4000-8000-000000001200';"],
    ["UPDATE synchronous_image_idempotency SET request_hash='drift' WHERE idempotency_key='fixture-image-00';", `UPDATE synchronous_image_idempotency SET request_hash='${manifest.synchronous_image_idempotency.find(row => row.idempotency_key === "fixture-image-00")!.request_hash}' WHERE idempotency_key='fixture-image-00';`],
    ["UPDATE request_records SET response_object='{\"drift\":true}' WHERE id='00000000-0000-4000-8000-000000001600';", "UPDATE request_records SET response_object='{\"data\":[{\"url\":\"fixture-only-0\"}]}' WHERE id='00000000-0000-4000-8000-000000001600';"],
  ];
  for (const [index, [introduce, restore]] of drifts.entries()) {
    success(run("sqlite3", [database], introduce), `introduce drift ${index}`);
    const result = run(process.execPath, toolArgs(workspace, manifestPath, join(workspace, `drift-${index}.json`), databaseArgs));
    assert.notEqual(result.status, 0, `drift ${index} must reject the purge`);
    success(run("sqlite3", [database], restore), `restore drift ${index}`);
  }
});

test("SQLite dry-run, approved apply and replay preserve historical facts", () => {
  const workspace = mkdtempSync(join(tmpdir(), "mtc-api2-purge-sqlite-"));
  const database = join(workspace, "fixture.sqlite");
  const manifest = fixtureManifest();
  const manifestPath = join(workspace, "manifest.json");
  writePrivate(manifestPath, `${JSON.stringify(manifest)}\n`);
  success(run("sqlite3", [database], fixtureSql(manifest, false)), "initialize SQLite");
  chmodSync(database, 0o600);
  const databaseArgs = ["--backend", "sqlite", "--sqlite-database", database];
  const before = success(run("sqlite3", [database], "SELECT COUNT(*) FROM request_records;"), "SQLite history count");
  const dryReceipt = join(workspace, "dry.json");
  const dry = success(run(process.execPath, toolArgs(workspace, manifestPath, dryReceipt, databaseArgs)), "SQLite dry-run");
  assert.equal(JSON.parse(dry).mode, "dry-run");
  assert.equal(success(run("sqlite3", [database], "SELECT COUNT(*) FROM key_records;"), "SQLite dry-run keys"), "8");
  assert.equal(success(run("sqlite3", [database], "SELECT COUNT(*) FROM request_records;"), "SQLite dry-run history"), before);
  const applyReceipt = join(workspace, "apply.json");
  const applied = JSON.parse(success(run(process.execPath, toolArgs(workspace, manifestPath, applyReceipt, databaseArgs, true)), "SQLite apply"));
  assert.equal(applied.outcome, "planned");
  assert.equal(applied.conversation_projection_outbox, 7);
  assert.equal(applied.synchronous_image_idempotency, 24);
  assert.equal(success(run("sqlite3", [database], "SELECT COUNT(*) FROM key_records;"), "SQLite applied keys"), "1");
  assert.equal(success(run("sqlite3", [database], "SELECT status FROM key_records;"), "SQLite retained archived key"), "revoked");
  assert.equal(success(run("sqlite3", [database], "SELECT COUNT(*) FROM credential_rotation_replays;"), "SQLite rotation replays"), "0");
  assert.equal(success(run("sqlite3", [database], "SELECT COUNT(*) FROM synchronous_image_idempotency;"), "SQLite synchronous replay rows"), "0");
  assert.equal(success(run("sqlite3", [database], "SELECT COUNT(*) FROM credential_groups;"), "SQLite empty credential groups"), "0");
  assert.equal(success(run("sqlite3", [database], "SELECT COUNT(*) FROM route_groups;"), "SQLite empty route groups"), "0");
  assert.equal(success(run("sqlite3", [database], "SELECT COUNT(*) FROM deleted_upstream_account_snapshots;"), "SQLite applied snapshots"), "0");
  assert.equal(success(run("sqlite3", [database], "SELECT COUNT(*) FROM request_records;"), "SQLite applied history"), before);
  assert.equal(success(run("sqlite3", [database], "SELECT COUNT(*) FROM principals;"), "SQLite retained dependent principals"), "7");
  assert.equal(success(run("sqlite3", [database], "SELECT COUNT(*) FROM conversation_observations WHERE (session_name IS NULL OR session_name='') AND labels_json='{\"state\":\"retired\"}';"), "SQLite localized conversation tombstones"), "169");
  assert.equal(success(run("sqlite3", [database], "SELECT labels_json FROM conversation_observations WHERE id='00000000-0000-4000-8000-000000000800';"), "SQLite preserves unmarked labels"), "{\"ui\":\"preserve-this-label\"}");
  assert.equal(success(run("sqlite3", [database], "SELECT COUNT(*) FROM conversation_observations WHERE session_name LIKE 'retired-%' OR session_name LIKE '%00000000-%';"), "SQLite technical conversation titles"), "0");
  const replayReceipt = join(workspace, "replay.json");
  const replay = JSON.parse(success(run(process.execPath, toolArgs(workspace, manifestPath, replayReceipt, databaseArgs, true)), "SQLite replay"));
  assert.equal(replay.outcome, "replay");
});

const postgresConfigured = ["PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE"].every(name => Boolean(process.env[name]));

test("PostgreSQL dry-run and apply enforce the same reviewed cleanup contract", { skip: !postgresConfigured }, () => {
  const workspace = mkdtempSync(join(tmpdir(), "mtc-api2-purge-postgres-"));
  const schema = `purge_${Date.now()}_${process.pid}`;
  const environment = { ...process.env, PGOPTIONS: `-csearch_path=${schema}` };
  const psqlBase = ["-X", "--no-psqlrc", "-v", "ON_ERROR_STOP=1", "-qAt"];
  success(run("psql", psqlBase, `CREATE SCHEMA ${schema};`, process.env), "create PostgreSQL schema");
  try {
    const manifest = fixtureManifest();
    success(run("psql", psqlBase, fixtureSql(manifest, true), environment), "initialize PostgreSQL");
    const serviceFile = join(workspace, "pg_service.conf");
    writePrivate(serviceFile, `[purge_fixture]\nhost=${process.env.PGHOST}\nport=${process.env.PGPORT}\nuser=${process.env.PGUSER}\npassword=${process.env.PGPASSWORD}\ndbname=${process.env.PGDATABASE}\noptions=-csearch_path=${schema}\n`);
    const manifestPath = join(workspace, "manifest.json");
    writePrivate(manifestPath, `${JSON.stringify(manifest)}\n`);
    const databaseArgs = ["--backend", "postgres", "--pg-service-file", serviceFile, "--pg-service", "purge_fixture"];
    const dry = JSON.parse(success(run(process.execPath, toolArgs(workspace, manifestPath, join(workspace, "dry.json"), databaseArgs)), "PostgreSQL dry-run"));
    assert.equal(dry.mode, "dry-run");
    const applied = JSON.parse(success(run(process.execPath, toolArgs(workspace, manifestPath, join(workspace, "apply.json"), databaseArgs, true)), "PostgreSQL apply"));
    assert.equal(applied.outcome, "planned");
    assert.equal(success(run("psql", psqlBase, "SELECT COUNT(*) FROM request_records;", environment), "PostgreSQL history"), "31");
    assert.equal(success(run("psql", psqlBase, "SELECT COUNT(*) FROM key_records;", environment), "PostgreSQL keys"), "1");
    assert.equal(success(run("psql", psqlBase, "SELECT COUNT(*) FROM credential_rotation_replays;", environment), "PostgreSQL rotation replays"), "0");
    assert.equal(success(run("psql", psqlBase, "SELECT COUNT(*) FROM synchronous_image_idempotency;", environment), "PostgreSQL synchronous replay rows"), "0");
    assert.equal(success(run("psql", psqlBase, "SELECT COUNT(*) FROM principals;", environment), "PostgreSQL dependent principals"), "7");
  } finally {
    success(run("psql", psqlBase, `DROP SCHEMA ${schema} CASCADE;`, process.env), "drop PostgreSQL schema");
  }
});
