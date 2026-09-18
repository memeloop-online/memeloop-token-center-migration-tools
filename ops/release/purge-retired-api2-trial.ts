#!/usr/bin/env node
/**
 * Remove one reviewed retired API2 trial cohort from the product/configuration
 * surface while proving that durable traffic, billing, generation and
 * conversation facts are unchanged. The default mode executes the complete
 * transaction and rolls it back.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { invokedAsEntrypoint } from "../lib/invoked-as-entrypoint.ts";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const IDEMPOTENCY_KEY = /^[a-z0-9][a-z0-9._:-]{7,127}$/u;
const SERVICE = /^[A-Za-z0-9_.-]{1,128}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const LEGACY_TEXT = /(?:api2|legacy-cpa-bridge|cpa-|bridge)/iu;
const SNAPSHOT_NAME = /^(?:legacy-cpa-bridge-|cpa-).+/u;
const EXPECTED_SNAPSHOT_COUNT = 17;
const EXPECTED_KEY_COUNT = 7;
const EXPECTED_ROUTING_RELATION_COUNT = 16;
const MAX_MANIFEST_BYTES = 1024 * 1024;

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type Obj = { [key: string]: Json };

export class PurgeFailure extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export interface ReviewedSnapshot {
  upstream_account_id: string;
  name: string;
  driver: string;
  auth_kind: string;
  credential_generation: number;
  created_at: number;
  deleted_at: number;
}

export interface ReviewedCredential {
  credential_id: string;
  generation: number;
  fingerprint: string;
  created_at: number;
  revoked_at: number;
  plaintext_present: boolean;
}

export interface ReviewedRecoverySecret {
  credential_id: string;
  credential_generation: number;
  created_at: number;
  updated_at: number;
}

export interface ReviewedSourceProof {
  credential_id: string;
  proof_kind: string;
  source_digest: string;
  created_at: number;
}

export interface ReviewedMembership {
  credential_group_id: string;
  created_at: number;
}

export interface ReviewedGrant {
  model_route_id: string | null;
  route_group_id: string | null;
  created_at: number;
}

export interface ReviewedRevision {
  revision: number;
}

export interface ReviewedKey {
  key_id: string;
  principal_id: string;
  account_id: string;
  alias: string;
  currency: string;
  credential_generation: number;
  archived_at: number;
  created_at: number;
  updated_at: number;
  issued_ciphertext_present: boolean;
  credentials: ReviewedCredential[];
  recovery_secrets: ReviewedRecoverySecret[];
  source_proofs: ReviewedSourceProof[];
  credential_group_memberships: ReviewedMembership[];
  routing_grants: ReviewedGrant[];
  routing_revision: ReviewedRevision;
}

export interface ConversationRewrite {
  observation_id: string;
  key_id: string;
  session_name: string;
  labels_json: string;
  replacement_session_name: string;
  replacement_labels_json: string;
}

export interface ReviewedManifest {
  schema_version: 1;
  idempotency_key: string;
  tenant_external_id: string;
  expected: {
    deleted_upstream_account_snapshots: 17;
    key_records: 7;
    routing_relations: 16;
  };
  snapshots: ReviewedSnapshot[];
  keys: ReviewedKey[];
  conversation_rewrites: ConversationRewrite[];
}

interface Options {
  manifest?: string;
  receipt?: string;
  backend?: "postgres" | "sqlite";
  pgServiceFile?: string;
  pgService?: string;
  psqlBinary: string;
  sqliteDatabase?: string;
  sqliteBinary: string;
  approvedManifestSha256?: string;
  apply: boolean;
}

function fail(code: string, message: string): never {
  throw new PurgeFailure(code, message);
}

function object(value: Json | undefined, label: string): Obj {
  if (!value || Array.isArray(value) || typeof value !== "object") fail("manifest_invalid", `${label} must be an object`);
  return value as Obj;
}

function exactKeys(value: Obj, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail("manifest_invalid", `${label} fields do not match the schema`);
}

function text(value: Json | undefined, label: string, max = 500): string {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || Buffer.byteLength(value) > max || /[\u0000-\u001f\u007f]/u.test(value)) fail("manifest_invalid", `${label} must be bounded non-empty text`);
  return value;
}

function integer(value: Json | undefined, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) fail("manifest_invalid", `${label} must be a non-negative safe integer`);
  return value;
}

function bool(value: Json | undefined, label: string): boolean {
  if (typeof value !== "boolean") fail("manifest_invalid", `${label} must be boolean`);
  return value;
}

function uuid(value: Json | undefined, label: string): string {
  const parsed = text(value, label, 36);
  if (!UUID.test(parsed)) fail("manifest_invalid", `${label} must be a lowercase UUID`);
  return parsed;
}

function nullableUuid(value: Json | undefined, label: string): string | null {
  return value === null ? null : uuid(value, label);
}

function canonical(value: Json): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key]!)}`).join(",")}}`;
  const encoded = JSON.stringify(value);
  if (encoded === undefined) fail("manifest_invalid", "manifest contains a non-JSON value");
  return encoded;
}

function sortedUnique<T>(items: T[], identity: (item: T) => string, label: string): T[] {
  const sorted = [...items].sort((left, right) => identity(left).localeCompare(identity(right)));
  if (new Set(sorted.map(identity)).size !== sorted.length) fail("manifest_invalid", `${label} must be unique`);
  if (items.some((item, index) => identity(item) !== identity(sorted[index]!))) fail("manifest_invalid", `${label} must be sorted`);
  return items;
}

function parseCredential(value: Json, label: string): ReviewedCredential {
  const item = object(value, label);
  exactKeys(item, ["credential_id", "generation", "fingerprint", "created_at", "revoked_at", "plaintext_present"], label);
  return {
    credential_id: uuid(item.credential_id, `${label}.credential_id`),
    generation: integer(item.generation, `${label}.generation`),
    fingerprint: text(item.fingerprint, `${label}.fingerprint`, 128),
    created_at: integer(item.created_at, `${label}.created_at`),
    revoked_at: integer(item.revoked_at, `${label}.revoked_at`),
    plaintext_present: bool(item.plaintext_present, `${label}.plaintext_present`),
  };
}

function parseRecovery(value: Json, label: string): ReviewedRecoverySecret {
  const item = object(value, label);
  exactKeys(item, ["credential_id", "credential_generation", "created_at", "updated_at"], label);
  return {
    credential_id: uuid(item.credential_id, `${label}.credential_id`),
    credential_generation: integer(item.credential_generation, `${label}.credential_generation`),
    created_at: integer(item.created_at, `${label}.created_at`),
    updated_at: integer(item.updated_at, `${label}.updated_at`),
  };
}

function parseProof(value: Json, label: string): ReviewedSourceProof {
  const item = object(value, label);
  exactKeys(item, ["credential_id", "proof_kind", "source_digest", "created_at"], label);
  return {
    credential_id: uuid(item.credential_id, `${label}.credential_id`),
    proof_kind: text(item.proof_kind, `${label}.proof_kind`, 128),
    source_digest: text(item.source_digest, `${label}.source_digest`, 256),
    created_at: integer(item.created_at, `${label}.created_at`),
  };
}

function parseMembership(value: Json, label: string): ReviewedMembership {
  const item = object(value, label);
  exactKeys(item, ["credential_group_id", "created_at"], label);
  return { credential_group_id: uuid(item.credential_group_id, `${label}.credential_group_id`), created_at: integer(item.created_at, `${label}.created_at`) };
}

function parseGrant(value: Json, label: string): ReviewedGrant {
  const item = object(value, label);
  exactKeys(item, ["model_route_id", "route_group_id", "created_at"], label);
  const modelRoute = nullableUuid(item.model_route_id, `${label}.model_route_id`);
  const routeGroup = nullableUuid(item.route_group_id, `${label}.route_group_id`);
  if ((modelRoute === null) === (routeGroup === null)) fail("manifest_invalid", `${label} must select exactly one route target`);
  return { model_route_id: modelRoute, route_group_id: routeGroup, created_at: integer(item.created_at, `${label}.created_at`) };
}

function array(value: Json | undefined, label: string, max = 500): Json[] {
  if (!Array.isArray(value) || value.length > max) fail("manifest_invalid", `${label} must be a bounded array`);
  return value;
}

function parseKey(value: Json, index: number): ReviewedKey {
  const label = `keys[${index}]`;
  const item = object(value, label);
  exactKeys(item, ["key_id", "principal_id", "account_id", "alias", "currency", "credential_generation", "archived_at", "created_at", "updated_at", "issued_ciphertext_present", "credentials", "recovery_secrets", "source_proofs", "credential_group_memberships", "routing_grants", "routing_revision"], label);
  const alias = text(item.alias, `${label}.alias`, 200);
  if (!LEGACY_TEXT.test(alias)) fail("manifest_invalid", `${label}.alias does not identify retired API2/bridge material`);
  const credentials = array(item.credentials, `${label}.credentials`).map((entry, child) => parseCredential(entry, `${label}.credentials[${child}]`));
  const recovery = array(item.recovery_secrets, `${label}.recovery_secrets`).map((entry, child) => parseRecovery(entry, `${label}.recovery_secrets[${child}]`));
  const proofs = array(item.source_proofs, `${label}.source_proofs`).map((entry, child) => parseProof(entry, `${label}.source_proofs[${child}]`));
  const memberships = array(item.credential_group_memberships, `${label}.credential_group_memberships`).map((entry, child) => parseMembership(entry, `${label}.credential_group_memberships[${child}]`));
  const grants = array(item.routing_grants, `${label}.routing_grants`).map((entry, child) => parseGrant(entry, `${label}.routing_grants[${child}]`));
  const revision = object(item.routing_revision, `${label}.routing_revision`);
  exactKeys(revision, ["revision"], `${label}.routing_revision`);
  const parsed: ReviewedKey = {
    key_id: uuid(item.key_id, `${label}.key_id`),
    principal_id: uuid(item.principal_id, `${label}.principal_id`),
    account_id: uuid(item.account_id, `${label}.account_id`),
    alias,
    currency: text(item.currency, `${label}.currency`, 32),
    credential_generation: integer(item.credential_generation, `${label}.credential_generation`),
    archived_at: integer(item.archived_at, `${label}.archived_at`),
    created_at: integer(item.created_at, `${label}.created_at`),
    updated_at: integer(item.updated_at, `${label}.updated_at`),
    issued_ciphertext_present: bool(item.issued_ciphertext_present, `${label}.issued_ciphertext_present`),
    credentials: sortedUnique(credentials, entry => entry.credential_id, `${label}.credentials`),
    recovery_secrets: sortedUnique(recovery, entry => entry.credential_id, `${label}.recovery_secrets`),
    source_proofs: sortedUnique(proofs, entry => `${entry.credential_id}:${entry.proof_kind}`, `${label}.source_proofs`),
    credential_group_memberships: sortedUnique(memberships, entry => entry.credential_group_id, `${label}.credential_group_memberships`),
    routing_grants: sortedUnique(grants, entry => `${entry.model_route_id ?? ""}:${entry.route_group_id ?? ""}`, `${label}.routing_grants`),
    routing_revision: { revision: integer(revision.revision, `${label}.routing_revision.revision`) },
  };
  const credentialIds = new Set(parsed.credentials.map(entry => entry.credential_id));
  if (parsed.credentials.length === 0 || parsed.credentials.some(entry => entry.generation > parsed.credential_generation)) fail("manifest_invalid", `${label} has an invalid credential set`);
  if (parsed.recovery_secrets.some(entry => !credentialIds.has(entry.credential_id) || entry.credential_generation > parsed.credential_generation)) fail("manifest_invalid", `${label} recovery rows must belong to reviewed credentials`);
  if (parsed.source_proofs.some(entry => !credentialIds.has(entry.credential_id))) fail("manifest_invalid", `${label} source proofs must belong to reviewed credentials`);
  return parsed;
}

function parseRewrite(value: Json, index: number): ConversationRewrite {
  const label = `conversation_rewrites[${index}]`;
  const item = object(value, label);
  exactKeys(item, ["observation_id", "key_id", "session_name", "labels_json", "replacement_session_name", "replacement_labels_json"], label);
  const sessionName = text(item.session_name, `${label}.session_name`, 1024);
  const labelsJson = text(item.labels_json, `${label}.labels_json`, 64 * 1024);
  const replacementSessionName = text(item.replacement_session_name, `${label}.replacement_session_name`, 1024);
  const replacementLabelsJson = text(item.replacement_labels_json, `${label}.replacement_labels_json`, 64 * 1024);
  try { JSON.parse(labelsJson); JSON.parse(replacementLabelsJson); } catch { fail("manifest_invalid", `${label} labels must be valid JSON`); }
  if (!LEGACY_TEXT.test(`${sessionName}\n${labelsJson}`)) fail("manifest_invalid", `${label} does not contain retired API2/bridge text`);
  if (!replacementSessionName.startsWith("retired-") || (replacementLabelsJson !== "{}" && !replacementLabelsJson.includes("retired-")) || LEGACY_TEXT.test(`${replacementSessionName}\n${replacementLabelsJson}`)) fail("manifest_invalid", `${label} replacement must be neutral retired-* metadata`);
  return {
    observation_id: uuid(item.observation_id, `${label}.observation_id`),
    key_id: uuid(item.key_id, `${label}.key_id`),
    session_name: sessionName,
    labels_json: labelsJson,
    replacement_session_name: replacementSessionName,
    replacement_labels_json: replacementLabelsJson,
  };
}

export function parseManifest(value: Json): ReviewedManifest {
  const root = object(value, "manifest");
  exactKeys(root, ["schema_version", "idempotency_key", "tenant_external_id", "expected", "snapshots", "keys", "conversation_rewrites"], "manifest");
  if (root.schema_version !== 1) fail("manifest_invalid", "unsupported manifest schema_version");
  const idempotencyKey = text(root.idempotency_key, "idempotency_key", 128);
  if (!IDEMPOTENCY_KEY.test(idempotencyKey)) fail("manifest_invalid", "idempotency_key has an unsupported format");
  const expected = object(root.expected, "expected");
  exactKeys(expected, ["deleted_upstream_account_snapshots", "key_records", "routing_relations"], "expected");
  if (expected.deleted_upstream_account_snapshots !== EXPECTED_SNAPSHOT_COUNT || expected.key_records !== EXPECTED_KEY_COUNT || expected.routing_relations !== EXPECTED_ROUTING_RELATION_COUNT) fail("manifest_invalid", "manifest exact counts are not the approved 17/7/16 cohort");
  const snapshots = array(root.snapshots, "snapshots", EXPECTED_SNAPSHOT_COUNT).map((entry, index) => {
    const label = `snapshots[${index}]`;
    const item = object(entry, label);
    exactKeys(item, ["upstream_account_id", "name", "driver", "auth_kind", "credential_generation", "created_at", "deleted_at"], label);
    const name = text(item.name, `${label}.name`, 200);
    if (!SNAPSHOT_NAME.test(name)) fail("manifest_invalid", `${label}.name is outside the approved legacy snapshot patterns`);
    return {
      upstream_account_id: uuid(item.upstream_account_id, `${label}.upstream_account_id`),
      name,
      driver: text(item.driver, `${label}.driver`, 128),
      auth_kind: text(item.auth_kind, `${label}.auth_kind`, 128),
      credential_generation: integer(item.credential_generation, `${label}.credential_generation`),
      created_at: integer(item.created_at, `${label}.created_at`),
      deleted_at: integer(item.deleted_at, `${label}.deleted_at`),
    };
  });
  const keys = array(root.keys, "keys", EXPECTED_KEY_COUNT).map(parseKey);
  const rewrites = array(root.conversation_rewrites, "conversation_rewrites", 500).map(parseRewrite);
  if (snapshots.length !== EXPECTED_SNAPSHOT_COUNT || keys.length !== EXPECTED_KEY_COUNT) fail("manifest_invalid", "manifest object counts do not match the approved cohort");
  sortedUnique(snapshots, entry => entry.upstream_account_id, "snapshots");
  sortedUnique(keys, entry => entry.key_id, "keys");
  sortedUnique(rewrites, entry => entry.observation_id, "conversation_rewrites");
  const keyIds = new Set(keys.map(entry => entry.key_id));
  if (rewrites.some(entry => !keyIds.has(entry.key_id))) fail("manifest_invalid", "conversation rewrites must belong to reviewed keys");
  const relationCount = keys.reduce((count, key) => count + key.routing_grants.length + 1, 0);
  if (relationCount !== EXPECTED_ROUTING_RELATION_COUNT) fail("manifest_invalid", "routing grant/revision relation count is not exactly 16");
  return {
    schema_version: 1,
    idempotency_key: idempotencyKey,
    tenant_external_id: text(root.tenant_external_id, "tenant_external_id", 200),
    expected: { deleted_upstream_account_snapshots: 17, key_records: 7, routing_relations: 16 },
    snapshots,
    keys,
    conversation_rewrites: rewrites,
  };
}

export function manifestSha256(manifest: ReviewedManifest): string {
  return createHash("sha256").update(canonical(manifest as unknown as Json)).digest("hex");
}

function sqlText(value: string): string { return `'${value.replaceAll("'", "''")}'`; }
function sqlNullable(value: string | null): string { return value === null ? "NULL" : sqlText(value); }
function sqlBool(value: boolean): string { return value ? "1" : "0"; }
function tuples(rows: string[][]): string { return rows.map(row => `(${row.join(",")})`).join(",\n"); }

const protectedTables = [
  "request_records", "request_events", "request_record_locators", "request_event_locators",
  "request_stats_facts", "request_daily_aggregates", "usage_daily_aggregates",
  "usage_analysis_hourly", "usage_analysis_daily", "session_usage_totals",
  "session_usage_hourly", "session_usage_daily", "session_archive_totals",
  "session_archive_import_records", "session_archive_correlations",
  "session_archive_unlinked_requests", "session_archive_quarantine_resolutions",
  "generation_jobs", "generation_stats_facts", "generation_daily_aggregates",
  "generation_usage_dimensions_hourly", "generation_usage_dimensions_daily",
  "ledger_entries", "usage_reservations", "account_settlement_feed",
  "key_budget_state", "key_budget_daily_rollups", "key_budget_usage_events",
  "rate_limit_windows", "key_runtime_state", "metered_usage_projection_outbox",
  "memeloop_cloud_subscription_events", "key_credential_recovery_audit",
  "key_credential_recovery_access_audit", "conversation_observations",
  "conversation_key_clusters", "conversation_projection_outbox",
  "conversation_unresolved_explicit_parents", "session_routing_terminals",
  "synchronous_image_idempotency",
] as const;

function assertion(predicate: string): string {
  return `INSERT INTO purge_guard(value) SELECT 1 WHERE ${predicate};`;
}

export function buildSql(manifest: ReviewedManifest, digest: string, apply: boolean, backend: "postgres" | "sqlite", now: number): string {
  const keyRows = manifest.keys.map(key => [sqlText(key.key_id), sqlText(key.principal_id), sqlText(key.account_id), sqlText(key.alias), sqlText(key.currency), String(key.credential_generation), String(key.archived_at), String(key.created_at), String(key.updated_at), sqlBool(key.issued_ciphertext_present)]);
  const snapshotRows = manifest.snapshots.map(snapshot => [sqlText(snapshot.upstream_account_id), sqlText(snapshot.name), sqlText(snapshot.driver), sqlText(snapshot.auth_kind), String(snapshot.credential_generation), String(snapshot.created_at), String(snapshot.deleted_at)]);
  const credentialRows = manifest.keys.flatMap(key => key.credentials.map(credential => [sqlText(key.key_id), sqlText(credential.credential_id), String(credential.generation), sqlText(credential.fingerprint), String(credential.created_at), String(credential.revoked_at), sqlBool(credential.plaintext_present)]));
  const recoveryRows = manifest.keys.flatMap(key => key.recovery_secrets.map(recovery => [sqlText(key.key_id), sqlText(recovery.credential_id), String(recovery.credential_generation), String(recovery.created_at), String(recovery.updated_at)]));
  const proofRows = manifest.keys.flatMap(key => key.source_proofs.map(proof => [sqlText(key.key_id), sqlText(proof.credential_id), sqlText(proof.proof_kind), sqlText(proof.source_digest), String(proof.created_at)]));
  const membershipRows = manifest.keys.flatMap(key => key.credential_group_memberships.map(membership => [sqlText(key.key_id), sqlText(membership.credential_group_id), String(membership.created_at)]));
  const grantRows = manifest.keys.flatMap(key => key.routing_grants.map(grant => [sqlText(key.key_id), sqlNullable(grant.model_route_id), sqlNullable(grant.route_group_id), String(grant.created_at)]));
  const revisionRows = manifest.keys.map(key => [sqlText(key.key_id), String(key.routing_revision.revision)]);
  const rewriteRows = manifest.conversation_rewrites.map(rewrite => [sqlText(rewrite.observation_id), sqlText(rewrite.key_id), sqlText(rewrite.session_name), sqlText(rewrite.labels_json), sqlText(rewrite.replacement_session_name), sqlText(rewrite.replacement_labels_json)]);
  const values = (rows: string[][], fallback: string[]) => rows.length === 0 ? `SELECT ${fallback.join(",")} WHERE 0` : `VALUES ${tuples(rows)}`;
  const begin = backend === "sqlite" ? "BEGIN IMMEDIATE;" : "BEGIN;\nSET TRANSACTION ISOLATION LEVEL SERIALIZABLE;";
  const lock = backend === "postgres" ? "LOCK TABLE deleted_upstream_account_snapshots, key_records, key_credentials, key_credential_recovery_secrets, key_credential_source_proofs, credential_group_memberships, routing_grants, routing_grant_relation_revisions, principals, conversation_observations IN SHARE ROW EXCLUSIVE MODE;" : "";
  const replay = `EXISTS (SELECT 1 FROM migration_tool_operation_receipts WHERE idempotency_key=${sqlText(manifest.idempotency_key)})`;
  const fresh = "(SELECT initial_replay FROM operation_state)=0";
  const protectedBefore = protectedTables.map(table => `INSERT INTO protected_counts(table_name,before_count) SELECT ${sqlText(table)},COUNT(*) FROM ${table} row WHERE row.key_id IN (SELECT key_id FROM target_keys);`).join("\n");
  const protectedAfter = protectedTables.map(table => assertion(`(SELECT before_count FROM protected_counts WHERE table_name=${sqlText(table)})<>(SELECT COUNT(*) FROM ${table} row WHERE row.key_id IN (SELECT key_id FROM target_keys))`)).join("\n");
  const relationExpected = EXPECTED_ROUTING_RELATION_COUNT;
  return `${begin}
${lock}
CREATE TABLE IF NOT EXISTS migration_tool_operation_receipts (
  idempotency_key TEXT PRIMARY KEY,
  operation_kind TEXT NOT NULL,
  manifest_sha256 TEXT NOT NULL,
  applied_at BIGINT NOT NULL,
  summary_json TEXT NOT NULL
);
CREATE TEMP TABLE operation_state(initial_replay BIGINT NOT NULL);
INSERT INTO operation_state SELECT CASE WHEN ${replay} THEN 1 ELSE 0 END;
CREATE TEMP TABLE purge_guard(value BIGINT NOT NULL CHECK(value=0));
CREATE TEMP TABLE target_snapshots(upstream_account_id TEXT PRIMARY KEY,name TEXT NOT NULL,driver TEXT NOT NULL,auth_kind TEXT NOT NULL,credential_generation BIGINT NOT NULL,created_at BIGINT NOT NULL,deleted_at BIGINT NOT NULL);
INSERT INTO target_snapshots ${values(snapshotRows, ["''", "''", "''", "''", "0", "0", "0"])};
CREATE TEMP TABLE target_keys(key_id TEXT PRIMARY KEY,principal_id TEXT NOT NULL,account_id TEXT NOT NULL,alias TEXT NOT NULL,currency TEXT NOT NULL,credential_generation BIGINT NOT NULL,archived_at BIGINT NOT NULL,created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL,issued_ciphertext_present BIGINT NOT NULL);
INSERT INTO target_keys ${values(keyRows, ["''", "''", "''", "''", "''", "0", "0", "0", "0", "0"])};
CREATE TEMP TABLE target_credentials(key_id TEXT NOT NULL,credential_id TEXT PRIMARY KEY,generation BIGINT NOT NULL,fingerprint TEXT NOT NULL,created_at BIGINT NOT NULL,revoked_at BIGINT NOT NULL,plaintext_present BIGINT NOT NULL);
INSERT INTO target_credentials ${values(credentialRows, ["''", "''", "0", "''", "0", "0", "0"])};
CREATE TEMP TABLE target_recovery(key_id TEXT NOT NULL,credential_id TEXT PRIMARY KEY,credential_generation BIGINT NOT NULL,created_at BIGINT NOT NULL,updated_at BIGINT NOT NULL);
INSERT INTO target_recovery ${values(recoveryRows, ["''", "''", "0", "0", "0"])};
CREATE TEMP TABLE target_proofs(key_id TEXT NOT NULL,credential_id TEXT NOT NULL,proof_kind TEXT NOT NULL,source_digest TEXT NOT NULL,created_at BIGINT NOT NULL,PRIMARY KEY(credential_id,proof_kind));
INSERT INTO target_proofs ${values(proofRows, ["''", "''", "''", "''", "0"])};
CREATE TEMP TABLE target_memberships(key_id TEXT NOT NULL,credential_group_id TEXT NOT NULL,created_at BIGINT NOT NULL,PRIMARY KEY(key_id,credential_group_id));
INSERT INTO target_memberships ${values(membershipRows, ["''", "''", "0"])};
CREATE TEMP TABLE target_grants(key_id TEXT NOT NULL,model_route_id TEXT,route_group_id TEXT,created_at BIGINT NOT NULL);
INSERT INTO target_grants ${values(grantRows, ["''", "NULL", "NULL", "0"])};
CREATE TEMP TABLE target_revisions(key_id TEXT PRIMARY KEY,revision BIGINT NOT NULL);
INSERT INTO target_revisions ${values(revisionRows, ["''", "0"])};
CREATE TEMP TABLE target_rewrites(observation_id TEXT PRIMARY KEY,key_id TEXT NOT NULL,session_name TEXT NOT NULL,labels_json TEXT NOT NULL,replacement_session_name TEXT NOT NULL,replacement_labels_json TEXT NOT NULL);
INSERT INTO target_rewrites ${values(rewriteRows, ["''", "''", "''", "''", "''", "''"])};
${assertion(`EXISTS (SELECT 1 FROM migration_tool_operation_receipts WHERE idempotency_key=${sqlText(manifest.idempotency_key)} AND (operation_kind<>'retired-api2-trial-purge-v1' OR manifest_sha256<>${sqlText(digest)}))`)}
${assertion(`${fresh} AND (SELECT COUNT(*) FROM target_snapshots)<>${EXPECTED_SNAPSHOT_COUNT}`)}
${assertion(`${fresh} AND (SELECT COUNT(*) FROM target_keys)<>${EXPECTED_KEY_COUNT}`)}
${assertion(`${fresh} AND ((SELECT COUNT(*) FROM target_grants)+(SELECT COUNT(*) FROM target_revisions))<>${relationExpected}`)}
${assertion(`${fresh} AND (SELECT COUNT(*) FROM tenants WHERE external_id=${sqlText(manifest.tenant_external_id)})<>1`)}
${assertion(`${fresh} AND EXISTS (SELECT 1 FROM target_snapshots expected LEFT JOIN deleted_upstream_account_snapshots actual ON actual.upstream_account_id=expected.upstream_account_id WHERE actual.upstream_account_id IS NULL OR actual.tenant_id<>(SELECT id FROM tenants WHERE external_id=${sqlText(manifest.tenant_external_id)}) OR actual.name<>expected.name OR actual.driver<>expected.driver OR actual.auth_kind<>expected.auth_kind OR actual.credential_generation<>expected.credential_generation OR actual.created_at<>expected.created_at OR actual.deleted_at<>expected.deleted_at)`)}
${assertion(`${fresh} AND EXISTS (SELECT 1 FROM deleted_upstream_account_snapshots actual JOIN tenants tenant ON tenant.id=actual.tenant_id WHERE tenant.external_id=${sqlText(manifest.tenant_external_id)} AND (actual.name LIKE 'legacy-cpa-bridge-%' OR actual.name LIKE 'cpa-%') AND NOT EXISTS (SELECT 1 FROM target_snapshots expected WHERE expected.upstream_account_id=actual.upstream_account_id))`)}
${assertion(`${fresh} AND EXISTS (SELECT 1 FROM target_keys expected LEFT JOIN key_records actual ON actual.id=expected.key_id WHERE actual.id IS NULL OR actual.tenant_id<>(SELECT id FROM tenants WHERE external_id=${sqlText(manifest.tenant_external_id)}) OR actual.principal_id<>expected.principal_id OR actual.account_id<>expected.account_id OR actual.alias<>expected.alias OR actual.currency<>expected.currency OR actual.status<>'revoked' OR actual.credential_generation<>expected.credential_generation OR actual.archived_at<>expected.archived_at OR actual.created_at<>expected.created_at OR actual.updated_at<>expected.updated_at OR CASE WHEN actual.issued_key_ciphertext IS NULL THEN 0 ELSE 1 END<>expected.issued_ciphertext_present)`)}
${assertion(`${fresh} AND EXISTS (SELECT 1 FROM key_records actual WHERE actual.tenant_id=(SELECT id FROM tenants WHERE external_id=${sqlText(manifest.tenant_external_id)}) AND (LOWER(actual.alias) LIKE '%api2%' OR LOWER(actual.alias) LIKE '%legacy-cpa-bridge%' OR LOWER(actual.alias) LIKE '%cpa-%' OR LOWER(actual.alias) LIKE '%bridge%') AND NOT EXISTS (SELECT 1 FROM target_keys expected WHERE expected.key_id=actual.id))`)}
${assertion(`${fresh} AND (SELECT COUNT(*) FROM key_credentials actual WHERE actual.key_id IN (SELECT key_id FROM target_keys))<>(SELECT COUNT(*) FROM target_credentials)`)}
${assertion(`${fresh} AND EXISTS (SELECT 1 FROM target_credentials expected LEFT JOIN key_credentials actual ON actual.id=expected.credential_id WHERE actual.id IS NULL OR actual.key_id<>expected.key_id OR actual.generation<>expected.generation OR actual.fingerprint<>expected.fingerprint OR actual.created_at<>expected.created_at OR actual.revoked_at<>expected.revoked_at OR CASE WHEN actual.secret_plaintext IS NULL THEN 0 ELSE 1 END<>expected.plaintext_present)`)}
${assertion(`${fresh} AND (SELECT COUNT(*) FROM key_credential_recovery_secrets actual WHERE actual.key_id IN (SELECT key_id FROM target_keys))<>(SELECT COUNT(*) FROM target_recovery)`)}
${assertion(`${fresh} AND EXISTS (SELECT 1 FROM target_recovery expected LEFT JOIN key_credential_recovery_secrets actual ON actual.credential_id=expected.credential_id WHERE actual.credential_id IS NULL OR actual.key_id<>expected.key_id OR actual.credential_generation<>expected.credential_generation OR actual.created_at<>expected.created_at OR actual.updated_at<>expected.updated_at OR actual.ciphertext='')`)}
${assertion(`${fresh} AND (SELECT COUNT(*) FROM key_credential_source_proofs actual JOIN key_credentials credential ON credential.id=actual.credential_id WHERE credential.key_id IN (SELECT key_id FROM target_keys))<>(SELECT COUNT(*) FROM target_proofs)`)}
${assertion(`${fresh} AND EXISTS (SELECT 1 FROM target_proofs expected LEFT JOIN key_credential_source_proofs actual ON actual.credential_id=expected.credential_id AND actual.proof_kind=expected.proof_kind WHERE actual.credential_id IS NULL OR actual.source_digest<>expected.source_digest OR actual.created_at<>expected.created_at)`)}
${assertion(`${fresh} AND (SELECT COUNT(*) FROM credential_group_memberships actual WHERE actual.key_id IN (SELECT key_id FROM target_keys))<>(SELECT COUNT(*) FROM target_memberships)`)}
${assertion(`${fresh} AND EXISTS (SELECT 1 FROM target_memberships expected LEFT JOIN credential_group_memberships actual ON actual.key_id=expected.key_id AND actual.credential_group_id=expected.credential_group_id WHERE actual.key_id IS NULL OR actual.created_at<>expected.created_at)`)}
${assertion(`${fresh} AND (SELECT COUNT(*) FROM routing_grants actual WHERE actual.key_id IN (SELECT key_id FROM target_keys))<>(SELECT COUNT(*) FROM target_grants)`)}
${assertion(`${fresh} AND EXISTS (SELECT 1 FROM target_grants expected LEFT JOIN routing_grants actual ON actual.key_id=expected.key_id AND ((actual.model_route_id=expected.model_route_id) OR (actual.model_route_id IS NULL AND expected.model_route_id IS NULL)) AND ((actual.route_group_id=expected.route_group_id) OR (actual.route_group_id IS NULL AND expected.route_group_id IS NULL)) WHERE actual.key_id IS NULL OR actual.created_at<>expected.created_at)`)}
${assertion(`${fresh} AND (SELECT COUNT(*) FROM routing_grant_relation_revisions actual WHERE actual.subject_kind='credential' AND actual.key_id IN (SELECT key_id FROM target_keys))<>(SELECT COUNT(*) FROM target_revisions)`)}
${assertion(`${fresh} AND EXISTS (SELECT 1 FROM target_revisions expected LEFT JOIN routing_grant_relation_revisions actual ON actual.subject_kind='credential' AND actual.subject_id=expected.key_id AND actual.key_id=expected.key_id WHERE actual.key_id IS NULL OR actual.tenant_id<>(SELECT id FROM tenants WHERE external_id=${sqlText(manifest.tenant_external_id)}) OR actual.model_route_id IS NOT NULL OR actual.revision<>expected.revision)`)}
${assertion(`${fresh} AND (SELECT COUNT(*) FROM conversation_observations actual WHERE actual.id IN (SELECT observation_id FROM target_rewrites))<>(SELECT COUNT(*) FROM target_rewrites)`)}
${assertion(`${fresh} AND EXISTS (SELECT 1 FROM target_rewrites expected LEFT JOIN conversation_observations actual ON actual.id=expected.observation_id WHERE actual.id IS NULL OR actual.key_id<>expected.key_id OR actual.session_name<>expected.session_name OR actual.labels_json<>expected.labels_json)`)}
CREATE TEMP TABLE protected_counts(table_name TEXT PRIMARY KEY,before_count BIGINT NOT NULL);
${protectedBefore}
UPDATE key_records SET issued_key_ciphertext=NULL WHERE id IN (SELECT key_id FROM target_keys) AND ${fresh};
UPDATE key_credentials SET secret_plaintext=NULL WHERE id IN (SELECT credential_id FROM target_credentials) AND ${fresh};
UPDATE key_credential_recovery_secrets SET ciphertext='' WHERE credential_id IN (SELECT credential_id FROM target_recovery) AND ${fresh};
UPDATE conversation_observations SET session_name=(SELECT replacement_session_name FROM target_rewrites WHERE observation_id=conversation_observations.id),labels_json=(SELECT replacement_labels_json FROM target_rewrites WHERE observation_id=conversation_observations.id) WHERE id IN (SELECT observation_id FROM target_rewrites) AND ${fresh};
DELETE FROM deleted_upstream_account_snapshots WHERE upstream_account_id IN (SELECT upstream_account_id FROM target_snapshots) AND ${fresh};
DELETE FROM key_credential_recovery_secrets WHERE credential_id IN (SELECT credential_id FROM target_recovery) AND ${fresh};
DELETE FROM key_credential_source_proofs WHERE credential_id IN (SELECT credential_id FROM target_proofs) AND ${fresh};
DELETE FROM credential_group_memberships WHERE key_id IN (SELECT key_id FROM target_keys) AND ${fresh};
DELETE FROM routing_grants WHERE key_id IN (SELECT key_id FROM target_keys) AND ${fresh};
DELETE FROM routing_grant_relation_revisions WHERE subject_kind='credential' AND key_id IN (SELECT key_id FROM target_keys) AND ${fresh};
DELETE FROM key_credentials WHERE id IN (SELECT credential_id FROM target_credentials) AND ${fresh};
DELETE FROM key_records WHERE id IN (SELECT key_id FROM target_keys) AND ${fresh};
DELETE FROM principals WHERE id IN (SELECT DISTINCT principal_id FROM target_keys) AND NOT EXISTS (SELECT 1 FROM key_records remaining WHERE remaining.principal_id=principals.id AND remaining.status='active') AND ${fresh};
${assertion(`${fresh} AND EXISTS (SELECT 1 FROM deleted_upstream_account_snapshots WHERE upstream_account_id IN (SELECT upstream_account_id FROM target_snapshots))`)}
${assertion(`${fresh} AND EXISTS (SELECT 1 FROM key_records WHERE id IN (SELECT key_id FROM target_keys))`)}
${assertion(`${fresh} AND EXISTS (SELECT 1 FROM key_credentials WHERE id IN (SELECT credential_id FROM target_credentials))`)}
${assertion(`${fresh} AND EXISTS (SELECT 1 FROM conversation_observations actual JOIN target_rewrites expected ON expected.observation_id=actual.id WHERE actual.session_name<>expected.replacement_session_name OR actual.labels_json<>expected.replacement_labels_json)`)}
${assertion(`${fresh} AND EXISTS (SELECT 1 FROM conversation_observations actual WHERE actual.key_id IN (SELECT key_id FROM target_keys) AND (LOWER(COALESCE(actual.session_name,'')) LIKE '%api2%' OR LOWER(COALESCE(actual.session_name,'')) LIKE '%legacy-cpa-bridge%' OR LOWER(COALESCE(actual.session_name,'')) LIKE '%cpa-%' OR LOWER(COALESCE(actual.session_name,'')) LIKE '%bridge%' OR LOWER(actual.labels_json) LIKE '%api2%' OR LOWER(actual.labels_json) LIKE '%legacy-cpa-bridge%' OR LOWER(actual.labels_json) LIKE '%cpa-%' OR LOWER(actual.labels_json) LIKE '%bridge%'))`)}
${protectedAfter}
INSERT INTO migration_tool_operation_receipts(idempotency_key,operation_kind,manifest_sha256,applied_at,summary_json)
SELECT ${sqlText(manifest.idempotency_key)},'retired-api2-trial-purge-v1',${sqlText(digest)},${now},${sqlText(JSON.stringify({ deleted_upstream_account_snapshots: 17, key_records: 7, routing_relations: 16, conversation_rewrites: manifest.conversation_rewrites.length }))}
WHERE ${fresh};
${assertion(`(SELECT COUNT(*) FROM migration_tool_operation_receipts WHERE idempotency_key=${sqlText(manifest.idempotency_key)} AND operation_kind='retired-api2-trial-purge-v1' AND manifest_sha256=${sqlText(digest)})<>1`)}
SELECT CASE WHEN (SELECT initial_replay FROM operation_state)=1 THEN 'replay' ELSE 'planned' END,${EXPECTED_SNAPSHOT_COUNT},${EXPECTED_KEY_COUNT},${relationExpected},${manifest.conversation_rewrites.length},(SELECT COUNT(DISTINCT principal_id) FROM target_keys WHERE NOT EXISTS (SELECT 1 FROM key_records remaining WHERE remaining.principal_id=target_keys.principal_id AND remaining.status='active'));
${apply ? "COMMIT;" : "ROLLBACK;"}
`;
}

function regularProtectedFile(path: string, label: string, maxBytes: number): string {
  if (!isAbsolute(path)) fail("input_invalid", `${label} must be an absolute path`);
  const supplied = lstatSync(path);
  if (supplied.isSymbolicLink()) fail("input_invalid", `${label} must not be a symbolic link`);
  const resolved = realpathSync(path);
  const stat = lstatSync(resolved);
  if (!stat.isFile() || stat.nlink !== 1 || stat.size <= 0 || stat.size > maxBytes || (stat.mode & 0o077) !== 0) fail("input_invalid", `${label} must be a non-empty, private regular file`);
  return resolved;
}

function outputPath(path: string): string {
  if (!isAbsolute(path)) fail("input_invalid", "receipt output must be an absolute path");
  return resolve(path);
}

function parseArgs(argv: string[]): Options {
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write("usage: purge-retired-api2-trial --manifest FILE --receipt-output FILE --backend postgres|sqlite [database options] [--apply --approved-manifest-sha256 SHA256]\n\nPostgreSQL: --pg-service-file FILE --pg-service NAME [--psql-binary PATH]\nSQLite: --sqlite-database FILE [--sqlite-binary PATH]\nDefault mode is a complete transactional dry-run followed by ROLLBACK.\n");
    process.exit(0);
  }
  const result: Options = { psqlBinary: "psql", sqliteBinary: "sqlite3", apply: false };
  const valued: Record<string, keyof Options> = {
    "--manifest": "manifest", "--receipt-output": "receipt", "--backend": "backend",
    "--pg-service-file": "pgServiceFile", "--pg-service": "pgService", "--psql-binary": "psqlBinary",
    "--sqlite-database": "sqliteDatabase", "--sqlite-binary": "sqliteBinary",
    "--approved-manifest-sha256": "approvedManifestSha256",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (argument === "--apply") result.apply = true;
    else if (valued[argument]) {
      const value = argv[++index];
      if (!value) fail("arguments_invalid", `${argument} requires a value`);
      (result as unknown as Record<string, string | boolean | undefined>)[valued[argument]!] = value;
    } else fail("arguments_invalid", `unrecognized argument: ${argument}`);
  }
  if (!result.manifest || !result.receipt || (result.backend !== "postgres" && result.backend !== "sqlite")) fail("arguments_invalid", "manifest, receipt output and backend are required");
  if (result.backend === "postgres" && (!result.pgServiceFile || !result.pgService || !SERVICE.test(result.pgService))) fail("arguments_invalid", "PostgreSQL requires a valid service file and service name");
  if (result.backend === "sqlite" && !result.sqliteDatabase) fail("arguments_invalid", "SQLite requires --sqlite-database");
  if (result.apply && (!result.approvedManifestSha256 || !SHA256.test(result.approvedManifestSha256))) fail("approval_required", "apply requires --approved-manifest-sha256");
  if (!result.apply && result.approvedManifestSha256) fail("arguments_invalid", "manifest approval is accepted only with --apply");
  return result;
}

function runDatabase(options: Options, sql: string): string {
  const common = { input: sql, encoding: "utf8" as const, shell: false, maxBuffer: 1024 * 1024, stdio: ["pipe", "pipe", "pipe"] as ["pipe", "pipe", "pipe"] };
  const result = options.backend === "postgres"
    ? spawnSync(options.psqlBinary, ["-X", "--no-psqlrc", "--no-password", "-qAt", "-F", "|", "--set=ON_ERROR_STOP=1", `service=${options.pgService}`], { ...common, env: { ...process.env, PGSERVICEFILE: regularProtectedFile(options.pgServiceFile!, "PostgreSQL service file", 64 * 1024), PGAPPNAME: "mtc-retired-api2-trial-purge", PGCONNECT_TIMEOUT: process.env.PGCONNECT_TIMEOUT ?? "10" } })
    : spawnSync(options.sqliteBinary, ["-batch", "-noheader", "-separator", "|", regularProtectedFile(options.sqliteDatabase!, "SQLite database", Number.MAX_SAFE_INTEGER)], common);
  if (result.error || result.status !== 0) fail("database_rejected_plan", result.error ? "database client could not be started" : "database rejected the reviewed cleanup plan");
  const lines = result.stdout.trim().split("\n").filter(Boolean);
  const summary = lines.at(-1);
  if (!summary || !/^(?:planned|replay)\|17\|7\|16\|\d+\|\d+$/u.test(summary)) fail("database_receipt_invalid", "database did not return the bounded cleanup summary");
  return summary;
}

export function receipt(manifest: ReviewedManifest, digest: string, mode: "dry-run" | "apply", summary: string): Obj {
  const [outcome, snapshots, keys, relations, rewrites, principals] = summary.split("|");
  return {
    schema_version: 1,
    operation: "retired-api2-trial-purge-v1",
    mode,
    outcome: outcome!,
    idempotency_key: manifest.idempotency_key,
    manifest_sha256: digest,
    tenant_external_id_sha256: createHash("sha256").update(manifest.tenant_external_id).digest("hex"),
    deleted_upstream_account_snapshots: Number(snapshots),
    key_records: Number(keys),
    routing_relations: Number(relations),
    conversation_rewrites: Number(rewrites),
    eligible_principals: Number(principals),
  };
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const manifestPath = regularProtectedFile(options.manifest!, "manifest", MAX_MANIFEST_BYTES);
  let raw: Json;
  try { raw = JSON.parse(readFileSync(manifestPath, "utf8")) as Json; } catch { fail("manifest_invalid", "manifest is not valid JSON"); }
  const manifest = parseManifest(raw);
  const digest = manifestSha256(manifest);
  if (options.apply && options.approvedManifestSha256 !== digest) fail("approval_mismatch", "approved manifest SHA-256 does not match the reviewed manifest");
  const summary = runDatabase(options, buildSql(manifest, digest, options.apply, options.backend!, Date.now()));
  const result = receipt(manifest, digest, options.apply ? "apply" : "dry-run", summary);
  const destination = outputPath(options.receipt!);
  writeFileSync(destination, `${JSON.stringify(result, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (invokedAsEntrypoint("purge-retired-api2-trial", import.meta.url)) {
  main().catch((error: unknown) => {
    const failure = error instanceof PurgeFailure ? error : new PurgeFailure("unexpected_failure", "retired API2 trial purge failed");
    process.stderr.write(`${failure.code}: ${failure.message}\n`);
    process.exitCode = 1;
  });
}
