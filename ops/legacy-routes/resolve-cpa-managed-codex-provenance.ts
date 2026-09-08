#!/usr/bin/env node
/**
 * Produce a sealed, read-only binding receipt for already-imported CPA
 * managed Codex OAuth accounts.
 *
 * This is deliberately not an importer and does not read an OAuth document.
 * It proves an existing target account only by reproducing the product's
 * source-key HMAC, then looking up that immutable import provenance in one
 * PostgreSQL read-only transaction.  A changed OAuth refresh payload is
 * evidence about the current payload revision, never an instruction to call
 * the product import API again.
 */

import { spawnSync } from "node:child_process";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, openSync, readSync, unlinkSync, writeSync } from "node:fs";
import { basename, dirname, isAbsolute, parse, relative, resolve, sep } from "node:path";
import { readSourceIdentityKey } from "../cpa-upstreams/import-cpa-upstreams.ts";
import { parseSourceInventory } from "./import-cpa-model-routes.ts";
import { assertManagedCodexModelSnapshotConfig, managedCodexRouteSourceStableId, parseManagedCodexModelSnapshot } from "./cpa-managed-codex-route-parser.ts";
import { parseStrictJson } from "../lib/strict-json.ts";

const MAX_BYTES = 8 * 1024 * 1024;
const MAX_BINDINGS = 256;
const MAX_STATEMENT_TIMEOUT_MS = 60_000;
const SHA256 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TARGET_TENANT = /^[A-Za-z0-9._:-]{1,200}$/;
const SERVICE_NAME = /^[A-Za-z0-9_-]{1,63}$/;
const SOURCE_KEY_DOMAIN = "memeloop:cpa-managed-oauth:source-key:v1\0";

type ObjectValue = Record<string, unknown>;
export type ManagedCodexSourceEvidence = Readonly<{
  sourceImportTenant: string;
  targetTenant: string;
}>;
export type ManagedCodexProvenanceRequest = Readonly<{ sourceStableId: string; sourceKey: string }>;
export type ManagedCodexProvenanceObservation = Readonly<{
  sourceStableId: string;
  sourceKey: string;
  payloadDigest: string;
  contractVersion: number;
  accountId: string;
  driver: string;
  authKind: string;
  status: string;
  credentialGeneration: number;
  oauthSessionId: string;
  oauthDriver: string;
  oauthRefreshUrl: string;
  updatedAt: number;
}>;
export type PreparedManagedCodexProvenance = Readonly<{
  evidence: ManagedCodexSourceEvidence;
  sourceDigest: string;
  materialDigest: string;
  requests: readonly ManagedCodexProvenanceRequest[];
}>;
export type ManagedCodexBindingReceipt = Readonly<{
  receipt: Buffer;
  bindingCount: number;
  provenanceDigest: string;
  sourceDigest: string;
  materialDigest: string;
}>;

type Candidate = Readonly<{ sourceStableId: string; sourceProvider: string; driver: string }>;
type OutputTarget = Readonly<{ target: string; parentDescriptor: number }>;
type Options = Readonly<{
  sourceTenantMappingFile: string;
  sourceConfigFile: string;
  managedCodexModelSnapshotFile: string;
  sourceIdentityKeyFile: string;
  keyPepperFile: string;
  sourceInventoryFile: string;
  candidateMaterialFile: string;
  pgServiceFile: string;
  pgService: string;
  output: string;
  psqlBinary: string;
  statementTimeoutMs: number;
}>;
type MutableOptions = Partial<Options>;

export class ManagedCodexProvenanceFailure extends Error {}

const compare = (left: string, right: string): number => left < right ? -1 : left > right ? 1 : 0;
const digest = (value: Uint8Array | string): string => createHash("sha256").update(value).digest("hex");

function object(value: unknown, keys: readonly string[], label: string): ObjectValue {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new ManagedCodexProvenanceFailure(`${label} has an invalid schema`);
  const actual = Object.keys(value as ObjectValue).sort(compare), expected = [...keys].sort(compare);
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new ManagedCodexProvenanceFailure(`${label} has an invalid schema`);
  return value as ObjectValue;
}
function text(value: unknown, label: string, pattern?: RegExp, maximum = 500): string {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || Buffer.byteLength(value) > maximum || /[\0\r\n]/.test(value) || (pattern && !pattern.test(value))) throw new ManagedCodexProvenanceFailure(`${label} has an invalid schema`);
  return value;
}
function productTenant(value: unknown, label: string): string {
  if (typeof value !== "string" || Buffer.byteLength(value) > 200 || value.trim().length === 0 || [...value].some((character) => /\p{C}/u.test(character))) throw new ManagedCodexProvenanceFailure(`${label} has an invalid schema`);
  return value;
}
function relativeAuthPath(value: unknown): string {
  const path = text(value, "managed Codex auth relative path", undefined, 512);
  if (path.startsWith("/") || path.includes("\\") || path.split("/").some((segment) => !segment || segment === "." || segment === "..")) throw new ManagedCodexProvenanceFailure("managed Codex auth relative path is invalid");
  return path;
}
function positiveInteger(value: unknown, label: string, max: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > max) throw new ManagedCodexProvenanceFailure(`${label} has an invalid schema`);
  return Number(value);
}
function safeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0 || Number(value) > 1_000_000_000_000_000) throw new ManagedCodexProvenanceFailure(`${label} has an invalid schema`);
  return Number(value);
}
function strictJson(raw: Buffer, label: string): unknown {
  try { return parseStrictJson(new TextDecoder("utf-8", { fatal: true }).decode(raw)); }
  catch { throw new ManagedCodexProvenanceFailure(`${label} is not strict UTF-8 JSON`); }
}

/** Parse the sealed tenant mapping. Auth paths come only from the sealed CPA snapshot. */
export function parseManagedCodexSourceEvidence(raw: Buffer): ManagedCodexSourceEvidence {
  const root = object(strictJson(raw, "managed Codex source tenant mapping"), ["version", "source_import_tenant_external_id", "target_tenant_external_id", "source_kind", "source_type"], "managed Codex source tenant mapping");
  if (root.version !== 1 || root.source_kind !== "auth_file" || root.source_type !== "codex") throw new ManagedCodexProvenanceFailure("managed Codex source tenant mapping has an invalid schema");
  const sourceImportTenant = productTenant(root.source_import_tenant_external_id, "managed Codex source import tenant");
  const targetTenant = text(root.target_tenant_external_id, "managed Codex target tenant", TARGET_TENANT, 200);
  return { sourceImportTenant, targetTenant };
}

/** Match the product API's immutable managed OAuth source-key HMAC byte-for-byte. */
export function managedCodexImportSourceKey(keyPepper: Buffer, sourceImportTenant: string, relativePath: string): string {
  if (!Buffer.isBuffer(keyPepper) || keyPepper.length === 0 || keyPepper.length > 16 * 1024) throw new ManagedCodexProvenanceFailure("managed Codex key pepper is invalid");
  const tenant = productTenant(sourceImportTenant, "managed Codex source import tenant"), path = relativeAuthPath(relativePath);
  return createHmac("sha256", keyPepper)
    .update(SOURCE_KEY_DOMAIN)
    .update(tenant, "utf8")
    .update("\0", "utf8")
    .update("auth_file", "utf8")
    .update("\0", "utf8")
    .update(path, "utf8")
    .digest("hex");
}

function sourceCoordinateKey(value: ObjectValue, label: string): string {
  const source = object(value, ["provider", "model", "group", "upstream_prefix", "protocol"], label);
  const provider = text(source.provider, label), model = text(source.model, label);
  const group = source.group === null ? null : text(source.group, label), prefix = source.upstream_prefix === null ? null : text(source.upstream_prefix, label);
  if (source.protocol !== "openai" && source.protocol !== "anthropic") throw new ManagedCodexProvenanceFailure(`${label} has an invalid schema`);
  return JSON.stringify([provider, model, group, prefix, source.protocol]);
}
function managedCandidates(raw: Buffer, sourceDigest: string, validSourceCoordinates: ReadonlySet<string>): Candidate[] {
  const root = object(strictJson(raw, "provider candidate material"), ["version", "source_inventory_sha256", "provider_candidate_sets"], "provider candidate material");
  if (root.version !== 1 || root.source_inventory_sha256 !== sourceDigest || !Array.isArray(root.provider_candidate_sets) || root.provider_candidate_sets.length === 0 || root.provider_candidate_sets.length > 1_000) throw new ManagedCodexProvenanceFailure("provider candidate material does not match the selected source inventory");
  const selected = new Map<string, Candidate>(); let totalCandidates = 0;
  for (const value of root.provider_candidate_sets) {
    const item = object(value, ["source", "upstream_model", "protocol", "selection", "candidates"], "provider candidate set");
    const coordinate = sourceCoordinateKey(object(item.source, ["provider", "model", "group", "upstream_prefix", "protocol"], "provider candidate source"), "provider candidate source");
    const source = item.source as ObjectValue;
    if (!validSourceCoordinates.has(coordinate) || item.protocol !== source.protocol || item.selection !== "equal_round_robin" || !Array.isArray(item.candidates) || item.candidates.length === 0 || item.candidates.length > MAX_BINDINGS) throw new ManagedCodexProvenanceFailure("provider candidate material has insufficient exact route evidence");
    text(item.upstream_model, "provider candidate upstream model");
    const drivers = new Set<string>();
    for (const candidateRaw of item.candidates) {
      totalCandidates += 1;
      if (totalCandidates > 4_096) throw new ManagedCodexProvenanceFailure("provider candidate material exceeds the supported size");
      const candidate = object(candidateRaw, ["source_stable_id", "source_provider", "driver"], "provider source candidate");
      const sourceStableId = text(candidate.source_stable_id, "provider source candidate", SHA256), sourceProvider = text(candidate.source_provider, "provider source candidate"), driver = text(candidate.driver, "provider source candidate");
      if (sourceProvider !== source.provider) throw new ManagedCodexProvenanceFailure("provider candidate material crosses source providers");
      drivers.add(driver);
      if (driver !== "openai-codex") continue;
      if (sourceProvider !== "codex" || source.provider !== "codex" || source.protocol !== "openai") throw new ManagedCodexProvenanceFailure("managed Codex candidate evidence is invalid");
      const existing = selected.get(sourceStableId), current = { sourceStableId, sourceProvider, driver };
      if (existing && (existing.sourceProvider !== current.sourceProvider || existing.driver !== current.driver)) throw new ManagedCodexProvenanceFailure("managed Codex candidate identity is conflicting");
      selected.set(sourceStableId, current);
    }
    if (drivers.size !== 1) throw new ManagedCodexProvenanceFailure("provider candidate set mixes drivers");
  }
  if (selected.size === 0 || selected.size > MAX_BINDINGS) throw new ManagedCodexProvenanceFailure("managed Codex candidate evidence is absent or too large");
  return [...selected.values()].sort((left, right) => compare(left.sourceStableId, right.sourceStableId));
}

/**
 * Bind sealed metadata to the exact combined source/material artifacts before
 * opening a database connection. Every managed candidate must be represented
 * by exactly one auth-file path from the sealed snapshot; unselected snapshot
 * paths (for example disabled auth files) cannot create a binding.
 */
export function prepareManagedCodexProvenance(
  sourceTenantMappingRaw: Buffer,
  sourceConfigRaw: Buffer,
  managedCodexModelSnapshotRaw: Buffer,
  sourceInventoryRaw: Buffer,
  candidateMaterialRaw: Buffer,
  sourceIdentityKey: Buffer,
  keyPepper: Buffer,
): PreparedManagedCodexProvenance {
  const evidence = parseManagedCodexSourceEvidence(sourceTenantMappingRaw);
  let sourceInventory: ReturnType<typeof parseSourceInventory>;
  try { sourceInventory = parseSourceInventory(sourceInventoryRaw); }
  catch { throw new ManagedCodexProvenanceFailure("source inventory has insufficient exact route evidence"); }
  if (sourceInventory.version !== 2) throw new ManagedCodexProvenanceFailure("managed Codex provenance requires a version 2 source inventory");
  const validCoordinates = new Set(sourceInventory.mappings.map((mapping) => JSON.stringify([mapping.provider, mapping.model, mapping.group, mapping.upstreamPrefix, mapping.protocol])));
  const sourceDigest = digest(sourceInventoryRaw), materialDigest = digest(candidateMaterialRaw), candidates = managedCandidates(candidateMaterialRaw, sourceDigest, validCoordinates);
  if (sourceIdentityKey.length !== 32) throw new ManagedCodexProvenanceFailure("managed Codex source identity key is invalid");
  let snapshot: ReturnType<typeof parseManagedCodexModelSnapshot>;
  try { snapshot = parseManagedCodexModelSnapshot(managedCodexModelSnapshotRaw); assertManagedCodexModelSnapshotConfig(snapshot, sourceConfigRaw); }
  catch { throw new ManagedCodexProvenanceFailure("managed Codex model snapshot has insufficient current source evidence"); }
  const pathsByStableId = new Map<string, string>();
  for (const auth of snapshot.auth_models) {
    const relativePath = relativeAuthPath(auth.auth_id), stableId = managedCodexRouteSourceStableId(sourceIdentityKey, relativePath);
    if (pathsByStableId.has(stableId)) throw new ManagedCodexProvenanceFailure("managed Codex model snapshot has conflicting source identities");
    pathsByStableId.set(stableId, relativePath);
  }
  const requests = candidates.map((candidate) => {
    const relativePath = pathsByStableId.get(candidate.sourceStableId);
    if (!relativePath) throw new ManagedCodexProvenanceFailure("managed Codex model snapshot does not exactly identify a candidate");
    return { sourceStableId: candidate.sourceStableId, sourceKey: managedCodexImportSourceKey(keyPepper, evidence.sourceImportTenant, relativePath) };
  }).sort((left, right) => compare(left.sourceStableId, right.sourceStableId));
  if (new Set(requests.map((item) => item.sourceStableId)).size !== requests.length || new Set(requests.map((item) => item.sourceKey)).size !== requests.length) throw new ManagedCodexProvenanceFailure("managed Codex source evidence has conflicting identities");
  return { evidence, sourceDigest, materialDigest, requests };
}

function observation(value: unknown): ManagedCodexProvenanceObservation {
  const item = object(value, ["source_stable_id", "source_key", "payload_digest", "contract_version", "upstream_account_id", "driver", "auth_kind", "status", "credential_generation", "oauth_session_id", "oauth_driver", "oauth_refresh_url", "updated_at"], "managed Codex provenance query result");
  return {
    sourceStableId: text(item.source_stable_id, "managed Codex provenance query result", SHA256),
    sourceKey: text(item.source_key, "managed Codex provenance query result", SHA256),
    payloadDigest: text(item.payload_digest, "managed Codex provenance query result", SHA256),
    contractVersion: positiveInteger(item.contract_version, "managed Codex provenance query result", 1),
    accountId: text(item.upstream_account_id, "managed Codex provenance query result", UUID),
    driver: text(item.driver, "managed Codex provenance query result"),
    authKind: text(item.auth_kind, "managed Codex provenance query result"),
    status: text(item.status, "managed Codex provenance query result"),
    credentialGeneration: positiveInteger(item.credential_generation, "managed Codex provenance query result", 1_000_000_000_000_000),
    oauthSessionId: text(item.oauth_session_id, "managed Codex provenance query result", UUID),
    oauthDriver: text(item.oauth_driver, "managed Codex provenance query result"),
    oauthRefreshUrl: text(item.oauth_refresh_url, "managed Codex provenance query result", undefined, 500),
    updatedAt: safeInteger(item.updated_at, "managed Codex provenance query result"),
  };
}

/**
 * Construct the composer-compatible managed receipt from a bounded query
 * result. The observed payload digest is retained only inside the hashed
 * provenance proof. It is explicitly non-blocking: normal OAuth refreshes
 * change that observation without changing the immutable route identity or
 * requesting a re-import.
 */
export function buildManagedCodexBindingReceipt(prepared: PreparedManagedCodexProvenance, rawObservations: unknown): ManagedCodexBindingReceipt {
  if (!Array.isArray(rawObservations) || rawObservations.length !== prepared.requests.length || rawObservations.length === 0 || rawObservations.length > MAX_BINDINGS) throw new ManagedCodexProvenanceFailure("managed Codex provenance query did not return an exact binding set");
  const observations = rawObservations.map(observation).sort((left, right) => compare(left.sourceStableId, right.sourceStableId));
  const requests = new Map(prepared.requests.map((request) => [request.sourceStableId, request]));
  const accounts = new Set<string>();
  for (const item of observations) {
    const request = requests.get(item.sourceStableId);
    if (!request || request.sourceKey !== item.sourceKey || item.contractVersion !== 1 || item.driver !== "openai-codex" || item.authKind !== "oauth" || item.status !== "active" || item.oauthSessionId !== item.accountId || item.oauthDriver !== "openai_codex_device" || item.oauthRefreshUrl !== "https://auth.openai.com/oauth/token" || item.credentialGeneration < 1 || accounts.has(item.accountId)) throw new ManagedCodexProvenanceFailure("managed Codex target provenance is absent, unsuitable, or ambiguous");
    accounts.add(item.accountId);
  }
  if (new Set(observations.map((item) => item.sourceStableId)).size !== observations.length) throw new ManagedCodexProvenanceFailure("managed Codex target provenance is ambiguous");
  const provenance = Buffer.from(`${JSON.stringify({
    version: 1,
    source_inventory_sha256: prepared.sourceDigest,
    provider_candidate_material_sha256: prepared.materialDigest,
    source_import_tenant_external_id: prepared.evidence.sourceImportTenant,
    target_tenant_external_id: prepared.evidence.targetTenant,
    source_kind: "auth_file",
    source_type: "codex",
    bindings: observations.map((item) => ({ source_stable_id: item.sourceStableId, source_key_matches: true, payload_revision_state: "observed_nonblocking", payload_digest: item.payloadDigest, contract_version: item.contractVersion, upstream_account_id: item.accountId, driver: item.driver, auth_kind: item.authKind, status: item.status, credential_generation: item.credentialGeneration, oauth_session_id: item.oauthSessionId, oauth_driver: item.oauthDriver, oauth_refresh_url: item.oauthRefreshUrl, updated_at: item.updatedAt })),
  })}\n`);
  const provenanceDigest = digest(provenance); provenance.fill(0);
  const receipt = Buffer.from(`${JSON.stringify({
    version: 1,
    tenant_external_id: prepared.evidence.targetTenant,
    source_inventory_sha256: prepared.sourceDigest,
    provider_candidate_material_sha256: prepared.materialDigest,
    managed_provenance_evidence_sha256: provenanceDigest,
    bindings: observations.map((item) => ({ source_stable_id: item.sourceStableId, source_provider: "codex", upstream_account_id: item.accountId, driver: "openai-codex", status: "active", updated_at: item.updatedAt })),
    quarantined: [],
  })}\n`);
  return { receipt, bindingCount: observations.length, provenanceDigest, sourceDigest: prepared.sourceDigest, materialDigest: prepared.materialDigest };
}

const querySql = String.raw`
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = :'statement_timeout_ms';
WITH requested AS MATERIALIZED (
  SELECT source_stable_id, source_key
    FROM jsonb_to_recordset(convert_from(decode(:'requested_bindings_b64', 'base64'), 'UTF8')::jsonb)
      AS requested(source_stable_id text, source_key text)
), source_tenant AS MATERIALIZED (
  SELECT id FROM tenants
   WHERE external_id = convert_from(decode(:'source_import_tenant_external_id_b64', 'base64'), 'UTF8')
), target_tenant AS MATERIALIZED (
  SELECT id FROM tenants
   WHERE external_id = convert_from(decode(:'target_tenant_external_id_b64', 'base64'), 'UTF8')
)
SELECT COALESCE(json_agg(json_build_object(
  'source_stable_id', requested.source_stable_id,
  'source_key', imports.source_key,
  'payload_digest', imports.payload_digest,
  'contract_version', imports.contract_version,
  'upstream_account_id', accounts.id,
  'driver', accounts.driver,
  'auth_kind', accounts.auth_kind,
  'status', accounts.status,
  'credential_generation', accounts.credential_generation,
  'oauth_session_id', accounts.oauth_session_id,
  'oauth_driver', accounts.oauth_driver,
  'oauth_refresh_url', accounts.oauth_refresh_url,
  'updated_at', accounts.updated_at
) ORDER BY requested.source_stable_id), '[]'::json)::text
  FROM requested
  JOIN upstream_account_imports imports
    ON imports.tenant_id = (SELECT id FROM source_tenant)
   AND imports.import_kind = 'cpa_managed_oauth'
   AND imports.source_key = requested.source_key
  JOIN upstream_accounts accounts
    ON accounts.id = imports.upstream_account_id
   AND accounts.tenant_id = (SELECT id FROM target_tenant)
  JOIN upstream_credentials credentials
    ON credentials.upstream_account_id = accounts.id
   AND credentials.generation = accounts.credential_generation
   AND credentials.revoked_at IS NULL
 WHERE accounts.driver = 'openai-codex'
   AND accounts.auth_kind = 'oauth'
   AND accounts.status = 'active'
   AND accounts.credential_generation >= 1
   AND accounts.oauth_session_id = accounts.id
   AND accounts.oauth_driver = 'openai_codex_device'
   AND accounts.oauth_refresh_url = 'https://auth.openai.com/oauth/token'
 LIMIT 257;
COMMIT;
`;

function assertOwnerOnlyFile(path: string, label: string): void {
  if (!isAbsolute(path) || path !== resolve(path) || path.includes("\0")) throw new ManagedCodexProvenanceFailure(`${label} path is invalid`);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o600 || (process.geteuid?.() !== undefined && metadata.uid !== process.geteuid())) throw new Error("unsafe");
  } catch (error) {
    if (error instanceof ManagedCodexProvenanceFailure) throw error;
    throw new ManagedCodexProvenanceFailure(`${label} is not an owner-only regular file`);
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}
function readOwnerOnly(path: string, label: string, maximum = MAX_BYTES): Buffer {
  assertOwnerOnlyFile(path, label); let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const buffer = Buffer.allocUnsafe(maximum + 1); let offset = 0;
    while (offset < buffer.length) { const count = readSync(descriptor, buffer, offset, buffer.length - offset, null); if (count === 0) break; offset += count; }
    if (offset > maximum) { buffer.fill(0); throw new ManagedCodexProvenanceFailure(`${label} exceeds the supported size`); }
    return Buffer.from(buffer.subarray(0, offset));
  } catch (error) {
    if (error instanceof ManagedCodexProvenanceFailure) throw error;
    throw new ManagedCodexProvenanceFailure(`${label} is not safely readable`);
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}
function outputTarget(path: string): OutputTarget {
  if (!isAbsolute(path) || path !== resolve(path) || path === parse(path).root || path.includes("\0")) throw new ManagedCodexProvenanceFailure("managed Codex receipt output path is invalid");
  const directory = resolve(dirname(path)), root = parse(directory).root; let current = root;
  for (const part of relative(root, directory).split(sep).filter(Boolean)) {
    current = resolve(current, part); let metadata: ReturnType<typeof lstatSync>;
    try { metadata = lstatSync(current); } catch { throw new ManagedCodexProvenanceFailure("managed Codex receipt output directory is unsafe"); }
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new ManagedCodexProvenanceFailure("managed Codex receipt output directory is unsafe");
  }
  let descriptor: number | undefined;
  try {
    descriptor = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.nlink < 1 || (metadata.mode & 0o022) !== 0 || (process.geteuid?.() !== undefined && metadata.uid !== process.geteuid())) throw new Error("unsafe");
    const target = `/proc/self/fd/${descriptor}/${basename(path)}`;
    try { lstatSync(target); throw new ManagedCodexProvenanceFailure("managed Codex receipt output already exists"); }
    catch (error) {
      if (error instanceof ManagedCodexProvenanceFailure) throw error;
      if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) throw new ManagedCodexProvenanceFailure("managed Codex receipt output directory is unsafe");
    }
    return { target, parentDescriptor: descriptor };
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    if (error instanceof ManagedCodexProvenanceFailure) throw error;
    throw new ManagedCodexProvenanceFailure("managed Codex receipt output directory is unsafe");
  }
}
function publish(target: OutputTarget, value: Buffer): void {
  const temporary = `${target.target}.tmp-${randomBytes(16).toString("hex")}`; let descriptor: number | undefined;
  try {
    descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    for (let offset = 0; offset < value.length;) { const written = writeSync(descriptor, value, offset, value.length - offset); if (written <= 0) throw new Error("short write"); offset += written; }
    fsyncSync(descriptor); closeSync(descriptor); descriptor = undefined; linkSync(temporary, target.target); unlinkSync(temporary);
    const metadata = lstatSync(target.target); if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o600) throw new Error("unsafe output");
    fsyncSync(target.parentDescriptor);
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    try { lstatSync(temporary); unlinkSync(temporary); } catch {}
    if (error instanceof ManagedCodexProvenanceFailure) throw error;
    throw new ManagedCodexProvenanceFailure("managed Codex receipt could not be persisted");
  }
}
function queryExistingBindings(prepared: PreparedManagedCodexProvenance, serviceFile: string, service: string, statementTimeoutMs: number, psqlBinary: string): unknown {
  assertOwnerOnlyFile(serviceFile, "PostgreSQL service file");
  if (!SERVICE_NAME.test(service)) throw new ManagedCodexProvenanceFailure("PostgreSQL service name is invalid");
  if (!Number.isSafeInteger(statementTimeoutMs) || statementTimeoutMs < 1 || statementTimeoutMs > MAX_STATEMENT_TIMEOUT_MS) throw new ManagedCodexProvenanceFailure("PostgreSQL statement timeout is invalid");
  if (psqlBinary !== "psql" && (!isAbsolute(psqlBinary) || psqlBinary !== resolve(psqlBinary) || psqlBinary.includes("\0"))) throw new ManagedCodexProvenanceFailure("psql binary path is invalid");
  const requested = Buffer.from(JSON.stringify(prepared.requests.map((item) => ({ source_stable_id: item.sourceStableId, source_key: item.sourceKey })))).toString("base64");
  const sourceTenant = Buffer.from(prepared.evidence.sourceImportTenant, "utf8").toString("base64"), targetTenant = Buffer.from(prepared.evidence.targetTenant, "utf8").toString("base64");
  const psqlInput = `\\set requested_bindings_b64 ${requested}\n\\set source_import_tenant_external_id_b64 ${sourceTenant}\n\\set target_tenant_external_id_b64 ${targetTenant}\n${querySql}`;
  const environment: NodeJS.ProcessEnv = { PATH: process.env.PATH ?? "/usr/bin:/bin", LANG: "C", PGSERVICEFILE: serviceFile, PGSERVICE: service, PGAPPNAME: "mtc-managed-codex-provenance", PGCONNECT_TIMEOUT: "10" };
  const result = spawnSync(psqlBinary, ["-X", "--no-psqlrc", "--no-password", "-qAt", "--set=ON_ERROR_STOP=1", `--set=statement_timeout_ms=${statementTimeoutMs}`], { encoding: "utf8", env: environment, input: psqlInput, shell: false, stdio: ["pipe", "pipe", "pipe"], timeout: 30_000, maxBuffer: MAX_BYTES });
  if (result.error || result.status !== 0) throw new ManagedCodexProvenanceFailure("managed Codex provenance query failed");
  const output = Buffer.from(String(result.stdout), "utf8");
  if (output.length === 0 || output.length > MAX_BYTES || output.includes(0x0a, output.length - 2)) throw new ManagedCodexProvenanceFailure("managed Codex provenance query returned invalid output");
  return strictJson(Buffer.from(output.toString("utf8").trim(), "utf8"), "managed Codex provenance query result");
}
function options(argv: readonly string[]): Options {
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write("usage: resolve-cpa-managed-codex-provenance --source-import-tenant-mapping-file FILE --source-config-file FILE --managed-codex-model-snapshot-file FILE --source-identity-key-file FILE --key-pepper-file FILE --source-inventory-file FILE --provider-candidate-material-file FILE --pg-service-file FILE --pg-service NAME --binding-receipt-output FILE [--psql-binary PATH] [--statement-timeout-ms N]\n");
    process.exit(0);
  }
  const fields: Record<string, keyof MutableOptions> = { "--source-import-tenant-mapping-file": "sourceTenantMappingFile", "--source-config-file": "sourceConfigFile", "--managed-codex-model-snapshot-file": "managedCodexModelSnapshotFile", "--source-identity-key-file": "sourceIdentityKeyFile", "--key-pepper-file": "keyPepperFile", "--source-inventory-file": "sourceInventoryFile", "--provider-candidate-material-file": "candidateMaterialFile", "--pg-service-file": "pgServiceFile", "--pg-service": "pgService", "--binding-receipt-output": "output", "--psql-binary": "psqlBinary", "--statement-timeout-ms": "statementTimeoutMs" };
  const parsed: MutableOptions = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!, field = fields[argument], value = argv[index + 1];
    if (!field || !value || value.startsWith("--") || parsed[field] !== undefined) throw new ManagedCodexProvenanceFailure("arguments are invalid");
    (parsed as unknown as Record<string, unknown>)[field] = field === "statementTimeoutMs" ? Number(value) : value; index += 1;
  }
  parsed.psqlBinary ??= "psql"; parsed.statementTimeoutMs ??= 15_000;
  if (!parsed.sourceTenantMappingFile || !parsed.sourceConfigFile || !parsed.managedCodexModelSnapshotFile || !parsed.sourceIdentityKeyFile || !parsed.keyPepperFile || !parsed.sourceInventoryFile || !parsed.candidateMaterialFile || !parsed.pgServiceFile || !parsed.pgService || !parsed.output || !parsed.psqlBinary || parsed.statementTimeoutMs === undefined) throw new ManagedCodexProvenanceFailure("required arguments are missing");
  return parsed as Options;
}

export function run(argv = process.argv.slice(2)): Readonly<Record<string, number | string>> {
  const selected = options(argv);
  let tenantMappingRaw: Buffer | undefined, sourceConfigRaw: Buffer | undefined, modelSnapshotRaw: Buffer | undefined, sourceRaw: Buffer | undefined, materialRaw: Buffer | undefined, pepper: Buffer | undefined, identityKey: Buffer | undefined, output: OutputTarget | undefined;
  try {
    tenantMappingRaw = readOwnerOnly(selected.sourceTenantMappingFile, "managed Codex source tenant mapping");
    sourceConfigRaw = readOwnerOnly(selected.sourceConfigFile, "CPA source config", 4 * 1024 * 1024);
    modelSnapshotRaw = readOwnerOnly(selected.managedCodexModelSnapshotFile, "managed Codex model snapshot");
    sourceRaw = readOwnerOnly(selected.sourceInventoryFile, "source inventory");
    materialRaw = readOwnerOnly(selected.candidateMaterialFile, "provider candidate material");
    pepper = readOwnerOnly(selected.keyPepperFile, "key pepper", 16 * 1024);
    assertOwnerOnlyFile(selected.sourceIdentityKeyFile, "source identity key"); identityKey = readSourceIdentityKey(selected.sourceIdentityKeyFile);
    const prepared = prepareManagedCodexProvenance(tenantMappingRaw, sourceConfigRaw, modelSnapshotRaw, sourceRaw, materialRaw, identityKey, pepper);
    const observations = queryExistingBindings(prepared, selected.pgServiceFile, selected.pgService, selected.statementTimeoutMs, selected.psqlBinary);
    const receipt = buildManagedCodexBindingReceipt(prepared, observations);
    output = outputTarget(selected.output); publish(output, receipt.receipt);
    return { mode: "resolve-cpa-managed-codex-provenance", binding_count: receipt.bindingCount, source_inventory_sha256: receipt.sourceDigest, provider_candidate_material_sha256: receipt.materialDigest, managed_provenance_evidence_sha256: receipt.provenanceDigest, binding_receipt_sha256: digest(receipt.receipt) };
  } finally {
    tenantMappingRaw?.fill(0); sourceConfigRaw?.fill(0); modelSnapshotRaw?.fill(0); sourceRaw?.fill(0); materialRaw?.fill(0); pepper?.fill(0); identityKey?.fill(0);
    if (output) closeSync(output.parentDescriptor);
  }
}

if (basename(process.argv[1] ?? "").replace(/\.(?:ts|[cm]?js)$/, "") === "resolve-cpa-managed-codex-provenance") {
  try { process.stdout.write(`${JSON.stringify(run())}\n`); }
  catch (error) { process.stderr.write(`managed Codex provenance stopped: ${error instanceof ManagedCodexProvenanceFailure ? error.message : "unexpected operator failure"}\n`); process.exitCode = 2; }
}
