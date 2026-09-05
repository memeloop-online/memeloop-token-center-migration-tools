#!/usr/bin/env node
/** Strict, fail-closed CPA native key-policy to MTC exact-route grant importer. */

import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { dirname } from "node:path";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { parseStrictJson } from "../lib/strict-json.ts";

const SHA256 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TENANT = /^[A-Za-z0-9._:-]{1,200}$/;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_HTTP_BYTES = 8 * 1024 * 1024;
const END = "__MTC_POLICY_IDENTITIES_END__";
const PING = "__MTC_POLICY_IDENTITIES_PING__";
const LOCK_SQL = "pg_try_advisory_lock(hashtextextended('memeloop-token-center:legacy-cpa-key-policy', 734627102948314))";

type JsonObject = Record<string, unknown>;
export type SourceGrant = Readonly<{ provider?: string; model?: string; group?: string; upstream_prefix?: string }>;
export type NativePolicy = Readonly<{ keyHash: string; enabled: boolean; grants: readonly SourceGrant[] }>;
export type Identity = Readonly<{ sourceHash: string; keyId: string }>;
export type CandidateSource = Readonly<{ upstreamAccountId: string; sourceStableId: string }>;
export type InventoryRoute = Readonly<{
  routeId: string;
  publicModel: string;
  upstreamModel: string;
  protocol: "openai" | "anthropic" | "generation";
  enabled: true;
  updatedAt: number;
  upstreamAccountIds: readonly string[];
  candidateUpstreamAccountIds: readonly string[];
  candidateSources: readonly CandidateSource[];
}>;
export type RouteMapping = Readonly<{
  source: SourceGrant;
  routeId: string;
  expectedPublicModel: string;
  expectedUpstreamModel: string;
  expectedProtocol: "openai" | "anthropic" | "generation";
  expectedUpdatedAt: number;
  expectedUpstreamAccountIds: readonly string[];
  expectedCandidateUpstreamAccountIds: readonly string[];
  expectedCandidateSources: readonly CandidateSource[];
}>;
export type ImportPlanItem = Readonly<{ keyId: string; routeIds: readonly string[] }>;
export type ImportPlan = Readonly<{
  items: readonly ImportPlanItem[];
  routeById: ReadonlyMap<string, InventoryRoute>;
  policyCount: number;
  enabledPolicyCount: number;
  disabledPolicyCount: number;
  grantCount: number;
  matchedGrantCount: number;
  unmatchedGrantCount: number;
  sourceDigest: string;
  mappingDigest: string;
  inventoryDigest: string;
  planDigest: string;
}>;
type Summary = Readonly<Record<string, number>>;

export class ImportFailure extends Error {
  readonly counts?: Summary;
  constructor(message: string, counts?: Summary) { super(message); this.counts = counts; }
}

const utf8 = new TextDecoder("utf-8", { fatal: true });
function decode(value: Uint8Array, label: string): string {
  try { return utf8.decode(value); }
  catch { throw new ImportFailure(`${label} is not valid UTF-8`); }
}
function sha(value: Uint8Array | string): string { return createHash("sha256").update(value).digest("hex"); }
function object(value: unknown, keys: readonly string[], label: string): JsonObject {
  if (value === null || Array.isArray(value) || typeof value !== "object") throw new ImportFailure(`${label} has an invalid schema`);
  const record = value as JsonObject;
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new ImportFailure(`${label} has an invalid schema`);
  return record;
}
function partialObject(value: unknown, allowed: readonly string[], label: string): JsonObject {
  if (value === null || Array.isArray(value) || typeof value !== "object") throw new ImportFailure(`${label} has an invalid schema`);
  const record = value as JsonObject, keys = Object.keys(record);
  if (keys.length === 0 || keys.some((key) => !allowed.includes(key))) throw new ImportFailure(`${label} has an invalid schema`);
  return record;
}
function string(value: unknown, label: string, allowEmpty = false): string {
  if (typeof value !== "string" || value.trim() !== value || /[\0\r\n]/.test(value) || (!allowEmpty && value.length === 0) || Buffer.byteLength(value) > 512) throw new ImportFailure(`${label} has an invalid schema`);
  return value;
}
function integer(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) throw new ImportFailure(`${label} has an invalid schema`);
  return Number(value);
}
function uuid(value: unknown, label: string): string {
  const result = string(value, label).toLowerCase();
  if (!UUID.test(result) || result !== value) throw new ImportFailure(`${label} has an invalid schema`);
  return result;
}
function hex(value: unknown, label: string): string {
  const result = string(value, label).toLowerCase();
  if (!SHA256.test(result) || result !== value) throw new ImportFailure(`${label} has an invalid schema`);
  return result;
}
function uniqueSorted(values: unknown, label: string, parser: (value: unknown, label: string) => string): string[] {
  if (!Array.isArray(values) || values.length > 1000) throw new ImportFailure(`${label} has an invalid schema`);
  const result = values.map((value) => parser(value, label)).sort();
  if (new Set(result).size !== result.length) throw new ImportFailure(`${label} contains duplicates`);
  return result;
}
function candidateSources(values: unknown, label: string): CandidateSource[] {
  if (!Array.isArray(values) || values.length > 1000) throw new ImportFailure(`${label} has an invalid schema`);
  const result = values.map((value) => { const record = object(value, ["upstream_account_id", "source_stable_id"], label); return { upstreamAccountId: uuid(record["upstream_account_id"], label), sourceStableId: string(record["source_stable_id"], label) }; }).sort((left, right) => left.upstreamAccountId.localeCompare(right.upstreamAccountId));
  if (new Set(result.map((item) => item.upstreamAccountId)).size !== result.length || new Set(result.map((item) => item.sourceStableId)).size !== result.length) throw new ImportFailure(`${label} contains duplicate source bindings`);
  return result;
}
function protocol(value: unknown, label: string): "openai" | "anthropic" | "generation" {
  if (value !== "openai" && value !== "anthropic" && value !== "generation") throw new ImportFailure(`${label} has an invalid schema`);
  return value;
}
function grant(value: unknown, label: string): SourceGrant {
  const fields = ["provider", "model", "group", "upstream_prefix"] as const;
  const record = partialObject(value, fields, label), output: { provider?: string; model?: string; group?: string; upstream_prefix?: string } = {};
  for (const field of fields) if (Object.hasOwn(record, field)) output[field] = string(record[field], label, true);
  return output;
}
function grantKey(value: SourceGrant): string { return JSON.stringify(["provider", "model", "group", "upstream_prefix"].map((field) => Object.hasOwn(value, field) ? [1, value[field as keyof SourceGrant]] : [0])); }
function parseJson(raw: Buffer, label: string): unknown {
  try { return parseStrictJson(decode(raw, label)); }
  catch (error) { if (error instanceof ImportFailure) throw error; throw new ImportFailure(`${label} is not strict JSON`); }
}

export function readProtectedFile(path: string, label: string, limit = MAX_FILE_BYTES): Buffer {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o600) throw new ImportFailure(`${label} must be a mode 0600 regular file with one link`);
    const output = Buffer.allocUnsafe(limit + 1); let offset = 0;
    while (offset < output.length) { const count = readSync(descriptor, output, offset, output.length - offset, null); if (count === 0) break; offset += count; }
    if (offset > limit) { output.fill(0); throw new ImportFailure(`${label} exceeds the allowed size`); }
    return Buffer.from(output.subarray(0, offset));
  } catch (error) {
    if (error instanceof ImportFailure) throw error;
    throw new ImportFailure(`${label} is not safely readable`);
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}

export function parseNativePolicy(raw: Buffer): NativePolicy[] {
  const root = object(parseJson(raw, "source policy"), ["version", "policies", "usage"], "source policy");
  if (root["version"] !== 1) throw new ImportFailure("source policy version is unsupported");
  if (root["usage"] === null || Array.isArray(root["usage"]) || typeof root["usage"] !== "object") throw new ImportFailure("source policy has an invalid schema");
  if (!Array.isArray(root["policies"]) || root["policies"].length === 0 || root["policies"].length > 100_000) throw new ImportFailure("source policy has an invalid schema");
  const seen = new Set<string>();
  return root["policies"].map((value, index) => {
    const record = object(value, ["key_hash", "enabled", "grants"], `source policy item ${index}`);
    const keyHash = hex(record["key_hash"], "source policy hash");
    if (seen.has(keyHash)) throw new ImportFailure("source policy contains a duplicate hash"); seen.add(keyHash);
    if (typeof record["enabled"] !== "boolean" || !Array.isArray(record["grants"]) || record["grants"].length > 500) throw new ImportFailure("source policy has an invalid schema");
    const grants = record["grants"].map((item) => grant(item, "source grant"));
    if (new Set(grants.map(grantKey)).size !== grants.length) throw new ImportFailure("source policy contains a duplicate grant");
    return { keyHash, enabled: record["enabled"], grants };
  });
}

export function parseRouteInventory(raw: Buffer): InventoryRoute[] {
  const root = object(parseJson(raw, "route inventory"), ["version", "routes"], "route inventory");
  if (root["version"] !== 1 || !Array.isArray(root["routes"]) || root["routes"].length > 1000) throw new ImportFailure("route inventory has an invalid schema");
  const seen = new Set<string>();
  return root["routes"].map((value) => {
    const record = object(value, ["route_id", "public_model", "upstream_model", "protocol", "enabled", "updated_at", "upstream_account_ids", "candidate_upstream_account_ids", "candidate_sources"], "route inventory item");
    const routeId = uuid(record["route_id"], "route inventory item");
    if (seen.has(routeId)) throw new ImportFailure("route inventory contains a duplicate route"); seen.add(routeId);
    if (record["enabled"] !== true) throw new ImportFailure("route inventory contains a disabled selected route");
    const candidates = uniqueSorted(record["candidate_upstream_account_ids"], "route inventory item", uuid), sources = candidateSources(record["candidate_sources"], "route inventory item");
    if (!same(candidates, sources.map((item) => item.upstreamAccountId))) throw new ImportFailure("route inventory has an incomplete candidate source binding");
    return {
      routeId,
      publicModel: string(record["public_model"], "route inventory item"),
      upstreamModel: string(record["upstream_model"], "route inventory item"),
      protocol: protocol(record["protocol"], "route inventory item"),
      enabled: true,
      updatedAt: integer(record["updated_at"], "route inventory item"),
      upstreamAccountIds: uniqueSorted(record["upstream_account_ids"], "route inventory item", uuid),
      candidateUpstreamAccountIds: candidates,
      candidateSources: sources,
    };
  });
}

export function parseMapping(raw: Buffer, sourceDigest: string, inventoryDigest: string): { mappings: RouteMapping[]; tenant: string } {
  const root = object(parseJson(raw, "reviewed mapping"), ["version", "tenant_external_id", "source_snapshot_sha256", "route_inventory_sha256", "mappings"], "reviewed mapping");
  if (root["version"] !== 1 || hex(root["source_snapshot_sha256"], "reviewed mapping") !== sourceDigest || hex(root["route_inventory_sha256"], "reviewed mapping") !== inventoryDigest) throw new ImportFailure("reviewed mapping does not match the selected snapshots");
  const tenant = string(root["tenant_external_id"], "reviewed mapping"); if (!TENANT.test(tenant)) throw new ImportFailure("reviewed mapping has an invalid tenant");
  if (!Array.isArray(root["mappings"]) || root["mappings"].length > 10_000) throw new ImportFailure("reviewed mapping has an invalid schema");
  const seen = new Set<string>();
  const mappings = root["mappings"].map((value) => {
    const record = object(value, ["source", "target"], "reviewed mapping item");
    const source = grant(record["source"], "reviewed source pattern");
    const key = grantKey(source); if (seen.has(key)) throw new ImportFailure("reviewed mapping contains an ambiguous source pattern"); seen.add(key);
    const target = object(record["target"], ["route_id", "expected_public_model", "expected_upstream_model", "expected_protocol", "expected_updated_at", "expected_upstream_account_ids", "expected_candidate_upstream_account_ids", "expected_candidate_sources"], "reviewed mapping target");
    const candidates = uniqueSorted(target["expected_candidate_upstream_account_ids"], "reviewed mapping target", uuid), sources = candidateSources(target["expected_candidate_sources"], "reviewed mapping target");
    if (!same(candidates, sources.map((item) => item.upstreamAccountId))) throw new ImportFailure("reviewed mapping has an incomplete candidate source binding");
    return {
      source,
      routeId: uuid(target["route_id"], "reviewed mapping target"),
      expectedPublicModel: string(target["expected_public_model"], "reviewed mapping target"),
      expectedUpstreamModel: string(target["expected_upstream_model"], "reviewed mapping target"),
      expectedProtocol: protocol(target["expected_protocol"], "reviewed mapping target"),
      expectedUpdatedAt: integer(target["expected_updated_at"], "reviewed mapping target"),
      expectedUpstreamAccountIds: uniqueSorted(target["expected_upstream_account_ids"], "reviewed mapping target", uuid),
      expectedCandidateUpstreamAccountIds: candidates,
      expectedCandidateSources: sources,
    };
  });
  return { mappings, tenant };
}

function same(left: readonly string[], right: readonly string[]): boolean { return left.length === right.length && left.every((value, index) => value === right[index]); }
function sameSources(left: readonly CandidateSource[], right: readonly CandidateSource[]): boolean { return left.length === right.length && left.every((value, index) => value.upstreamAccountId === right[index]?.upstreamAccountId && value.sourceStableId === right[index]?.sourceStableId); }
function validateRoute(mapping: RouteMapping, route: InventoryRoute): void {
  if (route.publicModel !== mapping.expectedPublicModel || route.upstreamModel !== mapping.expectedUpstreamModel || route.protocol !== mapping.expectedProtocol || route.enabled !== true || route.updatedAt !== mapping.expectedUpdatedAt || !same(route.upstreamAccountIds, mapping.expectedUpstreamAccountIds) || !same(route.candidateUpstreamAccountIds, mapping.expectedCandidateUpstreamAccountIds) || !sameSources(route.candidateSources, mapping.expectedCandidateSources)) throw new ImportFailure("a reviewed route no longer matches its exact inventory coordinates");
}

export function buildPlan(rawPolicy: Buffer, rawMapping: Buffer, rawInventory: Buffer, identities: readonly Identity[]): { plan: ImportPlan; tenant: string } {
  const sourceDigest = sha(rawPolicy), mappingDigest = sha(rawMapping), inventoryDigest = sha(rawInventory);
  const policies = parseNativePolicy(rawPolicy), routes = parseRouteInventory(rawInventory), parsed = parseMapping(rawMapping, sourceDigest, inventoryDigest);
  const identityByHash = new Map<string, string>(), identityKeys = new Set<string>();
  for (const identity of identities) {
    const sourceHash = hex(identity.sourceHash, "target identity"), keyId = uuid(identity.keyId, "target identity");
    if (identityByHash.has(sourceHash) || identityKeys.has(keyId)) throw new ImportFailure("target identities are not one-to-one");
    identityByHash.set(sourceHash, keyId); identityKeys.add(keyId);
  }
  if (identities.length !== policies.length || policies.some((policy) => !identityByHash.has(policy.keyHash))) throw new ImportFailure("active source policies and target identities do not match exactly");
  const routeById = new Map(routes.map((route) => [route.routeId, route]));
  const mappingByGrant = new Map(parsed.mappings.map((mapping) => [grantKey(mapping.source), mapping]));
  for (const mapping of parsed.mappings) { const route = routeById.get(mapping.routeId); if (!route) throw new ImportFailure("a reviewed route is absent from the inventory"); validateRoute(mapping, route); }
  let grantCount = 0, matchedGrantCount = 0, unmatchedGrantCount = 0;
  const items = [...policies].sort((a, b) => a.keyHash.localeCompare(b.keyHash)).map((policy) => {
    const routeIds = new Set<string>();
    if (policy.enabled) for (const sourceGrant of policy.grants) {
      grantCount += 1; const mapping = mappingByGrant.get(grantKey(sourceGrant));
      if (!mapping) { unmatchedGrantCount += 1; continue; }
      matchedGrantCount += 1; routeIds.add(mapping.routeId);
    }
    return { keyId: identityByHash.get(policy.keyHash)!, routeIds: [...routeIds].sort() };
  });
  if (unmatchedGrantCount > 0) throw new ImportFailure("source grants require additional reviewed route mappings", { policy_count: policies.length, grant_count: grantCount, matched_grant_count: matchedGrantCount, unmatched_grant_count: unmatchedGrantCount });
  const planDigest = sha(JSON.stringify(items));
  return { plan: { items, routeById, policyCount: policies.length, enabledPolicyCount: policies.filter((item) => item.enabled).length, disabledPolicyCount: policies.filter((item) => !item.enabled).length, grantCount, matchedGrantCount, unmatchedGrantCount, sourceDigest, mappingDigest, inventoryDigest, planDigest }, tenant: parsed.tenant };
}

class PsqlIdentitySession {
  readonly child: ChildProcessWithoutNullStreams;
  private buffer = ""; private readonly lines: string[] = []; private waiter?: { resolve: (value: string) => void; reject: (error: Error) => void; timer: NodeJS.Timeout };
  constructor(binary: string, tenant: string) {
    if (!TENANT.test(tenant)) throw new ImportFailure("tenant has an invalid format");
    try { this.child = spawn(binary, ["-X", "--no-psqlrc", "-qAt", "--no-password", "--set=ON_ERROR_STOP=1", `--set=tenant_external_id=${tenant}`], { env: { ...process.env, PGAPPNAME: "mtc-legacy-policy-import", PGCONNECT_TIMEOUT: process.env.PGCONNECT_TIMEOUT ?? "10" }, stdio: "pipe" }); }
    catch { throw new ImportFailure("identity database process could not start"); }
    this.child.stderr.resume(); this.child.stdin.on("error", () => undefined);
    this.child.stdout.setEncoding("utf8"); this.child.stdout.on("data", (chunk: string) => { this.buffer += chunk; if (this.buffer.length > MAX_FILE_BYTES) { this.fail(); return; } let newline: number; while ((newline = this.buffer.indexOf("\n")) >= 0) { const line = this.buffer.slice(0, newline).replace(/\r$/, ""); this.buffer = this.buffer.slice(newline + 1); const waiter = this.waiter; if (waiter) { this.waiter = undefined; clearTimeout(waiter.timer); waiter.resolve(line); } else this.lines.push(line); } });
    this.child.on("error", () => this.fail()); this.child.on("close", () => this.fail());
    this.child.stdin.write(`SELECT CASE WHEN ${LOCK_SQL} THEN '1' ELSE '0' END;\nSELECT json_build_array(lower(i.api_key_hash), i.key_id)::text FROM cpamp_import_identities i JOIN key_records k ON k.id = i.key_id AND k.status = 'active' JOIN tenants t ON t.id = k.tenant_id WHERE t.external_id = :'tenant_external_id' ORDER BY lower(i.api_key_hash), i.key_id;\n\\echo ${END}\n`);
  }
  private fail(): void { const waiter = this.waiter; if (!waiter) return; this.waiter = undefined; clearTimeout(waiter.timer); waiter.reject(new ImportFailure("identity database session ended unexpectedly")); }
  private async line(): Promise<string> { if (this.lines.length > 0) return this.lines.shift()!; return await new Promise((resolve, reject) => { const timer = setTimeout(() => { this.waiter = undefined; reject(new ImportFailure("identity database query timed out")); }, 30_000); this.waiter = { resolve, reject, timer }; }); }
  async identities(): Promise<Identity[]> {
    if (await this.line() !== "1") throw new ImportFailure("another policy import holds the migration lock");
    const output: Identity[] = [];
    while (true) { const line = await this.line(); if (line === END) break; let row: unknown; try { row = parseStrictJson(line); } catch { throw new ImportFailure("identity database returned an invalid result"); } if (!Array.isArray(row) || row.length !== 2) throw new ImportFailure("identity database returned an invalid result"); output.push({ sourceHash: hex(row[0], "target identity"), keyId: uuid(row[1], "target identity") }); if (output.length > 100_000) throw new ImportFailure("identity database returned too many rows"); }
    this.child.stdin.write(`SELECT '${PING}';\n`); if (await this.line() !== PING) throw new ImportFailure("identity database session lost its migration lock"); return output;
  }
  async ping(): Promise<void> { this.child.stdin.write(`SELECT '${PING}';\n`); if (await this.line() !== PING) throw new ImportFailure("identity database session lost its migration lock"); }
  close(): void { if (!this.child.killed) this.child.kill("SIGTERM"); }
}

function normalizedUrl(raw: string, allowHttp: boolean): string {
  let url: URL; try { url = new URL(raw); } catch { throw new ImportFailure("target API URL is invalid"); }
  if ((!allowHttp && url.protocol !== "https:") || (allowHttp && !["http:", "https:"].includes(url.protocol)) || !url.hostname || url.username || url.password || url.search || url.hash) throw new ImportFailure("target API URL is invalid");
  url.pathname = url.pathname.replace(/\/+$/, ""); return url.toString().replace(/\/$/, "");
}
function secret(path: string, label: string): string { const raw = decode(readProtectedFile(path, label, 64 * 1024), label); const value = raw.trim(); if (!value || /[\0\r\n]/.test(value) || raw !== value) throw new ImportFailure(`${label} is invalid`); return value; }
async function requestJson(method: string, rawUrl: string, bearer: string, expected: number, body?: JsonObject): Promise<unknown> {
  const url = new URL(rawUrl), bytes = body ? Buffer.from(JSON.stringify(body)) : undefined;
  return await new Promise((resolve, reject) => {
    const request = (url.protocol === "https:" ? httpsRequest : httpRequest)({ protocol: url.protocol, hostname: url.hostname, port: url.port, path: `${url.pathname}${url.search}`, method, timeout: 30_000, headers: { Authorization: `Bearer ${bearer}`, Accept: "application/json", ...(bytes ? { "Content-Type": "application/json", "Content-Length": bytes.length } : {}) } }, (response) => {
      if (response.statusCode !== expected) { response.resume(); reject(new ImportFailure("target control API rejected the migration operation")); return; }
      let size = 0; const chunks: Buffer[] = []; response.on("data", (chunk: Buffer) => { size += chunk.length; if (size > MAX_HTTP_BYTES) request.destroy(new ImportFailure("target control API response is too large")); else chunks.push(chunk); }); response.on("end", () => { try { resolve(parseStrictJson(decode(Buffer.concat(chunks), "target control API response"))); } catch { reject(new ImportFailure("target control API returned an invalid response")); } });
    }); request.on("timeout", () => request.destroy()); request.on("error", (error) => reject(error instanceof ImportFailure ? error : new ImportFailure("target control API request failed"))); request.end(bytes);
  });
}
function liveRoute(value: unknown): InventoryRoute {
  if (value === null || Array.isArray(value) || typeof value !== "object") throw new ImportFailure("target route inventory response is invalid"); const item = value as JsonObject;
  if (item["enabled"] !== true) throw new ImportFailure("a reviewed live route is disabled");
  return { routeId: uuid(item["id"], "target route"), publicModel: string(item["public_model"], "target route"), upstreamModel: string(item["upstream_model"], "target route"), protocol: protocol(item["protocol"], "target route"), enabled: true, updatedAt: integer(item["updated_at"], "target route"), upstreamAccountIds: uniqueSorted(item["upstream_account_ids"], "target route", uuid), candidateUpstreamAccountIds: uniqueSorted(item["candidate_upstream_account_ids"], "target route", uuid), candidateSources: [] };
}
function routing(value: unknown, expectedKeyId: string): { routeIds: string[]; routeGroupIds: string[]; revision: number } {
  if (value === null || Array.isArray(value) || typeof value !== "object") throw new ImportFailure("target credential routing response is invalid"); const item = value as JsonObject;
  if (uuid(item["key_id"], "target routing") !== expectedKeyId) throw new ImportFailure("target credential routing response is invalid");
  return { routeIds: uniqueSorted(item["route_ids"], "target routing", uuid), routeGroupIds: uniqueSorted(item["route_group_ids"], "target routing", uuid), revision: integer(item["grant_revision"], "target routing") };
}

export type Checkpoint = Readonly<{ version: 1; source_digest: string; mapping_digest: string; inventory_digest: string; plan_digest: string; completed_count: number }>;
export function loadCheckpoint(path: string | undefined, plan: ImportPlan): Checkpoint {
  const empty: Checkpoint = { version: 1, source_digest: plan.sourceDigest, mapping_digest: plan.mappingDigest, inventory_digest: plan.inventoryDigest, plan_digest: plan.planDigest, completed_count: 0 };
  if (!path) return empty;
  try { statSync(path); } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return empty; throw new ImportFailure("checkpoint is not safely accessible"); }
  const value = object(parseJson(readProtectedFile(path, "checkpoint"), "checkpoint"), ["version", "source_digest", "mapping_digest", "inventory_digest", "plan_digest", "completed_count"], "checkpoint");
  const current: Checkpoint = { version: 1, source_digest: hex(value["source_digest"], "checkpoint"), mapping_digest: hex(value["mapping_digest"], "checkpoint"), inventory_digest: hex(value["inventory_digest"], "checkpoint"), plan_digest: hex(value["plan_digest"], "checkpoint"), completed_count: integer(value["completed_count"], "checkpoint") };
  if (value["version"] !== 1 || current.source_digest !== empty.source_digest || current.mapping_digest !== empty.mapping_digest || current.inventory_digest !== empty.inventory_digest || current.plan_digest !== empty.plan_digest || current.completed_count > plan.items.length) throw new ImportFailure("checkpoint conflicts with the selected source, mapping, inventory, or plan");
  return current;
}
export function writeCheckpoint(path: string, value: Checkpoint): void {
  const temporary = `${path}.new`; try { unlinkSync(temporary); } catch { /* absent */ }
  writeFileSync(temporary, `${JSON.stringify(value)}\n`, { mode: 0o600, flag: "wx" }); chmodSync(temporary, 0o600); renameSync(temporary, path);
  const metadata = statSync(path); if (!metadata.isFile() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o600) throw new ImportFailure("checkpoint could not be stored safely");
}

export type TargetClient = Readonly<{ get: (path: string) => Promise<unknown>; put: (path: string, body: JsonObject) => Promise<unknown> }>;
export async function executePlan(plan: ImportPlan, tenant: string, client: TargetClient, apply: boolean, priorCompleted = 0, progress?: (completed: number) => void): Promise<{ changed: number; replayed: number }> {
  const listed = await client.get(`/internal/v1/model-routes?tenant_external_id=${encodeURIComponent(tenant)}&limit=100`);
  if (!Array.isArray(listed)) throw new ImportFailure("target route inventory response is invalid");
  const live = new Map<string, InventoryRoute>(); for (const value of listed) { const route = liveRoute(value); if (live.has(route.routeId)) throw new ImportFailure("target route inventory response is invalid"); live.set(route.routeId, route); }
  for (const route of plan.routeById.values()) {
    const current = live.get(route.routeId); if (!current) throw new ImportFailure("a reviewed route is absent from the live target");
    if (current.publicModel !== route.publicModel || current.upstreamModel !== route.upstreamModel || current.protocol !== route.protocol || current.enabled !== true || current.updatedAt !== route.updatedAt || !same(current.upstreamAccountIds, route.upstreamAccountIds) || !same(current.candidateUpstreamAccountIds, route.candidateUpstreamAccountIds)) throw new ImportFailure("live target routes changed after review");
  }
  let changed = 0, replayed = 0;
  for (let index = 0; index < plan.items.length; index += 1) {
    const item = plan.items[index]!;
    const path = `/internal/v1/keys/${item.keyId}/routing`;
    const current = routing(await client.get(`${path}?tenant_external_id=${encodeURIComponent(tenant)}`), item.keyId);
    const identical = same(current.routeIds, item.routeIds) && current.routeGroupIds.length === 0;
    if (index < priorCompleted && !identical) throw new ImportFailure("checkpointed routing state changed after a partial apply");
    if (identical) replayed += 1;
    else if (apply) {
      const updated = routing(await client.put(path, { tenant_external_id: tenant, route_ids: item.routeIds, route_group_ids: [], expected_grant_revision: current.revision }), item.keyId);
      if (!same(updated.routeIds, item.routeIds) || updated.routeGroupIds.length !== 0) throw new ImportFailure("target control API did not verify the routing replacement");
      changed += 1;
    } else changed += 1;
    if (apply && progress) progress(index + 1);
  }
  return { changed, replayed };
}

type Options = { tenant?: string; policy?: string; mapping?: string; inventory?: string; checkpoint?: string; target?: string; token?: string; psql: string; apply: boolean; allowHttp: boolean };
function args(argv: string[]): Options {
  if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write("usage: import-cpa-key-policy --tenant-external-id ID --policy-file FILE --mapping-file FILE --route-inventory-file FILE --target-api-base-url URL --service-token-file FILE [--checkpoint-file FILE] [--apply]\n\nStrict live-target exact-route migration; dry-run by default. Apply additionally requires a durable checkpoint.\n"); process.exit(0); }
  const output: Options = { psql: "psql", apply: false, allowHttp: false };
  const valued: Record<string, keyof Options> = { "--tenant-external-id": "tenant", "--policy-file": "policy", "--mapping-file": "mapping", "--route-inventory-file": "inventory", "--checkpoint-file": "checkpoint", "--target-api-base-url": "target", "--service-token-file": "token", "--psql-binary": "psql" };
  for (let index = 0; index < argv.length; index += 1) { const arg = argv[index]!; if (arg === "--apply") output.apply = true; else if (arg === "--allow-http-target") output.allowHttp = true; else if (valued[arg]) { const value = argv[++index]; if (!value) throw new ImportFailure("an option requires a value"); (output as Record<string, unknown>)[valued[arg]!] = value; } else throw new ImportFailure("an unsupported option was supplied"); }
  if (!output.tenant || !output.policy || !output.mapping || !output.inventory || !TENANT.test(output.tenant)) throw new ImportFailure("tenant, policy, mapping, and route inventory are required");
  if (!output.target || !output.token) throw new ImportFailure("target API and service token are required for live dry-run verification");
  if (output.apply && !output.checkpoint) throw new ImportFailure("apply requires a durable checkpoint input");
  return output;
}
function safeSummary(plan: ImportPlan, mode: string, changed: number, replayed: number): JsonObject { return { mode, source_snapshot_sha256: plan.sourceDigest, mapping_sha256: plan.mappingDigest, route_inventory_sha256: plan.inventoryDigest, plan_sha256: plan.planDigest, policy_count: plan.policyCount, enabled_policy_count: plan.enabledPolicyCount, disabled_policy_count: plan.disabledPolicyCount, grant_count: plan.grantCount, matched_grant_count: plan.matchedGrantCount, unmatched_grant_count: plan.unmatchedGrantCount, changed_count: changed, replayed_count: replayed }; }
async function main(): Promise<void> {
  const options = args(process.argv.slice(2));
  const rawPolicy = readProtectedFile(options.policy!, "source policy"), rawMapping = readProtectedFile(options.mapping!, "reviewed mapping"), rawInventory = readProtectedFile(options.inventory!, "route inventory");
  const session = new PsqlIdentitySession(options.psql, options.tenant!);
  try {
    const { plan, tenant } = buildPlan(rawPolicy, rawMapping, rawInventory, await session.identities());
    if (tenant !== options.tenant) throw new ImportFailure("reviewed tenant does not match the requested tenant");
    const base = normalizedUrl(options.target!, options.allowHttp), bearer = secret(options.token!, "service token"), prior = loadCheckpoint(options.checkpoint, plan);
    const client: TargetClient = { get: async (path) => await requestJson("GET", `${base}${path}`, bearer, 200), put: async (path, body) => await requestJson("PUT", `${base}${path}`, bearer, 200, body) };
    const result = await executePlan(plan, tenant, client, options.apply, prior.completed_count, options.apply && options.checkpoint ? (completed) => { writeCheckpoint(options.checkpoint!, { version: 1, source_digest: plan.sourceDigest, mapping_digest: plan.mappingDigest, inventory_digest: plan.inventoryDigest, plan_digest: plan.planDigest, completed_count: completed }); } : undefined);
    await session.ping();
    process.stdout.write(`${JSON.stringify(safeSummary(plan, options.apply ? "apply" : "dry-run", result.changed, result.replayed))}\n`);
  } finally { session.close(); }
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) main().catch((error) => { const failure = error instanceof ImportFailure ? error : new ImportFailure("policy import failed safely"); if (failure.counts) process.stdout.write(`${JSON.stringify(failure.counts)}\n`); process.stderr.write(`import-cpa-key-policy: ${failure.message}\n`); process.exitCode = 2; });
