#!/usr/bin/env node
/** Attach unchanged CPA client credentials to imported CPAMP identities. */

import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { basename } from "node:path";
import { parseStrictJson } from "../lib/strict-json.ts";

const MAX_INPUT_BYTES = 4 * 1024 * 1024;
const MAX_HTTP_RESPONSE_BYTES = 1024 * 1024;
const MAX_IDENTITIES = 100_000;
const IDENTITIES_END = "__MTC_LEGACY_IDENTITIES_END__";
const IDENTITY_HEARTBEAT = "__MTC_LEGACY_IDENTITY_HEARTBEAT__";
const TENANT_ID = /^[A-Za-z0-9._:-]{1,200}$/;
const HEX_SHA256 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const LOCK_SQL = "pg_try_advisory_lock(hashtextextended('memeloop-token-center:legacy-cpa-credentials', 734627102948314))";

export class ImportFailure extends Error {}
export type Identity = Readonly<{ sourceHash: string; keyId: string }>;
export type Plan = Readonly<{ candidates: ReadonlyArray<readonly [string, Identity]>; identityCount: number; existingCount: number; alreadyAttached: number }>;

const UTF8 = new TextDecoder("utf-8", { fatal: true });
function decodeUtf8(value: Uint8Array, label: string): string {
  try { return UTF8.decode(value); }
  catch { throw new ImportFailure(`${label} is not valid UTF-8`); }
}

function readSecretFile(path: string, label: string, limit = MAX_INPUT_BYTES): Buffer {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    const groups = new Set([process.getegid?.(), ...(process.getgroups?.() ?? [])]);
    const unauthorized = (metadata.mode & 0o037) !== 0 || ((metadata.mode & 0o040) !== 0 && !groups.has(metadata.gid));
    if (!metadata.isFile()) throw new ImportFailure(`${label} must be a regular file`);
    if (unauthorized) throw new ImportFailure(`${label} has unsafe access permissions`);
    const buffer = Buffer.allocUnsafe(limit + 1); let offset = 0;
    while (offset < buffer.length) { const count = readSync(descriptor, buffer, offset, buffer.length - offset, null); if (count === 0) break; offset += count; }
    if (offset > limit) { buffer.fill(0); throw new ImportFailure(`${label} exceeds the allowed size`); }
    return Buffer.from(buffer.subarray(0, offset));
  } catch (error) {
    if (error instanceof ImportFailure) throw error;
    throw new ImportFailure(`${label} is not readable`);
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}
function credential(value: unknown): string {
  if (typeof value !== "string" || value.trim() !== value || /[\0\r\n]/.test(value) || Buffer.byteLength(value) < 16 || Buffer.byteLength(value) > 512) throw new ImportFailure("credential input contains an invalid item");
  return value;
}
export function parseCandidates(raw: Buffer, format: string): string[] {
  let values: unknown;
  if (format === "cpa-json") {
    let document: unknown; try { document = parseStrictJson(decodeUtf8(raw, "credential input")); } catch { throw new ImportFailure("CPA JSON is invalid"); }
    if (document === null || Array.isArray(document) || typeof document !== "object" || Object.keys(document).length !== 1 || !("api-keys" in document)) throw new ImportFailure("CPA JSON must contain only the api-keys field");
    values = (document as Record<string, unknown>)["api-keys"]; if (!Array.isArray(values)) throw new ImportFailure("CPA JSON api-keys must be an array");
  } else if (format === "lines") {
    values = decodeUtf8(raw, "credential input").split(/\r?\n/); if ((values as string[]).at(-1) === "") (values as string[]).pop();
    if ((values as string[]).length === 0 || (values as string[]).some((item) => item === "")) throw new ImportFailure("line input must contain non-empty credentials");
  } else throw new ImportFailure("unsupported credential input format");
  const output = (values as unknown[]).map(credential); if (output.length === 0) throw new ImportFailure("credential input is empty"); return output;
}
function normalizedUrl(value: string, label: string, allowHttp: boolean): string {
  let url: URL; try { url = new URL(value); } catch { throw new ImportFailure(`${label} is invalid`); }
  if (!(["https:", ...(allowHttp ? ["http:"] : [])].includes(url.protocol)) || !url.hostname || url.username || url.password || url.search || url.hash) throw new ImportFailure(`${label} is invalid`);
  url.pathname = url.pathname.replace(/\/+$/, ""); return url.toString().replace(/\/$/, "");
}
function token(path: string, label: string): string {
  const value = decodeUtf8(readSecretFile(path, label, 16 * 1024), label); const result = value.trim();
  if (!result || (value !== result && value.replace(/[\r\n]+$/, "") !== result) || /[\0\r\n]/.test(result)) throw new ImportFailure(`${label} is invalid`); return result;
}
async function requestBytes(method: string, rawUrl: string, authorization: string, label: string, expected: number, limit: number, body?: Buffer, caFile?: string): Promise<Buffer> {
  const url = new URL(rawUrl);
  return await new Promise<Buffer>((fulfill, reject) => {
    const request = (url.protocol === "https:" ? httpsRequest : httpRequest)({ protocol: url.protocol, hostname: url.hostname, port: url.port, path: `${url.pathname}${url.search}`, method, timeout: 30_000, ca: caFile ? caBytes(caFile) : undefined, headers: { Authorization: `Bearer ${authorization}`, Accept: "application/json", ...(body ? { "Content-Type": "application/json", "Content-Length": body.length } : {}) } }, (response) => {
      if (response.statusCode !== expected) { response.destroy(); reject(new ImportFailure(`${label} returned an unexpected status`)); return; }
      let size = 0; const chunks: Buffer[] = []; response.on("data", (chunk: Buffer) => { size += chunk.length; if (size > limit) request.destroy(new ImportFailure(`${label} exceeds the allowed size`)); else chunks.push(chunk); }); response.on("end", () => fulfill(Buffer.concat(chunks)));
    });
    request.on("timeout", () => request.destroy()); request.on("error", (error) => reject(error instanceof ImportFailure ? error : new ImportFailure(`${label} request failed`))); request.end(body);
  });
}

const caCache = new Map<string, Buffer>();
function caBytes(path: string): Buffer {
  const cached = caCache.get(path); if (cached) return cached;
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    if (!fstatSync(descriptor).isFile()) throw new Error("not regular");
    const limit = 4 * 1024 * 1024, buffer = Buffer.allocUnsafe(limit + 1); let offset = 0;
    while (offset < buffer.length) { const count = readSync(descriptor, buffer, offset, buffer.length - offset, null); if (count === 0) break; offset += count; }
    if (offset > limit) throw new ImportFailure("CA file exceeds the allowed size");
    const value = Buffer.from(buffer.subarray(0, offset)); caCache.set(path, value); return value;
  } catch (error) {
    if (error instanceof ImportFailure) throw error;
    throw new ImportFailure("CA file is invalid or unreadable");
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}

class PsqlSession {
  readonly process: ChildProcessWithoutNullStreams;
  readonly queue: string[] = [];
  stdoutBuffer = Buffer.alloc(0);
  waiter?: { resolve: (line: string) => void; reject: (error: ImportFailure) => void; timer: NodeJS.Timeout };
  closed = false;
  exitCode: number | null = null;
  constructor(tenant: string, binary: string) {
    if (!TENANT_ID.test(tenant)) throw new ImportFailure("tenant external id contains unsupported characters");
    try { this.process = spawn(binary, ["-X", "--no-psqlrc", "-qAt", "--no-password", "--set=ON_ERROR_STOP=1", `--set=tenant_external_id=${tenant}`], { env: { ...process.env, PGCONNECT_TIMEOUT: process.env.PGCONNECT_TIMEOUT ?? "10", PGAPPNAME: process.env.PGAPPNAME ?? "mtc-legacy-credential-import" }, stdio: "pipe" }); }
    catch { throw new ImportFailure("psql could not be started"); }
    this.process.stderr.resume();
    this.process.stdin.on("error", () => { /* classified by the child close/error handlers */ });
    this.process.stdout.on("data", (chunk: Buffer) => {
      this.stdoutBuffer = Buffer.concat([this.stdoutBuffer, chunk]);
      if (this.stdoutBuffer.length > 4 * 1024 * 1024 && !this.stdoutBuffer.includes(0x0a)) { this.failPending(new ImportFailure("PostgreSQL identity output is invalid")); this.close(); return; }
      while (true) {
        const newline = this.stdoutBuffer.indexOf(0x0a); if (newline < 0) break;
        let raw = this.stdoutBuffer.subarray(0, newline); this.stdoutBuffer = this.stdoutBuffer.subarray(newline + 1);
        if (raw.length > 4 * 1024 * 1024) { this.failPending(new ImportFailure("PostgreSQL identity output is invalid")); this.close(); return; }
        if (raw.at(-1) === 0x0d) raw = raw.subarray(0, -1);
        let line: string; try { line = decodeUtf8(raw, "PostgreSQL identity output"); } catch { this.failPending(new ImportFailure("PostgreSQL identity output is invalid")); this.close(); return; }
        const waiter = this.waiter;
        if (waiter) { this.waiter = undefined; clearTimeout(waiter.timer); waiter.resolve(line); } else this.queue.push(line);
      }
    });
    this.process.on("error", () => { this.closed = true; this.failPending(new ImportFailure("psql could not be started")); });
    this.process.on("close", (code, signal) => {
      this.closed = true;
      this.exitCode = code;
      const status = signal ? `psql was terminated by signal ${signal} during the identity query` : code === 2 ? "PostgreSQL identity connection was lost (psql status 2)" : code === 3 ? "PostgreSQL rejected the identity query (psql status 3)" : code === 1 ? "psql failed before completing the PostgreSQL identity query (status 1)" : code === 0 ? "psql closed PostgreSQL identity output before completion" : `psql exited unexpectedly during the identity query (status ${String(code)})`;
      this.failPending(new ImportFailure(status));
    });
    this.write(`SELECT CASE WHEN ${LOCK_SQL} THEN '1' ELSE '0' END;\nSELECT json_build_array(kind, source_hash, key_id)::text FROM (SELECT 'identity' AS kind, lower(i.api_key_hash) AS source_hash, i.key_id AS key_id FROM cpamp_import_identities i JOIN key_records k ON k.id = i.key_id AND k.status = 'active' JOIN tenants t ON t.id = k.tenant_id WHERE t.external_id = :'tenant_external_id' UNION ALL SELECT CASE WHEN c.revoked_at IS NULL THEN 'existing' ELSE 'revoked' END AS kind, lower(c.source_hash), c.key_id FROM legacy_key_credentials c WHERE EXISTS (SELECT 1 FROM cpamp_import_identities i JOIN key_records k ON k.id = i.key_id JOIN tenants t ON t.id = k.tenant_id WHERE t.external_id = :'tenant_external_id' AND (lower(c.source_hash) = lower(i.api_key_hash) OR c.key_id = i.key_id))) mappings ORDER BY kind, source_hash, key_id;\n\\echo ${IDENTITIES_END}\n`);
  }
  failPending(error: ImportFailure): void { const waiter = this.waiter; if (!waiter) return; this.waiter = undefined; clearTimeout(waiter.timer); waiter.reject(error); }
  write(value: string): void { if (this.closed || this.process.stdin.destroyed) throw new ImportFailure("PostgreSQL identity session ended unexpectedly"); this.process.stdin.write(value); }
  async line(timeoutMs: number): Promise<string> {
    if (this.queue.length > 0) return this.queue.shift()!;
    if (this.closed) throw new ImportFailure("PostgreSQL identity session ended unexpectedly");
    return await new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => { this.waiter = undefined; reject(new ImportFailure("PostgreSQL identity query timed out")); }, timeoutMs);
      this.waiter = { resolve, reject, timer };
    });
  }
  async mappings(): Promise<[Identity[], Identity[], Identity[]]> {
    if (await this.line(30_000) !== "1") throw new ImportFailure("another legacy credential import holds the advisory lock"); const rows: [Identity[], Identity[], Identity[]] = [[], [], []];
    while (true) { const line = await this.line(30_000); if (line === IDENTITIES_END) break; let row: unknown; try { row = parseStrictJson(line); } catch { throw new ImportFailure("PostgreSQL identity output is invalid"); } if (!Array.isArray(row) || row.length !== 3 || !row.every((item) => typeof item === "string") || !["identity", "existing", "revoked"].includes(row[0] as string)) throw new ImportFailure("PostgreSQL identity output is invalid"); rows[["identity", "existing", "revoked"].indexOf(row[0] as string)]!.push(checkedIdentity(row[1] as string, row[2] as string)); if (rows.reduce((sum, items) => sum + items.length, 0) > MAX_IDENTITIES) throw new ImportFailure("PostgreSQL identity result exceeds the allowed size"); }
    await this.heartbeat(); return rows;
  }
  async heartbeat(): Promise<void> {
    this.write(`SELECT '${IDENTITY_HEARTBEAT}';\n`);
    let response: string;
    try { response = await this.line(5_000); }
    catch (error) {
      if (error instanceof ImportFailure && error.message === "PostgreSQL identity query timed out") throw new ImportFailure("PostgreSQL identity heartbeat timed out");
      throw error;
    }
    if (response !== IDENTITY_HEARTBEAT) throw new ImportFailure("PostgreSQL identity heartbeat output is invalid");
  }
  close(): void { if (this.closed) return; this.closed = true; this.process.kill("SIGTERM"); }
}
function checkedIdentity(sourceHash: string, keyId: string): Identity { const hash = sourceHash.toLowerCase(), id = keyId.toLowerCase(); if (!HEX_SHA256.test(hash)) throw new ImportFailure("PostgreSQL contains an invalid source hash"); if (!UUID.test(id) || id !== keyId.toLowerCase()) throw new ImportFailure("PostgreSQL contains an invalid target key id"); return { sourceHash: hash, keyId: id }; }
export function buildPlan(credentials: string[], identities: Identity[], existing: Identity[], revoked: Identity[] = []): Plan {
  const byHash = new Map<string, Identity>(), byKey = new Map<string, string>(); for (const identity of identities) { if (byHash.has(identity.sourceHash)) throw new ImportFailure("CPAMP identities contain a duplicate source hash"); const old = byKey.get(identity.keyId); if (old && old !== identity.sourceHash) throw new ImportFailure("CPAMP identities contain a duplicate target key"); byHash.set(identity.sourceHash, identity); byKey.set(identity.keyId, identity.sourceHash); } if (byHash.size === 0) throw new ImportFailure("CPAMP identity set is empty");
  const candidates = new Map<string, string>(); for (const item of credentials) { const hash = createHash("sha256").update(item).digest("hex"); if (candidates.has(hash)) throw new ImportFailure("credential input contains a duplicate credential"); candidates.set(hash, item); }
  if (candidates.size !== byHash.size || [...candidates.keys()].some((hash) => !byHash.has(hash))) throw new ImportFailure("credential and CPAMP identity sets do not match exactly"); if (revoked.length > 0) throw new ImportFailure("a selected source or target has a revoked legacy mapping");
  const existingHash = new Map<string, string>(), existingKey = new Map<string, string>(); for (const item of existing) { const oldKey = existingHash.get(item.sourceHash), oldHash = existingKey.get(item.keyId); if ((oldKey && oldKey !== item.keyId) || (oldHash && oldHash !== item.sourceHash)) throw new ImportFailure("existing legacy mappings contain a source conflict"); existingHash.set(item.sourceHash, item.keyId); existingKey.set(item.keyId, item.sourceHash); }
  let alreadyAttached = 0; const pairs: Array<readonly [string, Identity]> = []; for (const hash of [...candidates.keys()].sort()) { const identity = byHash.get(hash)!; if ((existingHash.has(hash) && existingHash.get(hash) !== identity.keyId) || (existingKey.has(identity.keyId) && existingKey.get(identity.keyId) !== hash)) throw new ImportFailure("an existing legacy source maps to another target"); if (existingHash.get(hash) === identity.keyId) alreadyAttached += 1; pairs.push([candidates.get(hash)!, identity]); }
  return { candidates: pairs, identityCount: identities.length, existingCount: existing.length, alreadyAttached };
}
async function attach(rawUrl: string, serviceToken: string, pair: readonly [string, Identity], caFile?: string): Promise<void> { const body = Buffer.from(JSON.stringify({ credential: pair[0], source_hash: pair[1].sourceHash })); let response: unknown; try { response = parseStrictJson(decodeUtf8(await requestBytes("POST", `${rawUrl}/internal/v1/keys/${pair[1].keyId}/legacy-credentials`, serviceToken, "Token Center legacy credential API", 201, MAX_HTTP_RESPONSE_BYTES, body, caFile), "Token Center legacy credential response")); } catch (error) { if (error instanceof ImportFailure) throw error; throw new ImportFailure("Token Center legacy credential response is invalid"); } if (response === null || typeof response !== "object" || Array.isArray(response)) throw new ImportFailure("Token Center legacy credential response did not verify"); const item = response as Record<string, unknown>; if (item.key_id !== pair[1].keyId || item.source_hash !== pair[1].sourceHash || !Number.isInteger(item.generation) || typeof item.fingerprint !== "string" || !item.fingerprint) throw new ImportFailure("Token Center legacy credential response did not verify"); }
type Options = Record<string, string | boolean | undefined> & { tenant?: string; inputFormat: string; apply: boolean; allowHttpCpa: boolean; allowHttpTarget: boolean; psql: string };
function args(argv: string[]): Options { if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write("usage: attach-legacy-cpa-credentials --tenant-external-id ID (--input-file FILE | --cpa-management-url URL) [options]\n\nMatch unchanged CPA credentials to CPAMP identities (dry-run by default).\n"); process.exit(0); } const output: Options = { inputFormat: "cpa-json", apply: false, allowHttpCpa: false, allowHttpTarget: false, psql: "psql" }; const valued: Record<string, string> = { "--tenant-external-id": "tenant", "--input-file": "inputFile", "--cpa-management-url": "cpaUrl", "--input-format": "inputFormat", "--cpa-management-token-file": "cpaToken", "--cpa-ca-file": "cpaCa", "--target-api-base-url": "targetUrl", "--service-token-file": "serviceToken", "--target-ca-file": "targetCa", "--psql-binary": "psql" }; for (let index = 0; index < argv.length; index += 1) { const arg = argv[index]!; if (arg === "--apply") output.apply = true; else if (arg === "--allow-http-cpa") output.allowHttpCpa = true; else if (arg === "--allow-http-target") output.allowHttpTarget = true; else if (valued[arg]) { const value = argv[++index]; if (!value) throw new ImportFailure(`${arg} requires a value`); output[valued[arg]!] = value; } else throw new ImportFailure(`unrecognized argument: ${arg}`); } if (!output.tenant || (!output.inputFile && !output.cpaUrl) || (output.inputFile && output.cpaUrl)) throw new ImportFailure("tenant and exactly one credential source are required"); return output; }
async function stdin(): Promise<Buffer> { const chunks: Buffer[] = []; let size = 0; for await (const chunk of process.stdin) { const value = Buffer.from(chunk); size += value.length; if (size > MAX_INPUT_BYTES) throw new ImportFailure("credential input exceeds the allowed size"); chunks.push(value); } return Buffer.concat(chunks); }
async function main(): Promise<void> { const options = args(process.argv.slice(2)); let raw: Buffer; if (options.cpaUrl) { if (!options.cpaToken || options.inputFormat !== "cpa-json") throw new ImportFailure("CPA management token file is required"); const url = normalizedUrl(String(options.cpaUrl), "CPA management URL", Boolean(options.allowHttpCpa)); raw = await requestBytes("GET", `${url}/v0/management/api-keys`, token(String(options.cpaToken), "CPA management token file"), "CPA management export", 200, MAX_INPUT_BYTES, undefined, options.cpaCa ? String(options.cpaCa) : undefined); } else { if (options.cpaToken || options.cpaCa) throw new ImportFailure("CPA management options require CPA management URL"); raw = options.inputFile === "-" ? await stdin() : readSecretFile(String(options.inputFile), "credential input"); }
  const credentials = parseCandidates(raw, options.inputFormat); let target = "", serviceToken = ""; if (options.apply) { if (!options.targetUrl || !options.serviceToken) throw new ImportFailure("target API URL and service token file are required for apply"); target = normalizedUrl(String(options.targetUrl), "Token Center API URL", Boolean(options.allowHttpTarget)); serviceToken = token(String(options.serviceToken), "service token file"); } else if (options.targetUrl || options.serviceToken || options.targetCa) throw new ImportFailure("target API options are accepted only with --apply");
  const database = new PsqlSession(String(options.tenant), options.psql); try { const mappings = await database.mappings(); const plan = buildPlan(credentials, ...mappings); let attached = 0; if (options.apply) for (const pair of plan.candidates) { await database.heartbeat(); await attach(target, serviceToken, pair, options.targetCa ? String(options.targetCa) : undefined); await database.heartbeat(); attached += 1; } process.stdout.write(`${JSON.stringify({ mode: options.apply ? "apply" : "dry-run", candidate_count: plan.candidates.length, identity_count: plan.identityCount, existing_mapping_count: plan.existingCount, already_attached_count: plan.alreadyAttached, pending_count: plan.candidates.length - plan.alreadyAttached, attached_verified_count: attached })}\n`); } finally { database.close(); }
}
if (basename(process.argv[1] ?? "").replace(/\.(?:ts|[cm]?js)$/, "") === "attach-legacy-cpa-credentials") {
  main().catch((error) => { process.stderr.write(`legacy credential import failed: ${error instanceof ImportFailure ? error.message : "unexpected operator failure"}\n`); process.exitCode = 2; });
}
