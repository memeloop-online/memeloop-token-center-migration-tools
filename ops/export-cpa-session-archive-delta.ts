#!/usr/bin/env node
/**
 * Export a replay-safe cpa-session-archive delta from a bounded source API.
 *
 * This implementation deliberately uses only Node built-ins. Records are staged
 * in node:sqlite so a large archive does not have to be retained in memory. It
 * never logs credentials, tickets, session ids, snapshots, or archive payloads.
 */

import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { promises as dns } from "node:dns";
import {
  closeSync,
  constants as fsConstants,
  createReadStream,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { request as httpRequest, type IncomingMessage } from "node:http";
import { request as httpsRequest, type RequestOptions } from "node:https";
import { isIP } from "node:net";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { invokedAsEntrypoint } from "./lib/invoked-as-entrypoint.ts";
import { parseArgs } from "node:util";
import { parseStrictJson } from "./lib/strict-json.ts";
import { gunzipSync } from "node:zlib";

export const SOURCE_FINGERPRINT_VERSION = 1;
export const COLLECTOR_FINGERPRINT_VERSION = 2;
export const CHECKPOINT_VERSION = 2;
export const MANIFEST_VERSION = 3;
export const STABLE_CURSOR_PROTOCOL = "session-snapshot-cursor-v1";
export const LEGACY_PROJECTION_PROTOCOL = "legacy-last-at-limit-v1";
const MAX_SESSION_COUNT = 1_000_000;
const MAX_MANAGEMENT_RESPONSE_BYTES = 8 * 1024 * 1024;
const TICKET_PATH_PREFIX = "/archive-api/v1/exports/";
const TOKEN_ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const LEGACY_SPOOL_BASENAME = /^\.mtc-archive-delta-spool\.[1-9][0-9]*\.[0-9]+\.sqlite$/;
const CPA_PATHS = {
  mode: "cpa-plugin-input",
  sessions: "/v0/management/plugins/cpa-session-archive/sessions",
  export: "/v0/management/plugins/cpa-session-archive/export",
  stats: "/v0/management/plugins/cpa-session-archive/stats",
} as const;
const COLLECTOR_PATHS = {
  mode: "collector-direct",
  sessions: "/v1/sessions",
  export: "/v1/export-tickets",
  stats: "/v1/stats",
} as const;
const COLLECTOR_READY_PATH = "/readyz";

/**
 * One canonical payload copy is sufficient for de-duplication, per-session
 * digest verification, and both output orders. `emit` retains the legacy
 * overlap filter without staging selected records in a second table.
 */
export const ARCHIVE_SPOOL_SCHEMA = `
  PRAGMA journal_mode=WAL;
  PRAGMA synchronous=NORMAL;
  CREATE TABLE IF NOT EXISTS records(
    request_id TEXT PRIMARY KEY COLLATE BINARY,
    session_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    digest TEXT NOT NULL,
    canonical BLOB NOT NULL,
    emit INTEGER NOT NULL CHECK(emit IN (0, 1))
  ) WITHOUT ROWID;
  CREATE INDEX IF NOT EXISTS records_by_session ON records(session_id COLLATE BINARY, request_id COLLATE BINARY);
  CREATE INDEX IF NOT EXISTS records_by_output ON records(started_at, request_id COLLATE BINARY) WHERE emit = 1;
  CREATE TABLE IF NOT EXISTS completed_sessions(
    session_id TEXT PRIMARY KEY COLLATE BINARY,
    requests INTEGER NOT NULL,
    records_sha256 TEXT NOT NULL,
    downloaded_bytes INTEGER NOT NULL CHECK(downloaded_bytes >= 0)
  ) WITHOUT ROWID;
  CREATE TABLE IF NOT EXISTS session_progress(
    session_id TEXT PRIMARY KEY COLLATE BINARY,
    requests INTEGER NOT NULL CHECK(requests >= 0),
    records_sha256 TEXT NOT NULL,
    record_cursor TEXT NOT NULL COLLATE BINARY,
    staged_records INTEGER NOT NULL CHECK(staged_records >= 0),
    staged_bytes INTEGER NOT NULL CHECK(staged_bytes >= 0),
    downloaded_bytes INTEGER NOT NULL CHECK(downloaded_bytes >= 0),
    chunks INTEGER NOT NULL CHECK(chunks >= 1)
  ) WITHOUT ROWID;
  CREATE TABLE IF NOT EXISTS spool_metadata(
    id INTEGER PRIMARY KEY CHECK(id=1),
    descriptor_json TEXT NOT NULL
  );
`;

function archiveSpoolSidecars(path: string): string[] { return [`${path}-wal`, `${path}-shm`]; }
function archiveSpoolExists(path: string): boolean { return [path, ...archiveSpoolSidecars(path)].some(existsSync); }

function ensurePrivateSpoolFile(path: string, label: string): void {
  ensurePrivateRegular(path, label);
  if (lstatSync(path).nlink !== 1) throw new DeltaError(`${label} must have one private filesystem link`);
}

function openArchiveSpool(path: string, resume: boolean): { database: DatabaseSync; resumed: boolean } {
  if (existsSync(path)) {
    if (!resume) throw new DeltaError("an incomplete archive spool exists; use --resume after reviewing the prior failure");
    ensurePrivateSpoolFile(path, "incomplete archive spool");
    for (const sidecar of archiveSpoolSidecars(path)) if (existsSync(sidecar)) ensurePrivateSpoolFile(sidecar, "incomplete archive spool sidecar");
    const database = new DatabaseSync(path);
    let integrity: Record<string, unknown> | undefined;
    try { integrity = database.prepare("PRAGMA integrity_check").get() as Record<string, unknown> | undefined; }
    catch { database.close(); throw new DeltaError("incomplete archive spool failed its integrity check"); }
    if (integrity === undefined || Object.values(integrity)[0] !== "ok") { database.close(); throw new DeltaError("incomplete archive spool failed its integrity check"); }
    return { database, resumed: true };
  }
  if (archiveSpoolSidecars(path).some(existsSync)) throw new DeltaError("archive spool sidecar exists without its database");
  let descriptor = -1;
  let created = false;
  try {
    descriptor = openSync(path, fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    created = true;
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.nlink !== 1 || (metadata.mode & 0o077) !== 0) throw new DeltaError("archive spool could not be created safely");
  } catch (error) {
    if (created) { try { unlinkSync(path); } catch { /* preserve the safe creation failure */ } }
    if (error instanceof DeltaError) throw error;
    throw new DeltaError("archive spool could not be created safely");
  } finally { if (descriptor >= 0) closeSync(descriptor); }
  return { database: new DatabaseSync(path), resumed: false };
}

function removeArchiveSpool(path: string): void {
  const targets = [...archiveSpoolSidecars(path), path];
  for (const target of targets) if (existsSync(target)) ensurePrivateSpoolFile(target, "archive spool cleanup target");
  for (const target of targets) rmSync(target, { force: true });
  fsyncDirectory(dirname(path));
}

type JsonObject = Record<string, unknown>;
type SourcePaths = typeof CPA_PATHS | typeof COLLECTOR_PATHS;
type Time = { nanos: bigint };
type SessionSummary = JsonObject & {
  session_id: string;
  requests: number;
  first_at?: string;
  last_at: string;
  records_sha256?: string;
  deleted?: boolean;
  deleted_at?: string;
};
type Projection = {
  sessions: SessionSummary[];
  protocol: string;
  requestCount: number;
  snapshot?: string;
  ingestFence?: string;
  snapshotSchemaVersion?: number;
  tombstoneSafeAfterIngestFence?: string;
  deletedSessionCount: number;
};
type TlsFiles = { cert: Buffer; key: Buffer };
type SQLiteSourceRow = {
  request_id: string; session_id: string; key_id: string; principal_id: string; credential_hash: string;
  requested_model: string; model: string; outcome: string; status_code: number; started_at: string; completed_at: string;
  metadata_json: string; facets_json: string; original_ref: string; response_ref: string;
  original_request_gz: Uint8Array | null; response_gz: Uint8Array | null;
};

export class DeltaError extends Error {}
export class StableCursorUnsupported extends DeltaError {}
export class SourceHTTPError extends DeltaError {
  readonly status: number;
  constructor(status: number) {
    super(`source request returned HTTP ${status}`);
    this.status = status;
  }
}
export class SnapshotExpired extends SourceHTTPError {
  constructor() { super(410); }
}

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new DeltaError("non-finite JSON number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (isObject(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  throw new DeltaError("value is not JSON-compatible");
}

export function canonicalBytes(value: unknown): Buffer { return Buffer.from(canonicalize(value), "utf8"); }
export function sha256Bytes(value: Buffer | string): string { return createHash("sha256").update(value).digest("hex"); }
export function compareUtf8Bytewise(left: string, right: string): number { return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")); }
function isSha256(value: unknown): value is string { return typeof value === "string" && /^[0-9a-f]{64}$/.test(value); }

/** Parse RFC3339 into integer nanoseconds, rejecting absent timezones. */
export function parseTime(value: unknown, label: string): Time {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0) throw new DeltaError(`${label} is missing`);
  const match = value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/);
  if (match === null) throw new DeltaError(`${label} is not RFC3339`);
  const [, year, month, day, hour, minute, second, fraction = "", zone] = match;
  const base = Date.parse(`${year}-${month}-${day}T${hour}:${minute}:${second}${zone}`);
  if (!Number.isFinite(base)) throw new DeltaError(`${label} is not RFC3339`);
  const reconstructed = new Date(base);
  // Date.parse normalizes impossible calendar fields; round-trip through the
  // original offset by validating date components independently.
  const utcCalendar = Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second));
  const calendar = new Date(utcCalendar);
  if (calendar.getUTCFullYear() !== Number(year) || calendar.getUTCMonth() + 1 !== Number(month) || calendar.getUTCDate() !== Number(day)
      || calendar.getUTCHours() !== Number(hour) || calendar.getUTCMinutes() !== Number(minute) || calendar.getUTCSeconds() !== Number(second)
      || Number.isNaN(reconstructed.valueOf())) throw new DeltaError(`${label} is not RFC3339`);
  return { nanos: BigInt(base) * 1_000_000n + BigInt(fraction.padEnd(9, "0")) };
}

export function formatTime(value: Time): string {
  const millis = value.nanos / 1_000_000n;
  const micros = (((value.nanos % 1_000_000_000n) + 1_000_000_000n) % 1_000_000_000n) / 1000n;
  const secondMillis = millis - (millis % 1000n);
  return `${new Date(Number(secondMillis)).toISOString().slice(0, 19)}.${micros.toString().padStart(6, "0")}Z`;
}
function parseCanonicalTime(value: unknown, label: string): Time {
  const parsed = parseTime(value, label);
  if (value !== formatTime(parsed)) throw new DeltaError(`${label} is not canonical six-digit UTC`);
  return parsed;
}
function compareTime(left: Time, right: Time): number { return left.nanos < right.nanos ? -1 : left.nanos > right.nanos ? 1 : 0; }
function addSeconds(value: Time, seconds: number): Time { return { nanos: value.nanos + BigInt(seconds) * 1_000_000_000n }; }

function ensurePrivateRegular(path: string, label: string): void {
  let metadata;
  try { metadata = lstatSync(path); } catch { throw new DeltaError(`${label} does not exist`); }
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new DeltaError(`${label} must be a regular non-symlink file`);
  if ((metadata.mode & 0o077) !== 0) throw new DeltaError(`${label} must not be accessible by group or other`);
}

function validateToken(raw: string, label: string): string {
  if (raw.length === 0 || Buffer.byteLength(raw) > 16_384 || [...raw].some((character) => character.charCodeAt(0) < 0x21 || character.charCodeAt(0) > 0x7e)) {
    throw new DeltaError(`${label} is invalid`);
  }
  return raw;
}
function loadToken(path: string): string {
  ensurePrivateRegular(path, "management token file");
  let descriptor = -1;
  try {
    descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || (metadata.mode & 0o077) !== 0) throw new DeltaError("management token file must be a private regular file");
    const buffer = Buffer.alloc(16_385);
    const length = readSync(descriptor, buffer, 0, buffer.length, null);
    if (length > 16_384) throw new DeltaError("management token file is invalid");
    return validateToken(buffer.subarray(0, length).toString("utf8").trim(), "management token file");
  } catch (error) {
    if (error instanceof DeltaError) throw error;
    throw new DeltaError("management token file could not be opened safely");
  } finally { if (descriptor >= 0) closeSync(descriptor); }
}
function loadTokenEnv(name: string): string {
  if (!TOKEN_ENV_NAME.test(name)) throw new DeltaError("token environment variable name is invalid");
  const value = process.env[name];
  if (value === undefined) throw new DeltaError("token environment variable is missing");
  return validateToken(value, "token environment secret");
}

export function checkpointLockPath(checkpoint: string): string { return join(dirname(checkpoint), `.${basename(checkpoint)}.lock`); }
async function withCheckpointLock<T>(checkpoint: string, deadline: number, action: () => Promise<T>): Promise<T> {
  mkdirSync(dirname(checkpoint), { recursive: true, mode: 0o700 });
  const lockPath = checkpointLockPath(checkpoint);
  let holder: ReturnType<typeof spawn> | undefined;
  while (true) {
    let descriptor = -1;
    try {
      descriptor = openSync(lockPath, fsConstants.O_RDWR | fsConstants.O_CREAT | fsConstants.O_NOFOLLOW, 0o600);
      const metadata = fstatSync(descriptor);
      if (!metadata.isFile() || (metadata.mode & 0o077) !== 0) throw new DeltaError("checkpoint transaction lock must be a private regular file");
      const candidate = spawn("flock", [
        "--exclusive", "--nonblock", "--conflict-exit-code", "75", "/proc/self/fd/3",
        process.execPath, "--experimental-strip-types", fileURLToPath(import.meta.url), "--checkpoint-lock-holder",
      ], {
        stdio: ["pipe", "ignore", "ignore", descriptor, "pipe"],
        shell: false,
      });
      closeSync(descriptor); descriptor = -1;
      const acquired = await new Promise<boolean>((resolve) => {
        let settled = false;
        candidate.stdio[4]?.once("data", () => { if (!settled) { settled = true; resolve(true); } });
        candidate.once("error", () => { if (!settled) { settled = true; resolve(false); } });
        candidate.once("exit", () => { if (!settled) { settled = true; resolve(false); } });
      });
      if (acquired) { holder = candidate; break; }
    } catch (error) {
      if (error instanceof DeltaError) throw error;
      throw new DeltaError("checkpoint transaction lock could not be opened safely");
    } finally { if (descriptor >= 0) closeSync(descriptor); }
    if (performance.now() >= deadline) throw new DeltaError("checkpoint transaction lock exceeded the elapsed-time limit");
    await delay(Math.min(100, Math.max(1, deadline - performance.now())));
  }
  try { return await action(); }
  finally {
    if (holder !== undefined && holder.exitCode === null) {
      holder.stdin?.end("\n");
      await new Promise<void>((resolve) => holder?.once("exit", () => resolve()));
    }
  }
}

async function runCheckpointLockHolder(argv: string[]): Promise<boolean> {
  if (argv.length !== 1 || argv[0] !== "--checkpoint-lock-holder") return false;
  try {
    const metadata = fstatSync(3);
    if (!metadata.isFile() || (metadata.mode & 0o077) !== 0) process.exit(76);
    writeSync(4, Buffer.from("ready"));
  } catch {
    process.exit(76);
  }
  process.stdin.resume();
  await new Promise<void>((resolve) => process.stdin.once("end", resolve));
  return true;
}

function normalizeHost(value: string): string { return value.replace(/\.+$/, "").toLowerCase(); }
function isPrivateAddress(address: string): boolean {
  if (address === "169.254.169.254" || address === "100.100.100.200") return false;
  if (isIP(address) === 4) {
    const parts = address.split(".").map(Number);
    const first = parts[0] ?? -1, second = parts[1] ?? -1;
    return first === 10 || first === 127 || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168);
  }
  const lower = address.toLowerCase().split("%")[0]!;
  return lower === "::1" || lower.startsWith("fc") || lower.startsWith("fd");
}
async function verifyPrivateHost(host: string, allowed: ReadonlySet<string>): Promise<boolean> {
  const normalized = normalizeHost(host);
  if (!allowed.has(normalized)) return false;
  try {
    const addresses = await dns.lookup(normalized, { all: true, verbatim: true });
    return addresses.length > 0 && addresses.every((item) => isPrivateAddress(item.address));
  } catch { return false; }
}

type SafeOrigin = { origin: string; base: string; host: string; protocol: string };
function safeOrigin(raw: string, allowAllHttp: boolean, allowed: ReadonlySet<string>, label: string): SafeOrigin {
  if (raw.length === 0 || [...raw].some((character) => character.charCodeAt(0) < 0x21 || character.charCodeAt(0) > 0x7e)) throw new DeltaError(`${label} is invalid`);
  let parsed: URL;
  try { parsed = new URL(raw); } catch { throw new DeltaError(`${label} is invalid`); }
  if (!['https:', 'http:'].includes(parsed.protocol)) throw new DeltaError(`${label} must use HTTPS`);
  if (parsed.username || parsed.password || parsed.search || parsed.hash) throw new DeltaError(`${label} is invalid`);
  const host = normalizeHost(parsed.hostname);
  if (parsed.protocol === "http:" && !allowAllHttp && !allowed.has(host)) throw new DeltaError(`${label} HTTP host is not in the resolved private allowlist`);
  const origin = parsed.origin;
  const prefix = parsed.pathname.replace(/\/+$/, "");
  return { origin, base: origin + prefix, host, protocol: parsed.protocol };
}

export function unwrapJson(value: unknown): unknown {
  let current = value;
  for (let index = 0; index < 6; index += 1) {
    if (!isObject(current)) return current;
    if ("url" in current || "records" in current || "session_id" in current) return current;
    if ("StatusCode" in current) {
      if (current.StatusCode !== 200) throw new DeltaError("source plugin response returned a non-success status");
      if (typeof current.Body !== "string") throw new DeltaError("source plugin response body is invalid");
      const body = current.Body;
      try { current = parseStrictJson(body); }
      catch {
        try {
          if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(body)) throw new Error("invalid base64");
          current = parseStrictJson(Buffer.from(body, "base64").toString("utf8"));
        }
        catch { throw new DeltaError("source plugin response body is invalid"); }
      }
      continue;
    }
    let moved = false;
    for (const key of ["result", "Result", "data", "body"]) {
      if (!(key in current)) continue;
      let nested = current[key];
      if (typeof nested === "string") { try { nested = parseStrictJson(nested); } catch { continue; } }
      current = nested; moved = true; break;
    }
    if (!moved) return current;
  }
  return current;
}

type HttpResponse = { status: number; headers: IncomingMessage["headers"]; response: IncomingMessage; deadlineExceeded: () => boolean };
type CollectorRequestStage = "readyz" | "stats" | "sessions" | "export-ticket" | "archive-download";
export type CollectorReadinessDriver = {
  now: () => number;
  wait: (milliseconds: number) => Promise<void>;
  probe: (timeoutMilliseconds: number) => Promise<{ status: number; drain: () => void }>;
};

export function classifyTransportFailure(error: unknown): string {
  const code = isObject(error) && typeof error.code === "string" ? error.code.toUpperCase() : "";
  if (["ETIMEDOUT", "ESOCKETTIMEDOUT"].includes(code)) return "timeout";
  if (["ENOTFOUND", "EAI_AGAIN", "EAI_FAIL"].includes(code)) return "dns";
  if (["ECONNREFUSED", "ENETUNREACH", "EHOSTUNREACH"].includes(code)) return "connect";
  if (["ECONNRESET", "EPIPE"].includes(code)) return "reset";
  if (code.startsWith("ERR_TLS_") || code.includes("CERT")) return "tls";
  if (code === "ABORT_ERR") return "cancelled";
  return "unknown";
}

export function collectorTransportDiagnostic(stage: CollectorRequestStage, error: unknown): string {
  return `collector request failed (stage=${stage},cause=${classifyTransportFailure(error)})`;
}

function requestTimeoutError(): Error & { code: string } {
  return Object.assign(new Error("request timed out"), { code: "ETIMEDOUT" });
}

function requestDeadlineError(): Error & { code: string; overallDeadline: true } {
  return Object.assign(new Error("request exceeded the overall deadline"), { code: "ETIMEDOUT", overallDeadline: true as const });
}

function isOverallDeadlineError(error: unknown): boolean {
  return isObject(error) && error.overallDeadline === true;
}

function request(url: URL, headers: Record<string, string>, timeoutMs: number, tls?: TlsFiles, deadline?: number, onInformation?: (statusCode: number) => void): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const options: RequestOptions = { method: "GET", headers, timeout: timeoutMs, agent: false, cert: tls?.cert, key: tls?.key };
    let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
    let deadlineExceeded = false;
    const clearDeadline = () => { if (deadlineTimer !== undefined) clearTimeout(deadlineTimer); };
    const exceedDeadline = () => { deadlineExceeded = true; operation.destroy(requestDeadlineError()); };
    const operation = (url.protocol === "https:" ? httpsRequest : httpRequest)(url, options, (response) => {
      response.once("end", clearDeadline);
      response.once("close", clearDeadline);
      response.once("error", clearDeadline);
      resolve({ status: response.statusCode ?? 0, headers: response.headers, response, deadlineExceeded: () => deadlineExceeded });
    });
    if (deadline !== undefined) {
      const remaining = deadline - performance.now();
      if (remaining <= 0) queueMicrotask(exceedDeadline);
      else deadlineTimer = setTimeout(exceedDeadline, remaining);
    }
    // Node does not treat an HTTP informational response as response-body
    // activity for the request timeout. The collector sends 102 while it
    // materializes a stable artifact, so explicitly restart this bounded idle
    // timer when that progress signal arrives. The overall export deadline is
    // intentionally unchanged.
    operation.on("information", (information: IncomingMessage) => {
      if (information.statusCode === 102) {
        if (deadline !== undefined && deadline <= performance.now()) exceedDeadline();
        else operation.setTimeout(timeoutMs);
        onInformation?.(information.statusCode);
      }
    });
    operation.once("timeout", () => operation.destroy(requestTimeoutError()));
    operation.once("error", (error) => { clearDeadline(); reject(error); });
    operation.once("close", clearDeadline);
    operation.end();
  });
}
async function readBounded(response: IncomingMessage, maximum: number): Promise<Buffer> {
  const chunks: Buffer[] = []; let size = 0;
  for await (const raw of response) {
    const chunk = Buffer.from(raw as Buffer); size += chunk.length;
    if (size > maximum) { response.destroy(); throw new DeltaError("source management response is too large"); }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
function delay(milliseconds: number): Promise<void> { return new Promise((resolve) => setTimeout(resolve, milliseconds)); }

export class SourceClient {
  readonly origin: string;
  readonly base: string;
  readonly downloadOrigin: string;
  readonly downloadBase: string;
  readonly paths: SourcePaths;
  readonly token: string | undefined;
  readonly timeoutSeconds: number;
  readonly allowAllHttp: boolean;
  readonly privateHttpHosts: ReadonlySet<string>;
  readonly collectorDirect: boolean;
  readonly maxRetries: number;
  readonly retryBaseSeconds: number;
  readonly deadline: number | undefined;
  readonly tls: TlsFiles | undefined;
  readonly maxDownloadBytes: number | undefined;
  readonly offlineFull: boolean;
  readonly archiveDownloadDiagnostics: ((message: string) => void) | undefined;
  downloadedBytes = 0;
  constructor(
    baseUrl: string,
    downloadBaseUrl: string,
    token: string | undefined,
    timeoutSeconds: number,
    allowAllHttp: boolean,
    privateHttpHosts: ReadonlySet<string>,
    collectorDirect = false,
    maxRetries = 5,
    retryBaseSeconds = 0.5,
    deadline?: number,
    tls?: TlsFiles,
    maxDownloadBytes?: number,
    offlineFull = false,
    archiveDownloadDiagnostics?: (message: string) => void,
  ) {
    const source = safeOrigin(baseUrl, allowAllHttp, privateHttpHosts, "archive source base URL");
    const download = safeOrigin(downloadBaseUrl, allowAllHttp, privateHttpHosts, "archive download base URL");
    this.origin = source.origin; this.base = source.base;
    this.downloadOrigin = download.origin; this.downloadBase = download.base;
    this.paths = collectorDirect ? COLLECTOR_PATHS : CPA_PATHS;
    this.token = token; this.timeoutSeconds = timeoutSeconds; this.allowAllHttp = allowAllHttp;
    this.privateHttpHosts = privateHttpHosts; this.collectorDirect = collectorDirect;
    this.maxRetries = maxRetries; this.retryBaseSeconds = retryBaseSeconds; this.deadline = deadline;
    this.tls = tls; this.maxDownloadBytes = maxDownloadBytes; this.offlineFull = offlineFull;
    this.archiveDownloadDiagnostics = archiveDownloadDiagnostics;
    if (collectorDirect && this.downloadOrigin !== this.origin) throw new DeltaError("collector-direct ticket downloads must use the collector origin");
    if (collectorDirect && token !== undefined) throw new DeltaError("collector-direct requests must not carry a CPA token");
    if (collectorDirect && tls === undefined && !privateHttpHosts.has(source.host)) throw new DeltaError("collector-direct requires a private host allowlist or mTLS");
  }

  private timeout(): number {
    if (this.deadline === undefined) return this.timeoutSeconds * 1000;
    const remaining = this.deadline - performance.now();
    if (remaining <= 0) throw new DeltaError("source export exceeded the configured elapsed-time limit");
    return Math.min(this.timeoutSeconds * 1000, remaining);
  }
  private archiveDownloadDiagnostic(event: "progress" | "failure", startedAt: number, lastActivityAt: number, cause?: string): void {
    if (!this.collectorDirect || this.archiveDownloadDiagnostics === undefined) return;
    const now = performance.now();
    const elapsedSeconds = Math.max(0, Math.floor((now - startedAt) / 1000));
    const idleSeconds = Math.max(0, Math.floor((now - lastActivityAt) / 1000));
    if (event === "progress") {
      this.archiveDownloadDiagnostics(`archive download progress status=102 elapsed_seconds=${elapsedSeconds} idle_seconds=${idleSeconds} idle_timer_reset=true`);
      return;
    }
    this.archiveDownloadDiagnostics(`archive download failure cause=${cause ?? "internal"} elapsed_seconds=${elapsedSeconds} idle_seconds=${idleSeconds}`);
  }
  private retryDelay(attempt: number, retryAfter?: string): number {
    let seconds = Math.min(this.retryBaseSeconds * 2 ** Math.min(attempt, 20), 10);
    if (retryAfter !== undefined && /^\d+$/.test(retryAfter)) seconds = Math.min(Math.max(seconds, Number(retryAfter)), 30);
    let milliseconds = seconds * 1000;
    if (this.deadline !== undefined) milliseconds = Math.min(milliseconds, Math.max(0, this.deadline - performance.now()));
    return milliseconds;
  }
  private async waitForRetry(attempt: number, retryAfter?: string): Promise<void> {
    const milliseconds = this.retryDelay(attempt, retryAfter);
    if (milliseconds <= 0) throw new DeltaError("source export exceeded the configured elapsed-time limit");
    await delay(milliseconds);
  }
  private stage(path: string): CollectorRequestStage {
    if (path === this.paths.stats) return "stats";
    if (path === this.paths.sessions) return "sessions";
    return "export-ticket";
  }
  async waitUntilReady(timeoutSeconds: number, intervalMilliseconds: number, injected?: CollectorReadinessDriver): Promise<void> {
    if (!this.collectorDirect) throw new DeltaError("collector readiness preflight requires collector-direct mode");
    const driver: CollectorReadinessDriver = injected ?? {
      now: () => performance.now(),
      wait: delay,
      probe: async (timeoutMilliseconds) => {
        const result = await request(new URL(this.base + COLLECTOR_READY_PATH), { Accept: "text/plain", "User-Agent": "memeloop-token-center-delta-export/1" }, timeoutMilliseconds, this.tls);
        return { status: result.status, drain: () => result.response.resume() };
      },
    };
    const configuredDeadline = driver.now() + timeoutSeconds * 1000;
    const deadline = this.deadline === undefined ? configuredDeadline : Math.min(configuredDeadline, this.deadline);
    const limit = this.deadline !== undefined && this.deadline <= configuredDeadline ? "overall" : "readiness";
    let lastCause = "not_ready";
    while (driver.now() < deadline) {
      let result: { status: number; drain: () => void };
      try {
        result = await driver.probe(Math.min(this.timeoutSeconds * 1000, deadline - driver.now()));
      } catch (error) {
        lastCause = classifyTransportFailure(error);
        if (!["timeout", "dns", "connect", "reset"].includes(lastCause)) throw new DeltaError(collectorTransportDiagnostic("readyz", error));
        if (driver.now() >= deadline) break;
        await driver.wait(Math.min(intervalMilliseconds, Math.max(1, deadline - driver.now())));
        continue;
      }
      result.drain();
      if (result.status === 200) return;
      lastCause = `http_${result.status}`;
      if (![429, 503].includes(result.status)) throw new DeltaError(`collector request failed (stage=readyz,cause=${lastCause})`);
      if (driver.now() >= deadline) break;
      await driver.wait(Math.min(intervalMilliseconds, Math.max(1, deadline - driver.now())));
    }
    throw new DeltaError(`collector request failed (stage=readyz,cause=${lastCause},limit=${limit})`);
  }
  private async managementJson(path: string, query: Record<string, string>): Promise<unknown> {
    const url = new URL(this.base + path);
    for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
    const headers: Record<string, string> = { Accept: "application/json", "User-Agent": "memeloop-token-center-delta-export/1" };
    if (this.token !== undefined) headers.Authorization = `Bearer ${this.token}`;
    let attempt = 0;
    while (true) {
      let result: HttpResponse;
      try { result = await request(url, headers, this.timeout(), this.tls); }
      catch (error) {
        if (error instanceof DeltaError) {
          if (this.collectorDirect && error.message === "source export exceeded the configured elapsed-time limit") throw new DeltaError(`collector request failed (stage=${this.stage(path)},cause=overall_timeout)`);
          throw error;
        }
        if (this.collectorDirect) throw new DeltaError(collectorTransportDiagnostic(this.stage(path), error));
        throw new DeltaError("source management request failed");
      }
      if (result.status === 200) {
        let payload: Buffer;
        try { payload = await readBounded(result.response, MAX_MANAGEMENT_RESPONSE_BYTES); }
        catch (error) {
          if (this.collectorDirect) throw new DeltaError(`collector request failed (stage=${this.stage(path)},cause=${error instanceof DeltaError ? "response_too_large" : classifyTransportFailure(error)})`);
          throw error;
        }
        try { return unwrapJson(parseStrictJson(payload.toString("utf8"))); }
        catch (error) {
          if (this.collectorDirect) throw new DeltaError(`collector request failed (stage=${this.stage(path)},cause=invalid_json)`);
          if (error instanceof DeltaError) throw error;
          throw new DeltaError("source management response is not valid JSON");
        }
      }
      result.response.resume();
      if (result.status === 410) throw new SnapshotExpired();
      const extended = this.collectorDirect && this.offlineFull && path === this.paths.sessions && [429, 503].includes(result.status);
      if ([429, 503].includes(result.status) && (attempt < this.maxRetries || extended)) {
        await this.waitForRetry(attempt, Array.isArray(result.headers["retry-after"]) ? result.headers["retry-after"]?.[0] : result.headers["retry-after"]);
        attempt += 1; continue;
      }
      if (this.collectorDirect) throw new DeltaError(`collector request failed (stage=${this.stage(path)},cause=http_${result.status})`);
      throw new SourceHTTPError(result.status);
    }
  }

  private sessionItems(payload: unknown, strict: boolean): SessionSummary[] {
    if (!Array.isArray(payload)) throw new DeltaError("source sessions response is not an array");
    const output: SessionSummary[] = []; const seen = new Set<string>(); let previous: [Time, string] | undefined;
    for (const raw of payload) {
      if (!isObject(raw)) throw new DeltaError("source session summary is invalid");
      const sessionId = raw.session_id;
      if (typeof sessionId !== "string" || sessionId.length === 0 || seen.has(sessionId)) throw new DeltaError("source session identity is invalid or duplicated");
      if (strict && (sessionId.length > 512 || [...sessionId].some((character) => character.charCodeAt(0) < 0x20 || character.charCodeAt(0) > 0x7e))) throw new DeltaError("source stable session identity is not printable ASCII");
      const deleted = raw.deleted === true;
      const last = parseTime(raw.last_at, "source session last_at");
      if (deleted) {
        const deletedAt = parseTime(raw.deleted_at, "source session deleted_at");
        if (!strict || raw.requests !== 0 || raw.first_at !== undefined || raw.records_sha256 !== undefined || raw.last_at !== formatTime(last)
            || raw.deleted_at !== formatTime(deletedAt) || compareTime(last, deletedAt) !== 0) throw new DeltaError("source stable session tombstone is invalid");
      } else {
        if (raw.deleted !== undefined || raw.deleted_at !== undefined) throw new DeltaError("source session contains unsupported tombstone fields");
        const first = parseTime(raw.first_at, "source session first_at");
        if (compareTime(first, last) > 0) throw new DeltaError("source session time range is invalid");
        if (strict && (raw.first_at !== formatTime(first) || raw.last_at !== formatTime(last) || !isSha256(raw.records_sha256))) throw new DeltaError("source stable session timestamps or record digest are invalid");
      }
      if (previous !== undefined && (compareTime(last, previous[0]) > 0 || (strict && compareTime(last, previous[0]) === 0 && sessionId <= previous[1]))) throw new DeltaError("source sessions are not in stable last_at/session_id order");
      if (!Number.isSafeInteger(raw.requests) || (raw.requests as number) < 0) throw new DeltaError("source session request count is invalid");
      const item = raw as SessionSummary; output.push(item); seen.add(sessionId); previous = [last, sessionId];
    }
    return output;
  }
  async sessions(limit: number): Promise<SessionSummary[]> {
    let payload = await this.managementJson(this.paths.sessions, { limit: String(limit) });
    if (isObject(payload)) payload = payload.sessions ?? payload.items;
    return this.sessionItems(payload, false);
  }
  private opaqueCursor(value: unknown, label: string): string {
    const maximum = this.collectorDirect ? 128 : 4096;
    if (typeof value !== "string" || value.length === 0 || value.length > maximum || [...value].some((character) => character.charCodeAt(0) < 0x21 || character.charCodeAt(0) > 0x7e)) throw new DeltaError(`source ${label} is invalid`);
    return value;
  }
  static ingestFence(value: unknown, label: string): string {
    if (typeof value !== "string" || !/^(?:0|[1-9]\d{0,19})$/.test(value) || BigInt(value) > 9_223_372_036_854_775_807n) throw new DeltaError(`source ${label} is invalid`);
    return value;
  }
  async stableSessions(limit: number, lowerBound: Time, snapshot?: string, afterFence?: string): Promise<Projection> {
    if (afterFence !== undefined) afterFence = SourceClient.ingestFence(afterFence, "prior ingest fence");
    const sessions: SessionSummary[] = []; const seenSessions = new Set<string>(); const seenCursors = new Set<string>();
    let cursor: string | undefined; let expected: [string, string, number, number, string, number, string | null, number] | undefined; let expectedSnapshot = snapshot;
    let previous: [Time, string] | undefined; let pageCount = 0;
    while (true) {
      const query: Record<string, string> = { limit: String(limit), cursor_protocol: STABLE_CURSOR_PROTOCOL, lower_bound_completed_at: formatTime(lowerBound) };
      if (expectedSnapshot !== undefined) query.snapshot = expectedSnapshot;
      if (afterFence !== undefined) query.after_ingest_fence = afterFence;
      if (cursor !== undefined) query.cursor = cursor;
      const payload = await this.managementJson(this.paths.sessions, query);
      if (!isObject(payload) || payload.cursor_protocol !== STABLE_CURSOR_PROTOCOL) {
        if (Array.isArray(payload) || (isObject(payload) && !("cursor_protocol" in payload) && ("sessions" in payload || "items" in payload))) throw new StableCursorUnsupported(`source does not implement ${STABLE_CURSOR_PROTOCOL}`);
        throw new DeltaError("source returned an invalid stable session projection response");
      }
      const pageSnapshot = this.opaqueCursor(payload.snapshot, "snapshot"); const fence = SourceClient.ingestFence(payload.ingest_fence, "ingest fence");
      if (afterFence !== undefined && BigInt(fence) < BigInt(afterFence)) throw new DeltaError("source ingest fence moved backwards");
      const count = payload.session_count, requests = payload.request_count, digest = payload.session_set_sha256, complete = payload.complete;
      const schemaVersion = payload.snapshot_schema_version === undefined ? 1 : payload.snapshot_schema_version;
      if (![1, 2].includes(schemaVersion as number)) throw new DeltaError("source stable snapshot schema is unsupported");
      const tombstoneFence = schemaVersion === 2 ? SourceClient.ingestFence(payload.tombstone_safe_after_ingest_fence, "tombstone-safe ingest fence") : undefined;
      const deletedCount = schemaVersion === 2 ? payload.deleted_session_count : 0;
      if (!Number.isSafeInteger(count) || (count as number) < 0 || (count as number) > MAX_SESSION_COUNT || !Number.isSafeInteger(requests) || (requests as number) < 0 || !isSha256(digest) || typeof complete !== "boolean"
          || !Number.isSafeInteger(deletedCount) || (deletedCount as number) < 0 || (deletedCount as number) > (count as number)) throw new DeltaError("source stable session projection metadata is invalid");
      if (schemaVersion === 2 && afterFence !== undefined && BigInt(afterFence) < BigInt(tombstoneFence!)) throw new DeltaError("source accepted a prior fence before its tombstone-safe upgrade fence");
      const metadata: [string, string, number, number, string, number, string | null, number] = [pageSnapshot, fence, count as number, requests as number, digest, schemaVersion as number, tombstoneFence ?? null, deletedCount as number];
      if (expected === undefined) { expected = metadata; expectedSnapshot = pageSnapshot; }
      else if (canonicalize(expected) !== canonicalize(metadata)) throw new DeltaError("source stable session projection metadata changed between pages");
      if (snapshot !== undefined && pageSnapshot !== snapshot) throw new DeltaError("source stable session snapshot could not be replayed");
      const page = this.sessionItems(payload.sessions ?? payload.items, true); pageCount += 1;
      if (schemaVersion === 1 && page.some((item) => item.deleted === true)) throw new DeltaError("source snapshot schema v1 contains tombstones");
      if (page.length > limit || (page.length === 0 && !complete)) throw new DeltaError("source stable session projection page is invalid");
      if (!complete && page.length !== limit) throw new DeltaError("source stable session projection has a short page gap");
      if (pageCount > Math.max(1, Math.ceil((count as number) / limit))) throw new DeltaError("source stable session projection has too many pages");
      for (const item of page) {
        const last = parseTime(item.last_at, "source session last_at");
        if (previous !== undefined && (compareTime(last, previous[0]) > 0 || (compareTime(last, previous[0]) === 0 && item.session_id <= previous[1]))) throw new DeltaError("source stable session pages overlap or are not in cursor order");
        if (seenSessions.has(item.session_id)) throw new DeltaError("source stable session pages contain a duplicate session");
        sessions.push(item); seenSessions.add(item.session_id); previous = [last, item.session_id];
        if (sessions.length > (count as number)) throw new DeltaError("source stable session projection exceeds its declared count");
      }
      if (complete) { if (payload.next_cursor !== null && payload.next_cursor !== undefined) throw new DeltaError("source stable session projection completion is invalid"); break; }
      const next = this.opaqueCursor(payload.next_cursor, "session cursor");
      if (seenCursors.has(next)) throw new DeltaError("source stable session projection cursor loop detected");
      seenCursors.add(next); cursor = next;
    }
    if (expected === undefined) throw new DeltaError("source stable session projection is empty without metadata");
    if (sessions.length !== expected[2]) throw new DeltaError("source stable session projection has a gap");
    if (sessions.reduce((sum, item) => sum + item.requests, 0) !== expected[3]) throw new DeltaError("source stable session projection request count disagrees");
    if (sessions.filter((item) => item.deleted === true).length !== expected[7]) throw new DeltaError("source stable session projection tombstone count disagrees");
    if (selectionDigest(sessions) !== expected[4]) throw new DeltaError("source stable session projection digest disagrees");
    return { sessions, protocol: STABLE_CURSOR_PROTOCOL, requestCount: expected[3], snapshot: expected[0], ingestFence: expected[1], snapshotSchemaVersion: expected[5], ...(expected[6] === null ? {} : { tombstoneSafeAfterIngestFence: expected[6] }), deletedSessionCount: expected[7] };
  }
  async statsRecords(): Promise<number> {
    const payload = await this.managementJson(this.paths.stats, {});
    if (!isObject(payload) || !Number.isSafeInteger(payload.records) || (payload.records as number) < 0) throw new DeltaError("source stats record count is invalid");
    return payload.records as number;
  }
  async verifyOfflineFull(): Promise<void> {
    const payload = await this.managementJson(this.paths.stats, {});
    if (!isObject(payload) || !Array.isArray(payload.session_cursor_protocols) || !payload.session_cursor_protocols.includes(STABLE_CURSOR_PROTOCOL) || payload.offline_full_snapshot_enabled !== true) throw new DeltaError("collector does not advertise an enabled offline full snapshot");
  }
  private async ticketUrl(sessionId: string, snapshot?: string, recordsSha256?: string): Promise<URL> {
    const query: Record<string, string> = { [this.collectorDirect ? "session_id" : "id"]: sessionId, scope: "session", format: "archive" };
    if (snapshot !== undefined) query.snapshot = snapshot;
    const payload = await this.managementJson(this.paths.export, query);
    if (!isObject(payload) || typeof payload.url !== "string" || [...payload.url].some((character) => character.charCodeAt(0) < 0x21 || character.charCodeAt(0) > 0x7e)) throw new DeltaError("source export ticket response is invalid");
    if (snapshot !== undefined && (payload.cursor_protocol !== STABLE_CURSOR_PROTOCOL || payload.snapshot !== snapshot || payload.records_sha256 !== recordsSha256)) throw new DeltaError("source export ticket is not bound to the stable snapshot");
    const ticket = new URL(payload.url, `${this.downloadBase}/`);
    if (ticket.origin !== this.downloadOrigin || ticket.username || ticket.password || ticket.hash || !ticket.pathname.startsWith(TICKET_PATH_PREFIX)) throw new DeltaError("source export ticket escaped the configured download origin");
    const capability = ticket.pathname.slice(TICKET_PATH_PREFIX.length); let decoded: string;
    try { decoded = decodeURIComponent(capability); } catch { throw new DeltaError("source export ticket path is invalid"); }
    if (!capability || capability.includes("/") || capability.includes("\\") || decoded.includes("/") || decoded.includes("\\") || [".", ".."].includes(decoded) || decoded.length > 512 || [...decoded].some((character) => character.charCodeAt(0) < 0x21 || character.charCodeAt(0) > 0x7e)) throw new DeltaError("source export ticket path is invalid");
    if (this.collectorDirect) { if (ticket.search || !/^[0-9a-f]{64}$/.test(capability)) throw new DeltaError("collector export capability is invalid"); }
    else if (ticket.search) {
      const entries = [...ticket.searchParams.entries()];
      if (entries.length !== 1 || entries[0]?.[0] !== "snapshot" || snapshot === undefined || entries[0]?.[1] !== snapshot) throw new DeltaError("source export ticket query is invalid");
    }
    return ticket;
  }
  async *exportLines(sessionId: string, maximum: number, snapshot?: string, recordsSha256?: string): AsyncGenerator<string> {
    let response: IncomingMessage | undefined;
    let responseDeadlineExceeded = () => false;
    let downloadStartedAt = performance.now();
    let lastActivityAt = downloadStartedAt;
    for (let attempt = 0; attempt <= this.maxRetries; attempt += 1) {
      const ticket = await this.ticketUrl(sessionId, snapshot, recordsSha256);
      downloadStartedAt = performance.now();
      lastActivityAt = downloadStartedAt;
      let result: HttpResponse;
      try {
        result = await request(ticket, { Accept: "application/x-ndjson", "User-Agent": "memeloop-token-center-delta-export/1" }, this.timeout(), this.tls, this.deadline, () => {
          this.archiveDownloadDiagnostic("progress", downloadStartedAt, lastActivityAt);
          lastActivityAt = performance.now();
        });
      }
      catch (error) {
        this.archiveDownloadDiagnostic("failure", downloadStartedAt, lastActivityAt, error instanceof DeltaError || isOverallDeadlineError(error) ? "overall_timeout" : classifyTransportFailure(error));
        if (error instanceof DeltaError) {
          if (this.collectorDirect && error.message === "source export exceeded the configured elapsed-time limit") throw new DeltaError("collector request failed (stage=archive-download,cause=overall_timeout)");
          throw error;
        }
        if (this.collectorDirect) throw new DeltaError(`collector request failed (stage=archive-download,cause=${isOverallDeadlineError(error) ? "overall_timeout" : classifyTransportFailure(error)})`);
        throw new DeltaError("source archive export failed");
      }
      if (result.status === 200) { response = result.response; responseDeadlineExceeded = result.deadlineExceeded; break; }
      result.response.resume();
      if (this.collectorDirect && snapshot !== undefined && result.status === 404 && attempt < this.maxRetries) { await this.waitForRetry(attempt); continue; }
      if (this.collectorDirect && snapshot !== undefined && result.status === 404) throw new SnapshotExpired();
      if (this.collectorDirect) throw new DeltaError(`collector request failed (stage=archive-download,cause=http_${result.status})`);
      throw new DeltaError(`source archive export returned HTTP ${result.status}`);
    }
    if (response === undefined) throw new DeltaError("source archive export failed");
    let fragments: Buffer[] = [];
    let bufferedBytes = 0;
    const append = (fragment: Buffer): void => {
      if (fragment.length === 0) return;
      bufferedBytes += fragment.length;
      if (bufferedBytes > maximum) throw new DeltaError("source archive record exceeds the configured line limit");
      fragments.push(fragment);
    };
    const decode = (): string => {
      const bytes = fragments.length === 1 ? fragments[0]! : Buffer.concat(fragments, bufferedBytes);
      fragments = []; bufferedBytes = 0;
      return bytes.toString("utf8");
    };
    try {
      for await (const raw of response) {
        this.timeout(); lastActivityAt = performance.now(); const chunk = Buffer.isBuffer(raw) ? raw : Buffer.from(raw as Uint8Array); this.downloadedBytes += chunk.length;
        if (this.maxDownloadBytes !== undefined && this.downloadedBytes > this.maxDownloadBytes) throw new DeltaError("source archive downloads exceed the configured limit");
        let offset = 0;
        while (offset < chunk.length) {
          const newline = chunk.indexOf(0x0a, offset);
          const end = newline < 0 ? chunk.length : newline + 1;
          append(chunk.subarray(offset, end));
          if (newline < 0) break;
          const line = decode();
          if (line.trim()) yield line;
          offset = end;
        }
      }
      if (bufferedBytes > 0) {
        const line = decode();
        if (line.trim()) yield line;
      }
    } catch (error) {
      const cause = responseDeadlineExceeded() ? "overall_timeout" : error instanceof DeltaError ? "validation" : classifyTransportFailure(error);
      this.archiveDownloadDiagnostic("failure", downloadStartedAt, lastActivityAt, cause);
      if (error instanceof DeltaError) throw error;
      if (this.collectorDirect) throw new DeltaError(`collector request failed (stage=archive-download,cause=${cause})`);
      throw new DeltaError("source archive export stream failed");
    }
  }
}

/**
 * Read a sealed cpa-session-archive SQLite online-backup directly. The file is
 * required to be immutable and sidecar-free so request-id seek cursors remain
 * valid across process restarts without holding a long-lived source snapshot.
 */
export class SQLiteArchiveSource {
  readonly path: string;
  readonly database: DatabaseSync;
  readonly projection: Projection;
  readonly recordCount: number;

  constructor(path: string) {
    if (!isAbsolute(path) || path !== resolve(path)) throw new DeltaError("source SQLite snapshot path must be absolute");
    ensurePrivateSpoolFile(path, "source SQLite snapshot");
    const metadata = lstatSync(path);
    if ((metadata.mode & 0o222) !== 0) throw new DeltaError("source SQLite snapshot must be filesystem read-only");
    if (archiveSpoolSidecars(path).some(existsSync)) throw new DeltaError("source SQLite snapshot must not have WAL or SHM sidecars");
    this.path = path;
    this.database = new DatabaseSync(path, { readOnly: true });
    try {
      this.database.exec("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF");
      this.verifySchema();
      const counts = this.database.prepare("SELECT COUNT(*) AS records,COUNT(DISTINCT session_id) AS sessions FROM records").get() as { records: number; sessions: number };
      const indexed = this.database.prepare("SELECT COALESCE(SUM(requests),0) AS records,COUNT(*) AS sessions FROM session_summaries").get() as { records: number; sessions: number };
      if (!Number.isSafeInteger(counts.records) || counts.records < 0 || counts.records !== indexed.records || counts.sessions !== indexed.sessions) {
        throw new DeltaError("source SQLite snapshot session index is incomplete");
      }
      this.recordCount = counts.records;
      this.projection = this.loadProjection(counts.sessions);
    } catch (error) {
      this.database.close();
      throw error;
    }
  }

  private verifySchema(): void {
    const required: Record<string, string[]> = {
      records: ["request_id", "session_id", "key_id", "principal_id", "credential_hash", "requested_model", "model", "outcome", "status_code", "started_at", "completed_at", "metadata_json", "facets_json", "original_ref", "response_ref", "original_request_gz", "response_gz"],
      blobs: ["hash", "codec", "data"],
      session_summaries: ["session_id", "requests"],
      archive_ingest_clock: ["id", "sequence"],
      archive_ingest_events: ["sequence", "session_id", "previous_session_id"],
      session_export_digests: ["session_id", "requests", "first_at", "last_at", "records_sha256", "max_ingest_sequence"],
      archive_snapshot_contract: ["id", "schema_version", "tombstone_safe_after_sequence"],
    };
    for (const [table, columns] of Object.entries(required)) {
      const found = new Set((this.database.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>).map((item) => item.name));
      if (columns.some((column) => !found.has(column))) throw new DeltaError("source SQLite snapshot schema is unsupported");
    }
  }

  private loadProjection(expectedSessions: number): Projection {
    const clock = this.database.prepare("SELECT sequence FROM archive_ingest_clock WHERE id=1").get() as { sequence: number } | undefined;
    const contract = this.database.prepare("SELECT schema_version,tombstone_safe_after_sequence FROM archive_snapshot_contract WHERE id=1").get() as { schema_version: number; tombstone_safe_after_sequence: number } | undefined;
    if (clock === undefined || !Number.isSafeInteger(clock.sequence) || clock.sequence < 0 || contract === undefined || contract.schema_version !== 2
        || !Number.isSafeInteger(contract.tombstone_safe_after_sequence) || contract.tombstone_safe_after_sequence < 0 || contract.tombstone_safe_after_sequence > clock.sequence) {
      throw new DeltaError("source SQLite snapshot stable contract is invalid");
    }
    const rows = this.database.prepare(`SELECT d.session_id,d.requests,d.first_at,d.last_at,d.records_sha256,d.max_ingest_sequence,
      COALESCE((SELECT MAX(e.sequence) FROM archive_ingest_events e WHERE e.session_id=d.session_id OR e.previous_session_id=d.session_id),0) AS current_sequence
      FROM session_export_digests d
      WHERE EXISTS(SELECT 1 FROM records r WHERE r.session_id=d.session_id)
      ORDER BY d.last_at DESC,d.session_id COLLATE BINARY ASC`).all() as Array<{
        session_id: string; requests: number; first_at: string; last_at: string; records_sha256: string; max_ingest_sequence: number; current_sequence: number;
      }>;
    if (rows.length !== expectedSessions) throw new DeltaError("source SQLite snapshot export digests are incomplete");
    const sessions: SessionSummary[] = [];
    let requests = 0;
    for (const row of rows) {
      if (typeof row.session_id !== "string" || row.session_id.length === 0 || row.session_id.length > 512
          || [...row.session_id].some((character) => character.charCodeAt(0) < 0x20 || character.charCodeAt(0) > 0x7e)
          || !Number.isSafeInteger(row.requests) || row.requests < 1 || !isSha256(row.records_sha256)
          || row.max_ingest_sequence !== row.current_sequence) throw new DeltaError("source SQLite snapshot export digest is stale or invalid");
      const first = parseTime(row.first_at, "source SQLite session first_at"), last = parseTime(row.last_at, "source SQLite session last_at");
      const item: SessionSummary = { session_id: row.session_id, requests: row.requests, first_at: formatTime(first), last_at: formatTime(last), records_sha256: row.records_sha256 };
      sessions.push(item); requests += row.requests;
    }
    if (requests !== this.recordCount) throw new DeltaError("source SQLite snapshot request count disagrees");
    const setDigest = selectionDigest(sessions);
    return {
      sessions,
      protocol: STABLE_CURSOR_PROTOCOL,
      requestCount: requests,
      snapshot: `sqlite-${sha256Bytes(canonicalBytes({ fence: String(clock.sequence), sessions: setDigest }))}`,
      ingestFence: String(clock.sequence),
      snapshotSchemaVersion: 2,
      tombstoneSafeAfterIngestFence: String(contract.tombstone_safe_after_sequence),
      deletedSessionCount: 0,
    };
  }

  statsRecords(): number { return this.recordCount; }
  stableProjection(): Projection { return this.projection; }

  private blob(hash: string): Buffer {
    const row = this.database.prepare("SELECT codec,data FROM blobs WHERE hash=?").get(hash) as { codec: string; data: Uint8Array } | undefined;
    if (row === undefined) throw new DeltaError("source SQLite snapshot payload blob is missing");
    const value = Buffer.from(row.data);
    try { return row.codec === "gzip" ? gunzipSync(value) : value; }
    catch { throw new DeltaError("source SQLite snapshot payload blob is invalid"); }
  }

  private expand(value: unknown): unknown {
    if (Array.isArray(value)) return value.map((item) => this.expand(item));
    if (!isObject(value)) return value;
    if (typeof value.$cpa_blob === "string") {
      const raw = this.blob(value.$cpa_blob); const encoding = value.encoding;
      if (encoding === "raw") return raw;
      if (encoding === "utf8") return raw.toString("utf8");
      if (encoding === "data-url") return `data:${typeof value.media_type === "string" ? value.media_type : ""};base64,${raw.toString("base64")}`;
      if (encoding === "json") {
        let nested: unknown;
        try { nested = parseStrictJson(raw.toString("utf8")); } catch { throw new DeltaError("source SQLite snapshot JSON payload blob is invalid"); }
        return this.expand(nested);
      }
      throw new DeltaError("source SQLite snapshot payload encoding is unsupported");
    }
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, this.expand(item)]));
  }

  private decodedPayload(reference: string, legacy: Uint8Array | null): unknown {
    let expanded: unknown;
    if (reference !== "") {
      let manifest: unknown;
      try { manifest = parseStrictJson(this.blob(reference).toString("utf8")); } catch { throw new DeltaError("source SQLite snapshot payload manifest is invalid"); }
      expanded = this.expand(manifest);
      if (!Buffer.isBuffer(expanded)) return expanded;
    } else {
      if (legacy === null || legacy.byteLength === 0) return undefined;
      try { expanded = gunzipSync(Buffer.from(legacy)); } catch { throw new DeltaError("source SQLite snapshot legacy payload is invalid"); }
    }
    const raw = Buffer.from(expanded as Uint8Array);
    try { return parseStrictJson(raw.toString("utf8")); } catch { return raw.toString("utf8"); }
  }

  private optionalJson(raw: string, label: string): unknown {
    if (raw === "") return undefined;
    try { const value = parseStrictJson(raw); return value === null ? undefined : value; }
    catch { throw new DeltaError(`source SQLite snapshot ${label} is invalid`); }
  }

  async *exportLines(sessionId: string, maximum: number, afterRequestId?: string): AsyncGenerator<string> {
    const statement = this.database.prepare(`SELECT request_id,session_id,COALESCE(key_id,'') AS key_id,COALESCE(principal_id,'') AS principal_id,
      COALESCE(credential_hash,'') AS credential_hash,COALESCE(requested_model,'') AS requested_model,COALESCE(model,'') AS model,
      COALESCE(outcome,'') AS outcome,COALESCE(status_code,0) AS status_code,started_at,completed_at,COALESCE(metadata_json,'') AS metadata_json,
      COALESCE(facets_json,'') AS facets_json,COALESCE(original_ref,'') AS original_ref,COALESCE(response_ref,'') AS response_ref,
      original_request_gz,response_gz FROM records WHERE session_id=? AND request_id>? ORDER BY request_id COLLATE BINARY ASC`);
    for (const row of statement.iterate(sessionId, afterRequestId ?? "") as Iterable<SQLiteSourceRow>) {
      const started = parseTime(row.started_at, "source SQLite record started_at"), completed = parseTime(row.completed_at, "source SQLite record completed_at");
      const record: JsonObject = { schema_version: 2, session_id: row.session_id, request_id: row.request_id, started_at: formatTime(started), completed_at: formatTime(completed) };
      for (const [key, value] of Object.entries({ key_id: row.key_id, principal_id: row.principal_id, credential_hash: row.credential_hash, requested_model: row.requested_model, model: row.model, outcome: row.outcome })) if (value.trim() !== "") record[key] = value;
      if (row.status_code !== 0) record.status_code = row.status_code;
      const metadata = this.optionalJson(row.metadata_json, "metadata"), facets = this.optionalJson(row.facets_json, "facets");
      if (metadata !== undefined) record.metadata = metadata;
      if (facets !== undefined) record.facets = facets;
      const requestPayload = this.decodedPayload(row.original_ref, row.original_request_gz), responsePayload = this.decodedPayload(row.response_ref, row.response_gz);
      if (requestPayload !== undefined) record.request = requestPayload;
      if (responsePayload !== undefined) record.response = responsePayload;
      const line = `${canonicalize(record)}\n`;
      if (Buffer.byteLength(line) > maximum) throw new DeltaError("source archive record exceeds the configured line limit");
      yield line;
    }
  }

  close(): void { this.database.close(); }
}

export function sourceFingerprint(client: SourceClient): string {
  const descriptor: JsonObject = {
    origin: client.origin, base: client.base, download_origin: client.downloadOrigin, download_base: client.downloadBase,
    sessions_path: client.paths.sessions, export_path: client.paths.export, stats_path: client.paths.stats,
    version: client.collectorDirect ? COLLECTOR_FINGERPRINT_VERSION : SOURCE_FINGERPRINT_VERSION,
  };
  if (client.collectorDirect) descriptor.source_mode = client.paths.mode;
  return sha256Bytes(canonicalBytes(descriptor));
}

function readStrictFile(path: string, label: string): unknown {
  ensurePrivateRegular(path, label);
  try { return parseStrictJson(readFileSync(path, "utf8")); } catch { throw new DeltaError(`${label} is not valid JSON`); }
}
function loadCheckpoint(path: string, fingerprint: string): JsonObject | undefined {
  if (!existsSync(path)) return undefined;
  const value = readStrictFile(path, "checkpoint");
  if (!isObject(value) || ![1, CHECKPOINT_VERSION].includes(value.version as number) || value.source_fingerprint !== fingerprint
      || !Number.isSafeInteger(value.sequence) || (value.sequence as number) < 0 || !isSha256(value.last_output_sha256)
      || !Number.isSafeInteger(value.last_output_records) || (value.last_output_records as number) < 0
      || !Number.isSafeInteger(value.last_source_records) || (value.last_source_records as number) < 0) throw new DeltaError("checkpoint does not match this source or version");
  parseCanonicalTime(value.watermark_completed_at, "checkpoint watermark");
  if (value.version === CHECKPOINT_VERSION) {
    if (![LEGACY_PROJECTION_PROTOCOL, STABLE_CURSOR_PROTOCOL].includes(value.session_projection_protocol as string)) throw new DeltaError("checkpoint session projection protocol is invalid");
    if (value.session_projection_protocol === STABLE_CURSOR_PROTOCOL) SourceClient.ingestFence(value.source_ingest_fence, "checkpoint ingest fence");
    else if (value.source_ingest_fence !== null) throw new DeltaError("legacy checkpoint contains an ingest fence");
  }
  return value;
}
function fsyncDirectory(path: string): void { const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY); try { fsyncSync(descriptor); } finally { closeSync(descriptor); } }
function writeAtomicJson(path: string, value: JsonObject): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  if (existsSync(path) && lstatSync(path).isSymbolicLink()) throw new DeltaError("refusing to replace a symlink");
  const temporary = join(dirname(path), `.${basename(path)}.${process.pid}.${Date.now()}`);
  let descriptor = -1;
  try {
    descriptor = openSync(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    writeFileSync(descriptor, Buffer.concat([canonicalBytes(value), Buffer.from("\n")])); fsyncSync(descriptor);
    closeSync(descriptor); descriptor = -1;
    renameSync(temporary, path); fsyncDirectory(dirname(path));
  } finally { if (descriptor >= 0) closeSync(descriptor); rmSync(temporary, { force: true }); }
}
async function fileDigest(path: string): Promise<[number, string]> {
  let size = 0; const digest = createHash("sha256");
  for await (const raw of createReadStream(path)) { const chunk = Buffer.from(raw); size += chunk.length; digest.update(chunk); }
  return [size, digest.digest("hex")];
}
function validateManifest(manifest: unknown, fingerprint: string, output: string): JsonObject {
  if (!isObject(manifest)) throw new DeltaError("delta manifest is invalid");
  const integers = ["sequence", "overlap_seconds", "max_future_skew_seconds", "session_limit", "session_count", "record_count", "source_records_before", "source_records_after", "output_size_bytes"];
  if (![1, 2, MANIFEST_VERSION].includes(manifest.version as number) || manifest.source_fingerprint !== fingerprint || manifest.output_file !== basename(output)
      || integers.some((key) => !Number.isSafeInteger(manifest[key]) || (manifest[key] as number) < 0) || (manifest.sequence as number) < 1
      || (manifest.overlap_seconds as number) < 1 || !isSha256(manifest.output_sha256) || !isSha256(manifest.session_set_sha256) || typeof manifest.stable_source_required !== "boolean") throw new DeltaError("delta manifest is invalid");
  if (manifest.prior_output_sha256 !== null && !isSha256(manifest.prior_output_sha256)) throw new DeltaError("delta manifest prior output digest is invalid");
  const protocol = (manifest.session_projection_protocol ?? LEGACY_PROJECTION_PROTOCOL) as string;
  if (![LEGACY_PROJECTION_PROTOCOL, STABLE_CURSOR_PROTOCOL].includes(protocol)) throw new DeltaError("delta manifest session projection protocol is invalid");
  if (protocol === STABLE_CURSOR_PROTOCOL) {
    if (!Number.isSafeInteger(manifest.source_projection_requests) || !isSha256(manifest.source_snapshot_sha256)) throw new DeltaError("delta manifest stable snapshot metadata is invalid");
    SourceClient.ingestFence(manifest.source_ingest_fence, "manifest ingest fence");
    if (manifest.version === MANIFEST_VERSION) {
      if (![1, 2].includes(manifest.snapshot_schema_version as number) || !Number.isSafeInteger(manifest.deleted_session_count) || (manifest.deleted_session_count as number) < 0) throw new DeltaError("delta manifest snapshot schema metadata is invalid");
      if (manifest.snapshot_schema_version === 2) SourceClient.ingestFence(manifest.tombstone_safe_after_ingest_fence, "manifest tombstone-safe ingest fence");
      else if (manifest.tombstone_safe_after_ingest_fence !== null || manifest.deleted_session_count !== 0) throw new DeltaError("delta manifest schema v1 contains tombstone metadata");
    }
  }
  const prior = parseCanonicalTime(manifest.prior_watermark_completed_at, "delta manifest prior watermark");
  const lower = parseCanonicalTime(manifest.lower_bound_completed_at, "delta manifest lower bound");
  const watermark = parseCanonicalTime(manifest.watermark_completed_at, "delta manifest watermark");
  const observed = parseCanonicalTime(manifest.observed_at, "delta manifest observation time");
  if (compareTime(lower, addSeconds(prior, -(manifest.overlap_seconds as number))) !== 0 || compareTime(prior, watermark) > 0 || compareTime(watermark, addSeconds(observed, manifest.max_future_skew_seconds as number)) > 0) throw new DeltaError("delta manifest watermarks are inconsistent");
  return manifest;
}
function commitCheckpoint(path: string, fingerprint: string, manifest: JsonObject): void {
  writeAtomicJson(path, { version: CHECKPOINT_VERSION, source_fingerprint: fingerprint, sequence: manifest.sequence, watermark_completed_at: manifest.watermark_completed_at,
    last_output_sha256: manifest.output_sha256, last_output_records: manifest.record_count, last_source_records: manifest.source_records_after,
    session_projection_protocol: manifest.session_projection_protocol ?? LEGACY_PROJECTION_PROTOCOL, source_ingest_fence: manifest.source_ingest_fence ?? null });
}
async function resumeOutput(output: string, pending: string, manifestPath: string, checkpointPath: string, checkpoint: JsonObject | undefined, fingerprint: string): Promise<JsonObject> {
  const manifest = validateManifest(readStrictFile(manifestPath, "delta manifest"), fingerprint, output);
  const priorSequence = checkpoint === undefined ? 0 : checkpoint.sequence as number;
  let isNext = manifest.sequence === priorSequence + 1;
  if (isNext && checkpoint !== undefined) isNext = manifest.prior_watermark_completed_at === checkpoint.watermark_completed_at && manifest.prior_output_sha256 === checkpoint.last_output_sha256 && manifest.prior_source_ingest_fence === checkpoint.source_ingest_fence;
  else if (isNext) isNext = manifest.prior_output_sha256 === null && manifest.prior_source_ingest_fence === null;
  const committed = checkpoint !== undefined && manifest.sequence === checkpoint.sequence && manifest.output_sha256 === checkpoint.last_output_sha256 && manifest.record_count === checkpoint.last_output_records && manifest.source_ingest_fence === checkpoint.source_ingest_fence;
  if (!isNext && !committed) throw new DeltaError("delta manifest is not the next checkpoint transition");
  if (existsSync(output) && existsSync(pending)) throw new DeltaError("both final and pending delta outputs exist");
  const selected = existsSync(output) ? output : pending; ensurePrivateRegular(selected, "delta output");
  const [size, digest] = await fileDigest(selected);
  if (size !== manifest.output_size_bytes || digest !== manifest.output_sha256) throw new DeltaError("delta output does not match its manifest");
  if (selected === pending) { renameSync(pending, output); fsyncDirectory(dirname(output)); }
  if (isNext) commitCheckpoint(checkpointPath, fingerprint, manifest);
  return manifest;
}

export function selectionDigest(sessions: SessionSummary[]): string {
  const stable = sessions.map((item) => item.deleted === true
    ? ({ last_at: formatTime(parseTime(item.last_at, "source session last_at")), requests: 0, session_id: item.session_id, deleted: true, deleted_at: formatTime(parseTime(item.deleted_at, "source session deleted_at")) })
    : ({ first_at: formatTime(parseTime(item.first_at, "source session first_at")), last_at: formatTime(parseTime(item.last_at, "source session last_at")), ...(item.records_sha256 === undefined ? {} : { records_sha256: item.records_sha256 }), requests: item.requests, session_id: item.session_id }));
  stable.sort((left, right) => compareUtf8Bytewise(left.session_id, right.session_id));
  return sha256Bytes(JSON.stringify(stable));
}
async function loadProjection(client: SourceClient, lower: Time, limit: number, sourceRecords: number, snapshot?: string, fence?: string): Promise<Projection> {
  if (snapshot !== undefined) return client.stableSessions(limit, lower, snapshot, fence);
  if (fence !== undefined) return client.stableSessions(limit, lower, undefined, fence);
  try { return await client.stableSessions(limit, lower); }
  catch (error) { if (!(error instanceof StableCursorUnsupported)) throw error; if (client.collectorDirect) throw new DeltaError(`collector does not implement ${STABLE_CURSOR_PROTOCOL}`); }
  const legacy = await client.sessions(limit);
  if (legacy.length < limit && legacy.reduce((sum, item) => sum + item.requests, 0) !== sourceRecords) throw new DeltaError("source record count disagrees with the complete session projection");
  const selected = legacy.filter((item) => compareTime(parseTime(item.last_at, "source session last_at"), lower) >= 0);
  if (legacy.length === limit && compareTime(parseTime(legacy.at(-1)!.last_at, "source session last_at"), lower) >= 0) throw new DeltaError(`source session projection is saturated and does not implement ${STABLE_CURSOR_PROTOCOL}`);
  return { sessions: selected, protocol: LEGACY_PROJECTION_PROTOCOL, requestCount: selected.reduce((sum, item) => sum + item.requests, 0), deletedSessionCount: 0 };
}
function verifyClock(sessions: SessionSummary[], maximum: Time): void {
  for (const item of sessions) if ((item.first_at !== undefined && compareTime(parseTime(item.first_at, "source session first_at"), maximum) > 0) || compareTime(parseTime(item.last_at, "source session last_at"), maximum) > 0) throw new DeltaError("source session timestamp exceeds the future-skew limit");
}

type RecoveredLegacySession = Readonly<{ sessionId: string; requests: number; recordsSha256: string; canonicalBytes: number }>;
type LegacySpoolRecovery = Readonly<{
  database: DatabaseSync;
  sessions: readonly RecoveredLegacySession[];
  reusedRecords: number;
  reusedCanonicalBytes: number;
  remainingSessions: number;
  remainingRecords: number;
}>;

function legacySpoolSchema(database: DatabaseSync): void {
  const tables = database.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all() as Array<{ name: string }>;
  if (tables.length !== 1 || tables[0]?.name !== "records") throw new DeltaError("legacy archive spool does not match the 3612 records-only schema");
  const columns = database.prepare("PRAGMA table_info(records)").all() as Array<{ name: string; type: string; notnull: number; pk: number }>;
  const expected = [
    ["request_id", "TEXT", 1, 1], ["session_id", "TEXT", 1, 0], ["started_at", "TEXT", 1, 0], ["completed_at", "TEXT", 1, 0],
    ["digest", "TEXT", 1, 0], ["canonical", "BLOB", 1, 0], ["emit", "INTEGER", 1, 0],
  ] as const;
  if (columns.length !== expected.length || columns.some((column, index) => column.name !== expected[index]![0] || column.type !== expected[index]![1] || column.notnull !== expected[index]![2] || column.pk !== expected[index]![3])) {
    throw new DeltaError("legacy archive spool does not match the 3612 records-only schema");
  }
}

/**
 * The 3612 exporter kept only a per-record spool. Its successful sessions are
 * recoverable only when a fresh stable source projection supplies the exact
 * per-session count and digest. This opens that historical file read-only and
 * never adds PR8 metadata to it; the caller creates a separate PR8 spool after
 * every candidate has been verified.
 */
function inspectLegacySpool(path: string, projection: Projection): LegacySpoolRecovery {
  if (!isAbsolute(path) || path !== resolve(path) || !LEGACY_SPOOL_BASENAME.test(basename(path))) throw new DeltaError("legacy archive spool path does not match the 3612 random-spool contract");
  ensurePrivateSpoolFile(path, "legacy archive spool");
  for (const sidecar of archiveSpoolSidecars(path)) if (existsSync(sidecar)) throw new DeltaError("legacy archive spool has unsealed SQLite sidecars");
  if (projection.protocol !== STABLE_CURSOR_PROTOCOL) throw new DeltaError("legacy archive spool recovery requires a stable source projection");
  const source = new Map<string, SessionSummary>();
  for (const session of projection.sessions) {
    if (session.deleted === true || session.records_sha256 === undefined) continue;
    if (source.has(session.session_id)) throw new DeltaError("stable source projection contains duplicate session identities");
    source.set(session.session_id, session);
  }
  let database: DatabaseSync | undefined;
  try {
    database = new DatabaseSync(path, { readOnly: true });
    const integrity = database.prepare("PRAGMA integrity_check").get() as Record<string, unknown> | undefined;
    if (integrity === undefined || Object.values(integrity)[0] !== "ok") throw new DeltaError("legacy archive spool failed its integrity check");
    legacySpoolSchema(database);
    const sessions: RecoveredLegacySession[] = [];
    let currentId: string | undefined, currentCount = 0, currentBytes = 0, currentDigest = createHash("sha256");
    const complete = (): void => {
      if (currentId === undefined) return;
      const summary = source.get(currentId);
      if (summary === undefined) throw new DeltaError("legacy archive spool contains a session absent from the stable source projection");
      const digest = currentDigest.digest("hex");
      if (currentCount === summary.requests && digest === summary.records_sha256) sessions.push({ sessionId: currentId, requests: currentCount, recordsSha256: digest, canonicalBytes: currentBytes });
    };
    const rows = database.prepare("SELECT request_id,session_id,started_at,completed_at,digest,canonical,emit FROM records ORDER BY session_id COLLATE BINARY,request_id COLLATE BINARY");
    for (const row of rows.iterate() as Iterable<{ request_id: string; session_id: string; started_at: string; completed_at: string; digest: string; canonical: Uint8Array; emit: number }>) {
      if (currentId !== undefined && currentId !== row.session_id) { complete(); currentCount = 0; currentBytes = 0; currentDigest = createHash("sha256"); }
      currentId = row.session_id;
      const canonical = Buffer.from(row.canonical); let record: unknown;
      try { record = parseStrictJson(canonical.toString("utf8")); } catch { throw new DeltaError("legacy archive spool record content failed verification"); }
      if (!isObject(record) || row.emit !== 1 || record.request_id !== row.request_id || record.session_id !== row.session_id || record.started_at !== row.started_at || record.completed_at !== row.completed_at || row.digest !== sha256Bytes(canonical)) {
        throw new DeltaError("legacy archive spool record content failed verification");
      }
      parseCanonicalTime(row.started_at, "legacy archive spool started_at"); parseCanonicalTime(row.completed_at, "legacy archive spool completed_at");
      currentDigest.update(canonical); currentCount += 1; currentBytes += canonical.length;
    }
    complete();
    if (sessions.length === 0) throw new DeltaError("legacy archive spool contains no source-verified completed sessions");
    const reusedRecords = sessions.reduce((sum, session) => sum + session.requests, 0);
    const reusedCanonicalBytes = sessions.reduce((sum, session) => sum + session.canonicalBytes, 0);
    const projectionSessions = [...source.values()];
    return { database, sessions, reusedRecords, reusedCanonicalBytes,
      remainingSessions: projectionSessions.length - sessions.length,
      remainingRecords: projectionSessions.reduce((sum, session) => sum + session.requests, 0) - reusedRecords };
  } catch (error) {
    database?.close();
    throw error;
  }
}

function seedRecoveredLegacySessions(target: DatabaseSync, recovery: LegacySpoolRecovery): void {
  const insertRecord = target.prepare("INSERT INTO records VALUES(?,?,?,?,?,?,?)");
  const markSessionCompleted = target.prepare("INSERT INTO completed_sessions(session_id,requests,records_sha256,downloaded_bytes) VALUES(?,?,?,?)");
  const legacyRows = recovery.database.prepare("SELECT request_id,session_id,started_at,completed_at,digest,canonical,emit FROM records WHERE session_id=? ORDER BY request_id COLLATE BINARY");
  target.exec("BEGIN IMMEDIATE");
  try {
    for (const session of recovery.sessions) {
      let copied = 0, copiedBytes = 0;
      for (const row of legacyRows.iterate(session.sessionId) as Iterable<{ request_id: string; session_id: string; started_at: string; completed_at: string; digest: string; canonical: Uint8Array; emit: number }>) {
        const canonical = Buffer.from(row.canonical);
        insertRecord.run(row.request_id, row.session_id, row.started_at, row.completed_at, row.digest, canonical, row.emit);
        copied += 1; copiedBytes += canonical.length;
      }
      if (copied !== session.requests || copiedBytes !== session.canonicalBytes) throw new DeltaError("legacy archive spool changed while it was being recovered");
      markSessionCompleted.run(session.sessionId, session.requests, session.recordsSha256, session.canonicalBytes);
    }
    target.exec("COMMIT"); target.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  } catch (error) {
    try { target.exec("ROLLBACK"); } catch { /* the caller will close the target spool */ }
    throw error;
  }
}

type Arguments = {
  baseUrl: string; downloadBaseUrl?: string; tokenFile?: string; tokenEnv?: string; checkpoint: string; output: string;
  collectorDirect: boolean; offlineFull: boolean; privateHttpHosts: string[]; clientCertFile?: string; clientKeyFile?: string; since?: string;
  overlapSeconds: number; sessionLimit: number; maxLineBytes: number; maxDownloadBytes: number; maxOutputBytes: number; timeoutSeconds: number;
  maxElapsedSeconds: number; readinessTimeoutSeconds: number; readinessPollMilliseconds: number; maxRetries: number; retryBaseSeconds: number;
  maxFutureSkewSeconds: number; requireStableSource: boolean; allowHttp: boolean; resume: boolean; legacySpool?: string; sourceSqlite?: string;
  chunkRecords: number; chunkBytes: number; chunkSeconds: number; maxChunks: number; deadline: number;
};

async function exportDelta(args: Arguments, internalResume = false): Promise<JsonObject> {
  const token = args.collectorDirect ? undefined : args.tokenFile !== undefined ? loadToken(args.tokenFile) : loadTokenEnv(args.tokenEnv!);
  const hosts = new Set(args.privateHttpHosts.map(normalizeHost));
  let tls: TlsFiles | undefined;
  if (args.clientCertFile !== undefined && args.clientKeyFile !== undefined) {
    const certificate = lstatSync(args.clientCertFile); if (certificate.isSymbolicLink() || !certificate.isFile()) throw new DeltaError("mTLS certificate must be a regular non-symlink file");
    ensurePrivateRegular(args.clientKeyFile, "mTLS private key"); tls = { cert: readFileSync(args.clientCertFile), key: readFileSync(args.clientKeyFile) };
  }
  const diagnostics = args.collectorDirect ? (message: string) => process.stderr.write(`${message}\n`) : undefined;
  const client = new SourceClient(args.baseUrl, args.downloadBaseUrl ?? args.baseUrl, token, args.timeoutSeconds, args.allowHttp, hosts, args.collectorDirect, args.maxRetries, args.retryBaseSeconds, args.deadline, tls, args.maxDownloadBytes, args.offlineFull, diagnostics);
  const localSource = args.sourceSqlite === undefined ? undefined : new SQLiteArchiveSource(args.sourceSqlite);
  const fingerprint = sourceFingerprint(client); const checkpoint = loadCheckpoint(args.checkpoint, fingerprint);
  const manifestPath = `${args.output}.manifest.json`; const pending = `${args.output}.pending`; const spoolPath = `${args.output}.spool.sqlite`;
  if (args.legacySpool !== undefined && (checkpoint !== undefined || !args.collectorDirect || !args.offlineFull || !args.resume || args.since === undefined)) {
    throw new DeltaError("legacy archive spool recovery requires --resume, --collector-direct, --offline-full, --since, and no checkpoint");
  }
  if (localSource !== undefined && (checkpoint !== undefined || !args.collectorDirect || !args.offlineFull || args.since === undefined)) {
    localSource.close();
    throw new DeltaError("source SQLite snapshots are only valid for the first collector-direct offline-full export");
  }
  if (args.resume) {
    if (existsSync(pending) && !existsSync(manifestPath) && !existsSync(args.output)) { ensurePrivateRegular(pending, "orphaned pending delta output"); unlinkSync(pending); fsyncDirectory(dirname(pending)); }
    else if (existsSync(args.output) || existsSync(pending) || existsSync(manifestPath)) {
      const manifest = await resumeOutput(args.output, pending, manifestPath, args.checkpoint, checkpoint, fingerprint);
      if (archiveSpoolExists(spoolPath)) removeArchiveSpool(spoolPath);
      return manifest;
    }
  }
  if (existsSync(args.output) || existsSync(pending) || existsSync(manifestPath)) throw new DeltaError("delta output, pending file, or manifest already exists; use --resume or a new path");
  let prior: Time, priorFence: string | undefined, sequence: number;
  if (checkpoint === undefined) { if (args.since === undefined) throw new DeltaError("--since is required before the first checkpoint"); prior = parseTime(args.since, "initial since watermark"); sequence = 1; }
  else { if (args.since !== undefined) throw new DeltaError("--since cannot replace an existing checkpoint"); prior = parseTime(checkpoint.watermark_completed_at, "checkpoint watermark"); priorFence = checkpoint.source_ingest_fence === null ? undefined : checkpoint.source_ingest_fence as string | undefined; sequence = (checkpoint.sequence as number) + 1; }
  const initialCollectorSnapshot = args.collectorDirect && priorFence === undefined;
  if (initialCollectorSnapshot) { if (!args.offlineFull) throw new DeltaError("the first collector-direct snapshot requires --offline-full"); }
  else if (args.offlineFull) throw new DeltaError("--offline-full is only valid for the first collector-direct snapshot");
  const lower = addSeconds(prior, -args.overlapSeconds); const observed: Time = { nanos: BigInt(Date.now()) * 1_000_000n }; const maximum = addSeconds(observed, args.maxFutureSkewSeconds);
  if (compareTime(prior, maximum) > 0) throw new DeltaError("source checkpoint timestamp exceeds the future-skew limit");
  if (localSource === undefined && !args.allowHttp) for (const host of hosts) if (!await verifyPrivateHost(host, hosts)) throw new DeltaError("private HTTP host allowlist did not resolve exclusively to private addresses");
  if (args.collectorDirect && localSource === undefined) await client.waitUntilReady(args.readinessTimeoutSeconds, args.readinessPollMilliseconds);
  if (initialCollectorSnapshot && localSource === undefined) await client.verifyOfflineFull();
  const before = localSource?.statsRecords() ?? await client.statsRecords();
  if (checkpoint !== undefined && before < (checkpoint.last_source_records as number)) throw new DeltaError("source record count moved backwards since the checkpoint");
  const first = localSource?.stableProjection() ?? await loadProjection(client, lower, args.sessionLimit, before, undefined, priorFence); verifyClock(first.sessions, maximum); const firstDigest = selectionDigest(first.sessions);
  const legacyRecovery = args.legacySpool === undefined ? undefined : inspectLegacySpool(args.legacySpool, first);
  mkdirSync(dirname(args.output), { recursive: true, mode: 0o700 });
  let database: DatabaseSync | undefined; let outputTemporary: string | undefined; let completed = false; let spoolTransactionOpen = false;
  const seededLegacySessions = new Set<string>();
  let retainSpoolOnFailure = existsSync(spoolPath) || first.protocol === STABLE_CURSOR_PROTOCOL;
  let maximumCompleted = prior; let maximumStarted: Time | undefined;
  try {
    let spool = openArchiveSpool(spoolPath, args.resume || internalResume); database = spool.database; database.exec(ARCHIVE_SPOOL_SCHEMA);
    const spoolDescriptor = canonicalize({ version: 1, source_fingerprint: fingerprint, sequence, prior_watermark_completed_at: formatTime(prior),
      prior_source_ingest_fence: priorFence ?? null, lower_bound_completed_at: formatTime(lower), session_projection_protocol: first.protocol,
      source_projection_requests: first.requestCount, session_count: first.sessions.length, session_set_sha256: firstDigest,
      snapshot_schema_version: first.snapshotSchemaVersion ?? null, deleted_session_count: first.deletedSessionCount,
      offline_full_snapshot: args.offlineFull, max_line_bytes: args.maxLineBytes, max_future_skew_seconds: args.maxFutureSkewSeconds,
      max_download_bytes: args.maxDownloadBytes, max_output_bytes: args.maxOutputBytes, stable_source_required: args.requireStableSource });
    let existingDescriptor = database.prepare("SELECT descriptor_json FROM spool_metadata WHERE id=1").get() as { descriptor_json: string } | undefined;
    if (existingDescriptor === undefined && spool.resumed) {
      const counts = database.prepare("SELECT (SELECT COUNT(*) FROM records) AS records,(SELECT COUNT(*) FROM completed_sessions) AS sessions").get() as { records: number; sessions: number };
      if (counts.records !== 0 || counts.sessions !== 0) throw new DeltaError("incomplete archive spool is missing its versioned descriptor");
      database.close(); database = undefined; removeArchiveSpool(spoolPath);
      spool = openArchiveSpool(spoolPath, false); database = spool.database; database.exec(ARCHIVE_SPOOL_SCHEMA);
      existingDescriptor = undefined;
    }
    if (existingDescriptor === undefined) database.prepare("INSERT INTO spool_metadata(id,descriptor_json) VALUES(1,?)").run(spoolDescriptor);
    else if (existingDescriptor.descriptor_json !== spoolDescriptor) throw new DeltaError("incomplete archive spool does not match the current source projection");
    if (legacyRecovery !== undefined) {
      if (!spool.resumed) {
        seedRecoveredLegacySessions(database, legacyRecovery);
        for (const session of legacyRecovery.sessions) seededLegacySessions.add(session.sessionId);
      }
    }
    if (spool.resumed && first.protocol === LEGACY_PROJECTION_PROTOCOL) {
      const discarded = (database.prepare("SELECT COUNT(*) AS records FROM records").get() as { records: number }).records;
      database.close(); database = undefined; removeArchiveSpool(spoolPath);
      spool = openArchiveSpool(spoolPath, false); database = spool.database; database.exec(ARCHIVE_SPOOL_SCHEMA);
      database.prepare("INSERT INTO spool_metadata(id,descriptor_json) VALUES(1,?)").run(spoolDescriptor);
      retainSpoolOnFailure = false;
      process.stderr.write(`archive spool resume legacy_rebuild=true records_discarded=${discarded}\n`);
    }
    const orphaned = (database.prepare("SELECT COUNT(*) AS records FROM records WHERE session_id NOT IN (SELECT session_id FROM completed_sessions UNION SELECT session_id FROM session_progress)").get() as { records: number }).records;
    if (orphaned !== 0) throw new DeltaError("incomplete archive spool contains an unverified session");
    const seen = database.prepare("SELECT session_id, digest FROM records WHERE request_id=?");
    const addRecord = database.prepare("INSERT INTO records VALUES(?,?,?,?,?,?,?)");
    const completedSession = database.prepare("SELECT requests,records_sha256 FROM completed_sessions WHERE session_id=?");
    const markSessionCompleted = database.prepare("INSERT INTO completed_sessions(session_id,requests,records_sha256,downloaded_bytes) VALUES(?,?,?,?)");
    const sessionProgress = database.prepare("SELECT requests,records_sha256,record_cursor,staged_records,staged_bytes,downloaded_bytes,chunks FROM session_progress WHERE session_id=?");
    const saveSessionProgress = database.prepare(`INSERT INTO session_progress(session_id,requests,records_sha256,record_cursor,staged_records,staged_bytes,downloaded_bytes,chunks)
      VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET record_cursor=excluded.record_cursor,staged_records=excluded.staged_records,
      staged_bytes=excluded.staged_bytes,downloaded_bytes=excluded.downloaded_bytes,chunks=excluded.chunks`);
    const clearSessionProgress = database.prepare("DELETE FROM session_progress WHERE session_id=?");
    let selectedBytes = (database.prepare("SELECT COALESCE(SUM(length(canonical)),0) AS bytes FROM records WHERE emit=1").get() as { bytes: number }).bytes;
    if (selectedBytes > args.maxOutputBytes) throw new DeltaError("delta output exceeds the configured size limit");
    client.downloadedBytes = (database.prepare("SELECT COALESCE((SELECT SUM(downloaded_bytes) FROM completed_sessions),0)+COALESCE((SELECT SUM(downloaded_bytes) FROM session_progress),0) AS bytes").get() as { bytes: number }).bytes;
    if (client.downloadedBytes > args.maxDownloadBytes) throw new DeltaError("source archive downloads exceed the configured limit");
    const beginSpoolTransaction = (): void => { if (!spoolTransactionOpen) { database!.exec("BEGIN IMMEDIATE"); spoolTransactionOpen = true; } };
    const commitSpoolTransaction = (): void => { if (spoolTransactionOpen) { database!.exec("COMMIT"); spoolTransactionOpen = false; } };
    if (seededLegacySessions.size !== 0 && legacyRecovery !== undefined) {
      process.stderr.write(`archive legacy spool recovery reused_sessions=${legacyRecovery.sessions.length} reused_records=${legacyRecovery.reusedRecords} reused_canonical_bytes=${legacyRecovery.reusedCanonicalBytes} remaining_sessions=${legacyRecovery.remainingSessions} remaining_records=${legacyRecovery.remainingRecords}\n`);
    }
    if (spool.resumed) {
      const counts = database.prepare("SELECT (SELECT COUNT(*) FROM completed_sessions) AS sessions,(SELECT COUNT(*) FROM session_progress) AS partial_sessions,(SELECT COUNT(*) FROM records) AS records").get() as { sessions: number; partial_sessions: number; records: number };
      process.stderr.write(`archive spool resume completed_sessions=${counts.sessions} records=${counts.records} partial_sessions=${counts.partial_sessions}\n`);
    }
    let invocationChunks = 0;
    for (const session of [...first.sessions].sort((left, right) => compareUtf8Bytewise(left.session_id, right.session_id))) {
      if (session.deleted === true) {
        const deletedAt = parseTime(session.deleted_at, "source session deleted_at");
        if (compareTime(deletedAt, maximumCompleted) > 0) maximumCompleted = deletedAt;
        continue;
      }
      const priorSession = first.protocol === STABLE_CURSOR_PROTOCOL ? completedSession.get(session.session_id) as { requests: number; records_sha256: string } | undefined : undefined;
      if (priorSession !== undefined) {
        if (priorSession.requests !== session.requests || priorSession.records_sha256 !== session.records_sha256) throw new DeltaError("incomplete archive spool session metadata changed");
        // The recovery bridge just verified the source spool's canonical rows,
        // then copied them in one transaction. Avoid another full local blob
        // pass here; a later invocation uses the ordinary PR8 re-verification.
        if (seededLegacySessions.has(session.session_id)) continue;
        const verified = database.prepare("SELECT COUNT(*) AS records,COALESCE(MIN(emit),0) AS all_emit FROM records WHERE session_id=?").get(session.session_id) as { records: number; all_emit: number };
        if (verified.records !== session.requests || verified.all_emit !== 1) throw new DeltaError("incomplete archive spool session content failed verification");
        continue;
      }
      const progress = first.protocol === STABLE_CURSOR_PROTOCOL ? sessionProgress.get(session.session_id) as {
        requests: number; records_sha256: string; record_cursor: string; staged_records: number; staged_bytes: number; downloaded_bytes: number; chunks: number;
      } | undefined : undefined;
      if (progress !== undefined && (progress.requests !== session.requests || progress.records_sha256 !== session.records_sha256)) throw new DeltaError("incomplete archive spool partial session metadata changed");
      if (progress !== undefined) {
        const staged = database.prepare("SELECT COUNT(*) AS records,COALESCE(MAX(request_id),'') AS cursor,COALESCE(SUM(length(canonical)),0) AS bytes FROM records WHERE session_id=?").get(session.session_id) as { records: number; cursor: string; bytes: number };
        if (staged.records !== progress.staged_records || staged.cursor !== progress.record_cursor || staged.bytes !== progress.staged_bytes || staged.records > session.requests) {
          throw new DeltaError("incomplete archive spool partial session checkpoint is invalid");
        }
      }
      let exported = progress?.staged_records ?? 0;
      let stagedBytes = progress?.staged_bytes ?? 0;
      let cursor = progress?.record_cursor;
      let chunks = progress?.chunks ?? 0;
      const resumeCursor = cursor;
      const resumedRecords = exported;
      const downloadedBeforeAttempt = client.downloadedBytes;
      const priorDownloaded = progress?.downloaded_bytes ?? 0;
      let skippedForHttpResume = 0;
      let foundHttpCursor = resumeCursor === undefined;
      let chunkRecords = 0, chunkBytes = 0, chunkStartedAt = performance.now();
      beginSpoolTransaction();
      const lines = localSource === undefined
        ? client.exportLines(session.session_id, args.maxLineBytes, first.snapshot, session.records_sha256)
        : localSource.exportLines(session.session_id, args.maxLineBytes, resumeCursor);
      for await (const rawLine of lines) {
        if (localSource !== undefined) {
          client.downloadedBytes += Buffer.byteLength(rawLine);
          if (client.downloadedBytes > args.maxDownloadBytes) throw new DeltaError("source archive downloads exceed the configured limit");
        }
        let item: unknown; try { item = parseStrictJson(rawLine); } catch { throw new DeltaError("source archive stream contains invalid JSON"); }
        if (!isObject(item) || ![1, 2].includes(item.schema_version as number)) throw new DeltaError("source archive record schema is unsupported");
        if (typeof item.request_id !== "string" || item.request_id.length === 0) throw new DeltaError("source archive request identity is invalid");
        const requestId = item.request_id;
        if (item.session_id !== session.session_id) throw new DeltaError("source session export returned a foreign session record");
        if (first.protocol === STABLE_CURSOR_PROTOCOL && resumeCursor !== undefined && localSource === undefined && compareUtf8Bytewise(requestId, resumeCursor) <= 0) {
          skippedForHttpResume += 1;
          if (requestId === resumeCursor) foundHttpCursor = true;
          continue;
        }
        if (first.protocol === STABLE_CURSOR_PROTOCOL && cursor !== undefined && compareUtf8Bytewise(requestId, cursor) <= 0) throw new DeltaError("source stable session records are not in request-id cursor order");
        if (resumeCursor !== undefined && localSource === undefined && (!foundHttpCursor || skippedForHttpResume !== resumedRecords)) throw new DeltaError("source stable session resume cursor could not be replayed");
        let record = item;
        const started = parseTime(item.started_at, "archive started_at"), completed = parseTime(item.completed_at, "archive completed_at");
        if (compareTime(completed, started) < 0) throw new DeltaError("source archive record time range is invalid");
        if (compareTime(started, maximum) > 0 || compareTime(completed, maximum) > 0) throw new DeltaError("source archive timestamp exceeds the future-skew limit");
        if (first.protocol === STABLE_CURSOR_PROTOCOL && (item.started_at !== formatTime(started) || item.completed_at !== formatTime(completed))) throw new DeltaError("source stable archive timestamps are not canonical");
        if (first.protocol === LEGACY_PROJECTION_PROTOCOL) {
          record = { ...item, started_at: formatTime(started), completed_at: formatTime(completed) };
        }
        const encoded = Buffer.concat([canonicalBytes(record), Buffer.from("\n")]); const digest = sha256Bytes(encoded);
        const existing = seen.get(requestId) as { session_id: string; digest: string } | undefined;
        if (existing !== undefined) { if (existing.session_id !== session.session_id || existing.digest !== digest) throw new DeltaError("one source request id has conflicting archive records"); continue; }
        const emit = first.protocol !== LEGACY_PROJECTION_PROTOCOL || compareTime(started, lower) >= 0 || compareTime(completed, lower) >= 0;
        if (emit) {
          selectedBytes += encoded.length;
          if (selectedBytes > args.maxOutputBytes) throw new DeltaError("delta output exceeds the configured size limit");
        }
        addRecord.run(requestId, session.session_id, formatTime(started), formatTime(completed), digest, encoded, emit ? 1 : 0); exported += 1; stagedBytes += encoded.length; cursor = requestId;
        chunkRecords += 1; chunkBytes += encoded.length;
        if (!emit) continue;
        if (compareTime(completed, maximumCompleted) > 0) maximumCompleted = completed;
        if (maximumStarted === undefined || compareTime(started, maximumStarted) > 0) maximumStarted = started;
        if (first.protocol === STABLE_CURSOR_PROTOCOL && (chunkRecords >= args.chunkRecords || chunkBytes >= args.chunkBytes || performance.now() - chunkStartedAt >= args.chunkSeconds * 1000)) {
          chunks += 1;
          saveSessionProgress.run(session.session_id, session.requests, session.records_sha256!, cursor, exported, stagedBytes,
            priorDownloaded + client.downloadedBytes - downloadedBeforeAttempt, chunks);
          commitSpoolTransaction(); database.exec("PRAGMA wal_checkpoint(TRUNCATE)"); invocationChunks += 1;
          if (args.maxChunks !== 0 && invocationChunks >= args.maxChunks) throw new DeltaError("archive session chunk budget reached; rerun the same command with --resume");
          if (performance.now() >= args.deadline) throw new DeltaError("source export exceeded the configured elapsed-time limit; rerun the same command with --resume");
          beginSpoolTransaction(); chunkRecords = 0; chunkBytes = 0; chunkStartedAt = performance.now();
        }
      }
      if (resumeCursor !== undefined && localSource === undefined && (!foundHttpCursor || skippedForHttpResume !== resumedRecords)) throw new DeltaError("source stable session resume cursor could not be replayed");
      if (exported !== session.requests) throw new DeltaError("source session export count disagrees with its session summary");
      if (first.protocol === STABLE_CURSOR_PROTOCOL) {
        const digest = createHash("sha256");
        for (const row of database.prepare("SELECT canonical FROM records WHERE session_id=? ORDER BY request_id COLLATE BINARY").iterate(session.session_id) as Iterable<{ canonical: Uint8Array }>) digest.update(row.canonical);
        if (digest.digest("hex") !== session.records_sha256) throw new DeltaError("source session export digest disagrees with its stable summary");
      }
      if (first.protocol === STABLE_CURSOR_PROTOCOL) {
        clearSessionProgress.run(session.session_id);
        markSessionCompleted.run(session.session_id, session.requests, session.records_sha256!, priorDownloaded + client.downloadedBytes - downloadedBeforeAttempt);
      }
      commitSpoolTransaction();
      database.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    }
    const spoolWatermarks = database.prepare("SELECT MAX(completed_at) AS completed_at,MAX(started_at) AS started_at FROM records WHERE emit=1").get() as { completed_at: string | null; started_at: string | null };
    if (spoolWatermarks.completed_at !== null) {
      const value = parseCanonicalTime(spoolWatermarks.completed_at, "archive spool maximum completed_at");
      if (compareTime(value, maximumCompleted) > 0) maximumCompleted = value;
    }
    if (spoolWatermarks.started_at !== null) maximumStarted = parseCanonicalTime(spoolWatermarks.started_at, "archive spool maximum started_at");
    const afterExport = localSource?.statsRecords() ?? await client.statsRecords(); if (args.requireStableSource && afterExport !== before) throw new DeltaError("source record count changed despite the requested write barrier");
    const second = localSource?.stableProjection() ?? await loadProjection(client, lower, args.sessionLimit, afterExport, first.snapshot, priorFence); verifyClock(second.sessions, maximum);
    if (second.protocol !== first.protocol || second.requestCount !== first.requestCount || selectionDigest(second.sessions) !== firstDigest) throw new DeltaError("source session projection changed during delta export; retry");
    const after = localSource?.statsRecords() ?? await client.statsRecords(); if (args.requireStableSource && after !== before) throw new DeltaError("source record count changed despite the requested write barrier"); if (after < before) throw new DeltaError("source record count decreased during delta export");
    outputTemporary = join(dirname(args.output), `.${basename(args.output)}.${process.pid}.${Date.now()}`); const descriptor = openSync(outputTemporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    const outputDigest = createHash("sha256"); let outputSize = 0, recordCount = 0;
    try {
      if (first.snapshotSchemaVersion === 2) {
        for (const session of [...first.sessions].sort((left, right) => compareUtf8Bytewise(left.session_id, right.session_id))) {
          const summary = session.deleted === true
            ? { _mtc_delta_type: "session_summary", schema_version: 2, session_id: session.session_id, requests: 0, last_at: session.last_at, deleted: true, deleted_at: session.deleted_at }
            : { _mtc_delta_type: "session_summary", schema_version: 2, session_id: session.session_id, requests: session.requests, first_at: session.first_at, last_at: session.last_at, records_sha256: session.records_sha256 };
          const summaryBytes = Buffer.concat([canonicalBytes(summary), Buffer.from("\n")]);
          if (outputSize + summaryBytes.length > args.maxOutputBytes) throw new DeltaError("delta output exceeds the configured size limit");
          writeFileSync(descriptor, summaryBytes); outputDigest.update(summaryBytes); outputSize += summaryBytes.length;
          if (session.deleted !== true) {
            for (const row of database.prepare("SELECT canonical FROM records WHERE session_id=? ORDER BY request_id COLLATE BINARY").iterate(session.session_id) as Iterable<{ canonical: Uint8Array }>) {
              const bytes = Buffer.from(row.canonical);
              if (outputSize + bytes.length > args.maxOutputBytes) throw new DeltaError("delta output exceeds the configured size limit");
              writeFileSync(descriptor, bytes); outputDigest.update(bytes); outputSize += bytes.length; recordCount += 1;
            }
          }
        }
      } else {
        for (const row of database.prepare("SELECT canonical FROM records WHERE emit=1 ORDER BY started_at, request_id COLLATE BINARY").iterate() as Iterable<{ canonical: Uint8Array }>) { const bytes = Buffer.from(row.canonical); writeFileSync(descriptor, bytes); outputDigest.update(bytes); outputSize += bytes.length; recordCount += 1; }
      }
      fsyncSync(descriptor);
    } finally { closeSync(descriptor); }
    renameSync(outputTemporary, pending); outputTemporary = undefined; fsyncDirectory(dirname(args.output));
    const manifest: JsonObject = { version: MANIFEST_VERSION, source_fingerprint: fingerprint, observed_at: formatTime(observed), max_future_skew_seconds: args.maxFutureSkewSeconds,
      sequence, prior_watermark_completed_at: formatTime(prior), prior_output_sha256: checkpoint?.last_output_sha256 ?? null, lower_bound_completed_at: formatTime(lower), overlap_seconds: args.overlapSeconds,
      watermark_completed_at: formatTime(maximumCompleted), max_started_at: maximumStarted === undefined ? null : formatTime(maximumStarted), session_limit: args.sessionLimit, session_count: first.sessions.length,
      session_projection_protocol: first.protocol, source_mode: client.paths.mode, source_read_mode: localSource === undefined ? "http-ticket" : "sqlite-snapshot", offline_full_snapshot: args.offlineFull, source_projection_requests: first.requestCount,
      session_chunk_records: args.chunkRecords, session_chunk_bytes: args.chunkBytes, session_chunk_seconds: args.chunkSeconds,
      source_snapshot_sha256: first.snapshot === undefined ? null : sha256Bytes(first.snapshot), prior_source_ingest_fence: priorFence ?? null, source_ingest_fence: first.ingestFence ?? null,
      snapshot_schema_version: first.snapshotSchemaVersion ?? null, tombstone_safe_after_ingest_fence: first.tombstoneSafeAfterIngestFence ?? null, deleted_session_count: first.deletedSessionCount,
      session_set_sha256: firstDigest, record_count: recordCount, source_records_before: before, source_records_after: after, stable_source_required: args.requireStableSource,
      output_file: basename(args.output), output_size_bytes: outputSize, output_sha256: outputDigest.digest("hex") };
    writeAtomicJson(manifestPath, manifest); renameSync(pending, args.output); fsyncDirectory(dirname(args.output)); commitCheckpoint(args.checkpoint, fingerprint, manifest); completed = true; return manifest;
  } finally {
    if (spoolTransactionOpen) { try { database?.exec("ROLLBACK"); } catch { /* closing the database still rolls back an interrupted transaction */ } }
    try { database?.close(); legacyRecovery?.database.close(); localSource?.close(); }
    finally {
      if (completed || !retainSpoolOnFailure) removeArchiveSpool(spoolPath);
      if (outputTemporary !== undefined) rmSync(outputTemporary, { force: true });
    }
  }
}

function numberOption(values: Record<string, unknown>, key: string, fallback: number): number {
  const raw = values[key]; if (raw === undefined) return fallback; const value = Number(raw); if (!Number.isFinite(value)) throw new DeltaError(`--${key.replaceAll("_", "-")} is invalid`); return value;
}
function parseCli(argv: string[]): Arguments {
  const { values } = parseArgs({ args: argv, strict: true, allowPositionals: false, options: {
    "base-url": { type: "string" }, "download-base-url": { type: "string" }, "token-file": { type: "string" }, "token-env": { type: "string" }, checkpoint: { type: "string" }, output: { type: "string" }, "legacy-spool": { type: "string" }, "source-sqlite": { type: "string" },
    "collector-direct": { type: "boolean", default: false }, "offline-full": { type: "boolean", default: false }, "private-http-host": { type: "string", multiple: true, default: [] }, "client-cert-file": { type: "string" }, "client-key-file": { type: "string" }, since: { type: "string" },
    "overlap-seconds": { type: "string" }, "session-limit": { type: "string" }, "max-line-bytes": { type: "string" }, "max-download-bytes": { type: "string" }, "max-output-bytes": { type: "string" }, "timeout-seconds": { type: "string" }, "max-elapsed-seconds": { type: "string" },
    "readiness-timeout-seconds": { type: "string" }, "readiness-poll-milliseconds": { type: "string" }, "max-retries": { type: "string" }, "retry-base-seconds": { type: "string" }, "max-future-skew-seconds": { type: "string" },
    "chunk-records": { type: "string" }, "chunk-bytes": { type: "string" }, "chunk-seconds": { type: "string" }, "max-chunks": { type: "string" },
    "require-stable-source": { type: "boolean", default: false }, "allow-http": { type: "boolean", default: false }, resume: { type: "boolean", default: false },
  } });
  if (typeof values["base-url"] !== "string" || typeof values.checkpoint !== "string" || typeof values.output !== "string") throw new DeltaError("--base-url, --checkpoint, and --output are required");
  const args: Arguments = { baseUrl: values["base-url"], downloadBaseUrl: values["download-base-url"], tokenFile: values["token-file"], tokenEnv: values["token-env"], checkpoint: values.checkpoint, output: values.output, legacySpool: values["legacy-spool"], sourceSqlite: values["source-sqlite"],
    collectorDirect: values["collector-direct"]!, offlineFull: values["offline-full"]!, privateHttpHosts: values["private-http-host"]!, clientCertFile: values["client-cert-file"], clientKeyFile: values["client-key-file"], since: values.since,
    overlapSeconds: numberOption(values, "overlap-seconds", 86_400), sessionLimit: numberOption(values, "session-limit", 1000), maxLineBytes: numberOption(values, "max-line-bytes", 16 * 1024 * 1024), maxDownloadBytes: numberOption(values, "max-download-bytes", 64 * 1024 ** 3), maxOutputBytes: numberOption(values, "max-output-bytes", 64 * 1024 ** 3), timeoutSeconds: numberOption(values, "timeout-seconds", 60), maxElapsedSeconds: numberOption(values, "max-elapsed-seconds", 6 * 3600),
    readinessTimeoutSeconds: numberOption(values, "readiness-timeout-seconds", 900), readinessPollMilliseconds: numberOption(values, "readiness-poll-milliseconds", 1000), maxRetries: numberOption(values, "max-retries", 5), retryBaseSeconds: numberOption(values, "retry-base-seconds", 0.5), maxFutureSkewSeconds: numberOption(values, "max-future-skew-seconds", 3600), requireStableSource: values["require-stable-source"]!, allowHttp: values["allow-http"]!, resume: values.resume!,
    chunkRecords: numberOption(values, "chunk-records", 128), chunkBytes: numberOption(values, "chunk-bytes", 16 * 1024 * 1024), chunkSeconds: numberOption(values, "chunk-seconds", 30), maxChunks: numberOption(values, "max-chunks", 0), deadline: 0 };
  if (!Number.isInteger(args.overlapSeconds) || args.overlapSeconds < 1 || args.overlapSeconds > 31 * 86_400) throw new DeltaError("overlap seconds must be between one second and 31 days");
  if (!Number.isInteger(args.sessionLimit) || args.sessionLimit < 1 || args.sessionLimit > 1000) throw new DeltaError("session limit must be between 1 and 1000");
  if (!Number.isInteger(args.maxLineBytes) || args.maxLineBytes < 1024 || args.maxLineBytes > 16 * 1024 * 1024) throw new DeltaError("max line bytes must be between 1 KiB and 16 MiB");
  if (!Number.isInteger(args.maxDownloadBytes) || args.maxDownloadBytes < args.maxLineBytes || args.maxDownloadBytes > 1024 ** 4) throw new DeltaError("max download bytes must cover one line and be at most 1 TiB");
  if (!Number.isInteger(args.maxOutputBytes) || args.maxOutputBytes < args.maxLineBytes || args.maxOutputBytes > 1024 ** 4) throw new DeltaError("max output bytes must cover one line and be at most 1 TiB");
  if (args.timeoutSeconds <= 0 || args.timeoutSeconds > 3600) throw new DeltaError("timeout seconds must be between 0 and 3600");
  if (args.maxElapsedSeconds <= 0 || args.maxElapsedSeconds > 86_400) throw new DeltaError("max elapsed seconds must be between 0 and 86400");
  if (args.readinessTimeoutSeconds <= 0 || args.readinessTimeoutSeconds > 86_400) throw new DeltaError("readiness timeout seconds must be between 0 and 86400");
  if (!Number.isInteger(args.readinessPollMilliseconds) || args.readinessPollMilliseconds < 10 || args.readinessPollMilliseconds > 60_000) throw new DeltaError("readiness poll milliseconds must be between 10 and 60000");
  if (!Number.isInteger(args.maxRetries) || args.maxRetries < 0 || args.maxRetries > 20) throw new DeltaError("max retries must be between 0 and 20");
  if (args.retryBaseSeconds <= 0 || args.retryBaseSeconds > 30) throw new DeltaError("retry base seconds must be between 0 and 30");
  if (!Number.isInteger(args.maxFutureSkewSeconds) || args.maxFutureSkewSeconds < 0 || args.maxFutureSkewSeconds > 86_400) throw new DeltaError("max future skew seconds must be between 0 and 86400");
  if (!Number.isInteger(args.chunkRecords) || args.chunkRecords < 1 || args.chunkRecords > 100_000) throw new DeltaError("chunk records must be between 1 and 100000");
  if (!Number.isInteger(args.chunkBytes) || args.chunkBytes < 1024 || args.chunkBytes > 1024 ** 3) throw new DeltaError("chunk bytes must be between 1 KiB and 1 GiB");
  if (args.chunkSeconds <= 0 || args.chunkSeconds > 3600) throw new DeltaError("chunk seconds must be between 0 and 3600");
  if (!Number.isInteger(args.maxChunks) || args.maxChunks < 0 || args.maxChunks > 1_000_000) throw new DeltaError("max chunks must be between 0 and 1000000");
  if (args.offlineFull && !args.collectorDirect) throw new DeltaError("--offline-full requires --collector-direct");
  if (args.collectorDirect && (args.tokenFile !== undefined || args.tokenEnv !== undefined)) throw new DeltaError("collector-direct does not accept a CPA token");
  if (!args.collectorDirect && args.tokenFile === undefined && args.tokenEnv === undefined) throw new DeltaError("the legacy CPA plugin input requires --token-file or --token-env");
  if (args.tokenFile !== undefined && args.tokenEnv !== undefined) throw new DeltaError("--token-file and --token-env are mutually exclusive");
  if (args.collectorDirect && args.allowHttp) throw new DeltaError("collector-direct HTTP requires an exact --private-http-host allowlist");
  if (!args.collectorDirect && (values["readiness-timeout-seconds"] !== undefined || values["readiness-poll-milliseconds"] !== undefined)) throw new DeltaError("readiness options require --collector-direct");
  if (args.allowHttp && args.privateHttpHosts.length > 0) throw new DeltaError("--allow-http and --private-http-host cannot be combined");
  if ((args.clientCertFile === undefined) !== (args.clientKeyFile === undefined)) throw new DeltaError("mTLS requires both --client-cert-file and --client-key-file");
  if (args.clientCertFile !== undefined && !args.collectorDirect) throw new DeltaError("mTLS client files are only valid with --collector-direct");
  if (args.legacySpool !== undefined && (!isAbsolute(args.legacySpool) || args.legacySpool !== resolve(args.legacySpool) || !LEGACY_SPOOL_BASENAME.test(basename(args.legacySpool)))) throw new DeltaError("legacy archive spool path does not match the 3612 random-spool contract");
  if (args.sourceSqlite !== undefined && (!args.collectorDirect || !args.offlineFull)) throw new DeltaError("--source-sqlite requires --collector-direct and --offline-full");
  const normalized = args.privateHttpHosts.map(normalizeHost); if (normalized.some((item, index) => item.length === 0 || item !== args.privateHttpHosts[index])) throw new DeltaError("private HTTP host allowlist contains an invalid host");
  if (new Set(normalized).size !== normalized.length) throw new DeltaError("private HTTP host allowlist contains duplicates");
  args.deadline = performance.now() + args.maxElapsedSeconds * 1000; return args;
}

async function runExport(args: Arguments): Promise<JsonObject> {
  for (let attempt = 0; attempt <= args.maxRetries; attempt += 1) {
    try { return await exportDelta(args, attempt > 0); }
    catch (error) {
      if (!(error instanceof SnapshotExpired)) throw error;
      if (attempt >= args.maxRetries) throw new DeltaError("collector snapshot or export ticket repeatedly expired");
      const wait = Math.min(args.retryBaseSeconds * 2 ** attempt * 1000, 10_000, args.deadline - performance.now()); if (wait <= 0) throw new DeltaError("source export exceeded the configured elapsed-time limit"); await delay(wait);
    }
  }
  throw new DeltaError("collector snapshot retry limit was exceeded");
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) {
    process.stdout.write(
      "Usage: export-cpa-session-archive-delta --base-url URL --checkpoint FILE --output FILE [options]\n" +
      "  --collector-direct             use the collector snapshot/ticket API\n" +
      "  --offline-full                 export a sealed offline collector snapshot\n" +
      "  --token-file FILE              read the legacy CPA token from a protected file\n" +
      "  --token-env NAME               read the legacy CPA token from the named environment variable\n" +
      "  --private-http-host HOST       allow one exact private HTTP collector host\n" +
      "  --readiness-timeout-seconds N bound collector readiness within the overall elapsed limit\n" +
      "  --readiness-poll-milliseconds N poll /readyz without starting archive reads early\n" +
      "  --client-cert-file FILE        mTLS client certificate for collector-direct\n" +
      "  --client-key-file FILE         mTLS client key for collector-direct\n" +
      "  --legacy-spool FILE            read-only recovery of a verified 3612 random spool\n" +
      "  --source-sqlite FILE           read a sealed, read-only archive.sqlite backup directly\n" +
      "  --chunk-records N              checkpoint a stable session after at most N records\n" +
      "  --chunk-bytes N                checkpoint a stable session after at most N canonical bytes\n" +
      "  --chunk-seconds N              checkpoint a stable session after at most N elapsed seconds\n" +
      "  --max-chunks N                 stop after N committed chunks (zero is unlimited)\n" +
      "  --resume                       resume a verified stable spool or sealed checkpoint\n",
    );
    return 0;
  }
  const args = parseCli(argv);
  const manifest = await withCheckpointLock(args.checkpoint, args.deadline, () => runExport(args));
  process.stdout.write(`${canonicalize({ sequence: manifest.sequence, sessions: manifest.session_count, records: manifest.record_count, watermark_completed_at: manifest.watermark_completed_at, source_records: manifest.source_records_after, output_sha256: manifest.output_sha256 })}\n`);
  return 0;
}

if (invokedAsEntrypoint("export-cpa-session-archive-delta", import.meta.url)) {
  runCheckpointLockHolder(process.argv.slice(2)).then((held) => held ? 0 : main()).then((code) => { process.exitCode = code; }).catch((error: unknown) => {
    if (error instanceof DeltaError) process.stderr.write(`delta export refused: ${error.message}\n`);
    else if (process.env.MTC_DELTA_DEBUG === "1") process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    else process.stderr.write("delta export failed because of a local I/O error\n");
    process.exitCode = 2;
  });
}
