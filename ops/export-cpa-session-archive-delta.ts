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
import { basename, dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { parseStrictJson } from "./lib/strict-json.ts";

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

/**
 * One canonical payload copy is sufficient for de-duplication, per-session
 * digest verification, and both output orders. `emit` retains the legacy
 * overlap filter without staging selected records in a second table.
 */
export const ARCHIVE_SPOOL_SCHEMA = `
  PRAGMA journal_mode=DELETE;
  PRAGMA synchronous=FULL;
  CREATE TABLE records(
    request_id TEXT PRIMARY KEY COLLATE BINARY,
    session_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    digest TEXT NOT NULL,
    canonical BLOB NOT NULL,
    emit INTEGER NOT NULL CHECK(emit IN (0, 1))
  ) WITHOUT ROWID;
  CREATE INDEX records_by_session ON records(session_id COLLATE BINARY, request_id COLLATE BINARY);
  CREATE INDEX records_by_output ON records(started_at, request_id COLLATE BINARY) WHERE emit = 1;
`;

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

type HttpResponse = { status: number; headers: IncomingMessage["headers"]; response: IncomingMessage };
function request(url: URL, headers: Record<string, string>, timeoutMs: number, tls?: TlsFiles): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const options: RequestOptions = { method: "GET", headers, timeout: timeoutMs, agent: false, cert: tls?.cert, key: tls?.key };
    const operation = (url.protocol === "https:" ? httpsRequest : httpRequest)(url, options, (response) => resolve({ status: response.statusCode ?? 0, headers: response.headers, response }));
    operation.once("timeout", () => operation.destroy(new Error("timeout")));
    operation.once("error", reject);
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
  private async managementJson(path: string, query: Record<string, string>): Promise<unknown> {
    const url = new URL(this.base + path);
    for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
    const headers: Record<string, string> = { Accept: "application/json", "User-Agent": "memeloop-token-center-delta-export/1" };
    if (this.token !== undefined) headers.Authorization = `Bearer ${this.token}`;
    let attempt = 0;
    while (true) {
      let result: HttpResponse;
      try { result = await request(url, headers, this.timeout(), this.tls); }
      catch { throw new DeltaError("source management request failed"); }
      if (result.status === 200) {
        const payload = await readBounded(result.response, MAX_MANAGEMENT_RESPONSE_BYTES);
        try { return unwrapJson(parseStrictJson(payload.toString("utf8"))); }
        catch (error) { if (error instanceof DeltaError) throw error; throw new DeltaError("source management response is not valid JSON"); }
      }
      result.response.resume();
      if (result.status === 410) throw new SnapshotExpired();
      const extended = this.collectorDirect && this.offlineFull && path === this.paths.sessions && [429, 503].includes(result.status);
      if ([429, 503].includes(result.status) && (attempt < this.maxRetries || extended)) {
        await this.waitForRetry(attempt, Array.isArray(result.headers["retry-after"]) ? result.headers["retry-after"]?.[0] : result.headers["retry-after"]);
        attempt += 1; continue;
      }
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
  async *exportLines(sessionId: string, maximum: number, snapshot?: string, recordsSha256?: string): AsyncGenerator<Buffer> {
    let response: IncomingMessage | undefined;
    for (let attempt = 0; attempt <= this.maxRetries; attempt += 1) {
      const ticket = await this.ticketUrl(sessionId, snapshot, recordsSha256);
      let result: HttpResponse;
      try { result = await request(ticket, { Accept: "application/x-ndjson", "User-Agent": "memeloop-token-center-delta-export/1" }, this.timeout(), this.tls); }
      catch { throw new DeltaError("source archive export failed"); }
      if (result.status === 200) { response = result.response; break; }
      result.response.resume();
      if (this.collectorDirect && snapshot !== undefined && result.status === 404 && attempt < this.maxRetries) { await this.waitForRetry(attempt); continue; }
      if (this.collectorDirect && snapshot !== undefined && result.status === 404) throw new SnapshotExpired();
      throw new DeltaError(`source archive export returned HTTP ${result.status}`);
    }
    if (response === undefined) throw new DeltaError("source archive export failed");
    let buffered = Buffer.alloc(0);
    try {
      for await (const raw of response) {
        this.timeout(); const chunk = Buffer.from(raw as Buffer); this.downloadedBytes += chunk.length;
        if (this.maxDownloadBytes !== undefined && this.downloadedBytes > this.maxDownloadBytes) throw new DeltaError("source archive downloads exceed the configured limit");
        buffered = Buffer.concat([buffered, chunk]);
        while (true) {
          const newline = buffered.indexOf(0x0a); if (newline < 0) break;
          const line = buffered.subarray(0, newline + 1); buffered = buffered.subarray(newline + 1);
          if (line.length > maximum) throw new DeltaError("source archive record exceeds the configured line limit");
          if (line.toString("utf8").trim()) yield line;
        }
        if (buffered.length > maximum) throw new DeltaError("source archive record exceeds the configured line limit");
      }
      if (buffered.length > 0 && buffered.toString("utf8").trim()) yield buffered;
    } catch (error) { if (error instanceof DeltaError) throw error; throw new DeltaError("source archive export stream failed"); }
  }
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

type Arguments = {
  baseUrl: string; downloadBaseUrl?: string; tokenFile?: string; tokenEnv?: string; checkpoint: string; output: string;
  collectorDirect: boolean; offlineFull: boolean; privateHttpHosts: string[]; clientCertFile?: string; clientKeyFile?: string; since?: string;
  overlapSeconds: number; sessionLimit: number; maxLineBytes: number; maxDownloadBytes: number; maxOutputBytes: number; timeoutSeconds: number;
  maxElapsedSeconds: number; maxRetries: number; retryBaseSeconds: number; maxFutureSkewSeconds: number; requireStableSource: boolean; allowHttp: boolean; resume: boolean; deadline: number;
};

async function exportDelta(args: Arguments): Promise<JsonObject> {
  const token = args.collectorDirect ? undefined : args.tokenFile !== undefined ? loadToken(args.tokenFile) : loadTokenEnv(args.tokenEnv!);
  const hosts = new Set(args.privateHttpHosts.map(normalizeHost));
  if (!args.allowHttp) for (const host of hosts) if (!await verifyPrivateHost(host, hosts)) throw new DeltaError("private HTTP host allowlist did not resolve exclusively to private addresses");
  let tls: TlsFiles | undefined;
  if (args.clientCertFile !== undefined && args.clientKeyFile !== undefined) {
    const certificate = lstatSync(args.clientCertFile); if (certificate.isSymbolicLink() || !certificate.isFile()) throw new DeltaError("mTLS certificate must be a regular non-symlink file");
    ensurePrivateRegular(args.clientKeyFile, "mTLS private key"); tls = { cert: readFileSync(args.clientCertFile), key: readFileSync(args.clientKeyFile) };
  }
  const client = new SourceClient(args.baseUrl, args.downloadBaseUrl ?? args.baseUrl, token, args.timeoutSeconds, args.allowHttp, hosts, args.collectorDirect, args.maxRetries, args.retryBaseSeconds, args.deadline, tls, args.maxDownloadBytes, args.offlineFull);
  const fingerprint = sourceFingerprint(client); const checkpoint = loadCheckpoint(args.checkpoint, fingerprint);
  const manifestPath = `${args.output}.manifest.json`; const pending = `${args.output}.pending`;
  if (args.resume) {
    if (existsSync(pending) && !existsSync(manifestPath) && !existsSync(args.output)) { ensurePrivateRegular(pending, "orphaned pending delta output"); unlinkSync(pending); fsyncDirectory(dirname(pending)); }
    else return resumeOutput(args.output, pending, manifestPath, args.checkpoint, checkpoint, fingerprint);
  }
  if (existsSync(args.output) || existsSync(pending) || existsSync(manifestPath)) throw new DeltaError("delta output, pending file, or manifest already exists; use --resume or a new path");
  let prior: Time, priorFence: string | undefined, sequence: number;
  if (checkpoint === undefined) { if (args.since === undefined) throw new DeltaError("--since is required before the first checkpoint"); prior = parseTime(args.since, "initial since watermark"); sequence = 1; }
  else { if (args.since !== undefined) throw new DeltaError("--since cannot replace an existing checkpoint"); prior = parseTime(checkpoint.watermark_completed_at, "checkpoint watermark"); priorFence = checkpoint.source_ingest_fence === null ? undefined : checkpoint.source_ingest_fence as string | undefined; sequence = (checkpoint.sequence as number) + 1; }
  if (args.collectorDirect && priorFence === undefined) { if (!args.offlineFull) throw new DeltaError("the first collector-direct snapshot requires --offline-full"); await client.verifyOfflineFull(); }
  else if (args.offlineFull) throw new DeltaError("--offline-full is only valid for the first collector-direct snapshot");
  const lower = addSeconds(prior, -args.overlapSeconds); const observed: Time = { nanos: BigInt(Date.now()) * 1_000_000n }; const maximum = addSeconds(observed, args.maxFutureSkewSeconds);
  if (compareTime(prior, maximum) > 0) throw new DeltaError("source checkpoint timestamp exceeds the future-skew limit");
  const before = await client.statsRecords();
  if (checkpoint !== undefined && before < (checkpoint.last_source_records as number)) throw new DeltaError("source record count moved backwards since the checkpoint");
  const first = await loadProjection(client, lower, args.sessionLimit, before, undefined, priorFence); verifyClock(first.sessions, maximum); const firstDigest = selectionDigest(first.sessions);
  mkdirSync(dirname(args.output), { recursive: true, mode: 0o700 });
  const spoolPath = join(dirname(args.output), `.mtc-archive-delta-spool.${process.pid}.${Date.now()}.sqlite`); let database: DatabaseSync | undefined; let outputTemporary: string | undefined;
  let maximumCompleted = prior; let maximumStarted: Time | undefined;
  try {
    database = new DatabaseSync(spoolPath); database.exec(ARCHIVE_SPOOL_SCHEMA);
    const seen = database.prepare("SELECT session_id, digest FROM records WHERE request_id=?");
    const addRecord = database.prepare("INSERT INTO records VALUES(?,?,?,?,?,?,?)");
    let selectedBytes = 0;
    for (const session of [...first.sessions].sort((left, right) => compareUtf8Bytewise(left.session_id, right.session_id))) {
      if (session.deleted === true) {
        const deletedAt = parseTime(session.deleted_at, "source session deleted_at");
        if (compareTime(deletedAt, maximumCompleted) > 0) maximumCompleted = deletedAt;
        continue;
      }
      let exported = 0;
      for await (const rawLine of client.exportLines(session.session_id, args.maxLineBytes, first.snapshot, session.records_sha256)) {
        let item: unknown; try { item = parseStrictJson(rawLine.toString("utf8")); } catch { throw new DeltaError("source archive stream contains invalid JSON"); }
        if (!isObject(item) || ![1, 2].includes(item.schema_version as number)) throw new DeltaError("source archive record schema is unsupported");
        if (typeof item.request_id !== "string" || item.request_id.length === 0) throw new DeltaError("source archive request identity is invalid");
        const requestId = item.request_id;
        if (item.session_id !== session.session_id) throw new DeltaError("source session export returned a foreign session record");
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
        addRecord.run(requestId, session.session_id, formatTime(started), formatTime(completed), digest, encoded, emit ? 1 : 0); exported += 1;
        if (!emit) continue;
        if (compareTime(completed, maximumCompleted) > 0) maximumCompleted = completed;
        if (maximumStarted === undefined || compareTime(started, maximumStarted) > 0) maximumStarted = started;
      }
      if (exported !== session.requests) throw new DeltaError("source session export count disagrees with its session summary");
      if (first.protocol === STABLE_CURSOR_PROTOCOL) {
        const digest = createHash("sha256");
        for (const row of database.prepare("SELECT canonical FROM records WHERE session_id=? ORDER BY request_id COLLATE BINARY").iterate(session.session_id) as Iterable<{ canonical: Uint8Array }>) digest.update(row.canonical);
        if (digest.digest("hex") !== session.records_sha256) throw new DeltaError("source session export digest disagrees with its stable summary");
      }
    }
    const afterExport = await client.statsRecords(); if (args.requireStableSource && afterExport !== before) throw new DeltaError("source record count changed despite the requested write barrier");
    const second = await loadProjection(client, lower, args.sessionLimit, afterExport, first.snapshot, priorFence); verifyClock(second.sessions, maximum);
    if (second.protocol !== first.protocol || second.requestCount !== first.requestCount || selectionDigest(second.sessions) !== firstDigest) throw new DeltaError("source session projection changed during delta export; retry");
    const after = await client.statsRecords(); if (args.requireStableSource && after !== before) throw new DeltaError("source record count changed despite the requested write barrier"); if (after < before) throw new DeltaError("source record count decreased during delta export");
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
      session_projection_protocol: first.protocol, source_mode: client.paths.mode, offline_full_snapshot: args.offlineFull, source_projection_requests: first.requestCount,
      source_snapshot_sha256: first.snapshot === undefined ? null : sha256Bytes(first.snapshot), prior_source_ingest_fence: priorFence ?? null, source_ingest_fence: first.ingestFence ?? null,
      snapshot_schema_version: first.snapshotSchemaVersion ?? null, tombstone_safe_after_ingest_fence: first.tombstoneSafeAfterIngestFence ?? null, deleted_session_count: first.deletedSessionCount,
      session_set_sha256: firstDigest, record_count: recordCount, source_records_before: before, source_records_after: after, stable_source_required: args.requireStableSource,
      output_file: basename(args.output), output_size_bytes: outputSize, output_sha256: outputDigest.digest("hex") };
    writeAtomicJson(manifestPath, manifest); renameSync(pending, args.output); fsyncDirectory(dirname(args.output)); commitCheckpoint(args.checkpoint, fingerprint, manifest); return manifest;
  } finally { database?.close(); rmSync(spoolPath, { force: true }); if (outputTemporary !== undefined) rmSync(outputTemporary, { force: true }); }
}

function numberOption(values: Record<string, unknown>, key: string, fallback: number): number {
  const raw = values[key]; if (raw === undefined) return fallback; const value = Number(raw); if (!Number.isFinite(value)) throw new DeltaError(`--${key.replaceAll("_", "-")} is invalid`); return value;
}
function parseCli(argv: string[]): Arguments {
  const { values } = parseArgs({ args: argv, strict: true, allowPositionals: false, options: {
    "base-url": { type: "string" }, "download-base-url": { type: "string" }, "token-file": { type: "string" }, "token-env": { type: "string" }, checkpoint: { type: "string" }, output: { type: "string" },
    "collector-direct": { type: "boolean", default: false }, "offline-full": { type: "boolean", default: false }, "private-http-host": { type: "string", multiple: true, default: [] }, "client-cert-file": { type: "string" }, "client-key-file": { type: "string" }, since: { type: "string" },
    "overlap-seconds": { type: "string" }, "session-limit": { type: "string" }, "max-line-bytes": { type: "string" }, "max-download-bytes": { type: "string" }, "max-output-bytes": { type: "string" }, "timeout-seconds": { type: "string" }, "max-elapsed-seconds": { type: "string" }, "max-retries": { type: "string" }, "retry-base-seconds": { type: "string" }, "max-future-skew-seconds": { type: "string" },
    "require-stable-source": { type: "boolean", default: false }, "allow-http": { type: "boolean", default: false }, resume: { type: "boolean", default: false },
  } });
  if (typeof values["base-url"] !== "string" || typeof values.checkpoint !== "string" || typeof values.output !== "string") throw new DeltaError("--base-url, --checkpoint, and --output are required");
  const args: Arguments = { baseUrl: values["base-url"], downloadBaseUrl: values["download-base-url"], tokenFile: values["token-file"], tokenEnv: values["token-env"], checkpoint: values.checkpoint, output: values.output,
    collectorDirect: values["collector-direct"]!, offlineFull: values["offline-full"]!, privateHttpHosts: values["private-http-host"]!, clientCertFile: values["client-cert-file"], clientKeyFile: values["client-key-file"], since: values.since,
    overlapSeconds: numberOption(values, "overlap-seconds", 86_400), sessionLimit: numberOption(values, "session-limit", 1000), maxLineBytes: numberOption(values, "max-line-bytes", 16 * 1024 * 1024), maxDownloadBytes: numberOption(values, "max-download-bytes", 64 * 1024 ** 3), maxOutputBytes: numberOption(values, "max-output-bytes", 64 * 1024 ** 3), timeoutSeconds: numberOption(values, "timeout-seconds", 60), maxElapsedSeconds: numberOption(values, "max-elapsed-seconds", 6 * 3600), maxRetries: numberOption(values, "max-retries", 5), retryBaseSeconds: numberOption(values, "retry-base-seconds", 0.5), maxFutureSkewSeconds: numberOption(values, "max-future-skew-seconds", 3600), requireStableSource: values["require-stable-source"]!, allowHttp: values["allow-http"]!, resume: values.resume!, deadline: 0 };
  if (!Number.isInteger(args.overlapSeconds) || args.overlapSeconds < 1 || args.overlapSeconds > 31 * 86_400) throw new DeltaError("overlap seconds must be between one second and 31 days");
  if (!Number.isInteger(args.sessionLimit) || args.sessionLimit < 1 || args.sessionLimit > 1000) throw new DeltaError("session limit must be between 1 and 1000");
  if (!Number.isInteger(args.maxLineBytes) || args.maxLineBytes < 1024 || args.maxLineBytes > 16 * 1024 * 1024) throw new DeltaError("max line bytes must be between 1 KiB and 16 MiB");
  if (!Number.isInteger(args.maxDownloadBytes) || args.maxDownloadBytes < args.maxLineBytes || args.maxDownloadBytes > 1024 ** 4) throw new DeltaError("max download bytes must cover one line and be at most 1 TiB");
  if (!Number.isInteger(args.maxOutputBytes) || args.maxOutputBytes < args.maxLineBytes || args.maxOutputBytes > 1024 ** 4) throw new DeltaError("max output bytes must cover one line and be at most 1 TiB");
  if (args.timeoutSeconds <= 0 || args.timeoutSeconds > 3600) throw new DeltaError("timeout seconds must be between 0 and 3600");
  if (args.maxElapsedSeconds <= 0 || args.maxElapsedSeconds > 86_400) throw new DeltaError("max elapsed seconds must be between 0 and 86400");
  if (!Number.isInteger(args.maxRetries) || args.maxRetries < 0 || args.maxRetries > 20) throw new DeltaError("max retries must be between 0 and 20");
  if (args.retryBaseSeconds <= 0 || args.retryBaseSeconds > 30) throw new DeltaError("retry base seconds must be between 0 and 30");
  if (!Number.isInteger(args.maxFutureSkewSeconds) || args.maxFutureSkewSeconds < 0 || args.maxFutureSkewSeconds > 86_400) throw new DeltaError("max future skew seconds must be between 0 and 86400");
  if (args.offlineFull && !args.collectorDirect) throw new DeltaError("--offline-full requires --collector-direct");
  if (args.collectorDirect && (args.tokenFile !== undefined || args.tokenEnv !== undefined)) throw new DeltaError("collector-direct does not accept a CPA token");
  if (!args.collectorDirect && args.tokenFile === undefined && args.tokenEnv === undefined) throw new DeltaError("the legacy CPA plugin input requires --token-file or --token-env");
  if (args.tokenFile !== undefined && args.tokenEnv !== undefined) throw new DeltaError("--token-file and --token-env are mutually exclusive");
  if (args.collectorDirect && args.allowHttp) throw new DeltaError("collector-direct HTTP requires an exact --private-http-host allowlist");
  if (args.allowHttp && args.privateHttpHosts.length > 0) throw new DeltaError("--allow-http and --private-http-host cannot be combined");
  if ((args.clientCertFile === undefined) !== (args.clientKeyFile === undefined)) throw new DeltaError("mTLS requires both --client-cert-file and --client-key-file");
  if (args.clientCertFile !== undefined && !args.collectorDirect) throw new DeltaError("mTLS client files are only valid with --collector-direct");
  const normalized = args.privateHttpHosts.map(normalizeHost); if (normalized.some((item, index) => item.length === 0 || item !== args.privateHttpHosts[index])) throw new DeltaError("private HTTP host allowlist contains an invalid host");
  if (new Set(normalized).size !== normalized.length) throw new DeltaError("private HTTP host allowlist contains duplicates");
  args.deadline = performance.now() + args.maxElapsedSeconds * 1000; return args;
}

async function runExport(args: Arguments): Promise<JsonObject> {
  for (let attempt = 0; attempt <= args.maxRetries; attempt += 1) {
    try { return await exportDelta(args); }
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
      "  --client-cert-file FILE        mTLS client certificate for collector-direct\n" +
      "  --client-key-file FILE         mTLS client key for collector-direct\n" +
      "  --resume                       resume from the sealed checkpoint\n",
    );
    return 0;
  }
  const args = parseCli(argv);
  const manifest = await withCheckpointLock(args.checkpoint, args.deadline, () => runExport(args));
  process.stdout.write(`${canonicalize({ sequence: manifest.sequence, sessions: manifest.session_count, records: manifest.record_count, watermark_completed_at: manifest.watermark_completed_at, source_records: manifest.source_records_after, output_sha256: manifest.output_sha256 })}\n`);
  return 0;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCheckpointLockHolder(process.argv.slice(2)).then((held) => held ? 0 : main()).then((code) => { process.exitCode = code; }).catch((error: unknown) => {
    if (error instanceof DeltaError) process.stderr.write(`delta export refused: ${error.message}\n`);
    else if (process.env.MTC_DELTA_DEBUG === "1") process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    else process.stderr.write("delta export failed because of a local I/O error\n");
    process.exitCode = 2;
  });
}
