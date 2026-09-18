#!/usr/bin/env node
/** Black-box and contract tests for the TypeScript archive delta exporter. */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, closeSync, constants as fsConstants, existsSync, mkdtempSync, openSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import test, { after, before, beforeEach } from "node:test";
import { gzipSync } from "node:zlib";
import {
  ARCHIVE_SPOOL_SCHEMA,
  canonicalBytes,
  type CollectorReadinessDriver,
  collectorTransportDiagnostic,
  compareUtf8Bytewise,
  formatTime,
  parseTime,
  selectionDigest,
  SourceClient,
  sourceFingerprint,
  STABLE_CURSOR_PROTOCOL,
  unwrapJson,
} from "../../ops/export-cpa-session-archive-delta.ts";

const ROOT = resolve(import.meta.dirname, "../..");
const EXPORTER = join(ROOT, "ops/export-cpa-session-archive-delta.ts");
const TOKEN = "management-token-that-must-never-appear";

type RecordValue = Record<string, unknown> & {
  schema_version: number;
  session_id: string;
  request_id: string;
  started_at: string;
  completed_at: string;
};
type Session = { session_id: string; requests: number; first_at?: string; last_at: string; records_sha256?: string; deleted?: boolean; deleted_at?: string };
type State = {
  records: Map<string, RecordValue[]>;
  stable: boolean;
  redirects: boolean;
  leakCalls: number;
  authorizationOnTicket: boolean;
  directAuthorizationSeen: boolean;
  snapshot: string;
  fence: string;
  snapshotSchemaVersion: 1 | 2;
  tombstoneFence: string;
  tombstones: Session[];
  ready: boolean;
  readyRequests: number;
  statsRequests: number;
  sessionsRequests: number;
  archiveRequests: Map<string, number>;
  failedArchiveSessions: Set<string>;
  onReadyRequest?: () => void;
  readyGate?: Promise<void>;
};

function canonicalLine(value: unknown): Buffer { return Buffer.concat([canonicalBytes(value), Buffer.from("\n")]); }
function digestRecords(rows: RecordValue[]): string {
  const digest = createHash("sha256");
  for (const row of [...rows].sort((left, right) => compareUtf8Bytewise(left.request_id, right.request_id))) digest.update(canonicalLine(row));
  return digest.digest("hex");
}
function record(requestId: string, sessionId: string, startedAt: string, completedAt: string): RecordValue {
  return {
    schema_version: 2,
    session_id: sessionId,
    request_id: requestId,
    started_at: startedAt,
    completed_at: completedAt,
    key_id: "key-hash",
    principal_id: "principal",
    requested_model: "model",
    model: "model",
    outcome: "success",
    status_code: 200,
    request: { prompt: "payload-secret-that-must-never-appear" },
    response: { answer: requestId },
  };
}
function sessions(state: State): Session[] {
  const result: Session[] = [...state.records.entries()].map(([sessionId, rows]) => ({
    session_id: sessionId,
    requests: rows.length,
    first_at: rows.map((row) => row.started_at).sort()[0]!,
    last_at: rows.map((row) => row.completed_at).sort().at(-1)!,
    ...(state.stable ? { records_sha256: digestRecords(rows) } : {}),
  }));
  result.push(...state.tombstones);
  result.sort((left, right) => right.last_at.localeCompare(left.last_at, "en") || compareUtf8Bytewise(left.session_id, right.session_id));
  return result;
}
function sendJson(response: ServerResponse, value: unknown, status = 200): void {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, { "Content-Type": "application/json", "Content-Length": String(body.length) });
  response.end(body);
}

let state: State;
let port = 0;
const server = createServer(async (request: IncomingMessage, response: ServerResponse) => {
  const url = new URL(request.url ?? "/", `http://127.0.0.1:${port}`);
  if (url.pathname === "/leak") { state.leakCalls += 1; sendJson(response, { authorization: request.headers.authorization }); return; }
  if (url.pathname === "/readyz") {
    state.readyRequests += 1; state.onReadyRequest?.();
    if (state.readyGate !== undefined) await state.readyGate;
    if (!state.ready) { sendJson(response, { error: "preparing-secret-must-not-be-logged" }, 503); return; }
    response.writeHead(200, { "Content-Type": "text/plain", "Content-Length": "5" }); response.end("ready"); return;
  }
  if (url.pathname.startsWith("/archive-api/v1/exports/")) {
    state.authorizationOnTicket ||= request.headers.authorization !== undefined;
    const capability = decodeURIComponent(url.pathname.slice("/archive-api/v1/exports/".length));
    const sessionId = /^[0-9a-f]{64}$/.test(capability) ? [...state.records.keys()][0]! : capability;
    state.archiveRequests.set(sessionId, (state.archiveRequests.get(sessionId) ?? 0) + 1);
    if (state.failedArchiveSessions.has(sessionId)) { sendJson(response, { error: "injected archive failure" }, 500); return; }
    const rows = state.records.get(sessionId);
    if (rows === undefined) { sendJson(response, { error: "not found" }, 404); return; }
    response.writeHead(200, { "Content-Type": "application/x-ndjson" });
    for (const row of state.stable ? [...rows].sort((left, right) => compareUtf8Bytewise(left.request_id, right.request_id)) : rows) response.write(canonicalLine(row));
    response.end(); return;
  }
  const direct = url.pathname.startsWith("/v1/");
  if (direct) state.directAuthorizationSeen ||= request.headers.authorization !== undefined;
  else if (request.headers.authorization !== `Bearer ${TOKEN}`) { sendJson(response, { error: "unauthorized" }, 401); return; }
  if (url.pathname.endsWith("/stats")) { state.statsRequests += 1; sendJson(response, { records: [...state.records.values()].reduce((sum, rows) => sum + rows.length, 0), ...(direct ? { session_cursor_protocols: [STABLE_CURSOR_PROTOCOL], offline_full_snapshot_enabled: true } : {}) }); return; }
  if (url.pathname.endsWith("/sessions")) {
    state.sessionsRequests += 1;
    if (state.redirects) { response.writeHead(302, { Location: "/leak" }); response.end(); return; }
    const all = sessions(state);
    if (url.searchParams.get("cursor_protocol") !== STABLE_CURSOR_PROTOCOL || !state.stable) { sendJson(response, { sessions: all }); return; }
    const limit = Number(url.searchParams.get("limit"));
    const cursor = Number(url.searchParams.get("cursor") ?? "0");
    const page = all.slice(cursor, cursor + limit);
    const complete = cursor + page.length === all.length;
    sendJson(response, {
      cursor_protocol: STABLE_CURSOR_PROTOCOL,
      snapshot: state.snapshot,
      ingest_fence: state.fence,
      session_count: all.length,
      request_count: all.reduce((sum, item) => sum + item.requests, 0),
      session_set_sha256: selectionDigest(all),
      ...(state.snapshotSchemaVersion === 2 ? { snapshot_schema_version: 2, tombstone_safe_after_ingest_fence: state.tombstoneFence, deleted_session_count: state.tombstones.length } : {}),
      complete,
      next_cursor: complete ? null : String(cursor + page.length),
      sessions: page,
    });
    return;
  }
  if (url.pathname.endsWith("/export") || url.pathname.endsWith("/export-tickets")) {
    const sessionId = url.searchParams.get(direct ? "session_id" : "id") ?? "";
    const snapshot = url.searchParams.get("snapshot");
    const rows = state.records.get(sessionId);
    if (rows === undefined) { sendJson(response, { error: "not found" }, 404); return; }
    sendJson(response, {
      url: direct ? `/archive-api/v1/exports/${"a".repeat(64)}` : `/archive-api/v1/exports/${encodeURIComponent(sessionId)}${snapshot === null ? "" : `?snapshot=${encodeURIComponent(snapshot)}`}`,
      ...(snapshot === null ? {} : { cursor_protocol: STABLE_CURSOR_PROTOCOL, snapshot, records_sha256: digestRecords(rows) }),
    });
    return;
  }
  sendJson(response, { error: "not found" }, 404);
});

before(async () => {
  await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const address = server.address(); assert(address !== null && typeof address === "object"); port = address.port;
});
after(async () => { await new Promise<void>((resolveClose, reject) => server.close((error) => error === undefined ? resolveClose() : reject(error))); });
beforeEach(() => {
  state = { records: new Map(), stable: false, redirects: false, leakCalls: 0, authorizationOnTicket: false, directAuthorizationSeen: false, snapshot: "snapshot-one", fence: "7", snapshotSchemaVersion: 1, tombstoneFence: "0", tombstones: [], ready: true, readyRequests: 0, statsRequests: 0, sessionsRequests: 0, archiveRequests: new Map(), failedArchiveSessions: new Set() };
});

test("collector 102 progress restarts the bounded archive-download idle timer", async () => {
  const progressServer = createServer((_request, response) => {
    response.writeProcessing();
    setTimeout(() => response.writeProcessing(), 20);
    setTimeout(() => {
      response.writeHead(200, { "Content-Type": "application/x-ndjson" });
      response.end('{"schema_version":2}\n');
    }, 45);
  });
  await new Promise<void>((resolveListen, rejectListen) => {
    progressServer.once("error", rejectListen);
    progressServer.listen(0, "127.0.0.1", resolveListen);
  });
  const address = progressServer.address();
  assert(address !== null && typeof address === "object");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    const diagnostics: string[] = [];
    const client = new SourceClient(base, base, undefined, 0.03, true, new Set(["127.0.0.1"]), true, 5, 0.5, undefined, undefined, undefined, false, (message) => diagnostics.push(message));
    (client as unknown as { ticketUrl: () => Promise<URL> }).ticketUrl = async () => new URL(`/archive-api/v1/exports/${"a".repeat(64)}`, base);
    const lines: string[] = [];
    for await (const line of client.exportLines("session", 1024, "snapshot", "0".repeat(64))) lines.push(line);
    assert.deepEqual(lines, ['{"schema_version":2}\n']);
    assert(diagnostics.some((message) => /^archive download progress status=102 elapsed_seconds=\d+ idle_seconds=\d+ idle_timer_reset=true$/.test(message)));
  } finally {
    await new Promise<void>((resolveClose, rejectClose) => progressServer.close((error) => error === undefined ? resolveClose() : rejectClose(error)));
  }
});

test("collector 102 progress cannot extend the overall archive-download deadline", async () => {
  const progressServer = createServer((_request, response) => {
    response.writeProcessing();
    const progress = setInterval(() => response.writeProcessing(), 5);
    response.once("close", () => clearInterval(progress));
  });
  await new Promise<void>((resolveListen, rejectListen) => {
    progressServer.once("error", rejectListen);
    progressServer.listen(0, "127.0.0.1", resolveListen);
  });
  const address = progressServer.address();
  assert(address !== null && typeof address === "object");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    const client = new SourceClient(base, base, undefined, 0.1, true, new Set(["127.0.0.1"]), true, 0, 0.5, performance.now() + 0.04 * 1000);
    (client as unknown as { ticketUrl: () => Promise<URL> }).ticketUrl = async () => new URL(`/archive-api/v1/exports/${"b".repeat(64)}`, base);
    await assert.rejects(async () => {
      for await (const _line of client.exportLines("session", 1024, "snapshot", "0".repeat(64))) { /* no body is sent */ }
    }, /stage=archive-download,cause=overall_timeout/);
  } finally {
    await new Promise<void>((resolveClose, rejectClose) => progressServer.close((error) => error === undefined ? resolveClose() : rejectClose(error)));
  }
});

test("overall archive-download deadline also covers a final response body", async () => {
  const bodyServer = createServer((_request, response) => {
    response.writeHead(200, { "Content-Type": "application/x-ndjson" });
    const body = setInterval(() => response.write('{"schema_version":2}\n'), 5);
    response.once("close", () => clearInterval(body));
  });
  await new Promise<void>((resolveListen, rejectListen) => {
    bodyServer.once("error", rejectListen);
    bodyServer.listen(0, "127.0.0.1", resolveListen);
  });
  const address = bodyServer.address();
  assert(address !== null && typeof address === "object");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    const client = new SourceClient(base, base, undefined, 0.1, true, new Set(["127.0.0.1"]), true, 0, 0.5, performance.now() + 0.04 * 1000);
    (client as unknown as { ticketUrl: () => Promise<URL> }).ticketUrl = async () => new URL(`/archive-api/v1/exports/${"c".repeat(64)}`, base);
    await assert.rejects(async () => {
      for await (const _line of client.exportLines("session", 1024, "snapshot", "0".repeat(64))) { /* body continues beyond the deadline */ }
    }, /stage=archive-download,cause=overall_timeout/);
  } finally {
    await new Promise<void>((resolveClose, rejectClose) => bodyServer.close((error) => error === undefined ? resolveClose() : rejectClose(error)));
  }
});

test("archive framing preserves split UTF-8, separator boundaries, and an unterminated final line", async () => {
  const terminated = Buffer.from('{"text":"汉字"}\n');
  const final = Buffer.from('{"tail":true}');
  const character = terminated.indexOf(Buffer.from("汉"));
  assert(character >= 0);
  const chunks = [
    terminated.subarray(0, character + 1),
    terminated.subarray(character + 1, terminated.length - 1),
    terminated.subarray(terminated.length - 1),
    Buffer.from(" \t"),
    Buffer.from("\r"),
    Buffer.from("\n"),
    final.subarray(0, 4),
    final.subarray(4),
  ];
  const fragmentServer = createServer(async (_request, response) => {
    response.writeHead(200, { "Content-Type": "application/x-ndjson" });
    for (const chunk of chunks) {
      response.write(chunk);
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    response.end();
  });
  await new Promise<void>((resolveListen, rejectListen) => { fragmentServer.once("error", rejectListen); fragmentServer.listen(0, "127.0.0.1", resolveListen); });
  const address = fragmentServer.address(); assert(address !== null && typeof address === "object");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    const client = new SourceClient(base, base, undefined, 5, true, new Set(["127.0.0.1"]), true);
    (client as unknown as { ticketUrl: () => Promise<URL> }).ticketUrl = async () => new URL(`/archive-api/v1/exports/${"d".repeat(64)}`, base);
    const lines: string[] = [];
    for await (const line of client.exportLines("session", Math.max(terminated.length, final.length), "snapshot", "0".repeat(64))) lines.push(line);
    assert.deepEqual(lines, [terminated.toString("utf8"), final.toString("utf8")]);
  } finally {
    await new Promise<void>((resolveClose, rejectClose) => fragmentServer.close((error) => error === undefined ? resolveClose() : rejectClose(error)));
  }
});

test("archive framing rejects an overlong line assembled across chunks before its separator", async () => {
  const fragmentServer = createServer(async (_request, response) => {
    response.writeHead(200, { "Content-Type": "application/x-ndjson" });
    response.write(Buffer.alloc(12, 0x61));
    await new Promise((resolve) => setTimeout(resolve, 2));
    response.write(Buffer.alloc(12, 0x62));
    await new Promise((resolve) => setTimeout(resolve, 2));
    response.end("\n");
  });
  await new Promise<void>((resolveListen, rejectListen) => { fragmentServer.once("error", rejectListen); fragmentServer.listen(0, "127.0.0.1", resolveListen); });
  const address = fragmentServer.address(); assert(address !== null && typeof address === "object");
  const base = `http://127.0.0.1:${address.port}`;
  try {
    const client = new SourceClient(base, base, undefined, 5, true, new Set(["127.0.0.1"]), true);
    (client as unknown as { ticketUrl: () => Promise<URL> }).ticketUrl = async () => new URL(`/archive-api/v1/exports/${"e".repeat(64)}`, base);
    await assert.rejects(async () => {
      for await (const _line of client.exportLines("session", 20, "snapshot", "0".repeat(64))) { /* rejected before a line can be yielded */ }
    }, /source archive record exceeds the configured line limit/);
  } finally {
    await new Promise<void>((resolveClose, rejectClose) => fragmentServer.close((error) => error === undefined ? resolveClose() : rejectClose(error)));
  }
});

async function run(arguments_: string[], environment: NodeJS.ProcessEnv = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const child = spawn(process.execPath, [EXPORTER, ...arguments_], { cwd: ROOT, env: { ...process.env, ...environment }, stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "", stderr = ""; child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8"); child.stdout.on("data", (chunk: string) => { stdout += chunk; }); child.stderr.on("data", (chunk: string) => { stderr += chunk; });
  const code = await new Promise<number | null>((resolveExit, reject) => { child.once("error", reject); child.once("exit", resolveExit); });
  return { code, stdout, stderr };
}
function fixture(): { directory: string; token: string; checkpoint: string; output: string } {
  const directory = mkdtempSync(join(tmpdir(), "mtc-delta-ts-")); chmodSync(directory, 0o700);
  const token = join(directory, "token"); writeFileSync(token, `${TOKEN}\n`, { mode: 0o600 });
  return { directory, token, checkpoint: join(directory, "checkpoint.json"), output: join(directory, "delta.ndjson") };
}
function baseArguments(paths: ReturnType<typeof fixture>): string[] {
  return ["--base-url", `http://127.0.0.1:${port}`, "--allow-http", "--token-file", paths.token, "--checkpoint", paths.checkpoint, "--output", paths.output, "--since", "2025-01-01T00:00:00Z", "--retry-base-seconds", "0.001"];
}
function collectorBaselineArguments(paths: ReturnType<typeof fixture>): string[] {
  return ["--collector-direct", "--offline-full", "--base-url", `http://127.0.0.1:${port}`, "--private-http-host", "127.0.0.1", "--checkpoint", paths.checkpoint, "--output", paths.output, "--since", "1970-01-01T00:00:00Z", "--retry-base-seconds", "0.001"];
}
const LEGACY_3612_SPOOL_SCHEMA = `
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
function writeLegacy3612RecordSpool(path: string, rows: RecordValue[]): void {
  const database = new DatabaseSync(path); database.exec(LEGACY_3612_SPOOL_SCHEMA);
  const insert = database.prepare("INSERT INTO records VALUES(?,?,?,?,?,?,?)");
  for (const row of rows) {
    const canonical = canonicalLine(row);
    insert.run(row.request_id, row.session_id, row.started_at, row.completed_at, createHash("sha256").update(canonical).digest("hex"), canonical, 1);
  }
  database.close(); chmodSync(path, 0o600);
}

function writeLargeArchiveSQLite(path: string, recordCount = 257, payloadBytes = 2048): RecordValue[] {
  const database = new DatabaseSync(path);
  database.exec(`
    CREATE TABLE records(id INTEGER PRIMARY KEY,request_id TEXT NOT NULL UNIQUE,session_id TEXT NOT NULL,key_id TEXT,principal_id TEXT,credential_hash TEXT,
      requested_model TEXT,model TEXT,outcome TEXT,status_code INTEGER,started_at TEXT,completed_at TEXT,metadata_json TEXT,facets_json TEXT,
      original_ref TEXT,response_ref TEXT,original_request_gz BLOB,response_gz BLOB);
    CREATE INDEX idx_records_session_request ON records(session_id,request_id COLLATE BINARY);
    CREATE TABLE blobs(hash TEXT PRIMARY KEY,codec TEXT NOT NULL,data BLOB NOT NULL);
    CREATE TABLE credential_principals(credential_hash TEXT PRIMARY KEY COLLATE NOCASE,principal_id TEXT NOT NULL,alias TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'active',updated_at TEXT NOT NULL);
    CREATE INDEX idx_credential_principals_principal ON credential_principals(principal_id);
    CREATE TABLE session_summaries(session_id TEXT PRIMARY KEY,requests INTEGER NOT NULL,first_at TEXT NOT NULL,last_at TEXT NOT NULL);
    CREATE TABLE archive_ingest_clock(id INTEGER PRIMARY KEY,sequence INTEGER NOT NULL);
    CREATE TABLE archive_ingest_events(sequence INTEGER PRIMARY KEY,session_id TEXT NOT NULL,previous_session_id TEXT NOT NULL DEFAULT '');
    CREATE INDEX idx_events_session ON archive_ingest_events(session_id,sequence);
    CREATE TABLE session_export_digests(session_id TEXT PRIMARY KEY,requests INTEGER NOT NULL,first_at TEXT NOT NULL,last_at TEXT NOT NULL,records_sha256 TEXT NOT NULL,max_ingest_sequence INTEGER NOT NULL);
    CREATE TABLE archive_snapshot_contract(id INTEGER PRIMARY KEY,schema_version INTEGER NOT NULL,tombstone_safe_after_sequence INTEGER NOT NULL);
  `);
  const insertRecord = database.prepare(`INSERT INTO records(request_id,session_id,key_id,principal_id,credential_hash,requested_model,model,outcome,status_code,started_at,completed_at,
    metadata_json,facets_json,original_ref,response_ref,original_request_gz,response_gz) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  const insertEvent = database.prepare("INSERT INTO archive_ingest_events(sequence,session_id,previous_session_id) VALUES(?,'large-session','')");
  database.prepare("INSERT INTO credential_principals VALUES(?,?,?,?,?)").run("credential-old", "principal", "Historical Alias", "active", "2025-01-01T00:00:00.000000Z");
  database.prepare("INSERT INTO credential_principals VALUES(?,?,?,?,?)").run("credential-current", "principal", "Current Alias", "active", "2025-01-02T00:00:00.000000Z");
  database.prepare("INSERT INTO credential_principals VALUES(?,?,?,?,?)").run("credential-empty", "principal", "", "active", "2025-01-03T00:00:00.000000Z");
  const rows: RecordValue[] = [];
  for (let index = 0; index < recordCount; index += 1) {
    const requestId = `request-${String(index).padStart(6, "0")}`;
    const startedAt = new Date(Date.UTC(2025, 0, 2, 1, 0, index)).toISOString().replace(".000Z", ".000000Z");
    const completedAt = new Date(Date.UTC(2025, 0, 2, 1, 0, index, 500)).toISOString().replace(".500Z", ".500000Z");
    const item = record(requestId, "large-session", startedAt, completedAt);
    item.principal_alias = "Current Alias";
    item.request = { prompt: `${requestId}:${"x".repeat(payloadBytes)}` };
    rows.push(item);
    insertRecord.run(item.request_id, item.session_id, String(item.key_id), String(item.principal_id), "", String(item.requested_model), String(item.model), String(item.outcome), Number(item.status_code),
      item.started_at, item.completed_at, "", "", "", "", gzipSync(Buffer.from(JSON.stringify(item.request))), gzipSync(Buffer.from(JSON.stringify(item.response))));
    insertEvent.run(index + 1);
  }
  const ordered = [...rows].sort((left, right) => compareUtf8Bytewise(left.request_id, right.request_id));
  const digest = digestRecords(ordered);
  database.prepare("INSERT INTO session_summaries VALUES('large-session',?,?,?)").run(recordCount, ordered[0]!.started_at, ordered.at(-1)!.completed_at);
  database.prepare("INSERT INTO archive_ingest_clock VALUES(1,?)").run(recordCount);
  database.prepare("INSERT INTO archive_snapshot_contract VALUES(1,2,0)").run();
  database.prepare("INSERT INTO session_export_digests VALUES('large-session',?,?,?,?,?)").run(recordCount, ordered[0]!.started_at, ordered.at(-1)!.completed_at, digest, recordCount);
  database.close(); chmodSync(path, 0o400);
  return ordered;
}

function scriptedReadinessDriver(steps: Array<number | Error>, fallbackStatus = 503): {
  clock: { now: number };
  waits: number[];
  probeTimeouts: number[];
  drains: number[];
  driver: CollectorReadinessDriver;
} {
  const clock = { now: 0 }, waits: number[] = [], probeTimeouts: number[] = [], drains: number[] = [];
  const driver: CollectorReadinessDriver = {
    now: () => clock.now,
    wait: async (milliseconds) => { waits.push(milliseconds); clock.now += milliseconds; },
    probe: async (timeoutMilliseconds) => {
      probeTimeouts.push(timeoutMilliseconds);
      const step = steps.shift() ?? fallbackStatus;
      if (step instanceof Error) throw step;
      return { status: step, drain: () => { drains.push(step); } };
    },
  };
  return { clock, waits, probeTimeouts, drains, driver };
}

test("canonical helpers preserve six-digit UTC timestamps and deterministic keys", () => {
  assert.equal(formatTime(parseTime("2025-01-02T03:04:05.1234+00:00", "time")), "2025-01-02T03:04:05.123400Z");
  assert.equal(formatTime(parseTime("2025-01-02T11:04:05.123456789+08:00", "legacy time")), "2025-01-02T03:04:05.123456Z");
  assert.notDeepEqual(parseTime("2025-01-02T03:04:05.123456001Z", "time"), parseTime("2025-01-02T03:04:05.123456999Z", "time"));
  assert.equal(canonicalBytes({ z: 1, a: { y: 2, x: 3 } }).toString(), '{"a":{"x":3,"y":2},"z":1}');
});

test("archive spool stores each canonical payload in one indexed table", () => {
  const database = new DatabaseSync(":memory:");
  try {
    database.exec(ARCHIVE_SPOOL_SCHEMA);
    database.exec(ARCHIVE_SPOOL_SCHEMA);
    const tables = database.prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name").all() as Array<{ name: string }>;
    assert.deepEqual(tables.map((table) => table.name), ["completed_sessions", "records", "session_progress", "spool_metadata"]);
    const columns = database.prepare("PRAGMA table_info(records)").all() as Array<{ name: string }>;
    assert.equal(columns.filter((column) => column.name === "canonical").length, 1);
    assert.equal(columns.some((column) => column.name === "emit"), true);
    const indexes = database.prepare("SELECT name FROM sqlite_schema WHERE type='index' AND tbl_name='records' ORDER BY name").all() as Array<{ name: string }>;
    assert.deepEqual(indexes.map((index) => index.name), ["records_by_output", "records_by_session"]);
    assert.doesNotMatch(ARCHIVE_SPOOL_SCHEMA, /seen_records/);
  } finally { database.close(); }
});

test("schema-v2 set digest matches the fixed Go field order and bytewise session order", () => {
  const projection: Session[] = [
    { session_id: "a", requests: 0, last_at: "2026-01-03T03:04:05.000000Z", deleted: true, deleted_at: "2026-01-03T03:04:05.000000Z" },
    { session_id: "Z", requests: 2, first_at: "2026-01-02T03:04:05.000000Z", last_at: "2026-01-02T03:05:06.000000Z", records_sha256: "1".repeat(64) },
  ];
  assert.equal(selectionDigest(projection), "0a0b2faaba791ab3d356fe3e143119e94f09a801c47e5c2b102912535a88505b");
  assert.deepEqual(["_", "-", "0", "a", "A", "Z"].sort(compareUtf8Bytewise), ["-", "0", "A", "Z", "_", "a"]);
});

test("legacy source fingerprint remains version-one compatible and plugin envelopes are strict", () => {
  const base = `http://127.0.0.1:${port}`;
  const client = new SourceClient(base, base, TOKEN, 5, true, new Set());
  const expected = createHash("sha256").update(canonicalBytes({
    origin: base,
    base,
    download_origin: base,
    download_base: base,
    sessions_path: "/v0/management/plugins/cpa-session-archive/sessions",
    export_path: "/v0/management/plugins/cpa-session-archive/export",
    stats_path: "/v0/management/plugins/cpa-session-archive/stats",
    version: 1,
  })).digest("hex");
  assert.equal(sourceFingerprint(client), expected);
  const body = Buffer.from('{"records":3}').toString("base64");
  assert.equal(canonicalBytes(unwrapJson({ StatusCode: 200, Body: body })).toString(), '{"records":3}');
  assert.throws(() => unwrapJson({ StatusCode: 200, Body: "%%%" }), /body is invalid/);
});

test("checkpoint holder keeps the validated inode locked without a shell", async () => {
  const directory = mkdtempSync(join(tmpdir(), "mtc-delta-lock-"));
  const lock = join(directory, "checkpoint.lock");
  let descriptor = -1;
  try {
    writeFileSync(lock, "", { mode: 0o600 });
    descriptor = openSync(lock, fsConstants.O_RDWR | fsConstants.O_NOFOLLOW);
    const holderArgs = ["--exclusive", "--nonblock", "--conflict-exit-code", "75", "/proc/self/fd/3", process.execPath, "--experimental-strip-types", EXPORTER, "--checkpoint-lock-holder"];
    const first = spawn("flock", holderArgs, { stdio: ["pipe", "ignore", "pipe", descriptor, "pipe"], shell: false });
    await new Promise<void>((resolve, reject) => {
      first.once("error", reject);
      first.stdio[4]?.once("data", (chunk) => String(chunk).includes("ready") ? resolve() : reject(new Error("lock holder readiness marker changed")));
      first.once("exit", (code) => reject(new Error(`lock holder exited before readiness: ${code}`)));
    });
    const second = spawn("flock", holderArgs, { stdio: ["pipe", "ignore", "pipe", descriptor, "pipe"], shell: false });
    const conflict = await new Promise<number>((resolve, reject) => { second.once("error", reject); second.once("exit", (code) => resolve(code ?? -1)); });
    assert.equal(conflict, 75, "flock contention must use the dedicated retryable exit code");
    first.stdin!.end();
    assert.equal(await new Promise<number>((resolve) => first.once("exit", (code) => resolve(code ?? -1))), 0);
    assert.doesNotMatch(readFileSync(EXPORTER, "utf8"), /spawn\(["']sh["']/);
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
    rmSync(directory, { recursive: true, force: true });
  }
});

test("stable snapshot contract still rejects non-canonical nanosecond timestamps", async () => {
  state.stable = true;
  state.records.set("session-stable-nanos", [record(
    "request-stable-nanos",
    "session-stable-nanos",
    "2025-01-02T01:00:00.123456789Z",
    "2025-01-02T01:00:01.123456789Z",
  )]);
  const base = `http://127.0.0.1:${port}`;
  const client = new SourceClient(base, base, TOKEN, 5, true, new Set());
  await assert.rejects(
    client.stableSessions(10, parseTime("2025-01-01T00:00:00.000000Z", "lower bound")),
    /stable session timestamps or record digest are invalid/,
  );
});

test("legacy export is canonical, private, checkpointed, and incrementally replay-safe", async () => {
  const paths = fixture();
  try {
    state.records.set("session-b", [record("request-2", "session-b", "2025-01-03T01:00:00Z", "2025-01-03T01:00:01Z")]);
    state.records.set("session-a", [record("request-1", "session-a", "2025-01-02T09:00:00.123456789+08:00", "2025-01-02T09:00:01.987654321+08:00")]);
    const first = await run(baseArguments(paths));
    assert.equal(first.code, 0, first.stderr); assert(!first.stderr.includes(TOKEN)); assert(!first.stderr.includes("payload-secret"));
    assert.equal(state.authorizationOnTicket, false, "ticket download must not receive management authorization");
    const lines = readFileSync(paths.output, "utf8").trim().split("\n").map((line) => JSON.parse(line) as RecordValue);
    assert.deepEqual(lines.map((row) => row.request_id), ["request-1", "request-2"]);
    assert.equal(lines[0]!.started_at, "2025-01-02T01:00:00.123456Z");
    assert.equal(lines[0]!.completed_at, "2025-01-02T01:00:01.987654Z");
    const checkpoint = JSON.parse(readFileSync(paths.checkpoint, "utf8")) as Record<string, unknown>; assert.equal(checkpoint.sequence, 1);
    const manifest = JSON.parse(readFileSync(`${paths.output}.manifest.json`, "utf8")) as Record<string, unknown>; assert.equal(manifest.session_projection_protocol, "legacy-last-at-limit-v1");

    const secondOutput = join(paths.directory, "delta-2.ndjson");
    state.records.set("session-c", [record("request-3", "session-c", "2025-01-04T01:00:00Z", "2025-01-04T01:00:01Z")]);
    const second = await run(["--base-url", `http://127.0.0.1:${port}`, "--allow-http", "--token-file", paths.token, "--checkpoint", paths.checkpoint, "--output", secondOutput, "--retry-base-seconds", "0.001"]);
    assert.equal(second.code, 0, second.stderr);
    assert.equal(existsSync(join(ROOT, "3")), false, "flock descriptor must never be interpreted as a repository path");
    const replay = readFileSync(secondOutput, "utf8").trim().split("\n").map((line) => (JSON.parse(line) as RecordValue).request_id);
    assert.deepEqual(replay, ["request-1", "request-2", "request-3"], "overlap deliberately replays prior records for idempotent import");
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("stable snapshot pages and record digests are verified", async () => {
  const paths = fixture();
  try {
    state.stable = true;
    for (let index = 0; index < 3; index += 1) {
      const sessionId = `session-${index}`;
      state.records.set(sessionId, [record(`request-${index}`, sessionId, `2025-01-0${index + 2}T01:00:00.000000Z`, `2025-01-0${index + 2}T01:00:01.000000Z`)]);
    }
    const result = await run([...baseArguments(paths), "--session-limit", "2"]);
    assert.equal(result.code, 0, result.stderr);
    const manifest = JSON.parse(readFileSync(`${paths.output}.manifest.json`, "utf8")) as Record<string, unknown>;
    assert.equal(manifest.session_projection_protocol, STABLE_CURSOR_PROTOCOL); assert.equal(manifest.source_ingest_fence, "7"); assert.equal(manifest.session_count, 3);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("stable snapshot schema v2 exports tombstones without requesting archive tickets", async () => {
  const paths = fixture();
  try {
    state.stable = true;
    state.snapshotSchemaVersion = 2;
    state.tombstoneFence = "5";
    state.records.set("session-present", [record("request-present", "session-present", "2025-01-02T01:00:00.000000Z", "2025-01-02T01:00:01.000000Z")]);
    state.tombstones.push({ session_id: "session-deleted", requests: 0, last_at: "2025-01-03T01:00:00.000000Z", deleted: true, deleted_at: "2025-01-03T01:00:00.000000Z" });
    const result = await run(baseArguments(paths));
    assert.equal(result.code, 0, result.stderr);
    const output = readFileSync(paths.output, "utf8").trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
    assert.equal(output.length, 3);
    assert.equal(output[0]!._mtc_delta_type, "session_summary");
    assert.equal(output[0]!.session_id, "session-deleted");
    assert.equal(output[0]!.deleted, true);
    assert.equal(output[1]!._mtc_delta_type, "session_summary");
    assert.equal(output[1]!.session_id, "session-present");
    assert.equal(output[2]!.request_id, "request-present");
    const manifest = JSON.parse(readFileSync(`${paths.output}.manifest.json`, "utf8")) as Record<string, unknown>;
    assert.equal(manifest.version, 3);
    assert.equal(manifest.snapshot_schema_version, 2);
    assert.equal(manifest.tombstone_safe_after_ingest_fence, "5");
    assert.equal(manifest.deleted_session_count, 1);
    assert.equal(manifest.record_count, 1);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("stable snapshot schema v2 output remains byte-identical while the spool keeps one payload copy", async () => {
  const paths = fixture();
  try {
    state.stable = true;
    state.snapshotSchemaVersion = 2;
    state.tombstoneFence = "5";
    const laterRequest = record("request-z", "session-present", "2025-01-02T01:00:02.000000Z", "2025-01-02T01:00:03.000000Z");
    const earlierRequest = record("request-a", "session-present", "2025-01-02T01:00:00.000000Z", "2025-01-02T01:00:01.000000Z");
    state.records.set("session-present", [laterRequest, earlierRequest]);
    const result = await run(baseArguments(paths));
    assert.equal(result.code, 0, result.stderr);
    const summary = {
      _mtc_delta_type: "session_summary",
      schema_version: 2,
      session_id: "session-present",
      requests: 2,
      first_at: earlierRequest.started_at,
      last_at: laterRequest.completed_at,
      records_sha256: digestRecords([laterRequest, earlierRequest]),
    };
    const expected = Buffer.concat([canonicalLine(summary), canonicalLine(earlierRequest), canonicalLine(laterRequest)]);
    assert.deepEqual(readFileSync(paths.output), expected);
    const manifest = JSON.parse(readFileSync(`${paths.output}.manifest.json`, "utf8")) as Record<string, unknown>;
    assert.equal(manifest.output_size_bytes, expected.length);
    assert.equal(manifest.output_sha256, createHash("sha256").update(expected).digest("hex"));
    assert.equal(manifest.record_count, 2);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("stable snapshot schema and tombstone metadata fail closed", async () => {
  state.stable = true;
  state.snapshotSchemaVersion = 2;
  state.tombstoneFence = "9";
  state.fence = "10";
  state.tombstones.push({ session_id: "session-deleted", requests: 0, last_at: "2025-01-03T01:00:00.000000Z", deleted: true, deleted_at: "2025-01-03T01:00:00.000000Z" });
  const base = `http://127.0.0.1:${port}`;
  const client = new SourceClient(base, base, TOKEN, 5, true, new Set());
  await assert.rejects(client.stableSessions(10, parseTime("2025-01-01T00:00:00.000000Z", "lower bound"), undefined, "8"), /before its tombstone-safe upgrade fence/);
  state.tombstones[0]!.records_sha256 = "a".repeat(64);
  await assert.rejects(client.stableSessions(10, parseTime("2025-01-01T00:00:00.000000Z", "lower bound")), /tombstone is invalid/);
});

test("collector-direct offline baseline uses stable snapshots without CPA authorization", async () => {
  const paths = fixture();
  try {
    state.stable = true;
    state.records.set("session-direct", [record("request-direct", "session-direct", "2025-01-02T01:00:00.000000Z", "2025-01-02T01:00:01.000000Z")]);
    const result = await run([
      "--collector-direct", "--offline-full", "--base-url", `http://127.0.0.1:${port}`,
      "--private-http-host", "127.0.0.1", "--checkpoint", paths.checkpoint, "--output", paths.output,
      "--since", "1970-01-01T00:00:00Z", "--retry-base-seconds", "0.001",
    ]);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(state.directAuthorizationSeen, false);
    assert.equal(state.authorizationOnTicket, false);
    assert.equal(state.readyRequests, 1);
    const manifest = JSON.parse(readFileSync(`${paths.output}.manifest.json`, "utf8")) as Record<string, unknown>;
    assert.equal(manifest.source_mode, "collector-direct"); assert.equal(manifest.offline_full_snapshot, true);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("collector-direct waits for readiness before any archive projection read", async () => {
  const paths = fixture();
  try {
    state.ready = false; state.stable = true;
    state.records.set("session-deferred", [record("request-deferred", "session-deferred", "2025-01-02T01:00:00.000000Z", "2025-01-02T01:00:01.000000Z")]);
    let observeReady!: () => void;
    const readyRequested = new Promise<void>((resolve) => { observeReady = resolve; });
    let releaseReady!: () => void;
    state.readyGate = new Promise<void>((resolve) => { releaseReady = resolve; });
    state.onReadyRequest = observeReady;
    const resultPromise = run([
      "--collector-direct", "--offline-full", "--base-url", `http://127.0.0.1:${port}`,
      "--private-http-host", "127.0.0.1", "--checkpoint", paths.checkpoint, "--output", paths.output,
      "--since", "1970-01-01T00:00:00Z", "--readiness-timeout-seconds", "5",
    ]);
    await readyRequested;
    assert.equal(state.statsRequests, 0); assert.equal(state.sessionsRequests, 0);
    state.ready = true; releaseReady();
    const result = await resultPromise;
    assert.equal(result.code, 0, result.stderr);
    assert.equal(state.readyRequests, 1); assert(state.statsRequests > 0); assert(state.sessionsRequests > 0);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("collector readiness retries transport timeout and preparing status with a virtual clock", async () => {
  const secret = `${TOKEN}:http://secret.example/private-response-body`;
  const timeout = Object.assign(new Error(secret), { code: "ETIMEDOUT" });
  const runtime = scriptedReadinessDriver([timeout, 503, 200]);
  const base = `http://127.0.0.1:${port}`;
  const client = new SourceClient(base, base, undefined, 5, false, new Set(["127.0.0.1"]), true, 5, 0.5, 100, undefined, undefined, true);
  await client.waitUntilReady(50, 10, runtime.driver);
  assert.deepEqual(runtime.waits, [10, 10]); assert.deepEqual(runtime.probeTimeouts, [100, 90, 80]); assert.deepEqual(runtime.drains, [503, 200]);
  const diagnostic = collectorTransportDiagnostic("readyz", timeout);
  assert.equal(diagnostic, "collector request failed (stage=readyz,cause=timeout)"); assert(!diagnostic.includes(secret)); assert(!diagnostic.includes(TOKEN));
});

test("collector readiness clips every wait and probe to the overall elapsed deadline", async () => {
  const runtime = scriptedReadinessDriver([]);
  const base = `http://127.0.0.1:${port}`;
  const client = new SourceClient(base, base, undefined, 5, false, new Set(["127.0.0.1"]), true, 5, 0.5, 15, undefined, undefined, true);
  await assert.rejects(client.waitUntilReady(50, 10, runtime.driver), /stage=readyz,cause=http_503,limit=overall/);
  assert.deepEqual(runtime.probeTimeouts, [15, 5]); assert.deepEqual(runtime.waits, [10, 5]); assert.equal(runtime.clock.now, 15);
});

test("collector readiness reports its own configured deadline without wall-clock waits", async () => {
  const runtime = scriptedReadinessDriver([]);
  const base = `http://127.0.0.1:${port}`;
  const client = new SourceClient(base, base, undefined, 5, false, new Set(["127.0.0.1"]), true, 5, 0.5, 100, undefined, undefined, true);
  await assert.rejects(client.waitUntilReady(0.015, 10, runtime.driver), /stage=readyz,cause=http_503,limit=readiness/);
  assert.deepEqual(runtime.probeTimeouts, [15, 5]); assert.deepEqual(runtime.waits, [10, 5]); assert.equal(runtime.clock.now, 15);
});

test("readiness CLI bounds and legacy-only rejection fail before any network request", async () => {
  const paths = fixture();
  try {
    const direct = [
      "--collector-direct", "--offline-full", "--base-url", `http://127.0.0.1:${port}`,
      "--private-http-host", "127.0.0.1", "--checkpoint", paths.checkpoint, "--output", paths.output,
      "--since", "1970-01-01T00:00:00Z",
    ];
    for (const [flag, value, message] of [
      ["--readiness-timeout-seconds", "0", /readiness timeout seconds/],
      ["--readiness-timeout-seconds", "86401", /readiness timeout seconds/],
      ["--readiness-poll-milliseconds", "9", /readiness poll milliseconds/],
      ["--readiness-poll-milliseconds", "60001", /readiness poll milliseconds/],
      ["--chunk-seconds", "0", /chunk seconds must be greater than 0 and at most 3600/],
    ] as const) {
      const result = await run([...direct, flag, value]); assert.equal(result.code, 2); assert.match(result.stderr, message);
    }
    const legacy = await run([...baseArguments(paths), "--readiness-timeout-seconds", "30"]);
    assert.equal(legacy.code, 2); assert.match(legacy.stderr, /readiness options require --collector-direct/);
    assert.equal(state.readyRequests, 0); assert.equal(state.statsRequests, 0); assert.equal(state.sessionsRequests, 0);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("collector local snapshot and checkpoint preconditions fail before readyz", async () => {
  const paths = fixture();
  try {
    const common = [
      "--collector-direct", "--base-url", `http://127.0.0.1:${port}`, "--private-http-host", "127.0.0.1",
      "--checkpoint", paths.checkpoint, "--output", paths.output, "--since", "1970-01-01T00:00:00Z",
    ];
    const missingOffline = await run(common);
    assert.equal(missingOffline.code, 2); assert.match(missingOffline.stderr, /first collector-direct snapshot requires --offline-full/);
    assert.equal(state.readyRequests, 0); assert.equal(state.statsRequests, 0);
    writeFileSync(paths.checkpoint, "{}\n", { mode: 0o600 });
    const invalidCheckpoint = await run([...common, "--offline-full"]);
    assert.equal(invalidCheckpoint.code, 2); assert.match(invalidCheckpoint.stderr, /checkpoint does not match this source or version/);
    assert.equal(state.readyRequests, 0); assert.equal(state.statsRequests, 0); assert.equal(state.sessionsRequests, 0);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("resume seals a pending output without re-contacting the source", async () => {
  const paths = fixture();
  try {
    state.records.set("session-a", [record("request-1", "session-a", "2025-01-02T01:00:00Z", "2025-01-02T01:00:01Z")]);
    const first = await run(baseArguments(paths)); assert.equal(first.code, 0, first.stderr);
    // Simulate the crash point after manifest fsync and before pending rename/checkpoint commit.
    const pending = `${paths.output}.pending`; const bytes = readFileSync(paths.output); writeFileSync(pending, bytes, { mode: 0o600 }); rmSync(paths.output); rmSync(paths.checkpoint);
    writeFileSync(`${paths.output}.spool.sqlite-wal`, "interrupted cleanup", { mode: 0o600 });
    writeFileSync(`${paths.output}.spool.sqlite-shm`, "interrupted cleanup", { mode: 0o600 });
    state.redirects = true;
    const resumed = await run([...baseArguments(paths), "--resume"]); assert.equal(resumed.code, 0, resumed.stderr); assert.equal(state.leakCalls, 0); assert.equal(readFileSync(paths.output, "utf8"), bytes.toString());
    assert.equal(existsSync(`${paths.output}.spool.sqlite-wal`), false); assert.equal(existsSync(`${paths.output}.spool.sqlite-shm`), false);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("resume safely initializes an empty spool left before its descriptor commit", async () => {
  const paths = fixture();
  const spool = `${paths.output}.spool.sqlite`;
  try {
    state.stable = true;
    state.records.set("session-a", [record("request-a", "session-a", "2025-01-02T01:00:00.000000Z", "2025-01-02T01:00:01.000000Z")]);
    const database = new DatabaseSync(spool); database.exec(ARCHIVE_SPOOL_SCHEMA); database.close(); chmodSync(spool, 0o600);
    const resumed = await run([...baseArguments(paths), "--resume"]);
    assert.equal(resumed.code, 0, resumed.stderr); assert.equal(state.archiveRequests.get("session-a"), 1); assert.equal(existsSync(spool), false);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("stable spool resume skips previously verified sessions after a fresh snapshot", async () => {
  const paths = fixture();
  const spool = `${paths.output}.spool.sqlite`;
  try {
    state.stable = true;
    state.records.set("session-a", [record("request-a", "session-a", "2025-01-02T01:00:00.000000Z", "2025-01-02T01:00:01.000000Z")]);
    state.records.set("session-b", [record("request-b", "session-b", "2025-01-03T01:00:00.000000Z", "2025-01-03T01:00:01.000000Z")]);
    state.failedArchiveSessions.add("session-b");
    const failed = await run(baseArguments(paths));
    assert.equal(failed.code, 2); assert.match(failed.stderr, /source archive export returned HTTP 500/);
    assert.equal(existsSync(spool), true);
    assert.equal(state.archiveRequests.get("session-a"), 1); assert.equal(state.archiveRequests.get("session-b"), 1);

    state.failedArchiveSessions.clear(); state.snapshot = "snapshot-two";
    const resumed = await run([...baseArguments(paths), "--resume"]);
    assert.equal(resumed.code, 0, resumed.stderr);
    assert.match(resumed.stderr, /archive spool resume completed_sessions=1 records=1/);
    assert.equal(state.archiveRequests.get("session-a"), 1, "the verified session must not be downloaded again");
    assert.equal(state.archiveRequests.get("session-b"), 2);
    assert.equal(existsSync(spool), false);
    const requestIds = readFileSync(paths.output, "utf8").trim().split("\n").map((line) => (JSON.parse(line) as RecordValue).request_id);
    assert.deepEqual(requestIds, ["request-a", "request-b"]);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("read-only SQLite large session checkpoints a request cursor and resumes without an HTTP ticket", async () => {
  const paths = fixture();
  const source = join(paths.directory, "archive.sqlite");
  const spool = `${paths.output}.spool.sqlite`;
  try {
    const rows = writeLargeArchiveSQLite(source);
    const common = [
      "--collector-direct", "--offline-full", "--base-url", `http://127.0.0.1:${port}`, "--private-http-host", "127.0.0.1",
      "--source-sqlite", source, "--checkpoint", paths.checkpoint, "--output", paths.output, "--since", "1970-01-01T00:00:00Z",
      "--chunk-records", "8", "--chunk-bytes", "8192", "--chunk-seconds", "30",
    ];
    const interrupted = await run([...common, "--max-chunks", "3"]);
    assert.equal(interrupted.code, 2); assert.match(interrupted.stderr, /chunk budget reached/);
    assert.equal(existsSync(spool), true); assert.equal(state.archiveRequests.size, 0, "direct SQLite must not request a whole-session ticket");
    const checkpointed = new DatabaseSync(spool, { readOnly: true });
    const progress = checkpointed.prepare("SELECT record_cursor,staged_records,chunks FROM session_progress").get() as { record_cursor: string; staged_records: number; chunks: number };
    checkpointed.close();
    assert.equal(progress.chunks, 3); assert(progress.staged_records > 0 && progress.staged_records < rows.length);
    assert.equal(progress.record_cursor, rows[progress.staged_records - 1]!.request_id);

    const resumed = await run([...common, "--resume"]);
    assert.equal(resumed.code, 0, resumed.stderr); assert.match(resumed.stderr, /partial_sessions=1/);
    assert.equal(state.archiveRequests.size, 0); assert.equal(existsSync(spool), false);
    const output = readFileSync(paths.output, "utf8").trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
    assert.equal(output.length, rows.length + 1); assert.equal(output[0]!.requests, rows.length);
    assert.equal(output[0]!.records_sha256, digestRecords(rows), "the direct SQLite records must exactly match the source stable digest");
    assert.deepEqual(output.slice(1).map((item) => item.request_id), rows.map((item) => item.request_id));
    assert.equal(output[1]!.principal_alias, "Current Alias", "the newest non-empty alias for the principal must be reconstructed");
    const manifest = JSON.parse(readFileSync(`${paths.output}.manifest.json`, "utf8")) as Record<string, unknown>;
    assert.equal(manifest.source_read_mode, "sqlite-snapshot"); assert.equal(manifest.record_count, rows.length); assert.equal(manifest.session_count, 1);
    rmSync(source);
    const sealedReplay = await run([...common, "--resume"]);
    assert.equal(sealedReplay.code, 0, sealedReplay.stderr);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("read-only SQLite rejects snapshots that cannot reconstruct principal aliases", async () => {
  const paths = fixture();
  const source = join(paths.directory, "archive.sqlite");
  try {
    writeLargeArchiveSQLite(source, 1); chmodSync(source, 0o600);
    const database = new DatabaseSync(source); database.exec("DROP TABLE credential_principals"); database.close(); chmodSync(source, 0o400);
    const result = await run([
      "--collector-direct", "--offline-full", "--base-url", `http://127.0.0.1:${port}`, "--private-http-host", "127.0.0.1",
      "--source-sqlite", source, "--checkpoint", paths.checkpoint, "--output", paths.output, "--since", "1970-01-01T00:00:00Z",
    ]);
    assert.equal(result.code, 2); assert.match(result.stderr, /source SQLite snapshot schema is unsupported/);
    assert.equal(state.readyRequests, 0); assert.equal(state.archiveRequests.size, 0);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("max-chunks counts a small session tail commit and resumes from the completed session", async () => {
  const paths = fixture();
  const source = join(paths.directory, "archive.sqlite");
  const spool = `${paths.output}.spool.sqlite`;
  try {
    const rows = writeLargeArchiveSQLite(source, 3);
    const common = [
      "--collector-direct", "--offline-full", "--base-url", `http://127.0.0.1:${port}`, "--private-http-host", "127.0.0.1",
      "--source-sqlite", source, "--checkpoint", paths.checkpoint, "--output", paths.output, "--since", "1970-01-01T00:00:00Z",
      "--chunk-records", "100000", "--chunk-bytes", "1073741824", "--chunk-seconds", "3600",
    ];
    const interrupted = await run([...common, "--max-chunks", "1"]);
    assert.equal(interrupted.code, 2); assert.match(interrupted.stderr, /chunk budget reached/);
    const checkpointed = new DatabaseSync(spool, { readOnly: true });
    const counts = checkpointed.prepare("SELECT (SELECT COUNT(*) FROM completed_sessions) AS completed,(SELECT COUNT(*) FROM session_progress) AS partial,(SELECT COUNT(*) FROM records) AS records").get() as { completed: number; partial: number; records: number };
    checkpointed.close();
    assert.equal(counts.completed, 1); assert.equal(counts.partial, 0); assert.equal(counts.records, rows.length);

    const resumed = await run([...common, "--resume"]);
    assert.equal(resumed.code, 0, resumed.stderr); assert.equal(state.archiveRequests.size, 0);
    const output = readFileSync(paths.output, "utf8").trim().split("\n");
    assert.equal(output.length, rows.length + 1);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("completed large-session resume obeys the elapsed deadline and retains only its spool", async () => {
  const paths = fixture();
  const source = join(paths.directory, "archive.sqlite");
  const spool = `${paths.output}.spool.sqlite`;
  try {
    writeLargeArchiveSQLite(source, 10_000, 8192);
    const common = [
      "--collector-direct", "--offline-full", "--base-url", `http://127.0.0.1:${port}`, "--private-http-host", "127.0.0.1",
      "--source-sqlite", source, "--checkpoint", paths.checkpoint, "--output", paths.output, "--since", "1970-01-01T00:00:00Z",
      "--chunk-records", "100000", "--chunk-bytes", "1073741824", "--chunk-seconds", "3600",
    ];
    const completed = await run([...common, "--max-chunks", "1"]);
    assert.equal(completed.code, 2); assert.match(completed.stderr, /chunk budget reached/); assert.equal(existsSync(spool), true);
    const checkpointed = new DatabaseSync(spool, { readOnly: true });
    const completedSessions = checkpointed.prepare("SELECT COUNT(*) AS count FROM completed_sessions").get() as { count: number };
    checkpointed.close(); assert.equal(completedSessions.count, 1);

    const timedOut = await run([...common, "--resume", "--max-elapsed-seconds", "0.25"]);
    assert.equal(timedOut.code, 2); assert.match(timedOut.stderr, /elapsed-time limit during completed session verification/);
    assert.equal(existsSync(spool), true, "the verified spool remains resumable after the deadline");
    assert.equal(existsSync(paths.output), false); assert.equal(existsSync(`${paths.output}.pending`), false);
    assert.equal(readdirSync(paths.directory).some((name) => name.startsWith(`.${basename(paths.output)}.`)), false, "temporary JSONL output must be removed");
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("read-only legacy 3612 recovery seeds only source-verified sessions", async () => {
  const paths = fixture();
  const legacy = join(paths.directory, ".mtc-archive-delta-spool.1.1789479841474.sqlite");
  try {
    state.stable = true;
    const later = record("request-later", "session-later", "2025-01-03T01:00:00.000000Z", "2025-01-03T01:00:01.000000Z");
    const recovered = record("request-recovered", "session-recovered", "2025-01-02T01:00:00.000000Z", "2025-01-02T01:00:01.000000Z");
    // The direct fixture deliberately resolves hashed tickets to the first map
    // entry, so leave the unseeded session first and verify it is the only ticket
    // fetched by the recovery run.
    state.records.set("session-later", [later]); state.records.set("session-recovered", [recovered]);
    writeLegacy3612RecordSpool(legacy, [recovered]);
    const legacyBytes = readFileSync(legacy);

    const result = await run([...collectorBaselineArguments(paths), "--resume", "--legacy-spool", legacy]);
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stderr, /archive legacy spool recovery reused_sessions=1 reused_records=1 reused_canonical_bytes=\d+ remaining_sessions=1 remaining_records=1/);
    assert.equal(state.archiveRequests.get("session-recovered") ?? 0, 0, "a source-verified session must not be downloaded again");
    assert.equal(state.archiveRequests.get("session-later"), 1);
    assert.equal(existsSync(legacy), true); assert.deepEqual(readFileSync(legacy), legacyBytes, "the legacy source spool is read-only evidence");
    assert.equal(existsSync(`${paths.output}.spool.sqlite`), false, "only the completed new spool is cleaned up");
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("legacy 3612 recovery refuses unverified rows before creating a canonical spool", async () => {
  const paths = fixture();
  const legacy = join(paths.directory, ".mtc-archive-delta-spool.2.1789479841475.sqlite");
  try {
    state.stable = true;
    const source = record("request-source", "session-source", "2025-01-02T01:00:00.000000Z", "2025-01-02T01:00:01.000000Z");
    const mismatched = { ...source, request_id: "request-mismatched" };
    state.records.set("session-source", [source]); writeLegacy3612RecordSpool(legacy, [mismatched]);
    const legacyBytes = readFileSync(legacy);

    const result = await run([...collectorBaselineArguments(paths), "--resume", "--legacy-spool", legacy]);
    assert.equal(result.code, 2); assert.match(result.stderr, /legacy archive spool contains no source-verified completed sessions/);
    assert.equal(state.archiveRequests.size, 0);
    assert.equal(existsSync(`${paths.output}.spool.sqlite`), false);
    assert.deepEqual(readFileSync(legacy), legacyBytes);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("stable spool resume rejects a changed source projection before another archive download", async () => {
  const paths = fixture();
  const spool = `${paths.output}.spool.sqlite`;
  try {
    state.stable = true;
    state.records.set("session-a", [record("request-a", "session-a", "2025-01-02T01:00:00.000000Z", "2025-01-02T01:00:01.000000Z")]);
    state.records.set("session-b", [record("request-b", "session-b", "2025-01-03T01:00:00.000000Z", "2025-01-03T01:00:01.000000Z")]);
    state.failedArchiveSessions.add("session-b");
    const failed = await run(baseArguments(paths)); assert.equal(failed.code, 2, failed.stderr); assert.equal(existsSync(spool), true);
    const downloadsBeforeResume = [...state.archiveRequests.values()].reduce((sum, count) => sum + count, 0);

    state.failedArchiveSessions.clear();
    state.records.set("session-c", [record("request-c", "session-c", "2025-01-04T01:00:00.000000Z", "2025-01-04T01:00:01.000000Z")]);
    const resumed = await run([...baseArguments(paths), "--resume"]);
    assert.equal(resumed.code, 2); assert.match(resumed.stderr, /spool does not match the current source projection/);
    assert.equal([...state.archiveRequests.values()].reduce((sum, count) => sum + count, 0), downloadsBeforeResume);
    assert.equal(existsSync(spool), true);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("stable spool resume rejects changed download and output limits", async () => {
  const paths = fixture();
  try {
    state.stable = true;
    state.records.set("session-a", [record("request-a", "session-a", "2025-01-02T01:00:00.000000Z", "2025-01-02T01:00:01.000000Z")]);
    state.records.set("session-b", [record("request-b", "session-b", "2025-01-03T01:00:00.000000Z", "2025-01-03T01:00:01.000000Z")]);
    state.failedArchiveSessions.add("session-b");
    const limits = ["--max-download-bytes", "20000000", "--max-output-bytes", "20000000"];
    const failed = await run([...baseArguments(paths), ...limits]); assert.equal(failed.code, 2, failed.stderr);
    const downloadsBeforeResume = [...state.archiveRequests.values()].reduce((sum, count) => sum + count, 0);
    state.failedArchiveSessions.clear();
    const resumed = await run([...baseArguments(paths), "--max-download-bytes", "21000000", "--max-output-bytes", "21000000", "--resume"]);
    assert.equal(resumed.code, 2); assert.match(resumed.stderr, /spool does not match the current source projection/);
    assert.equal([...state.archiveRequests.values()].reduce((sum, count) => sum + count, 0), downloadsBeforeResume);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("stable spool resume rejects changed time projections even when counts and emit flags still match", async () => {
  const paths = fixture();
  const spool = `${paths.output}.spool.sqlite`;
  try {
    state.stable = true;
    state.records.set("session-a", [record("request-a", "session-a", "2025-01-02T01:00:00.000000Z", "2025-01-02T01:00:01.000000Z")]);
    state.records.set("session-b", [record("request-b", "session-b", "2025-01-03T01:00:00.000000Z", "2025-01-03T01:00:01.000000Z")]);
    state.failedArchiveSessions.add("session-b");
    const failed = await run(baseArguments(paths)); assert.equal(failed.code, 2, failed.stderr);
    const database = new DatabaseSync(spool);
    database.prepare("UPDATE records SET started_at='2025-01-02T00:59:59.000000Z' WHERE session_id='session-a'").run(); database.close();
    const downloadsBeforeResume = [...state.archiveRequests.values()].reduce((sum, count) => sum + count, 0);

    state.failedArchiveSessions.clear(); state.snapshot = "snapshot-two";
    const resumed = await run([...baseArguments(paths), "--resume"]);
    assert.equal(resumed.code, 2); assert.match(resumed.stderr, /spool session content failed verification/);
    assert.equal([...state.archiveRequests.values()].reduce((sum, count) => sum + count, 0), downloadsBeforeResume);
    assert.equal(existsSync(spool), true);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("stable spool resume recomputes the completed session digest after internally consistent row tampering", async () => {
  const paths = fixture();
  const spool = `${paths.output}.spool.sqlite`;
  try {
    state.stable = true;
    const original = record("request-a", "session-a", "2025-01-02T01:00:00.000000Z", "2025-01-02T01:00:01.000000Z");
    state.records.set("session-a", [original]);
    state.records.set("session-b", [record("request-b", "session-b", "2025-01-03T01:00:00.000000Z", "2025-01-03T01:00:01.000000Z")]);
    state.failedArchiveSessions.add("session-b");
    const failed = await run(baseArguments(paths)); assert.equal(failed.code, 2, failed.stderr);
    const tampered = canonicalLine({ ...original, model: "tampered-model" });
    const database = new DatabaseSync(spool);
    database.prepare("UPDATE records SET canonical=?,digest=? WHERE session_id='session-a'").run(tampered, createHash("sha256").update(tampered).digest("hex"));
    database.close();
    const downloadsBeforeResume = [...state.archiveRequests.values()].reduce((sum, count) => sum + count, 0);

    state.failedArchiveSessions.clear(); state.snapshot = "snapshot-two";
    const resumed = await run([...baseArguments(paths), "--resume"]);
    assert.equal(resumed.code, 2); assert.match(resumed.stderr, /spool session content failed verification/);
    assert.equal([...state.archiveRequests.values()].reduce((sum, count) => sum + count, 0), downloadsBeforeResume);
    assert.equal(existsSync(spool), true);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("legacy spool resume rebuilds unverifiable scratch instead of deadlocking retries", async () => {
  const paths = fixture();
  const spool = `${paths.output}.spool.sqlite`;
  try {
    const row = record("request-legacy", "session-legacy", "2025-01-02T01:00:00Z", "2025-01-02T01:00:01Z");
    state.records.set("session-legacy", [row]);
    const projection = sessions(state);
    const base = `http://127.0.0.1:${port}`;
    const fingerprint = sourceFingerprint(new SourceClient(base, base, TOKEN, 60, true, new Set()));
    const descriptor = canonicalBytes({
      version: 1,
      source_fingerprint: fingerprint,
      sequence: 1,
      prior_watermark_completed_at: "2025-01-01T00:00:00.000000Z",
      prior_source_ingest_fence: null,
      lower_bound_completed_at: "2024-12-31T00:00:00.000000Z",
      session_projection_protocol: "legacy-last-at-limit-v1",
      source_projection_requests: 1,
      session_count: 1,
      session_set_sha256: selectionDigest(projection),
      snapshot_schema_version: null,
      deleted_session_count: 0,
      offline_full_snapshot: false,
      max_line_bytes: 16 * 1024 * 1024,
      max_future_skew_seconds: 3600,
      max_download_bytes: 64 * 1024 ** 3,
      max_output_bytes: 64 * 1024 ** 3,
      stable_source_required: false,
    }).toString();
    const database = new DatabaseSync(spool);
    database.exec(ARCHIVE_SPOOL_SCHEMA);
    database.prepare("INSERT INTO spool_metadata(id,descriptor_json) VALUES(1,?)").run(descriptor);
    const encoded = canonicalLine(row);
    database.prepare("INSERT INTO records VALUES(?,?,?,?,?,?,1)").run(row.request_id, row.session_id, row.started_at, row.completed_at, createHash("sha256").update(encoded).digest("hex"), encoded);
    database.close(); chmodSync(spool, 0o600);

    const resumed = await run([...baseArguments(paths), "--resume"]);
    assert.equal(resumed.code, 0, resumed.stderr);
    assert.match(resumed.stderr, /archive spool resume legacy_rebuild=true records_discarded=1/);
    assert.equal(state.archiveRequests.get("session-legacy"), 1);
    assert.equal(existsSync(spool), false);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("redirects are refused and management credentials never cross the boundary", async () => {
  const paths = fixture();
  try {
    state.redirects = true;
    const result = await run(baseArguments(paths));
    assert.equal(result.code, 2); assert.match(result.stderr, /source request returned HTTP 302/); assert.equal(state.leakCalls, 0); assert(!result.stderr.includes(TOKEN));
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("single-table de-duplication fails closed on a conflicting request identity", async () => {
  const paths = fixture();
  try {
    state.stable = true;
    state.snapshotSchemaVersion = 2;
    state.tombstoneFence = "5";
    state.records.set("session-a", [record("request-shared", "session-a", "2025-01-02T01:00:00.000000Z", "2025-01-02T01:00:01.000000Z")]);
    state.records.set("session-b", [record("request-shared", "session-b", "2025-01-03T01:00:00.000000Z", "2025-01-03T01:00:01.000000Z")]);
    const result = await run(baseArguments(paths));
    assert.equal(result.code, 2);
    assert.match(result.stderr, /conflicting archive records/);
    assert.equal(existsSync(paths.output), false);
    assert.equal(existsSync(`${paths.output}.manifest.json`), false);
    assert.equal(existsSync(paths.checkpoint), false);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("duplicate JSON keys and foreign session records fail closed", async () => {
  const paths = fixture();
  try {
    state.records.set("session-a", [{ ...record("request-1", "session-foreign", "2025-01-02T01:00:00Z", "2025-01-02T01:00:01Z"), session_id: "session-foreign" }]);
    // Session summaries use the map key while the archive row asserts a foreign identity.
    const result = await run(baseArguments(paths)); assert.equal(result.code, 2); assert.match(result.stderr, /foreign session record/);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});
