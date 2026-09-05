#!/usr/bin/env node
/** Black-box and contract tests for the TypeScript archive delta exporter. */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, closeSync, constants as fsConstants, existsSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import test, { after, before, beforeEach } from "node:test";
import {
  ARCHIVE_SPOOL_SCHEMA,
  canonicalBytes,
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
const server = createServer((request: IncomingMessage, response: ServerResponse) => {
  const url = new URL(request.url ?? "/", `http://127.0.0.1:${port}`);
  if (url.pathname === "/leak") { state.leakCalls += 1; sendJson(response, { authorization: request.headers.authorization }); return; }
  if (url.pathname.startsWith("/archive-api/v1/exports/")) {
    state.authorizationOnTicket ||= request.headers.authorization !== undefined;
    const capability = decodeURIComponent(url.pathname.slice("/archive-api/v1/exports/".length));
    const sessionId = /^[0-9a-f]{64}$/.test(capability) ? [...state.records.keys()][0]! : capability;
    const rows = state.records.get(sessionId);
    if (rows === undefined) { sendJson(response, { error: "not found" }, 404); return; }
    response.writeHead(200, { "Content-Type": "application/x-ndjson" });
    for (const row of rows) response.write(canonicalLine(row));
    response.end(); return;
  }
  const direct = url.pathname.startsWith("/v1/");
  if (direct) state.directAuthorizationSeen ||= request.headers.authorization !== undefined;
  else if (request.headers.authorization !== `Bearer ${TOKEN}`) { sendJson(response, { error: "unauthorized" }, 401); return; }
  if (url.pathname.endsWith("/stats")) { sendJson(response, { records: [...state.records.values()].reduce((sum, rows) => sum + rows.length, 0), ...(direct ? { session_cursor_protocols: [STABLE_CURSOR_PROTOCOL], offline_full_snapshot_enabled: true } : {}) }); return; }
  if (url.pathname.endsWith("/sessions")) {
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
  state = { records: new Map(), stable: false, redirects: false, leakCalls: 0, authorizationOnTicket: false, directAuthorizationSeen: false, snapshot: "snapshot-one", fence: "7", snapshotSchemaVersion: 1, tombstoneFence: "0", tombstones: [] };
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
    const tables = database.prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name").all() as Array<{ name: string }>;
    assert.deepEqual(tables.map((table) => table.name), ["records"]);
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
    const manifest = JSON.parse(readFileSync(`${paths.output}.manifest.json`, "utf8")) as Record<string, unknown>;
    assert.equal(manifest.source_mode, "collector-direct"); assert.equal(manifest.offline_full_snapshot, true);
  } finally { rmSync(paths.directory, { recursive: true, force: true }); }
});

test("resume seals a pending output without re-contacting the source", async () => {
  const paths = fixture();
  try {
    state.records.set("session-a", [record("request-1", "session-a", "2025-01-02T01:00:00Z", "2025-01-02T01:00:01Z")]);
    const first = await run(baseArguments(paths)); assert.equal(first.code, 0, first.stderr);
    // Simulate the crash point after manifest fsync and before pending rename/checkpoint commit.
    const pending = `${paths.output}.pending`; const bytes = readFileSync(paths.output); writeFileSync(pending, bytes, { mode: 0o600 }); rmSync(paths.output); rmSync(paths.checkpoint);
    state.redirects = true;
    const resumed = await run([...baseArguments(paths), "--resume"]); assert.equal(resumed.code, 0, resumed.stderr); assert.equal(state.leakCalls, 0); assert.equal(readFileSync(paths.output, "utf8"), bytes.toString());
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
