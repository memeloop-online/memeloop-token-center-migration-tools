#!/usr/bin/env node
/**
 * An auditable, plan-first refund tool for terminal requests that were
 * recorded as billed. Request rows and their original usage ledger rows are
 * immutable: this command only appends a linked refund ledger row and updates
 * mutable balance/budget projections after a human-approved plan is applied.
 */

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  accessSync,
  closeSync,
  constants as fsConstants,
  lstatSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseStrictJson, StrictJsonError } from "./lib/strict-json.ts";
import { invokedAsEntrypoint } from "./lib/invoked-as-entrypoint.ts";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const planSchema = "failed-request-cost-adjustment-plan-v1";
const maxPlanBytes = 1_000_000;
const defaultStatusCodes = [499, 502, 503] as const;

class CliError extends Error {
  constructor(message: string, readonly exitCode = 2) { super(message); }
}

function fail(message: string, exitCode = 2): never { throw new CliError(message, exitCode); }

function required(name: string): string {
  const value = process.env[name];
  if (!value) fail(`${name} is required`);
  if (value.includes("\0") || /[\r\n]/u.test(value)) fail(`${name} must be a single line`);
  return value;
}

function decimal(name: string): string {
  const value = required(name);
  if (!/^\d+$/u.test(value)) fail(`${name} must be an integer`);
  return value;
}

function port(): string {
  const value = process.env.FRA_PGPORT ?? "5432";
  if (!/^\d+$/u.test(value) || BigInt(value) === 0n || BigInt(value) > 65535n) {
    fail("FRA_PGPORT must be an integer between 1 and 65535");
  }
  return value;
}

function passFile(): string {
  const value = required("FRA_PGPASSFILE");
  try {
    const metadata = lstatSync(value);
    accessSync(value, fsConstants.R_OK);
    if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o777) !== 0o600) {
      fail("FRA_PGPASSFILE must be a readable regular non-symlink file with mode 0600");
    }
  } catch (error) {
    if (error instanceof CliError) throw error;
    fail("FRA_PGPASSFILE must be a readable regular non-symlink file with mode 0600");
  }
  return value;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function readSql(name: string): string {
  return readFileSync(join(scriptDirectory, "sql", "failed-request-adjustments", name), "utf8");
}

function statusCodes(): number[] {
  const raw = process.env.FRA_STATUS_CODES ?? defaultStatusCodes.join(",");
  const values = raw.split(",").map((value) => value.trim());
  if (values.length === 0 || values.some((value) => !/^\d{3}$/u.test(value))) {
    fail("FRA_STATUS_CODES must be a comma-separated list of HTTP status codes");
  }
  const codes = values.map(Number);
  if (codes.some((code) => code < 400 || code > 599) || new Set(codes).size !== codes.length) {
    fail("FRA_STATUS_CODES must contain unique status codes from 400 through 599");
  }
  return codes.sort((left, right) => left - right);
}

function psql(extra: readonly string[], input: string): string {
  const result = spawnSync("psql", ["-X", "--no-psqlrc", "-v", "ON_ERROR_STOP=1", "-At", ...extra], {
    encoding: "utf8",
    env: {
      ...process.env,
      PGHOST: required("FRA_PGHOST"),
      PGPORT: port(),
      PGUSER: required("FRA_PGUSER"),
      PGDATABASE: required("FRA_PGDATABASE"),
      PGPASSFILE: passFile(),
    },
    input,
    shell: false,
    stdio: ["pipe", "pipe", "pipe"],
  });
  if (result.error) fail(`psql is unavailable: ${result.error.message}`);
  if (result.status !== 0) {
    const diagnostic = String(result.stderr).trim().replace(/\s+/gu, " ").slice(0, 500);
    fail(diagnostic ? `PostgreSQL command failed: ${diagnostic}` : "PostgreSQL command failed", 1);
  }
  return String(result.stdout).trim();
}

type Candidate = Readonly<{
  request_id: string;
  request_created_at: string;
  tenant_id: string;
  key_id: string;
  account_id: string;
  reservation_id: string;
  usage_ledger_id: string;
  usage_ledger_created_at: string;
  status_code: string;
  currency: string;
  refund_micros: string;
}>;

type Scope = Readonly<{
  tenant_external_id: string;
  from_ms: string;
  to_ms: string;
  status_codes: readonly number[];
}>;

type Blocker = Readonly<{ reason: string; count: string }>;

type PlanBody = Readonly<{
  schema_version: typeof planSchema;
  scope: Scope;
  candidates: readonly Candidate[];
  blockers: readonly Blocker[];
}>;

type Plan = PlanBody & Readonly<{ plan_sha256: string }>;

function record(value: unknown, message: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail(message);
  return value as Record<string, unknown>;
}

function text(value: unknown, message: string, pattern = /^[^\r\n\0]{1,512}$/u): string {
  if (typeof value !== "string" || !pattern.test(value)) fail(message);
  return value;
}

function unsigned(value: unknown, message: string, positive = false): string {
  const output = text(value, message, /^\d+$/u);
  if (positive && BigInt(output) === 0n) fail(message);
  return output;
}

function candidate(value: unknown): Candidate {
  const input = record(value, "plan candidate must be an object");
  const known = ["request_id", "request_created_at", "tenant_id", "key_id", "account_id", "reservation_id", "usage_ledger_id", "usage_ledger_created_at", "status_code", "currency", "refund_micros"];
  if (Object.keys(input).length !== known.length || known.some((key) => !(key in input))) fail("plan candidate has unsupported fields");
  const result: Candidate = {
    request_id: text(input.request_id, "plan request ID is invalid"),
    request_created_at: unsigned(input.request_created_at, "plan request timestamp is invalid"),
    tenant_id: text(input.tenant_id, "plan tenant ID is invalid"),
    key_id: text(input.key_id, "plan key ID is invalid"),
    account_id: text(input.account_id, "plan account ID is invalid"),
    reservation_id: text(input.reservation_id, "plan reservation ID is invalid"),
    usage_ledger_id: text(input.usage_ledger_id, "plan usage ledger ID is invalid"),
    usage_ledger_created_at: unsigned(input.usage_ledger_created_at, "plan usage ledger timestamp is invalid"),
    status_code: unsigned(input.status_code, "plan status code is invalid"),
    currency: text(input.currency, "plan currency is invalid", /^[A-Z]{3}$/u),
    refund_micros: unsigned(input.refund_micros, "plan refund amount is invalid", true),
  };
  if (BigInt(result.status_code) < 400n || BigInt(result.status_code) > 599n) fail("plan status code is invalid");
  return result;
}

function planBody(value: unknown): PlanBody {
  const input = record(value, "plan body must be an object");
  const known = ["schema_version", "scope", "candidates", "blockers"];
  if (Object.keys(input).length !== known.length || known.some((key) => !(key in input)) || input.schema_version !== planSchema) {
    fail("plan body schema is unsupported");
  }
  const rawScope = record(input.scope, "plan scope is invalid");
  const scopeKeys = ["tenant_external_id", "from_ms", "to_ms", "status_codes"];
  if (Object.keys(rawScope).length !== scopeKeys.length || scopeKeys.some((key) => !(key in rawScope))) fail("plan scope is invalid");
  if (!Array.isArray(rawScope.status_codes) || rawScope.status_codes.length === 0) fail("plan status codes are invalid");
  const scope: Scope = {
    tenant_external_id: text(rawScope.tenant_external_id, "plan tenant is invalid"),
    from_ms: unsigned(rawScope.from_ms, "plan start time is invalid"),
    to_ms: unsigned(rawScope.to_ms, "plan end time is invalid"),
    status_codes: rawScope.status_codes.map((value) => {
      if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 400 || value > 599) fail("plan status codes are invalid");
      return value;
    }),
  };
  if (BigInt(scope.from_ms) >= BigInt(scope.to_ms) || new Set(scope.status_codes).size !== scope.status_codes.length) fail("plan scope is invalid");
  if (!Array.isArray(input.candidates) || input.candidates.length > 10_000) fail("plan candidates are invalid");
  const candidates = input.candidates.map(candidate);
  const requests = new Set(candidates.map((entry) => entry.request_id));
  const ledgers = new Set(candidates.map((entry) => entry.usage_ledger_id));
  if (requests.size !== candidates.length || ledgers.size !== candidates.length) fail("plan contains duplicate request or usage ledger IDs");
  if (candidates.some((entry) => !scope.status_codes.includes(Number(entry.status_code)))) fail("plan candidate status is outside its scope");
  if (!Array.isArray(input.blockers) || input.blockers.length > 100) fail("plan blockers are invalid");
  const blockers = input.blockers.map((value) => {
    const blocker = record(value, "plan blocker is invalid");
    if (Object.keys(blocker).length !== 2 || !("reason" in blocker) || !("count" in blocker)) fail("plan blocker is invalid");
    return { reason: text(blocker.reason, "plan blocker is invalid"), count: unsigned(blocker.count, "plan blocker is invalid", true) };
  }).sort((left, right) => left.reason.localeCompare(right.reason));
  if (new Set(blockers.map((blocker) => blocker.reason)).size !== blockers.length) fail("plan contains duplicate blockers");
  return { schema_version: planSchema, scope: { ...scope, status_codes: [...scope.status_codes] }, candidates, blockers };
}

function parsePlan(source: string): Plan {
  if (Buffer.byteLength(source, "utf8") > maxPlanBytes) fail("plan file exceeds the 1 MB safety limit");
  let parsed: unknown;
  try { parsed = parseStrictJson(source); } catch (error) {
    if (error instanceof StrictJsonError) fail("plan file is not valid strict JSON");
    throw error;
  }
  const input = record(parsed, "plan file must be an object");
  const known = ["schema_version", "scope", "candidates", "blockers", "plan_sha256"];
  if (Object.keys(input).length !== known.length || known.some((key) => !(key in input))) fail("plan file has unsupported fields");
  const body = planBody({ schema_version: input.schema_version, scope: input.scope, candidates: input.candidates, blockers: input.blockers });
  const digest = text(input.plan_sha256, "plan digest is invalid", /^[a-f0-9]{64}$/u);
  if (sha256(JSON.stringify(body)) !== digest) fail("plan digest does not match its approved contents");
  return { ...body, plan_sha256: digest };
}

function writePlan(path: string, plan: Plan): void {
  const target = resolve(path);
  const serialized = `${JSON.stringify(plan)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > maxPlanBytes) fail("plan exceeds the 1 MB safety limit; use a narrower time range");
  let descriptor: number | undefined;
  try {
    descriptor = openSync(target, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    writeFileSync(descriptor, serialized, { encoding: "utf8" });
  } catch (error) {
    if (error instanceof CliError) throw error;
    fail("plan output must be a new writable path; existing files are never overwritten");
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function readPlan(path: string): Plan {
  try {
    const metadata = lstatSync(path);
    accessSync(path, fsConstants.R_OK);
    if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o777) !== 0o600) {
      fail("approved plan must be a readable regular non-symlink file with mode 0600");
    }
    return parsePlan(readFileSync(path, "utf8"));
  } catch (error) {
    if (error instanceof CliError) throw error;
    fail("approved plan must be a readable regular non-symlink file with mode 0600");
  }
}

function parsedPsqlJson(output: string): Record<string, unknown> {
  try { return record(parseStrictJson(output), "PostgreSQL returned an invalid receipt"); } catch (error) {
    if (error instanceof CliError) throw error;
    fail("PostgreSQL returned an invalid receipt");
  }
}

function canonicalPlan(scope: Scope, raw: Record<string, unknown>): { plan: Plan; blockers: readonly { reason: string; count: string }[]; receipt: Record<string, unknown> } {
  const rawCandidates = raw.eligible_candidates;
  if (!Array.isArray(rawCandidates)) fail("PostgreSQL plan receipt has invalid candidates");
  const candidates = rawCandidates.map(candidate).sort((left, right) => left.request_id.localeCompare(right.request_id));
  const rawBlockers = raw.blockers;
  if (!Array.isArray(rawBlockers)) fail("PostgreSQL plan receipt has invalid blockers");
  const blockers = rawBlockers.map((value) => {
    const item = record(value, "PostgreSQL plan blocker is invalid");
    return { reason: text(item.reason, "PostgreSQL plan blocker is invalid"), count: unsigned(item.count, "PostgreSQL plan blocker is invalid", true) };
  }).sort((left, right) => left.reason.localeCompare(right.reason));
  const body: PlanBody = { schema_version: planSchema, scope, candidates, blockers };
  return { plan: { ...body, plan_sha256: sha256(JSON.stringify(body)) }, blockers, receipt: raw };
}

function planMode(): void {
  const scope: Scope = {
    tenant_external_id: required("FRA_TENANT_EXTERNAL_ID"),
    from_ms: decimal("FRA_FROM_MS"),
    to_ms: decimal("FRA_TO_MS"),
    status_codes: statusCodes(),
  };
  if (BigInt(scope.from_ms) >= BigInt(scope.to_ms)) fail("FRA_FROM_MS must be before FRA_TO_MS");
  const raw = parsedPsqlJson(psql([
    "-v", `tenant_external_id=${scope.tenant_external_id}`,
    "-v", `from_ms=${scope.from_ms}`,
    "-v", `to_ms=${scope.to_ms}`,
    "-v", `status_codes=${scope.status_codes.join(",")}`,
  ], readSql("plan.sql")));
  const result = canonicalPlan(scope, raw);
  const path = required("FRA_PLAN_OUTPUT");
  writePlan(path, result.plan);
  const refundMicros = result.plan.candidates.reduce((total, entry) => total + BigInt(entry.refund_micros), 0n).toString();
  process.stdout.write(`${JSON.stringify({
    schema_version: planSchema,
    mode: "plan",
    outcome: result.blockers.length === 0 ? "ready_for_approval" : "blocked",
    plan_sha256: result.plan.plan_sha256,
    plan_output: resolve(path),
    scope: { tenant_external_id_sha256: sha256(scope.tenant_external_id), from_ms: scope.from_ms, to_ms: scope.to_ms, status_codes: scope.status_codes },
    candidate_count: String(result.plan.candidates.length),
    refund_micros: refundMicros,
    blockers: result.blockers,
    receipt: result.receipt,
  })}\n`);
  if (result.blockers.length > 0) process.exitCode = 1;
}

function applyMode(): void {
  if (process.env.FRA_APPLY_CONFIRM !== "APPLY_FAILED_REQUEST_COST_ADJUSTMENTS") {
    fail("FRA_APPLY_CONFIRM=APPLY_FAILED_REQUEST_COST_ADJUSTMENTS is required");
  }
  const approvalReference = required("FRA_APPROVAL_REFERENCE");
  if (!/^[A-Za-z0-9._:-]{1,160}$/u.test(approvalReference)) fail("FRA_APPROVAL_REFERENCE is invalid");
  const plan = readPlan(required("FRA_APPROVED_PLAN"));
  if (plan.blockers.length > 0) fail("approved plan contains unresolved accounting blockers");
  const output = parsedPsqlJson(psql([
    "-v", `plan_sha256=${plan.plan_sha256}`,
    "-v", `approval_reference=${approvalReference}`,
    "-v", `now_ms=${Date.now()}`,
    "-v", `plan_json=${JSON.stringify(plan)}`,
  ], readSql("apply.sql")));
  process.stdout.write(`${JSON.stringify({ schema_version: planSchema, mode: "apply", plan_sha256: plan.plan_sha256, receipt: output })}\n`);
}

function verifyMode(): void {
  const output = parsedPsqlJson(psql([
    "-v", `tenant_external_id=${required("FRA_TENANT_EXTERNAL_ID")}`,
  ], readSql("verify.sql")));
  process.stdout.write(`${JSON.stringify({ schema_version: planSchema, mode: "verify", receipt: output })}\n`);
  if (output.outcome !== "pass") process.exitCode = 1;
}

function rebuildDerivedMode(): void {
  if (process.env.FRA_DERIVED_CONFIRM !== "REBUILD_FAILED_REQUEST_ADJUSTMENT_DAILY") {
    fail("FRA_DERIVED_CONFIRM=REBUILD_FAILED_REQUEST_ADJUSTMENT_DAILY is required");
  }
  const tenantExternalId = required("FRA_TENANT_EXTERNAL_ID");
  const output = parsedPsqlJson(psql([
    "-v", `tenant_external_id=${tenantExternalId}`,
    "-v", `now_ms=${Date.now()}`,
  ], readSql("rebuild-derived.sql")));
  process.stdout.write(`${JSON.stringify({ schema_version: planSchema, mode: "rebuild-derived", receipt: output })}\n`);
}

function usage(): void {
  process.stdout.write("Usage: node ops/adjust-failed-request-costs.ts --plan | --apply | --rebuild-derived | --verify\n");
}

async function main(): Promise<void> {
  const [mode] = process.argv.slice(2);
  if (mode === "--help") return usage();
  if (mode === "--plan") return planMode();
  if (mode === "--apply") return applyMode();
  if (mode === "--rebuild-derived") return rebuildDerivedMode();
  if (mode === "--verify") return verifyMode();
  fail("choose exactly one mode: --plan, --apply, --rebuild-derived, or --verify");
}

if (invokedAsEntrypoint("adjust-failed-request-costs", import.meta.url)) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = error instanceof CliError ? error.exitCode : 1;
  });
}
