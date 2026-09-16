#!/usr/bin/env node
/**
 * Apply an immutable failed-billing plan through the settlement-adjustment API.
 *
 * The command is deliberately dry-run by default.  A write requires all of:
 * an audit receipt file with mode 0600, the expected plan row/amount totals, a
 * matching approved SHA-256 plan digest, an HTTPS API base, an explicitly
 * opted-in write flag, and a service token supplied only through the process
 * environment.  It never updates request, reservation, fact, feed, or
 * aggregate tables directly; after every bounded batch it verifies those
 * immutable sources and the adjustment event/ledger trail with read-only SQL.
 */

import { accessSync, constants as fsConstants, lstatSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { invokedAsEntrypoint } from "./lib/invoked-as-entrypoint.ts";

const NAMESPACE = "memeloop-cloud:usage-discount";
const DEFAULT_SOURCE_PREFIX = "failed-billing-zero-v1:";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

class CliError extends Error {
  readonly exitCode: number;

  constructor(message: string, exitCode = 2) {
    super(message);
    this.exitCode = exitCode;
  }
}

function fail(message: string, exitCode = 2): never {
  throw new CliError(message, exitCode);
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) fail(`${name} is required`);
  if (value.includes("\0") || /[\r\n]/u.test(value)) fail(`${name} must be a single line`);
  return value;
}

function optional(name: string): string {
  const value = process.env[name] ?? "";
  if (value.includes("\0") || /[\r\n]/u.test(value)) fail(`${name} must be a single line`);
  return value;
}

function positiveInteger(name: string, fallback: string, maximum?: number): number {
  const raw = process.env[name] ?? fallback;
  if (!/^\d+$/u.test(raw) || BigInt(raw) === 0n) fail(`${name} must be a positive integer`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || (maximum !== undefined && value > maximum)) {
    fail(`${name} is outside the supported range`);
  }
  return value;
}

function psqlPassFile(): string {
  const value = required("FAILED_BILLING_PGPASSFILE");
  try {
    const metadata = lstatSync(value);
    accessSync(value, fsConstants.R_OK);
    if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o777) !== 0o600) {
      fail("FAILED_BILLING_PGPASSFILE must be a readable regular non-symlink file with mode 0600");
    }
  } catch (error) {
    if (error instanceof CliError) throw error;
    fail("FAILED_BILLING_PGPASSFILE must be a readable regular non-symlink file with mode 0600");
  }
  return value;
}

function protectedPlanFile(): string {
  const value = required("FAILED_BILLING_PLAN_FILE");
  try {
    const metadata = lstatSync(value);
    accessSync(value, fsConstants.R_OK);
    if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o777) !== 0o600) {
      fail("FAILED_BILLING_PLAN_FILE must be a readable regular non-symlink file with mode 0600");
    }
  } catch (error) {
    if (error instanceof CliError) throw error;
    fail("FAILED_BILLING_PLAN_FILE must be a readable regular non-symlink file with mode 0600");
  }
  return value;
}

type JsonRecord = Record<string, unknown>;

function record(value: unknown, name: string): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail(`invalid ${name}`, 1);
  return value as JsonRecord;
}

function stringValue(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0") || /[\r\n]/u.test(value)) {
    fail(`invalid ${name}`, 1);
  }
  return value;
}

function integerString(value: unknown, name: string): string {
  const parsed = stringValue(value, name);
  if (!/^-?\d+$/u.test(parsed)) fail(`invalid ${name}`, 1);
  return parsed;
}

function nonnegativeInteger(value: unknown, name: string): string {
  const parsed = integerString(value, name);
  if (parsed.startsWith("-")) fail(`invalid ${name}`, 1);
  return parsed;
}

function nonnegativeMoney(value: unknown, name: string): string {
  const parsed = stringValue(value, name);
  if (!/^\d+(?:\.\d{1,6})?$/u.test(parsed)) fail(`invalid ${name}`, 1);
  return parsed;
}

function nullableNonnegativeInteger(value: unknown, name: string): string | null {
  return value === null ? null : nonnegativeInteger(value, name);
}

function uuid(value: unknown, name: string): string {
  const parsed = stringValue(value, name).toLowerCase();
  if (!UUID.test(parsed)) fail(`invalid ${name}`, 1);
  return parsed;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function stable(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("non-finite value in plan", 1);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${stable(object[key])}`).join(",")}}`;
  }
  fail("unsupported value in plan", 1);
}

function microsToDecimal(micros: string): string {
  const value = BigInt(micros);
  if (value < 0n) fail("rebate micros cannot be negative", 1);
  const units = value / 1_000_000n;
  const fraction = (value % 1_000_000n).toString().padStart(6, "0").replace(/0+$/u, "");
  return fraction ? `${units}.${fraction}` : units.toString();
}

function decimalToMicros(value: unknown, name: string): string {
  const parsed = nonnegativeMoney(value, name);
  const [whole, fraction = ""] = parsed.split(".");
  return (BigInt(whole) * 1_000_000n + BigInt(fraction.padEnd(6, "0"))).toString();
}

type Candidate = {
  requestId: string;
  createdAt: string;
  statusCode: string;
  errorCode: string;
  protocol: string;
  model: string;
  currency: string;
  reservationId: string;
  accountId: string;
  settlementId: string;
  costMicros: string;
  idempotencyKey: string;
  decisionDigest: string;
};

type Plan = {
  candidates: Candidate[];
  planSha256: string;
  totalMicros: string;
  source: string;
  dayBuckets: string[];
  hourBuckets: string[];
  scope: JsonRecord;
  expectedPreviewRows: string;
  expectedSafeRows: string;
  expectedSafeMicros: string;
  expectedBoundRows: string;
  expectedProviderRows: string;
  expectedNullableBasisRows: string;
};

type PreviewSummary = {
  pages: string;
  preview_rows: string;
  safe_rows: string;
  safe_micros: string;
  bound_rows: string;
  invariant_mismatch_rows: string;
  excluded_provider_reported_rows: string;
  excluded_nullable_basis_rows: string;
};

function planCandidate(raw: unknown): Candidate {
  const value = record(raw, "repair candidate");
  const requestId = uuid(value.request_id, "repair candidate request_id");
  const createdAt = nonnegativeInteger(value.created_at, `${requestId}.created_at`);
  const statusCode = integerString(value.status_code, `${requestId}.status_code`);
  if (Number(statusCode) < 400) fail(`${requestId} is not a failed request`, 1);
  const errorCode = stringValue(value.error_code, `${requestId}.error_code`);
  const protocol = stringValue(value.protocol, `${requestId}.protocol`);
  if (protocol === "audio-transcription") fail(`${requestId} is not a text request`, 1);
  const model = stringValue(value.model, `${requestId}.model`);
  const currency = stringValue(value.currency, `${requestId}.currency`).toUpperCase();
  if (!/^[A-Z]{3}$/u.test(currency)) fail(`${requestId} has invalid currency`, 1);
  const reservationId = uuid(value.reservation_id, `${requestId}.reservation_id`);
  const accountId = uuid(value.account_id, `${requestId}.account_id`);
  const settlementId = uuid(value.settlement_id, `${requestId}.settlement_id`);
  const old = record(value.old, `${requestId}.old`);
  const proposed = record(value.proposed, `${requestId}.proposed`);
  const archive = record(value.archive, `${requestId}.archive`);
  const invariants = record(value.invariants, `${requestId}.invariants`);
  const repair = record(value.repair, `${requestId}.repair`);
  if (old.usage_basis !== "contract_ceiling") fail(`${requestId} is not contract_ceiling`, 1);
  const costMicros = nonnegativeInteger(old.cost_micros, `${requestId}.old.cost_micros`);
  if (BigInt(costMicros) <= 0n) fail(`${requestId} has no positive rebate`, 1);
  if (proposed.usage_basis !== "not_observed" || proposed.cost_micros !== "0") fail(`${requestId} proposed state is unsafe`, 1);
  if (value.provider_evidence !== "none_observed" || archive.response_state !== "gap" || archive.response_available !== false) {
    fail(`${requestId} has provider/archive evidence`, 1);
  }
  for (const key of ["reservation_settled", "reservation_actual_matches_cost", "usage_ledger_unique", "usage_ledger_matches_cost", "settlement_feed_matches_cost", "request_stats_fact_matches_cost"]) {
    if (invariants[key] !== true) fail(`${requestId} invariant ${key} is not true`, 1);
  }
  const idempotencyKey = stringValue(repair.idempotency_key, `${requestId}.repair.idempotency_key`);
  if (idempotencyKey !== `${DEFAULT_SOURCE_PREFIX}${requestId}`) fail(`${requestId} idempotency key is not the reviewed key`, 1);
  if (repair.desired_rebate_micros !== costMicros) fail(`${requestId} desired rebate differs from old cost`, 1);
  const evidence = {
    request_id: requestId,
    created_at: createdAt,
    status_code: statusCode,
    error_code: errorCode,
    protocol,
    model,
    currency,
    reservation_id: reservationId,
    account_id: accountId,
    settlement_id: settlementId,
    old: {
      usage_basis: old.usage_basis,
      cost_micros: costMicros,
      input_tokens: nullableNonnegativeInteger(old.input_tokens, `${requestId}.old.input_tokens`),
      cached_input_tokens: nullableNonnegativeInteger(old.cached_input_tokens, `${requestId}.old.cached_input_tokens`),
      cache_write_tokens: nullableNonnegativeInteger(old.cache_write_tokens, `${requestId}.old.cache_write_tokens`),
      output_tokens: nullableNonnegativeInteger(old.output_tokens, `${requestId}.old.output_tokens`),
    },
    proposed: { usage_basis: proposed.usage_basis, cost_micros: proposed.cost_micros },
    provider_evidence: value.provider_evidence,
    archive: {
      response_state: archive.response_state,
      response_available: archive.response_available,
      response_chunk_count: nonnegativeInteger(archive.response_chunk_count, `${requestId}.archive.response_chunk_count`),
      response_byte_count: nonnegativeInteger(archive.response_byte_count, `${requestId}.archive.response_byte_count`),
      response_bound_locator_present: archive.response_bound_locator_present,
      request_state: archive.request_state,
    },
    invariants,
    repair: { action: repair.action, desired_rebate_micros: costMicros, idempotency_key: idempotencyKey, reversible: repair.reversible },
  };
  return {
    requestId,
    createdAt,
    statusCode,
    errorCode,
    protocol,
    model,
    currency,
    reservationId,
    accountId,
    settlementId,
    costMicros,
    idempotencyKey,
    decisionDigest: sha256(stable(evidence)),
  };
}

function receiptCount(value: JsonRecord, key: string, name: string): string {
  return nonnegativeInteger(value[key], name);
}

function readPlan(): Plan {
  const file = protectedPlanFile();
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch {
    fail("FAILED_BILLING_PLAN_FILE is not valid JSON", 1);
  }
  const root = record(parsed, "plan root");
  if (root.schema !== "mtc-failed-billing-reconciliation-receipt-v1" || root.mode !== "dry-run") {
    fail("plan is not an immutable failed-billing dry-run receipt", 1);
  }
  const receipt = record(root.receipt, "plan receipt");
  const scope = record(receipt.scope, "plan scope");
  const manualReview = record(receipt.manual_review, "plan manual_review");
  const archiveStates = manualReview.contract_ceiling_archive_states;
  if (!Array.isArray(archiveStates)) fail("plan manual_review has no contract_ceiling_archive_states", 1);
  const archiveCounts = new Map<string, { rows: string; micros: string }>();
  for (const rawState of archiveStates) {
    const state = record(rawState, "plan archive state");
    const name = stringValue(state.response_archive_state, "plan response_archive_state");
    if (archiveCounts.has(name)) fail("plan has duplicate response archive state", 1);
    archiveCounts.set(name, {
      rows: receiptCount(state, "request_count", `${name}.request_count`),
      micros: receiptCount(state, "cost_micros", `${name}.cost_micros`),
    });
  }
  const safeArchive = archiveCounts.get("gap");
  const boundArchive = archiveCounts.get("bound") ?? { rows: "0", micros: "0" };
  const expectedProviderRows = receiptCount(manualReview, "evidence_preserved_rows_in_interval", "manual_review.evidence_preserved_rows_in_interval");
  const expectedNullableBasisRows = receiptCount(manualReview, "nullable_basis_failed_nonzero_in_interval", "manual_review.nullable_basis_failed_nonzero_in_interval");
  const rawCandidates = receipt.repair_candidates;
  if (!Array.isArray(rawCandidates)) fail("plan has no repair_candidates", 1);
  const candidates = rawCandidates.map(planCandidate).sort((a, b) => {
    const byTime = BigInt(a.createdAt) < BigInt(b.createdAt) ? -1 : BigInt(a.createdAt) > BigInt(b.createdAt) ? 1 : 0;
    return byTime || a.requestId.localeCompare(b.requestId);
  });
  const seenRequests = new Set<string>();
  const seenSettlements = new Set<string>();
  for (const candidate of candidates) {
    if (!seenRequests.add(candidate.requestId) || !seenSettlements.add(candidate.settlementId)) fail("plan contains duplicate request or settlement", 1);
  }
  // Bind the digest to the entire receipt, not just the selected rows.  This
  // keeps the time-zone scope, interval evidence, and manual-review counts
  // immutable alongside the candidate set.
  const planSha256 = sha256(stable(receipt));
  const totalMicros = candidates.reduce((total, candidate) => total + BigInt(candidate.costMicros), 0n).toString();
  const dayBuckets = [...new Set(candidates.map((candidate) => (BigInt(candidate.createdAt) / 86_400_000n).toString()))].sort((a, b) => Number(BigInt(a) - BigInt(b)));
  const hourBuckets = [...new Set(candidates.map((candidate) => (BigInt(candidate.createdAt) / 3_600_000n).toString()))].sort((a, b) => Number(BigInt(a) - BigInt(b)));
  const expectedSafeRows = safeArchive?.rows ?? String(candidates.length);
  const expectedSafeMicros = safeArchive?.micros ?? totalMicros;
  if (BigInt(expectedSafeRows) !== BigInt(candidates.length) || expectedSafeMicros !== totalMicros) {
    fail("plan candidate set does not match its gap archive summary", 1);
  }
  return {
    candidates,
    planSha256,
    totalMicros,
    source: `${DEFAULT_SOURCE_PREFIX}${planSha256}`,
    dayBuckets,
    hourBuckets,
    scope,
    expectedPreviewRows: (BigInt(expectedSafeRows) + BigInt(boundArchive.rows)).toString(),
    expectedSafeRows,
    expectedSafeMicros,
    expectedBoundRows: boundArchive.rows,
    expectedProviderRows,
    expectedNullableBasisRows,
  };
}

function expectedPlan(plan: Plan, requireApproval = false): void {
  const expectedRows = optional("FAILED_BILLING_EXPECTED_ROWS");
  const expectedMicros = optional("FAILED_BILLING_EXPECTED_MICROS");
  if (expectedRows && (!/^\d+$/u.test(expectedRows) || BigInt(expectedRows) !== BigInt(plan.candidates.length))) {
    fail("FAILED_BILLING_EXPECTED_ROWS does not match the immutable plan", 1);
  }
  if (expectedMicros && (!/^\d+$/u.test(expectedMicros) || BigInt(expectedMicros) !== BigInt(plan.totalMicros))) {
    fail("FAILED_BILLING_EXPECTED_MICROS does not match the immutable plan", 1);
  }
  const approved = optional("FAILED_BILLING_APPROVED_PLAN_SHA256");
  if (requireApproval && !approved) fail("FAILED_BILLING_APPROVED_PLAN_SHA256 is required for --apply", 1);
  if (approved && !/^[0-9a-f]{64}$/u.test(approved)) fail("FAILED_BILLING_APPROVED_PLAN_SHA256 must be lowercase SHA-256", 1);
  if (approved && approved !== plan.planSha256) fail("approved plan digest does not match the immutable plan", 1);
}

const baselineSql = String.raw`
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = :'statement_timeout';
WITH daily AS (
  SELECT count(*)::text AS rows, COALESCE(sum(a.cost_micros), 0)::text AS cost_micros,
         md5(COALESCE(string_agg(to_jsonb(a)::text, E'\n' ORDER BY to_jsonb(a)::text), '')) AS fingerprint
    FROM request_daily_aggregates a
   WHERE a.day_bucket = ANY(string_to_array(:'day_buckets', ',')::bigint[])
), analysis_daily AS (
  SELECT count(*)::text AS rows, COALESCE(sum(a.cost_micros), 0)::text AS cost_micros,
         md5(COALESCE(string_agg(to_jsonb(a)::text, E'\n' ORDER BY to_jsonb(a)::text), '')) AS fingerprint
    FROM usage_analysis_daily a
   WHERE a.source_kind = 'request'
     AND a.day_bucket = ANY(string_to_array(:'day_buckets', ',')::bigint[])
), hourly AS (
  SELECT count(*)::text AS rows, COALESCE(sum(a.cost_micros), 0)::text AS cost_micros,
         md5(COALESCE(string_agg(to_jsonb(a)::text, E'\n' ORDER BY to_jsonb(a)::text), '')) AS fingerprint
    FROM usage_analysis_hourly a
   WHERE a.source_kind = 'request'
     AND a.hour_bucket = ANY(string_to_array(:'hour_buckets', ',')::bigint[])
)
SELECT jsonb_build_object(
  'daily', (SELECT to_jsonb(daily) FROM daily),
  'analysis_daily', (SELECT to_jsonb(analysis_daily) FROM analysis_daily),
  'hourly', (SELECT to_jsonb(hourly) FROM hourly)
)::text;
COMMIT;
`;

const verifySql = String.raw`
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = :'statement_timeout';
WITH ids AS (
  SELECT unnest(string_to_array(:'request_ids', ',')) AS request_id
)
SELECT COALESCE(jsonb_agg(jsonb_build_object(
  'request_id', ids.request_id,
  'request_cost_micros', r.cost_micros::text,
  'request_usage_basis', r.usage_basis,
  'reservation_status', u.status,
  'reservation_actual_micros', u.actual_micros::text,
  'reservation_account_id', u.account_id,
  'reservation_key_id', u.key_id,
  'fact_cost_micros', fact.cost_micros::text,
  'feed_settlement_id', feed.settlement_id,
  'feed_account_id', feed.account_id,
  'feed_key_id', feed.key_id,
  'feed_cost_micros', feed.cost_micros::text,
  'feed_currency', feed.currency,
  'feed_usage_basis', feed.usage_basis,
  'usage_ledger_count', usage_ledger.ledger_count::text,
  'usage_ledger_amount', usage_ledger.ledger_amount::text,
  'usage_ledger_currency', usage_ledger.ledger_currency,
  'event_count', events.event_count::text,
  'event_request_id', event.request_id,
  'event_desired_rebate_micros', event.desired_rebate_micros::text,
  'event_applied_delta_micros', event.applied_delta_micros::text,
  'event_version', event.version::text,
  'event_decision_digest', event.decision_digest,
  'event_source', event.source,
  'state_desired_rebate_micros', state.desired_rebate_micros::text,
  'state_version', state.version::text,
  'state_decision_digest', state.decision_digest,
  'state_source', state.source,
  'adjustment_ledger_count', adjustment_ledger.ledger_count::text,
  'adjustment_ledger_micros', adjustment_ledger.ledger_micros::text,
  'funding_reduction_micros', funding_reduction.funding_reduction_micros::text
) ORDER BY ids.request_id), '[]'::jsonb)::text
FROM ids
LEFT JOIN request_records r ON r.id = ids.request_id
LEFT JOIN usage_reservations u ON u.id = r.reservation_id
LEFT JOIN LATERAL (
  SELECT f.cost_micros
    FROM request_stats_facts f
   WHERE f.request_id = r.id
   ORDER BY f.created_at DESC
   LIMIT 1
) fact ON true
LEFT JOIN LATERAL (
  SELECT f.settlement_id, f.account_id, f.key_id, f.cost_micros, f.currency, f.usage_basis
    FROM account_settlement_feed f
   WHERE f.request_kind = 'text' AND f.request_id = r.id
   ORDER BY f.settlement_sequence DESC, f.settlement_id DESC
   LIMIT 1
) feed ON true
LEFT JOIN LATERAL (
  SELECT count(*) AS ledger_count, min(l.amount_micros) AS ledger_amount, min(l.currency) AS ledger_currency
    FROM ledger_entries l
   WHERE l.account_id = u.account_id
     AND l.key_id = u.key_id
     AND l.kind = 'usage'
     AND l.source = u.id
) usage_ledger ON true
LEFT JOIN LATERAL (
  SELECT count(*) AS event_count
    FROM settlement_adjustment_events e
   WHERE e.account_id = u.account_id
     AND e.settlement_id = feed.settlement_id
     AND e.namespace = :'namespace'
) events ON true
LEFT JOIN LATERAL (
  SELECT e.request_id, e.desired_rebate_micros, e.applied_delta_micros, e.version, e.decision_digest, e.source, e.id
    FROM settlement_adjustment_events e
   WHERE e.account_id = u.account_id
     AND e.settlement_id = feed.settlement_id
     AND e.namespace = :'namespace'
   ORDER BY e.version DESC, e.created_at DESC, e.id DESC
   LIMIT 1
) event ON true
LEFT JOIN LATERAL (
  SELECT s.desired_rebate_micros, s.version, s.decision_digest, s.source
    FROM settlement_adjustment_states s
   WHERE s.account_id = u.account_id
     AND s.settlement_id = feed.settlement_id
     AND s.namespace = :'namespace'
   LIMIT 1
) state ON true
LEFT JOIN LATERAL (
  SELECT count(*) AS ledger_count, COALESCE(sum(l.amount_micros), 0) AS ledger_micros
    FROM ledger_entries l
   WHERE l.account_id = u.account_id
     AND l.kind = 'settlement_adjustment'
     AND l.reference_entry_id = feed.settlement_id
     AND l.source = :'source'
) adjustment_ledger ON true
LEFT JOIN LATERAL (
  SELECT COALESCE(sum(f.amount_micros), 0) AS funding_reduction_micros
    FROM settlement_adjustment_entitlement_funding_reductions f
   WHERE f.event_id = event.id
) funding_reduction ON true;
COMMIT;
`;

function psqlJson(sql: string, variables: Record<string, string>): unknown {
  const args = ["-X", "--no-psqlrc", "-qAt", "-v", "ON_ERROR_STOP=1"];
  for (const [name, value] of Object.entries(variables)) args.push("-v", `${name}=${value}`);
  const kubectlPod = optional("FAILED_BILLING_KUBECTL_POD");
  const command = kubectlPod ? required("FAILED_BILLING_KUBECTL_BINARY") : optional("FAILED_BILLING_PSQL_BINARY") || "psql";
  const commandArguments = kubectlPod
    ? [
        "-n", required("FAILED_BILLING_KUBECTL_NAMESPACE"), "exec", "-i", kubectlPod,
        ...(optional("FAILED_BILLING_KUBECTL_CONTAINER") ? ["-c", required("FAILED_BILLING_KUBECTL_CONTAINER")] : []),
        "--", "sh", "-c", 'IFS= read -r pw || exit 2; export PGPASSWORD="$pw"; exec psql "$@"', "sh",
        ...args.slice(0, 3), "-h", "127.0.0.1", "-U", required("FAILED_BILLING_KUBECTL_DB_USER"), "-d", required("FAILED_BILLING_KUBECTL_DB_DATABASE"),
        ...args.slice(3),
      ]
    : args;
  const environment = kubectlPod
    ? { PATH: process.env.PATH, HOME: process.env.HOME, ...(process.env.KUBECONFIG ? { KUBECONFIG: process.env.KUBECONFIG } : {}) }
    : {
        PATH: process.env.PATH,
        PGHOST: required("FAILED_BILLING_PGHOST"),
        PGPORT: String(positiveInteger("FAILED_BILLING_PGPORT", "5432", 65_535)),
        PGUSER: required("FAILED_BILLING_PGUSER"),
        PGDATABASE: required("FAILED_BILLING_PGDATABASE"),
        PGPASSFILE: psqlPassFile(),
      };
  const input = kubectlPod ? `${required("FAILED_BILLING_KUBECTL_DB_PASSWORD")}\n${sql}` : sql;
  const result = spawnSync(command, commandArguments, {
    encoding: "utf8",
    input,
    shell: false,
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["pipe", "pipe", "inherit"],
    env: environment,
  });
  if (result.error || result.status !== 0) fail(result.error ? `psql is unavailable: ${result.error.message}` : "read-only verification query failed", 1);
  const output = String(result.stdout).trim();
  if (!output || output.includes("\n")) fail("verification query returned invalid receipt output", 1);
  try {
    return JSON.parse(output);
  } catch {
    fail("verification query returned invalid JSON", 1);
  }
}

function baseline(plan: Plan, statementTimeout: number): JsonRecord {
  return record(psqlJson(baselineSql, {
    day_buckets: plan.dayBuckets.join(","),
    hour_buckets: plan.hourBuckets.join(","),
    statement_timeout: `${statementTimeout}ms`,
  }), "aggregate baseline");
}

function assertBaseline(before: JsonRecord, after: JsonRecord, batchNumber: number): void {
  if (stable(before) !== stable(after)) fail(`aggregate verification mismatch after batch ${batchNumber}; execution stopped`, 1);
}

function assertText(value: unknown, expected: unknown, name: string, requestId: string): void {
  if (value !== expected) fail(`${requestId} verification mismatch: ${name}`, 1);
}

function assertCandidateRows(rows: unknown, candidates: Candidate[], source: string): void {
  if (!Array.isArray(rows) || rows.length !== candidates.length) fail("verification did not return exactly one row per candidate", 1);
  const byRequest = new Map<string, JsonRecord>();
  for (const value of rows) {
    const row = record(value, "verification row");
    const requestId = uuid(row.request_id, "verification request_id");
    if (byRequest.has(requestId)) fail("verification returned duplicate request rows", 1);
    byRequest.set(requestId, row);
  }
  for (const candidate of candidates) {
    const row = byRequest.get(candidate.requestId);
    if (!row) fail(`${candidate.requestId} is missing from verification`, 1);
    assertImmutableCandidateRow(row, candidate);
    for (const [field, expected] of [
      ["request_cost_micros", candidate.costMicros],
      ["request_usage_basis", "contract_ceiling"],
      ["reservation_status", "settled"],
      ["reservation_actual_micros", candidate.costMicros],
      ["reservation_account_id", candidate.accountId],
      ["reservation_key_id", undefined],
      ["fact_cost_micros", candidate.costMicros],
      ["feed_settlement_id", candidate.settlementId],
      ["feed_account_id", candidate.accountId],
      ["feed_cost_micros", candidate.costMicros],
      ["feed_currency", candidate.currency],
      ["feed_usage_basis", "contract_ceiling"],
      ["event_count", "1"],
      ["event_request_id", candidate.requestId],
      ["event_desired_rebate_micros", candidate.costMicros],
      ["event_applied_delta_micros", candidate.costMicros],
      ["event_version", "1"],
      ["event_decision_digest", candidate.decisionDigest],
      ["event_source", source],
      ["state_desired_rebate_micros", candidate.costMicros],
      ["state_version", "1"],
      ["state_decision_digest", candidate.decisionDigest],
      ["state_source", source],
    ] as const) {
      if (expected !== undefined) assertText(row[field], expected, field, candidate.requestId);
    }
    const ledgerMicros = nonnegativeInteger(row.adjustment_ledger_micros, `${candidate.requestId}.adjustment_ledger_micros`);
    const fundingMicros = nonnegativeInteger(row.funding_reduction_micros, `${candidate.requestId}.funding_reduction_micros`);
    if (BigInt(ledgerMicros) + BigInt(fundingMicros) !== BigInt(candidate.costMicros)) fail(`${candidate.requestId} funding/ledger delta mismatch`, 1);
    const ledgerCount = nonnegativeInteger(row.adjustment_ledger_count, `${candidate.requestId}.adjustment_ledger_count`);
    if ((BigInt(ledgerMicros) > 0n && ledgerCount !== "1") || (BigInt(ledgerMicros) === 0n && ledgerCount !== "0")) fail(`${candidate.requestId} adjustment ledger count mismatch`, 1);
  }
}

function assertImmutableCandidateRow(row: JsonRecord, candidate: Candidate): void {
  for (const [field, expected] of [
    ["request_cost_micros", candidate.costMicros],
    ["request_usage_basis", "contract_ceiling"],
    ["reservation_status", "settled"],
    ["reservation_actual_micros", candidate.costMicros],
    ["reservation_account_id", candidate.accountId],
    ["fact_cost_micros", candidate.costMicros],
    ["feed_settlement_id", candidate.settlementId],
    ["feed_account_id", candidate.accountId],
    ["feed_cost_micros", candidate.costMicros],
    ["feed_currency", candidate.currency],
    ["feed_usage_basis", "contract_ceiling"],
    ["usage_ledger_count", "1"],
    ["usage_ledger_amount", `-${candidate.costMicros}`],
    ["usage_ledger_currency", candidate.currency],
  ] as const) assertText(row[field], expected, field, candidate.requestId);
}

function assertPreflightRows(rows: unknown, candidates: Candidate[], source: string): void {
  if (!Array.isArray(rows) || rows.length !== candidates.length) fail("preflight did not return exactly one row per candidate", 1);
  const byRequest = new Map<string, JsonRecord>();
  for (const value of rows) {
    const row = record(value, "preflight row");
    const requestId = uuid(row.request_id, "preflight request_id");
    if (byRequest.has(requestId)) fail("preflight returned duplicate request rows", 1);
    byRequest.set(requestId, row);
  }
  for (const candidate of candidates) {
    const row = byRequest.get(candidate.requestId);
    if (!row) fail(`${candidate.requestId} is missing from preflight`, 1);
    assertImmutableCandidateRow(row, candidate);
    const eventCount = nonnegativeInteger(row.event_count, `${candidate.requestId}.event_count`);
    if (eventCount === "0") continue;
    if (eventCount !== "1") fail(`${candidate.requestId} has unexpected prior adjustment events`, 1);
    for (const [field, expected] of [
      ["event_request_id", candidate.requestId],
      ["event_desired_rebate_micros", candidate.costMicros],
      ["event_applied_delta_micros", candidate.costMicros],
      ["event_version", "1"],
      ["event_decision_digest", candidate.decisionDigest],
      ["event_source", source],
      ["state_desired_rebate_micros", candidate.costMicros],
      ["state_version", "1"],
      ["state_decision_digest", candidate.decisionDigest],
      ["state_source", source],
    ] as const) assertText(row[field], expected, field, candidate.requestId);
  }
}

type ApiPreviewCursor = {
  afterCreatedAt: string;
  afterRequestId: string;
};

type ApiPreviewPage = {
  items: JsonRecord[];
  nextCursor: ApiPreviewCursor | null;
};

type ApiPreviewRow = {
  requestId: string;
  accountId: string;
  settlementId: string | null;
  currency: string;
  statusCode: string;
  createdAt: string;
  usageBasis: string | null;
  costMicros: string;
  archiveState: string;
  responseAvailable: boolean;
  feedState: string;
  reviewState: string;
};

const PREVIEW_PAGE_SIZE = 500;
const MAX_PREVIEW_RANGE_MILLIS = 93n * 86_400_000n;

function integerValue(value: unknown, name: string): string {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail(`invalid ${name}`, 1);
    return String(value);
  }
  return integerString(value, name);
}

function apiConfig(): { base: string; token: string } {
  const base = required("FAILED_BILLING_API_BASE_URL").replace(/\/+$/u, "");
  const apiUrl = new URL(`${base}/`);
  if (apiUrl.protocol !== "https:") fail("FAILED_BILLING_API_BASE_URL must use HTTPS");
  const token = required("FAILED_BILLING_SERVICE_TOKEN");
  if (token.length < 16) fail("FAILED_BILLING_SERVICE_TOKEN is too short");
  return { base, token };
}

async function getPreviewPage(
  base: string,
  token: string,
  accountId: string,
  fromCreatedAt: string,
  toCreatedAt: string,
  cursor: ApiPreviewCursor | null,
  timeout: number,
): Promise<ApiPreviewPage> {
  const url = new URL(`/internal/v1/accounts/${accountId}/settlement-correction-previews`, `${base}/`);
  url.searchParams.set("from_created_at", fromCreatedAt);
  url.searchParams.set("to_created_at", toCreatedAt);
  url.searchParams.set("limit", String(PREVIEW_PAGE_SIZE));
  if (cursor) {
    url.searchParams.set("after_created_at", cursor.afterCreatedAt);
    url.searchParams.set("after_request_id", cursor.afterRequestId);
  }
  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      headers: { Accept: "application/json", Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(timeout),
    });
  } catch {
    fail("settlement-correction preview API transport failure; execution stopped", 1);
  }
  const responseText = await response.text();
  if (response.status !== 200) fail(`settlement-correction preview API returned HTTP ${response.status}; execution stopped`, 1);
  let parsed: unknown;
  try {
    parsed = JSON.parse(responseText);
  } catch {
    fail("settlement-correction preview API returned invalid JSON; execution stopped", 1);
  }
  const root = record(parsed, "settlement-correction preview page");
  if (!Array.isArray(root.items)) fail("settlement-correction preview API returned no items array", 1);
  const items = root.items.map((item, index) => record(item, `settlement-correction preview item ${index}`));
  let nextCursor: ApiPreviewCursor | null = null;
  if (root.next_cursor !== null && root.next_cursor !== undefined) {
    const rawCursor = record(root.next_cursor, "settlement-correction preview cursor");
    nextCursor = {
      afterCreatedAt: integerValue(rawCursor.after_created_at, "preview cursor after_created_at"),
      afterRequestId: uuid(rawCursor.after_request_id, "preview cursor after_request_id"),
    };
  }
  return { items, nextCursor };
}

function apiPreviewRow(raw: JsonRecord): ApiPreviewRow {
  const requestId = uuid(raw.request_id, "preview request_id");
  const accountId = uuid(raw.account_id, "preview account_id");
  const settlementId = raw.settlement_id === undefined || raw.settlement_id === null
    ? null
    : uuid(raw.settlement_id, "preview settlement_id");
  const original = record(raw.original, `${requestId}.original`);
  const evidence = record(raw.evidence, `${requestId}.evidence`);
  const invariants = record(raw.invariants, `${requestId}.invariants`);
  const usageBasis = original.usage_basis === null || original.usage_basis === undefined
    ? null
    : stringValue(original.usage_basis, `${requestId}.original.usage_basis`);
  const costMicros = original.cost_micros === undefined
    ? decimalToMicros(original.cost, `${requestId}.original.cost`)
    : nonnegativeInteger(original.cost_micros, `${requestId}.original.cost_micros`);
  if (typeof evidence.response_available !== "boolean") fail(`invalid ${requestId}.evidence.response_available`, 1);
  return {
    requestId,
    accountId,
    settlementId,
    currency: stringValue(raw.currency, `${requestId}.currency`).toUpperCase(),
    statusCode: integerValue(raw.status_code, `${requestId}.status_code`),
    createdAt: integerValue(raw.created_at, `${requestId}.created_at`),
    usageBasis,
    costMicros,
    archiveState: stringValue(evidence.archive_state, `${requestId}.evidence.archive_state`),
    responseAvailable: evidence.response_available,
    feedState: stringValue(invariants.settlement_feed, `${requestId}.invariants.settlement_feed`),
    reviewState: stringValue(raw.review_state, `${requestId}.review_state`),
  };
}

function previewWindows(candidates: Candidate[]): Array<{ fromCreatedAt: string; toCreatedAt: string }> {
  if (candidates.length === 0) fail("plan has no candidates", 1);
  const times = candidates.map((candidate) => BigInt(candidate.createdAt));
  let from = times.reduce((minimum, value) => value < minimum ? value : minimum, times[0]!);
  const maximum = times.reduce((maximumValue, value) => value > maximumValue ? value : maximumValue, times[0]!);
  const windows: Array<{ fromCreatedAt: string; toCreatedAt: string }> = [];
  while (from <= maximum) {
    const to = from + MAX_PREVIEW_RANGE_MILLIS < maximum ? from + MAX_PREVIEW_RANGE_MILLIS : maximum;
    windows.push({ fromCreatedAt: from.toString(), toCreatedAt: to.toString() });
    if (to === maximum) break;
    from = to + 1n;
  }
  return windows;
}

function previewWindowsByAccount(candidates: Candidate[]): Array<{ accountId: string; windows: Array<{ fromCreatedAt: string; toCreatedAt: string }> }> {
  const byAccount = new Map<string, Candidate[]>();
  for (const candidate of candidates) byAccount.set(candidate.accountId, [...(byAccount.get(candidate.accountId) ?? []), candidate]);
  return [...byAccount.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([accountId, accountCandidates]) => ({ accountId, windows: previewWindows(accountCandidates) }));
}

function assertApiPreviewCandidate(row: ApiPreviewRow, candidate: Candidate): void {
  if (row.accountId !== candidate.accountId || row.currency !== candidate.currency || row.costMicros !== candidate.costMicros || row.statusCode !== candidate.statusCode || (row.settlementId !== null && row.settlementId !== candidate.settlementId)) {
    fail("settlement-correction preview does not match the immutable plan", 1);
  }
}

async function previewPlan(plan: Plan, base: string, token: string, timeout: number): Promise<PreviewSummary> {
  const candidates = new Map(plan.candidates.map((candidate) => [candidate.requestId, candidate]));
  const seen = new Set<string>();
  let pages = 0n;
  let previewRows = 0n;
  let safeRows = 0n;
  let safeMicros = 0n;
  let boundRows = 0n;
  let invariantMismatchRows = 0n;
  for (const { accountId, windows } of previewWindowsByAccount(plan.candidates)) {
    for (const window of windows) {
      let cursor: ApiPreviewCursor | null = null;
      do {
        const page = await getPreviewPage(base, token, accountId, window.fromCreatedAt, window.toCreatedAt, cursor, timeout);
        pages += 1n;
        if (page.items.length > PREVIEW_PAGE_SIZE) fail("settlement-correction preview page exceeds the API limit", 1);
        for (const raw of page.items) {
          const row = apiPreviewRow(raw);
          if (!seen.add(row.requestId)) fail("settlement-correction preview returned a duplicate row", 1);
          previewRows += 1n;
          if (row.archiveState === "bound") boundRows += 1n;
          if (row.reviewState !== "ready_for_evidence" || row.feedState !== "matched") invariantMismatchRows += 1n;
          const safe = BigInt(row.statusCode) >= 400n
            && row.usageBasis === "contract_ceiling"
            && row.archiveState === "gap"
            && row.responseAvailable === false
            && row.reviewState === "ready_for_evidence"
            && row.feedState === "matched";
          if (!safe) continue;
          const candidate = candidates.get(row.requestId);
          if (!candidate) fail("settlement-correction preview contains an unplanned safe row", 1);
          assertApiPreviewCandidate(row, candidate);
          safeRows += 1n;
          safeMicros += BigInt(row.costMicros);
        }
        if (page.items.length === PREVIEW_PAGE_SIZE && page.nextCursor === null) fail("settlement-correction preview pagination ended without a cursor", 1);
        if (page.items.length === 0 && page.nextCursor !== null) fail("settlement-correction preview returned an empty page with a cursor", 1);
        if (cursor && page.nextCursor && cursor.afterCreatedAt === page.nextCursor.afterCreatedAt && cursor.afterRequestId === page.nextCursor.afterRequestId) {
          fail("settlement-correction preview cursor did not advance", 1);
        }
        cursor = page.nextCursor;
      } while (cursor !== null);
    }
  }
  if (previewRows !== BigInt(plan.expectedPreviewRows)
    || safeRows !== BigInt(plan.expectedSafeRows)
    || safeMicros !== BigInt(plan.expectedSafeMicros)
    || boundRows !== BigInt(plan.expectedBoundRows)) {
    fail("settlement-correction preview totals do not match the immutable plan", 1);
  }
  if (safeRows !== BigInt(plan.candidates.length)) fail("settlement-correction preview did not select exactly the planned safe rows", 1);
  for (const candidate of plan.candidates) if (!seen.has(candidate.requestId)) fail("settlement-correction preview omitted a planned row", 1);
  return {
    pages: pages.toString(),
    preview_rows: previewRows.toString(),
    safe_rows: safeRows.toString(),
    safe_micros: safeMicros.toString(),
    bound_rows: boundRows.toString(),
    invariant_mismatch_rows: invariantMismatchRows.toString(),
    excluded_provider_reported_rows: plan.expectedProviderRows,
    excluded_nullable_basis_rows: plan.expectedNullableBasisRows,
  };
}

async function putAdjustment(base: string, token: string, candidate: Candidate, source: string, timeout: number): Promise<JsonRecord> {
  const url = new URL(`/internal/v1/accounts/${candidate.accountId}/settlements/${candidate.settlementId}/adjustments`, `${base}/`);
  const body = JSON.stringify({
    namespace: NAMESPACE,
    request_kind: "text",
    request_id: candidate.requestId,
    currency: candidate.currency,
    version: 1,
    desired_rebate: microsToDecimal(candidate.costMicros),
    decision_digest: candidate.decisionDigest,
    source,
  });
  let response: Response;
  try {
    response = await fetch(url, {
      method: "PUT",
      headers: { Accept: "application/json", "Content-Type": "application/json", Authorization: `Bearer ${token}`, "Idempotency-Key": candidate.idempotencyKey },
      body,
      signal: AbortSignal.timeout(timeout),
    });
  } catch {
    fail("settlement-adjustment API transport failure; execution stopped", 1);
  }
  const responseText = await response.text();
  if (response.status !== 200 && response.status !== 201) fail(`settlement-adjustment API returned HTTP ${response.status}; execution stopped`, 1);
  let parsed: unknown;
  try {
    parsed = JSON.parse(responseText);
  } catch {
    fail("settlement-adjustment API returned invalid JSON; execution stopped", 1);
  }
  const result = record(parsed, "settlement-adjustment response");
  assertText(result.account_id, candidate.accountId, "response account_id", candidate.requestId);
  assertText(result.settlement_id, candidate.settlementId, "response settlement_id", candidate.requestId);
  assertText(result.request_id, candidate.requestId, "response request_id", candidate.requestId);
  assertText(result.currency, candidate.currency, "response currency", candidate.requestId);
  assertText(result.desired_rebate, microsToDecimal(candidate.costMicros), "response desired_rebate", candidate.requestId);
  assertText(result.version, 1, "response version", candidate.requestId);
  if (typeof result.replayed !== "boolean") fail(`${candidate.requestId} API response replay flag is invalid`, 1);
  nonnegativeMoney(result.applied_delta, `${candidate.requestId}.response.applied_delta`);
  return result;
}

async function main(): Promise<void> {
  const arguments_ = process.argv.slice(2);
  if (arguments_.length > 1 || (arguments_.length === 1 && arguments_[0] !== "--dry-run" && arguments_[0] !== "--preflight" && arguments_[0] !== "--apply" && arguments_[0] !== "--help")) fail("usage: node ops/apply-failed-billing-rebates.ts [--dry-run|--preflight|--apply]");
  if (arguments_[0] === "--help") {
    process.stdout.write("Usage: node ops/apply-failed-billing-rebates.ts [--dry-run|--preflight|--apply]\nRequired env: FAILED_BILLING_PLAN_FILE, FAILED_BILLING_EXPECTED_ROWS, FAILED_BILLING_EXPECTED_MICROS, FAILED_BILLING_APPROVED_PLAN_SHA256 (apply), FAILED_BILLING_API_BASE_URL (apply), FAILED_BILLING_SERVICE_TOKEN (apply), PostgreSQL env (preflight/apply)\n--preflight may also perform a read-only paginated API preview when both API env vars are supplied.\n");
    return;
  }
  const apply = arguments_[0] === "--apply";
  const preflight = arguments_[0] === "--preflight";
  const plan = readPlan();
  expectedPlan(plan, apply);
  const summary = {
    schema: "mtc-failed-billing-rebate-execution-v1",
    mode: apply ? "apply" : preflight ? "preflight" : "dry-run",
    plan_sha256: plan.planSha256,
    rows: String(plan.candidates.length),
    total_rebate_micros: plan.totalMicros,
    total_rebate_usd: microsToDecimal(plan.totalMicros),
    source: plan.source,
    batch_size: String(positiveInteger("FAILED_BILLING_BATCH_SIZE", "50", 100)),
    batches: String(Math.ceil(plan.candidates.length / positiveInteger("FAILED_BILLING_BATCH_SIZE", "50", 100))),
    production_write_performed: false,
  };
  if (!apply && !preflight) {
    process.stdout.write(`${JSON.stringify(summary)}\n`);
    return;
  }
  if (preflight) {
    const statementTimeout = positiveInteger("FAILED_BILLING_STATEMENT_TIMEOUT_MS", "30000", 300_000);
    const aggregateBaseline = baseline(plan, statementTimeout);
    const preflightRows = psqlJson(verifySql, {
      request_ids: plan.candidates.map((candidate) => candidate.requestId).join(","),
      namespace: NAMESPACE,
      source: plan.source,
      statement_timeout: `${statementTimeout}ms`,
    });
    assertPreflightRows(preflightRows, plan.candidates, plan.source);
    const configuredBase = optional("FAILED_BILLING_API_BASE_URL");
    const configuredToken = optional("FAILED_BILLING_SERVICE_TOKEN");
    let apiPreview: PreviewSummary | undefined;
    if (configuredBase || configuredToken) {
      if (!configuredBase || !configuredToken) fail("FAILED_BILLING_API_BASE_URL and FAILED_BILLING_SERVICE_TOKEN must be supplied together");
      const api = apiConfig();
      apiPreview = await previewPlan(plan, api.base, api.token, positiveInteger("FAILED_BILLING_API_TIMEOUT_MS", "30000", 300_000));
    }
    process.stdout.write(`${JSON.stringify({ ...summary, aggregate_baseline: aggregateBaseline, preflight: "all_immutable_rows_consistent", ...(apiPreview ? { api_preview: apiPreview } : {}), production_write_performed: false })}\n`);
    return;
  }
  if (optional("FAILED_BILLING_ALLOW_WRITE") !== "I_UNDERSTAND_SETTLEMENT_ADJUSTMENT_API") fail("FAILED_BILLING_ALLOW_WRITE must explicitly authorize settlement-adjustment API writes");
  const api = apiConfig();
  const base = api.base;
  const token = api.token;
  const statementTimeout = positiveInteger("FAILED_BILLING_STATEMENT_TIMEOUT_MS", "30000", 300_000);
  const apiTimeout = positiveInteger("FAILED_BILLING_API_TIMEOUT_MS", "30000", 300_000);
  const batchSize = positiveInteger("FAILED_BILLING_BATCH_SIZE", "50", 100);
  const apiPreview = await previewPlan(plan, base, token, apiTimeout);
  const before = baseline(plan, statementTimeout);
  const initialRows = psqlJson(verifySql, {
    request_ids: plan.candidates.map((candidate) => candidate.requestId).join(","),
    namespace: NAMESPACE,
    source: plan.source,
    statement_timeout: `${statementTimeout}ms`,
  });
  assertPreflightRows(initialRows, plan.candidates, plan.source);
  let applied = 0;
  let replayed = 0;
  const batchSummaries: Array<Record<string, string>> = [];
  for (let offset = 0; offset < plan.candidates.length; offset += batchSize) {
    const batch = plan.candidates.slice(offset, offset + batchSize);
    let batchApplied = 0;
    let batchReplayed = 0;
    for (const candidate of batch) {
      const result = await putAdjustment(base, token, candidate, plan.source, apiTimeout);
      if (result.replayed === true) batchReplayed += 1;
      else batchApplied += 1;
    }
    const verified = psqlJson(verifySql, {
      request_ids: batch.map((candidate) => candidate.requestId).join(","),
      namespace: NAMESPACE,
      source: plan.source,
      statement_timeout: `${statementTimeout}ms`,
    });
    assertCandidateRows(verified, batch, plan.source);
    const after = baseline(plan, statementTimeout);
    assertBaseline(before, after, Math.floor(offset / batchSize) + 1);
    applied += batchApplied;
    replayed += batchReplayed;
    const batchSummary = { batch: String(Math.floor(offset / batchSize) + 1), rows: String(batch.length), applied: String(batchApplied), replayed: String(batchReplayed), micros: batch.reduce((total, candidate) => total + BigInt(candidate.costMicros), 0n).toString() };
    batchSummaries.push(batchSummary);
    process.stderr.write(`verified failed-billing batch ${batchSummary.batch}/${summary.batches}: ${batchSummary.rows} rows, ${batchSummary.applied} applied, ${batchSummary.replayed} replayed\n`);
  }
  process.stdout.write(`${JSON.stringify({ ...summary, api_preview: apiPreview, production_write_performed: true, applied: String(applied), replayed: String(replayed), verification: "all_batches_ledger_reservation_fact_feed_aggregate_consistent", batch_summaries: batchSummaries })}\n`);
}

if (invokedAsEntrypoint("apply-failed-billing-rebates", import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : "failed-billing rebate execution failed"}\n`);
    process.exitCode = error instanceof CliError ? error.exitCode : 1;
  });
}
