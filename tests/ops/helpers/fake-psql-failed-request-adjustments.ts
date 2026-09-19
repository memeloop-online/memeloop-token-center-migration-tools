#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const chunks: Buffer[] = [];
for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
const sql = Buffer.concat(chunks).toString("utf8");
const passFile = process.env.PGPASSFILE;
if (!passFile) process.exit(9);
let fixture: Record<string, unknown>;
try {
  const parsed = JSON.parse(readFileSync(join(dirname(passFile), "failed-request-adjustments-fixture.json"), "utf8"));
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) process.exit(9);
  fixture = parsed as Record<string, unknown>;
} catch { process.exit(9); }
const logPath = join(dirname(passFile), "psql-invocations.json");
let invocations: Array<Record<string, unknown>> = [];
try { invocations = JSON.parse(readFileSync(logPath, "utf8")) as Array<Record<string, unknown>>; } catch { /* first call */ }
const mode = sql.includes("FRA_PLAN_READ_ONLY_V1") ? "plan"
  : sql.includes("FRA_APPLY_APPROVED_PLAN_V1") ? "apply"
    : sql.includes("FRA_REBUILD_DERIVED_V2") ? "rebuild-derived"
    : sql.includes("FRA_VERIFY_READ_ONLY_V2") ? "verify" : "unknown";
invocations.push({ mode, argv: process.argv.slice(2), sql, pgpassfile: passFile });
writeFileSync(logPath, JSON.stringify(invocations));
if (mode === "unknown") process.exit(9);

const candidate = {
  request_id: "00000000-0000-5000-a000-000000000111",
  request_created_at: "1726400000000",
  tenant_id: "00000000-0000-5000-a000-000000000222",
  key_id: "00000000-0000-5000-a000-000000000333",
  account_id: "00000000-0000-5000-a000-000000000444",
  reservation_id: "00000000-0000-5000-a000-000000000555",
  usage_ledger_id: "00000000-0000-5000-a000-000000000666",
  usage_ledger_created_at: "1726400000100",
  status_code: "503",
  currency: "USD",
  refund_micros: "594137836",
};
function receipt(value: unknown): never {
  // The large-plan transport check deliberately exceeds a pipe's usual
  // high-water mark. A synchronous descriptor write keeps this fake's
  // process lifetime from truncating its own test receipt before Node flushes
  // stdout on exit.
  writeFileSync(1, `${JSON.stringify(value)}\n`);
  process.exit(0);
}
if (mode === "plan") {
  if (!sql.includes("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
    || /\b(?:INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|LOCK)\b/u.test(sql)) process.exit(9);
  const candidates = fixture.large === true
    ? Array.from({ length: 300 }, (_, index) => ({
      ...candidate,
      request_id: `fixture-request-${index.toString().padStart(5, "0")}-${"x".repeat(96)}`,
      usage_ledger_id: `fixture-ledger-${index.toString().padStart(5, "0")}-${"y".repeat(96)}`,
    }))
    : [candidate];
  receipt({
    selected_tenant_count: "1", observed_request_count: fixture.empty === true ? "0" : "2", eligible_candidates: fixture.empty === true ? [] : candidates, already_zero_cost_count: "1",
    blockers: fixture.blocked ? [{ reason: "request_stats_cost_mismatch", count: "1" }] : [],
  });
}
if (mode === "apply") {
  if (!sql.includes("failed_request_refund")
    || !sql.includes("failed_request_cost_adjustment_daily")
    || /UPDATE\s+(?:request_records|ledger_entries)\b/iu.test(sql)
    || /DELETE\s+FROM\s+(?:request_records|ledger_entries)\b/iu.test(sql)) process.exit(9);
  receipt({ outcome: "applied", candidate_count: "1", refund_micros: "594137836" });
}
if (mode === "rebuild-derived") {
  if (!sql.includes("DELETE FROM failed_request_cost_adjustment_daily")
    || /DELETE\s+FROM\s+(?:request_records|request_stats_facts|ledger_entries)\b/iu.test(sql)
    || /UPDATE\s+(?:request_records|request_stats_facts|ledger_entries)\b/iu.test(sql)) process.exit(9);
  receipt({ outcome: "rebuilt", daily_rows: "1" });
}
if (!sql.includes("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
  || /\b(?:INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|LOCK)\b/u.test(sql)) process.exit(9);
receipt({ outcome: "pass", aggregate_counts: { plans: "1", items: "1", refund_micros: "594137836", invalid_ledger_pairs: "0", derived_daily_mismatches: "0" } });
