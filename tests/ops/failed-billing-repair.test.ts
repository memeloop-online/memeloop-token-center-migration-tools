import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { installExecutableHelper, repository } from "./contract-helpers.ts";

const script = join(repository, "ops/reconcile-failed-billing.ts");

function runAudit(workspace: string, args: readonly string[] = [], omitTimeZone = false) {
  const passFile = join(workspace, "pgpass");
  writeFileSync(passFile, "fixture-host:5432:fixture:fixture:fixture-only-password\n", { mode: 0o600 });
  chmodSync(passFile, 0o600);
  const environment: NodeJS.ProcessEnv = {
    PATH: `${workspace}:${process.env.PATH ?? ""}`,
    FAILED_BILLING_PGHOST: "fixture-host",
    FAILED_BILLING_PGUSER: "fixture-user",
    FAILED_BILLING_PGDATABASE: "fixture-db",
    FAILED_BILLING_PGPASSFILE: passFile,
    FAILED_BILLING_FROM_LOCAL: "2026-09-16 11:00:00",
    FAILED_BILLING_TO_LOCAL: "2026-09-16 13:00:00",
    FAILED_BILLING_TIME_ZONE: "Asia/Shanghai",
    FAILED_BILLING_TENANT_EXTERNAL_ID: "fixture-tenant",
  };
  if (omitTimeZone) delete environment.FAILED_BILLING_TIME_ZONE;
  return spawnSync(process.execPath, [script, ...args], { encoding: "utf8", shell: false, env: environment });
}

test("failed-billing dry-run emits a candidate and keeps production writes out of SQL", () => {
  const workspace = mkdtempSync(join(tmpdir(), "mtc-failed-billing."));
  try {
    installExecutableHelper("tests/ops/helpers/fake-psql-failed-billing-repair.ts", workspace, "psql");
    const result = runAudit(workspace);
    assert.equal(result.status, 0, result.stderr);
    const receipt = JSON.parse(result.stdout) as Record<string, unknown>;
    assert.equal(receipt.mode, "dry-run");
    assert.equal(receipt.outcome, "review_required");
    const impact = receipt.impact as Record<string, string>;
    assert.equal(impact.interval_repair_eligible_rows, "1");
    assert.equal(impact.interval_repair_eligible_cost_micros, "5937130");
    const nested = receipt.receipt as Record<string, unknown>;
    const candidates = nested.repair_candidates as Array<Record<string, unknown>>;
    assert.equal(candidates.length, 1);
    assert.equal(candidates[0]?.provider_evidence, "none_observed");
    assert.equal((candidates[0]?.proposed as Record<string, string>).cost_micros, "0");
    assert.equal(result.stdout.includes("fixture-only-password"), false);
    const invocation = JSON.parse(readFileSync(join(workspace, "psql.json"), "utf8")) as { sql: string; pgpassfile: string };
    assert.match(invocation.sql, /BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY/);
    assert.doesNotMatch(invocation.sql, /\b(?:INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|LOCK)\b/);
    assert.match(invocation.sql, /usage_analysis_hourly/);
    assert.equal(invocation.pgpassfile.endsWith("/pgpass"), true);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
});
test("failed-billing audit requires an explicit local timezone", () => {
  const workspace = mkdtempSync(join(tmpdir(), "mtc-failed-billing-time-zone."));
  try {
    const result = runAudit(workspace, [], true);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /FAILED_BILLING_TIME_ZONE is required/);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
});

test("failed-billing audit has no apply mode", () => {
  const workspace = mkdtempSync(join(tmpdir(), "mtc-failed-billing-no-apply."));
  try {
    const result = runAudit(workspace, ["--apply"]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /read-only/);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
});
