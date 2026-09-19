import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { installExecutableHelper, repository } from "./contract-helpers.ts";

const script = join(repository, "ops/adjust-failed-request-costs.ts");

function environment(workspace: string): NodeJS.ProcessEnv {
  const passFile = join(workspace, "pgpass");
  writeFileSync(passFile, "fixture-host:5432:fixture-db:fixture-user:fixture-password\n", { mode: 0o600 });
  chmodSync(passFile, 0o600);
  writeFileSync(join(workspace, "failed-request-adjustments-fixture.json"), JSON.stringify({}), { mode: 0o600 });
  return {
    PATH: `${workspace}:${process.env.PATH ?? ""}`,
    FRA_PGHOST: "fixture-host",
    FRA_PGUSER: "fixture-user",
    FRA_PGDATABASE: "fixture-db",
    FRA_PGPASSFILE: passFile,
    FRA_TENANT_EXTERNAL_ID: "fixture-tenant",
    FRA_FROM_MS: "1726358400000",
    FRA_TO_MS: "1726444800000",
  };
}

function invoke(args: readonly string[], env: NodeJS.ProcessEnv) {
  return spawnSync(process.execPath, [script, ...args], { encoding: "utf8", shell: false, env });
}

test("plan is read-only, excludes 504 by default, and writes a sealed approval artifact", () => {
  const workspace = mkdtempSync(join(tmpdir(), "mtc-failed-request-adjustments."));
  try {
    installExecutableHelper("tests/ops/helpers/fake-psql-failed-request-adjustments.ts", workspace, "psql");
    const planPath = join(workspace, "approval-plan.json");
    const result = invoke(["--plan"], { ...environment(workspace), FRA_PLAN_OUTPUT: planPath });
    assert.equal(result.status, 0, result.stderr);
    const receipt = JSON.parse(result.stdout) as Record<string, unknown>;
    assert.equal(receipt.mode, "plan");
    assert.equal(receipt.outcome, "ready_for_approval");
    assert.equal(receipt.refund_micros, "594137836");
    assert.equal(statSync(planPath).mode & 0o777, 0o600);
    const plan = JSON.parse(readFileSync(planPath, "utf8")) as Record<string, unknown>;
    assert.equal(plan.schema_version, "failed-request-cost-adjustment-plan-v1");
    assert.equal(typeof plan.plan_sha256, "string");
    const invocations = JSON.parse(readFileSync(join(workspace, "psql-invocations.json"), "utf8")) as Array<{ argv: string[]; sql: string }>;
    assert.equal(invocations.length, 1);
    assert.match(invocations[0]!.sql, /BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY/);
    assert.doesNotMatch(invocations[0]!.sql, /\b(?:INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|LOCK)\b/);
    assert.doesNotMatch(invocations[0]!.sql, /LEFT\s+JOIN\s+LATERAL/iu);
    const codes = invocations[0]!.argv.find((value) => value.startsWith("status_codes="));
    assert.equal(codes, "status_codes=499,502,503");
    assert.equal(result.stdout.includes("fixture-password"), false);
    assert.equal(result.stdout.includes("00000000-0000-5000-a000-000000000111"), false);
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});

test("blocked plans remain inspectable but cannot become silent partial refunds", () => {
  const workspace = mkdtempSync(join(tmpdir(), "mtc-failed-request-blocked."));
  try {
    installExecutableHelper("tests/ops/helpers/fake-psql-failed-request-adjustments.ts", workspace, "psql");
    const planPath = join(workspace, "blocked-plan.json");
    const fixture = join(workspace, "failed-request-adjustments-fixture.json");
    const env = { ...environment(workspace), FRA_PLAN_OUTPUT: planPath };
    writeFileSync(fixture, JSON.stringify({ blocked: true }), { mode: 0o600 });
    const result = invoke(["--plan"], env);
    assert.equal(result.status, 1, result.stderr);
    const receipt = JSON.parse(result.stdout) as Record<string, unknown>;
    assert.equal(receipt.outcome, "blocked");
    assert.equal(Array.isArray(receipt.blockers), true);
    assert.equal(statSync(planPath).mode & 0o777, 0o600);
    const apply = invoke(["--apply"], {
      ...env,
      FRA_APPROVED_PLAN: planPath,
      FRA_APPROVAL_REFERENCE: "ops-123",
      FRA_APPLY_CONFIRM: "APPLY_FAILED_REQUEST_COST_ADJUSTMENTS",
    });
    assert.notEqual(apply.status, 0);
    assert.match(apply.stderr, /unresolved accounting blockers/u);
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});

test("an empty scope is blocked before it can be presented as a successful correction", () => {
  const workspace = mkdtempSync(join(tmpdir(), "mtc-failed-request-empty."));
  try {
    installExecutableHelper("tests/ops/helpers/fake-psql-failed-request-adjustments.ts", workspace, "psql");
    const planPath = join(workspace, "empty-plan.json");
    const env = { ...environment(workspace), FRA_PLAN_OUTPUT: planPath };
    writeFileSync(join(workspace, "failed-request-adjustments-fixture.json"), JSON.stringify({ empty: true }), { mode: 0o600 });
    const result = invoke(["--plan"], env);
    assert.equal(result.status, 1, result.stderr);
    const receipt = JSON.parse(result.stdout) as { blockers: Array<{ reason: string }> };
    assert.equal(receipt.blockers.some((blocker) => blocker.reason === "empty_scope_requires_explicit_override"), true);
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});

test("apply requires an explicit confirmation and consumes the exact sealed plan without mutating evidence", () => {
  const workspace = mkdtempSync(join(tmpdir(), "mtc-failed-request-apply."));
  try {
    installExecutableHelper("tests/ops/helpers/fake-psql-failed-request-adjustments.ts", workspace, "psql");
    const planPath = join(workspace, "approval-plan.json");
    const env = { ...environment(workspace), FRA_PLAN_OUTPUT: planPath };
    assert.equal(invoke(["--plan"], env).status, 0);
    const rejected = invoke(["--apply"], { ...env, FRA_APPROVED_PLAN: planPath, FRA_APPROVAL_REFERENCE: "ops-123" });
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /FRA_APPLY_CONFIRM/u);
    const applied = invoke(["--apply"], {
      ...env,
      FRA_APPROVED_PLAN: planPath,
      FRA_APPROVAL_REFERENCE: "ops-123",
      FRA_APPLY_CONFIRM: "APPLY_FAILED_REQUEST_COST_ADJUSTMENTS",
    });
    assert.equal(applied.status, 0, applied.stderr);
    const output = JSON.parse(applied.stdout) as { receipt: { outcome: string } };
    assert.equal(output.receipt.outcome, "applied");
    const invocations = JSON.parse(readFileSync(join(workspace, "psql-invocations.json"), "utf8")) as Array<{ mode: string; sql: string }>;
    const applySql = invocations.find((entry) => entry.mode === "apply")!.sql;
    assert.match(applySql, /failed_request_refund/);
    assert.match(applySql, /failed_request_cost_adjustment_daily/);
    assert.doesNotMatch(applySql, /LOCK\s+TABLE/iu);
    assert.doesNotMatch(applySql, /LEFT\s+JOIN\s+LATERAL/iu);
    assert.doesNotMatch(applySql, /UPDATE\s+(?:request_records|ledger_entries)\b/iu);
    assert.doesNotMatch(applySql, /DELETE\s+FROM\s+(?:request_records|ledger_entries)\b/iu);
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});

test("a large sealed plan is streamed from its 0600 file instead of a psql argv payload", () => {
  const workspace = mkdtempSync(join(tmpdir(), "mtc-failed-request-large-plan."));
  try {
    installExecutableHelper("tests/ops/helpers/fake-psql-failed-request-adjustments.ts", workspace, "psql");
    const planPath = join(workspace, "large-approval-plan.json");
    const env = { ...environment(workspace), FRA_PLAN_OUTPUT: planPath };
    writeFileSync(join(workspace, "failed-request-adjustments-fixture.json"), JSON.stringify({ large: true }), { mode: 0o600 });
    const planned = invoke(["--plan"], env);
    assert.equal(planned.status, 0, planned.stderr);
    assert.ok(statSync(planPath).size > 128 * 1024);
    const applied = invoke(["--apply"], {
      ...env,
      FRA_APPROVED_PLAN: planPath,
      FRA_APPROVAL_REFERENCE: "ops-large-123",
      FRA_APPLY_CONFIRM: "APPLY_FAILED_REQUEST_COST_ADJUSTMENTS",
    });
    assert.equal(applied.status, 0, applied.stderr);
    const invocations = JSON.parse(readFileSync(join(workspace, "psql-invocations.json"), "utf8")) as Array<{ mode: string; argv: string[]; sql: string }>;
    const apply = invocations.find((entry) => entry.mode === "apply")!;
    assert.equal(apply.argv.some((value) => value.startsWith("plan_json=")), false);
    assert.equal(apply.argv.some((value) => value === `plan_file=${planPath}`), false);
    assert.equal(apply.argv.some((value) => /^plan_file=\/tmp\/mtc-failed-request-plan-/u.test(value)), true);
    assert.equal(Math.max(...apply.argv.map((value) => value.length)) < 8_192, true);
    assert.match(apply.sql, /\\copy fra_plan_payload\(payload\) FROM :'plan_file'/);
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});

test("verify is a separate read-only projection and evidence check", () => {
  const workspace = mkdtempSync(join(tmpdir(), "mtc-failed-request-verify."));
  try {
    installExecutableHelper("tests/ops/helpers/fake-psql-failed-request-adjustments.ts", workspace, "psql");
    const result = invoke(["--verify"], environment(workspace));
    assert.equal(result.status, 0, result.stderr);
    const receipt = JSON.parse(result.stdout) as { receipt: { outcome: string } };
    assert.equal(receipt.receipt.outcome, "pass");
    const invocations = JSON.parse(readFileSync(join(workspace, "psql-invocations.json"), "utf8")) as Array<{ sql: string }>;
    assert.match(invocations[0]!.sql, /READ ONLY/);
    assert.doesNotMatch(invocations[0]!.sql, /\b(?:INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|LOCK)\b/);
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});

test("derived correction totals have an explicit rebuild command that only replaces the derived view", () => {
  const workspace = mkdtempSync(join(tmpdir(), "mtc-failed-request-rebuild."));
  try {
    installExecutableHelper("tests/ops/helpers/fake-psql-failed-request-adjustments.ts", workspace, "psql");
    const env = environment(workspace);
    const rejected = invoke(["--rebuild-derived"], env);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /FRA_DERIVED_CONFIRM/u);
    const result = invoke(["--rebuild-derived"], {
      ...env,
      FRA_DERIVED_CONFIRM: "REBUILD_FAILED_REQUEST_ADJUSTMENT_DAILY",
    });
    assert.equal(result.status, 0, result.stderr);
    const receipt = JSON.parse(result.stdout) as { receipt: { outcome: string } };
    assert.equal(receipt.receipt.outcome, "rebuilt");
    const invocations = JSON.parse(readFileSync(join(workspace, "psql-invocations.json"), "utf8")) as Array<{ mode: string; sql: string }>;
    const sql = invocations.find((entry) => entry.mode === "rebuild-derived")!.sql;
    assert.match(sql, /DELETE FROM failed_request_cost_adjustment_daily/);
    assert.doesNotMatch(sql, /DELETE\s+FROM\s+(?:request_records|request_stats_facts|ledger_entries)\b/iu);
  } finally { rmSync(workspace, { recursive: true, force: true }); }
});
