import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { installExecutableHelper, repository } from "./contract-helpers.ts";

const script = join(repository, "ops/reconcile-final-price-cache.ts");

function runReconciliation(workspace: string, gaps: number, args: readonly string[] = []) {
  const passFile = join(workspace, "pgpass");
  writeFileSync(passFile, "fixture-host:5432:fixture:fixture:fixture-only-password\n", { mode: 0o600 });
  chmodSync(passFile, 0o600);
  writeFileSync(join(workspace, "price-cache-reconciliation-fixture.json"), JSON.stringify({ current_price_gap_count: gaps }), { mode: 0o600 });
  return spawnSync(process.execPath, [script, ...args], {
    encoding: "utf8",
    shell: false,
    env: {
      PATH: `${workspace}:${process.env.PATH ?? ""}`,
      PRICE_RECON_PGHOST: "fixture-host",
      PRICE_RECON_PGUSER: "fixture-user",
      PRICE_RECON_PGDATABASE: "fixture-db",
      PRICE_RECON_PGPASSFILE: passFile,
      PRICE_RECON_TENANT_EXTERNAL_ID: "fixture-tenant",
      PRICE_RECON_IMPORT_SOURCE: "fixture-import-source",
      PRICE_RECON_CURRENCY: "USD",
    },
  });
}

test("final price/cache reconciliation emits a read-only aggregate receipt", () => {
  const workspace = mkdtempSync(join(tmpdir(), "mtc-price-cache-reconciliation."));
  try {
    installExecutableHelper("tests/ops/helpers/fake-psql-price-cache-reconciliation.ts", workspace, "psql");
    const result = runReconciliation(workspace, 0);
    assert.equal(result.status, 0, result.stderr);
    const receipt = JSON.parse(result.stdout) as Record<string, unknown>;
    assert.equal(receipt.mode, "dry-run");
    assert.equal(receipt.outcome, "pass");
    assert.deepEqual(receipt.blockers, []);
    const scope = receipt.scope;
    assert.ok(scope && typeof scope === "object");
    const tenantExternalIdSha256 = (scope as Record<string, unknown>).tenant_external_id_sha256;
    assert.ok(typeof tenantExternalIdSha256 === "string");
    assert.equal(tenantExternalIdSha256.length, 64);
    const nested = receipt.receipt as Record<string, unknown>;
    assert.equal((nested.per_key_model_day as unknown[]).length, 1);
    assert.equal(result.stdout.includes("fixture-only-password"), false);
    assert.equal(result.stdout.includes("request_object"), false);
    const invocation = JSON.parse(readFileSync(join(workspace, "psql.json"), "utf8")) as { argv: string[]; sql: string; pgpassfile: string };
    assert.equal(invocation.argv.some((value) => value.includes("fixture-only-password")), false);
    assert.match(invocation.sql, /BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY/);
    assert.doesNotMatch(invocation.sql, /\b(?:INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|LOCK)\b/);
    assert.equal(invocation.pgpassfile.endsWith("/pgpass"), true);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
});

test("current-price gaps are data-driven blockers and remain machine-readable", () => {
  const workspace = mkdtempSync(join(tmpdir(), "mtc-price-cache-gaps."));
  try {
    installExecutableHelper("tests/ops/helpers/fake-psql-price-cache-reconciliation.ts", workspace, "psql");
    const result = runReconciliation(workspace, 11, ["--dry-run"]);
    assert.equal(result.status, 1, result.stderr);
    const receipt = JSON.parse(result.stdout) as Record<string, unknown>;
    assert.equal(receipt.outcome, "blocked");
    assert.deepEqual(receipt.blockers, ["missing_current_price_combinations"]);
    const nested = receipt.receipt as Record<string, unknown>;
    assert.equal((nested.missing_current_price_combinations as unknown[]).length, 11);
    assert.equal(((nested.aggregate_counts as Record<string, string>).missing_current_price_combinations), "11");
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
});

test("final price/cache reconciliation has no apply mode", () => {
  const workspace = mkdtempSync(join(tmpdir(), "mtc-price-cache-no-apply."));
  try {
    const result = runReconciliation(workspace, 0, ["--apply"]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /read-only/);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
});
