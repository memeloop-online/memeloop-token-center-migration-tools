import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { installExecutableHelper } from "./contract-helpers.ts";

const repository = resolve(import.meta.dirname, "../..");
const script = join(repository, "ops/audit-cpa-migration.ts");

function runAudit(workspace: string, counts: string, expectedArchive = "5") {
  const env = {
    ...process.env,
    PATH: `${workspace}:${process.env.PATH ?? ""}`,
    PGHOST: "postgres.example.test",
    PGUSER: "fixture",
    PGPASSWORD: "fixture-only-password",
    PGDATABASE: "fixture",
    IMPORT_TENANT_EXTERNAL_ID: "cpa-fixture",
    CPAMP_IMPORT_SOURCE: "cpamp-fixture-v1",
    SESSION_ARCHIVE_IMPORT_SOURCE: "archive-fixture-v2",
    EXPECTED_CPAMP_EVENTS: "4",
    EXPECTED_ARCHIVE_RECORDS: expectedArchive,
    FAKE_PSQL_COUNTS: counts,
    FAKE_PSQL_LOG: join(workspace, "psql.json"),
  };
  return spawnSync(process.execPath, [script], { encoding: "utf8", env, shell: false });
}

test("CPA migration audit fails closed and emits only aggregate evidence", () => {
  const workspace = mkdtempSync(join(tmpdir(), "mtc-cpa-audit."));
  try {
    installExecutableHelper("tests/ops/helpers/fake-psql-audit.ts", workspace, "psql");

    const good = runAudit(workspace, "4|4|5|5000|5|3|2|3|2|0|0|0|2|5|1");
    assert.equal(good.status, 0, good.stderr);
    const evidence = JSON.parse(good.stdout) as Record<string, number>;
    assert.equal(evidence.cpamp_checkpoint, 4);
    assert.equal(evidence.archive_checkpoint, 5);
    assert.equal(evidence.archive_exact, 3);
    assert.equal(evidence.archive_unlinked, 2);
    assert.equal(evidence.conversation_clusters, 2);
    assert.equal(evidence.conversation_observations, 5);
    assert.equal(evidence.conversation_edges, 1);
    assert.equal(evidence.gap_locators, 0);
    const invocation = JSON.parse(readFileSync(join(workspace, "psql.json"), "utf8")) as { argv: string[]; sql: string };
    assert.equal(invocation.argv.some((value) => value.includes("fixture-only-password")), false);
    assert.match(invocation.sql, /BEGIN TRANSACTION READ ONLY/);

    const mismatch = runAudit(workspace, "4|4|5|5000|5|3|2|3|2|0|0|0|2|5|1", "6");
    assert.notEqual(mismatch.status, 0);
    assert.match(mismatch.stderr, /archive source, checkpoint, correlation, projection, or quarantine counts disagree/);

    for (const counts of [
      "4|4|5|5000|5|3|2|3|2|1|0|0|2|5|1",
      "4|4|5|5000|5|3|2|3|2|0|1|0|2|5|1",
    ]) {
      const rejected = runAudit(workspace, counts);
      assert.notEqual(rejected.status, 0);
      assert.match(rejected.stderr, /archive source, checkpoint, correlation, projection, or quarantine counts disagree/);
    }
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
});
