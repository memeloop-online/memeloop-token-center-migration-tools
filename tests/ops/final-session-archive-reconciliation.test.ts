import assert from "node:assert/strict";
import { chmodSync, copyFileSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { main, validateFinalArtifactSet } from "../../ops/finalize-session-archive-delta.ts";

const ROOT = resolve(import.meta.dirname, "../..");
const FIXTURES = join(ROOT, "tests/fixtures/final-session-archive");

function copyFixture(directory: string, name: string): string {
  const target = join(directory, name);
  copyFileSync(join(FIXTURES, name), target);
  copyFileSync(join(FIXTURES, `${name}.manifest.json`), `${target}.manifest.json`);
  chmodSync(target, 0o600);
  chmodSync(`${target}.manifest.json`, 0o600);
  return target;
}

test("final archive reconciliation seals a snapshot-to-delta chain before a dry run", async () => {
  const directory = mkdtempSync(join(tmpdir(), "mtc-final-archive."));
  try {
    const baseline = copyFixture(directory, "baseline.jsonl");
    const delta = copyFixture(directory, "final-delta.jsonl");
    const set = validateFinalArtifactSet([baseline, delta]);
    assert.equal(set.finalArtifact.sourceRecordsAfter, 5);
    assert.equal(set.artifacts.length, 2);
    assert.match(set.artifactSetSha256, /^[0-9a-f]{64}$/);

    const receipt = join(directory, "dry-run-receipt.json");
    assert.equal(await main(["--artifact", baseline, "--artifact", delta, "--receipt", receipt]), 0);
    assert.equal(statSync(receipt).mode & 0o777, 0o600);
    const parsed = JSON.parse(readFileSync(receipt, "utf8")) as Record<string, unknown>;
    assert.equal(parsed.mode, "dry-run");
    assert.equal(parsed.status, "sealed-awaiting-approved-apply");
    assert.deepEqual(parsed.quarantine, { measurement: "not-performed" });
    assert.deepEqual(parsed.content_locator, { measurement: "not-performed" });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("final archive reconciliation rejects incomplete chains and duplicate receipts", async () => {
  const directory = mkdtempSync(join(tmpdir(), "mtc-final-archive."));
  try {
    const baseline = copyFixture(directory, "baseline.jsonl");
    const delta = copyFixture(directory, "final-delta.jsonl");
    assert.throws(() => validateFinalArtifactSet([baseline]), /final snapshot and at least one delta/);
    const receipt = join(directory, "receipt.json");
    assert.equal(await main(["--artifact", baseline, "--artifact", delta, "--receipt", receipt]), 0);
    await assert.rejects(main(["--artifact", baseline, "--artifact", delta, "--receipt", receipt]), /receipt path already exists/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
