#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";

const repository = resolve(import.meta.dirname, "../..");
const composer = join(repository, "ops/legacy-routes/compose-cpa-upstream-inventory.ts");
const hash = (value: Buffer | string): string => createHash("sha256").update(value).digest("hex");

function privateJson(path: string, value: unknown): Buffer {
  const raw = Buffer.from(`${JSON.stringify(value)}\n`);
  writeFileSync(path, raw, { mode: 0o600 }); chmodSync(path, 0o600);
  return raw;
}

describe("CPA upstream-inventory composition", () => {
  it("requires complete typed direct and managed bindings before publishing v2", () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-upstream-compose-")); chmodSync(root, 0o700);
    const sourcePath = join(root, "source-inventory.json");
    const source = privateJson(sourcePath, {
      version: 2,
      mappings: [
        { provider: "fixture-direct", model: "fixture-direct-model", group: null, upstream_prefix: null, protocol: "openai" },
        { provider: "codex", model: "fixture-codex-model", group: "fixture-group", upstream_prefix: null, protocol: "openai" },
      ],
      reauthorization_required: [],
      anomalies: [],
    });
    const directStableId = "a".repeat(64), managedStableId = "b".repeat(64);
    const materialPath = join(root, "provider-candidate-material.json");
    const material = privateJson(materialPath, {
      version: 1,
      source_inventory_sha256: hash(source),
      provider_candidate_sets: [
        { source: { provider: "fixture-direct", model: "fixture-direct-model", group: null, upstream_prefix: null, protocol: "openai" }, upstream_model: "fixture-direct-upstream", protocol: "openai", selection: "equal_round_robin", candidates: [{ source_stable_id: directStableId, source_provider: "fixture-direct", driver: "http-json" }] },
        { source: { provider: "codex", model: "fixture-codex-model", group: "fixture-group", upstream_prefix: null, protocol: "openai" }, upstream_model: "fixture-codex-upstream", protocol: "openai", selection: "equal_round_robin", candidates: [{ source_stable_id: managedStableId, source_provider: "codex", driver: "openai-codex" }] },
      ],
    });
    const directPath = join(root, "direct-receipt.json");
    privateJson(directPath, {
      version: 1, tenant_external_id: "default", source_inventory_sha256: hash(source), provider_candidate_material_sha256: hash(material),
      bindings: [{ source_stable_id: directStableId, source_provider: "fixture-direct", upstream_account_id: "10000000-0000-4000-8000-000000000001", driver: "http-json", status: "active", updated_at: 7 }], quarantined: [],
    });
    const managedPath = join(root, "managed-receipt.json");
    privateJson(managedPath, {
      version: 1, tenant_external_id: "default", source_inventory_sha256: hash(source), provider_candidate_material_sha256: hash(material), managed_provenance_evidence_sha256: "c".repeat(64),
      bindings: [{ source_stable_id: managedStableId, source_provider: "codex", upstream_account_id: "10000000-0000-4000-8000-000000000002", driver: "openai-codex", status: "active", updated_at: 9 }], quarantined: [],
    });
    const output = join(root, "upstream-inventory.json");
    const arguments_ = [composer, "--source-inventory-file", sourcePath, "--provider-candidate-material-file", materialPath, "--direct-binding-receipt-file", directPath, "--managed-binding-receipt-file", managedPath, "--upstream-inventory-output", output];
    const result = spawnSync(process.execPath, arguments_, { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    const summary = JSON.parse(result.stdout) as Record<string, unknown>, inventory = JSON.parse(readFileSync(output, "utf8")) as Record<string, unknown>;
    assert.equal(summary.mode, "compose-cpa-upstream-inventory"); assert.equal(summary.upstream_count, 2); assert.equal(summary.provider_candidate_set_count, 2);
    assert.equal(statSync(output).mode & 0o777, 0o600);
    assert.deepEqual(inventory.upstreams, [
      { upstream_account_id: "10000000-0000-4000-8000-000000000001", source_stable_id: directStableId, source_provider: "fixture-direct", driver: "http-json", status: "active", updated_at: 7 },
      { upstream_account_id: "10000000-0000-4000-8000-000000000002", source_stable_id: managedStableId, source_provider: "codex", driver: "openai-codex", status: "active", updated_at: 9 },
    ]);
    assert.doesNotMatch(`${result.stdout}${result.stderr}${readFileSync(output, "utf8")}`, /fixture-.*-secret|source-id|account-name/);

    const retained = readFileSync(output);
    const overwrite = spawnSync(process.execPath, arguments_, { encoding: "utf8" });
    assert.equal(overwrite.status, 2); assert.deepEqual(readFileSync(output), retained);

    const quarantinedManagedPath = join(root, "managed-receipt-quarantined.json");
    privateJson(quarantinedManagedPath, {
      version: 1, tenant_external_id: "default", source_inventory_sha256: hash(source), provider_candidate_material_sha256: hash(material), managed_provenance_evidence_sha256: "c".repeat(64),
      bindings: [{ source_stable_id: managedStableId, source_provider: "codex", upstream_account_id: "10000000-0000-4000-8000-000000000002", driver: "openai-codex", status: "active", updated_at: 9 }], quarantined: [{ source_stable_id: "d".repeat(64), source_provider: "codex", reason: "target_absent" }],
    });
    const rejectedOutput = join(root, "upstream-inventory-rejected.json");
    const rejected = spawnSync(process.execPath, [...arguments_.map((value, index, values) => value === managedPath && values[index - 1] === "--managed-binding-receipt-file" ? quarantinedManagedPath : value).map((value, index, values) => value === output && values[index - 1] === "--upstream-inventory-output" ? rejectedOutput : value)], { encoding: "utf8" });
    assert.equal(rejected.status, 2); assert.throws(() => readFileSync(rejectedOutput));

    const missingManagedPath = join(root, "managed-receipt-missing.json");
    privateJson(missingManagedPath, {
      version: 1, tenant_external_id: "default", source_inventory_sha256: hash(source), provider_candidate_material_sha256: hash(material), managed_provenance_evidence_sha256: "c".repeat(64),
      bindings: [], quarantined: [],
    });
    const missingOutput = join(root, "upstream-inventory-missing.json");
    const missing = spawnSync(process.execPath, [...arguments_.map((value, index, values) => value === managedPath && values[index - 1] === "--managed-binding-receipt-file" ? missingManagedPath : value).map((value, index, values) => value === output && values[index - 1] === "--upstream-inventory-output" ? missingOutput : value)], { encoding: "utf8" });
    assert.equal(missing.status, 2); assert.throws(() => readFileSync(missingOutput));

    const mismatchedManagedPath = join(root, "managed-receipt-mismatched.json");
    privateJson(mismatchedManagedPath, {
      version: 1, tenant_external_id: "default", source_inventory_sha256: hash(source), provider_candidate_material_sha256: hash(material), managed_provenance_evidence_sha256: "c".repeat(64),
      bindings: [{ source_stable_id: managedStableId, source_provider: "wrong-provider", upstream_account_id: "10000000-0000-4000-8000-000000000002", driver: "openai-codex", status: "active", updated_at: 9 }], quarantined: [],
    });
    const mismatchedOutput = join(root, "upstream-inventory-mismatched.json");
    const mismatched = spawnSync(process.execPath, [...arguments_.map((value, index, values) => value === managedPath && values[index - 1] === "--managed-binding-receipt-file" ? mismatchedManagedPath : value).map((value, index, values) => value === output && values[index - 1] === "--upstream-inventory-output" ? mismatchedOutput : value)], { encoding: "utf8" });
    assert.equal(mismatched.status, 2); assert.throws(() => readFileSync(mismatchedOutput));
  });
});
