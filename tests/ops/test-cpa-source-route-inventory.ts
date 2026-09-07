#!/usr/bin/env node

import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";
import { createHash } from "node:crypto";
import { parseSourceInventory } from "../../ops/legacy-routes/import-cpa-model-routes.ts";

const repository = resolve(import.meta.dirname, "../..");
const exporter = join(repository, "ops/legacy-routes/export-cpa-source-route-inventory.ts");
const keyGenerator = join(repository, "ops/cpa-upstreams/generate-source-identity-key.ts");
const apiKey = "fixture-only-route-export-api-key";
const opaqueHandle = "FixtureCopilotHandle";
const opaqueEmail = "fixture-route-export@example.test";

function writeSource(root: string, invalidModel = false): { config: string; auth: string; policy: string; key: string } {
  const source = join(root, "source"), auth = join(source, "auth"); mkdirSync(auth, { recursive: true, mode: 0o700 }); chmodSync(source, 0o700); chmodSync(auth, 0o700);
  const config = join(source, "config.yaml");
  writeFileSync(config, [
    'auth-dir: "/sealed/auth"',
    "openai-compatibility:",
    '  - name: "astra-provider"',
    '    prefix: "astra"',
    '    base-url: "https://astra.example.test/v1"',
    "    api-key-entries:",
    `      - api-key: "${apiKey}-a"`,
    `      - api-key: "${apiKey}-b"`,
    "    models:",
    '      - name: "gpt-6-astra-upstream"',
    '        alias: "gpt-6-astra"',
    ...(invalidModel ? ["        unsupported: true"] : []),
    ""].join("\n"), { mode: 0o600 });
  writeFileSync(join(auth, "copilot.json"), JSON.stringify({ type: "copilot", upstream: "copilot", handle: opaqueHandle, label: opaqueEmail }), { mode: 0o600 });
  const policy = join(root, "native-policy.json");
  writeFileSync(policy, JSON.stringify({
    version: 1,
    policies: [
      { key_hash: "a".repeat(64), enabled: true, grants: [
        { provider: "astra-provider", model: "gpt-6-astra", group: "text", upstream_prefix: "astra" },
        { provider: "astra-provider", model: "gpt-6-malformed", upstream_prefix: "astra" },
      ] },
      { key_hash: "b".repeat(64), enabled: false, grants: [{ provider: "astra-provider", model: "disabled-only", group: "text", upstream_prefix: "astra" }] },
    ],
    usage: {},
  }), { mode: 0o600 });
  const key = join(root, "source-identity.key");
  const generated = spawnSync(process.execPath, [keyGenerator, key], { encoding: "utf8" }); assert.equal(generated.status, 0, generated.stderr);
  return { config, auth, policy, key };
}
function exportArguments(source: { config: string; auth: string; policy: string; key: string }, output: string): string[] {
  return [exporter, "--config", source.config, "--auth-dir", source.auth, "--policy-snapshot-file", source.policy, "--source-identity-key-file", source.key, "--source-inventory-output", join(output, "source-inventory.json"), "--provider-candidate-material-output", join(output, "provider-candidate-material.json")];
}

describe("CPA source route inventory exporter", () => {
  it("dynamically seals a newly introduced model and its complete exact two-account provider pool", () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-source-route-export-")), source = writeSource(root), output = join(root, "output"); mkdirSync(output, { mode: 0o700 });
    const result = spawnSync(process.execPath, exportArguments(source, output), { encoding: "utf8" }); assert.equal(result.status, 0, result.stderr);
    const receipt = JSON.parse(result.stdout) as Record<string, unknown>, sourcePath = join(output, "source-inventory.json"), materialPath = join(output, "provider-candidate-material.json");
    assert.equal(receipt.source_mapping_count, 1); assert.equal(receipt.provider_candidate_set_count, 1); assert.equal(receipt.source_account_candidate_count, 2); assert.equal(receipt.reauthorization_required_count, 1); assert.equal(receipt.anomaly_count, 1);
    assert.equal(statSync(sourcePath).mode & 0o777, 0o600); assert.equal(statSync(materialPath).mode & 0o777, 0o600);
    const sourceInventory = JSON.parse(readFileSync(sourcePath, "utf8")) as Record<string, unknown>, material = JSON.parse(readFileSync(materialPath, "utf8")) as Record<string, unknown>;
    assert.equal(sourceInventory.version, 2); assert.deepEqual(sourceInventory.mappings, [{ provider: "astra-provider", model: "gpt-6-astra", group: "text", upstream_prefix: "astra", protocol: "openai" }]);
    assert.deepEqual(sourceInventory.anomalies, [{ provider: "astra-provider", model: "gpt-6-malformed", reason: "source grant lacks exact route coordinates" }]);
    assert.equal(parseSourceInventory(readFileSync(sourcePath)).reauthorizationRequired, 1);
    assert.deepEqual(sourceInventory.reauthorization_required && (sourceInventory.reauthorization_required as unknown[]).map((item) => Object.keys(item as Record<string, unknown>).sort()), [["provider", "source_stable_id"]]);
    const firstReauthorization = sourceInventory.reauthorization_required as Array<Record<string, unknown>>; assert.match(String(firstReauthorization[0]!.source_stable_id), /^[0-9a-f]{64}$/u);
    const pools = material.provider_candidate_sets as Array<Record<string, unknown>>; assert.equal(material.version, 1); assert.equal(material.source_inventory_sha256, createHash("sha256").update(readFileSync(sourcePath)).digest("hex")); assert.equal(pools.length, 1);
    assert.deepEqual(pools[0]!.source, (sourceInventory.mappings as unknown[])[0]); assert.equal(pools[0]!.upstream_model, "gpt-6-astra-upstream"); assert.equal(pools[0]!.protocol, "openai"); assert.equal(pools[0]!.selection, "equal_round_robin");
    const candidates = pools[0]!.candidates as Array<Record<string, unknown>>; assert.equal(candidates.length, 2); assert.deepEqual(candidates.map((item) => item.driver), ["http-json", "http-json"]); assert.deepEqual(candidates.map((item) => item.source_provider), ["astra-provider", "astra-provider"]); assert.equal(new Set(candidates.map((item) => item.source_stable_id)).size, 2);
    const outputText = `${result.stdout}${result.stderr}${readFileSync(sourcePath, "utf8")}${readFileSync(materialPath, "utf8")}`;
    for (const forbidden of [apiKey, opaqueHandle, opaqueEmail, "/sealed/auth", source.config, source.auth, source.key]) assert.doesNotMatch(outputText, new RegExp(forbidden.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")));
    assert.deepEqual(readdirSync(output).sort(), ["provider-candidate-material.json", "source-inventory.json"]);
    const replayOutput = join(root, "replay-output"); mkdirSync(replayOutput, { mode: 0o700 }); const replay = spawnSync(process.execPath, exportArguments(source, replayOutput), { encoding: "utf8" }); assert.equal(replay.status, 0, replay.stderr);
    assert.deepEqual(JSON.parse(readFileSync(join(replayOutput, "source-inventory.json"), "utf8")).reauthorization_required, firstReauthorization);
  });

  it("is no-overwrite on repetition and leaves no partial outputs for an unsupported source model shape", () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-source-route-repeat-")), source = writeSource(root), output = join(root, "output"); mkdirSync(output, { mode: 0o700 });
    const first = spawnSync(process.execPath, exportArguments(source, output), { encoding: "utf8" }); assert.equal(first.status, 0, first.stderr);
    const sourcePath = join(output, "source-inventory.json"), materialPath = join(output, "provider-candidate-material.json"), initialSource = readFileSync(sourcePath), initialMaterial = readFileSync(materialPath);
    const repeated = spawnSync(process.execPath, exportArguments(source, output), { encoding: "utf8" }); assert.equal(repeated.status, 2); assert.deepEqual(readFileSync(sourcePath), initialSource); assert.deepEqual(readFileSync(materialPath), initialMaterial);
    const invalidRoot = mkdtempSync(join(tmpdir(), "mtc-source-route-invalid-")), invalid = writeSource(invalidRoot, true), invalidOutput = join(invalidRoot, "output"); mkdirSync(invalidOutput, { mode: 0o700 });
    const rejected = spawnSync(process.execPath, exportArguments(invalid, invalidOutput), { encoding: "utf8" }); assert.equal(rejected.status, 2); assert.equal(existsSync(join(invalidOutput, "source-inventory.json")), false); assert.equal(existsSync(join(invalidOutput, "provider-candidate-material.json")), false); assert.doesNotMatch(rejected.stderr, /fixture-only-route-export-api-key|FixtureCopilotHandle|fixture-route-export@example/u);
    const missingRoot = mkdtempSync(join(tmpdir(), "mtc-source-route-missing-")), missing = writeSource(missingRoot), missingOutput = join(missingRoot, "output"); mkdirSync(missingOutput, { mode: 0o700 });
    writeFileSync(missing.policy, JSON.stringify({ version: 1, policies: [{ key_hash: "c".repeat(64), enabled: true, grants: [{ provider: "astra-provider", model: "unresolved", group: "text", upstream_prefix: "astra" }] }], usage: {} }), { mode: 0o600 });
    const unresolved = spawnSync(process.execPath, exportArguments(missing, missingOutput), { encoding: "utf8" }); assert.equal(unresolved.status, 2); assert.equal(existsSync(join(missingOutput, "source-inventory.json")), false); assert.equal(existsSync(join(missingOutput, "provider-candidate-material.json")), false);
  });
});
