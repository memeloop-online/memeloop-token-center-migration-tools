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
    '  - name: "kimi"',
    '    base-url: "https://kimi.example.test/v1"',
    "    api-key-entries:",
    `      - api-key: "${apiKey}-a"`,
    `      - api-key: "${apiKey}-b"`,
    "    models:",
    '      - name: "kimi-k2-upstream"',
    '        alias: "kimi-k2"',
    '  - name: "westlake"',
    '    base-url: "https://westlake.example.test/v1"',
    "    api-key-entries:",
    `      - api-key: "${apiKey}-westlake"`,
    "    models:",
    '      - name: "westlake-null-upstream"',
    '        alias: "westlake-null"',
    '      - name: "westlake-prefixed-upstream"',
    '        alias: "westlake-prefixed"',
    '        prefix: "westlake"',
    "codex-api-key:",
    `  - api-key: "${apiKey}-codex"`,
    '    base-url: "https://codex.example.test/v1"',
    "    models:",
    '      - name: "gpt-6-astra-upstream"',
    '        alias: "gpt-6-astra"',
    '      - name: "gpt-6-group-only-upstream"',
    '        alias: "gpt-6-group-only"',
    '      - name: "gpt-6-prefix-default-upstream"',
    '        alias: "gpt-6-prefix"',
    '        prefix: "codex"',
    '      - name: "gpt-6-prefix-csil-upstream"',
    '        alias: "gpt-6-prefix"',
    '        prefix: "codex-csil"',
    ...(invalidModel ? ["        unsupported: true"] : []),
    ""].join("\n"), { mode: 0o600 });
  writeFileSync(join(auth, "copilot.json"), JSON.stringify({ type: "copilot", upstream: "copilot", handle: opaqueHandle, label: opaqueEmail, created_at: "2026-09-09T12:00:00Z" }), { mode: 0o600 });
  const policy = join(root, "native-policy.json");
  writeFileSync(policy, JSON.stringify({
    version: 1,
    policies: [
      { key_hash: "a".repeat(64), enabled: true, grants: [
        { provider: "codex", model: "gpt-6-astra" },
        { provider: "kimi", model: "kimi-k2" },
        { provider: "westlake", model: "westlake-null", group: "westlake" },
        { provider: "westlake", model: "westlake-prefixed", group: "westlake", upstream_prefix: "westlake" },
        { provider: "codex", model: "gpt-6-group-only", group: "csil" },
        { provider: "codex", model: "gpt-6-prefix", group: "standard", upstream_prefix: "codex" },
        { provider: "codex", model: "gpt-6-prefix", group: "csil", upstream_prefix: "codex-csil" },
        { provider: "codex", group: "malformed" },
      ] },
      { key_hash: "b".repeat(64), enabled: false, grants: [{ provider: "codex", model: "disabled-only" }] },
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
  it("dynamically seals nullable exact source coordinates and a complete provider pool", () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-source-route-export-")), source = writeSource(root), output = join(root, "output"); mkdirSync(output, { mode: 0o700 });
    const result = spawnSync(process.execPath, exportArguments(source, output), { encoding: "utf8" }); assert.equal(result.status, 0, result.stderr);
    const receipt = JSON.parse(result.stdout) as Record<string, unknown>, sourcePath = join(output, "source-inventory.json"), materialPath = join(output, "provider-candidate-material.json");
    assert.equal(receipt.source_mapping_count, 7); assert.equal(receipt.provider_candidate_set_count, 7); assert.equal(receipt.source_account_candidate_count, 8); assert.equal(receipt.reauthorization_required_count, 1); assert.equal(receipt.anomaly_count, 1);
    assert.equal(statSync(sourcePath).mode & 0o777, 0o600); assert.equal(statSync(materialPath).mode & 0o777, 0o600);
    const sourceInventory = JSON.parse(readFileSync(sourcePath, "utf8")) as Record<string, unknown>, material = JSON.parse(readFileSync(materialPath, "utf8")) as Record<string, unknown>;
    assert.equal(sourceInventory.version, 2);
    const mappings = sourceInventory.mappings as Array<Record<string, unknown>>;
    assert.equal(mappings.length, 7);
    const mappingFor = (provider: string, model: string, upstreamPrefix: string | null): Record<string, unknown> | undefined => mappings.find((item) => item.provider === provider && item.model === model && item.upstream_prefix === upstreamPrefix);
    assert.deepEqual(mappingFor("codex", "gpt-6-astra", null), { provider: "codex", model: "gpt-6-astra", group: null, upstream_prefix: null, protocol: "openai" });
    assert.deepEqual(mappingFor("kimi", "kimi-k2", null), { provider: "kimi", model: "kimi-k2", group: null, upstream_prefix: null, protocol: "openai" });
    assert.deepEqual(mappingFor("westlake", "westlake-null", null), { provider: "westlake", model: "westlake-null", group: "westlake", upstream_prefix: null, protocol: "openai" });
    assert.deepEqual(mappingFor("westlake", "westlake-prefixed", "westlake"), { provider: "westlake", model: "westlake-prefixed", group: "westlake", upstream_prefix: "westlake", protocol: "openai" });
    assert.deepEqual(mappingFor("codex", "gpt-6-group-only", null), { provider: "codex", model: "gpt-6-group-only", group: "csil", upstream_prefix: null, protocol: "openai" });
    assert.deepEqual(mappingFor("codex", "gpt-6-prefix", "codex"), { provider: "codex", model: "gpt-6-prefix", group: "standard", upstream_prefix: "codex", protocol: "openai" });
    assert.deepEqual(mappingFor("codex", "gpt-6-prefix", "codex-csil"), { provider: "codex", model: "gpt-6-prefix", group: "csil", upstream_prefix: "codex-csil", protocol: "openai" });
    assert.deepEqual(sourceInventory.anomalies, [{ provider: "codex", model: "unknown", reason: "source grant lacks provider or model route coordinates" }]);
    assert.equal(parseSourceInventory(readFileSync(sourcePath)).reauthorizationRequired, 1);
    assert.deepEqual(sourceInventory.reauthorization_required && (sourceInventory.reauthorization_required as unknown[]).map((item) => Object.keys(item as Record<string, unknown>).sort()), [["provider", "source_stable_id"]]);
    const firstReauthorization = sourceInventory.reauthorization_required as Array<Record<string, unknown>>; assert.match(String(firstReauthorization[0]!.source_stable_id), /^[0-9a-f]{64}$/u);
    const pools = material.provider_candidate_sets as Array<Record<string, unknown>>; assert.equal(material.version, 1); assert.equal(material.source_inventory_sha256, createHash("sha256").update(readFileSync(sourcePath)).digest("hex")); assert.equal(pools.length, 7);
    const kimiPool = pools.find((item) => (item.source as Record<string, unknown>).provider === "kimi"); assert(kimiPool); assert.equal(kimiPool.upstream_model, "kimi-k2-upstream"); assert.equal(kimiPool.protocol, "openai"); assert.equal(kimiPool.selection, "equal_round_robin");
    const candidates = kimiPool.candidates as Array<Record<string, unknown>>; assert.equal(candidates.length, 2); assert.deepEqual(candidates.map((item) => item.driver), ["http-json", "http-json"]); assert.deepEqual(candidates.map((item) => item.source_provider), ["kimi", "kimi"]); assert.equal(new Set(candidates.map((item) => item.source_stable_id)).size, 2);
    const westlakePools = pools.filter((item) => (item.source as Record<string, unknown>).provider === "westlake"); assert.equal(westlakePools.length, 2); assert.deepEqual(westlakePools.map((item) => (item.source as Record<string, unknown>).upstream_prefix).sort(), [null, "westlake"]); assert.deepEqual(westlakePools.map((item) => (item.candidates as unknown[]).length).sort(), [1, 1]);
    const outputText = `${result.stdout}${result.stderr}${readFileSync(sourcePath, "utf8")}${readFileSync(materialPath, "utf8")}`;
    for (const forbidden of [apiKey, opaqueHandle, opaqueEmail, "/sealed/auth", source.config, source.auth, source.key]) assert.doesNotMatch(outputText, new RegExp(forbidden.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")));
    assert.deepEqual(readdirSync(output).sort(), ["provider-candidate-material.json", "source-inventory.json"]);
    const replayOutput = join(root, "replay-output"); mkdirSync(replayOutput, { mode: 0o700 }); const replay = spawnSync(process.execPath, exportArguments(source, replayOutput), { encoding: "utf8" }); assert.equal(replay.status, 0, replay.stderr);
    assert.deepEqual(JSON.parse(readFileSync(join(replayOutput, "source-inventory.json"), "utf8")).reauthorization_required, firstReauthorization);
  });

  it("uses CPA's name fallback for omitted or empty aliases and ignores catalog-only display names", () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-source-route-cpa-alias-")), source = writeSource(root), output = join(root, "output"); mkdirSync(output, { mode: 0o700 });
    writeFileSync(source.config, [
      'auth-dir: "/sealed/auth"',
      "openai-compatibility:",
      '  - name: "fixture-route-provider"',
      '    base-url: "https://route-provider.example.test/v1"',
      "    api-key-entries:",
      `      - api-key: "${apiKey}-alias"`,
      "    models:",
      '      - name: "fixture-empty-alias-upstream"',
      '        alias: ""',
      '        display-name: "Fixture empty alias catalog label"',
      '      - name: "fixture-omitted-alias-upstream"',
      "",
    ].join("\n"), { mode: 0o600 });
    writeFileSync(source.policy, JSON.stringify({
      version: 1,
      policies: [{ key_hash: "c".repeat(64), enabled: true, grants: [
        { provider: "fixture-route-provider", model: "fixture-empty-alias-upstream" },
        { provider: "fixture-route-provider", model: "fixture-omitted-alias-upstream" },
      ] }],
      usage: {},
    }), { mode: 0o600 });
    const result = spawnSync(process.execPath, exportArguments(source, output), { encoding: "utf8" }); assert.equal(result.status, 0, result.stderr);
    const sourceInventory = JSON.parse(readFileSync(join(output, "source-inventory.json"), "utf8")) as Record<string, unknown>;
    assert.deepEqual(sourceInventory.mappings, [
      { provider: "fixture-route-provider", model: "fixture-empty-alias-upstream", group: null, upstream_prefix: null, protocol: "openai" },
      { provider: "fixture-route-provider", model: "fixture-omitted-alias-upstream", group: null, upstream_prefix: null, protocol: "openai" },
    ]);

    const invalidRoot = mkdtempSync(join(tmpdir(), "mtc-source-route-cpa-alias-invalid-")), invalid = writeSource(invalidRoot), invalidOutput = join(invalidRoot, "output"); mkdirSync(invalidOutput, { mode: 0o700 });
    writeFileSync(invalid.config, readFileSync(invalid.config, "utf8").replace('        alias: "kimi-k2"', "        alias: 42"), { mode: 0o600 });
    const rejected = spawnSync(process.execPath, exportArguments(invalid, invalidOutput), { encoding: "utf8" }); assert.equal(rejected.status, 2); assert.equal(existsSync(join(invalidOutput, "source-inventory.json")), false); assert.equal(existsSync(join(invalidOutput, "provider-candidate-material.json")), false);
  });

  it("is no-overwrite on repetition and leaves no partial outputs for an unsupported source model shape", () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-source-route-repeat-")), source = writeSource(root), output = join(root, "output"); mkdirSync(output, { mode: 0o700 });
    const first = spawnSync(process.execPath, exportArguments(source, output), { encoding: "utf8" }); assert.equal(first.status, 0, first.stderr);
    const sourcePath = join(output, "source-inventory.json"), materialPath = join(output, "provider-candidate-material.json"), initialSource = readFileSync(sourcePath), initialMaterial = readFileSync(materialPath);
    const repeated = spawnSync(process.execPath, exportArguments(source, output), { encoding: "utf8" }); assert.equal(repeated.status, 2); assert.deepEqual(readFileSync(sourcePath), initialSource); assert.deepEqual(readFileSync(materialPath), initialMaterial);
    const invalidRoot = mkdtempSync(join(tmpdir(), "mtc-source-route-invalid-")), invalid = writeSource(invalidRoot, true), invalidOutput = join(invalidRoot, "output"); mkdirSync(invalidOutput, { mode: 0o700 });
    const rejected = spawnSync(process.execPath, exportArguments(invalid, invalidOutput), { encoding: "utf8" }); assert.equal(rejected.status, 2); assert.equal(existsSync(join(invalidOutput, "source-inventory.json")), false); assert.equal(existsSync(join(invalidOutput, "provider-candidate-material.json")), false); assert.doesNotMatch(rejected.stderr, /fixture-only-route-export-api-key|FixtureCopilotHandle|fixture-route-export@example/u);
    const missingRoot = mkdtempSync(join(tmpdir(), "mtc-source-route-missing-")), missing = writeSource(missingRoot), missingOutput = join(missingRoot, "output"); mkdirSync(missingOutput, { mode: 0o700 });
    writeFileSync(missing.policy, JSON.stringify({ version: 1, policies: [{ key_hash: "c".repeat(64), enabled: true, grants: [{ provider: "codex", model: "unresolved" }] }], usage: {} }), { mode: 0o600 });
    const unresolved = spawnSync(process.execPath, exportArguments(missing, missingOutput), { encoding: "utf8" }); assert.equal(unresolved.status, 2); assert.equal(existsSync(join(missingOutput, "source-inventory.json")), false); assert.equal(existsSync(join(missingOutput, "provider-candidate-material.json")), false);
  });

  it("records each Kimi OAuth source capability gap and every affected exact grant without manufacturing a direct pool", () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-kimi-source-capability-gap-")), source = writeSource(root), output = join(root, "output"); mkdirSync(output, { mode: 0o700 });
    writeFileSync(join(source.auth, "kimi-first.json"), JSON.stringify({ type: "kimi", opaque: "fixture-only-kimi-first" }), { mode: 0o600 });
    writeFileSync(join(source.auth, "kimi-second.json"), JSON.stringify({ type: "kimi", opaque: "fixture-only-kimi-second" }), { mode: 0o600 });
    const result = spawnSync(process.execPath, exportArguments(source, output), { encoding: "utf8" }); assert.equal(result.status, 0, result.stderr);
    const receipt = JSON.parse(result.stdout) as Record<string, unknown>, sourceInventory = JSON.parse(readFileSync(join(output, "source-inventory.json"), "utf8")) as Record<string, unknown>, material = JSON.parse(readFileSync(join(output, "provider-candidate-material.json"), "utf8")) as Record<string, unknown>;
    assert.equal(receipt.source_mapping_count, 6); assert.equal(receipt.provider_candidate_set_count, 6); assert.equal(receipt.source_account_candidate_count, 6);
    assert.equal(receipt.reauthorization_required_count, 3); assert.equal(receipt.source_capability_gap_auth_count, 2); assert.equal(receipt.source_capability_gap_grant_count, 1); assert.equal(receipt.anomaly_count, 2);
    assert.equal((sourceInventory.mappings as Array<Record<string, unknown>>).some((item) => item.provider === "kimi"), false);
    const remediation = sourceInventory.reauthorization_required as Array<Record<string, unknown>>;
    assert.deepEqual(remediation.map((item) => item.provider), ["copilot", "kimi", "kimi"]);
    assert.equal(new Set(remediation.map((item) => item.source_stable_id)).size, 3);
    assert.deepEqual((sourceInventory.anomalies as Array<Record<string, unknown>>).filter((item) => item.provider === "kimi"), [{ provider: "kimi", model: "kimi-k2", reason: "source capability gap: target lacks a managed OAuth adapter" }]);
    assert.equal((material.provider_candidate_sets as Array<Record<string, unknown>>).some((item) => (item.source as Record<string, unknown>).provider === "kimi"), false);
    const outputText = `${result.stdout}${result.stderr}${readFileSync(join(output, "source-inventory.json"), "utf8")}${readFileSync(join(output, "provider-candidate-material.json"), "utf8")}`;
    assert.doesNotMatch(outputText, /fixture-only-kimi|kimi-(?:first|second)\.json/u);
  });

  it("unifies only registry-proven managed Codex OAuth candidates in their exact classify groups", () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-managed-codex-route-")), source = join(root, "source"), auth = join(source, "auth"), output = join(root, "output");
    mkdirSync(auth, { recursive: true, mode: 0o700 }); mkdirSync(output, { mode: 0o700 }); chmodSync(source, 0o700); chmodSync(auth, 0o700);
    const dongwu = "lindongwu11@gmail.com.json", csil = "csil.ai.automation@gmail.com.json";
    const config = join(source, "config.yaml");
    writeFileSync(config, [
      'auth-dir: "/sealed/auth"',
      "force-model-prefix: false",
      "oauth-model-alias:",
      "  codex:",
      "    - name: gpt-5.6-terra-dongwu-upstream",
      "      alias: gpt-5.6-terra",
      "codex-api-key:",
      "  - api-key: fixture-only-direct-codex-key",
      '    base-url: "https://codex.example.test/v1"',
      "    models:",
      "      - name: gpt-5.6-direct-upstream",
      "        alias: gpt-5.6-direct",
      "plugins:",
      "  configs:",
      "    cpa-key-policy:",
      "      mode: native-access",
      "      classify_rules:",
      "        - name: codex-dongwu-credential",
      "          field: filename",
      "          pattern: 'lindongwu11@gmail\\.com'",
      "          group: dongwu",
      "          enabled: true",
      "        - name: codex-csil-credential",
      "          field: filename",
      "          pattern: 'csil\\.ai\\.automation@gmail\\.com'",
      "          group: csil",
      "          enabled: true",
      "",
    ].join("\n"), { mode: 0o600 });
    writeFileSync(join(auth, dongwu), JSON.stringify({ type: "codex", prefix: "codex-dongwu", refresh_token: "fixture-only" }), { mode: 0o600 });
    writeFileSync(join(auth, csil), JSON.stringify({ type: "codex", prefix: "codex-csil", refresh_token: "fixture-only", model_aliases: [{ name: "gpt-5.6-terra-csil-upstream", alias: "gpt-5.6-terra" }] }), { mode: 0o600 });
    const policy = join(root, "native-policy.json");
    writeFileSync(policy, JSON.stringify({ version: 1, policies: [{ key_hash: "c".repeat(64), enabled: true, grants: [
      { provider: "codex", model: "gpt-5.6-direct" },
      { provider: "codex", model: "gpt-5.6-terra", group: "classify:dongwu", upstream_prefix: "codex-dongwu" },
      { provider: "codex", model: "gpt-5.6-terra", group: "classify:csil", upstream_prefix: "codex-csil" },
    ] }], usage: {} }), { mode: 0o600 });
    const snapshot = join(root, "managed-models.json"), authFiles = [
      { id: csil, provider: "codex", disabled: false, status: "active" },
      { id: dongwu, provider: "codex", disabled: false, status: "active" },
    ];
    writeFileSync(snapshot, JSON.stringify({ version: 1, source_config_sha256: createHash("sha256").update(readFileSync(config)).digest("hex"), auth_files_sha256: createHash("sha256").update(`${JSON.stringify(authFiles)}\n`).digest("hex"), auth_models: [
      { auth_id: csil, provider: "codex", registered_models: ["codex-csil/gpt-5.6-terra", "gpt-5.6-terra-csil-upstream"] },
      { auth_id: dongwu, provider: "codex", registered_models: ["codex-dongwu/gpt-5.6-terra", "gpt-5.6-terra-dongwu-upstream"] },
    ] }), { mode: 0o600 });
    const key = join(root, "source-identity.key"), generated = spawnSync(process.execPath, [keyGenerator, key], { encoding: "utf8" }); assert.equal(generated.status, 0, generated.stderr);
    const sourceOutput = join(output, "source-inventory.json"), materialOutput = join(output, "provider-candidate-material.json");
    const result = spawnSync(process.execPath, [exporter, "--config", config, "--auth-dir", auth, "--policy-snapshot-file", policy, "--source-identity-key-file", key, "--managed-codex-model-snapshot-file", snapshot, "--source-inventory-output", sourceOutput, "--provider-candidate-material-output", materialOutput], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    const inventory = JSON.parse(readFileSync(sourceOutput, "utf8")) as { mappings: Array<Record<string, unknown>> }, material = JSON.parse(readFileSync(materialOutput, "utf8")) as { provider_candidate_sets: Array<Record<string, unknown>> };
    assert.deepEqual(inventory.mappings.map((item) => item.group).sort(), ["classify:csil", "classify:dongwu", null]);
    assert.equal(material.provider_candidate_sets.length, 3);
    assert.deepEqual(material.provider_candidate_sets.map((item) => ((item.candidates as Array<Record<string, unknown>>)[0]!.driver)).sort(), ["http-json", "openai-codex", "openai-codex"]);
    const outputText = `${result.stdout}${result.stderr}${readFileSync(sourceOutput, "utf8")}${readFileSync(materialOutput, "utf8")}`;
    assert.doesNotMatch(outputText, /lindongwu11@gmail\.com|csil\.ai\.automation@gmail\.com|fixture-only/u);
  });
});
