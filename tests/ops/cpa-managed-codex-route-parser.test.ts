import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";
import {
  assertManagedCodexModelSnapshotConfig,
  inspectManagedCodexRouteModels,
  managedCodexModelSnapshotDigest,
  managedCodexRouteSourceStableId,
  parseManagedCodexModelSnapshot,
  ManagedCodexRouteFailure,
  type ManagedCodexAuthInput,
  type ManagedCodexModelSnapshotEntry,
  type ManagedCodexSourceCoordinate,
} from "../../ops/legacy-routes/cpa-managed-codex-route-parser.ts";
import {
  ManagedCodexSnapshotFailure,
  buildManagedCodexModelSnapshot,
  type CapturedAuth,
  type CapturedModels,
} from "../../ops/legacy-routes/export-cpa-managed-codex-model-snapshot.ts";

const key = Buffer.alloc(32, 7);
const sha = (value: Buffer): string => createHash("sha256").update(value).digest("hex");
const config = Buffer.from([
  'auth-dir: "/sealed/auth"',
  "force-model-prefix: false",
  "oauth-model-alias:",
  "  codex:",
  "    - name: gpt-5.6-terra-dongwu-upstream",
  "      alias: gpt-5.6-terra",
  "oauth-excluded-models:",
  "  codex:",
  "    - blocked-*",
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
].join("\n"));

const dongwu = "lindongwu11@gmail.com.json";
const csil = "csil.ai.automation@gmail.com.json";
const auths: readonly ManagedCodexAuthInput[] = [
  { relative_path: dongwu, document: { type: "codex", prefix: "codex-dongwu", refresh_token: "fixture" } },
  { relative_path: csil, document: { type: "codex", prefix: "codex-csil", refresh_token: "fixture", model_aliases: [{ name: "gpt-5.6-terra-csil-upstream", alias: "gpt-5.6-terra" }] } },
];
const snapshot: readonly ManagedCodexModelSnapshotEntry[] = [
  { auth_id: dongwu, provider: "codex", registered_models: ["codex-dongwu/gpt-5.6-terra", "gpt-5.6-terra-dongwu-upstream"] },
  { auth_id: csil, provider: "codex", registered_models: ["codex-csil/gpt-5.6-terra", "gpt-5.6-terra-csil-upstream"] },
];
const csilCoordinate: ManagedCodexSourceCoordinate = { provider: "codex", model: "gpt-5.6-terra", group: "classify:csil", upstream_prefix: "codex-csil", protocol: "openai" };
const dongwuCoordinate: ManagedCodexSourceCoordinate = { provider: "codex", model: "gpt-5.6-terra", group: "classify:dongwu", upstream_prefix: "codex-dongwu", protocol: "openai" };

describe("managed CPA Codex OAuth route parser", () => {
  it("uses source classify filename rules, per-auth aliases, prefixes, and registry evidence without group leakage", () => {
    const routes = inspectManagedCodexRouteModels(config, auths, snapshot, [csilCoordinate, dongwuCoordinate], key);
    assert.equal(routes.length, 2);
    const csilRoute = routes.find((item) => item.source.group === "classify:csil");
    const dongwuRoute = routes.find((item) => item.source.group === "classify:dongwu");
    assert(csilRoute); assert(dongwuRoute);
    assert.equal(csilRoute.upstream_model, "gpt-5.6-terra-csil-upstream");
    assert.equal(dongwuRoute.upstream_model, "gpt-5.6-terra-dongwu-upstream");
    assert.deepEqual(csilRoute.candidates.map((item) => item.driver), ["openai-codex"]);
    assert.deepEqual(dongwuRoute.candidates.map((item) => item.driver), ["openai-codex"]);
    assert.equal(csilRoute.candidates.length, 1); assert.equal(dongwuRoute.candidates.length, 1);
    assert.notEqual(csilRoute.candidates[0]!.source_stable_id, dongwuRoute.candidates[0]!.source_stable_id);
    assert.equal(csilRoute.candidates[0]!.source_stable_id, managedCodexRouteSourceStableId(key, csil));
    assert.equal(JSON.stringify(routes).includes(csil), false);
    assert.equal(JSON.stringify(routes).includes(dongwu), false);
  });

  it("fails closed for missing custom-group, missing registry, and incompatible per-account alias mappings", () => {
    const unknown: ManagedCodexSourceCoordinate = { ...csilCoordinate, group: "classify:not-configured" };
    assert.throws(() => inspectManagedCodexRouteModels(config, auths, snapshot, [unknown], key), ManagedCodexRouteFailure);
    const missing = snapshot.filter((item) => item.auth_id !== csil);
    assert.throws(() => inspectManagedCodexRouteModels(config, auths, missing, [csilCoordinate], key), ManagedCodexRouteFailure);
    const secondCsil = {
      relative_path: "csil.ai.automation@gmail.com-secondary.json",
      document: { type: "codex", prefix: "codex-csil", refresh_token: "fixture", model_aliases: [{ name: "different-upstream", alias: "gpt-5.6-terra" }] },
    } as const;
    const conflictingSnapshot = [...snapshot, { auth_id: secondCsil.relative_path, provider: "codex" as const, registered_models: ["codex-csil/gpt-5.6-terra", "different-upstream"] }];
    assert.throws(() => inspectManagedCodexRouteModels(config, [...auths, secondCsil], conflictingSnapshot, [csilCoordinate], key), /incompatible per-account/u);
  });

  it("pins a sealed registry observation to the same copied source config", () => {
    const authFiles: readonly CapturedAuth[] = [
      { id: csil, provider: "codex" as const, disabled: false, status: "active" },
      { id: dongwu, provider: "codex" as const, disabled: false, status: "active" },
    ].sort((left, right) => left.id.localeCompare(right.id, "en"));
    const modelEntries: readonly CapturedModels[] = authFiles.map((item) => ({ auth_id: item.id, provider: "codex", registered_models: item.id === csil ? ["codex-csil/gpt-5.6-terra"] : ["codex-dongwu/gpt-5.6-terra"] }));
    const built = buildManagedCodexModelSnapshot(config, authFiles, modelEntries, authFiles, modelEntries);
    const parsed = parseManagedCodexModelSnapshot(built.snapshot);
    assert.equal(parsed.source_config_sha256, sha(config));
    assert.equal(parsed.auth_models.length, 2);
    assert.doesNotThrow(() => assertManagedCodexModelSnapshotConfig(parsed, config));
    assert.throws(() => assertManagedCodexModelSnapshotConfig(parsed, Buffer.from("different")), ManagedCodexRouteFailure);
    assert.equal(managedCodexModelSnapshotDigest(parsed.auth_models), managedCodexModelSnapshotDigest(parsed.auth_models));
    assert.throws(() => buildManagedCodexModelSnapshot(config, authFiles, modelEntries, [{ ...authFiles[0]!, status: "disabled" }, authFiles[1]!], modelEntries), ManagedCodexSnapshotFailure);
    assert.throws(() => buildManagedCodexModelSnapshot(config, authFiles, modelEntries, authFiles, [...modelEntries].reverse()), ManagedCodexSnapshotFailure);
  });
});
