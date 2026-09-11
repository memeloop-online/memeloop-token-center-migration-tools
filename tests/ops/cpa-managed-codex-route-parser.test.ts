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
  "    - name: gpt-5.6-terra-beta-upstream",
  "      alias: gpt-5.6-terra",
  "oauth-excluded-models:",
  "  codex:",
  "    - blocked-*",
  "plugins:",
  "  configs:",
  "    cpa-key-policy:",
  "      mode: native-access",
  "      classify_rules:",
  "        - name: codex-beta-credential",
  "          field: filename",
  "          pattern: 'beta-account@example\\.test'",
  "          group: beta",
  "          enabled: true",
  "        - name: codex-alpha-credential",
  "          field: filename",
  "          pattern: 'alpha-account@example\\.test'",
  "          group: alpha",
  "          enabled: true",
  "",
].join("\n"));

const beta = "beta-account@example.test.json";
const alpha = "alpha-account@example.test.json";
const auths: readonly ManagedCodexAuthInput[] = [
  { relative_path: beta, document: { type: "codex", prefix: "codex-beta", refresh_token: "fixture" } },
  { relative_path: alpha, document: { type: "codex", prefix: "codex-alpha", refresh_token: "fixture", model_aliases: [{ name: "gpt-5.6-terra-alpha-upstream", alias: "gpt-5.6-terra" }] } },
];
const snapshot: readonly ManagedCodexModelSnapshotEntry[] = [
  { auth_id: beta, provider: "codex", registered_models: ["codex-beta/gpt-5.6-terra", "gpt-5.6-terra-beta-upstream"] },
  { auth_id: alpha, provider: "codex", registered_models: ["codex-alpha/gpt-5.6-terra", "gpt-5.6-terra-alpha-upstream"] },
];
const alphaCoordinate: ManagedCodexSourceCoordinate = { provider: "codex", model: "gpt-5.6-terra", group: "classify:alpha", upstream_prefix: "codex-alpha", protocol: "openai" };
const betaCoordinate: ManagedCodexSourceCoordinate = { provider: "codex", model: "gpt-5.6-terra", group: "classify:beta", upstream_prefix: "codex-beta", protocol: "openai" };

describe("managed CPA Codex OAuth route parser", () => {
  it("uses source classify filename rules, per-auth aliases, prefixes, and registry evidence without group leakage", () => {
    const routes = inspectManagedCodexRouteModels(config, auths, snapshot, [alphaCoordinate, betaCoordinate], key);
    assert.equal(routes.length, 2);
    const alphaRoute = routes.find((item) => item.source.group === "classify:alpha");
    const betaRoute = routes.find((item) => item.source.group === "classify:beta");
    assert(alphaRoute); assert(betaRoute);
    assert.equal(alphaRoute.upstream_model, "gpt-5.6-terra-alpha-upstream");
    assert.equal(betaRoute.upstream_model, "gpt-5.6-terra-beta-upstream");
    assert.deepEqual(alphaRoute.candidates.map((item) => item.driver), ["openai-codex"]);
    assert.deepEqual(betaRoute.candidates.map((item) => item.driver), ["openai-codex"]);
    assert.equal(alphaRoute.candidates.length, 1); assert.equal(betaRoute.candidates.length, 1);
    assert.notEqual(alphaRoute.candidates[0]!.source_stable_id, betaRoute.candidates[0]!.source_stable_id);
    assert.equal(alphaRoute.candidates[0]!.source_stable_id, managedCodexRouteSourceStableId(key, alpha));
    assert.equal(JSON.stringify(routes).includes(alpha), false);
    assert.equal(JSON.stringify(routes).includes(beta), false);
  });

  it("fails closed for missing custom-group, missing registry, and incompatible per-account alias mappings", () => {
    const unknown: ManagedCodexSourceCoordinate = { ...alphaCoordinate, group: "classify:not-configured" };
    assert.throws(() => inspectManagedCodexRouteModels(config, auths, snapshot, [unknown], key), ManagedCodexRouteFailure);
    const missing = snapshot.filter((item) => item.auth_id !== alpha);
    assert.throws(() => inspectManagedCodexRouteModels(config, auths, missing, [alphaCoordinate], key), ManagedCodexRouteFailure);
    const secondAlpha = {
      relative_path: "alpha-account@example.test-secondary.json",
      document: { type: "codex", prefix: "codex-alpha", refresh_token: "fixture", model_aliases: [{ name: "different-upstream", alias: "gpt-5.6-terra" }] },
    } as const;
    const conflictingSnapshot = [...snapshot, { auth_id: secondAlpha.relative_path, provider: "codex" as const, registered_models: ["codex-alpha/gpt-5.6-terra", "different-upstream"] }];
    assert.throws(() => inspectManagedCodexRouteModels(config, [...auths, secondAlpha], conflictingSnapshot, [alphaCoordinate], key), /incompatible per-account/u);
  });

  it("pins a sealed registry observation to the same copied source config", () => {
    const authFiles: readonly CapturedAuth[] = [
      { id: alpha, provider: "codex" as const, disabled: false, status: "active" },
      { id: beta, provider: "codex" as const, disabled: false, status: "active" },
    ].sort((left, right) => left.id.localeCompare(right.id, "en"));
    const modelEntries: readonly CapturedModels[] = authFiles.map((item) => ({ auth_id: item.id, provider: "codex", registered_models: item.id === alpha ? ["codex-alpha/gpt-5.6-terra"] : ["codex-beta/gpt-5.6-terra"] }));
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
