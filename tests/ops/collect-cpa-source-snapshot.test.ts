#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";

const repository = resolve(import.meta.dirname, "../..");
const collector = join(repository, "ops/legacy-routes/collect-cpa-source-snapshot.ts");
const fakeKubectl = join(repository, "tests/ops/helpers/fake-kubectl-cpa-source-snapshot.ts");
const podUid = "10000000-0000-4000-8000-000000000001";

function secureTree(path: string): void {
  const metadata = lstatSync(path);
  assert.equal(metadata.isSymbolicLink(), false);
  assert.equal(statSync(path).mode & 0o777, metadata.isDirectory() ? 0o700 : 0o600);
  if (metadata.isDirectory()) for (const name of readdirSync(path)) secureTree(join(path, name));
}
function argumentsFor(root: string, output: string): string[] {
  return [collector,
    "--kubectl-binary", process.execPath,
    "--kubectl-argument", "--experimental-strip-types",
    "--kubectl-argument", fakeKubectl,
    "--context", "fixture-context",
    "--namespace", "fixture-cpa",
    "--pod", "cliproxyapi-0",
    "--pod-uid", podUid,
    "--container", "cliproxyapi",
    "--expected-app-name", "cliproxyapi",
    "--expected-pvc", "cliproxyapi-auth",
    "--source-state-root", "/root/.cli-proxy-api",
    "--config-mount-path", "/CLIProxyAPI/config.yaml",
    "--management-port", "8317",
    "--management-token-file", join(root, "management.token"),
    "--output-directory", output,
    "--timeout-ms", "10000",
  ];
}
function run(root: string, output: string, mode: "stable" | "route-change" | "config-drift" | "traversal" | "symlink" | "uid-drift" | "pvc-drift" = "stable") {
  return spawnSync(process.execPath, ["--experimental-strip-types", ...argumentsFor(root, output)], {
    cwd: repository,
    encoding: "utf8",
    timeout: 30_000,
    env: {
      ...process.env,
      FAKE_CPA_COUNTER_PATH: join(root, "capture-counter"),
      FAKE_CPA_CONFIG_COUNTER_PATH: join(root, "config-counter"),
      FAKE_CPA_CONFIG_DRIFT: mode === "config-drift" ? "1" : "0",
      FAKE_CPA_UNSTABLE_ROUTE: mode === "route-change" ? "1" : "0",
      FAKE_CPA_UNSAFE_ARCHIVE: mode === "traversal" || mode === "symlink" ? mode : "",
      FAKE_CPA_POD_DRIFT: mode === "uid-drift" ? "uid" : mode === "pvc-drift" ? "pvc" : "",
    },
  });
}

describe("local CPA source snapshot collector", () => {
  it("uses one fixed Pod, excludes logs when present, permits only an OAuth payload revision, and seals protected inputs", () => {
    const root = mkdtempSync(join(repository, ".test-cpa-source-capture-"));
    try {
      chmodSync(root, 0o700);
      writeFileSync(join(root, "management.token"), "fixture-management-token\n", { mode: 0o600 }); chmodSync(join(root, "management.token"), 0o600);
      const output = join(root, "capture"), result = run(root, output);
      assert.equal(result.status, 0, result.stderr);
      assert.deepEqual(JSON.parse(result.stdout), {
        mode: "collect-cpa-source-snapshot",
        source_route_evidence_sha256: (JSON.parse(readFileSync(join(output, "source-capture-receipt.json"), "utf8")) as Record<string, unknown>).source_route_evidence_sha256,
        source_capture_sha256: (JSON.parse(readFileSync(join(output, "source-capture-receipt.json"), "utf8")) as Record<string, unknown>).source_capture_sha256,
        auth_file_count: 1,
        managed_codex_auth_file_count: 1,
      });
      assert.deepEqual(readdirSync(output).sort(), ["auth", "config.yaml", "managed-codex-model-snapshot.json", "native-key-policy.json", "source-capture-receipt.json"]);
      secureTree(output);
      const receipt = JSON.parse(readFileSync(join(output, "source-capture-receipt.json"), "utf8")) as Record<string, unknown>;
      for (const key of ["source_config_sha256", "source_policy_sha256", "auth_route_projection_sha256", "auth_payload_revision_sha256", "source_route_evidence_sha256", "source_capture_sha256", "managed_codex_model_snapshot_sha256"]) assert.match(String(receipt[key]), /^[0-9a-f]{64}$/u);
      assert.equal(receipt.auth_file_count, 1); assert.equal(receipt.managed_codex_auth_file_count, 1);
      assert.doesNotMatch(`${result.stdout}${result.stderr}`, /fixture-refresh|csil\.json|auth-dir|fixture-management-token/u);
      const repeat = run(root, output); assert.equal(repeat.status, 2); assert.doesNotMatch(repeat.stderr, /fixture-refresh|csil\.json|fixture-management-token/u);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it("rejects a route-policy projection that changes inside the capture window without publishing an output", () => {
    const root = mkdtempSync(join(repository, ".test-cpa-source-capture-"));
    try {
      chmodSync(root, 0o700);
      writeFileSync(join(root, "management.token"), "fixture-management-token\n", { mode: 0o600 }); chmodSync(join(root, "management.token"), 0o600);
      const output = join(root, "capture"), result = run(root, output, "route-change");
      assert.equal(result.status, 2); assert.equal(existsSync(output), false);
      assert.doesNotMatch(`${result.stdout}${result.stderr}`, /fixture-refresh|csil\.json|fixture-management-token|codex-other/u);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it("rejects unsafe tar entry kinds and fixed-Pod identity/PVC drift before any receipt is published", () => {
    for (const mode of ["config-drift", "traversal", "symlink", "uid-drift", "pvc-drift"] as const) {
      const root = mkdtempSync(join(repository, ".test-cpa-source-capture-"));
      try {
        chmodSync(root, 0o700);
        writeFileSync(join(root, "management.token"), "fixture-management-token\n", { mode: 0o600 }); chmodSync(join(root, "management.token"), 0o600);
        const output = join(root, "capture"), result = run(root, output, mode);
        assert.equal(result.status, 2, mode); assert.equal(existsSync(output), false, mode);
        assert.doesNotMatch(`${result.stdout}${result.stderr}`, /fixture-refresh|csil\.json|fixture-management-token|escape\.json|unexpected-pvc/u, mode);
      } finally { rmSync(root, { recursive: true, force: true }); }
    }
  });
});
