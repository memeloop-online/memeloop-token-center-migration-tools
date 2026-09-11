#!/usr/bin/env node

import assert from "node:assert/strict";
import { chmodSync, existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";
import { CpaSourceCollectionFailure, run as collect } from "../../ops/legacy-routes/collect-cpa-source-snapshot.ts";

const repository = resolve(import.meta.dirname, "../..");
const fakeKubectl = join(repository, "tests/ops/helpers/fake-kubectl-cpa-source-snapshot.ts");
const podUid = "10000000-0000-4000-8000-000000000001";

function secureTree(path: string): void {
  const metadata = lstatSync(path);
  assert.equal(metadata.isSymbolicLink(), false);
  assert.equal(statSync(path).mode & 0o777, metadata.isDirectory() ? 0o700 : 0o600);
  if (metadata.isDirectory()) for (const name of readdirSync(path)) secureTree(join(path, name));
}
function argumentsFor(root: string, output: string): string[] {
  return ["--kubectl-binary", process.execPath,
    "--kubectl-argument", "--experimental-strip-types",
    "--kubectl-argument", fakeKubectl,
    "--context", "fixture-context",
    "--namespace", "fixture-cpa",
    "--pod", "source-adapter-0",
    "--pod-uid", podUid,
    "--container", "source-adapter",
    "--expected-app-name", "source-adapter",
    "--expected-pvc", "source-state",
    "--source-state-root", "/fixture/source-state",
    "--config-mount-path", "/fixture/config/config.yaml",
    "--management-port", "18443",
    "--management-token-file", join(root, "management.token"),
    "--output-directory", output,
    "--timeout-ms", "10000",
  ];
}
async function run(root: string, output: string, mode: "stable" | "backup" | "non-json" | "route-change" | "config-drift" | "traversal" | "symlink" | "uid-drift" | "pvc-drift" = "stable") {
  const environment: Record<string, string> = {
    FAKE_CPA_COUNTER_PATH: join(root, "capture-counter"),
    FAKE_CPA_CONFIG_COUNTER_PATH: join(root, "config-counter"),
    FAKE_CPA_CONFIG_DRIFT: mode === "config-drift" ? "1" : "0",
    FAKE_CPA_UNSTABLE_ROUTE: mode === "route-change" ? "1" : "0",
    FAKE_CPA_UNSAFE_ARCHIVE: mode === "traversal" || mode === "symlink" ? mode : "",
    FAKE_CPA_POD_DRIFT: mode === "uid-drift" ? "uid" : mode === "pvc-drift" ? "pvc" : "",
    FAKE_CPA_AUTH_ENTRY: mode === "backup" || mode === "non-json" ? mode : "",
  };
  const original = new Map(Object.keys(environment).map((key) => [key, process.env[key]]));
  try {
    Object.assign(process.env, environment);
    return await collect(argumentsFor(root, output));
  } finally {
    for (const [key, value] of original) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}
async function expectFailure(root: string, output: string, mode: Parameters<typeof run>[2], expected: string): Promise<void> {
  await assert.rejects(
    () => run(root, output, mode),
    (error: unknown): boolean => {
      assert(error instanceof CpaSourceCollectionFailure);
      assert.equal(error.message, expected);
      return true;
    },
  );
}

describe("local CPA source snapshot collector", () => {
  it("uses one fixed Pod, excludes logs when present, permits only an OAuth payload revision, and seals protected inputs", async () => {
    const root = mkdtempSync(join(repository, ".test-cpa-source-capture-"));
    try {
      chmodSync(root, 0o700);
      writeFileSync(join(root, "management.token"), "fixture-management-token", { mode: 0o600 }); chmodSync(join(root, "management.token"), 0o600);
      const output = join(root, "capture"), result = await run(root, output);
      assert.deepEqual(result, {
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
      await expectFailure(root, output, "stable", "output directory already exists");
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it("excludes only the documented inactive CPA auth backup suffixes", async () => {
    const root = mkdtempSync(join(repository, ".test-cpa-source-capture-"));
    try {
      chmodSync(root, 0o700);
      writeFileSync(join(root, "management.token"), "fixture-management-token", { mode: 0o600 }); chmodSync(join(root, "management.token"), 0o600);
      const backupOutput = join(root, "backup-capture"), result = await run(root, backupOutput, "backup");
      assert.equal(result.auth_file_count, 1);
      assert.deepEqual(readdirSync(join(backupOutput, "auth")), ["fixture-account.json"]);
      await expectFailure(root, join(root, "non-json-capture"), "non-json", "source archive contains a non-JSON auth entry");
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it("rejects a route-policy projection that changes inside the capture window without publishing an output", async () => {
    const root = mkdtempSync(join(repository, ".test-cpa-source-capture-"));
    try {
      chmodSync(root, 0o700);
      writeFileSync(join(root, "management.token"), "fixture-management-token", { mode: 0o600 }); chmodSync(join(root, "management.token"), 0o600);
      const output = join(root, "capture");
      await expectFailure(root, output, "route-change", "CPA source route evidence changed during capture");
      assert.equal(existsSync(output), false);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it("rejects unsafe tar entry kinds and fixed-Pod identity/PVC drift before any receipt is published", async () => {
    const expected = {
      "config-drift": "CPA source config changed while deriving the capture layout",
      traversal: "source archive has an unsafe path",
      symlink: "source archive has an unsupported entry",
      "uid-drift": "selected CPA Pod identity changed",
      "pvc-drift": "CPA source PVC is not approved",
    } as const;
    for (const mode of Object.keys(expected) as Array<keyof typeof expected>) {
      const root = mkdtempSync(join(repository, ".test-cpa-source-capture-"));
      try {
        chmodSync(root, 0o700);
        writeFileSync(join(root, "management.token"), "fixture-management-token", { mode: 0o600 }); chmodSync(join(root, "management.token"), 0o600);
        const output = join(root, "capture");
        await expectFailure(root, output, mode, expected[mode]);
        assert.equal(existsSync(output), false, mode);
      } finally { rmSync(root, { recursive: true, force: true }); }
    }
  });
});
