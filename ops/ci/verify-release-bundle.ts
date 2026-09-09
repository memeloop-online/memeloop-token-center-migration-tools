/** Exercise the standalone bundle outside this checkout and its node_modules. */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { releaseEntrypointNames } from "./release-entrypoints.ts";
import { verifiedArchiveRuntime } from "../lib/session-archive-runtime.ts";

const repository = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const bundleArgument = process.argv[2] ?? resolve(repository, "dist/release");
let bundle = resolve(bundleArgument);

function privateTree(path: string): void {
  const stat = lstatSync(path);
  chmodSync(path, stat.isDirectory() ? 0o700 : 0o600);
  if (stat.isDirectory()) for (const name of readdirSync(path)) privateTree(join(path, name));
}

function execute(path: string, args: readonly string[], environment: NodeJS.ProcessEnv = {}): string {
  const result = spawnSync(process.execPath, [path, ...args], {
    cwd: bundle,
    encoding: "utf8",
    env: { ...process.env, ...environment },
    timeout: 30_000,
  });
  assert.equal(result.status, 0, `release command failed: ${path}`);
  return String(result.stdout);
}

function writePrivate(path: string, value: string): void {
  writeFileSync(path, value, { encoding: "utf8", mode: 0o600 });
  chmodSync(path, 0o600);
}

const sha256 = (value: Buffer): string => createHash("sha256").update(value).digest("hex");

function command(name: string): string {
  return join(bundle, "commands", `${name}.mjs`);
}

const manifestPath = join(bundle, "release-manifest.json");
assert.equal(existsSync(manifestPath), true, "release manifest is missing");
const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as { node_version?: unknown; commands?: unknown };
assert.equal(manifest.node_version, "24.18.0");
assert.deepEqual(
  (manifest.commands as Array<{ name?: unknown }>).map((item) => item.name),
  releaseEntrypointNames,
);
for (const name of releaseEntrypointNames) assert.equal(existsSync(command(name)), true, `release command is missing: ${name}`);

const root = mkdtempSync(join(tmpdir(), "mtc-release-bundle-"));
try {
  const isolated = join(root, "release");
  cpSync(bundle, isolated, { recursive: true });
  assert.equal(existsSync(join(isolated, "node_modules")), false, "release must not contain runtime dependencies");
  const originalBundle = bundle;
  // Commands resolve from a copied directory under /tmp, so Node cannot fall
  // back to this checkout's node_modules for the bundled YAML dependency.
  bundle = isolated;
  // Execute only the validated native binary from the isolated release tree.
  const archiveBinary = join(bundle, "commands/runtime/import-cpa-session-archive");
  verifiedArchiveRuntime(archiveBinary);
  const archiveHelp = spawnSync(archiveBinary, ["--help"], { encoding: "utf8", timeout: 10_000 });
  assert.equal(archiveHelp.status, 0, "isolated archive runtime must execute without product checkout");
  assert.match(archiveHelp.stdout, /--max-plan-bytes/u);

  execute(command("export-cpa-managed-codex-model-snapshot"), ["--help"]);
  execute(command("resolve-cpa-managed-codex-provenance"), ["--help"]);
  execute(command("reconcile-existing-transport"), ["--help"]);
  execute(command("credential-recovery-preflight"), ["--help"]);
  execute(command("source-credential-recovery-apply"), ["--help"]);

  const captureRoot = join(root, "source-capture");
  mkdirSync(captureRoot, { mode: 0o700 }); chmodSync(captureRoot, 0o700);
  const captureToken = join(captureRoot, "management.token");
  writePrivate(captureToken, "fixture-management-token");
  const capture = JSON.parse(execute(command("collect-cpa-source-snapshot"), [
    "--kubectl-binary", process.execPath,
    "--kubectl-argument", "--experimental-strip-types",
    "--kubectl-argument", join(repository, "tests/ops/helpers/fake-kubectl-cpa-source-snapshot.ts"),
    "--context", "fixture-context",
    "--namespace", "fixture-cpa",
    "--pod", "cliproxyapi-0",
    "--pod-uid", "10000000-0000-4000-8000-000000000001",
    "--container", "cliproxyapi",
    "--expected-app-name", "cliproxyapi",
    "--expected-pvc", "cliproxyapi-auth",
    "--source-state-root", "/root/.cli-proxy-api",
    "--config-mount-path", "/CLIProxyAPI/config.yaml",
    "--management-port", "8317",
    "--management-token-file", captureToken,
    "--output-directory", join(captureRoot, "capture"),
  ], { FAKE_CPA_COUNTER_PATH: join(captureRoot, "counter") })) as Record<string, unknown>;
  assert.equal(capture.mode, "collect-cpa-source-snapshot");
  assert.equal(capture.auth_file_count, 1);
  assert.equal(existsSync(join(captureRoot, "capture", "source-capture-receipt.json")), true);

  const source = join(root, "source");
  cpSync(join(repository, "tests/fixtures/cpa-upstreams/supported"), source, { recursive: true });
  privateTree(source);
  const identity = join(source, "source-identity.key");
  execute(command("generate-source-identity-key"), [identity]);
  const policy = join(root, "transport-policy.json");
  writePrivate(policy, `${JSON.stringify({ contract_version: 1, private_target_base_urls: ["https://openai-compatible.example.test/v1"], result_origins_by_base_url: {} })}\n`);
  const yamlSummary = JSON.parse(execute(command("import-cpa-upstreams"), [
    "--config", join(source, "config.yaml"),
    "--auth-dir", join(source, "auth"),
    "--source-identity-key-file", identity,
    "--transport-policy-file", policy,
  ])) as Record<string, unknown>;
  assert.equal(yamlSummary.mode, "dry-run");
  assert.equal(yamlSummary.api_account_count, 6);

  // Exercise a bundled command that imports two other release CLIs, then
  // compose its exact output. This catches an imported command accidentally
  // treating the outer bundle's import.meta.url as an instruction to run.
  const routePolicy = join(root, "native-route-policy.json");
  writePrivate(routePolicy, `${JSON.stringify({
    version: 1,
    policies: [{
      key_hash: "a".repeat(64),
      enabled: true,
      grants: [{ provider: "fixture-openai-compatible", model: "fixture-model" }],
    }],
    usage: {},
  })}\n`);
  const routeArtifacts = join(root, "route-artifacts");
  mkdirSync(routeArtifacts, { mode: 0o700 }); chmodSync(routeArtifacts, 0o700);
  const sourceInventory = join(routeArtifacts, "source-inventory.json");
  const candidateMaterial = join(routeArtifacts, "provider-candidate-material.json");
  const exporter = JSON.parse(execute(command("export-cpa-source-route-inventory"), [
    "--config", join(source, "config.yaml"),
    "--auth-dir", join(source, "auth"),
    "--policy-snapshot-file", routePolicy,
    "--source-identity-key-file", identity,
    "--source-inventory-output", sourceInventory,
    "--provider-candidate-material-output", candidateMaterial,
  ])) as Record<string, unknown>;
  assert.equal(exporter.source_mapping_count, 1);
  assert.equal(exporter.provider_candidate_set_count, 1);
  const sourceRaw = readFileSync(sourceInventory), materialRaw = readFileSync(candidateMaterial);
  const material = JSON.parse(materialRaw.toString("utf8")) as { provider_candidate_sets?: unknown };
  assert.equal(Array.isArray(material.provider_candidate_sets), true);
  const sets = material.provider_candidate_sets as Array<{ candidates?: unknown }>;
  assert.equal(sets.length, 1);
  assert.equal(Array.isArray(sets[0]?.candidates), true);
  const candidates = sets[0]!.candidates as Array<Record<string, unknown>>;
  assert.equal(candidates.length, 2);
  assert.deepEqual(candidates.map((candidate) => candidate.driver), ["http-json", "http-json"]);
  const receiptDirectory = join(root, "route-receipts");
  mkdirSync(receiptDirectory, { mode: 0o700 }); chmodSync(receiptDirectory, 0o700);
  const sourceDigest = sha256(sourceRaw), materialDigest = sha256(materialRaw);
  const directReceipt = join(receiptDirectory, "direct-receipt.json");
  writePrivate(directReceipt, `${JSON.stringify({
    version: 1,
    tenant_external_id: "fixture-tenant",
    source_inventory_sha256: sourceDigest,
    provider_candidate_material_sha256: materialDigest,
    bindings: candidates.map((candidate, index) => ({
      source_stable_id: candidate.source_stable_id,
      source_provider: candidate.source_provider,
      upstream_account_id: `10000000-0000-4000-8000-00000000000${index + 1}`,
      driver: "http-json",
      status: "active",
      updated_at: index + 1,
    })),
    quarantined: [],
  })}\n`);
  const managedReceipt = join(receiptDirectory, "managed-receipt.json");
  writePrivate(managedReceipt, `${JSON.stringify({
    version: 1,
    tenant_external_id: "fixture-tenant",
    source_inventory_sha256: sourceDigest,
    provider_candidate_material_sha256: materialDigest,
    managed_provenance_evidence_sha256: "b".repeat(64),
    bindings: [],
    quarantined: [],
  })}\n`);
  const composedInventory = join(routeArtifacts, "upstream-inventory.json");
  const composer = JSON.parse(execute(command("compose-cpa-upstream-inventory"), [
    "--source-inventory-file", sourceInventory,
    "--provider-candidate-material-file", candidateMaterial,
    "--direct-binding-receipt-file", directReceipt,
    "--managed-binding-receipt-file", managedReceipt,
    "--upstream-inventory-output", composedInventory,
  ])) as Record<string, unknown>;
  assert.equal(composer.mode, "compose-cpa-upstream-inventory");
  assert.equal(composer.upstream_count, 2);
  assert.equal(composer.provider_candidate_set_count, 1);
  assert.equal(existsSync(composedInventory), true);

  // Exercise both directions of the composer/importer bundle dependency.
  // Their import.meta.url is shared after bundling, so only the command-name
  // guard may select the CLI. No network or application writes are required.
  const directInventory = join(routeArtifacts, "direct-preflight-upstreams.json");
  const directBatch = join(receiptDirectory, "direct-preflight-batch.json");
  const directSummary = JSON.parse(execute(command("compose-cpa-upstream-inventory"), [
    "--direct-batch-preflight",
    "--source-inventory-file", sourceInventory,
    "--provider-candidate-material-file", candidateMaterial,
    "--direct-binding-receipt-file", directReceipt,
    "--upstream-inventory-output", directInventory,
    "--batch-receipt-output", directBatch,
  ])) as Record<string, unknown>;
  assert.equal(directSummary.mode, "direct-route-batch-preflight-only");
  assert.equal(directSummary.provider_candidate_set_count, 1);
  assert.equal(directSummary.deferred_mapping_count, 0);
  const directInventoryRaw = readFileSync(directInventory);
  const directDocument = JSON.parse(directInventoryRaw.toString("utf8"));
  const selectedPool = directDocument.provider_candidate_sets[0];
  const reviewedDirect = join(receiptDirectory, "reviewed-direct-manifest.json");
  writePrivate(reviewedDirect, `${JSON.stringify({
    version: 2, tenant_external_id: "fixture-tenant",
    target_api_base_url: "https://fixture-reviewed-control.invalid/",
    source_inventory_sha256: sourceDigest,
    upstream_inventory_sha256: sha256(directInventoryRaw),
    anomaly_quarantine: null,
    routes: [{
      source: selectedPool.source,
      target: {
        upstream_candidates: selectedPool.candidates,
        public_model: selectedPool.source.model,
        upstream_model: selectedPool.upstream_model,
        protocol: selectedPool.protocol, priority: 0,
      },
      expected_existing: {
        action: "create", route_id: null, updated_at: null, grant_revision: null,
        history_and_references_reviewed: false, history_and_references_evidence_sha256: null,
      },
    }],
  })}\n`);
  const readToken = join(receiptDirectory, "fixture-control-read-token");
  writePrivate(readToken, "fixture-only-control-read-token");
  const directArguments = [
    "--direct-batch-preflight", "--batch-receipt-file", directBatch,
    "--source-inventory-file", sourceInventory,
    "--upstream-inventory-file", directInventory,
    "--reviewed-manifest-file", reviewedDirect,
    // Deliberately fail the existing exact-URL fence after local recomposition,
    // but before constructing a request. A nested CLI or missing bundle import
    // would produce a different error (or invalid/non-single JSON).
    "--target-api-base-url", "https://fixture-different-control.invalid/",
    "--service-token-file", readToken,
  ];
  const directPreflight = spawnSync(process.execPath, [command("import-cpa-model-routes"), ...directArguments], { cwd: bundle, encoding: "utf8", timeout: 30_000 });
  assert.equal(directPreflight.status, 1);
  assert.equal(directPreflight.stdout, "");
  assert.equal(JSON.parse(directPreflight.stderr).error, "target API URL differs from the owner-reviewed manifest");
  const directApply = spawnSync(process.execPath, [command("import-cpa-model-routes"), ...directArguments, "--apply"], { cwd: bundle, encoding: "utf8", timeout: 30_000 });
  assert.equal(directApply.status, 1);
  assert.equal(directApply.stdout, "");
  assert.match(JSON.parse(directApply.stderr).error, /apply is forbidden/u);

  const psqlDirectory = join(root, "bin");
  // The audit runs an actual child process with its SQL on stdin; the stub is
  // intentionally outside the bundle and returns only synthetic counts.
  mkdirSync(psqlDirectory, { mode: 0o700 });
  const psql = join(psqlDirectory, "psql");
  writeFileSync(psql, "#!/usr/bin/env node\nprocess.stdin.resume(); process.stdin.on('end', () => process.stdout.write('1|1|1|1|1|1|0|1|0|0|0|0|1|0|1|1|1\\n'));\n", { mode: 0o700 });
  chmodSync(psql, 0o700);
  const audit = JSON.parse(execute(command("audit-cpa-migration"), [], {
    PATH: `${psqlDirectory}:${process.env.PATH ?? ""}`,
    PGHOST: "fixture-postgres",
    PGUSER: "fixture-user",
    PGDATABASE: "fixture-database",
    PGPASSFILE: "",
    PGPASSWORD: "fixture-only-password",
    IMPORT_TENANT_EXTERNAL_ID: "fixture-tenant",
    CPAMP_IMPORT_SOURCE: "fixture-cpamp",
    SESSION_ARCHIVE_IMPORT_SOURCE: "fixture-archive",
    EXPECTED_CPAMP_EVENTS: "1",
    EXPECTED_ARCHIVE_RECORDS: "1",
  })) as Record<string, unknown>;
  assert.equal(audit.cpamp_checkpoint, 1);
  assert.equal(audit.archive_checkpoint, 1);
  bundle = originalBundle;
} finally {
  rmSync(root, { recursive: true, force: true });
}
