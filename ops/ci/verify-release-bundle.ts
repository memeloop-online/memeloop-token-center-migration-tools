/** Exercise the standalone bundle outside this checkout and its node_modules. */

import assert from "node:assert/strict";
import { chmodSync, cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { releaseEntrypointNames } from "./release-entrypoints.ts";

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

  execute(command("export-cpa-managed-codex-model-snapshot"), ["--help"]);
  execute(command("resolve-cpa-managed-codex-provenance"), ["--help"]);

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
