import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { dispatch, targetForEntrypoint } from "../../ops/ci/run-typescript-entrypoint.ts";

const repository = fileURLToPath(new URL("../..", import.meta.url));
const stageScript = join(repository, "ops/ci/stage-protected-inputs.ts");
const targetUid = process.getuid?.() ?? 0;
const targetGid = process.getgid?.() ?? 0;

function privateDirectory(path: string): void {
  mkdirSync(path, { mode: 0o700 });
  chmodSync(path, 0o700);
}

function privateFile(path: string, contents: string | Buffer, mode = 0o600): void {
  writeFileSync(path, contents, { mode });
  chmodSync(path, mode);
}

function workspace(): string {
  return mkdtempSync(join(tmpdir(), "mtc-stage-protected-inputs-"));
}

function runStage(arguments_: readonly string[]) {
  return spawnSync(process.execPath, ["--experimental-strip-types", stageScript, "--target-uid", String(targetUid), "--target-gid", String(targetGid), ...arguments_], {
    cwd: repository,
    encoding: "utf8",
  });
}

function receipt(result: ReturnType<typeof runStage>): Record<string, unknown> {
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout.trim()) as Record<string, unknown>;
}

function rejected(arguments_: readonly string[], pattern?: RegExp): void {
  const result = runStage(arguments_);
  assert.notEqual(result.status, 0, `unexpected success: ${result.stdout}`);
  if (pattern !== undefined) assert.match(result.stderr, pattern);
}

function assertPrivateFile(path: string): void {
  const stat = lstatSync(path);
  assert.equal(stat.isFile(), true);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.nlink, 1);
  assert.equal(stat.mode & 0o777, 0o600);
  assert.equal(stat.uid, targetUid);
  assert.equal(stat.gid, targetGid);
}

function assertPrivateDirectory(path: string): void {
  const stat = lstatSync(path);
  assert.equal(stat.isDirectory(), true);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.mode & 0o777, 0o700);
  assert.equal(stat.uid, targetUid);
  assert.equal(stat.gid, targetGid);
}

test("copies the full source staging shape with nested auth and an exact exclusion", () => {
  const root = workspace();
  try {
    const source = join(root, "source");
    const runtime = join(root, "runtime");
    const inputs = join(root, "inputs");
    const auth = join(source, "auth");
    const nested = join(auth, "nested");
    const logs = join(auth, "logs");
    privateDirectory(source);
    privateDirectory(runtime);
    privateDirectory(inputs);
    privateDirectory(auth);
    privateDirectory(nested);
    privateDirectory(logs);
    const config = join(source, "config.yaml");
    const nativePolicy = join(auth, "cpa-key-access-policy-state.json");
    const sourceIdentity = join(inputs, "source-identity.key");
    privateFile(config, "mode: fixture\n");
    privateFile(join(auth, "account.json"), "{\"provider\":\"fixture\"}\n");
    privateFile(join(nested, "account.json"), "{\"nested\":true}\n");
    privateFile(join(logs, "debug.log"), "reviewed non-credential output\n");
    privateFile(nativePolicy, "{\"version\":1,\"policies\":[],\"usage\":{}}\n");
    privateFile(sourceIdentity, "fixture-identity\n");

    const result = receipt(runStage([
      "--copy", config, join(runtime, "config.yaml"),
      "--copy-auth-dir", auth, join(runtime, "auth"),
      "--exclude-auth-subdir", "logs",
      "--copy", nativePolicy, join(runtime, "native-key-policy.json"),
      "--copy", sourceIdentity, join(runtime, "source-identity.key"),
    ]));
    assert.deepEqual(result, {
      auth_file_count: 3,
      checkpoint_present: false,
      copied_count: 3,
      excluded_directory_count: 1,
      target_gid: targetGid,
      target_uid: targetUid,
    });
    assertPrivateFile(join(runtime, "config.yaml"));
    assertPrivateFile(join(runtime, "auth/account.json"));
    assertPrivateFile(join(runtime, "auth/nested/account.json"));
    assertPrivateFile(join(runtime, "auth/cpa-key-access-policy-state.json"));
    assertPrivateFile(join(runtime, "native-key-policy.json"));
    assertPrivateFile(join(runtime, "source-identity.key"));
    assert.deepEqual(readFileSync(join(runtime, "config.yaml")), readFileSync(config));
    assert.deepEqual(readFileSync(join(runtime, "auth/nested/account.json")), readFileSync(join(nested, "account.json")));
    assert.equal(existsSync(join(runtime, "auth/logs")), false);
    assertPrivateDirectory(join(runtime, "auth"));
    assertPrivateDirectory(join(runtime, "auth/nested"));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("skips exactly one reviewed auth subdirectory and reports only its count", () => {
  const root = workspace();
  try {
    const source = join(root, "source");
    const auth = join(source, "auth");
    const nested = join(auth, "nested");
    const logs = join(auth, "logs");
    const target = join(root, "runtime/auth");
    privateDirectory(source);
    privateDirectory(join(root, "runtime"));
    privateDirectory(auth);
    privateDirectory(nested);
    privateDirectory(logs);
    privateFile(join(auth, "account.json"), "{}\n");
    privateFile(join(logs, "debug.log"), "not JSON\n");
    privateFile(join(nested, "account.json"), "{\"kept\":true}\n");

    const result = receipt(runStage([
      "--copy-auth-dir", auth, target,
      "--exclude-auth-subdir", "logs",
    ]));
    assert.equal(result.auth_file_count, 2);
    assert.equal(result.excluded_directory_count, 1);
    assert.equal(existsSync(join(target, "logs")), false);
    assert.equal(existsSync(join(target, "nested/account.json")), true);
    assert.doesNotMatch(JSON.stringify(result), /logs/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("fails closed for unknown auth entries even when logs is excluded", () => {
  const root = workspace();
  try {
    const auth = join(root, "auth");
    privateDirectory(auth);
    privateDirectory(join(auth, "logs"));
    privateFile(join(auth, "logs/debug.log"), "approved log\n");
    privateFile(join(auth, "unexpected.txt"), "not approved\n");
    rejected(["--copy-auth-dir", auth, join(root, "out"), "--exclude-auth-subdir", "logs"], /non-JSON/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("accepts only normalized relative exact exclusion paths and rejects duplicates", () => {
  const root = workspace();
  try {
    const auth = join(root, "auth");
    privateDirectory(auth);
    privateFile(join(auth, "account.json"), "{}\n");
    for (const value of ["logs/*", "./logs", "../logs", "/logs", "logs/", "logs//child", "logs\\child"]) {
      rejected(["--copy-auth-dir", auth, join(root, `out-${value.replaceAll("/", "_")}`), "--exclude-auth-subdir", value], /normalized relative path/);
    }
    rejected(["--copy-auth-dir", auth, join(root, "missing-exclusion"), "--exclude-auth-subdir", "logs"], /not found/);
    rejected(["--copy-auth-dir", auth, join(root, "duplicate"), "--exclude-auth-subdir", "logs", "--exclude-auth-subdir", "logs"], /duplicate/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("rejects symlinks, hardlinks, unsafe modes, overwrites, and oversized inputs", () => {
  const root = workspace();
  try {
    const source = join(root, "source");
    const runtime = join(root, "runtime");
    privateDirectory(source);
    privateDirectory(runtime);

    const real = join(source, "real.json");
    privateFile(real, "{}\n");
    symlinkSync(real, join(source, "symlink.json"));
    rejected(["--copy", join(source, "symlink.json"), join(runtime, "symlink.json")], /regular non-symlink/);

    const hardlinked = join(source, "hardlinked.json");
    linkSync(real, hardlinked);
    rejected(["--copy", hardlinked, join(runtime, "hardlinked.json")], /exactly one hard link/);

    const unsafeMode = join(source, "unsafe-mode.json");
    privateFile(unsafeMode, "{}\n", 0o640);
    rejected(["--copy", unsafeMode, join(runtime, "unsafe-mode.json")], /group\/other accessible/);

    const existing = join(runtime, "existing.json");
    privateFile(existing, "original\n");
    rejected(["--copy", real, existing], /overwrite copy target/);

    const oversized = join(source, "oversized.json");
    privateFile(oversized, "123456789\n");
    rejected(["--copy", oversized, join(runtime, "oversized.json"), "--max-bytes", "4"], /copy limit/);

    const auth = join(source, "auth");
    privateDirectory(auth);
    privateFile(join(auth, "account.json"), "{}\n", 0o640);
    rejected(["--copy-auth-dir", auth, join(runtime, "auth")], /mode 0600/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("reports only a safe staging phase and errno for an unpublished destination failure", () => {
  const root = workspace();
  const source = join(root, "source");
  const runtime = join(root, "runtime");
  try {
    privateDirectory(source);
    privateDirectory(runtime);
    const config = join(source, "config.yaml");
    privateFile(config, "private-fixture-content\n");
    chmodSync(runtime, 0o500);
    const result = runStage(["--copy", config, join(runtime, "config.yaml")]);
    assert.notEqual(result.status, 0, `unexpected success: ${result.stdout}`);
    assert.match(result.stderr, /^protected input staging failed \(EACCES\)\n$/);
    assert.doesNotMatch(result.stderr, /private-fixture-content|config\.yaml|runtime/);
  } finally {
    try { chmodSync(runtime, 0o700); } catch {}
    rmSync(root, { recursive: true, force: true });
  }
});

test("fences an existing checkpoint and rejects unsafe checkpoint links", () => {
  const root = workspace();
  try {
    const checkpoint = join(root, "checkpoint.json");
    privateFile(checkpoint, "checkpoint\n", 0o644);
    const result = receipt(runStage(["--checkpoint", checkpoint]));
    assert.equal(result.checkpoint_present, true);
    assertPrivateFile(checkpoint);

    const hardlinked = join(root, "hardlinked-checkpoint.json");
    linkSync(checkpoint, hardlinked);
    rejected(["--checkpoint", hardlinked], /exactly one hard link/);

    const symlink = join(root, "symlink-checkpoint.json");
    symlinkSync(checkpoint, symlink);
    rejected(["--checkpoint", symlink], /regular non-symlink/);
    rejected(["--checkpoint", join(root, "missing.json"), "--checkpoint-required"], /required checkpoint/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("dispatches extensionless launchers by basename to explicit TypeScript targets", async () => {
  const root = workspace();
  try {
    const marker = join(root, "marker.json");
    const target = join(root, "import-cpa-model-routes.ts");
    privateFile(join(root, "package.json"), "{\"type\":\"module\"}\n");
    privateFile(target, [
      "#!/usr/bin/env node",
      "import { writeFileSync } from \"node:fs\";",
      "const markerPath = process.env.MTC_STAGE_TEST_MARKER;",
      "if (markerPath === undefined) throw new Error(\"test marker is missing\");",
      "writeFileSync(markerPath, JSON.stringify(process.argv.slice(1)));",
      "",
    ].join("\n"));
    const argv = ["node", join(root, "import-cpa-model-routes"), "--help"];
    const previousMarker = process.env.MTC_STAGE_TEST_MARKER;
    const previousArgv = process.argv;
    process.env.MTC_STAGE_TEST_MARKER = marker;
    try {
      await dispatch("import-cpa-model-routes", argv, root);
    } finally {
      process.argv = previousArgv;
      if (previousMarker === undefined) delete process.env.MTC_STAGE_TEST_MARKER;
      else process.env.MTC_STAGE_TEST_MARKER = previousMarker;
    }
    assert.deepEqual(JSON.parse(readFileSync(marker, "utf8")), [target, "--help"]);
    assert.equal(targetForEntrypoint("unknown"), undefined);
    assert.equal(targetForEntrypoint("stage-protected-inputs"), "stage-protected-inputs.ts");
    assert.equal(
      targetForEntrypoint("export-cpa-source-route-inventory"),
      "export-cpa-source-route-inventory.ts",
    );
    assert.equal(
      targetForEntrypoint("compose-cpa-upstream-inventory"),
      "compose-cpa-upstream-inventory.ts",
    );
    assert.equal(
      targetForEntrypoint("reconcile-final-price-cache"),
      "reconcile-final-price-cache.ts",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
