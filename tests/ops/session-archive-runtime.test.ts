import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { archiveRuntimePin, fileDigest, verifiedArchiveRuntime } from "../../ops/lib/session-archive-runtime.ts";

test("archive runtime rejects missing, drifted, substituted and symlinked artifacts before execution", () => {
  const directory = mkdtempSync(join(tmpdir(), "archive-runtime-fixture-"));
  const binary = join(directory, "import-cpa-session-archive");
  const manifest = join(directory, "compatibility.json");
  try {
    assert.throws(() => verifiedArchiveRuntime(binary), /verification failed/);
    writeFileSync(binary, "synthetic binary bytes; never executed", { mode: 0o700 });
    writeFileSync(join(directory, "source.tar"), "synthetic retained source bytes");
    const value = {
      format_version: 1, ...archiveRuntimePin,
      binary: "import-cpa-session-archive", source_archive: "source.tar",
      binary_sha256: fileDigest(binary), source_archive_sha256: fileDigest(join(directory, "source.tar")),
      cli_contract: "session-archive-import-v1", build_os: "ubuntu-24.04", minimum_glibc: "2.39",
      schema_policy: "engine-read-only-schema-precondition", source_closure_extracted: false,
      archive_schema_versions: [1, 2],
    };
    const reset = (): void => writeFileSync(manifest, JSON.stringify(value));
    reset();
    assert.equal(verifiedArchiveRuntime(binary), binary);
    for (const field of ["revision", "cargo_lock_sha256", "rust_version", "binary_sha256", "source_archive_sha256", "cli_contract", "minimum_glibc"]) {
      writeFileSync(manifest, JSON.stringify({ ...value, [field]: "tampered" }));
      assert.throws(() => verifiedArchiveRuntime(binary), /verification failed/);
    }
    reset();
    chmodSync(binary, 0o600);
    assert.throws(() => verifiedArchiveRuntime(binary), /verification failed/);
    chmodSync(binary, 0o700);
    const saved = readFileSync(binary);
    writeFileSync(binary, "substituted bytes");
    assert.throws(() => verifiedArchiveRuntime(binary), /verification failed/);
    writeFileSync(binary, saved);
    const alternate = join(directory, "alternate");
    writeFileSync(alternate, saved, { mode: 0o700 });
    rmSync(binary);
    symlinkSync(alternate, binary);
    assert.throws(() => verifiedArchiveRuntime(binary), /verification failed/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("release CI pins engine provenance and packages source without runtime builds", () => {
  const workflow = readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8");
  assert.ok(workflow.includes(archiveRuntimePin.revision));
  assert.ok(workflow.includes(archiveRuntimePin.cargo_lock_sha256));
  assert.match(workflow, /cargo build --locked --release --bin import-cpa-session-archive/);
  assert.match(workflow, /cargo test --locked --test session_archive_import --test session_archive_quarantine --test session_archive_unlinked/);
  const wrapper = readFileSync(new URL("../../ops/import-cpa-session-archive.ts", import.meta.url), "utf8");
  assert.match(wrapper, /verifiedArchiveRuntime\(binary\)/);
  assert.doesNotMatch(wrapper, /spawn\(["'](?:cargo|git|curl)/);
});
