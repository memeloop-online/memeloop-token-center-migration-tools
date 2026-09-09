import assert from "node:assert/strict";
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { releaseEntrypointNames, releaseEntrypoints } from "../../ops/ci/release-entrypoints.ts";

const repository = resolve(fileURLToPath(new URL("../..", import.meta.url)));

test("release registry is the explicit non-container command contract", () => {
  assert.equal(existsSync(resolve(repository, "Dockerfile.importer")), false);
  assert.deepEqual(releaseEntrypointNames, Object.keys(releaseEntrypoints));
  assert.equal(
    releaseEntrypoints["export-cpa-managed-codex-model-snapshot"],
    "ops/legacy-routes/export-cpa-managed-codex-model-snapshot.ts",
  );
  assert.equal(
    releaseEntrypoints["collect-cpa-source-snapshot"],
    "ops/legacy-routes/collect-cpa-source-snapshot.ts",
  );
  assert.equal(
    releaseEntrypoints["resolve-cpa-managed-codex-provenance"],
    "ops/legacy-routes/resolve-cpa-managed-codex-provenance.ts",
  );

  for (const [name, source] of Object.entries(releaseEntrypoints)) {
    assert.match(name, /^[a-z][a-z0-9-]+$/);
    assert.match(source, /^ops\/.+\.ts$/);
    assert.doesNotMatch(source, /cpa-managed-codex-route-parser/);
    const path = resolve(repository, source);
    assert.equal(lstatSync(path).isFile(), true);
    const content = readFileSync(path, "utf8");
    assert.match(content, /^#!\/usr\/bin\/env node$/m);
    assert.match(content, /from ["'][^"']*invoked-as-entrypoint\.ts["']/u);
    assert.match(content, new RegExp(`invokedAsEntrypoint\\("${name}", import\\.meta\\.url\\)`, "u"));
  }
});
