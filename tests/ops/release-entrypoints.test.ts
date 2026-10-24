import assert from "node:assert/strict";
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { releaseEntrypointNames, releaseEntrypoints } from "../../ops/ci/release-entrypoints.ts";

const repository = resolve(fileURLToPath(new URL("../..", import.meta.url)));

test("release bundle container qualifies the GNU executable before publication", () => {
  const dockerfile = readFileSync(resolve(repository, "ops/ci/Dockerfile.release-bundle"), "utf8");
  const workflow = readFileSync(resolve(repository, ".github/workflows/publish-release-bundle-oci.yml"), "utf8");
  const continuousIntegration = readFileSync(resolve(repository, ".github/workflows/ci.yml"), "utf8");
  assert.match(dockerfile, /^FROM node:24\.18\.0-trixie-slim@sha256:[0-9a-f]{64}$/mu);
  assert.doesNotMatch(dockerfile, /BASE_IMAGE|FROM .*alpine/iu);
  assert.match(dockerfile, /USER 10001:10001/u);
  assert.match(dockerfile, /RUN --network=none/u);
  assert.match(dockerfile, /sha256sum -c SHA256SUMS/u);
  assert.match(dockerfile, /import-cpa-session-archive" --help > "\$runtime\/importer-help\.txt"/u);
  assert.match(dockerfile, /grep -- --max-plan-bytes "\$runtime\/importer-help\.txt"/u);
  assert.match(dockerfile, /cpa-session-archive-backup" --help > "\$runtime\/backup-help\.txt"/u);
  assert.match(dockerfile, /grep -- pages-per-step "\$runtime\/backup-help\.txt"/u);
  assert.match(dockerfile, /export-cpa-session-archive-delta\.mjs" --help/u);
  assert.match(continuousIntegration, /name: Verify GNU release bundle container entrypoints/u);
  assert.match(continuousIntegration, /docker build --platform linux\/amd64/u);
  assert.doesNotMatch(workflow, /BASE_IMAGE/u);
  assert.match(workflow, /release-bundle-\$\{\{ env\.REVISION \}\}-delivery-\$\{\{ github\.sha \}\}/u);
});

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
    releaseEntrypoints["credential-recovery-backfill"],
    "src/credential-recovery-backfill.ts",
  );
  assert.equal(
    releaseEntrypoints["source-credential-recovery-apply"],
    "src/source-credential-recovery-apply.ts",
  );
  assert.equal(
    releaseEntrypoints["purge-retired-api2-trial"],
    "ops/release/purge-retired-api2-trial.ts",
  );
  assert.equal(
    releaseEntrypoints["adjust-failed-request-costs"],
    "ops/adjust-failed-request-costs.ts",
  );
  for (const retired of [
    ["native", "kimi", "import"].join("-"),
    ["import", "cpa", "upstreams"].join("-"),
  ]) assert.equal(retired in releaseEntrypoints, false);
  assert.equal(
    releaseEntrypoints["resolve-cpa-managed-codex-provenance"],
    "ops/legacy-routes/resolve-cpa-managed-codex-provenance.ts",
  );

  for (const [name, source] of Object.entries(releaseEntrypoints)) {
    assert.match(name, /^[a-z][a-z0-9-]+$/);
    assert.match(source, /^(?:ops|src)\/.+\.ts$/);
    assert.doesNotMatch(source, /cpa-managed-codex-route-parser/);
    const path = resolve(repository, source);
    assert.equal(lstatSync(path).isFile(), true);
    const content = readFileSync(path, "utf8");
    assert.match(content, /^#!\/usr\/bin\/env node$/m);
    assert.match(content, /from ["'][^"']*invoked-as-entrypoint\.ts["']/u);
    assert.match(content, new RegExp(`invokedAsEntrypoint\\("${name}", import\\.meta\\.url\\)`, "u"));
  }
});
