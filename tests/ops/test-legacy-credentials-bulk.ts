#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";
import { installExecutableHelper } from "./contract-helpers.ts";

const { buildPlan, ImportFailure, parseCandidates } = await import("../../ops/legacy-credentials/attach-legacy-cpa-credentials.ts");
const { parseStrictJson, StrictJsonError } = await import("../../ops/lib/strict-json.ts");

const first = "fixture-only-cpa-linux-codex-key-0001";
const second = "fixture-only-cpa-claude-code-key-0002";
const identity = (value: string, keyId: string) => ({ sourceHash: createHash("sha256").update(value).digest("hex"), keyId });
const firstIdentity = identity(first, "10000000-0000-4000-8000-000000000001");
const secondIdentity = identity(second, "20000000-0000-4000-8000-000000000002");

describe("legacy credential attachment planning", () => {
  it("is exact, deterministic, one-to-one, and replay aware", () => {
    const plan = buildPlan([second, first], [firstIdentity, secondIdentity], [firstIdentity]);
    assert.deepEqual(plan.candidates.map((item) => item[1]), [firstIdentity, secondIdentity]);
    assert.equal(plan.alreadyAttached, 1);
  });

  it("rejects missing, unmatched, duplicate, revoked, and conflicting mappings", () => {
    for (const operation of [
      () => buildPlan([first], [firstIdentity, secondIdentity], []),
      () => buildPlan([first, second], [firstIdentity], []),
      () => buildPlan([first, first], [firstIdentity], []),
      () => buildPlan([first], [firstIdentity], [], [firstIdentity]),
      () => buildPlan([first, second], [firstIdentity, { ...secondIdentity, keyId: firstIdentity.keyId }], []),
      () => buildPlan([first], [firstIdentity], [{ ...firstIdentity, keyId: "30000000-0000-4000-8000-000000000003" }]),
    ]) assert.throws(operation, ImportFailure);
  });

  it("rejects duplicate JSON fields and credential whitespace", () => {
    assert.throws(() => parseCandidates(Buffer.from('{"api-keys":["fixture-only-key-00000001"],"api-keys":[]}'), "cpa-json"), ImportFailure);
    assert.throws(() => parseCandidates(Buffer.from(" fixture-only-key-00000001\n"), "lines"), ImportFailure);
    assert.deepEqual(parseCandidates(Buffer.from(`${first}\n${second}\n`), "lines"), [first, second]);
    assert.throws(() => parseCandidates(Buffer.concat([Buffer.from(first), Buffer.from([0xff])]), "lines"), ImportFailure);
    assert.throws(() => parseStrictJson("\u00a0null"), StrictJsonError);
    assert.throws(() => parseStrictJson("9007199254740993"), StrictJsonError);
  });

  it("runs a locked dry-run session without exposing credentials or hashes", () => {
    const repository = resolve(import.meta.dirname, "../..");
    const root = mkdtempSync(join(tmpdir(), "mtc-legacy-credentials-"));
    const candidate = join(root, "api-keys.json");
    writeFileSync(candidate, readFileSync(join(repository, "tests/fixtures/legacy-credentials/cpa-api-keys.json")), { mode: 0o400 });
    const fakePsql = installExecutableHelper("tests/ops/helpers/fake-psql-legacy.ts", root, "psql");
    const result = spawnSync(process.execPath, [
      join(repository, "ops/legacy-credentials/attach-legacy-cpa-credentials.ts"),
      "--tenant-external-id", "fixture-tenant",
      "--input-file", candidate,
      "--psql-binary", fakePsql,
    ], { encoding: "utf8", timeout: 20_000, env: { ...process.env, FAKE_PSQL_ROWS: join(repository, "tests/fixtures/legacy-credentials/cpamp-identities.csv") } });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), {
      mode: "dry-run", candidate_count: 2, identity_count: 2,
      existing_mapping_count: 0, already_attached_count: 0,
      pending_count: 2, attached_verified_count: 0,
    });
    for (const forbidden of [first, second, firstIdentity.sourceHash, secondIdentity.sourceHash]) assert.doesNotMatch(result.stdout + result.stderr, new RegExp(forbidden));
  });

  it("reports a missing psql process promptly without exposing input", () => {
    const repository = resolve(import.meta.dirname, "../..");
    const root = mkdtempSync(join(tmpdir(), "mtc-legacy-no-psql-"));
    const candidate = join(root, "api-keys.json"); writeFileSync(candidate, JSON.stringify({ "api-keys": [first] }), { mode: 0o400 });
    const result = spawnSync(process.execPath, [join(repository, "ops/legacy-credentials/attach-legacy-cpa-credentials.ts"), "--tenant-external-id", "fixture-tenant", "--input-file", candidate, "--psql-binary", join(root, "missing-psql")], { encoding: "utf8", timeout: 5_000 });
    assert.equal(result.status, 2);
    assert.match(result.stderr, /psql could not be started/);
    assert.doesNotMatch(result.stdout + result.stderr, new RegExp(first));
  });
});
