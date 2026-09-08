#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, createHmac } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";
import {
  buildManagedCodexBindingReceipt,
  managedCodexImportSourceKey,
  ManagedCodexProvenanceFailure,
  prepareManagedCodexProvenance,
} from "../../ops/legacy-routes/resolve-cpa-managed-codex-provenance.ts";
import { managedCodexRouteSourceStableId } from "../../ops/legacy-routes/cpa-managed-codex-route-parser.ts";

const repository = resolve(import.meta.dirname, "../..");
const resolver = join(repository, "ops/legacy-routes/resolve-cpa-managed-codex-provenance.ts");
const fakePsql = join(repository, "tests/ops/helpers/fake-psql-managed-codex-provenance.ts");
const sourceKeyPrefix = Buffer.from("4d54432d534f555243452d49442d4b45590001", "hex");
const sha = (value: Buffer | string): string => createHash("sha256").update(value).digest("hex");
const accountId = "10000000-0000-4000-8000-000000000001";
const relativePath = "fixture-managed-codex.json";
const sourceTenant = "fixture-import-tenant", targetTenant = "fixture-route-tenant";
const identityKey = Buffer.alloc(32, 7), pepper = Buffer.from("fixture-key-pepper");

function protectedFile(path: string, value: Buffer | string): Buffer {
  const raw = Buffer.isBuffer(value) ? value : Buffer.from(value);
  writeFileSync(path, raw, { mode: 0o600 }); chmodSync(path, 0o600); return raw;
}
function artifacts(): Readonly<{ mapping: Buffer; config: Buffer; snapshot: Buffer; source: Buffer; material: Buffer; stableId: string; sourceKey: string }> {
  const config = Buffer.from("force-model-prefix: false\n");
  const stableId = managedCodexRouteSourceStableId(identityKey, relativePath);
  const source = Buffer.from(`${JSON.stringify({
    version: 2,
    mappings: [{ provider: "codex", model: "fixture-codex-model", group: null, upstream_prefix: null, protocol: "openai" }],
    reauthorization_required: [], anomalies: [],
  })}\n`);
  const material = Buffer.from(`${JSON.stringify({
    version: 1, source_inventory_sha256: sha(source),
    provider_candidate_sets: [{
      source: { provider: "codex", model: "fixture-codex-model", group: null, upstream_prefix: null, protocol: "openai" },
      upstream_model: "fixture-codex-upstream", protocol: "openai", selection: "equal_round_robin",
      candidates: [{ source_stable_id: stableId, source_provider: "codex", driver: "openai-codex" }],
    }],
  })}\n`);
  const snapshot = Buffer.from(`${JSON.stringify({
    version: 1, source_config_sha256: sha(config), auth_files_sha256: "a".repeat(64),
    auth_models: [{ auth_id: relativePath, provider: "codex", registered_models: ["fixture-codex-model"] }],
  })}\n`);
  const mapping = Buffer.from(`${JSON.stringify({ version: 1, source_import_tenant_external_id: sourceTenant, target_tenant_external_id: targetTenant, source_kind: "auth_file", source_type: "codex" })}\n`);
  return { mapping, config, snapshot, source, material, stableId, sourceKey: managedCodexImportSourceKey(pepper, sourceTenant, relativePath) };
}
function currentObservation(stableId: string, sourceKey: string, payloadDigest = "b".repeat(64)): Record<string, unknown> {
  return {
    source_stable_id: stableId, source_key: sourceKey, payload_digest: payloadDigest, contract_version: 1,
    upstream_account_id: accountId, driver: "openai-codex", auth_kind: "oauth", status: "active",
    credential_generation: 4, oauth_session_id: accountId, oauth_driver: "openai_codex_device",
    oauth_refresh_url: "https://auth.openai.com/oauth/token", updated_at: 72,
  };
}

describe("managed Codex existing-provenance receipt", () => {
  it("reproduces the product source-key HMAC and keeps route identity separate from a refreshed payload revision", () => {
    const expected = createHmac("sha256", pepper)
      .update("memeloop:cpa-managed-oauth:source-key:v1\0")
      .update(sourceTenant).update("\0").update("auth_file").update("\0").update(relativePath).digest("hex");
    assert.equal(managedCodexImportSourceKey(pepper, sourceTenant, relativePath), expected);

    const item = artifacts();
    const prepared = prepareManagedCodexProvenance(item.mapping, item.config, item.snapshot, item.source, item.material, identityKey, pepper);
    assert.deepEqual(prepared.requests, [{ sourceStableId: item.stableId, sourceKey: item.sourceKey }]);
    const first = buildManagedCodexBindingReceipt(prepared, [currentObservation(item.stableId, item.sourceKey)]);
    const refreshed = buildManagedCodexBindingReceipt(prepared, [currentObservation(item.stableId, item.sourceKey, "c".repeat(64))]);
    const firstReceipt = JSON.parse(first.receipt.toString("utf8")) as Record<string, unknown>;
    const refreshedReceipt = JSON.parse(refreshed.receipt.toString("utf8")) as Record<string, unknown>;
    assert.deepEqual(firstReceipt.bindings, [{ source_stable_id: item.stableId, source_provider: "codex", upstream_account_id: accountId, driver: "openai-codex", status: "active", updated_at: 72 }]);
    assert.deepEqual(refreshedReceipt.bindings, firstReceipt.bindings);
    assert.notEqual(first.provenanceDigest, refreshed.provenanceDigest);
    assert.doesNotMatch(first.receipt.toString("utf8"), /fixture-managed-codex|fixture-key-pepper|payload_digest|source_key/u);
  });

  it("rejects stale source snapshots and non-native or ambiguous target observations", () => {
    const item = artifacts();
    assert.throws(() => prepareManagedCodexProvenance(item.mapping, Buffer.from("changed-config"), item.snapshot, item.source, item.material, identityKey, pepper), ManagedCodexProvenanceFailure);
    const prepared = prepareManagedCodexProvenance(item.mapping, item.config, item.snapshot, item.source, item.material, identityKey, pepper);
    assert.throws(() => buildManagedCodexBindingReceipt(prepared, [{ ...currentObservation(item.stableId, item.sourceKey), oauth_driver: "wrong" }]), ManagedCodexProvenanceFailure);
    assert.throws(() => buildManagedCodexBindingReceipt(prepared, [currentObservation(item.stableId, item.sourceKey), currentObservation(item.stableId, item.sourceKey)]), ManagedCodexProvenanceFailure);
  });

  it("executes only a bounded read-only PostgreSQL receipt query and publishes a non-overwritable 0600 receipt", () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-managed-provenance-")); chmodSync(root, 0o700); chmodSync(fakePsql, 0o700);
    const item = artifacts();
    const mapping = join(root, "source-import-tenant-mapping.json"), config = join(root, "config.yaml"), snapshot = join(root, "managed-codex-model-snapshot.json"), source = join(root, "source-inventory.json"), material = join(root, "provider-candidate-material.json"), identity = join(root, "source-identity-key.bin"), keyPepper = join(root, "key-pepper.bin"), service = join(root, "pg-service.conf"), result = join(root, "managed-codex-provenance-query-result.json"), output = join(root, "managed-codex-receipt.json");
    protectedFile(mapping, item.mapping); protectedFile(config, item.config); protectedFile(snapshot, item.snapshot); protectedFile(source, item.source); protectedFile(material, item.material); protectedFile(identity, Buffer.concat([sourceKeyPrefix, identityKey])); protectedFile(keyPepper, pepper);
    protectedFile(service, "[fixture_provenance]\nhost=fixture.invalid\n");
    protectedFile(result, `${JSON.stringify([currentObservation(item.stableId, item.sourceKey)])}\n`);
    const arguments_ = [resolver, "--source-import-tenant-mapping-file", mapping, "--source-config-file", config, "--managed-codex-model-snapshot-file", snapshot, "--source-identity-key-file", identity, "--key-pepper-file", keyPepper, "--source-inventory-file", source, "--provider-candidate-material-file", material, "--pg-service-file", service, "--pg-service", "fixture_provenance", "--binding-receipt-output", output, "--psql-binary", fakePsql];
    const run = spawnSync(process.execPath, arguments_, { encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    const summary = JSON.parse(run.stdout) as Record<string, unknown>;
    assert.equal(summary.mode, "resolve-cpa-managed-codex-provenance"); assert.equal(summary.binding_count, 1);
    assert.equal(statSync(output).mode & 0o777, 0o600);
    assert.doesNotMatch(`${run.stdout}${run.stderr}${readFileSync(output, "utf8")}`, /fixture-managed-codex|fixture-key-pepper|payload_digest|source_key/u);
    const retained = readFileSync(output);
    const repeat = spawnSync(process.execPath, arguments_, { encoding: "utf8" });
    assert.equal(repeat.status, 2); assert.deepEqual(readFileSync(output), retained);
  });
});
