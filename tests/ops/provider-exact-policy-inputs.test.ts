import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";
import {
  buildProviderExactPolicyInputs,
  ProviderExactPolicyInputFailure,
} from "../../ops/legacy-policy/generate-provider-exact-policy-inputs.ts";

const keyHash = "a".repeat(64);
const sourceId = "11111111-1111-7111-8111-111111111111";
const routeId = "22222222-2222-7222-8222-222222222222";
const sourceStableId = "b".repeat(64);
const hash = (value: Buffer): string => createHash("sha256").update(value).digest("hex");
const bytes = (value: unknown): Buffer => Buffer.from(`${JSON.stringify(value)}\n`);

function fixture(options: { missingSource?: boolean; retiredDriver?: boolean; staleReceipt?: boolean } = {}): {
  policy: Buffer;
  source: Buffer;
  upstream: Buffer;
  manifest: Buffer;
  receipt: Buffer;
} {
  const sourceCoordinate = { provider: "codex-alpha", model: "gpt-5.6-sol", group: "classify:alpha", upstream_prefix: "codex-alpha", protocol: "openai" };
  const policy = bytes({ version: 1, policies: [{ key_hash: keyHash, enabled: true, grants: [{ provider: "codex-alpha", model: "gpt-5.6-sol", group: "classify:alpha", upstream_prefix: "codex-alpha" }] }], usage: {} });
  const source = bytes({ version: 2, mappings: options.missingSource ? [] : [sourceCoordinate], reauthorization_required: [], anomalies: [] });
  const upstream = bytes({
    version: 2,
    tenant_external_id: "default",
    upstreams: [{ upstream_account_id: sourceId, source_stable_id: sourceStableId, source_provider: "codex-alpha", driver: options.retiredDriver ? "legacy-cpa-bridge" : "http-json", status: "active", updated_at: 4 }],
    provider_candidate_sets: options.missingSource ? [] : [{ source: sourceCoordinate, upstream_model: "gpt-5.6-sol", protocol: "openai", selection: "equal_round_robin", candidates: [{ upstream_account_id: sourceId, source_stable_id: sourceStableId }] }],
  });
  const manifest = bytes({
    version: 2,
    tenant_external_id: "default",
    target_api_base_url: "http://control.example.test/",
    source_inventory_sha256: hash(source),
    upstream_inventory_sha256: hash(upstream),
    anomaly_quarantine: null,
    routes: options.missingSource ? [] : [{
      source: sourceCoordinate,
      target: { upstream_candidates: [{ upstream_account_id: sourceId, source_stable_id: sourceStableId }], public_model: "gpt-5.6-sol", upstream_model: "gpt-5.6-sol", protocol: "openai", priority: -100 },
      expected_existing: { action: "update", route_id: routeId, updated_at: 9, grant_revision: 2, history_and_references_reviewed: true, history_and_references_evidence_sha256: "c".repeat(64) },
    }],
  });
  const receipt = bytes({
    version: 1,
    tenant_external_id: "default",
    source_inventory_sha256: options.staleReceipt ? "d".repeat(64) : hash(source),
    upstream_inventory_sha256: hash(upstream),
    reviewed_route_manifest_sha256: hash(manifest),
    routes: options.missingSource ? [] : [{
      route_id: routeId,
      public_model: "gpt-5.6-sol",
      upstream_model: "gpt-5.6-sol",
      protocol: "openai",
      priority: -100,
      enabled: true,
      updated_at: 9,
      upstream_account_ids: [sourceId],
      candidate_upstream_account_ids: [sourceId],
      candidate_sources: [{ upstream_account_id: sourceId, source_stable_id: sourceStableId }],
    }],
  });
  return { policy, source, upstream, manifest, receipt };
}

describe("provider-exact policy input generator", () => {
  it("derives a full digest-bound mapping without exposing source key hashes", () => {
    const input = fixture();
    const generated = buildProviderExactPolicyInputs(input.policy, input.source, input.upstream, input.manifest, input.receipt);
    const routes = JSON.parse(generated.routeInventory.toString("utf8")) as { routes: Array<Record<string, unknown>> };
    const mapping = JSON.parse(generated.policyMapping.toString("utf8")) as { mappings: Array<Record<string, unknown>>; route_inventory_sha256: string };
    assert.equal(routes.routes.length, 1);
    assert.equal(mapping.mappings.length, 1);
    assert.equal(mapping.route_inventory_sha256, hash(generated.routeInventory));
    assert.equal(generated.policyMapping.includes(keyHash), false);
    assert.equal(generated.receipt.active_grant_count, 1);
    assert.equal(generated.receipt.mapped_route_count, 1);
  });

  it("fails closed on missing source coverage, retired candidates, and stale target receipts", () => {
    for (const options of [{ missingSource: true }, { retiredDriver: true }, { staleReceipt: true }]) {
      const input = fixture(options);
      assert.throws(
        () => buildProviderExactPolicyInputs(input.policy, input.source, input.upstream, input.manifest, input.receipt),
        ProviderExactPolicyInputFailure,
      );
    }
  });
});
