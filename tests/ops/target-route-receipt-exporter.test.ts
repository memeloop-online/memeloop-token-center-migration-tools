import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";
import {
  buildTargetRouteReceipt,
  encodeTargetRouteReceipt,
  TargetRouteReceiptExportFailure,
} from "../../ops/legacy-routes/export-cpa-target-route-receipt.ts";

const accountId = "11111111-1111-7111-8111-111111111111";
const routeId = "22222222-2222-7222-8222-222222222222";
const sourceStableId = "a".repeat(64);
const evidenceDigest = "b".repeat(64);
const hash = (value: Buffer): string => createHash("sha256").update(value).digest("hex");
const bytes = (value: unknown): Buffer => Buffer.from(`${JSON.stringify(value)}\n`);

function fixture(options: { tenantMismatch?: boolean; staleDigest?: boolean; routeMismatch?: boolean; retiredCandidate?: boolean } = {}) {
  const sourceCoordinate = { provider: "codex-alpha", model: "gpt-5.6-sol", group: "classify:alpha", upstream_prefix: "codex-alpha", protocol: "openai" } as const;
  const source = bytes({ version: 2, mappings: [sourceCoordinate], reauthorization_required: [], anomalies: [] });
  const upstream = bytes({
    version: 2,
    tenant_external_id: "default",
    upstreams: [{ upstream_account_id: accountId, source_stable_id: sourceStableId, source_provider: "codex-alpha", driver: options.retiredCandidate ? "legacy-cpa-bridge" : "http-json", status: "active", updated_at: 4 }],
    provider_candidate_sets: [{ source: sourceCoordinate, upstream_model: "gpt-5.6-sol", protocol: "openai", selection: "equal_round_robin", candidates: [{ upstream_account_id: accountId, source_stable_id: sourceStableId }] }],
  });
  const manifest = bytes({
    version: 2,
    tenant_external_id: options.tenantMismatch ? "other-tenant" : "default",
    target_api_base_url: "https://control.example.test/",
    source_inventory_sha256: options.staleDigest ? "c".repeat(64) : hash(source),
    upstream_inventory_sha256: hash(upstream),
    anomaly_quarantine: null,
    routes: [{
      source: sourceCoordinate,
      target: { upstream_candidates: [{ upstream_account_id: accountId, source_stable_id: sourceStableId }], public_model: "gpt-5.6-sol", upstream_model: "gpt-5.6-sol", protocol: "openai", priority: -100 },
      expected_existing: { action: "update", route_id: routeId, updated_at: 9, grant_revision: 2, history_and_references_reviewed: true, history_and_references_evidence_sha256: evidenceDigest },
    }],
  });
  const driver = options.retiredCandidate ? "legacy-cpa-bridge" : "http-json";
  const routes = [{
    id: routeId,
    publicModel: "gpt-5.6-sol",
    upstreamModel: "gpt-5.6-sol",
    protocol: "openai" as const,
    priority: -100,
    enabled: !options.routeMismatch,
    accountIds: [accountId],
    candidateAccountIds: [accountId],
    includedProviderGroupIds: [],
    excludedProviderGroupIds: [],
    routeGroupIds: [],
    grantedCredentialIds: [],
    customModelConfirmed: true,
    updatedAt: 9,
    grantRevision: 2,
  }];
  const accounts = [{ id: accountId, driver, status: "active", updatedAt: 4 }];
  return { source, upstream, manifest, routes, accounts };
}

describe("digest-bound target route receipt exporter", () => {
  it("seals the complete exact post-replay route without credentials", () => {
    const input = fixture();
    const receipt = encodeTargetRouteReceipt(buildTargetRouteReceipt(input.source, input.upstream, input.manifest, input.routes, input.accounts));
    const parsed = JSON.parse(receipt.toString("utf8")) as Record<string, unknown>;
    assert.deepEqual(Object.keys(parsed).sort(), ["reviewed_route_manifest_sha256", "routes", "source_inventory_sha256", "tenant_external_id", "upstream_inventory_sha256", "version"]);
    assert.equal(parsed.version, 1);
    assert.equal(parsed.tenant_external_id, "default");
    assert.equal(parsed.source_inventory_sha256, hash(input.source));
    assert.equal(parsed.upstream_inventory_sha256, hash(input.upstream));
    assert.equal(parsed.reviewed_route_manifest_sha256, hash(input.manifest));
    const routes = parsed.routes as Array<Record<string, unknown>>;
    assert.equal(routes.length, 1);
    assert.deepEqual(Object.keys(routes[0]!).sort(), ["candidate_sources", "candidate_upstream_account_ids", "enabled", "priority", "protocol", "public_model", "route_id", "updated_at", "upstream_account_ids", "upstream_model"]);
    assert.deepEqual(routes[0]!.candidate_sources, [{ upstream_account_id: accountId, source_stable_id: sourceStableId }]);
  });

  it("fails closed on tenant, digest, live-route, and retired-candidate mismatches", () => {
    for (const options of [{ tenantMismatch: true }, { staleDigest: true }, { routeMismatch: true }, { retiredCandidate: true }]) {
      const input = fixture(options);
      assert.throws(
        () => buildTargetRouteReceipt(input.source, input.upstream, input.manifest, input.routes, input.accounts),
        TargetRouteReceiptExportFailure,
      );
    }
  });
});
