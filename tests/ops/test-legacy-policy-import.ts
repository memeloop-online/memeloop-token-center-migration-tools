#!/usr/bin/env node

import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { createHash } from "node:crypto";
import {
  buildPlan,
  executePlan,
  ImportFailure,
  loadCheckpoint,
  parseNativePolicy,
  readProtectedFile,
  writeCheckpoint,
  type ImportPlan,
  type TargetClient,
} from "../../ops/legacy-policy/import-cpa-key-policy.ts";

const firstHash = "a".repeat(64), secondHash = "b".repeat(64);
const firstKey = "11111111-1111-7111-8111-111111111111", secondKey = "22222222-2222-7222-8222-222222222222";
const routeId = "33333333-3333-7333-8333-333333333333", accountId = "44444444-4444-7444-8444-444444444444";
const source = { provider: "codex-csil", model: "gpt-5.6-sol", group: "classify:csil", upstream_prefix: "codex-csil" };
const digest = (value: Buffer): string => createHash("sha256").update(value).digest("hex");
const bytes = (value: unknown): Buffer => Buffer.from(JSON.stringify(value));

function fixture(options: { unknown?: boolean; duplicateMapping?: boolean; broad?: boolean; secondEnabled?: boolean; pairIssue?: "swapped" | "missing" | "duplicate" } = {}): { policy: Buffer; mapping: Buffer; inventory: Buffer } {
  const policyItem: Record<string, unknown> = { key_hash: firstHash, enabled: true, grants: [source] };
  if (options.unknown) policyItem["unexpected"] = true;
  const policy = bytes({ version: 1, policies: [policyItem, { key_hash: secondHash, enabled: options.secondEnabled ?? false, grants: options.secondEnabled ? [source] : [] }], usage: { count: 2 } });
  const secondAccount = "55555555-5555-7555-8555-555555555555";
  const candidateIds = options.broad || options.pairIssue ? [accountId, secondAccount] : [accountId];
  const canonicalSources = candidateIds.map((upstream_account_id, index) => ({ upstream_account_id, source_stable_id: `source-stable-${index + 1}` }));
  const inventorySources = options.pairIssue === "duplicate" ? [canonicalSources[0], canonicalSources[0]] : canonicalSources;
  const inventory = bytes({ version: 1, routes: [{ route_id: routeId, public_model: "gpt-5.6-sol", upstream_model: "gpt-5.6-sol", protocol: "openai", enabled: true, updated_at: 29, upstream_account_ids: [accountId], candidate_upstream_account_ids: candidateIds, candidate_sources: inventorySources }] });
  const mappingCandidateIds = options.broad ? [accountId] : candidateIds;
  let mappingSources = canonicalSources;
  if (options.broad || options.pairIssue === "missing") mappingSources = canonicalSources.slice(0, 1);
  if (options.pairIssue === "swapped") mappingSources = [{ upstream_account_id: accountId, source_stable_id: "source-stable-2" }, { upstream_account_id: secondAccount, source_stable_id: "source-stable-1" }];
  const item = { source, target: { route_id: routeId, expected_public_model: "gpt-5.6-sol", expected_upstream_model: "gpt-5.6-sol", expected_protocol: "openai", expected_updated_at: 29, expected_upstream_account_ids: [accountId], expected_candidate_upstream_account_ids: mappingCandidateIds, expected_candidate_sources: mappingSources } };
  const mapping = bytes({ version: 1, tenant_external_id: "fixture-tenant", source_snapshot_sha256: digest(policy), route_inventory_sha256: digest(inventory), mappings: options.duplicateMapping ? [item, item] : [item] });
  return { policy, mapping, inventory };
}
function planOf(options: Parameters<typeof fixture>[0] = {}): ImportPlan {
  const selected = fixture(options);
  return buildPlan(selected.policy, selected.mapping, selected.inventory, [{ sourceHash: firstHash, keyId: firstKey }, { sourceHash: secondHash, keyId: secondKey }]).plan;
}

class MemoryTarget implements TargetClient {
  readonly routes = new Map([[firstKey, { routeIds: [] as string[], routeGroupIds: [] as string[], revision: 0 }], [secondKey, { routeIds: [] as string[], routeGroupIds: [] as string[], revision: 0 }]]);
  readonly plan: ImportPlan;
  liveRouteOverride: Record<string, unknown> = {};
  failPut = 0; puts = 0; stale = false;
  constructor(plan: ImportPlan) { this.plan = plan; }
  async get(path: string): Promise<unknown> {
    if (path.startsWith("/internal/v1/model-routes?")) return [...this.plan.routeById.values()].map((route) => ({ id: route.routeId, public_model: route.publicModel, upstream_model: route.upstreamModel, protocol: route.protocol, enabled: route.enabled, updated_at: route.updatedAt, upstream_account_ids: route.upstreamAccountIds, candidate_upstream_account_ids: route.candidateUpstreamAccountIds, ...this.liveRouteOverride }));
    const key = path.split("/")[4]!; const state = this.routes.get(key); if (!state) throw new ImportFailure("fixture missing");
    return { key_id: key, route_ids: state.routeIds, route_group_ids: state.routeGroupIds, effective_route_ids: state.routeIds, updated_at: 0, grant_revision: state.revision };
  }
  async put(path: string, body: Record<string, unknown>): Promise<unknown> {
    this.puts += 1; if (this.stale || (this.failPut > 0 && this.puts === this.failPut)) throw new ImportFailure("target control API rejected the migration operation");
    const key = path.split("/")[4]!; const state = this.routes.get(key)!;
    assert.equal(body["expected_grant_revision"], state.revision);
    state.routeIds = [...body["route_ids"] as string[]].sort(); state.routeGroupIds = [...body["route_group_ids"] as string[]].sort(); state.revision += 1;
    return { key_id: key, route_ids: state.routeIds, route_group_ids: state.routeGroupIds, effective_route_ids: state.routeIds, updated_at: 1, grant_revision: state.revision };
  }
}

describe("legacy CPA policy import", () => {
  it("builds a strict dry-run plan with exact one-to-one identities", async () => {
    const plan = planOf();
    assert.equal(plan.policyCount, 2); assert.equal(plan.enabledPolicyCount, 1); assert.equal(plan.disabledPolicyCount, 1);
    assert.equal(plan.grantCount, 1); assert.equal(plan.matchedGrantCount, 1); assert.equal(plan.unmatchedGrantCount, 0);
    assert.deepEqual(plan.items.map((item) => item.routeIds), [[routeId], []]);
    const target = new MemoryTarget(plan); const result = await executePlan(plan, "fixture-tenant", target, false);
    assert.deepEqual(result, { changed: 1, replayed: 1 }); assert.equal(target.puts, 0);
  });

  it("applies with CAS and treats the exact second run as a zero-change replay", async () => {
    const plan = planOf(), target = new MemoryTarget(plan);
    assert.deepEqual(await executePlan(plan, "fixture-tenant", target, true), { changed: 1, replayed: 1 });
    assert.equal(target.puts, 1);
    assert.deepEqual(await executePlan(plan, "fixture-tenant", target, true), { changed: 0, replayed: 2 });
    assert.equal(target.puts, 1);
  });

  it("rejects unknown source fields, ambiguous mappings, and broader target candidates", () => {
    const unknown = fixture({ unknown: true }); assert.throws(() => parseNativePolicy(unknown.policy), ImportFailure);
    assert.throws(() => parseNativePolicy(bytes({ version: 2, policies: [], usage: {} })), /version is unsupported/);
    for (const options of [{ duplicateMapping: true }, { broad: true }]) assert.throws(() => planOf(options), ImportFailure);
  });

  it("pins account-to-source pairs and rejects swapped, missing, or duplicate bindings", () => {
    for (const pairIssue of ["swapped", "missing", "duplicate"] as const) assert.throws(() => planOf({ pairIssue }), ImportFailure);
  });

  it("rejects live protocol, enabled-state, revision, and candidate drift", async () => {
    const plan = planOf();
    for (const override of [{ protocol: "anthropic" }, { enabled: false }, { updated_at: 30 }, { candidate_upstream_account_ids: [] }]) {
      const target = new MemoryTarget(plan); target.liveRouteOverride = override;
      await assert.rejects(executePlan(plan, "fixture-tenant", target, false), ImportFailure);
    }
  });

  it("keeps missing source coordinates distinct from present empty coordinates", () => {
    const missing = { provider: source.provider, model: source.model, group: source.group };
    const policy = bytes({ version: 1, policies: [{ key_hash: firstHash, enabled: true, grants: [missing] }, { key_hash: secondHash, enabled: false, grants: [] }], usage: {} });
    assert.deepEqual(parseNativePolicy(policy)[0]?.grants[0], missing);
    const selected = fixture(), mapping = bytes({ version: 1, tenant_external_id: "fixture-tenant", source_snapshot_sha256: digest(policy), route_inventory_sha256: digest(selected.inventory), mappings: [{ source: { ...missing, upstream_prefix: "" }, target: { route_id: routeId, expected_public_model: "gpt-5.6-sol", expected_upstream_model: "gpt-5.6-sol", expected_protocol: "openai", expected_updated_at: 29, expected_upstream_account_ids: [accountId], expected_candidate_upstream_account_ids: [accountId], expected_candidate_sources: [{ upstream_account_id: accountId, source_stable_id: "source-stable-1" }] } }] });
    assert.throws(() => buildPlan(policy, mapping, selected.inventory, [{ sourceHash: firstHash, keyId: firstKey }, { sourceHash: secondHash, keyId: secondKey }]), (error: unknown) => error instanceof ImportFailure && error.counts?.["unmatched_grant_count"] === 1);
  });

  it("rejects changed source snapshots and missing mappings without disclosing the worklist", () => {
    const selected = fixture();
    const changedPolicy = Buffer.from(selected.policy); changedPolicy[changedPolicy.length - 2] = changedPolicy[changedPolicy.length - 2] === 49 ? 50 : 49;
    assert.throws(() => buildPlan(changedPolicy, selected.mapping, selected.inventory, [{ sourceHash: firstHash, keyId: firstKey }, { sourceHash: secondHash, keyId: secondKey }]), ImportFailure);
    const emptyMapping = bytes({ version: 1, tenant_external_id: "fixture-tenant", source_snapshot_sha256: digest(selected.policy), route_inventory_sha256: digest(selected.inventory), mappings: [] });
    assert.throws(() => buildPlan(selected.policy, emptyMapping, selected.inventory, [{ sourceHash: firstHash, keyId: firstKey }, { sourceHash: secondHash, keyId: secondKey }]), (error: unknown) => error instanceof ImportFailure && error.counts?.["unmatched_grant_count"] === 1);
  });

  it("fails a stale CAS without advancing progress", async () => {
    const plan = planOf(), target = new MemoryTarget(plan); target.stale = true; const progress: number[] = [];
    await assert.rejects(executePlan(plan, "fixture-tenant", target, true, 0, (count) => progress.push(count)), ImportFailure);
    assert.deepEqual(progress, []); assert.deepEqual(target.routes.get(firstKey)?.routeIds, []);
  });

  it("resumes a partial apply only after verifying checkpointed state", async () => {
    const plan = planOf({ secondEnabled: true }), target = new MemoryTarget(plan); target.failPut = 2; const progress: number[] = [];
    await assert.rejects(executePlan(plan, "fixture-tenant", target, true, 0, (count) => progress.push(count)), ImportFailure);
    assert.deepEqual(progress, [1]); assert.deepEqual(target.routes.get(firstKey)?.routeIds, [routeId]); assert.deepEqual(target.routes.get(secondKey)?.routeIds, []);
    target.failPut = 0; target.puts = 0;
    assert.deepEqual(await executePlan(plan, "fixture-tenant", target, true, 1), { changed: 1, replayed: 1 });
    target.routes.get(firstKey)!.routeIds = [];
    await assert.rejects(executePlan(plan, "fixture-tenant", target, true, 1), /checkpointed routing state changed/);
  });

  it("stores a mode-0600 checkpoint and rejects changed snapshot fences", () => {
    const plan = planOf(), root = mkdtempSync(join(tmpdir(), "mtc-policy-checkpoint-")), path = join(root, "checkpoint.json");
    writeCheckpoint(path, { version: 1, source_digest: plan.sourceDigest, mapping_digest: plan.mappingDigest, inventory_digest: plan.inventoryDigest, plan_digest: plan.planDigest, completed_count: 1 });
    assert.equal(readFileSync(path, "utf8").includes(firstHash), false); assert.equal(loadCheckpoint(path, plan).completed_count, 1);
    assert.throws(() => loadCheckpoint(path, { ...plan, sourceDigest: "f".repeat(64) }), /checkpoint conflicts/);
    chmodSync(path, 0o640); assert.throws(() => loadCheckpoint(path, plan), /mode 0600/);
  });

  it("requires mode 0600 for all protected inputs and keeps failures redacted", () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-policy-mode-")), path = join(root, "policy.json"); writeFileSync(path, "{}", { mode: 0o640 });
    assert.throws(() => readProtectedFile(path, "source policy"), /mode 0600/); chmodSync(path, 0o600); assert.equal(readProtectedFile(path, "source policy").toString(), "{}");
    for (const operation of [() => planOf({ broad: true }), () => planOf({ duplicateMapping: true })]) {
      try { operation(); assert.fail("expected failure"); } catch (error) {
        const output = error instanceof Error ? error.message : String(error);
        for (const forbidden of [firstHash, secondHash, firstKey, secondKey, routeId, accountId, "https://fixture.invalid"]) assert.doesNotMatch(output, new RegExp(forbidden));
      }
    }
  });
});
