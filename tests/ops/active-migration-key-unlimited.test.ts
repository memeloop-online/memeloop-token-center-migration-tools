import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  parsePlan,
  parseReceipt,
  planDigestForCandidates,
  runTransition,
  TransitionFailure,
  type Candidate,
  type TargetClient,
  type TransitionCapabilities,
} from "../../ops/legacy-policy/transition-active-migration-keys-to-unlimited.ts";

const firstKey = "11111111-1111-7111-8111-111111111111";
const secondKey = "22222222-2222-7222-8222-222222222222";
const hex = (letter: string): string => letter.repeat(64);

const capabilities: TransitionCapabilities = {
  apiSchema: 1,
  planPath: "/internal/v1/migration-key-policy-unlimited/plan",
  applyPath: "/internal/v1/migration-key-policy-unlimited/apply",
  // Deliberately not the preferred spelling: the client accepts a current
  // product's formally advertised equivalent only when it supplies every
  // required safety guarantee.
  transitionName: "ledger_unrestricted",
};

function candidate(keyId: string, revision: number, requiresTransition = true): Candidate {
  return {
    keyId,
    policyRevision: revision,
    requiresTransition,
    identityDigest: hex("a"),
    grantsDigest: hex("b"),
    historyDigest: hex("c"),
    balanceDigest: hex("d"),
    credentialDigest: hex("e"),
  };
}

function capabilityResponse(): unknown {
  return {
    contract: "active-migration-key-unlimited",
    api_schema: capabilities.apiSchema,
    plan_path: capabilities.planPath,
    apply_path: capabilities.applyPath,
    transition: {
      name: capabilities.transitionName,
      atomic_batch_cas: true,
      balance_exhaustion_disabled: true,
      current_credential_preserved: true,
      grants_preserved: true,
      history_preserved: true,
      idempotent: true,
      key_identity_preserved: true,
      revoked_excluded: true,
    },
  };
}

function candidateResponse(value: Candidate): unknown {
  return {
    key_id: value.keyId,
    policy_revision: value.policyRevision,
    requires_transition: value.requiresTransition,
    status: "active",
    migration_primary: true,
    current_credential: true,
    revoked: false,
    identity_digest: value.identityDigest,
    grants_digest: value.grantsDigest,
    history_digest: value.historyDigest,
    balance_digest: value.balanceDigest,
    credential_digest: value.credentialDigest,
  };
}

function planResponse(values: readonly Candidate[]): unknown {
  return {
    contract: "active-migration-key-unlimited",
    transition: capabilities.transitionName,
    candidate_count: values.length,
    candidates: values.map(candidateResponse),
    plan_sha256: planDigestForCandidates(capabilities, values),
  };
}

class FixtureTarget implements TargetClient {
  values: Candidate[] = [candidate(firstKey, 7), candidate(secondKey, 11)];
  posts = 0;
  readonly requests: Array<Record<string, unknown>> = [];
  readonly idempotentResponses = new Map<string, Omit<Record<string, unknown>, "observed_plan_sha256">>();

  async get(path: string): Promise<unknown> {
    if (path === "/internal/v1/migration-key-policy-unlimited/capabilities") return capabilityResponse();
    if (path === capabilities.planPath) return planResponse(this.values);
    throw new TransitionFailure("fixture target received an unsupported read");
  }

  async post(path: string, body: Record<string, unknown>): Promise<unknown> {
    assert.equal(path, capabilities.applyPath);
    this.posts += 1;
    this.requests.push(body);
    const observed = String(body["observed_plan_sha256"]);
    const approved = String(body["approved_plan_sha256"]);
    const idempotencyKey = String(body["idempotency_key"]);
    const replay = this.idempotentResponses.get(idempotencyKey);
    if (replay) return { ...replay, observed_plan_sha256: observed };
    if (approved !== observed) throw new TransitionFailure("fixture target rejected a stale approved plan");
    const changed = this.values.filter((value) => value.requiresTransition).length;
    const count = this.values.length;
    this.values = this.values.map((value) => ({ ...value, requiresTransition: false, policyRevision: value.policyRevision + 1 }));
    const response = {
      contract: "active-migration-key-unlimited",
      transition: capabilities.transitionName,
      approved_plan_sha256: approved,
      candidate_count: count,
      changed_count: changed,
      already_unlimited_count: count - changed,
      identity_preserved_count: count,
      grants_preserved_count: count,
      history_preserved_count: count,
      balance_preserved_count: count,
      current_credentials_preserved_count: count,
      revoked_excluded: true,
      balance_exhaustion_disabled: true,
      atomic_cas: true,
      idempotent: true,
    };
    this.idempotentResponses.set(idempotencyKey, response);
    return { ...response, observed_plan_sha256: observed };
  }
}

describe("active migration key unlimited policy transition", () => {
  it("uses only the dynamically queried active migration-primary set in dry-run", async () => {
    const target = new FixtureTarget();
    const receipt = await runTransition(target, false);
    assert.equal(receipt.mode, "dry-run");
    assert.equal(receipt.transition, "ledger_unrestricted");
    assert.equal(receipt.candidate_count, target.values.length);
    assert.equal(receipt.planned_change_count, target.values.length);
    assert.equal(receipt.changed_count, 0);
    assert.equal(target.posts, 0);
    const serialized = JSON.stringify(receipt);
    for (const forbidden of [firstKey, secondKey, "fixture-token-value"]) assert.doesNotMatch(serialized, new RegExp(forbidden));
  });

  it("requires the target atomic CAS receipt and preserves identity, grants, history, balance, and credentials", async () => {
    const target = new FixtureTarget();
    const dryRun = await runTransition(target, false);
    const receipt = await runTransition(target, true, dryRun);
    assert.equal(receipt.mode, "apply");
    assert.equal(receipt.changed_count, 2);
    assert.equal(receipt.already_unlimited_count, 0);
    assert.equal(receipt.identity_preserved_count, 2);
    assert.equal(receipt.grants_preserved_count, 2);
    assert.equal(receipt.history_preserved_count, 2);
    assert.equal(receipt.balance_preserved_count, 2);
    assert.equal(receipt.current_credentials_preserved_count, 2);
    assert.ok(target.values.every((value) => !value.requiresTransition));
    assert.equal(target.posts, 1);
    assert.equal(target.requests[0]?.["approved_plan_sha256"], dryRun.plan_sha256);
    assert.match(String(target.requests[0]?.["idempotency_key"]), /^active-migration-key-unlimited-v1-[0-9a-f]{64}$/);
  });

  it("replays a lost apply response with the approved operation key and no second transition", async () => {
    const target = new FixtureTarget();
    const dryRun = await runTransition(target, false);
    const first = await runTransition(target, true, dryRun);
    const replay = await runTransition(target, true, dryRun);
    assert.equal(target.posts, 2);
    assert.equal(first.changed_count, 2);
    assert.equal(replay.changed_count, 2);
    assert.equal(replay.already_unlimited_count, 0);
    assert.ok(target.values.every((value) => !value.requiresTransition));
    assert.equal(target.requests[0]?.["idempotency_key"], target.requests[1]?.["idempotency_key"]);
  });

  it("accepts a fresh zero-write apply receipt after the exact policy is already present", async () => {
    const target = new FixtureTarget();
    const initial = await runTransition(target, false);
    await runTransition(target, true, initial);
    const current = await runTransition(target, false);
    assert.equal(current.planned_change_count, 0);
    const replay = await runTransition(target, true, current);
    assert.equal(replay.changed_count, 0);
    assert.equal(replay.already_unlimited_count, 2);
  });

  it("rejects a revoked, unproven, or balance-restricted candidate before any write", async () => {
    const original = planResponse([candidate(firstKey, 1)]);
    const mutate = (field: string, value: unknown): unknown => {
      const root = structuredClone(original) as Record<string, unknown>;
      const rows = root["candidates"] as Array<Record<string, unknown>>;
      rows[0]![field] = value;
      root["plan_sha256"] = planDigestForCandidates(capabilities, [candidate(firstKey, 1)]);
      return root;
    };
    for (const [field, value] of [["revoked", true], ["migration_primary", false], ["current_credential", false]] as const) {
      assert.throws(() => parsePlan(mutate(field, value), capabilities), TransitionFailure);
    }
    const unsafeCapabilities = structuredClone(capabilityResponse()) as Record<string, unknown>;
    const transition = unsafeCapabilities["transition"] as Record<string, unknown>;
    transition["balance_exhaustion_disabled"] = false;
    const target: TargetClient = { get: async () => unsafeCapabilities, post: async () => { assert.fail("must not write"); } };
    await assert.rejects(runTransition(target, false), TransitionFailure);
  });

  it("binds apply to an untampered dry-run receipt without disclosing candidate identities", async () => {
    const target = new FixtureTarget();
    const dryRun = await runTransition(target, false);
    const tampered = structuredClone(dryRun) as Record<string, unknown>;
    tampered["candidate_count"] = 1;
    assert.throws(() => parseReceipt(tampered), TransitionFailure);
    const parsed = parseReceipt(JSON.parse(JSON.stringify(dryRun)));
    assert.equal(parsed.receipt_sha256, dryRun.receipt_sha256);
    await assert.rejects(runTransition(target, true, { ...parsed, transition: "another_policy" }), TransitionFailure);
    assert.equal(target.posts, 0);
  });
});
