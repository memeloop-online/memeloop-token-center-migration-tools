import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { reconcileTransport, runTransportReconciliation, type SourceTransport, type ExistingTransport } from "../../ops/cpa-upstreams/reconcile-existing-transport.ts";
import { releaseEntrypoints } from "../../ops/ci/release-entrypoints.ts";

const source: SourceTransport = {
  stableId: "fixture-stable", provider: "fixture-provider", name: "fixture-name",
  config: { base_url: "https://fixture.example.test/v1", network_scope: "public" }, proxied: false,
};
const target: ExistingTransport = {
  id: "fixture-target", name: source.name, driver: "http-json", status: "active", updatedAt: 1,
  config: { ...source.config, result_origins: ["https://assets.example.test"] },
};
const candidates = [{ sourceStableId: source.stableId, sourceProvider: source.provider }];
test("exact existing transport becomes a policy without modifying either inventory", () => {
  const before = JSON.stringify([source, target]);
  const result = reconcileTransport([source], [target], candidates);
  assert.equal(result.matches.length, 1);
  assert.equal(result.quarantined.length, 0);
  assert.deepEqual(result.policy, {
    contract_version: 1, private_target_base_urls: [],
    result_origins_by_base_url: { "https://fixture.example.test/v1": ["https://assets.example.test"] },
  });
  assert.equal(JSON.stringify([source, target]), before);
});
test("proxy evidence is never inferred from private network scope or account identity", () => {
  const result = reconcileTransport([{ ...source, proxied: true }], [target], candidates);
  assert.equal(result.matches.length, 0);
  assert.equal(result.quarantined[0]?.reason, "source_proxy_unverifiable");
  assert.deepEqual(result.policy.private_target_base_urls, []);
});
test("missing, duplicate, stale, different-driver and altered configuration are quarantined", () => {
  for (const [targets, reason] of [
    [[], "target_absent"],
    [[target, { ...target, id: "fixture-other" }], "target_ambiguous"],
    [[{ ...target, status: "disabled" }], "target_inactive"],
    [[{ ...target, driver: "openai-codex" }], "target_driver_mismatch"],
    [[{ ...target, config: { ...target.config, timeout_seconds: 60 } }], "target_config_mismatch"],
    [[{ ...target, config: { ...target.config, network_scope: "unknown" } }], "target_transport_invalid"],
    [[{ ...target, config: { ...target.config, network_scope: "private" } }], "source_proxy_unverifiable"],
  ] as const) {
    const result = reconcileTransport([source], targets, candidates);
    assert.equal(result.quarantined[0]?.reason, reason);
    assert.equal(result.matches.length, 0);
    assert.deepEqual(result.policy.private_target_base_urls, []);
  }
});
test("base-level policy cannot broaden another unmatched source account sharing that base", () => {
  const other = { ...source, stableId: "fixture-other", name: "fixture-other", proxied: true };
  const result = reconcileTransport([source, other], [target], [...candidates, { sourceStableId: other.stableId, sourceProvider: other.provider }]);
  assert.equal(result.matches.length, 0);
  assert.deepEqual(new Set(result.quarantined.map(x => x.reason)), new Set(["source_proxy_unverifiable", "shared_base_transport_conflict"]));
});
test("conflicting target transport on the same base is not collapsed", () => {
  const other = { ...source, stableId: "fixture-other", name: "fixture-other" };
  const result = reconcileTransport([source, other], [target, { ...target, id: "fixture-other", name: other.name, config: source.config }],
    [...candidates, { sourceStableId: other.stableId, sourceProvider: other.provider }]);
  assert.equal(result.matches.length, 0);
  assert.equal(result.quarantined.length, 2);
  assert.deepEqual(result.policy.private_target_base_urls, []);
});
test("CLI refuses apply, omitted tenant and incomplete inputs before network or output", async () => {
  await assert.rejects(runTransportReconciliation(["--apply"]));
  await assert.rejects(runTransportReconciliation([]));
  assert.equal(releaseEntrypoints["reconcile-existing-transport"], "ops/cpa-upstreams/reconcile-existing-transport.ts");
});

test("CLI performs only authenticated GET and publishes bound owner-private outputs", { timeout: 20_000 }, async () => {
  const directory = mkdtempSync(join(tmpdir(), "transport-reconcile-fixture-"));
  chmodSync(directory, 0o700);
  const privateFile = (name: string, bytes: string | Buffer): string => {
    const path = join(directory, name);
    writeFileSync(path, bytes, { mode: 0o600 });
    chmodSync(path, 0o600);
    return path;
  };
  const digest = (bytes: string | Buffer): string => createHash("sha256").update(bytes).digest("hex");
  const configDocument = JSON.stringify({ "gemini-api-key": [{ "api-key": "fixture-only-source-key" }] });
  const config = privateFile("config.yaml", configDocument), sourceInventory = privateFile("source.json", "{}\n");
  const material = privateFile("candidate.json", JSON.stringify({
    version: 1, source_inventory_sha256: digest("{}\n"), provider_candidate_sets: [],
  }));
  const identity = privateFile("identity.key", Buffer.concat([
    Buffer.from("4d54432d534f555243452d49442d4b45590001", "hex"), Buffer.from(Array.from({ length: 32 }, (_, index) => index)),
  ]));
  const token = privateFile("token", "fixture-only-service-token\n");
  const auth = join(directory, "auth");
  mkdirSync(auth, { mode: 0o700 });
  const policy = join(directory, "policy.json"), receipt = join(directory, "receipt.json");
  let requests = 0;
  const server = createServer((request, response) => {
    requests++;
    assert.equal(request.method, "GET");
    assert.equal(request.url, "/internal/v1/upstreams?tenant_external_id=default&limit=100");
    assert.equal(request.headers.authorization, "Bearer fixture-only-service-token");
    response.setHeader("Content-Type", "application/json");
    response.end("[]");
  });
  await new Promise<void>(done => server.listen(0, "127.0.0.1", done));
  try {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const args = [
      resolve(import.meta.dirname, "../../ops/cpa-upstreams/reconcile-existing-transport.ts"),
      "--config", config, "--auth-dir", auth, "--source-identity-key-file", identity,
      "--source-inventory-file", sourceInventory, "--provider-candidate-material-file", material,
      "--tenant", "default", "--target-api-base-url", `http://127.0.0.1:${address.port}`,
      "--service-token-file", token, "--policy-output", policy, "--receipt-output", receipt,
      "--allow-http-loopback",
    ];
    const result = await new Promise<{ code: number | null; stdout: string; stderr: string }>((done, fail) => {
      const child = spawn(process.execPath, args, { stdio: ["ignore", "pipe", "pipe"], timeout: 15_000 });
      let stdout = "", stderr = "";
      child.stdout.on("data", chunk => { stdout += String(chunk); });
      child.stderr.on("data", chunk => { stderr += String(chunk); });
      child.on("error", fail);
      child.on("close", code => done({ code, stdout, stderr }));
    });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(requests, 1);
    assert.deepEqual(JSON.parse(result.stdout), {
      mode: "read-only-transport-reconciliation", candidate_count: 0, matched_count: 0, quarantined_count: 0,
    });
    for (const path of [policy, receipt]) assert.equal(statSync(path).mode & 0o777, 0o600);
    const saved = JSON.parse(readFileSync(receipt, "utf8"));
    assert.equal(saved.source_config_sha256, digest(configDocument));
    assert.equal(saved.transport_policy_sha256, digest(readFileSync(policy)));
    assert.equal(saved.target_inventory_sha256, digest("[]"));
    assert.doesNotMatch(result.stdout + result.stderr + readFileSync(receipt, "utf8"), /fixture-only-service-token/);
  } finally {
    server.closeAllConnections();
    await new Promise<void>(done => server.close(() => done()));
    rmSync(directory, { recursive: true, force: true });
  }
});
