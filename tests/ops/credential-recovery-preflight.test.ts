import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { readSourceKeys, runRecoveryPreflight, verifyIdentity } from "../../src/credential-recovery-preflight.ts";

const key = "fixture-only-existing-client-key";
const keyId = "10000000-0000-4000-8000-000000000001";
const hash = (raw: Buffer): string => createHash("sha256").update(raw).digest("hex");
const source = Buffer.from(JSON.stringify({ "api-keys": [key] }));
const capture = (raw: Buffer): Buffer => Buffer.from(JSON.stringify({ source_config_sha256: hash(raw) }));
const self = { key_id: keyId, credential_generation: 3 };
const control = { ...self, tenant_external_id: "default", status: "active", credential_recovery_available: false };

test("approved source must have exact digest/count, unique exact client keys and strict YAML", () => {
  assert.deepEqual(readSourceKeys(source, capture(source), 1), [key]);
  assert.throws(() => readSourceKeys(source, capture(Buffer.from("{}")), 1));
  assert.throws(() => readSourceKeys(source, capture(source), 2));
  for (const raw of [
    Buffer.from(JSON.stringify({ "api-keys": [key, key] })),
    Buffer.from(`api-keys: [${key}]\napi-keys: [${key}]\n`),
    Buffer.from(JSON.stringify({ "api-keys": [` ${key}`] })),
    Buffer.from(JSON.stringify({ "api-keys": [] })),
  ]) assert.throws(() => readSourceKeys(raw, capture(raw), 1));
});

test("identity is double-bound to active explicit tenant and current generation", () => {
  assert.equal(verifyIdentity({ ...self, credential_generation: 0 },
    [{ ...control, credential_generation: 0 }], "default", 0).credential_generation, 0);
  assert.throws(() => verifyIdentity({ ...self, credential_generation: -1 },
    [{ ...control, credential_generation: -1 }], "default", 0));
  assert.deepEqual(verifyIdentity(self, [control], "default", 0), {
    source_index: 0, key_id: keyId, credential_generation: 3, recovery_available: false,
  });
  for (const wrong of [
    [], [control, control], [{ ...control, tenant_external_id: "other" }],
    [{ ...control, credential_generation: 4 }], [{ ...control, status: "revoked" }],
    [{ ...control, key_id: "20000000-0000-4000-8000-000000000002" }],
    [{ ...control, credential_recovery_available: undefined }],
  ]) assert.throws(() => verifyIdentity(self, wrong, "default", 0));
  assert.throws(() => verifyIdentity({ ...self, key_id: "../keys" }, [control], "default", 0));
});

test("preflight rejects apply, missing inputs and HTTP outside explicit loopback", async () => {
  await assert.rejects(runRecoveryPreflight(["--apply"]));
  await assert.rejects(runRecoveryPreflight([]));
});

for (const scenario of ["success", "generation_zero", "revoked", "generation_changed", "duplicate_identity", "control_missing",
  "control_wrapper", "tenant_wrong", "generation_string", "status_wrong", "recovery_missing",
  "self_wrapper", "self_generation_string"] as const) {
  test(`GET-only CLI ${scenario} never stores original keys or prints them`, { timeout: 20_000 }, async () => {
    const directory = mkdtempSync(join(tmpdir(), "credential-identity-preflight-"));
    chmodSync(directory, 0o700);
    const privateFile = (name: string, bytes: Buffer | string): string => {
      const path = join(directory, name);
      writeFileSync(path, bytes, { mode: 0o600 }); chmodSync(path, 0o600);
      return path;
    };
    const rawSource = scenario === "duplicate_identity"
      ? Buffer.from(JSON.stringify({ "api-keys": [key, `${key}-second`] })) : source;
    const configPath = privateFile("config.yaml", rawSource);
    const capturePath = privateFile("capture.json", capture(rawSource));
    const tokenPath = privateFile("control.token", "fixture-only-control-read-token\n");
    const receiptPath = join(directory, "receipt.json");
    let selfRequests = 0, controlRequests = 0;
    const server = createServer((request, response) => {
      assert.equal(request.method, "GET");
      response.setHeader("Content-Type", "application/json");
      if (request.url === "/self/v1/key") {
        selfRequests++;
        assert.ok([`Bearer ${key}`, `Bearer ${key}-second`].includes(request.headers.authorization ?? ""));
        if (scenario === "revoked") { response.statusCode = 401; response.end(key); return; }
        if (scenario === "self_wrapper") { response.end(JSON.stringify({ data: self })); return; }
        response.end(JSON.stringify({
          ...self, credential_generation: scenario === "generation_zero" ? 0 : scenario === "self_generation_string" ? "3"
            : scenario === "generation_changed" && selfRequests > 1 ? 4 : 3,
        }));
      } else {
        controlRequests++;
        assert.equal(request.url, `/internal/v1/keys?tenant_external_id=default&key_id=${keyId}&limit=2`);
        assert.equal(request.headers.authorization, "Bearer fixture-only-control-read-token");
        const item = { ...control };
        if (scenario === "control_missing") { response.end("[]"); return; }
        if (scenario === "control_wrapper") { response.end(JSON.stringify({ items: [control] })); return; }
        response.end(JSON.stringify([{
          ...item,
          ...(scenario === "generation_zero" ? { credential_generation: 0 } : {}),
          ...(scenario === "tenant_wrong" ? { tenant_external_id: "different" } : {}),
          ...(scenario === "generation_string" ? { credential_generation: "3" } : {}),
          ...(scenario === "status_wrong" ? { status: "revoked" } : {}),
          ...(scenario === "recovery_missing" ? { credential_recovery_available: undefined } : {}),
        }]));
      }
    });
    await new Promise<void>(done => server.listen(0, "127.0.0.1", done));
    try {
      const address = server.address();
      assert.ok(address && typeof address !== "string");
      const endpoint = `http://127.0.0.1:${address.port}`;
      const result = await new Promise<{ code: number | null; stdout: string; stderr: string }>((done, fail) => {
        const child = spawn(process.execPath, [
          resolve(import.meta.dirname, "../../src/credential-recovery-preflight.ts"),
          "--source-config-file", configPath, "--source-receipt-file", capturePath,
          "--expected-count", scenario === "duplicate_identity" ? "2" : "1", "--tenant", "default",
          "--gateway-api-base-url", endpoint, "--control-api-base-url", endpoint,
          "--service-token-file", tokenPath, "--receipt-output", receiptPath, "--allow-http-loopback",
        ], { stdio: ["ignore", "pipe", "pipe"], timeout: 15_000 });
        let stdout = "", stderr = "";
        child.stdout.on("data", chunk => { stdout += String(chunk); });
        child.stderr.on("data", chunk => { stderr += String(chunk); });
        child.on("error", fail);
        child.on("close", code => done({ code, stdout, stderr }));
      });
      const successful = scenario === "success" || scenario === "generation_zero";
      assert.equal(result.code, successful ? 0 : 2, result.stderr);
      let receiptText = "";
      if (scenario === "success" || scenario === "generation_zero") {
        assert.equal(selfRequests, 2); assert.equal(controlRequests, 1);
        assert.deepEqual(JSON.parse(result.stdout), {
          mode: "dry-run", source_count: 1, verified_count: 1, recovery_available_count: 0, recovery_missing_count: 1, stored_count: 0,
        });
        assert.equal(statSync(receiptPath).mode & 0o777, 0o600);
        receiptText = readFileSync(receiptPath, "utf8");
        const receipt = JSON.parse(receiptText);
        assert.equal(receipt.source_config_sha256, hash(rawSource));
        assert.equal(receipt.identities[0].key_id, keyId);
        assert.equal(receipt.identities[0].credential_generation, scenario === "generation_zero" ? 0 : 3);
      } else {
        assert.equal(result.stdout, "");
        assert.equal(existsSync(receiptPath), true);
        receiptText = readFileSync(receiptPath, "utf8");
        const receipt = JSON.parse(receiptText);
        assert.equal(receipt.mode, "credential-recovery-preflight-failed");
        assert.equal(receipt.eligible_for_apply, false);
        assert.equal(receipt.stored_count, 0);
        assert.equal(Object.hasOwn(receipt, "identities"), false);
        const reasons = {
          revoked: "http_status", generation_changed: "secondpass_generation_changed",
          duplicate_identity: "duplicate_identity", control_missing: "control_match_count",
          control_wrapper: "control_shape", tenant_wrong: "tenant_mismatch",
          generation_string: "generation_type", status_wrong: "status_not_active",
          recovery_missing: "recovery_flag_type", self_wrapper: "self_identity_shape",
          self_generation_string: "self_generation_type",
        };
        assert.equal(receipt.reason, reasons[scenario]);
        if (scenario === "revoked") assert.equal(receipt.http_status, 401);
        if (scenario === "control_missing") assert.equal(receipt.control_match_count, 0);
        assert.equal(statSync(receiptPath).mode & 0o777, 0o600);
      }
      for (const forbidden of [key, "fixture-only-control-read-token", endpoint]) {
        assert.equal((result.stdout + result.stderr + receiptText).includes(forbidden), false);
      }
      assert.equal((result.stdout + result.stderr).includes(keyId), false);
    } finally {
      server.closeAllConnections();
      await new Promise<void>(done => server.close(() => done()));
      rmSync(directory, { recursive: true, force: true });
    }
  });
}
