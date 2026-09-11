import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { inspectSealedKimiCohort, NativeKimiImportFailure, run } from "../../src/native-kimi-import.ts";

const SOURCE_KEY_PREFIX = Buffer.from("4d54432d534f555243452d49442d4b45590001", "hex");
const REVISION = "a".repeat(40);
const roots: string[] = [];

function sha256(value: Buffer | string): string {
  return createHash("sha256").update(value).digest("hex");
}
function writePrivate(path: string, value: string | Buffer): void {
  writeFileSync(path, value, { mode: 0o600 });
  chmodSync(path, 0o600);
}
function jwt(subject: string, device: string, exp: number): string {
  const encode = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "fixture" })}.${encode({ iss: "https://auth.kimi.test", sub: subject, user_id: subject, device_id: device, exp })}.${Buffer.from(`sig-${subject}`).toString("base64url")}`;
}
function policies(): Record<string, unknown> {
  const models = [
    "kimi-k2", "kimi-k2-thinking", "kimi-k2.5", "kimi-k2.6",
    "kimi-k2.7-code", "kimi-k2.7-code-highspeed", "kimi-k3", "kimi-k3-256k",
  ];
  const entries = Array.from({ length: 10 }, (_, index) => ({
    key_hash: index.toString(16).padStart(64, "0"),
    enabled: true,
    grants: [3, 4, 9].includes(index)
      ? models.map((model) => ({ provider: "kimi", model }))
      : [],
  }));
  // The reviewed source has 131 total grants. Only the 24 Kimi grants are
  // semantically inspected by this cohort command.
  for (let index = 0; index < 107; index += 1) {
    (entries[index % 7]!.grants as Array<Record<string, unknown>>).push({
      provider: "other", model: `other-${index}`,
    });
  }
  return { version: 1, policies: entries, usage: {} };
}
type Fixture = { root: string; identityKey: string; secrets: string[]; devices: string[]; subjects: string[] };
function fixture(options: { duplicateIdentity?: boolean; disabled?: boolean } = {}): Fixture {
  const parent = mkdtempSync(join(tmpdir(), "mtc-native-kimi-"));
  roots.push(parent);
  chmodSync(parent, 0o700);
  const root = join(parent, "capture"), auth = join(root, "auth");
  mkdirSync(root, { mode: 0o700 });
  mkdirSync(auth, { mode: 0o700 });
  const config = Buffer.from("auth-dir: /root/.cli-proxy-api/auth\n");
  const policy = Buffer.from(`${JSON.stringify(policies())}\n`);
  writePrivate(join(root, "config.yaml"), config);
  writePrivate(join(root, "native-key-policy.json"), policy);
  const exp = 4_070_908_800;
  const subjects = ["fixture-user-one", options.duplicateIdentity ? "fixture-user-one" : "fixture-user-two"];
  const devices = ["fixture-device-one", "fixture-device-two"];
  const secrets = ["fixture-access-secret-one", "fixture-refresh-secret-one", "fixture-access-secret-two", "fixture-refresh-secret-two"];
  const payloads: Array<{ path: string; sha256: string }> = [];
  for (let index = 0; index < 2; index += 1) {
    const path = `kimi-${index + 1}.json`;
    const document = {
      type: "kimi",
      access_token: jwt(subjects[index]!, devices[index]!, exp),
      refresh_token: secrets[index * 2 + 1],
      token_type: "Bearer",
      scope: "coding",
      device_id: devices[index],
      expired: new Date(exp * 1_000).toISOString(),
      last_refresh: "2026-09-08T00:00:00.000Z",
      timestamp: 1_789_000_000 + index,
      disabled: options.disabled && index === 1,
    };
    const raw = Buffer.from(`${JSON.stringify(document)}\n`);
    writePrivate(join(auth, path), raw);
    payloads.push({ path, sha256: sha256(raw) });
  }
  const configSha256 = sha256(config), policySha256 = sha256(policy);
  const authPayloadRevisionSha256 = sha256(`${JSON.stringify({ version: 1, auth: payloads })}\n`);
  const sourceCaptureSha256 = sha256(`${JSON.stringify({ version: 1, config_sha256: configSha256, policy_sha256: policySha256, auth_payload_revision_sha256: authPayloadRevisionSha256 })}\n`);
  writePrivate(join(root, "source-capture-receipt.json"), `${JSON.stringify({
    version: 1,
    mode: "collect-cpa-source-snapshot",
    source_config_sha256: configSha256,
    source_policy_sha256: policySha256,
    auth_route_projection_sha256: "b".repeat(64),
    auth_payload_revision_sha256: authPayloadRevisionSha256,
    source_route_evidence_sha256: "c".repeat(64),
    source_capture_sha256: sourceCaptureSha256,
    managed_codex_model_snapshot_sha256: null,
    auth_file_count: 2,
    managed_codex_auth_file_count: 0,
  })}\n`);
  const identityKey = join(parent, "source-identity.key");
  writePrivate(identityKey, Buffer.concat([SOURCE_KEY_PREFIX, Buffer.from(Array.from({ length: 32 }, (_, index) => index + 1))]));
  return { root, identityKey, secrets, devices, subjects };
}

afterEach(() => {
  while (roots.length > 0) rmSync(roots.pop()!, { recursive: true, force: true });
});

describe("native Kimi sealed cohort", () => {
  it("emits only hashed active-account identity and a deferred route plan", async () => {
    const source = fixture(), receiptDirectory = join(source.root, "receipts");
    mkdirSync(receiptDirectory, { mode: 0o700 });
    const receipt = join(receiptDirectory, "dry-run.json");
    const summary = await run([
      "--source-directory", source.root,
      "--source-identity-key-file", source.identityKey,
      "--receipt", receipt,
    ]);
    assert.equal(summary.mode, "dry-run");
    assert.equal(summary.source_account_count, 2);
    assert.equal(summary.source_unique_identity_count, 2);
    assert.equal(summary.route_plan_count, 8);
    assert.equal(summary.import_count, 0);
    const raw = readFileSync(receipt, "utf8"), value = JSON.parse(raw) as Record<string, unknown>;
    assert.equal(value.outcome, "verified");
    assert.equal(value.route_write_count, 0);
    assert.equal(value.permission_write_count, 0);
    assert.equal(value.provider_request_count, 0);
    assert.equal((value.route_plan as unknown[]).length, 8);
    assert.equal((value.source_accounts as unknown[]).length, 2);
    for (const forbidden of [...source.secrets, ...source.devices, ...source.subjects, "kimi-1.json", "kimi-2.json"]) {
      assert.doesNotMatch(raw, new RegExp(forbidden, "u"));
    }
  });

  it("rejects disabled, duplicate, changed, and backup-like source cohorts before target access", () => {
    for (const options of [{ disabled: true }, { duplicateIdentity: true }]) {
      const source = fixture(options);
      assert.throws(() => inspectSealedKimiCohort(source.root, source.identityKey), NativeKimiImportFailure);
    }
    const changed = fixture();
    writePrivate(join(changed.root, "config.yaml"), "auth-dir: /changed\n");
    assert.throws(() => inspectSealedKimiCohort(changed.root, changed.identityKey), NativeKimiImportFailure);
    const backup = fixture();
    writePrivate(join(backup.root, "auth", "kimi-backup.json"), "{}\n");
    assert.throws(() => inspectSealedKimiCohort(backup.root, backup.identityKey), NativeKimiImportFailure);
  });
});

describe("native Kimi target preflight and apply gate", () => {
  it("uses only reviewed control endpoints and binds apply to the dry-run receipt", async () => {
    const source = fixture(), requests: Array<{ method?: string; url?: string }> = [];
    let imported = 0;
    const server = createServer((request: IncomingMessage, response: ServerResponse) => {
      requests.push({ method: request.method, url: request.url });
      response.setHeader("content-type", "application/json");
      if (request.method === "GET" && request.url === "/version") response.end(JSON.stringify({ service: "memeloop-token-center", revision: REVISION }));
      else if (request.method === "GET" && request.url === "/internal/v1/imports/cpa/managed-oauth/capabilities") response.end(JSON.stringify({ contract_version: 1, source_types: ["codex", "kimi"] }));
      else if (request.method === "GET" && request.url === "/internal/v1/provider-types") response.end(JSON.stringify([{ id: "kimi-oauth" }]));
      else if (request.method === "GET" && request.url === "/internal/v1/upstreams?tenant_external_id=default&limit=100") response.end("[]");
      else if (request.method === "POST" && request.url === "/internal/v1/imports/cpa/managed-oauth") {
        let raw = "";
        request.setEncoding("utf8");
        request.on("data", (chunk: string) => { raw += chunk; });
        request.on("end", () => {
          const body = JSON.parse(raw) as Record<string, unknown>;
          assert.equal(body.source_type, "kimi");
          assert.equal(body.tenant_external_id, "default");
          imported += 1;
          response.statusCode = 201;
          response.end(JSON.stringify({
            disposition: "created",
            account: {
              id: `10000000-0000-4000-8000-00000000000${imported}`,
              tenant_external_id: "default",
              name: `Kimi account ${String(imported).repeat(12)}`,
              driver: "kimi-oauth",
              status: "active",
            },
          }));
        });
      } else { response.statusCode = 404; response.end("{}"); }
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      assert(address && typeof address === "object");
      const origin = `http://127.0.0.1:${address.port}/`;
      const tokenFile = join(source.root, "service.token");
      writePrivate(tokenFile, "fixture-only-service-token\n");
      const receiptDirectory = join(source.root, "receipts");
      mkdirSync(receiptDirectory, { mode: 0o700 });
      const dryRun = join(receiptDirectory, "target-dry-run.json");
      const dry = await run([
        "--source-directory", source.root,
        "--source-identity-key-file", source.identityKey,
        "--receipt", dryRun,
        "--target-api-base-url", origin,
        "--service-token-file", tokenFile,
        "--tenant", "default",
        "--expected-target-revision", REVISION,
        "--allow-http-loopback",
      ]);
      assert.equal(dry.target_capabilities_verified, true);
      assert.equal(imported, 0);
      const applyReceipt = join(receiptDirectory, "apply.json");
      const applied = await run([
        "--source-directory", source.root,
        "--source-identity-key-file", source.identityKey,
        "--receipt", applyReceipt,
        "--target-api-base-url", origin,
        "--service-token-file", tokenFile,
        "--tenant", "default",
        "--expected-target-revision", REVISION,
        "--approved-dry-run-receipt", dryRun,
        "--expected-count", "2",
        "--apply",
        "--allow-http-loopback",
      ]);
      assert.equal(applied.import_count, 2);
      assert.equal(imported, 2);
      const appliedValue = JSON.parse(readFileSync(applyReceipt, "utf8")) as Record<string, unknown>;
      assert.equal((appliedValue.bindings as unknown[]).length, 2);
      assert.equal(appliedValue.route_write_count, 0);
      assert.equal(appliedValue.permission_write_count, 0);
      assert.equal(appliedValue.provider_request_count, 0);
      assert.deepEqual(new Set(requests.map((entry) => entry.url)), new Set([
        "/version",
        "/internal/v1/imports/cpa/managed-oauth/capabilities",
        "/internal/v1/provider-types",
        "/internal/v1/upstreams?tenant_external_id=default&limit=100",
        "/internal/v1/imports/cpa/managed-oauth",
      ]));
      assert.equal(requests.some((entry) => /models|health|quota|auth\.kimi/u.test(entry.url ?? "")), false);
    } finally {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});
