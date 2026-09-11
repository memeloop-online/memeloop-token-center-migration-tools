import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { inspectSealedKimiCohort, NativeKimiImportFailure, run } from "../../src/native-kimi-import.ts";

const SOURCE_KEY_PREFIX = Buffer.from("4d54432d534f555243452d49442d4b45590001", "hex");
const NOW = 1_789_000_000_000;
const roots: string[] = [];

function sha256(value: Buffer | string): string {
  return createHash("sha256").update(value).digest("hex");
}
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entry = value as Record<string, unknown>;
  return `{${Object.keys(entry).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(entry[key])}`).join(",")}}`;
}
function writePrivate(path: string, value: string | Buffer): void {
  writeFileSync(path, value, { mode: 0o600 });
  chmodSync(path, 0o600);
}
function jwt(subject: string, device: string, exp: number): string {
  const encode = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "fixture" })}.${encode({
    iss: "https://auth.kimi.test",
    sub: subject,
    user_id: subject,
    device_id: device,
    exp,
  })}.${Buffer.from(`sig-${subject}`).toString("base64url")}`;
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
  for (let index = 0; index < 107; index += 1) {
    (entries[index % 7]!.grants as Array<Record<string, unknown>>).push({
      provider: "other",
      model: `other-${index}`,
    });
  }
  return { version: 1, policies: entries, usage: {} };
}

type Fixture = {
  root: string;
  identityKey: string;
  sensitiveValues: string[];
};
function fixture(options: {
  disabled?: boolean;
  duplicateIdentity?: boolean;
  expired?: boolean;
  pathKind?: "backup" | "unsafe";
} = {}): Fixture {
  const parent = mkdtempSync(join(tmpdir(), "mtc-native-kimi-source-"));
  roots.push(parent);
  chmodSync(parent, 0o700);
  const root = join(parent, "capture");
  const auth = join(root, "auth");
  mkdirSync(root, { mode: 0o700 });
  mkdirSync(auth, { mode: 0o700 });

  const config = Buffer.from("auth-dir: /fixture/source-state/auth\n");
  const policy = Buffer.from(`${JSON.stringify(policies())}\n`);
  writePrivate(join(root, "config.yaml"), config);
  writePrivate(join(root, "native-key-policy.json"), policy);

  const exp = options.expired ? 1_600_000_000 : 4_070_908_800;
  const subjects = ["fixture-user-one", options.duplicateIdentity ? "fixture-user-one" : "fixture-user-two"];
  const devices = ["fixture-device-one", "fixture-device-two"];
  const refreshTokens = ["fixture-refresh-one", "fixture-refresh-two"];
  const payloads: Array<{ path: string; sha256: string }> = [];
  const accessTokens: string[] = [];
  for (let index = 0; index < 2; index += 1) {
    const relativePath = index !== 1 ? "kimi-1.json"
      : options.pathKind === "backup" ? "kimi-backup.json"
        : options.pathKind === "unsafe" ? "kimi\\unsafe.json" : "kimi-2.json";
    const accessToken = jwt(subjects[index]!, devices[index]!, exp);
    accessTokens.push(accessToken);
    const raw = Buffer.from(`${JSON.stringify({
      type: "kimi",
      access_token: accessToken,
      refresh_token: refreshTokens[index],
      token_type: "Bearer",
      scope: "coding",
      device_id: devices[index],
      expired: new Date(exp * 1_000).toISOString(),
      last_refresh: "2026-09-08T00:00:00.000Z",
      timestamp: 1_789_000_000 + index,
      disabled: options.disabled && index === 1,
    })}\n`);
    writePrivate(join(auth, relativePath), raw);
    payloads.push({ path: relativePath, sha256: sha256(raw) });
  }

  const configSha256 = sha256(config);
  const policySha256 = sha256(policy);
  const authPayloadRevisionSha256 = sha256(`${JSON.stringify({ version: 1, auth: payloads })}\n`);
  const sourceCaptureSha256 = sha256(`${JSON.stringify({
    version: 1,
    config_sha256: configSha256,
    policy_sha256: policySha256,
    auth_payload_revision_sha256: authPayloadRevisionSha256,
  })}\n`);
  writePrivate(join(root, "source-capture-receipt.json"), `${JSON.stringify({
    version: 1,
    mode: "collect-cpa-source-snapshot",
    source_config_sha256: configSha256,
    source_policy_sha256: policySha256,
    auth_payload_revision_sha256: authPayloadRevisionSha256,
    source_capture_sha256: sourceCaptureSha256,
    auth_file_count: payloads.length,
  })}\n`);
  const identityKey = join(parent, "source-identity.key");
  writePrivate(identityKey, Buffer.concat([
    SOURCE_KEY_PREFIX,
    Buffer.from(Array.from({ length: 32 }, (_, index) => index + 1)),
  ]));
  return {
    root,
    identityKey,
    sensitiveValues: [...subjects, ...devices, ...refreshTokens, ...accessTokens, ...payloads.map((item) => item.path)],
  };
}

afterEach(() => {
  while (roots.length > 0) rmSync(roots.pop()!, { recursive: true, force: true });
});

describe("native Kimi sealed source cohort", () => {
  it("audits two accounts end-to-end and writes only redacted source evidence", async () => {
    const source = fixture();
    const receiptDirectory = join(source.root, "receipts");
    mkdirSync(receiptDirectory, { mode: 0o700 });
    const receipt = join(receiptDirectory, "source-audit.json");
    const result = await run([
      "--source-directory", source.root,
      "--source-identity-key-file", source.identityKey,
      "--receipt", receipt,
    ]);
    assert.equal(result.mode, "source-audit");
    assert.equal(result.source_account_count, 2);
    assert.equal(result.source_unique_identity_count, 2);
    assert.match(String(result.batch_source_sha256), /^[0-9a-f]{64}$/u);

    const raw = readFileSync(receipt, "utf8");
    const value = JSON.parse(raw) as Record<string, unknown>;
    assert.equal(value.workflow, "sealed-kimi-source-audit-v1");
    assert.equal(value.outcome, "verified");
    assert.equal(value.source_validation, "verified");
    assert.equal(value.source_expired_access_count, 0);
    const accounts = value.source_accounts as Array<Record<string, unknown>>;
    assert.equal(accounts.length, 2);
    assert.equal(value.batch_source_sha256, sha256(canonicalJson({
      source_capture_sha256: value.source_capture_sha256,
      source_accounts: accounts,
    })));
    for (const account of accounts) {
      assert.deepEqual(Object.keys(account).sort(), [
        "asserted_identity_hmac_sha256",
        "source_document_sha256",
        "source_document_validation",
        "source_expires_at",
        "source_stable_id",
        "source_status",
      ]);
      assert.equal(account.source_status, "active");
      assert.equal(account.source_document_validation, "verified");
    }
    assert.doesNotMatch(raw, /target_|credential_|route_plan|route_write|permission_write|provider_request/u);
    for (const secret of source.sensitiveValues) {
      assert.equal(raw.includes(secret), false, `receipt leaked synthetic sensitive value: ${secret}`);
    }
  });

  it("rejects capture drift, duplicate identity, disabled or expired accounts, and unsafe or backup-like paths", () => {
    for (const options of [
      { duplicateIdentity: true },
      { disabled: true },
      { expired: true },
      { pathKind: "unsafe" as const },
      { pathKind: "backup" as const },
    ]) {
      const source = fixture(options);
      assert.throws(() => inspectSealedKimiCohort(source.root, source.identityKey, NOW), NativeKimiImportFailure);
    }
    const changed = fixture();
    writePrivate(join(changed.root, "config.yaml"), "auth-dir: /changed/source-state/auth\n");
    assert.throws(() => inspectSealedKimiCohort(changed.root, changed.identityKey, NOW), NativeKimiImportFailure);
    const tampered = fixture();
    const capturePath = join(tampered.root, "source-capture-receipt.json");
    const capture = JSON.parse(readFileSync(capturePath, "utf8")) as Record<string, unknown>;
    capture.source_capture_sha256 = "0".repeat(64);
    writePrivate(capturePath, `${JSON.stringify(capture)}\n`);
    assert.throws(() => inspectSealedKimiCohort(tampered.root, tampered.identityKey, NOW), NativeKimiImportFailure);
  });

  it("rejects retired target/apply arguments before reading source material", async () => {
    for (const retired of ["--apply", "--target-api-base-url", "--service-token-file", "--approved-dry-run-receipt"]) {
      await assert.rejects(run([retired]), NativeKimiImportFailure);
    }
  });
});
