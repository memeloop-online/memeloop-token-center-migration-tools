import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, closeSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, it } from "node:test";
import { inspectSealedOAuthCohort, SealedOAuthSourceAuditFailure, run } from "../../src/sealed-oauth-source-audit.ts";

const SOURCE_KEY_PREFIX = Buffer.from("4d54432d534f555243452d49442d4b45590001", "hex");
const NOW = 1_789_000_000_000;
const roots: string[] = [];
const repository = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const FIXTURE_CAPTURE_MODE = "fixture-sealed-source-snapshot";
const FIXTURE_MODELS = ["fixture-model-alpha", "fixture-model-beta", "fixture-model-gamma"];

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
  const entries = Array.from({ length: 4 }, (_, index) => ({
    key_hash: index.toString(16).padStart(64, "0"),
    enabled: true,
    grants: [0, 2].includes(index)
      ? FIXTURE_MODELS.map((model) => ({ provider: "kimi", model }))
      : [],
  }));
  for (let index = 0; index < 3; index += 1) {
    (entries[index]!.grants as Array<Record<string, unknown>>).push({
      provider: "other",
      model: `other-${index}`,
    });
  }
  return { version: 1, policies: entries, usage: {} };
}

type Fixture = {
  root: string;
  identityKey: string;
  expectation: string;
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
  writePrivate(join(root, "fixture-policy.json"), policy);

  const exp = options.expired ? 1_600_000_000 : 4_070_908_800;
  const subjects = [
    "fixture-user-one",
    options.duplicateIdentity ? "fixture-user-one" : "fixture-user-two",
    "fixture-user-three",
  ];
  const devices = ["fixture-device-one", "fixture-device-two", "fixture-device-three"];
  const refreshTokens = ["fixture-refresh-one", "fixture-refresh-two", "fixture-refresh-three"];
  const payloads: Array<{ path: string; sha256: string }> = [];
  const accessTokens: string[] = [];
  for (let index = 0; index < 3; index += 1) {
    const relativePath = index === 0 ? "fixture-oauth-1.json"
      : index === 1
        ? options.pathKind === "backup" ? "fixture-oauth-backup.json"
          : options.pathKind === "unsafe" ? "fixture-oauth\\unsafe.json" : "fixture-oauth-2.json"
        : "fixture-oauth-3.json";
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
      disabled: options.disabled && index === 2,
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
    mode: FIXTURE_CAPTURE_MODE,
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
  const expectation = join(parent, "source-expectation.json");
  writePrivate(expectation, `${JSON.stringify({
    version: 1,
    capture_mode: FIXTURE_CAPTURE_MODE,
    source_policy_file: "fixture-policy.json",
    source_type: "kimi",
    source_account_count: 3,
    source_policy_count: 4,
    source_grant_count: 9,
    provider_model_policy_counts: Object.fromEntries(FIXTURE_MODELS.map((model) => [model, 2])),
  })}\n`);
  return {
    root,
    identityKey,
    expectation,
    sensitiveValues: [
      "https://auth.kimi.test",
      ...subjects,
      ...devices,
      ...refreshTokens,
      ...accessTokens,
      ...accessTokens.flatMap((token) => token.split(".")),
      ...payloads.map((item) => item.path),
    ],
  };
}

afterEach(() => {
  while (roots.length > 0) rmSync(roots.pop()!, { recursive: true, force: true });
});

describe("sealed managed-OAuth source cohort", () => {
  it("has a recursively verified no-network dependency closure", () => {
    const entrypoint = join(repository, "src/sealed-oauth-source-audit.ts");
    const seen = new Set<string>();
    const allowedModules = new Set(["node:crypto", "node:fs", "node:path", "node:url"]);
    const visit = (path: string): void => {
      const normalized = resolve(path);
      assert.equal(relative(repository, normalized).startsWith(".."), false);
      if (seen.has(normalized)) return;
      seen.add(normalized);
      const body = readFileSync(normalized, "utf8");
      assert.doesNotMatch(body, /\bimport\s+["'][^"']+["']/u, "side-effect imports are forbidden");
      for (const pattern of [
        /node:(?:http|https|net|tls)/u,
        /\bimport\s*\(/u,
        /\brequire\s*\(/u,
        /\bgetBuiltinModule\s*\(/u,
        /\bfetch\s*\(/u,
        /\brequestJson\b/u,
        new RegExp(["--", "apply"].join(""), "u"),
        new RegExp(["--", "target", "-api-base-url"].join(""), "u"),
        new RegExp(["--", "service", "-token-file"].join(""), "u"),
      ]) assert.doesNotMatch(body, pattern, `forbidden dependency surface in ${relative(repository, normalized)}`);
      for (const match of body.matchAll(/\bfrom\s+["']([^"']+)["']/gu)) {
        const source = match[1]!;
        if (source.startsWith(".")) visit(resolve(dirname(normalized), source));
        else assert(allowedModules.has(source), `forbidden package dependency ${source}`);
      }
    };
    visit(entrypoint);
    assert(seen.has(join(repository, "src/lib/sealed-source-io.ts")));
    assert.deepEqual([...seen].map((path) => relative(repository, path)).sort(), [
      "ops/lib/invoked-as-entrypoint.ts",
      "ops/lib/strict-json.ts",
      "src/lib/sealed-source-io.ts",
      "src/sealed-oauth-source-audit.ts",
    ]);
  });

  it("audits an externally-bound synthetic cohort and writes only redacted source evidence", async () => {
    const source = fixture();
    const receiptDirectory = join(source.root, "receipts");
    mkdirSync(receiptDirectory, { mode: 0o700 });
    const receipt = join(receiptDirectory, "source-audit.json");
    const result = await run([
      "--source-directory", source.root,
      "--source-identity-key-file", source.identityKey,
      "--source-expectation-file", source.expectation,
      "--receipt", receipt,
    ]);
    assert.equal(result.mode, "source-audit");
    assert.equal(result.source_account_count, 3);
    assert.equal(result.source_unique_identity_count, 3);
    assert.match(String(result.batch_source_sha256), /^[0-9a-f]{64}$/u);

    const raw = readFileSync(receipt, "utf8");
    const value = JSON.parse(raw) as Record<string, unknown>;
    assert.equal(value.workflow, "sealed-managed-oauth-source-audit-v1");
    assert.equal(value.outcome, "verified");
    assert.equal(value.source_validation, "verified");
    assert.equal(value.source_expired_access_count, 0);
    const accounts = value.source_accounts as Array<Record<string, unknown>>;
    assert.equal(accounts.length, 3);
    assert.equal(value.batch_source_sha256, sha256(canonicalJson({
      source_capture_sha256: value.source_capture_sha256,
      source_accounts: accounts,
      source_expectation_sha256: value.source_expectation_sha256,
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
      assert.throws(() => inspectSealedOAuthCohort(source.root, source.identityKey, source.expectation, NOW), SealedOAuthSourceAuditFailure);
    }
    const changed = fixture();
    writePrivate(join(changed.root, "config.yaml"), "auth-dir: /changed/source-state/auth\n");
    assert.throws(() => inspectSealedOAuthCohort(changed.root, changed.identityKey, changed.expectation, NOW), SealedOAuthSourceAuditFailure);
    const tampered = fixture();
    const capturePath = join(tampered.root, "source-capture-receipt.json");
    const capture = JSON.parse(readFileSync(capturePath, "utf8")) as Record<string, unknown>;
    capture.source_capture_sha256 = "0".repeat(64);
    writePrivate(capturePath, `${JSON.stringify(capture)}\n`);
    assert.throws(() => inspectSealedOAuthCohort(tampered.root, tampered.identityKey, tampered.expectation, NOW), SealedOAuthSourceAuditFailure);
  });

  it("does not expose source paths when directory traversal fails", () => {
    const source = fixture();
    rmSync(join(source.root, "auth"), { recursive: true });
    assert.throws(
      () => inspectSealedOAuthCohort(source.root, source.identityKey, source.expectation, NOW),
      (error: unknown) => {
        assert(error instanceof Error);
        assert.equal(error.message, "sealed source I/O validation failed");
        assert.equal(String(error).includes(source.root), false);
        return true;
      },
    );
  });

  it("rejects retired remote-operation arguments before reading source material", async () => {
    for (const retired of [
      ["--", "apply"].join(""),
      ["--", "target", "-api-base-url"].join(""),
      ["--", "service", "-token-file"].join(""),
      ["--", "approved", "-dry-run-receipt"].join(""),
    ]) {
      await assert.rejects(run([retired]), SealedOAuthSourceAuditFailure);
    }
  });

  it("validates all bindings before creating a receipt and never overwrites a terminal receipt", async () => {
    const invalid = fixture({ disabled: true });
    const invalidReceiptDirectory = join(invalid.root, "receipts");
    mkdirSync(invalidReceiptDirectory, { mode: 0o700 });
    const invalidReceipt = join(invalidReceiptDirectory, "source-audit.json");
    await assert.rejects(run([
      "--source-directory", invalid.root,
      "--source-identity-key-file", invalid.identityKey,
      "--source-expectation-file", invalid.expectation,
      "--receipt", invalidReceipt,
    ]), (error: unknown) => {
      assert(error instanceof SealedOAuthSourceAuditFailure);
      assert.equal(error.outcome, "failed");
      return true;
    });
    assert.equal(existsSync(invalidReceipt), false);

    const source = fixture();
    const receiptDirectory = join(source.root, "receipts");
    mkdirSync(receiptDirectory, { mode: 0o700 });
    const receipt = join(receiptDirectory, "source-audit.json");
    const expectation = JSON.parse(readFileSync(source.expectation, "utf8")) as Record<string, unknown>;
    expectation.source_account_count = 4;
    writePrivate(source.expectation, `${JSON.stringify(expectation)}\n`);
    await assert.rejects(run([
      "--source-directory", source.root,
      "--source-identity-key-file", source.identityKey,
      "--source-expectation-file", source.expectation,
      "--receipt", receipt,
    ]), SealedOAuthSourceAuditFailure);
    assert.equal(existsSync(receipt), false);

    expectation.source_account_count = 3;
    writePrivate(source.expectation, `${JSON.stringify(expectation)}\n`);
    await run([
      "--source-directory", source.root,
      "--source-identity-key-file", source.identityKey,
      "--source-expectation-file", source.expectation,
      "--receipt", receipt,
    ]);
    const terminal = readFileSync(receipt);
    await assert.rejects(run([
      "--source-directory", source.root,
      "--source-identity-key-file", source.identityKey,
      "--source-expectation-file", source.expectation,
      "--receipt", receipt,
    ]), SealedOAuthSourceAuditFailure);
    assert.deepEqual(readFileSync(receipt), terminal);
  });

  it("classifies a single atomic receipt-write exception as uncertain without retrying or leaking tokens", async () => {
    const source = fixture();
    const receiptDirectory = join(source.root, "receipts");
    mkdirSync(receiptDirectory, { mode: 0o700 });
    const receipt = join(receiptDirectory, "source-audit.json");
    let writes = 0;
    await assert.rejects(run([
      "--source-directory", source.root,
      "--source-identity-key-file", source.identityKey,
      "--source-expectation-file", source.expectation,
      "--receipt", receipt,
    ], () => {
      writes += 1;
      throw new Error(source.sensitiveValues.join("."));
    }), (error: unknown) => {
      assert(error instanceof SealedOAuthSourceAuditFailure);
      assert.equal(error.outcome, "uncertain");
      for (const secret of source.sensitiveValues) assert.equal(String(error).includes(secret), false);
      return true;
    });
    assert.equal(writes, 1);
    assert.equal(existsSync(receipt), false);
  });

  it("classifies a descriptor-close failure after durable persistence as uncertain", async () => {
    const source = fixture();
    const receiptDirectory = join(source.root, "receipts");
    mkdirSync(receiptDirectory, { mode: 0o700 });
    const receipt = join(receiptDirectory, "source-audit.json");
    const closeCause = source.sensitiveValues[0]!;
    await assert.rejects(run([
      "--source-directory", source.root,
      "--source-identity-key-file", source.identityKey,
      "--source-expectation-file", source.expectation,
      "--receipt", receipt,
    ], undefined, (descriptor) => {
      closeSync(descriptor);
      throw new Error(closeCause);
    }), (error: unknown) => {
      assert(error instanceof SealedOAuthSourceAuditFailure);
      assert.equal(error.outcome, "uncertain");
      assert.equal(String(error).includes(closeCause), false);
      return true;
    });
    assert.equal(existsSync(receipt), true);
    assert.equal((JSON.parse(readFileSync(receipt, "utf8")) as Record<string, unknown>).outcome, "verified");
  });
});
