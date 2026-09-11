import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  NativeKimiImportFailure,
  run,
  validateKimiDocument,
} from "../../src/native-kimi-import.ts";

const IDENTITY_KEY = Buffer.from(Array.from({ length: 32 }, (_, index) => index + 1));

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

function document(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const exp = 4_070_908_800;
  return {
    type: "kimi",
    access_token: jwt("fixture-user", "fixture-device", exp),
    refresh_token: "fixture-refresh-token",
    token_type: "Bearer",
    scope: "coding",
    device_id: "fixture-device",
    expired: new Date(exp * 1_000).toISOString(),
    last_refresh: "2026-09-08T00:00:00.000Z",
    timestamp: 1_789_000_000,
    disabled: false,
    ...overrides,
  };
}

describe("native Kimi source-format audit", () => {
  it("accepts a bounded active OAuth document and emits only a keyed identity", () => {
    const inspected = validateKimiDocument(document(), IDENTITY_KEY, 1_789_000_000_000);
    assert.equal(inspected.document.type, "kimi");
    assert.match(inspected.assertedIdentityHmacSha256, /^[0-9a-f]{64}$/u);
    assert.doesNotMatch(inspected.assertedIdentityHmacSha256, /fixture-user|fixture-device/u);
  });

  it("rejects disabled, proxied, expired, and identity-mismatched documents", () => {
    for (const candidate of [
      document({ disabled: true }),
      document({ proxy_url: "socks5h://proxy.example.test:1080" }),
      document({ expired: "2020-01-01T00:00:00.000Z" }),
      document({ device_id: "different-device" }),
    ]) {
      assert.throws(() => validateKimiDocument(candidate, IDENTITY_KEY, 1_789_000_000_000), NativeKimiImportFailure);
    }
  });
});

describe("native Kimi retired target surface", () => {
  it("rejects former target and apply arguments before reading source material", async () => {
    for (const retired of [
      "--apply",
      "--target-api-base-url",
      "--service-token-file",
      "--approved-dry-run-receipt",
    ]) {
      await assert.rejects(run([retired]), NativeKimiImportFailure);
    }
  });
});
