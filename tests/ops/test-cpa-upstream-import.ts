#!/usr/bin/env node

import assert from "node:assert/strict";
import { chmodSync, cpSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";

const repository = resolve(import.meta.dirname, "../..");
const importer = join(repository, "ops/cpa-upstreams/import-cpa-upstreams.ts");
const generator = join(repository, "ops/cpa-upstreams/generate-source-identity-key.ts");
const sanitizer = join(repository, "tests/ops/sanitize-cpa-upstream-fixtures.ts");
const fixtures = join(repository, "tests/fixtures/cpa-upstreams");

function privateTree(path: string): void {
  const metadata = lstatSync(path);
  chmodSync(path, metadata.isDirectory() ? 0o700 : 0o600);
  if (metadata.isDirectory()) {
    for (const name of readFileNames(path)) privateTree(join(path, name));
  }
}
function readFileNames(path: string): string[] {
  return readdirSync(path);
}
function writeTransportPolicy(root: string, privateTargetBaseUrls: string[], resultOriginsByBaseUrl: Record<string, string[]> = {}): string {
  const path = join(root, "transport-policy.json");
  writeFileSync(path, `${JSON.stringify({ contract_version: 1, private_target_base_urls: privateTargetBaseUrls, result_origins_by_base_url: resultOriginsByBaseUrl })}\n`, { mode: 0o600 });
  return path;
}

describe("CPA upstream TypeScript operators", () => {
  it("sanitizes every checked-in synthetic fixture", () => {
    const result = spawnSync(process.execPath, [sanitizer], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /^CPA upstream fixture sanitizer: PASS files=9/m);
  });

  it("generates an atomic private versioned key and never overwrites", () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-source-key-"));
    const path = join(root, "source-identity.key");
    const first = spawnSync(process.execPath, [generator, path], { encoding: "utf8" });
    assert.equal(first.status, 0, first.stderr);
    assert.equal(lstatSync(path).mode & 0o777, 0o600);
    const value = readFileSync(path);
    assert.equal(value.subarray(0, 19).toString("hex"), "4d54432d534f555243452d49442d4b45590001");
    assert.equal(value.length, 51);
    const second = spawnSync(process.execPath, [generator, path], { encoding: "utf8" });
    assert.equal(second.status, 2);
    assert.deepEqual(readFileSync(path), value);
  });

  it("produces a count-only source audit without leaking fixture secrets", () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-cpa-import-"));
    const source = join(root, "source");
    cpSync(join(fixtures, "supported"), source, { recursive: true });
    privateTree(source);
    const key = join(source, "source-identity.key");
    assert.equal(spawnSync(process.execPath, [generator, key]).status, 0);
    const policy = writeTransportPolicy(root, ["https://openai-compatible.example.test/v1"]);
    const result = spawnSync(process.execPath, [importer, "--config", join(source, "config.yaml"), "--auth-dir", join(source, "auth"), "--source-identity-key-file", key, "--transport-policy-file", policy], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    const summary = JSON.parse(result.stdout) as Record<string, unknown>;
    assert.equal(summary.mode, "source-audit");
    assert.equal(summary.api_account_count, 6);
    assert.equal(summary.proxied_api_account_count, 2);
    assert.equal(summary.private_target_api_account_count, 2);
    assert.equal(summary.native_reauthorization_required_count, 2);
    assert.doesNotMatch(result.stdout + result.stderr, /fixture-only-|Fixture(Copilot|Cursor)Handle/);
  });

  it("records Kimi as a source capability gap and rejects every retired target flag", () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-cpa-kimi-capability-gap-"));
    const source = join(root, "source"); cpSync(join(fixtures, "supported"), source, { recursive: true });
    const auth = join(source, "auth");
    writeFileSync(join(auth, "kimi-first.json"), JSON.stringify({ type: "kimi", opaque: "fixture-only-kimi-first" }), { mode: 0o600 });
    writeFileSync(join(auth, "kimi-second.json"), JSON.stringify({ type: "kimi", opaque: "fixture-only-kimi-second", disabled: true }), { mode: 0o600 });
    privateTree(source);
    const key = join(source, "source-identity.key"); assert.equal(spawnSync(process.execPath, [generator, key]).status, 0);
    try {
      const dry = spawnSync(process.execPath, [importer, "--config", join(source, "config.yaml"), "--auth-dir", auth, "--source-identity-key-file", key], { encoding: "utf8" });
      assert.equal(dry.status, 0, dry.stderr);
      const summary = JSON.parse(dry.stdout) as Record<string, unknown>;
      assert.equal(summary.api_account_count, 6);
      assert.equal(summary.managed_oauth_account_count, 0);
      assert.equal(summary.source_capability_gap_count, 2);
      assert.deepEqual(summary.source_capability_gap_source_type_counts, { kimi: 2 });
      const gaps = summary.source_capability_gaps as Array<Record<string, unknown>>;
      assert.equal(gaps.length, 2);
      assert.deepEqual(gaps.map((item) => Object.keys(item).sort()), [["source_disabled", "source_stable_id", "source_type"], ["source_disabled", "source_stable_id", "source_type"]]);
      assert.deepEqual(gaps.map((item) => item.source_type), ["kimi", "kimi"]);
      assert.equal(new Set(gaps.map((item) => item.source_stable_id)).size, 2);
      assert.doesNotMatch(`${dry.stdout}${dry.stderr}`, /fixture-only-kimi|kimi-(?:first|second)\.json/u);

      for (const retired of ["--apply", "--target-api-base-url", "--service-token-file", "--resolve-existing-route-bindings"]) {
        const stopped = spawnSync(process.execPath, [importer, "--config", join(source, "config.yaml"), "--auth-dir", auth, "--source-identity-key-file", key, retired], { encoding: "utf8" });
        assert.equal(stopped.status, 2);
        assert.match(stopped.stderr, /unrecognized argument/u);
      }

      writeFileSync(join(auth, "unknown.json"), JSON.stringify({ type: "unknown-kimi-like", refresh_token: "fixture-only-unknown" }), { mode: 0o600 }); privateTree(source);
      const unknown = spawnSync(process.execPath, [importer, "--config", join(source, "config.yaml"), "--auth-dir", auth, "--source-identity-key-file", key], { encoding: "utf8" });
      assert.equal(unknown.status, 2);
      assert.doesNotMatch(`${unknown.stdout}${unknown.stderr}`, /fixture-only-unknown|unknown-kimi-like/u);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it("validates only the documented opaque created_at metadata field", () => {
    for (const [name, createdAt, extra] of [
      ["invalid-timestamp", "2026-99-09T12:00:00Z", {}],
      ["unknown-field", "2026-09-09T12:00:00Z", { unexpected_metadata: true }],
    ] as const) {
      const root = mkdtempSync(join(tmpdir(), "mtc-cpa-opaque-metadata-"));
      try {
        const source = join(root, "source"); cpSync(join(fixtures, "supported"), source, { recursive: true });
        const authPath = join(source, "auth", "copilot-account.json"), auth = JSON.parse(readFileSync(authPath, "utf8")) as Record<string, unknown>;
        writeFileSync(authPath, JSON.stringify({ ...auth, created_at: createdAt, ...extra }), { mode: 0o600 }); privateTree(source);
        const result = spawnSync(process.execPath, [importer, "--config", join(source, "config.yaml"), "--auth-dir", join(source, "auth")], { encoding: "utf8" });
        assert.equal(result.status, 2, name);
        assert.doesNotMatch(result.stderr, /2026-99-09|unexpected_metadata/);
      } finally { rmSync(root, { recursive: true, force: true }); }
    }
  });

  it("rejects unsafe fixture permissions before parsing secret material", () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-cpa-unsafe-"));
    const source = join(root, "source");
    cpSync(join(fixtures, "supported"), source, { recursive: true });
    privateTree(source);
    chmodSync(join(source, "config.yaml"), 0o644);
    const result = spawnSync(process.execPath, [importer, "--config", join(source, "config.yaml"), "--auth-dir", join(source, "auth")], { encoding: "utf8" });
    assert.equal(result.status, 2);
    assert.match(result.stderr, /owner-only regular file/);
    assert.doesNotMatch(result.stderr, /fixture-only-/);
  });

  it("rejects remote-DNS and public proxy endpoints without echoing them", () => {
    for (const rejectedProxy of ["socks5h://fixture-proxy.internal:1080", "socks5h://8.8.8.8:1080", "socks5://[2001:4860:4860::8888]:1080"]) {
      const root = mkdtempSync(join(tmpdir(), "mtc-cpa-proxy-reject-"));
      const source = join(root, "source");
      cpSync(join(fixtures, "supported"), source, { recursive: true });
      const config = join(source, "config.yaml");
      writeFileSync(config, readFileSync(config, "utf8").replace("socks5://fixture-proxy.internal:1080", rejectedProxy));
      privateTree(source);
      const result = spawnSync(process.execPath, [importer, "--config", config, "--auth-dir", join(source, "auth")], { encoding: "utf8" });
      assert.equal(result.status, 2);
      assert.doesNotMatch(result.stderr, /fixture-proxy|8\.8\.8\.8|2001:4860/);
    }
  });

  it("requires a strict owner-only policy and rejects unmatched or duplicate private targets", () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-cpa-policy-reject-"));
    const source = join(root, "source");
    cpSync(join(fixtures, "supported"), source, { recursive: true });
    privateTree(source);
    const baseArguments = [importer, "--config", join(source, "config.yaml"), "--auth-dir", join(source, "auth")];
    const cases = [
      { contract_version: 1, private_target_base_urls: ["https://absent.example.test", "https://absent.example.test"] },
      { contract_version: 1, private_target_base_urls: ["https://absent.example.test"] },
      { contract_version: 2, private_target_base_urls: [] },
      { contract_version: 1, private_target_base_urls: [], extra: true },
      { contract_version: 1, private_target_base_urls: [], result_origins_by_base_url: { "https://absent.example.test/v1": ["https://assets.example.test"] } },
      { contract_version: 1, private_target_base_urls: [], result_origins_by_base_url: { "https://openai-compatible.example.test/v1": ["https://assets.example.test/path"] } },
    ];
    for (const [index, document] of cases.entries()) {
      const policy = join(root, `rejected-${index}.json`);
      writeFileSync(policy, JSON.stringify(document), { mode: 0o600 });
      const result = spawnSync(process.execPath, [...baseArguments, "--transport-policy-file", policy], { encoding: "utf8" });
      assert.equal(result.status, 2);
      assert.doesNotMatch(result.stderr, /absent\.example\.test/);
    }
    const unsafe = writeTransportPolicy(root, []);
    chmodSync(unsafe, 0o644);
    const result = spawnSync(process.execPath, [...baseArguments, "--transport-policy-file", unsafe], { encoding: "utf8" });
    assert.equal(result.status, 2);
    assert.match(result.stderr, /owner-only regular file/);
    const relative = spawnSync(process.execPath, [...baseArguments, "--transport-policy-file", "transport-policy.json"], { encoding: "utf8" });
    assert.equal(relative.status, 2);
    assert.match(relative.stderr, /path must be absolute/);
  });

  it("permits cleartext only for an explicitly reviewed private target", () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-cpa-private-http-"));
    const source = join(root, "source");
    cpSync(join(fixtures, "supported"), source, { recursive: true });
    const config = join(source, "config.yaml");
    writeFileSync(config, readFileSync(config, "utf8").replace("https://openai-compatible.example.test/v1", "http://10.20.30.40/v1"));
    privateTree(source);
    const key = join(source, "source-identity.key");
    assert.equal(spawnSync(process.execPath, [generator, key]).status, 0);
    const baseArguments = [importer, "--config", config, "--auth-dir", join(source, "auth"), "--source-identity-key-file", key];
    const withoutPolicy = spawnSync(process.execPath, baseArguments, { encoding: "utf8" });
    assert.equal(withoutPolicy.status, 2);
    const policy = writeTransportPolicy(root, ["http://10.20.30.40/v1"]);
    const reviewed = spawnSync(process.execPath, [...baseArguments, "--transport-policy-file", policy], { encoding: "utf8" });
    assert.equal(reviewed.status, 0, reviewed.stderr);
    assert.equal(JSON.parse(reviewed.stdout).private_target_api_account_count, 2);
    assert.doesNotMatch(reviewed.stdout + reviewed.stderr, /10\.20\.30\.40/);
  });

});
