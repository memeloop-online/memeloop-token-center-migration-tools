#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, cpSync, lstatSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile, spawnSync } from "node:child_process";
import { promisify } from "node:util";
import { describe, it } from "node:test";

const repository = resolve(import.meta.dirname, "../..");
const importer = join(repository, "ops/cpa-upstreams/import-cpa-upstreams.ts");
const generator = join(repository, "ops/cpa-upstreams/generate-source-identity-key.ts");
const sanitizer = join(repository, "tests/ops/sanitize-cpa-upstream-fixtures.ts");
const fixtures = join(repository, "tests/fixtures/cpa-upstreams");
const execFileAsync = promisify(execFile);

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

  it("produces a count-only dry-run without leaking fixture secrets", () => {
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
    assert.equal(summary.mode, "dry-run");
    assert.equal(summary.api_account_count, 6);
    assert.equal(summary.proxied_api_account_count, 2);
    assert.equal(summary.private_target_api_account_count, 2);
    assert.equal(summary.native_reauthorization_required_count, 2);
    assert.doesNotMatch(result.stdout + result.stderr, /fixture-only-|Fixture(Copilot|Cursor)Handle/);
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

  it("rejects a private target without a proxy before any target request", async () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-cpa-private-without-proxy-"));
    const source = join(root, "source");
    cpSync(join(fixtures, "supported"), source, { recursive: true });
    const config = join(source, "config.yaml");
    writeFileSync(config, readFileSync(config, "utf8").replace('    proxy-url: "socks5://fixture-proxy.internal:1080"\n', ""));
    privateTree(source);
    const key = join(source, "source-identity.key");
    assert.equal(spawnSync(process.execPath, [generator, key]).status, 0);
    const token = join(root, "service-token");
    writeFileSync(token, "fixture-only-target-service-token\n", { mode: 0o600 });
    const policy = writeTransportPolicy(root, ["https://openai-compatible.example.test/v1"]);
    let requests = 0;
    const server = createServer((_request, response) => { requests += 1; response.statusCode = 500; response.end("{}"); });
    await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
    try {
      const address = server.address(); assert(address && typeof address === "object");
      await assert.rejects(execFileAsync(process.execPath, [importer,
        "--config", config, "--auth-dir", join(source, "auth"), "--source-identity-key-file", key,
        "--transport-policy-file", policy, "--apply", "--allow-http-loopback",
        "--target-api-base-url", `http://127.0.0.1:${address.port}`, "--service-token-file", token,
      ], { timeout: 20_000 }), /private target requires an approved private SOCKS5 proxy/);
      assert.equal(requests, 0);
    } finally { await new Promise<void>((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose())); }
  });

  it("preflights every direct conflict before any managed OAuth write", async () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-cpa-preflight-"));
    const source = join(root, "source");
    cpSync(join(fixtures, "supported"), source, { recursive: true });
    copyFileSync(join(fixtures, "oauth-blocked/auth/codex-account.json"), join(source, "auth/managed-codex.json"));
    privateTree(source);
    const key = join(source, "source-identity.key");
    assert.equal(spawnSync(process.execPath, [generator, key]).status, 0);
    const token = join(root, "service-token");
    writeFileSync(token, "fixture-only-target-service-token\n", { mode: 0o600 });
    let managedWrites = 0;
    const stableSource = ["cpa-upstream-import-v1", "config", "openai-compatibility", "fixture-openai-compatible", "0"].join("\0");
    const stableName = `cpa-fixture-openai-compatible-${createHash("sha256").update(stableSource).digest("hex").slice(0, 16)}`;
    const server = createServer((request, response) => {
      response.setHeader("content-type", "application/json");
      if (request.url === "/internal/v1/imports/cpa/managed-oauth/capabilities") response.end(JSON.stringify({ contract_version: 1, source_types: ["codex"] }));
      else if (request.url === "/internal/v1/provider-types") response.end(JSON.stringify([{ id: "http-json" }]));
      else if (request.url?.startsWith("/internal/v1/upstreams?")) response.end(JSON.stringify([{ id: "10000000-0000-4000-8000-000000000001", tenant_external_id: "default", name: stableName, driver: "http-json", config: { base_url: "https://conflict.example.test", network_scope: "public" }, status: "active", updated_at: 1 }]));
      else if (request.url === "/internal/v1/imports/cpa/managed-oauth") { managedWrites += 1; response.statusCode = 201; response.end("{}"); }
      else { response.statusCode = 404; response.end("{}"); }
    });
    await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
    try {
      const address = server.address(); assert(address && typeof address === "object");
      await assert.rejects(execFileAsync(process.execPath, [importer,
        "--config", join(source, "config.yaml"), "--auth-dir", join(source, "auth"),
        "--source-identity-key-file", key, "--apply", "--allow-http-loopback",
        "--target-api-base-url", `http://127.0.0.1:${address.port}`, "--service-token-file", token,
      ], { timeout: 20_000 }), /target account conflicts with a stable CPA source identity/);
      assert.equal(managedWrites, 0);
    } finally { await new Promise<void>((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose())); }
  });

  it("applies and replays stable direct accounts without leaking credentials", async () => {
    const root = mkdtempSync(join(tmpdir(), "mtc-cpa-apply-"));
    const source = join(root, "source"); cpSync(join(fixtures, "supported"), source, { recursive: true });
    const config = join(source, "config.yaml");
    writeFileSync(config, readFileSync(config, "utf8").replaceAll("socks5://fixture-proxy.internal:1080", "socks5h://100.64.0.16:1080"));
    privateTree(source);
    const key = join(source, "source-identity.key"); assert.equal(spawnSync(process.execPath, [generator, key]).status, 0);
    const token = join(root, "service-token"); writeFileSync(token, "fixture-only-target-service-token\n", { mode: 0o600 });
    const policy = writeTransportPolicy(root, ["https://openai-compatible.example.test/v1"], {
      "https://openai-compatible.example.test/v1": ["https://assets.example.test"],
    });
    const accounts = new Map<string, Record<string, unknown>>(); const credentials: Record<string, unknown>[] = []; let rotations = 0;
    const server = createServer(async (request, response) => {
      const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(Buffer.from(chunk));
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown> : undefined;
      response.setHeader("content-type", "application/json");
      if (request.headers.authorization !== "Bearer fixture-only-target-service-token") { response.statusCode = 403; response.end("{}"); return; }
      if (request.method === "GET" && request.url === "/internal/v1/provider-types") response.end(JSON.stringify([{ id: "http-json" }]));
      else if (request.method === "GET" && request.url?.startsWith("/internal/v1/upstreams?")) response.end(JSON.stringify([...accounts.values()]));
      else if (request.method === "POST" && request.url === "/internal/v1/upstreams") {
        credentials.push(body?.credential as Record<string, unknown>);
        const name = String(body?.name); const account = { id: `10000000-0000-4000-8000-${String(accounts.size + 1).padStart(12, "0")}`, tenant_external_id: body?.tenant_external_id, name, driver: body?.driver, config: body?.config, status: "active", updated_at: 1 };
        accounts.set(name, account); response.statusCode = 201; response.end(JSON.stringify(account));
      } else if (request.method === "PUT" && request.url?.endsWith("/credential")) {
        rotations += 1; credentials.push(body?.credential as Record<string, unknown>); const id = request.url.split("/")[4]; const account = [...accounts.values()].find((item) => item.id === id); response.end(JSON.stringify(account));
      } else { response.statusCode = 404; response.end("{}"); }
    });
    await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
    try {
      const address = server.address(); assert(address && typeof address === "object");
      const arguments_ = [importer, "--config", join(source, "config.yaml"), "--auth-dir", join(source, "auth"), "--source-identity-key-file", key, "--transport-policy-file", policy, "--apply", "--allow-http-loopback", "--target-api-base-url", `http://127.0.0.1:${address.port}`, "--service-token-file", token];
      const firstRun = await execFileAsync(process.execPath, arguments_, { timeout: 20_000 });
      const secondRun = await execFileAsync(process.execPath, arguments_, { timeout: 20_000 });
      const firstSummary = JSON.parse(firstRun.stdout) as Record<string, unknown>, secondSummary = JSON.parse(secondRun.stdout) as Record<string, unknown>;
      assert.equal(firstSummary.created_count, 6); assert.equal(firstSummary.replayed_count, 0);
      assert.equal(secondSummary.created_count, 0); assert.equal(secondSummary.replayed_count, 6);
      assert.equal(accounts.size, 6); assert.equal(rotations, 12);
      assert.equal([...accounts.values()].filter((account) => (account.config as Record<string, unknown>).network_scope === "private").length, 2);
      assert.equal([...accounts.values()].filter((account) => (account.config as Record<string, unknown>).network_scope === "public").length, 4);
      assert.equal([...accounts.values()].filter((account) => Array.isArray((account.config as Record<string, unknown>).result_origins)).length, 2);
      await assert.rejects(
        execFileAsync(process.execPath, arguments_.filter((value, index, values) => value !== "--transport-policy-file" && values[index - 1] !== "--transport-policy-file"), { timeout: 20_000 }),
        /target account conflicts with a stable CPA source identity/,
      );
      assert.equal(accounts.size, 6);
      assert.equal(rotations, 12);
      const proxied = credentials.filter((credential) => credential.type === "api_key_proxy");
      assert.equal(proxied.length, 6);
      for (const credential of proxied) {
        assert.equal(credential.proxy_url, "socks5h://100.64.0.16:1080");
        assert.equal(credential.proxy_network_scope, "private");
      }
      assert.doesNotMatch(firstRun.stdout + firstRun.stderr + secondRun.stdout + secondRun.stderr, /fixture-only-/);
    } finally { await new Promise<void>((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose())); }
  });
});
