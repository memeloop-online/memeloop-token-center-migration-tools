#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const repository = resolve(import.meta.dirname, "../..");
const command = join(repository, "src/credential-recovery-backfill.ts");
const { CredentialRecoveryBackfillError, parseIdentityToOriginalKeyMapping } = await import("../../src/credential-recovery-backfill.ts");

const firstIdentity = "10000000-0000-4000-8000-000000000001";
const secondIdentity = "20000000-0000-4000-8000-000000000002";
const firstKey = "fixture-only-original-key-00000001";
const secondKey = "fixture-only-original-key-00000002";
const adminToken = "fixture-only-admin-token-00000001";

function protectedFile(directory: string, name: string, contents: string): string {
  const path = join(directory, name);
  writeFileSync(path, contents, { encoding: "utf8", mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

function mappingDocument(): string {
  return JSON.stringify({
    format_version: 1,
    identity_to_original_key: {
      [secondIdentity]: secondKey,
      [firstIdentity]: firstKey,
    },
  });
}

async function runCommand(args: readonly string[]): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return await new Promise((resolveRun, rejectRun) => {
    const child = spawn(process.execPath, [command, ...args], { cwd: repository, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => { stdout += chunk; });
    child.stderr.on("data", (chunk: string) => { stderr += chunk; });
    child.on("error", rejectRun);
    child.on("close", (status) => resolveRun({ status, stdout, stderr }));
  });
}

async function requestBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

test("identity mapping is explicit, exact, bounded, and does not accept source-system fields", () => {
  const mappings = parseIdentityToOriginalKeyMapping(Buffer.from(mappingDocument()));
  assert.deepEqual(mappings, [
    { identity: firstIdentity, originalKey: firstKey },
    { identity: secondIdentity, originalKey: secondKey },
  ]);
  for (const invalid of [
    '{"format_version":1,"identity_to_original_key":{},"model":"anything"}',
    `{"format_version":1,"identity_to_original_key":{"${firstIdentity}":"${firstKey}"},"identity_to_original_key":{}}`,
    '{"format_version":1,"identity_to_original_key":{"not-a-target-identity":"fixture-only-original-key-00000001"}}',
    `{"format_version":1,"identity_to_original_key":{"${firstIdentity}":"short"}}`,
  ]) assert.throws(() => parseIdentityToOriginalKeyMapping(Buffer.from(invalid)), CredentialRecoveryBackfillError);
});

test("dry-run reads only a protected explicit mapping and prints count-only output", () => {
  const directory = mkdtempSync(join(tmpdir(), "mtc-credential-recovery-dry-run-"));
  const mapping = protectedFile(directory, "mapping.json", mappingDocument());
  const result = spawnSync(process.execPath, [command, "--mapping-file", mapping], { cwd: repository, encoding: "utf8", timeout: 10_000 });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { mode: "dry-run", mapping_count: 2, stored_count: 0 });
  for (const forbidden of [firstIdentity, secondIdentity, firstKey, secondKey, adminToken]) assert.doesNotMatch(result.stdout + result.stderr, new RegExp(forbidden));
});

test("apply uses only the fixed encrypted-recovery PUT endpoint and a protected admin token", async () => {
  const directory = mkdtempSync(join(tmpdir(), "mtc-credential-recovery-apply-"));
  const mapping = protectedFile(directory, "mapping.json", mappingDocument());
  const token = protectedFile(directory, "admin.token", `${adminToken}\n`);
  const requests: Array<{ method: string | undefined; url: string | undefined; authorization: string | undefined; body: string }> = [];
  const server = createServer(async (request, response) => {
    requests.push({
      method: request.method,
      url: request.url,
      authorization: request.headers.authorization,
      body: await requestBody(request),
    });
    response.statusCode = 204;
    response.end();
  });
  await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  try {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const result = await runCommand([
      "--mapping-file", mapping,
      "--apply",
      "--target-api-base-url", `http://127.0.0.1:${address.port}/private-control`,
      "--admin-token-file", token,
      "--allow-http-target",
    ]);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { mode: "apply", mapping_count: 2, stored_count: 2 });
    assert.deepEqual(requests, [
      {
        method: "PUT",
        url: `/private-control/internal/v1/keys/${firstIdentity}/credential-recovery`,
        authorization: `Bearer ${adminToken}`,
        body: JSON.stringify({ key: firstKey }),
      },
      {
        method: "PUT",
        url: `/private-control/internal/v1/keys/${secondIdentity}/credential-recovery`,
        authorization: `Bearer ${adminToken}`,
        body: JSON.stringify({ key: secondKey }),
      },
    ]);
    for (const forbidden of [firstIdentity, secondIdentity, firstKey, secondKey, adminToken]) assert.doesNotMatch(result.stdout + result.stderr, new RegExp(forbidden));
  } finally {
    await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
  }
});

test("retryable failures are bounded, stop the batch, and never echo mapping or token material", async () => {
  const directory = mkdtempSync(join(tmpdir(), "mtc-credential-recovery-failure-"));
  const mapping = protectedFile(directory, "mapping.json", mappingDocument());
  const token = protectedFile(directory, "admin.token", `${adminToken}\n`);
  let requests = 0;
  const server = createServer(async (request, response) => {
    await requestBody(request);
    requests += 1;
    response.statusCode = 503;
    response.end("ignored target response");
  });
  await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  try {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const result = await runCommand([
      "--mapping-file", mapping,
      "--apply",
      "--target-api-base-url", `http://127.0.0.1:${address.port}`,
      "--admin-token-file", token,
      "--allow-http-target",
    ]);
    assert.equal(result.status, 2);
    assert.equal(requests, 2);
    assert.equal(result.stdout, "");
    for (const forbidden of [firstIdentity, secondIdentity, firstKey, secondKey, adminToken]) assert.doesNotMatch(result.stdout + result.stderr, new RegExp(forbidden));
  } finally {
    await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
  }
});

test("apply rejects a non-private admin token before it can contact the target", () => {
  const directory = mkdtempSync(join(tmpdir(), "mtc-credential-recovery-permissions-"));
  const mapping = protectedFile(directory, "mapping.json", mappingDocument());
  const token = protectedFile(directory, "admin.token", `${adminToken}\n`);
  chmodSync(token, 0o644);
  const result = spawnSync(process.execPath, [
    command,
    "--mapping-file", mapping,
    "--apply",
    "--target-api-base-url", "https://control.example.test",
    "--admin-token-file", token,
  ], { cwd: repository, encoding: "utf8", timeout: 10_000 });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /unsafe access permissions/);
  for (const forbidden of [firstIdentity, secondIdentity, firstKey, secondKey, adminToken]) assert.doesNotMatch(result.stdout + result.stderr, new RegExp(forbidden));
});

test("a rejected mapping stops without draining an unfinished response or retrying", { timeout: 10_000 }, async () => {
  const directory = mkdtempSync(join(tmpdir(), "mtc-credential-recovery-rejected-"));
  const mapping = protectedFile(directory, "mapping.json", mappingDocument());
  const token = protectedFile(directory, "admin.token", adminToken);
  let requests = 0;
  const server = createServer(async (request, response) => {
    await requestBody(request);
    requests += 1;
    assert.equal(request.url, `/internal/v1/keys/${firstIdentity}/credential-recovery`);
    response.writeHead(403);
    response.write("fixture-only-sensitive-target-error");
    // Intentionally never finish: the client must destroy this response.
  });
  await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  try {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const result = await runCommand([
      "--mapping-file", mapping,
      "--apply",
      "--target-api-base-url", `http://127.0.0.1:${address.port}`,
      "--admin-token-file", token,
      "--allow-http-target",
    ]);
    assert.equal(result.status, 2);
    assert.equal(requests, 1);
    assert.equal(result.stdout, "");
    assert.doesNotMatch(result.stderr, /fixture-only-sensitive-target-error/);
    for (const forbidden of [firstIdentity, secondIdentity, firstKey, secondKey, adminToken]) {
      assert.doesNotMatch(result.stdout + result.stderr, new RegExp(forbidden));
    }
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
  }
});
