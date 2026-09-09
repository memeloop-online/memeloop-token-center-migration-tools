#!/usr/bin/env node
/**
 * Authenticate approved existing client keys to discover their stable identity.
 * GET-only: no new plaintext mapping, database access, or recovery write.
 */
import { createHash } from "node:crypto";
import { closeSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isAbsolute } from "node:path";
import { parseDocument } from "yaml";
import { parseStrictJson } from "../ops/lib/strict-json.ts";
import { invokedAsEntrypoint } from "../ops/lib/invoked-as-entrypoint.ts";
import { openSafeOutput, readOwnerOnly, writeBindingReceipt } from "../ops/cpa-upstreams/import-cpa-upstreams.ts";

const MAX_SOURCE_BYTES = 4 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 256 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{64}$/;
const sha256 = (raw: Buffer): string => createHash("sha256").update(raw).digest("hex");
const utf8 = new TextDecoder("utf-8", { fatal: true });
class PreflightFailure extends Error {}
function fail(): never { throw new PreflightFailure("credential recovery preflight rejected an input or identity"); }
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  return value as Record<string, unknown>;
}

/** Source credentials never leave process memory or enter the receipt. */
export function readSourceKeys(sourceRaw: Buffer, captureRaw: Buffer, expectedCount: number): string[] {
  const capture = record(parseStrictJson(utf8.decode(captureRaw)));
  if (typeof capture.source_config_sha256 !== "string" || !SHA.test(capture.source_config_sha256)
    || capture.source_config_sha256 !== sha256(sourceRaw)) fail();
  const yaml = parseDocument(utf8.decode(sourceRaw), { uniqueKeys: true });
  if (yaml.errors.length || yaml.warnings.length) fail();
  const values = record(yaml.toJS({ maxAliasCount: 0 }))["api-keys"];
  if (!Array.isArray(values) || values.length !== expectedCount || values.length === 0 || values.length > 1000) fail();
  const keys = values.map(value => {
    // Authorization Bearer must preserve the original bytes exactly.
    if (typeof value !== "string" || !/^[!-~]{16,512}$/.test(value)) fail();
    return value;
  });
  if (new Set(keys).size !== keys.length) fail();
  return keys;
}

export type VerifiedIdentity = Readonly<{
  source_index: number; key_id: string; credential_generation: number; recovery_available: boolean;
}>;
export function verifyIdentity(selfValue: unknown, controlValue: unknown, tenant: string, sourceIndex: number): VerifiedIdentity {
  const self = record(selfValue);
  if (typeof self.key_id !== "string" || !UUID.test(self.key_id)
    || !Number.isSafeInteger(self.credential_generation) || Number(self.credential_generation) < 1) fail();
  if (!Array.isArray(controlValue) || controlValue.length !== 1) fail();
  const control = record(controlValue[0]);
  if (control.key_id !== self.key_id || control.tenant_external_id !== tenant
    || control.status !== "active" || control.credential_generation !== self.credential_generation
    || typeof control.credential_recovery_available !== "boolean") fail();
  return { source_index: sourceIndex, key_id: self.key_id, credential_generation: Number(self.credential_generation),
    recovery_available: control.credential_recovery_available };
}

function baseUrl(value: string, allowLoopback: boolean): URL {
  const url = new URL(value);
  const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname);
  if ((url.protocol !== "https:" && !(url.protocol === "http:" && allowLoopback && loopback))
    || url.username || url.password || url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) fail();
  return url;
}

/** One fixed authenticated GET, no redirects/retries, bounded bytes and deadline. */
function getJson(base: URL, path: string, token: string): Promise<unknown> {
  return new Promise((resolveRequest, rejectRequest) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (error: boolean, value?: unknown): void => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (error) rejectRequest(new PreflightFailure("credential identity request failed"));
      else resolveRequest(value);
    };
    const req = (base.protocol === "https:" ? httpsRequest : httpRequest)({
      protocol: base.protocol, hostname: base.hostname, port: base.port, path, method: "GET",
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json", "Cache-Control": "no-store" },
      maxHeaderSize: 32 * 1024,
    }, response => {
      if (response.statusCode !== 200) { finish(true); response.destroy(); return; }
      let size = 0;
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) { finish(true); response.destroy(); }
        else chunks.push(chunk);
      });
      response.on("error", () => finish(true));
      response.on("aborted", () => finish(true));
      response.on("end", () => {
        try { finish(false, parseStrictJson(utf8.decode(Buffer.concat(chunks)))); }
        catch { finish(true); }
        finally { for (const chunk of chunks) chunk.fill(0); }
      });
    });
    req.on("error", () => finish(true));
    timer = setTimeout(() => { finish(true); req.destroy(); }, 30_000);
    req.end();
  });
}

export async function runRecoveryPreflight(argv: readonly string[]): Promise<void> {
  if (argv.length === 1 && argv[0] === "--help") {
    process.stdout.write("usage: credential-recovery-preflight --source-config-file FILE --source-receipt-file FILE --expected-count N --tenant ID --gateway-api-base-url URL --control-api-base-url URL --service-token-file FILE --receipt-output FILE [--allow-http-loopback]\nGET-only dry-run. Never creates plaintext mappings or writes recovery envelopes.\n");
    return;
  }
  const required = ["--source-config-file", "--source-receipt-file", "--expected-count", "--tenant",
    "--gateway-api-base-url", "--control-api-base-url", "--service-token-file", "--receipt-output"];
  const options = new Map<string, string>();
  let loopback = false;
  for (let i = 0; i < argv.length; i++) {
    const name = argv[i]!;
    if (name === "--allow-http-loopback" && !loopback) { loopback = true; continue; }
    if (!required.includes(name) || options.has(name) || !argv[i + 1] || argv[i + 1]!.startsWith("--")) fail();
    options.set(name, argv[++i]!);
  }
  if (required.some(name => !options.has(name))) fail();
  const get = (name: string): string => options.get(name)!;
  for (const name of ["--source-config-file", "--source-receipt-file", "--service-token-file", "--receipt-output"]) {
    if (!isAbsolute(get(name))) fail();
  }
  const countText = get("--expected-count"), tenant = get("--tenant");
  if (!/^[1-9][0-9]{0,3}$/.test(countText) || Number(countText) > 1000 || !/^[A-Za-z0-9._:-]{1,200}$/.test(tenant)) fail();
  const gateway = baseUrl(get("--gateway-api-base-url"), loopback), control = baseUrl(get("--control-api-base-url"), loopback);
  const sourceRaw = readOwnerOnly(get("--source-config-file"), "approved source config", MAX_SOURCE_BYTES);
  const captureRaw = readOwnerOnly(get("--source-receipt-file"), "approved source receipt", MAX_SOURCE_BYTES);
  const tokenRaw = readOwnerOnly(get("--service-token-file"), "control read token", 16 * 1024);
  try {
    const keys = readSourceKeys(sourceRaw, captureRaw, Number(countText));
    const token = utf8.decode(tokenRaw).replace(/\r?\n$/, "");
    if (!/^[!-~]{1,8192}$/.test(token)) fail();
    const identities: VerifiedIdentity[] = [];
    for (let index = 0; index < keys.length; index++) {
      const self = record(await getJson(gateway, "/self/v1/key", keys[index]!));
      if (typeof self.key_id !== "string" || !UUID.test(self.key_id)) fail();
      const selected = await getJson(control, `/internal/v1/keys?tenant_external_id=${encodeURIComponent(tenant)}&key_id=${self.key_id}&limit=2`, token);
      const identity = verifyIdentity(self, selected, tenant, index);
      if (identities.some(prior => prior.key_id === identity.key_id)) fail();
      identities.push(identity);
    }
    // Reauthenticate after all control checks to fence a rotation during the batch.
    for (const identity of identities) {
      const after = record(await getJson(gateway, "/self/v1/key", keys[identity.source_index]!));
      if (after.key_id !== identity.key_id || after.credential_generation !== identity.credential_generation) fail();
    }
    const sourceAfter = readOwnerOnly(get("--source-config-file"), "approved source config", MAX_SOURCE_BYTES);
    try { if (sha256(sourceAfter) !== sha256(sourceRaw)) fail(); } finally { sourceAfter.fill(0); }
    const receipt = Buffer.from(`${JSON.stringify({
      version: 1, mode: "credential-recovery-preflight", tenant_external_id: tenant,
      source_config_sha256: sha256(sourceRaw), source_receipt_sha256: sha256(captureRaw),
      verified_count: identities.length, identities,
    })}\n`);
    const output = openSafeOutput(get("--receipt-output"));
    try { writeBindingReceipt(output, receipt); } finally { closeSync(output.parentDescriptor); }
    process.stdout.write(`${JSON.stringify({ mode: "dry-run", source_count: keys.length,
      verified_count: identities.length, recovery_available_count: identities.filter(x => x.recovery_available).length,
      recovery_missing_count: identities.filter(x => !x.recovery_available).length, stored_count: 0 })}\n`);
  } finally { sourceRaw.fill(0); captureRaw.fill(0); tokenRaw.fill(0); }
}

if (invokedAsEntrypoint("credential-recovery-preflight", import.meta.url)) {
  runRecoveryPreflight(process.argv.slice(2)).catch(() => {
    process.stderr.write("credential recovery preflight failed; no recovery write attempted\n");
    process.exitCode = 2;
  });
}
