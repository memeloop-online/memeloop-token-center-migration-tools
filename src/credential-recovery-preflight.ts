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
type Reason = "invalid_input" | "source_capture_invalid" | "source_digest_mismatch" | "source_yaml_invalid"
  | "source_keys_shape" | "source_count_mismatch" | "source_key_invalid" | "source_key_duplicate"
  | "self_shape" | "self_identity_shape" | "self_generation_type" | "control_shape"
  | "control_match_count" | "control_identity_mismatch" | "tenant_type" | "tenant_mismatch"
  | "generation_type" | "generation_mismatch" | "status_type" | "status_not_active"
  | "recovery_flag_type" | "duplicate_identity" | "secondpass_identity_changed"
  | "secondpass_generation_changed" | "source_changed" | "http_status" | "response_json"
  | "response_too_large" | "request_failed" | "request_timeout" | "protected_file";
type Stage = "arguments" | "source" | "self" | "control" | "secondpass" | "source_recheck" | "publish";
class PreflightFailure extends Error {
  readonly reason: Reason;
  readonly httpStatus?: number;
  constructor(reason: Reason, httpStatus?: number) {
    super("credential recovery preflight failed");
    this.reason = reason;
    this.httpStatus = httpStatus;
  }
}
function fail(reason: Reason = "invalid_input"): never { throw new PreflightFailure(reason); }
function record(value: unknown, reason: Reason = "invalid_input"): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(reason);
  return value as Record<string, unknown>;
}

/** Source credentials never leave process memory or enter the receipt. */
export function readSourceKeys(sourceRaw: Buffer, captureRaw: Buffer, expectedCount: number): string[] {
  let capture: Record<string, unknown>;
  try { capture = record(parseStrictJson(utf8.decode(captureRaw))); } catch { fail("source_capture_invalid"); }
  if (typeof capture.source_config_sha256 !== "string" || !SHA.test(capture.source_config_sha256)
    || capture.source_config_sha256 !== sha256(sourceRaw)) fail("source_digest_mismatch");
  let values: unknown;
  try {
    const yaml = parseDocument(utf8.decode(sourceRaw), { uniqueKeys: true });
    if (yaml.errors.length || yaml.warnings.length) fail("source_yaml_invalid");
    values = record(yaml.toJS({ maxAliasCount: 0 }))["api-keys"];
  } catch { fail("source_yaml_invalid"); }
  if (!Array.isArray(values)) fail("source_keys_shape");
  if (values.length !== expectedCount || values.length === 0 || values.length > 1000) fail("source_count_mismatch");
  const keys = values.map(value => {
    // Authorization Bearer must preserve the original bytes exactly.
    if (typeof value !== "string" || !/^[!-~]{16,512}$/.test(value)) fail("source_key_invalid");
    return value;
  });
  if (new Set(keys).size !== keys.length) fail("source_key_duplicate");
  return keys;
}

export type VerifiedIdentity = Readonly<{
  source_index: number; key_id: string; credential_generation: number; recovery_available: boolean;
}>;
export function verifyIdentity(selfValue: unknown, controlValue: unknown, tenant: string, sourceIndex: number): VerifiedIdentity {
  const self = record(selfValue, "self_shape");
  if (typeof self.key_id !== "string" || !UUID.test(self.key_id)) fail("self_identity_shape");
  if (!Number.isSafeInteger(self.credential_generation) || Number(self.credential_generation) < 0) fail("self_generation_type");
  if (!Array.isArray(controlValue)) fail("control_shape");
  if (controlValue.length !== 1) fail("control_match_count");
  const control = record(controlValue[0], "control_shape");
  if (control.key_id !== self.key_id) fail("control_identity_mismatch");
  if (typeof control.tenant_external_id !== "string") fail("tenant_type");
  if (control.tenant_external_id !== tenant) fail("tenant_mismatch");
  if (typeof control.status !== "string") fail("status_type");
  if (control.status !== "active") fail("status_not_active");
  if (!Number.isSafeInteger(control.credential_generation) || Number(control.credential_generation) < 0) fail("generation_type");
  if (control.credential_generation !== self.credential_generation) fail("generation_mismatch");
  if (typeof control.credential_recovery_available !== "boolean") fail("recovery_flag_type");
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
    const finish = (reason: Reason | null, value?: unknown, status?: number): void => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (reason) rejectRequest(new PreflightFailure(reason, status));
      else resolveRequest(value);
    };
    const req = (base.protocol === "https:" ? httpsRequest : httpRequest)({
      protocol: base.protocol, hostname: base.hostname, port: base.port, path, method: "GET",
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json", "Cache-Control": "no-store" },
      maxHeaderSize: 32 * 1024,
    }, response => {
      if (response.statusCode !== 200) { finish("http_status", undefined, response.statusCode); response.destroy(); return; }
      let size = 0;
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) { finish("response_too_large"); response.destroy(); }
        else chunks.push(chunk);
      });
      response.on("error", () => finish("request_failed"));
      response.on("aborted", () => finish("request_failed"));
      response.on("end", () => {
        try { finish(null, parseStrictJson(utf8.decode(Buffer.concat(chunks)))); }
        catch { finish("response_json"); }
        finally { for (const chunk of chunks) chunk.fill(0); }
      });
    });
    req.on("error", () => finish("request_failed"));
    timer = setTimeout(() => { finish("request_timeout"); req.destroy(); }, 30_000);
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
  let stage: Stage = "source";
  let sourceCount: number | null = null, controlMatchCount: number | null = null;
  let selfSuccessCount = 0, verifiedCount = 0, secondpassCount = 0;
  let sourceRaw: Buffer | undefined, captureRaw: Buffer | undefined, tokenRaw: Buffer | undefined;
  try {
    sourceRaw = readOwnerOnly(get("--source-config-file"), "approved source config", MAX_SOURCE_BYTES);
    captureRaw = readOwnerOnly(get("--source-receipt-file"), "approved source receipt", MAX_SOURCE_BYTES);
    tokenRaw = readOwnerOnly(get("--service-token-file"), "control read token", 16 * 1024);
    const keys = readSourceKeys(sourceRaw, captureRaw, Number(countText));
    sourceCount = keys.length;
    const token = utf8.decode(tokenRaw).replace(/\r?\n$/, "");
    if (!/^[!-~]{1,8192}$/.test(token)) fail();
    const identities: VerifiedIdentity[] = [];
    for (let index = 0; index < keys.length; index++) {
      stage = "self";
      const self = record(await getJson(gateway, "/self/v1/key", keys[index]!), "self_shape");
      if (typeof self.key_id !== "string" || !UUID.test(self.key_id)) fail("self_identity_shape");
      if (!Number.isSafeInteger(self.credential_generation) || Number(self.credential_generation) < 0) fail("self_generation_type");
      selfSuccessCount++;
      stage = "control";
      const selected = await getJson(control, `/internal/v1/keys?tenant_external_id=${encodeURIComponent(tenant)}&key_id=${self.key_id}&limit=2`, token);
      controlMatchCount = Array.isArray(selected) ? selected.length : null;
      const identity = verifyIdentity(self, selected, tenant, index);
      if (identities.some(prior => prior.key_id === identity.key_id)) fail("duplicate_identity");
      identities.push(identity);
      verifiedCount = identities.length;
    }
    // Reauthenticate after all control checks to fence a rotation during the batch.
    for (const identity of identities) {
      stage = "secondpass";
      const after = record(await getJson(gateway, "/self/v1/key", keys[identity.source_index]!), "self_shape");
      if (after.key_id !== identity.key_id) fail("secondpass_identity_changed");
      if (after.credential_generation !== identity.credential_generation) fail("secondpass_generation_changed");
      secondpassCount++;
    }
    stage = "source_recheck";
    const sourceAfter = readOwnerOnly(get("--source-config-file"), "approved source config", MAX_SOURCE_BYTES);
    try { if (sha256(sourceAfter) !== sha256(sourceRaw)) fail("source_changed"); } finally { sourceAfter.fill(0); }
    const receipt = Buffer.from(`${JSON.stringify({
      version: 1, mode: "credential-recovery-preflight", tenant_external_id: tenant,
      source_config_sha256: sha256(sourceRaw), source_receipt_sha256: sha256(captureRaw),
      verified_count: identities.length, identities,
    })}\n`);
    stage = "publish";
    const output = openSafeOutput(get("--receipt-output"));
    try { writeBindingReceipt(output, receipt); } finally { closeSync(output.parentDescriptor); }
    process.stdout.write(`${JSON.stringify({ mode: "dry-run", source_count: keys.length,
      verified_count: identities.length, recovery_available_count: identities.filter(x => x.recovery_available).length,
      recovery_missing_count: identities.filter(x => !x.recovery_available).length, stored_count: 0 })}\n`);
  } catch (error) {
    const failure = error instanceof PreflightFailure ? error : new PreflightFailure("protected_file");
    const diagnostic = {
      version: 1, mode: "credential-recovery-preflight-failed", stage, reason: failure.reason,
      ...(failure.httpStatus === undefined ? {} : { http_status: failure.httpStatus }),
      expected_source_count: Number(countText), source_count: sourceCount, self_success_count: selfSuccessCount,
      verified_count: verifiedCount, control_match_count: controlMatchCount, secondpass_verified_count: secondpassCount,
      stored_count: 0, eligible_for_apply: false,
    };
    // Failure receipts never contain identities or any partial-success input.
    if (stage !== "publish") {
      const output = openSafeOutput(get("--receipt-output"));
      try { writeBindingReceipt(output, Buffer.from(`${JSON.stringify(diagnostic)}\n`)); }
      finally { closeSync(output.parentDescriptor); }
    }
    process.stderr.write(`${JSON.stringify(diagnostic)}\n`);
    throw failure;
  } finally { sourceRaw?.fill(0); captureRaw?.fill(0); tokenRaw?.fill(0); }
}

if (invokedAsEntrypoint("credential-recovery-preflight", import.meta.url)) {
  runRecoveryPreflight(process.argv.slice(2)).catch(() => {
    process.stderr.write("credential recovery preflight failed; no recovery write attempted\n");
    process.exitCode = 2;
  });
}
