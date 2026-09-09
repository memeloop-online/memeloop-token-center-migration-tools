#!/usr/bin/env node
/** Reviewed source-bound recovery only; never rotates keys or modifies grants. */
import { createHash, timingSafeEqual } from "node:crypto";
import { closeSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isAbsolute } from "node:path";
import { readSourceKeys, verifyIdentity, type VerifiedIdentity } from "./credential-recovery-preflight.ts";
import { readOwnerOnly, openSafeOutput, writeBindingReceipt } from "../ops/cpa-upstreams/import-cpa-upstreams.ts";
import { parseStrictJson } from "../ops/lib/strict-json.ts";
import { invokedAsEntrypoint } from "../ops/lib/invoked-as-entrypoint.ts";

const utf8 = new TextDecoder("utf-8", { fatal: true });
const hash = (raw: Buffer): string => createHash("sha256").update(raw).digest("hex");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
type Reason = "invalid_input" | "protected_input" | "approval_mismatch" | "identity_changed" | "recovery_state"
  | "http_status" | "request_failed" | "deadline" | "response_shape" | "copy_mismatch" | "source_changed" | "output_failed";
class SafeFailure extends Error {
  readonly reason: Reason;
  constructor(reason: Reason) { super("source credential recovery failed"); this.reason = reason; }
}
function fail(reason: Reason): never { throw new SafeFailure(reason); }
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("response_shape");
  return value as Record<string, unknown>;
}
function base(value: string, loopback: boolean): URL {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash || url.pathname !== "/"
    || !(url.protocol === "https:" || (loopback && url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))) fail("invalid_input");
  return url;
}

/** One request only. Raw server errors, auth headers and body bytes are never diagnostics. */
function request(baseUrl: URL, path: string, token: string, deadline: number, method: "GET" | "PUT" | "POST" = "GET", key?: string): Promise<unknown> {
  if (Date.now() >= deadline) fail("deadline");
  const body = key === undefined ? undefined : Buffer.from(JSON.stringify({ key }));
  return new Promise((resolve, reject) => {
    let done = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const chunks: Buffer[] = [];
    let size = 0;
    const finish = (reason?: Reason, value?: unknown) => {
      if (done) return;
      done = true; clearTimeout(timer); body?.fill(0);
      for (const chunk of chunks) chunk.fill(0);
      if (reason) reject(new SafeFailure(reason)); else resolve(value);
    };
    const req = (baseUrl.protocol === "https:" ? httpsRequest : httpRequest)({
      protocol: baseUrl.protocol, hostname: baseUrl.hostname, port: baseUrl.port, path, method,
      maxHeaderSize: 32 * 1024,
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json", "Cache-Control": "no-store",
        ...(body ? { "Content-Type": "application/json", "Content-Length": body.length } : {}) },
    }, response => {
      if (response.statusCode !== (method === "PUT" ? 204 : 200)) {
        finish("http_status"); response.destroy(); return;
      }
      response.on("data", (chunk: Buffer) => {
        if (done) { chunk.fill(0); return; }
        size += chunk.length;
        if (size > 256 * 1024) { chunk.fill(0); finish("response_shape"); response.destroy(); }
        else chunks.push(chunk);
      });
      response.on("error", () => finish("request_failed"));
      response.on("aborted", () => finish("request_failed"));
      response.on("end", () => {
        if (done) return;
        if (method === "PUT") { finish(size ? "response_shape" : undefined); return; }
        const raw = Buffer.concat(chunks);
        try { finish(undefined, parseStrictJson(utf8.decode(raw))); }
        catch { finish("response_shape"); }
        finally { raw.fill(0); }
      });
    });
    req.on("error", () => finish("request_failed"));
    timer = setTimeout(() => { finish("deadline"); req.destroy(); }, Math.min(30_000, deadline - Date.now()));
    req.end(body);
  });
}

export function approvedIdentities(raw: Buffer, source: Buffer, capture: Buffer, tenant: string): VerifiedIdentity[] {
  const approval = record(parseStrictJson(utf8.decode(raw)));
  if (approval.version !== 1 || approval.mode !== "credential-recovery-preflight"
    || approval.tenant_external_id !== tenant || approval.source_config_sha256 !== hash(source)
    || approval.source_receipt_sha256 !== hash(capture) || approval.verified_count !== 10
    || !Array.isArray(approval.identities) || approval.identities.length !== 10) fail("approval_mismatch");
  const identities = approval.identities.map((value, index) => {
    const identity = record(value);
    if (identity.source_index !== index || typeof identity.key_id !== "string" || !UUID.test(identity.key_id)
      || !Number.isSafeInteger(identity.credential_generation) || Number(identity.credential_generation) < 0
      || identity.recovery_available !== false) fail("approval_mismatch");
    return { source_index: index, key_id: identity.key_id, credential_generation: Number(identity.credential_generation), recovery_available: false };
  });
  if (new Set(identities.map(identity => identity.key_id)).size !== 10) fail("approval_mismatch");
  return identities;
}

export async function runSourceRecovery(argv: readonly string[]): Promise<void> {
  if (argv.length === 1 && argv[0] === "--help") {
    process.stdout.write("usage: source-credential-recovery-apply --source-config-file FILE --source-receipt-file FILE --approved-identity-receipt-file FILE --expected-count 10 --tenant ID --gateway-api-base-url URL --control-api-base-url URL --service-token-file FILE --receipt-output FILE [--apply | --verify-only] [--allow-http-loopback]\nDefault dry-run performs only GET checks. Apply performs fixed recovery PUTs and two verified copy reads. Verify-only never issues PUT.\n");
    return;
  }
  let stage = "arguments", mode = "dry-run", verifiedCount = 0, storedCount = 0, attemptedCount = 0, copyVerifiedCount = 0;
  let receiptPath: string | undefined;
  const protectedBuffers: Buffer[] = [];
  let output: ReturnType<typeof openSafeOutput> | undefined;
  try {
    const names = ["--source-config-file", "--source-receipt-file", "--approved-identity-receipt-file",
      "--expected-count", "--tenant", "--gateway-api-base-url", "--control-api-base-url", "--service-token-file", "--receipt-output"];
    const options = new Map<string, string>();
    let loopback = false;
    for (let i = 0; i < argv.length; i++) {
      const name = argv[i]!;
      if (name === "--allow-http-loopback" && !loopback) { loopback = true; continue; }
      if ((name === "--apply" || name === "--verify-only") && mode === "dry-run") { mode = name.slice(2); continue; }
      if (!names.includes(name) || options.has(name) || !argv[i + 1] || argv[i + 1]!.startsWith("--")) fail("invalid_input");
      options.set(name, argv[++i]!);
    }
    if (names.some(name => !options.has(name)) || options.get("--expected-count") !== "10") fail("invalid_input");
    const get = (name: string): string => options.get(name)!;
    for (const name of names.filter(name => name.endsWith("-file") || name === "--receipt-output")) if (!isAbsolute(get(name))) fail("invalid_input");
    const tenant = get("--tenant");
    if (!/^[A-Za-z0-9._:-]{1,200}$/.test(tenant)) fail("invalid_input");
    const gateway = base(get("--gateway-api-base-url"), loopback), control = base(get("--control-api-base-url"), loopback);
    receiptPath = get("--receipt-output");
    if (names.filter(name => name.endsWith("-file")).some(name => get(name) === receiptPath)) fail("invalid_input");
    // Check the output destination before any network or recovery side effect.
    output = openSafeOutput(receiptPath);
    stage = "protected_inputs";
    const read = (name: string, limit = 4 * 1024 * 1024) => {
      const raw = readOwnerOnly(get(name), "protected recovery input", limit);
      protectedBuffers.push(raw); return raw;
    };
    const source = read("--source-config-file"), capture = read("--source-receipt-file");
    const approval = read("--approved-identity-receipt-file"), tokenRaw = read("--service-token-file", 16 * 1024);
    const keys = readSourceKeys(source, capture, 10);
    const token = utf8.decode(tokenRaw).replace(/\r?\n$/, "");
    if (!/^[!-~]{1,8192}$/.test(token)) fail("invalid_input");
    const identities = approvedIdentities(approval, source, capture, tenant);
    const deadline = Date.now() + 15 * 60_000;
    const check = async (identity: VerifiedIdentity, recoveryAvailable: boolean): Promise<void> => {
      const self = record(await request(gateway, "/self/v1/key", keys[identity.source_index]!, deadline));
      // Approved UUID only: never interpolate an untrusted response into a path.
      const selected = await request(control, `/internal/v1/keys?tenant_external_id=${encodeURIComponent(tenant)}&key_id=${identity.key_id}&limit=2`, token, deadline);
      let actual: VerifiedIdentity;
      try { actual = verifyIdentity(self, selected, tenant, identity.source_index); } catch { fail("identity_changed"); }
      if (actual.key_id !== identity.key_id || actual.credential_generation !== identity.credential_generation) fail("identity_changed");
      if (actual.recovery_available !== recoveryAvailable) fail("recovery_state");
    };
    const recheckSources = () => {
      for (const [name, original] of [["--source-config-file", source], ["--source-receipt-file", capture], ["--approved-identity-receipt-file", approval], ["--service-token-file", tokenRaw]] as const) {
        const fresh = readOwnerOnly(get(name), "protected recovery input", 4 * 1024 * 1024);
        try { if (hash(fresh) !== hash(original)) fail("source_changed"); } finally { fresh.fill(0); }
      }
    };
    for (let pass = 0; pass < 2; pass++) {
      stage = pass === 0 ? "batch_identity" : "batch_secondpass";
      for (const identity of identities) { await check(identity, mode === "verify-only"); verifiedCount++; }
    }
    recheckSources();
    if (mode !== "dry-run") {
      for (const identity of identities) {
        stage = "immediate_identity"; await check(identity, mode === "verify-only");
        recheckSources();
        const path = `/internal/v1/keys/${identity.key_id}/credential-recovery`;
        if (mode === "apply") {
          stage = "recovery_put"; attemptedCount++;
          await request(control, path, token, deadline, "PUT", keys[identity.source_index]!);
          storedCount++;
        }
        stage = "postwrite_identity"; await check(identity, true);
        for (let copy = 0; copy < 2; copy++) {
          stage = "copy_verification";
          const recovered = record(await request(control, `${path}/copy`, token, deadline, "POST"));
          if (recovered.key_id !== identity.key_id || recovered.credential_generation !== identity.credential_generation
            || typeof recovered.key !== "string") fail("copy_mismatch");
          const actual = Buffer.from(recovered.key), expected = Buffer.from(keys[identity.source_index]!);
          recovered.key = undefined;
          try { if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) fail("copy_mismatch"); }
          finally { actual.fill(0); expected.fill(0); }
        }
        await check(identity, true);
        copyVerifiedCount++;
        process.stdout.write(`${JSON.stringify({ mode, stored_count: storedCount, copy_verified_count: copyVerifiedCount })}\n`);
      }
      stage = "final_identity";
      for (const identity of identities) await check(identity, true);
    }
    recheckSources();
    stage = "publish";
    const receipt = { version: 1, mode, success: true, source_count: 10, verified_check_count: verifiedCount,
      stored_count: storedCount, copy_verified_count: copyVerifiedCount, source_config_sha256: hash(source),
      source_receipt_sha256: hash(capture), approval_sha256: hash(approval) };
    writeBindingReceipt(output, Buffer.from(`${JSON.stringify(receipt)}\n`));
    process.stdout.write(`${JSON.stringify({ mode, success: true, source_count: 10, stored_count: storedCount, copy_verified_count: copyVerifiedCount })}\n`);
  } catch (error) {
    const reason = error instanceof SafeFailure ? error.reason : stage === "publish" ? "output_failed" : stage === "arguments" ? "invalid_input" : "protected_input";
    const diagnostic = { version: 1, mode, success: false, stage, reason, verified_check_count: verifiedCount,
      stored_count: storedCount, attempted_count: attemptedCount, write_outcome_uncertain: attemptedCount > storedCount, copy_verified_count: copyVerifiedCount };
    if (output && stage !== "publish") { try { writeBindingReceipt(output, Buffer.from(`${JSON.stringify(diagnostic)}\n`)); } catch { /* stderr remains count-only */ } }
    process.stderr.write(`${JSON.stringify(diagnostic)}\n`);
    throw new SafeFailure(reason);
  } finally {
    for (const raw of protectedBuffers) raw.fill(0);
    if (output) closeSync(output.parentDescriptor);
  }
}

if (invokedAsEntrypoint("source-credential-recovery-apply", import.meta.url)) {
  runSourceRecovery(process.argv.slice(2)).catch(() => { process.exitCode = 2; });
}
