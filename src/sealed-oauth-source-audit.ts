#!/usr/bin/env node
/** Inspect one reviewed, sealed managed-OAuth cohort without network access. */
import { createHash, createHmac } from "node:crypto";
import { closeSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import {
  authFiles,
  canonicalJson,
  invokedAsEntrypoint,
  openSafeOutput,
  parseStrictJson,
  readOwnerOnly,
  readSourceIdentityKey,
  writeBindingReceipt,
} from "./lib/sealed-source-io.ts";

type JsonObject = Record<string, unknown>;
type KimiDocument = JsonObject & {
  type: "kimi";
  access_token: string;
  refresh_token: string;
  token_type: string;
  timestamp?: number;
  disabled?: boolean;
};
type KimiRecord = {
  relativePath: string;
  documentSha256: string;
  sourceStableId: string;
  assertedIdentityHmacSha256: string;
  expiresAt: string;
};
type SourceCohort = { summary: JsonObject; records: KimiRecord[] };
type SourceExpectation = {
  captureMode: string;
  policyFile: string;
  sourceType: "kimi";
  accountCount: number;
  policyCount: number;
  grantCount: number;
  providerModelPolicyCounts: ReadonlyMap<string, number>;
  sha256: string;
};

const MAX_CAPTURE_FILE_BYTES = 8 * 1024 * 1024;
const MAX_AUTH_BYTES = 1024 * 1024;
const MAX_RECEIPT_BYTES = 4 * 1024 * 1024;
const MAX_EXPECTATION_BYTES = 1024 * 1024;
const MAX_EXPECTED_ITEMS = 10_000;
const MAX_SOURCE_PATH_BYTES = 512;
const MINIMUM_SOURCE_ACTIVE_MS = 10 * 60 * 1_000;
const SOURCE_ACCOUNT_DOMAIN = "sealed-managed-oauth-source-account\0v1\0";
const ASSERTED_IDENTITY_DOMAIN = "sealed-managed-oauth-asserted-identity\0v1\0";
const SOURCE_KEY_HASH = /^(?:sha256:)?[0-9a-f]{64}$/iu;
const UTF8 = new TextDecoder("utf-8", { fatal: true });

export class SealedOAuthSourceAuditFailure extends Error {
  readonly outcome: "failed" | "uncertain";
  constructor(outcome: "failed" | "uncertain" = "failed") {
    super("sealed managed-OAuth source audit failed");
    this.outcome = outcome;
  }
}

function fail(): never { throw new SealedOAuthSourceAuditFailure(); }
function sha256(value: string | Buffer): string { return createHash("sha256").update(value).digest("hex"); }
function object(value: unknown): JsonObject {
  if (value === null || Array.isArray(value) || typeof value !== "object") fail();
  return value as JsonObject;
}
function strictJson(raw: Buffer): JsonObject {
  try { return object(parseStrictJson(UTF8.decode(raw))); }
  catch { fail(); }
}
function controlledText(value: unknown, maximum = 2_048, allowEmpty = true): string {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0)
    || Buffer.byteLength(value) > maximum || /[\0\r\n]/u.test(value)) fail();
  return value;
}
function secret(value: unknown): string {
  const result = controlledText(value, 16 * 1024, false);
  if (/\s/u.test(result)) fail();
  return result;
}
function hmac(key: Buffer, domain: string, value: string): string {
  return createHmac("sha256", key).update(domain).update(value).digest("hex");
}
function jwtPayload(token: string): JsonObject {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/u.test(part))) fail();
  try {
    const raw = Buffer.from(parts[1]!, "base64url");
    if (raw.length === 0 || raw.length > 64 * 1024) fail();
    try { return object(parseStrictJson(UTF8.decode(raw))); }
    finally { raw.fill(0); }
  } catch { fail(); }
}
function timestamp(value: unknown): void {
  if (value === undefined) return;
  if (!Number.isSafeInteger(value) || Number(value) < 0) fail();
}
function optionalRfc3339(value: unknown): void {
  if (value === undefined || value === null || value === "") return;
  const text = controlledText(value, 2_048, false);
  if (!/^\d{4}-\d\d-\d\dT.+(?:Z|[+-]\d\d:\d\d)$/u.test(text) || !Number.isFinite(Date.parse(text))) fail();
}

function expectedInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > MAX_EXPECTED_ITEMS) fail();
  return Number(value);
}

function sourceExpectation(raw: Buffer): SourceExpectation {
  const value = strictJson(raw);
  const keys = Object.keys(value).sort();
  if (keys.join("\0") !== [
    "capture_mode",
    "provider_model_policy_counts",
    "source_policy_file",
    "source_account_count",
    "source_grant_count",
    "source_policy_count",
    "source_type",
    "version",
  ].sort().join("\0") || value.version !== 1 || value.source_type !== "kimi") fail();
  const modelCounts = object(value.provider_model_policy_counts);
  const entries = Object.entries(modelCounts);
  if (entries.length < 1 || entries.length > MAX_EXPECTED_ITEMS) fail();
  const providerModelPolicyCounts = new Map<string, number>();
  for (const [model, count] of entries) {
    const normalized = controlledText(model, 500, false);
    if (providerModelPolicyCounts.has(normalized)) fail();
    providerModelPolicyCounts.set(normalized, expectedInteger(count));
  }
  return {
    captureMode: controlledText(value.capture_mode, 200, false),
    policyFile: controlledText(value.source_policy_file, 500, false),
    sourceType: "kimi",
    accountCount: expectedInteger(value.source_account_count),
    policyCount: expectedInteger(value.source_policy_count),
    grantCount: expectedInteger(value.source_grant_count),
    providerModelPolicyCounts,
    sha256: sha256(raw),
  };
}

export function validateKimiDocument(value: unknown, identityKey: Buffer, now = Date.now()): {
  assertedIdentityHmacSha256: string;
  expiresAt: string;
} {
  const document = object(value) as KimiDocument;
  const allowed = new Set([
    "type", "access_token", "refresh_token", "token_type", "scope", "device_id",
    "expired", "last_refresh", "disabled", "proxy_url", "timestamp",
  ]);
  if (Object.keys(document).some((key) => !allowed.has(key)) || document.type !== "kimi"
    || controlledText(document.token_type, 64, false).toLowerCase() !== "bearer"
    || (document.disabled !== undefined && typeof document.disabled !== "boolean")) fail();
  const accessToken = secret(document.access_token);
  secret(document.refresh_token);
  if (document.disabled === true) fail();
  if (document.scope !== undefined && document.scope !== null) controlledText(document.scope);
  const documentDevice = controlledText(document.device_id, 2_048, false);
  optionalRfc3339(document.expired);
  optionalRfc3339(document.last_refresh);
  timestamp(document.timestamp);
  // A proxied cohort needs a separately reviewed transport contract. Never
  // silently drop, expose, or reinterpret a source proxy URL.
  if (document.proxy_url !== undefined && document.proxy_url !== null) fail();

  const claims = jwtPayload(accessToken);
  const issuer = controlledText(claims.iss, 1_024, false);
  const subject = controlledText(claims.sub, 1_024, false);
  const userId = controlledText(claims.user_id, 1_024, false);
  if (subject !== userId || claims.device_id !== documentDevice) fail();
  if (typeof claims.exp !== "number" || !Number.isSafeInteger(claims.exp)
    || claims.exp < 0) fail();
  if (typeof document.expired !== "string"
    || claims.exp * 1_000 !== Date.parse(document.expired)
    || claims.exp * 1_000 <= now + MINIMUM_SOURCE_ACTIVE_MS) fail();
  const assertedIdentityHmacSha256 = hmac(
    identityKey,
    ASSERTED_IDENTITY_DOMAIN,
    canonicalJson({ issuer, subject, user_id: userId }, "Kimi asserted identity"),
  );
  return { assertedIdentityHmacSha256, expiresAt: document.expired };
}

function sourcePath(value: string): void {
  if (Buffer.byteLength(value) > MAX_SOURCE_PATH_BYTES || value.startsWith("/")
    || value.includes("\\") || /\p{Cc}/u.test(value)
    || value.split("/").some((part) => !part || part === "." || part === "..")) fail();
}

function validateSourcePolicy(raw: Buffer, expectation: SourceExpectation): void {
  const policy = strictJson(raw);
  if (policy.version !== 1 || !Array.isArray(policy.policies)
    || policy.policies.length !== expectation.policyCount) fail();
  const modelPolicies = new Map<string, number[]>();
  let sourceGrantCount = 0;
  policy.policies.forEach((rawEntry, policyIndex) => {
    const entry = object(rawEntry);
    if (typeof entry.enabled !== "boolean" || typeof entry.key_hash !== "string"
      || !SOURCE_KEY_HASH.test(entry.key_hash) || !Array.isArray(entry.grants)) fail();
    sourceGrantCount += entry.grants.length;
    for (const rawGrant of entry.grants) {
      const grant = object(rawGrant);
      if (grant.provider !== expectation.sourceType) continue;
      if (entry.enabled !== true) fail();
      if (grant.group !== undefined && grant.group !== null && typeof grant.group !== "string") fail();
      if (grant.upstream_prefix !== undefined && grant.upstream_prefix !== null
        && typeof grant.upstream_prefix !== "string") fail();
      if (grant.group !== undefined && grant.group !== null && grant.group !== "") fail();
      if (grant.upstream_prefix !== undefined && grant.upstream_prefix !== null
        && grant.upstream_prefix !== "") fail();
      const model = controlledText(grant.model, 500, false);
      const indexes = modelPolicies.get(model) ?? [];
      indexes.push(policyIndex);
      modelPolicies.set(model, indexes);
    }
  });
  if (sourceGrantCount !== expectation.grantCount
    || [...modelPolicies.keys()].sort().join("\0") !== [...expectation.providerModelPolicyCounts.keys()].sort().join("\0")) fail();
  for (const [model, expectedCount] of expectation.providerModelPolicyCounts) {
    const indexes = modelPolicies.get(model);
    if (!indexes || indexes.length !== expectedCount || new Set(indexes).size !== indexes.length) fail();
  }
}

export function inspectSealedOAuthCohort(root: string, identityKeyPath: string, expectationPath: string, now = Date.now()): SourceCohort {
  if (!isAbsolute(root) || !isAbsolute(identityKeyPath) || !isAbsolute(expectationPath)) fail();
  const identityKey = readSourceIdentityKey(identityKeyPath);
  let expectationRaw: Buffer | undefined;
  let captureRaw: Buffer | undefined;
  let configRaw: Buffer | undefined;
  let policyRaw: Buffer | undefined;
  const records: KimiRecord[] = [];
  const payloads: Array<{ path: string; sha256: string }> = [];
  try {
    expectationRaw = readOwnerOnly(expectationPath, "source expectation", MAX_EXPECTATION_BYTES);
    const expectation = sourceExpectation(expectationRaw);
    sourcePath(expectation.policyFile);
    captureRaw = readOwnerOnly(join(root, "source-capture-receipt.json"), "source capture receipt", MAX_RECEIPT_BYTES);
    configRaw = readOwnerOnly(join(root, "config.yaml"), "source config", MAX_CAPTURE_FILE_BYTES);
    policyRaw = readOwnerOnly(join(root, expectation.policyFile), "source policy", MAX_CAPTURE_FILE_BYTES);
    const capture = strictJson(captureRaw);
    for (const [relativePath, path] of authFiles(join(root, "auth"))) {
      const raw = readOwnerOnly(path, "source auth document", MAX_AUTH_BYTES);
      try {
        const documentSha256 = sha256(raw);
        payloads.push({ path: relativePath, sha256: documentSha256 });
        const parsed = strictJson(raw);
        if (parsed.type !== "kimi") continue;
        if (!relativePath.toLowerCase().endsWith(".json")
          || /(?:^|[._-])(?:bak|backup|old|refresh)(?:[._-]|$)/iu.test(relativePath)) fail();
        sourcePath(relativePath);
        const validated = validateKimiDocument(parsed, identityKey, now);
        records.push({
          relativePath,
          documentSha256,
          sourceStableId: hmac(identityKey, SOURCE_ACCOUNT_DOMAIN, relativePath),
          assertedIdentityHmacSha256: validated.assertedIdentityHmacSha256,
          expiresAt: validated.expiresAt,
        });
      } finally { raw.fill(0); }
    }
    const configSha256 = sha256(configRaw);
    const policySha256 = sha256(policyRaw);
    const authPayloadRevisionSha256 = sha256(`${JSON.stringify({ version: 1, auth: payloads })}\n`);
    const sourceCaptureSha256 = sha256(`${JSON.stringify({ version: 1, config_sha256: configSha256, policy_sha256: policySha256, auth_payload_revision_sha256: authPayloadRevisionSha256 })}\n`);
    if (capture.version !== 1 || capture.mode !== expectation.captureMode
      || capture.source_config_sha256 !== configSha256
      || capture.source_policy_sha256 !== policySha256
      || capture.auth_payload_revision_sha256 !== authPayloadRevisionSha256
      || capture.source_capture_sha256 !== sourceCaptureSha256
      || capture.auth_file_count !== payloads.length
      || records.length !== expectation.accountCount
      || new Set(records.map((record) => record.sourceStableId)).size !== records.length
      || new Set(records.map((record) => record.assertedIdentityHmacSha256)).size !== records.length) fail();

    records.sort((left, right) => left.sourceStableId.localeCompare(right.sourceStableId, "en"));
    validateSourcePolicy(policyRaw, expectation);
    const sourceAccounts = records.map((record) => ({
      source_stable_id: record.sourceStableId,
      source_document_sha256: record.documentSha256,
      asserted_identity_hmac_sha256: record.assertedIdentityHmacSha256,
      source_status: "active",
      source_expires_at: record.expiresAt,
      source_document_validation: "verified",
    }));
    const batchSourceSha256 = sha256(canonicalJson({
      source_capture_sha256: sourceCaptureSha256,
      source_accounts: sourceAccounts,
      source_expectation_sha256: expectation.sha256,
    }, "sealed managed-OAuth source batch"));
    return {
      records,
      summary: {
        version: 1,
        workflow: "sealed-managed-oauth-source-audit-v1",
        source_expectation_sha256: expectation.sha256,
        source_capture_sha256: sourceCaptureSha256,
        source_receipt_sha256: sha256(captureRaw),
        source_config_sha256: configSha256,
        source_policy_sha256: policySha256,
        auth_payload_revision_sha256: authPayloadRevisionSha256,
        batch_source_sha256: batchSourceSha256,
        source_account_count: records.length,
        source_active_account_count: records.length,
        source_unique_identity_count: records.length,
        source_expired_access_count: records.filter((record) => Date.parse(record.expiresAt) <= now).length,
        source_validation: "verified",
        source_accounts: sourceAccounts,
      },
    };
  } finally {
    identityKey.fill(0);
    expectationRaw?.fill(0);
    captureRaw?.fill(0);
    configRaw?.fill(0);
    policyRaw?.fill(0);
  }
}

type ParsedOptions = {
  sourceDirectory?: string;
  sourceIdentityKeyFile?: string;
  sourceExpectationFile?: string;
  receipt?: string;
};

function usage(): string {
  return "usage: sealed-oauth-source-audit --source-directory DIR --source-identity-key-file FILE --source-expectation-file FILE --receipt FILE\n\nOffline source audit only; network and target/apply support are absent.";
}
function options(argv: readonly string[]): ParsedOptions {
  if (argv.length === 1 && ["--help", "-h"].includes(argv[0]!)) {
    process.stdout.write(`${usage()}\n`);
    return {};
  }
  const parsed: ParsedOptions = {};
  const values: Record<string, keyof ParsedOptions> = {
    "--source-directory": "sourceDirectory",
    "--source-identity-key-file": "sourceIdentityKeyFile",
    "--source-expectation-file": "sourceExpectationFile",
    "--receipt": "receipt",
  };
  const seen = new Set<string>();
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index]!;
    if (seen.has(flag)) fail();
    seen.add(flag);
    const key = values[flag], value = argv[index + 1];
    if (!key || !value) fail();
    parsed[key] = value;
    index += 1;
  }
  if (!parsed.sourceDirectory || !parsed.sourceIdentityKeyFile || !parsed.sourceExpectationFile || !parsed.receipt
    || !isAbsolute(parsed.sourceDirectory) || !isAbsolute(parsed.sourceIdentityKeyFile)
    || !isAbsolute(parsed.sourceExpectationFile) || !isAbsolute(parsed.receipt)) fail();
  return parsed;
}

export async function run(
  argv = process.argv.slice(2),
  receiptWriter: typeof writeBindingReceipt = writeBindingReceipt,
  parentDescriptorCloser: (descriptor: number) => void = closeSync,
): Promise<JsonObject> {
  const selected = options(argv);
  if (!selected.sourceDirectory) return {};
  // Every protected input and binding is validated before the output is
  // opened. This command has no network client and therefore cannot perform a
  // partial remote operation.
  const cohort = inspectSealedOAuthCohort(
    selected.sourceDirectory,
    selected.sourceIdentityKeyFile!,
    selected.sourceExpectationFile!,
  );
  let output: ReturnType<typeof openSafeOutput>;
  try { output = openSafeOutput(selected.receipt!); }
  catch {
    cohort.records.length = 0;
    throw new SealedOAuthSourceAuditFailure("failed");
  }
  const receipt: JsonObject = {
    ...cohort.summary,
    mode: "source-audit",
    outcome: "pending",
  };
  let closeAttempted = false;
  try {
    receipt.outcome = "verified";
    const encoded = Buffer.from(`${JSON.stringify(receipt)}\n`);
    try { receiptWriter(output, encoded); }
    finally { encoded.fill(0); }
    const result = {
      mode: receipt.mode,
      outcome: receipt.outcome,
      source_account_count: receipt.source_account_count,
      source_unique_identity_count: receipt.source_unique_identity_count,
      source_expired_access_count: receipt.source_expired_access_count,
      batch_source_sha256: receipt.batch_source_sha256,
      receipt_sha256: sha256(`${JSON.stringify(receipt)}\n`),
    };
    closeAttempted = true;
    parentDescriptorCloser(output.parentDescriptor);
    return result;
  } catch {
    // Persistence is atomic, but an I/O failure after the final link is an
    // uncertain local outcome. Never overwrite or retry the same output path.
    throw new SealedOAuthSourceAuditFailure("uncertain");
  } finally {
    cohort.records.length = 0;
    if (!closeAttempted) {
      try { parentDescriptorCloser(output.parentDescriptor); }
      catch { /* preserve the primary uncertain write outcome */ }
    }
  }
}

if (invokedAsEntrypoint("sealed-oauth-source-audit", import.meta.url)) {
  run().then((result) => {
    if (Object.keys(result).length > 0) process.stdout.write(`${JSON.stringify(result)}\n`);
  }).catch((error: unknown) => {
    const outcome = error instanceof SealedOAuthSourceAuditFailure ? error.outcome : "failed";
    process.stderr.write(outcome === "uncertain"
      ? "Sealed managed-OAuth source audit outcome is uncertain; do not retry or reuse the receipt path\n"
      : "Sealed managed-OAuth source audit failed before a terminal receipt; no remote operation occurred\n");
    process.exitCode = 2;
  });
}
