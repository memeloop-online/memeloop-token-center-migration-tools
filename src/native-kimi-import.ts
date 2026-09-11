#!/usr/bin/env node
/** Inspect one reviewed, sealed Kimi cohort without contacting a target. */
import { createHash, createHmac } from "node:crypto";
import { closeSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import {
  authFiles,
  canonicalJson,
  openSafeOutput,
  readOwnerOnly,
  readSourceIdentityKey,
  writeBindingReceipt,
} from "../ops/cpa-upstreams/import-cpa-upstreams.ts";
import { invokedAsEntrypoint } from "../ops/lib/invoked-as-entrypoint.ts";
import { parseStrictJson } from "../ops/lib/strict-json.ts";

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

const MAX_CAPTURE_FILE_BYTES = 8 * 1024 * 1024;
const MAX_AUTH_BYTES = 1024 * 1024;
const MAX_RECEIPT_BYTES = 4 * 1024 * 1024;
const EXPECTED_SOURCE_ACCOUNTS = 2;
const EXPECTED_SOURCE_POLICIES = 10;
const EXPECTED_SOURCE_GRANTS = 131;
const MAX_SOURCE_PATH_BYTES = 512;
const MINIMUM_SOURCE_ACTIVE_MS = 10 * 60 * 1_000;
const EXPECTED_KIMI_MODELS = Object.freeze([
  "kimi-k2",
  "kimi-k2-thinking",
  "kimi-k2.5",
  "kimi-k2.6",
  "kimi-k2.7-code",
  "kimi-k2.7-code-highspeed",
  "kimi-k3",
  "kimi-k3-256k",
]);
const SOURCE_ACCOUNT_DOMAIN = "memeloop-token-center\0native-kimi-source-account\0v1\0";
const ASSERTED_IDENTITY_DOMAIN = "memeloop-token-center\0native-kimi-asserted-identity\0v1\0";
const SOURCE_KEY_HASH = /^(?:sha256:)?[0-9a-f]{64}$/iu;
const UTF8 = new TextDecoder("utf-8", { fatal: true });

export class NativeKimiImportFailure extends Error {
  constructor() { super("native Kimi source audit failed"); }
}

function fail(): never { throw new NativeKimiImportFailure(); }
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

function validateSourcePolicy(raw: Buffer): void {
  const policy = strictJson(raw);
  if (policy.version !== 1 || !Array.isArray(policy.policies)
    || policy.policies.length !== EXPECTED_SOURCE_POLICIES) fail();
  const modelPolicies = new Map<string, number[]>();
  let sourceGrantCount = 0;
  policy.policies.forEach((rawEntry, policyIndex) => {
    const entry = object(rawEntry);
    if (typeof entry.enabled !== "boolean" || typeof entry.key_hash !== "string"
      || !SOURCE_KEY_HASH.test(entry.key_hash) || !Array.isArray(entry.grants)) fail();
    sourceGrantCount += entry.grants.length;
    for (const rawGrant of entry.grants) {
      const grant = object(rawGrant);
      if (grant.provider !== "kimi") continue;
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
  if (sourceGrantCount !== EXPECTED_SOURCE_GRANTS
    || [...modelPolicies.keys()].sort().join("\0") !== [...EXPECTED_KIMI_MODELS].sort().join("\0")
    || [...modelPolicies.values()].some((indexes) => indexes.length !== 3
      || new Set(indexes).size !== indexes.length)) fail();
}

export function inspectSealedKimiCohort(root: string, identityKeyPath: string, now = Date.now()): SourceCohort {
  if (!isAbsolute(root) || !isAbsolute(identityKeyPath)) fail();
  const identityKey = readSourceIdentityKey(identityKeyPath);
  const captureRaw = readOwnerOnly(join(root, "source-capture-receipt.json"), "source capture receipt", MAX_RECEIPT_BYTES);
  const configRaw = readOwnerOnly(join(root, "config.yaml"), "source config", MAX_CAPTURE_FILE_BYTES);
  const policyRaw = readOwnerOnly(join(root, "native-key-policy.json"), "source policy", MAX_CAPTURE_FILE_BYTES);
  const records: KimiRecord[] = [];
  const payloads: Array<{ path: string; sha256: string }> = [];
  try {
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
    if (capture.version !== 1 || capture.mode !== "collect-cpa-source-snapshot"
      || capture.source_config_sha256 !== configSha256
      || capture.source_policy_sha256 !== policySha256
      || capture.auth_payload_revision_sha256 !== authPayloadRevisionSha256
      || capture.source_capture_sha256 !== sourceCaptureSha256
      || capture.auth_file_count !== payloads.length
      || records.length !== EXPECTED_SOURCE_ACCOUNTS
      || new Set(records.map((record) => record.sourceStableId)).size !== records.length
      || new Set(records.map((record) => record.assertedIdentityHmacSha256)).size !== records.length) fail();

    records.sort((left, right) => left.sourceStableId.localeCompare(right.sourceStableId, "en"));
    validateSourcePolicy(policyRaw);
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
    }, "sealed Kimi source batch"));
    return {
      records,
      summary: {
        version: 1,
        workflow: "sealed-kimi-source-audit-v1",
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
    captureRaw.fill(0);
    configRaw.fill(0);
    policyRaw.fill(0);
  }
}

type ParsedOptions = {
  sourceDirectory?: string;
  sourceIdentityKeyFile?: string;
  receipt?: string;
};

function usage(): string {
  return "usage: native-kimi-import --source-directory DIR --source-identity-key-file FILE --receipt FILE\n\nOffline source audit only; target import/apply support is retired.";
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
  if (!parsed.sourceDirectory || !parsed.sourceIdentityKeyFile || !parsed.receipt
    || !isAbsolute(parsed.sourceDirectory) || !isAbsolute(parsed.sourceIdentityKeyFile)
    || !isAbsolute(parsed.receipt)) fail();
  return parsed;
}

export async function run(argv = process.argv.slice(2)): Promise<JsonObject> {
  const selected = options(argv);
  if (!selected.sourceDirectory) return {};
  const cohort = inspectSealedKimiCohort(selected.sourceDirectory, selected.sourceIdentityKeyFile!);
  const output = openSafeOutput(selected.receipt!);
  const receipt: JsonObject = {
    ...cohort.summary,
    mode: "source-audit",
    outcome: "pending",
  };
  try {
    receipt.outcome = "verified";
    const encoded = Buffer.from(`${JSON.stringify(receipt)}\n`);
    try { writeBindingReceipt(output, encoded); }
    finally { encoded.fill(0); }
    return {
      mode: receipt.mode,
      outcome: receipt.outcome,
      source_account_count: receipt.source_account_count,
      source_unique_identity_count: receipt.source_unique_identity_count,
      source_expired_access_count: receipt.source_expired_access_count,
      batch_source_sha256: receipt.batch_source_sha256,
      receipt_sha256: sha256(`${JSON.stringify(receipt)}\n`),
    };
  } catch {
    receipt.outcome = "failed";
    const encoded = Buffer.from(`${JSON.stringify(receipt)}\n`);
    try { writeBindingReceipt(output, encoded); }
    finally { encoded.fill(0); }
    throw new NativeKimiImportFailure();
  } finally {
    cohort.records.length = 0;
    closeSync(output.parentDescriptor);
  }
}

if (invokedAsEntrypoint("native-kimi-import", import.meta.url)) {
  run().then((result) => {
    if (Object.keys(result).length > 0) process.stdout.write(`${JSON.stringify(result)}\n`);
  }).catch(() => {
    process.stderr.write("Native Kimi source audit stopped; no target was contacted\n");
    process.exitCode = 2;
  });
}
