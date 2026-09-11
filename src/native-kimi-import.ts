#!/usr/bin/env node
/**
 * Import exactly one reviewed, sealed two-account Kimi cohort.
 *
 * Default operation is offline and read-only. Target preflight uses only
 * control-plane GETs. `--apply` is separately approval-bound and imports
 * accounts only: it never creates routes, grants, keys, catalog observations,
 * health observations, or provider requests.
 */
import { createHash, createHmac } from "node:crypto";
import { closeSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import {
  authFiles,
  canonicalJson,
  openSafeOutput,
  readOwnerOnly,
  readSourceIdentityKey,
  requestJson,
  upstreamUrl,
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
  disabled?: boolean;
};
type KimiRecord = {
  relativePath: string;
  document: KimiDocument;
  documentSha256: string;
  sourceStableId: string;
  assertedIdentityHmacSha256: string;
};
type SourceCohort = { summary: JsonObject; records: KimiRecord[] };

const MAX_CAPTURE_FILE_BYTES = 8 * 1024 * 1024;
const MAX_AUTH_BYTES = 1024 * 1024;
const MAX_RECEIPT_BYTES = 4 * 1024 * 1024;
const MAX_TARGET_ACCOUNTS = 100;
const EXPECTED_SOURCE_ACCOUNTS = 2;
const EXPECTED_SOURCE_POLICIES = 10;
const EXPECTED_SOURCE_GRANTS = 131;
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
const REVISION = /^[0-9a-f]{40}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const TENANT = /^[A-Za-z0-9._:-]{1,200}$/u;
const UTF8 = new TextDecoder("utf-8", { fatal: true });

export class NativeKimiImportFailure extends Error {
  constructor() { super("native Kimi import precondition or operation failed"); }
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

export function validateKimiDocument(value: unknown, identityKey: Buffer): {
  document: KimiDocument;
  assertedIdentityHmacSha256: string;
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
  for (const key of ["scope", "device_id"] as const) {
    if (document[key] !== undefined && document[key] !== null) controlledText(document[key]);
  }
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
  const documentDevice = document.device_id;
  if (subject !== userId || typeof documentDevice !== "string"
    || claims.device_id !== documentDevice) fail();
  if (typeof claims.exp !== "number" || !Number.isSafeInteger(claims.exp)
    || claims.exp < 0) fail();
  if (typeof document.expired === "string"
    && claims.exp * 1_000 !== Date.parse(document.expired)) fail();
  const assertedIdentityHmacSha256 = hmac(
    identityKey,
    ASSERTED_IDENTITY_DOMAIN,
    canonicalJson({ issuer, subject, user_id: userId }, "Kimi asserted identity"),
  );
  return { document, assertedIdentityHmacSha256 };
}

function sourcePolicy(raw: Buffer, sourceStableIds: readonly string[]): {
  routePlan: JsonObject[];
  sourcePolicyCount: number;
  sourceGrantCount: number;
  kimiGrantCount: number;
} {
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
    || [...modelPolicies.values()].some((indexes) => indexes.length !== 3)) fail();
  const routePlan = [...modelPolicies.entries()].sort(([left], [right]) => left.localeCompare(right, "en"))
    .map(([model, sourcePolicyIndexes]) => ({
      public_model: model,
      upstream_model: model,
      required_protocols: ["openai", "anthropic"],
      candidate_source_stable_ids: [...sourceStableIds],
      source_policy_indexes: sourcePolicyIndexes,
      state: "deferred_pending_route_price_and_protocol_review",
    }));
  return {
    routePlan,
    sourcePolicyCount: policy.policies.length,
    sourceGrantCount,
    kimiGrantCount: [...modelPolicies.values()].reduce((sum, indexes) => sum + indexes.length, 0),
  };
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
        const validated = validateKimiDocument(parsed, identityKey);
        records.push({
          relativePath,
          document: validated.document,
          documentSha256,
          sourceStableId: hmac(identityKey, SOURCE_ACCOUNT_DOMAIN, relativePath),
          assertedIdentityHmacSha256: validated.assertedIdentityHmacSha256,
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
    const policy = sourcePolicy(policyRaw, records.map((record) => record.sourceStableId));
    const sourceAccounts = records.map((record) => ({
      source_stable_id: record.sourceStableId,
      source_document_sha256: record.documentSha256,
      asserted_identity_hmac_sha256: record.assertedIdentityHmacSha256,
      target_driver: "kimi-oauth",
      target_status: "active",
      target_name_policy: "neutral-server-keyed-source-suffix",
    }));
    const batchSha256 = sha256(canonicalJson({
      source_capture_sha256: sourceCaptureSha256,
      source_accounts: sourceAccounts,
      route_plan: policy.routePlan,
    }, "native Kimi import batch"));
    return {
      records,
      summary: {
        version: 1,
        workflow: "native-kimi-import-v1",
        source_capture_sha256: sourceCaptureSha256,
        source_receipt_sha256: sha256(captureRaw),
        source_config_sha256: configSha256,
        source_policy_sha256: policySha256,
        auth_payload_revision_sha256: authPayloadRevisionSha256,
        batch_sha256: batchSha256,
        source_account_count: records.length,
        source_active_account_count: records.length,
        source_unique_identity_count: records.length,
        source_expired_access_count: records.filter((record) =>
          typeof record.document.expired === "string" && Date.parse(record.document.expired) <= now).length,
        source_policy_count: policy.sourcePolicyCount,
        source_grant_count: policy.sourceGrantCount,
        kimi_grant_count: policy.kimiGrantCount,
        source_accounts: sourceAccounts,
        route_plan: policy.routePlan,
        route_write_count: 0,
        permission_write_count: 0,
        provider_request_count: 0,
        credential_storage: "target-encrypted-managed-oauth-envelope",
        target_source_type: "kimi",
        target_driver: "kimi-oauth",
      },
    };
  } finally {
    identityKey.fill(0);
    captureRaw.fill(0);
    configRaw.fill(0);
    policyRaw.fill(0);
  }
}

function targetOrigin(value: string, allowLoopback: boolean): string {
  const normalized = upstreamUrl(value, "target control API base URL", allowLoopback);
  const parsed = new URL(normalized);
  if (parsed.pathname !== "/" || parsed.search || parsed.hash) fail();
  return parsed.origin;
}
function targetToken(path: string): string {
  const raw = readOwnerOnly(path, "target service token", 64 * 1024);
  try { return controlledText(UTF8.decode(raw).replace(/\n$/u, ""), 16 * 1024, false); }
  finally { raw.fill(0); }
}
function validateTargetAccount(value: unknown, tenant: string): JsonObject {
  const account = object(value);
  if (account.tenant_external_id !== tenant || typeof account.id !== "string"
    || !UUID.test(account.id) || typeof account.name !== "string" || typeof account.driver !== "string"
    || typeof account.status !== "string" || "credential" in account) fail();
  return account;
}

async function preflightTarget(
  origin: string,
  token: string,
  tenant: string,
  expectedRevision: string,
): Promise<JsonObject> {
  const version = object((await requestJson("GET", `${origin}/version`, token, "target version", [200])).value);
  if (version.service !== "memeloop-token-center" || version.revision !== expectedRevision) fail();
  const capabilities = object((await requestJson("GET", `${origin}/internal/v1/imports/cpa/managed-oauth/capabilities`, token, "target managed OAuth capabilities", [200])).value);
  if (capabilities.contract_version !== 1 || !Array.isArray(capabilities.source_types)
    || !capabilities.source_types.includes("kimi")) fail();
  const providers = (await requestJson("GET", `${origin}/internal/v1/provider-types`, token, "target provider types", [200])).value;
  if (!Array.isArray(providers) || !providers.some((value) => object(value).id === "kimi-oauth")) fail();
  const targetAccounts = (await requestJson("GET", `${origin}/internal/v1/upstreams?tenant_external_id=${encodeURIComponent(tenant)}&limit=${MAX_TARGET_ACCOUNTS}`, token, "target upstream accounts", [200])).value;
  if (!Array.isArray(targetAccounts) || targetAccounts.length >= MAX_TARGET_ACCOUNTS) fail();
  const kimi = targetAccounts.map((value) => validateTargetAccount(value, tenant))
    .filter((account) => account.driver === "kimi-oauth");
  // This is a closed two-account cohort. A nonempty partial or unrelated
  // cohort is neither safe to resume nor safe to merge implicitly: the
  // server-owned source key can resolve exact replays only during an approved
  // import. Keep the target preflight at the same cardinality boundary as the
  // sealed source.
  if ((kimi.length !== 0 && kimi.length !== EXPECTED_SOURCE_ACCOUNTS)
    || kimi.some((account) => account.status !== "active" || /cpa|bridge/iu.test(String(account.name)))) fail();
  return {
    target_origin: origin,
    target_revision: expectedRevision,
    target_capabilities_verified: true,
    target_existing_kimi_account_count: kimi.length,
    target_replay_resolution: kimi.length === 0 ? "create_expected" : "server_source_key_replay_required",
  };
}

type ParsedOptions = {
  sourceDirectory?: string;
  sourceIdentityKeyFile?: string;
  receipt?: string;
  target?: string;
  tokenFile?: string;
  tenant: string;
  expectedTargetRevision?: string;
  approvalReceipt?: string;
  apply: boolean;
  allowLoopback: boolean;
};

function usage(): string {
  return "usage: native-kimi-import --source-directory DIR --source-identity-key-file FILE --receipt FILE [--target-api-base-url URL --service-token-file FILE --tenant default --expected-target-revision SHA] [--apply --expected-count 2 --approved-dry-run-receipt FILE] [--allow-http-loopback]";
}
function options(argv: readonly string[]): ParsedOptions {
  if (argv.length === 1 && ["--help", "-h"].includes(argv[0]!)) {
    process.stdout.write(`${usage()}\n`);
    return { tenant: "default", apply: false, allowLoopback: false };
  }
  const parsed: ParsedOptions = { tenant: "default", apply: false, allowLoopback: false };
  const values: Record<string, keyof ParsedOptions | "expectedCount"> = {
    "--source-directory": "sourceDirectory",
    "--source-identity-key-file": "sourceIdentityKeyFile",
    "--receipt": "receipt",
    "--target-api-base-url": "target",
    "--service-token-file": "tokenFile",
    "--tenant": "tenant",
    "--expected-target-revision": "expectedTargetRevision",
    "--approved-dry-run-receipt": "approvalReceipt",
    "--expected-count": "expectedCount",
  };
  let expectedCount: string | undefined;
  const seen = new Set<string>();
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index]!;
    if (seen.has(flag)) fail();
    seen.add(flag);
    if (flag === "--apply") { parsed.apply = true; continue; }
    if (flag === "--allow-http-loopback") { parsed.allowLoopback = true; continue; }
    const key = values[flag], value = argv[index + 1];
    if (!key || !value) fail();
    if (key === "expectedCount") expectedCount = value;
    else (parsed as unknown as Record<string, unknown>)[key] = value;
    index += 1;
  }
  if (!parsed.sourceDirectory || !parsed.sourceIdentityKeyFile || !parsed.receipt
    || !isAbsolute(parsed.sourceDirectory) || !isAbsolute(parsed.sourceIdentityKeyFile)
    || !isAbsolute(parsed.receipt) || !TENANT.test(parsed.tenant)
    || Boolean(parsed.target) !== Boolean(parsed.tokenFile)
    || Boolean(parsed.target) !== Boolean(parsed.expectedTargetRevision)
    || (parsed.expectedTargetRevision !== undefined && !REVISION.test(parsed.expectedTargetRevision))
    || (parsed.apply && (!parsed.target || expectedCount !== "2" || !parsed.approvalReceipt))
    || (!parsed.apply && (expectedCount !== undefined || parsed.approvalReceipt !== undefined))
    || (parsed.approvalReceipt !== undefined && !isAbsolute(parsed.approvalReceipt))) fail();
  return parsed;
}

export async function run(argv = process.argv.slice(2)): Promise<JsonObject> {
  const selected = options(argv);
  if (!selected.sourceDirectory) return {};
  const cohort = inspectSealedKimiCohort(selected.sourceDirectory, selected.sourceIdentityKeyFile!);
  const output = openSafeOutput(selected.receipt!);
  const bindings: JsonObject[] = [];
  let submitted = 0;
  let imported = 0;
  let token = "";
  const receipt: JsonObject = {
    ...cohort.summary,
    tenant_external_id: selected.tenant,
    mode: selected.apply ? "apply" : "dry-run",
    outcome: "pending",
    target_capabilities_verified: false,
    submitted_count: 0,
    import_count: 0,
    bindings,
  };
  try {
    if (selected.target) {
      const origin = targetOrigin(selected.target, selected.allowLoopback);
      token = targetToken(selected.tokenFile!);
      Object.assign(receipt, await preflightTarget(origin, token, selected.tenant, selected.expectedTargetRevision!));
      if (selected.apply) {
        const approvedRaw = readOwnerOnly(selected.approvalReceipt!, "approved Kimi dry-run receipt", MAX_RECEIPT_BYTES);
        try {
          const approved = strictJson(approvedRaw);
          for (const key of [
            "workflow", "batch_sha256", "source_capture_sha256", "source_receipt_sha256",
            "tenant_external_id", "target_origin", "target_revision",
          ]) if (approved[key] !== receipt[key]) fail();
          if (approved.mode !== "dry-run" || approved.outcome !== "verified"
            || approved.target_capabilities_verified !== true || approved.source_account_count !== 2
            || approved.route_write_count !== 0 || approved.permission_write_count !== 0
            || approved.provider_request_count !== 0) fail();
        } finally { approvedRaw.fill(0); }
        for (const record of cohort.records) {
          if (inspectSealedKimiCohort(selected.sourceDirectory, selected.sourceIdentityKeyFile!).summary.batch_sha256
            !== cohort.summary.batch_sha256) fail();
          submitted += 1;
          receipt.submitted_count = submitted;
          const result = await requestJson("POST", `${origin}/internal/v1/imports/cpa/managed-oauth`, token, "native Kimi managed OAuth import", [200, 201], {
            contract_version: 1,
            tenant_external_id: selected.tenant,
            source: { kind: "auth_file", relative_path: record.relativePath },
            source_type: "kimi",
            document: record.document,
          });
          const response = object(result.value);
          const account = validateTargetAccount(response.account, selected.tenant);
          const expectedDisposition = result.status === 201 ? "created" : "replayed";
          if (response.disposition !== expectedDisposition || account.driver !== "kimi-oauth"
            || account.status !== "active" || /cpa|bridge/iu.test(String(account.name))) fail();
          bindings.push({
            source_stable_id: record.sourceStableId,
            source_document_sha256: record.documentSha256,
            upstream_account_id: account.id,
            account_name: account.name,
            driver: account.driver,
            disposition: response.disposition,
          });
          imported += 1;
          receipt.import_count = imported;
        }
        if (inspectSealedKimiCohort(selected.sourceDirectory, selected.sourceIdentityKeyFile!).summary.batch_sha256
          !== cohort.summary.batch_sha256) fail();
      }
    }
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
      route_plan_count: Array.isArray(receipt.route_plan) ? receipt.route_plan.length : 0,
      import_count: imported,
      target_capabilities_verified: receipt.target_capabilities_verified,
      receipt_sha256: sha256(`${JSON.stringify(receipt)}\n`),
    };
  } catch {
    receipt.outcome = submitted > imported ? "uncertain-stop-no-retry"
      : imported > 0 ? "partial-stop-no-retry" : "failed";
    const encoded = Buffer.from(`${JSON.stringify(receipt)}\n`);
    try { writeBindingReceipt(output, encoded); }
    finally { encoded.fill(0); }
    throw new NativeKimiImportFailure();
  } finally {
    token = "";
    cohort.records.length = 0;
    closeSync(output.parentDescriptor);
  }
}

if (invokedAsEntrypoint("native-kimi-import", import.meta.url)) {
  run().then((result) => {
    if (Object.keys(result).length > 0) process.stdout.write(`${JSON.stringify(result)}\n`);
  }).catch(() => {
    process.stderr.write("Native Kimi import stopped; inspect the protected receipt; do not retry automatically\n");
    process.exitCode = 2;
  });
}
