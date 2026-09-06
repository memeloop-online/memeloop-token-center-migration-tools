#!/usr/bin/env node
/**
 * Promote only the target service's currently active, proven migration-primary
 * keys to its advertised balance-unrestricted policy.  The service, not this
 * client, owns the selection query and the single transaction.
 */

import { createHash } from "node:crypto";
import { closeSync, constants, fsyncSync, fstatSync, openSync, readSync, unlinkSync, writeSync } from "node:fs";
import { parseStrictJson } from "../lib/strict-json.ts";

const MAX_HTTP_BYTES = 1024 * 1024;
const MAX_RECEIPT_BYTES = 64 * 1024;
const SHA256 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const INTERNAL_PATH = /^\/internal\/v1\/[A-Za-z0-9/_-]{1,200}$/;
const RECEIPT_FORMAT = "memeloop-active-migration-key-unlimited-receipt-v1";
const CAPABILITIES_PATH = "/internal/v1/migration-key-policy-unlimited/capabilities";

type JsonObject = Record<string, unknown>;

export class TransitionFailure extends Error {}

export type TransitionCapabilities = Readonly<{
  apiSchema: number;
  planPath: string;
  applyPath: string;
  transitionName: string;
}>;

export type Candidate = Readonly<{
  keyId: string;
  policyRevision: number;
  requiresTransition: boolean;
  identityDigest: string;
  grantsDigest: string;
  historyDigest: string;
  balanceDigest: string;
  credentialDigest: string;
}>;

export type TransitionPlan = Readonly<{
  capabilities: TransitionCapabilities;
  candidates: readonly Candidate[];
  planDigest: string;
  plannedChangeCount: number;
}>;

export type Receipt = Readonly<{
  format: typeof RECEIPT_FORMAT;
  mode: "dry-run" | "apply";
  plan_sha256: string;
  approved_dry_run_receipt_sha256?: string;
  transition: string;
  candidate_count: number;
  planned_change_count: number;
  changed_count: number;
  already_unlimited_count: number;
  identity_preserved_count: number;
  grants_preserved_count: number;
  history_preserved_count: number;
  balance_preserved_count: number;
  current_credentials_preserved_count: number;
  revoked_excluded: true;
  balance_exhaustion_disabled: true;
  atomic_cas: true;
  idempotent: true;
  receipt_sha256: string;
}>;

export type TargetClient = Readonly<{
  get: (path: string) => Promise<unknown>;
  post: (path: string, body: JsonObject) => Promise<unknown>;
}>;

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function object(value: unknown, allowed: readonly string[], label: string): JsonObject {
  if (value === null || Array.isArray(value) || typeof value !== "object") throw new TransitionFailure(`${label} is invalid`);
  const output = value as JsonObject;
  const keys = Object.keys(output).sort();
  const expected = [...allowed].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) throw new TransitionFailure(`${label} is invalid`);
  return output;
}

function objectWithOptional(value: unknown, required: readonly string[], optional: readonly string[], label: string): JsonObject {
  if (value === null || Array.isArray(value) || typeof value !== "object") throw new TransitionFailure(`${label} is invalid`);
  const output = value as JsonObject;
  const keys = Object.keys(output);
  if (required.some((key) => !Object.hasOwn(output, key)) || keys.some((key) => !required.includes(key) && !optional.includes(key))) throw new TransitionFailure(`${label} is invalid`);
  return output;
}

function string(value: unknown, label: string, max = 200): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max || value.trim() !== value || /[\0\r\n]/.test(value)) throw new TransitionFailure(`${label} is invalid`);
  return value;
}

function positiveInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1) throw new TransitionFailure(`${label} is invalid`);
  return Number(value);
}

function nonNegativeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) throw new TransitionFailure(`${label} is invalid`);
  return Number(value);
}

function digest(value: unknown, label: string): string {
  const result = string(value, label, 64).toLowerCase();
  if (!SHA256.test(result) || result !== value) throw new TransitionFailure(`${label} is invalid`);
  return result;
}

function keyId(value: unknown, label: string): string {
  const result = string(value, label, 36).toLowerCase();
  if (!UUID.test(result) || result !== value) throw new TransitionFailure(`${label} is invalid`);
  return result;
}

function internalPath(value: unknown, label: string): string {
  const result = string(value, label, 220);
  if (!INTERNAL_PATH.test(result)) throw new TransitionFailure(`${label} is invalid`);
  return result;
}

function transitionName(value: unknown, label: string): string {
  const result = string(value, label, 128);
  if (!/^[a-z][a-z0-9_-]*$/.test(result)) throw new TransitionFailure(`${label} is invalid`);
  return result;
}

function bool(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") throw new TransitionFailure(`${label} is invalid`);
  return value;
}

/** Parse an advertised formal policy transition; no product policy name is assumed. */
export function parseCapabilities(value: unknown): TransitionCapabilities {
  const root = object(value, ["api_schema", "apply_path", "contract", "plan_path", "transition"], "transition capabilities");
  if (root["contract"] !== "active-migration-key-unlimited") throw new TransitionFailure("transition contract is unsupported");
  const apiSchema = positiveInteger(root["api_schema"], "transition capabilities");
  const planPath = internalPath(root["plan_path"], "transition capabilities");
  const applyPath = internalPath(root["apply_path"], "transition capabilities");
  if (planPath === applyPath) throw new TransitionFailure("transition capabilities are invalid");
  const transition = object(root["transition"], ["atomic_batch_cas", "balance_exhaustion_disabled", "current_credential_preserved", "grants_preserved", "history_preserved", "idempotent", "key_identity_preserved", "name", "revoked_excluded"], "transition capabilities");
  if (
    !bool(transition["atomic_batch_cas"], "transition capabilities") ||
    !bool(transition["balance_exhaustion_disabled"], "transition capabilities") ||
    !bool(transition["current_credential_preserved"], "transition capabilities") ||
    !bool(transition["grants_preserved"], "transition capabilities") ||
    !bool(transition["history_preserved"], "transition capabilities") ||
    !bool(transition["idempotent"], "transition capabilities") ||
    !bool(transition["key_identity_preserved"], "transition capabilities") ||
    !bool(transition["revoked_excluded"], "transition capabilities")
  ) throw new TransitionFailure("target does not advertise the required safe transition");
  return { apiSchema, planPath, applyPath, transitionName: transitionName(transition["name"], "transition capabilities") };
}

function parseCandidate(value: unknown): Candidate {
  const item = object(value, ["balance_digest", "credential_digest", "current_credential", "grants_digest", "history_digest", "identity_digest", "key_id", "migration_primary", "policy_revision", "requires_transition", "revoked", "status"], "transition candidate");
  if (item["status"] !== "active" || !bool(item["migration_primary"], "transition candidate") || !bool(item["current_credential"], "transition candidate") || bool(item["revoked"], "transition candidate")) throw new TransitionFailure("transition candidate fails the active migration-primary fence");
  return {
    keyId: keyId(item["key_id"], "transition candidate"),
    policyRevision: positiveInteger(item["policy_revision"], "transition candidate"),
    requiresTransition: bool(item["requires_transition"], "transition candidate"),
    identityDigest: digest(item["identity_digest"], "transition candidate"),
    grantsDigest: digest(item["grants_digest"], "transition candidate"),
    historyDigest: digest(item["history_digest"], "transition candidate"),
    balanceDigest: digest(item["balance_digest"], "transition candidate"),
    credentialDigest: digest(item["credential_digest"], "transition candidate"),
  };
}

function canonicalPlan(capabilities: TransitionCapabilities, candidates: readonly Candidate[]): string {
  return JSON.stringify({
    api_schema: capabilities.apiSchema,
    transition: capabilities.transitionName,
    candidates: candidates.map((candidate) => ({
      key_id: candidate.keyId,
      policy_revision: candidate.policyRevision,
      requires_transition: candidate.requiresTransition,
      identity_digest: candidate.identityDigest,
      grants_digest: candidate.grantsDigest,
      history_digest: candidate.historyDigest,
      balance_digest: candidate.balanceDigest,
      credential_digest: candidate.credentialDigest,
    })),
  });
}

/** The target and fixture contract share this canonical, non-secret plan fence. */
export function planDigestForCandidates(capabilities: TransitionCapabilities, candidates: readonly Candidate[]): string {
  return sha256(canonicalPlan(capabilities, candidates));
}

export function parsePlan(value: unknown, capabilities: TransitionCapabilities): TransitionPlan {
  const root = object(value, ["candidate_count", "candidates", "contract", "plan_sha256", "transition"], "transition plan");
  if (root["contract"] !== "active-migration-key-unlimited" || root["transition"] !== capabilities.transitionName) throw new TransitionFailure("transition plan does not match the advertised contract");
  if (!Array.isArray(root["candidates"]) || root["candidates"].length === 0 || root["candidates"].length > 100_000) throw new TransitionFailure("transition plan has an invalid candidate set");
  const candidates = root["candidates"].map(parseCandidate);
  if (nonNegativeInteger(root["candidate_count"], "transition plan") !== candidates.length) throw new TransitionFailure("transition plan count is invalid");
  for (let index = 1; index < candidates.length; index += 1) {
    if (candidates[index - 1]!.keyId >= candidates[index]!.keyId) throw new TransitionFailure("transition plan is not canonical");
  }
  const planDigest = digest(root["plan_sha256"], "transition plan");
  if (planDigest !== planDigestForCandidates(capabilities, candidates)) throw new TransitionFailure("transition plan digest is invalid");
  return { capabilities, candidates, planDigest, plannedChangeCount: candidates.filter((candidate) => candidate.requiresTransition).length };
}

function receiptCore(receipt: Omit<Receipt, "receipt_sha256">): string {
  return JSON.stringify(receipt);
}

function makeReceipt(core: Omit<Receipt, "receipt_sha256">): Receipt {
  return { ...core, receipt_sha256: sha256(receiptCore(core)) };
}

function receiptCoreFrom(value: unknown): Omit<Receipt, "receipt_sha256"> {
  const root = objectWithOptional(value, ["already_unlimited_count", "atomic_cas", "balance_exhaustion_disabled", "balance_preserved_count", "candidate_count", "changed_count", "current_credentials_preserved_count", "format", "grants_preserved_count", "history_preserved_count", "idempotent", "identity_preserved_count", "mode", "plan_sha256", "planned_change_count", "receipt_sha256", "revoked_excluded", "transition"], ["approved_dry_run_receipt_sha256"], "transition receipt");
  if (root["format"] !== RECEIPT_FORMAT || (root["mode"] !== "dry-run" && root["mode"] !== "apply")) throw new TransitionFailure("transition receipt is invalid");
  const mode: "dry-run" | "apply" = root["mode"] === "dry-run" ? "dry-run" : "apply";
  const approved = root["approved_dry_run_receipt_sha256"];
  if ((mode === "dry-run" && approved !== undefined) || (mode === "apply" && typeof approved !== "string")) throw new TransitionFailure("transition receipt is invalid");
  const core: Omit<Receipt, "receipt_sha256"> = {
    format: RECEIPT_FORMAT,
    mode,
    plan_sha256: digest(root["plan_sha256"], "transition receipt"),
    ...(mode === "apply" ? { approved_dry_run_receipt_sha256: digest(approved, "transition receipt") } : {}),
    transition: transitionName(root["transition"], "transition receipt"),
    candidate_count: nonNegativeInteger(root["candidate_count"], "transition receipt"),
    planned_change_count: nonNegativeInteger(root["planned_change_count"], "transition receipt"),
    changed_count: nonNegativeInteger(root["changed_count"], "transition receipt"),
    already_unlimited_count: nonNegativeInteger(root["already_unlimited_count"], "transition receipt"),
    identity_preserved_count: nonNegativeInteger(root["identity_preserved_count"], "transition receipt"),
    grants_preserved_count: nonNegativeInteger(root["grants_preserved_count"], "transition receipt"),
    history_preserved_count: nonNegativeInteger(root["history_preserved_count"], "transition receipt"),
    balance_preserved_count: nonNegativeInteger(root["balance_preserved_count"], "transition receipt"),
    current_credentials_preserved_count: nonNegativeInteger(root["current_credentials_preserved_count"], "transition receipt"),
    revoked_excluded: bool(root["revoked_excluded"], "transition receipt") as true,
    balance_exhaustion_disabled: bool(root["balance_exhaustion_disabled"], "transition receipt") as true,
    atomic_cas: bool(root["atomic_cas"], "transition receipt") as true,
    idempotent: bool(root["idempotent"], "transition receipt") as true,
  };
  const invalidAccounting = core.mode === "apply"
    ? core.changed_count + core.already_unlimited_count !== core.candidate_count
    : core.changed_count !== 0 || core.already_unlimited_count !== core.candidate_count - core.planned_change_count;
  if (!core.revoked_excluded || !core.balance_exhaustion_disabled || !core.atomic_cas || !core.idempotent || invalidAccounting || core.planned_change_count > core.candidate_count || [core.identity_preserved_count, core.grants_preserved_count, core.history_preserved_count, core.balance_preserved_count, core.current_credentials_preserved_count].some((count) => count !== core.candidate_count)) throw new TransitionFailure("transition receipt does not prove the required invariants");
  return core;
}

export function parseReceipt(value: unknown): Receipt {
  const root = value as JsonObject;
  const core = receiptCoreFrom(value);
  const receiptSha = digest(root["receipt_sha256"], "transition receipt");
  if (receiptSha !== sha256(receiptCore(core))) throw new TransitionFailure("transition receipt digest is invalid");
  return { ...core, receipt_sha256: receiptSha };
}

export async function readPlan(client: TargetClient): Promise<TransitionPlan> {
  const capabilities = parseCapabilities(await client.get(CAPABILITIES_PATH));
  return parsePlan(await client.get(capabilities.planPath), capabilities);
}

function dryRunReceipt(plan: TransitionPlan): Receipt {
  return makeReceipt({
    format: RECEIPT_FORMAT,
    mode: "dry-run",
    plan_sha256: plan.planDigest,
    transition: plan.capabilities.transitionName,
    candidate_count: plan.candidates.length,
    planned_change_count: plan.plannedChangeCount,
    changed_count: 0,
    already_unlimited_count: plan.candidates.length - plan.plannedChangeCount,
    identity_preserved_count: plan.candidates.length,
    grants_preserved_count: plan.candidates.length,
    history_preserved_count: plan.candidates.length,
    balance_preserved_count: plan.candidates.length,
    current_credentials_preserved_count: plan.candidates.length,
    revoked_excluded: true,
    balance_exhaustion_disabled: true,
    atomic_cas: true,
    idempotent: true,
  });
}

function applyResult(value: unknown, plan: TransitionPlan, approval: Receipt): Receipt {
  const root = object(value, ["already_unlimited_count", "atomic_cas", "balance_exhaustion_disabled", "balance_preserved_count", "candidate_count", "changed_count", "contract", "current_credentials_preserved_count", "grants_preserved_count", "history_preserved_count", "idempotent", "identity_preserved_count", "observed_plan_sha256", "approved_plan_sha256", "revoked_excluded", "transition"], "transition apply receipt");
  if (root["contract"] !== "active-migration-key-unlimited" || root["transition"] !== plan.capabilities.transitionName || digest(root["approved_plan_sha256"], "transition apply receipt") !== approval.plan_sha256 || digest(root["observed_plan_sha256"], "transition apply receipt") !== plan.planDigest) throw new TransitionFailure("transition apply receipt does not match the approved plan");
  const candidateCount = nonNegativeInteger(root["candidate_count"], "transition apply receipt");
  const changedCount = nonNegativeInteger(root["changed_count"], "transition apply receipt");
  const alreadyUnlimitedCount = nonNegativeInteger(root["already_unlimited_count"], "transition apply receipt");
  if (candidateCount !== plan.candidates.length || changedCount + alreadyUnlimitedCount !== candidateCount || !bool(root["atomic_cas"], "transition apply receipt") || !bool(root["balance_exhaustion_disabled"], "transition apply receipt") || !bool(root["idempotent"], "transition apply receipt") || !bool(root["revoked_excluded"], "transition apply receipt")) throw new TransitionFailure("transition apply receipt does not prove the required result");
  const preserved = ["identity_preserved_count", "grants_preserved_count", "history_preserved_count", "balance_preserved_count", "current_credentials_preserved_count"].map((field) => nonNegativeInteger(root[field], "transition apply receipt"));
  if (preserved.some((count) => count !== candidateCount)) throw new TransitionFailure("transition apply receipt does not preserve existing state");
  return makeReceipt({
    format: RECEIPT_FORMAT,
    mode: "apply",
    plan_sha256: plan.planDigest,
    approved_dry_run_receipt_sha256: approval.receipt_sha256,
    transition: plan.capabilities.transitionName,
    candidate_count: candidateCount,
    planned_change_count: plan.plannedChangeCount,
    changed_count: changedCount,
    already_unlimited_count: alreadyUnlimitedCount,
    identity_preserved_count: preserved[0]!,
    grants_preserved_count: preserved[1]!,
    history_preserved_count: preserved[2]!,
    balance_preserved_count: preserved[3]!,
    current_credentials_preserved_count: preserved[4]!,
    revoked_excluded: true,
    balance_exhaustion_disabled: true,
    atomic_cas: true,
    idempotent: true,
  });
}

/** A fresh plan is always read; apply remains tied to a prior immutable dry-run receipt. */
export async function runTransition(client: TargetClient, apply: boolean, approvedDryRun?: Receipt): Promise<Receipt> {
  const plan = await readPlan(client);
  if (!apply) return dryRunReceipt(plan);
  if (!approvedDryRun) throw new TransitionFailure("apply requires a matching dry-run receipt");
  const approved = parseReceipt(approvedDryRun);
  if (approved.mode !== "dry-run" || approved.transition !== plan.capabilities.transitionName) throw new TransitionFailure("apply requires a matching dry-run receipt");
  const operationKey = `active-migration-key-unlimited-v1-${sha256(approved.receipt_sha256)}`;
  const result = await client.post(plan.capabilities.applyPath, {
    approved_plan_sha256: approved.plan_sha256,
    observed_plan_sha256: plan.planDigest,
    idempotency_key: operationKey,
  });
  return applyResult(result, plan, approved);
}

function readProtectedFile(path: string, label: string, limit: number): Buffer {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o600) throw new TransitionFailure(`${label} is not an owner-only regular file`);
    const output = Buffer.allocUnsafe(limit + 1);
    let offset = 0;
    while (offset < output.length) {
      const read = readSync(descriptor, output, offset, output.length - offset, null);
      if (read === 0) break;
      offset += read;
    }
    if (offset > limit) throw new TransitionFailure(`${label} exceeds the size limit`);
    return Buffer.from(output.subarray(0, offset));
  } catch (error) {
    if (error instanceof TransitionFailure) throw error;
    throw new TransitionFailure(`${label} is not safely readable`);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function decodeJson(raw: Buffer, label: string): unknown {
  try { return parseStrictJson(new TextDecoder("utf-8", { fatal: true }).decode(raw)); }
  catch { throw new TransitionFailure(`${label} is invalid`); }
}

function targetBase(value: string, allowHttp: boolean): string {
  let url: URL;
  try { url = new URL(value); }
  catch { throw new TransitionFailure("target API URL is invalid"); }
  if ((url.protocol !== "https:" && !(allowHttp && url.protocol === "http:")) || !url.hostname || url.username || url.password || url.search || url.hash || (url.pathname !== "" && url.pathname !== "/")) throw new TransitionFailure("target API URL is invalid");
  return url.origin;
}

function token(path: string): string {
  const raw = readProtectedFile(path, "service token", 16 * 1024);
  const value = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  const trimmed = value.trim();
  if (!trimmed || (value !== trimmed && value.replace(/[\r\n]+$/, "") !== trimmed) || /[\0\r\n]/.test(trimmed)) throw new TransitionFailure("service token is invalid");
  return trimmed;
}

async function readResponse(response: Response): Promise<unknown> {
  if (!response.ok || !response.headers.get("content-type")?.toLowerCase().startsWith("application/json")) throw new TransitionFailure("target rejected the transition request");
  if (!response.body) throw new TransitionFailure("target response is invalid");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.length;
      if (size > MAX_HTTP_BYTES) throw new TransitionFailure("target response exceeds the size limit");
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  return decodeJson(Buffer.concat(chunks), "target response");
}

function httpClient(baseUrl: string, serviceToken: string): TargetClient {
  const request = async (method: "GET" | "POST", path: string, body?: JsonObject): Promise<unknown> => {
    try {
      const response = await fetch(`${baseUrl}${path}`, {
        method,
        redirect: "error",
        headers: { authorization: `Bearer ${serviceToken}`, accept: "application/json", ...(body ? { "content-type": "application/json" } : {}) },
        ...(body ? { body: JSON.stringify(body) } : {}),
        signal: AbortSignal.timeout(30_000),
      });
      return await readResponse(response);
    } catch (error) {
      if (error instanceof TransitionFailure) throw error;
      throw new TransitionFailure("target request failed safely");
    }
  };
  return { get: async (path) => await request("GET", path), post: async (path, body) => await request("POST", path, body) };
}

function createReceiptFile(path: string): { descriptor: number; abort: () => void } {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    if ((fstatSync(descriptor).mode & 0o777) !== 0o600) throw new TransitionFailure("receipt file permissions are unsafe");
    return {
      descriptor,
      abort: () => {
        if (descriptor !== undefined) {
          try { closeSync(descriptor); } catch {}
          descriptor = undefined;
        }
        try { unlinkSync(path); } catch {}
      },
    };
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    if (error instanceof TransitionFailure) throw error;
    throw new TransitionFailure("receipt file must be a new owner-only path");
  }
}

function writeReceipt(path: string, receipt: Receipt, reserved: { descriptor: number; abort: () => void }): void {
  try {
    const bytes = Buffer.from(`${JSON.stringify(receipt)}\n`);
    let offset = 0;
    while (offset < bytes.length) {
      const written = writeSync(reserved.descriptor, bytes, offset, bytes.length - offset);
      if (written <= 0) throw new TransitionFailure("receipt could not be committed");
      offset += written;
    }
    fsyncSync(reserved.descriptor);
    closeSync(reserved.descriptor);
  } catch {
    reserved.abort();
    throw new TransitionFailure("receipt could not be committed; replay the approved operation to a new receipt path");
  }
  void path;
}

type Options = Readonly<{ target?: string; tokenFile?: string; receiptFile?: string; approvedReceiptFile?: string; apply: boolean; allowHttp: boolean }>;

function args(argv: string[]): Options {
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write("usage: transition-active-migration-keys-to-unlimited --target-api-base-url URL --service-token-file FILE --receipt-file NEW_FILE [--apply --approved-dry-run-receipt-file FILE] [--allow-http-target]\n\nDry-run is the default. The target must advertise an atomic, idempotent, balance-unrestricted policy transition.\n");
    process.exit(0);
  }
  const output: { target?: string; tokenFile?: string; receiptFile?: string; approvedReceiptFile?: string; apply: boolean; allowHttp: boolean } = { apply: false, allowHttp: false };
  const valued: Record<string, "target" | "tokenFile" | "receiptFile" | "approvedReceiptFile"> = { "--target-api-base-url": "target", "--service-token-file": "tokenFile", "--receipt-file": "receiptFile", "--approved-dry-run-receipt-file": "approvedReceiptFile" };
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index]!;
    if (item === "--apply") output.apply = true;
    else if (item === "--allow-http-target") output.allowHttp = true;
    else if (valued[item]) {
      const value = argv[++index];
      if (!value) throw new TransitionFailure("an option requires a value");
      output[valued[item]!] = value;
    } else throw new TransitionFailure("an unsupported option was supplied");
  }
  if (!output.target || !output.tokenFile || !output.receiptFile || (output.apply !== Boolean(output.approvedReceiptFile))) throw new TransitionFailure("target, token, receipt, and matching apply approval are required");
  return output;
}

async function main(): Promise<void> {
  const options = args(process.argv.slice(2));
  const reserved = createReceiptFile(options.receiptFile!);
  let receiptCommitted = false;
  try {
    const approved = options.approvedReceiptFile ? parseReceipt(decodeJson(readProtectedFile(options.approvedReceiptFile, "approved dry-run receipt", MAX_RECEIPT_BYTES), "approved dry-run receipt")) : undefined;
    const receipt = await runTransition(httpClient(targetBase(options.target!, options.allowHttp), token(options.tokenFile!)), options.apply, approved);
    writeReceipt(options.receiptFile!, receipt, reserved);
    receiptCommitted = true;
    process.stdout.write(`${JSON.stringify({ mode: receipt.mode, transition: receipt.transition, candidate_count: receipt.candidate_count, planned_change_count: receipt.planned_change_count, changed_count: receipt.changed_count, already_unlimited_count: receipt.already_unlimited_count, receipt_sha256: receipt.receipt_sha256 })}\n`);
  } catch (error) {
    if (!receiptCommitted) reserved.abort();
    throw error;
  }
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main().catch((error: unknown) => {
    process.stderr.write(`active migration unlimited transition: ${error instanceof TransitionFailure ? error.message : "failed safely"}\n`);
    process.exitCode = 2;
  });
}
