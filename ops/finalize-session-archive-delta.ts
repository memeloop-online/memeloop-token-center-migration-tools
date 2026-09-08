#!/usr/bin/env node
/**
 * Seal a final offline snapshot plus its ordered deltas before delegating to
 * the isolated archive importer.  It never decodes archive JSONL or emits
 * payload, ticket, database, or credential material.
 */

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { canonicalBytes, formatTime, parseTime, sha256Bytes, STABLE_CURSOR_PROTOCOL } from "./export-cpa-session-archive-delta.ts";
import { parseStrictJson } from "./lib/strict-json.ts";

const WORKFLOW = "final-session-archive-delta-v1";
const MAX_DIGESTED_FILE_BYTES = 1_099_511_627_776;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const SHA256 = /^[0-9a-f]{64}$/;

type JsonObject = Record<string, unknown>;

export class FinalArchiveError extends Error {}

export type FinalArtifact = Readonly<{
  sequence: number;
  outputSha256: string;
  outputSizeBytes: number;
  sourceFingerprint: string;
  priorOutputSha256: string | null;
  priorWatermarkCompletedAt: string;
  watermarkCompletedAt: string;
  priorIngestFence: string | null;
  ingestFence: string;
  sourceRecordsAfter: number;
  overlapSeconds: number;
  stableSourceRequired: boolean;
}>;

export type FinalArtifactSet = Readonly<{
  artifactSetSha256: string;
  sourceFingerprint: string;
  finalArtifact: FinalArtifact;
  artifacts: readonly FinalArtifact[];
}>;

type Arguments = Readonly<{
  artifacts: readonly string[];
  receipt: string;
  apply: boolean;
  approvalFile?: string;
  migrationWindowId?: string;
  tenantExternalId?: string;
  archiveSource?: string;
  cpampSource?: string;
  expectedCpampRecords?: string;
  overlapMs?: string;
  planDirectory?: string;
}>;

type AggregateAudit = Readonly<{
  archive_checkpoint: number;
  archive_correlated: number;
  archive_exact: number;
  archive_unlinked: number;
  archive_watermark_ms: number;
  content_locators: number;
  exact_content_locators: number;
  unlinked_content_locators: number;
  conversation_clusters: number;
  conversation_edges: number;
  conversation_observations: number;
  cpamp_checkpoint: number;
  cpamp_links: number;
  gap_locators: number;
  unresolved_quarantine: number;
}>;

function fail(message: string): never { throw new FinalArchiveError(message); }

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function privateRegular(path: string, label: string): void {
  let metadata;
  try { metadata = lstatSync(path, { bigint: true }); } catch { fail(`${label} is unavailable`); }
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077n) !== 0n) fail(`${label} must be a private regular file`);
  if (metadata.size > BigInt(MAX_DIGESTED_FILE_BYTES)) fail(`${label} exceeds the finalization size ceiling`);
}

function jsonFile(path: string, label: string): JsonObject {
  privateRegular(path, label);
  try {
    const value = parseStrictJson(readFileSync(path, "utf8"));
    if (!isObject(value)) fail(`${label} is invalid`);
    return value;
  } catch (error) {
    if (error instanceof FinalArchiveError) throw error;
    fail(`${label} is invalid`);
  }
}

function unsigned(value: unknown, label: string, nonzero = false): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (nonzero && value === 0)) fail(`${label} is invalid`);
  return value as number;
}

function digestFile(path: string, label: string): { size: number; sha256: string } {
  privateRegular(path, label);
  let descriptor = -1;
  try {
    descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const before = fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || (before.mode & 0o077n) !== 0n || before.size > BigInt(MAX_DIGESTED_FILE_BYTES)) fail(`${label} changed while being sealed`);
    const digest = createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let total = 0;
    while (true) {
      const length = readSync(descriptor, buffer, 0, buffer.length, null);
      if (length === 0) break;
      total += length;
      if (total > MAX_DIGESTED_FILE_BYTES) fail(`${label} exceeds the finalization size ceiling`);
      digest.update(buffer.subarray(0, length));
    }
    const after = fstatSync(descriptor, { bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || BigInt(total) !== after.size) fail(`${label} changed while being sealed`);
    return { size: total, sha256: digest.digest("hex") };
  } catch (error) {
    if (error instanceof FinalArchiveError) throw error;
    return fail(`${label} could not be sealed`);
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
}

function canonicalTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string" || formatTime(parseTime(value, label)) !== value) fail(`${label} is invalid`);
  return value;
}

function ingestFence(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^(?:0|[1-9]\d{0,18})$/.test(value) || BigInt(value) > 9_223_372_036_854_775_807n) fail(`${label} is invalid`);
  return value;
}

function sha256(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) fail(`${label} is invalid`);
  return value;
}

function optionalSha256(value: unknown, label: string): string | null {
  return value === null ? null : sha256(value, label);
}

/**
 * Reads only envelope metadata plus a byte stream for hashing. Archive JSONL
 * remains opaque to this coordinator and is parsed solely by the importer.
 */
export function readFinalArtifact(path: string): FinalArtifact {
  const manifest = jsonFile(`${path}.manifest.json`, "delta manifest");
  if (manifest.version !== 3 || manifest.output_file !== basename(path) || manifest.session_projection_protocol !== STABLE_CURSOR_PROTOCOL
      || manifest.source_mode !== "collector-direct" || manifest.snapshot_schema_version !== 2 || manifest.deleted_session_count === undefined
      || typeof manifest.source_fingerprint !== "string" || !SHA256.test(manifest.source_fingerprint) || typeof manifest.offline_full_snapshot !== "boolean"
      || typeof manifest.stable_source_required !== "boolean") fail("delta manifest is not a final stable-snapshot artifact");
  const sequence = unsigned(manifest.sequence, "delta sequence", true);
  const outputSizeBytes = unsigned(manifest.output_size_bytes, "delta output size");
  const sourceRecordsAfter = unsigned(manifest.source_records_after, "source record count", true);
  const overlapSeconds = unsigned(manifest.overlap_seconds, "delta overlap", true);
  unsigned(manifest.record_count, "delta record count");
  unsigned(manifest.deleted_session_count, "deleted session count");
  const sealed = digestFile(path, "delta artifact");
  const outputSha256 = sha256(manifest.output_sha256, "delta output digest");
  if (sealed.size !== outputSizeBytes || sealed.sha256 !== outputSha256) fail("delta artifact does not match its manifest");
  return {
    sequence,
    outputSha256,
    outputSizeBytes,
    sourceFingerprint: manifest.source_fingerprint,
    priorOutputSha256: optionalSha256(manifest.prior_output_sha256, "prior delta output digest"),
    priorWatermarkCompletedAt: canonicalTimestamp(manifest.prior_watermark_completed_at, "prior delta watermark"),
    watermarkCompletedAt: canonicalTimestamp(manifest.watermark_completed_at, "delta watermark"),
    priorIngestFence: manifest.prior_source_ingest_fence === null ? null : ingestFence(manifest.prior_source_ingest_fence, "prior ingest fence"),
    ingestFence: ingestFence(manifest.source_ingest_fence, "ingest fence"),
    sourceRecordsAfter,
    overlapSeconds,
    stableSourceRequired: manifest.stable_source_required,
  };
}

export function validateFinalArtifactSet(paths: readonly string[]): FinalArtifactSet {
  if (paths.length < 2) fail("a final snapshot and at least one delta are required");
  const artifacts = paths.map(readFinalArtifact);
  const first = artifacts[0]!;
  if (first.sequence !== 1 || first.priorOutputSha256 !== null || first.priorIngestFence !== null) fail("the first artifact is not an offline baseline transition");
  const firstManifest = jsonFile(`${paths[0]!}.manifest.json`, "baseline manifest");
  if (firstManifest.offline_full_snapshot !== true) fail("the first artifact is not an offline full snapshot");
  for (let index = 1; index < artifacts.length; index += 1) {
    const previous = artifacts[index - 1]!;
    const current = artifacts[index]!;
    const manifest = jsonFile(`${paths[index]!}.manifest.json`, "delta manifest");
    if (manifest.offline_full_snapshot !== false || current.sequence !== previous.sequence + 1 || current.sourceFingerprint !== first.sourceFingerprint
        || current.priorOutputSha256 !== previous.outputSha256 || current.priorWatermarkCompletedAt !== previous.watermarkCompletedAt
        || current.priorIngestFence !== previous.ingestFence) fail("final artifacts are not one contiguous snapshot-to-delta chain");
  }
  const finalArtifact = artifacts.at(-1)!;
  if (!finalArtifact.stableSourceRequired) fail("the final delta was not exported under the source stability requirement");
  const receiptProjection = artifacts.map((artifact) => ({
    sequence: artifact.sequence,
    output_sha256: artifact.outputSha256,
    output_size_bytes: artifact.outputSizeBytes,
    watermark_completed_at: artifact.watermarkCompletedAt,
    source_ingest_fence: artifact.ingestFence,
  }));
  return {
    artifactSetSha256: sha256Bytes(canonicalBytes({ workflow: WORKFLOW, source_fingerprint: first.sourceFingerprint, artifacts: receiptProjection })),
    sourceFingerprint: first.sourceFingerprint,
    finalArtifact,
    artifacts,
  };
}

function identifier(value: unknown, label: string): string {
  if (typeof value !== "string" || !SAFE_IDENTIFIER.test(value)) fail(`${label} is invalid`);
  return value;
}

function requiredApplyArguments(args: Arguments, set: FinalArtifactSet): Required<Pick<Arguments, "approvalFile" | "migrationWindowId" | "tenantExternalId" | "archiveSource" | "cpampSource" | "expectedCpampRecords" | "overlapMs" | "planDirectory">> {
  const expectedCpampRecords = args.expectedCpampRecords;
  if (expectedCpampRecords === undefined || !/^[1-9]\d*$/.test(expectedCpampRecords)) fail("expected CPAMP record count is invalid");
  const overlapMs = args.overlapMs;
  if (overlapMs === undefined || !/^\d+$/.test(overlapMs) || BigInt(overlapMs) < BigInt(set.artifacts.reduce((maximum, artifact) => Math.max(maximum, artifact.overlapSeconds), 0)) * 1000n) fail("target overlap is smaller than the sealed source overlap");
  if (args.approvalFile === undefined || args.migrationWindowId === undefined || args.tenantExternalId === undefined || args.archiveSource === undefined || args.cpampSource === undefined || args.planDirectory === undefined) fail("approved apply requires all target identity and plan arguments");
  return {
    approvalFile: args.approvalFile,
    migrationWindowId: identifier(args.migrationWindowId, "migration window"),
    tenantExternalId: identifier(args.tenantExternalId, "tenant external id"),
    archiveSource: identifier(args.archiveSource, "archive source"),
    cpampSource: identifier(args.cpampSource, "CPAMP source"),
    expectedCpampRecords,
    overlapMs,
    planDirectory: args.planDirectory,
  };
}

function verifyApproval(path: string, set: FinalArtifactSet, values: Required<Pick<Arguments, "migrationWindowId" | "tenantExternalId" | "archiveSource" | "cpampSource" | "expectedCpampRecords">>): string {
  const approval = jsonFile(path, "approval receipt");
  if (approval.version !== 1 || approval.workflow !== WORKFLOW || approval.artifact_set_sha256 !== set.artifactSetSha256
      || approval.migration_window_id !== values.migrationWindowId || approval.tenant_external_id !== values.tenantExternalId
      || approval.archive_source !== values.archiveSource || approval.cpamp_source !== values.cpampSource
      || approval.expected_cpamp_records !== values.expectedCpampRecords || typeof approval.approval_id !== "string" || !SAFE_IDENTIFIER.test(approval.approval_id)) fail("approval receipt does not authorize this final artifact set");
  canonicalTimestamp(approval.approved_at, "approval time");
  return sha256Bytes(readFileSync(path));
}

function receiptArtifact(artifact: FinalArtifact): JsonObject {
  return {
    sequence: artifact.sequence,
    output_sha256: artifact.outputSha256,
    output_size_bytes: artifact.outputSizeBytes,
    watermark_completed_at: artifact.watermarkCompletedAt,
    source_ingest_fence: artifact.ingestFence,
  };
}

function dryRunReceipt(set: FinalArtifactSet): JsonObject {
  return {
    contract: "final-session-archive-receipt-v1",
    mode: "dry-run",
    status: "sealed-awaiting-approved-apply",
    artifact_set_sha256: set.artifactSetSha256,
    artifacts: set.artifacts.map(receiptArtifact),
    checkpoint: { source_fingerprint: set.sourceFingerprint, final_sequence: set.finalArtifact.sequence, final_watermark_completed_at: set.finalArtifact.watermarkCompletedAt, final_ingest_fence: set.finalArtifact.ingestFence, expected_archive_records: set.finalArtifact.sourceRecordsAfter },
    correlation: { measurement: "not-performed" },
    provenance: { measurement: "not-performed" },
    quarantine: { measurement: "not-performed" },
    unlinked: { measurement: "not-performed" },
    content_locator: { measurement: "not-performed" },
  };
}

function writeReceipt(path: string, value: JsonObject): void {
  if (existsSync(path)) fail("receipt path already exists");
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = join(dirname(path), `.${basename(path)}.${process.pid}.${Date.now()}`);
  let descriptor = -1;
  try {
    descriptor = openSync(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    writeFileSync(descriptor, Buffer.concat([canonicalBytes(value), Buffer.from("\n")]));
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = -1;
    renameSync(temporary, path);
    const directory = openSync(dirname(path), fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
    try { fsyncSync(directory); } finally { closeSync(directory); }
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
    rmSync(temporary, { force: true });
  }
}

function mutedChild(command: string, args: readonly string[], env: NodeJS.ProcessEnv, label: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env, shell: false, stdio: ["ignore", "ignore", "ignore"] });
    child.once("error", () => reject(new FinalArchiveError(`${label} could not start`)));
    child.once("close", (status) => status === 0 ? resolve() : reject(new FinalArchiveError(`${label} failed without a receipt`)));
  });
}

function siblingCommand(name: string): string {
  // Source commands run directly as TypeScript, while the release artifact
  // uses the same reviewed basename as a bundled .mjs command.
  const extension = fileURLToPath(import.meta.url).endsWith(".mjs") ? ".mjs" : ".ts";
  return fileURLToPath(new URL(`./${name}${extension}`, import.meta.url));
}

function aggregateAudit(env: NodeJS.ProcessEnv): Promise<AggregateAudit> {
  const audit = siblingCommand("audit-cpa-migration");
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [audit], { env, shell: false, stdio: ["ignore", "pipe", "ignore"] });
    const chunks: Buffer[] = [];
    let length = 0;
    child.stdout?.on("data", (chunk: Buffer) => {
      length += chunk.length;
      if (length <= 16_384) chunks.push(chunk);
      else child.kill();
    });
    child.once("error", () => reject(new FinalArchiveError("aggregate audit could not start")));
    child.once("close", (status) => {
      if (status !== 0 || length > 16_384) { reject(new FinalArchiveError("aggregate audit failed without a receipt")); return; }
      try {
        const parsed = parseStrictJson(Buffer.concat(chunks).toString("utf8"));
        if (!isObject(parsed)) fail("aggregate audit receipt is invalid");
        const fields = ["archive_checkpoint", "archive_correlated", "archive_exact", "archive_unlinked", "archive_watermark_ms", "content_locators", "exact_content_locators", "unlinked_content_locators", "conversation_clusters", "conversation_edges", "conversation_observations", "cpamp_checkpoint", "cpamp_links", "gap_locators", "unresolved_quarantine"] as const;
        for (const field of fields) unsigned(parsed[field], "aggregate audit receipt");
        resolve(parsed as AggregateAudit);
      } catch {
        reject(new FinalArchiveError("aggregate audit receipt is invalid"));
      }
    });
  });
}

function sameAudit(left: AggregateAudit, right: AggregateAudit): boolean {
  return Buffer.compare(canonicalBytes(left), canonicalBytes(right)) === 0;
}

async function approvedApply(args: Arguments, set: FinalArtifactSet): Promise<JsonObject> {
  const values = requiredApplyArguments(args, set);
  const approvalSha256 = verifyApproval(values.approvalFile, set, values);
  const importer = siblingCommand("import-cpa-session-archive");
  const shared = {
    ...process.env,
    IMPORT_TENANT_EXTERNAL_ID: values.tenantExternalId,
    CPAMP_IMPORT_SOURCE: values.cpampSource,
    SESSION_ARCHIVE_IMPORT_SOURCE: values.archiveSource,
    SESSION_ARCHIVE_OVERLAP_MS: values.overlapMs,
    SESSION_ARCHIVE_PLAN_DIRECTORY: values.planDirectory,
    SESSION_ARCHIVE_ALLOW_UNMAPPED: "false",
    SESSION_ARCHIVE_APPLY: "true",
  };
  const assertStillSealed = (): void => {
    const current = validateFinalArtifactSet(args.artifacts);
    if (current.artifactSetSha256 !== set.artifactSetSha256) fail("final artifacts changed after approval");
  };
  assertStillSealed();
  for (const path of args.artifacts) await mutedChild(process.execPath, [importer], { ...shared, CPA_SESSION_ARCHIVE_INPUT: path }, "archive import");
  const auditEnvironment = {
    ...shared,
    EXPECTED_CPAMP_EVENTS: values.expectedCpampRecords,
    EXPECTED_ARCHIVE_RECORDS: String(set.finalArtifact.sourceRecordsAfter),
  };
  const beforeReplay = await aggregateAudit(auditEnvironment);
  assertStillSealed();
  for (const path of args.artifacts) await mutedChild(process.execPath, [importer], { ...shared, CPA_SESSION_ARCHIVE_INPUT: path }, "archive replay");
  const afterReplay = await aggregateAudit(auditEnvironment);
  if (!sameAudit(beforeReplay, afterReplay)) fail("same-file replay changed final archive aggregate receipts");
  return {
    contract: "final-session-archive-receipt-v1",
    mode: "apply",
    status: "reconciled",
    migration_window_id: values.migrationWindowId,
    approval_sha256: approvalSha256,
    artifact_set_sha256: set.artifactSetSha256,
    artifacts: set.artifacts.map(receiptArtifact),
    checkpoint: { expected_archive_records: set.finalArtifact.sourceRecordsAfter, imported_records: afterReplay.archive_checkpoint, watermark_ms: afterReplay.archive_watermark_ms },
    correlation: { total: afterReplay.archive_correlated, exact: afterReplay.archive_exact, unlinked: afterReplay.archive_unlinked },
    provenance: { exact_records: afterReplay.archive_exact },
    quarantine: { unresolved_records: afterReplay.unresolved_quarantine },
    unlinked: { projection_records: afterReplay.archive_unlinked, conversation_observations: afterReplay.conversation_observations, conversation_clusters: afterReplay.conversation_clusters, conversation_edges: afterReplay.conversation_edges },
    content_locator: { non_gap_records: afterReplay.content_locators, exact_non_gap_records: afterReplay.exact_content_locators, unlinked_non_gap_records: afterReplay.unlinked_content_locators, gap_records: afterReplay.gap_locators },
    idempotency_replay: { unchanged: true, aggregate_receipt_sha256: sha256Bytes(canonicalBytes(afterReplay)) },
  };
}

export function parseFinalizationArguments(argv: readonly string[]): Arguments {
  const { values } = parseArgs({ args: [...argv], strict: true, allowPositionals: false, options: {
    artifact: { type: "string", multiple: true, default: [] }, receipt: { type: "string" }, apply: { type: "boolean", default: false },
    "approval-file": { type: "string" }, "migration-window-id": { type: "string" }, "tenant-external-id": { type: "string" }, "archive-source": { type: "string" }, "cpamp-source": { type: "string" }, "expected-cpamp-records": { type: "string" }, "overlap-ms": { type: "string" }, "plan-directory": { type: "string" },
  } });
  if (typeof values.receipt !== "string" || values.receipt.length === 0) fail("--receipt is required");
  return {
    artifacts: values.artifact as string[], receipt: values.receipt, apply: values.apply === true,
    approvalFile: values["approval-file"] as string | undefined, migrationWindowId: values["migration-window-id"] as string | undefined,
    tenantExternalId: values["tenant-external-id"] as string | undefined, archiveSource: values["archive-source"] as string | undefined,
    cpampSource: values["cpamp-source"] as string | undefined, expectedCpampRecords: values["expected-cpamp-records"] as string | undefined,
    overlapMs: values["overlap-ms"] as string | undefined, planDirectory: values["plan-directory"] as string | undefined,
  };
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  const args = parseFinalizationArguments(argv);
  const set = validateFinalArtifactSet(args.artifacts);
  const receipt = args.apply ? await approvedApply(args, set) : dryRunReceipt(set);
  writeReceipt(args.receipt, receipt);
  process.stdout.write(`${canonicalBytes({ artifact_set_sha256: set.artifactSetSha256, mode: args.apply ? "apply" : "dry-run", status: receipt.status }).toString("utf8")}\n`);
  return 0;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then((code) => { process.exitCode = code; }).catch((error: unknown) => {
    process.stderr.write(`${error instanceof FinalArchiveError ? error.message : "final archive reconciliation failed"}\n`);
    process.exitCode = 2;
  });
}
