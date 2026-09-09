#!/usr/bin/env node
/**
 * Compose the exact provider-candidate bindings into the reviewed upstream
 * inventory shape. This is an offline, no-API, no-route-decision step.
 */

import { createHash, randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, openSync, unlinkSync, writeSync } from "node:fs";
import { basename, dirname, isAbsolute, parse, relative, resolve, sep } from "node:path";
import { invokedAsEntrypoint } from "../lib/invoked-as-entrypoint.ts";
import { parseStrictJson } from "../lib/strict-json.ts";
import { parseSourceInventory, readProtected } from "./import-cpa-model-routes.ts";

const SHA256 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TENANT = /^[A-Za-z0-9._:-]{1,200}$/;
const MAX_ITEMS = 1_000;

type JsonObject = Record<string, unknown>;
type Driver = "http-json" | "openai-codex";
type Protocol = "openai" | "anthropic";
type SourcePattern = Readonly<{ provider: string; model: string; group: string | null; upstreamPrefix: string | null; protocol: Protocol }>;
type Candidate = Readonly<{ sourceStableId: string; sourceProvider: string; driver: Driver }>;
type CandidateSet = Readonly<{ source: SourcePattern; upstreamModel: string; protocol: Protocol; candidates: readonly Candidate[] }>;
type CandidateMaterial = Readonly<{ sourceDigest: string; sets: readonly CandidateSet[]; candidates: ReadonlyMap<string, Candidate> }>;
type Binding = Readonly<{ sourceStableId: string; sourceProvider: string; accountId: string; driver: Driver; updatedAt: number }>;
type BindingReceipt = Readonly<{ tenant: string; sourceDigest: string; candidateMaterialDigest: string; bindings: readonly Binding[]; quarantined: number }>;
type ComposedInventory = Readonly<{ inventory: Buffer; receipt: Readonly<Record<string, number | string>>; batchReceipt?: Buffer }>;
type OutputTarget = Readonly<{ target: string; parentDescriptor: number }>;

export class UpstreamInventoryComposeFailure extends Error {}

const digest = (value: Uint8Array | string): string => createHash("sha256").update(value).digest("hex");
const compare = (left: string, right: string): number => left < right ? -1 : left > right ? 1 : 0;

function object(value: unknown, keys: readonly string[], label: string): JsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new UpstreamInventoryComposeFailure(`${label} has an invalid schema`);
  const actual = Object.keys(value as JsonObject).sort(compare), expected = [...keys].sort(compare);
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new UpstreamInventoryComposeFailure(`${label} has an invalid schema`);
  return value as JsonObject;
}
function text(value: unknown, label: string, pattern?: RegExp): string {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || Buffer.byteLength(value) > 500 || /[\0\r\n]/.test(value) || (pattern && !pattern.test(value))) throw new UpstreamInventoryComposeFailure(`${label} has an invalid schema`);
  return value;
}
function integer(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0 || Number(value) > 1_000_000_000_000_000) throw new UpstreamInventoryComposeFailure(`${label} has an invalid schema`);
  return Number(value);
}
function strictJson(raw: Buffer, label: string): unknown {
  try { return parseStrictJson(new TextDecoder("utf-8", { fatal: true }).decode(raw)); }
  catch { throw new UpstreamInventoryComposeFailure(`${label} is not strict UTF-8 JSON`); }
}
function protocol(value: unknown, label: string): Protocol {
  if (value !== "openai" && value !== "anthropic") throw new UpstreamInventoryComposeFailure(`${label} has an invalid schema`);
  return value;
}
function driver(value: unknown, label: string): Driver {
  if (value !== "http-json" && value !== "openai-codex") throw new UpstreamInventoryComposeFailure(`${label} has an unsupported driver`);
  return value;
}
function sourcePattern(value: unknown, label: string): SourcePattern {
  const item = object(value, ["provider", "model", "group", "upstream_prefix", "protocol"], label);
  const group = item.group === null ? null : text(item.group, label), upstreamPrefix = item.upstream_prefix === null ? null : text(item.upstream_prefix, label);
  return { provider: text(item.provider, label), model: text(item.model, label), group, upstreamPrefix, protocol: protocol(item.protocol, label) };
}
function sourceKey(value: SourcePattern): string { return JSON.stringify([value.provider, value.model, value.group, value.upstreamPrefix, value.protocol]); }
function exactSet(left: readonly string[], right: readonly string[], label: string): void {
  const sortedLeft = [...left].sort(compare), sortedRight = [...right].sort(compare);
  if (new Set(sortedLeft).size !== sortedLeft.length || new Set(sortedRight).size !== sortedRight.length || sortedLeft.length !== sortedRight.length || sortedLeft.some((value, index) => value !== sortedRight[index])) throw new UpstreamInventoryComposeFailure(label);
}

// Shared schema and set-coverage validation for read-only transport receipts.
export { parseCandidateMaterial, sourceKey, exactSet };

function parseCandidateMaterial(raw: Buffer): CandidateMaterial {
  const root = object(strictJson(raw, "provider candidate material"), ["version", "source_inventory_sha256", "provider_candidate_sets"], "provider candidate material");
  if (root.version !== 1 || !Array.isArray(root.provider_candidate_sets) || root.provider_candidate_sets.length === 0 || root.provider_candidate_sets.length > MAX_ITEMS) throw new UpstreamInventoryComposeFailure("provider candidate material has an invalid schema");
  const candidates = new Map<string, Candidate>();
  const sets = root.provider_candidate_sets.map((value) => {
    const item = object(value, ["source", "upstream_model", "protocol", "selection", "candidates"], "provider candidate set");
    const source = sourcePattern(item.source, "provider candidate set source"), targetProtocol = protocol(item.protocol, "provider candidate set");
    if (targetProtocol !== source.protocol || item.selection !== "equal_round_robin" || !Array.isArray(item.candidates) || item.candidates.length === 0 || item.candidates.length > MAX_ITEMS) throw new UpstreamInventoryComposeFailure("provider candidate set has an invalid schema");
    const pool = item.candidates.map((entry) => {
      const candidate = object(entry, ["source_stable_id", "source_provider", "driver"], "provider source candidate");
      const result: Candidate = { sourceStableId: text(candidate.source_stable_id, "provider source candidate", SHA256), sourceProvider: text(candidate.source_provider, "provider source candidate"), driver: driver(candidate.driver, "provider source candidate") };
      if (result.sourceProvider !== source.provider) throw new UpstreamInventoryComposeFailure("provider candidate source does not match its pool");
      const prior = candidates.get(result.sourceStableId);
      if (prior && (prior.sourceProvider !== result.sourceProvider || prior.driver !== result.driver)) throw new UpstreamInventoryComposeFailure("provider candidate material has conflicting source identities");
      candidates.set(result.sourceStableId, result);
      return result;
    }).sort((left, right) => compare(left.sourceStableId, right.sourceStableId));
    if (new Set(pool.map((candidate) => candidate.sourceStableId)).size !== pool.length || new Set(pool.map((candidate) => candidate.driver)).size !== 1) throw new UpstreamInventoryComposeFailure("provider candidate set is not an exact homogeneous pool");
    return { source, upstreamModel: text(item.upstream_model, "provider candidate set"), protocol: targetProtocol, candidates: pool };
  }).sort((left, right) => compare(sourceKey(left.source), sourceKey(right.source)));
  if (new Set(sets.map((item) => sourceKey(item.source))).size !== sets.length || candidates.size === 0) throw new UpstreamInventoryComposeFailure("provider candidate material has duplicate or empty pools");
  return { sourceDigest: text(root.source_inventory_sha256, "provider candidate material", SHA256), sets, candidates };
}

function parseBinding(value: unknown, expectedDriver: Driver, label: string): Binding {
  const item = object(value, ["source_stable_id", "source_provider", "upstream_account_id", "driver", "status", "updated_at"], label);
  if (item.status !== "active" || item.driver !== expectedDriver) throw new UpstreamInventoryComposeFailure(`${label} has an invalid status or driver`);
  return {
    sourceStableId: text(item.source_stable_id, label, SHA256),
    sourceProvider: text(item.source_provider, label),
    accountId: text(item.upstream_account_id, label, UUID),
    driver: expectedDriver,
    updatedAt: integer(item.updated_at, label),
  };
}
function parseQuarantine(value: unknown, label: string): void {
  const item = object(value, ["source_stable_id", "source_provider", "reason"], label);
  text(item.source_stable_id, label, SHA256); text(item.source_provider, label); text(item.reason, label);
}
function parseBindingReceipt(raw: Buffer, kind: "direct" | "managed"): BindingReceipt {
  const parsed = strictJson(raw, `${kind} binding receipt`);
  const expected = kind === "direct"
    ? ["version", "tenant_external_id", "source_inventory_sha256", "provider_candidate_material_sha256", "bindings", "quarantined"]
    : ["version", "tenant_external_id", "source_inventory_sha256", "provider_candidate_material_sha256", "managed_provenance_evidence_sha256", "bindings", "quarantined"];
  const root = object(parsed, expected, `${kind} binding receipt`);
  if (root.version !== 1 || !Array.isArray(root.bindings) || !Array.isArray(root.quarantined) || root.bindings.length > MAX_ITEMS || root.quarantined.length > MAX_ITEMS) throw new UpstreamInventoryComposeFailure(`${kind} binding receipt has an invalid schema`);
  if (kind === "managed") text(root.managed_provenance_evidence_sha256, "managed binding receipt provenance evidence", SHA256);
  const expectedDriver: Driver = kind === "direct" ? "http-json" : "openai-codex";
  const bindings = root.bindings.map((value) => parseBinding(value, expectedDriver, `${kind} binding receipt binding`)).sort((left, right) => compare(left.sourceStableId, right.sourceStableId));
  for (const value of root.quarantined) parseQuarantine(value, `${kind} binding receipt quarantine`);
  if (new Set(bindings.map((binding) => binding.sourceStableId)).size !== bindings.length || new Set(bindings.map((binding) => binding.accountId)).size !== bindings.length) throw new UpstreamInventoryComposeFailure(`${kind} binding receipt has duplicate bindings`);
  return {
    tenant: text(root.tenant_external_id, `${kind} binding receipt tenant`, TENANT),
    sourceDigest: text(root.source_inventory_sha256, `${kind} binding receipt`, SHA256),
    candidateMaterialDigest: text(root.provider_candidate_material_sha256, `${kind} binding receipt`, SHA256),
    bindings,
    quarantined: root.quarantined.length,
  };
}

/** Construct, but never publish, a complete version 2 upstream inventory. */
export function composeUpstreamInventory(sourceRaw: Buffer, candidateMaterialRaw: Buffer, directReceiptRaw: Buffer, managedReceiptRaw?: Buffer, directBatchPreflight = false): ComposedInventory {
  const sourceDigest = digest(sourceRaw), materialDigest = digest(candidateMaterialRaw);
  let source: ReturnType<typeof parseSourceInventory>;
  try { source = parseSourceInventory(sourceRaw); }
  catch { throw new UpstreamInventoryComposeFailure("source inventory has an invalid schema"); }
  if (source.version !== 2) throw new UpstreamInventoryComposeFailure("upstream inventory composition requires a version 2 source inventory");
  if (directBatchPreflight ? managedReceiptRaw !== undefined : managedReceiptRaw === undefined) throw new UpstreamInventoryComposeFailure("direct preflight and full composition require distinct binding inputs");
  const material = parseCandidateMaterial(candidateMaterialRaw), direct = parseBindingReceipt(directReceiptRaw, "direct");
  const managed = managedReceiptRaw === undefined ? { ...direct, bindings: [], quarantined: 0 } : parseBindingReceipt(managedReceiptRaw, "managed");
  if (material.sourceDigest !== sourceDigest || direct.sourceDigest !== sourceDigest || managed.sourceDigest !== sourceDigest) throw new UpstreamInventoryComposeFailure("binding inputs do not share the selected source inventory");
  if (direct.candidateMaterialDigest !== materialDigest || managed.candidateMaterialDigest !== materialDigest) throw new UpstreamInventoryComposeFailure("binding inputs do not share the selected provider candidate material");
  if (direct.tenant !== managed.tenant) throw new UpstreamInventoryComposeFailure("binding receipts select different tenants");
  if (direct.quarantined !== 0 || managed.quarantined !== 0) throw new UpstreamInventoryComposeFailure("binding receipts contain quarantined candidates");
  exactSet(source.mappings.map(sourceKey), material.sets.map((item) => sourceKey(item.source)), "provider candidate pools do not exactly cover the source mappings");
  const selectedSets = directBatchPreflight ? material.sets.filter((set) => set.candidates.every((item) => item.driver === "http-json")) : material.sets;
  if (directBatchPreflight && selectedSets.length === 0) throw new UpstreamInventoryComposeFailure("direct preflight has no complete direct pools");
  const selectedIds = new Set(selectedSets.flatMap((set) => set.candidates.map((item) => item.sourceStableId)));

  const bindings = [...direct.bindings, ...managed.bindings];
  if (new Set(bindings.map((binding) => binding.sourceStableId)).size !== bindings.length || new Set(bindings.map((binding) => binding.accountId)).size !== bindings.length) throw new UpstreamInventoryComposeFailure("binding receipts overlap on a source or target account");
  const bound = new Map(bindings.map((binding) => [binding.sourceStableId, binding]));
  exactSet([...selectedIds], [...bound.keys()], "binding receipts do not exactly cover the provider candidates");
  for (const [stableId, candidate] of material.candidates) {
    if (!selectedIds.has(stableId)) continue;
    const binding = bound.get(stableId);
    if (!binding || binding.sourceProvider !== candidate.sourceProvider || binding.driver !== candidate.driver) throw new UpstreamInventoryComposeFailure("binding receipt does not match its exact provider candidate");
  }

  const upstreams = [...bound.values()].sort((left, right) => compare(left.accountId, right.accountId));
  const inventory = Buffer.from(`${JSON.stringify({
    version: 2,
    tenant_external_id: direct.tenant,
    upstreams: upstreams.map((binding) => ({ upstream_account_id: binding.accountId, source_stable_id: binding.sourceStableId, source_provider: binding.sourceProvider, driver: binding.driver, status: "active", updated_at: binding.updatedAt })),
    provider_candidate_sets: selectedSets.map((set) => ({
      source: { provider: set.source.provider, model: set.source.model, group: set.source.group, upstream_prefix: set.source.upstreamPrefix, protocol: set.source.protocol },
      upstream_model: set.upstreamModel,
      protocol: set.protocol,
      selection: "equal_round_robin",
      candidates: set.candidates.map((candidate) => {
        const binding = bound.get(candidate.sourceStableId);
        if (!binding) throw new UpstreamInventoryComposeFailure("provider candidate is unexpectedly unbound");
        return { upstream_account_id: binding.accountId, source_stable_id: candidate.sourceStableId };
      }).sort((left, right) => compare(left.upstream_account_id, right.upstream_account_id)),
    })),
  })}\n`);
  const sourceDocument = strictJson(sourceRaw, "source inventory") as JsonObject;
  const selectedKeys = new Set(selectedSets.map((set) => sourceKey(set.source)));
  const deferredMappings = source.mappings.filter((item) => !selectedKeys.has(sourceKey(item)));
  // Retain the complete sealed evidence, not a filtered source or policy. Raw
  // UTF-8 inputs preserve the exact digest binding when the importer recomposes.
  const batchReceipt = directBatchPreflight ? Buffer.from(`${JSON.stringify({
    version: 1, mode: "direct-route-batch-preflight-only",
    source_inventory_sha256: sourceDigest,
    provider_candidate_material_sha256: materialDigest,
    direct_binding_receipt_sha256: digest(directReceiptRaw),
    upstream_inventory_sha256: digest(inventory),
    provider_candidate_material_utf8: candidateMaterialRaw.toString("utf8"),
    direct_binding_receipt_utf8: directReceiptRaw.toString("utf8"),
    selected_mapping_count: selectedSets.length,
    deferred_mappings: deferredMappings,
    retained_anomalies: sourceDocument.anomalies,
    retained_reauthorization_required: sourceDocument.reauthorization_required,
    policy_mutation_authorized: false,
    route_apply_authorized: false,
  })}\n`) : undefined;
  if (batchReceipt && batchReceipt.length > 8 * 1024 * 1024) throw new UpstreamInventoryComposeFailure("direct batch receipt exceeds the protected reader size limit");
  return {
    inventory,
    ...(batchReceipt ? { batchReceipt } : {}),
    receipt: {
      mode: directBatchPreflight ? "direct-route-batch-preflight-only" : "compose-cpa-upstream-inventory",
      source_inventory_sha256: sourceDigest,
      provider_candidate_material_sha256: materialDigest,
      direct_binding_receipt_sha256: digest(directReceiptRaw),
      ...(managedReceiptRaw ? { managed_binding_receipt_sha256: digest(managedReceiptRaw) } : {}),
      upstream_inventory_sha256: digest(inventory),
      upstream_count: upstreams.length,
      provider_candidate_set_count: selectedSets.length,
      ...(batchReceipt ? { batch_receipt_sha256: digest(batchReceipt), deferred_mapping_count: deferredMappings.length, retained_anomaly_count: source.anomalies.length, retained_reauthorization_count: source.reauthorizationRequired } : {}),
    },
  };
}

function protectedAbsolute(path: string, label: string): string {
  if (!isAbsolute(path) || path !== resolve(path) || path.includes("\0")) throw new UpstreamInventoryComposeFailure(`${label} path must be absolute and normalized`);
  return path;
}
function openSafeOutput(path: string): OutputTarget {
  if (!isAbsolute(path) || path !== resolve(path) || path === parse(path).root || path.includes("\0")) throw new UpstreamInventoryComposeFailure("upstream inventory output path is invalid");
  const directory = resolve(dirname(path)), root = parse(directory).root;
  let current = root;
  for (const part of relative(root, directory).split(sep).filter(Boolean)) {
    current = resolve(current, part);
    let metadata: ReturnType<typeof lstatSync>;
    try { metadata = lstatSync(current); } catch { throw new UpstreamInventoryComposeFailure("upstream inventory output directory is unsafe"); }
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new UpstreamInventoryComposeFailure("upstream inventory output directory is unsafe");
  }
  let descriptor: number | undefined;
  try {
    descriptor = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || (process.geteuid?.() !== undefined && metadata.uid !== process.geteuid()) || (metadata.mode & 0o022) !== 0) throw new UpstreamInventoryComposeFailure("upstream inventory output directory is unsafe");
    const target = `/proc/self/fd/${descriptor}/${basename(path)}`;
    try { lstatSync(target); throw new UpstreamInventoryComposeFailure("upstream inventory output already exists"); }
    catch (error) { if (error instanceof UpstreamInventoryComposeFailure) throw error; if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) throw new UpstreamInventoryComposeFailure("upstream inventory output directory is unsafe"); }
    return { target, parentDescriptor: descriptor };
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    if (error instanceof UpstreamInventoryComposeFailure) throw error;
    throw new UpstreamInventoryComposeFailure("upstream inventory output directory is unsafe");
  }
}
function writeAtomicNoOverwrite(output: OutputTarget, value: Buffer): void {
  const temporary = `${output.target}.tmp-${randomBytes(16).toString("hex")}`;
  let descriptor: number | undefined;
  try {
    descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    for (let offset = 0; offset < value.length;) { const written = writeSync(descriptor, value, offset, value.length - offset); if (written <= 0) throw new UpstreamInventoryComposeFailure("upstream inventory output could not be written"); offset += written; }
    fsyncSync(descriptor); closeSync(descriptor); descriptor = undefined;
    linkSync(temporary, output.target); unlinkSync(temporary);
    const metadata = lstatSync(output.target); if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o600) throw new UpstreamInventoryComposeFailure("upstream inventory output could not be persisted");
    fsyncSync(output.parentDescriptor);
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    try { lstatSync(temporary); unlinkSync(temporary); } catch {}
    if (error instanceof UpstreamInventoryComposeFailure) throw error;
    throw new UpstreamInventoryComposeFailure("upstream inventory output could not be persisted");
  }
}

type Options = { source?: string; material?: string; direct?: string; managed?: string; output?: string; batchOutput?: string; directBatchPreflight?: boolean };
function options(argv: readonly string[]): Options {
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write("usage: compose-cpa-upstream-inventory --source-inventory-file FILE --provider-candidate-material-file FILE --direct-binding-receipt-file FILE --managed-binding-receipt-file FILE --upstream-inventory-output FILE\n       compose-cpa-upstream-inventory --direct-batch-preflight --source-inventory-file FILE --provider-candidate-material-file FILE --direct-binding-receipt-file FILE --upstream-inventory-output FILE --batch-receipt-output FILE\n\nOffline-compose typed CPA upstream bindings. Explicit direct preflight preserves all deferred evidence and never authorizes route or policy writes.\n");
    process.exit(0);
  }
  const result: Options = {}, names: Record<string, Exclude<keyof Options, "directBatchPreflight">> = { "--source-inventory-file": "source", "--provider-candidate-material-file": "material", "--direct-binding-receipt-file": "direct", "--managed-binding-receipt-file": "managed", "--upstream-inventory-output": "output", "--batch-receipt-output": "batchOutput" };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--direct-batch-preflight") { if (result.directBatchPreflight) throw new UpstreamInventoryComposeFailure("duplicate preflight opt-in"); result.directBatchPreflight = true; continue; }
    const name = argv[index]!, field = names[name], value = argv[index + 1];
    if (!field || !value || value.startsWith("--") || result[field] !== undefined) throw new UpstreamInventoryComposeFailure("arguments are invalid");
    result[field] = value; index += 1;
  }
  if (!result.source || !result.material || !result.direct || !result.output || (result.directBatchPreflight ? !result.batchOutput || result.managed : !result.managed || result.batchOutput)) throw new UpstreamInventoryComposeFailure("required full or direct-preflight arguments are invalid");
  const paths = [result.source, result.material, result.direct, result.managed, result.output, result.batchOutput].filter((item) => item !== undefined);
  if (new Set(paths).size !== paths.length) throw new UpstreamInventoryComposeFailure("input and output paths must be distinct");
  return result;
}

export function run(argv = process.argv.slice(2)): Readonly<Record<string, number | string>> {
  const selected = options(argv);
  let source: Buffer | undefined, material: Buffer | undefined, direct: Buffer | undefined, managed: Buffer | undefined;
  let output: OutputTarget | undefined, batchOutput: OutputTarget | undefined;
  try {
    source = readProtected(protectedAbsolute(selected.source!, "source inventory"), "source inventory");
    material = readProtected(protectedAbsolute(selected.material!, "provider candidate material"), "provider candidate material");
    direct = readProtected(protectedAbsolute(selected.direct!, "direct binding receipt"), "direct binding receipt");
    if (selected.managed) managed = readProtected(protectedAbsolute(selected.managed, "managed binding receipt"), "managed binding receipt");
    const composed = composeUpstreamInventory(source, material, direct, managed, selected.directBatchPreflight);
    output = openSafeOutput(protectedAbsolute(selected.output!, "upstream inventory output"));
    if (selected.batchOutput) batchOutput = openSafeOutput(protectedAbsolute(selected.batchOutput, "batch receipt output"));
    writeAtomicNoOverwrite(output, composed.inventory);
    if (batchOutput && composed.batchReceipt) {
      try { writeAtomicNoOverwrite(batchOutput, composed.batchReceipt); }
      catch (error) { unlinkSync(output.target); fsyncSync(output.parentDescriptor); throw error; }
    }
    return composed.receipt;
  } finally {
    source?.fill(0); material?.fill(0); direct?.fill(0); managed?.fill(0);
    if (output) closeSync(output.parentDescriptor);
    if (batchOutput) closeSync(batchOutput.parentDescriptor);
  }
}

if (invokedAsEntrypoint("compose-cpa-upstream-inventory", import.meta.url)) {
  try { process.stdout.write(`${JSON.stringify(run())}\n`); }
  catch { process.stderr.write("CPA upstream-inventory composition stopped\n"); process.exitCode = 2; }
}
