#!/usr/bin/env node
/** Seal dynamic CPA route source mappings and target-independent v2 pool material. */

import { createHash, createHmac, randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, openSync, unlinkSync, writeSync } from "node:fs";
import { basename, dirname, isAbsolute, parse, relative, resolve, sep } from "node:path";
import { cpaRouteSourceStableId, inspectCpaSourceRoutes, readSourceIdentityKey, type CpaManagedOAuthCapabilityGap, type CpaRouteModel } from "../cpa-upstreams/import-cpa-upstreams.ts";
import { invokedAsEntrypoint } from "../lib/invoked-as-entrypoint.ts";
import { parseNativePolicy, readProtectedFile, type SourceGrant } from "../legacy-policy/import-cpa-key-policy.ts";
import {
  assertManagedCodexModelSnapshotConfig,
  inspectManagedCodexRouteModels,
  parseManagedCodexModelSnapshot,
  readManagedCodexAuthInputs,
  type ManagedCodexRouteModel,
} from "./cpa-managed-codex-route-parser.ts";

const MAX_MAPPINGS = 1_000;
const MAX_CONFIG_BYTES = 4 * 1024 * 1024;
const STABLE_ID = /^[0-9a-f]{64}$/;
// CPA provider identifiers are source-owned opaque route coordinates. Permit
// their documented Unicode letters/numbers without case-folding or Unicode
// normalization, while retaining the ASCII delimiter grammar shared by the
// sealed source/target inventory contracts.
const SOURCE_FIELD = /^[\p{L}\p{N}][\p{L}\p{N}._:/+-]*$/u;
const OPAQUE_ACCOUNT_DOMAIN = "memeloop-token-center\0cpa-native-reauthorization-source-id\0v1\0";
const MANAGED_OAUTH_CAPABILITY_GAP_DOMAIN = "memeloop-token-center\0cpa-managed-oauth-capability-gap-source-id\0v1\0";
const MANAGED_OAUTH_CAPABILITY_GAP_REASON = "source capability gap: target lacks a managed OAuth adapter";

type Protocol = "openai" | "anthropic";
type Source = Readonly<{ provider: string; model: string; group: string | null; upstream_prefix: string | null; protocol: Protocol }>;
type Anomaly = Readonly<{ provider: string; model: string; reason: string }>;
type Candidate = Readonly<{ source_stable_id: string; source_provider: string; driver: "http-json" | "openai-codex" }>;
type CandidateSet = Readonly<{ source: Source; upstream_model: string; protocol: Protocol; selection: "equal_round_robin"; candidates: readonly Candidate[] }>;
type Artifacts = Readonly<{ sourceInventory: Buffer; candidateMaterial: Buffer; counts: Readonly<Record<string, number>> }>;

export class SourceRouteExportFailure extends Error {}

const digest = (value: Uint8Array | string): string => createHash("sha256").update(value).digest("hex");
const key = (value: Source): string => JSON.stringify([value.provider, value.model, value.group, value.upstream_prefix, value.protocol]);
const compare = (left: string, right: string): number => left < right ? -1 : left > right ? 1 : 0;
function stableId(identityKey: Buffer, domain: string, sourceId: string): string {
  return createHmac("sha256", identityKey).update(Buffer.concat([Buffer.from(domain), Buffer.from(sourceId)])).digest("hex");
}
function publicField(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() === value && value.length > 0 && Buffer.byteLength(value) <= 500 && !/[\p{Cc}]/u.test(value) && SOURCE_FIELD.test(value) && !value.includes("@") && !value.startsWith("/") && !value.includes("//") && !/^(?:sk-|pk-|rk-|gh[oprsu]_|mtc_)/iu.test(value) ? value : undefined;
}
function anomalyField(value: unknown): string { return publicField(value) ?? "unknown"; }
function nullableField(value: string | undefined): string | null | undefined {
  if (value === undefined) return null;
  return publicField(value);
}
function exactGrant(grant: SourceGrant): Source | Anomaly {
  const provider = publicField(grant.provider), model = publicField(grant.model), group = nullableField(grant.group), upstreamPrefix = nullableField(grant.upstream_prefix);
  if (!provider || !model) return { provider: anomalyField(grant.provider), model: anomalyField(grant.model), reason: "source grant lacks provider or model route coordinates" };
  if (group === undefined || upstreamPrefix === undefined) return { provider, model, reason: "source grant contains an invalid optional route coordinate" };
  return { provider, model, group, upstream_prefix: upstreamPrefix, protocol: "openai" };
}
function isAnomaly(value: Source | Anomaly): value is Anomaly { return "reason" in value; }
function modelIndex(models: readonly CpaRouteModel[]): ReadonlyMap<string, readonly CpaRouteModel[]> {
  const values = new Map<string, CpaRouteModel[]>();
  for (const model of models) {
    const id = JSON.stringify([model.provider, model.model, model.upstreamPrefix]);
    const current = values.get(id); if (current) current.push(model); else values.set(id, [model]);
  }
  return values;
}

/** Pure construction step: it receives only parsed non-secret coordinates and policy grants. */
export function buildArtifacts(models: readonly CpaRouteModel[], opaque: readonly { sourceId: string; provider: string }[], capabilityGaps: readonly CpaManagedOAuthCapabilityGap[], grants: readonly SourceGrant[], identityKey: Buffer): Artifacts {
  if (identityKey.length !== 32) throw new SourceRouteExportFailure("source identity key is invalid");
  if (models.some((model) => !publicField(model.provider) || !publicField(model.model) || !publicField(model.upstreamModel) || (model.upstreamPrefix !== null && !publicField(model.upstreamPrefix)))) throw new SourceRouteExportFailure("configured route model contains an unsafe public coordinate");
  const lookup = modelIndex(models), mappings = new Map<string, Source>(), pools = new Map<string, CandidateSet>(), anomalies = new Map<string, Anomaly>();
  const missingManagedKimiAdapter = capabilityGaps.some((item) => item.sourceType === "kimi"); let capabilityGapGrantCount = 0;
  const addAnomaly = (item: Anomaly): void => { anomalies.set(JSON.stringify([item.provider, item.model, item.reason]), item); };
  for (const grant of grants) {
    const parsed = exactGrant(grant);
    if (isAnomaly(parsed)) { addAnomaly(parsed); continue; }
    // This is a source capability gap, not a direct candidate.  Even a
    // same-named config provider cannot substitute for an observed Kimi OAuth
    // account, because doing so would silently change the source pool.
    if (missingManagedKimiAdapter && parsed.provider === "kimi") {
      capabilityGapGrantCount += 1; addAnomaly({ provider: parsed.provider, model: parsed.model, reason: MANAGED_OAUTH_CAPABILITY_GAP_REASON }); continue;
    }
    const matches = lookup.get(JSON.stringify([parsed.provider, parsed.model, parsed.upstream_prefix])) ?? [];
    if (matches.length === 0) throw new SourceRouteExportFailure("source grant lacks an exact configured route model");
    if (matches.length !== 1) throw new SourceRouteExportFailure("source grant has an ambiguous configured route model");
    const model = matches[0]!;
    const source: Source = { ...parsed, protocol: model.protocol };
    if (model.candidateSourceIds.length === 0) throw new SourceRouteExportFailure("source grant has no active exact source account candidates");
    const candidates = model.candidateSourceIds.map((sourceId) => ({ source_stable_id: cpaRouteSourceStableId(identityKey, sourceId), source_provider: source.provider, driver: "http-json" as const })).sort((left, right) => compare(left.source_stable_id, right.source_stable_id));
    if (new Set(candidates.map((candidate) => candidate.source_stable_id)).size !== candidates.length || candidates.some((candidate) => !STABLE_ID.test(candidate.source_stable_id))) throw new SourceRouteExportFailure("source account candidate identity is invalid");
    const sourceKey = key(source), current = pools.get(sourceKey), candidateSet: CandidateSet = { source, upstream_model: model.upstreamModel, protocol: model.protocol, selection: "equal_round_robin", candidates };
    if (current && JSON.stringify(current) !== JSON.stringify(candidateSet)) throw new SourceRouteExportFailure("source mapping has conflicting provider candidate material");
    mappings.set(sourceKey, source); pools.set(sourceKey, candidateSet);
  }
  if (mappings.size > MAX_MAPPINGS || anomalies.size > MAX_MAPPINGS || opaque.length + capabilityGaps.length > MAX_MAPPINGS) throw new SourceRouteExportFailure("source route inventory exceeds the supported safety boundary");
  const reauthorization = opaque.map((item) => {
    const provider = publicField(item.provider); if (!provider || (provider !== "copilot" && provider !== "cursor")) throw new SourceRouteExportFailure("opaque source reauthorization record is invalid");
    return { provider, source_stable_id: stableId(identityKey, OPAQUE_ACCOUNT_DOMAIN, item.sourceId) };
  }).concat(capabilityGaps.map((item) => {
    if (item.sourceType !== "kimi" || !item.sourceId) throw new SourceRouteExportFailure("managed OAuth capability gap record is invalid");
    return { provider: item.sourceType, source_stable_id: stableId(identityKey, MANAGED_OAUTH_CAPABILITY_GAP_DOMAIN, item.sourceId) };
  })).sort((left, right) => compare(`${left.provider}\0${left.source_stable_id}`, `${right.provider}\0${right.source_stable_id}`));
  if (new Set(reauthorization.map((item) => item.source_stable_id)).size !== reauthorization.length) throw new SourceRouteExportFailure("source authorization remediation identity is duplicated");
  const sourceMappings = [...mappings.values()].sort((left, right) => compare(key(left), key(right)));
  const anomalyList = [...anomalies.values()].sort((left, right) => compare(JSON.stringify([left.provider, left.model, left.reason]), JSON.stringify([right.provider, right.model, right.reason])));
  const sourceInventory = Buffer.from(`${JSON.stringify({ version: 2, mappings: sourceMappings, reauthorization_required: reauthorization, anomalies: anomalyList })}\n`);
  const candidateSets = [...pools.values()].sort((left, right) => compare(key(left.source), key(right.source)));
  const candidateMaterial = Buffer.from(`${JSON.stringify({ version: 1, source_inventory_sha256: digest(sourceInventory), provider_candidate_sets: candidateSets })}\n`);
  return {
    sourceInventory,
    candidateMaterial,
    counts: {
      source_mapping_count: sourceMappings.length,
      provider_candidate_set_count: candidateSets.length,
      source_account_candidate_count: candidateSets.reduce((sum, item) => sum + item.candidates.length, 0),
      reauthorization_required_count: reauthorization.length,
      source_capability_gap_auth_count: capabilityGaps.length,
      source_capability_gap_grant_count: capabilityGapGrantCount,
      anomaly_count: anomalyList.length,
    },
  };
}

function decodedArtifact(value: Buffer, label: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value.toString("utf8"));
    if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") throw new Error("invalid");
    return parsed as Record<string, unknown>;
  } catch { throw new SourceRouteExportFailure(`${label} could not be normalized`); }
}
function managedSet(value: ManagedCodexRouteModel): CandidateSet {
  const source: Source = {
    provider: value.source.provider,
    model: value.source.model,
    group: value.source.group,
    upstream_prefix: value.source.upstream_prefix,
    protocol: value.source.protocol,
  };
  if (!publicField(source.provider) || !publicField(source.model) || (source.group !== null && !publicField(source.group)) || (source.upstream_prefix !== null && !publicField(source.upstream_prefix)) || !publicField(value.upstream_model) || value.protocol !== "openai" || value.selection !== "equal_round_robin" || value.candidates.length === 0) throw new SourceRouteExportFailure("managed Codex candidate material contains an unsafe source coordinate");
  const candidates = value.candidates.map((candidate) => ({ source_stable_id: candidate.source_stable_id, source_provider: candidate.source_provider, driver: candidate.driver })).sort((left, right) => compare(left.source_stable_id, right.source_stable_id));
  if (new Set(candidates.map((candidate) => candidate.source_stable_id)).size !== candidates.length || candidates.some((candidate) => candidate.driver !== "openai-codex" || candidate.source_provider !== "codex" || !STABLE_ID.test(candidate.source_stable_id))) throw new SourceRouteExportFailure("managed Codex candidate material has an invalid source binding");
  return { source, upstream_model: value.upstream_model, protocol: "openai", selection: "equal_round_robin", candidates };
}
function combineArtifacts(direct: Artifacts, managed: readonly ManagedCodexRouteModel[], anomalies: readonly Anomaly[]): Artifacts {
  const sourceDocument = decodedArtifact(direct.sourceInventory, "direct source inventory"), materialDocument = decodedArtifact(direct.candidateMaterial, "direct provider candidate material");
  if (sourceDocument.version !== 2 || !Array.isArray(sourceDocument.mappings) || !Array.isArray(sourceDocument.reauthorization_required) || !Array.isArray(sourceDocument.anomalies) || materialDocument.version !== 1 || !Array.isArray(materialDocument.provider_candidate_sets)) throw new SourceRouteExportFailure("direct source artifact has an unsupported schema");
  const mappings = new Map<string, Source>(), sets = new Map<string, CandidateSet>();
  for (const raw of sourceDocument.mappings) {
    if (raw === null || Array.isArray(raw) || typeof raw !== "object") throw new SourceRouteExportFailure("direct source inventory has an invalid mapping");
    const source = raw as Source, sourceKey = key(source);
    if (mappings.has(sourceKey)) throw new SourceRouteExportFailure("direct source inventory has an invalid mapping");
    mappings.set(sourceKey, source);
  }
  for (const raw of materialDocument.provider_candidate_sets) {
    const set = raw as CandidateSet, sourceKey = set && typeof set === "object" ? key(set.source) : "";
    if (!sourceKey || sets.has(sourceKey)) throw new SourceRouteExportFailure("direct provider candidate material has an invalid mapping");
    sets.set(sourceKey, set);
  }
  if (mappings.size !== sets.size || [...mappings.keys()].some((sourceKey) => !sets.has(sourceKey))) throw new SourceRouteExportFailure("direct source inventory and candidate material disagree");
  for (const model of managed) {
    const set = managedSet(model), sourceKey = key(set.source);
    if (mappings.has(sourceKey) || sets.has(sourceKey)) throw new SourceRouteExportFailure("a managed Codex route collides with an existing source route; mixed-driver pools are unsupported");
    mappings.set(sourceKey, set.source); sets.set(sourceKey, set);
  }
  const anomalyMap = new Map<string, Anomaly>();
  for (const raw of sourceDocument.anomalies) {
    const item = raw as Anomaly;
    if (!item || typeof item !== "object") throw new SourceRouteExportFailure("direct source inventory has an invalid anomaly");
    anomalyMap.set(JSON.stringify([item.provider, item.model, item.reason]), item);
  }
  for (const item of anomalies) anomalyMap.set(JSON.stringify([item.provider, item.model, item.reason]), item);
  const sourceMappings = [...mappings.values()].sort((left, right) => compare(key(left), key(right)));
  const candidateSets = [...sets.values()].sort((left, right) => compare(key(left.source), key(right.source)));
  const anomalyList = [...anomalyMap.values()].sort((left, right) => compare(JSON.stringify([left.provider, left.model, left.reason]), JSON.stringify([right.provider, right.model, right.reason])));
  const sourceInventory = Buffer.from(`${JSON.stringify({ version: 2, mappings: sourceMappings, reauthorization_required: sourceDocument.reauthorization_required, anomalies: anomalyList })}\n`);
  const candidateMaterial = Buffer.from(`${JSON.stringify({ version: 1, source_inventory_sha256: digest(sourceInventory), provider_candidate_sets: candidateSets })}\n`);
  return {
    sourceInventory,
    candidateMaterial,
    counts: {
      source_mapping_count: sourceMappings.length,
      provider_candidate_set_count: candidateSets.length,
      source_account_candidate_count: candidateSets.reduce((sum, item) => sum + item.candidates.length, 0),
      reauthorization_required_count: (sourceDocument.reauthorization_required as unknown[]).length,
      source_capability_gap_auth_count: direct.counts.source_capability_gap_auth_count ?? 0,
      source_capability_gap_grant_count: direct.counts.source_capability_gap_grant_count ?? 0,
      anomaly_count: anomalyList.length,
    },
  };
}
function isCustomClassifyGroup(value: string | null): boolean { return value !== null && value.startsWith("classify:"); }
function sourceFromManaged(value: Source): { provider: "codex"; model: string; group: string | null; upstream_prefix: string | null; protocol: "openai" } {
  if (value.provider !== "codex" || value.protocol !== "openai") throw new SourceRouteExportFailure("managed Codex source coordinate is invalid");
  return { provider: "codex", model: value.model, group: value.group, upstream_prefix: value.upstream_prefix, protocol: "openai" };
}
function buildManagedAwareArtifacts(
  inspection: Readonly<{ models: readonly CpaRouteModel[]; opaqueReauthorizations: readonly { sourceId: string; provider: string }[]; managedOAuthCapabilityGaps: readonly CpaManagedOAuthCapabilityGap[] }>,
  grants: readonly SourceGrant[],
  identityKey: Buffer,
  configRaw: Buffer,
  authDirectory: string,
  snapshotRaw: Buffer,
): Artifacts {
  const directGrants: SourceGrant[] = [], anomalies: Anomaly[] = [], managedSources = new Map<string, Source>();
  for (const grant of grants) {
    const parsed = exactGrant(grant);
    if (isAnomaly(parsed)) { anomalies.push(parsed); continue; }
    if (parsed.provider !== "codex") { directGrants.push(grant); continue; }
    // A native-access classify route is selected by the deployed key-policy
    // plugin from OAuth auth-file identity.  It must never inherit a direct
    // API-key pool merely because the same model name also appears in config.
    if (isCustomClassifyGroup(parsed.group)) managedSources.set(key(parsed), parsed);
    else directGrants.push(grant);
  }
  const direct = buildArtifacts(inspection.models, inspection.opaqueReauthorizations, inspection.managedOAuthCapabilityGaps, directGrants, identityKey);
  const snapshot = parseManagedCodexModelSnapshot(snapshotRaw); assertManagedCodexModelSnapshotConfig(snapshot, configRaw);
  const managed = managedSources.size === 0 ? [] : inspectManagedCodexRouteModels(configRaw, readManagedCodexAuthInputs(authDirectory), snapshot.auth_models, [...managedSources.values()].sort((left, right) => compare(key(left), key(right))).map(sourceFromManaged), identityKey, { allow_missing_candidates: true });
  const managedCovered = new Set(managed.map((item) => key(item.source)));
  for (const source of managedSources.values()) if (!managedCovered.has(key(source))) throw new SourceRouteExportFailure("managed Codex source route has no exact active account candidate");
  return combineArtifacts(direct, managed, anomalies);
}

type OutputTarget = Readonly<{ target: string; parentDescriptor: number }>;
function openSafeOutput(path: string): OutputTarget {
  if (!isAbsolute(path) || path !== resolve(path) || path === parse(path).root || path.includes("\0")) throw new SourceRouteExportFailure("output path must be an absolute normalized path");
  const directory = dirname(path), normalized = resolve(directory), root = parse(normalized).root, pieces = relative(root, normalized).split(sep).filter(Boolean);
  let current = root;
  for (const piece of pieces) {
    current = resolve(current, piece);
    let stat: ReturnType<typeof lstatSync>;
    try { stat = lstatSync(current); } catch { throw new SourceRouteExportFailure("output directory is not safely writable"); }
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new SourceRouteExportFailure("output directory is not safely writable");
  }
  let descriptor: number | undefined;
  try {
    descriptor = openSync(normalized, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const stat = fstatSync(descriptor);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (process.geteuid?.() !== undefined && stat.uid !== process.geteuid()) || (stat.mode & 0o022) !== 0) throw new SourceRouteExportFailure("output directory is not safely writable");
    const target = `/proc/self/fd/${descriptor}/${basename(path)}`;
    try { lstatSync(target); throw new SourceRouteExportFailure("output path already exists"); }
    catch (error) { if (error instanceof SourceRouteExportFailure) throw error; const code = error && typeof error === "object" && "code" in error ? (error as { code?: string }).code : undefined; if (code !== "ENOENT") throw new SourceRouteExportFailure("output path is not safely writable"); }
    return { target, parentDescriptor: descriptor };
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    if (error instanceof SourceRouteExportFailure) throw error;
    throw new SourceRouteExportFailure("output directory is not safely writable");
  }
}
function writeAll(descriptor: number, value: Buffer): void {
  let written = 0;
  while (written < value.length) { const count = writeSync(descriptor, value, written, value.length - written); if (count <= 0) throw new SourceRouteExportFailure("output could not be written safely"); written += count; }
}
function temporaryPath(path: string): string {
  for (let attempt = 0; attempt < 32; attempt += 1) {
    const candidate = `${path}.tmp-${randomBytes(16).toString("hex")}`;
    try { lstatSync(candidate); } catch (error) { const code = error && typeof error === "object" && "code" in error ? (error as { code?: string }).code : undefined; if (code === "ENOENT") return candidate; }
  }
  throw new SourceRouteExportFailure("output temporary name could not be reserved");
}
function writeAtomicNoOverwrite(output: OutputTarget, value: Buffer): void {
  const temporary = temporaryPath(output.target); let descriptor: number | undefined;
  try {
    descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    writeAll(descriptor, value); fsyncSync(descriptor); closeSync(descriptor); descriptor = undefined;
    linkSync(temporary, output.target); unlinkSync(temporary);
    const published = lstatSync(output.target); if (!published.isFile() || published.isSymbolicLink() || published.nlink !== 1 || (published.mode & 0o777) !== 0o600) throw new SourceRouteExportFailure("output could not be persisted safely");
    fsyncSync(output.parentDescriptor);
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    try { lstatSync(temporary); unlinkSync(temporary); } catch {}
    if (error instanceof SourceRouteExportFailure) throw error;
    throw new SourceRouteExportFailure("output could not be persisted safely");
  }
}

type Options = { config?: string; authDir?: string; policy?: string; sourceKey?: string; sourceOutput?: string; candidateOutput?: string; managedCodexModelSnapshot?: string };
function options(argv: readonly string[]): Options {
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write("usage: export-cpa-source-route-inventory --config FILE --auth-dir DIR --policy-snapshot-file FILE --source-identity-key-file FILE --source-inventory-output FILE --provider-candidate-material-output FILE [--managed-codex-model-snapshot-file FILE]\n\nSeal dynamic CPA route mappings and target-independent v2 provider candidate material. A source containing Codex OAuth auth files requires the protected read-only management model snapshot.\n");
    process.exit(0);
  }
  const result: Options = {}, names: Record<string, keyof Options> = { "--config": "config", "--auth-dir": "authDir", "--policy-snapshot-file": "policy", "--source-identity-key-file": "sourceKey", "--source-inventory-output": "sourceOutput", "--provider-candidate-material-output": "candidateOutput", "--managed-codex-model-snapshot-file": "managedCodexModelSnapshot" };
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index]!, field = names[name], value = argv[index + 1];
    if (!field || !value || value.startsWith("--") || result[field] !== undefined) throw new SourceRouteExportFailure("arguments are invalid");
    result[field] = value; index += 1;
  }
  if (!result.config || !result.authDir || !result.policy || !result.sourceKey || !result.sourceOutput || !result.candidateOutput) throw new SourceRouteExportFailure("required arguments are missing");
  return result;
}

export function run(argv = process.argv.slice(2)): Readonly<Record<string, string | number>> {
  const selected = options(argv), inspection = inspectCpaSourceRoutes(selected.config!, selected.authDir!);
  const policy = parseNativePolicy(readProtectedFile(selected.policy!, "source route policy snapshot"));
  const identityKey = readSourceIdentityKey(selected.sourceKey!);
  let sourceOutput: OutputTarget | undefined, candidateOutput: OutputTarget | undefined, configRaw: Buffer | undefined, snapshotRaw: Buffer | undefined;
  try {
    if (selected.sourceOutput === selected.candidateOutput) throw new SourceRouteExportFailure("output paths must be distinct");
    const managedAuths = readManagedCodexAuthInputs(selected.authDir!);
    if (managedAuths.length > 0 && !selected.managedCodexModelSnapshot) throw new SourceRouteExportFailure("managed Codex OAuth source routes require a read-only CPA model snapshot");
    if (managedAuths.length === 0 && selected.managedCodexModelSnapshot) throw new SourceRouteExportFailure("managed Codex model snapshot was supplied without a managed Codex OAuth source");
    const grants = policy.filter((item) => item.enabled).flatMap((item) => item.grants);
    let artifacts: Artifacts;
    if (managedAuths.length === 0) artifacts = buildArtifacts(inspection.models, inspection.opaqueReauthorizations, inspection.managedOAuthCapabilityGaps, grants, identityKey);
    else {
      configRaw = readProtectedFile(selected.config!, "CPA source config", MAX_CONFIG_BYTES);
      snapshotRaw = readProtectedFile(selected.managedCodexModelSnapshot!, "managed Codex model snapshot");
      artifacts = buildManagedAwareArtifacts(inspection, grants, identityKey, configRaw, selected.authDir!, snapshotRaw);
      const after = readProtectedFile(selected.config!, "CPA source config", MAX_CONFIG_BYTES);
      try { if (!after.equals(configRaw)) throw new SourceRouteExportFailure("CPA source config changed while managed Codex routes were inspected"); }
      finally { after.fill(0); }
    }
    const reservedSource = openSafeOutput(selected.sourceOutput!); sourceOutput = reservedSource;
    const reservedCandidate = openSafeOutput(selected.candidateOutput!); candidateOutput = reservedCandidate;
    writeAtomicNoOverwrite(reservedSource, artifacts.sourceInventory);
    try { writeAtomicNoOverwrite(reservedCandidate, artifacts.candidateMaterial); }
    catch (error) { try { unlinkSync(reservedSource.target); fsyncSync(reservedSource.parentDescriptor); } catch {} throw error; }
    return { source_inventory_sha256: digest(artifacts.sourceInventory), provider_candidate_material_sha256: digest(artifacts.candidateMaterial), ...artifacts.counts };
  } finally {
    identityKey.fill(0);
    configRaw?.fill(0); snapshotRaw?.fill(0);
    if (candidateOutput) closeSync(candidateOutput.parentDescriptor);
    if (sourceOutput) closeSync(sourceOutput.parentDescriptor);
  }
}

if (invokedAsEntrypoint("export-cpa-source-route-inventory", import.meta.url)) {
  try { process.stdout.write(`${JSON.stringify(run())}\n`); }
  catch { process.stderr.write("CPA source-route inventory export stopped\n"); process.exitCode = 2; }
}
