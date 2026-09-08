#!/usr/bin/env node
/** Seal dynamic CPA route source mappings and target-independent v2 pool material. */

import { createHash, createHmac, randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, openSync, unlinkSync, writeSync } from "node:fs";
import { basename, dirname, isAbsolute, parse, relative, resolve, sep } from "node:path";
import { cpaRouteSourceStableId, inspectCpaSourceRoutes, readSourceIdentityKey, type CpaRouteModel } from "../cpa-upstreams/import-cpa-upstreams.ts";
import { parseNativePolicy, readProtectedFile, type SourceGrant } from "../legacy-policy/import-cpa-key-policy.ts";

const MAX_MAPPINGS = 1_000;
const STABLE_ID = /^[0-9a-f]{64}$/;
const SOURCE_FIELD = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,199}$/;
const OPAQUE_ACCOUNT_DOMAIN = "memeloop-token-center\0cpa-native-reauthorization-source-id\0v1\0";

type Protocol = "openai" | "anthropic";
type Source = Readonly<{ provider: string; model: string; group: string | null; upstream_prefix: string | null; protocol: Protocol }>;
type Anomaly = Readonly<{ provider: string; model: string; reason: string }>;
type Candidate = Readonly<{ source_stable_id: string; source_provider: string; driver: "http-json" }>;
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
  return typeof value === "string" && SOURCE_FIELD.test(value) && !value.includes("@") && !value.startsWith("/") && !value.includes("//") && !/^(?:sk-|pk-|rk-|gh[oprsu]_|mtc_)/iu.test(value) ? value : undefined;
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
export function buildArtifacts(models: readonly CpaRouteModel[], opaque: readonly { sourceId: string; provider: string }[], grants: readonly SourceGrant[], identityKey: Buffer): Artifacts {
  if (identityKey.length !== 32) throw new SourceRouteExportFailure("source identity key is invalid");
  if (models.some((model) => !publicField(model.provider) || !publicField(model.model) || !publicField(model.upstreamModel) || (model.upstreamPrefix !== null && !publicField(model.upstreamPrefix)))) throw new SourceRouteExportFailure("configured route model contains an unsafe public coordinate");
  const lookup = modelIndex(models), mappings = new Map<string, Source>(), pools = new Map<string, CandidateSet>(), anomalies = new Map<string, Anomaly>();
  const addAnomaly = (item: Anomaly): void => { anomalies.set(JSON.stringify([item.provider, item.model, item.reason]), item); };
  for (const grant of grants) {
    const parsed = exactGrant(grant);
    if (isAnomaly(parsed)) { addAnomaly(parsed); continue; }
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
  if (mappings.size > MAX_MAPPINGS || anomalies.size > MAX_MAPPINGS || opaque.length > MAX_MAPPINGS) throw new SourceRouteExportFailure("source route inventory exceeds the supported safety boundary");
  const reauthorization = opaque.map((item) => {
    const provider = publicField(item.provider); if (!provider || (provider !== "copilot" && provider !== "cursor")) throw new SourceRouteExportFailure("opaque source reauthorization record is invalid");
    return { provider, source_stable_id: stableId(identityKey, OPAQUE_ACCOUNT_DOMAIN, item.sourceId) };
  }).sort((left, right) => compare(`${left.provider}\0${left.source_stable_id}`, `${right.provider}\0${right.source_stable_id}`));
  if (new Set(reauthorization.map((item) => item.source_stable_id)).size !== reauthorization.length) throw new SourceRouteExportFailure("opaque source reauthorization identity is duplicated");
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
      anomaly_count: anomalyList.length,
    },
  };
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

type Options = { config?: string; authDir?: string; policy?: string; sourceKey?: string; sourceOutput?: string; candidateOutput?: string };
function options(argv: readonly string[]): Options {
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write("usage: export-cpa-source-route-inventory --config FILE --auth-dir DIR --policy-snapshot-file FILE --source-identity-key-file FILE --source-inventory-output FILE --provider-candidate-material-output FILE\n\nSeal dynamic CPA route mappings and target-independent v2 provider candidate material.\n");
    process.exit(0);
  }
  const result: Options = {}, names: Record<string, keyof Options> = { "--config": "config", "--auth-dir": "authDir", "--policy-snapshot-file": "policy", "--source-identity-key-file": "sourceKey", "--source-inventory-output": "sourceOutput", "--provider-candidate-material-output": "candidateOutput" };
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
  let sourceOutput: OutputTarget | undefined, candidateOutput: OutputTarget | undefined;
  try {
    if (selected.sourceOutput === selected.candidateOutput) throw new SourceRouteExportFailure("output paths must be distinct");
    const artifacts = buildArtifacts(inspection.models, inspection.opaqueReauthorizations, policy.filter((item) => item.enabled).flatMap((item) => item.grants), identityKey);
    const reservedSource = openSafeOutput(selected.sourceOutput!); sourceOutput = reservedSource;
    const reservedCandidate = openSafeOutput(selected.candidateOutput!); candidateOutput = reservedCandidate;
    writeAtomicNoOverwrite(reservedSource, artifacts.sourceInventory);
    try { writeAtomicNoOverwrite(reservedCandidate, artifacts.candidateMaterial); }
    catch (error) { try { unlinkSync(reservedSource.target); fsyncSync(reservedSource.parentDescriptor); } catch {} throw error; }
    return { source_inventory_sha256: digest(artifacts.sourceInventory), provider_candidate_material_sha256: digest(artifacts.candidateMaterial), ...artifacts.counts };
  } finally {
    identityKey.fill(0);
    if (candidateOutput) closeSync(candidateOutput.parentDescriptor);
    if (sourceOutput) closeSync(sourceOutput.parentDescriptor);
  }
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  try { process.stdout.write(`${JSON.stringify(run())}\n`); }
  catch { process.stderr.write("CPA source-route inventory export stopped\n"); process.exitCode = 2; }
}
