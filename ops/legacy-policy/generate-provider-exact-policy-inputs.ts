#!/usr/bin/env node
/**
 * Derive, but never apply, the complete provider-exact policy inputs after a
 * reviewed native route replay. The owner still reviews and supplies the two
 * generated files to the policy stage as separate protected inputs.
 */

import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  openSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { basename, dirname, isAbsolute, parse, relative, resolve, sep } from "node:path";
import { invokedAsEntrypoint } from "../lib/invoked-as-entrypoint.ts";
import { parseStrictJson } from "../lib/strict-json.ts";
import { parseNativePolicy, readProtectedFile, type SourceGrant } from "./import-cpa-key-policy.ts";
import {
  parseManifest,
  parseSourceInventory,
  parseUpstreamInventory,
} from "../legacy-routes/import-cpa-model-routes.ts";

const SHA256 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_ROUTES = 1_000;
const fields = ["provider", "model", "group", "upstream_prefix"] as const;

type JsonObject = Record<string, unknown>;
type Protocol = "openai" | "anthropic" | "generation";
type CandidateSource = Readonly<{ upstreamAccountId: string; sourceStableId: string }>;
type CandidateBinding = Readonly<{ accountId: string; sourceStableId: string }>;
type TargetRoute = Readonly<{
  routeId: string;
  publicModel: string;
  upstreamModel: string;
  protocol: Protocol;
  priority: number;
  updatedAt: number;
  upstreamAccountIds: readonly string[];
  candidateUpstreamAccountIds: readonly string[];
  candidateSources: readonly CandidateSource[];
}>;
type GeneratedInputs = Readonly<{
  routeInventory: Buffer;
  policyMapping: Buffer;
  receipt: Readonly<Record<string, number | string>>;
}>;

export class ProviderExactPolicyInputFailure extends Error {}

const digest = (value: Uint8Array | string): string => createHash("sha256").update(value).digest("hex");
const compare = (left: string, right: string): number => left < right ? -1 : left > right ? 1 : 0;

function object(value: unknown, keys: readonly string[], label: string): JsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new ProviderExactPolicyInputFailure(`${label} has an invalid schema`);
  const actual = Object.keys(value as JsonObject).sort(), expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new ProviderExactPolicyInputFailure(`${label} has an invalid schema`);
  return value as JsonObject;
}

function text(value: unknown, label: string, pattern?: RegExp): string {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || Buffer.byteLength(value) > 512 || /[\0\r\n]/.test(value) || (pattern && !pattern.test(value))) throw new ProviderExactPolicyInputFailure(`${label} has an invalid schema`);
  return value;
}

function integer(value: unknown, label: string, minimum = 0): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > 1_000_000_000_000_000) throw new ProviderExactPolicyInputFailure(`${label} has an invalid schema`);
  return Number(value);
}

function protocol(value: unknown, label: string): Protocol {
  if (value !== "openai" && value !== "anthropic" && value !== "generation") throw new ProviderExactPolicyInputFailure(`${label} has an invalid schema`);
  return value;
}

function sortedIds(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_ROUTES) throw new ProviderExactPolicyInputFailure(`${label} has an invalid schema`);
  const ids = value.map((item) => text(item, label, UUID)).sort(compare);
  if (new Set(ids).size !== ids.length) throw new ProviderExactPolicyInputFailure(`${label} contains duplicates`);
  return ids;
}

function candidateSources(value: unknown, label: string): CandidateSource[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_ROUTES) throw new ProviderExactPolicyInputFailure(`${label} has an invalid schema`);
  const candidates = value.map((entry) => {
    const item = object(entry, ["source_stable_id", "upstream_account_id"], label);
    return {
      upstreamAccountId: text(item["upstream_account_id"], label, UUID),
      sourceStableId: text(item["source_stable_id"], label, SHA256),
    };
  }).sort((left, right) => compare(left.upstreamAccountId, right.upstreamAccountId));
  if (new Set(candidates.map((item) => item.upstreamAccountId)).size !== candidates.length || new Set(candidates.map((item) => item.sourceStableId)).size !== candidates.length) throw new ProviderExactPolicyInputFailure(`${label} contains duplicate bindings`);
  return candidates;
}

function same(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function sameCandidateAccounts(left: readonly CandidateBinding[], right: readonly CandidateSource[]): boolean {
  return left.length === right.length && left.every((value, index) => value.accountId === right[index]?.upstreamAccountId && value.sourceStableId === right[index]?.sourceStableId);
}

function sameBindings(left: readonly CandidateBinding[], right: readonly CandidateBinding[]): boolean {
  return left.length === right.length && left.every((value, index) => value.accountId === right[index]?.accountId && value.sourceStableId === right[index]?.sourceStableId);
}

function grantKey(value: SourceGrant): string {
  return JSON.stringify(fields.map((field) => Object.hasOwn(value, field) ? [1, value[field as keyof SourceGrant]] : [0]));
}

function sourceKey(value: { provider: string; model: string; group: string | null; upstreamPrefix: string | null; protocol: "openai" | "anthropic" }): string {
  return JSON.stringify([value.provider, value.model, value.group, value.upstreamPrefix, value.protocol]);
}

function grantFromSource(value: { provider: string; model: string; group: string | null; upstreamPrefix: string | null }): SourceGrant {
  return {
    provider: value.provider,
    model: value.model,
    ...(value.group === null ? {} : { group: value.group }),
    ...(value.upstreamPrefix === null ? {} : { upstream_prefix: value.upstreamPrefix }),
  };
}

function parseTargetReceipt(raw: Buffer, sourceDigest: string, upstreamDigest: string, manifestDigest: string): { tenant: string; routes: readonly TargetRoute[] } {
  let parsed: unknown;
  try { parsed = parseStrictJson(new TextDecoder("utf-8", { fatal: true }).decode(raw)); }
  catch { throw new ProviderExactPolicyInputFailure("target route receipt is not strict UTF-8 JSON"); }
  const root = object(parsed, ["reviewed_route_manifest_sha256", "routes", "source_inventory_sha256", "tenant_external_id", "upstream_inventory_sha256", "version"], "target route receipt");
  if (root["version"] !== 1 || text(root["source_inventory_sha256"], "target route receipt", SHA256) !== sourceDigest || text(root["upstream_inventory_sha256"], "target route receipt", SHA256) !== upstreamDigest || text(root["reviewed_route_manifest_sha256"], "target route receipt", SHA256) !== manifestDigest || !Array.isArray(root["routes"]) || root["routes"].length > MAX_ROUTES) throw new ProviderExactPolicyInputFailure("target route receipt does not match the reviewed inputs");
  const routeIds = new Set<string>();
  const routes = root["routes"].map((value) => {
    const item = object(value, ["candidate_sources", "candidate_upstream_account_ids", "enabled", "priority", "protocol", "public_model", "route_id", "updated_at", "upstream_account_ids", "upstream_model"], "target route receipt item");
    const routeId = text(item["route_id"], "target route receipt item", UUID);
    if (routeIds.has(routeId)) throw new ProviderExactPolicyInputFailure("target route receipt contains duplicate routes");
    routeIds.add(routeId);
    if (item["enabled"] !== true) throw new ProviderExactPolicyInputFailure("target route receipt contains a disabled route");
    const candidates = sortedIds(item["candidate_upstream_account_ids"], "target route receipt item"), sources = candidateSources(item["candidate_sources"], "target route receipt item");
    if (!same(candidates, sources.map((source) => source.upstreamAccountId))) throw new ProviderExactPolicyInputFailure("target route receipt has incomplete candidate bindings");
    const upstream = sortedIds(item["upstream_account_ids"], "target route receipt item");
    if (!same(upstream, candidates)) throw new ProviderExactPolicyInputFailure("target route receipt does not use its complete candidate pool");
    return {
      routeId,
      publicModel: text(item["public_model"], "target route receipt item"),
      upstreamModel: text(item["upstream_model"], "target route receipt item"),
      protocol: protocol(item["protocol"], "target route receipt item"),
      priority: integer(item["priority"], "target route receipt item", -1_000_000),
      updatedAt: integer(item["updated_at"], "target route receipt item"),
      upstreamAccountIds: upstream,
      candidateUpstreamAccountIds: candidates,
      candidateSources: sources,
    };
  });
  return { tenant: text(root["tenant_external_id"], "target route receipt"), routes };
}

function assertExactSet(left: readonly string[], right: readonly string[], label: string): void {
  const sortedLeft = [...left].sort(compare), sortedRight = [...right].sort(compare);
  if (new Set(sortedLeft).size !== sortedLeft.length || new Set(sortedRight).size !== sortedRight.length || !same(sortedLeft, sortedRight)) throw new ProviderExactPolicyInputFailure(label);
}

function matches(spec: { publicModel: string; upstreamModel: string; protocol: "openai" | "anthropic"; priority: number; candidates: readonly CandidateBinding[] }, route: TargetRoute): boolean {
  const candidateIds = spec.candidates.map((item) => item.accountId);
  return spec.publicModel === route.publicModel
    && spec.upstreamModel === route.upstreamModel
    && spec.protocol === route.protocol
    && spec.priority === route.priority
    && same(candidateIds, route.upstreamAccountIds)
    && same(candidateIds, route.candidateUpstreamAccountIds)
    && sameCandidateAccounts(spec.candidates, route.candidateSources);
}

/**
 * This pure step keeps the owner decision in the reviewed route manifest and
 * only seals the complete policy coordinates that the policy importer needs.
 */
export function buildProviderExactPolicyInputs(
  policyRaw: Buffer,
  sourceRaw: Buffer,
  upstreamRaw: Buffer,
  manifestRaw: Buffer,
  targetReceiptRaw: Buffer,
): GeneratedInputs {
  const sourceDigest = digest(sourceRaw), upstreamDigest = digest(upstreamRaw), manifestDigest = digest(manifestRaw), policyDigest = digest(policyRaw);
  const policies = parseNativePolicy(policyRaw);
  const source = parseSourceInventory(sourceRaw);
  const upstream = parseUpstreamInventory(upstreamRaw);
  if (upstream.version !== 2) throw new ProviderExactPolicyInputFailure("provider-exact mapping requires a complete version 2 upstream inventory");
  const manifest = parseManifest(manifestRaw, sourceDigest, upstreamDigest, source);
  if (manifest.tenant !== upstream.tenant) throw new ProviderExactPolicyInputFailure("reviewed route inputs select different tenants");
  const receipt = parseTargetReceipt(targetReceiptRaw, sourceDigest, upstreamDigest, manifestDigest);
  if (receipt.tenant !== upstream.tenant) throw new ProviderExactPolicyInputFailure("target route receipt selects a different tenant");

  const activeGrants = policies.filter((policy) => policy.enabled).flatMap((policy) => policy.grants);
  const activeGrantCoordinates = [...new Set(activeGrants.map(grantKey))];
  const sourceByGrant = new Map<string, (typeof source.mappings)[number]>();
  for (const item of source.mappings) {
    const key = grantKey(grantFromSource(item));
    if (sourceByGrant.has(key)) throw new ProviderExactPolicyInputFailure("source inventory has ambiguous policy coordinates");
    sourceByGrant.set(key, item);
  }
  assertExactSet(activeGrantCoordinates, [...sourceByGrant.keys()], "source policy grants do not have a complete exact source mapping");

  const sourceKeys = source.mappings.map(sourceKey);
  assertExactSet(sourceKeys, upstream.candidateSets.map((item) => sourceKey(item.source)), "upstream candidate pools do not cover every source mapping");
  assertExactSet(sourceKeys, manifest.specs.map((item) => sourceKey(item.source)), "reviewed route manifest does not cover every source mapping");

  const pools = new Map(upstream.candidateSets.map((item) => [sourceKey(item.source), item]));
  for (const spec of manifest.specs) {
    const pool = pools.get(sourceKey(spec.source));
    if (!pool || pool.protocol !== spec.protocol || pool.upstreamModel !== spec.upstreamModel || !sameBindings(pool.candidates, spec.candidates)) throw new ProviderExactPolicyInputFailure("reviewed route manifest has a non-exact native provider candidate set");
    const accounts = new Map(upstream.upstreams.map((item) => [item.accountId, item]));
    for (const candidate of spec.candidates) {
      const account = accounts.get(candidate.accountId);
      if (!account || account.sourceStableId !== candidate.sourceStableId || account.sourceProvider !== spec.source.provider || /(?:bridge|legacy|cliproxyapi)/iu.test(account.driver)) throw new ProviderExactPolicyInputFailure("reviewed route manifest selects a non-native or retired candidate");
    }
  }

  const selected: Array<{ source: (typeof manifest.specs)[number]["source"]; route: TargetRoute }> = [];
  for (const spec of manifest.specs) {
    const matchesForSpec = receipt.routes.filter((route) => matches(spec, route));
    if (matchesForSpec.length !== 1) throw new ProviderExactPolicyInputFailure("target route receipt lacks one exact post-replay route");
    selected.push({ source: spec.source, route: matchesForSpec[0]! });
  }
  if (new Set(selected.map((item) => item.route.routeId)).size !== selected.length) throw new ProviderExactPolicyInputFailure("reviewed source mappings converge on one target route");
  selected.sort((left, right) => compare(sourceKey(left.source), sourceKey(right.source)));

  const routeInventory = Buffer.from(`${JSON.stringify({
    version: 1,
    routes: selected.map(({ route }) => ({
      route_id: route.routeId,
      public_model: route.publicModel,
      upstream_model: route.upstreamModel,
      protocol: route.protocol,
      enabled: true,
      updated_at: route.updatedAt,
      upstream_account_ids: route.upstreamAccountIds,
      candidate_upstream_account_ids: route.candidateUpstreamAccountIds,
      candidate_sources: route.candidateSources.map((item) => ({ upstream_account_id: item.upstreamAccountId, source_stable_id: item.sourceStableId })),
    })),
  })}\n`);
  const routeDigest = digest(routeInventory);
  const policyMapping = Buffer.from(`${JSON.stringify({
    version: 1,
    tenant_external_id: upstream.tenant,
    source_snapshot_sha256: policyDigest,
    route_inventory_sha256: routeDigest,
    mappings: selected.map(({ source: routeSource, route }) => ({
      source: grantFromSource(routeSource),
      target: {
        route_id: route.routeId,
        expected_public_model: route.publicModel,
        expected_upstream_model: route.upstreamModel,
        expected_protocol: route.protocol,
        expected_updated_at: route.updatedAt,
        expected_upstream_account_ids: route.upstreamAccountIds,
        expected_candidate_upstream_account_ids: route.candidateUpstreamAccountIds,
        expected_candidate_sources: route.candidateSources.map((item) => ({ upstream_account_id: item.upstreamAccountId, source_stable_id: item.sourceStableId })),
      },
    })),
  })}\n`);
  return {
    routeInventory,
    policyMapping,
    receipt: {
      source_policy_sha256: policyDigest,
      source_inventory_sha256: sourceDigest,
      upstream_inventory_sha256: upstreamDigest,
      reviewed_route_manifest_sha256: manifestDigest,
      target_route_receipt_sha256: digest(targetReceiptRaw),
      route_inventory_sha256: routeDigest,
      reviewed_policy_mapping_sha256: digest(policyMapping),
      enabled_policy_count: policies.filter((policy) => policy.enabled).length,
      active_grant_count: activeGrants.length,
      distinct_active_grant_coordinate_count: sourceByGrant.size,
      mapped_route_count: selected.length,
      reauthorization_required_count: source.reauthorizationRequired,
      source_anomaly_count: source.anomalies.length,
    },
  };
}

type OutputTarget = Readonly<{ target: string; parentDescriptor: number }>;

function openSafeOutput(path: string): OutputTarget {
  if (!isAbsolute(path) || path !== resolve(path) || path === parse(path).root || path.includes("\0")) throw new ProviderExactPolicyInputFailure("output path must be an absolute normalized path");
  const directory = dirname(path), normalized = resolve(directory), root = parse(normalized).root;
  let current = root;
  for (const part of relative(root, normalized).split(sep).filter(Boolean)) {
    current = resolve(current, part);
    let metadata: ReturnType<typeof lstatSync>;
    try { metadata = lstatSync(current); } catch { throw new ProviderExactPolicyInputFailure("output directory is not safely writable"); }
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new ProviderExactPolicyInputFailure("output directory is not safely writable");
  }
  let descriptor: number | undefined;
  try {
    descriptor = openSync(normalized, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || (process.geteuid?.() !== undefined && metadata.uid !== process.geteuid()) || (metadata.mode & 0o022) !== 0) throw new ProviderExactPolicyInputFailure("output directory is not safely writable");
    const target = `/proc/self/fd/${descriptor}/${basename(path)}`;
    try { lstatSync(target); throw new ProviderExactPolicyInputFailure("output path already exists"); }
    catch (error) {
      if (error instanceof ProviderExactPolicyInputFailure) throw error;
      if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) throw new ProviderExactPolicyInputFailure("output path is not safely writable");
    }
    return { target, parentDescriptor: descriptor };
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    if (error instanceof ProviderExactPolicyInputFailure) throw error;
    throw new ProviderExactPolicyInputFailure("output directory is not safely writable");
  }
}

function writeAtomicNoOverwrite(output: OutputTarget, content: Buffer): void {
  const temporary = `${output.target}.tmp-${randomBytes(16).toString("hex")}`;
  let descriptor: number | undefined;
  try {
    descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    for (let offset = 0; offset < content.length;) {
      const written = writeSync(descriptor, content, offset, content.length - offset);
      if (written <= 0) throw new ProviderExactPolicyInputFailure("output could not be written safely");
      offset += written;
    }
    fsyncSync(descriptor); closeSync(descriptor); descriptor = undefined;
    linkSync(temporary, output.target); unlinkSync(temporary);
    const metadata = lstatSync(output.target);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o600) throw new ProviderExactPolicyInputFailure("output could not be persisted safely");
    fsyncSync(output.parentDescriptor);
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    try { lstatSync(temporary); unlinkSync(temporary); } catch {}
    if (error instanceof ProviderExactPolicyInputFailure) throw error;
    throw new ProviderExactPolicyInputFailure("output could not be persisted safely");
  }
}

type Options = Readonly<{
  policy?: string;
  source?: string;
  upstream?: string;
  manifest?: string;
  receipt?: string;
  routeOutput?: string;
  mappingOutput?: string;
}>;

function options(argv: readonly string[]): Options {
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write("usage: generate-provider-exact-policy-inputs --policy-snapshot-file FILE --source-inventory-file FILE --upstream-inventory-file FILE --reviewed-route-manifest-file FILE --target-route-receipt-file FILE --route-inventory-output FILE --reviewed-policy-mapping-output FILE\n\nDerive complete reviewed policy inputs from existing owner-reviewed source, native-provider, route and target-receipt inputs. It never applies a policy.\n");
    process.exit(0);
  }
  const names: Record<string, keyof Options> = {
    "--policy-snapshot-file": "policy",
    "--source-inventory-file": "source",
    "--upstream-inventory-file": "upstream",
    "--reviewed-route-manifest-file": "manifest",
    "--target-route-receipt-file": "receipt",
    "--route-inventory-output": "routeOutput",
    "--reviewed-policy-mapping-output": "mappingOutput",
  };
  const result: Record<string, string> = {};
  for (let index = 0; index < argv.length; index += 1) {
    const field = names[argv[index] ?? ""], value = argv[index + 1];
    if (!field || !value || value.startsWith("--") || result[field] !== undefined) throw new ProviderExactPolicyInputFailure("arguments are invalid");
    result[field] = value; index += 1;
  }
  if (!result.policy || !result.source || !result.upstream || !result.manifest || !result.receipt || !result.routeOutput || !result.mappingOutput || result.routeOutput === result.mappingOutput) throw new ProviderExactPolicyInputFailure("required arguments are missing");
  return result;
}

export function main(argv = process.argv.slice(2)): Readonly<Record<string, number | string>> {
  const selected = options(argv);
  const policy = readProtectedFile(selected.policy!, "source policy");
  const source = readProtectedFile(selected.source!, "source inventory");
  const upstream = readProtectedFile(selected.upstream!, "upstream inventory");
  const manifest = readProtectedFile(selected.manifest!, "reviewed route manifest");
  const targetReceipt = readProtectedFile(selected.receipt!, "target route receipt");
  let routeOutput: OutputTarget | undefined, mappingOutput: OutputTarget | undefined;
  try {
    const inputs = buildProviderExactPolicyInputs(policy, source, upstream, manifest, targetReceipt);
    routeOutput = openSafeOutput(selected.routeOutput!);
    mappingOutput = openSafeOutput(selected.mappingOutput!);
    writeAtomicNoOverwrite(routeOutput, inputs.routeInventory);
    try { writeAtomicNoOverwrite(mappingOutput, inputs.policyMapping); }
    catch (error) { try { unlinkSync(routeOutput.target); fsyncSync(routeOutput.parentDescriptor); } catch {} throw error; }
    return inputs.receipt;
  } finally {
    policy.fill(0); source.fill(0); upstream.fill(0); manifest.fill(0); targetReceipt.fill(0);
    if (mappingOutput) closeSync(mappingOutput.parentDescriptor);
    if (routeOutput) closeSync(routeOutput.parentDescriptor);
  }
}

if (invokedAsEntrypoint("generate-provider-exact-policy-inputs", import.meta.url)) {
  try { process.stdout.write(`${JSON.stringify(main())}\n`); }
  catch { process.stderr.write("provider-exact policy input generation stopped\n"); process.exitCode = 2; }
}
