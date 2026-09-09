#!/usr/bin/env node
/**
 * Reconcile only existing direct-account transport metadata. Never imports,
 * updates accounts, discovers secrets, or relaxes the normal binding resolver.
 */
import { createHash } from "node:crypto";
import { closeSync } from "node:fs";
import { isAbsolute } from "node:path";
import {
  ImportFailure, buildInventory, canonicalJson, cpaRouteSourceStableId,
  decodeUtf8, openSafeOutput, parseTransportPolicy,
  readOwnerOnly, readSourceIdentityKey, requestJson, targetAccount,
  upstreamUrl, writeBindingReceipt,
} from "./import-cpa-upstreams.ts";
import { invokedAsEntrypoint } from "../lib/invoked-as-entrypoint.ts";
import { parseSourceInventory } from "../legacy-routes/import-cpa-model-routes.ts";
import { exactSet, parseCandidateMaterial, sourceKey } from "../legacy-routes/compose-cpa-upstream-inventory.ts";

const MAX_BYTES = 4 * 1024 * 1024;
const sha256 = (value: Buffer | string): string => createHash("sha256").update(value).digest("hex");
type Config = Record<string, unknown>;
export type SourceTransport = Readonly<{
  stableId: string; provider: string; name: string; config: Config; proxied: boolean;
  disabled?: boolean;
}>;
export type ExistingTransport = Readonly<{
  id: string; name: string; driver: string; config: Config; status: string; updatedAt: number;
}>;
type GapReason = "source_candidate_unavailable" | "source_candidate_metadata_mismatch"
  | "source_proxy_unverifiable" | "target_absent" | "target_ambiguous"
  | "target_inactive" | "target_driver_mismatch" | "target_config_mismatch"
  | "target_transport_invalid" | "shared_base_transport_conflict";
type Candidate = Readonly<{ sourceStableId: string; sourceProvider: string }>;
type Match = { source_stable_id: string; source_provider: string; upstream_account_id: string; updated_at: number };
type Gap = { source_stable_id: string; source_provider: string; reason: GapReason };

/** Reject schema-valid but incomplete/empty candidate material before any GET. */
export function validateTransportInputs(sourceRaw: Buffer, candidateRaw: Buffer) {
  const source = parseSourceInventory(sourceRaw), material = parseCandidateMaterial(candidateRaw);
  if (source.version !== 2 || source.mappings.length === 0 || material.sets.length === 0
    || material.sourceDigest !== sha256(sourceRaw)) throw new ImportFailure("transport source inventory is empty or mismatched");
  exactSet(source.mappings.map(sourceKey), material.sets.map(x => sourceKey(x.source)),
    "transport candidate pools do not exactly cover source mappings");
  const candidates = [...material.candidates.values()].filter(x => x.driver === "http-json");
  if (candidates.length === 0) throw new ImportFailure("transport source has no direct candidates");
  return { source, material, candidates };
}

/** Pure comparison. No target credentials are accepted or inspected. */
export function reconcileTransport(
  sources: readonly SourceTransport[], targets: readonly ExistingTransport[], candidates: readonly Candidate[],
): { policy: { contract_version: number; private_target_base_urls: string[]; result_origins_by_base_url: Record<string, string[]> }; matches: Match[]; quarantined: Gap[] } {
  if (new Set(sources.map(x => x.stableId)).size !== sources.length
    || new Set(targets.map(x => x.id)).size !== targets.length) throw new ImportFailure("transport inventory has duplicate identities");
  const bySource = new Map(sources.map(x => [x.stableId, x]));
  const groups = new Map<string, { source: SourceTransport; target: ExistingTransport; scope: string; origins?: string[] }[]>();
  const quarantined: Gap[] = [];
  const gap = (candidate: Candidate, reason: GapReason): void => {
    quarantined.push({ source_stable_id: candidate.sourceStableId, source_provider: candidate.sourceProvider, reason });
  };
  for (const candidate of candidates) {
    const source = bySource.get(candidate.sourceStableId);
    if (!source || source.disabled) { gap(candidate, "source_candidate_unavailable"); continue; }
    if (source.provider !== candidate.sourceProvider) { gap(candidate, "source_candidate_metadata_mismatch"); continue; }
    if (source.proxied) { gap(candidate, "source_proxy_unverifiable"); continue; }
    const named = targets.filter(x => x.name === source.name);
    if (named.length === 0) { gap(candidate, "target_absent"); continue; }
    if (named.length !== 1) { gap(candidate, "target_ambiguous"); continue; }
    const target = named[0]!;
    if (target.status !== "active") { gap(candidate, "target_inactive"); continue; }
    if (target.driver !== "http-json") { gap(candidate, "target_driver_mismatch"); continue; }
    const config = { ...target.config }, scope = config.network_scope, origins = config.result_origins;
    if (scope !== "public" && scope !== "private") { gap(candidate, "target_transport_invalid"); continue; }
    // The shared importer requires a private SOCKS proxy for private targets.
    // Source-proxy candidates have already been quarantined, so admitting a
    // private target here could only manufacture an unprovable transport.
    if (scope === "private") { gap(candidate, "source_proxy_unverifiable"); continue; }
    // Only transport annotations may differ. All other configuration, including
    // exact base URL and extra target options, remains an exact comparison.
    delete config.result_origins;
    config.network_scope = source.config.network_scope;
    if (canonicalJson(config, "target transport configuration") !== canonicalJson(source.config, "source transport configuration")) {
      gap(candidate, "target_config_mismatch"); continue;
    }
    const base = source.config.base_url;
    if (typeof base !== "string" || (origins !== undefined
      && (!Array.isArray(origins) || origins.some(x => typeof x !== "string")))) {
      gap(candidate, "target_transport_invalid"); continue;
    }
    try {
      parseTransportPolicy(Buffer.from(JSON.stringify({
        contract_version: 1, private_target_base_urls: [],
        result_origins_by_base_url: origins === undefined ? {} : { [base]: origins },
      })), false);
    } catch { gap(candidate, "target_transport_invalid"); continue; }
    const group = groups.get(base) ?? [];
    group.push({ source, target, scope, ...(origins === undefined ? {} : { origins: origins as string[] }) });
    groups.set(base, group);
  }
  const policy = { contract_version: 1, private_target_base_urls: [] as string[], result_origins_by_base_url: {} as Record<string, string[]> };
  const matches: Match[] = [];
  for (const [base, group] of [...groups].sort(([a], [b]) => a.localeCompare(b))) {
    const signatures = new Set(group.map(x => JSON.stringify([x.scope, x.origins])));
    // A base-level policy cannot represent contradictory per-account states.
    const otherSources = sources.filter(x => x.config.base_url === base && !group.some(g => g.source.stableId === x.stableId));
    if (signatures.size !== 1 || otherSources.length !== 0) {
      for (const item of group) gap({ sourceStableId: item.source.stableId, sourceProvider: item.source.provider }, "shared_base_transport_conflict");
      continue;
    }
    if (group[0]!.scope === "private") policy.private_target_base_urls.push(base);
    if (group[0]!.origins !== undefined) policy.result_origins_by_base_url[base] = group[0]!.origins!;
    for (const { source, target } of group) matches.push({
      source_stable_id: source.stableId, source_provider: source.provider,
      upstream_account_id: target.id, updated_at: target.updatedAt,
    });
  }
  matches.sort((a, b) => a.source_stable_id.localeCompare(b.source_stable_id));
  quarantined.sort((a, b) => a.source_stable_id.localeCompare(b.source_stable_id));
  return { policy, matches, quarantined };
}

export async function runTransportReconciliation(argv: readonly string[]): Promise<void> {
  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) {
    process.stdout.write("usage: reconcile-existing-transport --config FILE --auth-dir DIR --source-identity-key-file FILE --source-inventory-file FILE --provider-candidate-material-file FILE --tenant ID --target-api-base-url URL --service-token-file FILE --policy-output FILE --receipt-output FILE [--ca-file FILE] [--allow-http-loopback]\nRead-only existing transport reconciliation; no apply mode.\n");
    return;
  }
  const allowed = new Set(["--config", "--auth-dir", "--source-identity-key-file",
    "--provider-candidate-material-file", "--source-inventory-file", "--tenant",
    "--target-api-base-url", "--service-token-file", "--policy-output", "--receipt-output", "--ca-file"]);
  const options = new Map<string, string>();
  let loopback = false;
  for (let i = 0; i < argv.length; i++) {
    const name = argv[i]!;
    if (name === "--allow-http-loopback" && !loopback) { loopback = true; continue; }
    if (!allowed.has(name) || options.has(name) || !argv[i + 1] || argv[i + 1]!.startsWith("--")) throw new ImportFailure("transport reconciliation arguments are invalid");
    options.set(name, argv[++i]!);
  }
  for (const name of allowed) {
    if (name !== "--ca-file" && !options.has(name)) throw new ImportFailure("transport reconciliation requires explicit inputs");
  }
  const get = (name: string): string => options.get(name)!;
  for (const [name, value] of options) {
    if (name !== "--tenant" && name !== "--target-api-base-url" && !isAbsolute(value)) throw new ImportFailure("transport reconciliation paths must be absolute");
  }
  const tenant = get("--tenant");
  if (!/^[A-Za-z0-9._:-]{1,200}$/.test(tenant)) throw new ImportFailure("target tenant is invalid");
  if (get("--policy-output") === get("--receipt-output")) throw new ImportFailure("transport output paths must differ");
  const configRaw = readOwnerOnly(get("--config"), "sealed source config", MAX_BYTES);
  const sourceRaw = readOwnerOnly(get("--source-inventory-file"), "sealed source inventory", MAX_BYTES);
  const candidateRaw = readOwnerOnly(get("--provider-candidate-material-file"), "sealed candidate material", MAX_BYTES);
  const identity = readSourceIdentityKey(get("--source-identity-key-file"));
  const tokenRaw = readOwnerOnly(get("--service-token-file"), "target service token", 64 * 1024);
  try {
    const validated = validateTransportInputs(sourceRaw, candidateRaw);
    const { candidates } = validated;
    const empty = parseTransportPolicy(Buffer.from('{"contract_version":1,"private_target_base_urls":[]}'), false);
    const [inventory] = buildInventory(get("--config"), get("--auth-dir"), empty, false);
    const sources: SourceTransport[] = inventory.direct.map(x => ({
      stableId: cpaRouteSourceStableId(identity, x.sourceId), provider: x.sourceProvider,
      name: x.name, config: x.config, proxied: x.proxySecretRef !== undefined, disabled: x.disabled,
    }));
    const token = decodeUtf8(tokenRaw, "target service token").replace(/\r?\n$/, "");
    if (!/^[!-~]{1,8192}$/.test(token)) throw new ImportFailure("target service token is invalid");
    const base = upstreamUrl(get("--target-api-base-url"), "target control base URL", loopback);
    const response = await requestJson("GET", `${base}/internal/v1/upstreams?tenant_external_id=${encodeURIComponent(tenant)}&limit=100`,
      token, "target upstream inventory", [200], undefined, undefined, options.get("--ca-file"));
    if (!Array.isArray(response.value) || response.value.length >= 100) throw new ImportFailure("target upstream inventory is incomplete");
    const targets = response.value.map(value => {
      const item = targetAccount(value, tenant);
      return { ...item, config: JSON.parse(item.config) as Config };
    });
    const result = reconcileTransport(sources, targets, candidates);
    const policyBytes = Buffer.from(`${JSON.stringify(result.policy)}\n`);
    const configAfter = readOwnerOnly(get("--config"), "sealed source config", MAX_BYTES);
    try {
      if (sha256(configRaw) !== sha256(configAfter)) throw new ImportFailure("source config changed during reconciliation");
    } finally { configAfter.fill(0); }
    const receipt = Buffer.from(`${JSON.stringify({
      version: 1, mode: "read-only-transport-reconciliation", tenant_external_id: tenant,
      source_config_sha256: sha256(configRaw), source_inventory_sha256: sha256(sourceRaw),
      provider_candidate_material_sha256: sha256(candidateRaw),
      target_inventory_sha256: sha256(canonicalJson(response.value, "target inventory")),
      transport_policy_sha256: sha256(policyBytes), candidate_count: candidates.length,
      source_mapping_count: validated.source.mappings.length,
      source_anomaly_count: validated.source.anomalies.length,
      reauthorization_required_count: validated.source.reauthorizationRequired,
      managed_candidate_count: validated.material.candidates.size - candidates.length,
      coverage: "supplied-source-mappings-and-direct-candidates-only",
      matched_count: result.matches.length, quarantined_count: result.quarantined.length,
      matches: result.matches, quarantined: result.quarantined,
    })}\n`);
    const policyOutput = openSafeOutput(get("--policy-output"));
    try {
      const receiptOutput = openSafeOutput(get("--receipt-output"));
      try { writeBindingReceipt(policyOutput, policyBytes); writeBindingReceipt(receiptOutput, receipt); }
      finally { closeSync(receiptOutput.parentDescriptor); }
    } finally { closeSync(policyOutput.parentDescriptor); }
    process.stdout.write(`${JSON.stringify({ mode: "read-only-transport-reconciliation", candidate_count: candidates.length,
      matched_count: result.matches.length, quarantined_count: result.quarantined.length })}\n`);
  } finally { configRaw.fill(0); sourceRaw.fill(0); candidateRaw.fill(0); identity.fill(0); tokenRaw.fill(0); }
}

if (invokedAsEntrypoint("reconcile-existing-transport", import.meta.url)) {
  runTransportReconciliation(process.argv.slice(2)).catch(() => {
    process.stderr.write("transport reconciliation stopped; no target mutation was attempted\n");
    process.exitCode = 2;
  });
}
