/**
 * Exact, target-independent CPA Codex OAuth route inspection.
 *
 * This module intentionally does not import OAuth payloads or contact either
 * control plane.  Its model evidence is the CPA management plane's per-auth
 * registry projection, not an assumption that every enabled OAuth credential
 * supports every Codex model.
 */

import { createHash, createHmac } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readSync, type Dirent } from "node:fs";
import { relative, resolve, sep } from "node:path";
import { parseDocument } from "yaml";
import { parseStrictJson } from "../lib/strict-json.ts";

const SOURCE_VERSION = "cpa-upstream-import-v1";
const SOURCE_KEY_BYTES = 32;
const MAX_ACCOUNTS = 10_000;
const MAX_MODELS = 2_000;
const MAX_CONFIG_BYTES = 4 * 1024 * 1024;
const MAX_AUTH_BYTES = 1024 * 1024;
const STABLE_ID = /^[0-9a-f]{64}$/;
const PUBLIC_TEXT = /^[A-Za-z0-9][A-Za-z0-9._:/+@=-]{0,499}$/;
const MANAGED_ROUTE_SOURCE_DOMAIN = "memeloop-token-center\0cpa-managed-codex-route-source-account-id\0v1\0";

type ObjectValue = Record<string, unknown>;
type Alias = Readonly<{ name: string; alias: string }>;
type ClassifyRule = Readonly<{ field: "filename" | "id" | "provider"; pattern: string; group: string; enabled: boolean }>;

export class ManagedCodexRouteFailure extends Error {}

/** A protected CPA registry observation, captured from auth-files/models. */
export type ManagedCodexModelSnapshotEntry = Readonly<{
  auth_id: string;
  provider: "codex";
  registered_models: readonly string[];
}>;

export type ParsedManagedCodexModelSnapshot = Readonly<{
  source_config_sha256: string;
  auth_files_sha256: string;
  auth_models: readonly ManagedCodexModelSnapshotEntry[];
}>;

/** A source auth document is only retained in memory while its route proof is built. */
export type ManagedCodexAuthInput = Readonly<{
  relative_path: string;
  document: unknown;
}>;

export type ManagedCodexSourceCoordinate = Readonly<{
  provider: "codex";
  model: string;
  group: string | null;
  upstream_prefix: string | null;
  protocol: "openai";
}>;

export type ManagedCodexRouteCandidate = Readonly<{
  source_stable_id: string;
  source_provider: "codex";
  driver: "openai-codex";
}>;

export type ManagedCodexRouteModel = Readonly<{
  source: ManagedCodexSourceCoordinate;
  upstream_model: string;
  protocol: "openai";
  selection: "equal_round_robin";
  candidates: readonly ManagedCodexRouteCandidate[];
}>;

type ManagedAuth = Readonly<{
  relativePath: string;
  prefix: string | null;
  groups: readonly string[];
  aliases: readonly Alias[];
  excluded: readonly string[];
  registeredModels: ReadonlySet<string>;
}>;

type ParsedConfig = Readonly<{
  forceModelPrefix: boolean;
  globalAliases: readonly Alias[];
  globalExcluded: readonly string[];
  classifyRules: readonly ClassifyRule[];
}>;

function object(value: unknown, label: string): ObjectValue {
  if (value === null || Array.isArray(value) || typeof value !== "object") throw new ManagedCodexRouteFailure(`${label} has an invalid schema`);
  return value as ObjectValue;
}
function text(value: unknown, label: string, pattern = PUBLIC_TEXT): string {
  if (typeof value !== "string" || value.trim() !== value || !pattern.test(value) || /[\0\r\n]/.test(value)) throw new ManagedCodexRouteFailure(`${label} has an invalid schema`);
  return value;
}
function sourceText(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || Buffer.byteLength(value) > 500 || /[\0\r\n]/.test(value)) throw new ManagedCodexRouteFailure(`${label} has an invalid schema`);
  return value;
}
function compare(left: string, right: string): number { return left < right ? -1 : left > right ? 1 : 0; }
function sha256(value: Uint8Array): string { return createHash("sha256").update(value).digest("hex"); }
function key(value: ManagedCodexSourceCoordinate): string { return JSON.stringify([value.provider, value.model, value.group, value.upstream_prefix, value.protocol]); }
function sourceIdentity(relativePath: string): string { return [SOURCE_VERSION, "auth", relativePath, "codex"].join("\0"); }

/** Derive a route-only source stable ID. This deliberately is not the target pepper HMAC domain. */
export function managedCodexRouteSourceStableId(identityKey: Buffer, relativePath: string): string {
  if (identityKey.length !== SOURCE_KEY_BYTES) throw new ManagedCodexRouteFailure("managed Codex source identity key is invalid");
  const safePath = relativeAuthPath(relativePath);
  return createHmac("sha256", identityKey).update(Buffer.concat([Buffer.from(MANAGED_ROUTE_SOURCE_DOMAIN), Buffer.from(sourceIdentity(safePath))])).digest("hex");
}

function relativeAuthPath(value: unknown): string {
  const path = sourceText(value, "managed Codex auth relative path");
  if (Buffer.byteLength(path) > 512 || path.startsWith("/") || path.includes("\\") || path.split("/").some((part) => !part || part === "." || part === "..")) throw new ManagedCodexRouteFailure("managed Codex auth relative path is invalid");
  return path;
}
function readOwnerOnly(path: string, label: string, limit: number): Buffer {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600 || (process.geteuid?.() !== undefined && stat.uid !== process.geteuid())) throw new Error("unsafe");
    const output = Buffer.allocUnsafe(limit + 1); let offset = 0;
    while (offset < output.length) { const count = readSync(descriptor, output, offset, output.length - offset, null); if (count === 0) break; offset += count; }
    if (offset > limit) { output.fill(0); throw new ManagedCodexRouteFailure(`${label} exceeds the supported size`); }
    return Buffer.from(output.subarray(0, offset));
  } catch (error) {
    if (error instanceof ManagedCodexRouteFailure) throw error;
    throw new ManagedCodexRouteFailure(`${label} is not a readable owner-only regular file`);
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}
function safeAuthFiles(root: string): Array<readonly [string, string]> {
  let rootStat: ReturnType<typeof lstatSync>;
  try { rootStat = lstatSync(root); } catch { throw new ManagedCodexRouteFailure("CPA auth directory is not safely readable"); }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || (rootStat.mode & 0o777) !== 0o700 || (process.geteuid?.() !== undefined && rootStat.uid !== process.geteuid())) throw new ManagedCodexRouteFailure("CPA auth directory is not safely readable");
  const resolvedRoot = resolve(root), result: Array<readonly [string, string]> = [];
  const visit = (directory: string): void => {
    let entries: Dirent[];
    try { entries = readdirSync(directory, { withFileTypes: true }); } catch { throw new ManagedCodexRouteFailure("CPA auth directory is not safely readable"); }
    for (const entry of entries) {
      const path = resolve(directory, entry.name); let stat: ReturnType<typeof lstatSync>;
      try { stat = lstatSync(path); } catch { throw new ManagedCodexRouteFailure("CPA auth directory is not safely readable"); }
      if (stat.isSymbolicLink()) throw new ManagedCodexRouteFailure("CPA auth directory contains a symbolic link");
      if (stat.isDirectory()) {
        if ((stat.mode & 0o777) !== 0o700 || (process.geteuid?.() !== undefined && stat.uid !== process.geteuid())) throw new ManagedCodexRouteFailure("CPA auth directory contains an unsafe directory");
        visit(path); continue;
      }
      if (!stat.isFile() || !entry.name.toLowerCase().endsWith(".json")) throw new ManagedCodexRouteFailure("CPA auth directory contains an unsupported file");
      result.push([relative(resolvedRoot, path).split(sep).join("/"), path]);
    }
  };
  visit(resolvedRoot); result.sort(([left], [right]) => compare(left, right));
  if (result.length > MAX_ACCOUNTS) throw new ManagedCodexRouteFailure("CPA auth directory contains too many records");
  return result;
}

/** Read only Codex OAuth source documents from the same protected auth tree as the account importer. */
export function readManagedCodexAuthInputs(authDirectory: string): ManagedCodexAuthInput[] {
  const result: ManagedCodexAuthInput[] = [];
  for (const [relativePath, path] of safeAuthFiles(authDirectory)) {
    let document: ObjectValue;
    try { document = object(parseStrictJson(new TextDecoder("utf-8", { fatal: true }).decode(readOwnerOnly(path, "CPA auth document", MAX_AUTH_BYTES))), "CPA auth document"); }
    catch (error) { if (error instanceof ManagedCodexRouteFailure) throw error; throw new ManagedCodexRouteFailure("CPA auth document is invalid JSON"); }
    if (typeof document.type === "string" && document.type.trim().toLowerCase() === "codex") result.push({ relative_path: relativeAuthPath(relativePath), document });
  }
  return result;
}
function parseConfig(raw: Buffer): ObjectValue {
  if (raw.length > MAX_CONFIG_BYTES) throw new ManagedCodexRouteFailure("CPA config exceeds the supported size");
  try {
    const document = parseDocument(new TextDecoder("utf-8", { fatal: true }).decode(raw), { uniqueKeys: true });
    if (document.errors.length > 0 || document.warnings.length > 0) throw new Error("invalid YAML");
    return object(document.toJS({ maxAliasCount: 0 }), "CPA config");
  } catch { throw new ManagedCodexRouteFailure("CPA config is not valid safe YAML"); }
}
function normalizeAliases(value: unknown, label: string): Alias[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > MAX_MODELS) throw new ManagedCodexRouteFailure(`${label} has an invalid schema`);
  const result: Alias[] = [], seen = new Set<string>();
  for (const item of value) {
    const record = object(item, label);
    const name = record.name, alias = record.alias;
    // CPA's Config.SanitizeOAuthModelAlias drops incomplete/equivalent entries.
    if (typeof name !== "string" || typeof alias !== "string") continue;
    const cleanName = name.trim(), cleanAlias = alias.trim();
    if (!cleanName || !cleanAlias || Buffer.byteLength(cleanName) > 500 || Buffer.byteLength(cleanAlias) > 500 || /[\0\r\n]/.test(cleanName) || /[\0\r\n]/.test(cleanAlias) || cleanName.toLowerCase() === cleanAlias.toLowerCase()) continue;
    const aliasKey = cleanAlias.toLowerCase();
    if (seen.has(aliasKey)) continue;
    seen.add(aliasKey); result.push({ name: cleanName, alias: cleanAlias });
  }
  return result;
}
function normalizeExcluded(value: unknown, label: string): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > MAX_MODELS) throw new ManagedCodexRouteFailure(`${label} has an invalid schema`);
  const seen = new Set<string>();
  for (const item of value) {
    const entry = sourceText(item, label).toLowerCase();
    seen.add(entry);
  }
  return [...seen].sort(compare);
}
function literalGoRegexp(pattern: unknown, label: string): string {
  const value = sourceText(pattern, label);
  // The deployed rules are literal substring RE2 patterns (with escaped dots).
  // Accept only that common subset; arbitrary Go RE2 must be rejected rather
  // than approximated with JavaScript RegExp.
  let result = "";
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]!;
    if (character === "\\") {
      const escaped = value[index + 1];
      if (!escaped || !"\\.^$*+?()[]{}|".includes(escaped)) throw new ManagedCodexRouteFailure(`${label} uses an unsupported RE2 construct`);
      result += escaped; index += 1; continue;
    }
    if (".^$*+?()[]{}|".includes(character)) throw new ManagedCodexRouteFailure(`${label} uses an unsupported RE2 construct`);
    result += character;
  }
  if (!result) throw new ManagedCodexRouteFailure(`${label} is invalid`);
  return result;
}
function parseClassifyRules(config: ObjectValue): ClassifyRule[] {
  const plugins = config.plugins;
  if (plugins === undefined) return [];
  const pluginRoot = object(plugins, "CPA plugins"), configs = object(pluginRoot.configs, "CPA plugin configs"), policy = configs["cpa-key-policy"];
  if (policy === undefined) return [];
  const policyConfig = object(policy, "CPA key-policy plugin config");
  if (policyConfig.mode !== "native-access") throw new ManagedCodexRouteFailure("CPA key-policy plugin is not in native-access mode");
  const rawRules = policyConfig.classify_rules;
  if (rawRules === undefined || rawRules === null) return [];
  if (!Array.isArray(rawRules) || rawRules.length > MAX_ACCOUNTS) throw new ManagedCodexRouteFailure("CPA key-policy classify rules have an invalid schema");
  const result: ClassifyRule[] = [], names = new Set<string>();
  for (const value of rawRules) {
    const rule = object(value, "CPA key-policy classify rule");
    const name = sourceText(rule.name, "CPA key-policy classify rule name").toLowerCase();
    if (names.has(name)) throw new ManagedCodexRouteFailure("CPA key-policy classify rule is duplicated");
    names.add(name);
    if (typeof rule.enabled !== "boolean") throw new ManagedCodexRouteFailure("CPA key-policy classify rule has an invalid schema");
    const fieldValue = sourceText(rule.field, "CPA key-policy classify rule field").toLowerCase();
    if (fieldValue !== "filename" && fieldValue !== "id" && fieldValue !== "provider") throw new ManagedCodexRouteFailure("CPA key-policy classify rule needs unavailable scheduler metadata");
    const group = sourceText(rule.group, "CPA key-policy classify rule group").toLowerCase();
    result.push({ field: fieldValue, pattern: literalGoRegexp(rule.pattern, "CPA key-policy classify rule pattern"), group, enabled: rule.enabled });
  }
  return result;
}
function configInspection(raw: Buffer): ParsedConfig {
  const config = parseConfig(raw);
  const force = config["force-model-prefix"] ?? false;
  if (typeof force !== "boolean") throw new ManagedCodexRouteFailure("CPA force-model-prefix is invalid");
  const oauthAliases = config["oauth-model-alias"];
  const aliases = oauthAliases === undefined ? [] : normalizeAliases(object(oauthAliases, "CPA oauth-model-alias").codex, "CPA codex OAuth aliases");
  const oauthExcluded = config["oauth-excluded-models"];
  const excluded = oauthExcluded === undefined ? [] : normalizeExcluded(object(oauthExcluded, "CPA oauth-excluded-models").codex, "CPA Codex OAuth excluded models");
  return { forceModelPrefix: force, globalAliases: aliases, globalExcluded: excluded, classifyRules: parseClassifyRules(config) };
}
function authPrefix(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") return null;
  const normalized = value.trim().replace(/^\/+|\/+$/gu, "");
  return normalized && !normalized.includes("/") ? normalized : null;
}
function authGroups(relativePath: string, rules: readonly ClassifyRule[]): string[] {
  const result: string[] = [], seen = new Set<string>();
  for (const rule of rules) {
    if (!rule.enabled) continue;
    const field = rule.field === "provider" ? "codex" : relativePath;
    if (!field.includes(rule.pattern)) continue;
    const group = `classify:${rule.group}`;
    if (!seen.has(group)) { seen.add(group); result.push(group); }
  }
  return result;
}
function wildcard(pattern: string, value: string): boolean {
  const parts = pattern.toLowerCase().split("*"), input = value.toLowerCase();
  let offset = 0;
  if (parts[0] && !input.startsWith(parts[0]!)) return false;
  offset = parts[0]?.length ?? 0;
  for (let index = 1; index < parts.length - 1; index += 1) {
    const part = parts[index]!;
    if (!part) continue;
    const found = input.indexOf(part, offset); if (found < 0) return false;
    offset = found + part.length;
  }
  const suffix = parts.at(-1)!;
  return !suffix || input.endsWith(suffix);
}
function aliasesForAuth(perAuth: readonly Alias[], globalAliases: readonly Alias[]): readonly Alias[] {
  // Runtime resolution asks per-auth aliases first. It falls through to global
  // aliases only when this auth has no matching alias, not when lists differ.
  return [...perAuth, ...globalAliases];
}
function resolveAlias(requested: string, aliases: readonly Alias[]): string {
  const exact = requested.toLowerCase();
  for (const alias of aliases) if (alias.alias.toLowerCase() === exact) return alias.name;
  return requested;
}
function snapshotModels(entries: readonly ManagedCodexModelSnapshotEntry[]): Map<string, ReadonlySet<string>> {
  if (entries.length > MAX_ACCOUNTS) throw new ManagedCodexRouteFailure("managed Codex model snapshot is too large");
  const result = new Map<string, ReadonlySet<string>>();
  for (const entry of entries) {
    const authId = relativeAuthPath(entry.auth_id);
    if (entry.provider !== "codex" || !Array.isArray(entry.registered_models) || entry.registered_models.length > MAX_MODELS || result.has(authId)) throw new ManagedCodexRouteFailure("managed Codex model snapshot has an invalid schema");
    const models = entry.registered_models.map((model) => sourceText(model, "managed Codex registered model").toLowerCase());
    if (new Set(models).size !== models.length) throw new ManagedCodexRouteFailure("managed Codex model snapshot has duplicate models");
    result.set(authId, new Set(models));
  }
  return result;
}
function inspectAuths(inputs: readonly ManagedCodexAuthInput[], snapshot: Map<string, ReadonlySet<string>>, config: ParsedConfig): ManagedAuth[] {
  if (inputs.length > MAX_ACCOUNTS) throw new ManagedCodexRouteFailure("CPA managed Codex auth inventory is too large");
  const result: ManagedAuth[] = [], paths = new Set<string>();
  for (const input of inputs) {
    const relativePath = relativeAuthPath(input.relative_path);
    if (paths.has(relativePath)) throw new ManagedCodexRouteFailure("CPA managed Codex auth path is duplicated");
    paths.add(relativePath);
    const document = object(input.document, "CPA managed Codex auth document");
    if (typeof document.type !== "string" || document.type.trim().toLowerCase() !== "codex") throw new ManagedCodexRouteFailure("CPA managed auth input is not Codex OAuth");
    const disabled = document.disabled ?? false;
    if (typeof disabled !== "boolean") throw new ManagedCodexRouteFailure("CPA managed Codex auth disabled flag is invalid");
    const registeredModels = snapshot.get(relativePath);
    if (!registeredModels) throw new ManagedCodexRouteFailure("managed Codex model snapshot does not exactly cover source auth files");
    if (disabled) continue;
    const aliasesValue = Object.hasOwn(document, "model_aliases") ? document.model_aliases : document["model-aliases"];
    const excludedValue = Object.hasOwn(document, "excluded_models") ? document.excluded_models : document["excluded-models"];
    const perAuthAliases = normalizeAliases(aliasesValue, "CPA managed Codex per-auth aliases");
    const perAuthExcluded = normalizeExcluded(excludedValue, "CPA managed Codex per-auth excluded models");
    const excluded = [...new Set([...perAuthExcluded, ...config.globalExcluded])].sort(compare);
    result.push({ relativePath, prefix: authPrefix(document.prefix), groups: authGroups(relativePath, config.classifyRules), aliases: aliasesForAuth(perAuthAliases, config.globalAliases), excluded, registeredModels });
  }
  if (result.length === 0) throw new ManagedCodexRouteFailure("CPA source has no active managed Codex OAuth account");
  if (snapshot.size !== paths.size) throw new ManagedCodexRouteFailure("managed Codex model snapshot does not exactly cover source auth files");
  return result.sort((left, right) => compare(left.relativePath, right.relativePath));
}
function coordinate(value: ManagedCodexSourceCoordinate): ManagedCodexSourceCoordinate {
  if (value.provider !== "codex" || value.protocol !== "openai") throw new ManagedCodexRouteFailure("managed Codex route is not an exact Codex OpenAI source coordinate");
  const model = text(value.model, "managed Codex route model");
  const group = value.group === null ? null : text(value.group, "managed Codex route group").toLowerCase();
  if (group !== null && !group.startsWith("classify:")) throw new ManagedCodexRouteFailure("managed Codex route uses an unsupported non-custom credential group");
  const upstreamPrefix = value.upstream_prefix === null ? null : text(value.upstream_prefix, "managed Codex route upstream prefix");
  if (model.includes("/")) throw new ManagedCodexRouteFailure("managed Codex route model must be canonical rather than prefixed");
  return { provider: "codex", model, group, upstream_prefix: upstreamPrefix, protocol: "openai" };
}
function authCanServe(auth: ManagedAuth, config: ParsedConfig, source: ManagedCodexSourceCoordinate): { upstreamModel: string } | undefined {
  if (source.group !== null && !auth.groups.includes(source.group)) return undefined;
  if (source.upstream_prefix !== null) {
    if (auth.prefix !== source.upstream_prefix) return undefined;
  } else if (config.forceModelPrefix && auth.prefix !== null) return undefined;
  const requested = source.upstream_prefix === null ? source.model : `${source.upstream_prefix}/${source.model}`;
  const aliasInput = source.upstream_prefix === null ? source.model : source.model;
  const upstreamModel = resolveAlias(aliasInput, auth.aliases);
  if (auth.excluded.some((pattern) => wildcard(pattern, upstreamModel))) return undefined;
  if (!auth.registeredModels.has(requested.toLowerCase()) && !auth.registeredModels.has(upstreamModel.toLowerCase())) return undefined;
  return { upstreamModel };
}

/**
 * Build exact managed Codex candidate pools. Every returned candidate has a
 * verified custom group, prefix eligibility, credential-aware alias result,
 * and CPA runtime registry observation. Ambiguous upstream model mappings are
 * not representable by MTC's one-upstream-model route contract and fail closed.
 */
export function inspectManagedCodexRouteModels(
  configRaw: Buffer,
  authInputs: readonly ManagedCodexAuthInput[],
  modelSnapshot: readonly ManagedCodexModelSnapshotEntry[],
  requestedCoordinates: readonly ManagedCodexSourceCoordinate[],
  identityKey: Buffer,
  options: Readonly<{ allow_missing_candidates?: boolean }> = {},
): ManagedCodexRouteModel[] {
  if (identityKey.length !== SOURCE_KEY_BYTES) throw new ManagedCodexRouteFailure("managed Codex source identity key is invalid");
  const config = configInspection(configRaw), auths = inspectAuths(authInputs, snapshotModels(modelSnapshot), config);
  if (requestedCoordinates.length === 0 || requestedCoordinates.length > MAX_MODELS) throw new ManagedCodexRouteFailure("managed Codex source route set is invalid");
  const results: ManagedCodexRouteModel[] = [], seen = new Set<string>();
  for (const raw of requestedCoordinates) {
    const source = coordinate(raw), sourceKey = key(source);
    if (seen.has(sourceKey)) throw new ManagedCodexRouteFailure("managed Codex source route is duplicated");
    seen.add(sourceKey);
    const selected: Array<{ auth: ManagedAuth; upstreamModel: string }> = [];
    for (const auth of auths) {
      const candidate = authCanServe(auth, config, source);
      if (candidate) selected.push({ auth, ...candidate });
    }
    if (selected.length === 0) {
      if (options.allow_missing_candidates === true) continue;
      throw new ManagedCodexRouteFailure("managed Codex source route has no exact active account candidate");
    }
    const upstreamModels = new Set(selected.map((item) => item.upstreamModel));
    if (upstreamModels.size !== 1) throw new ManagedCodexRouteFailure("managed Codex source route resolves to incompatible per-account upstream models");
    const candidates = selected.map((item) => ({ source_stable_id: managedCodexRouteSourceStableId(identityKey, item.auth.relativePath), source_provider: "codex" as const, driver: "openai-codex" as const })).sort((left, right) => compare(left.source_stable_id, right.source_stable_id));
    if (new Set(candidates.map((item) => item.source_stable_id)).size !== candidates.length || candidates.some((item) => !STABLE_ID.test(item.source_stable_id))) throw new ManagedCodexRouteFailure("managed Codex source candidate identity is invalid");
    results.push({ source, upstream_model: selected[0]!.upstreamModel, protocol: "openai", selection: "equal_round_robin", candidates });
  }
  return results.sort((left, right) => compare(key(left.source), key(right.source)));
}

/**
 * Encode the managed portion using the existing provider-candidate-material v1
 * set shape. The caller combines these sets with direct sets before one final
 * serialization and digest; this helper never invents a cross-artifact digest.
 */
export function managedCodexCandidateSets(models: readonly ManagedCodexRouteModel[]): readonly ManagedCodexRouteModel[] {
  if (models.length === 0 || models.length > MAX_MODELS) throw new ManagedCodexRouteFailure("managed Codex candidate material is empty or too large");
  const seen = new Set<string>();
  for (const model of models) {
    const source = coordinate(model.source), sourceKey = key(source);
    if (seen.has(sourceKey) || model.protocol !== "openai" || model.selection !== "equal_round_robin" || model.candidates.length === 0 || model.candidates.some((candidate) => candidate.driver !== "openai-codex" || candidate.source_provider !== "codex" || !STABLE_ID.test(candidate.source_stable_id))) throw new ManagedCodexRouteFailure("managed Codex candidate material is invalid");
    seen.add(sourceKey);
  }
  return [...models].sort((left, right) => compare(key(left.source), key(right.source)));
}

/** A small public receipt for snapshot pinning; it excludes auth paths and model IDs. */
export function managedCodexModelSnapshotDigest(entries: readonly ManagedCodexModelSnapshotEntry[]): string {
  const normalized = [...snapshotModels(entries).entries()].map(([authId, models]) => ({ auth_id: authId, provider: "codex", registered_models: [...models].sort(compare) })).sort((left, right) => compare(left.auth_id, right.auth_id));
  return sha256(Buffer.from(`${JSON.stringify({ version: 1, auth_models: normalized })}\n`));
}

/** Reject a runtime model observation captured for a different source config. */
export function assertManagedCodexModelSnapshotConfig(snapshot: ParsedManagedCodexModelSnapshot, configRaw: Buffer): void {
  if (!STABLE_ID.test(snapshot.source_config_sha256) || snapshot.source_config_sha256 !== sha256(configRaw)) throw new ManagedCodexRouteFailure("managed Codex model snapshot does not match the source config");
}

/** Parse a sealed snapshot document written by the future read-only capture step. */
export function parseManagedCodexModelSnapshot(raw: Buffer): ParsedManagedCodexModelSnapshot {
  let value: unknown;
  try { value = parseStrictJson(new TextDecoder("utf-8", { fatal: true }).decode(raw)); }
  catch { throw new ManagedCodexRouteFailure("managed Codex model snapshot is not strict JSON"); }
  const root = object(value, "managed Codex model snapshot");
  if (Object.keys(root).sort().join("\0") !== "auth_files_sha256\0auth_models\0source_config_sha256\0version" || root.version !== 1 || typeof root.source_config_sha256 !== "string" || typeof root.auth_files_sha256 !== "string" || !STABLE_ID.test(root.source_config_sha256) || !STABLE_ID.test(root.auth_files_sha256) || !Array.isArray(root.auth_models)) throw new ManagedCodexRouteFailure("managed Codex model snapshot has an invalid schema");
  const authModels = root.auth_models.map((entry) => {
    const record = object(entry, "managed Codex model snapshot entry");
    if (Object.keys(record).sort().join("\0") !== "auth_id\0provider\0registered_models") throw new ManagedCodexRouteFailure("managed Codex model snapshot has an invalid schema");
    if (record.provider !== "codex" || !Array.isArray(record.registered_models)) throw new ManagedCodexRouteFailure("managed Codex model snapshot has an invalid schema");
    return { auth_id: relativeAuthPath(record.auth_id), provider: "codex" as const, registered_models: record.registered_models.map((model) => sourceText(model, "managed Codex registered model")) };
  });
  snapshotModels(authModels);
  return { source_config_sha256: root.source_config_sha256 as string, auth_files_sha256: root.auth_files_sha256 as string, auth_models: authModels };
}
