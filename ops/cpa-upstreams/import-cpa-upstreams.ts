#!/usr/bin/env node
/** Inventory and import CPA upstream accounts through the control API. */

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readdirSync, lstatSync, openSync, closeSync, fstatSync, fsyncSync, linkSync, readSync, unlinkSync, writeSync, constants } from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { basename, dirname, isAbsolute, parse, relative, resolve, sep } from "node:path";
import { parseDocument } from "yaml";
import { parseStrictJson } from "../lib/strict-json.ts";

const MAX_CONFIG_BYTES = 4 * 1024 * 1024;
const MAX_AUTH_BYTES = 1024 * 1024;
const MAX_SECRET_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const MAX_ACCOUNTS = 10_000;
const SOURCE_VERSION = "cpa-upstream-import-v1";
const SOURCE_KEY_PREFIX = Buffer.from("4d54432d534f555243452d49442d4b45590001", "hex");
const SOURCE_KEY_BYTES = 32;
const TENANT_PATTERN = /^[A-Za-z0-9._:-]{1,200}$/;
const HANDLE_PATTERN = /^[A-Za-z0-9]{1,80}$/;
const HEADER_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,200}$/;
const MANAGED_OAUTH_SOURCE_TYPES: Readonly<Record<string, string>> = { codex: "codex", gemini: "gemini-legacy" };
const DIRECT_ROUTE_SOURCE_DOMAIN = "memeloop-token-center\0cpa-route-source-account-id\0v1\0";
const SHA256 = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export class ImportFailure extends Error {}
type JsonObject = Record<string, unknown>;
type ProxyNetworkScope = "private";
type TargetNetworkScope = "public" | "private";
type DirectAccount = { sourceId: string; sourceProvider: string; name: string; driver: "http-json"; config: JsonObject; header: string; prefix: string; secretRef: string; proxySecretRef?: string; proxyNetworkScope?: ProxyNetworkScope; disabled: boolean };
type NativeReauthorization = { sourceId: string; provider: string; sourceDisabled: boolean };
type ManagedOAuth = { sourceId: string; stableId: string; sourceType: string; payloadRef: string };
type Inventory = { direct: DirectAccount[]; native: NativeReauthorization[]; managed: ManagedOAuth[]; disabledSourceCount: number };
type TransportPolicy = {
  privateTargetBaseUrls: Set<string>;
  matchedPrivateTargetBaseUrls: Set<string>;
  resultOriginsByBaseUrl: Map<string, string[]>;
  matchedResultOriginBaseUrls: Set<string>;
};
type ProviderCandidate = Readonly<{ sourceStableId: string; sourceProvider: string; driver: "http-json" }>;
type BindingReceipt = Readonly<{
  sourceInventoryDigest: string;
  providerCandidateMaterialDigest: string;
  tenant: string;
  bindings: readonly Readonly<{ sourceStableId: string; sourceProvider: string; accountId: string; driver: "http-json"; updatedAt: number }>[];
  quarantined: readonly Readonly<{ sourceStableId: string; sourceProvider: string; reason: "source_candidate_unavailable" | "source_candidate_metadata_mismatch" | "target_absent" | "target_driver_mismatch" | "target_config_mismatch" | "target_inactive" | "target_ambiguous" }>[];
}>;

/** Non-secret source coordinates reused by route-inventory export. */
export type CpaRouteSourceAccount = Readonly<{ sourceId: string; sourceProvider: string; driver: "http-json"; disabled: boolean }>;
export type CpaRouteModel = Readonly<{ provider: string; model: string; upstreamModel: string; upstreamPrefix: string | null; protocol: "openai" | "anthropic"; candidateSourceIds: readonly string[] }>;
export type CpaOpaqueReauthorization = Readonly<{ sourceId: string; provider: string }>;
export type CpaSourceRouteInspection = Readonly<{ accounts: readonly CpaRouteSourceAccount[]; models: readonly CpaRouteModel[]; opaqueReauthorizations: readonly CpaOpaqueReauthorization[] }>;

/** Derive the same non-reversible direct-account identity used by the source route exporter. */
export function cpaRouteSourceStableId(identityKey: Buffer, sourceId: string): string {
  if (identityKey.length !== SOURCE_KEY_BYTES || !sourceId) throw new ImportFailure("source route identity inputs are invalid");
  return createHmac("sha256", identityKey).update(Buffer.concat([Buffer.from(DIRECT_ROUTE_SOURCE_DOMAIN), Buffer.from(sourceId)])).digest("hex");
}

class SecretStore {
  readonly values = new Map<string, unknown>();
  put(reference: string, value: unknown): void {
    if (this.values.has(reference)) throw new ImportFailure("CPA source identity is duplicated");
    this.values.set(reference, value);
  }
  string(reference: string): string {
    const value = this.values.get(reference);
    if (typeof value !== "string") throw new ImportFailure("internal credential reference is invalid");
    return value;
  }
  take(reference: string): JsonObject {
    const value = this.values.get(reference);
    this.values.delete(reference);
    return mapping(value, "internal managed OAuth reference");
  }
}
const UTF8 = new TextDecoder("utf-8", { fatal: true });
function decodeUtf8(value: Uint8Array, label: string): string {
  try { return UTF8.decode(value); }
  catch { throw new ImportFailure(`${label} is not valid UTF-8`); }
}
function readBoundedDescriptor(descriptor: number, limit: number, label: string): Buffer {
  const buffer = Buffer.allocUnsafe(limit + 1); let offset = 0;
  while (offset < buffer.length) { const count = readSync(descriptor, buffer, offset, buffer.length - offset, null); if (count === 0) break; offset += count; }
  if (offset > limit) { buffer.fill(0); throw new ImportFailure(`${label} exceeds the allowed size`); }
  return Buffer.from(buffer.subarray(0, offset));
}

function mapping(value: unknown, label: string): JsonObject {
  if (value === null || Array.isArray(value) || typeof value !== "object") throw new ImportFailure(`${label} must be a string-keyed mapping`);
  return value as JsonObject;
}
function list(value: unknown, label: string): unknown[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new ImportFailure(`${label} must be a list`);
  return value;
}
function exact(value: JsonObject, allowed: readonly string[], label: string): void {
  if (Object.keys(value).some((key) => !allowed.includes(key))) throw new ImportFailure(`${label} contains an unsupported field`);
}
function secretString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || Buffer.byteLength(value) > 16 * 1024 || /[\0\r\n]/.test(value)) {
    throw new ImportFailure(`${label} is invalid`);
  }
  return value;
}
function readOwnerOnly(path: string, label: string, limit: number): Buffer {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || (stat.mode & 0o777) !== 0o600 || (process.geteuid?.() !== undefined && stat.uid !== process.geteuid()) || stat.nlink !== 1) throw new Error("unsafe");
    return readBoundedDescriptor(descriptor, limit, label);
  } catch (error) {
    if (error instanceof ImportFailure) throw error;
    throw new ImportFailure(`${label} is not a readable owner-only regular file`);
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}
function parseConfig(raw: Buffer): JsonObject {
  try {
    const document = parseDocument(decodeUtf8(raw, "CPA config"), { uniqueKeys: true });
    if (document.errors.length > 0 || document.warnings.length > 0) throw new Error("invalid YAML");
    const result = mapping(document.toJS({ maxAliasCount: 0 }), "CPA config");
    if (typeof result["auth-dir"] !== "string" || !(result["auth-dir"] as string).trim()) throw new ImportFailure("CPA config must declare auth-dir");
    for (const [key, value] of Object.entries(result)) {
      if (["api-keys", "gemini-api-key", "codex-api-key", "claude-api-key", "openai-compatibility"].includes(key)) continue;
      if ((key.endsWith("-api-key") || key.endsWith("-compatibility")) && value) throw new ImportFailure("CPA config contains an unsupported upstream credential section");
    }
    return result;
  } catch (error) {
    if (error instanceof ImportFailure) throw error;
    throw new ImportFailure("CPA config is not valid safe YAML");
  }
}
function parseAuth(raw: Buffer): JsonObject {
  try { return mapping(parseStrictJson(decodeUtf8(raw, "CPA auth document")), "CPA auth document"); }
  catch { throw new ImportFailure("CPA auth document is invalid JSON"); }
}
function parseTransportPolicy(raw: Buffer, allowHttpLoopback: boolean): TransportPolicy {
  let document: JsonObject;
  try { document = mapping(parseStrictJson(decodeUtf8(raw, "CPA transport policy")), "CPA transport policy"); }
  catch { throw new ImportFailure("CPA transport policy is invalid JSON"); }
  exact(document, ["contract_version", "private_target_base_urls", "result_origins_by_base_url"], "CPA transport policy");
  if (document.contract_version !== 1) throw new ImportFailure("CPA transport policy has an unsupported contract version");
  const values = document.private_target_base_urls;
  if (!Array.isArray(values) || values.length > MAX_ACCOUNTS) throw new ImportFailure("CPA transport policy private targets must be a bounded list");
  const privateTargetBaseUrls = new Set<string>();
  for (const value of values) {
    const normalized = upstreamUrl(value, "CPA transport policy private target", allowHttpLoopback, "private");
    if (privateTargetBaseUrls.has(normalized)) throw new ImportFailure("CPA transport policy contains a duplicate private target");
    privateTargetBaseUrls.add(normalized);
  }
  const resultOriginsByBaseUrl = new Map<string, string[]>();
  const resultOriginEntries = Object.entries(mapping(document.result_origins_by_base_url ?? {}, "CPA transport policy result origins"));
  if (resultOriginEntries.length > MAX_ACCOUNTS) throw new ImportFailure("CPA transport policy contains too many result-origin entries");
  for (const [rawBaseUrl, rawOrigins] of resultOriginEntries) {
    const baseUrl = upstreamUrl(rawBaseUrl, "CPA transport policy result-origin base URL", allowHttpLoopback, "private");
    const origins = list(rawOrigins, "CPA transport policy result origins");
    if (origins.length === 0 || origins.length > 64) throw new ImportFailure("CPA transport policy result origins must be a bounded non-empty list");
    const normalized = origins.map((value) => upstreamOrigin(value, "CPA transport policy result origin", allowHttpLoopback));
    if (new Set(normalized).size !== normalized.length) throw new ImportFailure("CPA transport policy contains a duplicate result origin");
    if (resultOriginsByBaseUrl.has(baseUrl)) throw new ImportFailure("CPA transport policy contains a duplicate result-origin base URL");
    resultOriginsByBaseUrl.set(baseUrl, normalized);
  }
  return {
    privateTargetBaseUrls,
    matchedPrivateTargetBaseUrls: new Set<string>(),
    resultOriginsByBaseUrl,
    matchedResultOriginBaseUrls: new Set<string>(),
  };
}
function validateAuthDirectory(path: string): string {
  try {
    const stat = lstatSync(path);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700 || (process.geteuid?.() !== undefined && stat.uid !== process.geteuid())) throw new Error();
    return resolve(path);
  } catch { throw new ImportFailure("CPA auth directory must be an owner-owned mode-0700 directory"); }
}
function authFiles(root: string): Array<[string, string]> {
  const found: Array<[string, string]> = [];
  const visit = (directory: string): void => {
    const stat = lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700 || (process.geteuid?.() !== undefined && stat.uid !== process.geteuid())) throw new ImportFailure("CPA auth directory contains an unsafe directory");
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = resolve(directory, entry.name);
      const child = lstatSync(path);
      if (child.isSymbolicLink()) throw new ImportFailure("CPA auth directory contains a symbolic link");
      if (child.isDirectory()) visit(path);
      else if (child.isFile()) {
        if (!entry.name.toLowerCase().endsWith(".json")) throw new ImportFailure("CPA auth directory contains an unsupported file");
        found.push([relative(root, path).split(sep).join("/"), path]);
      }
    }
  };
  visit(root); found.sort(([a], [b]) => a.localeCompare(b, "en"));
  if (found.length > MAX_ACCOUNTS) throw new ImportFailure("CPA auth directory contains too many records");
  return found;
}
function upstreamUrl(value: unknown, label: string, allowHttpLoopback: boolean, scope: TargetNetworkScope = "public"): string {
  if (typeof value !== "string") throw new ImportFailure(`${label} must be a URL string`);
  let url: URL;
  try { url = new URL(value); } catch { throw new ImportFailure(`${label} is invalid`); }
  if (!["http:", "https:"].includes(url.protocol) || !url.hostname || url.username || url.password || url.search || url.hash) throw new ImportFailure(`${label} is invalid`);
  const testLoopback = allowHttpLoopback && ["localhost", "127.0.0.1", "::1", "[::1]"].includes(url.hostname);
  if (url.protocol === "http:" && scope !== "private" && !testLoopback) throw new ImportFailure(`${label} must use HTTPS`);
  url.pathname = url.pathname.replace(/\/+$/, "");
  return url.toString().replace(/\/$/, "");
}
function upstreamOrigin(value: unknown, label: string, allowHttpLoopback: boolean): string {
  const normalized = upstreamUrl(value, label, allowHttpLoopback);
  const url = new URL(normalized);
  if (url.pathname !== "/") throw new ImportFailure(`${label} must be an exact origin`);
  return url.origin;
}
function targetNetworkScope(baseUrl: string, policy: TransportPolicy): TargetNetworkScope {
  if (!policy.privateTargetBaseUrls.has(baseUrl)) return "public";
  policy.matchedPrivateTargetBaseUrls.add(baseUrl);
  return "private";
}
function reviewedTargetUrl(value: unknown, label: string, allowHttpLoopback: boolean, policy: TransportPolicy): string {
  const candidate = upstreamUrl(value, label, allowHttpLoopback, "private");
  const scope = policy.privateTargetBaseUrls.has(candidate) ? "private" : "public";
  return upstreamUrl(value, label, allowHttpLoopback, scope);
}
const digest = (value: string | Buffer): string => createHash("sha256").update(value).digest("hex");
const sourceIdentity = (...parts: unknown[]): string => [SOURCE_VERSION, ...parts.map(String)].join("\0");
const accountName = (label: string, sourceId: string): string => `cpa-${label.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 80) || "upstream"}-${digest(sourceId).slice(0, 16)}`;
function rejectUnsupportedTransport(entry: JsonObject, label: string): void {
  if (entry.headers !== undefined && JSON.stringify(entry.headers) !== "{}") throw new ImportFailure(`${label} uses custom headers unsupported by the target API`);
  if (entry.cloak !== undefined && JSON.stringify(entry.cloak) !== "{}") throw new ImportFailure(`${label} uses request cloaking unsupported by the target API`);
}
function privateAddress(host: string): boolean {
  const address = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  if (isIP(address) === 4) {
    const octets = address.split(".").map(Number);
    return octets[0] === 10 || (octets[0] === 172 && octets[1]! >= 16 && octets[1]! <= 31)
      || (octets[0] === 192 && octets[1] === 168)
      || (octets[0] === 100 && octets[1]! >= 64 && octets[1]! <= 127 && address !== "100.100.100.200");
  }
  if (isIP(address) === 6) {
    const normalized = address.toLowerCase().split("%")[0]!;
    return normalized.startsWith("fc") || normalized.startsWith("fd");
  }
  const normalized = address.toLowerCase().replace(/\.$/, "");
  return (!normalized.includes(".") && !normalized.includes(":")) || normalized === "localhost" || normalized.endsWith(".localhost") || normalized.endsWith(".local")
    || normalized.endsWith(".internal") || normalized.endsWith(".lan") || normalized.endsWith(".cluster.local");
}
function proxyUrl(value: unknown, label: string): { value: string; scope: ProxyNetworkScope } | undefined {
  if (value === undefined || value === "") return undefined;
  const raw = secretString(value, label);
  if (Buffer.byteLength(raw) > 2_048) throw new ImportFailure(`${label} is invalid`);
  let parsed: URL;
  try { parsed = new URL(raw); } catch { throw new ImportFailure(`${label} is invalid`); }
  if ((parsed.protocol !== "socks5:" && parsed.protocol !== "socks5h:") || !parsed.hostname
    || parsed.port === "0" || (parsed.pathname !== "" && parsed.pathname !== "/") || parsed.search || parsed.hash) throw new ImportFailure(`${label} is invalid`);
  const proxyHost = parsed.hostname.startsWith("[") && parsed.hostname.endsWith("]") ? parsed.hostname.slice(1, -1) : parsed.hostname;
  if (parsed.protocol === "socks5h:" && isIP(proxyHost) === 0) throw new ImportFailure(`${label} is invalid`);
  if (!privateAddress(parsed.hostname)) throw new ImportFailure(`${label} must use a private SOCKS5 endpoint`);
  return { value: raw, scope: "private" };
}
function effectiveProxy(provider: unknown, account: unknown, label: string): { value: string; scope: ProxyNetworkScope } | undefined {
  const inherited = proxyUrl(provider, `${label} provider proxy URL`), direct = proxyUrl(account, `${label} account proxy URL`);
  if (inherited !== undefined && direct !== undefined && inherited.value !== direct.value) throw new ImportFailure(`${label} declares conflicting proxy URLs`);
  return direct ?? inherited;
}
function addDirect(records: DirectAccount[], secrets: SecretStore, policy: TransportPolicy, sourceId: string, sourceProvider: string, label: string, baseUrl: string, credential: string, header: string, prefix: string, disabled: boolean, proxy?: { value: string; scope: ProxyNetworkScope }): void {
  const secretRef = `direct:${digest(sourceId)}`; secrets.put(secretRef, credential);
  let proxyFields: Pick<DirectAccount, "proxySecretRef" | "proxyNetworkScope"> = {};
  if (proxy !== undefined) {
    const proxySecretRef = `proxy:${digest(sourceId)}`;
    secrets.put(proxySecretRef, proxy.value);
    proxyFields = { proxySecretRef, proxyNetworkScope: proxy.scope };
  }
  const resultOrigins = policy.resultOriginsByBaseUrl.get(baseUrl);
  if (resultOrigins !== undefined) policy.matchedResultOriginBaseUrls.add(baseUrl);
  const config: JsonObject = { base_url: baseUrl, network_scope: targetNetworkScope(baseUrl, policy) };
  if (resultOrigins !== undefined) config.result_origins = resultOrigins;
  records.push({ sourceId, sourceProvider, name: accountName(label, sourceId), driver: "http-json", config, header, prefix, secretRef, ...proxyFields, disabled });
}
function inventoryConfig(config: JsonObject, secrets: SecretStore, policy: TransportPolicy, allowHttp: boolean): [DirectAccount[], number] {
  const records: DirectAccount[] = []; let disabledCount = 0; const names = new Set<string>();
  for (const raw of list(config["openai-compatibility"], "CPA openai-compatibility")) {
    const provider = mapping(raw, "CPA openai-compatibility entry");
    exact(provider, ["name", "disabled", "prefix", "base-url", "headers", "proxy-url", "api-key-entries", "models", "excluded-models"], "CPA openai-compatibility entry");
    const name = provider.name;
    if (typeof name !== "string" || !name.trim() || name.length > 200) throw new ImportFailure("CPA openai-compatibility provider name is invalid");
    if (names.has(name)) throw new ImportFailure("CPA openai-compatibility provider name is duplicated"); names.add(name);
    const disabled = provider.disabled ?? false; if (typeof disabled !== "boolean") throw new ImportFailure("CPA openai-compatibility disabled flag is invalid");
    rejectUnsupportedTransport(provider, "CPA openai-compatibility entry");
    const baseUrl = reviewedTargetUrl(provider["base-url"], "CPA openai-compatibility base URL", allowHttp, policy);
    list(provider["api-key-entries"], "CPA openai-compatibility api-key-entries").forEach((rawEntry, index) => {
      const entry = mapping(rawEntry, "CPA openai-compatibility API key entry"); exact(entry, ["api-key", "proxy-url"], "CPA openai-compatibility API key entry"); rejectUnsupportedTransport(entry, "CPA openai-compatibility API key entry");
      addDirect(records, secrets, policy, sourceIdentity("config", "openai-compatibility", name, index), name, name, baseUrl, secretString(entry["api-key"], "CPA upstream API key"), "authorization", "Bearer ", disabled, effectiveProxy(provider["proxy-url"], entry["proxy-url"], "CPA openai-compatibility entry")); disabledCount += Number(disabled);
    });
  }
  const sections: Array<[string, string, string | undefined, string, string]> = [
    ["gemini-api-key", "gemini", "https://generativelanguage.googleapis.com", "x-goog-api-key", ""],
    ["codex-api-key", "codex", undefined, "authorization", "Bearer "],
    ["claude-api-key", "claude", "https://api.anthropic.com", "x-api-key", ""],
  ];
  const allowed = ["api-key", "prefix", "base-url", "headers", "proxy-url", "models", "excluded-models", "cloak", "disabled"];
  for (const [section, label, defaultUrl, header, prefix] of sections) list(config[section], `CPA ${section}`).forEach((raw, index) => {
    const entry = mapping(raw, `CPA ${section} entry`); exact(entry, allowed, `CPA ${section} entry`); rejectUnsupportedTransport(entry, `CPA ${section} entry`);
    const disabled = entry.disabled ?? false; if (typeof disabled !== "boolean") throw new ImportFailure(`CPA ${section} disabled flag is invalid`);
    const rawUrl = entry["base-url"] ?? defaultUrl; if (rawUrl === undefined) throw new ImportFailure("CPA codex-api-key entry requires an explicit base-url for lossless import");
    addDirect(records, secrets, policy, sourceIdentity("config", section, index), label, label, reviewedTargetUrl(rawUrl, `CPA ${section} base URL`, allowHttp, policy), secretString(entry["api-key"], "CPA upstream API key"), header, prefix, disabled, proxyUrl(entry["proxy-url"], `CPA ${section} proxy URL`)); disabledCount += Number(disabled);
  });
  return [records, disabledCount];
}
function validateOauth(document: JsonObject): void {
  const containers = [document]; if (document.token !== undefined) containers.push(mapping(document.token, "CPA OAuth token"));
  const access = containers.map((item) => item.access_token).find((item) => item !== undefined);
  const refresh = containers.map((item) => item.refresh_token).find((item) => item !== undefined);
  if (access === undefined && refresh === undefined) throw new ImportFailure("CPA OAuth record contains no recognized token material");
  if (access !== undefined) secretString(access, "CPA OAuth access token"); if (refresh !== undefined) secretString(refresh, "CPA OAuth refresh token");
}
function inventoryAuth(root: string, secrets: SecretStore, policy: TransportPolicy, allowHttp: boolean): [DirectAccount[], NativeReauthorization[], ManagedOAuth[], number] {
  const direct: DirectAccount[] = [], native: NativeReauthorization[] = [], managed: ManagedOAuth[] = []; let disabledCount = 0; const handles = new Set<string>();
  for (const [relativePath, path] of authFiles(root)) {
    const document = parseAuth(readOwnerOnly(path, "CPA auth document", MAX_AUTH_BYTES)); const disabled = document.disabled ?? false;
    if (typeof disabled !== "boolean") throw new ImportFailure("CPA auth disabled flag is invalid");
    if (typeof document.type !== "string" || !document.type.trim()) throw new ImportFailure("CPA auth document has no recognized type");
    const recordType = document.type.trim().toLowerCase(); const upstream = document.upstream;
    if ((upstream === "copilot" || upstream === "cursor") && "handle" in document) {
      if (!["subscription-bridge", "cpa-subscription-bridge", "copilot", "cursor"].includes(recordType)) throw new ImportFailure("CPA opaque Copilot/Cursor auth document has an unsupported type");
      exact(document, ["type", "upstream", "handle", "label", "login", "disabled"], "CPA opaque Copilot/Cursor auth document");
      const handle = secretString(document.handle, "CPA opaque Copilot/Cursor handle"); if (!HANDLE_PATTERN.test(handle)) throw new ImportFailure("CPA opaque Copilot/Cursor handle has an unsupported shape");
      const handleDigest = digest(Buffer.concat([Buffer.from("cpa-opaque-account-handle\0"), Buffer.from(handle)])); if (handles.has(handleDigest)) throw new ImportFailure("CPA opaque Copilot/Cursor handle is duplicated"); handles.add(handleDigest);
      if (document.label !== undefined && (typeof document.label !== "string" || !document.label || document.label.length > 200)) throw new ImportFailure("CPA opaque Copilot/Cursor label is invalid");
      native.push({ sourceId: sourceIdentity("auth", relativePath, recordType, upstream), provider: String(upstream), sourceDisabled: disabled }); disabledCount += Number(disabled); continue;
    }
    if (recordType === "api_key") {
      exact(document, ["type", "name", "provider", "base_url", "api_key", "header", "prefix", "disabled"], "CPA API auth document");
      const header = document.header ?? "authorization", prefix = document.prefix ?? "Bearer ";
      if (typeof header !== "string" || !HEADER_NAME_PATTERN.test(header) || typeof prefix !== "string" || prefix.length > 1024 || /[\0\r\n]/.test(prefix)) throw new ImportFailure("CPA API auth header configuration is invalid");
      const label = document.name ?? document.provider ?? "api"; if (typeof label !== "string" || !label || label.length > 200) throw new ImportFailure("CPA API auth account name is invalid");
      const sourceProvider = typeof document.provider === "string" && document.provider.trim() ? document.provider : label;
      addDirect(direct, secrets, policy, sourceIdentity("auth", relativePath, recordType), sourceProvider, label, reviewedTargetUrl(document.base_url, "CPA API auth base URL", allowHttp, policy), secretString(document.api_key, "CPA upstream API key"), header, prefix, disabled); disabledCount += Number(disabled); continue;
    }
    const sourceType = MANAGED_OAUTH_SOURCE_TYPES[recordType];
    if (sourceType) {
      validateOauth(document); if (Buffer.byteLength(relativePath) > 512 || relativePath.startsWith("/") || relativePath.includes("\\") || relativePath.split("/").some((part) => !part || part === "." || part === "..")) throw new ImportFailure("CPA managed OAuth auth file has an invalid relative path");
      const sourceId = sourceIdentity("auth", relativePath, recordType), stableId = digest(sourceId), payloadRef = `managed-oauth:${stableId}`;
      secrets.put(payloadRef, { source: { kind: "auth_file", relative_path: relativePath }, document }); managed.push({ sourceId, stableId, sourceType, payloadRef }); disabledCount += Number(disabled); continue;
    }
    if (["access_token", "refresh_token", "id_token", "token"].some((field) => field in document)) throw new ImportFailure("CPA auth document has an unsupported managed OAuth type");
    throw new ImportFailure("CPA auth document has an unsupported account type");
  }
  return [direct, native, managed, disabledCount];
}
function buildInventoryFromConfig(config: JsonObject, authDirectory: string, policy: TransportPolicy, allowHttp: boolean): [Inventory, SecretStore] {
  const secrets = new SecretStore(); const [direct, disabledConfig] = inventoryConfig(config, secrets, policy, allowHttp);
  const [authDirect, native, managed, disabledAuth] = inventoryAuth(validateAuthDirectory(authDirectory), secrets, policy, allowHttp); direct.push(...authDirect);
  if (direct.length + native.length + managed.length > MAX_ACCOUNTS) throw new ImportFailure("CPA source contains too many upstream accounts");
  const identities = [...direct.map((item) => item.sourceId), ...native.map((item) => item.sourceId), ...managed.map((item) => item.sourceId)], names = direct.map((item) => item.name);
  if (new Set(identities).size !== identities.length || new Set(names).size !== names.length) throw new ImportFailure("CPA source contains a stable identity conflict");
  if (policy.matchedPrivateTargetBaseUrls.size !== policy.privateTargetBaseUrls.size) throw new ImportFailure("CPA transport policy contains a private target absent from the source");
  if (policy.matchedResultOriginBaseUrls.size !== policy.resultOriginsByBaseUrl.size) throw new ImportFailure("CPA transport policy contains a result-origin target absent from the source");
  if (direct.some((record) => record.config.network_scope === "private" && record.proxySecretRef === undefined)) throw new ImportFailure("CPA private target requires an approved private SOCKS5 proxy");
  if (identities.length === 0) throw new ImportFailure("CPA source contains no active supported upstream accounts");
  return [{ direct, native, managed, disabledSourceCount: disabledConfig + disabledAuth }, secrets];
}
function buildInventory(configPath: string, authDirectory: string, policy: TransportPolicy, allowHttp: boolean): [Inventory, SecretStore] {
  return buildInventoryFromConfig(parseConfig(readOwnerOnly(configPath, "CPA config", MAX_CONFIG_BYTES)), authDirectory, policy, allowHttp);
}

type RouteModelDefinition = { provider: string; model: string; upstreamModel: string; upstreamPrefix: string | null; protocol: "openai" | "anthropic"; candidateSourceIds: string[] };
function routeText(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || Buffer.byteLength(value) > 500 || /[\0\r\n]/.test(value)) throw new ImportFailure(`${label} is invalid`);
  return value;
}
function routePrefix(value: unknown, label: string): string | null { return value === undefined ? null : routeText(value, label); }
function routeModelDefinitions(value: unknown, label: string, provider: string, upstreamPrefix: string | null, protocol: "openai" | "anthropic", candidateSourceIds: readonly string[], excluded: unknown): RouteModelDefinition[] {
  const entries = list(value, `${label} models`);
  const excludedModels = list(excluded, `${label} excluded models`).map((item) => routeText(item, `${label} excluded model`));
  if (new Set(excludedModels).size !== excludedModels.length) throw new ImportFailure(`${label} contains a duplicate excluded model`);
  const result = entries.map((raw) => {
    const model = mapping(raw, `${label} model`); exact(model, ["name", "alias", "prefix"], `${label} model`);
    const modelPrefix = routePrefix(model.prefix, `${label} model prefix`);
    if (modelPrefix !== null && upstreamPrefix !== null && modelPrefix !== upstreamPrefix) throw new ImportFailure(`${label} model prefix conflicts with its provider prefix`);
    const exactPrefix = modelPrefix ?? upstreamPrefix;
    return { provider, model: routeText(model.alias, `${label} model alias`), upstreamModel: routeText(model.name, `${label} model name`), upstreamPrefix: exactPrefix, protocol, candidateSourceIds: excludedModels.includes(routeText(model.alias, `${label} model alias`)) ? [] : [...candidateSourceIds] };
  });
  if (new Set(result.map((item) => JSON.stringify([item.model, item.upstreamPrefix]))).size !== result.length) throw new ImportFailure(`${label} contains a duplicate model alias/prefix pair`);
  if (excludedModels.some((model) => !result.some((item) => item.model === model))) throw new ImportFailure(`${label} excludes a model absent from its declared model list`);
  return result;
}
function configuredRouteModels(config: JsonObject, direct: readonly DirectAccount[]): CpaRouteModel[] {
  const definitions: RouteModelDefinition[] = [];
  for (const raw of list(config["openai-compatibility"], "CPA openai-compatibility")) {
    const provider = mapping(raw, "CPA openai-compatibility entry"), name = routeText(provider.name, "CPA openai-compatibility provider name");
    const accountIds = list(provider["api-key-entries"], "CPA openai-compatibility api-key-entries").map((_entry, index) => sourceIdentity("config", "openai-compatibility", name, index));
    definitions.push(...routeModelDefinitions(provider.models, "CPA openai-compatibility entry", name, routePrefix(provider.prefix, "CPA openai-compatibility prefix"), "openai", accountIds, provider["excluded-models"]));
  }
  const sections: Array<[string, string, "openai" | "anthropic"]> = [["gemini-api-key", "gemini", "openai"], ["codex-api-key", "codex", "openai"], ["claude-api-key", "claude", "anthropic"]];
  for (const [section, provider, protocol] of sections) {
    list(config[section], `CPA ${section}`).forEach((raw, index) => {
      const entry = mapping(raw, `CPA ${section} entry`);
      definitions.push(...routeModelDefinitions(entry.models, `CPA ${section} entry`, provider, routePrefix(entry.prefix, `CPA ${section} prefix`), protocol, [sourceIdentity("config", section, index)], entry["excluded-models"]));
    });
  }
  const accounts = new Map(direct.map((item) => [item.sourceId, item]));
  const merged = new Map<string, RouteModelDefinition>();
  for (const definition of definitions) {
    const key = JSON.stringify([definition.provider, definition.model, definition.upstreamModel, definition.upstreamPrefix, definition.protocol]);
    const current = merged.get(key);
    if (current) current.candidateSourceIds.push(...definition.candidateSourceIds); else merged.set(key, { ...definition, candidateSourceIds: [...definition.candidateSourceIds] });
  }
  const result: CpaRouteModel[] = [];
  for (const definition of merged.values()) {
    const candidates = definition.candidateSourceIds.map((sourceId) => accounts.get(sourceId));
    if (candidates.some((candidate) => candidate === undefined || candidate.sourceProvider !== definition.provider)) throw new ImportFailure("CPA route model does not resolve to its exact source provider account");
    const active = candidates.filter((candidate): candidate is DirectAccount => candidate !== undefined && !candidate.disabled);
    if (new Set(active.map((candidate) => candidate.sourceId)).size !== active.length) throw new ImportFailure("CPA route model contains a duplicate source account");
    if (new Set(active.map((candidate) => JSON.stringify([candidate.driver, candidate.config]))).size > 1) throw new ImportFailure("CPA route model merges incompatible source account drivers or configurations");
    result.push({ provider: definition.provider, model: definition.model, upstreamModel: definition.upstreamModel, upstreamPrefix: definition.upstreamPrefix, protocol: definition.protocol, candidateSourceIds: active.map((candidate) => candidate.sourceId).sort((left, right) => left.localeCompare(right, "en")) });
  }
  if (new Set(result.map((item) => JSON.stringify([item.provider, item.model, item.upstreamPrefix, item.protocol]))).size !== result.length) throw new ImportFailure("CPA route model source pattern is ambiguous");
  return result.sort((left, right) => JSON.stringify([left.provider, left.model, left.upstreamPrefix, left.protocol]).localeCompare(JSON.stringify([right.provider, right.model, right.upstreamPrefix, right.protocol]), "en"));
}

/**
 * Parse the same sealed CPA snapshot used by the upstream importer and expose
 * only non-secret route coordinates. Route policy joins happen elsewhere.
 */
export function inspectCpaSourceRoutes(configPath: string, authDirectory: string): CpaSourceRouteInspection {
  const config = parseConfig(readOwnerOnly(configPath, "CPA config", MAX_CONFIG_BYTES));
  const emptyPolicy: TransportPolicy = { privateTargetBaseUrls: new Set<string>(), matchedPrivateTargetBaseUrls: new Set<string>(), resultOriginsByBaseUrl: new Map<string, string[]>(), matchedResultOriginBaseUrls: new Set<string>() };
  const [inventory] = buildInventoryFromConfig(config, authDirectory, emptyPolicy, false);
  return {
    accounts: inventory.direct.map((item) => ({ sourceId: item.sourceId, sourceProvider: item.sourceProvider, driver: item.driver, disabled: item.disabled })).sort((left, right) => left.sourceId.localeCompare(right.sourceId, "en")),
    models: configuredRouteModels(config, inventory.direct),
    opaqueReauthorizations: inventory.native.map((item) => ({ sourceId: item.sourceId, provider: item.provider })).sort((left, right) => `${left.provider}\0${left.sourceId}`.localeCompare(`${right.provider}\0${right.sourceId}`, "en")),
  };
}

type HttpResponse = { status: number; value: unknown };
const caCache = new Map<string, Buffer>();
function caBytes(path: string): Buffer {
  const cached = caCache.get(path); if (cached) return cached;
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    if (!fstatSync(descriptor).isFile()) throw new Error("not regular");
    const value = readBoundedDescriptor(descriptor, 4 * 1024 * 1024, "CA file"); caCache.set(path, value); return value;
  } catch (error) {
    if (error instanceof ImportFailure) throw error;
    throw new ImportFailure("CA file is invalid or unreadable");
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}
async function requestJson(method: string, rawUrl: string, token: string, label: string, statuses: number[], body?: JsonObject, idempotencyKey?: string, caFile?: string): Promise<HttpResponse> {
  const url = new URL(rawUrl); const encoded = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
  return await new Promise<HttpResponse>((fulfill, reject) => {
    const request = (url.protocol === "https:" ? httpsRequest : httpRequest)({ protocol: url.protocol, hostname: url.hostname, port: url.port, path: `${url.pathname}${url.search}`, method, timeout: 30_000, maxHeaderSize: 64 * 1024, ca: caFile ? caBytes(caFile) : undefined, headers: { Accept: "application/json", Authorization: `Bearer ${token}`, ...(encoded ? { "Content-Type": "application/json", "Content-Length": encoded.length } : {}), ...(idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {}) } }, (response) => {
      let size = 0; const chunks: Buffer[] = []; response.on("data", (chunk: Buffer) => { size += chunk.length; if (size > MAX_RESPONSE_BYTES) request.destroy(new ImportFailure(`${label} response exceeds the allowed size`)); else chunks.push(chunk); });
      response.on("end", () => { if (!statuses.includes(response.statusCode ?? 0)) { reject(new ImportFailure(`${label} returned an unexpected status`)); return; } try { fulfill({ status: response.statusCode!, value: parseStrictJson(decodeUtf8(Buffer.concat(chunks), `${label} response`)) }); } catch { reject(new ImportFailure(`${label} returned invalid JSON`)); } });
    });
    request.on("timeout", () => request.destroy()); request.on("error", (error) => reject(error instanceof ImportFailure ? error : new ImportFailure(`${label} failed`))); if (encoded) request.end(encoded); else request.end();
  });
}
function validateAccount(value: unknown, tenant: string, label: string): JsonObject {
  const account = mapping(value, `${label} account response`); for (const key of ["id", "tenant_external_id", "name", "driver", "config", "status", "updated_at"]) if (!(key in account)) throw new ImportFailure(`${label} returned an incomplete account`);
  if (account.tenant_external_id !== tenant) throw new ImportFailure(`${label} returned an account outside the selected tenant`); if (["credential", "access_token", "refresh_token", "api_key"].some((key) => key in account)) throw new ImportFailure(`${label} returned credential material`); return account;
}

function text(value: unknown, label: string, pattern?: RegExp): string {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || Buffer.byteLength(value) > 500 || /[\0\r\n]/.test(value) || (pattern && !pattern.test(value))) throw new ImportFailure(`${label} is invalid`);
  return value;
}
function integer(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > 1_000_000_000_000_000) throw new ImportFailure(`${label} is invalid`);
  return value;
}
function canonicalJson(value: unknown, label: string, depth = 0): string {
  if (depth > 32) throw new ImportFailure(`${label} is invalid`);
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") { if (!Number.isFinite(value)) throw new ImportFailure(`${label} is invalid`); return JSON.stringify(value); }
  if (Array.isArray(value)) {
    if (value.length > MAX_ACCOUNTS) throw new ImportFailure(`${label} is invalid`);
    return `[${value.map((item) => canonicalJson(item, label, depth + 1)).join(",")}]`;
  }
  const object = mapping(value, label), keys = Object.keys(object).sort((left, right) => left.localeCompare(right, "en"));
  if (keys.length > MAX_ACCOUNTS) throw new ImportFailure(`${label} is invalid`);
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key], label, depth + 1)}`).join(",")}}`;
}
function providerCandidates(raw: Buffer): { sourceInventoryDigest: string; candidates: ProviderCandidate[] } {
  let parsed: unknown;
  try { parsed = parseStrictJson(decodeUtf8(raw, "provider candidate material")); }
  catch { throw new ImportFailure("provider candidate material is invalid"); }
  const root = mapping(parsed, "provider candidate material");
  exact(root, ["version", "source_inventory_sha256", "provider_candidate_sets"], "provider candidate material");
  if (root.version !== 1 || !Array.isArray(root.provider_candidate_sets) || root.provider_candidate_sets.length > MAX_ACCOUNTS) throw new ImportFailure("provider candidate material is invalid");
  const sourceInventoryDigest = text(root.source_inventory_sha256, "provider candidate material source inventory digest", SHA256);
  const candidates = new Map<string, ProviderCandidate>();
  for (const rawSet of root.provider_candidate_sets) {
    const set = mapping(rawSet, "provider candidate set");
    exact(set, ["source", "upstream_model", "protocol", "selection", "candidates"], "provider candidate set");
    const source = mapping(set.source, "provider candidate source");
    exact(source, ["provider", "model", "group", "upstream_prefix", "protocol"], "provider candidate source");
    const provider = text(source.provider, "provider candidate source provider");
    text(source.model, "provider candidate source model");
    if ((source.group !== null && typeof source.group !== "string") || (source.upstream_prefix !== null && typeof source.upstream_prefix !== "string") || (source.protocol !== "openai" && source.protocol !== "anthropic") || set.protocol !== source.protocol || set.selection !== "equal_round_robin" || !Array.isArray(set.candidates) || set.candidates.length === 0 || set.candidates.length > MAX_ACCOUNTS) throw new ImportFailure("provider candidate set is invalid");
    if (source.group !== null) text(source.group, "provider candidate source group");
    if (source.upstream_prefix !== null) text(source.upstream_prefix, "provider candidate source prefix");
    const poolDrivers = new Set<"http-json" | "openai-codex">();
    for (const rawCandidate of set.candidates) {
      const candidate = mapping(rawCandidate, "provider source candidate");
      exact(candidate, ["source_stable_id", "source_provider", "driver"], "provider source candidate");
      const sourceStableId = text(candidate.source_stable_id, "provider source candidate stable ID", SHA256), sourceProvider = text(candidate.source_provider, "provider source candidate provider"), candidateDriver = candidate.driver;
      if (sourceProvider !== provider || (candidateDriver !== "http-json" && candidateDriver !== "openai-codex")) throw new ImportFailure("provider source candidate is invalid");
      poolDrivers.add(candidateDriver);
      if (candidateDriver === "openai-codex") continue;
      const prior = candidates.get(sourceStableId), current: ProviderCandidate = { sourceStableId, sourceProvider, driver: "http-json" };
      if (prior && (prior.sourceProvider !== current.sourceProvider || prior.driver !== current.driver)) throw new ImportFailure("provider candidate material has a conflicting source binding");
      candidates.set(sourceStableId, current);
    }
    if (poolDrivers.size !== 1) throw new ImportFailure("provider candidate set mixes unsupported resolver drivers");
  }
  return { sourceInventoryDigest, candidates: [...candidates.values()].sort((left, right) => left.sourceStableId.localeCompare(right.sourceStableId, "en")) };
}
type TargetAccount = Readonly<{ id: string; name: string; driver: string; config: string; status: string; updatedAt: number }>;
function targetAccount(value: unknown, tenant: string): TargetAccount {
  const account = validateAccount(value, tenant, "target upstream inventory");
  return {
    id: text(account.id, "target upstream identifier", UUID),
    name: text(account.name, "target upstream name"),
    driver: text(account.driver, "target upstream driver"),
    config: canonicalJson(account.config, "target upstream configuration"),
    status: text(account.status, "target upstream status"),
    updatedAt: integer(account.updated_at, "target upstream revision"),
  };
}
function buildBindingReceipt(candidateRaw: Buffer, inventory: Inventory, identityKey: Buffer, tenant: string, targetAccounts: readonly TargetAccount[]): BindingReceipt {
  const material = providerCandidates(candidateRaw), sourceAccounts = new Map<string, DirectAccount>();
  for (const account of inventory.direct) {
    if (account.disabled) continue;
    const stableId = cpaRouteSourceStableId(identityKey, account.sourceId);
    if (sourceAccounts.has(stableId)) throw new ImportFailure("source route identity is duplicated");
    sourceAccounts.set(stableId, account);
  }
  if (new Set(targetAccounts.map((account) => account.id)).size !== targetAccounts.length) throw new ImportFailure("target upstream inventory contains duplicate account IDs");
  const targetsByName = new Map<string, TargetAccount[]>();
  for (const account of targetAccounts) {
    const current = targetsByName.get(account.name); if (current) current.push(account); else targetsByName.set(account.name, [account]);
  }
  const bindings: Array<BindingReceipt["bindings"][number]> = [], quarantined: Array<BindingReceipt["quarantined"][number]> = [];
  for (const candidate of material.candidates) {
    const source = sourceAccounts.get(candidate.sourceStableId);
    if (!source) { quarantined.push({ sourceStableId: candidate.sourceStableId, sourceProvider: candidate.sourceProvider, reason: "source_candidate_unavailable" }); continue; }
    if (source.sourceProvider !== candidate.sourceProvider || source.driver !== candidate.driver) { quarantined.push({ sourceStableId: candidate.sourceStableId, sourceProvider: candidate.sourceProvider, reason: "source_candidate_metadata_mismatch" }); continue; }
    const named = targetsByName.get(source.name) ?? [];
    if (named.length === 0) { quarantined.push({ sourceStableId: candidate.sourceStableId, sourceProvider: candidate.sourceProvider, reason: "target_absent" }); continue; }
    const sameDriver = named.filter((account) => account.driver === source.driver);
    if (sameDriver.length === 0) { quarantined.push({ sourceStableId: candidate.sourceStableId, sourceProvider: candidate.sourceProvider, reason: "target_driver_mismatch" }); continue; }
    const sameConfig = sameDriver.filter((account) => account.config === canonicalJson(source.config, "source upstream configuration"));
    if (sameConfig.length === 0) { quarantined.push({ sourceStableId: candidate.sourceStableId, sourceProvider: candidate.sourceProvider, reason: "target_config_mismatch" }); continue; }
    const active = sameConfig.filter((account) => account.status === "active");
    if (active.length === 0) { quarantined.push({ sourceStableId: candidate.sourceStableId, sourceProvider: candidate.sourceProvider, reason: "target_inactive" }); continue; }
    if (active.length !== 1) { quarantined.push({ sourceStableId: candidate.sourceStableId, sourceProvider: candidate.sourceProvider, reason: "target_ambiguous" }); continue; }
    const target = active[0]!;
    bindings.push({ sourceStableId: candidate.sourceStableId, sourceProvider: candidate.sourceProvider, accountId: target.id, driver: "http-json", updatedAt: target.updatedAt });
  }
  return { sourceInventoryDigest: material.sourceInventoryDigest, providerCandidateMaterialDigest: digest(candidateRaw), tenant, bindings, quarantined };
}
function encodeBindingReceipt(receipt: BindingReceipt): Buffer {
  return Buffer.from(`${JSON.stringify({
    version: 1,
    tenant_external_id: receipt.tenant,
    source_inventory_sha256: receipt.sourceInventoryDigest,
    provider_candidate_material_sha256: receipt.providerCandidateMaterialDigest,
    bindings: receipt.bindings.map((binding) => ({ source_stable_id: binding.sourceStableId, source_provider: binding.sourceProvider, upstream_account_id: binding.accountId, driver: binding.driver, status: "active", updated_at: binding.updatedAt })),
    quarantined: receipt.quarantined.map((item) => ({ source_stable_id: item.sourceStableId, source_provider: item.sourceProvider, reason: item.reason })),
  })}\n`);
}
type OutputTarget = Readonly<{ target: string; parentDescriptor: number }>;
function openSafeOutput(path: string): OutputTarget {
  if (!isAbsolute(path) || path !== resolve(path) || path === parse(path).root || path.includes("\0")) throw new ImportFailure("binding receipt output path is invalid");
  const directory = resolve(dirname(path)), root = parse(directory).root;
  let current = root;
  for (const part of relative(root, directory).split(sep).filter(Boolean)) {
    current = resolve(current, part);
    let metadata: ReturnType<typeof lstatSync>;
    try { metadata = lstatSync(current); } catch { throw new ImportFailure("binding receipt output directory is unsafe"); }
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new ImportFailure("binding receipt output directory is unsafe");
  }
  let descriptor: number | undefined;
  try {
    descriptor = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || (process.geteuid?.() !== undefined && metadata.uid !== process.geteuid()) || (metadata.mode & 0o022) !== 0) throw new ImportFailure("binding receipt output directory is unsafe");
    const target = `/proc/self/fd/${descriptor}/${basename(path)}`;
    try { lstatSync(target); throw new ImportFailure("binding receipt output already exists"); }
    catch (error) { if (error instanceof ImportFailure) throw error; if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) throw new ImportFailure("binding receipt output directory is unsafe"); }
    return { target, parentDescriptor: descriptor };
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    if (error instanceof ImportFailure) throw error;
    throw new ImportFailure("binding receipt output directory is unsafe");
  }
}
function writeBindingReceipt(output: OutputTarget, receipt: Buffer): void {
  const temporary = `${output.target}.tmp-${randomBytes(16).toString("hex")}`;
  let descriptor: number | undefined;
  try {
    descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    for (let offset = 0; offset < receipt.length;) { const written = writeSync(descriptor, receipt, offset, receipt.length - offset); if (written <= 0) throw new ImportFailure("binding receipt could not be written"); offset += written; }
    fsyncSync(descriptor); closeSync(descriptor); descriptor = undefined;
    linkSync(temporary, output.target); unlinkSync(temporary);
    const metadata = lstatSync(output.target); if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o600) throw new ImportFailure("binding receipt could not be persisted");
    fsyncSync(output.parentDescriptor);
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    try { lstatSync(temporary); unlinkSync(temporary); } catch {}
    if (error instanceof ImportFailure) throw error;
    throw new ImportFailure("binding receipt could not be persisted");
  }
}
async function resolveExistingRouteBindings(baseUrl: string, token: string, tenant: string, inventory: Inventory, identityKey: Buffer, candidateMaterial: Buffer, caFile?: string): Promise<Buffer> {
  const response = (await requestJson("GET", `${baseUrl}/internal/v1/upstreams?tenant_external_id=${encodeURIComponent(tenant)}&limit=100`, token, "target upstream inventory", [200], undefined, undefined, caFile)).value;
  if (!Array.isArray(response) || response.length >= 100) throw new ImportFailure("target upstream inventory is incomplete");
  const receipt = buildBindingReceipt(candidateMaterial, inventory, identityKey, tenant, response.map((item) => targetAccount(item, tenant)));
  return encodeBindingReceipt(receipt);
}
async function apply(baseUrl: string, token: string, tenant: string, inventory: Inventory, secrets: SecretStore, caFile?: string): Promise<[number, number, number, number]> {
  if (inventory.managed.length > 0) {
    const capabilities = mapping((await requestJson("GET", `${baseUrl}/internal/v1/imports/cpa/managed-oauth/capabilities`, token, "CPA managed OAuth capability discovery", [200], undefined, undefined, caFile)).value, "CPA managed OAuth capability response");
    if (Object.keys(capabilities).sort().join("\0") !== "contract_version\0source_types") throw new ImportFailure("CPA managed OAuth capability response has an unsupported shape");
    const sourceTypes = capabilities.source_types;
    if (capabilities.contract_version !== 1) throw new ImportFailure("target does not support the required CPA managed OAuth contract");
    if (!Array.isArray(sourceTypes) || sourceTypes.length === 0 || !sourceTypes.every((item) => typeof item === "string" && /^[a-z0-9._-]{1,64}$/.test(item)) || new Set(sourceTypes).size !== sourceTypes.length) throw new ImportFailure("CPA managed OAuth capability response has invalid source types");
    if (inventory.managed.some((item) => !sourceTypes.includes(item.sourceType))) throw new ImportFailure("target is missing a managed OAuth source type required by the CPA source");
  }
  const providers = (await requestJson("GET", `${baseUrl}/internal/v1/provider-types`, token, "target provider discovery", [200], undefined, undefined, caFile)).value;
  if (!Array.isArray(providers)) throw new ImportFailure("target provider discovery returned an invalid document");
  if (inventory.direct.length > 0 && !providers.some((item) => mapping(item, "target provider discovery").id === "http-json")) throw new ImportFailure("target is missing a provider driver required by the CPA source");
  const existingValue = (await requestJson("GET", `${baseUrl}/internal/v1/upstreams?tenant_external_id=${encodeURIComponent(tenant)}`, token, "target upstream inventory", [200], undefined, undefined, caFile)).value;
  if (!Array.isArray(existingValue)) throw new ImportFailure("target upstream inventory returned an invalid document");
  const existing = new Map<string, JsonObject>();
  for (const value of existingValue) {
    const account = validateAccount(value, tenant, "target upstream inventory");
    if (typeof account.name !== "string" || existing.has(account.name)) throw new ImportFailure("target upstream inventory contains a name conflict");
    existing.set(account.name, account);
  }
  for (const record of inventory.direct) {
    const account = existing.get(record.name);
    if (account && (account.driver !== record.driver || JSON.stringify(account.config) !== JSON.stringify(record.config))) throw new ImportFailure("target account conflicts with a stable CPA source identity");
  }
  let createdManaged = 0, replayedManaged = 0;
  for (const record of inventory.managed) {
    const payload = secrets.take(record.payloadRef);
    if (Object.keys(payload).sort().join("\0") !== "document\0source") throw new ImportFailure("internal managed OAuth payload is invalid");
    Object.assign(payload, { contract_version: 1, tenant_external_id: tenant, source_type: record.sourceType });
    const result = await requestJson("POST", `${baseUrl}/internal/v1/imports/cpa/managed-oauth`, token, "CPA managed OAuth import", [200, 201], payload, undefined, caFile);
    const response = mapping(result.value, "CPA managed OAuth import response");
    if (Object.keys(response).sort().join("\0") !== "account\0disposition") throw new ImportFailure("CPA managed OAuth import returned an unsupported response");
    const expectedDisposition = result.status === 201 ? "created" : "replayed";
    if (response.disposition !== expectedDisposition) throw new ImportFailure("CPA managed OAuth import returned an inconsistent disposition");
    validateAccount(response.account, tenant, "CPA managed OAuth import");
    if (result.status === 201) createdManaged += 1; else replayedManaged += 1;
  }
  let created = 0, replayed = 0;
  for (const record of inventory.direct) {
    const credential = record.proxySecretRef === undefined
      ? { type: "api_key", value: secrets.string(record.secretRef), header: record.header, prefix: record.prefix }
      : { type: "api_key_proxy", value: secrets.string(record.secretRef), header: record.header, prefix: record.prefix, proxy_url: secrets.string(record.proxySecretRef), proxy_network_scope: record.proxyNetworkScope };
    let account = existing.get(record.name);
    if (!account) {
      account = validateAccount((await requestJson("POST", `${baseUrl}/internal/v1/upstreams`, token, "target upstream creation", [201], { tenant_external_id: tenant, name: record.name, driver: record.driver, config: record.config, credential }, undefined, caFile)).value, tenant, "target upstream creation");
      if (account.name !== record.name || account.driver !== record.driver || JSON.stringify(account.config) !== JSON.stringify(record.config)) throw new ImportFailure("target upstream creation returned another account");
      created += 1;
    } else {
      if (account.driver !== record.driver || JSON.stringify(account.config) !== JSON.stringify(record.config)) throw new ImportFailure("target account conflicts with a stable CPA source identity");
      replayed += 1;
    }
    const id = account.id; if (typeof id !== "string") throw new ImportFailure("target account identifier is invalid"); account = validateAccount((await requestJson("PUT", `${baseUrl}/internal/v1/upstreams/${encodeURIComponent(id)}/credential`, token, "target upstream credential convergence", [200], { credential }, `cpa-import-v1-${digest(record.sourceId).slice(0, 48)}`, caFile)).value, tenant, "target upstream credential convergence");
    const status = record.disabled ? "disabled" : "active";
    if (account.status !== status) account = validateAccount((await requestJson("PATCH", `${baseUrl}/internal/v1/upstreams/${encodeURIComponent(id)}`, token, "target upstream status convergence", [200], { tenant_external_id: tenant, status, expected_updated_at: account.updated_at }, undefined, caFile)).value, tenant, "target upstream status convergence");
    if (account.status !== status) throw new ImportFailure("target upstream status did not converge");
  }
  return [created, replayed, createdManaged, replayedManaged];
}
export function readSourceIdentityKey(path: string): Buffer {
  if (!isAbsolute(path)) throw new ImportFailure("source identity key file path must be absolute"); const value = readOwnerOnly(path, "source identity key file", MAX_SECRET_BYTES);
  if (value.length !== SOURCE_KEY_PREFIX.length + SOURCE_KEY_BYTES || !timingSafeEqual(value.subarray(0, SOURCE_KEY_PREFIX.length), SOURCE_KEY_PREFIX)) throw new ImportFailure("source identity key has an invalid binary format"); const payload = Buffer.from(value.subarray(SOURCE_KEY_PREFIX.length)); value.fill(0); if (payload.every((byte) => byte === payload[0])) throw new ImportFailure("source identity key payload is invalid"); return payload;
}
function summary(mode: string, inventory: Inventory, native: JsonObject[], counts = [0, 0, 0, 0]): JsonObject {
  const sourceCounts: Record<string, number> = {}; for (const record of inventory.managed) sourceCounts[record.sourceType] = (sourceCounts[record.sourceType] ?? 0) + 1;
  return { api_account_count: inventory.direct.length, created_count: counts[0], created_managed_oauth_count: counts[2], disabled_source_count: inventory.disabledSourceCount, managed_oauth_account_count: inventory.managed.length, managed_oauth_source_type_counts: Object.fromEntries(Object.entries(sourceCounts).sort()), mode, native_reauthorization_required: native, native_reauthorization_required_count: native.length, private_target_api_account_count: inventory.direct.filter((record) => record.config.network_scope === "private").length, proxied_api_account_count: inventory.direct.filter((record) => record.proxySecretRef !== undefined).length, replayed_count: counts[1], replayed_managed_oauth_count: counts[3] };
}
type Options = { config?: string; authDir?: string; tenant: string; apply: boolean; resolveBindings: boolean; target?: string; token?: string; sourceKey?: string; candidateMaterial?: string; bindingReceipt?: string; transportPolicy?: string; ca?: string; allowHttp: boolean };
function args(argv: string[]): Options {
  if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write("usage: import-cpa-upstreams --config FILE --auth-dir DIR [--transport-policy-file FILE] [--tenant ID] [--apply] [--target-api-base-url URL] [--service-token-file FILE] [--source-identity-key-file FILE] [--ca-file FILE] [--allow-http-loopback]\n       import-cpa-upstreams --resolve-existing-route-bindings --config FILE --auth-dir DIR --source-identity-key-file FILE --provider-candidate-material-file FILE --binding-receipt-output FILE --target-api-base-url URL --service-token-file FILE [--transport-policy-file FILE] [--tenant ID] [--ca-file FILE] [--allow-http-loopback]\n\nImport real CPA config.yaml/auth-dir upstreams (dry-run by default), or read only deterministic direct-account bindings for provider-exact route review.\n"); process.exit(0); }
  const result: Options = { tenant: "default", apply: false, resolveBindings: false, allowHttp: false }; const valued: Record<string, keyof Options> = { "--config": "config", "--auth-dir": "authDir", "--transport-policy-file": "transportPolicy", "--tenant": "tenant", "--target-api-base-url": "target", "--service-token-file": "token", "--source-identity-key-file": "sourceKey", "--provider-candidate-material-file": "candidateMaterial", "--binding-receipt-output": "bindingReceipt", "--ca-file": "ca" };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]!;
    if (arg === "--apply") { if (result.apply) throw new ImportFailure("arguments are invalid"); result.apply = true; }
    else if (arg === "--resolve-existing-route-bindings") { if (result.resolveBindings) throw new ImportFailure("arguments are invalid"); result.resolveBindings = true; }
    else if (arg === "--allow-http-loopback") { if (result.allowHttp) throw new ImportFailure("arguments are invalid"); result.allowHttp = true; }
    else if (valued[arg]) { const value = argv[++index]; if (!value || result[valued[arg]!] !== undefined) throw new ImportFailure(`${arg} requires one value`); (result as unknown as Record<string, unknown>)[valued[arg]!] = value; }
    else throw new ImportFailure(`unrecognized argument: ${arg}`);
  }
  if (!result.config || !result.authDir) throw new ImportFailure("--config and --auth-dir are required"); return result;
}
async function main(): Promise<void> {
  const options = args(process.argv.slice(2));
  if (!TENANT_PATTERN.test(options.tenant)) throw new ImportFailure("target tenant external ID is invalid");
  if (options.transportPolicy && !isAbsolute(options.transportPolicy)) throw new ImportFailure("transport policy file path must be absolute");
  const policy = options.transportPolicy
    ? parseTransportPolicy(readOwnerOnly(options.transportPolicy, "CPA transport policy file", MAX_CONFIG_BYTES), options.allowHttp)
    : {
      privateTargetBaseUrls: new Set<string>(),
      matchedPrivateTargetBaseUrls: new Set<string>(),
      resultOriginsByBaseUrl: new Map<string, string[]>(),
      matchedResultOriginBaseUrls: new Set<string>(),
  };
  const [inventory, secrets] = buildInventory(options.config!, options.authDir!, policy, options.allowHttp);
  if (options.resolveBindings) {
    if (options.apply || !options.target || !options.token || !options.sourceKey || !options.candidateMaterial || !options.bindingReceipt) throw new ImportFailure("binding resolution requires its explicit read-only inputs");
    const identityKey = readSourceIdentityKey(options.sourceKey), candidateMaterial = readOwnerOnly(options.candidateMaterial, "provider candidate material", MAX_CONFIG_BYTES);
    let output: OutputTarget | undefined;
    try {
      const target = upstreamUrl(options.target, "target API base URL", options.allowHttp);
      const token = secretString(decodeUtf8(readOwnerOnly(options.token, "target service token file", MAX_SECRET_BYTES), "target service token file").replace(/\n$/, ""), "target service token file");
      const receipt = await resolveExistingRouteBindings(target, token, options.tenant, inventory, identityKey, candidateMaterial, options.ca);
      output = openSafeOutput(options.bindingReceipt); writeBindingReceipt(output, receipt);
      const parsed = JSON.parse(receipt.toString("utf8")) as { bindings: unknown[]; quarantined: unknown[] };
      process.stdout.write(`${JSON.stringify({ mode: "resolve-existing-route-bindings", provider_candidate_material_sha256: digest(candidateMaterial), binding_receipt_sha256: digest(receipt), bound_count: parsed.bindings.length, quarantined_count: parsed.quarantined.length })}\n`);
      return;
    } finally {
      candidateMaterial.fill(0); identityKey.fill(0);
      if (output) closeSync(output.parentDescriptor);
    }
  }
  let native: JsonObject[] = []; if (inventory.native.length > 0) { if (!options.sourceKey) throw new ImportFailure("source identity key file is required for opaque reauthorization records"); const key = readSourceIdentityKey(options.sourceKey); native = inventory.native.map((record) => ({ provider: record.provider, source_disabled: record.sourceDisabled, source_stable_id: createHmac("sha256", key).update(Buffer.concat([Buffer.from("memeloop-token-center\0cpa-native-reauthorization-source-id\0v1\0"), Buffer.from(record.sourceId)])).digest("hex") })); key.fill(0); }
  if (!options.apply || (inventory.direct.length === 0 && inventory.managed.length === 0)) { process.stdout.write(`${JSON.stringify(summary(options.apply ? "apply" : "dry-run", inventory, native))}\n`); return; }
  if (!options.target || !options.token) throw new ImportFailure("apply requires target API base URL and service token file"); const base = upstreamUrl(options.target, "target API base URL", options.allowHttp); const token = secretString(decodeUtf8(readOwnerOnly(options.token, "target service token file", MAX_SECRET_BYTES), "target service token file").replace(/\n$/, ""), "target service token file"); const counts = await apply(base, token, options.tenant, inventory, secrets, options.ca); process.stdout.write(`${JSON.stringify(summary("apply", inventory, native, counts))}\n`);
}
if (basename(process.argv[1] ?? "").replace(/\.(?:ts|[cm]?js)$/, "") === "import-cpa-upstreams") {
  main().catch((error) => { process.stderr.write(`CPA upstream import stopped: ${error instanceof ImportFailure ? error.message : "unexpected operator failure"}\n`); process.exitCode = 2; });
}
