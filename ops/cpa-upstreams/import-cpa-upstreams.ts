#!/usr/bin/env node
/** Inventory and import CPA upstream accounts through the control API. */

import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { readdirSync, lstatSync, openSync, closeSync, fstatSync, readSync, constants } from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { basename, isAbsolute, relative, resolve, sep } from "node:path";
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

class ImportFailure extends Error {}
type JsonObject = Record<string, unknown>;
type ProxyNetworkScope = "private";
type TargetNetworkScope = "public" | "private";
type DirectAccount = { sourceId: string; name: string; driver: "http-json"; config: JsonObject; header: string; prefix: string; secretRef: string; proxySecretRef?: string; proxyNetworkScope?: ProxyNetworkScope; disabled: boolean };
type NativeReauthorization = { sourceId: string; provider: string; sourceDisabled: boolean };
type ManagedOAuth = { stableId: string; sourceType: string; payloadRef: string };
type Inventory = { direct: DirectAccount[]; native: NativeReauthorization[]; managed: ManagedOAuth[]; disabledSourceCount: number };
type TransportPolicy = {
  privateTargetBaseUrls: Set<string>;
  matchedPrivateTargetBaseUrls: Set<string>;
  resultOriginsByBaseUrl: Map<string, string[]>;
  matchedResultOriginBaseUrls: Set<string>;
};

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
function addDirect(records: DirectAccount[], secrets: SecretStore, policy: TransportPolicy, sourceId: string, label: string, baseUrl: string, credential: string, header: string, prefix: string, disabled: boolean, proxy?: { value: string; scope: ProxyNetworkScope }): void {
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
  records.push({ sourceId, name: accountName(label, sourceId), driver: "http-json", config, header, prefix, secretRef, ...proxyFields, disabled });
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
      addDirect(records, secrets, policy, sourceIdentity("config", "openai-compatibility", name, index), name, baseUrl, secretString(entry["api-key"], "CPA upstream API key"), "authorization", "Bearer ", disabled, effectiveProxy(provider["proxy-url"], entry["proxy-url"], "CPA openai-compatibility entry")); disabledCount += Number(disabled);
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
    addDirect(records, secrets, policy, sourceIdentity("config", section, index), label, reviewedTargetUrl(rawUrl, `CPA ${section} base URL`, allowHttp, policy), secretString(entry["api-key"], "CPA upstream API key"), header, prefix, disabled, proxyUrl(entry["proxy-url"], `CPA ${section} proxy URL`)); disabledCount += Number(disabled);
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
      addDirect(direct, secrets, policy, sourceIdentity("auth", relativePath, recordType), label, reviewedTargetUrl(document.base_url, "CPA API auth base URL", allowHttp, policy), secretString(document.api_key, "CPA upstream API key"), header, prefix, disabled); disabledCount += Number(disabled); continue;
    }
    const sourceType = MANAGED_OAUTH_SOURCE_TYPES[recordType];
    if (sourceType) {
      validateOauth(document); if (Buffer.byteLength(relativePath) > 512 || relativePath.startsWith("/") || relativePath.includes("\\") || relativePath.split("/").some((part) => !part || part === "." || part === "..")) throw new ImportFailure("CPA managed OAuth auth file has an invalid relative path");
      const stableId = digest(sourceIdentity("auth", relativePath, recordType)), payloadRef = `managed-oauth:${stableId}`;
      secrets.put(payloadRef, { source: { kind: "auth_file", relative_path: relativePath }, document }); managed.push({ stableId, sourceType, payloadRef }); disabledCount += Number(disabled); continue;
    }
    if (["access_token", "refresh_token", "id_token", "token"].some((field) => field in document)) throw new ImportFailure("CPA auth document has an unsupported managed OAuth type");
    throw new ImportFailure("CPA auth document has an unsupported account type");
  }
  return [direct, native, managed, disabledCount];
}
function buildInventory(configPath: string, authDirectory: string, policy: TransportPolicy, allowHttp: boolean): [Inventory, SecretStore] {
  const secrets = new SecretStore(); const [direct, disabledConfig] = inventoryConfig(parseConfig(readOwnerOnly(configPath, "CPA config", MAX_CONFIG_BYTES)), secrets, policy, allowHttp);
  const [authDirect, native, managed, disabledAuth] = inventoryAuth(validateAuthDirectory(authDirectory), secrets, policy, allowHttp); direct.push(...authDirect);
  if (direct.length + native.length + managed.length > MAX_ACCOUNTS) throw new ImportFailure("CPA source contains too many upstream accounts");
  const identities = [...direct.map((item) => item.sourceId), ...native.map((item) => item.sourceId), ...managed.map((item) => item.stableId)], names = direct.map((item) => item.name);
  if (new Set(identities).size !== identities.length || new Set(names).size !== names.length) throw new ImportFailure("CPA source contains a stable identity conflict");
  if (policy.matchedPrivateTargetBaseUrls.size !== policy.privateTargetBaseUrls.size) throw new ImportFailure("CPA transport policy contains a private target absent from the source");
  if (policy.matchedResultOriginBaseUrls.size !== policy.resultOriginsByBaseUrl.size) throw new ImportFailure("CPA transport policy contains a result-origin target absent from the source");
  if (direct.some((record) => record.config.network_scope === "private" && record.proxySecretRef === undefined)) throw new ImportFailure("CPA private target requires an approved private SOCKS5 proxy");
  if (identities.length === 0) throw new ImportFailure("CPA source contains no active supported upstream accounts");
  return [{ direct, native, managed, disabledSourceCount: disabledConfig + disabledAuth }, secrets];
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
function readSourceKey(path: string): Buffer {
  if (!isAbsolute(path)) throw new ImportFailure("source identity key file path must be absolute"); const value = readOwnerOnly(path, "source identity key file", MAX_SECRET_BYTES);
  if (value.length !== SOURCE_KEY_PREFIX.length + SOURCE_KEY_BYTES || !timingSafeEqual(value.subarray(0, SOURCE_KEY_PREFIX.length), SOURCE_KEY_PREFIX)) throw new ImportFailure("source identity key has an invalid binary format"); const payload = Buffer.from(value.subarray(SOURCE_KEY_PREFIX.length)); value.fill(0); if (payload.every((byte) => byte === payload[0])) throw new ImportFailure("source identity key payload is invalid"); return payload;
}
function summary(mode: string, inventory: Inventory, native: JsonObject[], counts = [0, 0, 0, 0]): JsonObject {
  const sourceCounts: Record<string, number> = {}; for (const record of inventory.managed) sourceCounts[record.sourceType] = (sourceCounts[record.sourceType] ?? 0) + 1;
  return { api_account_count: inventory.direct.length, created_count: counts[0], created_managed_oauth_count: counts[2], disabled_source_count: inventory.disabledSourceCount, managed_oauth_account_count: inventory.managed.length, managed_oauth_source_type_counts: Object.fromEntries(Object.entries(sourceCounts).sort()), mode, native_reauthorization_required: native, native_reauthorization_required_count: native.length, private_target_api_account_count: inventory.direct.filter((record) => record.config.network_scope === "private").length, proxied_api_account_count: inventory.direct.filter((record) => record.proxySecretRef !== undefined).length, replayed_count: counts[1], replayed_managed_oauth_count: counts[3] };
}
type Options = { config?: string; authDir?: string; tenant: string; apply: boolean; target?: string; token?: string; sourceKey?: string; transportPolicy?: string; ca?: string; allowHttp: boolean };
function args(argv: string[]): Options {
  if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write("usage: import-cpa-upstreams --config FILE --auth-dir DIR [--transport-policy-file FILE] [--tenant ID] [--apply] [--target-api-base-url URL] [--service-token-file FILE] [--source-identity-key-file FILE] [--ca-file FILE] [--allow-http-loopback]\n\nImport real CPA config.yaml/auth-dir upstreams (dry-run by default).\n"); process.exit(0); }
  const result: Options = { tenant: "default", apply: false, allowHttp: false }; const valued: Record<string, keyof Options> = { "--config": "config", "--auth-dir": "authDir", "--transport-policy-file": "transportPolicy", "--tenant": "tenant", "--target-api-base-url": "target", "--service-token-file": "token", "--source-identity-key-file": "sourceKey", "--ca-file": "ca" };
  for (let index = 0; index < argv.length; index += 1) { const arg = argv[index]!; if (arg === "--apply") result.apply = true; else if (arg === "--allow-http-loopback") result.allowHttp = true; else if (valued[arg]) { const value = argv[++index]; if (!value) throw new ImportFailure(`${arg} requires a value`); (result as unknown as Record<string, unknown>)[valued[arg]!] = value; } else throw new ImportFailure(`unrecognized argument: ${arg}`); }
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
  let native: JsonObject[] = []; if (inventory.native.length > 0) { if (!options.sourceKey) throw new ImportFailure("source identity key file is required for opaque reauthorization records"); const key = readSourceKey(options.sourceKey); native = inventory.native.map((record) => ({ provider: record.provider, source_disabled: record.sourceDisabled, source_stable_id: createHmac("sha256", key).update(Buffer.concat([Buffer.from("memeloop-token-center\0cpa-native-reauthorization-source-id\0v1\0"), Buffer.from(record.sourceId)])).digest("hex") })); key.fill(0); }
  if (!options.apply || (inventory.direct.length === 0 && inventory.managed.length === 0)) { process.stdout.write(`${JSON.stringify(summary(options.apply ? "apply" : "dry-run", inventory, native))}\n`); return; }
  if (!options.target || !options.token) throw new ImportFailure("apply requires target API base URL and service token file"); const base = upstreamUrl(options.target, "target API base URL", options.allowHttp); const token = secretString(decodeUtf8(readOwnerOnly(options.token, "target service token file", MAX_SECRET_BYTES), "target service token file").replace(/\n$/, ""), "target service token file"); const counts = await apply(base, token, options.tenant, inventory, secrets, options.ca); process.stdout.write(`${JSON.stringify(summary("apply", inventory, native, counts))}\n`);
}
if (basename(process.argv[1] ?? "").replace(/\.(?:ts|[cm]?js)$/, "") === "import-cpa-upstreams") {
  main().catch((error) => { process.stderr.write(`CPA upstream import stopped: ${error instanceof ImportFailure ? error.message : "unexpected operator failure"}\n`); process.exitCode = 2; });
}
