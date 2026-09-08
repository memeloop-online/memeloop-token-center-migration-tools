#!/usr/bin/env node
/**
 * Read a CPA source snapshot through one already-running Pod.
 *
 * This command deliberately has no Kubernetes write verb, no Secret API
 * access, no shell invocation, and no selector-based Pod discovery. It copies
 * only the configured CPA source tree into a new local owner-only directory,
 * then obtains the managed Codex model observation through a loopback-only
 * kubectl port-forward. Dynamic source bytes are never written to stdout or
 * stderr.
 */

import { spawn, type ChildProcessByStdio } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, renameSync, rmSync, writeSync } from "node:fs";
import { dirname, isAbsolute, parse, relative, resolve, sep } from "node:path";
import { Readable } from "node:stream";
import { extract } from "tar-stream";
import { parseDocument } from "yaml";
import { parseStrictJson } from "../lib/strict-json.ts";
import { run as exportManagedCodexModelSnapshot } from "./export-cpa-managed-codex-model-snapshot.ts";

const MAX_TOTAL_BYTES = 64 * 1024 * 1024;
const MAX_ENTRY_BYTES = 8 * 1024 * 1024;
const MAX_ENTRIES = 10_000;
const MAX_METADATA_BYTES = 1024 * 1024;
const MAX_PORT_FORWARD_OUTPUT = 8 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_TIMEOUT_MS = 60_000;
const POD_NAME = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const KUBE_NAME = /^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/;
const POD_UID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ARGUMENT = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;

type JsonObject = Record<string, unknown>;
type ArchiveEntry = Readonly<{ name: string; kind: "file" | "directory"; content: Buffer }>;
type SourceLayout = Readonly<{ authRelativePath: string; policyRelativePath: string }>;
type AuthProjection = Readonly<{ path: string; type: string; disabled: boolean; prefix: string | null; aliases: readonly Readonly<{ name: string; alias: string }>[]; excluded: readonly string[] }>;
type SourceCapture = Readonly<{
  config: Buffer;
  policy: Buffer;
  authFiles: ReadonlyMap<string, Buffer>;
  authFileCount: number;
  managedCodexAuthFileCount: number;
  configSha256: string;
  policySha256: string;
  authProjectionSha256: string;
  authPayloadRevisionSha256: string;
  sourceRouteEvidenceSha256: string;
  sourceCaptureSha256: string;
}>;

type Options = Readonly<{
  kubectl: string;
  kubectlArguments: readonly string[];
  context: string;
  namespace: string;
  pod: string;
  podUid: string;
  container: string;
  expectedAppName: string;
  expectedPvc: string;
  sourceStateRoot: string;
  configMountPath: string;
  managementPort: number;
  managementTokenFile?: string;
  outputDirectory: string;
  timeoutMs: number;
  maxTotalBytes: number;
}>;

type MutableOptions = { -readonly [Key in keyof Options]?: Options[Key] };
type KubectlChild = ChildProcessByStdio<null, Readable, null>;

export class CpaSourceCollectionFailure extends Error {}

const compare = (left: string, right: string): number => left < right ? -1 : left > right ? 1 : 0;
const sha256 = (value: Uint8Array | string): string => createHash("sha256").update(value).digest("hex");

function fail(message: string): never { throw new CpaSourceCollectionFailure(message); }
function record(value: unknown, label: string): JsonObject {
  if (value === null || Array.isArray(value) || typeof value !== "object") fail(`${label} has an invalid schema`);
  return value as JsonObject;
}
function text(value: unknown, label: string, pattern = ARGUMENT, maximum = 256): string {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || Buffer.byteLength(value) > maximum || /[\0\r\n]/.test(value) || !pattern.test(value)) fail(`${label} has an invalid schema`);
  return value;
}
function absolutePath(value: unknown, label: string): string {
  if (typeof value !== "string" || !isAbsolute(value) || value !== resolve(value) || value === parse(value).root || value.includes("\0")) fail(`${label} must be an absolute normalized path`);
  return value;
}
function positiveInteger(value: unknown, label: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > maximum) fail(`${label} is invalid`);
  return Number(value);
}
function decode(value: Buffer, label: string): string {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(value); }
  catch { fail(`${label} is not UTF-8`); }
}
function strictJson(value: Buffer, label: string): unknown {
  try { return parseStrictJson(decode(value, label)); }
  catch { fail(`${label} is not strict JSON`); }
}

function usage(): string {
  return "usage: collect-cpa-source-snapshot --kubectl-binary PATH --context NAME --namespace NAME --pod NAME --pod-uid UUID --container NAME --expected-app-name NAME --expected-pvc NAME --source-state-root PATH --config-mount-path PATH --management-port PORT --output-directory PATH [--management-token-file FILE] [--kubectl-argument ARG] [--timeout-ms N] [--max-total-bytes N]";
}

function options(argv: readonly string[]): Options {
  if (argv.includes("--help") || argv.includes("-h")) { process.stdout.write(`${usage()}\n`); process.exit(0); }
  const fields: Record<string, keyof MutableOptions> = {
    "--kubectl-binary": "kubectl",
    "--context": "context",
    "--namespace": "namespace",
    "--pod": "pod",
    "--pod-uid": "podUid",
    "--container": "container",
    "--expected-app-name": "expectedAppName",
    "--expected-pvc": "expectedPvc",
    "--source-state-root": "sourceStateRoot",
    "--config-mount-path": "configMountPath",
    "--management-port": "managementPort",
    "--management-token-file": "managementTokenFile",
    "--output-directory": "outputDirectory",
    "--timeout-ms": "timeoutMs",
    "--max-total-bytes": "maxTotalBytes",
  };
  const parsed: MutableOptions = {}, kubectlArguments: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (argument === "--kubectl-argument") {
      const value = argv[index + 1];
      if (value === undefined || value.length === 0 || Buffer.byteLength(value) > 4_096 || /[\0\r\n]/.test(value)) fail("arguments are invalid");
      kubectlArguments.push(value); index += 1; continue;
    }
    const field = fields[argument], value = argv[index + 1];
    if (!field || value === undefined || value.startsWith("--") || parsed[field] !== undefined) fail("arguments are invalid");
    if (field === "managementPort") parsed.managementPort = positiveInteger(Number(value), "management port", 65_535);
    else if (field === "timeoutMs") parsed.timeoutMs = positiveInteger(Number(value), "timeout", MAX_TIMEOUT_MS);
    else if (field === "maxTotalBytes") parsed.maxTotalBytes = positiveInteger(Number(value), "maximum archive size", 256 * 1024 * 1024);
    else if (field === "kubectl" || field === "sourceStateRoot" || field === "configMountPath" || field === "managementTokenFile" || field === "outputDirectory") parsed[field] = absolutePath(value, argument) as never;
    else if (field === "pod") parsed.pod = text(value, "pod", POD_NAME, 253);
    else if (field === "podUid") parsed.podUid = text(value, "pod UID", POD_UID, 36);
    else if (field === "namespace" || field === "expectedAppName" || field === "expectedPvc") parsed[field] = text(value, argument, KUBE_NAME, 253) as never;
    else parsed[field] = text(value, argument) as never;
    index += 1;
  }
  if (!parsed.kubectl || !parsed.context || !parsed.namespace || !parsed.pod || !parsed.podUid || !parsed.container || !parsed.expectedAppName || !parsed.expectedPvc || !parsed.sourceStateRoot || !parsed.configMountPath || !parsed.managementPort || !parsed.outputDirectory) fail("required arguments are missing");
  if (parsed.outputDirectory === parsed.managementTokenFile || parsed.outputDirectory === parsed.sourceStateRoot) fail("output directory conflicts with an input");
  return {
    kubectl: parsed.kubectl,
    kubectlArguments,
    context: parsed.context,
    namespace: parsed.namespace,
    pod: parsed.pod,
    podUid: parsed.podUid,
    container: parsed.container,
    expectedAppName: parsed.expectedAppName,
    expectedPvc: parsed.expectedPvc,
    sourceStateRoot: parsed.sourceStateRoot,
    configMountPath: parsed.configMountPath,
    managementPort: parsed.managementPort,
    managementTokenFile: parsed.managementTokenFile,
    outputDirectory: parsed.outputDirectory,
    timeoutMs: parsed.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    maxTotalBytes: parsed.maxTotalBytes ?? MAX_TOTAL_BYTES,
  };
}

function kubectlPrefix(selected: Options): string[] { return [...selected.kubectlArguments, "--context", selected.context, "--namespace", selected.namespace]; }

async function command(binary: string, args: readonly string[], maximum: number, timeoutMs: number): Promise<Buffer> {
  return await new Promise((resolveCommand, rejectCommand) => {
    let child: KubectlChild;
    try { child = spawn(binary, [...args], { shell: false, windowsHide: true, stdio: ["ignore", "pipe", "ignore"], env: process.env }); }
    catch { rejectCommand(new CpaSourceCollectionFailure("kubectl command could not start")); return; }
    const chunks: Buffer[] = []; let total = 0, settled = false;
    let forceTimer: NodeJS.Timeout | undefined;
    const wipeChunks = (): void => { for (const chunk of chunks) chunk.fill(0); chunks.length = 0; };
    const terminate = (): void => {
      if (child.exitCode !== null || child.killed) return;
      child.kill("SIGTERM");
      forceTimer = setTimeout(() => { if (child.exitCode === null) child.kill("SIGKILL"); }, 5_000);
    };
    const finish = (result: Buffer | CpaSourceCollectionFailure): void => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (Buffer.isBuffer(result)) resolveCommand(result);
      else { wipeChunks(); rejectCommand(result); }
    };
    const timer = setTimeout(() => { terminate(); finish(new CpaSourceCollectionFailure("kubectl command timed out")); }, timeoutMs);
    child.stdout.on("data", (chunk: Buffer | Uint8Array) => {
      if (settled) return;
      const value = Buffer.from(chunk); total += value.length;
      if (total > maximum) { terminate(); finish(new CpaSourceCollectionFailure("kubectl response exceeds the safety limit")); return; }
      chunks.push(value);
    });
    child.once("error", () => finish(new CpaSourceCollectionFailure("kubectl command failed")));
    child.once("close", (code) => {
      if (forceTimer) clearTimeout(forceTimer);
      if (settled) return;
      if (code !== 0) finish(new CpaSourceCollectionFailure("kubectl command failed"));
      else { const output = Buffer.concat(chunks); wipeChunks(); finish(output); }
    });
  });
}

function podMetadata(selected: Options, raw: Buffer): void {
  const root = record(strictJson(raw, "Pod metadata"), "Pod metadata"), metadata = record(root.metadata, "Pod metadata"), spec = record(root.spec, "Pod metadata");
  if (metadata.namespace !== selected.namespace || metadata.uid !== selected.podUid) fail("selected CPA Pod identity changed");
  const labels = record(metadata.labels, "Pod metadata labels");
  if (labels["app.kubernetes.io/name"] !== selected.expectedAppName) fail("selected Pod is not the approved CPA workload");
  if (!Array.isArray(spec.containers) || !Array.isArray(spec.volumes)) fail("selected Pod lacks approved source mount metadata");
  const container = spec.containers.find((value) => value !== null && typeof value === "object" && !Array.isArray(value) && (value as JsonObject).name === selected.container);
  if (container === undefined) fail("selected Pod lacks the approved CPA container");
  const containerRecord = record(container, "CPA container"), mounts = containerRecord.volumeMounts;
  if (!Array.isArray(mounts)) fail("CPA container lacks source mount metadata");
  const stateMount = mounts.find((value) => value !== null && typeof value === "object" && !Array.isArray(value) && (value as JsonObject).mountPath === selected.sourceStateRoot);
  const configMount = mounts.find((value) => value !== null && typeof value === "object" && !Array.isArray(value) && (value as JsonObject).mountPath === selected.configMountPath);
  if (!stateMount || !configMount) fail("CPA source mount layout is not approved");
  const state = record(stateMount, "CPA state mount"), config = record(configMount, "CPA config mount");
  if (typeof state.name !== "string" || config.name !== state.name || config.subPath !== "config.yaml") fail("CPA source mount layout is not approved");
  const volume = spec.volumes.find((value) => value !== null && typeof value === "object" && !Array.isArray(value) && (value as JsonObject).name === state.name);
  if (volume === undefined) fail("CPA source PVC is unavailable");
  const pvc = record(record(volume, "CPA source volume").persistentVolumeClaim, "CPA source PVC");
  if (pvc.claimName !== selected.expectedPvc) fail("CPA source PVC is not approved");
  if (!Array.isArray(containerRecord.ports) || !containerRecord.ports.some((value) => value !== null && typeof value === "object" && !Array.isArray(value) && (value as JsonObject).containerPort === selected.managementPort && (((value as JsonObject).protocol ?? "TCP") === "TCP"))) fail("CPA management port is not approved");
}

async function verifyPod(selected: Options): Promise<void> {
  const raw = await command(selected.kubectl, [...kubectlPrefix(selected), "get", "pod", selected.pod, "--output", "json"], MAX_METADATA_BYTES, selected.timeoutMs);
  podMetadata(selected, raw); raw.fill(0);
}

function archiveName(value: unknown, kind: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024 || value.includes("\0") || value.startsWith("/") || value.startsWith("./") || value.includes("\\")) fail("source archive has an unsafe path");
  const normalized = kind === "directory" && value.endsWith("/") ? value.slice(0, -1) : value;
  if (!normalized || normalized.split("/").some((part) => !part || part === "." || part === "..")) fail("source archive has an unsafe path");
  return normalized;
}

async function parseArchive(raw: Buffer, maximum: number): Promise<ReadonlyMap<string, ArchiveEntry>> {
  return await new Promise((resolveArchive, rejectArchive) => {
    const entries = new Map<string, ArchiveEntry>(); let total = 0, count = 0, settled = false;
    const parser = extract(), input = Readable.from(raw);
    const finish = (error?: CpaSourceCollectionFailure): void => {
      if (settled) return;
      settled = true;
      if (error) rejectArchive(error); else resolveArchive(entries);
    };
    const abort = (error: CpaSourceCollectionFailure): void => {
      if (settled) return;
      try { input.unpipe(parser); } catch {}
      try { input.destroy(); } catch {}
      try { parser.destroy(); } catch {}
      finish(error);
    };
    parser.on("entry", (header, stream, next) => {
      if (settled) { stream.resume(); return; }
      count += 1;
      const kind = header.type ?? "file";
      let name: string;
      try {
        if (count > MAX_ENTRIES || (kind !== "file" && kind !== "directory")) fail("source archive has an unsupported entry");
        name = archiveName(header.name, kind);
        if (entries.has(name) || !Number.isSafeInteger(header.size) || Number(header.size) < 0 || Number(header.size) > MAX_ENTRY_BYTES) fail("source archive has an invalid entry");
      } catch (error) { stream.resume(); abort(error instanceof CpaSourceCollectionFailure ? error : new CpaSourceCollectionFailure("source archive is invalid")); return; }
      const chunks: Buffer[] = []; let size = 0;
      stream.on("data", (chunk: unknown) => {
        if (settled) return;
        if (!(chunk instanceof Uint8Array)) { abort(new CpaSourceCollectionFailure("source archive has an invalid entry stream")); return; }
        const value = Buffer.from(chunk); size += value.length; total += value.length;
        if (size > MAX_ENTRY_BYTES || total > maximum) { abort(new CpaSourceCollectionFailure("source archive exceeds the safety limit")); return; }
        chunks.push(value);
      });
      stream.on("error", () => abort(new CpaSourceCollectionFailure("source archive could not be read")));
      stream.once("end", () => {
        if (settled) return;
        if (size !== Number(header.size) || (kind === "directory" && size !== 0)) { abort(new CpaSourceCollectionFailure("source archive entry changed while being read")); return; }
        entries.set(name, { name, kind: kind as "file" | "directory", content: Buffer.concat(chunks) }); next();
      });
    });
    parser.once("finish", () => finish());
    parser.on("error", () => finish(new CpaSourceCollectionFailure("source archive is invalid")));
    input.on("error", () => abort(new CpaSourceCollectionFailure("source archive could not be read")));
    input.pipe(parser);
  });
}

function relativeSourcePath(root: string, value: unknown, label: string): string {
  if (typeof value !== "string" || !isAbsolute(value) || value !== resolve(value) || value.includes("\0")) fail(`${label} is outside the approved CPA source state`);
  const path = relative(root, value).split(sep).join("/");
  if (!path || path === ".." || path.startsWith("../") || path.includes("\\") || path.split("/").some((part) => !part || part === "." || part === "..")) fail(`${label} is outside the approved CPA source state`);
  return path;
}

function sourceLayout(configRaw: Buffer, stateRoot: string): SourceLayout {
  let config: JsonObject;
  try {
    const document = parseDocument(decode(configRaw, "CPA source config"), { uniqueKeys: true });
    if (document.errors.length !== 0 || document.warnings.length !== 0) throw new Error("invalid");
    config = record(document.toJS({ maxAliasCount: 0 }), "CPA source config");
  } catch { fail("CPA source config is not valid safe YAML"); }
  const authRelativePath = relativeSourcePath(stateRoot, config["auth-dir"], "CPA auth directory");
  const plugins = record(config.plugins, "CPA plugin config"), configs = record(plugins.configs, "CPA plugin config"), policy = record(configs["cpa-key-policy"], "CPA key-policy config");
  if (policy.mode !== "native-access") fail("CPA key-policy source is not native-access");
  const policyRelativePath = relativeSourcePath(stateRoot, policy.native_state_file, "CPA native policy");
  if (policyRelativePath === "config.yaml" || policyRelativePath === authRelativePath || inside(policyRelativePath, `${authRelativePath}/logs`)) fail("CPA source layout is invalid");
  return { authRelativePath, policyRelativePath };
}

function inside(path: string, directory: string): boolean { return path === directory || path.startsWith(`${directory}/`); }

function selectedAlias(value: unknown): readonly Readonly<{ name: string; alias: string }>[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > 2_000) fail("CPA auth route projection is invalid");
  const result: Array<Readonly<{ name: string; alias: string }>> = [];
  for (const item of value) {
    const entry = record(item, "CPA auth route projection");
    if (typeof entry.name !== "string" || typeof entry.alias !== "string" || entry.name.trim() !== entry.name || entry.alias.trim() !== entry.alias || !entry.name || !entry.alias || /[\0\r\n]/.test(entry.name) || /[\0\r\n]/.test(entry.alias)) fail("CPA auth route projection is invalid");
    result.push({ name: entry.name, alias: entry.alias });
  }
  return result;
}
function selectedExcluded(value: unknown): readonly string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > 2_000) fail("CPA auth route projection is invalid");
  const values = value.map((item) => {
    if (typeof item !== "string" || item.trim() !== item || !item || /[\0\r\n]/.test(item)) fail("CPA auth route projection is invalid");
    return item.toLowerCase();
  });
  return [...new Set(values)].sort(compare);
}
function normalizedPrefix(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") return null;
  const normalized = value.trim().replace(/^\/+|\/+$/gu, "");
  return normalized && !normalized.includes("/") ? normalized : null;
}
function authProjection(path: string, raw: Buffer): AuthProjection {
  const document = record(strictJson(raw, "CPA auth document"), "CPA auth document");
  if (typeof document.type !== "string" || document.type.trim().length === 0 || /[\0\r\n]/.test(document.type)) fail("CPA auth route projection is invalid");
  const disabled = document.disabled ?? false;
  if (typeof disabled !== "boolean") fail("CPA auth route projection is invalid");
  const aliases = Object.hasOwn(document, "model_aliases") ? selectedAlias(document.model_aliases) : selectedAlias(document["model-aliases"]);
  const excluded = Object.hasOwn(document, "excluded_models") ? selectedExcluded(document.excluded_models) : selectedExcluded(document["excluded-models"]);
  return { path, type: document.type.trim().toLowerCase(), disabled, prefix: normalizedPrefix(document.prefix), aliases, excluded };
}

function captureFromArchive(entries: ReadonlyMap<string, ArchiveEntry>, layout: SourceLayout): SourceCapture {
  const config = entries.get("config.yaml"), policy = entries.get(layout.policyRelativePath);
  if (!config || config.kind !== "file" || !policy || policy.kind !== "file") fail("source archive lacks the approved CPA inputs");
  const authFiles = new Map<string, Buffer>(), projections: AuthProjection[] = [];
  for (const entry of entries.values()) {
    if (entry.name === "config.yaml" || entry.name === layout.policyRelativePath) continue;
    if (!inside(entry.name, layout.authRelativePath)) fail("source archive contains an unapproved path");
    if (inside(entry.name, `${layout.authRelativePath}/logs`)) fail("source archive did not exclude the reviewed logs subtree");
    if (entry.kind === "directory") continue;
    const relativePath = entry.name.slice(`${layout.authRelativePath}/`.length);
    if (!relativePath || !relativePath.toLowerCase().endsWith(".json")) fail("source archive contains a non-JSON auth entry");
    authFiles.set(relativePath, entry.content);
    projections.push(authProjection(relativePath, entry.content));
  }
  if (authFiles.size > MAX_ENTRIES) fail("CPA auth source exceeds the safety limit");
  projections.sort((left, right) => compare(left.path, right.path));
  const authPayload = [...authFiles.entries()].sort(([left], [right]) => compare(left, right)).map(([path, content]) => ({ path, sha256: sha256(content) }));
  const configSha256 = sha256(config.content), policySha256 = sha256(policy.content), authProjectionSha256 = sha256(Buffer.from(`${JSON.stringify({ version: 1, auth: projections })}\n`)), authPayloadRevisionSha256 = sha256(Buffer.from(`${JSON.stringify({ version: 1, auth: authPayload })}\n`));
  const sourceRouteEvidenceSha256 = sha256(Buffer.from(`${JSON.stringify({ version: 1, config_sha256: configSha256, policy_sha256: policySha256, auth_route_projection_sha256: authProjectionSha256 })}\n`));
  const sourceCaptureSha256 = sha256(Buffer.from(`${JSON.stringify({ version: 1, config_sha256: configSha256, policy_sha256: policySha256, auth_payload_revision_sha256: authPayloadRevisionSha256 })}\n`));
  return {
    config: Buffer.from(config.content),
    policy: Buffer.from(policy.content),
    authFiles,
    authFileCount: authFiles.size,
    managedCodexAuthFileCount: projections.filter((item) => item.type === "codex").length,
    configSha256,
    policySha256,
    authProjectionSha256,
    authPayloadRevisionSha256,
    sourceRouteEvidenceSha256,
    sourceCaptureSha256,
  };
}

async function archive(selected: Options, paths: readonly string[], excluded: readonly string[]): Promise<ReadonlyMap<string, ArchiveEntry>> {
  const args = [...kubectlPrefix(selected), "exec", selected.pod, "--container", selected.container, "--", "tar", "-C", selected.sourceStateRoot, ...excluded.map((path) => `--exclude=${path}`), "-cf", "-", ...paths];
  const raw = await command(selected.kubectl, args, selected.maxTotalBytes + (MAX_ENTRIES * 1024), selected.timeoutMs);
  try { return await parseArchive(raw, selected.maxTotalBytes); }
  finally { raw.fill(0); }
}

async function captureSource(selected: Options): Promise<SourceCapture> {
  const configArchive = await archive(selected, ["config.yaml"], []);
  const config = configArchive.get("config.yaml");
  if (!config || config.kind !== "file" || configArchive.size !== 1) fail("source archive lacks the exact CPA config");
  const layoutConfigSha256 = sha256(config.content); let layout: SourceLayout;
  try { layout = sourceLayout(config.content, selected.sourceStateRoot); }
  finally { for (const entry of configArchive.values()) entry.content.fill(0); }
  const paths = ["config.yaml", layout.authRelativePath];
  if (!inside(layout.policyRelativePath, layout.authRelativePath)) paths.push(layout.policyRelativePath);
  const entries = await archive(selected, paths, [`${layout.authRelativePath}/logs`]);
  const capturedConfig = entries.get("config.yaml");
  if (!capturedConfig || capturedConfig.kind !== "file" || sha256(capturedConfig.content) !== layoutConfigSha256) fail("CPA source config changed while deriving the capture layout");
  return captureFromArchive(entries, layout);
}

function assertStable(first: SourceCapture, second: SourceCapture): void {
  if (!first.config.equals(second.config) || !first.policy.equals(second.policy) || first.authProjectionSha256 !== second.authProjectionSha256) fail("CPA source route evidence changed during capture");
}

function safeParent(path: string): string {
  const parent = dirname(path), root = parse(parent).root;
  let current = root;
  for (const piece of relative(root, parent).split(sep).filter(Boolean)) {
    current = resolve(current, piece);
    let metadata: ReturnType<typeof lstatSync>;
    try { metadata = lstatSync(current); } catch { fail("output parent directory is unsafe"); }
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) fail("output parent directory is unsafe");
  }
  let descriptor: number | undefined;
  try {
    descriptor = openSync(parent, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || (process.geteuid?.() !== undefined && metadata.uid !== process.geteuid()) || (metadata.mode & 0o022) !== 0) fail("output parent directory is unsafe");
    return parent;
  } catch (error) {
    if (error instanceof CpaSourceCollectionFailure) throw error;
    fail("output parent directory is unsafe");
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
  fail("output parent directory is unsafe");
}
function privateDirectory(path: string): void {
  try { mkdirSync(path, { mode: 0o700 }); }
  catch (error) {
    const code = error && typeof error === "object" && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
    if (code !== "EEXIST") fail("local staging directory is unsafe");
  }
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || (metadata.mode & 0o777) !== 0o700 || (process.geteuid?.() !== undefined && metadata.uid !== process.geteuid())) fail("local staging directory is unsafe");
}
function newPrivateDirectory(path: string): void {
  try { mkdirSync(path, { mode: 0o700 }); }
  catch (error) {
    const code = error && typeof error === "object" && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
    if (code === "EEXIST") fail("output directory already exists");
    fail("source capture could not be published");
  }
  const metadata = lstatSync(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || (metadata.mode & 0o777) !== 0o700 || (process.geteuid?.() !== undefined && metadata.uid !== process.geteuid())) fail("source capture could not be published");
}
function privateFile(path: string, value: Buffer): void {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    for (let offset = 0; offset < value.length;) { const written = writeSync(descriptor, value, offset, value.length - offset); if (written <= 0) fail("local protected input could not be written"); offset += written; }
    fsyncSync(descriptor); closeSync(descriptor); descriptor = undefined;
    const metadata = lstatSync(path);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o600) fail("local protected input could not be persisted");
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    if (error instanceof CpaSourceCollectionFailure) throw error;
    fail("local protected input could not be written");
  }
}
function writeSourceCapture(directory: string, capture: SourceCapture): void {
  privateFile(resolve(directory, "config.yaml"), capture.config);
  privateFile(resolve(directory, "native-key-policy.json"), capture.policy);
  const authDirectory = resolve(directory, "auth"); privateDirectory(authDirectory);
  for (const [relativePath, content] of [...capture.authFiles.entries()].sort(([left], [right]) => compare(left, right))) {
    const pieces = relativePath.split("/"); let current = authDirectory;
    for (const piece of pieces.slice(0, -1)) { current = resolve(current, piece); privateDirectory(current); }
    privateFile(resolve(authDirectory, relativePath), content);
  }
}

type PortForward = Readonly<{ port: number; close: () => Promise<void> }>;
async function portForward(selected: Options): Promise<PortForward> {
  let child: KubectlChild;
  try {
    child = spawn(selected.kubectl, [...kubectlPrefix(selected), "port-forward", `pod/${selected.pod}`, "--address", "127.0.0.1", `:${selected.managementPort}`], { shell: false, windowsHide: true, stdio: ["ignore", "pipe", "ignore"], env: process.env });
  } catch { fail("kubectl port-forward could not start"); }
  return await new Promise((resolveForward, rejectForward) => {
    let output = "", settled = false;
    let forceTimer: NodeJS.Timeout | undefined;
    const terminate = (): void => {
      if (child.exitCode !== null || child.killed) return;
      child.kill("SIGTERM");
      forceTimer = setTimeout(() => { if (child.exitCode === null) child.kill("SIGKILL"); }, 5_000);
    };
    const timer = setTimeout(() => {
      if (!settled) { settled = true; terminate(); rejectForward(new CpaSourceCollectionFailure("kubectl port-forward timed out")); }
    }, selected.timeoutMs);
    const reject = (error: CpaSourceCollectionFailure): void => { if (!settled) { settled = true; clearTimeout(timer); terminate(); rejectForward(error); } };
    child.stdout.on("data", (chunk: Buffer | Uint8Array) => {
      if (settled) return;
      output += Buffer.from(chunk).toString("utf8");
      if (Buffer.byteLength(output) > MAX_PORT_FORWARD_OUTPUT) { reject(new CpaSourceCollectionFailure("kubectl port-forward returned invalid output")); return; }
      const match = /Forwarding from 127\.0\.0\.1:(\d+) -> \d+/u.exec(output);
      if (!match) return;
      const port = Number(match[1]);
      if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) { reject(new CpaSourceCollectionFailure("kubectl port-forward returned invalid output")); return; }
      settled = true; clearTimeout(timer);
      resolveForward({
        port,
        close: async () => {
          if (child.exitCode === null && !child.killed) child.kill("SIGTERM");
          await new Promise<void>((resolveClose) => {
            if (child.exitCode !== null) { resolveClose(); return; }
            const closeTimer = setTimeout(() => { if (child.exitCode === null) child.kill("SIGKILL"); }, 5_000);
            child.once("close", () => { clearTimeout(closeTimer); resolveClose(); });
          });
        },
      });
    });
    child.once("error", () => reject(new CpaSourceCollectionFailure("kubectl port-forward failed")));
    child.once("close", () => { if (forceTimer) clearTimeout(forceTimer); reject(new CpaSourceCollectionFailure("kubectl port-forward ended before use")); });
  });
}

function receipt(capture: SourceCapture, modelSnapshot: Buffer | undefined): Buffer {
  return Buffer.from(`${JSON.stringify({
    version: 1,
    mode: "collect-cpa-source-snapshot",
    source_config_sha256: capture.configSha256,
    source_policy_sha256: capture.policySha256,
    auth_route_projection_sha256: capture.authProjectionSha256,
    auth_payload_revision_sha256: capture.authPayloadRevisionSha256,
    source_route_evidence_sha256: capture.sourceRouteEvidenceSha256,
    source_capture_sha256: capture.sourceCaptureSha256,
    managed_codex_model_snapshot_sha256: modelSnapshot === undefined ? null : sha256(modelSnapshot),
    auth_file_count: capture.authFileCount,
    managed_codex_auth_file_count: capture.managedCodexAuthFileCount,
  })}\n`);
}

function fsyncDirectory(path: string): void {
  let descriptor: number | undefined;
  try { descriptor = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW); fsyncSync(descriptor); }
  catch { fail("source capture could not be published"); }
  finally { if (descriptor !== undefined) closeSync(descriptor); }
}
function publish(work: string, output: string): void {
  newPrivateDirectory(output);
  try {
    for (const name of ["config.yaml", "native-key-policy.json", "auth", "managed-codex-model-snapshot.json"]) {
      try { lstatSync(resolve(work, name)); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
        fail("source capture could not be published");
      }
      renameSync(resolve(work, name), resolve(output, name));
    }
    fsyncDirectory(output);
    renameSync(resolve(work, "source-capture-receipt.json"), resolve(output, "source-capture-receipt.json"));
    fsyncDirectory(output);
    fsyncDirectory(dirname(output));
    rmSync(work, { recursive: true, force: true });
  } catch (error) {
    if (error instanceof CpaSourceCollectionFailure) throw error;
    fail("source capture could not be published");
  }
}

export async function run(argv = process.argv.slice(2)): Promise<Readonly<Record<string, number | string>>> {
  const selected = options(argv), parent = safeParent(selected.outputDirectory);
  let work: string | undefined, first: SourceCapture | undefined, second: SourceCapture | undefined, forwarded: PortForward | undefined, modelSnapshot: Buffer | undefined;
  try {
    try { lstatSync(selected.outputDirectory); fail("output directory already exists"); }
    catch (error) { if (error instanceof CpaSourceCollectionFailure) throw error; }
    await verifyPod(selected);
    first = await captureSource(selected);
    await verifyPod(selected);
    work = mkdtempSync(resolve(parent, `.cpa-source-capture-${randomBytes(8).toString("hex")}-`));
    const workMetadata = lstatSync(work);
    if (!workMetadata.isDirectory() || workMetadata.isSymbolicLink()) fail("local staging directory is unsafe");
    let workDescriptor: number | undefined;
    try { workDescriptor = openSync(work, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW); fsyncSync(workDescriptor); }
    catch { fail("local staging directory is unsafe"); }
    finally { if (workDescriptor !== undefined) closeSync(workDescriptor); }
    privateFile(resolve(work, "config.yaml"), first.config);
    if (first.managedCodexAuthFileCount > 0) {
      if (!selected.managementTokenFile) fail("managed Codex source requires a protected management token file");
      forwarded = await portForward(selected);
      try {
        await exportManagedCodexModelSnapshot([
          "--management-api-base-url", `http://127.0.0.1:${forwarded.port}/v0/management`,
          "--allow-http-loopback",
          "--management-token-file", selected.managementTokenFile,
          "--source-config-file", resolve(work, "config.yaml"),
          "--output", resolve(work, "managed-codex-model-snapshot.json"),
        ]);
      } finally { await forwarded.close(); forwarded = undefined; }
      modelSnapshot = readFileSync(resolve(work, "managed-codex-model-snapshot.json"));
    }
    await verifyPod(selected);
    second = await captureSource(selected);
    await verifyPod(selected);
    assertStable(first, second);
    rmSync(resolve(work, "config.yaml"), { force: true });
    writeSourceCapture(work, second);
    privateFile(resolve(work, "source-capture-receipt.json"), receipt(second, modelSnapshot));
    modelSnapshot?.fill(0); modelSnapshot = undefined;
    publish(work, selected.outputDirectory); work = undefined;
    return {
      mode: "collect-cpa-source-snapshot",
      source_route_evidence_sha256: second.sourceRouteEvidenceSha256,
      source_capture_sha256: second.sourceCaptureSha256,
      auth_file_count: second.authFileCount,
      managed_codex_auth_file_count: second.managedCodexAuthFileCount,
    };
  } finally {
    if (forwarded) await forwarded.close();
    first?.config.fill(0); first?.policy.fill(0); for (const value of first?.authFiles.values() ?? []) value.fill(0);
    second?.config.fill(0); second?.policy.fill(0); for (const value of second?.authFiles.values() ?? []) value.fill(0);
    modelSnapshot?.fill(0);
    if (work) { try { rmSync(work, { recursive: true, force: true }); } catch {} }
  }
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  run().then((result) => process.stdout.write(`${JSON.stringify(result)}\n`)).catch(() => { process.stderr.write("CPA source collection stopped\n"); process.exitCode = 2; });
}
