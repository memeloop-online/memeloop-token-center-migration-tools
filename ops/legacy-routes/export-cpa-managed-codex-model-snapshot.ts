#!/usr/bin/env node
/** Capture a read-only CPA per-auth Codex model-registry snapshot. */

import { createHash, randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, openSync, readSync, unlinkSync, writeSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { basename, dirname, isAbsolute, parse, relative, resolve, sep } from "node:path";
import { parseStrictJson } from "../lib/strict-json.ts";

const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_CONFIG_BYTES = 4 * 1024 * 1024;
const MAX_AUTH_FILES = 10_000;
const MAX_MODELS = 2_000;

type ObjectValue = Record<string, unknown>;
export type CapturedAuth = Readonly<{ id: string; provider: "codex"; disabled: boolean; status: string }>;
export type CapturedModels = Readonly<{ auth_id: string; provider: "codex"; registered_models: readonly string[] }>;
type Artifacts = Readonly<{ snapshot: Buffer; counts: Readonly<Record<string, number | string>> }>;

export class ManagedCodexSnapshotFailure extends Error {}

function object(value: unknown, label: string): ObjectValue {
  if (value === null || Array.isArray(value) || typeof value !== "object") throw new ManagedCodexSnapshotFailure(`${label} has an invalid schema`);
  return value as ObjectValue;
}
function publicText(value: unknown, label: string, maximum = 500): string {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || Buffer.byteLength(value) > maximum || /[\0\r\n]/.test(value)) throw new ManagedCodexSnapshotFailure(`${label} has an invalid schema`);
  return value;
}
function relativeAuthId(value: unknown): string {
  const id = publicText(value, "CPA auth-file ID");
  if (Buffer.byteLength(id) > 512 || id.startsWith("/") || id.includes("\\") || id.split("/").some((part) => !part || part === "." || part === "..")) throw new ManagedCodexSnapshotFailure("CPA auth-file ID is invalid");
  return id;
}
function compare(left: string, right: string): number { return left < right ? -1 : left > right ? 1 : 0; }
function sha256(value: Uint8Array): string { return createHash("sha256").update(value).digest("hex"); }
function decode(raw: Uint8Array, label: string): string {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(raw); }
  catch { throw new ManagedCodexSnapshotFailure(`${label} is not valid UTF-8`); }
}
function parseJson(raw: Buffer, label: string): unknown {
  try { return parseStrictJson(decode(raw, label)); }
  catch { throw new ManagedCodexSnapshotFailure(`${label} is not strict JSON`); }
}
function readOwnerOnly(path: string, label: string, limit: number): Buffer {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600 || (process.geteuid?.() !== undefined && stat.uid !== process.geteuid())) throw new Error("unsafe");
    const output = Buffer.allocUnsafe(limit + 1); let offset = 0;
    while (offset < output.length) { const count = readSync(descriptor, output, offset, output.length - offset, null); if (count === 0) break; offset += count; }
    if (offset > limit) { output.fill(0); throw new ManagedCodexSnapshotFailure(`${label} exceeds the supported size`); }
    return Buffer.from(output.subarray(0, offset));
  } catch (error) {
    if (error instanceof ManagedCodexSnapshotFailure) throw error;
    throw new ManagedCodexSnapshotFailure(`${label} is not a readable owner-only regular file`);
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}
function snapshotAuths(value: unknown): CapturedAuth[] {
  const root = object(value, "CPA auth-files response");
  if (!Array.isArray(root.files) || root.files.length > MAX_AUTH_FILES) throw new ManagedCodexSnapshotFailure("CPA auth-files response has an invalid schema");
  const result: CapturedAuth[] = [];
  for (const item of root.files) {
    const record = object(item, "CPA auth-files entry");
    if (record.type !== "codex" || record.provider !== "codex") continue;
    const id = relativeAuthId(record.id), status = publicText(record.status, "CPA auth-file status");
    if (typeof record.disabled !== "boolean") throw new ManagedCodexSnapshotFailure("CPA auth-files entry has an invalid schema");
    result.push({ id, provider: "codex", disabled: record.disabled, status });
  }
  result.sort((left, right) => compare(left.id, right.id));
  if (new Set(result.map((item) => item.id)).size !== result.length) throw new ManagedCodexSnapshotFailure("CPA auth-files response has duplicate Codex IDs");
  return result;
}
function snapshotModels(authId: string, value: unknown): CapturedModels {
  const root = object(value, "CPA auth-file models response");
  if (!Array.isArray(root.models) || root.models.length > MAX_MODELS) throw new ManagedCodexSnapshotFailure("CPA auth-file models response has an invalid schema");
  const models = root.models.map((item) => publicText(object(item, "CPA auth-file model").id, "CPA auth-file model ID")).sort(compare);
  if (new Set(models).size !== models.length) throw new ManagedCodexSnapshotFailure("CPA auth-file models response has duplicate models");
  return { auth_id: authId, provider: "codex", registered_models: models };
}
function authDigest(auths: readonly CapturedAuth[]): string {
  return sha256(Buffer.from(`${JSON.stringify(auths)}\n`));
}
function sameAuths(left: readonly CapturedAuth[], right: readonly CapturedAuth[]): boolean { return JSON.stringify(left) === JSON.stringify(right); }

/** Pure sealing step. Network collection must perform the pre/post observations around it. */
export function buildManagedCodexModelSnapshot(configRaw: Buffer, before: readonly CapturedAuth[], models: readonly CapturedModels[], after: readonly CapturedAuth[], verifiedModels: readonly CapturedModels[]): Artifacts {
  if (configRaw.length > MAX_CONFIG_BYTES || !sameAuths(before, after) || JSON.stringify(models) !== JSON.stringify(verifiedModels)) throw new ManagedCodexSnapshotFailure("CPA managed Codex registry changed during snapshot capture");
  const activeIds = before.map((item) => item.id);
  if (models.length !== activeIds.length || models.some((item, index) => item.auth_id !== activeIds[index] || item.provider !== "codex")) throw new ManagedCodexSnapshotFailure("CPA managed Codex model snapshot has incomplete auth coverage");
  const snapshot = Buffer.from(`${JSON.stringify({ version: 1, source_config_sha256: sha256(configRaw), auth_files_sha256: authDigest(before), auth_models: models })}\n`);
  return { snapshot, counts: { auth_file_count: before.length, registered_model_count: models.reduce((sum, item) => sum + item.registered_models.length, 0), source_config_sha256: sha256(configRaw), auth_files_sha256: authDigest(before), model_snapshot_sha256: sha256(snapshot) } };
}

function managementBase(raw: string, allowHttpLoopback: boolean): URL {
  let url: URL;
  try { url = new URL(raw); } catch { throw new ManagedCodexSnapshotFailure("CPA management API base URL is invalid"); }
  const loopback = ["localhost", "127.0.0.1", "::1", "[::1]"].includes(url.hostname);
  if ((!allowHttpLoopback && url.protocol !== "https:") || (allowHttpLoopback && url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) || !url.hostname || url.username || url.password || url.search || url.hash || url.pathname.replace(/\/+$/u, "") !== "/v0/management") throw new ManagedCodexSnapshotFailure("CPA management API base URL is invalid");
  url.pathname = "/v0/management/"; return url;
}
function requestJson(url: URL, token: string): Promise<unknown> {
  return new Promise((resolveRequest, rejectRequest) => {
    const callback = (response: import("node:http").IncomingMessage) => {
      const chunks: Buffer[] = []; let length = 0;
      response.on("data", (chunk: Buffer) => { length += chunk.length; if (length <= MAX_RESPONSE_BYTES) chunks.push(chunk); });
      response.on("error", () => rejectRequest(new ManagedCodexSnapshotFailure("CPA management request failed")));
      response.on("end", () => {
        if (length > MAX_RESPONSE_BYTES || response.statusCode !== 200) { rejectRequest(new ManagedCodexSnapshotFailure("CPA management request was rejected")); return; }
        try { resolveRequest(parseJson(Buffer.concat(chunks), "CPA management response")); }
        catch (error) { rejectRequest(error); }
      });
    };
    const request = url.protocol === "https:"
      ? httpsRequest(url, { method: "GET", headers: { authorization: `Bearer ${token}`, accept: "application/json" } }, callback)
      : httpRequest(url, { method: "GET", headers: { authorization: `Bearer ${token}`, accept: "application/json" } }, callback);
    request.setTimeout(15_000, () => request.destroy(new ManagedCodexSnapshotFailure("CPA management request timed out")));
    request.on("error", () => rejectRequest(new ManagedCodexSnapshotFailure("CPA management request failed")));
    request.end();
  });
}
async function collectAuths(base: URL, token: string): Promise<CapturedAuth[]> { return snapshotAuths(await requestJson(new URL("auth-files", base), token)); }
async function collectModels(base: URL, token: string, auths: readonly CapturedAuth[]): Promise<CapturedModels[]> {
  const result: CapturedModels[] = [];
  for (const auth of auths) {
    const url = new URL("auth-files/models", base); url.searchParams.set("name", auth.id);
    result.push(snapshotModels(auth.id, await requestJson(url, token)));
  }
  return result;
}

type OutputTarget = Readonly<{ target: string; descriptor: number }>;
function openOutput(path: string): OutputTarget {
  if (!isAbsolute(path) || resolve(path) !== path || path === parse(path).root || path.includes("\0")) throw new ManagedCodexSnapshotFailure("snapshot output path is invalid");
  const directory = dirname(path), root = parse(directory).root;
  let current = root;
  for (const piece of relative(root, directory).split(sep).filter(Boolean)) {
    current = resolve(current, piece); const stat = lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new ManagedCodexSnapshotFailure("snapshot output directory is unsafe");
  }
  let descriptor: number | undefined;
  try {
    descriptor = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const stat = fstatSync(descriptor);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0 || (process.geteuid?.() !== undefined && stat.uid !== process.geteuid())) throw new Error("unsafe");
    const target = `/proc/self/fd/${descriptor}/${basename(path)}`;
    try { lstatSync(target); throw new ManagedCodexSnapshotFailure("snapshot output path already exists"); }
    catch (error) { if (error instanceof ManagedCodexSnapshotFailure) throw error; if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw new ManagedCodexSnapshotFailure("snapshot output path is unsafe"); }
    return { target, descriptor };
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    if (error instanceof ManagedCodexSnapshotFailure) throw error;
    throw new ManagedCodexSnapshotFailure("snapshot output directory is unsafe");
  }
}
function publish(output: OutputTarget, value: Buffer): void {
  const temporary = `${output.target}.tmp-${randomBytes(16).toString("hex")}`; let descriptor: number | undefined;
  try {
    descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    let offset = 0; while (offset < value.length) { const written = writeSync(descriptor, value, offset); if (written <= 0) throw new Error("short write"); offset += written; }
    fsyncSync(descriptor); closeSync(descriptor); descriptor = undefined; linkSync(temporary, output.target); unlinkSync(temporary); fsyncSync(output.descriptor);
  } catch {
    if (descriptor !== undefined) closeSync(descriptor);
    try { unlinkSync(temporary); } catch {}
    throw new ManagedCodexSnapshotFailure("snapshot output could not be written safely");
  }
}

type Options = Readonly<{ managementBase: string; tokenFile: string; configFile: string; output: string; allowHttpLoopback: boolean }>;
type MutableOptions = { managementBase?: string; tokenFile?: string; configFile?: string; output?: string; allowHttpLoopback: boolean };
function options(argv: readonly string[]): Options {
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write("usage: export-cpa-managed-codex-model-snapshot --management-api-base-url URL --management-token-file FILE --source-config-file FILE --output FILE [--allow-http-loopback]\n"); process.exit(0);
  }
  const fields: Record<string, "managementBase" | "tokenFile" | "configFile" | "output"> = { "--management-api-base-url": "managementBase", "--management-token-file": "tokenFile", "--source-config-file": "configFile", "--output": "output" };
  const parsed: MutableOptions = { allowHttpLoopback: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (argument === "--allow-http-loopback") { if (parsed.allowHttpLoopback) throw new ManagedCodexSnapshotFailure("arguments are invalid"); parsed.allowHttpLoopback = true; continue; }
    const field = fields[argument], value = argv[index + 1];
    if (!field || !value || value.startsWith("--") || parsed[field] !== undefined) throw new ManagedCodexSnapshotFailure("arguments are invalid");
    parsed[field] = value; index += 1;
  }
  if (!parsed.managementBase || !parsed.tokenFile || !parsed.configFile || !parsed.output) throw new ManagedCodexSnapshotFailure("required arguments are missing");
  return parsed as Options;
}

export async function run(argv = process.argv.slice(2)): Promise<Readonly<Record<string, number | string>>> {
  const selected = options(argv), base = managementBase(selected.managementBase, selected.allowHttpLoopback);
  let token = readOwnerOnly(selected.tokenFile, "CPA management token", 16 * 1024), config = readOwnerOnly(selected.configFile, "CPA source config", MAX_CONFIG_BYTES), output: OutputTarget | undefined;
  try {
    const tokenText = publicText(decode(token, "CPA management token"), "CPA management token", 16 * 1024);
    const before = await collectAuths(base, tokenText), models = await collectModels(base, tokenText, before), after = await collectAuths(base, tokenText), verifiedModels = await collectModels(base, tokenText, after);
    const verifiedConfig = readOwnerOnly(selected.configFile, "CPA source config", MAX_CONFIG_BYTES);
    try { if (!verifiedConfig.equals(config)) throw new ManagedCodexSnapshotFailure("CPA source config changed during snapshot capture"); }
    finally { verifiedConfig.fill(0); }
    const artifacts = buildManagedCodexModelSnapshot(config, before, models, after, verifiedModels);
    output = openOutput(selected.output); publish(output, artifacts.snapshot); return artifacts.counts;
  } finally {
    token.fill(0); config.fill(0); if (output) closeSync(output.descriptor);
  }
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  run().then((result) => process.stdout.write(`${JSON.stringify(result)}\n`)).catch(() => { process.stderr.write("CPA managed Codex model snapshot stopped\n"); process.exitCode = 2; });
}
