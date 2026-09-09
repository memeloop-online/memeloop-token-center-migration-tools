#!/usr/bin/env node
/**
 * Read and seal the exact post-replay native route state. This command has no
 * mutation path: it only calls the target control-plane list endpoints.
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
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { basename, dirname, isAbsolute, parse, relative, resolve, sep } from "node:path";
import { invokedAsEntrypoint } from "../lib/invoked-as-entrypoint.ts";
import { parseStrictJson } from "../lib/strict-json.ts";
import {
  completeSinglePage,
  parseLiveRoute,
  parseManifest,
  parseSourceInventory,
  parseUpstreamInventory,
  readProtected,
  type LiveRoute,
  type RouteSpec,
} from "./import-cpa-model-routes.ts";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TOKEN = /^[^\0\r\n]{1,16384}$/;
const MAX_BYTES = 8 * 1024 * 1024;

type JsonObject = Record<string, unknown>;
type TargetAccount = Readonly<{ id: string; driver: string; status: string; updatedAt: number }>;
type CandidateBinding = Readonly<{ accountId: string; sourceStableId: string }>;
type ReceiptRoute = Readonly<{
  routeId: string;
  publicModel: string;
  upstreamModel: string;
  protocol: "openai" | "anthropic";
  priority: number;
  enabled: true;
  updatedAt: number;
  upstreamAccountIds: readonly string[];
  candidateUpstreamAccountIds: readonly string[];
  candidateSources: readonly CandidateBinding[];
}>;
type TargetRouteReceipt = Readonly<{
  tenant: string;
  sourceDigest: string;
  upstreamDigest: string;
  manifestDigest: string;
  routes: readonly ReceiptRoute[];
}>;
type OutputTarget = Readonly<{ target: string; parentDescriptor: number }>;

export class TargetRouteReceiptExportFailure extends Error {}

const digest = (value: Uint8Array | string): string => createHash("sha256").update(value).digest("hex");
const compare = (left: string, right: string): number => left < right ? -1 : left > right ? 1 : 0;
const same = <T>(left: readonly T[], right: readonly T[]): boolean => left.length === right.length && left.every((value, index) => value === right[index]);

function sourceKey(value: { provider: string; model: string; group: string | null; upstreamPrefix: string | null; protocol: "openai" | "anthropic" }): string {
  return JSON.stringify([value.provider, value.model, value.group, value.upstreamPrefix, value.protocol]);
}

function sameBindings(left: readonly CandidateBinding[], right: readonly CandidateBinding[]): boolean {
  return left.length === right.length && left.every((value, index) => value.accountId === right[index]?.accountId && value.sourceStableId === right[index]?.sourceStableId);
}

function exactSet(left: readonly string[], right: readonly string[]): boolean {
  const sortedLeft = [...left].sort(compare), sortedRight = [...right].sort(compare);
  return new Set(sortedLeft).size === sortedLeft.length && new Set(sortedRight).size === sortedRight.length && same(sortedLeft, sortedRight);
}

function routeMatches(route: LiveRoute, spec: RouteSpec): boolean {
  const candidates = spec.candidates.map((candidate) => candidate.accountId);
  return route.enabled
    && route.publicModel === spec.publicModel
    && route.upstreamModel === spec.upstreamModel
    && route.protocol === spec.protocol
    && route.priority === spec.priority
    && same(route.accountIds, candidates)
    && same(route.candidateAccountIds, candidates)
    && route.includedProviderGroupIds.length === 0
    && route.excludedProviderGroupIds.length === 0
    && route.routeGroupIds.length === 0
    && route.grantedCredentialIds.length === 0
    && route.customModelConfirmed;
}

function retiredDriver(driver: string): boolean {
  return /(?:bridge|legacy|cliproxyapi)/iu.test(driver);
}

function convertFailure(error: unknown): never {
  if (error instanceof TargetRouteReceiptExportFailure) throw error;
  throw new TargetRouteReceiptExportFailure("target route receipt inputs are invalid");
}

/**
 * Pure verification and receipt construction. Candidate source identities are
 * copied only after all live account, pool, and route fences have matched.
 */
export function buildTargetRouteReceipt(
  sourceRaw: Buffer,
  upstreamRaw: Buffer,
  manifestRaw: Buffer,
  liveRoutes: readonly LiveRoute[],
  liveAccounts: readonly TargetAccount[],
): TargetRouteReceipt {
  try {
    const sourceDigest = digest(sourceRaw), upstreamDigest = digest(upstreamRaw), manifestDigest = digest(manifestRaw);
    const source = parseSourceInventory(sourceRaw), upstream = parseUpstreamInventory(upstreamRaw);
    if (upstream.version !== 2) throw new TargetRouteReceiptExportFailure("target route receipt requires a version 2 upstream inventory");
    const manifest = parseManifest(manifestRaw, sourceDigest, upstreamDigest, source);
    if (manifest.tenant !== upstream.tenant) throw new TargetRouteReceiptExportFailure("reviewed route inputs select different tenants");

    const sourceKeys = source.mappings.map(sourceKey), poolKeys = upstream.candidateSets.map((pool) => sourceKey(pool.source)), manifestKeys = manifest.specs.map((spec) => sourceKey(spec.source));
    if (!exactSet(sourceKeys, poolKeys) || !exactSet(sourceKeys, manifestKeys)) throw new TargetRouteReceiptExportFailure("reviewed route inputs do not provide complete exact candidate coverage");

    const upstreams = new Map(upstream.upstreams.map((account) => [account.accountId, account]));
    const accounts = new Map(liveAccounts.map((account) => [account.id, account]));
    if (accounts.size !== liveAccounts.length) throw new TargetRouteReceiptExportFailure("target upstream response has duplicate accounts");
    if (new Set(liveRoutes.map((route) => route.id)).size !== liveRoutes.length) throw new TargetRouteReceiptExportFailure("target route response has duplicate routes");
    const pools = new Map(upstream.candidateSets.map((pool) => [sourceKey(pool.source), pool]));

    const routes: ReceiptRoute[] = [];
    for (const spec of manifest.specs) {
      const pool = pools.get(sourceKey(spec.source));
      if (!pool || pool.protocol !== spec.protocol || pool.upstreamModel !== spec.upstreamModel || !sameBindings(pool.candidates, spec.candidates)) throw new TargetRouteReceiptExportFailure("reviewed route candidate pool is not exact");
      for (const candidate of spec.candidates) {
        const upstreamAccount = upstreams.get(candidate.accountId), targetAccount = accounts.get(candidate.accountId);
        if (!upstreamAccount
          || upstreamAccount.sourceStableId !== candidate.sourceStableId
          || upstreamAccount.sourceProvider !== spec.source.provider
          || retiredDriver(upstreamAccount.driver)
          || !targetAccount
          || targetAccount.driver !== upstreamAccount.driver
          || targetAccount.status !== upstreamAccount.status
          || targetAccount.updatedAt !== upstreamAccount.updatedAt) {
          throw new TargetRouteReceiptExportFailure("reviewed route candidate binding is stale, retired, or conflicting");
        }
      }

      const collisions = liveRoutes.filter((route) => route.publicModel === spec.publicModel && route.protocol === spec.protocol && route.priority === spec.priority);
      if (collisions.length !== 1 || !routeMatches(collisions[0]!, spec)) throw new TargetRouteReceiptExportFailure("target route does not exactly match its reviewed replay");
      const route = collisions[0]!;
      if (spec.existing.action === "update" && route.id !== spec.existing.routeId) throw new TargetRouteReceiptExportFailure("target route identifier differs from the reviewed update");
      routes.push({
        routeId: route.id,
        publicModel: route.publicModel,
        upstreamModel: route.upstreamModel,
        protocol: spec.protocol,
        priority: route.priority,
        enabled: true,
        updatedAt: route.updatedAt,
        upstreamAccountIds: route.accountIds,
        candidateUpstreamAccountIds: route.candidateAccountIds,
        candidateSources: spec.candidates.map((candidate) => ({ accountId: candidate.accountId, sourceStableId: candidate.sourceStableId })),
      });
    }
    if (new Set(routes.map((route) => route.routeId)).size !== routes.length) throw new TargetRouteReceiptExportFailure("reviewed source mappings converge on one target route");
    routes.sort((left, right) => compare(left.routeId, right.routeId));
    return { tenant: upstream.tenant, sourceDigest, upstreamDigest, manifestDigest, routes };
  } catch (error) {
    return convertFailure(error);
  }
}

export function encodeTargetRouteReceipt(receipt: TargetRouteReceipt): Buffer {
  return Buffer.from(`${JSON.stringify({
    version: 1,
    tenant_external_id: receipt.tenant,
    source_inventory_sha256: receipt.sourceDigest,
    upstream_inventory_sha256: receipt.upstreamDigest,
    reviewed_route_manifest_sha256: receipt.manifestDigest,
    routes: receipt.routes.map((route) => ({
      route_id: route.routeId,
      public_model: route.publicModel,
      upstream_model: route.upstreamModel,
      protocol: route.protocol,
      priority: route.priority,
      enabled: route.enabled,
      updated_at: route.updatedAt,
      upstream_account_ids: route.upstreamAccountIds,
      candidate_upstream_account_ids: route.candidateUpstreamAccountIds,
      candidate_sources: route.candidateSources.map((candidate) => ({ upstream_account_id: candidate.accountId, source_stable_id: candidate.sourceStableId })),
    })),
  })}\n`);
}

function targetText(value: unknown): string {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0 || Buffer.byteLength(value) > 500 || /[\0\r\n]/.test(value)) throw new TargetRouteReceiptExportFailure("target upstream response is invalid");
  return value;
}

function targetInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0 || Number(value) > 1_000_000_000_000_000) throw new TargetRouteReceiptExportFailure("target upstream response is invalid");
  return Number(value);
}

function parseTargetAccount(value: unknown): TargetAccount {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TargetRouteReceiptExportFailure("target upstream response is invalid");
  const item = value as JsonObject;
  const id = targetText(item["id"]);
  if (!UUID.test(id)) throw new TargetRouteReceiptExportFailure("target upstream response is invalid");
  return { id, driver: targetText(item["driver"]), status: targetText(item["status"]), updatedAt: targetInteger(item["updated_at"]) };
}

function parseTargetResponse(raw: Buffer): unknown {
  try { return parseStrictJson(new TextDecoder("utf-8", { fatal: true }).decode(raw)); }
  catch { throw new TargetRouteReceiptExportFailure("target API response is not strict UTF-8 JSON"); }
}

class ReadOnlyTarget {
  private readonly base: URL;
  private readonly token: Buffer;

  constructor(base: URL, token: Buffer) {
    this.base = base;
    this.token = token;
  }

  private async request(path: string): Promise<unknown> {
    const url = new URL(path, this.base);
    return await new Promise((resolveRequest, rejectRequest) => {
      const transport = url.protocol === "https:" ? httpsRequest : httpRequest;
      const request = transport(url, {
        method: "GET",
        headers: { authorization: `Bearer ${this.token.toString("utf8")}`, accept: "application/json" },
      }, (response) => {
        const parts: Buffer[] = [];
        let bytes = 0;
        response.on("data", (part: Buffer) => {
          bytes += part.length;
          if (bytes > MAX_BYTES) request.destroy(new TargetRouteReceiptExportFailure("target response exceeds the size limit"));
          else parts.push(part);
        });
        response.on("error", () => rejectRequest(new TargetRouteReceiptExportFailure("target API request failed")));
        response.on("end", () => {
          const raw = Buffer.concat(parts);
          if (!response.statusCode || response.statusCode < 200 || response.statusCode > 299) {
            raw.fill(0);
            rejectRequest(new TargetRouteReceiptExportFailure("target API request failed"));
            return;
          }
          try { resolveRequest(parseTargetResponse(raw)); }
          catch (error) { rejectRequest(error); }
          finally { raw.fill(0); }
        });
      });
      request.on("error", () => rejectRequest(new TargetRouteReceiptExportFailure("target API request failed")));
      request.setTimeout(30_000, () => request.destroy());
      request.end();
    });
  }

  async listRoutes(tenant: string): Promise<LiveRoute[]> {
    const result = completeSinglePage(await this.request(`/internal/v1/model-routes?tenant_external_id=${encodeURIComponent(tenant)}&limit=100`), "target route");
    try { return result.map(parseLiveRoute); }
    catch { throw new TargetRouteReceiptExportFailure("target route response is invalid"); }
  }

  async listAccounts(tenant: string): Promise<TargetAccount[]> {
    const result = completeSinglePage(await this.request(`/internal/v1/upstreams?tenant_external_id=${encodeURIComponent(tenant)}&limit=100`), "target upstream");
    return result.map(parseTargetAccount);
  }
}

function safeBase(raw: string, reviewed: string, allowHttp: boolean): URL {
  if (raw !== reviewed) throw new TargetRouteReceiptExportFailure("target API URL differs from the owner-reviewed manifest");
  let target: URL;
  try { target = new URL(raw); }
  catch { throw new TargetRouteReceiptExportFailure("target API URL is invalid"); }
  if (target.username || target.password || target.search || target.hash || target.pathname !== "/") throw new TargetRouteReceiptExportFailure("target API URL is invalid");
  if (target.protocol === "http:" && allowHttp) return target;
  if (target.protocol !== "https:") throw new TargetRouteReceiptExportFailure("HTTP target requires explicit owner-reviewed opt-in");
  return target;
}

function openSafeOutput(path: string): OutputTarget {
  if (!isAbsolute(path) || path !== resolve(path) || path === parse(path).root || path.includes("\0")) throw new TargetRouteReceiptExportFailure("output path must be an absolute normalized path");
  const directory = dirname(path), normalized = resolve(directory), root = parse(normalized).root;
  let current = root;
  for (const part of relative(root, normalized).split(sep).filter(Boolean)) {
    current = resolve(current, part);
    let metadata: ReturnType<typeof lstatSync>;
    try { metadata = lstatSync(current); }
    catch { throw new TargetRouteReceiptExportFailure("output directory is not safely writable"); }
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new TargetRouteReceiptExportFailure("output directory is not safely writable");
  }
  let descriptor: number | undefined;
  try {
    descriptor = openSync(normalized, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || (process.geteuid?.() !== undefined && metadata.uid !== process.geteuid()) || (metadata.mode & 0o022) !== 0) throw new TargetRouteReceiptExportFailure("output directory is not safely writable");
    const target = `/proc/self/fd/${descriptor}/${basename(path)}`;
    try { lstatSync(target); throw new TargetRouteReceiptExportFailure("output path already exists"); }
    catch (error) {
      if (error instanceof TargetRouteReceiptExportFailure) throw error;
      const code = error && typeof error === "object" && "code" in error ? (error as { code?: string }).code : undefined;
      if (code !== "ENOENT") throw new TargetRouteReceiptExportFailure("output path is not safely writable");
    }
    return { target, parentDescriptor: descriptor };
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    return convertFailure(error);
  }
}

function writeAtomicNoOverwrite(output: OutputTarget, content: Buffer): void {
  const temporary = `${output.target}.tmp-${randomBytes(16).toString("hex")}`;
  let descriptor: number | undefined;
  try {
    descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    for (let offset = 0; offset < content.length;) {
      const written = writeSync(descriptor, content, offset, content.length - offset);
      if (written <= 0) throw new TargetRouteReceiptExportFailure("output could not be written safely");
      offset += written;
    }
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    linkSync(temporary, output.target);
    unlinkSync(temporary);
    const metadata = lstatSync(output.target);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o600) throw new TargetRouteReceiptExportFailure("output could not be persisted safely");
    fsyncSync(output.parentDescriptor);
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    try { lstatSync(temporary); unlinkSync(temporary); } catch {}
    convertFailure(error);
  }
}

type Options = Readonly<{
  source?: string;
  upstream?: string;
  manifest?: string;
  target?: string;
  token?: string;
  output?: string;
  allowHttpTarget: boolean;
}>;

function options(argv: readonly string[]): Options {
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write("usage: export-cpa-target-route-receipt --source-inventory-file FILE --upstream-inventory-file FILE --reviewed-route-manifest-file FILE --target-api-base-url URL --service-token-file FILE --receipt-output FILE [--allow-http-target]\\n\\nRead only the exact post-replay target routes and upstreams, then seal a digest-bound v1 receipt. HTTP requires an exact owner-reviewed manifest URL.\\n");
    process.exit(0);
  }
  const result: { source?: string; upstream?: string; manifest?: string; target?: string; token?: string; output?: string; allowHttpTarget: boolean } = { allowHttpTarget: false };
  const names: Record<string, "source" | "upstream" | "manifest" | "target" | "token" | "output"> = {
    "--source-inventory-file": "source",
    "--upstream-inventory-file": "upstream",
    "--reviewed-route-manifest-file": "manifest",
    "--target-api-base-url": "target",
    "--service-token-file": "token",
    "--receipt-output": "output",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (argument === "--allow-http-target") {
      if (result.allowHttpTarget) throw new TargetRouteReceiptExportFailure("arguments are invalid");
      result.allowHttpTarget = true;
      continue;
    }
    const field = names[argument], value = argv[index + 1];
    if (!field || !value || value.startsWith("--") || result[field] !== undefined) throw new TargetRouteReceiptExportFailure("arguments are invalid");
    result[field] = value;
    index += 1;
  }
  if (!result.source || !result.upstream || !result.manifest || !result.target || !result.token || !result.output) throw new TargetRouteReceiptExportFailure("required arguments are missing");
  return result;
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  let token: Buffer | undefined;
  let output: OutputTarget | undefined;
  try {
    const selected = options(argv);
    const source = readProtected(selected.source!, "source inventory"), upstream = readProtected(selected.upstream!, "upstream inventory"), manifest = readProtected(selected.manifest!, "reviewed manifest");
    const tokenFile = readProtected(selected.token!, "service token");
    const tokenText = tokenFile.toString("utf8").trim();
    tokenFile.fill(0);
    if (!TOKEN.test(tokenText)) throw new TargetRouteReceiptExportFailure("service token file is invalid");
    token = Buffer.from(tokenText);
    const parsedSource = parseSourceInventory(source), parsedUpstream = parseUpstreamInventory(upstream);
    const parsedManifest = parseManifest(manifest, digest(source), digest(upstream), parsedSource);
    const target = new ReadOnlyTarget(safeBase(selected.target!, parsedManifest.targetBaseUrl, selected.allowHttpTarget), token);
    const [routes, accounts] = await Promise.all([target.listRoutes(parsedUpstream.tenant), target.listAccounts(parsedUpstream.tenant)]);
    const sealed = buildTargetRouteReceipt(source, upstream, manifest, routes, accounts);
    const receipt = encodeTargetRouteReceipt(sealed);
    output = openSafeOutput(selected.output!);
    writeAtomicNoOverwrite(output, receipt);
    process.stdout.write(`${JSON.stringify({ route_count: sealed.routes.length, target_route_receipt_sha256: digest(receipt) })}\n`);
    return 0;
  } catch {
    process.stderr.write("target route receipt export stopped\\n");
    return 2;
  } finally {
    token?.fill(0);
    if (output) closeSync(output.parentDescriptor);
  }
}

if (invokedAsEntrypoint("export-cpa-target-route-receipt", import.meta.url)) process.exitCode = await main();
