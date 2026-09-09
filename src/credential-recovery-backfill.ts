#!/usr/bin/env node
/**
 * Backfill durable recovery envelopes from an owner-reviewed, explicit
 * target-key-identity to original-key mapping. This deliberately has no
 * source-system, model, route, policy, grant, or database integration.
 */

import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { invokedAsEntrypoint } from "../ops/lib/invoked-as-entrypoint.ts";
import { parseStrictJson } from "../ops/lib/strict-json.ts";

const MAX_MAPPING_BYTES = 4 * 1024 * 1024;
const MAX_CA_BYTES = 1024 * 1024;
const MAX_MAPPINGS = 10_000;
const MAX_TOKEN_BYTES = 16 * 1024;
const MAX_RESPONSE_BYTES = 64 * 1024;
const REQUEST_TIMEOUT_MILLIS = 30_000;
const MAX_ATTEMPTS_PER_MAPPING = 2;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ASCII_TOKEN = /^[!-~]{1,8192}$/;
const UTF8 = new TextDecoder("utf-8", { fatal: true });

export class CredentialRecoveryBackfillError extends Error {
  readonly retryable: boolean;

  constructor(message: string, retryable = false) {
    super(message);
    this.retryable = retryable;
  }
}

export type CredentialRecoveryMapping = Readonly<{
  identity: string;
  originalKey: string;
}>;

export type BackfillOptions = Readonly<{
  mappingFile: string;
  apply: boolean;
  targetApiBaseUrl?: string;
  adminTokenFile?: string;
  targetCaFile?: string;
  allowHttpTarget: boolean;
}>;

function fail(message: string): never {
  throw new CredentialRecoveryBackfillError(message);
}

function decodeUtf8(value: Uint8Array, label: string): string {
  try {
    return UTF8.decode(value);
  } catch {
    throw new CredentialRecoveryBackfillError(`${label} is not valid UTF-8`);
  }
}

/**
 * Opens a single-link regular file through O_NOFOLLOW and bounds its contents.
 * Mapping and token inputs must be owner-private. CA material is public but
 * still may not be a symlink or a multiply-linked replacement target.
 */
function readBoundedRegularFile(path: string, label: string, limit: number, ownerPrivate: boolean): Buffer {
  let descriptor: number | undefined;
  let buffer: Buffer | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    const currentUid = process.getuid?.();
    if (!metadata.isFile() || metadata.nlink !== 1) fail(`${label} must be a regular protected file`);
    if (ownerPrivate && ((metadata.mode & 0o077) !== 0 || (currentUid !== undefined && metadata.uid !== currentUid))) {
      fail(`${label} has unsafe access permissions`);
    }
    buffer = Buffer.allocUnsafe(limit + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const read = readSync(descriptor, buffer, offset, buffer.length - offset, null);
      if (read === 0) break;
      offset += read;
    }
    if (offset > limit) fail(`${label} exceeds the allowed size`);
    return Buffer.from(buffer.subarray(0, offset));
  } catch (error) {
    if (error instanceof CredentialRecoveryBackfillError) throw error;
    throw new CredentialRecoveryBackfillError(`${label} is unavailable`);
  } finally {
    buffer?.fill(0);
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function originalKey(value: unknown): string {
  if (typeof value !== "string" || Buffer.byteLength(value) < 16 || Buffer.byteLength(value) > 512 || /[\0\r\n]/.test(value)) {
    fail("identity mapping contains an invalid original key");
  }
  // A lone UTF-16 surrogate would not survive JSON body encoding byte-for-byte.
  if (Buffer.from(value, "utf8").toString("utf8") !== value) fail("identity mapping contains an invalid original key");
  return value;
}

/** Parses only an explicit, duplicate-key-rejecting identity-to-key document. */
export function parseIdentityToOriginalKeyMapping(raw: Buffer): CredentialRecoveryMapping[] {
  let document: unknown;
  try {
    document = parseStrictJson(decodeUtf8(raw, "identity mapping"));
  } catch {
    fail("identity mapping is invalid JSON");
  }
  if (document === null || Array.isArray(document) || typeof document !== "object") fail("identity mapping has an invalid shape");
  const root = document as Record<string, unknown>;
  const rootKeys = Object.keys(root).sort();
  if (rootKeys.length !== 2 || rootKeys[0] !== "format_version" || rootKeys[1] !== "identity_to_original_key" || root.format_version !== 1) {
    fail("identity mapping has an invalid shape");
  }
  const source = root.identity_to_original_key;
  if (source === null || Array.isArray(source) || typeof source !== "object") fail("identity mapping has an invalid shape");
  const entries = Object.entries(source as Record<string, unknown>);
  if (entries.length === 0) fail("identity mapping is empty");
  if (entries.length > MAX_MAPPINGS) fail("identity mapping exceeds the allowed entry count");
  const mappings = entries.map(([identity, key]) => {
    if (!UUID.test(identity)) fail("identity mapping contains an invalid target identity");
    return { identity, originalKey: originalKey(key) };
  });
  mappings.sort((left, right) => left.identity.localeCompare(right.identity));
  return mappings;
}

function readAdminToken(path: string): string {
  const raw = readBoundedRegularFile(path, "admin token file", MAX_TOKEN_BYTES, true);
  try {
    let value = decodeUtf8(raw, "admin token file");
    if (value.endsWith("\r\n")) value = value.slice(0, -2);
    else if (value.endsWith("\n")) value = value.slice(0, -1);
    if (!ASCII_TOKEN.test(value)) fail("admin token file is invalid");
    return value;
  } finally {
    raw.fill(0);
  }
}

function readTargetCa(path: string): Buffer {
  return readBoundedRegularFile(path, "target CA file", MAX_CA_BYTES, false);
}

function normalizedTargetApiBaseUrl(value: string, allowHttp: boolean): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    fail("target API base URL is invalid");
  }
  if (
    !(["https:", ...(allowHttp ? ["http:"] : [])].includes(url.protocol))
    || !url.hostname
    || url.username
    || url.password
    || url.search
    || url.hash
  ) {
    fail("target API base URL is invalid");
  }
  url.pathname = url.pathname.replace(/\/+$/, "");
  return url;
}

function recoveryEndpoint(target: URL, identity: string): string {
  const endpoint = new URL(target.toString());
  endpoint.pathname = `${target.pathname.replace(/\/+$/, "")}/internal/v1/keys/${identity}/credential-recovery`;
  endpoint.search = "";
  endpoint.hash = "";
  return endpoint.toString();
}

function requestRecoveryWrite(endpoint: string, adminToken: string, key: string, ca?: Buffer): Promise<void> {
  const url = new URL(endpoint);
  const body = Buffer.from(JSON.stringify({ key }));
  return new Promise<void>((resolve, reject) => {
    let completed = false;
    let deadline: ReturnType<typeof setTimeout> | undefined;
    const resolveOnce = (): void => {
      if (completed) return;
      completed = true;
      clearTimeout(deadline);
      resolve();
    };
    const rejectOnce = (error: CredentialRecoveryBackfillError): void => {
      if (completed) return;
      completed = true;
      clearTimeout(deadline);
      reject(error);
    };
    const request = (url.protocol === "https:" ? httpsRequest : httpRequest)(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port,
        path: `${url.pathname}${url.search}`,
        method: "PUT",
        timeout: REQUEST_TIMEOUT_MILLIS,
        ca,
        headers: {
          Authorization: `Bearer ${adminToken}`,
          Accept: "application/json",
          "Cache-Control": "no-store",
          "Content-Type": "application/json",
          "Content-Length": body.length,
        },
      },
      (response) => {
        if (response.statusCode !== 204) {
          rejectOnce(new CredentialRecoveryBackfillError("target recovery endpoint rejected a mapping", (response.statusCode ?? 0) >= 500));
          // Do not drain an untrusted, potentially unbounded error response.
          response.destroy();
          return;
        }
        let responseBytes = 0;
        response.on("data", (chunk: Buffer) => {
          responseBytes += chunk.length;
          if (responseBytes > MAX_RESPONSE_BYTES) {
            response.destroy();
            rejectOnce(new CredentialRecoveryBackfillError("target recovery response exceeds the allowed size", true));
          }
        });
        response.on("error", () => rejectOnce(new CredentialRecoveryBackfillError("target recovery request failed", true)));
        response.on("end", () => {
          if (responseBytes === 0) resolveOnce();
          else rejectOnce(new CredentialRecoveryBackfillError("target recovery response is invalid"));
        });
      },
    );
    request.on("timeout", () => request.destroy(new CredentialRecoveryBackfillError("target recovery request timed out", true)));
    request.on("error", (error) => {
      if (error instanceof CredentialRecoveryBackfillError) rejectOnce(error);
      else rejectOnce(new CredentialRecoveryBackfillError("target recovery request failed", true));
    });
    // Socket inactivity alone does not bound DNS/connect or a trickling peer.
    deadline = setTimeout(() => {
      const error = new CredentialRecoveryBackfillError("target recovery request timed out", true);
      rejectOnce(error);
      request.destroy(error);
    }, REQUEST_TIMEOUT_MILLIS);
    request.end(body);
  }).finally(() => body.fill(0));
}

async function storeRecoveryEnvelope(target: URL, adminToken: string, mapping: CredentialRecoveryMapping, ca?: Buffer): Promise<void> {
  const endpoint = recoveryEndpoint(target, mapping.identity);
  let lastError: CredentialRecoveryBackfillError | undefined;
  for (let attempt = 0; attempt < MAX_ATTEMPTS_PER_MAPPING; attempt += 1) {
    try {
      await requestRecoveryWrite(endpoint, adminToken, mapping.originalKey, ca);
      return;
    } catch (error) {
      if (!(error instanceof CredentialRecoveryBackfillError)) throw error;
      lastError = error;
      if (!error.retryable) throw error;
    }
  }
  throw lastError ?? new CredentialRecoveryBackfillError("target recovery request failed");
}

function usage(): string {
  return [
    "usage: credential-recovery-backfill --mapping-file FILE [--apply --target-api-base-url URL --admin-token-file FILE] [options]",
    "",
    "Backfill encrypted credential-recovery envelopes from an explicit mapping (dry-run by default).",
    "",
    "  --mapping-file FILE       owner-private JSON identity-to-original-key mapping",
    "  --apply                   permit fixed recovery-endpoint PUT requests",
    "  --target-api-base-url URL private Token Center control API base URL (apply only)",
    "  --admin-token-file FILE   owner-private keys:write Bearer token file (apply only)",
    "  --target-ca-file FILE     optional private-control CA bundle (apply only)",
    "  --allow-http-target       allow HTTP only for an approved private test hop",
  ].join("\n");
}

/** Parses an intentionally small CLI surface; secrets are never accepted in argv. */
export function parseBackfillArguments(argv: readonly string[]): BackfillOptions {
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write(`${usage()}\n`);
    process.exit(0);
  }
  let mappingFile: string | undefined;
  let targetApiBaseUrl: string | undefined;
  let adminTokenFile: string | undefined;
  let targetCaFile: string | undefined;
  let apply = false;
  let allowHttpTarget = false;
  const valued: Readonly<Record<string, "mapping" | "target" | "token" | "ca">> = {
    "--mapping-file": "mapping",
    "--target-api-base-url": "target",
    "--admin-token-file": "token",
    "--target-ca-file": "ca",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (argument === "--apply") {
      if (apply) fail("duplicate apply flag");
      apply = true;
      continue;
    }
    if (argument === "--allow-http-target") {
      if (allowHttpTarget) fail("duplicate HTTP-target flag");
      allowHttpTarget = true;
      continue;
    }
    const field = valued[argument];
    if (!field) fail("unrecognized argument");
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) fail("a required argument value is missing");
    index += 1;
    if (field === "mapping") {
      if (mappingFile !== undefined) fail("duplicate mapping file");
      mappingFile = value;
    } else if (field === "target") {
      if (targetApiBaseUrl !== undefined) fail("duplicate target API base URL");
      targetApiBaseUrl = value;
    } else if (field === "token") {
      if (adminTokenFile !== undefined) fail("duplicate admin token file");
      adminTokenFile = value;
    } else {
      if (targetCaFile !== undefined) fail("duplicate target CA file");
      targetCaFile = value;
    }
  }
  if (mappingFile === undefined) fail("mapping file is required");
  if (apply) {
    if (targetApiBaseUrl === undefined || adminTokenFile === undefined) fail("apply requires target API URL and admin token file");
  } else if (targetApiBaseUrl !== undefined || adminTokenFile !== undefined || targetCaFile !== undefined || allowHttpTarget) {
    fail("target API options require apply");
  }
  return { mappingFile, apply, targetApiBaseUrl, adminTokenFile, targetCaFile, allowHttpTarget };
}

export async function runCredentialRecoveryBackfill(argv = process.argv.slice(2)): Promise<void> {
  const options = parseBackfillArguments(argv);
  const rawMapping = readBoundedRegularFile(options.mappingFile, "identity mapping file", MAX_MAPPING_BYTES, true);
  let mappings: CredentialRecoveryMapping[];
  try {
    mappings = parseIdentityToOriginalKeyMapping(rawMapping);
  } finally {
    rawMapping.fill(0);
  }
  if (!options.apply) {
    process.stdout.write(`${JSON.stringify({ mode: "dry-run", mapping_count: mappings.length, stored_count: 0 })}\n`);
    return;
  }
  const target = normalizedTargetApiBaseUrl(options.targetApiBaseUrl!, options.allowHttpTarget);
  const adminToken = readAdminToken(options.adminTokenFile!);
  const ca = options.targetCaFile === undefined ? undefined : readTargetCa(options.targetCaFile);
  try {
    let stored = 0;
    for (const mapping of mappings) {
      await storeRecoveryEnvelope(target, adminToken, mapping, ca);
      stored += 1;
    }
    process.stdout.write(`${JSON.stringify({ mode: "apply", mapping_count: mappings.length, stored_count: stored })}\n`);
  } finally {
    ca?.fill(0);
  }
}

if (invokedAsEntrypoint("credential-recovery-backfill", import.meta.url)) {
  runCredentialRecoveryBackfill().catch((error) => {
    const message = error instanceof CredentialRecoveryBackfillError ? error.message : "unexpected operator failure";
    process.stderr.write(`credential recovery backfill failed: ${message}\n`);
    process.exitCode = 2;
  });
}
