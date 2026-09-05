#!/usr/bin/env node
/** Fail if CPA upstream fixtures appear to contain non-synthetic material. */

import { readFileSync, readdirSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import { parse } from "yaml";

const ROOT = resolve(import.meta.dirname, "../fixtures/cpa-upstreams");
const SENSITIVE_KEYS = new Set([
  "api-key", "api_key", "access_token", "refresh_token", "id_token", "credential", "handle",
]);
const EMAIL = /^[^@\s]+@example\.test$/;
const FORBIDDEN_PATTERNS = [
  /\bgh[opusr]_[A-Za-z0-9]{16,}\b/,
  /\bsk-[A-Za-z0-9_-]{16,}\b/,
  /\beyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/,
];

function filesBelow(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? filesBelow(path) : entry.isFile() ? [path] : [];
  }).sort();
}

function inspect(value: unknown, key?: string): void {
  if (Array.isArray(value)) {
    for (const child of value) inspect(child, key);
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [childKey, childValue] of Object.entries(value)) inspect(childValue, childKey);
    return;
  }
  if (typeof value !== "string") return;
  if (key && SENSITIVE_KEYS.has(key) && !(value.startsWith("fixture-only-") || value.startsWith("Fixture"))) {
    throw new Error("fixture contains a non-synthetic sensitive value");
  }
  if ((key === "email" || key === "login") && !EMAIL.test(value)) {
    throw new Error("fixture contains a non-example email address");
  }
  if ((key === "base-url" || key === "base_url") && !value.includes(".example.test")) {
    throw new Error("fixture contains a non-example upstream URL");
  }
  if (key === "proxy-url") {
    let proxy: URL;
    try { proxy = new URL(value); } catch { throw new Error("fixture contains an invalid proxy URL"); }
    if (proxy.protocol !== "socks5:" || proxy.hostname !== "fixture-proxy.internal" || proxy.username || proxy.password) {
      throw new Error("fixture contains a non-synthetic proxy URL");
    }
  }
}

export function main(): void {
  const files = filesBelow(ROOT);
  if (files.length === 0) throw new Error("CPA upstream fixture set is empty");
  for (const path of files) {
    const raw = readFileSync(path, "utf8");
    if (FORBIDDEN_PATTERNS.some((pattern) => pattern.test(raw))) {
      throw new Error("fixture contains credential-like material");
    }
    const extension = extname(path);
    if (extension !== ".json" && extension !== ".yaml" && extension !== ".yml") {
      throw new Error("fixture set contains an unsupported file");
    }
    inspect(extension === ".json" ? JSON.parse(raw) : parse(raw, { maxAliasCount: 0, uniqueKeys: true }));
  }
  process.stdout.write(`CPA upstream fixture sanitizer: PASS files=${files.length}\n`);
}

try { main(); } catch (error) {
  process.stderr.write(`CPA upstream fixture sanitizer: FAIL ${error instanceof Error ? error.message : "unknown error"}\n`);
  process.exitCode = 1;
}
