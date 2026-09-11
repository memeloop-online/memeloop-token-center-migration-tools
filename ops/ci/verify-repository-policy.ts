import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const ignoredDirectories = new Set([".git", "dist", "node_modules"]);
const forbiddenScriptExtensions = new Set([".bash", ".cjs", ".js", ".mjs", ".ps1", ".py", ".sh", ".zsh"]);
const forbiddenSecretPatterns: readonly [string, RegExp][] = [
  ["private key", /-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----/u],
  ["GitHub token", /\bgh[oprsu]_[A-Za-z0-9]{20,}\b/u],
  ["live MTC credential", /\bmtc_[A-Za-z0-9_-]{20,}\b/u],
];
const forbiddenPublicEnvironmentPatterns: readonly [string, RegExp][] = [
  ["internal service domain", /\b(?:token|token-operator)\.k3s\.[a-z0-9.-]+\b/iu],
  ["retired environment name", /\bmemeloop-token-center-(?:api[0-9]+-)?(?:trial|dev)\b/iu],
  ["environment-specific source workload", /\bcliproxyapi[-](?:auth|[0-9]+)\b/iu],
  ["host-specific absolute path", /\/(?:home|Users|root)\//u],
  ["Kubernetes Secret retrieval command", /\bkubectl\b[^\n]{0,160}\bget\s+secrets?\b/iu],
  ["Secret decoding command", /\bjsonpath\b[^\n]{0,160}\bbase64\s+(?:--decode|-d)\b/iu],
  ["internal route alias", new RegExp([["c", "sil"].join(""), ["dong", "wu"].join("")].join("|"), "iu")],
  ["internal failure-domain alias", new RegExp([["hub", "ble"].join(""), ["xuan", "yuan"].join("")].join("|"), "iu")],
];
const emailPattern = /\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b/giu;

function walk(directory: string): string[] {
  const paths: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) paths.push(...walk(path));
    else if (entry.isFile()) paths.push(path);
    else throw new Error(`non-regular repository entry: ${relative(root, path)}`);
  }
  return paths;
}

const violations: string[] = [];
for (const path of walk(root)) {
  const repositoryPath = relative(root, path);
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    violations.push(`${repositoryPath}: must be a regular file`);
    continue;
  }
  const extension = extname(path).toLowerCase();
  if (forbiddenScriptExtensions.has(extension)) {
    violations.push(`${repositoryPath}: scripts must use TypeScript`);
  }
  const body = readFileSync(path, "utf8");
  if (body.startsWith("#!") && !(path.endsWith(".ts") && body.startsWith("#!/usr/bin/env node\n"))) {
    violations.push(`${repositoryPath}: unsupported script entrypoint`);
  }
  if ((extension === ".yaml" || extension === ".yml") && /^kind:\s*Secret\s*$/mu.test(body)) {
    violations.push(`${repositoryPath}: Kubernetes Secret manifests are forbidden`);
  }
  for (const [label, pattern] of forbiddenSecretPatterns) {
    if (pattern.test(body)) violations.push(`${repositoryPath}: possible ${label}`);
  }
  for (const [label, pattern] of forbiddenPublicEnvironmentPatterns) {
    if (pattern.test(body)) violations.push(`${repositoryPath}: possible ${label}`);
  }
  for (const match of body.matchAll(emailPattern)) {
    const domain = match[1]?.toLowerCase().replace(/\.json$/u, "");
    if (domain !== "example.test") {
      violations.push(`${repositoryPath}: non-fixture email address`);
      break;
    }
  }
}

if (violations.length > 0) {
  process.stderr.write(`${violations.join("\n")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write("repository policy passed\n");
}
