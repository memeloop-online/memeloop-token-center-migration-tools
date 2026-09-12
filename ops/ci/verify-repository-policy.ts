import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { releaseEntrypoints } from "./release-entrypoints.ts";

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
];
const retiredTargetSurfacePatterns: readonly [string, RegExp][] = [
  ["retired provider-specific target endpoint", new RegExp(["internal", "v1", "imports", "cpa", "managed-oauth"].join("/"), "u")],
  ["retired provider-specific write scope", new RegExp(["imports", "cpa", "write"].join(":"), "u")],
];
const emailPattern = /\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b/giu;

function walk(directory: string): string[] {
  const paths: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (ignoredDirectories.has(entry.name)) continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) paths.push(...walk(path));
    else if (entry.isFile()) paths.push(path);
    else throw new Error(`non-regular repository entry: ${relative(root, path)}`);
  }
  return paths;
}

const violations: string[] = [];
for (const retiredName of [["native", "kimi", "import"].join("-"), ["import", "cpa", "upstreams"].join("-")]) {
  if (retiredName in releaseEntrypoints) violations.push(`release registry: retired target command is published: ${retiredName}`);
}
const allowedAuditModules = new Set(["node:crypto", "node:fs", "node:path", "node:url"]);
function localDependencyClosure(entrypoint: string): string[] {
  const seen = new Set<string>();
  const visit = (path: string): void => {
    const normalized = resolve(path);
    if (relative(root, normalized).startsWith("..")) {
      violations.push("sealed source audit: dependency escapes the repository");
      return;
    }
    if (seen.has(normalized)) return;
    seen.add(normalized);
    const body = readFileSync(normalized, "utf8");
    if (/\bimport\s+["'][^"']+["']/u.test(body)) {
      violations.push(`${relative(root, normalized)}: forbidden audit side-effect dependency`);
    }
    for (const match of body.matchAll(/\bfrom\s+["']([^"']+)["']/gu)) {
      const source = match[1]!;
      if (source.startsWith(".")) visit(resolve(dirname(normalized), source));
      else if (!allowedAuditModules.has(source)) {
        violations.push(`${relative(root, normalized)}: forbidden audit package dependency`);
      }
    }
  };
  visit(entrypoint);
  return [...seen];
}

const auditEntrypoint = join(root, "src/sealed-oauth-source-audit.ts");
const auditClosure = localDependencyClosure(auditEntrypoint);
if (!auditClosure.includes(join(root, "src/lib/sealed-source-io.ts"))) {
  violations.push("sealed source audit: neutral I/O dependency is absent");
}
const forbiddenAuditClosureSurface: readonly [string, RegExp][] = [
  ["network module", /node:(?:http|https|net|tls)/u],
  ["dynamic import", /\bimport\s*\(/u],
  ["CommonJS loader", /\brequire\s*\(/u],
  ["dynamic builtin loader", /\bgetBuiltinModule\s*\(/u],
  ["fetch call", /\bfetch\s*\(/u],
  ["remote request helper", /\brequestJson\b/u],
  ["remote apply flag", new RegExp(["--", "apply"].join(""), "u")],
  ["target URL flag", new RegExp(["--", "target", "-api-base-url"].join(""), "u")],
  ["service credential flag", new RegExp(["--", "service", "-token-file"].join(""), "u")],
  ["hard-coded cohort count", /EXPECTED_SOURCE_(?:ACCOUNTS|POLICIES|GRANTS)/u],
];
for (const path of auditClosure) {
  const body = readFileSync(path, "utf8");
  for (const [label, pattern] of forbiddenAuditClosureSurface) {
    if (pattern.test(body)) violations.push(`${relative(root, path)}: forbidden audit dependency ${label}`);
  }
}
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
  for (const [label, pattern] of retiredTargetSurfacePatterns) {
    if (pattern.test(body)) violations.push(`${repositoryPath}: possible ${label}`);
  }
  for (const match of body.matchAll(emailPattern)) {
    const domain = match[1]?.toLowerCase().replace(/(?:-secondary)?\.json$/u, "");
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
