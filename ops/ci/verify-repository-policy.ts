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
}

if (violations.length > 0) {
  process.stderr.write(`${violations.join("\n")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write("repository policy passed\n");
}
