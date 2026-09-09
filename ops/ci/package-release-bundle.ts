/** Produce a checked release manifest for the dependency-bundled commands. */

import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { releaseEntrypointNames, releaseEntrypoints } from "./release-entrypoints.ts";
import { verifiedArchiveRuntime } from "../lib/session-archive-runtime.ts";

const repository = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const releaseDirectory = resolve(repository, "dist/release");
const commandsDirectory = resolve(releaseDirectory, "commands");
const SHA256 = /^[0-9a-f]{40}$/;

function digest(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function regularFile(path: string): void {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`release artifact is not a regular file: ${relative(releaseDirectory, path)}`);
}

function files(directory: string): string[] {
  const result: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) result.push(...files(path));
    else if (entry.isFile() && !entry.isSymbolicLink()) result.push(path);
    else throw new Error(`release artifact has an unsupported entry: ${relative(releaseDirectory, path)}`);
  }
  return result;
}

function releasePath(path: string): string {
  const pathInRelease = relative(releaseDirectory, path);
  if (!pathInRelease || pathInRelease.startsWith(`..${sep}`) || pathInRelease === "..") throw new Error("release artifact path escapes the release directory");
  return pathInRelease.split(sep).join("/");
}

function revision(): string {
  const value = process.env.GITHUB_SHA;
  if (value === undefined || !SHA256.test(value)) throw new Error("GITHUB_SHA must be the verified 40-character revision");
  return value;
}

const commandFiles = releaseEntrypointNames.map((name) => {
  const path = resolve(commandsDirectory, `${name}.mjs`);
  regularFile(path);
  return { name, source: releaseEntrypoints[name], path: releasePath(path), sha256: digest(path) };
});
const expected = new Set(commandFiles.map((entry) => entry.path));
const runtimeFiles = ["import-cpa-session-archive", "compatibility.json", "source.tar"]
  .map((name) => resolve(commandsDirectory, "runtime", name));
verifiedArchiveRuntime(runtimeFiles[0]!);
const runtimePaths = new Set(runtimeFiles.map(releasePath));
for (const path of files(commandsDirectory)) {
  const packaged = releasePath(path);
  if (!expected.has(packaged) && !runtimePaths.has(packaged) && !packaged.startsWith("commands/sql/cpamp/")) throw new Error(`release artifact contains an unregistered file: ${packaged}`);
}

const assets = files(resolve(commandsDirectory, "sql", "cpamp")).map((path) => ({ path: releasePath(path), sha256: digest(path) }));
if (assets.length === 0) throw new Error("release artifact is missing CPAMP SQL inputs");
assets.push(...runtimeFiles.map((path) => ({ path: releasePath(path), sha256: digest(path) })));

const manifest = {
  format_version: 1,
  repository: "memeloop-online/memeloop-token-center-migration-tools",
  revision: revision(),
  node_version: "24.18.0",
  commands: commandFiles,
  assets,
};
writeFileSync(resolve(releaseDirectory, "release-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, { encoding: "utf8", mode: 0o644, flag: "wx" });
