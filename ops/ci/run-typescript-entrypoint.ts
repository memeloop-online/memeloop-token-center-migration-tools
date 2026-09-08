#!/usr/bin/env node
/**
 * Extensionless, shebang-compatible entrypoint for a reviewed TypeScript
 * command.  The target remains a .ts file so Node's native type stripping is
 * explicit and no generated JavaScript or shell wrapper is needed.
 */

import { basename } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { releaseEntrypoints } from "./release-entrypoints.ts";

/**
 * @param {string} entrypoint
 * @returns {string | undefined}
 */
export function targetForEntrypoint(entrypoint = "") {
  const source = releaseEntrypoints[entrypoint as keyof typeof releaseEntrypoints];
  return source === undefined ? undefined : basename(source);
}

/**
 * @param {string} entrypoint
 * @param {string[]} argv
 * @param {string} binDirectory
 * @returns {Promise<void>}
 */
export async function dispatch(
  entrypoint = "",
  argv = process.argv,
  binDirectory = "/usr/local/bin",
) {
  const targetName = targetForEntrypoint(entrypoint);
  if (targetName === undefined) {
    process.stderr.write(`unknown TypeScript entrypoint: ${entrypoint}\n`);
    process.exitCode = 64;
    return;
  }
  const target = `${binDirectory}/${targetName}`;
  // Several reviewed commands intentionally guard their main() call by
  // process.argv[1]. Make an explicit import indistinguishable from `node
  // /usr/local/bin/<target>.ts` while preserving all operator arguments.
  if (argv !== process.argv) process.argv = argv;
  argv[1] = target;
  await import(pathToFileURL(target).href);
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && fileURLToPath(import.meta.url) === invokedPath) {
  await dispatch(basename(invokedPath));
}
