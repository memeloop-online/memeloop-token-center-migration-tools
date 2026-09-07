#!/usr/bin/env node
/**
 * Extensionless, shebang-compatible entrypoint for a reviewed TypeScript
 * command.  The target remains a .ts file so Node's native type stripping is
 * explicit and no generated JavaScript or shell wrapper is needed.
 */

import { basename } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const entrypoints = Object.freeze({
  "audit-cpa-migration": "audit-cpa-migration.ts",
  "export-cpa-session-archive-delta": "export-cpa-session-archive-delta.ts",
  "export-cpa-source-route-inventory": "export-cpa-source-route-inventory.ts",
  "finalize-session-archive-delta": "finalize-session-archive-delta.ts",
  "generate-source-identity-key": "generate-source-identity-key.ts",
  "import-cpa-key-policy": "import-cpa-key-policy.ts",
  "import-cpa-model-routes": "import-cpa-model-routes.ts",
  "import-cpa-session-archive": "import-cpa-session-archive.ts",
  "import-cpa-upstreams": "import-cpa-upstreams.ts",
  "stage-protected-inputs": "stage-protected-inputs.ts",
});

/**
 * @param {string} entrypoint
 * @returns {string | undefined}
 */
export function targetForEntrypoint(entrypoint: string): string | undefined {
  return Object.entries(entrypoints).find(([name]) => name === entrypoint)?.[1];
}

/**
 * @param {string} entrypoint
 * @param {string[]} argv
 * @param {string} binDirectory
 * @returns {Promise<void>}
 */
export async function dispatch(
  entrypoint: string,
  argv: string[] = process.argv,
  binDirectory = "/usr/local/bin",
): Promise<void> {
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
