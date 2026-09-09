/**
 * Guard a release CLI's side effect when its implementation is bundled into
 * another release command. esbuild gives bundled modules the outer command's
 * import.meta.url, so URL equality alone would incorrectly start an imported
 * CLI. Require both the reviewed command basename and its actual module URL.
 */

import { basename } from "node:path";
import { pathToFileURL } from "node:url";

const SCRIPT_EXTENSION = /\.(?:ts|[cm]?js)$/u;

export function invokedAsEntrypoint(name: string, moduleUrl: string): boolean {
  const invoked = process.argv[1];
  return invoked !== undefined
    && basename(invoked).replace(SCRIPT_EXTENSION, "") === name
    && pathToFileURL(invoked).href === moduleUrl;
}
