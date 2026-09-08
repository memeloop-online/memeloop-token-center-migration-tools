import { cpSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { releaseEntrypoints } from './release-entrypoints.ts';

const repository = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const output = resolve(repository, 'dist/release');
const commands = resolve(output, 'commands');
rmSync(output, { recursive: true, force: true });
await build({
  absWorkingDir: repository,
  entryPoints: Object.fromEntries(Object.entries(releaseEntrypoints)),
  bundle: true,
  platform: 'node',
  target: 'node24.18',
  format: 'esm',
  // yaml's Node export is CommonJS. Bundle its maintained ESM distribution so
  // the importer remains a native ESM executable without a createRequire shim.
  alias: { yaml: resolve(repository, 'node_modules/yaml/browser/index.js') },
  outExtension: { '.js': '.mjs' },
  outdir: commands,
  logLevel: 'info',
});
mkdirSync(resolve(commands, 'sql/cpamp'), { recursive: true });
cpSync(resolve(repository, 'ops/sql/cpamp'), resolve(commands, 'sql/cpamp'), { recursive: true, force: false });
