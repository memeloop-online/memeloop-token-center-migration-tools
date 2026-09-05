import { cpSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const repository = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const output = resolve(repository, 'dist/operator-scripts');
rmSync(output, { recursive: true, force: true });
await build({
  absWorkingDir: repository,
  entryPoints: [
    'ops/migrate-cpamp.ts',
    'ops/audit-cpa-migration.ts',
    'ops/import-cpa-session-archive.ts',
    'ops/legacy-credentials/attach-legacy-cpa-credentials.ts',
    'ops/legacy-policy/import-cpa-key-policy.ts',
    'ops/legacy-routes/import-cpa-model-routes.ts',
    'ops/cpa-upstreams/import-cpa-upstreams.ts',
    'ops/cpa-upstreams/generate-source-identity-key.ts',
    'ops/export-cpa-session-archive-delta.ts',
    'ops/api2-target-rollback.ts',
  ],
  bundle: true,
  platform: 'node',
  target: 'node24.18',
  format: 'esm',
  // yaml's Node export is CommonJS. Bundle its maintained ESM distribution so
  // the importer remains a native ESM executable without a createRequire shim.
  alias: { yaml: resolve(repository, 'node_modules/yaml/browser/index.js') },
  outExtension: { '.js': '.mjs' },
  outdir: output,
  logLevel: 'info',
});
mkdirSync(resolve(output, 'sql/cpamp'), { recursive: true });
cpSync(resolve(repository, 'ops/sql/cpamp'), resolve(output, 'sql/cpamp'), { recursive: true, force: false });
