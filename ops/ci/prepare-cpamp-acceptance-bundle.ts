import { chmodSync, copyFileSync, existsSync, lstatSync, mkdirSync, readdirSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, join, parse, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function fail(message: string): never { throw new Error(message); }
const repository = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const target = process.argv[2] ?? fail('usage: node prepare-cpamp-acceptance-bundle.ts <absolute-empty-directory>');
if (!isAbsolute(target)) fail('acceptance bundle target must be absolute');
const name = parse(target).base;
if (name === '' || name === '.' || name === '..') fail('invalid acceptance bundle directory name');
const parent = dirname(target);
if (!existsSync(parent) || realpathSync(parent) !== parent) fail('acceptance bundle parent must be an existing canonical path without symlinks');
if (existsSync(target)) {
  const stat = lstatSync(target);
  if (stat.isSymbolicLink() || !stat.isDirectory()) fail('acceptance bundle target must be a non-symlink directory');
  if (readdirSync(target).length !== 0) fail('acceptance bundle target must be empty');
} else mkdirSync(target, { mode: 0o700 });
chmodSync(target, 0o700);

function copyRegular(source: string, destination: string, mode: number): void {
  const stat = lstatSync(source);
  if (!stat.isFile() || stat.isSymbolicLink()) fail(`required CPAMP acceptance asset is not a regular non-symlink file: ${source}`);
  const output = join(target, destination);
  copyFileSync(source, output);
  chmodSync(output, mode);
}

copyRegular(join(repository, 'tests/ops/cpamp-import-postgres-acceptance.test.ts'), 'cpamp-import-postgres-acceptance.test.ts', 0o444);
copyRegular(join(repository, 'ops/migrate-cpamp.ts'), 'migrate-cpamp.ts', 0o444);
copyRegular(join(repository, 'tests/fixtures/cpamp/initial.sql'), 'initial.sql', 0o444);
mkdirSync(join(target, 'sql'), { mode: 0o700 });
mkdirSync(join(target, 'sql/cpamp'), { mode: 0o700 });
for (const sql of [
  'prepare.sql', 'evaluate.sql', 'apply.sql', 'correct-plan.sql',
  'correct.sql', 'correct-rebuild.sql', 'reset.sql',
]) {
  copyRegular(join(repository, 'ops/sql/cpamp', sql), join('sql/cpamp', sql), 0o444);
}
chmodSync(join(target, 'sql/cpamp'), 0o555);
chmodSync(join(target, 'sql'), 0o555);
for (const migration of [
  '0001_initial', '0002_query_indexes', '0004_request_events', '0005_generation_jobs',
  '0018_model_price_tiers', '0019_session_archive_import', '0021_request_locators',
  '0022_budget_rollups', '0023_generation_daily_aggregates', '0024_request_stats_rollups',
  '0027_cpamp_source_digests',
]) {
  const postgres = join(repository, 'migrations/postgres', `${migration}.sql`);
  const common = join(repository, 'migrations/common', `${migration}.sql`);
  copyRegular(existsSync(postgres) ? postgres : common, `${migration}.sql`, 0o444);
}
chmodSync(target, 0o555);
