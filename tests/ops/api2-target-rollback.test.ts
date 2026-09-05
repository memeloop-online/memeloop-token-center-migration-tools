import assert from 'node:assert/strict';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { repository } from './contract-helpers.ts';

const evidence = 'a'.repeat(64);
const windowId = 'window-2026-08-28';

type RunResult = { status: number | null; stdout: string; stderr: string; error?: Error };

function runTool(workspace: string, args: string[], extraEnv: NodeJS.ProcessEnv = {}): RunResult {
  const result = spawnSync(process.execPath, [join(repository, 'ops/api2-target-rollback.ts'), ...args], {
    cwd: workspace,
    env: { ...process.env, PATH: `${join(workspace, 'bin')}:${process.env.PATH ?? ''}`, ...extraEnv },
    encoding: 'utf8',
    shell: false,
  });
  assert.equal(result.error, undefined);
  return result as RunResult;
}

function expectSuccess(result: RunResult): void {
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
}

function common(receipt: string): string[] {
  return ['--window-id', windowId, '--quiesce-evidence-sha256', evidence, '--source-failure-domain-id', 'cluster:hubble/api2', '--backup-failure-domain-id', 'object-store:xuanyuan', '--receipt', receipt];
}

function remoteBackup(workspace: string, prefix = `rollback/${windowId}/postgres`): { args: string[]; env: NodeJS.ProcessEnv } {
  return {
    args: ['--backup-alias', 'backup', '--backup-bucket', 'rollback-bucket', '--backup-prefix', prefix],
    env: { FAKE_MC_STATE: join(workspace, 'mc-state.json'), MC_HOST_backup: 'https://access:external-secret@backup.invalid/' },
  };
}

function postgres(workspace: string, role: 'backup' | 'restore' = 'backup'): string[] {
  return [
    '--host', role === 'backup' ? 'memeloop-token-center-api2-trial-pg-rw.memeloop-token-center-api2-trial.svc.cluster.local' : 'mtc-restore-pg-rw.mtc-restore.svc.cluster.local',
    '--port', '5432', '--database', role === 'backup' ? 'memeloop_token_center' : 'mtc_restore', '--username', 'rollback_operator',
    '--pgpass-file', join(workspace, 'pgpass'), '--inventory-sql-file', join(workspace, 'inventory.sql'),
  ];
}

function installFakeTools(workspace: string): void {
  const body = `#!/usr/bin/env node
import { basename } from 'node:path';
import { readFileSync, writeFileSync } from 'node:fs';
const binary = basename(process.argv[1]);
const args = process.argv.slice(2);
if (binary === 'pg_dump') {
  if (process.env.FAKE_FAIL === 'pg_dump') process.exit(23);
  process.stdout.write('fake-custom-dump-v1');
} else if (binary === 'pg_restore') {
  let bytes = 0;
  for await (const chunk of process.stdin) bytes += chunk.length;
  if (bytes === 0 || process.env.FAKE_FAIL === 'pg_restore') process.exit(24);
} else if (binary === 'psql') {
  if (args.includes('--command')) process.stdout.write((process.env.FAKE_TARGET_COUNT ?? '0') + '\\n');
  else {
    for await (const _chunk of process.stdin) { /* consume inventory SQL */ }
    process.stdout.write(process.env.FAKE_PG_INVENTORY ?? 'accounts\\t120\\t' + '1'.repeat(64) + '\\nrequests\\t440\\t' + '2'.repeat(64) + '\\n');
  }
} else if (binary === 'mc') {
  const statePath = process.env.FAKE_MC_STATE;
  const state = JSON.parse(readFileSync(statePath, 'utf8'));
  const operation = args[0];
  if (operation === 'ls') {
    const path = args.at(-1);
    for (const object of [...(state[path] ?? [])].sort((a, b) => Buffer.compare(Buffer.from(a.key), Buffer.from(b.key)))) process.stdout.write(JSON.stringify({ status: 'success', type: 'file', key: object.key, size: object.size, etag: object.etag ?? 'opaque-etag' }) + '\\n');
  } else if (operation === 'mirror') {
    const source = args.at(-2), destination = args.at(-1);
    const sourcePrefix = source.split('/').slice(2).join('/');
    const destinationPrefix = destination.split('/').slice(2).join('/');
    state[destination] = (state[source] ?? []).map((object) => ({ ...object, key: (destinationPrefix ? destinationPrefix + '/' : '') + (sourcePrefix && object.key.startsWith(sourcePrefix + '/') ? object.key.slice(sourcePrefix.length + 1) : object.key) }));
    writeFileSync(statePath, JSON.stringify(state));
  } else if (operation === 'cat') {
    const path = args.at(-1);
    let found;
    for (const objects of Object.values(state)) for (const object of objects) {
      const bucketPath = Object.entries(state).find(([, candidate]) => candidate === objects)?.[0].split('/').slice(0, 2).join('/');
      if (bucketPath + '/' + object.key === path) found = object;
    }
    if (!found) process.exit(27);
    process.stdout.write(found.content);
  } else if (operation === 'pipe') {
    const path = args.at(-1), parent = path.split('/').slice(0, -1).join('/'), key = path.split('/').slice(2).join('/');
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    let content = Buffer.concat(chunks).toString();
    if (process.env.FAKE_PIPE_TAMPER === '1' && content.length > 0) content = (content[0] === 'x' ? 'y' : 'x') + content.slice(1);
    state[parent] ??= [];
    state[parent].push({ key, size: Buffer.byteLength(content), etag: 'uploaded-etag', content });
    writeFileSync(statePath, JSON.stringify(state));
  } else process.exit(25);
} else process.exit(26);
`;
  for (const binary of ['pg_dump', 'pg_restore', 'psql', 'mc']) {
    const path = join(workspace, 'bin', binary);
    writeFileSync(path, body, { mode: 0o755 });
    chmodSync(path, 0o755);
  }
}

function fixture(testContext: { after: (callback: () => void) => void }): string {
  const workspace = mkdtempSync(join(tmpdir(), 'mtc-api2-rollback-'));
  testContext.after(() => rmSync(workspace, { recursive: true, force: true }));
  const bin = join(workspace, 'bin');
  mkdirSync(bin, { recursive: true });
  installFakeTools(workspace);
  writeFileSync(join(workspace, 'pgpass'), 'postgres.internal:5432:mtc_restore:rollback_operator:super-secret-value\n', { mode: 0o600 });
  chmodSync(join(workspace, 'pgpass'), 0o600);
  writeFileSync(join(workspace, 'inventory.sql'), 'SELECT identity, logical_bytes, content_sha256 FROM rollback_inventory ORDER BY identity COLLATE "C";\n', { mode: 0o600 });
  writeFileSync(join(workspace, 'mc-state.json'), JSON.stringify({}));
  return workspace;
}

test('help documents empty-target, environment-secret, and canonical inventory contracts', () => {
  const result = spawnSync(process.execPath, [join(repository, 'ops/api2-target-rollback.ts'), '--help'], { cwd: repository, encoding: 'utf8', shell: false });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /empty new PostgreSQL target/);
  assert.match(result.stdout, /MC_HOST_<alias>/);
  assert.match(result.stdout, /identity<TAB>bytes<TAB>sha256/);
  assert.match(result.stdout, /--source-failure-domain-id/); assert.match(result.stdout, /--backup-failure-domain-id/);
  assert.doesNotMatch(result.stdout, /--(?:password|secret|access-key)(?:[ =]|$)/i);
});

test('PostgreSQL backup and restore seal the dump and compare logical inventories', (context) => {
  const workspace = fixture(context);
  const remote = remoteBackup(workspace);
  const dump = join(workspace, 'postgres.dump'), backupReceipt = join(workspace, 'postgres-backup.json');
  expectSuccess(runTool(workspace, ['postgres-backup', ...postgres(workspace), ...remote.args, '--dump-file', dump, ...common(backupReceipt)], remote.env));
  assert.equal(readFileSync(dump, 'utf8'), 'fake-custom-dump-v1');
  const backup = JSON.parse(readFileSync(backupReceipt, 'utf8'));
  assert.equal(backup.kind, 'postgres'); assert.equal(backup.operation, 'backup');
  assert.equal(backup.source_failure_domain_id, 'cluster:hubble/api2'); assert.equal(backup.backup_failure_domain_id, 'object-store:xuanyuan');
  assert.deepEqual(backup.inventory, { count: 2, bytes: 560, sha256: backup.source_inventory.sha256 });
  assert.equal(backup.artifact.bytes, 19); assert.match(backup.artifact.sha256, /^[0-9a-f]{64}$/u);
  assert.equal(backup.backup_inventory.count, 1); assert.equal(backup.backup_origin.host, 'backup.invalid');
  assert.doesNotMatch(JSON.stringify(backup), /external-secret|access@|access:/);
  assert.equal(lstatSync(dump).mode & 0o777, 0o600); assert.equal(lstatSync(backupReceipt).mode & 0o777, 0o600);

  const duplicate = runTool(workspace, ['postgres-backup', ...postgres(workspace), ...remote.args, '--dump-file', dump, ...common(join(workspace, 'duplicate.json'))], remote.env);
  assert.notEqual(duplicate.status, 0); assert.match(duplicate.stderr, /already exists/);

  const restoredReceipt = join(workspace, 'postgres-restore.json'), restoredDump = join(workspace, 'restored.dump');
  expectSuccess(runTool(workspace, ['postgres-restore', ...postgres(workspace, 'restore'), ...remote.args, '--dump-file', restoredDump, '--backup-receipt', backupReceipt, ...common(restoredReceipt)], remote.env));
  const restored = JSON.parse(readFileSync(restoredReceipt, 'utf8'));
  assert.equal(restored.operation, 'restore'); assert.deepEqual(restored.inventory, backup.source_inventory);
  assert.match(restored.source_receipt_sha256, /^[0-9a-f]{64}$/u);

  const nonempty = runTool(workspace, ['postgres-restore', ...postgres(workspace, 'restore'), ...remote.args, '--dump-file', join(workspace, 'nonempty.dump'), '--backup-receipt', backupReceipt, ...common(join(workspace, 'nonempty.json'))], { ...remote.env, FAKE_TARGET_COUNT: '1' });
  assert.notEqual(nonempty.status, 0); assert.match(nonempty.stderr, /target is not empty/);

  const mismatch = runTool(workspace, ['postgres-restore', ...postgres(workspace, 'restore'), ...remote.args, '--dump-file', join(workspace, 'mismatch.dump'), '--backup-receipt', backupReceipt, ...common(join(workspace, 'mismatch.json'))], { ...remote.env, FAKE_PG_INVENTORY: `accounts\t121\t${'1'.repeat(64)}\nrequests\t440\t${'2'.repeat(64)}\n` });
  assert.notEqual(mismatch.status, 0); assert.match(mismatch.stderr, /inventory does not match/);
});

test('PostgreSQL backup and restore reject source/target origin confusion', (context) => {
  const workspace = fixture(context);
  const remote = remoteBackup(workspace);
  const wrongSource = postgres(workspace);
  wrongSource[1] = 'postgres.other.svc.cluster.local';
  const rejectedBackup = runTool(workspace, [
    'postgres-backup', ...wrongSource, ...remote.args, '--dump-file', join(workspace, 'wrong-source.dump'),
    ...common(join(workspace, 'wrong-source.json')),
  ], remote.env);
  assert.notEqual(rejectedBackup.status, 0);
  assert.match(rejectedBackup.stderr, /exact API2 database origin/);

  const dump = join(workspace, 'postgres.dump');
  const backupReceipt = join(workspace, 'postgres-backup.json');
  expectSuccess(runTool(workspace, [
    'postgres-backup', ...postgres(workspace), ...remote.args, '--dump-file', dump,
    ...common(backupReceipt),
  ], remote.env));
  const rejectedRestore = runTool(workspace, [
    'postgres-restore', ...postgres(workspace), ...remote.args,
    '--dump-file', join(workspace, 'same-source.dump'), '--backup-receipt', backupReceipt,
    ...common(join(workspace, 'same-source.json')),
  ], remote.env);
  assert.notEqual(rejectedRestore.status, 0);
  assert.match(rejectedRestore.stderr, /restore target must be a new endpoint/);
});

test('failure-domain and external MinIO endpoint boundaries reject unsafe backup placement', (context) => {
  const workspace = fixture(context);
  const statePath = join(workspace, 'mc-state.json');
  writeFileSync(statePath, JSON.stringify({ 'source/live-bucket': [{ key: 'asset', size: 1, etag: 'same', content: 'x' }] }));
  const base = ['minio-backup', '--source-alias', 'source', '--source-bucket', 'live-bucket', '--backup-alias', 'backup', '--backup-bucket', 'rollback-bucket', '--backup-prefix', `rollback/${windowId}/minio`, ...common(join(workspace, 'unsafe.json'))];
  const source = 'http://u:s@minio.memeloop-token-center-api2-trial.svc.cluster.local:9000/';
  const cases: Array<[string, NodeJS.ProcessEnv, RegExp]> = [
    ['same failure domain', { MC_HOST_source: source, MC_HOST_backup: 'https://u:s@backup.invalid/', FAKE_MC_STATE: statePath }, /failure domains must differ/],
    ['HTTP backup', { MC_HOST_source: source, MC_HOST_backup: 'http://u:s@backup.invalid/', FAKE_MC_STATE: statePath }, /external HTTPS/],
    ['service backup', { MC_HOST_source: source, MC_HOST_backup: 'https://u:s@minio.other.svc.cluster.local/', FAKE_MC_STATE: statePath }, /external HTTPS/],
    ['RFC1918 backup', { MC_HOST_source: source, MC_HOST_backup: 'https://u:s@10.10.2.3/', FAKE_MC_STATE: statePath }, /external HTTPS/],
    ['Tailnet backup', { MC_HOST_source: source, MC_HOST_backup: 'https://u:s@100.100.2.3/', FAKE_MC_STATE: statePath }, /external HTTPS/],
    ['wrong source', { MC_HOST_source: 'http://u:s@minio.other.svc.cluster.local:9000/', MC_HOST_backup: 'https://u:s@backup.invalid/', FAKE_MC_STATE: statePath }, /exact API2 cluster-local origin/],
  ];
  for (const [label, environment, expected] of cases) {
    const args = label === 'same failure domain' ? base.map((value) => value === 'object-store:xuanyuan' ? 'cluster:hubble/api2' : value) : base;
    const result = runTool(workspace, args, environment);
    assert.notEqual(result.status, 0, label); assert.match(result.stderr, expected, label);
  }
});

test('PostgreSQL remote prefix must be empty and uploaded bytes are read back before sealing', (context) => {
  const occupiedWorkspace = fixture(context), occupied = remoteBackup(occupiedWorkspace);
  writeFileSync(join(occupiedWorkspace, 'mc-state.json'), JSON.stringify({
    [`backup/rollback-bucket/rollback/${windowId}/postgres`]: [{ key: `rollback/${windowId}/postgres/existing`, size: 1, etag: 'e', content: 'x' }],
  }));
  const occupiedResult = runTool(occupiedWorkspace, ['postgres-backup', ...postgres(occupiedWorkspace), ...occupied.args, '--dump-file', join(occupiedWorkspace, 'occupied.dump'), ...common(join(occupiedWorkspace, 'occupied.json'))], occupied.env);
  assert.notEqual(occupiedResult.status, 0); assert.match(occupiedResult.stderr, /not unique and empty/);

  const tamperWorkspace = fixture(context), tamper = remoteBackup(tamperWorkspace);
  const tamperedResult = runTool(tamperWorkspace, ['postgres-backup', ...postgres(tamperWorkspace), ...tamper.args, '--dump-file', join(tamperWorkspace, 'tampered.dump'), ...common(join(tamperWorkspace, 'tampered.json'))], { ...tamper.env, FAKE_PIPE_TAMPER: '1' });
  assert.notEqual(tamperedResult.status, 0); assert.match(tamperedResult.stderr, /remote PostgreSQL dump inventory does not match/);

  const symlinkWorkspace = fixture(context), symlinkRemote = remoteBackup(symlinkWorkspace);
  const dumpLink = join(symlinkWorkspace, 'dump-link'); symlinkSync(join(symlinkWorkspace, 'nowhere'), dumpLink);
  const symlinkResult = runTool(symlinkWorkspace, ['postgres-backup', ...postgres(symlinkWorkspace), ...symlinkRemote.args, '--dump-file', dumpLink, ...common(join(symlinkWorkspace, 'symlink.json'))], symlinkRemote.env);
  assert.notEqual(symlinkResult.status, 0); assert.match(symlinkResult.stderr, /already exists|safely/);
});

test('MinIO backup and restore require an empty unique destination and exact inventory', (context) => {
  const workspace = fixture(context);
  const statePath = join(workspace, 'mc-state.json');
  const source = 'source/live-bucket/live', backup = `backup/rollback-bucket/rollback/${windowId}/minio`, target = 'target/new-bucket';
  writeFileSync(statePath, JSON.stringify({
    [source]: [
      { key: 'live/a.bin', size: 3, etag: 'etag-a', content: 'aaa' },
      { key: 'live/z.bin', size: 7, etag: 'etag-z', content: 'zzzzzzz' },
    ],
    [backup]: [],
    [target]: [],
  }));
  const environment = {
    FAKE_MC_STATE: statePath,
    MC_HOST_source: 'http://access:do-not-log-secret@minio.memeloop-token-center-api2-trial.svc.cluster.local:9000/',
    MC_HOST_backup: 'https://access:do-not-log-secret@backup.invalid/',
    MC_HOST_target: 'http://access:do-not-log-secret@minio-restore.mtc-restore.svc.cluster.local:9000/',
  };
  const backupReceipt = join(workspace, 'minio-backup.json');
  expectSuccess(runTool(workspace, [
    'minio-backup', '--source-alias', 'source', '--source-bucket', 'live-bucket', '--source-prefix', 'live',
    '--backup-alias', 'backup', '--backup-bucket', 'rollback-bucket', '--backup-prefix', `rollback/${windowId}/minio`,
    ...common(backupReceipt),
  ], environment));
  const sealed = JSON.parse(readFileSync(backupReceipt, 'utf8'));
  assert.deepEqual(sealed.inventory, { count: 2, bytes: 10, sha256: sealed.source_inventory.sha256 });
  assert.doesNotMatch(readFileSync(backupReceipt, 'utf8'), /do-not-log-secret|access/);

  const sameSourceRestore = runTool(workspace, [
    'minio-restore', '--backup-alias', 'backup', '--backup-bucket', 'rollback-bucket', '--backup-prefix', `rollback/${windowId}/minio`,
    '--target-alias', 'target', '--target-bucket', 'new-bucket', '--backup-receipt', backupReceipt,
    ...common(join(workspace, 'same-source-minio.json')),
  ], { ...environment, MC_HOST_target: environment.MC_HOST_source });
  assert.notEqual(sameSourceRestore.status, 0);
  assert.match(sameSourceRestore.stderr, /restore target must be a new endpoint/);

  const restoreReceipt = join(workspace, 'minio-restore.json');
  expectSuccess(runTool(workspace, [
    'minio-restore', '--backup-alias', 'backup', '--backup-bucket', 'rollback-bucket', '--backup-prefix', `rollback/${windowId}/minio`,
    '--target-alias', 'target', '--target-bucket', 'new-bucket', '--backup-receipt', backupReceipt,
    ...common(restoreReceipt),
  ], environment));
  const restored = JSON.parse(readFileSync(restoreReceipt, 'utf8'));
  assert.equal(restored.operation, 'restore'); assert.deepEqual(restored.inventory, sealed.source_inventory);

  const state = JSON.parse(readFileSync(statePath, 'utf8'));
  state[backup] = [
    { key: `rollback/${windowId}/minio/a.bin`, size: 3, etag: 'etag-a', content: 'bbb' },
    { key: `rollback/${windowId}/minio/z.bin`, size: 7, etag: 'etag-z', content: 'zzzzzzz' },
  ];
  state[target] = [];
  writeFileSync(statePath, JSON.stringify(state));
  const mismatch = runTool(workspace, [
    'minio-restore', '--backup-alias', 'backup', '--backup-bucket', 'rollback-bucket', '--backup-prefix', `rollback/${windowId}/minio`,
    '--target-alias', 'target', '--target-bucket', 'new-bucket', '--backup-receipt', backupReceipt,
    ...common(join(workspace, 'bad-minio-restore.json')),
  ], environment);
  assert.notEqual(mismatch.status, 0); assert.match(mismatch.stderr, /sealed MinIO backup inventory does not match/);
});

test('pair binds both private receipts to one operation, window, and quiesce evidence hash', (context) => {
  const workspace = fixture(context);
  const pgRemote = remoteBackup(workspace, `rollback/${windowId}/postgres`);
  const dump = join(workspace, 'postgres.dump'), postgresReceipt = join(workspace, 'postgres.json');
  expectSuccess(runTool(workspace, ['postgres-backup', ...postgres(workspace), ...pgRemote.args, '--dump-file', dump, ...common(postgresReceipt)], pgRemote.env));

  const statePath = join(workspace, 'mc-state.json');
  const prefix = `rollback/${windowId}`;
  const priorState = JSON.parse(readFileSync(statePath, 'utf8'));
  writeFileSync(statePath, JSON.stringify({ ...priorState, 'source/live-bucket': [{ key: 'asset', size: 1, etag: 'e', content: 'x' }], [`backup/rollback-bucket/${prefix}/minio`]: [] }));
  const minioReceipt = join(workspace, 'minio.json');
  const environment = { FAKE_MC_STATE: statePath, MC_HOST_source: 'http://u:s@minio.memeloop-token-center-api2-trial.svc.cluster.local:9000/', MC_HOST_backup: 'https://u:s@backup.invalid/' };
  expectSuccess(runTool(workspace, ['minio-backup', '--source-alias', 'source', '--source-bucket', 'live-bucket', '--backup-alias', 'backup', '--backup-bucket', 'rollback-bucket', '--backup-prefix', `${prefix}/minio`, ...common(minioReceipt)], environment));

  const pairedReceipt = join(workspace, 'paired.json');
  const evidenceReceipt = join(workspace, 'evidence.json');
  expectSuccess(runTool(workspace, ['pair', '--postgres-receipt', postgresReceipt, '--minio-receipt', minioReceipt, '--evidence-receipt', evidenceReceipt, '--backup-alias', 'backup', '--backup-bucket', 'rollback-bucket', '--backup-prefix', `rollback/${windowId}`, ...common(pairedReceipt)], environment));
  const paired = JSON.parse(readFileSync(pairedReceipt, 'utf8'));
  assert.equal(paired.kind, 'api2-paired-rollback'); assert.equal(paired.operation, 'backup');
  assert.equal(paired.window_id, windowId); assert.equal(paired.quiesce_evidence_sha256, evidence);
  assert.match(paired.postgres_receipt_sha256, /^[0-9a-f]{64}$/u); assert.match(paired.minio_receipt_sha256, /^[0-9a-f]{64}$/u);
  const evidenceManifest = JSON.parse(readFileSync(evidenceReceipt, 'utf8'));
  assert.equal(evidenceManifest.artifacts.length, 3); assert.equal(evidenceManifest.origin.host, 'backup.invalid');

});

test('child failures never expose PGPASSFILE contents or MinIO environment credentials', (context) => {
  const workspace = fixture(context);
  const remote = remoteBackup(workspace);
  const result = runTool(workspace, ['postgres-backup', ...postgres(workspace), ...remote.args, '--dump-file', join(workspace, 'failed.dump'), ...common(join(workspace, 'failed.json'))], { ...remote.env, FAKE_FAIL: 'pg_dump' });
  assert.notEqual(result.status, 0);
  assert.doesNotMatch(`${result.stdout}${result.stderr}`, /super-secret-value/);
  assert.match(result.stderr, /^pg_dump failed\n$/u);

  const listWorkspace = fixture(context);
  const listRemote = remoteBackup(listWorkspace);
  const listFailure = runTool(listWorkspace, [
    'postgres-backup', ...postgres(listWorkspace), ...listRemote.args,
    '--dump-file', join(listWorkspace, 'unlistable.dump'),
    ...common(join(listWorkspace, 'unlistable.json')),
  ], { ...listRemote.env, FAKE_FAIL: 'pg_restore' });
  assert.notEqual(listFailure.status, 0);
  assert.match(listFailure.stderr, /^pg_restore failed\n$/u);
  assert.deepEqual(JSON.parse(readFileSync(join(listWorkspace, 'mc-state.json'), 'utf8')), {});
});
