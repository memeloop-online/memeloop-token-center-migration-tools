#!/usr/bin/env node
/** Fail-closed paired PostgreSQL/MinIO backup and restore tooling for API2. */

import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readSync,
  writeSync,
  type BigIntStats,
} from 'node:fs';
import { basename } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { StringDecoder } from 'node:string_decoder';

const SHA256 = /^[0-9a-f]{64}$/u;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const SAFE_FAILURE_DOMAIN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const SAFE_ALIAS = /^[a-z][a-z0-9-]{0,62}$/u;
const SAFE_BUCKET = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u;
const MAX_FILE_BYTES = 256 * 1024 * 1024;
const MAX_LINE_BYTES = 1024 * 1024;
const API2_MINIO_ORIGIN = 'http://minio.memeloop-token-center-api2-trial.svc.cluster.local:9000';
const API2_POSTGRES_HOST = 'memeloop-token-center-api2-trial-pg-rw.memeloop-token-center-api2-trial.svc.cluster.local';
const API2_POSTGRES_DATABASE = 'memeloop_token_center';

type Inventory = { count: number; bytes: number; sha256: string };
type OriginLocation = { host: string; bucket: string; prefix: string };
type Receipt = {
  version: 1;
  kind: 'postgres' | 'minio';
  operation: 'backup' | 'restore';
  window_id: string;
  quiesce_evidence_sha256: string;
  source_failure_domain_id: string;
  backup_failure_domain_id: string;
  created_at: string;
  inventory: Inventory;
  source_inventory: Inventory;
  artifact: { bytes?: number; sha256: string; location_sha256?: string };
  source_receipt_sha256?: string;
  source_origin?: OriginLocation;
  backup_origin?: OriginLocation;
  restore_origin?: OriginLocation;
  backup_inventory?: Inventory;
};
type CommonBinding = { windowId: string; evidence: string; sourceFailureDomainId: string; backupFailureDomainId: string };

export class RollbackError extends Error {}

function sha256(value: Buffer | string): string {
  return createHash('sha256').update(value).digest('hex');
}

function stableStat(fd: number, path: string): BigIntStats {
  const byFd = fstatSync(fd, { bigint: true });
  let byPath: BigIntStats;
  try { byPath = lstatSync(path, { bigint: true }); } catch { throw new RollbackError(`${basename(path)} disappeared while in use`); }
  if (!byFd.isFile() || byPath.isSymbolicLink() || !byPath.isFile() || byFd.dev !== byPath.dev || byFd.ino !== byPath.ino || byFd.size !== byPath.size) {
    throw new RollbackError(`${basename(path)} changed while in use`);
  }
  return byFd;
}

function openPrivateInput(path: string, label: string): number {
  let fd = -1;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = stableStat(fd, path);
    if ((stat.mode & 0o077n) !== 0n) throw new RollbackError(`${label} must have mode 0600 or stricter`);
    return fd;
  } catch (error) {
    if (fd >= 0) closeSync(fd);
    if (error instanceof RollbackError) throw error;
    throw new RollbackError(`${label} must be an existing private regular file`);
  }
}

function openRegularInput(path: string, label: string): number {
  let fd = -1;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    stableStat(fd, path);
    return fd;
  } catch (error) {
    if (fd >= 0) closeSync(fd);
    if (error instanceof RollbackError) throw error;
    throw new RollbackError(`${label} must be an existing regular non-symlink file`);
  }
}

function openExclusiveOutput(path: string, label: string): number {
  try {
    return openSync(path, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  } catch {
    throw new RollbackError(`${label} already exists or cannot be created safely`);
  }
}

function readFd(fd: number, path: string, limit = MAX_FILE_BYTES): Buffer {
  const before = stableStat(fd, path);
  if (before.size > BigInt(limit)) throw new RollbackError(`${basename(path)} exceeds the safety limit`);
  const output = Buffer.alloc(Number(before.size));
  let offset = 0;
  while (offset < output.length) {
    const size = readSync(fd, output, offset, output.length - offset, offset);
    if (size === 0) throw new RollbackError(`${basename(path)} was truncated while reading`);
    offset += size;
  }
  const after = stableStat(fd, path);
  if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) {
    throw new RollbackError(`${basename(path)} changed while reading`);
  }
  return output;
}

function hashFd(fd: number, path: string): { bytes: number; sha256: string } {
  const before = stableStat(fd, path);
  if (before.size > BigInt(Number.MAX_SAFE_INTEGER)) throw new RollbackError(`${basename(path)} exceeds the safe byte-count limit`);
  const total = Number(before.size);
  const buffer = Buffer.alloc(1024 * 1024);
  const digest = createHash('sha256');
  let offset = 0;
  while (offset < total) {
    const size = readSync(fd, buffer, 0, Math.min(buffer.length, total - offset), offset);
    if (size === 0) throw new RollbackError(`${basename(path)} was truncated while hashing`);
    digest.update(buffer.subarray(0, size));
    offset += size;
  }
  const after = stableStat(fd, path);
  if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) {
    throw new RollbackError(`${basename(path)} changed while hashing`);
  }
  return { bytes: total, sha256: digest.digest('hex') };
}

function sealOutput(fd: number, path: string): { bytes: number; sha256: string } {
  fsyncSync(fd);
  return hashFd(fd, path);
}

function writeReceipt(path: string, value: object): { bytes: number; sha256: string } {
  const fd = openExclusiveOutput(path, 'receipt');
  try {
    const body = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
    let offset = 0;
    while (offset < body.length) offset += writeSync(fd, body, offset, body.length - offset, offset);
    return sealOutput(fd, path);
  } finally { closeSync(fd); }
}

function readJson(path: string, label: string): { value: unknown; bytes: Buffer; sha256: string } {
  const fd = openRegularInput(path, label);
  try {
    const bytes = readFd(fd, path);
    let value: unknown;
    try { value = JSON.parse(bytes.toString('utf8')); } catch { throw new RollbackError(`${label} is not valid JSON`); }
    return { value, bytes, sha256: sha256(bytes) };
  } finally { closeSync(fd); }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseInventory(value: unknown): Inventory {
  if (!isRecord(value) || !Number.isSafeInteger(value.count) || Number(value.count) < 0 || !Number.isSafeInteger(value.bytes) || Number(value.bytes) < 0 || typeof value.sha256 !== 'string' || !SHA256.test(value.sha256)) {
    throw new RollbackError('receipt inventory is invalid');
  }
  return { count: Number(value.count), bytes: Number(value.bytes), sha256: value.sha256 };
}

function parseReceipt(value: unknown, kind?: Receipt['kind'], operation?: Receipt['operation']): Receipt {
  if (!isRecord(value) || value.version !== 1 || (value.kind !== 'postgres' && value.kind !== 'minio') || (value.operation !== 'backup' && value.operation !== 'restore') || typeof value.window_id !== 'string' || !SAFE_NAME.test(value.window_id) || typeof value.quiesce_evidence_sha256 !== 'string' || !SHA256.test(value.quiesce_evidence_sha256) || typeof value.source_failure_domain_id !== 'string' || !SAFE_FAILURE_DOMAIN.test(value.source_failure_domain_id) || typeof value.backup_failure_domain_id !== 'string' || !SAFE_FAILURE_DOMAIN.test(value.backup_failure_domain_id) || value.source_failure_domain_id === value.backup_failure_domain_id || typeof value.created_at !== 'string' || !Number.isFinite(Date.parse(value.created_at)) || !isRecord(value.artifact) || typeof value.artifact.sha256 !== 'string' || !SHA256.test(value.artifact.sha256)) {
    throw new RollbackError('receipt contract is invalid');
  }
  if (kind !== undefined && value.kind !== kind) throw new RollbackError(`expected a ${kind} receipt`);
  if (operation !== undefined && value.operation !== operation) throw new RollbackError(`expected a ${operation} receipt`);
  const artifact: Receipt['artifact'] = { sha256: value.artifact.sha256 };
  if (value.artifact.bytes !== undefined) {
    if (!Number.isSafeInteger(value.artifact.bytes) || Number(value.artifact.bytes) < 0) throw new RollbackError('receipt artifact bytes are invalid');
    artifact.bytes = Number(value.artifact.bytes);
  }
  if (value.artifact.location_sha256 !== undefined) {
    if (typeof value.artifact.location_sha256 !== 'string' || !SHA256.test(value.artifact.location_sha256)) throw new RollbackError('receipt artifact location is invalid');
    artifact.location_sha256 = value.artifact.location_sha256;
  }
  if (value.source_receipt_sha256 !== undefined && (typeof value.source_receipt_sha256 !== 'string' || !SHA256.test(value.source_receipt_sha256))) throw new RollbackError('source receipt SHA-256 is invalid');
  const sourceOrigin = value.source_origin === undefined ? undefined : parseOriginLocation(value.source_origin, 'source origin');
  const backupOrigin = value.backup_origin === undefined ? undefined : parseOriginLocation(value.backup_origin, 'backup origin');
  const restoreOrigin = value.restore_origin === undefined ? undefined : parseOriginLocation(value.restore_origin, 'restore origin');
  const backupInventory = value.backup_inventory === undefined ? undefined : parseInventory(value.backup_inventory);
  if (value.kind === 'minio' && (sourceOrigin === undefined || backupOrigin === undefined)) throw new RollbackError('MinIO receipt origins are missing');
  if (value.kind === 'postgres' && (backupOrigin === undefined || backupInventory === undefined)) throw new RollbackError('PostgreSQL remote backup evidence is missing');
  return {
    version: 1,
    kind: value.kind,
    operation: value.operation,
    window_id: value.window_id,
    quiesce_evidence_sha256: value.quiesce_evidence_sha256,
    source_failure_domain_id: value.source_failure_domain_id,
    backup_failure_domain_id: value.backup_failure_domain_id,
    created_at: value.created_at,
    inventory: parseInventory(value.inventory),
    source_inventory: parseInventory(value.source_inventory),
    artifact,
    ...(typeof value.source_receipt_sha256 === 'string' ? { source_receipt_sha256: value.source_receipt_sha256 } : {}),
    ...(sourceOrigin === undefined ? {} : { source_origin: sourceOrigin }),
    ...(backupOrigin === undefined ? {} : { backup_origin: backupOrigin }),
    ...(restoreOrigin === undefined ? {} : { restore_origin: restoreOrigin }),
    ...(backupInventory === undefined ? {} : { backup_inventory: backupInventory }),
  };
}

function equalInventory(left: Inventory, right: Inventory): boolean {
  return left.count === right.count && left.bytes === right.bytes && left.sha256 === right.sha256;
}

function requireEqualInventory(left: Inventory, right: Inventory, label: string): void {
  if (!equalInventory(left, right)) throw new RollbackError(`${label} inventory does not match`);
}

function validateCommon(windowId: string, evidence: string, sourceFailureDomainId: string, backupFailureDomainId: string): void {
  if (!SAFE_NAME.test(windowId)) throw new RollbackError('window id is invalid');
  if (!SHA256.test(evidence)) throw new RollbackError('quiesce evidence SHA-256 is invalid');
  if (!SAFE_FAILURE_DOMAIN.test(sourceFailureDomainId) || !SAFE_FAILURE_DOMAIN.test(backupFailureDomainId)) throw new RollbackError('failure-domain id is invalid');
  if (sourceFailureDomainId === backupFailureDomainId) throw new RollbackError('source and backup failure domains must differ');
}

function assertCommon(receipt: Receipt, windowId: string, evidence: string, sourceFailureDomainId: string, backupFailureDomainId: string): void {
  if (receipt.window_id !== windowId || receipt.quiesce_evidence_sha256 !== evidence || receipt.source_failure_domain_id !== sourceFailureDomainId || receipt.backup_failure_domain_id !== backupFailureDomainId) throw new RollbackError('receipt is from a different window, quiesce evidence, or failure-domain pair');
}

function commonBinding(values: Values): CommonBinding {
  const binding = {
    windowId: required(values, 'window-id'),
    evidence: required(values, 'quiesce-evidence-sha256'),
    sourceFailureDomainId: required(values, 'source-failure-domain-id'),
    backupFailureDomainId: required(values, 'backup-failure-domain-id'),
  };
  validateCommon(binding.windowId, binding.evidence, binding.sourceFailureDomainId, binding.backupFailureDomainId);
  return binding;
}

function assertBinding(receipt: Receipt, binding: CommonBinding): void {
  assertCommon(receipt, binding.windowId, binding.evidence, binding.sourceFailureDomainId, binding.backupFailureDomainId);
}

function childEnvironment(pgpass?: string): NodeJS.ProcessEnv {
  return pgpass === undefined ? { ...process.env } : { ...process.env, PGPASSFILE: pgpass };
}

function validatePgpass(path: string): void {
  const fd = openPrivateInput(path, 'PGPASSFILE');
  try { stableStat(fd, path); } finally { closeSync(fd); }
}

function postgresArgs(options: Record<string, string>, role: 'backup' | 'restore'): string[] {
  const port = options.port ?? '5432';
  if (!/^\d{1,5}$/u.test(port) || Number(port) < 1 || Number(port) > 65535) throw new RollbackError('PostgreSQL port is invalid');
  for (const name of ['host', 'database', 'username'] as const) if (!options[name] || /[\u0000\r\n]/u.test(options[name]!)) throw new RollbackError(`PostgreSQL ${name} is invalid`);
  if (role === 'backup' && (options.host !== API2_POSTGRES_HOST || options.database !== API2_POSTGRES_DATABASE)) {
    throw new RollbackError('PostgreSQL backup source must be the exact API2 database origin');
  }
  if (role === 'restore' && options.host === API2_POSTGRES_HOST) {
    throw new RollbackError('PostgreSQL restore target must be a new endpoint');
  }
  return ['--host', options.host!, '--port', port, '--username', options.username!, '--dbname', options.database!];
}

function runQuiet(binary: string, args: string[], environment: NodeJS.ProcessEnv, inputFd?: number): void {
  const result = spawnSync(binary, args, { env: environment, shell: false, stdio: [inputFd ?? 'ignore', 'ignore', 'ignore'] });
  if (result.error !== undefined || result.status !== 0) throw new RollbackError(`${basename(binary)} failed`);
}

function runText(binary: string, args: string[], environment: NodeJS.ProcessEnv): string {
  const result = spawnSync(binary, args, { env: environment, shell: false, encoding: 'utf8', maxBuffer: 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] });
  if (result.error !== undefined || result.status !== 0) throw new RollbackError(`${basename(binary)} failed`);
  return result.stdout;
}

type InventoryLine = { identity: string; bytes: number; fingerprint: string } | undefined;

async function inventoryFromProcess(binary: string, args: string[], environment: NodeJS.ProcessEnv, stdin: Buffer | undefined, parseLine: (line: string) => InventoryLine | Promise<InventoryLine>): Promise<Inventory> {
  const child = spawn(binary, args, { env: environment, shell: false, stdio: [stdin === undefined ? 'ignore' : 'pipe', 'pipe', 'ignore'] });
  const completion = new Promise<number | null>((resolve) => {
    child.once('error', () => resolve(null));
    child.once('close', (code) => resolve(code));
  });
  child.stdin?.on('error', () => { /* completion reports the child failure without leaking arguments */ });
  if (stdin !== undefined) child.stdin?.end(stdin);
  const digest = createHash('sha256');
  let count = 0;
  let bytes = 0;
  let pending = '';
  const decoder = new StringDecoder('utf8');
  let previous: Buffer | undefined;
  const accept = async (line: string): Promise<void> => {
    if (Buffer.byteLength(line) > MAX_LINE_BYTES) throw new RollbackError('inventory line exceeds the safety limit');
    const item = await parseLine(line);
    if (item === undefined) return;
    const identity = Buffer.from(item.identity, 'utf8');
    if (previous !== undefined && Buffer.compare(previous, identity) >= 0) throw new RollbackError('inventory is not strictly bytewise sorted');
    previous = identity;
    count += 1;
    bytes += item.bytes;
    if (!Number.isSafeInteger(bytes)) throw new RollbackError('inventory bytes exceed the safe integer limit');
    digest.update(`${item.identity}\t${item.bytes}\t${item.fingerprint}\n`, 'utf8');
  };
  try {
    for await (const chunk of child.stdout!) {
      pending += decoder.write(Buffer.from(chunk));
      if (Buffer.byteLength(pending) > MAX_LINE_BYTES * 2) throw new RollbackError('inventory output contains an oversized line');
      let newline = pending.indexOf('\n');
      while (newline >= 0) {
        const line = pending.slice(0, newline).replace(/\r$/u, '');
        pending = pending.slice(newline + 1);
        if (line.length > 0) await accept(line);
        newline = pending.indexOf('\n');
      }
    }
    pending += decoder.end();
    if (pending.length > 0) await accept(pending.replace(/\r$/u, ''));
  } catch (error) {
    child.kill('SIGKILL');
    await completion;
    throw error;
  }
  const status = await completion;
  if (status !== 0) throw new RollbackError(`${basename(binary)} failed`);
  return { count, bytes, sha256: digest.digest('hex') };
}

function parsePostgresInventoryLine(line: string): InventoryLine {
  const fields = line.split('\t');
  if (fields.length !== 3 || fields[0] === undefined || fields[0].length === 0 || /[\u0000-\u001f]/u.test(fields[0]) || fields[1] === undefined || !/^\d+$/u.test(fields[1]) || fields[2] === undefined || !SHA256.test(fields[2])) throw new RollbackError('PostgreSQL inventory row must be identity, bytes, SHA-256');
  const bytes = Number(fields[1]);
  if (!Number.isSafeInteger(bytes)) throw new RollbackError('PostgreSQL inventory bytes are invalid');
  return { identity: fields[0], bytes, fingerprint: fields[2] };
}

function readInventorySql(path: string): Buffer {
  const fd = openRegularInput(path, 'inventory SQL file');
  try {
    const sql = readFd(fd, path, 1024 * 1024);
    if (sql.length === 0 || sql.includes(0)) throw new RollbackError('inventory SQL file is invalid');
    return sql;
  } finally { closeSync(fd); }
}

async function postgresInventory(connection: string[], environment: NodeJS.ProcessEnv, sql: Buffer): Promise<Inventory> {
  return inventoryFromProcess('psql', [...connection, '--set=ON_ERROR_STOP=1', '--tuples-only', '--no-align', '--field-separator=\t'], environment, sql, parsePostgresInventoryLine);
}

function emptyPostgresTarget(connection: string[], environment: NodeJS.ProcessEnv): void {
  const query = "SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p','m','S','f') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname !~ '^pg_toast';";
  const result = runText('psql', [...connection, '--set=ON_ERROR_STOP=1', '--tuples-only', '--no-align', '--command', query], environment).trim();
  if (result !== '0') throw new RollbackError('PostgreSQL restore target is not empty');
}

function validateAlias(alias: string): string {
  if (!SAFE_ALIAS.test(alias)) throw new RollbackError('MinIO alias is invalid');
  const credentialName = `MC_HOST_${alias}`;
  if (process.env[credentialName] === undefined) throw new RollbackError(`required MinIO credential environment ${credentialName} is missing`);
  return alias;
}

function isUnsafeBackupHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/u, '');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.lan') || host.endsWith('.home') || host.endsWith('.svc') || host.endsWith('.svc.cluster.local')) return true;
  const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u);
  if (ipv4 !== null) {
    const octets = ipv4.slice(1).map(Number);
    if (octets.some((value) => value > 255)) return true;
    const [a = -1, b = -1] = octets;
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  const unwrapped = host.replace(/^\[|\]$/gu, '');
  if (unwrapped === '::' || unwrapped === '::1' || unwrapped.startsWith('fe8') || unwrapped.startsWith('fe9') || unwrapped.startsWith('fea') || unwrapped.startsWith('feb') || unwrapped.startsWith('fc') || unwrapped.startsWith('fd')) return true;
  const mapped = unwrapped.match(/^::ffff:(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/u);
  return mapped !== null && isUnsafeBackupHost(mapped.slice(1).join('.'));
}

function minioEndpoint(alias: string, role: 'source' | 'backup' | 'restore'): URL {
  validateAlias(alias);
  const raw = process.env[`MC_HOST_${alias}`]!;
  let endpoint: URL;
  try { endpoint = new URL(raw); } catch { throw new RollbackError(`MinIO ${role} endpoint URL is invalid`); }
  if (endpoint.username.length === 0 || endpoint.password.length === 0 || endpoint.pathname !== '/' || endpoint.search !== '' || endpoint.hash !== '') throw new RollbackError(`MinIO ${role} endpoint URL contract is invalid`);
  if (role === 'source') {
    if (endpoint.origin !== API2_MINIO_ORIGIN) throw new RollbackError('MinIO source endpoint must be the exact API2 cluster-local origin');
  } else if (role === 'backup' && (endpoint.protocol !== 'https:' || isUnsafeBackupHost(endpoint.hostname) || endpoint.hostname === new URL(API2_MINIO_ORIGIN).hostname)) {
    throw new RollbackError('MinIO backup endpoint must be an external HTTPS failure domain');
  } else if (role === 'restore' && endpoint.origin === API2_MINIO_ORIGIN) {
    throw new RollbackError('MinIO restore target must be a new endpoint');
  } else if (role === 'restore' && endpoint.protocol !== 'http:' && endpoint.protocol !== 'https:') {
    throw new RollbackError('MinIO restore target endpoint protocol is invalid');
  }
  return endpoint;
}

function parseOriginLocation(value: unknown, label: string): OriginLocation {
  if (!isRecord(value) || typeof value.host !== 'string' || value.host.length === 0 || /[@\u0000\r\n]/u.test(value.host) || typeof value.bucket !== 'string' || !SAFE_BUCKET.test(value.bucket) || typeof value.prefix !== 'string') throw new RollbackError(`${label} is invalid`);
  normalizePrefix(value.prefix);
  return { host: value.host, bucket: value.bucket, prefix: value.prefix };
}

function originLocation(endpoint: URL, bucket: string, prefix: string): OriginLocation {
  return { host: endpoint.host, bucket, prefix };
}

function normalizePrefix(prefix: string): string {
  if (prefix === '') return '';
  if (prefix.startsWith('/') || prefix.endsWith('/') || prefix.split('/').some((part) => !SAFE_NAME.test(part))) throw new RollbackError('MinIO prefix is invalid');
  return prefix;
}

function minioPath(alias: string, bucket: string, prefix: string): string {
  validateAlias(alias);
  if (!SAFE_BUCKET.test(bucket)) throw new RollbackError('MinIO bucket is invalid');
  const normalized = normalizePrefix(prefix);
  return `${alias}/${bucket}${normalized === '' ? '' : `/${normalized}`}`;
}

function parseMinioListingLine(line: string, rootPrefix: string): { identity: string; bytes: number; objectKey: string } | undefined {
  let value: unknown;
  try { value = JSON.parse(line); } catch { throw new RollbackError('mc returned invalid JSON inventory'); }
  if (!isRecord(value) || value.status !== 'success') throw new RollbackError('mc inventory reported an error');
  if (value.type === 'folder') return undefined;
  if (value.type !== 'file' || typeof value.key !== 'string' || value.key.length === 0 || /[\u0000\r\n\t]/u.test(value.key) || !Number.isSafeInteger(value.size) || Number(value.size) < 0) throw new RollbackError('mc returned an invalid object inventory row');
  if (rootPrefix !== '' && !value.key.startsWith(`${rootPrefix}/`)) throw new RollbackError('mc returned an object outside the requested prefix');
  const rooted = rootPrefix !== '' && value.key.startsWith(`${rootPrefix}/`) ? value.key.slice(rootPrefix.length + 1) : value.key;
  if (rooted.length === 0) throw new RollbackError('mc returned an invalid empty relative object key');
  return { identity: rooted, bytes: Number(value.size), objectKey: value.key };
}

async function hashMinioObject(rootPath: string, rootPrefix: string, objectKey: string, expectedBytes: number): Promise<string> {
  const bucketPath = rootPath.split('/').slice(0, 2).join('/');
  const objectPath = rootPrefix !== '' && objectKey.startsWith(`${rootPrefix}/`) ? `${bucketPath}/${objectKey}` : `${rootPath}/${objectKey}`;
  const child = spawn('mc', ['cat', '--', objectPath], { env: childEnvironment(), shell: false, stdio: ['ignore', 'pipe', 'ignore'] });
  const completion = new Promise<number | null>((resolve) => { child.once('error', () => resolve(null)); child.once('close', (code) => resolve(code)); });
  const digest = createHash('sha256');
  let bytes = 0;
  for await (const chunk of child.stdout!) {
    const buffer = Buffer.from(chunk);
    bytes += buffer.length;
    if (!Number.isSafeInteger(bytes) || bytes > expectedBytes) { child.kill('SIGKILL'); await completion; throw new RollbackError('mc object content exceeds its listed size'); }
    digest.update(buffer);
  }
  if (await completion !== 0) throw new RollbackError('mc failed while hashing object content');
  if (bytes !== expectedBytes) throw new RollbackError('mc object content size does not match its listing');
  return digest.digest('hex');
}

async function minioInventory(path: string, rootPrefix: string): Promise<Inventory> {
  return inventoryFromProcess('mc', ['ls', '--recursive', '--json', path], childEnvironment(), undefined, async (line) => {
    const listing = parseMinioListingLine(line, rootPrefix);
    if (listing === undefined) return undefined;
    return { identity: listing.identity, bytes: listing.bytes, fingerprint: await hashMinioObject(path, rootPrefix, listing.objectKey, listing.bytes) };
  });
}

function singleObjectInventory(identity: string, bytes: number, contentSha256: string): Inventory {
  return { count: 1, bytes, sha256: sha256(`${identity}\t${bytes}\t${contentSha256}\n`) };
}

function externalBackupTarget(values: Values, binding: CommonBinding): { alias: string; bucket: string; prefix: string; endpoint: URL; path: string; origin: OriginLocation } {
  const alias = required(values, 'backup-alias'), bucket = required(values, 'backup-bucket'), prefix = normalizePrefix(required(values, 'backup-prefix'));
  if (!prefix.split('/').includes(binding.windowId)) throw new RollbackError('backup prefix must contain the exact window id as a path segment');
  const endpoint = minioEndpoint(alias, 'backup'), path = minioPath(alias, bucket, prefix);
  return { alias, bucket, prefix, endpoint, path, origin: originLocation(endpoint, bucket, prefix) };
}

function requireTerminalPrefix(prefix: string, terminal: string): void {
  if (prefix.split('/').at(-1) !== terminal) throw new RollbackError(`backup prefix must end with /${terminal}`);
}

function uploadFd(fd: number, remotePath: string): void {
  runQuiet('mc', ['pipe', remotePath], childEnvironment(), fd);
}

function uploadPath(path: string, remotePath: string): { bytes: number; sha256: string } {
  const fd = openRegularInput(path, 'evidence input');
  try {
    const sealed = hashFd(fd, path);
    uploadFd(fd, remotePath);
    stableStat(fd, path);
    return sealed;
  } finally { closeSync(fd); }
}

function objectInventory(entries: Array<{ identity: string; bytes: number; sha256: string }>): Inventory {
  const ordered = [...entries].sort((left, right) => Buffer.compare(Buffer.from(left.identity), Buffer.from(right.identity)));
  const digest = createHash('sha256');
  let bytes = 0;
  for (const entry of ordered) { bytes += entry.bytes; digest.update(`${entry.identity}\t${entry.bytes}\t${entry.sha256}\n`); }
  return { count: ordered.length, bytes, sha256: digest.digest('hex') };
}

function downloadToFd(remotePath: string, fd: number): void {
  const result = spawnSync('mc', ['cat', '--', remotePath], { env: childEnvironment(), shell: false, stdio: ['ignore', fd, 'ignore'] });
  if (result.error !== undefined || result.status !== 0) throw new RollbackError('mc failed while downloading sealed backup content');
}

function receiptBase(kind: Receipt['kind'], operation: Receipt['operation'], binding: CommonBinding, inventory: Inventory, sourceInventory: Inventory, artifact: Receipt['artifact'], extra: Partial<Pick<Receipt, 'source_receipt_sha256' | 'source_origin' | 'backup_origin' | 'restore_origin' | 'backup_inventory'>> = {}): Receipt {
  return { version: 1, kind, operation, window_id: binding.windowId, quiesce_evidence_sha256: binding.evidence, source_failure_domain_id: binding.sourceFailureDomainId, backup_failure_domain_id: binding.backupFailureDomainId, created_at: new Date().toISOString(), inventory, source_inventory: sourceInventory, artifact, ...extra };
}

type Values = Record<string, string>;

async function postgresBackup(values: Values): Promise<void> {
  const binding = commonBinding(values);
  const remote = externalBackupTarget(values, binding);
  requireTerminalPrefix(remote.prefix, 'postgres');
  const dumpPath = required(values, 'dump-file'), receiptPath = required(values, 'receipt'), pgpass = required(values, 'pgpass-file');
  validatePgpass(pgpass);
  const connection = postgresArgs(values, 'backup'), environment = childEnvironment(pgpass), sql = readInventorySql(required(values, 'inventory-sql-file'));
  const before = await postgresInventory(connection, environment, sql);
  const fd = openExclusiveOutput(dumpPath, 'PostgreSQL dump');
  let artifact: { bytes: number; sha256: string };
  try {
    const result = spawnSync('pg_dump', [...connection, '--format=custom', '--no-owner', '--no-privileges'], { env: environment, shell: false, stdio: ['ignore', fd, 'ignore'] });
    if (result.error !== undefined || result.status !== 0) throw new RollbackError('pg_dump failed');
    artifact = sealOutput(fd, dumpPath);
    const listFd = openRegularInput(dumpPath, 'PostgreSQL dump');
    try { runQuiet('pg_restore', ['--list'], environment, listFd); } finally { closeSync(listFd); }
    if ((await minioInventory(remote.path, remote.prefix)).count !== 0) throw new RollbackError('PostgreSQL remote backup prefix is not unique and empty');
    const uploaded = uploadPath(dumpPath, `${remote.path}/postgres.dump`);
    if (uploaded.bytes !== artifact.bytes || uploaded.sha256 !== artifact.sha256) throw new RollbackError('PostgreSQL dump changed before remote upload');
  } finally { closeSync(fd); }
  const remoteInventory = await minioInventory(remote.path, remote.prefix);
  requireEqualInventory(singleObjectInventory('postgres.dump', artifact.bytes, artifact.sha256), remoteInventory, 'remote PostgreSQL dump');
  const after = await postgresInventory(connection, environment, sql);
  requireEqualInventory(before, after, 'quiesced PostgreSQL source');
  writeReceipt(receiptPath, receiptBase('postgres', 'backup', binding, after, before, { ...artifact, location_sha256: sha256(JSON.stringify(remote.origin)) }, { backup_origin: remote.origin, backup_inventory: remoteInventory }));
}

async function postgresRestore(values: Values): Promise<void> {
  const binding = commonBinding(values);
  const backupRaw = readJson(required(values, 'backup-receipt'), 'PostgreSQL backup receipt');
  const backup = parseReceipt(backupRaw.value, 'postgres', 'backup');
  assertBinding(backup, binding);
  const remote = externalBackupTarget(values, binding);
  requireTerminalPrefix(remote.prefix, 'postgres');
  if (JSON.stringify(backup.backup_origin) !== JSON.stringify(remote.origin) || backup.artifact.location_sha256 !== sha256(JSON.stringify(remote.origin))) throw new RollbackError('PostgreSQL remote backup location does not match its receipt');
  const remoteInventory = await minioInventory(remote.path, remote.prefix);
  requireEqualInventory(backup.backup_inventory!, remoteInventory, 'sealed remote PostgreSQL dump');
  const dumpPath = required(values, 'dump-file'), dumpFd = openExclusiveOutput(dumpPath, 'downloaded PostgreSQL dump');
  try {
    downloadToFd(`${remote.path}/postgres.dump`, dumpFd);
    const dump = sealOutput(dumpFd, dumpPath);
    if (backup.artifact.bytes !== dump.bytes || backup.artifact.sha256 !== dump.sha256) throw new RollbackError('PostgreSQL dump does not match its backup receipt');
    const pgpass = required(values, 'pgpass-file');
    validatePgpass(pgpass);
    const connection = postgresArgs(values, 'restore'), environment = childEnvironment(pgpass);
    emptyPostgresTarget(connection, environment);
    const restoreFd = openRegularInput(dumpPath, 'downloaded PostgreSQL dump');
    try {
      runQuiet('pg_restore', [...connection, '--exit-on-error', '--no-owner', '--no-privileges'], environment, restoreFd);
      stableStat(restoreFd, dumpPath);
    } finally { closeSync(restoreFd); }
    const inventory = await postgresInventory(connection, environment, readInventorySql(required(values, 'inventory-sql-file')));
    requireEqualInventory(backup.source_inventory, inventory, 'restored PostgreSQL target');
    writeReceipt(required(values, 'receipt'), receiptBase('postgres', 'restore', binding, inventory, backup.source_inventory, backup.artifact, { source_receipt_sha256: backupRaw.sha256, backup_origin: backup.backup_origin!, backup_inventory: backup.backup_inventory! }));
  } finally { closeSync(dumpFd); }
}

async function minioBackup(values: Values): Promise<void> {
  const binding = commonBinding(values);
  const sourceAlias = required(values, 'source-alias'), backupAlias = required(values, 'backup-alias');
  const sourceEndpoint = minioEndpoint(sourceAlias, 'source'), backupEndpoint = minioEndpoint(backupAlias, 'backup');
  const sourceBucket = required(values, 'source-bucket'), backupBucket = required(values, 'backup-bucket');
  const source = minioPath(sourceAlias, sourceBucket, values['source-prefix'] ?? '');
  const prefix = normalizePrefix(required(values, 'backup-prefix'));
  if (!prefix.split('/').includes(binding.windowId)) throw new RollbackError('backup prefix must contain the exact window id as a path segment');
  requireTerminalPrefix(prefix, 'minio');
  const destination = minioPath(backupAlias, backupBucket, prefix);
  const sourcePrefix = normalizePrefix(values['source-prefix'] ?? '');
  const before = await minioInventory(source, sourcePrefix);
  if ((await minioInventory(destination, prefix)).count !== 0) throw new RollbackError('MinIO backup prefix is not unique and empty');
  runQuiet('mc', ['mirror', '--preserve', '--json', source, destination], childEnvironment());
  const after = await minioInventory(source, sourcePrefix), copied = await minioInventory(destination, prefix);
  requireEqualInventory(before, after, 'quiesced MinIO source');
  requireEqualInventory(after, copied, 'MinIO backup');
  const sourceOrigin = originLocation(sourceEndpoint, sourceBucket, sourcePrefix), backupOrigin = originLocation(backupEndpoint, backupBucket, prefix);
  writeReceipt(required(values, 'receipt'), receiptBase('minio', 'backup', binding, copied, after, { sha256: copied.sha256, location_sha256: sha256(JSON.stringify(backupOrigin)) }, { source_origin: sourceOrigin, backup_origin: backupOrigin }));
}

async function minioRestore(values: Values): Promise<void> {
  const binding = commonBinding(values);
  const backupRaw = readJson(required(values, 'backup-receipt'), 'MinIO backup receipt');
  const backup = parseReceipt(backupRaw.value, 'minio', 'backup');
  assertBinding(backup, binding);
  const backupAlias = required(values, 'backup-alias'), targetAlias = required(values, 'target-alias');
  const backupEndpoint = minioEndpoint(backupAlias, 'backup'), targetEndpoint = minioEndpoint(targetAlias, 'restore');
  const backupBucket = required(values, 'backup-bucket'), targetBucket = required(values, 'target-bucket');
  const backupPrefixValue = normalizePrefix(required(values, 'backup-prefix'));
  requireTerminalPrefix(backupPrefixValue, 'minio');
  const source = minioPath(backupAlias, backupBucket, backupPrefixValue);
  const suppliedBackupOrigin = originLocation(backupEndpoint, backupBucket, backupPrefixValue);
  if (backup.artifact.location_sha256 !== sha256(JSON.stringify(suppliedBackupOrigin)) || JSON.stringify(backup.backup_origin) !== JSON.stringify(suppliedBackupOrigin)) throw new RollbackError('MinIO backup location does not match its receipt');
  if ((values['target-prefix'] ?? '') !== '') throw new RollbackError('MinIO restore target must be a whole empty new bucket, not a prefix');
  const targetPrefix = '';
  const target = minioPath(targetAlias, targetBucket, targetPrefix);
  const backupPrefix = backupPrefixValue;
  const sourceInventory = await minioInventory(source, backupPrefix);
  requireEqualInventory(backup.inventory, sourceInventory, 'sealed MinIO backup');
  if ((await minioInventory(target, targetPrefix)).count !== 0) throw new RollbackError('MinIO restore target bucket/prefix is not empty');
  runQuiet('mc', ['mirror', '--preserve', '--json', source, target], childEnvironment());
  const restored = await minioInventory(target, targetPrefix);
  requireEqualInventory(backup.source_inventory, restored, 'restored MinIO target');
  writeReceipt(required(values, 'receipt'), receiptBase('minio', 'restore', binding, restored, sourceInventory, { sha256: restored.sha256, location_sha256: sha256(JSON.stringify(originLocation(targetEndpoint, targetBucket, ''))) }, { source_receipt_sha256: backupRaw.sha256, source_origin: backup.source_origin!, backup_origin: backup.backup_origin!, restore_origin: originLocation(targetEndpoint, targetBucket, '') }));
}

async function pair(values: Values): Promise<void> {
  const binding = commonBinding(values);
  const remote = externalBackupTarget(values, binding);
  if (remote.prefix.split('/').at(-1) !== binding.windowId) throw new RollbackError('paired evidence prefix must end with the exact window id');
  const evidencePrefix = `${remote.prefix}/evidence`, evidencePath = minioPath(remote.alias, remote.bucket, evidencePrefix);
  if ((await minioInventory(evidencePath, evidencePrefix)).count !== 0) throw new RollbackError('paired evidence prefix is not unique and empty');
  const postgresRaw = readJson(required(values, 'postgres-receipt'), 'PostgreSQL receipt');
  const minioRaw = readJson(required(values, 'minio-receipt'), 'MinIO receipt');
  const postgres = parseReceipt(postgresRaw.value, 'postgres'), minio = parseReceipt(minioRaw.value, 'minio');
  assertBinding(postgres, binding); assertBinding(minio, binding);
  if (postgres.operation !== minio.operation) throw new RollbackError('paired receipts must describe the same operation');
  for (const origin of [postgres.backup_origin!, minio.backup_origin!]) {
    if (origin.host !== remote.origin.host || origin.bucket !== remote.origin.bucket || (origin.prefix !== remote.prefix && !origin.prefix.startsWith(`${remote.prefix}/`))) throw new RollbackError('paired receipt backup origins must share the external window prefix');
  }
  const pairedPath = required(values, 'receipt');
  const pairedSeal = writeReceipt(pairedPath, {
    version: 1,
    kind: 'api2-paired-rollback',
    operation: postgres.operation,
    window_id: binding.windowId,
    quiesce_evidence_sha256: binding.evidence,
    source_failure_domain_id: binding.sourceFailureDomainId,
    backup_failure_domain_id: binding.backupFailureDomainId,
    created_at: new Date().toISOString(),
    postgres_receipt_sha256: postgresRaw.sha256,
    minio_receipt_sha256: minioRaw.sha256,
    postgres_inventory: postgres.inventory,
    minio_inventory: minio.inventory,
    evidence_origin: originLocation(remote.endpoint, remote.bucket, evidencePrefix),
    evidence_manifest_object: 'evidence-manifest.json',
  });
  const postgresSeal = uploadPath(required(values, 'postgres-receipt'), `${evidencePath}/postgres-receipt.json`);
  const minioSeal = uploadPath(required(values, 'minio-receipt'), `${evidencePath}/minio-receipt.json`);
  const uploadedPairedSeal = uploadPath(pairedPath, `${evidencePath}/paired-receipt.json`);
  if (pairedSeal.bytes !== uploadedPairedSeal.bytes || pairedSeal.sha256 !== uploadedPairedSeal.sha256) throw new RollbackError('paired receipt changed before evidence upload');
  const three = [
    { identity: 'minio-receipt.json', ...minioSeal },
    { identity: 'paired-receipt.json', ...pairedSeal },
    { identity: 'postgres-receipt.json', ...postgresSeal },
  ];
  requireEqualInventory(objectInventory(three), await minioInventory(evidencePath, evidencePrefix), 'three-file paired evidence');
  const manifestPath = required(values, 'evidence-receipt');
  const manifestSeal = writeReceipt(manifestPath, {
    version: 1,
    kind: 'api2-paired-rollback-evidence',
    operation: postgres.operation,
    window_id: binding.windowId,
    quiesce_evidence_sha256: binding.evidence,
    source_failure_domain_id: binding.sourceFailureDomainId,
    backup_failure_domain_id: binding.backupFailureDomainId,
    created_at: new Date().toISOString(),
    origin: originLocation(remote.endpoint, remote.bucket, evidencePrefix),
    artifacts: three.map((entry) => ({ object: entry.identity, bytes: entry.bytes, content_sha256: entry.sha256 })),
  });
  uploadPath(manifestPath, `${evidencePath}/evidence-manifest.json`);
  requireEqualInventory(objectInventory([...three, { identity: 'evidence-manifest.json', ...manifestSeal }]), await minioInventory(evidencePath, evidencePrefix), 'complete paired evidence');
}

function required(values: Values, name: string): string {
  const value = values[name];
  if (value === undefined || value.length === 0) throw new RollbackError(`--${name} is required`);
  return value;
}

const HELP = `Usage: api2-target-rollback <command> [options]

Commands:
  postgres-backup   Create a custom-format dump and sealed source inventory receipt
  postgres-restore  Restore a sealed dump only to an empty new PostgreSQL target
  minio-backup      Mirror a quiesced source to an empty unique backup prefix
  minio-restore     Restore a sealed mirror only to an empty new bucket/prefix
  pair              Bind PostgreSQL and MinIO receipts to one window/evidence hash

Common: --window-id ID --quiesce-evidence-sha256 HEX --receipt FILE
        --source-failure-domain-id ID --backup-failure-domain-id ID
PostgreSQL: --host HOST --port PORT --database DB --username USER
            --pgpass-file FILE --inventory-sql-file FILE
            backup: --dump-file FILE --backup-alias A --backup-bucket B --backup-prefix P
            restore: --dump-file NEWFILE --backup-receipt FILE
                     --backup-alias A --backup-bucket B --backup-prefix P
MinIO credentials must be provided only through MC_HOST_<alias> environment variables.
            backup: --source-alias A --source-bucket B [--source-prefix P]
                    --backup-alias A --backup-bucket B --backup-prefix P
            restore: --backup-alias A --backup-bucket B --backup-prefix P
                     --target-alias A --target-bucket B
                     --backup-receipt FILE
pair: --postgres-receipt FILE --minio-receipt FILE --evidence-receipt FILE
      --backup-alias A --backup-bucket B --backup-prefix P

Inventory SQL must emit strictly bytewise-sorted identity<TAB>bytes<TAB>sha256 rows.
Outputs and receipts are never overwritten; symlinks and changing inputs fail closed.
Secrets are never accepted as command-line values or written to receipts/logs.`;

const OPTION_NAMES = [
  'window-id', 'quiesce-evidence-sha256', 'receipt', 'host', 'port', 'database', 'username', 'pgpass-file',
  'inventory-sql-file', 'dump-file', 'backup-receipt', 'source-alias', 'source-bucket', 'source-prefix',
  'backup-alias', 'backup-bucket', 'backup-prefix', 'target-alias', 'target-bucket', 'target-prefix',
  'postgres-receipt', 'minio-receipt', 'evidence-receipt', 'source-failure-domain-id', 'backup-failure-domain-id',
] as const;

export async function main(argv: string[]): Promise<void> {
  if (argv.length === 0 || argv.includes('--help') || argv[0] === 'help') { process.stdout.write(`${HELP}\n`); return; }
  const options = Object.fromEntries(OPTION_NAMES.map((name) => [name, { type: 'string' as const }]));
  const parsed = parseArgs({ args: argv, options, allowPositionals: true, strict: true });
  if (parsed.positionals.length !== 1) throw new RollbackError('exactly one command is required');
  const values = parsed.values as Values;
  switch (parsed.positionals[0]) {
    case 'postgres-backup': await postgresBackup(values); break;
    case 'postgres-restore': await postgresRestore(values); break;
    case 'minio-backup': await minioBackup(values); break;
    case 'minio-restore': await minioRestore(values); break;
    case 'pair': await pair(values); break;
    default: throw new RollbackError('unknown command');
  }
}

if (pathToFileURL(process.argv[1] ?? '').href === import.meta.url) {
  main(process.argv.slice(2)).catch((error: unknown) => {
    process.stderr.write(`${error instanceof RollbackError ? error.message : 'unexpected rollback tool failure'}\n`);
    process.exitCode = 1;
  });
}
