import assert from 'node:assert/strict';
import { spawnSync, type SpawnSyncOptionsWithStringEncoding } from 'node:child_process';
import { chmodSync, copyFileSync, readFileSync, symlinkSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const repository = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

export function read(path: string): string {
  return readFileSync(resolve(repository, path), 'utf8');
}

export function contains(path: string, needle: string): void {
  assert.ok(read(path).includes(needle), `${path} is missing ${JSON.stringify(needle)}`);
}

export function excludes(path: string, pattern: string | RegExp): void {
  const body = read(path);
  assert.ok(
    typeof pattern === 'string' ? !body.includes(pattern) : !pattern.test(body),
    `${path} contains forbidden ${String(pattern)}`,
  );
}

export function occurrences(body: string, pattern: string | RegExp): number {
  if (typeof pattern === 'string') return body.split(pattern).length - 1;
  return [...body.matchAll(new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`))].length;
}

export function run(
  command: string,
  args: readonly string[] = [],
  options: Omit<SpawnSyncOptionsWithStringEncoding, 'encoding'> = {},
): string {
  const result = spawnSync(command, args, {
    cwd: repository,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options,
  });
  assert.equal(
    result.status,
    0,
    `${command} ${args.join(' ')} failed (${result.status ?? result.signal}):\n${result.stderr}`,
  );
  return result.stdout;
}

export function rejected(
  command: string,
  args: readonly string[] = [],
  options: Omit<SpawnSyncOptionsWithStringEncoding, 'encoding'> = {},
): void {
  const result = spawnSync(command, args, {
    cwd: repository,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options,
  });
  assert.notEqual(result.status, 0, `${command} ${args.join(' ')} unexpectedly succeeded`);
}

export function installExecutableHelper(source: string, directory: string, command: string): string {
  const target = resolve(directory, `${command}.ts`);
  copyFileSync(resolve(repository, source), target);
  chmodSync(target, 0o500);
  symlinkSync(`${command}.ts`, resolve(directory, command));
  return target;
}
