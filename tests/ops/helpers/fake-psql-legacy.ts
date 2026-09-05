#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';

const source = process.env.FAKE_PSQL_ROWS;
if (source === undefined) process.exit(9);
const rows = readFileSync(source, 'utf8').trim().split('\n').map((line) => line.split(','));
const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
input.on('line', (line) => {
  if (line.includes('pg_try_advisory_lock')) process.stdout.write('1\n');
  else if (line.startsWith('SELECT json_build_array')) for (const row of rows) process.stdout.write(`${JSON.stringify(row)}\n`);
  else if (line.startsWith('\\echo __MTC_LEGACY_IDENTITIES_END__')) process.stdout.write('__MTC_LEGACY_IDENTITIES_END__\n');
  else if (line.includes('__MTC_LEGACY_IDENTITY_HEARTBEAT__')) process.stdout.write('__MTC_LEGACY_IDENTITY_HEARTBEAT__\n');
});
