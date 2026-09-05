#!/usr/bin/env node
import { chmodSync, chownSync, cpSync, readdirSync, statSync, writeFileSync } from 'node:fs';

cpSync('/fixture', '/source', { recursive: true });
writeFileSync('/source/transport-policy.json', `${JSON.stringify({ contract_version: 1, private_target_base_urls: ['https://openai-compatible.example.test/v1'] })}\n`);
const entries = readdirSync('/source', { recursive: true, encoding: 'utf8' })
  .sort((left, right) => right.split('/').length - left.split('/').length);
for (const entry of entries) {
  const path = `/source/${entry}`;
  try {
    chmodSync(path, statSync(path).isDirectory() ? 0o700 : 0o600);
    chownSync(path, 10001, 10001);
  } catch { /* a concurrently removed fixture must fail at the final importer read */ }
}
chmodSync('/source', 0o700);
chownSync('/source', 10001, 10001);
