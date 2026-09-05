#!/usr/bin/env node
import { writeFileSync } from 'node:fs';

const chunks: Buffer[] = [];
for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
const sql = Buffer.concat(chunks).toString('utf8');
if (!sql.includes('BEGIN TRANSACTION READ ONLY') || !sql.includes('session_archive_quarantine_records')) process.exit(9);
const log = process.env.FAKE_PSQL_LOG;
const counts = process.env.FAKE_PSQL_COUNTS;
if (log === undefined || counts === undefined) process.exit(9);
writeFileSync(log, JSON.stringify({ argv: process.argv.slice(2), sql }));
process.stdout.write(`${counts}\n`);
