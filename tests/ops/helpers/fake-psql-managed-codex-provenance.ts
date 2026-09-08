#!/usr/bin/env node
/** Synthetic psql boundary for the managed Codex provenance CLI contract. */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";

const chunks: Buffer[] = [];
for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
const sql = Buffer.concat(chunks).toString("utf8");
if (!sql.includes("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
  || !sql.includes("upstream_account_imports")
  || !sql.includes("accounts.credential_generation")
  || /\b(?:INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|LOCK)\b/u.test(sql)) process.exit(9);

const serviceFile = process.env.PGSERVICEFILE;
if (!serviceFile || process.env.PGSERVICE !== "fixture_provenance") process.exit(9);
try {
  const result = readFileSync(join(dirname(serviceFile), "managed-codex-provenance-query-result.json"));
  JSON.parse(result.toString("utf8"));
  process.stdout.write(result);
} catch {
  process.exit(9);
}
