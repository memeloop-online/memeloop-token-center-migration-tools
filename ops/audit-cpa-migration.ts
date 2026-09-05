#!/usr/bin/env node
/** Fail-closed source/target audit for the combined CPA migration. */

import { accessSync, constants as fsConstants, lstatSync } from "node:fs";
import { spawnSync } from "node:child_process";

class CliError extends Error {
  readonly exitCode: number;

  constructor(message: string, exitCode = 2) {
    super(message);
    this.exitCode = exitCode;
  }
}

function fail(message: string, exitCode = 2): never {
  throw new CliError(message, exitCode);
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) fail(`${name} is required`);
  return value;
}

function positiveCount(name: string): string {
  const value = required(name);
  if (!/^\d+$/.test(value)) fail("expected source counts must be unsigned integers");
  if (BigInt(value) === 0n) fail("expected source counts must be greater than zero");
  return value;
}

const auditSql = String.raw`
BEGIN TRANSACTION READ ONLY;
WITH selected_tenant AS (
  SELECT id FROM tenants WHERE external_id = :'tenant'
), migration_request_ids AS (
  SELECT target_request_id AS request_id FROM session_archive_correlations
   WHERE tenant_id = (SELECT id FROM selected_tenant) AND source = :'archive_source' AND disposition = 'exact'
  UNION ALL
  SELECT archive_request_id FROM session_archive_unlinked_requests
   WHERE tenant_id = (SELECT id FROM selected_tenant) AND source = :'archive_source'
), migration_observations AS (
  SELECT o.id, o.cluster_id FROM conversation_observations o
  JOIN migration_request_ids m ON m.request_id = o.request_id
), measured AS (
  SELECT
    COALESCE((SELECT imported_events FROM cpamp_import_checkpoints WHERE tenant_external_id = :'tenant' AND source = :'cpamp_source'), 0) AS cpamp_checkpoint,
    (SELECT count(*) FROM import_request_links l WHERE l.tenant_id = (SELECT id FROM selected_tenant) AND l.source = :'cpamp_source') AS cpamp_links,
    COALESCE((SELECT imported_records FROM session_archive_import_checkpoints WHERE tenant_id = (SELECT id FROM selected_tenant) AND source = :'archive_source'), 0) AS archive_checkpoint,
    COALESCE((SELECT watermark_ms FROM session_archive_import_checkpoints WHERE tenant_id = (SELECT id FROM selected_tenant) AND source = :'archive_source'), 0) AS archive_watermark,
    (SELECT count(*) FROM session_archive_correlations c WHERE c.tenant_id = (SELECT id FROM selected_tenant) AND c.source = :'archive_source') AS archive_correlated,
    (SELECT count(*) FROM session_archive_correlations c WHERE c.tenant_id = (SELECT id FROM selected_tenant) AND c.source = :'archive_source' AND c.disposition = 'exact') AS archive_exact,
    (SELECT count(*) FROM session_archive_correlations c WHERE c.tenant_id = (SELECT id FROM selected_tenant) AND c.source = :'archive_source' AND c.disposition = 'unlinked') AS archive_unlinked,
    (SELECT count(*) FROM session_archive_import_records r WHERE r.tenant_id = (SELECT id FROM selected_tenant) AND r.source = :'archive_source') AS exact_provenance,
    (SELECT count(*) FROM session_archive_unlinked_requests u WHERE u.tenant_id = (SELECT id FROM selected_tenant) AND u.source = :'archive_source') AS unlinked_projection,
    (SELECT count(*) FROM session_archive_quarantine_records q LEFT JOIN session_archive_quarantine_resolutions z ON z.quarantine_id = q.id WHERE q.tenant_id = (SELECT id FROM selected_tenant) AND q.source = :'archive_source' AND z.id IS NULL) AS unresolved_quarantine,
    (SELECT count(*) FROM session_archive_import_records a JOIN request_records r ON r.id = a.target_request_id WHERE a.tenant_id = (SELECT id FROM selected_tenant) AND a.source = :'archive_source' AND (r.request_object LIKE 'gap://%' OR r.response_object LIKE 'gap://%')) AS exact_gap_locators,
    (SELECT count(*) FROM session_archive_unlinked_requests u WHERE u.tenant_id = (SELECT id FROM selected_tenant) AND u.source = :'archive_source' AND (u.request_object LIKE 'gap://%' OR u.response_object LIKE 'gap://%')) AS unlinked_gap_locators,
    (SELECT count(DISTINCT cluster_id) FROM migration_observations) AS correlated_clusters,
    (SELECT count(*) FROM migration_observations) AS correlated_observations,
    (SELECT count(*) FROM conversation_edges e WHERE e.to_observation_id IN (SELECT id FROM migration_observations) AND (e.from_observation_id IS NULL OR e.from_observation_id IN (SELECT id FROM migration_observations))) AS conversation_edges
)
SELECT cpamp_checkpoint || '|' || cpamp_links || '|' || archive_checkpoint || '|' || archive_watermark || '|' || archive_correlated || '|' || archive_exact || '|' || archive_unlinked || '|' || exact_provenance || '|' || unlinked_projection || '|' || unresolved_quarantine || '|' || exact_gap_locators || '|' || unlinked_gap_locators || '|' || correlated_clusters || '|' || correlated_observations || '|' || conversation_edges FROM measured;
COMMIT;
`;

function main(): void {
  Object.assign(process.env, {
    PGHOST: required("PGHOST"),
    PGPORT: process.env.PGPORT ?? "5432",
    PGUSER: required("PGUSER"),
    PGDATABASE: required("PGDATABASE"),
  });
  const tenant = required("IMPORT_TENANT_EXTERNAL_ID");
  const cpampSource = required("CPAMP_IMPORT_SOURCE");
  const archiveSource = required("SESSION_ARCHIVE_IMPORT_SOURCE");
  const expectedCpamp = positiveCount("EXPECTED_CPAMP_EVENTS");
  const expectedArchive = positiveCount("EXPECTED_ARCHIVE_RECORDS");

  const passFile = process.env.PGPASSFILE;
  const password = process.env.PGPASSWORD;
  if (passFile && password) fail("set exactly one of PGPASSFILE or PGPASSWORD");
  if (passFile) {
    try {
      const metadata = lstatSync(passFile);
      accessSync(passFile, fsConstants.R_OK);
      if (!metadata.isFile() || metadata.isSymbolicLink()) fail("PGPASSFILE must be a readable regular non-symlink file");
      if ((metadata.mode & 0o777) !== 0o600) fail("PGPASSFILE must have mode 0600");
    } catch (error) {
      if (error instanceof CliError) throw error;
      fail("PGPASSFILE must be a readable regular non-symlink file");
    }
  } else if (!password) {
    fail("PGPASSFILE or PGPASSWORD is required");
  }

  const result = spawnSync("psql", ["-X", "-v", "ON_ERROR_STOP=1", "--no-psqlrc", "-qAt", "-v", `tenant=${tenant}`, "-v", `cpamp_source=${cpampSource}`, "-v", `archive_source=${archiveSource}`], {
    encoding: "utf8",
    env: process.env,
    input: auditSql,
    shell: false,
    stdio: ["pipe", "pipe", "inherit"],
  });
  if (result.error || result.status !== 0) fail(result.error ? `psql is unavailable: ${result.error.message}` : "migration audit query failed", 1);
  const values = String(result.stdout).trim().split("|");
  if (values.length !== 15 || values.some((value) => !/^\d+$/.test(value ?? ""))) fail("migration audit returned invalid counts", 1);
  const [cpampCheckpoint, cpampLinks, archiveCheckpoint, archiveWatermark, archiveCorrelated, archiveExact, archiveUnlinked, exactProvenance, unlinkedProjection, unresolvedQuarantine, exactGapLocators, unlinkedGapLocators, clusters, observations, edges] = values as [string, string, string, string, string, string, string, string, string, string, string, string, string, string, string];
  if (cpampCheckpoint !== expectedCpamp || cpampLinks !== expectedCpamp) fail("migration audit failed: CPAMP source, checkpoint, and request links disagree", 1);
  if (archiveCheckpoint !== expectedArchive || archiveCorrelated !== expectedArchive || exactProvenance !== archiveExact || unlinkedProjection !== archiveUnlinked || unresolvedQuarantine !== "0" || exactGapLocators !== "0" || unlinkedGapLocators !== "0") {
    fail("migration audit failed: archive source, checkpoint, correlation, projection, or quarantine counts disagree", 1);
  }
  process.stdout.write(`{"archive_checkpoint":${archiveCheckpoint},"archive_correlated":${archiveCorrelated},"archive_exact":${archiveExact},"archive_unlinked":${archiveUnlinked},"archive_watermark_ms":${archiveWatermark},"conversation_clusters":${clusters},"conversation_edges":${edges},"conversation_observations":${observations},"cpamp_checkpoint":${cpampCheckpoint},"cpamp_links":${cpampLinks},"gap_locators":0,"unresolved_quarantine":0}\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : "migration audit failed"}\n`);
  process.exitCode = error instanceof CliError ? error.exitCode : 1;
}
