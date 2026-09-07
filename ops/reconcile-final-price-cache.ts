#!/usr/bin/env node
/**
 * Read-only final CPAMP price/cache reconciliation receipt.
 *
 * The receipt intentionally contains only opaque key references, model/tier
 * dimensions, and numeric accounting evidence.  It never selects request or
 * response locators, request bodies, credentials, or authentication tokens.
 */

import { accessSync, constants as fsConstants, lstatSync } from "node:fs";
import { createHash } from "node:crypto";
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
  if (value.includes("\0") || /[\r\n]/u.test(value)) fail(`${name} must be a single line`);
  return value;
}

function decimal(name: string, fallback: string): string {
  const value = process.env[name] ?? fallback;
  if (!/^\d+$/u.test(value) || BigInt(value) === 0n) fail(`${name} must be a positive integer`);
  return value;
}

function port(): string {
  const value = decimal("PRICE_RECON_PGPORT", "5432");
  if (BigInt(value) > 65535n) fail("PRICE_RECON_PGPORT must be at most 65535");
  return value;
}

function passFile(): string {
  const value = required("PRICE_RECON_PGPASSFILE");
  try {
    const metadata = lstatSync(value);
    accessSync(value, fsConstants.R_OK);
    if (!metadata.isFile() || metadata.isSymbolicLink()) fail("PRICE_RECON_PGPASSFILE must be a readable regular non-symlink file");
    if ((metadata.mode & 0o777) !== 0o600) fail("PRICE_RECON_PGPASSFILE must have mode 0600");
  } catch (error) {
    if (error instanceof CliError) throw error;
    fail("PRICE_RECON_PGPASSFILE must be a readable regular non-symlink file");
  }
  return value;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function parseArguments(arguments_: readonly string[]): void {
  if (arguments_.length === 0 || (arguments_.length === 1 && arguments_[0] === "--dry-run")) return;
  if (arguments_.length === 1 && arguments_[0] === "--help") {
    process.stdout.write("Usage: node ops/reconcile-final-price-cache.ts [--dry-run]\n");
    process.exit(0);
  }
  fail("this reconciliation is read-only; only --dry-run is accepted");
}

const reconciliationSql = String.raw`
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = :'statement_timeout';
WITH selected_tenant AS MATERIALIZED (
  SELECT id FROM tenants WHERE external_id = :'tenant_external_id'
), provenance AS MATERIALIZED (
  /*
   * `output_tokens` was not part of the original durable provenance schema.
   * Do not reference it as a PostgreSQL column: a reference would make the
   * whole read-only receipt fail to plan on an otherwise supported target.
   * `total_tokens` is the source receipt total and the importer requires the
   * normalized input partition to account for every input token, so an older
   * row's output is exactly total - normalized input. Newer schemas may
   * persist output_tokens; inspect the row JSON rather than pinning a schema
   * migration version. A malformed, negative, or out-of-range persisted value,
   * or a negative derivation, is measured below and blocks the receipt.
   */
  SELECT p.*, to_jsonb(p) AS provenance_json
    FROM cpamp_import_event_provenance p
   WHERE p.tenant_id = (SELECT id FROM selected_tenant)
     AND p.source = :'import_source'
), provenance_output_text AS MATERIALIZED (
  SELECT p.*, p.provenance_json->>'output_tokens' AS persisted_output_token_text
    FROM provenance p
), provenance_with_output AS MATERIALIZED (
  SELECT p.*,
         CASE
           WHEN p.provenance_json ? 'output_tokens'
             AND COALESCE(
               p.persisted_output_token_text ~ '^[0-9]+$'
               AND (
                 length(p.persisted_output_token_text) < 19
                 OR (length(p.persisted_output_token_text) = 19
                   AND p.persisted_output_token_text <= '9223372036854775807')
               ),
               false
             )
             THEN p.persisted_output_token_text::bigint
           WHEN NOT (p.provenance_json ? 'output_tokens')
             AND p.total_tokens >= p.normalized_total_input_tokens
             THEN p.total_tokens - p.normalized_total_input_tokens
           ELSE NULL
         END AS provenance_output_tokens,
         CASE
           WHEN p.provenance_json ? 'output_tokens'
             THEN NOT COALESCE(
               p.persisted_output_token_text ~ '^[0-9]+$'
               AND (
                 length(p.persisted_output_token_text) < 19
                 OR (length(p.persisted_output_token_text) = 19
                   AND p.persisted_output_token_text <= '9223372036854775807')
               ),
               false
             )
           ELSE p.total_tokens < p.normalized_total_input_tokens
         END AS invalid_provenance_output_tokens
    FROM provenance_output_text p
), scoped AS MATERIALIZED (
  SELECT p.external_event_hash, p.target_request_id, p.source_digest,
         p.pricing_digest, p.pricing_config_json, p.pricing_model,
         p.applied_service_tier, p.correction_revision,
         p.normalized_uncached_input_tokens, p.normalized_total_input_tokens,
         p.normalized_cache_read_tokens, p.normalized_cache_creation_tokens,
         p.provenance_output_tokens, p.invalid_provenance_output_tokens,
         p.cost_micros AS provenance_cost_micros,
         l.target_request_id AS linked_target_request_id,
         r.id AS request_id, r.key_id, r.created_at, r.model AS request_model,
         r.currency AS request_currency, r.reservation_id,
         r.input_tokens AS request_input_tokens,
         r.output_tokens AS request_output_tokens,
         r.cached_input_tokens AS request_cached_input_tokens,
         r.cache_write_tokens AS request_cache_write_tokens,
         r.cost_micros AS request_cost_micros,
         f.request_id AS fact_request_id,
         f.input_tokens AS fact_input_tokens,
         f.output_tokens AS fact_output_tokens,
         f.cached_input_tokens AS fact_cached_input_tokens,
         f.cache_write_tokens AS fact_cache_write_tokens,
         f.cost_micros AS fact_cost_micros
    FROM provenance_with_output p
    LEFT JOIN import_request_links l
      ON l.tenant_id = p.tenant_id
     AND l.source = p.source
     AND l.external_event_hash = p.external_event_hash
    LEFT JOIN request_record_locators locator
      ON locator.id = p.target_request_id
     AND locator.tenant_id = p.tenant_id
    LEFT JOIN request_records r
      ON r.id = locator.id
     AND r.created_at = locator.created_at
     AND r.tenant_id = locator.tenant_id
     AND r.key_id = locator.key_id
    LEFT JOIN request_stats_facts f
      ON f.request_id = p.target_request_id
     AND f.tenant_id = p.tenant_id
), duplicate_targets AS MATERIALIZED (
  SELECT target_request_id, count(*) AS event_count
    FROM provenance
   GROUP BY target_request_id
  HAVING count(*) > 1
), unexpected_usage_reservations AS MATERIALIZED (
  SELECT s.external_event_hash
    FROM scoped s
    JOIN usage_reservations u ON u.id = s.reservation_id
   WHERE s.request_id IS NOT NULL
), unexpected_usage_ledger AS MATERIALIZED (
  SELECT s.external_event_hash
    FROM scoped s
    JOIN ledger_entries l
      ON l.source = s.reservation_id
     AND l.kind = 'usage'
   WHERE s.request_id IS NOT NULL
), current_price_combinations AS MATERIALIZED (
  SELECT p.pricing_model, p.applied_service_tier,
         count(*) AS event_count,
         COALESCE(sum(p.normalized_uncached_input_tokens), 0) AS input_tokens,
         COALESCE(sum(p.normalized_cache_read_tokens), 0) AS cached_input_tokens,
         COALESCE(sum(p.normalized_cache_creation_tokens), 0) AS cache_write_tokens,
         COALESCE(sum(p.provenance_output_tokens), 0) AS output_tokens,
         COALESCE(sum(p.cost_micros), 0) AS historical_cost_micros,
         max(t.id) AS current_price_id,
         COALESCE(max(t.cache_price_estimated), 0) AS cache_price_estimated
    FROM provenance_with_output p
    LEFT JOIN model_price_tiers t
      ON t.model = p.pricing_model
     AND t.currency = :'currency'
     AND t.service_tier = p.applied_service_tier
   WHERE p.normalized_uncached_input_tokens <> 0
      OR p.normalized_cache_read_tokens <> 0
      OR p.normalized_cache_creation_tokens <> 0
      OR p.provenance_output_tokens <> 0
   GROUP BY p.pricing_model, p.applied_service_tier
), missing_current_price_combinations AS MATERIALIZED (
  SELECT * FROM current_price_combinations WHERE current_price_id IS NULL
), key_model_day AS MATERIALIZED (
  SELECT encode(sha256(convert_to(s.key_id, 'UTF8')), 'hex') AS key_ref_sha256,
         s.created_at / 86400000 AS day_bucket,
         s.request_model AS model,
         count(*) AS provenance_events,
         COALESCE(sum(s.normalized_uncached_input_tokens), 0) AS provenance_input_tokens,
         COALESCE(sum(s.normalized_cache_read_tokens), 0) AS provenance_cached_input_tokens,
         COALESCE(sum(s.normalized_cache_creation_tokens), 0) AS provenance_cache_write_tokens,
         COALESCE(sum(s.provenance_output_tokens), 0) AS provenance_output_tokens,
         COALESCE(sum(s.provenance_cost_micros), 0) AS provenance_cost_micros,
         count(s.request_id) AS request_rows,
         COALESCE(sum(s.request_input_tokens), 0) AS request_input_tokens,
         COALESCE(sum(s.request_cached_input_tokens), 0) AS request_cached_input_tokens,
         COALESCE(sum(s.request_cache_write_tokens), 0) AS request_cache_write_tokens,
         COALESCE(sum(s.request_output_tokens), 0) AS request_output_tokens,
         COALESCE(sum(s.request_cost_micros), 0) AS request_cost_micros,
         count(s.fact_request_id) AS fact_rows,
         COALESCE(sum(s.fact_input_tokens), 0) AS fact_input_tokens,
         COALESCE(sum(s.fact_cached_input_tokens), 0) AS fact_cached_input_tokens,
         COALESCE(sum(s.fact_cache_write_tokens), 0) AS fact_cache_write_tokens,
         COALESCE(sum(s.fact_output_tokens), 0) AS fact_output_tokens,
         COALESCE(sum(s.fact_cost_micros), 0) AS fact_cost_micros
    FROM scoped s
   WHERE s.request_id IS NOT NULL
   GROUP BY s.key_id, s.created_at / 86400000, s.request_model
), measured AS MATERIALIZED (
  SELECT
    (SELECT count(*) FROM provenance) AS provenance_events,
    (SELECT count(*) FROM import_request_links l
      WHERE l.tenant_id = (SELECT id FROM selected_tenant)
        AND l.source = :'import_source') AS import_links,
    (SELECT count(*) FROM import_request_links l
      LEFT JOIN provenance p ON p.external_event_hash = l.external_event_hash
      WHERE l.tenant_id = (SELECT id FROM selected_tenant)
        AND l.source = :'import_source'
        AND p.external_event_hash IS NULL) AS import_links_without_provenance,
    (SELECT count(*) FROM scoped WHERE linked_target_request_id IS NULL) AS provenance_without_link,
    (SELECT count(*) FROM scoped WHERE linked_target_request_id IS NOT NULL AND linked_target_request_id <> target_request_id) AS link_target_mismatches,
    (SELECT count(*) FROM scoped WHERE request_id IS NULL) AS provenance_without_target_request,
    (SELECT count(*) FROM scoped WHERE fact_request_id IS NULL) AS provenance_without_fact,
    (SELECT count(*) FROM scoped WHERE source_digest = '' OR pricing_digest = '' OR pricing_config_json = '') AS provenance_without_price_snapshot,
    (SELECT count(*) FROM scoped WHERE normalized_total_input_tokens <> normalized_uncached_input_tokens + normalized_cache_read_tokens + normalized_cache_creation_tokens) AS invalid_cache_partitions,
    (SELECT count(*) FROM scoped WHERE invalid_provenance_output_tokens) AS invalid_provenance_output_tokens,
    (SELECT count(*) FROM scoped WHERE request_id IS NOT NULL AND request_currency <> :'currency') AS request_currency_mismatches,
    (SELECT count(*) FROM scoped WHERE request_id IS NOT NULL AND reservation_id <> 'cpamp-import:' || external_event_hash) AS reservation_identity_mismatches,
    (SELECT count(*) FROM duplicate_targets) AS duplicate_target_request_count,
    (SELECT COALESCE(sum(event_count), 0) FROM duplicate_targets) AS duplicate_target_event_count,
    (SELECT count(*) FROM unexpected_usage_reservations) AS unexpected_usage_reservation_count,
    (SELECT count(*) FROM unexpected_usage_ledger) AS unexpected_usage_ledger_count,
    (SELECT count(*) FROM current_price_combinations) AS current_price_combination_count,
    (SELECT count(*) FROM missing_current_price_combinations) AS missing_current_price_combination_count,
    (SELECT count(*) FROM current_price_combinations WHERE cache_price_estimated <> 0) AS estimated_cache_price_combination_count,
    (SELECT count(DISTINCT correction_revision) FROM provenance) AS correction_revision_count,
    (SELECT count(*) FROM provenance_with_output WHERE provenance_json ? 'output_tokens') AS persisted_provenance_output_token_rows,
    (SELECT count(*) FROM provenance_with_output WHERE NOT (provenance_json ? 'output_tokens')) AS derived_provenance_output_token_rows,
    (SELECT count(*) FROM key_model_day) AS key_model_day_count,
    (SELECT COALESCE(sum(request_input_tokens - normalized_total_input_tokens), 0) FROM scoped WHERE request_id IS NOT NULL) AS request_input_delta,
    (SELECT COALESCE(sum(request_cached_input_tokens - normalized_cache_read_tokens), 0) FROM scoped WHERE request_id IS NOT NULL) AS request_cache_read_delta,
    (SELECT COALESCE(sum(request_cache_write_tokens - normalized_cache_creation_tokens), 0) FROM scoped WHERE request_id IS NOT NULL) AS request_cache_write_delta,
    (SELECT COALESCE(sum(request_output_tokens - provenance_output_tokens), 0) FROM scoped WHERE request_id IS NOT NULL) AS request_output_delta,
    (SELECT COALESCE(sum(request_cost_micros - provenance_cost_micros), 0) FROM scoped WHERE request_id IS NOT NULL) AS request_cost_delta,
    (SELECT COALESCE(sum(fact_input_tokens - request_input_tokens), 0) FROM scoped WHERE fact_request_id IS NOT NULL) AS fact_input_delta,
    (SELECT COALESCE(sum(fact_cached_input_tokens - request_cached_input_tokens), 0) FROM scoped WHERE fact_request_id IS NOT NULL) AS fact_cache_read_delta,
    (SELECT COALESCE(sum(fact_cache_write_tokens - request_cache_write_tokens), 0) FROM scoped WHERE fact_request_id IS NOT NULL) AS fact_cache_write_delta,
    (SELECT COALESCE(sum(fact_output_tokens - request_output_tokens), 0) FROM scoped WHERE fact_request_id IS NOT NULL) AS fact_output_delta,
    (SELECT COALESCE(sum(fact_cost_micros - request_cost_micros), 0) FROM scoped WHERE fact_request_id IS NOT NULL) AS fact_cost_delta,
    (SELECT count(*) FROM scoped WHERE request_id IS NOT NULL AND (
      request_input_tokens <> normalized_total_input_tokens
      OR request_cached_input_tokens <> normalized_cache_read_tokens
      OR request_cache_write_tokens <> normalized_cache_creation_tokens
      OR provenance_output_tokens IS NULL
      OR request_output_tokens <> provenance_output_tokens
      OR request_cost_micros <> provenance_cost_micros
    )) AS request_amount_mismatch_count,
    (SELECT count(*) FROM scoped WHERE fact_request_id IS NOT NULL AND (
      fact_input_tokens <> request_input_tokens
      OR fact_cached_input_tokens <> request_cached_input_tokens
      OR fact_cache_write_tokens <> request_cache_write_tokens
      OR fact_output_tokens <> request_output_tokens
      OR fact_cost_micros <> request_cost_micros
    )) AS fact_amount_mismatch_count
)
SELECT jsonb_build_object(
  'aggregate_counts', jsonb_build_object(
    'provenance_events', provenance_events::text,
    'import_links', import_links::text,
    'key_model_day_rows', key_model_day_count::text,
    'current_price_combinations', current_price_combination_count::text,
    'missing_current_price_combinations', missing_current_price_combination_count::text,
    'estimated_cache_price_combinations', estimated_cache_price_combination_count::text,
    'correction_revisions', correction_revision_count::text,
    'persisted_provenance_output_token_rows', persisted_provenance_output_token_rows::text,
    'derived_provenance_output_token_rows', derived_provenance_output_token_rows::text
  ),
  'historical_provenance_coverage', jsonb_build_object(
    'provenance_without_link', provenance_without_link::text,
    'import_links_without_provenance', import_links_without_provenance::text,
    'link_target_mismatches', link_target_mismatches::text,
    'provenance_without_target_request', provenance_without_target_request::text,
    'provenance_without_fact', provenance_without_fact::text,
    'provenance_without_price_snapshot', provenance_without_price_snapshot::text,
    'invalid_cache_partitions', invalid_cache_partitions::text,
    'invalid_provenance_output_tokens', invalid_provenance_output_tokens::text,
    'request_currency_mismatches', request_currency_mismatches::text
  ),
  'amount_differences', jsonb_build_object(
    'request_input_tokens', request_input_delta::text,
    'request_cache_read_tokens', request_cache_read_delta::text,
    'request_cache_write_tokens', request_cache_write_delta::text,
    'request_output_tokens', request_output_delta::text,
    'request_cost_micros', request_cost_delta::text,
    'fact_input_tokens', fact_input_delta::text,
    'fact_cache_read_tokens', fact_cache_read_delta::text,
    'fact_cache_write_tokens', fact_cache_write_delta::text,
    'fact_output_tokens', fact_output_delta::text,
    'fact_cost_micros', fact_cost_delta::text,
    'request_amount_mismatches', request_amount_mismatch_count::text,
    'fact_amount_mismatches', fact_amount_mismatch_count::text
  ),
  'duplicate_billing_check', jsonb_build_object(
    'duplicate_target_requests', duplicate_target_request_count::text,
    'duplicate_target_events', duplicate_target_event_count::text,
    'reservation_identity_mismatches', reservation_identity_mismatches::text,
    'unexpected_usage_reservations', unexpected_usage_reservation_count::text,
    'unexpected_usage_ledger_entries', unexpected_usage_ledger_count::text
  ),
  'missing_current_price_combinations', COALESCE((
    SELECT jsonb_agg(jsonb_build_object(
      'pricing_model', pricing_model,
      'service_tier', applied_service_tier,
      'events', event_count::text,
      'input_tokens', input_tokens::text,
      'cached_input_tokens', cached_input_tokens::text,
      'cache_write_tokens', cache_write_tokens::text,
      'output_tokens', output_tokens::text,
      'historical_cost_micros', historical_cost_micros::text
    ) ORDER BY pricing_model, applied_service_tier)
    FROM missing_current_price_combinations
  ), '[]'::jsonb),
  'per_key_model_day', COALESCE((
    SELECT jsonb_agg(jsonb_build_object(
      'key_ref_sha256', key_ref_sha256,
      'day_bucket', day_bucket::text,
      'model', model,
      'provenance_events', provenance_events::text,
      'request_rows', request_rows::text,
      'fact_rows', fact_rows::text,
      'provenance_input_tokens', provenance_input_tokens::text,
      'provenance_cached_input_tokens', provenance_cached_input_tokens::text,
      'provenance_cache_write_tokens', provenance_cache_write_tokens::text,
      'provenance_output_tokens', provenance_output_tokens::text,
      'provenance_cost_micros', provenance_cost_micros::text,
      'request_input_delta', (request_input_tokens - provenance_input_tokens)::text,
      'request_cache_read_delta', (request_cached_input_tokens - provenance_cached_input_tokens)::text,
      'request_cache_write_delta', (request_cache_write_tokens - provenance_cache_write_tokens)::text,
      'request_output_delta', (request_output_tokens - provenance_output_tokens)::text,
      'request_cost_delta', (request_cost_micros - provenance_cost_micros)::text,
      'fact_input_delta', (fact_input_tokens - request_input_tokens)::text,
      'fact_cache_read_delta', (fact_cached_input_tokens - request_cached_input_tokens)::text,
      'fact_cache_write_delta', (fact_cache_write_tokens - request_cache_write_tokens)::text,
      'fact_output_delta', (fact_output_tokens - request_output_tokens)::text,
      'fact_cost_delta', (fact_cost_micros - request_cost_micros)::text
    ) ORDER BY day_bucket, key_ref_sha256, model)
    FROM key_model_day
  ), '[]'::jsonb)
)::text
FROM measured;
COMMIT;
`;

type JsonRecord = Record<string, unknown>;

function record(value: unknown, name: string): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail(`psql receipt has invalid ${name}`, 1);
  return value as JsonRecord;
}

function numericString(value: unknown, name: string): string {
  if (typeof value !== "string" || !/^-?\d+$/u.test(value)) fail(`psql receipt has invalid ${name}`, 1);
  return value;
}

function nonZero(value: unknown, name: string): boolean {
  return BigInt(numericString(value, name)) !== 0n;
}

function parseReceipt(output: string): JsonRecord {
  const outputLine = output.trim();
  if (!outputLine || outputLine.includes("\n")) fail("reconciliation query returned invalid receipt output", 1);
  let parsed: unknown;
  try {
    parsed = JSON.parse(outputLine);
  } catch {
    fail("reconciliation query returned invalid JSON receipt", 1);
  }
  const receipt = record(parsed, "root");
  const aggregate = record(receipt.aggregate_counts, "aggregate_counts");
  const provenance = record(receipt.historical_provenance_coverage, "historical_provenance_coverage");
  const differences = record(receipt.amount_differences, "amount_differences");
  const duplicate = record(receipt.duplicate_billing_check, "duplicate_billing_check");
  for (const [name, value] of Object.entries({ ...aggregate, ...provenance, ...differences, ...duplicate })) numericString(value, name);
  if (!Array.isArray(receipt.missing_current_price_combinations) || !Array.isArray(receipt.per_key_model_day)) fail("psql receipt has invalid reconciliation arrays", 1);
  return receipt;
}

function main(): void {
  parseArguments(process.argv.slice(2));
  const tenant = required("PRICE_RECON_TENANT_EXTERNAL_ID");
  const source = required("PRICE_RECON_IMPORT_SOURCE");
  const currency = required("PRICE_RECON_CURRENCY");
  const timeout = decimal("PRICE_RECON_STATEMENT_TIMEOUT_MS", "30000");
  const result = spawnSync("psql", [
    "-X", "--no-psqlrc", "-qAt", "-v", "ON_ERROR_STOP=1",
    "-v", `tenant_external_id=${tenant}`,
    "-v", `import_source=${source}`,
    "-v", `currency=${currency}`,
    "-v", `statement_timeout=${timeout}ms`,
  ], {
    encoding: "utf8",
    input: reconciliationSql,
    shell: false,
    stdio: ["pipe", "pipe", "inherit"],
    env: {
      PATH: process.env.PATH,
      PGHOST: required("PRICE_RECON_PGHOST"),
      PGPORT: port(),
      PGUSER: required("PRICE_RECON_PGUSER"),
      PGDATABASE: required("PRICE_RECON_PGDATABASE"),
      PGPASSFILE: passFile(),
    },
  });
  if (result.error || result.status !== 0) fail(result.error ? `psql is unavailable: ${result.error.message}` : "price/cache reconciliation query failed", 1);

  const receipt = parseReceipt(String(result.stdout));
  const aggregate = record(receipt.aggregate_counts, "aggregate_counts");
  const provenance = record(receipt.historical_provenance_coverage, "historical_provenance_coverage");
  const differences = record(receipt.amount_differences, "amount_differences");
  const duplicate = record(receipt.duplicate_billing_check, "duplicate_billing_check");
  const checks: [string, boolean][] = [
    ["empty_provenance", aggregate.provenance_events === "0"],
    ["missing_current_price_combinations", nonZero(aggregate.missing_current_price_combinations, "missing_current_price_combinations")],
  ];
  checks.push(
    ...Object.entries(provenance).map(([name, value]): [string, boolean] => [name, nonZero(value, name)]),
    ...Object.entries(differences).map(([name, value]): [string, boolean] => [name, nonZero(value, name)]),
    ...Object.entries(duplicate).map(([name, value]): [string, boolean] => [name, nonZero(value, name)]),
  );
  const blockers = checks.filter(([, blocked]) => blocked).map(([name]) => name);

  process.stdout.write(`${JSON.stringify({
    schema: "mtc-final-price-cache-reconciliation-receipt-v1",
    mode: "dry-run",
    snapshot: { isolation: "repeatable-read", access: "read-only", statement_timeout_ms: timeout },
    scope: {
      tenant_external_id_sha256: sha256(tenant),
      import_source_sha256: sha256(source),
      currency,
    },
    outcome: blockers.length === 0 ? "pass" : "blocked",
    blockers,
    receipt,
  })}\n`);
  if (blockers.length > 0) process.exitCode = 1;
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : "price/cache reconciliation failed"}\n`);
  process.exitCode = error instanceof CliError ? error.exitCode : 1;
}
