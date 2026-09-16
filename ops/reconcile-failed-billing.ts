#!/usr/bin/env node
/**
 * Read-only failed-request billing audit and zero-cost repair plan.
 *
 * The command deliberately does not mutate a database.  It identifies only
 * terminal non-success text requests that were charged from a contract
 * ceiling, have no response archive evidence, and still satisfy every
 * reservation/ledger/fact/feed invariant required by the reviewed correction
 * endpoint.  A later operator workflow can replay the emitted plan through
 * the settlement-adjustment API; nullable historical usage basis is reported
 * separately and is never inferred here.
 */

import { accessSync, constants as fsConstants, lstatSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { invokedAsEntrypoint } from "./lib/invoked-as-entrypoint.ts";

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

function optional(name: string): string {
  const value = process.env[name] ?? "";
  if (value.includes("\0") || /[\r\n]/u.test(value)) fail(`${name} must be a single line`);
  return value;
}

function positiveInteger(name: string, fallback: string): string {
  const value = process.env[name] ?? fallback;
  if (!/^\d+$/u.test(value) || BigInt(value) === 0n) fail(`${name} must be a positive integer`);
  return value;
}

function port(): string {
  const value = positiveInteger("FAILED_BILLING_PGPORT", "5432");
  if (BigInt(value) > 65535n) fail("FAILED_BILLING_PGPORT must be at most 65535");
  return value;
}

function passFile(): string {
  const value = required("FAILED_BILLING_PGPASSFILE");
  try {
    const metadata = lstatSync(value);
    accessSync(value, fsConstants.R_OK);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      fail("FAILED_BILLING_PGPASSFILE must be a readable regular non-symlink file");
    }
    if ((metadata.mode & 0o777) !== 0o600) {
      fail("FAILED_BILLING_PGPASSFILE must have mode 0600");
    }
  } catch (error) {
    if (error instanceof CliError) throw error;
    fail("FAILED_BILLING_PGPASSFILE must be a readable regular non-symlink file");
  }
  return value;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function parseArguments(arguments_: readonly string[]): void {
  if (arguments_.length === 0 || (arguments_.length === 1 && arguments_[0] === "--dry-run")) return;
  if (arguments_.length === 1 && arguments_[0] === "--help") {
    process.stdout.write(
      "Usage: node ops/reconcile-failed-billing.ts [--dry-run]\n"
        + "Required env: FAILED_BILLING_FROM_LOCAL, FAILED_BILLING_TO_LOCAL, FAILED_BILLING_TIME_ZONE, "
        + "FAILED_BILLING_PGHOST, FAILED_BILLING_PGUSER, FAILED_BILLING_PGDATABASE, FAILED_BILLING_PGPASSFILE\n",
    );
    process.exit(0);
  }
  fail("this audit is read-only; only --dry-run is accepted");
}

function validateTimestamp(name: string, value: string): void {
  if (!/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?$/u.test(value)) {
    fail(`${name} must be an ISO local timestamp without an offset`);
  }
}

function validateTimeZone(value: string): void {
  // PostgreSQL owns the authoritative IANA/TZ validation.  This check only
  // prevents psql variable syntax from being used as an input channel.
  if (!/^[A-Za-z0-9_+./:-]+$/u.test(value)) fail("FAILED_BILLING_TIME_ZONE contains invalid characters");
}

const auditSql = String.raw`
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = :'statement_timeout';
WITH params AS MATERIALIZED (
  SELECT
    (:'from_local'::timestamp AT TIME ZONE :'time_zone') AS from_instant,
    (:'to_local'::timestamp AT TIME ZONE :'time_zone') AS to_instant,
    (extract(epoch FROM (:'from_local'::timestamp AT TIME ZONE :'time_zone')) * 1000)::bigint AS from_created_at,
    (extract(epoch FROM (:'to_local'::timestamp AT TIME ZONE :'time_zone')) * 1000)::bigint AS to_created_at,
    :'tenant_external_id'::text AS tenant_external_id
), selected_tenant AS MATERIALIZED (
  SELECT id FROM tenants WHERE external_id = (SELECT tenant_external_id FROM params)
), scoped AS MATERIALIZED (
  SELECT r.id AS request_id,
         r.tenant_id,
         r.key_id,
         r.created_at,
         r.completed_at,
         r.protocol,
         r.model,
         r.status_code,
         COALESCE(r.error_code, '') AS error_code,
         r.usage_basis,
         r.cost_micros,
         r.currency,
         r.input_tokens,
         r.cached_input_tokens,
         r.cache_write_tokens,
         r.output_tokens,
         r.response_object,
         r.reservation_id,
         u.account_id,
         u.status AS reservation_status,
         u.actual_micros,
         u.reserved_micros,
         u.reserved_tokens,
         u.enforcement_mode,
         f.cost_micros AS fact_cost_micros,
         f.input_tokens AS fact_input_tokens,
         f.cached_input_tokens AS fact_cached_input_tokens,
         f.cache_write_tokens AS fact_cache_write_tokens,
         f.output_tokens AS fact_output_tokens,
         feed.settlement_id AS feed_settlement_id,
         feed.account_id AS feed_account_id,
         feed.key_id AS feed_key_id,
         feed.cost_micros AS feed_cost_micros,
         feed.currency AS feed_currency,
         feed.usage_basis AS feed_usage_basis,
         response_spool.state AS response_spool_state,
         response_spool.chunk_count AS response_chunk_count,
         response_spool.byte_count AS response_byte_count,
         response_spool.bound_locator AS response_bound_locator,
         response_spool.last_error_code AS response_spool_error,
         request_spool.state AS request_spool_state,
         CASE
           WHEN response_spool.state IS NOT NULL THEN response_spool.state
           WHEN r.response_object IS NULL OR r.response_object LIKE 'gap://%' THEN 'gap'
           ELSE 'bound'
         END AS response_archive_state,
         CASE
           WHEN response_spool.state = 'bound'
                AND r.response_object IS NOT NULL
                AND r.response_object NOT LIKE 'gap://%' THEN 1
           WHEN response_spool.state IS NULL
                AND r.response_object IS NOT NULL
                AND r.response_object NOT LIKE 'gap://%' THEN 1
           ELSE 0
         END AS response_available,
         (SELECT count(*)
            FROM ledger_entries ledger
           WHERE ledger.account_id = u.account_id
             AND ledger.key_id = u.key_id
             AND ledger.kind = 'usage'
             AND ledger.source = u.id) AS usage_ledger_count,
         (SELECT min(ledger.id)
            FROM ledger_entries ledger
           WHERE ledger.account_id = u.account_id
             AND ledger.key_id = u.key_id
             AND ledger.kind = 'usage'
             AND ledger.source = u.id) AS usage_ledger_entry_id,
         (SELECT min(ledger.amount_micros)
            FROM ledger_entries ledger
           WHERE ledger.account_id = u.account_id
             AND ledger.key_id = u.key_id
             AND ledger.kind = 'usage'
             AND ledger.source = u.id) AS usage_ledger_amount,
         (SELECT min(ledger.currency)
            FROM ledger_entries ledger
           WHERE ledger.account_id = u.account_id
             AND ledger.key_id = u.key_id
             AND ledger.kind = 'usage'
             AND ledger.source = u.id) AS usage_ledger_currency
    FROM request_records r
    JOIN usage_reservations u ON u.id = r.reservation_id
    LEFT JOIN request_stats_facts f ON f.request_id = r.id
    LEFT JOIN account_settlement_feed feed
           ON feed.request_kind = 'text' AND feed.request_id = r.id
    LEFT JOIN response_archive_spools response_spool
           ON response_spool.request_id = r.id
          AND response_spool.tenant_id = r.tenant_id
          AND response_spool.reservation_id = r.reservation_id
    LEFT JOIN request_archive_spools request_spool
           ON request_spool.request_id = r.id
          AND request_spool.tenant_id = r.tenant_id
          AND request_spool.reservation_id = r.reservation_id
   CROSS JOIN params p
   WHERE r.created_at >= p.from_created_at
     AND r.created_at < p.to_created_at
     AND (
       p.tenant_external_id = ''
       OR r.tenant_id = (SELECT id FROM selected_tenant)
     )
), evaluated AS MATERIALIZED (
  SELECT s.*,
         s.status_code IS NOT NULL AND s.status_code NOT BETWEEN 200 AND 399 AS failed,
         s.cost_micros > 0 AS nonzero_cost,
         s.usage_basis = 'contract_ceiling' AS contract_ceiling,
         s.fact_cost_micros IS NOT NULL AND s.fact_cost_micros = s.cost_micros AS fact_matches,
         s.reservation_status = 'settled' AND s.actual_micros = s.cost_micros AS reservation_matches,
         s.usage_ledger_count = 1
           AND s.usage_ledger_amount = -s.cost_micros
           AND s.usage_ledger_currency = s.currency AS ledger_matches,
         s.feed_settlement_id IS NOT NULL
           AND s.feed_account_id = s.account_id
           AND s.feed_key_id = s.key_id
           AND s.feed_cost_micros = s.cost_micros
           AND s.feed_currency = s.currency
           AND s.feed_usage_basis = 'contract_ceiling' AS feed_matches,
         s.response_available = 0 AND s.response_archive_state = 'gap' AS response_unobserved,
         s.status_code IS NOT NULL
           AND s.status_code NOT BETWEEN 200 AND 399
           AND s.cost_micros > 0
           AND s.usage_basis = 'contract_ceiling'
           AND s.protocol <> 'audio-transcription'
           AND s.fact_cost_micros IS NOT NULL AND s.fact_cost_micros = s.cost_micros
           AND s.reservation_status = 'settled' AND s.actual_micros = s.cost_micros
           AND s.usage_ledger_count = 1
           AND s.usage_ledger_amount = -s.cost_micros
           AND s.usage_ledger_currency = s.currency
           AND s.feed_settlement_id IS NOT NULL
           AND s.feed_account_id = s.account_id
           AND s.feed_key_id = s.key_id
           AND s.feed_cost_micros = s.cost_micros
           AND s.feed_currency = s.currency
           AND s.feed_usage_basis = 'contract_ceiling'
           AND s.response_available = 0
           AND s.response_archive_state = 'gap' AS repair_eligible
    FROM scoped s
), history_failed_nonzero AS MATERIALIZED (
  SELECT COALESCE(NULLIF(r.usage_basis, ''), '<null>') AS usage_basis,
         r.status_code,
         COALESCE(r.error_code, '') AS error_code,
         count(*) AS request_count,
         COALESCE(sum(r.cost_micros), 0) AS cost_micros,
         min(r.created_at) AS first_created_at,
         max(r.created_at) AS last_created_at
    FROM request_records r
    CROSS JOIN params p
   WHERE r.status_code IS NOT NULL
     AND r.status_code NOT BETWEEN 200 AND 399
     AND r.cost_micros > 0
     AND (
       p.tenant_external_id = ''
       OR r.tenant_id = (SELECT id FROM selected_tenant)
     )
   GROUP BY COALESCE(NULLIF(r.usage_basis, ''), '<null>'), r.status_code, COALESCE(r.error_code, '')
), history_contract_archive AS MATERIALIZED (
  SELECT COALESCE(e.response_archive_state, 'unknown') AS response_archive_state,
         count(*) AS request_count,
         COALESCE(sum(r.cost_micros), 0) AS cost_micros
    FROM request_records r
    JOIN usage_reservations u ON u.id = r.reservation_id
    LEFT JOIN response_archive_spools spool
           ON spool.request_id = r.id
          AND spool.tenant_id = r.tenant_id
          AND spool.reservation_id = r.reservation_id
    CROSS JOIN params p
    LEFT JOIN LATERAL (
      SELECT CASE
               WHEN spool.state IS NOT NULL THEN spool.state
               WHEN r.response_object IS NULL OR r.response_object LIKE 'gap://%' THEN 'gap'
               ELSE 'bound'
             END AS response_archive_state
    ) e ON true
   WHERE r.status_code IS NOT NULL
     AND r.status_code NOT BETWEEN 200 AND 399
     AND r.cost_micros > 0
     AND r.usage_basis = 'contract_ceiling'
     AND (
       p.tenant_external_id = ''
       OR r.tenant_id = (SELECT id FROM selected_tenant)
     )
   GROUP BY COALESCE(e.response_archive_state, 'unknown')
), facts_source AS MATERIALIZED (
  SELECT count(e.fact_cost_micros) AS fact_rows,
         COALESCE(sum(e.fact_cost_micros), 0) AS fact_cost_micros,
         count(*) FILTER (WHERE e.fact_cost_micros IS NULL) AS missing_fact_rows,
         count(*) FILTER (WHERE e.fact_cost_micros IS NOT NULL AND e.fact_cost_micros <> e.cost_micros) AS fact_mismatch_rows
    FROM evaluated e
), settlement_source AS MATERIALIZED (
  SELECT count(feed.settlement_id) AS settlement_rows,
         COALESCE(sum(feed.cost_micros), 0) AS settlement_cost_micros,
         count(*) FILTER (WHERE feed.request_id IS NULL) AS missing_settlement_rows
    FROM evaluated e
    LEFT JOIN account_settlement_feed feed
      ON feed.request_kind = 'text' AND feed.request_id = e.request_id
), daily_source AS MATERIALIZED (
  SELECT count(*) AS aggregate_rows, COALESCE(sum(a.cost_micros), 0) AS aggregate_cost_micros
    FROM request_daily_aggregates a
    CROSS JOIN params p
   WHERE a.day_bucket >= p.from_created_at / 86400000
     AND a.day_bucket <= (p.to_created_at - 1) / 86400000
     AND (
       p.tenant_external_id = ''
       OR a.tenant_id = (SELECT id FROM selected_tenant)
     )
), hourly_source AS MATERIALIZED (
  SELECT count(*) AS aggregate_rows, COALESCE(sum(a.cost_micros), 0) AS aggregate_cost_micros
    FROM usage_analysis_hourly a
    CROSS JOIN params p
   WHERE a.source_kind = 'request'
     AND a.hour_bucket >= p.from_created_at / 3600000
     AND a.hour_bucket <= (p.to_created_at - 1) / 3600000
     AND (
       p.tenant_external_id = ''
       OR a.tenant_id = (SELECT id FROM selected_tenant)
     )
), historical_summary AS MATERIALIZED (
  SELECT
    COALESCE(sum(request_count) FILTER (WHERE usage_basis = 'contract_ceiling'), 0) AS contract_failure_rows,
    COALESCE(sum(cost_micros) FILTER (WHERE usage_basis = 'contract_ceiling'), 0) AS contract_failure_cost_micros,
    COALESCE(sum(request_count) FILTER (WHERE usage_basis = '<null>'), 0) AS null_basis_failure_rows,
    COALESCE(sum(cost_micros) FILTER (WHERE usage_basis = '<null>'), 0) AS null_basis_failure_cost_micros,
    COALESCE(sum(request_count), 0) AS all_failed_nonzero_rows,
    COALESCE(sum(cost_micros), 0) AS all_failed_nonzero_cost_micros
  FROM history_failed_nonzero
), measured AS MATERIALIZED (
  SELECT
    count(*) AS scoped_rows,
    COALESCE(sum(e.cost_micros), 0) AS scoped_cost_micros,
    count(*) FILTER (WHERE e.failed) AS failed_rows,
    COALESCE(sum(e.cost_micros) FILTER (WHERE e.failed), 0) AS failed_cost_micros,
    count(*) FILTER (WHERE e.repair_eligible) AS repair_eligible_rows,
    COALESCE(sum(e.cost_micros) FILTER (WHERE e.repair_eligible), 0) AS repair_eligible_cost_micros,
    count(*) FILTER (WHERE e.failed AND e.nonzero_cost AND e.usage_basis IS NULL) AS nullable_basis_failed_rows,
    COALESCE(sum(e.cost_micros) FILTER (WHERE e.failed AND e.nonzero_cost AND e.usage_basis IS NULL), 0) AS nullable_basis_failed_cost_micros,
    count(*) FILTER (WHERE e.failed AND e.nonzero_cost AND e.usage_basis = 'contract_ceiling' AND NOT e.repair_eligible) AS manual_contract_rows,
    COALESCE(sum(e.cost_micros) FILTER (WHERE e.failed AND e.nonzero_cost AND e.usage_basis = 'contract_ceiling' AND NOT e.repair_eligible), 0) AS manual_contract_cost_micros,
    count(*) FILTER (WHERE e.failed AND e.nonzero_cost AND e.usage_basis IN ('provider_reported', 'provider_estimated')) AS evidence_preserved_rows,
    COALESCE(sum(e.cost_micros) FILTER (WHERE e.failed AND e.nonzero_cost AND e.usage_basis IN ('provider_reported', 'provider_estimated')), 0) AS evidence_preserved_cost_micros
  FROM evaluated e
)
SELECT jsonb_build_object(
  'scope', jsonb_build_object(
    'from_local', :'from_local',
    'to_local_exclusive', :'to_local',
    'time_zone', :'time_zone',
    'from_created_at', (SELECT from_created_at::text FROM params),
    'to_created_at_exclusive', (SELECT to_created_at::text FROM params),
    'tenant_external_id_sha256', CASE WHEN :'tenant_external_id' = '' THEN NULL ELSE encode(sha256(convert_to(:'tenant_external_id', 'UTF8')), 'hex') END
  ),
  'interval_summary', jsonb_build_object(
    'scoped_rows', measured.scoped_rows::text,
    'scoped_cost_micros', measured.scoped_cost_micros::text,
    'failed_rows', measured.failed_rows::text,
    'failed_cost_micros', measured.failed_cost_micros::text,
    'repair_eligible_rows', measured.repair_eligible_rows::text,
    'repair_eligible_cost_micros', measured.repair_eligible_cost_micros::text,
    'nullable_basis_failed_rows', measured.nullable_basis_failed_rows::text,
    'nullable_basis_failed_cost_micros', measured.nullable_basis_failed_cost_micros::text,
    'manual_contract_rows', measured.manual_contract_rows::text,
    'manual_contract_cost_micros', measured.manual_contract_cost_micros::text,
    'evidence_preserved_rows', measured.evidence_preserved_rows::text,
    'evidence_preserved_cost_micros', measured.evidence_preserved_cost_micros::text,
    'by_usage_basis', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'usage_basis', grouped.usage_basis,
        'request_count', grouped.request_count::text,
        'cost_micros', grouped.cost_micros::text
      ) ORDER BY grouped.usage_basis)
      FROM (
        SELECT COALESCE(NULLIF(e.usage_basis, ''), '<null>') AS usage_basis,
               count(*) AS request_count,
               COALESCE(sum(e.cost_micros), 0) AS cost_micros
          FROM evaluated e
         GROUP BY COALESCE(NULLIF(e.usage_basis, ''), '<null>')
      ) grouped
    ), '[]'::jsonb),
    'by_status_error', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'status_code', grouped.status_code::text,
        'error_code', grouped.error_code,
        'usage_basis', grouped.usage_basis,
        'request_count', grouped.request_count::text,
        'cost_micros', grouped.cost_micros::text
      ) ORDER BY grouped.status_code, grouped.error_code, grouped.usage_basis)
      FROM (
        SELECT e.status_code,
               e.error_code,
               COALESCE(e.usage_basis, '<null>') AS usage_basis,
               count(*) AS request_count,
               COALESCE(sum(e.cost_micros), 0) AS cost_micros
          FROM evaluated e
         GROUP BY e.status_code, e.error_code, COALESCE(e.usage_basis, '<null>')
      ) grouped
    ), '[]'::jsonb)
  ),
  'repair_candidates', COALESCE((
    SELECT jsonb_agg(jsonb_build_object(
      'request_id', e.request_id,
      'created_at', e.created_at::text,
      'status_code', e.status_code::text,
      'error_code', e.error_code,
      'protocol', e.protocol,
      'model', e.model,
      'currency', e.currency,
      'reservation_id', e.reservation_id,
      'account_id', e.account_id,
      'key_id', e.key_id,
      'settlement_id', e.feed_settlement_id,
      'usage_ledger_entry_id', e.usage_ledger_entry_id,
      'old', jsonb_build_object(
        'usage_basis', e.usage_basis,
        'cost_micros', e.cost_micros::text,
        'input_tokens', e.input_tokens::text,
        'cached_input_tokens', e.cached_input_tokens::text,
        'cache_write_tokens', e.cache_write_tokens::text,
        'output_tokens', e.output_tokens::text
      ),
      'proposed', jsonb_build_object(
        'usage_basis', 'not_observed',
        'cost_micros', '0',
        'input_tokens', '0',
        'cached_input_tokens', '0',
        'cache_write_tokens', '0',
        'output_tokens', '0'
      ),
      'provider_evidence', 'none_observed',
      'archive', jsonb_build_object(
        'response_state', e.response_archive_state,
        'response_available', (e.response_available = 1),
        'response_chunk_count', COALESCE(e.response_chunk_count, 0)::text,
        'response_byte_count', COALESCE(e.response_byte_count, 0)::text,
        'response_bound_locator_present', (e.response_bound_locator IS NOT NULL),
        'request_state', e.request_spool_state
      ),
      'invariants', jsonb_build_object(
        'reservation_settled', (e.reservation_status = 'settled'),
        'reservation_actual_matches_cost', e.reservation_matches,
        'usage_ledger_unique', (e.usage_ledger_count = 1),
        'usage_ledger_matches_cost', e.ledger_matches,
        'settlement_feed_matches_cost', e.feed_matches,
        'request_stats_fact_matches_cost', e.fact_matches
      ),
      'repair', jsonb_build_object(
        'action', 'settlement_adjustment_rebate',
        'desired_rebate_micros', e.cost_micros::text,
        'idempotency_key', 'failed-billing-zero-v1:' || e.request_id,
        'reversible', true,
        'requires_manual_confirmation', true
      )
    ) ORDER BY e.created_at, e.request_id)
    FROM evaluated e WHERE e.repair_eligible
  ), '[]'::jsonb),
  'manual_review', jsonb_build_object(
    'contract_ceiling_archive_states', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'response_archive_state', response_archive_state,
        'request_count', request_count::text,
        'cost_micros', cost_micros::text
      ) ORDER BY response_archive_state)
      FROM history_contract_archive
    ), '[]'::jsonb),
    'nullable_basis_failed_nonzero_in_interval', measured.nullable_basis_failed_rows::text,
    'nullable_basis_failed_nonzero_cost_micros_in_interval', measured.nullable_basis_failed_cost_micros::text,
    'manual_contract_rows_in_interval', measured.manual_contract_rows::text,
    'manual_contract_cost_micros_in_interval', measured.manual_contract_cost_micros::text,
    'evidence_preserved_rows_in_interval', measured.evidence_preserved_rows::text,
    'evidence_preserved_cost_micros_in_interval', measured.evidence_preserved_cost_micros::text
  ),
  'historical_dirty_data', jsonb_build_object(
    'failed_nonzero_rows', historical_summary.all_failed_nonzero_rows::text,
    'failed_nonzero_cost_micros', historical_summary.all_failed_nonzero_cost_micros::text,
    'contract_ceiling_rows', historical_summary.contract_failure_rows::text,
    'contract_ceiling_cost_micros', historical_summary.contract_failure_cost_micros::text,
    'nullable_basis_rows', historical_summary.null_basis_failure_rows::text,
    'nullable_basis_cost_micros', historical_summary.null_basis_failure_cost_micros::text,
    'by_status_error_basis', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'usage_basis', usage_basis,
        'status_code', status_code::text,
        'error_code', error_code,
        'request_count', request_count::text,
        'cost_micros', cost_micros::text,
        'first_created_at', first_created_at::text,
        'last_created_at', last_created_at::text
      ) ORDER BY usage_basis, status_code, error_code)
      FROM history_failed_nonzero
    ), '[]'::jsonb)
  ),
  'statistics_sources', jsonb_build_object(
    'request_stats_facts', jsonb_build_object(
      'rows', (SELECT fact_rows::text FROM facts_source),
      'cost_micros', (SELECT fact_cost_micros::text FROM facts_source),
      'missing_rows', (SELECT missing_fact_rows::text FROM facts_source),
      'mismatch_rows', (SELECT fact_mismatch_rows::text FROM facts_source)
    ),
    'account_settlement_feed', jsonb_build_object(
      'rows', (SELECT settlement_rows::text FROM settlement_source),
      'cost_micros', (SELECT settlement_cost_micros::text FROM settlement_source),
      'missing_rows', (SELECT missing_settlement_rows::text FROM settlement_source)
    ),
    'request_daily_aggregates', jsonb_build_object(
      'bucket_rows', (SELECT aggregate_rows::text FROM daily_source),
      'bucket_cost_micros', (SELECT aggregate_cost_micros::text FROM daily_source),
      'note', 'day buckets overlap the requested interval at both edges'
    ),
    'usage_analysis_hourly_request', jsonb_build_object(
      'bucket_rows', (SELECT aggregate_rows::text FROM hourly_source),
      'bucket_cost_micros', (SELECT aggregate_cost_micros::text FROM hourly_source),
      'note', 'hour buckets overlap the requested interval at both edges'
    )
  )
)
FROM measured, historical_summary;
COMMIT;
`;

type JsonRecord = Record<string, unknown>;

function record(value: unknown, name: string): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`psql receipt has invalid ${name}`, 1);
  }
  return value as JsonRecord;
}

function numericString(value: unknown, name: string): string {
  if (typeof value !== "string" || !/^-?\d+$/u.test(value)) fail(`psql receipt has invalid ${name}`, 1);
  return value;
}

function parseReceipt(output: string): JsonRecord {
  const outputLine = output.trim();
  if (!outputLine || outputLine.includes("\n")) fail("failed-billing query returned invalid receipt output", 1);
  let parsed: unknown;
  try {
    parsed = JSON.parse(outputLine);
  } catch {
    fail("failed-billing query returned invalid JSON receipt", 1);
  }
  const receipt = record(parsed, "root");
  const summary = record(receipt.interval_summary, "interval_summary");
  const historical = record(receipt.historical_dirty_data, "historical_dirty_data");
  const stats = record(receipt.statistics_sources, "statistics_sources");
  for (const [name, value] of Object.entries(summary)) {
    if (name === "by_usage_basis" || name === "by_status_error") continue;
    numericString(value, `interval_summary.${name}`);
  }
  for (const name of ["failed_nonzero_rows", "failed_nonzero_cost_micros", "contract_ceiling_rows", "contract_ceiling_cost_micros", "nullable_basis_rows", "nullable_basis_cost_micros"]) {
    numericString(historical[name], `historical_dirty_data.${name}`);
  }
  for (const [sourceName, sourceValue] of Object.entries(stats)) {
    const source = record(sourceValue, `statistics_sources.${sourceName}`);
    for (const [field, value] of Object.entries(source)) {
      if (field === "note") continue;
      numericString(value, `statistics_sources.${sourceName}.${field}`);
    }
  }
  if (!Array.isArray(receipt.repair_candidates)) fail("psql receipt has invalid repair_candidates", 1);
  if (!Array.isArray(record(receipt.manual_review, "manual_review").contract_ceiling_archive_states)) {
    fail("psql receipt has invalid manual_review.contract_ceiling_archive_states", 1);
  }
  return receipt;
}

function main(): void {
  parseArguments(process.argv.slice(2));
  const fromLocal = required("FAILED_BILLING_FROM_LOCAL");
  const toLocal = required("FAILED_BILLING_TO_LOCAL");
  const timeZone = required("FAILED_BILLING_TIME_ZONE");
  validateTimestamp("FAILED_BILLING_FROM_LOCAL", fromLocal);
  validateTimestamp("FAILED_BILLING_TO_LOCAL", toLocal);
  if (fromLocal >= toLocal) fail("FAILED_BILLING_TO_LOCAL must be after FAILED_BILLING_FROM_LOCAL");
  validateTimeZone(timeZone);
  const tenant = optional("FAILED_BILLING_TENANT_EXTERNAL_ID");
  const timeout = positiveInteger("FAILED_BILLING_STATEMENT_TIMEOUT_MS", "30000");
  const result = spawnSync("psql", [
    "-X", "--no-psqlrc", "-qAt", "-v", "ON_ERROR_STOP=1",
    "-v", `from_local=${fromLocal}`,
    "-v", `to_local=${toLocal}`,
    "-v", `time_zone=${timeZone}`,
    "-v", `tenant_external_id=${tenant}`,
    "-v", `statement_timeout=${timeout}ms`,
  ], {
    encoding: "utf8",
    input: auditSql,
    shell: false,
    stdio: ["pipe", "pipe", "inherit"],
    env: {
      PATH: process.env.PATH,
      PGHOST: required("FAILED_BILLING_PGHOST"),
      PGPORT: port(),
      PGUSER: required("FAILED_BILLING_PGUSER"),
      PGDATABASE: required("FAILED_BILLING_PGDATABASE"),
      PGPASSFILE: passFile(),
    },
  });
  if (result.error || result.status !== 0) {
    fail(result.error ? `psql is unavailable: ${result.error.message}` : "failed-billing audit query failed", 1);
  }
  const receipt = parseReceipt(String(result.stdout));
  const summary = record(receipt.interval_summary, "interval_summary");
  const historical = record(receipt.historical_dirty_data, "historical_dirty_data");
  const candidates = receipt.repair_candidates as unknown[];
  process.stdout.write(`${JSON.stringify({
    schema: "mtc-failed-billing-reconciliation-receipt-v1",
    mode: "dry-run",
    outcome: candidates.length === 0 ? "reviewed_no_safe_candidates" : "review_required",
    snapshot: { isolation: "repeatable-read", access: "read-only", statement_timeout_ms: timeout },
    scope: receipt.scope,
    policy: {
      failed_status_default_cost_micros: "0",
      allowed_provider_evidence_basis: ["provider_reported", "provider_estimated"],
      auto_candidate_basis: "contract_ceiling",
      nullable_basis_is_manual_only: true,
      response_archive_gap_required: true,
      production_write_performed: false,
    },
    impact: {
      interval_repair_eligible_rows: summary.repair_eligible_rows,
      interval_repair_eligible_cost_micros: summary.repair_eligible_cost_micros,
      historical_contract_ceiling_failed_rows: historical.contract_ceiling_rows,
      historical_contract_ceiling_failed_cost_micros: historical.contract_ceiling_cost_micros,
      historical_nullable_basis_failed_rows: historical.nullable_basis_rows,
      historical_nullable_basis_failed_cost_micros: historical.nullable_basis_cost_micros,
    },
    receipt,
  })}\n`);
}

if (invokedAsEntrypoint("reconcile-failed-billing", import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "failed-billing audit failed"}\n`);
    process.exitCode = error instanceof CliError ? error.exitCode : 1;
  }
}
