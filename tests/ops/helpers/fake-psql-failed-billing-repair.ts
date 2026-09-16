#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const chunks: Buffer[] = [];
for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
const sql = Buffer.concat(chunks).toString("utf8");
if (!sql.includes("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
  || !sql.includes("repair_eligible")
  || !sql.includes("history_failed_nonzero")
  || !sql.includes("usage_analysis_hourly")
  || /\b(?:INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|LOCK)\b/u.test(sql)) process.exit(9);

const passFile = process.env.PGPASSFILE;
if (passFile === undefined) process.exit(9);
writeFileSync(join(dirname(passFile), "psql.json"), JSON.stringify({ argv: process.argv.slice(2), sql, pgpassfile: passFile }));
process.stdout.write(`${JSON.stringify({
  scope: {
    from_local: "2026-09-16 11:00:00",
    to_local_exclusive: "2026-09-16 13:00:00",
    time_zone: "Asia/Shanghai",
    from_created_at: "1789556400000",
    to_created_at_exclusive: "1789563600000",
    tenant_external_id_sha256: "a".repeat(64),
  },
  interval_summary: {
    scoped_rows: "2",
    scoped_cost_micros: "5937130",
    failed_rows: "2",
    failed_cost_micros: "5937130",
    repair_eligible_rows: "1",
    repair_eligible_cost_micros: "5937130",
    nullable_basis_failed_rows: "0",
    nullable_basis_failed_cost_micros: "0",
    manual_contract_rows: "1",
    manual_contract_cost_micros: "100",
    evidence_preserved_rows: "0",
    evidence_preserved_cost_micros: "0",
    by_usage_basis: [],
    by_status_error: [],
  },
  repair_candidates: [{
    request_id: "01a0a894-ba5b-7a02-9031-f904c7761ecf",
    created_at: "1789559914858",
    status_code: "502",
    error_code: "upstream_stream",
    protocol: "openai",
    model: "gpt-5.6-terra",
    currency: "USD",
    reservation_id: "01a0a894-bb70-7881-96c8-3ec65f033c66",
    account_id: "01a0a894-bc00-7881-96c8-3ec65f033c66",
    key_id: "01a0a894-bc00-7881-96c8-3ec65f033c66",
    settlement_id: "01a0a895-4328-7ef1-a84e-7d8f23228730",
    usage_ledger_entry_id: "01a0a895-4328-7ef1-a84e-7d8f23228730",
    old: { usage_basis: "contract_ceiling", cost_micros: "5937130", input_tokens: "1069252", cached_input_tokens: "0", cache_write_tokens: "0", output_tokens: "272000" },
    proposed: { usage_basis: "not_observed", cost_micros: "0", input_tokens: "0", cached_input_tokens: "0", cache_write_tokens: "0", output_tokens: "0" },
    provider_evidence: "none_observed",
    archive: { response_state: "gap", response_available: false, response_chunk_count: "1", response_byte_count: "65536", response_bound_locator_present: false, request_state: "bound" },
    invariants: { reservation_settled: true, reservation_actual_matches_cost: true, usage_ledger_unique: true, usage_ledger_matches_cost: true, settlement_feed_matches_cost: true, request_stats_fact_matches_cost: true },
    repair: { action: "settlement_adjustment_rebate", desired_rebate_micros: "5937130", idempotency_key: "failed-billing-zero-v1:01a0a894-ba5b-7a02-9031-f904c7761ecf", reversible: true, requires_manual_confirmation: true },
  }],
  manual_review: { contract_ceiling_archive_states: [{ response_archive_state: "bound", request_count: "1", cost_micros: "100" }], nullable_basis_failed_nonzero_in_interval: "0", nullable_basis_failed_nonzero_cost_micros_in_interval: "0", manual_contract_rows_in_interval: "1", manual_contract_cost_micros_in_interval: "100", evidence_preserved_rows_in_interval: "0", evidence_preserved_cost_micros_in_interval: "0" },
  historical_dirty_data: { failed_nonzero_rows: "3", failed_nonzero_cost_micros: "6037130", contract_ceiling_rows: "2", contract_ceiling_cost_micros: "5937230", nullable_basis_rows: "1", nullable_basis_cost_micros: "9900", by_status_error_basis: [] },
  statistics_sources: {
    request_stats_facts: { rows: "2", cost_micros: "5937130", missing_rows: "0", mismatch_rows: "0" },
    account_settlement_feed: { rows: "2", cost_micros: "5937130", missing_rows: "0" },
    request_daily_aggregates: { bucket_rows: "1", bucket_cost_micros: "5937130", note: "day buckets overlap the requested interval at both edges" },
    usage_analysis_hourly_request: { bucket_rows: "2", bucket_cost_micros: "5937130", note: "hour buckets overlap the requested interval at both edges" },
  },
})}\n`);
