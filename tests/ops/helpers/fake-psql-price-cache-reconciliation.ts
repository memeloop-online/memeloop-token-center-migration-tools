#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const chunks: Buffer[] = [];
for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
const sql = Buffer.concat(chunks).toString("utf8");
if (!sql.includes("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
  || !sql.includes("missing_current_price_combinations")
  || /\b(?:INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|LOCK)\b/u.test(sql)) process.exit(9);

const passFile = process.env.PGPASSFILE;
if (passFile === undefined) process.exit(9);
let fixture: unknown;
try {
  fixture = JSON.parse(readFileSync(join(dirname(passFile), "price-cache-reconciliation-fixture.json"), "utf8"));
} catch {
  process.exit(9);
}
const fields = typeof fixture === "object" && fixture !== null && !Array.isArray(fixture)
  ? fixture as Record<string, unknown>
  : undefined;
const gapCount = fields?.current_price_gap_count;
const invalidProvenanceOutputTokens = fields?.invalid_provenance_output_tokens;
if (typeof gapCount !== "number" || !Number.isSafeInteger(gapCount) || gapCount < 0
  || typeof invalidProvenanceOutputTokens !== "number" || !Number.isSafeInteger(invalidProvenanceOutputTokens) || invalidProvenanceOutputTokens < 0) process.exit(9);
const zero = "0";
const missing = Array.from({ length: gapCount }, (_, index) => ({
  pricing_model: `fixture-price-gap-${String(index + 1).padStart(2, "0")}`,
  service_tier: index % 2 === 0 ? "default" : "priority",
  events: "1",
  input_tokens: "10",
  cached_input_tokens: "2",
  cache_write_tokens: "1",
  output_tokens: "3",
  historical_cost_micros: "42",
}));
writeFileSync(join(dirname(passFile), "psql.json"), JSON.stringify({ argv: process.argv.slice(2), sql, pgpassfile: passFile }));
process.stdout.write(`${JSON.stringify({
  aggregate_counts: {
    provenance_events: "3", import_links: "3", key_model_day_rows: "2",
    current_price_combinations: String(gapCount + 2),
    missing_current_price_combinations: String(gapCount),
    estimated_cache_price_combinations: zero, correction_revisions: "1",
    persisted_provenance_output_token_rows: zero, derived_provenance_output_token_rows: "3",
  },
  historical_provenance_coverage: {
    provenance_without_link: zero, import_links_without_provenance: zero,
    link_target_mismatches: zero,
    provenance_without_target_request: zero, provenance_without_fact: zero,
    provenance_without_price_snapshot: zero, invalid_cache_partitions: zero,
    invalid_provenance_output_tokens: String(invalidProvenanceOutputTokens),
    request_currency_mismatches: zero,
  },
  amount_differences: {
    request_input_tokens: zero, request_cache_read_tokens: zero,
    request_cache_write_tokens: zero, request_output_tokens: zero,
    request_cost_micros: zero, fact_input_tokens: zero,
    fact_cache_read_tokens: zero, fact_cache_write_tokens: zero,
    fact_output_tokens: zero, fact_cost_micros: zero,
    request_amount_mismatches: zero, fact_amount_mismatches: zero,
  },
  duplicate_billing_check: {
    duplicate_target_requests: zero, duplicate_target_events: zero,
    reservation_identity_mismatches: zero, unexpected_usage_reservations: zero,
    unexpected_usage_ledger_entries: zero,
  },
  missing_current_price_combinations: missing,
  per_key_model_day: [{
    key_ref_sha256: "a".repeat(64), day_bucket: "20400", model: "fixture-model",
    provenance_events: "3", request_rows: "3", fact_rows: "3",
    provenance_input_tokens: "30", provenance_cached_input_tokens: "6",
    provenance_cache_write_tokens: "3", provenance_output_tokens: "9",
    provenance_cost_micros: "126", request_input_delta: zero,
    request_cache_read_delta: zero, request_cache_write_delta: zero,
    request_output_delta: zero, request_cost_delta: zero, fact_input_delta: zero,
    fact_cache_read_delta: zero, fact_cache_write_delta: zero,
    fact_output_delta: zero, fact_cost_delta: zero,
  }],
})}\n`);
