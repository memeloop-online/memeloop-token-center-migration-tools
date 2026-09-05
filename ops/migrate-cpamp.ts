#!/usr/bin/env node
/** Replay-safe CPAMP SQLite to PostgreSQL importer. */

import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import {
  accessSync,
  constants as fsConstants,
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const correctionRevision = "cpamp-cache-pricing-v2";

class CliError extends Error {
  readonly exitCode: number;

  constructor(message: string, exitCode = 2) {
    super(message);
    this.exitCode = exitCode;
  }
}

function fail(message: string): never {
  throw new CliError(message);
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) fail(`${name} is required`);
  return value;
}

function booleanSetting(name: string, fallback: boolean): boolean {
  const raw = process.env[name] ?? String(fallback);
  if (raw !== "true" && raw !== "false") fail(`${name} must be true or false`);
  return raw === "true";
}

function unsignedSetting(name: string, fallback: string): bigint {
  const raw = process.env[name] ?? fallback;
  if (!/^\d+$/.test(raw)) fail(`${name} must be an integer`);
  return BigInt(raw);
}

function correctionModeSetting(): "off" | "plan" | "apply" {
  const raw = process.env.CPAMP_CORRECTION_MODE ?? "off";
  if (raw !== "off" && raw !== "plan" && raw !== "apply") {
    fail("CPAMP_CORRECTION_MODE must be off, plan, or apply");
  }
  return raw;
}

function psqlArgs(extra: readonly string[] = []): string[] {
  return ["-X", "-v", "ON_ERROR_STOP=1", "--no-psqlrc", ...extra];
}

function runPsql(
  extra: readonly string[],
  input?: string,
  output: "capture" | "inherit" | "ignore" = "inherit",
): string {
  const result = spawnSync("psql", psqlArgs(extra), {
    encoding: "utf8",
    env: process.env,
    input,
    shell: false,
    stdio: [input === undefined ? "inherit" : "pipe", output === "capture" ? "pipe" : output, "inherit"],
  });
  if (result.error) fail(`psql is unavailable: ${result.error.message}`);
  if (result.status !== 0) fail("PostgreSQL command failed");
  return output === "capture" ? String(result.stdout).trim() : "";
}

function sqliteColumns(sqlitePath: string, table: string): Set<string> {
  if (!/^[a-z0-9_]+$/.test(table)) fail("invalid SQLite table name");
  const result = spawnSync(
    "sqlite3",
    ["-readonly", "-batch", "-bail", "-noheader", sqlitePath, `SELECT name FROM pragma_table_info('${table}') ORDER BY cid;`],
    { encoding: "utf8", shell: false, stdio: ["ignore", "pipe", "inherit"] },
  );
  if (result.error) fail(`sqlite3 is unavailable: ${result.error.message}`);
  if (result.status !== 0) fail(`unable to inspect CPAMP SQLite table ${table}`);
  return new Set(String(result.stdout).trim().split(/\s+/).filter(Boolean));
}

function requireSqliteColumns(sqlitePath: string, table: string, requiredColumns: readonly string[]): void {
  const present = sqliteColumns(sqlitePath, table);
  if (present.size === 0) fail(`CPAMP source table ${table} is missing`);
  const missing = requiredColumns.filter((column) => !present.has(column));
  if (missing.length > 0) {
    fail(`CPAMP source schema is too old for exact billing (${table} missing: ${missing.join(", ")}); upgrade and finish the CPAMP cache-accounting migration before importing`);
  }
}

async function pipeSqliteCsvToPostgres(
  sqlitePath: string,
  query: string,
  table: string,
  columns: readonly string[],
): Promise<void> {
  if (!/^[a-z0-9_]+$/.test(table) || columns.length === 0 || columns.some((column) => !/^[a-z0-9_]+$/.test(column))) {
    fail("invalid PostgreSQL staging copy contract");
  }
  const target = `${table} (${columns.join(", ")})`;
  const sqlite = spawn("sqlite3", ["-header", "-csv", sqlitePath, query], {
    shell: false,
    stdio: ["ignore", "pipe", "inherit"],
  });
  const postgres = spawn("psql", psqlArgs(["-c", `\\copy ${target} FROM STDIN WITH (FORMAT csv, HEADER true)`]), {
    env: process.env,
    shell: false,
    stdio: ["pipe", "inherit", "inherit"],
  });
  sqlite.stdout.pipe(postgres.stdin);
  const result = await Promise.all([
    new Promise<number>((resolve, reject) => {
      sqlite.once("error", reject);
      sqlite.once("close", (code) => resolve(code ?? 1));
    }),
    new Promise<number>((resolve, reject) => {
      postgres.once("error", reject);
      postgres.once("close", (code) => resolve(code ?? 1));
    }),
  ]).catch((error: unknown) => {
    sqlite.kill("SIGTERM");
    postgres.kill("SIGTERM");
    fail(`SQLite/PostgreSQL streaming copy failed: ${error instanceof Error ? error.message : "unknown error"}`);
  });
  if (result[0] !== 0 || result[1] !== 0) fail("SQLite/PostgreSQL streaming copy failed");
}

function readSql(name: string): string {
  return readFileSync(join(scriptDirectory, "sql", "cpamp", name), "utf8");
}

async function sleep(milliseconds: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function main(): Promise<void> {
  const pgHost = required("PGHOST");
  const pgPort = process.env.PGPORT ?? "5432";
  const pgUser = required("PGUSER");
  const pgDatabase = required("PGDATABASE");
  const sqlitePath = process.env.CPAMP_SQLITE_PATH ?? "/source/usage.sqlite";
  const tenant = process.env.IMPORT_TENANT_EXTERNAL_ID ?? "cpa-dogfood-import";
  const source = process.env.CPAMP_IMPORT_SOURCE ?? "cpamp-usage-events-v1";
  const overlapMs = unsignedSetting("CPAMP_OVERLAP_MS", "86400000");
  const reset = booleanSetting("CPAMP_RESET_IMPORT", false);
  const allowUnmapped = booleanSetting("CPAMP_ALLOW_UNMAPPED", false);
  const correctionMode = correctionModeSetting();

  if (reset && tenant !== "cpa-dogfood-import") fail("reset is only allowed for the cpa-dogfood-import tenant");
  if (reset && process.env.CPAMP_RESET_CONFIRM !== "DELETE_CPA_DOGFOOD_IMPORT") {
    fail("CPAMP_RESET_CONFIRM=DELETE_CPA_DOGFOOD_IMPORT is required for a reset");
  }
  try {
    accessSync(sqlitePath, fsConstants.R_OK);
  } catch {
    fail("CPAMP SQLite database is not readable");
  }
  if (!/^[A-Za-z0-9._:-]+$/.test(source)) fail("CPAMP_IMPORT_SOURCE contains unsupported characters");
  if (correctionMode === "apply" && process.env.CPAMP_CORRECTION_CONFIRM !== "CORRECT_CPAMP_IMPORTED_USAGE") {
    fail("CPAMP_CORRECTION_CONFIRM=CORRECT_CPAMP_IMPORTED_USAGE is required for a correction");
  }

  requireSqliteColumns(sqlitePath, "usage_events", [
    "event_hash", "request_id", "timestamp_ms", "provider", "model", "endpoint",
    "api_key_hash", "requested_model", "resolved_model", "reasoning_effort",
    "service_tier", "request_service_tier", "response_service_tier", "cache_input_mode",
    "input_tokens", "output_tokens", "reasoning_tokens", "cached_tokens", "cache_tokens",
    "cache_read_tokens", "cache_creation_tokens", "normalized_uncached_input_tokens",
    "normalized_total_input_tokens", "normalized_cache_read_tokens",
    "normalized_cache_creation_tokens", "total_tokens", "latency_ms", "ttft_ms", "failed",
    "fail_status_code", "fail_summary",
  ]);
  requireSqliteColumns(sqlitePath, "api_key_aliases", ["api_key_hash", "alias", "updated_at_ms"]);
  requireSqliteColumns(sqlitePath, "model_prices", [
    "model", "prompt_per_1m", "completion_per_1m", "cache_per_1m",
    "cache_read_per_1m", "cache_creation_per_1m", "prompt_configured",
    "completion_configured", "cache_read_configured", "cache_creation_configured",
    "source", "source_model_id", "updated_at_ms",
  ]);
  requireSqliteColumns(sqlitePath, "model_price_context_tiers", [
    "model", "threshold_tokens", "prompt_per_1m", "completion_per_1m", "cache_per_1m",
    "cache_read_per_1m", "cache_creation_per_1m", "prompt_configured",
    "completion_configured", "cache_configured", "cache_read_configured",
    "cache_creation_configured",
  ]);
  requireSqliteColumns(sqlitePath, "model_price_service_tiers", [
    "model", "mode", "service_tier", "prompt_per_1m", "completion_per_1m",
    "cache_per_1m", "cache_read_per_1m", "cache_creation_per_1m",
    "prompt_configured", "completion_configured", "cache_configured",
    "cache_read_configured", "cache_creation_configured",
  ]);

  const pgPassFile = process.env.PGPASSFILE;
  const pgPassword = process.env.PGPASSWORD;
  if (pgPassFile && pgPassword) fail("set exactly one of PGPASSFILE or PGPASSWORD");
  if (pgPassFile) {
    try {
      const metadata = lstatSync(pgPassFile);
      accessSync(pgPassFile, fsConstants.R_OK);
      if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error("not a regular file");
      if ((metadata.mode & 0o777) !== 0o600) fail("PGPASSFILE must have mode 0600");
    } catch (error) {
      if (error instanceof Error && error.message === "PGPASSFILE must have mode 0600") throw error;
      fail("PGPASSFILE must be a readable regular non-symlink file");
    }
  } else if (!pgPassword) {
    fail("PGPASSFILE or PGPASSWORD is required");
  }
  Object.assign(process.env, { PGHOST: pgHost, PGPORT: pgPort, PGUSER: pgUser, PGDATABASE: pgDatabase });

  const lockKey = "memeloop-token-center:cpamp:global-staging-v1";
  const lockDirectory = mkdtempSync(join(tmpdir(), "mtc-cpamp-lock."));
  const lockApplication = `mtc-cpamp-lock-${lockDirectory.slice(lockDirectory.lastIndexOf(".") + 1)}`;
  let lockProcess: ChildProcess | undefined;
  let lockSpawnError: Error | undefined;

  const cleanup = (): void => {
    if (lockProcess?.exitCode === null) lockProcess.kill("SIGTERM");
    try {
      runPsql(["-v", `lock_app=${lockApplication}`, "-At"], `SELECT pg_terminate_backend(pid)\n  FROM pg_stat_activity\n WHERE application_name = :'lock_app'\n   AND usename = current_user\n   AND pid <> pg_backend_pid();\n`, "ignore");
    } catch {
      // Cleanup is best effort; the importing command has already failed or completed.
    }
    rmSync(lockDirectory, { recursive: true, force: true });
  };
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
    process.once(signal, () => {
      cleanup();
      process.exit(128 + ({ SIGHUP: 1, SIGINT: 2, SIGTERM: 15 } as const)[signal]);
    });
  }

  try {
    lockProcess = spawn("psql", psqlArgs(["-v", `lock_key=${lockKey}`, "-At"]), {
      env: { ...process.env, PGAPPNAME: lockApplication },
      shell: false,
      stdio: ["pipe", "ignore", "inherit"],
    });
    lockProcess.once("error", (error) => {
      lockSpawnError = error;
    });
    lockProcess.stdin?.once("error", (error) => {
      lockSpawnError = error;
    });
    lockProcess.stdin?.end("SET lock_timeout = '30s';\nSELECT pg_advisory_lock(hashtextextended(:'lock_key', 734627102948313));\nSELECT pg_sleep(86400);\n");

    let lockAcquired = false;
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const ready = runPsql(
        ["-v", `lock_app=${lockApplication}`, "-At"],
        "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name = :'lock_app' AND wait_event = 'PgSleep');\n",
        "capture",
      );
      if (ready === "t") {
        lockAcquired = true;
        break;
      }
      if (lockSpawnError) fail(`psql is unavailable: ${lockSpawnError.message}`);
      if (lockProcess.exitCode !== null) break;
      await sleep(1_000);
    }
    if (!lockAcquired) fail("another CPAMP import is running or the import lock failed");

    runPsql(["-v", `tenant_external_id=${tenant}`], readSql("prepare.sql"));
    if (reset) {
      runPsql(["-v", `tenant_external_id=${tenant}`, "-v", `import_source=${source}`], readSql("reset.sql"));
    }

    // The checkpoint revision is committed in the same serializable
    // transaction as the correction and all rebuilt projections. Once it is
    // present, an apply replay has nothing to recover or compare. Return
    // before copying and evaluating the all-history SQLite source: doing that
    // work again can consume gigabytes of PostgreSQL temporary space even
    // though the eventual candidate set is empty.
    if (correctionMode === "apply" && !reset) {
      const appliedRevision = runPsql(
        ["-v", `tenant_external_id=${tenant}`, "-v", `import_source=${source}`, "-At"],
        "SELECT COALESCE((SELECT correction_revision FROM cpamp_import_checkpoints WHERE tenant_external_id = :'tenant_external_id' AND source = :'import_source'), '');\n",
        "capture",
      );
      if (appliedRevision === correctionRevision) {
        process.stdout.write(`correction_revision=${correctionRevision} corrected_events=0 replay=unchanged\n`);
        return;
      }
    }

    const watermarkText = runPsql(
      ["-v", `tenant_external_id=${tenant}`, "-v", `import_source=${source}`, "-At"],
      "SELECT COALESCE((SELECT watermark_ms FROM cpamp_import_checkpoints WHERE tenant_external_id = :'tenant_external_id' AND source = :'import_source'), 0);\n",
      "capture",
    );
    if (!/^\d+$/.test(watermarkText)) fail("invalid PostgreSQL import watermark");
    const watermark = BigInt(watermarkText);
    // A correction must evaluate every legacy receipt against the same sealed
    // source, not only the ordinary late-write overlap window. Otherwise an
    // apparently clean plan could silently omit older v1 digests.
    const lowerBound = correctionMode === "off"
      ? (watermark > overlapMs ? watermark - overlapMs : 0n)
      : 0n;

    await pipeSqliteCsvToPostgres(
      sqlitePath,
      `SELECT event_hash, request_id, timestamp_ms, provider, model, endpoint, lower(api_key_hash), requested_model, resolved_model, reasoning_effort, service_tier, request_service_tier, response_service_tier, cache_input_mode, input_tokens, output_tokens, reasoning_tokens, cached_tokens, cache_tokens, cache_read_tokens, cache_creation_tokens, normalized_uncached_input_tokens, normalized_total_input_tokens, normalized_cache_read_tokens, normalized_cache_creation_tokens, total_tokens, latency_ms, ttft_ms, CASE WHEN failed THEN 1 ELSE 0 END, COALESCE(fail_status_code, 0), COALESCE(fail_summary, '') FROM usage_events WHERE event_hash <> '' AND timestamp_ms >= ${lowerBound};`,
      "cpamp_import_usage",
      [
        "event_hash", "request_id", "timestamp_ms", "provider", "model", "endpoint",
        "api_key_hash", "requested_model", "resolved_model", "reasoning_effort", "service_tier",
        "request_service_tier", "response_service_tier", "cache_input_mode", "input_tokens",
        "output_tokens", "reasoning_tokens", "cached_tokens", "cache_tokens", "cache_read_tokens",
        "cache_creation_tokens", "normalized_uncached_input_tokens", "normalized_total_input_tokens",
        "normalized_cache_read_tokens", "normalized_cache_creation_tokens", "total_tokens", "latency_ms",
        "ttft_ms", "failed", "fail_status_code", "fail_summary",
      ],
    );
    await pipeSqliteCsvToPostgres(sqlitePath, "SELECT lower(api_key_hash), alias, updated_at_ms FROM api_key_aliases;", "cpamp_import_aliases", ["api_key_hash", "alias", "updated_at_ms"]);
    await pipeSqliteCsvToPostgres(sqlitePath, "SELECT model, prompt_per_1m, completion_per_1m, cache_per_1m, cache_read_per_1m, cache_creation_per_1m, prompt_configured, completion_configured, cache_read_configured, cache_creation_configured, COALESCE(source, ''), COALESCE(source_model_id, ''), updated_at_ms FROM model_prices;", "cpamp_import_prices", ["model", "prompt_per_1m", "completion_per_1m", "cache_per_1m", "cache_read_per_1m", "cache_creation_per_1m", "prompt_configured", "completion_configured", "cache_read_configured", "cache_creation_configured", "source", "source_model_id", "updated_at_ms"]);
    await pipeSqliteCsvToPostgres(sqlitePath, "SELECT model, threshold_tokens, prompt_per_1m, completion_per_1m, cache_per_1m, cache_read_per_1m, cache_creation_per_1m, prompt_configured, completion_configured, cache_configured, cache_read_configured, cache_creation_configured FROM model_price_context_tiers;", "cpamp_import_context_prices", ["model", "threshold_tokens", "prompt_per_1m", "completion_per_1m", "cache_per_1m", "cache_read_per_1m", "cache_creation_per_1m", "prompt_configured", "completion_configured", "cache_configured", "cache_read_configured", "cache_creation_configured"]);
    await pipeSqliteCsvToPostgres(sqlitePath, "SELECT model, lower(trim(mode)), lower(trim(service_tier)), prompt_per_1m, completion_per_1m, cache_per_1m, cache_read_per_1m, cache_creation_per_1m, prompt_configured, completion_configured, cache_configured, cache_read_configured, cache_creation_configured FROM model_price_service_tiers;", "cpamp_import_service_prices", ["model", "mode", "service_tier", "prompt_per_1m", "completion_per_1m", "cache_per_1m", "cache_read_per_1m", "cache_creation_per_1m", "prompt_configured", "completion_configured", "cache_configured", "cache_read_configured", "cache_creation_configured"]);

    runPsql([], readSql("evaluate.sql"));

    const validationSql = `SELECT count(*) FROM cpamp_import_usage;
SELECT count(*) FROM cpamp_import_usage WHERE COALESCE(api_key_hash, '') !~ '^[0-9a-f]{64}$';
SELECT count(*) FROM cpamp_import_aliases WHERE COALESCE(api_key_hash, '') !~ '^[0-9a-f]{64}$';
SELECT COALESCE(sum(events - 1), 0) FROM (SELECT count(*) AS events FROM cpamp_import_evaluated GROUP BY event_hash HAVING count(*) > 1) duplicates;
SELECT count(*) FROM (SELECT event_hash FROM cpamp_import_evaluated GROUP BY event_hash HAVING count(DISTINCT source_digest) > 1) conflicts;
SELECT count(*) FROM cpamp_import_evaluated WHERE validation_error <> '';
SELECT count(*) FROM (
  SELECT model FROM cpamp_import_prices
   GROUP BY model HAVING count(*) <> 1
  UNION ALL
  SELECT model || ':' || threshold_tokens FROM cpamp_import_context_prices
   GROUP BY model, threshold_tokens HAVING count(*) <> 1
  UNION ALL
  SELECT p.model FROM cpamp_import_prices p
   WHERE COALESCE(p.model, '') = ''
      OR NOT (p.prompt_per_1m BETWEEN 0 AND 1000000000)
      OR NOT (p.completion_per_1m BETWEEN 0 AND 1000000000)
      OR NOT (p.cache_per_1m BETWEEN 0 AND 1000000000)
      OR NOT (p.cache_read_per_1m BETWEEN 0 AND 1000000000)
      OR NOT (p.cache_creation_per_1m BETWEEN 0 AND 1000000000)
      OR p.prompt_configured NOT IN (0,1) OR p.completion_configured NOT IN (0,1)
      OR p.cache_read_configured NOT IN (0,1) OR p.cache_creation_configured NOT IN (0,1)
  UNION ALL
  SELECT c.model FROM cpamp_import_context_prices c
   WHERE COALESCE(c.model, '') = '' OR c.threshold_tokens < 0
      OR NOT (c.prompt_per_1m BETWEEN 0 AND 1000000000)
      OR NOT (c.completion_per_1m BETWEEN 0 AND 1000000000)
      OR NOT (c.cache_per_1m BETWEEN 0 AND 1000000000)
      OR NOT (c.cache_read_per_1m BETWEEN 0 AND 1000000000)
      OR NOT (c.cache_creation_per_1m BETWEEN 0 AND 1000000000)
      OR c.prompt_configured NOT IN (0,1) OR c.completion_configured NOT IN (0,1)
      OR c.cache_configured NOT IN (0,1) OR c.cache_read_configured NOT IN (0,1)
      OR c.cache_creation_configured NOT IN (0,1)
  UNION ALL
  SELECT s.model FROM cpamp_import_service_prices s
   WHERE COALESCE(s.model, '') = '' OR COALESCE(s.mode, '') = ''
      OR COALESCE(s.service_tier, '') = ''
      OR NOT (s.prompt_per_1m BETWEEN 0 AND 1000000000)
      OR NOT (s.completion_per_1m BETWEEN 0 AND 1000000000)
      OR NOT (s.cache_per_1m BETWEEN 0 AND 1000000000)
      OR NOT (s.cache_read_per_1m BETWEEN 0 AND 1000000000)
      OR NOT (s.cache_creation_per_1m BETWEEN 0 AND 1000000000)
      OR s.prompt_configured NOT IN (0,1) OR s.completion_configured NOT IN (0,1)
      OR s.cache_configured NOT IN (0,1) OR s.cache_read_configured NOT IN (0,1)
      OR s.cache_creation_configured NOT IN (0,1)
  UNION ALL
  SELECT left_rule.model FROM cpamp_import_service_prices left_rule
  JOIN cpamp_import_service_prices right_rule
    ON left_rule.model = right_rule.model AND left_rule.ctid < right_rule.ctid
   AND (left_rule.mode IN (right_rule.mode, right_rule.service_tier)
     OR left_rule.service_tier IN (right_rule.mode, right_rule.service_tier))
) invalid_price_configuration;
`;
    const values = runPsql(["-At"], validationSql, "capture").split(/\s+/);
    if (values.length !== 7 || values.some((value) => !/^\d+$/.test(value ?? ""))) fail("invalid CPAMP staging validation result");
    const [stagedText, unmappedText, invalidAliasText, duplicateText, conflictsText, invalidBillingText, invalidPricesText] = values as [string, string, string, string, string, string, string];
    const unmapped = BigInt(unmappedText);
    const invalidAliases = BigInt(invalidAliasText);
    const conflicts = BigInt(conflictsText);
    if (unmapped > 0n && !allowUnmapped) fail(`CPAMP import stopped: ${unmappedText} staged events have no supported key identity; set CPAMP_ALLOW_UNMAPPED=true only after accepting that data loss`);
    if (invalidAliases > 0n) fail(`CPAMP import stopped: ${invalidAliasText} staged aliases have a non-hex key identity`);
    if (conflicts > 0n) fail(`CPAMP import stopped: ${conflictsText} event hashes map to conflicting source rows`);
    if (BigInt(invalidPricesText) > 0n) fail(`CPAMP import stopped: ${invalidPricesText} source price rows are ambiguous or invalid`);
    if (BigInt(invalidBillingText) > 0n) {
      const reasons = runPsql(
        ["-At", "-F", " | "],
        "SELECT validation_error, count(*) FROM cpamp_import_evaluated WHERE validation_error <> '' GROUP BY validation_error ORDER BY count(*) DESC, validation_error LIMIT 5;",
        "capture",
      );
      fail(`CPAMP import stopped: ${invalidBillingText} staged events lack exact token/pricing provenance${reasons ? ` (${reasons})` : ""}`);
    }
    process.stderr.write(`CPAMP staged=${stagedText} unmapped=${unmappedText} duplicate_rows_deduplicated=${duplicateText} conflicting_event_hashes=0\n`);

    const legacyCorrectionText = runPsql(
      ["-v", `tenant_external_id=${tenant}`, "-v", `import_source=${source}`, "-At"],
      `SELECT count(*) FROM cpamp_import_evaluated e JOIN tenants t ON t.external_id = :'tenant_external_id' JOIN import_request_links l ON l.tenant_id=t.id AND l.source=:'import_source' AND l.external_event_hash=e.event_hash WHERE l.source_digest=e.legacy_source_digest AND l.source_digest<>e.source_digest;\n`,
      "capture",
    );
    if (!/^\d+$/.test(legacyCorrectionText)) fail("invalid CPAMP correction preflight result");
    if (BigInt(legacyCorrectionText) > 0n && correctionMode === "off") {
      fail(`CPAMP import stopped: ${legacyCorrectionText} previously imported events require the explicit cache/pricing correction mode`);
    }
    if (correctionMode === "plan") {
      runPsql(["-v", `tenant_external_id=${tenant}`, "-v", `import_source=${source}`], readSql("correct-plan.sql"));
      return;
    }
    if (correctionMode === "apply") {
      runPsql(
        ["-v", `tenant_external_id=${tenant}`, "-v", `import_source=${source}`],
        `${readSql("correct.sql")}\n${readSql("correct-rebuild.sql")}`,
      );
      // Correction is a separately fenced, all-history operation. Do not
      // immediately feed the same wide all-history staging set into the
      // ordinary importer: that duplicates work, can require multi-gigabyte
      // temporary sorts, and obscures whether correction replay or ordinary
      // overlap replay changed state. Operations run the ordinary importer as
      // a distinct job after a zero-change second correction.
      return;
    }

    runPsql(["-v", `tenant_external_id=${tenant}`, "-v", `import_source=${source}`], readSql("apply.sql"));
  } finally {
    cleanup();
  }
}

try {
  await main();
} catch (error) {
  if (error instanceof CliError) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = error.exitCode;
  } else {
    process.stderr.write(`CPAMP import failed: ${error instanceof Error ? error.message : "unknown error"}\n`);
    process.exitCode = 1;
  }
}
