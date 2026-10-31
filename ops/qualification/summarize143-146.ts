/** Read-only analysis of retained CI evidence, never a database client. */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const directory = process.argv[2];
if (!directory) throw new Error("usage: summarize143-146.ts <CI evidence directory>");
const records = readFileSync(join(directory, "postgres.log"), "utf8").split(/(?=^\d{4}-\d\d-\d\d )/mu);
type Statement = { sql: string; start: number; duration_ms?: number; end?: number };
type Transaction = { pid: number; begin: number; end?: number; outcome?: string;
  statements: Statement[]; fatal?: string };
const current = new Map<number, Statement>();
const transactions = new Map<number, Transaction>();
for (const record of records) {
  const match = record.match(/^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) UTC \[(\d+)\] (LOG|FATAL|ERROR):\s+([\s\S]*)/u);
  if (!match) continue;
  const at = Date.parse(`${match[1]!.replace(" ", "T")}Z`), pid = Number(match[2]), message = match[4]!.trim();
  const statement = message.match(/^(?:statement: |execute [^:]+: )([\s\S]*)/u)?.[1];
  if (statement) {
    const item: Statement = { sql: statement, start: at };
    current.set(pid, item);
    if (statement==="BEGIN") transactions.set(pid, { pid, begin: at, statements: [] });
    transactions.get(pid)?.statements.push(item);
    continue;
  }
  const duration = message.match(/^duration: ([\d.]+) ms$/u);
  const item = current.get(pid), tx = transactions.get(pid);
  if (duration && item) {
    item.duration_ms = Number(duration[1]);
    item.end = at;
    if (item.sql==="COMMIT" && tx) { tx.end = at; tx.outcome = "committed"; }
  }
  if (match[3]==="FATAL" && tx) {
    tx.end = at; tx.outcome = "aborted"; tx.fatal = message;
  }
}
const concise = [...transactions.values()].map((tx) => {
  const sql143 = tx.statements.find((s) => s.sql.startsWith("ALTER TABLE response_archive_spools"));
  const sql144 = tx.statements.find((s) => s.sql.startsWith("UPDATE upstream_accounts"));
  const sql146 = tx.statements.find((s) => s.sql.includes("CREATE INDEX request_records_live_owner_expiry_idx"));
  const maintenance = tx.statements.find((s) => s.sql.startsWith("SAVEPOINT memeloop_partition_maintenance"));
  const commit = tx.statements.find((s) => s.sql==="COMMIT");
  return { pid: tx.pid, outcome: tx.outcome, fatal: tx.fatal,
    begin: new Date(tx.begin).toISOString(), end: tx.end ? new Date(tx.end).toISOString() : undefined,
    begin_through_commit_or_abort_ms: tx.end ? tx.end-tx.begin : undefined,
    sql143_ms: sql143?.duration_ms, sql144_ms: sql144?.duration_ms, sql146_ms: sql146?.duration_ms,
    maintenance_through_commit_ms: maintenance && tx.end ? tx.end-maintenance.start : undefined,
    commit_ms: commit?.duration_ms,
    first143_statement_through_commit_ms: sql143 && tx.end ? tx.end-sql143.start : undefined,
    partition_create_statements: tx.statements.filter((s) =>
      /^CREATE TABLE IF NOT EXISTS request_(records|events)_/u.test(s.sql)).length,
  };
});
const locks: Record<string, unknown> = {};
for (const file of readdirSync(directory).filter((f) => f.endsWith("-locks.jsonl"))) {
  const observed = new Map<string, { first: number; last: number; samples: number }>();
  let maxBlockedWriters = 0;
  const progress = new Set<string>();
  for (const line of readFileSync(join(directory, file), "utf8").trim().split("\n")) {
    const sample = JSON.parse(line);
    const at = Date.parse(sample.at);
    const migrators = new Set((sample.activity ?? []).filter((a: any) =>
      a.application_name==="qual_migrator").map((a: any) => a.pid));
    maxBlockedWriters = Math.max(maxBlockedWriters, (sample.activity ?? []).filter((a: any) =>
      a.application_name.startsWith("qual_writer") && a.wait_event_type==="Lock").length);
    for (const l of sample.locks ?? []) {
      if (!migrators.has(l.pid)) continue;
      const key = `${l.pid}/${l.relation}/${l.mode}/${l.granted ? "granted" : "waiting"}`;
      const previous = observed.get(key);
      observed.set(key, { first: previous?.first ?? at, last: at, samples: (previous?.samples ?? 0)+1 });
    }
    for (const p of sample.progress ?? []) progress.add(`${p.command}/${p.phase}`);
  }
  locks[file] = { max_blocked_writer_sessions: maxBlockedWriters,
    sampled_index_progress: [...progress],
    sampled_locks: [...observed].map(([key, value]) => ({ key, samples: value.samples,
      observed_span_ms: value.last-value.first })) };
}
const result = JSON.parse(readFileSync(join(directory, "result.json"), "utf8"));
const lsn = (value: string) => {
  const [high, low] = value.split("/");
  return (BigInt(`0x${high}`)<<32n)+BigInt(`0x${low}`);
};
const wal = (result.scenarios ?? []).map((s: any) => ({ database: s.database,
  bytes: s.resources_after ? Number(lsn(s.resources_after[0].wal_lsn)-lsn(s.resources_before[0].wal_lsn)) : null }));
console.log(JSON.stringify({ transactions: concise, lock_samples: locks, wal_deltas: wal,
  caveats: [
    "143 is one original multi-statement raw_sql message; its duration is aggregate ALTER/CHECK/index time.",
    "Lock samples are discrete observations, not exact acquisition/release timestamps.",
    "143-start-to-COMMIT is an upper-bound proxy for first table lock occupancy, including acquisition wait.",
    "WAL includes concurrent writers and preparation/abort phases; not DDL-only attribution.",
    "Exact59b6 resets URL lock/statement options; server SET logs and transaction-abort FATALs are authoritative.",
  ] }, null, 2));
