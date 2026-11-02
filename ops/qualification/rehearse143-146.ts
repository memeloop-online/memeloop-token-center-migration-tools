/**
 * CI-only destructive synthetic qualification, NOT a production execution tool.
 * Original fixture runner owns baseline ledger creation; exact CI source owns upgrades.
 * No customer timeouts, production endpoints, global settings or ledger edits.
 */
import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, appendFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const revision = "45bef4137bb75b281322384a38461e053fbe0be1";
const migrator = process.env.QUAL_MIGRATOR_BIN!;
const root = join(process.env.RUNNER_TEMP ?? "", "migration143-146");
assert.equal(process.env.GITHUB_ACTIONS, "true", "remote CI only");
assert.equal(process.env.PGHOST, "127.0.0.1");
assert.equal(process.env.PGDATABASE, "rehearsal142");
mkdirSync(root, { recursive: true });
const receipt: Record<string, unknown> = {
  revision, migrator, release_artifact: false,
  run: process.env.GITHUB_RUN_ID, tooling_sha: process.env.GITHUB_SHA,
  status: "running", scenarios: [], source_hashes: {},
};
const save = () => writeFileSync(join(root, "result.json"), JSON.stringify(receipt, null, 2));
const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
const quote = (s: string) => `'${s.replaceAll("'", "''")}'`;
const ident = (s: string) => { assert.match(s, /^[a-z][a-z0-9_]+$/u); return `"${s}"`; };
type Row = Record<string, any>;

// Persistent psql sessions keep process startup out of write timings. The SQLSTATE
// marker distinguishes server errors even if stderr and stdout arrive separately.
class Session {
  process: ChildProcessWithoutNullStreams;
  pending?: { marker: string; lines: string[]; resolve: (s: string) => void; reject: (e: Error) => void };
  buffer = "";
  serial = 0;
  constructor(database: string, application: string) {
    assert.match(database, /^rehearsal[a-z0-9_]*$/u);
    this.process = spawn("psql", ["-X", "-qAt", "-v", "ON_ERROR_STOP=0", "-d", database], {
      env: { ...process.env, PGAPPNAME: application },
    });
    this.process.stdout.on("data", (chunk: Buffer) => {
      this.buffer += chunk.toString();
      let end: number;
      while ((end = this.buffer.indexOf("\n")) >= 0) {
        const line = this.buffer.slice(0, end).replace(/\r$/u, "");
        this.buffer = this.buffer.slice(end + 1);
        const pending = this.pending;
        if (!pending) continue;
        if (line.startsWith(pending.marker)) {
          this.pending = undefined;
          const state = line.slice(pending.marker.length).trim();
          if (state !== "00000") pending.reject(new Error(`SQLSTATE ${state}`));
          else pending.resolve(pending.lines.join("\n"));
        } else pending.lines.push(line);
      }
    });
    this.process.stderr.on("data", (chunk: Buffer) =>
      appendFileSync(join(root, "psql.log"), `[${application}] ${chunk}`));
    this.process.on("error", (e) => this.pending?.reject(e));
    this.process.on("exit", (code) => {
      if (this.pending) this.pending.reject(new Error(`psql exited ${code}`));
    });
  }
  async sql(sql: string): Promise<string> {
    assert.equal(this.pending, undefined, "one query at a time per backend");
    const marker = `__REHEARSAL_${++this.serial}__`;
    return new Promise((resolve, reject) => {
      this.pending = { marker, lines: [], resolve, reject };
      this.process.stdin.write(`${sql};\n\\echo ${marker} :SQLSTATE\n`);
    });
  }
  async rows(sql: string): Promise<Row[]> {
    return JSON.parse(await this.sql(`SELECT COALESCE(json_agg(q),'[]'::json) FROM (${sql}) q`)) as Row[];
  }
  async close() {
    this.process.stdin.end("\\q\n");
    await new Promise<void>((resolve) => this.process.once("exit", () => resolve()));
  }
}

async function command(args: string[], env: NodeJS.ProcessEnv = process.env) {
  const started = performance.now();
  return new Promise<{ code: number | null; ms: number; output: string }>((resolve, reject) => {
    const child = spawn(args[0]!, args.slice(1), { env });
    let output = "";
    child.stdout.on("data", (s: Buffer) => { output += s; });
    child.stderr.on("data", (s: Buffer) => { output += s; });
    child.on("error", reject);
    child.on("exit", (code) => resolve({ code, ms: performance.now() - started, output }));
  });
}

type Leaf = { name: string; start: number; end: number; rows: number; pages: number };
const shape = JSON.parse(readFileSync("ops/qualification/shape143-146.json", "utf8")) as {
  first_day: string; daily_rows: number[]; daily_pages: number[]; default_rows: number;
  default_pages: number; request_spool_rows: number; response_spool_rows: number;
};
assert.equal(shape.daily_rows.length, 77);
const leaves: Leaf[] = shape.daily_rows.map((rows, i) => {
  const start = Date.parse(shape.first_day) + i * 86400000;
  return { name: `request_records_${new Date(start).toISOString().slice(0, 10).replaceAll("-", "")}`,
    start, end: start + 86400000, rows, pages: shape.daily_pages[i]! };
});
const extraStart = Date.parse(shape.first_day) + 77 * 86400000;
leaves.push({ name: `request_records_${new Date(extraStart).toISOString().slice(0, 10).replaceAll("-", "")}`,
  start: extraStart, end: extraStart + 86400000, rows: 0, pages: 0 });
leaves.push({ name: "request_records_default", start: Date.parse(shape.first_day) - 86400000,
  end: Date.parse(shape.first_day), rows: shape.default_rows, pages: shape.default_pages });
const sql146 = readFileSync(".upgrade-source/migrations/common/0146_request_live_owner_index.sql", "utf8");
assert.equal(sha(sql146), "71712dca882c19d43f5c095f06daeae494c27994f710eca9ccb65a37e35c6a2e");
const keys146 = "(proxy_owner_expires_at DESC, id DESC) WHERE completed_at IS NULL AND proxy_owner_expires_at IS NOT NULL";
const spoolSql = readFileSync(".upgrade-source/migrations/common/0143_archive_spool_ready_indexes.sql", "utf8");
const spoolStatements = spoolSql.trim().split(";").map((s) => s.trim()).filter(Boolean);
const spoolNames = spoolStatements.map((s) => s.match(/IF NOT EXISTS (\w+)/u)![1]!);

async function catalog147(db: Session) {
  return db.rows(`SELECT c.relname AS name, c.oid::bigint AS oid, i.indisvalid AS valid,
    i.indisready AS ready, i.indislive AS live, pg_get_indexdef(c.oid) AS definition
    FROM pg_class c JOIN pg_index i ON i.indexrelid=c.oid WHERE c.relname IN
    ('conversation_observations_explicit_session_idx','request_stats_facts_session_idx') ORDER BY c.relname`);
}

async function verify151(db: Session, probes: Row[], selections: Row[]) {
  assert.deepEqual(await db.rows(`SELECT upstream_account_id,status,error_code,latency_ms,checked_at
    FROM upstream_service_probes ORDER BY upstream_account_id`), probes);
  assert.equal(await db.sql(`SELECT count(*) FROM upstream_service_probes WHERE result_json IS NOT NULL
    OR last_attempt_json IS NOT NULL OR actual_model IS NOT NULL`), "0");
  assert.deepEqual(await db.rows("SELECT * FROM upstream_transport_proxy_selections ORDER BY account_id"), selections);
  assert.equal(await db.sql("SELECT count(*) FROM upstream_supplier_availability"), "0");
  await db.sql(`UPDATE upstream_transport_proxy_selections SET base_index=172,selected_index=172
    WHERE account_id='synthetic-upstream-1'`);
  await db.sql(`UPDATE upstream_transport_proxy_selections SET base_index=1,selected_index=1
    WHERE account_id='synthetic-upstream-1'`);
  return { legacy_probes_preserved: probes.length, no_invented_independent_provenance: true,
    selections_preserved: selections.length, expanded_member_index_accepted: true };
}

async function catalog(db: Session) {
  return db.rows(`SELECT c.relname AS leaf, i.indexrelid::int AS oid, ci.relname AS name,
    i.indisvalid AS valid, i.indisready AS ready, i.indislive AS live,
    i.indisunique AS unique, i.indnkeyatts AS keys, i.indnatts AS attrs,
    i.indkey::text AS attnums, i.indclass::text AS opclasses,
    i.indcollation::text AS collations, i.indoption::text AS options,
    pg_get_expr(i.indpred,i.indrelid) AS predicate,
    pg_get_indexdef(i.indexrelid) AS definition, pg_relation_size(i.indexrelid) AS bytes,
    a.inhparent::int AS parent_oid
    FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid
    JOIN pg_class ci ON ci.oid=i.indexrelid LEFT JOIN pg_inherits a ON a.inhrelid=i.indexrelid
    WHERE ci.relname LIKE 'qual146_%' OR ci.relname='request_records_live_owner_expiry_idx'
       OR ci.relname IN (${spoolNames.map(quote).join(",")}) ORDER BY ci.relname`);
}

async function preflight(db: Session) {
  const actual = await db.rows(`SELECT c.relname AS name, pg_get_expr(c.relpartbound,c.oid) AS bound
    FROM pg_inherits p JOIN pg_class c ON c.oid=p.inhrelid
    WHERE p.inhparent='request_records'::regclass ORDER BY c.relname`);
  assert.deepEqual(actual.map((r) => r.name), leaves.map((r) => r.name).sort());
  for (const leaf of leaves) {
    assert.equal(actual.find((r) => r.name===leaf.name)?.bound, leaf.name.endsWith("default")
      ? "DEFAULT" : `FOR VALUES FROM ('${leaf.start}') TO ('${leaf.end}')`);
  }
  const indexes = (await catalog(db)).filter((r) => r.name.startsWith("qual146_"));
  assert.equal(indexes.length, 79);
  for (const [i, leaf] of leaves.entries()) {
    const ix = indexes.find((r) => r.name === `qual146_${i}`);
    assert.ok(ix && ix.leaf === leaf.name && ix.valid && ix.ready && ix.live);
    assert.equal(ix.parent_oid, null);
    assert.equal(ix.unique, false);
    assert.equal(ix.keys, 2);
    assert.equal(ix.attrs, 2);
    assert.equal(ix.options, "3 3");
    assert.equal(ix.definition,
      `CREATE INDEX qual146_${i} ON public.${leaf.name} USING btree (proxy_owner_expires_at DESC, id DESC) WHERE ((completed_at IS NULL) AND (proxy_owner_expires_at IS NOT NULL))`);
  }
  return indexes;
}

async function seed(db: Session) {
  console.log("Seeding original142 production-shaped synthetic relations");
  const version = await db.sql("SHOW server_version_num");
  assert.equal(version.trim(), "170005");
  receipt.server_version_num = version;
  receipt.original_ledger = await db.rows("SELECT * FROM schema_migrations ORDER BY version");
  assert.equal((receipt.original_ledger as Row[]).at(-1)?.version, 142);
  assert.equal(await db.sql("SELECT count(*) FROM request_records"), "0");
  // Remove only empty fixture-generated daily partitions before reproducing the
  // observed exact topology. Never alter ledger/history or source DDL.
  const initial = await db.rows(`SELECT c.relname FROM pg_inherits p JOIN pg_class c ON c.oid=p.inhrelid
    WHERE p.inhparent='request_records'::regclass`);
  for (const r of initial) await db.sql(`DROP TABLE ${ident(r.relname)}`);
  for (const leaf of leaves) {
    await db.sql(`CREATE TABLE ${ident(leaf.name)} PARTITION OF request_records ${
      leaf.name.endsWith("default") ? "DEFAULT" : `FOR VALUES FROM (${leaf.start}) TO (${leaf.end})`}`);
    if (!leaf.rows) continue;
    const padding = Math.max(0, Math.min(1600, Math.round(leaf.pages * 8192 / leaf.rows) - 400));
    await db.sql(`INSERT INTO request_records
      (id,tenant_id,key_id,created_at,completed_at,protocol,model,input_tokens,output_tokens,
       cost_micros,request_object,reservation_id,proxy_owner_expires_at,proxy_owner_token)
      SELECT md5(${quote(leaf.name)}||g::text), 'synthetic-tenant','synthetic-key',
        ${leaf.start}+g, CASE WHEN g%20<18 THEN ${leaf.start}+g+10 ELSE NULL END,
        'openai','synthetic-model',0,0,0,
        left(repeat(md5(g::text),60),${padding}),'synthetic-reservation',
        CASE WHEN g%20=18 THEN 1793491200000 WHEN g%20=19 THEN 1787529600000 ELSE NULL END,
        CASE WHEN g%20>=18 THEN 'synthetic-owner' ELSE NULL END
      FROM generate_series(1,${leaf.rows}) g`);
  }
  for (const kind of ["request", "response"] as const) {
    const count = shape[`${kind}_spool_rows`];
    await db.sql(`INSERT INTO ${kind}_archive_spools
      (request_id,tenant_id,reservation_id,state,next_attempt_at,created_at,updated_at,expires_at,
       cleaned_at,bound_locator,cipher_bytes,lease_expires_at)
      SELECT '${kind}-spool-'||g, 'synthetic-tenant','synthetic-reservation',
        CASE WHEN g%20=1 THEN 'pending' WHEN g%20=2 THEN 'uploading' ELSE 'bound' END,
        1793404800000,1793404800000,1793404800000,1794009600000,
        CASE WHEN g%20 NOT IN (1,2) THEN 1793404800001 ELSE NULL END,
        repeat(md5(g::text),5), CASE WHEN g%20 IN (1,2) THEN 1024 ELSE 0 END,
        CASE WHEN g%20=2 THEN 1793491200000 ELSE NULL END
      FROM generate_series(1,${count}) g`);
  }
  await db.sql(`UPDATE response_archive_spool_budget SET
    request_cipher_bytes=(SELECT sum(cipher_bytes) FROM request_archive_spools),
    cipher_bytes=(SELECT sum(cipher_bytes) FROM request_archive_spools)
                +(SELECT sum(cipher_bytes) FROM response_archive_spools)`);
  await db.sql(`INSERT INTO upstream_accounts
    (id,tenant_id,name,driver,auth_kind,config_json,status,credential_generation,created_at,updated_at)
    SELECT 'synthetic-upstream-'||g,'synthetic-tenant','synthetic-upstream-'||g,'openai','api_key',
      CASE WHEN g%2=0 THEN '{"transport_policy":{"failover_deadline_millis":1000,"keep":true}}'
      ELSE '{"transport_policy":{"keep":true}}' END, 'disabled',1,1793404800000,1793404800000
    FROM generate_series(1,2000) g`);
  await db.sql(`INSERT INTO credit_accounts
    (id,tenant_id,principal_id,currency,available_micros,reserved_micros,created_at,updated_at) VALUES
    ('synthetic-account','synthetic-tenant','synthetic-principal','USD',1000000,0,0,0)`);
  await db.sql(`INSERT INTO conversation_observations
    (id,cluster_id,request_id,key_id,atom_hashes_json,explicit_session_id,created_at,inference_version,labels_json)
    SELECT 'observation-'||g,'synthetic-cluster','observation-request-'||g,'synthetic-key','[]',
      'synthetic-session-'||(g%10),1793404800000+g,1,'{"padding":"'||repeat(md5(g::text),16)||'"}'
    FROM generate_series(1,655700) g`);
  await db.sql(`INSERT INTO request_stats_facts
    (request_id,tenant_id,key_id,session_id,created_at,model,protocol,status_class,error_code,
     upstream_account_id,model_route_id,duration_ms,input_tokens,output_tokens,cost_micros)
    SELECT 'facts-'||g,'synthetic-tenant','synthetic-key','synthetic-session-'||(g%10),1793404800000+g,
      repeat(md5(g::text),3),'openai','success','','synthetic-upstream-1','synthetic-route',1,7,3,22
    FROM generate_series(1,1170772) g`);
  await db.sql(`INSERT INTO upstream_service_probes (upstream_account_id,status,error_code,latency_ms,checked_at)
    SELECT 'synthetic-upstream-'||g,'success',NULL,100,1793404800000 FROM generate_series(1,20) g`);
  await db.sql(`INSERT INTO upstream_transport_proxy_selections
    SELECT 'synthetic-upstream-'||g,1,'original-fingerprint',1,g%4,g%4,1 FROM generate_series(1,20) g`);
  await db.sql("ANALYZE");
  receipt.fixture_relations = await db.rows(`SELECT relname, reltuples::bigint AS estimated_rows,
    relpages, pg_relation_size(oid) AS bytes FROM pg_class
    WHERE relname LIKE 'request_records_%' AND relkind='r'
    OR relname IN ('request_archive_spools','response_archive_spools',
      'conversation_observations','request_stats_facts') ORDER BY relname`);
  receipt.fixture_counts = { request_records: leaves.reduce((n, l) => n + l.rows, 0),
    request_spools: shape.request_spool_rows, response_spools: shape.response_spool_rows,
    conversation_observations:655700,request_stats_facts:1170772 };
  receipt.assumptions = JSON.parse(readFileSync("ops/qualification/shape143-146.json", "utf8")).assumptions;
  save();
  console.log("Seed complete", receipt.fixture_counts);
}

type Sample = { phase: string; kind: string; start: number; ms: number; error?: string };
function summary(samples: Sample[]) {
  const groups: Record<string, unknown> = {};
  for (const key of new Set(samples.map((s) => `${s.phase}/${s.kind}`))) {
    const all = samples.filter((s) => `${s.phase}/${s.kind}` === key);
    const values = all.map((s) => s.ms).sort((a,b) => a-b);
    const percentile = (p: number) => values[Math.min(values.length-1, Math.floor(values.length*p))];
    groups[key] = { count: all.length, errors: all.filter((s) => s.error).length,
      p50: percentile(.5), p95: percentile(.95), p99: percentile(.99), max: values.at(-1) };
  }
  return groups;
}

class Load {
  phase = "baseline";
  stop = false;
  samples: Sample[] = [];
  tasks: Promise<void>[] = [];
  paused = false;
  boundaryWaiters: (() => void)[] = [];
  allAtBoundary?: () => void;
  async pauseAtBoundary() {
    this.paused = true;
    await new Promise<void>((resolve) => { this.allAtBoundary = resolve; });
  }
  async boundary() {
    if (!this.paused) return;
    await new Promise<void>((resolve) => {
      this.boundaryWaiters.push(resolve);
      if (this.boundaryWaiters.length === 12) this.allAtBoundary?.();
    });
  }
  resume() {
    this.paused = false;
    for (const release of this.boundaryWaiters.splice(0)) release();
  }
  start(database: string) {
    for (let worker=0; worker<12; worker++) {
      this.tasks.push((async () => {
        const kind = worker<2 ? "records" : worker<4 ? "request" : worker<6 ? "response" : worker<8 ? "reader"
          : worker===8 ? "observation" : worker===9 ? "facts" : worker===10 ? "observation_reader" : "facts_reader";
        const db = new Session(database, `qual_writer_${kind}_${worker}`);
        let n = 0;
        try {
          await db.sql("SET statement_timeout = 30000");
          await db.sql("SET lock_timeout = 10000");
          assert.equal(await db.sql("SHOW statement_timeout"), "30s");
          assert.equal(await db.sql("SHOW lock_timeout"), "10s");
          assert.equal(await db.sql("SHOW transaction_timeout"), "0");
          while (!this.stop) {
            await this.boundary();
            if (this.stop) break;
            const start = performance.now(), phase = this.phase;
            let error: string | undefined;
            try {
              if (kind === "reader") {
                await db.sql(`SELECT r.id, q.state, s.state FROM request_records r
                  LEFT JOIN request_archive_spools q ON q.request_id=r.id AND q.tenant_id=r.tenant_id AND q.reservation_id=r.reservation_id
                  LEFT JOIN response_archive_spools s ON s.request_id=r.id AND s.tenant_id=r.tenant_id AND s.reservation_id=r.reservation_id
                  WHERE r.id='writer-${database}-0-${Math.max(0,n-1)}' LIMIT 1`);
              } else if (kind === "records") {
                await db.sql("BEGIN");
                await db.sql(`INSERT INTO request_records
                  (id,tenant_id,key_id,created_at,protocol,model,input_tokens,output_tokens,cost_micros,
                   request_object,reservation_id,proxy_owner_token,proxy_owner_expires_at)
                  VALUES ('writer-${database}-${worker}-${n}','synthetic-tenant','synthetic-key',
                  1793448000000,'openai','synthetic-model',0,0,0,'{}','synthetic-reservation',
                  'synthetic-owner',1793491200000)`);
                await db.sql(`UPDATE request_archive_spools SET updated_at=1793448000000
                  WHERE request_id='request-spool-1' AND state='pending'`);
                await db.sql(`UPDATE response_archive_spools SET updated_at=1793448000000
                  WHERE request_id='response-spool-1' AND state='pending'`);
                await db.sql("COMMIT");
              } else if (kind === "observation") {
                await db.sql(`UPDATE conversation_observations SET explicit_session_id='synthetic-session-${n%10}'
                  WHERE id='observation-${1+n%1000}'`);
              } else if (kind === "facts") {
                await db.sql(`UPDATE request_stats_facts SET session_id='synthetic-session-${n%10}'
                  WHERE request_id='facts-${1+n%1000}'`);
              } else if (kind === "observation_reader") {
                await db.sql("SELECT explicit_session_id FROM conversation_observations WHERE id='observation-1'");
              } else if (kind === "facts_reader") {
                await db.sql("SELECT session_id,cost_micros FROM request_stats_facts WHERE request_id='facts-1'");
              } else {
                const id = 1 + ((n * 2 + worker % 2) % 10000) * 20;
                await db.sql(`UPDATE ${kind}_archive_spools SET next_attempt_at=1793448000000,
                  updated_at=1793448000000 WHERE request_id='${kind}-spool-${id}' AND state='pending'`);
              }
            } catch (e) {
              error = String(e);
              if (kind === "records") await db.sql("ROLLBACK");
            }
            this.samples.push({ phase, kind, start, ms: performance.now()-start, ...(error ? { error } : {}) });
            n++;
            await delay(10); // pacing synthetic load, never a customer deadline
          }
        } finally { await db.close(); }
      })());
    }
  }
  async finish(name: string) {
    this.stop = true;
    this.resume();
    await Promise.all(this.tasks);
    writeFileSync(join(root, `${name}-writes.json`), JSON.stringify(this.samples));
    return summary(this.samples);
  }
}

async function observe(database: string, control: { stop: boolean }, name: string) {
  const db = new Session(database, "qual_observer");
  const file = join(root, `${name}-locks.jsonl`);
  try {
    while (!control.stop) {
      const rows = await db.rows(`SELECT clock_timestamp() AS at,
        (SELECT json_agg(a) FROM (SELECT pid,application_name,state,wait_event_type,wait_event,
          left(query,300) AS query,pg_blocking_pids(pid) AS blockers, xact_start,query_start
          FROM pg_stat_activity WHERE datname=current_database()
          AND application_name<>'qual_observer' AND state<>'idle') a) AS activity,
        (SELECT json_agg(l) FROM (SELECT pid,relation::regclass::text AS relation,mode,granted
          FROM pg_locks WHERE database=(SELECT oid FROM pg_database WHERE datname=current_database())
          AND locktype='relation' AND (NOT granted OR mode IN ('AccessExclusiveLock','ShareLock','ShareUpdateExclusiveLock'))) l) AS locks,
        (SELECT json_agg(p) FROM pg_stat_progress_create_index p) AS progress`);
      appendFileSync(file, JSON.stringify(rows[0])+"\n");
      await delay(20);
    }
  } finally { await db.close(); }
}

async function resources(db: Session) {
  return db.rows(`SELECT pg_current_wal_lsn() AS wal_lsn,
    (SELECT row_to_json(s) FROM pg_stat_database s WHERE datname=current_database()) AS database,
    (SELECT json_agg(i) FROM pg_stat_io i) AS io,
    (SELECT json_agg(r) FROM pg_stat_replication r) AS replicas`);
}

async function prepare146(db: Session) {
  const timings = [];
  for (const [i, l] of leaves.entries()) {
    const t = performance.now();
    // Own preparation session only; each CIC commits independently.
    await db.sql(`CREATE INDEX CONCURRENTLY qual146_${i} ON ${ident(l.name)} ${keys146}`);
    timings.push({ leaf: l.name, ms: performance.now()-t });
  }
  await preflight(db);
  return { timings, indexes: await catalog(db) };
}

async function prepare143(db: Session) {
  const timings = [];
  for (const statement of spoolStatements) {
    const t = performance.now();
    await db.sql(statement.replace("CREATE INDEX IF NOT EXISTS", "CREATE INDEX CONCURRENTLY"));
    timings.push({ statement, ms: performance.now()-t });
  }
  const ix = (await catalog(db)).filter((r) => spoolNames.includes(r.name));
  assert.equal(ix.length, 4);
  assert.ok(ix.every((r) => r.valid && r.ready && r.live));
  return { timings, indexes: ix };
}

async function migrate(database: string, name: string, limits: string, binary = migrator) {
  const started = new Date().toISOString();
  const uri = new URL(`postgres://token_center:token_center@127.0.0.1:5432/${database}`);
  uri.searchParams.set("options", `${limits} -c application_name=qual_migrator -c log_statement=all -c log_min_duration_statement=0 -c log_error_verbosity=verbose`);
  const env = { ...process.env, MTC_DATABASE_URL: uri.toString(),
    MTC_KEY_PEPPER: "synthetic-ci-only-pepper-0000000000000000",
    MTC_SERVICE_TOKEN: "synthetic-ci-only-service-token-0000000000000000",
    MTC_DATABASE_MAX_CONNECTIONS: "1" };
  const result = await command([binary,"migrate"], env);
  writeFileSync(join(root, `${name}-migrator.log`), result.output);
  let sqlstate: string | undefined;
  let failureRelation: string | undefined;
  if (result.code !== 0) {
    const server = await command(["docker", "logs", "--since", started, process.env.QUAL_POSTGRES_CONTAINER!]);
    writeFileSync(join(root, `${name}-server.log`), server.output);
    assert.match(server.output, /55P03/u, "only actual NOWAIT conflicts qualify for a fast maintenance failure");
    assert.doesNotMatch(server.output, /40P01/u);
    sqlstate = "55P03";
    failureRelation = server.output.match(/ERROR:\s+55P03: could not obtain lock on relation "([^"]+)"/u)?.[1];
  }
  return { code: result.code, wall_ms: result.ms, sqlstate, failure_relation: failureRelation, requested_url_options: limits,
    effective_migration_profile: {
      lock_timeout_ms: 60000, statement_timeout_ms: 900000,
      transaction_timeout_ms: Number(limits.match(/transaction_timeout=(\d+)ms/u)?.[1] ??
        Number(limits.match(/transaction_timeout=(\d+)s/u)?.[1]) * 1000) || 0,
      warning: "Existing after_connect overwrites URL lock/statement limits; NOWAIT does not change those settings.",
    } };
}

async function executionScenario(database: string) {
  const spool = true;
  console.log("Starting exact source runner qualification", database);
  const db = new Session(database, "qual_coordinator");
  const load = new Load();
  const observing = { stop: false };
  const observer = observe(database, observing, database);
  load.start(database);
  const result: Row = { database, resources_before: await resources(db) };
  const ledger = await db.rows("SELECT * FROM schema_migrations ORDER BY version");
  const finance = await db.rows("SELECT * FROM credit_accounts ORDER BY id");
  const probes = await db.rows(`SELECT upstream_account_id,status,error_code,latency_ms,checked_at
    FROM upstream_service_probes ORDER BY upstream_account_id`);
  const selections = await db.rows("SELECT * FROM upstream_transport_proxy_selections ORDER BY account_id");
  const before = await preflight(db);
  result.ledger_before = ledger;
  result.finance_before = finance;
  result.indexes_before = before;
  try {
    await delay(15000);
    if (spool) {
      load.phase = "spool_cic";
      result.spool_preparation = await prepare143(db);
      load.phase = "post_cic";
      await delay(5000);

      const inventory = async () => db.rows(`SELECT 'request' AS kind, count(*) AS rows,
        sum(cipher_bytes) AS cipher_bytes, sum(chunk_count) AS chunks, sum(byte_count) AS plain_bytes
        FROM request_archive_spools UNION ALL SELECT 'response', count(*), sum(cipher_bytes),
        sum(chunk_count), sum(byte_count) FROM response_archive_spools ORDER BY kind`);
      const dataBefore = await inventory();
      const indexesBefore = await catalog(db);
      const definitions = (indexes: Row[]) => indexes.map(({ bytes, ...definition }) => definition);
      assert.equal(indexesBefore.length, 83);
      const prepareBlocker = new Session(database, "qual_cic_boundary_reader");
      try {
        await prepareBlocker.sql("BEGIN; LOCK TABLE request_records IN ACCESS SHARE MODE");
        load.phase = "online147_prepare";
        result.online147_preparation = await migrate(database, `${database}-online147-prepare`, "");
        assert.notEqual(result.online147_preparation.code, 0);
        assert.equal(result.online147_preparation.failure_relation, "request_records");
        result.online147_indexes = await catalog147(db);
        assert.equal(result.online147_indexes.length, 2);
        assert.ok(result.online147_indexes.every((index: Row) => index.valid && index.ready && index.live));
        assert.deepEqual(await db.rows("SELECT * FROM schema_migrations ORDER BY version"), ledger);
        assert.deepEqual(await db.rows("SELECT * FROM credit_accounts ORDER BY id"), finance);
        assert.deepEqual(definitions(await catalog(db)), definitions(indexesBefore));
      } finally { await prepareBlocker.sql("ROLLBACK"); await prepareBlocker.close(); }
      result.conflicts = [];
      for (const target of ["request_records", "request_events", "request_archive_spools", "response_archive_spools",
        "response_archive_spool_budget", "archive_budget_reservations"]) {
        for (const mode of ["ACCESS SHARE", "ROW EXCLUSIVE"]) {
          const blocker = new Session(database, "qual_held_business");
          try {
            await blocker.sql("BEGIN");
            await blocker.sql(`LOCK TABLE ${ident(target)} IN ${mode} MODE`);
            load.phase = "held_business_abort";
            const attempt = await migrate(database, `${database}-${target}-${mode.replaceAll(" ", "-")}`, "");
            assert.notEqual(attempt.code, 0);
            assert.ok(attempt.wall_ms < 2000, `NOWAIT must exit promptly, actual ${attempt.wall_ms}ms`);
            assert.deepEqual(await db.rows("SELECT * FROM schema_migrations ORDER BY version"), ledger);
            assert.deepEqual(await db.rows("SELECT * FROM credit_accounts ORDER BY id"), finance);
            assert.deepEqual(await inventory(), dataBefore);
            assert.deepEqual(definitions(await catalog(db)), definitions(indexesBefore));
            assert.deepEqual(await catalog147(db), result.online147_indexes);
            assert.equal(await db.sql("SELECT to_regclass('request_records_live_owner_expiry_idx') IS NULL"), "t");
            assert.equal(await db.sql(`SELECT count(*) FROM information_schema.columns
              WHERE table_name='response_archive_spools' AND column_name='body_blake3'`), "0");
            await db.sql("BEGIN");
            await db.sql(`LOCK TABLE request_archive_spools, response_archive_spools,
              response_archive_spool_budget, archive_budget_reservations IN ROW EXCLUSIVE MODE NOWAIT`);
            await db.sql("ROLLBACK");
            result.conflicts.push({ target, mode, ...attempt, rollback_verified: true,
              held_target_was_first_conflict: attempt.failure_relation === target,
              all_83_oids_preserved: true, data_and_ledger_preserved: true });
          } finally { await blocker.sql("ROLLBACK"); await blocker.close(); }
        }
      }
      const logs = await command(["docker", "logs", process.env.QUAL_POSTGRES_CONTAINER!]);
      assert.match(logs.output, /55P03/u, "actual server must identify NOWAIT lock_not_available");
      assert.doesNotMatch(logs.output, /40P01/u);
      result.data_before = dataBefore;
      result.all_indexes_before = indexesBefore;
      load.phase = "after_abort";
      await delay(500);
    }
    load.phase = "official_upgrade";
    result.normal_attempts = [];
    for (let attempt = 0; attempt < 5; attempt++) {
      result.migration = await migrate(database, `${database}-normal-${attempt}`, "");
      result.normal_attempts.push(result.migration);
      if (result.migration.code === 0) break;
      assert.ok(result.migration.wall_ms < 2000);
      assert.deepEqual(await db.rows("SELECT * FROM schema_migrations ORDER BY version"), ledger);
    }
    result.uncoordinated_commit = result.migration.code === 0;
    if (!result.uncoordinated_commit) {
      load.phase = "synthetic_entry_boundary";
      await load.pauseAtBoundary();
      result.entry_boundary = "All twelve CI generators acknowledge between-transaction boundary; not a production admission policy";
      let completed = false;
      const migration = migrate(database, `${database}-boundary-entry`, "")
        .finally(() => { completed = true; });
      let acquired = false;
      while (!completed && !acquired) {
        const held = await db.rows(`SELECT count(*)::int AS count FROM pg_locks l
          JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database()
          AND a.application_name='qual_migrator' AND l.granted AND l.mode='AccessExclusiveLock'
          AND l.relation IN ('request_archive_spools'::regclass,'response_archive_spools'::regclass,
            'response_archive_spool_budget'::regclass,'archive_budget_reservations'::regclass)`);
        acquired = held[0]!.count === 4;
        if (!acquired) await delay(2);
      }
      load.phase = "boundary_entry_concurrent_workload";
      load.resume();
      result.migration = await migration;
      result.concurrent_generators_resumed_after_granted_locks = acquired;
      assert.ok(acquired, "twelve generators must resume while migration actually holds all four locks");
    }
    load.phase = "after_commit";
    assert.equal(result.migration.code, 0, "official migration must commit");
    console.log("Official migration committed", result.migration);
    await delay(15000);
    const after = await catalog(db);
    for (const ix of before) {
      const reused = after.find((r) => r.oid===ix.oid);
      assert.ok(reused?.valid && reused.ready && reused.live && reused.parent_oid);
    }
    const parent = after.find((r) => r.name==="request_records_live_owner_expiry_idx");
    assert.ok(parent?.valid);
    result.original_leaf_oids_reused = before.length;
    result.indexes_after = after;
    result.ledger_after = await db.rows("SELECT * FROM schema_migrations ORDER BY version");
    assert.deepEqual(result.ledger_after.filter((r: Row) => r.version<=142), ledger);
    assert.deepEqual(result.ledger_after.filter((r: Row) => r.version>142).map((r: Row) => r.version), [143,144,145,146,147,148,149,150,151]);
    assert.deepEqual(await catalog147(db), result.online147_indexes);
    result.online147_oids_reused = true;
    result.additional149_151 = await verify151(db, probes, selections);
    result.finance_after = await db.rows("SELECT * FROM credit_accounts ORDER BY id");
    assert.deepEqual(result.finance_after, finance);
    for (const original of result.all_indexes_before) {
      const reused = after.find((index) => index.oid === original.oid);
      assert.ok(reused?.valid && reused.ready && reused.live);
    }
    result.all_83_oids_preserved = true;
    const repeatedReader = new Session(database, "qual_already_applied_reader");
    try {
      await repeatedReader.sql("BEGIN");
      await repeatedReader.sql(`LOCK TABLE request_archive_spools, response_archive_spools,
        response_archive_spool_budget, archive_budget_reservations IN ACCESS SHARE MODE`);
      result.applied143_repeat = await migrate(database, `${database}-already-applied`, "");
      assert.equal(result.applied143_repeat.code, 0, "applied143 must skip lock acquisition");
      assert.deepEqual(await db.rows("SELECT * FROM schema_migrations ORDER BY version"), result.ledger_after);
    } finally { await repeatedReader.sql("ROLLBACK"); await repeatedReader.close(); }
    result.constraints_after = await db.rows(`SELECT conrelid::regclass::text AS relation,
      conname AS name, convalidated AS valid, pg_get_constraintdef(oid) AS definition
      FROM pg_constraint WHERE conrelid IN ('request_archive_spools'::regclass,
        'response_archive_spools'::regclass, 'response_archive_spool_budget'::regclass,
        'archive_budget_reservations'::regclass) ORDER BY conrelid, conname`);
    assert.ok(result.constraints_after.every((r: Row) => r.valid));
    assert.equal(await db.sql(`SELECT count(*) FROM upstream_accounts WHERE
      (config_json::jsonb->'transport_policy') ? 'failover_deadline_millis'`), "0");
    assert.equal(await db.sql(`SELECT count(*) FROM upstream_accounts WHERE
      (config_json::jsonb#>>'{transport_policy,keep}')='true'`), "2000");
    result.ledger_and_finance_preserved = true;
    result.config144 = { matched: 1000, preserved_keep: 2000, deadline_remaining: 0 };
    result.partitions_after = await db.rows(`SELECT c.relname FROM pg_inherits p
      JOIN pg_class c ON c.oid=p.inhrelid WHERE p.inhparent='request_records'::regclass`);
    result.resources_after = await resources(db);
    if (spool) {
      load.phase = "future_partition";
      // Genuinely new partition outside both the observed and runner-maintained set.
      const start = Math.max(Date.UTC(2026,10,9), Math.floor(Date.now()/86400000)*86400000+10*86400000);
      const name = `request_records_${new Date(start).toISOString().slice(0,10).replaceAll("-","")}`;
      const t = performance.now();
      await db.sql(`CREATE TABLE ${ident(name)} PARTITION OF request_records
        FOR VALUES FROM (${start}) TO (${start+86400000})`);
      const inherited = await db.rows(`SELECT ci.relname, i.indisvalid, a.inhparent::regclass::text AS parent
        FROM pg_index i JOIN pg_class ci ON ci.oid=i.indexrelid
        JOIN pg_inherits a ON a.inhrelid=i.indexrelid
        WHERE i.indrelid=${quote(name)}::regclass
        AND a.inhparent='request_records_live_owner_expiry_idx'::regclass`);
      assert.equal(inherited.length, 1);
      assert.equal(inherited[0]!.indisvalid, true);
      result.future_partition = { name, ms: performance.now()-t, inherited };
      load.phase = "after_future_partition";
      await delay(5000);
    }
  } finally {
    result.writes = await load.finish(database);
    observing.stop = true;
    await observer;
    await db.close();
    (receipt.scenarios as Row[]).push(result);
    save();
    assert.equal(load.samples.filter((sample) => sample.error).length, 0, "business workload must have zero errors");
  }
}

async function test146Scenario(database: string) {
  const db = new Session(database, "qual_test146_coordinator");
  const result: Row = {database, scenario:"genuine_TEST146_missing145_to151"};
  const load = new Load();
  const control = {stop:false};
  const observer = observe(database,control,database);
  try {
    const originalBinary = process.env.QUAL_TEST146_MIGRATOR_BIN!;
    assert.ok(originalBinary.endsWith("/.test146-source/target/debug/memeloop-token-center"));
    result.baseline_source = "3150445f4841e74faf7a526aa933fe6558c747ed";
    result.baseline_upgrade = await migrate(database,`${database}-original146`,"",originalBinary);
    assert.equal(result.baseline_upgrade.code,0);
    const ledger = await db.rows("SELECT * FROM schema_migrations ORDER BY version");
    result.ledger_before = ledger;
    assert.deepEqual(ledger.filter(entry=>entry.version>=143).map(entry=>entry.version),[143,144,146]);
    const finance = await db.rows("SELECT * FROM credit_accounts ORDER BY id");
    const probes = await db.rows(`SELECT upstream_account_id,status,error_code,latency_ms,checked_at
      FROM upstream_service_probes ORDER BY upstream_account_id`);
    const selections = await db.rows("SELECT * FROM upstream_transport_proxy_selections ORDER BY account_id");
    const indexes = await catalog(db);
    const held = new Session(database,"qual_test146_applied143_reader");
    try {
      await held.sql(`BEGIN; LOCK TABLE request_archive_spools,response_archive_spools,
        response_archive_spool_budget,archive_budget_reservations IN ACCESS SHARE MODE`);
      load.start(database);
      load.phase="test146_upgrade_with_applied143_readers";
      result.migration=await migrate(database,`${database}-to151`,"");
      assert.equal(result.migration.code,0);
      result.ledger_after=await db.rows("SELECT * FROM schema_migrations ORDER BY version");
      for (const entry of ledger) {
        assert.deepEqual(result.ledger_after.find((row:Row)=>row.version===entry.version),entry);
      }
      assert.deepEqual(result.ledger_after.filter((entry:Row)=>!ledger.some(before=>before.version===entry.version))
        .map((entry:Row)=>entry.version),[145,147,148,149,150,151]);
      assert.deepEqual(await db.rows("SELECT * FROM credit_accounts ORDER BY id"),finance);
      result.additional149_151=await verify151(db,probes,selections);
      const after=await catalog(db);
      assert.ok(indexes.every(index=>after.some(row=>row.oid===index.oid&&row.valid&&row.ready&&row.live)));
      result.all_original_index_oids_preserved=true;
      result.indexes147=await catalog147(db);
      assert.equal(result.indexes147.length,2);
      assert.ok(result.indexes147.every((row:Row)=>row.valid&&row.ready&&row.live));
      result.repeated_migration=await migrate(database,`${database}-repeat151`,"");
      assert.equal(result.repeated_migration.code,0);
      assert.deepEqual(await db.rows("SELECT * FROM schema_migrations ORDER BY version"),result.ledger_after);
      result.applied143_144_146_identity_preserved=true;
      await delay(1000);
    } finally { await held.sql("ROLLBACK");await held.close(); }
  } finally {
    result.writes=await load.finish(database);
    control.stop=true;
    await observer;
    await db.close();
    (receipt.scenarios as Row[]).push(result);
    save();
    assert.equal(load.samples.filter(sample=>sample.error).length,0);
  }
}

async function main() {
  // Every old migration file is byte-identical;142 is the genuine source
  // conversion receipt, not an SQL migration or a synthetic fixture INSERT.
  const hashes: Record<string, string> = {};
  for (const backend of ["common","postgres"]) {
    for (const file of readdirSync(`.fixture-source/migrations/${backend}`)) {
      const path = `migrations/${backend}/${file}`;
      const old = readFileSync(`.fixture-source/${path}`);
      assert.deepEqual(readFileSync(`.upgrade-source/${path}`), old);
      hashes[path] = sha(old);
    }
  }
  for (const file of ["postgres/0143_archive_spool_storage_accounting.sql",
    "common/0143_archive_spool_ready_indexes.sql","postgres/0144_retire_failover_deadline.sql",
    "common/0146_request_live_owner_index.sql"]) {
    hashes[`migrations/${file}`] = sha(readFileSync(`.upgrade-source/migrations/${file}`));
  }
  assert.equal(hashes["migrations/postgres/0143_archive_spool_storage_accounting.sql"],
    "f64b44d38302f50225711de74e4385f195e40b54353c18dc1063efd118df6716");
  assert.equal(hashes["migrations/common/0143_archive_spool_ready_indexes.sql"],
    "156e5beeb6ff694fc069ff3328398fb6b31d73a2e8ffe84ee0477e15aae0d0be");
  assert.equal(sha(readFileSync(".upgrade-source/migrations/common/0147_session_task_relationships.sql")),
    "32edfecc096f0fb52e9db6ec75f2c54c819506fc93f0eb0790c73b7f6291256c");
  receipt.source_hashes = hashes;
  const profileSource = readFileSync(".upgrade-source/src/db/mod.rs", "utf8");
  assert.ok(profileSource.includes('POSTGRES_MIGRATION_STATEMENT_TIMEOUT: &str = "SET statement_timeout = 900000"'));
  assert.ok(profileSource.includes('POSTGRES_MIGRATION_LOCK_TIMEOUT: &str = "SET lock_timeout = 60000"'));
  receipt.migration_profile = {
    source_sha256: sha(profileSource),
    source: `memeloop-online/memeloop-token-center@${revision}:src/db/mod.rs`,
    lock_timeout_ms: 60000, statement_timeout_ms: 900000,
    url_lock_and_statement_options_overwritten: true,
    transaction_timeout_url_option_preserved: true,
  };
  assert.ok(migrator.endsWith("/.upgrade-source/target/debug/memeloop-token-center"));
  const sourceHead = await command(["git","-C",".upgrade-source","rev-parse","HEAD"]);
  assert.equal(sourceHead.output.trim(), revision);
  receipt.migrator_sha256 = sha(readFileSync(migrator));
  const db = new Session("rehearsal142","qual_fixture");
  await seed(db);
  const load = new Load();
  const observing = { stop: false };
  const observer = observe("rehearsal142", observing, "preparation146");
  load.start("rehearsal142");
  try {
    await delay(15000);
    load.phase = "leaf_cic";
    console.log("Preparing79 original146-equivalent leaf indexes concurrently");
    receipt.preparation146 = await prepare146(db);
    console.log("All79 leaf indexes prepared and validated");
    load.phase = "after_cic";
    await delay(15000);
  } finally {
    receipt.preparation_writes = await load.finish("preparation146");
    observing.stop = true;
    await observer;
    await db.close();
    save();
  }
  const container = process.env.QUAL_POSTGRES_CONTAINER!;
  assert.match(container, /^[a-f0-9]{64}$/u);
  // Use server-matched pg_dump/restore. Preserve genuine schema and ledger
  // receipt exactly; no fabricated SQL replay or backwards ledger manipulation.
  const dump = await command(["docker","exec",container,"pg_dump","-U","token_center",
    "-d","rehearsal142","-Fc","-f","/tmp/qualification142.dump"]);
  assert.equal(dump.code, 0, dump.output);
  console.log("Genuine142 fixture dump complete", dump.ms);
  const clone = new Session("rehearsal142","qual_clone");
  for (const database of ["rehearsal_prebuilt","rehearsal_test146"]) {
    console.log("Restoring isolated comparison", database);
    await clone.sql(`CREATE DATABASE ${ident(database)}`);
    const restored = await command(["docker","exec",container,"pg_restore","-U","token_center",
      "--exit-on-error","-d",database,"/tmp/qualification142.dump"]);
    assert.equal(restored.code, 0, restored.output);
    console.log("Restore complete", database, restored.ms);
  }
  await clone.close();
  await executionScenario("rehearsal_prebuilt");
  await test146Scenario("rehearsal_test146");
  const finalLogs = await command(["docker", "logs", container]);
  assert.doesNotMatch(finalLogs.output, /40P01/u);
  receipt.no_deadlock_sqlstate = true;
  receipt.status = "passed";
  save();
}

let resourceStop = false;
async function sampleResources() {
  while (!resourceStop) {
    const docker = await command(["docker","stats","--no-stream","--format","{{json .}}"]);
    appendFileSync(join(root,"resources.jsonl"), JSON.stringify({
      at: new Date().toISOString(), docker: docker.output,
      memory: readFileSync("/proc/meminfo","utf8"), disk: readFileSync("/proc/diskstats","utf8"),
      cpu: readFileSync("/proc/stat","utf8"),
    })+"\n");
    await delay(3000);
  }
}
const resourceTask = sampleResources();
main().then(async () => { resourceStop = true; await resourceTask; }).catch((error: unknown) => {
  receipt.status = "failed";
  receipt.error = String(error);
  save();
  console.error(error);
  process.exit(1);
});
