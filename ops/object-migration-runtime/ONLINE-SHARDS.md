# Online payload partitioning

`copy-payloads --online-copy` keeps the released serial behavior by default.
`--online-shards N --online-shard I` assigns all six existing payload fields to
worker I, for 0 <= I < N. The unsigned first 32 bits of PostgreSQL
`md5(tenant_id || ':' || request_id)` modulo N determine ownership. The same
request's fields always belong to one worker. This metadata hash partitions work;
source integrity still uses the original repeatable-read source snapshot,
byte/character counts, source MD5 and streamed BLAKE3. Each field retains its own
snapshot, as in the released protocol; there is no claim of an atomic snapshot
across fields or across rows. The existing 65,536-character streaming chunk is
unchanged. No business request or payload size limit is introduced.

Every worker needs a distinct `--checkpoint`, for example `/checkpoints/shard-0.json`.
Its `online-layout.json` binds the source/target identity, six-field list, total
partitions and partition index. A changed layout is rejected rather than silently
reusing a checkpoint. Existing serial checkpoints remain usable only with the
serial layout. Sharding does not change the original object/receipt identity or
immutable receipt keys.

A sharded worker holds the **same bigint source advisory key 70720261029** in
shared mode. Released serial copy and all quiesced migration phases hold it in
exclusive mode, so they cannot overlap. On the same session, layout admission is
briefly serialized by key 70720261030. Two-int reserved namespaces bind the exact
partition count (7072026), exclusive partition index (7072027), and all eight
32-bit words of the source/target identity hash (7072030..7072037). Incompatible
active layouts/targets and duplicate workers are rejected. Admission does not
hold the coordinator during body transfer. All locks use one dedicated pool
connection, and the existing maximum is **two PG connections per worker**:
one lock session plus one stream/metadata transaction. Four workers therefore
need at most eight connections; obtain a fresh production connection budget
before activation. The tool does not change PostgreSQL limits or create a pool
outside its worker.

## Reuse a stopped serial ledger

Pass `--import-online-ledger /checkpoints/production-online.online-payload-receipts`
on each new worker. The old directory and source data remain present. A shared
filesystem lock on the corresponding old checkpoint lock file prevents an old
local writer from reopening it; the PG source lock also fences the old binary.
The checkpoint volume must permit opening that existing lock file for locking.
Only receipts owned by the worker are imported. Both `.json` and recoverable
`.pending` receipts are supported. The tool validates filename digest, receipt
format and source/target identity, reads back each target CAS object with its
BLAKE3/length check, and validates the exact immutable target receipt. Imported
committed receipts are atomically saved and fsynced in the new ledger. An
interrupted old pending publication may be completed at its identical target
key; the old ledger file is never removed or rewritten.

Every invocation rescans the assigned primary keys. For a current source row
with historical receipts, it re-reads and hashes the full field under a new
repeatable-read snapshot. Only matching BLAKE3, bytes, characters, locator and
MD5 permit reuse without a new upload. MD5 or target existence alone is
insufficient. Changed versions are copied under their own source snapshot and
receive a distinct receipt. Disappeared/null fields are counted as skipped;
their old receipts and objects remain retained. A runtime projection cleanup
therefore cannot silently turn a disappeared source field into verified source
coverage. Deleted/changed historical versions remain part of the ledger.

## Coordinated activation (not performed by this change)

1. Publish the reviewed runtime after the real PostgreSQL/RustFS CI contract.
2. Record the live old Job UID and durable receipt count/bytes. Stop that one
   writer at a receipt boundary; confirm its Pod process is gone/Job terminal
   and the exclusive PG source lock is released. Preserve its volume and ledger.
   A `.pending` receipt is recoverable; an unreceipted in-flight version is
   rescanned from the retained source, never declared copied.
3. Check the actual PG budget for eight total worker connections and that all
   worker Pods can reach PG and the correct target bucket. Reuse the same durable
   checkpoint volume/node topology, with four separate checkpoint filenames.
4. Start each I=0..3 with the same N=4, original source/target configuration and
   import directory. Observe the new UIDs and durable ledgers. Do not restart a
   live worker merely because a watch timed out. A layout change requires stopping
   every worker before activating the next layout; keep all old ledgers.
5. Sum per-shard `rows_observed`/`bytes_observed` and
   `versions_reused_without_upload`; the union of imported receipt names must
   match the old ledger, with no duplicate ownership. Preserve original ledgers
   until the migration is independently verified.

`scan_finished` means only that a live-source scan ended. Output deliberately
keeps `source_verified=false`, `source_writers_quiesced=false`, and
`requires_quiesced_final_copy_and_verification=true`. Copy completion does not
perform reference switching, delete PostgreSQL rows, or reclaim PG storage.
