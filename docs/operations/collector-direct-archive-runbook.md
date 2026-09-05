# Collector-direct archive migration

Use this path with `cpa-session-archive` 0.8 or newer. It talks to the collector
API directly and does not depend on CPA product behavior. The older CPA plugin
path remains an input adapter for historical migrations only.

## Isolation and source identity

The collector API has no Authorization middleware. Do not expose it through an
Internet ingress and do not pass a CPA token to `--collector-direct`. Run the
export Job in the source cluster and restrict a migration-only Service with a
default-deny NetworkPolicy so only the Job pod label can connect. Use cluster
TLS, including an mTLS sidecar or service-mesh policy when the cluster provides
it, or explicitly allow exactly one private Service DNS name with
`--private-http-host`.
The exporter disables environment HTTP proxies for management and ticket
requests, so a capability or archive body cannot leave this reviewed origin.

Keep the source URL byte-for-byte stable for the baseline and all deltas. A
practical layout is one migration-only Service whose selector initially targets
the isolated offline collector and later targets the active collector. Review
the selector change and endpoints before applying it. Never copy the archive
database or a live SQLite/WAL pair between machines. First enable the v0.8
ingest clock on the active collector, then create a SQLite-online-backup or
storage-snapshot-derived Longhorn clone in the same cluster. The clone must be
isolated from production and writable only by the offline collector: v0.8
creates narrow ingest/digest tables and writes prepared session digests even
though archived request bodies are otherwise immutable. Do not mount the
production PVC into the offline collector, and do not use a raw filesystem copy
of an actively written database as migration evidence.

The Job needs a private evidence PVC. Run these checks inside the Job pod:

```sh
set -eu
umask 077
test -d /evidence
test "$(stat -c %a /evidence)" -le 700
getent ahostsv4 cpa-session-archive-migration.cpa.svc.cluster.local
```

## Offline baseline

Start the isolated collector with
`ARCHIVE_ALLOW_OFFLINE_FULL_SNAPSHOT=true`. Confirm that `/v1/stats` advertises
`session-snapshot-cursor-v1` and `offline_full_snapshot_enabled: true`; the
exporter checks both again before it creates a snapshot.

```sh
set -eu
umask 077
SOURCE_HOST=cpa-session-archive-migration.cpa.svc.cluster.local
SOURCE_URL=http://${SOURCE_HOST}:8080
node ops/export-cpa-session-archive-delta.ts \
  --collector-direct \
  --offline-full \
  --base-url "${SOURCE_URL}" \
  --private-http-host "${SOURCE_HOST}" \
  --checkpoint /evidence/archive-source-checkpoint.json \
  --output /evidence/archive-baseline-000001.jsonl \
  --since 1970-01-01T00:00:00Z \
  --overlap-seconds 86400 \
  --session-limit 1000 \
  --timeout-seconds 60 \
  --max-elapsed-seconds 21600
sha256sum /evidence/archive-baseline-000001.jsonl
```

HTTP 503 means digest preparation is still bounded and in progress; HTTP 429
means the one-snapshot capacity is occupied. The exporter retries both with a
bounded backoff until `--max-elapsed-seconds` during the offline baseline. HTTP
410 or an expired download ticket discards only the unpublished attempt. It
never advances the atomic checkpoint until every page, record count and digest
has been verified.

Before retaining this baseline, rehearse the same command on the isolated clone
and measure the evidence filesystem high-water mark. The exporter streams source
bytes and keeps one canonical payload copy in its SQLite spool. With `D` record
bytes, `H` summary bytes, `K` SQLite scalar/index bytes, `J` the transient
rollback journal and `E` manifest/checkpoint allowance, stable-schema-v2 peak is
`2D + H + K + J + E`: one spool payload plus the JSONL, not two spool payloads
plus the JSONL. `K` and `J` must be measured for the real record-count and
identifier distribution. Require the measured peak plus 20% free space; the
64 GiB CLI defaults are rejection ceilings rather than PVC sizing guidance.

## Online deltas

After the baseline is sealed, point the same migration-only Service at the live
collector and remove the offline collector. Verify the Service endpoints and
NetworkPolicy before continuing. Use a new output name, omit `--since`, and do
not pass `--offline-full`:

```sh
set -eu
umask 077
SOURCE_HOST=cpa-session-archive-migration.cpa.svc.cluster.local
SOURCE_URL=http://${SOURCE_HOST}:8080
node ops/export-cpa-session-archive-delta.ts \
  --collector-direct \
  --base-url "${SOURCE_URL}" \
  --private-http-host "${SOURCE_HOST}" \
  --checkpoint /evidence/archive-source-checkpoint.json \
  --output /evidence/archive-delta-000002.jsonl \
  --overlap-seconds 86400 \
  --session-limit 1000 \
  --timeout-seconds 60 \
  --max-elapsed-seconds 21600
```

Repeat with monotonically numbered output files. A stable ingest fence includes
late arrivals even when provider timestamps predate the overlap. Whole sessions
intentionally contain replayed records; target provenance removes duplicates.

## Target dry run, apply and replay

Mount one sealed JSONL read-only in the Token Center migration Job. Keep the
source name and overlap unchanged for all three invocations:

```sh
set -eu
export SESSION_ARCHIVE_FILE=/evidence/archive-delta-000002.jsonl
export SESSION_ARCHIVE_IMPORT_SOURCE=cpa-session-archive-production
export SESSION_ARCHIVE_OVERLAP_MS=86400000

SESSION_ARCHIVE_APPLY=false node ops/import-cpa-session-archive.ts
SESSION_ARCHIVE_APPLY=true node ops/import-cpa-session-archive.ts
SESSION_ARCHIVE_APPLY=true node ops/import-cpa-session-archive.ts
```

The third command must report `imported: 0`; overlap records may report as
`replayed`. Preserve the JSONL, adjacent manifest, source checkpoint, three
import summaries and target checkpoint as one audit set. `--resume` is only for
recovering the exact same sealed output/manifest transition and performs no
source request.

## Failure and rollback

- Never edit a checkpoint, manifest or JSONL to bypass a refusal.
- The private checkpoint lock file serializes the complete load/export/resume/
  commit transaction. A second Job waits only within its elapsed-time bound.
- On 401/403/invalid protocol, stop; those responses are not transient.
- On repeated 410, 429 or 503, retain evidence and investigate collector health,
  active snapshot age and digest queue statistics.
- Rolling back the migration means stopping the migration Job and restoring the
  migration-only Service selector. It does not change CPA traffic.
- Delete short-lived clone PVCs and migration Jobs only after retained evidence
  paths and ownership have been reviewed; never delete production archive data.
