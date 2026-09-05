# Importing cpa-session-archive

The importer accepts both normalized archive envelopes emitted by
`cpa-session-archive` v0.7.x. Releases through v0.7.21 emit
`schema_version: 1`; newer identity-aware builds emit `schema_version: 2`.
These are parsed as their actual versions rather than relabelled during export.
Do not copy an active `archive.sqlite` file without its WAL. Obtain the JSONL
through an authenticated export ticket, or export from a consistent SQLite
backup.

## Identity prerequisite

Run the CPAMP import first. For the initial migration, set `CPAMP_OVERLAP_MS` to
cover the complete CPAMP history so `import_request_links` contains every source
`request_id`, event hash, timestamp, model and key hash. Later runs can return to
the one-day default overlap. This full overlap is idempotent and does not duplicate
request or aggregate rows.

Schema-1 records require a full 64-character credential SHA-256 in legacy
`key_id`; `credential_hash` is not part of that schema and is never used to rescue
a missing or human-labelled schema-1 key. Schema-2 records prefer their explicit
`credential_hash`, accepting either 64 hexadecimal characters or the strict
`sha256:<64hex>` form, and use a valid legacy `key_id` only when the new field is
absent. The importer strips only that exact prefix and canonicalizes the digest;
an invalid explicit field is never rescued by `key_id`. Apply
cpa-session-archive's identity mapping backfill before exporting
records that only have a human label. The importer does not guess caller identity.
It treats source `principal_id` as untrusted source data and never uses it for
authorization or correlation.
The hash must prove exactly one stable `key_id` and `principal_id`, through the
legacy credential source-hash registry, CPAMP source links, or both. A missing or
conflicting identity proof rejects the complete eligible batch before relational
writes.

## Acquiring incremental source deltas

`cpa-session-archive` exposes whole-session export tickets, not a record-level
`since` cursor. `ops/export-cpa-session-archive-delta.ts` turns its bounded
session projection into a conservative source-side cursor. Prefer the native
0.8 collector contract described in
[`operations/collector-direct-archive-runbook.md`](operations/collector-direct-archive-runbook.md).
The CPA plugin endpoint remains only as an input adapter for migrations from an
older deployment:

Release importer images install this reviewed TypeScript exporter as
`/usr/local/bin/export-cpa-session-archive-delta`, so an isolated migration Job
does not need an untracked script copied into the cluster. The sealed JSONL is
then consumed by `/usr/local/bin/import-cpa-session-archive` from the matching
service image. Do not confuse these image roles or substitute the final audit
command for either stage.

1. read the exact indexed-record count and the `last_at`-ordered session list;
2. select every session at or after `checkpoint - overlap`;
3. export each selected session and reject a count mismatch. Legacy mode retains
   records whose `started_at` **or** `completed_at` is inside the overlap;
   snapshot mode retains each selected whole session so ingest-fence-selected
   late records cannot be removed by their provider timestamp;
4. coalesce canonical-equivalent duplicate request ids, but reject conflicting
   identity/body pairs and an unstable second session projection. A saturated
   legacy list is retried only through the snapshot-cursor contract below; an
   older source fails closed rather than omitting the tail;
5. write canonical JSONL in `(started_at, request_id)` order, followed by a
   SHA-256 manifest chained to the prior output digest and the next source
   checkpoint.

The direct collector has no Authorization middleware. Direct mode rejects CPA
tokens, never emits an Authorization header, and must be isolated by a
NetworkPolicy. Its source must be an exactly allowlisted private cluster host or
use HTTPS with a client certificate and private key. Direct tickets are fixed to
the collector origin and `/archive-api/v1/exports/<64-lowercase-hex>`.

The older CPA plugin input requires exactly one management secret source:
`--token-file` reads a regular non-symlink mode-`0600` file, while
`--token-env ENV_NAME` reads the named injected environment secret. The secret
value is never accepted in argv. Production plugin URLs use HTTPS;
`--allow-http` exists only for its local mock test. Redirects are refused, the
one-time download ticket must remain on the configured download origin, and the
ticket, session ids and payload are never printed. If the plugin advertises the
ticket on a separate origin, set an explicitly reviewed `--download-base-url`.

Record a trusted UTC fence immediately **before** starting the full baseline
export. The first post-baseline delta starts at that fence and subtracts the
configured overlap once more:

```sh
node ops/export-cpa-session-archive-delta.ts \
  --base-url https://REPLACE_API2_ORIGIN \
  --token-file /run/secrets/cpa-management-token \
  --checkpoint /private-evidence/archive-source-checkpoint.json \
  --output /private-evidence/archive-delta-000001.jsonl \
  --since 2026-08-16T00:00:00Z \
  --overlap-seconds 86400
```

Use a new output name for every later run and omit `--since`. Preserve every
JSONL and its adjacent `.manifest.json` as migration evidence. A completed
manifest whose checkpoint write or final rename was interrupted is recovered
without another source request by repeating the same command with `--resume`.
Do not delete or edit an output, manifest, pending file or checkpoint to force a
transition; retain it for investigation and retry from the last verified pair.

The host needs private scratch space for the bounded SQLite de-duplication spool
and the final JSONL. Downloads are streamed into that spool; there is no separate
download file. The spool has one `records` table and stores each canonical record
body exactly once. Its indexes carry request identity, session order and legacy
output selection without a second payload-bearing `seen_records` table.

Use this peak-space equation for the filesystem that contains `--output`:

```text
peak = D + K + O + J + E
stable-schema-v2: O = D + H, therefore peak = 2D + H + K + J + E
```

`D` is the canonical record-line bytes in the single SQLite spool, `K` is its
scalar columns and B-tree indexes, `O` is the pending/final JSONL (rename does not
duplicate it), `J` is the transient SQLite DELETE-mode rollback journal, `H` is
schema-v2 session-summary bytes, and `E` is the small manifest/checkpoint
allowance. The previous two-table spool stored the same canonical bytes twice,
making schema-v2 peak approximately `3D + H + K + J + E`; that estimate is no
longer valid.

`K` and `J` depend on record count, identifier lengths, page fill and filesystem,
so do not replace them with a universal percentage. Run the exact exporter
against the isolated clone, record the filesystem high-water mark, and require
at least that measured peak plus 20% free space before the retained baseline.
The default download and output caps are 64 GiB safety ceilings, not a statement
that a 64 GiB or 100 GiB evidence volume is sufficient. Adjust them explicitly
up to 1 TiB only after the capacity rehearsal. A session may contain records
older than the overlap because the source ticket is whole-session. Legacy mode
validates but does not emit them; stable mode emits them because the session may
have been selected by ingest fence rather than provider time.

The export host and CPA nodes must be time-synchronized. By default, a source
session or record more than one hour ahead of the export host is rejected so one
bad future timestamp cannot advance the checkpoint past later traffic. Adjust
`--max-future-skew-seconds` only to a measured, documented clock bound.

Run the CPAMP usage/identity delta before the matching archive delta. Then use
the normal importer dry-run, apply and same-file replay procedure below. Source
overlap duplicates are intentional; target provenance makes them idempotent.
Set `SESSION_ARCHIVE_OVERLAP_MS` to at least the manifest's
`overlap_seconds * 1000`; a smaller target window breaks the shared cursor
contract. Do not reduce either overlap until every earlier artifact has completed
apply/replay and its source/target checkpoints have been reconciled.
During the final write barrier add `--require-stable-source`; this requires the
indexed-record count to remain identical across the export, in addition to the
two session-list projections.

### Stable session cursor contract

The deployed `cpa-session-archive` v0.7.21 list accepts only `limit=1..1000` and
facet filters. It orders by `last_at DESC`, has no stable tie-breaker, time upper
bound, total or cursor, and treats unknown query parameters as facet filters.
Consequently, an empty response to a cursor-looking parameter is not proof of an
empty page. The exporter actively negotiates the stable protocol on every new
checkpoint transition. It falls back only when the source explicitly returns its
legacy sessions representation and that selected window is provably below the
limit; once a checkpoint contains an ingest fence, stable support is mandatory.

The negotiation requests
`cursor_protocol=session-snapshot-cursor-v1` on the same sessions endpoint. A
compatible source must return an object containing `cursor_protocol`, an opaque
`snapshot`, a decimal `ingest_fence`, `session_count`, `request_count`,
`session_set_sha256`, `sessions`, `complete`, and `next_cursor`. Each session also
contains a `records_sha256`. Subsequent requests repeat the inclusive
`lower_bound_completed_at`, the prior checkpoint's optional
`after_ingest_fence`, `limit`, and snapshot plus the opaque cursor.

The source-side contract is deliberately strict:

- the snapshot fixes a monotonically increasing signed-63-bit ingest-sequence
  upper fence and remains replayable for the complete enumeration and export;
- without `after_ingest_fence`, the first stable snapshot enumerates the complete
  history. Later snapshots return the union of sessions inside the timestamp
  overlap and sessions with a record inserted in `(after_ingest_fence,
  ingest_fence]`; this makes old-timestamp late arrivals visible;
- stable-protocol session ids are printable ASCII (maximum 512 bytes); pages use
  the total order `(last_at DESC, session_id ASC bytewise)` and include every
  session selected by that union;
- every page repeats identical snapshot/count/digest metadata, `next_cursor` is
  non-null exactly while another page exists, and cursors bind the snapshot,
  bounds and final tuple;
- `GET .../export?id=...&snapshot=...` returns `cursor_protocol`, the same
  snapshot and the session `records_sha256`, then produces the exact version
  counted by that snapshot summary; later appends are excluded. The digest is
  SHA-256 over canonical record lines ordered by `request_id`; each line uses
  sorted JSON object keys, UTF-8, no insignificant whitespace, and one trailing
  newline;
- invalid, expired or altered snapshots/cursors return a non-success response.
  They must never silently fall back to a default page or facet filter.

`session_set_sha256` is the SHA-256 of one UTF-8 JSON array sorted by
`session_id`. Each element contains only `session_id`, integer `requests`,
`records_sha256`, `first_at`, and `last_at`; stable-protocol timestamps must
already be normalized to UTC with exactly six fractional digits and `Z`. Object
keys are lexicographically sorted, non-ASCII JSON text is not escaped, and no
insignificant whitespace or trailing newline is present.
This is the same canonical projection retained in the manifest and makes a
missing page detectable independently of page boundaries.

Snapshot schema v2 extends that projection with explicit deleted-session
tombstones. The exporter writes one sealed `session_summary` control line for
every selected present session or tombstone, followed by the complete
request-id-bytewise record set of each present session. The importer verifies
each record count and `records_sha256`, recomputes the Go-field-order v2 set
digest, and rejects missing, duplicate, foreign or unknown controls. It stages
only bounded membership metadata in the target transaction, reconciles stale
or moved exact/unlinked/quarantine heads, verifies the resulting active heads,
then writes present summaries, tombstone audit rows, the legacy cursor and the
stable chain checkpoint atomically. Failure leaves locators, semantic
projections, audit heads and both checkpoints unchanged. A same-file replay is
idempotent and also removes its transaction-local staging rows.

The stable chain begins only with `sequence=1`, null prior digest/fence and an
offline full snapshot. Later artifacts must be non-full, use the same source
fingerprint, increment sequence by one and name the exact prior output digest
and ingest fence. A v1-to-v2 upgrade is accepted only when its prior fence is at
or beyond the source's tombstone-safe fence. A v2-to-v1 downgrade or a changed
tombstone-safe fence fails closed. Dry-run performs these target-chain and
tombstone-locator checks as well as apply; it is not merely a source parser.

The exporter verifies page order, duplicate identities, cursor loops, the total
session and request counts, the complete projection digest, snapshot-bound
per-session counts and record digests, and a second enumeration of the same
snapshot. Stable mode emits every record in each selected session; target
provenance coalesces the intentional replay. New and late records created after
the upper fence are selected on the next run by the persisted ingest fence, not
merely by provider timestamps. Only a SHA-256 digest of the opaque snapshot is
retained; the non-secret numeric ingest fence is chained through the private
manifest and checkpoint.
Until the source implements this complete contract, a saturated legacy window
remains a hard gate; client-side time splitting cannot prove an upper fence or a
complete equal-timestamp boundary.

The legacy CPA plugin projection (before its stable-snapshot contract) is a
separate compatibility boundary. Its RFC3339 timestamps may carry a numeric
offset and 1–9 fractional digits. The exporter compares them at nanosecond
precision so equal-microsecond ordering cannot collapse, then writes the
artifact's canonical UTC value with exactly six digits and `Z`. This
normalization is allowed only after the stable-cursor request has explicitly
fallen back to the unsaturated legacy projection. Stable-cursor responses still
fail closed unless their original timestamp strings are already canonical
six-digit UTC `Z` values and their projection digest matches.

New artifacts use manifest and checkpoint contract version 2. The reader accepts
legacy version-1 artifacts for a one-way upgrade, but version 2 stores the
projection protocol and optional ingest fence so an older exporter rejects the
checkpoint instead of silently dropping cursor state. Do not roll back the
exporter after it has committed a version-2 checkpoint.

An archive request UUID is not assumed to equal CPAMP's short request id. A
globally proven one-to-one edge is recorded as `exact`; only that disposition may
replace a CPAMP `gap://` locator. A record with a proven stable caller but no
target, or with multiple compatible targets, is recorded as `unlinked`
archive-only provenance. A claimed target id whose candidates all conflict on
timestamp, model, credential hash or available usage evidence is rejected as
inconsistent. No closest-time, file-order or arbitrary tie break is permitted.

## Safe execution

`node ops/import-cpa-session-archive.ts` is a dry run unless
`SESSION_ARCHIVE_APPLY=true`. The dry run scans the complete overlap batch and
stops if a source request has no unique stable key/principal identity. Exact
request correlation additionally uses the available request id, timestamp, model,
key hash and usage evidence. Records whose identity is proven but whose target
edge is absent or ambiguous are sealed as explicit `unlinked` plan rows rather
than skipped. `SESSION_ARCHIVE_ALLOW_UNMAPPED=true` is diagnostic-only: it can
count missing-identity records during a dry run, but the importer rejects it
together with `apply`. Cutover can therefore never silently skip an eligible
record.

Required runtime access is:

- a local JSONL export file mounted read-only in the importer container (do not
  bind-mount or copy it into a writable path);
- a pod-local writable plan directory. The reference Job mounts `/plan` as a
  `1200Mi` `emptyDir` (leaving metadata/journal headroom above the 1 GiB plan
  cap) and sets `SESSION_ARCHIVE_MAX_PLAN_BYTES=1073741824`; do not put the plan
  on the source PVC or a volume shared with another pod. The binary has
  non-overridable compile-time ceilings of 16 MiB per JSONL record and 1 GiB per
  plan. `SESSION_ARCHIVE_MAX_LINE_BYTES` and
  `SESSION_ARCHIVE_MAX_PLAN_BYTES` may lower those limits but cannot raise them;
  oversized settings are rejected before database or object-store connections
  are opened;
- the target PostgreSQL connection;
- write/list access to the target archive S3 bucket;
- only the target database and archive-store credentials, supplied by Secret
  references and never placed in command arguments.

Run the normal migration Job before this importer. The archive binary performs a
read-only check that every expected migration and importer relation exists; it
never calls the migration runner and should not receive schema-owner/DDL
privileges. Its importer-specific configuration path also does not read the
service token, key pepper, upstream credentials, plugins or pricing sources.

Migration 58 deliberately does not invent reversible provenance for exact
imports created by older binaries, because those releases accepted arbitrary
`gap://` locators and the original value cannot be reconstructed from an event
hash. Before admitting any schema-v2 artifact, run this read-only rollout gate
for every tenant/source pair:

```sql
SELECT tenant_id, source, COUNT(*) AS irreversible_legacy_exact_rows
FROM session_archive_import_records
WHERE previous_request_object IS NULL
GROUP BY tenant_id, source;
```

Any nonzero row is a rollout blocker. Preserve it for investigation and obtain
trusted old-locator provenance before an explicit repair; never synthesize a
canonical gap or clear the row to force admission. The API2 trial baseline was
reported empty, but trial and production must each be checked against their
actual target database immediately before schema-v2 import.
The standalone Kubernetes manifest includes its own default-deny NetworkPolicy
and permits only cluster DNS, the selected PostgreSQL pods and the selected
object-store pods. Review those selectors for the target cluster; never replace
them with unrestricted egress.

The importer opens the source once and records its device/inode, byte length,
nanosecond mtime and whole-file BLAKE3 digest. Apply then reuses that descriptor
for a complete planning scan. It may write request/response bytes to the
content-addressed archive and writes only minimal matched metadata to a bounded,
pod-local SQLite plan; it makes **no target relational database write** during
this phase. Source replacement, truncation, append or byte drift is fatal at EOF,
so a changed source can leave only harmless unreferenced CAS objects.

After the source seal matches, the plan transaction is closed, fsynced, changed
to mode `0400`, and sealed by device/inode, size and whole-file BLAKE3. The
importer reopens it read-only, parses and validates the header and every
record inside one explicit read transaction, verifies the complete file a second
time, then unlinks its pathname on Unix before the first target database
transaction. The same SQLite read snapshot remains open through the last apply
row, so a later SQLite writer cannot swap in unvalidated records between target
commits. A permission, content, size,
identity or path change is fatal. Target commits read only this sealed plan and
never return to the source JSONL. The source read-only mount remains mandatory,
but correctness does not assume it prevents a different pod or privileged writer
from modifying the underlying volume.

For PostgreSQL, the process also holds the same global advisory lock used by the
CPAMP importer and a second tenant/archive-source advisory lock for its complete
lifetime. This prevents CPAMP reconciliation or another archive importer from
changing the candidate mapping between preflight and apply. SQLite test imports
use an equivalent process-local mutex. Each relational commit then uses a
compare-and-swap update against the exact request/response locators read in its
transaction; a concurrent protected-locator change rolls the transaction back.
An insert conflict is accepted only when both target request and record digest
match the existing provenance row. A different digest is a fatal conflict, never
a silent replay.

Once planning succeeds, each exact transaction replaces compatible `gap://`
references with the previously staged BLAKE3 CAS locations. An unlinked
transaction instead inserts a correlation proof, archive-only metadata/CAS
references, conversation observation/projection and checkpoint. It deliberately
does not insert `request_records`, request locators, usage facts or billing
aggregates, so the already imported CPAMP usage is never charged or counted a
second time. Content-addressed
writes are safe to repeat. A null source payload preserves its current locator,
and a non-gap target object is never overwritten. Plan rows retain their original
sequence but commits are ordered by
`(source_completed_at, external_request_id, sequence)`, with the validated start
time as the narrow compatibility fallback when completion is absent. The target
checkpoint is completed-at based, matching the source cursor. This monotonic
order ensures a crash checkpoint cannot skip an older uncommitted record on
replay, including `overlap=0` records sharing the exact watermark millisecond.
Checkpoints are isolated by tenant and source; exact
correlation replays do not increment imported counts or duplicate conversation
observations. Each correlation row carries the record digest, canonical
correlation proof digest and canonical stable-identity proof digest; a changed
disposition, identity, target or CAS metadata fails closed.

Archive-only observations use a deterministic opaque UUID and participate in
the same logical-conversation graph. They appear only in conversation list/detail
and an explicitly addressed request detail. They do not appear in the ordinary
request list or request statistics. Self detail is bound to the authenticated
stable key; internal detail applies the service credential's tenant scope. API
responses mark `source: session_archive`, `provenance: archive_unlinked` and
`unlinked: true`.

Apply is recoverable and replayable, not one giant 63+ GiB database transaction.
A process/S3/I/O failure may leave already committed rows and unreferenced
content-addressed objects. Keep the sealed source file, fix the failure, and replay
that exact file; matching provenance rows are skipped and the remaining rows
converge. Cutover requires a successful same-file replay with zero new imports and
the final source/target reconciliation. Never switch traffic after only a failed
partial run.

## Source-format limits

The upstream schema-1/schema-2 archive envelopes normalize and rehydrate request
and response bodies, but neither exports a normalized usage object. Any `usage`
inside `response` is provider-specific payload data and is not assumed equivalent
to CPAMP token accounting. The envelopes also do not export `upstream_request`,
`parent_response_id`, `response_id`, or a top-level `source_format`; builds that
captured it expose the value as the `source.format` facet instead. Durable
`session_id`, turn/client/request-kind facets and request Merkle prefixes are used
when available. An explicit session groups observations into one cluster; it does
not by itself create a directed continuation edge. Missing strong ancestry
metadata is left as an unconnected observation rather than fabricated.

The whole-database endpoint still has no `since` parameter. The delta driver
therefore depends on the source session index being complete and current.
Before the baseline, run the collector's supported session-index repair/backfill
and prove on a consistent source SQLite snapshot that every record has a non-empty
session id and exactly one `session_indexed_requests` row, and that every indexed
session has an exact summary count/time range. API2 alone cannot prove those
invariants. If the overlap contains at least 1000 sessions, v0.7.21 cannot prove
the tail. Deploy the snapshot-cursor and snapshot-bound export contract above or
use a proven source write barrier plus a separately reviewed complete baseline;
do not override the exporter gate or attempt client-side `since`/`offset`
parameters that the source interprets as facets.

## Verification boundary

The implementation snapshot is exercised with file-backed SQLite and PostgreSQL
targets plus the test CAS. Module tests cover source and plan content/path/mode
tampering and verify that a validated Unix plan is unlinked before apply. The
integration test mutates the source during planning and asserts zero provenance,
conversation, checkpoint or locator changes (while allowing orphan CAS), and
injects a commit failure where a request starts first but completes last. The
sealed plan commits the shorter completion cursor first; an `overlap=0` replay
then completes the long request without skipping or duplicating rows. The tests
also cover exact CPAMP linkage, dry-run/apply, body rehydration, idempotent replay
and refusal to overwrite a real archive object.

The isolated PostgreSQL acceptance
`postgres_archive_import_lock_and_locator_cas_are_fail_closed` exercises the
body/session importer: a concurrent protected-locator change fails the batch with
zero import rows; after restoring the fixture, the same sealed plan commits
exactly one archive object, provenance/correlation and checkpoint. It also covers
a late-completed old-start record plus inverse start/completion order, injected
partial failure, `overlap=0` recovery and a final zero-import replay. Its
disposable PostgreSQL container is removed after the test.

This is still **not live migration evidence**. No production/dev
cpa-session-archive JSONL was imported, and no live target PostgreSQL/S3 counts
have been reconciled. The release gate must run dry-run, apply, replay and
source/target body/count sampling against the reviewed live destination before
traffic shift. The separately passing PostgreSQL CPAMP fixture validates usage
metadata/checkpoints; the two import paths must still be reconciled together.
The source-delta driver is covered by a local mock API2 test for deterministic
overlap, pending-output resume, projection drift, saturated windows, session
count disagreement, redirects, cross-origin tickets and an unstable freeze; that
test is not evidence that the live API2 session index is complete.
