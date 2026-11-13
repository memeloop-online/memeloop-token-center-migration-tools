# One completed raw request reference

This operational phase relocates one authoritative request root to an already
present, verified haixia training CAS body. It does not copy reference JSON as
body, scan a bucket, migrate responses, or delete source objects. There is no
service-wide writer pause and no model-request admission change.

Deploy all actual readers with qualified backend routing and source HEAD (#881),
and raw publication plus relational-binding replay compatibility (#885), before
production apply. Configure legacy MinIO using MTC_SOURCE_S3_* and the fixed new
haixia training target using MTC_S3_*. These must be distinct stores. Never
reinterpret old qualified identities by changing endpoint/bucket configuration.

Use a fresh per-request checkpoint and a private small plan file:

```json
{"tenant_id":"TENANT-UUID","request_id":"REQUEST-UUID","target_locator":"stores/training/EXACT-TRAINING-IDENTITY/tenants/TENANT-UUID/cas/v1/blake3/HH/DIGEST"}
```

```sh
migrate-conversation-objects --phase raw-request-reference \
  --checkpoint /checkpoints/haixia-raw-request-REQUEST.json \
  --raw-reference-plan /plans/request.json
# After compatibility is actually deployed, add --apply-references.
```

The tool verifies the complete decoded target bytes/BLAKE3 against the original
raw root's canonical tenant CAS identity, writes and reads back an immutable
proof receipt, and persists the original root bytes and exact SQL version.
It conditionally updates the small legacy authoritative root using the ETag or
version returned with that same GET. A lost PUT response never permits SQL
changes until exact root readback confirms the intended pointer. A short SQL
row lock then rechecks tenant/request/key/reservation/creation/completion/locator
and changes only request_object. All S3 calls remain outside that transaction.
Commit-unknown recovery re-reads SQL; conflicts preserve evidence and source.

The shared global migration lock and exclusive reference-writer lock serialize
migration tools, not native publishers. This phase grants no GC authority.
Legacy body objects, pending/financial/retention obligations and audits remain.
Small roots staying in MinIO are an interim stage: final retirement still needs
persistent root/staging backend identity across every reader and publisher,
actual publication/release fences, closed reference sets, final root lookup
cutover, and reference-aware GC. Neither terminal status nor projected_at alone
is a release proof. Do not erase legacy roots or blobs after this command.


## Online raw target preparation

`--phase copy-raw-request-target --raw-reference-plan <plan.json> --checkpoint
<request-checkpoint.json>` prepares only one completed request's exact raw body.
It requires explicit source S3 configuration and the same canonical target plan
as `raw-request-reference`. It rejects `--apply-references`; no source root or
SQL pointer changes occur. Raw gap locators are not synthesized from semantic
payloads.

The target is inspected only at the exact canonical tenant/digest key. If it
exists, the entire target is verified and reused without PUT. A missing target
is streamed from the original immutable CAS (including its decoded length and
BLAKE3 verification), through the existing multipart writer and immutable
same-backend promotion. The target receives its normal complete readback before
an immutable receipt and durable audit are written. A present corrupt object
fails closed rather than being overwritten. Source row/root identity is checked
again; changes keep the source and fail this operation. This does not claim
exclusive ownership, globally verified source, retention release or GC consent.

Once actual all-reader compatibility includes the raw publisher/binder replay
fix, the separate `raw-request-reference --apply-references` can use this same
checkpoint and revalidate target, root and source before conditional root and SQL
updates. Copy does not itself authorize that step. The legacy small root is
still authoritative during this intermediate phase; its final backend-aware
lookup migration and native publication/release fence remain separate work.

The phase retains the existing shared migration lock and exclusive reference
operation lock. Operate it at the single-writer scheduler's safe boundary;
do not start it alongside the automatic semantic CAS controller or another raw
operation. Existing semantic priority jobs and their checkpoints remain unchanged.

The report distinguishes `source_streamed` from `target_reused` (the exact key
was already present before copy). It does not infer a unique new CAS object
from staging upload: a concurrent conditional promotion may reuse a CAS object,
so `target_cas_creation_measured=false`. Body bytes are decoded bytes, not wire
or physical storage growth.

## Bounded raw batches

Both raw phases also accept `{"requests":[<the existing single-request plan>, ...]}`.
Use a metadata-only eligibility pass to select completed requests with an observed
legacy root and exact current SQL locator; in-flight requests and source gaps are
not filled or acknowledged. Financial/pending state is preserved.

Run copy-target, then explicit apply against the same checkpoint and exact plan.
Copy and apply have separate durable cursors bound to the full ordered plan,
source/target identity and action. Per-request audit files are shared between
those phases. A failed item stops the batch; restart resumes that item's existing
recovery protocol. Duplicate request identities are rejected before object IO.
Use distinct checkpoints for distinct batches, retain all audits, and never edit
checkpoint identities. The existing global migration locks and pool of two are
unchanged; members execute serially. Single-plan dry-run remains available;
batch dry-run is explicitly rejected.

Reports distinguish reference bytes, unique target locators/bytes, repeated
references to those targets, source-streamed requests and existing-target reuse.
Source-streamed does not measure newly created physical CAS objects: immutable
promotion may reuse a concurrently created object. Completed batch cursors are
execution receipts, not fresh readability, source-release or GC authorization.
No batch operation deletes source bodies or migrates the legacy root namespace.
