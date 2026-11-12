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
