# Archive recovery metadata preflight

Run `node ops/archive-recovery-preflight.ts RECEIPT.json` with an existing local
metadata receipt. This command reads at most 1 MiB, rejects symlinks and changing
files, emits only counts and classified statuses, and performs no network calls,
archive reads, exports, imports, checkpoint updates or resource mutations.

The receipt contains:

- `seal`: `source_records`, `source_sessions`, `source_blobs`, and
  `source_compressed_bytes` from the reviewed seal evidence.
- `live_stats`: the corresponding `records`, `sessions`, `blobs`, and
  `compressed_bytes` from a bounded collector stats GET.
- `export_job`: Kubernetes Job metadata including its UID, and status.
- `export_pods`: the PodList for that Job. Only matching owner UIDs contribute
  container exit evidence; an empty list is valid missing evidence.
- Optional `seal.source_ingest_fence` and `live_ingest_fence`: decimal strings
  from comparable source snapshots. Do not substitute a tombstone safety floor
  or a wall-clock timestamp for an ingest fence.

Record observation times and provenance alongside the receipt. Counts copied
from a successful seal Job's assertions are not a fresh verification of the
seal file, its source digest, or its source identity. Equal counts do not rule
out updates, deletions or replacement records. Even equal fences require source
identity and digest verification. This preflight never authorizes recovery or
deletion and must not be treated as import acceptance.

`BackoffLimitExceeded` is not an exporter root cause. Capture the original Pod's
init and main termination states plus sanitized logs before the Pod disappears.
The exporter now emits allowlisted system error codes and numeric SQLite error
codes for unexpected failures without exposing paths, SQL, payloads or stacks.
An unclassified exception remains unclassified; do not enable raw debug output
in shared evidence. Diagnosing an old generic I/O message still requires the
original error evidence or a separately authorized bounded reproduction.

Before recovery, verify the runtime bundle, seal SHA-256 and size, source ingest
fence and session digest, retained spool identity and resume cursor, free space,
and any existing artifact/manifest/checkpoint chain. Then use reviewed bounded
export parameters and a separate output destination. Final import requires the
complete nonempty artifact chain, matching history/identity inputs, target
schema and paired database/object-store rollback receipts, dry-run disposition,
apply, exact replay and source-to-target reconciliation. Retire old resources
only after final live delta closure and reference/backup dependency review.
