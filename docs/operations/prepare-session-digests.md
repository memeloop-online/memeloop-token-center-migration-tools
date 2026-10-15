# Resumable digest preparation on an isolated derivative

This is a one-shot subcommand of the existing verified SQLite backup runtime,
not a replacement collector service or a new backup. It writes only an already
copied, frozen, exclusive-work SQLite derivative. Never mount an original
archive, production database, or unrelated volume writable for this command.

```text
cpa-session-archive-backup prepare-digests \
  --work /work/prepared/archive.sqlite --expected-fence 531730 \
  --timeout 25m --checkpoint-records 64
```

No command is authorized merely by this example. Bind the intended PVC UID,
exclusive consumer, source-copy receipt, ingest fence, fixed runtime digest,
disk reserve and Job deadline in the existing operator before execution.
Keep the existing migration CPU/memory ceiling; this change does not authorize
a larger allocation or a longer Job. No production credentials are required.

## Proven work avoided

The pinned collector selects two missing/stale sessions at a time by sorting
the whole session catalogue. Its request-ID query uses the session/time index
and a temporary request-ID sort; a resumed keyset query would repeat that sort
without a `(session_id, request_id)` index. Request-ID and blob lookups already
use unique indexes: they are **not** proven per-record full table scans.

The official loader also reads principal aliases and upstream payloads that
the stable digest projection never emits. Most importantly, it commits only
after hashing an entire session. A bounded restart repeats any unfinished
session; no commit counter can report its in-session progress.

This subcommand makes these changes, without changing successful digest bytes:

- Create one ordered covering index on the derivative, once. Index preparation
  itself is deadline-bound, may need temporary disk space, and is not free.
- Load the small session catalogue once per invocation, not every two sessions.
- Use two independent indexed MAX lookups for the current/previous-session
  ingest fence, instead of enumerating a multi-index OR result.
- Use bounded keyset pages and load only projected request/response fields.
- Cache at most 16MiB of immutable decoded blob bytes across records. This
  avoids redundant reads/decompression, not required canonical hashing.
- Atomically save last request ID, processed count, canonical-byte count and
  Go SHA-256 binary state every 1..128 records. A crash repeats at most the
  uncommitted chunk; it does not restart a 20,000-record session.

The index/table additions and all digest writes are to the new derivative.
Do not promise a particular speedup from query plans alone. Actual CPU time,
payload amplification, storage latency and the largest record remain runtime
measurement gaps. The existing resource budget is a migration constraint,
not a business-concurrency setting.

## Integrity, restart and acceptance

The private regular work file must be owned by the invoking UID, mode0600,
non-symlink and single-link. An advisory lock excludes another invocation;
the operator must also exclude collectors and other consumers. Immediate
SQLite transactions prevent concurrent writes while chunks are read/committed.
The frozen global ingest fence, schema version, connection data version and
device/inode binding fail closed on observed source changes. Arbitrary edits
that bypass the ingest contract between invocations are not supported.

The checkpoint is private work data: SHA internal state can contain the last
partial input block and must not be logged, attached to PRs, or exported as
public evidence. It has a version, source/session fence/count binding, byte
length validation and a corruption-detection checksum. This is not a signature
against a malicious writer with access to the work database. A mismatch is an
error, not an instruction to discard progress and restart automatically.

Completed digests with matching fence/count and valid SHA are skipped without
rehashing. Partial sessions are never inserted into `session_export_digests`.
The final chunk publishes the complete digest and removes only its own resume
row in one transaction. Full acceptance requires every session, full record
counts and no remaining checkpoint. No record may be omitted to meet a limit.
Payload/record limits fail closed with no PASS.

Exit0 is `DIGEST_COVERAGE_PASS_NOT_SEALED`; exit3 is a bounded partial result
with checkpoints retained; exit1/2 rejects errors/arguments. Native errors,
paths, session IDs, credentials, payload and hash state are not printed.
Progress contains only stage, committed count/bytes, duration and completion.
WAL/checkpoints must be retained after interruption. Do not copy or hash the
30GiB source again. Seal/export/import and final financial/reference/delta
reconciliation are separate steps; this command never permits old-volume
deletion.

## CI

The existing workflow runs `go test ./cmd/cpa-session-archive-backup`; no new
pipeline or skipped protection is introduced. Coverage includes real CLI
dispatch, partial restart/replay, exact canonical SHA, CAS reuse, covering
keyset plans, corrupt checkpoints, changed fences/counts and missing payloads.
The existing static-runtime build verifies `prepare-digests --help` before
sealing its artifact. Tests/builds run in GHA, not on migration nodes.
