# Source provenance

This command was extracted from the public
[`linonetwo/cpa-session-archive`](https://github.com/linonetwo/cpa-session-archive)
repository at revision `7d8aec3e5301b6b33c94595a7cc466ad649cd24b`.

Retained source files:

- `cmd/cpa-session-archive-backup/main.go`
- `cmd/cpa-session-archive-backup/backup.go`
- focused tests from `cmd/cpa-session-archive-backup/backup_test.go`

The source is licensed under Apache-2.0, matching this repository. The extracted
version replaces the unbounded full-database integrity scan with SQLite
`quick_check`, adds bounded stage timing logs, and keeps the online backup,
archive counts, ingest fence, fsync, SHA-256, and no-replace atomic publication
contracts. No collector service, historical deployment code, or unrelated
source was copied.

## Offline derivative preparation

The optional `prepare-digests` subcommand retains the canonical projection of
`linonetwo/cpa-session-archive` revision
`38b49904ad90e7f9567b9a7d6689f05d509eac83`, specifically:

- `internal/archive/snapshot.go`: `stableTrainingRecord`, `canonicalTimestamp`,
  session/request ordering, and the final `session_export_digests` contract.
- `internal/archive/store.go`: request/response legacy gzip and CAS payload
  loading, JSON float64 decoding, metadata and facet types.
- `internal/archive/cas.go`: blob expansion including raw, UTF-8, nested JSON,
  and data URLs, with the same marshal/unmarshal boundary before projection.

`derive_projection.go` omits unused upstream payloads and principal aliases;
neither is included in this revision's `stableTrainingRecord`. It keeps Go's
JSON key ordering, float64 number semantics, no HTML escaping on the final
encoder, newline termination, and UTC six-digit timestamps. Invalid metadata,
timestamps, corrupt gzip, cyclic/deep CAS, or over-limit payloads fail closed
rather than producing a weaker digest. Successful valid projection bytes are
unchanged. `derive_test.go` fixes canonical bytes for legacy/CAS, large numbers,
HTML, raw text, nested JSON and data URLs; resumed hashes must equal these bytes.

No collector service is copied or deployed. The existing CI tests and builds
the same static executable and verifies the new subcommand on that artifact.
