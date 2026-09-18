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
