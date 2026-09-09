# Pinned session archive import runtime

This is an approved intermediate delivery boundary, **not** extraction of the
historical Rust closure and not authorization for final cleanup or real import.

## Immutable source and build

- Product source: `memeloop-online/memeloop-token-center`,
  revision `a65097f952e174ac482abe6ff719966fa9d330cb`.
- Cargo.lock SHA-256:
  `2134ac15927c1beaceed75d52e48312b6bb93db072c43df4c557cad7de23e029`.
- Rust `1.95.0`, `cargo --locked`, Ubuntu 24.04, Linux x86_64 GNU.
- CI executes the importer unit tests and session import/quarantine/unlinked
  integration tests with an isolated PostgreSQL service, then builds only the
  `import-cpa-session-archive` release binary.

Release assets include `commands/runtime/import-cpa-session-archive`,
`compatibility.json`, and an exact tracked `source.tar` retained independently
of future product-tree cleanup. The outer release manifest hashes all three.
The compatibility manifest also binds binary/source bytes, revision, Cargo.lock,
Rust version, target and CLI contract. Verify the fixed release archive and all
outer manifest hashes **before execution**; the inner checksum manifest is not
an independent signature or substitute for release provenance.

The packager refuses dirty tracked source or source/lock/compiler drift and
exercises the compiled CLI contract. Isolated release verification executes its
`--help` outside the source tree and node_modules. Synthetic verifier tests
reject missing/tampered manifest fields, changed payloads, absent executable
permission and symbolic links.

## Runtime contract

The wrapper defaults to its adjacent `runtime/import-cpa-session-archive`; it
does not fall back to PATH. `MTC_SESSION_ARCHIVE_IMPORT_BIN` can relocate the
same verified runtime, but its sibling compatibility manifest and retained
source archive are mandatory and must match the compiled pin. It cannot select
an arbitrary replacement executable. Overrides must be absolute paths; the
verifier returns the canonical absolute path and the wrapper executes exactly
that path, never a same-named executable found through PATH.

The runtime requires Linux x86_64 and glibc 2.39 or newer. The target database,
archive store and approved credentials/configuration remain external inputs.
No cargo, source checkout, package install, network download or product process
is needed to launch the delivered executable. Verify host dynamic-library
availability with the isolated `--help` check before supplying real inputs.

Dry-run remains the default. `SESSION_ARCHIVE_APPLY=true` is an explicit write
decision; the finalizer additionally requires its separately bound approval.
The unchanged engine checks the target schema read-only before import, validates
identity, and retains the existing gap/quarantine/provenance/replay semantics.
This release does not implement product schema upgrades and does not relax
import acceptance for a newer target schema.

## Closure still owned by the pinned engine

`src/bin/import-cpa-session-archive.rs` invokes
`Config::from_session_archive_import_env`,
`Database::ensure_session_archive_import_schema`,
`ArchiveStore::from_config`, `validate_session_archive_import_options` and
`import_session_archive`.

The remaining engine modules are `src/session_archive_import/{mod,plan,parsing,
correlation,apply}.rs`. Their DB closure includes request matching, exact and
unlinked transaction commits, quarantine, snapshot projection/staging,
checkpoint chains and tombstone preflight/apply through
`src/db/requests/session_archive*.rs`, plus shared model, conversation,
configuration, archive and error types. Extracting just the CLI file does not
extract this closure.

A later standalone crate extraction must preserve the reviewed SQL/schema and
identity/archive semantics and pass the same SQLite/PostgreSQL tests. Retaining
the exact source tar now prevents product cleanup from erasing the migration
engine's fixed source, but does not itself authorize that cleanup.
